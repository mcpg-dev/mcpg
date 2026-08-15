//! [`IdempotencyStore`] trait + supporting types.
//!
//! Mirrors the shape of [`crate::runtime::task_store`] — the trait
//! surface is sync + Send + Sync; concrete impls bridge to async KV
//! via `tokio::task::block_in_place` (see
//! [`KvBackedIdempotencyStore`](super::KvBackedIdempotencyStore)).
//! The two-phase `reserve_or_get` / `complete` pattern matches the
//! design doc §2.1: an atomic GET returns one of four outcomes, and
//! a subsequent `complete` writes the cached envelope for replay.

use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Logical scope under which an idempotency record lives.
///
/// Two records share dedupe semantics iff their scope encodes
/// equal. Default policy is per-identity (operator-tunable via
/// `IdempotencyConfig`):
///
/// - `tenant_id` — short multi-tenant namespace (never empty —
///   "anonymous-tenant" or similar when no operator-supplied
///   tenancy is in play).
/// - `identity_hash` — BLAKE3 of the canonicalised caller identity
///   (subject ID + auth provider + issuer). Hash, not raw bytes,
///   so the storage key cannot leak PII.
/// - `method` — JSON-RPC method name (`tools/call` or
///   `tasks/create`).
/// - `tool_name` — narrow to the binding being invoked. Two
///   different tools cannot collide on the same key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyScope {
    pub tenant_id: String,
    pub identity_hash: [u8; 32],
    pub method: String,
    pub tool_name: String,
}

/// Outcome of a [`IdempotencyStore::reserve_or_get`] call. The four
/// variants are mutually exclusive and exhaustive — every retry of
/// a request with the same key + scope lands in exactly one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// First request with this `(scope, key)` pair. The store has
    /// recorded a reservation; the caller MUST proceed to dispatch
    /// and call [`IdempotencyStore::complete`] on success or
    /// failure. The reservation is identified by an opaque UUID
    /// for observability.
    Reserved { reservation_id: Uuid },
    /// Another caller is mid-flight on this `(scope, key)` pair.
    /// Per design doc §2.2 the caller MUST return
    /// `-32011 IdempotencyInFlight` (HTTP 409 + `Retry-After: 1`).
    InFlight { started_at: SystemTime },
    /// A previous call completed; the cached envelope is returned
    /// for replay. Per design doc §2.4 the caller MUST stamp the
    /// replay marker on the response and skip QGATE / dispatch /
    /// post-dispatch payment plugins.
    Completed {
        outcome: CachedOutcome,
        completed_at: SystemTime,
    },
    /// Same `(scope, key)` but the request body hash differs from
    /// the cached one. Per design doc §1.6 the caller MUST return
    /// `-32010 IdempotencyConflict` (HTTP 422).
    Conflict { stored_request_hash: [u8; 32] },
}

/// Cached terminal envelope for a completed (non-streaming) tool
/// call, ready to be replayed verbatim on idempotent retries.
///
/// `envelope` is the JSON-RPC `result` body — the same value the
/// dispatcher would have placed on a `JsonRpcSuccess`. The
/// dispatcher serialises the `ToolCallResult` into this shape at
/// the end of the first call and the store hands it back wholesale
/// on a hit.
///
/// Tasks integration reuses this struct with
/// `envelope = { "task_id": "..." }` to dedupe `tasks/create`
/// handles per design doc §4. Streaming integration caches the
/// assembled envelope at stream completion, or marks
/// `payload_truncated` and skips caching when the envelope exceeds
/// `PAYLOAD_CAPTURE_CAP_BYTES`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedOutcome {
    /// JSON-RPC `result` field the original call produced.
    pub envelope: serde_json::Value,
    /// Original JSON-RPC request id, kept so audit events on
    /// replay can correlate to the call that filled the cache.
    pub original_request_id: serde_json::Value,
    /// The gateway correlation id of the call that filled this cache entry —
    /// the same value that call reported to the control plane.
    ///
    /// A replay tells the control plane "do not bill me", and nothing
    /// corroborated that: a gateway stamping every sample as a replay produced
    /// zero billable usage. The JSON-RPC id above cannot corroborate it —
    /// it is client-chosen and unique to nobody — so the replay carries this
    /// instead, which names a call the control plane has already seen and
    /// billed. Empty for entries written before this field existed.
    #[serde(default)]
    pub original_correlation_id: String,
    /// How many times this record has been replayed. Bumped by
    /// the store on each `Completed` return. Surfaces in audit
    /// events as a tamper-resistant counter.
    pub replay_count: u32,
    /// Flag set when the streaming-completion payload exceeded the
    /// gateway's `PAYLOAD_CAPTURE_CAP_BYTES` memory cap. The gateway
    /// logs a warn AND skips caching the
    /// over-cap envelope, so a record with `payload_truncated: true`
    /// won't typically be observable in practice; the field exists
    /// for forward compatibility with future "cache truncated
    /// envelope on a best-effort basis" policies.
    #[serde(default)]
    pub payload_truncated: bool,
}

/// Errors raised by [`IdempotencyStore`] implementations. Mirrors
/// the shape of [`crate::runtime::task_store::TaskStoreError`].
#[derive(Debug, Clone)]
pub enum IdempotencyError {
    /// Internal store error — KV backend down, encode/decode
    /// failure, etc. Carries a human-readable detail string. The
    /// dispatcher logs and treats this as "store unavailable",
    /// falling through to non-idempotent dispatch on `Internal` so
    /// a degraded store doesn't block traffic.
    Internal(String),
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdempotencyError::Internal(msg) => write!(f, "idempotency store error: {msg}"),
        }
    }
}

impl std::error::Error for IdempotencyError {}

/// Cheap-peek outcome: a read-only view of any record at
/// `(scope, key)`. Mirrors [`ReservationOutcome`]'s shape but
/// elides `Reserved` (peek never reserves) — a miss returns
/// `None` instead. Used by the dispatcher's pre-gate hot path to
/// short-circuit cache hits without paying the PUT cost on the
/// typical "no key supplied" call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekOutcome {
    /// Another caller is mid-flight on this `(scope, key)` pair.
    InFlight { started_at: SystemTime },
    /// A previous call completed; the cached envelope is returned
    /// for replay. The `replay_count` inside `outcome` already
    /// reflects this peek (the store atomically bumps on read).
    Completed {
        outcome: CachedOutcome,
        completed_at: SystemTime,
    },
    /// Same `(scope, key)` but the request body hash differs from
    /// the cached one. Caller MUST 422 even before the policy
    /// chain re-runs — a body-mismatch is a client bug, not a
    /// transient policy state.
    Conflict { stored_request_hash: [u8; 32] },
}

/// Storage backend for idempotency records.
///
/// Three-phase API:
/// - `peek` reads any existing record without reserving (used by
///   the dispatcher's cheap pre-gate check);
/// - `reserve_or_get` atomically claims a slot OR returns the
///   existing record's outcome (used at dispatch time);
/// - `complete` writes the terminal envelope after successful
///   dispatch.
///
/// The trait is async-flavoured (matches the cluster KV
/// substrate's async surface). The concrete
/// `KvBackedIdempotencyStore` bridges to a sync caller via
/// `tokio::task::block_in_place`.
#[async_trait::async_trait]
pub trait IdempotencyStore: Send + Sync + fmt::Debug {
    /// Read-only view of any record at `(scope, key)`. Returns
    /// `Ok(None)` for a clean miss (no reservation created).
    /// `Some(PeekOutcome::Conflict)` is returned even on a
    /// body-hash mismatch so the dispatcher can 422 without
    /// taking the gate path.
    async fn peek(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        request_hash: &[u8; 32],
    ) -> Result<Option<PeekOutcome>, IdempotencyError>;

    /// Atomically reserve a slot for `(scope, key, request_hash)`
    /// or return the existing record's outcome.
    ///
    /// `ttl_override` lets the caller bound the reservation's
    /// wall-clock expiry below the store's configured default —
    /// used by the tasks/create integration so an idempotency
    /// record never outlives the task it points at. `None` means
    /// "use the configured default".
    ///
    /// See [`ReservationOutcome`] for the four return shapes.
    async fn reserve_or_get(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        request_hash: &[u8; 32],
        ttl_override: Option<Duration>,
    ) -> Result<ReservationOutcome, IdempotencyError>;

    /// Persist the terminal envelope for a previously-`Reserved`
    /// slot. Idempotent — safe to call once per reservation.
    /// On a re-reserve race the LWW write may overwrite, but the
    /// envelope is the same per the body-hash invariant so callers
    /// observe the same replay regardless.
    async fn complete(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        outcome: CachedOutcome,
    ) -> Result<(), IdempotencyError>;

    /// Sweep records whose TTL has elapsed. Returns the number of
    /// records removed. KV backends with native TTL return 0 (the
    /// backend auto-expires).
    async fn gc_expired(&self) -> usize;
}

/// No-op idempotency store used when the operator has the feature
/// disabled. Every reservation succeeds with a fresh UUID; no
/// state is persisted. The dispatcher detects this via the
/// `enabled` config bit and short-circuits BEFORE reaching the
/// trait surface, so the no-op is purely defensive.
#[derive(Debug, Default)]
pub struct NoopIdempotencyStore;

#[async_trait::async_trait]
impl IdempotencyStore for NoopIdempotencyStore {
    async fn peek(
        &self,
        _scope: &IdempotencyScope,
        _key: &str,
        _request_hash: &[u8; 32],
    ) -> Result<Option<PeekOutcome>, IdempotencyError> {
        Ok(None)
    }

    async fn reserve_or_get(
        &self,
        _scope: &IdempotencyScope,
        _key: &str,
        _request_hash: &[u8; 32],
        _ttl_override: Option<Duration>,
    ) -> Result<ReservationOutcome, IdempotencyError> {
        Ok(ReservationOutcome::Reserved {
            reservation_id: Uuid::new_v4(),
        })
    }

    async fn complete(
        &self,
        _scope: &IdempotencyScope,
        _key: &str,
        _outcome: CachedOutcome,
    ) -> Result<(), IdempotencyError> {
        Ok(())
    }

    async fn gc_expired(&self) -> usize {
        0
    }
}

/// Convenience: produce a thread-safe [`NoopIdempotencyStore`]
/// behind `Arc<dyn IdempotencyStore>` for tests and the
/// disabled-feature boot path.
#[must_use]
pub fn noop_idempotency_store() -> std::sync::Arc<dyn IdempotencyStore> {
    std::sync::Arc::new(NoopIdempotencyStore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_scope() -> IdempotencyScope {
        IdempotencyScope {
            tenant_id: "tenant-alpha".to_owned(),
            identity_hash: [7u8; 32],
            method: "tools/call".to_owned(),
            tool_name: "charge_customer".to_owned(),
        }
    }

    #[test]
    fn idempotency_scope_serde_round_trip() {
        let scope = sample_scope();
        let bytes = serde_json::to_vec(&scope).unwrap();
        let back: IdempotencyScope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn cached_outcome_serde_round_trip() {
        let outcome = CachedOutcome {
            envelope: json!({"content": [{"type": "text", "text": "ok"}]}),
            original_request_id: json!(42),
            original_correlation_id: String::new(),
            replay_count: 3,
            payload_truncated: false,
        };
        let bytes = serde_json::to_vec(&outcome).unwrap();
        let back: CachedOutcome = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn cached_outcome_serde_back_compat_omits_payload_truncated() {
        // An older record on disk (written before the
        // `payload_truncated` field existed) MUST decode cleanly
        // thanks to `#[serde(default)]`.
        let bytes = br#"{"envelope":{},"original_request_id":1,"replay_count":0}"#;
        let outcome: CachedOutcome = serde_json::from_slice(bytes).unwrap();
        assert!(!outcome.payload_truncated);
    }

    #[test]
    fn trait_object_compiles_and_dispatches() {
        // Compile-time guard: `Arc<dyn IdempotencyStore>` must be
        // Send + Sync so the dispatcher can hold it across awaits.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<std::sync::Arc<dyn IdempotencyStore>>();
        let _: std::sync::Arc<dyn IdempotencyStore> = noop_idempotency_store();
    }

    #[tokio::test]
    async fn noop_store_always_reserves_fresh() {
        let store = NoopIdempotencyStore;
        let scope = sample_scope();
        // peek always misses on the noop — disabled-feature
        // dispatcher must observe a clean fall-through.
        assert_eq!(store.peek(&scope, "k1", &[1u8; 32]).await.unwrap(), None);
        let outcome = store
            .reserve_or_get(&scope, "k1", &[1u8; 32], None)
            .await
            .unwrap();
        assert!(matches!(outcome, ReservationOutcome::Reserved { .. }));
        store
            .complete(
                &scope,
                "k1",
                CachedOutcome {
                    envelope: json!({}),
                    original_request_id: json!(1),
                    original_correlation_id: String::new(),
                    replay_count: 0,
                    payload_truncated: false,
                },
            )
            .await
            .unwrap();
        // gc_expired returns 0 for native-TTL backends (which the
        // noop simulates).
        assert_eq!(store.gc_expired().await, 0);
    }
}
