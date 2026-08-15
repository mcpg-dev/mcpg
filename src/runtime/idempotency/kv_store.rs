//! [`KvBackedIdempotencyStore`] — concrete impl of
//! [`IdempotencyStore`] over an `Arc<dyn KeyValueStore>`.
//!
//! The KV substrate handles native TTL expiry + cluster fan-out; this
//! layer adds:
//!
//! - Two-phase `reserve_or_get`: GET → if miss, PUT a record with
//!   state=`InFlight` and the supplied request hash. A concurrent
//!   second writer races but the second PUT wins (LWW), and the
//!   GET-before-PUT race surfaces as `InFlight` to the second
//!   caller (which 409s + retries).
//!
//! - Body-hash invariance: a record's `request_hash` is sealed at
//!   reserve time. A retry with a different hash returns
//!   `Conflict` so the dispatcher can 422.
//!
//! - Cross-tenant guard: the record's serialised `tenant_id` and
//!   `identity_hash` are re-validated against the requesting scope
//!   on every read. A mismatch returns `NotFound` (existence not
//!   leaked) and emits a warn — defense-in-depth against an
//!   operator misconfiguring the key prefix.
//!
//! - TTL preservation: `complete` recomputes the remaining TTL
//!   from the reservation deadline so completing a record doesn't
//!   reset the wall-clock expiry.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::store::{
    CachedOutcome, IdempotencyError, IdempotencyScope, IdempotencyStore, PeekOutcome,
    ReservationOutcome,
};

/// Active retention policy threaded through the store. Sourced
/// from [`crate::config::IdempotencyConfig`] at boot.
/// Carrying it as a tiny copy struct (rather than borrowing the
/// full config) lets the store own its policy independent of
/// hot-reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyRetentionPolicy {
    /// Default TTL applied to a fresh reservation (milliseconds).
    pub default_ttl_ms: u64,
    /// Hard upper bound on per-record TTL (milliseconds). Today
    /// only consulted at config-validate time; future per-binding
    /// `ttl_ms` overrides will saturate against this.
    pub max_ttl_ms: u64,
}

impl Default for IdempotencyRetentionPolicy {
    fn default() -> Self {
        Self {
            default_ttl_ms: 86_400_000, // 24h
            max_ttl_ms: 604_800_000,    // 7d
        }
    }
}

/// On-disk record encoded under
/// `idempotency/<scope_encoded>/<key>`. Serde shape is stable so
/// different gateway minor versions can read each other's records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Hash of the canonicalised request body. Sealed at
    /// reservation time.
    pub request_hash: [u8; 32],
    /// Discriminator — `in_flight` or `completed`.
    pub state: RecordState,
    /// Reservation UUID; opaque to operators, surfaces in audit
    /// events for traceability.
    pub reservation_id: Uuid,
    /// Cached envelope; `None` while the request is in flight.
    pub outcome: Option<CachedOutcome>,
    /// Tenant binding — re-validated on every read.
    pub tenant_id: String,
    /// Identity binding — BLAKE3 of canonical identity. Stored as
    /// hex to keep the JSON shape portable.
    pub identity_hash_hex: String,
    /// JSON-RPC method (informational; matched against scope on
    /// read for symmetry).
    pub method: String,
    /// Bound tool name.
    pub tool_name: String,
    /// RFC3339 timestamp of reservation. Used to compute the
    /// remaining-TTL on `complete` so the wall-clock expiry stays
    /// pinned.
    pub created_at: DateTime<Utc>,
    /// RFC3339 timestamp at which the record expires. Backends
    /// auto-expire via the TTL passed to `put`; this field is
    /// kept for audit + observability + the LWW completion path.
    pub expires_at: DateTime<Utc>,
    /// How many times this record has been replayed. Bumped each
    /// time a `Completed` outcome is returned.
    pub replay_count: u32,
}

/// In-flight vs terminal discriminator on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    InFlight,
    Completed,
}

/// Idempotency store backed by any
/// [`mcpg_cluster_api::KeyValueStore`] impl. The store owns its
/// retention policy; updates land via boot / hot-reload.
pub struct KvBackedIdempotencyStore {
    state: Arc<dyn mcpg_cluster_api::KeyValueStore>,
    policy: IdempotencyRetentionPolicy,
}

impl std::fmt::Debug for KvBackedIdempotencyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedIdempotencyStore")
            .field("policy", &self.policy)
            .finish()
    }
}

impl KvBackedIdempotencyStore {
    /// Bind the store to a concrete KV substrate + retention
    /// policy. The KV is typically the cluster coordinator's
    /// `key_value_store()` primitive.
    pub fn new(
        state: Arc<dyn mcpg_cluster_api::KeyValueStore>,
        policy: IdempotencyRetentionPolicy,
    ) -> Self {
        Self { state, policy }
    }

    /// In-process backing for tests (mirrors
    /// `KvBackedTaskStore::new_in_memory`).
    pub fn new_in_memory(policy: IdempotencyRetentionPolicy) -> Self {
        Self::new(
            Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()),
            policy,
        )
    }

    /// Convenience: in-memory + default policy.
    pub fn new_in_memory_default() -> Self {
        Self::new_in_memory(IdempotencyRetentionPolicy::default())
    }

    /// Compute the storage key for a `(scope, key)` pair. Layout:
    /// `idempotency/<blake3_16(scope)>/<key>` — short enough to
    /// keep keys reasonable, long enough that two distinct scopes
    /// don't collide in practice.
    fn storage_key(scope: &IdempotencyScope, key: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(scope.tenant_id.as_bytes());
        hasher.update(b":");
        hasher.update(scope.identity_hash.as_slice());
        hasher.update(b":");
        hasher.update(scope.method.as_bytes());
        hasher.update(b":");
        hasher.update(scope.tool_name.as_bytes());
        let digest = hasher.finalize();
        // First 16 bytes hex = 32 chars — collision probability
        // is overwhelmingly low for the scope cardinality we
        // expect (a typical operator has < 1000 tools × < 1000
        // tenants).
        let scope_hex = hex::encode(&digest.as_bytes()[..16]);
        format!("idempotency/{scope_hex}/{key}")
    }

    /// Storage prefix — exposed so a future `gc_expired_scan` impl
    /// can list-prefix.
    fn storage_prefix() -> &'static str {
        "idempotency/"
    }

    /// Encode an [`IdempotencyScope`]'s `identity_hash` as hex for
    /// the on-disk record.
    fn hex_identity(scope: &IdempotencyScope) -> String {
        hex::encode(scope.identity_hash)
    }

    /// Read the record at `storage_key`, validating that the
    /// stored `tenant_id` + `identity_hash_hex` match the
    /// requesting scope. Returns `Ok(None)` for legitimate misses
    /// AND for cross-scope mismatches (the latter is logged as a
    /// warn so an operator misconfiguring a key prefix doesn't
    /// silently leak record existence).
    async fn read_record(
        &self,
        scope: &IdempotencyScope,
        storage_key: &str,
    ) -> Result<Option<IdempotencyRecord>, IdempotencyError> {
        let entry = self
            .state
            .get(storage_key)
            .await
            .map_err(|e| IdempotencyError::Internal(format!("kv get: {e}")))?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let record: IdempotencyRecord = match serde_json::from_slice(&entry.bytes) {
            Ok(r) => r,
            Err(e) => {
                return Err(IdempotencyError::Internal(format!(
                    "decode IdempotencyRecord: {e}"
                )));
            }
        };
        let expected_identity = Self::hex_identity(scope);
        if record.tenant_id != scope.tenant_id
            || record.identity_hash_hex != expected_identity
            || record.method != scope.method
            || record.tool_name != scope.tool_name
        {
            tracing::warn!(
                storage_key = storage_key,
                stored_tenant = %record.tenant_id,
                request_tenant = %scope.tenant_id,
                "idempotency record scope mismatch — treating as NotFound"
            );
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Compute the remaining TTL between `now` and the record's
    /// `expires_at`, clamped to ≥ 1 ms so a put that lands at the
    /// expiration boundary doesn't reset to "no TTL".
    fn remaining_ttl(record: &IdempotencyRecord) -> Duration {
        let now = Utc::now();
        let remaining = (record.expires_at - now).num_milliseconds();
        if remaining <= 0 {
            Duration::from_millis(1)
        } else {
            Duration::from_millis(remaining as u64)
        }
    }
}

#[async_trait::async_trait]
impl IdempotencyStore for KvBackedIdempotencyStore {
    async fn peek(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        request_hash: &[u8; 32],
    ) -> Result<Option<PeekOutcome>, IdempotencyError> {
        let storage_key = Self::storage_key(scope, key);
        let Some(existing) = self.read_record(scope, &storage_key).await? else {
            return Ok(None);
        };
        if existing.request_hash != *request_hash {
            return Ok(Some(PeekOutcome::Conflict {
                stored_request_hash: existing.request_hash,
            }));
        }
        match existing.state {
            RecordState::InFlight => Ok(Some(PeekOutcome::InFlight {
                started_at: SystemTime::from(existing.created_at),
            })),
            RecordState::Completed => {
                let envelope = existing.outcome.clone().ok_or_else(|| {
                    IdempotencyError::Internal("completed record missing envelope".to_owned())
                })?;
                let mut bumped = envelope;
                bumped.replay_count = existing.replay_count.saturating_add(1);
                // Persist the bumped counter best-effort (LWW).
                let mut updated = existing.clone();
                updated.replay_count = updated.replay_count.saturating_add(1);
                let bytes = serde_json::to_vec(&updated).map_err(|e| {
                    IdempotencyError::Internal(format!("encode IdempotencyRecord: {e}"))
                })?;
                let ttl = Self::remaining_ttl(&updated);
                let _ = self
                    .state
                    .put(&storage_key, bytes::Bytes::from(bytes), Some(ttl))
                    .await;
                Ok(Some(PeekOutcome::Completed {
                    outcome: bumped,
                    completed_at: SystemTime::from(existing.created_at),
                }))
            }
        }
    }

    async fn reserve_or_get(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        request_hash: &[u8; 32],
        ttl_override: Option<Duration>,
    ) -> Result<ReservationOutcome, IdempotencyError> {
        let storage_key = Self::storage_key(scope, key);
        // First phase — atomic GET of any existing record.
        if let Some(existing) = self.read_record(scope, &storage_key).await? {
            // Body-hash invariance check applies regardless of
            // state (a different body during InFlight is also a
            // conflict, not a coincident retry).
            if existing.request_hash != *request_hash {
                return Ok(ReservationOutcome::Conflict {
                    stored_request_hash: existing.request_hash,
                });
            }
            return match existing.state {
                RecordState::InFlight => Ok(ReservationOutcome::InFlight {
                    started_at: SystemTime::from(existing.created_at),
                }),
                RecordState::Completed => {
                    let outcome = match existing.outcome.clone() {
                        Some(mut cached) => {
                            cached.replay_count = existing.replay_count.saturating_add(1);
                            cached
                        }
                        // A `Completed` record without an envelope
                        // is corrupt — surface as Internal so the
                        // dispatcher can fall through.
                        None => {
                            return Err(IdempotencyError::Internal(
                                "completed record missing envelope".to_owned(),
                            ));
                        }
                    };
                    // Persist the bumped replay_count best-effort
                    // (LWW). The cached return value carries the
                    // correct count regardless.
                    let mut updated = existing.clone();
                    updated.replay_count = updated.replay_count.saturating_add(1);
                    let bytes = serde_json::to_vec(&updated).map_err(|e| {
                        IdempotencyError::Internal(format!("encode IdempotencyRecord: {e}"))
                    })?;
                    let ttl = Self::remaining_ttl(&updated);
                    let _ = self
                        .state
                        .put(&storage_key, bytes::Bytes::from(bytes), Some(ttl))
                        .await;
                    Ok(ReservationOutcome::Completed {
                        outcome,
                        completed_at: SystemTime::from(existing.created_at),
                    })
                }
            };
        }

        // Second phase — claim the slot. The configured default TTL
        // applies unless the caller passed a tighter override
        // (tasks/create binds idempotency lifetime to the task's
        // TTL — `min(idempotency_ttl, task_ttl)` — so the record
        // never outlives the task it points at).
        let now = Utc::now();
        let policy_ttl_ms = self.policy.default_ttl_ms;
        let ttl_ms = match ttl_override {
            Some(override_dur) => {
                let override_ms = override_dur.as_millis() as u64;
                policy_ttl_ms.min(override_ms.max(1))
            }
            None => policy_ttl_ms,
        };
        let expires_at = now
            + chrono::Duration::milliseconds(ttl_ms as i64).max(chrono::Duration::milliseconds(1));
        let reservation_id = Uuid::new_v4();
        let record = IdempotencyRecord {
            request_hash: *request_hash,
            state: RecordState::InFlight,
            reservation_id,
            outcome: None,
            tenant_id: scope.tenant_id.clone(),
            identity_hash_hex: Self::hex_identity(scope),
            method: scope.method.clone(),
            tool_name: scope.tool_name.clone(),
            created_at: now,
            expires_at,
            replay_count: 0,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| IdempotencyError::Internal(format!("encode IdempotencyRecord: {e}")))?;
        let claim_ttl = Some(Duration::from_millis(ttl_ms.max(1)));

        // Atomic single-winner claim. `put_if_absent` guarantees that of
        // N concurrent racers across N replicas, exactly one observes
        // `true` — so a non-idempotent tool (payment, provisioning)
        // dispatches exactly once even under a simultaneous cross-replica
        // retry. The tiny bounded loop absorbs the rare race where we lose
        // the claim but the winner's record then expires/clears before our
        // classifying read.
        for _ in 0..3 {
            let claimed = self
                .state
                .put_if_absent(&storage_key, bytes::Bytes::from(bytes.clone()), claim_ttl)
                .await
                .map_err(|e| IdempotencyError::Internal(format!("kv put_if_absent: {e}")))?;
            if claimed {
                return Ok(ReservationOutcome::Reserved { reservation_id });
            }
            // Lost the claim — classify the winner's record.
            match self.read_record(scope, &storage_key).await? {
                Some(observed) if observed.request_hash != *request_hash => {
                    return Ok(ReservationOutcome::Conflict {
                        stored_request_hash: observed.request_hash,
                    });
                }
                Some(observed) => {
                    return match observed.state {
                        RecordState::InFlight => Ok(ReservationOutcome::InFlight {
                            started_at: SystemTime::from(observed.created_at),
                        }),
                        RecordState::Completed => {
                            let outcome = observed.outcome.clone().ok_or_else(|| {
                                IdempotencyError::Internal(
                                    "completed record missing envelope".to_owned(),
                                )
                            })?;
                            Ok(ReservationOutcome::Completed {
                                outcome,
                                completed_at: SystemTime::from(observed.created_at),
                            })
                        }
                    };
                }
                // Winner's record vanished between our failed claim and
                // this read (TTL/delete race) — retry the claim.
                None => continue,
            }
        }
        // Pathological churn (key created+cleared repeatedly under our
        // feet). Surface as InFlight so the caller can retry rather than
        // risk a double-dispatch.
        Ok(ReservationOutcome::InFlight {
            started_at: SystemTime::from(now),
        })
    }

    async fn complete(
        &self,
        scope: &IdempotencyScope,
        key: &str,
        outcome: CachedOutcome,
    ) -> Result<(), IdempotencyError> {
        let storage_key = Self::storage_key(scope, key);
        let Some(mut record) = self.read_record(scope, &storage_key).await? else {
            // Reservation evaporated (TTL race / cluster mishap).
            // Re-create the record in `Completed` state so future
            // retries replay; lose the original `created_at` but
            // that's the lesser of two evils.
            let now = Utc::now();
            let ttl_ms = self.policy.default_ttl_ms;
            let new = IdempotencyRecord {
                request_hash: [0u8; 32], // unknown — fresh write
                state: RecordState::Completed,
                reservation_id: Uuid::new_v4(),
                outcome: Some(outcome),
                tenant_id: scope.tenant_id.clone(),
                identity_hash_hex: Self::hex_identity(scope),
                method: scope.method.clone(),
                tool_name: scope.tool_name.clone(),
                created_at: now,
                expires_at: now + chrono::Duration::milliseconds(ttl_ms as i64),
                replay_count: 0,
            };
            let bytes = serde_json::to_vec(&new).map_err(|e| {
                IdempotencyError::Internal(format!("encode IdempotencyRecord: {e}"))
            })?;
            return self
                .state
                .put(
                    &storage_key,
                    bytes::Bytes::from(bytes),
                    Some(Duration::from_millis(ttl_ms.max(1))),
                )
                .await
                .map_err(|e| IdempotencyError::Internal(format!("kv put: {e}")));
        };
        record.state = RecordState::Completed;
        record.outcome = Some(outcome);
        let ttl = Self::remaining_ttl(&record);
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| IdempotencyError::Internal(format!("encode IdempotencyRecord: {e}")))?;
        self.state
            .put(&storage_key, bytes::Bytes::from(bytes), Some(ttl))
            .await
            .map_err(|e| IdempotencyError::Internal(format!("kv put: {e}")))
    }

    async fn gc_expired(&self) -> usize {
        // KV backends auto-expire via the TTL passed to `put`;
        // mirror `KvBackedTaskStore::gc_expired_tasks` and return
        // 0. A future "no native TTL" backend can scan
        // `Self::storage_prefix()` and delete on `expires_at`.
        let _ = Self::storage_prefix();
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> KvBackedIdempotencyStore {
        KvBackedIdempotencyStore::new_in_memory_default()
    }

    fn scope() -> IdempotencyScope {
        IdempotencyScope {
            tenant_id: "tenant-a".to_owned(),
            identity_hash: [1u8; 32],
            method: "tools/call".to_owned(),
            tool_name: "charge".to_owned(),
        }
    }

    fn other_tenant_scope() -> IdempotencyScope {
        IdempotencyScope {
            tenant_id: "tenant-b".to_owned(),
            ..scope()
        }
    }

    fn outcome(envelope: serde_json::Value) -> CachedOutcome {
        CachedOutcome {
            envelope,
            original_request_id: json!(1),
            original_correlation_id: String::new(),
            replay_count: 0,
            payload_truncated: false,
        }
    }

    #[tokio::test]
    async fn reserve_returns_reserved_for_first_call() {
        let store = store();
        let res = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        assert!(matches!(res, ReservationOutcome::Reserved { .. }));
    }

    #[tokio::test]
    async fn second_call_with_same_key_returns_in_flight() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        let res = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        assert!(
            matches!(res, ReservationOutcome::InFlight { .. }),
            "expected InFlight, got {res:?}"
        );
    }

    #[tokio::test]
    async fn reserve_then_complete_returns_completed_on_replay() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        store
            .complete(
                &scope(),
                "key-1",
                outcome(json!({"content": [], "isError": false})),
            )
            .await
            .unwrap();
        let res = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        match res {
            ReservationOutcome::Completed { outcome, .. } => {
                assert_eq!(outcome.envelope["isError"], false);
                assert!(outcome.replay_count >= 1, "replay_count must bump");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_mismatch_returns_conflict() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        let res = store
            .reserve_or_get(&scope(), "key-1", &[8u8; 32], None)
            .await
            .unwrap();
        assert!(
            matches!(res, ReservationOutcome::Conflict { .. }),
            "expected Conflict, got {res:?}"
        );
    }

    #[tokio::test]
    async fn cross_tenant_lookup_treats_record_as_missing() {
        // Defense-in-depth: a record reserved under tenant-a
        // must NOT be observable from tenant-b even if the
        // operator misconfigured a key prefix. Storage key
        // already incorporates tenant via scope_encoded so the
        // two tenants land in different keys; the record-level
        // re-validation guards against a future operator
        // narrowing the scope encoding.
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        let res = store
            .reserve_or_get(&other_tenant_scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        // Different scope ⇒ different storage key ⇒ NotFound,
        // surfacing as a fresh `Reserved`.
        assert!(matches!(res, ReservationOutcome::Reserved { .. }));
    }

    #[tokio::test]
    async fn replay_count_increments_on_each_replay() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        store
            .complete(&scope(), "key-1", outcome(json!({"content": []})))
            .await
            .unwrap();
        let mut counts = Vec::new();
        for _ in 0..3 {
            let res = store
                .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
                .await
                .unwrap();
            if let ReservationOutcome::Completed { outcome, .. } = res {
                counts.push(outcome.replay_count);
            }
        }
        // Three replays back-to-back: count must monotonically
        // increase. Best-effort LWW means we don't insist on
        // exactly [1,2,3], just that it climbs.
        assert!(counts[2] > counts[0], "replay_count climbed: {counts:?}");
    }

    #[tokio::test]
    async fn ttl_remaining_is_capped_to_at_least_one_ms() {
        let mut record = IdempotencyRecord {
            request_hash: [0; 32],
            state: RecordState::Completed,
            reservation_id: Uuid::new_v4(),
            outcome: None,
            tenant_id: "t".to_owned(),
            identity_hash_hex: hex::encode([0u8; 32]),
            method: "tools/call".to_owned(),
            tool_name: "x".to_owned(),
            created_at: Utc::now(),
            expires_at: Utc::now() - chrono::Duration::seconds(60),
            replay_count: 0,
        };
        // expired record → 1 ms floor (not "no TTL").
        let ttl = KvBackedIdempotencyStore::remaining_ttl(&record);
        assert_eq!(ttl, Duration::from_millis(1));
        record.expires_at = Utc::now() + chrono::Duration::seconds(60);
        let ttl = KvBackedIdempotencyStore::remaining_ttl(&record);
        assert!(
            ttl.as_secs() >= 59 && ttl.as_secs() <= 61,
            "ttl in expected window: {ttl:?}"
        );
    }

    #[tokio::test]
    async fn peek_returns_none_for_clean_miss() {
        let store = store();
        let res = store
            .peek(&scope(), "key-missing", &[7u8; 32])
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn peek_returns_completed_for_replay_hits() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        store
            .complete(&scope(), "key-1", outcome(json!({"ok": true})))
            .await
            .unwrap();
        let res = store.peek(&scope(), "key-1", &[7u8; 32]).await.unwrap();
        match res {
            Some(PeekOutcome::Completed { outcome, .. }) => {
                assert_eq!(outcome.envelope["ok"], true);
                assert!(outcome.replay_count >= 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn peek_returns_conflict_on_body_mismatch() {
        let store = store();
        let _ = store
            .reserve_or_get(&scope(), "key-1", &[7u8; 32], None)
            .await
            .unwrap();
        let res = store.peek(&scope(), "key-1", &[8u8; 32]).await.unwrap();
        assert!(matches!(res, Some(PeekOutcome::Conflict { .. })));
    }

    #[tokio::test]
    async fn concurrent_reserves_serialise_one_winner() {
        // With the atomic `put_if_absent` substrate, two simultaneous
        // reservations sharing one KV resolve to EXACTLY ONE `Reserved`
        // (the single winner); the loser observes the winner's `InFlight`
        // record.
        let store = std::sync::Arc::new(store());
        let s1 = store.clone();
        let s2 = store.clone();
        let h1 = tokio::spawn(async move {
            s1.reserve_or_get(&scope(), "key-1", &[42u8; 32], None)
                .await
                .unwrap()
        });
        let h2 = tokio::spawn(async move {
            s2.reserve_or_get(&scope(), "key-1", &[42u8; 32], None)
                .await
                .unwrap()
        });
        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();
        let reserved = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, ReservationOutcome::Reserved { .. }))
            .count();
        let inflight = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, ReservationOutcome::InFlight { .. }))
            .count();
        assert_eq!(
            reserved, 1,
            "exactly one racer must win Reserved: {r1:?} / {r2:?}"
        );
        assert_eq!(
            inflight, 1,
            "the loser must observe InFlight, not a second Reserved: {r1:?} / {r2:?}"
        );
    }
}
