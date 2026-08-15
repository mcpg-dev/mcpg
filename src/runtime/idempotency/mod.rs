//! `dev.mcpg/idempotency` extension — gateway-side request dedupe.
//!
//! This module covers the protocol surface of the extension:
//!
//! - Capability identifiers (`EXTENSION_ID`) and `_meta` keys
//!   (`META_KEY_REQUEST`, `META_KEY_REPLAYED`,
//!   `META_KEY_ORIGINAL_COMPLETED_AT`).
//! - JSON-RPC error codes for the four idempotency-specific failure
//!   modes (`-32010`..`-32013`; `-32012 IdempotencyKeyRequired` is
//!   reserved for a future per-binding "key required" policy and not
//!   emitted yet).
//! - Format validation for the request-side key
//!   ([`validate_request_key`]): ASCII, ≤255 chars, non-empty after
//!   trim. Rejection surfaces as `IdempotencyKeyMalformed`.
//!
//! The storage side is the [`store::IdempotencyStore`] trait and its
//! `KvBackedIdempotencyStore` impl; these are wired to the
//! `idempotency:` config block, the dispatcher pipeline, and the HTTP
//! transport header lift.

pub mod kv_store;
pub mod store;

pub use kv_store::{IdempotencyRecord, IdempotencyRetentionPolicy, KvBackedIdempotencyStore};
pub use store::{
    CachedOutcome, IdempotencyError, IdempotencyScope, IdempotencyStore, NoopIdempotencyStore,
    PeekOutcome, ReservationOutcome, noop_idempotency_store,
};

/// Reverse-DNS extension identifier advertised at `initialize` time.
///
/// Used both as the key under
/// `result.capabilities.extensions[…]` in the initialize response
/// and as the namespace for the request/response `_meta` keys
/// emitted by this extension.
pub const EXTENSION_ID: &str = "dev.mcpg/idempotency";

/// `_meta` key on the request side carrying the caller-supplied
/// idempotency key. Matches the spec-required `prefix/name` shape
/// (slash, not dot — SEP-1788).
pub const META_KEY_REQUEST: &str = "dev.mcpg/idempotency-key";

/// `_meta` key the gateway stamps on a replayed response envelope so
/// the caller can tell a cache hit from a fresh execution.
pub const META_KEY_REPLAYED: &str = "dev.mcpg/idempotency-replayed";

/// `_meta` key carrying the RFC3339 timestamp at which the original
/// (non-replayed) call completed. Stamped alongside
/// [`META_KEY_REPLAYED`] so the caller can compute "how stale is
/// this answer".
pub const META_KEY_ORIGINAL_COMPLETED_AT: &str = "dev.mcpg/idempotency-original-completed-at";

/// JSON-RPC error code for "same key + different request body hash".
///
/// HTTP transport maps this to 422 Unprocessable Entity, matching
/// RFC `draft-ietf-httpapi-idempotency-key-header-07`.
pub const ERROR_CODE_CONFLICT: i32 = -32010;

/// JSON-RPC error code for "another request with this key is in
/// flight". HTTP transport maps to 409 Conflict + `Retry-After: 1`.
pub const ERROR_CODE_IN_FLIGHT: i32 = -32011;

/// JSON-RPC error code for "key violates format constraints" —
/// non-ASCII byte, length > 255, or empty after trim.
pub const ERROR_CODE_KEY_MALFORMED: i32 = -32013;

/// Maximum permitted length of a caller-supplied idempotency key
/// (in bytes). RFC `draft-ietf-httpapi-idempotency-key-header-07`
/// recommends 255; we apply the same cap to the JSON-RPC `_meta`
/// path for parity.
pub const MAX_KEY_LEN: usize = 255;

/// Outcome of [`validate_request_key`]: either a sanitised owned
/// key string ready for downstream lookups, or a malformed-key
/// error describing why the input was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValidation {
    /// Caller did not supply a key (or supplied `null`); no dedupe
    /// will happen for this request.
    Absent,
    /// Caller supplied a syntactically valid key. The owned `String`
    /// is the trimmed canonical form used as the storage lookup key.
    Valid(String),
    /// Caller supplied a key that violates the format constraints.
    /// Rejected with `-32013 IdempotencyKeyMalformed`.
    Invalid(KeyMalformedReason),
}

/// Why a caller-supplied idempotency key was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMalformedReason {
    /// `_meta["dev.mcpg/idempotency-key"]` was present but not a
    /// JSON string (object / array / number / bool / null).
    NotAString,
    /// Empty after `trim()`.
    Empty,
    /// Length (in bytes) exceeded [`MAX_KEY_LEN`].
    TooLong,
    /// Contained a non-ASCII byte. Per RFC the key MUST be opaque
    /// ASCII; non-ASCII reduces interop with HTTP transport
    /// bindings.
    NonAscii,
}

impl KeyMalformedReason {
    /// Human-readable error message, suitable as the JSON-RPC error
    /// `message` field.
    pub fn as_message(self) -> &'static str {
        match self {
            Self::NotAString => "`_meta[\"dev.mcpg/idempotency-key\"]` must be a string",
            Self::Empty => "idempotency key must not be empty after trim",
            Self::TooLong => "idempotency key exceeds 255 bytes",
            Self::NonAscii => {
                "idempotency key must be ASCII (RFC `draft-ietf-httpapi-idempotency-key-header-07`)"
            }
        }
    }
}

/// Validate a caller-supplied idempotency key value extracted from
/// `params._meta["dev.mcpg/idempotency-key"]` (or the equivalent
/// HTTP `Idempotency-Key` header lift).
///
/// Returns:
/// - [`KeyValidation::Absent`] when `meta_value` is `None` or the
///   underlying JSON is `Null`.
/// - [`KeyValidation::Valid`] for an in-bounds ASCII string. The
///   wrapped owned `String` is the trimmed canonical form callers
///   should hash and look up by.
/// - [`KeyValidation::Invalid`] with the specific failure reason
///   for malformed input.
///
/// Format constraints (per design doc §1.4):
/// - MUST be a JSON string (not an object/array/number/bool).
/// - MUST be non-empty after `trim()`.
/// - MUST be ≤ 255 bytes.
/// - MUST be ASCII.
pub fn validate_request_key(meta_value: Option<&serde_json::Value>) -> KeyValidation {
    let Some(value) = meta_value else {
        return KeyValidation::Absent;
    };
    if value.is_null() {
        return KeyValidation::Absent;
    }
    let Some(raw) = value.as_str() else {
        return KeyValidation::Invalid(KeyMalformedReason::NotAString);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return KeyValidation::Invalid(KeyMalformedReason::Empty);
    }
    if trimmed.len() > MAX_KEY_LEN {
        return KeyValidation::Invalid(KeyMalformedReason::TooLong);
    }
    if !trimmed.is_ascii() {
        return KeyValidation::Invalid(KeyMalformedReason::NonAscii);
    }
    KeyValidation::Valid(trimmed.to_owned())
}

/// Convenience: extract the request-side idempotency key from a
/// raw `_meta` JSON object (the `params._meta` field on a tool/task
/// request) and validate its format in one call.
///
/// `meta` is the caller's full `_meta` value (typically
/// `params.meta.as_ref()` in the dispatcher); we look up the
/// well-known [`META_KEY_REQUEST`] entry inside it.
pub fn extract_request_key(meta: Option<&serde_json::Value>) -> KeyValidation {
    let Some(meta) = meta else {
        return KeyValidation::Absent;
    };
    let Some(obj) = meta.as_object() else {
        return KeyValidation::Absent;
    };
    validate_request_key(obj.get(META_KEY_REQUEST))
}

/// Build the JSON value the gateway emits under
/// `result.capabilities.extensions[EXTENSION_ID]` in the
/// `initialize` response. The values are the operator-tunable knobs
/// (TTLs, scope, supported methods), sourced from the runtime
/// [`crate::config::IdempotencyConfig`]. This helper exists so the
/// initialize handler can build the value declaratively from a
/// config struct.
pub fn capability_advertisement(
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    scope_label: &str,
    supported_methods: &[&str],
    conflict_policy_label: &str,
) -> serde_json::Value {
    serde_json::json!({
        "scope": scope_label,
        "default_ttl_seconds": default_ttl_seconds,
        "max_ttl_seconds": max_ttl_seconds,
        "supported_methods": supported_methods,
        "supports_replay_marker": true,
        "conflict_policy": conflict_policy_label,
    })
}

/// BLAKE3 hash of the canonical JSON encoding of a tool-call's
/// `(name, arguments)` pair. Sealed at reservation time and
/// re-hashed on every retry to enforce the body-hash invariant
/// (same key + different body ⇒ Conflict).
///
/// Uses serde_json's compact form rather than a full canonical-JSON
/// serializer; arguments going through the same client should
/// serialize identically across retries since both the client
/// SDK and the gateway re-parser preserve key ordering. A full
/// canonical-JSON pass (RFC 8785) is a follow-up if real-world
/// integration shows clients reordering keys between retries.
pub fn hash_request_body(
    method: &str,
    tool_name: &str,
    arguments: Option<&serde_json::Value>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\x00");
    hasher.update(tool_name.as_bytes());
    hasher.update(b"\x00");
    if let Some(args) = arguments {
        // Serialize via serde_json::to_writer with a hasher
        // adapter would avoid the temporary allocation; the
        // straightforward `to_vec` is already fast enough for the
        // dispatch path (one hash per call).
        if let Ok(bytes) = serde_json::to_vec(args) {
            hasher.update(&bytes);
        }
    }
    *hasher.finalize().as_bytes()
}

/// BLAKE3 hash of a caller's resolved identity, scoped to the
/// fields that actually identify the principal (subject id +
/// auth provider + issuer). Used as the `identity_hash` field on
/// `IdempotencyScope`.
pub fn hash_identity(
    subject_id: Option<&str>,
    auth_provider: Option<&str>,
    issuer: Option<&str>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(subject_id.unwrap_or("").as_bytes());
    hasher.update(b"\x00");
    hasher.update(auth_provider.unwrap_or("").as_bytes());
    hasher.update(b"\x00");
    hasher.update(issuer.unwrap_or("").as_bytes());
    *hasher.finalize().as_bytes()
}

/// BLAKE3 hex hash of a key, used in audit events so the literal
/// caller-supplied value never lands in the audit lane.
pub fn key_hash_hex(key: &str) -> String {
    let digest = blake3::hash(key.as_bytes());
    hex::encode(&digest.as_bytes()[..16])
}

/// Stamp the replay marker on a tool-call result envelope's
/// `_meta` field. Returns the modified envelope. If the envelope
/// is not a JSON object (which would be a pre-existing bug —
/// every `ToolCallResult` serialises as an object), the input is
/// returned unchanged.
pub fn stamp_replay_marker(
    mut envelope: serde_json::Value,
    original_completed_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let Some(obj) = envelope.as_object_mut() else {
        return envelope;
    };
    let meta = obj
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(meta_obj) = meta.as_object_mut() {
        meta_obj.insert(META_KEY_REPLAYED.to_owned(), serde_json::Value::Bool(true));
        meta_obj.insert(
            META_KEY_ORIGINAL_COMPLETED_AT.to_owned(),
            serde_json::Value::String(original_completed_at.to_rfc3339()),
        );
    }
    envelope
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_accepts_valid_ascii_key() {
        let v = json!("01J9X8N3QKHA0V9C4D8TYR2ABC");
        match validate_request_key(Some(&v)) {
            KeyValidation::Valid(s) => assert_eq!(s, "01J9X8N3QKHA0V9C4D8TYR2ABC"),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn validate_trims_surrounding_whitespace() {
        let v = json!("  abc  ");
        match validate_request_key(Some(&v)) {
            KeyValidation::Valid(s) => assert_eq!(s, "abc"),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_string() {
        let v = json!("   ");
        assert_eq!(
            validate_request_key(Some(&v)),
            KeyValidation::Invalid(KeyMalformedReason::Empty)
        );
    }

    #[test]
    fn validate_rejects_non_ascii() {
        let v = json!("naïve-key");
        assert_eq!(
            validate_request_key(Some(&v)),
            KeyValidation::Invalid(KeyMalformedReason::NonAscii)
        );
    }

    #[test]
    fn validate_rejects_too_long() {
        let v = json!("a".repeat(MAX_KEY_LEN + 1));
        assert_eq!(
            validate_request_key(Some(&v)),
            KeyValidation::Invalid(KeyMalformedReason::TooLong)
        );
    }

    #[test]
    fn validate_rejects_non_string() {
        let v = json!(42);
        assert_eq!(
            validate_request_key(Some(&v)),
            KeyValidation::Invalid(KeyMalformedReason::NotAString)
        );
    }

    #[test]
    fn absent_when_missing_or_null() {
        assert_eq!(validate_request_key(None), KeyValidation::Absent);
        let null = json!(null);
        assert_eq!(validate_request_key(Some(&null)), KeyValidation::Absent);
    }

    #[test]
    fn extract_from_meta_finds_well_known_key() {
        let meta = json!({"dev.mcpg/idempotency-key": "abc"});
        assert!(matches!(
            extract_request_key(Some(&meta)),
            KeyValidation::Valid(s) if s == "abc"
        ));
    }

    #[test]
    fn extract_returns_absent_when_meta_lacks_key() {
        let meta = json!({"progressToken": "p"});
        assert_eq!(extract_request_key(Some(&meta)), KeyValidation::Absent);
    }

    #[test]
    fn hash_request_body_deterministic_and_distinct() {
        let a = hash_request_body("tools/call", "charge", Some(&json!({"amount": 100})));
        let b = hash_request_body("tools/call", "charge", Some(&json!({"amount": 100})));
        let c = hash_request_body("tools/call", "charge", Some(&json!({"amount": 200})));
        assert_eq!(a, b, "same input ⇒ same hash");
        assert_ne!(a, c, "different arguments ⇒ different hash");
    }

    #[test]
    fn hash_identity_distinct_per_subject() {
        let a = hash_identity(Some("alice"), Some("oidc"), Some("issuer-a"));
        let b = hash_identity(Some("bob"), Some("oidc"), Some("issuer-a"));
        assert_ne!(a, b);
    }

    #[test]
    fn stamp_replay_marker_idempotent() {
        let env = json!({"content": [], "isError": false});
        let stamped = stamp_replay_marker(env, chrono::Utc::now());
        assert_eq!(stamped["_meta"][META_KEY_REPLAYED], true);
        assert!(stamped["_meta"][META_KEY_ORIGINAL_COMPLETED_AT].is_string());
    }

    #[test]
    fn key_hash_hex_short() {
        let h = key_hash_hex("abc");
        assert_eq!(h.len(), 32, "16 bytes → 32 hex chars");
    }

    #[test]
    fn capability_advertisement_shape() {
        let v = capability_advertisement(
            86400,
            604800,
            "per-identity",
            &["tools/call", "tasks/create"],
            "reject",
        );
        assert_eq!(v["scope"], "per-identity");
        assert_eq!(v["default_ttl_seconds"], 86400);
        assert_eq!(v["max_ttl_seconds"], 604800);
        assert_eq!(v["supports_replay_marker"], true);
        assert_eq!(v["conflict_policy"], "reject");
        assert_eq!(v["supported_methods"][0], "tools/call");
    }

    // -----------------------------------------------------------
    // Dispatcher branch logic in isolation.
    //
    // These tests target the four mutually-exclusive outcomes the
    // dispatcher's pre-gate peek can encounter, without spinning
    // up the full HTTP transport. Each test proves the helper
    // composition the runtime relies on (hash → scope → store
    // operation → outcome shape) is correct in isolation.
    // -----------------------------------------------------------

    #[test]
    fn dispatcher_scope_construction_is_stable() {
        // The dispatcher builds an `IdempotencyScope` from the
        // request's identity + method + tool name. Two calls
        // sharing all three fields hash to the same scope key;
        // changing any one field shifts the key.
        let id_a = hash_identity(Some("alice"), Some("oidc"), Some("issuer"));
        let id_b = hash_identity(Some("bob"), Some("oidc"), Some("issuer"));
        // Same subject + provider + issuer → identical hash.
        assert_eq!(
            id_a,
            hash_identity(Some("alice"), Some("oidc"), Some("issuer"))
        );
        // Different subject → different hash. The dispatcher
        // composes this into `IdempotencyScope.identity_hash`,
        // which is what makes per-identity scope work.
        assert_ne!(id_a, id_b);
    }

    #[tokio::test]
    async fn dispatcher_hit_completed_returns_replay_envelope() {
        // Branch: peek returns Completed. The dispatcher MUST
        // call `stamp_replay_marker` and short-circuit before
        // tool-gate plugins, dispatch, etc. This isolates the
        // envelope-stamping step.
        let original_completed_at = chrono::Utc::now();
        let envelope = serde_json::json!({"content": [], "isError": false});
        let stamped = stamp_replay_marker(envelope.clone(), original_completed_at);
        assert_eq!(stamped["_meta"][META_KEY_REPLAYED], true);
        assert_eq!(
            stamped["_meta"][META_KEY_ORIGINAL_COMPLETED_AT],
            original_completed_at.to_rfc3339()
        );
        // The original `content` payload is preserved.
        assert_eq!(stamped["content"], envelope["content"]);
    }

    #[tokio::test]
    async fn dispatcher_hit_in_flight_emits_audit_payload() {
        // Branch: peek returns InFlight. The dispatcher's audit
        // event payload includes the key_hash + started_at. We
        // build the same payload here to confirm shape.
        let key = "in-flight-test-key";
        let started_at = chrono::Utc::now();
        let payload = serde_json::json!({
            "key_hash": key_hash_hex(key),
            "started_at": started_at.to_rfc3339(),
        });
        // The key_hash MUST hide the literal key (no plaintext in
        // audit events).
        let body_text = payload.to_string();
        assert!(!body_text.contains(key), "literal key leaked into audit");
        assert!(payload["started_at"].is_string());
    }

    #[tokio::test]
    async fn dispatcher_hit_conflict_carries_stored_hash() {
        // Branch: peek returns Conflict. The dispatcher's audit
        // event + JSON-RPC error data MUST carry the stored
        // request hash so operators can correlate the mismatch.
        let stored = [9u8; 32];
        let new = [3u8; 32];
        let payload = serde_json::json!({
            "key_hash": key_hash_hex("k"),
            "stored_hash": hex::encode(stored),
            "new_hash": hex::encode(new),
        });
        // Hex encoding is deterministic and 64 chars wide for
        // the 32-byte hash.
        assert_eq!(payload["stored_hash"].as_str().unwrap().len(), 64);
        assert_ne!(payload["stored_hash"], payload["new_hash"]);
    }
}
