//! MRTR `requestState` codec.
//!
//! Encodes / decodes the opaque `requestState` blob carried on
//! [`InputRequiredResult`] and echoed back in the resumption
//! request's `_meta.io.modelcontextprotocol/requestState`.
//!
//! ## Hybrid scheme
//!
//! Two encoding paths, picked by payload size:
//!
//! - **Encrypted inline** (`"c.<base64url>"`) — payloads ≤ 8 KiB.
//!   ChaCha20-Poly1305 AEAD over the payload with a 12-byte
//!   randomly-minted nonce. The wire form is
//!   `"c."` + base64url-no-pad(`nonce || ciphertext`). Tamper-
//!   evident (AEAD), stateless (no KV lookup), small enough for
//!   ~100-byte pipeline-resumption blobs to round-trip in a
//!   request header without bloat.
//!
//! - **KV-store handle** (`"h.<uuid>"`) — payloads > 8 KiB. The
//!   handle is a random v4 UUID; the actual payload is stored via
//!   [`RequestStateStore`]. Lookup is one Get per resumption.
//!   Used when the inline form would push the resumption request
//!   over reasonable size limits.
//!
//! The 8 KiB threshold is conservative — it leaves headroom for
//! the rest of the request body and any HTTP header overhead.
//!
//! ## Encryption-key sourcing
//!
//! `RequestStateCodec::new` takes a 32-byte key directly. The
//! boot wiring sources the key from
//! `mcp.configurations.request_state.encryption_key` (base64-encoded
//! 32-byte ChaCha20-Poly1305 key); when unset, it generates an
//! ephemeral key at process start and logs a WARN telling the
//! operator that resumptions won't survive a gateway restart.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use parking_lot::Mutex;
use uuid::Uuid;

/// Default inline-payload threshold (bytes). Payloads larger than
/// this fall through to the KV-handle path.
pub const DEFAULT_INLINE_THRESHOLD_BYTES: usize = 8 * 1024;

/// Wire-prefix marker for encrypted-inline encoded payloads.
const PREFIX_INLINE: &str = "c.";
/// Wire-prefix marker for KV-store handle payloads.
const PREFIX_HANDLE: &str = "h.";

/// Failure modes the codec can surface to callers.
#[derive(Debug, Clone)]
pub enum RequestStateError {
    /// Encoded blob does not start with `"c."` or `"h."`.
    InvalidPrefix(String),
    /// Base64 / UUID parse failed, or ciphertext too short.
    InvalidPayload(String),
    /// AEAD authentication tag did not verify (tampered ciphertext,
    /// wrong key, or the presenter's owner-binding does not match the
    /// associated data the blob was minted under).
    AuthenticationFailed,
    /// The handle didn't resolve in the KV store.
    HandleNotFound(String),
    /// An inline blob was presented after it was already consumed —
    /// a single-use replay. Distinct from `AuthenticationFailed`: the
    /// blob is cryptographically valid but has been spent.
    Replayed,
    /// Underlying store error.
    Store(String),
}

impl std::fmt::Display for RequestStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix(got) => write!(
                f,
                "invalid requestState prefix: expected 'c.' or 'h.', got `{got:?}`"
            ),
            Self::InvalidPayload(detail) => {
                write!(f, "invalid requestState payload: {detail}")
            }
            Self::AuthenticationFailed => write!(
                f,
                "requestState ciphertext failed AEAD verification — \
                 the blob was tampered with or the gateway's encryption key has rotated"
            ),
            Self::HandleNotFound(handle) => write!(
                f,
                "requestState handle `{handle}` not found in the KV store"
            ),
            Self::Replayed => write!(
                f,
                "requestState blob has already been consumed — inline resumption blobs are single-use"
            ),
            Self::Store(detail) => write!(f, "requestState store error: {detail}"),
        }
    }
}

impl std::error::Error for RequestStateError {}

/// Pluggable KV store backing the handle-encoded (>8 KiB) payloads.
///
/// In the gateway this is `KvBackedRequestStateStore`
/// (`crate::runtime::request_state_store`) over the cluster coordinator
/// KV, so a large-payload modern suspension resumes on any replica and
/// across restarts. Tests / dev can use the
/// [`InMemoryRequestStateStore`] below.
#[async_trait]
pub trait RequestStateStore: Send + Sync {
    async fn put(&self, handle: &str, payload: &[u8]) -> Result<(), RequestStateError>;
    async fn get(&self, handle: &str) -> Result<Option<Vec<u8>>, RequestStateError>;
    async fn delete(&self, handle: &str) -> Result<(), RequestStateError>;

    /// Atomically claim single-use for `key`. Returns `Ok(true)` the
    /// first time `key` is seen, `Ok(false)` on every later call. This
    /// is the cross-replica single-winner primitive backing inline-blob
    /// anti-replay; implementations MUST be atomic against the backing
    /// store (in the gateway: the coordinator KV `put_if_absent`).
    async fn claim_once(&self, key: &str) -> Result<bool, RequestStateError>;
}

/// Build the AEAD associated data that binds a `requestState` blob to
/// the principal owning the suspended pipeline. Decoding requires the
/// identical associated data, so a blob minted under one principal
/// fails AEAD verification when presented by another. An anonymous
/// owner (`None`) maps to a fixed sentinel so anonymous suspend/resume
/// still round-trips while remaining distinct from any real principal.
pub fn owner_aad(principal: Option<&str>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"mcpg.mrtr.owner.v1\x1f");
    match principal {
        Some(p) if !p.is_empty() => aad.extend_from_slice(p.as_bytes()),
        _ => aad.extend_from_slice(b"\x00anonymous"),
    }
    aad
}

/// In-memory `RequestStateStore` implementation. Used by tests and
/// single-process dev. Production uses
/// `crate::runtime::request_state_store::KvBackedRequestStateStore` over
/// the cluster coordinator KV.
#[derive(Debug, Default)]
pub struct InMemoryRequestStateStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryRequestStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RequestStateStore for InMemoryRequestStateStore {
    async fn put(&self, handle: &str, payload: &[u8]) -> Result<(), RequestStateError> {
        self.inner
            .lock()
            .insert(handle.to_owned(), payload.to_vec());
        Ok(())
    }

    async fn get(&self, handle: &str) -> Result<Option<Vec<u8>>, RequestStateError> {
        Ok(self.inner.lock().get(handle).cloned())
    }

    async fn delete(&self, handle: &str) -> Result<(), RequestStateError> {
        self.inner.lock().remove(handle);
        Ok(())
    }

    async fn claim_once(&self, key: &str) -> Result<bool, RequestStateError> {
        // Compare-and-insert under the one lock — atomic against
        // concurrent claims in-process (the cluster-wide guarantee comes
        // from the KV-backed store used in production).
        let mut guard = self.inner.lock();
        if guard.contains_key(key) {
            Ok(false)
        } else {
            guard.insert(key.to_owned(), Vec::new());
            Ok(true)
        }
    }
}

/// `requestState` codec — encode / decode the opaque blob the
/// modern handler ships on `InputRequiredResult` and reads back on
/// resumption.
pub struct RequestStateCodec {
    cipher: ChaCha20Poly1305,
    inline_threshold: usize,
    store: Arc<dyn RequestStateStore>,
}

impl RequestStateCodec {
    /// Construct a codec from a raw 32-byte ChaCha20-Poly1305 key
    /// and a KV store backing the handle path.
    pub fn new(key: [u8; 32], store: Arc<dyn RequestStateStore>) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self {
            cipher,
            inline_threshold: DEFAULT_INLINE_THRESHOLD_BYTES,
            store,
        }
    }

    /// Override the inline-payload threshold (bytes). Tests use
    /// this to exercise the handle path without minting an 8 KiB
    /// payload.
    pub fn with_inline_threshold(mut self, threshold: usize) -> Self {
        self.inline_threshold = threshold;
        self
    }

    /// Mint an ephemeral 32-byte key (random per process). Used by
    /// boot when the operator did not configure an explicit key.
    pub fn ephemeral_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        // ChaCha20Poly1305's KeyInit::generate_key uses OsRng under
        // the hood; reuse that via the cipher's own generator so
        // we don't pull in a parallel `rand` dependency.
        let g = ChaCha20Poly1305::generate_key(&mut OsRng);
        key.copy_from_slice(g.as_slice());
        key
    }

    /// Encode a payload to the wire form. Chooses inline if
    /// `payload.len() <= inline_threshold`, else uses the KV-handle
    /// path. `aad` binds the inline ciphertext to the owning principal
    /// (see [`owner_aad`]); the same `aad` must be supplied to
    /// [`Self::decode`] or AEAD verification fails.
    pub async fn encode(&self, payload: &[u8], aad: &[u8]) -> Result<String, RequestStateError> {
        if payload.len() <= self.inline_threshold {
            self.encode_inline(payload, aad)
        } else {
            self.encode_handle(payload).await
        }
    }

    /// Decode a wire-form blob back to the original payload. `aad` must
    /// match the associated data the blob was encoded under — a
    /// mismatch (different owning principal) surfaces as
    /// [`RequestStateError::AuthenticationFailed`].
    pub async fn decode(&self, state: &str, aad: &[u8]) -> Result<Vec<u8>, RequestStateError> {
        if let Some(rest) = state.strip_prefix(PREFIX_INLINE) {
            self.decode_inline(rest, aad)
        } else if let Some(rest) = state.strip_prefix(PREFIX_HANDLE) {
            self.decode_handle(rest).await
        } else {
            Err(RequestStateError::InvalidPrefix(state.to_owned()))
        }
    }

    /// Enforce single-use for an inline (`c.`) blob — the cross-replica
    /// anti-replay claim. Handle (`h.`) blobs are already single-use
    /// (the resume path deletes the handle via [`Self::cleanup`], so a
    /// replay decodes to `HandleNotFound`), so this is a no-op for them.
    /// Returns [`RequestStateError::Replayed`] when the inline blob has
    /// already been consumed.
    pub async fn enforce_single_use(&self, state: &str) -> Result<(), RequestStateError> {
        let Some(rest) = state.strip_prefix(PREFIX_INLINE) else {
            return Ok(());
        };
        // Key the claim by a hash of the wire blob so the ledger entry
        // is bounded-size and reveals nothing about the payload.
        let mut hasher = blake3::Hasher::new();
        hasher.update(rest.as_bytes());
        let key = format!("claim:{}", hasher.finalize().to_hex());
        if self.store.claim_once(&key).await? {
            Ok(())
        } else {
            Err(RequestStateError::Replayed)
        }
    }

    fn encode_inline(&self, payload: &[u8], aad: &[u8]) -> Result<String, RequestStateError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, Payload { msg: payload, aad })
            .map_err(|e| RequestStateError::InvalidPayload(format!("encrypt failed: {e}")))?;
        let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
        buf.extend_from_slice(nonce.as_slice());
        buf.extend_from_slice(&ciphertext);
        Ok(format!("{PREFIX_INLINE}{}", URL_SAFE_NO_PAD.encode(&buf)))
    }

    fn decode_inline(&self, b64: &str, aad: &[u8]) -> Result<Vec<u8>, RequestStateError> {
        let buf = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| RequestStateError::InvalidPayload(format!("base64: {e}")))?;
        if buf.len() < 12 {
            return Err(RequestStateError::InvalidPayload(
                "ciphertext shorter than nonce".to_owned(),
            ));
        }
        let (nonce_bytes, ciphertext) = buf.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| RequestStateError::AuthenticationFailed)
    }

    async fn encode_handle(&self, payload: &[u8]) -> Result<String, RequestStateError> {
        let handle = Uuid::new_v4().to_string();
        self.store.put(&handle, payload).await?;
        Ok(format!("{PREFIX_HANDLE}{handle}"))
    }

    async fn decode_handle(&self, handle: &str) -> Result<Vec<u8>, RequestStateError> {
        match self.store.get(handle).await? {
            Some(payload) => Ok(payload),
            None => Err(RequestStateError::HandleNotFound(handle.to_owned())),
        }
    }

    /// Delete a handle-backed payload after the dispatch arm has
    /// consumed it. No-op for inline-encoded blobs (nothing to
    /// clean up).
    pub async fn cleanup(&self, state: &str) -> Result<(), RequestStateError> {
        if let Some(handle) = state.strip_prefix(PREFIX_HANDLE) {
            self.store.delete(handle).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; 32] {
        // Deterministic key for tests so blob bytes are
        // reproducible across runs (the encrypted output isn't —
        // ChaCha20-Poly1305 mints a random nonce per call — but
        // round-trip correctness is.)
        *b"0123456789abcdef0123456789abcdef"
    }

    fn codec() -> RequestStateCodec {
        RequestStateCodec::new(fixed_key(), Arc::new(InMemoryRequestStateStore::new()))
    }

    /// Associated data used by the round-trip tests that don't
    /// exercise the owner-binding behaviour. Encode and decode share
    /// it, so AEAD verification passes.
    const AAD: &[u8] = b"test-owner-aad";

    #[tokio::test]
    async fn inline_round_trip_recovers_payload() {
        let c = codec();
        let payload = br#"{"pipelineId":"p-1","stepId":"s-2"}"#;
        let encoded = c.encode(payload, AAD).await.unwrap();
        assert!(encoded.starts_with("c."));
        let decoded = c.decode(&encoded, AAD).await.unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn handle_round_trip_recovers_payload() {
        // Force the handle path with a tiny inline threshold.
        let c = codec().with_inline_threshold(4);
        let payload = b"long enough to exceed threshold";
        let encoded = c.encode(payload, AAD).await.unwrap();
        assert!(encoded.starts_with("h."));
        let decoded = c.decode(&encoded, AAD).await.unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn handle_decode_after_cleanup_returns_not_found() {
        let c = codec().with_inline_threshold(0);
        let encoded = c.encode(b"payload", AAD).await.unwrap();
        assert!(encoded.starts_with("h."));
        c.cleanup(&encoded).await.unwrap();
        match c.decode(&encoded, AAD).await {
            Err(RequestStateError::HandleNotFound(_)) => {}
            other => panic!("expected HandleNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cleanup_is_a_noop_for_inline_encoded_blobs() {
        let c = codec();
        let encoded = c.encode(b"inline payload", AAD).await.unwrap();
        assert!(encoded.starts_with("c."));
        c.cleanup(&encoded).await.unwrap();
        // Decoding still works because the cleanup didn't touch anything.
        assert_eq!(c.decode(&encoded, AAD).await.unwrap(), b"inline payload");
    }

    #[tokio::test]
    async fn decode_rejects_unknown_prefix() {
        let c = codec();
        let err = c.decode("x.junk", AAD).await.unwrap_err();
        assert!(matches!(err, RequestStateError::InvalidPrefix(_)));
    }

    #[tokio::test]
    async fn decode_inline_rejects_malformed_base64() {
        let c = codec();
        let err = c.decode("c.not!base64!", AAD).await.unwrap_err();
        assert!(matches!(err, RequestStateError::InvalidPayload(_)));
    }

    #[tokio::test]
    async fn decode_inline_rejects_short_ciphertext() {
        let c = codec();
        // A blob with fewer than 12 bytes (the nonce length).
        let short = format!("c.{}", URL_SAFE_NO_PAD.encode([0u8; 4]));
        let err = c.decode(&short, AAD).await.unwrap_err();
        assert!(matches!(err, RequestStateError::InvalidPayload(_)));
    }

    #[tokio::test]
    async fn decode_inline_rejects_tampered_ciphertext() {
        let c = codec();
        let mut encoded = c.encode(b"secret", AAD).await.unwrap();
        // Flip the last char to corrupt the auth tag.
        let last = encoded.pop().unwrap();
        let bumped = if last == 'a' { 'b' } else { 'a' };
        encoded.push(bumped);
        match c.decode(&encoded, AAD).await {
            Err(RequestStateError::AuthenticationFailed) => {}
            // base64 may now also be invalid which is fine — both
            // failures indicate the integrity check worked.
            Err(RequestStateError::InvalidPayload(_)) => {}
            other => panic!("expected AuthenticationFailed/InvalidPayload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_inline_rejects_payload_encoded_with_different_key() {
        let store = Arc::new(InMemoryRequestStateStore::new());
        let codec_a = RequestStateCodec::new(fixed_key(), Arc::clone(&store) as _);
        let codec_b = RequestStateCodec::new(*b"differentdifferentdifferentdiff!", store as _);
        let encoded = codec_a.encode(b"x", AAD).await.unwrap();
        match codec_b.decode(&encoded, AAD).await {
            Err(RequestStateError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed across keys, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_inline_rejects_payload_bound_to_a_different_owner() {
        // A blob minted for one principal must not decode under another.
        let c = codec();
        let alice = owner_aad(Some("alice"));
        let bob = owner_aad(Some("bob"));
        let encoded = c.encode(b"answer", &alice).await.unwrap();
        assert!(encoded.starts_with("c."));
        match c.decode(&encoded, &bob).await {
            Err(RequestStateError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed across owners, got {other:?}"),
        }
        // The rightful owner still decodes it.
        assert_eq!(c.decode(&encoded, &alice).await.unwrap(), b"answer");
    }

    #[tokio::test]
    async fn owner_aad_distinguishes_anonymous_from_named() {
        assert_ne!(owner_aad(None), owner_aad(Some("alice")));
        // Empty principal collapses to the anonymous sentinel.
        assert_eq!(owner_aad(None), owner_aad(Some("")));
    }

    #[tokio::test]
    async fn inline_blob_is_single_use() {
        let c = codec();
        let encoded = c.encode(b"answer", AAD).await.unwrap();
        // First spend succeeds; the second is rejected as a replay.
        c.enforce_single_use(&encoded).await.unwrap();
        match c.enforce_single_use(&encoded).await {
            Err(RequestStateError::Replayed) => {}
            other => panic!("expected Replayed on second use, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enforce_single_use_is_a_noop_for_handle_blobs() {
        // Handle blobs are consumed via cleanup(), not the claim ledger,
        // so enforce_single_use never trips for them.
        let c = codec().with_inline_threshold(0);
        let encoded = c.encode(b"big payload", AAD).await.unwrap();
        assert!(encoded.starts_with("h."));
        c.enforce_single_use(&encoded).await.unwrap();
        c.enforce_single_use(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn handle_decode_returns_not_found_for_unknown_handle() {
        let c = codec();
        let err = c.decode("h.does-not-exist", AAD).await.unwrap_err();
        assert!(matches!(err, RequestStateError::HandleNotFound(_)));
    }

    #[tokio::test]
    async fn ephemeral_key_yields_a_working_codec() {
        let key = RequestStateCodec::ephemeral_key();
        let c = RequestStateCodec::new(key, Arc::new(InMemoryRequestStateStore::new()));
        let encoded = c.encode(b"hello", AAD).await.unwrap();
        assert_eq!(c.decode(&encoded, AAD).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn threshold_picks_inline_under_boundary_and_handle_over() {
        let c = codec().with_inline_threshold(10);
        assert!(
            c.encode(b"ten chars!", AAD)
                .await
                .unwrap()
                .starts_with("c.")
        ); // exactly 10
        assert!(
            c.encode(b"eleven char", AAD)
                .await
                .unwrap()
                .starts_with("h.")
        ); // 11
    }
}
