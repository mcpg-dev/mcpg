//! [`RequestStateStore`] over a cluster [`mcpg_cluster_api::KeyValueStore`].
//!
//! The MRTR `requestState` codec offloads resumption payloads larger than
//! its inline threshold (>8 KiB) to an opaque `h.<uuid>` handle backed by
//! a [`RequestStateStore`]. Backing it with the cluster coordinator KV —
//! the same substrate the pipeline / idempotency stores use — makes the
//! handle resolvable on any replica and across restarts.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::protocol::v_2026_07_28::dispatch::request_state::{
    RequestStateError, RequestStateStore,
};

/// Default TTL on a stored resumption blob: long enough to outlive any
/// realistic gather / elicitation suspension, short enough that abandoned
/// suspensions don't accumulate on the coordinator forever.
pub const DEFAULT_REQUEST_STATE_TTL: Duration = Duration::from_secs(3600);

/// Key namespace for handle-encoded resumption blobs. Distinct from the
/// `pipeline/` prefix so request-state and pipeline records never collide
/// even when they share one coordinator KV.
const STORAGE_PREFIX: &str = "request_state/";

/// `RequestStateStore` backed by any [`mcpg_cluster_api::KeyValueStore`]
/// (typically the cluster coordinator's `key_value_store()` primitive).
pub struct KvBackedRequestStateStore {
    kv: Arc<dyn mcpg_cluster_api::KeyValueStore>,
    ttl: Option<Duration>,
}

impl std::fmt::Debug for KvBackedRequestStateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedRequestStateStore")
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl KvBackedRequestStateStore {
    /// Bind to a KV substrate with an explicit TTL (`None` = no expiry).
    pub fn new(kv: Arc<dyn mcpg_cluster_api::KeyValueStore>, ttl: Option<Duration>) -> Self {
        Self { kv, ttl }
    }

    /// Bind with the default 1-hour TTL.
    pub fn with_default_ttl(kv: Arc<dyn mcpg_cluster_api::KeyValueStore>) -> Self {
        Self::new(kv, Some(DEFAULT_REQUEST_STATE_TTL))
    }

    /// In-process backing for tests (mirrors the other KV-backed stores).
    pub fn new_in_memory() -> Self {
        Self::new(
            Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()),
            Some(DEFAULT_REQUEST_STATE_TTL),
        )
    }

    fn storage_key(handle: &str) -> String {
        format!("{STORAGE_PREFIX}{handle}")
    }
}

#[async_trait]
impl RequestStateStore for KvBackedRequestStateStore {
    async fn put(&self, handle: &str, payload: &[u8]) -> Result<(), RequestStateError> {
        self.kv
            .put(
                &Self::storage_key(handle),
                Bytes::copy_from_slice(payload),
                self.ttl,
            )
            .await
            .map_err(|e| RequestStateError::Store(e.to_string()))
    }

    async fn get(&self, handle: &str) -> Result<Option<Vec<u8>>, RequestStateError> {
        let entry = self
            .kv
            .get(&Self::storage_key(handle))
            .await
            .map_err(|e| RequestStateError::Store(e.to_string()))?;
        Ok(entry.map(|e| e.bytes.to_vec()))
    }

    async fn delete(&self, handle: &str) -> Result<(), RequestStateError> {
        self.kv
            .delete(&Self::storage_key(handle))
            .await
            .map_err(|e| RequestStateError::Store(e.to_string()))?;
        Ok(())
    }

    async fn claim_once(&self, key: &str) -> Result<bool, RequestStateError> {
        // The coordinator KV's cross-replica single-winner primitive:
        // exactly one caller (on any replica) observes `true`. The
        // ledger entry is a 1-byte sentinel under the same TTL as the
        // handle payloads so spent inline-blob markers self-clean.
        self.kv
            .put_if_absent(&Self::storage_key(key), Bytes::from_static(b"1"), self.ttl)
            .await
            .map_err(|e| RequestStateError::Store(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_payload_via_kv() {
        let store = KvBackedRequestStateStore::new_in_memory();
        store.put("h.abc", b"large-resumption-blob").await.unwrap();
        let got = store.get("h.abc").await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"large-resumption-blob"[..]));
    }

    #[tokio::test]
    async fn missing_handle_is_none_not_error() {
        let store = KvBackedRequestStateStore::new_in_memory();
        assert!(store.get("h.nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_removes_the_handle() {
        let store = KvBackedRequestStateStore::new_in_memory();
        store.put("h.x", b"v").await.unwrap();
        store.delete("h.x").await.unwrap();
        assert!(store.get("h.x").await.unwrap().is_none());
        // Idempotent: deleting a missing handle is not an error.
        store.delete("h.x").await.unwrap();
    }

    #[tokio::test]
    async fn claim_once_is_single_winner_across_replicas() {
        // The inline-blob anti-replay primitive: the same claim key is
        // won exactly once, even across stores sharing one KV (replicas).
        let kv: Arc<dyn mcpg_cluster_api::KeyValueStore> =
            Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let replica_a = KvBackedRequestStateStore::with_default_ttl(Arc::clone(&kv));
        let replica_b = KvBackedRequestStateStore::with_default_ttl(Arc::clone(&kv));
        assert!(replica_a.claim_once("claim:abc").await.unwrap());
        // Second claim on the same key loses — on either replica.
        assert!(!replica_a.claim_once("claim:abc").await.unwrap());
        assert!(!replica_b.claim_once("claim:abc").await.unwrap());
        // A different key is still claimable.
        assert!(replica_b.claim_once("claim:def").await.unwrap());
    }

    #[tokio::test]
    async fn two_stores_sharing_one_kv_resolve_each_others_handles() {
        // The cross-replica guarantee: a handle minted against one store
        // (replica A) resolves through another store over the SAME KV
        // (replica B).
        let kv: Arc<dyn mcpg_cluster_api::KeyValueStore> =
            Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let replica_a = KvBackedRequestStateStore::with_default_ttl(Arc::clone(&kv));
        let replica_b = KvBackedRequestStateStore::with_default_ttl(Arc::clone(&kv));
        replica_a.put("h.shared", b"payload-from-a").await.unwrap();
        let on_b = replica_b.get("h.shared").await.unwrap();
        assert_eq!(on_b.as_deref(), Some(&b"payload-from-a"[..]));
    }
}
