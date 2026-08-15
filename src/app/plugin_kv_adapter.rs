//! Adapter that bridges a plugin-protocol [`Store`] (role-aware)
//! into the cluster-api [`KeyValueStore`] (role-less) trait that
//! capability subsystems consume.
//!
//! When an operator writes
//! `mcp.configurations.<cap>.store: { kind: <plugin-id> }`, the
//! gateway looks up the named plugin in the registry and wraps it
//! in a [`StoreToKvAdapter`] keyed to the capability's canonical
//! [`StoreRole`]. Every subsequent KV call delegates to the
//! plugin's `Store::{get,put,delete,list,...}` with the fixed
//! role baked in at adapter construction.
//!
//! The adapter is one-shot: a separate adapter instance per
//! capability. Two capabilities pointing at the same plugin id
//! get two adapter instances each with its own fixed role,
//! sharing the underlying `Arc<dyn Store>`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore};
use mcpg_plugin_protocol::store::{Store, StoreError, StoreRole, StoreValue};

/// Role-fixed bridge from a plugin-registered `Store` to the
/// cluster-api `KeyValueStore` trait that capability subsystems
/// consume.
pub struct StoreToKvAdapter {
    store: Arc<dyn Store>,
    role: StoreRole,
}

impl StoreToKvAdapter {
    pub fn new(store: Arc<dyn Store>, role: StoreRole) -> Self {
        Self { store, role }
    }
}

impl std::fmt::Debug for StoreToKvAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreToKvAdapter")
            .field("plugin_id", &self.store.manifest().id)
            .field("role", &self.role)
            .finish()
    }
}

#[async_trait]
impl KeyValueStore for StoreToKvAdapter {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        match self.store.get(self.role.clone(), key).await {
            Ok(Some(value)) => Ok(Some(store_value_to_entry(value))),
            Ok(None) => Ok(None),
            Err(e) => Err(map_store_error(e)),
        }
    }

    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        let mut sv = StoreValue::new(value);
        if let Some(ttl) = ttl {
            sv = sv.with_ttl(ttl);
        }
        self.store
            .put(self.role.clone(), key, sv)
            .await
            .map_err(map_store_error)
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        // CAVEAT — NOT atomic. The plugin `Store` FFI trait exposes only
        // get/put/delete (no conditional write), so this bridge can only
        // do a best-effort get-then-put: correct under low contention,
        // but two concurrent claimants on a plugin-`Store`-backed override
        // CAN both observe `true` (last-writer-wins). For exactly-once
        // guarantees (idempotency, single-winner claims), point the
        // capability at the coordinator KV (`kind: cluster`) — its
        // backends (memory/redis/nats) implement put_if_absent atomically.
        // Closing this gap needs a conditional op on the Store FFI trait,
        // a separate ABI-touching follow-up.
        if self
            .store
            .get(self.role.clone(), key)
            .await
            .map_err(map_store_error)?
            .is_some()
        {
            return Ok(false);
        }
        let mut sv = StoreValue::new(value);
        if let Some(ttl) = ttl {
            sv = sv.with_ttl(ttl);
        }
        self.store
            .put(self.role.clone(), key, sv)
            .await
            .map_err(map_store_error)?;
        Ok(true)
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        // `Store::delete` is idempotent — returns Ok(()) for a
        // missing key. The KeyValueStore trait wants Ok(true) /
        // Ok(false). Pre-check via `get` to disambiguate; the
        // extra round-trip is the cost of bridging the two
        // contracts. Most callers don't depend on the bool, so
        // the overhead is acceptable.
        let existed = self
            .store
            .get(self.role.clone(), key)
            .await
            .is_ok_and(|v| v.is_some());
        self.store
            .delete(self.role.clone(), key)
            .await
            .map_err(map_store_error)?;
        Ok(existed)
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        // Walk pages until we hit `limit` or run out. Pagination
        // is hidden from the KeyValueStore caller by design;
        // backends that can't paginate return everything in one
        // page anyway.
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(self.role.clone(), prefix, cursor)
                .await
                .map_err(map_store_error)?;
            for (k, v) in page.items {
                out.push((k, store_value_to_entry(v)));
                if out.len() >= limit {
                    return Ok(out);
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(out),
            }
        }
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        // Store has no native `expire` — emulate via get + put.
        // The same trade-off as `delete`: an extra round-trip
        // for the contract bridge. CAS would be safer but the
        // KeyValueStore contract doesn't promise atomicity.
        let Some(current) = self
            .store
            .get(self.role.clone(), key)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(false);
        };
        let mut sv = StoreValue::new(current.bytes);
        if let Some(ttl) = ttl {
            sv = sv.with_ttl(ttl);
        }
        for (k, v) in current.metadata {
            sv = sv.with_metadata(k, v);
        }
        self.store
            .put(self.role.clone(), key, sv)
            .await
            .map_err(map_store_error)?;
        Ok(true)
    }
}

fn store_value_to_entry(value: StoreValue) -> Entry {
    let expires_at = value.ttl.map(|d| SystemTime::now() + d);
    Entry {
        bytes: value.bytes,
        expires_at,
    }
}

fn map_store_error(e: StoreError) -> ClusterError {
    match e {
        StoreError::Backend { reason } => ClusterError::BackendUnavailable { reason },
        StoreError::CasMismatch => ClusterError::CasConflict {
            key: String::new(),
            reason: "compare-and-swap pre-condition failed".to_owned(),
        },
        StoreError::UnsupportedRole => ClusterError::Unsupported {
            reason: "store plugin does not serve the requested role".to_owned(),
        },
        StoreError::Unsupported { op } => ClusterError::Unsupported {
            reason: format!("store plugin does not support `{op}`"),
        },
        StoreError::Throttled => ClusterError::Precondition {
            reason: "store plugin returned throttled".to_owned(),
        },
        StoreError::NotFound => ClusterError::NotFound { key: String::new() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::store_memory::MemoryStore;

    fn memory_store() -> Arc<dyn Store> {
        MemoryStore::new() as Arc<dyn Store>
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Session);
        kv.put("alpha", Bytes::from_static(b"hello"), None)
            .await
            .unwrap();
        let got = kv.get("alpha").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().bytes.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Task);
        assert!(kv.get("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_reports_existence() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Pipeline);
        kv.put("a", Bytes::from_static(b"1"), None).await.unwrap();
        assert!(kv.delete("a").await.unwrap()); // existed
        assert!(!kv.delete("a").await.unwrap()); // gone now
    }

    #[tokio::test]
    async fn list_prefix_walks_pages() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Subscription);
        kv.put("k/1", Bytes::from_static(b"1"), None).await.unwrap();
        kv.put("k/2", Bytes::from_static(b"2"), None).await.unwrap();
        kv.put("other/1", Bytes::from_static(b"x"), None)
            .await
            .unwrap();
        let entries = kv.list_prefix("k/", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn list_prefix_honours_limit() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Session);
        for i in 0..10 {
            kv.put(&format!("k/{i}"), Bytes::from(format!("{i}")), None)
                .await
                .unwrap();
        }
        let entries = kv.list_prefix("k/", 3).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn expire_extends_existing_key() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Session);
        kv.put("k", Bytes::from_static(b"v"), None).await.unwrap();
        assert!(kv.expire("k", Some(Duration::from_secs(60))).await.unwrap());
        // Subsequent get still returns the same bytes — expire is
        // a TTL-only mutation; the value round-trips intact.
        assert_eq!(kv.get("k").await.unwrap().unwrap().bytes.as_ref(), b"v");
    }

    #[tokio::test]
    async fn expire_missing_returns_false() {
        let kv = StoreToKvAdapter::new(memory_store(), StoreRole::Task);
        assert!(
            !kv.expire("nope", Some(Duration::from_secs(60)))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn role_isolation_keeps_keys_separate() {
        // Two adapters over the SAME underlying Arc<dyn Store>,
        // each scoped to a different role. A key written under
        // Session must not be visible under Task.
        let store = memory_store();
        let session = StoreToKvAdapter::new(Arc::clone(&store), StoreRole::Session);
        let task = StoreToKvAdapter::new(Arc::clone(&store), StoreRole::Task);
        session
            .put("shared-key", Bytes::from_static(b"session-value"), None)
            .await
            .unwrap();
        assert_eq!(
            session
                .get("shared-key")
                .await
                .unwrap()
                .unwrap()
                .bytes
                .as_ref(),
            b"session-value"
        );
        assert!(task.get("shared-key").await.unwrap().is_none());
    }
}
