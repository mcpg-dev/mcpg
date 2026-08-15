//! Built-in `store` plugin — `dev.mcpg.builtin.store.memory`.
//!
//! The gateway's bundled `store`. In-process memory-backed store
//! supporting all five canonical roles
//! (Session / Task / Pipeline / Subscription / Replay) plus any
//! `Custom(_)` an operator defines.
//!
//! # Scope + durability caveat
//!
//! Single-node. Zero durability. Process restart loses every key.
//! Not suitable for HA. Operators SHOULD register a durable
//! backend (NATS KV / Redis / Postgres) for every role that matters
//! and only use `memory` for dev / CI / testing.
//!
//! # Concurrency
//!
//! Each role lives in its own `DashMap<String, StoreEntry>` — the
//! library's sharded-lock design gives concurrent `get` / `put` /
//! `delete` without a global mutex. CAS serialises through the
//! shard lock alone (the critical section is a two-line
//! compare-and-replace). `watch` hands out a
//! `tokio::sync::broadcast` subscriber; put / delete fan the event
//! into every live subscriber on the same key.
//!
//! # TTL
//!
//! TTLs are honoured lazily. A key with an expired `ttl` is
//! evicted on the next read of that key (and the read returns
//! `None`). No background sweeper — the assumption is the memory
//! store is dev-scale and hot keys get refreshed quickly; cold
//! keys with long-expired TTLs waste a few hundred bytes each.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::broadcast;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    store::{
        AppendResult, BoxStoreEventStream, Store, StoreError, StoreEvent, StorePage, StoreRole,
        StoreValue,
    },
};

/// Descriptor shipped alongside the code. `FirstPartyRegistrar`
/// parses this at registration time + cross-checks against the
/// in-code manifest.
pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.store.memory
name: Built-in In-Memory Store
description: |
  Gateway-bundled store: in-process DashMap-backed, serves all five
  canonical roles (session / task / pipeline / subscription / replay)
  plus any operator-defined custom role. Single-node, zero
  durability. Dev / CI / testing only — production deployments MUST
  register a durable backend.
class: store
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// One stored value plus a per-key append sequence. `expires_at`
/// is `None` for keys without a TTL; a pegged `Instant` otherwise.
#[derive(Debug, Clone)]
struct StoreEntry {
    value: StoreValue,
    expires_at: Option<Instant>,
    /// Next sequence number to hand out on `append` for THIS key.
    /// Shared by all append callers via the shard lock.
    append_seq: u64,
}

fn with_expiry(value: StoreValue) -> StoreEntry {
    let expires_at = value.ttl.map(|d| Instant::now() + d);
    StoreEntry {
        value,
        expires_at,
        append_seq: 0,
    }
}

/// Per-role state. Keyed by string key; the watch broadcaster is
/// shared across every watcher on that key.
#[derive(Default)]
struct RoleState {
    entries: DashMap<String, StoreEntry>,
    /// Per-key broadcasters for `watch`. Kept alongside `entries`
    /// so put / delete can notify subscribers without taking the
    /// shard lock twice. Capacity is modest — operators who expect
    /// heavy watch traffic should reach for a real backend.
    watches: DashMap<String, broadcast::Sender<StoreEvent>>,
    /// Monotonic counter for the Replay role's append sequence
    /// (shared across keys — Replay is append-only and treats the
    /// whole role as one log).
    replay_seq: AtomicU64,
}

/// The memory store.
pub struct MemoryStore {
    manifest: PluginManifest,
    roles: DashMap<StoreRole, Arc<RoleState>>,
}

impl MemoryStore {
    /// Build an instance that advertises every canonical role +
    /// any `Custom(_)` the caller pre-declares.
    pub fn new() -> Arc<Self> {
        let roles = DashMap::new();
        for role in [
            StoreRole::Session,
            StoreRole::Task,
            StoreRole::Pipeline,
            StoreRole::Subscription,
            StoreRole::Replay,
        ] {
            roles.insert(role, Arc::new(RoleState::default()));
        }
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.store.memory".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in In-Memory Store".into(),
                plugin_class: PluginClass::Store,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            roles,
        })
    }

    /// Get-or-create the `RoleState` for `role`. Required because
    /// Custom roles are allocated lazily on first access.
    fn role_state(&self, role: &StoreRole) -> Arc<RoleState> {
        if let Some(s) = self.roles.get(role) {
            return Arc::clone(s.value());
        }
        // Double-checked insert: another thread may have inserted
        // the role while we took the miss-path lock. `entry` is
        // atomic per the DashMap contract.
        let new = Arc::new(RoleState::default());
        self.roles
            .entry(role.clone())
            .or_insert_with(|| Arc::clone(&new));
        Arc::clone(self.roles.get(role).expect("just inserted").value())
    }

    fn broadcaster(state: &RoleState, key: &str) -> broadcast::Sender<StoreEvent> {
        if let Some(s) = state.watches.get(key) {
            return s.value().clone();
        }
        let (tx, _rx) = broadcast::channel(128);
        state
            .watches
            .entry(key.to_owned())
            .or_insert_with(|| tx.clone());
        state
            .watches
            .get(key)
            .expect("just inserted")
            .value()
            .clone()
    }
}

/// Lazy-TTL check on read. Returns `Some(value)` if live, `None`
/// (and removes the entry) if expired.
fn read_live(state: &RoleState, key: &str) -> Option<StoreValue> {
    let live_value = state.entries.get(key).and_then(|entry| {
        let e = entry.value();
        if e.expires_at.is_some_and(|t| t < Instant::now()) {
            None
        } else {
            Some(e.value.clone())
        }
    });
    if live_value.is_none() {
        // Lazy evict on miss — drops the entry on the floor if we
        // observed an expired TTL just now. Racy with concurrent
        // writers but safe: a writer that reinserts between our
        // read + remove wins the next read.
        state.entries.remove_if(key, |_, entry| {
            entry.expires_at.is_some_and(|t| t < Instant::now())
        });
    }
    live_value
}

#[mcpg_plugin_protocol::async_trait]
impl Store for MemoryStore {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_roles(&self) -> Vec<StoreRole> {
        vec![
            StoreRole::Session,
            StoreRole::Task,
            StoreRole::Pipeline,
            StoreRole::Subscription,
            StoreRole::Replay,
        ]
    }

    async fn get(&self, role: StoreRole, key: &str) -> Result<Option<StoreValue>, StoreError> {
        let state = self.role_state(&role);
        Ok(read_live(&state, key))
    }

    async fn put(&self, role: StoreRole, key: &str, value: StoreValue) -> Result<(), StoreError> {
        let state = self.role_state(&role);
        let entry = with_expiry(value.clone());
        state.entries.insert(key.to_owned(), entry);
        // Fan the event out BEFORE returning so a watcher's read-
        // your-writes expectation holds on the same task.
        if let Some(tx) = state.watches.get(key) {
            let _ = tx.value().send(StoreEvent::Put {
                key: key.to_owned(),
                value,
            });
        }
        Ok(())
    }

    async fn delete(&self, role: StoreRole, key: &str) -> Result<(), StoreError> {
        let state = self.role_state(&role);
        state.entries.remove(key);
        if let Some(tx) = state.watches.get(key) {
            let _ = tx.value().send(StoreEvent::Delete {
                key: key.to_owned(),
            });
        }
        Ok(())
    }

    async fn list(
        &self,
        role: StoreRole,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<StorePage, StoreError> {
        // Single-page backend: the memory store is small enough
        // that returning every match at once is cheaper than
        // maintaining a cursor state. Callers who paginate get one
        // page with `next_cursor: None`.
        if cursor.is_some() {
            return Ok(StorePage {
                items: vec![],
                next_cursor: None,
            });
        }
        let state = self.role_state(&role);
        let mut items: Vec<(String, StoreValue)> = Vec::new();
        for entry in state.entries.iter() {
            if entry.key().starts_with(prefix) {
                let e = entry.value();
                if e.expires_at.is_some_and(|t| t < Instant::now()) {
                    continue;
                }
                items.push((entry.key().clone(), e.value.clone()));
            }
        }
        // Stable order lets test assertions be deterministic.
        items.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(StorePage {
            items,
            next_cursor: None,
        })
    }

    async fn compare_and_swap(
        &self,
        role: StoreRole,
        key: &str,
        expected: Option<StoreValue>,
        new: StoreValue,
    ) -> Result<bool, StoreError> {
        let state = self.role_state(&role);
        // Serialise CAS through a single DashMap `entry` — the API
        // guarantees atomicity on the entry, which is what CAS
        // needs.
        let mut applied = false;
        state
            .entries
            .entry(key.to_owned())
            .and_modify(|existing| {
                let live = if existing.expires_at.is_some_and(|t| t < Instant::now()) {
                    None
                } else {
                    Some(&existing.value)
                };
                // `expected == Some(v)` requires exact match;
                // `expected == None` requires NO live value, which
                // means we're inside `and_modify` so a live value
                // exists — that's a mismatch.
                let matches = match &expected {
                    Some(want) => live.map(|v| v == want).unwrap_or(false),
                    None => live.is_none(),
                };
                if matches {
                    *existing = with_expiry(new.clone());
                    applied = true;
                }
            })
            .or_insert_with(|| {
                if expected.is_none() {
                    applied = true;
                    with_expiry(new.clone())
                } else {
                    // Caller wanted a specific prior value but the
                    // key was missing. Insert a placeholder with
                    // zero TTL so list doesn't see it — and remove
                    // immediately below.
                    with_expiry(new.clone())
                }
            });
        if !applied {
            // The or_insert_with ran + inserted something we
            // shouldn't have committed. Undo.
            state
                .entries
                .remove_if(key, |_, entry| !applied && entry.value == new);
        }
        if applied && let Some(tx) = state.watches.get(key) {
            let _ = tx.value().send(StoreEvent::Put {
                key: key.to_owned(),
                value: new,
            });
        }
        Ok(applied)
    }

    async fn append(
        &self,
        role: StoreRole,
        key: &str,
        value: StoreValue,
    ) -> Result<AppendResult, StoreError> {
        let state = self.role_state(&role);
        // Replay is a single log — sequence is per-role, not per-
        // key, so auditors reading back get a global ordering.
        let sequence = if role == StoreRole::Replay {
            state.replay_seq.fetch_add(1, Ordering::AcqRel)
        } else {
            // For non-Replay, sequence counts per-key. Grab the
            // entry (or default 0) + bump it atomically via the
            // DashMap entry API.
            let mut seq = 0u64;
            state
                .entries
                .entry(key.to_owned())
                .and_modify(|existing| {
                    existing.append_seq += 1;
                    seq = existing.append_seq;
                    existing.value = value.clone();
                    existing.expires_at = value.ttl.map(|d| Instant::now() + d);
                })
                .or_insert_with(|| StoreEntry {
                    value: value.clone(),
                    expires_at: value.ttl.map(|d| Instant::now() + d),
                    append_seq: 0,
                });
            seq
        };
        // For Replay, key each record with its sequence so callers
        // can re-read the log in order.
        if role == StoreRole::Replay {
            let seq_key = format!("{key}@{sequence}");
            state
                .entries
                .insert(seq_key.clone(), with_expiry(value.clone()));
            if let Some(tx) = state.watches.get(key) {
                let _ = tx.value().send(StoreEvent::Put {
                    key: seq_key,
                    value,
                });
            }
        } else if let Some(tx) = state.watches.get(key) {
            let _ = tx.value().send(StoreEvent::Put {
                key: key.to_owned(),
                value,
            });
        }
        Ok(AppendResult { sequence })
    }

    async fn watch(&self, role: StoreRole, key: &str) -> Result<BoxStoreEventStream, StoreError> {
        let state = self.role_state(&role);
        let tx = Self::broadcaster(&state, key);
        let rx = tx.subscribe();
        let stream = async_stream::stream! {
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok(event) => yield event,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Drop lagged events — operators who care
                        // about every event should use a durable
                        // backend, not the in-memory store.
                        continue;
                    }
                }
            }
        };
        Ok(Pin::from(
            Box::new(stream) as Box<dyn futures::Stream<Item = _> + Send + 'static>
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn get_returns_none_for_missing() {
        let store = MemoryStore::new();
        let v = store.get(StoreRole::Session, "nope").await.unwrap();
        assert!(v.is_none());
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let store = MemoryStore::new();
        store
            .put(
                StoreRole::Session,
                "k",
                StoreValue::new(b"v".to_vec()).with_metadata("shard", "1"),
            )
            .await
            .unwrap();
        let v = store.get(StoreRole::Session, "k").await.unwrap().unwrap();
        assert_eq!(v.bytes.as_ref(), b"v");
        assert_eq!(v.metadata.get("shard").map(String::as_str), Some("1"));
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let store = MemoryStore::new();
        store
            .put(StoreRole::Session, "k", StoreValue::new(b"v".to_vec()))
            .await
            .unwrap();
        store.delete(StoreRole::Session, "k").await.unwrap();
        assert!(store.get(StoreRole::Session, "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_filters_by_prefix() {
        let store = MemoryStore::new();
        for k in ["a/1", "a/2", "b/1"] {
            store
                .put(StoreRole::Task, k, StoreValue::new(b"x".to_vec()))
                .await
                .unwrap();
        }
        let page = store.list(StoreRole::Task, "a/", None).await.unwrap();
        let keys: Vec<String> = page.items.into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a/1".to_string(), "a/2".to_string()]);
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn cas_succeeds_on_matching_expected() {
        let store = MemoryStore::new();
        store
            .put(StoreRole::Task, "t", StoreValue::new(b"pending".to_vec()))
            .await
            .unwrap();
        let current = store.get(StoreRole::Task, "t").await.unwrap().unwrap();
        let ok = store
            .compare_and_swap(
                StoreRole::Task,
                "t",
                Some(current),
                StoreValue::new(b"running".to_vec()),
            )
            .await
            .unwrap();
        assert!(ok);
        let after = store.get(StoreRole::Task, "t").await.unwrap().unwrap();
        assert_eq!(after.bytes.as_ref(), b"running");
    }

    #[tokio::test]
    async fn cas_fails_on_mismatched_expected() {
        let store = MemoryStore::new();
        store
            .put(StoreRole::Task, "t", StoreValue::new(b"pending".to_vec()))
            .await
            .unwrap();
        let wrong = StoreValue::new(b"not-what-we-have".to_vec());
        let ok = store
            .compare_and_swap(
                StoreRole::Task,
                "t",
                Some(wrong),
                StoreValue::new(b"should-not-apply".to_vec()),
            )
            .await
            .unwrap();
        assert!(!ok);
        let after = store.get(StoreRole::Task, "t").await.unwrap().unwrap();
        assert_eq!(after.bytes.as_ref(), b"pending");
    }

    #[tokio::test]
    async fn cas_insert_when_expected_none_and_missing() {
        let store = MemoryStore::new();
        let ok = store
            .compare_and_swap(
                StoreRole::Session,
                "fresh",
                None,
                StoreValue::new(b"1".to_vec()),
            )
            .await
            .unwrap();
        assert!(ok);
        let after = store
            .get(StoreRole::Session, "fresh")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.bytes.as_ref(), b"1");
    }

    #[tokio::test]
    async fn ttl_evicts_on_read() {
        let store = MemoryStore::new();
        store
            .put(
                StoreRole::Session,
                "short",
                StoreValue::new(b"fleeting".to_vec()).with_ttl(Duration::from_millis(20)),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            store
                .get(StoreRole::Session, "short")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn append_replay_assigns_monotonic_sequence() {
        let store = MemoryStore::new();
        let r1 = store
            .append(StoreRole::Replay, "log", StoreValue::new(b"a".to_vec()))
            .await
            .unwrap();
        let r2 = store
            .append(StoreRole::Replay, "log", StoreValue::new(b"b".to_vec()))
            .await
            .unwrap();
        assert_eq!(r1.sequence, 0);
        assert_eq!(r2.sequence, 1);
    }

    #[tokio::test]
    async fn watch_receives_put_events() {
        use tokio_stream::StreamExt;
        let store = MemoryStore::new();
        let mut stream = store.watch(StoreRole::Session, "k").await.unwrap();
        let store2 = store.clone();
        tokio::spawn(async move {
            store2
                .put(StoreRole::Session, "k", StoreValue::new(b"hello".to_vec()))
                .await
                .unwrap();
        });
        let event = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended");
        match event {
            StoreEvent::Put { key, value } => {
                assert_eq!(key, "k");
                assert_eq!(value.bytes.as_ref(), b"hello");
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    #[test]
    fn supported_roles_lists_all_canonical() {
        let store = MemoryStore::new();
        let roles = store.supported_roles();
        for r in [
            StoreRole::Session,
            StoreRole::Task,
            StoreRole::Pipeline,
            StoreRole::Subscription,
            StoreRole::Replay,
        ] {
            assert!(roles.contains(&r), "missing {r}");
        }
    }

    #[test]
    fn descriptor_yaml_parses_as_store() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.store.memory");
        assert_eq!(d.class, PluginClass::Store);
    }
}
