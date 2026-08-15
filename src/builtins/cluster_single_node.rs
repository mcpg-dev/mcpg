//! Built-in `cluster` plugin —
//! `dev.mcpg.builtin.cluster.single-node`.
//!
//! The default coordinator for single-node deployments. Always
//! leader for every role; no peers; in-process broadcast pub/sub.
//! Fencing tokens are strictly monotonic per key / role across
//! the coordinator's lifetime — consumer code that defensively
//! uses fencing behaves identically between single-node and
//! multi-node modes.
//!
//! # What it supports
//!
//! - `node_info` / `list_peers` / `watch_peers` — yields a single
//!   synthetic node + empty peer list + empty peer-event stream.
//! - `acquire_leadership` / `acquire_lock` — always succeeds
//!   immediately; fencing token bumps on each fresh acquire.
//! - `publish` / `subscribe` — in-process broadcast. When
//!   `group` is None, every subscriber receives every message
//!   (broadcast semantics). When `group` is Some, returns
//!   `InvalidReference` — queue-group semantics require a real
//!   multi-node backend.
//!
//! # Not suitable for
//!
//! Anything multi-node. The single-node coordinator is the safe
//! default so a fresh gateway install works with zero
//! configuration; any real deployment should replace it with
//! NATS / Consul / etcd / Raft.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use mcpg_cluster_api::{
    ActiveLease, BoxActiveLease, BoxPeerEventStream, BoxPublishedMessageStream, ClusterBackend,
    ClusterError, ClusterNodeInfo, ClusterPeer, KeyValueStore, PubSub, PublishedMessage, Watch,
};
use mcpg_plugin_protocol::{PluginClass, PluginManifest};

use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv, MemoryWatch, WatchHub};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.cluster.single-node
name: Built-in Single-Node Cluster Coordinator
description: |
  Default coordinator for single-node deployments. Always leader,
  no peers, in-process broadcast pub/sub. Fencing tokens are
  strictly monotonic per key / role. Not suitable for multi-node
  — replace with NATS / Consul / etcd / Raft for real HA.
class: cluster
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
provides:
  - cache
  - kv
  - bus
"#;

/// Upper bound on in-flight undelivered pub/sub messages per
/// topic. In broadcast mode a slow subscriber pressures the
/// channel; the subscriber receives a `Lagged` marker it can
/// use to know it missed messages. 256 is enough for normal
/// gateway traffic + keeps memory bounded.
const BROADCAST_CAPACITY: usize = 256;

/// Per-coordinator state — all mutation crosses this mutex.
/// Held only for short synchronous windows (counter bumps,
/// map inserts); never across await points.
struct State {
    node_id: String,
    started_at: String,
    /// Currently-held leadership roles. Reported in
    /// `node_info.roles`. Used by `try_acquire_leadership` to
    /// decide acquired-vs-declined without ever blocking.
    roles: BTreeSet<String>,
    /// Currently-held distributed locks. Tracked separately from
    /// `roles` because locks don't surface in `node_info`. Used
    /// by `try_acquire_lock` to decide acquired-vs-declined.
    active_locks: BTreeSet<String>,
    /// Per-key fencing-token counter. Single namespace for
    /// roles ("role:{name}") + locks ("lock:{key}") — keeps the
    /// counter sequence trivially monotonic and eliminates
    /// accidental collisions.
    lease_counters: BTreeMap<String, u64>,
    /// Per-topic broadcast channel. Created lazily on first
    /// publish or subscribe. Lives for the coordinator's
    /// lifetime.
    pubsub: BTreeMap<String, broadcast::Sender<PublishedMessage>>,
}

pub struct SingleNodeClusterBackend {
    manifest: PluginManifest,
    state: Arc<Mutex<State>>,
    /// Shared in-memory `KeyValueStore` primitive — exposed via the
    /// `key_value_store()` accessor so capabilities can extract it.
    /// Constructed with a [`WatchHub`] so put/delete events flow to
    /// `MemoryWatch` subscribers.
    kv: Arc<MemoryKv>,
    /// Shared in-memory `PubSub` primitive — exposed via the
    /// `pub_sub()` accessor.
    bus: Arc<MemoryBus>,
    /// Shared in-memory `Watch` primitive over the same hub `kv`
    /// publishes into. Exposed via the `watch()` accessor.
    watch: Arc<MemoryWatch>,
}

impl SingleNodeClusterBackend {
    pub fn new() -> Arc<Self> {
        Self::with_node_id(format!("single-node-{:016x}", rand_u64(),))
    }

    /// Construct with an explicit node id — used by tests for
    /// deterministic assertions.
    pub fn with_node_id(node_id: impl Into<String>) -> Arc<Self> {
        let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Single shared hub: `MemoryKv` publishes onto it; the
        // accompanying `MemoryWatch` subscribes from it. Operators
        // who consume both `key_value_store()` and `watch()` see a
        // consistent change stream.
        let watch_hub = Arc::new(WatchHub::new());
        let kv = Arc::new(MemoryKv::with_watch_hub(Arc::clone(&watch_hub)));
        let watch = Arc::new(MemoryWatch::new(watch_hub));
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.cluster.single-node".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in Single-Node Cluster Coordinator".into(),
                plugin_class: PluginClass::Cluster,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                // Single-node backs every slot role in-process — KV /
                // cache via the in-memory store, bus via in-process
                // broadcast pub/sub. (Slot roles, not primitive
                // accessors — see `cluster_provides()` /
                // CLUSTER_PROVIDES_ROLES.)
                provides: vec!["cache".into(), "kv".into(), "bus".into()],
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            state: Arc::new(Mutex::new(State {
                node_id: node_id.into(),
                started_at,
                roles: BTreeSet::new(),
                active_locks: BTreeSet::new(),
                lease_counters: BTreeMap::new(),
                pubsub: BTreeMap::new(),
            })),
            kv,
            bus: Arc::new(MemoryBus::new()),
            watch,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("single-node cluster state mutex poisoned")
    }
}

/// 64-bit random seed derived from the current time. Not
/// cryptographically secure — just enough entropy to distinguish
/// gateway restarts in admin output.
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

/// What kind of lease a handle represents. Lock releases are
/// no-ops on the state; role releases drop the role from
/// `roles`.
#[derive(Debug, Clone)]
enum LeaseKind {
    Role(String),
    Lock(#[allow(dead_code)] String),
}

struct SingleNodeLease {
    kind: LeaseKind,
    fencing_token: u64,
    /// Advisory expiry RFC3339 string. Single-node coordinator
    /// never actually expires leases (single-node can't have
    /// lease handoff); we compute + report the expiry so
    /// consumer code observing `expires_at` gets a sensible
    /// value, and renew updates it.
    expires_at: Mutex<String>,
    /// Original TTL — renew extends by this amount.
    ttl: Duration,
    state: Arc<Mutex<State>>,
    released: AtomicBool,
}

fn expiry_from_now(ttl: Duration) -> String {
    let now = chrono::Utc::now();
    let expiry = now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::zero());
    expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[mcpg_plugin_protocol::async_trait]
impl ActiveLease for SingleNodeLease {
    fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    fn expires_at(&self) -> String {
        self.expires_at
            .lock()
            .expect("single-node lease expires_at mutex poisoned")
            .clone()
    }

    async fn renew(&self) -> Result<(), ClusterError> {
        // Single-node coordinator never loses a lease to another
        // holder, so renew never fails with LeaseExpired. It just
        // refreshes the advisory expires_at.
        if self.released.load(Ordering::Acquire) {
            return Err(ClusterError::LeaseExpired);
        }
        let fresh = expiry_from_now(self.ttl);
        *self
            .expires_at
            .lock()
            .expect("single-node lease expires_at mutex poisoned") = fresh;
        Ok(())
    }

    async fn release(&self) -> Result<(), ClusterError> {
        // Idempotent — double-release is a no-op per spec.
        if self.released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut guard = self
            .state
            .lock()
            .expect("single-node cluster state mutex poisoned");
        match &self.kind {
            LeaseKind::Role(role) => {
                guard.roles.remove(role);
            }
            LeaseKind::Lock(key) => {
                // Drop the active-lock entry so subsequent
                // try_acquire_lock for the same key can succeed.
                guard.active_locks.remove(key);
            }
        }
        Ok(())
    }
}

// Backstop in case the consumer drops the lease without calling
// release explicitly. Mirrors the behaviour the coordinator-
// adapter's `lease_drop` slot expects: `active_locks` /
// `roles` membership is freed even on panic-paths.
impl Drop for SingleNodeLease {
    fn drop(&mut self) {
        if self.released.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut guard) = self.state.lock() {
            match &self.kind {
                LeaseKind::Role(role) => {
                    guard.roles.remove(role);
                }
                LeaseKind::Lock(key) => {
                    guard.active_locks.remove(key);
                }
            }
        }
    }
}

#[mcpg_plugin_protocol::async_trait]
impl ClusterBackend for SingleNodeClusterBackend {
    // `cluster_provides()` uses the default impl: it derives the role
    // set from `manifest().provides` (= cache/kv/bus, declared above).

    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn key_value_store(&self) -> Option<Arc<dyn KeyValueStore>> {
        Some(Arc::clone(&self.kv) as Arc<dyn KeyValueStore>)
    }

    fn pub_sub(&self) -> Option<Arc<dyn PubSub>> {
        Some(Arc::clone(&self.bus) as Arc<dyn PubSub>)
    }

    fn watch(&self) -> Option<Arc<dyn Watch>> {
        Some(Arc::clone(&self.watch) as Arc<dyn Watch>)
    }

    async fn node_info(&self) -> ClusterNodeInfo {
        let s = self.lock();
        ClusterNodeInfo {
            node_id: s.node_id.clone(),
            address: "local".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at: s.started_at.clone(),
            roles: s.roles.iter().cloned().collect(),
        }
    }

    async fn list_peers(&self) -> Vec<ClusterPeer> {
        // Single-node has no peers by definition.
        Vec::new()
    }

    async fn watch_peers(&self) -> BoxPeerEventStream {
        // No peer events are ever produced — return an immediately-
        // closed stream. A long-lived subscriber calling `next()`
        // gets `None` right away and can release its task.
        Box::pin(tokio_stream::empty())
    }

    async fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        if role.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty role name".into(),
            });
        }
        let key = format!("role:{role}");
        let fencing_token = {
            let mut guard = self.lock();
            guard.roles.insert(role.to_owned());
            let counter = guard.lease_counters.entry(key).or_insert(0);
            *counter += 1;
            *counter
        };
        Ok(Box::new(SingleNodeLease {
            kind: LeaseKind::Role(role.to_owned()),
            fencing_token,
            expires_at: Mutex::new(expiry_from_now(lease_ttl)),
            ttl: lease_ttl,
            state: Arc::clone(&self.state),
            released: AtomicBool::new(false),
        }))
    }

    async fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        if key.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty lock key".into(),
            });
        }
        let bucket = format!("lock:{key}");
        let fencing_token = {
            let mut guard = self.lock();
            // Single-node coordinator: blocking acquire on a
            // contended lock is a programming error (no peer ever
            // releases it for us). Surface it as InvalidReference
            // so the caller's bug doesn't masquerade as a benign
            // lease wait.
            if guard.active_locks.contains(key) {
                return Err(ClusterError::InvalidReference {
                    message: format!(
                        "single-node coordinator: lock '{key}' already held by this node \
                         (non-reentrant). Use try_acquire_lock if your control flow \
                         expects contention."
                    ),
                });
            }
            guard.active_locks.insert(key.to_owned());
            let counter = guard.lease_counters.entry(bucket).or_insert(0);
            *counter += 1;
            *counter
        };
        Ok(Box::new(SingleNodeLease {
            kind: LeaseKind::Lock(key.to_owned()),
            fencing_token,
            expires_at: Mutex::new(expiry_from_now(lease_ttl)),
            ttl: lease_ttl,
            state: Arc::clone(&self.state),
            released: AtomicBool::new(false),
        }))
    }

    async fn try_acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        if role.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty role name".into(),
            });
        }
        let key = format!("role:{role}");
        let fencing_token = {
            let mut guard = self.lock();
            // Already held by THIS node — single-node coordinator
            // has no peers, so contention here means the same
            // process tried twice. Decline (the caller's contract
            // says try-variant returns None on contention).
            if guard.roles.contains(role) {
                return Ok(None);
            }
            guard.roles.insert(role.to_owned());
            let counter = guard.lease_counters.entry(key).or_insert(0);
            *counter += 1;
            *counter
        };
        Ok(Some(Box::new(SingleNodeLease {
            kind: LeaseKind::Role(role.to_owned()),
            fencing_token,
            expires_at: Mutex::new(expiry_from_now(lease_ttl)),
            ttl: lease_ttl,
            state: Arc::clone(&self.state),
            released: AtomicBool::new(false),
        })))
    }

    async fn try_acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        if key.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty lock key".into(),
            });
        }
        let bucket = format!("lock:{key}");
        let fencing_token = {
            let mut guard = self.lock();
            if guard.active_locks.contains(key) {
                // Already held by this node — decline.
                return Ok(None);
            }
            guard.active_locks.insert(key.to_owned());
            let counter = guard.lease_counters.entry(bucket).or_insert(0);
            *counter += 1;
            *counter
        };
        Ok(Some(Box::new(SingleNodeLease {
            kind: LeaseKind::Lock(key.to_owned()),
            fencing_token,
            expires_at: Mutex::new(expiry_from_now(lease_ttl)),
            ttl: lease_ttl,
            state: Arc::clone(&self.state),
            released: AtomicBool::new(false),
        })))
    }

    async fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: Bytes,
    ) -> Result<(), ClusterError> {
        if topic.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty topic".into(),
            });
        }
        let sender_opt = {
            let guard = self.lock();
            guard.pubsub.get(topic).cloned()
        };
        let Some(sender) = sender_opt else {
            // No subscribers → drop the message. Broadcast
            // semantics: "fire and forget; late subscribers don't
            // see earlier messages".
            return Ok(());
        };
        let node_id = self.lock().node_id.clone();
        let msg = PublishedMessage {
            topic: topic.to_owned(),
            routing_key: routing_key.map(String::from),
            payload,
            from_node: node_id,
        };
        // send() returns Err when there are no subscribers; that's
        // the same "drop the message" semantic, so ignore.
        let _ = sender.send(msg);
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
    ) -> Result<BoxPublishedMessageStream, ClusterError> {
        if topic.is_empty() {
            return Err(ClusterError::InvalidReference {
                message: "empty topic".into(),
            });
        }
        if group.is_some() {
            // Queue-group semantics need a real multi-node backend
            // with a single shared consumer. Single-node can't
            // round-robin in a way that survives a restart, so
            // surface the limitation loudly instead of pretending.
            return Err(ClusterError::InvalidReference {
                message: "single-node coordinator does not implement queue \
                     groups; use a multi-node backend (NATS / JetStream / \
                     Consul) for load-balanced subscribers"
                    .into(),
            });
        }
        let receiver = {
            let mut guard = self.lock();
            let sender = guard
                .pubsub
                .entry(topic.to_owned())
                .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0);
            sender.subscribe()
        };
        let expected_routing_key = routing_key.map(String::from);
        // Map the broadcast::Receiver → Stream<PublishedMessage>.
        // Errors from BroadcastStream (Lagged) are swallowed
        // silently — real consumers care about lag counts, but the
        // single-node coordinator is a "starter" backend and the
        // broadcast capacity is tuned high enough that healthy
        // gateway traffic won't trip it.
        let stream = BroadcastStream::new(receiver).filter_map(move |r| {
            let m = r.ok()?;
            if let Some(expected) = &expected_routing_key {
                // Routing-key filter: only deliver messages whose
                // routing_key matches the subscription's filter.
                if m.routing_key.as_deref() != Some(expected) {
                    return None;
                }
            }
            Some(m)
        });
        Ok(Box::pin(stream))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn node_info_has_expected_defaults() {
        let cc = SingleNodeClusterBackend::with_node_id("test-node");
        let info = cc.node_info().await;
        assert_eq!(info.node_id, "test-node");
        assert_eq!(info.address, "local");
        assert!(info.roles.is_empty());
        assert!(info.started_at.ends_with('Z'));
    }

    #[tokio::test]
    async fn list_peers_is_always_empty() {
        let cc = SingleNodeClusterBackend::new();
        assert!(cc.list_peers().await.is_empty());
    }

    #[tokio::test]
    async fn watch_peers_closes_immediately() {
        let cc = SingleNodeClusterBackend::new();
        let mut s = cc.watch_peers().await;
        assert!(s.next().await.is_none());
    }

    #[tokio::test]
    async fn acquire_leadership_bumps_fencing_token_per_role() {
        let cc = SingleNodeClusterBackend::new();
        let a = cc
            .acquire_leadership("replay-compactor", Duration::from_secs(30))
            .await
            .unwrap();
        let b = cc
            .acquire_leadership("replay-compactor", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(
            b.fencing_token() > a.fencing_token(),
            "fencing tokens MUST be strictly monotonic"
        );

        // Different role gets its own counter starting at 1.
        let c = cc
            .acquire_leadership("task-sweeper", Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(
            c.fencing_token(),
            1,
            "per-role counters start independently"
        );
    }

    #[tokio::test]
    async fn node_info_reports_currently_held_roles() {
        let cc = SingleNodeClusterBackend::new();
        let _a = cc
            .acquire_leadership("role-a", Duration::from_secs(30))
            .await
            .unwrap();
        let _b = cc
            .acquire_leadership("role-b", Duration::from_secs(30))
            .await
            .unwrap();
        let info = cc.node_info().await;
        assert!(info.roles.contains(&"role-a".to_string()));
        assert!(info.roles.contains(&"role-b".to_string()));
    }

    #[tokio::test]
    async fn release_role_drops_from_node_info() {
        let cc = SingleNodeClusterBackend::new();
        let lease = cc
            .acquire_leadership("role-a", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(cc.node_info().await.roles.contains(&"role-a".to_string()));
        lease.release().await.unwrap();
        assert!(!cc.node_info().await.roles.contains(&"role-a".to_string()));
    }

    #[tokio::test]
    async fn release_is_idempotent() {
        let cc = SingleNodeClusterBackend::new();
        let lease = cc
            .acquire_leadership("role-a", Duration::from_secs(30))
            .await
            .unwrap();
        lease.release().await.unwrap();
        lease.release().await.unwrap();
    }

    #[tokio::test]
    async fn acquire_lock_has_independent_counter_space() {
        let cc = SingleNodeClusterBackend::new();
        let lock = cc
            .acquire_lock("my-lock", Duration::from_secs(10))
            .await
            .unwrap();
        // First acquire on a new key starts at 1, matching leadership.
        assert_eq!(lock.fencing_token(), 1);
    }

    #[tokio::test]
    async fn renew_updates_expires_at() {
        let cc = SingleNodeClusterBackend::new();
        let lease = cc
            .acquire_leadership("role-a", Duration::from_secs(30))
            .await
            .unwrap();
        let before = lease.expires_at();
        tokio::time::sleep(Duration::from_secs(1)).await;
        lease.renew().await.unwrap();
        let after = lease.expires_at();
        // `after` should be >= `before` (second resolution).
        assert!(after >= before);
    }

    #[tokio::test]
    async fn renew_after_release_fails_cleanly() {
        let cc = SingleNodeClusterBackend::new();
        let lease = cc
            .acquire_leadership("role-a", Duration::from_secs(30))
            .await
            .unwrap();
        lease.release().await.unwrap();
        let err = lease.renew().await.unwrap_err();
        assert_eq!(err.kind_label(), "lease_expired");
    }

    #[tokio::test]
    async fn acquire_rejects_empty_role_and_key() {
        let cc = SingleNodeClusterBackend::new();
        // BoxActiveLease doesn't impl Debug — use match.
        match cc.acquire_leadership("", Duration::from_secs(10)).await {
            Err(e) => assert_eq!(e.kind_label(), "invalid_reference"),
            Ok(_) => panic!("expected invalid_reference"),
        }
        match cc.acquire_lock("", Duration::from_secs(10)).await {
            Err(e) => assert_eq!(e.kind_label(), "invalid_reference"),
            Ok(_) => panic!("expected invalid_reference"),
        }
    }

    #[tokio::test]
    async fn publish_subscribe_round_trips() {
        let cc = SingleNodeClusterBackend::new();
        let mut sub = cc.subscribe("t1", None, None).await.unwrap();
        cc.publish("t1", None, Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let m = sub.next().await.unwrap();
        assert_eq!(m.payload.as_ref(), b"hello");
        assert_eq!(m.topic, "t1");
    }

    #[tokio::test]
    async fn publish_broadcasts_to_every_subscriber() {
        let cc = SingleNodeClusterBackend::new();
        let mut a = cc.subscribe("t1", None, None).await.unwrap();
        let mut b = cc.subscribe("t1", None, None).await.unwrap();
        cc.publish("t1", None, Bytes::from_static(b"x"))
            .await
            .unwrap();
        let ma = a.next().await.unwrap();
        let mb = b.next().await.unwrap();
        assert_eq!(ma.payload.as_ref(), b"x");
        assert_eq!(mb.payload.as_ref(), b"x");
    }

    #[tokio::test]
    async fn subscribe_routing_key_filters_messages() {
        let cc = SingleNodeClusterBackend::new();
        let mut alpha = cc.subscribe("t1", None, Some("alpha")).await.unwrap();
        cc.publish("t1", Some("alpha"), Bytes::from_static(b"for-alpha"))
            .await
            .unwrap();
        cc.publish("t1", Some("beta"), Bytes::from_static(b"for-beta"))
            .await
            .unwrap();
        let m = alpha.next().await.unwrap();
        assert_eq!(m.payload.as_ref(), b"for-alpha");
        // No more messages — beta was filtered out. Use try_next
        // semantics via a short timeout.
        let second = tokio::time::timeout(Duration::from_millis(50), alpha.next()).await;
        assert!(
            second.is_err() || matches!(second, Ok(None)),
            "beta-routed message must not reach alpha subscriber"
        );
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_noop() {
        let cc = SingleNodeClusterBackend::new();
        cc.publish("t1", None, Bytes::from_static(b"nobody"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn subscribe_with_group_is_unsupported() {
        let cc = SingleNodeClusterBackend::new();
        // BoxPublishedMessageStream doesn't impl Debug — use
        // match instead of unwrap_err.
        match cc.subscribe("t1", Some("workers"), None).await {
            Err(e) => {
                assert_eq!(e.kind_label(), "invalid_reference");
                assert!(e.to_string().contains("queue groups"));
            }
            Ok(_) => panic!("expected invalid_reference"),
        }
    }

    #[tokio::test]
    async fn publish_and_subscribe_reject_empty_topic() {
        let cc = SingleNodeClusterBackend::new();
        let err = cc
            .publish("", None, Bytes::from_static(b"x"))
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
        match cc.subscribe("", None, None).await {
            Err(e) => assert_eq!(e.kind_label(), "invalid_reference"),
            Ok(_) => panic!("expected invalid_reference"),
        }
    }

    #[test]
    fn descriptor_yaml_parses_as_cluster() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.cluster.single-node");
        assert_eq!(d.class, PluginClass::Cluster);
    }

    // ----- non-blocking try-acquire variants ------------------

    #[tokio::test]
    async fn try_acquire_lock_returns_some_on_first_call() {
        let cc = SingleNodeClusterBackend::new();
        let lease = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap();
        assert!(lease.is_some(), "first try-acquire must succeed");
        assert_eq!(lease.unwrap().fencing_token(), 1);
    }

    #[tokio::test]
    async fn try_acquire_lock_returns_none_when_already_held() {
        let cc = SingleNodeClusterBackend::new();
        let _held = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap()
            .expect("first acquire must succeed");
        let second = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap();
        assert!(second.is_none(), "concurrent try-acquire must decline");
    }

    #[tokio::test]
    async fn try_acquire_lock_succeeds_again_after_release() {
        let cc = SingleNodeClusterBackend::new();
        let first = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap()
            .expect("first acquire must succeed");
        first.release().await.unwrap();
        // Drop the handle so Drop's safety net also runs cleanly.
        drop(first);
        let second = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            second.is_some(),
            "release+drop of prior lease must free the lock"
        );
    }

    #[tokio::test]
    async fn try_acquire_lock_succeeds_after_drop_without_explicit_release() {
        // Drop's safety-net releases membership in active_locks.
        let cc = SingleNodeClusterBackend::new();
        {
            let _first = cc
                .try_acquire_lock("hot-path", Duration::from_secs(10))
                .await
                .unwrap()
                .expect("first acquire must succeed");
            // _first dropped at end of scope without explicit release.
        }
        let second = cc
            .try_acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap();
        assert!(second.is_some(), "Drop alone must free the lock");
    }

    #[tokio::test]
    async fn try_acquire_leadership_declines_when_held_locally() {
        let cc = SingleNodeClusterBackend::new();
        let _first = cc
            .try_acquire_leadership("primary", Duration::from_secs(10))
            .await
            .unwrap()
            .expect("first acquire must succeed");
        let second = cc
            .try_acquire_leadership("primary", Duration::from_secs(10))
            .await
            .unwrap();
        assert!(second.is_none(), "non-reentrant: same role declines");
    }

    #[tokio::test]
    async fn try_acquire_lock_rejects_empty_key() {
        let cc = SingleNodeClusterBackend::new();
        match cc.try_acquire_lock("", Duration::from_secs(10)).await {
            Err(e) => assert_eq!(e.kind_label(), "invalid_reference"),
            Ok(_) => panic!("expected invalid_reference"),
        }
    }

    #[tokio::test]
    async fn acquire_lock_rejects_self_double_acquire() {
        // Strict reentrant check on the blocking variant — same
        // process must not double-hold a lock. Lockless callers
        // who actually want skip-on-contention should use
        // try_acquire_lock instead.
        let cc = SingleNodeClusterBackend::new();
        let _held = cc
            .acquire_lock("hot-path", Duration::from_secs(10))
            .await
            .unwrap();
        match cc.acquire_lock("hot-path", Duration::from_secs(10)).await {
            Err(e) => assert_eq!(e.kind_label(), "invalid_reference"),
            Ok(_) => panic!("expected invalid_reference"),
        }
    }
}
