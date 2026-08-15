use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Durable backstop. KV key prefix under which pending
/// cancellation events are mirrored so a reconnecting / restarting
/// subscriber can recover events lost in the at-most-once pub/sub gap.
const PENDING_PREFIX: &str = "mcpg.cancel.pending.";
/// How long a mirrored cancellation lingers in KV. Must comfortably
/// exceed the worst-case subscriber reconnect gap (redis re-subscribes
/// ~5s after a drop) and a brief replica restart, while still
/// self-cleaning. Cancellation is idempotent, so an over-long TTL only
/// costs a few redundant (no-op) re-deliveries.
const PENDING_TTL: Duration = Duration::from_secs(120);
/// Re-drain cadence. The live bus is the primary path; this loop only
/// recovers losses, so a coarse interval (matched to the redis
/// reconnect window) keeps overhead negligible.
const REDRAIN_INTERVAL: Duration = Duration::from_secs(5);
/// Cap on entries pulled per drain. Pending cancellations are
/// short-lived and low-volume; this is a generous backstop ceiling.
const DRAIN_LIMIT: usize = 1024;

/// Cancellation event broadcast across cluster nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationEvent {
    /// The request ID or task ID being cancelled.
    pub target_id: String,
    /// The kind of target: "request" or "task".
    pub kind: CancellationKind,
    /// Session that originated the cancellation.
    pub session_id: String,
    /// Principal (OIDC `sub` claim or equivalent) that owns the
    /// cancellation — used by the bus to partition NATS subjects /
    /// Redis channels so tenant ACLs can be enforced at the broker.
    /// `None` means unauthenticated caller; those events are routed
    /// to an `anonymous` partition.
    #[serde(default)]
    pub principal_id: Option<String>,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

/// Normalize a principal id into a single broker-safe subject/channel
/// token. NATS subjects disallow `.`, spaces, and wildcards; Redis
/// channels are more permissive but the same sanitizer keeps encoding
/// consistent across backends. Always yields exactly one token (no `.`),
/// so a `mcpg.cancel.*` wildcard subscribe matches every partition.
/// `None`/empty principal → the `anonymous` partition.
pub(crate) fn partition_key(principal_id: Option<&str>) -> String {
    match principal_id {
        None | Some("") => "anonymous".to_owned(),
        Some(s) => s
            .chars()
            .map(|c| match c {
                '.' | '*' | '>' | ' ' | '\t' | '\n' | '\r' | ':' => '_',
                c => c,
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CancellationKind {
    /// A JSON-RPC request cancellation (notifications/cancelled).
    Request,
    /// A task cancellation (tasks/cancel).
    Task,
}

/// Cluster-wide cancellation broadcast bus.
///
/// Publishes cancellation events to all cluster nodes. Each node subscribes
/// to receive events and acts on them locally (e.g., aborting pipelines or
/// tasks that match the cancelled target).
pub trait CancellationBus: Send + Sync + std::fmt::Debug {
    /// Subscribe to cancellation events across the cluster.
    fn subscribe(
        &self,
    ) -> Pin<Box<dyn Future<Output = mpsc::Receiver<CancellationEvent>> + Send + '_>>;

    /// Broadcast a cancellation event to all cluster nodes.
    fn publish(
        &self,
        event: CancellationEvent,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// BusBackedCancellationBus — single impl over the orthogonal TopicBus primitive
// ---------------------------------------------------------------------------

/// Cancellation bus backed by any [`mcpg_cluster_api::PubSub`] impl.
///
/// Publishes/subscribes a JSON-encoded [`CancellationEvent`] on a
/// single topic. Replaces the per-backend `RedisCancellationBus` /
/// `NatsCancellationBus` impls that lived in
/// `mcpg-plugin-backend-{redis,nats}` before the substrate was
/// unified behind the cluster API.
///
/// **Principal-scoped subject partitioning (opt-in).**
/// By default every cancellation flows through one topic (`mcpg.cancel`)
/// and replicas filter locally by `target_id`. When
/// `with_principal_partitioning(true)` is set, publishes go to
/// `mcpg.cancel.<partition>` (partition = the sanitized principal id, or
/// `anonymous`) and the subscriber uses a `mcpg.cancel.*` wildcard — so
/// broker-native subject ACLs (NATS subject perms, redis PSUBSCRIBE) can
/// fence per-principal cancel traffic. **Requires a wildcard-capable bus
/// (redis/nats); the in-process single-node bus is exact-match only**, so
/// the boot guard refuses to enable it without such a backend (it would
/// otherwise silently drop every cancellation). The KV backstop is
/// unaffected (it keys by target, not principal).
///
/// **Durable backstop.** Bare pub/sub is at-most-once — a redis
/// reconnect gap, a coordinator restart, or subscriber lag silently
/// drops a cancellation, leaving the targeted request running until its
/// own timeout. When constructed with a [`KeyValueStore`] backstop, each
/// publish also mirrors the event to KV (TTL'd, keyed by target) and the
/// subscriber periodically drains that prefix, so a reconnecting /
/// restarting subscriber recovers the events it missed. Re-delivery is
/// safe: applying a cancellation to an already-cancelled / absent target
/// is a no-op.
#[derive(Debug)]
pub struct BusBackedCancellationBus {
    bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>,
    topic: String,
    /// Durable backstop; `None` = pure at-most-once (the trivial
    /// in-memory default used by tests / single-node-without-KV).
    backstop: Option<Arc<dyn mcpg_cluster_api::KeyValueStore>>,
    /// When true, publish to `topic.<partition>` + subscribe
    /// `topic.*`. Default false = single flat `topic`.
    partition_by_principal: bool,
}

impl BusBackedCancellationBus {
    pub fn new(bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>) -> Self {
        Self {
            bus,
            topic: "mcpg.cancel".to_owned(),
            backstop: None,
            partition_by_principal: false,
        }
    }

    /// Construct with a durable KV backstop. The KV is typically
    /// the cluster coordinator's `key_value_store()` primitive; pass the
    /// same one the capability stores inherit so the backstop shares the
    /// cluster backbone.
    pub fn new_with_backstop(
        bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>,
        kv: Arc<dyn mcpg_cluster_api::KeyValueStore>,
    ) -> Self {
        Self {
            bus,
            topic: "mcpg.cancel".to_owned(),
            backstop: Some(kv),
            partition_by_principal: false,
        }
    }

    /// Enable principal-scoped subject partitioning.
    /// REQUIRES a wildcard-capable pub/sub backend (redis/nats) — the
    /// boot guard enforces this; do not enable on the single-node bus.
    pub fn with_principal_partitioning(mut self, on: bool) -> Self {
        self.partition_by_principal = on;
        self
    }

    /// Convenience: in-process `MemoryBus` backing, no backstop.
    pub fn new_in_memory() -> Self {
        Self::new(std::sync::Arc::new(
            crate::builtins::cluster_primitives::MemoryBus::new(),
        ))
    }

    /// The subject a cancellation publishes to: the flat `topic`, or
    /// `topic.<partition>` when principal-partitioning is on.
    fn publish_topic(&self, event: &CancellationEvent) -> String {
        if self.partition_by_principal {
            format!(
                "{}.{}",
                self.topic,
                partition_key(event.principal_id.as_deref())
            )
        } else {
            self.topic.clone()
        }
    }

    /// The pattern the subscriber listens on: the flat `topic`, or the
    /// `topic.*` wildcard covering every principal partition.
    fn subscribe_pattern(&self) -> String {
        if self.partition_by_principal {
            format!("{}.*", self.topic)
        } else {
            self.topic.clone()
        }
    }

    /// KV key under which a cancellation for `event` is mirrored. Keyed
    /// by kind + target so a request and a task that happen to share an
    /// id don't collide, and a re-cancel of the same target overwrites
    /// (idempotent) rather than accumulating.
    fn pending_key(event: &CancellationEvent) -> String {
        let kind = match event.kind {
            CancellationKind::Request => "request",
            CancellationKind::Task => "task",
        };
        format!("{PENDING_PREFIX}{kind}.{}", event.target_id)
    }
}

impl CancellationBus for BusBackedCancellationBus {
    fn subscribe(
        &self,
    ) -> Pin<Box<dyn Future<Output = mpsc::Receiver<CancellationEvent>> + Send + '_>> {
        let bus = self.bus.clone();
        let pattern = self.subscribe_pattern();
        let backstop = self.backstop.clone();
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(256);
            // Live pub/sub path (primary). When principal-partitioning is on
            // this is a `mcpg.cancel.*` wildcard; else the flat `mcpg.cancel`.
            let stream = match bus.subscribe(&pattern, None).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "topic bus subscribe failed for cancellation");
                    None
                }
            };
            if let Some(mut stream) = stream {
                let tx_live = tx.clone();
                tokio::spawn(async move {
                    use futures::StreamExt;
                    while let Some(msg) = stream.next().await {
                        let Ok(msg) = msg else { break };
                        let Ok(event) = serde_json::from_slice::<CancellationEvent>(&msg.payload)
                        else {
                            continue;
                        };
                        if tx_live.send(event).await.is_err() {
                            break;
                        }
                    }
                });
            }
            // Durable-backstop drain: recover cancellations that the
            // at-most-once live path dropped (reconnect gap / restart /
            // lag). Each KV key is emitted at most once per subscriber
            // lifetime via the `seen` set, which is reset to the live key
            // set each pass so TTL'd-out keys are forgotten (a same-target
            // re-cancel after expiry is a genuinely new event).
            if let Some(kv) = backstop {
                let tx_drain = tx;
                tokio::spawn(async move {
                    let mut seen: HashSet<String> = HashSet::new();
                    loop {
                        match kv.list_prefix(PENDING_PREFIX, DRAIN_LIMIT).await {
                            Ok(entries) => {
                                let mut current = HashSet::with_capacity(entries.len());
                                for (key, entry) in entries {
                                    current.insert(key.clone());
                                    if seen.contains(&key) {
                                        continue;
                                    }
                                    if let Ok(event) =
                                        serde_json::from_slice::<CancellationEvent>(&entry.bytes)
                                    {
                                        if tx_drain.send(event).await.is_err() {
                                            return;
                                        }
                                        metrics::counter!(
                                            "mcpg_cancellation_backstop_recovered_total"
                                        )
                                        .increment(1);
                                    }
                                }
                                seen = current;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "cancellation backstop drain failed (W-14); live bus only this pass"
                                );
                            }
                        }
                        tokio::time::sleep(REDRAIN_INTERVAL).await;
                    }
                });
            }
            rx
        })
    }

    fn publish(
        &self,
        event: CancellationEvent,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let bus = self.bus.clone();
        // Principal-partitioned subject when enabled, else the flat topic.
        // Computed before `event` is moved into the future.
        let topic = self.publish_topic(&event);
        let backstop = self.backstop.clone();
        Box::pin(async move {
            let payload = serde_json::to_vec(&event)?;
            // Mirror to the durable backstop BEFORE the live publish
            // so a subscriber that comes up between the two still recovers
            // it via drain. Best-effort — the live bus is the primary
            // path, so a KV write failure only forfeits recovery, not the
            // cancellation itself.
            if let Some(kv) = &backstop {
                let key = Self::pending_key(&event);
                if let Err(e) = kv
                    .put(&key, bytes::Bytes::from(payload.clone()), Some(PENDING_TTL))
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        key = %key,
                        "cancellation backstop KV put failed (W-14); relying on live bus only"
                    );
                }
            }
            bus.publish(&topic, bytes::Bytes::from(payload))
                .await
                .map_err(|e| anyhow::anyhow!("topic bus publish: {e}"))
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_process_publish_and_subscribe() {
        let bus = BusBackedCancellationBus::new_in_memory();
        let mut rx = bus.subscribe().await;

        bus.publish(CancellationEvent {
            target_id: "req-123".to_owned(),
            kind: CancellationKind::Request,
            session_id: "sess-1".to_owned(),
            principal_id: None,
            reason: Some("user cancelled".to_owned()),
        })
        .await
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("receive timeout")
            .expect("event received");
        assert_eq!(event.target_id, "req-123");
        assert_eq!(event.kind, CancellationKind::Request);
        assert_eq!(event.session_id, "sess-1");
        assert_eq!(event.reason, Some("user cancelled".to_owned()));
    }

    #[test]
    fn partition_key_sanitizes_nats_reserved_chars() {
        assert_eq!(partition_key(None), "anonymous");
        assert_eq!(partition_key(Some("")), "anonymous");
        assert_eq!(
            partition_key(Some("alice@example.com")),
            "alice@example_com"
        );
        assert_eq!(partition_key(Some("sub.with.dots")), "sub_with_dots");
        assert_eq!(partition_key(Some("has space")), "has_space");
        assert_eq!(partition_key(Some("has*wild")), "has_wild");
        assert_eq!(partition_key(Some("has>gt")), "has_gt");
    }

    #[test]
    fn nats_publish_subject_partitions_by_principal() {
        // Exercises partition_key independently — constructing a real
        // NatsCancellationBus requires a live NATS client and lives in
        // the plugin crate's integration tests.
        assert_eq!(partition_key(Some("user-1")), "user-1");
    }

    #[tokio::test]
    async fn backstop_recovers_event_published_before_subscribe() {
        // A subscriber that comes up AFTER a cancellation was
        // published would miss it on the at-most-once live bus (a
        // late MemoryBus subscriber never sees prior broadcasts). With
        // the durable KV backstop it recovers the event via drain.
        use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv};
        let bus = std::sync::Arc::new(MemoryBus::new());
        let kv = std::sync::Arc::new(MemoryKv::new());
        let cbus = BusBackedCancellationBus::new_with_backstop(bus, kv);

        // Publish FIRST — no subscriber yet, so the live broadcast is lost.
        cbus.publish(CancellationEvent {
            target_id: "req-late".to_owned(),
            kind: CancellationKind::Request,
            session_id: "sess-late".to_owned(),
            principal_id: None,
            reason: Some("backstop".to_owned()),
        })
        .await
        .unwrap();

        // Subscribe AFTER — receipt can only come from the KV drain.
        let mut rx = cbus.subscribe().await;
        let event = tokio::time::timeout(REDRAIN_INTERVAL * 2 + Duration::from_secs(1), rx.recv())
            .await
            .expect("backstop drain should deliver within a redrain cycle")
            .expect("event recovered");
        assert_eq!(event.target_id, "req-late");
        assert_eq!(event.kind, CancellationKind::Request);
    }

    #[tokio::test]
    async fn backstop_does_not_redeliver_same_key_to_one_subscriber() {
        // The per-subscriber `seen` set means a still-live pending
        // key is emitted exactly once, not re-emitted every redrain pass.
        use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv};
        let bus = std::sync::Arc::new(MemoryBus::new());
        let kv = std::sync::Arc::new(MemoryKv::new());
        let cbus = BusBackedCancellationBus::new_with_backstop(bus, kv);

        cbus.publish(CancellationEvent {
            target_id: "req-dedup".to_owned(),
            kind: CancellationKind::Task,
            session_id: "sess-dedup".to_owned(),
            principal_id: None,
            reason: None,
        })
        .await
        .unwrap();

        let mut rx = cbus.subscribe().await;
        // First drain delivers it.
        let first = tokio::time::timeout(REDRAIN_INTERVAL * 2 + Duration::from_secs(1), rx.recv())
            .await
            .expect("first delivery")
            .expect("event");
        assert_eq!(first.target_id, "req-dedup");
        // A second redrain pass must NOT re-deliver the same key.
        let second =
            tokio::time::timeout(REDRAIN_INTERVAL + Duration::from_secs(1), rx.recv()).await;
        assert!(
            second.is_err(),
            "still-live key must not be re-emitted within one subscriber lifetime"
        );
    }

    #[test]
    fn partitioning_off_uses_flat_topic_and_pattern() {
        // Default (single-node safe): one flat topic, exact-match subscribe.
        let bus = BusBackedCancellationBus::new_in_memory();
        let event = CancellationEvent {
            target_id: "req-1".to_owned(),
            kind: CancellationKind::Request,
            session_id: "sess-1".to_owned(),
            principal_id: Some("alice".to_owned()),
            reason: None,
        };
        assert_eq!(bus.publish_topic(&event), "mcpg.cancel");
        assert_eq!(bus.subscribe_pattern(), "mcpg.cancel");
    }

    #[test]
    fn partitioning_on_scopes_topic_by_principal_and_subscribes_wildcard() {
        // Publish to `mcpg.cancel.<principal>`, subscribe on the
        // `mcpg.cancel.*` wildcard so subject ACLs can fence per principal.
        let bus = BusBackedCancellationBus::new_in_memory().with_principal_partitioning(true);
        let event = CancellationEvent {
            target_id: "req-1".to_owned(),
            kind: CancellationKind::Request,
            session_id: "sess-1".to_owned(),
            principal_id: Some("alice@example.com".to_owned()),
            reason: None,
        };
        // Principal id is sanitized into exactly one subject token (no `.`),
        // so the single-segment `*` wildcard matches it.
        assert_eq!(bus.publish_topic(&event), "mcpg.cancel.alice@example_com");
        assert_eq!(bus.subscribe_pattern(), "mcpg.cancel.*");
    }

    #[test]
    fn partitioning_on_anonymous_principal_partition() {
        // A missing principal lands in the `anonymous` partition rather than
        // an empty subject token, so the wildcard still matches it.
        let bus = BusBackedCancellationBus::new_in_memory().with_principal_partitioning(true);
        let event = CancellationEvent {
            target_id: "req-1".to_owned(),
            kind: CancellationKind::Task,
            session_id: "sess-1".to_owned(),
            principal_id: None,
            reason: None,
        };
        assert_eq!(bus.publish_topic(&event), "mcpg.cancel.anonymous");
    }

    #[tokio::test]
    async fn in_process_broadcast_to_multiple_subscribers() {
        let bus = BusBackedCancellationBus::new_in_memory();
        let mut rx1 = bus.subscribe().await;
        let mut rx2 = bus.subscribe().await;

        bus.publish(CancellationEvent {
            target_id: "task-456".to_owned(),
            kind: CancellationKind::Task,
            session_id: "sess-2".to_owned(),
            principal_id: None,
            reason: None,
        })
        .await
        .unwrap();

        let timeout = std::time::Duration::from_secs(1);
        let e1 = tokio::time::timeout(timeout, rx1.recv())
            .await
            .unwrap()
            .unwrap();
        let e2 = tokio::time::timeout(timeout, rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e1.target_id, "task-456");
        assert_eq!(e2.target_id, "task-456");
    }
}
