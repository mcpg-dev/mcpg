//! In-gateway server-request bridge for federation.
//!
//! The gateway's pipeline already bridges server→client requests
//! (elicitation/sampling/roots) via a **store-based, HTTP-handler-driven**
//! suspend/resume. Federation dispatch can't use that: `call_tool` runs in a
//! tokio task holding the open upstream connection, so it must *await the
//! client's answer in place* and feed it back to the upstream on the same
//! logical call.
//!
//! [`ServerRequestBridge`] is that missing primitive: publish a server→client
//! request on the session's delivery stream and await the client's response on
//! an in-memory `oneshot`. The HTTP response intake
//! (`runtime::GatewayRuntime::handle_server_request_response`) routes a matching
//! response id here *before* the pipeline-resume path. Bridge ids are
//! gateway-minted + namespaced (`fed-…`) so they never collide with an
//! upstream id or a pipeline server-request id.
//!
//! **Cross-replica rendezvous (coordinator-backed).** The in-process
//! `DashMap` of `oneshot` waiters is the fast same-replica path. When a cluster
//! coordinator is present the bridge ALSO records the pending request on the
//! coordinator KV (keyed by the federation id, carrying the owning session +
//! a TTL) and subscribes a per-id coordinator bus topic. If the client's answer
//! lands on a *different* replica than the one awaiting, the answer leg finds no
//! local waiter, validates the responder's session against the KV record's
//! owning session (rejecting a foreign principal — mirrors the resume/cancel
//! ownership check), claims the record exactly-once (a single-winner KV delete),
//! and publishes the answer on that id's bus topic. The awaiting replica —
//! subscribed to that topic — completes its local oneshot. `single_node` /
//! no-coordinator deployments skip the KV/bus calls entirely; the in-process
//! map is the whole story.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::protocol::JSONRPC_VERSION;
use crate::runtime::delivery_bus::DeliveryBus;
use crate::runtime::pipeline_store::{DeliveryKind, DeliveryMessage};

/// Failure modes of a bridged server-request.
#[derive(Debug)]
pub(crate) enum BridgeError {
    /// The client did not respond within the bridge timeout.
    Timeout,
    /// The client answered with a JSON-RPC error.
    ClientError(String),
    /// Publishing the request onto the delivery stream failed.
    Publish(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "server-request to client timed out"),
            Self::ClientError(m) => write!(f, "client returned an error: {m}"),
            Self::Publish(m) => write!(f, "server-request publish failed: {m}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// request id → `(owning session_id, waiter)`. Shared behind an `Arc` so a
/// per-id bus-subscriber task can resolve the waiter on a cross-replica answer.
type WaiterMap = Arc<DashMap<String, (String, oneshot::Sender<Result<Value, String>>)>>;

/// The pending-request record persisted to coordinator KV on `ask_client`.
/// Holds the owning session so the answer leg (on any replica) can reject a
/// foreign responder, and is the single-winner claim anchor (one delete wins).
#[derive(Serialize, Deserialize)]
struct PendingRecord {
    owner_session: String,
}

/// The answer payload published on a federation id's bus topic. `result` wins
/// over `error`; both absent resolves to `null`.
#[derive(Serialize, Deserialize)]
struct AnswerEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

/// Coordinator-backed cross-replica rendezvous. Present only when a cluster
/// coordinator is wired; `single_node`/no-coordinator deployments leave this
/// `None` and the bridge is the in-process `DashMap` alone.
struct ClusterRendezvous {
    coordinator: Arc<dyn mcpg_cluster_api::ClusterBackend>,
    /// Coordinator KV (the single-winner claim + owner record). `None` when the
    /// coordinator advertises only `bus` (no KV): without a record the
    /// cross-replica owner check + delete-claim are unavailable, so a foreign
    /// answer can't be validated and exactly-once relies solely on the awaiting
    /// replica's local oneshot — the answer leg therefore does NOT take the bus
    /// path when KV is absent (it returns a miss and the federated call times
    /// out, same as before, rather than admit an un-owner-checked answer).
    kv: Option<Arc<dyn mcpg_cluster_api::KeyValueStore>>,
    /// Opt-in per-deployment tenant segment; prefixes KV keys (`t.<seg>/`) and
    /// bus topics (`t.<seg>.`) for broker-native ACL fencing. Matches the
    /// capability-store/bus prefix convention.
    tenant_segment: Option<String>,
    /// TTL on the pending KV record. Bounds orphan records when an awaiter dies
    /// before its answer arrives.
    pending_ttl: Duration,
}

impl ClusterRendezvous {
    fn pending_key(&self, id: &str) -> String {
        match &self.tenant_segment {
            Some(seg) => format!("t.{seg}/fed_pending:{id}"),
            None => format!("fed_pending:{id}"),
        }
    }

    fn answer_topic(&self, id: &str) -> String {
        match &self.tenant_segment {
            Some(seg) => format!("t.{seg}.mcpg.fed.answer.{id}"),
            None => format!("mcpg.fed.answer.{id}"),
        }
    }
}

/// Publish a server→client request and await the client's response in-task.
pub(crate) struct ServerRequestBridge {
    delivery_bus: Arc<dyn DeliveryBus>,
    /// Pending in-process waiters (the fast same-replica path). The owning
    /// session is the only session permitted to answer this request: a response
    /// is resolved only when the responder's session matches. Removed on
    /// response, timeout, or drop.
    waiters: WaiterMap,
    /// Coordinator-backed cross-replica rendezvous; `None` on single-node.
    cluster: Option<ClusterRendezvous>,
}

impl ServerRequestBridge {
    pub(crate) fn new(delivery_bus: Arc<dyn DeliveryBus>) -> Self {
        Self {
            delivery_bus,
            waiters: Arc::new(DashMap::new()),
            cluster: None,
        }
    }

    /// Attach the cluster coordinator so server→client requests rendezvous
    /// across replicas (KV pending record + per-id bus topic). When never
    /// called (single-node / no coordinator) the bridge is the in-process map.
    pub(crate) fn with_cluster(
        mut self,
        coordinator: Arc<dyn mcpg_cluster_api::ClusterBackend>,
        tenant_segment: Option<String>,
    ) -> Self {
        let kv = coordinator.key_value_store();
        self.cluster = Some(ClusterRendezvous {
            coordinator,
            kv,
            tenant_segment,
            pending_ttl: Duration::from_secs(300),
        });
        self
    }

    /// Publish a server→client request on `session_id`'s delivery stream and
    /// await the client's response, bounded by `timeout`. `id` must be a
    /// gateway-minted, namespaced id (never an upstream id).
    pub(crate) async fn ask_client(
        &self,
        session_id: &str,
        id: String,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.waiters.insert(id.clone(), (session_id.to_owned(), tx));

        // Coordinator-backed rendezvous: record the pending request (owner +
        // TTL) and subscribe this id's answer topic BEFORE publishing the
        // request, so an answer landing on another replica can find the owner
        // and the awaiting replica never misses the bus signal. The pending
        // record is the cross-replica owner-check + single-winner claim anchor;
        // a KV failure forfeits the cross-replica path, but the local
        // same-replica oneshot still resolves.
        let subscriber = if let Some(cluster) = &self.cluster {
            if let Some(kv) = &cluster.kv {
                let record = PendingRecord {
                    owner_session: session_id.to_owned(),
                };
                if let Ok(bytes) = serde_json::to_vec(&record)
                    && let Err(e) = kv
                        .put(
                            &cluster.pending_key(&id),
                            Bytes::from(bytes),
                            Some(cluster.pending_ttl),
                        )
                        .await
                {
                    tracing::warn!(
                        id = %id, error = %e,
                        "federation bridge: pending-record KV put failed; \
                         cross-replica answer will not resolve"
                    );
                }
            }
            self.spawn_answer_subscriber(cluster, &id)
        } else {
            None
        };

        let request = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "method": method,
            "params": params,
        });
        let message = DeliveryMessage {
            kind: DeliveryKind::ServerRequest,
            jsonrpc_message: request,
            delivery_id: String::new(),
        };
        if let Err(e) = self.delivery_bus.publish(session_id, message).await {
            self.waiters.remove(&id);
            if let Some(h) = subscriber {
                h.abort();
            }
            self.clear_pending_record(&id).await;
            return Err(BridgeError::Publish(e.to_string()));
        }

        let outcome = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(client_err))) => Err(BridgeError::ClientError(client_err)),
            // Sender dropped without sending (e.g. bridge torn down).
            Ok(Err(_recv)) => Err(BridgeError::Timeout),
            // Elapsed: reclaim the waiter slot so it doesn't leak.
            Err(_elapsed) => {
                self.waiters.remove(&id);
                Err(BridgeError::Timeout)
            }
        };
        if let Some(h) = subscriber {
            h.abort();
        }
        self.clear_pending_record(&id).await;
        outcome
    }

    /// Subscribe this id's answer bus topic and complete the local oneshot when
    /// a peer replica publishes the answer. Returns the task handle so the
    /// awaiter can abort it on resolve/timeout. The subscriber resolves the
    /// shared waiter map directly (the answer's owner was already validated on
    /// the publishing replica against the KV record). Returns `None` when the
    /// coordinator exposes no KV (no record to own-check ⇒ no cross-replica
    /// rendezvous).
    fn spawn_answer_subscriber(
        &self,
        cluster: &ClusterRendezvous,
        id: &str,
    ) -> Option<tokio::task::JoinHandle<()>> {
        cluster.kv.as_ref()?;
        let coordinator = Arc::clone(&cluster.coordinator);
        let topic = cluster.answer_topic(id);
        let id = id.to_owned();
        let waiters = Arc::clone(&self.waiters);
        Some(tokio::spawn(async move {
            let mut stream = match coordinator.subscribe(&topic, None, None).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        id = %id, error = ?e,
                        "federation bridge: answer-topic subscribe failed; \
                         cross-replica answer for this id will not resolve here"
                    );
                    return;
                }
            };
            use futures::StreamExt;
            while let Some(msg) = stream.next().await {
                let Ok(env) = serde_json::from_slice::<AnswerEnvelope>(&msg.payload) else {
                    continue;
                };
                // The publishing replica already owner-checked + single-winner
                // claimed this answer; the local waiter slot is the
                // exactly-once consumer on THIS (awaiting) replica.
                if let Some((_, (_owner, tx))) = waiters.remove(&id) {
                    let payload = match (env.result, env.error) {
                        (Some(r), _) => Ok(r),
                        (None, Some(e)) => Err(e.to_string()),
                        (None, None) => Ok(Value::Null),
                    };
                    let _ = tx.send(payload);
                }
                return;
            }
        }))
    }

    /// Forward a server→client *notification* (no response expected) to the
    /// session's delivery stream — used to relay upstream `notifications/progress`
    /// during a bridged call (P3-D). Best-effort.
    pub(crate) async fn forward_notification(&self, session_id: &str, jsonrpc_message: Value) {
        let message = DeliveryMessage {
            kind: DeliveryKind::Notification,
            jsonrpc_message,
            delivery_id: String::new(),
        };
        if let Err(e) = self.delivery_bus.publish(session_id, message).await {
            tracing::debug!(
                session = %session_id, error = %e,
                "federation notification forward failed"
            );
        }
    }

    /// Best-effort delete of the pending KV record for `id` (the single-winner
    /// claim anchor). Called on the awaiting replica's terminal paths.
    async fn clear_pending_record(&self, id: &str) {
        if let Some(cluster) = &self.cluster
            && let Some(kv) = &cluster.kv
        {
            let _ = kv.delete(&cluster.pending_key(id)).await;
        }
    }

    /// Resolve the local waiter for `id` IFF it is owned by
    /// `responder_session_id`. Returns whether it consumed the waiter.
    fn resolve_local(
        &self,
        id: &str,
        responder_session_id: &str,
        result: Option<Value>,
        error: Option<Value>,
    ) -> bool {
        let Some((_, (_owner, tx))) = self
            .waiters
            .remove_if(id, |_id, (owner, _tx)| owner == responder_session_id)
        else {
            return false;
        };
        let payload = match (result, error) {
            (Some(r), _) => Ok(r),
            (None, Some(e)) => Err(e.to_string()),
            (None, None) => Ok(Value::Null),
        };
        // Receiver may have already timed out and gone — that's fine.
        let _ = tx.send(payload);
        true
    }

    /// Route a client's response (by request id) to the awaiting caller.
    /// Returns `true` iff this call consumed the response — either the local
    /// waiter (same replica) or a coordinator-backed claim (the awaiter is on
    /// another replica). The HTTP intake then skips the pipeline-resume path.
    ///
    /// Fast path: a local waiter owned by `responder_session_id` resolves
    /// directly. Otherwise, when a coordinator is wired, the bus path validates
    /// the responder's session against the persisted owner (rejecting a foreign
    /// principal — mirrors the resume/cancel ownership check), claims the record
    /// exactly-once (single-winner KV delete), and publishes the answer on the
    /// id's bus topic for the awaiting replica to complete its oneshot.
    ///
    /// A `result` wins over an `error`; both absent resolves to `null`.
    pub(crate) async fn deliver_response(
        &self,
        id: &str,
        responder_session_id: &str,
        result: Option<Value>,
        error: Option<Value>,
    ) -> bool {
        // Fast path: a waiter for this id lives on THIS replica.
        if let Some(owner) = self.waiters.get(id).map(|e| e.0.clone()) {
            if owner == responder_session_id {
                let resolved = self.resolve_local(id, responder_session_id, result, error);
                if resolved {
                    self.clear_pending_record(id).await;
                }
                return resolved;
            }
            // A local waiter exists but the responder is a different session —
            // reject (do not consume) and do not fall through to the bus path.
            tracing::warn!(
                id = %id,
                responder_session = %responder_session_id,
                "federation bridge: server-request response from a non-owning session — ignored"
            );
            return false;
        }

        // Cross-replica path: the awaiter is on a different replica. Validate
        // the owner against the KV record and claim it exactly-once.
        let Some(cluster) = &self.cluster else {
            return false;
        };
        let Some(kv) = &cluster.kv else {
            return false;
        };
        let key = cluster.pending_key(id);
        let record = match kv.get(&key).await {
            Ok(Some(entry)) => match serde_json::from_slice::<PendingRecord>(&entry.bytes) {
                Ok(r) => r,
                Err(_) => return false,
            },
            // No pending record: unknown id, expired, or already claimed.
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(id = %id, error = %e, "federation bridge: pending-record KV get failed");
                return false;
            }
        };
        if record.owner_session != responder_session_id {
            tracing::warn!(
                id = %id,
                responder_session = %responder_session_id,
                "federation bridge: cross-replica response from a non-owning session — ignored"
            );
            return false;
        }
        // Exactly-once single-winner claim: only the caller that deletes the
        // record proceeds to publish. A racing double-deliver loses the delete
        // and returns false (no double publish, no double consume).
        match kv.delete(&key).await {
            Ok(true) => {}
            Ok(false) => return false,
            Err(e) => {
                tracing::warn!(id = %id, error = %e, "federation bridge: claim delete failed");
                return false;
            }
        }
        let env = AnswerEnvelope { result, error };
        let payload = match serde_json::to_vec(&env) {
            Ok(b) => Bytes::from(b),
            Err(_) => return false,
        };
        if let Err(e) = cluster
            .coordinator
            .publish(&cluster.answer_topic(id), None, payload)
            .await
        {
            tracing::warn!(
                id = %id, error = ?e,
                "federation bridge: answer publish failed; the awaiting replica will time out"
            );
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::cluster_single_node::SingleNodeClusterBackend;
    use crate::runtime::delivery_bus::BusBackedDeliveryBus;
    use std::time::Duration;

    #[tokio::test]
    async fn ask_publishes_then_resolves_on_client_response() {
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));

        // The client's delivery stream must be live before the ask publishes.
        let mut rx = bus.subscribe("sess-1").await;

        let b = Arc::clone(&bridge);
        let asked = tokio::spawn(async move {
            b.ask_client(
                "sess-1",
                "fed-1".into(),
                "elicitation/create",
                json!({ "message": "name?" }),
                Duration::from_secs(5),
            )
            .await
        });

        // The request reaches the client's stream with the gateway-minted id.
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("delivery within timeout")
            .expect("a delivery message");
        assert_eq!(msg.jsonrpc_message["method"], "elicitation/create");
        assert_eq!(msg.jsonrpc_message["id"], "fed-1");

        // The client answers; the awaiting caller resolves with the result.
        assert!(
            bridge
                .deliver_response("fed-1", "sess-1", Some(json!({ "name": "ada" })), None)
                .await
        );
        let result = asked.await.expect("join").expect("bridged ok");
        assert_eq!(result, json!({ "name": "ada" }));
    }

    /// Regression: a response from a DIFFERENT session must not resolve
    /// (or cancel) another session's in-flight federated server-request, even
    /// with the correct (guessable) id. The legitimate owner can still answer.
    #[tokio::test]
    async fn forged_response_from_other_session_is_rejected() {
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));
        let _rx = bus.subscribe("victim").await;

        let b = Arc::clone(&bridge);
        let asked = tokio::spawn(async move {
            b.ask_client(
                "victim",
                "fed-1".into(),
                "sampling/createMessage",
                json!({}),
                Duration::from_secs(5),
            )
            .await
        });
        // Let the ask register its waiter.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attacker (different session) tries to forge the answer with the
        // guessable id — must be rejected and must NOT consume the waiter.
        assert!(
            !bridge
                .deliver_response("fed-1", "attacker", Some(json!({ "forged": true })), None)
                .await
        );

        // The legitimate owner can still resolve it.
        assert!(
            bridge
                .deliver_response("fed-1", "victim", Some(json!({ "ok": true })), None)
                .await
        );
        let result = asked.await.expect("join").expect("bridged ok");
        assert_eq!(result, json!({ "ok": true }));
    }

    #[tokio::test]
    async fn times_out_and_reclaims_the_waiter() {
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = ServerRequestBridge::new(Arc::clone(&bus));
        let _rx = bus.subscribe("sess-1").await;

        let r = bridge
            .ask_client(
                "sess-1",
                "fed-2".into(),
                "roots/list",
                json!({}),
                Duration::from_millis(80),
            )
            .await;
        assert!(matches!(r, Err(BridgeError::Timeout)));
        // The waiter slot must not leak after a timeout.
        assert!(bridge.waiters.is_empty());
    }

    #[tokio::test]
    async fn deliver_to_unknown_id_is_a_noop() {
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = ServerRequestBridge::new(bus);
        assert!(
            !bridge
                .deliver_response("nope", "sess-1", Some(json!({})), None)
                .await
        );
    }

    // -----------------------------------------------------------------------
    // Coordinator-backed cross-replica rendezvous.
    //
    // Two `ServerRequestBridge`s sharing ONE `SingleNodeClusterBackend`
    // (each with its own in-process delivery bus) stand in for two replicas
    // sharing one coordinator: replica A awaits, the answer lands on B.
    // -----------------------------------------------------------------------

    fn clustered_bridge(coordinator: &Arc<SingleNodeClusterBackend>) -> Arc<ServerRequestBridge> {
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        Arc::new(ServerRequestBridge::new(bus).with_cluster(
            Arc::clone(coordinator) as Arc<dyn mcpg_cluster_api::ClusterBackend>,
            None,
        ))
    }

    /// The answer arrives on a DIFFERENT replica than the awaiter: replica B's
    /// `deliver_response` finds no local waiter, owner-checks the KV record,
    /// claims it, and publishes on the bus; replica A's per-id subscription
    /// completes the awaiting oneshot.
    #[tokio::test]
    async fn cross_replica_answer_resolves_the_awaiter_via_bus() {
        let coordinator = SingleNodeClusterBackend::new();
        let replica_a = clustered_bridge(&coordinator);
        let replica_b = clustered_bridge(&coordinator);

        let a = Arc::clone(&replica_a);
        let asked = tokio::spawn(async move {
            a.ask_client(
                "sess-1",
                "fed-x".into(),
                "elicitation/create",
                json!({ "message": "name?" }),
                Duration::from_secs(5),
            )
            .await
        });
        // Let A register its KV record + bus subscription.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // The owning session answers on replica B (no local waiter there).
        assert!(
            replica_b
                .deliver_response("fed-x", "sess-1", Some(json!({ "name": "ada" })), None)
                .await,
            "B should claim + publish the cross-replica answer"
        );

        let result = tokio::time::timeout(Duration::from_secs(2), asked)
            .await
            .expect("awaiter resolves")
            .expect("join")
            .expect("bridged ok");
        assert_eq!(result, json!({ "name": "ada" }));
    }

    /// A foreign principal answering on another replica is rejected by the
    /// KV-record owner check (mirrors resume/cancel ownership). The legitimate
    /// owner can still answer afterwards.
    #[tokio::test]
    async fn cross_replica_foreign_principal_is_rejected() {
        let coordinator = SingleNodeClusterBackend::new();
        let replica_a = clustered_bridge(&coordinator);
        let replica_b = clustered_bridge(&coordinator);

        let a = Arc::clone(&replica_a);
        let asked = tokio::spawn(async move {
            a.ask_client(
                "victim",
                "fed-y".into(),
                "sampling/createMessage",
                json!({}),
                Duration::from_secs(5),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Foreign session answering on B must be rejected and must NOT consume
        // the pending record (so the real owner can still answer).
        assert!(
            !replica_b
                .deliver_response("fed-y", "attacker", Some(json!({ "forged": true })), None)
                .await
        );

        // The legitimate owner answers on B and resolves A.
        assert!(
            replica_b
                .deliver_response("fed-y", "victim", Some(json!({ "ok": true })), None)
                .await
        );
        let result = tokio::time::timeout(Duration::from_secs(2), asked)
            .await
            .expect("awaiter resolves")
            .expect("join")
            .expect("bridged ok");
        assert_eq!(result, json!({ "ok": true }));
    }

    /// Exactly-once under a double-deliver: two replicas answer the same id
    /// concurrently; the single-winner KV delete claim lets exactly one publish.
    #[tokio::test]
    async fn cross_replica_double_deliver_is_exactly_once() {
        let coordinator = SingleNodeClusterBackend::new();
        let replica_a = clustered_bridge(&coordinator);
        let replica_b = clustered_bridge(&coordinator);
        let replica_c = clustered_bridge(&coordinator);

        let a = Arc::clone(&replica_a);
        let asked = tokio::spawn(async move {
            a.ask_client(
                "sess-2",
                "fed-z".into(),
                "elicitation/create",
                json!({}),
                Duration::from_secs(5),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Two peers race to deliver the same answer; only one wins the claim.
        let b = Arc::clone(&replica_b);
        let c = Arc::clone(&replica_c);
        let win_b = tokio::spawn(async move {
            b.deliver_response("fed-z", "sess-2", Some(json!({ "from": "b" })), None)
                .await
        });
        let win_c = tokio::spawn(async move {
            c.deliver_response("fed-z", "sess-2", Some(json!({ "from": "c" })), None)
                .await
        });
        let (rb, rc) = (win_b.await.unwrap(), win_c.await.unwrap());
        // Exactly one delivery claimed the record.
        assert!(
            rb ^ rc,
            "exactly one of the two delivers should win the claim"
        );

        let result = tokio::time::timeout(Duration::from_secs(2), asked)
            .await
            .expect("awaiter resolves")
            .expect("join")
            .expect("bridged ok");
        // The awaiter got the winner's payload (whichever it was).
        assert!(result["from"] == json!("b") || result["from"] == json!("c"));
    }

    /// Same-replica answer still takes the fast in-process path even with a
    /// coordinator wired (no bus round-trip needed).
    #[tokio::test]
    async fn clustered_same_replica_uses_fast_path() {
        let coordinator = SingleNodeClusterBackend::new();
        let bridge = clustered_bridge(&coordinator);

        let b = Arc::clone(&bridge);
        let asked = tokio::spawn(async move {
            b.ask_client(
                "sess-3",
                "fed-local".into(),
                "roots/list",
                json!({}),
                Duration::from_secs(5),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            bridge
                .deliver_response("fed-local", "sess-3", Some(json!({ "ok": true })), None)
                .await
        );
        let result = tokio::time::timeout(Duration::from_secs(2), asked)
            .await
            .expect("awaiter resolves")
            .expect("join")
            .expect("bridged ok");
        assert_eq!(result, json!({ "ok": true }));
    }
}
