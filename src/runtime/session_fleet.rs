//! Tells the replicas of a fleet that a session ended, so none goes on
//! serving it, holding its streams open, or keeping state for it.
//!
//! The replica that records an end (see
//! [`super::session_store::KvBackedSessionStore`]) tells it once; every
//! other replica drops its copy and cleans up. The bus is at-most-once: a
//! replica that misses the word finds the recorded end when the session is
//! next used there.

use std::sync::{Arc, Weak};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::GatewayRuntime;
use super::session_store::SessionEndReason;

/// The topic the ends of sessions go out on.
pub(crate) const TOPIC: &str = "mcpg.sessions.ended";

/// The first pause before a lost subscription is taken again; it doubles to
/// [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Word that a session ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionEndedEvent {
    pub session_id: String,
    /// When the session began, as every copy of it holds it: tells it from a
    /// later session under the same id.
    pub created_at: DateTime<Utc>,
    pub reason: SessionEndReason,
    /// The [`SessionFleet`] that told it.
    pub origin: String,
}

/// The bus a runtime tells and hears the ends of sessions on: none on a
/// single node, or where each replica keeps sessions of its own.
#[derive(Debug, Clone, Default)]
pub(crate) struct SessionFleet {
    bus: Option<Arc<dyn mcpg_cluster_api::PubSub>>,
    /// Names this runtime's word, which it does not act on again. A runtime
    /// a reload installs has a name of its own; it acts once more on what
    /// its predecessor told, which every replica's cleanup tolerates.
    origin: Arc<str>,
}

impl SessionFleet {
    pub(crate) fn new(bus: Arc<dyn mcpg_cluster_api::PubSub>) -> Self {
        Self {
            bus: Some(bus),
            origin: Arc::from(uuid::Uuid::new_v4().simple().to_string()),
        }
    }

    /// Tell the other replicas of an end this replica recorded.
    pub(crate) fn tell_ended(
        &self,
        session_id: &str,
        created_at: DateTime<Utc>,
        reason: SessionEndReason,
    ) {
        let Some(bus) = self.bus.clone() else {
            return;
        };
        let event = SessionEndedEvent {
            session_id: session_id.to_owned(),
            created_at,
            reason,
            origin: self.origin.to_string(),
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(payload) = serde_json::to_vec(&event) else {
            return;
        };
        handle.spawn(async move {
            if let Err(error) = bus.publish(TOPIC, bytes::Bytes::from(payload)).await {
                metrics::counter!("mcpg_session_end_publish_failed_total").increment(1);
                tracing::warn!(
                    %error,
                    session_id = %event.session_id,
                    "the end of a session was not told to the fleet; \
                     the other replicas find it when they next use the session"
                );
            }
        });
    }

    /// Hear the ends the other replicas record, for as long as `runtime`
    /// lives.
    pub(crate) fn listen(
        &self,
        runtime: Weak<GatewayRuntime>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let bus = self.bus.clone()?;
        Some(tokio::spawn(listen(bus, Arc::clone(&self.origin), runtime)))
    }
}

async fn listen(
    bus: Arc<dyn mcpg_cluster_api::PubSub>,
    origin: Arc<str>,
    runtime: Weak<GatewayRuntime>,
) {
    use futures::StreamExt;
    let mut backoff = MIN_BACKOFF;
    while runtime.strong_count() > 0 {
        match bus.subscribe(TOPIC, None).await {
            Ok(mut stream) => {
                backoff = MIN_BACKOFF;
                while let Some(Ok(message)) = stream.next().await {
                    let Ok(event) = serde_json::from_slice::<SessionEndedEvent>(&message.payload)
                    else {
                        continue;
                    };
                    if *event.origin == *origin {
                        continue;
                    }
                    let Some(runtime) = runtime.upgrade() else {
                        return;
                    };
                    runtime.on_session_ended_elsewhere(&event);
                }
                tracing::warn!(
                    "the subscription to the ends of sessions was lost; taking it again"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "subscribing to the ends of sessions failed; retrying");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv};
    use crate::protocol::{ImplementationInfo, InitializeParams, SUPPORTED_PROTOCOL_VERSION};
    use crate::runtime::session_store::{
        KvBackedSessionStore, SessionAccessError, SessionStoreConfig,
    };

    fn init_params() -> InitializeParams {
        InitializeParams {
            protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
            capabilities: Default::default(),
            client_info: ImplementationInfo {
                name: "fleet-test".to_owned(),
                title: None,
                version: "0.0.0".to_owned(),
                description: None,
                website_url: None,
                icons: None,
            },
        }
    }

    /// A replica over the fleet's shared store and bus, hearing the fleet.
    async fn replica(
        kv: &Arc<dyn mcpg_cluster_api::KeyValueStore>,
        bus: &Arc<dyn mcpg_cluster_api::PubSub>,
        config: SessionStoreConfig,
    ) -> Arc<GatewayRuntime> {
        let store = KvBackedSessionStore::new(config, Arc::clone(kv))
            .await
            .expect("store")
            .shared_across_replicas(true);
        let mut runtime = GatewayRuntime::try_new_with_runtime_controls(
            "mcpg",
            "0.1.0",
            "127.0.0.1:0",
            "/health",
            "/mcp",
            "info",
            vec![crate::config::SinkConfig {
                kind: "stdout".to_owned(),
                config: serde_json::json!({"format": "json"}),
                level: None,
            }],
            true,
            Arc::new(store),
            Default::default(),
            Default::default(),
            &[],
            &[],
            &[],
            &[],
            None,
            None,
            Arc::new(crate::runtime::pipeline_store::KvBackedPipelineStore::new_in_memory()),
            Arc::new(crate::runtime::delivery_bus::BusBackedDeliveryBus::new_in_memory()),
        )
        .expect("runtime");
        runtime.set_session_fleet(SessionFleet::new(Arc::clone(bus)));
        // The drain `serve` runs for the ends the store finds on its own.
        let (end_tx, mut end_rx) = tokio::sync::mpsc::unbounded_channel();
        runtime.install_session_end_notifier(end_tx);
        let runtime = Arc::new(runtime);
        let drain = Arc::downgrade(&runtime);
        tokio::spawn(async move {
            while let Some(ended) = end_rx.recv().await {
                let Some(runtime) = drain.upgrade() else {
                    break;
                };
                runtime.on_session_end(&ended);
            }
        });
        runtime.start_cluster_listeners();
        runtime
    }

    fn operational_session(runtime: &GatewayRuntime) -> String {
        let id = runtime
            .session_store()
            .create_session(SUPPORTED_PROTOCOL_VERSION, &init_params())
            .session_id;
        runtime
            .session_store()
            .transition_session_to_operational(&id)
            .expect("operational");
        id
    }

    /// Wait until `peer` hears the ends `teller` tells: the bus keeps nothing
    /// for a subscriber that is not there yet.
    async fn until_heard(teller: &GatewayRuntime, peer: &GatewayRuntime) {
        for _ in 0..200 {
            let probe = operational_session(teller);
            peer.session_store()
                .load_session(Some(&probe), false)
                .expect("the peer reads the probe back");
            assert!(teller.terminate_session(&probe));
            tokio::time::sleep(Duration::from_millis(10)).await;
            if !peer.session_store().contains_active_session(&probe) {
                return;
            }
        }
        panic!("the peer never heard the fleet");
    }

    async fn eventually(what: &str, done: impl Fn() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("{what}");
    }

    fn fleet() -> (
        Arc<dyn mcpg_cluster_api::KeyValueStore>,
        Arc<dyn mcpg_cluster_api::PubSub>,
    ) {
        (Arc::new(MemoryKv::new()), Arc::new(MemoryBus::new()))
    }

    /// A session one replica terminates ends on the replica that also serves
    /// it, at once: its copy, its stream, and the state it keeps for it go.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_terminated_session_ends_on_every_replica() {
        let (kv, bus) = fleet();
        let a = replica(&kv, &bus, SessionStoreConfig::default()).await;
        let b = replica(&kv, &bus, SessionStoreConfig::default()).await;
        until_heard(&a, &b).await;

        let session_id = operational_session(&a);
        b.session_store()
            .load_session(Some(&session_id), true)
            .expect("B serves the session too");
        let stream_ended = b
            .session_store()
            .session_lifetime(&session_id)
            .expect("B holds a copy")
            .ended();
        let _ = b.record_client_request_id(Some(&session_id), false, &serde_json::json!("req-1"));

        assert!(a.terminate_session(&session_id));
        tokio::time::timeout(Duration::from_secs(1), stream_ended)
            .await
            .expect("B's stream ends with the session");
        assert!(matches!(
            b.session_store().load_session(Some(&session_id), false),
            Err(SessionAccessError::UnknownSession)
        ));
        eventually("B drops the state it keeps for the session", || {
            !b.seen_request_ids.contains_key(&session_id)
        })
        .await;
    }

    /// A session idle on every replica ends on all of them when the first
    /// to find it idle records the end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_expired_session_ends_on_every_replica() {
        let config = SessionStoreConfig {
            session_idle_timeout_ms: 2_000,
            ..SessionStoreConfig::default()
        };
        let (kv, bus) = fleet();
        let a = replica(&kv, &bus, config).await;
        let b = replica(&kv, &bus, config).await;
        until_heard(&a, &b).await;

        let session_id = operational_session(&a);
        b.session_store()
            .load_session(Some(&session_id), true)
            .unwrap();
        let stream_ended = b
            .session_store()
            .session_lifetime(&session_id)
            .unwrap()
            .ended();
        // The idle timeout, and the refresh interval a replica in use may
        // hold its touch back for.
        tokio::time::sleep(Duration::from_millis(3_300)).await;

        assert!(
            a.session_store()
                .load_session(Some(&session_id), true)
                .is_err(),
            "A finds it idle everywhere"
        );
        tokio::time::timeout(Duration::from_secs(1), stream_ended)
            .await
            .expect("B's stream ends with the session");
        assert!(!b.session_store().contains_active_session(&session_id));
    }

    /// A runtime a reload retired hears the fleet no more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stopped_replica_hears_nothing() {
        let (kv, bus) = fleet();
        let a = replica(&kv, &bus, SessionStoreConfig::default()).await;
        let b = replica(&kv, &bus, SessionStoreConfig::default()).await;
        until_heard(&a, &b).await;
        b.stop_cluster_listeners().await;

        let session_id = operational_session(&a);
        b.session_store()
            .load_session(Some(&session_id), true)
            .unwrap();
        assert!(a.terminate_session(&session_id));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            b.session_store().contains_active_session(&session_id),
            "the copy stays until B next verifies it"
        );
    }

    /// The word of an end names the session as every copy of it holds it:
    /// to the nanosecond it began at, which a later session under the same
    /// id does not share.
    #[test]
    fn the_word_of_an_end_names_one_session() {
        let fleet = SessionFleet::new(Arc::new(MemoryBus::new()));
        let event = SessionEndedEvent {
            session_id: "s".to_owned(),
            created_at: Utc::now(),
            reason: SessionEndReason::Terminated,
            origin: fleet.origin.to_string(),
        };
        let wire = serde_json::to_vec(&event).unwrap();
        let back: SessionEndedEvent = serde_json::from_slice(&wire).unwrap();
        assert_eq!(back, event, "the time it began survives to the nanosecond");
        assert_ne!(
            *SessionFleet::new(Arc::new(MemoryBus::new())).origin,
            *fleet.origin,
            "every runtime names its own word"
        );
    }
}
