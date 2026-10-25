//! Delivery bus — internal pub/sub for routing server-initiated messages
//! (deferred results, resource updates, progress) to the correct SSE stream.
//!
//! Single concrete impl `BusBackedDeliveryBus` over any
//! `Arc<dyn mcpg_cluster_api::PubSub>`. Single-node deployments use
//! `MemoryBus`; clustered deployments wire in the cluster plugin's
//! pub/sub primitive (redis, nats, …).

use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;

use crate::runtime::pipeline_store::DeliveryMessage;

/// Internal pub/sub channel for routing server-initiated messages
/// to the MCPG instance holding the client's active SSE stream.
pub trait DeliveryBus: Send + Sync + std::fmt::Debug {
    /// Subscribe to delivery messages for a session.
    fn subscribe(
        &self,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = mpsc::Receiver<DeliveryMessage>> + Send + '_>>;

    /// Publish a delivery message to the bus for a session.
    fn publish(
        &self,
        session_id: &str,
        message: DeliveryMessage,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// BusBackedDeliveryBus — single impl over the orthogonal TopicBus primitive
// ---------------------------------------------------------------------------

/// Delivery bus backed by any [`mcpg_cluster_api::PubSub`] impl.
///
/// Routes session-scoped delivery messages over per-session topics
/// (`mcpg.delivery.{session_id}`). Each replica subscribes to the
/// session topics it owns; publishes from any replica reach every
/// listener. Replaces the per-backend `RedisDeliveryBus` /
/// `NatsDeliveryBus` impls that lived in
/// `mcpg-plugin-backend-{redis,nats}` before the substrate was
/// unified behind the cluster API.
#[derive(Debug)]
pub struct BusBackedDeliveryBus {
    bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>,
}

impl BusBackedDeliveryBus {
    pub fn new(bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>) -> Self {
        Self { bus }
    }

    /// Convenience: in-process `MemoryBus` backing.
    pub fn new_in_memory() -> Self {
        Self::new(std::sync::Arc::new(
            crate::builtins::cluster_primitives::MemoryBus::new(),
        ))
    }

    fn topic(session_id: &str) -> String {
        format!("mcpg.delivery.{session_id}")
    }
}

impl DeliveryBus for BusBackedDeliveryBus {
    fn subscribe(
        &self,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = mpsc::Receiver<DeliveryMessage>> + Send + '_>> {
        let bus = self.bus.clone();
        let topic = Self::topic(session_id);
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(64);
            let mut stream = match bus.subscribe(&topic, None).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "topic bus subscribe failed for delivery");
                    return rx;
                }
            };
            tokio::spawn(async move {
                use futures::StreamExt;
                loop {
                    // The receiver goes with the SSE stream it feeds, and no
                    // message comes for a session that ended: wait on both, so
                    // the bus subscription ends with the stream.
                    let msg = tokio::select! {
                        () = tx.closed() => break,
                        msg = stream.next() => msg,
                    };
                    let Some(Ok(msg)) = msg else { break };
                    let Ok(delivery) = serde_json::from_slice::<DeliveryMessage>(&msg.payload)
                    else {
                        continue;
                    };
                    if tx.send(delivery).await.is_err() {
                        break;
                    }
                }
            });
            rx
        })
    }

    fn publish(
        &self,
        session_id: &str,
        message: DeliveryMessage,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let bus = self.bus.clone();
        let topic = Self::topic(session_id);
        Box::pin(async move {
            let payload = serde_json::to_vec(&message)?;
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
    use crate::runtime::pipeline_store::DeliveryKind;

    #[tokio::test]
    async fn in_process_publish_and_subscribe() {
        let bus = BusBackedDeliveryBus::new_in_memory();
        let mut rx = bus.subscribe("sess-1").await;

        let msg = DeliveryMessage {
            kind: DeliveryKind::ServerRequest,
            jsonrpc_message: serde_json::json!({"method": "elicitation/create"}),
            delivery_id: String::new(),
        };
        bus.publish("sess-1", msg).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.kind, DeliveryKind::ServerRequest);
    }

    #[tokio::test]
    async fn in_process_no_subscriber_does_not_error() {
        let bus = BusBackedDeliveryBus::new_in_memory();
        let msg = DeliveryMessage {
            kind: DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({}),
            delivery_id: String::new(),
        };
        bus.publish("sess-no-sub", msg).await.unwrap();
    }

    #[tokio::test]
    async fn in_process_different_sessions_isolated() {
        let bus = BusBackedDeliveryBus::new_in_memory();
        let mut rx1 = bus.subscribe("sess-1").await;
        let _rx2 = bus.subscribe("sess-2").await;

        let msg = DeliveryMessage {
            kind: DeliveryKind::PipelineError,
            jsonrpc_message: serde_json::json!({"error": true}),
            delivery_id: String::new(),
        };
        bus.publish("sess-1", msg).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.kind, DeliveryKind::PipelineError);
    }

    /// A bus that counts the subscriptions alive on it.
    #[derive(Debug)]
    struct CountingBus {
        inner: crate::builtins::cluster_primitives::MemoryBus,
        live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    struct Counted {
        inner: mcpg_cluster_api::Subscription,
        live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl futures::Stream for Counted {
        type Item = Result<mcpg_cluster_api::Message, mcpg_cluster_api::ClusterError>;
        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.get_mut().inner.as_mut().poll_next(cx)
        }
    }

    #[async_trait::async_trait]
    impl mcpg_cluster_api::PubSub for CountingBus {
        async fn publish(
            &self,
            topic: &str,
            payload: bytes::Bytes,
        ) -> Result<(), mcpg_cluster_api::ClusterError> {
            self.inner.publish(topic, payload).await
        }

        async fn subscribe(
            &self,
            pattern: &str,
            queue_group: Option<&str>,
        ) -> Result<mcpg_cluster_api::Subscription, mcpg_cluster_api::ClusterError> {
            let inner = self.inner.subscribe(pattern, queue_group).await?;
            self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::pin(Counted {
                inner,
                live: std::sync::Arc::clone(&self.live),
            }))
        }
    }

    /// The SSE stream a session's deliveries feed ends with the session; no
    /// message comes for it after, so its bus subscription must end with the
    /// receiver, not at a next message.
    #[tokio::test]
    async fn a_subscription_ends_with_its_receiver() {
        let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bus = BusBackedDeliveryBus::new(std::sync::Arc::new(CountingBus {
            inner: crate::builtins::cluster_primitives::MemoryBus::new(),
            live: std::sync::Arc::clone(&live),
        }));
        let rx = bus.subscribe("sess-1").await;
        assert_eq!(live.load(std::sync::atomic::Ordering::SeqCst), 1);

        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while live.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the bus subscription ends with its receiver");
    }
}
