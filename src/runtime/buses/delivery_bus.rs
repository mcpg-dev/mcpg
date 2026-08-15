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
                while let Some(msg) = stream.next().await {
                    let Ok(msg) = msg else { break };
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
}
