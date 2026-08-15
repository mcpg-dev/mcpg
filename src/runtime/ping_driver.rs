//! Server-initiated ping driver.
//!
//! MCP 2025-11-25 §Utilities/Ping says a server SHOULD periodically
//! ping active sessions to detect dead peers. This driver walks the
//! session store on a configured cadence and publishes a
//! `{"jsonrpc":"2.0","id":"srv-ping-<uuid>","method":"ping"}` onto
//! each session's delivery bus. The gateway does not wait for a
//! response — `ping` is fire-and-forget health signalling; a client
//! failing to reply would simply stay idle until the next cadence or
//! until the session idle-timeout reaper sweeps it.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::delivery_bus::DeliveryBus;
use super::pipeline_store::{DeliveryKind, DeliveryMessage};
use super::session_store::SessionStore;

/// Periodically pings active sessions to detect dead peers.
pub struct ServerPingDriver {
    interval: Duration,
}

impl ServerPingDriver {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval: Duration::from_secs(interval_ms.max(1)),
        }
    }

    pub fn spawn(
        self,
        session_store: Arc<dyn SessionStore>,
        delivery_bus: Arc<dyn DeliveryBus>,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> JoinHandle<()> {
        info!(
            interval_ms = self.interval.as_secs(),
            "server-initiated ping driver starting"
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            // Skip the immediate first tick.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = shutdown_rx.changed() => {
                        debug!("ping driver received shutdown signal");
                        return;
                    }
                }

                let sessions = session_store.list_sessions();
                for session in sessions {
                    let ping_id = format!("srv-ping-{}", uuid::Uuid::new_v4());
                    let message = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": ping_id,
                        "method": "ping"
                    });
                    let msg = DeliveryMessage {
                        kind: DeliveryKind::ServerRequest,
                        jsonrpc_message: message,
                        delivery_id: String::new(),
                    };
                    if let Err(e) = delivery_bus.publish(&session.session_id, msg).await {
                        warn!(
                            session_id = %session.session_id,
                            error = %e,
                            "failed to publish server ping to delivery bus"
                        );
                    } else {
                        metrics::counter!("mcpg_server_ping_emitted_total").increment(1);
                    }
                }
            }
        })
    }
}
