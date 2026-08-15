//! Pipeline reaper — periodic cleanup of expired pipeline executions.
//!
//! Runs on a configurable cadence and removes pipelines whose
//! timeout has elapsed, preventing stale state from accumulating.

use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{info, warn};

use crate::runtime::pipeline_store::PipelineStore;

/// Async callback the reaper invokes to deliver a terminal JSON-RPC error to
/// the original caller of an expiring SUSPENDED pipeline (whole-pipeline
/// timeout or per-step elicitation timeout). Arguments:
/// `(session_id, original_jsonrpc_id, code, message)`. Without this, a
/// suspended pipeline would be deleted silently and the caller's stream would
/// hang until its transport timeout.
pub type TerminalErrorDelivery = std::sync::Arc<
    dyn Fn(String, Value, i32, String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

/// JSON-RPC error code for a server-side timeout of a suspended pipeline.
const TIMEOUT_ERROR_CODE: i32 = -32001;

/// Periodic background task that cleans up expired pipelines.
/// Runs at a configurable interval, checking for pipelines that have
/// exceeded their timeout and removing them.
pub struct PipelineReaper {
    interval: Duration,
    /// Terminal-error delivery for expiring suspended pipelines. `None` in
    /// tests / contexts without a delivery path (the sweep still deletes).
    deliver_terminal_error: Option<TerminalErrorDelivery>,
}

impl PipelineReaper {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            deliver_terminal_error: None,
        }
    }

    /// Attach the terminal-error delivery callback used when a SUSPENDED
    /// pipeline is reaped (so the caller unblocks with a real timeout error
    /// instead of a silent drop).
    pub fn with_terminal_error_delivery(mut self, deliver: TerminalErrorDelivery) -> Self {
        self.deliver_terminal_error = Some(deliver);
        self
    }

    /// Leadership role this reaper contends for when clustered.
    const LEADER_ROLE: &'static str = "gateway.reaper.pipeline";

    /// Spawn the reaper as a background tokio task.
    /// Returns a `JoinHandle` that can be used to abort the task.
    ///
    /// `leadership` gates the sweep behind cluster leader-election:
    /// `Some(coordinator)` ⇒ only the replica holding `LEADER_ROLE` reaps;
    /// `None` (single-node / no coordinator) ⇒ reap unconditionally.
    pub fn spawn(
        self,
        pipeline_store: std::sync::Arc<dyn PipelineStore>,
        leadership: Option<std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    ) -> tokio::task::JoinHandle<()> {
        // TTL comfortably exceeds the interval so a single slow tick doesn't
        // drop leadership; a crashed leader is reclaimed within a few ticks.
        let lease_ttl = self.interval.saturating_mul(3).max(Duration::from_secs(30));
        let interval_dur = self.interval;
        let deliver = self.deliver_terminal_error.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_dur);
            interval.tick().await; // first tick is immediate, skip it
            let mut lease: Option<mcpg_cluster_api::BoxActiveLease> = None;
            loop {
                interval.tick().await;
                if let Some(backend) = &leadership
                    && !crate::runtime::reaper_leadership::maintain_leadership(
                        Self::LEADER_ROLE,
                        backend.as_ref(),
                        lease_ttl,
                        &mut lease,
                    )
                    .await
                {
                    continue;
                }
                Self::reap_once_with_delivery(&*pipeline_store, deliver.as_ref()).await;
            }
        })
    }

    /// Single reap pass with no terminal-error delivery (suspended pipelines
    /// are deleted silently). Retained for tests + callers that have no
    /// delivery path. The `PipelineStore` surface is sync, so this is sync.
    pub fn reap_once(pipeline_store: &dyn PipelineStore) -> usize {
        // Single sweep; the collected terminal errors are discarded (no
        // delivery path on this entry).
        Self::sweep_and_collect_deliveries(pipeline_store).1
    }

    /// Single reap pass. Expires per-step `elicitation_timeout_ms` for
    /// SUSPENDED pipelines and the whole-pipeline `pipeline_timeout_ms` for
    /// any pipeline, delivering a terminal timeout error to the caller of any
    /// SUSPENDED pipeline before deleting it. Returns the number reaped.
    ///
    /// The `PipelineStore` surface is sync; only delivery is async, so the
    /// sweep+delete is performed synchronously and the collected terminal
    /// errors are then awaited.
    pub async fn reap_once_with_delivery(
        pipeline_store: &dyn PipelineStore,
        deliver: Option<&TerminalErrorDelivery>,
    ) -> usize {
        let (deliveries, reaped) = Self::sweep_and_collect_deliveries(pipeline_store);
        if let Some(deliver) = deliver {
            for (session_id, jsonrpc_id, code, message) in deliveries {
                deliver(session_id, jsonrpc_id, code, message).await;
            }
        }
        reaped
    }

    /// Sweep both timeout classes synchronously: deletes expired pipelines and
    /// returns `(terminal_errors_to_deliver, reaped_count)`. The terminal
    /// errors are `(session_id, original_jsonrpc_id, code, message)` for every
    /// SUSPENDED pipeline that was reaped — the caller delivers them.
    fn sweep_and_collect_deliveries(
        pipeline_store: &dyn PipelineStore,
    ) -> (Vec<(String, Value, i32, String)>, usize) {
        let mut deliveries = Vec::new();
        let mut reaped = 0usize;

        // Per-step elicitation timeouts first: these are suspended pipelines
        // that must receive a terminal error. Doing them before the
        // whole-pipeline sweep means each gets its delivery exactly once
        // (the subsequent delete makes the whole-pipeline sweep skip it).
        match pipeline_store.list_elicitation_timed_out() {
            Ok(timed_out) => {
                for (pipeline_id, session_id, original_jsonrpc_id) in timed_out {
                    if let Err(e) = pipeline_store.delete_pipeline(&pipeline_id) {
                        warn!(pipeline_id = %pipeline_id, error = %e,
                            "pipeline reaper: failed to delete elicitation-timed-out pipeline");
                    } else {
                        reaped += 1;
                        deliveries.push((
                            session_id,
                            original_jsonrpc_id,
                            TIMEOUT_ERROR_CODE,
                            "elicitation timed out waiting for client response".to_owned(),
                        ));
                        metrics::counter!("mcpg_pipeline_reaper_cleaned_total").increment(1);
                        metrics::counter!("mcpg_pipeline_elicitation_timeout_total").increment(1);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "pipeline reaper: failed to list elicitation-timed-out pipelines");
            }
        }

        // Whole-pipeline timeouts.
        let expired = match pipeline_store.list_expired_pipelines() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(error = %e, "pipeline reaper: failed to list expired pipelines");
                metrics::gauge!("mcpg_pipeline_reaper_last_sweep_count").set(reaped as f64);
                return (deliveries, reaped);
            }
        };

        if !expired.is_empty() {
            info!(
                expired_count = expired.len(),
                "pipeline reaper: cleaning up expired pipelines"
            );
        }

        for pipeline_id in &expired {
            // A suspended pipeline reaped at the whole-pipeline timeout still
            // owes its caller a terminal error (else the stream hangs). Load
            // before delete to find out; non-suspended pipelines are deleted
            // silently as before. An already-deleted (elicitation-timed-out)
            // pipeline loads as None and is skipped.
            let suspended_owner = match pipeline_store.load_pipeline(pipeline_id) {
                Ok(Some(state)) if state.suspended_at.is_some() => {
                    Some((state.session_id, state.original_jsonrpc_id))
                }
                _ => None,
            };
            if let Err(e) = pipeline_store.delete_pipeline(pipeline_id) {
                warn!(
                    pipeline_id = %pipeline_id,
                    error = %e,
                    "pipeline reaper: failed to delete expired pipeline"
                );
            } else {
                reaped += 1;
                if let Some((session_id, original_jsonrpc_id)) = suspended_owner {
                    deliveries.push((
                        session_id,
                        original_jsonrpc_id,
                        TIMEOUT_ERROR_CODE,
                        "pipeline timed out before completion".to_owned(),
                    ));
                }
                metrics::counter!("mcpg_pipeline_reaper_cleaned_total").increment(1);
            }
        }

        metrics::gauge!("mcpg_pipeline_reaper_last_sweep_count").set(reaped as f64);
        (deliveries, reaped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::pipeline_store::{KvBackedPipelineStore, PipelineExecutionState};
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn expired_pipeline(id: &str) -> PipelineExecutionState {
        PipelineExecutionState {
            pipeline_id: id.to_owned(),
            session_id: "sess-1".to_owned(),
            original_jsonrpc_id: Value::Number(serde_json::Number::from(1)),
            tool_name: "test".to_owned(),
            steps: vec![],
            current_step_index: 0,
            completed_steps: BTreeMap::new(),
            original_args: serde_json::json!({}),
            request_context: crate::runtime::RequestContext::new(
                crate::runtime::GatewayRequestId::new(),
                None,
                Some("sess-1".to_owned()),
                None,
                crate::runtime::RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                crate::runtime::TransportKind::Http,
            ),
            created_at: Utc::now() - chrono::Duration::seconds(60),
            suspended_at: None,
            pipeline_timeout_ms: 0, // immediately expired
            pending_server_request_id: None,
            elicitation_timeout_ms: None,
            related_task_id: None,
            client_capabilities: crate::protocol::ClientCapabilities::default(),
            state_version: 0,
            surface: crate::runtime::pipeline_store::PipelineSurface::Tool,
        }
    }

    #[test]
    fn reaper_cleans_expired_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        store.save_pipeline(&expired_pipeline("pipe-1")).unwrap();
        store.save_pipeline(&expired_pipeline("pipe-2")).unwrap();
        let reaped = PipelineReaper::reap_once(&store);
        assert_eq!(reaped, 2);
        assert!(store.load_pipeline("pipe-1").unwrap().is_none());
        assert!(store.load_pipeline("pipe-2").unwrap().is_none());
    }

    #[test]
    fn reaper_skips_active_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        let mut active = expired_pipeline("pipe-active");
        active.pipeline_timeout_ms = 999_999_999; // way in the future
        active.created_at = Utc::now();
        store.save_pipeline(&active).unwrap();
        let reaped = PipelineReaper::reap_once(&store);
        assert_eq!(reaped, 0);
        assert!(store.load_pipeline("pipe-active").unwrap().is_some());
    }

    #[test]
    fn reaper_returns_zero_when_no_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        let reaped = PipelineReaper::reap_once(&store);
        assert_eq!(reaped, 0);
    }

    /// A suspended pipeline reaped at its WHOLE-pipeline timeout owes the
    /// caller a terminal error (not a silent drop).
    #[tokio::test(flavor = "multi_thread")]
    async fn suspended_whole_timeout_delivers_terminal_error() {
        use std::sync::{Arc, Mutex};
        let store = KvBackedPipelineStore::new_in_memory();
        let mut suspended = expired_pipeline("pipe-susp"); // pipeline_timeout_ms == 0
        suspended.suspended_at = Some(Utc::now());
        suspended.pending_server_request_id = Some("srv-1".to_owned());
        store.save_pipeline(&suspended).unwrap();

        let captured: Arc<Mutex<Vec<(String, Value, i32, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        let deliver: TerminalErrorDelivery =
            Arc::new(move |session_id, jsonrpc_id, code, message| {
                let captured = captured_cb.clone();
                Box::pin(async move {
                    captured
                        .lock()
                        .unwrap()
                        .push((session_id, jsonrpc_id, code, message));
                })
            });

        let reaped = PipelineReaper::reap_once_with_delivery(&store, Some(&deliver)).await;
        assert_eq!(reaped, 1);
        assert!(store.load_pipeline("pipe-susp").unwrap().is_none());
        let calls = captured.lock().unwrap();
        assert_eq!(calls.len(), 1, "one terminal error delivered");
        assert_eq!(calls[0].0, "sess-1");
        assert_eq!(calls[0].2, TIMEOUT_ERROR_CODE);
    }

    /// A suspended pipeline past its per-step `elicitation_timeout_ms` (but
    /// well within the whole-pipeline timeout) is reaped with a terminal
    /// elicitation-timeout error.
    #[tokio::test(flavor = "multi_thread")]
    async fn elicitation_timeout_delivers_terminal_error() {
        use std::sync::{Arc, Mutex};
        let store = KvBackedPipelineStore::new_in_memory();
        let mut suspended = expired_pipeline("pipe-elic");
        suspended.pipeline_timeout_ms = 999_999_999; // whole-pipeline still alive
        suspended.created_at = Utc::now();
        suspended.suspended_at = Some(Utc::now() - chrono::Duration::seconds(10));
        suspended.elicitation_timeout_ms = Some(1); // suspended 10s > 1ms bound
        store.save_pipeline(&suspended).unwrap();

        let captured: Arc<Mutex<Vec<(String, Value, i32, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        let deliver: TerminalErrorDelivery =
            Arc::new(move |session_id, jsonrpc_id, code, message| {
                let captured = captured_cb.clone();
                Box::pin(async move {
                    captured
                        .lock()
                        .unwrap()
                        .push((session_id, jsonrpc_id, code, message));
                })
            });

        let reaped = PipelineReaper::reap_once_with_delivery(&store, Some(&deliver)).await;
        assert_eq!(reaped, 1);
        assert!(store.load_pipeline("pipe-elic").unwrap().is_none());
        let calls = captured.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, TIMEOUT_ERROR_CODE);
        assert!(calls[0].3.contains("elicitation timed out"));
    }

    /// A non-suspended expired pipeline is deleted WITHOUT a terminal error
    /// (only suspended pipelines have a waiting caller to notify).
    #[tokio::test(flavor = "multi_thread")]
    async fn non_suspended_expiry_delivers_no_error() {
        use std::sync::{Arc, Mutex};
        let store = KvBackedPipelineStore::new_in_memory();
        store
            .save_pipeline(&expired_pipeline("pipe-plain"))
            .unwrap();
        let captured: Arc<Mutex<Vec<(String, Value, i32, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        let deliver: TerminalErrorDelivery = Arc::new(move |s, j, c, m| {
            let captured = captured_cb.clone();
            Box::pin(async move {
                captured.lock().unwrap().push((s, j, c, m));
            })
        });
        let reaped = PipelineReaper::reap_once_with_delivery(&store, Some(&deliver)).await;
        assert_eq!(reaped, 1);
        assert!(captured.lock().unwrap().is_empty());
    }
}
