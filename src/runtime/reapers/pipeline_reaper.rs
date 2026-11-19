//! Pipeline reaper — periodic cleanup of expired pipeline executions.
//!
//! Runs on a configurable cadence and removes pipelines whose timeout has
//! elapsed, preventing stale state from accumulating. The task of a
//! task-augmented pipeline that was suspended awaiting input is failed with
//! it, so `tasks/get` answers a terminal status instead of `input_required`
//! until the task's TTL.

use std::time::Duration;
use tracing::{info, warn};

use crate::protocol::{JsonRpcErrorBody, TaskStatus};
use crate::runtime::pipeline_store::{PipelineExecutionState, PipelineStore};
use crate::runtime::task_store::{TaskStore, TaskStoreError, TerminalEnvelope};

/// JSON-RPC error code a reaped pipeline's task fails with.
const TIMEOUT_ERROR_CODE: i32 = -32001;

/// Periodic background task that cleans up expired pipelines.
pub struct PipelineReaper {
    interval: Duration,
}

impl PipelineReaper {
    pub fn new(interval: Duration) -> Self {
        Self { interval }
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
        task_store: std::sync::Arc<dyn TaskStore>,
        leadership: Option<std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    ) -> tokio::task::JoinHandle<()> {
        // TTL comfortably exceeds the interval so a single slow tick doesn't
        // drop leadership; a crashed leader is reclaimed within a few ticks.
        let lease_ttl = self.interval.saturating_mul(3).max(Duration::from_secs(30));
        let interval_dur = self.interval;
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
                Self::reap_once(&*pipeline_store, &*task_store);
            }
        })
    }

    /// Single reap pass: per-step `elicitation_timeout_ms` for SUSPENDED
    /// pipelines first, then the whole-pipeline `pipeline_timeout_ms` for
    /// any pipeline. Returns the number reaped. The store surfaces are sync,
    /// so this is sync.
    pub fn reap_once(pipeline_store: &dyn PipelineStore, task_store: &dyn TaskStore) -> usize {
        let mut reaped = 0usize;

        match pipeline_store.list_elicitation_timed_out() {
            Ok(timed_out) => {
                for state in &timed_out {
                    if Self::reap(
                        pipeline_store,
                        task_store,
                        state,
                        "elicitation timed out waiting for client response",
                    ) {
                        reaped += 1;
                        metrics::counter!("mcpg_pipeline_elicitation_timeout_total").increment(1);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "pipeline reaper: failed to list elicitation-timed-out pipelines");
            }
        }

        // Listed after the elicitation sweep deleted its pipelines, so none
        // is reaped twice.
        let expired = match pipeline_store.list_expired_pipelines() {
            Ok(expired) => expired,
            Err(e) => {
                warn!(error = %e, "pipeline reaper: failed to list expired pipelines");
                metrics::gauge!("mcpg_pipeline_reaper_last_sweep_count").set(reaped as f64);
                return reaped;
            }
        };
        if !expired.is_empty() {
            info!(
                expired_count = expired.len(),
                "pipeline reaper: cleaning up expired pipelines"
            );
        }
        for state in &expired {
            if Self::reap(
                pipeline_store,
                task_store,
                state,
                "pipeline timed out before completion",
            ) {
                reaped += 1;
            }
        }

        metrics::gauge!("mcpg_pipeline_reaper_last_sweep_count").set(reaped as f64);
        reaped
    }

    /// Delete `state`, and fail the task of a suspended task-augmented
    /// pipeline with `why`. A running pipeline's task is left to the work
    /// that still runs it. Returns whether the pipeline was deleted.
    fn reap(
        pipeline_store: &dyn PipelineStore,
        task_store: &dyn TaskStore,
        state: &PipelineExecutionState,
        why: &str,
    ) -> bool {
        if let Err(e) = pipeline_store.delete_pipeline(&state.pipeline_id) {
            warn!(
                pipeline_id = %state.pipeline_id,
                error = %e,
                "pipeline reaper: failed to delete expired pipeline"
            );
            return false;
        }
        metrics::counter!("mcpg_pipeline_reaper_cleaned_total").increment(1);
        let Some(task_id) = state.related_task_id.as_deref() else {
            return true;
        };
        if state.suspended_at.is_none() {
            return true;
        }
        let envelope = TerminalEnvelope::error(JsonRpcErrorBody {
            code: TIMEOUT_ERROR_CODE,
            message: why.to_owned(),
            data: None,
        });
        match task_store.store_task_terminal(task_id, TaskStatus::Failed, envelope) {
            Ok(()) | Err(TaskStoreError::AlreadyTerminal | TaskStoreError::NotFound) => {}
            Err(e) => warn!(
                pipeline_id = %state.pipeline_id,
                task_id,
                error = %e,
                "pipeline reaper: failed to fail the task of a reaped pipeline"
            ),
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::pipeline_store::{KvBackedPipelineStore, PipelineExecutionState};
    use crate::runtime::task_store::KvBackedTaskStore;
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn expired_pipeline(id: &str) -> PipelineExecutionState {
        let mut request_context = crate::runtime::RequestContext::new(
            crate::runtime::GatewayRequestId::new(),
            None,
            crate::runtime::RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            crate::runtime::TransportKind::Http,
        );
        request_context.session_id = Some("sess-1".to_owned());
        PipelineExecutionState {
            pipeline_id: id.to_owned(),
            session_id: "sess-1".to_owned(),
            original_jsonrpc_id: Value::Number(serde_json::Number::from(1)),
            tool_name: "test".to_owned(),
            steps: vec![],
            current_step_index: 0,
            completed_steps: BTreeMap::new(),
            original_args: serde_json::json!({}),
            request_context,
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

    fn tasks() -> KvBackedTaskStore {
        KvBackedTaskStore::new_in_memory_default()
    }

    #[test]
    fn reaper_cleans_expired_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        store.save_pipeline(&expired_pipeline("pipe-1")).unwrap();
        store.save_pipeline(&expired_pipeline("pipe-2")).unwrap();
        let reaped = PipelineReaper::reap_once(&store, &tasks());
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
        let reaped = PipelineReaper::reap_once(&store, &tasks());
        assert_eq!(reaped, 0);
        assert!(store.load_pipeline("pipe-active").unwrap().is_some());
    }

    #[test]
    fn reaper_returns_zero_when_no_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        let reaped = PipelineReaper::reap_once(&store, &tasks());
        assert_eq!(reaped, 0);
    }

    /// The task of a suspended pipeline reaped at its whole-pipeline timeout
    /// fails with it, and answers a terminal status from then on.
    #[test]
    fn a_suspended_pipelines_task_fails_at_the_pipeline_timeout() {
        let store = KvBackedPipelineStore::new_in_memory();
        let tasks = tasks();
        let task = tasks
            .create_task("owner", serde_json::json!(1), "test")
            .unwrap();
        let mut suspended = expired_pipeline("pipe-susp"); // pipeline_timeout_ms == 0
        suspended.suspended_at = Some(Utc::now());
        suspended.related_task_id = Some(task.task.task_id.clone());
        store.save_pipeline(&suspended).unwrap();

        assert_eq!(PipelineReaper::reap_once(&store, &tasks), 1);
        assert!(store.load_pipeline("pipe-susp").unwrap().is_none());
        let record = tasks.get_task(&task.task.task_id, "owner").unwrap();
        assert_eq!(record.task.status, TaskStatus::Failed);
        match record.terminal_envelope {
            Some(TerminalEnvelope::Error { error }) => {
                assert_eq!(error.code, TIMEOUT_ERROR_CODE);
                assert!(error.message.contains("pipeline timed out"));
            }
            other => panic!("expected a terminal error, got {other:?}"),
        }
    }

    /// A suspended pipeline past its per-step `elicitation_timeout_ms` (but
    /// well within the whole-pipeline timeout) is reaped and fails its task.
    #[test]
    fn an_elicitation_timeout_fails_the_task() {
        let store = KvBackedPipelineStore::new_in_memory();
        let tasks = tasks();
        let task = tasks
            .create_task("owner", serde_json::json!(1), "test")
            .unwrap();
        let mut suspended = expired_pipeline("pipe-elic");
        suspended.pipeline_timeout_ms = 999_999_999; // whole-pipeline still alive
        suspended.created_at = Utc::now();
        suspended.suspended_at = Some(Utc::now() - chrono::Duration::seconds(10));
        suspended.elicitation_timeout_ms = Some(1); // suspended 10s > 1ms bound
        suspended.related_task_id = Some(task.task.task_id.clone());
        store.save_pipeline(&suspended).unwrap();

        assert_eq!(PipelineReaper::reap_once(&store, &tasks), 1);
        assert!(store.load_pipeline("pipe-elic").unwrap().is_none());
        let record = tasks.get_task(&task.task.task_id, "owner").unwrap();
        assert_eq!(record.task.status, TaskStatus::Failed);
        assert_eq!(
            record.task.status_message.as_deref(),
            Some("elicitation timed out waiting for client response")
        );
    }

    /// A running pipeline's task is left to the work that still runs it,
    /// and a task that already ended stays as it ended.
    #[test]
    fn a_running_or_ended_task_is_left_alone() {
        let store = KvBackedPipelineStore::new_in_memory();
        let tasks = tasks();
        let running = tasks
            .create_task("owner", serde_json::json!(1), "test")
            .unwrap();
        let mut pipeline = expired_pipeline("pipe-running");
        pipeline.related_task_id = Some(running.task.task_id.clone());
        store.save_pipeline(&pipeline).unwrap();

        let ended = tasks
            .create_task("owner", serde_json::json!(2), "test")
            .unwrap();
        tasks
            .cancel_task(&ended.task.task_id, "owner")
            .expect("cancelled");
        let mut suspended = expired_pipeline("pipe-ended");
        suspended.suspended_at = Some(Utc::now());
        suspended.related_task_id = Some(ended.task.task_id.clone());
        store.save_pipeline(&suspended).unwrap();

        assert_eq!(PipelineReaper::reap_once(&store, &tasks), 2);
        assert_eq!(
            tasks
                .get_task(&running.task.task_id, "owner")
                .unwrap()
                .task
                .status,
            TaskStatus::Working
        );
        assert_eq!(
            tasks
                .get_task(&ended.task.task_id, "owner")
                .unwrap()
                .task
                .status,
            TaskStatus::Cancelled
        );
    }
}
