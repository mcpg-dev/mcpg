//! Background reaper for the task store.
//!
//! Deletes task records whose `created_at + ttl` has elapsed so memory-backed
//! stores do not leak terminal records indefinitely and remote backends match
//! the configured retention policy.

use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::runtime::task_store::TaskStore;

/// Periodically garbage-collects expired task records.
pub struct TaskReaper {
    interval: Duration,
}

impl TaskReaper {
    pub fn new(interval: Duration) -> Self {
        Self { interval }
    }

    /// Leadership role this reaper contends for when clustered.
    const LEADER_ROLE: &'static str = "gateway.reaper.task";

    /// Spawn the reaper as a background tokio task.
    ///
    /// `leadership` gates the sweep behind cluster leader-election:
    /// `Some(coordinator)` ⇒ only the replica holding `LEADER_ROLE` reaps;
    /// `None` (single-node / no coordinator) ⇒ reap unconditionally.
    pub fn spawn(
        self,
        task_store: Arc<dyn TaskStore>,
        leadership: Option<Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    ) -> tokio::task::JoinHandle<()> {
        let lease_ttl = self.interval.saturating_mul(3).max(Duration::from_secs(30));
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.interval);
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
                let removed = task_store.gc_expired_tasks();
                if removed > 0 {
                    info!(removed, "task reaper: expired records removed");
                    metrics::counter!("mcpg_task_reaper_cleaned_total").increment(removed as u64);
                    metrics::gauge!("mcpg_task_reaper_last_sweep_count").set(removed as f64);
                }
            }
        })
    }
}
