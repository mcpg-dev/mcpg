//! Leader-election gate for gateway-core background loops (the pipeline
//! and task reapers, the registry syncer).
//!
//! These loops act on SHARED state — the coordinator KV, or a remote
//! registry a whole fleet would otherwise stampede. Without a gate, N
//! replicas each run the same work. [`maintain_leadership`] gates each
//! tick behind a named leadership role so exactly one replica runs it
//! at a time.
//!
//! Single-node deployments pass no backend and run unconditionally —
//! no leadership traffic, behaviour unchanged.

use std::time::Duration;

use mcpg_cluster_api::{BoxActiveLease, ClusterBackend};

/// Returns `true` when this replica currently holds `role` (and may run
/// its work this tick), `false` when a peer leads or the coordinator is
/// unreachable (skip the tick — fail-open: the work is idempotent and a
/// missed tick just defers it one interval).
///
/// `lease` carries the held lease across ticks: the leader renews it each
/// tick; a follower re-contends each tick and becomes leader once the
/// current leader's lease expires (crash) or is released. `lease_ttl`
/// should comfortably exceed the tick interval so a single slow tick
/// doesn't drop leadership.
pub(crate) async fn maintain_leadership(
    role: &str,
    backend: &dyn ClusterBackend,
    lease_ttl: Duration,
    lease: &mut Option<BoxActiveLease>,
) -> bool {
    if let Some(held) = lease.as_ref() {
        match held.renew().await {
            Ok(()) => return true,
            Err(error) => {
                tracing::warn!(role, error = %error, "lost leadership lease; re-contending");
                *lease = None;
            }
        }
    }
    match backend.try_acquire_leadership(role, lease_ttl).await {
        Ok(Some(acquired)) => {
            tracing::info!(role, "acquired leadership — this replica owns the work");
            *lease = Some(acquired);
            true
        }
        Ok(None) => false,
        Err(error) => {
            tracing::warn!(role, error = %error, "leadership acquire failed; skipping this tick");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn single_node_backend_always_grants_leadership() {
        // single_node is always-acquire: the reaper gate is a no-op on a
        // single-instance deployment, so it reaps exactly as before. Both
        // the initial acquire and the subsequent renew yield `true`.
        let backend: Arc<dyn ClusterBackend> =
            crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
        let mut lease: Option<BoxActiveLease> = None;

        let acquired = maintain_leadership(
            "gateway.reaper.test",
            backend.as_ref(),
            Duration::from_secs(30),
            &mut lease,
        )
        .await;
        assert!(acquired, "single_node must grant leadership");
        assert!(lease.is_some(), "the lease is retained for renewal");

        // Second tick: the held lease is renewed, still the leader.
        let renewed = maintain_leadership(
            "gateway.reaper.test",
            backend.as_ref(),
            Duration::from_secs(30),
            &mut lease,
        )
        .await;
        assert!(renewed, "a held lease renews → this replica stays leader");
    }
}
