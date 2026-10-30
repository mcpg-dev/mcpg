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

use mcpg_cluster_api::{ActiveLease, BoxActiveLease, ClusterBackend, ClusterError};

/// Returns `true` when this replica currently holds `role` (and may run
/// its work this tick), `false` when a peer leads or the coordinator is
/// unreachable (skip the tick — fail-open: the work is idempotent and a
/// missed tick just defers it one interval).
///
/// `lease` carries the held lease across ticks: the leader renews it each
/// tick; a follower re-contends each tick and becomes leader once the
/// current leader's lease expires (crash) or is released. A renewal the
/// coordinator does not answer keeps the lease until the end its last
/// renewal set, before which no other replica can take it. `lease_ttl`
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
            Err(error) if unanswered(&error) && !lapsed(held.as_ref()) => {
                tracing::warn!(role, error = %error, "leadership lease renewal unanswered; the lease holds until it expires");
                return true;
            }
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

/// A renewal error that leaves the lease where it was: the coordinator
/// timed out or could not be reached, so it gave the lease to no one.
fn unanswered(error: &ClusterError) -> bool {
    matches!(
        error,
        ClusterError::Timeout | ClusterError::BackendUnavailable { .. }
    )
}

/// Whether the end the last renewal of `lease` set has passed.
fn lapsed(lease: &dyn ActiveLease) -> bool {
    match chrono::DateTime::parse_from_rfc3339(&lease.expires_at()) {
        Ok(end) => end.timestamp_millis() <= chrono::Utc::now().timestamp_millis(),
        Err(_) => true,
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

    /// The fencing token of a [`FailingLease`]; a single-node lease starts
    /// at 1.
    const FAILING_FENCE: u64 = 77;

    /// A held lease whose every renewal fails with `error`.
    struct FailingLease {
        error: ClusterError,
        expires_at: String,
    }

    impl FailingLease {
        /// One that ends `ends_in` from now (in the past when negative).
        fn held(error: ClusterError, ends_in: chrono::Duration) -> Option<BoxActiveLease> {
            Some(Box::new(Self {
                error,
                expires_at: (chrono::Utc::now() + ends_in).to_rfc3339(),
            }))
        }
    }

    #[async_trait::async_trait]
    impl ActiveLease for FailingLease {
        fn fencing_token(&self) -> u64 {
            FAILING_FENCE
        }

        fn expires_at(&self) -> String {
            self.expires_at.clone()
        }

        async fn renew(&self) -> Result<(), ClusterError> {
            Err(self.error.clone())
        }

        async fn release(&self) -> Result<(), ClusterError> {
            Ok(())
        }
    }

    /// One tick over `lease`; a lease given up is replaced by a single-node
    /// one, so the fencing token shows which lease is held after it.
    async fn tick(lease: &mut Option<BoxActiveLease>) -> Option<u64> {
        let backend = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
        let held = maintain_leadership(
            "gateway.reaper.test",
            backend.as_ref(),
            Duration::from_secs(30),
            lease,
        )
        .await;
        assert!(held);
        lease.as_ref().map(|lease| lease.fencing_token())
    }

    #[tokio::test]
    async fn an_unanswered_renewal_keeps_a_lease_until_its_end() {
        for error in [
            ClusterError::Timeout,
            ClusterError::BackendUnavailable {
                reason: "lease renew read: timed out".into(),
            },
        ] {
            let mut lease = FailingLease::held(error, chrono::Duration::seconds(10));
            assert_eq!(tick(&mut lease).await, Some(FAILING_FENCE));
        }
    }

    #[tokio::test]
    async fn a_lease_past_its_end_is_given_up_when_its_renewal_goes_unanswered() {
        let mut lease = FailingLease::held(ClusterError::Timeout, chrono::Duration::seconds(-1));
        assert_ne!(tick(&mut lease).await, Some(FAILING_FENCE));
    }

    #[tokio::test]
    async fn a_lease_the_coordinator_gave_to_another_holder_is_given_up_at_once() {
        for error in [
            ClusterError::LeaseExpired,
            ClusterError::CasConflict {
                key: "role:gateway.reaper.test".into(),
                reason: "another holder".into(),
            },
        ] {
            let mut lease = FailingLease::held(error, chrono::Duration::seconds(10));
            assert_ne!(tick(&mut lease).await, Some(FAILING_FENCE));
        }
    }
}
