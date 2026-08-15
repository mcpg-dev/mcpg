//! Re-entrancy guard shared by the metrics, log, and telemetry bridges.
//!
//! Each bridge forwards a queued signal to its sinks by awaiting an
//! `emit_*_filtered` fan-out. A sink invoked there may itself emit a
//! signal — a metric increment, a `tracing` event, a span — and that
//! emission re-enters the producer side of a bridge. Re-enqueueing it
//! feeds a forwarder its own output: every processed signal produces more,
//! and the bridge channel spins hot forever, burning CPU while idle.
//!
//! Invariant: a signal emitted while a bridge is dispatching to its sinks
//! is self-referential and MUST NOT be re-enqueued. [`with_scope`] marks
//! the current task as "inside a sink dispatch" for the duration of one
//! fan-out; every bridge producer checks [`in_dispatch`] and drops a
//! signal emitted while it is set. A signal emitted from anywhere else
//! enqueues normally. The guard is a single task-local shared across all
//! three bridges, so a cross-bridge emission (a log sink that increments a
//! metric, a metric sink that logs) is caught as well.

use std::future::Future;

tokio::task_local! {
    static IN_DISPATCH: ();
}

/// True while the current task is inside an observability sink dispatch
/// (see [`with_scope`]). Bridge producers drop signals emitted here rather
/// than re-enqueue them.
pub fn in_dispatch() -> bool {
    IN_DISPATCH.try_with(|()| ()).is_ok()
}

/// Run `fut` — a bridge's `emit_*_filtered` fan-out — with the dispatch
/// guard set, so any signal a sink emits during it is recognised as
/// self-referential and dropped by the producers.
pub async fn with_scope<F: Future>(fut: F) -> F::Output {
    IN_DISPATCH.scope((), fut).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn guard_is_unset_outside_scope() {
        assert!(!in_dispatch());
    }

    #[tokio::test]
    async fn guard_is_set_inside_scope() {
        with_scope(async {
            assert!(in_dispatch());
        })
        .await;
        assert!(!in_dispatch());
    }
}
