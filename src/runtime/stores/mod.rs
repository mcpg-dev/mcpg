pub mod content_store_registry;
pub mod pipeline_store;
pub mod request_state_store;
pub mod session_store;
pub mod subscription_store;
pub mod task_store;

/// Run a store future from synchronous code. One that is ready on its first
/// poll, as an in-memory store's is, answers at once; any other runs on this
/// thread while the worker is handed over.
pub(crate) fn block_on_store<F: std::future::Future>(fut: F) -> F::Output {
    use tokio::runtime::{Handle, RuntimeFlavor};
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
        return out;
    }
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| h.block_on(fut))
        }
        // current_thread runtime (e.g. default `#[tokio::test]`) or no
        // tokio context: fall back to a thread-local executor. Safe for
        // primitives that don't require the tokio reactor (e.g. MemoryKv);
        // real I/O backends (Redis, NATS) only run under multi-thread
        // runtimes in production.
        _ => futures::executor::block_on(fut),
    }
}

#[cfg(test)]
mod tests {
    use super::block_on_store;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_store_call_completes_whether_or_not_its_future_is_ready_at_once() {
        assert_eq!(block_on_store(async { 7 }), 7);
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = tx.send(8);
        });
        assert_eq!(block_on_store(rx), Ok(8));
    }
}
