//! The HTTP request deadline (`gateway.server.request_timeout_ms`) and the
//! backend calls that hold it.
//!
//! A request still unanswered at its deadline gets a `408` with an empty
//! body. A backend call that a tool dispatch awaits holds the deadline: the
//! plugin's own data timeout bounds that call, so a call that runs past the
//! deadline still gives the request its result. Once no call holds it, the
//! first wait of an expired request ends it with the `408`.
//!
//! A request whose backend call has begun is not cancelled when it is
//! dropped (its client goes away, or it times out after the call): its
//! handler finishes on a task of its own, so the call's idempotency record,
//! audit event, usage charge and session clean-up complete, and the quota
//! permit and the plugin stay held until the call returns.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;

tokio::task_local! {
    static CALLS: BackendCalls;
}

/// The backend calls of one HTTP request. The middleware polls the request's
/// handler in [`BackendCalls::in_scope`], where [`begin_backend_call`] finds
/// them.
#[derive(Clone, Default)]
pub(crate) struct BackendCalls(Arc<CallState>);

#[derive(Default)]
struct CallState {
    in_flight: AtomicUsize,
    begun: AtomicBool,
}

impl BackendCalls {
    /// Runs `f` with these calls as the ones [`begin_backend_call`] counts.
    fn in_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        CALLS.sync_scope(self.clone(), f)
    }

    fn begun(&self) -> bool {
        self.0.begun.load(Ordering::Relaxed)
    }

    fn in_flight(&self) -> bool {
        self.0.in_flight.load(Ordering::Relaxed) > 0
    }
}

/// Marks a backend call of the request this task serves as in flight until
/// the guard drops. `None` outside an HTTP request.
pub(crate) fn begin_backend_call() -> Option<BackendCall> {
    CALLS
        .try_with(|calls| {
            calls.0.begun.store(true, Ordering::Relaxed);
            calls.0.in_flight.fetch_add(1, Ordering::Relaxed);
            BackendCall(calls.clone())
        })
        .ok()
}

/// A backend call in flight; see [`begin_backend_call`].
pub(crate) struct BackendCall(BackendCalls);

impl Drop for BackendCall {
    fn drop(&mut self) {
        (self.0).0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A request's handler, polled in the scope of its [`BackendCalls`]. Dropped
/// before it completes, it finishes on a task of its own once a backend call
/// has begun, and is cancelled otherwise.
struct DetachOnDrop<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fut: Option<Pin<Box<F>>>,
    calls: BackendCalls,
}

impl<F> DetachOnDrop<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn new(calls: BackendCalls, fut: F) -> Self {
        Self {
            fut: Some(Box::pin(fut)),
            calls,
        }
    }
}

impl<F> Future for DetachOnDrop<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let fut = this
            .fut
            .as_mut()
            .expect("DetachOnDrop polled after it completed");
        let output = ready!(this.calls.in_scope(|| fut.as_mut().poll(cx)));
        this.fut = None;
        Poll::Ready(output)
    }
}

impl<F> Drop for DetachOnDrop<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn drop(&mut self) {
        if self.calls.begun()
            && let Some(mut fut) = self.fut.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let calls = self.calls.clone();
            runtime.spawn(std::future::poll_fn(move |cx| {
                calls.in_scope(|| fut.as_mut().poll(cx))
            }));
        }
    }
}

/// The layer that answers `408` once `timeout` has passed, while no backend
/// call is in flight. Its service calls the inner service in `call`, so a
/// request costs no clone of the inner service and no boxed middleware
/// future.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestDeadlineLayer {
    timeout: Duration,
}

impl RequestDeadlineLayer {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> tower::Layer<S> for RequestDeadlineLayer {
    type Service = RequestDeadline<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestDeadline {
            inner,
            timeout: self.timeout,
        }
    }
}

/// The service of a [`RequestDeadlineLayer`].
#[derive(Clone, Debug)]
pub(crate) struct RequestDeadline<S> {
    inner: S,
    timeout: Duration,
}

impl<S> tower::Service<Request> for RequestDeadline<S>
where
    S: tower::Service<Request, Response = Response, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = DeadlineFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        DeadlineFuture {
            response: DetachOnDrop::new(BackendCalls::default(), self.inner.call(request)),
            expired: Box::pin(tokio::time::sleep(self.timeout)),
        }
    }
}

/// A request's response, or the empty `408` once its deadline passed while
/// no backend call held it.
pub(crate) struct DeadlineFuture<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    response: DetachOnDrop<F>,
    expired: Pin<Box<tokio::time::Sleep>>,
}

impl<F> Future for DeadlineFuture<F>
where
    F: Future<Output = Result<Response, Infallible>> + Send + 'static,
{
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Poll::Ready(response) = Pin::new(&mut this.response).poll(cx) {
            return Poll::Ready(response);
        }
        // Past the deadline a request with a call in flight is woken by its
        // own work, so the elapsed timer needs no waker.
        if this.expired.as_mut().poll(cx).is_pending() || this.response.calls.in_flight() {
            return Poll::Pending;
        }
        Poll::Ready(Ok(timed_out()))
    }
}

fn timed_out() -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
    response
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::routing::get;
    use tower::ServiceExt;

    const DEADLINE: Duration = Duration::from_millis(50);
    const PAST_THE_DEADLINE: Duration = Duration::from_millis(150);

    /// Runs `fut` as a request's handler that is dropped after `after`
    /// unless it finished; returns whether it finished in time.
    pub(crate) async fn drop_request_after<F>(after: Duration, fut: F) -> bool
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handler = DetachOnDrop::new(BackendCalls::default(), fut);
        tokio::time::timeout(after, handler).await.is_ok()
    }

    async fn call(app: Router) -> (StatusCode, String) {
        let app = app.layer(RequestDeadlineLayer::new(DEADLINE));
        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_request_answered_in_time_gets_its_response() {
        let app = Router::new().route("/", get(|| async { "done" }));
        assert_eq!(call(app).await, (StatusCode::OK, "done".to_owned()));
    }

    #[tokio::test]
    async fn a_request_past_its_deadline_gets_an_empty_408() {
        let app = Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(PAST_THE_DEADLINE).await;
                "late"
            }),
        );
        assert_eq!(
            call(app).await,
            (StatusCode::REQUEST_TIMEOUT, String::new())
        );
    }

    #[tokio::test]
    async fn a_call_in_flight_holds_the_deadline() {
        let app = Router::new().route(
            "/",
            get(|| async {
                let _call = begin_backend_call().expect("inside the request scope");
                tokio::time::sleep(PAST_THE_DEADLINE).await;
                "result"
            }),
        );
        assert_eq!(call(app).await, (StatusCode::OK, "result".to_owned()));
    }

    #[tokio::test]
    async fn an_expired_request_ends_at_its_first_wait_after_the_call() {
        let app = Router::new().route(
            "/",
            get(|| async {
                let call = begin_backend_call();
                tokio::time::sleep(PAST_THE_DEADLINE).await;
                drop(call);
                tokio::time::sleep(Duration::from_millis(10)).await;
                "late"
            }),
        );
        assert_eq!(
            call(app).await,
            (StatusCode::REQUEST_TIMEOUT, String::new())
        );
    }

    /// A handler dropped before any backend call began is cancelled; once a
    /// call began, it finishes on a task of its own.
    #[tokio::test]
    async fn a_dropped_request_finishes_only_once_a_backend_call_began() {
        for begin_call in [false, true] {
            let (finished, finish) = tokio::sync::oneshot::channel();
            let in_time = drop_request_after(Duration::from_millis(5), async move {
                let _call = begin_call.then(begin_backend_call);
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = finished.send(());
            })
            .await;
            assert!(!in_time, "the handler outlasts the request");
            assert_eq!(finish.await.is_ok(), begin_call, "begin_call: {begin_call}");
        }
    }

    /// Through the layer: a request dropped before its response finishes
    /// its handler once a backend call began, and cancels it otherwise.
    #[tokio::test]
    async fn the_layer_detaches_a_dropped_request_only_once_a_backend_call_began() {
        for begin_call in [false, true] {
            let (finished, finish) = tokio::sync::oneshot::channel::<()>();
            let finished = Arc::new(std::sync::Mutex::new(Some(finished)));
            let app = Router::new()
                .route(
                    "/",
                    get(move || {
                        let finished = Arc::clone(&finished);
                        async move {
                            let _call = begin_call.then(begin_backend_call);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            if let Some(finished) = finished.lock().unwrap().take() {
                                let _ = finished.send(());
                            }
                            "done"
                        }
                    }),
                )
                .layer(RequestDeadlineLayer::new(DEADLINE));
            let request = app.oneshot(Request::get("/").body(Body::empty()).unwrap());
            let in_time = tokio::time::timeout(Duration::from_millis(5), request)
                .await
                .is_ok();
            assert!(!in_time, "the handler outlasts the request");
            assert_eq!(finish.await.is_ok(), begin_call, "begin_call: {begin_call}");
        }
    }

    /// The layer's service is ready when the inner service is.
    #[tokio::test]
    async fn the_layer_waits_for_the_inner_service() {
        use tower::{Service, ServiceExt as _};
        let mut service = tower::Layer::layer(
            &RequestDeadlineLayer::new(DEADLINE),
            tower::service_fn(|_: Request| async { Ok::<_, Infallible>(timed_out()) }),
        );
        let ready = service.ready().await.expect("an infallible service");
        let response = ready
            .call(Request::get("/").body(Body::empty()).unwrap())
            .await
            .expect("an infallible service");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[test]
    fn a_call_marks_the_request_begun() {
        let calls = BackendCalls::default();
        assert!(!calls.begun());
        calls.in_scope(|| drop(begin_backend_call().expect("inside the scope")));
        assert!(calls.begun());
        assert!(!calls.in_flight());
    }

    #[tokio::test]
    async fn outside_a_request_there_is_no_call() {
        assert!(begin_backend_call().is_none());
    }
}
