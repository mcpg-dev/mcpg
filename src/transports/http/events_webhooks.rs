//! `POST /webhooks/events/{source_id}` — the route of an `inbound` event
//! source — and `POST /webhooks/mcp-events/{federation}/{id}` — the
//! callback of an upstream webhook subscription of an imported event type.
//!
//! Authentication is the sender's signature over the raw body, not a
//! gateway credential. The answer is 2xx only once the event is durably in
//! the inbox of each type that keeps it; a full or stale inbox answers 503
//! with `Retry-After` so the sender keeps the event and retries. No answer
//! echoes a request value, except the challenge of a verification envelope
//! or of a signing profile's handshake.

use super::*;
use crate::protocol::v_2026_07_28::extensions::events::wire::VerificationResponse;
use crate::runtime::events::InboundReply;

pub(crate) async fn webhook_events_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(source_id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let config = state.config.load();
    let request_id = GatewayRequestId::new();
    // Server-to-server senders send no Origin; a cross-origin browser request
    // is refused before anything is read.
    if let Some(resp) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_id,
    ) {
        return resp;
    }
    let core = state
        .runtime
        .load()
        .shared_services
        .load_full()
        .and_then(|services| services.events_core.get().cloned());
    let reply = match core {
        Some(core) => core.receive_inbound(&source_id, &headers, &body).await,
        None => InboundReply::NotFound,
    };
    inbound_response(reply)
}

/// `POST /webhooks/mcp-events/{federation}/{id}`: a delivery of an upstream
/// webhook subscription of an imported event type. Authentication is the
/// upstream's signature with the secret derived for `id`.
pub(crate) async fn upstream_events_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((federation, id)): axum::extract::Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    use crate::runtime::events::upstream_webhook::UpstreamReply;
    use axum::http::StatusCode;
    let config = state.config.load();
    let request_id = GatewayRequestId::new();
    if let Some(resp) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_id,
    ) {
        return resp;
    }
    let core = state
        .runtime
        .load()
        .shared_services
        .load_full()
        .and_then(|services| services.events_core.get().cloned());
    let reply = match core {
        Some(core) => {
            core.receive_upstream(&federation, &id, &headers, &body)
                .await
        }
        None => UpstreamReply::Unknown,
    };
    let (status, retry_after, body) = match reply {
        UpstreamReply::Accepted => (StatusCode::OK, None, serde_json::json!({})),
        UpstreamReply::Challenge(challenge) => (
            StatusCode::OK,
            None,
            serde_json::json!(VerificationResponse { challenge }),
        ),
        UpstreamReply::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            None,
            serde_json::json!({ "error": "signature verification failed" }),
        ),
        UpstreamReply::BadRequest => (
            StatusCode::BAD_REQUEST,
            None,
            serde_json::json!({ "error": "the body is not an event delivery" }),
        ),
        UpstreamReply::Gone => (
            StatusCode::GONE,
            None,
            serde_json::json!({ "error": "this subscription has ended" }),
        ),
        UpstreamReply::Unknown => (
            StatusCode::SERVICE_UNAVAILABLE,
            Some(std::time::Duration::from_secs(30)),
            serde_json::json!({ "error": "no subscription has this id now" }),
        ),
        UpstreamReply::RateLimited(wait) => (
            StatusCode::TOO_MANY_REQUESTS,
            Some(wait),
            serde_json::json!({ "error": "too many requests" }),
        ),
        UpstreamReply::Unavailable(wait) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Some(wait),
            serde_json::json!({ "error": "the event cannot be accepted now" }),
        ),
    };
    with_retry_after((status, axum::Json(body)).into_response(), retry_after)
}

/// `response` with `Retry-After` in whole seconds, rounded up, when `wait`
/// is set.
fn with_retry_after(mut response: Response, wait: Option<std::time::Duration>) -> Response {
    if let Some(wait) = wait {
        let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        if let Ok(value) = axum::http::HeaderValue::from_str(&secs.max(1).to_string()) {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
    }
    response
}

pub(crate) fn inbound_response(reply: InboundReply) -> Response {
    use axum::http::StatusCode;
    let (status, retry_after, error) = match reply {
        InboundReply::Handshake(Some(object)) => {
            return (StatusCode::OK, axum::Json(object)).into_response();
        }
        InboundReply::Accepted | InboundReply::Ignored | InboundReply::Handshake(None) => {
            (StatusCode::ACCEPTED, None, None)
        }
        InboundReply::NotFound => (StatusCode::NOT_FOUND, None, Some("unknown event source")),
        InboundReply::Unauthorized | InboundReply::Stale => (
            StatusCode::UNAUTHORIZED,
            None,
            Some("signature verification failed"),
        ),
        InboundReply::BadRequest => (
            StatusCode::BAD_REQUEST,
            None,
            Some("the body is not a JSON object the route can read"),
        ),
        InboundReply::RateLimited(wait) => (
            StatusCode::TOO_MANY_REQUESTS,
            Some(wait),
            Some("too many requests"),
        ),
        InboundReply::Unavailable(wait) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Some(wait),
            Some("the event cannot be accepted now"),
        ),
    };
    let body = match error {
        Some(error) => serde_json::json!({ "error": error }),
        None => serde_json::json!({}),
    };
    with_retry_after((status, axum::Json(body)).into_response(), retry_after)
}
