//! HTTP/SSE transport — Axum router, MCP Streamable HTTP endpoint,
//! health/readiness probes, and OAuth protected-resource metadata.
//!
//! Implements the MCP Streamable HTTP specification including session
//! management, SSE streaming, and reconnection with `Last-Event-ID`.

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, HeaderName, HeaderValue},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
    routing::post,
};
use serde::Serialize;
use serde_json::Value;
use std::convert::Infallible;
use tokio_stream::{StreamExt, iter, wrappers::ReceiverStream};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::transports::wire_policy::{self, Negotiated, WireVersion};
use crate::{
    app::AppState,
    protocol::{
        PROTOCOL_VERSION_HEADER, ProtocolError, ProtocolHttpResponse, ProtocolResponse,
        SESSION_ID_HEADER, map_client_message_to_operation, parse_client_message,
    },
    runtime::{
        DiagnosticsOperation, GatewayOperation, GatewayRequest, GatewayRequestId, GatewayResponse,
        GatewayResponsePayload, RequestContext, RequestIdentity, ResumeCursor, SseEventRecord,
        StreamAccessError, TransportKind, pipeline_store::DeliveryMessage,
    },
};

/// Per-handler convenience extractor: optional `Extension<TlsInfoArc>`
/// stamped by [`crate::transports::tls::McpgTlsAcceptor`]. Plain HTTP
/// requests (no TLS) and TLS requests where the acceptor decided
/// there was nothing worth stamping (no SNI, no client cert) leave
/// the extension absent — the wrapper resolves to `None` in both
/// cases.
type TlsInfoExt = Option<axum::extract::Extension<crate::transports::tls::TlsInfoArc>>;

trait TlsInfoExtUnwrap {
    fn into_inner(self) -> Option<crate::transports::tls::TlsInfoArc>;
}

impl TlsInfoExtUnwrap for TlsInfoExt {
    fn into_inner(self) -> Option<crate::transports::tls::TlsInfoArc> {
        self.map(|axum::extract::Extension(arc)| arc)
    }
}

mod discovery;
mod identity;
mod probes;
mod response;
mod sse;
mod validate;
mod webhooks;

pub(crate) use discovery::{
    oauth_authorization_server_metadata_handler, oauth_protected_resource_handler,
    oauth_token_handler, served_registry_list_handler, served_registry_version_handler,
};
pub(crate) use identity::{build_full_request_context, lift_idempotency_key_header};
pub(crate) use probes::{health_handler, metrics_handler, readiness_handler, runtime_handler};
pub(crate) use response::{
    INSUFFICIENT_SCOPE_DATA_KEY, map_gateway_response, map_protocol_error_response,
    map_protocol_error_with_status, map_sse_events, map_transport_rejection,
    reject_method_on_modern_wire, resource_metadata_url, with_request_id_header,
    with_session_id_header, with_www_authenticate_challenge,
};
pub(crate) use sse::{
    ResourceSubscriptionGuard, SlottedEventStream, SseStreamSlot, acquire_sse_slot,
    delivery_bus_sse, delivery_dedupe_key, delivery_to_sse_event, open_post_continuation_sse,
    register_modern_resource_subscriptions, sse_event_from_record,
};
pub(crate) use validate::{
    enforce_http_protocol_version_header, post_accepts_sse, validate_get_accept, validate_origin,
    validate_post_accept, validate_post_content_type,
};
pub(crate) use webhooks::{webhook_approval_resolution_handler, webhook_resource_updated_handler};
// Reached only from this transport's test module.
#[cfg(test)]
pub(crate) use identity::{build_request_context, plugin_identity_to_request};
#[cfg(test)]
pub(crate) use response::INSUFFICIENT_SCOPE_HEADER;
#[cfg(test)]
pub(crate) use sse::SseStreamCounts;

const REQUEST_ID_RESPONSE_HEADER: &str = "x-mcpg-request-id";
const UPSTREAM_REQUEST_ID_HEADER: &str = "x-request-id";
const SUBJECT_ID_HEADER: &str = "x-mcpg-subject-id";
const ORIGIN_HEADER: &str = "origin";
const LAST_EVENT_ID_HEADER: &str = "last-event-id";
const JSON_ACCEPT: &str = "application/json";
const SSE_ACCEPT: &str = "text/event-stream";

/// Start the HTTP(S) transport listener. Binds to the configured address,
/// optionally with TLS, and serves until the shutdown signal fires.
pub async fn serve(state: AppState, shutdown: tokio::sync::watch::Receiver<()>) -> Result<()> {
    let config = state.config.load();
    let bind_address = config.gateway.server.bind_address.clone();
    let health_path = config.gateway.server.health_path.clone();
    let mcp_path = config.gateway.server.mcp_path.clone();
    let tls_config = config.gateway.server.tls.clone();
    let app = router(state, &health_path, &mcp_path);

    let mut shutdown_rx = shutdown;

    if let Some(tls) = tls_config {
        use crate::transports::tls::{McpgTlsAcceptor, RustlsConfig, build_server_config};
        use axum_server::tls_rustls::RustlsAcceptor;
        // Build a custom rustls ServerConfig so we can wire mTLS
        // (`WebPkiClientVerifier` against the operator's CA bundle)
        // and ALPN (`h2` then `http/1.1`). axum-server's
        // `RustlsConfig::from_pem_file` doesn't expose these, so
        // we hand it a pre-built ServerConfig via `from_config`.
        let server_config = build_server_config(&tls)
            .map_err(|e| anyhow::anyhow!("failed to build TLS server config: {}", e))?;
        let rustls_config = RustlsConfig::from_config(server_config);
        // McpgTlsAcceptor wraps the standard rustls acceptor and
        // stamps `TlsInfo` (peer cert chain + parsed leaf details)
        // onto every request via Extensions; the HTTP handler then
        // threads it into `RequestMetadata.tls`.
        let acceptor = McpgTlsAcceptor::new(RustlsAcceptor::new(rustls_config));
        let addr: std::net::SocketAddr = bind_address
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid bind_address for TLS: {}", e))?;
        info!(
            bind_address = %bind_address,
            health_path = %health_path,
            mcp_path = %mcp_path,
            min_tls = %tls.min_tls_version,
            client_cert_required = ?tls.client_cert_required,
            "https transport listening (TLS)"
        );
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            info!("https transport: graceful shutdown signal received");
            server_handle.graceful_shutdown(None);
        });
        axum_server::bind(addr)
            .acceptor(acceptor)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind_address).await?;
        info!(bind_address = %bind_address, health_path = %health_path, mcp_path = %mcp_path, "http transport listening");
        // Connect-info make-service so handlers can read the transport peer
        // (`ConnectInfo<SocketAddr>`) — the anonymous per-IP rate limiter's
        // key. The TLS branch gets the same extension from McpgTlsAcceptor.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
            info!("http transport: graceful shutdown signal received");
        })
        .await?;
    }
    Ok(())
}

/// Build the Axum router with health, readiness, metrics, MCP, webhook, and
/// OAuth protected-resource-metadata endpoints.
pub fn router(state: AppState, health_path: &str, mcp_path: &str) -> Router {
    let config = state.config.load();
    let request_timeout =
        std::time::Duration::from_millis(config.gateway.server.request_timeout_ms);

    let mut router = Router::new()
        .route(health_path, get(health_handler))
        .route("/ready", get(readiness_handler))
        .route("/runtime", get(runtime_handler))
        .route(
            mcp_path,
            get(mcp_get_handler)
                .post(mcp_handler)
                .delete(mcp_delete_handler),
        );

    if config.observability.is_metrics_on() {
        // The route delegates rendering to the canonical Prometheus
        // plugin via `MetricsSink::render_text_exposition`. Path comes
        // from the first sink whose kind is the Prometheus plugin id
        // (the gateway-side built-ins are stderr/stdout/file only).
        // Defaults to `/metrics` when the operator didn't override it.
        let metrics_path = config
            .observability
            .metrics
            .sinks
            .iter()
            .find(|s| s.kind == crate::observability::PROMETHEUS_PLUGIN_ID)
            .and_then(|s| s.config.get("path").and_then(|v| v.as_str()))
            .unwrap_or("/metrics")
            .to_owned();
        router = router.route(&metrics_path, get(metrics_handler));
    }

    // Webhook receiver for external resource change notifications.
    // Third-party systems POST to this endpoint to trigger
    // `notifications/resources/updated` for subscribed clients.
    router = router.route(
        "/webhooks/resource-updated/{token}",
        post(webhook_resource_updated_handler),
    );

    // Tool-gate approval resolution webhook. The
    // notifier embeds the HMAC-signed callback URL in its UI; on
    // approve/deny the human's interaction posts here. The
    // gateway runtime resolves the in-flight approval (locally or
    // via cluster broadcast) and the waiting tool-call request
    // returns the corresponding outcome to the MCP client.
    router = router.route(
        "/webhooks/approvals/{approval_id}",
        post(webhook_approval_resolution_handler),
    );

    // http_route plugin mount — namespaced under `/plugins/*` so it
    // can never collide with gateway routes. Two routes: one for the
    // bare `/plugins/{id}/{entity}` case and one for any subpath.
    // Both handlers dispatch through the same pipeline; the split is
    // purely to keep axum's path-parameter extractor happy.
    router = router
        .route(
            "/plugins/{plugin_id}/{entity_name}",
            axum::routing::any(super::http_route::dispatch_no_subpath),
        )
        .route(
            "/plugins/{plugin_id}/{entity_name}/{*subpath}",
            axum::routing::any(super::http_route::dispatch_with_subpath),
        );

    // Override-mode routes — plugins that declared
    // `http_route_serve` and that the operator granted
    // + enabled with `http_route.allow_path_override: true`. Each
    // entry becomes a top-level axum route. Collisions + reserved
    // paths are rejected at build time; a single bad plugin config
    // refuses the whole gateway boot rather than silently picking
    // one winner.
    router =
        super::http_route::mount_override_routes(router, state.runtime.load().plugin_registry())
            .expect("override-mode http_route wiring");

    // OAuth 2.1 Protected Resource Metadata (RFC 9728).
    // Only mounted when auth configuration provides issuer info. Both the
    // root well-known path and the RFC 9728 §3.1 path-aware form
    // (`/.well-known/oauth-protected-resource/{*path}`) are served so a
    // client that derives the metadata URL from a resource carrying a
    // path component finds it.
    if config.governance.access.resource_metadata.is_some()
        || config.governance.access.oidc_oauth.is_some()
        || config
            .governance
            .access
            .jwks
            .as_ref()
            .and_then(|j| j.issuer.as_ref())
            .is_some()
    {
        router = router
            .route(
                "/.well-known/oauth-protected-resource",
                get(oauth_protected_resource_handler),
            )
            .route(
                "/.well-known/oauth-protected-resource/{*resource_path}",
                get(oauth_protected_resource_handler),
            );
    }

    // Embedded EMA authorization server (RFC 8414 metadata + the
    // jwt-bearer/ID-JAG token endpoint). Mounted only when
    // `governance.access.authorization_server` is configured.
    if config.governance.access.authorization_server.is_some() {
        router = router
            .route(
                "/.well-known/oauth-authorization-server",
                get(oauth_authorization_server_metadata_handler),
            )
            .route("/oauth/token", post(oauth_token_handler));
    }

    // MCP-Registry surface (v0.1 API): one entry describing this
    // gateway, so registry-driven client policies can discover MCPG as
    // their approved server. Mounted only when
    // `mcp.registry.enabled` (a restart-time toggle, like the
    // well-known mounts).
    if config.mcp.registry.enabled {
        router = router
            .route("/v0.1/servers", get(served_registry_list_handler))
            .route(
                "/v0.1/servers/{name}/versions/{version}",
                get(served_registry_version_handler),
            );
    }

    // body cap is operator-tunable via server.max_request_body_mb.
    // A misconfigured 0 falls back to 4 MiB — an unbounded request body is
    // never acceptable on a public endpoint.
    let body_cap_mb = if config.gateway.server.max_request_body_mb == 0 {
        4
    } else {
        config.gateway.server.max_request_body_mb
    };
    router
        .layer(axum::extract::DefaultBodyLimit::max(
            body_cap_mb * 1024 * 1024,
        ))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        // Last-resort panic boundary: a panic in any handler becomes a
        // JSON-RPC 500 instead of resetting the connection / killing the
        // worker task. Placed inside TraceLayer so the synthesized 500 is
        // still traced.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            handle_router_panic,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Panic responder for [`tower_http::catch_panic::CatchPanicLayer`]. Converts a
/// handler panic into a `-32603` JSON-RPC 500. The panic payload is logged
/// host-side but never surfaced to the client (it can carry internal detail).
fn handle_router_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = err
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| err.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>");
    tracing::error!(panic.detail = %detail, "request handler panicked; returning 500");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32603, "message": "internal error" },
            "id": null,
        })),
    )
        .into_response()
}

/// Gates every `POST /mcp` passes before its body is parsed: per-IP rate limit
/// for below-Verified callers, then origin, `Accept` and `Content-Type`.
///
/// Returns whether the client admitted `text/event-stream`, which is the input
/// to every optional SSE upgrade on the response path. `Err` is the rejection to
/// send back as-is.
fn mcp_post_preflight(
    headers: &HeaderMap,
    config: &crate::config::AppConfig,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    request_context: &RequestContext,
) -> Result<bool, Response> {
    // Per-IP rate limit for requests below cryptographically-verified trust —
    // Anonymous AND header-asserted (`server.anonymous_rate_limit_*`). A
    // header-asserted caller presents no proof, so it must not buy itself out
    // of the limiter by setting `x-mcpg-subject-id`; only Verified traffic
    // (attributable, metered per tenant) skips this branch. Checked before any
    // body parse/dispatch work.
    if request_context.identity.is_below_verified() {
        let srv = &config.gateway.server;
        // `client_ip` is None only for an unattributable source (no trusted
        // XFF, no ConnectInfo — in-process tests): skip rather than lump every
        // such caller into one shared bucket. Real serve paths always stamp it.
        if srv.anonymous_rate_limit_per_min > 0
            && let Some(ip) = crate::transports::anon_limit::client_ip(
                srv.trust_proxy_ip,
                headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
                peer.map(|ext| ext.0.0.ip()),
            )
            && !crate::transports::anon_limit::check(
                ip,
                srv.anonymous_rate_limit_per_min,
                srv.anonymous_rate_limit_burst,
            )
        {
            metrics::counter!("mcpg_anonymous_rate_limited_total").increment(1);
            tracing::warn!(%ip, "anonymous /mcp rate limit exceeded");
            return Err((
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "60")],
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32099,
                        "message": "anonymous rate limit exceeded — slow down or authenticate",
                    },
                })),
            )
                .into_response());
        }
    }

    if let Some(response) = validate_origin(
        headers,
        &config.gateway.server.allowed_origins,
        &request_context.request_id,
    ) {
        return Err(response);
    }
    if let Some(response) = validate_post_accept(headers, &request_context.request_id) {
        return Err(response);
    }
    // `validate_post_accept` admits a client that advertised only
    // `application/json`; this is the other half of that policy — such a client
    // gets the inline-JSON shape at every optional SSE upgrade.
    let client_accepts_sse = post_accepts_sse(headers);
    if let Some(response) = validate_post_content_type(headers, &request_context.request_id) {
        return Err(response);
    }
    Ok(client_accepts_sse)
}

/// POST handler for the MCP endpoint. Flow: parse JSON body -> validate headers
/// (origin, accept, content-type, protocol version) -> parse client message ->
/// route to runtime -> either stream via SSE or return JSON-RPC directly.
/// Batch arrays are rejected; only single JSON-RPC messages are accepted.
async fn mcp_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    // `ConnectInfo` rides the request extensions on BOTH serve paths (axum's
    // `into_make_service_with_connect_info` on plain HTTP; `McpgTlsAcceptor`'s
    // inject shim on TLS), so extract it as an optional Extension — the same
    // shape as `TlsInfoExt`. (`Option<ConnectInfo<…>>` itself doesn't satisfy
    // axum 0.8's `OptionalFromRequestParts`.) Absent in `oneshot` tests.
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    body: Bytes,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let peer_ip = peer.as_ref().map(|ext| ext.0.0.ip());
    let mut request_context = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &method,
        Some(
            original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        ),
        peer_ip,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    let client_accepts_sse = match mcp_post_preflight(&headers, &config, peer, &request_context) {
        Ok(accepts_sse) => accepts_sse,
        Err(rejection) => return rejection,
    };

    let body: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(parse_err) => {
            let error = crate::protocol::ProtocolError::parse_error(format!(
                "Failed to parse the request body as JSON: {parse_err}"
            ));
            // The only exit with no body to negotiate against.
            return WireVersion::from_headers(&runtime, &headers).apply_protocol_version_header(
                map_protocol_error_response(error, &request_context.request_id),
            );
        }
    };

    // Single wire-negotiation point. Everything below — the two dispatch
    // paths, the response framing, and the version header on every exit —
    // reads this. The idempotency lift only touches `params._meta`, so
    // negotiating before it sees the same method the dispatch will.
    let Negotiated {
        wire,
        modern_handler,
    } = WireVersion::negotiate(&runtime, &headers, &body);

    // SEP-2133 `dev.mcpg/idempotency` HTTP-transport header lift.
    // When the caller supplies the conventional RFC
    // `Idempotency-Key` HTTP header AND the body's
    // `params._meta["dev.mcpg/idempotency-key"]` field is absent,
    // promote the header value into `_meta` so the downstream
    // dispatcher can dedupe over a stdio/HTTP-uniform code path.
    // The explicit `_meta` field always wins on conflict
    // (Stripe-style precedence, design doc §1.4).
    let body = match lift_idempotency_key_header(body, &headers, &request_context.request_id) {
        Ok(v) => v,
        Err(resp) => return wire.apply_protocol_version_header(resp),
    };

    // Per MCP 2025-11-25 transport: an explicit invalid or unsupported
    // `Mcp-Protocol-Version` header MUST cause HTTP 400. Absent headers are allowed;
    // the runtime will fall back to the negotiated session version or the single
    // supported revision. The gate also accepts the modern wire strings
    // (DRAFT-2026-v1 / 2026-07-28) — registry-driven dispatch picks the
    // right handler below.
    //
    // Pass the body's `id` through so the resulting JSON-RPC error
    // envelope echoes it back (SEP-2575 says all error responses
    // carry the request id; otherwise the client can't correlate).
    let body_id_for_errors = body.as_object().and_then(|obj| obj.get("id")).cloned();
    if let Err(response) =
        enforce_http_protocol_version_header(&headers, body_id_for_errors.as_ref())
    {
        return response;
    }

    // MCP 2025-11-25: POST body MUST be a single JSON-RPC request, notification, or response.
    // JSON-RPC batch arrays were removed from the spec in 2025-06-18 and are rejected.
    if body.is_array() {
        return wire.apply_protocol_version_header(map_protocol_error_response(
            ProtocolError::invalid_request(
                "JSON-RPC batch arrays are not supported; POST a single JSON-RPC message",
            ),
            &request_context.request_id,
        ));
    }

    // (SEP-414 draft): if the request body carries
    // `params._meta.traceparent` and the transport layer did not see a
    // W3C header, promote the in-band value to the request's trace
    // context so spans correlate.
    if request_context.trace_context.is_none()
        && let Some(body_meta_tc) = body
            .get("params")
            .and_then(|p| p.get("_meta"))
            .and_then(crate::transports::TraceContext::from_meta_object)
    {
        request_context = request_context.with_trace_context(Some(body_meta_tc));
    }

    // Session-owner binding on the main dispatch path. The control was
    // applied to GET / DELETE / subscribe / continuation but not here, so a
    // caller presenting someone else's `Mcp-Session-Id` reached the session's
    // tasks, cached idempotent results and subscriptions through an ordinary
    // POST — the task store compares `record.session_id` only, and has no
    // notion of who owns that session. Not-found-style on mismatch so the
    // session's existence is not leaked, matching the GET path.
    if let Some(ref sid) = request_context.session_id
        && !runtime.caller_owns_session(sid, &request_context)
    {
        return with_request_id_header(
            axum::http::StatusCode::NOT_FOUND.into_response(),
            &request_context.request_id,
        );
    }

    // A modern request routes through the registry-driven path
    // (`handler.parse` → `handler.dispatch` via
    // `runtime.handle_protocol_message`); a legacy one stays on
    // `parse_client_message` + `map_client_message_to_operation`.
    let dispatch = if let Some(handler) = modern_handler {
        dispatch_modern(
            &state,
            &runtime,
            &config,
            handler,
            &headers,
            body,
            &request_context,
            wire,
        )
        .await
    } else {
        dispatch_legacy(&runtime, &config, body, &mut request_context).await
    };
    let dispatch = match dispatch {
        Dispatch::Dispatched(outcome) => outcome,
        Dispatch::Complete(response) => return response,
    };

    finish_response(
        &state,
        &runtime,
        &config,
        &request_context,
        wire,
        client_accepts_sse,
        dispatch,
    )
    .await
}

/// A request's dispatch either produced a runtime result the response tail has
/// to shape, or produced the whole response itself (a rejection, or the
/// long-lived `subscriptions/listen` stream, which does not fit the finite
/// parse → dispatch shape).
enum Dispatch {
    Dispatched(DispatchOutcome),
    Complete(Response),
}

/// What the response tail needs from whichever wire dispatched.
struct DispatchOutcome {
    response: Result<GatewayResponse, ProtocolError>,
    /// Stream the result onto the session's SSE channel. Legacy only — the
    /// modern wire never uses the long-lived channel for `tools/call`
    /// responses.
    should_stream_response: bool,
    /// The synthetic session a modern `tools/call` ran under, so the tail can
    /// drain that request's own `notifications/progress` +
    /// `notifications/message` and, when any were produced, reframe the
    /// buffered JSON result as a per-request SSE stream. `None` on every other
    /// method and on the legacy wire.
    modern_tools_call_session: Option<String>,
}

/// Modern (`2026-07-28`) dispatch: transport-header validation, the synthetic
/// session, then `handler.parse` → `runtime.handle_protocol_message`.
#[allow(clippy::too_many_arguments)]
async fn dispatch_modern(
    state: &AppState,
    runtime: &crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    handler: std::sync::Arc<dyn crate::protocol::shared::traits::ProtocolHandler>,
    headers: &HeaderMap,
    body: Value,
    request_context: &RequestContext,
    wire: WireVersion,
) -> Dispatch {
    let mut modern_tools_call_session: Option<String> = None;
    // SEP-2243 transport-level header validation (handler decides).
    if let Err(rejection) = handler.validate_transport_headers(headers, &body) {
        return Dispatch::Complete(wire.apply_protocol_version_header(map_transport_rejection(
            rejection,
            &request_context.request_id,
        )));
    }
    // TOOLS-09 (opt-in): when the operator enables
    // `server.enforce_modern_request_meta`, require the SEP-2575
    // per-request `_meta` identity triple on every id-bearing
    // modern method, not just `server/discover`. Default off so
    // existing modern clients are unaffected.
    if config.gateway.server.enforce_modern_request_meta
        && let Some(rejection) =
            crate::protocol::v_2026_07_28::wire::enforce_request_meta_triple(&body)
    {
        return Dispatch::Complete(wire.apply_protocol_version_header(map_transport_rejection(
            rejection,
            &request_context.request_id,
        )));
    }
    // Stamp the negotiated version onto the request context so
    // version-aware code paths inside `handle_protocol_operation`
    // (e.g., MRTR's `InputRequiredResult` vs the legacy SSE+202
    // suspension envelope) can branch on it.
    let mut stamped_context = request_context
        .clone()
        .with_negotiated_version(handler.version());

    // SEP-2567/2575: the modern wire has no protocol-level
    // sessions. A 2026-07-28 server MUST IGNORE any inbound
    // `Mcp-Session-Id` (and the resume cursor it would key); the
    // synthetic operational session is derived internally from the
    // principal by `ensure_modern_session`, not adopted from a
    // client-supplied header. Clearing it here also forces the
    // synthetic mint instead of trusting a forged/foreign id.
    stamped_context.session_id = None;
    stamped_context.resume_cursor = None;

    // SEP-2575 stateless: extract the per-request
    // `_meta.io.modelcontextprotocol/clientCapabilities` from the
    // request body and stash it on the context. The runtime's
    // `client_capabilities_for_context` consults this BEFORE the
    // session-bound caps, so suspending pipeline steps (elicitation /
    // sampling / roots) gate correctly on modern stateless traffic
    // where the synthetic session itself carries empty caps.
    if let Some(caps_value) = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("io.modelcontextprotocol/clientCapabilities"))
    {
        match serde_json::from_value::<crate::protocol::ClientCapabilities>(caps_value.clone()) {
            Ok(typed_caps) => {
                stamped_context = stamped_context.with_modern_request_capabilities(typed_caps);
            }
            Err(error) => {
                tracing::warn!(
                    request_id = stamped_context.request_id.as_str(),
                    error = %error,
                    "failed to deserialize modern _meta clientCapabilities"
                );
            }
        }
    }

    // Modern stateless mode. When a modern request arrives
    // without an `Mcp-Session-Id`, mint an ephemeral operational
    // session so the legacy session-requiring dispatch paths
    // still work. Pass-through when the client does supply a
    // session header (e.g., across the migration). A store that
    // refuses the row (`sessions.max_sessions`) is answered with
    // explicit backpressure rather than a dispatch that would
    // fail against a never-stored session.
    let stamped_context = match runtime.ensure_modern_session(&stamped_context) {
        crate::runtime::ModernSessionOutcome::Ready(ctx) => ctx,
        crate::runtime::ModernSessionOutcome::CapacityExhausted => {
            return Dispatch::Complete(wire.apply_protocol_version_header(
                map_transport_rejection(
                    crate::protocol::shared::messages::TransportRejection {
                        status: 503,
                        error_code: -32000,
                        message: "session capacity exhausted; retry later".to_owned(),
                        data: None,
                        jsonrpc_id: body.get("id").cloned(),
                    },
                    &stamped_context.request_id,
                ),
            ));
        }
    };
    // The ephemeral (row-less) session id this request runs under,
    // if any — continuations materialize the real row post-dispatch.
    let modern_ephemeral_session = if stamped_context.session_ephemeral {
        stamped_context.session_id.clone()
    } else {
        None
    };

    // `subscriptions/listen` is a long-lived POST-SSE response
    // that cannot fit in the finite `handler.parse` +
    // `handler.dispatch` shape. Intercept BEFORE parse and route
    // to the dedicated streaming handler. The stream outlives the
    // request, so an ephemeral session materializes its row first
    // (session lifecycle then belongs to the TTL reaper, exactly
    // as for a stored synthetic session).
    if body.get("method").and_then(serde_json::Value::as_str) == Some("subscriptions/listen") {
        if let Some(sid) = modern_ephemeral_session.as_deref() {
            runtime.materialize_ephemeral_session(sid);
        }
        return Dispatch::Complete(
            modern_subscriptions_listen_handler(state.clone(), stamped_context, body).await,
        );
    }

    // RPN-4: remember the synthetic session id this `tools/call`
    // runs under so the post-dispatch step can drain the request's
    // own progress/log notifications from it. Captured BEFORE
    // `handle_protocol_message` consumes `stamped_context`.
    if body.get("method").and_then(serde_json::Value::as_str) == Some("tools/call") {
        modern_tools_call_session = stamped_context.session_id.clone();
    }

    let resp = match handler.parse(body) {
        Ok(message) => Ok(runtime
            .handle_protocol_message(stamped_context, message)
            .await),
        Err(error) => Err(error),
    };
    // An ephemeral session has no store row. When the response hands
    // the client a continuation (`resultType` `task` /
    // `input_required` — a background task keeps delivering into the
    // session; a suspended MRTR resumes against it), materialize the
    // row now so the continuation behaves exactly like one under a
    // stored synthetic session. A terminal response needs nothing:
    // the id was never revealed on the wire (and inbound
    // `Mcp-Session-Id` is ignored on this wire), so the request
    // leaves zero session-store state behind. The RPN-4 drain below
    // only needs the id string; pending deliveries live in the
    // pipeline store, not the session row.
    if let Some(sid) = modern_ephemeral_session.as_deref() {
        let hands_continuation = matches!(
            &resp,
            Ok(response) if matches!(
                &response.payload,
                GatewayResponsePayload::Protocol(p)
                    if p.http_status == 200
                        && matches!(
                            &p.response,
                            ProtocolResponse::JsonRpcSuccess(s)
                                if matches!(
                                    s.result.get("resultType").and_then(serde_json::Value::as_str),
                                    Some("task") | Some("input_required")
                                )
                        )
            )
        );
        if hands_continuation {
            runtime.materialize_ephemeral_session(sid);
        }
    }
    // Modern wire never uses the long-lived SSE channel for
    // tools/call responses — MRTR carries `InputRequiredResult`
    // inline, server-initiated requests go through
    // `subscriptions/listen`, and the per-request response stream
    // (RPN-4) is handled by the dedicated post-dispatch branch
    // below rather than this legacy `should_stream` flag.
    Dispatch::Dispatched(DispatchOutcome {
        response: resp,
        should_stream_response: false,
        modern_tools_call_session,
    })
}

/// Legacy (`2025-11-25`) dispatch: parse the client message, apply the
/// `sessions.optional` ephemeral lane, then `runtime.handle_request`.
async fn dispatch_legacy(
    runtime: &crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    body: Value,
    request_context: &mut RequestContext,
) -> Dispatch {
    let client_message = match parse_client_message(body) {
        Ok(message) => message,
        Err(error) => {
            return Dispatch::Complete(map_protocol_error_response(
                error,
                &request_context.request_id,
            ));
        }
    };

    // `sessions.optional`: a legacy request that arrives without a
    // session header for a session-requiring method rides the same
    // ephemeral (row-less) lane the modern wire uses, instead of the
    // `-32600` "missing session" rejection. `initialize` still mints
    // a real session, and a request that supplied a session id keeps
    // the stored path. The ephemeral snapshot pins the request's own
    // (legacy) negotiated version.
    let is_non_initialize_request = matches!(
        client_message,
        crate::protocol::ClientMessage::Request(ref request) if request.method != "initialize"
    );
    if config.mcp.configurations.sessions.optional
        && request_context.session_id.is_none()
        && is_non_initialize_request
    {
        let snapshot = crate::runtime::GatewayRuntime::ephemeral_session_snapshot_for(
            request_context.negotiated_version.as_str(),
        );
        *request_context = request_context.clone().with_ephemeral_session(snapshot);
    }

    // Stream onto the session's SSE channel only for a request bound
    // to a REAL (stored) session; an ephemeral session has no channel,
    // so it answers with inline JSON (the `unary_json_fast_path`
    // shape), interleaving any emitted notifications as one-shot SSE
    // frames via the pending-delivery path below.
    let should_stream = is_non_initialize_request
        && request_context.session_id.is_some()
        && !request_context.session_ephemeral;

    let resp = match map_client_message_to_operation(client_message) {
        Ok(operation) => {
            let request = GatewayRequest::new(
                request_context.clone(),
                GatewayOperation::Protocol(operation),
            );
            Ok(runtime.handle_request(request).await)
        }
        Err(e) => Err(e),
    };
    Dispatch::Dispatched(DispatchOutcome {
        response: resp,
        should_stream_response: should_stream,
        modern_tools_call_session: None,
    })
}

/// Shape the dispatched result into the HTTP response: the modern per-request
/// SSE stream, the ephemeral/unary inline-JSON fast paths, the legacy session
/// SSE channel, or the POST-continuation upgrade — in that order, which is the
/// order they were written in and the order their conditions assume.
async fn finish_response(
    state: &AppState,
    runtime: &crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    request_context: &RequestContext,
    wire: WireVersion,
    client_accepts_sse: bool,
    dispatch: DispatchOutcome,
) -> Response {
    let DispatchOutcome {
        response,
        should_stream_response,
        modern_tools_call_session,
    } = dispatch;
    let auth_enabled = config.governance.access.is_enabled();
    // SEP-2567/2575: a 2026-07-28 server MUST NOT surface `Mcp-Session-Id`
    // on the wire. The synthetic operational session still exists
    // internally (clustering / MRTR resume / delivery re-keying) but is
    // never echoed on a modern response. Legacy (`2025-11-25`) keeps the
    // session header byte-identical.
    let session_id_for_header = if wire.is_modern() {
        None
    } else {
        request_context.session_id.clone()
    };

    match response {
        Ok(response) => {
            // RPN-4: per-request SSE response stream for a modern
            // (`2026-07-28`) `tools/call`. The spec's preferred shape is
            // a POST that returns `text/event-stream` carrying this
            // request's own `notifications/progress` +
            // `notifications/message`, terminated by the JSON-RPC
            // result. We take it ONLY when the tool/pipeline actually
            // emitted such notifications for this request (drained from
            // the request's synthetic session); a tool that emits
            // nothing keeps the inline single-response fast path. The
            // MRTR suspend (`resultType:"input_required"`) and task
            // materialization (`resultType:"task"`) shapes are excluded
            // — only a terminal `resultType:"complete"` is streamable —
            // so suspend/resume + task surfaces are untouched.
            if client_accepts_sse
                && let Some(session_id) = modern_tools_call_session.as_deref()
                && let GatewayResponsePayload::Protocol(protocol_http_response) = &response.payload
                && protocol_http_response.http_status == 200
                && let ProtocolResponse::JsonRpcSuccess(success) = &protocol_http_response.response
                && wire_policy::modern_result_is_streamable_complete(&success.result)
            {
                let pending = runtime.take_pending_deliveries(session_id);
                if !pending.is_empty() {
                    let frames: Vec<String> = pending
                        .into_iter()
                        .map(|msg| msg.jsonrpc_message.to_string())
                        .chain(std::iter::once(
                            serde_json::to_value(success)
                                .map(|v| v.to_string())
                                .unwrap_or_default(),
                        ))
                        .collect();
                    // No `Mcp-Session-Id` (TS-09) and no SSE event ids
                    // (TS-11) on the modern wire. The terminal frame is
                    // the JSON-RPC response; the stream then closes.
                    return wire.apply_protocol_version_header(with_request_id_header(
                        wire_policy::map_modern_response_stream(frames),
                        &response.request_id,
                    ));
                }
                // Pending empty ⇒ fall through to the inline JSON path.
            }
            // Ephemeral-session (`sessions.optional`) legacy request: it
            // has no stored session, so no SSE replay channel exists —
            // answer with inline JSON. If the tool/pipeline emitted
            // per-request notifications, deliver them as one-shot SSE
            // frames (store-free, non-resumable) terminated by the
            // result, mirroring the modern ephemeral shape. Draining also
            // keeps the pipeline store from retaining deliveries for a
            // session id with no reaping row.
            if client_accepts_sse
                && request_context.session_ephemeral
                && let Some(session_id) = request_context.session_id.as_deref()
                && let GatewayResponsePayload::Protocol(p) = &response.payload
                && p.http_status == 200
                && let ProtocolResponse::JsonRpcSuccess(success) = &p.response
            {
                let pending = runtime.take_pending_deliveries(session_id);
                if pending.is_empty() {
                    let resp = with_www_authenticate_challenge(
                        map_gateway_response(response),
                        auth_enabled,
                        &resource_metadata_url(config),
                    );
                    return resp;
                }
                let frames: Vec<String> = pending
                    .into_iter()
                    .map(|m| m.jsonrpc_message.to_string())
                    .chain(std::iter::once(
                        serde_json::to_value(success)
                            .map(|v| v.to_string())
                            .unwrap_or_default(),
                    ))
                    .collect();
                return with_request_id_header(
                    wire_policy::map_modern_response_stream(frames),
                    &response.request_id,
                );
            }
            // Legacy inline-JSON fast path (opt-in via
            // `server.unary_json_fast_path`): a unary 200 result that emitted
            // no server→client notifications answers with a single
            // application/json body instead of a one-frame SSE stream. This
            // skips the per-request SSE bookkeeping (replay-window append,
            // priming/logging frames, session snapshot) that otherwise runs
            // under the session lock. A request that DID emit notifications, or
            // whose stream build fails, still streams / falls back cleanly.
            if (should_stream_response || !client_accepts_sse)
                && config.gateway.server.unary_json_fast_path
                && request_context.session_id.is_some()
                && matches!(
                    &response.payload,
                    GatewayResponsePayload::Protocol(p) if p.http_status == 200
                )
            {
                let session_id = request_context.session_id.clone().unwrap();
                let pending = runtime.take_pending_deliveries(&session_id);
                if pending.is_empty() {
                    let resp = with_www_authenticate_challenge(
                        map_gateway_response(response),
                        auth_enabled,
                        &resource_metadata_url(config),
                    );
                    return with_session_id_header(resp, session_id_for_header.as_deref());
                }
                let pending_payloads: Vec<String> = pending
                    .into_iter()
                    .map(|m| m.jsonrpc_message.to_string())
                    .collect();
                let events = match &response.payload {
                    GatewayResponsePayload::Protocol(p) => runtime
                        .stream_protocol_response_with_pending(
                            &session_id,
                            &p.response,
                            &pending_payloads,
                        )
                        .ok(),
                    _ => None,
                };
                let resp = match events {
                    Some(events) => {
                        with_request_id_header(map_sse_events(events), &response.request_id)
                    }
                    None => with_www_authenticate_challenge(
                        map_gateway_response(response),
                        auth_enabled,
                        &resource_metadata_url(config),
                    ),
                };
                return with_session_id_header(resp, session_id_for_header.as_deref());
            }
            if should_stream_response
                && let GatewayResponsePayload::Protocol(protocol_http_response) = &response.payload
            {
                // Case 1: runtime produced an immediate JSON-RPC result.
                // Stream it so the POST response lands on the session's SSE
                // channel — but only for a client that admitted
                // `text/event-stream`. A JSON-only client falls through to the
                // inline body below, which is the whole point of admitting it
                // in `validate_post_accept`.
                if client_accepts_sse
                    && protocol_http_response.http_status == 200
                    && let Some(session_id) = request_context.session_id.as_deref()
                {
                    // Drain any pipeline-emitted notifications (`log` /
                    // `progress` steps) and interleave them between the
                    // priming/logging events and the terminal response so the
                    // client matches them to the in-flight request.
                    let pending = runtime.take_pending_deliveries(session_id);
                    let pending_payloads: Vec<String> = pending
                        .into_iter()
                        .map(|msg| msg.jsonrpc_message.to_string())
                        .collect();
                    if let Ok(events) = runtime.stream_protocol_response_with_pending(
                        session_id,
                        &protocol_http_response.response,
                        &pending_payloads,
                    ) {
                        let sse_response =
                            with_request_id_header(map_sse_events(events), &response.request_id);
                        return with_session_id_header(
                            sse_response,
                            session_id_for_header.as_deref(),
                        );
                    }
                }

                // Case 2: runtime suspended the pipeline and queued a
                // server-initiated request. MCP 2025-11-25 forbids returning
                // `202` with an empty body for a POSTed JSON-RPC request — the
                // canonical continuation is an SSE stream on the same POST.
                //
                // We open SSE here and subscribe the client to the session's
                // delivery bus so it receives the pending server request and,
                // once the pipeline resumes, the eventual terminal JSON-RPC
                // response.
                //
                // This is the one upgrade that cannot honour a JSON-only
                // `Accept`: there is no result to inline yet, and the spec
                // forbids the empty-202 alternative. A client that reaches a
                // suspending pipeline has to speak SSE.
                if protocol_http_response.http_status == 202
                    && matches!(
                        protocol_http_response.response,
                        ProtocolResponse::NotificationAccepted
                    )
                    && let Some(session_id) = request_context.session_id.clone()
                {
                    // Session-owner binding: only the creator may upgrade a
                    // suspended POST to a continuation SSE on the session.
                    if !state
                        .runtime
                        .load()
                        .caller_owns_session(&session_id, request_context)
                    {
                        return with_request_id_header(
                            axum::http::StatusCode::NOT_FOUND.into_response(),
                            &request_context.request_id,
                        );
                    }
                    let sse_response =
                        open_post_continuation_sse(state, &session_id, &request_context.request_id)
                            .await;
                    return with_session_id_header(sse_response, session_id_for_header.as_deref());
                }
            }
            let resp = with_www_authenticate_challenge(
                map_gateway_response(response),
                auth_enabled,
                &resource_metadata_url(config),
            );
            let resp = with_session_id_header(resp, session_id_for_header.as_deref());
            wire.apply_protocol_version_header(resp)
        }
        Err(error) => {
            // SEP-2575 modern stateless: any method-not-found
            // returns HTTP 404 + JSON-RPC `-32601`. Legacy keeps
            // the historical HTTP 200 behaviour. `modern_handler`
            // was set above when the registry picked the modern
            // version — use that rather than the request_context,
            // because the outer `request_context` here still
            // carries its default `negotiated_version` (the
            // stamped one is local to the modern arm above).
            let resp = if wire.is_modern() && error.code() == crate::protocol::METHOD_NOT_FOUND_CODE
            {
                map_protocol_error_with_status(
                    error,
                    axum::http::StatusCode::NOT_FOUND,
                    &request_context.request_id,
                )
            } else {
                map_protocol_error_response(error, &request_context.request_id)
            };
            let resp = with_session_id_header(resp, session_id_for_header.as_deref());
            wire.apply_protocol_version_header(resp)
        }
    }
}

async fn modern_subscriptions_listen_handler(
    state: AppState,
    request_context: crate::runtime::RequestContext,
    body: Value,
) -> Response {
    use crate::protocol::v_2026_07_28::wire::subscriptions::{self, SubscriptionsListenParams};
    use axum::http::StatusCode;
    // `iter` and `ReceiverStream` are already imported at the
    // top of this module (re-used by mcp_get_handler).

    let request_id_value = body.get("id").cloned().unwrap_or(Value::Null);

    // Parse params.
    let Some(params_value) = body.get("params").cloned() else {
        return map_protocol_error_response(
            ProtocolError::invalid_params(
                Some(request_id_value),
                "missing subscriptions/listen params",
                None,
            ),
            &request_context.request_id,
        );
    };
    let params: SubscriptionsListenParams = match serde_json::from_value(params_value) {
        Ok(p) => p,
        Err(error) => {
            return map_protocol_error_response(
                ProtocolError::invalid_params(
                    Some(request_id_value),
                    format!("invalid subscriptions/listen params: {error}"),
                    None,
                ),
                &request_context.request_id,
            );
        }
    };

    // SEP-2567/2575: the modern wire has no protocol-level sessions
    // and no `Mcp-Session-Id` requirement. Subscriptions are keyed
    // client-facing by the listen request's JSON-RPC id (the
    // `subscriptionId` below); the server-internal synthetic session
    // (principal-derived, minted by `ensure_modern_session`) is what
    // the cross-instance delivery bus keys on — it always resolves on
    // the modern path, so no hard session requirement is imposed on
    // the client. If the synthetic minter ever failed, the delivery
    // bus simply has nothing to subscribe to and the stream carries
    // only the ack + the eventual graceful close.
    let session_id = request_context.session_id.clone();

    // Concurrent-SSE-slot reservation; released when the stream below is
    // dropped (client disconnect / completion). Held here through the
    // stream build so an early return still releases it via Drop.
    let mut sse_slot: Option<SseStreamSlot> = None;

    // Session-owner binding + per-session SSE cap only apply when an
    // internal synthetic session backs the delivery bus (the normal
    // modern path). These guards protect the server-internal bus; they
    // are never surfaced on the wire.
    if let Some(ref sid) = session_id {
        // Only the creator may subscribe to the session's server-push
        // delivery bus. Checked before the SSE counter so a foreign
        // caller cannot inflate the victim's count.
        if !state
            .runtime
            .load()
            .caller_owns_session(sid, &request_context)
        {
            return with_request_id_header(
                StatusCode::NOT_FOUND.into_response(),
                &request_context.request_id,
            );
        }

        // Reserve a concurrent SSE slot — same backstop the legacy GET /mcp
        // handler uses. The guard releases the slot when the stream is dropped.
        match acquire_sse_slot(&state.sse_stream_counts, sid) {
            Some(slot) => sse_slot = Some(slot),
            None => {
                metrics::counter!(
                    "mcpg_sse_stream_limit_rejected_total",
                    "session_id" => sid.clone(),
                )
                .increment(1);
                return with_request_id_header(
                    StatusCode::TOO_MANY_REQUESTS.into_response(),
                    &request_context.request_id,
                );
            }
        }
    }

    // SEP-2567/2575/RES-07: the client-facing subscription id is the
    // listen request's JSON-RPC id, NOT a fresh UUID — this is the
    // stdio correlation contract. String ids pass through verbatim;
    // numeric/other ids use their canonical JSON rendering.
    let subscription_id = match &request_id_value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    metrics::counter!("mcpg_subscriptions_listen_opened_total").increment(1);

    let runtime = state.runtime.load();

    // `resources/updated` targets are a real subscription, not just a
    // filter: something has to tell the watch engine this URI is being
    // watched or no update event is ever produced to filter. Register them
    // the way the legacy `resources/subscribe` arm does — the guard
    // unsubscribes when the stream ends, which is the modern wire's
    // equivalent of `resources/unsubscribe`.
    //
    // Registration runs BEFORE the ack is built, because the ack reports what
    // was established: a URI no resource route resolves, or one the store
    // rejected, is not a subscription and must not be acked as one.
    let watched_resources: Vec<String> = params
        .subscriptions
        .iter()
        .filter_map(|target| match target {
            subscriptions::SubscriptionTarget::ResourcesUpdated { uri } => Some(uri.clone()),
            _ => None,
        })
        .collect();
    let mut resource_subscriptions: Option<ResourceSubscriptionGuard> = None;
    if let Some(ref sid) = session_id
        && !watched_resources.is_empty()
    {
        resource_subscriptions = Some(
            register_modern_resource_subscriptions(
                &runtime,
                sid,
                &request_context,
                &watched_resources,
            )
            .await,
        );
    }

    // SEP-2575 ack contract: the FIRST frame on a
    // `subscriptions/listen` stream is the
    // `notifications/subscriptions/acknowledged` notification
    // carrying the subscription id (= the listen request's JSON-RPC
    // id) and the honored-subset `notifications` object. Subsequent
    // frames are the live notifications matched against the
    // subscriber's target list, each tagged with the same id under
    // `_meta.io.modelcontextprotocol/subscriptionId`. The JSON-RPC
    // response envelope for the `subscriptions/listen` request itself
    // rides immediately after the ack so the client's
    // request-correlator can still resolve the call.
    let established = resource_subscriptions
        .as_ref()
        .map(ResourceSubscriptionGuard::established)
        .unwrap_or_default();
    let honored = params.honored_notifications(&established);
    let ack_payload = subscriptions::acknowledged_notification(&subscription_id, &honored);
    let response_payload =
        subscriptions::listen_response_envelope(&request_id_value, &subscription_id, &honored);
    // SEP-2575 removes SSE resumability on the modern wire — no event
    // IDs are assigned, so a dropped stream cannot be resumed via
    // `Last-Event-ID` (the client re-issues `subscriptions/listen`).
    let ack_event: Result<Event, Infallible> = Ok(Event::default()
        .event("message")
        .data(ack_payload.to_string()));
    let response_event: Result<Event, Infallible> = Ok(Event::default()
        .event("message")
        .data(response_payload.to_string()));

    // Live event stream: subscribe to the server-internal (synthetic)
    // session delivery bus, filter by subscription targets, stamp the
    // client-facing subscriptionId on each. The bus is keyed on the
    // synthetic session (cross-instance), which is decoupled from the
    // wire-facing subscriptionId above.
    let subscription_targets = std::sync::Arc::new(params.subscriptions);
    let sub_id_for_filter = subscription_id.clone();
    let live: std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>,
    > = if let Some(ref sid) = session_id {
        Box::pin(
            delivery_bus_sse(&runtime, sid, move |msg| {
                // Each `DeliveryMessage.jsonrpc_message` is a JSON-RPC
                // notification. Match it against the subscriber's target
                // list; mutate to inject `_meta.subscriptionId`.
                let mut payload = msg.jsonrpc_message;
                let method = payload
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if !subscriptions::subscription_matches(&subscription_targets, &method, &payload) {
                    return None;
                }
                subscriptions::inject_subscription_id_meta(&mut payload, &sub_id_for_filter);
                Some(Ok(Event::default()
                    .event("message")
                    .data(payload.to_string())))
            })
            .await,
        )
    } else {
        Box::pin(tokio_stream::empty())
    };

    // RES-09: graceful terminal frame. When the delivery bus closes
    // (server shutdown / session teardown) the live stream ends; emit
    // a final `resultType:"complete"` frame correlated to the listen
    // request so the client sees an orderly close rather than a bare
    // socket drop.
    let close_payload = subscriptions::complete_notification(&subscription_id);
    let close_event: Result<Event, Infallible> = Ok(Event::default()
        .event("message")
        .data(close_payload.to_string()));

    let priming = iter(vec![ack_event, response_event]);
    let merged = priming.chain(live).chain(iter(vec![close_event]));
    let guarded = SlottedEventStream {
        inner: Box::pin(merged),
        _slot: sse_slot,
        _resource_subscriptions: resource_subscriptions,
    };
    let response = Sse::new(guarded)
        .keep_alive(KeepAlive::default())
        .into_response();
    // SEP-2567/2575: never echo `Mcp-Session-Id` on the modern wire.
    with_request_id_header(response, &request_context.request_id)
}

async fn mcp_get_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let request_context = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &method,
        Some(
            original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        ),
        peer.as_ref().map(|ext| ext.0.0.ip()),
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    if let Some(response) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_context.request_id,
    ) {
        return response;
    }
    // SEP-2575: a 2026-07-28 server has no server-push GET stream
    // (`subscriptions/listen` over POST replaces it) — answer 405.
    // Legacy GET (SSE delivery) is unchanged.
    if let Some(response) =
        reject_method_on_modern_wire(&runtime, &headers, &request_context.request_id)
    {
        return response;
    }
    if let Some(response) = validate_get_accept(&headers, &request_context.request_id) {
        return response;
    }
    if let Err(response) = enforce_http_protocol_version_header(&headers, None) {
        return response;
    }
    // Session-owner binding: only the session's creator may drain its
    // server-push stream. Checked before the per-session stream counter so
    // a foreign caller cannot inflate the victim's count. Not-found-style
    // on mismatch so existence isn't leaked.
    if let Some(ref sid) = request_context.session_id
        && !runtime.caller_owns_session(sid, &request_context)
    {
        return with_request_id_header(
            axum::http::StatusCode::NOT_FOUND.into_response(),
            &request_context.request_id,
        );
    }
    // Reserve one of the session's concurrent SSE slots; the guard releases
    // it when the stream below is dropped (client disconnect / completion).
    let mut sse_slot: Option<SseStreamSlot> = None;
    if let Some(ref sid) = request_context.session_id {
        match acquire_sse_slot(&state.sse_stream_counts, sid) {
            Some(slot) => sse_slot = Some(slot),
            None => {
                metrics::counter!(
                    "mcpg_sse_stream_limit_rejected_total",
                    "session_id" => sid.clone(),
                )
                .increment(1);
                return with_request_id_header(
                    axum::http::StatusCode::TOO_MANY_REQUESTS.into_response(),
                    &request_context.request_id,
                );
            }
        }
    }

    match runtime.open_sse_stream(&request_context) {
        Ok(events) => {
            let session_id = request_context.session_id.clone();

            // Order matters for cross-replica delivery (continuation SSE).
            // A terminal result published by a peer between the backlog drain
            // and the live subscribe would be lost on BOTH paths: too late for
            // the drain (its KV row is written after the drain reads), dropped
            // on the bus (no subscriber yet). So SUBSCRIBE FIRST, then drain.
            //
            // Subscribing first reopens a different hazard: a delivery that is
            // both still in the backlog AND replayed on the live bus would be
            // delivered twice. We dedupe by content key: every drained message
            // is recorded, and the first matching live event is suppressed
            // (the duplicate is the same logical delivery). The dedupe set
            // covers only the brief startup overlap, after which live events
            // are never in the (already-drained) backlog.
            if let Some(ref sid) = session_id {
                // 0. Reconnect ack-prune: if the client reconnects
                //    echoing a delivery-tagged Last-Event-Id, it has PROVEN it
                //    received that backlog row (live or replayed). Delete it
                //    from the coordinator-KV backlog BEFORE draining so an
                //    already-delivered server-push is not replayed. Only the
                //    exact acknowledged row is removed — never an unseen one —
                //    so this cannot drop a result.
                if let Some(ref cursor) = request_context.resume_cursor {
                    runtime.ack_delivery_from_cursor(sid, &cursor.last_event_id);
                }

                // 1. Subscribe to the live delivery bus FIRST so nothing
                //    published from this point on can fall through the gap.
                //    The live filter suppresses the first occurrence of any
                //    delivery whose content matches a just-drained backlog
                //    entry (the race-window duplicate). The dedupe set is
                //    shared with the filter because the helper subscribes
                //    before the step-2 drain populates it; the drain
                //    completes before any live event is polled, so the filter
                //    always sees the full set.
                let drained_keys: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u64>>> =
                    std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
                // Session store rather than the runtime — see
                // `open_post_continuation_sse`. A GET stream is the longest-lived
                // body the gateway serves, so pinning the runtime here is what
                // kept a reload from ever retiring the old one.
                let store = state.session_store.clone();
                let sid_owned = sid.clone();
                let filter_keys = std::sync::Arc::clone(&drained_keys);
                let live = delivery_bus_sse(&runtime, sid, move |msg| {
                    let key = delivery_dedupe_key(&msg);
                    if filter_keys.lock().expect("drained-keys lock").remove(&key) {
                        // Same delivery already emitted from the backlog drain.
                        None
                    } else {
                        delivery_to_sse_event(&store, &sid_owned, msg)
                    }
                })
                .await;

                // 2. Drain the persisted backlog and assign replay event ids.
                let pending = runtime.take_pending_deliveries(sid);
                let mut sse_records = Vec::new();
                {
                    let mut keys = drained_keys.lock().expect("drained-keys lock");
                    for msg in pending {
                        keys.insert(delivery_dedupe_key(&msg));
                        if let Ok(records) = runtime.stream_delivery_message(
                            sid,
                            &msg.jsonrpc_message.to_string(),
                            &msg.delivery_id,
                        ) {
                            sse_records.extend(records);
                        }
                    }
                }

                // 3. Build the initial stream (replay/priming + drained backlog).
                let initial = iter(
                    events
                        .into_iter()
                        .chain(sse_records)
                        .map(sse_event_from_record),
                );

                let merged = initial.chain(live);
                let guarded = SlottedEventStream {
                    inner: Box::pin(merged),
                    _slot: sse_slot,
                    // The legacy GET stream carries no subscriptions of its
                    // own: `resources/subscribe` owns them and
                    // `resources/unsubscribe` releases them.
                    _resource_subscriptions: None,
                };
                with_session_id_header(
                    with_request_id_header(
                        Sse::new(guarded)
                            .keep_alive(KeepAlive::default())
                            .into_response(),
                        &request_context.request_id,
                    ),
                    session_id.as_deref(),
                )
            } else {
                let initial = iter(events.into_iter().map(sse_event_from_record));
                with_request_id_header(
                    Sse::new(initial)
                        .keep_alive(KeepAlive::default())
                        .into_response(),
                    &request_context.request_id,
                )
            }
        }
        Err(
            StreamAccessError::MissingSessionId
            | StreamAccessError::InvalidCursor
            | StreamAccessError::NotInitialized,
        ) => with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            &request_context.request_id,
        ),
        Err(StreamAccessError::ExpiredCursor) => with_request_id_header(
            axum::http::StatusCode::CONFLICT.into_response(),
            &request_context.request_id,
        ),
        Err(StreamAccessError::UnknownSession) => with_request_id_header(
            axum::http::StatusCode::NOT_FOUND.into_response(),
            &request_context.request_id,
        ),
    }
}

/// DELETE handler for the MCP endpoint: terminates the session and cascades
/// cleanup (session store removal, SSE stream counter pruning, tenant quota
/// release, request-id tracker eviction, progress state purge).
async fn mcp_delete_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let request_context = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &method,
        Some(
            original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        ),
        peer.as_ref().map(|ext| ext.0.0.ip()),
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    if let Some(response) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_context.request_id,
    ) {
        return response;
    }
    // SEP-2567/2575: the modern wire has no protocol-level sessions to
    // terminate — answer 405 on DELETE. Legacy DELETE (session
    // termination) is unchanged.
    if let Some(response) =
        reject_method_on_modern_wire(&runtime, &headers, &request_context.request_id)
    {
        return response;
    }
    if let Err(response) = enforce_http_protocol_version_header(&headers, None) {
        return response;
    }
    let Some(session_id) = request_context.session_id.as_deref() else {
        return with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            &request_context.request_id,
        );
    };

    // Session-owner binding: only the creator may terminate the session.
    // Not-found-style on mismatch so existence isn't leaked. The owner
    // check lives at the HTTP layer (not the runtime wrapper) so admin /
    // self-cleanup terminate paths stay unconditional.
    if !runtime.caller_owns_session(session_id, &request_context) {
        return with_request_id_header(
            axum::http::StatusCode::NOT_FOUND.into_response(),
            &request_context.request_id,
        );
    }

    let response = if runtime.terminate_session(session_id) {
        // prune SSE stream counter for terminated sessions.
        if let Ok(mut counts) = state.sse_stream_counts.lock() {
            counts.remove(session_id);
        }
        axum::http::StatusCode::NO_CONTENT.into_response()
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    };

    // The session identifier MUST be echoed on every session-scoped HTTP
    // response, DELETE included (MCP 2025-11-25 Streamable HTTP).
    let response = with_request_id_header(response, &request_context.request_id);
    with_session_id_header(response, Some(session_id))
}

#[cfg(test)]
#[path = "../http_tests.rs"]
mod tests;
