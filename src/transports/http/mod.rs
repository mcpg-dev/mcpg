//! HTTP transport — Axum router, the MCP endpoint, health/readiness probes,
//! and OAuth protected-resource metadata.
//!
//! The MCP endpoint serves MCP 2026-07-28 over `POST`: every request is
//! answered on its own response, as JSON or as an SSE stream.
//! `subscriptions/listen` and `events/stream` are POSTs answered with a
//! long-lived SSE stream. `GET`, `HEAD` and `DELETE` answer `405`.

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
use futures::FutureExt as _;
use serde::Serialize;
use serde_json::Value;
use std::convert::Infallible;
use tokio_stream::{StreamExt, iter};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::transports::dispatch::{DispatchOutcome, dispatch};
use crate::transports::listen::{ListenRefusal, open_listen};
use crate::{
    app::AppState,
    protocol::{
        METHOD_NOT_FOUND_CODE, PROTOCOL_VERSION_HEADER, ProtocolError, ProtocolHttpResponse,
        ProtocolResponse, StreamPlan,
    },
    runtime::{
        DiagnosticsOperation, GatewayRequestId, GatewayResponse, GatewayResponsePayload,
        RequestContext, RequestIdentity, TransportKind,
    },
};

/// Per-handler extractor of what the connection vouches for: the
/// `TlsInfoArc` [`crate::transports::tls::McpgTlsAcceptor`] stamps (absent on
/// plain HTTP, and on TLS with no SNI and no client cert) and the peer a
/// transport plugin attests (absent on every other path).
pub(crate) struct ConnectionExt(crate::transports::attested::ConnectionFacts);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ConnectionExt {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            crate::transports::attested::ConnectionFacts::from_extensions(&parts.extensions),
        ))
    }
}

impl ConnectionExt {
    fn into_inner(self) -> crate::transports::attested::ConnectionFacts {
        self.0
    }
}

/// The request headers, moved out of the request instead of copied. Every
/// extractor after it sees an empty map, so a handler lists it after every
/// other parts extractor.
pub(crate) struct RequestHeaders(HeaderMap);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestHeaders {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(std::mem::take(&mut parts.headers)))
    }
}

mod cors;
pub(crate) mod discovery;
mod events_stream;
mod events_webhooks;
mod identity;
mod oauth_browser;
mod personal_agent_operations;
mod probes;
mod response;
mod validate;
mod webhooks;

pub(crate) use discovery::{
    aauth_authorize_handler, aauth_jwks_handler, aauth_resource_metadata_handler,
    aauth_revoke_handler, oauth_authorization_server_metadata_handler, oauth_jwks_handler,
    oauth_protected_resource_handler, oauth_register_handler, oauth_revoke_handler,
    oauth_token_handler, poppy_document_handler, served_registry_list_handler,
    served_registry_version_handler,
};
pub(crate) use identity::{build_full_request_context, lift_idempotency_key_header};
pub(crate) use oauth_browser::{
    oauth_authorize_handler, oauth_browser_method_not_allowed, oauth_callback_handler,
    oauth_connect_decision_handler, oauth_connect_handler, oauth_consent_handler,
};
pub(crate) use probes::{health_handler, metrics_handler, readiness_handler, runtime_handler};
pub(crate) use response::{
    INSUFFICIENT_SCOPE_DATA_KEY, RETRY_AFTER_DATA_KEY, SIGN_IN_REQUIRED_DATA_KEY, challenge_scope,
    map_gateway_response, map_protocol_error_response, map_protocol_error_with_status,
    map_protocol_http_response, map_response_stream, map_transport_rejection, request_host,
    resource_metadata_url, retry_after_data, strip_internal_markers, with_protocol_version_header,
    with_request_id_header, with_resource_metadata_pointer, with_www_authenticate_challenge,
    without_internal_headers,
};
pub use validate::origin_admitted;
pub(crate) use validate::{validate_origin, validate_post_accept, validate_post_content_type};
pub(crate) use webhooks::{webhook_approval_resolution_handler, webhook_resource_updated_handler};
// Reached only from this transport's test module.
#[cfg(test)]
pub(crate) use crate::transports::listen::{SseStreamCounts, acquire_sse_slot};
#[cfg(test)]
pub(crate) use identity::{CredentialOrigin, build_request_context, plugin_identity_to_request};
#[cfg(test)]
pub(crate) use response::INSUFFICIENT_SCOPE_HEADER;

const REQUEST_ID_RESPONSE_HEADER: &str = "x-mcpg-request-id";
const UPSTREAM_REQUEST_ID_HEADER: &str = "x-request-id";
const SUBJECT_ID_HEADER: &str = "x-mcpg-subject-id";
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const JSON_ACCEPT: &str = "application/json";
const SSE_ACCEPT: &str = "text/event-stream";

/// The MCP listener: its socket, bound but not yet serving, and the TLS
/// config it serves through when `gateway.server.tls` is set.
pub struct HttpListener {
    listener: tokio::net::TcpListener,
    tls: Option<crate::transports::tls::RustlsConfig>,
}

impl HttpListener {
    /// Bind `gateway.server.bind_address`, after the TLS server config
    /// loads when TLS is configured. Fails when the address does not
    /// resolve, is in use or is not permitted, or the TLS config does not
    /// load.
    pub async fn bind(config: &crate::config::AppConfig) -> Result<Self> {
        let server = &config.gateway.server;
        let tls = match &server.tls {
            // A pre-built rustls ServerConfig carries the mTLS client
            // verifier and the ALPN list, which axum-server's PEM loaders
            // do not expose.
            Some(tls) => Some(crate::transports::tls::RustlsConfig::from_config(
                crate::transports::tls::build_server_config(tls)
                    .map_err(|e| anyhow::anyhow!("failed to build TLS server config: {e}"))?,
            )),
            None => None,
        };
        let listener = tokio::net::TcpListener::bind(&server.bind_address).await?;
        Ok(Self { listener, tls })
    }

    /// The address the listener holds.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

/// Serve the HTTP(S) transport on `listener` until the shutdown signal
/// fires.
pub async fn serve(
    state: AppState,
    listener: HttpListener,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let config = state.config.load();
    let bind_address = listener.local_addr()?;
    let health_path = config.gateway.server.health_path.clone();
    let mcp_path = config.gateway.server.mcp_path.clone();
    let tls_config = config.gateway.server.tls.clone();
    let app = router(state, &health_path, &mcp_path);

    let mut shutdown_rx = shutdown;

    if let (Some(rustls_config), Some(tls)) = (listener.tls, tls_config) {
        use crate::transports::tls::McpgTlsAcceptor;
        use axum_server::tls_rustls::RustlsAcceptor;
        // McpgTlsAcceptor wraps the standard rustls acceptor and
        // stamps `TlsInfo` (peer cert chain + parsed leaf details)
        // onto every request via Extensions; the HTTP handler then
        // threads it into `RequestMetadata.tls`.
        let acceptor = McpgTlsAcceptor::new(RustlsAcceptor::new(rustls_config));
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
        axum_server::Server::<std::net::SocketAddr>::from_listener(listener.listener)
            .acceptor(acceptor)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = listener.listener;
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
    let mcp_path_owned = mcp_path.to_owned();

    let mut router = Router::new()
        .route(health_path, get(health_handler))
        .route(probes::READINESS_PATH, get(readiness_handler))
        .route(probes::RUNTIME_PATH, get(runtime_handler))
        // `get` serves `HEAD` too.
        .route(
            mcp_path,
            get(mcp_405_handler)
                .post(mcp_handler)
                .delete(mcp_405_handler),
        )
        // The Server Card, at the location the Server Card specification
        // reserves under the MCP endpoint.
        .route(
            &format!(
                "{}{}",
                mcp_path.trim_end_matches('/'),
                discovery::SERVER_CARD_SUFFIX
            ),
            get(discovery::server_card_handler),
        );

    // Kept for the canonical-host exemption list below: the metrics endpoint is
    // scraped by address, not by the gateway's public name.
    let mut metrics_path: Option<String> = None;
    // The route delegates rendering to the Prometheus plugin via
    // `MetricsSink::render_text_exposition`, so it exists only while a
    // sink of that kind is listed. Its `config.path` overrides `/metrics`.
    let prometheus_sink = config
        .observability
        .metrics
        .sinks
        .iter()
        .find(|s| s.kind == crate::observability::PROMETHEUS_PLUGIN_ID);
    if let (true, Some(sink)) = (config.observability.is_metrics_on(), prometheus_sink) {
        let path = sink
            .config
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("/metrics")
            .to_owned();
        router = router.route(&path, get(metrics_handler));
        metrics_path = Some(path);
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

    // Inbound MCP Events sources: third parties POST signed events here.
    // Answers 404 for every id while events are off.
    router = router.route(
        "/webhooks/events/{source_id}",
        post(events_webhooks::webhook_events_handler).layer(axum::extract::DefaultBodyLimit::max(
            crate::config::events::MAX_INBOUND_BODY_BYTES,
        )),
    );

    // Upstream webhook subscriptions of imported event types deliver here.
    // Answers 503 for every id while events are off.
    router = router.route(
        "/webhooks/mcp-events/{federation}/{id}",
        post(events_webhooks::upstream_events_handler).layer(axum::extract::DefaultBodyLimit::max(
            crate::protocol::v_2026_07_28::extensions::events::wire::MAX_WEBHOOK_BODY_BYTES,
        )),
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

    // OAuth 2.1 Protected Resource Metadata (RFC 9728) and the embedded EMA
    // authorization server (RFC 8414 metadata, the token endpoint and its
    // JWKS, and interactive sign-in's pages, RFC 7009 revocation and RFC 7591
    // registration). Mounted
    // unconditionally: each handler reads the live config or runtime and
    // answers 404 while its block is unset, so a hot reload that adds or
    // removes one takes effect without a restart. The PRM is
    // served at the root and at the RFC 9728 §3.1 path-aware form so a
    // client that derives the metadata URL from a resource carrying a path
    // component finds it.
    router = router
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_handler),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*resource_path}",
            get(oauth_protected_resource_handler),
        )
        // Personal Agent Protocol discovery (`personal_agent.discovery`).
        .route("/.well-known/poppy.json", get(poppy_document_handler))
        // The operations endpoint (`personal_agent.operations`); 404 while
        // unset.
        .route(
            "/poppy/operations/{operation_id}",
            get(personal_agent_operations::pap_operation_handler),
        )
        .route(
            "/poppy/operations/{operation_id}/confirm",
            post(personal_agent_operations::pap_operation_confirm_handler),
        )
        .route(
            "/poppy/operations/{operation_id}/cancel",
            post(personal_agent_operations::pap_operation_cancel_handler),
        );
    let authorization_server = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server_metadata_handler),
        )
        .route(
            crate::runtime::authorization_server::TOKEN_PATH,
            post(oauth_token_handler),
        )
        .route(
            crate::runtime::authorization_server::JWKS_PATH,
            get(oauth_jwks_handler),
        )
        .route(
            crate::config::interactive_login::CLIENT_METADATA_DOCUMENT_PATH,
            get(discovery::oauth_client_metadata_document_handler),
        )
        .route(
            crate::runtime::authorization_server::revocation::REVOCATION_PATH,
            post(oauth_revoke_handler),
        )
        .route(
            crate::runtime::authorization_server::dcr::REGISTRATION_PATH,
            post(oauth_register_handler),
        )
        .route(
            crate::runtime::authorization_server::interactive::AUTHORIZE_PATH,
            get(oauth_authorize_handler)
                .head(oauth_browser_method_not_allowed)
                .fallback(oauth_browser_method_not_allowed),
        )
        .route(
            crate::runtime::authorization_server::interactive::CONSENT_PATH,
            post(oauth_consent_handler).fallback(oauth_browser_method_not_allowed),
        )
        .route(
            crate::runtime::authorization_server::interactive::CALLBACK_PATH,
            get(oauth_callback_handler)
                .head(oauth_browser_method_not_allowed)
                .fallback(oauth_browser_method_not_allowed),
        )
        .route(
            crate::runtime::authorization_server::interactive::CONNECT_PATH,
            get(oauth_connect_handler)
                .post(oauth_connect_decision_handler)
                .head(oauth_browser_method_not_allowed)
                .fallback(oauth_browser_method_not_allowed),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            discovery::refuse_while_authorization_server_held,
        ));
    router = router.merge(authorization_server);

    // AAuth resource metadata (draft-hardt-oauth-aauth-protocol). Mounted
    // only when `server.aauth_resource_metadata` is configured; the same
    // config drives the `AAuth-Requirement: requirement=agent-token`
    // challenge on authentication-required 401s.
    if config.gateway.server.aauth_resource_metadata.is_some() {
        router = router
            .route(
                "/.well-known/aauth-resource.json",
                get(aauth_resource_metadata_handler),
            )
            .route(
                crate::runtime::aauth_resource::JWKS_PATH,
                get(aauth_jwks_handler),
            )
            .route(
                crate::runtime::aauth_resource::AUTHORIZE_PATH,
                post(aauth_authorize_handler),
            )
            .route(
                crate::runtime::aauth_resource::REVOKE_PATH,
                post(aauth_revoke_handler),
            );
    }

    // MCP-Registry surface (v0.1 API): one entry describing this
    // gateway, so registry-driven client policies can discover MCPG as
    // their approved server. Mounted only when
    // `mcp.registry.enabled` (a restart-time toggle).
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
    // Browser clients: answer the preflight and expose the headers script has
    // to read. A deployment with no `cors` block adds no layer at all, so a
    // non-browser gateway pays nothing.
    if let Some(cors_cfg) = config.gateway.server.cors.clone() {
        let cors_cfg = std::sync::Arc::new(cors_cfg);
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let cors_cfg = cors_cfg.clone();
                async move { cors::cors_layer(cors_cfg, req, next).await }
            },
        ));
    }

    // One identity: when `server.canonical_url` is set, a request on any other
    // host is redirected rather than served, so the deployment advertises a
    // single OAuth resource however many names resolve to it. Operational
    // paths keep answering on every host (a kubelet probe's `Host` is the pod
    // IP). Applied outermost so a redirected request touches nothing else.
    let canonical = config.gateway.server.canonical_url.clone();
    if let Some(canonical) = canonical {
        let exempt: Vec<String> = std::iter::once(health_path.to_owned())
            .chain([
                probes::READINESS_PATH.to_owned(),
                probes::RUNTIME_PATH.to_owned(),
            ])
            .chain(metrics_path.clone())
            .collect();
        let trust_proxy = config.gateway.server.trust_proxy_ip;
        router =
            router.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let canonical = canonical.clone();
                    let exempt = exempt.clone();
                    async move {
                        redirect_to_canonical(req, next, &canonical, &exempt, trust_proxy).await
                    }
                },
            ));
    }

    router
        // Every event stream tells an nginx-family proxy in front of the
        // gateway not to buffer it: such a proxy holds a response without a
        // Content-Length until the upstream closes, and an SSE body never
        // closes on its own — the client sees no status line at all. One
        // layer covers the SSE-framed POST results and the long-lived
        // `subscriptions/listen` and `events/stream` responses alike.
        .layer(axum::middleware::map_response(
            no_proxy_buffering_for_event_streams,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(
            body_cap_mb * 1024 * 1024,
        ))
        // The request deadline. A tool call's awaited plugin call holds it,
        // and a request dropped once such a call began still finishes.
        .layer(crate::transports::request_deadline::RequestDeadlineLayer::new(request_timeout))
        // Last-resort panic boundary: a panic in any handler becomes a
        // JSON-RPC 500 instead of resetting the connection / killing the
        // worker task. Placed inside TraceLayer so the synthesized 500 is
        // still traced.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            handle_router_panic,
        ))
        // Every answer of the MCP endpoint names the revision it serves,
        // the timeout and the panic answers included, so the stamp sits
        // outside both.
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let stamp = req.uri().path() == mcp_path_owned;
                async move {
                    let response = next.run(req).await;
                    if stamp {
                        with_protocol_version_header(response)
                    } else {
                        response
                    }
                }
            },
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .with_state(state)
}

/// The span every request runs in, with the method and the path only. A
/// query string can carry an authorization code or `state` (RFC 6749
/// §10.5), so the URI is never recorded whole.
fn request_span(req: &axum::http::Request<axum::body::Body>) -> tracing::Span {
    tracing::debug_span!("request", method = %req.method(), path = %req.uri().path())
}

/// Answer `308` to the canonical origin when a request arrives on another host.
///
/// The redirect preserves method, path and query — 308 forbids a client from
/// rewriting the method, so a POSTed JSON-RPC call replays as a POST. Anything
/// on `exempt` (health, readiness, runtime, metrics) is served on every host:
/// a kubelet probe reaches the pod by IP and would follow a redirect to a name
/// it cannot resolve.
///
/// A request with no `Host` at all is served rather than redirected — there is
/// nothing to compare, and HTTP/1.0 clients and some probes omit it.
async fn redirect_to_canonical(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    canonical: &str,
    exempt: &[String],
    trust_proxy: bool,
) -> Response {
    let path = req.uri().path();
    if exempt.iter().any(|p| p == path) {
        return next.run(req).await;
    }
    let Some(canonical_host) = url::Url::parse(canonical)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    else {
        return next.run(req).await;
    };
    let Some(arrived_on) = request_host(req.headers(), trust_proxy) else {
        return next.run(req).await;
    };
    if canonical_host_matches(&arrived_on, &canonical_host) {
        return next.run(req).await;
    }
    let origin = canonical.trim_end_matches('/');
    let origin = match url::Url::parse(origin) {
        Ok(u) => format!(
            "{}://{}",
            u.scheme(),
            u.host_str().unwrap_or_default().to_owned()
                + &u.port().map(|p| format!(":{p}")).unwrap_or_default()
        ),
        Err(_) => return next.run(req).await,
    };
    let target = format!(
        "{origin}{}",
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    metrics::counter!("mcpg_canonical_host_redirects_total").increment(1);
    match axum::http::HeaderValue::from_str(&target) {
        Ok(location) => (
            axum::http::StatusCode::PERMANENT_REDIRECT,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => next.run(req).await,
    }
}

/// Host comparison for the canonical check: case-insensitive, port-insensitive
/// (the canonical URL carries the scheme's port, a `Host` header usually does
/// not).
fn canonical_host_matches(arrived_on: &str, canonical_host: &str) -> bool {
    let bare = |h: &str| -> String {
        let h = h.trim();
        if let Some(rest) = h.strip_prefix('[') {
            return rest.split(']').next().unwrap_or(rest).to_ascii_lowercase();
        }
        h.split(':').next().unwrap_or(h).to_ascii_lowercase()
    };
    bare(arrived_on) == bare(canonical_host)
}

/// Response header that nginx-family proxies (nginx, APISIX, OpenResty) honour
/// per response to disable their upstream response buffering.
const NO_PROXY_BUFFERING_HEADER: &str = "x-accel-buffering";

/// Stamp `X-Accel-Buffering: no` on every `text/event-stream` response.
async fn no_proxy_buffering_for_event_streams(mut response: Response) -> Response {
    let is_event_stream = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.trim_start().starts_with("text/event-stream"));
    if is_event_stream {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(NO_PROXY_BUFFERING_HEADER),
            axum::http::HeaderValue::from_static("no"),
        );
    }
    response
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
            && let Some(ip) = request_context.client_ip
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
    // A client that advertised only `application/json` gets the inline-JSON
    // shape at every optional SSE upgrade.
    let client_accepts_sse = validate_post_accept(headers, &request_context.request_id)?;
    if let Some(response) = validate_post_content_type(headers, &request_context.request_id) {
        return Err(response);
    }
    Ok(client_accepts_sse)
}

/// POST handler for the MCP endpoint. Flow: identity -> the preflight gates
/// (rate limit, origin, `Accept`, `Content-Type`) -> authentication -> parse
/// the JSON body -> [`dispatch`] (protocol version, routing headers, session)
/// -> frame the outcome as JSON or SSE.
async fn mcp_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    connection: ConnectionExt,
    // `ConnectInfo` rides the request extensions on BOTH serve paths (axum's
    // `into_make_service_with_connect_info` on plain HTTP; `McpgTlsAcceptor`'s
    // inject shim on TLS), so extract it as an optional Extension.
    // (`Option<ConnectInfo<…>>` itself doesn't satisfy
    // axum 0.8's `OptionalFromRequestParts`.) Absent in `oneshot` tests.
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    RequestHeaders(headers): RequestHeaders,
    body: Bytes,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let peer_ip = peer.as_ref().map(|ext| ext.0.0.ip());
    let mut request_context = match build_full_request_context(
        &headers,
        &runtime,
        connection.into_inner(),
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
        Err(resp) => return refused_credential_response(resp, &config, &headers),
    };
    let trust_proxy = config.gateway.server.trust_proxy_ip;
    request_context.client_ip = crate::transports::anon_limit::client_ip(
        trust_proxy,
        trust_proxy
            .then(|| headers.get(X_FORWARDED_FOR))
            .flatten()
            .and_then(|v| v.to_str().ok()),
        peer_ip,
    );

    // The preflight first: a foreign `Origin` is a 403 (MCP Streamable
    // HTTP), whether or not the caller must authenticate.
    let client_accepts_sse = match mcp_post_preflight(&headers, &config, &request_context) {
        Ok(accepts_sse) => accepts_sse,
        Err(rejection) => return rejection,
    };
    if let Some(response) =
        authentication_required_response(&runtime, &config, &headers, &request_context)
    {
        return response;
    }

    let body: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(parse_err) => {
            let error = crate::protocol::ProtocolError::parse_error(format!(
                "Failed to parse the request body as JSON: {parse_err}"
            ));
            return map_protocol_error_response(error, &request_context.request_id);
        }
    };

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
        Err(resp) => return resp,
    };

    let request_id = request_context.request_id.clone();
    let outcome = dispatch(&runtime, &config, body, request_context, Some(&headers)).await;
    match outcome {
        DispatchOutcome::Rejected(rejection) => map_transport_rejection(rejection, &request_id),
        DispatchOutcome::Stream {
            plan: StreamPlan::SubscriptionsListen,
            ctx,
            session_id,
            body,
        } => {
            subscriptions_listen_handler(state.clone(), ctx, session_id, body)
                .boxed()
                .await
        }
        DispatchOutcome::Stream {
            plan: StreamPlan::EventsStream,
            ctx,
            body,
            ..
        } => {
            events_stream::events_stream_handler(state.clone(), ctx, body, client_accepts_sse)
                .boxed()
                .await
        }
        DispatchOutcome::Response {
            response,
            notifications,
            ctx,
        } => finish_response(
            &runtime,
            &config,
            &headers,
            &ctx,
            client_accepts_sse,
            response,
            notifications,
        ),
    }
}

/// The identity gate refused the credential: point the challenge at the
/// resource metadata bound to the hostname the request came in on.
fn refused_credential_response(
    response: Response,
    config: &crate::config::AppConfig,
    headers: &HeaderMap,
) -> Response {
    let host = request_host(headers, config.gateway.server.trust_proxy_ip);
    with_resource_metadata_pointer(response, &resource_metadata_url(config, host.as_deref()))
}

/// `governance.access.require_authentication`: a caller below verified is
/// refused before any MCP work, with the 401 challenge an OAuth or EMA
/// client starts its flow from. `None` lets the request through.
fn authentication_required_response(
    runtime: &crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    headers: &HeaderMap,
    request_context: &RequestContext,
) -> Option<Response> {
    if !config.governance.access.require_authentication
        || !request_context.identity.is_below_verified()
    {
        return None;
    }
    metrics::counter!("mcpg_authentication_required_total").increment(1);
    tracing::debug!(
        request_id = %request_context.request_id.as_str(),
        "caller below verified refused by governance.access.require_authentication"
    );
    let response = (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32000,
                "message": "authentication required",
            },
        })),
    )
        .into_response();
    let host = request_host(headers, config.gateway.server.trust_proxy_ip);
    let caller = Some(&request_context.identity);
    let aauth = runtime
        .aauth_resource()
        .map(|resource| response::AauthChallenge {
            resource,
            identity: caller,
        });
    // A 401 must carry a challenge (RFC 9110 §15.5.2), so the Bearer one is
    // sent even when only an identity plugin verifies callers.
    let response = with_www_authenticate_challenge(
        response,
        true,
        &resource_metadata_url(config, host.as_deref()),
        challenge_scope(config).as_deref(),
        aauth,
        caller,
        runtime.dpop_challenge(),
    );
    Some(with_request_id_header(
        response,
        &request_context.request_id,
    ))
}

/// Shape the dispatched result into the HTTP response: an SSE stream of the
/// request's notifications followed by its result, or the inline JSON
/// result. A `-32601` is a `404`: the method does not exist on this endpoint.
fn finish_response(
    runtime: &crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    headers: &HeaderMap,
    request_context: &RequestContext,
    client_accepts_sse: bool,
    response: Result<ProtocolHttpResponse, ProtocolError>,
    notifications: Vec<Value>,
) -> Response {
    let request_id = &request_context.request_id;
    let response = match response {
        Ok(response) => response,
        Err(error) if error.code() == METHOD_NOT_FOUND_CODE => {
            return map_protocol_error_with_status(
                error,
                axum::http::StatusCode::NOT_FOUND,
                &request_context.request_id,
            );
        }
        Err(error) => return map_protocol_error_response(error, &request_context.request_id),
    };
    // A `tools/call` that emitted progress or log notifications
    // answers a client that accepts `text/event-stream` with a per-request
    // stream: the notifications in order, then the result, then the stream
    // closes. A client that accepts only JSON gets the result inline.
    if client_accepts_sse
        && !notifications.is_empty()
        && let ProtocolResponse::JsonRpcSuccess(success) = &response.response
    {
        let frames: Vec<String> = notifications
            .iter()
            .map(Value::to_string)
            .chain(std::iter::once(
                serde_json::to_string(success).unwrap_or_default(),
            ))
            .collect();
        return with_request_id_header(map_response_stream(frames), request_id);
    }
    let response = with_request_id_header(map_protocol_http_response(response), request_id);
    // Only a 401 or a 403 carries a challenge, so no other status pays for
    // the challenge inputs below.
    if !matches!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED | axum::http::StatusCode::FORBIDDEN
    ) {
        return without_internal_headers(response);
    }
    let auth_enabled = config.governance.access.is_enabled();
    // The challenge names the resource metadata bound to the hostname the
    // request arrived on, so a host reaching a custom domain discovers a
    // `resource` equal to the URL it used.
    let host = request_host(headers, config.gateway.server.trust_proxy_ip);
    let prm_url = resource_metadata_url(config, host.as_deref());
    let scope = challenge_scope(config);
    let caller = Some(&request_context.identity);
    // The AAuth challenge context: the resource role plus the caller — an
    // AAuth caller short on scope is stepped up with a resource token.
    let aauth_challenge = runtime
        .aauth_resource()
        .map(|resource| response::AauthChallenge {
            resource,
            identity: caller,
        });
    with_www_authenticate_challenge(
        response,
        auth_enabled,
        &prm_url,
        scope.as_deref(),
        aauth_challenge,
        caller,
        runtime.dpop_challenge(),
    )
}

/// `subscriptions/listen`: a POST answered with an SSE stream of the
/// notifications the request names, until the client closes it or the
/// session ends ([`open_listen`]). The client-facing subscription id is the
/// request's JSON-RPC id; the session that keys the delivery bus stays
/// internal.
async fn subscriptions_listen_handler(
    state: AppState,
    request_context: RequestContext,
    session_id: String,
    body: Value,
) -> Response {
    let request_id = request_context.request_id.clone();
    let listen = match open_listen(&state, &request_context, &session_id, &body).await {
        Ok(listen) => listen,
        Err(ListenRefusal::Error(error))
            if error.code() == crate::protocol::MISSING_REQUIRED_CLIENT_CAPABILITY_CODE =>
        {
            return map_protocol_error_with_status(
                error,
                axum::http::StatusCode::BAD_REQUEST,
                &request_id,
            );
        }
        Err(ListenRefusal::Error(error)) => {
            return map_protocol_error_response(error, &request_id);
        }
        Err(ListenRefusal::NotOwner) => {
            return with_request_id_header(
                axum::http::StatusCode::NOT_FOUND.into_response(),
                &request_id,
            );
        }
        Err(ListenRefusal::TooManyStreams) => {
            return with_request_id_header(
                axum::http::StatusCode::TOO_MANY_REQUESTS.into_response(),
                &request_id,
            );
        }
        Err(ListenRefusal::CapacityExhausted) => {
            return map_transport_rejection(
                crate::transports::dispatch::capacity_exhausted(body.get("id").cloned()),
                &request_id,
            );
        }
    };
    let events = listen.map(|frame| {
        Ok::<_, Infallible>(Event::default().event("message").data(frame.to_string()))
    });
    with_request_id_header(
        Sse::new(events)
            .keep_alive(KeepAlive::default())
            .into_response(),
        &request_id,
    )
}

/// `GET`, `HEAD` and `DELETE` on the MCP endpoint, whose only method is
/// `POST`. The gates run in the order `POST` runs them, so these methods
/// disclose nothing a `POST` would not: the browser hand-off (`GET`/`HEAD`
/// only), then identity, the origin check (`403`) and authentication
/// (`401`), and only then `405 Allow: POST`.
async fn mcp_405_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    connection: ConnectionExt,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    method: axum::http::Method,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    // Browser hand-off, BEFORE identity and every other gate: a plain
    // navigation (GET/HEAD, Accept has text/html and not text/event-stream)
    // 303s to the configured literal URL. Anonymous browsers are the point,
    // the Location carries no request data, and the request class it claims
    // is otherwise a guaranteed 405 — so the pre-auth surface gets simpler
    // here, not wider. `Vary: Accept` keeps a shared cache from serving the
    // redirect to an SSE client.
    if matches!(method, axum::http::Method::GET | axum::http::Method::HEAD)
        && let Some(ref url) = config.gateway.server.browser_redirect_url
    {
        let accept = headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if accept.contains("text/html") && !accept.contains(SSE_ACCEPT) {
            metrics::counter!("mcpg_browser_redirects_total").increment(1);
            return Response::builder()
                .status(axum::http::StatusCode::SEE_OTHER)
                .header(axum::http::header::LOCATION, url.clone())
                .header(axum::http::header::VARY, "Accept")
                .body(axum::body::Body::empty())
                .unwrap();
        }
    }
    let request_context = match build_full_request_context(
        &headers,
        &runtime,
        connection.into_inner(),
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
        Err(resp) => return refused_credential_response(resp, &config, &headers),
    };
    if let Some(response) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_context.request_id,
    ) {
        return response;
    }
    if let Some(response) =
        authentication_required_response(&runtime, &config, &headers, &request_context)
    {
        return response;
    }
    with_request_id_header(
        (
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            [(axum::http::header::ALLOW, "POST")],
        )
            .into_response(),
        &request_context.request_id,
    )
}

#[cfg(test)]
#[path = "../http_tests.rs"]
mod tests;
