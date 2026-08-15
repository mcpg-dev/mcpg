//! Axum dispatch for the `http_route` plugin entity kind (spec §9.7).
//!
//! Plugins declared with `plugin_class: http_route` mount under the
//! namespaced prefix `/plugins/{plugin_id}/{entity_name}/...`. The
//! gateway runs two catch-all routes that funnel every such request
//! into [`dispatch`], which:
//!
//! 1. Parses the mount prefix to recover `(plugin_id, entity_name)`.
//! 2. Looks up the entity in [`mcpg_plugin_host::PluginRegistry`] —
//!    returns `404` if absent or if the plugin is not serving traffic
//!    (disabled, draining, failed).
//! 3. Matches the remaining path against the plugin's declared
//!    [`RouteSpec`]s, picking the first spec whose method + path
//!    pattern match.
//! 4. Enforces `requires_identity` (401 if no identity resolved) and
//!    `max_body_bytes` (413 if the body cap is exceeded).
//! 5. Invokes [`HttpRoute::handle`] and re-serialises the returned
//!    [`HttpRouteResponse`] into an axum response, streaming
//!    [`HttpBody::Stream`] bodies when `streaming: true`.
//!
//! Override-mode mounts (`allow_path_override: true`, top-level path)
//! are **not** yet wired — the override registry lands with
//! operator config plumbing. Namespaced mounts do not
//! require operator opt-in because they can't collide with gateway
//! routes (`/plugins/*` is reserved).
//!
//! # Trailing slashes
//!
//! axum 0.8 does not normalise trailing slashes (there is no
//! `NormalizePathLayer` on the main router — the MCP endpoint relies
//! on the strict path match). Clients hitting `/plugins/{id}/{entity}/`
//! with a trailing slash will NOT match the no-subpath route; they
//! get 404. Clients should omit the trailing slash. The path matcher
//! inside this module tolerates a trailing slash when matching a
//! `RouteSpec.path` — that's purely for plugins that declare their
//! specs with an optional trailing slash; axum routing happens before
//! that matcher runs.

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use mcpg_plugin_protocol::http_route::{
    HttpBody, HttpChunk, HttpRouteRequest, HttpRouteResponse, RouteSpec,
};
use std::collections::BTreeMap;

use crate::{app::AppState, runtime::plugin_identity_from_request};

/// Reserved top-level paths the override mode must refuse even when
/// it ships. Kept here so both namespaced (informational) and the
/// future override dispatcher share one source of truth.
pub const RESERVED_TOP_LEVEL_PATHS: &[&str] = &["/", "/mcp", "/.well-known/"];

/// Add override-mode routes to `router` for every
/// `http_route_override_entries()` row in `registry`. Fails loudly
/// when two plugins claim the same `(method, path)` tuple — a
/// collision between override plugins is an operator-config bug,
/// and the gateway must refuse to start rather than silently pick
/// a winner.
///
/// Reserved paths are rejected at `register_http_route_with_overrides`
/// time; this builder re-checks as a defence-in-depth layer, so a
/// direct registry push that bypassed the registration API still
/// can't produce a broken router.
pub(crate) fn mount_override_routes(
    mut router: axum::Router<AppState>,
    registry: &mcpg_plugin_host::PluginRegistry,
) -> anyhow::Result<axum::Router<AppState>> {
    use std::collections::BTreeSet;
    let mut claimed: BTreeSet<(String, String)> = BTreeSet::new();
    for entry in registry.http_route_override_entries() {
        // Double-check the reserved set — see doc above.
        if mcpg_plugin_host::RESERVED_OVERRIDE_PATH_PREFIXES
            .iter()
            .any(|p| entry.path == p.trim_end_matches('/') || entry.path.starts_with(p))
            || entry.path == "/"
        {
            anyhow::bail!(
                "http_route plugin '{}' entity '{}' override path '{}' is reserved",
                entry.plugin_id,
                entry.entity_name,
                entry.path,
            );
        }
        let key = (entry.method.to_ascii_uppercase(), entry.path.to_owned());
        if !claimed.insert(key) {
            anyhow::bail!(
                "http_route override path collision: method '{}' path '{}' \
                 claimed by more than one plugin (second claimant: '{}/{}')",
                entry.method,
                entry.path,
                entry.plugin_id,
                entry.entity_name,
            );
        }
        let plugin_id = entry.plugin_id.to_owned();
        let entity_name = entry.entity_name.to_owned();
        let path = entry.path.to_owned();
        // Every override route uses `any()` — the per-spec method
        // filter runs inside `dispatch_inner_impl` via
        // `select_route`. Registering one axum route per spec and
        // then sharing the dispatch logic keeps the code path
        // identical with namespaced mounts.
        let handler = move |state: State<AppState>, req: Request<Body>| {
            let plugin_id = plugin_id.clone();
            let entity_name = entity_name.clone();
            async move { dispatch_override(state.0, plugin_id, entity_name, req).await }
        };
        router = router.route(&path, axum::routing::any(handler));
        tracing::info!(
            plugin_id = %entry.plugin_id,
            entity_name = %entry.entity_name,
            method = %entry.method,
            path = %entry.path,
            "http_route override route mounted",
        );
    }
    Ok(router)
}

/// Default per-request body cap when the plugin does not declare
/// `max_body_bytes`. Mirrors the server's transport-level default so
/// a plugin that forgets to set a cap still gets protected.
const DEFAULT_BODY_CAP_BYTES: u64 = 1024 * 1024;

/// Axum handler for the namespaced mount with no subpath, e.g.
/// `/plugins/dev.mcpg.health/status`. Rewrites the extracted params
/// into the same shape [`dispatch_inner`] expects and delegates.
pub async fn dispatch_no_subpath(
    State(state): State<AppState>,
    Path((plugin_id, entity_name)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    dispatch_inner(state, plugin_id, entity_name, String::new(), req).await
}

/// Axum handler for override-mode mounts — `(plugin_id, entity_name)`
/// are captured when the router builder adds the route, and the
/// request path is taken verbatim as `full_path` + the relative path
/// the plugin's `RouteSpec` matched against.
pub async fn dispatch_override(
    state: AppState,
    plugin_id: String,
    entity_name: String,
    req: Request<Body>,
) -> Response {
    // In override mode the incoming path IS the spec's relative
    // path — no mount prefix to strip. Reuse dispatch_inner_impl by
    // passing the tail of the URI (minus leading '/') as `subpath`.
    let raw = req.uri().path().to_owned();
    let subpath = raw.trim_start_matches('/').to_owned();
    dispatch_inner(state, plugin_id, entity_name, subpath, req).await
}

/// Axum handler for the namespaced mount with a subpath, e.g.
/// `/plugins/dev.mcpg.health/status/deep`. `subpath` is everything
/// after the entity-name segment, without the leading `/`.
pub async fn dispatch_with_subpath(
    State(state): State<AppState>,
    Path((plugin_id, entity_name, subpath)): Path<(String, String, String)>,
    req: Request<Body>,
) -> Response {
    dispatch_inner(state, plugin_id, entity_name, subpath, req).await
}

async fn dispatch_inner(
    state: AppState,
    plugin_id: String,
    entity_name: String,
    subpath: String,
    req: Request<Body>,
) -> Response {
    let started_at = std::time::Instant::now();
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    // Snapshot the request id before we move `req` into dispatch — the
    // ctx is built inside dispatch_inner_impl, so we synthesise here.
    let request_id = req
        .headers()
        .get("Mcp-Request-Id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    // Snapshot identity hint for audit attribution. The full
    // RequestIdentity lives inside dispatch_inner_impl; we capture
    // the principal_id from a header if present, falling back to
    // anonymous (system) actor.
    let actor: Option<mcpg_plugin_protocol::PluginIdentity> = None;
    let registry = state.runtime.load().plugin_registry_arc();
    let response = dispatch_inner_impl(&state, &plugin_id, &entity_name, subpath, req).await;
    let status = response.status().as_u16();
    let elapsed = started_at.elapsed();
    emit_request_metrics(&plugin_id, &entity_name, status, elapsed);
    // Audit: every plugin-handled HTTP route override dispatch lands
    // on the audit lane, even when the runtime never looked at the
    // request (404 / 401 paths).
    let event = mcpg_plugin_host::audit_events::http_route_dispatched_event(
        actor,
        &request_id,
        &plugin_id,
        &entity_name,
        &method,
        &path,
        status,
        elapsed.as_millis() as u64,
    );
    tokio::spawn(async move {
        let _ = registry.emit_audit_event(&event).await;
    });
    response
}

async fn dispatch_inner_impl(
    state: &AppState,
    plugin_id: &str,
    entity_name: &str,
    subpath: String,
    req: Request<Body>,
) -> Response {
    // Same DNS-rebinding posture as /mcp: refuse a cross-origin browser
    // request before any work — ahead of the entity/route lookup so a
    // disallowed Origin yields 403 regardless of whether the route exists (no
    // 403-vs-404 existence oracle). No Origin (server-to-server callers)
    // passes through. Override-mode mounts funnel through here too.
    let cfg = state.config.load();
    if let Some(resp) = crate::transports::http::validate_origin(
        req.headers(),
        &cfg.gateway.server.allowed_origins,
        &crate::runtime::GatewayRequestId::new(),
    ) {
        return resp;
    }

    let runtime = state.runtime.load();
    let registry = runtime.plugin_registry();
    let Some(entity) = registry.http_route(plugin_id, entity_name) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // The path we match RouteSpec against is always rooted at `/`.
    let relative_path = if subpath.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", subpath)
    };

    let routes = entity.routes();
    let Some((spec, path_params)) = select_route(&routes, req.method(), &relative_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut spec = spec.clone();
    // Apply operator overrides from the plugins config.
    // `None` on either override field leaves the plugin's declared
    // value intact; `Some(x)` replaces it. Overrides apply to every
    // spec the entity registered, not just the matched one —
    // operator intent is per-entity, not per-route.
    if let Some(ovr) = registry.http_route_overrides(plugin_id, entity_name) {
        if let Some(cap) = ovr.max_body_bytes {
            spec.max_body_bytes = Some(cap);
        }
        if let Some(req_id) = ovr.requires_identity {
            spec.requires_identity = req_id;
        }
    }

    let (parts, body) = req.into_parts();

    let headers = header_pairs(&parts.headers);
    let query = query_pairs(parts.uri.query());
    let full_path = parts.uri.path().to_owned();

    let body_cap = spec.max_body_bytes.unwrap_or(DEFAULT_BODY_CAP_BYTES);
    let body_bytes = match axum::body::to_bytes(body, body_cap as usize).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let tls_info = parts
        .extensions
        .get::<crate::transports::tls::TlsInfoArc>()
        .cloned();
    let trust_subject_header = state.config.load().gateway.server.trust_subject_header;
    let ctx = match crate::transports::http_request_context(
        &parts.headers,
        &runtime,
        tls_info,
        trust_subject_header,
        &parts.method,
        parts.uri.path_and_query().map(|pq| pq.as_str()),
        None,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let identity_present = !matches!(
        ctx.identity,
        crate::runtime::RequestIdentity::Anonymous { .. }
    );
    if spec.requires_identity && !identity_present {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let identity = if identity_present {
        Some(plugin_identity_from_request(&ctx))
    } else {
        None
    };
    let request_id = ctx.request_id.as_str().to_owned();

    let route_req = HttpRouteRequest {
        method: parts.method.as_str().to_owned(),
        full_path,
        path_params,
        query,
        headers,
        body: body_bytes,
        identity,
        request_id,
        remote_addr: None,
    };

    let route_resp = entity.handle(route_req).await;
    if !spec.streaming && matches!(route_resp.body, HttpBody::Stream(_)) {
        tracing::warn!(
            plugin_id = %plugin_id,
            entity_name = %entity_name,
            "http_route: plugin returned HttpBody::Stream on non-streaming route spec"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    into_axum_response(route_resp)
}

/// Emit one request-counter increment and one latency-histogram
/// sample for a dispatcher invocation. Labels:
///
/// - `plugin_id` + `entity_name` — identify the entity that handled
///   (or would have handled) the request.
/// - `status_class` — `1xx`/`2xx`/`3xx`/`4xx`/`5xx`, derived from
///   the final HTTP status. Classing at emit time keeps Prometheus
///   cardinality bounded (five fixed labels, not 50+ raw statuses).
///
/// Latency is the full dispatch walltime: from router entry to
/// response finalisation (before the response body streams back to
/// the client). Plugin handle time dominates; the registry lookup
/// and path match are sub-microsecond.
fn emit_request_metrics(
    plugin_id: &str,
    entity_name: &str,
    status: u16,
    elapsed: std::time::Duration,
) {
    let class = status_class(status);
    metrics::counter!(
        "mcpg_http_route_requests_total",
        "plugin_id" => plugin_id.to_owned(),
        "entity_name" => entity_name.to_owned(),
        "status_class" => class,
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_http_route_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "entity_name" => entity_name.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

/// Match `(method, path)` against the plugin's declared specs. Returns
/// the first spec that matches along with captured `:name` params. A
/// spec `method` of `"*"` matches any HTTP verb.
fn select_route<'a>(
    specs: &'a [RouteSpec],
    method: &Method,
    path: &str,
) -> Option<(&'a RouteSpec, BTreeMap<String, String>)> {
    for spec in specs {
        if !method_matches(&spec.method, method) {
            continue;
        }
        if let Some(params) = match_path(&spec.path, path) {
            return Some((spec, params));
        }
    }
    None
}

fn method_matches(declared: &str, incoming: &Method) -> bool {
    if declared == "*" {
        return true;
    }
    declared.eq_ignore_ascii_case(incoming.as_str())
}

/// Match `spec` (which may contain `:name` placeholders) against
/// `incoming`. Returns captured placeholders on a match. Trailing
/// slashes are treated as insignificant — `"/x"` and `"/x/"` both
/// match `"/x"`.
fn match_path(spec: &str, incoming: &str) -> Option<BTreeMap<String, String>> {
    let spec_parts: Vec<&str> = spec.split('/').filter(|s| !s.is_empty()).collect();
    let in_parts: Vec<&str> = incoming.split('/').filter(|s| !s.is_empty()).collect();
    if spec_parts.len() != in_parts.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (s, i) in spec_parts.iter().zip(in_parts.iter()) {
        if let Some(name) = s.strip_prefix(':') {
            params.insert(name.to_owned(), (*i).to_owned());
        } else if s != i {
            return None;
        }
    }
    Some(params)
}

fn header_pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_owned(), val.to_owned()))
        })
        .collect()
}

/// Split the raw query string into `(key, value)` pairs without
/// percent-decoding. Handlers that need decoded values can decode
/// themselves — leaving the raw form here avoids pulling in an
/// extra dependency for every gateway build and keeps lossy-utf8
/// decisions in the plugin's hands.
fn query_pairs(q: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = q else {
        return Vec::new();
    };
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.to_owned(), v.to_owned()),
            None => (pair.to_owned(), String::new()),
        })
        .collect()
}

fn into_axum_response(resp: HttpRouteResponse) -> Response {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);
    for (k, v) in &resp.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    match resp.body {
        HttpBody::Bytes(b) => builder
            .body(Body::from(b))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        HttpBody::Stream(stream) => {
            use futures::stream::{Stream, StreamExt};

            // Translate each `HttpChunk` into the `Result<Bytes, _>`
            // items axum's `Body::from_stream` expects. The `End`
            // marker and the underlying stream's exhaustion both
            // terminate; subsequent chunks after `End` are dropped
            // with a warning per the http_route trait docs.
            let mapped = stream
                .take_while(|chunk| {
                    let keep = !matches!(chunk, HttpChunk::End);
                    async move { keep }
                })
                .filter_map(|chunk| async move {
                    match chunk {
                        HttpChunk::Data(b) => Some(Ok::<_, std::convert::Infallible>(b)),
                        HttpChunk::Event { name, data } => {
                            let mut buf = Vec::with_capacity(name.len() + data.len() + 16);
                            buf.extend_from_slice(b"event: ");
                            buf.extend_from_slice(name.as_bytes());
                            buf.extend_from_slice(b"\ndata: ");
                            buf.extend_from_slice(&data);
                            buf.extend_from_slice(b"\n\n");
                            Some(Ok(Bytes::from(buf)))
                        }
                        HttpChunk::End => None,
                    }
                });
            let _: &dyn Stream<Item = _> = &mapped;
            builder
                .body(Body::from_stream(mapped))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_path_literal() {
        let p = match_path("/health", "/health").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn match_path_trailing_slash_tolerated() {
        assert!(match_path("/health", "/health/").is_some());
        assert!(match_path("/health/", "/health").is_some());
    }

    #[test]
    fn match_path_placeholder_captures() {
        let p = match_path("/webhooks/:name", "/webhooks/foo").unwrap();
        assert_eq!(p.get("name").map(String::as_str), Some("foo"));
    }

    #[test]
    fn match_path_arity_mismatch_fails() {
        assert!(match_path("/a/b", "/a").is_none());
        assert!(match_path("/a", "/a/b").is_none());
    }

    #[test]
    fn match_path_literal_mismatch_fails() {
        assert!(match_path("/a/b", "/a/c").is_none());
    }

    #[test]
    fn method_matches_wildcard_and_case() {
        assert!(method_matches("*", &Method::PATCH));
        assert!(method_matches("get", &Method::GET));
        assert!(method_matches("POST", &Method::POST));
        assert!(!method_matches("GET", &Method::POST));
    }

    #[test]
    fn select_route_picks_first_match() {
        let specs = vec![
            RouteSpec {
                method: "POST".into(),
                path: "/a".into(),
                requires_identity: false,
                streaming: false,
                max_body_bytes: None,
            },
            RouteSpec {
                method: "GET".into(),
                path: "/a".into(),
                requires_identity: false,
                streaming: false,
                max_body_bytes: None,
            },
        ];
        let (spec, _) = select_route(&specs, &Method::GET, "/a").unwrap();
        assert_eq!(spec.method, "GET");
    }

    #[test]
    fn select_route_none_when_no_spec_matches() {
        let specs = vec![RouteSpec {
            method: "POST".into(),
            path: "/a".into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: None,
        }];
        assert!(select_route(&specs, &Method::GET, "/a").is_none());
        assert!(select_route(&specs, &Method::POST, "/b").is_none());
    }

    #[test]
    fn status_class_covers_every_hundred_bucket() {
        assert_eq!(status_class(100), "1xx");
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(499), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(599), "5xx");
        assert_eq!(status_class(999), "other");
    }

    #[test]
    fn query_pairs_split_no_decode() {
        let got = query_pairs(Some("x=a%20b&y=c"));
        assert_eq!(
            got,
            vec![("x".into(), "a%20b".into()), ("y".into(), "c".into())]
        );
    }

    #[test]
    fn query_pairs_none_on_empty_query() {
        assert!(query_pairs(None).is_empty());
        assert!(query_pairs(Some("")).is_empty());
    }
}
