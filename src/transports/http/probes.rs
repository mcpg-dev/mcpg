//! Operational probes: health, readiness, metrics, and the runtime snapshot.
//!
//! These are the endpoints an orchestrator and a scrape job call. They carry no
//! MCP semantics and are expected to be network-restricted rather than
//! authenticated — see `router` for what that implies.

use super::*;

/// JSON body returned by the health endpoint.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HealthResponse {
    status: &'static str,
    service: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bindings: Option<
        std::collections::BTreeMap<String, crate::runtime::backend_health::BackendHealthStatus>,
    >,
}

pub(crate) async fn health_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let request_context = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &axum::http::Method::GET,
        None,
        None,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    runtime.record_request_received(&request_context, "health");

    let bindings = if query.get("detail").map(|v| v.as_str()) == Some("bindings") {
        let health_map = runtime.backend_health();
        let mut map = std::collections::BTreeMap::new();
        for entry in health_map.iter() {
            map.insert(entry.key().clone(), entry.value().clone());
        }
        Some(map)
    } else {
        None
    };

    let response = Json(HealthResponse {
        status: "ok",
        service: runtime.service_name.clone(),
        version: runtime.service_version.clone(),
        bindings,
    })
    .into_response();
    runtime.record_request_completed(&request_context, "health");
    with_request_id_header(response, &request_context.request_id)
}

pub(crate) async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    // Pull from the canonical Prometheus plugin's accumulator
    // (the metrics-rs recorder bridge feeds it). The
    // route is only mounted when `observability.metrics.enabled
    // = true`, so a `None` here means the operator listed the
    // Prometheus kind but the plugin failed to register or is
    // not currently serving traffic — surface that as a 503 so
    // operators notice instead of silently returning empty text.
    let runtime = state.runtime.load();
    let body = runtime
        .plugin_registry()
        .metrics_sink_render_text_exposition(crate::observability::PROMETHEUS_PLUGIN_ID)
        .await;
    match body {
        Some(text) => (
            axum::http::StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            text,
        )
            .into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Prometheus metrics sink unavailable",
        )
            .into_response(),
    }
}

pub(crate) async fn readiness_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let ctx = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &axum::http::Method::GET,
        None,
        None,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let request = GatewayRequest::new(
        ctx,
        GatewayOperation::Diagnostics(DiagnosticsOperation::Readiness),
    );
    map_gateway_response(runtime.handle_request(request).await)
}

pub(crate) async fn runtime_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
) -> Response {
    let runtime = state.runtime.load();
    let config = state.config.load();
    let ctx = match build_full_request_context(
        &headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        &axum::http::Method::GET,
        None,
        None,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let request = GatewayRequest::new(
        ctx,
        GatewayOperation::Diagnostics(DiagnosticsOperation::Runtime),
    );
    map_gateway_response(runtime.handle_request(request).await)
}
