//! Axum request handlers for the admin API.
//!
//! Each handler delegates to `AdminService` for business logic and
//! returns JSON responses. Mounted by `admin_router` in `admin/mod.rs`.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use super::service::AdminService;

type SharedAdmin = Arc<AdminService>;

/// Liveness probe — returns current health status.
pub async fn health(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.health())
}

/// Readiness probe — reports whether the gateway is ready to accept traffic.
pub async fn readiness(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.readiness())
}

/// Returns runtime metadata (version, uptime, loaded plugins).
pub async fn runtime_info(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.runtime_info())
}

/// Lists all active MCP sessions.
pub async fn list_sessions(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.list_sessions())
}

/// Returns details for a single session by ID.
pub async fn get_session(
    State(svc): State<SharedAdmin>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match svc.get_session(&id) {
        Some(session) => (StatusCode::OK, Json(serde_json::to_value(session).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session not found"})),
        ),
    }
}

/// Forcefully terminates a session by ID.
pub async fn terminate_session(
    State(svc): State<SharedAdmin>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if svc.terminate_session(&id) {
        (
            StatusCode::OK,
            Json(serde_json::json!({"terminated": true})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session not found"})),
        )
    }
}

/// Lists all configured bindings (tools, prompts, resources).
pub async fn list_bindings(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.list_bindings())
}

/// Returns details for a single binding by ID.
pub async fn get_binding(
    State(svc): State<SharedAdmin>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match svc.get_binding(&id) {
        Some(binding) => (StatusCode::OK, Json(serde_json::to_value(binding).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "binding not found"})),
        ),
    }
}

/// Lists all loaded plugins with their manifests.
pub async fn list_plugins(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    Json(svc.list_plugins())
}

/// Disable a registered plugin. The plugin stays loaded but is
/// skipped during chain evaluation and binding / watch lookups
/// until [`enable_plugin`] is called.
pub async fn disable_plugin(
    State(svc): State<SharedAdmin>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    plugin_op_response(svc.disable_plugin(&id).await)
}

/// Re-enable a previously disabled plugin.
pub async fn enable_plugin(
    State(svc): State<SharedAdmin>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    plugin_op_response(svc.enable_plugin(&id).await)
}

/// Map a `PluginOpResult` to the right HTTP status code. The
/// mutation outcome itself returns 200 OK regardless (a
/// well-formed request that couldn't transition state is still
/// not a protocol error — the body's `ok: false` carries that
/// signal); but an `audit_error` surfaces as 500 so the operator
/// alarm fires on the audit-sink failure even when the registry
/// state change succeeded.
fn plugin_op_response(
    result: crate::admin::service::PluginOpResult,
) -> (
    axum::http::StatusCode,
    Json<crate::admin::service::PluginOpResult>,
) {
    let status = if result.audit_error.is_some() {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    } else {
        axum::http::StatusCode::OK
    };
    (status, Json(result))
}

/// `GET /admin/v1/plugins/:id` — full detail for a single plugin.
/// 404 if no plugin with that id is registered.
pub async fn get_plugin(
    State(svc): State<SharedAdmin>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match svc.get_plugin(&id) {
        Some(detail) => (StatusCode::OK, Json(serde_json::to_value(detail).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "plugin not found", "plugin_id": id})),
        ),
    }
}

/// Query params for `POST /admin/v1/plugins/:id:drain`.
#[derive(serde::Deserialize, Default)]
pub struct DrainQuery {
    /// Timeout in seconds. Operator-visible cap; default 30s.
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// `POST /admin/v1/plugins/:id:drain[?timeout=<secs>]`.
///
/// Responds 200 on a clean drain, 408 on timeout, 400 when the plugin
/// isn't in a drainable state (e.g., already disabled). The body
/// carries a structured `DrainResult` in every case — operator
/// tooling parses it rather than hand-matching status codes.
pub async fn drain_plugin(
    State(svc): State<SharedAdmin>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DrainQuery>,
) -> impl IntoResponse {
    // Defaults + bounds. 0s is meaningless (race the drain into
    // immediate timeout); >1h is almost certainly a typo.
    let timeout_secs = q.timeout.unwrap_or(30).clamp(1, 3600);
    let result = svc
        .drain_plugin(&id, std::time::Duration::from_secs(timeout_secs))
        .await;

    let status = match result.outcome.as_str() {
        "completed" => StatusCode::OK,
        "timed_out" => StatusCode::REQUEST_TIMEOUT,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, Json(serde_json::to_value(result).unwrap()))
}

/// Request body for the config validation endpoint.
#[derive(serde::Deserialize)]
pub struct ValidateConfigRequest {
    pub yaml: String,
}

/// Validates a candidate YAML config without applying it.
pub async fn validate_config(
    State(svc): State<SharedAdmin>,
    Json(body): Json<ValidateConfigRequest>,
) -> impl IntoResponse {
    Json(svc.validate_config(&body.yaml))
}

/// Request body for the policy preview endpoint.
#[derive(serde::Deserialize)]
pub struct PolicyPreviewRequest {
    pub candidate_yaml: String,
    pub test_cases: Vec<super::service::PolicyTestCase>,
}

/// Dry-runs policy evaluation against test cases without side effects.
pub async fn policy_preview(
    State(svc): State<SharedAdmin>,
    Json(body): Json<PolicyPreviewRequest>,
) -> impl IntoResponse {
    Json(svc.policy_preview(&body.candidate_yaml, body.test_cases))
}

/// `POST /admin/v1/config:reload` — admin-API hot-reload trigger.
///
/// Parameterless. Returns `200 OK` on a successful reload, `500` on
/// failure (the body's `error` carries the cause; the previous config
/// remains live).
pub async fn reload_config_handler(State(svc): State<SharedAdmin>) -> impl IntoResponse {
    let result = svc.reload_config().await;
    let status = if result.ok {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(result))
}
