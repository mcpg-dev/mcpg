//! Inbound webhook receivers.
//!
//! Third-party systems POST here to signal that a watched resource changed or
//! that a pending human approval was resolved. Both are token-gated and
//! origin-checked; neither speaks MCP.

use super::*;

/// Webhook receiver: third-party systems POST here to signal a resource changed.
///
/// Path: `POST /webhooks/resource-updated/{token}`
///
/// The `{token}` must match a token configured in a resource binding's `watch.strategy.webhook.token`.
/// When matched, the watch engine delivers `notifications/resources/updated` to all subscribed clients.
///
/// Accepts an empty body or a JSON body (ignored — only the token matters).
pub(crate) async fn webhook_resource_updated_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    let config = state.config.load();
    let request_id = GatewayRequestId::new();
    // Same DNS-rebinding posture as /mcp: a cross-origin browser request is
    // refused before touching the watch engine. No Origin (server-to-server
    // senders) is allowed through.
    if let Some(resp) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_id,
    ) {
        return resp;
    }

    let runtime = state.runtime.load();

    // Constant-time-ish token validation (tokens are not secret, just routing keys).
    let uri = match runtime.watch_engine.resolve_webhook_token(&token) {
        Some(uri) => uri.clone(),
        None => {
            // truncate token in logs so a leaked log
            // line does not expose the full routing key.
            let token_hint: String = token.chars().take(8).collect();
            tracing::debug!(token_hint = %token_hint, "webhook: unknown token");
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "unknown webhook token"})),
            )
                .into_response();
        }
    };

    let token_hint = if token.len() > 8 { &token[..8] } else { &token };
    tracing::info!(uri = %uri, token_hint = %token_hint, "webhook: resource change received");
    runtime.watch_engine.notify_resource_changed(&uri).await;

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"ok": true, "uri": uri})),
    )
        .into_response()
}

/// Approval resolution callback. Notifiers (and human
/// reviewers using the direct callback URL) POST here with an
/// `ApprovalOutcome` JSON body. Auth = HMAC over `<id>|<expires>`
/// using the runtime's per-deploy signing key; signature is
/// validated in constant time.
///
/// Body:
///
/// ```json
/// {"outcome": "approved" | "denied",
///  "approver_subject": "alice", "reason": "ok"}
/// ```
///
/// Query params: `?expires=<unix_ts>&sig=<base64url(hmac)>`.
///
/// Returns 200 on success, 401 on signature mismatch / expiry,
/// 404 if the approval is not held locally and the gateway has no
/// cluster_backend (so the resolution can't propagate to the
/// holder), 400 on malformed body.
pub(crate) async fn webhook_approval_resolution_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<ApprovalCallbackQuery>,
    axum::extract::Json(body): axum::extract::Json<
        mcpg_plugin_protocol::approval_notifier::ApprovalOutcome,
    >,
) -> Response {
    // Origin runs before HMAC verification so a cross-origin browser request
    // is 403'd before any signature work. No Origin (server-to-server
    // notifiers) is allowed through. The `Json` body extractor must stay last.
    let config = state.config.load();
    let request_id = GatewayRequestId::new();
    if let Some(resp) = validate_origin(
        &headers,
        &config.gateway.server.allowed_origins,
        &request_id,
    ) {
        return resp;
    }

    let runtime = state.runtime.load();
    let registry = std::sync::Arc::clone(&runtime.approval_registry);
    if let Err(err) = registry.verify_signature(&approval_id, query.expires, &query.sig) {
        tracing::warn!(
            approval_id = %approval_id,
            error = %err,
            "approval webhook: signature verification failed"
        );
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": err.to_string()})),
        )
            .into_response();
    }
    // Always propagate=true — webhook callbacks may land on any
    // gateway instance; the cluster topic ensures the holder
    // receives the resolution.
    match registry.resolve(&approval_id, body, true).await {
        Ok(()) => (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({"ok": true, "approval_id": approval_id})),
        )
            .into_response(),
        Err(crate::runtime::approvals::ResolveError::NotFound(_)) => {
            // The pending entry isn't held locally — the cluster
            // broadcast above will reach the holder. We return 200
            // because the resolution _was_ accepted; 404 would
            // mislead a single-instance deploy into thinking the
            // approval failed.
            tracing::info!(
                approval_id = %approval_id,
                "approval webhook: resolution accepted (entry held by another instance)"
            );
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "ok": true,
                    "approval_id": approval_id,
                    "note": "broadcast to cluster; holding instance will resolve"
                })),
            )
                .into_response()
        }
        Err(err) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = %err,
                "approval webhook: resolve failed"
            );
            (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"error": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct ApprovalCallbackQuery {
    expires: u64,
    sig: String,
}
