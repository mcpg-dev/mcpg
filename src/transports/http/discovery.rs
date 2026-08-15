//! Unauthenticated discovery surfaces.
//!
//! OAuth 2.1 Protected Resource Metadata (RFC 9728) and Authorization Server
//! Metadata (RFC 8414), the token endpoint, and the MCP registry `v0.1` catalog
//! view of this gateway's own servers.

use super::*;

/// OAuth 2.1 Protected Resource Metadata (RFC 9728).
///
/// Returns JSON document at `GET /.well-known/oauth-protected-resource` that lets
/// MCP clients discover which authorization server(s) protect this gateway.
pub(crate) async fn oauth_protected_resource_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let config = state.config.load();

    // RFC 8707/9728: the published `resource` MUST be the canonical
    // external URL the authorization server binds tokens to as `aud`.
    // A `bind_address`-derived value (e.g. `0.0.0.0:8080`) would not
    // match any real token audience, so audience-bound validation would
    // silently fail. Require an explicit, validated
    // `resource_metadata.resource`; refuse to publish a guessed value.
    let Some(ref rm) = config.governance.access.resource_metadata else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "protected resource metadata not configured",
                "detail": "set governance.access.resource_metadata.resource to the canonical \
                           external URL of this gateway (RFC 9728)",
            })),
        )
            .into_response();
    };
    let mut auth_servers = rm.authorization_servers.clone();
    // Fall back to OIDC provider issuers if authorization_servers is empty.
    if auth_servers.is_empty() {
        auth_servers = derive_authorization_servers(&config.governance.access);
    }
    Json(serde_json::json!({
        "resource": rm.resource,
        "authorization_servers": auth_servers,
        "scopes_supported": rm.scopes_supported,
        "bearer_methods_supported": rm.bearer_methods_supported,
    }))
    .into_response()
}

/// The one server entry the registry surface publishes: this gateway.
/// `None` when no canonical MCP URL is resolvable
/// (`mcp.registry.url` unset and no
/// `governance.access.resource_metadata.resource`).
pub(crate) fn served_registry_entry(
    config: &crate::config::AppConfig,
) -> Option<serde_json::Value> {
    let served = &config.mcp.registry;
    let url = served.url.clone().or_else(|| {
        config
            .governance
            .access
            .resource_metadata
            .as_ref()
            .map(|rm| rm.resource.clone())
    })?;
    let mut server = serde_json::json!({
        "name": served.name,
        "version": env!("CARGO_PKG_VERSION"),
        "remotes": [{ "type": "streamable-http", "url": url }],
    });
    if let Some(description) = served.description.as_deref() {
        server["description"] = serde_json::json!(description);
    }
    Some(serde_json::json!({
        "server": server,
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": "active",
                "isLatest": true,
            }
        }
    }))
}

/// `GET /v0.1/servers` — the standard registry list envelope with this
/// gateway as the single entry.
pub(crate) async fn served_registry_list_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let config = state.config.load();
    let servers: Vec<serde_json::Value> = served_registry_entry(&config).into_iter().collect();
    if servers.is_empty() {
        tracing::warn!(
            "mcp.registry enabled but no canonical URL is resolvable; set \
             mcp.registry.url or governance.access.resource_metadata.resource"
        );
    }
    Json(serde_json::json!({ "servers": servers, "metadata": {} })).into_response()
}

/// `GET /v0.1/servers/{name}/versions/{version}` — the pinned-fetch
/// half of the registry contract. Only the current version exists
/// (`latest` or the exact crate version); anything else is 404.
pub(crate) async fn served_registry_version_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path((name, version)): axum::extract::Path<(String, String)>,
) -> Response {
    let config = state.config.load();
    let known = name == config.mcp.registry.name
        && (version == "latest" || version == env!("CARGO_PKG_VERSION"));
    match served_registry_entry(&config).filter(|_| known) {
        Some(entry) => Json(entry).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "server or version not found" })),
        )
            .into_response(),
    }
}

/// Extract authorization server URLs from auth config.
pub(crate) fn derive_authorization_servers(auth: &crate::config::AccessConfig) -> Vec<String> {
    let mut servers = Vec::new();
    // The embedded EMA authorization server fronts this very gateway —
    // list it first so EMA-capable clients discover the ID-JAG grant
    // profile without extra configuration.
    if let Some(ref authz) = auth.authorization_server {
        servers.push(authz.issuer.trim_end_matches('/').to_owned());
    }
    if let Some(ref oidc) = auth.oidc_oauth {
        for provider in &oidc.providers {
            servers.push(provider.issuer.clone());
        }
    }
    if let Some(ref jwks) = auth.jwks
        && let Some(ref issuer) = jwks.issuer
    {
        servers.push(issuer.clone());
    }
    servers
}

/// RFC 8414 authorization-server metadata for the embedded EMA
/// authorization server. Mounted only when
/// `governance.access.authorization_server` is configured.
pub(crate) async fn oauth_authorization_server_metadata_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let runtime = state.runtime.load();
    match runtime.ema_authorization_server() {
        Some(server) => Json(server.metadata()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "authorization server not configured",
            })),
        )
            .into_response(),
    }
}

/// `POST /oauth/token` — ID-JAG redemption (the only supported grant).
/// Token responses and errors are never cacheable (RFC 6749 §5.1/§5.2).
pub(crate) async fn oauth_token_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<crate::runtime::authorization_server::TokenRequestForm>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    use crate::runtime::authorization_server::OAuthError;

    let runtime = state.runtime.load();
    let Some(server) = runtime.ema_authorization_server() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "authorization server not configured" })),
        )
            .into_response();
    };
    let outcome = match form {
        Ok(axum::extract::Form(form)) => {
            let authorization = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            server.handle_token_request(form, authorization).await
        }
        Err(rejection) => Err(OAuthError {
            status: 400,
            error: "invalid_request",
            description: format!("malformed token request: {rejection}"),
            basic_challenge: false,
        }),
    };
    match outcome {
        Ok(token) => {
            let mut resp = Json(token).into_response();
            let h = resp.headers_mut();
            h.insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            h.insert(
                axum::http::header::PRAGMA,
                axum::http::HeaderValue::from_static("no-cache"),
            );
            resp
        }
        Err(err) => {
            let status = axum::http::StatusCode::from_u16(err.status)
                .unwrap_or(axum::http::StatusCode::BAD_REQUEST);
            let mut resp = (status, Json(err.body())).into_response();
            let h = resp.headers_mut();
            h.insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            if err.basic_challenge {
                h.insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static("Basic realm=\"mcpg\""),
                );
            }
            resp
        }
    }
}
