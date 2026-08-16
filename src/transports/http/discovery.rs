//! Unauthenticated discovery surfaces.
//!
//! OAuth 2.1 Protected Resource Metadata (RFC 9728) and Authorization Server
//! Metadata (RFC 8414), the token endpoint, and the MCP registry `v0.1` catalog
//! view of this gateway's own servers.

use super::*;

/// AAuth resource metadata (draft-hardt-oauth-aauth-protocol).
///
/// Serves the operator-declared document at
/// `GET /.well-known/aauth-resource.json`, letting an AAuth agent that knows
/// only this gateway's hostname learn the credential flow (`access_mode`),
/// the signature window, any extra covered components, exactly which
/// signature algorithms the verifier accepts, the scopes it grants, and the
/// endpoints of its resource role (`jwks_uri`, `authorization_endpoint`,
/// `revocation_endpoint`) — before its first signed call.
pub(crate) async fn aauth_resource_metadata_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let runtime = state.runtime.load();
    let Some(resource) = runtime.aauth_resource() else {
        // The route is only mounted when configured; a config reload that
        // removed the block still answers coherently.
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "aauth resource metadata not configured",
            })),
        )
            .into_response();
    };
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        Json(resource.metadata_document()),
    )
        .into_response()
}

/// The resource's JWKS at `GET /.well-known/aauth-jwks.json` — the public
/// half of the key that signs resource tokens. Person servers verify our
/// resource tokens against it (discovered through `aauth-resource.json`).
pub(crate) async fn aauth_jwks_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let runtime = state.runtime.load();
    let Some(resource) = runtime.aauth_resource() else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        Json(resource.jwks_document().clone()),
    )
        .into_response()
}

/// AAuth authorization endpoint (`POST /aauth/authorize`).
///
/// An agent that holds a person token for this gateway asks for a resource
/// token naming the `scope` it wants; it takes that token to its person
/// server, which returns an auth token the agent then signs with. The
/// request MUST be signed with a person token — a caller presenting only an
/// agent token (or nothing) is answered `401` with
/// `AAuth-Requirement: requirement=person-token`.
pub(crate) async fn aauth_authorize_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let runtime = state.runtime.load();
    let Some(resource) = runtime.aauth_resource() else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
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

    // The protocol requires a person token here. Anything else is told so.
    let is_person = matches!(
        crate::runtime::aauth_resource::AauthTokenType::of(&ctx.identity),
        Some(crate::runtime::aauth_resource::AauthTokenType::Person)
    );
    if !is_person {
        return aauth_problem(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_request",
            "the authorization endpoint requires a person token presented via Signature-Key",
            &[("aauth-requirement", "requirement=person-token")],
        );
    }

    #[derive(serde::Deserialize)]
    struct AuthorizeBody {
        scope: String,
        #[serde(default)]
        account: Option<String>,
    }
    let parsed: AuthorizeBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return aauth_problem(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("body must be JSON with a `scope` string: {e}"),
                &[],
            );
        }
    };
    let scopes: Vec<String> = parsed.scope.split_whitespace().map(str::to_owned).collect();
    if scopes.is_empty() {
        return aauth_problem(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "`scope` must name at least one scope value",
            &[],
        );
    }
    match resource.mint_resource_token(&ctx.identity, &scopes, parsed.account.as_deref()) {
        Ok(token) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "resource_token": token })),
        )
            .into_response(),
        Err(crate::runtime::aauth_resource::MintRefusal::UnknownScope(s)) => aauth_problem(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_scope",
            &format!("scope {s:?} is not one this resource grants (see scope_descriptions)"),
            &[],
        ),
        Err(crate::runtime::aauth_resource::MintRefusal::PersonTokenRequired) => aauth_problem(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_request",
            "a verified person token is required before a resource token can be issued",
            &[("aauth-requirement", "requirement=person-token")],
        ),
        Err(crate::runtime::aauth_resource::MintRefusal::NoSigningKey) => aauth_problem(
            axum::http::StatusCode::NOT_FOUND,
            "invalid_request",
            "this resource does not issue resource tokens (no signing key configured)",
            &[],
        ),
    }
}

/// AAuth revocation endpoint (`POST /aauth/revoke`).
///
/// A person server (or access server) tells this resource that a token it
/// issued is revoked, by `(iss, jti)`, in a request signed as itself. Only
/// the issuer of a token may revoke it. Answers `200` whether or not the
/// token was ever seen — a revocation that arrives before the token does
/// must not be lost — and denies every later request presenting it.
pub(crate) async fn aauth_revoke_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let runtime = state.runtime.load();
    let Some(resource) = runtime.aauth_resource() else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, 16 * 1024).await {
        Ok(b) => b,
        Err(_) => return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let authority = parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            let lowered = h.trim().to_ascii_lowercase();
            lowered
                .strip_suffix(":443")
                .map(str::to_owned)
                .unwrap_or(lowered)
        })
        .unwrap_or_default();
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    match resource
        .verify_revocation(
            parts.method.as_str(),
            &authority,
            parts.uri.path(),
            &query,
            &headers,
            &body,
        )
        .await
    {
        Ok((iss, jti)) => {
            // Keep the entry for the longest token lifetime the protocol
            // allows to be outstanding under this issuer.
            let until =
                mcpg_aauth_core::now_unix() + mcpg_aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS;
            resource.revoke(&iss, &jti, until);
            tracing::info!(iss = %iss, jti = %jti, "AAuth token revoked by its issuer");
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "revoked": true })),
            )
                .into_response()
        }
        Err(e) => {
            let mut sig_error = format!("error={}", e.code.as_str());
            if let Some(required) = &e.required_input {
                let refs: Vec<&str> = required.iter().map(|s| s.as_str()).collect();
                sig_error.push_str(&format!(
                    ", required_input={}",
                    mcpg_aauth_core::sfv::serialize_string_list(&refs)
                ));
            }
            let mut extra: Vec<(&str, String)> = vec![("signature-error", sig_error)];
            if e.code == mcpg_aauth_core::sig::SigErrorCode::UnsupportedScheme {
                extra.push(("accept-signature-scheme", "jwks_uri".to_owned()));
            }
            let extra_refs: Vec<(&str, &str)> =
                extra.iter().map(|(n, v)| (*n, v.as_str())).collect();
            aauth_problem(
                axum::http::StatusCode::UNAUTHORIZED,
                e.code.as_str(),
                &e.detail,
                &extra_refs,
            )
        }
    }
}

/// An RFC 9457 problem response in the AAuth error shape (`error` + `detail`
/// members) with any extra headers.
fn aauth_problem(
    status: axum::http::StatusCode,
    error: &str,
    detail: &str,
    extra_headers: &[(&str, &str)],
) -> Response {
    let mut resp = (
        status,
        Json(serde_json::json!({
            "error": error,
            "detail": detail,
            "status": status.as_u16(),
        })),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    for (name, value) in extra_headers {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::try_from(*name),
            axum::http::HeaderValue::try_from(*value),
        ) {
            resp.headers_mut().append(n, v);
        }
    }
    resp
}

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
