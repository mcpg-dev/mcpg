//! Unauthenticated discovery surfaces.
//!
//! OAuth 2.1 Protected Resource Metadata (RFC 9728) and Authorization Server
//! Metadata (RFC 8414), the token, revocation and client registration
//! endpoints, and the MCP registry `v0.1` catalog view of this gateway's own
//! servers.

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
/// The published `resource` is the configured identifier bound to the
/// hostname the request arrived on (a client compares it with the URL it
/// connected to, RFC 9728 §3.3), falling back to the canonical one.
pub(crate) async fn oauth_protected_resource_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
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
    let host = super::request_host(&headers, config.gateway.server.trust_proxy_ip);
    let mut document = serde_json::json!({
        "resource": rm.resource_for_host(host.as_deref()),
        "authorization_servers": auth_servers,
        "scopes_supported": rm.scopes_supported,
        "bearer_methods_supported": rm.bearer_methods_supported,
    });
    // RFC 9728 §2: while the embedded authorization server binds tokens,
    // this resource takes them with the DPoP scheme.
    if let Some(dpop) = config
        .governance
        .access
        .authorization_server
        .as_ref()
        .map(|authz| &authz.dpop)
        .filter(|dpop| dpop.enabled)
    {
        let runtime = state.runtime.load();
        let identity_plugins = runtime.plugin_registry().has_identity_plugins();
        let embedded_only =
            embedded_server_only(&config.governance.access, &auth_servers, identity_plugins);
        document["dpop_signing_alg_values_supported"] = serde_json::json!(dpop.allowed_algs);
        document["dpop_bound_access_tokens_required"] =
            serde_json::json!(dpop.required && embedded_only);
    }
    // RFC 9728 §2: the authorization details types this resource's own
    // tokens may be limited to.
    if let Some(details) = config
        .governance
        .access
        .authorization_server
        .as_ref()
        .map(|authz| &authz.authorization_details)
        .filter(|details| details.enabled())
    {
        let types: Vec<&str> = details
            .types
            .iter()
            .map(|rule| rule.type_name.as_str())
            .collect();
        document["authorization_details_types_supported"] = serde_json::json!(types);
    }
    Json(document).into_response()
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

/// Whether the embedded authorization server is the one verifier of this
/// resource's access tokens: the only authorization server listed, with no
/// `oidc_oauth` provider, `jwks` verifier or identity plugin beside it. Its
/// `dpop.required` binds its own tokens only, so only then does every
/// token the resource accepts have to be DPoP-bound.
fn embedded_server_only(
    access: &crate::config::AccessConfig,
    auth_servers: &[String],
    identity_plugins: bool,
) -> bool {
    let Some(ref authz) = access.authorization_server else {
        return false;
    };
    auth_servers.iter().all(|server| *server == authz.issuer)
        && access
            .oidc_oauth
            .as_ref()
            .is_none_or(|oidc| oidc.providers.is_empty())
        && access.jwks.is_none()
        && !identity_plugins
}

/// Extract authorization server URLs from auth config.
pub(crate) fn derive_authorization_servers(auth: &crate::config::AccessConfig) -> Vec<String> {
    let mut servers = Vec::new();
    // The embedded EMA authorization server fronts this very gateway —
    // list it first so EMA-capable clients discover the ID-JAG grant
    // profile without extra configuration. Verbatim: a client compares the
    // metadata `issuer` with this string exactly (RFC 8414 §3.3).
    if let Some(ref authz) = auth.authorization_server {
        servers.push(authz.issuer.clone());
        // With interactive sign-in it is the only one listed: a client
        // signs in at the first entry, and a longer list invites guessing.
        if authz.login_idp().is_some() {
            return servers;
        }
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
/// authorization server. Answers 404 while
/// `governance.access.authorization_server` is unset.
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

/// `GET /oauth/jwks` — the public keys of the embedded authorization
/// server's asymmetric signing keys, advertised as `jwks_uri` in its
/// metadata. 404 while it has none: an HMAC secret is never published.
pub(crate) async fn oauth_jwks_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Response {
    let runtime = state.runtime.load();
    let Some(jwks) = runtime
        .ema_authorization_server()
        .and_then(|server| server.jwks())
    else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no published signing keys" })),
        )
            .into_response();
    };
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        Json(jwks.clone()),
    )
        .into_response()
}

/// `POST /oauth/token` — ID-JAG redemption and, with a login IdP, the
/// authorization code and the refresh token of an interactive sign-in.
/// Token responses and errors are never cacheable (RFC 6749 §5.1/§5.2).
/// Every request within the per-IP rate limit is audited, under the
/// `x-mcpg-request-id` it answers with, together with what it did to
/// grants (a replayed code, a reused refresh token, a revoked grant, an
/// ended IdP sign-in). Only refused requests spend the limit: a successful
/// redemption gives back what it took. The `DPoP` headers go to the
/// server, which reads them while DPoP is on.
pub(crate) async fn oauth_token_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    form: Result<
        axum::extract::Form<crate::runtime::authorization_server::TokenRequestForm>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    use crate::runtime::authorization_server::TokenRedemption;
    use crate::runtime::authorization_server::dpop::{self, DpopPresentation};

    let runtime = state.runtime.load();
    let Some(server) = runtime.ema_authorization_server() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "authorization server not configured" })),
        )
            .into_response();
    };
    // Before any redemption work: signature checks and key or metadata
    // document fetches are what a flood would buy. An unattributable
    // source is not limited, as on `/mcp`.
    let per_min = server.rate_limit_per_min();
    let limited_ip = if per_min > 0 {
        crate::transports::anon_limit::client_ip(
            state.config.load().gateway.server.trust_proxy_ip,
            headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
            peer.map(|ext| ext.0.0.ip()),
        )
    } else {
        None
    };
    if let Some(ip) = limited_ip
        && let Err(wait) = crate::transports::anon_limit::OAUTH_TOKEN.acquire(ip, per_min, per_min)
    {
        return token_rate_limited_response(ip, wait);
    }
    let request_id = GatewayRequestId::new();
    let redemption = match form {
        Ok(axum::extract::Form(form)) => {
            let authorization = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let presentation = DpopPresentation::from_values(
                headers
                    .get_all(dpop::DPOP_HEADER)
                    .iter()
                    .map(axum::http::HeaderValue::as_bytes),
            );
            server
                .redeem_with_dpop(form, authorization, &presentation)
                .await
        }
        Err(rejection) => TokenRedemption {
            dpop_nonce: server.token_endpoint_nonce(),
            ..TokenRedemption::malformed(format!("malformed token request: {rejection}"))
        },
    };
    // Clients behind one address (a NAT, a proxy, a hosted MCP client)
    // share the budget, so their successful redemptions, and the nonce
    // round trip before them, must not spend it.
    if let Some(ip) = limited_ip
        && (redemption.result.is_ok() || redemption.nonce_requested())
    {
        crate::transports::anon_limit::OAUTH_TOKEN.refund(ip, per_min, per_min);
    }
    let upstream_request_id = headers
        .get(UPSTREAM_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    for event in redemption.audit_events(request_id.as_str()) {
        let event = event.with_upstream_request_id(upstream_request_id.clone());
        let _ = runtime.plugin_registry().emit_audit_event(&event).await;
    }
    let mut resp = token_endpoint_response(redemption);
    if let Ok(value) = axum::http::HeaderValue::from_str(request_id.as_str()) {
        resp.headers_mut().insert(REQUEST_ID_RESPONSE_HEADER, value);
    }
    resp
}

/// `POST /oauth/revoke` — RFC 7009 token revocation, offered with a login
/// IdP (404 otherwise). The client authenticates as at the token endpoint
/// and shares its per-IP budget. Answers 200 with no body whether or not
/// the token was known (RFC 7009 §2.2), an RFC 6749 §5.2 error otherwise;
/// never cacheable. Audited like a token request; the IdP refresh token of
/// a sign-in the revocation released is revoked at the IdP after the
/// answer.
pub(crate) async fn oauth_revoke_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    form: Result<
        axum::extract::Form<
            crate::runtime::authorization_server::revocation::RevocationRequestForm,
        >,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    use crate::runtime::authorization_server::revocation::TokenRevocation;

    let runtime = state.runtime.load();
    let Some(server) = runtime
        .ema_authorization_server()
        .filter(|server| server.login_idp().is_some())
    else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "token revocation is not offered" })),
        )
            .into_response();
    };
    let per_min = server.rate_limit_per_min();
    let limited_ip = if per_min > 0 {
        crate::transports::anon_limit::client_ip(
            state.config.load().gateway.server.trust_proxy_ip,
            headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
            peer.map(|ext| ext.0.0.ip()),
        )
    } else {
        None
    };
    if let Some(ip) = limited_ip
        && let Err(wait) = crate::transports::anon_limit::OAUTH_TOKEN.acquire(ip, per_min, per_min)
    {
        return token_rate_limited_response(ip, wait);
    }
    let request_id = GatewayRequestId::new();
    let mut revocation = match form {
        Ok(axum::extract::Form(form)) => {
            let authorization = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            server.revoke_token(form, authorization).await
        }
        Err(rejection) => {
            TokenRevocation::malformed(format!("malformed revocation request: {rejection}"))
        }
    };
    if let Some(ip) = limited_ip
        && revocation.result.is_ok()
    {
        crate::transports::anon_limit::OAUTH_TOKEN.refund(ip, per_min, per_min);
    }
    let upstream_request_id = headers
        .get(UPSTREAM_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    for event in revocation.audit_events(request_id.as_str()) {
        let event = event.with_upstream_request_id(upstream_request_id.clone());
        let _ = runtime.plugin_registry().emit_audit_event(&event).await;
    }
    if let Some(released) = revocation.released.take() {
        let runtime = state.runtime.load_full();
        tokio::spawn(async move {
            if let Some(server) = runtime.ema_authorization_server() {
                server.revoke_superseded(released).await;
            }
        });
    }
    let mut resp = match revocation.result {
        Ok(()) => {
            let mut resp = axum::http::StatusCode::OK.into_response();
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
        Err(ref err) => oauth_error_response(err),
    };
    if let Ok(value) = axum::http::HeaderValue::from_str(request_id.as_str()) {
        resp.headers_mut().insert(REQUEST_ID_RESPONSE_HEADER, value);
    }
    resp
}

/// `POST /oauth/register` — RFC 7591 dynamic client registration, offered
/// with a login IdP while `interactive.dynamic_client_registration` is on
/// (404 otherwise). It shares the token endpoint's per-IP budget; a
/// successful registration gives back what it took. Answers 201 with the
/// registered client, or an RFC 7591 §3.2.2 error (401 with a Bearer
/// challenge for a missing or unknown initial access token, 429 with
/// `Retry-After` over the hourly allowance, 503 at `max_clients`); never
/// cacheable. Audited, except a request over the hourly allowance.
pub(crate) async fn oauth_register_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    body: axum::body::Body,
) -> Response {
    use crate::runtime::authorization_server::dcr::{ClientRegistration, MAX_REGISTRATION_BYTES};

    let runtime = state.runtime.load();
    let Some(server) = runtime
        .ema_authorization_server()
        .filter(|server| server.registers_clients())
    else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "dynamic client registration is not offered" })),
        )
            .into_response();
    };
    let client_ip = crate::transports::anon_limit::client_ip(
        state.config.load().gateway.server.trust_proxy_ip,
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        peer.map(|ext| ext.0.0.ip()),
    );
    let per_min = server.rate_limit_per_min();
    let limited_ip = client_ip.filter(|_| per_min > 0);
    if let Some(ip) = limited_ip
        && let Err(wait) = crate::transports::anon_limit::OAUTH_TOKEN.acquire(ip, per_min, per_min)
    {
        return token_rate_limited_response(ip, wait);
    }
    let request_id = GatewayRequestId::new();
    let is_json = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    let registration = if !is_json {
        ClientRegistration::malformed(
            "the registration request must be sent as application/json".to_owned(),
        )
    } else {
        match axum::body::to_bytes(body, MAX_REGISTRATION_BYTES).await {
            Ok(body) => {
                let authorization = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                server
                    .register_client(&body, authorization, client_ip)
                    .await
            }
            Err(_) => ClientRegistration::malformed(format!(
                "the registration request exceeds {MAX_REGISTRATION_BYTES} bytes"
            )),
        }
    };
    if let Some(ip) = limited_ip
        && registration.result.is_ok()
    {
        crate::transports::anon_limit::OAUTH_TOKEN.refund(ip, per_min, per_min);
    }
    if let Some(event) = registration.audit_event(request_id.as_str()) {
        let upstream_request_id = headers
            .get(UPSTREAM_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let event = event.with_upstream_request_id(upstream_request_id);
        let _ = runtime.plugin_registry().emit_audit_event(&event).await;
    }
    let mut resp = match registration.result {
        Ok(ref registered) => {
            (axum::http::StatusCode::CREATED, Json(registered.body())).into_response()
        }
        Err(ref error) => {
            let status = axum::http::StatusCode::from_u16(error.status())
                .unwrap_or(axum::http::StatusCode::BAD_REQUEST);
            let mut resp = (status, Json(error.body())).into_response();
            let h = resp.headers_mut();
            if let Some(challenge) = error.www_authenticate() {
                h.insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(challenge),
                );
            }
            if let crate::runtime::authorization_server::dcr::RegistrationError::RateLimited {
                retry_after_secs,
            } = *error
            {
                h.insert(axum::http::header::RETRY_AFTER, retry_after_secs.into());
            }
            resp
        }
    };
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(request_id.as_str()) {
        h.insert(REQUEST_ID_RESPONSE_HEADER, value);
    }
    resp
}

/// `429` for a client address over the token endpoint's rate limit, as an
/// RFC 6749 §5.2 error body with `Retry-After`. Not audited: a flood would
/// otherwise fill the audit log.
fn token_rate_limited_response(ip: std::net::IpAddr, wait: std::time::Duration) -> Response {
    let retry_after = (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1);
    metrics::counter!("mcpg_ema_token_rate_limited_total").increment(1);
    tracing::debug!(%ip, retry_after, "EMA token endpoint rate limit exceeded");
    let mut resp = (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "temporarily_unavailable",
            "error_description": format!(
                "too many token requests from this address; retry in {retry_after} s"
            ),
        })),
    )
        .into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(axum::http::header::RETRY_AFTER, retry_after.into());
    resp
}

/// The token response or error of `redemption`, with the `DPoP-Nonce` it
/// carries while DPoP proofs at the token endpoint need one (RFC 9449 §8).
fn token_endpoint_response(
    redemption: crate::runtime::authorization_server::TokenRedemption,
) -> Response {
    let mut resp = match redemption.result {
        Ok((token, _)) => {
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
        Err(ref err) => oauth_error_response(err),
    };
    if let Some(nonce) = redemption.dpop_nonce
        && let Ok(value) = axum::http::HeaderValue::from_str(nonce.as_str())
    {
        resp.headers_mut().insert(
            crate::runtime::authorization_server::dpop::DPOP_NONCE_HEADER,
            value,
        );
    }
    resp
}

/// An RFC 6749 §5.2 error of the token or revocation endpoint: never
/// cacheable, with a Basic challenge after a failed HTTP Basic
/// authentication.
fn oauth_error_response(err: &crate::runtime::authorization_server::OAuthError) -> Response {
    let status =
        axum::http::StatusCode::from_u16(err.status).unwrap_or(axum::http::StatusCode::BAD_REQUEST);
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
