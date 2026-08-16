//! Response mapping for the HTTP transport.
//!
//! Projects the runtime's version-neutral outcomes — `GatewayResponse`,
//! `ProtocolHttpResponse`, `ProtocolError`, `TransportRejection` — onto HTTP
//! status codes, bodies and headers, and stamps the headers every surface
//! shares (`x-mcpg-request-id`, `Mcp-Session-Id`, the RFC 9728
//! `WWW-Authenticate` challenge).

use super::*;

pub(crate) fn map_gateway_response(response: GatewayResponse) -> Response {
    let request_id = response.request_id.clone();
    let response = match response.payload {
        GatewayResponsePayload::Readiness(snapshot) => {
            Json(serde_json::to_value(snapshot).expect("readiness snapshot serialized"))
                .into_response()
        }
        GatewayResponsePayload::Runtime(snapshot) => {
            Json(serde_json::to_value(snapshot).expect("runtime snapshot serialized"))
                .into_response()
        }
        GatewayResponsePayload::Protocol(protocol_response) => {
            map_protocol_http_response(protocol_response)
        }
    };

    with_request_id_header(response, &request_id)
}

pub(crate) fn map_protocol_http_response(response: ProtocolHttpResponse) -> Response {
    // Inspect the result envelope BEFORE we move the response
    // into the JSON serializer — we need to surface the SEP-2133
    // replay marker as a non-normative
    // `Idempotent-Replayed: true` HTTP response header (Increase
    // / Chargebee convention) so clients that prefer header-side
    // signalling don't have to peek inside `_meta`.
    let mut idempotent_replayed: Option<String> = None;
    let mut retry_after: Option<&'static str> = None;
    if let ProtocolResponse::JsonRpcSuccess(success) = &response.response {
        let meta = success
            .result
            .get("_meta")
            .and_then(serde_json::Value::as_object);
        if let Some(meta) = meta
            && meta
                .get(crate::runtime::idempotency::META_KEY_REPLAYED)
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        {
            idempotent_replayed = meta
                .get(crate::runtime::idempotency::META_KEY_ORIGINAL_COMPLETED_AT)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some(String::new()));
        }
    }
    if response.http_status == 409
        && let ProtocolResponse::JsonRpcError(err) = &response.response
        && err.error.code == crate::runtime::idempotency::ERROR_CODE_IN_FLIGHT
    {
        retry_after = Some("1");
    }
    // SEP-2350 step-up: a policy scope denial tags the JSON-RPC error
    // `data` with the missing-scope list. Lift it into the internal
    // header so the transport-level challenge builder can mint the
    // `insufficient_scope` 403 challenge, and strip the marker from the
    // wire body (the challenge carries it).
    let mut insufficient_scope: Option<String> = None;
    let mut response = response;
    if response.http_status == 403
        && let ProtocolResponse::JsonRpcError(err) = &mut response.response
        && let Some(data) = err.error.data.as_mut().and_then(Value::as_object_mut)
        && let Some(scope_value) = data.remove(INSUFFICIENT_SCOPE_DATA_KEY)
    {
        insufficient_scope = scope_value.as_str().map(str::to_owned);
        // Drop a now-empty `data` object so the error body stays clean.
        if data.is_empty() {
            err.error.data = None;
        }
    }
    let mut http_response = match response.response {
        ProtocolResponse::JsonRpcSuccess(success) => Json(success).into_response(),
        ProtocolResponse::JsonRpcError(error) => Json(error).into_response(),
        ProtocolResponse::NotificationAccepted => axum::http::StatusCode::ACCEPTED.into_response(),
    };

    *http_response.status_mut() =
        // Plugin-supplied and never clamped on the way in, so an out-of-range
        // value would panic the response mapper. The three sibling mapping
        // sites already fall back rather than expect.
        axum::http::StatusCode::from_u16(response.http_status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    http_response.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::SUPPORTED_PROTOCOL_VERSION),
    );
    if let Some(session_id) = response.session_id_header
        && let Ok(value) = HeaderValue::from_str(&session_id)
    {
        http_response
            .headers_mut()
            .insert(HeaderName::from_static(SESSION_ID_HEADER), value);
    }
    if let Some(completed_at) = idempotent_replayed {
        http_response
            .headers_mut()
            .insert("idempotent-replayed", HeaderValue::from_static("true"));
        if !completed_at.is_empty()
            && let Ok(value) = HeaderValue::from_str(&completed_at)
        {
            http_response
                .headers_mut()
                .insert("idempotent-replayed-at", value);
        }
    }
    if let Some(secs) = retry_after {
        http_response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static(secs));
    }
    if let Some(scope) = insufficient_scope
        && let Ok(value) = HeaderValue::from_str(&scope)
    {
        http_response
            .headers_mut()
            .insert(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER), value);
    }
    http_response
}

/// SEP-2567/2575: a 2026-07-28 server exposes only the POST endpoint.
/// Return an HTTP 405 response when the request negotiates the modern
/// wire; `None` lets the legacy GET/DELETE handler proceed.
pub(crate) fn reject_method_on_modern_wire(
    runtime: &crate::runtime::GatewayRuntime,
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Option<Response> {
    if WireVersion::from_headers(runtime, headers).is_modern() {
        Some(with_request_id_header(
            (
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                [("allow", "POST")],
            )
                .into_response(),
            request_id,
        ))
    } else {
        None
    }
}

/// Inject `Mcp-Session-Id` header into any response when the request carried a session.
/// Per MCP spec, the session ID header MUST be present in ALL HTTP responses after
/// session creation — not just the initialize response.
pub(crate) fn with_session_id_header(mut response: Response, session_id: Option<&str>) -> Response {
    if let Some(session_id) = session_id {
        // Only add if not already present (initialize sets it from runtime).
        if !response.headers().contains_key(SESSION_ID_HEADER)
            && let Ok(value) = HeaderValue::from_str(session_id)
        {
            response
                .headers_mut()
                .insert(HeaderName::from_static(SESSION_ID_HEADER), value);
        }
    }
    response
}

/// Internal response header used to pipe insufficient-scope hints from the
/// auth / policy / plugin layer up to the `WWW-Authenticate` challenge
/// builder. The header is stripped before the response leaves the gateway —
/// it never appears on the wire. Value is a space-separated list of OAuth
/// scope identifiers the caller needs to acquire for the operation to
/// succeed. A 403 carrying this header is an authenticated-but-under-scoped
/// denial and earns an `insufficient_scope` step-up challenge (SEP-2350);
/// a 403 without it is an ordinary authorization denial and gets no
/// challenge.
pub const INSUFFICIENT_SCOPE_HEADER: &str = "x-mcpg-insufficient-scope";

/// JSON-RPC error `data` marker carrying the space-separated missing-scope
/// list from a policy scope denial. `map_protocol_http_response` lifts it
/// into [`INSUFFICIENT_SCOPE_HEADER`] so the transport-level challenge
/// builder can mint the SEP-2350 `insufficient_scope` step-up challenge.
pub const INSUFFICIENT_SCOPE_DATA_KEY: &str = "mcpg_insufficient_scope";

/// Fallback relative well-known path used when no canonical PRM `resource`
/// is configured.
pub(crate) const RELATIVE_PRM_PATH: &str = "/.well-known/oauth-protected-resource";

/// Resolve the absolute `resource_metadata` URL advertised in
/// `WWW-Authenticate` challenges. RFC 9728 wants the absolute well-known
/// URL; we derive it from the canonical configured `resource`. When no
/// `resource_metadata.resource` is configured we fall back to the relative
/// root path (back-compat with deployments that haven't set a canonical
/// resource yet).
pub(crate) fn resource_metadata_url(config: &crate::config::AppConfig) -> String {
    config
        .governance
        .access
        .resource_metadata
        .as_ref()
        .map(crate::config::OAuthResourceMetadataConfig::well_known_url)
        .unwrap_or_else(|| RELATIVE_PRM_PATH.to_owned())
}

/// Attach the RFC 6750 / RFC 9728 `WWW-Authenticate` challenge to 401
/// (unauthenticated) and to 403 (authenticated-but-under-scoped, SEP-2350)
/// responses.
///
/// - **401**: a `Bearer resource_metadata="…"` challenge so an
///   unauthenticated client can discover the authorization server.
/// - **403 + [`INSUFFICIENT_SCOPE_HEADER`]**: a step-up challenge
///   `Bearer resource_metadata="…", error="insufficient_scope", scope="a b c"`
///   per RFC 6750 §3.1 / SEP-2350. A bare 403 (ordinary authorization
///   denial, no missing-scope hint) is left untouched — it is not a
///   re-authentication signal.
///
/// `resource_metadata` is the absolute well-known URL (see
/// [`resource_metadata_url`]). The internal scope header is always
/// stripped, even on paths that mint no challenge, so it never reaches the
/// wire.
///
/// `aauth` additionally mints the AAuth challenge on 401s: the protocol's
/// `AAuth-Requirement: requirement=agent-token` (asking specifically for an
/// AAuth agent token) plus `Accept-Signature-Scheme` / `Accept-Signature-Alg`
/// so the agent can select a scheme and algorithm before signing.
/// `AAuth-Requirement` and `WWW-Authenticate` are independent fields — the
/// draft is explicit that a response MAY carry both. Existing AAuth headers
/// (e.g. a plugin-minted `Signature-Error` path) are left untouched.
pub(crate) fn with_www_authenticate_challenge(
    response: Response,
    auth_enabled: bool,
    resource_metadata: &str,
    aauth: Option<AauthChallenge<'_>>,
) -> Response {
    // The scope hint is read here (before it is stripped below) so the AAuth
    // step-up can name the scopes the caller lacks.
    let scope_hint = response
        .headers()
        .get(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER))
        .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
        .filter(|s| !s.is_empty());
    let mut response = with_aauth_challenge(response, aauth, scope_hint.as_deref());
    // Lift the scope hint regardless of status so it is always stripped.
    let insufficient_scope = response
        .headers_mut()
        .remove(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER))
        .and_then(|v| v.to_str().ok().map(|s| s.to_owned()))
        .filter(|s| !s.is_empty());

    if !auth_enabled {
        return response;
    }

    let status = response.status();
    let header_value = if status == axum::http::StatusCode::UNAUTHORIZED {
        // Quote-sanitize the URL so the header value stays well-formed.
        let url = sanitize_header_quotes(resource_metadata);
        match &insufficient_scope {
            Some(scope) => {
                let scope = sanitize_header_quotes(scope);
                HeaderValue::from_str(&format!(
                    "Bearer resource_metadata=\"{url}\", error=\"insufficient_scope\", scope=\"{scope}\""
                ))
                .ok()
            }
            None => HeaderValue::from_str(&format!("Bearer resource_metadata=\"{url}\"")).ok(),
        }
    } else if status == axum::http::StatusCode::FORBIDDEN {
        // SEP-2350 step-up: only a 403 that names the missing scopes is a
        // re-authentication signal. A bare authorization 403 is not.
        match &insufficient_scope {
            Some(scope) => {
                let url = sanitize_header_quotes(resource_metadata);
                let scope = sanitize_header_quotes(scope);
                HeaderValue::from_str(&format!(
                    "Bearer resource_metadata=\"{url}\", error=\"insufficient_scope\", scope=\"{scope}\""
                ))
                .ok()
            }
            None => None,
        }
    } else {
        None
    };

    if let Some(value) = header_value {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

/// What the AAuth challenge needs: the resource role (its `access_mode`,
/// accepted algorithms, and — in `auth-token` mode — the signing key that
/// mints the resource token a step-up carries) and the caller's identity,
/// when one was resolved.
#[derive(Clone, Copy)]
pub(crate) struct AauthChallenge<'a> {
    pub resource: &'a crate::runtime::aauth_resource::AauthResource,
    pub identity: Option<&'a crate::runtime::RequestIdentity>,
}

/// Attach the AAuth challenge the gateway's `access_mode` calls for.
///
/// - Unauthenticated `401`: `requirement=agent-token` for an identity-only
///   resource, `requirement=person-token` where the resource authorizes on
///   the person (`person-token` / `auth-token` modes) — plus the
///   `Accept-Signature-Scheme` / `Accept-Signature-Alg` capability statements.
/// - An AAuth person or auth-token caller denied for insufficient scope, at
///   an `auth-token` resource: `requirement=auth-token` carrying a resource
///   token for the scopes it holds plus the ones it lacks. This is answered
///   as a `401`, the status the AAuth deferred-response state machine acts
///   on for that requirement (a `403` is terminal "denied" to an AAuth agent);
///   non-AAuth callers keep the SEP-2350 `403` step-up untouched.
///
/// A response already carrying `aauth-requirement` is left alone.
fn with_aauth_challenge(
    mut response: Response,
    aauth: Option<AauthChallenge<'_>>,
    scope_hint: Option<&str>,
) -> Response {
    use crate::runtime::aauth_resource::{AauthTokenType, MintRefusal};

    let Some(challenge) = aauth else {
        return response;
    };
    if response.headers().contains_key("aauth-requirement") {
        return response;
    }
    let cfg = challenge.resource.config();
    let status = response.status();
    let aauth_caller = challenge.identity.and_then(AauthTokenType::of);

    // Step-up: an AAuth caller that authenticated but lacks scope.
    let scope_denied = status == axum::http::StatusCode::FORBIDDEN && scope_hint.is_some();
    if (scope_denied || status == axum::http::StatusCode::UNAUTHORIZED)
        && cfg.access_mode == "auth-token"
        && challenge.resource.can_mint()
        && let Some(identity) = challenge.identity
        && matches!(
            aauth_caller,
            Some(AauthTokenType::Person | AauthTokenType::Auth)
        )
    {
        let mut scopes: Vec<String> = identity.scopes().to_vec();
        if let Some(hint) = scope_hint {
            for s in hint.split_whitespace() {
                if !scopes.iter().any(|h| h == s) {
                    scopes.push(s.to_owned());
                }
            }
        }
        // Only scopes this resource declares can be requested; unknown
        // ones (a tool naming a scope outside `scope_descriptions`) are
        // dropped rather than failing the challenge.
        scopes.retain(|s| cfg.scope_descriptions.contains_key(s));
        let requirement = if scopes.is_empty() {
            None
        } else {
            match challenge
                .resource
                .mint_resource_token(identity, &scopes, None)
            {
                Ok(token) => Some(format!(
                    "requirement=auth-token; resource-token={}",
                    mcpg_aauth_core::sfv::serialize_string(&token)
                )),
                Err(MintRefusal::PersonTokenRequired) => {
                    Some("requirement=person-token".to_owned())
                }
                Err(_) => None,
            }
        };
        if let Some(value) = requirement
            && let Ok(v) = HeaderValue::from_str(&value)
        {
            *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
            response
                .headers_mut()
                .insert(HeaderName::from_static("aauth-requirement"), v);
            return response;
        }
    }

    // An unauthenticated caller refused at the trust floor: mcpg answers
    // that with a policy 403, but at a declared AAuth resource the caller
    // needs the protocol's 401 challenge to learn what credential to bring
    // (a 403 is terminal "denied" to an AAuth agent), and 401 is the correct
    // status for "no credential" under RFC 9110 too. Authenticated callers
    // (any verified identity) keep their 403.
    let unauthenticated = challenge
        .identity
        .map(|i| i.trust_level() < crate::runtime::RequestTrustLevel::Verified)
        .unwrap_or(true);
    let floor_denial = status == axum::http::StatusCode::FORBIDDEN
        && scope_hint.is_none()
        && unauthenticated
        && aauth_caller.is_none();
    if floor_denial {
        *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
    } else if status != axum::http::StatusCode::UNAUTHORIZED {
        return response;
    }
    let requirement = match cfg.access_mode.as_str() {
        "person-token" | "auth-token" => "requirement=person-token",
        _ => "requirement=agent-token",
    };
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("aauth-requirement"),
        HeaderValue::from_static(requirement),
    );
    headers.insert(
        HeaderName::from_static("accept-signature-scheme"),
        HeaderValue::from_static("jwt"),
    );
    if let Ok(algs) = HeaderValue::from_str(&cfg.accept_signature_algs.join(", ")) {
        headers.insert(HeaderName::from_static("accept-signature-alg"), algs);
    }
    response
}

/// Strip `"` so an attacker-influenced scope/URL string can't break out of
/// the quoted `WWW-Authenticate` auth-param grammar (RFC 7235 §2.1).
pub(crate) fn sanitize_header_quotes(value: &str) -> String {
    value.chars().filter(|c| *c != '"').collect()
}

pub(crate) fn map_protocol_error_response(
    error: ProtocolError,
    request_id: &GatewayRequestId,
) -> Response {
    let mut response = Json(error.into_jsonrpc_error()).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::SUPPORTED_PROTOCOL_VERSION),
    );
    with_request_id_header(response, request_id)
}

/// Status-aware variant of [`map_protocol_error_response`] for
/// callers that need to surface a JSON-RPC error envelope at a
/// specific HTTP status (e.g., SEP-2575 modern stateless wants
/// `-32601` carried on HTTP 404, not 200).
pub(crate) fn map_protocol_error_with_status(
    error: ProtocolError,
    status: axum::http::StatusCode,
    request_id: &GatewayRequestId,
) -> Response {
    let mut response = (status, Json(error.into_jsonrpc_error())).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::SUPPORTED_PROTOCOL_VERSION),
    );
    with_request_id_header(response, request_id)
}

/// Render a transport-level rejection (e.g., SEP-2243
/// `Mcp-Method` header mismatch) as an HTTP response. Used by the
/// modern dispatch path when the handler's
/// `validate_transport_headers` rejects a request *before* parsing.
pub(crate) fn map_transport_rejection(
    rejection: crate::protocol::shared::messages::TransportRejection,
    request_id: &GatewayRequestId,
) -> Response {
    use axum::http::StatusCode;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rejection.jsonrpc_id,
        "error": {
            "code": rejection.error_code,
            "message": rejection.message,
            "data": rejection.data,
        }
    });
    let status = StatusCode::from_u16(rejection.status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::SUPPORTED_PROTOCOL_VERSION),
    );
    with_request_id_header(response, request_id)
}

pub(crate) fn map_sse_events(events: Vec<SseEventRecord>) -> Response {
    let stream = iter(events.into_iter().map(sse_event_from_record));

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub(crate) fn with_request_id_header(
    mut response: Response,
    request_id: &GatewayRequestId,
) -> Response {
    let header_name = HeaderName::from_static(REQUEST_ID_RESPONSE_HEADER);
    match HeaderValue::from_str(request_id.as_str()) {
        Ok(value) => {
            response.headers_mut().insert(header_name, value);
        }
        Err(error) => {
            warn!(
                request_id = %request_id,
                error = %error,
                "failed to write request id response header"
            );
        }
    }
    response
}
