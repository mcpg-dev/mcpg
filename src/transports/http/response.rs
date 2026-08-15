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
pub(crate) fn with_www_authenticate_challenge(
    mut response: Response,
    auth_enabled: bool,
    resource_metadata: &str,
) -> Response {
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
