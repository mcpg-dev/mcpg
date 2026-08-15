//! Header and origin validation for the HTTP transport.
//!
//! Each function returns `Some(Response)` for a rejection and `None` when the
//! request may proceed, so a handler reads as a list of gates.

use super::*;

pub(crate) fn validate_origin(
    headers: &HeaderMap,
    allowed_origins: &[String],
    request_id: &GatewayRequestId,
) -> Option<Response> {
    let origin = headers
        .get(ORIGIN_HEADER)
        .and_then(|value| value.to_str().ok())?;
    // case-insensitive origin comparison. RFC 6454 §6.1 says
    // the scheme + host + port triple is case-insensitive for ASCII;
    // `HTTP://Example.COM` and `http://example.com` are the same
    // origin. Strip trailing dots (DNS root) for defence against the
    // `http://example.com.` bypass.
    let origin_lower = origin.trim_end_matches('.').to_ascii_lowercase();

    // Operator-empty allow-list: default-allow loopback origins, reject
    // everything else. This is the documented MCP DNS-rebinding posture
    // (https://modelcontextprotocol.io/specification/.../security_best_practices)
    // and matches what every reference client expects when connecting to
    // a locally-bound MCPG. Operators with a public-facing deployment
    // configure `gateway.server.allowed_origins` explicitly, at which
    // point the loopback defaults no longer apply.
    if allowed_origins.is_empty() {
        if is_loopback_origin(&origin_lower) {
            return None;
        }
        return Some(with_request_id_header(
            axum::http::StatusCode::FORBIDDEN.into_response(),
            request_id,
        ));
    }

    if allowed_origins
        .iter()
        .any(|candidate| candidate.trim_end_matches('.').to_ascii_lowercase() == origin_lower)
    {
        return None;
    }

    Some(with_request_id_header(
        axum::http::StatusCode::FORBIDDEN.into_response(),
        request_id,
    ))
}

/// Loopback-host detection for Origin defaults. Matches `localhost`,
/// `127.0.0.1`, and the bracketed IPv6 form `[::1]` across both
/// http/https with an optional port. Origins are already lowercased
/// and trailing-dot-stripped by the caller, so straight prefix /
/// equality checks are safe.
fn is_loopback_origin(origin_lower: &str) -> bool {
    const HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];
    for scheme in ["http://", "https://"] {
        for host in HOSTS {
            let bare = format!("{scheme}{host}");
            if origin_lower == bare {
                return true;
            }
            if let Some(rest) = origin_lower.strip_prefix(&format!("{bare}:")) {
                // The port suffix must be digits-only — `http://localhost:evil`
                // is not loopback.
                if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn validate_post_accept(
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Option<Response> {
    let Some(value) = headers.get(axum::http::header::ACCEPT) else {
        return Some(with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            request_id,
        ));
    };
    let Ok(accepts) = value.to_str() else {
        return Some(with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            request_id,
        ));
    };
    // media-range-aware match (see validate_get_accept).
    //
    // The spec'd "Streamable HTTP" Accept advertisement is
    // `application/json, text/event-stream` — clients that may need to
    // receive an SSE upgrade for long-lived responses include both.
    // Clients that won't ever need SSE (modern stateless wire's
    // inline-only MRTR shape, or any client that only ever calls
    // non-streaming methods) legitimately advertise just
    // `application/json`. Requiring both forced spec-compliant
    // modern clients (including the upstream conformance suite) to
    // hit 400 here even though their request never needed SSE.
    //
    // Policy: accept `application/json` as the minimum. If the client
    // also lists SSE, MCPG may upgrade; if not, the response stays
    // inline JSON.
    if accept_list_includes(accepts, JSON_ACCEPT) {
        return None;
    }

    Some(with_request_id_header(
        axum::http::StatusCode::BAD_REQUEST.into_response(),
        request_id,
    ))
}

/// Whether a POST's `Accept` admits `text/event-stream`, i.e. whether this
/// client consented to an SSE upgrade.
///
/// Runs after [`validate_post_accept`] has already established that
/// `application/json` is present, so a `false` here means "JSON only" rather
/// than "unusable header".
pub(crate) fn post_accepts_sse(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accepts| accept_list_includes(accepts, SSE_ACCEPT))
}

/// Enforce `Mcp-Protocol-Version` header rules for the primary POST endpoint.
///
/// Per the MCP Streamable HTTP spec (2025-11-25): when the client sends
/// `Mcp-Protocol-Version`, it MUST be a supported revision; otherwise the server
/// MUST reply with HTTP `400 Bad Request`.
///
/// absent headers on post-initialize requests are interpreted as the
/// `2025-03-26` legacy revision — the SHOULD from the spec — and are
/// observable via `mcpg_protocol_version_absent_total`. We accept the
/// current revision plus the declared legacy revisions here; the runtime
/// still reconciles the effective version with the session state.
pub(crate) fn enforce_http_protocol_version_header(
    headers: &HeaderMap,
    body_id: Option<&Value>,
) -> Result<(), Response> {
    let Some(raw) = headers.get(PROTOCOL_VERSION_HEADER) else {
        metrics::counter!(
            "mcpg_protocol_version_absent_total",
            "assumed" => crate::protocol::LEGACY_DEFAULT_PROTOCOL_VERSION,
        )
        .increment(1);
        return Ok(());
    };
    let header = raw
        .to_str()
        .map_err(|_| invalid_request_protocol_version(body_id.cloned()))?;
    if header == crate::protocol::SUPPORTED_PROTOCOL_VERSION {
        return Ok(());
    }
    if crate::protocol::LEGACY_PROTOCOL_VERSIONS.contains(&header) {
        metrics::counter!(
            "mcpg_protocol_version_legacy_total",
            "version" => header.to_owned(),
        )
        .increment(1);
        return Ok(());
    }
    // Accept modern wire strings through the shared version vocabulary
    // (`ProtocolVersion::parse`), which also takes the pre-final
    // `DRAFT-2026-v1` alias — the registry-driven dispatch path below
    // resolves either spelling to the modern handler.
    if crate::protocol::version::ProtocolVersion::parse(header)
        == Some(crate::protocol::version::ProtocolVersion::V_2026_07_28)
    {
        metrics::counter!(
            "mcpg_protocol_version_modern_total",
            "version" => header.to_owned(),
        )
        .increment(1);
        return Ok(());
    }
    Err(unsupported_protocol_version_response(
        header,
        body_id.cloned(),
    ))
}

/// JSON-RPC error for a present-but-unservable `Mcp-Protocol-Version`.
/// Uses the MCP-reserved `UnsupportedProtocolVersion` code (`-32022`,
/// adopted in `2026-07-28`), matching the code the registry's
/// `into_rejection` emits, not the generic `-32600` (`InvalidRequest`)
/// which is reserved for a malformed header. The `error.data` here adds a
/// `kind` discriminator (the registry's variant omits it); both carry
/// `requested` + `supported`.
fn unsupported_protocol_version_response(requested: &str, body_id: Option<Value>) -> Response {
    // Advertise every revision MCPG can actually serve, not just
    // the default, so a client receiving the error can pick a working
    // revision without trial-and-error.
    let mut supported: Vec<String> = crate::protocol::LEGACY_PROTOCOL_VERSIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    supported.push(crate::protocol::SUPPORTED_PROTOCOL_VERSION.to_owned());
    supported.push(crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION.to_owned());
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": body_id.unwrap_or(Value::Null),
        "error": {
            "code": crate::protocol::shared::error::UNSUPPORTED_PROTOCOL_VERSION_CODE,
            "message": "Unsupported protocol version",
            "data": {
                "kind": "unsupported_protocol_version",
                "requested": requested,
                "supported": supported,
            }
        }
    });
    protocol_version_error_response(body)
}

/// JSON-RPC error for a malformed (non-UTF-8) `Mcp-Protocol-Version`
/// header. Uses `-32600` (`InvalidRequest`) — the header is unparseable,
/// not merely an unsupported revision.
fn invalid_request_protocol_version(body_id: Option<Value>) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": body_id.unwrap_or(Value::Null),
        "error": {
            "code": -32600,
            "message": "Mcp-Protocol-Version header is not valid UTF-8",
        }
    });
    protocol_version_error_response(body)
}

/// Shared 400 + JSON body + `Mcp-Protocol-Version` response header used by
/// both protocol-version rejection paths. The id is carried in the body
/// (SEP-2575 mandates error responses correlate against the request id).
fn protocol_version_error_response(body: Value) -> Response {
    use axum::http::StatusCode;
    let mut resp = (StatusCode::BAD_REQUEST, Json(body)).into_response();
    resp.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::SUPPORTED_PROTOCOL_VERSION),
    );
    resp
}

pub(crate) fn validate_post_content_type(
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Option<Response> {
    let Some(value) = headers.get(axum::http::header::CONTENT_TYPE) else {
        return Some(with_request_id_header(
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
            request_id,
        ));
    };
    let Ok(ct) = value.to_str() else {
        return Some(with_request_id_header(
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
            request_id,
        ));
    };
    // Accept "application/json" with optional parameters (charset, etc.).
    // Compare only the media-type token (before any ';' parameter),
    // case-insensitively, so "application/json-patch+json" and friends
    // don't slip past a bare prefix check.
    let media_type = ct.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case(JSON_ACCEPT) {
        return None;
    }
    Some(with_request_id_header(
        axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
        request_id,
    ))
}

pub(crate) fn validate_get_accept(
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Option<Response> {
    let Some(value) = headers.get(axum::http::header::ACCEPT) else {
        return Some(with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            request_id,
        ));
    };
    let Ok(accepts) = value.to_str() else {
        return Some(with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            request_id,
        ));
    };
    // parse Accept as comma-separated media ranges instead of a
    // substring match. `text/event-streamXYZ` and `;q=0` must both be
    // rejected per RFC 9110 §12.5.1.
    if accept_list_includes(accepts, SSE_ACCEPT) {
        return None;
    }

    Some(with_request_id_header(
        axum::http::StatusCode::BAD_REQUEST.into_response(),
        request_id,
    ))
}

/// Returns true when `header_value` parses as a comma-separated media
/// range list that contains `media` with a non-zero quality. Quality
/// values, trailing params, and surrounding whitespace are tolerated.
pub(crate) fn accept_list_includes(header_value: &str, media: &str) -> bool {
    for entry in header_value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';');
        let Some(range) = parts.next() else { continue };
        let range = range.trim();
        if !range.eq_ignore_ascii_case(media) && range != "*/*" {
            continue;
        }
        // If an explicit q=0 is present, treat as rejection.
        let mut accepted = true;
        for param in parts {
            let p = param.trim();
            if let Some(q) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(v) = q.parse::<f32>()
                && v <= 0.0
            {
                accepted = false;
            }
        }
        if accepted {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod accept_tests {
    use super::super::SSE_ACCEPT;
    use super::accept_list_includes;

    #[test]
    fn exact_match_accepted() {
        assert!(accept_list_includes(SSE_ACCEPT, SSE_ACCEPT));
    }

    #[test]
    fn wildcard_range_accepted() {
        assert!(accept_list_includes("*/*", SSE_ACCEPT));
    }

    #[test]
    fn prefix_collision_rejected() {
        assert!(!accept_list_includes("text/event-streamXYZ", SSE_ACCEPT));
    }

    #[test]
    fn multiple_ranges_tolerated() {
        assert!(accept_list_includes(
            "application/json, text/event-stream;q=0.9",
            SSE_ACCEPT,
        ));
    }

    #[test]
    fn q_zero_rejected() {
        assert!(!accept_list_includes("text/event-stream;q=0", SSE_ACCEPT));
    }

    #[test]
    fn missing_media_rejected() {
        assert!(!accept_list_includes("application/json", SSE_ACCEPT));
    }
}
