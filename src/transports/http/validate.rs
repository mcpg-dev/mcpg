//! Header and origin validation for the HTTP transport.
//!
//! Each function returns `Some(Response)` for a rejection and `None` when the
//! request may proceed, so a handler reads as a list of gates.

use super::*;

/// Whether the rebinding guard would admit `origin` under `allowed_origins` —
/// the same rule [`validate_origin`] applies, exposed so config validation can
/// ask the guard instead of reimplementing it.
pub fn origin_admitted(allowed_origins: &[String], origin: &str) -> bool {
    let origin_lower = origin.trim().trim_end_matches('.').to_ascii_lowercase();
    if allowed_origins.is_empty() {
        return is_loopback_origin(&origin_lower);
    }
    allowed_origins
        .iter()
        .any(|candidate| candidate.trim_end_matches('.').to_ascii_lowercase() == origin_lower)
}

pub(crate) fn validate_origin(
    headers: &HeaderMap,
    allowed_origins: &[String],
    request_id: &GatewayRequestId,
) -> Option<Response> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
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

/// Gate a POST's `Accept`. `Err` is the `400` for a header that does not
/// admit `application/json`; `Ok` says whether it also admits
/// `text/event-stream`, i.e. whether this client consented to an SSE upgrade.
pub(crate) fn validate_post_accept(
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Result<bool, Response> {
    // The Streamable HTTP Accept advertisement is
    // `application/json, text/event-stream`: a client that may receive an
    // SSE response lists both. A client that never needs SSE (MRTR answers
    // inline, and most methods never stream) legitimately lists only
    // `application/json`.
    //
    // Policy: accept `application/json` as the minimum. If the client
    // also lists SSE, MCPG may answer with a stream; if not, the response
    // stays inline JSON.
    match headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(admitted_media)
    {
        Some(AdmittedMedia { json: true, sse }) => Ok(sse),
        _ => Err(with_request_id_header(
            axum::http::StatusCode::BAD_REQUEST.into_response(),
            request_id,
        )),
    }
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

/// Which of `application/json` and `text/event-stream` an `Accept` value
/// admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmittedMedia {
    json: bool,
    sse: bool,
}

/// Read `header_value` as a comma-separated media range list: a media type is
/// admitted when an entry names it, or is `*/*`, with a non-zero quality.
/// Quality values, trailing params, and surrounding whitespace are tolerated;
/// a prefix collision (`text/event-streamXYZ`) and `;q=0` are refused (RFC
/// 9110 §12.5.1).
fn admitted_media(header_value: &str) -> AdmittedMedia {
    let mut admitted = AdmittedMedia {
        json: false,
        sse: false,
    };
    for entry in header_value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';');
        let Some(range) = parts.next() else { continue };
        let range = range.trim();
        let any = range == "*/*";
        let json = any || range.eq_ignore_ascii_case(JSON_ACCEPT);
        let sse = any || range.eq_ignore_ascii_case(SSE_ACCEPT);
        if !json && !sse {
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
            admitted.json |= json;
            admitted.sse |= sse;
            if admitted.json && admitted.sse {
                break;
            }
        }
    }
    admitted
}

#[cfg(test)]
mod accept_tests {
    use super::super::SSE_ACCEPT;
    use super::{AdmittedMedia, admitted_media};

    fn admits_sse(header_value: &str) -> bool {
        admitted_media(header_value).sse
    }

    #[test]
    fn exact_match_accepted() {
        assert!(admits_sse(SSE_ACCEPT));
    }

    #[test]
    fn wildcard_range_accepted() {
        assert!(admits_sse("*/*"));
    }

    #[test]
    fn prefix_collision_rejected() {
        assert!(!admits_sse("text/event-streamXYZ"));
    }

    #[test]
    fn multiple_ranges_tolerated() {
        assert!(admits_sse("application/json, text/event-stream;q=0.9"));
    }

    #[test]
    fn q_zero_rejected() {
        assert!(!admits_sse("text/event-stream;q=0"));
    }

    #[test]
    fn missing_media_rejected() {
        assert!(!admits_sse("application/json"));
    }

    /// Each media type is decided on its own: a refused entry for one never
    /// hides a later entry that admits it, and `*/*` admits both.
    #[test]
    fn json_and_sse_are_decided_in_one_pass() {
        let both = AdmittedMedia {
            json: true,
            sse: true,
        };
        assert_eq!(admitted_media("application/json, text/event-stream"), both);
        assert_eq!(admitted_media("*/*"), both);
        assert_eq!(admitted_media("text/event-stream;q=0, */*"), both);
        assert_eq!(
            admitted_media("APPLICATION/JSON"),
            AdmittedMedia {
                json: true,
                sse: false,
            }
        );
        assert_eq!(
            admitted_media("application/json;q=0, text/event-stream"),
            AdmittedMedia {
                json: false,
                sse: true,
            }
        );
        assert_eq!(
            admitted_media("application/json-patch+json, text/html"),
            AdmittedMedia {
                json: false,
                sse: false,
            }
        );
    }
}
