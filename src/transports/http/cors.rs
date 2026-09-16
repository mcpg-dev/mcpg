//! Cross-origin access for browser clients (`server.cors`).
//!
//! `server.allowed_origins` is the MCP DNS-rebinding guard: it inspects the
//! `Origin` of requests that arrive. It grants a browser nothing — a page
//! calling `/mcp` with `Content-Type: application/json` and the MCP headers
//! always preflights first, and a gateway that answers no preflight is a
//! gateway no page can call, however the guard is configured. This module is
//! the other half: the preflight answer, and the response headers that let
//! script read what it needs.
//!
//! Two rules shape it. A listed origin is echoed back rather than answered
//! with `*`, because `*` is refused outright with credentials and is a
//! standing invitation without them; and an unlisted origin is refused with
//! no CORS headers at all, which is what makes the browser block it.

use super::*;

/// Answer a preflight, or stamp the response headers on a cross-origin call.
///
/// Runs for every route. A request with no `Origin` is not cross-origin and is
/// passed through untouched — that is every non-browser client, which is most
/// of them.
pub(crate) async fn cors_layer(
    cfg: std::sync::Arc<crate::config::CorsConfig>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(origin) = req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return next.run(req).await;
    };
    let allowed = origin_allowed(&cfg.allowed_origins, &origin);

    if req.method() == axum::http::Method::OPTIONS
        && req
            .headers()
            .contains_key(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        // A preflight is answered here and never reaches a route: the MCP path
        // has no OPTIONS handler, and a 405 tells the browser nothing.
        let mut response = axum::http::StatusCode::NO_CONTENT.into_response();
        if allowed {
            stamp_common(response.headers_mut(), &cfg, &origin);
            let headers = response.headers_mut();
            insert(
                headers,
                "access-control-allow-methods",
                "GET, POST, DELETE, OPTIONS",
            );
            insert(
                headers,
                "access-control-allow-headers",
                &cfg.allowed_headers.join(", "),
            );
            insert(
                headers,
                "access-control-max-age",
                &cfg.max_age_secs.to_string(),
            );
        }
        // `Vary: Origin` even when refused: the answer depends on the origin,
        // and a cache that missed that would serve one page's refusal to
        // another page's request.
        vary_on_origin(response.headers_mut());
        return response;
    }

    let mut response = next.run(req).await;
    if allowed {
        stamp_common(response.headers_mut(), &cfg, &origin);
        insert(
            response.headers_mut(),
            "access-control-expose-headers",
            &cfg.expose_headers.join(", "),
        );
    }
    vary_on_origin(response.headers_mut());
    response
}

/// Case-insensitive origin match, trailing dot stripped — the same comparison
/// the rebinding guard makes, so the two cannot disagree about what an origin
/// is.
pub(crate) fn origin_allowed(allowed: &[String], origin: &str) -> bool {
    let normalise = |o: &str| o.trim().trim_end_matches('.').to_ascii_lowercase();
    let origin = normalise(origin);
    allowed.iter().any(|a| normalise(a) == origin)
}

fn stamp_common(
    headers: &mut axum::http::HeaderMap,
    cfg: &crate::config::CorsConfig,
    origin: &str,
) {
    insert(headers, "access-control-allow-origin", origin);
    if cfg.allow_credentials {
        insert(headers, "access-control-allow-credentials", "true");
    }
}

fn vary_on_origin(headers: &mut axum::http::HeaderMap) {
    let existing = headers
        .get(axum::http::header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if existing
        .split(',')
        .any(|v| v.trim().eq_ignore_ascii_case("origin"))
    {
        return;
    }
    let merged = if existing.is_empty() {
        "Origin".to_owned()
    } else {
        format!("{existing}, Origin")
    };
    insert(headers, "vary", &merged);
}

fn insert(headers: &mut axum::http::HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = axum::http::HeaderValue::from_str(value) {
        headers.insert(axum::http::HeaderName::from_static(name), value);
    }
}
