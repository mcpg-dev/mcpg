//! Transport layer — pluggable wire transports for the MCP gateway.
//!
//! Currently supports HTTP/SSE (`http`), stdio (`stdio`), and the
//! outbound relay tunnel (`tunnel`).
//! Also defines the shared `TraceContext` for W3C trace propagation.

pub mod anon_limit;
pub mod http;
pub mod http_route;
pub mod stdio;
pub mod tls;
pub mod tunnel;
pub mod wire_policy;

/// Pub(crate) bridge used by [`http_route`] to build a
/// [`crate::runtime::RequestContext`] from the inbound HTTP headers.
/// Lives here so the http_route dispatcher doesn't have to re-implement
/// the identity resolution pipeline.
///
/// `tls_info` carries the per-connection TLS metadata that the
/// [`tls::McpgTlsAcceptor`] stamped onto the request — passing
/// `None` is correct for plain-HTTP requests or when the route
/// dispatcher couldn't recover an extension (defensive on
/// transport flips).
pub(crate) async fn http_request_context(
    headers: &axum::http::HeaderMap,
    runtime: &crate::runtime::GatewayRuntime,
    tls_info: Option<tls::TlsInfoArc>,
    trust_subject_header: bool,
    method: &axum::http::Method,
    path: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<crate::runtime::RequestContext, axum::response::Response> {
    http::build_full_request_context(
        headers,
        runtime,
        tls_info,
        trust_subject_header,
        method,
        path,
        peer_ip,
    )
    .await
}

use serde::{Deserialize, Serialize};

/// W3C Trace Context (traceparent + tracestate) extracted from inbound requests.
/// See <https://www.w3.org/TR/trace-context/>
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceContext {
    /// Full `traceparent` header value, e.g. `00-<trace_id>-<parent_id>-<flags>`
    pub traceparent: String,
    /// Optional `tracestate` header value (vendor-specific key-value pairs)
    pub tracestate: Option<String>,
    /// Parsed 16-byte trace ID (hex-encoded, 32 chars)
    pub trace_id: String,
    /// Parsed 8-byte parent span ID (hex-encoded, 16 chars)
    pub parent_span_id: String,
    /// Trace flags (1 byte)
    pub trace_flags: u8,
}

impl TraceContext {
    /// Parse a W3C `traceparent` header value.
    /// Format: `version-trace_id-parent_id-trace_flags` (all hex, dash-separated)
    /// Returns `None` if the header is missing, empty, or malformed.
    pub fn parse(traceparent: &str, tracestate: Option<&str>) -> Option<Self> {
        let traceparent = traceparent.trim();
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() < 4 {
            return None;
        }

        let version = parts[0];
        let trace_id = parts[1];
        let parent_span_id = parts[2];
        let flags_str = parts[3];

        // Version must be 2 hex chars
        if version.len() != 2 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        // trace-id: 32 hex chars, must not be all zeros
        if trace_id.len() != 32
            || !trace_id.chars().all(|c| c.is_ascii_hexdigit())
            || trace_id.chars().all(|c| c == '0')
        {
            return None;
        }
        // parent-id: 16 hex chars, must not be all zeros
        if parent_span_id.len() != 16
            || !parent_span_id.chars().all(|c| c.is_ascii_hexdigit())
            || parent_span_id.chars().all(|c| c == '0')
        {
            return None;
        }
        // flags: 2 hex chars
        if flags_str.len() != 2 || !flags_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let trace_flags = u8::from_str_radix(flags_str, 16).ok()?;

        // For version 00, reject if there are extra fields (future version may have them)
        if version == "00" && parts.len() != 4 {
            return None;
        }

        Some(Self {
            traceparent: traceparent.to_owned(),
            tracestate: tracestate
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
            trace_id: trace_id.to_lowercase(),
            parent_span_id: parent_span_id.to_lowercase(),
            trace_flags,
        })
    }

    /// Generate a new `traceparent` header for a child span.
    /// Creates a new random span ID while preserving trace_id and flags.
    pub fn child_traceparent(&self) -> String {
        let child_span_id = Self::random_span_id();
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, child_span_id, self.trace_flags
        )
    }

    /// (SEP-414): render this trace context as a `_meta` object
    /// suitable for inclusion on outbound JSON-RPC params. Draft SEP;
    /// the field names are `traceparent` (child span derived from this
    /// context) and optional `tracestate`, kept at the top level of
    /// `_meta` as the SEP currently proposes.
    pub fn to_meta_object(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "traceparent".to_owned(),
            serde_json::Value::String(self.child_traceparent()),
        );
        if let Some(ref ts) = self.tracestate {
            map.insert(
                "tracestate".to_owned(),
                serde_json::Value::String(ts.clone()),
            );
        }
        serde_json::Value::Object(map)
    }

    /// (SEP-414): attempt to parse a TraceContext out of an
    /// inbound `params._meta` object. Returns `None` when the expected
    /// fields are missing or malformed.
    pub fn from_meta_object(meta: &serde_json::Value) -> Option<Self> {
        let obj = meta.as_object()?;
        let traceparent = obj.get("traceparent")?.as_str()?;
        let tracestate = obj.get("tracestate").and_then(|v| v.as_str());
        Self::parse(traceparent, tracestate)
    }

    /// Generate a random 8-byte span ID as 16 hex chars.
    fn random_span_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        // Mix nanos + thread id for uniqueness
        let thread_id = std::thread::current().id();
        let hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            nanos.hash(&mut hasher);
            thread_id.hash(&mut hasher);
            hasher.finish()
        };
        format!("{:016x}", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_traceparent() {
        let ctx = TraceContext::parse(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            Some("congo=t61rcWkgMzE"),
        )
        .unwrap();
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
        assert_eq!(ctx.trace_flags, 1);
        assert_eq!(ctx.tracestate.as_deref(), Some("congo=t61rcWkgMzE"));
    }

    #[test]
    fn parse_traceparent_without_tracestate() {
        let ctx = TraceContext::parse(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
            None,
        )
        .unwrap();
        assert_eq!(ctx.trace_flags, 0);
        assert!(ctx.tracestate.is_none());
    }

    #[test]
    fn reject_all_zero_trace_id() {
        assert!(
            TraceContext::parse(
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn reject_all_zero_parent_id() {
        assert!(
            TraceContext::parse(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn reject_short_traceparent() {
        assert!(TraceContext::parse("00-abc-def-01", None).is_none());
    }

    #[test]
    fn reject_non_hex_characters() {
        assert!(
            TraceContext::parse(
                "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn reject_version_00_with_extra_fields() {
        assert!(
            TraceContext::parse(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn child_traceparent_preserves_trace_id_and_flags() {
        let ctx = TraceContext::parse(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            None,
        )
        .unwrap();
        let child = ctx.child_traceparent();
        assert!(child.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(child.ends_with("-01"));
        // Child span ID should NOT be the same as parent
        let parts: Vec<&str> = child.split('-').collect();
        assert_ne!(parts[2], "00f067aa0ba902b7");
        assert_eq!(parts[2].len(), 16);
    }

    #[test]
    fn parse_with_whitespace() {
        let ctx = TraceContext::parse(
            "  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01  ",
            Some("  "),
        )
        .unwrap();
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(ctx.tracestate.is_none()); // whitespace-only tracestate → None
    }

    #[test]
    fn uppercase_hex_normalized_to_lowercase() {
        let ctx = TraceContext::parse(
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
            None,
        )
        .unwrap();
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
    }
}
