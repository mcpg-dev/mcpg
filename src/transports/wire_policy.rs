//! Wire-version policy for the HTTP transport.
//!
//! The gateway serves two MCP wire revisions over the same HTTP
//! endpoint: the legacy `2025-11-25` protocol and the modern
//! `2026-07-28` protocol. They differ in a handful of transport-level
//! decisions — which protocol-version header a response echoes, whether
//! `Mcp-Session-Id` is surfaced, whether GET/DELETE are served, and how
//! a modern `tools/call` result is framed. [`WireVersion`] gathers those
//! decisions so the request path reads one policy value instead of
//! scattering `if is_modern { … }` branches, keeping the two wires'
//! bytes identical to their historical shapes.

use std::convert::Infallible;

use axum::{
    http::{HeaderMap, HeaderName, HeaderValue},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use serde_json::Value;
use tokio_stream::iter;

use crate::protocol::PROTOCOL_VERSION_HEADER;
use crate::runtime::GatewayRuntime;

/// The MCP wire revision a request negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireVersion {
    /// `2025-11-25` — long-lived SSE delivery channel, exposes
    /// `Mcp-Session-Id`, serves GET/DELETE.
    Legacy,
    /// `2026-07-28` — stateless (SEP-2567/2575): hides `Mcp-Session-Id`,
    /// POST-only, per-request SSE framing for streamable `tools/call`.
    Modern,
}

/// What a POST negotiated: the revision it speaks and, when that is the
/// modern one, the handler that will serve it.
///
/// The two travel together because they come from one registry selection.
/// Deriving them separately is what let a request's early error exits stamp a
/// different revision than its dispatch used.
pub(crate) struct Negotiated {
    pub(crate) wire: WireVersion,
    /// `Some` iff `wire` is [`WireVersion::Modern`].
    pub(crate) modern_handler:
        Option<std::sync::Arc<dyn crate::protocol::shared::traits::ProtocolHandler>>,
}

impl WireVersion {
    /// Negotiate the revision for a POST whose body has been parsed.
    ///
    /// This is the request path's single negotiation point: everything
    /// downstream — the dispatch, the response framing, the version header on
    /// every exit — reads the result rather than re-deriving it.
    pub(crate) fn negotiate(
        runtime: &GatewayRuntime,
        headers: &HeaderMap,
        body: &Value,
    ) -> Negotiated {
        let modern_handler = runtime
            .protocol_registry
            .load_full()
            .and_then(|registry| registry.select(headers, body).ok().cloned())
            .filter(|handler| {
                matches!(
                    handler.version(),
                    crate::protocol::version::ProtocolVersion::V_2026_07_28
                )
            });
        Negotiated {
            wire: if modern_handler.is_some() {
                Self::Modern
            } else {
                Self::Legacy
            },
            modern_handler,
        }
    }

    /// Resolve the negotiated revision from the HTTP headers alone.
    ///
    /// Only for requests that have no JSON-RPC body to consult: GET, DELETE,
    /// and the POST exit where the body failed to parse. Every other site
    /// takes [`Self::negotiate`]'s result, which sees the body the dispatch
    /// will see.
    ///
    /// Falls back to [`WireVersion::Legacy`] when no registry is
    /// installed or the version cannot be resolved — GET/DELETE stay
    /// served and pre-negotiation errors echo the legacy revision.
    pub(crate) fn from_headers(runtime: &GatewayRuntime, headers: &HeaderMap) -> Self {
        Self::negotiate(runtime, headers, &Value::Null).wire
    }

    /// True iff this is the modern (`2026-07-28`) stateless wire.
    pub(crate) fn is_modern(self) -> bool {
        matches!(self, Self::Modern)
    }

    /// Echo the negotiated protocol version on a response. The shared
    /// response mappers stamp the legacy default because they run before
    /// wire selection; a modern exit re-stamps the modern revision here,
    /// while a legacy exit keeps the mapper default untouched.
    pub(crate) fn apply_protocol_version_header(self, response: Response) -> Response {
        match self {
            Self::Modern => with_modern_protocol_version_header(response),
            Self::Legacy => response,
        }
    }
}

/// Overwrite the `Mcp-Protocol-Version` response header with the modern
/// revision.
fn with_modern_protocol_version_header(mut response: Response) -> Response {
    response.headers_mut().insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION),
    );
    response
}

/// Is a modern `tools/call` result eligible for the per-request SSE
/// response stream? Only a terminal `resultType:"complete"` is — the
/// result is the stream's terminating frame. A result carrying
/// `resultType:"input_required"` (MRTR suspension, the client must act on
/// it and re-issue) or `resultType:"task"` (server-directed task
/// materialization, the client polls `tasks/get`) is NEVER streamed:
/// those are control results, not the tool's terminal output. The
/// SEP-2322 default — a result with no `resultType` is treated as
/// `"complete"` — applies, though the modern handler stamps `"complete"`
/// explicitly on the tool-call path.
pub(crate) fn modern_result_is_streamable_complete(result: &Value) -> bool {
    match result.get("resultType").and_then(Value::as_str) {
        Some("complete") | None => true,
        Some(_) => false,
    }
}

/// Frame a modern (`2026-07-28`) `tools/call` response as a per-request
/// SSE stream — the `text/event-stream` body the spec's preferred shape
/// calls for. Each frame is the JSON-RPC notification
/// (`notifications/progress` / `notifications/message`) the request
/// emitted, in order, followed by the terminal JSON-RPC response frame;
/// the stream then closes. Unlike the legacy SSE path, NO SSE event `id:`
/// field is assigned (modern streams are not resumable, TS-11) and no
/// `Mcp-Session-Id` is attached (TS-09). The `message` event name matches
/// the legacy framing the spec and MCPG already use.
pub(crate) fn map_modern_response_stream(frames: Vec<String>) -> Response {
    let stream = iter(frames.into_iter().map(|data| {
        let event: Result<Event, Infallible> = Ok(Event::default().event("message").data(data));
        event
    }));
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
