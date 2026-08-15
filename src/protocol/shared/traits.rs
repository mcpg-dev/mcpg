//! The single trait that defines what a per-version protocol adapter
//! looks like.
//!
//! Each protocol revision (`v_2025_11_25`, `v_2026_07_28`, ...)
//! provides exactly one [`ProtocolHandler`] implementation. The
//! runtime's [`ProtocolRegistry`](crate::protocol::registry::ProtocolRegistry)
//! picks the right handler for an inbound request based on the
//! negotiated version and delegates parsing, validation, and dispatch
//! to it.
//!
//! ## Lifecycle
//!
//! For a single request:
//! 1. Transport reads headers + body bytes.
//! 2. `ProtocolRegistry::select` picks a handler.
//! 3. `handler.validate_transport_headers(&headers, &body)` rejects on
//!    mismatch — short-circuit response.
//! 4. `handler.parse(body)` → `ProtocolMessage`.
//! 5. `handler.long_lived_stream_plan(&ctx, &msg)` — if `Some`, the
//!    transport switches to SSE streaming and the dispatcher writes
//!    events into the stream's channel. If `None`, dispatch produces
//!    a single response.
//! 6. `handler.dispatch(&ctx, msg, &services)` → `ProtocolHttpResponse`.
//! 7. Transport serializes and writes.
//!
//! Pipeline suspension and resumption are NOT part of this trait. Both wires
//! shape those responses where the suspension is detected — in
//! `runtime::handlers::tools_call` and `runtime::delivery` — branching on the
//! negotiated version inline.

use async_trait::async_trait;
use axum::http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::messages::{ProtocolMessage, TransportRejection};
use crate::protocol::version::ProtocolVersion;
use crate::protocol::{ProtocolError, ProtocolHttpResponse};
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;

/// Per-version protocol adapter.
///
/// Every implementation lives under `protocol/v_<date>/`. The version's
/// handler owns:
/// - the wire-format types (structs / enums)
/// - the method-name → operation routing table
/// - the header-validation rules (HTTP-layer)
/// - the dispatch arms that turn parsed operations into responses
/// - the suspension / resumption envelope (legacy SSE + bus vs modern
///   MRTR)
///
/// The trait is the single seam between version-specific logic and the
/// version-blind runtime substrate (backends, plugins, gates, cluster).
#[async_trait]
pub trait ProtocolHandler: Send + Sync + 'static {
    /// Wire-string identity. e.g., `"2025-11-25"`, `"DRAFT-2026-v1"`.
    fn version_string(&self) -> &'static str;

    /// Typed identity. Used inside the gateway for routing decisions
    /// and metric labels.
    fn version(&self) -> ProtocolVersion;

    /// Per-version header validation. Returns
    /// `Err(TransportRejection)` on rejection; the transport converts
    /// that into an HTTP response.
    ///
    /// Called by the HTTP transport before [`parse`](Self::parse).
    /// Implementations should validate any version-specific headers
    /// (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-{Name}` on modern; legacy
    /// accepts silently). The body is provided for body↔header
    /// consistency checks.
    fn validate_transport_headers(
        &self,
        headers: &HeaderMap,
        body: &Value,
    ) -> Result<(), TransportRejection>;

    /// Parse a JSON body into this version's typed operation. The
    /// returned [`ProtocolMessage`] is opaque to callers; only this
    /// handler's [`dispatch`](Self::dispatch) understands the boxed
    /// inner type.
    fn parse(&self, body: Value) -> Result<ProtocolMessage, ProtocolError>;

    /// Dispatch a parsed operation. Returns a complete wire-shaped
    /// response ready for the transport to emit.
    async fn dispatch(
        &self,
        ctx: &RequestContext,
        op: ProtocolMessage,
        services: &SharedServices,
    ) -> ProtocolHttpResponse;
}
