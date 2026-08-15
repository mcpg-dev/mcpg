//! [`ProtocolHandler`] implementation for MCP revision `2025-11-25`.
//!
//! [`Handler`] is the concrete adapter the
//! [`ProtocolRegistry`](crate::protocol::registry::ProtocolRegistry)
//! resolves to when an inbound request negotiates the `2025-11-25`
//! wire revision. It is stateless — every service it needs is
//! reached through the [`SharedServices`] bundle it receives on
//! `dispatch`.
//!
//! ## What this layer does
//!
//! - Parses request bodies into the version's
//!   [`ProtocolOperation`] enum (delegating to
//!   `parse_client_message` + `map_client_message_to_operation`).
//! - Wraps the parsed operation in a version-erased
//!   [`ProtocolMessage`] carrying its label + `jsonrpc_id`.
//! - Dispatches by calling the existing
//!   [`GatewayRuntime::handle_protocol_operation`] arms — the 13-stage
//!   tools/call pipeline, lifecycle handlers, task store, delivery
//!   bus, plugin chains, etc. all stay where they are. The handler is
//!   a thin shim.
//!
//! ## What it does not own
//!
//! Suspension shaping. When a pipeline suspends, the response is built
//! where the suspension is detected — `runtime::handlers::tools_call`
//! and `runtime::delivery` — not here, and those sites branch on the
//! negotiated version inline.

use async_trait::async_trait;
use axum::http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::error::ProtocolError;
use crate::protocol::shared::jsonrpc::handler_internal_error;
use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, parse_client_message};
use crate::protocol::shared::messages::{ProtocolMessage, TransportRejection};
use crate::protocol::shared::traits::ProtocolHandler;
use crate::protocol::v_2025_11_25::wire::SUPPORTED_PROTOCOL_VERSION;
use crate::protocol::v_2025_11_25::wire::operations::ProtocolOperation;
use crate::protocol::v_2025_11_25::wire::routing::map_client_message_to_operation;
use crate::protocol::version::ProtocolVersion;
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;

/// Per-version handler for MCP revision `2025-11-25`.
///
/// Stateless: `Handler::new()` is `Handler` (no fields). All state
/// reaches the handler via [`SharedServices`] at dispatch time.
#[derive(Debug, Clone, Default)]
pub struct Handler;

impl Handler {
    /// Construct the handler. The single instance is registered into
    /// the [`ProtocolRegistry`](crate::protocol::registry::ProtocolRegistry)
    /// at boot.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for Handler {
    fn version_string(&self) -> &'static str {
        SUPPORTED_PROTOCOL_VERSION
    }

    fn version(&self) -> ProtocolVersion {
        ProtocolVersion::V_2025_11_25
    }

    /// 2025-11-25 transports do not enforce any body↔header
    /// consistency rules at the protocol-handler level. The
    /// `Mcp-Protocol-Version` header is already validated by the
    /// [`ProtocolRegistry`](crate::protocol::registry::ProtocolRegistry)
    /// before this handler is selected; `Mcp-Method` /
    /// `Mcp-Name` / `Mcp-Param-{Name}` are SEP-2243 additions that
    /// only the modern wire requires. The `Origin` / `Accept` /
    /// `Content-Type` checks stay at the transport layer.
    fn validate_transport_headers(
        &self,
        _headers: &HeaderMap,
        _body: &Value,
    ) -> Result<(), TransportRejection> {
        Ok(())
    }

    /// Parse a JSON body into a [`ProtocolMessage`] carrying this
    /// version's [`ProtocolOperation`] enum.
    ///
    /// Two-step under the hood: `parse_client_message` produces a
    /// [`ClientMessage`](crate::protocol::shared::jsonrpc::ClientMessage)
    /// (validates JSON-RPC envelope + `_meta` reserved-prefix rules);
    /// `map_client_message_to_operation` then routes by `method` to
    /// the right operation variant.
    fn parse(&self, body: Value) -> Result<ProtocolMessage, ProtocolError> {
        // Capture the wire method string before mapping; it is lost
        // once the message becomes a typed `ProtocolOperation` and
        // future SEP-2243 (`Mcp-Method` header) validation will want
        // it in `ProtocolMessage`.
        let mcp_method = match &body {
            v if v.is_object() => v.get("method").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        };

        let message = parse_client_message(body)?;
        let operation = map_client_message_to_operation(message)?;
        let label = operation.label();
        let jsonrpc_id = operation.client_request_id();

        Ok(ProtocolMessage {
            label,
            inner: Box::new(operation),
            jsonrpc_id,
            mcp_method,
            negotiated_version: ProtocolVersion::V_2025_11_25,
        })
    }

    /// Hand the parsed operation to the existing
    /// [`GatewayRuntime::handle_protocol_operation`] arms.
    ///
    /// The legacy dispatch path stays in `runtime/mod.rs` for the
    /// 2025-11-25 era; this method is a thin shim that loads the
    /// current swap epoch of the runtime and delegates.
    async fn dispatch(
        &self,
        ctx: &RequestContext,
        op: ProtocolMessage,
        services: &SharedServices,
    ) -> ProtocolHttpResponse {
        // Downcast the boxed payload into this version's
        // `ProtocolOperation`. A mismatch here means the wrong
        // handler was picked for this message — a registry-routing
        // bug, not a wire error.
        let jsonrpc_id = op.jsonrpc_id.clone();
        let operation = match op.downcast::<ProtocolOperation>() {
            Ok(operation) => *operation,
            Err(_) => {
                tracing::error!(
                    "v_2025_11_25::Handler::dispatch received a ProtocolMessage \
                     whose inner type is not ProtocolOperation — registry routing bug"
                );
                return handler_internal_error(
                    jsonrpc_id,
                    "internal handler routing error: wrong operation type for v_2025_11_25",
                );
            }
        };

        let Some(runtime_handle) = services.runtime() else {
            // Only reachable if the runtime is being torn down while a
            // request is still in flight — should not happen in a
            // healthy gateway. Surface a clear -32603 so a client
            // sees something diagnosable rather than a hang.
            tracing::error!(
                request_id = ctx.request_id.as_str(),
                "v_2025_11_25::Handler::dispatch — SharedServices.runtime Weak failed to upgrade; \
                 the gateway is shutting down or AppState dropped"
            );
            return handler_internal_error(jsonrpc_id, "gateway runtime is shutting down");
        };
        let runtime = runtime_handle.load();
        runtime.handle_protocol_operation(operation, ctx).await
    }
}

/// Build a generic JSON-RPC `-32603 InternalError` response with the
/// given message. Used by the handler shim for paths that should be
/// unreachable in practice (routing bugs, premature suspension-seam calls).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v_2025_11_25::wire::tasks::RELATED_TASK_META_KEY;

    #[test]
    fn handler_version_identity() {
        let h = Handler::new();
        assert_eq!(h.version_string(), "2025-11-25");
        assert_eq!(h.version(), ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn validate_transport_headers_accepts_any_request() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        });
        assert!(
            h.validate_transport_headers(&HeaderMap::new(), &body)
                .is_ok()
        );
    }

    #[test]
    fn parse_routes_initialize_into_protocol_message() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "t", "version": "0" }
            }
        });
        let msg = h.parse(body).expect("parse ok");
        assert_eq!(msg.label, "lifecycle.initialize");
        assert_eq!(msg.jsonrpc_id, Some(serde_json::json!(1)));
        assert_eq!(msg.mcp_method.as_deref(), Some("initialize"));
        assert_eq!(msg.negotiated_version, ProtocolVersion::V_2025_11_25);
        // Inner is downcastable back to ProtocolOperation.
        let Ok(op) = msg.downcast::<ProtocolOperation>() else {
            panic!("inner should be ProtocolOperation");
        };
        assert!(matches!(
            *op,
            ProtocolOperation::Lifecycle(
                crate::protocol::v_2025_11_25::wire::operations::LifecycleOperation::Initialize { .. }
            )
        ));
    }

    #[test]
    fn parse_propagates_protocol_error_for_unknown_method() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "this/does/not/exist"
        });
        let Err(err) = h.parse(body) else {
            panic!("unknown method must produce ProtocolError::method_not_found");
        };
        assert_eq!(err.code(), -32601);
    }

    #[test]
    fn parse_captures_notification_method() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let msg = h.parse(body).expect("parse ok");
        assert_eq!(msg.label, "lifecycle.initialized");
        // Notifications carry no jsonrpc_id.
        assert!(msg.jsonrpc_id.is_none());
        assert_eq!(msg.mcp_method.as_deref(), Some("notifications/initialized"));
    }

    #[test]
    fn related_task_meta_inject_preserves_existing_meta() {
        let params = serde_json::json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "_meta": { "traceparent": "00-deadbeef-cafef00d-01" }
        });
        let injected =
            crate::protocol::v_2025_11_25::wire::tasks::inject_related_task_meta(params, "task-42");
        let meta = &injected["_meta"];
        // Existing traceparent stays.
        assert_eq!(meta["traceparent"], "00-deadbeef-cafef00d-01");
        // related-task is added under the spec-reserved key.
        assert_eq!(
            meta[RELATED_TASK_META_KEY]["taskId"], "task-42",
            "related-task meta added under spec-reserved key, alongside existing _meta entries"
        );
    }

    #[test]
    fn related_task_meta_inject_creates_meta_when_missing() {
        let params = serde_json::json!({ "messages": [] });
        let injected =
            crate::protocol::v_2025_11_25::wire::tasks::inject_related_task_meta(params, "task-1");
        assert_eq!(injected["_meta"][RELATED_TASK_META_KEY]["taskId"], "task-1");
        assert!(injected["messages"].is_array(), "messages preserved");
    }

    #[test]
    fn related_task_meta_inject_handles_non_object_params() {
        // Defensive: if upstream passed something weird (e.g. `null`),
        // we coerce to an object so the meta injection lands somewhere.
        let injected = crate::protocol::v_2025_11_25::wire::tasks::inject_related_task_meta(
            serde_json::Value::Null,
            "task-x",
        );
        assert!(injected.is_object());
        assert_eq!(injected["_meta"][RELATED_TASK_META_KEY]["taskId"], "task-x");
    }
}
