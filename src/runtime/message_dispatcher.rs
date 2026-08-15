//! `MessageDispatcher` implementation wrapping the gateway runtime.
//!
//! Bridges the `Transport` entity's dispatcher callback onto the
//! existing `GatewayRuntime::handle_request` pipeline. A `Transport`
//! plugin receives raw MCP message bytes
//! and hands them to the dispatcher; the dispatcher parses
//! JSON-RPC, maps to a `GatewayOperation`, calls through to the
//! runtime, and serialises the response back to bytes.
//!
//! # Scope
//!
//! MVP ships identity-less dispatch: every message maps to
//! `RequestIdentity::Anonymous { source: "transport-dispatcher" }`.
//! The `MessageDispatcher::dispatch` signature doesn't carry
//! auth-bearing context today; a follow-up would extend the
//! trait (spec-level change) or add a transport-side auth hook
//! before HTTP / stdio migrations can replace their existing
//! identity-plugin wiring. For the memory transport + future
//! identity-less transports (local embedded use, internal
//! control-plane channels), anonymous identity is correct.
//!
//! # Transport kind label
//!
//! `TransportKind` is a typed enum with variants `Http` + `Stdio`.
//! No "Generic" variant exists; the dispatcher picks `Stdio` as
//! the closest-fit default (single-stream, frame-per-read
//! semantics match stdio more than HTTP). Operators observing
//! per-transport metrics see dispatcher traffic labeled as
//! `stdio` until a generic transport label is added.

use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use mcpg_plugin_protocol::transport::{DispatchResponse, DispatcherError, MessageDispatcher};

use crate::protocol::{ProtocolResponse, map_client_message_to_operation, parse_client_message};
use crate::runtime::{
    GatewayOperation, GatewayRequest, GatewayRequestId, GatewayResponsePayload, GatewayRuntime,
    RequestContext, RequestIdentity, ResumeCursor, TransportKind,
};

/// Runtime-side dispatcher the gateway hands to Transport
/// plugins. Holds an `ArcSwap<GatewayRuntime>` so hot-reload
/// propagates without restarting the Transport.
pub struct GatewayMessageDispatcher {
    runtime: Arc<ArcSwap<GatewayRuntime>>,
}

impl GatewayMessageDispatcher {
    pub fn new(runtime: Arc<ArcSwap<GatewayRuntime>>) -> Self {
        Self { runtime }
    }

    /// Construct a RequestContext from the transport-supplied
    /// session id. Kept on the impl so the identity default and
    /// transport-kind choice live in one place.
    fn build_context(&self, session_id: Option<String>) -> RequestContext {
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            session_id,
            None::<ResumeCursor>,
            RequestIdentity::Anonymous {
                source: "transport-dispatcher".to_owned(),
            },
            // Pick stdio because the dispatcher's semantics
            // (single frame per dispatch call) match stdio
            // more than HTTP. See module docs.
            TransportKind::Stdio,
        )
    }
}

#[mcpg_plugin_protocol::async_trait]
impl MessageDispatcher for GatewayMessageDispatcher {
    async fn dispatch(
        &self,
        session_id: &str,
        message: Bytes,
    ) -> Result<DispatchResponse, DispatcherError> {
        // Empty session id = "no session yet" (matches stdio's
        // pre-initialize semantic). Wrap into Option for the
        // request context.
        let session_id_opt = if session_id.is_empty() {
            None
        } else {
            Some(session_id.to_owned())
        };

        // 1. Parse bytes as JSON.
        let json: serde_json::Value =
            serde_json::from_slice(&message).map_err(|e| DispatcherError::InvalidMessage {
                reason: format!("JSON parse: {e}"),
            })?;

        // 2. Parse JSON-RPC client message shape.
        let client_message = parse_client_message(json).map_err(|e| {
            // ProtocolError serializes to a JSON-RPC error object;
            // for dispatcher boundary we surface just the reason.
            // The HTTP/stdio callers that do the full JSON-RPC
            // error round-trip don't use this dispatcher path.
            DispatcherError::InvalidMessage {
                reason: format!("{:?}", e),
            }
        })?;

        // 3. Map to a gateway protocol operation.
        let operation = map_client_message_to_operation(client_message).map_err(|e| {
            DispatcherError::InvalidMessage {
                reason: format!("{:?}", e),
            }
        })?;

        // 4. Build the request + dispatch.
        let context = self.build_context(session_id_opt);
        let request = GatewayRequest::new(context, GatewayOperation::Protocol(operation));
        let rt = self.runtime.load();
        let response = rt.handle_request(request).await;

        // 5. Serialise response back to bytes.
        match response.payload {
            GatewayResponsePayload::Protocol(protocol_response) => {
                match protocol_response.response {
                    ProtocolResponse::JsonRpcSuccess(success) => serialise_json_reply(&success),
                    ProtocolResponse::JsonRpcError(error) => serialise_json_reply(&error),
                    ProtocolResponse::NotificationAccepted => {
                        // Notifications don't get a response — ack
                        // with an empty DispatchResponse.
                        Ok(DispatchResponse::ack())
                    }
                }
            }
            GatewayResponsePayload::Readiness(snapshot) => serialise_json_reply(&snapshot),
            GatewayResponsePayload::Runtime(snapshot) => serialise_json_reply(&snapshot),
        }
    }
}

fn serialise_json_reply<T: serde::Serialize>(
    value: &T,
) -> Result<DispatchResponse, DispatcherError> {
    let bytes = serde_json::to_vec(value).map_err(|e| DispatcherError::Internal {
        reason: format!("response serialize: {e}"),
    })?;
    Ok(DispatchResponse::unary(bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal runtime for tests. Readiness + runtime-info don't
    /// require plugin wiring, so these tests don't need the full
    /// AppState setup.
    fn test_runtime() -> Arc<ArcSwap<GatewayRuntime>> {
        let runtime = GatewayRuntime::new(
            "mcpg-test",
            "0.0.0",
            "127.0.0.1:0",
            "/health",
            "/mcp",
            "info",
            vec![crate::config::SinkConfig {
                kind: "stderr".to_owned(),
                config: serde_json::json!({"format": "json"}),
                level: None,
            }],
            true,
        );
        Arc::new(ArcSwap::from_pointee(runtime))
    }

    #[tokio::test]
    async fn malformed_json_returns_invalid_message() {
        let rt = test_runtime();
        let d = GatewayMessageDispatcher::new(rt);
        let err = d
            .dispatch("", Bytes::from_static(b"{not-json"))
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "invalid_message");
    }

    #[tokio::test]
    async fn missing_jsonrpc_field_returns_invalid_message() {
        let rt = test_runtime();
        let d = GatewayMessageDispatcher::new(rt);
        // Syntactically valid JSON but not a valid JSON-RPC message.
        let err = d
            .dispatch("", Bytes::from_static(br#"{"id": 1, "params": {}}"#))
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "invalid_message");
    }

    #[tokio::test]
    async fn empty_session_id_does_not_panic() {
        // `session_id = ""` is the pre-initialize state. Dispatch
        // should succeed as far as parsing goes and bubble the
        // real error (not-initialized, etc.) from handle_request.
        let rt = test_runtime();
        let d = GatewayMessageDispatcher::new(rt);
        // Use a well-formed ping; the runtime will reject as
        // not-initialized but we shouldn't panic inside the
        // dispatcher itself.
        let resp = d
            .dispatch(
                "",
                Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            )
            .await;
        // Not asserting success/error shape — just that we
        // don't panic + the dispatcher path completes.
        match resp {
            Ok(_) | Err(_) => {}
        }
    }
}
