//! `support` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::error::{INVALID_PARAMS_CODE, INVALID_REQUEST_CODE};
use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, JsonRpcSuccess, ProtocolHttpResponse,
    ProtocolResponse,
};
use serde_json::Value;

/// Common JSON-RPC success envelope wrapping a serialisable result.
/// Used by the modern list arms to keep the per-arm code small.
pub(crate) fn serialize_jsonrpc_success<T: serde::Serialize>(
    request_id: Value,
    result: &T,
    operation_label: &str,
) -> ProtocolHttpResponse {
    let result_value = match serde_json::to_value(result) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(
                error = %error,
                operation = operation_label,
                "failed to serialize modern result"
            );
            return handler_internal_error(
                Some(request_id),
                &format!("failed to serialize {operation_label} result"),
            );
        }
    };
    ProtocolHttpResponse {
        http_status: 200,
        session_id_header: None,
        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
            jsonrpc: JSONRPC_VERSION,
            id: request_id,
            result: result_value,
        }),
    }
}

/// Stamp the SEP-2322 `resultType:"complete"` discriminator onto a
/// delegated success response that was built by the version-blind
/// runtime pipeline (which has no notion of the modern envelope).
///
/// Only applied to a `JsonRpcSuccess` whose `result` is a JSON object
/// that does not already carry a `resultType` — so a runtime-minted
/// MRTR `InputRequiredResult` (`resultType:"input_required"`) or a
/// future task shape (`"task"`) is left untouched. Error envelopes
/// and the 202 notification-accepted response pass through unchanged.
pub(crate) fn stamp_complete_result_type(
    mut response: ProtocolHttpResponse,
) -> ProtocolHttpResponse {
    if let ProtocolResponse::JsonRpcSuccess(success) = &mut response.response
        && let Some(obj) = success.result.as_object_mut()
        && !obj.contains_key("resultType")
    {
        obj.insert(
            "resultType".to_owned(),
            Value::String(crate::protocol::shared::caching::RESULT_TYPE_COMPLETE.to_owned()),
        );
    }
    response
}

/// Generic `-32603 InternalError` envelope used for unreachable /
/// not-yet-implemented dispatch paths.
pub(crate) use crate::protocol::shared::jsonrpc::handler_internal_error;

/// Client-fault JSON-RPC error envelope at a caller-appropriate HTTP status.
/// Distinct from [`handler_internal_error`]: a malformed request must not be
/// dressed as `-32603`/500, which reads as a gateway fault the client should
/// retry (and which pages an operator for a non-incident).
pub(crate) fn handler_client_error(
    jsonrpc_id: Option<Value>,
    http_status: u16,
    code: i32,
    message: &str,
) -> ProtocolHttpResponse {
    ProtocolHttpResponse {
        http_status,
        session_id_header: None,
        response: ProtocolResponse::JsonRpcError(JsonRpcError {
            jsonrpc: JSONRPC_VERSION,
            id: jsonrpc_id,
            error: JsonRpcErrorBody {
                code,
                message: message.to_owned(),
                data: None,
            },
        }),
    }
}

/// Classify a `requestState` decode failure. Only a genuine store fault (a KV
/// read error) is a gateway-internal `-32603`/500; a malformed, tampered, or
/// foreign-owned blob is the caller's (`-32602`/400), and one whose
/// server-side state is gone or already spent is a stale request
/// (`-32600`/200 — retry-safe, matching the code the resume path treats as
/// "committed nothing").
pub(crate) fn map_request_state_decode_error(
    jsonrpc_id: Option<Value>,
    error: &crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateError,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateError as E;
    match error {
        E::Store(_) => handler_internal_error(
            jsonrpc_id,
            &format!("MRTR requestState store error: {error}"),
        ),
        E::HandleNotFound(_) | E::Replayed => handler_client_error(
            jsonrpc_id,
            200,
            INVALID_REQUEST_CODE,
            &format!("MRTR requestState no longer resolvable: {error}"),
        ),
        E::InvalidPrefix(_) | E::InvalidPayload(_) | E::AuthenticationFailed => {
            handler_client_error(
                jsonrpc_id,
                400,
                INVALID_PARAMS_CODE,
                &format!("invalid MRTR requestState: {error}"),
            )
        }
    }
}
