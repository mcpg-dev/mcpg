//! The one dispatch every MCP request goes through, on HTTP and on stdio.
//!
//! A transport hands [`dispatch`] one parsed JSON-RPC body. The function
//! checks the protocol version, the routing headers (HTTP only) and the
//! request `_meta`, binds the request to its session, and then either names
//! the long-lived stream the transport runs or returns the runtime's
//! response together with the notifications the request emitted. A
//! transport only frames the outcome: HTTP as JSON or SSE, stdio as JSON
//! lines.

use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::Value;

use crate::config::AppConfig;
use crate::protocol::shared::messages::TransportRejection;
use crate::protocol::v_2026_07_28::wire::meta::{
    META_KEY_CLIENT_CAPABILITIES, META_KEY_CLIENT_INFO,
};
use crate::protocol::{
    ClientCapabilities, Handler, JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, ProtocolError,
    ProtocolHttpResponse, ProtocolResponse, StreamPlan,
};
use crate::runtime::{GatewayRuntime, RequestContext, SessionOutcome, TransportKind};

/// Longest client name or version kept; the client chooses both.
const MAX_CLIENT_FIELD_CHARS: usize = 128;

/// What [`dispatch`] made of one request.
pub(crate) enum DispatchOutcome {
    /// Refused before the runtime saw it: the protocol version, a routing
    /// header, the request `_meta`, or session capacity.
    Rejected(TransportRejection),
    /// A request the transport answers with a long-lived stream. `ctx` is
    /// bound to `session_id`.
    Stream {
        plan: StreamPlan,
        ctx: RequestContext,
        session_id: String,
        body: Value,
    },
    /// The runtime's response. `notifications` are the progress and log
    /// notifications a `tools/call` emitted before its terminal result, in
    /// order; on the wire they precede the result. `ctx` is the context the
    /// request ran under.
    Response {
        response: Result<ProtocolHttpResponse, ProtocolError>,
        notifications: Vec<Value>,
        ctx: RequestContext,
    },
}

/// Dispatch one JSON-RPC message.
///
/// `headers` is `Some` on HTTP and `None` on stdio. `ctx` names no session on
/// HTTP; on stdio it names the process session, which the request then runs
/// under.
pub(crate) async fn dispatch(
    runtime: &GatewayRuntime,
    config: &AppConfig,
    body: Value,
    mut ctx: RequestContext,
    headers: Option<&HeaderMap>,
) -> DispatchOutcome {
    // One message per request: a batch array is refused before anything
    // reads its members.
    if body.is_array() {
        return DispatchOutcome::Response {
            response: Err(ProtocolError::invalid_request(
                "JSON-RPC batch arrays are not supported; send a single JSON-RPC message",
            )),
            notifications: Vec::new(),
            ctx,
        };
    }
    let body_id = body.get("id").cloned();
    if let Err(error) = crate::protocol::negotiate(headers, &body) {
        return DispatchOutcome::Rejected(error.into_rejection(body_id));
    }
    let handler = Handler;
    if let Some(headers) = headers
        && let Err(rejection) = handler.validate_transport_headers(headers, &body)
    {
        return DispatchOutcome::Rejected(rejection);
    }
    if config.gateway.server.enforce_request_meta
        && let Some(rejection) =
            crate::protocol::v_2026_07_28::wire::enforce_request_meta_triple(&body)
    {
        return DispatchOutcome::Rejected(rejection);
    }

    // A client never chooses its session: only stdio names one, the process
    // session it opened itself. Every other request runs under the session
    // `ensure_session` derives from the caller.
    if ctx.transport != TransportKind::Stdio {
        ctx.session_id = None;
    }
    let ctx = with_request_meta(ctx, &body);
    let ctx = match runtime.ensure_session(ctx) {
        SessionOutcome::Ready(ctx) => Arc::new(ctx),
        SessionOutcome::CapacityExhausted => {
            return DispatchOutcome::Rejected(capacity_exhausted(body_id));
        }
    };
    let Some(session_id) = ctx.session_id.as_deref() else {
        tracing::error!(
            request_id = ctx.request_id.as_str(),
            "a ready session outcome carries no session id"
        );
        return DispatchOutcome::Rejected(TransportRejection {
            status: 500,
            error_code: crate::protocol::INTERNAL_ERROR_CODE,
            message: "internal error".to_owned(),
            data: None,
            jsonrpc_id: body_id,
        });
    };

    // A long-lived stream does not fit parse → dispatch: the handler names
    // the plan from the body, and the transport runs it.
    if let Some(plan) = handler.long_lived_stream_plan(&body) {
        runtime.record_request_received(&ctx, plan.method());
        metrics::counter!(
            "mcpg_requests_total",
            "operation" => plan.method(),
            "transport" => crate::runtime::transport_label(&ctx.transport),
        )
        .increment(1);
        let session_id = session_id.to_owned();
        return DispatchOutcome::Stream {
            plan,
            ctx: Arc::unwrap_or_clone(ctx),
            session_id,
            body,
        };
    }

    let tools_call = body.get("method").and_then(Value::as_str) == Some("tools/call");
    let ephemeral = ctx.session_ephemeral;
    let response = match handler.parse(body) {
        Ok(message) => Ok(runtime.handle_protocol_message(&ctx, message).await),
        Err(error) => Err(error),
    };
    let (continuation, terminal) = match response.as_ref().ok().and_then(success_result) {
        Some(result) => (
            hands_continuation(result),
            result_is_streamable_complete(result),
        ),
        None => (false, false),
    };
    // A row-less session gets its row when the response hands the client a
    // continuation: a task keeps delivering into the session, and a
    // suspended request resumes against it.
    let materialized =
        ephemeral && continuation && runtime.materialize_ephemeral_session(session_id);
    // The progress and log notifications a `tools/call` emitted precede its
    // terminal result. An `input_required` or `task` result is a control
    // result, not the tool's output, so its notifications stay pending.
    let notifications = if tools_call && terminal {
        runtime
            .take_pending_deliveries(session_id)
            .into_iter()
            .map(|delivery| delivery.jsonrpc_message)
            .collect()
    } else {
        Vec::new()
    };
    // No later request names an ephemeral session, so nothing could drain
    // what it still buffers, and a session left without a row keeps no
    // progress state.
    if ephemeral {
        runtime.discard_pending_deliveries(session_id);
        if !materialized {
            runtime
                .execution_dispatcher
                .clear_progress_state_for_session(session_id);
        }
    }
    DispatchOutcome::Response {
        response,
        notifications,
        // A copy only when a task the request started still holds the
        // context.
        ctx: Arc::unwrap_or_clone(ctx),
    }
}

/// The backpressure answer when no session row can be created now.
pub(crate) fn capacity_exhausted(jsonrpc_id: Option<Value>) -> TransportRejection {
    TransportRejection {
        status: 503,
        error_code: -32000,
        message: "session capacity exhausted; retry later".to_owned(),
        data: None,
        jsonrpc_id,
    }
}

/// The JSON-RPC error body of a transport rejection.
pub(crate) fn transport_rejection_body(rejection: &TransportRejection) -> Value {
    let error = JsonRpcError {
        jsonrpc: JSONRPC_VERSION,
        id: rejection.jsonrpc_id.clone(),
        error: JsonRpcErrorBody {
            code: rejection.error_code,
            message: rejection.message.clone(),
            data: rejection.data.clone(),
        },
    };
    serde_json::to_value(error).unwrap_or_default()
}

/// Whether a `tools/call` result is the tool's terminal output: a
/// `resultType` of `complete`, or none (which means `complete`).
/// `input_required` and `task` are control results the client acts on.
pub(crate) fn result_is_streamable_complete(result: &Value) -> bool {
    matches!(
        result.get("resultType").and_then(Value::as_str),
        Some("complete") | None
    )
}

/// Whether a result hands the client a continuation that outlives the
/// request: a task, or a request suspended for input.
fn hands_continuation(result: &Value) -> bool {
    matches!(
        result.get("resultType").and_then(Value::as_str),
        Some("task") | Some("input_required")
    )
}

/// The `result` of a successful (HTTP 200) JSON-RPC response.
fn success_result(response: &ProtocolHttpResponse) -> Option<&Value> {
    match &response.response {
        ProtocolResponse::JsonRpcSuccess(success) if response.http_status == 200 => {
            Some(&success.result)
        }
        _ => None,
    }
}

/// Bind what the request's own `params._meta` says to `ctx`: the client it
/// names, its capabilities, and its trace context when the transport saw
/// none.
fn with_request_meta(mut ctx: RequestContext, body: &Value) -> RequestContext {
    let meta = body.get("params").and_then(|params| params.get("_meta"));
    ctx.client = meta.and_then(request_client);
    if ctx.trace_context.is_none()
        && let Some(trace_context) =
            meta.and_then(crate::transports::TraceContext::from_meta_object)
    {
        ctx = ctx.with_trace_context(Some(trace_context));
    }
    if let Some(capabilities) = meta.and_then(|meta| meta.get(META_KEY_CLIENT_CAPABILITIES)) {
        match <ClientCapabilities as serde::Deserialize>::deserialize(capabilities) {
            Ok(capabilities) => ctx = ctx.with_request_capabilities(capabilities),
            Err(error) => tracing::warn!(
                request_id = ctx.request_id.as_str(),
                error = %error,
                "the request _meta clientCapabilities do not parse"
            ),
        }
    }
    ctx
}

/// The client a request names in its `_meta` client info, with control
/// characters dropped and each field bounded. `None` without a name.
fn request_client(meta: &Value) -> Option<mcpg_plugin_protocol::ClientInfo> {
    let info = meta.get(META_KEY_CLIENT_INFO)?;
    let clean = |value: &Value| -> Option<String> {
        let text: String = value
            .as_str()?
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_CLIENT_FIELD_CHARS)
            .collect();
        let text = text.trim().to_owned();
        (!text.is_empty()).then_some(text)
    };
    Some(mcpg_plugin_protocol::ClientInfo {
        name: clean(info.get("name")?)?,
        version: info.get("version").and_then(clean),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_complete_or_untyped_result_is_terminal() {
        assert!(result_is_streamable_complete(
            &json!({"resultType": "complete"})
        ));
        assert!(result_is_streamable_complete(&json!({"content": []})));
        assert!(!result_is_streamable_complete(
            &json!({"resultType": "input_required"})
        ));
        assert!(!result_is_streamable_complete(
            &json!({"resultType": "task"})
        ));
    }

    #[test]
    fn task_and_input_required_results_hand_a_continuation() {
        assert!(hands_continuation(&json!({"resultType": "task"})));
        assert!(hands_continuation(&json!({"resultType": "input_required"})));
        assert!(!hands_continuation(&json!({"resultType": "complete"})));
        assert!(!hands_continuation(&json!({})));
    }

    #[test]
    fn the_request_client_is_cleaned_and_bounded() {
        let long = "x".repeat(MAX_CLIENT_FIELD_CHARS + 10);
        let meta = json!({
            META_KEY_CLIENT_INFO: { "name": " host\u{7}app ", "version": long },
        });
        let client = request_client(&meta).expect("named client");
        assert_eq!(client.name, "hostapp");
        assert_eq!(
            client.version.map(|v| v.chars().count()),
            Some(MAX_CLIENT_FIELD_CHARS)
        );
    }

    #[test]
    fn a_client_without_a_name_is_none() {
        assert!(request_client(&json!({ META_KEY_CLIENT_INFO: { "version": "1" } })).is_none());
        assert!(request_client(&json!({ META_KEY_CLIENT_INFO: { "name": "  " } })).is_none());
        assert!(request_client(&json!({})).is_none());
    }

    #[test]
    fn a_rejection_body_is_a_jsonrpc_error_with_the_request_id() {
        let body = transport_rejection_body(&TransportRejection {
            status: 400,
            error_code: -32022,
            message: "Unsupported protocol version".to_owned(),
            data: Some(json!({"supported": ["2026-07-28"]})),
            jsonrpc_id: Some(json!(7)),
        });
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], -32022);
        assert_eq!(body["error"]["data"]["supported"][0], "2026-07-28");
    }
}
