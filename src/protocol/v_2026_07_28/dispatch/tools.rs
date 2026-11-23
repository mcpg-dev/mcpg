//! `tools/list` and `tools/call` dispatch arms.

use crate::protocol::shared::error::INVALID_PARAMS_CODE;
use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, JsonRpcSuccess, ProtocolHttpResponse,
    ProtocolResponse,
};
use crate::protocol::v_2026_07_28::dispatch::mrtr::{
    LinkResumption, MrtrResumption, dispatch_mrtr_resumption, resume_connect_link,
};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_client_error, handler_internal_error, stamp_complete_result_type,
};
use crate::protocol::v_2026_07_28::dispatch::tasks::client_declared_tasks_extension;
use crate::protocol::v_2026_07_28::wire::tools::{
    CacheScope, ToolCallParams, ToolDescriptor, ToolsListParams, ToolsListResult,
};
use crate::runtime::shared_services::SharedServices;
use crate::runtime::{GatewayRuntime, RequestContext};
use futures::FutureExt as _;
use serde_json::Value;
use std::sync::Arc;

/// Dispatch `tools/list`.
///
/// Uses the runtime's catalog-page enumerator (visibility filter +
/// catalog chain + bounded pagination), converts each backend
/// [`crate::backends::ToolDescriptor`] into the wire shape, and stamps
/// the SEP-2549 cache triple onto the result envelope.
pub(crate) async fn dispatch_tools_list(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: ToolsListParams,
) -> ProtocolHttpResponse {
    // An opaque cursor that does not decode is invalid params (-32602),
    // not a silent restart at page 1 (SEP pagination contract).
    if !runtime.cursor_is_valid(params.cursor.as_deref(), ctx) {
        return ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcError(JsonRpcError {
                jsonrpc: JSONRPC_VERSION,
                id: Some(request_id),
                error: JsonRpcErrorBody {
                    code: -32602,
                    message: "invalid pagination cursor".to_owned(),
                    data: None,
                },
            }),
        };
    }

    let (page, next_cursor) = runtime
        .enumerate_tools_page(ctx, params.cursor.as_deref())
        .await;

    let tools: Vec<ToolDescriptor> = page.iter().map(tool_descriptor).collect();

    // Audit: tool catalog enumeration.
    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "tool",
        tools.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    // SEP-1865 MCP Apps audit: record which UI apps this listing
    // offered the caller.
    runtime.audit_apps_offered(ctx, &page).await;

    let result = ToolsListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        tools,
        next_cursor,
        ttl_ms: DEFAULT_TOOLS_LIST_TTL_MS,
        // Per-principal visibility filtering (`is_visible`) makes this
        // list caller-specific — private-cacheable only, never shared, or a
        // shared cache would serve one principal's filtered catalog to another.
        cache_scope: CacheScope::Private,
        meta: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize ToolsListResult");
            return handler_internal_error(
                Some(request_id),
                "failed to serialize tools/list result",
            );
        }
    };

    ProtocolHttpResponse {
        http_status: 200,
        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
            jsonrpc: JSONRPC_VERSION,
            id: request_id,
            result: result_value,
        }),
    }
}

/// Default `ttlMs` advertised on `tools/list` results.
/// 60 seconds — short enough that operator-side catalog changes
/// propagate promptly, long enough that an active client doesn't
/// thrash the registry every request.
pub(crate) const DEFAULT_TOOLS_LIST_TTL_MS: u64 = 60_000;

/// Dispatch `tools/call`.
///
/// The call runs the runtime's full pipeline (schema validation → rate
/// limit → policy gate → plugin chain → backend dispatch → post-dispatch
/// plugins → response). A pipeline that suspends for input answers with
/// MRTR's `InputRequiredResult`; the retry carries `requestState` +
/// `inputResponses` at the top level of params (SEP-2322) and resumes it.
pub(crate) async fn dispatch_tools_call(
    ctx: &Arc<RequestContext>,
    runtime: &GatewayRuntime,
    services: &SharedServices,
    request_id: Value,
    params: ToolCallParams,
) -> ProtocolHttpResponse {
    // The retry of a call that offered a link to store the caller's IdP
    // sign-in runs the call again, as the user answered the link.
    match resume_connect_link(
        ctx,
        runtime,
        &params.name,
        params.request_state.as_deref(),
        params.input_responses.as_ref(),
    )
    .await
    {
        LinkResumption::NotALink => {}
        LinkResumption::Resumed => {
            return run_tools_call(ctx, runtime, request_id, params).await;
        }
        LinkResumption::Refused(message) => {
            return handler_client_error(Some(request_id), 400, INVALID_PARAMS_CODE, message);
        }
    }

    if let Some(resumption) = MrtrResumption::from_params(
        params.request_state.as_deref(),
        params.input_responses.as_ref(),
    ) {
        // A retry is the original `tools/call` again, so its headers must
        // mirror its arguments as on the first call.
        if let Some(refused) = runtime.tools_call_param_header_mismatch(
            &request_id,
            &params.name,
            params.arguments.as_ref(),
            ctx,
        ) {
            return refused;
        }
        return dispatch_mrtr_resumption(ctx, runtime, services, request_id, resumption)
            .boxed()
            .await;
    }

    run_tools_call(ctx, runtime, request_id, params).await
}

/// Run `tools/call` through the runtime and stamp `resultType:"complete"`
/// on a result that names no other type.
async fn run_tools_call(
    ctx: &Arc<RequestContext>,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: ToolCallParams,
) -> ProtocolHttpResponse {
    // SEP-2663: tasks are server-directed. The call becomes a task
    // (`resultType:"task"`) only when
    //
    //   * the client declared `io.modelcontextprotocol/tasks` on this
    //     request (the server MUST NOT return a task otherwise), AND
    //   * the tool's configured `taskSupport` is `optional` or `required`
    //     (absent ⇒ `forbidden` ⇒ never a task).
    //
    // Otherwise the call runs inline, a `required` tool included: a client
    // that did not declare the extension still gets a usable result.
    let materialize_as_task = client_declared_tasks_extension(ctx)
        && matches!(
            runtime.tool_task_support(&params.name),
            Some(crate::backends::TaskSupport::Optional)
                | Some(crate::backends::TaskSupport::Required)
        );

    let call = crate::protocol::ToolCallParams {
        name: params.name,
        arguments: params.arguments,
        meta: params.meta,
    };
    // A task answer carries `resultType:"task"` and an MRTR suspension
    // `"input_required"`; the stamp leaves both as they are.
    stamp_complete_result_type(
        runtime
            .handle_tools_call(request_id, call, materialize_as_task, ctx)
            .await,
    )
}

/// Project a backend [`crate::backends::ToolDescriptor`] (the
/// catalog-registry shape) into the wire [`ToolDescriptor`].
///
/// - Wire `description` is `Option<String>`; the backend's is `String`
///   (always `Some` after conversion).
/// - Wire drops `execution` (a dispatch-layer concern that never
///   belonged on the catalog wire).
/// - Wire `annotations` is opaque `Value`; the backend's is the typed
///   `ToolAnnotations` struct — serialize to `Value` and forward.
/// - Per-entry `cache_scope` left `None`: tools inherit the
///   page-level scope.
pub(crate) fn tool_descriptor(t: &crate::backends::ToolDescriptor) -> ToolDescriptor {
    ToolDescriptor {
        name: t.name.clone(),
        title: t.title.clone(),
        description: Some(t.description.clone()),
        input_schema: t.input_schema.clone(),
        output_schema: t.output_schema.clone(),
        icons: t.icons.clone(),
        cache_scope: None,
        annotations: t
            .annotations
            .as_ref()
            .map(|a| serde_json::to_value(a).expect("ToolAnnotations serialises infallibly")),
        meta: t.meta.clone(),
    }
}
