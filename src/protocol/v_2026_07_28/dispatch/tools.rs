//! `tools` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, JsonRpcSuccess, ProtocolHttpResponse,
    ProtocolResponse,
};
use crate::protocol::v_2026_07_28::dispatch::mrtr::{
    dispatch_mrtr_resumption, extract_mrtr_resumption, extract_mrtr_resumption_from_params,
};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, stamp_complete_result_type,
};
use crate::protocol::v_2026_07_28::dispatch::tasks::client_declared_tasks_extension;
use crate::protocol::v_2026_07_28::wire::tools::{
    CacheScope, ToolCallParams as ModernToolCallParams, ToolDescriptor as ModernToolDescriptor,
    ToolsListParams, ToolsListResult,
};
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// Dispatch `tools/list` on the modern wire.
///
/// Reuses the version-blind catalog-page enumerator on `GatewayRuntime`
/// (visibility filter + catalog chain + bounded pagination),
/// converts each backend [`crate::backends::ToolDescriptor`] into the
/// modern wire shape, and stamps the SEP-2549 cache triple onto the
/// result envelope. Returns 200 with the JSON-RPC success body.
pub(crate) async fn dispatch_tools_list(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ToolsListParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    // An opaque cursor that does not decode is invalid params (-32602),
    // not a silent restart at page 1 (SEP pagination contract).
    if !runtime.cursor_is_valid(params.cursor.as_deref(), ctx.session_id.as_deref()) {
        return ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
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

    let modern_tools: Vec<ModernToolDescriptor> = page.iter().map(legacy_tool_to_modern).collect();

    // Audit: tool catalog enumeration. The modern path emits the
    // same event the legacy path does so cluster-wide catalog
    // telemetry stays consistent across versions.
    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "tool",
        modern_tools.len() as u64,
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
        tools: modern_tools,
        next_cursor,
        ttl_ms: DEFAULT_TOOLS_LIST_TTL_MS,
        // Per-principal visibility filtering (`is_tool_visible`) makes this
        // list caller-specific — private-cacheable only, never shared, or a
        // shared cache would serve one principal's filtered catalog to another.
        cache_scope: CacheScope::Private,
        meta: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize modern ToolsListResult");
            return handler_internal_error(
                Some(request_id),
                "failed to serialize tools/list result",
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

/// Default `ttlMs` advertised on modern `tools/list` results.
/// 60 seconds — short enough that operator-side catalog changes
/// propagate promptly, long enough that an active client doesn't
/// thrash the registry every request.
pub(crate) const DEFAULT_TOOLS_LIST_TTL_MS: u64 = 60_000;

/// Dispatch `tools/call` on the modern wire.
///
/// Reuses the legacy [`crate::runtime::GatewayRuntime::handle_protocol_operation`]
/// path for the full 13-stage pipeline (schema validation → rate
/// limit → policy gate → plugin chain → backend dispatch →
/// post-dispatch plugins → response) because the wire shapes of
/// `ToolCallParams` (apart from the legacy-only `task` field) and
/// `ToolCallResult` are structurally identical across versions, so
/// the legacy result serialises into a modern-compliant envelope
/// without translation.
///
/// **Suspension handling:** if the pipeline suspends (elicitation /
/// sampling / roots), the legacy path returns HTTP 202
/// `NotificationAccepted` with the server-initiated request on the
/// session's SSE delivery bus. The modern wire has no such delivery
/// bus — suspension is carried by MRTR's `InputRequiredResult`
/// inline body, which the runtime mints directly for the modern
/// version (see the resumption branch below).
pub(crate) async fn dispatch_tools_call(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernToolCallParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    // MRTR resumption. The spec (SEP-2322) puts
    // `requestState` + `inputResponses` at the top level of params;
    // earlier MCPG drafts stashed them under `_meta`. Accept both
    // shapes so neither in-flight clients nor the upstream
    // conformance suite (which uses top-level params) break.
    if let Some(mrtr_meta) = extract_mrtr_resumption_from_params(
        params.request_state.as_deref(),
        params.input_responses.as_ref(),
    )
    .or_else(|| extract_mrtr_resumption(params.meta.as_ref()))
    {
        return dispatch_mrtr_resumption(ctx, services, request_id, mrtr_meta).await;
    }

    // SEP-2663 live materialization. Tasks are
    // server-directed: the gateway elects async execution on a
    // per-request basis. The decision is:
    //
    //   * the client declared `io.modelcontextprotocol/tasks` on this
    //     request (MUST-NOT return a task otherwise), AND
    //   * the tool's configured `taskSupport` is `Optional` or
    //     `Required` (absent ⇒ `Forbidden` ⇒ never async).
    //
    // When the client did NOT declare the extension, the call runs
    // SYNCHRONOUSLY regardless of `taskSupport` — a `Required` tool
    // simply runs inline (the spec removed the per-request `task`
    // opt-in; the extension capability is the single handshake point,
    // and a non-declaring client must still get a usable result).
    //
    // The `task` augment field the legacy runtime arm keys on is the
    // gateway-internal trigger for the principal-keyed background
    // spawn — it never appears on the modern wire (SEP-2663 removed
    // it; modern params can't carry one).
    let materialize_as_task = client_declared_tasks_extension(ctx)
        && matches!(
            runtime.tool_task_support(&params.name),
            Some(crate::backends::TaskSupport::Optional)
                | Some(crate::backends::TaskSupport::Required)
        );

    // Project modern params into the legacy shape. The two structs
    // differ only by the legacy-only `task` augment field; on the
    // modern wire we synthesize it to drive the runtime's
    // principal-keyed background-task spawn when (and only when) the
    // materialization gate above fired.
    let legacy_params = crate::protocol::v_2025_11_25::wire::tools::ToolCallParams {
        name: params.name,
        arguments: params.arguments,
        meta: params.meta,
        task: materialize_as_task
            .then_some(crate::protocol::v_2025_11_25::wire::tasks::TaskAugmentParams { ttl: None }),
    };
    let legacy_op =
        crate::protocol::v_2025_11_25::wire::operations::ProtocolOperation::Capabilities(
            crate::protocol::v_2025_11_25::wire::operations::CapabilityOperation::ToolsCall {
                request_id: request_id.clone(),
                params: legacy_params,
            },
        );

    // The runtime branches on
    // `request_context.negotiated_version` inside the Suspended
    // consumer of the legacy `tools/call` arm. For
    // `V_2026_07_28`, the runtime mints the MRTR
    // `InputRequiredResult` directly (HTTP 200 + JsonRpcSuccess);
    // for legacy versions it still emits the SSE+202 envelope.
    // The complete-path result carries no `resultType` from the
    // version-blind pipeline, so stamp `"complete"` here; the MRTR
    // shape already carries `"input_required"` and is left untouched.
    let response = runtime.handle_protocol_operation(legacy_op, ctx).await;
    if materialize_as_task {
        // The runtime returned the legacy nested `{ task: {...} }`
        // CreateTaskResult; project it to the flat modern
        // `resultType:"task"` shape (SEP-2663 `Result & Task`).
        stamp_modern_create_task_result(response)
    } else {
        stamp_complete_result_type(response)
    }
}

/// Re-project the runtime's legacy nested `CreateTaskResult`
/// (`{ "task": { taskId, status, ttl, pollInterval, … } }`) into the
/// flat modern SEP-2663 shape: `resultType:"task"` with the task
/// fields inlined and `ttl`/`pollInterval` renamed to
/// `ttlMs`/`pollIntervalMs`. A non-success response (error) passes
/// through unchanged.
///
/// Idempotent in shape: an already-flat input (e.g. a cached
/// first-time envelope replayed straight back) is read via its modern
/// `ttlMs`/`pollIntervalMs` spelling too, so re-stamping is a no-op
/// rather than a corruption. Any top-level `_meta` on the original
/// envelope — notably the idempotency replay marker
/// (`dev.mcpg/idempotency-replayed`) — is carried through onto the flat
/// result.
pub(crate) fn stamp_modern_create_task_result(
    response: ProtocolHttpResponse,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::{
        CreateTaskResult, Task, TaskStatus,
    };

    let ProtocolResponse::JsonRpcSuccess(success) = response.response else {
        return response;
    };
    let legacy = &success.result;
    let task_obj = legacy.get("task").unwrap_or(legacy);

    let status = match task_obj.get("status").and_then(Value::as_str) {
        Some("working") => TaskStatus::Working,
        Some("input_required") => TaskStatus::InputRequired,
        Some("completed") => TaskStatus::Completed,
        Some("failed") => TaskStatus::Failed,
        Some("cancelled") => TaskStatus::Cancelled,
        _ => TaskStatus::Working,
    };
    let task = Task {
        task_id: task_obj
            .get("taskId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        status,
        status_message: task_obj
            .get("statusMessage")
            .and_then(Value::as_str)
            .map(str::to_owned),
        created_at: task_obj
            .get("createdAt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        last_updated_at: task_obj
            .get("lastUpdatedAt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        ttl_ms: task_obj
            .get("ttl")
            .or_else(|| task_obj.get("ttlMs"))
            .and_then(Value::as_u64),
        poll_interval_ms: task_obj
            .get("pollInterval")
            .or_else(|| task_obj.get("pollIntervalMs"))
            .and_then(Value::as_u64),
        result: None,
        error: None,
        input_requests: None,
        request_state: None,
    };
    let modern = CreateTaskResult::new(task);
    let mut result_value =
        serde_json::to_value(&modern).expect("modern CreateTaskResult serialized");
    // Carry through any top-level `_meta` (the idempotency replay
    // marker on a replayed materialization) — the typed
    // `CreateTaskResult` has no `_meta` field, so it must be re-attached
    // after serialization.
    if let Some(meta) = legacy.get("_meta")
        && let Some(obj) = result_value.as_object_mut()
    {
        obj.insert("_meta".to_owned(), meta.clone());
    }
    ProtocolHttpResponse {
        // The modern wire returns all `tools/call` results (incl. the
        // `resultType:"task"` materialization) inline as HTTP 200.
        http_status: 200,
        session_id_header: response.session_id_header,
        response: ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
            jsonrpc: success.jsonrpc,
            id: success.id,
            result: result_value,
        }),
    }
}

/// Project a backend [`crate::backends::ToolDescriptor`] (the
/// catalog-registry shape used by the legacy wire) into the modern
/// wire [`ModernToolDescriptor`].
///
/// Differences handled:
/// - Modern `description` is `Option<String>`; legacy is `String`
///   (always `Some` after conversion).
/// - Modern drops `execution` (a dispatch-layer concern that never
///   belonged on the catalog wire).
/// - Modern `annotations` is opaque `Value`; legacy is the typed
///   `ToolAnnotations` struct — serialize to `Value` and forward.
/// - Per-entry `cache_scope` left `None`: tools inherit the
///   page-level scope. Operator-configurable per-tool cache scope
///   is a possible future refinement.
pub(crate) fn legacy_tool_to_modern(t: &crate::backends::ToolDescriptor) -> ModernToolDescriptor {
    ModernToolDescriptor {
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
