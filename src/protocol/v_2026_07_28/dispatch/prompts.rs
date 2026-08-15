//! `prompts` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse,
};
use crate::protocol::v_2026_07_28::dispatch::mrtr::{
    dispatch_mrtr_resumption, extract_mrtr_resumption, extract_mrtr_resumption_from_params,
};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, stamp_complete_result_type,
};
use crate::protocol::v_2026_07_28::wire::prompts::{
    PromptArgument as ModernPromptArgument, PromptDescriptor as ModernPromptDescriptor,
    PromptGetParams as ModernPromptGetParams, PromptsListParams, PromptsListResult,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// Default `ttlMs` advertised on modern `prompts/list` results.
/// Prompts change slowly; 10 minutes is a sensible default. The
/// `cacheToken` invalidates any operator-driven catalog change so
/// the long TTL is safe.
pub(crate) const DEFAULT_PROMPTS_LIST_TTL_MS: u64 = 600_000;

/// Dispatch `prompts/list` on the modern wire.
///
/// Same pattern as [`dispatch_tools_list`] — reuse the
/// runtime's `enumerate_prompts_page` helper, convert each
/// backend `PromptDescriptor` to the modern wire shape, stamp the
/// SEP-2549 cache triple onto the result envelope.
pub(crate) async fn dispatch_prompts_list(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: PromptsListParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    let (page, next_cursor) = runtime.enumerate_prompts_page(ctx, params.cursor.as_deref());
    let modern_prompts: Vec<ModernPromptDescriptor> =
        page.iter().map(legacy_prompt_to_modern).collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "prompt",
        modern_prompts.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = PromptsListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        prompts: modern_prompts,
        next_cursor,
        ttl_ms: DEFAULT_PROMPTS_LIST_TTL_MS,
        // Per-principal filtered — private-cacheable only (see tools/list).
        cache_scope: CacheScope::Private,
        meta: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize modern PromptsListResult");
            return handler_internal_error(
                Some(request_id),
                "failed to serialize prompts/list result",
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

/// Dispatch `prompts/get` on the modern wire.
///
/// Like `tools/call`, the legacy and modern `PromptGetResult` wire
/// shapes are structurally identical (description + messages +
/// `_meta`), so the legacy result serialiser produces a
/// modern-compliant envelope unchanged. Conversion is just
/// `arguments: Option<Map<String, Value>>` → `Option<Value>` (the
/// JSON wire is the same Object either way).
pub(crate) async fn dispatch_prompts_get(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernPromptGetParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    // SEP-2322 MRTR resumption — a prompt backed by a suspending
    // pipeline returns an `InputRequiredResult`; round 2 re-issues
    // `prompts/get` with `requestState` + `inputResponses`. Detect it
    // and route to the shared resumption path (which recovers the
    // suspended pipeline by correlation token and resumes from the
    // next step) BEFORE projecting onto the legacy `prompts/get` op.
    // Mirrors `dispatch_tools_call`'s resumption check; accepts both
    // the spec's top-level placement and the legacy `_meta` shape.
    if let Some(mrtr_meta) = extract_mrtr_resumption_from_params(
        params.request_state.as_deref(),
        params.input_responses.as_ref(),
    )
    .or_else(|| extract_mrtr_resumption(params.meta.as_ref()))
    {
        return dispatch_mrtr_resumption(ctx, services, request_id, mrtr_meta).await;
    }

    let legacy_arguments = params.arguments.map(Value::Object);
    let legacy_params = crate::protocol::v_2025_11_25::wire::prompts::PromptGetParams {
        name: params.name,
        arguments: legacy_arguments,
        meta: params.meta,
    };
    let legacy_op =
        crate::protocol::v_2025_11_25::wire::operations::ProtocolOperation::Capabilities(
            crate::protocol::v_2025_11_25::wire::operations::CapabilityOperation::PromptsGet {
                request_id,
                params: legacy_params,
            },
        );

    let response = runtime.handle_protocol_operation(legacy_op, ctx).await;
    stamp_complete_result_type(response)
}

/// Project a backend [`crate::backends::PromptDescriptor`] into the
/// modern wire shape. Differences handled:
/// - `arguments: Vec<PromptArgument>` → `Option<Vec<...>>`
///   (`None` when empty; modern serializes `arguments` only when
///   the prompt actually takes any).
/// - Per-argument `required: bool` → `Option<bool>` (always `Some`
///   after conversion; downstream consumers can collapse `None` to
///   `false`).
/// - `cache_scope: None` — prompts inherit the page-level scope.
pub(crate) fn legacy_prompt_to_modern(
    p: &crate::backends::PromptDescriptor,
) -> ModernPromptDescriptor {
    ModernPromptDescriptor {
        name: p.name.clone(),
        title: p.title.clone(),
        description: p.description.clone(),
        arguments: if p.arguments.is_empty() {
            None
        } else {
            Some(
                p.arguments
                    .iter()
                    .map(legacy_prompt_arg_to_modern)
                    .collect(),
            )
        },
        icons: p.icons.clone(),
        cache_scope: None,
        meta: p.meta.clone(),
    }
}

pub(crate) fn legacy_prompt_arg_to_modern(
    a: &crate::backends::PromptArgument,
) -> ModernPromptArgument {
    ModernPromptArgument {
        name: a.name.clone(),
        title: a.title.clone(),
        description: a.description.clone(),
        required: Some(a.required),
        meta: None,
    }
}
