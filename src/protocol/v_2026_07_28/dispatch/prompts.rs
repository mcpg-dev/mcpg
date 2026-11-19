//! `prompts/list` and `prompts/get` dispatch arms.

use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse,
};
use crate::protocol::v_2026_07_28::dispatch::mrtr::{MrtrResumption, dispatch_mrtr_resumption};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, stamp_complete_result_type,
};
use crate::protocol::v_2026_07_28::wire::prompts::{
    PromptArgument, PromptDescriptor, PromptGetParams, PromptsListParams, PromptsListResult,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::shared_services::SharedServices;
use crate::runtime::{GatewayRuntime, RequestContext};
use serde_json::Value;

/// Default `ttlMs` advertised on `prompts/list` results.
/// Prompts change slowly; 10 minutes is a sensible default. The
/// `cacheToken` invalidates any operator-driven catalog change so
/// the long TTL is safe.
pub(crate) const DEFAULT_PROMPTS_LIST_TTL_MS: u64 = 600_000;

/// Dispatch `prompts/list`.
///
/// Same pattern as `tools/list` — the runtime's
/// `enumerate_prompts_page` helper, each backend `PromptDescriptor`
/// converted to the wire shape, the SEP-2549 cache triple stamped onto
/// the result envelope.
pub(crate) async fn dispatch_prompts_list(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: PromptsListParams,
) -> ProtocolHttpResponse {
    let (page, next_cursor) = runtime.enumerate_prompts_page(ctx, params.cursor.as_deref());
    let prompts: Vec<PromptDescriptor> = page.iter().map(prompt_descriptor).collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "prompt",
        prompts.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = PromptsListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        prompts,
        next_cursor,
        ttl_ms: DEFAULT_PROMPTS_LIST_TTL_MS,
        // Per-principal filtered — private-cacheable only (see tools/list).
        cache_scope: CacheScope::Private,
        meta: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize PromptsListResult");
            return handler_internal_error(
                Some(request_id),
                "failed to serialize prompts/list result",
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

/// Dispatch `prompts/get`.
///
/// A prompt backed by a suspending pipeline answers with an
/// `InputRequiredResult`; the retry re-issues `prompts/get` with
/// `requestState` + `inputResponses` (SEP-2322) and resumes the pipeline.
/// Every other request runs the runtime's prompt read (gate, backend,
/// audit), and its result is stamped `resultType:"complete"`.
pub(crate) async fn dispatch_prompts_get(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    services: &SharedServices,
    request_id: Value,
    params: PromptGetParams,
) -> ProtocolHttpResponse {
    if let Some(resumption) = MrtrResumption::from_params(
        params.request_state.as_deref(),
        params.input_responses.as_ref(),
    ) {
        return dispatch_mrtr_resumption(ctx, runtime, services, request_id, resumption).await;
    }

    let get = crate::protocol::PromptGetParams {
        name: params.name,
        arguments: params.arguments.map(Value::Object),
        meta: params.meta,
    };
    stamp_complete_result_type(runtime.handle_prompt_get(request_id, get, ctx).await)
}

/// Project a backend [`crate::backends::PromptDescriptor`] into the
/// wire shape:
/// - `arguments: Vec<PromptArgument>` → `Option<Vec<...>>` (`None` when
///   empty; `arguments` is serialized only when the prompt takes any).
/// - `cache_scope: None` — prompts inherit the page-level scope.
pub(crate) fn prompt_descriptor(p: &crate::backends::PromptDescriptor) -> PromptDescriptor {
    PromptDescriptor {
        name: p.name.clone(),
        title: p.title.clone(),
        description: p.description.clone(),
        arguments: if p.arguments.is_empty() {
            None
        } else {
            Some(p.arguments.iter().map(prompt_argument).collect())
        },
        icons: p.icons.clone(),
        cache_scope: None,
        meta: p.meta.clone(),
    }
}

/// Project a backend [`crate::backends::PromptArgument`]; `required` is
/// always `Some` on the wire.
pub(crate) fn prompt_argument(a: &crate::backends::PromptArgument) -> PromptArgument {
    PromptArgument {
        name: a.name.clone(),
        title: a.title.clone(),
        description: a.description.clone(),
        required: Some(a.required),
        meta: None,
    }
}
