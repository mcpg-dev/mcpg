//! `completion` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::jsonrpc::ProtocolHttpResponse;
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, stamp_complete_result_type,
};
use crate::protocol::v_2026_07_28::wire::completion::CompletionCompleteParams as ModernCompletionCompleteParams;
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// Dispatch `completion/complete` on the modern wire.
///
/// The completion wire shape is identical across versions —
/// `CompletionCompleteParams` and `CompletionResult` carry the same
/// fields on both sides. Convert modern params → legacy params
/// (field-for-field copy, including the nested `CompletionContext`
/// and `CompletionReference`), delegate to legacy
/// `handle_protocol_operation`, return the legacy response unchanged.
pub(crate) async fn dispatch_completion_complete(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernCompletionCompleteParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    let legacy_params = crate::protocol::v_2025_11_25::wire::completion::CompletionCompleteParams {
        reference: crate::protocol::v_2025_11_25::wire::completion::CompletionReference {
            ref_type: params.reference.ref_type,
            name: params.reference.name,
            uri: params.reference.uri,
        },
        argument: crate::protocol::v_2025_11_25::wire::completion::CompletionArgument {
            name: params.argument.name,
            value: params.argument.value,
        },
        context: params.context.map(|c| {
            crate::protocol::v_2025_11_25::wire::completion::CompletionContext {
                arguments: c.arguments,
            }
        }),
        meta: params.meta,
    };
    let legacy_op =
        crate::protocol::v_2025_11_25::wire::operations::ProtocolOperation::Capabilities(
            crate::protocol::v_2025_11_25::wire::operations::CapabilityOperation::Complete {
                request_id,
                params: legacy_params,
            },
        );

    let response = runtime.handle_protocol_operation(legacy_op, ctx).await;
    stamp_complete_result_type(response)
}
