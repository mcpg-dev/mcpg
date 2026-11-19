//! `completion/complete` dispatch arm.

use crate::protocol::shared::jsonrpc::ProtocolHttpResponse;
use crate::protocol::v_2026_07_28::dispatch::support::stamp_complete_result_type;
use crate::protocol::v_2026_07_28::wire::completion::CompletionCompleteParams;
use crate::runtime::{GatewayRuntime, RequestContext};
use serde_json::Value;

/// Dispatch `completion/complete` to the runtime's completion source and
/// stamp `resultType:"complete"` on its result.
pub(crate) async fn dispatch_completion_complete(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: CompletionCompleteParams,
) -> ProtocolHttpResponse {
    stamp_complete_result_type(runtime.handle_completion(request_id, params, ctx).await)
}
