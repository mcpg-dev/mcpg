//! `mrtr` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::error::INVALID_PARAMS_CODE;
use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, ProtocolResponse};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_client_error, handler_internal_error, map_request_state_decode_error,
    stamp_complete_result_type,
};
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// Extracted MRTR resumption signal from a request's `_meta`. None
/// if the meta either is absent or lacks the resumption keys.
pub(crate) struct MrtrResumption {
    pub(crate) request_state: String,
    pub(crate) input_responses: Value,
}

pub(crate) fn extract_mrtr_resumption(meta: Option<&Value>) -> Option<MrtrResumption> {
    use crate::protocol::v_2026_07_28::wire::mrtr::{
        META_KEY_INPUT_RESPONSES, META_KEY_REQUEST_STATE,
    };

    let meta = meta?.as_object()?;
    let request_state = meta.get(META_KEY_REQUEST_STATE)?.as_str()?.to_owned();
    let input_responses = meta.get(META_KEY_INPUT_RESPONSES)?.clone();
    Some(MrtrResumption {
        request_state,
        input_responses,
    })
}

/// Companion to [`extract_mrtr_resumption`] for the spec-canonical
/// top-level params placement (SEP-2322). Returns `Some` only when
/// **both** `request_state` and `input_responses` are present —
/// either alone is malformed and should fall through to the
/// non-resumption path so the runtime returns a clear error.
pub(crate) fn extract_mrtr_resumption_from_params(
    request_state: Option<&str>,
    input_responses: Option<&Value>,
) -> Option<MrtrResumption> {
    let request_state = request_state?.to_owned();
    let input_responses = input_responses?.clone();
    Some(MrtrResumption {
        request_state,
        input_responses,
    })
}

/// Translate an MRTR resumption (`_meta.requestState` +
/// `_meta.inputResponses`) into the legacy `ServerRequestResponse`
/// machinery so the pipeline picks up where it suspended.
///
/// Today this handles the **single-entry** case (one elicitation /
/// sampling / roots input per suspension) — the shape the suspension
/// path emits. Multi-entry MRTR (multiple simultaneous inputs from
/// the spec's `inputRequests` map) is a follow-up: it needs a
/// pipeline-engine refactor to consume an `InputResponses` map at
/// once instead of one response at a time.
pub(crate) async fn dispatch_mrtr_resumption(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    mrtr: MrtrResumption,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::wire::mrtr::{InputResponseValue, InputResponses};

    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    // Validate the requestState blob is well-formed for this
    // gateway's codec (key not rotated, ciphertext not tampered).
    // The decoded payload (pipeline_id) is informational — the
    // pending-server-request lookup keyed by correlation token
    // recovers the pipeline id authoritatively.
    let codec = &services.request_state_codec;
    // The blob is bound to the principal that suspended the pipeline;
    // decoding under a different principal fails AEAD verification.
    let owner_aad = crate::protocol::v_2026_07_28::dispatch::request_state::owner_aad(
        ctx.identity.principal_id(),
    );
    let decoded_pipeline_id = match codec.decode(&mrtr.request_state, &owner_aad).await {
        Ok(blob) => match std::str::from_utf8(&blob) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return handler_internal_error(
                    Some(request_id),
                    "MRTR requestState decoded to non-UTF-8 bytes",
                );
            }
        },
        Err(error) => {
            tracing::warn!(error = %error, "MRTR requestState decode failed");
            return map_request_state_decode_error(Some(request_id), &error);
        }
    };

    // Parse the inputResponses map. Single-entry only for now;
    // multi-entry MRTR is a follow-up.
    let responses = match InputResponses::from_value(&mrtr.input_responses) {
        Ok(r) => r,
        Err(error) => {
            return handler_client_error(
                Some(request_id),
                400,
                INVALID_PARAMS_CODE,
                &format!("invalid inputResponses: {error}"),
            );
        }
    };
    if responses.entries.is_empty() {
        return handler_client_error(
            Some(request_id),
            400,
            INVALID_PARAMS_CODE,
            "MRTR resumption requires at least one inputResponses entry",
        );
    }

    // SEP-2322 multi-entry MRTR — the client answered a `gather`
    // step's batch in one `inputResponses` map. The `requestState`
    // recovers the suspended pipeline directly (the per-token pending
    // requests all point at it), so route to the multi-input resume
    // path that records every answer and resumes once.
    if responses.entries.len() > 1 {
        let _ = request_id;
        let answers: std::collections::BTreeMap<String, Value> = responses
            .entries
            .into_iter()
            .map(|(token, value)| {
                let v = match value {
                    InputResponseValue::Ok(v) => v,
                    InputResponseValue::Err { error } => {
                        serde_json::json!({ "error": {
                            "code": error.code,
                            "message": error.message,
                            "data": error.data,
                        }})
                    }
                };
                (token, v)
            })
            .collect();
        let response = runtime
            .handle_multi_input_resumption(ctx, &decoded_pipeline_id, answers)
            .await;
        spend_request_state_after_resume(codec, &mrtr.request_state, &response).await;
        // A resume that ran the pipeline to completion returns a
        // result without `resultType`; stamp `"complete"`. A re-
        // suspension already carries `"input_required"`.
        return stamp_complete_result_type(response);
    }

    let (correlation_token, response_value) = responses.entries.into_iter().next().unwrap();
    let (result, error) = match response_value {
        InputResponseValue::Ok(v) => (Some(v), None),
        InputResponseValue::Err { error } => (
            None,
            Some(crate::protocol::JsonRpcErrorBody {
                code: error.code,
                message: error.message,
                data: error.data,
            }),
        ),
    };

    tracing::debug!(
        request_id = ctx.request_id.as_str(),
        correlation_token = %correlation_token,
        decoded_pipeline_id = %decoded_pipeline_id,
        "MRTR resumption: delegating to legacy handle_server_request_response"
    );

    // Drop the unused request_id binding; the resumption path mints
    // its own response envelope using the original tools/call id
    // recovered from the pipeline state.
    let _ = request_id;

    let response_id_value = Value::String(correlation_token);
    let response = runtime
        .handle_server_request_response(ctx, response_id_value, result, error)
        .await;
    spend_request_state_after_resume(codec, &mrtr.request_state, &response).await;
    stamp_complete_result_type(response)
}

/// JSON-RPC error codes a resume can return WITHOUT having advanced the
/// pipeline: the pending request was already gone (`-32600`), the pipeline
/// state had expired/completed (`-32001`), or a transient KV read failed
/// (`-32603`). On these the resume committed nothing, so the inline
/// `requestState` blob must stay un-spent — a legitimate retry has to be able
/// to re-present it.
pub(crate) fn resume_did_not_commit(response: &ProtocolHttpResponse) -> bool {
    match &response.response {
        ProtocolResponse::JsonRpcError(err) => {
            matches!(err.error.code, -32600 | -32001 | -32603)
        }
        _ => false,
    }
}

/// Spend the inline `requestState` blob (cross-replica single-use claim) AND
/// clean up any handle-encoded state — but only once the resume actually
/// committed. Deferring the claim past the resume means a recoverable
/// downstream failure (pending-not-found / expired / transient KV error)
/// leaves the blob reusable instead of wedging the suspension until pipeline
/// timeout. Double-resume is already prevented by the pipeline's own
/// `try_claim_pipeline` CAS, so the blob claim is purely the bearer-replay
/// guard for an already-completed resume. Handle (`h.`) blobs are single-use
/// by construction (the resume deletes the handle); `cleanup` removes any
/// residual handle row regardless of outcome.
pub(crate) async fn spend_request_state_after_resume(
    codec: &crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec,
    request_state: &str,
    response: &ProtocolHttpResponse,
) {
    let _ = codec.cleanup(request_state).await;
    if resume_did_not_commit(response) {
        return;
    }
    if let Err(error) = codec.enforce_single_use(request_state).await {
        tracing::debug!(error = %error, "MRTR requestState already spent post-resume");
    }
}
