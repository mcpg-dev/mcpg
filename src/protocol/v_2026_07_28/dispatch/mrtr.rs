//! MRTR resumption (SEP-2322): the retry of a request that answered
//! `InputRequiredResult`, carrying `requestState` + `inputResponses` at
//! the top level of params.

use crate::protocol::shared::error::INVALID_PARAMS_CODE;
use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, ProtocolResponse};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_client_error, handler_internal_error, map_request_state_decode_error,
    stamp_complete_result_type,
};
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use futures::FutureExt as _;
use serde_json::Value;

/// The `requestState` + `inputResponses` of an MRTR retry.
pub(crate) struct MrtrResumption {
    pub(crate) request_state: String,
    pub(crate) input_responses: Value,
}

impl MrtrResumption {
    /// The resumption a request's params carry: `Some` only when **both**
    /// `requestState` and `inputResponses` are present. Either one alone
    /// falls through to the ordinary path, which answers it as a new
    /// request.
    pub(crate) fn from_params(
        request_state: Option<&str>,
        input_responses: Option<&Value>,
    ) -> Option<Self> {
        Some(Self {
            request_state: request_state?.to_owned(),
            input_responses: input_responses?.clone(),
        })
    }
}

/// What the retry of a `tools/call` that offered the caller a link to
/// store their IdP sign-in comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkResumption {
    /// The request carries no `requestState` of a link.
    NotALink,
    /// The call runs again; the request context holds the user's answer.
    Resumed,
    /// The `requestState` of a link that does not verify for this caller
    /// and tool, or unreadable `inputResponses`.
    Refused(&'static str),
}

/// How the user answered the link a `requestState` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkAnswer {
    /// They opened it (`accept`).
    Accepted,
    /// They declined or dismissed it, or the client could not show it.
    Declined,
    /// The retry carries no answer for it.
    Unanswered,
}

fn link_answer(input_responses: Option<&Value>) -> Result<LinkAnswer, &'static str> {
    use crate::protocol::v_2026_07_28::wire::mrtr::{InputResponseValue, InputResponses};
    use crate::runtime::authorization_server::connect::LINK_INPUT_KEY;
    let Some(input_responses) = input_responses else {
        return Ok(LinkAnswer::Unanswered);
    };
    let mut responses =
        InputResponses::from_value(input_responses).map_err(|_| "invalid inputResponses")?;
    Ok(match responses.entries.remove(LINK_INPUT_KEY) {
        None => LinkAnswer::Unanswered,
        Some(InputResponseValue::Err { .. }) => LinkAnswer::Declined,
        Some(InputResponseValue::Ok(result)) => {
            match result.get("action").and_then(Value::as_str) {
                Some("accept") => LinkAnswer::Accepted,
                Some("decline" | "cancel") => LinkAnswer::Declined,
                _ => LinkAnswer::Unanswered,
            }
        }
    })
}

/// Take the retry of a `tools/call` of `tool` whose earlier attempt
/// offered the caller a link to store their IdP sign-in (a URL-mode
/// elicitation): its `requestState` must open under the sign-in state keys
/// and name a link offered to this caller for this tool (SEP-2322: state is
/// attacker-controlled). An accepted link is waited for a short while; a
/// declined one is not offered again; an unanswered one is offered again
/// while it is pending; one that expired runs the call again as a new
/// request would. `requestState` and `inputResponses` are the top-level
/// params of the retry.
pub(crate) async fn resume_connect_link(
    ctx: &RequestContext,
    runtime: &crate::runtime::GatewayRuntime,
    tool: &str,
    request_state: Option<&str>,
    input_responses: Option<&Value>,
) -> LinkResumption {
    use crate::runtime::authorization_server::connect::{
        LINK_REQUEST_STATE_PREFIX, LinkStateCheck,
    };
    let Some(request_state) =
        request_state.filter(|state| state.starts_with(LINK_REQUEST_STATE_PREFIX))
    else {
        return LinkResumption::NotALink;
    };
    let refused = LinkResumption::Refused(
        "requestState does not name a link offered to this caller for this tool",
    );
    let principal = match ctx.identity {
        crate::runtime::RequestIdentity::Verified { .. } => ctx.identity.synthetic_principal_key(),
        _ => None,
    };
    let (Some(server), Some(principal)) = (runtime.ema_authorization_server(), principal) else {
        return refused;
    };
    // A link that expired was still offered to this caller for this tool:
    // the call runs again, and succeeds or offers a new link.
    let link = match server.open_link_request_state(request_state, &principal, tool) {
        LinkStateCheck::Valid(link) => Some(link),
        LinkStateCheck::Expired => None,
        LinkStateCheck::Refused => return refused,
    };
    match (link_answer(input_responses), link) {
        (Err(reason), _) => return LinkResumption::Refused(reason),
        (Ok(LinkAnswer::Declined), _) => ctx.connect_link.decline(),
        (Ok(_), None) => {}
        (Ok(LinkAnswer::Accepted), Some(link)) => {
            let status = server
                .await_link(&link, &principal, server.link_resume_wait())
                .boxed()
                .await;
            tracing::debug!(status = ?status, "the retry of a call that offered a link");
            ctx.connect_link.resume(link);
        }
        (Ok(LinkAnswer::Unanswered), Some(link)) => ctx.connect_link.resume(link),
    }
    LinkResumption::Resumed
}

/// Resume the pipeline an MRTR `requestState` names with the client's
/// `inputResponses`, so it picks up where it suspended, and answer under
/// `request_id`, the id of the retry.
///
/// The `requestState` must open under the codec for the calling principal
/// (AEAD-bound to its owner), and the pipeline id it seals is the pipeline
/// that resumes. One answer goes to `resume_single_input`, which requires
/// its correlation token to be the request the pipeline awaits; the
/// answers to a `gather` step's batch go to
/// `handle_multi_input_resumption`, which records each and resumes once.
pub(crate) async fn dispatch_mrtr_resumption(
    ctx: &RequestContext,
    runtime: &crate::runtime::GatewayRuntime,
    services: &SharedServices,
    request_id: Value,
    mrtr: MrtrResumption,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::wire::mrtr::{InputResponseValue, InputResponses};

    // The blob must open for this gateway's codec (key not rotated,
    // ciphertext not tampered); its payload is the pipeline id.
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
    // step's batch in one `inputResponses` map. Route to the multi-input
    // resume path that records every answer and resumes once.
    if responses.entries.len() > 1 {
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
            .handle_multi_input_resumption(ctx, request_id, &decoded_pipeline_id, answers)
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
        "MRTR resumption: resuming the suspended pipeline"
    );

    let response = runtime
        .resume_single_input(
            ctx,
            request_id,
            &decoded_pipeline_id,
            &correlation_token,
            result,
            error,
        )
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

/// Spend the `requestState` blob once the resume committed: claim an inline
/// (`c.`) blob in the cross-replica single-use ledger and delete the row of
/// a handle (`h.`) blob. A resume that committed nothing (pending-not-found,
/// a foreign resumer, expired, a transient KV error) leaves the blob
/// reusable, so neither a recoverable failure nor another principal that
/// presents the blob can take the owner's resume away. Double-resume is
/// already prevented by the pipeline's own `try_claim_pipeline` CAS, so the
/// spend is the bearer-replay guard for an already-completed resume.
pub(crate) async fn spend_request_state_after_resume(
    codec: &crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec,
    request_state: &str,
    response: &ProtocolHttpResponse,
) {
    if resume_did_not_commit(response) {
        return;
    }
    let _ = codec.cleanup(request_state).await;
    if let Err(error) = codec.enforce_single_use(request_state).await {
        tracing::debug!(error = %error, "MRTR requestState already spent post-resume");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_resumption_needs_both_request_state_and_input_responses() {
        let answers = json!({ "e1": { "action": "accept" } });
        let resumption =
            MrtrResumption::from_params(Some("c.blob"), Some(&answers)).expect("resumption");
        assert_eq!(resumption.request_state, "c.blob");
        assert_eq!(resumption.input_responses, answers);

        assert!(MrtrResumption::from_params(Some("c.blob"), None).is_none());
        assert!(MrtrResumption::from_params(None, Some(&answers)).is_none());
        assert!(MrtrResumption::from_params(None, None).is_none());
    }

    #[test]
    fn link_answers_read_the_connect_input() {
        use crate::runtime::authorization_server::connect::LINK_INPUT_KEY;
        let answered = |value: Value| json!({ LINK_INPUT_KEY: value });
        assert_eq!(link_answer(None), Ok(LinkAnswer::Unanswered));
        assert_eq!(
            link_answer(Some(&answered(json!({ "action": "accept" })))),
            Ok(LinkAnswer::Accepted)
        );
        assert_eq!(
            link_answer(Some(&answered(json!({ "action": "decline" })))),
            Ok(LinkAnswer::Declined)
        );
        assert_eq!(
            link_answer(Some(&answered(json!({ "action": "cancel" })))),
            Ok(LinkAnswer::Declined)
        );
        assert_eq!(
            link_answer(Some(&json!({ "other": { "action": "accept" } }))),
            Ok(LinkAnswer::Unanswered)
        );
        assert!(link_answer(Some(&json!("not a map"))).is_err());
    }
}
