//! The answer to a tool call whose federated upstream needs the caller's
//! stored IdP sign-in and found none, when the call may offer the link
//! that stores it: a URL-mode elicitation (MCP Elicitation) inside an
//! `InputRequiredResult`. Its `inputRequests` holds one URL-mode
//! `elicitation/create`, and its `requestState` names the link, sealed for
//! the caller and the tool. The client retries with both.

use std::collections::BTreeMap;

use serde_json::Value;

use super::super::*;
use crate::protocol::{JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse};
use crate::runtime::authorization_server::connect::LINK_INPUT_KEY;
use crate::runtime::federation::idp_sessions::UrlElicitation;

/// An `InputRequiredResult` with the elicitation and `request_state`.
pub(crate) fn input_required(
    request_id: Value,
    elicitation: &UrlElicitation,
    request_state: String,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::wire::mrtr::{InputRequest, InputRequiredResult};
    let mut input_requests = BTreeMap::new();
    input_requests.insert(
        LINK_INPUT_KEY.to_owned(),
        InputRequest::Elicitation {
            params: serde_json::json!({
                "mode": "url",
                "message": elicitation.message,
                "url": elicitation.url,
            }),
        },
    );
    let result = InputRequiredResult::new(request_state, input_requests);
    match serde_json::to_value(&result) {
        Ok(result) => ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result,
            }),
        },
        Err(error) => {
            tracing::error!(error = %error, "an InputRequiredResult could not be serialized");
            protocol_http_error(
                200,
                Some(request_id),
                -32603,
                "the tool call could not be answered",
                None,
            )
        }
    }
}

impl GatewayRuntime {
    /// The URL elicitation that answers the call of `tool` for
    /// `request_context`. `None` when the caller has no principal or the
    /// `requestState` cannot be sealed: the call then answers with its tool
    /// error.
    pub(crate) fn connect_link_response(
        &self,
        request_context: &RequestContext,
        request_id: Value,
        tool: &str,
        elicitation: &UrlElicitation,
    ) -> Option<ProtocolHttpResponse> {
        metrics::counter!("mcpg_federation_url_elicitation_total").increment(1);
        let principal = request_context.identity.synthetic_principal_key()?;
        let request_state = self.ema_authorization_server()?.link_request_state(
            &elicitation.id,
            elicitation.expires_at,
            &principal,
            tool,
        )?;
        Some(input_required(request_id, elicitation, request_state))
    }
}

#[cfg(test)]
#[path = "connect_link_tests.rs"]
mod tests;
