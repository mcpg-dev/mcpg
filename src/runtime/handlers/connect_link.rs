//! The answer to a tool call whose federated upstream needs the caller's
//! stored IdP sign-in and found none, when the call may offer the link
//! that stores it: a URL-mode elicitation in the shape the negotiated
//! protocol version defines (MCP Elicitation).
//!
//! - `2025-11-25`: the JSON-RPC error `-32042` (URL elicitation required),
//!   whose `data.elicitations` holds one URL-mode elicitation with its
//!   `elicitationId`, and whose message repeats its text and link. The
//!   session is told when the link completes
//!   (`notifications/elicitation/complete`), and the client retries.
//! - `2026-07-28`: an `InputRequiredResult` whose `inputRequests` holds one
//!   URL-mode `elicitation/create`, which carries no id, and whose
//!   `requestState` names the link, sealed for the caller and the tool.
//!   The client retries with both.

use std::collections::BTreeMap;

use super::super::*;
use crate::runtime::authorization_server::connect::LINK_INPUT_KEY;
use crate::runtime::federation::idp_sessions::UrlElicitation;

/// The `message` of a `-32042` error: what the elicitation asks, and its
/// link, so a client that shows only the message still tells the user
/// what to do.
fn url_elicitation_required_message(elicitation: &UrlElicitation) -> String {
    format!("{} Link: {}", elicitation.message, elicitation.url)
}

/// The session told when a link offered to `request_context` completes:
/// that of a `2025-11-25` request whose session has a delivery stream.
pub(crate) fn connect_link_notify_session(request_context: &RequestContext) -> Option<String> {
    (request_context.negotiated_version != crate::protocol::version::ProtocolVersion::V_2026_07_28
        && !request_context.session_ephemeral)
        .then(|| request_context.session_id.clone())
        .flatten()
}

/// The `2025-11-25` answer: `-32042` with the elicitation.
pub(crate) fn url_elicitation_required(
    request_id: Value,
    elicitation: &UrlElicitation,
) -> ProtocolHttpResponse {
    protocol_http_error(
        200,
        Some(request_id),
        crate::protocol::URL_ELICITATION_REQUIRED_CODE,
        url_elicitation_required_message(elicitation),
        Some(serde_json::json!({
            "elicitations": [{
                "mode": "url",
                "elicitationId": elicitation.id,
                "url": elicitation.url,
                "message": elicitation.message,
            }],
        })),
    )
}

/// The `2026-07-28` answer: an `InputRequiredResult` with the elicitation
/// and `request_state`.
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
            session_id_header: None,
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
    /// `request_context`, in the shape of its protocol version. `None` when
    /// the `2026-07-28` `requestState` cannot be sealed: the call then
    /// answers with its tool error.
    pub(crate) fn connect_link_response(
        &self,
        request_context: &RequestContext,
        request_id: Value,
        tool: &str,
        elicitation: &UrlElicitation,
    ) -> Option<ProtocolHttpResponse> {
        metrics::counter!(
            "mcpg_federation_url_elicitation_total",
            "protocol_version" => request_context.negotiated_version.as_str(),
        )
        .increment(1);
        if request_context.negotiated_version
            != crate::protocol::version::ProtocolVersion::V_2026_07_28
        {
            return Some(url_elicitation_required(request_id, elicitation));
        }
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
