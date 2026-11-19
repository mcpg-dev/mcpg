//! The URL elicitation a tool call answers with (MCP Elicitation).

use serde_json::json;

use super::*;

fn elicitation() -> UrlElicitation {
    UrlElicitation {
        id: "link-id-0123456789".to_owned(),
        url: "https://gw.example/oauth/connect?e=link-id-0123456789".to_owned(),
        message: "`crm` needs your Acme SSO sign-in".to_owned(),
        expires_at: 1_900_000_000,
    }
}

/// The JSON-RPC message `response` carries.
fn body(response: &ProtocolHttpResponse) -> Value {
    match response.response {
        ProtocolResponse::JsonRpcSuccess(ref success) => serde_json::to_value(success),
        ProtocolResponse::JsonRpcError(ref error) => serde_json::to_value(error),
        ProtocolResponse::NotificationAccepted => panic!("expected a JSON-RPC message"),
    }
    .expect("response serializes")
}

/// An `InputRequiredResult` whose one input request is a URL-mode
/// `elicitation/create` without an id, and the `requestState` to echo.
#[test]
fn the_answer_is_an_input_required_result() {
    let response = input_required(json!(7), &elicitation(), "l.sealed".to_owned());
    assert_eq!(response.http_status, 200);
    let body = body(&response);
    assert_eq!(body["id"], 7);
    assert_eq!(
        body["result"],
        json!({
            "resultType": "input_required",
            "requestState": "l.sealed",
            "inputRequests": {
                "connect_sign_in": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "url",
                        "message": "`crm` needs your Acme SSO sign-in",
                        "url": "https://gw.example/oauth/connect?e=link-id-0123456789",
                    },
                },
            },
        })
    );
}

/// The URL-mode elicitation carries no `elicitationId`: the retry names the
/// link by its sealed `requestState`.
#[test]
fn the_answer_does_not_carry_an_elicitation_id() {
    let response = input_required(json!(7), &elicitation(), "l.sealed".to_owned());
    let body = body(&response).to_string();
    assert!(!body.contains("elicitationId"), "{body}");
}
