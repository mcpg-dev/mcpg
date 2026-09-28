//! The URL elicitation a tool call answers with, in the shape of each
//! protocol version (MCP Elicitation).

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

/// `2025-11-25`: the error `-32042` whose `data.elicitations` holds one
/// URL-mode elicitation with its id, url and message, and whose own
/// message carries that text and link for a client that shows only it.
#[test]
fn the_2025_wire_answers_url_elicitation_required() {
    let response = url_elicitation_required(json!("call-1"), &elicitation());
    assert_eq!(response.http_status, 200);
    assert_eq!(
        body(&response),
        json!({
            "jsonrpc": "2.0",
            "id": "call-1",
            "error": {
                "code": -32042,
                "message": "`crm` needs your Acme SSO sign-in Link: \
                            https://gw.example/oauth/connect?e=link-id-0123456789",
                "data": {
                    "elicitations": [{
                        "mode": "url",
                        "elicitationId": "link-id-0123456789",
                        "url": "https://gw.example/oauth/connect?e=link-id-0123456789",
                        "message": "`crm` needs your Acme SSO sign-in",
                    }],
                },
            },
        })
    );
}

/// `2026-07-28`: an `InputRequiredResult` whose one input request is a
/// URL-mode `elicitation/create` without an id (the version removed
/// `elicitationId`), and the `requestState` to echo.
#[test]
fn the_2026_wire_answers_an_input_required_result() {
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

/// Only a `2025-11-25` request on a session with a delivery stream is told
/// when its link completes.
#[test]
fn only_a_legacy_session_is_told_of_completion() {
    let context = |session: Option<&str>| {
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            session.map(str::to_owned),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        )
    };
    let legacy = context(Some("sess-1"))
        .with_negotiated_version(crate::protocol::version::ProtocolVersion::V_2025_11_25);
    assert_eq!(
        connect_link_notify_session(&legacy).as_deref(),
        Some("sess-1")
    );
    assert_eq!(connect_link_notify_session(&context(None)), None);
    let modern = context(Some("sess-2"))
        .with_negotiated_version(crate::protocol::version::ProtocolVersion::V_2026_07_28);
    assert_eq!(connect_link_notify_session(&modern), None);
    let mut ephemeral = context(Some("sess-3"));
    ephemeral.session_ephemeral = true;
    assert_eq!(connect_link_notify_session(&ephemeral), None);
}
