use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::protocol::v_2026_07_28::extensions::events::errors::EventsErrorData;
use crate::protocol::v_2026_07_28::extensions::events::wire::UnsubscribeDelivery;
use crate::runtime::events::test_support::{
    ORDERS_TYPE, WebhookHarness, request_context, verified_identity, whsec,
};

fn alice() -> RequestContext {
    request_context(verified_identity("alice"))
}

fn unsubscribe(h: &WebhookHarness, path: &str, arguments: Value) -> UnsubscribeEventsParams {
    UnsubscribeEventsParams {
        name: "orders.created".to_owned(),
        arguments: arguments.as_object().cloned().unwrap_or_default(),
        delivery: UnsubscribeDelivery {
            mode: Some("webhook".to_owned()),
            url: h.receiver.url(path),
        },
        meta: None,
    }
}

#[tokio::test]
async fn a_subscribe_verifies_the_callback_then_grants_a_deterministic_subscription() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let result = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({ "region": "eu" }), 1))
        .await
        .expect("subscribes");
    assert!(result.id.starts_with("sub_"));
    assert!(result.refresh_before.is_some(), "a finite grant");
    assert!(result.cursor.is_some(), "a replayable type issues a cursor");
    assert!(!result.truncated);
    let status = result.delivery_status.expect("a delivery status");
    assert!(status.active);
    let challenges = h.receiver.envelopes("verification");
    assert_eq!(challenges.len(), 1, "one challenge for a new callback");
    assert_eq!(
        challenges[0].header("x-mcp-subscription-id").as_deref(),
        Some(result.id.as_str())
    );

    // The same key is the same subscription: the cursor is a no-op and no
    // second challenge goes out.
    let again = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({ "region": "eu" }), 1))
        .await
        .expect("refreshes");
    assert_eq!(again.id, result.id);
    assert_eq!(h.receiver.envelopes("verification").len(), 1);

    // Another principal, URL or argument set is another subscription.
    let bob = h
        .core
        .subscribe_webhook(
            &request_context(verified_identity("bob")),
            h.params("/hook", json!({ "region": "eu" }), 1),
        )
        .await
        .unwrap();
    assert_ne!(bob.id, result.id);
    let other_args = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({ "region": "us" }), 1))
        .await
        .unwrap();
    assert_ne!(other_args.id, result.id);
}

#[tokio::test]
async fn a_failed_challenge_answers_32015_and_stores_nothing() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    h.receiver.set_reply(Arc::new(|_| (200, b"{}".to_vec())));
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .expect_err("refused");
    assert_eq!(error.code(), -32015);
    assert!(matches!(
        EventsErrorData::parse(error.code(), error.data()),
        Some(EventsErrorData::CallbackEndpoint(data))
            if data.reason == DeliveryErrorCategory::ChallengeFailed
    ));
    let stores = h.core.stores().unwrap();
    let principal = verified_identity("alice")
        .synthetic_principal_key()
        .unwrap();
    assert_eq!(
        stores
            .subscriptions
            .principal_usage(&principal)
            .await
            .unwrap()
            .subscriptions,
        0
    );

    h.receiver.set_reply(Arc::new(|_| (500, Vec::new())));
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/other", json!({}), 1))
        .await
        .expect_err("refused");
    assert_eq!(
        error.data().unwrap()["reason"],
        DeliveryErrorCategory::Http5xx.as_str()
    );
}

#[tokio::test]
async fn subscribe_refuses_bad_input_before_any_request() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let mut params = h.params("/hook", json!({}), 1);
    params.delivery.url = "ftp://receiver.test/hook".to_owned();
    let error = h
        .core
        .subscribe_webhook(&alice(), params)
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32602);
    assert!(
        !error.message().contains("receiver.test"),
        "the URL is not echoed"
    );

    let params = h.params("/hook", json!({ "region": 7 }), 1);
    let error = h
        .core
        .subscribe_webhook(&alice(), params)
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32602, "arguments outside the inputSchema");

    let mut params = h.params("/hook", json!({}), 1);
    params.name = "nope".to_owned();
    let error = h
        .core
        .subscribe_webhook(&alice(), params)
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32011);

    let mut deep = json!("leaf");
    for _ in 0..10 {
        deep = json!({ "n": deep });
    }
    let mut params = h.params("/hook", json!({}), 1);
    params.arguments = json!({ "region": deep }).as_object().cloned().unwrap();
    let error = h
        .core
        .subscribe_webhook(&alice(), params)
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32602);

    assert!(
        h.receiver.requests().is_empty(),
        "no request leaves before the local checks pass"
    );
}

#[tokio::test]
async fn subscribe_and_unsubscribe_need_a_verified_principal_by_default() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let header = request_context(RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "test".to_owned(),
    });
    let anonymous = request_context(RequestIdentity::Anonymous {
        source: "test".to_owned(),
    });
    for ctx in [&header, &anonymous] {
        let error = h
            .core
            .subscribe_webhook(ctx, h.params("/hook", json!({}), 1))
            .await
            .unwrap_err();
        assert_eq!(error.code(), -32012);
        let error = h
            .core
            .unsubscribe_webhook(ctx, unsubscribe(&h, "/hook", json!({})))
            .await
            .unwrap_err();
        assert_eq!(error.code(), -32012);
    }
    assert!(h.receiver.requests().is_empty());
}

#[tokio::test]
async fn header_asserted_principals_may_subscribe_when_the_operator_opts_in() {
    let h = WebhookHarness::start(
        "      webhook: { require_trust: header_asserted }",
        ORDERS_TYPE,
    )
    .await;
    let header = request_context(RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "test".to_owned(),
    });
    let result = h
        .core
        .subscribe_webhook(&header, h.params("/hook", json!({}), 1))
        .await
        .expect("subscribes");
    let verified = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap();
    assert_ne!(
        result.id, verified.id,
        "a header-asserted alice is not the verified alice"
    );
}

#[tokio::test]
async fn unsubscribe_is_idempotent_and_reaches_only_the_callers_own_key() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap();
    // Bob's unsubscribe of the same URL is another key: Alice's stays.
    h.core
        .unsubscribe_webhook(
            &request_context(verified_identity("bob")),
            unsubscribe(&h, "/hook", json!({})),
        )
        .await
        .expect("{} for an unknown key");
    let principal = verified_identity("alice")
        .synthetic_principal_key()
        .unwrap();
    let stores = h.core.stores().unwrap();
    assert_eq!(
        stores
            .subscriptions
            .principal_usage(&principal)
            .await
            .unwrap()
            .subscriptions,
        1
    );
    for _ in 0..2 {
        h.core
            .unsubscribe_webhook(&alice(), unsubscribe(&h, "/hook", json!({})))
            .await
            .expect("idempotent");
    }
    assert_eq!(
        stores
            .subscriptions
            .principal_usage(&principal)
            .await
            .unwrap()
            .subscriptions,
        0
    );
}

#[tokio::test]
async fn unsubscribe_of_an_unknown_key_can_answer_not_found() {
    let h = WebhookHarness::start("      unsubscribe_unknown: not_found", ORDERS_TYPE).await;
    let error = h
        .core
        .unsubscribe_webhook(&alice(), unsubscribe(&h, "/hook", json!({})))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32011);
    assert_eq!(error.data().unwrap()["kind"], "subscription");
}

#[tokio::test]
async fn limits_are_checked_before_the_challenge() {
    let h = WebhookHarness::start(
        "      webhook: { limits: { per_principal: 1, per_principal_callback_hosts: 1 } }",
        ORDERS_TYPE,
    )
    .await;
    h.core
        .subscribe_webhook(&alice(), h.params("/a", json!({}), 1))
        .await
        .unwrap();
    let before = h.receiver.requests().len();
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/b", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32013);
    assert_eq!(error.data().unwrap()["limit"], "subscriptions");
    assert_eq!(h.receiver.requests().len(), before);
    // A refresh of the subscription held is not a new one.
    h.core
        .subscribe_webhook(&alice(), h.params("/a", json!({}), 1))
        .await
        .expect("a refresh at the limit");
}

#[tokio::test]
async fn a_refresh_rotates_the_secret_and_keeps_the_previous_one_for_the_grace() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let first = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap();
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 2))
        .await
        .unwrap();
    let stores = h.core.stores().unwrap();
    let record = stores.subscriptions.get(&first.id).await.unwrap().unwrap();
    let current = stores
        .subscriptions
        .open_secret(&record.id, &record.secret)
        .unwrap();
    assert_eq!(current.expose_secret(), whsec(2));
    let previous = stores
        .subscriptions
        .open_secret(&record.id, record.previous_secret.as_ref().unwrap())
        .unwrap();
    assert_eq!(previous.expose_secret(), whsec(1));
    assert!(record.previous_secret_until_ms.unwrap() > now_ms());
    assert!(record.reactivated_at_ms.is_some());
}

#[tokio::test]
async fn a_paused_gateway_still_answers_subscribe_with_an_inactive_status() {
    let h = WebhookHarness::start("      delivery_paused: true", ORDERS_TYPE).await;
    let result = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap();
    let status = result.delivery_status.unwrap();
    assert!(!status.active);
    assert_eq!(status.last_error, Some(DeliveryErrorCategory::Paused));
}

#[tokio::test]
async fn an_event_rule_governs_subscribe_with_cel_over_the_arguments() {
    let rules = r#"governance:
  policy:
    tool_access:
      rules:
        - event_name: orders.created
          minimum_trust: verified
          cel_allow_if: 'surface == "event" && (!has(arguments.region) || arguments.region == "eu")'"#;
    let h = WebhookHarness::start_in(tempfile::tempdir().unwrap(), rules, "", ORDERS_TYPE).await;
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({ "region": "eu" }), 1))
        .await
        .expect("allowed");
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({ "region": "us" }), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32012);
    assert_eq!(error.data().unwrap()["reason"], "policy");
}

#[test]
fn bearer_claims_read_exp_and_jti_from_a_jwt_only() {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"exp":1700000000,"jti":"j-1","sub":"alice"}"#);
    let claims = jwt_claims(&format!("e30.{payload}.sig")).unwrap();
    assert_eq!(claims.exp, Some(1_700_000_000));
    assert_eq!(claims.jti.as_deref(), Some("j-1"));
    assert!(jwt_claims("opaque-token").is_none());
    assert!(jwt_claims("a.b.c.d").is_none());
}

#[test]
fn only_a_gateway_minted_token_contributes_a_grant_and_jti() {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"exp":1700000000,"jti":"j-1"}"#);
    let mut ctx = alice().with_inbound_bearer(Some(format!("e30.{payload}.sig")));
    let snapshot = credential_snapshot(&ctx);
    assert_eq!(snapshot.token_exp_ms, Some(1_700_000_000_000));
    assert_eq!(
        snapshot.jti, None,
        "a token from another issuer has no revocation feed here"
    );

    ctx.identity = RequestIdentity::Verified {
        subject_id: "alice".to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: crate::runtime::EMA_ACCESS_TOKEN_SOURCE.to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: [("grant_id".to_owned(), "g-1".to_owned())].into(),
    };
    let snapshot = credential_snapshot(&ctx);
    assert_eq!(snapshot.grant_id.as_deref(), Some("g-1"));
    assert_eq!(snapshot.jti.as_deref(), Some("j-1"));
}

#[test]
fn gate_denials_map_to_events_codes() {
    let denial = |code: i32, data: Option<Value>| {
        crate::runtime::util::protocol_http_error(403, None, code, "denied", data)
    };
    assert_eq!(gate_error(denial(-32003, None)).code(), -32012);
    assert_eq!(gate_error(denial(-32022, None)).code(), -32012);
    assert_eq!(gate_error(denial(-33000, None)).code(), -32012);
    assert_eq!(gate_error(denial(-33001, None)).code(), -32013);
    assert_eq!(gate_error(denial(-32029, None)).code(), -32013);
    // The policy gate marks a missing scope under the transport's key; the
    // events error keeps it there, so the transport still mints the
    // `insufficient_scope` challenge.
    let key = crate::transports::http::INSUFFICIENT_SCOPE_DATA_KEY;
    let scoped = gate_error(denial(
        -32003,
        Some(json!({ key: "events:read events:write" })),
    ));
    let data = scoped.data().unwrap();
    assert_eq!(data["reason"], "insufficient_scope");
    assert_eq!(data[key], "events:read events:write");
    assert_eq!(
        gate_error(denial(-32003, Some(json!({ "other": true }))))
            .data()
            .unwrap()["reason"],
        "trust",
        "a denial with no missing scope is the trust floor"
    );
}

#[tokio::test]
async fn a_receiver_document_stands_in_for_the_challenge() {
    let h = WebhookHarness::start(
        "      webhook: { verification: { modes: [challenge, well_known] } }",
        ORDERS_TYPE,
    )
    .await;
    let prefix = h.receiver.url("/hooks/");
    h.receiver.set_reply(Arc::new(
        move |request: &crate::runtime::events::test_support::Received| {
            if request.method == axum::http::Method::GET
                && request.path == crate::runtime::events::verifier::RECEIVER_DOCUMENT_PATH
            {
                let document = json!({ "callbacks": [prefix.clone()] });
                (200, serde_json::to_vec(&document).unwrap())
            } else {
                (200, Vec::new())
            }
        },
    ));
    h.core
        .subscribe_webhook(&alice(), h.params("/hooks/orders", json!({}), 1))
        .await
        .expect("a documented callback needs no challenge");
    assert!(
        h.receiver.envelopes("verification").is_empty(),
        "no challenge was posted"
    );
    // A URL the document does not name still gets the challenge, which this
    // receiver does not echo.
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/elsewhere", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32015);
}
