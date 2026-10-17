use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mcpg_standard_webhooks::{Verifier, WhsecSecret};
use serde_json::json;

use super::*;
use crate::protocol::v_2026_07_28::extensions::events::wire::SubscribeEventsResult;
use crate::runtime::events::test_support::{
    ORDERS_TYPE, Received, WebhookHarness, echo_reply, eventually, eventually_within,
    request_context, verified_identity, whsec,
};

fn now_s() -> u64 {
    now_ms() / 1_000
}

fn alice() -> RequestContext {
    request_context(verified_identity("alice"))
}

async fn subscribe(h: &WebhookHarness, arguments: Value) -> SubscribeEventsResult {
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", arguments, 1))
        .await
        .expect("subscribes")
}

fn event_ids(requests: &[Received]) -> Vec<String> {
    requests
        .iter()
        .map(|r| r.json()["eventId"].as_str().unwrap().to_owned())
        .collect()
}

/// Answer events with the statuses in `script`, in order, then `200`;
/// challenges always pass.
fn scripted(script: Vec<u16>) -> crate::runtime::events::test_support::Reply {
    let calls = Arc::new(AtomicUsize::new(0));
    let echo = echo_reply();
    Arc::new(move |request: &Received| {
        if request.json().get("type").is_some() {
            return echo(request);
        }
        let n = calls.fetch_add(1, Ordering::SeqCst);
        (script.get(n).copied().unwrap_or(200), Vec::new())
    })
}

#[tokio::test]
async fn each_event_goes_in_one_signed_post_whose_id_is_the_event_id() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let subscription = subscribe(&h, json!({ "region": "eu" })).await;
    h.fire("o-1", "eu").await;
    h.fire("o-2", "us").await;
    h.fire("o-3", "eu").await;
    h.deliver().await;

    let events = h.receiver.events();
    assert_eq!(
        event_ids(&events),
        ["o-1", "o-3"],
        "the match drops other regions"
    );
    let verifier = Verifier::new(vec![WhsecSecret::parse(&whsec(1)).unwrap()]).unwrap();
    for request in &events {
        let body = request.json();
        assert_eq!(
            request.header("webhook-id"),
            body["eventId"].as_str().map(str::to_owned)
        );
        assert_eq!(
            request.header("x-mcp-subscription-id").as_deref(),
            Some(subscription.id.as_str())
        );
        assert_eq!(body["name"], "orders.created");
        assert_eq!(body["data"]["region"], "eu");
        assert!(body["cursor"].as_str().unwrap().starts_with("ev1."));
        assert!(body.get("type").is_none());
        verifier
            .verify_headers(&request.headers, &request.body, now_s())
            .expect("every delivery is signed");
        assert!(request.body.len() <= MAX_WEBHOOK_BODY_BYTES);
    }
}

#[tokio::test]
async fn a_failed_delivery_is_retried_with_the_same_id_and_a_fresh_signature() {
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 1800, max_attempts: 5 } }",
        ORDERS_TYPE,
    )
    .await;
    subscribe(&h, json!({})).await;
    h.receiver.set_reply(scripted(vec![503, 500]));
    h.fire("o-1", "eu").await;
    assert!(
        eventually_within(Duration::from_secs(5), || h.receiver.events().len() >= 3).await,
        "two failures and a success: {:?}",
        event_ids(&h.receiver.events())
    );
    h.core.dispatch_settle().await;
    let events = h.receiver.events();
    assert_eq!(event_ids(&events), ["o-1", "o-1", "o-1"]);
    let signatures: std::collections::HashSet<_> = events
        .iter()
        .map(|r| (r.header("webhook-timestamp"), r.header("webhook-signature")))
        .collect();
    assert!(!signatures.is_empty());
    let stores = h.core.stores().unwrap();
    let id = events[0].header("x-mcp-subscription-id").unwrap();
    let state = stores.subscriptions.delivery(&id).await.unwrap().unwrap();
    assert!(state.in_flight.is_empty());
    assert_eq!(
        state.counters.last_error, None,
        "the success clears the error"
    );
    assert!(state.counters.last_delivery_at_ms.is_some());
}

#[tokio::test]
async fn gone_and_too_large_are_never_retried() {
    for status in [410u16, 413] {
        let h = WebhookHarness::start("      webhook: { retry: { window_ms: 1800 } }", ORDERS_TYPE)
            .await;
        let subscription = subscribe(&h, json!({})).await;
        h.receiver.set_reply(scripted(vec![status]));
        h.fire("o-1", "eu").await;
        h.fire("o-2", "eu").await;
        h.deliver().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        h.deliver().await;
        assert_eq!(event_ids(&h.receiver.events()), ["o-1", "o-2"], "{status}");
        let state = h
            .core
            .stores()
            .unwrap()
            .subscriptions
            .delivery(&subscription.id)
            .await
            .unwrap()
            .unwrap();
        assert!(state.in_flight.is_empty());
        assert_eq!(
            state.ack_seq, 2,
            "an abandoned event does not hold the watermark"
        );
    }
}

#[tokio::test]
async fn an_event_id_no_attempt_can_sign_is_abandoned_at_once_and_suspends_nothing() {
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 1800 }, suspension: { min_attempts: 1, failure_rate: 0.01 } }",
        ORDERS_TYPE,
    )
    .await;
    let subscription = subscribe(&h, json!({})).await;
    // A log row whose id holds a `.`, as a build that kept such ids wrote it.
    let lease = (*h.core.owner_lease().borrow()).expect("the owner");
    let ty = Arc::clone(h.core.catalog().get("orders.created").unwrap());
    h.core
        .stores()
        .unwrap()
        .log
        .append(
            &ty.source_key,
            StoredOccurrence {
                event_id: "orders.eu-1".to_owned(),
                timestamp: "2026-10-11T12:00:00.000Z".to_owned(),
                data: json!({ "id": "orders.eu-1", "region": "eu" }),
                audience: None,
                arguments: None,
            },
            &ty.retention,
            lease,
        )
        .await
        .unwrap();
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-2"],
        "the dotted id is never sent, and the next event still is"
    );
    let state = h
        .core
        .stores()
        .unwrap()
        .subscriptions
        .delivery(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.in_flight.is_empty());
    assert_eq!(state.ack_seq, 2);
    assert_eq!(state.counters.suspended_at_ms, None);
    assert_eq!(state.counters.window_failures, 0);
    assert_eq!(state.counters.last_error, None);
}

#[tokio::test]
async fn retries_give_up_after_the_attempt_budget() {
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 1800, max_attempts: 2 } }",
        ORDERS_TYPE,
    )
    .await;
    let subscription = subscribe(&h, json!({})).await;
    h.receiver.set_reply(scripted(vec![500, 500, 500, 500]));
    h.fire("o-1", "eu").await;
    assert!(eventually_within(Duration::from_secs(5), || h.receiver.events().len() >= 2).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.deliver().await;
    assert_eq!(h.receiver.events().len(), 2, "two attempts, then abandoned");
    let state = h
        .core
        .stores()
        .unwrap()
        .subscriptions
        .delivery(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.ack_seq, 1);
    assert_eq!(
        state.counters.last_error,
        Some(DeliveryErrorCategory::Http5xx)
    );
}

#[tokio::test]
async fn a_cursor_in_a_body_never_passes_an_event_still_in_flight() {
    // The first retry waits a 180th of the window: 20 s, past the end of the
    // test however slowly it runs.
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 3600000 } }",
        ORDERS_TYPE,
    )
    .await;
    let subscription = subscribe(&h, json!({})).await;
    // The first event fails and waits for a retry; the second succeeds.
    h.receiver.set_reply(scripted(vec![500]));
    h.fire("o-1", "eu").await;
    h.deliver().await;
    h.fire("o-2", "eu").await;
    h.deliver().await;
    let events = h.receiver.events();
    assert_eq!(event_ids(&events), ["o-1", "o-2"]);
    let stores = h.core.stores().unwrap();
    let ty = h.core.catalog().get("orders.created").cloned().unwrap();
    let scope = CursorScope::new(&ty.source_key, &json!({}));
    let position = |r: &Received| {
        stores
            .keys
            .cursor()
            .open(r.json()["cursor"].as_str().unwrap(), &scope)
            .unwrap()
            .seq
    };
    assert_eq!(
        position(&events[0]),
        1,
        "the first event carries its own position"
    );
    assert_eq!(
        position(&events[1]),
        0,
        "the second does not skip the first, which is still awaiting a retry"
    );
    let state = stores
        .subscriptions
        .delivery(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.ack_seq, 0);
    assert_eq!(state.in_flight.len(), 1);
}

#[tokio::test]
async fn a_restart_on_the_file_store_resumes_without_repeating_delivered_events() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
    h.core.shutdown().await;
    let WebhookHarness {
        dir,
        state,
        core,
        receiver,
        ..
    } = h;
    drop(core);
    drop(state);

    let h = WebhookHarness::start_in(dir, "", "", ORDERS_TYPE).await;
    // The new gateway's receiver is another endpoint; route the old URL to
    // it by keeping the old receiver's port.
    drop(h.receiver);
    let h = WebhookHarness { receiver, ..h };
    h.core.owner_tick().await;
    // The log is in memory here, so the restart lost it: an event that
    // reaches the new log before the dispatcher runs is still delivered,
    // and a gap says what the restart may have dropped.
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-1", "o-2"],
        "nothing repeats"
    );
    assert_eq!(h.receiver.envelopes("gap").len(), 1);
    let gap = &h.receiver.envelopes("gap")[0];
    assert!(gap.header("webhook-id").unwrap().starts_with("msg_gap_"));
    assert!(gap.json()["cursor"].as_str().unwrap().starts_with("ev1."));
}

#[tokio::test]
async fn an_owner_that_steps_down_checkpoints_what_it_delivered() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    for id in ["o-1", "o-2", "o-3"] {
        h.fire(id, "eu").await;
    }
    // Hand the attempts out but leave their outcomes unapplied, so only the
    // hand-off can checkpoint them.
    h.core.dispatch_tick().await;
    assert!(eventually(|| h.receiver.events().len() == 3).await);
    h.core.shutdown().await;

    h.core.owner_tick().await;
    h.fire("o-4", "eu").await;
    h.deliver().await;
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-1", "o-2", "o-3", "o-4"],
        "the next owner repeats nothing the last one delivered"
    );
}

async fn reload_with(h: &WebhookHarness, yaml: &str) {
    crate::app::reload_config_from_yaml(&h.state, yaml)
        .await
        .expect("reload");
    h.core.owner_tick().await;
}

#[tokio::test]
async fn a_breaking_schema_change_ends_delivery_and_the_refresh_says_why() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;

    let broken = h
        .yaml
        .replace("region: { type: string }", "region: { type: integer }");
    assert_ne!(broken, h.yaml);
    reload_with(&h, &broken).await;
    h.deliver().await;
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await
    );
    let terminated = &h.receiver.envelopes("terminated")[0];
    assert_eq!(
        terminated.json()["error"]["code"],
        -32014,
        "{}",
        terminated.json()
    );
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);

    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32014);
    assert_eq!(error.data().unwrap()["reason"], "schema_changed");
    // Re-listed, the client subscribes afresh on the new schema.
    subscribe(&h, json!({})).await;
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1", "o-2"]);
}

#[tokio::test]
async fn an_additive_schema_change_keeps_delivering() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    let grown = h.yaml.replace(
        "properties: { region: { type: string } }",
        "properties: { region: { type: string }, tier: { type: string } }",
    );
    assert_ne!(grown, h.yaml);
    reload_with(&h, &grown).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
    assert!(h.receiver.envelopes("terminated").is_empty());
}

#[tokio::test]
async fn a_terminated_envelope_carries_the_configured_numbering() {
    let h = WebhookHarness::start("      error_codes: sep_3415", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    let other = ORDERS_TYPE
        .replace("orders.created", "invoices.created")
        .replace("source_id: orders", "source_id: invoices");
    reload_with(&h, &h.yaml.replace(ORDERS_TYPE, &other)).await;
    h.deliver().await;
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await
    );
    let terminated = &h.receiver.envelopes("terminated")[0];
    assert_eq!(terminated.json()["error"]["code"], -32023);
    assert_eq!(terminated.json()["error"]["data"]["kind"], "event");
}

#[tokio::test]
async fn a_removed_type_ends_delivery_and_the_refresh_finds_no_event() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    let other = ORDERS_TYPE
        .replace("orders.created", "invoices.created")
        .replace("source_id: orders", "source_id: invoices");
    reload_with(&h, &h.yaml.replace(ORDERS_TYPE, &other)).await;
    h.deliver().await;
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await
    );
    let terminated = &h.receiver.envelopes("terminated")[0];
    assert_eq!(
        terminated.json()["error"]["code"],
        -32011,
        "{}",
        terminated.json()
    );

    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32011);
    assert_eq!(error.data().unwrap()["kind"], "event");

    // The type comes back: the subscriber starts over, not refused.
    reload_with(&h, &h.yaml).await;
    subscribe(&h, json!({})).await;
}

#[tokio::test]
async fn an_end_in_the_log_ends_the_subscriptions_of_its_arguments_after_what_came_before() {
    use crate::runtime::events::log::EndReason;
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let eu = subscribe(&h, json!({ "region": "eu" })).await.id;
    let us = subscribe(&h, json!({ "region": "us" })).await.id;
    h.fire("o-1", "eu").await;
    let stores = h.core.stores().expect("stores");
    let ty = h.core.catalog().get("orders.created").cloned().unwrap();
    let lease = (*h.core.owner_lease().borrow()).expect("the owner");
    let eu_hash = stores
        .keys
        .arguments_hash(json!({ "region": "eu" }).as_object().unwrap());
    stores
        .log
        .append_end(
            &ty.source_key,
            EndReason::Forbidden,
            crate::runtime::events::log::RowScope::of(None, eu_hash),
            &ty.retention,
            lease,
        )
        .await
        .unwrap();
    h.fire("o-2", "eu").await;
    h.fire("o-3", "us").await;
    for _ in 0..3 {
        h.deliver().await;
    }

    let to = |id: &str| -> Vec<Received> {
        h.receiver
            .requests()
            .into_iter()
            .filter(|r| r.header("x-mcp-subscription-id").as_deref() == Some(id))
            .filter(|r| r.json().get("eventId").is_some())
            .collect()
    };
    assert_eq!(event_ids(&to(&eu)), ["o-1"], "nothing past the end");
    assert_eq!(event_ids(&to(&us)), ["o-3"], "other arguments go on");
    // The envelope is posted off the delivery pass.
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await
    );
    let terminated = h.receiver.envelopes("terminated");
    assert_eq!(terminated.len(), 1, "only the ended arguments end");
    assert_eq!(
        terminated[0].header("x-mcp-subscription-id").as_deref(),
        Some(eu.as_str())
    );
    assert_eq!(terminated[0].json()["error"]["code"], -32012);
    assert_eq!(
        terminated[0].json()["error"]["data"]["reason"],
        "upstream_forbidden"
    );

    let again = subscribe(&h, json!({ "region": "eu" })).await;
    assert_eq!(
        again.id, eu,
        "no tombstone: a refresh subscribes anew and asks the upstream again"
    );
}

#[tokio::test]
async fn a_reload_during_delivery_repeats_nothing() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    h.reload().await;
    h.core.owner_tick().await;
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1", "o-2"]);
}

#[tokio::test]
async fn pausing_stops_every_post_and_resuming_delivers_the_backlog() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    h.core.admin_set_paused(true).await.unwrap();
    // The dispatcher reads the flag at most every two seconds.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert!(h.receiver.events().is_empty());
    h.core.admin_set_paused(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
}

#[tokio::test]
async fn delivery_stops_when_the_grant_ends() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let subscription = subscribe(&h, json!({})).await;
    h.fire("o-0", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-0"]);
    let stores = h.core.stores().unwrap();
    let mut record = stores
        .subscriptions
        .get(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    record.expires_at_ms = Some(now_ms() + 200);
    stores.subscriptions.replace(&record).await.unwrap();
    h.core
        .note_subscription(&super::super::subscriptions::SubscriptionHint {
            op: super::super::subscriptions::HintOp::Upsert,
            id: record.id.clone(),
            name: record.name.clone(),
            expires_at_ms: record.expires_at_ms,
        });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A pass that began while the grant still ran ends before the next event.
    drop(h.core.dispatcher().lock().await);
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-0"],
        "nothing after the grant"
    );
}

#[tokio::test]
async fn a_policy_that_no_longer_admits_the_subscriber_ends_delivery_after_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let h = WebhookHarness::start_in(dir, "", "", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert_eq!(h.receiver.events().len(), 1);

    let rules = r#"governance:
  policy:
    tool_access:
      rules:
        - event_name: orders.created
          minimum_trust: verified
          cel_allow_if: '"ops" in identity.roles'"#;
    let yaml = format!(
        r#"
observability: {{ logs: {{ enabled: false }} }}
{rules}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{}" }}
  capabilities:
    events:
{ORDERS_TYPE}
"#,
        crate::runtime::events::test_support::SESSION_KEY,
        h.dir.path().display()
    );
    crate::app::reload_config_from_yaml(&h.state, &yaml)
        .await
        .unwrap();
    h.core.owner_tick().await;
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await,
        "the receiver is told"
    );
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-1"],
        "nothing after the denial"
    );
    let terminated = &h.receiver.envelopes("terminated")[0];
    assert_eq!(terminated.json()["error"]["code"], -32012);
    assert!(
        terminated
            .header("webhook-id")
            .unwrap()
            .starts_with("msg_terminated_")
    );
    // The type is no longer visible to the subscriber, so a refresh finds
    // nothing to refresh.
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32011);
}

#[tokio::test]
async fn repeated_failures_suspend_and_a_refresh_resumes() {
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 1800, max_attempts: 1 }, suspension: { min_attempts: 2, failure_rate: 0.5 } }",
        ORDERS_TYPE,
    )
    .await;
    let subscription = subscribe(&h, json!({})).await;
    h.receiver.set_reply(scripted(vec![500, 500]));
    h.fire("o-1", "eu").await;
    h.deliver().await;
    h.fire("o-2", "eu").await;
    h.deliver().await;
    let stores = h.core.stores().unwrap();
    let state = stores
        .subscriptions
        .delivery(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.counters.suspended_at_ms.is_some(), "suspended");
    h.fire("o-3", "eu").await;
    h.deliver().await;
    assert_eq!(
        event_ids(&h.receiver.events()),
        ["o-1", "o-2"],
        "nothing while suspended"
    );

    let refreshed = subscribe(&h, json!({})).await;
    assert!(refreshed.delivery_status.unwrap().active);
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1", "o-2", "o-3"]);
}

#[tokio::test]
async fn an_operator_terminate_tells_the_receiver_and_refuses_the_refresh() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let subscription = subscribe(&h, json!({})).await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    {
        // A pass already under way holds the record from before; none runs
        // while it changes.
        let _no_pass = h.core.dispatcher().lock().await;
        h.core.admin_terminate(&subscription.id).await.unwrap();
    }
    h.fire("o-2", "eu").await;
    h.deliver().await;
    assert!(
        eventually_within(Duration::from_secs(2), || !h
            .receiver
            .envelopes("terminated")
            .is_empty())
        .await
    );
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
    let error = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap_err();
    assert_eq!(error.data().unwrap()["reason"], "revoked");
    let listed = h.core.admin_subscriptions(None, None, 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "terminated");
    assert!(!serde_json::to_string(&listed).unwrap().contains("/hook"));
}

#[tokio::test]
async fn an_operator_suspend_holds_until_the_client_refreshes() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let subscription = subscribe(&h, json!({})).await;
    {
        // A pass already under way holds the record from before; none runs
        // while it changes.
        let _no_pass = h.core.dispatcher().lock().await;
        h.core.admin_suspend(&subscription.id).await.unwrap();
    }
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert!(h.receiver.events().is_empty());
    subscribe(&h, json!({})).await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
}

#[tokio::test]
async fn a_subscription_made_again_on_an_ended_key_is_delivered() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let first = subscribe(&h, json!({})).await;
    h.core.admin_terminate(&first.id).await.unwrap();
    h.deliver().await;
    {
        // No pass runs between the purge and the new subscribe.
        let _no_pass = h.core.dispatcher().lock().await;
        let alice_key = verified_identity("alice")
            .synthetic_principal_key()
            .unwrap();
        assert_eq!(h.core.admin_purge(&alice_key).await.unwrap(), 1);
        let again = subscribe(&h, json!({})).await;
        assert_eq!(again.id, first.id, "the same key");
    }
    // A pass reads the new record before there is anything to send.
    h.deliver().await;
    h.fire("o-1", "eu").await;
    h.deliver().await;
    assert_eq!(event_ids(&h.receiver.events()), ["o-1"]);
}

#[tokio::test]
async fn purge_removes_every_subscription_of_a_principal() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    subscribe(&h, json!({ "region": "eu" })).await;
    h.core
        .subscribe_webhook(
            &request_context(verified_identity("bob")),
            h.params("/hook", json!({}), 1),
        )
        .await
        .unwrap();
    let alice_key = verified_identity("alice")
        .synthetic_principal_key()
        .unwrap();
    assert_eq!(h.core.admin_purge(&alice_key).await.unwrap(), 2);
    let left = h.core.admin_subscriptions(None, None, 10).await.unwrap();
    assert_eq!(left.len(), 1);
    assert!(left[0].principal.ends_with("::bob"));
}

/// A post gate that masks `secret`, refuses `blocked`, and records the
/// surface and name it was asked about.
struct MaskingGate {
    manifest: mcpg_plugin_protocol::PluginManifest,
    seen: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::ToolGatePlugin for MaskingGate {
    fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
        &self.manifest
    }

    async fn evaluate_pre_dispatch(
        &self,
        _ctx: &mcpg_plugin_protocol::PluginContext,
        _arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> mcpg_plugin_protocol::GateDecision {
        mcpg_plugin_protocol::GateDecision::allow()
    }

    async fn evaluate_post_dispatch(
        &self,
        ctx: &mcpg_plugin_protocol::PluginContext,
        _arguments: &Value,
        result: &Value,
        _execution_duration_ms: u64,
        _config: &Value,
    ) -> mcpg_plugin_protocol::GateDecision {
        self.seen
            .lock()
            .unwrap()
            .push((ctx.surface.clone(), ctx.tool_name.clone()));
        if result["blocked"] == true {
            return mcpg_plugin_protocol::GateDecision::Deny {
                http_status: 403,
                code: -33000,
                message: "blocked".to_owned(),
                error_data: None,
            };
        }
        let mut masked = result.clone();
        if masked.get("secret").is_some() {
            masked["secret"] = json!("***");
        }
        mcpg_plugin_protocol::GateDecision::Allow {
            modified_arguments: None,
            modified_result: Some(masked),
            metadata: None,
        }
    }
}

#[tokio::test]
async fn post_gates_mask_or_refuse_each_payload_for_its_subscriber() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    subscribe(&h, json!({})).await;
    let stores = h.core.stores().unwrap();
    let id = h.receiver.envelopes("verification")[0]
        .header("x-mcp-subscription-id")
        .unwrap();
    let record = stores.subscriptions.get(&id).await.unwrap().unwrap();

    let empty = mcpg_plugin_host::PluginRegistry::new();
    let data = json!({ "secret": "s", "region": "eu" });
    assert_eq!(
        gate_payload(&empty, &record, &data).await,
        Some(data.clone())
    );

    let seen = Arc::default();
    let mut registry = mcpg_plugin_host::PluginRegistry::new();
    let mut manifest = mcpg_plugin_protocol::WatchStrategyPlugin::manifest(
        &*crate::runtime::events::test_support::ScriptedWatch::new("unused"),
    )
    .clone();
    manifest.id = "test.gate.masking".to_owned();
    manifest.plugin_class = mcpg_plugin_protocol::PluginClass::ToolGate;
    registry
        .register_tool_gate(
            Box::new(MaskingGate {
                manifest,
                seen: Arc::clone(&seen),
            }),
            mcpg_plugin_protocol::PluginTier::Native,
            json!({}),
        )
        .unwrap();
    assert_eq!(
        gate_payload(&registry, &record, &data).await,
        Some(json!({ "secret": "***", "region": "eu" }))
    );
    assert_eq!(
        gate_payload(&registry, &record, &json!({ "blocked": true })).await,
        None
    );
    assert_eq!(
        seen.lock().unwrap()[0],
        ("event".to_owned(), "event:orders.created".to_owned())
    );
}

#[test]
fn backoff_spreads_retries_over_the_window() {
    let window = 900_000;
    let waits: Vec<u64> = (1..=5).map(|n| backoff_ms(n, window)).collect();
    for (wait, base) in waits
        .iter()
        .zip([5_000u64, 30_000, 120_000, 300_000, 600_000])
    {
        assert!(
            (base..base + base / 10).contains(wait),
            "{wait} near {base}"
        );
    }
    assert!(
        backoff_ms(9, window) >= 600_000,
        "later retries keep the last step"
    );
}
