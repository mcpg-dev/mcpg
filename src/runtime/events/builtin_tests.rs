use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::protocol::v_2026_07_28::extensions::events::wire::SubscribeEventsParams;
use crate::runtime::events::test_support::{
    WebhookHarness, request_context, verified_identity, whsec,
};

const BUILTIN_TYPES: &str = r#"      - name: tasks.updated
        source: { builtin: mcp.task.updated }
      - name: approvals.requested
        source: { builtin: approval.requested }
      - name: approvals.resolved
        source: { builtin: approval.resolved }"#;

/// Subscribe `subject` to `name`; the subscription id.
async fn subscribe(h: &WebhookHarness, subject: &str, name: &str) -> String {
    let params = SubscribeEventsParams::from_value_redacted(json!({
        "name": name,
        "delivery": { "mode": "webhook", "url": h.receiver.url(&format!("/{subject}")), "secret": whsec(1) },
    }))
    .unwrap();
    h.core
        .subscribe_webhook(&request_context(verified_identity(subject)), params)
        .await
        .unwrap_or_else(|e| panic!("subscribe {subject} to {name}: {e:?}"))
        .id
}

/// The event bodies delivered to subscription `id`.
fn delivered_to(h: &WebhookHarness, id: &str) -> Vec<Value> {
    h.receiver
        .events()
        .into_iter()
        .filter(|r| r.header("x-mcp-subscription-id").as_deref() == Some(id))
        .map(|r| r.json())
        .collect()
}

/// Let the spawned emission land, then append and deliver it.
async fn settle(h: &WebhookHarness) {
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.core.drain_now().await;
    h.deliver().await;
}

#[tokio::test]
async fn a_task_status_change_reaches_only_the_principal_that_owns_the_task() {
    let h = WebhookHarness::start("", BUILTIN_TYPES).await;
    let alice = subscribe(&h, "alice", "tasks.updated").await;
    let bob = subscribe(&h, "bob", "tasks.updated").await;

    let runtime = h.state.runtime.load_full();
    let session = runtime.session_store().create_session(
        "2026-07-28",
        &crate::runtime::GatewayRuntime::modern_synthetic_init_params(),
    );
    let alice_key = verified_identity("alice")
        .synthetic_principal_key()
        .unwrap();
    runtime
        .session_store()
        .bind_session_owner(&session.session_id, Some(&alice_key));
    let task = runtime
        .task_store()
        .create_task(&session.session_id, json!(1), "slow.tool", None)
        .unwrap();
    settle(&h).await;

    let to_alice = delivered_to(&h, &alice);
    assert_eq!(to_alice.len(), 1, "{to_alice:?}");
    let body = &to_alice[0];
    assert_eq!(body["name"], "tasks.updated");
    assert_eq!(body["data"]["taskId"], task.task.task_id.as_str());
    assert_eq!(body["data"]["status"], "working");
    assert_eq!(body["data"]["toolName"], "slow.tool");
    assert!(
        delivered_to(&h, &bob).is_empty(),
        "another principal's task is not bob's to see"
    );
}

#[tokio::test]
async fn a_task_of_an_anonymous_session_raises_nothing() {
    let h = WebhookHarness::start("", BUILTIN_TYPES).await;
    let alice = subscribe(&h, "alice", "tasks.updated").await;
    let runtime = h.state.runtime.load_full();
    let session = runtime.session_store().create_session(
        "2026-07-28",
        &crate::runtime::GatewayRuntime::modern_synthetic_init_params(),
    );
    runtime
        .task_store()
        .create_task(&session.session_id, json!(1), "slow.tool", None)
        .unwrap();
    settle(&h).await;
    assert!(delivered_to(&h, &alice).is_empty());
}

#[tokio::test]
async fn approvals_raise_requested_and_resolved_events() {
    let h = WebhookHarness::start("", BUILTIN_TYPES).await;
    let requested = subscribe(&h, "alice", "approvals.requested").await;
    let resolved = subscribe(&h, "alice", "approvals.resolved").await;
    let observer = ApprovalEvents {
        core: Arc::downgrade(&h.core),
    };
    observer.requested(
        "ap-1",
        "payments.charge",
        "Charge 12 EUR",
        "2026-10-10T00:00:00Z",
    );
    observer.resolved("ap-1", "payments.charge", "approved");
    settle(&h).await;

    let asked = delivered_to(&h, &requested);
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["data"]["summary"], "Charge 12 EUR");
    assert_eq!(asked[0]["eventId"], "approval:ap-1:requested");
    let decided = delivered_to(&h, &resolved);
    assert_eq!(decided.len(), 1, "{decided:?}");
    assert_eq!(decided[0]["data"]["outcome"], "approved");
    assert_eq!(
        h.usage.ingested("approvals.requested") + h.usage.ingested("approvals.resolved"),
        0,
        "the gateway's own events count nothing against the ingest allowance"
    );
}

/// The gateway's own events are delivered but never billed: their
/// deliveries count nothing toward the delivery allowance or its overage,
/// while an operator-defined type's do.
#[tokio::test]
async fn builtin_deliveries_are_not_billed_and_operator_types_are() {
    let types = format!(
        "{BUILTIN_TYPES}\n{}",
        crate::runtime::events::test_support::ORDERS_TYPE
    );
    let h = WebhookHarness::start("", &types).await;
    let requested = subscribe(&h, "alice", "approvals.requested").await;
    let orders = subscribe(&h, "alice", "orders.created").await;
    let observer = ApprovalEvents {
        core: Arc::downgrade(&h.core),
    };
    observer.requested(
        "ap-3",
        "payments.charge",
        "Charge 7 EUR",
        "2026-10-10T00:00:00Z",
    );
    h.fire("o-1", "eu").await;
    settle(&h).await;
    assert_eq!(delivered_to(&h, &requested).len(), 1);
    assert_eq!(delivered_to(&h, &orders).len(), 1);

    let delivered = |name: &str| -> u64 {
        h.usage
            .event_usage()
            .iter()
            .filter(|call| call.event_name == name)
            .map(|call| call.delivered)
            .sum()
    };
    assert_eq!(
        delivered("approvals.requested"),
        0,
        "{:?}",
        h.usage.event_usage()
    );
    assert_eq!(
        delivered("orders.created"),
        1,
        "{:?}",
        h.usage.event_usage()
    );
    assert!(
        h.core
            .catalog()
            .get("approvals.requested")
            .unwrap()
            .is_builtin()
    );
    assert!(!h.core.catalog().get("orders.created").unwrap().is_builtin());
    assert_eq!(
        h.core
            .catalog()
            .get("approvals.requested")
            .unwrap()
            .billable_deliveries(5),
        0
    );
}

/// Poll and push on, beside webhook delivery.
const POLL_AND_PUSH: &str = "      poll: { enabled: true, next_poll_ms: 5000, min_next_poll_ms: 1 }
      push: { enabled: true, heartbeat_interval_ms: 1000 }";

/// A poll or a stream of the gateway's own events counts nothing toward the
/// delivery allowance either, while a poll of an operator-defined type does.
#[tokio::test]
async fn builtin_events_read_by_poll_or_stream_are_not_billed() {
    use crate::protocol::v_2026_07_28::extensions::events::wire::{
        PollEventsParams, StreamEventsParams,
    };
    use crate::runtime::events::test_support::{ORDERS_TYPE, eventually};
    let types = format!("{BUILTIN_TYPES}\n{ORDERS_TYPE}");
    let h = WebhookHarness::start(POLL_AND_PUSH, &types).await;
    let alice = request_context(verified_identity("alice"));
    let poll = |name: &str, cursor: Option<String>| PollEventsParams {
        name: name.to_owned(),
        arguments: serde_json::Map::new(),
        cursor,
        max_age_ms: None,
        max_events: None,
        meta: None,
    };
    let approvals = h
        .core
        .poll_events(&alice, poll("approvals.requested", None))
        .await
        .unwrap();
    let orders = h
        .core
        .poll_events(&alice, poll("orders.created", None))
        .await
        .unwrap();
    let mut frames = h
        .core
        .open_stream(
            &alice,
            StreamEventsParams {
                name: "approvals.requested".to_owned(),
                arguments: serde_json::Map::new(),
                cursor: None,
                max_age_ms: None,
                meta: None,
            },
            json!(1),
        )
        .await
        .unwrap();
    let next = async |frames: &mut tokio::sync::mpsc::Receiver<Value>| {
        tokio::time::timeout(Duration::from_secs(5), frames.recv())
            .await
            .expect("a frame within five seconds")
            .expect("the stream is open")
    };
    assert_eq!(
        next(&mut frames).await["method"],
        "notifications/events/active"
    );

    ApprovalEvents {
        core: Arc::downgrade(&h.core),
    }
    .requested(
        "ap-5",
        "payments.charge",
        "Charge 3 EUR",
        "2026-10-10T00:00:00Z",
    );
    h.fire("o-2", "eu").await;
    settle(&h).await;

    let read = h
        .core
        .poll_events(&alice, poll("approvals.requested", approvals.cursor))
        .await
        .unwrap();
    assert_eq!(read.events.len(), 1, "{:?}", read.events);
    let read = h
        .core
        .poll_events(&alice, poll("orders.created", orders.cursor))
        .await
        .unwrap();
    assert_eq!(read.events.len(), 1, "{:?}", read.events);
    let event = loop {
        let frame = next(&mut frames).await;
        if frame["method"] == "notifications/events/event" {
            break frame;
        }
    };
    assert_eq!(event["params"]["name"], "approvals.requested");

    let usage = |name: &str, mode: &str| -> (u64, u64) {
        h.usage
            .event_usage()
            .iter()
            .filter(|call| call.event_name == name && call.mode == mode)
            .fold((0, 0), |(d, b), call| (d + call.delivered, b + call.bytes))
    };
    assert!(
        eventually(|| usage("approvals.requested", "push").1 > 0).await,
        "{:?}",
        h.usage.event_usage()
    );
    assert_eq!(usage("approvals.requested", "push").0, 0);
    let (delivered, bytes) = usage("approvals.requested", "poll");
    assert_eq!(delivered, 0, "{:?}", h.usage.event_usage());
    assert!(bytes > 0, "the read is still reported");
    assert_eq!(usage("orders.created", "poll").0, 1);
}

/// The plan's ingest hold leaves the builtin types alone: an approver still
/// hears of an approval.
#[tokio::test]
async fn a_held_ingest_still_raises_builtin_events() {
    let h = WebhookHarness::start("", BUILTIN_TYPES).await;
    let requested = subscribe(&h, "alice", "approvals.requested").await;
    h.quota.set_events(crate::runtime::cp_quota::EventsPlan {
        ingest_held: true,
        held_until: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..Default::default()
    });
    let observer = ApprovalEvents {
        core: Arc::downgrade(&h.core),
    };
    observer.requested(
        "ap-2",
        "payments.charge",
        "Charge 5 EUR",
        "2026-10-10T00:00:00Z",
    );
    settle(&h).await;
    assert_eq!(delivered_to(&h, &requested).len(), 1);
}

#[tokio::test]
async fn the_list_change_reaches_modern_sessions_only() {
    let h = WebhookHarness::start("", BUILTIN_TYPES).await;
    let runtime = h.state.runtime.load_full();
    let sessions = runtime.session_store();
    let modern = sessions.create_session(
        "2026-07-28",
        &crate::runtime::GatewayRuntime::modern_synthetic_init_params(),
    );
    let legacy = sessions.create_session(
        "2025-11-25",
        &crate::runtime::GatewayRuntime::modern_synthetic_init_params(),
    );
    let bus = runtime.delivery_bus();
    let mut modern_rx = bus.subscribe(&modern.session_id).await;
    let mut legacy_rx = bus.subscribe(&legacy.session_id).await;
    announce_list_changed(sessions, bus);
    let message = tokio::time::timeout(Duration::from_secs(2), modern_rx.recv())
        .await
        .expect("the modern session hears it")
        .expect("a message");
    assert_eq!(
        message.jsonrpc_message["method"],
        crate::protocol::v_2026_07_28::extensions::events::wire::METHOD_NOTIFICATIONS_LIST_CHANGED
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), legacy_rx.recv())
            .await
            .is_err(),
        "the 2025-11-25 session hears nothing"
    );
}
