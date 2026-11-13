//! The realtime admission over the events engine: a stream, a poll lease
//! and a webhook subscription each ask the admission tool.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::protocol::v_2026_07_28::extensions::events::wire::{
    PollEventsParams, StreamEventsParams,
};
use crate::runtime::RequestContext;
use crate::runtime::events::test_support::{
    ORDERS_TYPE, WebhookHarness, request_context, verified_identity,
};

const MODES: &str = "      push: { enabled: true, heartbeat_interval_ms: 1000 }\n      poll: { enabled: true, next_poll_ms: 5000, min_next_poll_ms: 1 }";

const ALLOW: &str = "{ allow: true }";
const DENY: &str = "{ allow: false, error: { code: realtime_limit, message: one realtime consumer on this plan, details: { limit: 1 } } }";

fn alice() -> RequestContext {
    request_context(verified_identity("alice"))
}

/// Reload `h` with an admission whose tool answers `decision`.
async fn admit_with(h: &WebhookHarness, decision: &str) {
    let tools = format!(
        r#"  realtime:
    admission: {{ tool: realtime.admit, renew_interval_ms: 1000 }}
  capabilities:
    tools:
      - name: realtime.admit
        description: Decides who gets realtime delivery.
        backend: {{ kind: mock, response: {decision} }}
"#
    );
    let yaml = h.yaml.replacen("  capabilities:\n", &tools, 1);
    assert_ne!(yaml, h.yaml, "the config has a capabilities block");
    crate::app::reload_config_from_yaml(&h.state, &yaml)
        .await
        .expect("reload with the admission");
}

fn stream_params() -> StreamEventsParams {
    StreamEventsParams {
        name: "orders.created".to_owned(),
        arguments: Map::new(),
        cursor: None,
        max_age_ms: None,
        meta: None,
    }
}

fn poll_params() -> PollEventsParams {
    PollEventsParams {
        name: "orders.created".to_owned(),
        arguments: Map::new(),
        cursor: None,
        max_age_ms: None,
        max_events: None,
        meta: None,
    }
}

async fn next(frames: &mut tokio::sync::mpsc::Receiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(10), frames.recv())
        .await
        .expect("a frame within ten seconds")
        .expect("the stream is open")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_is_admitted_then_ends_when_a_renewal_is_refused() {
    let h = WebhookHarness::start(MODES, ORDERS_TYPE).await;
    admit_with(&h, ALLOW).await;
    let mut frames = h
        .core
        .open_stream(&alice(), stream_params(), json!(7))
        .await
        .expect("admitted");
    assert_eq!(
        next(&mut frames).await["method"],
        "notifications/events/active"
    );

    admit_with(&h, DENY).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let terminated = loop {
        let frame = next(&mut frames).await;
        if frame["method"] != "notifications/events/heartbeat" {
            break frame;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refused renewal ends the stream"
        );
    };
    assert_eq!(
        terminated["method"], "notifications/events/terminated",
        "{terminated}"
    );
    let error = &terminated["params"]["error"];
    assert_eq!(error["code"], -32013, "{terminated}");
    assert_eq!(error["message"], "one realtime consumer on this plan");
    assert_eq!(error["data"]["code"], "realtime_limit");
    assert_eq!(error["data"]["details"]["limit"], 1);

    let refused = h
        .core
        .open_stream(&alice(), stream_params(), json!(8))
        .await
        .expect_err("refused at the open");
    assert_eq!(refused.code(), -32013);
    assert_eq!(refused.message(), "one realtime consumer on this plan");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_poll_lease_is_admitted_on_its_first_poll_and_renewed_on_later_ones() {
    let h = WebhookHarness::start(MODES, ORDERS_TYPE).await;
    admit_with(&h, DENY).await;
    let refused = h
        .core
        .poll_events(&alice(), poll_params())
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), -32013);
    assert_eq!(refused.data().unwrap()["details"]["limit"], 1);

    admit_with(&h, ALLOW).await;
    h.core
        .poll_events(&alice(), poll_params())
        .await
        .expect("admitted");
    // Inside the grant's interval a poll asks nothing.
    h.core
        .poll_events(&alice(), poll_params())
        .await
        .expect("still admitted");

    admit_with(&h, DENY).await;
    let refused = h
        .core
        .poll_events(&alice(), poll_params())
        .await
        .expect_err("the renewal is refused");
    assert_eq!(refused.code(), -32013);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_webhook_subscription_asks_the_admission_before_the_callback() {
    let h = WebhookHarness::start(MODES, ORDERS_TYPE).await;
    admit_with(&h, DENY).await;
    let refused = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), -32013);
    assert_eq!(refused.message(), "one realtime consumer on this plan");
    assert!(
        h.receiver.requests().is_empty(),
        "a refused caller's callback gets no challenge"
    );

    admit_with(&h, ALLOW).await;
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .expect("admitted");
    assert_eq!(h.receiver.envelopes("verification").len(), 1);
}
