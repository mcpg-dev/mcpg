//! The plan's MCP Events limits, as an attached control plane sets them:
//! the reader cap, the per-gateway request ceiling, the monthly ingest
//! allowance, the type cap and the retry window.

use std::time::Duration;

use serde_json::{Map, Value, json};

use super::InboundReply;
use crate::protocol::v_2026_07_28::extensions::events::errors::{EventsError, EventsErrorData};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    PollEventsParams, StreamEventsParams,
};
use crate::runtime::RequestContext;
use crate::runtime::cp_quota::{EventsPlan, QuotaStatusInfo};
use crate::runtime::events::test_support::{
    ORDERS_TYPE, WebhookHarness, request_context, verified_identity,
};

/// Poll and push on, beside webhook delivery.
const EVERY_MODE: &str = "      poll: { enabled: true, next_poll_ms: 5000, min_next_poll_ms: 1 }
      push: { enabled: true, heartbeat_interval_ms: 1000 }";

fn alice() -> RequestContext {
    request_context(verified_identity("alice"))
}

fn region(region: &str) -> Map<String, Value> {
    let mut arguments = Map::new();
    arguments.insert("region".to_owned(), json!(region));
    arguments
}

fn poll(region_name: &str) -> PollEventsParams {
    PollEventsParams {
        name: "orders.created".to_owned(),
        arguments: region(region_name),
        cursor: None,
        max_age_ms: None,
        max_events: None,
        meta: None,
    }
}

fn stream(region_name: &str) -> StreamEventsParams {
    StreamEventsParams {
        name: "orders.created".to_owned(),
        arguments: region(region_name),
        cursor: None,
        max_age_ms: None,
        meta: None,
    }
}

fn readers_cap(error: &EventsError) -> Option<u64> {
    match EventsErrorData::parse(error.code(), error.data()) {
        Some(EventsErrorData::ResourceExhausted(data))
            if data.limit == "plan.event_subscriptions" =>
        {
            data.max
        }
        _ => None,
    }
}

#[tokio::test]
async fn the_reader_cap_counts_webhook_subscriptions_poll_leases_and_streams_together() {
    let h = WebhookHarness::start(EVERY_MODE, ORDERS_TYPE).await;
    h.quota.set_events(EventsPlan {
        readers_limit: Some(3),
        ..EventsPlan::default()
    });
    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .expect("a webhook subscription is the first reader");
    h.core
        .poll_events(&alice(), poll("eu"))
        .await
        .expect("a poll lease is the second");
    h.core
        .poll_events(&alice(), poll("eu"))
        .await
        .expect("the same lease again is no new reader");
    let _stream = h
        .core
        .open_stream(&alice(), stream("us"), json!(1))
        .await
        .expect("a stream is the third");

    let refused = h.core.poll_events(&alice(), poll("us")).await.unwrap_err();
    assert_eq!(readers_cap(&refused), Some(3), "{refused}");
    let refused = h
        .core
        .open_stream(&alice(), stream("eu"), json!(2))
        .await
        .unwrap_err();
    assert_eq!(readers_cap(&refused), Some(3), "{refused}");
    let refused = h
        .core
        .subscribe_webhook(&alice(), h.params("/other", json!({}), 2))
        .await
        .unwrap_err();
    assert_eq!(readers_cap(&refused), Some(3), "{refused}");

    h.core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .expect("a refresh of a live subscription is no new reader");

    h.quota.set_events(EventsPlan::default());
    h.core
        .poll_events(&alice(), poll("us"))
        .await
        .expect("no cap, no count");
}

#[tokio::test]
async fn a_verified_inbound_webhook_counts_against_the_request_ceiling() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    h.quota.set(QuotaStatusInfo {
        exhausted: false,
        until: None,
        remaining: None,
        limit: None,
        rps_limit: Some(1),
        events: EventsPlan::default(),
    });
    let mut replies = Vec::new();
    for n in 0..3 {
        let body = json!({ "id": format!("o-{n}"), "region": "eu" });
        replies.push(
            h.core
                .receive_inbound(
                    "orders",
                    &axum::http::HeaderMap::new(),
                    &serde_json::to_vec(&body).unwrap(),
                )
                .await,
        );
    }
    assert!(
        replies.contains(&InboundReply::RateLimited(Duration::from_secs(1))),
        "three requests in under three seconds pass a ceiling of one a second: {replies:?}"
    );
}

#[tokio::test]
async fn a_stream_open_counts_against_the_request_ceiling() {
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt as _;
    let h = WebhookHarness::start(EVERY_MODE, ORDERS_TYPE).await;
    h.quota.set(QuotaStatusInfo {
        exhausted: false,
        until: None,
        remaining: None,
        limit: None,
        rps_limit: Some(1),
        events: EventsPlan::default(),
    });
    let app = crate::transports::http::router(h.state.clone(), "/health", "/mcp");
    let open = |id: u64| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "events/stream")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "events/stream",
                    "params": {
                        "name": "orders.created",
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    },
                })
                .to_string(),
            ))
            .unwrap()
    };
    let mut refused = None;
    for id in 1..=3 {
        let response = app.clone().oneshot(open(id)).await.unwrap();
        if response.status() == axum::http::StatusCode::TOO_MANY_REQUESTS {
            refused = Some(response);
            break;
        }
    }
    let response =
        refused.expect("three opens in under three seconds pass a ceiling of one a second");
    assert_eq!(response.headers()["retry-after"], "1");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        body["error"]["data"]["limit"], "plan.rps_per_gateway",
        "{body}"
    );
}

#[tokio::test]
async fn an_unverified_webhook_does_not_use_up_the_request_ceiling() {
    const WHSEC: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    let signed = format!(
        r#"      - name: orders.created
        source: {{ inbound: {{ source_id: orders, verify: {{ profile: standard_webhooks, secrets: ['{WHSEC}'] }} }} }}"#
    );
    let h = WebhookHarness::start("", &signed).await;
    h.quota.set(QuotaStatusInfo {
        exhausted: false,
        until: None,
        remaining: None,
        limit: None,
        rps_limit: Some(1),
        events: EventsPlan::default(),
    });
    let body = br#"{"id":"o-1"}"#;
    for _ in 0..5 {
        let reply = h
            .core
            .receive_inbound("orders", &axum::http::HeaderMap::new(), body)
            .await;
        assert_eq!(reply, InboundReply::Unauthorized);
    }
    let secret = mcpg_standard_webhooks::WhsecSecret::parse(WHSEC).unwrap();
    let mut headers = axum::http::HeaderMap::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    mcpg_standard_webhooks::sign_message(&[&secret], "msg_1", now, body)
        .unwrap()
        .insert_into(&mut headers)
        .unwrap();
    let reply = h.core.receive_inbound("orders", &headers, body).await;
    assert_eq!(
        reply,
        InboundReply::Accepted,
        "refused senders left the second's request for the signed one"
    );
}

#[tokio::test]
async fn a_used_ingest_allowance_answers_inbound_webhooks_429_until_the_period_ends() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    h.quota.set_events(EventsPlan {
        ingest_held: true,
        held_until: Some(chrono::Utc::now() + chrono::Duration::seconds(3_600)),
        ..EventsPlan::default()
    });
    let body = serde_json::to_vec(&json!({ "id": "o-1", "region": "eu" })).unwrap();
    let reply = h
        .core
        .receive_inbound("orders", &axum::http::HeaderMap::new(), &body)
        .await;
    let InboundReply::RateLimited(wait) = reply else {
        panic!("held: {reply:?}");
    };
    assert!(
        (3_590..=3_600).contains(&wait.as_secs()),
        "the sender comes back when the period ends: {wait:?}"
    );

    h.quota.set_events(EventsPlan::default());
    let reply = h
        .core
        .receive_inbound("orders", &axum::http::HeaderMap::new(), &body)
        .await;
    assert_eq!(reply, InboundReply::Accepted);
}

#[tokio::test]
async fn each_appended_occurrence_is_metered_once_as_ingested() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    h.fire("o-1", "eu").await;
    h.fire("o-1", "eu").await;
    h.fire("o-2", "us").await;
    assert_eq!(
        h.usage.ingested("orders.created"),
        2,
        "a repeated event id is one occurrence"
    );
    let calls = h.usage.event_usage();
    assert!(
        calls
            .iter()
            .filter(|call| call.ingested > 0)
            .all(|call| call.mode == "inbound" && call.bytes > 0 && call.delivered == 0),
        "{calls:?}"
    );
}

#[tokio::test]
async fn the_type_cap_serves_the_first_types_and_announces_the_change() {
    let extra = r#"
      - name: zz.extra
        source: { inbound: { source_id: extra, allow_unsigned: true } }"#;
    let h = WebhookHarness::start("", &format!("{ORDERS_TYPE}{extra}")).await;
    assert!(h.core.catalog().get("zz.extra").is_some());
    let version = h.core.catalog_version();

    h.quota.set_events(EventsPlan {
        types_limit: Some(1),
        ..EventsPlan::default()
    });
    h.core.owner_tick().await;
    assert!(h.core.catalog().get("orders.created").is_some());
    assert!(
        h.core.catalog().get("zz.extra").is_none(),
        "past the cap, in name order"
    );
    assert!(h.core.catalog_version() > version);
    assert_eq!(h.core.types_not_served(), 1);
    let status = h.core.admin_status().await;
    assert_eq!(status.plan.types_limit, Some(1));
    assert_eq!(status.plan.types_not_served, 1);
    let reply = h
        .core
        .receive_inbound("extra", &axum::http::HeaderMap::new(), b"{}")
        .await;
    assert_eq!(
        reply,
        InboundReply::NotFound,
        "a type not served takes nothing"
    );

    h.quota.set_events(EventsPlan::default());
    h.core.owner_tick().await;
    assert!(h.core.catalog().get("zz.extra").is_some(), "served again");
}

#[tokio::test]
async fn the_plan_retry_window_cuts_retries_short() {
    let h = WebhookHarness::start(
        "      webhook: { retry: { window_ms: 60000, max_attempts: 5 } }",
        ORDERS_TYPE,
    )
    .await;
    let subscription = h
        .core
        .subscribe_webhook(&alice(), h.params("/hook", json!({}), 1))
        .await
        .unwrap();
    h.quota.set_events(EventsPlan {
        retry_window_ms_limit: Some(1),
        ..EventsPlan::default()
    });
    assert_eq!(
        h.core.plan().retry_window_ms(60_000),
        1,
        "the plan's window is in force before the first attempt"
    );
    let echo = crate::runtime::events::test_support::echo_reply();
    h.receiver.set_reply(std::sync::Arc::new(
        move |request: &crate::runtime::events::test_support::Received| {
            if request.json().get("type").is_some() {
                return echo(request);
            }
            (500, Vec::new())
        },
    ));
    h.fire("o-1", "eu").await;
    h.deliver().await;
    let state = h
        .core
        .stores()
        .unwrap()
        .subscriptions
        .delivery(&subscription.id)
        .await
        .unwrap()
        .unwrap();
    let attempts: Vec<_> = h
        .receiver
        .events()
        .iter()
        .map(|r| (r.header("webhook-id"), r.header("webhook-timestamp")))
        .collect();
    assert_eq!(
        attempts.len(),
        1,
        "one attempt, no retry: {attempts:?}, {state:?}"
    );
    assert_eq!(state.ack_seq, 1, "given up within the plan's window");
    assert!(state.in_flight.is_empty());
}

#[tokio::test]
async fn the_plan_holds_and_counts_what_the_admin_status_shows() {
    let h = WebhookHarness::start("", ORDERS_TYPE).await;
    let status = h.core.admin_status().await;
    assert!(!status.plan.ingest_held && !status.plan.deliveries_held);
    assert_eq!(status.plan.readers_limit, None);
    h.quota.set_events(EventsPlan {
        deliveries_held: true,
        ingest_held: true,
        held_until: Some(chrono::Utc::now()),
        readers_limit: Some(10),
        retention_bytes_limit: Some(1 << 20),
        ..EventsPlan::default()
    });
    let status = h.core.admin_status().await;
    assert!(status.plan.ingest_held && status.plan.deliveries_held);
    assert!(status.plan.held_until.is_some());
    assert_eq!(status.plan.readers_limit, Some(10));
    assert_eq!(status.plan.retention_bytes_limit, Some(1 << 20));
}
