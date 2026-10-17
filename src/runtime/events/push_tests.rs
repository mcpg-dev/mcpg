use super::*;
use crate::config::AppConfig;
use crate::runtime::events::test_support::SESSION_KEY;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt as _;

/// Boots in one test process race to install the global log subscriber, so
/// these gateways log nowhere.
const QUIET: &str = "observability: { logs: { enabled: false } }";

const ORDERS: &str = r#"      - name: orders.created
        source: { inbound: { source_id: orders, allow_unsigned: true } }"#;
const HOOKS_ONLY: &str = r#"      - name: hooks.only
        delivery: [webhook]
        source: { inbound: { source_id: hooks, allow_unsigned: true } }"#;

fn yaml(store_dir: &std::path::Path, push: &str, types: &str) -> String {
    format!(
        r#"
{QUIET}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{dir}/subscriptions" }}
      log_store: {{ kind: file, dir: "{dir}/log" }}
      push: {push}
  capabilities:
    events:
{types}
"#,
        dir = store_dir.display()
    )
}

const PUSH: &str = "{ enabled: true, heartbeat_interval_ms: 1000 }";

async fn boot(yaml: &str) -> crate::app::AppState {
    let config = AppConfig::load_from_yaml_str(yaml).unwrap();
    crate::app::build_from_config(config, Vec::new())
        .await
        .unwrap_or_else(|e| panic!("boots: {e:#}"))
}

fn core_of(state: &crate::app::AppState) -> Arc<EventsCore> {
    state
        .runtime
        .load()
        .shared_services
        .load_full()
        .and_then(|s| s.events_core.get().cloned())
        .expect("an events core is installed at boot")
}

fn verified(subject: &str) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: subject.to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: "test".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: Default::default(),
    }
}

fn ctx(identity: RequestIdentity) -> RequestContext {
    RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        identity,
        TransportKind::Http,
    )
}

fn params(name: &str, cursor: Option<String>) -> StreamEventsParams {
    StreamEventsParams {
        name: name.to_owned(),
        arguments: Map::new(),
        cursor,
        max_age_ms: None,
        meta: None,
    }
}

async fn open(
    core: &Arc<EventsCore>,
    name: &str,
    cursor: Option<String>,
) -> Result<mpsc::Receiver<Value>, EventsError> {
    core.open_stream(&ctx(verified("alice")), params(name, cursor), json!(7))
        .await
}

/// Post `ns` to the inbound route of `source_id` and let the owner write
/// them to the log.
async fn logged(state: &crate::app::AppState, core: &Arc<EventsCore>, source_id: &str, ns: &[u32]) {
    for n in ns {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/webhooks/events/{source_id}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"n":{n}}}"#)))
            .unwrap();
        let response = crate::transports::http::router(state.clone(), "/health", "/mcp")
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    core.owner_tick().await;
    core.drain_now().await;
}

async fn next(frames: &mut mpsc::Receiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(5), frames.recv())
        .await
        .expect("a frame within five seconds")
        .expect("the stream is open")
}

/// The next frame that is not a heartbeat.
async fn next_non_heartbeat(frames: &mut mpsc::Receiver<Value>) -> Value {
    loop {
        let frame = next(frames).await;
        if frame["method"] != "notifications/events/heartbeat" {
            return frame;
        }
    }
}

#[tokio::test]
async fn a_stream_opens_active_then_carries_each_event_and_heartbeats() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), PUSH, ORDERS)).await;
    let core = core_of(&state);
    let mut frames = open(&core, "orders.created", None).await.unwrap();

    let active = next(&mut frames).await;
    assert_eq!(active["method"], "notifications/events/active");
    assert_eq!(active["params"]["truncated"], false);
    assert!(active["params"]["cursor"].is_string());
    assert_eq!(
        active["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        7
    );

    logged(&state, &core, "orders", &[1, 2]).await;
    for n in [1, 2] {
        let event = next_non_heartbeat(&mut frames).await;
        assert_eq!(event["method"], "notifications/events/event");
        assert_eq!(event["params"]["data"]["n"], n);
        assert_eq!(event["params"]["name"], "orders.created");
        assert!(event["params"]["cursor"].is_string());
    }

    let heartbeat = next(&mut frames).await;
    assert_eq!(heartbeat["method"], "notifications/events/heartbeat");
    assert!(heartbeat["params"]["cursor"].is_string());
    assert!(
        core.subscription_index()
            .has_demand("orders.created", now_ms()),
        "an open stream is demand for its source"
    );
    let status = core.admin_status().await;
    assert!(status.push_enabled);
    assert_eq!(status.open_streams, 1);
    drop(frames);
    for _ in 0..50 {
        if core.open_streams() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(core.open_streams(), 0, "a dropped stream ends");
}

#[tokio::test]
async fn a_reconnect_with_the_last_cursor_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), PUSH, ORDERS)).await;
    let core = core_of(&state);
    let mut frames = open(&core, "orders.created", None).await.unwrap();
    next(&mut frames).await;
    logged(&state, &core, "orders", &[1]).await;
    let first = next_non_heartbeat(&mut frames).await;
    let cursor = first["params"]["cursor"].as_str().unwrap().to_owned();
    drop(frames);

    logged(&state, &core, "orders", &[2, 3]).await;
    let mut again = open(&core, "orders.created", Some(cursor)).await.unwrap();
    let active = next(&mut again).await;
    assert_eq!(active["params"]["truncated"], false);
    for n in [2, 3] {
        assert_eq!(
            next_non_heartbeat(&mut again).await["params"]["data"]["n"],
            n
        );
    }

    // A cursor the log cannot resume starts at now and says so.
    let mut fresh = open(&core, "orders.created", Some("not-a-cursor".to_owned()))
        .await
        .unwrap();
    assert_eq!(next(&mut fresh).await["params"]["truncated"], true);
}

#[tokio::test]
async fn the_cap_refuses_one_stream_too_many_and_a_closed_stream_frees_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(
        dir.path(),
        "{ enabled: true, heartbeat_interval_ms: 1000, max_streams_per_principal: 2 }",
        ORDERS,
    ))
    .await;
    let core = core_of(&state);
    let first = open(&core, "orders.created", None).await.unwrap();
    let _second = open(&core, "orders.created", None).await.unwrap();
    let error = open(&core, "orders.created", None).await.unwrap_err();
    assert_eq!(error.code(), -32013);
    assert_eq!(error.data().unwrap()["limit"], "streams");

    drop(first);
    let mut reopened = None;
    for _ in 0..50 {
        if let Ok(frames) = open(&core, "orders.created", None).await {
            reopened = Some(frames);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(reopened.is_some(), "the closed stream released its slot");
}

#[tokio::test]
async fn an_end_in_the_log_terminates_the_stream_after_the_events_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), PUSH, ORDERS)).await;
    let core = core_of(&state);
    let mut frames = open(&core, "orders.created", None).await.unwrap();
    next(&mut frames).await;
    logged(&state, &core, "orders", &[1]).await;
    let stores = core.stores().unwrap();
    let ty = core.catalog().get("orders.created").cloned().unwrap();
    let lease = (*core.owner_lease().borrow()).expect("the owner");
    stores
        .log
        .append_end(
            &ty.source_key,
            super::super::log::EndReason::NotFound,
            super::super::log::RowScope::of(None, stores.keys.arguments_hash(&Map::new())),
            &ty.retention,
            lease,
        )
        .await
        .unwrap();
    logged(&state, &core, "orders", &[2]).await;

    let event = next_non_heartbeat(&mut frames).await;
    assert_eq!(event["params"]["data"]["n"], 1);
    let terminated = next_non_heartbeat(&mut frames).await;
    assert_eq!(terminated["method"], "notifications/events/terminated");
    assert_eq!(terminated["params"]["error"]["code"], -32011);
    let result = next(&mut frames).await;
    assert_eq!(result["id"], 7, "nothing past the end: {result}");
}

#[tokio::test]
async fn a_removed_type_terminates_the_stream_with_a_final_result() {
    let dir = tempfile::tempdir().unwrap();
    let both = format!("{ORDERS}\n{HOOKS_ONLY}");
    let state = boot(&yaml(dir.path(), PUSH, &both)).await;
    let core = core_of(&state);
    let mut frames = open(&core, "orders.created", None).await.unwrap();
    next(&mut frames).await;

    crate::app::reload_config_from_yaml(&state, &yaml(dir.path(), PUSH, HOOKS_ONLY))
        .await
        .unwrap();
    let terminated = next_non_heartbeat(&mut frames).await;
    assert_eq!(terminated["method"], "notifications/events/terminated");
    assert_eq!(terminated["params"]["error"]["code"], -32011);
    assert_eq!(terminated["params"]["error"]["data"]["kind"], "event");
    let result = next(&mut frames).await;
    assert_eq!(result["id"], 7);
    assert_eq!(
        result["result"]["_meta"],
        json!({ "io.modelcontextprotocol/subscriptionId": 7 })
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), frames.recv())
            .await
            .unwrap()
            .is_none(),
        "the stream ends after its result"
    );
}

#[tokio::test]
async fn a_stream_is_refused_off_its_mode_or_trust() {
    let dir = tempfile::tempdir().unwrap();
    let off = boot(&yaml(dir.path(), "{ enabled: false }", ORDERS)).await;
    let error = open(&core_of(&off), "orders.created", None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32014);

    let dir = tempfile::tempdir().unwrap();
    let both = format!("{ORDERS}\n{HOOKS_ONLY}");
    let state = boot(&yaml(dir.path(), PUSH, &both)).await;
    let core = core_of(&state);
    let header = RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "test".to_owned(),
    };
    let error = core
        .open_stream(&ctx(header), params("orders.created", None), json!(1))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32012);
    let error = open(&core, "hooks.only", None).await.unwrap_err();
    assert_eq!(error.code(), -32014);
    let error = open(&core, "nope", None).await.unwrap_err();
    assert_eq!(error.code(), -32011);
}
