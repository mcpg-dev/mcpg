use super::*;
use crate::config::AppConfig;
use crate::runtime::events::test_support::SESSION_KEY;
use crate::runtime::{GatewayRequestId, RequestIdentity, TransportKind};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

/// Boots in one test process race to install the global log subscriber, so
/// these gateways log nowhere.
const QUIET: &str = "observability: { logs: { enabled: false } }";

const TYPES: &str = r#"      - name: orders.created
        source: { inbound: { source_id: orders, allow_unsigned: true } }
      - name: orders.shipped
        source: { inbound: { source_id: shipped, allow_unsigned: true } }
      - name: pings
        replay: none
        source: { inbound: { source_id: pings, allow_unsigned: true } }
      - name: hooks.only
        delivery: [webhook]
        source: { inbound: { source_id: hooks, allow_unsigned: true } }"#;

fn yaml(store_dir: &std::path::Path, poll: &str) -> String {
    format!(
        r#"
{QUIET}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{}/subscriptions" }}
      log_store: {{ kind: file, dir: "{}/log" }}
      poll: {poll}
  capabilities:
    events:
{TYPES}
"#,
        store_dir.display(),
        store_dir.display()
    )
}

const POLL: &str = "{ enabled: true, next_poll_ms: 5000, min_next_poll_ms: 1 }";

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

fn params(name: &str, cursor: Option<String>) -> PollEventsParams {
    PollEventsParams {
        name: name.to_owned(),
        arguments: Map::new(),
        cursor,
        max_age_ms: None,
        max_events: None,
        meta: None,
    }
}

async fn send(state: &crate::app::AppState, source_id: &str, n: u32) {
    let body = format!(r#"{{"n":{n}}}"#);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/webhooks/events/{source_id}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = crate::transports::http::router(state.clone(), "/health", "/mcp")
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// Post `ns` to `source_id` and let the owner write them to the log.
async fn logged(state: &crate::app::AppState, core: &Arc<EventsCore>, source_id: &str, ns: &[u32]) {
    for n in ns {
        send(state, source_id, *n).await;
    }
    core.owner_tick().await;
    core.drain_now().await;
}

fn numbers(result: &PollEventsResult) -> Vec<u64> {
    result
        .events
        .iter()
        .map(|e| e.data["n"].as_u64().unwrap())
        .collect()
}

#[tokio::test]
async fn a_poll_from_now_reads_what_comes_after_it_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    logged(&state, &core, "orders", &[0]).await;

    let first = core
        .poll_events(&caller, params("orders.created", None))
        .await
        .unwrap();
    assert!(first.events.is_empty(), "a null cursor starts at now");
    assert!(!first.truncated && !first.has_more);
    assert_eq!(first.next_poll_ms, 5_000);
    let cursor = first
        .cursor
        .clone()
        .expect("a type with replay has a cursor");

    logged(&state, &core, "orders", &[1, 2, 3]).await;
    let second = core
        .poll_events(&caller, params("orders.created", Some(cursor)))
        .await
        .unwrap();
    assert_eq!(numbers(&second), vec![1, 2, 3]);
    assert!(!second.truncated && !second.has_more);
    assert!(second.events.iter().all(|e| e.name == "orders.created"));

    let third = core
        .poll_events(&caller, params("orders.created", second.cursor.clone()))
        .await
        .unwrap();
    assert!(third.events.is_empty());
    let after_last = core
        .poll_events(
            &caller,
            params("orders.created", second.events[2].cursor.clone()),
        )
        .await
        .unwrap();
    assert!(
        after_last.events.is_empty(),
        "the last event's cursor is the poll's"
    );

    // An earlier cursor reads the same events again.
    let replay = core
        .poll_events(
            &caller,
            params("orders.created", second.events[0].cursor.clone()),
        )
        .await
        .unwrap();
    assert_eq!(numbers(&replay), vec![2, 3]);
}

/// An operator's pause holds polls as it holds webhook deliveries: no
/// events and the same cursor while it lasts, everything after it.
#[tokio::test]
async fn a_paused_gateway_holds_polls_until_it_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    let start = core
        .poll_events(&caller, params("orders.created", None))
        .await
        .unwrap()
        .cursor;
    logged(&state, &core, "orders", &[1, 2]).await;

    core.admin_set_paused(true).await.unwrap();
    let held = core
        .poll_events(&caller, params("orders.created", start.clone()))
        .await
        .unwrap();
    assert!(held.events.is_empty(), "a held poll answers no events");
    assert_eq!(held.cursor, start, "and the cursor it was given");

    core.admin_set_paused(false).await.unwrap();
    let resumed = core
        .poll_events(&caller, params("orders.created", start))
        .await
        .unwrap();
    assert_eq!(numbers(&resumed), vec![1, 2]);
}

#[tokio::test]
async fn max_events_pages_with_has_more_and_an_immediate_poll_reads_on() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(
        dir.path(),
        "{ enabled: true, next_poll_ms: 60000, min_next_poll_ms: 60000 }",
    ))
    .await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    let start = core
        .poll_events(&caller, params("orders.created", None))
        .await
        .unwrap();
    logged(&state, &core, "orders", &[1, 2, 3]).await;

    // The floor holds a poll that comes too soon: nothing read, the same
    // cursor, the time left.
    let early = core
        .poll_events(&caller, params("orders.created", start.cursor.clone()))
        .await
        .unwrap();
    assert!(early.events.is_empty());
    assert_eq!(early.cursor, start.cursor);
    assert!(early.next_poll_ms > 0 && early.next_poll_ms <= 60_000);

    // Past the floor (the lease forgets its last read), a page of two.
    let stores = core.stores().unwrap();
    let ty = Arc::clone(core.catalog().get("orders.created").unwrap());
    let principal = verified("alice").synthetic_principal_key().unwrap();
    let id = stores.leases.lease_id(&principal, &ty.name, &Map::new());
    let mut lease = stores.leases.get(&id).await.unwrap().unwrap();
    lease.last_read_ms = 0;
    stores
        .leases
        .put(&id, &principal, &lease, Duration::from_secs(60))
        .await
        .unwrap();
    let mut page = params("orders.created", start.cursor.clone());
    page.max_events = Some(2);
    let first = core.poll_events(&caller, page).await.unwrap();
    assert_eq!(numbers(&first), vec![1, 2]);
    assert!(first.has_more);
    assert_eq!(first.next_poll_ms, 60_000);

    // `hasMore` asks for an immediate poll, which the floor lets through.
    let rest = core
        .poll_events(&caller, params("orders.created", first.cursor.clone()))
        .await
        .unwrap();
    assert_eq!(numbers(&rest), vec![3]);
    assert!(!rest.has_more);
}

#[tokio::test]
async fn a_cursor_the_log_cannot_resume_is_truncated_with_a_fresh_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    logged(&state, &core, "orders", &[1]).await;

    let result = core
        .poll_events(
            &caller,
            params("orders.created", Some("not-a-cursor".to_owned())),
        )
        .await
        .unwrap();
    assert!(result.truncated);
    assert!(result.events.is_empty());
    let fresh = result.cursor.expect("a fresh cursor");
    logged(&state, &core, "orders", &[2]).await;
    let next = core
        .poll_events(&caller, params("orders.created", Some(fresh)))
        .await
        .unwrap();
    assert_eq!(numbers(&next), vec![2]);
    assert!(!next.truncated);
}

#[tokio::test]
async fn a_type_without_replay_continues_where_the_lease_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    let first = core
        .poll_events(&caller, params("pings", None))
        .await
        .unwrap();
    assert_eq!(first.cursor, None);
    logged(&state, &core, "pings", &[1, 2]).await;
    let second = core
        .poll_events(&caller, params("pings", None))
        .await
        .unwrap();
    assert_eq!(numbers(&second), vec![1, 2]);
    assert!(second.events.iter().all(|e| e.cursor.is_none()));
    assert_eq!(second.cursor, None);
    let third = core
        .poll_events(&caller, params("pings", None))
        .await
        .unwrap();
    assert!(third.events.is_empty());

    // Another principal has a lease of its own, from now.
    let bob = core
        .poll_events(&ctx(verified("bob")), params("pings", None))
        .await
        .unwrap();
    assert!(bob.events.is_empty());
}

#[tokio::test]
async fn poll_is_refused_off_its_mode_trust_or_lease_cap() {
    let dir = tempfile::tempdir().unwrap();
    let off = boot(&yaml(dir.path(), "{ enabled: false }")).await;
    let error = core_of(&off)
        .poll_events(&ctx(verified("alice")), params("orders.created", None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32014, "poll off is an unsupported mode");

    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(
        dir.path(),
        "{ enabled: true, min_next_poll_ms: 1, max_leases_per_principal: 1 }",
    ))
    .await;
    let core = core_of(&state);
    let header = RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "test".to_owned(),
    };
    let error = core
        .poll_events(&ctx(header), params("orders.created", None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32012);

    let error = core
        .poll_events(&ctx(verified("alice")), params("hooks.only", None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32014, "a type that does not offer poll");

    let error = core
        .poll_events(&ctx(verified("alice")), params("nope", None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32011);

    core.poll_events(&ctx(verified("alice")), params("orders.created", None))
        .await
        .unwrap();
    // The same lease again is no new lease.
    core.poll_events(&ctx(verified("alice")), params("orders.created", None))
        .await
        .unwrap();
    let error = core
        .poll_events(&ctx(verified("alice")), params("orders.shipped", None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), -32013);
    assert_eq!(error.data().unwrap()["limit"], "poll_leases");
}

#[tokio::test]
async fn a_poll_lease_is_demand_for_its_type_on_every_replica() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let now = now_ms();
    assert!(!core.subscription_index().has_demand("orders.created", now));
    core.poll_events(&ctx(verified("alice")), params("orders.created", None))
        .await
        .unwrap();
    let index = core.subscription_index();
    assert!(index.has_demand("orders.created", now));
    assert!(!index.has_demand("orders.shipped", now));
    assert!(index.live_ids("orders.created", now).is_empty());

    // The demand is in the store, where an owner's rebuild finds it.
    let stores = core.stores().unwrap();
    let until = stores.leases.demand("orders.created").await.unwrap();
    assert!(until.is_some_and(|until| until > now));
}

#[tokio::test]
async fn another_replica_answers_the_same_sequence_for_the_same_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), POLL)).await;
    let core = core_of(&state);
    let caller = ctx(verified("alice"));
    let start = core
        .poll_events(&caller, params("orders.created", None))
        .await
        .unwrap();
    logged(&state, &core, "orders", &[1, 2]).await;

    let other = boot(&yaml(dir.path(), POLL)).await;
    let read_here = core
        .poll_events(&caller, params("orders.created", start.cursor.clone()))
        .await
        .unwrap();
    let read_there = core_of(&other)
        .poll_events(&caller, params("orders.created", start.cursor.clone()))
        .await
        .unwrap();
    assert_eq!(numbers(&read_here), vec![1, 2]);
    let ids = |result: &PollEventsResult| -> Vec<String> {
        result.events.iter().map(|e| e.event_id.clone()).collect()
    };
    assert_eq!(ids(&read_here), ids(&read_there));
    // Each replica's cursor resumes on the other.
    let crossed = core
        .poll_events(&caller, params("orders.created", read_there.cursor.clone()))
        .await
        .unwrap();
    assert!(crossed.events.is_empty() && !crossed.truncated);
}
