use super::*;
use crate::builtins::cluster_primitives::MemoryKv;
use crate::protocol::v_2026_07_28::extensions::events::wire::ListEventsParams;
use crate::runtime::events::log::{LogEntry, RowBody};
use crate::runtime::events::test_support::{SESSION_KEY, keys};
use crate::runtime::{GatewayRequestId, RequestContext, RequestIdentity, TransportKind};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

const HOOK_SECRET: &str = "s3cr3t";

/// Boots in one test process race to install the global log subscriber, so
/// these gateways log nowhere.
const QUIET: &str = "observability: { logs: { enabled: false } }";

fn yaml(store_dir: &std::path::Path, extra_events_config: &str, types: &str) -> String {
    format!(
        r#"
{QUIET}
governance:
  policy:
    tool_access:
      rules:
        - tool_name: "event:secret.type"
          minimum_trust: verified
        - tool_name: "gh.issue"
          minimum_trust: verified
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{}" }}
{extra_events_config}
  capabilities:
    events:
{types}
"#,
        store_dir.display()
    )
}

const TYPES: &str = r#"      - name: gh.issue
        description: An issue changed.
        source:
          inbound:
            source_id: gh
            verify: { profile: github, secrets: [s3cr3t] }
            event_id: /delivery_id
            when: { body: { /action: opened } }
            rate_limit: { per_sec: 1000, burst: 1000 }
      - name: secret.type
        source: { inbound: { source_id: secret, allow_unsigned: true } }
      - name: another
        source: { inbound: { source_id: another, allow_unsigned: true } }"#;

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

fn header_asserted() -> RequestIdentity {
    RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "test".to_owned(),
    }
}

fn verified() -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: "alice".to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: "test".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: Default::default(),
    }
}

fn names(core: &EventsCore, identity: RequestIdentity) -> Vec<String> {
    core.list_events(&ctx(identity), &ListEventsParams::default())
        .unwrap()
        .events
        .into_iter()
        .map(|d| d.name)
        .collect()
}

#[tokio::test]
async fn events_off_installs_a_dormant_core() {
    let state = boot(QUIET).await;
    let core = core_of(&state);
    assert!(!core.config().enabled);
    assert!(core.stores().is_none());
    assert!(core.catalog().is_empty());
    assert!(!core.loop_started.load(Ordering::SeqCst));
    assert_eq!(
        core.receive_inbound("gh", &axum::http::HeaderMap::new(), b"{}")
            .await,
        InboundReply::NotFound
    );
    let services = state.runtime.load().shared_services.load_full().unwrap();
    assert!(services.events.is_installed());
}

#[tokio::test]
async fn list_serves_the_catalog_to_the_types_each_caller_may_see() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    assert!(core.config().enabled);
    assert_eq!(
        names(&core, verified()),
        ["another", "gh.issue", "secret.type"]
    );
    // A rule keyed `event:<name>` governs the event; a tool rule of the same
    // name does not.
    assert_eq!(names(&core, header_asserted()), ["another", "gh.issue"]);
    assert!(
        names(
            &core,
            RequestIdentity::Anonymous {
                source: "test".to_owned()
            }
        )
        .is_empty()
    );
    let listed = core
        .list_events(&ctx(verified()), &ListEventsParams::default())
        .unwrap();
    assert_eq!(listed.next_cursor, None);
    let gh = listed.events.iter().find(|d| d.name == "gh.issue").unwrap();
    assert_eq!(gh.description.as_deref(), Some("An issue changed."));
}

#[tokio::test]
async fn list_pages_with_an_opaque_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let types = (0..(handler_page() + 5))
        .map(|i| {
            format!(
                "      - name: t{i:03}\n        retention: {{ max_bytes: 262144 }}\n        source: {{ inbound: {{ source_id: s{i}, allow_unsigned: true }} }}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let state = boot(&yaml(dir.path(), "", &types)).await;
    let core = core_of(&state);
    let first = core
        .list_events(&ctx(verified()), &ListEventsParams::default())
        .unwrap();
    assert_eq!(first.events.len(), handler_page());
    let cursor = first.next_cursor.clone().expect("a second page");
    let second = core
        .list_events(
            &ctx(verified()),
            &ListEventsParams {
                cursor: Some(cursor),
                meta: None,
            },
        )
        .unwrap();
    assert_eq!(second.events.len(), 5);
    assert_eq!(second.next_cursor, None);
    assert_eq!(second.events[0].name, format!("t{:03}", handler_page()));

    let error = core
        .list_events(
            &ctx(verified()),
            &ListEventsParams {
                cursor: Some("not-a-cursor".to_owned()),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), -32602);
}

fn handler_page() -> usize {
    crate::runtime::events::handler::LIST_PAGE_SIZE
}

fn signed_post(source_id: &str, body: &str, secret: &str) -> Request<Body> {
    let signature = format!(
        "sha256={}",
        hex::encode(hmac_sha256::HMAC::mac(body.as_bytes(), secret.as_bytes()))
    );
    Request::builder()
        .method("POST")
        .uri(format!("/webhooks/events/{source_id}"))
        .header("content-type", "application/json")
        .header("x-hub-signature-256", signature)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn post(state: &crate::app::AppState, request: Request<Body>) -> axum::response::Response {
    crate::transports::http::router(state.clone(), "/health", "/mcp")
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_inbound_event_reaches_the_log_through_the_route_and_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    let body = r#"{"action":"opened","delivery_id":"d-1","issue":{"number":7}}"#;

    let response = post(&state, signed_post("gh", body, HOOK_SECRET)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    core.owner_tick().await;
    core.drain_now().await;
    assert!(core.is_owner());
    let stores = core.stores().unwrap();
    let ty = Arc::clone(core.catalog().get("gh.issue").unwrap());
    let rows = stores.log.read(&ty.source_key, 0, 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    let LogEntry::Row(row) = &rows[0] else {
        panic!("readable");
    };
    let RowBody::Event(occurrence) = &row.body else {
        panic!("an event");
    };
    assert_eq!(occurrence.event_id, "d-1");
    assert_eq!(occurrence.data["issue"]["number"], 7);

    // The sender retries the same delivery: accepted again, logged once.
    let again = post(&state, signed_post("gh", body, HOOK_SECRET)).await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);
    core.drain_now().await;
    assert_eq!(
        stores.log.read(&ty.source_key, 0, 10).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn the_route_refuses_what_it_cannot_accept() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    let opened = r#"{"action":"opened","delivery_id":"d-2"}"#;

    let wrong_key = post(&state, signed_post("gh", opened, "not-the-secret")).await;
    assert_eq!(wrong_key.status(), StatusCode::UNAUTHORIZED);

    let unknown = post(&state, signed_post("nope", opened, HOOK_SECRET)).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let not_object = post(&state, signed_post("gh", "[1,2]", HOOK_SECRET)).await;
    assert_eq!(not_object.status(), StatusCode::BAD_REQUEST);

    let huge = format!(r#"{{"action":"opened","pad":"{}"}}"#, "x".repeat(300_000));
    let too_large = post(&state, signed_post("gh", &huge, HOOK_SECRET)).await;
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Verified but outside `when`: acknowledged, never logged.
    let closed = post(
        &state,
        signed_post(
            "gh",
            r#"{"action":"closed","delivery_id":"d-3"}"#,
            HOOK_SECRET,
        ),
    )
    .await;
    assert_eq!(closed.status(), StatusCode::ACCEPTED);
    core.owner_tick().await;
    core.drain_now().await;
    let ty = Arc::clone(core.catalog().get("gh.issue").unwrap());
    let stores = core.stores().unwrap();
    assert!(
        stores
            .log
            .read(&ty.source_key, 0, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let cross_origin = Request::builder()
        .method("POST")
        .uri("/webhooks/events/another")
        .header("origin", "https://evil.example")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        post(&state, cross_origin).await.status(),
        StatusCode::FORBIDDEN
    );
}

/// The events in the log of type `name`, as (event id, data).
async fn logged(core: &Arc<EventsCore>, name: &str) -> Vec<(String, serde_json::Value)> {
    let ty = Arc::clone(core.catalog().get(name).unwrap());
    let stores = core.stores().unwrap();
    stores
        .log
        .read(&ty.source_key, 0, 100)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|entry| match entry {
            LogEntry::Row(row) => match row.body {
                RowBody::Event(occurrence) => Some((occurrence.event_id, occurrence.data)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn one_route_feeds_every_type_whose_filter_keeps_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let types = r#"      - name: gh.issues
        source:
          inbound:
            source_id: gh
            verify: { profile: github, secrets: [s3cr3t] }
            when: { header: { X-GitHub-Event: issues } }
      - name: gh.all
        source:
          inbound:
            source_id: gh
            verify: { profile: github, secrets: [s3cr3t] }"#;
    let state = boot(&yaml(dir.path(), "", types)).await;
    let core = core_of(&state);
    let delivery = |kind: &str, id: &str, body: &str| {
        let mut request = signed_post("gh", body, HOOK_SECRET);
        let headers = request.headers_mut();
        headers.insert("x-github-event", kind.parse().unwrap());
        headers.insert("x-github-delivery", id.parse().unwrap());
        request
    };

    // The webhook's ping is answered and never becomes an event.
    let ping = post(
        &state,
        delivery("ping", "p-1", r#"{"zen":"Keep it simple."}"#),
    )
    .await;
    assert_eq!(ping.status(), StatusCode::ACCEPTED);

    let issue = post(&state, delivery("issues", "d-1", r#"{"action":"opened"}"#)).await;
    assert_eq!(issue.status(), StatusCode::ACCEPTED);
    let push = post(&state, delivery("push", "d-2", r#"{"ref":"main"}"#)).await;
    assert_eq!(push.status(), StatusCode::ACCEPTED);
    // A redelivery keeps its delivery id and is logged once.
    let again = post(&state, delivery("issues", "d-1", r#"{"action":"opened"}"#)).await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);

    core.owner_tick().await;
    core.drain_now().await;
    let ids = |rows: Vec<(String, serde_json::Value)>| {
        rows.into_iter().map(|(id, _)| id).collect::<Vec<_>>()
    };
    assert_eq!(ids(logged(&core, "gh.issues").await), ["d-1"]);
    assert_eq!(ids(logged(&core, "gh.all").await), ["d-1", "d-2"]);

    // Wrongly signed: refused once for the route, not once per type.
    let forged = post(&state, signed_post("gh", "{}", "not-the-secret")).await;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_profile_handshake_is_answered_with_its_reply() {
    let dir = tempfile::tempdir().unwrap();
    let types = r#"      - name: slack.mention
        source:
          inbound:
            source_id: slack
            verify: { profile: slack, secrets: [signing-secret] }
            when: { body: { /event/type: app_mention } }"#;
    let state = boot(&yaml(dir.path(), "", types)).await;
    let core = core_of(&state);
    let slack = |body: &str| {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let signature = format!(
            "v0={}",
            hex::encode(hmac_sha256::HMAC::mac(
                format!("v0:{at}:{body}").as_bytes(),
                b"signing-secret"
            ))
        );
        Request::builder()
            .method("POST")
            .uri("/webhooks/events/slack")
            .header("content-type", "application/json")
            .header("x-slack-request-timestamp", at)
            .header("x-slack-signature", signature)
            .body(Body::from(body.to_owned()))
            .unwrap()
    };

    let challenge = post(
        &state,
        slack(r#"{"token":"t","challenge":"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P","type":"url_verification"}"#),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(challenge.into_body(), 1 << 16)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"})
    );

    let mention = post(
        &state,
        slack(r#"{"type":"event_callback","event_id":"Ev01","event_time":1790000000,"event":{"type":"app_mention","text":"hi"}}"#),
    )
    .await;
    assert_eq!(mention.status(), StatusCode::ACCEPTED);
    core.owner_tick().await;
    core.drain_now().await;
    let ty = Arc::clone(core.catalog().get("slack.mention").unwrap());
    let stores = core.stores().unwrap();
    let rows = stores.log.read(&ty.source_key, 0, 10).await.unwrap();
    assert_eq!(rows.len(), 1, "the challenge is not an event");
    let LogEntry::Row(row) = &rows[0] else {
        panic!("readable");
    };
    let RowBody::Event(occurrence) = &row.body else {
        panic!("an event");
    };
    assert_eq!(occurrence.event_id, "Ev01", "the profile's event id");
    assert_eq!(
        occurrence.timestamp, "2026-09-21T14:13:20.000Z",
        "the profile's event time"
    );
}

#[tokio::test]
async fn a_busy_or_full_route_asks_the_sender_to_retry() {
    let dir = tempfile::tempdir().unwrap();
    let types = r#"      - name: limited
        source: { inbound: { source_id: limited, allow_unsigned: true, rate_limit: { per_sec: 1, burst: 1 } } }
      - name: small
        source: { inbound: { source_id: small, allow_unsigned: true } }"#;
    let state = boot(&yaml(dir.path(), "      log: { inbox_max_rows: 1 }", types)).await;
    let unsigned = |id: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/webhooks/events/{id}"))
            .body(Body::from("{}"))
            .unwrap()
    };
    assert_eq!(
        post(&state, unsigned("limited")).await.status(),
        StatusCode::ACCEPTED
    );
    let limited = post(&state, unsigned("limited")).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key("retry-after"));

    assert_eq!(
        post(&state, unsigned("small")).await.status(),
        StatusCode::ACCEPTED
    );
    let full = post(&state, unsigned("small")).await;
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.headers()["retry-after"], "60");
}

#[tokio::test]
async fn a_reload_keeps_the_core_its_stores_and_its_logs() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    let stores_before = core.stores().unwrap();
    post(
        &state,
        signed_post(
            "gh",
            r#"{"action":"opened","delivery_id":"d-9"}"#,
            HOOK_SECRET,
        ),
    )
    .await;
    core.owner_tick().await;
    core.drain_now().await;
    let fence_before = (*core.owner_lease().borrow()).unwrap().fence;

    let added = format!(
        "{TYPES}\n      - name: added.later\n        source: {{ inbound: {{ source_id: later, allow_unsigned: true }} }}"
    );
    crate::app::reload_config_from_yaml(&state, &yaml(dir.path(), "", &added))
        .await
        .unwrap();
    let after = core_of(&state);
    assert!(Arc::ptr_eq(&core, &after), "the core outlives the reload");
    assert!(Arc::ptr_eq(&stores_before, &core.stores().unwrap()));
    assert!(core.catalog().get("added.later").is_some());
    let ty = Arc::clone(core.catalog().get("gh.issue").unwrap());
    assert_eq!(
        core.stores()
            .unwrap()
            .log
            .read(&ty.source_key, 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    core.owner_tick().await;
    assert_eq!(
        (*core.owner_lease().borrow()).unwrap().fence,
        fence_before,
        "the owner lease is kept, not dropped and re-taken"
    );
}

#[tokio::test]
async fn a_reload_whose_events_do_not_compile_keeps_the_previous_config() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    let broken = format!(
        "{TYPES}\n      - name: transformed\n        transform: {{ plugin: dev.mcpg.transform.absent, expression: x }}\n        source: {{ inbound: {{ source_id: t, allow_unsigned: true }} }}"
    );
    let error = crate::app::reload_config_from_yaml(&state, &yaml(dir.path(), "", &broken))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("not a loaded transform plugin"));
    assert!(core.catalog().get("transformed").is_none());
    assert_eq!(core.catalog().len(), 3);
}

#[tokio::test]
async fn a_probe_url_the_egress_policy_refuses_fails_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let refused = "      webhook: { egress: { allowed_ports: [443], probe_url: \"https://probe.example:8443/\" } }";
    let error = crate::app::reload_config_from_yaml(&state, &yaml(dir.path(), refused, TYPES))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("mcp.configurations.events.webhook.egress.probe_url"),
        "{error:#}"
    );
}

#[tokio::test]
async fn the_egress_probe_reports_whether_its_url_answers() {
    use crate::runtime::events::test_support::{Received, Receiver, loopback_egress};
    let receiver = Receiver::start(Arc::new(|_: &Received| (404, Vec::new()))).await;
    let egress = Arc::new(loopback_egress());
    assert!(probe_egress(Arc::clone(&egress), receiver.url("/probe")).await);
    let seen = receiver.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, axum::http::Method::GET);
    assert_eq!(seen[0].path, "/probe");

    // A port held by a socket that never listens: refused, and no other
    // process can bind it meanwhile.
    let held = tokio::net::TcpSocket::new_v4().unwrap();
    held.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let closed = held.local_addr().unwrap().port();
    let gone = format!("http://receiver.test:{closed}/probe");
    assert!(!probe_egress(Arc::clone(&egress), gone).await);
    drop(held);
    assert!(!probe_egress(egress, "ftp://receiver.test/".to_owned()).await);
}

#[tokio::test]
async fn a_reload_that_turns_events_off_stops_serving_and_steps_down() {
    let dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    core.owner_tick().await;
    assert!(core.is_owner());
    crate::app::reload_config_from_yaml(&state, QUIET)
        .await
        .unwrap();
    assert!(!core.config().enabled);
    assert!(!core.is_owner());
    assert_eq!(
        post(&state, signed_post("gh", "{}", HOOK_SECRET))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    // Records and logs are kept for a later re-enable.
    assert!(core.stores().is_some());
}

fn test_runtime() -> Arc<ArcSwap<GatewayRuntime>> {
    Arc::new(ArcSwap::from_pointee(GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        Vec::new(),
        true,
    )))
}

fn enabled_config() -> EventsConfig {
    EventsConfig {
        enabled: true,
        ..EventsConfig::default()
    }
}

/// A core over explicit stores whose owner loop the test drives by hand.
async fn core_on(
    backend: Option<&Arc<dyn ClusterBackend>>,
    log_kv: &Arc<MemoryKv>,
    runtime: &Arc<ArcSwap<GatewayRuntime>>,
    catalog: EventCatalog,
) -> Arc<EventsCore> {
    let core = Arc::new(EventsCore::new());
    core.loop_started.store(true, Ordering::SeqCst);
    let stores = EventsStores::new(
        keys(),
        Arc::clone(log_kv) as Arc<dyn KeyValueStore>,
        Arc::new(MemoryKv::new()),
        None,
        backend.cloned(),
        true,
    );
    core.commit(
        PreparedEvents {
            config: enabled_config(),
            stores: Some(Arc::new(stores)),
            catalog: Arc::new(catalog),
            egress: None,
            imports: None,
            imports_pending: false,
            public_address: PublicAddress::default(),
        },
        runtime,
    )
    .await;
    core
}

#[tokio::test]
async fn a_stopped_replica_takes_no_lease_again() {
    let backend: Arc<dyn ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let log_kv = Arc::new(MemoryKv::new());
    let runtime = test_runtime();
    let a = core_on(Some(&backend), &log_kv, &runtime, EventCatalog::empty()).await;
    let b = core_on(Some(&backend), &log_kv, &runtime, EventCatalog::empty()).await;

    a.owner_tick().await;
    assert!(a.is_owner());
    a.stop().await;
    a.owner_tick().await;
    assert!(!a.is_owner());
    assert!(a.held_shards(now_ms()).is_empty());
    b.owner_tick().await;
    assert!(b.is_owner(), "the stopped replica released the owner lease");
}

#[tokio::test]
async fn one_replica_owns_the_logs_at_a_time() {
    let backend: Arc<dyn ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let log_kv = Arc::new(MemoryKv::new());
    let runtime = test_runtime();
    let a = core_on(Some(&backend), &log_kv, &runtime, EventCatalog::empty()).await;
    let b = core_on(Some(&backend), &log_kv, &runtime, EventCatalog::empty()).await;

    a.owner_tick().await;
    b.owner_tick().await;
    assert!(a.is_owner());
    assert!(!b.is_owner());
    assert!(b.owner_lease().borrow().is_none());

    a.shutdown().await;
    assert!(!a.is_owner());
    b.owner_tick().await;
    assert!(b.is_owner());
    let fence = (*b.owner_lease().borrow()).unwrap().fence;
    assert!(fence > 1, "a new owner holds a newer fence: {fence}");
}

/// Subscribe checks the per-type and total limits against the local
/// index, so a replica that is not the owner builds it from the store too.
#[tokio::test]
async fn a_replica_that_is_not_the_owner_keeps_its_subscription_index() {
    let backend: Arc<dyn ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let dir = tempfile::tempdir().unwrap();
    let config = AppConfig::load_from_yaml_str(&yaml(dir.path(), "", TYPES)).unwrap();
    let registry = crate::runtime::events::test_support::ScriptedWatch::registry(&[]);
    let runtime = test_runtime();
    let log_kv = Arc::new(MemoryKv::new());
    let owner = core_on(
        Some(&backend),
        &log_kv,
        &runtime,
        EventCatalog::build(&config, &keys(), &registry)
            .await
            .unwrap(),
    )
    .await;
    let other = core_on(
        Some(&backend),
        &log_kv,
        &runtime,
        EventCatalog::build(&config, &keys(), &registry)
            .await
            .unwrap(),
    )
    .await;
    owner.owner_tick().await;
    let store = &other.stores().unwrap().subscriptions;
    let principal = "verified::oidc::https://idp.example::alice";
    let id = store.id_for(
        principal,
        "https://h.example/a",
        "gh.issue",
        &Default::default(),
    );
    let secret = crate::protocol::v_2026_07_28::extensions::events::wire::WebhookSecret::parse(
        &crate::runtime::events::test_support::whsec(1),
    )
    .unwrap();
    let record = crate::runtime::events::subscriptions::SubscriptionRecord {
        v: 1,
        secret: store.seal_secret(&id, &secret),
        id,
        principal_key: principal.to_owned(),
        identity: verified(),
        credential: Default::default(),
        url: "https://h.example/a".to_owned(),
        host: "h.example".to_owned(),
        name: "gh.issue".to_owned(),
        arguments: Default::default(),
        previous_secret: None,
        previous_secret_until_ms: None,
        created_at_ms: now_ms(),
        refreshed_at_ms: now_ms(),
        expires_at_ms: Some(now_ms() + 3_600_000),
        verified_at_ms: None,
        start: Default::default(),
        schema_epoch: 0,
        reactivated_at_ms: None,
        operator_suspended_at_ms: None,
        revoked: None,
    };
    store.create(&record).await.unwrap();
    other.owner_tick().await;
    assert!(!other.is_owner());
    assert_eq!(other.live_counts("gh.issue", now_ms()), (1, 1));
}

#[tokio::test]
async fn a_replica_that_is_not_the_owner_still_accepts_inbound_events() {
    let dir = tempfile::tempdir().unwrap();
    let config = AppConfig::load_from_yaml_str(&yaml(dir.path(), "", TYPES)).unwrap();
    let catalog = EventCatalog::build(
        &config,
        &keys(),
        &crate::runtime::events::test_support::ScriptedWatch::registry(&[]),
    )
    .await
    .unwrap();
    let runtime = test_runtime();
    let core = core_on(None, &Arc::new(MemoryKv::new()), &runtime, catalog).await;
    assert!(!core.is_owner(), "no tick has run");
    let body = r#"{"action":"opened","delivery_id":"d-5"}"#;
    let signature = format!(
        "sha256={}",
        hex::encode(hmac_sha256::HMAC::mac(
            body.as_bytes(),
            HOOK_SECRET.as_bytes()
        ))
    );
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-hub-signature-256",
        axum::http::HeaderValue::from_str(&signature).unwrap(),
    );
    assert_eq!(
        core.receive_inbound("gh", &headers, body.as_bytes()).await,
        InboundReply::Accepted
    );
    core.drain_now().await;
    let ty = Arc::clone(core.catalog().get("gh.issue").unwrap());
    let stores = core.stores().unwrap();
    assert_eq!(stores.log.inbox_pending(&ty.source_key).await.unwrap(), 1);
    core.owner_tick().await;
    assert_eq!(stores.log.inbox_pending(&ty.source_key).await.unwrap(), 0);
}

#[tokio::test]
async fn stores_in_this_process_survive_a_reload_but_new_ones_are_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = tempfile::tempdir().unwrap();
    let state = boot(&yaml(dir.path(), "", TYPES)).await;
    let core = core_of(&state);
    let before = core.stores().unwrap();
    let moved = yaml(
        dir.path(),
        &format!(
            "      log_store: {{ kind: file, dir: \"{}\" }}",
            log_dir.path().display()
        ),
        TYPES,
    );
    crate::app::reload_config_from_yaml(&state, &moved)
        .await
        .unwrap();
    let after = core.stores().unwrap();
    assert!(
        !Arc::ptr_eq(&before, &after),
        "a changed store is resolved again"
    );
    assert!(after.subscriptions_durable);
}

/// A push receiver runs on every replica: what one that is not the owner
/// saw reaches the owner's log through the inbox, once per event id.
#[tokio::test]
async fn the_owner_appends_what_an_every_replica_source_saw_once() {
    use crate::runtime::events::test_support::ScriptedWatch;
    let types = r#"      - name: sms.received
        source:
          watch:
            strategy: { type: nats_topic, subject: sms }
            event_type: twilio.sms.received"#;
    let plugin = ScriptedWatch::declaring(mcpg_plugin_protocol::WatchStrategyDescriptor {
        kind: "nats_topic".to_owned(),
        placement: mcpg_plugin_protocol::EventPlacement::EveryReplica,
        resume: false,
        event_types: vec![mcpg_plugin_protocol::EventTypeDescriptor {
            name: "twilio.sms.received".to_owned(),
            description: String::new(),
            input_schema: None,
            payload_schema: None,
        }],
    });
    let dir = tempfile::tempdir().unwrap();
    let config = AppConfig::load_from_yaml_str(&yaml(dir.path(), "", types)).unwrap();
    let catalog = EventCatalog::build(&config, &keys(), &ScriptedWatch::registry(&[plugin]))
        .await
        .unwrap();
    let runtime = test_runtime();
    let core = core_on(None, &Arc::new(MemoryKv::new()), &runtime, catalog).await;
    let ty = Arc::clone(core.catalog().get("sms.received").unwrap());
    assert!(ty.source.runs_on_every_replica());
    let stores = core.stores().unwrap();
    let row = InboxRow {
        v: 1,
        event_id: Some("SM1".to_owned()),
        timestamp: None,
        data: serde_json::json!({ "messageSid": "SM1", "body": "hi" }),
        received_at_ms: now_ms(),
        ..InboxRow::default()
    };
    let limits = InboxLimits {
        ttl: Duration::from_secs(60),
        max_rows: 100,
    };
    // Twilio retried the POST: the same SID twice.
    for _ in 0..2 {
        stores
            .log
            .inbox_put(&ty.source_key, row.clone(), limits)
            .await
            .unwrap();
    }
    core.owner_tick().await;
    assert_eq!(stores.log.inbox_pending(&ty.source_key).await.unwrap(), 0);
    let entries = stores.log.read(&ty.source_key, 0, 10).await.unwrap();
    let ids: Vec<String> = entries
        .iter()
        .filter_map(|entry| match entry {
            LogEntry::Row(row) => match &row.body {
                RowBody::Event(occurrence) => Some(occurrence.event_id.clone()),
                RowBody::Gap { .. } | RowBody::Ended { .. } => None,
            },
            LogEntry::Unreadable { .. } => None,
        })
        .collect();
    assert_eq!(ids, ["SM1"]);
}

/// While the plan's ingest allowance is used, a source that runs on every
/// replica stops, and its readers learn, once, that they may miss what it
/// saw; it starts again when the allowance comes back.
#[tokio::test]
async fn a_held_ingest_stops_every_replica_sources_and_marks_their_gap_once() {
    use crate::runtime::cp_quota::{EventsPlan, TestQuota};
    use crate::runtime::events::log::GapReason;
    use crate::runtime::events::test_support::ScriptedWatch;
    let types = r#"      - name: sms.received
        always_on: true
        source:
          watch:
            strategy: { type: nats_topic, subject: sms }
            event_type: twilio.sms.received"#;
    let plugin = ScriptedWatch::declaring(mcpg_plugin_protocol::WatchStrategyDescriptor {
        kind: "nats_topic".to_owned(),
        placement: mcpg_plugin_protocol::EventPlacement::EveryReplica,
        resume: false,
        event_types: vec![mcpg_plugin_protocol::EventTypeDescriptor {
            name: "twilio.sms.received".to_owned(),
            description: String::new(),
            input_schema: None,
            payload_schema: None,
        }],
    });
    let dir = tempfile::tempdir().unwrap();
    let config = AppConfig::load_from_yaml_str(&yaml(dir.path(), "", types)).unwrap();
    let catalog = EventCatalog::build(&config, &keys(), &ScriptedWatch::registry(&[plugin]))
        .await
        .unwrap();
    let quota = TestQuota::default();
    let mut runtime = GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        Vec::new(),
        true,
    );
    runtime.set_cp_quota_status_provider(Arc::new(quota.clone()));
    let runtime = Arc::new(ArcSwap::from_pointee(runtime));
    let core = core_on(None, &Arc::new(MemoryKv::new()), &runtime, catalog).await;
    let ty = Arc::clone(core.catalog().get("sms.received").unwrap());
    let stores = core.stores().unwrap();
    let gaps = || async {
        stores
            .log
            .read(&ty.source_key, 0, 10)
            .await
            .unwrap()
            .into_iter()
            .filter(|entry| {
                matches!(entry, LogEntry::Row(row) if matches!(
                    &row.body,
                    RowBody::Gap { reason: GapReason::SourceRestart, .. }
                ))
            })
            .count()
    };

    core.owner_tick().await;
    assert_eq!(
        core.owner.lock().await.replica_sources.running(),
        ["sms.received"]
    );

    quota.set_events(EventsPlan {
        ingest_held: true,
        held_until: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..EventsPlan::default()
    });
    core.owner_tick().await;
    core.owner_tick().await;
    assert!(core.owner.lock().await.replica_sources.running().is_empty());
    assert_eq!(
        gaps().await,
        1,
        "one gap when the hold starts, not one a tick"
    );

    quota.set_events(EventsPlan::default());
    core.owner_tick().await;
    assert_eq!(
        core.owner.lock().await.replica_sources.running(),
        ["sms.received"]
    );
    assert_eq!(gaps().await, 1);
}

/// The owner's retention pass keeps a log within the plan's cap when the
/// type's own retention keeps more.
#[tokio::test]
async fn the_retention_pass_keeps_a_log_within_the_plan_cap() {
    use crate::runtime::cp_quota::{EventsPlan, TestQuota};
    use crate::runtime::events::occurrence::StoredOccurrence;
    let types = r#"      - name: orders.created
        source: { inbound: { source_id: orders, allow_unsigned: true } }"#;
    let dir = tempfile::tempdir().unwrap();
    let config = AppConfig::load_from_yaml_str(&yaml(dir.path(), "", types)).unwrap();
    let catalog = EventCatalog::build(
        &config,
        &keys(),
        &crate::runtime::events::test_support::ScriptedWatch::registry(&[]),
    )
    .await
    .unwrap();
    let quota = TestQuota::default();
    let mut runtime = GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        Vec::new(),
        true,
    );
    runtime.set_cp_quota_status_provider(Arc::new(quota.clone()));
    let runtime = Arc::new(ArcSwap::from_pointee(runtime));
    let core = core_on(None, &Arc::new(MemoryKv::new()), &runtime, catalog).await;
    core.owner_tick().await;
    let lease = (*core.owner_lease().borrow()).expect("the owner");
    let ty = Arc::clone(core.catalog().get("orders.created").unwrap());
    assert_eq!(ty.retention.max_events, 10_000, "the configured default");
    let stores = core.stores().unwrap();
    for n in 0..5 {
        stores
            .log
            .append(
                &ty.source_key,
                StoredOccurrence {
                    event_id: format!("o-{n}"),
                    timestamp: "2026-10-10T12:00:00.000Z".to_owned(),
                    data: serde_json::json!({ "n": n }),
                    audience: None,
                    arguments: None,
                },
                &ty.retention,
                lease,
            )
            .await
            .unwrap();
    }
    let depth = || async {
        let bounds = stores.log.bounds(&ty.source_key).await.unwrap();
        (bounds.head + 1).saturating_sub(bounds.floor)
    };
    assert_eq!(depth().await, 5);

    quota.set_events(EventsPlan {
        retention_events_limit: Some(2),
        ..EventsPlan::default()
    });
    core.owner.lock().await.last_retention_ms = 0;
    core.owner_tick().await;
    assert_eq!(depth().await, 2, "the plan's 2, not the configured 10 000");
}

/// One coordinator as replica `node` sees it, with the replicas in `peers`
/// alive.
struct Replica {
    inner: Arc<dyn ClusterBackend>,
    node: String,
    peers: Arc<parking_lot::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl ClusterBackend for Replica {
    fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
        self.inner.manifest()
    }
    fn key_value_store(&self) -> Option<Arc<dyn KeyValueStore>> {
        self.inner.key_value_store()
    }
    fn pub_sub(&self) -> Option<Arc<dyn PubSub>> {
        self.inner.pub_sub()
    }
    async fn node_info(&self) -> mcpg_cluster_api::ClusterNodeInfo {
        mcpg_cluster_api::ClusterNodeInfo {
            node_id: self.node.clone(),
            ..self.inner.node_info().await
        }
    }
    async fn list_peers(&self) -> Vec<mcpg_cluster_api::ClusterPeer> {
        self.peers
            .lock()
            .iter()
            .map(|node| mcpg_cluster_api::ClusterPeer {
                node_id: node.clone(),
                address: "local".to_owned(),
                last_seen: String::new(),
                health: mcpg_cluster_api::PeerHealth::Healthy,
                roles: Vec::new(),
            })
            .collect()
    }
    async fn watch_peers(&self) -> mcpg_cluster_api::BoxPeerEventStream {
        self.inner.watch_peers().await
    }
    async fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, mcpg_cluster_api::ClusterError> {
        self.inner.acquire_leadership(role, lease_ttl).await
    }
    async fn try_acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, mcpg_cluster_api::ClusterError> {
        self.inner.try_acquire_leadership(role, lease_ttl).await
    }
    async fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, mcpg_cluster_api::ClusterError> {
        self.inner.acquire_lock(key, lease_ttl).await
    }
    async fn try_acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, mcpg_cluster_api::ClusterError> {
        self.inner.try_acquire_lock(key, lease_ttl).await
    }
    async fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: bytes::Bytes,
    ) -> Result<(), mcpg_cluster_api::ClusterError> {
        self.inner.publish(topic, routing_key, payload).await
    }
    async fn subscribe(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
    ) -> Result<mcpg_cluster_api::BoxPublishedMessageStream, mcpg_cluster_api::ClusterError> {
        self.inner.subscribe(topic, group, routing_key).await
    }
}

#[tokio::test]
async fn the_replicas_share_the_dispatcher_shards_and_take_over_what_one_gives_up() {
    let shared: Arc<dyn ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let peers = Arc::new(parking_lot::Mutex::new(vec![
        "a".to_owned(),
        "b".to_owned(),
    ]));
    let replica = |node: &str| -> Arc<dyn ClusterBackend> {
        Arc::new(Replica {
            inner: Arc::clone(&shared),
            node: node.to_owned(),
            peers: Arc::clone(&peers),
        })
    };
    let log_kv = Arc::new(MemoryKv::new());
    let runtime = test_runtime();
    let a = core_on(
        Some(&replica("a")),
        &log_kv,
        &runtime,
        EventCatalog::empty(),
    )
    .await;
    let b = core_on(
        Some(&replica("b")),
        &log_kv,
        &runtime,
        EventCatalog::empty(),
    )
    .await;

    a.owner_tick().await;
    b.owner_tick().await;
    let (held_a, held_b) = (a.held_shards(now_ms()), b.held_shards(now_ms()));
    let half = (DISPATCH_SHARDS / 2) as usize;
    assert_eq!((held_a.len(), held_b.len()), (half, half));
    assert!(
        held_a.keys().all(|shard| !held_b.contains_key(shard)),
        "no shard is delivered twice"
    );

    // b leaves: a takes every shard once b is no longer a peer.
    b.shutdown().await;
    assert!(b.held_shards(now_ms()).is_empty());
    peers.lock().retain(|node| node == "a");
    a.owner_tick().await;
    let all = a.held_shards(now_ms());
    assert_eq!(all.len(), DISPATCH_SHARDS as usize);
    for (shard, lease) in &held_b {
        assert!(
            all[shard].fence > lease.fence,
            "a takes shard {shard} under a newer fence"
        );
    }

    // b comes back: a gives up what is above its share, and b takes it.
    peers.lock().push("b".to_owned());
    let b = core_on(
        Some(&replica("b")),
        &log_kv,
        &runtime,
        EventCatalog::empty(),
    )
    .await;
    a.owner_tick().await;
    b.owner_tick().await;
    assert_eq!(a.held_shards(now_ms()).len(), half);
    assert_eq!(b.held_shards(now_ms()).len(), half);
}

#[tokio::test]
async fn a_single_node_delivers_every_shard() {
    let runtime = test_runtime();
    let core = core_on(
        None,
        &Arc::new(MemoryKv::new()),
        &runtime,
        EventCatalog::empty(),
    )
    .await;
    core.owner_tick().await;
    assert_eq!(core.held_shards(now_ms()).len(), DISPATCH_SHARDS as usize);
}
