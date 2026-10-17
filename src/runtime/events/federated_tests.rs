use std::sync::Mutex;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;

use super::*;
use crate::builtins::cluster_primitives::MemoryKv;
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    ControlEnvelope, DeliveryMode, EventOccurrence, ListEventsParams, PollEventsParams,
    PollEventsResult,
};
use crate::runtime::cp_quota::{EventsPlan, TestQuota};
use crate::runtime::events::log::{EventLog, LogEntry, RowBody};
use crate::runtime::events::test_support::{SESSION_KEY, keys, request_context, verified_identity};

/// One read of the upstream: the method, the `region` argument and the
/// cursor sent.
type Read = (String, Option<String>, Option<String>);

/// A webhook subscription made on the upstream: the callback, its secret,
/// the `region` argument, and what the callback has been sent up to.
#[derive(Clone)]
struct Callback {
    url: String,
    secret: String,
    region: Option<String>,
    sent: usize,
}

/// An upstream on the 2026-07-28 wire that serves `orders.created`, whose
/// occurrences the test adds. A cursor is the count of occurrences read
/// past.
#[derive(Clone, Default)]
struct Upstream {
    events: Arc<Mutex<Vec<(String, String)>>>,
    reads: Arc<Mutex<Vec<Read>>>,
    types: Arc<Mutex<Vec<Value>>>,
    callbacks: Arc<Mutex<Vec<Callback>>>,
}

impl Upstream {
    async fn start() -> (Self, String) {
        let upstream = Self::default();
        upstream.types.lock().unwrap().push(json!({
            "name": "orders.created",
            "description": "An order was placed.",
            "delivery": ["poll", "push", "webhook"],
            "inputSchema": {
                "type": "object",
                "properties": { "region": { "type": "string" } },
                "additionalProperties": false
            },
            "payloadSchema": { "type": "object" }
        }));
        let app = Router::new()
            .route("/mcp", post(serve))
            .with_state(upstream.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (upstream, format!("http://{addr}/mcp"))
    }

    fn add(&self, id: &str, region: &str) {
        self.events
            .lock()
            .unwrap()
            .push((id.to_owned(), region.to_owned()));
    }

    /// The occurrences of `region` after position `after`, each with its
    /// position, and the head.
    fn after(&self, region: Option<&str>, after: usize) -> (Vec<(usize, EventOccurrence)>, usize) {
        let events = self.events.lock().unwrap();
        let found = events
            .iter()
            .enumerate()
            .skip(after)
            .filter(|(_, (_, r))| region.is_none_or(|region| region == r))
            .map(|(i, (id, r))| {
                (
                    i + 1,
                    EventOccurrence {
                        event_id: id.clone(),
                        name: "orders.created".to_owned(),
                        timestamp: "2026-10-10T00:00:00Z".to_owned(),
                        data: json!({ "id": id, "region": r }),
                        cursor: Some((i + 1).to_string()),
                        meta: None,
                    },
                )
            })
            .collect();
        (found, events.len())
    }

    /// The regions of the reads made with `method`.
    fn regions(&self, method: &str) -> Vec<Option<String>> {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == method)
            .map(|(_, region, _)| region.clone())
            .collect()
    }

    /// The first webhook subscription the upstream holds.
    fn callback(&self) -> Option<Callback> {
        self.callbacks.lock().unwrap().first().cloned()
    }

    /// What the upstream was asked and the callbacks it holds, for a
    /// failure message.
    fn seen(&self) -> String {
        let reads = self.reads.lock().unwrap().clone();
        let callbacks = self.callbacks.lock().unwrap().len();
        format!("the upstream holds {callbacks} callback(s) and was asked {reads:?}")
    }

    /// POST every occurrence a webhook subscription has not been sent yet
    /// to its callback, signed with its secret; the statuses answered.
    async fn deliver(&self) -> Vec<u16> {
        let callbacks = self.callbacks.lock().unwrap().clone();
        let client = reqwest::Client::new();
        let mut statuses = Vec::new();
        for callback in &callbacks {
            let (found, head) = self.after(callback.region.as_deref(), callback.sent);
            for (_, occurrence) in found {
                let body = serde_json::to_vec(&occurrence).unwrap();
                statuses.push(post_signed(&client, callback, &occurrence.event_id, &body).await);
            }
            if let Some(held) = self
                .callbacks
                .lock()
                .unwrap()
                .iter_mut()
                .find(|c| c.url == callback.url)
            {
                held.sent = head;
            }
        }
        statuses
    }

    /// POST `envelope` to every callback, signed.
    async fn deliver_envelope(&self, envelope: &ControlEnvelope) -> Vec<u16> {
        let callbacks = self.callbacks.lock().unwrap().clone();
        let client = reqwest::Client::new();
        let body = serde_json::to_vec(envelope).unwrap();
        let mut statuses = Vec::new();
        for callback in &callbacks {
            let id = envelope.webhook_id("t1");
            statuses.push(post_signed(&client, callback, &id, &body).await);
        }
        statuses
    }
}

async fn post_signed(client: &reqwest::Client, callback: &Callback, id: &str, body: &[u8]) -> u16 {
    let secret = mcpg_standard_webhooks::WhsecSecret::parse(&callback.secret).unwrap();
    let now = now_ms() / 1_000;
    let headers = mcpg_standard_webhooks::sign_message(&[&secret], id, now, body).unwrap();
    client
        .post(&callback.url)
        .header("content-type", "application/json")
        .header("webhook-id", headers.id)
        .header("webhook-timestamp", headers.timestamp)
        .header("webhook-signature", headers.signature)
        .body(body.to_vec())
        .send()
        .await
        .map(|response| response.status().as_u16())
        .unwrap_or(0)
}

/// Each read is recorded once its effect is in place, so a test that sees
/// the read also sees its position and its callback.
async fn serve(State(upstream): State<Upstream>, Json(body): Json<Value>) -> Response {
    let method = body["method"].as_str().unwrap_or_default().to_owned();
    let id = body["id"].clone();
    let params = body.get("params").cloned().unwrap_or_else(|| json!({}));
    let region = params["arguments"]["region"].as_str().map(str::to_owned);
    let cursor = params["cursor"].as_str().map(str::to_owned);
    // The region `blocked` is one this upstream refuses the gateway.
    if region.as_deref() == Some("blocked")
        && method.starts_with("events/")
        && method != "events/list"
    {
        upstream
            .reads
            .lock()
            .unwrap()
            .push((method, region, cursor));
        return Json(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32012, "message": "forbidden", "data": { "reason": "not_shared" } }
        }))
        .into_response();
    }
    match method.as_str() {
        "events/list" => {
            let types = upstream.types.lock().unwrap().clone();
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": { "events": types } }))
                .into_response()
        }
        "events/poll" => {
            let head = upstream.events.lock().unwrap().len();
            let after = cursor
                .as_deref()
                .and_then(|c| c.parse().ok())
                .unwrap_or(head);
            let (found, head) = upstream.after(region.as_deref(), after);
            upstream
                .reads
                .lock()
                .unwrap()
                .push((method, region, cursor));
            let events: Vec<EventOccurrence> = found.into_iter().map(|(_, o)| o).collect();
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "events": events, "cursor": head.to_string(),
                    "truncated": false, "hasMore": false, "nextPollMs": 1
                }
            }))
            .into_response()
        }
        "events/stream" => {
            let head = upstream.events.lock().unwrap().len();
            let after = cursor
                .as_deref()
                .and_then(|c| c.parse().ok())
                .unwrap_or(head);
            upstream
                .reads
                .lock()
                .unwrap()
                .push((method, region.clone(), cursor));
            stream(upstream, id, region, after)
        }
        "events/subscribe" => {
            let url = params["delivery"]["url"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let secret = params["delivery"]["secret"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let head = upstream.events.lock().unwrap().len();
            let sent = cursor
                .as_deref()
                .and_then(|c| c.parse().ok())
                .unwrap_or(head);
            {
                let mut callbacks = upstream.callbacks.lock().unwrap();
                if !callbacks.iter().any(|c| c.url == url) {
                    callbacks.push(Callback {
                        url,
                        secret,
                        region: region.clone(),
                        sent,
                    });
                }
            }
            upstream
                .reads
                .lock()
                .unwrap()
                .push((method, region, cursor));
            let refresh_before = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "id": "up-sub-1", "refreshBefore": refresh_before,
                    "cursor": head.to_string(), "truncated": false
                }
            }))
            .into_response()
        }
        "events/unsubscribe" => {
            let url = params["delivery"]["url"].as_str().unwrap_or_default();
            upstream.callbacks.lock().unwrap().retain(|c| c.url != url);
            upstream
                .reads
                .lock()
                .unwrap()
                .push((method, region, cursor));
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": {} })).into_response()
        }
        _ => Json(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": "method not found" }
        }))
        .into_response(),
    }
}

/// An `events/stream` from position `after`: `active`, then each new
/// occurrence of `region` as it is added, with a heartbeat now and then.
fn stream(upstream: Upstream, id: Value, region: Option<String>, after: usize) -> Response {
    use axum::response::sse::{Event, Sse};
    let active = StreamFrame::Active {
        cursor: Some(after.to_string()),
        truncated: false,
    }
    .to_notification(&id);
    let start = (
        upstream,
        region,
        after,
        Some(active),
        tokio::time::Instant::now() + Duration::from_millis(500),
    );
    let frames = futures::stream::unfold(
        start,
        move |(upstream, region, mut after, mut next, mut beat_at)| {
            let id = id.clone();
            async move {
                loop {
                    if let Some(frame) = next.take() {
                        let event = Event::default().data(frame.to_string());
                        return Some((
                            Ok::<_, std::convert::Infallible>(event),
                            (upstream, region, after, None, beat_at),
                        ));
                    }
                    let (found, head) = upstream.after(region.as_deref(), after);
                    if let Some((position, occurrence)) = found.into_iter().next() {
                        after = position;
                        next = Some(StreamFrame::Event(occurrence).to_notification(&id));
                        continue;
                    }
                    if tokio::time::Instant::now() >= beat_at {
                        beat_at = tokio::time::Instant::now() + Duration::from_millis(500);
                        after = head;
                        next = Some(
                            StreamFrame::Heartbeat {
                                cursor: Some(head.to_string()),
                            }
                            .to_notification(&id),
                        );
                        continue;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        },
    );
    Sse::new(frames).into_response()
}

async fn boot(
    dir: &std::path::Path,
    url: &str,
    delivery: &str,
) -> (crate::app::AppState, Arc<EventsCore>) {
    boot_at(dir, url, delivery, "", 300_000).await
}

/// [`boot`] with `server` as `gateway.server` config.
async fn boot_at(
    dir: &std::path::Path,
    url: &str,
    delivery: &str,
    server: &str,
    linger_ms: u64,
) -> (crate::app::AppState, Arc<EventsCore>) {
    boot_planned(dir, url, delivery, server, linger_ms, TestQuota::default()).await
}

/// [`boot_at`] told about the plan `quota` sets, as by an attached control
/// plane.
async fn boot_planned(
    dir: &std::path::Path,
    url: &str,
    delivery: &str,
    server: &str,
    linger_ms: u64,
    quota: TestQuota,
) -> (crate::app::AppState, Arc<EventsCore>) {
    let yaml = format!(
        r#"
observability: {{ logs: {{ enabled: false }} }}
gateway: {{ server: {{ {server} }} }}
mcp:
  federations:
    - name: up
      upstream:
        url: "{url}"
        protocol_version: "2026-07-28"
        upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}
      import: {{ tools: false, events: true }}
      naming: {{ event_prefix: "up." }}
      events: {{ delivery: {delivery} }}
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{dir}/subscriptions" }}
      log_store: {{ kind: file, dir: "{dir}/log" }}
      # A lease is refreshed once half of it is left: half of 10 s outlasts a poll slowed by load.
      poll: {{ enabled: true, next_poll_ms: 1000, min_next_poll_ms: 1, lease_multiplier: 10 }}
      push: {{ enabled: true, heartbeat_interval_ms: 1000 }}
      sources: {{ linger_ms: {linger_ms} }}
"#,
        dir = dir.display()
    );
    let config = crate::config::AppConfig::load_from_yaml_str(&yaml).expect("config parses");
    let state = crate::app::build_from_config_adjusted(config, move |runtime| {
        runtime.set_cp_quota_status_provider(Arc::new(quota));
    })
    .await
    .unwrap_or_else(|e| panic!("boots: {e:#}"));
    let core = state
        .runtime
        .load()
        .shared_services
        .load_full()
        .and_then(|s| s.events_core.get().cloned())
        .expect("an events core");
    (state, core)
}

const TYPE: &str = "up.orders.created";

fn poll_params(region: &str, cursor: Option<String>) -> PollEventsParams {
    let mut arguments = Map::new();
    arguments.insert("region".to_owned(), json!(region));
    PollEventsParams {
        name: TYPE.to_owned(),
        arguments,
        cursor,
        max_age_ms: None,
        max_events: None,
        meta: None,
    }
}

fn ids(result: &PollEventsResult) -> Vec<String> {
    result.events.iter().map(|e| e.event_id.clone()).collect()
}

/// How long a wait lasts before the test fails. A wait ends as soon as its
/// condition holds, so only a failing run waits this long.
const WAIT: Duration = Duration::from_secs(60);

/// Wait up to [`WAIT`] for `check`.
async fn within<F: FnMut() -> bool>(mut check: F) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}

/// A client that polls `region` from `cursor` in the background until it
/// is stopped or dropped. Its lease, and the upstream demand it makes, stay
/// live meanwhile, however long the test takes between its own polls.
struct Reader {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Reader {
    fn start(core: &Arc<EventsCore>, region: &str, cursor: &str) -> Self {
        let core = Arc::clone(core);
        let params = poll_params(region, Some(cursor.to_owned()));
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let task = tokio::spawn(async move {
            let caller = request_context(verified_identity("alice"));
            loop {
                let _ = core.poll_events(&caller, params.clone()).await;
                tokio::select! {
                    () = stopped.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
        });
        Self { stop, task }
    }

    /// Stop polling, and return once no poll is in flight.
    async fn stop(mut self) {
        self.stop.cancel();
        (&mut self.task).await.expect("the reader stops");
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Poll `region` from `cursor` until the poll returns `want`, for up to
/// [`WAIT`]; the last answer.
async fn poll_until(
    core: &Arc<EventsCore>,
    region: &str,
    cursor: &str,
    want: &[&str],
) -> Vec<String> {
    let caller = request_context(verified_identity("alice"));
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        core.owner_tick().await;
        let seen = core
            .poll_events(&caller, poll_params(region, Some(cursor.to_owned())))
            .await
            .map(|result| ids(&result))
            .unwrap_or_default();
        if seen == want || tokio::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn imported(core: &Arc<EventsCore>) -> bool {
    within(|| core.catalog().get(TYPE).is_some()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_type_serves_each_set_of_arguments_from_its_own_upstream_poll() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core) = boot(dir.path(), &url, "poll").await;
    assert!(imported(&core).await, "the upstream's type is imported");
    let listed = core
        .list_events(
            &request_context(verified_identity("alice")),
            &ListEventsParams::default(),
        )
        .unwrap();
    let descriptor = listed
        .events
        .iter()
        .find(|e| e.name == TYPE)
        .expect("listed under the prefix");
    assert_eq!(
        descriptor.description.as_deref(),
        Some("An order was placed.")
    );
    assert!(descriptor.delivery.contains(&DeliveryMode::Poll));
    assert!(
        descriptor.delivery.contains(&DeliveryMode::Push),
        "served in every mode the gateway enables"
    );

    let caller = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _eu_reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    assert!(
        within(|| upstream.regions("events/poll").contains(&Some("eu".into()))).await,
        "the demand for `eu` starts an upstream poll with those arguments; {}",
        upstream.seen()
    );
    upstream.add("e1", "eu");
    upstream.add("e2", "us");
    upstream.add("e3", "eu");
    assert_eq!(
        poll_until(&core, "eu", &eu, &["up:e1", "up:e3"]).await,
        ["up:e1", "up:e3"],
        "the federation namespaces the upstream's event ids"
    );

    let us = core
        .poll_events(&caller, poll_params("us", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _us_reader = Reader::start(&core, "us", &us);
    core.owner_tick().await;
    assert!(
        within(|| upstream.regions("events/poll").contains(&Some("us".into()))).await,
        "a second set of arguments gets an upstream subscription of its own; {}",
        upstream.seen()
    );
    upstream.add("e4", "us");
    assert_eq!(poll_until(&core, "us", &us, &["up:e4"]).await, ["up:e4"]);
    assert_eq!(
        poll_until(&core, "eu", &eu, &["up:e1", "up:e3"]).await,
        ["up:e1", "up:e3"],
        "a reader of `eu` never receives what the `us` subscription read"
    );
    drop(state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_that_ends_a_subscription_ends_the_ones_it_served() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core) = boot(dir.path(), &url, "poll").await;
    assert!(imported(&core).await);
    let caller = request_context(verified_identity("alice"));
    let blocked = core
        .poll_events(&caller, poll_params("blocked", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    let deadline = tokio::time::Instant::now() + WAIT;
    let error = loop {
        core.owner_tick().await;
        match core
            .poll_events(&caller, poll_params("blocked", Some(blocked.clone())))
            .await
        {
            Err(error) => break error,
            Ok(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(result) => panic!("the poll never ended: {result:?}; {}", upstream.seen()),
        }
    };
    assert_eq!(error.code(), -32012);
    assert_eq!(
        error.data().unwrap()["reason"],
        "upstream_forbidden",
        "the gateway's own words, not the upstream's"
    );
    assert!(
        within(|| upstream.regions("events/poll").contains(&Some("eu".into()))).await,
        "the demand for `eu` starts an upstream poll; {}",
        upstream.seen()
    );
    upstream.add("e1", "eu");
    assert_eq!(
        poll_until(&core, "eu", &eu, &["up:e1"]).await,
        ["up:e1"],
        "other arguments read on"
    );
    drop(state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_type_reads_its_upstream_over_a_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core) = boot(dir.path(), &url, "push").await;
    assert!(imported(&core).await, "the upstream's type is imported");
    let caller = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    assert!(
        within(|| upstream
            .regions("events/stream")
            .contains(&Some("eu".into())))
        .await,
        "the demand opens an upstream stream; {}",
        upstream.seen()
    );
    assert!(
        upstream.regions("events/poll").is_empty(),
        "push mode never polls; {}",
        upstream.seen()
    );
    upstream.add("e1", "eu");
    upstream.add("e2", "us");
    assert_eq!(poll_until(&core, "eu", &eu, &["up:e1"]).await, ["up:e1"]);
    drop(state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_that_withdraws_a_type_withdraws_it_here() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core) = boot(dir.path(), &url, "poll").await;
    assert!(imported(&core).await);
    let version = core.catalog_version();
    upstream.types.lock().unwrap().clear();
    let engine = state
        .runtime
        .load()
        .federation_engine()
        .expect("a federation engine");
    engine.import_all().await;
    assert!(
        within(|| core.catalog().get(TYPE).is_none()).await,
        "a type the upstream no longer lists leaves the catalog"
    );
    assert!(core.catalog_version() > version);
}

fn source_context(log: Arc<EventLog>) -> SourceContext {
    SourceContext {
        log,
        lease: tokio::sync::watch::channel(None).0.subscribe(),
        registry: Arc::new(mcpg_plugin_host::PluginRegistry::new()),
        fetcher: None,
        max_payload_bytes: 245_760,
        inbox: None,
        core: std::sync::Weak::new(),
        usage: crate::runtime::cp_metrics::ToolCallRecorderHandle::default(),
        quota: crate::runtime::cp_quota::QuotaStatusHandle::default(),
    }
}

fn imported_type() -> Arc<EventType> {
    let federated = super::super::catalog::FederatedEventType {
        federation: "up".to_owned(),
        name: TYPE.to_owned(),
        upstream_name: "orders.created".to_owned(),
        descriptor: serde_json::from_value(json!({
            "name": "orders.created",
            "delivery": ["poll"],
        }))
        .unwrap(),
        delivery: crate::config::federation::UpstreamEventDelivery::Auto,
        sharing: crate::config::federation::UpstreamEventSharing::FanIn,
        retention: Default::default(),
    };
    let keys = keys();
    let ctx = super::super::catalog::ImportContext {
        enabled: &[crate::config::events::EventDeliveryMode::Poll],
        keys: &keys,
        callbacks: false,
    };
    let compiled =
        super::super::catalog::EventCatalog::empty().compile_federated(&[federated], &ctx);
    Arc::new(compiled.into_iter().next().expect("compiles"))
}

/// The id `subscription` gives its upstream subscription: its slot.
const SLOT: &str = "fsub_test";

fn subscription(ty: &Arc<EventType>, tx: mpsc::Sender<SourceItem>) -> UpstreamSubscription {
    UpstreamSubscription {
        ty: Arc::clone(ty),
        federation: "up".to_owned(),
        upstream_name: "orders.created".to_owned(),
        arguments: Map::new(),
        subscriber: None,
        scope: RowScope::of(None, "h1".to_owned()),
        id: SLOT.to_owned(),
        cursor: None,
        positioned_at: None,
        callback: None,
        tx,
    }
}

#[tokio::test]
async fn an_upstream_subscription_resumes_from_its_own_position() {
    let log = Arc::new(EventLog::new(Arc::new(MemoryKv::new()), None, keys()));
    let ctx = source_context(Arc::clone(&log));
    let ty = imported_type();
    let (tx, mut rx) = mpsc::channel(8);

    let mut first = subscription(&ty, tx.clone());
    assert!(first.resume(&ctx).await);
    assert_eq!(first.cursor, None, "a first run reads from now");
    assert_eq!(
        rx.try_recv().unwrap(),
        SourceItem::Position {
            slot: Some(SLOT.to_owned()),
            cursor: Value::Null
        },
        "and records that it ran, so a later start knows"
    );

    log.store_resume_position(&ty.source_key, Some(SLOT), Value::Null, None)
        .await
        .unwrap();
    let mut again = subscription(&ty, tx.clone());
    assert!(again.resume(&ctx).await);
    assert_eq!(
        rx.try_recv().unwrap(),
        SourceItem::Gap {
            reason: GapReason::SourceRestart,
            scope: RowScope::of(None, "h1".to_owned())
        },
        "a run with no cursor to resume from marks a gap for its readers"
    );

    log.store_resume_position(&ty.source_key, Some(SLOT), json!("41"), None)
        .await
        .unwrap();
    let mut resumed = subscription(&ty, tx);
    assert!(resumed.resume(&ctx).await);
    assert_eq!(resumed.cursor.as_deref(), Some("41"));
    assert!(rx.try_recv().is_err(), "a resume queues nothing");
    assert_eq!(
        log.resume_position(&ty.source_key, None).await.unwrap(),
        None,
        "each set of arguments keeps a position of its own"
    );
}

#[test]
fn upstream_errors_end_restart_or_retry_the_read() {
    let schema_changed = UpstreamError::JsonRpc {
        code: -32014,
        message: "inputSchema changed".to_owned(),
        data: Some(json!({ "feature": "inputSchema", "reason": "schema_changed" })),
    };
    assert!(matches!(Ended::of(schema_changed), Ended::SchemaChanged));
    let renumbered = UpstreamError::JsonRpc {
        code: -32026,
        message: "inputSchema changed".to_owned(),
        data: Some(json!({ "feature": "inputSchema", "reason": "schema_changed" })),
    };
    assert!(
        matches!(Ended::of(renumbered), Ended::SchemaChanged),
        "either numbering"
    );
    let rpc = |code: i64| UpstreamError::JsonRpc {
        code,
        message: "no".to_owned(),
        data: None,
    };
    assert!(matches!(
        Ended::of(rpc(-32012)),
        Ended::Terminated(EndReason::Forbidden)
    ));
    assert!(matches!(
        Ended::of(rpc(-32023)),
        Ended::Terminated(EndReason::NotFound)
    ));
    assert!(matches!(
        Ended::of(rpc(-32602)),
        Ended::Terminated(EndReason::ArgumentsRefused)
    ));
    assert!(
        matches!(Ended::of(rpc(-32013)), Ended::Refused(_)),
        "a limit passes"
    );
    assert!(matches!(
        Ended::of(UpstreamError::Transport("reset".to_owned())),
        Ended::Failed(_)
    ));

    // A 2026-07-28 server answers an error with the status its code maps
    // to; the error it carries decides, not the status.
    let with_status = |status: u16, code: i64, data: Option<Value>| UpstreamError::Http {
        status,
        error: Some(mcpg_mcp_client::wire::JsonRpcError {
            code,
            message: "no".to_owned(),
            data,
        }),
    };
    assert!(matches!(
        Ended::of(with_status(403, -32012, None)),
        Ended::Terminated(EndReason::Forbidden)
    ));
    assert!(matches!(
        Ended::of(with_status(400, -32602, None)),
        Ended::Terminated(EndReason::ArgumentsRefused)
    ));
    assert!(matches!(
        Ended::of(with_status(
            400,
            -32014,
            Some(json!({ "feature": "inputSchema", "reason": "schema_changed" }))
        )),
        Ended::SchemaChanged
    ));
    assert!(
        matches!(
            Ended::of(UpstreamError::Http {
                status: 502,
                error: None
            }),
            Ended::Failed(_)
        ),
        "a status with no JSON-RPC error is a failed read"
    );
    assert!(
        matches!(
            Ended::of(with_status(
                429,
                -32013,
                Some(json!({ "limit": "plan.rps_per_gateway", "max": 5 }))
            )),
            Ended::Failed(_)
        ),
        "the upstream's request ceiling clears within seconds: retried soon"
    );
}

#[tokio::test]
async fn a_gap_for_one_set_of_arguments_is_not_a_gap_for_another() {
    let log = EventLog::new(Arc::new(MemoryKv::new()), None, keys());
    let lease = super::super::log::WriterLease {
        fence: 1,
        expires_at_ms: u64::MAX,
    };
    let retention = crate::config::events::EventRetentionConfig::default();
    log.append_gap(
        "sk",
        GapReason::UpstreamTruncated,
        RowScope::of(Some("p".to_owned()), "a".to_owned()),
        &retention,
        lease,
    )
    .await
    .unwrap();
    let head = log.head("sk").await.unwrap().unwrap();
    assert_eq!(
        head.last_gap_seq, 0,
        "a gap of one set of readers is not every reader's"
    );
    let Some(LogEntry::Row(row)) = log.get("sk", 1).await.unwrap() else {
        panic!("a row");
    };
    assert!(row.body.is_gap_for("p", "a"));
    assert!(!row.body.is_gap_for("p", "b"), "other arguments");
    assert!(!row.body.is_gap_for("q", "a"), "another principal");
    assert!(matches!(row.body, RowBody::Gap { .. }));
}

/// A gateway on a loopback port whose `canonical_url` is that port, so an
/// upstream can deliver webhooks to it. Upstream subscriptions stop
/// `linger_ms` after their demand.
async fn boot_public(
    dir: &std::path::Path,
    url: &str,
    delivery: &str,
    linger_ms: u64,
) -> (crate::app::AppState, Arc<EventsCore>, String) {
    boot_public_planned(dir, url, delivery, linger_ms, TestQuota::default()).await
}

/// [`boot_public`] told about the plan `quota` sets.
async fn boot_public_planned(
    dir: &std::path::Path,
    url: &str,
    delivery: &str,
    linger_ms: u64,
    quota: TestQuota,
) -> (crate::app::AppState, Arc<EventsCore>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = format!("canonical_url: \"{base}\"");
    let (state, core) = boot_planned(dir, url, delivery, &server, linger_ms, quota).await;
    let router = crate::transports::http::router(state.clone(), "/health", "/mcp");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (state, core, base)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_type_reads_its_upstream_by_webhook() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core, base) = boot_public(dir.path(), &url, "auto", 1).await;
    assert!(imported(&core).await);
    let caller = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    assert!(
        within(|| upstream.callback().is_some()).await,
        "with a public address, auto subscribes by webhook; {}",
        upstream.seen()
    );
    let callback = upstream.callback().expect("a callback");
    assert!(
        callback
            .url
            .starts_with(&format!("{base}/webhooks/mcp-events/up/fsub_")),
        "{}",
        callback.url
    );
    assert_eq!(callback.region.as_deref(), Some("eu"));
    assert!(
        upstream.regions("events/poll").is_empty(),
        "{}",
        upstream.seen()
    );
    assert!(
        upstream.regions("events/stream").is_empty(),
        "{}",
        upstream.seen()
    );

    upstream.add("e1", "eu");
    upstream.add("e2", "us");
    assert_eq!(
        upstream.deliver().await,
        [200],
        "taken once durable; {}",
        upstream.seen()
    );
    assert_eq!(poll_until(&core, "eu", &eu, &["up:e1"]).await, ["up:e1"]);
    assert_eq!(
        upstream
            .deliver_envelope(&ControlEnvelope::Verification {
                challenge: "c-1".to_owned()
            })
            .await,
        [200],
        "{}",
        upstream.seen()
    );

    // No more polls: once the lease lapses, the gateway ends the upstream
    // subscription, and its route turns late deliveries away.
    reader.stop().await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while upstream.regions("events/unsubscribe").is_empty()
        && tokio::time::Instant::now() < deadline
    {
        core.owner_tick().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        upstream.regions("events/unsubscribe"),
        [Some("eu".to_owned())],
        "no demand: the upstream subscription ends; {}",
        upstream.seen()
    );
    let client = reqwest::Client::new();
    assert_eq!(
        post_signed(&client, &callback, "e3", br#"{"eventId":"e3"}"#).await,
        410,
        "a late delivery is turned away"
    );
    drop(state);
}

/// Wait until the clock is between `from_ms` and 900 ms into a second.
async fn late_in_a_second(from_ms: u64) {
    loop {
        let into = now_ms() % 1_000;
        if (from_ms..900).contains(&into) {
            return;
        }
        tokio::time::sleep(Duration::from_millis((from_ms + 1_000 - into) % 1_000)).await;
    }
}

#[tokio::test]
async fn demand_rows_on_a_whole_second_store_are_read_until_they_lapse() {
    let dir = tempfile::tempdir().unwrap();
    let kv = crate::builtins::cluster_primitives::FileKv::new(dir.path())
        .await
        .unwrap();
    let leases = super::super::poll::LeaseStore::new(kv, None, keys());
    let arguments: Map<String, Value> = json!({ "region": "eu" }).as_object().unwrap().clone();
    let identity = verified_identity("alice");
    let holder = LeaseHolder {
        principal_key: "v:alice",
        identity: &identity,
        arguments: &arguments,
    };
    let demand = Demand::of(UpstreamEventSharing::FanIn, &holder);
    let key = demand.key(&keys());
    // Each lease is written late in a second, where a whole-second store
    // loses the most of the write time and of a fractional TTL.
    for (late_ms, lease) in [
        (500, Duration::from_secs(1)),
        (600, Duration::from_millis(1_500)),
    ] {
        late_in_a_second(late_ms).await;
        let until = now_ms() + lease.as_millis() as u64;
        leases.extend_demand(TYPE, until, lease).await.unwrap();
        leases
            .extend_argument_demand(TYPE, &key, &demand, until, lease)
            .await
            .unwrap();
        loop {
            let before = now_ms();
            let type_row = leases.demand(TYPE).await.unwrap();
            let found = leases.argument_demand(TYPE, before).await.unwrap();
            if now_ms() >= until {
                break;
            }
            assert!(
                type_row.is_some(),
                "a {lease:?} lease: the type's row is gone {} ms before it lapses",
                until - before
            );
            assert!(
                found.contains_key(&key),
                "a {lease:?} lease: the arguments' row is gone {} ms before it lapses",
                until - before
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_delivery_is_checked_before_it_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let (state, core, _) = boot_public(dir.path(), &url, "webhook", 300_000).await;
    assert!(imported(&core).await);
    let caller = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    assert!(
        within(|| upstream.callback().is_some()).await,
        "the demand subscribes by webhook; {}",
        upstream.seen()
    );
    let callback = upstream.callback().expect("a callback");

    let mut forged = callback.clone();
    forged.secret = "whsec_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_owned();
    let client = reqwest::Client::new();
    assert_eq!(
        post_signed(&client, &forged, "e9", br#"{"eventId":"e9"}"#).await,
        401,
        "a delivery signed with another secret"
    );
    let mut unknown = callback;
    let (route_base, _) = unknown.url.rsplit_once('/').unwrap();
    unknown.url = format!("{route_base}/fsub_00000000000000000000000000000000");
    assert_eq!(
        post_signed(&client, &unknown, "e9", br#"{"eventId":"e9"}"#).await,
        503,
        "no route: the upstream retries"
    );

    // The upstream ends the subscription for good: its readers end there.
    let terminated = ControlEnvelope::Terminated {
        error: crate::protocol::shared::jsonrpc::JsonRpcErrorBody {
            code: -32012,
            message: "forbidden".to_owned(),
            data: None,
        },
    };
    assert_eq!(
        upstream.deliver_envelope(&terminated).await,
        [200],
        "{}",
        upstream.seen()
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    let error = loop {
        core.owner_tick().await;
        core.drain_now().await;
        match core
            .poll_events(&caller, poll_params("eu", Some(eu.clone())))
            .await
        {
            Err(error) => break error,
            Ok(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(result) => panic!("the poll never ended: {result:?}; {}", upstream.seen()),
        }
    };
    assert_eq!(error.code(), -32012);
    drop(state);
}

#[test]
fn per_principal_demand_is_keyed_by_subscriber() {
    use crate::config::federation::UpstreamEventSharing;
    let keys = keys();
    let arguments: Map<String, Value> = json!({ "region": "eu" }).as_object().unwrap().clone();
    let alice_identity = verified_identity("alice");
    let bob_identity = verified_identity("bob");
    let alice = LeaseHolder {
        principal_key: "v:alice",
        identity: &alice_identity,
        arguments: &arguments,
    };
    let bob = LeaseHolder {
        principal_key: "v:bob",
        identity: &bob_identity,
        arguments: &arguments,
    };
    let shared_a = Demand::of(UpstreamEventSharing::FanIn, &alice);
    let shared_b = Demand::of(UpstreamEventSharing::FanIn, &bob);
    assert_eq!(
        shared_a.key(&keys),
        shared_b.key(&keys),
        "fan_in: one upstream subscription for both"
    );
    assert!(shared_a.subscriber.is_none());
    let own_a = Demand::of(UpstreamEventSharing::PerPrincipal, &alice);
    let own_b = Demand::of(UpstreamEventSharing::PerPrincipal, &bob);
    assert_ne!(
        own_a.key(&keys),
        own_b.key(&keys),
        "per_principal: one each"
    );
    assert_eq!(own_a.subscriber.as_ref().unwrap().principal_key, "v:alice");

    let (tx, _rx) = mpsc::channel(1);
    let ty = imported_type();
    let fan_in =
        UpstreamSubscription::new(&ty, "up", "orders.created", &shared_a, &keys, tx.clone());
    let alices = UpstreamSubscription::new(&ty, "up", "orders.created", &own_a, &keys, tx);
    assert_eq!(fan_in.scope.audience, None, "every principal reads it");
    assert_eq!(
        alices.scope.audience.as_deref(),
        Some(audience_hash(&keys, "v:alice").as_str()),
        "only alice reads what hers reads"
    );
    assert_eq!(fan_in.scope.arguments, alices.scope.arguments);
    assert_ne!(fan_in.id, alices.id);
}

#[test]
fn the_secret_of_an_upstream_subscription_is_derived_alike_everywhere() {
    let one = keys();
    let other = keys();
    let id = one.upstream_subscription_id("up", "orders.created", None, "h");
    assert_eq!(
        id,
        other.upstream_subscription_id("up", "orders.created", None, "h")
    );
    assert!(id.starts_with("fsub_"));
    assert_ne!(
        id,
        one.upstream_subscription_id("up", "orders.created", Some("p"), "h")
    );
    assert_eq!(
        one.upstream_webhook_secret(&id).expose_secret(),
        other.upstream_webhook_secret(&id).expose_secret()
    );
    assert_ne!(
        one.upstream_webhook_secret(&id).expose_secret(),
        one.upstream_webhook_secret("fsub_other").expose_secret()
    );
}

/// The last cursor an `events/subscribe` sent the upstream.
fn last_subscribe_cursor(upstream: &Upstream) -> Option<String> {
    upstream
        .reads
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(method, _, _)| method == "events/subscribe")
        .and_then(|(_, _, cursor)| cursor.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_ingest_ends_upstream_webhook_subscriptions_and_takes_them_up_from_the_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, url) = Upstream::start().await;
    let quota = TestQuota::default();
    let (state, core, _) =
        boot_public_planned(dir.path(), &url, "webhook", 300_000, quota.clone()).await;
    assert!(imported(&core).await);
    let caller = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap()
        .cursor
        .expect("a cursor");
    let _reader = Reader::start(&core, "eu", &eu);
    core.owner_tick().await;
    assert!(
        within(|| upstream.callback().is_some()).await,
        "the demand subscribes by webhook; {}",
        upstream.seen()
    );
    let late = upstream.callback().expect("a callback");
    // The position the subscribe answered goes through the source's queue,
    // a delivered one straight to the store: the first must land first.
    let slot = late.url.rsplit('/').next().expect("an id").to_owned();
    let ty = core.catalog().get(TYPE).cloned().expect("the type");
    let stores = core.stores().expect("stores");
    let deadline = tokio::time::Instant::now() + WAIT;
    let mut stored = None;
    while stored != Some(json!("0")) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        stored = stores
            .log
            .resume_position(&ty.source_key, Some(&slot))
            .await
            .unwrap();
    }
    assert_eq!(stored, Some(json!("0")), "the subscribe answer's position");
    upstream.add("e1", "eu");
    assert_eq!(upstream.deliver().await, [200], "{}", upstream.seen());

    quota.set_events(EventsPlan {
        ingest_held: true,
        held_until: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..EventsPlan::default()
    });
    core.owner_tick().await;
    assert!(
        within(|| !upstream.regions("events/unsubscribe").is_empty()).await,
        "a hold ends the upstream subscription; {}",
        upstream.seen()
    );
    assert!(
        upstream.callbacks.lock().unwrap().is_empty(),
        "{}",
        upstream.seen()
    );
    assert_eq!(
        post_signed(&reqwest::Client::new(), &late, "e9", br#"{"eventId":"e9"}"#).await,
        410,
        "a delivery after the subscription ended: the upstream stops"
    );
    upstream.add("e2", "eu");

    let subscribes = upstream.regions("events/subscribe").len();
    quota.set_events(EventsPlan::default());
    core.poll_events(&caller, poll_params("eu", None))
        .await
        .unwrap();
    core.owner_tick().await;
    assert!(
        within(|| upstream.regions("events/subscribe").len() > subscribes).await,
        "the hold ended: the upstream subscription is taken up again; {}",
        upstream.seen()
    );
    assert_eq!(
        last_subscribe_cursor(&upstream).as_deref(),
        Some("1"),
        "from where it stopped, so the upstream replays what came meanwhile"
    );
    assert_eq!(
        upstream.deliver().await,
        [200],
        "e2 arrives after the hold; {}",
        upstream.seen()
    );
    drop(state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reader_cap_counts_the_upstream_subscriptions_of_imported_types() {
    let dir = tempfile::tempdir().unwrap();
    let (_upstream, url) = Upstream::start().await;
    let quota = TestQuota::default();
    quota.set_events(EventsPlan {
        readers_limit: Some(3),
        ..EventsPlan::default()
    });
    let (state, core) = boot_planned(dir.path(), &url, "poll", "", 300_000, quota).await;
    assert!(imported(&core).await);
    let alice = request_context(verified_identity("alice"));
    let eu = core
        .poll_events(&alice, poll_params("eu", None))
        .await
        .expect("a lease and the upstream subscription it needs: two of three")
        .cursor
        .expect("a cursor");
    let _reader = Reader::start(&core, "eu", &eu);
    let stores = core.stores().unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        core.owner_tick().await;
        let upstreams = stores.leases.count_upstreams(10).await.unwrap();
        if upstreams == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the upstream subscription is present: {upstreams} counted"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let bob = request_context(verified_identity("bob"));
    core.poll_events(&bob, poll_params("eu", None))
        .await
        .expect("the same arguments share the upstream subscription: three of three");
    let refused = core
        .poll_events(&alice, poll_params("us", None))
        .await
        .unwrap_err();
    assert_eq!(
        refused.data().unwrap()["limit"],
        "plan.event_subscriptions",
        "new arguments need a lease and an upstream subscription: {refused}"
    );
    drop(state);
}
