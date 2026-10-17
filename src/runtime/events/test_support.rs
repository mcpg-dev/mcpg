//! Fixtures shared by the events tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::{
    PluginClass, PluginManifest, PluginTier, WatchError, WatchEvent, WatchEventSink, WatchHandle,
    WatchStrategyPlugin,
};
use parking_lot::Mutex;

use super::keys::{EventsKeys, KeySource};

/// Standard base64 of the bytes 0..32, a valid synthetic session key.
pub const SESSION_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// A key set over a fixed base.
pub fn keys() -> Arc<EventsKeys> {
    Arc::new(EventsKeys::from_base(
        &[5u8; 32],
        KeySource::SyntheticSessionKey,
        "test",
    ))
}

/// A watch plugin the test fires by hand.
pub struct ScriptedWatch {
    manifest: PluginManifest,
    kind: String,
    event_source: Option<mcpg_plugin_protocol::WatchStrategyDescriptor>,
    sinks: Mutex<Vec<(String, Arc<dyn WatchEventSink>)>>,
    /// The spec of every watch started, in order.
    pub specs: Mutex<Vec<serde_json::Value>>,
    pub started: AtomicUsize,
    pub cancelled: Arc<AtomicUsize>,
    /// Every position the host acknowledged, in order.
    pub acknowledged: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl ScriptedWatch {
    pub fn new(kind: &str) -> Arc<Self> {
        Self::with(kind, None)
    }

    /// A watch plugin whose descriptor declares `source`, under its kind.
    pub fn declaring(source: mcpg_plugin_protocol::WatchStrategyDescriptor) -> Arc<Self> {
        Self::with(&source.kind.clone(), Some(source))
    }

    fn with(
        kind: &str,
        event_source: Option<mcpg_plugin_protocol::WatchStrategyDescriptor>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: format!("test.watch.{kind}"),
                version: "0.1.0".into(),
                name: "scripted watch".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".to_owned(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            kind: kind.to_owned(),
            event_source,
            sinks: Mutex::new(Vec::new()),
            specs: Mutex::new(Vec::new()),
            started: AtomicUsize::new(0),
            cancelled: Arc::new(AtomicUsize::new(0)),
            acknowledged: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Report one change on every watcher started on `uri`.
    pub async fn fire(&self, uri: &str) {
        self.emit(uri, WatchEvent::default()).await;
    }

    /// Report `event` on every watcher started on `uri`.
    pub async fn emit(&self, uri: &str, event: WatchEvent) {
        let sinks: Vec<_> = self
            .sinks
            .lock()
            .iter()
            .filter(|(u, _)| u == uri)
            .map(|(_, s)| Arc::clone(s))
            .collect();
        for sink in sinks {
            sink.emit(event.clone()).await;
        }
    }

    /// URIs watchers were started on.
    pub fn uris(&self) -> Vec<String> {
        self.sinks.lock().iter().map(|(u, _)| u.clone()).collect()
    }

    /// A registry holding `plugins`.
    pub fn registry(plugins: &[Arc<Self>]) -> Arc<mcpg_plugin_host::PluginRegistry> {
        let mut registry = mcpg_plugin_host::PluginRegistry::new();
        for plugin in plugins {
            registry
                .register_watch_strategy(
                    Arc::clone(plugin) as Arc<dyn WatchStrategyPlugin>,
                    PluginTier::Native,
                )
                .expect("register watch strategy");
        }
        Arc::new(registry)
    }
}

struct CountingHandle {
    cancelled: Arc<AtomicUsize>,
    acknowledged: Arc<Mutex<Vec<serde_json::Value>>>,
}

#[async_trait]
impl WatchHandle for CountingHandle {
    async fn cancel(&self) {
        self.cancelled.fetch_add(1, Ordering::SeqCst);
    }

    async fn acknowledge(&self, position: &serde_json::Value) {
        self.acknowledged.lock().push(position.clone());
    }
}

#[async_trait]
impl WatchStrategyPlugin for ScriptedWatch {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    fn event_source(&self) -> Option<mcpg_plugin_protocol::WatchStrategyDescriptor> {
        self.event_source.clone()
    }

    async fn watch(
        &self,
        uri: &str,
        spec: &serde_json::Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.specs.lock().push(spec.clone());
        self.sinks.lock().push((uri.to_owned(), sink));
        Ok(Box::new(CountingHandle {
            cancelled: Arc::clone(&self.cancelled),
            acknowledged: Arc::clone(&self.acknowledged),
        }))
    }
}

/// Id of [`WrapTransform`].
pub const WRAP_TRANSFORM: &str = "test.transform.wrap";

/// What a transform call saw: surface, tool name, config.
pub type TransformCalls = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

/// A transform plugin that wraps its input as `{"wrapped": …}`, or fails
/// when the expression is `fail`, and records every call.
pub struct WrapTransform {
    manifest: PluginManifest,
    calls: TransformCalls,
}

#[async_trait]
impl mcpg_plugin_protocol::TransformPlugin for WrapTransform {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn transform_arguments(
        &self,
        _ctx: &mcpg_plugin_protocol::PluginContext,
        _arguments: &serde_json::Value,
        _config: &serde_json::Value,
    ) -> mcpg_plugin_protocol::TransformResult {
        mcpg_plugin_protocol::TransformResult::Unchanged
    }

    async fn transform_result(
        &self,
        ctx: &mcpg_plugin_protocol::PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> mcpg_plugin_protocol::TransformResult {
        self.calls
            .lock()
            .push((ctx.surface.clone(), ctx.tool_name.clone(), config.clone()));
        if config["expression"] == "fail" {
            return mcpg_plugin_protocol::TransformResult::Error {
                message: "asked to fail".to_owned(),
            };
        }
        mcpg_plugin_protocol::TransformResult::Modified {
            value: serde_json::json!({ "wrapped": result }),
        }
    }
}

/// A registry holding [`WrapTransform`], and the calls it records.
pub fn transform_registry() -> (Arc<mcpg_plugin_host::PluginRegistry>, TransformCalls) {
    let calls = TransformCalls::default();
    let mut manifest = ScriptedWatch::new("unused").manifest.clone();
    manifest.id = WRAP_TRANSFORM.to_owned();
    manifest.plugin_class = PluginClass::Transform;
    let mut registry = mcpg_plugin_host::PluginRegistry::new();
    registry
        .register_transform(
            Box::new(WrapTransform {
                manifest,
                calls: Arc::clone(&calls),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .expect("register transform");
    (Arc::new(registry), calls)
}

/// Resolves every host to loopback.
pub struct Loopback;

impl mcpg_safe_egress::Resolve for Loopback {
    fn resolve<'a>(&'a self, _host: &'a str) -> mcpg_safe_egress::ResolveFuture<'a> {
        Box::pin(async { Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])]) })
    }
}

/// An outbound client that reaches [`Receiver`]s over loopback `http`.
pub fn loopback_egress() -> mcpg_safe_egress::SafeEgress {
    let factory = super::delivery::loopback_factory(Arc::new(Loopback));
    factory(mcpg_safe_egress::EgressPolicy {
        attempt_timeout: std::time::Duration::from_secs(2),
        ..mcpg_safe_egress::EgressPolicy::default()
    })
    .expect("loopback egress")
}

/// One request a [`Receiver`] took.
#[derive(Debug, Clone)]
pub struct Received {
    pub method: axum::http::Method,
    pub path: String,
    pub headers: axum::http::HeaderMap,
    pub body: bytes::Bytes,
}

impl Received {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

/// How a [`Receiver`] answers: status and body for each request.
pub type Reply = Arc<dyn Fn(&Received) -> (u16, Vec<u8>) + Send + Sync>;

/// Answers a challenge with its echo and anything else with `200`.
pub fn echo_reply() -> Reply {
    Arc::new(|request: &Received| {
        let body = request.json();
        if body["type"] == "verification" {
            let echo = serde_json::json!({ "challenge": body["challenge"] });
            (200, serde_json::to_vec(&echo).unwrap())
        } else {
            (200, Vec::new())
        }
    })
}

/// An in-process webhook receiver on loopback, under a host name of its own.
/// A request for another host is one meant for whatever had its port
/// before: it is answered `421` and not taken.
pub struct Receiver {
    pub port: u16,
    host: String,
    requests: Arc<Mutex<Vec<Received>>>,
    reply: Arc<Mutex<Reply>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Receiver {
    /// A receiver answering with `reply`.
    pub async fn start(reply: Reply) -> Self {
        let requests: Arc<Mutex<Vec<Received>>> = Arc::default();
        let reply = Arc::new(Mutex::new(reply));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a receiver");
        let port = listener.local_addr().expect("receiver address").port();
        let host = format!("{}.receiver.test", uuid::Uuid::new_v4().simple());
        let (seen, answer) = (Arc::clone(&requests), Arc::clone(&reply));
        let own = host.clone();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method,
                  uri: axum::http::Uri,
                  headers: axum::http::HeaderMap,
                  body: bytes::Bytes| {
                let (seen, answer) = (Arc::clone(&seen), Arc::clone(&answer));
                let addressed = headers
                    .get(axum::http::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(':').next())
                    == Some(own.as_str());
                async move {
                    if !addressed {
                        return (axum::http::StatusCode::MISDIRECTED_REQUEST, Vec::new());
                    }
                    let request = Received {
                        method,
                        path: uri.path().to_owned(),
                        headers,
                        body,
                    };
                    let reply = Arc::clone(&*answer.lock());
                    let (status, body) = reply(&request);
                    seen.lock().push(request);
                    (
                        axum::http::StatusCode::from_u16(status).expect("a status"),
                        body,
                    )
                }
            },
        );
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            port,
            host,
            requests,
            reply,
            task,
        }
    }

    /// The callback URL of path `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", self.host, self.port)
    }

    pub fn set_reply(&self, reply: Reply) {
        *self.reply.lock() = reply;
    }

    pub fn requests(&self) -> Vec<Received> {
        self.requests.lock().clone()
    }

    /// The requests that carried events, not control envelopes.
    pub fn events(&self) -> Vec<Received> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == axum::http::Method::POST && r.json().get("type").is_none())
            .collect()
    }

    /// The control envelopes of `kind`.
    pub fn envelopes(&self, kind: &str) -> Vec<Received> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == axum::http::Method::POST && r.json()["type"] == kind)
            .collect()
    }
}

/// A verified identity of subject `subject`.
pub fn verified_identity(subject: &str) -> crate::runtime::RequestIdentity {
    crate::runtime::RequestIdentity::Verified {
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

/// A request context for `identity`.
pub fn request_context(
    identity: crate::runtime::RequestIdentity,
) -> crate::runtime::RequestContext {
    crate::runtime::RequestContext::new(
        crate::runtime::GatewayRequestId::new(),
        None,
        None,
        None,
        identity,
        crate::runtime::TransportKind::Http,
    )
}

/// A `whsec_` secret of 32 bytes of `byte`.
pub fn whsec(byte: u8) -> String {
    use base64::Engine as _;
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

/// One webhook event type over an unsigned inbound route `orders`, with
/// a `region` argument the `match` filters on.
pub const ORDERS_TYPE: &str = r#"      - name: orders.created
        input_schema:
          type: object
          properties: { region: { type: string } }
          additionalProperties: false
        match: '!has(arguments.region) || arguments.region == event.data.region'
        source: { inbound: { source_id: orders, allow_unsigned: true, event_id: /id } }"#;

/// A gateway with MCP Events on over a file store, whose webhook client
/// reaches an in-process receiver. It stands in for an attached control
/// plane: `quota` sets the plan it is told about, `usage` keeps what it
/// meters. No plan is set until a test sets one.
pub struct WebhookHarness {
    pub dir: tempfile::TempDir,
    pub state: crate::app::AppState,
    pub core: Arc<super::EventsCore>,
    pub receiver: Receiver,
    pub yaml: String,
    pub quota: crate::runtime::cp_quota::TestQuota,
    pub usage: crate::runtime::cp_metrics::TestRecorder,
}

impl WebhookHarness {
    /// Boot with `events_extra` under `mcp.configurations.events` (indented
    /// six spaces) and `types` under `mcp.capabilities.events`.
    pub async fn start(events_extra: &str, types: &str) -> Self {
        let dir = tempfile::tempdir().expect("a store directory");
        Self::start_in(dir, "", events_extra, types).await
    }

    /// [`Self::start`] over an existing store directory, with `prefix` as
    /// more top-level config.
    pub async fn start_in(
        dir: tempfile::TempDir,
        prefix: &str,
        events_extra: &str,
        types: &str,
    ) -> Self {
        let yaml = format!(
            r#"
observability: {{ logs: {{ enabled: false }} }}
{prefix}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events:
      enabled: true
      store: {{ kind: file, dir: "{}" }}
{events_extra}
  capabilities:
    events:
{types}
"#,
            dir.path().display()
        );
        let config = crate::config::AppConfig::load_from_yaml_str(&yaml).expect("config parses");
        let quota = crate::runtime::cp_quota::TestQuota::default();
        let usage = crate::runtime::cp_metrics::TestRecorder::default();
        let (wired_quota, wired_usage) = (quota.clone(), usage.clone());
        let state = crate::app::build_from_config_adjusted(config, move |runtime| {
            runtime.set_cp_quota_status_provider(Arc::new(wired_quota));
            runtime.set_tool_call_recorder(Arc::new(wired_usage));
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
        core.set_egress_factory(super::delivery::loopback_factory(Arc::new(Loopback)));
        crate::app::reload_config_from_yaml(&state, &yaml)
            .await
            .expect("reload with the loopback client");
        core.owner_tick().await;
        let receiver = Receiver::start(echo_reply()).await;
        Self {
            dir,
            state,
            core,
            receiver,
            yaml,
            quota,
            usage,
        }
    }

    /// Reload with the same config.
    pub async fn reload(&self) {
        crate::app::reload_config_from_yaml(&self.state, &self.yaml)
            .await
            .expect("reload");
    }

    /// Subscribe params for `orders.created` to `path` on the receiver.
    pub fn params(
        &self,
        path: &str,
        arguments: serde_json::Value,
        secret: u8,
    ) -> crate::protocol::v_2026_07_28::extensions::events::wire::SubscribeEventsParams {
        crate::protocol::v_2026_07_28::extensions::events::wire::SubscribeEventsParams::from_value_redacted(
            serde_json::json!({
                "name": "orders.created",
                "arguments": arguments,
                "delivery": { "mode": "webhook", "url": self.receiver.url(path), "secret": whsec(secret) },
            }),
        )
        .expect("subscribe params")
    }

    /// Report one `orders.created` occurrence through the inbound route
    /// and append it to the log.
    pub async fn fire(&self, id: &str, region: &str) {
        let body = serde_json::json!({ "id": id, "region": region });
        let reply = self
            .core
            .receive_inbound(
                "orders",
                &axum::http::HeaderMap::new(),
                serde_json::to_vec(&body).unwrap().as_slice(),
            )
            .await;
        assert_eq!(reply, super::InboundReply::Accepted);
        self.core.drain_now().await;
    }

    /// Run the dispatcher until nothing is in flight.
    pub async fn deliver(&self) {
        for _ in 0..4 {
            self.core.dispatch_tick().await;
            self.core.dispatch_settle().await;
        }
    }
}

/// Poll `check` until it holds or `limit` passes.
pub async fn eventually_within<F: FnMut() -> bool>(
    limit: std::time::Duration,
    mut check: F,
) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    check()
}

/// Poll `check` until it holds or two seconds pass.
pub async fn eventually<F: FnMut() -> bool>(mut check: F) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    check()
}

/// [`eventually`] for a check that awaits.
pub async fn eventually_async<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    check().await
}
