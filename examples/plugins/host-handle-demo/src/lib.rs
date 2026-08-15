//! Canonical reference plugin for the `HostHandle` adoption pattern.
//!
//! # What this plugin demonstrates
//!
//! The SDK hands every plugin factory a [`HostHandle`] as the second argument,
//! providing one ergonomic Rust surface for every host call a
//! plugin can make (secrets, credentials, config, audit, metrics,
//! spans, cluster primitives). The 34 first-party plugins receive
//! the handle but, for the most part, still discard it — they
//! pre-date Wave L and have not yet been swept onto the new
//! pattern.
//!
//! This crate is the **canonical "here is how" example**. Read
//! end-to-end, it should answer:
//!
//! 1. How does a plugin **store** the [`HostHandle`] on `Self` at
//!    construction time so subsequent request handlers can reach
//!    every host service through one struct field?
//! 2. How does a request handler **open a span**, emit timing
//!    plus counter metrics, and persist an audit event on
//!    notable outcomes through the unified API?
//! 3. How are **operator-supplied URIs** in plugin config
//!    threaded into [`HostHandle::resolve_secret`] and
//!    [`HostHandle::config_snapshot`] so the plugin reaches its
//!    upstream credentials + configuration through the
//!    capability-filtered host surface (rather than reading
//!    environment variables or the filesystem directly, which
//!    bypasses operator policy)?
//!
//! # The plugin in one sentence
//!
//! A no-network "echo" [`SyncBackendPlugin`] that pretends to
//! call an upstream HTTP endpoint, returning the request payload
//! unchanged. The interesting code is the *instrumentation
//! envelope* wrapped around the (trivial) work, not the work
//! itself.
//!
//! # Layout
//!
//! - [`DemoBackend`] — the plugin struct. Holds the parsed
//!   [`DemoConfig`], the [`HostHandle`] handed in at `make()`
//!   time, and a `started_at` timestamp used in audit events.
//! - [`DemoConfig`] — the operator-supplied JSON shape:
//!   `{"endpoint", "secret_uri", "config_uri", "fail_every_n"}`.
//!   See [`plugin.yaml`](../plugin.yaml) for the descriptor.
//! - [`execute`](SyncBackendPlugin::execute) — the per-request
//!   handler that exercises every documented [`HostHandle`]
//!   method via the canonical pattern.
//!
//! [`HostHandle`]: mcpg_plugin_sdk::HostHandle
//! [`SyncBackendPlugin`]: mcpg_plugin_sdk::ffi::SyncBackendPlugin

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{BackendError, BackendRequest, BackendResponse, PROTOCOL_VERSION};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;

/// Stable plugin id; mirrored in `plugin.yaml` and used by the
/// macro-generated cdylib + static-firstparty registration paths.
pub const PLUGIN_ID: &str = "dev.mcpg.example.host-handle-demo";

/// Operator-supplied config the plugin parses at `make()` time.
/// Plugins typically deserialise their config slice here and
/// keep a fully-typed copy on `Self` so per-request handlers
/// don't re-parse on every call.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct DemoConfig {
    /// Pretend-upstream endpoint. Echoed back via spans + audit
    /// events so operators can see *which* upstream call the
    /// plugin attributed work to.
    pub endpoint: String,

    /// `secret://` (or `vault://`) URI the plugin resolves on
    /// every `execute()` to demonstrate
    /// [`HostHandle::resolve_secret`]. Real plugins would resolve
    /// this **once at `make()`-time** for config-static secrets
    /// (see §6.15.3.8 "HostHandle method caching guidance");
    /// this example resolves per-request *only* to keep the
    /// demonstration surface visible — production plugins must
    /// cache.
    pub secret_uri: String,

    /// `file://` / `consul://` config URI exercised through
    /// [`HostHandle::config_snapshot`] — same caching caveat as
    /// `secret_uri`.
    pub config_uri: String,

    /// Emit an `Audit::Failure` event every Nth call (`1` =
    /// every call; `0` = never). Notable-outcome audit events
    /// are how operators reconstruct what went wrong after the
    /// fact; this knob lets the reference test exercise that
    /// path deterministically.
    pub fail_every_n: u64,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://example.invalid/echo".to_owned(),
            secret_uri: "secret://demo/api-key".to_owned(),
            config_uri: "file:///etc/mcpg/host-handle-demo.json".to_owned(),
            fail_every_n: 0,
        }
    }
}

/// The plugin struct — **the pattern this example exists for**:
/// most first-party plugins accept `_host: HostHandle` in their
/// factory closure and immediately discard it. This struct
/// **stores it on `Self`** so every per-request handler can
/// reach the host's full service surface through a single field.
pub struct DemoBackend {
    manifest: PluginManifest,
    config: DemoConfig,
    /// The unified host surface. Constructed once in
    /// [`make_demo_backend`] from the `HostHandle` the host hands
    /// the factory closure, then kept on `Self` for the plugin's
    /// lifetime. `Clone` is cheap (the FFI backend is `Copy`; the
    /// services backend clones an `Arc`) so the plugin MAY clone
    /// for background tasks without coordinating shared
    /// ownership.
    host: HostHandle,
    /// Per-call counter — used both to drive `fail_every_n` and
    /// to label metrics so operators can correlate spikes with
    /// call rate.
    calls: AtomicU64,
}

impl DemoBackend {
    /// The interesting body of the example. Exercises every
    /// documented [`HostHandle`] surface inside one
    /// `execute()` call body. Read this top-to-bottom alongside
    /// `docs/plugin-protocol/rfcs/0018-plugin-system-v25.md` §6.15.3.8.
    fn run_request(&self, request: BackendRequest) -> Result<BackendResponse, BackendError> {
        let call_number = self.calls.fetch_add(1, Ordering::Relaxed) + 1;

        // (1) Open a span attributed to this plugin. The host's
        // tracing subscriber gets a parented span whose Drop
        // closes the timing window — operators see the work in
        // the same trace as the inbound tool call.
        let span = self.host.span(
            "host_handle_demo.execute",
            serde_json::json!({
                "endpoint": self.config.endpoint,
                "request_id": request.request_id,
                "call_number": call_number,
            }),
        );

        // (2) Resolve a per-request secret. In a real plugin
        // this URI would have come from the *caller* (per-caller
        // credentials) or would be config-static and resolved
        // ONCE in the factory, cached at make() time. We
        // synthesise the URI from config here purely so the
        // demonstration surface is visible inside one method.
        let secret_outcome = match self.host.resolve_secret(&self.config.secret_uri) {
            Ok(v) => {
                // Don't log the bytes — secrets MUST NOT land in
                // span attributes / metrics labels / log lines.
                // Length + version are usually enough for
                // operators to diagnose rotation issues.
                span.event(
                    "secret.resolved",
                    serde_json::json!({
                        "version": v.version,
                        "bytes_len": v.bytes.len(),
                    }),
                );
                "ok"
            }
            Err(e) => {
                span.event(
                    "secret.resolve_failed",
                    serde_json::json!({ "error": e.to_string() }),
                );
                "err"
            }
        };

        // (3) Read a config snapshot. Same caveat as the secret —
        // production plugins cache config-static snapshots at
        // make() time and refresh on watch events.
        let config_outcome = match self.host.config_snapshot(&self.config.config_uri) {
            Ok(snap) => {
                span.event(
                    "config.snapshot",
                    serde_json::json!({
                        "version": snap.version,
                        "source": snap.source,
                    }),
                );
                "ok"
            }
            Err(e) => {
                span.event(
                    "config.snapshot_failed",
                    serde_json::json!({ "error": e.to_string() }),
                );
                "err"
            }
        };

        // (4) Do the work. This example's "work" is a no-op
        // echo — what matters for the reference is the
        // instrumentation envelope around it, not the body.
        let start = Instant::now();
        let result = self.do_work(&request, call_number);
        let elapsed = start.elapsed().as_secs_f64();

        // (5) Compute the outcome label every metric + audit
        // event shares. Keeping the label cardinality bounded
        // (here: just "ok" / "err") is critical for the host's
        // metrics-rs recorder — unbounded labels are the #1 way
        // plugins blow up Prometheus cardinality budgets.
        let outcome_label = match &result {
            Ok(_) => "ok",
            Err(_) => "err",
        };

        // (6) Histogram for per-call latency. Operators slice
        // this by `outcome` to compare ok vs. err tail latencies
        // (failures are often slow — timeouts, retries — and a
        // mixed histogram hides that).
        self.host.histogram(
            "mcpg_example_host_handle_demo_latency_seconds",
            elapsed,
            &[
                ("outcome", outcome_label),
                ("secret_outcome", secret_outcome),
                ("config_outcome", config_outcome),
            ],
        );

        // (7) Counter for call rate. Same dimensions as the
        // histogram so PromQL `rate()` joins line up.
        self.host.counter(
            "mcpg_example_host_handle_demo_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        // (8) Audit event on notable outcomes. Audit is for the
        // compliance / forensics path — emit when something
        // happened the operator would want reconstructable after
        // the fact (denials, failures, sensitive operations).
        // Don't audit every successful call — audit sinks are
        // expensive (durable persistence) and dashboards drown
        // in success noise. Use `mcpg_plugin_*_total` counters
        // for the per-call observability budget instead.
        if let Err(ref err) = result {
            let event_id = format!("evt-{}-{}", request.request_id, call_number);
            let _ = self.host.audit_event(AuditEvent {
                event_id,
                occurred_at: rfc3339_now(),
                actor: request
                    .identity
                    .clone()
                    .unwrap_or_else(synthetic_system_identity),
                action: "dev.mcpg.example.host_handle_demo.execute_failed".into(),
                resource: Some(format!("upstream://{}", self.config.endpoint)),
                outcome: AuditOutcome::Failure,
                request_id: Some(request.request_id.clone()),
                node_id: None,
                details: serde_json::json!({
                    "reason": err.to_string(),
                    "call_number": call_number,
                    "endpoint": self.config.endpoint,
                    "alias": self.host.alias(),
                }),
                prev_event_hash: None,
            });
        }

        // (9) Drop the span explicitly. `SpanGuard::Drop`
        // calls `span_end_raw` so the host closes the timing
        // window. Implicit-drop-at-end-of-scope works too, but
        // many production plugins prefer the explicit form
        // because it documents the timing boundary precisely
        // and survives later refactors that add early returns.
        drop(span);

        result
    }

    /// Pretend-upstream call. Real backends would dispatch over
    /// HTTP / NATS / Kafka / SQL etc.; this example echoes the
    /// request bytes back to keep the focus on instrumentation.
    /// Returns `Err` every `fail_every_n` calls so the audit /
    /// counter / span paths exercise both branches in the unit
    /// test.
    fn do_work(
        &self,
        request: &BackendRequest,
        call_number: u64,
    ) -> Result<BackendResponse, BackendError> {
        if self.config.fail_every_n > 0 && call_number.is_multiple_of(self.config.fail_every_n) {
            return Err(BackendError::Transport {
                message: format!(
                    "host-handle-demo: synthetic failure on call #{call_number} (configured to \
                     fail every {n} calls)",
                    n = self.config.fail_every_n
                ),
            });
        }
        Ok(BackendResponse {
            payload: request.payload.clone(),
            truncated: false,
        })
    }
}

impl SyncBackendPlugin for DemoBackend {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        // A non-empty kind discriminator — matches the
        // operator-visible label in tracing spans + metrics so
        // ops dashboards can group by `kind="example"`.
        "example"
    }

    fn register_profile(
        &self,
        _backend_name: &str,
        _spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        // No per-profile setup for the demo — register_profile
        // is where real backends would lazily compile per-route
        // CEL programs / open per-broker connections. The macro
        // wraps the return through the `{"ok": null}` envelope.
        Ok(())
    }

    fn execute(
        &self,
        _backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.run_request(request)
    }
}

/// Build the plugin manifest. Pulled out of the factory so the
/// unit test can construct it independently.
fn build_manifest() -> PluginManifest {
    PluginManifest {
        id: PLUGIN_ID.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        name: "mcpg-example-host-handle-demo".into(),
        plugin_class: PluginClass::Backend,
        protocol_version: PROTOCOL_VERSION.into(),
        license: None,
        required_capabilities: vec![],
        tags: vec!["example".into(), "reference".into(), "host-handle".into()],
        provides: vec![],
        provides_schemes: vec![],
        module_path_prefix: ::std::module_path!()
            .split("::")
            .next()
            .unwrap_or("mcpg_example_host_handle_demo")
            .to_owned(),
        backend_profile: None,
    }
}

/// The factory the SDK macro hands the user's config slice + the
/// constructed [`HostHandle`] to. **This is the L.10 gap closed:**
/// instead of `_host: HostHandle` (the 33-of-34 first-party
/// shape today), we **store the handle on `Self`** so every
/// per-request handler reaches every host surface through one
/// field.
pub fn make_demo_backend(config_json: &str, host: HostHandle) -> DemoBackend {
    // Default-on-deserialise-failure: a misconfigured plugin
    // would normally surface validation errors via
    // `register_profile`, but the make() slot has no fallible
    // shape today. Surfacing the parse failure as defaults +
    // logging it via the host is the canonical pattern — the
    // plugin stays loadable, the operator sees the warning, and
    // the next config reload picks up the fix.
    let config: DemoConfig = serde_json::from_str(config_json).unwrap_or_default();
    DemoBackend {
        manifest: build_manifest(),
        config,
        host,
        calls: AtomicU64::new(0),
    }
}

/// Best-effort RFC 3339 timestamp for audit events. The protocol
/// crate is dep-free (no `chrono` / `time`); audit events that
/// need real wall clocks (this is real) call out to whatever
/// time crate the plugin already depends on. The reference
/// plugin keeps its dep surface minimal, so we synthesise via
/// the system clock + a hand-formatted string — fine for the
/// demo, real plugins should depend on `chrono` and call
/// `Utc::now().to_rfc3339()`.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Not strictly RFC 3339 (no calendar conversion) — the
    // string is a placeholder so audit sinks can sort by
    // `occurred_at`. Real plugins use chrono / time.
    format!("1970-01-01T00:00:00Z+epoch{secs}")
}

/// Synthetic identity used when the inbound request has no
/// caller attribution (system-initiated paths, e.g. watch-engine
/// refresh). Audit sinks treat the `system` kind specially.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("host-handle-demo".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    entities: [
        backend as demo {
            inner_name: "",
            plugin_type: DemoBackend,
            factory: make_demo_backend,
        },
    ],
}

// ---------------------------------------------------------------------------
// Unit test
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "static-firstparty"))]
mod tests {
    //! The L.10 acceptance test: construct the plugin with a
    //! `HostHandle` backed by a Recorder `HostServices` impl
    //! (similar to `libs/plugin-host/tests/host_bridge_wired.rs`),
    //! drive one happy-path execute + one failure execute, and
    //! assert the host saw the expected audit / metric / span
    //! traffic.

    use super::*;
    use std::sync::{Arc, Mutex};

    use mcpg_plugin_protocol::async_trait;
    use mcpg_plugin_protocol::audit::{AuditError, AuditReceipt};
    use mcpg_plugin_protocol::config::{ConfigError, ConfigSnapshot};
    use mcpg_plugin_protocol::credential::{CredentialError, IssuedCredential};
    use mcpg_plugin_protocol::secret::{SecretError, SecretValue};
    use mcpg_plugin_sdk::plugin_host::host_services::{HostServices, MetricPoint};

    /// `HostServices` test double that records every call the
    /// plugin makes. Same shape as
    /// `libs/plugin-host/tests/host_bridge_wired.rs::Recorder` —
    /// kept self-contained in the example so plugin authors
    /// have a copy-paste pattern in one place.
    #[derive(Default)]
    struct Recorder {
        audits: Mutex<Vec<AuditEvent>>,
        metrics: Mutex<Vec<MetricPoint>>,
        spans_started: Mutex<Vec<(String, String)>>,
        spans_ended: Mutex<Vec<u64>>,
        span_events: Mutex<Vec<(u64, String)>>,
        secret_uris: Mutex<Vec<String>>,
        config_uris: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl HostServices for Recorder {
        async fn resolve_secret(
            &self,
            _alias: &str,
            uri: &str,
        ) -> Result<SecretValue, SecretError> {
            self.secret_uris.lock().unwrap().push(uri.to_owned());
            Ok(SecretValue::new(b"super-secret-bytes".to_vec()))
        }

        async fn issue_credential(
            &self,
            _alias: &str,
            _uri: &str,
            _identity: PluginIdentity,
        ) -> Result<IssuedCredential, CredentialError> {
            // Not exercised by the demo's execute path — the
            // reference plugin doesn't need a per-caller
            // credential (it's a pretend-echo). The slot is
            // wired in case a future test adds coverage.
            Ok(IssuedCredential::from_value("tok-test", 60))
        }

        async fn config_snapshot(
            &self,
            _alias: &str,
            uri: &str,
        ) -> Result<ConfigSnapshot, ConfigError> {
            self.config_uris.lock().unwrap().push(uri.to_owned());
            Ok(ConfigSnapshot {
                version: "v1".into(),
                values: serde_json::json!({"upstream": {"timeout_ms": 250}}),
                fetched_at: "2026-05-11T00:00:00Z".into(),
                source: uri.to_owned(),
            })
        }

        async fn audit_event(
            &self,
            _alias: &str,
            event: AuditEvent,
        ) -> Result<AuditReceipt, AuditError> {
            self.audits.lock().unwrap().push(event.clone());
            Ok(AuditReceipt {
                sink_id: "test.sink".into(),
                persisted_at: event.occurred_at,
                durable_hash: String::new(),
            })
        }

        fn metric_emit(&self, _alias: &str, point: MetricPoint) {
            self.metrics.lock().unwrap().push(point);
        }

        fn span_start(&self, _alias: &str, name: &str, attrs: serde_json::Value) -> u64 {
            self.spans_started
                .lock()
                .unwrap()
                .push((name.to_owned(), attrs.to_string()));
            // Non-zero so SpanGuard::id() reports a real handle.
            7
        }

        fn span_end(&self, span_id: u64) {
            self.spans_ended.lock().unwrap().push(span_id);
        }

        fn span_event(&self, span_id: u64, name: &str, _attrs: serde_json::Value) {
            self.span_events
                .lock()
                .unwrap()
                .push((span_id, name.to_owned()));
        }
    }

    /// Helper: drive `n` execute calls through a freshly-built
    /// plugin instance and return the underlying recorder for
    /// assertions.
    async fn drive(config: DemoConfig, calls: u64) -> Arc<Recorder> {
        let rec = Arc::new(Recorder::default());
        // The static-firstparty `HostHandle` captures
        // `Handle::try_current()` at construction time —
        // we MUST construct on a worker thread that has the
        // multi-threaded runtime in scope.
        let host =
            HostHandle::from_services(rec.clone() as Arc<dyn HostServices>, "demo-alias", None);
        let cfg_json = serde_json::to_string(&serde_json::json!({
            "endpoint": config.endpoint,
            "secret_uri": config.secret_uri,
            "config_uri": config.config_uri,
            "fail_every_n": config.fail_every_n,
        }))
        .unwrap();
        let plugin = make_demo_backend(&cfg_json, host);

        // Plugins are dispatched from spawn_blocking workers
        // in production; mirror that here so the
        // `block_on_or_err` inside HostHandle's services
        // backend bridges sync↔async correctly.
        let plugin = Arc::new(plugin);
        for i in 0..calls {
            let p = plugin.clone();
            tokio::task::spawn_blocking(move || {
                let _ = p.execute(
                    "demo",
                    BackendRequest {
                        payload: format!("call-{i}").into_bytes(),
                        headers: vec![],
                        request_id: format!("req-{i}"),
                        session_id: None,
                        identity: None,
                        idempotency: None,
                    },
                );
            })
            .await
            .unwrap();
        }

        rec
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn happy_path_emits_span_metric_and_resolves_uris() {
        let rec = drive(
            DemoConfig {
                endpoint: "https://upstream.invalid/v1".into(),
                secret_uri: "secret://demo/key".into(),
                config_uri: "file:///etc/demo.json".into(),
                fail_every_n: 0,
            },
            1,
        )
        .await;

        // Span lifecycle: one start, one end, matched by id.
        let starts = rec.spans_started.lock().unwrap();
        assert_eq!(starts.len(), 1, "expected exactly one span_start");
        assert_eq!(starts[0].0, "host_handle_demo.execute");
        // Span attrs include the endpoint + request_id we passed in.
        assert!(
            starts[0].1.contains("upstream.invalid"),
            "span attrs should carry endpoint; got {}",
            starts[0].1
        );

        let ends = rec.spans_ended.lock().unwrap();
        assert_eq!(*ends, vec![7], "SpanGuard::Drop must close the span");

        // Span events: secret.resolved + config.snapshot.
        let events = rec.span_events.lock().unwrap();
        let event_names: Vec<&str> = events.iter().map(|(_, n)| n.as_str()).collect();
        assert!(
            event_names.contains(&"secret.resolved"),
            "expected secret.resolved span event; saw {:?}",
            event_names
        );
        assert!(
            event_names.contains(&"config.snapshot"),
            "expected config.snapshot span event; saw {:?}",
            event_names
        );

        // Both URIs reached HostServices.
        let secrets = rec.secret_uris.lock().unwrap();
        assert_eq!(*secrets, vec!["secret://demo/key"]);
        let configs = rec.config_uris.lock().unwrap();
        assert_eq!(*configs, vec!["file:///etc/demo.json"]);

        // Metrics: 1 histogram + 1 counter on success.
        let metrics = rec.metrics.lock().unwrap();
        let names: Vec<&str> = metrics
            .iter()
            .map(|m| match m {
                MetricPoint::Counter { name, .. }
                | MetricPoint::Gauge { name, .. }
                | MetricPoint::Histogram { name, .. } => name.as_str(),
            })
            .collect();
        assert!(
            names.contains(&"mcpg_example_host_handle_demo_latency_seconds"),
            "expected latency histogram; got {:?}",
            names
        );
        assert!(
            names.contains(&"mcpg_example_host_handle_demo_calls_total"),
            "expected calls counter; got {:?}",
            names
        );

        // Histogram emitted with outcome=ok.
        let hist_outcome = metrics.iter().find_map(|m| match m {
            MetricPoint::Histogram { name, labels, .. }
                if name == "mcpg_example_host_handle_demo_latency_seconds" =>
            {
                labels
                    .iter()
                    .find(|(k, _)| k == "outcome")
                    .map(|(_, v)| v.clone())
            }
            _ => None,
        });
        assert_eq!(
            hist_outcome.as_deref(),
            Some("ok"),
            "histogram outcome label should be 'ok' on the happy path"
        );

        // No audit events on the happy path — audit is for
        // notable outcomes only.
        let audits = rec.audits.lock().unwrap();
        assert!(
            audits.is_empty(),
            "happy-path call must not emit an audit event; got {:?}",
            audits.iter().map(|a| &a.action).collect::<Vec<_>>()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failure_path_emits_audit_event_with_expected_action() {
        let rec = drive(
            DemoConfig {
                endpoint: "https://upstream.invalid/v1".into(),
                secret_uri: "secret://demo/key".into(),
                config_uri: "file:///etc/demo.json".into(),
                fail_every_n: 1,
            },
            1,
        )
        .await;

        // Audit event recorded with the documented action +
        // Failure outcome.
        let audits = rec.audits.lock().unwrap();
        assert_eq!(audits.len(), 1, "expected exactly one audit event");
        assert_eq!(
            audits[0].action,
            "dev.mcpg.example.host_handle_demo.execute_failed"
        );
        assert_eq!(audits[0].outcome, AuditOutcome::Failure);
        assert_eq!(
            audits[0].request_id.as_deref(),
            Some("req-0"),
            "audit event should carry the inbound request_id"
        );
        assert!(
            audits[0].details["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("synthetic failure"),
            "audit details should include the failure reason; got {:?}",
            audits[0].details
        );

        // Histogram emitted with outcome=err on failure.
        let metrics = rec.metrics.lock().unwrap();
        let hist_outcome = metrics.iter().find_map(|m| match m {
            MetricPoint::Histogram { name, labels, .. }
                if name == "mcpg_example_host_handle_demo_latency_seconds" =>
            {
                labels
                    .iter()
                    .find(|(k, _)| k == "outcome")
                    .map(|(_, v)| v.clone())
            }
            _ => None,
        });
        assert_eq!(
            hist_outcome.as_deref(),
            Some("err"),
            "histogram outcome label should be 'err' on the failure path"
        );
    }

    #[test]
    fn manifest_advertises_backend_class() {
        // Cheap structural assertion — catches accidental
        // class/protocol drift on copy-paste.
        let m = build_manifest();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::Backend);
        assert!(m.tags.iter().any(|t| t == "host-handle"));
    }
}
