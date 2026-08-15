//! Bridge `tracing` events into the `log_sink` entity-kind
//! fan-out, gated by the operator's
//! `observability.logs.sinks[].kind` allow-list.
//!
//! Operators wiring up Datadog / Honeycomb / Splunk via plugin
//! entries opt their plugins into the fan-out by listing each
//! plugin's id under `observability.logs.sinks: [{kind: <id>}]`.
//! Plugin ids absent from that list are silently skipped — config
//! is the only switch that turns a registered LogSink on or off.
//!
//! # Architecture
//!
//! - A `PluginLogLayer` (implements `tracing_subscriber::Layer`)
//!   translates each tracing `Event` into a `LogRecord` + sends
//!   it via a bounded tokio mpsc channel.
//! - A forwarder task holds the channel receiver + an
//!   `Arc<ArcSwap<GatewayRuntime>>` + an `Arc<HashSet<String>>` of
//!   plugin ids the operator opted in. Events before the runtime
//!   attaches sit in the channel (up to capacity); once attached,
//!   the task drains them via `registry.emit_log_record_filtered`.
//! - `try_send` on the sender drops when the channel is full —
//!   the tracing emit path MUST NOT block (tracing is called from
//!   every request handler, a stalled emit would wedge the
//!   gateway). Drop-on-overflow is the spec-documented behaviour
//!   for `LogSink::emit` (§9.11, "best-effort").

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use arc_swap::ArcSwap;
use mcpg_plugin_protocol::logs::{LogLevel, LogRecord};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context as LayerContext;

use crate::observability::signal_router::{
    RouteDecision, SharedTargetMap, SignalFilter, route_event, source_from_target,
};
use crate::runtime::GatewayRuntime;

/// Upper bound on in-flight-but-undelivered log records. Matches
/// what a real logging client library typically sets — enough to
/// absorb a burst (e.g. startup with many plugin registrations
/// each logging 2–3 lines) without dropping in normal ops; small
/// enough that memory bounds stay predictable even under a
/// sustained flood.
const BRIDGE_CHANNEL_CAPACITY: usize = 8192;

/// Build a new log bridge. The `allowed_plugin_ids` set comes from
/// `observability.logs.sinks[].kind` (filtered to non-builtin
/// kinds) and stops the bridge from fanning records out to plugin
/// LogSinks the operator did not opt in. Returns the tracing
/// layer (attach via `.with(layer)` on the subscriber registry)
/// and a handle the app-level init calls `attach` on once the
/// runtime is available.
///
/// `target_to_plugin_id` is consulted at event-translation time
/// to resolve the source plugin id from the event's `target`
/// (the calling crate's module path). `per_plugin_filters`
/// applies per-source `inherit` / `replace` / `tee` routing on
/// the forwarder side. Both maps are immutable post-boot.
/// Late-bound sink for shipping captured log lines off-box — set by the
/// CP-attach path to the agent's log buffer once it exists. Defined here (no
/// cp-client dep) so the always-compiled tracing layer can call it through a
/// trait object; `None` until a sink is installed (capture is inert).
pub trait LogSink: Send + Sync {
    fn record(&self, record: &LogRecord);
}

/// Install-once, lock-free slot for the optional [`LogSink`]. Set once by the
/// cp-attach path after the agent exists; read lock-free per event thereafter.
pub type SharedLogSink = Arc<std::sync::OnceLock<Arc<dyn LogSink>>>;

pub fn new_bridge(
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    target_to_plugin_id: SharedTargetMap,
    log_sink: SharedLogSink,
) -> (PluginLogLayer, PluginLogBridgeHandle) {
    let (tx, rx) = mpsc::channel::<LogRecord>(BRIDGE_CHANNEL_CAPACITY);
    (
        PluginLogLayer {
            tx,
            target_to_plugin_id,
            log_sink,
        },
        PluginLogBridgeHandle {
            rx: Some(rx),
            global_allowed_plugin_ids,
        },
    )
}

/// The tracing Layer. Holds a sender; cloning is allowed because
/// `mpsc::Sender` is Clone + cheap. The `target_to_plugin_id` map
/// is `Arc`'d so the per-event resolution is read-only.
#[derive(Clone)]
pub struct PluginLogLayer {
    tx: mpsc::Sender<LogRecord>,
    target_to_plugin_id: SharedTargetMap,
    /// Optional off-box capture sink (CP log shipping). Lock-free read per
    /// event; `None` (the default) is a no-op.
    log_sink: SharedLogSink,
}

impl<S> tracing_subscriber::Layer<S> for PluginLogLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        let mut record = event_to_log_record(event);
        // Source resolution: prefer an explicit `plugin_id` field
        // on the event (the gateway's cross-crate attribution
        // convention); otherwise look up the event's target prefix
        // in the boot-time map.
        if record.plugin_id.is_none() {
            let mut explicit: Option<String> = None;
            if let Some(serde_json::Value::String(s)) = record.fields.get("plugin_id") {
                explicit = Some(s.clone());
            }
            let resolved = explicit.unwrap_or_else(|| {
                let map = self.target_to_plugin_id.load();
                source_from_target(&record.target, &map)
            });
            record.plugin_id = Some(resolved);
        }
        // Off-box capture tap (CP log shipping). Lock-free read; the sink's
        // own ring is drop-on-overflow, so this never blocks. No-op until the
        // cp-attach path installs a sink.
        if let Some(sink) = self.log_sink.get() {
            sink.record(&record);
        }
        // A log emitted while a bridge is dispatching to a sink is
        // self-referential — a sink logging from its own `emit` would feed
        // the forwarder its own output and spin the channel hot. Drop it
        // rather than re-enqueue; a log from anywhere else enqueues.
        if crate::observability::dispatch_guard::in_dispatch() {
            return;
        }
        // Drop-on-full — never block the tracing emit path.
        // Surface the channel saturation so operators can
        // distinguish bridge contention from filter-driven drops.
        if self.tx.try_send(record).is_err() {
            metrics::counter!(
                "mcpg_observability_bridge_overflow_total",
                "signal" => "logs",
            )
            .increment(1);
        }
    }
}

/// App-level handle returned from `new_bridge`. Call `attach`
/// after `build_plugin_registry` + runtime construction to start
/// the forwarder task. Events sent to the bridge before attach
/// sit in the channel (up to capacity); once attached, the task
/// drains them into the registry, applying per-plugin override
/// routing keyed off the resolved `plugin_id` on each record.
pub struct PluginLogBridgeHandle {
    rx: Option<mpsc::Receiver<LogRecord>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
}

impl PluginLogBridgeHandle {
    /// Spawn the forwarder task, connecting accumulated + future
    /// events to the operator-listed log sinks. Consumes the
    /// handle — the receiver lives inside the spawned task from
    /// here on. `per_plugin_filters` carries the routing rules
    /// derived from `config.plugins[].observability.logs`
    /// at attach time.
    pub fn attach(
        mut self,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    ) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        tokio::spawn(forward_records(
            rx,
            runtime,
            self.global_allowed_plugin_ids,
            per_plugin_filters,
        ));
    }
}

/// Forwarder task body. Runs until the channel closes (all
/// senders dropped). Each record passes the per-plugin gate
/// (`enabled` toggle + `level` floor) before flowing to the
/// global allow-list fan-out. Bindings to the live registry
/// come from the current runtime snapshot, so registry reloads
/// (see `app::reload_config`) are picked up automatically.
async fn forward_records(
    mut rx: mpsc::Receiver<LogRecord>,
    runtime: Arc<ArcSwap<GatewayRuntime>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
) {
    use crate::observability::signal_router::CORE_PSEUDO_ID;
    while let Some(record) = rx.recv().await {
        let source = record.plugin_id.as_deref().unwrap_or(CORE_PSEUDO_ID);
        // Gate (enabled + level floor) + sink redirection (mode =
        // inherit | replace | tee). The RouteDecision tells us
        // whether to drop, fall through to the global allow-list,
        // or fan out to a per-plugin sink set.
        let decision = route_event(
            source,
            &per_plugin_filters,
            Some(record.level),
            &global_allowed_plugin_ids,
        );
        let rt = runtime.load();
        match decision {
            RouteDecision::Drop(reason) => {
                // Surface drop rate so operators can distinguish
                // "filter dropped this" from "lost due to a bug".
                metrics::counter!(
                    "mcpg_observability_dropped_total",
                    "source_plugin_id" => source.to_owned(),
                    "signal" => "logs",
                    "reason" => reason.as_label(),
                )
                .increment(1);
                continue;
            }
            RouteDecision::UseGlobal => {
                crate::observability::dispatch_guard::with_scope(
                    rt.plugin_registry()
                        .emit_log_record_filtered(&record, &global_allowed_plugin_ids),
                )
                .await;
            }
            RouteDecision::Override(sinks) => {
                crate::observability::dispatch_guard::with_scope(
                    rt.plugin_registry()
                        .emit_log_record_filtered(&record, &sinks),
                )
                .await;
            }
        }
    }
}

/// Translate a single tracing `Event` into a `LogRecord`. Only
/// field categories the receiving sinks care about are captured:
/// level, target, message, and any structured fields the event
/// supplied. Span context (span_id / trace_id) is omitted —
/// wiring span context through requires additional lookup work
/// and the structured-log receivers (stderr-json + operator
/// external sinks) typically get span correlation from OTel (the
/// telemetry bridge) rather than from here.
fn event_to_log_record(event: &tracing::Event<'_>) -> LogRecord {
    let metadata = event.metadata();
    let level = match *metadata.level() {
        tracing::Level::TRACE => LogLevel::Trace,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::ERROR => LogLevel::Error,
    };
    let mut visitor = RecordVisitor::default();
    event.record(&mut visitor);
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    LogRecord {
        timestamp_ns,
        level,
        target: metadata.target().to_owned(),
        message: visitor.message,
        fields: visitor.fields,
        span_id: None,
        trace_id: None,
        request_id: None,
        identity: None,
        node_id: None,
        plugin_id: None,
    }
}

#[derive(Default)]
struct RecordVisitor {
    message: String,
    fields: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Visit for RecordVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            // Use Display-via-Debug for the `message` field (that's
            // how tracing's own macros write it; it's a `&dyn
            // Debug` of `format_args!(...)` — the `{:?}` projection
            // yields the formatted-message string without quoting).
            self.message = format!("{value:?}");
        } else {
            self.fields.insert(
                field.name().into(),
                serde_json::Value::String(format!("{value:?}")),
            );
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.fields.insert(
                field.name().into(),
                serde_json::Value::String(value.to_owned()),
            );
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().into(), serde_json::Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().into(), serde_json::Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().into(), serde_json::Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields
            .insert(field.name().into(), serde_json::Value::from(value));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spin up a tracing subscriber with just the bridge layer +
    /// emit an event + drain records from the receiver. Lets us
    /// assert the translation without needing a full runtime.
    async fn emit_and_capture(emit: impl FnOnce()) -> Vec<LogRecord> {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
            Arc::new(std::sync::OnceLock::new()),
        );
        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt;
            tracing_subscriber::registry().with(layer)
        };
        let guard = tracing::subscriber::set_default(subscriber);
        emit();
        drop(guard); // re-enable normal subscribers before we start awaiting

        // Pull every currently-buffered record without waiting for
        // the channel to close.
        let mut out = Vec::new();
        let rx = handle.rx.as_mut().unwrap();
        while let Ok(r) = rx.try_recv() {
            out.push(r);
        }
        out
    }

    #[tokio::test]
    async fn info_event_builds_info_log_record() {
        let records = emit_and_capture(|| {
            tracing::info!(target: "wave20_test", "hello {}", "world");
        })
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, LogLevel::Info);
        assert_eq!(records[0].target, "wave20_test");
        assert_eq!(records[0].message, "hello world");
    }

    #[tokio::test]
    async fn capture_tap_feeds_installed_sink() {
        use std::sync::Mutex;
        struct VecSink(Arc<Mutex<Vec<(LogLevel, String)>>>);
        impl LogSink for VecSink {
            fn record(&self, r: &LogRecord) {
                self.0.lock().unwrap().push((r.level, r.message.clone()));
            }
        }
        let captured = Arc::new(Mutex::new(Vec::new()));
        let cell: SharedLogSink = Arc::new(std::sync::OnceLock::new());
        cell.set(Arc::new(VecSink(captured.clone())) as Arc<dyn LogSink>)
            .ok();

        let (layer, _handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
            cell,
        );
        {
            use tracing_subscriber::layer::SubscriberExt;
            let subscriber = tracing_subscriber::registry().with(layer);
            let guard = tracing::subscriber::set_default(subscriber);
            tracing::error!(target: "wave20_test", "tapped {}", "line");
            drop(guard);
        }

        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 1, "the installed sink should receive the event");
        assert_eq!(got[0].0, LogLevel::Error);
        assert_eq!(got[0].1, "tapped line");
    }

    #[tokio::test]
    async fn warn_and_error_levels_mapped_correctly() {
        let records = emit_and_capture(|| {
            tracing::warn!(target: "wave20_test", "yellow flag");
            tracing::error!(target: "wave20_test", "red alert");
        })
        .await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].level, LogLevel::Warn);
        assert_eq!(records[1].level, LogLevel::Error);
    }

    #[tokio::test]
    async fn structured_fields_land_in_record_fields_map() {
        let records = emit_and_capture(|| {
            tracing::info!(
                target: "wave20_test",
                plugin_id = "dev.test.x",
                count = 42_i64,
                enabled = true,
                "plugin loaded"
            );
        })
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "plugin loaded");
        assert_eq!(records[0].fields.get("plugin_id").unwrap(), "dev.test.x");
        assert_eq!(records[0].fields.get("count").unwrap(), 42);
        assert_eq!(records[0].fields.get("enabled").unwrap(), true);
    }

    #[tokio::test]
    async fn timestamp_ns_is_non_zero() {
        let records = emit_and_capture(|| {
            tracing::info!(target: "wave20_test", "ping");
        })
        .await;
        assert!(records[0].timestamp_ns > 0);
    }

    #[tokio::test]
    async fn drop_on_full_channel_does_not_panic() {
        // Directly construct a layer with a capacity-1 channel +
        // fill it + emit more — the layer must swallow the
        // overflow cleanly rather than panic or block.
        let (tx, _rx) = mpsc::channel::<LogRecord>(1);
        let layer = PluginLogLayer {
            tx: tx.clone(),
            target_to_plugin_id: crate::observability::signal_router::new_target_map(),
            log_sink: Arc::new(std::sync::OnceLock::new()),
        };
        // Pre-fill the channel.
        tx.try_send(LogRecord {
            timestamp_ns: 0,
            level: LogLevel::Info,
            target: "seed".into(),
            message: "seed".into(),
            fields: Default::default(),
            span_id: None,
            trace_id: None,
            request_id: None,
            identity: None,
            node_id: None,
            plugin_id: None,
        })
        .unwrap();
        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt;
            tracing_subscriber::registry().with(layer)
        };
        let _guard = tracing::subscriber::set_default(subscriber);
        // This try_send fails silently inside on_event; no panic,
        // no block.
        tracing::info!(target: "wave20_test", "overflow");
    }

    #[tokio::test]
    async fn log_emitted_during_sink_dispatch_is_not_reenqueued() {
        use tracing_subscriber::layer::SubscriberExt;
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
            Arc::new(std::sync::OnceLock::new()),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);

        // Outside any dispatch: enqueues.
        tracing::info!(target: "wave20_test", "normal");
        // Emitted while a bridge is dispatching: dropped, not re-enqueued.
        crate::observability::dispatch_guard::with_scope(async {
            tracing::info!(target: "wave20_test", "during dispatch");
        })
        .await;
        drop(guard);

        let rx = handle.rx.as_mut().unwrap();
        let mut msgs = Vec::new();
        while let Ok(r) = rx.try_recv() {
            msgs.push(r.message);
        }
        assert_eq!(
            msgs,
            vec!["normal".to_owned()],
            "only the log emitted outside a sink dispatch should enqueue"
        );
    }
}
