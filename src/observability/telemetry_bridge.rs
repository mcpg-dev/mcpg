//! Bridge tracing spans into the `telemetry_sink` entity-kind
//! fan-out.
//!
//! Parallel to the log bridge. Every `tracing::info_span!`
//! / `debug_span!` / `error_span!` the gateway opens also
//! reaches every registered `telemetry_sink` as a `SpanStart` +
//! `SpanEnd` event pair, in addition to the existing direct
//! OTLP emit path. Operators wiring sinks (Datadog, Honeycomb,
//! custom APM) as `telemetry_sink` plugin entries see gateway
//! spans; the existing OTel direct-export path stays untouched
//! for backwards compat.
//!
//! # Scope
//!
//! Spans only. Metrics require a `metrics::Recorder`
//! implementation (different crate, different plumbing) and go
//! through [`crate::observability::metrics_bridge`] instead. An
//! OTLP-grpc `telemetry_sink` built-in plugin is lower priority —
//! the OTel direct path already exports to OTLP, so a plugin that
//! duplicates that adds little.
//!
//! # Trace id semantics
//!
//! Tracing spans don't carry OTel `trace_id` natively; the
//! bridge synthesises trace ids per root span + propagates them
//! down via tracing's span-extension mechanism. Not
//! OTel-correlated with whatever upstream traces might exist —
//! operators who need full OTel correlation stay on the direct
//! OTLP path. This bridge's value is "let telemetry_sink
//! plugins see gateway spans without having to re-implement
//! OTLP receive".

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use arc_swap::ArcSwap;
use mcpg_plugin_protocol::telemetry::{SpanEnd, SpanKind, SpanStart, SpanStatus};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::registry::LookupSpan;

use crate::observability::signal_router::{
    CORE_PSEUDO_ID, RouteDecision, SharedTargetMap, SignalFilter, route_event, source_from_target,
};
use crate::runtime::GatewayRuntime;

/// Upper bound on in-flight-but-undelivered span events. Matches
/// the log bridge capacity; spans fire at a rate comparable to
/// log events in practice.
const BRIDGE_CHANNEL_CAPACITY: usize = 8192;

/// Event carried on the bridge channel. Single enum so SpanStart
/// + SpanEnd share one channel + one forwarder loop.
///
/// Each variant carries the resolved `source_plugin_id` so the
/// forwarder can apply per-plugin override routing without a
/// second pass over the span metadata.
enum BridgedEvent {
    Start {
        span: SpanStart,
        source_plugin_id: String,
    },
    End {
        span: SpanEnd,
        source_plugin_id: String,
    },
}

/// Tracing-level extension stored on each span so descendants
/// inherit the same trace_id. Keeps the parent→child trace
/// propagation cheap (no lookup cache needed — tracing's own
/// extensions storage does the work).
#[derive(Clone)]
struct SpanTraceId(String);

/// Span-level extension carrying the resolved source plugin id so
/// descendant spans / events can inherit without re-walking the
/// target map.
#[derive(Clone)]
struct SpanSourcePluginId(String);

/// Build the bridge. The `allowed_plugin_ids` set comes from
/// `observability.traces.sinks[].kind` (filtered to non-builtin
/// kinds) and stops the bridge from fanning span events out to
/// `TelemetrySink` plugins the operator did not opt in. Returns
/// the tracing Layer + a handle the app startup path consumes
/// via `attach`.
pub fn new_bridge(
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    target_to_plugin_id: SharedTargetMap,
) -> (PluginTelemetryLayer, PluginTelemetryBridgeHandle) {
    let (tx, rx) = mpsc::channel::<BridgedEvent>(BRIDGE_CHANNEL_CAPACITY);
    (
        PluginTelemetryLayer {
            tx,
            target_to_plugin_id,
        },
        PluginTelemetryBridgeHandle {
            rx: Some(rx),
            global_allowed_plugin_ids,
        },
    )
}

#[derive(Clone)]
pub struct PluginTelemetryLayer {
    tx: mpsc::Sender<BridgedEvent>,
    target_to_plugin_id: SharedTargetMap,
}

impl<S> tracing_subscriber::Layer<S> for PluginTelemetryLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        let span_ref = match ctx.span(id) {
            Some(s) => s,
            None => return,
        };
        // Inherit parent trace_id if present, else mint a fresh
        // one derived from this span's id.
        let parent_trace_id = span_ref.parent().and_then(|parent| {
            parent
                .extensions()
                .get::<SpanTraceId>()
                .map(|t| t.0.clone())
        });
        let trace_id = parent_trace_id.unwrap_or_else(|| synth_trace_id(id.into_u64()));
        // Stash on this span's extensions so children find it.
        span_ref
            .extensions_mut()
            .insert(SpanTraceId(trace_id.clone()));

        let metadata = span_ref.metadata();
        let mut visitor = AttributeVisitor::default();
        attrs.values().record(&mut visitor);

        let parent_id = span_ref
            .parent()
            .map(|p| format!("{:016x}", p.id().into_u64()));
        // Source resolution: prefer a `plugin_id` attribute set on
        // the span (the explicit attribution hook used by gateway
        // code wrapping plugin invocations); otherwise inherit from
        // the parent span; fall back to the target prefix lookup;
        // finally `core`.
        let source_plugin_id = visitor
            .attributes
            .get("plugin_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                span_ref.parent().and_then(|p| {
                    p.extensions()
                        .get::<SpanSourcePluginId>()
                        .map(|s| s.0.clone())
                })
            })
            .unwrap_or_else(|| {
                let map = self.target_to_plugin_id.load();
                source_from_target(metadata.target(), &map)
            });
        // Stash on the span's extensions so on_close + descendants
        // skip the resolution.
        span_ref
            .extensions_mut()
            .insert(SpanSourcePluginId(source_plugin_id.clone()));
        let start = SpanStart {
            trace_id,
            span_id: format!("{:016x}", id.into_u64()),
            parent_id,
            name: metadata.name().to_owned(),
            kind: SpanKind::Internal,
            start_ns: now_ns(),
            attributes: visitor.attributes,
        };
        // A span opened while a bridge is dispatching to a sink is
        // self-referential — a sink that traces from its own `emit` would
        // feed the forwarder its own output and spin the channel hot. Drop
        // it rather than re-enqueue; a span from anywhere else enqueues.
        if crate::observability::dispatch_guard::in_dispatch() {
            return;
        }
        if self
            .tx
            .try_send(BridgedEvent::Start {
                span: start,
                source_plugin_id,
            })
            .is_err()
        {
            // Surface bridge contention.
            metrics::counter!(
                "mcpg_observability_bridge_overflow_total",
                "signal" => "traces",
            )
            .increment(1);
        }
    }

    fn on_close(&self, id: Id, ctx: LayerContext<'_, S>) {
        // Re-derive trace_id + source from extensions stored at
        // on_new_span — the span may be about to be removed from
        // the registry after we return.
        let span_ref = ctx.span(&id);
        let trace_id = span_ref
            .as_ref()
            .and_then(|s| s.extensions().get::<SpanTraceId>().map(|t| t.0.clone()))
            .unwrap_or_else(|| synth_trace_id(id.into_u64()));
        let source_plugin_id = span_ref
            .as_ref()
            .and_then(|s| {
                s.extensions()
                    .get::<SpanSourcePluginId>()
                    .map(|s| s.0.clone())
            })
            .unwrap_or_else(|| CORE_PSEUDO_ID.to_owned());
        let end = SpanEnd {
            trace_id,
            span_id: format!("{:016x}", id.into_u64()),
            end_ns: now_ns(),
            status: SpanStatus::Unset,
            events: Vec::new(),
            additional_attributes: Default::default(),
        };
        if crate::observability::dispatch_guard::in_dispatch() {
            return;
        }
        if self
            .tx
            .try_send(BridgedEvent::End {
                span: end,
                source_plugin_id,
            })
            .is_err()
        {
            metrics::counter!(
                "mcpg_observability_bridge_overflow_total",
                "signal" => "traces",
            )
            .increment(1);
        }
    }
}

pub struct PluginTelemetryBridgeHandle {
    rx: Option<mpsc::Receiver<BridgedEvent>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
}

impl PluginTelemetryBridgeHandle {
    pub fn attach(
        mut self,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    ) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        tokio::spawn(forward_events(
            rx,
            runtime,
            self.global_allowed_plugin_ids,
            per_plugin_filters,
        ));
    }
}

async fn forward_events(
    mut rx: mpsc::Receiver<BridgedEvent>,
    runtime: Arc<ArcSwap<GatewayRuntime>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
) {
    while let Some(ev) = rx.recv().await {
        // Per-plugin gate first, then the global allow-list
        // fan-out. Spans don't carry a tracing severity in this
        // bridge — we admit all levels when enabled (operators
        // wanting verbosity control set the global tracing filter).
        let (source_plugin_id, do_emit_start, do_emit_end) = match &ev {
            BridgedEvent::Start {
                source_plugin_id, ..
            } => (source_plugin_id.as_str(), true, false),
            BridgedEvent::End {
                source_plugin_id, ..
            } => (source_plugin_id.as_str(), false, true),
        };
        let decision = route_event(
            source_plugin_id,
            &per_plugin_filters,
            None,
            &global_allowed_plugin_ids,
        );
        let allowed: &HashSet<String> = match &decision {
            RouteDecision::Drop(reason) => {
                // Surface drop rate so operators can distinguish
                // filter behaviour from a bug.
                metrics::counter!(
                    "mcpg_observability_dropped_total",
                    "source_plugin_id" => source_plugin_id.to_owned(),
                    "signal" => "traces",
                    "reason" => reason.as_label(),
                )
                .increment(1);
                continue;
            }
            RouteDecision::UseGlobal => &global_allowed_plugin_ids,
            RouteDecision::Override(set) => set,
        };
        let rt = runtime.load();
        let registry = rt.plugin_registry();
        match ev {
            BridgedEvent::Start { span, .. } if do_emit_start => {
                crate::observability::dispatch_guard::with_scope(
                    registry.emit_telemetry_span_started_filtered(&span, allowed),
                )
                .await;
            }
            BridgedEvent::End { span, .. } if do_emit_end => {
                crate::observability::dispatch_guard::with_scope(
                    registry.emit_telemetry_span_ended_filtered(&span, allowed),
                )
                .await;
            }
            _ => {}
        }
    }
}

/// Mint a synthetic 32-hex-char trace id from a span id. Not
/// cryptographically random — just deterministic + distinct
/// across the gateway's runtime. Sinks that need OTel-correlated
/// trace ids (cross-service propagation) stay on the direct OTLP
/// export path.
fn synth_trace_id(seed: u64) -> String {
    // Left half = seed, right half = boot-nanos, keeps it
    // distinguishable even if two restarts reuse span ids.
    let boot = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{seed:016x}{boot:016x}")
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[derive(Default)]
struct AttributeVisitor {
    attributes: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Visit for AttributeVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.attributes.insert(
            field.name().into(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.attributes.insert(
            field.name().into(),
            serde_json::Value::String(value.to_owned()),
        );
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.attributes
            .insert(field.name().into(), serde_json::Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.attributes
            .insert(field.name().into(), serde_json::Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.attributes
            .insert(field.name().into(), serde_json::Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.attributes
            .insert(field.name().into(), serde_json::Value::from(value));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    /// Drain every currently-queued event from the handle's
    /// receiver. Used to inspect what the Layer sent without
    /// starting a forwarder task.
    fn drain(handle: &mut PluginTelemetryBridgeHandle) -> Vec<BridgedEvent> {
        let mut out = Vec::new();
        let rx = handle.rx.as_mut().unwrap();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn single_span_produces_start_and_end() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!("test.span");
            let _entered = span.enter();
        }
        let events = drain(&mut handle);
        assert_eq!(events.len(), 2);
        match &events[0] {
            BridgedEvent::Start { span: s, .. } => {
                assert_eq!(s.name, "test.span");
                assert!(s.parent_id.is_none(), "root span has no parent");
                assert_eq!(s.kind, SpanKind::Internal);
            }
            _ => panic!("first event should be Start"),
        }
        match &events[1] {
            BridgedEvent::End { span: e, .. } => {
                // Span id round-trips; trace id populated.
                assert!(!e.span_id.is_empty());
                assert!(!e.trace_id.is_empty());
                assert_eq!(e.status, SpanStatus::Unset);
            }
            _ => panic!("second event should be End"),
        }
    }

    #[test]
    fn start_and_end_share_span_and_trace_id() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!("paired");
            let _entered = span.enter();
        }
        let events = drain(&mut handle);
        assert_eq!(events.len(), 2);
        let (start_span, start_trace) = match &events[0] {
            BridgedEvent::Start { span: s, .. } => (s.span_id.clone(), s.trace_id.clone()),
            _ => unreachable!(),
        };
        let (end_span, end_trace) = match &events[1] {
            BridgedEvent::End { span: e, .. } => (e.span_id.clone(), e.trace_id.clone()),
            _ => unreachable!(),
        };
        assert_eq!(start_span, end_span);
        assert_eq!(start_trace, end_trace);
    }

    #[test]
    fn child_span_inherits_trace_id_and_sets_parent() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let parent = tracing::info_span!("parent");
            let _p = parent.enter();
            let child = tracing::info_span!("child");
            let _c = child.enter();
        }
        let events = drain(&mut handle);
        // Expect: parent start, child start, child end, parent end.
        // Tracing orders ends LIFO; starts are FIFO. So:
        //   events[0] parent Start
        //   events[1] child  Start
        //   events[2] child  End
        //   events[3] parent End
        assert_eq!(events.len(), 4);
        let (parent_trace, parent_span) = match &events[0] {
            BridgedEvent::Start { span: s, .. } => {
                assert_eq!(s.name, "parent");
                assert!(s.parent_id.is_none());
                (s.trace_id.clone(), s.span_id.clone())
            }
            _ => panic!("events[0] should be parent Start"),
        };
        match &events[1] {
            BridgedEvent::Start { span: s, .. } => {
                assert_eq!(s.name, "child");
                // Same trace as parent.
                assert_eq!(s.trace_id, parent_trace);
                // Parent id populated.
                assert_eq!(s.parent_id.as_deref(), Some(parent_span.as_str()));
            }
            _ => panic!("events[1] should be child Start"),
        };
    }

    #[test]
    fn span_fields_become_attributes() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!(
                "typed",
                plugin_id = "dev.test.x",
                count = 42_i64,
                enabled = true
            );
            let _entered = span.enter();
        }
        let events = drain(&mut handle);
        match &events[0] {
            BridgedEvent::Start { span: s, .. } => {
                assert_eq!(s.attributes.get("plugin_id").unwrap(), "dev.test.x");
                assert_eq!(s.attributes.get("count").unwrap(), 42);
                assert_eq!(s.attributes.get("enabled").unwrap(), true);
            }
            _ => panic!("first event should be Start"),
        }
    }

    #[test]
    fn start_ns_is_populated() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let s = tracing::info_span!("ts");
            let _e = s.enter();
        }
        let events = drain(&mut handle);
        match &events[0] {
            BridgedEvent::Start { span: s, .. } => assert!(s.start_ns > 0),
            _ => panic!(),
        }
    }

    #[test]
    fn drop_on_full_channel_does_not_panic() {
        // capacity-1 channel, pre-filled — overflow on span open
        // silently drops rather than blocking.
        let (tx, _rx) = mpsc::channel::<BridgedEvent>(1);
        let layer = PluginTelemetryLayer {
            tx: tx.clone(),
            target_to_plugin_id: crate::observability::signal_router::new_target_map(),
        };
        tx.try_send(BridgedEvent::Start {
            span: SpanStart {
                trace_id: "seed".into(),
                span_id: "seed".into(),
                parent_id: None,
                name: "seed".into(),
                kind: SpanKind::Internal,
                start_ns: 0,
                attributes: Default::default(),
            },
            source_plugin_id: "core".into(),
        })
        .unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let s = tracing::info_span!("overflow");
        let _e = s.enter();
    }

    #[tokio::test]
    async fn span_opened_during_sink_dispatch_is_not_reenqueued() {
        let (layer, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            crate::observability::signal_router::new_target_map(),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);

        // Outside any dispatch: the span produces Start + End.
        {
            let s = tracing::info_span!("outside");
            let _e = s.enter();
        }
        // Opened while a bridge is dispatching: dropped, not re-enqueued.
        crate::observability::dispatch_guard::with_scope(async {
            let s = tracing::info_span!("during");
            let _e = s.enter();
        })
        .await;
        drop(guard);

        let events = drain(&mut handle);
        assert_eq!(
            events.len(),
            2,
            "only the span opened outside a sink dispatch should enqueue (Start + End)"
        );
        for ev in &events {
            let name = match ev {
                BridgedEvent::Start { span, .. } => &span.name,
                BridgedEvent::End { span, .. } => &span.span_id,
            };
            assert!(
                !name.contains("during"),
                "a span opened during dispatch must not be enqueued"
            );
        }
    }
}
