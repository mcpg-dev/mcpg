//! Bridge `metrics-rs` recorder events into the `metrics_sink`
//! entity-kind fan-out, gated by the operator's
//! `observability.metrics.sinks[].kind` allow-list.
//!
//! A per-plugin gate sits on top: each bridged handle captures the
//! source `module_path` at register time, and the forwarder
//! consults a `target_prefix → plugin_id` map plus a
//! `plugin_id → SignalFilter` map. Filtered events are dropped
//! before reaching the global allow-list — events that pass the
//! filter route through the global fan-out unchanged.
//!
//! # Architecture
//!
//! - [`PluginMetricsRecorder`] implements [`metrics::Recorder`].
//!   `register_*` reads `Metadata::module_path()` for the
//!   call-site crate, looks up the prefix in `target_to_plugin_id`,
//!   and bakes the resolved source plugin id into the returned
//!   handle. The per-emission cost is a clone of the resolved id
//!   (a String) plus the `MetricPoint` build, on top of the
//!   drop-on-overflow `try_send`.
//! - [`MetricsBridgeHandle`] holds the receiver + the global
//!   allow-list + the per-plugin filter table. `attach(runtime)`
//!   spawns the forwarder; events sent before attach buffer in
//!   the channel up to `BRIDGE_CHANNEL_CAPACITY`.
//! - The forwarder loop checks `should_emit(source, filters,
//!   None)` — metrics has no level — and skips dispatch when the
//!   per-plugin override has the metrics signal disabled.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use arc_swap::ArcSwap;
use mcpg_plugin_protocol::metrics::{MetricKind, MetricPoint, MetricValue};
use metrics::{
    Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SetRecorderError, SharedString,
    Unit,
};
use tokio::sync::mpsc;

use crate::observability::signal_router::{
    RouteDecision, SharedTargetMap, SignalFilter, route_event, source_from_target,
};
use crate::runtime::GatewayRuntime;

/// Bound on in-flight-but-undelivered metric points. Sized to
/// absorb a request-per-millisecond burst (every request hits
/// several counters) while keeping memory bounded under sustained
/// flood; matches the `log_bridge` capacity for symmetry.
const BRIDGE_CHANNEL_CAPACITY: usize = 16384;

use crate::observability::dispatch_guard;

/// One queued event: the wire-shape `MetricPoint` plus the
/// source-plugin-id captured at register time. The forwarder uses
/// the source id to pick which allow-list to fan to.
struct BridgedMetric {
    point: MetricPoint,
    source_plugin_id: String,
}

/// Build the bridge: returns the global-recorder candidate + the
/// app-level handle whose `attach` spins the forwarder task. The
/// `target_to_plugin_id` map is consulted at register-* time to
/// resolve each call site's source plugin id; `per_plugin_filters`
/// is consulted at forward time to resolve per-source routing.
pub fn new_bridge(
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    target_to_plugin_id: SharedTargetMap,
) -> (PluginMetricsRecorder, MetricsBridgeHandle) {
    let (tx, rx) = mpsc::channel::<BridgedMetric>(BRIDGE_CHANNEL_CAPACITY);
    (
        PluginMetricsRecorder {
            tx: tx.clone(),
            target_to_plugin_id,
        },
        MetricsBridgeHandle {
            rx: Some(rx),
            global_allowed_plugin_ids,
        },
    )
}

/// Install the recorder as the metrics-rs global. Returns `Ok` on
/// first install; surfaces `SetRecorderError` when a prior call
/// (or a prior process boot in the same address space) already
/// claimed the slot — the caller logs and continues, since the
/// crate-level recorder is a one-time-init concern.
pub fn install_recorder(
    recorder: PluginMetricsRecorder,
) -> Result<(), SetRecorderError<PluginMetricsRecorder>> {
    metrics::set_global_recorder(recorder)
}

/// `metrics::Recorder` impl that funnels every emission into the
/// bridge channel. Cloning the recorder is cheap — `mpsc::Sender`
/// is `Clone` + bounded — but `metrics::set_global_recorder`
/// consumes the value, so cloning is reserved for tests.
#[derive(Clone)]
pub struct PluginMetricsRecorder {
    tx: mpsc::Sender<BridgedMetric>,
    target_to_plugin_id: SharedTargetMap,
}

impl PluginMetricsRecorder {
    /// Resolve a metrics-rs call-site `module_path` into the
    /// source plugin id we attribute the emit to. Empty / unknown
    /// targets fall back to the `core` pseudo-id. Reads via
    /// `ArcSwap::load()` so post-init map population takes effect
    /// on subsequent registrations.
    fn resolve_source(&self, module_path: Option<&str>) -> String {
        let Some(mp) = module_path else {
            return "core".into();
        };
        let map = self.target_to_plugin_id.load();
        source_from_target(mp, &map)
    }
}

impl Recorder for PluginMetricsRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, meta: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(BridgedCounter {
            tx: self.tx.clone(),
            name: key.name().to_owned(),
            labels: key_labels(key),
            source_plugin_id: self.resolve_source(meta.module_path()),
        }))
    }

    fn register_gauge(&self, key: &Key, meta: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(BridgedGauge {
            tx: self.tx.clone(),
            name: key.name().to_owned(),
            labels: key_labels(key),
            source_plugin_id: self.resolve_source(meta.module_path()),
        }))
    }

    fn register_histogram(&self, key: &Key, meta: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(BridgedHistogram {
            tx: self.tx.clone(),
            name: key.name().to_owned(),
            labels: key_labels(key),
            source_plugin_id: self.resolve_source(meta.module_path()),
        }))
    }
}

fn key_labels(key: &Key) -> BTreeMap<String, String> {
    key.labels()
        .map(|l| (l.key().to_owned(), l.value().to_owned()))
        .collect()
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// try_send wrapper for metrics-bridge producers.
///
/// Drops silently on a saturated channel and accumulates the count
/// in `METRICS_BRIDGE_OVERFLOWS` (a process-wide AtomicU64). The
/// counter MUST NOT be emitted via `metrics::counter!` here —
/// `BridgedCounter::increment` is the very call site we're guarding,
/// so re-entering through the metrics-rs recorder on a saturated
/// channel infinite-loops the stack. The forwarder task drains the
/// atomic into `mcpg_observability_bridge_overflow_total{signal=
/// "metrics"}` from the consumer side, which is naturally
/// non-reentrant (it runs only after a `recv().await` returns,
/// i.e. the channel had room).
///
/// Log + telemetry bridges don't have this constraint — their
/// overflow goes via `metrics::counter!` directly because their
/// `try_send` and the metrics-bridge `try_send` are independent
/// channels.
static METRICS_BRIDGE_OVERFLOWS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn try_send_metric(tx: &mpsc::Sender<BridgedMetric>, msg: BridgedMetric) {
    // A metric emitted while any bridge is dispatching to a sink is
    // self-referential (the dispatch-accounting counters, a sink emitting
    // from its own `emit`). Re-enqueueing it would feed the forwarder its
    // own output and spin the bridge channel hot, so drop it here.
    if dispatch_guard::in_dispatch() {
        return;
    }
    if tx.try_send(msg).is_err() {
        METRICS_BRIDGE_OVERFLOWS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Drain accumulated metrics-bridge overflows into the observability
/// counter. Called from the forwarder task between recvs — the
/// channel just had a slot freed, so re-entering through
/// `metrics::counter!` is safe.
fn drain_metrics_bridge_overflows() {
    let n = METRICS_BRIDGE_OVERFLOWS.swap(0, std::sync::atomic::Ordering::Relaxed);
    if n > 0 {
        metrics::counter!(
            "mcpg_observability_bridge_overflow_total",
            "signal" => "metrics",
        )
        .increment(n);
    }
}

/// Per-key counter handler. Holds the resolved name + label set +
/// source-plugin-id so the per-emission cost is just `MetricPoint`
/// construction + `try_send` (no map lookups on the hot path).
struct BridgedCounter {
    tx: mpsc::Sender<BridgedMetric>,
    name: String,
    labels: BTreeMap<String, String>,
    source_plugin_id: String,
}

impl metrics::CounterFn for BridgedCounter {
    fn increment(&self, value: u64) {
        // metrics-rs counters are u64; we widen to i64 + cap so a
        // pathological u64::MAX increment (rare in practice) still
        // round-trips through the wire's signed slot.
        let signed = i64::try_from(value).unwrap_or(i64::MAX);
        try_send_metric(
            &self.tx,
            BridgedMetric {
                point: MetricPoint {
                    name: self.name.clone(),
                    unit: None,
                    kind: MetricKind::Counter,
                    value: MetricValue::I64 { value: signed },
                    labels: self.labels.clone(),
                    timestamp_ns: now_ns(),
                },
                source_plugin_id: self.source_plugin_id.clone(),
            },
        );
    }

    fn absolute(&self, value: u64) {
        // `absolute` is the "external counter sync" hook — see the
        // metrics-rs docs. Treat it as an emit with the new total
        // so sinks that snapshot still observe the latest value;
        // sinks that accumulate (the canonical Prometheus sink)
        // will over-count, but that's the documented mismatch
        // between metrics-rs counter semantics and exporter-side
        // accumulators.
        self.increment(value);
    }
}

struct BridgedGauge {
    tx: mpsc::Sender<BridgedMetric>,
    name: String,
    labels: BTreeMap<String, String>,
    source_plugin_id: String,
}

impl metrics::GaugeFn for BridgedGauge {
    fn increment(&self, value: f64) {
        // Gauge increment is "delta" — the consuming sink composes
        // the delta with the prior value. The Prometheus plugin
        // resolves gauge sequences on the receive side.
        try_send_metric(
            &self.tx,
            BridgedMetric {
                point: MetricPoint {
                    name: self.name.clone(),
                    unit: None,
                    kind: MetricKind::Gauge,
                    value: MetricValue::F64 { value },
                    labels: self.labels.clone(),
                    timestamp_ns: now_ns(),
                },
                source_plugin_id: self.source_plugin_id.clone(),
            },
        );
    }

    fn decrement(&self, value: f64) {
        self.increment(-value);
    }

    fn set(&self, value: f64) {
        try_send_metric(
            &self.tx,
            BridgedMetric {
                point: MetricPoint {
                    name: self.name.clone(),
                    unit: None,
                    kind: MetricKind::Gauge,
                    value: MetricValue::F64 { value },
                    labels: self.labels.clone(),
                    timestamp_ns: now_ns(),
                },
                source_plugin_id: self.source_plugin_id.clone(),
            },
        );
    }
}

struct BridgedHistogram {
    tx: mpsc::Sender<BridgedMetric>,
    name: String,
    labels: BTreeMap<String, String>,
    source_plugin_id: String,
}

impl metrics::HistogramFn for BridgedHistogram {
    fn record(&self, value: f64) {
        // Single observation — the receiving plugin merges into
        // its accumulator. `MetricValue::Histogram` carries
        // count=1 / sum=value / observations=[value] so sinks that
        // need bucketed aggregates have the per-sample data.
        try_send_metric(
            &self.tx,
            BridgedMetric {
                point: MetricPoint {
                    name: self.name.clone(),
                    unit: None,
                    kind: MetricKind::Histogram,
                    value: MetricValue::Histogram {
                        count: 1,
                        sum: value,
                        observations: vec![value],
                    },
                    labels: self.labels.clone(),
                    timestamp_ns: now_ns(),
                },
                source_plugin_id: self.source_plugin_id.clone(),
            },
        );
    }
}

/// App-level handle returned from `new_bridge`. Call `attach`
/// after the runtime is up to start the forwarder. Events sent
/// before attach buffer in the channel (up to capacity); once
/// attached, the task drains them through the per-source filter
/// and emits to `registry.emit_metric_event_filtered`. The
/// per-plugin filters map is supplied at attach time, after the
/// gateway has parsed `config.plugins[].observability`
/// into the routing shape.
pub struct MetricsBridgeHandle {
    rx: Option<mpsc::Receiver<BridgedMetric>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
}

impl MetricsBridgeHandle {
    pub fn attach(
        mut self,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    ) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        tokio::spawn(forward_metrics(
            rx,
            runtime,
            self.global_allowed_plugin_ids,
            per_plugin_filters,
        ));
    }
}

/// Forwarder task body. Drains the bridge channel + applies
/// per-source override routing for each event. Routes through the
/// per-tick runtime snapshot so reload-time changes to plugin
/// registrations are picked up automatically.
async fn forward_metrics(
    mut rx: mpsc::Receiver<BridgedMetric>,
    runtime: Arc<ArcSwap<GatewayRuntime>>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
) {
    while let Some(msg) = rx.recv().await {
        // Surface accumulated producer-side overflow
        // (`try_send_metric` couldn't enqueue) now that the channel
        // has room. Doing it from the consumer side avoids the
        // recursion the producer side would hit.
        drain_metrics_bridge_overflows();
        // Gate (enabled) + sink redirection. metrics has no level
        // (event_level: None), so the level floor is ignored.
        let decision = route_event(
            &msg.source_plugin_id,
            &per_plugin_filters,
            None,
            &global_allowed_plugin_ids,
        );
        let rt = runtime.load();
        match decision {
            RouteDecision::Drop(reason) => {
                // Surface drop rate so operators can tell
                // intentional filtering apart from a bug.
                metrics::counter!(
                    "mcpg_observability_dropped_total",
                    "source_plugin_id" => msg.source_plugin_id.clone(),
                    "signal" => "metrics",
                    "reason" => reason.as_label(),
                )
                .increment(1);
                continue;
            }
            RouteDecision::UseGlobal => {
                dispatch_guard::with_scope(
                    rt.plugin_registry()
                        .emit_metric_event_filtered(&msg.point, &global_allowed_plugin_ids),
                )
                .await;
            }
            RouteDecision::Override(sinks) => {
                dispatch_guard::with_scope(
                    rt.plugin_registry()
                        .emit_metric_event_filtered(&msg.point, &sinks),
                )
                .await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(rx: &mut mpsc::Receiver<BridgedMetric>) -> Vec<BridgedMetric> {
        let mut out = Vec::new();
        while let Ok(p) = rx.try_recv() {
            out.push(p);
        }
        out
    }

    fn empty_targets() -> crate::observability::signal_router::SharedTargetMap {
        crate::observability::signal_router::new_target_map()
    }

    #[test]
    fn counter_increment_translates_to_metric_point_with_core_source() {
        // No target map = every emit attributes to "core".
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), empty_targets());
        let key = Key::from_parts("requests_total", vec![metrics::Label::new("path", "/x")]);
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let counter = rec.register_counter(&key, &meta);
        counter.increment(3);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].point.name, "requests_total");
        assert_eq!(pts[0].source_plugin_id, "core");
    }

    fn sample_metric() -> BridgedMetric {
        BridgedMetric {
            point: MetricPoint {
                name: "mcpg_metrics_sink_records_total".to_owned(),
                unit: None,
                kind: MetricKind::Counter,
                value: MetricValue::I64 { value: 1 },
                labels: BTreeMap::new(),
                timestamp_ns: 0,
            },
            source_plugin_id: "core".to_owned(),
        }
    }

    #[tokio::test]
    async fn metric_emitted_during_sink_dispatch_is_not_reenqueued() {
        // A metric produced while the dispatch guard is in scope is
        // self-referential (the dispatch-accounting counters, sink-internal
        // emits). Re-enqueueing it feeds the forwarder its own output and
        // spins the bridge channel hot, so it must be dropped. A metric
        // emitted outside the scope enqueues normally.
        let (tx, mut rx) = mpsc::channel::<BridgedMetric>(8);

        try_send_metric(&tx, sample_metric());
        assert!(
            rx.try_recv().is_ok(),
            "a metric emitted outside a sink dispatch must enqueue"
        );

        dispatch_guard::with_scope(async {
            try_send_metric(&tx, sample_metric());
        })
        .await;
        assert!(
            rx.try_recv().is_err(),
            "a metric emitted during a sink dispatch must be dropped, not re-enqueued"
        );
    }

    #[test]
    fn module_path_resolves_via_target_map_to_plugin_id() {
        let mut targets: HashMap<String, String> = HashMap::new();
        targets.insert(
            "mcpg_plugin_observability_audit".into(),
            "dev.mcpg.observability.audit".into(),
        );
        let (rec, mut handle) = new_bridge(
            Arc::new(HashSet::new()),
            Arc::new(arc_swap::ArcSwap::from_pointee(targets)),
        );
        let key = Key::from_name("emit_total");
        let meta = Metadata::new(
            "t",
            metrics::Level::INFO,
            Some("mcpg_plugin_observability_audit::write"),
        );
        let counter = rec.register_counter(&key, &meta);
        counter.increment(1);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].source_plugin_id, "dev.mcpg.observability.audit");
    }

    #[test]
    fn gauge_set_emits_f64_value() {
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), empty_targets());
        let key = Key::from_parts("active", Vec::<metrics::Label>::new());
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let g = rec.register_gauge(&key, &meta);
        g.set(7.5);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].point.kind, MetricKind::Gauge);
        match &pts[0].point.value {
            MetricValue::F64 { value } => assert!((*value - 7.5).abs() < f64::EPSILON),
            other => panic!("expected F64, got {other:?}"),
        }
    }

    #[test]
    fn gauge_decrement_negates_the_delta() {
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), empty_targets());
        let key = Key::from_parts("active", Vec::<metrics::Label>::new());
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let g = rec.register_gauge(&key, &meta);
        g.decrement(2.0);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        match &pts[0].point.value {
            MetricValue::F64 { value } => assert!((*value + 2.0).abs() < f64::EPSILON),
            other => panic!("expected F64, got {other:?}"),
        }
    }

    #[test]
    fn histogram_record_carries_single_observation() {
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), empty_targets());
        let key = Key::from_parts("latency_ms", Vec::<metrics::Label>::new());
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let h = rec.register_histogram(&key, &meta);
        h.record(42.0);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].point.kind, MetricKind::Histogram);
        match &pts[0].point.value {
            MetricValue::Histogram {
                count,
                sum,
                observations,
            } => {
                assert_eq!(*count, 1);
                assert!((*sum - 42.0).abs() < f64::EPSILON);
                assert_eq!(observations, &vec![42.0]);
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    #[test]
    fn channel_overflow_drops_silently() {
        // Overflow does not go via metrics::counter! (would recurse
        // through the bridge); it accumulates in the
        // METRICS_BRIDGE_OVERFLOWS atomic instead.
        let baseline = METRICS_BRIDGE_OVERFLOWS.load(std::sync::atomic::Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<BridgedMetric>(1);
        let rec = PluginMetricsRecorder {
            tx,
            target_to_plugin_id: empty_targets(),
        };
        let key = Key::from_parts("ops", Vec::<metrics::Label>::new());
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let c = rec.register_counter(&key, &meta);
        for _ in 0..10 {
            c.increment(1);
        }
        let drained = drain(&mut rx);
        assert!(
            drained.len() <= 1,
            "overflow path produced more than capacity: got {}",
            drained.len()
        );
        // 10 emits, capacity 1 → ≥ 9 overflows recorded.
        let overflows =
            METRICS_BRIDGE_OVERFLOWS.load(std::sync::atomic::Ordering::Relaxed) - baseline;
        assert!(
            overflows >= 9,
            "expected ≥9 overflows accumulated, got {overflows}"
        );
    }

    #[test]
    fn bridged_counter_caps_u64_max_at_i64_max() {
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), empty_targets());
        let key = Key::from_parts("ops", Vec::<metrics::Label>::new());
        let meta = Metadata::new("t", metrics::Level::INFO, None);
        let c = rec.register_counter(&key, &meta);
        c.increment(u64::MAX);
        let pts = drain(handle.rx.as_mut().unwrap());
        assert_eq!(pts.len(), 1);
        match &pts[0].point.value {
            MetricValue::I64 { value } => assert_eq!(*value, i64::MAX),
            other => panic!("expected I64, got {other:?}"),
        }
    }
}
