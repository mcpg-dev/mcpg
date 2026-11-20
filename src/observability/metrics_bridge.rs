//! Bridge `metrics-rs` recorder events into the `metrics_sink`
//! entity-kind fan-out, gated by the operator's
//! `observability.metrics.sinks[].kind` allow-list.
//!
//! A per-plugin gate sits on top: each bridged series keeps the
//! `module_path` of its call site, and the forwarder consults a
//! `target_prefix → plugin_id` map plus a `plugin_id → SignalFilter`
//! map. Filtered points are dropped before reaching the global
//! allow-list — points that pass the filter route through the
//! global fan-out unchanged.
//!
//! # Architecture
//!
//! - [`PluginMetricsRecorder`] implements [`metrics::Recorder`].
//!   `register_*` returns the cached handle of the series that the
//!   key and the call site's `Metadata::module_path()` name, and
//!   builds it on first use. A cached handle aggregates each sample in
//!   place: an atomic add for a counter, a compare-and-swap for a
//!   gauge, a short lock for a histogram. It allocates nothing.
//! - [`MetricsFlusher`] takes what every cached series aggregated
//!   since the last flush and delivers one point per series and kind:
//!   a counter's increase, a gauge's current value, a histogram's
//!   exact count and sum with a uniform sample of at most
//!   `MAX_OBSERVATIONS` observations. The forwarder flushes every
//!   [`FLUSH_INTERVAL`], `/metrics` flushes before it renders, and
//!   shutdown flushes once more.
//! - A series past `MAX_CACHED_SERIES` gets an uncached handle, which
//!   queues each sample on the bounded bridge channel with a
//!   drop-on-overflow `try_send`; the forwarder delivers those one by one.
//! - Each point is routed by `route_event(source, filters, None, …)`
//!   — metrics has no level — with the source plugin id resolved from
//!   the series' module path.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use mcpg_plugin_protocol::metrics::{MetricKind, MetricPoint, MetricValue};
use metrics::{
    Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SetRecorderError, SharedString,
    Unit,
};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::observability::dispatch_guard;
use crate::observability::signal_router::{
    CORE_PSEUDO_ID, RouteDecision, SharedTargetMap, SignalFilter, route_event,
    source_ref_from_target,
};
use crate::runtime::GatewayRuntime;

/// Interval at which the forwarder delivers the aggregated series. It
/// bounds the lag of push sinks; `/metrics` and shutdown flush on their own.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// Bound on queued samples of uncached series; a full channel drops.
const BRIDGE_CHANNEL_CAPACITY: usize = 16384;

/// Bound on cached series. A key past it gets an uncached handle, so
/// a label with unbounded values cannot grow the cache without limit.
const MAX_CACHED_SERIES: usize = 4096;

/// Most observations a histogram point carries: a uniform sample of the
/// interval's observations, next to their exact count and sum.
const MAX_OBSERVATIONS: usize = 64;

/// `GaugeCell::pending` values: delivered, or the last write is not
/// delivered yet and came before / after the target map filled.
const GAUGE_DELIVERED: u8 = 0;
const GAUGE_PENDING_BEFORE_TARGETS: u8 = 1;
const GAUGE_PENDING: u8 = 2;

/// The name, labels and call-site module path of one series, copied
/// out of the metrics-rs key once, when the series is first registered.
struct Series {
    name: String,
    labels: BTreeMap<String, String>,
    module_path: Option<String>,
}

impl Series {
    /// The plugin id a sample is attributed to: the module path's crate
    /// looked up in `targets`, `core` when unknown or absent, or when the
    /// sample came before the map was filled.
    fn source<'m>(&self, targets: &'m HashMap<String, String>, before_targets: bool) -> &'m str {
        match self.module_path.as_deref() {
            Some(module_path) if !before_targets => source_ref_from_target(module_path, targets),
            _ => CORE_PSEUDO_ID,
        }
    }

    fn point(&self, kind: MetricKind, value: MetricValue, timestamp_ns: u64) -> MetricPoint {
        MetricPoint {
            name: self.name.clone(),
            unit: None,
            kind,
            value,
            labels: self.labels.clone(),
            timestamp_ns,
        }
    }
}

/// One queued sample of an uncached series.
struct BridgedMetric {
    series: Arc<Series>,
    sample: Sample,
    timestamp_ns: u64,
    /// The target map was empty when the sample was emitted: plugin
    /// registration had not filled it, so the sample is the gateway's.
    before_targets: bool,
}

/// One sample of an uncached series, in the form its point carries it.
#[derive(Debug, Clone, Copy)]
enum Sample {
    /// The counter's increase.
    Counter(u64),
    /// The gauge's value after the operation.
    Gauge(f64),
    /// One histogram observation.
    Histogram(f64),
}

impl BridgedMetric {
    fn source_plugin_id<'m>(&self, targets: &'m HashMap<String, String>) -> &'m str {
        self.series.source(targets, self.before_targets)
    }

    fn to_point(&self) -> MetricPoint {
        let (kind, value) = match self.sample {
            Sample::Counter(increase) => (
                MetricKind::Counter,
                MetricValue::I64 {
                    value: saturating_i64(increase),
                },
            ),
            Sample::Gauge(value) => (MetricKind::Gauge, MetricValue::F64 { value }),
            Sample::Histogram(value) => (
                MetricKind::Histogram,
                MetricValue::Histogram {
                    count: 1,
                    sum: value,
                    observations: vec![value],
                },
            ),
        };
        self.series.point(kind, value, self.timestamp_ns)
    }
}

/// The wire carries counter values in an `i64`.
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Build the bridge: returns the global-recorder candidate + the
/// app-level handle whose `attach` spins the forwarder task. The
/// forwarder consults `target_to_plugin_id` to resolve each point's
/// source plugin id and `per_plugin_filters` to route it.
pub fn new_bridge(
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    target_to_plugin_id: SharedTargetMap,
) -> (PluginMetricsRecorder, MetricsBridgeHandle) {
    let (tx, rx) = mpsc::channel::<BridgedMetric>(BRIDGE_CHANNEL_CAPACITY);
    let series = Arc::<SeriesCache>::default();
    (
        PluginMetricsRecorder {
            tx,
            series: Arc::clone(&series),
            targets: Arc::clone(&target_to_plugin_id),
        },
        MetricsBridgeHandle {
            rx: Some(rx),
            series,
            global_allowed_plugin_ids,
            target_to_plugin_id,
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

/// `metrics::Recorder` impl that aggregates every emission in its
/// series. Clones share the channel and the series cache, but
/// `metrics::set_global_recorder` consumes the value, so cloning is
/// reserved for tests.
#[derive(Clone)]
pub struct PluginMetricsRecorder {
    tx: mpsc::Sender<BridgedMetric>,
    series: Arc<SeriesCache>,
    targets: SharedTargetMap,
}

/// Bridged handles by key. A key holds one handle per call-site
/// module path, because the module path decides the source plugin id.
#[derive(Default)]
struct SeriesCache {
    handles: DashMap<Key, Vec<Arc<BridgedHandle>>>,
    len: AtomicUsize,
}

impl SeriesCache {
    fn find(&self, key: &Key, module_path: Option<&str>) -> Option<Arc<BridgedHandle>> {
        let handles = self.handles.get(key)?;
        handles
            .iter()
            .find(|h| h.series.module_path.as_deref() == module_path)
            .cloned()
    }

    fn is_full(&self) -> bool {
        self.len.load(Ordering::Relaxed) >= MAX_CACHED_SERIES
    }

    /// Cache `handle`. Returns the handle the series resolves to from now
    /// on: the one a concurrent first registration cached, when there is one.
    fn insert(&self, key: &Key, handle: Arc<BridgedHandle>) -> Arc<BridgedHandle> {
        let mut handles = self.handles.entry(key.clone()).or_default();
        let module_path = handle.series.module_path.as_deref();
        if let Some(cached) = handles
            .iter()
            .find(|h| h.series.module_path.as_deref() == module_path)
        {
            return Arc::clone(cached);
        }
        handles.push(Arc::clone(&handle));
        self.len.fetch_add(1, Ordering::Relaxed);
        handle
    }

    /// Appends the points of what every cached series aggregated since
    /// the last call, each with its source plugin id.
    fn take_points<'m>(
        &self,
        targets: &'m HashMap<String, String>,
        timestamp_ns: u64,
        points: &mut Vec<(&'m str, MetricPoint)>,
    ) {
        for entry in self.handles.iter() {
            for handle in entry.value() {
                handle.take_points(targets, timestamp_ns, points);
            }
        }
    }
}

impl PluginMetricsRecorder {
    fn handle(&self, key: &Key, meta: &Metadata<'_>) -> Arc<BridgedHandle> {
        let module_path = meta.module_path();
        if let Some(handle) = self.series.find(key, module_path) {
            return handle;
        }
        let cached = !self.series.is_full();
        let handle = Arc::new(BridgedHandle {
            series: Arc::new(Series {
                name: key.name().to_owned(),
                labels: key_labels(key),
                module_path: module_path.map(str::to_owned),
            }),
            tx: self.tx.clone(),
            targets: Arc::clone(&self.targets),
            cached,
            targets_seen: AtomicBool::new(false),
            slots: Default::default(),
            gauge: GaugeCell::default(),
        });
        if cached {
            self.series.insert(key, handle)
        } else {
            handle
        }
    }
}

impl Recorder for PluginMetricsRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, meta: &Metadata<'_>) -> Counter {
        Counter::from_arc(self.handle(key, meta))
    }

    fn register_gauge(&self, key: &Key, meta: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(self.handle(key, meta))
    }

    fn register_histogram(&self, key: &Key, meta: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(self.handle(key, meta))
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

/// Count of samples of uncached series that a saturated channel refused.
///
/// The count MUST NOT be emitted via `metrics::counter!` on the
/// producer side: an uncached overflow counter would queue on the same
/// saturated channel and recurse. The forwarder drains the atomic into
/// `mcpg_observability_bridge_overflow_total{signal="metrics"}`.
static METRICS_BRIDGE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// Drain accumulated metrics-bridge overflows into the observability
/// counter. Called from the forwarder, outside any producer.
fn drain_metrics_bridge_overflows() {
    let n = METRICS_BRIDGE_OVERFLOWS.swap(0, Ordering::Relaxed);
    if n > 0 {
        metrics::counter!(
            "mcpg_observability_bridge_overflow_total",
            "signal" => "metrics",
        )
        .increment(n);
    }
}

/// The handle every `register_*` call for one series returns. It
/// implements all three handle traits; the trait method called
/// decides which aggregate a sample goes to.
struct BridgedHandle {
    series: Arc<Series>,
    tx: mpsc::Sender<BridgedMetric>,
    targets: SharedTargetMap,
    /// A cached handle aggregates; an uncached one queues each sample.
    cached: bool,
    /// A sample found the target map filled, so later ones skip the check.
    targets_seen: AtomicBool,
    /// Counter and histogram aggregates of the samples emitted after
    /// (`[0]`) and before (`[1]`) the target map filled.
    slots: [Slot; 2],
    gauge: GaugeCell,
}

#[derive(Default)]
struct Slot {
    counter: CounterCell,
    histogram: Mutex<HistogramCell>,
}

#[derive(Default)]
struct CounterCell {
    /// Sum of the increments, raised by `absolute`.
    total: AtomicU64,
    /// The part of `total` already delivered; only a flush writes it.
    delivered: AtomicU64,
}

impl CounterCell {
    /// The increase since the last call, at most `i64::MAX`; the rest
    /// waits for the next call.
    fn take(&self) -> Option<i64> {
        let total = self.total.load(Ordering::Acquire);
        let delivered = self.delivered.load(Ordering::Relaxed);
        let increase = saturating_i64(total.wrapping_sub(delivered));
        if increase == 0 {
            return None;
        }
        self.delivered.store(
            delivered.wrapping_add(increase.unsigned_abs()),
            Ordering::Relaxed,
        );
        Some(increase)
    }
}

#[derive(Default)]
struct HistogramCell {
    count: u64,
    sum: f64,
    /// Uniform sample of the interval's observations (reservoir sampling).
    observations: Vec<f64>,
    /// State of the generator that picks the observation a new one replaces.
    rng: u64,
}

impl HistogramCell {
    fn record(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        if self.observations.len() < MAX_OBSERVATIONS {
            if self.observations.capacity() == 0 {
                self.observations.reserve_exact(MAX_OBSERVATIONS);
            }
            self.observations.push(value);
            return;
        }
        // The n-th observation replaces a kept one with probability MAX_OBSERVATIONS / n.
        let index = self.below(self.count);
        if let Some(kept) = self.observations.get_mut(index as usize) {
            *kept = value;
        }
    }

    /// A uniform value in `0..bound`: splitmix64, scaled by multiply-shift.
    fn below(&mut self, bound: u64) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        ((u128::from(z) * u128::from(bound)) >> 64) as u64
    }

    fn take(&mut self) -> Option<MetricValue> {
        if self.count == 0 {
            return None;
        }
        let value = MetricValue::Histogram {
            count: self.count,
            sum: self.sum,
            observations: self.observations.clone(),
        };
        self.count = 0;
        self.sum = 0.0;
        self.observations.clear();
        Some(value)
    }
}

#[derive(Default)]
struct GaugeCell {
    /// The value's `f64` bits.
    bits: AtomicU64,
    /// One of the `GAUGE_*` states.
    pending: AtomicU8,
}

impl GaugeCell {
    /// Applies `op` to the value atomically and returns the new value.
    fn update(&self, op: impl Fn(f64) -> f64) -> f64 {
        let mut current = self.bits.load(Ordering::Relaxed);
        loop {
            let next = op(f64::from_bits(current));
            match self.bits.compare_exchange_weak(
                current,
                next.to_bits(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    fn mark_pending(&self, before_targets: bool) {
        let pending = if before_targets {
            GAUGE_PENDING_BEFORE_TARGETS
        } else {
            GAUGE_PENDING
        };
        self.pending.store(pending, Ordering::Release);
    }

    /// The value, when it changed since the last call, and whether its
    /// last write came before the target map filled.
    fn take(&self) -> Option<(bool, f64)> {
        let pending = self.pending.swap(GAUGE_DELIVERED, Ordering::AcqRel);
        (pending != GAUGE_DELIVERED).then(|| {
            (
                pending == GAUGE_PENDING_BEFORE_TARGETS,
                f64::from_bits(self.bits.load(Ordering::Acquire)),
            )
        })
    }
}

impl BridgedHandle {
    /// `None` for a sample emitted while a bridge dispatches to a sink:
    /// it is self-referential (dispatch accounting, a sink's own emits),
    /// and recording it would feed the sinks their own output. Otherwise
    /// whether the sample came before the target map filled.
    fn admit(&self) -> Option<bool> {
        (!dispatch_guard::in_dispatch()).then(|| self.before_targets())
    }

    fn before_targets(&self) -> bool {
        if self.series.module_path.is_none() || self.targets_seen.load(Ordering::Relaxed) {
            return false;
        }
        if self.targets.load().is_empty() {
            return true;
        }
        self.targets_seen.store(true, Ordering::Relaxed);
        false
    }

    fn slot(&self, before_targets: bool) -> &Slot {
        &self.slots[usize::from(before_targets)]
    }

    /// Queue one sample of an uncached series. Drops it on a saturated
    /// channel and counts the drop in `METRICS_BRIDGE_OVERFLOWS`.
    fn send(&self, sample: Sample, before_targets: bool) {
        let msg = BridgedMetric {
            series: Arc::clone(&self.series),
            sample,
            timestamp_ns: now_ns(),
            before_targets,
        };
        if self.tx.try_send(msg).is_err() {
            METRICS_BRIDGE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn gauge_written(&self, value: f64, before_targets: bool) {
        if self.cached {
            self.gauge.mark_pending(before_targets);
        } else {
            self.send(Sample::Gauge(value), before_targets);
        }
    }

    /// Appends the points of what the series aggregated since the last call.
    fn take_points<'m>(
        &self,
        targets: &'m HashMap<String, String>,
        timestamp_ns: u64,
        points: &mut Vec<(&'m str, MetricPoint)>,
    ) {
        for before_targets in [true, false] {
            let slot = self.slot(before_targets);
            let source = self.series.source(targets, before_targets);
            if let Some(value) = slot.counter.take() {
                let value = MetricValue::I64 { value };
                points.push((
                    source,
                    self.series.point(MetricKind::Counter, value, timestamp_ns),
                ));
            }
            if let Some(value) = slot.histogram.lock().take() {
                points.push((
                    source,
                    self.series
                        .point(MetricKind::Histogram, value, timestamp_ns),
                ));
            }
        }
        if let Some((before_targets, value)) = self.gauge.take() {
            points.push((
                self.series.source(targets, before_targets),
                self.series
                    .point(MetricKind::Gauge, MetricValue::F64 { value }, timestamp_ns),
            ));
        }
    }
}

impl metrics::CounterFn for BridgedHandle {
    fn increment(&self, value: u64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        self.slot(before_targets)
            .counter
            .total
            .fetch_add(value, Ordering::Relaxed);
        if !self.cached {
            self.send(Sample::Counter(value), before_targets);
        }
    }

    fn absolute(&self, value: u64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        // The counter is the sum of both slots; raise it to at least `value`.
        let other = self
            .slot(!before_targets)
            .counter
            .total
            .load(Ordering::Relaxed);
        let target = value.saturating_sub(other);
        let previous = self
            .slot(before_targets)
            .counter
            .total
            .fetch_max(target, Ordering::Relaxed);
        if !self.cached && target > previous {
            self.send(Sample::Counter(target - previous), before_targets);
        }
    }
}

impl metrics::GaugeFn for BridgedHandle {
    fn increment(&self, value: f64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        let current = self.gauge.update(|gauge| gauge + value);
        self.gauge_written(current, before_targets);
    }

    fn decrement(&self, value: f64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        let current = self.gauge.update(|gauge| gauge - value);
        self.gauge_written(current, before_targets);
    }

    fn set(&self, value: f64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        self.gauge.bits.store(value.to_bits(), Ordering::Release);
        self.gauge_written(value, before_targets);
    }
}

impl metrics::HistogramFn for BridgedHandle {
    fn record(&self, value: f64) {
        let Some(before_targets) = self.admit() else {
            return;
        };
        if self.cached {
            self.slot(before_targets).histogram.lock().record(value);
        } else {
            self.send(Sample::Histogram(value), before_targets);
        }
    }
}

/// App-level handle returned from `new_bridge`. Call `attach` after
/// the runtime is up to start the forwarder. Samples recorded before
/// attach aggregate in their series (the queued samples of uncached
/// series buffer up to the channel capacity). The per-plugin filters
/// map is supplied at attach time, after the gateway has parsed
/// `config.plugins[].observability` into the routing shape.
pub struct MetricsBridgeHandle {
    rx: Option<mpsc::Receiver<BridgedMetric>>,
    series: Arc<SeriesCache>,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    target_to_plugin_id: SharedTargetMap,
}

impl MetricsBridgeHandle {
    /// Spawn the forwarder, which flushes every [`FLUSH_INTERVAL`] and
    /// delivers the queued samples of uncached series. Returns the
    /// flusher that `/metrics` and shutdown flush through.
    pub fn attach(
        mut self,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    ) -> Option<MetricsFlusher> {
        let rx = self.rx.take()?;
        let flusher = self.flusher(runtime, per_plugin_filters);
        tokio::spawn(forward_metrics(rx, Arc::clone(&flusher.0), FLUSH_INTERVAL));
        Some(flusher)
    }

    fn flusher(
        &self,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    ) -> MetricsFlusher {
        MetricsFlusher(Arc::new(Forwarder {
            series: Arc::clone(&self.series),
            runtime,
            target_to_plugin_id: Arc::clone(&self.target_to_plugin_id),
            global_allowed_plugin_ids: Arc::clone(&self.global_allowed_plugin_ids),
            per_plugin_filters,
            flushing: tokio::sync::Mutex::new(()),
            closed: AtomicBool::new(false),
            stop: tokio::sync::Notify::new(),
        }))
    }
}

/// Delivers what the cached series aggregated to the metrics sinks.
/// Clones share one forwarder.
#[derive(Clone)]
pub struct MetricsFlusher(Arc<Forwarder>);

impl MetricsFlusher {
    /// Deliver what the series aggregated since the last flush.
    pub async fn flush(&self) {
        self.spawn_flush(false).await;
    }

    /// The final flush: deliver the last interval, and nothing after it.
    pub async fn close(&self) {
        self.spawn_flush(true).await;
    }

    /// A flush takes the aggregates before it delivers them, so it runs
    /// on a task of its own: a caller that stops waiting loses nothing.
    async fn spawn_flush(&self, close: bool) {
        let forwarder = Arc::clone(&self.0);
        let _ = tokio::spawn(async move { forwarder.flush(close).await }).await;
    }
}

struct Forwarder {
    series: Arc<SeriesCache>,
    runtime: Arc<ArcSwap<GatewayRuntime>>,
    target_to_plugin_id: SharedTargetMap,
    global_allowed_plugin_ids: Arc<HashSet<String>>,
    per_plugin_filters: Arc<HashMap<String, SignalFilter>>,
    /// Held through a flush: a series' points reach a sink in order, and
    /// a counter's `delivered` has one writer.
    flushing: tokio::sync::Mutex<()>,
    /// Set by the final flush.
    closed: AtomicBool,
    /// Wakes the forwarder task after the final flush, so it ends.
    stop: tokio::sync::Notify,
}

impl Forwarder {
    async fn flush(&self, close: bool) {
        let _flushing = self.flushing.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        drain_metrics_bridge_overflows();
        let targets = self.target_to_plugin_id.load_full();
        let mut points = Vec::new();
        self.series.take_points(&targets, now_ns(), &mut points);
        if close {
            self.closed.store(true, Ordering::Release);
            self.stop.notify_one();
        }
        let runtime = self.runtime.load_full();
        for (source, point) in &points {
            self.deliver(&runtime, source, point).await;
        }
    }

    /// Deliver one queued sample of an uncached series.
    async fn deliver_sample(&self, msg: BridgedMetric) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        drain_metrics_bridge_overflows();
        let targets = self.target_to_plugin_id.load_full();
        let runtime = self.runtime.load_full();
        self.deliver(&runtime, msg.source_plugin_id(&targets), &msg.to_point())
            .await;
    }

    /// Gate (enabled) + sink redirection by the point's source plugin id.
    /// Metrics has no level (event_level: None), so the level floor is ignored.
    async fn deliver(&self, runtime: &GatewayRuntime, source: &str, point: &MetricPoint) {
        let decision = route_event(
            source,
            &self.per_plugin_filters,
            None,
            &self.global_allowed_plugin_ids,
        );
        let sinks = match &decision {
            RouteDecision::Drop(reason) => {
                // One per dropped point, so operators can tell intentional
                // filtering apart from a bug.
                metrics::counter!(
                    "mcpg_observability_dropped_total",
                    "source_plugin_id" => source.to_owned(),
                    "signal" => "metrics",
                    "reason" => reason.as_label(),
                )
                .increment(1);
                return;
            }
            RouteDecision::UseGlobal => self.global_allowed_plugin_ids.as_ref(),
            RouteDecision::Override(sinks) => sinks,
        };
        dispatch_guard::with_scope(
            runtime
                .plugin_registry()
                .emit_metric_event_filtered(point, sinks),
        )
        .await;
    }
}

/// Forwarder task body: flushes every `interval` and delivers the
/// queued samples of uncached series as they arrive, until the final
/// flush. Routes through the runtime snapshot of each delivery, so
/// reload-time changes to plugin registrations are picked up.
async fn forward_metrics(
    mut rx: mpsc::Receiver<BridgedMetric>,
    forwarder: Arc<Forwarder>,
    interval: Duration,
) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut queue_open = true;
    while !forwarder.closed.load(Ordering::Acquire) {
        tokio::select! {
            msg = rx.recv(), if queue_open => match msg {
                Some(msg) => forwarder.deliver_sample(msg).await,
                None => queue_open = false,
            },
            _ = ticks.tick() => forwarder.flush(false).await,
            () = forwarder.stop.notified() => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use mcpg_plugin_protocol::{
        PluginClass, PluginManifest, PluginTier,
        metrics::{MetricsError, MetricsSink},
    };

    use super::*;
    use crate::observability::signal_router::{SinkMode, new_target_map, swap_target_map};

    const GLOBAL_SINK: &str = "dev.test.metrics.global";
    const B_SINK: &str = "dev.test.metrics.b";

    fn meta(module_path: Option<&'static str>) -> Metadata<'static> {
        Metadata::new("t", metrics::Level::INFO, module_path)
    }

    fn targets_of(pairs: &[(&str, &str)]) -> SharedTargetMap {
        let map = pairs
            .iter()
            .map(|(prefix, id)| ((*prefix).to_owned(), (*id).to_owned()))
            .collect::<HashMap<_, _>>();
        Arc::new(ArcSwap::from_pointee(map))
    }

    /// The points a flush would deliver now, with their source plugin ids.
    fn take(rec: &PluginMetricsRecorder) -> Vec<(String, MetricPoint)> {
        let targets = rec.targets.load_full();
        let mut points = Vec::new();
        rec.series.take_points(&targets, 0, &mut points);
        points
            .into_iter()
            .map(|(source, point)| (source.to_owned(), point))
            .collect()
    }

    fn drain(rx: &mut mpsc::Receiver<BridgedMetric>) -> Vec<BridgedMetric> {
        let mut out = Vec::new();
        while let Ok(p) = rx.try_recv() {
            out.push(p);
        }
        out
    }

    fn values(points: &[(String, MetricPoint)]) -> Vec<(&str, MetricValue)> {
        points
            .iter()
            .map(|(source, point)| (source.as_str(), point.value.clone()))
            .collect()
    }

    /// A recorder whose series cache is full, so every handle is uncached.
    fn uncached_recorder(
        capacity: usize,
    ) -> (PluginMetricsRecorder, mpsc::Receiver<BridgedMetric>) {
        let (tx, rx) = mpsc::channel::<BridgedMetric>(capacity);
        let recorder = PluginMetricsRecorder {
            tx,
            series: Arc::new(SeriesCache {
                len: AtomicUsize::new(MAX_CACHED_SERIES),
                ..SeriesCache::default()
            }),
            targets: new_target_map(),
        };
        (recorder, rx)
    }

    /// What a Prometheus-style sink keeps: counter sums, the last gauge
    /// value, and histogram count and sum.
    #[derive(Default)]
    struct Totals {
        counters: HashMap<String, i64>,
        gauges: HashMap<String, f64>,
        histograms: HashMap<String, (u64, f64)>,
        largest_sample: usize,
    }

    struct TotalsSink {
        manifest: PluginManifest,
        totals: Arc<std::sync::Mutex<Totals>>,
    }

    #[mcpg_plugin_protocol::async_trait]
    impl MetricsSink for TotalsSink {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }

        async fn emit(&self, metric: &MetricPoint) {
            let mut totals = self.totals.lock().unwrap();
            let name = metric.name.clone();
            match (&metric.kind, &metric.value) {
                (MetricKind::Counter, MetricValue::I64 { value }) => {
                    *totals.counters.entry(name).or_default() += value;
                }
                (MetricKind::Gauge, MetricValue::F64 { value }) => {
                    totals.gauges.insert(name, *value);
                }
                (
                    MetricKind::Histogram,
                    MetricValue::Histogram {
                        count,
                        sum,
                        observations,
                    },
                ) => {
                    let histogram = totals.histograms.entry(name).or_default();
                    histogram.0 += count;
                    histogram.1 += sum;
                    totals.largest_sample = totals.largest_sample.max(observations.len());
                }
                other => panic!("unexpected point {other:?}"),
            }
        }

        async fn flush(&self, _: Duration) -> Result<(), MetricsError> {
            Ok(())
        }
    }

    type SharedTotals = Arc<std::sync::Mutex<Totals>>;

    /// A runtime whose registry holds one totals sink per id.
    fn runtime_with_sinks(ids: &[&str]) -> (Arc<ArcSwap<GatewayRuntime>>, Vec<SharedTotals>) {
        let mut registry = mcpg_plugin_host::PluginRegistry::new();
        let mut all = Vec::new();
        for id in ids {
            let totals = SharedTotals::default();
            let sink = TotalsSink {
                manifest: PluginManifest {
                    id: (*id).to_owned(),
                    version: "0.1.0".into(),
                    name: (*id).to_owned(),
                    plugin_class: PluginClass::MetricsSink,
                    protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION.into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: String::new(),
                    backend_profile: None,
                },
                totals: Arc::clone(&totals),
            };
            registry
                .register_metrics_sink(Arc::new(sink), PluginTier::Native)
                .unwrap();
            all.push(totals);
        }
        let mut runtime = GatewayRuntime::new(
            "mcpg",
            "0.1.0",
            "127.0.0.1:0",
            "/health",
            "/mcp",
            "info",
            Vec::new(),
            true,
        );
        runtime.replace_gate_registry_for_test(Arc::new(registry));
        (Arc::new(ArcSwap::from_pointee(runtime)), all)
    }

    fn global_only() -> Arc<HashSet<String>> {
        Arc::new(HashSet::from([GLOBAL_SINK.to_owned()]))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sinks_receive_exact_totals_far_past_the_channel_capacity() {
        const THREADS: u64 = 8;
        const ROUNDS: u64 = 25_000;
        let (runtime, totals) = runtime_with_sinks(&[GLOBAL_SINK, B_SINK]);
        let targets = targets_of(&[
            ("plugin_a", "dev.test.plugin.a"),
            ("plugin_b", "dev.test.plugin.b"),
        ]);
        let (rec, mut handle) = new_bridge(global_only(), targets);
        // Plugin b's points go only to its own sink; plugin a's to the global one.
        let filters = HashMap::from([(
            "dev.test.plugin.b".to_owned(),
            SignalFilter {
                mode: SinkMode::Replace,
                sinks: vec![B_SINK.to_owned()],
                ..SignalFilter::default()
            },
        )]);
        let flusher = handle.flusher(runtime, Arc::new(filters));
        let forwarder = tokio::spawn(forward_metrics(
            handle.rx.take().unwrap(),
            Arc::clone(&flusher.0),
            Duration::from_millis(5),
        ));

        rec.register_gauge(&Key::from_name("inflight"), &meta(Some("plugin_a::calls")))
            .set(1000.0);
        let emitters: Vec<_> = (0..THREADS)
            .map(|_| {
                let rec = rec.clone();
                tokio::task::spawn_blocking(move || {
                    let (a, b) = (meta(Some("plugin_a::calls")), meta(Some("plugin_b::calls")));
                    for round in 0..ROUNDS {
                        let (calls, inflight, latency) = (
                            Key::from_name("calls_total"),
                            Key::from_name("inflight"),
                            Key::from_name("latency_ms"),
                        );
                        rec.register_counter(&calls, &a).increment(1);
                        rec.register_counter(&calls, &b).increment(2);
                        rec.register_gauge(&inflight, &a).increment(1.0);
                        rec.register_gauge(&inflight, &b).decrement(1.0);
                        rec.register_histogram(&latency, &a)
                            .record((round % 10) as f64);
                        rec.register_histogram(&latency, &b).record(1.0);
                    }
                })
            })
            .collect();
        for emitter in emitters {
            emitter.await.unwrap();
        }
        flusher.close().await;
        forwarder.await.unwrap();

        let samples = THREADS * ROUNDS;
        assert!(samples > BRIDGE_CHANNEL_CAPACITY as u64 * 10);
        let a = totals[0].lock().unwrap();
        assert_eq!(a.counters["calls_total"], samples as i64);
        assert_eq!(a.gauges["inflight"], 1000.0 + samples as f64);
        assert_eq!(
            a.histograms["latency_ms"],
            (samples, (samples / 10 * 45) as f64)
        );
        assert!(a.largest_sample <= MAX_OBSERVATIONS);
        let b = totals[1].lock().unwrap();
        assert_eq!(b.counters["calls_total"], 2 * samples as i64);
        assert_eq!(b.gauges["inflight"], -(samples as f64));
        assert_eq!(b.histograms["latency_ms"], (samples, samples as f64));
        assert!(b.largest_sample <= MAX_OBSERVATIONS);
    }

    #[test]
    fn a_gauge_point_carries_the_value_after_set_increment_and_decrement() {
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let gauge = rec.register_gauge(&Key::from_name("active_sessions"), &meta(None));
        gauge.set(10.0);
        gauge.increment(5.0);
        gauge.decrement(2.0);
        assert_eq!(
            values(&take(&rec)),
            [("core", MetricValue::F64 { value: 13.0 })]
        );
        gauge.decrement(1.0);
        assert_eq!(
            values(&take(&rec)),
            [("core", MetricValue::F64 { value: 12.0 })]
        );
        assert!(
            take(&rec).is_empty(),
            "an unchanged gauge is not sent again"
        );
    }

    #[test]
    fn an_uncached_gauge_queues_its_value_not_the_change() {
        let (rec, mut rx) = uncached_recorder(16);
        let gauge = rec.register_gauge(&Key::from_name("active_sessions"), &meta(None));
        gauge.set(3.0);
        gauge.increment(2.0);
        gauge.decrement(4.0);
        let queued: Vec<_> = drain(&mut rx)
            .iter()
            .map(|msg| msg.to_point().value)
            .collect();
        assert_eq!(
            queued,
            [3.0, 5.0, 1.0].map(|value| MetricValue::F64 { value })
        );
    }

    #[tokio::test]
    async fn the_final_flush_delivers_the_last_interval_and_nothing_after_it() {
        let (runtime, totals) = runtime_with_sinks(&[GLOBAL_SINK]);
        let (rec, mut handle) = new_bridge(global_only(), new_target_map());
        let flusher = handle.flusher(runtime, Arc::default());
        let forwarder = tokio::spawn(forward_metrics(
            handle.rx.take().unwrap(),
            Arc::clone(&flusher.0),
            Duration::from_secs(3600),
        ));
        let m = meta(None);
        rec.register_counter(&Key::from_name("calls_total"), &m)
            .increment(3);
        rec.register_gauge(&Key::from_name("inflight"), &m).set(2.0);
        rec.register_histogram(&Key::from_name("latency_ms"), &m)
            .record(7.0);

        flusher.close().await;
        {
            let totals = totals[0].lock().unwrap();
            assert_eq!(totals.counters.get("calls_total"), Some(&3));
            assert_eq!(totals.gauges.get("inflight"), Some(&2.0));
            assert_eq!(totals.histograms.get("latency_ms"), Some(&(1, 7.0)));
        }
        tokio::time::timeout(Duration::from_secs(10), forwarder)
            .await
            .expect("the forwarder stops after the final flush")
            .unwrap();

        rec.register_counter(&Key::from_name("calls_total"), &m)
            .increment(1);
        flusher.flush().await;
        assert_eq!(totals[0].lock().unwrap().counters["calls_total"], 3);
    }

    #[tokio::test]
    async fn the_forwarder_flushes_on_its_interval() {
        let (runtime, totals) = runtime_with_sinks(&[GLOBAL_SINK]);
        let (rec, mut handle) = new_bridge(global_only(), new_target_map());
        let flusher = handle.flusher(runtime, Arc::default());
        tokio::spawn(forward_metrics(
            handle.rx.take().unwrap(),
            Arc::clone(&flusher.0),
            Duration::from_millis(10),
        ));
        rec.register_counter(&Key::from_name("calls_total"), &meta(None))
            .increment(4);
        tokio::time::timeout(Duration::from_secs(10), async {
            while totals[0].lock().unwrap().counters.get("calls_total") != Some(&4) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a periodic flush delivers the counter");
        flusher.close().await;
    }

    #[test]
    fn counter_increments_aggregate_into_one_point_with_core_source() {
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let key = Key::from_parts("requests_total", vec![metrics::Label::new("path", "/x")]);
        let counter = rec.register_counter(&key, &meta(None));
        counter.increment(3);
        counter.increment(4);
        let points = take(&rec);
        assert_eq!(points.len(), 1);
        let (source, point) = &points[0];
        assert_eq!(source, "core");
        assert_eq!(point.name, "requests_total");
        assert_eq!(
            point.labels,
            BTreeMap::from([("path".to_owned(), "/x".to_owned())])
        );
        assert_eq!(point.kind, MetricKind::Counter);
        assert_eq!(point.value, MetricValue::I64 { value: 7 });
        assert!(take(&rec).is_empty(), "nothing new, nothing sent");
    }

    #[test]
    fn counter_absolute_raises_the_total_to_at_least_the_value() {
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let counter = rec.register_counter(&Key::from_name("synced_total"), &meta(None));
        counter.increment(30);
        counter.absolute(100);
        assert_eq!(
            values(&take(&rec)),
            [("core", MetricValue::I64 { value: 100 })]
        );
        counter.absolute(50);
        assert!(take(&rec).is_empty(), "absolute never lowers a counter");
        counter.increment(5);
        counter.absolute(104);
        assert_eq!(
            values(&take(&rec)),
            [("core", MetricValue::I64 { value: 5 })]
        );
    }

    #[test]
    fn an_increase_past_i64_max_is_delivered_over_several_flushes() {
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        rec.register_counter(&Key::from_name("ops"), &meta(None))
            .increment(u64::MAX);
        let mut delivered: u64 = 0;
        for expected in [i64::MAX, i64::MAX, 1] {
            assert_eq!(
                values(&take(&rec)),
                [("core", MetricValue::I64 { value: expected })]
            );
            delivered += expected.unsigned_abs();
        }
        assert!(take(&rec).is_empty());
        assert_eq!(delivered, u64::MAX);
    }

    #[test]
    fn a_histogram_point_has_the_exact_count_and_sum_and_a_bounded_sample() {
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let histogram = rec.register_histogram(&Key::from_name("latency_ms"), &meta(None));
        for value in 0..10_000 {
            histogram.record(f64::from(value));
        }
        let points = take(&rec);
        let [(_, point)] = points.as_slice() else {
            panic!("one point expected, got {points:?}");
        };
        assert_eq!(point.kind, MetricKind::Histogram);
        let MetricValue::Histogram {
            count,
            sum,
            observations,
        } = &point.value
        else {
            panic!("expected Histogram, got {:?}", point.value);
        };
        assert_eq!(*count, 10_000);
        assert_eq!(*sum, 49_995_000.0);
        assert_eq!(observations.len(), MAX_OBSERVATIONS);
        assert!(observations.iter().all(|v| (0.0..10_000.0).contains(v)));
        assert!(
            observations.iter().any(|v| *v >= MAX_OBSERVATIONS as f64),
            "the sample spans the interval, not its first observations"
        );

        histogram.record(42.0);
        assert_eq!(
            values(&take(&rec)),
            [(
                "core",
                MetricValue::Histogram {
                    count: 1,
                    sum: 42.0,
                    observations: vec![42.0],
                }
            )]
        );
    }

    #[tokio::test]
    async fn metric_emitted_during_sink_dispatch_is_not_recorded() {
        // A metric produced while the dispatch guard is in scope is
        // self-referential (the dispatch-accounting counters, sink-internal
        // emits); recording it would feed the sinks their own output.
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let m = meta(None);
        let counter = rec.register_counter(&Key::from_name("mcpg_metrics_sink_records_total"), &m);
        let gauge = rec.register_gauge(&Key::from_name("gauge"), &m);
        let histogram = rec.register_histogram(&Key::from_name("histogram"), &m);

        counter.increment(1);
        assert_eq!(
            take(&rec).len(),
            1,
            "a metric outside a sink dispatch is recorded"
        );

        dispatch_guard::with_scope(async {
            counter.increment(1);
            gauge.set(1.0);
            histogram.record(1.0);
        })
        .await;
        assert!(
            take(&rec).is_empty(),
            "a metric emitted during a sink dispatch must be dropped"
        );
    }

    #[test]
    fn module_path_resolves_via_target_map_to_plugin_id() {
        let targets = targets_of(&[(
            "mcpg_plugin_observability_audit",
            "dev.mcpg.observability.audit",
        )]);
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), targets);
        rec.register_counter(
            &Key::from_name("emit_total"),
            &meta(Some("mcpg_plugin_observability_audit::write")),
        )
        .increment(1);
        assert_eq!(
            values(&take(&rec)),
            [(
                "dev.mcpg.observability.audit",
                MetricValue::I64 { value: 1 }
            )]
        );
    }

    #[test]
    fn a_sample_emitted_before_the_target_map_fills_is_the_gateways() {
        let targets = new_target_map();
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), Arc::clone(&targets));
        let m = meta(Some("mcpg_plugin_observability_audit::write"));
        let counter = rec.register_counter(&Key::from_name("emit_total"), &m);
        let gauge = rec.register_gauge(&Key::from_name("depth"), &m);
        counter.increment(1);
        gauge.set(1.0);
        swap_target_map(
            &targets,
            HashMap::from([(
                "mcpg_plugin_observability_audit".to_owned(),
                "dev.mcpg.observability.audit".to_owned(),
            )]),
        );
        counter.increment(2);

        let taken = take(&rec);
        let points = values(&taken);
        let expected = [
            ("core", MetricValue::I64 { value: 1 }),
            ("core", MetricValue::F64 { value: 1.0 }),
            (
                "dev.mcpg.observability.audit",
                MetricValue::I64 { value: 2 },
            ),
        ];
        assert_eq!(points.len(), expected.len(), "{points:?}");
        for point in &expected {
            assert!(points.contains(point), "{point:?} missing from {points:?}");
        }

        gauge.increment(1.0);
        assert_eq!(
            values(&take(&rec)),
            [(
                "dev.mcpg.observability.audit",
                MetricValue::F64 { value: 2.0 }
            )]
        );
    }

    #[test]
    fn register_returns_one_cached_series_per_key_and_module_path() {
        let targets = targets_of(&[(
            "mcpg_plugin_observability_audit",
            "dev.mcpg.observability.audit",
        )]);
        let (rec, _handle) = new_bridge(Arc::new(HashSet::new()), targets);
        let key = || Key::from_parts("calls_total", vec![metrics::Label::new("tool", "echo")]);
        let core = meta(Some("mcpg::runtime"));
        let plugin = meta(Some("mcpg_plugin_observability_audit::write"));

        assert!(
            Arc::ptr_eq(&rec.handle(&key(), &core), &rec.handle(&key(), &core)),
            "the same key from the same module path reuses its series"
        );
        assert!(
            !Arc::ptr_eq(&rec.handle(&key(), &core), &rec.handle(&key(), &plugin)),
            "another module path gets its own series"
        );
        rec.register_counter(&key(), &core).increment(1);
        rec.register_histogram(&key(), &core).record(0.5);
        rec.register_counter(&key(), &plugin).increment(1);

        let mut points: Vec<_> = take(&rec)
            .into_iter()
            .map(|(source, point)| (source, point.kind))
            .collect();
        points.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        assert_eq!(
            points,
            [
                ("core".to_owned(), MetricKind::Counter),
                ("core".to_owned(), MetricKind::Histogram),
                (
                    "dev.mcpg.observability.audit".to_owned(),
                    MetricKind::Counter
                ),
            ]
        );
        assert_eq!(rec.series.len.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_full_series_cache_hands_out_uncached_handles() {
        let (rec, mut handle) = new_bridge(Arc::new(HashSet::new()), new_target_map());
        let m = meta(None);
        let key = |i: usize| {
            Key::from_parts("calls_total", vec![metrics::Label::new("n", i.to_string())])
        };
        for i in 0..MAX_CACHED_SERIES {
            drop(rec.register_counter(&key(i), &m));
        }
        assert_eq!(rec.series.len.load(Ordering::Relaxed), MAX_CACHED_SERIES);

        rec.register_counter(&key(MAX_CACHED_SERIES), &m)
            .increment(1);
        rec.register_counter(&key(MAX_CACHED_SERIES), &m)
            .increment(2);
        rec.register_histogram(&key(MAX_CACHED_SERIES), &m)
            .record(42.0);

        let queued = drain(handle.rx.as_mut().unwrap());
        assert_eq!(queued.len(), 3, "an uncached handle still delivers");
        assert!(!Arc::ptr_eq(&queued[0].series, &queued[1].series));
        assert_eq!(
            queued
                .iter()
                .map(BridgedMetric::to_point)
                .map(|p| p.value)
                .collect::<Vec<_>>(),
            [
                MetricValue::I64 { value: 1 },
                MetricValue::I64 { value: 2 },
                MetricValue::Histogram {
                    count: 1,
                    sum: 42.0,
                    observations: vec![42.0],
                },
            ]
        );
        assert_eq!(queued[0].source_plugin_id(&HashMap::new()), "core");
        assert!(take(&rec).is_empty(), "uncached samples are not aggregated");
        assert_eq!(rec.series.len.load(Ordering::Relaxed), MAX_CACHED_SERIES);
    }

    #[test]
    fn channel_overflow_drops_silently() {
        // Overflow does not go via metrics::counter! (an uncached
        // overflow counter would recurse through the saturated channel);
        // it accumulates in the METRICS_BRIDGE_OVERFLOWS atomic instead.
        let baseline = METRICS_BRIDGE_OVERFLOWS.load(Ordering::Relaxed);
        let (rec, mut rx) = uncached_recorder(1);
        let c = rec.register_counter(&Key::from_name("ops"), &meta(None));
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
        let overflows = METRICS_BRIDGE_OVERFLOWS.load(Ordering::Relaxed) - baseline;
        assert!(
            overflows >= 9,
            "expected ≥9 overflows accumulated, got {overflows}"
        );
    }
}
