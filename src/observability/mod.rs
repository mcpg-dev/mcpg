//! Observability stack — structured logging, plugin-driven metrics,
//! and plugin-driven OpenTelemetry tracing.
//!
//! Multi-sink log dispatch: each sink in
//! `observability.logs.sinks: [...]` becomes its own
//! `tracing_subscriber::fmt::Layer` with an independent format
//! (`json` / `pretty`), writer (`stderr` / `stdout` / `file`), and
//! per-sink level filter (`sink.level` falls back to `logs.level`).
//!
//! There is no in-gateway OTLP exporter — operators who want OTLP
//! span export declare `dev.mcpg.observability.otlp` in `plugins[]`,
//! and the loader registers the signed cdylib via
//! [`FirstPartyRegistrar`] when the operator lists its id in
//! `observability.traces.sinks[].kind`. The [`telemetry_bridge`]
//! then routes gateway spans into the plugin's tracer provider for
//! OTLP export.
//!
//! Metrics work the same way: there is no in-gateway Prometheus
//! exporter. The [`metrics_bridge::PluginMetricsRecorder`] is the
//! `metrics-rs` global recorder; every `counter!` / `gauge!` /
//! `histogram!` call aggregates into its series, and the bridge
//! delivers one `MetricPoint` per series and flush to every
//! operator-listed `MetricsSink` plugin. The canonical Prometheus plugin
//! (`dev.mcpg.observability.prometheus`) accumulates events into
//! its own in-memory registry and renders text-exposition v0.0.4
//! through the `MetricsSink::render_text_exposition` slot —
//! the gateway's `/metrics` route just delegates to that.
//!
//! Plugin sinks (any `kind:` outside the built-in factory set
//! `stderr` / `stdout` / `file`) flow through the [`log_bridge`],
//! [`telemetry_bridge`], and [`metrics_bridge`] layers. Each bridge
//! receives the per-signal allow-list of plugin ids and routes only
//! to the `LogSink` / `TelemetrySink` / `MetricsSink` plugins whose
//! `manifest.id` appears in their signal's `sinks[].kind`.
//! Plugins not listed by the operator are silently skipped —
//! config controls fan-out.

/// Ids of the first-party observability plugins the gateway looks up in the
/// plugin registry. The gateway does NOT link these — they ship as signed
/// cdylibs, and an operator enables one by declaring the artifact in
/// `plugins[]`. Only the id is needed here: `/metrics` rendering asks the
/// registry for the sink registered under it.
pub const PROMETHEUS_PLUGIN_ID: &str = "dev.mcpg.observability.prometheus";
/// See [`PROMETHEUS_PLUGIN_ID`]; the canonical span exporter's id.
pub const OTLP_PLUGIN_ID: &str = "dev.mcpg.observability.otlp";

pub(crate) mod dispatch_guard;
mod json_format;
pub mod log_bridge;
pub mod metrics_bridge;
pub mod signal_router;
pub mod telemetry_bridge;

use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{self, Write},
    mem,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use tracing::{Metadata, level_filters::LevelFilter, subscriber::Interest};
use tracing_subscriber::{
    EnvFilter, Layer, fmt, fmt::MakeWriter, layer::SubscriberExt, registry::Registry,
    util::SubscriberInitExt,
};

use crate::config::{LogsConfig, ObservabilityConfig, SinkConfig};

static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();
/// Held from the check of [`LOGGING_INITIALIZED`] to its set, so two boots
/// in one process never both install the global subscriber.
static LOGGING_INIT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Built-in sink kinds dispatched in-gateway. The set is limited
/// to OS-stream emitters only (`stderr` / `stdout` / `file`) —
/// `otlp` and `prometheus` are opt-in via the
/// `dev.mcpg.observability.{otlp, prometheus}` plugin ids
/// registered through [`FirstPartyRegistrar`]. Anything outside
/// this set is treated as a plugin id and routed through the
/// log / telemetry bridges.
const BUILTIN_SINK_KINDS: &[&str] = &["stderr", "stdout", "file"];

/// Per-layer filter in front of a bridge layer. Open, the bridge sees every
/// span and event; closed, it sees none, and its `OFF` hint lets a callsite
/// that no other layer enables (DEBUG under an `info` stderr sink) be
/// disabled at the callsite instead of being built for nobody.
#[derive(Clone)]
struct BridgeGate(Arc<AtomicBool>);

impl Default for BridgeGate {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl BridgeGate {
    fn is_open(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// A change rebuilds the callsite interest cache: cached interest and the
    /// global max level would otherwise keep the old state.
    fn set_open(&self, open: bool) {
        if self.0.swap(open, Ordering::Relaxed) != open {
            tracing::callsite::rebuild_interest_cache();
        }
    }
}

impl<S> tracing_subscriber::layer::Filter<S> for BridgeGate {
    fn enabled(&self, _: &Metadata<'_>, _: &tracing_subscriber::layer::Context<'_, S>) -> bool {
        self.is_open()
    }

    fn callsite_enabled(&self, _: &'static Metadata<'static>) -> Interest {
        if self.is_open() {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(if self.is_open() {
            LevelFilter::TRACE
        } else {
            LevelFilter::OFF
        })
    }
}

/// Owns the three bridge handles (logs / traces / metrics) that
/// are consumed by `attach_*_bridge` once the runtime is up.
///
/// There is no in-gateway OTel `SdkTracerProvider` field — span
/// export lives in the `dev.mcpg.observability.otlp` plugin — and
/// no `metrics-exporter-prometheus` recorder handle. The metrics-rs
/// global recorder is the [`metrics_bridge::PluginMetricsRecorder`],
/// which fans every emit out to operator-listed `MetricsSink`
/// plugins; the canonical Prometheus plugin renders `/metrics` from
/// its own accumulator via the `render_text_exposition` slot.
#[derive(Default)]
pub struct ObservabilityHandle {
    /// tracing→LogSink bridge handle. `Some` on the
    /// first `init()` call; `attach_log_bridge` consumes it and
    /// spawns the forwarder task. `None` after attach, or when
    /// logging was already initialised by a prior `init()`.
    log_bridge: Option<log_bridge::PluginLogBridgeHandle>,
    /// tracing-span→TelemetrySink bridge handle. Same
    /// consume-on-attach pattern as `log_bridge`.
    telemetry_bridge: Option<telemetry_bridge::PluginTelemetryBridgeHandle>,
    /// metrics-rs→MetricsSink bridge handle.
    /// `Some` when the operator opted at least one metrics sink
    /// in (and the global recorder install succeeded); `None`
    /// when metrics is disabled, the sinks list is empty, or the
    /// recorder slot was already claimed (test harness reentry).
    metrics_bridge: Option<metrics_bridge::MetricsBridgeHandle>,
    /// Flushes the aggregated metrics to the sinks; `Some` once
    /// `attach_metrics_bridge` started the forwarder.
    metrics_flusher: Option<metrics_bridge::MetricsFlusher>,
    /// Shared `target_prefix → plugin_id` map used
    /// by all three bridges + the metrics recorder. Empty at
    /// init; gateway boot calls `populate_target_map` after
    /// plugin registration to install the resolved values.
    target_to_plugin_id: signal_router::SharedTargetMap,
    /// Install-once slot for an off-box log-capture sink (CP log shipping).
    /// The log bridge layer reads it per event; `set_log_sink` installs one
    /// once the cp-attach agent exists. Empty (no-op) otherwise.
    log_sink: log_bridge::SharedLogSink,
    /// Filter in front of the log bridge layer. Open until attach, so
    /// boot events queue for the sinks; closed at attach when nothing
    /// consumes a record.
    log_gate: BridgeGate,
    /// Filter in front of the telemetry bridge layer; see `log_gate`.
    telemetry_gate: BridgeGate,
}

impl ObservabilityHandle {
    /// Populate the `target_prefix → plugin_id`
    /// map after plugin registration. Iterates every registered
    /// plugin's manifest, harvesting `module_path_prefix` →
    /// `manifest.id` pairs (skipping plugins that didn't fill
    /// the field), then atomically swaps the resolved map into
    /// the shared `ArcSwap`.
    ///
    /// Subsequent metric handle registrations + tracing events
    /// resolve their source plugin id via the populated map.
    /// Calling this with a fresh registry effectively clears any
    /// prior mapping (e.g. after a `reload_config` swaps the
    /// runtime).
    /// Install the off-box log-capture sink (CP log shipping). Idempotent
    /// install-once: a second call is a no-op. Returns `true` when installed.
    /// Opens the log gate, so the bridge layer sees every event again.
    pub fn set_log_sink(&self, sink: Arc<dyn log_bridge::LogSink>) -> bool {
        let installed = self.log_sink.set(sink).is_ok();
        self.log_gate.set_open(true);
        installed
    }

    pub fn populate_target_map(&self, registry: &mcpg_plugin_host::PluginRegistry) {
        let mut map: HashMap<String, String> = HashMap::new();
        for manifest in registry.iter_manifests() {
            if manifest.module_path_prefix.is_empty() {
                continue;
            }
            // Iter may yield the same plugin multiple times
            // (http_route entities share one manifest); insert is
            // idempotent on identical (prefix, id) pairs.
            map.insert(manifest.module_path_prefix.clone(), manifest.id.clone());
        }
        signal_router::swap_target_map(&self.target_to_plugin_id, map);
    }

    /// Connect the tracing→LogSink bridge to the live
    /// runtime so tracing events start flowing through the
    /// per-signal plugin-id allow-list to every operator-listed
    /// log sink. `per_plugin_filters` carries the routing rules
    /// derived from `config.plugins[].observability.logs`.
    pub fn attach_log_bridge(
        &mut self,
        runtime: std::sync::Arc<arc_swap::ArcSwap<crate::runtime::GatewayRuntime>>,
        per_plugin_filters: std::sync::Arc<HashMap<String, signal_router::SignalFilter>>,
    ) {
        if let Some(handle) = self.log_bridge.take() {
            let consumed =
                handle.feeds_plugins(&per_plugin_filters) || self.log_sink.get().is_some();
            handle.attach(runtime, per_plugin_filters);
            if !consumed {
                self.log_gate.set_open(false);
            }
        }
    }

    /// Connect the tracing-span→TelemetrySink bridge to
    /// the live runtime. `per_plugin_filters` carries the routing
    /// rules derived from
    /// `config.plugins[].observability.traces`.
    pub fn attach_telemetry_bridge(
        &mut self,
        runtime: std::sync::Arc<arc_swap::ArcSwap<crate::runtime::GatewayRuntime>>,
        per_plugin_filters: std::sync::Arc<HashMap<String, signal_router::SignalFilter>>,
    ) {
        if let Some(handle) = self.telemetry_bridge.take() {
            let consumed = handle.feeds_plugins(&per_plugin_filters);
            handle.attach(runtime, per_plugin_filters);
            if !consumed {
                self.telemetry_gate.set_open(false);
            }
        }
    }

    /// Connect the metrics-rs→MetricsSink bridge
    /// to the live runtime. `per_plugin_filters` carries the
    /// routing rules derived from
    /// `config.plugins[].observability.metrics`.
    pub fn attach_metrics_bridge(
        &mut self,
        runtime: std::sync::Arc<arc_swap::ArcSwap<crate::runtime::GatewayRuntime>>,
        per_plugin_filters: std::sync::Arc<HashMap<String, signal_router::SignalFilter>>,
    ) {
        if let Some(handle) = self.metrics_bridge.take() {
            self.metrics_flusher = handle.attach(runtime, per_plugin_filters);
        }
    }

    /// Deliver the metrics aggregated since the last flush to the sinks.
    /// `/metrics` calls it before it renders, so a scrape sees exact values.
    pub async fn flush_metrics(&self) {
        if let Some(flusher) = &self.metrics_flusher {
            flusher.flush().await;
        }
    }

    /// The final metrics flush at shutdown, while the sinks still run.
    pub async fn close_metrics(&self) {
        if let Some(flusher) = &self.metrics_flusher {
            flusher.close().await;
        }
    }
}

/// Initialize the full observability stack from the OTel signal triad.
/// Each signal observes the master `observability.enabled` switch via
/// the [`ObservabilityConfig::is_*_on`] accessors — when the master
/// is off, every child stays off regardless of its own `enabled:`.
///
/// The gateway-side work per signal:
/// - **Logs**: per-sink `tracing_subscriber::fmt::Layer` for OS-stream
///   sinks (`stderr` / `stdout` / `file`); the log bridge fans every
///   tracing event to plugin `LogSink` entries opted in via the
///   sinks list.
/// - **Metrics**: when the operator listed at least one plugin
///   sink (e.g. `dev.mcpg.observability.prometheus`), install
///   [`metrics_bridge::PluginMetricsRecorder`] as the metrics-rs
///   global recorder. Every gateway `counter!` / `gauge!` /
///   `histogram!` aggregates into its series; the forwarder task —
///   attached once the runtime is up — flushes the series into
///   `registry.emit_metric_event_filtered`. The Prometheus
///   plugin owns the in-memory registry that `/metrics`
///   renders from.
/// - **Traces**: no in-gateway OTel exporter. The telemetry bridge
///   routes tracing spans to plugin `TelemetrySink` entries; the
///   `dev.mcpg.observability.otlp` plugin (registered when the
///   operator lists its id) owns the OTel SDK tracer provider.
pub fn init(observability: &ObservabilityConfig) -> Result<ObservabilityHandle> {
    // One shared `ArcSwap<HashMap>` flows through every bridge +
    // the metrics recorder. Empty at init; populated
    // post-registration by `populate_target_map`.
    let target_to_plugin_id = signal_router::new_target_map();
    // Install-once log-capture sink slot, shared by the log bridge layer and
    // the handle (so cp-attach can install a sink post-boot). Inert until set.
    let log_sink: log_bridge::SharedLogSink = Arc::new(std::sync::OnceLock::new());

    let metrics_bridge = if observability.is_metrics_on() {
        let plugin_ids = plugin_sink_ids(&observability.metrics.sinks);
        if plugin_ids.is_empty() {
            warn_no_metrics_sink_opt_in();
            None
        } else {
            let (recorder, handle) =
                metrics_bridge::new_bridge(plugin_ids, Arc::clone(&target_to_plugin_id));
            match metrics_bridge::install_recorder(recorder) {
                Ok(()) => Some(handle),
                Err(_) => {
                    tracing::warn!(
                        "metrics-rs global recorder already installed; \
                         bridge skipped — /metrics will not return \
                         gateway counters"
                    );
                    None
                }
            }
        }
    } else {
        None
    };

    if !observability.is_logs_on() {
        return Ok(ObservabilityHandle {
            log_bridge: None,
            telemetry_bridge: None,
            metrics_bridge,
            metrics_flusher: None,
            target_to_plugin_id,
            log_sink,
            log_gate: BridgeGate::default(),
            telemetry_gate: BridgeGate::default(),
        });
    }

    let _init = LOGGING_INIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if LOGGING_INITIALIZED.get().is_some() {
        return Ok(ObservabilityHandle {
            log_bridge: None,
            telemetry_bridge: None,
            metrics_bridge,
            metrics_flusher: None,
            target_to_plugin_id,
            log_sink,
            log_gate: BridgeGate::default(),
            telemetry_gate: BridgeGate::default(),
        });
    }

    let logs_config = &observability.logs;
    let os_stream_layers = build_os_stream_layers(logs_config)?;

    let log_plugin_ids = plugin_sink_ids(&logs_config.sinks);
    let (log_bridge_layer, log_bridge_handle) = log_bridge::new_bridge(
        log_plugin_ids,
        Arc::clone(&target_to_plugin_id),
        Arc::clone(&log_sink),
    );
    // Span lifecycle events ride through a TelemetrySink fan-out
    // gated by `observability.traces.sinks[].kind`. There is no
    // in-gateway OTLP exporter — the `dev.mcpg.observability.otlp`
    // plugin (when registered) is the canonical OTLP destination
    // via this bridge.
    let traces_plugin_ids = plugin_sink_ids(&observability.traces.sinks);
    let (telemetry_bridge_layer, telemetry_bridge_handle) =
        telemetry_bridge::new_bridge(traces_plugin_ids, Arc::clone(&target_to_plugin_id));

    let log_gate = BridgeGate::default();
    let telemetry_gate = BridgeGate::default();
    tracing_subscriber::registry()
        .with(os_stream_layers)
        .with(log_bridge_layer.with_filter(log_gate.clone()))
        .with(telemetry_bridge_layer.with_filter(telemetry_gate.clone()))
        .try_init()
        .context("failed to initialize structured logging")?;

    let _ = LOGGING_INITIALIZED.set(());

    Ok(ObservabilityHandle {
        log_bridge: Some(log_bridge_handle),
        telemetry_bridge: Some(telemetry_bridge_handle),
        metrics_bridge,
        metrics_flusher: None,
        target_to_plugin_id,
        log_sink,
        log_gate,
        telemetry_gate,
    })
}

/// Build one `tracing_subscriber::fmt::Layer` per OS-stream sink
/// (`stderr` / `stdout` / `file`). Each layer carries an
/// independent format selection and per-sink `EnvFilter` — sink
/// `level:` overrides the workspace `logs.level` when set. Plugin
/// kinds are skipped here; they're delivered by the log bridge.
fn build_os_stream_layers(
    config: &LogsConfig,
) -> Result<Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>>> {
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>> = Vec::new();
    for sink in &config.sinks {
        let level = sink.level.as_deref().unwrap_or(&config.level);
        let env_filter = EnvFilter::try_new(level).with_context(|| {
            format!(
                "invalid log filter '{}' for observability.logs.sinks[kind={}]",
                level, sink.kind
            )
        })?;

        let format = sink_format(&sink.config);

        let layer: Box<dyn Layer<Registry> + Send + Sync + 'static> = match sink.kind.as_str() {
            "stderr" => build_fmt_layer(stderr_writer(), format),
            "stdout" => build_fmt_layer(stdout_writer(), format),
            "file" => {
                let path = sink
                    .config
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("observability.logs.sinks (file): config.path is required")
                    })?;
                if let Some(parent) = Path::new(path).parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create log directory: {}", parent.display())
                    })?;
                }
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("failed to open log file: {path}"))?;
                let writer = SharedFileWriter(Arc::new(Mutex::new(file)));
                build_fmt_layer(writer, format)
            }
            // Plugin / non-OS-stream kinds — delivered via the
            // log bridge based on the plugin-id allow-list.
            _ => continue,
        };

        layers.push(layer.with_filter(env_filter).boxed());
    }
    Ok(layers)
}

/// The process-wide combiners of the `stderr` and `stdout` sinks.
static STDERR: OnceLock<CombiningWriter<io::Stderr>> = OnceLock::new();
static STDOUT: OnceLock<CombiningWriter<io::Stdout>> = OnceLock::new();

/// Writer for a `stderr` sink: the process [`CombiningWriter`] of stderr.
/// Unit tests write through `eprint!`, which libtest captures per test
/// thread; a raw process-stream write is not captured and floods the
/// shared test log.
fn stderr_writer() -> impl for<'a> MakeWriter<'a> + Send + Sync + 'static {
    #[cfg(test)]
    {
        fmt::TestWriter::with_stderr
    }
    #[cfg(not(test))]
    {
        OsStream(STDERR.get_or_init(|| {
            write_queued_lines_on_panic();
            CombiningWriter::new(io::stderr())
        }))
    }
}

/// Writer for a `stdout` sink; unit tests write through `print!`, as in
/// [`stderr_writer`].
fn stdout_writer() -> impl for<'a> MakeWriter<'a> + Send + Sync + 'static {
    #[cfg(test)]
    {
        fmt::TestWriter::new
    }
    #[cfg(not(test))]
    {
        OsStream(STDOUT.get_or_init(|| {
            write_queued_lines_on_panic();
            CombiningWriter::new(io::stdout())
        }))
    }
}

/// Writes every log line the `stderr` and `stdout` sinks still queue,
/// waiting for a thread that is writing. The process calls it before it
/// exits.
pub fn flush_os_streams() {
    if let Some(stderr) = STDERR.get() {
        let _ = stderr.flush();
    }
    if let Some(stdout) = STDOUT.get() {
        let _ = stdout.flush();
    }
}

/// Installs, once, a panic hook that writes the queued log lines before the
/// panic message, so the message follows the lines logged before it.
#[cfg(not(test))]
fn write_queued_lines_on_panic() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(stderr) = STDERR.get() {
                stderr.flush_on_panic();
            }
            if let Some(stdout) = STDOUT.get() {
                stdout.flush_on_panic();
            }
            previous(info);
        }));
    });
}

/// `MakeWriter` over a process-wide [`CombiningWriter`].
#[cfg(not(test))]
struct OsStream<S: 'static>(&'static CombiningWriter<S>);

#[cfg(not(test))]
impl<'a, S: Write + 'static> MakeWriter<'a> for OsStream<S> {
    type Writer = EventWriter<'static, S>;

    fn make_writer(&'a self) -> Self::Writer {
        self.0.make_writer()
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        self.0.make_writer_for(meta)
    }
}

/// Largest write that a pipe delivers whole, never interleaved with the
/// writes of another process to the same pipe (`PIPE_BUF` on Linux).
const ATOMIC_WRITE_BYTES: usize = 4096;

/// Queued bytes past which an event waits for the stream, so a stalled
/// reader blocks the callers instead of growing the queue.
const MAX_QUEUED_BYTES: usize = 256 * 1024;

/// `MakeWriter` for a process stream that combines the events of concurrent
/// threads into one write. Each event goes onto a queue; the thread that
/// gets the stream writes the whole queue, and a thread that finds the
/// stream busy returns at once, its event written by the holder. A write
/// carries whole events in queue order, at most [`ATOMIC_WRITE_BYTES`]
/// unless a single event is larger.
struct CombiningWriter<S> {
    queue: Mutex<Pending>,
    stream: Mutex<Stream<S>>,
}

#[derive(Default)]
struct Pending {
    bytes: Vec<u8>,
    /// End offset in `bytes` of each event.
    ends: Vec<usize>,
}

impl Pending {
    fn write_to(&self, sink: &mut impl Write) -> io::Result<()> {
        let (mut start, mut end) = (0, 0);
        for &event_end in &self.ends {
            if event_end - start > ATOMIC_WRITE_BYTES && end > start {
                sink.write_all(&self.bytes[start..end])?;
                start = end;
            }
            end = event_end;
        }
        if end > start {
            sink.write_all(&self.bytes[start..end])?;
        }
        Ok(())
    }
}

struct Stream<S> {
    sink: S,
    /// Swapped with the queue, so both buffers keep their allocation.
    batch: Pending,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<S: Write> CombiningWriter<S> {
    fn new(sink: S) -> Self {
        Self {
            queue: Mutex::default(),
            stream: Mutex::new(Stream {
                sink,
                batch: Pending::default(),
            }),
        }
    }

    fn try_stream(&self) -> Option<MutexGuard<'_, Stream<S>>> {
        match self.stream.try_lock() {
            Ok(stream) => Some(stream),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Queues `event` and writes the queue when the stream is free. With
    /// `wait`, the caller waits for a busy stream, so its event is written
    /// before the call returns.
    fn submit(&self, event: &[u8], wait: bool) -> io::Result<()> {
        let queued = {
            let mut queue = lock(&self.queue);
            queue.bytes.extend_from_slice(event);
            let end = queue.bytes.len();
            queue.ends.push(end);
            end
        };
        let stream = if wait || queued > MAX_QUEUED_BYTES {
            lock(&self.stream)
        } else {
            match self.try_stream() {
                Some(stream) => stream,
                None => return Ok(()),
            }
        };
        self.drain(stream)
    }

    /// Writes the queue while it holds the stream. After it releases the
    /// stream it looks at the queue once more: the writer of an event queued
    /// during the last write saw the stream busy and returned.
    fn drain<'a>(&'a self, mut stream: MutexGuard<'a, Stream<S>>) -> io::Result<()> {
        let mut result = Ok(());
        loop {
            mem::swap(&mut *lock(&self.queue), &mut stream.batch);
            let Stream { sink, batch } = &mut *stream;
            let written = batch.write_to(sink);
            batch.bytes.clear();
            batch.ends.clear();
            result = result.and(written);
            drop(stream);
            if lock(&self.queue).ends.is_empty() {
                return result;
            }
            stream = match self.try_stream() {
                Some(stream) => stream,
                None => return result,
            };
        }
    }

    /// Writes the queue, waiting for a thread that holds the stream.
    fn flush(&self) -> io::Result<()> {
        self.drain(lock(&self.stream))?;
        lock(&self.stream).sink.flush()
    }

    /// [`Self::flush`] from a panic hook. The panicking thread may hold the
    /// stream itself, so it waits a bounded time and then gives up.
    #[cfg(not(test))]
    fn flush_on_panic(&self) {
        let give_up = std::time::Instant::now() + std::time::Duration::from_millis(100);
        loop {
            if let Some(stream) = self.try_stream() {
                let _ = self.drain(stream);
                return;
            }
            if std::time::Instant::now() >= give_up {
                return;
            }
            std::thread::yield_now();
        }
    }
}

/// Whether an event at `level` waits for a busy stream: a warning or an
/// error is on the stream before the code that logged it goes on, so it
/// precedes a crash or a panic message that follows it.
fn waits_for_stream(level: &tracing::Level) -> bool {
    *level <= tracing::Level::WARN
}

impl<'a, S: Write + 'static> MakeWriter<'a> for CombiningWriter<S> {
    type Writer = EventWriter<'a, S>;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            combiner: self,
            wait: false,
        }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        EventWriter {
            combiner: self,
            wait: waits_for_stream(meta.level()),
        }
    }
}

/// The writer of one event through a [`CombiningWriter`].
struct EventWriter<'a, S> {
    combiner: &'a CombiningWriter<S>,
    wait: bool,
}

impl<S: Write> Write for EventWriter<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.is_empty() {
            self.combiner.submit(buf, self.wait)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.combiner.flush()
    }
}

impl<S: Write> Write for &CombiningWriter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.is_empty() {
            self.submit(buf, false)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        CombiningWriter::flush(self)
    }
}

/// Build a single `fmt::Layer` for the given writer + format. The
/// json / pretty selection forks the concrete event-formatter type;
/// boxing flattens both branches to a single `Box<dyn Layer<...>>`
/// so the caller can collect mixed-format layers in one Vec.
fn build_fmt_layer<W>(
    writer: W,
    format: SinkFormat,
) -> Box<dyn Layer<Registry> + Send + Sync + 'static>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    match format {
        SinkFormat::Pretty => fmt::layer()
            .with_writer(writer)
            .with_target(true)
            .with_thread_names(true)
            .pretty()
            .boxed(),
        SinkFormat::Json => fmt::layer()
            .json()
            .with_writer(writer)
            .event_format(json_format::JsonEvents::new())
            .boxed(),
    }
}

/// Build the plugin-id allow-list for a signal: every sink `kind:`
/// that is NOT a built-in factory contributes its id. The log /
/// telemetry / metrics bridges check membership before fanning a
/// record out.
fn plugin_sink_ids(sinks: &[SinkConfig]) -> Arc<HashSet<String>> {
    let mut set = HashSet::new();
    for sink in sinks {
        if !is_builtin_sink_kind(&sink.kind) {
            set.insert(sink.kind.clone());
        }
    }
    Arc::new(set)
}

/// True when `kind` is one of the gateway's in-process emitters
/// (`stderr` / `stdout` / `file`).
pub fn is_builtin_sink_kind(kind: &str) -> bool {
    BUILTIN_SINK_KINDS.contains(&kind)
}

/// Log a one-time warning when metrics are enabled but the
/// operator listed no plugin sink. With the recorder bridge in
/// place, the gateway needs at least one `MetricsSink` plugin id
/// (e.g. `dev.mcpg.observability.prometheus`) to make `/metrics`
/// non-empty; otherwise the recorder is skipped entirely and
/// gateway counters fall on the floor.
fn warn_no_metrics_sink_opt_in() {
    tracing::warn!(
        "observability.metrics.enabled = true but no recognised plugin sink \
         configured (expected `kind: dev.mcpg.observability.prometheus`). \
         The /metrics endpoint will return an empty payload until a \
         Prometheus-compatible MetricsSink plugin is wired."
    );
}

/// Per-sink output format. Read from `sink.config.format`, defaults
/// to JSON for the unattended-deployment case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkFormat {
    Json,
    Pretty,
}

fn sink_format(config: &serde_json::Value) -> SinkFormat {
    match config.get("format").and_then(|v| v.as_str()) {
        Some("pretty") => SinkFormat::Pretty,
        _ => SinkFormat::Json,
    }
}

/// `MakeWriter` adapter over a shared file handle. Each `make_writer`
/// call clones the `Arc` so the per-event writer can lock/write/drop
/// without serialising the whole subscriber chain.
#[derive(Clone)]
struct SharedFileWriter(Arc<Mutex<File>>);

impl<'a> MakeWriter<'a> for SharedFileWriter {
    type Writer = SharedFileWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedFileWriterGuard(Arc::clone(&self.0))
    }
}

struct SharedFileWriterGuard(Arc<Mutex<File>>);

impl Write for SharedFileWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log file lock poisoned").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().expect("log file lock poisoned").flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{sync::mpsc, time::Duration};

    fn sink(kind: &str, config: serde_json::Value, level: Option<&str>) -> SinkConfig {
        SinkConfig {
            kind: kind.to_owned(),
            config,
            level: level.map(str::to_owned),
        }
    }

    #[test]
    fn plugin_sink_ids_excludes_builtin_kinds_only() {
        // The in-gateway built-in factory set is OS-stream
        // emitters only. `otlp` and `prometheus` are plugin-id
        // kinds (the `dev.mcpg.observability.{otlp,prometheus}`
        // plugins own them), not built-ins.
        let sinks = vec![
            sink("stderr", json!({"format": "json"}), None),
            sink("stdout", json!({}), None),
            sink("file", json!({"path": "/tmp/x"}), None),
            sink("dev.mcpg.observability.otlp", json!({"url": "x"}), None),
            sink(
                "dev.mcpg.observability.prometheus",
                json!({"namespace": "mcpg"}),
                None,
            ),
            sink("dev.acme.observability.datadog", json!({}), None),
            sink("dev.mcpg.builtin.log.stderr-json", json!({}), None),
        ];
        let ids = plugin_sink_ids(&sinks);
        assert!(ids.contains("dev.mcpg.observability.otlp"));
        assert!(ids.contains("dev.mcpg.observability.prometheus"));
        assert!(ids.contains("dev.acme.observability.datadog"));
        assert!(ids.contains("dev.mcpg.builtin.log.stderr-json"));
        assert!(!ids.contains("stderr"));
        assert!(!ids.contains("stdout"));
        assert!(!ids.contains("file"));
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn plugin_sink_ids_empty_when_only_builtin_kinds() {
        let sinks = vec![sink("stderr", json!({"format": "json"}), None)];
        let ids = plugin_sink_ids(&sinks);
        assert!(ids.is_empty());
    }

    #[test]
    fn is_builtin_sink_kind_recognises_os_stream_set() {
        // OS-stream sinks only.
        for k in ["stderr", "stdout", "file"] {
            assert!(is_builtin_sink_kind(k), "expected {k} to be built-in");
        }
        // The `otlp` and `prometheus` shorthand kinds are not
        // built-ins — they're explicit plugin ids.
        assert!(!is_builtin_sink_kind("otlp"));
        assert!(!is_builtin_sink_kind("prometheus"));
        assert!(!is_builtin_sink_kind("dev.mcpg.observability.otlp"));
        assert!(!is_builtin_sink_kind("dev.mcpg.observability.prometheus"));
        assert!(!is_builtin_sink_kind("dev.acme.observability.datadog"));
        assert!(!is_builtin_sink_kind("dev.mcpg.builtin.log.stderr-json"));
        assert!(!is_builtin_sink_kind(""));
    }

    #[test]
    fn sink_format_defaults_to_json() {
        assert_eq!(sink_format(&json!({})), SinkFormat::Json);
        assert_eq!(sink_format(&json!({"format": "json"})), SinkFormat::Json);
        assert_eq!(
            sink_format(&json!({"format": "pretty"})),
            SinkFormat::Pretty
        );
        // Unknown format string falls back to json (defensive).
        assert_eq!(sink_format(&json!({"format": "xml"})), SinkFormat::Json);
    }

    #[test]
    fn build_os_stream_layers_skips_plugin_kinds() {
        let config = LogsConfig {
            enabled: true,
            level: "info".into(),
            sinks: vec![
                sink("stderr", json!({"format": "json"}), None),
                sink("dev.acme.observability.datadog", json!({}), None),
                sink("stdout", json!({"format": "pretty"}), Some("debug")),
            ],
        };
        let layers = build_os_stream_layers(&config).expect("build succeeds");
        // Two OS-stream sinks → two layers; plugin-kind sink skipped.
        assert_eq!(layers.len(), 2);
    }

    #[test]
    fn os_stream_writers_go_through_libtest_capture_on_their_own_stream() {
        let stderr = std::any::type_name_of_val(&stderr_writer());
        let stdout = std::any::type_name_of_val(&stdout_writer());
        assert!(
            stderr.ends_with("TestWriter::with_stderr"),
            "stderr sink writer: {stderr}"
        );
        assert!(
            stdout.ends_with("TestWriter::new"),
            "stdout sink writer: {stdout}"
        );
    }

    #[test]
    fn build_os_stream_layers_uses_per_sink_level_when_set() {
        // No assertion on rejection (EnvFilter accepts almost any
        // string as a target directive); just verify the per-sink
        // level path is exercised + a layer comes back.
        let config = LogsConfig {
            enabled: true,
            level: "info".into(),
            sinks: vec![
                sink("stderr", json!({"format": "json"}), Some("debug")),
                sink("stdout", json!({"format": "pretty"}), None),
            ],
        };
        let layers = build_os_stream_layers(&config).expect("build succeeds");
        assert_eq!(layers.len(), 2);
    }

    #[derive(Clone, Default)]
    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    struct MessageSink(Arc<Mutex<Vec<String>>>);

    impl log_bridge::LogSink for MessageSink {
        fn record(&self, record: &mcpg_plugin_protocol::logs::LogRecord) {
            self.0.lock().unwrap().push(record.message.clone());
        }
    }

    #[test]
    fn a_closed_bridge_gate_mutes_the_bridge_and_leaves_the_stream_sink() {
        let bridged = Arc::new(Mutex::new(Vec::new()));
        let sink: log_bridge::SharedLogSink = Arc::new(OnceLock::new());
        let _ =
            sink.set(Arc::new(MessageSink(Arc::clone(&bridged))) as Arc<dyn log_bridge::LogSink>);
        let (bridge, _handle) = log_bridge::new_bridge(
            Arc::new(HashSet::new()),
            signal_router::new_target_map(),
            sink,
        );
        let written = CapturedWriter::default();
        let stream_sinks = vec![
            build_fmt_layer(written.clone(), SinkFormat::Json)
                .with_filter(EnvFilter::new("info"))
                .boxed(),
        ];
        let gate = BridgeGate::default();
        let subscriber = tracing_subscriber::registry()
            .with(stream_sinks)
            .with(bridge.with_filter(gate.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);
        let debug = |msg: &str| tracing::debug!(target: "bridge_gate_test", "{msg}");
        let info = |msg: &str| tracing::info!(target: "bridge_gate_test", "{msg}");

        debug("debug while open");
        info("info while open");
        gate.set_open(false);
        debug("debug while closed");
        info("info while closed");
        gate.set_open(true);
        debug("debug when reopened");

        assert_eq!(
            *bridged.lock().unwrap(),
            ["debug while open", "info while open", "debug when reopened"]
        );
        let written = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
        assert!(written.contains("info while open"), "{written}");
        assert!(written.contains("info while closed"), "{written}");
        assert!(!written.contains("debug while"), "{written}");
        assert!(!written.contains("debug when"), "{written}");
    }

    #[test]
    fn installing_a_log_sink_opens_the_log_gate() {
        let handle = ObservabilityHandle::default();
        handle.log_gate.set_open(false);
        let bridged = Arc::new(Mutex::new(Vec::new()));
        assert!(handle.set_log_sink(Arc::new(MessageSink(bridged))));
        assert!(handle.log_gate.is_open());
    }

    #[test]
    fn build_os_stream_layers_rejects_file_without_path() {
        let config = LogsConfig {
            enabled: true,
            level: "info".into(),
            sinks: vec![sink("file", json!({}), None)],
        };
        let err = build_os_stream_layers(&config)
            .err()
            .expect("must reject file sink without path");
        assert!(
            err.to_string().contains("config.path is required"),
            "unexpected error: {err}"
        );
    }

    /// Records each write. With `hold`, the first write tells the test that
    /// it started, then waits until the test releases it.
    struct RecordingSink {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        hold: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }

    impl Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some((started, release)) = self.hold.take() {
                started.send(()).unwrap();
                release.recv().unwrap();
            }
            self.writes.lock().unwrap().push(buf.to_vec());
            std::thread::yield_now();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct HeldStream {
        writer: Arc<CombiningWriter<RecordingSink>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        release: mpsc::Sender<()>,
        holder: std::thread::JoinHandle<()>,
    }

    /// A combining writer whose stream is busy: another thread is inside
    /// the write of `first` until `release`.
    fn held_stream(first: &'static [u8]) -> HeldStream {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let (started_tx, started) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let writer = Arc::new(CombiningWriter::new(RecordingSink {
            writes: Arc::clone(&writes),
            hold: Some((started_tx, release_rx)),
        }));
        let holder = {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || (&*writer).write_all(first).unwrap())
        };
        started.recv().unwrap();
        HeldStream {
            writer,
            writes,
            release,
            holder,
        }
    }

    /// Writes `events` on a new thread; the receiver gets a message when the
    /// last write returns.
    fn write_on_thread(
        writer: &Arc<CombiningWriter<RecordingSink>>,
        events: Vec<Vec<u8>>,
    ) -> mpsc::Receiver<()> {
        let writer = Arc::clone(writer);
        let (done, returned) = mpsc::channel();
        std::thread::spawn(move || {
            for event in events {
                (&*writer).write_all(&event).unwrap();
            }
            done.send(()).unwrap();
        });
        returned
    }

    #[test]
    fn a_busy_stream_queues_the_events_and_its_holder_writes_them_in_one_write() {
        let held = held_stream(b"a\n");
        write_on_thread(&held.writer, vec![b"b\n".to_vec(), b"c\n".to_vec()])
            .recv_timeout(Duration::from_secs(10))
            .expect("a writer that finds the stream busy returns at once");
        held.release.send(()).unwrap();
        held.holder.join().unwrap();
        assert_eq!(
            *held.writes.lock().unwrap(),
            [b"a\n".to_vec(), b"b\nc\n".to_vec()]
        );
    }

    #[test]
    fn a_batch_write_carries_whole_events_and_a_larger_event_goes_alone() {
        let event = |len: usize, byte: u8| {
            let mut event = vec![byte; len - 1];
            event.push(b'\n');
            event
        };
        let events = vec![
            event(1500, b'b'),
            event(1500, b'c'),
            event(1500, b'd'),
            event(5000, b'e'),
            event(100, b'f'),
            event(100, b'g'),
        ];
        let held = held_stream(b"a\n");
        write_on_thread(&held.writer, events.clone())
            .recv_timeout(Duration::from_secs(10))
            .expect("a writer that finds the stream busy returns at once");
        held.release.send(()).unwrap();
        held.holder.join().unwrap();
        let writes = held.writes.lock().unwrap();
        let lens: Vec<usize> = writes.iter().map(Vec::len).collect();
        assert_eq!(lens, [2, 3000, 1500, 5000, 200]);
        assert_eq!(writes[1..].concat(), events.concat());
    }

    #[test]
    fn an_event_past_the_queue_ceiling_waits_for_the_stream() {
        let held = held_stream(b"a\n");
        let big = vec![b'x'; MAX_QUEUED_BYTES + 1];
        let returned = write_on_thread(&held.writer, vec![big.clone()]);
        assert!(
            returned.recv_timeout(Duration::from_millis(100)).is_err(),
            "returned while the stream was busy"
        );
        held.release.send(()).unwrap();
        returned
            .recv_timeout(Duration::from_secs(10))
            .expect("the writer gets the stream once it is free");
        held.holder.join().unwrap();
        assert_eq!(
            held.writes.lock().unwrap().concat(),
            [b"a\n".as_slice(), big.as_slice()].concat()
        );
    }

    #[test]
    fn only_warnings_and_errors_wait_for_the_stream() {
        assert!(waits_for_stream(&tracing::Level::ERROR));
        assert!(waits_for_stream(&tracing::Level::WARN));
        assert!(!waits_for_stream(&tracing::Level::INFO));
        assert!(!waits_for_stream(&tracing::Level::DEBUG));
        assert!(!waits_for_stream(&tracing::Level::TRACE));
    }

    #[test]
    fn a_waiting_event_is_written_before_its_write_returns() {
        let held = held_stream(b"a\n");
        let writer = Arc::clone(&held.writer);
        let (done, returned) = mpsc::channel();
        std::thread::spawn(move || {
            let mut event = EventWriter {
                combiner: &*writer,
                wait: true,
            };
            event.write_all(b"w\n").unwrap();
            done.send(()).unwrap();
        });
        assert!(
            returned.recv_timeout(Duration::from_millis(100)).is_err(),
            "returned while the stream was busy"
        );
        held.release.send(()).unwrap();
        returned
            .recv_timeout(Duration::from_secs(10))
            .expect("the writer gets the stream once it is free");
        assert_eq!(held.writes.lock().unwrap().concat(), b"a\nw\n");
        held.holder.join().unwrap();
    }

    #[test]
    fn a_flush_waits_for_the_holder_and_leaves_nothing_queued() {
        let held = held_stream(b"a\n");
        write_on_thread(&held.writer, vec![b"b\n".to_vec()])
            .recv_timeout(Duration::from_secs(10))
            .expect("a writer that finds the stream busy returns at once");
        let writer = Arc::clone(&held.writer);
        let (done, flushed) = mpsc::channel();
        std::thread::spawn(move || {
            writer.flush().unwrap();
            done.send(()).unwrap();
        });
        assert!(
            flushed.recv_timeout(Duration::from_millis(100)).is_err(),
            "flushed while the stream was busy"
        );
        held.release.send(()).unwrap();
        flushed
            .recv_timeout(Duration::from_secs(10))
            .expect("the flush gets the stream once it is free");
        held.holder.join().unwrap();
        assert_eq!(held.writes.lock().unwrap().concat(), b"a\nb\n");
        assert!(lock(&held.writer.queue).ends.is_empty());
    }

    #[test]
    fn events_from_many_threads_are_written_once_whole_and_in_order() {
        const THREADS: usize = 8;
        const EVENTS: usize = 500;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let writer = CombiningWriter::new(RecordingSink {
            writes: Arc::clone(&writes),
            hold: None,
        });
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry().with(build_fmt_layer(writer, SinkFormat::Json)),
        );
        let threads: Vec<_> = (0..THREADS)
            .map(|thread| {
                let dispatch = dispatch.clone();
                std::thread::spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        for seq in 0..EVENTS {
                            tracing::info!(target: "combining_writer_test", thread, seq, "event");
                        }
                    });
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let mut next = [0; THREADS];
        for write in writes.lock().unwrap().iter() {
            let lines: Vec<&[u8]> = write.split_inclusive(|&b| b == b'\n').collect();
            assert!(lines.iter().all(|line| line.ends_with(b"\n")));
            assert!(write.len() <= ATOMIC_WRITE_BYTES || lines.len() == 1);
            for line in lines {
                let event: serde_json::Value = serde_json::from_slice(line).unwrap();
                let thread = event["fields"]["thread"].as_u64().unwrap() as usize;
                assert_eq!(event["fields"]["seq"], next[thread]);
                next[thread] += 1;
            }
        }
        assert_eq!(next, [EVENTS; THREADS]);
    }
}
