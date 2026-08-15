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
//! `histogram!` call enqueues a `MetricPoint` onto a bounded
//! channel that fans out to every operator-listed `MetricsSink`
//! plugin. The canonical Prometheus plugin
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
pub mod log_bridge;
pub mod metrics_bridge;
pub mod signal_router;
pub mod telemetry_bridge;

use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Context, Result};
use tracing_subscriber::{
    EnvFilter, Layer, fmt, fmt::MakeWriter, layer::SubscriberExt, registry::Registry,
    util::SubscriberInitExt,
};

use crate::config::{LogsConfig, ObservabilityConfig, SinkConfig};

static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Built-in sink kinds dispatched in-gateway. The set is limited
/// to OS-stream emitters only (`stderr` / `stdout` / `file`) —
/// `otlp` and `prometheus` are opt-in via the
/// `dev.mcpg.observability.{otlp, prometheus}` plugin ids
/// registered through [`FirstPartyRegistrar`]. Anything outside
/// this set is treated as a plugin id and routed through the
/// log / telemetry bridges.
const BUILTIN_SINK_KINDS: &[&str] = &["stderr", "stdout", "file"];

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
    /// Shared `target_prefix → plugin_id` map used
    /// by all three bridges + the metrics recorder. Empty at
    /// init; gateway boot calls `populate_target_map` after
    /// plugin registration to install the resolved values.
    target_to_plugin_id: signal_router::SharedTargetMap,
    /// Install-once slot for an off-box log-capture sink (CP log shipping).
    /// The log bridge layer reads it per event; `set_log_sink` installs one
    /// once the cp-attach agent exists. Empty (no-op) otherwise.
    log_sink: log_bridge::SharedLogSink,
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
    pub fn set_log_sink(&self, sink: Arc<dyn log_bridge::LogSink>) -> bool {
        self.log_sink.set(sink).is_ok()
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
            handle.attach(runtime, per_plugin_filters);
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
            handle.attach(runtime, per_plugin_filters);
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
            handle.attach(runtime, per_plugin_filters);
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
///   `histogram!` enqueues a `MetricPoint` onto the bounded
///   bridge channel; the forwarder task — attached once the
///   runtime is up — drains it into
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
            target_to_plugin_id,
            log_sink,
        });
    }

    if LOGGING_INITIALIZED.get().is_some() {
        return Ok(ObservabilityHandle {
            log_bridge: None,
            telemetry_bridge: None,
            metrics_bridge,
            target_to_plugin_id,
            log_sink,
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

    tracing_subscriber::registry()
        .with(os_stream_layers)
        .with(log_bridge_layer)
        .with(telemetry_bridge_layer)
        .try_init()
        .context("failed to initialize structured logging")?;

    let _ = LOGGING_INITIALIZED.set(());

    Ok(ObservabilityHandle {
        log_bridge: Some(log_bridge_handle),
        telemetry_bridge: Some(telemetry_bridge_handle),
        metrics_bridge,
        target_to_plugin_id,
        log_sink,
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
            "stderr" => build_fmt_layer(io::stderr, format),
            "stdout" => build_fmt_layer(io::stdout, format),
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
            .with_target(true)
            .with_thread_names(true)
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
}
