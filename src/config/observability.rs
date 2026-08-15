//! Top-level `observability:` block — the OTel signal triad
//! (logs / metrics / traces) plus the shared `SinkConfig` schema
//! that audit also consumes.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::default_true;

/// Top-level `observability:` block — the OpenTelemetry signal triad
/// (logs / metrics / traces) plus audit fan-out.
///
/// Each signal carries a `sinks: [...]` list of [`SinkConfig`]
/// entries. Each entry's `kind:` field dispatches to either a
/// built-in sink factory (`stderr` / `stdout` / `file` / `otlp` /
/// `prometheus`) or a plugin id resolved against the gateway's
/// plugin registry at boot.
///
/// **Master switch.** `enabled: false` (default `true`) silences
/// every child regardless of their own `enabled:` flags — useful
/// for embedded use cases where the host process owns observability
/// or for minimal-footprint test runs. Each child also has its own
/// `enabled:` for finer-grained control. The accessor helpers below
/// (`is_logs_on()`, `is_metrics_on()`, `is_traces_on()`,
/// `is_audit_on()`) implement the AND-fold so call sites can't
/// forget either flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Master kill switch. When `false`, every child is treated as
    /// disabled regardless of its own `enabled:` field — no logs
    /// emitted, no metrics endpoint registered, no traces pipeline
    /// started, no audit fan-out wired. Default `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Logs signal — gateway internals + plugin-emitted log events
    /// fanned to the configured sink list.
    #[serde(default)]
    pub logs: LogsConfig,
    /// Metrics signal — gateway internals + plugin-emitted metric
    /// events fanned to the configured sink list.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Traces signal — span lifecycle events fanned to the configured
    /// sink list.
    #[serde(default)]
    pub traces: TracesConfig,
    /// Plugin health probe. Lives under `observability:` because the
    /// probe is observability-shaped (it watches plugin liveness and
    /// writes `PluginState::Degraded` for monitoring consumers).
    #[serde(default)]
    pub plugin_health_probe: super::plugins::HealthProbeConfig,
    /// Per-call span sampling rate for native-plugin host-side
    /// spans. Range `[0.0, 1.0]`; `None` inherits the
    /// global subscriber sampler (no extra dampening).
    ///
    /// The host wraps every plugin FFI call in a `tracing` span for
    /// attribution. On hot paths (tool-gate chain → 5–15 spans/call;
    /// metrics_sink emit → up to 50 spans/call) the per-span
    /// construction + drop overhead is ~5–20 µs each. Operators
    /// running plugin-heavy workloads with traces sampled at a low
    /// rate end-to-end can additionally dampen the plugin-call
    /// spans here without changing the global subscriber, dropping
    /// the host-side overhead to a small fraction.
    ///
    /// `Some(1.0)` is a no-op (all plugin call spans honour the
    /// global sampler). `Some(0.01)` keeps 1% of spans; the rest
    /// become disabled spans, which `tracing` short-circuits at
    /// near-zero cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_call_sampling_rate: Option<f64>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            logs: LogsConfig::default(),
            metrics: MetricsConfig::default(),
            traces: TracesConfig::default(),
            plugin_health_probe: super::plugins::HealthProbeConfig::default(),
            plugin_call_sampling_rate: None,
        }
    }
}

impl ObservabilityConfig {
    pub fn validate(&self) -> Result<()> {
        self.logs.validate()?;
        self.metrics.validate()?;
        self.traces.validate()?;
        if let Some(rate) = self.plugin_call_sampling_rate
            && !(0.0..=1.0).contains(&rate)
        {
            anyhow::bail!(
                "observability.plugin_call_sampling_rate must be in [0.0, 1.0], got {}",
                rate
            );
        }
        Ok(())
    }

    /// Master AND child — true only when both the master switch and
    /// the child's own `enabled:` are on.
    pub fn is_logs_on(&self) -> bool {
        self.enabled && self.logs.enabled
    }
    pub fn is_metrics_on(&self) -> bool {
        self.enabled && self.metrics.enabled
    }
    pub fn is_traces_on(&self) -> bool {
        self.enabled && self.traces.enabled
    }
}

/// One sink in an observability signal's `sinks: [...]` list. The
/// `kind:` field dispatches to a built-in factory (`stderr`,
/// `stdout`, `file`, `otlp`, `prometheus`) or to a plugin id (any
/// other value is looked up in the plugin registry at boot).
///
/// `config:` is the sink-kind-specific config object. Built-in kinds
/// validate their own `config:` shape at boot; for plugin sinks, the
/// plugin's own config schema applies.
///
/// `level:` is an optional per-sink severity floor. When `None`, the
/// sink inherits the signal's `level:`. Useful for `stderr: warn,
/// file: debug` setups where the console is quiet but a file captures
/// everything. Per-sink level overrides are parsed but not yet
/// enforced; today signal-level `level:` is the only enforced
/// floor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SinkConfig {
    /// Sink kind. Built-in keywords: `stderr`, `stdout`, `file`,
    /// `otlp`, `prometheus`. Anything else is resolved as a plugin
    /// id at boot.
    pub kind: String,
    /// Sink-specific config object. Schema depends on `kind:`.
    #[serde(default)]
    pub config: serde_json::Value,
    /// Per-sink severity floor. `None` = inherit signal-level `level:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// Validate a sink `kind:` is non-empty. Built-in kinds (`stderr` /
/// `stdout` / `file` / `otlp` / `prometheus`) pass; anything else is
/// accepted as a plugin id and validated by the plugin registry at
/// boot.
pub(crate) fn validate_sink_kind(kind: &str, signal: &str, idx: usize) -> Result<()> {
    if kind.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "{signal}.sinks[{idx}].kind must not be empty"
        ));
    }
    Ok(())
}

/// `observability.logs:` — the logs signal.
///
/// Gateway internals (every `tracing::info!()` / `warn!()` /
/// `error!()` call) AND plugin-emitted log events both flow through
/// the configured sink list. Default sinks ship one `stderr` JSON
/// emitter — production deployments add `file`, `otlp`, or plugin
/// sinks (Loki, Splunk, …) by appending entries to `sinks:`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogsConfig {
    /// Master enable for the logs signal. When `false`, no log
    /// events are emitted regardless of `sinks:` content.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Signal-level severity floor (`trace` / `debug` / `info` /
    /// `warn` / `error`). Per-sink `level:` can raise it further but
    /// can't lower it below this floor. Default: `info`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Sink fan-out. Each entry's `kind:` resolves to a built-in
    /// factory (`stderr` / `stdout` / `file` / `otlp`) or plugin id.
    /// Default: one `stderr` sink with JSON format.
    #[serde(default = "default_logs_sinks")]
    pub sinks: Vec<SinkConfig>,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: default_log_level(),
            sinks: default_logs_sinks(),
        }
    }
}

impl LogsConfig {
    pub fn validate(&self) -> Result<()> {
        if self.level.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "observability.logs.level must not be empty"
            ));
        }
        if self.enabled && self.sinks.is_empty() {
            return Err(anyhow::anyhow!(
                "observability.logs.sinks must not be empty when logs.enabled = true"
            ));
        }
        for (i, sink) in self.sinks.iter().enumerate() {
            validate_sink_kind(&sink.kind, "observability.logs", i)?;
            // Built-in OS-stream kind config validation. There is no
            // `kind: otlp` shorthand for logs — operators who want
            // OTLP-logs install a dedicated plugin and reference its
            // plugin id.
            match sink.kind.as_str() {
                "stderr" | "stdout" => {} // No required config
                "file" => {
                    let path = sink
                        .config
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if path.trim().is_empty() {
                        return Err(anyhow::anyhow!(
                            "observability.logs.sinks[{i}] (file): config.path must not be empty"
                        ));
                    }
                }
                _ => {} // plugin-id — registry validates at boot
            }
        }
        Ok(())
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_logs_sinks() -> Vec<SinkConfig> {
    vec![SinkConfig {
        kind: "stderr".to_owned(),
        config: serde_json::json!({ "format": "json" }),
        level: None,
    }]
}

/// `observability.metrics:` — the metrics signal.
///
/// Gateway internals (every `metrics::counter!()` / `gauge!()` /
/// `histogram!()`) flow through the configured sink list. The
/// canonical Prometheus exporter is a plugin: operators wire
/// `kind: dev.mcpg.observability.prometheus`. The `sinks: []` list
/// otherwise carries plugin ids (`dev.acme.observability.datadog`,
/// etc.) — there are no built-in factory kinds for metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Master enable for the metrics signal. When `false`, no metric
    /// recorders are installed.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sink fan-out. Every entry's `kind:` is a plugin id (there is
    /// no `kind: prometheus` / `kind: otlp` shorthand). Default: one
    /// `dev.mcpg.observability.prometheus` sink at `/metrics`.
    #[serde(default = "default_metrics_sinks")]
    pub sinks: Vec<SinkConfig>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sinks: default_metrics_sinks(),
        }
    }
}

impl MetricsConfig {
    pub fn validate(&self) -> Result<()> {
        // Every sink kind is resolved as a plugin id; per-kind
        // config validation lives inside each plugin's
        // `from_config_json` (with `serde(deny_unknown_
        // fields)` for early typo detection). The gateway only
        // checks that `kind` is non-empty.
        for (i, sink) in self.sinks.iter().enumerate() {
            validate_sink_kind(&sink.kind, "observability.metrics", i)?;
        }
        Ok(())
    }
}

fn default_metrics_sinks() -> Vec<SinkConfig> {
    // Default to the Prometheus plugin id so a factory-fresh
    // gateway boot produces a working `/metrics` endpoint without
    // operator config.
    vec![SinkConfig {
        kind: "dev.mcpg.observability.prometheus".to_owned(),
        config: serde_json::json!({}),
        level: None,
    }]
}

/// `observability.traces:` — the traces signal.
///
/// Span lifecycle events (every `tracing::info_span!()` /
/// `debug_span!()` and every plugin-emitted span) flow through the
/// configured sink list. The canonical sink is `otlp` (exports to
/// an OpenTelemetry Collector). Default: traces disabled (operators
/// opt in by setting `enabled: true` and adding sinks).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TracesConfig {
    /// Master enable for the traces signal. Default `false` —
    /// tracing has non-trivial overhead so operators opt in.
    #[serde(default)]
    pub enabled: bool,
    /// Service name advertised to OTel collectors. Default `"mcpg"`.
    #[serde(default = "default_traces_service_name")]
    pub service_name: String,
    /// Propagate W3C trace context (`traceparent` / `tracestate`)
    /// headers to outbound binding calls. Defaults to `true` —
    /// downstream services join the same trace.
    #[serde(default = "default_true")]
    pub propagate_context: bool,
    /// Sink fan-out. Each entry's `kind:` resolves to a built-in
    /// factory (`otlp`) or plugin id. Default: empty — operators
    /// add an `otlp` sink to ship to a collector.
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
}

fn default_traces_service_name() -> String {
    "mcpg".to_owned()
}

impl Default for TracesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: default_traces_service_name(),
            propagate_context: true,
            sinks: Vec::new(),
        }
    }
}

impl TracesConfig {
    pub fn validate(&self) -> Result<()> {
        if self.service_name.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "observability.traces.service_name must not be empty"
            ));
        }
        if self.enabled && self.sinks.is_empty() {
            return Err(anyhow::anyhow!(
                "observability.traces.sinks must not be empty when traces.enabled = true \
                 — add an `otlp` (or plugin) sink"
            ));
        }
        for (i, sink) in self.sinks.iter().enumerate() {
            validate_sink_kind(&sink.kind, "observability.traces", i)?;
            if sink.kind == "otlp" {
                let url = sink
                    .config
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !(url.starts_with("http://")
                    || url.starts_with("https://")
                    || url.starts_with("grpc://"))
                {
                    return Err(anyhow::anyhow!(
                        "observability.traces.sinks[{i}] (otlp): config.url must start with http:// / https:// / grpc://"
                    ));
                }
            }
        }
        Ok(())
    }
}
