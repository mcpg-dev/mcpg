//! Built-in `telemetry_sink` plugin — `dev.mcpg.builtin.telemetry.debug`.
//!
//! Reference implementation of the `telemetry_sink` entity kind.
//! Minimal — each event emits a `tracing::debug!` with the key fields
//! plus an atomic counter per event kind, so tests can assert the
//! fan-out plumbing reaches this sink.
//!
//! # Why not a real OTLP exporter?
//!
//! Real OTLP/gRPC or OTLP/HTTP sender has its own dep + config
//! surface (endpoint / batching / TLS / sampling / retry) big
//! enough to deserve its own dedicated effort. Shipping a real
//! OTLP exporter here would rush an ecosystem surface operators
//! will care about for years; a minimal reference sink lets the
//! entity-kind infrastructure land without that pressure.
//!
//! The canonical production-quality telemetry sink arrives as a
//! follow-up (likely `dev.mcpg.builtin.telemetry.otlp` or an
//! external plugin against OpenTelemetry SDK).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    telemetry::{MetricPoint, SpanEnd, SpanStart, TelemetryError, TelemetrySink},
};

/// Descriptor shipped alongside the code.
/// Plugin id — operators opt this sink into the trace fan-out by
/// listing it under `observability.traces.sinks[].kind`.
pub const PLUGIN_ID: &str = "dev.mcpg.builtin.telemetry.debug";

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.telemetry.debug
name: Built-in Debug Telemetry Sink
description: |
  Gateway-bundled telemetry sink: logs every span / metric at
  `tracing::debug!` and increments an atomic counter per event
  kind. Proof-point for the telemetry_sink fan-out — the real OTLP
  sender is the dedicated `dev.mcpg.observability.otlp`
  plugin. Opt-in: operators list
  `kind: dev.mcpg.builtin.telemetry.debug` under
  `observability.traces.sinks` to enable it.
class: telemetry_sink
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

pub struct DebugTelemetrySink {
    manifest: PluginManifest,
    spans_started: AtomicUsize,
    spans_ended: AtomicUsize,
    metrics: AtomicUsize,
}

impl DebugTelemetrySink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.telemetry.debug".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in Debug Telemetry Sink".into(),
                plugin_class: PluginClass::TelemetrySink,
                protocol_version: "1.0".into(),
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
            spans_started: AtomicUsize::new(0),
            spans_ended: AtomicUsize::new(0),
            metrics: AtomicUsize::new(0),
        })
    }

    /// How many spans the sink has observed starting. Used by the
    /// gateway's tests to assert the fan-out reaches this sink;
    /// not surfaced on the trait.
    #[must_use]
    pub fn span_starts_seen(&self) -> usize {
        self.spans_started.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn span_ends_seen(&self) -> usize {
        self.spans_ended.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn metrics_seen(&self) -> usize {
        self.metrics.load(Ordering::Acquire)
    }
}

#[mcpg_plugin_protocol::async_trait]
impl TelemetrySink for DebugTelemetrySink {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn span_started(&self, span: SpanStart) {
        tracing::debug!(
            trace_id = %span.trace_id,
            span_id = %span.span_id,
            name = %span.name,
            kind = ?span.kind,
            "telemetry_debug: span_started"
        );
        self.spans_started.fetch_add(1, Ordering::AcqRel);
    }

    async fn span_ended(&self, span: SpanEnd) {
        tracing::debug!(
            trace_id = %span.trace_id,
            span_id = %span.span_id,
            status = ?span.status,
            "telemetry_debug: span_ended"
        );
        self.spans_ended.fetch_add(1, Ordering::AcqRel);
    }

    async fn metric_recorded(&self, metric: MetricPoint) {
        tracing::debug!(
            name = %metric.name,
            kind = ?metric.kind,
            "telemetry_debug: metric_recorded"
        );
        self.metrics.fetch_add(1, Ordering::AcqRel);
    }

    async fn flush(&self, _timeout: Duration) -> Result<(), TelemetryError> {
        // No buffer — nothing to flush.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::telemetry::{MetricKind, MetricValue, SpanKind, SpanStatus};

    fn span_start() -> SpanStart {
        SpanStart {
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_id: None,
            name: "op".into(),
            kind: SpanKind::Internal,
            start_ns: 0,
            attributes: Default::default(),
        }
    }
    fn span_end() -> SpanEnd {
        SpanEnd {
            trace_id: "t".into(),
            span_id: "s".into(),
            end_ns: 1,
            status: SpanStatus::Ok,
            events: vec![],
            additional_attributes: Default::default(),
        }
    }
    fn metric() -> MetricPoint {
        MetricPoint {
            name: "m".into(),
            unit: None,
            kind: MetricKind::Counter,
            value: MetricValue::I64 { value: 1 },
            labels: Default::default(),
            timestamp_ns: 0,
        }
    }

    #[tokio::test]
    async fn counters_bump_per_kind() {
        let sink = DebugTelemetrySink::new();
        assert_eq!(sink.span_starts_seen(), 0);
        sink.span_started(span_start()).await;
        sink.span_started(span_start()).await;
        sink.span_ended(span_end()).await;
        sink.metric_recorded(metric()).await;
        sink.metric_recorded(metric()).await;
        sink.metric_recorded(metric()).await;
        assert_eq!(sink.span_starts_seen(), 2);
        assert_eq!(sink.span_ends_seen(), 1);
        assert_eq!(sink.metrics_seen(), 3);
    }

    #[tokio::test]
    async fn flush_is_trivially_ok() {
        let sink = DebugTelemetrySink::new();
        assert!(sink.flush(Duration::from_millis(1)).await.is_ok());
    }

    #[test]
    fn descriptor_yaml_parses_as_telemetry_sink() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.telemetry.debug");
        assert_eq!(d.class, PluginClass::TelemetrySink);
    }
}
