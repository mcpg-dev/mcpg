//! Built-in `log_sink` plugin — `dev.mcpg.builtin.log.stderr-json`.
//!
//! Serialises each `LogRecord` as a JSON line to stderr. Matches
//! the shape the existing `tracing_subscriber` stderr-json
//! formatter produces; once the tracing → log_sink bridge lands as
//! a follow-up improvement, the built-in takes over the formatter
//! role and the subscriber is swapped out.
//!
//! # Min-level filter
//!
//! Operators configure `min_level` via the plugin entry config —
//! records below it are dropped. Default `Info`; dev deployments
//! usually drop to `Debug`.
//!
//! # Output channel
//!
//! Stderr by default. The spec's metadata schema admits other
//! destinations (file, network) but the `stderr-json` name makes
//! the one-channel contract explicit; an operator who wants file
//! output writes a different plugin or uses shell redirection on
//! the gateway's stderr.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    logs::{LogError, LogLevel, LogRecord, LogSink},
};

/// Plugin id — operators opt this sink into the log fan-out by
/// listing it under `observability.logs.sinks[].kind`.
pub const PLUGIN_ID: &str = "dev.mcpg.builtin.log.stderr-json";

/// Descriptor shipped alongside the code.
pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.log.stderr-json
name: Built-in Stderr JSON Log Sink
description: |
  Gateway-bundled log sink: serialises each LogRecord as a JSON
  line to stderr. Opt-in — operators opt the
  sink into the LogSink fan-out by listing
  `kind: dev.mcpg.builtin.log.stderr-json` under
  `observability.logs.sinks`. Min-level filter defaults to Info.
  Note: the gateway's tracing-subscriber emits structured logs
  directly via the `kind: stderr` OS-stream sink — the plugin is
  only useful when operators want the LogRecord trait's structured
  shape rather than the subscriber's textual line, e.g. for piping
  into a downstream log shipper that prefers the protocol's
  fielded JSON.
class: log_sink
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// Stderr-JSON log sink. The writer is stashed behind a `Mutex` so
/// line writes are serialised — partial interleaving on stderr
/// would produce unparseable output for log collectors.
pub struct StderrJsonLogSink {
    manifest: PluginManifest,
    min_level: LogLevel,
    /// Writer is boxed + mutexed so tests can swap in an in-memory
    /// buffer. Production always uses `io::stderr()`.
    writer: Mutex<Box<dyn Write + Send + Sync + 'static>>,
}

impl StderrJsonLogSink {
    /// Build an instance writing to `io::stderr()` with `min_level`
    /// filtering. The common-case constructor.
    pub fn new(min_level: LogLevel) -> Arc<Self> {
        Arc::new(Self {
            manifest: manifest(),
            min_level,
            writer: Mutex::new(Box::new(std::io::stderr())),
        })
    }

    /// Build an instance writing to an operator-supplied sink.
    /// Used by integration tests to capture output; production
    /// code uses [`Self::new`].
    pub fn with_writer(
        min_level: LogLevel,
        writer: Box<dyn Write + Send + Sync + 'static>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manifest: manifest(),
            min_level,
            writer: Mutex::new(writer),
        })
    }
}

fn manifest() -> PluginManifest {
    PluginManifest {
        id: "dev.mcpg.builtin.log.stderr-json".into(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        name: "Built-in Stderr JSON Log Sink".into(),
        plugin_class: PluginClass::LogSink,
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
    }
}

#[mcpg_plugin_protocol::async_trait]
impl LogSink for StderrJsonLogSink {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn emit(&self, record: &LogRecord) {
        if record.level < self.min_level {
            return;
        }
        // Serialise to a local buffer + write the whole line +
        // newline under the writer lock. Two writes would admit
        // partial interleaving between records.
        let Ok(mut json) = serde_json::to_vec(record) else {
            // If serialisation fails we've got a bug in the
            // record shape; drop silently rather than spam
            // stderr with malformed output.
            return;
        };
        json.push(b'\n');
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(&json);
        }
    }

    async fn flush(&self, _timeout: Duration) -> Result<(), LogError> {
        if let Ok(mut w) = self.writer.lock() {
            w.flush().map_err(|e| LogError::Backend {
                reason: format!("flush stderr: {e}"),
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    /// An in-memory writer (`Arc<Mutex<Vec<u8>>>`) we can snapshot
    /// after emit calls. Wrapped in a newtype so the trait object
    /// stays `Write + Send + Sync`.
    struct ShareableBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for ShareableBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn sink_with_capture(min_level: LogLevel) -> (Arc<StderrJsonLogSink>, Arc<Mutex<Vec<u8>>>) {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink =
            StderrJsonLogSink::with_writer(min_level, Box::new(ShareableBuf(Arc::clone(&buf))));
        (sink, buf)
    }

    fn record(level: LogLevel, message: &str) -> LogRecord {
        LogRecord {
            timestamp_ns: 42,
            level,
            target: "mcpg".into(),
            message: message.into(),
            fields: Default::default(),
            span_id: None,
            trace_id: None,
            request_id: None,
            identity: None,
            node_id: None,
            plugin_id: None,
        }
    }

    #[tokio::test]
    async fn emit_writes_json_line_per_record() {
        let (sink, buf) = sink_with_capture(LogLevel::Trace);
        sink.emit(&record(LogLevel::Info, "hello")).await;
        sink.emit(&record(LogLevel::Warn, "world")).await;

        let written = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = written.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2, "one line per record");
        let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v1["level"], "info");
        assert_eq!(v1["message"], "hello");
        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v2["level"], "warn");
    }

    #[tokio::test]
    async fn min_level_filters_lower_severity() {
        let (sink, buf) = sink_with_capture(LogLevel::Warn);
        sink.emit(&record(LogLevel::Info, "below")).await;
        sink.emit(&record(LogLevel::Warn, "at-threshold")).await;
        sink.emit(&record(LogLevel::Error, "above")).await;

        let written = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = written.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2, "info dropped");
        assert!(!written.contains("below"));
        assert!(written.contains("at-threshold"));
        assert!(written.contains("above"));
    }

    #[tokio::test]
    async fn flush_returns_ok_when_writer_is_healthy() {
        let (sink, _) = sink_with_capture(LogLevel::Info);
        assert!(sink.flush(Duration::from_millis(1)).await.is_ok());
    }

    #[test]
    fn descriptor_yaml_parses_as_log_sink() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.log.stderr-json");
        assert_eq!(d.class, PluginClass::LogSink);
    }

    #[tokio::test]
    async fn stderr_constructor_smoke_check() {
        // Spec: the stderr-writing constructor returns a usable
        // plugin even if we can't capture its output in a test.
        // Emit once + verify no panic; stderr capture is out of
        // scope for unit tests.
        let sink = StderrJsonLogSink::new(LogLevel::Error);
        sink.emit(&record(LogLevel::Error, "this goes to the real stderr"))
            .await;
        // Placate clippy: Cursor is just shown as an import in
        // rustdoc examples for test-writer patterns.
        let _ = Cursor::new(Vec::<u8>::new());
    }
}
