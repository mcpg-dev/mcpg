//! Per-tool-call observability hook for the Control Plane.
//!
//! The dispatch path emits a `ToolCallSample` for every tool call
//! it serves. The gateway holds an `Arc<dyn ToolCallRecorder>`
//! that an integrator wires up at startup; the default
//! `NoopRecorder` discards everything so the call site has zero
//! cost when nothing is registered.
//!
//! The cp-client side (`mcpg-control-plane-client`) ships
//! a `MetricsBuffer` that already implements the same shape over
//! the wire. The integrator that boots both crates in one
//! process (today: `mcpg --enroll <URL>`, the standalone CP-attached
//! agent) writes a thin adapter:
//!
//! ```ignore
//! struct CpMetrics(MetricsBuffer);
//! impl ToolCallRecorder for CpMetrics {
//!     fn record(&self, sample: ToolCallSample) {
//!         self.0.record(translate(sample));
//!     }
//! }
//! ```
//!
//! Privacy invariant: tool *names* and aggregate stats only.
//! Tool *arguments* and *responses* are NEVER captured here —
//! they may contain PII or secrets. `error_hash` is BLAKE3 of
//! the error message; the literal string is never shipped.
//! Operators correlate via local gateway logs by hash.

use std::sync::Arc;
use std::time::Duration;

/// Max serialized payload size shipped per sample when capture is
/// on. Anything beyond is dropped + flagged `payload_truncated:
/// true`. 256 KB matches the typical ceiling for tool-call args
/// + responses; a file-upload binding that exceeds it should be
///   captured via a separate content-store URI rather than inline.
pub const PAYLOAD_CAPTURE_CAP_BYTES: usize = 256 * 1024;

/// Serialize a JSON value for payload capture, enforcing
/// [`PAYLOAD_CAPTURE_CAP_BYTES`]. Returns
/// `(Some(bytes), false)` on a clean capture,
/// `(None, true)` when the serialized form is over the cap, and
/// `(None, false)` when serialization itself failed (treated as
/// "couldn't capture, not truncation").
pub fn serialize_payload(value: &serde_json::Value) -> (Option<Vec<u8>>, bool) {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= PAYLOAD_CAPTURE_CAP_BYTES => (Some(bytes), false),
        Ok(_) => (None, true),
        Err(_) => (None, false),
    }
}

/// Same as [`serialize_payload`] for `ToolCallResult` — the result
/// type doesn't have a `serde_json::Value` representation
/// available pre-serialization, so we serialize then size-check
/// in one shot.
pub fn serialize_result_payload(
    result: &crate::protocol::ToolCallResult,
) -> (Option<Vec<u8>>, bool) {
    match serde_json::to_vec(result) {
        Ok(bytes) if bytes.len() <= PAYLOAD_CAPTURE_CAP_BYTES => (Some(bytes), false),
        Ok(_) => (None, true),
        Err(_) => (None, false),
    }
}

/// Emit the truncation counter with a `path` label
/// (`direct` / `task_augmented` / `policy_chain_deny` /
/// `policy_static_deny`) so operators can see where capture is
/// hitting the cap.
pub fn note_truncation(path: &'static str) {
    metrics::counter!(
        "mcpg_payload_capture_truncated_total",
        "path" => path,
    )
    .increment(1);
}

/// Captured at the dispatch site. Cheap to construct — no
/// allocations beyond the two strings (plugin_id, tool_name)
/// the dispatcher already has on hand.
#[derive(Clone, Debug)]
pub struct ToolCallSample {
    /// Plugin / binding family that owns the tool (e.g.
    /// `"github"`, `"sql"`, `"nats"`). For the gateway today
    /// this is the `backend_kind`.
    pub plugin_id: String,
    /// The tool's wire name (e.g. `"list_repos"`).
    pub tool_name: String,
    /// Optional binding profile id when the tool routes through
    /// a named binding profile rather than the default.
    pub binding_id: Option<String>,
    /// Wall-clock at dispatch start (informational; CP uses its
    /// own ingest clock as authoritative for queries).
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Dispatch wall-clock duration.
    pub duration: Duration,
    /// Outcome class.
    pub outcome: SampleOutcome,
    /// Coarse error code when classifiable (e.g. `"TIMEOUT"`,
    /// `"INVALID_ARG"`, `"POLICY_DENIED"`). Empty on `Ok`.
    pub error_code: Option<String>,
    /// BLAKE3 hex of the error message. Operators correlate via
    /// local logs by hash; we never ship the literal string.
    /// Empty on `Ok`.
    pub error_hash: Option<String>,
    /// Correlation id for tracing.
    pub request_id: Option<String>,
    /// Identity of the caller (e.g. `"user:alice@acme"`,
    /// `"service:cron"`). May be `None` for anonymous.
    pub caller_subject: Option<String>,
    /// OPTIONAL request payload bytes (Enterprise opt-in). Off by
    /// default; populated only when the operator sets
    /// `control_plane.capture_payloads: true` and the active license
    /// carries the `payload_capture` feature flag. CP encrypts at
    /// ingest with a per-tenant key.
    pub request_payload: Option<Vec<u8>>,
    /// OPTIONAL response payload bytes. Same gating as
    /// `request_payload`.
    pub response_payload: Option<Vec<u8>>,
    /// Set when capture was enabled but the serialized payload
    /// exceeded [`PAYLOAD_CAPTURE_CAP_BYTES`]. Operators see the
    /// `mcpg_payload_capture_truncated_total` counter; the
    /// payload fields stay `None` rather than shipping an
    /// incomplete blob.
    pub payload_truncated: bool,
}

/// Coarse outcome class. Maps 1:1 to the wire `ToolOutcome` enum
/// in `mcpg.cp.v1.proto` and the CP-side `tool_invocations.outcome`
/// column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleOutcome {
    /// The tool call succeeded.
    Ok,
    /// Caller-side fault (bad input, invalid arguments, etc.).
    /// Does NOT include policy denials — those have their own
    /// variant.
    ClientError,
    /// Server-side fault (backend down, transport error, etc.).
    ServerError,
    /// Pre-dispatch policy gate denied the call. Recorded with
    /// `duration ≈ 0` since no backend dispatch happened.
    PolicyDenied,
    /// Pre-dispatch quota gate refused the call because the CP-
    /// reported tool-call quota for the org has been exhausted.
    /// Recorded with `duration ≈ 0`.
    QuotaExceeded,
    /// `dev.mcpg/idempotency` cache hit: the call replayed a
    /// previously-cached terminal envelope rather than running
    /// dispatch. CP-side aggregation MUST exclude this variant
    /// from `tool_calls_per_month` quota math (replays are not
    /// new executions). The gateway emits this variant; the CP-side
    /// aggregation must be updated to honour the exclusion.
    IdempotentReplay,
}

impl SampleOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
            Self::PolicyDenied => "policy_denied",
            Self::QuotaExceeded => "quota_exceeded",
            Self::IdempotentReplay => "idempotent_replay",
        }
    }
}

/// Records `ToolCallSample`s. Implementations must be cheap
/// (constant-time, lock-free or short-critical-section locks) —
/// `record` is called on every tool call from the dispatch hot
/// path.
///
/// The default `NoopRecorder` discards everything so a gateway
/// running without a CP attached has zero cost.
pub trait ToolCallRecorder: Send + Sync {
    fn record(&self, sample: ToolCallSample);
    /// Whether this recorder wants the dispatch site to capture
    /// `request_payload` + `response_payload` (Enterprise opt-in).
    /// Default `false`; only the
    /// cp-attached integrator returns `true` when the operator
    /// has set `control_plane.capture_payloads: true` AND the
    /// active license carries the `payload_capture` feature
    /// flag.
    ///
    /// Checked on the dispatch hot path so the gateway can
    /// avoid serializing args + result into JSON when capture
    /// is off — the default path stays zero-cost.
    fn payload_capture_enabled(&self) -> bool {
        false
    }
}

/// No-op recorder used when nothing is wired. Cheap: a method
/// call with no side effects.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRecorder;

impl ToolCallRecorder for NoopRecorder {
    fn record(&self, _sample: ToolCallSample) {}
}

/// BLAKE3 hex hash of an error message — operators correlate the
/// on-CP `error_hash` against gateway logs without ever shipping
/// the literal string. `None` for empty input. Single canonical
/// hash function so cp-server and gateway agree.
pub fn hash_error(msg: &str) -> Option<String> {
    if msg.is_empty() {
        None
    } else {
        Some(blake3::hash(msg.as_bytes()).to_hex().to_string())
    }
}

/// Thread-safe handle. Cloning is cheap (Arc bump). The default
/// constructed handle wraps `NoopRecorder`.
#[derive(Clone)]
pub struct ToolCallRecorderHandle(Arc<dyn ToolCallRecorder>);

impl ToolCallRecorderHandle {
    pub fn new(inner: Arc<dyn ToolCallRecorder>) -> Self {
        Self(inner)
    }
    pub fn noop() -> Self {
        Self(Arc::new(NoopRecorder))
    }
    pub fn record(&self, sample: ToolCallSample) {
        self.0.record(sample);
    }
    pub fn payload_capture_enabled(&self) -> bool {
        self.0.payload_capture_enabled()
    }
}

impl Default for ToolCallRecorderHandle {
    fn default() -> Self {
        Self::noop()
    }
}

impl std::fmt::Debug for ToolCallRecorderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCallRecorderHandle")
            .finish_non_exhaustive()
    }
}

/// Classify a `ToolCallResult` into a `SampleOutcome` + extract
/// any error code embedded in the result's content.
///
/// MCPG's binding adapters serialize errors as JSON in the first
/// `ToolContent::Text`; we look for `kind` (transport_error,
/// client_error, server_error) or `statusCode` (4xx → client,
/// 5xx → server) to classify. Falls back to `ServerError` when
/// the result is `is_error=true` but unparseable.
pub fn classify_result(
    result: &crate::protocol::ToolCallResult,
) -> (SampleOutcome, Option<String>, Option<String>) {
    if !result.is_error {
        return (SampleOutcome::Ok, None, None);
    }
    let mut error_text: Option<&str> = None;
    for content in &result.content {
        if let crate::protocol::ToolContent::Text { text, .. } = content {
            error_text = Some(text);
            break;
        }
    }
    let raw = error_text.unwrap_or("");
    let mut code: Option<String> = None;
    let mut outcome = SampleOutcome::ServerError;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(c) = v.get("code").and_then(|v| v.as_str()) {
            code = Some(c.to_string());
        }
        if let Some(kind) = v.get("kind").and_then(|v| v.as_str()) {
            match kind {
                "client_error" | "validation_error" => outcome = SampleOutcome::ClientError,
                "server_error" | "transport_error" | "backend_error" => {
                    outcome = SampleOutcome::ServerError
                }
                _ => {}
            }
        }
        if let Some(status) = v.get("statusCode").and_then(|v| v.as_u64()) {
            outcome = if (400..500).contains(&status) {
                SampleOutcome::ClientError
            } else {
                SampleOutcome::ServerError
            };
        }
    }
    let hash = hash_error(raw);
    (outcome, code, hash)
}

/// Map an MCPG `backend_kind` (the dispatcher's binding-family
/// classification) to the `plugin_id` field of a sample.
pub fn plugin_id_from_kind(kind: &str) -> String {
    kind.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ToolCallResult, ToolContent};

    #[test]
    fn noop_handle_is_zero_cost() {
        let h = ToolCallRecorderHandle::noop();
        h.record(ToolCallSample {
            plugin_id: "p".into(),
            tool_name: "t".into(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: Duration::from_millis(1),
            outcome: SampleOutcome::Ok,
            error_code: None,
            error_hash: None,
            request_id: None,
            caller_subject: None,
            request_payload: None,
            response_payload: None,
            payload_truncated: false,
        });
    }

    #[test]
    fn quota_exceeded_outcome_maps_to_wire_string() {
        // Stable wire string; CP's `tool_invocations.outcome`
        // column + the proto enum on the cp-client side both
        // depend on this exact spelling. Regression guard.
        assert_eq!(SampleOutcome::QuotaExceeded.as_str(), "quota_exceeded");
    }

    #[test]
    fn serialize_payload_under_cap_returns_bytes() {
        let v = serde_json::json!({"foo": "bar"});
        let (bytes, truncated) = serialize_payload(&v);
        assert!(bytes.is_some());
        assert!(!truncated);
    }

    #[test]
    fn serialize_payload_over_cap_returns_truncated_flag() {
        let big = "x".repeat(PAYLOAD_CAPTURE_CAP_BYTES + 1);
        let v = serde_json::json!({"data": big});
        let (bytes, truncated) = serialize_payload(&v);
        assert!(bytes.is_none());
        assert!(truncated);
    }

    #[test]
    fn serialize_result_payload_under_cap_returns_bytes() {
        let r = ToolCallResult {
            content: vec![ToolContent::text("ok".to_owned())],
            structured_content: None,
            is_error: false,
            meta: None,
        };
        let (bytes, truncated) = serialize_result_payload(&r);
        assert!(bytes.is_some());
        assert!(!truncated);
    }

    #[test]
    fn serialize_result_payload_over_cap_returns_truncated_flag() {
        let big = "x".repeat(PAYLOAD_CAPTURE_CAP_BYTES + 1);
        let r = ToolCallResult {
            content: vec![ToolContent::text(big)],
            structured_content: None,
            is_error: false,
            meta: None,
        };
        let (bytes, truncated) = serialize_result_payload(&r);
        assert!(bytes.is_none());
        assert!(truncated);
    }

    /// Test recorder that captures samples into a buffer + reports
    /// `payload_capture_enabled = true` so the dispatch sites
    /// exercise the serialization path.
    #[derive(Default)]
    struct RecordingRecorder {
        samples: std::sync::Mutex<Vec<ToolCallSample>>,
        capture_on: bool,
    }

    impl ToolCallRecorder for RecordingRecorder {
        fn record(&self, sample: ToolCallSample) {
            self.samples.lock().unwrap().push(sample);
        }
        fn payload_capture_enabled(&self) -> bool {
            self.capture_on
        }
    }

    #[test]
    fn handle_threads_payload_through_recorder() {
        let recorder = Arc::new(RecordingRecorder {
            samples: Default::default(),
            capture_on: true,
        });
        let handle = ToolCallRecorderHandle::new(recorder.clone());
        assert!(handle.payload_capture_enabled());
        let v = serde_json::json!({"args": "value"});
        let (bytes, _trunc) = serialize_payload(&v);
        handle.record(ToolCallSample {
            plugin_id: "test".into(),
            tool_name: "do".into(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: Duration::from_millis(1),
            outcome: SampleOutcome::PolicyDenied,
            error_code: Some("policy:test".into()),
            error_hash: None,
            request_id: None,
            caller_subject: None,
            request_payload: bytes,
            response_payload: None,
            payload_truncated: false,
        });
        let captured = recorder.samples.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].request_payload.is_some());
        assert!(captured[0].response_payload.is_none());
        assert!(!captured[0].payload_truncated);
    }

    #[test]
    fn classify_ok() {
        let r = ToolCallResult {
            content: vec![],
            structured_content: None,
            is_error: false,
            meta: None,
        };
        let (outcome, code, hash) = classify_result(&r);
        assert_eq!(outcome, SampleOutcome::Ok);
        assert!(code.is_none());
        assert!(hash.is_none());
    }

    #[test]
    fn classify_status_code_4xx_is_client_error() {
        let r = ToolCallResult {
            content: vec![ToolContent::text(
                r#"{"statusCode": 404, "kind": "transport_error"}"#.to_owned(),
            )],
            structured_content: None,
            is_error: true,
            meta: None,
        };
        let (outcome, _code, hash) = classify_result(&r);
        // statusCode=4xx wins over the kind hint.
        assert_eq!(outcome, SampleOutcome::ClientError);
        assert!(hash.is_some());
    }

    #[test]
    fn classify_status_code_5xx_is_server_error() {
        let r = ToolCallResult {
            content: vec![ToolContent::text(r#"{"statusCode": 502}"#.to_owned())],
            structured_content: None,
            is_error: true,
            meta: None,
        };
        let (outcome, _, _) = classify_result(&r);
        assert_eq!(outcome, SampleOutcome::ServerError);
    }

    #[test]
    fn classify_kind_validation_is_client_error() {
        let r = ToolCallResult {
            content: vec![ToolContent::text(
                r#"{"kind": "validation_error", "code": "MISSING_FIELD"}"#.to_owned(),
            )],
            structured_content: None,
            is_error: true,
            meta: None,
        };
        let (outcome, code, _) = classify_result(&r);
        assert_eq!(outcome, SampleOutcome::ClientError);
        assert_eq!(code, Some("MISSING_FIELD".into()));
    }

    #[test]
    fn classify_unstructured_error_falls_back_to_server() {
        let r = ToolCallResult {
            content: vec![ToolContent::text("backend exploded".to_owned())],
            structured_content: None,
            is_error: true,
            meta: None,
        };
        let (outcome, code, hash) = classify_result(&r);
        assert_eq!(outcome, SampleOutcome::ServerError);
        assert!(code.is_none());
        assert!(hash.is_some());
    }

    #[test]
    fn hash_is_deterministic_and_omits_empty() {
        assert!(hash_error("").is_none());
        let h1 = hash_error("connection refused");
        let h2 = hash_error("connection refused");
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_error("connection timed out"));
    }
}
