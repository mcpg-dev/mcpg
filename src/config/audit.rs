//! `governance.audit:` block — compliance audit channel that fans
//! out to a list of sinks, each with its own gating and routing.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::default_true;
use super::observability::validate_sink_kind;

/// One entry of `governance.audit.sinks`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkConfig {
    /// Plugin id (or `plugins[]` alias) of the audit sink.
    pub kind: String,
    /// Sink-specific config object. Schema depends on `kind:`.
    #[serde(default)]
    pub config: serde_json::Value,
    /// Per-sink severity floor; parsed, not enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// A gating sink (the default) is awaited: under `on_failure:
    /// fail_closed` a record it loses refuses the operation, and it
    /// satisfies `required`. `false` makes the sink best-effort: it gets
    /// each record in the background, never delays or refuses a request,
    /// and drops (and counts in `mcpg_audit_sink_dropped_total`) what it
    /// cannot keep up with.
    #[serde(default = "default_true")]
    pub gating: bool,
    /// Which records this sink receives.
    #[serde(default, skip_serializing_if = "AuditSinkRouting::is_empty")]
    pub routing: AuditSinkRouting,
}

/// Action filters of one audit sink. Patterns are globs over the
/// record's `action` (`*` matches any run), e.g. `mcpg.resource.*`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkRouting {
    /// Only these actions; empty takes every action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_actions: Vec<String>,
    /// Never these actions; wins over `allow_actions`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_actions: Vec<String>,
}

impl AuditSinkRouting {
    fn is_empty(&self) -> bool {
        self.allow_actions.is_empty() && self.deny_actions.is_empty()
    }
}

/// `governance.audit:` block. Kept apart from `observability:`, with
/// an inner schema aligned to the OTel signal-triad sinks-list
/// pattern (`logs` / `metrics` / `traces`). Spec §9.12 defines the
/// semantics; the fields here are the Rust projection.
///
/// Audit sinks fan out via `sinks: [{kind, config, level?}]`. The
/// built-in `dev.mcpg.builtin.audit.local-file` activates only
/// when its plugin id appears in `sinks[].kind` (there is no
/// `disable_builtins` toggle — just omit the sink to disable it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Master toggle for the audit channel. When `false`, no audit
    /// sinks are registered (built-in or plugin), no audit events
    /// are emitted, and `required` is ignored. Default `true`. Set
    /// `false` only for dev/test runs where compliance is out of
    /// scope.
    ///
    /// Audit is intentionally orthogonal to `observability.enabled`
    /// — operators occasionally disable observability for
    /// short-lived debugging runs, but compliance audit MUST stay
    /// on for production traffic.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// When `true` (default), the gateway REFUSES TO START unless
    /// at least one audit sink is serving traffic after plugin
    /// registration completes. Ignored when `enabled: false`.
    /// Operators explicitly set `false` only for dev / CI runs
    /// where compliance is not in scope.
    #[serde(default = "default_true")]
    pub required: bool,

    /// Policy for per-event emit failures. Today the fan-out is
    /// always best-effort at the registry level (failures are
    /// metricsed but don't block the request). This field is
    /// captured + validated so the operator's intent is durable;
    /// the runtime behavior hookup lands in a future improvement
    /// (the emit site needs to translate this into
    /// "return error from the tool-gate chain" on `fail_closed`).
    #[serde(default)]
    pub on_failure: AuditOnFailure,

    /// Emit `mcpg.tool.call.allowed` after every successful
    /// pre-dispatch tool_gate chain. Default `true` for the
    /// compliance posture most operators want — every tool call
    /// on record. High-volume / low-compliance deploys can set
    /// `false`; deny + challenge paths still emit regardless.
    #[serde(default = "default_true")]
    pub emit_tool_call_allowed: bool,

    /// Emit `mcpg.tool.call.completed` after every successful
    /// post-dispatch tool_gate chain. Default `true`. Records
    /// `execution_duration_ms` for auditors flagging long-running
    /// calls.
    #[serde(default = "default_true")]
    pub emit_tool_call_completed: bool,

    /// Audit-sink fan-out. Each entry's `kind:` is a
    /// plugin id resolved against the registered audit sinks at
    /// boot. The built-in `dev.mcpg.builtin.audit.local-file` is
    /// the canonical default — listed in
    /// [`AuditConfig::default`].
    #[serde(default = "default_audit_sinks")]
    pub sinks: Vec<AuditSinkConfig>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: true,
            on_failure: AuditOnFailure::default(),
            emit_tool_call_allowed: true,
            emit_tool_call_completed: true,
            sinks: default_audit_sinks(),
        }
    }
}

impl AuditConfig {
    pub fn validate(&self) -> Result<()> {
        for (i, sink) in self.sinks.iter().enumerate() {
            validate_sink_kind(&sink.kind, "audit", i)?;
            let patterns = sink
                .routing
                .allow_actions
                .iter()
                .chain(&sink.routing.deny_actions);
            if patterns.into_iter().any(|p| p.trim().is_empty()) {
                anyhow::bail!("audit.sinks[{i}].routing: an action pattern must not be empty");
            }
        }
        if self.enabled && self.required && self.sinks.is_empty() {
            return Err(anyhow::anyhow!(
                "audit.sinks must not be empty when audit.enabled = true and audit.required = true"
            ));
        }
        if self.enabled && self.required && !self.sinks.iter().any(|s| s.gating) {
            anyhow::bail!(
                "audit.required = true needs at least one sink with gating: true; \
                 a non-gating sink is best-effort and cannot be the audit of record"
            );
        }
        Ok(())
    }
}

fn default_audit_sinks() -> Vec<AuditSinkConfig> {
    // Default: the built-in local-file audit sink. Operators who
    // ship their own audit sink REPLACE this entry (the legacy
    // `disable_builtins: true` toggle is gone — list the kind to
    // enable, omit it to disable).
    vec![AuditSinkConfig {
        kind: "dev.mcpg.builtin.audit.local-file".to_owned(),
        config: serde_json::json!({}),
        level: None,
        gating: true,
        routing: AuditSinkRouting::default(),
    }]
}

/// Operator policy when an audit-sink `emit` fails.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditOnFailure {
    /// (default) On emit failure, refuse to serve the triggering
    /// request. Compliance-safe: no action happens without a
    /// durable audit trail. Subtle: this can wedge the gateway if
    /// every registered sink is broken — operators should always
    /// configure at least one sink whose availability they
    /// actually monitor.
    #[default]
    FailClosed,
    /// On emit failure, log + continue. The triggering request
    /// completes even if the audit event does not persist. Dev /
    /// CI use only — a compliance auditor will not accept this as
    /// SOC2-clean.
    FailOpen,
}
