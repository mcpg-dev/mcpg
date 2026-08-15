//! Top-level `feature_flags:` block — explicit operator opt-ins for
//! strictness / compatibility toggles that previously lived as
//! `MCPG_*` environment variables. Adding flags to this block is
//! preferred over scattering env-var reads across the runtime
//! because:
//!
//! - The flag is surfaced in `mcpg config doc` and JSON Schema, so
//!   operators discover it via the curated reference instead of
//!   hunting through source.
//! - Validation, defaults, and serde shape live with the rest of
//!   `AppConfig`, so the reload path picks up rotations
//!   automatically.
//! - The audit ledger emits `mcpg.config.feature_flags_active` at
//!   boot when any flag is non-default — auditors get an explicit
//!   record of which strictness gates the deployment overrides.
//!
//! The two existing `MCPG_*` strictness flags
//! (`ALLOW_HEADER_PASSTHROUGH`, `SEP2260_PANIC`) were migrated
//! into this block. It is named `feature_flags:` (rather than
//! `features:`) for unambiguous distinction from per-binding
//! capability metadata.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Operator-controlled strictness / compat flags.
///
/// Every field defaults to the safe / standards-compliant value;
/// flipping a flag is an explicit acknowledgement that the operator
/// is taking on the risk the default protects against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlagsConfig {
    /// Forward credential-shaped inbound HTTP headers (`Authorization`,
    /// `Cookie`, `X-API-Key`, …) through to outbound bindings. The
    /// gateway strips these by default to avoid leaking client
    /// tokens to upstreams. Flip to `true` only for deployments that
    /// intentionally proxy bearer tokens to the binding (e.g., a
    /// pure-router deployment in a trusted network).
    #[serde(default)]
    pub allow_header_passthrough: bool,

    /// Upgrade SEP-2260 violations (server-initiated request emitted
    /// without an originating client request id) from a warning +
    /// metric counter to a process panic. Useful in CI / dev where
    /// the violation indicates a bug; should stay `false` in
    /// production so a single misrouted code path does not take the
    /// gateway down.
    #[serde(default)]
    pub sep2260_panic_on_orphan: bool,

    /// Master switch for the operator-defined diagnostic tools
    /// (`mcpg.command.*` / `mcpg.network.*`). When `false`, every
    /// field under the top-level `debug:` block is ignored AND the
    /// debug tools are stripped from the capability registry
    /// regardless of `debug.tools.exposure`. Production deploys
    /// keep this off; flip on for CI / dev only.
    ///
    /// This flag lives here (rather than at the previous
    /// `debug.enabled` location) so every operator-controlled
    /// strictness toggle lives in one block.
    #[serde(default)]
    pub debug_tools_enabled: bool,
}

impl FeatureFlagsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        // Every field is bool with a safe default — no inter-field
        // invariants today. Function exists so the AppConfig
        // validator can call it uniformly with the rest of the
        // top-level blocks; future flags with constraints land here.
        Ok(())
    }

    /// True when at least one flag is flipped off the safe default.
    /// Drives the `mcpg.config.feature_flags_active` audit emission
    /// at boot / reload — emit only when there's something to record.
    #[must_use]
    pub fn any_active(&self) -> bool {
        self.allow_header_passthrough || self.sep2260_panic_on_orphan || self.debug_tools_enabled
    }

    /// Snapshot of active flags as a JSON object — the body of the
    /// audit event's `details` field. Default-valued flags are
    /// omitted so the record stays terse.
    #[must_use]
    pub fn audit_details(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if self.allow_header_passthrough {
            obj.insert(
                "allow_header_passthrough".into(),
                serde_json::Value::Bool(true),
            );
        }
        if self.sep2260_panic_on_orphan {
            obj.insert(
                "sep2260_panic_on_orphan".into(),
                serde_json::Value::Bool(true),
            );
        }
        if self.debug_tools_enabled {
            obj.insert("debug_tools_enabled".into(), serde_json::Value::Bool(true));
        }
        serde_json::Value::Object(obj)
    }
}
