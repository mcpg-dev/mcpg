//! Supervised inspector sidecar (`gateway.inspector`).
//!
//! Unlike the control-plane sidecar (flags-only), the inspector is
//! config-first: this block enables and shapes the supervised
//! `mcpg-inspector serve` child, and `--inspector-<flag>` passthrough
//! args override it (the child re-parses its own argv, so explicit
//! flags always win over the gap-only mapping the supervisor derives
//! from here).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectorSidecarConfig {
    /// Supervise an `mcpg-inspector` sidecar. `--inspector` flips this
    /// on for a single run.
    #[serde(default)]
    pub enabled: bool,

    /// host:port of the inspector's web UI + API (single origin).
    /// Defaults to the inspector's own `127.0.0.1:7846`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}
