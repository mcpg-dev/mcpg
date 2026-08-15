//! Anonymous adoption telemetry config. Distinct from the OTel
//! `observability` signal sinks: this is a minimal, opt-out, vendor-facing
//! usage ping (version + first-party plugins) so we can see how the community
//! grows. Control-plane-only, fail-open, schema-pinned, and auto-off when
//! air-gapped / licensed / CP-attached / CI. Disable also via `DO_NOT_TRACK` or
//! `MCPG_TELEMETRY=off`, independent of this block.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageReportingConfig {
    /// Send the anonymous adoption ping. Defaults to `false`.
    /// `DO_NOT_TRACK=1` / `MCPG_TELEMETRY=off` disable regardless.
    #[serde(default)]
    pub enabled: bool,

    /// Ingest endpoint (HTTPS). Self-hostable — point it at your own collector.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
}

fn default_endpoint() -> String {
    "https://telemetry.mcpg.dev/v1/usage".to_string()
}

impl Default for UsageReportingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
        }
    }
}

impl UsageReportingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enabled && !self.endpoint.starts_with("https://") {
            anyhow::bail!("usage_reporting.endpoint must be an https:// URL");
        }
        Ok(())
    }
}
