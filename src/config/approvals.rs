//! Tool-gate human approval configuration.

use serde::{Deserialize, Serialize};

/// Tool-gate human approval configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsConfig {
    /// Env var name from which the gateway reads the
    /// HMAC signing key for approval callback URLs. The key MUST
    /// be at least 32 bytes (256 bits) — the gateway hard-fails
    /// boot if shorter. When unset, the gateway falls back to a
    /// random per-process key (callbacks won't survive a restart).
    #[serde(default)]
    pub signing_key_env: Option<String>,
    /// Public base url the gateway hands to notifiers as the
    /// callback URL prefix (e.g. `"https://gw.example.com"`). The
    /// runtime appends `/webhooks/approvals/<id>?expires=...&sig=...`.
    #[serde(default)]
    pub callback_base_url: Option<String>,
    /// Seconds beyond `deadline_at` during which late callbacks
    /// still authenticate. Defence-in-depth — the registry's own
    /// deadline timer already rejects late resolutions; this just
    /// keeps the URL valid for short retries. Default 60s.
    #[serde(default = "default_callback_grace_ms")]
    pub callback_grace_ms: u64,
}

fn default_callback_grace_ms() -> u64 {
    60000
}
