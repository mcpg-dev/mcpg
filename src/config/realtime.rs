//! `mcp.realtime`: admission of realtime delivery.
//!
//! ```yaml
//! mcp:
//!   realtime:
//!     admission:
//!       tool: realtime.admit        # a tool binding of this gateway
//!       renew_interval_ms: 60000
//!       on_error: deny
//! ```

use serde::{Deserialize, Serialize};

/// `mcp.realtime`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RealtimeConfig {
    /// Ask a tool of this gateway before a caller gets realtime delivery,
    /// while it holds it, and when it lets go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<RealtimeAdmissionConfig>,
}

impl RealtimeConfig {
    pub fn is_default(&self) -> bool {
        self.admission.is_none()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let Some(admission) = &self.admission else {
            return Ok(());
        };
        if admission.tool.trim().is_empty() {
            anyhow::bail!("mcp.realtime.admission.tool is empty; name a tool binding");
        }
        if admission.renew_interval_ms < MIN_RENEW_INTERVAL_MS {
            anyhow::bail!(
                "mcp.realtime.admission.renew_interval_ms is {}; the least is {MIN_RENEW_INTERVAL_MS}",
                admission.renew_interval_ms
            );
        }
        Ok(())
    }
}

/// The shortest renew interval: each renew is a tool call per open stream.
pub const MIN_RENEW_INTERVAL_MS: u64 = 1_000;

/// `mcp.realtime.admission`.
///
/// The gateway calls `tool` as the caller, through the whole tool-call path
/// (policy, gates, the backend), with these arguments:
///
/// - `op`: `admit` (a caller opens realtime delivery), `renew` (it still
///   holds it) or `release` (it let go; best effort).
/// - `lease_id`: one id per held delivery, the same in all three calls and
///   on every replica.
/// - `kind`: `events` or `resource`.
/// - `delivery`: `stream`, `poll` or `webhook` for events; `listen` or
///   `subscribe` for a resource.
/// - `event`: `{name, arguments}` for events; `resource`: `{uri}` for a
///   resource.
/// - `client`: `{name, version}` of the MCP client, when it named itself.
///
/// The tool answers with an object that has a boolean `allow`. With
/// `allow: true`, `renew_after_seconds` (or `renewAfterSeconds`) may shorten
/// the renew interval. With `allow: false`, `error: {code, message, data}`
/// reaches the caller: a numeric `code` is the JSON-RPC error code and
/// `data` (or `details`) its data; any other `code` gives `-32013` with the
/// whole `error` object as data.
///
/// The tool is internal: `tools/list` does not show it and a caller's own
/// `tools/call` of it is refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RealtimeAdmissionConfig {
    /// The tool binding to call.
    pub tool: String,
    /// How often a held stream or subscription is renewed. A poll lease and
    /// a webhook subscription are renewed when the caller polls or
    /// refreshes, at most this often. Set the lease lifetime on the tool's
    /// side to at least twice this.
    #[serde(default = "default_renew_interval_ms")]
    pub renew_interval_ms: u64,
    /// What a call that fails or answers no decision means: `deny`
    /// (default) refuses the caller, `allow` admits it.
    #[serde(default)]
    pub on_error: AdmissionOnError,
}

fn default_renew_interval_ms() -> u64 {
    60_000
}

/// The decision when the admission tool gives none.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOnError {
    #[default]
    Deny,
    Allow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_renew_every_minute_and_fail_closed() {
        let cfg: RealtimeConfig =
            serde_yaml::from_str("admission:\n  tool: realtime.admit\n").unwrap();
        let admission = cfg.admission.clone().unwrap();
        assert_eq!(admission.renew_interval_ms, 60_000);
        assert_eq!(admission.on_error, AdmissionOnError::Deny);
        cfg.validate().unwrap();
        assert!(RealtimeConfig::default().is_default());
        RealtimeConfig::default().validate().unwrap();
    }

    #[test]
    fn an_empty_tool_and_a_too_short_interval_are_refused() {
        for (yaml, field) in [
            ("admission:\n  tool: ''\n", "admission.tool"),
            (
                "admission:\n  tool: t\n  renew_interval_ms: 10\n",
                "renew_interval_ms",
            ),
        ] {
            let cfg: RealtimeConfig = serde_yaml::from_str(yaml).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(field), "{err}");
        }
        assert!(serde_yaml::from_str::<RealtimeConfig>("admission:\n  tool: t\n  x: 1\n").is_err());
    }
}
