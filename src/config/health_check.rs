//! `server.health_check:` block — periodic outbound-binding health
//! probe configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default = "crate::config::default_true")]
    pub enabled: bool,
    #[serde(default = "default_hc_interval_secs")]
    pub interval_ms: u64,
    #[serde(default = "default_hc_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_hc_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_hc_degraded_latency_ms")]
    pub degraded_latency_threshold_ms: u64,
}

fn default_hc_interval_secs() -> u64 {
    30
}
fn default_hc_timeout_ms() -> u64 {
    2000
}
fn default_hc_unhealthy_threshold() -> u32 {
    3
}
fn default_hc_degraded_latency_ms() -> u64 {
    1000
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: crate::config::default_true(),
            interval_ms: default_hc_interval_secs(),
            timeout_ms: default_hc_timeout_ms(),
            unhealthy_threshold: default_hc_unhealthy_threshold(),
            degraded_latency_threshold_ms: default_hc_degraded_latency_ms(),
        }
    }
}
