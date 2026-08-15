//! Top-level `webhook:` block — outbound webhook delivery
//! configuration (gateway-emitted notifications).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn default_webhook_timeout_ms() -> u64 {
    5000
}

fn default_webhook_max_retries() -> u32 {
    3
}

fn default_webhook_retry_backoff_ms() -> u64 {
    1000
}

fn default_webhook_buffer_size() -> usize {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoints: Vec<WebhookEndpointConfig>,
    #[serde(default = "default_webhook_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_webhook_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    #[serde(default = "default_webhook_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_webhook_buffer_size")]
    pub buffer_size: usize,
    #[serde(default)]
    pub circuit_breaker: WebhookCircuitBreakerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookCircuitBreakerConfig {
    #[serde(default = "default_webhook_cb_threshold")]
    pub consecutive_5xx_threshold: u32,
    #[serde(default = "default_webhook_cb_open_ms")]
    pub open_duration_ms: u64,
    #[serde(default = "default_webhook_cb_probes")]
    pub half_open_probe_count: u32,
}

impl Default for WebhookCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_5xx_threshold: default_webhook_cb_threshold(),
            open_duration_ms: default_webhook_cb_open_ms(),
            half_open_probe_count: default_webhook_cb_probes(),
        }
    }
}

fn default_webhook_cb_threshold() -> u32 {
    5
}
fn default_webhook_cb_open_ms() -> u64 {
    30000
}
fn default_webhook_cb_probes() -> u32 {
    1
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoints: Vec::new(),
            max_retries: default_webhook_max_retries(),
            retry_backoff_ms: default_webhook_retry_backoff_ms(),
            timeout_ms: default_webhook_timeout_ms(),
            buffer_size: default_webhook_buffer_size(),
            circuit_breaker: WebhookCircuitBreakerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpointConfig {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub slow_threshold_ms: Option<u64>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}
