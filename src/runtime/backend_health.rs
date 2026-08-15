//! Per-binding health checking — background probing of backend health.
//!
//! A background task periodically probes each binding's backend and maintains
//! a shared `BackendHealthMap` that the `/health?detail=bindings` endpoint
//! can expose to operators.

use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::config::{BackendConfig, HealthCheckConfig};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BackendHealthStatus {
    pub status: HealthStatus,
    #[serde(skip)]
    pub last_check: Option<Instant>,
    #[serde(skip)]
    pub last_success: Option<Instant>,
    pub consecutive_failures: u32,
    pub latency_ms: Option<u64>,
}

impl Default for BackendHealthStatus {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            last_check: None,
            last_success: None,
            consecutive_failures: 0,
            latency_ms: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Shared binding health map, keyed by binding name.
pub type BackendHealthMap = Arc<DashMap<String, BackendHealthStatus>>;

/// Create a new empty health map, pre-populated with Unknown for each binding.
pub fn new_health_map(bindings: &[BackendConfig]) -> BackendHealthMap {
    let map = DashMap::new();
    for binding in bindings {
        map.insert(binding.name.clone(), BackendHealthStatus::default());
    }
    Arc::new(map)
}

// ---------------------------------------------------------------------------
// Prober
// ---------------------------------------------------------------------------

/// Background task that periodically probes each binding's backend health.
pub struct BackendHealthProber {
    config: HealthCheckConfig,
    bindings: Vec<BackendConfig>,
    health_map: BackendHealthMap,
    /// Plugin registry, consulted by `kind` for a manifest-declared
    /// [`BackendProfile`](mcpg_plugin_protocol::manifest::BackendProfile)
    /// health-probe declaration. When a binding's kind declares a profile,
    /// the declaration drives the probe; otherwise the prober falls back to
    /// the per-kind match. `None` (or a kind that declares nothing) is
    /// always the case today, so the fallback path is the live one.
    registry: Option<Arc<mcpg_plugin_host::PluginRegistry>>,
}

impl BackendHealthProber {
    pub fn new(
        config: HealthCheckConfig,
        bindings: Vec<BackendConfig>,
        health_map: BackendHealthMap,
        registry: Option<Arc<mcpg_plugin_host::PluginRegistry>>,
    ) -> Self {
        Self {
            config,
            bindings,
            health_map,
            registry,
        }
    }

    /// Spawn the background health-check task. Returns a JoinHandle.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    async fn run(&self) {
        let interval = Duration::from_millis(self.config.interval_ms);
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tick.tick().await;
            self.probe_all().await;
        }
    }

    async fn probe_all(&self) {
        for binding in &self.bindings {
            let start = Instant::now();
            let probe_result = self.probe_binding(binding).await;
            let latency = start.elapsed();

            let mut entry = self.health_map.entry(binding.name.clone()).or_default();

            entry.last_check = Some(Instant::now());
            entry.latency_ms = Some(latency.as_millis() as u64);

            match probe_result {
                ProbeResult::Success => {
                    entry.consecutive_failures = 0;
                    entry.last_success = Some(Instant::now());
                    if latency.as_millis() as u64 > self.config.degraded_latency_threshold_ms {
                        entry.status = HealthStatus::Degraded;
                        debug!(backend = %binding.name, latency_ms = latency.as_millis(), "binding health: degraded (slow)");
                    } else {
                        entry.status = HealthStatus::Healthy;
                    }
                }
                ProbeResult::Failure(reason) => {
                    entry.consecutive_failures += 1;
                    if entry.consecutive_failures >= self.config.unhealthy_threshold {
                        entry.status = HealthStatus::Unhealthy;
                        warn!(
                            backend = %binding.name,
                            failures = entry.consecutive_failures,
                            reason = %reason,
                            "binding health: unhealthy"
                        );
                    } else {
                        entry.status = HealthStatus::Degraded;
                    }
                }
                ProbeResult::Skip => {
                    // No-op: keep current status (Unknown for unprobeable types)
                }
            }

            metrics::gauge!("mcpg_binding_health_status",
                "binding" => binding.name.clone(),
                "status" => entry.status.to_string(),
            )
            .set(match entry.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                HealthStatus::Unhealthy => 0.0,
                HealthStatus::Unknown => -1.0,
            });
        }
    }

    async fn probe_binding(&self, binding: &BackendConfig) -> ProbeResult {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        // Generic path: when the binding's kind declares a manifest
        // `BackendProfile.health_probe`, honour the declaration. First-party
        // plugins now declare these profiles, so this generic
        // `probe_from_declaration` path is the live one.
        if let Some((kind, spec)) = crate::backends::binding_kind_and_spec(&binding.backend, false)
            && let Some(profile) = self
                .registry
                .as_ref()
                .and_then(|r| r.backend_profile(&kind))
        {
            return probe_from_declaration(&profile.health_probe, &spec, timeout).await;
        }

        // The trailing match only handles the gateway-native behavioral
        // routes that have no registry plugin: `http` (url-probe) and
        // `pipeline` (Skip — health is aggregated from its steps).
        match binding.backend.kind.as_str() {
            "http" => match binding.backend.spec.get("url").and_then(|v| v.as_str()) {
                Some(u) => probe_http(u, timeout).await,
                None => ProbeResult::Skip,
            },
            _ => ProbeResult::Skip,
        }
    }
}

/// Execute a manifest-declared health probe against a resolved binding
/// spec. The declaration — not the kind — selects the prober; the spec
/// supplies the resolved connection target. `Skip` / `Plugin` are
/// advisory-unknown for now (no standing connection to probe generically).
async fn probe_from_declaration(
    decl: &mcpg_plugin_protocol::manifest::HealthProbeDecl,
    spec: &serde_json::Value,
    timeout: Duration,
) -> ProbeResult {
    use mcpg_plugin_protocol::manifest::HealthProbeDecl;
    // The connection URL lives under the conventional `url` field; a few
    // backends name it `endpoint` (e.g. soap). Trying both keeps the gateway
    // kind-agnostic instead of enumerating kinds.
    let target = spec
        .get("url")
        .or_else(|| spec.get("endpoint"))
        .and_then(serde_json::Value::as_str);
    match decl {
        HealthProbeDecl::Skip | HealthProbeDecl::Plugin => ProbeResult::Skip,
        HealthProbeDecl::Tcp => match target {
            // Strip any `scheme://` so a plain `host:port` reaches the TCP probe
            // (e.g. `ldap://host:389`).
            Some(url) => {
                let host_port = url.rsplit_once("://").map_or(url, |(_, rest)| rest);
                probe_tcp(host_port, timeout).await
            }
            None => ProbeResult::Skip,
        },
        HealthProbeDecl::Http { path } => match target {
            Some(base) => {
                probe_http(&format!("{}{}", base.trim_end_matches('/'), path), timeout).await
            }
            None => ProbeResult::Skip,
        },
    }
}

enum ProbeResult {
    Success,
    Failure(String),
    Skip,
}

async fn probe_http(url: &str, timeout: Duration) -> ProbeResult {
    match tokio::time::timeout(timeout, async {
        reqwest::Client::new().head(url).send().await
    })
    .await
    {
        Ok(Ok(resp)) if resp.status().is_success() || resp.status().is_redirection() => {
            ProbeResult::Success
        }
        Ok(Ok(resp)) => ProbeResult::Failure(format!("HTTP {}", resp.status())),
        Ok(Err(e)) => ProbeResult::Failure(format!("request error: {e}")),
        Err(_) => ProbeResult::Failure("timeout".to_owned()),
    }
}

async fn probe_tcp(address: &str, timeout: Duration) -> ProbeResult {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(_)) => ProbeResult::Success,
        Ok(Err(e)) => ProbeResult::Failure(format!("TCP connect failed: {e}")),
        Err(_) => ProbeResult::Failure("timeout".to_owned()),
    }
}
