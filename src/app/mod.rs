pub mod config_overlay;
pub mod config_watch;
pub mod host_services_impl;
pub mod plugin_kv_adapter;

mod auth_wiring;
mod boot;
mod cache_wiring;
mod cluster_state;
mod observability_wiring;
mod oci_wiring;
mod openapi_wiring;
mod plugin_registry;
mod policy_wiring;
mod reload;
mod serve;
mod storage_wiring;

pub(crate) use std::sync::Arc;

pub(crate) use anyhow::{Context, Result};
pub(crate) use arc_swap::ArcSwap;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use tracing::{info, warn};

pub(crate) use crate::runtime::SessionStoreConfig;
pub(crate) use crate::{
    backends::{DebugToolBackends, DebugToolExposure},
    config::{AppConfig, TransportMode, TrustLevelConfig},
    observability::{self, ObservabilityHandle},
    runtime::{
        CommandToolRuntimeConfig, GatewayRuntime, NetworkToolRuntimeConfig, RequestTrustLevel,
        RuntimeDebugConfig, ToolAccessPolicyConfig, ToolTrustRule,
    },
    transports::{http, stdio},
};

pub use auth_wiring::build_ema_authorization_server;
pub use boot::{build, build_from_config, build_from_sources};
pub(crate) use reload::reapply_config;
pub use reload::{reload_config, reload_config_from_yaml};
pub use serve::run;

pub(crate) use auth_wiring::*;
pub(crate) use cache_wiring::*;
pub(crate) use cluster_state::*;
pub(crate) use observability_wiring::*;
pub(crate) use oci_wiring::*;
pub(crate) use openapi_wiring::*;
pub(crate) use plugin_registry::*;
pub(crate) use policy_wiring::*;
pub(crate) use storage_wiring::*;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<AppConfig>>,
    /// The applied config BEFORE the registry overlay is composed. The
    /// registry syncer re-runs the reload pipeline on this base, and
    /// every reload stores its incoming config here — so overlay
    /// re-application never resurrects a superseded config.
    pub base_config: Arc<ArcSwap<AppConfig>>,
    /// Federations synthesized from `mcp.registries` by the background
    /// syncer, composed onto every reload's config (operator entries
    /// win on collision). Empty until the first successful sync.
    pub registry_overlay: Arc<ArcSwap<crate::runtime::registry_sync::RegistryOverlay>>,
    pub runtime: Arc<ArcSwap<GatewayRuntime>>,
    pub session_store: Arc<dyn crate::runtime::session_store::SessionStore>,
    pub observability: Arc<ObservabilityHandle>,
    /// Operator-supplied config layers in merge order (later wins). Empty when
    /// the gateway runs on defaults + env-var overlay alone. Used by
    /// [`reload_config`] to re-merge the same source set: a
    /// [`ConfigSource::File`] is re-read from disk on reload, an
    /// [`ConfigSource::Inline`] (remote-fetched / base64) reuses its boot
    /// snapshot.
    pub config_sources: Vec<crate::config::ConfigSource>,
    /// Per-session concurrent SSE stream counter, bounded at
    /// MAX_SSE_STREAMS_PER_SESSION to prevent FD/memory exhaustion.
    pub sse_stream_counts: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    /// Merged JSON value from the `plugins.config_overlay` apply pass
    /// at boot. Subsystems that want dynamic-config values read from
    /// this (via `runtime.config_overlay()` or via the `AppState`
    /// directly). Empty object `{}` when no overlays were configured.
    /// Wrapped in `ArcSwap` so it can be swapped atomically on
    /// delta-watch events without touching subsystem state.
    pub config_overlay: Arc<ArcSwap<serde_json::Value>>,
    /// Canonical policy_engine chain in operator-declared order
    /// (`governance.policy.engine[]`). Each entry is the engine's
    /// self-declared `name()` (e.g. `"yaml-rules"`, `"cedar"`).
    /// Runtime decision points pass this to
    /// [`mcpg_plugin_host::PluginRegistry::evaluate_policy_chain`]
    /// — the host walks the list in order and short-circuits on
    /// the first explicit `Allow` / `Deny`. Empty when the
    /// operator configured no chain → every decision is
    /// `NotApplicable` and the caller picks its own default.
    /// Wrapped in `ArcSwap` so [`reload_config`] can hot-swap the
    /// chain alongside the runtime + config swap.
    pub policy_chain: Arc<ArcSwap<Vec<String>>>,
    /// Background plugin-health-prober handle. Held here (not
    /// `mem::forget`'d) so [`reload_config`] can stop the prober that
    /// targets the OLD registry and start a fresh one on the new
    /// registry — otherwise the boot prober kept probing the swapped-out
    /// registry forever. `None` when health probing is disabled / no
    /// plugins. Dropping the handle stops the prober (its `Drop` signals
    /// stop), so replacing the Option cancels the old one.
    pub plugin_health_prober:
        Arc<tokio::sync::Mutex<Option<mcpg_plugin_host::health_prober::HealthProberHandle>>>,
    /// Active secret-rotation watcher set. Held here (not `mem::forget`'d)
    /// so [`reload_config`] can `cancel()` the previous set before
    /// spawning the new one — otherwise each reload would leak a watcher set
    /// (and its tasks) that keeps running against the old registry. `None`
    /// when no rotation-aware secret refs are configured.
    pub secret_watcher:
        Arc<tokio::sync::Mutex<Option<mcpg_plugin_host::secret_watcher::SecretWatcherSet>>>,
    /// Operator-configured runtime quota gate.
    /// `Some` when the `governance-quotas` cargo feature is on AND
    /// `governance.quotas:` has at least one policy declared.
    /// `None` otherwise; the dispatch hook short-circuits the
    /// pre-binding evaluate when this is `None`.
    /// Wrapped in `ArcSwap` so [`reload_config`] can hot-swap the
    /// gate alongside the runtime + config swap.
    #[cfg(feature = "governance-quotas")]
    pub quota_gate: Arc<ArcSwap<Option<Arc<crate::runtime::quota_gate::QuotaGate>>>>,
}

/// Maximum concurrent GET SSE streams per session.
pub const MAX_SSE_STREAMS_PER_SESSION: usize = 3;

#[cfg(test)]
mod tests;
