//! Top-level `gateway:` umbrella block.
//!
//! Holds the gateway's own network face: listener (`server`),
//! admin surface (`admin`), Control Plane attachment
//! (`control_plane`), the OCI plugin-registry defaults
//! (`gateway.plugin_registry:`), and the config-overlay URI list
//! (`gateway.config_overlay:`).
//!
//! These fields are grouped under one umbrella so the "binary's
//! network face" mental model has a single home (they previously
//! lived flat at the `AppConfig` root: `server:`, `admin:`,
//! `control_plane:`).

use serde::{Deserialize, Serialize};

use super::plugins::PluginRegistryConfig;
use super::{AdminConfig, ControlPlaneAttachConfig, ServerConfig};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Listener configuration — bind address, transport mode
    /// (HTTP / stdio / SSE), TLS, allowed origins, and per-request
    /// timeouts. The block is mandatory in practice (the listener
    /// won't bind without `bind_address`) but defaults to a
    /// localhost dev-mode shape so out-of-the-box `mcpg` boots
    /// without any config.
    #[serde(default)]
    pub server: ServerConfig,

    /// Admin HTTP surface — `/admin/*` routes, mutual-TLS or
    /// bearer-token auth, the operator-facing `disclosure_level`
    /// gate that controls how much detail diagnostic endpoints
    /// expose. Defaults to disabled; production deploys mount it
    /// behind an internal-only listener.
    #[serde(default)]
    pub admin: AdminConfig,

    /// Optional Control Plane attachment. When set
    /// AND the `cp-attached` Cargo feature is built in, the
    /// gateway registers with the CP at boot, opens an agent
    /// Channel, and ships per-tool-call samples for centralized
    /// observability. When the feature
    /// isn't built in, this block is silently ignored.
    #[serde(default)]
    pub control_plane: Option<ControlPlaneAttachConfig>,

    /// Supervised inspector sidecar (`mcpg --inspector`, or
    /// `enabled: true` here): the gateway spawns a sibling
    /// `mcpg-inspector serve` pre-wired against this gateway with a
    /// per-boot loopback credential.
    #[serde(default)]
    pub inspector: crate::config::inspector::InspectorSidecarConfig,

    /// OCI plugin-registry configuration. Lives here (rather than
    /// per-plugin) because it's gateway-process tuning — where to
    /// fetch plugin artifacts from — not per-plugin config.
    /// Per-plugin source auth/tls live inline in each plugin
    /// entry's `source.{auth,tls}:`. Only consulted when at least
    /// one plugin entry uses `source: { oci: ... }`.
    #[serde(default)]
    pub plugin_registry: PluginRegistryConfig,

    /// Ordered list of `config_provider` URIs to snapshot at gateway
    /// boot + deep-merge into an overlay value (spec §9.16). Lives
    /// here (rather than per-plugin) because it's gateway-process
    /// bootstrap config. Each URI must use a scheme bound by a
    /// registered config-provider plugin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_overlay: Vec<String>,

    /// File-watch config-reload trigger (third trigger, alongside
    /// SIGHUP and `POST /admin/v1/config:reload`). Background task
    /// polls the `MCPG_CONFIG` source set on disk and triggers a
    /// hot-reload when contents change. Default disabled. See
    /// [`ConfigWatchConfig`] for tuning. Useful for bare-metal
    /// systemd deployments and K8s deployments without the MCPG
    /// operator (which already does cluster-level config
    /// propagation via `mcpg.dev/config-hash` annotation forcing
    /// rolling restart).
    #[serde(default)]
    pub config_watch: ConfigWatchConfig,
}

/// `gateway.config_watch:` — operator-tunable file-watch reload
/// trigger. Same semantics as SIGHUP and the admin endpoint:
/// full `GatewayRuntime` rebuild via `ArcSwap`; session store
/// preserved; credential cache rebuilt fresh; `list_changed`
/// emitted per category for operational sessions on inventory
/// delta.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigWatchConfig {
    /// When true, the gateway watches its config files on disk
    /// and triggers a hot-reload when contents change. Polling-
    /// based — handles editor-write-via-rename (vim/emacs) and
    /// K8s ConfigMap atomic-symlink-swap transparently because
    /// the watcher reads through the symlink chain regardless of
    /// how the write landed. Defaults to disabled — operators
    /// must opt in.
    #[serde(default)]
    pub enabled: bool,

    /// Poll interval in milliseconds. Lower = faster reload after
    /// edit; higher = lower disk I/O. Default 5000 (5s) is
    /// imperceptible for config changes and trivial in I/O cost.
    /// Values below 1000 (1s) are clamped to 1000 at validate
    /// time with a warning — sub-second polling burns I/O for no
    /// human-perceivable benefit.
    #[serde(default = "default_config_watch_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

fn default_config_watch_poll_interval_ms() -> u64 {
    5000
}
