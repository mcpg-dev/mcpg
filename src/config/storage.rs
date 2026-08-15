//! Top-level `storage:` block — operator-declared content-store
//! providers plus the gateway-managed LLM response cache.
//!
//! The `storage:` umbrella gathers both the content-store
//! providers and the response cache so all "where bytes go to
//! live" concerns share one home.
//!
//! The per-binding field that picks a provider id stays named
//! `content_storage:` for symmetry — that field is the consumer-side
//! route name, not the registry's name.
//!
//! The capability-state `<cap>.store:` overrides keep their name
//! (different concern: KV state inheritance, not blob backends).

use serde::{Deserialize, Serialize};

/// Top-level `storage:` block. Holds the gateway's content-store
/// providers + the LLM response cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Content-store provider entries. Each entry produces an
    /// `Arc<dyn ContentStore>` registered under `id` in the
    /// gateway's runtime registry. Bindings reference providers by
    /// `id` via their own `content_storage:` field.
    #[serde(default)]
    pub providers: Vec<StorageProviderConfig>,

    /// Provider id that bindings without an explicit
    /// `content_storage:` field route to. When unset, the gateway
    /// falls back to a provider with the conventional id `default`.
    /// Validated at boot — an unknown id fails fast.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// Gateway-managed LLM response cache. Lives here (rather than
    /// under `plugins:`) so all "where bytes go to live" config
    /// shares one home.
    #[serde(default)]
    pub response_cache: ResponseCacheConfig,
}

/// One operator-declared content-store provider, an entry in
/// `storage.providers: [...]`. The `kind` field selects the storage
/// plugin (`in_process` / `file_system` / `s3` / future plugins);
/// `config` is the per-plugin configuration object whose schema is
/// owned by the plugin (see each plugin's `plugin.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageProviderConfig {
    /// Operator-chosen id. Bindings reference providers via this
    /// id (`content_storage: <id>` on the binding entry). The
    /// conventional `default` id is the fallback when a binding
    /// doesn't specify its own AND `storage.default` is unset.
    pub id: String,
    /// Storage plugin kind (e.g. `in_process`, `file_system`, `s3`).
    /// Resolved against the gateway's content-store plugin registry
    /// at boot.
    pub kind: String,
    /// Plugin-specific configuration JSON. Validated by the plugin
    /// at `build_profile` time; gateway boot fails fast if the
    /// shape doesn't match.
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Operator-facing config for the gateway-managed LLM response
/// cache. The cache backs
/// `BackendHost::cache_get` / `cache_put`; chat + embedding bindings
/// opt in per-binding via their own `cache.enabled: true` knob, the
/// cache only exists at all if this config is non-disabled.
///
/// `kind: in_process` is the default — content-addressed BLAKE3 LRU
/// cache with 64 MiB byte cap, lost on restart. `kind: disabled`
/// turns the cache off gateway-wide; per-binding `cache.enabled`
/// becomes a no-op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseCacheConfig {
    InProcess(InProcessResponseCacheConfig),
    Disabled,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self::InProcess(InProcessResponseCacheConfig::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InProcessResponseCacheConfig {
    /// Maximum aggregate byte size kept in memory. LRU eviction
    /// past this. Default 64 MiB — embeddings are small (single-vec
    /// kilobytes) and chat outputs are modest (a few KB each), so a
    /// modest cap covers tens of thousands of cached calls.
    #[serde(default = "default_response_cache_max_bytes")]
    pub max_bytes: usize,
}

impl Default for InProcessResponseCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_response_cache_max_bytes(),
        }
    }
}

fn default_response_cache_max_bytes() -> usize {
    64 * 1024 * 1024
}
