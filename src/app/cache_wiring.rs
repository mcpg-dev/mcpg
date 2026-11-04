use super::*;

/// Inherit the byte cap a per-binding `cache: { kind: in-process }`
/// override falls back to when its `config.max_bytes` is absent.
/// Mirrors the gateway-wide `storage.response_cache.max_bytes`
/// when that's an in-process cache; uses the type's own default
/// otherwise (the gateway-wide cache may be `disabled` while a
/// binding still wants its own LRU).
pub(crate) fn response_cache_default_max_bytes(config: &crate::config::AppConfig) -> usize {
    use crate::config::ResponseCacheConfig;
    match &config.storage.response_cache {
        ResponseCacheConfig::InProcess(in_proc) => in_proc.max_bytes,
        ResponseCacheConfig::Disabled => {
            crate::config::InProcessResponseCacheConfig::default().max_bytes
        }
    }
}

/// Resolve every binding's per-binding `cache:` field into an
/// override map (binding name → `Option<Arc<dyn ResponseCache>>`).
/// `Some(_)` is an explicit per-binding cache instance; `None` is
/// the explicit `kind: disabled` opt-out. Bindings without a
/// `cache:` block don't appear in the map at all — those fall
/// through to the gateway-wide cache from
/// `storage.response_cache:`.
///
/// A `kind:` that resolves to a `cache` plugin binds the namespace
/// `response-cache.<binding>` to that plugin, so the binding's entries
/// live in the plugin (shared across replicas for a Redis cache).
///
/// Refuses boot on:
/// - a plugin the registry cannot bind (not a registered `cache`
///   plugin, or one that does not serve the namespace);
/// - `kind: cluster` (cluster coordinators don't advertise the
///   response-cache role);
/// - `kind: file` (no file-backed response cache implementation
///   ships today);
/// - duplicate binding names in `mcp.capabilities` that both
///   declare `cache:` (would otherwise silently keep the last
///   resolution).
pub(crate) fn build_binding_cache_overrides(
    config: &crate::config::AppConfig,
    default_max_bytes: &usize,
    registry: &mut mcpg_plugin_host::PluginRegistry,
) -> Result<
    std::collections::HashMap<
        String,
        Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>>,
    >,
> {
    use crate::config::wiring::{ResolvedKind, SlotClass, resolve_kind};
    let mut overrides: std::collections::HashMap<
        String,
        Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>>,
    > = std::collections::HashMap::new();
    let cluster_kind = config.cluster.kind.as_str();
    let plugins = config.plugins.as_slice();

    let lists: [&[crate::config::BackendConfig]; 4] = [
        &config.mcp.capabilities.tools,
        &config.mcp.capabilities.prompts,
        &config.mcp.capabilities.resources,
        &config.mcp.capabilities.resource_templates,
    ];
    for list in lists {
        for binding in list {
            let Some(kref) = &binding.cache else { continue };
            let resolved = resolve_kind(SlotClass::Cache, kref, plugins, cluster_kind)
                .with_context(|| {
                    format!(
                        "binding `{}`: `cache: kind: {}` failed to resolve",
                        binding.name, kref.kind
                    )
                })?;
            let cache: Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>> =
                match resolved {
                    ResolvedKind::Builtin(keyword) => match keyword.as_str() {
                        "disabled" => None,
                        "in-process" | "memory" | "builtin" => {
                            let max_bytes = kref
                                .config
                                .get("max_bytes")
                                .and_then(|v| v.as_u64())
                                .map(|v| v as usize)
                                .unwrap_or(*default_max_bytes);
                            Some(mcpg_backend_llm_shared::LruResponseCache::new(max_bytes)
                                as std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>)
                        }
                        "file" => {
                            anyhow::bail!(
                                "binding `{}`: `cache: kind: file` isn't supported \
                             — no file-backed `ResponseCache` ships today. \
                             Use `kind: in-process` or `kind: disabled`.",
                                binding.name,
                            );
                        }
                        other => {
                            anyhow::bail!(
                                "binding `{}`: unexpected built-in cache keyword \
                             `{}`",
                                binding.name,
                                other,
                            );
                        }
                    },
                    ResolvedKind::Plugin(plugin_id) => {
                        let namespace = format!("response-cache.{}", binding.name);
                        registry
                            .bind_cache_namespace(namespace.clone(), &plugin_id)
                            .with_context(|| {
                                format!(
                                    "binding `{}`: `cache: kind: {}` names plugin `{}`",
                                    binding.name, kref.kind, plugin_id,
                                )
                            })?;
                        let cache = registry
                            .cache_for_namespace(&namespace)
                            .context("a bound cache namespace has no cache")?;
                        Some(
                            std::sync::Arc::new(PluginResponseCache::new(namespace, cache))
                                as std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>,
                        )
                    }
                    ResolvedKind::Cluster => {
                        anyhow::bail!(
                            "binding `{}`: `cache: kind: cluster` is not valid — \
                         the response-cache role isn't provided by any \
                         cluster coordinator (LLM caches are gateway-local).",
                            binding.name,
                        );
                    }
                };
            if overrides.insert(binding.name.clone(), cache).is_some() {
                anyhow::bail!(
                    "binding name `{}` appears more than once in \
                     `mcp.capabilities` with a `cache:` override; binding \
                     names must be unique across all four capability lists",
                    binding.name,
                );
            }
        }
    }
    Ok(overrides)
}

/// A binding's response cache kept in a `cache` plugin, under one
/// namespace. Item and byte counts live in the plugin, so `stats`
/// reports only this gateway's hits and misses.
pub(crate) struct PluginResponseCache {
    namespace: String,
    cache: std::sync::Arc<dyn mcpg_plugin_protocol::cache::Cache>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl PluginResponseCache {
    pub(crate) fn new(
        namespace: String,
        cache: std::sync::Arc<dyn mcpg_plugin_protocol::cache::Cache>,
    ) -> Self {
        Self {
            namespace,
            cache,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for PluginResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginResponseCache")
            .field("namespace", &self.namespace)
            .field("plugin", &self.cache.manifest().id)
            .finish()
    }
}

/// A `ResponseCache` TTL of zero means "no expiry"; a cache plugin
/// expires a zero-TTL entry at once, so it gets this bound instead.
const PLUGIN_CACHE_NO_EXPIRY_TTL: std::time::Duration = std::time::Duration::from_secs(86_400);

#[async_trait::async_trait]
impl mcpg_backend_llm_shared::ResponseCache for PluginResponseCache {
    async fn get(&self, key: &mcpg_backend_llm_shared::CacheKey) -> Option<bytes::Bytes> {
        use std::sync::atomic::Ordering::Relaxed;
        let got = self.cache.get(&self.namespace, key.as_str()).await;
        if got.is_some() {
            self.hits.fetch_add(1, Relaxed);
        } else {
            self.misses.fetch_add(1, Relaxed);
        }
        got
    }

    async fn put(
        &self,
        key: mcpg_backend_llm_shared::CacheKey,
        value: bytes::Bytes,
        ttl: std::time::Duration,
    ) {
        let ttl = if ttl.is_zero() {
            PLUGIN_CACHE_NO_EXPIRY_TTL
        } else {
            ttl
        };
        if let Err(e) = self
            .cache
            .put(&self.namespace, key.as_str(), value, ttl)
            .await
        {
            warn!(
                namespace = %self.namespace,
                plugin_id = %self.cache.manifest().id,
                error = %e,
                "response cache write to the cache plugin failed"
            );
        }
    }

    async fn invalidate(&self, key: &mcpg_backend_llm_shared::CacheKey) {
        self.cache.delete(&self.namespace, key.as_str()).await;
    }

    fn stats(&self) -> mcpg_backend_llm_shared::CacheStats {
        use std::sync::atomic::Ordering::Relaxed;
        mcpg_backend_llm_shared::CacheStats {
            hits: self.hits.load(Relaxed),
            misses: self.misses.load(Relaxed),
            ..Default::default()
        }
    }
}

/// Construct the operator-configured LLM response cache.
/// Returns `None` when `plugins.response_cache.kind = disabled`. The
/// in-process backend is the only one shipping today; future Redis /
/// memcached backends would slot in here behind the same trait.
pub(crate) fn build_response_cache(
    config: &crate::config::ResponseCacheConfig,
) -> Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>> {
    use crate::config::ResponseCacheConfig;
    match config {
        ResponseCacheConfig::Disabled => {
            info!("LLM response cache disabled (plugins.response_cache.kind = disabled)");
            None
        }
        ResponseCacheConfig::InProcess(in_proc) => {
            let cache = mcpg_backend_llm_shared::LruResponseCache::new(in_proc.max_bytes);
            info!(
                max_bytes = in_proc.max_bytes,
                "in-process LLM response cache registered"
            );
            Some(cache as std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>)
        }
    }
}
