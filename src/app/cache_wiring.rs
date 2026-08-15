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
/// Refuses boot on:
/// - `kind:` resolves to a Plugin (no plugin bridge for
///   `ResponseCache` yet — the trait lives in
///   `mcpg-backend-llm-shared`, not `mcpg-plugin-protocol`);
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
                        anyhow::bail!(
                            "binding `{}`: `cache: kind: {}` resolves to plugin \
                         `{}`, but the LLM response cache trait is \
                         gateway-side only — no plugin bridge exists yet. \
                         Use `kind: in-process` or `kind: disabled` until a \
                         `ResponseCachePlugin` trait lands.",
                            binding.name,
                            kref.kind,
                            plugin_id,
                        );
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
