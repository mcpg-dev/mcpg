use super::*;

/// Build the content-store plugin registry — kind → plugin
/// factory. Always populated with the two built-ins (`in_process`,
/// `file_system`); the `s3` plugin joins under
/// `--features s3-content-store`. Future first-party storage plugins
/// are registered here.
pub(crate) fn build_content_store_plugins() -> std::collections::HashMap<
    &'static str,
    std::sync::Arc<dyn mcpg_backend_llm_shared::ContentStorePlugin>,
> {
    use std::sync::Arc;
    let mut by_type: std::collections::HashMap<
        &'static str,
        Arc<dyn mcpg_backend_llm_shared::ContentStorePlugin>,
    > = std::collections::HashMap::new();
    by_type.insert(
        "in_process",
        Arc::new(mcpg_plugin_storage_builtin::InProcessStoragePlugin::new()),
    );
    by_type.insert(
        "file_system",
        Arc::new(mcpg_plugin_storage_builtin::FileSystemStoragePlugin::new()),
    );
    #[cfg(feature = "s3-content-store")]
    {
        by_type.insert(
            "s3",
            Arc::new(mcpg_plugin_storage_s3::S3StoragePlugin::new()),
        );
    }
    by_type
}

/// Default `storage.providers: [...]` when the operator left the
/// block empty — a single in-process provider with id `default`
/// and the standard 256 MiB cap. Operators wanting persistence
/// override by declaring their own `storage.providers:` entries.
pub(crate) fn default_storage_providers() -> Vec<crate::config::StorageProviderConfig> {
    vec![crate::config::StorageProviderConfig {
        id: crate::runtime::content_store_registry::DEFAULT_STORAGE_ID.to_owned(),
        kind: "in_process".to_owned(),
        config: serde_json::json!({}),
    }]
}

/// Construct the operator-configured `ContentStoreRegistry`.
/// Walks `config.storage.providers` and dispatches to
/// the matching `ContentStorePlugin::build_profile(...)` factory;
/// populates the registry's binding-name → storage-id routing from
/// `BackendConfig.storage` values. Spawns one periodic TTL-sweep task
/// per registered store.
///
/// Operators who don't want a content surface can declare an empty
/// `storage.providers: []` array AND ensure no binding declares a
/// `storage:` field — but that's unusual; the default in-process
/// store is cheap.
pub(crate) async fn build_storages_registry(
    config: &crate::config::AppConfig,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
) -> anyhow::Result<
    Option<std::sync::Arc<crate::runtime::content_store_registry::ContentStoreRegistry>>,
> {
    use crate::runtime::content_store_registry::{ContentStoreRegistry, DEFAULT_STORAGE_ID};
    use std::collections::HashMap;

    // Empty `storage.providers: []` AND no binding asks for a storage
    // → the operator opted out. Return `None` so the gateway runs
    // without a content surface (resources/read of mcpg-resource://
    // URIs fails with the stock "not configured" error).
    let any_binding_uses_storage = config
        .all_bindings()
        .any(|(_, b)| b.content_storage.is_some());
    let entries: Vec<crate::config::StorageProviderConfig> = if config.storage.providers.is_empty()
    {
        if any_binding_uses_storage {
            // Fail loud rather than silently provision a `default`
            // when the operator has opinions about routing.
            anyhow::bail!(
                "binding declares `storage:` but no top-level `storage.providers: [...]` block was provided",
            );
        } else {
            default_storage_providers()
        }
    } else {
        config.storage.providers.clone()
    };

    // Static built-in storage plugins, keyed by kind.
    let mut plugins: HashMap<
        String,
        std::sync::Arc<dyn mcpg_backend_llm_shared::ContentStorePlugin>,
    > = build_content_store_plugins()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    // Merge cdylib-loaded content_store factories. A
    // cdylib kind that collides with a built-in is rejected loudly rather
    // than silently shadowing it. (The re-export in mcpg-backend-llm-shared
    // makes the protocol-crate `ContentStorePlugin` and the
    // shared-crate alias the same trait object, so the Arcs unify.)
    for (kind, plugin) in plugin_registry.content_store_plugins() {
        if plugins.contains_key(&kind) {
            anyhow::bail!(
                "content_store plugin kind '{}' (cdylib) collides with a built-in storage kind",
                kind
            );
        }
        info!(kind = %kind, "registered cdylib content_store factory");
        plugins.insert(kind, plugin);
    }
    let mut stores: HashMap<String, std::sync::Arc<dyn mcpg_backend_llm_shared::ContentStore>> =
        HashMap::new();
    for entry in &entries {
        let plugin = plugins.get(entry.kind.as_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "storage provider '{}' has unknown kind '{}'; available: {}",
                entry.id,
                entry.kind,
                plugins.keys().cloned().collect::<Vec<_>>().join(", "),
            )
        })?;
        let store = plugin
            .build_profile(&entry.id, &entry.config)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "build storage provider '{}' (kind {}): {e}",
                    entry.id,
                    entry.kind
                )
            })?;
        info!(
            id = %entry.id,
            kind = %entry.kind,
            "content store provider registered"
        );
        if stores.insert(entry.id.clone(), store).is_some() {
            anyhow::bail!(
                "duplicate storage provider id '{}' in `storage.providers: [...]`",
                entry.id
            );
        }
    }

    // Resolve the operator-configured default-id; validate it points
    // at a registered provider. When unset, fall back to the
    // conventional "default" id (which the auto-provisioned
    // single-provider config uses).
    let default_id = config
        .storage
        .default
        .clone()
        .unwrap_or_else(|| DEFAULT_STORAGE_ID.to_owned());
    if !stores.contains_key(&default_id) {
        anyhow::bail!(
            "`storage.default: {}` does not match any provider id in `storage.providers: [...]`",
            default_id
        );
    }

    // Build per-binding routing from BackendConfig.storage values.
    // Validate at boot: every named provider must exist in the
    // registry, otherwise the operator misconfigured a binding and
    // we'd surface the error as a runtime "no storage" message way
    // later.
    let mut binding_routes: HashMap<String, String> = HashMap::new();
    for (_, binding) in config.all_bindings() {
        if let Some(storage_id) = &binding.content_storage {
            if !stores.contains_key(storage_id) {
                anyhow::bail!(
                    "binding '{}' routes to storage provider '{}' which is not declared in `storage.providers: [...]`",
                    binding.name,
                    storage_id
                );
            }
            binding_routes.insert(binding.name.clone(), storage_id.clone());
        }
    }

    let registry = std::sync::Arc::new(ContentStoreRegistry::new(
        stores,
        binding_routes,
        default_id,
    ));

    // Periodic TTL sweep — one task per registered backend. Each
    // store decides what `sweep_expired()` means; in-process is a
    // no-op (lazy-expire), filesystem walks the meta tree, S3 lists
    // the blobs prefix.
    let sweep_interval = std::time::Duration::from_secs(60);
    for (name, store) in registry.iter() {
        let name = name.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(sweep_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await;
            loop {
                tick.tick().await;
                let removed = store.sweep_expired().await;
                if removed > 0 {
                    tracing::debug!(storage = %name, removed, "content_store: swept expired");
                }
            }
        });
    }

    Ok(Some(registry))
}

/// Build the credential cache from operator config + the
/// (possibly absent) cluster coordinator the registry just
/// installed. Returns the typed kind handle the runtime holds.
pub(crate) async fn build_credential_cache(
    cfg: &crate::config::CredentialsConfig,
    registry: &mcpg_plugin_host::PluginRegistry,
) -> Result<std::sync::Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind>> {
    use mcpg_plugin_host::credential_cache::{CredentialCache, CredentialCacheConfig};
    use mcpg_plugin_host::credential_cache_clustered::{
        ClusteredCredentialCache, CredentialCacheKind,
    };
    use std::sync::Arc;
    use std::time::Duration;

    let local = Arc::new(CredentialCache::new(CredentialCacheConfig {
        max_entries: cfg.max_entries,
        max_cache_ttl: Duration::from_millis(cfg.max_cache_ttl_ms),
        key_attributes: cfg.key_attributes.clone(),
    }));

    let clustered = if cfg.cluster.enabled {
        // refuse plaintext cluster credential pub/sub unless explicitly
        // opted in (fail-closed; same rule the cipher-build below enforces).
        cfg.cluster.validate()?;
        match registry.cluster_backend() {
            Some(coordinator) => {
                let node_id = registry.cluster_backend_plugin_id().unwrap_or_else(|| {
                    // Fallback when the coordinator's plugin id
                    // isn't surfaced — node_id only drives self-
                    // publish dedup, so an empty string just
                    // disables the dedup (peer events still apply
                    // correctly, the local instance just
                    // re-applies its own publishes which is a
                    // no-op for issued / revoked events).
                    String::new()
                });
                // build the application-layer AEAD cipher from the
                // operator's key. Cluster credential events carry per-caller
                // secrets; refuse to publish them in plaintext unless the
                // operator explicitly opted in.
                let cipher = match cfg.cluster.encryption_key_env.as_deref() {
                    Some(env_name) => {
                        let key_b64 = std::env::var(env_name).map_err(|_| {
                            anyhow::anyhow!(
                                "credentials.cluster.encryption_key_env '{env_name}' is \
                                 not set or not readable"
                            )
                        })?;
                        let kid = cfg
                            .cluster
                            .encryption_key_id
                            .clone()
                            .unwrap_or_else(|| "mcpg-cred-cache".to_owned());
                        let cipher = mcpg_plugin_host::credential_cache_cipher::EventCipher::from_base64_key(
                            key_b64.trim(),
                            kid,
                        )
                        .map_err(|e| {
                            anyhow::anyhow!("invalid credentials cluster encryption key: {e}")
                        })?;
                        Some(cipher)
                    }
                    None if cfg.cluster.allow_plaintext => {
                        tracing::warn!(
                            "credential cache: cluster pub/sub is PLAINTEXT (no \
                             encryption_key_env; allow_plaintext=true). Per-caller credentials \
                             are broadcast unencrypted — confidentiality relies solely on \
                             transport TLS. published_by is forgeable on this path: integrity \
                             depends entirely on broker write-ACLs restricting the topic to the \
                             listed allowed_publishers. Configure encryption_key_env (AEAD) for \
                             authenticated publishers — the only integrity-providing mode."
                        );
                        None
                    }
                    None => {
                        anyhow::bail!(
                            "credentials.cluster.enabled=true publishes per-caller \
                             credentials on the cluster topic. Set \
                             credentials.cluster.encryption_key_env (base64 32-byte key) \
                             to encrypt them, or set cluster.allow_plaintext=true to accept \
                             plaintext (relies on transport TLS only)."
                        );
                    }
                };
                match ClusteredCredentialCache::start(
                    Arc::clone(&local),
                    coordinator,
                    node_id,
                    cfg.cluster.topic.clone(),
                    cipher,
                    // Optional peer allowlist; empty = accept any peer.
                    cfg.cluster.allowed_publishers.clone().unwrap_or_default(),
                )
                .await
                {
                    Ok(c) => {
                        tracing::info!(
                            topic = ?cfg.cluster.topic,
                            encrypted = cfg.cluster.encryption_key_env.is_some(),
                            "credential cache: cluster pub/sub enabled"
                        );
                        Some(c)
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "credentials.cluster.enabled=true but \
                             ClusteredCredentialCache::start failed: {e}"
                        );
                    }
                }
            }
            None => {
                tracing::warn!(
                    "credentials.cluster.enabled=true but no \
                     cluster_backend is bound — falling back to local-only \
                     cache. Multi-instance deploys with per-caller credentials \
                     will diverge across peers; either bind a coordinator or \
                     set cluster.enabled=false to silence this warning"
                );
                None
            }
        }
    } else {
        None
    };

    Ok(Arc::new(match clustered {
        Some(c) => CredentialCacheKind::Clustered(c),
        None => CredentialCacheKind::Local(local),
    }))
}
