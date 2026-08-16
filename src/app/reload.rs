use super::*;

/// Reload configuration from disk and rebuild the gateway runtime.
///
/// The session store is preserved across reloads (held in AppState).
/// In-flight requests on the old runtime complete safely because they
/// hold an Arc reference to the previous GatewayRuntime.
pub async fn reload_config(state: &AppState) -> Result<()> {
    // File layers are re-read from disk; inline (remote/base64) layers reuse
    // their boot snapshot — so a signal/admin reload picks up edited files
    // without silently dropping a URL/base64 layer.
    let new_config = AppConfig::load_sources(&state.config_sources)?;
    // Anchor relative `schemas[].file` refs against the LAST file layer's
    // directory (inline layers have no directory to anchor against).
    let config_dir = state.config_sources.iter().rev().find_map(|s| match s {
        crate::config::ConfigSource::File(p) => p.parent().map(std::path::Path::to_path_buf),
        crate::config::ConfigSource::Inline { .. } => None,
    });
    reload_with_config(state, new_config, config_dir).await
}

/// Hot-reload from an in-memory config (control-plane push), where the on-disk
/// config is a read-only mount so a file-write-then-reload isn't possible. Same
/// atomic ArcSwap swap as the disk-driven [`reload_config`]; on any error the
/// gateway keeps its prior config + runtime (the swap only happens at the end).
pub async fn reload_config_from_yaml(state: &AppState, yaml: &str) -> Result<()> {
    let new_config = AppConfig::load_from_yaml_str(yaml)?;
    reload_with_config(state, new_config, None).await
}

/// Re-run the reload pipeline on the current base config. The registry
/// syncer calls this after updating the overlay so the standard
/// compose → validate → atomic-swap → `list_changed`-diff path applies
/// it; nothing swaps outside that pipeline.
pub(crate) async fn reapply_config(state: &AppState) -> Result<()> {
    let base = state.base_config.load_full();
    reload_with_config(state, (*base).clone(), None).await
}

/// Shared core of the two reload entry points: take a freshly-loaded config,
/// rebuild every subsystem, and atomically swap it in.
pub(crate) async fn reload_with_config(
    state: &AppState,
    mut new_config: AppConfig,
    config_dir: Option<std::path::PathBuf>,
) -> Result<()> {
    new_config
        .resolve_schema_refs(config_dir.as_deref())
        .await?;

    crate::license_gate::enforce_plugin_license_gate(&new_config)?;

    // Registry auto-federation composes here — the single point every
    // reload trigger passes through — so a CP push or file reload can
    // never wipe registry-synthesized federations, and the syncer can
    // never resurrect a superseded base config.
    state.base_config.store(Arc::new(new_config.clone()));
    if let Some(merged) = crate::runtime::registry_sync::merged_with_overlay(
        &new_config,
        &state.registry_overlay.load(),
    ) {
        new_config = merged;
    }

    let store_config = SessionStoreConfig {
        replay_window_limit: new_config.gateway.server.replay_window_limit,
        session_idle_timeout_ms: new_config.gateway.server.session_idle_timeout_ms,
        max_sessions: 10_000,
        max_sessions_per_tenant: new_config.gateway.server.max_sessions_per_tenant,
    };
    let _ = store_config; // session store is preserved, not rebuilt

    crate::runtime::feature_flags::install(&new_config.feature_flags);

    let jwt_verifier = build_jwt_verifier(&new_config).await?;
    let oidc_resolver = build_oidc_resolver(&new_config)?.map(std::sync::Arc::new);

    // Mirror the boot ordering on the reload path: build the new
    // plugin registry first, then extract the cluster coordinator and
    // let capabilities inherit primitives from it.
    let PluginBundle {
        registry: plugin_registry,
        backend_late_host,
        host_services_late,
        config_overlay: config_overlay_outcome,
        credential_cache,
        content_stores,
        response_cache,
        response_cache_overrides,
        policy_chain,
        #[cfg(feature = "governance-quotas")]
        quota_gate,
        resolved_secret_refs,
    } = build_plugin_registry(
        &mut new_config,
        jwt_verifier.as_ref(),
        oidc_resolver.clone(),
    )
    .await?;

    let cluster_backend = plugin_registry.cluster_backend();

    // Rebuild the opt-in state cipher from the reloaded config (the
    // key env-ref may have been added/removed across a hot reload).
    let state_cipher = build_state_cipher(&new_config.cluster)?;
    let tenant_seg = new_config.cluster.tenant_segment.clone();

    // Reload's delivery_bus rebuild uses the same inherit-or-default
    // path the boot wiring follows: when a `delivery_bus.bus: { kind,
    // … }` override is set, build it; otherwise inherit from the
    // freshly-built coordinator (or fall back to a fresh in-process
    // MemoryBus).
    let delivery_pubsub: Arc<dyn mcpg_cluster_api::PubSub> = resolve_capability_bus(
        new_config.mcp.configurations.delivery.bus.as_ref(),
        "delivery",
        cluster_backend.as_ref(),
    )
    .await?;
    let delivery_pubsub =
        wrap_tenant_bus(wrap_state_bus(delivery_pubsub, &state_cipher), &tenant_seg);
    let delivery_bus: std::sync::Arc<dyn crate::runtime::delivery_bus::DeliveryBus> =
        std::sync::Arc::new(crate::runtime::delivery_bus::BusBackedDeliveryBus::new(
            delivery_pubsub,
        ));

    // Same override-or-default path the boot wiring uses:
    // `kind: cluster` (or omitted) → inherit primitive from the
    // freshly-built coordinator, or a new MemoryKv when the
    // coordinator can't expose one.
    let pipeline_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        new_config.mcp.configurations.pipelines.store.as_ref(),
        "pipelines",
        cluster_backend.as_ref(),
        &plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Pipeline,
    )
    .await?;
    let pipeline_kv = wrap_tenant_kv(wrap_state_kv(pipeline_kv, &state_cipher), &tenant_seg);
    let pipeline_store: std::sync::Arc<dyn crate::runtime::pipeline_store::PipelineStore> =
        std::sync::Arc::new(crate::runtime::pipeline_store::KvBackedPipelineStore::new(
            pipeline_kv,
        ));

    let task_policy = crate::runtime::task_store::TaskRetentionPolicy {
        default_ttl_ms: new_config
            .mcp
            .capabilities
            .tasks
            .default_ttl_ms
            .saturating_mul(1000),
        max_tasks_per_session: new_config.mcp.capabilities.tasks.max_tasks_per_session,
        result_wait_ms: new_config.mcp.capabilities.tasks.result_wait_ms,
    };
    let task_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        new_config.mcp.capabilities.tasks.store.as_ref(),
        "tasks",
        cluster_backend.as_ref(),
        &plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Task,
    )
    .await?;
    let task_kv = wrap_tenant_kv(wrap_state_kv(task_kv, &state_cipher), &tenant_seg);
    let task_store: std::sync::Arc<dyn crate::runtime::task_store::TaskStore> = std::sync::Arc::new(
        crate::runtime::task_store::KvBackedTaskStore::new(task_kv, task_policy),
    );

    let subscription_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
        resolve_capability_kv(
            new_config.mcp.configurations.subscriptions.store.as_ref(),
            "subscriptions",
            cluster_backend.as_ref(),
            &plugin_registry,
            mcpg_plugin_protocol::store::StoreRole::Subscription,
        )
        .await?;
    let subscription_kv =
        wrap_tenant_kv(wrap_state_kv(subscription_kv, &state_cipher), &tenant_seg);
    let subscription_store_for_reload: std::sync::Arc<
        dyn crate::runtime::subscription_store::SubscriptionStore,
    > = std::sync::Arc::new(
        crate::runtime::subscription_store::KvBackedSubscriptionStore::new(
            subscription_kv,
            new_config.mcp.configurations.subscriptions.max_per_session,
        ),
    );

    // Reload-side wiring for `dev.mcpg/idempotency`.
    let new_idempotency_cfg = &new_config.mcp.configurations.idempotency;
    let new_idempotency_store: std::sync::Arc<dyn crate::runtime::idempotency::IdempotencyStore> =
        if new_idempotency_cfg.enabled {
            let kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
                new_idempotency_cfg.store.as_ref(),
                "idempotency",
                cluster_backend.as_ref(),
                &plugin_registry,
                mcpg_plugin_protocol::store::StoreRole::Custom("idempotency".to_owned()),
            )
            .await?;
            let kv = wrap_tenant_kv(wrap_state_kv(kv, &state_cipher), &tenant_seg);
            let policy = crate::runtime::idempotency::IdempotencyRetentionPolicy {
                default_ttl_ms: new_idempotency_cfg.default_ttl_ms,
                max_ttl_ms: new_idempotency_cfg.max_ttl_ms,
            };
            std::sync::Arc::new(crate::runtime::idempotency::KvBackedIdempotencyStore::new(
                kv, policy,
            ))
        } else {
            crate::runtime::idempotency::noop_idempotency_store()
        };
    let new_idempotency_capability = if new_idempotency_cfg.enabled {
        let methods: Vec<&str> = new_idempotency_cfg
            .supported_methods
            .iter()
            .map(String::as_str)
            .collect();
        Some(crate::runtime::idempotency::capability_advertisement(
            new_idempotency_cfg.default_ttl_ms / 1000,
            new_idempotency_cfg.max_ttl_ms / 1000,
            new_idempotency_cfg.scope.advertisement_label(),
            &methods,
            new_idempotency_cfg.conflict_policy.advertisement_label(),
        ))
    } else {
        None
    };

    let mut new_runtime = GatewayRuntime::try_new_with_runtime_controls_and_cache(
        "mcpg",
        env!("CARGO_PKG_VERSION"),
        new_config.gateway.server.bind_address.clone(),
        new_config.gateway.server.health_path.clone(),
        new_config.gateway.server.mcp_path.clone(),
        new_config.observability.logs.level.clone(),
        new_config.observability.logs.sinks.clone(),
        true,
        state.session_store.clone(), // Preserve session store across reload
        build_tool_access_policy_config(&new_config),
        RuntimeDebugConfig {
            enabled: new_config.feature_flags.debug_tools_enabled,
            command_profiles: new_config
                .debug
                .tools
                .command_profiles
                .iter()
                .map(|(name, profile)| {
                    (
                        name.clone(),
                        CommandToolRuntimeConfig {
                            command: profile.command.clone(),
                            args: profile.args.clone(),
                            timeout_ms: profile.timeout_ms,
                            max_output_bytes: profile.max_output_bytes,
                        },
                    )
                })
                .collect(),
            network_profiles: new_config
                .debug
                .tools
                .network_profiles
                .iter()
                .map(|(name, profile)| {
                    (
                        name.clone(),
                        NetworkToolRuntimeConfig {
                            url: profile.url.clone(),
                            timeout_ms: profile.timeout_ms,
                            max_response_bytes: profile.max_response_bytes,
                            expected_status_codes: profile.expected_status_codes.clone(),
                            require_json_response: profile.require_json_response,
                            headers: profile.headers.clone(),
                            allow_private_backends: new_config
                                .gateway
                                .server
                                .allow_private_backends,
                        },
                    )
                })
                .collect(),
            bindings: DebugToolBackends {
                command_probe_profile: new_config
                    .debug
                    .tools
                    .bindings
                    .command_probe_profile
                    .clone(),
                network_probe_profile: new_config
                    .debug
                    .tools
                    .bindings
                    .network_probe_profile
                    .clone(),
                network_json_call_profile: new_config
                    .debug
                    .tools
                    .bindings
                    .network_json_call_profile
                    .clone(),
            },
            exposure: DebugToolExposure {
                command_probe: new_config.debug.tools.exposure.command_probe,
                network_probe: new_config.debug.tools.exposure.network_probe,
                network_json_call: new_config.debug.tools.exposure.network_json_call,
                operational_overview_prompt: new_config
                    .debug
                    .tools
                    .exposure
                    .operational_overview_prompt,
                runtime_overview_resource: new_config
                    .debug
                    .tools
                    .exposure
                    .runtime_overview_resource,
            },
            default_allow_private_backends: new_config.gateway.server.allow_private_backends,
        },
        &new_config.mcp.capabilities.tools,
        &new_config.mcp.capabilities.prompts,
        &new_config.mcp.capabilities.resources,
        &new_config.mcp.capabilities.resource_templates,
        jwt_verifier,
        oidc_resolver,
        pipeline_store,
        task_store,
        delivery_bus,
        subscription_store_for_reload,
        if new_config.governance.policy.cache.enabled {
            Some(&new_config.governance.policy.cache)
        } else {
            None
        },
        plugin_registry,
        credential_cache,
        policy_chain.clone(),
    )?;

    new_runtime.set_content_stores(content_stores.clone());
    new_runtime.set_ema_authorization_server(build_ema_authorization_server(&new_config)?);
    new_runtime.set_aauth_resource(crate::app::auth_wiring::build_aauth_resource(&new_config)?);
    #[cfg(feature = "governance-quotas")]
    new_runtime.set_quota_gate(quota_gate.clone());
    new_runtime.set_idempotency_store(new_idempotency_store.clone());
    new_runtime.set_idempotency_capability(new_idempotency_capability.clone());
    new_runtime.set_idempotency_replay_revalidation(
        new_idempotency_cfg.enabled && new_idempotency_cfg.replay_revalidation,
    );
    new_runtime.set_revalidate_mutated_tool_arguments(
        new_config.gateway.server.revalidate_mutated_tool_arguments,
    );
    new_runtime.set_bind_session_owner(new_config.mcp.configurations.sessions.bind_session_owner);

    // SEP-1865 MCP Apps — re-wire on reload (mirrors boot path).
    let new_apps_cfg = &new_config.mcp.configurations.apps;
    let new_apps_capability = new_apps_cfg
        .enabled
        .then(|| crate::protocol::shared::apps::capability_value(&[]));
    let new_apps_policy = new_apps_cfg.enabled.then(|| new_apps_cfg.compiled_policy());
    new_runtime.set_apps_config(
        new_apps_capability,
        new_apps_cfg.federate_upstream_enabled(),
        new_apps_policy,
        &new_apps_cfg.registry,
    );
    new_runtime.set_tunnel_federation(new_config.gateway.server.tunnel_federation.as_ref());
    // CP-attached hooks are installed once, at attach time; a fresh runtime
    // starts on the no-op defaults, so they must be carried across every
    // reload or the CP stops receiving its own telemetry.
    {
        let old_runtime = state.runtime.load();
        new_runtime.adopt_cp_hooks(&old_runtime);
    }

    // Re-wire federation, preserving imported capabilities + governance
    // across the swap: seed the new overlays from the
    // old runtime (no flicker / governance gap), carry the old engine's
    // upstream sessions for unchanged federations, and skip the re-import
    // when the federation config is unchanged (no upstream reconnect).
    {
        let old_runtime = state.runtime.load();
        let federations_unchanged =
            state.config.load().mcp.federations == new_config.mcp.federations;
        new_runtime.rewire_federations(
            new_config.mcp.federations.clone(),
            format!("mcpg/{}", env!("CARGO_PKG_VERSION")),
            old_runtime.federated_capabilities(),
            old_runtime.federated_policies(),
            old_runtime.federation_engine(),
            !federations_unchanged,
            tenant_seg.clone(),
        );
    }

    // Mirror of the boot-time wiring in `run`: install the concrete
    // `GatewayBackendHost` on the late-bound host the LLM plugin
    // received during `build_plugin_registry`. See `run` for the
    // rationale.
    {
        let plugin_registry_arc = new_runtime.plugin_registry_arc();
        let mut host = crate::backends::host::GatewayBackendHost::new(
            plugin_registry_arc,
            &new_config.mcp.capabilities.tools,
            8,
            content_stores.clone(),
            response_cache.clone(),
            response_cache_overrides.clone(),
            Some(std::sync::Arc::clone(new_runtime.credential_cache())),
        );
        host.set_child_invoke_gates(
            new_config.governance.child_invoke.enforce_gates,
            policy_chain.clone(),
            new_runtime.pre_dispatch_policy_arc(),
        );
        let host = std::sync::Arc::new(host);

        // Secret rotation: cancel the PREVIOUS watcher set, then respawn
        // against the new registry. The set is held in AppState and
        // cancelled-before-replace (honoring SecretWatcherSet's reload
        // contract) so a reload doesn't leak a watcher set and its tasks
        // still bound to the swapped-out registry.
        {
            let mut watcher_guard = state.secret_watcher.lock().await;
            if let Some(old) = watcher_guard.take() {
                old.cancel().await;
            }
            if !resolved_secret_refs.is_empty() {
                let broadcaster = host.secret_rotation_broadcaster();
                let fan_out: mcpg_plugin_host::secret_watcher::RotationFanOut =
                    std::sync::Arc::new(move |secret_ref: &str, version: u64| -> usize {
                        broadcaster.notify(secret_ref, version)
                    });
                let watcher_set = mcpg_plugin_host::secret_watcher::SecretWatcherSet::spawn(
                    new_runtime.plugin_registry_arc(),
                    resolved_secret_refs.clone(),
                    fan_out,
                    mcpg_plugin_host::secret_watcher::DEFAULT_DEBOUNCE,
                )
                .await;
                *watcher_guard = Some(watcher_set);
            }
        }

        // Mirror the boot-time wiring: replay every buffered backend
        // plugin subscription onto the new `GatewayBackendHost` so
        // revocation + rotation fan-out stays live across hot-reload.
        backend_late_host.set(host.clone());

        // Re-bind GatewayHostServices to the
        // freshly-built registry. Mirrors the boot-time wiring at
        // `build_from_config`. Without this, adapters constructed by
        // the new registry would resolve host services against the
        // OLD registry handle and miss any newly-bound providers.
        // `host` (GatewayBackendHost) is passed so the backend
        // host-FFI slots also re-bind to the fresh registry.
        let gateway_host_services =
            std::sync::Arc::new(crate::app::host_services_impl::GatewayHostServices::new(
                new_runtime.plugin_registry_arc(),
                host,
            ));
        host_services_late.set(gateway_host_services);
    }

    // Capture old inventory for list_changed diffing
    let old_runtime = state.runtime.load();
    let (old_tools, old_prompts, old_resources) = old_runtime.inventory_names();
    let (new_tools, new_prompts, new_resources) = new_runtime.inventory_names();
    let session_store = state.session_store.clone();
    let new_delivery_bus = new_runtime.delivery_bus().clone();

    // Propagate the protocol registry + SharedServices installed on
    // the previous runtime onto the new one. Both are
    // immutable Arc handles and outlive any single reload; reusing
    // them keeps `handle_request` routing through the version
    // handler chain across hot reloads. (`SharedServices.runtime` is
    // a `Weak` to the `Arc<ArcSwap<...>>` swap cell, so the swap
    // below is transparent to it — no rebuild needed.)
    if let Some(registry) = old_runtime.protocol_registry.load_full() {
        new_runtime.set_protocol_registry(registry);
    }
    if let Some(services) = old_runtime.shared_services.load_full() {
        new_runtime.set_shared_services(services);
    }

    // Build the reloaded health-prober config BEFORE `new_config` is
    // moved into the swap below. The prober itself is (re)started after the
    // swap so it targets the new registry.
    let reloaded_prober_cfg =
        if !new_config.plugins.is_empty() && new_config.observability.plugin_health_probe.enabled {
            let p = &new_config.observability.plugin_health_probe;
            Some(mcpg_plugin_host::health_prober::HealthProbeConfig {
                interval: std::time::Duration::from_millis(p.interval_ms),
                probe_timeout: std::time::Duration::from_millis(p.probe_timeout_ms),
                failure_threshold: p.failure_threshold,
            })
        } else {
            None
        };

    // Atomically swap config, runtime, overlay, and policy chain
    state.runtime.store(Arc::new(new_runtime));
    state.config.store(Arc::new(new_config));
    state
        .config_overlay
        .store(Arc::new(config_overlay_outcome.merged));
    state.policy_chain.store(Arc::new(policy_chain));
    #[cfg(feature = "governance-quotas")]
    state.quota_gate.store(Arc::new(quota_gate));

    // Stop the prober that targeted the now-swapped-out registry and
    // start a fresh one on the reloaded registry, otherwise the boot prober
    // keeps probing a detached registry. Dropping the old handle signals it
    // to stop.
    {
        let mut prober_guard = state.plugin_health_prober.lock().await;
        *prober_guard = None;
        if let Some(cfg) = reloaded_prober_cfg {
            match cfg.validate() {
                Ok(()) => {
                    let handle = mcpg_plugin_host::health_prober::spawn(
                        state.runtime.load().plugin_registry_arc(),
                        cfg,
                    );
                    *prober_guard = Some(handle);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "reloaded plugin health prober config invalid; prober NOT restarted"
                    );
                }
            }
        }
    }

    // Drain the OLD registry's plugin background state, otherwise every old
    // plugin's background tasks/buffers (sinks, transports, providers, …)
    // would leak until process exit. The new runtime is already live, so the
    // old one is detached — safe to drain.
    old_runtime.plugin_registry().shutdown_all().await;
    // Stop the OLD watch engine and every watcher it started. The engine's
    // control loop would otherwise outlive the reload for as long as any clone
    // of its sender survives — and each reload would add another generation of
    // watchers polling the same resources.
    old_runtime.subscriptions().shutdown().await;
    // Likewise drain the OLD runtime's built content-store profiles
    // (held outside the plugin registry) so a reload flushes them too.
    if let Some(content_stores) = old_runtime.content_stores() {
        content_stores
            .shutdown(std::time::Duration::from_secs(5))
            .await;
    }

    // Re-wire the cluster audit emitter + start a
    // fresh watch_peers subscriber on the new registry. The prior
    // subscriber's stream will end when the old coordinator drops.
    spawn_cluster_audit_taps(&state.runtime.load());

    // Emit list_changed notifications for any inventory changes.
    // Only notify sessions that have completed initialization (Operational phase).
    let tools_changed = old_tools != new_tools;
    let prompts_changed = old_prompts != new_prompts;
    let resources_changed = old_resources != new_resources;

    if tools_changed || prompts_changed || resources_changed {
        let methods: Vec<&str> = [
            if tools_changed {
                Some("notifications/tools/list_changed")
            } else {
                None
            },
            if prompts_changed {
                Some("notifications/prompts/list_changed")
            } else {
                None
            },
            if resources_changed {
                Some("notifications/resources/list_changed")
            } else {
                None
            },
        ]
        .into_iter()
        .flatten()
        .collect();

        let sessions = session_store.list_sessions();
        let operational_sessions: Vec<_> = sessions
            .iter()
            .filter(|s| s.phase == crate::runtime::session_store::SessionPhase::Operational)
            .collect();

        info!(
            tools_changed,
            prompts_changed,
            resources_changed,
            session_count = operational_sessions.len(),
            "emitting list_changed notifications after config reload"
        );
        // list_changed broadcast on the audit lane.
        // One event per kind (tools / prompts / resources) carrying
        // the recipient session count.
        let registry_for_audit = state.runtime.load().plugin_registry_arc();
        let session_count = operational_sessions.len() as u64;
        for kind_label in [
            tools_changed.then_some("tools"),
            prompts_changed.then_some("prompts"),
            resources_changed.then_some("resources"),
        ]
        .into_iter()
        .flatten()
        {
            let event =
                mcpg_plugin_host::audit_events::list_changed_event(kind_label, session_count);
            let _ = registry_for_audit.emit_audit_event(&event).await;
        }

        for session in &operational_sessions {
            for method in &methods {
                let notification = crate::protocol::ListChangedNotification {
                    jsonrpc: crate::protocol::JSONRPC_VERSION,
                    method,
                };
                if let Ok(json_value) = serde_json::to_value(&notification) {
                    let message = crate::runtime::pipeline_store::DeliveryMessage {
                        kind: crate::runtime::pipeline_store::DeliveryKind::Notification,
                        jsonrpc_message: json_value,
                        delivery_id: String::new(),
                    };
                    let bus = new_delivery_bus.clone();
                    let sid = session.session_id.clone();
                    tokio::spawn(async move {
                        let _ = bus.publish(&sid, message).await;
                    });
                }
            }
        }
    }

    info!("gateway runtime reloaded successfully");
    Ok(())
}
