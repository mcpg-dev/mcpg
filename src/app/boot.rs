use super::*;

pub async fn build(config_paths: Vec<PathBuf>) -> Result<AppState> {
    let path_refs: Vec<&Path> = config_paths.iter().map(|p| p.as_path()).collect();
    let mut config = AppConfig::load_many(&path_refs)?;
    // For schema resolution use the LAST config file's directory — that's
    // the override layer the operator most recently authored, so any
    // relative `schemas[].file` paths anchor against it. When no files are
    // supplied (defaults + env only) there's nothing to anchor against.
    let config_dir = config_paths.last().and_then(|p| p.parent());
    config.resolve_schema_refs(config_dir).await?;
    build_from_config(config, config_paths).await
}

/// Build from an already-loaded config plus the file paths it came from.
/// Retained for callers (and tests) that only deal in file paths; wraps
/// [`build_from_sources`] by tagging each path as a [`ConfigSource::File`].
pub async fn build_from_config(config: AppConfig, config_paths: Vec<PathBuf>) -> Result<AppState> {
    let sources = config_paths
        .into_iter()
        .map(crate::config::ConfigSource::File)
        .collect();
    build_from_sources(config, sources).await
}

pub async fn build_from_sources(
    mut config: AppConfig,
    config_sources: Vec<crate::config::ConfigSource>,
) -> Result<AppState> {
    let mut observability = observability::init(&config.observability)?;
    // Config loads before this point, so the report waits for a subscriber.
    let ignored_env = crate::config::AppConfig::ignored_env_overrides();
    if !ignored_env.is_empty() {
        tracing::info!(
            variables = %ignored_env.join(", "),
            "ignoring MCPG_-prefixed environment variables that name no config key"
        );
    }
    crate::runtime::feature_flags::install(&config.feature_flags);
    // Apply the operator-supplied plugin-call span sampling rate to the
    // process-wide atomic the metering wrappers consult.
    // `None` leaves the threshold at its always-on default.
    if let Some(rate) = config.observability.plugin_call_sampling_rate {
        mcpg_plugin_host::span_sampling::set_plugin_call_sampling_rate(rate);
    }
    let store_config = SessionStoreConfig {
        replay_window_limit: config.gateway.server.replay_window_limit,
        session_idle_timeout_ms: config.gateway.server.session_idle_timeout_ms,
        max_sessions: 10_000,
        max_sessions_per_tenant: config.gateway.server.max_sessions_per_tenant,
    };
    let jwt_verifier = build_jwt_verifier(&config).await?;
    let oidc_resolver = build_oidc_resolver(&config)?.map(std::sync::Arc::new);

    // Standalone deployments prove their plugin entitlements before
    // anything is loaded; CP-attached ones are gated at the CP bind.
    crate::license_gate::enforce_plugin_license_gate(&config)?;

    // Build the plugin registry FIRST, before any capability touches
    // its KV / PubSub primitives. This guarantees the cluster
    // coordinator is fully registered (single-node built-in OR
    // cdylib-loaded redis / nats / consul / etcd) by the time
    // capability boot extracts its primitives via
    // `registry.cluster_backend().key_value_store()` etc. — so every
    // capability inherits them universally with no kind-specific
    // special-casing in the gateway boot path.
    //
    // `build_plugin_registry` does not consume any capability store,
    // so ordering it first costs nothing. OAuth-secret resolution
    // (which DOES consume the registry) still runs between the
    // registry build and the runtime constructor.
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
    } = build_plugin_registry(&mut config, jwt_verifier.as_ref(), oidc_resolver.clone()).await?;

    // Runs here rather than at validation time so it sees the final binding
    // set — including the capabilities plugins expanded during the registry
    // build.
    crate::config::warn_unreachable_binding_trust(&config);

    // Capability boot draws KV / PubSub primitives from the cluster
    // coordinator. `Some` for any cluster kind that exposes the
    // primitive (single-node always does; redis / nats both do; consul
    // / etcd partially do — see `provides:` on each plugin manifest).
    // `None` falls back to a fresh in-process `MemoryKv` / `MemoryBus`
    // per capability — the unconditional default before any kind of
    // cluster plugin is loaded.
    let cluster_backend = plugin_registry.cluster_backend();

    // Opt-in AEAD envelope encryption for ALL coordinator-backed
    // capability state. `None` (no `cluster.state_encryption_key_env`) =
    // plaintext serde. Built once here and applied to
    // every capability KV/bus resolved below (sessions, delivery,
    // pipelines, tasks, subscriptions, idempotency, cancellation +
    // backstop) and the approvals backstop. The credential cache is NOT
    // wrapped — it has its own cipher.
    let state_cipher = build_state_cipher(&config.cluster)?;
    // Optional per-deployment tenant segment that prefixes every
    // capability KV key + bus topic (outermost wrap) for broker-ACL fencing.
    let tenant_seg = config.cluster.tenant_segment.clone();

    // Per-capability backend selection lives entirely on the
    // per-capability `<capability>.store` / `<capability>.bus`
    // overrides. There is no global "all use this backend" knob.
    // When no override is set, capability boot
    // inherits from `cluster_backend.key_value_store()` /
    // `pub_sub()` and falls back to a fresh in-process Memory*
    // primitive only when the coordinator can't expose one. Operators
    // wanting nats / redis / etc. either point `cluster.kind` at the
    // matching backend (then every capability inherits) or set per-
    // capability overrides for finer control.

    // Unified session-store path: every backend resolves to a single
    // `Arc<dyn KeyValueStore>` and the session store is always
    // `KvBackedSessionStore` over that primitive. There is no
    // per-impl-class divergence (`InMemorySessionStore` /
    // `FileBackedSessionStore`) — `KvBackedSessionStore` over
    // `MemoryKv` / `FileKv` is functionally equivalent and lets the
    // session store consume the same primitive accessor surface the
    // cluster plugin advertises.
    //
    // When `sessions.store: { kind, … }` is set, that override drives
    // KV construction directly. The override carries its own
    // connection details (url, password, key_prefix, …), so the
    // top-level `redis:` / `nats:` blocks are not consulted for an
    // overridden session store.
    let session_kv: Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        config.mcp.configurations.sessions.store.as_ref(),
        "sessions",
        cluster_backend.as_ref(),
        &plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Session,
    )
    .await?;
    let session_kv = wrap_tenant_kv(wrap_state_kv(session_kv, &state_cipher), &tenant_seg);
    let session_store: Arc<dyn crate::runtime::session_store::SessionStore> = Arc::new(
        crate::runtime::session_store::KvBackedSessionStore::new(store_config, session_kv).await?,
    );

    // Unified delivery_bus path: every backend variant resolves to a
    // single `Arc<dyn PubSub>` and the bus is always
    // `BusBackedDeliveryBus`. There is no separate `InProcessDeliveryBus`
    // shortcut for the unconfigured / connect-failed case —
    // `BusBackedDeliveryBus` over `MemoryBus` is functionally
    // equivalent (in-process broadcast, fire-and-forget) and keeps
    // the impl single-source.
    //
    // When `delivery_bus.bus: { kind, … }` is set, the override drives
    // PubSub construction directly.
    let delivery_pubsub: Arc<dyn mcpg_cluster_api::PubSub> = resolve_capability_bus(
        config.mcp.configurations.delivery.bus.as_ref(),
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

    let pipeline_kv: Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        config.mcp.configurations.pipelines.store.as_ref(),
        "pipelines",
        cluster_backend.as_ref(),
        &plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Pipeline,
    )
    .await?;
    let pipeline_kv = wrap_tenant_kv(wrap_state_kv(pipeline_kv, &state_cipher), &tenant_seg); // also backs MRTR request-state
    let pipeline_store: std::sync::Arc<dyn crate::runtime::pipeline_store::PipelineStore> =
        std::sync::Arc::new(crate::runtime::pipeline_store::KvBackedPipelineStore::new(
            // Cloned so the same coordinator KV also backs the MRTR
            // requestState codec below.
            Arc::clone(&pipeline_kv),
        ));

    // Thread the configured retention policy into whichever backend. Both
    // sides are milliseconds — the config field is named `_ms`, defaults to
    // 1_800_000 (30 minutes), and is documented as such, matching the
    // `task.ttl` the client sends.
    let task_policy = crate::runtime::task_store::TaskRetentionPolicy {
        default_ttl_ms: config.mcp.capabilities.tasks.default_ttl_ms,
        max_tasks_per_session: config.mcp.capabilities.tasks.max_tasks_per_session,
        result_wait_ms: config.mcp.capabilities.tasks.result_wait_ms,
    };
    info!(
        default_ttl_ms = task_policy.default_ttl_ms,
        max_tasks_per_session = task_policy.max_tasks_per_session,
        "task store policy"
    );
    let task_kv: Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        config.mcp.capabilities.tasks.store.as_ref(),
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

    let subscription_kv: Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
        config.mcp.configurations.subscriptions.store.as_ref(),
        "subscriptions",
        cluster_backend.as_ref(),
        &plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Subscription,
    )
    .await?;
    let subscription_kv =
        wrap_tenant_kv(wrap_state_kv(subscription_kv, &state_cipher), &tenant_seg);
    let subscription_store: std::sync::Arc<
        dyn crate::runtime::subscription_store::SubscriptionStore,
    > = std::sync::Arc::new(
        crate::runtime::subscription_store::KvBackedSubscriptionStore::new(
            subscription_kv,
            config.mcp.configurations.subscriptions.max_per_session,
        ),
    );

    // `dev.mcpg/idempotency` — opt-in. When the
    // operator enables the feature the gateway wires a
    // `KvBackedIdempotencyStore` over the cluster KV; otherwise a
    // `NoopIdempotencyStore` placeholder satisfies the runtime
    // field without persisting anything. Capability advertisement
    // is computed from the same config so the two surfaces stay
    // in sync.
    let idempotency_cfg = &config.mcp.configurations.idempotency;
    let idempotency_store: std::sync::Arc<dyn crate::runtime::idempotency::IdempotencyStore> =
        if idempotency_cfg.enabled {
            let idempotency_kv: Arc<dyn mcpg_cluster_api::KeyValueStore> = resolve_capability_kv(
                idempotency_cfg.store.as_ref(),
                "idempotency",
                cluster_backend.as_ref(),
                &plugin_registry,
                mcpg_plugin_protocol::store::StoreRole::Custom("idempotency".to_owned()),
            )
            .await?;
            let idempotency_kv =
                wrap_tenant_kv(wrap_state_kv(idempotency_kv, &state_cipher), &tenant_seg);
            let policy = crate::runtime::idempotency::IdempotencyRetentionPolicy {
                default_ttl_ms: idempotency_cfg.default_ttl_ms,
                max_ttl_ms: idempotency_cfg.max_ttl_ms,
            };
            std::sync::Arc::new(crate::runtime::idempotency::KvBackedIdempotencyStore::new(
                idempotency_kv,
                policy,
            ))
        } else {
            crate::runtime::idempotency::noop_idempotency_store()
        };
    let idempotency_capability = if idempotency_cfg.enabled {
        let methods: Vec<&str> = idempotency_cfg
            .supported_methods
            .iter()
            .map(String::as_str)
            .collect();
        Some(crate::runtime::idempotency::capability_advertisement(
            idempotency_cfg.default_ttl_ms / 1000,
            idempotency_cfg.max_ttl_ms / 1000,
            idempotency_cfg.scope.advertisement_label(),
            &methods,
            idempotency_cfg.conflict_policy.advertisement_label(),
        ))
    } else {
        None
    };

    let mut runtime = GatewayRuntime::try_new_with_runtime_controls_and_cache(
        "mcpg",
        env!("CARGO_PKG_VERSION"),
        config.gateway.server.bind_address.clone(),
        config.gateway.server.health_path.clone(),
        config.gateway.server.mcp_path.clone(),
        config.observability.logs.level.clone(),
        config.observability.logs.sinks.clone(),
        true,
        session_store.clone(),
        build_tool_access_policy_config(&config),
        RuntimeDebugConfig {
            enabled: config.feature_flags.debug_tools_enabled,
            command_profiles: config
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
            network_profiles: config
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
                            allow_private_backends: config.gateway.server.allow_private_backends,
                        },
                    )
                })
                .collect(),
            bindings: DebugToolBackends {
                command_probe_profile: config.debug.tools.bindings.command_probe_profile.clone(),
                network_probe_profile: config.debug.tools.bindings.network_probe_profile.clone(),
                network_json_call_profile: config
                    .debug
                    .tools
                    .bindings
                    .network_json_call_profile
                    .clone(),
            },
            exposure: DebugToolExposure {
                command_probe: config.debug.tools.exposure.command_probe,
                network_probe: config.debug.tools.exposure.network_probe,
                network_json_call: config.debug.tools.exposure.network_json_call,
                operational_overview_prompt: config
                    .debug
                    .tools
                    .exposure
                    .operational_overview_prompt,
                runtime_overview_resource: config.debug.tools.exposure.runtime_overview_resource,
            },
            default_allow_private_backends: config.gateway.server.allow_private_backends,
        },
        &config.mcp.capabilities.tools,
        &config.mcp.capabilities.prompts,
        &config.mcp.capabilities.resources,
        &config.mcp.capabilities.resource_templates,
        jwt_verifier,
        oidc_resolver,
        pipeline_store,
        task_store,
        delivery_bus,
        subscription_store,
        if config.governance.policy.cache.enabled {
            Some(&config.governance.policy.cache)
        } else {
            None
        },
        plugin_registry,
        credential_cache,
        policy_chain.clone(),
    )?;

    // sql_tx/sql_await pipeline steps resolve the `sql` backend from the
    // plugin registry at dispatch time (BackendPlugin::execute_transaction
    // / execute) — no concrete-plugin handoff needed.

    // Wire the operator-configured content store so the
    // `mcpg-resource://` branch of `resources/read` serves bytes
    // directly. `None` keeps the runtime returning generic
    // "unknown resource" for those URIs.
    runtime.set_content_stores(content_stores.clone());

    // Embedded EMA authorization server (governance.access.authorization_server).
    runtime.set_ema_authorization_server(build_ema_authorization_server(&config)?);

    // Install the runtime quota gate so the
    // dispatch hook can reach it. `None` (no `governance.quotas:`
    // policies AND no per-binding refs) keeps the dispatch hook
    // short-circuiting to Allow without taking any locks.
    #[cfg(feature = "governance-quotas")]
    runtime.set_quota_gate(quota_gate.clone());

    // Install the `dev.mcpg/idempotency` extension surface. The store
    // + capability advertisement are wired
    // pre-construction; the setters thread them onto the runtime
    // after `try_new_with_runtime_controls_and_cache` returns so
    // existing call sites that don't care about idempotency keep a
    // stable signature.
    runtime.set_idempotency_store(idempotency_store.clone());
    runtime.set_idempotency_capability(idempotency_capability.clone());
    runtime.set_idempotency_replay_revalidation(
        idempotency_cfg.enabled && idempotency_cfg.replay_revalidation,
    );
    runtime.set_revalidate_mutated_tool_arguments(
        config.gateway.server.revalidate_mutated_tool_arguments,
    );
    runtime.set_bind_session_owner(config.mcp.configurations.sessions.bind_session_owner);

    // SEP-1865 MCP Apps. `enabled` lights up the downstream capability
    // advertisement + the egress CSP/permission policy;
    // `federate_upstream` (inheriting `enabled`) advertises the
    // capability to federated upstreams so they emit UI tools.
    let apps_cfg = &config.mcp.configurations.apps;
    let apps_capability = apps_cfg
        .enabled
        .then(|| crate::protocol::shared::apps::capability_value(&[]));
    let apps_policy = apps_cfg.enabled.then(|| apps_cfg.compiled_policy());
    runtime.set_apps_config(
        apps_capability,
        apps_cfg.federate_upstream_enabled(),
        apps_policy,
        &apps_cfg.registry,
    );
    runtime.set_tunnel_federation(config.gateway.server.tunnel_federation.as_ref());

    // Install the concrete `GatewayBackendHost` on the late-bound host
    // that the LLM plugin received at `register_profile` time. This
    // unlocks the agentic tool-calling loop — the LLM binding can now
    // dispatch `tool_calls` to other plugin-backed bindings (sql /
    // nats / kafka / llm). Until this line runs, child-tool calls
    // inside the LLM binding return `BackendHostError::NotImplemented`.
    // See `apps/gateway/src/bindings/host.rs` for the host's behaviour
    // and its scope (plugin-backed bindings only; adapter-backed
    // HTTP/Command/etc. as child tools remain a follow-up).
    // Hold the secret-watcher set + health-prober handle (rather than
    // mem::forget them) so they live in AppState and reload_config can
    // cancel/replace them instead of leaking one of each per reload.
    let mut secret_watcher_set: Option<mcpg_plugin_host::secret_watcher::SecretWatcherSet> = None;
    let mut health_prober_handle: Option<mcpg_plugin_host::health_prober::HealthProberHandle> =
        None;
    {
        let plugin_registry_arc = runtime.plugin_registry_arc();
        let mut host = crate::backends::host::GatewayBackendHost::new(
            plugin_registry_arc,
            &config.mcp.capabilities.tools,
            // Gateway-wide depth cap; the LLM binding's own
            // `tools.max_iterations` further bounds the per-call horizon.
            8,
            content_stores.clone(),
            response_cache.clone(),
            response_cache_overrides.clone(),
            Some(std::sync::Arc::clone(runtime.credential_cache())),
        );
        host.set_child_invoke_gates(
            config.governance.child_invoke.enforce_gates,
            policy_chain.clone(),
            runtime.pre_dispatch_policy_arc(),
        );
        let host = std::sync::Arc::new(host);
        info!(
            registered_routes = host.route_count(),
            content_stores = content_stores.is_some(),
            "GatewayBackendHost installed for LLM tool-calling loop"
        );

        // Secret rotation: spawn one `secret_watcher` task per unique
        // resolved `vault://...` (or other rotation-aware)
        // URI. The watch loop consumes
        // `SecretProvider::watch(secret_ref)` events, debounces
        // bursts, and fans each out to every backend that subscribed
        // via `BackendHost::subscribe_secret_rotation`.
        if !resolved_secret_refs.is_empty() {
            let broadcaster = host.secret_rotation_broadcaster();
            let fan_out: mcpg_plugin_host::secret_watcher::RotationFanOut =
                std::sync::Arc::new(move |secret_ref: &str, version: u64| -> usize {
                    broadcaster.notify(secret_ref, version)
                });
            let watcher_set = mcpg_plugin_host::secret_watcher::SecretWatcherSet::spawn(
                runtime.plugin_registry_arc(),
                resolved_secret_refs.clone(),
                fan_out,
                mcpg_plugin_host::secret_watcher::DEFAULT_DEBOUNCE,
            )
            .await;
            // Held in AppState (below) so `reload_config` can `cancel()` this
            // set before spawning the next one; a plain drop / graceful
            // shutdown also cancels every spawned task via the set's Drop.
            secret_watcher_set = Some(watcher_set);
        }

        // Energise the late-bound host the four non-LLM backend
        // plugins received at `register_profile`.
        // After this call, both `subscribe_credential_revoked` and
        // `subscribe_secret_rotation` callbacks the plugins
        // installed during boot are replayed onto the real
        // `GatewayBackendHost` and start receiving events.
        backend_late_host.set(host.clone());

        // Bind the real GatewayHostServices into the
        // late-bound wrapper every native adapter received
        // at `make` time. Until this point plugin → host calls
        // (resolve_secret, audit_event, metric_emit, span_*) routed
        // through `NullHostServices` and returned typed
        // "host services not wired" errors. After this set, those
        // calls reach the gateway's real implementation backed by
        // `PluginRegistry`. The set is idempotent across reloads —
        // `reload_config` calls it again with the freshly-built
        // registry's services.
        //
        // `host` (the GatewayBackendHost) is passed too so the
        // backend host-FFI slots (resolve_credentials / cache_get /
        // subscribe_*) reach the same services the static backends use.
        let gateway_host_services =
            std::sync::Arc::new(crate::app::host_services_impl::GatewayHostServices::new(
                runtime.plugin_registry_arc(),
                host,
            ));
        host_services_late.set(gateway_host_services);
    }

    // Spawn the plugin health prober. The handle is kept in AppState
    // (`plugin_health_prober`) so reload can stop this prober and start a
    // fresh one on the reloaded registry, and graceful shutdown can stop it
    // before teardown. Dropping the handle signals the prober to stop.
    if !config.plugins.is_empty() && config.observability.plugin_health_probe.enabled {
        let prober_cfg = mcpg_plugin_host::health_prober::HealthProbeConfig {
            // The config fields are MILLISECONDS (their `_ms` suffix + 30000/5000
            // defaults). Using `from_secs` here read them as seconds — a 1000x
            // unit error that made the default probe interval 8.3 HOURS (so health
            // probing effectively never ran).
            interval: std::time::Duration::from_millis(
                config.observability.plugin_health_probe.interval_ms,
            ),
            probe_timeout: std::time::Duration::from_millis(
                config.observability.plugin_health_probe.probe_timeout_ms,
            ),
            failure_threshold: config.observability.plugin_health_probe.failure_threshold,
        };
        match prober_cfg.validate() {
            Ok(()) => {
                let handle = mcpg_plugin_host::health_prober::spawn(
                    runtime.plugin_registry_arc(),
                    prober_cfg,
                );
                // Held in AppState (below) so reload can stop this prober
                // (which targets the boot registry) and start a fresh one on
                // the reloaded registry; dropping the handle signals stop.
                health_prober_handle = Some(handle);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "plugin health prober config invalid; prober NOT started"
                );
            }
        }
    }

    // Cluster-aware cancellation bus over the orthogonal PubSub
    // primitive. Backend choice (nats / redis / in-process MemoryBus)
    // is just which `Arc<dyn PubSub>` we plug into
    // `BusBackedCancellationBus`. The unconfigured case defaults to an
    // explicit MemoryBus rather than a separate in-process fallback,
    // so multi-replica deployments always have a working cross-replica
    // cancellation channel by construction (single-node / MemoryBus is
    // the same in-process broadcast).
    //
    // When `cancellation_bus.bus: { kind, … }` is set, the override
    // drives PubSub construction directly.
    let cancel_pubsub: Arc<dyn mcpg_cluster_api::PubSub> = resolve_capability_bus(
        config.mcp.configurations.cancellation.bus.as_ref(),
        "cancellation",
        cluster_backend.as_ref(),
    )
    .await?;
    let cancel_pubsub = wrap_tenant_bus(wrap_state_bus(cancel_pubsub, &state_cipher), &tenant_seg);
    // Durable backstop: mirror cancellations to the coordinator's KV
    // so a subscriber that reconnects / restarts recovers events the
    // at-most-once pub/sub path dropped. Inherits the coordinator KV (the
    // same backbone the capability stores use); single-node / no-coordinator
    // gets an in-process MemoryKv, which still recovers MemoryBus lag drops.
    // The backstop KV is wrapped too, so recovered cancellations are
    // sealed at rest like every other capability store.
    let cancel_backstop_kv = wrap_tenant_kv(
        wrap_state_kv(
            default_capability_kv("cancellation", cluster_backend.as_ref()),
            &state_cipher,
        ),
        &tenant_seg,
    );
    runtime.set_cancellation_bus(Arc::new(
        crate::runtime::cancellation_bus::BusBackedCancellationBus::new_with_backstop(
            cancel_pubsub,
            cancel_backstop_kv,
        )
        // Opt-in per-principal subject partitioning so broker-native subject
        // ACLs can fence cancel traffic. Validated at boot to require a
        // wildcard-capable bus (redis/nats).
        .with_principal_partitioning(
            config
                .mcp
                .configurations
                .cancellation
                .partition_by_principal,
        ),
    ));

    // Tool-call rate limiting (cluster-aware via NATS / Redis or
    // in-process token bucket) is now configured as a tool-gate
    // plugin under `plugins[]` — see
    // `libs/plugins/reliability/rate-limit/`. The previous top-level
    // `rate_limit:` block + `mcpg-backend-api` adapter chain has been
    // removed.

    runtime.set_completion_rate_limit(config.gateway.server.completion_rate_limit_per_sec);
    runtime.set_max_sessions_per_tenant(config.gateway.server.max_sessions_per_tenant);
    runtime.set_relax_request_id_uniqueness(config.gateway.server.relax_request_id_uniqueness);
    runtime.set_access_log(config.gateway.server.access_log);
    // Wire MCP federation: build the engine, attach it
    // to the dispatcher, and kick off capability import + the satellite
    // sweeper. No-op when `mcp.federations` is empty.
    runtime.wire_federations(
        config.mcp.federations.clone(),
        format!("mcpg/{}", env!("CARGO_PKG_VERSION")),
        tenant_seg.clone(),
    );
    crate::backends::set_extra_resource_uri_schemes(
        config.gateway.server.extra_resource_uri_schemes.clone(),
    );

    // Install operator-supplied approval signing key +
    // callback base url, then start the cluster subscriber + GC
    // tasks. Approvals work without this (random per-process key,
    // single-instance only) so the call is unconditional; absent
    // config just means the runtime keeps its default registry but
    // still spawns the GC.
    {
        let node_id = runtime
            .plugin_registry()
            .cluster_backend()
            .map(|c| {
                // Best-effort node id from the coordinator; fallback to
                // an empty string so self-publish dedup is a no-op
                // when the coordinator can't supply one synchronously.
                let _ = c;
                String::new()
            })
            .unwrap_or_default();
        runtime
            .apply_approvals_config(
                &config.governance.approvals,
                node_id,
                state_cipher.cipher.clone(),
                state_cipher.allow_plaintext_reads,
                tenant_seg.clone(),
            )
            .await?;
    }

    // Security: warn on insecure public bind (no TLS or no auth).
    {
        let bind = config.gateway.server.bind_address.as_str();
        let public_bind =
            bind.starts_with("0.0.0.0") || bind.starts_with("[::]") || bind.starts_with("::");
        let auth_enabled = config.governance.access.is_enabled();
        let tls_enabled = config.gateway.server.tls.is_some();
        if public_bind && (!auth_enabled || !tls_enabled) {
            tracing::warn!(
                bind_address = %bind,
                auth_enabled,
                tls_enabled,
                "MCPG bound on ALL interfaces without TLS and/or auth; \
                 prefer 127.0.0.1 for local deployments or configure \
                 server.tls + auth.jwks for public exposure"
            );
            metrics::counter!("mcpg_insecure_public_bind_total").increment(1);
        }
    }

    // Surface the credential-cache mode in startup logs +
    // metrics. The mode label drives ops dashboards that need to
    // tell single-node from multi-instance deploys at a glance.
    let credential_cache_mode = if runtime.credential_cache().is_clustered() {
        "clustered"
    } else {
        "local"
    };
    metrics::gauge!(
        "mcpg_credential_cache_mode_active",
        "mode" => credential_cache_mode,
    )
    .set(1.0);

    info!(
        service = %runtime.service_name,
        version = %runtime.service_version,
        started_at = %runtime.started_at,
        bind_address = %config.gateway.server.bind_address,
        health_path = %config.gateway.server.health_path,
        mcp_path = %config.gateway.server.mcp_path,
        credential_cache_mode = %credential_cache_mode,
        "application bootstrap complete"
    );
    // Connect the tracing bridges to the live runtime so
    // `tracing::info!` / `warn!` / `error!` start flowing through
    // `registry.emit_log_record` and every `tracing::info_span!` flows
    // through `registry.emit_telemetry_span_*`. Must happen AFTER
    // runtime construction (both bridges hold an `Arc<ArcSwap<
    // GatewayRuntime>>`) but BEFORE we wrap `observability` in Arc
    // (attach needs mutable access). Idempotent — no-op if already
    // attached (e.g. on a hot-reload path that re-enters this
    // function).
    // Optional Control Plane attachment. When the
    // `cp-attached` feature is built in AND `config.gateway.control_plane`
    // is set, this registers an `AgentRunner`, wires its
    // `MetricsBuffer` as the gateway's `ToolCallRecorder`, and
    // spawns the agent on its own task. No-op otherwise. Must
    // happen BEFORE `Arc::new(ArcSwap::from_pointee(runtime))`
    // so we still have `&mut runtime` to set the recorder slot.
    // The returned handle is intentionally leaked into the
    // background task — graceful shutdown follows the gateway's
    // own shutdown signal (the agent's reconnect loop exits
    // cleanly when the tokio runtime drops).
    let cp_attach =
        crate::runtime::cp::attach::wire_if_configured(&mut runtime, &config, &observability)
            .await?;

    let runtime_arc = Arc::new(ArcSwap::from_pointee(runtime));

    // Wire the cluster_metering audit emitter and spawn the
    // centralized watch_peers subscriber so member
    // join/leave/health_changed and leader-acquire events land on
    // the audit lane. Single subscriber → no fan-out duplicates.
    spawn_cluster_audit_taps(&runtime_arc.load());

    // Populate the bridge `target_prefix → plugin_id` map from the
    // now-registered manifests + build per-plugin signal filters from
    // `config.plugins[].observability`.
    // Must happen BEFORE the bridge attach calls so the forwarder
    // tasks see the populated maps.
    {
        let runtime_snapshot = runtime_arc.load();
        observability.populate_target_map(runtime_snapshot.plugin_registry());
    }
    let (logs_filters, metrics_filters, traces_filters) =
        build_per_plugin_observability_filters(&config.plugins)
            .map_err(|msg| anyhow::anyhow!("per-plugin observability config: {msg}"))?;

    // Validate that every per-plugin sink id refers to a sink
    // plugin actually registered for the matching signal — boot
    // refuses on a typo so operators don't silently lose events.
    {
        let runtime_snapshot = runtime_arc.load();
        let registry = runtime_snapshot.plugin_registry();
        validate_per_plugin_sink_ids(
            &logs_filters,
            &metrics_filters,
            &traces_filters,
            &registry.log_sink_ids().into_iter().collect(),
            &registry.metrics_sink_ids().into_iter().collect(),
            &registry.telemetry_sink_ids().into_iter().collect(),
        )
        .map_err(|msg| anyhow::anyhow!("per-plugin observability sink validation: {msg}"))?;
    }

    observability.attach_log_bridge(Arc::clone(&runtime_arc), logs_filters);
    observability.attach_telemetry_bridge(Arc::clone(&runtime_arc), traces_filters);
    observability.attach_metrics_bridge(Arc::clone(&runtime_arc), metrics_filters);

    // Install the multi-version protocol registry and
    // `SharedServices` bundle on the runtime. After this call
    // `GatewayRuntime::handle_request` routes the Protocol arm through
    // `ProtocolHandler::dispatch` for the negotiated version
    // (compile-time default = `V_2025_11_25`).
    //
    // Two handlers are registered today:
    // - `v_2025_11_25::Handler` — the production-grade legacy
    //   wire (default).
    // - `v_2026_07_28::Handler` — the modern wire (advertises
    //   `DRAFT-2026-v1`). Reachable when a client pins the modern
    //   version via the `Mcp-Protocol-Version` header or the
    //   request body's `_meta.io.modelcontextprotocol/protocolVersion`.
    //   `transports/http.rs::mcp_handler` runs `registry.select()` on the
    //   request itself, so a modern request reaches the modern handler's
    //   `parse()` + `dispatch()`.
    //
    // SharedServices holds a Weak handle to `runtime_arc` to break
    // the runtime↔services ownership cycle.
    let config_arc: Arc<AppConfig> = Arc::new(config);

    // Mint the MRTR `requestState` codec used by the modern handler's
    // suspending `tools/call` arm.
    // Sources the encryption key in the following order:
    //   1. operator config (`mcp.configurations.request_state.encryption_key`).
    //   2. clustered: a sub-key derived from `cluster.state_encryption_key_env`
    //      (HMAC-SHA256, domain-separated) so every replica decodes the same
    //      blob without a second configured secret.
    //   3. ephemeral key (random per process; resumptions lost on restart and
    //      undecodable on a peer) — guarded fail-closed in clustered mode when
    //      `request_state.strict_encryption` is set.
    use crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec;
    use base64::Engine;
    let configured_key = config_arc
        .mcp
        .configurations
        .request_state
        .encryption_key
        .as_deref();
    let clustered = !config_arc.cluster.is_single_node();
    let strict_encryption = config_arc
        .mcp
        .configurations
        .request_state
        .strict_encryption;
    // Cluster-stable derivation source, decoded once. A malformed cluster key
    // is a hard boot error (mirrors build_state_cipher) regardless of strict.
    let cluster_key = cluster_state_key_bytes(&config_arc.cluster)?;
    let request_state_key = if let Some(b64) = configured_key {
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                tracing::info!(
                    "MRTR `requestState` codec: using operator-configured encryption key \
                     (sourced from mcp.configurations.request_state.encryption_key)"
                );
                key
            }
            Ok(bytes) => {
                tracing::warn!(
                    key_bytes = bytes.len(),
                    "mcp.configurations.request_state.encryption_key decoded to {} bytes, \
                     expected 32 — falling back to ephemeral key",
                    bytes.len()
                );
                RequestStateCodec::ephemeral_key()
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "mcp.configurations.request_state.encryption_key is not valid base64 — \
                     falling back to ephemeral key"
                );
                RequestStateCodec::ephemeral_key()
            }
        }
    } else if let Some(base) = cluster_key {
        // No explicit codec key, but a cluster-stable key exists: derive a
        // domain-separated sub-key so the inline (≤8 KiB) resume blob decodes
        // on every replica.
        tracing::info!(
            "MRTR `requestState` codec: deriving the encryption key from \
             cluster.state_encryption_key_env (domain-separated) — modern resumptions \
             decode across replicas without a separate request_state.encryption_key"
        );
        derive_cluster_subkey(&base, b"mcpg:request-state-codec:v1")
    } else if clustered && strict_encryption {
        anyhow::bail!(
            "request_state.strict_encryption is set and this deployment is clustered \
             (cluster.kind != single_node), but the MRTR `requestState` codec has no \
             stable key: set mcp.configurations.request_state.encryption_key (base64 \
             32-byte secret, IDENTICAL on every replica) OR cluster.state_encryption_key_env. \
             Refusing to boot with an ephemeral per-process key, which is undecodable on a \
             peer and would silently break modern cross-replica resume."
        );
    } else {
        if clustered {
            tracing::warn!(
                "MRTR `requestState` codec is using an EPHEMERAL encryption key in a \
                 CLUSTERED deployment — the inline (≤8 KiB) modern resume blob cannot be \
                 decoded on another replica (cross-instance resume silently fails). Set \
                 mcp.configurations.request_state.encryption_key OR \
                 cluster.state_encryption_key_env (identical on every replica), or set \
                 request_state.strict_encryption to fail closed instead of degrading."
            );
        } else {
            tracing::warn!(
                "MRTR `requestState` codec is using an EPHEMERAL encryption key — \
                 configure `mcp.configurations.request_state.encryption_key` (base64-encoded \
                 32-byte secret) to keep modern resumptions decodable across gateway restarts."
            );
        }
        RequestStateCodec::ephemeral_key()
    };
    // Back the >8 KiB handle path with the coordinator KV (reusing
    // the pipeline KV — requestState IS pipeline-resumption state, with a
    // distinct `request_state/` key namespace) so a large-payload modern
    // suspension resumes on any replica and survives a restart, instead of
    // the per-process InMemory store that pinned it to one instance.
    let request_state_codec = Arc::new(RequestStateCodec::new(
        request_state_key,
        Arc::new(
            crate::runtime::request_state_store::KvBackedRequestStateStore::with_default_ttl(
                Arc::clone(&pipeline_kv),
            ),
        ),
    ));

    // Modern (DRAFT-2026-v1) stateless cross-replica continuity. The
    // synthetic session id minted for an authenticated principal is
    // deterministic across replicas when a shared
    // `sessions.synthetic_session_key` is configured OR (by default) when it
    // can be derived from `cluster.state_encryption_key_env`. Surface the
    // remaining failure modes at boot (malformed explicit key, clustered with
    // neither key) so a misconfigured multi-replica deployment doesn't
    // silently break task/subscription continuity + modern resume under a
    // round-robin LB.
    {
        let clustered = !config_arc.cluster.is_single_node();
        // Whether a cluster-stable derivation source exists (a malformed
        // cluster key already fails the boot in the requestState wiring above).
        let cluster_derivable = cluster_state_key_bytes(&config_arc.cluster)
            .ok()
            .flatten()
            .is_some();
        match config_arc
            .mcp
            .configurations
            .sessions
            .synthetic_session_key
            .as_deref()
        {
            Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                Ok(bytes) if bytes.len() == 32 => tracing::info!(
                    "modern stateless: deterministic per-principal synthetic session ids \
                     enabled (sessions.synthetic_session_key)"
                ),
                Ok(bytes) => tracing::warn!(
                    key_bytes = bytes.len(),
                    "mcp.configurations.sessions.synthetic_session_key decoded to {} bytes, \
                     expected 32 — modern synthetic sessions stay per-instance (no \
                     cross-replica continuity)",
                    bytes.len()
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "mcp.configurations.sessions.synthetic_session_key is not valid base64 — \
                     modern synthetic sessions stay per-instance"
                ),
            },
            None if clustered && cluster_derivable => tracing::info!(
                "modern stateless: deterministic per-principal synthetic session ids enabled \
                 via a key derived from cluster.state_encryption_key_env (no separate \
                 sessions.synthetic_session_key needed)"
            ),
            None if clustered => tracing::warn!(
                "a distributed cluster coordinator is configured but neither \
                 `mcp.configurations.sessions.synthetic_session_key` nor \
                 `cluster.state_encryption_key_env` is set — modern (DRAFT-2026-v1) stateless \
                 requests mint a PER-INSTANCE synthetic session on each replica, so the same \
                 principal gets a different session id per replica (task/subscription \
                 continuity AND cross-replica resume break under a round-robin LB). Set an \
                 identical base64 32-byte key on every replica (either field) for deterministic \
                 cross-replica sessions."
            ),
            None => {}
        }
    }

    let shared_services = Arc::new(crate::runtime::shared_services::SharedServices::new(
        Arc::clone(&config_arc),
        &runtime_arc,
        Arc::clone(&request_state_codec),
    ));
    let mut protocol_registry = crate::protocol::registry::ProtocolRegistry::new();
    protocol_registry.register(Arc::new(crate::protocol::v_2025_11_25::Handler::new()));
    protocol_registry.register(Arc::new(crate::protocol::v_2026_07_28::Handler::new()));
    let protocol_registry = Arc::new(protocol_registry);
    runtime_arc
        .load()
        .set_protocol_registry(Arc::clone(&protocol_registry));
    runtime_arc
        .load()
        .set_shared_services(Arc::clone(&shared_services));

    let base_config_arc = Arc::clone(&config_arc);
    let state = AppState {
        config: Arc::new(ArcSwap::new(config_arc)),
        base_config: Arc::new(ArcSwap::new(base_config_arc)),
        registry_overlay: Arc::new(ArcSwap::from_pointee(
            crate::runtime::registry_sync::RegistryOverlay::default(),
        )),
        runtime: runtime_arc,
        session_store,
        observability: Arc::new(observability),
        config_sources,
        sse_stream_counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        config_overlay: Arc::new(ArcSwap::from_pointee(config_overlay_outcome.merged)),
        policy_chain: Arc::new(ArcSwap::from_pointee(policy_chain)),
        plugin_health_prober: Arc::new(tokio::sync::Mutex::new(health_prober_handle)),
        secret_watcher: Arc::new(tokio::sync::Mutex::new(secret_watcher_set)),
        #[cfg(feature = "governance-quotas")]
        quota_gate: Arc::new(ArcSwap::from_pointee(quota_gate)),
    };

    // Bind the live state to the CP-attach hook so a pushed ConfigUpdate can
    // hot-reload this gateway in place, and so log capture ships to the agent.
    // The handle then drops at scope end (the agent task is detached and
    // retains its own clones of the shared cells).
    if let Some(handle) = &cp_attach {
        handle.bind_state(state.clone());
    }
    let _ = cp_attach;

    Ok(state)
}
