use super::*;

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config.load();
    let shutdown_timeout =
        std::time::Duration::from_millis(config.gateway.server.shutdown_timeout_ms);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // The first audit event every gateway emits.
    // Fires after the runtime is up + every plugin registered, so
    // the event actually reaches the sinks (audit emits from
    // before registration would be dropped on the floor). Embeds
    // service identity + loaded-plugin count so auditors can
    // correlate boots against configuration changes.
    //
    // Honour operator `on_failure` policy: if
    // `fail_closed` and any sink fails, halt startup — a gateway
    // that can't audit its own boot cannot serve traffic under
    // SOC2-clean semantics.
    {
        let rt = state.runtime.load();
        let registry = rt.plugin_registry();
        let event = mcpg_plugin_host::audit_events::lifecycle_event(
            "mcpg.lifecycle.gateway_started",
            mcpg_plugin_protocol::audit::AuditOutcome::Success,
            serde_json::json!({
                "service": rt.service_name,
                "version": rt.service_version,
                "plugin_count": registry.total_count(),
                "audit_required": config.governance.audit.required,
                "audit_on_failure": config.governance.audit.on_failure,
            }),
        );
        let policy = match config.governance.audit.on_failure {
            crate::config::AuditOnFailure::FailClosed => {
                mcpg_plugin_host::AuditEmitPolicy::FailClosed
            }
            crate::config::AuditOnFailure::FailOpen => mcpg_plugin_host::AuditEmitPolicy::FailOpen,
        };
        if let Err(failure) = registry.emit_audit_event_enforced(&event, policy).await {
            anyhow::bail!(
                "audit `on_failure: fail_closed` tripped at gateway \
                 start — refusing to serve traffic without a durable \
                 audit trail: {failure}"
            );
        }

        // Anchor every downstream audit event to a hash of the config
        // snapshot that was running at the time. Always
        // emitted, even when no flags are flipped, so auditors get
        // a deterministic provenance row per boot. Best-effort emit;
        // the `gateway_started` event above already enforced the
        // `fail_closed` audit policy if the operator wants it.
        let config_sha = config.canonical_sha256();
        let source_paths: Vec<String> = state
            .config_sources
            .iter()
            .map(crate::config::ConfigSource::origin_label)
            .collect();
        let loaded_event =
            mcpg_plugin_host::audit_events::config_loaded_event(&config_sha, &source_paths);
        let _ = registry.emit_audit_event(&loaded_event).await;

        // Record any non-default `feature_flags:` flags. Only emit
        // when at least one strictness gate is overridden so the
        // ledger stays quiet for the common case. Best-effort emit;
        // a `fail_closed` audit policy is already enforced via the
        // gateway_started event above.
        if config.feature_flags.any_active() {
            let features_event = mcpg_plugin_host::audit_events::config_feature_flags_active_event(
                config.feature_flags.audit_details(),
            );
            let _ = registry.emit_audit_event(&features_event).await;
        }

        // Surface every `${env.X}` and `<scheme>://...`
        // reference the loaded config carries. Auditors get an
        // explicit "what credentials this gateway will read at
        // runtime" record. Only emits when at least one ref exists
        // (default config produces an empty list and skips the
        // event).
        let secret_refs = crate::config::secret_scan::scan_app_config(&config);
        if !secret_refs.is_empty() {
            let refs_json =
                serde_json::to_value(&secret_refs).unwrap_or_else(|_| serde_json::json!([]));
            let secrets_event =
                mcpg_plugin_host::audit_events::config_secrets_resolved_event(refs_json);
            let _ = registry.emit_audit_event(&secrets_event).await;
        }
    }

    // Spawn the pipeline + task reaper background tasks. Gate them behind
    // cluster leader-election when a real (non-single_node) coordinator is
    // bound, so exactly one replica sweeps the shared KV. single_node
    // passes `None` and reaps unconditionally — single-instance unchanged.
    let reaper_leadership = if config.cluster.is_single_node() {
        None
    } else {
        state.runtime.load().plugin_registry().cluster_backend()
    };

    // Terminal-error delivery so the reaper unblocks the caller of an expiring
    // SUSPENDED pipeline (whole-pipeline or per-step elicitation timeout)
    // instead of deleting its state silently.
    let reaper_runtime = state.runtime.load_full();
    let terminal_error_delivery: crate::runtime::pipeline_reaper::TerminalErrorDelivery =
        std::sync::Arc::new(move |session_id, jsonrpc_id, code, message| {
            let rt = reaper_runtime.clone();
            Box::pin(async move {
                rt.deliver_pipeline_terminal_error(&session_id, &jsonrpc_id, code, message)
                    .await;
            })
        });
    let reaper =
        crate::runtime::pipeline_reaper::PipelineReaper::new(std::time::Duration::from_secs(30))
            .with_terminal_error_delivery(terminal_error_delivery);
    let reaper_handle = reaper.spawn(
        state.runtime.load().pipeline_store(),
        reaper_leadership.clone(),
    );

    let task_reaper = crate::runtime::task_reaper::TaskReaper::new(
        std::time::Duration::from_millis(config.mcp.capabilities.tasks.reaper_interval_ms),
    );
    let task_reaper_handle =
        task_reaper.spawn(state.runtime.load().task_store(), reaper_leadership);

    // Session idle-eviction cascade. The session store forwards every
    // idle-evicted session id here; the drain runs the runtime's per-session
    // cleanup cascade (tenant quota, subscriptions, progress, request-id
    // tracker, task cancellation) that explicit terminate does but idle
    // eviction otherwise skips — without which an idle-expired session leaks
    // that state forever (and its tenant-quota slot). The store is preserved
    // across config reloads, so a single registration suffices; the drain
    // always cascades on the CURRENT runtime.
    {
        let (evict_tx, mut evict_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        state
            .runtime
            .load()
            .install_session_eviction_notifier(evict_tx);
        let runtime_holder = std::sync::Arc::downgrade(&state.runtime);
        tokio::spawn(async move {
            while let Some(session_id) = evict_rx.recv().await {
                let Some(holder) = runtime_holder.upgrade() else {
                    break;
                };
                holder.load().on_session_evicted(&session_id);
            }
        });
    }

    // Periodic coordinator-health probe → `mcpg_cluster_backend_up`
    // gauge + the readiness gate. Only for a clustered coordinator that
    // exposes a KV accessor (single_node is in-process; consul/etcd are
    // coordination-only with no KV to ping — the gate stays a no-op there,
    // with a WARN if the operator nonetheless set a gate).
    let cluster_health_handle = if config.cluster.is_single_node() {
        None
    } else {
        let backend = state.runtime.load().plugin_registry().cluster_backend();
        match backend.as_ref().and_then(|b| b.key_value_store()) {
            Some(kv) => Some(crate::runtime::GatewayRuntime::spawn_cluster_health_probe(
                kv,
                std::time::Duration::from_secs(10),
            )),
            None => {
                if !matches!(
                    config.cluster.readiness_gate,
                    crate::config::ClusterReadinessGate::Off
                ) {
                    tracing::warn!(
                        "cluster.readiness_gate is set but the '{}' coordinator exposes no KV \
                         accessor — coordinator health cannot be probed, so the readiness gate \
                         is inert for this kind",
                        config.cluster.kind
                    );
                }
                None
            }
        }
    };

    let cancellation_subscriber_handle = state.runtime.load_full().spawn_cancellation_subscriber();

    // Registry auto-federation: crawls `mcp.registries` and composes the
    // synthesized federations through the reload pipeline. Reads the
    // live config each tick, so reloads need no respawn; no-op when no
    // registries are configured.
    crate::runtime::registry_sync::RegistrySyncer::spawn(state.clone());

    let ping_driver_handle = match config.gateway.server.server_ping_interval_ms {
        Some(secs) if secs > 0 => {
            let driver = crate::runtime::ping_driver::ServerPingDriver::new(secs);
            Some(driver.spawn(
                state.session_store.clone(),
                state.runtime.load().delivery_bus().clone(),
                shutdown_rx.clone(),
            ))
        }
        _ => None,
    };

    // Spawn per-binding health prober (if enabled)
    let health_prober_handle = if config.gateway.server.health_check.enabled {
        let prober = crate::runtime::backend_health::BackendHealthProber::new(
            config.gateway.server.health_check.clone(),
            config.all_bindings().map(|(_, b)| b.clone()).collect(),
            state.runtime.load().backend_health().clone(),
            Some(state.runtime.load().plugin_registry_arc()),
        );
        Some(prober.spawn())
    } else {
        None
    };

    // Start every plugin-supplied transport declared in
    // `gateway.server.transports[]` BEFORE the
    // primary HTTP / stdio listener. Each entry's `kind:`
    // resolves via `resolve_kind(SlotClass::Transport, ...)`
    // (built-in keyword, short alias, or full plugin id);
    // the resolved transport gets a `GatewayMessageDispatcher`
    // wired to the same `state.runtime` ArcSwap the primary
    // listener uses, so reloads propagate to extra transports
    // without restarting them. Failure to start refuses boot
    // — operators see the bind / config error directly.
    let extra_transport_handles = start_extra_transports(
        &config.gateway.server.transports,
        &config.plugins,
        &config.cluster.kind,
        state.runtime.clone(),
        &state.runtime.load().plugin_registry_arc(),
    )
    .await?;

    // Spawn transport
    let admin_shutdown_rx = shutdown_rx.clone();
    let transport_handle =
        if let Some(tunnel_cfg) = config.gateway.server.tunnel.clone().filter(|t| t.enabled) {
            // Tunnel mode: dial an MCPG-Cloud relay and answer
            // tunnelled MCP traffic through the gateway's own router — no public
            // TCP bind. This replaces the HTTP/stdio listener; a hot config reload
            // is picked up on the next reconnect.
            let state = state.clone();
            let rx = shutdown_rx;
            tokio::spawn(async move { crate::transports::tunnel::run(state, tunnel_cfg, rx).await })
        } else {
            match config.gateway.server.transport {
                TransportMode::Http => {
                    let state = state.clone();
                    let rx = shutdown_rx;
                    tokio::spawn(async move { http::serve(state, rx).await })
                }
                TransportMode::Stdio => {
                    let state = state.clone();
                    let rx = shutdown_rx;
                    tokio::spawn(async move { stdio::serve(state, rx).await })
                }
            }
        };

    // Conditionally start admin API on a separate listener
    let admin_handle = if config.gateway.admin.enabled {
        // the admin API is the most privileged surface (terminate
        // sessions, disable/drain plugins, reload config). Refuse to expose
        // it on a public interface without authentication — this dangerous
        // combo (auth.type=disabled or presence-only trusted_header on
        // 0.0.0.0) must not boot silently.
        {
            let bind = config.gateway.admin.bind_address.as_str();
            let public_bind =
                bind.starts_with("0.0.0.0") || bind.starts_with("[::]") || bind.starts_with("::");
            if public_bind && !config.gateway.admin.auth.is_authenticated() {
                metrics::counter!(
                    "mcpg_insecure_public_bind_total",
                    "listener" => "admin",
                )
                .increment(1);
                anyhow::bail!(
                    "admin API is bound to a public interface ({bind}) with no authentication \
                     (admin.auth.type=disabled or presence-only trusted_header). Bind admin to \
                     127.0.0.1, or set admin.auth to static_bearer / trusted_header with \
                     trusted_value_env."
                );
            }
        }
        let admin_service = crate::admin::AdminService::new(
            state.session_store.clone(),
            state.runtime.clone(),
            config.gateway.admin.clone(),
            config.governance.audit.on_failure,
            state.clone(),
        );
        let admin_router = crate::admin::admin_router(admin_service);
        let admin_addr: std::net::SocketAddr = config
            .gateway
            .admin
            .bind_address
            .parse()
            .expect("invalid gateway.admin.bind_address");
        let admin_shutdown = admin_shutdown_rx;
        info!(bind = %admin_addr, "starting admin API");
        Some(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(admin_addr)
                .await
                .expect("failed to bind admin listener");
            axum::serve(listener, admin_router)
                .with_graceful_shutdown(async move {
                    let mut rx = admin_shutdown;
                    let _ = rx.changed().await;
                })
                .await
                .expect("admin server error");
        }))
    } else {
        None
    };

    // Spawn the file-watch reload trigger (third reload
    // path alongside SIGHUP and POST /admin/v1/config:reload). No-op
    // when `gateway.config_watch.enabled = false` (default) or when
    // the gateway booted without on-disk config files.
    let config_watch_handle = config_watch::spawn(state.clone());

    // Anonymous adoption ping. Fully gated and fail-open: it logs
    // its on/off decision, and only when enabled spawns a detached task that
    // never blocks boot or reacts to the endpoint. Snapshots the config and
    // the loaded-plugin set by value so the background task never touches the
    // live registry.
    crate::usage_reporting::spawn(
        state.config.load_full(),
        env!("CARGO_PKG_VERSION"),
        state.runtime.load().plugin_registry_arc().loaded_plugins(),
    );

    // Wait for termination signal (loop to handle SIGHUP reloads)
    #[cfg(unix)]
    {
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("failed to install SIGHUP handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("received SIGINT");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                    break;
                }
                _ = sighup.recv() => {
                    info!("received SIGHUP — reloading config");
                    let prev_sha = state.config.load().canonical_sha256();
                    let outcome = reload_config(&state).await;
                    let (success, err_msg) = match &outcome {
                        Ok(()) => {
                            info!("config reload successful");
                            (true, None)
                        }
                        Err(e) => {
                            warn!("config reload failed: {e} — keeping current config");
                            (false, Some(e.to_string()))
                        }
                    };
                    metrics::counter!("mcpg_config_reloads_total").increment(1);
                    // Config-reload bookend on the audit lane. The
                    // SIGHUP source label distinguishes operator-driven
                    // reload from CP-driven (today CP pull also lands
                    // here; a future CP-attach pull can pass a different
                    // source).
                    //
                    // Also carry prev/next config SHAs so auditors can
                    // correlate this reload back to the exact YAML
                    // source-of-truth on either side.
                    let next_sha_owned: Option<String> = if success {
                        Some(state.config.load().canonical_sha256())
                    } else {
                        None
                    };
                    let registry = state.runtime.load().plugin_registry_arc();
                    let event =
                        mcpg_plugin_host::audit_events::config_reloaded_event(
                            "sighup",
                            success,
                            err_msg.as_deref(),
                            Some(prev_sha.as_str()),
                            next_sha_owned.as_deref(),
                        );
                    let _ = registry.emit_audit_event(&event).await;
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
        info!("received SIGINT");
    }

    info!(
        timeout_secs = shutdown_timeout.as_secs(),
        "initiating graceful shutdown"
    );

    // Publish a goodbye notification so clients can reconnect cleanly.
    {
        let runtime = state.runtime.load();
        let delivery = runtime.delivery_bus().clone();
        let sessions = state.session_store.list_sessions();
        let goodbye = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/mcpg/server_draining",
            "params": {
                "reason": "server shutting down; stream will close",
                "retry_hint_ms": 3000u64,
            }
        });
        let msg = crate::runtime::pipeline_store::DeliveryMessage {
            kind: crate::runtime::pipeline_store::DeliveryKind::Notification,
            jsonrpc_message: goodbye,
            delivery_id: String::new(),
        };
        for session in sessions {
            let _ = delivery.publish(&session.session_id, msg.clone()).await;
        }
        // brief nudge so the goodbye flushes before we yank the transport.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Ship the CP agent's buffered tool-call samples before anything else
    // stops. They are billable, and the transport has already stopped
    // accepting new work, so this is the last moment they can be sent.
    crate::runtime::cp::attach::shutdown_agent(shutdown_timeout).await;

    // Signal all subsystems to stop
    let _ = shutdown_tx.send(());

    // Wait for transport to drain (with timeout)
    let drain_result = tokio::time::timeout(shutdown_timeout, transport_handle).await;
    match drain_result {
        Ok(Ok(Ok(()))) => info!("transport drained cleanly"),
        Ok(Ok(Err(e))) => warn!("transport error during shutdown: {}", e),
        Ok(Err(e)) => warn!("transport task panicked: {}", e),
        Err(_) => warn!(
            timeout_secs = shutdown_timeout.as_secs(),
            "shutdown timeout exceeded, forcing exit"
        ),
    }

    // Close every plugin-supplied extra transport started from
    // `gateway.server.transports[]`. Each handle's
    // `close()` is bounded by the same shutdown budget; a transport
    // that exceeds the budget is logged and abandoned rather than
    // blocking teardown.
    if !extra_transport_handles.is_empty() {
        let count = extra_transport_handles.len();
        for handle in extra_transport_handles {
            if tokio::time::timeout(shutdown_timeout, handle.close())
                .await
                .is_err()
            {
                warn!(
                    timeout_secs = shutdown_timeout.as_secs(),
                    "extra transport close exceeded shutdown timeout"
                );
            }
        }
        info!(count, "extra transports closed");
    }

    // Cancel the pipeline reaper
    reaper_handle.abort();
    info!("pipeline reaper stopped");
    task_reaper_handle.abort();
    info!("task reaper stopped");
    if let Some(handle) = cluster_health_handle {
        handle.abort();
        info!("cluster health probe stopped");
    }
    cancellation_subscriber_handle.abort();
    info!("cancellation subscriber stopped");

    // Drain plugin-owned background state (audit sinks, webhook buffers).
    // Each plugin gets a bounded budget so a misbehaving shutdown hook
    // cannot stall gateway teardown.
    let shutdown_report = state.runtime.load().plugin_registry().shutdown_all().await;
    if !shutdown_report.is_clean() {
        warn!(
            abandoned = ?shutdown_report.timed_out,
            "some plugins exceeded shutdown budget and were abandoned"
        );
    }
    info!(
        clean = shutdown_report.clean,
        abandoned = shutdown_report.timed_out.len(),
        "plugin shutdown complete"
    );

    // Stop the resource watchers. Each is a spawned task holding a poll timer
    // or an upstream subscription; nothing else ends them, so without this
    // they keep running through the drain window.
    state.runtime.load().subscriptions().shutdown().await;
    info!("resource watchers stopped");

    // Drain the built content-store profile instances. These live
    // in the runtime's ContentStoreRegistry (built via
    // ContentStorePlugin::build_profile), NOT in the plugin-host registry
    // that `shutdown_all` above drained — so without this a stateful store
    // (e.g. S3 multipart buffers) never gets its final flush on shutdown.
    if let Some(content_stores) = state.runtime.load().content_stores() {
        content_stores
            .shutdown(std::time::Duration::from_secs(5))
            .await;
        info!("content stores drained");
    }

    // Cancel the health prober
    if let Some(handle) = health_prober_handle {
        handle.abort();
        info!("binding health prober stopped");
    }

    if let Some(handle) = ping_driver_handle {
        handle.abort();
        info!("server ping driver stopped");
    }

    // Cancel the admin listener (drains after MCP so operators can observe drain)
    if let Some(handle) = admin_handle {
        handle.abort();
        info!("admin API stopped");
    }

    // Stop the file-watch reloader. Abort is safe — the watcher
    // never holds runtime state across `await` points beyond the
    // reload itself, and `reload_config` is idempotent against the
    // shutdown path (the next config swap can't race with the
    // shutdown signal because admin handle + transport are already
    // torn down above).
    if let Some(handle) = config_watch_handle {
        handle.abort();
        info!("config-watch task stopped");
    }

    // Flush metrics — `shutdown_all` above drains every plugin
    // (including `MetricsSink` instances) with the per-plugin
    // budget. No gateway-side recorder handle remains to flush.

    info!("shutdown complete");
    Ok(())
}

/// Start every plugin-supplied transport declared in
/// `gateway.server.transports[]`. Each entry's `kind:` resolves
/// to a registered Transport plugin via the registry; the plugin's
/// `start(listener_config, dispatcher)` runs to bind a listener.
/// Returns the collected `TransportHandle` vec — the caller stores
/// it for the duration of the gateway run; closing each handle on
/// shutdown is wired into the same drain path that handles the
/// primary HTTP / stdio listener.
///
/// Refuses boot on:
/// - kind that resolves to a built-in keyword (`builtin-http` /
///   `builtin-stdio` are the gateway's primary listener, governed
///   by `transport:`, not by this list);
/// - kind that resolves to `cluster` (transport is not a cluster
///   role);
/// - plugin id that isn't loaded;
/// - any `start()` failure (bind, invalid config, etc.).
pub(crate) async fn start_extra_transports(
    transports_cfg: &[crate::config::wiring::KindRef],
    plugins: &[crate::config::PluginEntryConfig],
    cluster_kind: &str,
    runtime_swap: std::sync::Arc<arc_swap::ArcSwap<crate::runtime::GatewayRuntime>>,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
) -> Result<Vec<Box<dyn mcpg_plugin_protocol::transport::TransportHandle>>> {
    if transports_cfg.is_empty() {
        return Ok(Vec::new());
    }
    let dispatcher: std::sync::Arc<dyn mcpg_plugin_protocol::transport::MessageDispatcher> =
        std::sync::Arc::new(
            crate::runtime::message_dispatcher::GatewayMessageDispatcher::new(runtime_swap),
        );
    let mut handles: Vec<Box<dyn mcpg_plugin_protocol::transport::TransportHandle>> =
        Vec::with_capacity(transports_cfg.len());
    for kref in transports_cfg {
        let resolved = crate::config::wiring::resolve_kind(
            crate::config::wiring::SlotClass::Transport,
            kref,
            plugins,
            cluster_kind,
        )
        .with_context(|| {
            format!(
                "gateway.server.transports[] entry `kind: {}` failed to resolve",
                kref.kind
            )
        })?;
        let plugin_id = match resolved {
            crate::config::wiring::ResolvedKind::Plugin(id) => id,
            crate::config::wiring::ResolvedKind::Builtin(name) => {
                anyhow::bail!(
                    "gateway.server.transports[]: built-in keyword `{name}` is \
                     governed by the primary `transport:` field, not by this \
                     list. Either remove the entry or replace it with a \
                     plugin id (e.g. `kind: dev.mcpg.builtin.transport.memory` \
                     to start the in-process memory transport)."
                );
            }
            crate::config::wiring::ResolvedKind::Cluster => {
                anyhow::bail!(
                    "gateway.server.transports[]: `kind: cluster` is not a \
                     valid transport source — transport is not a cluster role"
                );
            }
        };
        let transport = plugin_registry.transport_by_id(&plugin_id).ok_or_else(|| {
            anyhow::anyhow!(
                "gateway.server.transports[]: plugin `{plugin_id}` \
                     (resolved from `kind: {}`) is not registered. Either \
                     load the plugin via plugins[] or remove the entry.",
                kref.kind
            )
        })?;
        let handle = transport
            .start(&kref.config, std::sync::Arc::clone(&dispatcher))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "gateway.server.transports[]: plugin `{plugin_id}` failed \
                     to start: {e}"
                )
            })?;
        let listen = handle.listen_address().await.unwrap_or_default();
        info!(
            kind = %kref.kind,
            plugin_id = %plugin_id,
            listen = %listen,
            "extra transport started"
        );
        handles.push(handle);
    }
    Ok(handles)
}
