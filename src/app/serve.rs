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

    let reaper =
        crate::runtime::pipeline_reaper::PipelineReaper::new(std::time::Duration::from_secs(30));
    let reaper_handle = reaper.spawn(
        state.runtime.load().pipeline_store(),
        state.runtime.load().task_store(),
        reaper_leadership.clone(),
    );

    let task_reaper = crate::runtime::task_reaper::TaskReaper::new(
        std::time::Duration::from_millis(config.mcp.capabilities.tasks.reaper_interval_ms),
    );
    let task_reaper_handle =
        task_reaper.spawn(state.runtime.load().task_store(), reaper_leadership);

    // Session end cleanup. The session store tells of every session that
    // ends without a terminate call — idle on every replica, or ended by
    // another replica — and the drain runs the runtime's per-session cleanup
    // (tenant quota, subscriptions, progress, task cancellation) that
    // explicit terminate runs itself — without which such a session leaks
    // that state forever (and its tenant-quota slot). The
    // store is preserved across config reloads, so a single registration
    // suffices; the drain always cleans up on the CURRENT runtime.
    {
        let (end_tx, mut end_rx) = tokio::sync::mpsc::unbounded_channel();
        state.runtime.load().install_session_end_notifier(end_tx);
        let runtime_holder = std::sync::Arc::downgrade(&state.runtime);
        tokio::spawn(async move {
            while let Some(ended) = end_rx.recv().await {
                let Some(holder) = runtime_holder.upgrade() else {
                    break;
                };
                holder.load().on_session_end(&ended);
            }
        });
    }

    // Periodic coordinator-health probe → `mcpg_cluster_backend_up`
    // gauge + the readiness gate. Only for a clustered coordinator that
    // exposes a KV accessor (single_node is in-process; a coordinator
    // advertising no `kv` role has no KV to ping — the gate stays a no-op
    // there, with a WARN if the operator nonetheless set a gate).
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
                // Warn only on an explicitly configured non-off gate: the
                // kind-dependent `degrade` default on a KV-less coordinator
                // is not an operator mistake (the gate simply never probes,
                // so the readiness body stays silent).
                if config
                    .cluster
                    .readiness_gate
                    .is_some_and(|g| !matches!(g, crate::config::ClusterReadinessGate::Off))
                {
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

    // The cancellation subscriber and the listener for the ends of sessions;
    // a config reload moves them to the runtime it installs.
    state.runtime.load_full().start_cluster_listeners();

    // Registry auto-federation: crawls `mcp.registries` and composes the
    // synthesized federations through the reload pipeline. Reads the
    // live config each tick, so reloads need no respawn; no-op when no
    // registries are configured.
    crate::runtime::registry_sync::RegistrySyncer::spawn(state.clone());

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

    // Bind the MCP and admin listeners before any transport starts: a port
    // in use, a denied bind or a TLS config that does not load refuses boot
    // here, before a plugin transport opens an ingress and before anything
    // can answer `/ready`.
    let tunnel_cfg = config.gateway.server.tunnel.clone().filter(|t| t.enabled);
    let http_listener = match (&tunnel_cfg, &config.gateway.server.transport) {
        (None, TransportMode::Http) => Some(
            http::HttpListener::bind(&config)
                .await
                .map_err(|e| listener_failed("mcp", &config.gateway.server.bind_address, e))?,
        ),
        _ => None,
    };
    let admin_listener = if config.gateway.admin.enabled {
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
        let admin_addr = config.gateway.admin.bind_address.as_str();
        let bound = match admin_addr.parse::<std::net::SocketAddr>() {
            Ok(addr) => tokio::net::TcpListener::bind(addr)
                .await
                .map_err(anyhow::Error::from),
            Err(e) => Err(anyhow::anyhow!("invalid gateway.admin.bind_address: {e}")),
        };
        Some(bound.map_err(|e| listener_failed("admin", admin_addr, e))?)
    } else {
        None
    };

    // Start every plugin-supplied transport declared in
    // `gateway.server.transports[]` BEFORE the primary HTTP / stdio
    // listener serves. Each entry's `kind:` resolves via
    // `resolve_kind(SlotClass::Transport, ...)` (short alias or full plugin
    // id), and the transport hands whole requests to the gateway's own
    // router, which reads the live runtime, so reloads reach extra
    // transports without restarting them. Failure to start refuses boot —
    // operators see the bind / config error directly.
    let server = &config.gateway.server;
    let extra_context = if server.transports.is_empty() {
        ExtraTransportContext::default()
    } else {
        ExtraTransportContext {
            http_router: Some(http::router(
                state.clone(),
                &server.health_path,
                &server.mcp_path,
            )),
            public_url: state
                .runtime
                .load()
                .shared_services
                .load_full()
                .map(|services| std::sync::Arc::clone(&services.tunnel_public_url)),
        }
    };
    let extra_transport_handles = start_extra_transports(
        &config.gateway.server.transports,
        &config.plugins,
        &config.cluster.kind,
        &state.runtime.load().plugin_registry_arc(),
        &extra_context,
    )
    .await
    .inspect_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "an extra transport cannot start; the gateway stops");
    })?;

    // Spawn transport
    let admin_shutdown_rx = shutdown_rx.clone();
    // The stdio client owns the session: when it closes stdin, the gateway
    // shuts down as it would on SIGTERM.
    let (stdio_closed_tx, mut stdio_closed) = tokio::sync::oneshot::channel::<()>();
    let mut stdio_mode = false;
    let (transport_handle, transport_address) = if let Some(tunnel_cfg) = tunnel_cfg {
        // Tunnel mode: dial an MCPG-Cloud relay and answer
        // tunnelled MCP traffic through the gateway's own router — no public
        // TCP bind. This replaces the HTTP/stdio listener; a hot config reload
        // is picked up on the next reconnect.
        let state = state.clone();
        let rx = shutdown_rx;
        let address = tunnel_cfg.relay_url.clone();
        let handle =
            tokio::spawn(
                async move { crate::transports::tunnel::run(state, tunnel_cfg, rx).await },
            );
        (handle, address)
    } else if let Some(listener) = http_listener {
        let state = state.clone();
        let rx = shutdown_rx;
        let address = listener.local_addr().map_or_else(
            |_| config.gateway.server.bind_address.clone(),
            |a| a.to_string(),
        );
        let handle = tokio::spawn(async move { http::serve(state, listener, rx).await });
        (handle, address)
    } else {
        let state = state.clone();
        let rx = shutdown_rx;
        stdio_mode = true;
        let handle = tokio::spawn(async move {
            let served = stdio::serve(state, rx).await;
            let _ = stdio_closed_tx.send(());
            served
        });
        (handle, "stdio".to_owned())
    };
    let mut mcp_task = ListenerTask {
        name: "mcp",
        address: transport_address,
        task: Some(transport_handle),
        watched: !stdio_mode,
    };

    // Serve the admin API on its own listener.
    let admin_handle = admin_listener.map(|listener| {
        let admin_service = crate::admin::AdminService::new(
            state.session_store.clone(),
            state.runtime.clone(),
            config.gateway.admin.clone(),
            config.governance.audit.on_failure,
            state.clone(),
        );
        let admin_router = crate::admin::admin_router(admin_service);
        let admin_shutdown = admin_shutdown_rx;
        info!(bind = %config.gateway.admin.bind_address, "starting admin API");
        tokio::spawn(async move {
            axum::serve(listener, admin_router)
                .with_graceful_shutdown(async move {
                    let mut rx = admin_shutdown;
                    let _ = rx.changed().await;
                })
                .await
                .context("admin server error")
        })
    });
    let mut admin_task = ListenerTask {
        name: "admin",
        address: config.gateway.admin.bind_address.clone(),
        task: admin_handle,
        watched: true,
    };

    // Spawn the file-watch reload trigger (third reload
    // path alongside SIGHUP and POST /admin/v1/config:reload). No-op
    // when `gateway.config_watch.enabled = false` (default) or when
    // the gateway booted without on-disk config files.
    let config_watch_handle = config_watch::spawn(state.clone());

    // Spawn the secrets-directory reload trigger. No-op when
    // `gateway.secrets.dir` is unset or `gateway.secrets.watch = false`;
    // independent of the config file-watch above.
    let secrets_watch_handle = secrets_watch::spawn(state.clone());

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

    // A listener that stops before a shutdown signal stops the gateway: the
    // normal shutdown runs, then `run` returns this error.
    let mut listener_fault: Option<anyhow::Error> = None;

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
                _ = &mut stdio_closed, if stdio_mode => {
                    info!("stdio client closed stdin");
                    break;
                }
                fault = first_listener_end(&mut mcp_task, &mut admin_task) => {
                    listener_fault = Some(fault);
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
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("received SIGINT"),
            _ = &mut stdio_closed, if stdio_mode => info!("stdio client closed stdin"),
            fault = first_listener_end(&mut mcp_task, &mut admin_task) => {
                listener_fault = Some(fault);
            }
        }
    }

    info!(
        timeout_secs = shutdown_timeout.as_secs(),
        "initiating graceful shutdown"
    );

    // Ship the CP agent's buffered tool-call samples before anything else
    // stops. They are billable, and the transport has already stopped
    // accepting new work, so this is the last moment they can be sent.
    crate::runtime::cp::attach::shutdown_agent(shutdown_timeout).await;

    // Signal all subsystems to stop
    let _ = shutdown_tx.send(());

    // Wait for transport to drain (with timeout); a transport that already
    // ended has nothing to drain.
    if let Some(transport_handle) = mcp_task.task.take() {
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
    state.runtime.load_full().stop_cluster_listeners().await;
    info!("cancellation subscriber and session end listener stopped");

    // Release the events owner lease and the dispatcher shards while the
    // cluster coordinator plugin still runs, so another replica takes them
    // at once rather than when they expire.
    if let Some(events) = state.runtime.load().events_core() {
        match tokio::time::timeout(shutdown_timeout, events.stop()).await {
            Ok(()) => info!("events leases released"),
            Err(_) => warn!(
                timeout_secs = shutdown_timeout.as_secs(),
                "events lease release exceeded shutdown timeout"
            ),
        }
    }

    // Stop the resource watchers. Each is a spawned task holding a poll timer
    // or an upstream subscription; nothing else ends them, so without this
    // they keep running through the drain window. Before the plugins drain,
    // so the coordinator can still release the watch shards.
    match tokio::time::timeout(
        shutdown_timeout,
        state.runtime.load().subscriptions().shutdown(),
    )
    .await
    {
        Ok(()) => info!("resource watchers stopped"),
        Err(_) => warn!(
            timeout_secs = shutdown_timeout.as_secs(),
            "resource watcher stop exceeded shutdown timeout"
        ),
    }

    // Deliver the metrics of the last interval while the metrics sinks run.
    if tokio::time::timeout(shutdown_timeout, state.observability.close_metrics())
        .await
        .is_err()
    {
        warn!(
            timeout_secs = shutdown_timeout.as_secs(),
            "final metrics flush exceeded shutdown timeout"
        );
    }

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

    // Cancel the admin listener (drains after MCP so operators can observe drain)
    if let Some(handle) = admin_task.task.take() {
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

    // Same contract as the config watcher: abort is safe because the
    // task holds no runtime state across await points beyond the reload
    // itself, and the listeners are already torn down.
    if let Some(handle) = secrets_watch_handle {
        handle.abort();
        info!("secrets-watch task stopped");
    }

    info!("shutdown complete");
    match listener_fault {
        Some(fault) => Err(fault),
        None => Ok(()),
    }
}

/// Log a listener that cannot serve at ERROR, with its address and the
/// cause, and return the error that stops the gateway.
fn listener_failed(listener: &str, address: &str, cause: anyhow::Error) -> anyhow::Error {
    tracing::error!(
        listener,
        address,
        error = %format!("{cause:#}"),
        "listener cannot serve; the gateway stops"
    );
    cause.context(format!("the {listener} listener on {address} cannot serve"))
}

/// A listener task the gateway serves through. Its end before a shutdown
/// signal means nothing serves on its address any more.
struct ListenerTask {
    name: &'static str,
    address: String,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    /// Whether an end before shutdown is a fault. The stdio transport ends
    /// when its client closes stdin, which is a normal shutdown.
    watched: bool,
}

impl ListenerTask {
    /// Resolves when the watched task ends, with the error that stops the
    /// gateway. Pending forever for an unwatched task or one already
    /// ended, so a select loop can poll it on every turn.
    async fn ended(&mut self) -> anyhow::Error {
        if !self.watched {
            return std::future::pending().await;
        }
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let outcome = task.await;
        self.task = None;
        let cause = match outcome {
            Ok(Ok(())) => anyhow::anyhow!("the listener task ended"),
            Ok(Err(e)) => e,
            Err(e) => anyhow::anyhow!("the listener task failed: {e}"),
        };
        listener_failed(self.name, &self.address, cause)
    }
}

/// The first of the MCP and admin listener tasks to end.
async fn first_listener_end(mcp: &mut ListenerTask, admin: &mut ListenerTask) -> anyhow::Error {
    tokio::select! {
        fault = mcp.ended() => fault,
        fault = admin.ended() => fault,
    }
}

/// What transport plugins need from the gateway.
#[derive(Default)]
pub(crate) struct ExtraTransportContext {
    /// The router that answers the requests a transport hands in; `None`
    /// refuses every entry. Each entry gets its own server, which records
    /// the peers that entry attests under its plugin id.
    pub http_router: Option<axum::Router>,
    /// Receives the first transport's public URL (the base for webhook
    /// callbacks) while no other public address is known.
    pub public_url: Option<std::sync::Arc<arc_swap::ArcSwapOption<String>>>,
}

/// Start every plugin-supplied transport declared in
/// `gateway.server.transports[]`. Each entry's `kind:` resolves
/// to a registered Transport plugin via the registry, whose
/// `start_http(listener_config, server)` opens its ingress and hands
/// each request to the gateway router.
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
/// - no gateway router in `context`;
/// - any start failure (bind, invalid config, etc.).
pub(crate) async fn start_extra_transports(
    transports_cfg: &[crate::config::wiring::KindRef],
    plugins: &[crate::config::PluginEntryConfig],
    cluster_kind: &str,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
    context: &ExtraTransportContext,
) -> Result<Vec<Box<dyn mcpg_plugin_protocol::transport::TransportHandle>>> {
    if transports_cfg.is_empty() {
        return Ok(Vec::new());
    }
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
                     transport plugin id (e.g. `kind: dev.mcpg.transport.ngrok`)."
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
        let Some(router) = &context.http_router else {
            anyhow::bail!(
                "gateway.server.transports[]: plugin `{plugin_id}` hands the \
                 gateway HTTP requests, but no gateway router is available"
            );
        };
        let server =
            crate::transports::ingress::GatewayHttpIngress::new(router.clone(), plugin_id.clone());
        let handle = transport
            .start_http(&kref.config, server)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "gateway.server.transports[]: plugin `{plugin_id}` failed \
                     to start: {e}"
                )
            })?;
        let listen = handle.listen_address().await.unwrap_or_default();
        if (listen.starts_with("https://") || listen.starts_with("http://"))
            && let Some(slot) = &context.public_url
            && slot.load().is_none()
        {
            slot.store(Some(std::sync::Arc::new(listen.clone())));
        }
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
