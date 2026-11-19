use super::*;

impl GatewayRuntime {
    /// Build the in-gateway federation engine from `mcp.federations`,
    /// wire it into the dispatcher, and kick off capability import + the
    /// idle-satellite sweeper. No-op when no federations are configured.
    /// Called at boot and on config reload; a reload carries the prior
    /// engine's satellites and import cache across (see
    /// [`Self::rewire_federations`]).
    pub fn wire_federations(
        &self,
        federations: Vec<crate::config::FederationConfig>,
        gateway_via: String,
    ) {
        // Boot: no prior engine to carry satellites from.
        self.install_federation_engine(federations, gateway_via, true, None);
    }

    /// Re-wire federation on config reload. The new engine adopts the prior
    /// engine's import cache and publishes it under the reloaded config's
    /// governance, so federated tools don't flicker while a re-import runs
    /// and never keep the prior config's floor, scopes or `allow_if`. It
    /// also carries forward the prior engine's live upstream sessions for
    /// unchanged federations (changed/removed ones re-establish lazily).
    /// When the federation config is unchanged, skips the re-import
    /// entirely: the carried capabilities stand and no upstream is
    /// reconnected. A reload that removed all federations leaves the fresh,
    /// empty overlays untouched.
    pub(crate) fn rewire_federations(
        &self,
        federations: Vec<crate::config::FederationConfig>,
        gateway_via: String,
        prior_engine: Option<Arc<federation::engine::FederationEngine>>,
        reimport: bool,
    ) {
        if federations.is_empty() {
            return;
        }
        self.install_federation_engine(federations, gateway_via, reimport, prior_engine);
    }

    /// Build the federation engine, attach it to the dispatcher, and spawn
    /// the idle-satellite sweeper; import capabilities off the boot path
    /// when `import` is set. No-op when no federations.
    pub(crate) fn install_federation_engine(
        &self,
        federations: Vec<crate::config::FederationConfig>,
        gateway_via: String,
        import: bool,
        prior_engine: Option<Arc<federation::engine::FederationEngine>>,
    ) {
        if federations.is_empty() {
            return;
        }
        let sweep_idle = std::time::Duration::from_secs(
            federations
                .iter()
                .map(|f| f.session.idle_timeout_secs)
                .min()
                .unwrap_or(600),
        );
        let engine =
            Arc::new(
                federation::engine::FederationEngine::new(
                    federations,
                    self.capability_registry.federated_overlay(),
                    self.pre_dispatch_policy.federated_policy_handle(),
                    gateway_via,
                )
                .with_credentials(
                    Arc::clone(&self.plugin_registry),
                    Arc::clone(&self.credential_cache),
                )
                .with_idp_sessions(self.ema_authorization_server.clone().map(
                    |server| -> Arc<dyn federation::idp_sessions::IdpSessionSource> { server },
                ))
                .with_notifier(
                    Arc::clone(&self.session_store),
                    Arc::clone(&self.delivery_bus),
                )
                .with_apps_upstream_advertisement(self.apps_federate_upstream)
                .with_tunnel_federation(self.tunnel_federation.clone())
                .with_event_types(Arc::clone(&self.federated_events)),
            );
        // Carry forward upstream sessions for unchanged federations across a
        // config reload; changed/removed ones re-establish.
        if let Some(prior) = &prior_engine {
            engine.adopt_satellites(prior);
            // Every republish rebuilds from the import cache, so it has to
            // come across or the first per-federation refresh wipes the rest.
            engine.adopt_imported(prior);
        }
        self.execution_dispatcher
            .set_federation_engine(Arc::clone(&engine));
        // Persistent listeners forward upstream `*/list_changed` to our
        // clients and refresh the overlay; TTL refreshers poll as a fallback.
        engine.spawn_listeners();
        engine.spawn_refreshers();

        if import {
            let import_engine = Arc::clone(&engine);
            tokio::spawn(async move {
                import_engine.import_all().await;
            });
        }

        // Idle-satellite sweeper. Holds a Weak so it exits when the engine
        // is dropped (e.g. replaced on a later config reload).
        let weak = Arc::downgrade(&engine);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                match weak.upgrade() {
                    Some(engine) => engine.sweep_idle(sweep_idle).await,
                    None => break,
                }
            }
        });
    }

    /// Wire the reverse-federation ingress from `gateway.server.tunnel_federation`
    /// so `tunnel://<name>` federation upstreams resolve through the relay's
    /// federation ingress. Read at boot, before any post-boot env scrub (the
    /// org-token env fallback needs `MCPG_TUNNEL_TOKEN` still present).
    pub fn set_tunnel_federation(&mut self, cfg: Option<&crate::config::TunnelFederationConfig>) {
        self.tunnel_federation = cfg.map(federation::engine::TunnelFederation::from_config);
    }
}
