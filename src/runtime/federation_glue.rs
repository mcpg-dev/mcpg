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
        cluster_tenant_segment: Option<String>,
    ) {
        // Boot: no prior engine to carry satellites from.
        self.install_federation_engine(
            federations,
            gateway_via,
            true,
            None,
            cluster_tenant_segment,
        );
    }

    /// Re-wire federation on config reload. Seeds the
    /// freshly-built capability + policy overlays from the previous
    /// runtime so federated tools — and their governance — don't flicker
    /// while a re-import runs, and carries forward the prior engine's live
    /// upstream sessions for unchanged federations (changed/removed ones
    /// re-establish lazily). When the federation config is unchanged, skips
    /// the re-import entirely: the seeded capabilities stand and no upstream
    /// is reconnected. A reload that removed all federations leaves the
    /// fresh, empty overlays untouched.
    pub(crate) fn rewire_federations(
        &self,
        federations: Vec<crate::config::FederationConfig>,
        gateway_via: String,
        prior_capabilities: Arc<crate::backends::FederatedCatalog>,
        prior_policies: Arc<policy::FederatedToolPolicies>,
        prior_engine: Option<Arc<federation::engine::FederationEngine>>,
        reimport: bool,
        cluster_tenant_segment: Option<String>,
    ) {
        if federations.is_empty() {
            return;
        }
        self.capability_registry
            .federated_overlay()
            .store(prior_capabilities);
        self.pre_dispatch_policy
            .federated_policy_handle()
            .store(prior_policies);
        self.install_federation_engine(
            federations,
            gateway_via,
            reimport,
            prior_engine,
            cluster_tenant_segment,
        );
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
        cluster_tenant_segment: Option<String>,
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
        let engine = Arc::new(
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
            .with_notifier(
                Arc::clone(&self.session_store),
                Arc::clone(&self.delivery_bus),
                Arc::clone(&self.subscription_store),
            )
            .with_server_request_bridge(Arc::new({
                // Coordinator-back the server-request rendezvous so an upstream
                // elicitation/sampling/roots relayed to the client resolves
                // even when the client's answer lands on a different replica
                // than the awaiting one. Single-node / no-coordinator leaves
                // the bridge on its in-process map.
                let bridge =
                    federation::bridge::ServerRequestBridge::new(Arc::clone(&self.delivery_bus));
                match self.plugin_registry.cluster_backend() {
                    Some(coordinator) => {
                        bridge.with_cluster(coordinator, cluster_tenant_segment.clone())
                    }
                    None => bridge,
                }
            }))
            .with_apps_upstream_advertisement(self.apps_federate_upstream)
            .with_tunnel_federation(self.tunnel_federation.clone()),
        );
        // Carry forward upstream sessions for unchanged federations across a
        // config reload; changed/removed ones re-establish.
        if let Some(prior) = &prior_engine {
            engine.adopt_satellites(prior);
            // The seeded overlay only holds until something republishes; the
            // import cache is what republish rebuilds from, so it has to come
            // across too or the first per-federation refresh wipes the rest.
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

    /// Install the SEP-1865 MCP Apps runtime state: the downstream
    /// `initialize` capability advertisement (`Some` ⇒ advertised), the
    /// upstream-advertisement flag (so federated servers emit UI tools),
    /// and the compiled egress policy. Wired from
    /// [`crate::config::apps::AppsConfig`] at boot + reload.
    /// Wire the reverse-federation ingress from `gateway.server.tunnel_federation`
    /// so `tunnel://<name>` federation upstreams resolve through the relay's
    /// federation ingress. Read at boot, before any post-boot env scrub (the
    /// org-token env fallback needs `MCPG_TUNNEL_TOKEN` still present).
    pub fn set_tunnel_federation(&mut self, cfg: Option<&crate::config::TunnelFederationConfig>) {
        self.tunnel_federation = cfg.map(federation::engine::TunnelFederation::from_config);
    }

    /// True when `request_context` may operate on `session_id`. With
    /// owner-binding disabled this is always true (today's
    /// possession-only behaviour). Otherwise the caller's principal must
    /// match the session creator's (an anonymous-owned session is
    /// matched only by an anonymous caller); an unknown/expired session
    /// is treated as not-owned so a caller cannot probe its existence.
    pub(crate) fn caller_owns_session(
        &self,
        session_id: &str,
        request_context: &RequestContext,
    ) -> bool {
        if !self.bind_session_owner {
            return true;
        }
        let owner = match self.session_store.load_session(Some(session_id), false) {
            Ok(snap) => snap.owner_principal,
            Err(_) => return false,
        };
        let caller = request_context.identity.synthetic_principal_key();
        if session_owner_matches(owner.as_deref(), caller.as_deref()) {
            return true;
        }
        metrics::counter!("mcpg_session_owner_mismatch_total").increment(1);
        tracing::warn!(
            session_id = %session_id,
            "session operation denied: caller principal does not own the session"
        );
        false
    }
}
