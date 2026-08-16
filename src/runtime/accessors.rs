use super::*;

impl GatewayRuntime {
    /// Test-only view of the session store for session-row accounting
    /// assertions.
    #[cfg(test)]
    pub(crate) fn session_store(&self) -> &Arc<dyn SessionStore> {
        &self.session_store
    }

    /// Access the delivery bus (used by config hot-reload for list_changed notifications).
    pub(crate) fn delivery_bus(&self) -> &Arc<dyn DeliveryBus> {
        &self.delivery_bus
    }

    /// Install the multi-version protocol registry. Bootstrap calls
    /// this AFTER the runtime is wrapped in `ArcSwap` because the
    /// paired `SharedServices` needs the swap handle to downgrade
    /// into its `Weak` runtime field. After this call,
    /// [`Self::handle_request`]'s Protocol arm dispatches through
    /// `registry.get(negotiated_version).dispatch(...)`; before the
    /// call the runtime falls through to the legacy direct path.
    /// Must be paired with [`Self::set_shared_services`].
    pub(crate) fn set_protocol_registry(&self, registry: Arc<ProtocolRegistry>) {
        self.protocol_registry.store(Some(registry));
    }

    /// Install the [`SharedServices`] bundle that `ProtocolHandler`
    /// implementations consume during dispatch. Paired with
    /// [`Self::set_protocol_registry`].
    pub(crate) fn set_shared_services(&self, services: Arc<SharedServices>) {
        self.shared_services.store(Some(services));
    }

    /// Replace the cancellation bus (used during app bootstrapping to select
    /// NATS or Redis backend based on cluster config).
    pub(crate) fn set_cancellation_bus(&mut self, bus: Arc<dyn cancellation_bus::CancellationBus>) {
        self.cancellation_bus = bus;
    }

    /// The live federation engine, if any — used to carry upstream sessions
    /// across a config reload.
    pub(crate) fn federation_engine(&self) -> Option<Arc<federation::engine::FederationEngine>> {
        self.execution_dispatcher.federation_engine()
    }

    /// Snapshot of the currently-imported federated capabilities (for
    /// carry-across-reload seeding).
    pub(crate) fn federated_capabilities(&self) -> Arc<crate::backends::FederatedCatalog> {
        self.capability_registry.federated_overlay().load_full()
    }

    /// Snapshot of the current federated-tool governance rules (for
    /// carry-across-reload seeding).
    pub(crate) fn federated_policies(&self) -> Arc<policy::FederatedToolPolicies> {
        self.pre_dispatch_policy
            .federated_policy_handle()
            .load_full()
    }

    /// Snapshot of the idempotency advertisement currently
    /// installed, used by the initialize handler and by tests that
    /// want to assert on the negotiated capability shape.
    pub fn idempotency_capability(&self) -> Option<&serde_json::Value> {
        self.idempotency_capability.as_ref()
    }

    /// Install the idempotency record store. The boot path threads
    /// either a `KvBackedIdempotencyStore` (feature on) or a
    /// `NoopIdempotencyStore` (feature off) so the dispatcher can
    /// hold a stable Arc.
    pub fn set_idempotency_store(
        &mut self,
        store: std::sync::Arc<dyn idempotency::IdempotencyStore>,
    ) {
        self.idempotency_store = store;
    }

    /// Read-only handle to the installed store, used by the
    /// dispatcher's pipeline insertion and by tests.
    pub fn idempotency_store(&self) -> &std::sync::Arc<dyn idempotency::IdempotencyStore> {
        &self.idempotency_store
    }

    /// The compiled MCP Apps egress policy, if Apps is enabled.
    pub fn apps_policy(&self) -> Option<&crate::protocol::shared::apps::AppsPolicy> {
        self.apps_policy.as_ref()
    }

    pub fn jwt_verifier(&self) -> Option<&identity::JwtVerifier> {
        self.jwt_verifier.as_ref()
    }

    pub fn ema_authorization_server(
        &self,
    ) -> Option<&crate::runtime::authorization_server::AuthorizationServer> {
        self.ema_authorization_server.as_deref()
    }

    /// Install the embedded EMA authorization server. Called once right
    /// after construction (and after each config-reload rebuild),
    /// before the runtime is shared.
    pub fn set_ema_authorization_server(
        &mut self,
        server: Option<std::sync::Arc<crate::runtime::authorization_server::AuthorizationServer>>,
    ) {
        self.ema_authorization_server = server;
    }

    /// The AAuth resource role, when `server.aauth_resource_metadata` is set.
    pub fn aauth_resource(&self) -> Option<&crate::runtime::aauth_resource::AauthResource> {
        self.aauth_resource.as_deref()
    }

    /// Install the AAuth resource role. Called once right after construction
    /// (and after each config-reload rebuild), before the runtime is shared.
    pub fn set_aauth_resource(
        &mut self,
        resource: Option<std::sync::Arc<crate::runtime::aauth_resource::AauthResource>>,
    ) {
        self.aauth_resource = resource;
    }

    pub fn backend_health(&self) -> &backend_health::BackendHealthMap {
        &self.backend_health
    }

    pub fn oidc_resolver(&self) -> Option<&oidc::OidcOAuthResolver> {
        self.oidc_resolver.as_deref()
    }

    pub fn plugin_registry(&self) -> &mcpg_plugin_host::PluginRegistry {
        &self.plugin_registry
    }

    /// Shared handle to the credential cache. Held here so the
    /// (deferred) credential-resolver call site at request
    /// dispatch time can reach it via `&self`. Today exercised
    /// only by the boot-time mode metric + the future
    /// `resolve_credential_refs` integration in dispatch_tool_call.
    pub fn credential_cache(
        &self,
    ) -> &Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind> {
        &self.credential_cache
    }

    /// Shared handle to the plugin registry for long-lived background
    /// consumers (health prober, future admin endpoints). The runtime
    /// already holds the registry as `Arc<PluginRegistry>`, so a clone
    /// here is cheap.
    pub fn plugin_registry_arc(&self) -> std::sync::Arc<mcpg_plugin_host::PluginRegistry> {
        std::sync::Arc::clone(&self.plugin_registry)
    }

    /// Shared handle to the built-in pre-dispatch policy gate (trust
    /// floor + CEL `allow_if`). The child `invoke_tool` path holds a
    /// clone so it runs the same built-in authz layer a direct
    /// `tools/call` runs.
    pub(crate) fn pre_dispatch_policy_arc(&self) -> Arc<PreDispatchPolicyGate> {
        Arc::clone(&self.pre_dispatch_policy)
    }

    /// Narrow seam for cache consumers. Returns the
    /// cache plugin bound to the given namespace via
    /// `plugins.caches.<namespace>: <plugin_id>`, or `None` if
    /// no operator binding exists. Callers that find `None` fall
    /// back to their own in-process state (typical pattern:
    /// response-cache LRU stays local until an operator opts
    /// into a shared cache by binding the namespace to, say,
    /// `dev.example.cache.redis`).
    ///
    /// Thin passthrough to `registry.cache_for_namespace`; lives
    /// on the runtime so consumer code doesn't have to reach
    /// through `plugin_registry()` + know about entity kinds.
    pub fn cache_for_namespace(
        &self,
        namespace: &str,
    ) -> Option<std::sync::Arc<dyn mcpg_plugin_protocol::cache::Cache>> {
        self.plugin_registry.cache_for_namespace(namespace)
    }

    /// Narrow seam for cluster_backend consumers.
    /// Returns the currently-installed coordinator (or `None` if
    /// none is registered; shouldn't happen at runtime because
    /// the app layer auto-installs the single-node built-in when
    /// no operator binding exists).
    ///
    /// **Intended consumers:** future singleton-role takeovers
    /// (pipeline_reaper / task_reaper / replay_compactor
    /// acquiring leadership before running; delivery_bus
    /// migrating to cluster publish/subscribe for cross-node
    /// notification fan-out). Today's gateway background jobs
    /// run in-process regardless of how many nodes are
    /// deployed — migration happens when an operator drives
    /// multi-node deployment.
    ///
    /// Thin passthrough to `registry.cluster_backend`;
    /// lives on the runtime so consumer code doesn't have to
    /// reach through `plugin_registry()`.
    pub fn cluster_backend(&self) -> Option<std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>> {
        self.plugin_registry.cluster_backend()
    }

    /// Narrow seam for store consumers. Returns the
    /// store plugin bound to the given role via
    /// `plugins.kv.<role>: <plugin_id>`, or `None` if no
    /// operator binding exists.
    ///
    /// **Intended consumers:** plugin-internal state that wants
    /// to outlive process restarts or be shared across gateway
    /// nodes — a tool_gate plugin tracking per-principal state,
    /// a policy engine keeping rule-cache hashes, etc. The
    /// gateway's own session / task / pipeline / subscription /
    /// replay stores DON'T go through this seam: they use the
    /// separate `mcpg-backend-api` trait family (shipped
    /// pre-entity-kind) because their surface is richer than
    /// KV get/put (SSE streaming, CAS, sequence-counted
    /// appends). That's a unification candidate for a future
    /// architectural refactor, not a per-consumer migration.
    ///
    /// Thin passthrough to `registry.store_for_role`; lives on
    /// the runtime so consumer code doesn't have to reach
    /// through `plugin_registry()` + know about entity kinds.
    pub fn store_for_role(
        &self,
        role: &mcpg_plugin_protocol::store::StoreRole,
    ) -> Option<std::sync::Arc<dyn mcpg_plugin_protocol::store::Store>> {
        self.plugin_registry.store_for_role(role)
    }

    pub fn pipeline_store(&self) -> std::sync::Arc<dyn pipeline_store::PipelineStore> {
        self.pipeline_store.clone()
    }

    /// Whether the LIVE catalog carries anything on each surface.
    ///
    /// `mcp.capabilities` in config is not the catalog: federated,
    /// registry-synthesized and gateway-app capabilities arrive after boot and
    /// exist only here. Capability advertisement has to consult both.
    ///
    /// Each check materialises the surface's descriptor list, which is fine at
    /// the once-per-connection call sites that use it and would not be on a
    /// per-request path.
    pub fn has_live_tools(&self) -> bool {
        !self.capability_registry.tools().is_empty()
    }

    pub fn has_live_prompts(&self) -> bool {
        !self.capability_registry.prompts().is_empty()
    }

    pub fn has_live_resources(&self) -> bool {
        !self.capability_registry.resources().is_empty()
            || !self.capability_registry.resource_templates().is_empty()
    }

    pub fn has_live_completions(&self) -> bool {
        self.capability_registry.has_completions()
    }

    /// The resource-subscription registry. Exposed for the transports:
    /// the modern `subscriptions/listen` stream owns its registrations and
    /// releases them when the stream ends.
    pub fn subscription_store(
        &self,
    ) -> std::sync::Arc<dyn stores::subscription_store::SubscriptionStore> {
        self.subscription_store.clone()
    }

    /// Resource subscriptions — store rows, watch-engine refcounts, and the
    /// holders that keep both alive. Both wires subscribe through this rather
    /// than touching [`Self::subscription_store`] directly, which is left for
    /// read-only queries (notification fan-out, diagnostics).
    pub fn subscriptions(&self) -> &std::sync::Arc<subscriptions::SubscriptionService> {
        &self.subscription_service
    }

    pub fn task_store(&self) -> std::sync::Arc<dyn task_store::TaskStore> {
        self.task_store.clone()
    }

    /// Plugin-registry handle for handlers that need to emit
    /// audit events directly (modern dispatch arms).
    pub(crate) fn plugin_registry_handle(&self) -> Arc<mcpg_plugin_host::PluginRegistry> {
        Arc::clone(&self.plugin_registry)
    }

    /// Read-only view of the operator-declared policy_engine
    /// chain. Empty `[]` when no chain is configured.
    pub fn policy_chain(&self) -> &[String] {
        &self.policy_chain
    }

    pub fn uptime_secs(&self) -> i64 {
        (Utc::now() - self.started_at).num_seconds().max(0)
    }

    /// Effective `taskSupport` for a tool (SEP-2663 materialization
    /// decision). `None` when the tool is unknown; absent
    /// `execution.taskSupport` resolves to `Forbidden`.
    pub fn tool_task_support(&self, name: &str) -> Option<crate::backends::TaskSupport> {
        self.capability_registry.tool_task_support(name)
    }
}
