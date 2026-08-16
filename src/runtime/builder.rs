use super::*;

impl GatewayRuntime {
    pub fn new(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
    ) -> Self {
        Self::try_new_with_configs(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            SessionStoreConfig::default(),
            ToolAccessPolicyConfig::default(),
            RuntimeDebugConfig {
                enabled: true,
                ..RuntimeDebugConfig::default()
            },
        )
        .expect("valid runtime config")
    }

    pub fn new_with_store_config(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        store_config: SessionStoreConfig,
    ) -> Self {
        Self::try_new_with_configs(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            store_config,
            ToolAccessPolicyConfig::default(),
            RuntimeDebugConfig {
                enabled: true,
                ..RuntimeDebugConfig::default()
            },
        )
        .expect("valid runtime config")
    }

    pub fn new_with_configs(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        store_config: SessionStoreConfig,
        tool_access_policy_config: ToolAccessPolicyConfig,
    ) -> Self {
        Self::new_with_configs_and_debug(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            store_config,
            tool_access_policy_config,
            RuntimeDebugConfig {
                enabled: true,
                ..RuntimeDebugConfig::default()
            },
        )
    }

    pub fn new_with_configs_and_debug(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        store_config: SessionStoreConfig,
        tool_access_policy_config: ToolAccessPolicyConfig,
        debug_config: RuntimeDebugConfig,
    ) -> Self {
        Self::try_new_with_configs(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            store_config,
            tool_access_policy_config,
            debug_config,
        )
        .expect("valid runtime config")
    }

    pub fn new_with_configs_and_runtime_controls(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        store_config: SessionStoreConfig,
        tool_access_policy_config: ToolAccessPolicyConfig,
        debug_config: RuntimeDebugConfig,
        tool_bindings: &[BackendConfig],
        prompt_bindings: &[BackendConfig],
        resource_bindings: &[BackendConfig],
        resource_template_bindings: &[BackendConfig],
    ) -> Self {
        Self::try_new_with_runtime_controls(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            Arc::new(session_store::KvBackedSessionStore::new_in_memory(
                store_config,
            )),
            tool_access_policy_config,
            debug_config,
            tool_bindings,
            prompt_bindings,
            resource_bindings,
            resource_template_bindings,
            None, // jwt_verifier
            None, // oidc_resolver
            std::sync::Arc::new(pipeline_store::KvBackedPipelineStore::new_in_memory()),
            Arc::new(delivery_bus::BusBackedDeliveryBus::new_in_memory()),
        )
        .expect("valid runtime config")
    }

    pub fn try_new_with_configs(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        store_config: SessionStoreConfig,
        tool_access_policy_config: ToolAccessPolicyConfig,
        debug_config: RuntimeDebugConfig,
    ) -> anyhow::Result<Self> {
        Self::try_new_with_runtime_controls(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            Arc::new(session_store::KvBackedSessionStore::new_in_memory(
                store_config,
            )),
            tool_access_policy_config,
            debug_config,
            &[],
            &[],
            &[],
            &[],
            None, // jwt_verifier
            None, // oidc_resolver
            std::sync::Arc::new(pipeline_store::KvBackedPipelineStore::new_in_memory()),
            Arc::new(delivery_bus::BusBackedDeliveryBus::new_in_memory()),
        )
    }

    pub fn try_new_with_runtime_controls(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        session_store: Arc<dyn SessionStore>,
        tool_access_policy_config: ToolAccessPolicyConfig,
        debug_config: RuntimeDebugConfig,
        tool_bindings: &[BackendConfig],
        prompt_bindings: &[BackendConfig],
        resource_bindings: &[BackendConfig],
        resource_template_bindings: &[BackendConfig],
        jwt_verifier: Option<identity::JwtVerifier>,
        oidc_resolver: Option<std::sync::Arc<oidc::OidcOAuthResolver>>,
        pipeline_store: std::sync::Arc<dyn pipeline_store::PipelineStore>,
        delivery_bus: Arc<dyn delivery_bus::DeliveryBus>,
    ) -> anyhow::Result<Self> {
        Self::try_new_with_runtime_controls_and_cache(
            service_name,
            service_version,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            session_store,
            tool_access_policy_config,
            debug_config,
            tool_bindings,
            prompt_bindings,
            resource_bindings,
            resource_template_bindings,
            jwt_verifier,
            oidc_resolver,
            pipeline_store,
            std::sync::Arc::new(task_store::KvBackedTaskStore::new_in_memory_default()),
            delivery_bus,
            Arc::new(subscription_store::KvBackedSubscriptionStore::new_in_memory(100)),
            None,
            mcpg_plugin_host::PluginRegistry::new(),
            std::sync::Arc::new(
                mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind::Local(
                    std::sync::Arc::new(
                        mcpg_plugin_host::credential_cache::CredentialCache::default(),
                    ),
                ),
            ),
            Vec::new(),
        )
    }

    pub fn try_new_with_runtime_controls_and_cache(
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        server_bind_address: impl Into<String>,
        health_path: impl Into<String>,
        mcp_path: impl Into<String>,
        log_level: impl Into<String>,
        log_sinks: Vec<SinkConfig>,
        logging_initialized: bool,
        session_store: Arc<dyn SessionStore>,
        tool_access_policy_config: ToolAccessPolicyConfig,
        debug_config: RuntimeDebugConfig,
        tool_bindings: &[BackendConfig],
        prompt_bindings: &[BackendConfig],
        resource_bindings: &[BackendConfig],
        resource_template_bindings: &[BackendConfig],
        jwt_verifier: Option<identity::JwtVerifier>,
        oidc_resolver: Option<std::sync::Arc<oidc::OidcOAuthResolver>>,
        pipeline_store: std::sync::Arc<dyn pipeline_store::PipelineStore>,
        task_store: std::sync::Arc<dyn task_store::TaskStore>,
        delivery_bus: Arc<dyn delivery_bus::DeliveryBus>,
        subscription_store: Arc<dyn subscription_store::SubscriptionStore>,
        policy_cache_config: Option<&crate::config::PolicyCacheConfig>,
        plugin_registry: mcpg_plugin_host::PluginRegistry,
        credential_cache: std::sync::Arc<
            mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind,
        >,
        policy_chain: Vec<String>,
    ) -> anyhow::Result<Self> {
        // Legacy helpers (backend_health, watch_configs, dynamic_list,
        // ExecutionDispatcher) still expect a flat slice. Build it
        // once from the four typed lists; CapabilityRegistry still
        // gets the lists individually so it can dispatch by list
        // membership instead of a per-entry `kind:` field.
        let binding_configs: Vec<BackendConfig> = tool_bindings
            .iter()
            .chain(prompt_bindings.iter())
            .chain(resource_bindings.iter())
            .chain(resource_template_bindings.iter())
            .cloned()
            .collect();
        let binding_configs = binding_configs.as_slice();

        // http is a runtime-loaded cdylib in production (registered by the
        // plugin loader from a `plugins[]` row, like kafka/nats/sql/LLMs) —
        // the gateway hard-wires no backend. Tests that build the `Runtime`
        // directly bypass the loader, so under `#[cfg(test)]` we register the
        // in-tree http plugin shell (dev-dependency) when http bindings need
        // it and nothing else registered it; the generic dynamic-register
        // pass wires the per-binding profiles like every other backend.
        #[cfg(test)]
        let plugin_registry = {
            let mut plugin_registry = plugin_registry;
            let http_already_registered = plugin_registry.backend("http").is_some();
            let has_http_bindings = binding_configs.iter().any(|b| b.backend.kind == "http");
            if has_http_bindings && !http_already_registered {
                let http_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_http::HttpBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_http::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            http_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
            }

            // Command bindings dispatch via the dev.mcpg.backend.command
            // plugin. Unlike http (whose in-test tools only check
            // availability), the promoted command-tool tests dispatch +
            // assert the envelope, so we register the plugin AND its
            // per-binding profiles here. `register_profile`'s body is
            // sync (spec parse + arg-template compile + map insert), so a
            // `futures` block_on suffices — no tokio runtime needed.
            let command_already = plugin_registry.backend("command").is_some();
            let command_bindings: Vec<&crate::config::BackendConfig> = binding_configs
                .iter()
                .filter(|b| b.backend.kind == "command")
                .collect();
            if !command_bindings.is_empty() && !command_already {
                let command_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_command::CommandBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_command::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            command_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in &command_bindings {
                    if let Some(spec) =
                        crate::backends::dynamic_register_spec(&binding.backend, true)
                    {
                        futures::executor::block_on(
                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                command_plugin.as_ref(),
                                &binding.name,
                                &spec,
                                host.clone(),
                            ),
                        )
                        .map_err(|e| {
                            anyhow::anyhow!("register command profile {}: {:?}", binding.name, e)
                        })?;
                    }
                }
            }

            // Mock is the standard test-fixture backend; many tests build
            // the Runtime with mock bindings + dispatch them. Register the
            // in-tree mock plugin + its per-binding profiles, same as
            // command (register_profile body is sync).
            let mock_already = plugin_registry.backend("mock").is_some();
            let mock_bindings: Vec<&crate::config::BackendConfig> = binding_configs
                .iter()
                .filter(|b| b.backend.kind == "mock")
                .collect();
            if !mock_bindings.is_empty() && !mock_already {
                let mock_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_mock::MockBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_mock::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            mock_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in &mock_bindings {
                    if let Some(spec) =
                        crate::backends::dynamic_register_spec(&binding.backend, true)
                    {
                        futures::executor::block_on(
                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                mock_plugin.as_ref(),
                                &binding.name,
                                &spec,
                                host.clone(),
                            ),
                        )
                        .map_err(|e| {
                            anyhow::anyhow!("register mock profile {}: {:?}", binding.name, e)
                        })?;
                    }
                }
            }

            // SOAP dispatches through the dev.mcpg.backend.soap plugin via
            // execute_envelope_plugin("soap", ...) — exactly like grpc /
            // graphql. Promoted SOAP tests dispatch + assert the response
            // envelope, so register the plugin AND its per-binding /
            // per-step profiles here (register_profile's body is sync: spec
            // parse + template compile + an uncontended RwLock insert, so
            // futures block_on suffices). Guard so we don't double-register
            // if a host already wired the cdylib in.
            let soap_already = plugin_registry.backend("soap").is_some();
            let has_soap = binding_configs.iter().any(|b| {
                (b.backend.kind == "soap")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "soap"))).unwrap_or(false))
            });
            if has_soap && !soap_already {
                let soap_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_soap::SoapBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_soap::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            soap_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "soap" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        soap_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register soap profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "soap"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                soap_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register soap step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // LDAP dispatches through the dev.mcpg.backend.ldap plugin via
            // execute_envelope_plugin("ldap", ...) — exactly like soap /
            // grpc. Promoted LDAP tests dispatch + assert the response
            // envelope, so register the plugin AND its per-binding /
            // per-step profiles here (register_profile's body is sync: spec
            // parse + filter compile + an uncontended RwLock insert, so
            // futures block_on suffices). Guard so we don't double-register
            // if a host already wired the cdylib in.
            let ldap_already = plugin_registry.backend("ldap").is_some();
            let has_ldap = binding_configs.iter().any(|b| {
                (b.backend.kind == "ldap")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "ldap"))).unwrap_or(false))
            });
            if has_ldap && !ldap_already {
                let ldap_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_ldap::LdapBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_ldap::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            ldap_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "ldap" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        ldap_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register ldap profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "ldap"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                ldap_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register ldap step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // MSSQL dispatches through the dev.mcpg.backend.mssql plugin via
            // execute_envelope_plugin("mssql", ...) — exactly like ldap / soap.
            // Promoted MSSQL tests dispatch + assert the response envelope, so
            // register the plugin AND its per-binding / per-step profiles here
            // (register_profile parses the spec, compiles CEL params, and
            // builds the connection pool — all sync, no I/O — so futures
            // block_on suffices). Guard against double-registering if a host
            // already wired the cdylib in.
            let mssql_already = plugin_registry.backend("mssql").is_some();
            let has_mssql = binding_configs.iter().any(|b| {
                (b.backend.kind == "mssql")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "mssql"))).unwrap_or(false))
            });
            if has_mssql && !mssql_already {
                let mssql_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_mssql::MssqlBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_mssql::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            mssql_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "mssql" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        mssql_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register mssql profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "mssql"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                mssql_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register mssql step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // AMQP dispatches through the dev.mcpg.backend.amqp plugin via
            // execute_envelope_plugin("amqp", ...) — exactly like mssql / ldap.
            // Promoted AMQP tests dispatch + assert the response envelope, so
            // register the plugin AND its per-binding / per-step profiles here
            // (register_profile parses + validates the spec and stores a lazy
            // connection slot — no I/O — so futures block_on suffices). Guard
            // against double-registering if a host already wired the cdylib in.
            let amqp_already = plugin_registry.backend("amqp").is_some();
            let has_amqp = binding_configs.iter().any(|b| {
                (b.backend.kind == "amqp")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "amqp"))).unwrap_or(false))
            });
            if has_amqp && !amqp_already {
                let amqp_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_amqp::AmqpBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_amqp::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            amqp_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "amqp" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        amqp_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register amqp profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "amqp"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                amqp_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register amqp step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Email dispatches through the dev.mcpg.backend.email plugin via
            // execute_envelope_plugin("email", ...) — exactly like amqp / mssql.
            // Promoted Email tests dispatch + assert the response envelope, so
            // register the plugin AND its per-binding / per-step profiles here
            // (register_profile parses + validates the spec — no I/O — so
            // futures block_on suffices). Guard against double-registering if a
            // host already wired the cdylib in.
            let email_already = plugin_registry.backend("email").is_some();
            let has_email = binding_configs.iter().any(|b| {
                (b.backend.kind == "email")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "email"))).unwrap_or(false))
            });
            if has_email && !email_already {
                let email_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_email::EmailBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_email::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            email_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "email" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        email_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register email profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "email"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                email_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register email step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // SFTP dispatches through the dev.mcpg.backend.sftp plugin via
            // execute_envelope_plugin("sftp", ...) — exactly like email / amqp.
            // Promoted SFTP tests dispatch + assert the response envelope, so
            // register the plugin AND its per-binding / per-step profiles here
            // (register_profile parses + validates the spec — no I/O — so
            // futures block_on suffices). Guard against double-registering if a
            // host already wired the cdylib in.
            let sftp_already = plugin_registry.backend("sftp").is_some();
            let has_sftp = binding_configs.iter().any(|b| {
                (b.backend.kind == "sftp")
                    || (b.backend.kind == "pipeline" && serde_json::from_value::<crate::config::PipelineBackendConfig>(serde_json::Value::Object(b.backend.spec.clone())).map(|p| p.steps.iter().any(|s| matches!(s, crate::config::PipelineStepConfig::Backend(s) if s.kind == "sftp"))).unwrap_or(false))
            });
            if has_sftp && !sftp_already {
                let sftp_plugin =
                    std::sync::Arc::new(mcpg_plugin_backend_sftp::SftpBackendPlugin::new());
                mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry).register(
                    mcpg_plugin_backend_sftp::BINDING_DESCRIPTOR_YAML,
                    &[],
                    (),
                    |reg, _host| {
                        reg.register_backend(
                            sftp_plugin.clone(),
                            mcpg_plugin_protocol::PluginTier::Native,
                        )
                    },
                )?;
                let host = mcpg_plugin_protocol::noop_backend_host();
                for binding in binding_configs.iter() {
                    match binding.backend.kind.as_str() {
                        "sftp" => {
                            if let Some(spec) =
                                crate::backends::dynamic_register_spec(&binding.backend, true)
                            {
                                futures::executor::block_on(
                                    mcpg_plugin_protocol::BackendPlugin::register_profile(
                                        sftp_plugin.as_ref(),
                                        &binding.name,
                                        &spec,
                                        host.clone(),
                                    ),
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "register sftp profile {}: {:?}",
                                        binding.name,
                                        e
                                    )
                                })?;
                            }
                        }
                        "pipeline" => {
                            let pipeline = match serde_json::from_value::<
                                crate::config::PipelineBackendConfig,
                            >(
                                serde_json::Value::Object(binding.backend.spec.clone()),
                            ) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            for step in &pipeline.steps {
                                if let crate::config::PipelineStepConfig::Backend(s) = step
                                    && s.kind == "sftp"
                                {
                                    let step_profile = format!("{}._step_.{}", binding.name, s.id);
                                    let spec = crate::backends::dynamic_register_spec(
                                        &crate::config::BackendImpl {
                                            kind: s.kind.clone(),
                                            spec: s.spec.clone(),
                                        },
                                        true,
                                    );
                                    if let Some(spec) = spec {
                                        futures::executor::block_on(
                                            mcpg_plugin_protocol::BackendPlugin::register_profile(
                                                sftp_plugin.as_ref(),
                                                &step_profile,
                                                &spec,
                                                host.clone(),
                                            ),
                                        )
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "register sftp step profile {}: {:?}",
                                                step_profile,
                                                e
                                            )
                                        })?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            plugin_registry
        };
        let plugin_registry = Arc::new(plugin_registry);
        let pre_dispatch_policy = Arc::new(match policy_cache_config {
            Some(cache_config) => {
                PreDispatchPolicyGate::try_new_with_cache(tool_access_policy_config, cache_config)?
            }
            None => PreDispatchPolicyGate::try_new(tool_access_policy_config)?,
        });

        // Materialise scalar params into locals so both the struct
        // literal below and the watch-fetcher snapshot can reference
        // them without consuming the `impl Into<String>` arguments
        // twice.
        let service_name: String = service_name.into();
        let service_version: String = service_version.into();
        let server_bind_address: String = server_bind_address.into();
        let health_path: String = health_path.into();
        let mcp_path: String = mcp_path.into();
        let log_level: String = log_level.into();
        let started_at = Utc::now();

        // Build capability_registry and execution_dispatcher into local
        // Arcs first so the watch-engine fetcher closure can capture
        // clones of them and call back into the same instances the
        // request path uses.
        let capability_registry = Arc::new(CapabilityRegistry::new(
            debug_config.enabled,
            debug_config.bindings.clone(),
            debug_config.exposure.clone(),
            tool_bindings,
            prompt_bindings,
            resource_bindings,
            resource_template_bindings,
            Some(plugin_registry.as_ref()),
        ));
        let execution_dispatcher = {
            let mut dispatcher = ExecutionDispatcher::from_runtime_debug_config(
                debug_config.clone(),
                binding_configs,
            );
            dispatcher.set_delivery_bus(Arc::clone(&delivery_bus));
            dispatcher.set_plugin_registry(Arc::clone(&plugin_registry));
            dispatcher.set_pipeline_store(Arc::clone(&pipeline_store));
            Arc::new(dispatcher)
        };

        let watch_engine = {
            // Build per-binding watch configs from the operator's
            // YAML at bootstrap; plugin-backed strategies
            // (nats_topic, kafka_topic, postgres_listen_notify)
            // route their events through the existing fan-out via
            // the registry. The engine always runs (an idle loop
            // parked on its channel) because federated resources
            // get their watch configs synthesized lazily by the
            // probe on first subscribe — federations are wired
            // after the runtime is built, so they cannot be
            // enumerated here.
            let watch_configs = build_watch_configs(binding_configs);
            let delivery_publish = watch_engine_delivery_publish(Arc::clone(&delivery_bus));
            let resource_fetcher = build_watch_resource_fetcher(
                Arc::clone(&capability_registry),
                Arc::clone(&execution_dispatcher),
            );
            // Synthesize a poll watcher for a subscribed federated
            // resource whose upstream cannot push updates (modern
            // stateless wire / stdio), per the federation's
            // `synthesize` config.
            let probe_registry = Arc::clone(&capability_registry);
            let probe_dispatcher = Arc::clone(&execution_dispatcher);
            let watch_probe: watch_engine::WatchProbe = Arc::new(move |uri: &str| {
                let route = probe_registry.resource_route(uri)?;
                let crate::backends::ResourceRoute::Federated { source, .. } = route else {
                    return None;
                };
                let engine = probe_dispatcher.federation_engine()?;
                let interval_ms = engine.synthesized_poll_interval_ms(&source)?;
                Some(watch_engine::WatchConfig {
                    uri: uri.to_owned(),
                    strategy: watch_engine::WatchStrategy::Poll { interval_ms },
                    notification_filter: None,
                    compiled_filter_program: None,
                })
            });
            watch_engine::WatchEngine::start_with_plugins(
                watch_configs,
                Arc::clone(&subscription_store),
                delivery_publish,
                resource_fetcher,
                Some(Arc::clone(&plugin_registry)),
                Some(watch_probe),
            )
        };
        let subscription_service = subscriptions::SubscriptionService::new(
            Arc::clone(&subscription_store),
            watch_engine.clone(),
        );

        Ok(Self {
            service_name,
            service_version,
            started_at,
            server_bind_address,
            health_path,
            mcp_path,
            log_level,
            log_sinks,
            logging_initialized,
            debug_enabled: debug_config.enabled,
            revalidate_mutated_tool_arguments: false,
            idempotency_replay_revalidation: false,
            bind_session_owner: false,
            capability_registry: Arc::clone(&capability_registry),
            dynamic_list_bindings: extract_dynamic_list_bindings(
                resource_bindings,
                resource_template_bindings,
                |kind| {
                    plugin_registry
                        .backend_profile(kind)
                        .map(|p| p.dynamic_list)
                        .unwrap_or(false)
                },
            ),
            pre_dispatch_policy,
            plugin_registry: Arc::clone(&plugin_registry),
            policy_chain,
            #[cfg(feature = "governance-quotas")]
            quota_gate: None,
            idempotency_capability: None,
            idempotency_store: idempotency::noop_idempotency_store(),
            apps_capability: None,
            apps_federate_upstream: false,
            tunnel_federation: None,
            apps_policy: None,
            gateway_apps: std::collections::BTreeMap::new(),
            credential_cache,
            execution_dispatcher: Arc::clone(&execution_dispatcher),
            content_stores: None,
            session_store,
            jwt_verifier,
            oidc_resolver,
            ema_authorization_server: None,
            aauth_resource: None,
            pipeline_store,
            task_store,
            delivery_bus: Arc::clone(&delivery_bus),
            subscription_store: Arc::clone(&subscription_store),
            watch_engine,
            subscription_service,
            backend_health: backend_health::new_health_map(binding_configs),
            cancellation_bus: Arc::new(cancellation_bus::BusBackedCancellationBus::new_in_memory()),
            cancellation_tokens: Arc::new(dashmap::DashMap::new()),
            completion_limiter: dashmap::DashMap::new(),
            completion_rate_limit_per_sec: None,
            cursor_hmac_key: Self::generate_cursor_hmac_key(),
            seen_request_ids: dashmap::DashMap::new(),
            relax_request_id_uniqueness: false,
            access_log: true,
            tenant_session_counts: dashmap::DashMap::new(),
            max_sessions_per_tenant: 0,
            session_tenants: dashmap::DashMap::new(),
            approval_registry: build_default_approval_registry(),
            tool_call_recorder: cp_metrics::ToolCallRecorderHandle::default(),
            cp_quota_status: cp_quota::QuotaStatusHandle::default(),
            cp_rps_limiter: std::sync::Arc::new(cp_quota::RpsLimiter::new()),
            protocol_registry: ArcSwapOption::const_empty(),
            shared_services: ArcSwapOption::const_empty(),
            modern_session_aliases: dashmap::DashMap::new(),
        })
    }

    /// Wire a per-tool-call observability hook.
    /// Default is a no-op; integrators running CP-attached
    /// (e.g. `mcpg --enroll <URL>` with the cp-client agent loaded)
    /// pass an adapter that pushes samples into the agent's
    /// `MetricsBuffer`. Idempotent; later calls overwrite earlier
    /// recorders.
    pub fn set_tool_call_recorder(
        &mut self,
        recorder: std::sync::Arc<dyn cp_metrics::ToolCallRecorder>,
    ) {
        self.tool_call_recorder = cp_metrics::ToolCallRecorderHandle::new(recorder);
    }

    /// Wire a CP-pushed quota status provider. Default is
    /// a no-op; the cp-attached integrator passes an adapter
    /// that reads from the cp-client's
    /// `Arc<ArcSwap<Option<QuotaStatus>>>`. Idempotent.
    pub fn set_cp_quota_status_provider(
        &mut self,
        provider: std::sync::Arc<dyn cp_quota::QuotaStatusProvider>,
    ) {
        self.cp_quota_status = cp_quota::QuotaStatusHandle::new(provider);
    }

    /// Carry the CP-attached observability hooks from a prior runtime.
    ///
    /// `set_tool_call_recorder` / `set_cp_quota_status_provider` are wired
    /// once, at CP attach, onto the runtime that exists then. A config reload
    /// builds a fresh runtime whose handles are the no-op defaults, so every
    /// reload must carry them forward or per-tool-call samples and CP-pushed
    /// quota status go silent until the process restarts — undetectably, since
    /// the agent keeps heartbeating either way.
    ///
    /// Both handles are cheap clones and carry no config, so this is
    /// unconditional: nothing here needs to know what the reload changed.
    pub fn adopt_cp_hooks(&mut self, prior: &GatewayRuntime) {
        self.tool_call_recorder = prior.tool_call_recorder.clone();
        self.cp_quota_status = prior.cp_quota_status.clone();
    }

    /// configure the per-tenant session quota at bootstrap.
    pub fn set_max_sessions_per_tenant(&mut self, n: usize) {
        self.max_sessions_per_tenant = n;
    }

    /// Toggle the per-request access log at bootstrap
    /// (`server.access_log`). Default on; disabling sheds the two
    /// `request received` / `request completed` events per request.
    pub fn set_access_log(&mut self, enabled: bool) {
        self.access_log = enabled;
    }

    /// Opt out of per-session JSON-RPC request-id uniqueness at bootstrap.
    /// Only load generators that replay a fixed request body set this
    /// (`server.relax_request_id_uniqueness`); production leaves it off.
    pub fn set_relax_request_id_uniqueness(&mut self, relax: bool) {
        self.relax_request_id_uniqueness = relax;
    }

    /// Install the operator-configured content store registry.
    /// Called once at bootstrap from `app::run`
    /// and the config-reload path; subsequent `resources/read` of
    /// `mcpg-resource://<storage>/<id>` URIs route through this map.
    /// `None` keeps the runtime operating without a content store —
    /// `mcpg-resource://` reads then return a generic "unknown
    /// resource" error.
    pub fn set_content_stores(
        &mut self,
        registry: Option<Arc<content_store_registry::ContentStoreRegistry>>,
    ) {
        self.content_stores = registry;
    }

    /// The runtime's content-store registry, if any storage providers are
    /// configured. Used by the shutdown / reload paths to drain the built
    /// `ContentStore` profile instances.
    pub fn content_stores(&self) -> Option<&Arc<content_store_registry::ContentStoreRegistry>> {
        self.content_stores.as_ref()
    }

    /// Install the runtime quota gate.
    /// Called from `app::run` after the gate is built by
    /// `build_quota_gate` and from `app::reload_config` on hot-
    /// swap. `None` when no quota policies are declared — the
    /// dispatch hook short-circuits.
    #[cfg(feature = "governance-quotas")]
    pub fn set_quota_gate(&mut self, gate: Option<Arc<crate::runtime::quota_gate::QuotaGate>>) {
        self.quota_gate = gate;
    }

    /// Read-only handle to the quota gate, if installed.
    #[cfg(feature = "governance-quotas")]
    pub fn quota_gate(&self) -> Option<&Arc<crate::runtime::quota_gate::QuotaGate>> {
        self.quota_gate.as_ref()
    }

    /// Install the `dev.mcpg/idempotency` extension's capability
    /// advertisement. The initialize handler embeds the value under
    /// `result.capabilities.extensions[…]` when set; passing `None`
    /// (the default) suppresses the advertisement entirely so
    /// SEP-2133 graceful-degrade kicks in client-side. Wired from
    /// [`crate::config::IdempotencyConfig`] at boot.
    pub fn set_idempotency_capability(&mut self, capability: Option<serde_json::Value>) {
        self.idempotency_capability = capability;
    }

    /// Enable re-validation of tool arguments after a tool_gate /
    /// transform plugin rewrites them. Wired from
    /// `server.revalidate_mutated_tool_arguments` at boot + reload.
    pub fn set_revalidate_mutated_tool_arguments(&mut self, on: bool) {
        self.revalidate_mutated_tool_arguments = on;
    }

    /// Enable re-running the full pre-dispatch authz stack on an
    /// idempotency completed-replay hit. Wired from
    /// `idempotency.replay_revalidation` at boot + reload.
    pub fn set_idempotency_replay_revalidation(&mut self, on: bool) {
        self.idempotency_replay_revalidation = on;
    }

    /// Enable session-owner binding for session-scoped HTTP operations.
    /// Wired from `sessions.bind_session_owner` at boot + reload.
    pub fn set_bind_session_owner(&mut self, on: bool) {
        self.bind_session_owner = on;
    }
}
