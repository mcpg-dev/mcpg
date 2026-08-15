use super::*;

// `expand_env_refs_in_spec` was retired in the STATE-1 unification.
// Binding-spec resolution now goes through
// `crate::config::resolver::resolve_config_value`, which runs CEL
// `${env.X}` first and then walks bound `scheme://` providers
// (env, file, vault, …) in one async pass.

mod entities;
mod native;
mod packaged;
mod policy;

pub(crate) use native::*;
pub(crate) use packaged::*;
pub(crate) use policy::*;

/// Result bundle from [`build_plugin_registry`] — the registry plus the
/// late-bound host handles the runtime installs after boot.
pub(crate) struct PluginBundle {
    pub registry: mcpg_plugin_host::PluginRegistry,
    /// Late-bound host shared by the HTTP / SQL / NATS / Kafka backend
    /// plugins. These four plugins call
    /// `subscribe_credential_revoked` and `subscribe_secret_rotation`
    /// from inside `register_profile`; the late-bound host buffers
    /// those subscriptions and replays them onto the real
    /// [`crate::backends::host::GatewayBackendHost`] once
    /// `set(...)` runs. Without it both subscription paths would
    /// fall through to the no-op default and the cred-cache eviction
    /// + secret-rotation fan-out wouldn't reach these plugins.
    pub backend_late_host: std::sync::Arc<mcpg_plugin_protocol::LateBoundBackendHost>,
    /// Late-bound [`HostServices`](mcpg_plugin_host::host_services::HostServices)
    /// shared by every `Native*Adapter`. Native plugins built from
    /// cdylibs receive an `Arc<dyn HostServices>` resolved off this
    /// late-bound wrapper at adapter-construction time. The wrapper
    /// returns a [`NullHostServices`](mcpg_plugin_host::host_services::NullHostServices)
    /// stub until `set(...)` runs after `build_plugin_registry`
    /// finishes and the registry is wrapped in `Arc`. From that
    /// point forward, plugin → host calls (resolve_secret,
    /// issue_credential, config_snapshot, audit_event, metric_emit,
    /// span_*) route into the gateway's real
    /// [`GatewayHostServices`](crate::app::host_services_impl::GatewayHostServices).
    pub host_services_late: std::sync::Arc<mcpg_plugin_host::host_services::LateBoundHostServices>,
    /// Merged JSON value produced by applying every
    /// `plugins.config_overlay` entry against the registered
    /// config_provider plugins. Empty object `{}` when the
    /// operator configured no overlays. Exposed to runtime
    /// subsystems via `AppState.config_overlay`.
    pub config_overlay: config_overlay::ConfigOverlayOutcome,
    /// Gateway-side L1 credential cache — wraps the
    /// configured `cluster_backend` pub/sub when
    /// `credentials.cluster.enabled` is true and a
    /// coordinator is bound, plain in-process otherwise. Held by
    /// the runtime so the (deferred) credential resolver call site
    /// at request-dispatch time can reach it via `&self`.
    pub credential_cache:
        std::sync::Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind>,
    /// Operator-configured content store registry. `Some` when
    /// `plugins.content_store.kind != disabled`. Multi-instance map backing the
    /// `BackendHost::store_content` / `fetch_content` surface and the
    /// `mcpg-resource://<storage>/<id>` branch of the
    /// `resources/read` handler.
    pub content_stores:
        Option<std::sync::Arc<crate::runtime::content_store_registry::ContentStoreRegistry>>,
    /// Operator-configured LLM response cache. `Some`
    /// when `plugins.response_cache.kind != disabled`. Backs the
    /// `BackendHost::cache_get` / `cache_put` / `cache_invalidate`
    /// surface; bindings reach it from the engine's per-call
    /// hashing path.
    pub response_cache: Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>>,
    /// Per-binding response-cache overrides.
    /// Keyed by binding name; outer `Some` means the operator
    /// declared a `cache:` block on that binding, inner `None`
    /// means `kind: disabled` (explicit opt-out), inner `Some(c)`
    /// is the per-binding cache instance. Bindings absent from this
    /// map fall through to the gateway-wide `response_cache` above.
    pub response_cache_overrides: std::collections::HashMap<
        String,
        Option<std::sync::Arc<dyn mcpg_backend_llm_shared::ResponseCache>>,
    >,
    /// Canonical policy_engine chain in operator-declared order
    /// (`governance.policy.engine[]`). Each entry is the engine's
    /// self-declared `name()` (e.g. `"yaml-rules"`, `"cedar"`,
    /// `"opa"`). Runtime decision points pass this verbatim to
    /// [`PluginRegistry::evaluate_policy_chain`]. An empty
    /// `Vec` means "no chain configured" → every decision is
    /// `NotApplicable` and the caller picks its own default.
    pub policy_chain: Vec<String>,
    /// Operator-configured runtime quota gate.
    /// `Some` when the `governance-quotas` cargo feature is on AND
    /// `governance.quotas:` has at least one policy declared.
    /// `None` otherwise — the runtime hook short-circuits and
    /// every request passes through.
    #[cfg(feature = "governance-quotas")]
    pub quota_gate: Option<std::sync::Arc<crate::runtime::quota_gate::QuotaGate>>,
    /// Secret rotation: every `scheme://...` URI that
    /// `config::resolver::resolve_config_value` successfully expanded
    /// during boot, deduplicated. Caller spawns a `secret_watcher`
    /// task per unique URI after registry assembly so backend pools
    /// can evict + rebuild on Vault rotations.
    pub resolved_secret_refs: std::collections::BTreeSet<String>,
}

pub(crate) async fn build_plugin_registry(
    config: &mut AppConfig,
    jwt_verifier: Option<&crate::runtime::identity::JwtVerifier>,
    oidc_resolver: Option<std::sync::Arc<crate::runtime::oidc::OidcOAuthResolver>>,
) -> Result<PluginBundle> {
    let mut registry = mcpg_plugin_host::PluginRegistry::new();

    // Secret rotation: accumulate every `scheme://...` URI
    // that `resolve_config_value` expanded across all binding +
    // plugin-entry config trees. After registry assembly the gateway
    // spawns one `secret_watcher` task per unique URI; the task
    // drives the provider's `watch(secret_ref)` stream into the
    // `secret_rotation_broadcaster().notify(...)` fan-out so backend
    // pools (HTTP, SQL, NATS, Kafka) evict + rebuild on rotation.
    let mut resolved_secret_refs: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    // Late-bound `BackendHost` shared by HTTP / SQL /
    // NATS / Kafka backend plugins. The
    // four plugins each call `subscribe_credential_revoked` and
    // `subscribe_secret_rotation` from inside `register_profile`,
    // and `LateBoundBackendHost` buffers those subscriptions until
    // the real `GatewayBackendHost` is constructed and `set()` runs.
    // Without this, both subscriptions silently fall through to the
    // `NoOpBackendHost` default and the cred-cache eviction +
    // secret-rotation fan-out paths are dead. See PluginBundle for
    // where `set()` is called from `run` / `reload_config`.
    let backend_late_host = mcpg_plugin_protocol::LateBoundBackendHost::new();

    // Late-bound HostServices threaded into
    // every native adapter at construction time. The Arc returned by
    // `resolve()` initially points at `NullHostServices` (so any
    // host-call attempted during early boot returns a typed error).
    // Once the registry is wrapped in `Arc<PluginRegistry>` after
    // this fn returns, the caller swaps in the real
    // `GatewayHostServices` via `host_services_late.set(...)`,
    // wiring all in-flight `HostBridge::with_services` Arcs to the
    // production implementation.
    let host_services_late =
        std::sync::Arc::new(mcpg_plugin_host::host_services::LateBoundHostServices::new());

    // Per-entry granted_capabilities is the source of truth. Each
    // `register*` site supplies its grants slice explicitly via
    // `config.granted_capabilities_for(<plugin_id>)`;
    // built-ins that don't appear in operator config pass `&[]`
    // (their `required_capabilities` are empty so the cap check
    // always passes against an empty grant set).

    // Built-in env + file secret providers.
    // Both auto-bind their schemes (env:// and file://) unless
    // the operator overrides via `plugins.secrets.{env,file}`.
    // Real backends (Vault / AWS-SM) ship as separate plugins.
    {
        let env_plugin = crate::builtins::secret_env::EnvSecretProvider::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::secret_env::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry
                    .register_secret_provider(env_plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
        let file_plugin = crate::builtins::secret_file::FileSecretProvider::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::secret_file::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry
                    .register_secret_provider(file_plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
        // Pre-bind built-in env + file schemes here so plugin-entry
        // secret-resolution (further down) can already expand
        // env:// / file:// references in third-party plugins'
        // own config blocks. Third-party schemes (vault, aws-sm…)
        // get auto-bound after plugin-entry loading via
        // `auto_bind_secret_provider_schemes()`.
        registry
            .bind_secret_scheme("env", "dev.mcpg.builtin.secret.env")
            .with_context(|| "binding env:// secret scheme")?;
        registry
            .bind_secret_scheme("file", "dev.mcpg.builtin.secret.file")
            .with_context(|| "binding file:// secret scheme")?;
    }

    // Built-in file config provider. Auto-
    // bound to the `file` scheme unless the operator overrides via
    // `plugins.configs.file`. Real backends (Consul / K8s
    // ConfigMaps / AWS AppConfig) ship as separate plugins.
    {
        let plugin = crate::builtins::config_file::FileConfigProvider::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::config_file::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_config_provider(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
        // Pre-bind built-in file:// config scheme. External config
        // providers (consul, k8s-cm, aws-appconfig …) get auto-bound
        // after plugin-entry loading via
        // `auto_bind_config_provider_schemes()`.
        registry
            .bind_config_scheme("file", "dev.mcpg.builtin.config.file")
            .with_context(|| "binding file:// config scheme")?;
    }

    // Register the built-in memory transport.
    // Registration is unconditional — the plugin is visible in
    // admin surfaces and available for lookup by name. Starting
    // a transport is a separate concern that requires a
    // `MessageDispatcher`; the gateway-side dispatcher impl +
    // start wiring lands separately. External transport
    // plugins load via `plugins[]` the same way every
    // other entity kind does.
    {
        let plugin = crate::builtins::transport_memory::MemoryTransport::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::transport_memory::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_transport(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // There is no standalone transport-entry cross-check loop:
    // `plugin_bindings.transports` doesn't exist. The cross-check
    // happens at the point of use, when a configuration declares a
    // transport via per-entry metadata.

    // Register the built-in YAML-rules
    // policy engine when the operator's chain references it.
    // Runs BEFORE plugins[] loading so that subsequent
    // plugin registrations (cedar / opa / casbin / external
    // toolgates) can be gated by `plugin.lifecycle.register`
    // rules the operator wrote in YAML. External engine plugins
    // get registered later in the entries-loop's PolicyEngine
    // class arm.
    if config
        .governance
        .policy
        .engine
        .iter()
        .any(|kref| kref.kind == "yaml-rules")
    {
        // The kref's `config:` is a JSON value matching the
        // PolicyDocument shape (default_effect / source / rules).
        // Re-serialise to YAML and feed YamlRulesPolicyEngine the
        // same way an operator would by hand. Empty/null config
        // falls back to the safe deny-all stub so a misconfigured
        // entry doesn't silently allow everything.
        let kref = config
            .governance
            .policy
            .engine
            .iter()
            .find(|k| k.kind == "yaml-rules")
            .expect("checked just above");
        let plugin = if kref.config.is_null()
            || kref
                .config
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(false)
        {
            crate::builtins::policy_yaml_rules::YamlRulesPolicyEngine::deny_all()
        } else {
            let yaml_text = serde_yaml::to_string(&kref.config).with_context(|| {
                "governance.policy.engine[yaml-rules]: config could not be \
                     serialised to YAML"
            })?;
            crate::builtins::policy_yaml_rules::YamlRulesPolicyEngine::from_yaml(
                &yaml_text,
                "config:governance.policy.engine[yaml-rules]",
            )
            .with_context(|| {
                "governance.policy.engine[yaml-rules]: config did not parse as a \
                 valid PolicyDocument"
            })?
        };
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::policy_yaml_rules::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_policy_engine(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // The cluster coordinator is installed AFTER the `plugins[]` loop
    // below — an external coordinator (`kind: redis/nats/consul/etcd`) is a
    // cdylib loaded by that loop, so its registration must precede the
    // single_node-vs-external selection + the vocabulary cross-check + the
    // boot reachability probe. See `install_cluster_coordinator` after the
    // loop.

    // Built-in observability fan-out plugins register
    // only when the operator opts them in by listing their plugin
    // id in `observability.{traces,logs}.sinks[].kind`. The list
    // is the single source of truth: omitting a built-in id
    // disables it (no separate `disable_builtins` toggle).
    let traces_plugin_kinds: std::collections::HashSet<&str> = config
        .observability
        .traces
        .sinks
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    if config.observability.is_traces_on()
        && traces_plugin_kinds.contains(crate::builtins::telemetry_debug::PLUGIN_ID)
    {
        let plugin = crate::builtins::telemetry_debug::DebugTelemetrySink::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::telemetry_debug::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_telemetry_sink(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    let logs_plugin_kinds: std::collections::HashSet<&str> = config
        .observability
        .logs
        .sinks
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    if config.observability.is_logs_on()
        && logs_plugin_kinds.contains(crate::builtins::log_stderr_json::PLUGIN_ID)
    {
        let plugin = crate::builtins::log_stderr_json::StderrJsonLogSink::new(
            mcpg_plugin_protocol::logs::LogLevel::Info,
        );
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::log_stderr_json::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_log_sink(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // OTLP + Prometheus are NOT linked into this binary. They ship as
    // signed cdylibs under the same ids the sinks name, so an operator who
    // wants them declares the artifact in `plugins[]` and the loader
    // registers it like any other plugin — one implementation, verified,
    // independently versioned. Naming the sink kind without a matching
    // `plugins[]` entry leaves the sink unregistered; the observability
    // wiring reports that rather than silently exporting nothing.
    // The built-in in-memory cache. Always registered; operator wires
    // it to namespaces via `plugins.caches.<namespace>`.
    {
        let plugin = crate::builtins::cache_memory::MemoryCache::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::cache_memory::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_cache(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // The built-in in-memory store. Always registered; operator may
    // bind it to any or all of the canonical roles via
    // `plugins.kv.<role>`. When no roles are bound the plugin sits
    // idle (fine for dev / CI runs where no code consumes the
    // entity-kind path).
    {
        let plugin = crate::builtins::store_memory::MemoryStore::new();
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::store_memory::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_store(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // Push the operator's tool-call audit emission preferences
    // into the registry. Default true/true matches the
    // compliance posture most operators want; flipping either to
    // false skips the corresponding event class without affecting
    // the deny / challenge / lifecycle paths.
    registry.set_tool_call_audit_emission(
        config.governance.audit.emit_tool_call_allowed,
        config.governance.audit.emit_tool_call_completed,
    );

    // The built-in `dev.mcpg.builtin.audit.local-file` sink registers
    // only when its plugin id appears in `audit.sinks[].kind` (the
    // same opt-in pattern the observability sinks use). Operators
    // who ship their own audit sink simply omit the built-in
    // id from the list. The sink's `path` config can come from either
    // the `plugins[]` entry (fallback) or from
    // `audit.sinks[id == ...].config.path` (preferred).
    let audit_sink_kinds: std::collections::HashSet<&str> = config
        .governance
        .audit
        .sinks
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    if config.governance.audit.enabled
        && audit_sink_kinds.contains(crate::builtins::audit_local_file::PLUGIN_ID)
    {
        let path = config
            .governance
            .audit
            .sinks
            .iter()
            .find(|s| s.kind == crate::builtins::audit_local_file::PLUGIN_ID)
            .and_then(|s| s.config.get("path"))
            .and_then(|v| v.as_str())
            .map(std::path::PathBuf::from)
            .or_else(|| {
                config
                    .plugins
                    .iter()
                    .find(|e| e.id == crate::builtins::audit_local_file::PLUGIN_ID)
                    .and_then(|e| e.config.get("path"))
                    .and_then(|v| v.as_str())
                    .map(std::path::PathBuf::from)
            })
            .unwrap_or_else(|| std::path::PathBuf::from("./mcpg-audit.log"));
        let plugin = crate::builtins::audit_local_file::LocalFileAuditSink::open(&path)
            .with_context(|| format!("opening built-in audit log at {}", path.display()))?;
        info!(
            audit_log_path = %path.display(),
            "opened built-in audit local-file sink"
        );
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
            crate::builtins::audit_local_file::DESCRIPTOR_YAML,
            &[],
            (),
            |registry, _host| {
                registry.register_audit_sink(plugin, mcpg_plugin_protocol::PluginTier::Native)
            },
        )?;
    }

    // The built-in http_route plugin. Registered
    // by default; operators opt out by setting
    // `plugins[?].http_route.disabled: true` with the
    // matching `id`. Surface is namespaced under
    // `/plugins/dev.mcpg.builtin.http.status/status/*` so it can
    // never collide with the gateway's own `/healthz`.
    {
        let entry = config
            .plugins
            .iter()
            .find(|e| e.id == "dev.mcpg.builtin.http.status");
        let http_route_cfg = entry.and_then(|e| e.http_route.as_ref());
        let disabled = http_route_cfg.is_some_and(|h| h.disabled);
        if disabled {
            info!("built-in plugin dev.mcpg.builtin.http.status disabled via plugins[]");
        } else {
            let plugin = crate::builtins::http_status::HttpStatusPlugin::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            );
            let overrides = http_route_cfg
                .map(|h| mcpg_plugin_host::HttpRouteOverrides {
                    max_body_bytes: h.max_body_bytes,
                    requires_identity: h.requires_identity,
                    // Override-mode for the built-in is refused by
                    // design — the built-in doesn't declare
                    // `http_route_serve`, and it makes
                    // no sense at a product level (there's nothing
                    // to override to the top level; the built-in's
                    // paths are relative to its namespaced mount).
                    // Propagate anyway for the registry's
                    // guardrail to fire if an operator really sets
                    // it, so the error message stays precise.
                    allow_path_override: h.allow_path_override,
                })
                .unwrap_or_default();
            mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
                crate::builtins::http_status::DESCRIPTOR_YAML,
                &[],
                (),
                |registry, _host| {
                    registry.register_http_route_with_overrides(
                        crate::builtins::http_status::ENTITY_NAME,
                        plugin,
                        mcpg_plugin_protocol::PluginTier::Native,
                        overrides,
                        // The built-in declares no typed capabilities, so an
                        // operator who sets allow_path_override is refused by
                        // the gate (which now keys on the typed set).
                        &[],
                    )
                },
            )?;
        }
    }

    // Kafka (binding `kind: kafka` + watch `kind: kafka_topic`) is a
    // runtime-loaded cdylib plugin (`dev.mcpg.backend.kafka`), not
    // statically linked into the gateway — this keeps rdkafka /
    // sasl2 / librdkafka out of the `mcpg` build.
    // The plugin's connection config is injected into its
    // `plugins[]` row from the kafka bindings (see the kafka
    // config-injection block in the plugin-loading section below); its
    // backend + watch entities register through the generic native
    // loader, and each kafka binding's profile registers through the
    // generic dynamic-backend `register_profile` pass after loading.

    // NATS (binding `kind: nats` + watch `kind: nats_topic`) is a
    // runtime-loaded cdylib plugin (`dev.mcpg.backend.nats`) — no longer
    // statically linked into the gateway (dropped the `async-nats` dep
    // from the `mcpg` build). The plugin connects lazily from the
    // `url`/`credentials_path` injected into its `plugins[]` row
    // (derived from the NATS bindings); its backend + watch entities
    // register through the generic native loader, and each NATS
    // binding's profile registers through the generic dynamic-backend
    // `register_profile` pass after loading.

    // SQL (binding `kind: sql` + watch `sql_polling` / `postgres_listen_notify`)
    // is a runtime-loaded cdylib plugin (`dev.mcpg.backend.sql`) — no longer
    // statically linked into the gateway (that dropped sqlx + the sql crate
    // from the `mcpg` build). Its entities register through the generic native
    // loader; each SQL binding's profile registers through the generic
    // dynamic-backend `register_profile` pass (the cdylib validates `c.spec`
    // there, surfacing `InvalidSpec` at boot — see
    // `backends::dynamic_register_spec`). `sql_tx`/`sql_await` pipeline steps
    // resolve the backend via `registry.backend("sql")` +
    // `BackendPlugin::execute_transaction` / `execute`.
    // All transport backends — http, kafka, nats, sql, and the 5 LLM
    // providers (17 kinds) — are runtime-loaded cdylib plugins now. None
    // is statically linked into the gateway: each is registered by the
    // generic native plugin loader from its `plugins[]` row, and
    // each binding's profile is wired by the generic dynamic-backend
    // `register_profile` pass (`backends::dynamic_register_spec`, which
    // maps every migrated `BackendImpl` variant — incl. http, which threads
    // the server-level `allow_private_backends` SSRF flag into its spec).
    // The plugins own their own validation (at register_profile), cred
    // resolution, SSRF/DNS-rebinding guards, and streaming.
    //
    // command / grpc / graphql / mock / soap dispatch via their cdylib
    // plugins through `execute_envelope_plugin` against the registered plugin.

    // Register identity plugins (OIDC first, then JWKS as fallback).
    // The plugin chain runs in-order; first `Resolved` wins.
    // Same override rule as the observability pair: an explicit `plugins[]`
    // artifact for this id is the signed copy and takes the slot. The
    // gateway still links the crate — its config types and discovery-URL
    // safety checks are part of the config schema — but the runtime plugin
    // it registers steps aside.
    // OIDC identity is NOT linked into this binary either: `dev.mcpg.identity
    // .oidc` ships as a signed cdylib, so a config that asks for it declares
    // the artifact in `plugins[]`. Unlike a telemetry sink, a missing identity
    // provider is not a soft failure — requests would arrive unauthenticated —
    // so this refuses the boot rather than warning.
    if oidc_resolver.is_some()
        && !registry
            .identity_plugin_ids()
            .iter()
            .any(|id| id == crate::runtime::identity::oidc::PLUGIN_ID)
    {
        anyhow::bail!(
            "`access.oauth` configures OIDC identity, but no identity plugin is \
             registered under {id:?}. It ships as a cdylib: add a `plugins[]` \
             entry with `source.path`/`source.oci` for it (the gateway images \
             bake it at /usr/local/lib/mcpg/plugins/{id}/plugin.so). Refusing to \
             boot rather than serve requests with the configured identity \
             provider missing.",
            id = crate::runtime::identity::oidc::PLUGIN_ID,
        );
    }
    if let Some(verifier) = jwt_verifier {
        let jwt_plugin = crate::runtime::identity_plugin::JwtIdentityPlugin::new(verifier.clone());
        registry.register_identity(
            Box::new(jwt_plugin),
            mcpg_plugin_protocol::PluginTier::Native,
            serde_json::json!({}),
        )?;
        info!("JWT/JWKS identity plugin registered in chain");
    }

    // The four payment plugins (`dev.mcpg.payment.{mpp,x402,ucp,acp}`)
    // are distributed as cdylibs and loaded via `plugins[*]`
    // like every other tool-gate plugin. Operators author the plugin's
    // typed config — including the `tools` map keyed by binding name —
    // directly under `plugins[*].config`, which the cdylib's
    // `from_config_json` factory deserialises.

    // `mcpg-plugin-reliability-circuit-breaker` ships as an externally-
    // distributed OCI cdylib. Operators configure
    // it via `plugins[]` with `config:` carrying
    // `failure_threshold`, `cooldown_ms`, `half_open_max_inflight`,
    // `per_tool`.

    // `mcpg-plugin-reliability-response-cache` ships as an externally-
    // distributed OCI cdylib. Operators configure
    // it via `plugins[]` with `default_ttl_ms`, `max_entries`,
    // `cache_scope`, and `per_tool` under `config:`.

    // `mcpg-plugin-security-ip-allowlist` ships as an externally-
    // distributed OCI cdylib. Operators opt in
    // via `plugins[...].source.oci`.

    // `mcpg-plugin-reliability-rate-limit` ships as an externally-
    // distributed OCI cdylib. Operators opt in
    // via `plugins[*].source.oci`. The separate in-gateway
    // `runtime::rate_limit::InMemoryRateLimiter` continues to use
    // `config.rate_limit` — that's a different rate-limit surface
    // (binding-scoped) and is unaffected.

    // `mcpg-plugin-security-guardrails` ships as an externally-distributed
    // OCI cdylib. Operators configure hooks via
    // `plugins[*].config` with the same `pre_execution` /
    // `post_execution` schema.

    // `mcpg-plugin-observability-call-logger` ships as an externally-distributed
    // OCI cdylib. Operators opt in by adding an
    // entry under `plugins[]` with `source.oci` pointing at the
    // published artefact. The plugin-loader loop below handles the
    // load — no static registration path remains.

    // `mcpg-plugin-integration-webhook` ships as an externally-distributed
    // OCI cdylib. Operators configure endpoints
    // + circuit-breaker tuning via `plugins[*].config`. The
    // plugin declares `required_capabilities:
    // [network_outbound]`, so the entry's
    // `plugins[].granted_capabilities` must list the grant or
    // `FirstPartyRegistrar::with_grants` refuses the plugin at load.

    // `mcpg-plugin-observability-audit` ships as an externally-distributed OCI
    // cdylib. Operators opt in by adding an entry
    // under `plugins[]` with `source.oci` pointing at the
    // published artefact. The plugin-loader loop below handles the load.

    if !config.plugins.is_empty() {
        info!(entries = config.plugins.len(), "plugin system enabled");

        // Per-entry signature posture is the source of truth. Each
        // plugin entry carries its own
        // `signature.{policy, sha256, trusted_keys[].pem}`;
        // missing fields fall back to the gateway-wide default
        // `gateway.plugin_registry.default_signature_policy`.
        // The single registry-wide revocation list (loaded once
        // here) layers on top of every entry's verify pass — a
        // matched SHA-256 refuses the load even when the
        // signature itself is valid.
        let default_policy = config.gateway.plugin_registry.default_signature_policy;
        let revocation_list = load_revocation_list(&config.gateway.plugin_registry)?;

        // Resolve `env://` / `file://` /
        // (operator-bound) `vault://` references in each plugin
        // entry's `config` JSON before the entry gets loaded. Uses
        // the secret-provider registry wired up earlier in this
        // function; consults every bound scheme through the
        // `resolve_secret_refs` walker. Fail-closed: any sink
        // returning an error halts startup with a precise
        // plugin-id + ref message. Unbound-scheme strings (URLs
        // inside configs, custom schemes the operator hasn't
        // bound) pass through untouched — the walker's
        // `skipped_schemes` field makes them visible in the
        // startup log for debugging.
        //
        // The resolved Vec shadows `config.plugins` for
        // the rest of this function; the source config stays
        // untouched (can't mutate `&AppConfig`), which also makes
        // it easy to log "what the operator wrote" separately
        // from "what we expanded it into".
        let mut resolved_entries = config.plugins.clone();
        // Inline-config override for the cluster coordinator: when
        // the operator writes `cluster: { kind: redis,
        // url: ... }` at the top level, that block IS the source of
        // truth for the plugin's runtime config — it replaces any
        // `config:` carried on the matching `plugins[]` row.
        // Lets operators keep the cdylib/OCI declaration in
        // `plugins[]` (technical) and the runtime knobs in
        // `cluster` (operational), without duplication.
        if let Some(coordinator_plugin_id) = config.cluster.plugin_id() {
            let inline = serde_json::Value::Object(config.cluster.config.clone());
            let mut matched = false;
            for entry in resolved_entries.iter_mut() {
                if entry.id == coordinator_plugin_id {
                    entry.config = inline.clone();
                    matched = true;
                }
            }
            if !matched {
                anyhow::bail!(
                    "cluster.kind='{kind}' selects plugin \
                     '{coordinator_plugin_id}' but no `plugins[]` row \
                     declares that plugin id. Add an entry that points at the \
                     cdylib (source.oci or source.path).",
                    kind = config.cluster.kind,
                );
            }
        }

        // Backend-plugin migration: kafka cdylib config injection.
        // Kafka connection params (`bootstrap_servers` / `group_id`)
        // live on the kafka *bindings* (`BackendImpl::Kafka`, validated
        // to agree across bindings by `validate_kafka_binding_consistency`).
        // The runtime-loaded cdylib reads them from its
        // `plugins[]` `config:` instead, so — mirroring the
        // cluster-coordinator single-source-of-truth injection above —
        // derive them from the first kafka binding and inject into the
        // matching entry. Operators declare the cdylib location in
        // `plugins[]` (source.oci/path); a kafka binding with no
        // matching entry fails fast (kafka is no longer statically
        // linked into the gateway).
        if let Some(kafka_conn) = config.all_bindings().find_map(|(_, b)| {
            (b.backend.kind == "kafka")
                .then(|| {
                    serde_json::from_value::<crate::config::KafkaBackendConfig>(
                        serde_json::Value::Object(b.backend.spec.clone()),
                    )
                    .ok()
                })
                .flatten()
        }) {
            const KAFKA_PLUGIN_ID: &str = "dev.mcpg.backend.kafka";
            let injected = serde_json::json!({
                "bootstrap_servers": kafka_conn.bootstrap_servers,
                "group_id": kafka_conn.group_id,
            });
            let mut matched = false;
            for entry in resolved_entries.iter_mut() {
                if entry.id == KAFKA_PLUGIN_ID {
                    entry.config = injected.clone();
                    matched = true;
                }
            }
            if !matched {
                anyhow::bail!(
                    "kafka binding(s) are configured but no `plugins[]` row \
                     declares plugin id '{KAFKA_PLUGIN_ID}'. Kafka is now a runtime-loaded \
                     cdylib plugin — add an entry pointing at the cdylib (source.oci or \
                     source.path); bootstrap_servers + group_id are taken from the kafka \
                     bindings, so the entry needs no `config:` block.",
                );
            }
        }

        // Backend-plugin migration: NATS cdylib config injection. Same
        // single-source-of-truth pattern as kafka above — derive the
        // connection (`url` / `credentials_path`) from the first NATS
        // binding and inject into the `dev.mcpg.backend.nats` entry. The
        // plugin connects lazily on first use; the gateway no longer
        // builds the NATS client itself.
        if let Some(nats_conn) = config.all_bindings().find_map(|(_, b)| {
            (b.backend.kind == "nats")
                .then(|| {
                    serde_json::from_value::<crate::config::NatsBackendConfig>(
                        serde_json::Value::Object(b.backend.spec.clone()),
                    )
                    .ok()
                })
                .flatten()
        }) {
            const NATS_PLUGIN_ID: &str = "dev.mcpg.backend.nats";
            let injected = serde_json::json!({
                "url": nats_conn.url,
                "credentials_path": nats_conn.credentials_path,
            });
            let mut matched = false;
            for entry in resolved_entries.iter_mut() {
                if entry.id == NATS_PLUGIN_ID {
                    entry.config = injected.clone();
                    matched = true;
                }
            }
            if !matched {
                anyhow::bail!(
                    "nats binding(s) are configured but no `plugins[]` row \
                     declares plugin id '{NATS_PLUGIN_ID}'. NATS is now a runtime-loaded \
                     cdylib plugin — add an entry pointing at the cdylib (source.oci or \
                     source.path); url + credentials_path are taken from the nats bindings, \
                     so the entry needs no `config:` block.",
                );
            }
        }

        // Per-plugin host-FFI RESOURCE allowlist — derived from the
        // PRE-resolution config: the concrete `scheme://resource` secret/config
        // URIs each entry statically references. `resolve_config_value` below
        // substitutes these in place, so the capture MUST run first. Keyed by
        // `entry.id` (the bridge alias the host-services callbacks carry), this
        // scopes a cdylib's `resolve_secret`/`config_snapshot` to the resources
        // its own config names — holding `SecretsRead{env}` no longer reads
        // EVERY env var. Empty set / absent alias ⇒ fail-closed deny.
        for entry in resolved_entries.iter() {
            registry.record_resource_resolve_allowlist(
                entry.id.clone(),
                mcpg_plugin_host::secret_resolver::collect_resource_refs(&entry.config),
            );
        }

        // CEL pass first, secret-URI pass second — applied uniformly
        // to every string leaf via `config::resolver::resolve_config_value`.
        let mut secret_refs_expanded: usize = 0;
        let mut secret_skipped_schemes = std::collections::BTreeSet::<String>::new();
        for entry in resolved_entries.iter_mut() {
            let report =
                crate::config::resolver::resolve_config_value(&mut entry.config, &registry)
                    .await
                    .map_err(|e| anyhow::anyhow!("plugin '{}' config: {e}", entry.id))?;
            secret_refs_expanded += report.expanded;
            secret_skipped_schemes.extend(report.skipped_schemes);
            resolved_secret_refs.extend(report.resolved_refs);
        }
        let secret_skipped_schemes: Vec<String> = secret_skipped_schemes.into_iter().collect();
        info!(
            plugins = resolved_entries.len(),
            expanded = secret_refs_expanded,
            skipped_schemes = ?secret_skipped_schemes,
            "plugin-entry secret refs resolved"
        );

        // Audit the secret-resolution pass.
        // Deliberately carries counts + scheme names only; never
        // the resolved values. Compliance contract: operators +
        // auditors reconstruct "which boots expanded which
        // schemes" without the audit trail itself becoming a
        // secret-leak vector. Honours `on_failure` like the
        // gateway_started event — a fail_closed + sink failure
        // here halts startup with the usual bail message.
        let audit_policy = match config.governance.audit.on_failure {
            crate::config::AuditOnFailure::FailClosed => {
                mcpg_plugin_host::AuditEmitPolicy::FailClosed
            }
            crate::config::AuditOnFailure::FailOpen => mcpg_plugin_host::AuditEmitPolicy::FailOpen,
        };
        let secrets_event = mcpg_plugin_host::audit_events::lifecycle_event(
            "mcpg.lifecycle.secrets_resolved",
            mcpg_plugin_protocol::audit::AuditOutcome::Success,
            serde_json::json!({
                "plugin_entries_walked": resolved_entries.len(),
                "refs_expanded": secret_refs_expanded,
                "skipped_schemes": secret_skipped_schemes,
            }),
        );
        if let Err(failure) = registry
            .emit_audit_event_enforced(&secrets_event, audit_policy)
            .await
        {
            anyhow::bail!(
                "audit `on_failure: fail_closed` tripped during secret \
                 resolution — refusing to serve without an audit record \
                 of which schemes expanded: {failure}"
            );
        }

        // Audit signal for any plugin entry whose resolved
        // signature policy is `disabled` — the development
        // escape hatch should never go unnoticed in
        // compliance trails. A single event lists all such
        // plugin ids; an empty list (the common case) emits
        // nothing.
        let disabled_policy_plugin_ids: Vec<String> = resolved_entries
            .iter()
            .filter(|e| {
                let policy = e
                    .signature
                    .as_ref()
                    .and_then(|s| s.policy)
                    .unwrap_or(default_policy);
                matches!(policy, crate::config::SignaturePolicy::Disabled)
            })
            .map(|e| e.id.clone())
            .collect();
        if !disabled_policy_plugin_ids.is_empty() {
            tracing::warn!(
                plugin_ids = ?disabled_policy_plugin_ids,
                "plugin entries are loading with signature policy `disabled` — \
                 development escape hatch is active"
            );
            let policy_event = mcpg_plugin_host::audit_events::lifecycle_event(
                "governance.plugin.signature_policy_disabled",
                mcpg_plugin_protocol::audit::AuditOutcome::Success,
                serde_json::json!({
                    "plugin_ids": disabled_policy_plugin_ids,
                    "default_signature_policy": default_policy.as_label(),
                }),
            );
            if let Err(failure) = registry
                .emit_audit_event_enforced(&policy_event, audit_policy)
                .await
            {
                anyhow::bail!(
                    "audit `on_failure: fail_closed` tripped while \
                     emitting signature_policy_disabled event: {failure}"
                );
            }
        }

        // Library load dedupe — when multiple
        // entries point at the same cdylib (multi-instance pattern,
        // e.g. two `cedar` aliases bound to different tenants), the
        // host loads `dlopen` + `mcpg_plugin_register()` once and
        // reuses the resulting `Arc<LoadedNativePlugin>` across
        // entries. Each entry still gets its own per-entry `make()`
        // call so plugin handles + per-entry state remain distinct.
        // Keyed on the canonicalized source path.
        //
        // Currently scoped to the raw cdylib path (`source.path`
        // pointing at a `.so`/`.dylib`). The packaged-plugin path
        // (`load_packaged_plugin`) has its own per-id unpack cache
        // that already keeps `entry.id`-distinct cdylibs apart;
        // tighter sharing across packaged aliases is a follow-up.
        let mut native_library_cache: std::collections::HashMap<
            String,
            std::sync::Arc<mcpg_plugin_host::native_loader::LoadedNativePlugin>,
        > = std::collections::HashMap::new();

        // Backend-plugin migration: snapshot the backend kinds already
        // registered by the static blocks above (http/sql/nats/kafka/
        // llm-*) so we can tell which backends arrive *dynamically* via
        // the plugin-entry loaders below. The diff (post-load kinds minus
        // this snapshot) is exactly the set of cdylib-loaded backends
        // whose per-binding profiles the generic registration pass must
        // wire up — the static blocks already registered their own.
        let static_backend_kinds: std::collections::HashSet<String> =
            registry.backend_kinds().into_iter().collect();

        // Process each configured plugin entry
        for entry in &resolved_entries {
            // OCI source — pull the artefact from the registry
            // (with pull cache) and normalise to a local file, then
            // fall through to the packaged-plugin path.
            if let Some(oci_ref) = entry.source.oci.as_deref() {
                enforce_oci_integrity_anchor(entry, oci_ref, &config.gateway.plugin_registry)?;
                let pulled =
                    resolve_oci_source(oci_ref, &entry.id, &config.gateway.plugin_registry)?;
                // Temporarily treat the pulled file as if the
                // operator had specified `source.path: <pulled>`.
                let patched = patch_entry_with_local_path(entry, pulled);
                load_packaged_plugin(
                    &mut registry,
                    &patched,
                    &config.gateway.plugin_registry,
                    revocation_list.clone(),
                    host_services_late.clone(),
                )?;
                continue;
            }

            // Packaged plugin (.zip). Unpack to the OS temp dir and
            // dispatch to the native or wasm loader based on the
            // embedded descriptor's runtime class; the descriptor
            // cross-check happens inside `FirstPartyRegistrar::register_with_descriptor`
            // so a tampered zip whose runtime manifest disagrees
            // with the descriptor fails startup loudly.
            if entry
                .source
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with(".zip"))
            {
                load_packaged_plugin(
                    &mut registry,
                    entry,
                    &config.gateway.plugin_registry,
                    revocation_list.clone(),
                    host_services_late.clone(),
                )?;
                continue;
            }
            match entry.kind.as_str() {
                "native" => {
                    if let Some(path) = &entry.source.path {
                        let artifact_path = std::path::Path::new(path);
                        if !artifact_path.exists() {
                            return Err(anyhow::anyhow!(
                                "plugin '{}': artifact not found at '{}'",
                                entry.id,
                                path,
                            ));
                        }

                        let verify_opts = derive_native_verify_options_for_entry(
                            entry,
                            &config.gateway.plugin_registry,
                            revocation_list.clone(),
                        )?;

                        // Canonical-path key for
                        // the per-boot library cache. `canonicalize`
                        // resolves symlinks + `.`/`..` so two operator
                        // entries that spell the same artifact path
                        // differently still share one library load.
                        let fingerprint = artifact_path
                            .canonicalize()
                            .map(|p| format!("path:{}", p.display()))
                            .unwrap_or_else(|_| format!("path:{}", artifact_path.display()));
                        let loaded = if let Some(cached) = native_library_cache.get(&fingerprint) {
                            info!(
                                plugin_alias = %entry.id,
                                path = %path,
                                fingerprint = %fingerprint,
                                "native plugin cdylib reused from per-boot library cache (multi-instance dedupe)"
                            );
                            cached.clone()
                        } else {
                            let fresh = mcpg_plugin_host::native_loader::load_native_plugin(
                                artifact_path,
                                &verify_opts,
                                derive_ffi_limits_for_entry(entry),
                            )?;
                            info!(
                                plugin_alias = %entry.id,
                                path = %path,
                                hash = %fresh.meta.artifact_hash.as_deref().unwrap_or(""),
                                signature_verified = fresh.meta.signature_verified,
                                abi_version = fresh.registration.abi_version,
                                "native plugin cdylib loaded"
                            );
                            native_library_cache.insert(fingerprint.clone(), fresh.clone());
                            fresh
                        };
                        let plugin_cfg = entry.config.clone();
                        // Capability cross-check: if the cdylib
                        // ships a sidecar `<artifact>.plugin.yaml`, hard-fail at
                        // boot when its typed `required_capabilities` disagree
                        // with the binary's FFI-declared set — packaging drift
                        // (descriptor says one thing, the compiled
                        // `declare_plugin! { capabilities: }` another) must
                        // surface here, not at first request. No sidecar = no
                        // cross-check (the FFI decls are authoritative).
                        let cap_sidecar = std::path::PathBuf::from(format!(
                            "{}.plugin.yaml",
                            artifact_path.display()
                        ));
                        if cap_sidecar.exists() {
                            let descriptor = mcpg_plugin_host::load_descriptor(&cap_sidecar)
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "plugin '{}': sidecar descriptor at {} — {}",
                                        entry.id,
                                        cap_sidecar.display(),
                                        e,
                                    )
                                })?;
                            mcpg_plugin_host::cross_check_cdylib_capabilities(
                                &entry.id,
                                &descriptor.required_capabilities,
                                &loaded.required_capabilities,
                            )?;
                        }
                        // Run the registered policy_engine chain
                        // at decision_point=plugin.lifecycle.register
                        // before committing to register adapters.
                        // On Deny, refuse the entry — the cdylib
                        // is unloaded when `loaded` drops out of
                        // scope.
                        enforce_plugin_registration_policy(
                            &registry,
                            &loaded,
                            plugin_cfg.clone(),
                            &entry.id,
                        )
                        .await?;
                        // Thread the late-bound HostServices into every
                        // adapter so plugin → host calls (resolve_secret,
                        // audit_event, metric_emit, …) reach the gateway's real
                        // implementation. Resolved fresh per entry so each
                        // `HostBridge::with_services` Arc points at whatever is
                        // bound at the moment (currently `NullHostServices` —
                        // the host services swap to the real impl after
                        // `build_plugin_registry` returns).
                        let svc = host_services_late.resolve();
                        // Record the operator-granted typed capabilities under
                        // this entry's alias (entry.id — the same alias the host
                        // bridge carries into every
                        // resolve_secret/issue_credential/config_snapshot
                        // callback) so GatewayHostServices can filter per call,
                        // not just validate once at boot.
                        registry.record_granted_capabilities(
                            entry.id.clone(),
                            entry.granted_capabilities.clone(),
                        );
                        // Config-origin `cred://` allowlist: a cdylib may
                        // resolve only the credential issuers — and the exact
                        // targets — its own config references. A compromised
                        // binary cannot hand the host an arbitrary `cred://`
                        // (unreferenced issuer OR an unreferenced target on a
                        // referenced issuer) and exfiltrate it.
                        registry.record_cred_resolve_allowlist(
                            entry.id.clone(),
                            mcpg_plugin_host::credential_resolver::collect_cred_issuers(
                                &entry.config,
                            ),
                        );
                        registry.record_cred_resolve_ref_allowlist(
                            entry.id.clone(),
                            mcpg_plugin_host::credential_resolver::collect_cred_refs(&entry.config),
                        );
                        entities::register_native_entities(
                            &mut registry,
                            &loaded,
                            svc,
                            &entities::NativeEntryOptions {
                                alias: entry.id.clone(),
                                config: plugin_cfg.clone(),
                                inline_dispatch: entry.inline_dispatch,
                                enforce: entry.enforce,
                                http_route: entities::native_http_route_overrides(entry),
                            },
                        )?;
                    } else {
                        warn!(
                            plugin_id = %entry.id,
                            "native plugin entry has no source.path; skipping"
                        );
                    }
                }
                "wasm" => {
                    if let Some(path) = &entry.source.path {
                        let artifact_path = std::path::Path::new(path);
                        if !artifact_path.exists() {
                            return Err(anyhow::anyhow!(
                                "plugin '{}': wasm artifact not found at '{}'",
                                entry.id,
                                path,
                            ));
                        }

                        #[cfg(feature = "wasm-plugins")]
                        {
                            let wasm_engine = mcpg_plugin_host::wasm::create_wasm_engine()
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "plugin '{}': failed to create wasm engine: {}",
                                        entry.id,
                                        e,
                                    )
                                })?;

                            let load_options = mcpg_plugin_host::wasm::WasmLoadOptions {
                                // Hold the in-process Wasm guest to the same
                                // integrity bar as a native cdylib: SHA-256 pin
                                // + Ed25519 signature (per-entry policy) +
                                // revocation. Built from the same per-entry
                                // signature config the native loader uses.
                                verify: derive_native_verify_options_for_entry(
                                    entry,
                                    &config.gateway.plugin_registry,
                                    revocation_list.clone(),
                                )?,
                                limits: {
                                    let mut limits =
                                        mcpg_plugin_host::wasm::WasmResourceLimits::default();
                                    if let Some(rl) = &entry.limits {
                                        if let Some(mem) = rl.memory_mb {
                                            limits.memory_limit_bytes = mem as usize * 1024 * 1024;
                                        }
                                        if let Some(fuel) = rl.fuel {
                                            limits.fuel_per_invocation = fuel;
                                        }
                                        if let Some(timeout) = rl.timeout_ms {
                                            limits.timeout_ms = timeout;
                                        }
                                    }
                                    limits
                                },
                            };

                            let artifact = mcpg_plugin_host::wasm::load_wasm_component(
                                &wasm_engine,
                                artifact_path,
                                &load_options,
                            )
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "plugin '{}': failed to load wasm component: {}",
                                    entry.id,
                                    e,
                                )
                            })?;

                            // Load the sidecar plugin.yaml — every
                            // runtime-loaded wasm artifact must ship
                            // `<artifact>.plugin.yaml` next to it. The
                            // descriptor is the authoritative source
                            // for class / protocol_version; the
                            // registrar cross-checks it against the
                            // wasm-reported manifest so a swapped
                            // artifact cannot masquerade as a
                            // different plugin.
                            let sidecar_path = std::path::PathBuf::from(format!(
                                "{}.plugin.yaml",
                                artifact_path.display()
                            ));
                            let descriptor = mcpg_plugin_host::load_descriptor(&sidecar_path)
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "plugin '{}': sidecar descriptor at {} — {}",
                                        entry.id,
                                        sidecar_path.display(),
                                        e,
                                    )
                                })?;

                            // Cross-check descriptor.id against the entry's
                            // effective manifest id (`ref` if set,
                            // else `id`). Single-instance
                            // configs where `entry.id == manifest.id`
                            // still pass because `ref_or_id()` falls
                            // back to `id`.
                            let expected_ref = entry.ref_or_id();
                            if descriptor.id != expected_ref {
                                return Err(anyhow::anyhow!(
                                    "plugin alias '{}': sidecar descriptor reports manifest id {:?} \
                                     but entry expects ref '{}'",
                                    entry.id,
                                    descriptor.id,
                                    expected_ref,
                                ));
                            }

                            let entry_class = entry.class.clone();
                            let entry_config = entry.config.clone();
                            let entry_enforce = entry.enforce;
                            let descriptor_class = descriptor.class;
                            let entry_id_for_err = entry.id.clone();

                            mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry)
                                .register_with_descriptor(&descriptor, &entry.granted_capabilities, (), move |registry, _host| {
                                    use mcpg_plugin_protocol::PluginClass;
                                    match descriptor_class {
                                        PluginClass::ToolGate => {
                                            let p = mcpg_plugin_host::wasm::WasmToolGatePlugin::new(
                                                wasm_engine,
                                                artifact,
                                            )?;
                                            registry.register_tool_gate_with_enforce(
                                                Box::new(p),
                                                mcpg_plugin_protocol::PluginTier::Wasm,
                                                entry_config,
                                                entry_enforce,
                                            )
                                        }
                                        PluginClass::Transform => {
                                            let p = mcpg_plugin_host::wasm::WasmTransformPlugin::new(
                                                wasm_engine,
                                                artifact,
                                            )?;
                                            registry.register_transform(
                                                Box::new(p),
                                                mcpg_plugin_protocol::PluginTier::Wasm,
                                                entry_config,
                                            )
                                        }
                                        PluginClass::IdentityProvider => {
                                            let p = mcpg_plugin_host::wasm::WasmIdentityPlugin::new(
                                                wasm_engine,
                                                artifact,
                                            )?;
                                            registry.register_identity(
                                                Box::new(p),
                                                mcpg_plugin_protocol::PluginTier::Wasm,
                                                entry_config,
                                            )
                                        }
                                        other => Err(anyhow::anyhow!(
                                            "plugin '{}': wasm artifacts cannot implement class {other}",
                                            entry_id_for_err,
                                        )),
                                    }
                                })?;

                            info!(
                                plugin_id = %entry.id,
                                path = %path,
                                class = %entry_class,
                                "wasm plugin loaded and registered"
                            );
                        }

                        #[cfg(not(feature = "wasm-plugins"))]
                        {
                            return Err(anyhow::anyhow!(
                                "plugin '{}': wasm plugin support requires the 'wasm-plugins' \
                                 feature flag; rebuild with --features wasm-plugins",
                                entry.id,
                            ));
                        }
                    } else {
                        warn!(
                            plugin_id = %entry.id,
                            "wasm plugin entry has no source.path; skipping"
                        );
                    }
                }
                _ => {
                    // Already validated in config, but be defensive
                    return Err(anyhow::anyhow!(
                        "plugin '{}': unsupported kind '{}'",
                        entry.id,
                        entry.kind,
                    ));
                }
            }
        }

        // Capability expansion. Now that every plugin
        // (incl. the openapi backend, whose `make` parsed its `sources`)
        // is loaded, ask it which tools to auto-expose and synthesize an
        // ordinary tool binding per result. Injected into the config tool
        // list BEFORE the register-profile pass below (so each synthetic
        // binding's profile registers via the same path) and before the
        // capability registry is built downstream (so they appear in
        // tools/list). On reload this re-runs against the fresh config.
        let synthetic = expand_openapi_bindings(config, &registry).await?;
        config.mcp.capabilities.tools.extend(synthetic.tools);
        config
            .mcp
            .capabilities
            .resource_templates
            .extend(synthetic.resource_templates);

        // Generic plugin-agnostic substrate (runs alongside the typed
        // per-kind paths; nothing downstream reads its results yet —
        // it duplicates guarantees the typed enum gives for free so the
        // typed arms can later be deleted without losing them):
        //
        //  - Boot guard: every binding's `kind` must resolve to a
        //    registered BACKEND plugin (`registry.backend(kind)`), which
        //    is the generic "is this a backend?" predicate. An unknown or
        //    non-backend kind fails closed at boot with a clear message
        //    listing the loaded backend kinds — stronger than the serde
        //    "unknown variant" the typed enum gave (it also catches a
        //    class mismatch the enum couldn't express).
        //  - Unconditional SSRF inject: `allow_private_backends` is
        //    stamped onto EVERY binding spec, not just the net kinds the
        //    typed `dynamic_register_spec` injects it into — so no kind
        //    can silently miss the toggle and fail open. Idempotent: the
        //    per-kind inject already wrote the same key/value.
        //  - Per-binding `cred://`/resource allowlist: the config-origin
        //    cred/resource collectors run over each binding's spec and
        //    extend the owning backend plugin's allowlist (keyed by its
        //    host-services bridge alias). A binding's `cred://` refs are
        //    as config-origin as the plugin entry's own; omitting this
        //    fails closed (deny) and would break legitimate per-binding
        //    credentials.
        for (_, binding) in config.all_bindings() {
            let Some(kind) = crate::backends::binding_plugin_kind(&binding.backend) else {
                // Pipeline / federated pseudo-bindings have no backend
                // kind of their own; their steps are guarded separately.
                continue;
            };
            // LLM bindings carry the underscore config kind but register under
            // the dotted plugin kind — resolve the registry key the same way
            // dispatch does so a valid LLM binding is not falsely rejected.
            let lookup_kind = crate::backends::registry_lookup_kind(&binding.backend)
                .unwrap_or_else(|| kind.to_owned());
            if registry.backend(&lookup_kind).is_none() {
                return Err(anyhow::anyhow!(
                    "binding '{}' names backend kind '{}', but no backend plugin is \
                     registered for it. Loaded backend kinds: [{}]. If '{}' is a plugin \
                     of a different class (e.g. a transform), it cannot back a binding; \
                     if it is a backend, add its `plugins[]` entry (source.oci / \
                     source.path) so the gateway loads it.",
                    binding.name,
                    kind,
                    {
                        let mut kinds = registry.backend_kinds();
                        kinds.sort();
                        kinds.join(", ")
                    },
                    kind,
                ));
            }
            // Materialize the per-binding spec the same way the register
            // pass does, then stamp the SSRF toggle unconditionally and
            // feed the spec to the config-origin allowlist collectors.
            let Some(mut spec) = crate::backends::dynamic_register_spec(
                &binding.backend,
                config.gateway.server.allow_private_backends,
            ) else {
                continue;
            };
            if let Some(map) = spec.as_object_mut() {
                map.entry("allow_private_backends".to_owned())
                    .or_insert(serde_json::Value::Bool(
                        config.gateway.server.allow_private_backends,
                    ));
            }
            if let Some(alias) = registry.backend_alias(&lookup_kind) {
                let alias = alias.to_owned();
                registry.extend_cred_resolve_allowlist(
                    &alias,
                    mcpg_plugin_host::credential_resolver::collect_cred_issuers(&spec),
                );
                registry.extend_cred_resolve_ref_allowlist(
                    &alias,
                    mcpg_plugin_host::credential_resolver::collect_cred_refs(&spec),
                );
                registry.extend_resource_resolve_allowlist(
                    &alias,
                    mcpg_plugin_host::secret_resolver::collect_resource_refs(&spec),
                );
            }
        }

        // Backend-plugin migration — generic per-binding profile
        // registration for dynamically-loaded (cdylib) backends. A
        // backend whose kind was NOT registered by a static block (the
        // `static_backend_kinds` snapshot taken before the loaders) but
        // IS now present in the registry arrived via a plugin-entry
        // loader above. Each binding of such a kind needs its profile
        // registered through the same `register_profile` contract the
        // static blocks use. Mirrors the SQL block (config-ref
        // resolution + secret-ref hint + block_on bridge) so dynamic and
        // static backends present an identical surface to operators.
        for (_, binding) in config.all_bindings() {
            let Some(kind) = crate::backends::binding_plugin_kind(&binding.backend) else {
                continue;
            };
            // LLM bindings carry the underscore config kind but register under
            // the dotted plugin kind; resolve the registry key the same way
            // dispatch does so the per-binding profile is actually registered.
            let lookup_kind = crate::backends::registry_lookup_kind(&binding.backend)
                .unwrap_or_else(|| kind.to_owned());
            if static_backend_kinds.contains(lookup_kind.as_str()) {
                continue; // a static block already registered this kind's profiles
            }
            if registry.backend(&lookup_kind).is_none() {
                continue; // kind not loaded as a plugin — dispatch surfaces the error
            }
            let Some(mut spec) = crate::backends::dynamic_register_spec(
                &binding.backend,
                config.gateway.server.allow_private_backends,
            ) else {
                return Err(anyhow::anyhow!(
                    "dynamic backend '{}' for binding '{}' has no register-profile spec \
                     mapping; add its variant to backends::dynamic_register_spec",
                    kind,
                    binding.name,
                ));
            };
            // Resolve config-time secret refs in the spec (CEL `${env.X}`
            // + bound `scheme://…` URIs), then thread the resolved-ref
            // hint so the plugin's rotation subscription scopes eviction
            // to those URIs — identical to the SQL/HTTP static paths.
            let report = crate::config::resolver::resolve_config_value(&mut spec, &registry)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "resolve config refs in dynamic backend binding '{}': {e}",
                        binding.name
                    )
                })?;
            inject_secret_refs_hint(&mut spec, &report.resolved_refs);
            resolved_secret_refs.extend(report.resolved_refs);
            let name = binding.name.clone();
            let plugin = registry
                .backend(&lookup_kind)
                .expect("backend present (checked above)");
            let host = backend_late_host.clone();
            let result: Result<(), mcpg_plugin_protocol::BackendError> =
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        mcpg_plugin_protocol::BackendPlugin::register_profile(
                            plugin.as_ref(),
                            &name,
                            &spec,
                            host,
                        )
                        .await
                    })
                });
            result.map_err(|e| {
                anyhow::anyhow!(
                    "register dynamic backend binding '{}' (kind {}): {e}",
                    binding.name,
                    kind
                )
            })?;
            info!(
                binding = %binding.name,
                kind = %kind,
                "dynamic backend profile registered"
            );
        }

        // Pipeline steps backed by a cdylib backend need their per-step
        // profile registered the same way a top-level binding does — the
        // binding loop above never descends into `Pipeline.steps`. Resolve
        // each step's kind through the already-loaded registry (no
        // compile-dep, no per-plugin register-block) under the step
        // profile name `{binding}._step_.{step_id}` that dispatch uses.
        fn step_backend_impl(
            step: &crate::config::PipelineStepConfig,
        ) -> Option<crate::config::BackendImpl> {
            use crate::config::PipelineStepConfig;
            // Every backend step carries its plugin kind + flattened spec
            // directly; control-flow steps have no register-profile mapping.
            // The caller guards on `static_backend_kinds` and registry
            // membership, so it is safe to surface every backend kind here.
            match step {
                PipelineStepConfig::Backend(s) => Some(crate::config::BackendImpl {
                    kind: s.kind.clone(),
                    spec: s.spec.clone(),
                }),
                _ => None,
            }
        }

        let pipeline_steps: Vec<(String, crate::config::PipelineStepConfig)> = config
            .all_bindings()
            .filter_map(|(_, binding)| {
                if binding.backend.kind != "pipeline" {
                    return None;
                }
                serde_json::from_value::<crate::config::PipelineBackendConfig>(
                    serde_json::Value::Object(binding.backend.spec.clone()),
                )
                .ok()
                .map(|p| (binding.name.clone(), p.steps))
            })
            .flat_map(|(name, steps)| steps.into_iter().map(move |s| (name.clone(), s)))
            .collect();

        for (binding_name, step) in &pipeline_steps {
            let Some(step_backend) = step_backend_impl(step) else {
                continue; // non-backend step (transform / suspending / nats / …)
            };
            // Read (kind, spec) uniformly so both the typed steps and the
            // generic `kind: backend` step take the same register path.
            let Some((kind, mut spec)) = crate::backends::binding_kind_and_spec(
                &step_backend,
                config.gateway.server.allow_private_backends,
            ) else {
                return Err(anyhow::anyhow!(
                    "pipeline step '{}' in binding '{}' has no register-profile spec mapping",
                    step.id(),
                    binding_name,
                ));
            };
            // LLM steps carry the underscore config kind but register and
            // dispatch under the dotted plugin kind; resolve the registry key
            // the same way dispatch does so the step profile lands where the
            // dispatcher looks for it.
            let lookup_kind = crate::backends::registry_lookup_kind(&step_backend)
                .unwrap_or_else(|| kind.clone());
            if static_backend_kinds.contains(lookup_kind.as_str()) {
                continue; // a static block owns this kind's step profiles
            }
            if registry.backend(&lookup_kind).is_none() {
                continue; // kind not loaded — dispatch surfaces the error
            }
            // Agnostic pipeline-step eligibility: a backend kind may only back
            // a pipeline step when its manifest profile declares
            // `pipeline_capable`. Kinds that leave it false (LLM providers,
            // openapi) fail closed at boot rather than silently misbehaving at
            // dispatch.
            let pipeline_capable = registry
                .backend_profile(&lookup_kind)
                .map(|p| p.pipeline_capable)
                .unwrap_or(false);
            if !pipeline_capable {
                return Err(anyhow::anyhow!(
                    "pipeline step '{}' in binding '{}' uses backend kind '{}', which does \
                     not declare `pipeline_capable` in its manifest backend profile and so \
                     cannot be used as a pipeline step.",
                    step.id(),
                    binding_name,
                    kind,
                ));
            }
            let report = crate::config::resolver::resolve_config_value(&mut spec, &registry)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "resolve config refs in pipeline step '{}' of binding '{}': {e}",
                        step.id(),
                        binding_name
                    )
                })?;
            inject_secret_refs_hint(&mut spec, &report.resolved_refs);
            resolved_secret_refs.extend(report.resolved_refs);
            // A pipeline step's config-origin cred/resource refs are as
            // legitimate as a top-level binding's; extend the owning backend
            // plugin's allowlists so the per-call HostServices gate authorizes
            // them identically whether the kind appears in a binding or a step.
            if let Some(alias) = registry.backend_alias(&lookup_kind) {
                let alias = alias.to_owned();
                registry.extend_cred_resolve_allowlist(
                    &alias,
                    mcpg_plugin_host::credential_resolver::collect_cred_issuers(&spec),
                );
                registry.extend_cred_resolve_ref_allowlist(
                    &alias,
                    mcpg_plugin_host::credential_resolver::collect_cred_refs(&spec),
                );
                registry.extend_resource_resolve_allowlist(
                    &alias,
                    mcpg_plugin_host::secret_resolver::collect_resource_refs(&spec),
                );
            }
            let step_profile = format!("{}._step_.{}", binding_name, step.id());
            let plugin = registry
                .backend(&lookup_kind)
                .expect("backend present (checked above)");
            let host = backend_late_host.clone();
            let result: Result<(), mcpg_plugin_protocol::BackendError> =
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        mcpg_plugin_protocol::BackendPlugin::register_profile(
                            plugin.as_ref(),
                            &step_profile,
                            &spec,
                            host,
                        )
                        .await
                    })
                });
            result.map_err(|e| {
                anyhow::anyhow!(
                    "register pipeline step '{}' of binding '{}' (kind {}): {e}",
                    step.id(),
                    binding_name,
                    kind
                )
            })?;
            info!(
                binding = %binding_name,
                step = %step.id(),
                kind = %kind,
                "dynamic pipeline-step profile registered"
            );
        }
    }

    // Install the cluster coordinator. Singleton. Runs AFTER the `plugins[]`
    // loop so an external coordinator's cdylib (`kind: redis/nats/consul/etcd`)
    // is already registered by the loop above. `kind: single_node` (the
    // default) installs the in-process built-in here; other kinds map to
    // `dev.mcpg.cluster.<kind>` cdylibs that must be declared under `plugins[]`
    // (loaded above). The inline `cluster.*` config block already overrode any
    // `config:` on the matching `plugins[]` row before the loop ran.
    {
        if config.cluster.is_single_node() {
            let plugin = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
            mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry).register(
                crate::builtins::cluster_single_node::DESCRIPTOR_YAML,
                &[],
                (),
                |registry, _host| {
                    registry
                        .register_cluster_backend(plugin, mcpg_plugin_protocol::PluginTier::Native)
                },
            )?;
        } else if let Some(expected_id) = config.cluster.plugin_id() {
            // External coordinator. The plugin registered itself via the
            // `plugins[]` loop above — cross-check it is the expected one.
            let Some(installed) = registry.cluster_backend_plugin_id() else {
                anyhow::bail!(
                    "cluster.kind='{kind}' expects plugin \
                     '{expected_id}' but no cluster_backend plugin is \
                     registered. Declare it under plugins[] so the \
                     gateway can load the cdylib.",
                    kind = config.cluster.kind,
                );
            };
            if installed != expected_id {
                anyhow::bail!(
                    "cluster.kind='{kind}' expects '{expected_id}' \
                     but registered coordinator is '{installed}'",
                    kind = config.cluster.kind,
                );
            }
        } else {
            anyhow::bail!(
                "cluster.kind='{kind}' is not recognized. \
                 Valid kinds: single_node, etcd, consul, nats, redis.",
                kind = config.cluster.kind,
            );
        }
        // Cross-check the coordinator's role vocabulary, fail-closed.
        // The manifest/descriptor `provides` list, the runtime
        // `cluster_provides()` trait method, and the static wiring table
        // are one role vocabulary (cache/kv/bus); this asserts they
        // actually agree.
        if let Some(coordinator) = registry.cluster_backend() {
            cross_check_cluster_provides(coordinator.as_ref(), &config.cluster.kind)?;
            // Vocabulary agreement is necessary but not sufficient: a
            // coordinator that advertises kv/bus but can't serve them over
            // the FFI would otherwise pass boot and silently de-cluster.
            // single_node is in-process (no FFI to probe) and is excluded.
            if !config.cluster.is_single_node() {
                probe_cluster_reachability(
                    coordinator.as_ref(),
                    config.cluster.allow_degraded_boot,
                )
                .await?;
            }
        }
        tracing::debug!(
            kind = %config.cluster.kind,
            coordinator_id = ?registry.cluster_backend_plugin_id(),
            "cluster_backend installed"
        );
    }

    let count = registry.total_count();
    if count > 0 {
        info!(plugin_count = count, "plugin registry initialized");
    }

    // Auto-bind every URI scheme advertised by every registered
    // secret-provider / config-provider plugin to its owning plugin
    // id. There is no `plugin_bindings.{secrets, configs}` operator
    // override map; per-plugin `supported_schemes()` is the source of
    // truth, and the registry's
    // binding map is just a dispatch cache. Built-in env/file
    // schemes were pre-bound above; the auto-bind sweep is
    // additive and skips any already-bound scheme. Refuses boot if
    // two plugins claim the same scheme — operator must pick one
    // or rename.
    registry
        .auto_bind_secret_provider_schemes()
        .with_context(|| "auto-binding secret_provider schemes")?;
    registry
        .auto_bind_config_provider_schemes()
        .with_context(|| "auto-binding config_provider schemes")?;

    // Opt-in post-boot env scrub (`server.scrub_process_env_after_boot`): all
    // config-origin secret resolution is now done (plugin entries + bindings +
    // pipeline steps) and the env secret provider holds its boot snapshot, so
    // remove every process-env var the config referenced via `${env.X}` or
    // `env://X`. A loaded cdylib can then no longer read those secrets through a
    // direct `std::env::var` / shared-process-env read; the host's own env://
    // resolution is unaffected (it reads the snapshot). Names are collected from
    // the ORIGINAL (unmutated) config, so only operator-named secret vars are
    // touched, never system vars. Defense-in-depth, NOT a hard boundary: it does
    // not clear `/proc/self/environ` (the exec-time copy), so a hostile
    // in-process plugin can still recover values there (documented on the flag).
    if config.gateway.server.scrub_process_env_after_boot {
        let mut names = std::collections::BTreeSet::<String>::new();
        if let Ok(cfg_json) = serde_json::to_value(&config) {
            crate::config::resolver::collect_env_var_names(&cfg_json, &mut names);
        }
        let mut scrubbed = 0usize;
        for name in &names {
            if std::env::var_os(name).is_some() {
                // SAFETY: single-threaded boot path — no other thread reads the
                // process environment concurrently at this point in startup.
                unsafe {
                    std::env::remove_var(name);
                }
                scrubbed += 1;
            }
        }
        info!(
            scrubbed,
            candidates = names.len(),
            "post-boot env scrub removed config-referenced env vars from the live process environment"
        );
    }
    info!(
        secret_bindings = ?registry.bound_secret_schemes(),
        config_bindings = ?registry.bound_config_schemes(),
        "URI scheme auto-binding complete"
    );

    // Build the canonical `policy_chain` in operator-declared
    // order. Each entry in `governance.policy.engine[]` is
    // resolved via `resolve_kind(SlotClass::PolicyEngine, ...)`
    // — built-in keyword (`yaml-rules`), short alias (`cedar` /
    // `opa` / `casbin` → `dev.mcpg.policy.<alias>`), or full
    // reverse-domain plugin id. Each resolved entry must
    // correspond to an engine that's actually registered in the
    // host (the registration loops above + the built-in YAML
    // block earlier handled this). Refusing boot here surfaces
    // operator typos loudly — a chain that silently drops
    // entries would let security-critical decision points fall
    // through to the caller's default-allow / default-deny.
    let policy_chain = build_policy_chain(
        &config.governance.policy.engine,
        &config.plugins,
        &registry,
        &config.cluster.kind,
    )?;
    info!(
        chain = ?policy_chain,
        "policy_engine chain configured"
    );

    // There is no gateway-wide store-role binding map
    // (`plugin_bindings.kv`). Per-role store selection lives on each
    // `mcp.configurations.*.store: { kind: ... }` declaration, so each
    // MCP configuration carries its own store posture.

    // Likewise there is no gateway-wide cache-namespace binding map
    // (`plugin_bindings.caches`); cache-namespace selection is
    // per-consumer.

    // Startup refuses when audit is required + no
    // sink is serving. `plugins.audit.required` defaults to true,
    // so a deployment that runs with the defaults + doesn't
    // actively break audit will always pass this check (the
    // built-in registers on the same path). The failure surface
    // catches: operator omitted the built-in audit sink (didn't list
    // its kind) without shipping their own; every registered sink is in
    // a non-serving state (disabled / failed); a typo in the
    // descriptor made the sink refuse registration.
    if config.governance.audit.enabled
        && config.governance.audit.required
        && !registry.has_serving_audit_sink()
    {
        anyhow::bail!(
            "plugins.audit.required=true but no audit_sink plugin is serving traffic — \
             register at least one audit sink, or set plugins.audit.required=false \
             (dev / CI only)"
        );
    }

    // Apply operator-configured config overlay.
    // Runs last in `build_plugin_registry` so every config_provider
    // built-in + operator entry is already registered + scheme-
    // bound. Failures halt startup with the failing URI + error.
    // Audits the applied sources (reference + version + fetched_at)
    // so auditors can reconstruct which overlay produced a live
    // config; audit payload deliberately carries NO merged values
    // (dynamic config can contain secrets the operator routed
    // through config_provider).
    let config_overlay_outcome =
        config_overlay::apply_config_overlay(&registry, &config.gateway.config_overlay)
            .await
            .with_context(|| {
                "applying plugins.config_overlay — each URI must use a scheme \
         bound in plugins.configs"
            })?;
    if !config.gateway.config_overlay.is_empty() {
        let audit_policy = match config.governance.audit.on_failure {
            crate::config::AuditOnFailure::FailClosed => {
                mcpg_plugin_host::AuditEmitPolicy::FailClosed
            }
            crate::config::AuditOnFailure::FailOpen => mcpg_plugin_host::AuditEmitPolicy::FailOpen,
        };
        let event = mcpg_plugin_host::audit_events::lifecycle_event(
            "mcpg.lifecycle.config_overlay_applied",
            mcpg_plugin_protocol::audit::AuditOutcome::Success,
            serde_json::json!({
                "source_count": config_overlay_outcome.sources.len(),
                "sources": config_overlay_outcome.sources,
            }),
        );
        if let Err(failure) = registry
            .emit_audit_event_enforced(&event, audit_policy)
            .await
        {
            anyhow::bail!(
                "audit `on_failure: fail_closed` tripped for \
                 config_overlay_applied: {failure}"
            );
        }
    }
    info!(
        sources = config_overlay_outcome.sources.len(),
        "config overlay applied"
    );

    // Construct the L1 credential cache AFTER the
    // cluster_backend install above so we can wrap it in the
    // clustered variant when both:
    //   1. operator opted in via `credentials.cluster.enabled`
    //   2. a coordinator is actually registered
    // Either condition false → drop to plain `Local` with a log
    // line so the operator's choice is visible in startup output.
    let credential_cache = build_credential_cache(&config.credentials, &registry).await?;

    let content_stores = build_storages_registry(config, &registry).await?;
    let response_cache = build_response_cache(&config.storage.response_cache);
    let response_cache_overrides =
        build_binding_cache_overrides(config, &response_cache_default_max_bytes(config))?;

    // Build the runtime quota gate (rate
    // limits / budgets / concurrency) when the feature is on AND
    // the operator declared at least one policy or per-binding
    // ref. Off-feature, empty registry, AND no per-binding refs →
    // `None`, dispatch hook short-circuits.
    #[cfg(feature = "governance-quotas")]
    let quota_gate = build_quota_gate(config, &registry).await?;

    // Observability sinks name a plugin id; nothing links those plugins, so a
    // config that enables a sink without a matching `plugins[]` entry would
    // otherwise export nothing and say nothing. Name the gap instead.
    warn_unregistered_observability_sinks(config, &registry);

    Ok(PluginBundle {
        registry,
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
    })
}

/// Expand `${env.VAR}` references inline using the unified gateway
/// interpolator (CEL-style env-var syntax). Missing env vars are an
/// error so misconfig fails fast rather than silently becoming empty
/// credentials. Strings without any `${env.` marker pass through
/// unchanged.
pub(crate) fn interpolate_env(raw: &str) -> Result<String> {
    crate::runtime::expr::resolve_env_in_string(raw)
        .with_context(|| format!("plugin_registry.auth: failed to resolve `{raw}`"))
}

/// Warn when an observability sink is configured but no plugin is registered
/// under its id. The sink plugins ship as cdylibs: the operator declares the
/// artifact in `plugins[]` and the loader registers it. Missing entry ⇒ the
/// signal silently goes nowhere, so this is the one place that can say so.
fn warn_unregistered_observability_sinks(
    config: &AppConfig,
    registry: &mcpg_plugin_host::PluginRegistry,
) {
    let complain = |kind: &str, signal: &str, registered: &[String]| {
        if !registered.iter().any(|id| id == kind) {
            tracing::warn!(
                plugin_id = %kind,
                signal = %signal,
                "{signal} sink {kind:?} is configured but no plugin is registered \
                 under that id — it ships as a cdylib, so add a `plugins[]` entry \
                 with `source.path`/`source.oci` for it (the gateway images bake \
                 it at /usr/local/lib/mcpg/plugins/<id>/plugin.so). Until then \
                 this signal is not exported."
            );
        }
    };
    if config.observability.is_metrics_on() {
        let registered = registry.metrics_sink_ids();
        for sink in &config.observability.metrics.sinks {
            complain(&sink.kind, "metrics", &registered);
        }
    }
    if config.observability.is_traces_on() {
        let registered = registry.telemetry_sink_ids();
        for sink in &config.observability.traces.sinks {
            complain(&sink.kind, "traces", &registered);
        }
    }
}

// `convert_guardrails_config` was removed when the guardrails plugin
// moved to an external cdylib: the gateway no longer constructs the
// plugin crate's typed config
// struct — operators now author it directly under
// `plugins[*].config`, which the cdylib's
// `from_config_json` factory deserialises.

// `build_nats_client` was removed as part of the backend-plugin
// migration: the NATS client is no longer built by the gateway. The
// `dev.mcpg.backend.nats` cdylib connects lazily from the url +
// credentials_path injected into its `plugins[]` config (derived
// from the NATS bindings, see the NATS config-injection block in
// `build_plugin_registry`).
