//! Gateway configuration — YAML + environment variable loading via figment.
//!
//! Defines `AppConfig` and all nested config structs for server, bindings,
//! auth, policy, stores, observability, and plugins.

use std::path::Path;

use anyhow::{Context, Result};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Yaml},
};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

pub mod access;
pub mod admin;
pub mod approvals;
pub mod apps;
pub mod audit;
pub mod backend;
pub mod capability_state;
pub mod cloud;
pub mod cluster;
pub mod control_plane;
pub mod credentials;
pub mod debug;
pub mod diagnostics;
pub mod feature_flags;
pub mod federation;
pub mod gateway;
pub mod governance;
pub mod guardrails;
pub mod health_check;
pub mod inspector;
pub mod license;
pub mod mcp;
pub mod observability;
pub mod plugins;
pub mod policy;
pub mod quotas;
pub mod registry;
pub mod resolver;
pub mod schema;
pub mod schema_safety;
pub mod secret_scan;
pub mod server;
pub mod source;
pub mod storage;
pub mod store_override;
pub mod usage_reporting;
pub mod watch;
pub mod webhook;
pub mod wiring;

pub use access::{
    AccessConfig, AuthorizationServerClientConfig, AuthorizationServerConfig, JwksConfig,
    OAuthResourceMetadataConfig, TrustedIdpConfig,
};
pub use admin::{AdminAuthConfig, AdminConfig, DisclosureLevel};
pub use approvals::ApprovalsConfig;
pub use audit::{AuditConfig, AuditOnFailure};
pub(crate) use backend::default_cel_gate_error_message;
pub use backend::{
    BackendAnnotationsConfig, BackendConfig, BackendGovernanceConfig, BackendIconConfig,
    BackendImpl, BackendKind, BackendResourceAnnotations, GatherInputConfig, HttpBackendConfig,
    HttpBackendMethod, KafkaBackendConfig, MockBackendConfig, NatsBackendConfig,
    PipelineBackendConfig, PipelineBackendStepConfig, PipelineCelGateStepConfig,
    PipelineElicitationMode, PipelineElicitationStepConfig, PipelineGatherStepConfig,
    PipelineLogStepConfig, PipelineProgressStepConfig, PipelineRootsListStepConfig,
    PipelineSamplingStepConfig, PipelineSqlAwaitStepConfig, PipelineSqlTxNestedStep,
    PipelineSqlTxStepConfig, PipelineStepConfig, PipelineTransformStepConfig, PromptArgumentConfig,
    RetryConfig, SamplingMessageConfig, binding_icons,
};
pub use capability_state::{
    CancellationConfig, ConflictPolicy, DeliveryConfig, IdempotencyConfig, IdempotencyScopeKind,
    PipelinesConfig, SessionsConfig, SubscriptionsConfig, TasksConfig,
};
pub use cloud::{CloudConfig, CloudIsolation, CloudProvenance, CloudTier, InstanceId};
pub use cluster::{ClusterConfig, ClusterReadinessGate};
pub use control_plane::ControlPlaneAttachConfig;
pub use credentials::{CredentialsClusterConfig, CredentialsConfig};
pub use debug::{
    DebugCommandToolConfig, DebugConfig, DebugNetworkToolConfig, DebugToolBackendsConfig,
    DebugToolExposureConfig, DebugToolsConfig,
};
pub use diagnostics::{
    reachable_trust_ceiling, trust_ceiling_remedy, unreachable_trust_bindings,
    warn_unreachable_binding_trust,
};
pub use feature_flags::FeatureFlagsConfig;
pub use federation::{
    AuthMode, FederationConfig, SynthesizeMode, UpstreamProtocolVersion, UpstreamTransport,
};
pub use gateway::{ConfigWatchConfig, GatewayConfig};
pub use governance::GovernanceConfig;
pub use guardrails::{GuardrailHookConfig, GuardrailOnError, GuardrailsConfig};
pub use health_check::HealthCheckConfig;
pub use inspector::InspectorSidecarConfig;
pub use license::LicenseConfig;
pub use mcp::{
    McpCapabilitiesConfig, McpConfig, McpConfigurationsConfig, McpElicitationConfig,
    McpRootsConfig, McpSamplingConfig,
};
pub use observability::{LogsConfig, MetricsConfig, ObservabilityConfig, SinkConfig, TracesConfig};
pub use plugins::{
    HealthProbeConfig, PluginEntryConfig, PluginHttpRouteConfig, PluginObservabilityToggle,
    PluginRegistryAuthConfig, PluginRegistryConfig, PluginRegistryMirrorConfig,
    PluginRegistryTlsConfig, PluginResourceLimitsConfig, PluginSourceConfig, SignalKind,
    SignalToggle, SignatureConfig, SignaturePolicy, SinkMode, TrustedKeyConfig, validate_plugins,
};
pub use policy::{
    PolicyCacheConfig, PolicyConfig, ToolAccessPolicyConfig, ToolTrustRuleConfig, TrustLevelConfig,
};
pub use quotas::{
    BackendQuotasRef, BudgetPolicy, ConcurrencyPolicy, QuotasConfig, RateLimitPolicy, RateLimitRate,
};
pub use schema::SchemaEntry;
pub use server::{
    AauthResourceMetadataConfig, AauthSigningKeyConfig, ClientCertMode, ServerConfig, TlsConfig,
    TransportMode, TunnelConfig, TunnelExposure, TunnelFederationConfig, TunnelTrustMode,
};
pub use source::ConfigSource;
pub use storage::{
    InProcessResponseCacheConfig, ResponseCacheConfig, StorageConfig, StorageProviderConfig,
};
pub use store_override::{BusOverrideConfig, CLUSTER_KIND, StoreOverrideConfig};
pub use usage_reporting::UsageReportingConfig;
pub use watch::{NotificationFilterConfig, ResourceWatchConfig, WatchStrategyConfig};
pub use webhook::{WebhookCircuitBreakerConfig, WebhookConfig, WebhookEndpointConfig};
pub use wiring::{
    KindRef, ResolvedKind, SlotClass, cluster_provides_for_kind, resolve_kind, warn_unwired_plugins,
};

/// First path segment of an `MCPG_`-stripped environment key, lowercased —
/// the top-level config field the variable addresses.
///
/// Accepts both spellings the two callers see: the raw environment name
/// (`GOVERNANCE__ACCESS__JWKS__URL`) and the form figment hands to an
/// `Env::filter`, where `split("__")` has already rewritten the separators
/// to dots (`GOVERNANCE.ACCESS.JWKS.URL`). Both yield `governance`; a name
/// with no separator at all (`PORT`, `CLOUD_TOKEN`) is its own root.
fn env_key_root(key: &str) -> String {
    key.split("__")
        .next()
        .unwrap_or_default()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Top-level gateway configuration. Loaded from YAML file and/or `MCPG_` environment
/// variables via figment. Bindings live under
/// `mcp.capabilities.{tools,prompts,resources,resource_templates}[]`.
/// Each binding carries an explicit nested `backend:`
/// block that picks the implementation, discriminated by `kind:`
/// (`kind: http`, `kind: sql`, `kind: openai_chat`, …). Env-var expansion
/// (`${env.X}`) happens at startup time via CEL.
///
/// `deny_unknown_fields` is set so a typo at the root (or a stale
/// renamed block left in an operator's YAML) fails parsing
/// instead of silently parsing to defaults. The same strictness
/// applies to every typed sub-config; this flag closes the gap at
/// the root.
// Eq is not derived: the sampling pipeline step carries an f64 temperature field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// `mcp:` namespace — the MCP protocol surface.
    /// Two children: `capabilities:` (tools / prompts / resources /
    /// resource_templates / tasks / elicitation / sampling / roots —
    /// what the server advertises in `initialize`) and
    /// `configurations:` (sessions / pipelines / subscriptions /
    /// delivery / cancellation — runtime-emergent state).
    /// Capability persistence (`store:` / `bus:`) defaults to
    /// `kind: cluster` — the cluster coordinator's primitive — and
    /// can be overridden per capability with `kind: memory` / `file`.
    #[serde(default)]
    pub mcp: McpConfig,

    /// `governance:` umbrella — tool-call lifecycle:
    /// identity (`access`) → authorization (`policy`) → human gate
    /// (`approvals`) → evidence (`audit`). Co-located under one
    /// umbrella so the governance story reads as a coherent block.
    #[serde(default)]
    pub governance: GovernanceConfig,

    /// `gateway:` umbrella — the binary's network face:
    /// listener (`server`), admin surface (`admin`), Control Plane
    /// attachment (`control_plane`).
    #[serde(default)]
    pub gateway: GatewayConfig,

    /// All observability concerns — log/metric/trace emission, the
    /// binding-backend health prober, and the sink fan-out routing
    /// for telemetry / log events. Sub-fields all default to
    /// safe single-node values so the block is fully optional.
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Operator-controlled strictness / compatibility flags. Every
    /// flag defaults off; flipping one is an explicit acknowledgement
    /// that the operator is taking on the risk the default protects
    /// against. Collapsing them into this block lets them show up in
    /// the curated reference + JSON Schema and audit-emit when active.
    #[serde(default)]
    pub feature_flags: FeatureFlagsConfig,

    /// Operator-defined diagnostic tools (`mcpg.command.*` /
    /// `mcpg.network.*`) plus their probe profiles. The block is
    /// fully ignored unless `feature_flags.debug_tools_enabled`
    /// is `true`; production deploys keep that flag off and treat
    /// this block as scaffolding for CI / dev rollouts.
    #[serde(default)]
    pub debug: DebugConfig,

    /// Named JSON Schemas operator-declared once, referenced by
    /// `{"$schema_ref": "<name>"}` in any binding's `input_schema:` /
    /// `output_schema:`. Named `schema_registry:` (rather than
    /// `schemas:`) to disambiguate from the per-binding schema
    /// fields (`input_schema:`, `output_schema:`). Each entry
    /// (`SchemaEntry`) is inline / file / url.
    #[serde(default)]
    pub schema_registry: BTreeMap<String, SchemaEntry>,

    /// `storage:` block. Holds operator-declared content-store
    /// providers AND the gateway-managed LLM response cache. Each
    /// provider entry produces a named `ContentStore` in the
    /// gateway's registry; bindings reference providers by id via
    /// their own `content_storage:` field. When `providers` is
    /// empty AND no binding declares a `content_storage:` route,
    /// the gateway auto-creates a single in-process provider with
    /// id `default` and the standard 256 MiB cap.
    ///
    /// The LLM response cache (`storage.response_cache:`) lives
    /// under `storage:` (rather than `plugins:`) so all "where
    /// bytes go to live" config shares one home.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Cluster coordinator.
    /// Singleton: the operator picks one coordinator and configures
    /// it inline. Default is the built-in single-node coordinator —
    /// safe for single-instance deployments. Other kinds map to
    /// `mcpg-plugin-cluster-*` cdylib plugins; the
    /// cdylib must still be declared under `plugins[]` for
    /// the gateway to load it. The inline `cluster`
    /// block is the single source of truth for the coordinator's
    /// runtime config — it overrides any `config:` block on the
    /// matching `plugins[]` row.
    #[serde(default)]
    pub cluster: ClusterConfig,

    /// `credentials:` — the gateway-side L1 credential cache for
    /// `cred://` URI substitution (sizing, per-entry TTL cap, the
    /// `key_attributes` cache-key dimension) plus the optional cluster
    /// pub/sub wrapper. Defaults are safe for single-node; a
    /// multi-instance deploy issuing per-caller dynamic credentials
    /// configures `credentials.cluster` to keep peer caches consistent.
    #[serde(default)]
    pub credentials: CredentialsConfig,

    /// `license:` — offline license token (or the non-production
    /// declaration) for standalone deployments; the plugin load gate
    /// refuses entitlement-gated plugins the resolved envelope does
    /// not admit. Ignored when `gateway.control_plane` is attached.
    #[serde(default)]
    pub license: LicenseConfig,

    /// Loaded plugin entries — flat array, no
    /// wrapper. Each entry is self-contained (id / class / source /
    /// signature / config / limits / enforce / granted_capabilities /
    /// observability / http_route / disabled). Identity / policy /
    /// credential / catalog / cluster plugins all dispatch via the
    /// `class:` field. An empty array is the kill switch — no
    /// plugins are loaded.
    ///
    /// Companion concerns live in dedicated homes:
    /// - `plugins:` is this flat array.
    /// - Per-entry wiring lives on each entry itself
    ///   (`granted_capabilities` / `signature` / `limits` /
    ///   `observability` / `http_route`).
    /// - `gateway.plugin_registry:` holds OCI defaults.
    /// - `gateway.config_overlay:` holds the bootstrap URI list.
    /// - `observability.plugin_health_probe:` holds prober tuning.
    #[serde(default)]
    pub plugins: Vec<PluginEntryConfig>,

    /// `cloud:` — managed-fleet (mcpg.cloud) identity + placement. Absent for
    /// self-host; inert when present-but-empty, so the gateway binary is
    /// byte-identical whether or not it runs in the cloud. Server-managed
    /// fields (`instance_id`, `subdomain`, `provenance.*`) are stamped by the
    /// provisioner/operator and ignored if hand-written.
    #[serde(default)]
    pub cloud: CloudConfig,

    /// `usage_reporting:` — anonymous adoption ping. A minimal,
    /// vendor-facing, opt-out signal (product version + first-party plugin
    /// set) so we can see how the community grows. Wholly distinct from
    /// `observability:` (the operator's own OTel/metrics/log sinks). Fail-open,
    /// schema-pinned, and self-suppressing when air-gapped / licensed /
    /// CP-attached / CI; also disabled by `DO_NOT_TRACK` / `MCPG_TELEMETRY=off`.
    #[serde(default)]
    pub usage_reporting: UsageReportingConfig,
}

impl AppConfig {
    /// Iterate every operator-declared binding across the four typed
    /// MCP lists alongside its [`BackendKind`]. Most cross-cutting
    /// validations and runtime wires need to see every binding
    /// regardless of which capability surface it serves; this helper
    /// keeps the AppConfig surface ergonomic without resurrecting a
    /// single flat array of all bindings.
    pub fn all_bindings(&self) -> impl Iterator<Item = (BackendKind, &BackendConfig)> {
        self.mcp.all_bindings()
    }

    /// Mutable counterpart to [`Self::all_bindings`] used by the
    /// schema-ref resolver, which mutates `input_schema` /
    /// `output_schema` in place after the initial parse.
    pub fn all_bindings_mut(&mut self) -> impl Iterator<Item = (BackendKind, &mut BackendConfig)> {
        self.mcp.all_bindings_mut()
    }

    /// Total count of operator-declared bindings across all four
    /// MCP lists.
    pub fn binding_count(&self) -> usize {
        self.mcp.binding_count()
    }

    /// Load configuration from an optional YAML file merged with `MCPG_`-prefixed
    /// environment variables. Validates the full config tree before returning.
    ///
    /// Equivalent to [`Self::load_many`] with a slice of length 0 or 1. Kept for
    /// backward compatibility — new callers (and the gateway main binary) use
    /// `load_many` so operators can stack multiple YAML files.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let paths: Vec<&Path> = path.into_iter().collect();
        Self::load_many(&paths)
    }

    /// Load configuration from zero or more YAML files merged in slice order,
    /// then overlayed with `MCPG_`-prefixed environment variables.
    ///
    /// **Merge order: later wins.** `paths[0]` is the base; each subsequent
    /// entry overrides previous values for any field they explicitly set.
    /// `MCPG_*` environment variables are applied last and override every
    /// file. Object fields deep-merge (recursive into nested maps); arrays
    /// and scalars replace wholesale.
    ///
    /// Operator entry-point: `MCPG_CONFIG=base.yaml:production.yaml mcpg`
    /// (path-separator splitting happens in `main.rs`).
    pub fn load_many(paths: &[&Path]) -> Result<Self> {
        let sources: Vec<ConfigSource> = paths
            .iter()
            .map(|p| ConfigSource::File(p.to_path_buf()))
            .collect();
        Self::load_sources(&sources)
    }

    /// Top-level `AppConfig` field names — the roots an `MCPG_` environment
    /// variable may address. Read off the serialized default so the set
    /// cannot drift from the struct.
    fn known_config_roots() -> std::collections::BTreeSet<String> {
        match serde_json::to_value(AppConfig::default()) {
            Ok(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
            _ => std::collections::BTreeSet::new(),
        }
    }

    /// `MCPG_`-prefixed variables that are *meant* to be read outside the
    /// config overlay — the tool family's own dispatch and kill switches.
    /// Never merged (they name no config root); listed so
    /// [`AppConfig::ignored_env_overrides`] does not nag about them.
    fn is_tool_family_env(key: &str) -> bool {
        const PREFIXES: &[&str] = &["CP_", "CONTROL_PLANE_", "FED_", "INSPECTOR_"];
        const KEYS: &[&str] = &[
            "CONFIG",
            "CONFIG_ALLOW_INSECURE_HTTP",
            // Feeds `plugin_registry.default_registry`'s serde default rather
            // than addressing a config root, so the overlay never sees it —
            // but it DOES take effect, and reporting it as ignored would be a
            // lie an operator acts on.
            "DEFAULT_PLUGIN_REGISTRY",
            "STATE_DIR",
            "PLUGIN_DIR",
            "JSON_LOGS",
            "ENROLLMENT_URL",
            "INSTANCE_UID",
            "ORG",
            "WORKSPACE",
            "ENV",
            "TELEMETRY",
            "TELEMETRY_DEBUG",
        ];
        let upper = key.to_ascii_uppercase();
        PREFIXES.iter().any(|p| upper.starts_with(p)) || KEYS.contains(&upper.as_str())
    }

    /// `MCPG_`-prefixed variables present in the environment that address no
    /// config root and belong to no CLI, so they had no effect on the loaded
    /// config.
    ///
    /// Recomputed from the environment rather than threaded out of
    /// [`Self::load_sources`], because config loads before the log subscriber
    /// exists — boot reports these once telemetry is up.
    #[must_use]
    pub fn ignored_env_overrides() -> Vec<String> {
        let roots = Self::known_config_roots();
        let mut ignored: Vec<String> = std::env::vars()
            .filter_map(|(name, _)| {
                let rest = name.strip_prefix("MCPG_")?;
                (!roots.contains(&env_key_root(rest)) && !Self::is_tool_family_env(rest))
                    .then_some(name)
            })
            .collect();
        ignored.sort();
        ignored
    }

    /// Load configuration from zero or more [`ConfigSource`] layers merged in
    /// slice order (later wins), then overlayed with `MCPG_`-prefixed
    /// environment variables. A [`ConfigSource::File`] is read from disk; a
    /// [`ConfigSource::Inline`] merges its captured YAML text (remote-fetched
    /// or base64-decoded). This is the shared core behind [`Self::load_many`]
    /// and the `--config` source list, so a URL/base64 layer gets the exact
    /// same merge + validation semantics as a file.
    pub fn load_sources(sources: &[ConfigSource]) -> Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(AppConfig::default()));
        for source in sources {
            figment = match source {
                ConfigSource::File(path) => {
                    if !path.exists() {
                        return Err(anyhow::anyhow!("config file not found: {}", path.display()));
                    }
                    figment.merge(Yaml::file(path))
                }
                ConfigSource::Inline { yaml, .. } => figment.merge(Yaml::string(yaml)),
            };
        }
        // The `MCPG_` env prefix is shared by the whole tool family — the CP
        // server (`MCPG_CP_*`), the CLIs (`MCPG_STATE_DIR`, `MCPG_ORG`, …),
        // the gateway's own dispatch (`MCPG_CONFIG`, `MCPG_PLUGIN_DIR`) —
        // and by whatever else happens to sit in an operator's environment.
        // With `deny_unknown_fields` on AppConfig, claiming the whole
        // namespace turns any stray `MCPG_*` variable into a boot abort, so
        // only variables whose first `__` segment names a real top-level
        // config field take part in the overlay. Strictness is kept where it
        // pays: a typo INSIDE a recognised subtree
        // (`MCPG_GOVERNANCE__ACESS__…`) still fails loudly.
        let known_roots = Self::known_config_roots();
        figment = figment.merge(
            Env::prefixed("MCPG_")
                .split("__")
                .filter(move |key| known_roots.contains(&env_key_root(key.as_str()))),
        );

        let config: AppConfig = figment
            .extract()
            .context("failed to load application config")?;
        config.validate()?;
        Ok(config)
    }

    /// Look up the typed `granted_capabilities` slice for a plugin id —
    /// returns `&[]` when no `plugins[]` entry matches (the
    /// fail-closed default).
    ///
    /// `FirstPartyRegistrar` carries no centralised grants map; each
    /// `register*` call site supplies its grants explicitly. Built-
    /// ins that don't appear in operator config pass `&[]` directly
    /// (or call this helper, which returns `&[]` for unknown ids).
    ///
    /// The return type is the typed capability slice
    /// `&[mcpg_plugin_protocol::capability::Capability]`.
    #[must_use]
    pub fn granted_capabilities_for(
        &self,
        plugin_id: &str,
    ) -> &[mcpg_plugin_protocol::capability::Capability] {
        self.plugins
            .iter()
            .find(|e| e.id == plugin_id)
            .map(|e| e.granted_capabilities.as_slice())
            .unwrap_or(&[])
    }

    /// Whether `plugins[]` carries an entry that loads `plugin_id` from an
    /// artifact (a `source:` — path or OCI).
    ///
    /// Three first-party plugins ship BOTH compiled into this binary and as
    /// signed cdylibs under the same id (`observability.otlp`,
    /// `observability.prometheus`, `identity.oidc`). An operator who names
    /// the artifact means the artifact: it is the verified one, and it can
    /// be a different version than whatever this build embedded. So an
    /// explicit entry suppresses the compiled-in copy — the same rule the
    /// operator applies to the cloud default backend plugins, rather than
    /// registering both and failing on a duplicate.
    ///
    /// An entry WITHOUT a source (capability grants for the built-in copy)
    /// is not an override; that is how grants are attached today.
    pub fn loads_plugin_artifact(&self, plugin_id: &str) -> bool {
        self.plugins
            .iter()
            .any(|e| e.id == plugin_id && (e.source.path.is_some() || e.source.oci.is_some()))
    }

    /// SHA-256 over the canonical JSON form of this config — stable
    /// across YAML key reorderings and re-serialisations, so two
    /// gateways loading the same source-of-truth produce the same
    /// digest. Returns the hex-encoded digest (`"a1b2…"`, 64 chars).
    ///
    /// **Scope.** The hash covers the *post-figment-merge / pre-CEL-
    /// expansion* shape. `${env.X}` references appear in the digest
    /// as-typed — we explicitly do NOT include the resolved env
    /// values, so the digest stays reproducible from the YAML files
    /// alone (operators correlate audit events back to source
    /// control without leaking secrets through the hash).
    ///
    /// Used by the `mcpg.config.loaded` / `mcpg.config.reloaded`
    /// audit-event surface so auditors can anchor every event in
    /// scope to the exact config snapshot that was running at the
    /// time.
    #[must_use]
    pub fn canonical_sha256(&self) -> String {
        use sha2::{Digest, Sha256};
        let value = serde_json::to_value(self).expect("AppConfig serialises");
        let canonical = canonicalize_json(&value);
        let bytes = serde_json::to_vec(&canonical).expect("canonical serialises");
        let digest = Sha256::digest(&bytes);
        format!("{digest:x}")
    }

    /// Parse and validate a YAML config string (for admin config:validate endpoint).
    pub fn load_from_yaml_str(yaml: &str) -> Result<Self> {
        let config: AppConfig =
            serde_yaml::from_str(yaml).context("failed to parse YAML config")?;
        config.validate()?;
        Ok(config)
    }

    /// Parse + figment-merge multiple YAML config strings in slice order
    /// (later wins) and validate. Used by `mcpg config check` to lock the
    /// pre-flight semantics to the same merge logic the runtime uses,
    /// without applying `MCPG_*` env-var overrides (the operator's source
    /// of truth is the file set as written).
    pub fn load_from_yaml_strs(yamls: &[&str]) -> Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(AppConfig::default()));
        for yaml in yamls {
            figment = figment.merge(Yaml::string(yaml));
        }
        let config: AppConfig = figment.extract().context("failed to merge YAML configs")?;
        config.validate()?;
        Ok(config)
    }

    /// Resolve all schema references in bindings.
    ///
    /// For each binding whose `input_schema` or `output_schema` contains `{"$schema_ref": "name"}`,
    /// replaces it with the actual schema from the registry. Also loads file/url schema sources.
    ///
    /// Should be called after `load()` during application bootstrap.
    pub async fn resolve_schema_refs(&mut self, config_dir: Option<&Path>) -> Result<()> {
        // First, resolve all schema entries to their actual JSON values
        let mut resolved: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for (name, entry) in &self.schema_registry {
            let schema = if let Some(ref inline) = entry.inline {
                inline.clone()
            } else if let Some(ref file_path) = entry.file {
                let full_path = if let Some(dir) = config_dir {
                    dir.join(file_path)
                } else {
                    std::path::PathBuf::from(file_path)
                };
                let content = std::fs::read_to_string(&full_path).with_context(|| {
                    format!(
                        "schema_registry.{}: failed to read file '{}'",
                        name,
                        full_path.display()
                    )
                })?;
                serde_json::from_str(&content).with_context(|| {
                    format!(
                        "schema_registry.{}: invalid JSON in file '{}'",
                        name,
                        full_path.display()
                    )
                })?
            } else if let Some(ref url) = entry.url {
                // Security: SSRF guard — resolve the host, reject private
                // targets, and pin the resolved address into the client.
                let client = schema::validate_and_pin_schema_url(
                    url,
                    self.gateway.server.allow_private_backends,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "schema_registry.{}: URL '{}' rejected by SSRF guard: {}",
                        name,
                        url,
                        e,
                    )
                })?;
                let body = client
                    .get(url)
                    .send()
                    .await
                    .with_context(|| {
                        format!("schema_registry.{}: failed to fetch URL '{}'", name, url)
                    })?
                    .text()
                    .await
                    .with_context(|| {
                        format!(
                            "schema_registry.{}: failed to read response from '{}'",
                            name, url
                        )
                    })?;
                serde_json::from_str(&body).with_context(|| {
                    format!("schema_registry.{}: invalid JSON from URL '{}'", name, url)
                })?
            } else {
                unreachable!("validate_schemas ensures exactly one source");
            };

            // Hold a registry schema to the same posture as an inline one:
            // ban off-document `$ref`, bound depth/breadth/size, and compile
            // fail-closed. This is the only place a `file:`/`url:` schema is
            // checked, and its body is not operator-authored — a registry
            // that serves a schema with a network `$ref` would otherwise
            // reach off-box from inside the boot task.
            schema_safety::compile_checked(&schema, &format!("schema_registry.{name}"))?;
            resolved.insert(name.clone(), schema);
        }

        // Replace $ref in bindings with actual schemas
        for (_, binding) in self.all_bindings_mut() {
            Self::resolve_ref_field(&mut binding.input_schema, &resolved)?;
            Self::resolve_ref_field(&mut binding.output_schema, &resolved)?;
        }
        // Re-check what substitution produced. `validate_bindings` skipped
        // every `$schema_ref` form, so this is the first time the schema a
        // binding will actually validate against is seen whole.
        for (kind, binding) in self.all_bindings() {
            let bucket = match kind {
                BackendKind::Tool => "tools",
                BackendKind::Prompt => "prompts",
                BackendKind::Resource => "resources",
                BackendKind::ResourceTemplate => "resource_templates",
            };
            let path = format!("mcp.capabilities.{bucket}[name=`{}`]", binding.name);
            if let Some(ref schema) = binding.input_schema {
                schema_safety::compile_checked(schema, &format!("{path}.input_schema"))?;
            }
            if let Some(ref schema) = binding.output_schema {
                schema_safety::compile_checked(schema, &format!("{path}.output_schema"))?;
            }
        }
        Ok(())
    }

    fn resolve_ref_field(
        field: &mut Option<serde_json::Value>,
        resolved: &BTreeMap<String, serde_json::Value>,
    ) -> Result<()> {
        if let Some(val) = field.as_ref()
            && let Some(ref_name) = val.get("$schema_ref").and_then(|v| v.as_str())
            && let Some(schema) = resolved.get(ref_name)
        {
            *field = Some(schema.clone());
        }
        Ok(())
    }

    /// Validate the complete config tree. Runs a cascade: global constraints first,
    /// then per-binding validation, then per-subsystem (store, governance, plugins,
    /// etc.), and finally cross-cutting invariants (e.g. NATS bindings require
    /// NATS enabled).
    pub fn validate(&self) -> Result<()> {
        let server = &self.gateway.server;
        if server.bind_address.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "gateway.server.bind_address must not be empty"
            ));
        }
        if !server.health_path.starts_with('/') {
            return Err(anyhow::anyhow!(
                "gateway.server.health_path must start with '/'"
            ));
        }
        if !server.mcp_path.starts_with('/') {
            return Err(anyhow::anyhow!(
                "gateway.server.mcp_path must start with '/'"
            ));
        }
        require_positive(
            "gateway.server",
            "replay_window_limit",
            server.replay_window_limit as u64,
        )?;
        require_positive(
            "gateway.server",
            "session_idle_timeout_ms",
            server.session_idle_timeout_ms,
        )?;
        require_positive(
            "gateway.server",
            "shutdown_timeout_ms",
            server.shutdown_timeout_ms,
        )?;
        require_positive(
            "gateway.server",
            "request_timeout_ms",
            server.request_timeout_ms,
        )?;
        if let Some(ref tls) = server.tls {
            tls.validate()?;
        }
        if let Some(ref aauth) = server.aauth_resource_metadata {
            aauth.validate()?;
        }
        if let Some(ref tunnel) = server.tunnel {
            tunnel.validate()?;
        }
        if let Some(ref tf) = server.tunnel_federation {
            tf.validate()?;
        }
        // A `tunnel://` federation upstream can only resolve through the relay
        // federation ingress, so its presence requires `tunnel_federation` to be
        // configured. Fail closed at boot rather than at first dispatch.
        if server.tunnel_federation.is_none() {
            for fed in &self.mcp.federations {
                if fed.upstream.url.starts_with("tunnel://") {
                    return Err(anyhow::anyhow!(
                        "mcp.federations[{}].upstream.url is a tunnel:// upstream but \
                         gateway.server.tunnel_federation (relay ingress) is not configured",
                        fed.name
                    ));
                }
            }
        }
        for origin in &server.allowed_origins {
            if origin.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "gateway.server.allowed_origins entries must not be empty"
                ));
            }
        }
        // File-watch sub-second polling burns disk I/O for
        // no operator-visible benefit. Warn instead of erroring so
        // an operator who wrote `0` in panic still boots; the watch
        // task clamps to the floor at spawn time.
        if self.gateway.config_watch.enabled && self.gateway.config_watch.poll_interval_ms < 1000 {
            tracing::warn!(
                value = self.gateway.config_watch.poll_interval_ms,
                "gateway.config_watch.poll_interval_ms is below the 1000ms floor; clamping to 1000ms at spawn time"
            );
        }
        self.debug
            .tools
            .validate(self.feature_flags.debug_tools_enabled)?;
        self.validate_bindings()?;
        self.mcp.validate()?;
        self.observability.validate()?;
        self.governance.validate()?;
        self.validate_binding_quota_refs()?;
        self.validate_binding_policy_conflicts()?;
        self.feature_flags.validate()?;
        validate_plugins(&self.plugins)?;
        self.validate_wiring_resolution()?;
        self.warn_cluster_connection_overlap();
        self.cluster.validate_transport_security()?;
        self.cluster.validate_tenant_segment()?;
        self.validate_cancellation_partitioning()?;
        self.validate_schemas()?;
        self.cloud.validate()?;
        self.usage_reporting.validate()?;
        // Same fail-closed clustered-credential rule the boot path enforces,
        // surfaced at pre-flight so `config validate` catches it too.
        self.credentials.cluster.validate()?;
        Ok(())
    }

    /// Config-time `resolve_kind` cross-check at every
    /// consumer slot whose discriminator is operator-typeable.
    /// Catches plugin-id typos, class mismatches, and `kind: cluster`
    /// against a coordinator that doesn't provide the role —
    /// surfaced before any plugin loading or backend connection.
    ///
    /// Slots covered:
    /// - `governance.policy.engine[].kind` (`SlotClass::PolicyEngine`)
    /// - `governance.quotas.store.kind` (`SlotClass::Kv`, when non-empty)
    /// - `gateway.server.transports[].kind` (`SlotClass::Transport`)
    /// - per-binding `cache.kind` (`SlotClass::Cache`)
    /// - `mcp.configurations.{sessions,pipelines,tasks,subscriptions}.store.kind`
    ///   (`SlotClass::Kv`) — the store override's kind+config map is
    ///   reshaped into a `KindRef` so resolution sees the same
    ///   shape.
    ///
    /// Slots intentionally NOT covered today:
    /// - `mcp.configurations.{delivery,cancellation}.bus.kind` —
    ///   `BusOverrideConfig::validate()` already enforces a closed
    ///   set (`cluster` / `memory`); plugin Bus support is a
    ///   separate slice.
    /// - `governance.audit.sinks[].kind` +
    ///   `observability.{logs,metrics,traces}.sinks[].kind` —
    ///   per-signal `SlotClass::{AuditSink, LogSink, MetricsSink,
    ///   TelemetrySink}` variants exist for boot-time
    ///   registry-aware consumers. Config-validate is
    ///   intentionally lax here because the default shipping
    ///   sinks reference first-party plugins
    ///   (`dev.mcpg.builtin.audit.local-file`,
    ///   `dev.mcpg.observability.prometheus`) that auto-register
    ///   via `FirstPartyRegistrar` at boot — they're not in
    ///   `config.plugins[]`. The boot-time observability /
    ///   audit bridges cross-check the registry and warn
    ///   on unresolved sinks.
    ///
    /// Empty-default `KindRef` values (e.g.
    /// `governance.quotas.store` defaults to `kind: ""` when no
    /// quotas are declared) are skipped — they're treated as "not
    /// configured", and the runtime short-circuits when there's
    /// nothing to resolve.
    fn validate_wiring_resolution(&self) -> Result<()> {
        use store_override::CLUSTER_KIND;
        use wiring::{KindRef, SlotClass, resolve_kind};

        let plugins = &self.plugins;
        let cluster_kind = self.cluster.kind.as_str();

        // governance.policy.engine[].kind
        for (i, kref) in self.governance.policy.engine.iter().enumerate() {
            resolve_kind(SlotClass::PolicyEngine, kref, plugins, cluster_kind)
                .map_err(|e| anyhow::anyhow!("governance.policy.engine[{i}].kind: {e}"))?;
        }

        // governance.quotas.store — skip the default empty
        // discriminator (no quotas configured). The runtime quota
        // gate is a no-op when the policy registry is empty, so
        // the store resolution doesn't fire either.
        if !self.governance.quotas.store.kind.trim().is_empty() {
            resolve_kind(
                SlotClass::Kv,
                &self.governance.quotas.store,
                plugins,
                cluster_kind,
            )
            .map_err(|e| anyhow::anyhow!("governance.quotas.store.kind: {e}"))?;
        }

        // gateway.server.transports[].kind (extra-listener entries;
        // built-in keywords for the primary listener live on
        // `gateway.server.transport:` not in this list).
        for (i, kref) in self.gateway.server.transports.iter().enumerate() {
            resolve_kind(SlotClass::Transport, kref, plugins, cluster_kind)
                .map_err(|e| anyhow::anyhow!("gateway.server.transports[{i}].kind: {e}"))?;
        }

        // Per-binding cache.kind — Vec<KindRef> distributed across
        // tools / prompts / resources / resource_templates.
        for (kind, binding) in self.all_bindings() {
            let Some(kref) = binding.cache.as_ref() else {
                continue;
            };
            let bucket = match kind {
                BackendKind::Tool => "tools",
                BackendKind::Prompt => "prompts",
                BackendKind::Resource => "resources",
                BackendKind::ResourceTemplate => "resource_templates",
            };
            resolve_kind(SlotClass::Cache, kref, plugins, cluster_kind).map_err(|e| {
                anyhow::anyhow!(
                    "mcp.capabilities.{bucket}[name=`{}`].cache.kind: {e}",
                    binding.name
                )
            })?;
        }

        // Per-capability store overrides (sessions / pipelines /
        // tasks / subscriptions). The override's `kind` field is
        // hand-restricted to {cluster, memory, file} OR a plugin
        // id / short alias — `cluster` short-circuits to the
        // coordinator primitive (always valid), built-in keywords
        // pass via the slot's keyword set, and plugin-id paths get
        // the full registry cross-check.
        let store_sites: [(&str, Option<&StoreOverrideConfig>); 4] = [
            (
                "mcp.configurations.sessions.store",
                self.mcp.configurations.sessions.store.as_ref(),
            ),
            (
                "mcp.configurations.pipelines.store",
                self.mcp.configurations.pipelines.store.as_ref(),
            ),
            (
                "mcp.capabilities.tasks.store",
                self.mcp.capabilities.tasks.store.as_ref(),
            ),
            (
                "mcp.configurations.subscriptions.store",
                self.mcp.configurations.subscriptions.store.as_ref(),
            ),
        ];
        for (path, over) in store_sites {
            let Some(over) = over else { continue };
            // The cluster meta-kind validates fine without going
            // through resolve_kind (no plugin lookup, no role
            // check) — `StoreOverrideConfig::is_cluster_meta` is
            // the canonical check the runtime uses.
            if over.kind == CLUSTER_KIND {
                continue;
            }
            let kref = KindRef {
                kind: over.kind.clone(),
                config: serde_json::Value::Object(over.config.clone()),
            };
            resolve_kind(SlotClass::Kv, &kref, plugins, cluster_kind)
                .map_err(|e| anyhow::anyhow!("{path}.kind: {e}"))?;
        }

        // Sink slots (`governance.audit.sinks[]` +
        // `observability.{logs,metrics,traces}.sinks[]`) are
        // intentionally NOT routed through resolve_kind at
        // config-validate time. Their per-signal `SlotClass`
        // variants exist (`AuditSink` / `LogSink` /
        // `MetricsSink` / `TelemetrySink`) for boot-time consumers
        // that have access to the populated plugin registry — but
        // config-validate only sees `&[PluginEntryConfig]`, which
        // is missing first-party auto-registered plugins
        // (`dev.mcpg.builtin.audit.local-file`,
        // `dev.mcpg.observability.prometheus`,
        // `dev.mcpg.observability.otlp`) that ship as gateway
        // path-deps + register via `FirstPartyRegistrar` at boot.
        // Strict resolve_kind here would reject the default
        // shipping config. The boot-time bridges
        // (`log_bridge`, `metrics_bridge`, `telemetry_bridge`,
        // audit `register_audit_sink_chain`) catch unknown plugin
        // ids at the registry-cross-check step.

        Ok(())
    }

    fn validate_bindings(&self) -> Result<()> {
        let mut seen_names = std::collections::HashSet::new();
        for (i, (_kind, binding)) in self.all_bindings().enumerate() {
            let path = format!("bindings[{}]", i);
            if binding.name.trim().is_empty() {
                return Err(anyhow::anyhow!("{}.name must not be empty", path));
            }
            // MCP 2025-11-25 tool-name guidance: 1..=128 chars of
            // [A-Za-z0-9_.-]. Enforced strictly — permitting other chars
            // breaks downstream integrations silently.
            if binding.name.len() > 128 {
                return Err(anyhow::anyhow!(
                    "{}.name '{}' exceeds the MCP 128-character guidance",
                    path,
                    binding.name
                ));
            }
            if !binding
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
            {
                return Err(anyhow::anyhow!(
                    "{}.name '{}' contains characters outside the MCP tool-name guidance \
                     ([A-Za-z0-9_.-])",
                    path,
                    binding.name
                ));
            }
            if !seen_names.insert(&binding.name) {
                return Err(anyhow::anyhow!(
                    "{}.name '{}' is duplicated; binding names must be unique",
                    path,
                    binding.name
                ));
            }
            if binding.description.trim().is_empty() {
                return Err(anyhow::anyhow!("{}.description must not be empty", path));
            }
            if let Some(ref title) = binding.title
                && title.trim().is_empty()
            {
                return Err(anyhow::anyhow!(
                    "{}.title must not be whitespace-only when provided",
                    path
                ));
            }
            if let Some(ref schema) = binding.input_schema {
                if !schema.is_object() {
                    return Err(anyhow::anyhow!(
                        "{}.input_schema must be a JSON object when provided",
                        path
                    ));
                }
                // Skip JSON Schema compilation if this is a $schema_ref — the
                // resolved schema is checked in `resolve_schema_refs`, both as
                // a registry entry and again after substitution.
                if schema.get("$schema_ref").is_none() {
                    // Schema-safety posture (SEP-2106): ban off-document
                    // network/file `$ref` and bound composition
                    // depth/breadth + total node count BEFORE compilation.
                    // Fail-closed compile-check: an uncompilable or
                    // unsupported-dialect schema is a hard config error,
                    // not a silently dropped validator.
                    schema_safety::compile_checked(schema, &format!("{path}.input_schema"))?;
                }
            }
            // Output schema mirrors input: fail closed on an
            // uncompilable / unsupported-dialect / unsafe schema rather
            // than dropping the validator at registration time.
            if let Some(ref schema) = binding.output_schema {
                if !schema.is_object() {
                    return Err(anyhow::anyhow!(
                        "{}.output_schema must be a JSON object when provided",
                        path
                    ));
                }
                if schema.get("$schema_ref").is_none() {
                    schema_safety::compile_checked(schema, &format!("{path}.output_schema"))?;
                }
            }
            // Icon `src` must be HTTPS or a `data:` URI — an HTTP or
            // off-scheme icon source is a mixed-content / SSRF hazard
            // when a client renders the descriptor.
            if let Some(ref icons) = binding.icons {
                for (icon_i, icon) in icons.iter().enumerate() {
                    let src = icon.src.trim();
                    let lower = src.to_ascii_lowercase();
                    if !(lower.starts_with("https://") || lower.starts_with("data:")) {
                        return Err(anyhow::anyhow!(
                            "{}.icons[{}].src '{}' must be an https:// URL or a data: URI",
                            path,
                            icon_i,
                            icon.src
                        ));
                    }
                }
            }
            binding.governance.validate(&path)?;
            if let Some(ref retry) = binding.retry {
                retry.validate(&path)?;
                if matches!(
                    binding.backend.kind.as_str(),
                    "mock" | "pipeline" | "command" | "sql"
                ) {
                    return Err(anyhow::anyhow!(
                        "{}.retry is not supported for {} bindings",
                        path,
                        binding.backend.kind
                    ));
                }
            }
            // Value-level spec validation is the owning plugin's
            // `register_profile` (surfaced as `InvalidSpec` at boot by the
            // generic register pass); unknown / non-backend kinds are caught
            // by the boot guard. Only the structural non-empty-kind check
            // lives at config-load.
            if binding.backend.kind.trim().is_empty() {
                return Err(anyhow::anyhow!("{path}.kind must not be empty"));
            }
        }
        Ok(())
    }

    /// Every binding's `quotas:` block must
    /// reference ids that exist in `governance.quotas.{rate_limits,
    /// budgets,concurrency}[]`. Runs AFTER `governance.validate()`
    /// (which checks the registry's own well-formedness) so a
    /// missing-id error is unambiguous: the registry is fine,
    /// the binding's reference is the typo.
    fn validate_binding_quota_refs(&self) -> Result<()> {
        for (kind, binding) in self.all_bindings() {
            let Some(qref) = &binding.quotas else {
                continue;
            };
            let bucket = match kind {
                BackendKind::Tool => "tools",
                BackendKind::Prompt => "prompts",
                BackendKind::Resource => "resources",
                BackendKind::ResourceTemplate => "resource_templates",
            };
            let path = format!("mcp.capabilities.{bucket}[name=`{}`]", binding.name);
            self.governance.quotas.validate_binding_ref(qref, &path)?;
        }
        Ok(())
    }

    fn validate_binding_policy_conflicts(&self) -> Result<()> {
        for (_, binding) in self.all_bindings() {
            if self
                .governance
                .policy
                .tool_access
                .rules
                .iter()
                .any(|rule| rule.tool_name == binding.name)
            {
                return Err(anyhow::anyhow!(
                    "policy.tool_access.rules must not configure '{}' directly; use the binding's governance.minimum_trust and governance.allow_if instead",
                    binding.name
                ));
            }
        }
        Ok(())
    }

    /// Boot guard: `cancellation.partition_by_principal`
    /// publishes to `mcpg.cancel.<principal>` and subscribes on the
    /// `mcpg.cancel.*` wildcard. That only delivers on a wildcard-capable
    /// pub/sub backend (redis PSUBSCRIBE / nats subject wildcards). The
    /// in-process single-node bus and the `memory` override are
    /// exact-match only — a wildcard subscribe matches nothing, so every
    /// cancellation would be silently dropped. Refuse the combination at
    /// boot rather than failing open at runtime.
    fn validate_cancellation_partitioning(&self) -> Result<()> {
        if !self.mcp.configurations.cancellation.partition_by_principal {
            return Ok(());
        }
        // Effective cancel-bus kind: a `memory` override pins the
        // in-process exact-match bus; a `cluster` override (or no
        // override) delegates to the coordinator, so inherit `cluster.kind`.
        let effective = match self.mcp.configurations.cancellation.bus.as_ref() {
            Some(over) if over.kind == "memory" => "memory",
            _ => self.cluster.kind.as_str(),
        };
        if !matches!(effective, "redis" | "nats") {
            return Err(anyhow::anyhow!(
                "cancellation.partition_by_principal requires a wildcard-capable \
                 pub/sub backend (cluster.kind: redis | nats); the effective cancel \
                 bus is '{effective}', which is exact-match only and would silently \
                 drop every cancellation under the `mcpg.cancel.*` wildcard subscribe. \
                 Either set cluster.kind to redis/nats or disable partition_by_principal."
            ));
        }
        Ok(())
    }

    /// Warn when `cluster.kind` opens a connection to the same NATS URL
    /// that a NATS binding also targets — operators usually mean to
    /// share, but today the gateway opens two independent clients.
    /// Pure observation; never errors.
    fn warn_cluster_connection_overlap(&self) {
        if self.cluster.kind.as_str() != "nats" {
            return;
        }
        let cluster_url = self
            .cluster
            .config
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if cluster_url.is_empty() {
            return;
        }
        let nats_binding_url = self.all_bindings().find_map(|(_, b)| {
            (b.backend.kind == "nats")
                .then(|| b.backend.spec.get("url").and_then(|v| v.as_str()))
                .flatten()
        });
        if nats_binding_url == Some(cluster_url) {
            tracing::warn!(
                cluster_url = %cluster_url,
                "cluster.kind: nats and a NATS binding both target the same URL; \
                 the gateway opens two independent connections. Consider \
                 using a YAML anchor or `${{$env.NATS_URL}}` so a single \
                 rotation covers both."
            );
        }
    }

    fn validate_schemas(&self) -> Result<()> {
        for (name, entry) in &self.schema_registry {
            let sources = [
                entry.inline.is_some(),
                entry.file.is_some(),
                entry.url.is_some(),
            ];
            let source_count = sources.iter().filter(|&&s| s).count();
            if source_count == 0 {
                return Err(anyhow::anyhow!(
                    "schema_registry.{}: must define exactly one of 'inline', 'file', or 'url'",
                    name
                ));
            }
            if source_count > 1 {
                return Err(anyhow::anyhow!(
                    "schema_registry.{}: must define exactly one of 'inline', 'file', or 'url', found {}",
                    name,
                    source_count
                ));
            }
            if let Some(ref schema) = entry.inline {
                if !schema.is_object() {
                    return Err(anyhow::anyhow!(
                        "schema_registry.{}.inline must be a JSON object",
                        name
                    ));
                }
                schema_safety::compile_checked(schema, &format!("schema_registry.{name}.inline"))?;
            }
            if let Some(ref path) = entry.file
                && path.trim().is_empty()
            {
                return Err(anyhow::anyhow!(
                    "schema_registry.{}.file must not be empty",
                    name
                ));
            }
            if let Some(ref url) = entry.url
                && !url.starts_with("http://")
                && !url.starts_with("https://")
            {
                return Err(anyhow::anyhow!(
                    "schema_registry.{}.url must start with http:// or https://",
                    name
                ));
            }
        }

        for (i, (kind, binding)) in self.all_bindings().enumerate() {
            let path = format!("bindings[{}]", i);
            Self::validate_schema_ref(
                &binding.input_schema,
                &self.schema_registry,
                &format!("{}.input_schema", path),
            )?;
            Self::validate_schema_ref(
                &binding.output_schema,
                &self.schema_registry,
                &format!("{}.output_schema", path),
            )?;

            if kind == BackendKind::ResourceTemplate
                && binding
                    .uri_template
                    .as_ref()
                    .is_none_or(|u| u.trim().is_empty())
            {
                return Err(anyhow::anyhow!(
                    "{}: resource_template bindings require a non-empty uri_template",
                    path
                ));
            }
        }
        Ok(())
    }

    /// Check if a schema value is a `$ref` to a registry entry.
    fn validate_schema_ref(
        schema: &Option<serde_json::Value>,
        registry: &BTreeMap<String, SchemaEntry>,
        path: &str,
    ) -> Result<()> {
        if let Some(val) = schema
            && let Some(ref_name) = val.get("$schema_ref").and_then(|v| v.as_str())
            && !registry.contains_key(ref_name)
        {
            return Err(anyhow::anyhow!(
                "{}: $ref '{}' not found in schemas registry",
                path,
                ref_name
            ));
        }
        Ok(())
    }
}

/// Recursively rewrite a JSON value into canonical form: object keys
/// sorted lexicographically. Arrays preserve order (operator-meaningful)
/// and scalars are passed through unchanged. Used by
/// [`AppConfig::canonical_sha256`] so the digest is invariant to YAML
/// key ordering.
fn canonicalize_json(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for k in keys {
                sorted.insert(k.clone(), canonicalize_json(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}

// --- OIDC/OAuth Enterprise Identity Configuration ---
//
// Canonical types live in the standalone mcpg-plugin-identity-oidc crate.
// Re-exported here so gateway config deserialization, validation, and
// all existing `crate::config::OidcOAuthConfig` paths remain unchanged.
pub use mcpg_plugin_identity_oidc_core::config::{
    ClaimMappingConfig, OidcOAuthConfig, OidcProviderConfig, TokenSourceConfig, TokenSourceKind,
    VerificationConfig, parse_algorithm,
};

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_false() -> bool {
    false
}

/// Reject a config value that must be strictly positive. Produces the
/// canonical `"{path}.{field} must be greater than 0"` message shared
/// across the typed sub-config validators.
pub(crate) fn require_positive(path: &str, field: &str, value: u64) -> Result<()> {
    if value == 0 {
        anyhow::bail!("{path}.{field} must be greater than 0");
    }
    Ok(())
}

// Tool-call rate limiting is configured as a tool-gate plugin under
// `plugins[]` — `dev.mcpg.rate-limit` (in-process token bucket) is
// the built-in option; clustered backends await host-injected NATS/Redis
// stores in the rate-limit plugin.

// IP allowlisting is the `mcpg-plugin-security-ip-allowlist` OCI cdylib,
// configured via a `plugins[]` entry with `allow` / `ip_header` /
// `tools` keys under `config:`.

// The circuit-breaker plugin is an OCI cdylib configured under
// `plugins[*].config`. Note the webhook plugin has its OWN internal
// `WebhookCircuitBreakerConfig` (different domain: outbound-HTTP CB, not
// tool-call CB).

// ---------------------------------------------------------------------------
// Admin API Config
// ---------------------------------------------------------------------------

// The call-logger is the `mcpg-plugin-observability-call-logger` OCI cdylib,
// configured via a `plugins[]` block — see
// `plugins/observability/call-logger/plugin.yaml` and the crate rustdoc for
// the config-JSON shape.

#[cfg(test)]
mod tests;
