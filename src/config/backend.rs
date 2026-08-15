//! Binding configuration. [`BackendImpl`] is a `{ kind, spec }` struct
//! backing `backend:` in YAML: `kind` names a loaded
//! `BackendPlugin::kind()`, and every sibling YAML key flattens into
//! `spec`, forwarded verbatim to the plugin. The gateway enumerates no
//! plugin kinds. The `<Kind>BackendConfig` structs below are retained
//! only as deserialization DTOs / test fixtures (via
//! [`BackendImpl::from_typed`]), not as enum variants.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{ResourceWatchConfig, TrustLevelConfig};

/// Tag identifying which MCP capability a [`BackendConfig`] surfaces
/// under. There is no per-binding `kind:` wire field — list
/// membership in `mcp.tools[]` / `mcp.prompts[]` /
/// `mcp.resources[]` / `mcp.resource_templates[]` carries the
/// information instead. Used internally to tag which capability list
/// (`tools` / `prompts` / `resources` / `resource_templates`) a binding
/// came from when a single helper iterates every binding.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    #[default]
    Tool,
    Prompt,
    Resource,
    ResourceTemplate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PromptArgumentConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub completions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct BackendConfig {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    pub description: String,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    /// Implementation backend — discriminated by `kind:`. The
    /// backend is an explicit nested object
    /// (`backend: { kind: http, url: ... }`) rather than fields
    /// hoisted onto the binding itself.
    pub backend: BackendImpl,
    #[serde(default)]
    pub governance: BackendGovernanceConfig,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Content-store provider this binding routes through. Must match
    /// one of the `storage.providers: [{id, ...}]` entries declared
    /// at the top level. When unset, the binding falls back to the
    /// provider id named in `content_storage.default` (or the
    /// conventional `default` id when neither is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_storage: Option<String>,

    /// Per-binding LLM response-cache override.
    /// Resolves via `resolve_kind(SlotClass::Cache, ...)` at boot:
    ///
    /// - `kind: in-process` (or alias `memory`) — fresh
    ///   [`mcpg_backend_llm_shared::LruResponseCache`] sized by
    ///   `config.max_bytes` (defaults to the gateway-wide
    ///   `storage.response_cache` byte cap when omitted). Each binding
    ///   that declares an in-process override gets its OWN cache
    ///   instance — bindings don't share entries across overrides.
    /// - `kind: disabled` — explicit opt-out. `cache_get` / `cache_put`
    ///   become no-ops for this binding regardless of the gateway-wide
    ///   default.
    /// - Full plugin id / short alias — refused at boot today; the
    ///   `ResponseCache` trait lives in `mcpg-backend-llm-shared`, not
    ///   in `mcpg-plugin-protocol`, so plugins can't impl it yet. A
    ///   future `ResponseCachePlugin` trait would make this arm live.
    /// - `kind: cluster` — refused; cluster coordinators don't
    ///   advertise the response-cache role.
    ///
    /// `None` (default) inherits the gateway-wide
    /// `storage.response_cache:` (which itself can be `kind: disabled`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<crate::config::wiring::KindRef>,

    /// Per-binding quota policy reference. Names at most one of each
    /// kind by id; each id must resolve to a registered policy in
    /// `governance.quotas.{rate_limits,budgets,concurrency}[]`.
    /// `None` (default) means this binding is exempt from quota
    /// enforcement. The runtime gate that consults this field is
    /// behind the `governance-quotas` cargo feature — until that
    /// feature is on, the field is parsed + validated but inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<crate::config::quotas::BackendQuotasRef>,

    // Tool hints (MCP 2025-11-25):
    #[serde(default)]
    pub annotations: Option<BackendAnnotationsConfig>,
    #[serde(default)]
    pub task_support: Option<String>,

    // Prompt-specific fields:
    #[serde(default)]
    pub prompt_arguments: Option<Vec<PromptArgumentConfig>>,

    // Resource-specific fields:
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,

    // Resource template fields:
    #[serde(default)]
    pub uri_template: Option<String>,

    /// Optional completion sources per template variable. The
    /// `completion/complete` handler returns the filtered subset matching
    /// the caller's prefix when the MCP client opens auto-complete on a
    /// resource template variable. Keys MUST match a `{variable}` declared
    /// in `uri_template`; mismatched keys are dropped at registration
    /// with a warning.
    ///
    /// Each value is a [`VariableCompletionSource`] — either a bare
    /// `["v1", "v2"]` array (shorthand for `{ kind: static, values: [...] }`)
    /// or a tagged `{ kind: static | dynamic, … }` object. The
    /// `dynamic` form names a registered backend; the gateway dispatches
    /// to that backend's [`BackendPlugin::complete_template_variable`]
    /// at request time and clamps the result to 100 values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable_completions: Option<BTreeMap<String, VariableCompletionSource>>,

    // Resource watch configuration for subscription-based change detection:
    #[serde(default)]
    pub watch: Option<ResourceWatchConfig>,

    /// MCP 2025-11-25 descriptor extensions — icons and free-form `_meta`.
    /// Populated directly on the tool/prompt/resource/template
    /// descriptor that this binding produces.
    #[serde(default)]
    pub icons: Option<Vec<BackendIconConfig>>,
    #[serde(default)]
    pub descriptor_meta: Option<serde_json::Value>,

    /// MCP App URL — a link to a rich UI for this resource. Populated
    /// on `_meta.mcpAppUrl` in resources/list descriptors and
    /// resources/read results. Supports CEL interpolation for dynamic
    /// segments (e.g., `https://app.example.com/docs/${arguments.id}`).
    /// Only meaningful on `kind: resource` or `kind: resource_template`.
    #[serde(default)]
    pub mcp_app_url: Option<String>,

    /// Optional per-resource size hint (bytes) surfaced on
    /// `resources/list` entries. Meaningful only on `kind: resource`
    /// bindings; ignored elsewhere.
    #[serde(default)]
    pub resource_size: Option<u64>,

    /// Optional resource annotations (`audience`, `priority`,
    /// `lastModified`) surfaced on `resources/list` entries. Meaningful
    /// only on `kind: resource` or `kind: resource_template` bindings.
    #[serde(default)]
    pub resource_annotations: Option<BackendResourceAnnotations>,
}

/// Per-template-variable completion source.
///
/// The bare-list shorthand stays valid (post-launch shipping shape):
/// `variable_completions: { region: ["us-east-1", "us-west-2"] }` is
/// read by the `BareList` arm and treated as if the operator had
/// written `{ kind: static, values: [...] }`. The tagged form is the
/// new shape — `kind: dynamic` introduces backend dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(untagged)]
pub enum VariableCompletionSource {
    /// Shorthand for `{ kind: static, values: [...] }`.
    BareList(Vec<String>),
    /// Discriminated form. New shape; `kind: dynamic` introduces
    /// dispatch to a backend's `complete_template_variable` method.
    Tagged(TaggedVariableCompletionSource),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaggedVariableCompletionSource {
    /// Static list of completion values. Same shape as the
    /// shorthand bare-list but with explicit `kind` tag.
    Static { values: Vec<String> },
    /// Dynamic dispatch: at completion time, the gateway calls
    /// [`crate::backends::CapabilityRegistry::complete_argument`],
    /// which routes to the named backend's
    /// `BackendPlugin::complete_template_variable(binding_name,
    /// variable_name, prefix, &config)`. The backend returns up to
    /// 100 completions matching the prefix.
    Dynamic {
        /// Binding name that hosts the lookup. Must resolve to a
        /// registered backend at boot — dangling names log a warning
        /// at registration and the variable falls through to the
        /// empty-completion path (spec-valid empty result).
        backend: String,
        /// Backend-specific opaque config. SQL passes
        /// `{ query: "SELECT DISTINCT … LIKE :prefix || '%' …",
        /// max_results?: u32 }`; future HTTP would pass
        /// `{ endpoint: "…" }`. The gateway does not inspect these
        /// fields — it forwards them to the backend, which routes
        /// internally.
        #[serde(default)]
        config: serde_json::Value,
    },
}

impl VariableCompletionSource {
    /// True iff this source resolves to a static list (either bare
    /// shorthand or the tagged static form). Used at registration
    /// time to decide between the static map and the dynamic map.
    pub fn as_static_values(&self) -> Option<&[String]> {
        match self {
            VariableCompletionSource::BareList(v) => Some(v.as_slice()),
            VariableCompletionSource::Tagged(TaggedVariableCompletionSource::Static { values }) => {
                Some(values.as_slice())
            }
            VariableCompletionSource::Tagged(TaggedVariableCompletionSource::Dynamic {
                ..
            }) => None,
        }
    }

    /// `Some((backend, config))` when this source is the dynamic
    /// dispatch form; `None` otherwise.
    pub fn as_dynamic(&self) -> Option<(&str, &serde_json::Value)> {
        match self {
            VariableCompletionSource::Tagged(TaggedVariableCompletionSource::Dynamic {
                backend,
                config,
            }) => Some((backend.as_str(), config)),
            _ => None,
        }
    }
}

/// Operator-configurable MCP `ContentAnnotations` for a resource binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct BackendResourceAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl BackendResourceAnnotations {
    pub fn to_protocol(&self) -> crate::protocol::ContentAnnotations {
        crate::protocol::ContentAnnotations {
            audience: self.audience.clone(),
            priority: self.priority,
            last_modified: self.last_modified.clone(),
        }
    }
}

/// Configurable descriptor icon shape, mirrored onto MCP's `Icon` type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct BackendIconConfig {
    pub src: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub sizes: Option<Vec<String>>,
    #[serde(default)]
    pub theme: Option<String>,
}

impl BackendIconConfig {
    pub fn to_protocol_icon(&self) -> crate::protocol::Icon {
        crate::protocol::Icon {
            src: self.src.clone(),
            mime_type: self.mime_type.clone(),
            sizes: self.sizes.clone(),
            theme: self.theme.clone(),
        }
    }
}

/// Convert an optional list of `BackendIconConfig` into MCP `Icon`s.
pub fn binding_icons(cfg: Option<&Vec<BackendIconConfig>>) -> Option<Vec<crate::protocol::Icon>> {
    cfg.map(|icons| icons.iter().map(|i| i.to_protocol_icon()).collect())
}

/// Tool annotation hints configurable per binding. Maps to MCP `ToolAnnotations`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, schemars::JsonSchema)]
pub struct BackendAnnotationsConfig {
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub destructive: Option<bool>,
    #[serde(default)]
    pub idempotent: Option<bool>,
    #[serde(default)]
    pub open_world: Option<bool>,
}

/// Implementation backend, identified by `kind:` with an opaque flattened
/// `spec`. The gateway enumerates NO plugin kinds: a binding names a `kind`
/// (a loaded `BackendPlugin::kind()` string) and every other key flattens into
/// `spec`, forwarded verbatim to the plugin's `register_profile` / `execute`.
/// The plugin owns and validates the schema; the gateway resolves `kind`
/// against the registry at boot and fails closed on unknown / non-backend
/// kinds. Mirrors `WatchStrategyConfig::Plugin`.
///
/// `spec` is an open object (no `deny_unknown_fields`); unknown keys are
/// forwarded verbatim, so a spec-key typo is caught only by the owning
/// plugin's `register_profile` (`InvalidSpec` at boot), not at config-load.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BackendImpl {
    /// Target `BackendPlugin::kind()` string, resolved against the registry at boot.
    pub kind: String,
    /// Spec forwarded verbatim to the plugin (it owns the schema).
    #[serde(flatten)]
    #[schemars(with = "serde_json::Value")]
    pub spec: serde_json::Map<String, serde_json::Value>,
}

impl BackendImpl {
    /// Build the generic binding from a typed config by serializing it into the
    /// flattened `spec` (the `kind` tag is set separately; a typed config
    /// serializes to its fields only). Used by tests and pipeline-step lowering.
    pub fn from_typed<T: serde::Serialize>(kind: &str, config: T) -> Self {
        let spec = match serde_json::to_value(config) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        BackendImpl {
            kind: kind.to_owned(),
            spec,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpBackendConfig {
    pub url: String,
    #[serde(default = "default_http_binding_method")]
    pub method: HttpBackendMethod,
    #[serde(default = "default_binding_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_http_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_http_expected_status_codes")]
    pub expected_status_codes: Vec<u16>,
    #[serde(default)]
    pub require_json_response: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Config-layer HTTP method discriminator for the `http` backend
/// binding. The gateway translates this into the plugin's runtime
/// `mcpg_plugin_backend_net_core::types::HttpBackendMethod`; both speak
/// the same vocabulary and both accept any common casing
/// (`get`/`GET`/`Get`) so `method:` reads identically wherever it
/// appears.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HttpBackendMethod {
    #[serde(alias = "POST", alias = "Post")]
    Post,
    #[serde(alias = "GET", alias = "Get")]
    Get,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct BackendGovernanceConfig {
    #[serde(default = "default_binding_minimum_trust")]
    pub minimum_trust: TrustLevelConfig,
    #[serde(default)]
    pub allow_if: Option<String>,
}

impl Default for BackendGovernanceConfig {
    fn default() -> Self {
        Self {
            minimum_trust: default_binding_minimum_trust(),
            allow_if: None,
        }
    }
}

/// Per-binding retry configuration. Only applies to HTTP, gRPC, GraphQL, NATS, and Kafka bindings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial attempt).
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,
    /// Initial backoff delay in milliseconds. Doubled on each subsequent retry.
    #[serde(default = "default_retry_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// HTTP status codes that trigger a retry (only applicable to HTTP/gRPC/GraphQL bindings).
    #[serde(default = "default_retry_on_status_codes")]
    pub retry_on_status_codes: Vec<u16>,
    /// Whether to retry on transport/connection errors.
    #[serde(default = "crate::config::default_true")]
    pub retry_on_transport_error: bool,
}

impl RetryConfig {
    pub(crate) fn validate(&self, path: &str) -> Result<()> {
        crate::config::require_positive(path, "retry.max_attempts", u64::from(self.max_attempts))?;
        if self.max_attempts > 10 {
            return Err(anyhow::anyhow!(
                "{}.retry.max_attempts must not exceed 10",
                path
            ));
        }
        crate::config::require_positive(path, "retry.initial_backoff_ms", self.initial_backoff_ms)?;
        Ok(())
    }
}

fn default_retry_max_attempts() -> u32 {
    3
}

fn default_retry_initial_backoff_ms() -> u64 {
    200
}

fn default_retry_on_status_codes() -> Vec<u16> {
    vec![429, 502, 503, 504]
}

impl BackendGovernanceConfig {
    pub(crate) fn validate(&self, path: &str) -> Result<()> {
        if self
            .allow_if
            .as_ref()
            .is_some_and(|expr| expr.trim().is_empty())
        {
            return Err(anyhow::anyhow!(
                "{}.governance.allow_if must not be empty when provided",
                path
            ));
        }
        Ok(())
    }
}

fn default_binding_minimum_trust() -> TrustLevelConfig {
    TrustLevelConfig::HeaderAsserted
}

fn default_http_binding_method() -> HttpBackendMethod {
    HttpBackendMethod::Post
}

fn default_binding_timeout_ms() -> u64 {
    2000
}

fn default_http_max_response_bytes() -> usize {
    4096
}

fn default_http_expected_status_codes() -> Vec<u16> {
    vec![200]
}

fn default_nats_max_response_bytes() -> usize {
    65536
}

fn default_kafka_max_response_bytes() -> usize {
    65536
}

fn default_kafka_timeout_ms() -> u64 {
    10000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KafkaBackendConfig {
    /// Bootstrap servers (`host:port,host:port,…`). All Kafka
    /// bindings in a single gateway must agree on this value —
    /// the gateway opens one shared producer/consumer host with
    /// these bootstrap servers at boot. This field lives on the
    /// binding (rather than a top-level `kafka:` block) to keep
    /// connection config next to the thing that uses it.
    pub bootstrap_servers: String,
    /// Consumer group id. All Kafka bindings must agree on this
    /// value too — it scopes consumer-group membership across the
    /// gateway's shared Kafka clients.
    pub group_id: String,
    pub request_topic: String,
    pub response_topic: String,
    #[serde(default = "default_kafka_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_kafka_max_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MockBackendConfig {
    #[serde(default)]
    pub response: serde_json::Value,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub error: bool,
    #[serde(default)]
    pub error_message: Option<String>,
    /// When `true`, `response` is treated as a literal
    /// `ToolCallResult` shape and surfaced to the client unchanged
    /// (typed fields: `content`, `isError`, `structuredContent`,
    /// `_meta`). Default `false` keeps the historical behaviour:
    /// the configured `response` value is JSON-stringified into a
    /// single text content block, with structured metadata
    /// produced separately.
    ///
    /// Use this for tools that need to surface MCP content shapes
    /// the wrapping path can't reach — image, audio, embedded
    /// resource, mixed-content arrays. Customer-facing example: an
    /// HTTP-backed tool whose API returns base64 image data; the
    /// operator wires it via a thin passthrough Mock + a transform
    /// step so the client receives `type: image` content.
    #[serde(default)]
    pub passthrough: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatsBackendConfig {
    /// Server URL (`nats://…` or `tls://…`). All NATS bindings in
    /// a single gateway must agree on this value — the gateway
    /// opens one shared `async_nats::Client` at boot and reuses
    /// it across every NATS profile. This field lives on the
    /// binding (rather than a top-level `nats:` block) to keep
    /// connection config next to the thing that uses it.
    pub url: String,
    /// Optional path to a NATS credentials file. Same constraint
    /// as `url`: every NATS binding must declare the same value
    /// (or all omit it).
    #[serde(default)]
    pub credentials_path: Option<String>,
    pub subject: String,
    #[serde(default = "default_binding_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_nats_max_response_bytes")]
    pub max_response_bytes: usize,
}

// --- Pipeline binding configuration ---

fn default_pipeline_timeout_ms() -> u64 {
    30_000
}

fn default_elicitation_timeout_ms() -> u64 {
    60_000
}

fn default_sampling_timeout_ms() -> u64 {
    60_000
}

fn default_roots_list_timeout_ms() -> u64 {
    30_000
}

fn default_sampling_max_tokens() -> u64 {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PipelineBackendConfig {
    #[serde(default = "default_pipeline_timeout_ms")]
    pub pipeline_timeout_ms: u64,
    pub steps: Vec<PipelineStepConfig>,
}

/// A single step in an inline pipeline binding.
///
/// Two shapes share the `kind:` wire tag. The control-flow variants
/// (`transform`, `plugin_transform`, `cel_gate`, the suspending
/// elicitation / sampling / roots / gather steps, `log`, `progress`,
/// `sql_tx`, `sql_await`) are gateway-owned and stay typed. Every other
/// `kind:` value is a backend step: it names a loaded
/// `BackendPlugin::kind()` directly and every sibling key flattens into
/// [`PipelineBackendStepConfig::spec`], forwarded verbatim to the plugin
/// — exactly like a [`BackendImpl`] binding. There is no per-vendor
/// enumeration; `kind` is data, not a literal.
///
/// (De)serialization is custom — see the `Deserialize` / `Serialize`
/// impls below — so the discriminator (`kind`) doubles as the backend
/// plugin id without a second field.
#[derive(Debug, Clone, PartialEq, schemars::JsonSchema)]
#[schemars(untagged)]
pub enum PipelineStepConfig {
    /// Backend step — `{ kind: <plugin>, id, …spec, input_transform? }`.
    /// `kind` names the target `BackendPlugin::kind()`; `id` and
    /// `input_transform` are the only step-level reserved keys, and
    /// everything else flattens into `spec`.
    Backend(PipelineBackendStepConfig),
    Transform(PipelineTransformStepConfig),
    /// Reshape the pipeline context by invoking a named `transform` plugin.
    /// Generic bridge — works with any transform plugin; the
    /// first user is `dev.mcpg.transform.jsonata`. The plugin receives the
    /// full pipeline context (`steps`, `arguments`, `context`, `tool_name`)
    /// and its `config` (e.g. a JSONata `expression`); its output is the
    /// step result.
    PluginTransform(PipelinePluginTransformStepConfig),
    CelGate(PipelineCelGateStepConfig),
    Elicitation(PipelineElicitationStepConfig),
    Sampling(PipelineSamplingStepConfig),
    RootsList(PipelineRootsListStepConfig),
    /// SEP-2322 multi-entry MRTR. Emits several server-to-client
    /// input requests (elicitation / sampling / roots) in ONE
    /// suspension and resumes once the client answers them together.
    /// Distinct from listing the individual suspending steps in
    /// sequence (which suspends/resumes one at a time).
    Gather(PipelineGatherStepConfig),
    /// Emit a `notifications/message` on the session's SSE
    /// channel. Non-suspending — pipeline continues immediately.
    Log(PipelineLogStepConfig),
    /// Emit a `notifications/progress` on the session's SSE
    /// channel. Non-suspending. Skipped (silently) when the
    /// inbound request didn't include a `progressToken`.
    Progress(PipelineProgressStepConfig),
    /// Nested SQL container with transactional semantics.
    /// Each inner step runs against a pinned connection; any error
    /// rolls the whole group back.
    SqlTx(PipelineSqlTxStepConfig),
    /// Fire-and-wait step. References an existing SQL binding
    /// whose profile declares `[bindings.sql.await]`. The plugin's
    /// inline await runtime is invoked: trigger query → poll-loop
    /// the check query → CEL predicate evaluation → matched row or
    /// timeout. Same machinery as the standalone SQL await binding,
    /// exposed for pipeline composability.
    SqlAwait(PipelineSqlAwaitStepConfig),
}

/// Wire tags of the gateway-owned control-flow step variants. Any
/// `kind:` outside this set is a backend step routed by plugin id.
const CONTROL_STEP_KINDS: &[&str] = &[
    "transform",
    "plugin_transform",
    "cel_gate",
    "elicitation",
    "sampling",
    "roots_list",
    "gather",
    "log",
    "progress",
    "sql_tx",
    "sql_await",
];

impl PipelineStepConfig {
    pub fn id(&self) -> &str {
        match self {
            Self::Backend(s) => &s.id,
            Self::Transform(s) => &s.id,
            Self::PluginTransform(s) => &s.id,
            Self::CelGate(s) => &s.id,
            Self::Elicitation(s) => &s.id,
            Self::Sampling(s) => &s.id,
            Self::RootsList(s) => &s.id,
            Self::Gather(s) => &s.id,
            Self::Log(s) => &s.id,
            Self::Progress(s) => &s.id,
            Self::SqlTx(s) => &s.id,
            Self::SqlAwait(s) => &s.id,
        }
    }

    /// Dispatch label. For a backend step this is the plugin kind; for a
    /// control-flow step it is the step's wire tag.
    pub fn type_label(&self) -> &str {
        match self {
            Self::Backend(s) => s.kind.as_str(),
            Self::Transform(_) => "transform",
            Self::PluginTransform(_) => "plugin_transform",
            Self::CelGate(_) => "cel_gate",
            Self::Elicitation(_) => "elicitation",
            Self::Sampling(_) => "sampling",
            Self::RootsList(_) => "roots_list",
            Self::Gather(_) => "gather",
            Self::Log(_) => "log",
            Self::Progress(_) => "progress",
            Self::SqlTx(_) => "sql_tx",
            Self::SqlAwait(_) => "sql_await",
        }
    }

    pub fn is_suspending(&self) -> bool {
        matches!(
            self,
            Self::Elicitation(_) | Self::Sampling(_) | Self::RootsList(_) | Self::Gather(_)
        )
    }

    /// Build a backend step from a typed backend config by flattening it
    /// into `spec` (the `kind` tag is set separately; a typed config
    /// serializes to its fields only). Mirrors [`BackendImpl::from_typed`]
    /// for pipeline-step construction in tests and tooling.
    pub fn backend_from_typed<T: serde::Serialize>(
        id: impl Into<String>,
        kind: impl Into<String>,
        config: T,
        input_transform: Option<String>,
    ) -> Self {
        let spec = match serde_json::to_value(config) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        Self::Backend(PipelineBackendStepConfig {
            id: id.into(),
            kind: kind.into(),
            spec,
            input_transform,
        })
    }

    pub fn input_transform(&self) -> Option<&str> {
        match self {
            Self::Backend(s) => s.input_transform.as_deref(),
            Self::SqlTx(s) => s.input_transform.as_deref(),
            Self::SqlAwait(s) => s.input_transform.as_deref(),
            Self::Transform(_)
            | Self::PluginTransform(_)
            | Self::CelGate(_)
            | Self::Elicitation(_)
            | Self::Sampling(_)
            | Self::RootsList(_)
            | Self::Gather(_)
            | Self::Log(_)
            | Self::Progress(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for PipelineStepConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let mut map: serde_json::Map<String, serde_json::Value> =
            Deserialize::deserialize(deserializer)?;

        let kind = match map.get("kind") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(_) => return Err(D::Error::custom("pipeline step `kind` must be a string")),
            None => return Err(D::Error::missing_field("kind")),
        };

        if CONTROL_STEP_KINDS.contains(&kind.as_str()) {
            // Control-flow step: route the whole object into the matching
            // typed variant. Re-tag through the derived serde so each
            // variant's own field rules (defaults, deny_unknown_fields)
            // still apply.
            let value = serde_json::Value::Object(map);
            macro_rules! typed {
                ($variant:ident) => {{
                    serde_json::from_value(value)
                        .map(PipelineStepConfig::$variant)
                        .map_err(D::Error::custom)
                }};
            }
            return match kind.as_str() {
                "transform" => typed!(Transform),
                "plugin_transform" => typed!(PluginTransform),
                "cel_gate" => typed!(CelGate),
                "elicitation" => typed!(Elicitation),
                "sampling" => typed!(Sampling),
                "roots_list" => typed!(RootsList),
                "gather" => typed!(Gather),
                "log" => typed!(Log),
                "progress" => typed!(Progress),
                "sql_tx" => typed!(SqlTx),
                "sql_await" => typed!(SqlAwait),
                _ => unreachable!("kind matched CONTROL_STEP_KINDS"),
            };
        }

        // Backend step: `kind` names the plugin; `id` and
        // `input_transform` are the only reserved step-level keys; every
        // remaining key flattens into `spec` (which excludes
        // kind/id/input_transform — same convention as `BackendImpl`).
        map.remove("kind");
        let id = match map.remove("id") {
            Some(serde_json::Value::String(s)) => s,
            Some(_) => return Err(D::Error::custom("pipeline step `id` must be a string")),
            None => return Err(D::Error::missing_field("id")),
        };
        let input_transform = match map.remove("input_transform") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) => Some(s),
            Some(_) => {
                return Err(D::Error::custom(
                    "pipeline step `input_transform` must be a string",
                ));
            }
        };

        Ok(PipelineStepConfig::Backend(PipelineBackendStepConfig {
            id,
            kind,
            spec: map,
            input_transform,
        }))
    }
}

impl Serialize for PipelineStepConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error as _;

        // Control-flow variants serialize through the derived path with
        // their `kind` tag reinstated; the backend variant emits
        // `kind`/`id`/`input_transform?` then the flattened spec.
        let mut value = match self {
            Self::Backend(s) => {
                let mut obj = serde_json::Map::new();
                obj.insert("kind".to_owned(), serde_json::Value::String(s.kind.clone()));
                obj.insert("id".to_owned(), serde_json::Value::String(s.id.clone()));
                if let Some(it) = &s.input_transform {
                    obj.insert(
                        "input_transform".to_owned(),
                        serde_json::Value::String(it.clone()),
                    );
                }
                for (k, v) in &s.spec {
                    obj.insert(k.clone(), v.clone());
                }
                return serde_json::Value::Object(obj)
                    .serialize(serializer)
                    .map_err(S::Error::custom);
            }
            Self::Transform(s) => serde_json::to_value(s),
            Self::PluginTransform(s) => serde_json::to_value(s),
            Self::CelGate(s) => serde_json::to_value(s),
            Self::Elicitation(s) => serde_json::to_value(s),
            Self::Sampling(s) => serde_json::to_value(s),
            Self::RootsList(s) => serde_json::to_value(s),
            Self::Gather(s) => serde_json::to_value(s),
            Self::Log(s) => serde_json::to_value(s),
            Self::Progress(s) => serde_json::to_value(s),
            Self::SqlTx(s) => serde_json::to_value(s),
            Self::SqlAwait(s) => serde_json::to_value(s),
        }
        .map_err(S::Error::custom)?;

        if let serde_json::Value::Object(obj) = &mut value {
            obj.insert(
                "kind".to_owned(),
                serde_json::Value::String(self.type_label().to_owned()),
            );
        }
        value.serialize(serializer).map_err(S::Error::custom)
    }
}

/// Backend pipeline step — `{ kind: <plugin>, id, …spec, input_transform? }`.
/// `kind` names the target `BackendPlugin::kind()` directly (the same
/// discriminator the wire carries), and every remaining key flattens into
/// `spec`, forwarded verbatim to the plugin via `execute_envelope_plugin` —
/// exactly like a [`BackendImpl`] binding. `id` and `input_transform` are
/// the only step-level reserved keys the gateway reads; neither appears in
/// `spec`.
///
/// The enclosing [`PipelineStepConfig`] uses a custom `Deserialize` /
/// `Serialize`, so this struct's derived serde impls are not exercised on
/// the pipeline-step wire path; they are kept for direct (de)serialization
/// in tests and tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct PipelineBackendStepConfig {
    pub id: String,
    /// Target `BackendPlugin::kind()` string for this step.
    pub kind: String,
    /// Spec forwarded verbatim to the plugin (it owns the schema).
    #[serde(flatten)]
    #[schemars(with = "serde_json::Value")]
    pub spec: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub input_transform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineTransformStepConfig {
    pub id: String,
    pub expression: String,
}

/// `kind: plugin_transform` step — reshape the pipeline context via a named
/// transform plugin. The gateway materializes the pipeline
/// context (`steps`, `arguments`, `context`, `tool_name`) and forwards it to
/// the plugin's `transform_result` along with `config`; the plugin's output
/// becomes the step result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct PipelinePluginTransformStepConfig {
    pub id: String,
    /// Alias/id of a registered `transform` plugin (e.g.
    /// `dev.mcpg.transform.jsonata`).
    pub plugin: String,
    /// Opaque per-step config handed to the plugin (e.g.
    /// `{ "expression": "<jsonata>" }`).
    #[serde(default)]
    pub config: serde_json::Value,
}

/// `type: sql_tx` container step. References an existing SQL
/// binding and groups one or more SQL statements under a single
/// transaction — all-or-nothing semantics.
///
/// Statements run sequentially on a pinned pool connection.
/// Any error rolls the whole group back; successful completion
/// commits. Non-SQL step types inside an `sql_tx` are rejected at
/// config-validation time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineSqlTxStepConfig {
    pub id: String,
    /// Name of an existing SQL backend whose connection pool backs
    /// the transaction. The referenced backend must be declared
    /// with `backend.sql.*`.
    pub backend: String,
    /// SQL statements executed against the shared tx handle, in
    /// declaration order.
    pub steps: Vec<PipelineSqlTxNestedStep>,
    #[serde(default)]
    pub input_transform: Option<String>,
}

/// One SQL statement inside a `sql_tx` container. Mirrors the shape
/// of a standalone binding's `query` block but scoped to the
/// container's transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineSqlTxNestedStep {
    pub id: String,
    /// SQL body — either a literal string or `sql_file` path,
    /// following the same shape as standalone binding queries.
    pub sql: String,
    /// Declared parameter names, in bind order if the statement
    /// uses positional placeholders.
    #[serde(default)]
    pub params: Vec<String>,
    /// Row-shape mode for this statement. Defaults to
    /// `affected_rows` since sql_tx steps are write-heavy in
    /// practice (INSERT / UPDATE / DELETE).
    #[serde(default = "default_sql_tx_row_mode")]
    pub row_mode: String,
    #[serde(default)]
    pub input_transform: Option<String>,
}

pub(crate) fn default_sql_tx_row_mode() -> String {
    "affected_rows".to_owned()
}

/// `kind: sql_await` pipeline step. References an existing SQL
/// binding whose profile declares `[bindings.sql.await]` and runs the
/// plugin's inline fire-and-wait runtime as a composable step.
///
/// Step input is forwarded as the binding payload (the same shape a
/// direct `tools/call` would carry) — operator-declared params + CEL
/// `param_exprs` derive the trigger / check bind values from there.
/// On match, the matched row is the step output; on timeout, the
/// step errors and the pipeline aborts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineSqlAwaitStepConfig {
    pub id: String,
    /// Name of an existing SQL backend profile with an `await` block.
    /// The referenced backend must be declared with `backend.sql.*`
    /// and must carry a `[backends.sql.await]` configuration — the
    /// runtime path is identical to a direct `tools/call` against
    /// that profile.
    pub backend: String,
    #[serde(default)]
    pub input_transform: Option<String>,
}

pub(crate) fn default_cel_gate_error_message(step_id: &str) -> String {
    format!("pipeline gate failed at step {}", step_id)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineCelGateStepConfig {
    pub id: String,
    pub expression: String,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Elicitation mode per MCP 2025-11-25. `form` collects a schema-driven
/// response; `url` redirects the client to a URL and correlates the
/// completion via `notifications/elicitation/complete`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PipelineElicitationMode {
    #[default]
    Form,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineElicitationStepConfig {
    pub id: String,
    pub message: String,
    #[serde(default)]
    pub mode: PipelineElicitationMode,
    #[serde(default)]
    pub requested_schema: Option<serde_json::Value>,
    /// URL mode: URL the client should navigate the user to.
    #[serde(default)]
    pub url: Option<String>,
    /// URL mode: server-owned identifier the client echoes back on
    /// `notifications/elicitation/complete`. When omitted the runtime
    /// generates a UUID per invocation.
    #[serde(default)]
    pub elicitation_id: Option<String>,
    /// Presentation hint: `"inline"`, `"popup"`, or `"newWindow"`.
    #[serde(default)]
    pub presentation_hint: Option<String>,
    /// Free-form `_meta` attached to the outgoing server request.
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    #[serde(default = "default_elicitation_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional override for the server-minted request id used as the
    /// MRTR `inputRequests` correlation key (2026-07-28 modern wire).
    /// When `None`, the runtime mints a UUID per invocation. When set,
    /// the operator's value is used verbatim — useful for tooling that
    /// expects a known key (e.g., conformance suites, integration tests).
    /// **Caveat:** must be unique across concurrent invocations of this
    /// step; collisions overwrite pending-request state in the pipeline
    /// store. Leave unset for production multi-session deployments.
    #[serde(default)]
    pub correlation_token: Option<String>,
    /// SEP-2322 capability-aware pruning. When `true` and the client
    /// did not advertise the capability this step requires, the
    /// executor SKIPS the step (records an empty skipped result and
    /// advances) instead of failing the pipeline. Default `false`
    /// preserves the fail-closed contract for production pipelines
    /// where a missing capability indicates a client/config bug.
    #[serde(default)]
    pub skip_if_unsupported: bool,
}

// Eq dropped: temperature is an f64.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct PipelineSamplingStepConfig {
    pub id: String,
    pub messages: Vec<SamplingMessageConfig>,
    #[serde(default = "default_sampling_max_tokens")]
    pub max_tokens: u64,
    #[serde(default = "default_sampling_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub system_prompt: Option<String>,
    /// Emission gated on the client advertising `sampling.context`.
    /// Typed enum — unknown values fail config load.
    #[serde(default)]
    pub include_context: Option<crate::protocol::SamplingIncludeContext>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(default)]
    pub model_preferences: Option<serde_json::Value>,
    /// Emission gated on the client advertising `sampling.tools`.
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// See [`PipelineElicitationStepConfig::correlation_token`].
    #[serde(default)]
    pub correlation_token: Option<String>,
    /// See [`PipelineElicitationStepConfig::skip_if_unsupported`].
    #[serde(default)]
    pub skip_if_unsupported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct SamplingMessageConfig {
    pub role: String,
    pub content: String,
}

/// Pipeline step that sends `roots/list` to the client and suspends
/// until the client responds with its root URIs. The result is stored
/// in the pipeline context as `steps.<id>.output.roots`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineRootsListStepConfig {
    pub id: String,
    #[serde(default = "default_roots_list_timeout_ms")]
    pub timeout_ms: u64,
    /// See [`PipelineElicitationStepConfig::correlation_token`].
    #[serde(default)]
    pub correlation_token: Option<String>,
    /// See [`PipelineElicitationStepConfig::skip_if_unsupported`].
    #[serde(default)]
    pub skip_if_unsupported: bool,
}

/// SEP-2322 multi-entry MRTR step. Emits every entry in `inputs` as a
/// distinct server-to-client request inside ONE `InputRequiredResult`
/// suspension; the pipeline resumes once the client returns all of
/// them in a single `inputResponses` map. The step's combined output
/// is `steps.<id>.output.<correlation_token>` per answered input, so
/// downstream `transform` steps can read each result.
///
/// Capability pruning: inputs whose required client capability wasn't
/// advertised are dropped from the emitted set (the modern wire's
/// "only emit inputRequests the client supports" contract). If every
/// input is pruned the step completes immediately with an empty
/// output instead of suspending.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct PipelineGatherStepConfig {
    pub id: String,
    /// Two or more inputs to request together. Each carries its own
    /// `correlation_token` — the key the client echoes back in
    /// `inputResponses` and the key under which the answer lands in
    /// this step's output.
    pub inputs: Vec<GatherInputConfig>,
}

/// One entry in a [`PipelineGatherStepConfig`]. A trimmed projection
/// of the standalone suspending-step configs carrying only the fields
/// needed to mint the outgoing server request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatherInputConfig {
    Elicitation {
        correlation_token: String,
        message: String,
        #[serde(default)]
        requested_schema: Option<serde_json::Value>,
    },
    Sampling {
        correlation_token: String,
        messages: Vec<SamplingMessageConfig>,
        #[serde(default = "default_sampling_max_tokens")]
        max_tokens: u64,
        #[serde(default)]
        system_prompt: Option<String>,
    },
    Roots {
        correlation_token: String,
    },
}

impl GatherInputConfig {
    /// Correlation token — the `inputRequests` map key the client
    /// echoes back and the gather step's output key.
    pub fn correlation_token(&self) -> &str {
        match self {
            Self::Elicitation {
                correlation_token, ..
            }
            | Self::Sampling {
                correlation_token, ..
            }
            | Self::Roots {
                correlation_token, ..
            } => correlation_token,
        }
    }
}

/// Pipeline step that publishes a `notifications/message` to the
/// session's delivery bus. Non-suspending — execution continues to
/// the next step immediately after the notification is queued.
///
/// Used by tools that surface structured log output to the client
/// during long-running work (e.g., LLM streaming progress, batch
/// pipelines reporting per-batch status, conformance test fixtures
/// for SEP-2575 `tools-call-with-logging`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct PipelineLogStepConfig {
    pub id: String,
    /// Severity level. Accepted values follow the MCP logging
    /// vocabulary: `debug` / `info` / `notice` / `warning` /
    /// `error` / `critical` / `alert` / `emergency`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Optional logger name. Surfaces on
    /// `notifications/message.params.logger` so clients can
    /// route by component. When unset, MCPG emits the binding
    /// name as a sensible default.
    #[serde(default)]
    pub logger: Option<String>,
    /// The message payload. Free-form — the spec lets servers ship
    /// strings, structured maps, or anything else. Typically a
    /// string description of what's happening.
    pub data: serde_json::Value,
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// Pipeline step that publishes a `notifications/progress` to the
/// session's delivery bus. Non-suspending — execution continues to
/// the next step immediately after the notification is queued.
///
/// The progress token is read from the inbound request's
/// `_meta.io.modelcontextprotocol/progressToken` (modern wire) or
/// `_meta.progressToken` (legacy). When the caller didn't supply
/// one, the step skips emission (silently — no progress token means
/// the client didn't ask for streaming progress).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct PipelineProgressStepConfig {
    pub id: String,
    /// Progress so far. Combined with `total` to compute the
    /// completion fraction client-side.
    pub progress: f64,
    /// Optional upper bound. When set, the client SHOULD render a
    /// determinate progress bar. When unset, an indeterminate
    /// spinner is appropriate.
    #[serde(default)]
    pub total: Option<f64>,
    /// Optional human-readable status to surface alongside the
    /// numeric progress, e.g. "Compiling library X".
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod deny_unknown_binding_tests {
    //! The fully-enumerated, gateway-owned binding kinds reject
    //! unknown fields so a typo'd binding-config key fails at parse rather
    //! than being silently dropped. The flatten-passthrough kinds (sql +
    //! the LLM families) intentionally stay permissive — the plugin owns
    //! that schema.
    use super::*;

    #[test]
    fn http_binding_accepts_known_fields() {
        let v = serde_json::json!({ "kind": "http", "url": "https://api.example.com" });
        let parsed: BackendImpl = serde_json::from_value(v).expect("valid http binding");
        assert!((parsed.kind == "http"));
    }

    #[test]
    fn sql_binding_stays_permissive_passthrough() {
        // Flatten-passthrough kind: extra keys are forwarded to the plugin,
        // NOT rejected at the gateway layer.
        let v = serde_json::json!({
            "kind": "sql",
            "database": "orders",
            "plugin_specific_future_field": true
        });
        assert!(serde_json::from_value::<BackendImpl>(v).is_ok());
    }
}

#[cfg(test)]
mod pipeline_step_tests {
    //! Backend pipeline steps collapse to the generic `Backend` variant:
    //! the `kind:` wire tag names the plugin directly and the remaining
    //! keys flatten into `spec`. Control-flow steps stay typed.
    use super::*;

    fn step(v: serde_json::Value) -> PipelineStepConfig {
        serde_json::from_value(v).expect("valid pipeline step")
    }

    #[test]
    fn backend_step_routes_to_generic_variant() {
        let s = step(serde_json::json!({
            "kind": "duckdb",
            "id": "load",
            "database": ":memory:",
            "statement": "SELECT 1",
            "input_transform": "${steps.prev.output}"
        }));
        let PipelineStepConfig::Backend(b) = &s else {
            panic!("expected backend step");
        };
        assert_eq!(b.kind, "duckdb");
        assert_eq!(b.id, "load");
        assert_eq!(b.input_transform.as_deref(), Some("${steps.prev.output}"));
        // kind/id/input_transform are reserved and do NOT land in spec.
        assert!(!b.spec.contains_key("kind"));
        assert!(!b.spec.contains_key("id"));
        assert!(!b.spec.contains_key("input_transform"));
        assert_eq!(
            b.spec.get("database").and_then(|v| v.as_str()),
            Some(":memory:")
        );
        assert_eq!(s.type_label(), "duckdb");
        assert_eq!(s.id(), "load");
        assert_eq!(s.input_transform(), Some("${steps.prev.output}"));
        assert!(!s.is_suspending());
    }

    #[test]
    fn backend_step_input_transform_optional() {
        let s = step(serde_json::json!({
            "kind": "bigquery", "id": "report", "project_id": "p", "statement": "SELECT 2"
        }));
        assert_eq!(s.type_label(), "bigquery");
        assert_eq!(s.id(), "report");
        assert_eq!(s.input_transform(), None);
    }

    #[test]
    fn missing_id_on_backend_step_is_an_error() {
        let r: Result<PipelineStepConfig, _> =
            serde_json::from_value(serde_json::json!({ "kind": "duckdb", "database": ":memory:" }));
        assert!(r.is_err());
    }

    #[test]
    fn missing_kind_is_an_error() {
        let r: Result<PipelineStepConfig, _> =
            serde_json::from_value(serde_json::json!({ "id": "x", "database": ":memory:" }));
        assert!(r.is_err());
    }

    #[test]
    fn control_step_stays_typed() {
        // cel_gate routes to the typed CelGate variant, not a backend step.
        let s = step(serde_json::json!({
            "kind": "cel_gate", "id": "guard", "expression": "true"
        }));
        assert!(matches!(s, PipelineStepConfig::CelGate(_)));
        assert_eq!(s.type_label(), "cel_gate");
        assert_eq!(s.id(), "guard");

        // transform likewise.
        let t = step(serde_json::json!({
            "kind": "transform", "id": "shape", "expression": "${steps.prev.output}"
        }));
        assert!(matches!(t, PipelineStepConfig::Transform(_)));
        assert_eq!(t.type_label(), "transform");
    }

    #[test]
    fn backend_step_wire_compat_round_trip() {
        // An existing per-vendor pipeline step (`kind: dynamodb` + flattened
        // backend fields + id) must keep parsing into the generic Backend
        // variant, and serialize back to the identical wire object.
        let wire = serde_json::json!({
            "kind": "dynamodb",
            "id": "s1",
            "region": "us-east-1",
            "table": "t",
            "operation": "scan",
            "partition_key": { "name": "pk", "type": "S" },
            "input_transform": "${steps.prev.output}"
        });
        let parsed: PipelineStepConfig =
            serde_json::from_value(wire.clone()).expect("valid dynamodb step");
        let PipelineStepConfig::Backend(b) = &parsed else {
            panic!("expected backend step");
        };
        assert_eq!(b.kind, "dynamodb");
        assert_eq!(b.id, "s1");
        assert_eq!(b.input_transform.as_deref(), Some("${steps.prev.output}"));
        assert_eq!(
            b.spec.get("region").and_then(|v| v.as_str()),
            Some("us-east-1")
        );
        assert_eq!(b.spec.get("table").and_then(|v| v.as_str()), Some("t"));
        assert_eq!(
            b.spec.get("operation").and_then(|v| v.as_str()),
            Some("scan")
        );
        assert!(b.spec.get("partition_key").is_some());

        // Round-trip: serialize back to the same wire object.
        let reser = serde_json::to_value(&parsed).expect("serialize");
        assert_eq!(reser, wire);
    }

    #[test]
    fn pipeline_parses_mixed_backend_and_control_steps() {
        let v = serde_json::json!({
            "pipeline_timeout_ms": 30000,
            "steps": [
                { "kind": "duckdb", "id": "load", "database": ":memory:", "statement": "SELECT 1" },
                { "kind": "cel_gate", "id": "guard", "expression": "true" },
                { "kind": "clickhouse", "id": "report", "url": "http://ch:8123", "statement": "SELECT 2" }
            ]
        });
        let parsed: PipelineBackendConfig = serde_json::from_value(v).expect("valid pipeline");
        assert_eq!(parsed.steps.len(), 3);
        assert_eq!(parsed.steps[0].type_label(), "duckdb");
        assert!(matches!(parsed.steps[1], PipelineStepConfig::CelGate(_)));
        assert_eq!(parsed.steps[2].type_label(), "clickhouse");
    }

    #[test]
    fn pipeline_step_kinds_match_binding_kinds() {
        // Each backend kind parses to a generic step whose dispatch label
        // (type_label) equals the wire `kind` — identical to the top-level
        // binding tag.
        let kinds = [
            "dynamodb",
            "elasticsearch",
            "oracle",
            "snowflake",
            "duckdb",
            "clickhouse",
            "odbc",
            "hana",
            "twilio",
            "bigquery",
            "ftp",
            "smb",
        ];
        for kind in kinds {
            let parsed: PipelineStepConfig = serde_json::from_value(serde_json::json!({
                "kind": kind, "id": "s1", "anything": true
            }))
            .unwrap_or_else(|e| panic!("{kind} step: {e}"));
            assert_eq!(parsed.type_label(), kind);
            assert_eq!(parsed.id(), "s1");
            assert!(matches!(parsed, PipelineStepConfig::Backend(_)));
        }
    }
}
