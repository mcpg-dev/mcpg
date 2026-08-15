use crate::config::{BackendConfig, BackendImpl};
use serde_json::Value;

/// Map a binding config to the `kind` string the plugin registry
/// uses to look up its plugin. Returns `None` only for the gateway-native
/// behavioral routes `http` and `pipeline`; every other kind (including
/// `command` and `mock`) returns `Some(kind)` and is dispatched by the
/// registry.
///
/// LLM bindings are split per provider: each provider
/// is its own plugin (kind `openai.chat`, `azure_openai.chat`,
/// `anthropic.chat`, `gemini.chat`, `compat.chat`).
pub fn binding_plugin_kind(bt: &BackendImpl) -> Option<&str> {
    // `http` + `pipeline` are gateway-native behavioral routes
    // (NetworkJsonCall / Pipeline), not registry-dispatched plugins; every
    // other kind dispatches to its plugin by name. This exclusion is a
    // separate concern from `host::CHILD_TOOL_INELIGIBLE_KINDS` (which
    // gates LLM child-tool eligibility); the two overlap only on `pipeline`.
    match bt.kind.as_str() {
        "http" | "pipeline" => None,
        k => Some(k),
    }
}

/// The registry key a binding's backend is actually registered under.
///
/// For most kinds this is the config `kind` verbatim. LLM bindings carry the
/// underscore config form (`openai_chat`) but their plugins register under the
/// dotted [`LlmKind::plugin_kind`] form (`openai.chat`), so a raw
/// `registry.backend(kind)` lookup would miss them. This single helper performs
/// that normalization so every registry-lookup site (boot guard, dynamic
/// register pass, pipeline-step pass) resolves the same key and cannot drift.
///
/// Returns `None` for the gateway-native behavioral routes that are never
/// registry-dispatched (`http`, `pipeline`).
pub fn registry_lookup_kind(bt: &BackendImpl) -> Option<String> {
    let kind = binding_plugin_kind(bt)?;
    Some(match LlmKind::from_kind_str(kind) {
        Some(llm) => llm.plugin_kind().to_owned(),
        None => kind.to_owned(),
    })
}

/// Build the per-binding `register_profile` spec JSON for a backend that
/// the gateway loads as a **dynamic cdylib plugin**. The generic
/// dynamic-registration path in `app/mod.rs` calls this for each binding
/// whose [`binding_plugin_kind`] resolves to a registry-dispatched plugin.
///
/// The binding's `spec` is forwarded verbatim and the server-level SSRF
/// toggle `allow_private_backends` (`gateway.server.allow_private_backends`)
/// is injected unconditionally — network-touching plugins honor it, the
/// rest ignore the extra field. Always returns `Some`.
///
/// Connection-level config that a plugin needs at construction (kafka
/// `bootstrap_servers` / `group_id`) reaches it through its `plugins[]`
/// entry `config:` instead; this spec carries only the per-binding fields.
pub fn dynamic_register_spec(bt: &BackendImpl, allow_private_backends: bool) -> Option<Value> {
    // The spec is forwarded verbatim to the plugin's `register_profile`; the
    // server-level SSRF toggle is injected unconditionally (network-touching
    // plugins honor it, the rest ignore the extra field).
    let mut spec = bt.spec.clone();
    spec.insert(
        "allow_private_backends".to_owned(),
        Value::Bool(allow_private_backends),
    );
    Some(Value::Object(spec))
}

/// Read the `(kind, spec)` pair uniformly off ANY [`BackendImpl`], whether
/// it arrived as a typed variant or the generic `{ kind, …spec }` form.
///
/// Typed variants compute the pair via the existing
/// [`binding_plugin_kind`] + [`dynamic_register_spec`] helpers (so the
/// spec is byte-identical to the typed dispatch path); the generic variant
/// returns its own `kind` + flattened `spec`. Returns `None` for binding
/// shapes that don't route through a `BackendPlugin` by kind (the
/// `Pipeline` pseudo-binding, and any typed variant `binding_plugin_kind`
/// excludes).
///
/// This is the single reader the generic dispatch path consults; it never
/// switches on the kind string.
pub fn binding_kind_and_spec(
    bt: &BackendImpl,
    allow_private_backends: bool,
) -> Option<(String, Value)> {
    let kind = binding_plugin_kind(bt)?.to_owned();
    let spec = dynamic_register_spec(bt, allow_private_backends)?;
    Some((kind, spec))
}

/// LLM provider plugin selector carried in `BackendInvocationRoute`
/// and `AdapterToolRoute`. Each variant maps 1-to-1 to a per-provider
/// `BackendPlugin` registered at gateway boot. The `plugin_kind()`
/// method returns the `BackendPlugin::kind()` string used to look the
/// plugin up in the registry, and `metrics_label()` returns the short
/// identifier used in the `provider` metrics label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmKind {
    OpenaiChat,
    AzureOpenaiChat,
    AnthropicChat,
    GeminiChat,
    CompatChat,
    OpenaiEmbedding,
    AzureOpenaiEmbedding,
    GeminiEmbedding,
    CompatEmbedding,
    OpenaiImage,
    AzureOpenaiImage,
    GeminiImage,
    StabilityImage,
    OpenaiTts,
    AzureOpenaiTts,
    OpenaiStt,
    AzureOpenaiStt,
}

impl LlmKind {
    pub fn plugin_kind(&self) -> &'static str {
        match self {
            Self::OpenaiChat => "openai.chat",
            Self::AzureOpenaiChat => "azure_openai.chat",
            Self::AnthropicChat => "anthropic.chat",
            Self::GeminiChat => "gemini.chat",
            Self::CompatChat => "compat.chat",
            Self::OpenaiEmbedding => "openai.embedding",
            Self::AzureOpenaiEmbedding => "azure_openai.embedding",
            Self::GeminiEmbedding => "gemini.embedding",
            Self::CompatEmbedding => "compat.embedding",
            Self::OpenaiImage => "openai.image",
            Self::AzureOpenaiImage => "azure_openai.image",
            Self::GeminiImage => "gemini.image",
            Self::StabilityImage => "stability.image",
            Self::OpenaiTts => "openai.tts",
            Self::AzureOpenaiTts => "azure_openai.tts",
            Self::OpenaiStt => "openai.stt",
            Self::AzureOpenaiStt => "azure_openai.stt",
        }
    }

    /// Map a config `kind:` string (the underscore wire form, e.g.
    /// `openai_chat`) to its `LlmKind`, or `None` when the kind is not an LLM
    /// provider — drives the behavioral LLM route off the generic binding.
    pub fn from_kind_str(kind: &str) -> Option<Self> {
        Some(match kind {
            "openai_chat" => Self::OpenaiChat,
            "azure_openai_chat" => Self::AzureOpenaiChat,
            "anthropic_chat" => Self::AnthropicChat,
            "gemini_chat" => Self::GeminiChat,
            "compat_chat" => Self::CompatChat,
            "openai_embedding" => Self::OpenaiEmbedding,
            "azure_openai_embedding" => Self::AzureOpenaiEmbedding,
            "gemini_embedding" => Self::GeminiEmbedding,
            "compat_embedding" => Self::CompatEmbedding,
            "openai_image" => Self::OpenaiImage,
            "azure_openai_image" => Self::AzureOpenaiImage,
            "gemini_image" => Self::GeminiImage,
            "stability_image" => Self::StabilityImage,
            "openai_tts" => Self::OpenaiTts,
            "azure_openai_tts" => Self::AzureOpenaiTts,
            "openai_stt" => Self::OpenaiStt,
            "azure_openai_stt" => Self::AzureOpenaiStt,
            _ => return None,
        })
    }
}

/// Classify a binding into its [`BackendInvocationRoute`].
///
/// This is the gateway's FIXED behavioral-route set: `http` (GET vs POST),
/// `command`, `nats`, `kafka`, `sql`, `pipeline`, `graphql`, `openapi`, and the
/// per-provider LLM routes (resolved via [`LlmKind::from_kind_str`]). Every
/// other kind dispatches generically by kind string through
/// `execute_envelope_plugin`. Used by both the tool-binding loop and the
/// all-bindings route-map loop so the two surfaces cannot desync.
pub fn classify_behavioral_route(binding: &BackendConfig) -> BackendInvocationRoute {
    match binding.backend.kind.as_str() {
        "http" => {
            if binding
                .backend
                .spec
                .get("method")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.eq_ignore_ascii_case("get"))
            {
                BackendInvocationRoute::NetworkQueryCall {
                    profile: binding.name.clone(),
                }
            } else {
                BackendInvocationRoute::NetworkJsonCall {
                    profile: binding.name.clone(),
                }
            }
        }
        "command" => BackendInvocationRoute::CommandJsonCall {
            profile: binding.name.clone(),
            require_json_stdout: binding
                .backend
                .spec
                .get("require_json_stdout")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        },
        "nats" => BackendInvocationRoute::NatsRequest {
            profile: binding.name.clone(),
        },
        "kafka" => BackendInvocationRoute::KafkaRequest {
            profile: binding.name.clone(),
        },
        "sql" => BackendInvocationRoute::SqlRequest {
            profile: binding.name.clone(),
        },
        "pipeline" => BackendInvocationRoute::Pipeline {
            profile: binding.name.clone(),
        },
        "graphql" => BackendInvocationRoute::GraphqlCall {
            profile: binding.name.clone(),
        },
        "openapi" => BackendInvocationRoute::OpenapiCall {
            profile: binding.name.clone(),
        },
        k if LlmKind::from_kind_str(k).is_some() => BackendInvocationRoute::LlmRequest {
            profile: binding.name.clone(),
            kind: LlmKind::from_kind_str(k).expect("LLM kind string -> LlmKind"),
        },
        // Every other kind dispatches generically by kind string
        // through `execute_envelope_plugin`.
        _ => BackendInvocationRoute::EnvelopePlugin {
            kind: binding.backend.kind.clone(),
            profile: binding.name.clone(),
        },
    }
}

pub const DEFAULT_COMMAND_PROFILE: &str = "default_command_probe";

pub const DEFAULT_NETWORK_PROFILE: &str = "default_network_probe";

#[derive(Debug, Clone)]
pub enum BackendInvocationRoute {
    RuntimeSnapshot,
    RequestEcho,
    CommandProbe {
        profile: String,
    },
    CommandJsonCall {
        profile: String,
        require_json_stdout: bool,
    },
    NetworkProbe {
        profile: String,
    },
    NetworkJsonCall {
        profile: String,
    },
    NetworkQueryCall {
        profile: String,
    },
    NatsRequest {
        profile: String,
    },
    GraphqlCall {
        profile: String,
    },
    KafkaRequest {
        profile: String,
    },
    MockResponse {
        profile: String,
    },
    Pipeline {
        profile: String,
    },
    /// Dispatch through the OpenAPI binding plugin. Like `GrpcCall` /
    /// `GraphqlCall`, the executor forwards the profile name to the
    /// plugin's `execute`, which returns the structured envelope.
    OpenapiCall {
        profile: String,
    },
    /// Dispatch through the SQL binding plugin. Mirrors the
    /// `NatsRequest` / `KafkaRequest` pattern — the executor
    /// forwards the profile name to the plugin's `execute` path.
    SqlRequest {
        profile: String,
    },
    /// Dispatch through one of the per-provider LLM binding plugins.
    /// `kind` picks the plugin (`openai.chat`, `azure_openai.chat`,
    /// `anthropic.chat`, `gemini.chat`, `compat.chat`); `profile`
    /// indexes into that plugin's per-binding state.
    LlmRequest {
        profile: String,
        kind: LlmKind,
    },
    /// Federated tool — dispatched back to its owning upstream MCP
    /// server by the in-gateway `FederationEngine`.
    /// `source` is the `mcp.federations[].name`; `upstream_name` is the
    /// bare (unprefixed) tool name on the upstream.
    Federated {
        source: String,
        upstream_name: String,
    },
    /// Generic backend dispatch by `kind` string — every backend kind
    /// without a gateway-native behavioral route (i.e. not http / command /
    /// nats / kafka / sql / pipeline / graphql / openapi / LLM) routes here.
    /// The executor forwards the profile name to the plugin registered under
    /// `kind` via `execute_envelope_plugin(kind, profile, …)`, which returns
    /// the structured envelope.
    EnvelopePlugin {
        kind: String,
        profile: String,
    },
}

impl BackendInvocationRoute {
    /// Whether this route's executor reads the (allocation-heavy)
    /// `RuntimeSnapshot` from its execution context. Only the two
    /// internal diagnostics tools do — the runtime-snapshot tool
    /// serializes the whole snapshot and the request-echo tool reports
    /// `service`/`version` — so dispatch builds the snapshot lazily,
    /// gated on this, instead of paying for it on every tool call.
    pub fn needs_runtime_snapshot(&self) -> bool {
        matches!(self, Self::RuntimeSnapshot | Self::RequestEcho)
    }
}

#[derive(Debug, Clone)]
pub enum PromptRoute {
    OperationalOverview,
    Binding {
        profile: String,
    },
    /// A federated prompt — fetched from its owning upstream MCP server
    /// by the `FederationEngine`. `upstream_name` is the bare (unprefixed)
    /// prompt name on the upstream.
    Federated {
        source: String,
        upstream_name: String,
    },
}

#[derive(Debug, Clone)]
pub enum ResourceRoute {
    RuntimeOverview,
    /// A gateway-authored templated app, served from the
    /// runtime's compiled `ui://mcpg/<id>` registry.
    GatewayApp {
        id: String,
    },
    Binding {
        profile: String,
    },
    /// a resource URI that matched a registered `uri_template`.
    /// `template_vars` carries the captured variables; the runtime forwards
    /// them to the bound profile so the backend can materialize a concrete
    /// resource response.
    Template {
        profile: String,
        template_vars: std::collections::BTreeMap<String, String>,
    },
    /// A federated resource — read back from its owning upstream MCP
    /// server by the `FederationEngine`. `upstream_uri` is the bare
    /// (unprefixed) URI on the upstream.
    Federated {
        source: String,
        upstream_uri: String,
    },
}
