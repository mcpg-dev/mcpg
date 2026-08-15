//! `mcp:` namespace — the MCP protocol surface.
//!
//! Carries first-class MCP capabilities (tasks, elicitation, sampling,
//! roots) plus a `configurations:` sub-tree for runtime-emergent
//! state operators only configure constraints + persistence on
//! (sessions, pipelines, subscriptions, delivery, cancellation).
//!
//! ## Distinction
//!
//! - **First-class MCP capabilities** (under `mcp:` directly):
//!   tasks, elicitation, sampling, roots. The operator declares
//!   what these surfaces look like. Tasks list the tools that opt
//!   into task semantics; elicitation/sampling/roots tune the
//!   gateway's behavior when the protocol-side calls land.
//! - **Runtime-emergent handling** (under `mcp.configurations:`):
//!   sessions, pipelines, subscriptions, delivery, cancellation.
//!   Clients create these at runtime via MCP requests; the
//!   operator only configures persistence (`store:` / `bus:`) and
//!   constraints (max-per-session, idle timeouts).
//!
//! ## Bindings
//!
//! Bindings live in per-capability typed arrays under
//! `mcp.capabilities:` (`mcp.capabilities.tools[]`,
//! `mcp.capabilities.prompts[]`, `mcp.capabilities.resources[]`,
//! `mcp.capabilities.resource_templates[]`) — list membership is
//! what tells the gateway which capability surface each binding serves.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::apps::AppsConfig;
use super::backend::{BackendConfig, BackendKind};
use super::capability_state::{
    CancellationConfig, DeliveryConfig, IdempotencyConfig, PipelinesConfig, RequestStateConfig,
    SessionsConfig, SubscriptionsConfig, TasksConfig,
};
use super::federation::FederationConfig;

/// Top-level `mcp:` block — the MCP protocol surface.
///
/// Two children that mirror MCP's own vocabulary:
/// - `capabilities:` — what the server advertises in the `initialize`
///   handshake (tools, prompts, resources, resource_templates, tasks,
///   elicitation, sampling, roots).
/// - `configurations:` — runtime-emergent state handling (sessions,
///   pipelines, subscriptions, delivery, cancellation). Operator only
///   tunes persistence + constraints; the items themselves are created
///   by clients at runtime.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// What this MCP server advertises in the `initialize` handshake.
    /// Mirrors the protocol spec's `capabilities` vocabulary one-to-one.
    #[serde(default)]
    pub capabilities: McpCapabilitiesConfig,

    /// Runtime-emergent state handling. Operator only tunes
    /// persistence + constraints; the items themselves are created
    /// by clients at runtime.
    #[serde(default)]
    pub configurations: McpConfigurationsConfig,

    /// Upstream MCP servers federated through this gateway. Each entry
    /// is a *capability source* (1:N): MCPG connects to the upstream,
    /// imports its capabilities, and re-serves them under a prefix.
    /// Default empty — existing configs are unaffected.
    #[serde(default)]
    pub federations: Vec<FederationConfig>,

    /// MCP registries whose listed servers MCPG auto-federates: a
    /// background syncer crawls each registry's `/v0.1` API and
    /// materializes one federation per usable server, kept in sync as
    /// the registry changes. Default empty.
    #[serde(default)]
    pub registries: Vec<crate::config::registry::McpRegistryConfig>,

    /// The registry MCPG *serves* (contrast `registries`, the
    /// registries MCPG *consumes*): a v0.1 MCP-Registry view of this
    /// gateway — one entry describing the governed catalog — so
    /// registry-driven clients (e.g. Copilot's allowed-registry
    /// policy) can discover MCPG as their approved server. Off by
    /// default.
    #[serde(default)]
    pub registry: crate::config::registry::ServedRegistryConfig,
}

/// `mcp.capabilities:` — the MCP protocol-advertised surface.
///
/// Matches the protocol's `initialize` handshake's `capabilities`
/// vocabulary: tools / prompts / resources / resource_templates,
/// plus the gateway-side feature configs that govern protocol
/// behaviour (tasks, elicitation, sampling, roots).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpCapabilitiesConfig {
    /// Operator-declared tools — the bindings that surface via
    /// `tools/list` and `tools/call`. Each entry has its own
    /// implementation `backend:` (HTTP / SQL / NATS / LLM / pipeline /
    /// …) plus tool-specific MCP fields (`annotations`, `task_support`).
    #[serde(default)]
    pub tools: Vec<BackendConfig>,

    /// Operator-declared prompts — the bindings that surface via
    /// `prompts/list` and `prompts/get`. Carry `prompt_arguments`.
    #[serde(default)]
    pub prompts: Vec<BackendConfig>,

    /// Operator-declared resources — the bindings that surface via
    /// `resources/list` and `resources/read`. Carry `uri`,
    /// `mime_type`, `mcp_app_url`, watch config.
    #[serde(default)]
    pub resources: Vec<BackendConfig>,

    /// Operator-declared resource templates — the bindings that
    /// surface via `resources/templates/list` and match `resources/read`
    /// URIs by template. Carry `uri_template` instead of `uri`.
    #[serde(default)]
    pub resource_templates: Vec<BackendConfig>,

    /// MCP Tasks — task-augmented tool-call semantics. Carries the task
    /// store override, TTL/reaper tuning, and the task-supported tools
    /// list.
    #[serde(default)]
    pub tasks: TasksConfig,

    /// MCP elicitation — server-initiated prompt requests the gateway
    /// emits during pipeline execution.
    #[serde(default)]
    pub elicitation: McpElicitationConfig,

    /// MCP sampling — server-initiated LLM completion requests
    /// forwarded back to the client.
    #[serde(default)]
    pub sampling: McpSamplingConfig,

    /// MCP roots-list — gateway requests roots from the client (e.g.
    /// for resource scoping).
    #[serde(default)]
    pub roots: McpRootsConfig,
}

impl McpConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.capabilities.validate()?;
        self.configurations.validate()?;
        self.validate_federations()?;
        self.validate_registries()?;
        Ok(())
    }

    fn validate_registries(&self) -> Result<()> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for registry in &self.registries {
            registry.validate()?;
            if !seen.insert(registry.name.as_str()) {
                anyhow::bail!(
                    "mcp.registries: duplicate registry name `{}`",
                    registry.name
                );
            }
        }
        self.registry.validate()?;
        Ok(())
    }

    /// Per-entry validation plus cross-federation invariants: unique
    /// names, unique tool prefixes, no native tool shadowed by a
    /// prefix, and a prefix required once more than one upstream is
    /// federated (otherwise upstream tool names could collide).
    fn validate_federations(&self) -> Result<()> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for fed in &self.federations {
            fed.validate()?;
            if !seen.insert(fed.name.as_str()) {
                anyhow::bail!("mcp.federations: duplicate federation name `{}`", fed.name);
            }
        }
        let mut prefixes: Vec<(&str, &str)> = Vec::new();
        for fed in &self.federations {
            let prefix = fed.tool_prefix();
            if prefix.is_empty() {
                continue;
            }
            if let Some((other, _)) = prefixes.iter().find(|(_, p)| *p == prefix) {
                anyhow::bail!(
                    "mcp.federations: `{}` and `{}` share tool_prefix `{}`",
                    other,
                    fed.name,
                    prefix
                );
            }
            prefixes.push((fed.name.as_str(), prefix));
        }
        for tool in &self.capabilities.tools {
            if let Some((fed_name, prefix)) =
                prefixes.iter().find(|(_, p)| tool.name.starts_with(*p))
            {
                anyhow::bail!(
                    "mcp.capabilities.tools[`{}`] collides with federation `{}` tool_prefix `{}`; rename the tool or change the prefix",
                    tool.name,
                    fed_name,
                    prefix
                );
            }
        }
        let unprefixed: Vec<&str> = self
            .federations
            .iter()
            .filter(|f| f.tool_prefix().is_empty())
            .map(|f| f.name.as_str())
            .collect();
        if unprefixed.len() > 1 {
            anyhow::bail!(
                "mcp.federations: {:?} have no naming.tool_prefix; a prefix is required when federating more than one upstream",
                unprefixed
            );
        }
        Ok(())
    }

    /// Iterate every operator-declared binding across the four typed
    /// lists (`tools` / `prompts` / `resources` / `resource_templates`)
    /// alongside its [`BackendKind`]. Delegates to
    /// [`McpCapabilitiesConfig::all_bindings`].
    pub fn all_bindings(&self) -> impl Iterator<Item = (BackendKind, &BackendConfig)> {
        self.capabilities.all_bindings()
    }

    /// Mutable counterpart to [`Self::all_bindings`].
    pub fn all_bindings_mut(&mut self) -> impl Iterator<Item = (BackendKind, &mut BackendConfig)> {
        self.capabilities.all_bindings_mut()
    }

    /// Total count of operator-declared bindings across all four lists.
    pub fn binding_count(&self) -> usize {
        self.capabilities.binding_count()
    }
}

impl McpCapabilitiesConfig {
    /// Whether the gateway exposes any argument-completion source — a
    /// prompt argument with static `completions`, or a resource
    /// template with `variable_completions`. Drives whether the
    /// `completions` server capability is advertised (PR-02); mirrors
    /// the runtime `CapabilityRegistry::has_completions` gate so the
    /// modern `server/discover` advertisement matches the legacy
    /// `initialize` one.
    pub(crate) fn has_completions(&self) -> bool {
        let prompt_completions = self.prompts.iter().any(|p| {
            p.prompt_arguments.as_ref().is_some_and(|args| {
                args.iter()
                    .any(|a| a.completions.as_ref().is_some_and(|c| !c.is_empty()))
            })
        });
        let template_completions = self.resource_templates.iter().any(|t| {
            t.variable_completions
                .as_ref()
                .is_some_and(|m| !m.is_empty())
        });
        prompt_completions || template_completions
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.tasks
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.capabilities.tasks: {e}"))?;
        self.elicitation
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.capabilities.elicitation: {e}"))?;
        self.sampling
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.capabilities.sampling: {e}"))?;
        self.roots
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.capabilities.roots: {e}"))?;
        Ok(())
    }

    /// Iterate every operator-declared binding across the four typed
    /// lists (`tools` / `prompts` / `resources` / `resource_templates`)
    /// alongside its [`BackendKind`]. Most cross-cutting validations
    /// (name uniqueness, NATS-URL agreement, content-storage
    /// references) need to see every binding regardless of capability.
    pub fn all_bindings(&self) -> impl Iterator<Item = (BackendKind, &BackendConfig)> {
        self.tools
            .iter()
            .map(|b| (BackendKind::Tool, b))
            .chain(self.prompts.iter().map(|b| (BackendKind::Prompt, b)))
            .chain(self.resources.iter().map(|b| (BackendKind::Resource, b)))
            .chain(
                self.resource_templates
                    .iter()
                    .map(|b| (BackendKind::ResourceTemplate, b)),
            )
    }

    /// Mutable counterpart to [`Self::all_bindings`]. Used by the
    /// schema-ref resolver, which mutates `input_schema` /
    /// `output_schema` in place after the initial parse.
    pub fn all_bindings_mut(&mut self) -> impl Iterator<Item = (BackendKind, &mut BackendConfig)> {
        self.tools
            .iter_mut()
            .map(|b| (BackendKind::Tool, b))
            .chain(self.prompts.iter_mut().map(|b| (BackendKind::Prompt, b)))
            .chain(
                self.resources
                    .iter_mut()
                    .map(|b| (BackendKind::Resource, b)),
            )
            .chain(
                self.resource_templates
                    .iter_mut()
                    .map(|b| (BackendKind::ResourceTemplate, b)),
            )
    }

    /// Total count of operator-declared bindings across all four lists.
    pub fn binding_count(&self) -> usize {
        self.tools.len() + self.prompts.len() + self.resources.len() + self.resource_templates.len()
    }
}

/// `mcp.configurations:` — runtime-emergent state handling.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpConfigurationsConfig {
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub pipelines: PipelinesConfig,
    #[serde(default)]
    pub subscriptions: SubscriptionsConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub cancellation: CancellationConfig,
    /// `dev.mcpg/idempotency` extension config. Off by
    /// default; flipping `enabled: true` lights up the SEP-2133
    /// capability advertisement and the dispatcher dedupe path.
    #[serde(default)]
    pub idempotency: IdempotencyConfig,
    /// MRTR `requestState` codec configuration (2026-07-28 modern
    /// wire). Inert when no modern client
    /// connects; absent encryption_key the codec uses an ephemeral
    /// key at boot.
    #[serde(default)]
    pub request_state: RequestStateConfig,
    /// `io.modelcontextprotocol/ui` (SEP-1865 MCP Apps) extension
    /// config. Off by default; `enabled: true` lights up the
    /// capability advertisement (downstream + upstream) and the
    /// tighten-only CSP/permission egress policy.
    #[serde(default)]
    pub apps: AppsConfig,
}

impl McpConfigurationsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.sessions
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.sessions: {e}"))?;
        self.pipelines
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.pipelines: {e}"))?;
        self.subscriptions
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.subscriptions: {e}"))?;
        self.delivery
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.delivery: {e}"))?;
        self.cancellation
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.cancellation: {e}"))?;
        self.idempotency
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.idempotency: {e}"))?;
        self.request_state
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.request_state: {e}"))?;
        self.apps
            .validate()
            .map_err(|e| anyhow::anyhow!("mcp.configurations.apps: {e}"))?;
        Ok(())
    }
}

/// `mcp.elicitation:` — gateway behavior for server-initiated
/// elicitation prompts. Today carries only `timeout_ms`; future
/// per-elicitation-type config can grow here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpElicitationConfig {
    /// Maximum time the gateway waits for the client's response
    /// to an elicitation prompt before giving up. Default 60 000.
    #[serde(default = "default_elicitation_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for McpElicitationConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_elicitation_timeout_ms(),
        }
    }
}

impl McpElicitationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::config::require_positive("mcp.elicitation", "timeout_ms", self.timeout_ms)?;
        Ok(())
    }
}

fn default_elicitation_timeout_ms() -> u64 {
    60_000
}

/// `mcp.sampling:` — gateway behavior for server-initiated sampling
/// (LLM completion) requests forwarded to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpSamplingConfig {
    /// Maximum time the gateway waits for the client's sampling
    /// response. Default 60 000.
    #[serde(default = "default_sampling_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for McpSamplingConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_sampling_timeout_ms(),
        }
    }
}

impl McpSamplingConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::config::require_positive("mcp.sampling", "timeout_ms", self.timeout_ms)?;
        Ok(())
    }
}

fn default_sampling_timeout_ms() -> u64 {
    60_000
}

/// `mcp.roots:` — gateway behavior for server-initiated roots-list
/// requests forwarded to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpRootsConfig {
    /// Maximum time the gateway waits for the client's roots-list
    /// response. Default 30 000.
    #[serde(default = "default_roots_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for McpRootsConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_roots_timeout_ms(),
        }
    }
}

impl McpRootsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::config::require_positive("mcp.roots", "timeout_ms", self.timeout_ms)?;
        Ok(())
    }
}

fn default_roots_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_config_defaults_round_trip() {
        let cfg = McpConfig::default();
        cfg.validate().expect("default mcp config valid");
        assert_eq!(cfg.capabilities.elicitation.timeout_ms, 60_000);
        assert_eq!(cfg.capabilities.sampling.timeout_ms, 60_000);
        assert_eq!(cfg.capabilities.roots.timeout_ms, 30_000);
    }

    #[test]
    fn mcp_elicitation_zero_timeout_rejected() {
        let cfg = McpConfig {
            capabilities: McpCapabilitiesConfig {
                elicitation: McpElicitationConfig { timeout_ms: 0 },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("elicitation"), "{err}");
    }

    #[test]
    fn mcp_sampling_zero_timeout_rejected() {
        let cfg = McpConfig {
            capabilities: McpCapabilitiesConfig {
                sampling: McpSamplingConfig { timeout_ms: 0 },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("sampling"), "{err}");
    }

    #[test]
    fn mcp_roots_zero_timeout_rejected() {
        let cfg = McpConfig {
            capabilities: McpCapabilitiesConfig {
                roots: McpRootsConfig { timeout_ms: 0 },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("roots"), "{err}");
    }

    #[test]
    fn mcp_serde_round_trip() {
        let yaml = r#"
capabilities:
  tasks:
    default_ttl_ms: 3600000
  elicitation:
    timeout_ms: 30000
configurations:
  subscriptions:
    max_per_session: 50
"#;
        let cfg: McpConfig = serde_yaml::from_str(yaml).expect("parse");
        cfg.validate().expect("valid");
        assert_eq!(cfg.capabilities.tasks.default_ttl_ms, 3600000);
        assert_eq!(cfg.capabilities.elicitation.timeout_ms, 30_000);
        assert_eq!(cfg.configurations.subscriptions.max_per_session, 50);
    }
}
