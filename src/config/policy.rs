//! Top-level `policy:` block — tool access policy + L1 decision
//! cache + per-decision-point policy_engine chain.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::wiring::KindRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub tool_access: ToolAccessPolicyConfig,
    #[serde(default)]
    pub cache: PolicyCacheConfig,
    /// Ordered chain of policy engines consulted at every
    /// decision point (`tool.call.pre`, `plugin.lifecycle.register`,
    /// etc.). Each entry is a [`KindRef`] — `kind:` resolves to a
    /// built-in keyword (`yaml-rules`), a short alias (`cedar`,
    /// `opa`, `casbin` → `dev.mcpg.policy.<alias>`), or a full
    /// reverse-domain plugin id. Chain semantics: the host walks
    /// the list in order, short-circuiting on the first
    /// `Allow` / `Deny`; `NotApplicable` falls through to the
    /// next engine. An empty chain is equivalent to
    /// `NotApplicable` everywhere — callers (e.g.
    /// `enforce_plugin_registration_policy`) decide whether
    /// that means "allow" (default-allow gateway) or
    /// "fail-closed" per their own policy posture.
    ///
    /// Operators who want only the built-in YAML-rules engine
    /// write `engine: [{ kind: yaml-rules }]`. Multi-engine
    /// deployments that pair declarative authz with a richer
    /// rule engine write
    /// `engine: [{ kind: yaml-rules }, { kind: cedar, config: {...} }]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine: Vec<KindRef>,
}

/// Configuration for the policy decision cache (L1 process-local).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_policy_cache_ttl_ms")]
    pub ttl_ms: u64,
    #[serde(default = "default_policy_cache_max_entries")]
    pub max_entries: usize,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_ms: default_policy_cache_ttl_ms(),
            max_entries: default_policy_cache_max_entries(),
        }
    }
}

impl PolicyCacheConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.ttl_ms == 0 {
            return Err(anyhow::anyhow!(
                "policy.cache.ttl_ms must be > 0 when cache is enabled"
            ));
        }
        if self.enabled && self.max_entries == 0 {
            return Err(anyhow::anyhow!(
                "policy.cache.max_entries must be > 0 when cache is enabled"
            ));
        }
        Ok(())
    }
}

fn default_policy_cache_ttl_ms() -> u64 {
    60000
}

fn default_policy_cache_max_entries() -> usize {
    10_000
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<()> {
        self.tool_access.validate()?;
        self.cache.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolAccessPolicyConfig {
    #[serde(default = "default_minimum_tool_trust")]
    pub default_minimum_trust: TrustLevelConfig,
    #[serde(default)]
    pub cel_allow_if: Option<String>,
    #[serde(default)]
    pub rules: Vec<ToolTrustRuleConfig>,
}

impl Default for ToolAccessPolicyConfig {
    fn default() -> Self {
        Self {
            default_minimum_trust: default_minimum_tool_trust(),
            cel_allow_if: None,
            rules: Vec::new(),
        }
    }
}

impl ToolAccessPolicyConfig {
    pub fn validate(&self) -> Result<()> {
        if self
            .cel_allow_if
            .as_deref()
            .is_some_and(|expression| expression.trim().is_empty())
        {
            return Err(anyhow::anyhow!(
                "policy.tool_access.cel_allow_if must not be empty when provided"
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            match &rule.event_name {
                Some(_) if !rule.tool_name.is_empty() => {
                    return Err(anyhow::anyhow!(
                        "policy.tool_access.rules[] names `{}` both as a tool_name and as an \
                         event_name; a rule governs one of them",
                        rule.tool_name
                    ));
                }
                Some(name) if !crate::config::events::is_event_name(name) => {
                    return Err(anyhow::anyhow!(
                        "policy.tool_access.rules[].event_name `{name}` is not an event type name"
                    ));
                }
                Some(_) => {}
                None if rule.tool_name.trim().is_empty() => {
                    return Err(anyhow::anyhow!(
                        "policy.tool_access.rules[].tool_name must not be empty"
                    ));
                }
                None => {}
            }
            if rule
                .cel_allow_if
                .as_deref()
                .is_some_and(|expression| expression.trim().is_empty())
            {
                return Err(anyhow::anyhow!(
                    "policy.tool_access.rules[].cel_allow_if must not be empty when provided"
                ));
            }
            if rule
                .required_scopes
                .iter()
                .any(|scope| scope.trim().is_empty())
            {
                return Err(anyhow::anyhow!(
                    "policy.tool_access.rules[].required_scopes must not contain empty entries"
                ));
            }
            if !seen.insert(rule.policy_key()) {
                return Err(anyhow::anyhow!(
                    "policy.tool_access.rules must not contain duplicate tool_name or \
                     event_name entries"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolTrustRuleConfig {
    /// The tool, prompt or resource the rule governs. Set this or
    /// `event_name`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_name: String,
    /// The MCP Events type the rule governs: who may see it in
    /// `events/list` and subscribe to it. A rule here never governs a tool
    /// of the same name. Set this or `tool_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    pub minimum_trust: TrustLevelConfig,
    #[serde(default)]
    pub cel_allow_if: Option<String>,
    /// OAuth scopes the caller's token MUST carry to invoke this tool
    /// (SEP-2350). A caller authenticated but lacking any of these is
    /// denied with HTTP 403 + a `WWW-Authenticate: Bearer
    /// error="insufficient_scope", scope="…"` step-up challenge naming the
    /// missing scopes, rather than a bare 403 — so a capability-aware
    /// client can request the additional scopes and retry. Empty (the
    /// default) means no scope requirement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
}

impl ToolTrustRuleConfig {
    /// The name the rule is filed under: the tool name, or `event:<name>`
    /// for an event type, so the two never meet.
    pub fn policy_key(&self) -> String {
        match &self.event_name {
            Some(name) => format!("event:{name}"),
            None => self.tool_name.clone(),
        }
    }
}

pub use mcpg_expr::governance::TrustLevelConfig;

fn default_minimum_tool_trust() -> TrustLevelConfig {
    TrustLevelConfig::HeaderAsserted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &str) -> Result<()> {
        let config: ToolAccessPolicyConfig =
            serde_yaml::from_str(&format!("rules:\n{rules}")).expect("parses");
        config.validate()
    }

    #[test]
    fn an_event_rule_is_filed_apart_from_a_tool_of_the_same_name() {
        let config: ToolAccessPolicyConfig = serde_yaml::from_str(
            "rules:\n  - event_name: orders.created\n    minimum_trust: verified\n  - tool_name: \
             orders.created\n    minimum_trust: verified\n",
        )
        .unwrap();
        config
            .validate()
            .expect("a tool and an event may share a name");
        assert_eq!(config.rules[0].policy_key(), "event:orders.created");
        assert_eq!(config.rules[1].policy_key(), "orders.created");
    }

    #[test]
    fn an_event_rule_names_one_valid_event_type() {
        assert!(
            policy("  - event_name: a.b\n    tool_name: a.b\n    minimum_trust: verified\n")
                .is_err()
        );
        assert!(policy("  - event_name: 'has space'\n    minimum_trust: verified\n").is_err());
        assert!(
            policy(
                "  - event_name: a.b\n    minimum_trust: verified\n  - event_name: a.b\n    \
                 minimum_trust: unauthenticated\n"
            )
            .is_err(),
            "duplicates"
        );
        assert!(
            policy("  - minimum_trust: verified\n").is_err(),
            "names nothing"
        );
    }
}
