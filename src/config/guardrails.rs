//! Top-level `guardrails:` block — external HTTP services called
//! pre/post tool execution. Distinct from policy (local trust + CEL):
//! guardrails handle content scanning, human approval, budget
//! enforcement, and external PDP callouts.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

fn default_guardrail_timeout_ms() -> u64 {
    5000
}

fn default_guardrail_max_response_bytes() -> usize {
    65536
}

/// How the gateway behaves when a guardrail service is unreachable or returns an error.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum GuardrailOnError {
    /// Block the tool call (fail-closed). This is the default.
    #[default]
    Deny,
    /// Allow the tool call to proceed (fail-open). Use with caution.
    Allow,
}

/// Configuration for a single guardrail hook (pre- or post-execution).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardrailHookConfig {
    /// Unique name for this guardrail (used in metrics, logs, error messages).
    pub name: String,
    /// HTTP POST endpoint for the guardrail service.
    pub url: String,
    /// Per-call timeout in milliseconds.
    #[serde(default = "default_guardrail_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum response body size in bytes.
    #[serde(default = "default_guardrail_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Behavior on guardrail service error.
    #[serde(default)]
    pub on_error: GuardrailOnError,
    /// Whether this guardrail can modify arguments (pre) or results (post).
    #[serde(default)]
    pub allow_mutation: bool,
    /// Glob patterns for tool names this guardrail applies to. Empty = all tools.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Glob patterns for tool names to exclude.
    #[serde(default)]
    pub exclude_tools: Vec<String>,
    /// Optional CEL expression for conditional activation.
    /// Has access to `tool_name`, `trust_level`, `principal_id`, `auth_provider`.
    /// Must evaluate to a boolean. When `false`, the guardrail is skipped.
    #[serde(default)]
    pub trigger_cel: Option<String>,
    /// Static headers sent to the guardrail service (e.g. for auth).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

impl GuardrailHookConfig {
    pub(crate) fn validate(&self, path: &str) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(anyhow::anyhow!("{}.name must not be empty", path));
        }
        if self.url.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "{}.url must not be empty (guardrail '{}')",
                path,
                self.name
            ));
        }
        let url_trimmed = self.url.trim();
        if !url_trimmed.starts_with("http://") && !url_trimmed.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "{}.url must start with http:// or https:// (guardrail '{}', got '{}')",
                path,
                self.name,
                url_trimmed
            ));
        }
        if self.timeout_ms == 0 {
            return Err(anyhow::anyhow!(
                "{}.timeout_ms must be greater than 0 (guardrail '{}')",
                path,
                self.name
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(anyhow::anyhow!(
                "{}.max_response_bytes must be greater than 0 (guardrail '{}')",
                path,
                self.name
            ));
        }
        if let Some(ref cel_expr) = self.trigger_cel {
            if cel_expr.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{}.trigger_cel must not be empty when provided (guardrail '{}')",
                    path,
                    self.name
                ));
            }
            cel::Program::compile(cel_expr).map_err(|e| {
                anyhow::anyhow!(
                    "{}.trigger_cel is not a valid CEL expression (guardrail '{}'): {}",
                    path,
                    self.name,
                    e
                )
            })?;
        }
        for (key, value) in &self.headers {
            if key.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{}.headers contains an empty key (guardrail '{}')",
                    path,
                    self.name
                ));
            }
            if value.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{}.headers['{}'] must not be empty (guardrail '{}')",
                    path,
                    key,
                    self.name
                ));
            }
        }
        Ok(())
    }
}

/// Top-level guardrails configuration.
///
/// Guardrails are external HTTP services called before and/or after tool execution.
/// They are distinct from policy (which is local trust-level + CEL) — guardrails handle
/// content scanning, human approval, budget enforcement, and external PDP callouts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct GuardrailsConfig {
    /// Pre-execution guardrails — evaluated after policy + schema validation, before dispatch.
    #[serde(default)]
    pub pre_execution: Vec<GuardrailHookConfig>,
    /// Post-execution guardrails — evaluated after binding returns, before client response.
    #[serde(default)]
    pub post_execution: Vec<GuardrailHookConfig>,
}

impl GuardrailsConfig {
    pub fn validate(&self) -> Result<()> {
        let mut seen_names = std::collections::HashSet::new();
        for (i, hook) in self.pre_execution.iter().enumerate() {
            let path = format!("guardrails.pre_execution[{}]", i);
            hook.validate(&path)?;
            if !seen_names.insert(&hook.name) {
                return Err(anyhow::anyhow!(
                    "guardrail name '{}' is duplicated; guardrail names must be unique across all hooks",
                    hook.name
                ));
            }
        }
        for (i, hook) in self.post_execution.iter().enumerate() {
            let path = format!("guardrails.post_execution[{}]", i);
            hook.validate(&path)?;
            if !seen_names.insert(&hook.name) {
                return Err(anyhow::anyhow!(
                    "guardrail name '{}' is duplicated; guardrail names must be unique across all hooks",
                    hook.name
                ));
            }
        }
        Ok(())
    }

    /// Returns true if any guardrail hooks are configured.
    pub fn has_hooks(&self) -> bool {
        !self.pre_execution.is_empty() || !self.post_execution.is_empty()
    }
}
