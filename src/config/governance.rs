//! Top-level `governance:` umbrella block.
//!
//! Holds the tool-call governance lifecycle: identity (`access`)
//! → authorization (`policy`) → human gate (`approvals`) →
//! evidence (`audit`) → limits (`quotas`, a registry of rate
//! limits / budgets / concurrency caps, per
//! `mcp_gateway_governance_quotas_rfc.md`).
//!
//! These blocks share one umbrella so the tool-call-lifecycle
//! story reads as a coherent block rather than scattered
//! top-level peers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::quotas::QuotasConfig;
use super::{AccessConfig, ApprovalsConfig, AuditConfig, PolicyConfig};

/// Tool-call governance lifecycle: who → allowed? → extra gate →
/// recorded → within limits.
///
/// Every child defaults to its own zero-value: an empty
/// `governance:` block is valid YAML and produces a fully-default
/// configuration (anonymous identity, untrusted-by-default policy,
/// no human-gate signing key, audit channel disabled, no quotas
/// declared).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernanceConfig {
    /// Inbound identity establishment — JWKS-backed JWT verification or
    /// OIDC discovery + introspection. When unset the gateway accepts
    /// unauthenticated callers and stamps every request with
    /// `identity_kind: anonymous` so the policy gate can deny them.
    /// `jwks` and `oidc_oauth` are mutually exclusive.
    #[serde(default)]
    pub access: AccessConfig,

    /// Tool-access policy — default minimum trust level + per-tool
    /// override rules. Operators can also point at a Cedar / Casbin
    /// / OPA bundle plugin under `plugins[]` to delegate the actual
    /// decision; this block stays useful for the gateway-internal
    /// default-trust gate every tool flows through before any plugin
    /// policy fires.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Tool-gate human approval — signing key + callback
    /// base url + grace window. When unset, the runtime defaults to
    /// a random per-process signing key + empty callback base url
    /// (suitable for tests + dev only — production deploys must
    /// supply a stable signing key).
    #[serde(default)]
    pub approvals: ApprovalsConfig,

    /// Compliance-grade event sink fan-out (spec §9.12). Lives
    /// under `governance:` (rather than `observability:`) so the
    /// audit-as-evidence-of-governance story reads alongside
    /// access / policy / approvals.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Registry of named rate-limit / budget / concurrency
    /// policies. Bindings opt into specific policies by id via
    /// their per-binding `quotas:` block. Storage backend is a
    /// `kind:` slot under `governance.quotas.store:`.
    ///
    /// Empty by default — operators opt in when they need limit
    /// enforcement. The runtime quota gate short-circuits when no
    /// policies are declared.
    #[serde(default)]
    pub quotas: QuotasConfig,

    /// Authorization for agentic child tool calls — the
    /// backend-to-backend `invoke_tool` path an LLM Generator drives
    /// when it emits `tool_calls`. Off by default.
    #[serde(default)]
    pub child_invoke: ChildInvokeConfig,
}

/// Governance for the agentic child-dispatch surface (`invoke_tool`).
///
/// Direct `tools/call` always runs the full pre-dispatch stack; the
/// child path an LLM binding drives did not. When `enforce_gates` is on,
/// child invocations are routed through the same external policy_engine
/// chain and tool_gate plugin chain as a direct call before reaching the
/// backend, so tool-level access controls are not silently absent on the
/// LLM-driven surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChildInvokeConfig {
    /// Run the policy_engine chain + tool_gate plugin chain on every
    /// child `invoke_tool`. Default false (the agentic surface is
    /// ungated, matching prior behaviour) — enable to require the same
    /// authorization a direct `tools/call` gets. A child whose identity
    /// is unresolved (the LLM path carries no per-call principal today)
    /// evaluates against the inherited parent identity.
    #[serde(default)]
    pub enforce_gates: bool,
}

impl GovernanceConfig {
    pub fn validate(&self) -> Result<()> {
        self.access.validate()?;
        self.policy.validate()?;
        // approvals carries no validation surface today.
        self.audit.validate()?;
        self.quotas.validate()?;
        Ok(())
    }
}
