//! Pre-dispatch policy gate — trust-level enforcement and CEL-based
//! access control evaluated before every tool call.
//!
//! Includes an optional in-process LRU cache for hot-path decisions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as AnyhowContext, Result};
use arc_swap::ArcSwap;
use cel::{
    Context as CelContext, Program, Value as CelValue,
    objects::{Key as CelKey, Map as CelMap},
};

use crate::config::PolicyCacheConfig;
use crate::runtime::{RequestContext, RequestTrustLevel};

/// Configuration for the pre-dispatch policy gate: minimum trust levels
/// and optional CEL expressions that determine whether a tool call is allowed.
#[derive(Debug, Clone)]
pub struct ToolAccessPolicyConfig {
    pub default_minimum_trust: RequestTrustLevel,
    pub cel_allow_if: Option<String>,
    pub rules: Vec<ToolTrustRule>,
}

impl Default for ToolAccessPolicyConfig {
    fn default() -> Self {
        Self {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: Vec::new(),
        }
    }
}

/// Per-tool override of the minimum trust level and optional CEL condition.
#[derive(Debug, Clone)]
pub struct ToolTrustRule {
    pub tool_name: String,
    pub minimum_trust: RequestTrustLevel,
    pub cel_allow_if: Option<String>,
    /// OAuth scopes the caller MUST hold to invoke this tool (SEP-2350).
    /// A caller missing any of these is denied 403 + an
    /// `insufficient_scope` step-up challenge.
    pub required_scopes: Vec<String>,
}

/// Input to the policy evaluator: tool name + caller identity attributes.
#[derive(Debug, Clone)]
pub(crate) struct ToolPolicyContext {
    pub tool_name: String,
    pub trust_level: RequestTrustLevel,
    pub principal_id: Option<String>,
    pub auth_provider: Option<String>,
    pub identity_kind: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub attributes: std::collections::BTreeMap<String, String>,
}

impl ToolPolicyContext {
    pub(crate) fn from_request_context(request_context: &RequestContext, tool_name: &str) -> Self {
        Self {
            tool_name: tool_name.to_owned(),
            trust_level: request_context.identity.trust_level(),
            principal_id: request_context.identity.principal_id().map(str::to_owned),
            auth_provider: request_context.identity.auth_provider().map(str::to_owned),
            identity_kind: request_context.identity.label().to_owned(),
            roles: request_context.identity.roles().to_vec(),
            groups: request_context.identity.groups().to_vec(),
            scopes: request_context.identity.scopes().to_vec(),
            attributes: request_context.identity.attributes().clone(),
        }
    }

    /// Build a policy context for a child `invoke_tool` call from the
    /// caller identity the agentic host carries on its
    /// `BackendInvocationContext` (a [`mcpg_plugin_protocol::PluginIdentity`]).
    /// The child inherits the parent's trust/claims; this lets the
    /// built-in trust floor + CEL `allow_if` evaluate against the CHILD
    /// tool name with the inherited identity. Fails closed: an
    /// unrecognised `trust_level` string maps to the LEAST-privileged
    /// [`RequestTrustLevel::Unauthenticated`] so a malformed identity
    /// can never satisfy a trust floor it shouldn't.
    pub(crate) fn from_plugin_identity(
        identity: &mcpg_plugin_protocol::PluginIdentity,
        tool_name: &str,
    ) -> Self {
        let trust_level = match identity.trust_level.as_str() {
            "verified" => RequestTrustLevel::Verified,
            "header_asserted" => RequestTrustLevel::HeaderAsserted,
            _ => RequestTrustLevel::Unauthenticated,
        };
        Self {
            tool_name: tool_name.to_owned(),
            trust_level,
            principal_id: identity.subject_id.clone(),
            auth_provider: identity.auth_provider.clone(),
            identity_kind: identity.kind.clone(),
            roles: identity.roles.clone(),
            groups: identity.groups.clone(),
            scopes: identity.scopes.clone(),
            attributes: identity.attributes.clone(),
        }
    }

    fn cache_key(&self) -> String {
        // Fold the full identity claim material into the key — not just
        // principal/tool/trust. The CEL `allow_if` policies (global,
        // per-tool, and per-federated-tool) read roles/groups/scopes/
        // attributes/auth_provider/identity_kind. If those are omitted, two
        // callers with the SAME principal_id but DIFFERENT claims hash to the
        // same key, so a cached Allow would survive a role/scope revocation
        // within the cache TTL. The claims fingerprint makes a changed claim
        // set a cache miss → re-evaluation. (Vecs are sorted so claim order
        // doesn't fragment the cache; attributes is a BTreeMap, already
        // ordered.)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.auth_provider.hash(&mut hasher);
        self.identity_kind.hash(&mut hasher);
        let mut roles = self.roles.clone();
        roles.sort_unstable();
        roles.hash(&mut hasher);
        let mut groups = self.groups.clone();
        groups.sort_unstable();
        groups.hash(&mut hasher);
        let mut scopes = self.scopes.clone();
        scopes.sort_unstable();
        scopes.hash(&mut hasher);
        for (k, v) in &self.attributes {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        format!(
            "{}:{}:{}:{:016x}",
            self.principal_id.as_deref().unwrap_or("_anon"),
            self.tool_name,
            self.trust_level_name(),
            hasher.finish(),
        )
    }

    fn trust_level_name(&self) -> &'static str {
        match self.trust_level {
            RequestTrustLevel::Unauthenticated => "unauthenticated",
            RequestTrustLevel::HeaderAsserted => "header_asserted",
            RequestTrustLevel::Verified => "verified",
        }
    }
}

/// Result of evaluating the pre-dispatch policy gate for a tool call.
#[derive(Debug, Clone)]
pub(crate) enum PreDispatchPolicyOutcome {
    Allow,
    Deny(PolicyDenial),
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyDenial {
    pub code: i32,
    pub http_status: u16,
    pub message: String,
    pub audit_reason: String,
    /// When set, this denial is an authenticated-but-under-scoped
    /// rejection (SEP-2350): the scopes the caller is missing. The HTTP
    /// transport lifts these into the `insufficient_scope` step-up
    /// challenge. `None` for ordinary trust/CEL denials.
    pub insufficient_scope: Option<Vec<String>>,
}

/// The pre-dispatch policy gate: evaluates trust level rules and optional CEL
/// conditions, with an optional LRU cache for hot-path decisions.
#[derive(Debug)]
pub(crate) struct PreDispatchPolicyGate {
    tool_access_policy: ToolAccessPolicy,
    cache: Option<PolicyCache>,
}

impl PreDispatchPolicyGate {
    pub(crate) fn try_new(config: ToolAccessPolicyConfig) -> Result<Self> {
        Ok(Self {
            tool_access_policy: ToolAccessPolicy::from_config(config)?,
            cache: None,
        })
    }

    pub(crate) fn try_new_with_cache(
        config: ToolAccessPolicyConfig,
        cache_config: &PolicyCacheConfig,
    ) -> Result<Self> {
        let cache = if cache_config.enabled {
            Some(PolicyCache::new(
                cache_config.ttl_ms,
                cache_config.max_entries,
            ))
        } else {
            None
        };
        Ok(Self {
            tool_access_policy: ToolAccessPolicy::from_config(config)?,
            cache,
        })
    }

    /// Shared handle to the federated-tool policy overlay. The
    /// `FederationEngine` stores compiled per-federation rules here at
    /// import time so synthetic tools inherit `governance.minimum_trust`
    /// / `allow_if`.
    pub(crate) fn federated_policy_handle(&self) -> Arc<ArcSwap<FederatedToolPolicies>> {
        Arc::clone(&self.tool_access_policy.federated)
    }

    pub(crate) fn evaluate_tool_call(
        &self,
        policy_context: &ToolPolicyContext,
    ) -> PreDispatchPolicyOutcome {
        // Check cache first
        if let Some(ref cache) = self.cache {
            let cache_key = policy_context.cache_key();
            if let Some(cached) = cache.get(&cache_key) {
                metrics::counter!("mcpg_policy_cache_hits_total").increment(1);
                return cached;
            }
            metrics::counter!("mcpg_policy_cache_misses_total").increment(1);

            let outcome = self.evaluate_uncached(policy_context);
            cache.put(cache_key, outcome.clone());
            return outcome;
        }

        self.evaluate_uncached(policy_context)
    }

    fn evaluate_uncached(&self, policy_context: &ToolPolicyContext) -> PreDispatchPolicyOutcome {
        // Evaluate in order: trust level floor, then global CEL, then per-tool CEL.
        let minimum_trust = self
            .tool_access_policy
            .required_trust_for(&policy_context.tool_name);

        if policy_context.trust_level < minimum_trust {
            return PreDispatchPolicyOutcome::Deny(PolicyDenial {
                code: -32003,
                http_status: 403,
                message: format!(
                    "tool {} requires trust level {:?}, current trust is {:?}",
                    policy_context.tool_name, minimum_trust, policy_context.trust_level,
                ),
                audit_reason: format!(
                    "tool_trust_requirement_not_met:{}:{:?}:{:?}",
                    policy_context.tool_name, minimum_trust, policy_context.trust_level,
                ),
                insufficient_scope: None,
            });
        }

        // SEP-2350: an authenticated caller missing a required scope earns a
        // distinct, flagged 403 so the transport mints the step-up
        // `insufficient_scope` challenge. Evaluated before CEL so the
        // scope-shaped denial isn't masked by a generic `allow_if` failure.
        if let Some(denial) = self
            .tool_access_policy
            .evaluate_required_scopes(policy_context)
        {
            return PreDispatchPolicyOutcome::Deny(denial);
        }

        if let Some(denial) = self
            .tool_access_policy
            .evaluate_cel_allow_if(policy_context)
        {
            return PreDispatchPolicyOutcome::Deny(denial);
        }

        if let Some(denial) = self
            .tool_access_policy
            .evaluate_per_tool_cel_allow_if(policy_context)
        {
            return PreDispatchPolicyOutcome::Deny(denial);
        }

        PreDispatchPolicyOutcome::Allow
    }

    /// Returns true if a tool should be visible to the caller in discovery responses.
    pub(crate) fn is_tool_visible(&self, policy_context: &ToolPolicyContext) -> bool {
        matches!(
            self.evaluate_tool_call(policy_context),
            PreDispatchPolicyOutcome::Allow
        )
    }
}

impl Default for PreDispatchPolicyGate {
    fn default() -> Self {
        Self {
            tool_access_policy: ToolAccessPolicy::from_config(ToolAccessPolicyConfig::default())
                .expect("default policy config valid"),
            cache: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy decision cache (L1 — process-local, TTL-based)
// ---------------------------------------------------------------------------

struct PolicyCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

struct CacheEntry {
    outcome: PreDispatchPolicyOutcome,
    inserted_at: Instant,
}

impl PolicyCache {
    fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: Duration::from_millis(ttl_ms),
            max_entries,
        }
    }

    fn get(&self, key: &str) -> Option<PreDispatchPolicyOutcome> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.outcome.clone())
    }

    fn put(&self, key: String, outcome: PreDispatchPolicyOutcome) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        // Evict expired entries if at capacity
        if entries.len() >= self.max_entries {
            let ttl = self.ttl;
            let before = entries.len();
            entries.retain(|_, entry| entry.inserted_at.elapsed() <= ttl);
            let evicted = before - entries.len();
            if evicted > 0 {
                metrics::counter!("mcpg_policy_cache_evictions_total").increment(evicted as u64);
            }

            // If still at capacity after eviction, skip insertion
            if entries.len() >= self.max_entries {
                return;
            }
        }

        entries.insert(
            key,
            CacheEntry {
                outcome,
                inserted_at: Instant::now(),
            },
        );
    }
}

impl std::fmt::Debug for PolicyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.entries.lock().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("PolicyCache")
            .field("entries", &len)
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

#[derive(Debug)]
struct ToolAccessPolicy {
    default_minimum_trust: RequestTrustLevel,
    per_tool_rules: HashMap<String, ToolRulePolicy>,
    cel_allow_if: Option<CelToolAccessPolicy>,
    /// Per-tool rules for federated tools, published by the
    /// `FederationEngine` (shared handle). Consulted after
    /// `per_tool_rules` so a native rule always wins.
    federated: Arc<ArcSwap<FederatedToolPolicies>>,
}

impl ToolAccessPolicy {
    fn from_config(config: ToolAccessPolicyConfig) -> Result<Self> {
        Ok(Self {
            default_minimum_trust: config.default_minimum_trust,
            per_tool_rules: config
                .rules
                .into_iter()
                .map(|rule| {
                    ToolRulePolicy::from_rule(rule).map(|policy| (policy.tool_name.clone(), policy))
                })
                .collect::<Result<HashMap<_, _>>>()?,
            cel_allow_if: config
                .cel_allow_if
                .map(|source| {
                    CelToolAccessPolicy::compile(
                        source,
                        "policy.tool_access.cel_allow_if".to_owned(),
                    )
                })
                .transpose()?,
            federated: Arc::new(ArcSwap::from_pointee(FederatedToolPolicies::default())),
        })
    }

    fn required_trust_for(&self, tool_name: &str) -> RequestTrustLevel {
        if let Some(rule) = self.per_tool_rules.get(tool_name) {
            return rule.minimum_trust;
        }
        if let Some(trust) = self
            .federated
            .load()
            .rule_for(tool_name)
            .map(|rule| rule.minimum_trust)
        {
            return trust;
        }
        self.default_minimum_trust
    }

    fn evaluate_cel_allow_if(&self, policy_context: &ToolPolicyContext) -> Option<PolicyDenial> {
        let cel_policy = self.cel_allow_if.as_ref()?;
        match cel_policy.evaluate(policy_context) {
            Ok(true) => None,
            Ok(false) => Some(PolicyDenial {
                code: -32022,
                http_status: 403,
                message: format!(
                    "tool {} was denied by CEL allow_if policy",
                    policy_context.tool_name
                ),
                audit_reason: format!(
                    "tool_access_cel_allow_if_denied:{}",
                    policy_context.tool_name
                ),
                insufficient_scope: None,
            }),
            Err(error) => Some(PolicyDenial {
                code: -32603,
                http_status: 500,
                message: "tool access policy evaluation failed".to_owned(),
                audit_reason: format!(
                    "tool_access_cel_allow_if_error:{}:{}",
                    policy_context.tool_name, error
                ),
                insufficient_scope: None,
            }),
        }
    }

    fn evaluate_per_tool_cel_allow_if(
        &self,
        policy_context: &ToolPolicyContext,
    ) -> Option<PolicyDenial> {
        if let Some(rule) = self.per_tool_rules.get(&policy_context.tool_name) {
            return Self::eval_rule_cel(rule, policy_context);
        }
        let federated = self.federated.load();
        let rule = federated.rule_for(&policy_context.tool_name)?;
        Self::eval_rule_cel(rule, policy_context)
    }

    /// SEP-2350 scope enforcement. Resolves the rule for the tool (native
    /// first, then federated) and denies with a step-up-flagged
    /// [`PolicyDenial`] when the caller is missing any required scope. A
    /// native rule wins over a federated one, mirroring the CEL/trust path.
    fn evaluate_required_scopes(&self, policy_context: &ToolPolicyContext) -> Option<PolicyDenial> {
        if let Some(rule) = self.per_tool_rules.get(&policy_context.tool_name) {
            return Self::scope_denial(rule, policy_context);
        }
        // Federated rules live behind an ArcSwap; resolve and check eagerly
        // within the guard's lifetime.
        let federated = self.federated.load();
        let rule = federated.rule_for(&policy_context.tool_name)?;
        Self::scope_denial(rule, policy_context)
    }

    fn scope_denial(
        rule: &ToolRulePolicy,
        policy_context: &ToolPolicyContext,
    ) -> Option<PolicyDenial> {
        let missing = rule.missing_scopes(policy_context);
        if missing.is_empty() {
            return None;
        }
        Some(PolicyDenial {
            code: -32003,
            http_status: 403,
            message: format!(
                "tool {} requires OAuth scope(s) {} not present on the caller's credential",
                policy_context.tool_name,
                missing.join(" "),
            ),
            audit_reason: format!(
                "tool_insufficient_scope:{}:{}",
                policy_context.tool_name,
                missing.join(","),
            ),
            insufficient_scope: Some(missing),
        })
    }

    fn eval_rule_cel(
        rule: &ToolRulePolicy,
        policy_context: &ToolPolicyContext,
    ) -> Option<PolicyDenial> {
        let cel_policy = rule.cel_allow_if.as_ref()?;

        match cel_policy.evaluate(policy_context) {
            Ok(true) => None,
            Ok(false) => Some(PolicyDenial {
                code: -32005,
                http_status: 403,
                message: format!(
                    "tool {} was denied by per-tool CEL allow_if policy",
                    policy_context.tool_name
                ),
                audit_reason: format!(
                    "tool_access_rule_cel_allow_if_denied:{}",
                    policy_context.tool_name
                ),
                insufficient_scope: None,
            }),
            Err(error) => Some(PolicyDenial {
                code: -32603,
                http_status: 500,
                message: "tool access policy evaluation failed".to_owned(),
                audit_reason: format!(
                    "tool_access_rule_cel_allow_if_error:{}:{}",
                    policy_context.tool_name, error
                ),
                insufficient_scope: None,
            }),
        }
    }
}

#[derive(Debug)]
struct ToolRulePolicy {
    tool_name: String,
    minimum_trust: RequestTrustLevel,
    cel_allow_if: Option<CelToolAccessPolicy>,
    required_scopes: Vec<String>,
}

/// Runtime-mutable per-tool policy for FEDERATED tools, published by the
/// `FederationEngine` at import time so synthetic tools inherit their
/// federation's governance. Keyed by the client-facing (prefixed) tool
/// name.
#[derive(Debug, Default)]
pub(crate) struct FederatedToolPolicies {
    rules: HashMap<String, ToolRulePolicy>,
    /// Prefix-keyed rules for federated surfaces whose client-facing name
    /// is NOT known exactly at import time — concrete reads of a federated
    /// resource *template* arrive as `<resource_uri_prefix><concrete-uri>`,
    /// which can't be enumerated. Each entry is `(prefix, rule)`; a name
    /// with no exact rule falls back to the first prefix it starts with.
    prefix_rules: Vec<(String, ToolRulePolicy)>,
}

impl FederatedToolPolicies {
    /// Compile federated tool rules (CEL compiled once here, not per
    /// call). Mirrors the native per-tool rule path. `prefix_rules` carry a
    /// match prefix (the federation's `resource_uri_prefix`) so template
    /// reads inherit their federation's governance too.
    pub(crate) fn compile(
        rules: Vec<ToolTrustRule>,
        prefix_rules: Vec<(String, ToolTrustRule)>,
    ) -> Result<Self> {
        let mut map = HashMap::with_capacity(rules.len());
        for rule in rules {
            let policy = ToolRulePolicy::from_rule(rule)?;
            map.insert(policy.tool_name.clone(), policy);
        }
        let mut prefixes = Vec::with_capacity(prefix_rules.len());
        for (prefix, rule) in prefix_rules {
            if prefix.is_empty() {
                // An empty prefix would match every request — skip it so a
                // prefix-less federation can't blanket the whole gateway.
                continue;
            }
            prefixes.push((prefix, ToolRulePolicy::from_rule(rule)?));
        }
        Ok(Self {
            rules: map,
            prefix_rules: prefixes,
        })
    }

    /// Resolve the governance rule for a client-facing name: exact match
    /// first, then the first prefix rule the name starts with.
    fn rule_for(&self, name: &str) -> Option<&ToolRulePolicy> {
        if let Some(rule) = self.rules.get(name) {
            return Some(rule);
        }
        self.prefix_rules
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix.as_str()))
            .map(|(_, rule)| rule)
    }
}

impl ToolRulePolicy {
    fn from_rule(rule: ToolTrustRule) -> Result<Self> {
        let tool_name = rule.tool_name;
        Ok(Self {
            minimum_trust: rule.minimum_trust,
            cel_allow_if: rule
                .cel_allow_if
                .map(|source| {
                    CelToolAccessPolicy::compile(
                        source,
                        format!("policy.tool_access.rules[{tool_name}].cel_allow_if"),
                    )
                })
                .transpose()?,
            required_scopes: rule.required_scopes,
            tool_name,
        })
    }

    /// The subset of `required_scopes` the caller does NOT hold. Empty when
    /// the caller satisfies every required scope (or none are required).
    fn missing_scopes(&self, ctx: &ToolPolicyContext) -> Vec<String> {
        self.required_scopes
            .iter()
            .filter(|required| !ctx.scopes.iter().any(|held| held == *required))
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
struct CelToolAccessPolicy {
    source: String,
    program: Program,
}

impl CelToolAccessPolicy {
    fn compile(source: String, config_path: String) -> Result<Self> {
        let program = Program::compile(&source)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("failed to compile {config_path}: {source}"))?;
        Ok(Self { source, program })
    }

    fn evaluate(&self, policy_context: &ToolPolicyContext) -> Result<bool> {
        let mut context = CelContext::default();
        context
            .add_variable("tool_name", policy_context.tool_name.as_str())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        context
            .add_variable("trust_level", policy_context.trust_level_name())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        context
            .add_variable("principal_id", policy_context.principal_id.clone())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        context
            .add_variable("auth_provider", policy_context.auth_provider.clone())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        context
            .add_variable("identity_kind", policy_context.identity_kind.as_str())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        // Claim-based variables — enable RBAC/ABAC expressions like:
        //   `"admin" in identity.roles`
        //   `"read" in identity.scopes`
        //   `identity.attributes["department"] == "eng"`
        let identity_map = build_policy_identity_map(policy_context);
        context
            .add_variable("identity", identity_map)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let value = self
            .program
            .execute(&context)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("failed to execute CEL policy: {}", self.source))?;

        match value {
            CelValue::Bool(result) => Ok(result),
            other => Err(anyhow::anyhow!(
                "CEL policy must evaluate to a boolean, got {other:?}"
            )),
        }
    }
}

/// Build a CEL identity map with full claim context for RBAC/ABAC policy expressions.
fn build_policy_identity_map(ctx: &ToolPolicyContext) -> CelValue {
    use std::sync::Arc;

    let mut map: HashMap<CelKey, CelValue> = HashMap::new();
    map.insert(
        CelKey::String("kind".to_owned().into()),
        CelValue::String(ctx.identity_kind.clone().into()),
    );
    map.insert(
        CelKey::String("trust_level".to_owned().into()),
        CelValue::String(ctx.trust_level_name().to_owned().into()),
    );
    map.insert(
        CelKey::String("subject_id".to_owned().into()),
        match &ctx.principal_id {
            Some(id) => CelValue::String(id.clone().into()),
            None => CelValue::Null,
        },
    );
    map.insert(
        CelKey::String("auth_provider".to_owned().into()),
        match &ctx.auth_provider {
            Some(p) => CelValue::String(p.clone().into()),
            None => CelValue::Null,
        },
    );

    // Claims — the key RBAC/ABAC fields
    let roles_cel: Vec<CelValue> = ctx
        .roles
        .iter()
        .map(|r| CelValue::String(r.clone().into()))
        .collect();
    map.insert(
        CelKey::String("roles".to_owned().into()),
        CelValue::List(roles_cel.into()),
    );

    let groups_cel: Vec<CelValue> = ctx
        .groups
        .iter()
        .map(|g| CelValue::String(g.clone().into()))
        .collect();
    map.insert(
        CelKey::String("groups".to_owned().into()),
        CelValue::List(groups_cel.into()),
    );

    let scopes_cel: Vec<CelValue> = ctx
        .scopes
        .iter()
        .map(|s| CelValue::String(s.clone().into()))
        .collect();
    map.insert(
        CelKey::String("scopes".to_owned().into()),
        CelValue::List(scopes_cel.into()),
    );

    let attrs_map: HashMap<CelKey, CelValue> = ctx
        .attributes
        .iter()
        .map(|(k, v)| {
            (
                CelKey::String(k.clone().into()),
                CelValue::String(v.clone().into()),
            )
        })
        .collect();
    map.insert(
        CelKey::String("attributes".to_owned().into()),
        CelValue::Map(CelMap {
            map: Arc::new(attrs_map),
        }),
    );

    CelValue::Map(CelMap { map: Arc::new(map) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{GatewayRequestId, RequestIdentity, ResumeCursor, TransportKind};

    fn sample_context(identity: RequestIdentity) -> RequestContext {
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some("session-1".to_owned()),
            None::<ResumeCursor>,
            identity,
            TransportKind::Http,
        )
    }

    #[test]
    fn tool_policy_context_normalizes_request_identity() {
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        assert_eq!(context.tool_name, "mcpg.runtime.snapshot");
        assert_eq!(context.trust_level, RequestTrustLevel::HeaderAsserted);
        assert_eq!(context.principal_id.as_deref(), Some("user-1"));
        assert_eq!(context.identity_kind, "http_header");
    }

    #[test]
    fn pre_dispatch_policy_denies_when_trust_is_below_requirement() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig::default())
            .expect("default policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::Anonymous {
                source: "test".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        match gate.evaluate_tool_call(&context) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 403);
                assert_eq!(denial.code, -32003);
                assert!(
                    denial
                        .audit_reason
                        .contains("tool_trust_requirement_not_met")
                );
            }
            PreDispatchPolicyOutcome::Allow => panic!("anonymous request should be denied"),
        }
    }

    #[test]
    fn federated_tools_inherit_their_federation_governance() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig::default())
            .expect("default policy valid");
        // The engine publishes per-federation rules at import time.
        gate.federated_policy_handle().store(std::sync::Arc::new(
            FederatedToolPolicies::compile(
                vec![
                    ToolTrustRule {
                        tool_name: "notion.search".to_owned(),
                        minimum_trust: RequestTrustLevel::Unauthenticated,
                        cel_allow_if: None,
                        required_scopes: Vec::new(),
                    },
                    ToolTrustRule {
                        tool_name: "notion.admin".to_owned(),
                        minimum_trust: RequestTrustLevel::Verified,
                        cel_allow_if: None,
                        required_scopes: Vec::new(),
                    },
                ],
                vec![],
            )
            .expect("compile federated rules"),
        ));
        let anon = |tool: &str| {
            ToolPolicyContext::from_request_context(
                &sample_context(RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                }),
                tool,
            )
        };
        // Federated rule lowers the bar below the default → allowed.
        assert!(matches!(
            gate.evaluate_tool_call(&anon("notion.search")),
            PreDispatchPolicyOutcome::Allow
        ));
        // Federated rule raises the bar → denied (governance enforced).
        assert!(matches!(
            gate.evaluate_tool_call(&anon("notion.admin")),
            PreDispatchPolicyOutcome::Deny(_)
        ));
    }

    #[test]
    fn pre_dispatch_policy_honors_per_tool_override() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                required_scopes: Vec::new(),
            }],
        })
        .expect("policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::Anonymous {
                source: "test".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        assert!(matches!(
            gate.evaluate_tool_call(&context),
            PreDispatchPolicyOutcome::Allow
        ));
    }

    #[test]
    fn pre_dispatch_policy_honors_cel_allow_if_expression() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: Some(
                "tool_name == \"mcpg.runtime.snapshot\" && trust_level == \"header_asserted\""
                    .to_owned(),
            ),
            rules: Vec::new(),
        })
        .expect("policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        assert!(matches!(
            gate.evaluate_tool_call(&context),
            PreDispatchPolicyOutcome::Allow
        ));
    }

    #[test]
    fn pre_dispatch_policy_denies_when_cel_allow_if_returns_false() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: Some("principal_id == \"admin\"".to_owned()),
            rules: Vec::new(),
        })
        .expect("policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        match gate.evaluate_tool_call(&context) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 403);
                assert_eq!(denial.code, -32022);
                assert!(
                    denial
                        .audit_reason
                        .contains("tool_access_cel_allow_if_denied")
                );
            }
            PreDispatchPolicyOutcome::Allow => panic!("policy should deny when CEL returns false"),
        }
    }

    /// AUTH-09 / TAN-03 (SEP-2350): a caller missing a required scope is
    /// denied 403 with the missing scopes carried on `insufficient_scope`
    /// so the transport can mint the step-up challenge. A caller that holds
    /// every required scope is allowed.
    #[test]
    fn pre_dispatch_policy_denies_on_missing_required_scope() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "admin.delete".to_owned(),
                minimum_trust: RequestTrustLevel::Verified,
                cel_allow_if: None,
                required_scopes: vec!["admin.write".to_owned(), "audit.read".to_owned()],
            }],
        })
        .expect("policy valid");

        // Holds only one of the two required scopes → denied, missing the other.
        let under_scoped =
            verified_context_with_claims(vec![], vec![], vec!["admin.write"], vec![]);
        match gate.evaluate_tool_call(&under_scoped) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 403);
                assert_eq!(denial.code, -32003);
                assert_eq!(
                    denial.insufficient_scope.as_deref(),
                    Some(["audit.read".to_owned()].as_slice()),
                );
                assert!(denial.audit_reason.contains("tool_insufficient_scope"));
            }
            PreDispatchPolicyOutcome::Allow => {
                panic!("under-scoped caller must be denied")
            }
        }

        // Holds both required scopes → allowed (no scope-shaped denial).
        let scoped =
            verified_context_with_claims(vec![], vec![], vec!["admin.write", "audit.read"], vec![]);
        assert!(matches!(
            gate.evaluate_tool_call(&scoped),
            PreDispatchPolicyOutcome::Allow
        ));
    }

    #[test]
    fn pre_dispatch_policy_rejects_invalid_cel_expression_at_construction() {
        let error = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: Some("tool_name == ".to_owned()),
            rules: Vec::new(),
        })
        .expect_err("invalid CEL should fail");

        assert!(
            error
                .to_string()
                .contains("failed to compile policy.tool_access.cel_allow_if")
        );
    }

    #[test]
    fn pre_dispatch_policy_honors_per_tool_cel_allow_if_expression() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::HeaderAsserted,
                cel_allow_if: Some("principal_id == \"user-1\"".to_owned()),
                required_scopes: Vec::new(),
            }],
        })
        .expect("policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        assert!(matches!(
            gate.evaluate_tool_call(&context),
            PreDispatchPolicyOutcome::Allow
        ));
    }

    #[test]
    fn pre_dispatch_policy_denies_when_per_tool_cel_allow_if_returns_false() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::HeaderAsserted,
                cel_allow_if: Some("principal_id == \"admin\"".to_owned()),
                required_scopes: Vec::new(),
            }],
        })
        .expect("policy valid");
        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        match gate.evaluate_tool_call(&context) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 403);
                assert_eq!(denial.code, -32005);
                assert!(
                    denial
                        .audit_reason
                        .contains("tool_access_rule_cel_allow_if_denied")
                );
            }
            PreDispatchPolicyOutcome::Allow => {
                panic!("policy should deny when per-tool CEL returns false")
            }
        }
    }

    #[test]
    fn pre_dispatch_policy_rejects_invalid_per_tool_cel_expression_at_construction() {
        let error = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::HeaderAsserted,
                cel_allow_if: Some("principal_id == ".to_owned()),
                required_scopes: Vec::new(),
            }],
        })
        .expect_err("invalid per-tool CEL should fail");

        assert!(error.to_string().contains(
            "failed to compile policy.tool_access.rules[mcpg.runtime.snapshot].cel_allow_if"
        ));
    }

    // -----------------------------------------------------------------------
    // Policy cache tests
    // -----------------------------------------------------------------------

    #[test]
    fn policy_cache_returns_cached_outcome() {
        let cache = PolicyCache::new(60, 100);
        let key = "user-1:my_tool:verified".to_owned();

        assert!(cache.get(&key).is_none());

        cache.put(key.clone(), PreDispatchPolicyOutcome::Allow);

        let cached = cache.get(&key).expect("should be cached");
        assert!(matches!(cached, PreDispatchPolicyOutcome::Allow));
    }

    #[test]
    fn policy_cache_expires_after_ttl() {
        let cache = PolicyCache::new(0, 100); // 0-second TTL = immediately expired
        let key = "user-1:my_tool:verified".to_owned();

        cache.put(key.clone(), PreDispatchPolicyOutcome::Allow);

        // With 0-second TTL, entry should be expired
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn policy_cache_evicts_expired_entries_when_full() {
        let cache = PolicyCache::new(0, 2); // 0-second TTL, max 2 entries

        cache.put("a:tool:v".to_owned(), PreDispatchPolicyOutcome::Allow);
        cache.put("b:tool:v".to_owned(), PreDispatchPolicyOutcome::Allow);

        // Wait for entries to expire
        std::thread::sleep(std::time::Duration::from_millis(10));

        // This should evict expired entries and succeed
        cache.put("c:tool:v".to_owned(), PreDispatchPolicyOutcome::Allow);

        // Only the new entry should survive (others expired)
        // Note: the new entry was just inserted so it's not expired yet
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key("c:tool:v"));
    }

    #[test]
    fn policy_gate_with_cache_returns_cached_decisions() {
        let cache_config = crate::config::PolicyCacheConfig {
            enabled: true,
            ttl_ms: 60,
            max_entries: 100,
        };
        let gate = PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig::default(),
            &cache_config,
        )
        .expect("valid");

        let context = ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            }),
            "mcpg.runtime.snapshot",
        );

        // First call evaluates the policy
        let first = gate.evaluate_tool_call(&context);
        assert!(matches!(first, PreDispatchPolicyOutcome::Allow));

        // Second call should use the cache (same result)
        let second = gate.evaluate_tool_call(&context);
        assert!(matches!(second, PreDispatchPolicyOutcome::Allow));
    }

    #[test]
    fn policy_cache_key_format_is_correct() {
        let ctx = ToolPolicyContext {
            tool_name: "my_tool".to_owned(),
            trust_level: RequestTrustLevel::Verified,
            principal_id: Some("user-1".to_owned()),
            auth_provider: None,
            identity_kind: "verified".to_owned(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        // principal:tool:trust prefix is preserved; a claims fingerprint
        // is appended so claim sets can't collide.
        assert!(
            ctx.cache_key().starts_with("user-1:my_tool:verified:"),
            "{}",
            ctx.cache_key()
        );

        let anon_ctx = ToolPolicyContext {
            tool_name: "my_tool".to_owned(),
            trust_level: RequestTrustLevel::Unauthenticated,
            principal_id: None,
            auth_provider: None,
            identity_kind: "anonymous".to_owned(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        assert!(
            anon_ctx
                .cache_key()
                .starts_with("_anon:my_tool:unauthenticated:"),
            "{}",
            anon_ctx.cache_key()
        );
    }

    #[test]
    fn policy_cache_key_distinguishes_claim_sets() {
        // Same principal/tool/trust but different RBAC/ABAC claims MUST
        // produce different cache keys, so a CEL allow_if decision keyed
        // on roles/scopes/attributes can't be served stale after a change.
        let base = ToolPolicyContext {
            tool_name: "t".to_owned(),
            trust_level: RequestTrustLevel::Verified,
            principal_id: Some("user-1".to_owned()),
            auth_provider: Some("oidc".to_owned()),
            identity_kind: "verified".to_owned(),
            roles: vec!["viewer".to_owned()],
            groups: Vec::new(),
            scopes: vec!["read".to_owned()],
            attributes: std::collections::BTreeMap::new(),
        };
        let k_base = base.cache_key();

        // Role added (e.g. privilege grant) → distinct key.
        let mut more_roles = base.clone();
        more_roles.roles = vec!["viewer".to_owned(), "admin".to_owned()];
        assert_ne!(k_base, more_roles.cache_key());

        // Scope removed (e.g. revocation) → distinct key.
        let mut fewer_scopes = base.clone();
        fewer_scopes.scopes = Vec::new();
        assert_ne!(k_base, fewer_scopes.cache_key());

        // Attribute change → distinct key.
        let mut attr = base.clone();
        attr.attributes.insert("dept".to_owned(), "eng".to_owned());
        assert_ne!(k_base, attr.cache_key());

        // Different auth_provider → distinct key.
        let mut prov = base.clone();
        prov.auth_provider = Some("saml".to_owned());
        assert_ne!(k_base, prov.cache_key());

        // Same claims (order permuted) → SAME key (sorted before hashing).
        let mut permuted = base.clone();
        permuted.roles = vec!["viewer".to_owned()];
        permuted.scopes = vec!["read".to_owned()];
        assert_eq!(k_base, permuted.cache_key());
    }

    // -----------------------------------------------------------------------
    // CEL claim-based RBAC/ABAC expressions
    // -----------------------------------------------------------------------

    fn verified_context_with_claims(
        roles: Vec<&str>,
        groups: Vec<&str>,
        scopes: Vec<&str>,
        attrs: Vec<(&str, &str)>,
    ) -> ToolPolicyContext {
        ToolPolicyContext {
            tool_name: "admin.delete".to_owned(),
            trust_level: RequestTrustLevel::Verified,
            principal_id: Some("user-1".to_owned()),
            auth_provider: Some("oidc".to_owned()),
            identity_kind: "verified".to_owned(),
            roles: roles.into_iter().map(str::to_owned).collect(),
            groups: groups.into_iter().map(str::to_owned).collect(),
            scopes: scopes.into_iter().map(str::to_owned).collect(),
            attributes: attrs
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        }
    }

    #[test]
    fn cel_policy_role_check_in_operator() {
        let policy = CelToolAccessPolicy::compile(
            r#""admin" in identity.roles"#.to_owned(),
            "test".to_owned(),
        )
        .unwrap();

        let ctx = verified_context_with_claims(vec!["admin", "user"], vec![], vec![], vec![]);
        assert!(policy.evaluate(&ctx).unwrap());

        let ctx_no_role = verified_context_with_claims(vec!["user"], vec![], vec![], vec![]);
        assert!(!policy.evaluate(&ctx_no_role).unwrap());
    }

    #[test]
    fn cel_policy_scope_check() {
        let policy = CelToolAccessPolicy::compile(
            r#""read" in identity.scopes"#.to_owned(),
            "test".to_owned(),
        )
        .unwrap();

        let ctx = verified_context_with_claims(vec![], vec![], vec!["read", "write"], vec![]);
        assert!(policy.evaluate(&ctx).unwrap());

        let ctx_no_scope = verified_context_with_claims(vec![], vec![], vec!["write"], vec![]);
        assert!(!policy.evaluate(&ctx_no_scope).unwrap());
    }

    #[test]
    fn cel_policy_group_check() {
        let policy = CelToolAccessPolicy::compile(
            r#""engineering" in identity.groups"#.to_owned(),
            "test".to_owned(),
        )
        .unwrap();

        let ctx =
            verified_context_with_claims(vec![], vec!["engineering", "billing"], vec![], vec![]);
        assert!(policy.evaluate(&ctx).unwrap());
    }

    #[test]
    fn cel_policy_attribute_check() {
        let policy = CelToolAccessPolicy::compile(
            r#"identity.attributes["department"] == "eng""#.to_owned(),
            "test".to_owned(),
        )
        .unwrap();

        let ctx = verified_context_with_claims(vec![], vec![], vec![], vec![("department", "eng")]);
        assert!(policy.evaluate(&ctx).unwrap());

        let ctx_wrong =
            verified_context_with_claims(vec![], vec![], vec![], vec![("department", "sales")]);
        assert!(!policy.evaluate(&ctx_wrong).unwrap());
    }

    #[test]
    fn cel_policy_compound_rbac_expression() {
        let policy = CelToolAccessPolicy::compile(
            r#"trust_level == "verified" && "admin" in identity.roles && "nuclear.launch" in identity.scopes"#.to_owned(),
            "test".to_owned(),
        ).unwrap();

        let ctx = verified_context_with_claims(
            vec!["admin"],
            vec![],
            vec!["nuclear.launch", "read"],
            vec![],
        );
        assert!(policy.evaluate(&ctx).unwrap());

        // Missing scope
        let ctx_no_scope =
            verified_context_with_claims(vec!["admin"], vec![], vec!["read"], vec![]);
        assert!(!policy.evaluate(&ctx_no_scope).unwrap());
    }

    #[test]
    fn cel_policy_claims_empty_for_anonymous() {
        let policy = CelToolAccessPolicy::compile(
            r#""admin" in identity.roles"#.to_owned(),
            "test".to_owned(),
        )
        .unwrap();

        let ctx = ToolPolicyContext {
            tool_name: "admin.delete".to_owned(),
            trust_level: RequestTrustLevel::Unauthenticated,
            principal_id: None,
            auth_provider: None,
            identity_kind: "anonymous".to_owned(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        assert!(!policy.evaluate(&ctx).unwrap());
    }
}
