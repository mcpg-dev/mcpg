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

use crate::backends::{BackendInvocationRoute, PromptRoute, ResourceRoute};
use crate::config::PolicyCacheConfig;
use crate::runtime::{RequestContext, RequestTrustLevel};

/// Where the router sends a request, as far as the gate needs to know: the
/// federation that serves it, and a name other than the one the caller
/// used that a rule for the served capability can be filed under.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyRoute<'a> {
    federation: Option<&'a str>,
    listed_as: Option<&'a str>,
    /// The kind of surface the request names, when the caller knows it. A
    /// binding's rule applies only to a request for its own kind.
    surface: Option<PolicySurface>,
    /// What CEL reads as `arguments`: an event subscription's arguments.
    arguments: Option<&'a serde_json::Value>,
}

/// The kind of surface a request names, and a binding's rule governs: a name
/// can be a tool, a prompt and a resource at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicySurface {
    Tool,
    Prompt,
    /// A resource or a resource template.
    Resource,
    /// An event type, named `event:<name>`.
    Event,
}

impl PolicySurface {
    /// What CEL reads as `surface`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Prompt => "prompt",
            Self::Resource => "resource",
            Self::Event => "event",
        }
    }
}

impl<'a> PolicyRoute<'a> {
    /// A surface the gateway serves itself: only the rules filed under the
    /// name the caller used apply.
    pub(crate) const fn gateway() -> Self {
        Self {
            federation: None,
            listed_as: None,
            surface: None,
            arguments: None,
        }
    }

    /// Served by `federation` when it is `Some`, by the gateway otherwise.
    pub(crate) const fn served_by(federation: Option<&'a str>) -> Self {
        Self {
            federation,
            listed_as: None,
            surface: None,
            arguments: None,
        }
    }

    /// The same route for a request that names a `surface`.
    pub(crate) const fn on(mut self, surface: PolicySurface) -> Self {
        self.surface = Some(surface);
        self
    }

    /// An event type the gateway serves, for a caller with `arguments`
    /// (none for a listing).
    pub(crate) const fn event(arguments: Option<&'a serde_json::Value>) -> Self {
        let mut route = Self::gateway().on(PolicySurface::Event);
        route.arguments = arguments;
        route
    }

    pub(crate) fn for_tool(route: &'a BackendInvocationRoute) -> Self {
        Self::served_by(route.federation()).on(PolicySurface::Tool)
    }

    pub(crate) fn for_prompt(route: &'a PromptRoute) -> Self {
        Self::served_by(route.federation()).on(PolicySurface::Prompt)
    }

    /// A read may name its resource by another spelling of the URI, or by a
    /// concrete URI a template matches, so the route also carries a name
    /// the served resource's rule is filed under: the native binding it
    /// dispatches to (a binding's rule is always filed under its name), or
    /// the URI or URI template a federation lists it as.
    pub(crate) fn for_resource(route: &'a ResourceRoute) -> Self {
        let route = match route {
            ResourceRoute::Federated {
                source, listed_as, ..
            } => Self {
                federation: Some(source),
                listed_as: Some(listed_as),
                surface: None,
                arguments: None,
            },
            ResourceRoute::Binding { profile } | ResourceRoute::Template { profile, .. } => Self {
                federation: None,
                listed_as: Some(profile),
                surface: None,
                arguments: None,
            },
            ResourceRoute::RuntimeOverview | ResourceRoute::GatewayApp { .. } => Self::gateway(),
        };
        route.on(PolicySurface::Resource)
    }
}

/// The route the running catalog gives a name the admin policy preview asks
/// about, owned so the running and the candidate policy decide under it.
#[derive(Debug, Clone)]
pub(crate) enum PreviewRoute {
    Tool(BackendInvocationRoute),
    Prompt(PromptRoute),
    Resource(ResourceRoute),
    /// Nothing in the running catalog answers to the name.
    Unrouted,
}

impl PreviewRoute {
    pub(crate) fn policy_route(&self) -> PolicyRoute<'_> {
        match self {
            Self::Tool(route) => PolicyRoute::for_tool(route),
            Self::Prompt(route) => PolicyRoute::for_prompt(route),
            Self::Resource(route) => PolicyRoute::for_resource(route),
            Self::Unrouted => PolicyRoute::gateway(),
        }
    }

    /// The surface the name was found on: `tool`, `prompt`, `resource`, or
    /// `unrouted`.
    pub(crate) fn surface(&self) -> &'static str {
        match self {
            Self::Tool(_) => "tool",
            Self::Prompt(_) => "prompt",
            Self::Resource(_) => "resource",
            Self::Unrouted => "unrouted",
        }
    }

    /// The federation the route sends the name to.
    pub(crate) fn federation(&self) -> Option<&str> {
        self.policy_route().federation
    }
}

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
    /// The kind of surface the rule governs: a binding's rule governs only
    /// its own kind, so a prompt's rule never reaches a tool of the same
    /// name. `None` (a central rule) governs every surface of the name.
    pub surface: Option<PolicySurface>,
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
    /// The party that vouched for the principal (token `iss`). Together with
    /// `principal_id` it is the identifier for issuers whose subjects are
    /// only unique within the issuer (AAuth person servers, `allow_any_issuer`).
    pub issuer: Option<String>,
}

impl ToolPolicyContext {
    pub(crate) fn from_request_context(request_context: &RequestContext, tool_name: &str) -> Self {
        Self {
            tool_name: tool_name.to_owned(),
            trust_level: request_context.identity.trust_level(),
            principal_id: request_context.identity.principal_id().map(str::to_owned),
            issuer: request_context.identity.issuer().map(str::to_owned),
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
            issuer: identity.issuer.clone(),
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
        self.issuer.hash(&mut hasher);
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

    /// Shared handle to the federated policy overlay. The
    /// `FederationEngine` stores each federation's compiled rule here so
    /// everything routed to that federation inherits its `governance`.
    pub(crate) fn federated_policy_handle(&self) -> Arc<ArcSwap<FederatedToolPolicies>> {
        Arc::clone(&self.tool_access_policy.federated)
    }

    /// Decide a request for the surface `policy_context` names, as the
    /// router sends it: `route` says which federation serves it, if any.
    pub(crate) fn evaluate(
        &self,
        policy_context: &ToolPolicyContext,
        route: PolicyRoute<'_>,
    ) -> PreDispatchPolicyOutcome {
        // One snapshot for the whole decision, so the trust floor, the scopes
        // and the per-tool CEL all judge the same federated governance.
        let federated = self.tool_access_policy.federated.load();
        if let Some(ref cache) = self.cache {
            // A federation's rule changes without a new gate, so a decision
            // routed to one is only reused under the version of its rule it
            // was made under. A decision for a native route depends on no
            // federation and survives every republish.
            let depends_on = route
                .federation
                .map(|federation| (federation.to_owned(), federated.version(federation)));
            let mut cache_key = format!(
                "{}|{:?}|{:?}|{:?}",
                policy_context.cache_key(),
                depends_on,
                route.listed_as,
                route.surface,
            );
            // CEL reads the arguments, so they are part of the decision.
            if let Some(arguments) = route.arguments {
                cache_key.push_str("|args:");
                cache_key.push_str(&hex::encode(hmac_sha256::Hash::hash(
                    &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(arguments),
                )));
            }
            if let Some(cached) = cache.get(&cache_key) {
                metrics::counter!("mcpg_policy_cache_hits_total").increment(1);
                return cached;
            }
            metrics::counter!("mcpg_policy_cache_misses_total").increment(1);

            let outcome = self.evaluate_uncached(policy_context, &federated, route);
            cache.put(cache_key, outcome.clone(), depends_on, &federated);
            return outcome;
        }

        self.evaluate_uncached(policy_context, &federated, route)
    }

    fn evaluate_uncached(
        &self,
        policy_context: &ToolPolicyContext,
        federated: &FederatedToolPolicies,
        route: PolicyRoute<'_>,
    ) -> PreDispatchPolicyOutcome {
        let policy = &self.tool_access_policy;
        let rules = match policy.rules_for(policy_context, federated, route) {
            Ok(rules) => rules,
            Err(denial) => return PreDispatchPolicyOutcome::Deny(denial),
        };

        // Evaluate in order: trust level floor, then global CEL, then per-tool CEL.
        let minimum_trust = rules
            .iter()
            .map(|rule| rule.minimum_trust)
            .max()
            .unwrap_or(policy.default_minimum_trust);

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
        if let Some(denial) = ToolAccessPolicy::scope_denial(&rules, policy_context) {
            return PreDispatchPolicyOutcome::Deny(denial);
        }

        if let Some(denial) = policy.evaluate_cel_allow_if(policy_context, route) {
            return PreDispatchPolicyOutcome::Deny(denial);
        }

        for rule in &rules {
            if let Some(denial) = ToolAccessPolicy::eval_rule_cel(rule, policy_context, route) {
                return PreDispatchPolicyOutcome::Deny(denial);
            }
        }

        PreDispatchPolicyOutcome::Allow
    }

    /// Whether a listed surface is shown to the caller: exactly when a
    /// request for it, routed as `route`, would be allowed.
    pub(crate) fn is_visible(
        &self,
        policy_context: &ToolPolicyContext,
        route: PolicyRoute<'_>,
    ) -> bool {
        matches!(
            self.evaluate(policy_context, route),
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
    /// The federation whose rule the decision was made under, and that
    /// rule's version.
    depends_on: Option<(String, u64)>,
}

impl CacheEntry {
    /// Whether a lookup can still find this entry: a decision made under a
    /// federation rule that has since changed is keyed by a version no
    /// lookup asks for again.
    fn is_live(&self, ttl: Duration, federated: &FederatedToolPolicies) -> bool {
        self.inserted_at.elapsed() <= ttl
            && self
                .depends_on
                .as_ref()
                .is_none_or(|(federation, version)| federated.version(federation) == *version)
    }
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

    /// Cache `outcome` under `key`. `depends_on` is the federation rule it
    /// was decided under and `federated` the set in force, so a full cache
    /// first drops what no lookup can reach any more.
    fn put(
        &self,
        key: String,
        outcome: PreDispatchPolicyOutcome,
        depends_on: Option<(String, u64)>,
        federated: &FederatedToolPolicies,
    ) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        if entries.len() >= self.max_entries {
            let ttl = self.ttl;
            let before = entries.len();
            entries.retain(|_, entry| entry.is_live(ttl, federated));
            let evicted = before - entries.len();
            if evicted > 0 {
                metrics::counter!("mcpg_policy_cache_evictions_total").increment(evicted as u64);
            }

            // Every entry is still reachable: the cache is at its bound.
            if entries.len() >= self.max_entries {
                return;
            }
        }

        entries.insert(
            key,
            CacheEntry {
                outcome,
                inserted_at: Instant::now(),
                depends_on,
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
    /// Every rule filed under a name. A central rule and a binding's rule
    /// can share one (a resource's URI or a template), and both apply.
    per_tool_rules: HashMap<String, Vec<ToolRulePolicy>>,
    cel_allow_if: Option<CelToolAccessPolicy>,
    /// Each federation's rule, published by the `FederationEngine` (shared
    /// handle). A request routed to a federation must pass it as well as
    /// every rule in `per_tool_rules` that names the request.
    federated: Arc<ArcSwap<FederatedToolPolicies>>,
}

impl ToolAccessPolicy {
    fn from_config(config: ToolAccessPolicyConfig) -> Result<Self> {
        let mut per_tool_rules: HashMap<String, Vec<ToolRulePolicy>> = HashMap::new();
        for rule in config.rules {
            let policy = ToolRulePolicy::from_rule(rule)?;
            per_tool_rules
                .entry(policy.tool_name.clone())
                .or_default()
                .push(policy);
        }
        Ok(Self {
            default_minimum_trust: config.default_minimum_trust,
            per_tool_rules,
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

    /// The per-tool rules that govern a request, all of which must pass:
    /// every native or central rule filed under the name the caller used or
    /// under the name the route lists the capability as (a native rule only
    /// when it governs the kind of surface requested), plus the rule of the
    /// federation the route sends it to. A native or central
    /// rule can therefore tighten a federation's rule but never loosen it,
    /// and a federation's rule never reaches a surface the gateway serves
    /// itself. Empty when no rule applies, so only the global floor and
    /// `cel_allow_if` do.
    ///
    /// `Err` when the route names a federation whose governance did not
    /// compile or that published none: its capabilities are refused rather
    /// than handed to the global policy, which would drop that federation's
    /// own floor, scopes and `allow_if`.
    fn rules_for<'a>(
        &'a self,
        policy_context: &ToolPolicyContext,
        federated: &'a FederatedToolPolicies,
        route: PolicyRoute<'_>,
    ) -> std::result::Result<Vec<&'a ToolRulePolicy>, PolicyDenial> {
        let tool_name = policy_context.tool_name.as_str();
        let listed_as = route.listed_as.filter(|listed| *listed != tool_name);
        // A binding's rule names a surface of its own kind; a request of
        // unknown kind is held to every rule of the name.
        let governs = |rule: &&ToolRulePolicy| match (rule.surface, route.surface) {
            (Some(governed), Some(requested)) => governed == requested,
            _ => true,
        };
        let mut rules: Vec<&ToolRulePolicy> = std::iter::once(tool_name)
            .chain(listed_as)
            .filter_map(|name| self.per_tool_rules.get(name))
            .flatten()
            .filter(governs)
            .collect();
        let Some(federation) = route.federation else {
            return Ok(rules);
        };
        let refused = |reason: &str| PolicyDenial {
            code: -32603,
            http_status: 500,
            message: "tool access policy evaluation failed".to_owned(),
            audit_reason: format!("{reason}:{tool_name}:{federation}"),
            insufficient_scope: None,
        };
        match federated.rule(federation) {
            Some(FederatedRule::Governed(policy)) => rules.push(policy),
            Some(FederatedRule::Uncompiled) => {
                return Err(refused("federation_governance_uncompiled"));
            }
            None => return Err(refused("federation_governance_missing")),
        }
        Ok(rules)
    }

    fn evaluate_cel_allow_if(
        &self,
        policy_context: &ToolPolicyContext,
        route: PolicyRoute<'_>,
    ) -> Option<PolicyDenial> {
        let cel_policy = self.cel_allow_if.as_ref()?;
        match cel_policy.evaluate_on(policy_context, route) {
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

    /// SEP-2350 scope enforcement over the rules [`Self::rules_for`]
    /// resolved: denies with a step-up-flagged [`PolicyDenial`] naming every
    /// required scope the caller is missing.
    fn scope_denial(
        rules: &[&ToolRulePolicy],
        policy_context: &ToolPolicyContext,
    ) -> Option<PolicyDenial> {
        let mut missing: Vec<String> = Vec::new();
        for scope in rules
            .iter()
            .flat_map(|rule| rule.missing_scopes(policy_context))
        {
            if !missing.contains(&scope) {
                missing.push(scope);
            }
        }
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
        route: PolicyRoute<'_>,
    ) -> Option<PolicyDenial> {
        let cel_policy = rule.cel_allow_if.as_ref()?;

        match cel_policy.evaluate_on(policy_context, route) {
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
    surface: Option<PolicySurface>,
}

/// One federation's governance as the `FederationEngine` publishes it: the
/// rule everything the router sends to that federation inherits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FederationGovernance {
    pub federation: String,
    pub minimum_trust: RequestTrustLevel,
    pub cel_allow_if: Option<String>,
    pub required_scopes: Vec<String>,
}

/// A federation's compiled rule.
#[derive(Debug)]
enum FederatedRule {
    Governed(ToolRulePolicy),
    /// The federation's governance did not compile. Every capability it
    /// serves is refused.
    Uncompiled,
}

impl FederatedRule {
    fn compile(governance: &FederationGovernance) -> Self {
        let federation = &governance.federation;
        let rule = ToolTrustRule {
            tool_name: federation.clone(),
            minimum_trust: governance.minimum_trust,
            cel_allow_if: governance.cel_allow_if.clone(),
            required_scopes: governance.required_scopes.clone(),
            surface: None,
        };
        match ToolRulePolicy::compile(
            rule,
            format!("mcp.federations[{federation}].governance.allow_if"),
        ) {
            Ok(policy) => Self::Governed(policy),
            Err(error) => {
                tracing::error!(
                    federation = %federation,
                    error = %format!("{error:#}"),
                    "federation governance did not compile; every capability it serves is refused"
                );
                Self::Uncompiled
            }
        }
    }
}

/// Runtime-mutable policy for FEDERATED capabilities, published by the
/// `FederationEngine`: one rule per federation, keyed by federation name.
///
/// The gate applies a federation's rule to exactly what the router sends to
/// that federation, never by matching names: the router serves a name or a
/// URI natively before any federation, so a federation whose names, URIs,
/// templates or prefix merely match a request must not govern it.
#[derive(Debug, Default)]
pub(crate) struct FederatedToolPolicies {
    rules: HashMap<String, PublishedRule>,
}

/// One federation's rule as published, with the version the decisions
/// cached under it are keyed by.
#[derive(Debug)]
struct PublishedRule {
    governance: FederationGovernance,
    rule: Arc<FederatedRule>,
    /// Never reused for other governance, so a cached decision never
    /// outlives the rule it was made under.
    version: u64,
}

impl FederatedToolPolicies {
    /// Compile each federation's rule once. A federation whose rule does not
    /// compile is recorded as refused; the others keep their own rules.
    pub(crate) fn from_federations(
        federations: impl IntoIterator<Item = FederationGovernance>,
    ) -> Self {
        Self::default().republished(federations)
    }

    /// The set `federations` publishes after this one. A federation whose
    /// governance is unchanged keeps its compiled rule and its version, so
    /// the decisions cached under it stay valid; a new or changed one is
    /// compiled under a new version.
    pub(crate) fn republished(
        &self,
        federations: impl IntoIterator<Item = FederationGovernance>,
    ) -> Self {
        static VERSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let rules = federations
            .into_iter()
            .map(|governance| {
                let published = match self.rules.get(&governance.federation) {
                    Some(previous) if previous.governance == governance => PublishedRule {
                        governance,
                        rule: Arc::clone(&previous.rule),
                        version: previous.version,
                    },
                    _ => PublishedRule {
                        rule: Arc::new(FederatedRule::compile(&governance)),
                        version: VERSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
                        governance,
                    },
                };
                (published.governance.federation.clone(), published)
            })
            .collect();
        Self { rules }
    }

    fn rule(&self, federation: &str) -> Option<&FederatedRule> {
        self.rules
            .get(federation)
            .map(|published| published.rule.as_ref())
    }

    /// The version of `federation`'s published rule; 0 when it has none.
    fn version(&self, federation: &str) -> u64 {
        self.rules
            .get(federation)
            .map_or(0, |published| published.version)
    }
}

impl ToolRulePolicy {
    fn from_rule(rule: ToolTrustRule) -> Result<Self> {
        let config_path = format!("policy.tool_access.rules[{}].cel_allow_if", rule.tool_name);
        Self::compile(rule, config_path)
    }

    fn compile(rule: ToolTrustRule, config_path: String) -> Result<Self> {
        Ok(Self {
            minimum_trust: rule.minimum_trust,
            cel_allow_if: rule
                .cel_allow_if
                .map(|source| CelToolAccessPolicy::compile(source, config_path))
                .transpose()?,
            required_scopes: rule.required_scopes,
            tool_name: rule.tool_name,
            surface: rule.surface,
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

    #[cfg(test)]
    fn evaluate(&self, policy_context: &ToolPolicyContext) -> Result<bool> {
        self.evaluate_on(policy_context, PolicyRoute::gateway())
    }

    fn evaluate_on(
        &self,
        policy_context: &ToolPolicyContext,
        route: PolicyRoute<'_>,
    ) -> Result<bool> {
        let mut context = CelContext::default();
        context
            .add_variable("tool_name", policy_context.tool_name.as_str())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        context
            .add_variable("surface", route.surface.map_or("", PolicySurface::as_str))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let arguments = route
            .arguments
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        context.add_variable_from_value("arguments", mcpg_expr::json_to_cel(&arguments));
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
    map.insert(
        CelKey::String("issuer".to_owned().into()),
        match &ctx.issuer {
            Some(i) => CelValue::String(i.clone().into()),
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
    map.insert(
        CelKey::String("authorization_details".to_owned().into()),
        authorization_details_value(&ctx.attributes),
    );

    CelValue::Map(CelMap { map: Arc::new(map) })
}

/// `identity.authorization_details`: the RFC 9396 details a token of the
/// embedded authorization server is limited to, as a list of maps; empty
/// when the caller carries none, or none that read as a list of objects.
fn authorization_details_value(
    attributes: &std::collections::BTreeMap<String, String>,
) -> CelValue {
    use crate::runtime::authorization_server::rar::{
        AUTHORIZATION_DETAILS_ATTRIBUTE, AuthorizationDetails,
    };
    attributes
        .get(AUTHORIZATION_DETAILS_ATTRIBUTE)
        .and_then(|value| AuthorizationDetails::from_attribute(value))
        .and_then(|details| cel::to_value(details.entries()).ok())
        .unwrap_or_else(|| CelValue::List(Vec::new().into()))
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

    impl PreDispatchPolicyGate {
        /// A request for a surface the gateway serves itself.
        fn evaluate_tool_call(
            &self,
            policy_context: &ToolPolicyContext,
        ) -> PreDispatchPolicyOutcome {
            self.evaluate(policy_context, PolicyRoute::gateway())
        }

        /// Publish `federations` after the current set, as the federation
        /// engine does on every refresh.
        fn store_federations<const N: usize>(&self, federations: [FederationGovernance; N]) {
            let handle = self.federated_policy_handle();
            let next = handle.load().republished(federations);
            handle.store(Arc::new(next));
        }

        fn cached_decisions(&self) -> usize {
            self.cache
                .as_ref()
                .map_or(0, |cache| cache.entries.lock().expect("cache lock").len())
        }
    }

    fn allows(outcome: PreDispatchPolicyOutcome) -> bool {
        matches!(outcome, PreDispatchPolicyOutcome::Allow)
    }

    #[test]
    fn federated_tools_inherit_their_federation_governance() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig::default())
            .expect("default policy valid");
        gate.store_federations([
            federation_governance("notion", RequestTrustLevel::Unauthenticated, None, &[]),
            federation_governance("admin", RequestTrustLevel::Verified, None, &[]),
        ]);
        // Federated rule lowers the bar below the default → allowed.
        assert!(allows(gate.evaluate(
            &anonymous_context("notion.search"),
            PolicyRoute::served_by(Some("notion"))
        )));
        // Federated rule raises the bar → denied (governance enforced).
        assert!(!allows(gate.evaluate(
            &anonymous_context("admin.purge"),
            PolicyRoute::served_by(Some("admin"))
        )));
    }

    fn federation_governance(
        federation: &str,
        minimum_trust: RequestTrustLevel,
        allow_if: Option<&str>,
        required_scopes: &[&str],
    ) -> FederationGovernance {
        FederationGovernance {
            federation: federation.to_owned(),
            minimum_trust,
            cel_allow_if: allow_if.map(str::to_owned),
            required_scopes: required_scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn gate_with_default_floor(default_minimum_trust: RequestTrustLevel) -> PreDispatchPolicyGate {
        gate_with_rules(default_minimum_trust, Vec::new())
    }

    fn gate_with_rules(
        default_minimum_trust: RequestTrustLevel,
        rules: Vec<ToolTrustRule>,
    ) -> PreDispatchPolicyGate {
        PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust,
            cel_allow_if: None,
            rules,
        })
        .expect("policy valid")
    }

    fn rule(
        name: &str,
        minimum_trust: RequestTrustLevel,
        allow_if: Option<&str>,
        required_scopes: &[&str],
    ) -> ToolTrustRule {
        ToolTrustRule {
            tool_name: name.to_owned(),
            minimum_trust,
            cel_allow_if: allow_if.map(str::to_owned),
            required_scopes: required_scopes.iter().map(|s| (*s).to_owned()).collect(),
            surface: None,
        }
    }

    /// A federated read routed as the read path routes it: `listed_as` is
    /// the URI or template the federation lists the resource under.
    fn federated_read(federation: &str, listed_as: &str) -> ResourceRoute {
        ResourceRoute::Federated {
            source: federation.to_owned(),
            upstream_uri: String::new(),
            listed_as: listed_as.to_owned(),
        }
    }

    fn anonymous_context(tool: &str) -> ToolPolicyContext {
        ToolPolicyContext::from_request_context(
            &sample_context(RequestIdentity::Anonymous {
                source: "test".to_owned(),
            }),
            tool,
        )
    }

    fn verified_context_for(tool: &str, scopes: &[&str]) -> ToolPolicyContext {
        let mut context = verified_context_with_claims(vec![], vec![], scopes.to_vec(), vec![]);
        context.tool_name = tool.to_owned();
        context
    }

    /// A federation whose `allow_if` does not compile has every capability
    /// it serves refused, even for a caller who clears its trust floor,
    /// while the other federations keep their own rules. The gateway-wide
    /// default is never consulted for it.
    #[test]
    fn uncompiled_federation_governance_refuses_only_that_federation() {
        let gate = gate_with_default_floor(RequestTrustLevel::Unauthenticated);
        gate.store_federations([
            federation_governance(
                "broken",
                RequestTrustLevel::Unauthenticated,
                Some("tool_name == "),
                &[],
            ),
            federation_governance(
                "notion",
                RequestTrustLevel::Verified,
                Some(r#"tool_name == "notion.search""#),
                &[],
            ),
        ]);
        let broken = PolicyRoute::served_by(Some("broken"));
        let notion = PolicyRoute::served_by(Some("notion"));

        for context in [
            anonymous_context("broken.search"),
            verified_context_for("broken.search", &[]),
            verified_context_for("mcp://broken/pages/{id}", &[]),
        ] {
            match gate.evaluate(&context, broken) {
                PreDispatchPolicyOutcome::Deny(denial) => {
                    assert_eq!(denial.http_status, 500);
                    assert!(
                        denial
                            .audit_reason
                            .starts_with("federation_governance_uncompiled:"),
                        "{}",
                        denial.audit_reason
                    );
                    assert!(denial.audit_reason.ends_with(":broken"));
                }
                PreDispatchPolicyOutcome::Allow => {
                    panic!("{} must be refused", context.tool_name)
                }
            }
            assert!(!gate.is_visible(&context, broken));
        }
        // A concrete template read the router sends to the broken federation.
        let read = verified_context_for("mcp://broken/pages/1", &[]);
        let route = federated_read("broken", "mcp://broken/pages/{id}");
        match gate.evaluate(&read, PolicyRoute::for_resource(&route)) {
            PreDispatchPolicyOutcome::Deny(denial) => assert_eq!(
                denial.audit_reason,
                "federation_governance_uncompiled:mcp://broken/pages/1:broken"
            ),
            PreDispatchPolicyOutcome::Allow => panic!("a read routed to it must be refused"),
        }

        // The healthy federation keeps its floor and its allow_if.
        assert!(allows(
            gate.evaluate(&verified_context_for("notion.search", &[]), notion)
        ));
        assert!(!allows(
            gate.evaluate(&anonymous_context("notion.search"), notion)
        ));
        assert!(!allows(
            gate.evaluate(&verified_context_for("notion.delete", &[]), notion)
        ));
        // A name the gateway serves itself still follows the gateway default.
        assert!(allows(
            gate.evaluate_tool_call(&anonymous_context("native.echo"))
        ));
    }

    /// A federation's `required_scopes` is enforced like a binding's: a
    /// caller short of a scope is refused with the step-up flag naming it.
    #[test]
    fn federated_required_scopes_are_enforced() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig::default())
            .expect("default policy valid");
        gate.store_federations([federation_governance(
            "notion",
            RequestTrustLevel::Verified,
            None,
            &["notion.read"],
        )]);
        let notion = PolicyRoute::served_by(Some("notion"));

        match gate.evaluate(&verified_context_for("notion.search", &["other"]), notion) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 403);
                assert_eq!(
                    denial.insufficient_scope.as_deref(),
                    Some(["notion.read".to_owned()].as_slice()),
                );
            }
            PreDispatchPolicyOutcome::Allow => panic!("a caller without the scope is refused"),
        }
        assert!(allows(gate.evaluate(
            &verified_context_for("notion.search", &["notion.read"]),
            notion
        )));
    }

    /// A binding's rule governs its own kind of surface only. A native
    /// prompt's rule never tightens a federated tool, or a native tool, of
    /// the same name; a native tool's rule, which names the routed surface,
    /// still tightens a federated tool of its name; a central rule governs
    /// every surface of its name; and a request of unknown kind is held to
    /// every rule of the name.
    #[test]
    fn a_binding_rule_governs_only_its_own_kind_of_surface() {
        let crm = PolicyRoute::served_by(Some("crm"));
        let gateway = PolicyRoute::gateway();
        let lenient_crm =
            federation_governance("crm", RequestTrustLevel::Unauthenticated, None, &[]);
        let gate_with = |surface: Option<PolicySurface>| {
            let gate = gate_with_rules(
                RequestTrustLevel::Unauthenticated,
                vec![ToolTrustRule {
                    surface,
                    ..rule("search", RequestTrustLevel::Verified, None, &[])
                }],
            );
            gate.store_federations([lenient_crm.clone()]);
            gate
        };
        let anonymous = anonymous_context("search");

        let prompt_rule = gate_with(Some(PolicySurface::Prompt));
        assert!(allows(
            prompt_rule.evaluate(&anonymous, crm.on(PolicySurface::Tool))
        ));
        assert!(allows(
            prompt_rule.evaluate(&anonymous, gateway.on(PolicySurface::Tool))
        ));
        assert!(!allows(
            prompt_rule.evaluate(&anonymous, gateway.on(PolicySurface::Prompt))
        ));
        assert!(!allows(
            prompt_rule.evaluate(&anonymous, crm.on(PolicySurface::Prompt))
        ));
        assert!(!allows(prompt_rule.evaluate(&anonymous, gateway)));

        let tool_rule = gate_with(Some(PolicySurface::Tool));
        assert!(!allows(
            tool_rule.evaluate(&anonymous, crm.on(PolicySurface::Tool))
        ));
        assert!(allows(
            tool_rule.evaluate(&anonymous, crm.on(PolicySurface::Prompt))
        ));
        assert!(allows(
            tool_rule.evaluate(&anonymous, gateway.on(PolicySurface::Resource))
        ));

        let central_rule = gate_with(None);
        for surface in [
            PolicySurface::Tool,
            PolicySurface::Prompt,
            PolicySurface::Resource,
        ] {
            assert!(
                !allows(central_rule.evaluate(&anonymous, crm.on(surface))),
                "{surface:?}"
            );
        }
    }

    /// A cached decision for one kind of surface is never reused for another
    /// of the same name.
    #[test]
    fn a_cached_decision_is_kept_per_kind_of_surface() {
        let gate = PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: vec![ToolTrustRule {
                    surface: Some(PolicySurface::Prompt),
                    ..rule("search", RequestTrustLevel::Verified, None, &[])
                }],
            },
            &PolicyCacheConfig {
                enabled: true,
                ttl_ms: 60_000,
                max_entries: 64,
            },
        )
        .expect("policy valid");
        let anonymous = anonymous_context("search");
        let gateway = PolicyRoute::gateway();
        assert!(allows(
            gate.evaluate(&anonymous, gateway.on(PolicySurface::Tool))
        ));
        assert!(!allows(
            gate.evaluate(&anonymous, gateway.on(PolicySurface::Prompt))
        ));
    }

    /// A central or native rule that names what the router sends to a
    /// federation is applied on top of the federation's rule: it can raise
    /// the floor, add scopes and add an `allow_if`, but a lower floor, fewer
    /// scopes or a more permissive condition never loosen the federation's.
    #[test]
    fn a_native_or_central_rule_tightens_a_federation_but_never_loosens_it() {
        let crm = PolicyRoute::served_by(Some("crm"));
        let strict_crm = federation_governance(
            "crm",
            RequestTrustLevel::Verified,
            Some(r#""sales" in identity.groups"#),
            &["crm.read"],
        );
        let mut sales = verified_context_for("search", &["crm.read"]);
        sales.groups = vec!["sales".to_owned()];

        // A lenient rule of the same name: the federation's rule still holds.
        let gate = gate_with_rules(
            RequestTrustLevel::Unauthenticated,
            vec![rule(
                "search",
                RequestTrustLevel::Unauthenticated,
                Some("true"),
                &[],
            )],
        );
        gate.store_federations([strict_crm.clone()]);
        assert!(!allows(gate.evaluate(&anonymous_context("search"), crm)));
        match gate.evaluate(&verified_context_for("search", &[]), crm) {
            PreDispatchPolicyOutcome::Deny(denial) => assert_eq!(
                denial.insufficient_scope.as_deref(),
                Some(["crm.read".to_owned()].as_slice()),
            ),
            PreDispatchPolicyOutcome::Allow => panic!("the federation's scope still applies"),
        }
        assert!(!allows(
            gate.evaluate(&verified_context_for("search", &["crm.read"]), crm)
        ));
        assert!(allows(gate.evaluate(&sales, crm)));

        // A strict rule of the same name tightens a lenient federation.
        let gate = gate_with_rules(
            RequestTrustLevel::Unauthenticated,
            vec![rule(
                "search",
                RequestTrustLevel::HeaderAsserted,
                Some(r#""sales" in identity.groups"#),
                &["crm.audit"],
            )],
        );
        gate.store_federations([federation_governance(
            "crm",
            RequestTrustLevel::Unauthenticated,
            None,
            &[],
        )]);
        assert!(!allows(gate.evaluate(&anonymous_context("search"), crm)));
        assert!(!allows(gate.evaluate(&sales, crm)));
        sales.scopes.push("crm.audit".to_owned());
        assert!(allows(gate.evaluate(&sales, crm)));
        sales.groups.clear();
        assert!(!allows(gate.evaluate(&sales, crm)));
    }

    /// A federated read answers to a rule filed under the URI or template
    /// the federation lists it as, whichever spelling or concrete URI the
    /// client read it by.
    #[test]
    fn a_rule_naming_a_listed_federated_uri_holds_for_every_read_of_it() {
        let gate = gate_with_rules(
            RequestTrustLevel::Unauthenticated,
            vec![
                rule(
                    "https://docs.example/readme",
                    RequestTrustLevel::Verified,
                    None,
                    &[],
                ),
                rule(
                    "notion://pages/{id}",
                    RequestTrustLevel::Verified,
                    None,
                    &[],
                ),
            ],
        );
        gate.store_federations([federation_governance(
            "docs",
            RequestTrustLevel::Unauthenticated,
            None,
            &[],
        )]);
        let readme = federated_read("docs", "https://docs.example/readme");
        let page = federated_read("docs", "notion://pages/{id}");
        for (uri, route) in [
            ("HTTPS://Docs.Example:443/readme", &readme),
            ("notion://pages/42", &page),
        ] {
            let route = PolicyRoute::for_resource(route);
            assert!(
                !allows(gate.evaluate(&anonymous_context(uri), route)),
                "{uri}"
            );
            assert!(
                allows(gate.evaluate(&verified_context_for(uri, &[]), route)),
                "{uri}"
            );
        }
    }

    /// A read the router sends to a federation answers to that federation's
    /// rule however it is spelled: a URI in another case or with a default
    /// port, and a concrete URI one of its templates matches when the
    /// federation has no `resource_uri_prefix`.
    #[test]
    fn a_read_routed_to_a_federation_answers_to_its_rule_by_any_spelling() {
        let gate = gate_with_default_floor(RequestTrustLevel::Unauthenticated);
        gate.store_federations([federation_governance(
            "docs",
            RequestTrustLevel::Verified,
            None,
            &["docs.read"],
        )]);

        let readme = federated_read("docs", "https://docs.example/readme");
        let page = federated_read("docs", "notion://pages/{id}");
        let routed = [
            ("https://docs.example/readme", &readme),
            ("HTTPS://Docs.Example:443/readme", &readme),
            (" https://docs.example/readme ", &readme),
            ("notion://pages/42", &page),
            ("notion://pages/{id}", &page),
        ];
        for (uri, route) in routed {
            let decide = |context: &ToolPolicyContext| {
                gate.evaluate(context, PolicyRoute::for_resource(route))
            };
            assert!(
                matches!(
                    decide(&anonymous_context(uri)),
                    PreDispatchPolicyOutcome::Deny(_)
                ),
                "{uri} must answer to the federation's floor"
            );
            match decide(&verified_context_for(uri, &[])) {
                PreDispatchPolicyOutcome::Deny(denial) => assert_eq!(
                    denial.insufficient_scope.as_deref(),
                    Some(["docs.read".to_owned()].as_slice()),
                    "{uri}"
                ),
                PreDispatchPolicyOutcome::Allow => panic!("{uri} must require docs.read"),
            }
            assert!(matches!(
                decide(&verified_context_for(uri, &["docs.read"])),
                PreDispatchPolicyOutcome::Allow
            ));
        }
    }

    /// A federation governs only what the router sends to it. A name it
    /// lists, or one of its URIs or templates would match, but that the
    /// router serves natively (a gateway-internal tool, a native template's
    /// concrete URI, another spelling of a native resource) keeps the
    /// gateway's own policy even when the federation's floor is lower —
    /// otherwise an upstream could lower it by advertising a prompt or a
    /// template under that name.
    #[test]
    fn a_federation_does_not_govern_what_the_router_sends_elsewhere() {
        let gate = gate_with_default_floor(RequestTrustLevel::HeaderAsserted);
        gate.store_federations([federation_governance(
            "open",
            RequestTrustLevel::Unauthenticated,
            None,
            &[],
        )]);

        for name in [
            "mcpg.debug.command_probe",
            "file:///secrets",
            "HTTPS://docs.example/readme",
        ] {
            assert!(
                !allows(gate.evaluate(&anonymous_context(name), PolicyRoute::gateway())),
                "{name} is not the federation's to open"
            );
            assert!(
                allows(gate.evaluate(
                    &anonymous_context(name),
                    PolicyRoute::served_by(Some("open"))
                )),
                "{name} routed to the federation takes its floor"
            );
        }
    }

    /// A native read answers to the rule of the binding it routes to, which
    /// is filed under the binding's name: a concrete URI a template matches
    /// and another spelling of a resource's URI get the binding's floor, not
    /// the gateway default.
    #[test]
    fn a_native_read_answers_to_the_binding_it_routes_to() {
        let gate = gate_with_rules(
            RequestTrustLevel::Unauthenticated,
            vec![
                rule("page", RequestTrustLevel::Verified, None, &["wiki.read"]),
                rule("wiki://pages/{id}", RequestTrustLevel::Verified, None, &[]),
                rule("readme", RequestTrustLevel::Verified, None, &[]),
                rule(
                    "https://docs.example/readme",
                    RequestTrustLevel::Verified,
                    None,
                    &[],
                ),
            ],
        );
        let page = ResourceRoute::Template {
            profile: "page".to_owned(),
            template_vars: std::collections::BTreeMap::new(),
        };
        let readme = ResourceRoute::Binding {
            profile: "readme".to_owned(),
        };
        for (uri, route) in [
            ("wiki://pages/7", &page),
            ("HTTPS://Docs.Example:443/readme", &readme),
        ] {
            let route = PolicyRoute::for_resource(route);
            assert!(
                !allows(gate.evaluate(&anonymous_context(uri), route)),
                "{uri} must answer to its binding's floor"
            );
        }
        match gate.evaluate(
            &verified_context_for("wiki://pages/7", &[]),
            PolicyRoute::for_resource(&page),
        ) {
            PreDispatchPolicyOutcome::Deny(denial) => assert_eq!(
                denial.insufficient_scope.as_deref(),
                Some(["wiki.read".to_owned()].as_slice())
            ),
            PreDispatchPolicyOutcome::Allow => panic!("the template binding's scope applies"),
        }
        assert!(allows(gate.evaluate(
            &verified_context_for("wiki://pages/7", &["wiki.read"]),
            PolicyRoute::for_resource(&page)
        )));
        assert!(allows(gate.evaluate(
            &verified_context_for("HTTPS://Docs.Example:443/readme", &[]),
            PolicyRoute::for_resource(&readme)
        )));
    }

    /// A read routed to a federation that published no governance is
    /// refused rather than decided by the gateway-wide policy.
    #[test]
    fn a_read_routed_to_an_ungoverned_federation_is_refused() {
        let gate = gate_with_default_floor(RequestTrustLevel::Unauthenticated);
        let route = federated_read("ghost", "notes/{id}");
        match gate.evaluate(
            &anonymous_context("notes/1"),
            PolicyRoute::for_resource(&route),
        ) {
            PreDispatchPolicyOutcome::Deny(denial) => {
                assert_eq!(denial.http_status, 500);
                assert_eq!(
                    denial.audit_reason,
                    "federation_governance_missing:notes/1:ghost"
                );
            }
            PreDispatchPolicyOutcome::Allow => panic!("an ungoverned route must be refused"),
        }
    }

    /// Federated governance changes under a running gate as imports land, so
    /// a cached decision is only reused under the set it was made under.
    #[test]
    fn a_cached_decision_does_not_outlive_its_federated_policy_set() {
        let gate = PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: Vec::new(),
            },
            &crate::config::PolicyCacheConfig {
                enabled: true,
                ttl_ms: 600_000,
                max_entries: 100,
            },
        )
        .expect("policy valid");
        let caller = anonymous_context("late.search");
        let late = PolicyRoute::served_by(Some("late"));
        gate.store_federations([federation_governance(
            "late",
            RequestTrustLevel::Unauthenticated,
            None,
            &[],
        )]);
        assert!(allows(gate.evaluate(&caller, late)));

        gate.store_federations([federation_governance(
            "late",
            RequestTrustLevel::Verified,
            None,
            &[],
        )]);
        assert!(!allows(gate.evaluate(&caller, late)));

        // The same name decided for a native route and for a route to the
        // federation are two decisions, not one cached answer; so are two
        // reads of one URI listed under different names.
        let reader = anonymous_context("late://notes/1");
        assert!(allows(gate.evaluate(&reader, PolicyRoute::gateway())));
        assert!(!allows(gate.evaluate(&reader, late)));
        let gate = PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: vec![rule(
                    "late://notes/{id}",
                    RequestTrustLevel::Verified,
                    None,
                    &[],
                )],
            },
            &crate::config::PolicyCacheConfig {
                enabled: true,
                ttl_ms: 600_000,
                max_entries: 100,
            },
        )
        .expect("policy valid");
        gate.store_federations([federation_governance(
            "late",
            RequestTrustLevel::Unauthenticated,
            None,
            &[],
        )]);
        let other = federated_read("late", "late://notes/1");
        let template = federated_read("late", "late://notes/{id}");
        assert!(allows(
            gate.evaluate(&reader, PolicyRoute::for_resource(&other))
        ));
        assert!(!allows(
            gate.evaluate(&reader, PolicyRoute::for_resource(&template))
        ));
    }

    fn cached_gate(max_entries: usize) -> PreDispatchPolicyGate {
        PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: Vec::new(),
            },
            &crate::config::PolicyCacheConfig {
                enabled: true,
                ttl_ms: 600_000,
                max_entries,
            },
        )
        .expect("policy valid")
    }

    /// An event rule's CEL reads `surface` and the subscription
    /// `arguments`, and a cached decision for one argument set never
    /// answers for another.
    #[test]
    fn event_rules_read_the_surface_and_arguments_and_cache_per_argument_set() {
        let gate = PreDispatchPolicyGate::try_new_with_cache(
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: vec![ToolTrustRule {
                    tool_name: "event:orders.created".to_owned(),
                    minimum_trust: RequestTrustLevel::Unauthenticated,
                    cel_allow_if: Some(
                        r#"surface == "event" && (!has(arguments.region) || arguments.region == "eu")"#
                            .to_owned(),
                    ),
                    required_scopes: Vec::new(),
                    surface: Some(PolicySurface::Event),
                }],
            },
            &crate::config::PolicyCacheConfig {
                enabled: true,
                ttl_ms: 600_000,
                max_entries: 100,
            },
        )
        .expect("policy valid");
        let caller = anonymous_context("event:orders.created");
        let eu = serde_json::json!({ "region": "eu" });
        let us = serde_json::json!({ "region": "us" });
        assert!(allows(
            gate.evaluate(&caller, PolicyRoute::event(Some(&eu)))
        ));
        assert!(!allows(
            gate.evaluate(&caller, PolicyRoute::event(Some(&us)))
        ));
        assert!(allows(
            gate.evaluate(&caller, PolicyRoute::event(Some(&eu)))
        ));
        assert!(
            allows(gate.evaluate(&caller, PolicyRoute::event(None))),
            "a listing has no arguments"
        );
        // A tool of the same bare name is not governed by the event rule.
        let tool = anonymous_context("orders.created");
        assert!(allows(gate.evaluate(&tool, PolicyRoute::gateway())));
    }

    #[test]
    fn a_republish_keeps_the_decisions_its_rules_still_make() {
        let gate = cached_gate(100);
        let notion = federation_governance("notion", RequestTrustLevel::Unauthenticated, None, &[]);
        let crm = federation_governance("crm", RequestTrustLevel::Unauthenticated, None, &[]);
        gate.store_federations([notion.clone(), crm.clone()]);
        let search = anonymous_context("notion.search");
        let contacts = anonymous_context("crm.contacts");
        let native = anonymous_context("mcpg.runtime.snapshot");
        assert!(allows(
            gate.evaluate(&search, PolicyRoute::served_by(Some("notion")))
        ));
        assert!(allows(
            gate.evaluate(&contacts, PolicyRoute::served_by(Some("crm")))
        ));
        assert!(allows(gate.evaluate(&native, PolicyRoute::gateway())));
        assert_eq!(gate.cached_decisions(), 3);

        // A refresh that publishes the same governance decides nothing anew.
        gate.store_federations([notion.clone(), crm.clone()]);
        assert!(allows(
            gate.evaluate(&search, PolicyRoute::served_by(Some("notion")))
        ));
        assert!(allows(
            gate.evaluate(&contacts, PolicyRoute::served_by(Some("crm")))
        ));
        assert!(allows(gate.evaluate(&native, PolicyRoute::gateway())));
        assert_eq!(gate.cached_decisions(), 3);

        // A changed rule is decided anew for its own federation only.
        let crm_verified = federation_governance("crm", RequestTrustLevel::Verified, None, &[]);
        gate.store_federations([notion, crm_verified]);
        assert!(allows(
            gate.evaluate(&search, PolicyRoute::served_by(Some("notion")))
        ));
        assert!(allows(gate.evaluate(&native, PolicyRoute::gateway())));
        assert_eq!(gate.cached_decisions(), 3);
        assert!(!allows(
            gate.evaluate(&contacts, PolicyRoute::served_by(Some("crm")))
        ));
        assert_eq!(gate.cached_decisions(), 4);
    }

    #[test]
    fn a_cache_full_of_decisions_under_a_replaced_rule_still_caches() {
        let gate = cached_gate(2);
        let open = federation_governance("crm", RequestTrustLevel::Unauthenticated, None, &[]);
        gate.store_federations([open]);
        let route = PolicyRoute::served_by(Some("crm"));
        assert!(allows(gate.evaluate(&anonymous_context("crm.a"), route)));
        assert!(allows(gate.evaluate(&anonymous_context("crm.b"), route)));
        assert_eq!(gate.cached_decisions(), 2);

        // Both cached decisions were made under a rule that no longer holds,
        // so no lookup can reach them: the next decision takes their place.
        let closed = federation_governance("crm", RequestTrustLevel::Verified, None, &[]);
        gate.store_federations([closed]);
        let caller = anonymous_context("crm.a");
        assert!(!allows(gate.evaluate(&caller, route)));
        assert_eq!(gate.cached_decisions(), 1);
        let cache = gate.cache.as_ref().expect("cache enabled");
        let federated = gate.tool_access_policy.federated.load();
        let key = format!(
            "{}|{:?}|{:?}|{:?}",
            caller.cache_key(),
            Some(("crm".to_owned(), federated.version("crm"))),
            None::<&str>,
            None::<PolicySurface>,
        );
        assert!(
            cache.get(&key).is_some(),
            "the new decision is cached under the rule in force"
        );
    }

    /// A rule names one exact capability, never a pattern, so a name prefix
    /// is governed in the global `cel_allow_if`, as the multi-tenant docs
    /// show; a caller without the tenant claim is denied, not errored.
    #[test]
    fn a_name_prefix_is_governed_in_the_global_cel_allow_if() {
        let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::Unauthenticated,
            cel_allow_if: Some(
                r#"(!tool_name.startsWith("acme.")
                     || ("tenant" in identity.attributes && identity.attributes["tenant"] == "acme")
                     || "platform" in identity.groups)
                   && (!tool_name.startsWith("partner.")
                     || ("tenant" in identity.attributes && identity.attributes["tenant"] == "partner"))"#
                    .to_owned(),
            ),
            rules: Vec::new(),
        })
        .expect("policy valid");
        let caller = |tool: &str, tenant: Option<&str>, groups: &[&str]| ToolPolicyContext {
            tool_name: tool.to_owned(),
            trust_level: RequestTrustLevel::Verified,
            principal_id: Some("user-1".to_owned()),
            auth_provider: None,
            issuer: None,
            identity_kind: "verified".to_owned(),
            roles: Vec::new(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            scopes: Vec::new(),
            attributes: tenant
                .map(|t| [("tenant".to_owned(), t.to_owned())].into())
                .unwrap_or_default(),
        };
        let decide = |context: ToolPolicyContext| gate.evaluate_tool_call(&context);

        assert!(allows(decide(caller("acme.search", Some("acme"), &[]))));
        assert!(allows(decide(caller("acme.search", None, &["platform"]))));
        assert!(allows(decide(caller(
            "shared.search",
            Some("partner"),
            &[]
        ))));
        assert!(allows(decide(caller("shared.search", None, &[]))));
        assert!(!allows(decide(caller("acme.search", Some("partner"), &[]))));
        assert!(!allows(decide(caller("partner.search", Some("acme"), &[]))));
        match decide(caller("acme.search", None, &[])) {
            PreDispatchPolicyOutcome::Deny(denial) => assert_eq!(denial.code, -32022),
            PreDispatchPolicyOutcome::Allow => panic!("a caller without the claim is denied"),
        }
        // `acme.*` is the name of one capability, not a pattern.
        let exact = gate_with_rules(
            RequestTrustLevel::Unauthenticated,
            vec![rule("acme.*", RequestTrustLevel::Verified, None, &[])],
        );
        assert!(allows(
            exact.evaluate_tool_call(&anonymous_context("acme.search"))
        ));
        assert!(!allows(
            exact.evaluate_tool_call(&anonymous_context("acme.*"))
        ));
    }

    /// Config validation checks a governance `allow_if` with the shared
    /// validator and the gate compiles it itself, so the two must accept
    /// exactly the same expressions.
    #[test]
    fn governance_validation_and_the_gate_agree_on_allow_if() {
        use mcpg_expr::governance::validate_allow_if;
        for source in [
            r#""ops" in identity.groups"#,
            r#"tool_name.startsWith("acme.")"#,
            r#"trust_level == "verified" && "#,
            "tool_name == ",
            "size(",
        ] {
            assert_eq!(
                validate_allow_if(source, "x").is_ok(),
                CelToolAccessPolicy::compile(source.to_owned(), "x".to_owned()).is_ok(),
                "{source}"
            );
        }
        let error = validate_allow_if(
            "tool_name == ",
            "mcp.federations[notion].governance.allow_if",
        )
        .expect_err("invalid CEL");
        assert!(
            error
                .to_string()
                .contains("mcp.federations[notion].governance.allow_if"),
            "{error:#}"
        );
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
                surface: None,
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
                surface: None,
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
                surface: None,
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
                surface: None,
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
                surface: None,
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
        let no_federations = FederatedToolPolicies::default();
        let key = "user-1:my_tool:verified".to_owned();

        assert!(cache.get(&key).is_none());

        cache.put(
            key.clone(),
            PreDispatchPolicyOutcome::Allow,
            None,
            &no_federations,
        );

        let cached = cache.get(&key).expect("should be cached");
        assert!(matches!(cached, PreDispatchPolicyOutcome::Allow));
    }

    #[test]
    fn policy_cache_expires_after_ttl() {
        let cache = PolicyCache::new(0, 100); // 0-second TTL = immediately expired
        let no_federations = FederatedToolPolicies::default();
        let key = "user-1:my_tool:verified".to_owned();

        cache.put(
            key.clone(),
            PreDispatchPolicyOutcome::Allow,
            None,
            &no_federations,
        );

        // With 0-second TTL, entry should be expired
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn policy_cache_evicts_expired_entries_when_full() {
        let cache = PolicyCache::new(0, 2); // 0-second TTL, max 2 entries
        let no_federations = FederatedToolPolicies::default();

        cache.put(
            "a:tool:v".to_owned(),
            PreDispatchPolicyOutcome::Allow,
            None,
            &no_federations,
        );
        cache.put(
            "b:tool:v".to_owned(),
            PreDispatchPolicyOutcome::Allow,
            None,
            &no_federations,
        );

        // Wait for entries to expire
        std::thread::sleep(std::time::Duration::from_millis(10));

        // This should evict expired entries and succeed
        cache.put(
            "c:tool:v".to_owned(),
            PreDispatchPolicyOutcome::Allow,
            None,
            &no_federations,
        );

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
            issuer: None,
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
            issuer: None,
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
            issuer: None,
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
            issuer: None,
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

    /// `identity.issuer` is the token `iss` — with `subject_id` it is THE
    /// identifier for issuers whose subjects are only unique within the
    /// issuer (AAuth person servers, `allow_any_issuer` agents), and the
    /// only way to pin a tool to one issuing party.
    #[test]
    fn cel_policy_reads_identity_issuer() {
        let policy = CelToolAccessPolicy::compile(
            r#"identity.issuer == "https://ps.example" && identity.attributes["aauth.token_type"] == "person""#
                .to_owned(),
            "test".to_owned(),
        )
        .unwrap();
        let mut ctx = verified_context_with_claims(
            vec![],
            vec![],
            vec![],
            vec![("aauth.token_type", "person")],
        );
        ctx.issuer = Some("https://ps.example".to_owned());
        assert!(policy.evaluate(&ctx).unwrap());
        ctx.issuer = Some("https://other.example".to_owned());
        assert!(!policy.evaluate(&ctx).unwrap());
        // Absent issuer is null, never an unbound-variable error.
        ctx.issuer = None;
        assert!(!policy.evaluate(&ctx).unwrap());
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

    /// `identity.authorization_details` lists the RFC 9396 details of the
    /// caller's token, read from its attribute, so a rule can require one
    /// that covers the call; a caller without details gets an empty list.
    #[test]
    fn cel_policy_reads_the_authorization_details_of_the_caller() {
        let policy = CelToolAccessPolicy::compile(
            r#"identity.authorization_details.exists(d, d.type == "mcp_tool" && "tools/call" in d.actions && d.identifier == tool_name)"#
                .to_owned(),
            "test".to_owned(),
        )
        .unwrap();
        let details = r#"[{"type":"mcp_tool","actions":["tools/call"],"identifier":"admin.delete","limits":{"max":3}}]"#;
        let ctx = verified_context_with_claims(
            vec![],
            vec![],
            vec![],
            vec![("authorization_details", details)],
        );
        assert!(policy.evaluate(&ctx).unwrap());

        let other_tool = details.replace("admin.delete", "admin.read");
        let ctx = verified_context_with_claims(
            vec![],
            vec![],
            vec![],
            vec![("authorization_details", other_tool.as_str())],
        );
        assert!(!policy.evaluate(&ctx).unwrap());

        let without = verified_context_with_claims(vec![], vec![], vec![], vec![]);
        assert!(!policy.evaluate(&without).unwrap());
        for unreadable in ["not json", r#"{"type":"mcp_tool"}"#, "[1, 2]"] {
            let ctx = verified_context_with_claims(
                vec![],
                vec![],
                vec![],
                vec![("authorization_details", unreadable)],
            );
            assert!(!policy.evaluate(&ctx).unwrap(), "{unreadable}");
        }
        let empty = CelToolAccessPolicy::compile(
            "size(identity.authorization_details) == 0".to_owned(),
            "test".to_owned(),
        )
        .unwrap();
        assert!(empty.evaluate(&without).unwrap());
    }

    #[test]
    fn policy_cache_key_follows_the_authorization_details() {
        let with = |details: &str| {
            verified_context_with_claims(
                vec![],
                vec![],
                vec![],
                vec![("authorization_details", details)],
            )
            .cache_key()
        };
        assert_ne!(
            with(r#"[{"type":"mcp_tool","actions":["tools/call"]}]"#),
            with(r#"[{"type":"mcp_tool","actions":["tools/list"]}]"#)
        );
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
            issuer: None,
            identity_kind: "anonymous".to_owned(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        assert!(!policy.evaluate(&ctx).unwrap());
    }
}
