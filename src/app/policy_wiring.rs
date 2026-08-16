use super::*;
use crate::config::backend::BackendKind;

/// Build the runtime quota gate from `governance.quotas:` plus
/// the per-binding `quotas:` references collected from every
/// `mcp.capabilities.*[]` entry. Returns `None` when the
/// registry is empty AND no binding declares a `quotas:` block
/// (no work for the gate to do). Otherwise resolves the
/// `governance.quotas.store:` `KindRef` via the standard
/// resolution path, wraps it in a `QuotaStore`, and constructs
/// the gate with the binding-refs map pre-built so the runtime
/// hook is a single tool-name lookup.
#[cfg(feature = "governance-quotas")]
pub(crate) async fn build_quota_gate(
    config: &crate::config::AppConfig,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
) -> Result<Option<std::sync::Arc<crate::runtime::quota_gate::QuotaGate>>> {
    let quotas = &config.governance.quotas;
    let binding_refs = collect_binding_quota_refs(config);
    if quotas.is_empty() && binding_refs.is_empty() {
        return Ok(None);
    }
    use std::sync::Arc;
    // Convert KindRef → StoreOverrideConfig so the existing KV
    // resolver picks it up. Default to `kind: cluster` when the
    // operator left store empty — quotas live on the cluster
    // coordinator's KV unless overridden.
    let kref = &quotas.store;
    let kind = if kref.kind.trim().is_empty() {
        "cluster".to_owned()
    } else {
        kref.kind.clone()
    };
    let config_map = kref.config.as_object().cloned().unwrap_or_default();
    let over = crate::config::StoreOverrideConfig {
        kind,
        config: config_map,
    };
    let coordinator = plugin_registry.cluster_backend();
    let kv = resolve_capability_kv(
        Some(&over),
        "quotas",
        coordinator.as_ref(),
        plugin_registry,
        mcpg_plugin_protocol::store::StoreRole::Custom("quota".into()),
    )
    .await
    .context("governance.quotas.store: failed to resolve KV backend")?;
    // Seal quota state with the cluster state cipher when configured,
    // + tenant-prefix (outermost) for broker-ACL fencing.
    let kv = wrap_tenant_kv(
        wrap_state_kv(kv, &build_state_cipher(&config.cluster)?),
        &config.cluster.tenant_segment,
    );
    let store = crate::runtime::quota_gate::QuotaStore::new(kv);
    let gate = Arc::new(crate::runtime::quota_gate::QuotaGate::new(
        quotas,
        binding_refs,
        store,
    ));
    info!(
        rate_limits = quotas.rate_limits.len(),
        budgets = quotas.budgets.len(),
        concurrency = quotas.concurrency.len(),
        "runtime quota gate constructed"
    );
    Ok(Some(gate))
}

/// Walk every binding under `mcp.capabilities.{tools,prompts,
/// resources,resource_templates}` and collect the per-binding
/// `quotas:` reference into a `HashMap<backend_name, BackendQuotasRef>`.
/// Bindings without a `quotas:` block are skipped — they don't
/// trigger the gate at all (fast-path Allow). Used by
/// [`build_quota_gate`] to seed the gate's tool-name lookup map.
#[cfg(feature = "governance-quotas")]
pub(crate) fn collect_binding_quota_refs(
    config: &crate::config::AppConfig,
) -> std::collections::HashMap<String, crate::config::BackendQuotasRef> {
    let mut refs = std::collections::HashMap::new();
    for (_kind, binding) in config.all_bindings() {
        if let Some(qref) = binding.quotas.clone() {
            refs.insert(binding.name.clone(), qref);
        }
    }
    refs
}

/// Build the canonical `policy_engine` chain from the operator's
/// `governance.policy.engine[]` declaration. Each entry resolves
/// via [`resolve_kind`] (built-in keyword, short alias, or full
/// plugin id) and the resolved name is cross-checked against
/// the live registry. Refuses boot on:
///
/// - any kind that doesn't resolve;
/// - any resolved engine name that isn't registered (operator
///   declared an engine but its plugin / built-in didn't load);
/// - duplicate engine names in the chain (a chain entry that
///   would never fire).
///
/// Returns the ordered list of engine names the chain dispatch
/// should walk at every decision point. Empty when the operator
/// configured no chain — equivalent to "no policy enforcement".
pub(crate) fn build_policy_chain(
    engine_refs: &[crate::config::wiring::KindRef],
    plugins: &[crate::config::PluginEntryConfig],
    registry: &mcpg_plugin_host::PluginRegistry,
    cluster_kind: &str,
) -> Result<Vec<String>> {
    let registered: std::collections::BTreeSet<String> =
        registry.policy_engine_names().into_iter().collect();
    let mut chain: Vec<String> = Vec::with_capacity(engine_refs.len());
    let mut seen = std::collections::BTreeSet::<String>::new();
    for kref in engine_refs {
        let resolved = crate::config::wiring::resolve_kind(
            crate::config::wiring::SlotClass::PolicyEngine,
            kref,
            plugins,
            cluster_kind,
        )
        .with_context(|| {
            format!(
                "governance.policy.engine entry `kind: {}` failed to resolve",
                kref.kind
            )
        })?;
        let engine_name = match resolved {
            crate::config::wiring::ResolvedKind::Builtin(name) => match name.as_str() {
                "yaml-rules" => "yaml-rules".to_owned(),
                other => {
                    anyhow::bail!(
                        "governance.policy.engine[]: built-in keyword `{other}` is not \
                         a known policy_engine — did you mean `yaml-rules`?"
                    );
                }
            },
            crate::config::wiring::ResolvedKind::Plugin(plugin_id) => {
                // Map plugin id → engine name. The convention for
                // first-party policy plugins is the alias suffix
                // (`dev.mcpg.policy.cedar` → `cedar`); third-party
                // plugins set their own name() returns. We trust
                // the registry: walk policy_engine_ids() and find
                // the matching id, then look up its name from the
                // already-loaded engine.
                let names = registry.policy_engine_names();
                let ids = registry.policy_engine_plugin_ids();
                names
                    .iter()
                    .zip(ids.iter())
                    .find(|(_, id)| id.as_str() == plugin_id)
                    .map(|(name, _)| name.clone())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "governance.policy.engine[]: plugin `{plugin_id}` resolved \
                             from `kind: {}` is not registered as a policy_engine — \
                             check the plugin's class and load order",
                            kref.kind
                        )
                    })?
            }
            crate::config::wiring::ResolvedKind::Cluster => {
                anyhow::bail!(
                    "governance.policy.engine[]: `kind: cluster` is not a valid \
                     policy_engine source — policy decisions are not a cluster role"
                );
            }
        };
        if !registered.contains(&engine_name) {
            anyhow::bail!(
                "governance.policy.engine[]: engine `{engine_name}` (resolved from \
                 `kind: {}`) is not registered. Either the plugin failed to load or \
                 the built-in YAML-rules engine wasn't constructed; check earlier \
                 boot logs.",
                kref.kind
            );
        }
        if !seen.insert(engine_name.clone()) {
            anyhow::bail!(
                "governance.policy.engine[]: engine `{engine_name}` appears more than \
                 once — a chain entry past the first match would never fire"
            );
        }
        chain.push(engine_name);
    }
    Ok(chain)
}

pub(crate) fn build_tool_access_policy_config(config: &AppConfig) -> ToolAccessPolicyConfig {
    let mut rules = config
        .governance
        .policy
        .tool_access
        .rules
        .iter()
        .map(|rule| ToolTrustRule {
            tool_name: rule.tool_name.clone(),
            minimum_trust: map_trust_level(rule.minimum_trust),
            cel_allow_if: rule.cel_allow_if.clone(),
            required_scopes: rule.required_scopes.clone(),
        })
        .collect::<Vec<_>>();

    // Inject binding governance rules — trust floor, CEL guard, and the
    // binding's own scope requirement (a central rule cannot name a bound
    // surface, so this is where a bound tool's scopes are declared).
    for (kind, binding) in config.all_bindings() {
        // Every surface is gated under the key that surface names it by, and
        // for resources that key is the URI, not the binding name — both
        // `resources/list` and the read path ask policy about the URI the
        // client sent. A name-only rule therefore never matches, and the
        // binding's `minimum_trust` silently degrades to
        // `default_minimum_trust`.
        let surface_key = match kind {
            BackendKind::Resource => binding.uri.clone(),
            BackendKind::ResourceTemplate => binding.uri_template.clone(),
            BackendKind::Tool | BackendKind::Prompt => None,
        };
        for key in std::iter::once(binding.name.clone()).chain(surface_key) {
            rules.push(ToolTrustRule {
                tool_name: key,
                minimum_trust: map_trust_level(binding.governance.minimum_trust),
                cel_allow_if: binding.governance.allow_if.clone(),
                required_scopes: binding.governance.required_scopes.clone(),
            });
        }
    }

    ToolAccessPolicyConfig {
        default_minimum_trust: map_trust_level(
            config.governance.policy.tool_access.default_minimum_trust,
        ),
        cel_allow_if: config.governance.policy.tool_access.cel_allow_if.clone(),
        rules,
    }
}
