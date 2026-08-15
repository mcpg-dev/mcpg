//! Plugin registration policy enforcement and the registry-wide
//! revocation list loader.

use super::*;

/// Build `NativeVerifyOptions` from the operator's trust policy
/// Run the registered `policy_engine` chain at decision_point
/// `plugin.lifecycle.register` against a freshly-loaded native
/// cdylib. Builds the plugin's authoritative manifest by peeking
/// the cdylib (one make+drop on whichever vtable is populated),
/// then dispatches through the chain. On Deny, returns an error
/// that surfaces to the operator at boot — the policy reason +
/// engine name are preserved.
///
/// Empty chain (no policy_engines registered yet) → no
/// enforcement; same shape as the per-request chain.
pub(crate) async fn enforce_plugin_registration_policy(
    registry: &mcpg_plugin_host::PluginRegistry,
    loaded: &std::sync::Arc<mcpg_plugin_host::native_loader::LoadedNativePlugin>,
    plugin_cfg: serde_json::Value,
    operator_id: &str,
) -> anyhow::Result<()> {
    let manifest = mcpg_plugin_host::native_loader::peek_manifest_from_loaded(loaded, plugin_cfg)
        .with_context(|| {
        format!("registration policy: peeking manifest from native plugin '{operator_id}' failed")
    })?;
    match registry
        .evaluate_plugin_registration_policy(&manifest)
        .await
    {
        mcpg_plugin_host::PolicyChainOutcome::Deny {
            engine,
            reason,
            policy_version,
        } => {
            metrics::counter!(
                "mcpg_plugin_registration_denials_total",
                "engine" => engine.clone(),
                "plugin_id" => manifest.id.clone(),
            )
            .increment(1);
            tracing::error!(
                plugin_id = %manifest.id,
                engine = %engine,
                policy_version = %policy_version,
                reason = %reason,
                "plugin registration denied by policy_engine chain"
            );
            anyhow::bail!(
                "plugin '{}' registration denied by policy `{engine}` (policy_version={policy_version}): {reason}",
                manifest.id,
            );
        }
        mcpg_plugin_host::PolicyChainOutcome::Allow {
            engine,
            policy_version,
        } => {
            tracing::info!(
                plugin_id = %manifest.id,
                engine = %engine,
                policy_version = %policy_version,
                "plugin registration allowed by policy_engine chain"
            );
            Ok(())
        }
        mcpg_plugin_host::PolicyChainOutcome::NotApplicable => Ok(()),
    }
}

/// Read the operator's revocation list (if configured) once at
/// gateway startup and parse it into the indexed
/// [`mcpg_plugin_host::revocation::RevocationList`] form.
///
/// `None` is returned when no path is configured. A configured
/// path that fails to load / parse is a hard error: the gateway
/// won't boot with a broken revocation list because the operator
/// asked for one — silently degrading to "no revocation
/// enforced" would be a security regression.
pub(crate) fn load_revocation_list(
    plugin_registry: &crate::config::PluginRegistryConfig,
) -> anyhow::Result<Option<mcpg_plugin_host::revocation::RevocationList>> {
    let Some(path_str) = plugin_registry.revocation_list_path.as_deref() else {
        return Ok(None);
    };
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let list =
        mcpg_plugin_host::revocation::RevocationList::from_file_path(std::path::Path::new(trimmed))
            .with_context(|| {
                format!(
                    "loading plugin revocation list at '{trimmed}' \
                 (gateway.plugin_registry.revocation_list_path)"
                )
            })?;
    tracing::info!(
        path = %trimmed,
        entries = list.len(),
        "plugin revocation list loaded"
    );
    Ok(Some(list))
}
