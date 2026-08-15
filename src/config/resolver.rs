//! Two-phase config-time string resolution.
//!
//! Every operator-supplied string field that may carry a credential
//! or env-var interpolation is resolved through the helpers in this
//! module. The resolution is deterministic and applies in this order:
//!
//! 1. **CEL `${env.X}` interpolation** — sync, env-only at config
//!    load. Other CEL variables (`${arguments.x}`, `${context.x}`,
//!    `${steps.X}`) are *not* in scope at this phase and pass
//!    through untouched so the binding/runtime CEL engine resolves
//!    them per-request.
//! 2. **Secret-provider URI resolution** — async, registry-driven.
//!    If the post-CEL string is a `scheme://...` URI and the scheme
//!    is bound to a `SecretProvider` plugin (`env`, `file`, `vault`,
//!    `aws-sm`, …), the provider fetches the secret and the field's
//!    value is replaced.
//!
//! The two passes are complementary. CEL can interpolate inside a
//! larger string (`"Bearer ${env.TOKEN}"`); secret URIs must occupy
//! the entire string (the field's value *is* the URI). Both spelled
//! correctly are valid; an operator can use either or both:
//!
//! ```yaml
//! state:
//!   url: ${env.REDIS_URL}                 # CEL only
//!   password: vault://secret/redis#pw      # URI only
//!   key_prefix: "mcpg:${env.MCPG_ENV}"    # CEL inline (no URI)
//! ```

use anyhow::{Context, Result};
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::secret_resolver::{ResolveReport, resolve_single_secret_ref};
use serde_json::Value;

/// Resolve a single config-time string field through both phases.
///
/// Returns the post-resolution value. Pass-through for plain
/// literals, errors on missing `${env.X}` env vars or failed
/// secret-provider lookups.
pub async fn resolve_config_string(input: &str, registry: &PluginRegistry) -> Result<String> {
    let after_cel = crate::runtime::expr::resolve_env_in_string(input)
        .with_context(|| format!("CEL env-var resolution failed for `{input}`"))?;
    if let Some(resolved) = resolve_single_secret_ref(&after_cel, registry)
        .await
        .with_context(|| format!("secret-provider resolution failed for `{after_cel}`"))?
    {
        Ok(resolved)
    } else {
        Ok(after_cel)
    }
}

/// Resolve every string leaf inside `value` through both phases,
/// mutating in place. CEL pass first (env-only at config load),
/// then secret-URI pass via the bound `SecretProvider` plugins.
///
/// Returns the [`ResolveReport`] from the secret-URI pass so callers
/// can surface per-scheme audit detail (counts of expansions,
/// schemes skipped because no provider was bound). Errors on CEL
/// failure or any secret-provider failure.
pub async fn resolve_config_value(
    value: &mut Value,
    registry: &PluginRegistry,
) -> Result<ResolveReport> {
    apply_cel_to_value(value)?;
    let report = mcpg_plugin_host::secret_resolver::resolve_secret_refs(value, registry).await;
    if !report.is_ok() {
        let failures = report
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.secret_ref, f.error))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("secret-provider resolution failed: {failures}");
    }
    Ok(report)
}

/// Collect the env-var names referenced by `${env.NAME}` (CEL interpolation)
/// and `env://NAME` (secret-ref) string forms anywhere in `value`. The opt-in
/// post-boot env scrub (`server.scrub_process_env_after_boot`) uses this on the
/// ORIGINAL (pre-resolution) config to learn which process-env vars carried
/// config-origin secrets, so it can remove them from the live environment after
/// resolution — without disturbing system vars the config never names.
pub fn collect_env_var_names(value: &Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::String(s) => scan_env_names(s, out),
        Value::Array(items) => items.iter().for_each(|v| collect_env_var_names(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_env_var_names(v, out)),
        _ => {}
    }
}

/// Extract `${env.NAME}` and `env://NAME` references from one string.
fn scan_env_names(s: &str, out: &mut std::collections::BTreeSet<String>) {
    let mut rest = s;
    while let Some(i) = rest.find("${env.") {
        let after = &rest[i + "${env.".len()..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                if !name.is_empty() {
                    out.insert(name.to_owned());
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    let mut rest = s;
    while let Some(i) = rest.find("env://") {
        let after = &rest[i + "env://".len()..];
        let name: String = after
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '#' | '/' | '"' | '\'' | '}' | ')'))
            .collect();
        let consumed = "env://".len() + name.len();
        if !name.is_empty() {
            out.insert(name);
        }
        rest = &rest[(i + consumed).min(rest.len())..];
    }
}

/// Walk a JSON value and apply CEL `${env.X}` resolution to every
/// string leaf in place. Mirrors the host crate's
/// [`mcpg_plugin_host::secret_resolver::resolve_secret_refs`] walker
/// but for the CEL pass (which is sync and env-only at this phase).
fn apply_cel_to_value(value: &mut Value) -> Result<()> {
    match value {
        Value::String(s) => {
            *s = crate::runtime::expr::resolve_env_in_string(s)
                .with_context(|| format!("CEL env-var resolution failed for `{s}`"))?;
            Ok(())
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                apply_cel_to_value(v)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                apply_cel_to_value(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_env_var_names_finds_both_forms() {
        let cfg = serde_json::json!({
            "auth_token": "${env.STRIPE_KEY}",
            "nested": { "url": "https://x/${env.HOST}:443", "sk": "env://SIGNING_SECRET" },
            "list": ["cred://vault/x", "env://API_KEY#field", "plain"],
            "interp": "Bearer ${env.HOOK_TOKEN}",
        });
        let mut out = std::collections::BTreeSet::new();
        collect_env_var_names(&cfg, &mut out);
        assert!(out.contains("STRIPE_KEY"));
        assert!(out.contains("HOST"));
        assert!(out.contains("HOOK_TOKEN"));
        assert!(out.contains("SIGNING_SECRET"));
        assert!(out.contains("API_KEY"), "env:// name stops at the # anchor");
        assert!(
            !out.iter().any(|n| n.contains("vault")),
            "cred:// is a different scheme"
        );
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn cel_walker_replaces_env_in_nested_strings() {
        // SAFETY: test-only, single-threaded
        unsafe {
            std::env::set_var("MCPGTEST_HOST", "prod.example.com");
        }
        let mut v = serde_json::json!({
            "url": "https://${env.MCPGTEST_HOST}/api",
            "headers": ["X-Host: ${env.MCPGTEST_HOST}"],
            "literal": "no-vars-here",
        });
        apply_cel_to_value(&mut v).unwrap();
        assert_eq!(v["url"], "https://prod.example.com/api");
        assert_eq!(v["headers"][0], "X-Host: prod.example.com");
        assert_eq!(v["literal"], "no-vars-here");
        unsafe {
            std::env::remove_var("MCPGTEST_HOST");
        }
    }

    #[test]
    fn cel_walker_errors_on_missing_var() {
        let mut v = serde_json::json!({
            "url": "${env.MCPG_DOES_NOT_EXIST_X42}",
        });
        let err = apply_cel_to_value(&mut v).unwrap_err();
        assert!(format!("{err:#}").contains("MCPG_DOES_NOT_EXIST_X42"));
    }

    #[test]
    fn cel_walker_leaves_request_time_vars_untouched() {
        let mut v = serde_json::json!({
            "url": "/${arguments.path}",
            "header": "${context.principal_id}",
        });
        apply_cel_to_value(&mut v).unwrap();
        assert_eq!(v["url"], "/${arguments.path}");
        assert_eq!(v["header"], "${context.principal_id}");
    }
}
