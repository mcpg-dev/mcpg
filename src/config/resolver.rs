//! Config-time string resolution.
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
//! 3. **`${secret.NAME}` interpolation** — sync, from the mounted
//!    directory behind `gateway.secrets.dir`. Runs last, so a
//!    substituted value is final: a tenant-authored secret can never
//!    be re-read as an `env://` / `file://` provider URI or an
//!    `${env.X}` reference, which would turn the secret store into a
//!    channel for reading the process environment or the filesystem.
//!
//! The passes are complementary. CEL can interpolate inside a
//! larger string (`"Bearer ${env.TOKEN}"`, `"Bearer ${secret.TOKEN}"`);
//! secret URIs must occupy the entire string (the field's value *is*
//! the URI). An operator can use any of them:
//!
//! ```yaml
//! state:
//!   url: ${env.REDIS_URL}                 # CEL only
//!   password: vault://secret/redis#pw      # URI only
//!   key_prefix: "mcpg:${env.MCPG_ENV}"    # CEL inline (no URI)
//!   token: "Bearer ${secret.API_TOKEN}"   # mounted secret inline
//! ```

use anyhow::{Context, Result};
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::secret_resolver::{ResolveReport, resolve_single_secret_ref};
use serde_json::Value;

use super::secrets::SecretsSource;

/// Resolve a single config-time string field through every phase.
///
/// Returns the post-resolution value. Pass-through for plain
/// literals, errors on missing `${env.X}` env vars, failed
/// secret-provider lookups, or unresolvable `${secret.NAME}` refs.
pub async fn resolve_config_string(
    input: &str,
    registry: &PluginRegistry,
    secrets: &SecretsSource,
) -> Result<String> {
    let after_cel = crate::runtime::expr::resolve_env_in_string(input)
        .with_context(|| format!("CEL env-var resolution failed for `{input}`"))?;
    let after_uri = match resolve_single_secret_ref(&after_cel, registry)
        .await
        .with_context(|| format!("secret-provider resolution failed for `{after_cel}`"))?
    {
        Some(resolved) => resolved,
        None => after_cel,
    };
    apply_secrets_to_string(&after_uri, secrets)
}

/// Resolve every string leaf inside `value` through every phase,
/// mutating in place: env CEL pass, then the secret-URI pass via the
/// bound `SecretProvider` plugins, then `${secret.NAME}` from the
/// mounted directory.
///
/// Returns the [`ResolveReport`] from the secret-URI pass so callers
/// can surface per-scheme audit detail (counts of expansions,
/// schemes skipped because no provider was bound). Errors on CEL
/// failure, any secret-provider failure, or a `${secret.NAME}` that
/// cannot be read.
pub async fn resolve_config_value(
    value: &mut Value,
    registry: &PluginRegistry,
    secrets: &SecretsSource,
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
    apply_secrets_to_value(value, secrets)?;
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
    for_each_string_leaf(value, &mut |s| {
        crate::runtime::expr::resolve_env_in_string(s)
            .with_context(|| format!("CEL env-var resolution failed for `{s}`"))
    })
}

/// Walk a JSON value and replace every `${secret.NAME}` in its string
/// leaves with the mounted value. Errors name the reference, never a
/// value.
fn apply_secrets_to_value(value: &mut Value, secrets: &SecretsSource) -> Result<()> {
    for_each_string_leaf(value, &mut |s| apply_secrets_to_string(s, secrets))
}

/// `${secret.NAME}` substitution for one string. The error context
/// carries the reference (`${secret.NAME}` is safe to log); the
/// surrounding string is omitted because after the earlier passes it
/// may already hold resolved values.
fn apply_secrets_to_string(s: &str, secrets: &SecretsSource) -> Result<String> {
    crate::runtime::expr::resolve_secret_in_string(s, &|name| secrets.lookup(name))
        .context("mounted-secret resolution failed")
}

fn for_each_string_leaf(
    value: &mut Value,
    f: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<()> {
    match value {
        Value::String(s) => {
            *s = f(s)?;
            Ok(())
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                for_each_string_leaf(v, f)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                for_each_string_leaf(v, f)?;
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

    fn secrets_in(dir: &std::path::Path) -> SecretsSource {
        SecretsSource::from_config(&crate::config::SecretsConfig {
            dir: Some(dir.to_path_buf()),
            ..Default::default()
        })
    }

    #[test]
    fn secrets_walker_replaces_refs_in_nested_strings_and_records_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("API_TOKEN"), "tok-123").unwrap();
        std::fs::write(dir.path().join("HOST"), "db.internal").unwrap();
        let secrets = secrets_in(dir.path());
        let mut v = serde_json::json!({
            "auth": "Bearer ${secret.API_TOKEN}",
            "nested": { "urls": ["https://${secret.HOST}/a", "https://${secret.HOST}/b"] },
            "literal": "no-secrets-here",
            "request_time": "${arguments.x}",
        });
        apply_secrets_to_value(&mut v, &secrets).unwrap();
        assert_eq!(v["auth"], "Bearer tok-123");
        assert_eq!(v["nested"]["urls"][0], "https://db.internal/a");
        assert_eq!(v["nested"]["urls"][1], "https://db.internal/b");
        assert_eq!(v["literal"], "no-secrets-here");
        assert_eq!(v["request_time"], "${arguments.x}");
        assert_eq!(secrets.referenced_keys(), ["API_TOKEN", "HOST"]);
        assert_eq!(secrets.digest().len(), 64);
    }

    #[test]
    fn secrets_walker_error_names_the_key_and_no_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PRESENT"), "s3cret-value").unwrap();
        let secrets = secrets_in(dir.path());
        let mut v = serde_json::json!({
            "a": "${secret.PRESENT}",
            "b": "${secret.MISSING}",
        });
        let err = format!(
            "{:#}",
            apply_secrets_to_value(&mut v, &secrets).unwrap_err()
        );
        assert!(err.contains("${secret.MISSING}"), "{err}");
        assert!(!err.contains("s3cret-value"), "{err}");
    }

    #[test]
    fn secrets_walker_without_dir_says_so() {
        let mut v = serde_json::json!({ "a": "${secret.API_TOKEN}" });
        let err = format!(
            "{:#}",
            apply_secrets_to_value(&mut v, &SecretsSource::unconfigured()).unwrap_err()
        );
        assert!(err.contains("gateway.secrets.dir"), "{err}");
        assert!(err.contains("${secret.API_TOKEN}"), "{err}");
    }

    #[tokio::test]
    async fn secret_values_are_never_reinterpreted_by_the_earlier_passes() {
        // SAFETY: test-only, single-threaded env manipulation
        unsafe {
            std::env::set_var("MCPGTEST_PLATFORM_TOKEN", "platform-only");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("AS_URI"), "env://MCPGTEST_PLATFORM_TOKEN").unwrap();
        std::fs::write(dir.path().join("AS_CEL"), "${env.MCPGTEST_PLATFORM_TOKEN}").unwrap();
        let secrets = secrets_in(dir.path());

        let mut registry = PluginRegistry::new();
        registry
            .register_secret_provider(
                crate::builtins::secret_env::EnvSecretProvider::new(),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .unwrap();
        registry
            .bind_secret_scheme("env", "dev.mcpg.builtin.secret.env")
            .unwrap();

        let mut v = serde_json::json!({
            "uri": "${secret.AS_URI}",
            "cel": "${secret.AS_CEL}",
            "direct": "env://MCPGTEST_PLATFORM_TOKEN",
        });
        resolve_config_value(&mut v, &registry, &secrets)
            .await
            .unwrap();
        assert_eq!(
            v["direct"], "platform-only",
            "operator-written URI resolves"
        );
        assert_eq!(v["uri"], "env://MCPGTEST_PLATFORM_TOKEN");
        assert_eq!(v["cel"], "${env.MCPGTEST_PLATFORM_TOKEN}");
        assert_eq!(
            resolve_config_string("${secret.AS_URI}", &registry, &secrets)
                .await
                .unwrap(),
            "env://MCPGTEST_PLATFORM_TOKEN"
        );
        unsafe {
            std::env::remove_var("MCPGTEST_PLATFORM_TOKEN");
        }
    }
}
