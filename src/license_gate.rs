//! Plugin license gate for standalone deployments.
//!
//! The control plane is the authoritative entitlement gate for
//! CP-attached gateways (plugin-set bind refuses unentitled plugins
//! before a config is ever pushed), so those skip this entirely. A
//! standalone gateway instead resolves an offline claims envelope —
//! the configured `license:` token, or the built-in community tier —
//! and refuses to boot when `plugins[]` contains entitlement-gated
//! plugins the envelope does not admit. `license.non_production_use`
//! loads them anyway under the license's free non-production grant,
//! loudly.

use anyhow::{Context, bail};
use mcpg_control_plane_license::license::{
    self, LicenseClaims, is_entitlement_gated, plugin_load_violation, verify_license,
};

use crate::config::{AppConfig, LicenseConfig};

/// The `aud` claim this binary verifies against. Issued tokens carry
/// both `mcpg-cp` and `mcpg-gateway`.
const GATEWAY_AUDIENCE: &str = "mcpg-gateway";

/// Refuses (with a remediation-bearing error) a standalone config whose
/// `plugins[]` include entitlement-gated plugins the resolved license
/// envelope does not admit. Runs at boot and on every reload.
pub fn enforce_plugin_license_gate(config: &AppConfig) -> anyhow::Result<()> {
    if config.gateway.control_plane.is_some() {
        return Ok(());
    }

    // Gate on the artifact's manifest id (`ref`), not the operator
    // alias: the loader separately asserts descriptor.id == ref.
    let gated: Vec<&str> = config
        .plugins
        .iter()
        .filter(|entry| !entry.disabled)
        .map(|entry| entry.r#ref.as_deref().unwrap_or(entry.id.as_str()))
        .filter(|id| is_entitlement_gated(id))
        .collect();
    if gated.is_empty() {
        return Ok(());
    }

    if config.license.non_production_use {
        tracing::warn!(
            plugins = ?gated,
            "entitlement-gated plugins loaded under their license's non-production \
             grant (license.non_production_use: true); production use requires an \
             entitling license token"
        );
        return Ok(());
    }

    let claims = resolve_claims(&config.license)?;
    let violations: Vec<String> = gated
        .iter()
        .filter_map(|id| plugin_load_violation(&claims, id).map(|v| v.to_string()))
        .collect();
    if violations.is_empty() {
        return Ok(());
    }
    bail!(
        "license gate: plan `{}` does not license {} configured plugin(s):\n  - {}\n\
         Install an entitling license (`license.token` / `license.token_file` + \
         `license.pubkey_pem`), declare a non-production deployment \
         (`license.non_production_use: true`), or remove the plugin(s). \
         Licensing: https://mcpg.dev/license",
        claims.plan,
        violations.len(),
        violations.join("\n  - "),
    );
}

/// The claims envelope this deployment runs under: the configured
/// token, verified offline against `pubkey_pem` (any failure refuses
/// boot — a paying install must not silently degrade), or the built-in
/// community tier when no token is configured.
///
/// `pub(crate)` so the usage-reporting gate can consult the same
/// envelope — it suppresses the ping for any non-community / air-gapped /
/// sovereign plan, and treats a resolution error as fail-closed (no ping).
pub(crate) fn resolve_claims(cfg: &LicenseConfig) -> anyhow::Result<LicenseClaims> {
    let inline = cfg
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let file = cfg
        .token_file
        .as_deref()
        .filter(|p| !p.as_os_str().is_empty());

    let token = match (inline, file) {
        (None, None) => {
            if cfg.pubkey_pem.is_some() {
                tracing::warn!(
                    "license.pubkey_pem is set but no license token is configured \
                     (license.token / license.token_file); using the community envelope"
                );
            }
            return Ok(LicenseClaims::community(GATEWAY_AUDIENCE));
        }
        (Some(_), Some(_)) => {
            bail!("both license.token and license.token_file are set — configure exactly one")
        }
        (Some(t), None) => t.to_owned(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading license.token_file `{}`", path.display()))?
            .trim()
            .to_owned(),
    };
    if token.is_empty() {
        bail!("configured license token is empty");
    }

    let Some(pem) = cfg
        .pubkey_pem
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        bail!(
            "a license token is configured but license.pubkey_pem is not — set it to \
             the issuer's Ed25519 public key (`mcpg-license keygen --public-out`)"
        );
    };
    let key = license::verifying_key_from_pem(pem)
        .map_err(|e| anyhow::anyhow!("license.pubkey_pem: {e}"))?;
    verify_license(&token, &key, GATEWAY_AUDIENCE)
        .context("configured license token failed verification; refusing to boot")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_plugins(ids: &[&str], license_yaml: &str) -> AppConfig {
        let plugins: String = ids
            .iter()
            .map(|id| {
                let class = id.split('.').nth(2).unwrap_or("backend");
                format!("  - id: {id}\n    class: {class}\n    source: {{ path: /tmp/x.so }}\n")
            })
            .collect();
        let yaml = format!("plugins:\n{plugins}{license_yaml}");
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    #[test]
    fn free_plugins_pass_unlicensed() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.http", "dev.mcpg.transform.jsonata"], "");
        assert!(enforce_plugin_license_gate(&cfg).is_ok());
    }

    #[test]
    fn gated_plugin_refuses_without_a_license() {
        let cfg = config_with_plugins(&["dev.mcpg.payment.ucp"], "");
        let err = enforce_plugin_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("payment.ucp"), "{err}");
        assert!(err.contains("non_production_use"), "{err}");
    }

    #[test]
    fn alias_plus_ref_is_gated_on_the_manifest_id() {
        let yaml = "plugins:\n  - id: my-sso\n    ref: dev.mcpg.identity.saml\n    class: identity_provider\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_plugin_license_gate(&cfg).is_err());
    }

    #[test]
    fn non_production_declaration_loads_gated_plugins() {
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml"],
            "license:\n  non_production_use: true\n",
        );
        assert!(enforce_plugin_license_gate(&cfg).is_ok());
    }

    #[test]
    fn disabled_entries_and_third_party_ids_are_ignored() {
        let yaml = "plugins:\n  - id: dev.mcpg.cluster.redis\n    class: cluster\n    source: { path: /tmp/x.so }\n    disabled: true\n  - id: acme.payment.custom\n    class: payment\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_plugin_license_gate(&cfg).is_ok());
    }

    #[test]
    fn cp_attached_configs_skip_the_gate() {
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n",
        );
        assert!(enforce_plugin_license_gate(&cfg).is_ok());
    }

    #[test]
    fn entitling_token_admits_and_lesser_token_refuses() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use jsonwebtoken::{EncodingKey, Header};

        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let pem = signing
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let der = signing.to_pkcs8_der().unwrap();

        let mut claims = LicenseClaims::community(GATEWAY_AUDIENCE);
        claims.exp = chrono::Utc::now().timestamp() + 3600;
        let (entitlements, quotas) = license::plan_envelope("team");
        claims.plugin_entitlements = entitlements;
        claims.quotas = quotas;
        claims.features = license::features_for("team");
        claims.plan = "team".into();

        let token = jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_der(der.as_bytes()),
        )
        .unwrap();

        let license_yaml = format!(
            "license:\n  token: {token}\n  pubkey_pem: |\n{}",
            pem.lines()
                .map(|l| format!("    {l}\n"))
                .collect::<String>()
        );
        // Team licenses saml + cluster...
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml", "dev.mcpg.cluster.redis"],
            &license_yaml,
        );
        assert!(enforce_plugin_license_gate(&cfg).is_ok());
        // ...but not kerberos (enterprise-only feature).
        let cfg = config_with_plugins(&["dev.mcpg.identity.kerberos"], &license_yaml);
        let err = enforce_plugin_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("sso.kerberos"), "{err}");
    }

    #[test]
    fn garbage_token_refuses_boot_even_for_free_configs_with_gated_entries() {
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            "license:\n  token: not-a-jwt\n  pubkey_pem: also-not-a-key\n",
        );
        let err = enforce_plugin_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("pubkey_pem"), "{err}");
    }
}
