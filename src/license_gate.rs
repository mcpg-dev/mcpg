//! License gate at boot and reload.
//!
//! The gateway resolves an offline claims envelope — the configured
//! `license:` token, or the built-in community tier — and refuses a config
//! whose `plugins[]` contain entitlement-gated plugins, or whose blocks turn
//! on a feature-gated surface of the embedded authorization server
//! (interactive sign-in: `sso.interactive_login`; DPoP: `oauth.dpop`; rich
//! authorization requests: `oauth.rich_authorization`), that the envelope
//! does not admit. `license.non_production_use` loads them anyway under the
//! license's free non-production grant, loudly.
//!
//! Two halves defer to the control plane, each only where the control plane
//! checks: plugins on a CP-attached gateway, which the plugin-set bind admits;
//! config surfaces on a config the managed-cloud platform rendered, which its
//! publish guard admitted. Every other config — standalone, attached to a
//! self-hosted control plane, or carrying a `gateway.control_plane` block the
//! binary ignores — has its surfaces checked here.

use anyhow::{Context, bail};
use mcpg_control_plane_license::license::{
    self, FEATURE_DPOP, FEATURE_INTERACTIVE_LOGIN, FEATURE_RICH_AUTHORIZATION, LicenseClaims,
    is_entitlement_gated, plugin_load_violation, verify_license,
};

use crate::config::{AppConfig, LicenseConfig};

/// The `aud` claim this binary verifies against. Issued tokens carry
/// both `mcpg-cp` and `mcpg-gateway`.
const GATEWAY_AUDIENCE: &str = "mcpg-gateway";

/// The config surfaces a license feature withholds, as
/// `(feature, config path of the block)`. A block counts only when it turns
/// its surface on: `dpop` with `enabled: true`, `authorization_details` with
/// at least one type. A present block that leaves it off needs no feature.
pub fn licensed_config_surfaces(config: &AppConfig) -> Vec<(&'static str, String)> {
    const SERVER: &str = "governance.access.authorization_server";
    let Some(ref server) = config.governance.access.authorization_server else {
        return Vec::new();
    };
    let mut surfaces: Vec<(&'static str, String)> = server
        .trusted_idps
        .iter()
        .filter(|idp| idp.login.is_some())
        .map(|idp| {
            (
                FEATURE_INTERACTIVE_LOGIN,
                format!("{SERVER}.trusted_idps[`{}`].login", idp.issuer),
            )
        })
        .collect();
    if server.interactive.is_some() {
        surfaces.push((FEATURE_INTERACTIVE_LOGIN, format!("{SERVER}.interactive")));
    }
    if server.dpop.enabled {
        surfaces.push((FEATURE_DPOP, format!("{SERVER}.dpop")));
    }
    if server.authorization_details.enabled() {
        surfaces.push((
            FEATURE_RICH_AUTHORIZATION,
            format!("{SERVER}.authorization_details"),
        ));
    }
    surfaces
}

/// Whether the control plane admits this gateway's plugins: an attached
/// gateway runs the plugin set its bind checked. A binary built without
/// `cp-attached` ignores the block and never binds.
fn control_plane_binds_plugins(config: &AppConfig) -> bool {
    cfg!(feature = "cp-attached") && config.gateway.control_plane.is_some()
}

/// Whether this config carries the stamp the managed-cloud provisioner puts on
/// every render (`gateway.control_plane` and the placement provenance); the
/// platform renders only a config its publish guard admitted. The stamp is
/// taken on trust, not verified.
fn platform_rendered(config: &AppConfig) -> bool {
    let provenance = &config.cloud.provenance;
    control_plane_binds_plugins(config)
        && provenance.cluster_id.is_some()
        && provenance.namespace.is_some()
}

/// Refuses (with a remediation-bearing error) a config whose `plugins[]`
/// include entitlement-gated plugins, or whose blocks turn on feature-gated
/// surfaces, that the resolved license envelope does not admit. Runs at boot
/// and on every reload.
pub fn enforce_license_gate(config: &AppConfig) -> anyhow::Result<()> {
    // Gate on the artifact's manifest id (`ref`), not the operator
    // alias: the loader separately asserts descriptor.id == ref.
    let gated: Vec<&str> = if control_plane_binds_plugins(config) {
        Vec::new()
    } else {
        config
            .plugins
            .iter()
            .filter(|entry| !entry.disabled)
            .map(|entry| entry.r#ref.as_deref().unwrap_or(entry.id.as_str()))
            .filter(|id| is_entitlement_gated(id))
            .collect()
    };
    let surfaces = if platform_rendered(config) {
        Vec::new()
    } else {
        licensed_config_surfaces(config)
    };
    if gated.is_empty() && surfaces.is_empty() {
        return Ok(());
    }

    if config.license.non_production_use {
        let features: Vec<String> = surfaces
            .iter()
            .map(|(feature, path)| format!("{path} ({feature})"))
            .collect();
        tracing::warn!(
            plugins = ?gated,
            features = ?features,
            "entitlement-gated plugins and features loaded under their license's \
             non-production grant (license.non_production_use: true); production use \
             requires an entitling license token"
        );
        return Ok(());
    }

    let claims = resolve_claims(&config.license)?;
    let mut violations: Vec<String> = gated
        .iter()
        .filter_map(|id| plugin_load_violation(&claims, id).map(|v| v.to_string()))
        .collect();
    violations.extend(
        surfaces
            .iter()
            .filter(|(feature, _)| !claims.has_feature(feature))
            .map(|(feature, path)| {
                format!("{path} requires the `{feature}` plan feature, which this license does not grant")
            }),
    );
    if violations.is_empty() {
        return Ok(());
    }
    bail!(
        "license gate: plan `{}` does not license {} configured item(s):\n  - {}\n\
         Install an entitling license (`license.token` / `license.token_file` + \
         `license.pubkey_pem`), declare a non-production deployment \
         (`license.non_production_use: true`), or remove them. \
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

    /// A token signed by a fresh issuer key for `plan`, and the `license:`
    /// block that trusts that key.
    fn license_yaml_for(plan: &str) -> String {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use jsonwebtoken::{EncodingKey, Header};

        let signing = SigningKey::generate(&mut rand::rng());
        let pem = signing
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let der = signing.to_pkcs8_der().unwrap();

        let mut claims = LicenseClaims::community(GATEWAY_AUDIENCE);
        claims.exp = chrono::Utc::now().timestamp() + 3600;
        let (entitlements, quotas) = license::plan_envelope(plan);
        claims.plugin_entitlements = entitlements;
        claims.quotas = quotas;
        claims.features = license::features_for(plan);
        claims.plan = plan.into();

        let token = jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_der(der.as_bytes()),
        )
        .unwrap();

        format!(
            "license:\n  token: {token}\n  pubkey_pem: |\n{}",
            pem.lines()
                .map(|l| format!("    {l}\n"))
                .collect::<String>()
        )
    }

    #[test]
    fn free_plugins_pass_unlicensed() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.http", "dev.mcpg.transform.jsonata"], "");
        assert!(enforce_license_gate(&cfg).is_ok());
    }

    #[test]
    fn gated_plugin_refuses_without_a_license() {
        let cfg = config_with_plugins(&["dev.mcpg.payment.ucp"], "");
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("payment.ucp"), "{err}");
        assert!(err.contains("non_production_use"), "{err}");
    }

    #[test]
    fn alias_plus_ref_is_gated_on_the_manifest_id() {
        let yaml = "plugins:\n  - id: my-sso\n    ref: dev.mcpg.identity.saml\n    class: identity_provider\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_license_gate(&cfg).is_err());
    }

    #[test]
    fn non_production_declaration_loads_gated_plugins() {
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml"],
            "license:\n  non_production_use: true\n",
        );
        assert!(enforce_license_gate(&cfg).is_ok());
    }

    #[test]
    fn disabled_entries_and_third_party_ids_are_ignored() {
        let yaml = "plugins:\n  - id: dev.mcpg.cluster.redis\n    class: cluster\n    source: { path: /tmp/x.so }\n    disabled: true\n  - id: acme.payment.custom\n    class: payment\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_license_gate(&cfg).is_ok());
    }

    /// The plugin-set bind admits an attached gateway's plugins; a binary
    /// that ignores the block gates them itself.
    #[test]
    fn cp_attached_configs_skip_the_plugin_gate() {
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n",
        );
        assert!(cfg.gateway.control_plane.is_some());
        assert_eq!(
            enforce_license_gate(&cfg).is_ok(),
            cfg!(feature = "cp-attached")
        );
    }

    #[test]
    fn entitling_token_admits_and_lesser_token_refuses() {
        let license_yaml = license_yaml_for("team");
        // Team licenses saml + cluster...
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml", "dev.mcpg.cluster.redis"],
            &license_yaml,
        );
        assert!(enforce_license_gate(&cfg).is_ok());
        // ...but not kerberos (enterprise-only feature).
        let cfg = config_with_plugins(&["dev.mcpg.identity.kerberos"], &license_yaml);
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("sso.kerberos"), "{err}");
    }

    #[test]
    fn garbage_token_refuses_boot_even_for_free_configs_with_gated_entries() {
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            "license:\n  token: not-a-jwt\n  pubkey_pem: also-not-a-key\n",
        );
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("pubkey_pem"), "{err}");
    }

    /// An authorization server with interactive sign-in, parsed without
    /// validation: the gate reads the blocks, not their contents.
    fn interactive_login_config(extra: &str) -> AppConfig {
        let yaml = format!(
            "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
             signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
             - issuer: https://acme.okta.com\n          login:\n            client_id: agent\n        \
             - issuer: https://other.example.com\n      interactive: {{}}\n{extra}"
        );
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    /// Interactive sign-in is enterprise-only: the community envelope and a
    /// team license refuse to boot with it and name both blocks and the
    /// feature; an enterprise license or the non-production grant admit it.
    #[test]
    fn interactive_login_needs_its_license_feature() {
        let surfaces = licensed_config_surfaces(&interactive_login_config(""));
        assert_eq!(
            surfaces,
            vec![
                (
                    FEATURE_INTERACTIVE_LOGIN,
                    "governance.access.authorization_server.trusted_idps[`https://acme.okta.com`].login"
                        .to_owned()
                ),
                (
                    FEATURE_INTERACTIVE_LOGIN,
                    "governance.access.authorization_server.interactive".to_owned()
                ),
            ]
        );

        for license_yaml in [String::new(), license_yaml_for("team")] {
            let err = enforce_license_gate(&interactive_login_config(&license_yaml))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("2 configured item(s)")
                    && err.contains("trusted_idps[`https://acme.okta.com`].login requires")
                    && err.contains("authorization_server.interactive requires")
                    && err.contains("`sso.interactive_login`")
                    && err.contains("non_production_use"),
                "{err}"
            );
        }
        enforce_license_gate(&interactive_login_config(&license_yaml_for("enterprise")))
            .expect("enterprise licenses interactive login");
        enforce_license_gate(&interactive_login_config(
            "license:\n  non_production_use: true\n",
        ))
        .expect("the non-production grant admits interactive login");
    }

    /// A `gateway.control_plane` block alone does not lift the surface gate:
    /// a self-hosted control plane never sees the gateway's local config.
    /// Only a config the platform rendered (the block plus its placement
    /// provenance) defers to the publish guard that admitted it.
    #[test]
    fn only_a_platform_rendered_config_defers_interactive_login_to_the_control_plane() {
        const ATTACHED: &str = "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n    \
                                enrollment_url: http://127.0.0.1:9\n";
        const PROVENANCE: &str =
            "cloud:\n  provenance:\n    cluster_id: cell-1\n    namespace: tenant-acme\n";

        let attached = interactive_login_config(ATTACHED);
        assert!(attached.gateway.control_plane.is_some());
        let err = enforce_license_gate(&attached)
            .expect_err("an attached gateway's local login block needs the feature")
            .to_string();
        assert!(
            err.contains("`sso.interactive_login`") && err.contains("2 configured item(s)"),
            "{err}"
        );
        enforce_license_gate(&interactive_login_config(&format!(
            "{ATTACHED}{}",
            license_yaml_for("enterprise")
        )))
        .expect("a local enterprise license admits an attached gateway's login block");

        let stamped_only = interactive_login_config(PROVENANCE);
        assert!(stamped_only.cloud.provenance.cluster_id.is_some());
        enforce_license_gate(&stamped_only)
            .expect_err("provenance without a control plane is not a platform render");

        let rendered = interactive_login_config(&format!("{ATTACHED}{PROVENANCE}"));
        assert_eq!(
            enforce_license_gate(&rendered).is_ok(),
            cfg!(feature = "cp-attached"),
            "a platform render passed the publish guard"
        );
    }

    /// An EMA-only authorization server with `extra` under it, parsed without
    /// validation: the gate reads the blocks, not their contents.
    fn authorization_server_config(server_extra: &str, extra: &str) -> AppConfig {
        let yaml = format!(
            "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
             signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
             - issuer: https://acme.okta.com\n{server_extra}{extra}"
        );
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    const DPOP_ON: &str = "      dpop:\n        enabled: true\n        required: true\n";
    const DETAILS_ON: &str = "      authorization_details:\n        types:\n          \
                              - type: mcp_tool\n            actions: [\"tools/call\"]\n";

    fn constrained_tokens_config(extra: &str) -> AppConfig {
        authorization_server_config(&format!("{DPOP_ON}{DETAILS_ON}"), extra)
    }

    /// DPoP and rich authorization requests are enterprise-only: the
    /// community envelope and a team license refuse to boot with either
    /// turned on and name the block, the feature and the plan; an enterprise
    /// license or the non-production grant admit both.
    #[test]
    fn dpop_and_rich_authorization_need_their_license_features() {
        assert_eq!(
            licensed_config_surfaces(&constrained_tokens_config("")),
            vec![
                (
                    FEATURE_DPOP,
                    "governance.access.authorization_server.dpop".to_owned()
                ),
                (
                    FEATURE_RICH_AUTHORIZATION,
                    "governance.access.authorization_server.authorization_details".to_owned()
                ),
            ]
        );

        for (plan, license_yaml) in [
            ("community", String::new()),
            ("team", license_yaml_for("team")),
        ] {
            let err = enforce_license_gate(&constrained_tokens_config(&license_yaml))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("plan `{plan}`"))
                    && err.contains("2 configured item(s)")
                    && err.contains(
                        "governance.access.authorization_server.dpop requires the `oauth.dpop` \
                         plan feature"
                    )
                    && err.contains(
                        "governance.access.authorization_server.authorization_details requires \
                         the `oauth.rich_authorization` plan feature"
                    )
                    && err.contains("non_production_use"),
                "{err}"
            );

            let dpop_only = authorization_server_config(DPOP_ON, &license_yaml);
            let err = enforce_license_gate(&dpop_only).unwrap_err().to_string();
            assert!(
                err.contains("1 configured item(s)")
                    && err.contains("`oauth.dpop`")
                    && !err.contains("oauth.rich_authorization"),
                "{err}"
            );
            let details_only = authorization_server_config(DETAILS_ON, &license_yaml);
            let err = enforce_license_gate(&details_only).unwrap_err().to_string();
            assert!(
                err.contains("1 configured item(s)")
                    && err.contains("`oauth.rich_authorization`")
                    && !err.contains("oauth.dpop"),
                "{err}"
            );
        }
        enforce_license_gate(&constrained_tokens_config(&license_yaml_for("enterprise")))
            .expect("enterprise licenses DPoP and rich authorization requests");
        enforce_license_gate(&constrained_tokens_config(
            "license:\n  non_production_use: true\n",
        ))
        .expect("the non-production grant admits DPoP and rich authorization requests");
    }

    /// Every gated block of one server is named in one refusal, whichever
    /// feature it needs.
    #[test]
    fn one_refusal_names_every_authorization_server_feature() {
        let every = format!("{DPOP_ON}{DETAILS_ON}      interactive: {{}}\n");
        let err = enforce_license_gate(&authorization_server_config(&every, ""))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("3 configured item(s)")
                && err.contains("`sso.interactive_login`")
                && err.contains("`oauth.dpop`")
                && err.contains("`oauth.rich_authorization`"),
            "{err}"
        );
    }

    /// A present block that leaves its surface off needs no feature: `dpop`
    /// with `enabled: false` whatever its other keys, and
    /// `authorization_details` without a type.
    #[test]
    fn disabled_dpop_and_authorization_details_blocks_need_no_feature() {
        for server_extra in [
            "      dpop:\n        enabled: false\n        nonce: always\n        \
             proof_max_age_secs: 30\n        allowed_algs: [ES256]\n",
            "      dpop: {}\n",
            "      authorization_details:\n        max_entries: 8\n",
            "      authorization_details:\n        types: []\n        max_entries: 4\n",
            "      dpop:\n        enabled: false\n      authorization_details:\n        types: []\n",
        ] {
            let cfg = authorization_server_config(server_extra, "");
            assert!(licensed_config_surfaces(&cfg).is_empty(), "{server_extra}");
            enforce_license_gate(&cfg).expect(server_extra);
        }
    }

    /// As for interactive sign-in, a `gateway.control_plane` block alone does
    /// not lift the gate; only a config the platform rendered defers to the
    /// publish guard that admitted it.
    #[test]
    fn only_a_platform_rendered_config_defers_dpop_and_rich_authorization_to_the_control_plane() {
        const ATTACHED: &str = "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n    \
                                enrollment_url: http://127.0.0.1:9\n";
        const PROVENANCE: &str =
            "cloud:\n  provenance:\n    cluster_id: cell-1\n    namespace: tenant-acme\n";

        let attached = constrained_tokens_config(ATTACHED);
        assert!(attached.gateway.control_plane.is_some());
        let err = enforce_license_gate(&attached)
            .expect_err("an attached gateway's local blocks need the features")
            .to_string();
        assert!(
            err.contains("`oauth.dpop`")
                && err.contains("`oauth.rich_authorization`")
                && err.contains("2 configured item(s)"),
            "{err}"
        );
        enforce_license_gate(&constrained_tokens_config(&format!(
            "{ATTACHED}{}",
            license_yaml_for("enterprise")
        )))
        .expect("a local enterprise license admits an attached gateway's blocks");

        enforce_license_gate(&constrained_tokens_config(PROVENANCE))
            .expect_err("provenance without a control plane is not a platform render");

        let rendered = constrained_tokens_config(&format!("{ATTACHED}{PROVENANCE}"));
        assert_eq!(
            enforce_license_gate(&rendered).is_ok(),
            cfg!(feature = "cp-attached"),
            "a platform render passed the publish guard"
        );
    }

    /// An EMA-only server (no login block, no interactive block) needs no
    /// feature and boots on the community envelope.
    #[test]
    fn an_ema_only_authorization_server_needs_no_feature() {
        let yaml = "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
                    signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
                    - issuer: https://acme.okta.com\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(licensed_config_surfaces(&cfg).is_empty());
        enforce_license_gate(&cfg).expect("EMA alone is not gated");
    }
}
