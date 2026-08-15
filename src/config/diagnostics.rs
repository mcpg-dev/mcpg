//! Boot-time configuration diagnostics.
//!
//! Warnings for configurations that parse, validate, and boot, but cannot
//! behave the way the operator meant. The trust-floor case is the reason
//! this module exists: a binding whose floor no request can clear is
//! filtered out of every `*/list` and rejected on call, and neither the
//! empty list nor the boot log says why.

use tracing::warn;

use super::{AppConfig, TrustLevelConfig};

/// The highest trust tier any request can reach under this config.
///
/// Mirrors `RequestIdentity::trust_level`: `Verified` needs an identity
/// source (embedded EMA authorization server, OIDC/OAuth, JWKS, or an
/// `identity_provider` plugin), `HeaderAsserted` additionally needs
/// `gateway.server.trust_subject_header`, and a gateway with neither can
/// only ever see anonymous callers.
pub fn reachable_trust_ceiling(config: &AppConfig) -> TrustLevelConfig {
    let access = &config.governance.access;
    let verifiable = access.jwks.is_some()
        || access.oidc_oauth.is_some()
        || access.authorization_server.is_some()
        || config
            .plugins
            .iter()
            .any(|entry| entry.class == "identity_provider");

    if verifiable {
        TrustLevelConfig::Verified
    } else if config.gateway.server.trust_subject_header {
        TrustLevelConfig::HeaderAsserted
    } else {
        TrustLevelConfig::Unauthenticated
    }
}

/// Bindings whose `governance.minimum_trust` sits above the trust ceiling
/// the identity posture can produce — each one hidden from every list and
/// rejected on call.
pub fn unreachable_trust_bindings(config: &AppConfig) -> Vec<&str> {
    let ceiling = reachable_trust_ceiling(config);
    config
        .all_bindings()
        .filter(|(_, binding)| binding.governance.minimum_trust > ceiling)
        .map(|(_, binding)| binding.name.as_str())
        .collect()
}

/// How to make an unreachable floor reachable, given what the config
/// already has.
pub fn trust_ceiling_remedy(ceiling: TrustLevelConfig) -> &'static str {
    if ceiling == TrustLevelConfig::Unauthenticated {
        "configure an identity source (governance.access.oidc_oauth / .jwks, or an \
         identity_provider plugin), set gateway.server.trust_subject_header to accept \
         header-asserted identity, or lower the binding's governance.minimum_trust"
    } else {
        "configure an identity source (governance.access.oidc_oauth / .jwks, or an \
         identity_provider plugin), or lower the binding's governance.minimum_trust"
    }
}

/// Boot-side counterpart to [`unreachable_trust_bindings`].
pub fn warn_unreachable_binding_trust(config: &AppConfig) {
    let unreachable = unreachable_trust_bindings(config);
    if unreachable.is_empty() {
        return;
    }
    let ceiling = reachable_trust_ceiling(config);
    warn!(
        bindings = %unreachable.join(", "),
        trust_ceiling = ?ceiling,
        "binding trust floor is unreachable: these capabilities are hidden from every \
         list and rejected on call because no request can reach their \
         governance.minimum_trust — {}",
        trust_ceiling_remedy(ceiling)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsed rather than constructed so the serde defaults under test
    /// (notably the per-binding trust floor) are the real ones.
    fn config(yaml: &str) -> AppConfig {
        serde_yaml::from_str(yaml).expect("test config parses")
    }

    fn unreachable(config: &AppConfig) -> Vec<&str> {
        let ceiling = reachable_trust_ceiling(config);
        config
            .all_bindings()
            .filter(|(_, b)| b.governance.minimum_trust > ceiling)
            .map(|(_, b)| b.name.as_str())
            .collect()
    }

    const ANONYMOUS_QUICKSTART: &str = r#"
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        backend:
          kind: mock
          response: { ok: true }
"#;

    #[test]
    fn ceiling_is_unauthenticated_without_identity_or_header_trust() {
        assert_eq!(
            reachable_trust_ceiling(&config(ANONYMOUS_QUICKSTART)),
            TrustLevelConfig::Unauthenticated
        );
    }

    #[test]
    fn trust_subject_header_lifts_ceiling_to_header_asserted() {
        let config = config(
            r#"
gateway:
  server:
    trust_subject_header: true
"#,
        );
        assert_eq!(
            reachable_trust_ceiling(&config),
            TrustLevelConfig::HeaderAsserted
        );
    }

    #[test]
    fn identity_provider_plugin_lifts_ceiling_to_verified() {
        let config = config(
            r#"
plugins:
  - id: dev.mcpg.identity.oidc
    class: identity_provider
    source:
      path: /nonexistent/oidc.so
"#,
        );
        assert_eq!(reachable_trust_ceiling(&config), TrustLevelConfig::Verified);
    }

    #[test]
    fn jwks_lifts_ceiling_to_verified() {
        let config = config(
            r#"
governance:
  access:
    jwks:
      url: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com/
      audience: mcpg
"#,
        );
        assert_eq!(reachable_trust_ceiling(&config), TrustLevelConfig::Verified);
    }

    /// The quickstart shape: anonymous posture, binding left on the
    /// default floor. Catching exactly this is why the module exists.
    #[test]
    fn default_binding_floor_is_unreachable_when_anonymous() {
        assert_eq!(
            unreachable(&config(ANONYMOUS_QUICKSTART)),
            vec!["dev.mock.echo"],
            "the default binding floor must be flagged under an anonymous posture"
        );
    }

    #[test]
    fn explicit_unauthenticated_floor_is_reachable_when_anonymous() {
        let config = config(
            r#"
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        governance:
          minimum_trust: unauthenticated
        backend:
          kind: mock
          response: { ok: true }
"#,
        );
        assert!(
            unreachable(&config).is_empty(),
            "an unauthenticated floor is always reachable"
        );
    }

    #[test]
    fn default_floor_is_reachable_once_header_trust_is_on() {
        let config = config(
            r#"
gateway:
  server:
    trust_subject_header: true
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        backend:
          kind: mock
          response: { ok: true }
"#,
        );
        assert!(unreachable(&config).is_empty());
    }
}
