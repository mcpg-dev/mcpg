//! OIDC/OAuth verification — thin shim re-exporting from the standalone
//! library.
//!
//! The verification pipeline lives in `mcpg-plugin-identity-oidc-core`, which
//! the gateway links: config validation runs its discovery-URL SSRF guard and
//! the authorization server builds on its resolver. The RUNTIME identity
//! provider is a separate cdylib (`dev.mcpg.identity.oidc`) that an operator
//! declares in `plugins[]` — the gateway does not link it.

// Re-export public types so existing references compile unchanged.
pub use mcpg_plugin_identity_oidc_core::{OidcIdentity, OidcOAuthResolver, OidcVerificationResult};

/// Id of the OIDC identity-provider plugin. The gateway holds only the id: it
/// checks the registry for a provider registered under it and refuses to boot
/// when `access.oauth` is configured without one.
pub const PLUGIN_ID: &str = "dev.mcpg.identity.oidc";

use crate::config::OidcOAuthConfig;

/// Construct an `OidcOAuthResolver` from the gateway's config types.
///
/// Since `crate::config::OidcOAuthConfig` is now a re-export of the
/// standalone crate's config type, this is a direct pass-through.
pub fn from_gateway_config(config: &OidcOAuthConfig) -> anyhow::Result<OidcOAuthResolver> {
    OidcOAuthResolver::from_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_gateway_config_constructs_resolver() {
        let config = crate::config::OidcOAuthConfig {
            token_source: crate::config::TokenSourceConfig::default(),
            providers: vec![crate::config::OidcProviderConfig {
                issuer: "https://login.example.com/".into(),
                discovery_uri: None,
                audiences: vec![],
                verification: crate::config::VerificationConfig::OidcJwks {
                    allowed_algs: vec!["RS256".into()],
                    refresh_interval_secs: 300,
                    timeout_ms: 2000,
                    max_staleness_secs: 3600,

                    allow_hmac: false,
                },
                claim_mappings: crate::config::ClaimMappingConfig::default(),
                clock_skew_secs: 60,
                allowed_issuer_hosts: Vec::new(),
                allow_private_issuer: true,
                allow_any_audience: false,
            }],
        };
        let resolver = from_gateway_config(&config);
        assert!(
            resolver.is_ok(),
            "should create resolver: {:?}",
            resolver.err()
        );
    }
}
