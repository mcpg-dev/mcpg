//! JWT identity plugin — bridges the gateway's local JwtVerifier into
//! the plugin system.
//!
//! The OIDC/OAuth counterpart lives in its own
//! [`mcpg-plugin-identity-oidc`](mcpg_plugin_identity_oidc) crate;
//! this module keeps only the gateway-internal JWT adapter. If JWT
//! identity ever becomes externally customisable, this lifts out
//! into `plugins/identity/jwt/` alongside the OIDC crate.

use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PROTOCOL_VERSION, PluginClass, PluginIdentity,
    PluginManifest, async_trait,
};

use super::jwt::{JwtVerificationResult, JwtVerifier};

/// Plugin adapter for JWT identity verification.
///
/// Wraps an existing `JwtVerifier` and exposes it through the `IdentityProviderPlugin` trait.
pub(crate) struct JwtIdentityPlugin {
    verifier: JwtVerifier,
    manifest: PluginManifest,
}

impl JwtIdentityPlugin {
    pub fn new(verifier: JwtVerifier) -> Self {
        Self {
            verifier,
            manifest: PluginManifest {
                id: "dev.mcpg.identity.jwt".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "JWT Identity Resolver".into(),
                plugin_class: PluginClass::IdentityProvider,
                protocol_version: PROTOCOL_VERSION.to_owned(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
        }
    }
}

#[async_trait]
impl IdentityProviderPlugin for JwtIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &serde_json::Value,
    ) -> IdentityResolution {
        // Convert (String, String) pairs to axum::http::HeaderMap
        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::header::HeaderName::from_bytes(name.as_bytes()),
                axum::http::header::HeaderValue::from_str(value),
            ) {
                header_map.insert(name, value);
            }
        }

        match self.verifier.verify_from_headers(&header_map) {
            JwtVerificationResult::Verified { subject, issuer } => IdentityResolution::Resolved {
                identity: PluginIdentity {
                    kind: "verified".into(),
                    trust_level: "verified".into(),
                    subject_id: Some(subject),
                    auth_provider: Some("jwt".into()),
                    issuer,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: std::collections::BTreeMap::new(),
                },
            },
            JwtVerificationResult::None => IdentityResolution::None,
            JwtVerificationResult::Invalid(reason) => IdentityResolution::Invalid { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full JwtVerifier tests are in the identity module.
    // These tests verify the plugin adapter layer.

    #[test]
    fn manifest_is_correct() {
        // Create a minimal JwtVerifier using test JWKS
        let jwks = r#"{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"test-key-1"}]}"#;
        let config = crate::config::JwksConfig {
            url: String::new(),
            keys_json: Some(jwks.into()),
            issuer: Some("test-issuer".into()),
            audience: Some("test-audience".into()),
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            allow_missing_audience: true,
        };
        let verifier = JwtVerifier::from_jwks_json(jwks, &config).unwrap();
        let plugin = JwtIdentityPlugin::new(verifier);

        let m = plugin.manifest();
        assert_eq!(m.id, "dev.mcpg.identity.jwt");
        assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    }

    #[tokio::test]
    async fn no_token_returns_no_token() {
        let jwks = r#"{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"test-key-1"}]}"#;
        let config = crate::config::JwksConfig {
            url: String::new(),
            keys_json: Some(jwks.into()),
            issuer: None,
            audience: None,
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            allow_missing_audience: true,
        };
        let verifier = JwtVerifier::from_jwks_json(jwks, &config).unwrap();
        let plugin = JwtIdentityPlugin::new(verifier);

        // Empty headers → no token
        let result = plugin
            .resolve_identity(
                &[],
                &mcpg_plugin_protocol::types::RequestMetadata::default(),
                &serde_json::json!({}),
            )
            .await;
        assert!(matches!(result, IdentityResolution::None));
    }

    #[tokio::test]
    async fn invalid_token_returns_invalid() {
        let jwks = r#"{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"test-key-1"}]}"#;
        let config = crate::config::JwksConfig {
            url: String::new(),
            keys_json: Some(jwks.into()),
            issuer: None,
            audience: None,
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            allow_missing_audience: true,
        };
        let verifier = JwtVerifier::from_jwks_json(jwks, &config).unwrap();
        let plugin = JwtIdentityPlugin::new(verifier);

        // Bad token
        let headers = vec![("authorization".into(), "Bearer not-a-real-jwt".into())];
        let result = plugin
            .resolve_identity(
                &headers,
                &mcpg_plugin_protocol::types::RequestMetadata::default(),
                &serde_json::json!({}),
            )
            .await;
        assert!(matches!(result, IdentityResolution::Invalid { .. }));
    }
}
