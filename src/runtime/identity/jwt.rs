use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::JwksConfig;

/// Standard JWT claims used for identity extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardClaims {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<Audience>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

/// A pre-parsed JWK entry with an optional `kid` and explicit algorithm.
/// Security: keys without an explicit algorithm are skipped during verification
/// to prevent algorithm confusion attacks (e.g. attacker forcing HS256 on an RSA key).
#[derive(Clone)]
struct KeyEntry {
    kid: Option<String>,
    key: DecodingKey,
    algorithm: Option<Algorithm>,
}

/// Outcome of a JWT verification attempt.
#[derive(Debug)]
pub enum JwtVerificationResult {
    /// Token verified successfully.
    Verified {
        subject: String,
        issuer: Option<String>,
    },
    /// No bearer token was present in the request.
    None,
    /// Token was present but verification failed.
    Invalid(String),
}

/// Runtime JWT verifier holding pre-parsed keys and validation config.
#[derive(Clone)]
pub struct JwtVerifier {
    keys: Vec<KeyEntry>,
    issuer: Option<String>,
    audience: Option<String>,
    /// Dev escape-hatch: when true, a token may omit the `aud` claim even
    /// though an audience is configured. Production keeps this false so a
    /// missing `aud` is rejected (audience-binding / confused-deputy).
    allow_missing_audience: bool,
    header_name: String,
    header_prefix: String,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("key_count", &self.keys.len())
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("header_name", &self.header_name)
            .finish()
    }
}

impl JwtVerifier {
    /// Build a verifier from JWKS JSON string and config.
    pub fn from_jwks_json(jwks_json: &str, config: &JwksConfig) -> Result<Self> {
        let jwk_set: JwkSet =
            serde_json::from_str(jwks_json).context("failed to parse JWKS JSON")?;

        let mut keys = Vec::new();
        for jwk in &jwk_set.keys {
            let decoding_key = DecodingKey::from_jwk(jwk).with_context(|| {
                format!(
                    "failed to create decoding key from JWK (kid: {:?})",
                    jwk.common.key_id
                )
            })?;

            let algorithm = jwk.common.key_algorithm.and_then(map_key_algorithm);

            keys.push(KeyEntry {
                kid: jwk.common.key_id.clone(),
                key: decoding_key,
                algorithm,
            });
        }

        if keys.is_empty() {
            return Err(anyhow::anyhow!("JWKS contains no usable keys"));
        }

        Ok(Self {
            keys,
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            allow_missing_audience: config.allow_missing_audience,
            header_name: config.header_name.clone(),
            header_prefix: config.header_prefix.clone(),
        })
    }

    /// Extract and verify a bearer token from the given headers.
    pub fn verify_from_headers(&self, headers: &axum::http::HeaderMap) -> JwtVerificationResult {
        let token = match self.extract_token(headers) {
            Some(t) => t,
            None => return JwtVerificationResult::None,
        };

        self.verify_token(token)
    }

    /// Extract the raw token string from request headers.
    fn extract_token<'a>(&self, headers: &'a axum::http::HeaderMap) -> Option<&'a str> {
        let header_value = headers
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok())?;

        if self.header_prefix.is_empty() {
            return Some(header_value);
        }

        header_value.strip_prefix(&self.header_prefix)
    }

    /// Verify a raw JWT token string against the loaded keys.
    fn verify_token(&self, token: &str) -> JwtVerificationResult {
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                return JwtVerificationResult::Invalid(format!("invalid JWT header: {e}"));
            }
        };

        // Find matching key(s) by kid or try all keys
        let candidate_keys: Vec<&KeyEntry> = if let Some(ref kid) = header.kid {
            let matching: Vec<_> = self
                .keys
                .iter()
                .filter(|k| k.kid.as_deref() == Some(kid))
                .collect();
            if matching.is_empty() {
                return JwtVerificationResult::Invalid(format!("no key found for kid: {kid}"));
            }
            matching
        } else {
            self.keys.iter().collect()
        };

        // Try each candidate key
        for key_entry in &candidate_keys {
            // Require the key to have an explicit algorithm to prevent
            // algorithm confusion attacks (e.g. attacker specifying HS256
            // against an RSA key with no explicit algorithm).
            let algorithm = match key_entry.algorithm {
                Some(alg) => alg,
                None => {
                    tracing::debug!(
                        kid = ?key_entry.kid,
                        header_alg = ?header.alg,
                        "skipping JWK without explicit algorithm"
                    );
                    continue;
                }
            };

            if algorithm != header.alg {
                tracing::debug!(
                    kid = ?key_entry.kid,
                    key_alg = ?algorithm,
                    header_alg = ?header.alg,
                    "algorithm mismatch, skipping key"
                );
                continue;
            }

            let mut validation = Validation::new(algorithm);
            validation.validate_exp = true;

            // jsonwebtoken's default `required_spec_claims` is just {exp};
            // `set_issuer`/`set_audience` only validate a claim when it is
            // PRESENT, so a token omitting `aud`/`iss` would silently pass the
            // allowlist. Require them explicitly so a missing claim is a hard
            // rejection — the MCP-mandated audience-binding / confused-deputy
            // protection.
            let mut required = vec!["exp"];
            if let Some(ref issuer) = self.issuer {
                validation.set_issuer(&[issuer]);
                required.push("iss");
            }

            if let Some(ref audience) = self.audience {
                validation.set_audience(&[audience]);
                if !self.allow_missing_audience {
                    required.push("aud");
                }
            }
            validation.set_required_spec_claims(&required);

            match decode::<StandardClaims>(token, &key_entry.key, &validation) {
                Ok(token_data) => {
                    let subject = match token_data.claims.sub {
                        Some(sub) if !sub.trim().is_empty() => sub,
                        _ => {
                            return JwtVerificationResult::Invalid(
                                "JWT missing or empty 'sub' claim".to_owned(),
                            );
                        }
                    };

                    debug!(
                        subject = %subject,
                        issuer = ?token_data.claims.iss,
                        kid = ?header.kid,
                        algorithm = ?algorithm,
                        "JWT verified successfully"
                    );

                    return JwtVerificationResult::Verified {
                        subject,
                        issuer: token_data.claims.iss,
                    };
                }
                Err(e) => {
                    debug!(
                        kid = ?key_entry.kid,
                        algorithm = ?algorithm,
                        error = %e,
                        "JWT verification failed with key, trying next"
                    );
                    continue;
                }
            }
        }

        let kid_info = header.kid.as_deref().unwrap_or("none");
        warn!(
            kid = %kid_info,
            keys_tried = candidate_keys.len(),
            "JWT verification failed: no key could verify the token"
        );
        JwtVerificationResult::Invalid("token signature verification failed".to_owned())
    }

    pub fn header_name(&self) -> &str {
        &self.header_name
    }
}

pub fn map_key_algorithm(ka: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    use jsonwebtoken::jwk::KeyAlgorithm;
    match ka {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    fn test_hmac_jwks(secret: &str) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let encoded_secret = URL_SAFE_NO_PAD.encode(secret.as_bytes());
        serde_json::json!({
            "keys": [{
                "kty": "oct",
                "kid": "test-key-1",
                "k": encoded_secret,
                "alg": "HS256"
            }]
        })
        .to_string()
    }

    fn test_config() -> JwksConfig {
        JwksConfig {
            url: "http://localhost/.well-known/jwks.json".to_owned(),
            keys_json: None,
            issuer: Some("test-issuer".to_owned()),
            audience: Some("test-audience".to_owned()),
            header_name: "authorization".to_owned(),
            header_prefix: "Bearer ".to_owned(),
            allow_missing_audience: true,
        }
    }

    fn make_test_token(secret: &str, claims: &StandardClaims) -> String {
        let key = EncodingKey::from_secret(secret.as_bytes());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".to_owned());
        encode(&header, claims, &key).expect("encoding should succeed")
    }

    fn valid_claims() -> StandardClaims {
        StandardClaims {
            sub: Some("user-42".to_owned()),
            iss: Some("test-issuer".to_owned()),
            aud: Some(Audience::Single("test-audience".to_owned())),
            exp: Some(jsonwebtoken::get_current_timestamp() + 3600),
            iat: Some(jsonwebtoken::get_current_timestamp()),
            nbf: None,
        }
    }

    #[test]
    fn verifier_from_jwks_json_succeeds() {
        let jwks = test_hmac_jwks("super-secret-key-for-testing-only");
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();
        assert_eq!(verifier.keys.len(), 1);
    }

    #[test]
    fn verifier_rejects_empty_jwks() {
        let jwks = r#"{"keys": []}"#;
        let config = test_config();
        let err = JwtVerifier::from_jwks_json(jwks, &config).unwrap_err();
        assert!(err.to_string().contains("no usable keys"));
    }

    #[test]
    fn verify_valid_token() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let token = make_test_token(secret, &valid_claims());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Verified { subject, issuer } => {
                assert_eq!(subject, "user-42");
                assert_eq!(issuer.as_deref(), Some("test-issuer"));
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn verify_returns_no_token_when_header_missing() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let headers = axum::http::HeaderMap::new();
        assert!(matches!(
            verifier.verify_from_headers(&headers),
            JwtVerificationResult::None
        ));
    }

    #[test]
    fn verify_rejects_expired_token() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let mut claims = valid_claims();
        claims.exp = Some(1000); // long expired
        let token = make_test_token(secret, &claims);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Invalid(msg) => {
                assert!(msg.contains("verification failed"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let mut claims = valid_claims();
        claims.iss = Some("wrong-issuer".to_owned());
        let token = make_test_token(secret, &claims);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Invalid(msg) => {
                assert!(msg.contains("verification failed"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let token = make_test_token("wrong-secret-not-matching", &valid_claims());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Invalid(msg) => {
                assert!(msg.contains("verification failed"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_missing_sub_claim() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let mut claims = valid_claims();
        claims.sub = None;
        let token = make_test_token(secret, &claims);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Invalid(msg) => {
                assert!(msg.contains("sub"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_unknown_kid() {
        let secret = "super-secret-key-for-testing-only";
        let jwks = test_hmac_jwks(secret);
        let config = test_config();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &config).unwrap();

        let key = EncodingKey::from_secret(secret.as_bytes());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("unknown-kid".to_owned());
        let token = encode(&header, &valid_claims(), &key).unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        match verifier.verify_from_headers(&headers) {
            JwtVerificationResult::Invalid(msg) => {
                assert!(msg.contains("no key found"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// Production posture: audience configured, escape-hatch off.
    fn prod_config() -> JwksConfig {
        JwksConfig {
            allow_missing_audience: false,
            ..test_config()
        }
    }

    fn headers_with(token: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    /// Regression: a signed token from the trusted key that OMITS the
    /// `aud` claim must be rejected when an audience is configured. Before the
    /// fix, jsonwebtoken only checked `aud` when present, so this passed.
    #[test]
    fn verify_rejects_token_missing_audience() {
        let secret = "super-secret-key-for-testing-only";
        let verifier =
            JwtVerifier::from_jwks_json(&test_hmac_jwks(secret), &prod_config()).unwrap();

        let mut claims = valid_claims();
        claims.aud = None; // no audience binding
        let token = make_test_token(secret, &claims);

        match verifier.verify_from_headers(&headers_with(&token)) {
            JwtVerificationResult::Invalid(_) => {}
            other => panic!("token without aud must be rejected, got {other:?}"),
        }
    }

    /// Regression: a token omitting `iss` is rejected when an issuer is
    /// configured.
    #[test]
    fn verify_rejects_token_missing_issuer() {
        let secret = "super-secret-key-for-testing-only";
        let verifier =
            JwtVerifier::from_jwks_json(&test_hmac_jwks(secret), &prod_config()).unwrap();

        let mut claims = valid_claims();
        claims.iss = None;
        let token = make_test_token(secret, &claims);

        match verifier.verify_from_headers(&headers_with(&token)) {
            JwtVerificationResult::Invalid(_) => {}
            other => panic!("token without iss must be rejected, got {other:?}"),
        }
    }

    /// Positive control: a token WITH aud + iss verifies under the production
    /// posture (the fix doesn't over-reject well-formed tokens).
    #[test]
    fn verify_accepts_token_with_aud_and_iss_in_prod() {
        let secret = "super-secret-key-for-testing-only";
        let verifier =
            JwtVerifier::from_jwks_json(&test_hmac_jwks(secret), &prod_config()).unwrap();
        let token = make_test_token(secret, &valid_claims());

        match verifier.verify_from_headers(&headers_with(&token)) {
            JwtVerificationResult::Verified { subject, .. } => assert_eq!(subject, "user-42"),
            other => panic!("well-formed token must verify, got {other:?}"),
        }
    }

    /// The dev escape-hatch still works: with `allow_missing_audience=true` a
    /// token without `aud` is accepted.
    #[test]
    fn allow_missing_audience_permits_token_without_aud() {
        let secret = "super-secret-key-for-testing-only";
        // test_config() has allow_missing_audience = true.
        let verifier =
            JwtVerifier::from_jwks_json(&test_hmac_jwks(secret), &test_config()).unwrap();

        let mut claims = valid_claims();
        claims.aud = None;
        let token = make_test_token(secret, &claims);

        match verifier.verify_from_headers(&headers_with(&token)) {
            JwtVerificationResult::Verified { .. } => {}
            other => panic!("escape-hatch should accept missing aud, got {other:?}"),
        }
    }
}
