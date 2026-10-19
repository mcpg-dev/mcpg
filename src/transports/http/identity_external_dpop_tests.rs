//! `governance.access.dpop` in the transport cascade: a token `jwks`
//! verifies is taken with the `DPoP` scheme only with a proof of its
//! `cnf.jkt` key, and a bound token is refused with the `Bearer` scheme;
//! an unbound Bearer token keeps working unless `required` is set.

use super::*;
use crate::runtime::authorization_server::{ExternalDpop, ReplayLedger};

const ISSUER: &str = "https://auth.example.com";
const RESOURCE: &str = "https://gateway.example.com/mcp";

/// A P-256 key, generated for the test, with its public JWK.
struct Key {
    encoding: jsonwebtoken::EncodingKey,
    jwk: jsonwebtoken::jwk::Jwk,
}

impl Key {
    fn new() -> Self {
        let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("P-256 key generates")
            .serialize_pem();
        let encoding =
            jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).expect("P-256 key parses");
        let jwk =
            jsonwebtoken::jwk::Jwk::from_encoding_key(&encoding, jsonwebtoken::Algorithm::ES256)
                .expect("public JWK");
        Self { encoding, jwk }
    }

    fn jkt(&self) -> String {
        self.jwk
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .expect("thumbprint")
    }

    /// A fresh proof of `POST` at the MCP endpoint for `token`.
    fn proof(&self, token: &str) -> String {
        use base64::Engine as _;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(self.jwk.clone());
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()));
        let claims = serde_json::json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": "POST",
            "htu": RESOURCE,
            "iat": now(),
            "ath": ath,
        });
        jsonwebtoken::encode(&header, &claims, &self.encoding).expect("proof signs")
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// The Company's issuer: its signing key, and a `jwks` verifier of it.
struct Issuer {
    key: Key,
    verifier: crate::runtime::identity::JwtVerifier,
}

impl Issuer {
    fn new() -> Self {
        use crate::runtime::identity::JwtVerifier;
        let key = Key::new();
        let mut public = serde_json::to_value(&key.jwk).expect("JWK serializes");
        public["kid"] = serde_json::json!("company-1");
        public["alg"] = serde_json::json!("ES256");
        let jwks = serde_json::json!({ "keys": [public] }).to_string();
        let verifier = JwtVerifier::from_jwks_json(&jwks, &jwks_config()).expect("JWKS loads");
        Self { key, verifier }
    }

    /// A Session Token for the MCP endpoint, bound to `bound` when given.
    fn token(&self, bound: Option<&Key>) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some("company-1".to_owned());
        let mut claims = serde_json::json!({
            "iss": ISSUER,
            "sub": "user-7",
            "aud": RESOURCE,
            "exp": now() + 600,
        });
        if let Some(key) = bound {
            claims["cnf"] = serde_json::json!({ "jkt": key.jkt() });
        }
        jsonwebtoken::encode(&header, &claims, &self.key.encoding).expect("token signs")
    }

    /// The cascade for a request with `authorization` and, if given, the
    /// DPoP `proof`, under `dpop`.
    async fn resolve(
        &self,
        dpop: Option<&ExternalDpop>,
        authorization: &str,
        proof: Option<&str>,
    ) -> Result<RequestContext, Response> {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            authorization.parse().expect("header"),
        );
        if let Some(proof) = proof {
            headers.insert(DPOP_HEADER, proof.parse().expect("header"));
        }
        build_request_context(
            &headers,
            Some(&self.verifier),
            None,
            None,
            dpop,
            None,
            false,
            None,
            Some(DpopTarget::of_request("POST", "/mcp", "/mcp")),
        )
        .await
        .map(|(ctx, _)| ctx)
    }
}

fn jwks_config() -> crate::config::access::JwksConfig {
    crate::config::access::JwksConfig {
        url: format!("{ISSUER}/jwks"),
        keys_json: None,
        issuer: Some(ISSUER.to_owned()),
        audience: Some(RESOURCE.to_owned()),
        audiences: vec![],
        header_name: "authorization".to_owned(),
        header_prefix: "Bearer ".to_owned(),
        allow_missing_audience: false,
    }
}

fn external_dpop(required: bool) -> ExternalDpop {
    let access: crate::config::AccessConfig = serde_json::from_value(serde_json::json!({
        "jwks": serde_json::to_value(jwks_config()).expect("serializes"),
        "resource_metadata": { "resource": RESOURCE, "authorization_servers": [ISSUER] },
        "dpop": { "enabled": true, "required": required, "allowed_algs": ["ES256"] },
    }))
    .expect("access config parses");
    access.validate().expect("access config is valid");
    ExternalDpop::from_access(&access, ReplayLedger::in_process())
        .expect("builds")
        .expect("on")
}

fn attributes(ctx: &RequestContext) -> &std::collections::BTreeMap<String, String> {
    match &ctx.identity {
        RequestIdentity::Verified { attributes, .. } => attributes,
        other => panic!("expected a verified caller, got {other:?}"),
    }
}

#[track_caller]
fn assert_dpop_refusal(response: &Response, error: &str) {
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "{error}"
    );
    let challenge = response
        .headers()
        .get(axum::http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        challenge.starts_with(&format!("DPoP error=\"{error}\"")),
        "{challenge}"
    );
    assert!(challenge.contains("algs=\"ES256\""), "{challenge}");
}

#[tokio::test]
async fn a_bound_token_with_a_proof_of_its_key_is_verified_and_carries_the_key() {
    let issuer = Issuer::new();
    let dpop = external_dpop(false);
    let agent = Key::new();
    let token = issuer.token(Some(&agent));
    let authorization = format!("DPoP {token}");
    let proof = agent.proof(&token);

    let ctx = issuer
        .resolve(Some(&dpop), &authorization, Some(&proof))
        .await
        .expect("verified");
    assert_eq!(
        attributes(&ctx).get("dpop_jkt").map(String::as_str),
        Some(agent.jkt().as_str())
    );

    let replayed = issuer
        .resolve(Some(&dpop), &authorization, Some(&proof))
        .await
        .expect_err("a spent proof is refused");
    assert_dpop_refusal(&replayed, "invalid_dpop_proof");
}

#[tokio::test]
async fn a_bound_token_is_refused_with_the_bearer_scheme() {
    let issuer = Issuer::new();
    let dpop = external_dpop(false);
    let token = issuer.token(Some(&Key::new()));

    let refused = issuer
        .resolve(Some(&dpop), &format!("Bearer {token}"), None)
        .await
        .expect_err("a bound token needs its proof");
    assert_dpop_refusal(&refused, "invalid_token");
}

#[tokio::test]
async fn a_proof_of_another_key_is_a_token_failure() {
    let issuer = Issuer::new();
    let dpop = external_dpop(false);
    let token = issuer.token(Some(&Key::new()));
    let proof = Key::new().proof(&token);

    let refused = issuer
        .resolve(Some(&dpop), &format!("DPoP {token}"), Some(&proof))
        .await
        .expect_err("the proof is of another key");
    assert_dpop_refusal(&refused, "invalid_token");
}

#[tokio::test]
async fn an_unbound_token_works_with_bearer_and_is_refused_with_dpop() {
    let issuer = Issuer::new();
    let dpop = external_dpop(false);
    let token = issuer.token(None);

    let ctx = issuer
        .resolve(Some(&dpop), &format!("Bearer {token}"), None)
        .await
        .expect("an unbound Bearer token keeps working");
    assert!(!attributes(&ctx).contains_key("dpop_jkt"));

    let proof = Key::new().proof(&token);
    let refused = issuer
        .resolve(Some(&dpop), &format!("DPoP {token}"), Some(&proof))
        .await
        .expect_err("an unbound token is not taken with the DPoP scheme");
    assert_dpop_refusal(&refused, "invalid_token");
}

#[tokio::test]
async fn required_refuses_an_unbound_bearer_token() {
    let issuer = Issuer::new();
    let dpop = external_dpop(true);
    let token = issuer.token(None);

    let refused = issuer
        .resolve(Some(&dpop), &format!("Bearer {token}"), None)
        .await
        .expect_err("only bound tokens are accepted");
    assert_dpop_refusal(&refused, "invalid_token");
}

#[tokio::test]
async fn a_token_the_verifier_refuses_with_the_dpop_scheme_gets_a_dpop_challenge() {
    let issuer = Issuer::new();
    let dpop = external_dpop(false);
    let proof = Key::new().proof("not-a-token");

    let refused = issuer
        .resolve(Some(&dpop), "DPoP not-a-token", Some(&proof))
        .await
        .expect_err("the token does not verify");
    assert_dpop_refusal(&refused, "invalid_token");
}

#[tokio::test]
async fn without_governance_access_dpop_nothing_changes() {
    let issuer = Issuer::new();
    let token = issuer.token(Some(&Key::new()));

    let ctx = issuer
        .resolve(None, &format!("Bearer {token}"), None)
        .await
        .expect("the bound token is accepted as before");
    assert!(!attributes(&ctx).contains_key("dpop_jkt"));
}
