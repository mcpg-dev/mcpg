//! `governance.access.dpop` as the resource applies it to a token another
//! verifier accepted: the proof's request must be under a configured
//! resource, the proof must be of the token's key, and each proof is
//! accepted once.

use serde_json::json;

use super::dpop_proofs::{ProofKey, presented, proof_claims};
use super::*;
use crate::runtime::authorization_server::dpop::{DpopChallengeError, DpopTarget};

const RESOURCE: &str = "https://mcp.example.com/mcp";
const TOKEN: &str = "an-externally-issued-token";

fn access(dpop: serde_json::Value) -> crate::config::AccessConfig {
    serde_json::from_value(json!({
        "jwks": {
            "url": "https://auth.example.com/jwks",
            "issuer": "https://auth.example.com",
            "audience": RESOURCE,
        },
        "resource_metadata": { "resource": RESOURCE, "authorization_servers": ["https://auth.example.com"] },
        "dpop": dpop,
    }))
    .expect("access config parses")
}

fn external(dpop: serde_json::Value) -> ExternalDpop {
    ExternalDpop::from_access(&access(dpop), ReplayLedger::in_process())
        .expect("builds")
        .expect("on")
}

const MCP: DpopTarget<'static> = DpopTarget {
    method: "POST",
    path: "/mcp",
    mcp_endpoint: true,
};

/// A proof by `key` of `POST` at `htu` for [`TOKEN`].
fn proof(key: &ProofKey, htu: &str) -> String {
    use base64::Engine as _;
    let mut claims = proof_claims("POST", htu);
    claims["ath"] = json!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(TOKEN.as_bytes()))
    );
    key.proof(&claims)
}

/// [`ExternalDpop::verify`] of `proof` with [`TOKEN`] bound to `bound`.
async fn verify(
    dpop: &ExternalDpop,
    bound: Option<&str>,
    proof: &str,
    target: Option<&DpopTarget<'_>>,
) -> ExternalProof {
    dpop.verify(TOKEN, bound, &presented(proof), target).await
}

#[track_caller]
fn refused(outcome: ExternalProof) -> (DpopChallengeError, String) {
    match outcome {
        ExternalProof::Refused(refusal) => (refusal.error, refusal.description),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn nothing_is_built_while_it_is_off() {
    for dpop in [json!({ "enabled": false }), serde_json::Value::Null] {
        let access = access(dpop);
        assert!(
            ExternalDpop::from_access(&access, ReplayLedger::in_process())
                .expect("builds")
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_proof_of_the_tokens_key_is_accepted_once() {
    let dpop = external(json!({ "enabled": true }));
    let key = ProofKey::p256();
    let jkt = key.jkt();
    let proof = proof(&key, RESOURCE);

    match verify(&dpop, Some(&jkt), &proof, Some(&MCP)).await {
        ExternalProof::Accepted(accepted) => assert_eq!(accepted, jkt),
        other => panic!("expected the proof to be accepted, got {other:?}"),
    }
    let (error, description) = refused(verify(&dpop, Some(&jkt), &proof, Some(&MCP)).await);
    assert_eq!(error, DpopChallengeError::InvalidDpopProof);
    assert!(description.contains("already been used"), "{description}");
}

#[tokio::test]
async fn a_proof_must_name_a_request_under_a_configured_resource() {
    let dpop = external(json!({ "enabled": true }));
    let key = ProofKey::p256();
    let elsewhere = proof(&key, "https://other.example.com/mcp");

    let (error, _) = refused(verify(&dpop, Some(&key.jkt()), &elsewhere, Some(&MCP)).await);
    assert_eq!(error, DpopChallengeError::InvalidDpopProof);
}

#[tokio::test]
async fn an_unbound_token_a_missing_target_and_another_key_are_refused() {
    let dpop = external(json!({ "enabled": true }));
    let key = ProofKey::p256();
    let jkt = key.jkt();
    let proof_of_key = proof(&key, RESOURCE);

    let (error, _) = refused(verify(&dpop, None, &proof_of_key, Some(&MCP)).await);
    assert_eq!(error, DpopChallengeError::InvalidToken, "not bound");

    let (error, _) = refused(verify(&dpop, Some(&jkt), &proof_of_key, None).await);
    assert_eq!(error, DpopChallengeError::InvalidDpopProof, "no target");

    let other = proof(&ProofKey::p256(), RESOURCE);
    let (error, description) = refused(verify(&dpop, Some(&jkt), &other, Some(&MCP)).await);
    assert_eq!(error, DpopChallengeError::InvalidToken, "another key");
    assert_eq!(description, "Invalid DPoP key binding");
}

#[test]
fn the_challenge_and_the_bearer_rules_follow_the_config() {
    let open = external(json!({ "enabled": true, "allowed_algs": ["ES256", "EdDSA"] }));
    let challenge = open.challenge();
    assert_eq!(challenge.algs, "ES256 EdDSA");
    assert!(!challenge.required);
    assert_eq!(open.alg_names(), ["ES256", "EdDSA"]);
    assert!(open.unbound_token_refused().is_none());
    assert_eq!(
        open.bound_token_as_bearer().error,
        DpopChallengeError::InvalidToken
    );

    let required = external(json!({ "enabled": true, "required": true }));
    assert!(required.challenge().required);
    assert!(required.unbound_token_refused().is_some());
}
