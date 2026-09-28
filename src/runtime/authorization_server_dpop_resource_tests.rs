//! DPoP (RFC 9449) at the resource: a token bound to a key is accepted only
//! with the `DPoP` scheme and a proof of that key for the request (`htm`,
//! `htu`, `ath`, single use, the resource nonce), and never as a Bearer
//! token; while `required` is set, a token bound to no key is refused too.
//! Each refusal names the error of its challenge (§7.1).

use serde_json::{Value, json};

use super::dpop_proofs::{
    ProofKey, TOKEN_HTU, dpop_config, dpop_server, dpop_server_with, issued_by, presented,
    proof_claims, redeem_presenting,
};
use super::*;
use crate::config::DpopNonceMode;
use crate::runtime::authorization_server::dpop::{
    DPOP_JKT_ATTRIBUTE, DpopChallengeError, DpopPresentation, DpopTarget, EmaRefusal,
};

/// The URL a proof at the MCP endpoint of the test resource names.
const MCP_HTU: &str = "https://gw.test/mcp";

fn mcp_target() -> DpopTarget<'static> {
    DpopTarget {
        method: "POST",
        path: "/mcp",
        mcp_endpoint: true,
    }
}

/// `ath` of `token` (RFC 9449 §4.2).
fn ath(token: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()))
}

/// A fresh proof by `key` of `POST` at the MCP endpoint for `token`.
fn resource_proof(key: &ProofKey, token: &str) -> String {
    key.proof(&resource_claims(token))
}

fn resource_claims(token: &str) -> Value {
    let mut claims = proof_claims("POST", MCP_HTU);
    claims["ath"] = json!(ath(token));
    claims
}

/// A token `server` binds to `key`.
async fn bound_token(server: &AuthorizationServer, key: &ProofKey) -> String {
    let redemption = redeem_presenting(
        server,
        &make_id_jag(AssertionOverrides::default()),
        Some(&key.proof_for("POST", TOKEN_HTU)),
    )
    .await;
    issued_by(&redemption).0.access_token.clone()
}

/// A token `server` issues bound to no key.
async fn unbound_token(server: &AuthorizationServer) -> String {
    let redemption =
        redeem_presenting(server, &make_id_jag(AssertionOverrides::default()), None).await;
    issued_by(&redemption).0.access_token.clone()
}

async fn verify_with(
    server: &AuthorizationServer,
    token: &str,
    proof: Option<&str>,
    target: Option<&DpopTarget<'_>>,
) -> EmaBearerOutcome {
    let presentation = proof.map_or_else(DpopPresentation::none, presented);
    server.verify_dpop(token, &presentation, target).await
}

#[track_caller]
fn refusal(outcome: EmaBearerOutcome) -> EmaRefusal {
    match outcome {
        EmaBearerOutcome::Refused(refusal) => refusal,
        other => panic!("expected a DPoP refusal, got {}", discriminant_name(&other)),
    }
}

#[track_caller]
fn verified_caller(outcome: EmaBearerOutcome) -> EmaVerifiedIdentity {
    match outcome {
        EmaBearerOutcome::Verified(identity) => identity,
        EmaBearerOutcome::Refused(refusal) => panic!("expected Verified, got {refusal:?}"),
        other => panic!("expected Verified, got {}", discriminant_name(&other)),
    }
}

#[tokio::test]
async fn a_bound_token_verifies_with_a_proof_of_its_key() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let token = bound_token(&server, &key).await;
    let proof = resource_proof(&key, &token);
    let identity =
        verified_caller(verify_with(&server, &token, Some(&proof), Some(&mcp_target())).await);
    assert_eq!(identity.subject_id, "user-42");
    assert_eq!(
        identity.attributes.get(DPOP_JKT_ATTRIBUTE),
        Some(&key.jkt())
    );
    assert_eq!(
        identity.attributes.get("grant_type").map(String::as_str),
        Some(GRANT_ATTRIBUTE_ID_JAG)
    );

    // The same proof is spent.
    let replayed = refusal(verify_with(&server, &token, Some(&proof), Some(&mcp_target())).await);
    assert_eq!(replayed.error, DpopChallengeError::InvalidDpopProof);
    assert!(
        replayed.description.contains("already been used"),
        "{replayed:?}"
    );
}

/// Every check of the proof at the resource, and the error each refusal
/// names.
#[tokio::test]
async fn each_refusal_names_the_error_of_its_challenge() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let token = bound_token(&server, &key).await;
    let target = mcp_target();

    let missing = refusal(verify_with(&server, &token, None, Some(&target)).await);
    assert_eq!(missing.error, DpopChallengeError::InvalidDpopProof);
    assert!(missing.description.contains("no DPoP proof"), "{missing:?}");

    let without_ath = key.proof_for("POST", MCP_HTU);
    let refused = refusal(verify_with(&server, &token, Some(&without_ath), Some(&target)).await);
    assert_eq!(refused.error, DpopChallengeError::InvalidDpopProof);
    assert!(refused.description.contains("ath"), "{refused:?}");

    let other_token = ath("another-token");
    let mut claims = proof_claims("POST", MCP_HTU);
    claims["ath"] = json!(other_token);
    let refused =
        refusal(verify_with(&server, &token, Some(&key.proof(&claims)), Some(&target)).await);
    assert_eq!(refused.error, DpopChallengeError::InvalidDpopProof);

    let mut claims = resource_claims(&token);
    claims["htu"] = json!("https://gw.test/other");
    let refused =
        refusal(verify_with(&server, &token, Some(&key.proof(&claims)), Some(&target)).await);
    assert_eq!(refused.error, DpopChallengeError::InvalidDpopProof);
    assert!(refused.description.contains("htu"), "{refused:?}");

    let mut claims = resource_claims(&token);
    claims["htm"] = json!("GET");
    let refused =
        refusal(verify_with(&server, &token, Some(&key.proof(&claims)), Some(&target)).await);
    assert_eq!(refused.error, DpopChallengeError::InvalidDpopProof);

    // RFC 9449 §7.1: a proof of another key is a token failure.
    let stranger = ProofKey::p256();
    let refused = refusal(
        verify_with(
            &server,
            &token,
            Some(&resource_proof(&stranger, &token)),
            Some(&target),
        )
        .await,
    );
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert_eq!(refused.description, "Invalid DPoP key binding");

    let no_target =
        refusal(verify_with(&server, &token, Some(&resource_proof(&key, &token)), None).await);
    assert_eq!(no_target.error, DpopChallengeError::InvalidDpopProof);

    // None of those refusals spent the key's proof: a valid one is served.
    verified_caller(
        verify_with(
            &server,
            &token,
            Some(&resource_proof(&key, &token)),
            Some(&target),
        )
        .await,
    );
}

/// The token's own checks come first: a token this server did not mint, a
/// forged one, one of another issuer, and one bound to no key are refused
/// with `invalid_token`, and a verification reason is logged, not echoed.
#[tokio::test]
async fn the_token_itself_must_be_this_servers_and_bound() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let token = bound_token(&server, &key).await;
    let target = mcp_target();

    let forged = corrupt_signature(&token);
    let refused = refusal(
        verify_with(
            &server,
            &forged,
            Some(&resource_proof(&key, &forged)),
            Some(&target),
        )
        .await,
    );
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert_eq!(
        refused.description,
        "the access token is invalid, expired or revoked"
    );
    assert!(!refused.reason.is_empty());

    let foreign = make_id_jag(AssertionOverrides {
        typ: Some("at+jwt"),
        ..Default::default()
    });
    let refused = refusal(
        verify_with(
            &server,
            &foreign,
            Some(&resource_proof(&key, &foreign)),
            Some(&target),
        )
        .await,
    );
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert!(
        refused.description.contains("its own authorization server"),
        "{refused:?}"
    );

    let unbound = unbound_token(&server).await;
    let refused = refusal(
        verify_with(
            &server,
            &unbound,
            Some(&resource_proof(&key, &unbound)),
            Some(&target),
        )
        .await,
    );
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert!(
        refused.description.contains("not DPoP-bound"),
        "{refused:?}"
    );
    // The unbound token stays a Bearer token.
    assert!(matches!(
        server.verify_bearer(&unbound),
        EmaBearerOutcome::Verified(_)
    ));
}

/// Off, the `DPoP` scheme is not recognised at all.
#[tokio::test]
async fn while_dpop_is_off_the_dpop_scheme_is_not_ours() {
    let key = ProofKey::p256();
    let token = bound_token(&dpop_server().await, &key).await;
    let server = test_server().await;
    let outcome = verify_with(
        &server,
        &token,
        Some(&resource_proof(&key, &token)),
        Some(&mcp_target()),
    )
    .await;
    assert!(matches!(outcome, EmaBearerOutcome::NotOurs));
    assert_eq!(server.dpop_challenge(), None);
}

/// RFC 9449 §7.2: a bound token is refused with the Bearer scheme, with a
/// DPoP challenge while DPoP is on and the Bearer one while it is off.
#[tokio::test]
async fn a_bound_token_sent_as_bearer_is_refused_whatever_the_configuration() {
    let key = ProofKey::p256();
    let on = dpop_server_with(|config| {
        config.dpop.allowed_algs = vec!["ES256".to_owned(), "EdDSA".to_owned()];
    })
    .await;
    let token = bound_token(&on, &key).await;
    let refused = refusal(on.verify_bearer(&token));
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert!(refused.audited());
    assert_eq!(
        refused.challenge(),
        "DPoP error=\"invalid_token\", error_description=\"the access token is DPoP-bound; \
         present it with the DPoP scheme and a proof\", algs=\"ES256 EdDSA\""
    );

    let off = test_server().await;
    match off.verify_bearer(&token) {
        EmaBearerOutcome::Invalid(reason) => assert!(reason.contains("DPoP-bound"), "{reason}"),
        other => panic!("expected Invalid, got {}", discriminant_name(&other)),
    }
}

/// `required`: a token bound to no key is refused at the resource, one the
/// server issued before `required` was set included.
#[tokio::test]
async fn required_refuses_a_token_bound_to_no_key() {
    let earlier = unbound_token(&test_server().await).await;
    let server = dpop_server_with(|config| config.dpop.required = true).await;
    let refused = refusal(server.verify_bearer(&earlier));
    assert_eq!(refused.error, DpopChallengeError::InvalidToken);
    assert_eq!(
        refused.description,
        "this resource accepts only DPoP-bound tokens"
    );
    assert_eq!(
        server.dpop_challenge().map(|challenge| challenge.required),
        Some(true)
    );

    let key = ProofKey::p256();
    let token = bound_token(&server, &key).await;
    verified_caller(
        verify_with(
            &server,
            &token,
            Some(&resource_proof(&key, &token)),
            Some(&mcp_target()),
        )
        .await,
    );
}

/// RFC 9449 §9: with `nonce: always`, a proof at the resource without a
/// current nonce is answered `use_dpop_nonce` with one, which is not a
/// failure to audit; the retry that carries it is served.
#[tokio::test]
async fn the_resource_hands_out_a_nonce_and_then_requires_it() {
    let server = dpop_server_with(|config| config.dpop.nonce = DpopNonceMode::Always).await;
    let key = ProofKey::p256();
    let nonce = server.token_endpoint_nonce().expect("nonces are on");
    let mut claims = proof_claims("POST", TOKEN_HTU);
    claims["nonce"] = json!(nonce.as_str());
    let redemption = redeem_presenting(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some(&key.proof(&claims)),
    )
    .await;
    let token = issued_by(&redemption).0.access_token.clone();

    let refused = refusal(
        verify_with(
            &server,
            &token,
            Some(&resource_proof(&key, &token)),
            Some(&mcp_target()),
        )
        .await,
    );
    assert_eq!(refused.error, DpopChallengeError::UseDpopNonce);
    assert!(!refused.audited());
    let handed_out = refused.nonce.expect("a nonce to use");
    let mut claims = resource_claims(&token);
    claims["nonce"] = json!(handed_out.as_str());
    verified_caller(
        verify_with(
            &server,
            &token,
            Some(&key.proof(&claims)),
            Some(&mcp_target()),
        )
        .await,
    );

    // `token_endpoint` leaves the resource without nonces.
    let server = dpop_server_with(|config| config.dpop.nonce = DpopNonceMode::TokenEndpoint).await;
    let mut claims = proof_claims("POST", TOKEN_HTU);
    claims["nonce"] = json!(server.token_endpoint_nonce().expect("nonces").as_str());
    let redemption = redeem_presenting(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some(&key.proof(&claims)),
    )
    .await;
    let token = issued_by(&redemption).0.access_token.clone();
    verified_caller(
        verify_with(
            &server,
            &token,
            Some(&resource_proof(&key, &token)),
            Some(&mcp_target()),
        )
        .await,
    );
}

/// A ledger that cannot record the proof refuses the request for now.
#[tokio::test]
async fn an_unwritable_ledger_leaves_the_resource_unavailable() {
    let key = ProofKey::p256();
    let token = bound_token(&dpop_server().await, &key).await;
    let server = test_server_on(dpop_config(), ReplayLedger::shared(Arc::new(UnreachableKv))).await;
    let outcome = verify_with(
        &server,
        &token,
        Some(&resource_proof(&key, &token)),
        Some(&mcp_target()),
    )
    .await;
    assert!(
        matches!(outcome, EmaBearerOutcome::Unavailable),
        "{}",
        discriminant_name(&outcome)
    );
}

/// The replay ledger every replica shares refuses a proof spent on another
/// replica.
#[tokio::test]
async fn a_proof_spent_on_one_replica_is_refused_on_another() {
    let (_, ledger) = shared_ledger();
    let replica_a = test_server_on(dpop_config(), ledger.clone()).await;
    let replica_b = test_server_on(dpop_config(), ledger).await;
    let key = ProofKey::p256();
    let token = bound_token(&replica_a, &key).await;
    let proof = resource_proof(&key, &token);
    verified_caller(verify_with(&replica_a, &token, Some(&proof), Some(&mcp_target())).await);
    let refused = refusal(verify_with(&replica_b, &token, Some(&proof), Some(&mcp_target())).await);
    assert_eq!(refused.error, DpopChallengeError::InvalidDpopProof);
}

/// `dpop_jkt` comes only from a proof: a token carrying it among its
/// mapped attributes does not set it.
#[tokio::test]
async fn the_dpop_jkt_attribute_cannot_be_carried_by_the_token() {
    let server = dpop_server().await;
    let now = now_unix();
    let claims = MintedClaims {
        iss: GW_ISSUER.to_owned(),
        sub: "user-42".to_owned(),
        aud: GW_ISSUER.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp: now + 600,
        idp: IDP_ISSUER.to_owned(),
        attributes: BTreeMap::from([(
            DPOP_JKT_ATTRIBUTE.to_owned(),
            "spoofed-thumbprint".to_owned(),
        )]),
        ..MintedClaims::default()
    };
    let token = server.signing_keys[0]
        .sign(&claims)
        .expect("the token signs");
    match server.verify_bearer(&token) {
        EmaBearerOutcome::Verified(identity) => {
            assert!(
                !identity.attributes.contains_key(DPOP_JKT_ATTRIBUTE),
                "{:?}",
                identity.attributes
            );
        }
        other => panic!("expected Verified, got {}", discriminant_name(&other)),
    }
    assert!(IDENTITY_ATTRIBUTES.contains(&DPOP_JKT_ATTRIBUTE));
}

#[tokio::test]
async fn resource_proofs_are_counted_by_outcome_and_reason() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let token = bound_token(&server, &key).await;
    let unbound = unbound_token(&server).await;
    let target = mcp_target();
    let _ = verify_with(
        &server,
        &token,
        Some(&resource_proof(&key, &token)),
        Some(&target),
    )
    .await;
    let stranger = ProofKey::p256();
    let _ = verify_with(
        &server,
        &token,
        Some(&resource_proof(&stranger, &token)),
        Some(&target),
    )
    .await;
    let _ = verify_with(
        &server,
        &unbound,
        Some(&resource_proof(&key, &unbound)),
        Some(&target),
    )
    .await;
    let _ = verify_with(&server, &token, Some(&resource_proof(&key, &token)), None).await;
    for metric in [
        "mcpg_as_dpop_proofs_total{endpoint=resource,outcome=accepted,reason=none}",
        "mcpg_as_dpop_proofs_total{endpoint=resource,outcome=refused,reason=key_mismatch}",
        "mcpg_as_dpop_proofs_total{endpoint=resource,outcome=refused,reason=not_bound}",
        "mcpg_as_dpop_proofs_total{endpoint=resource,outcome=refused,reason=no_target}",
        "mcpg_as_dpop_ledger_latency_ms{endpoint=resource}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}

/// The challenge keeps `error_description` in the RFC 6749 character set,
/// and the refusal's `Debug` shows no nonce.
#[test]
fn a_challenge_is_a_well_formed_header_value() {
    let refusal = EmaRefusal {
        error: DpopChallengeError::UseDpopNonce,
        description: "a \"quoted\" \\ value…".to_owned(),
        reason: "why".to_owned(),
        nonce: Some(dpop::mint_nonce(&[7u8; 32], GW_ISSUER, 3)),
        algs: "ES256".to_owned(),
    };
    let challenge = refusal.challenge();
    assert_eq!(
        challenge,
        "DPoP error=\"use_dpop_nonce\", error_description=\"a 'quoted' ' value...\", \
         algs=\"ES256\""
    );
    axum::http::HeaderValue::from_str(&challenge).expect("a valid header value");
    let nonce = refusal.nonce.as_ref().expect("a nonce").as_str().to_owned();
    assert!(!format!("{refusal:?}").contains(&nonce));
}

#[test]
fn a_request_target_names_its_path_and_the_mcp_endpoint() {
    let target = DpopTarget::of_request("GET", "/mcp?session=1", "/mcp");
    assert_eq!(
        target,
        DpopTarget {
            method: "GET",
            path: "/mcp",
            mcp_endpoint: true,
        }
    );
    let target = DpopTarget::of_request("POST", "/plugins/p/e?x", "/mcp");
    assert_eq!(target.path, "/plugins/p/e");
    assert!(!target.mcp_endpoint);
}
