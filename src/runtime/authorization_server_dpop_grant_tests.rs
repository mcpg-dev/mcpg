//! DPoP (RFC 9449) in interactive sign-in: the `dpop_jkt` of an
//! authorization request binds its code, a proof binds the access token,
//! a public client's grant is bound to its first proof key so its refresh
//! tokens redeem only with that key, a confidential client's is not, and
//! a refused request leaves its code or refresh token unspent. A token
//! issued before its grant was bound revokes the grant when spent again.
//! A client that registers `dpop_bound_access_tokens` sends a proof every
//! time.

use serde_json::json;

use super::*;
use crate::config::DpopNonceMode;
use crate::runtime::authorization_server::dpop::DpopPresentation;
use crate::runtime::authorization_server::grants::GRANT_TYPE_REFRESH_TOKEN;
use crate::runtime::authorization_server::state::GrantRecord;
use crate::runtime::authorization_server::tests::dpop_proofs::{
    ProofKey, TOKEN_HTU, presented, proof_claims,
};

const IDP_REFRESH: &str = "idp-refresh-1";
const CONFIDENTIAL_SECRET: &str = "confidential-web-secret-0123456789";

/// The server of `idp` with DPoP on, a confidential web client beside the
/// fixture clients, and `change` applied.
fn dpop_server(
    idp: &Idp,
    change: impl FnOnce(&mut AuthorizationServerConfig),
) -> AuthorizationServer {
    let mut config = config(idp);
    config.dpop.enabled = true;
    config.clients.push(
        serde_json::from_value(json!({
            "client_id": "web-confidential",
            "client_secret": CONFIDENTIAL_SECRET,
            "redirect_uris": [WEB_REDIRECT],
        }))
        .expect("client parses"),
    );
    change(&mut config);
    server_with(&config)
}

/// The authorization response of `client_id`'s request with `extra`
/// parameters, approving consent when it is asked.
async fn authorize_with(
    server: &AuthorizationServer,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    extra: &[(&str, &str)],
) -> BrowserResponse {
    let mut query = authorize_query(client_id, redirect_uri, challenge);
    for (name, value) in extra {
        query.push('&');
        query.push_str(
            &url::form_urlencoded::Serializer::new(String::new())
                .append_pair(name, value)
                .finish(),
        );
    }
    let response = server.authorize(&query, &BrowserCookies::default()).await;
    match response.outcome {
        BrowserOutcome::Consent(_) => approve(server, &response).await,
        _ => response,
    }
}

/// The code `client_id` receives for a request with `extra` parameters,
/// the IdP handing out a refresh token.
async fn code_with(
    server: &AuthorizationServer,
    idp: &Idp,
    client_id: &str,
    redirect_uri: &str,
    extra: &[(&str, &str)],
) -> Code {
    let verifier = random_token().expect("random");
    let challenge = s256_challenge(&verifier);
    let response = authorize_with(server, client_id, redirect_uri, &challenge, extra).await;
    let started = started(&response, &challenge);
    let (_, params) = code_issued(&complete(server, idp, &started, Some(IDP_REFRESH)).await);
    Code {
        code: params["code"].clone(),
        verifier,
    }
}

/// A token request of `form` with the DPoP proof `proof`, if any.
async fn presenting(
    server: &AuthorizationServer,
    form: TokenRequestForm,
    proof: Option<&str>,
) -> TokenRedemption {
    let presentation = proof.map_or_else(DpopPresentation::none, presented);
    server.redeem_with_dpop(form, None, &presentation).await
}

fn token_proof(key: &ProofKey) -> String {
    key.proof_for("POST", TOKEN_HTU)
}

fn refresh_form(client_id: &str, refresh_token: &str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_REFRESH_TOKEN.to_owned()),
        client_id: Some(client_id.to_owned()),
        refresh_token: Some(refresh_token.to_owned()),
        ..Default::default()
    }
}

fn confidential(form: TokenRequestForm) -> TokenRequestForm {
    TokenRequestForm {
        client_secret: Some(CONFIDENTIAL_SECRET.to_owned()),
        ..form
    }
}

/// The access token, its type and the refresh token of a successful
/// request.
#[track_caller]
fn tokens_of(redemption: &TokenRedemption) -> (String, &'static str, String) {
    let (response, _) = issued(redemption);
    (
        response.access_token.clone(),
        response.token_type,
        response
            .refresh_token
            .clone()
            .expect("a refresh token for a client that may refresh"),
    )
}

async fn grant_record(server: &AuthorizationServer, token: &str) -> GrantRecord {
    state_of(server)
        .get(&keys::grant(&grant_of(token)))
        .await
        .expect("store")
        .expect("the grant is kept")
}

#[track_caller]
fn bound_to(token: &str) -> Option<String> {
    minted_claims(token)["cnf"]["jkt"]
        .as_str()
        .map(str::to_owned)
}

/// The OAuth error an authorization request was refused with.
#[track_caller]
fn authorize_error(response: &BrowserResponse) -> &'static str {
    match response.outcome {
        BrowserOutcome::ErrorRedirect { error, .. } => error,
        BrowserOutcome::Page(ref page) => page.error,
        ref other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The code
// ---------------------------------------------------------------------------

/// RFC 9449 §10: a code whose request named a key redeems only with a
/// proof of it, and a refusal leaves the code unspent.
#[tokio::test]
async fn a_code_redeems_only_with_a_proof_of_the_key_its_request_named() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |_| {});
    let key = ProofKey::p256();
    let code = code_with(
        &server,
        &idp,
        "desktop",
        DESKTOP_REDIRECT,
        &[("dpop_jkt", &key.jkt())],
    )
    .await;
    let stored = state_of(&server)
        .get(&keys::code(&code.code))
        .await
        .expect("store")
        .expect("the code is kept");
    assert_eq!(stored.dpop_jkt.as_deref(), Some(key.jkt().as_str()));

    let missing = presenting(&server, code_form("desktop", &code), None).await;
    let error = refusal(&missing);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("dpop_jkt"), "{error:?}");
    let other = ProofKey::p256();
    let mismatch = presenting(
        &server,
        code_form("desktop", &code),
        Some(&token_proof(&other)),
    )
    .await;
    let error = refusal(&mismatch);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("not the key"), "{error:?}");

    let redeemed = presenting(
        &server,
        code_form("desktop", &code),
        Some(&token_proof(&key)),
    )
    .await;
    let (access, token_type, _) = tokens_of(&redeemed);
    assert_eq!(token_type, "DPoP");
    assert_eq!(bound_to(&access), Some(key.jkt()));
    assert_eq!(
        grant_record(&server, &access).await.dpop_jkt,
        Some(key.jkt())
    );
    assert!(refused_bearer(&server, &access).contains("DPoP-bound"));
}

#[tokio::test]
async fn dpop_jkt_is_checked_while_dpop_is_on_and_ignored_while_off() {
    let idp = Idp::start().await;
    let on = dpop_server(&idp, |_| {});
    let challenge = fresh_challenge();
    let refused = authorize_with(
        &on,
        "web-app",
        WEB_REDIRECT,
        &challenge,
        &[("dpop_jkt", "not-a-thumbprint")],
    )
    .await;
    assert_eq!(authorize_error(&refused), "invalid_request");
    let twice = format!(
        "{}&dpop_jkt=a&dpop_jkt=b",
        authorize_query("web-app", WEB_REDIRECT, &fresh_challenge())
    );
    let repeated = on.authorize(&twice, &BrowserCookies::default()).await;
    assert_eq!(authorize_error(&repeated), "invalid_request");

    let off = server(&idp);
    let code = code_with(
        &off,
        &idp,
        "web-app",
        WEB_REDIRECT,
        &[("dpop_jkt", "not-a-thumbprint")],
    )
    .await;
    let stored = state_of(&off)
        .get(&keys::code(&code.code))
        .await
        .expect("store")
        .expect("the code is kept");
    assert_eq!(stored.dpop_jkt, None);
    let redeemed = presenting(&off, code_form("web-app", &code), None).await;
    assert_eq!(tokens_of(&redeemed).1, "Bearer");
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

/// RFC 9449 §5: a public client's refresh token redeems only with the key
/// it was first redeemed with; a refused refresh leaves the token unspent.
#[tokio::test]
async fn a_public_clients_refresh_token_is_bound_to_its_proof_key() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |_| {});
    let key = ProofKey::p256();
    let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let (_, token_type, refresh) = tokens_of(
        &presenting(
            &server,
            code_form("desktop", &code),
            Some(&token_proof(&key)),
        )
        .await,
    );
    assert_eq!(token_type, "DPoP");

    let rotated = presenting(
        &server,
        refresh_form("desktop", &refresh),
        Some(&token_proof(&key)),
    )
    .await;
    let (access, token_type, refresh) = tokens_of(&rotated);
    assert_eq!(token_type, "DPoP");
    assert_eq!(bound_to(&access), Some(key.jkt()));

    let other = ProofKey::p256();
    for proof in [Some(token_proof(&other)), None] {
        let refused =
            presenting(&server, refresh_form("desktop", &refresh), proof.as_deref()).await;
        assert_eq!(refusal(&refused).error, "invalid_grant", "{proof:?}");
    }
    let again = presenting(
        &server,
        refresh_form("desktop", &refresh),
        Some(&token_proof(&key)),
    )
    .await;
    assert_eq!(tokens_of(&again).1, "DPoP");
}

/// A confidential client's refresh token is bound by its client
/// authentication: any key, or none, may refresh it.
#[tokio::test]
async fn a_confidential_clients_refresh_token_is_not_bound() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |_| {});
    let key = ProofKey::p256();
    let code = code_with(&server, &idp, "web-confidential", WEB_REDIRECT, &[]).await;
    let redeemed = presenting(
        &server,
        confidential(code_form("web-confidential", &code)),
        Some(&token_proof(&key)),
    )
    .await;
    let (access, token_type, refresh) = tokens_of(&redeemed);
    assert_eq!(token_type, "DPoP");
    assert_eq!(bound_to(&access), Some(key.jkt()));
    assert_eq!(grant_record(&server, &access).await.dpop_jkt, None);

    let other = ProofKey::p256();
    let rotated = presenting(
        &server,
        confidential(refresh_form("web-confidential", &refresh)),
        Some(&token_proof(&other)),
    )
    .await;
    let (access, _, refresh) = tokens_of(&rotated);
    assert_eq!(bound_to(&access), Some(other.jkt()));
    let unbound = presenting(
        &server,
        confidential(refresh_form("web-confidential", &refresh)),
        None,
    )
    .await;
    assert_eq!(tokens_of(&unbound).1, "Bearer");
}

/// A public grant redeemed without a proof is bound at its first refresh
/// with one: from then on its refresh tokens need that key.
#[tokio::test]
async fn a_public_grant_is_bound_at_its_first_refresh_with_a_proof() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |_| {});
    let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let (access, token_type, refresh) =
        tokens_of(&presenting(&server, code_form("desktop", &code), None).await);
    assert_eq!(token_type, "Bearer");
    assert_eq!(grant_record(&server, &access).await.dpop_jkt, None);

    let key = ProofKey::p256();
    let rotated = presenting(
        &server,
        refresh_form("desktop", &refresh),
        Some(&token_proof(&key)),
    )
    .await;
    let (access, _, refresh) = tokens_of(&rotated);
    assert_eq!(
        grant_record(&server, &access).await.dpop_jkt,
        Some(key.jkt())
    );
    let other = presenting(
        &server,
        refresh_form("desktop", &refresh),
        Some(&token_proof(&ProofKey::p256())),
    )
    .await;
    assert_eq!(refusal(&other).error, "invalid_grant");
}

/// Within the reuse grace, the successor goes again only to the key's
/// holder; a spent bound token presented without its key revokes nothing.
#[tokio::test]
async fn a_spent_bound_refresh_token_needs_its_key_to_retry_or_revoke() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |config| {
        interactive(config).refresh_tokens.reuse_grace_secs = 30;
    });
    let key = ProofKey::p256();
    let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let (_, _, first) = tokens_of(
        &presenting(
            &server,
            code_form("desktop", &code),
            Some(&token_proof(&key)),
        )
        .await,
    );
    let (_, _, second) = tokens_of(
        &presenting(
            &server,
            refresh_form("desktop", &first),
            Some(&token_proof(&key)),
        )
        .await,
    );
    let stranger = presenting(
        &server,
        refresh_form("desktop", &first),
        Some(&token_proof(&ProofKey::p256())),
    )
    .await;
    assert_eq!(refusal(&stranger).error, "invalid_grant");
    assert!(stranger.context.grant_events.is_empty());
    let retried = presenting(
        &server,
        refresh_form("desktop", &first),
        Some(&token_proof(&key)),
    )
    .await;
    assert_eq!(tokens_of(&retried).2, second);

    let without_grace = dpop_server(&idp, |_| {});
    let code = code_with(&without_grace, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let (_, _, first) = tokens_of(
        &presenting(
            &without_grace,
            code_form("desktop", &code),
            Some(&token_proof(&key)),
        )
        .await,
    );
    let (_, _, second) = tokens_of(
        &presenting(
            &without_grace,
            refresh_form("desktop", &first),
            Some(&token_proof(&key)),
        )
        .await,
    );
    let replayed = presenting(&without_grace, refresh_form("desktop", &first), None).await;
    assert_eq!(refusal(&replayed).error, "invalid_grant");
    assert!(replayed.context.grant_events.is_empty());
    let still_live = presenting(
        &without_grace,
        refresh_form("desktop", &second),
        Some(&token_proof(&key)),
    )
    .await;
    assert_eq!(tokens_of(&still_live).1, "DPoP");
}

/// RFC 9700 §4.14.2 against a stolen unbound token: whoever spends it
/// first with a proof binds the grant to their key, and the same token
/// presented again, without a proof or with a proof of another key,
/// within the reuse grace or past it, revokes the grant.
#[tokio::test]
async fn an_unbound_token_spent_again_after_its_grant_was_bound_revokes_the_grant() {
    let idp = Idp::start().await;
    for grace in [0, 30] {
        for replay_key in [None, Some(ProofKey::p256())] {
            let server = dpop_server(&idp, |config| {
                interactive(config).refresh_tokens.reuse_grace_secs = grace;
            });
            let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
            let (_, _, stolen) =
                tokens_of(&presenting(&server, code_form("desktop", &code), None).await);
            let thief = ProofKey::p256();
            let (access, _, successor) = tokens_of(
                &presenting(
                    &server,
                    refresh_form("desktop", &stolen),
                    Some(&token_proof(&thief)),
                )
                .await,
            );
            let grant = grant_record(&server, &access).await;
            assert_eq!(grant.dpop_jkt, Some(thief.jkt()));
            assert_eq!(grant.dpop_bound_generation, grant.generation);

            let proof = replay_key.as_ref().map(token_proof);
            let replayed =
                presenting(&server, refresh_form("desktop", &stolen), proof.as_deref()).await;
            assert_eq!(refusal(&replayed).error, "invalid_grant", "grace {grace}");
            assert!(
                replayed.context.grant_events.iter().any(|event| matches!(
                    event,
                    GrantEvent::Revoked {
                        reason: RevocationReason::RefreshReuse,
                        ..
                    }
                )),
                "grace {grace}, replay with a proof: {}",
                proof.is_some()
            );
            let after = presenting(
                &server,
                refresh_form("desktop", &successor),
                Some(&token_proof(&thief)),
            )
            .await;
            assert_eq!(refusal(&after).error, "invalid_grant", "grace {grace}");
        }
    }
}

/// Within the reuse grace, a public client that bound its grant at a
/// refresh and lost the answer receives the successor again with a proof
/// of the same key.
#[tokio::test]
async fn a_grant_bound_at_a_refresh_retries_within_the_grace_with_its_key() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |config| {
        interactive(config).refresh_tokens.reuse_grace_secs = 30;
    });
    let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let (_, _, first) = tokens_of(&presenting(&server, code_form("desktop", &code), None).await);
    let key = ProofKey::p256();
    let (_, _, second) = tokens_of(
        &presenting(
            &server,
            refresh_form("desktop", &first),
            Some(&token_proof(&key)),
        )
        .await,
    );
    let retried = presenting(
        &server,
        refresh_form("desktop", &first),
        Some(&token_proof(&key)),
    )
    .await;
    let (access, token_type, successor) = tokens_of(&retried);
    assert_eq!(successor, second);
    assert_eq!(token_type, "DPoP");
    assert_eq!(bound_to(&access), Some(key.jkt()));
    assert!(retried.context.grant_events.is_empty());
}

// ---------------------------------------------------------------------------
// Required proofs
// ---------------------------------------------------------------------------

/// With `required`, or a client that registered
/// `dpop_bound_access_tokens`, a code or refresh token without a proof is
/// `invalid_dpop_proof`, and stays unspent.
#[tokio::test]
async fn required_proofs_refuse_codes_and_refresh_tokens_without_one() {
    let idp = Idp::start().await;
    let required = dpop_server(&idp, |config| config.dpop.required = true);
    let flagged = dpop_server(&idp, |config| {
        for client in &mut config.clients {
            if client.client_id == "desktop" {
                client.dpop_bound_access_tokens = true;
            }
        }
    });
    for server in [&required, &flagged] {
        let key = ProofKey::p256();
        let code = code_with(server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
        let refused = presenting(server, code_form("desktop", &code), None).await;
        assert_eq!(refusal(&refused).error, "invalid_dpop_proof");
        let (_, _, refresh) = tokens_of(
            &presenting(
                server,
                code_form("desktop", &code),
                Some(&token_proof(&key)),
            )
            .await,
        );
        let refused = presenting(server, refresh_form("desktop", &refresh), None).await;
        assert_eq!(refusal(&refused).error, "invalid_grant");
        let rotated = presenting(
            server,
            refresh_form("desktop", &refresh),
            Some(&token_proof(&key)),
        )
        .await;
        assert_eq!(tokens_of(&rotated).1, "DPoP");
    }
    // A confidential client's grant is unbound, so `required` alone
    // decides.
    let code = code_with(&required, &idp, "web-confidential", WEB_REDIRECT, &[]).await;
    let (_, _, refresh) = tokens_of(
        &presenting(
            &required,
            confidential(code_form("web-confidential", &code)),
            Some(&token_proof(&ProofKey::p256())),
        )
        .await,
    );
    let refused = presenting(
        &required,
        confidential(refresh_form("web-confidential", &refresh)),
        None,
    )
    .await;
    assert_eq!(refusal(&refused).error, "invalid_dpop_proof");
}

/// A nonce at the token endpoint covers codes and refresh tokens too.
#[tokio::test]
async fn a_code_redeems_with_the_nonce_the_token_endpoint_hands_out() {
    let idp = Idp::start().await;
    let server = dpop_server(&idp, |config| {
        config.dpop.nonce = DpopNonceMode::TokenEndpoint;
    });
    let key = ProofKey::p256();
    let code = code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, &[]).await;
    let first = presenting(
        &server,
        code_form("desktop", &code),
        Some(&token_proof(&key)),
    )
    .await;
    assert_eq!(refusal(&first).error, "use_dpop_nonce");
    let nonce = first.dpop_nonce.clone().expect("a nonce");
    let mut claims = proof_claims("POST", TOKEN_HTU);
    claims["nonce"] = json!(nonce.as_str());
    let redeemed = presenting(
        &server,
        code_form("desktop", &code),
        Some(&key.proof(&claims)),
    )
    .await;
    assert_eq!(tokens_of(&redeemed).1, "DPoP");
}

// ---------------------------------------------------------------------------
// Dynamic registration
// ---------------------------------------------------------------------------

async fn register_with(
    server: &AuthorizationServer,
    extra: serde_json::Value,
) -> crate::runtime::authorization_server::dcr::ClientRegistration {
    let mut body = json!({
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    });
    if let Some(extra) = extra.as_object() {
        for (name, value) in extra {
            body[name] = value.clone();
        }
    }
    server
        .register_client(body.to_string().as_bytes(), None, None)
        .await
}

/// RFC 9449 §5.2 at registration: kept and echoed while DPoP is on, a
/// boolean only; ignored while DPoP is off.
#[tokio::test]
async fn a_registration_may_ask_for_bound_tokens_while_dpop_is_on() {
    let idp = Idp::start().await;
    let open = |config: &mut AuthorizationServerConfig| {
        interactive(config).dynamic_client_registration = serde_json::from_value(json!({
            "enabled": true,
            "allow_open": true,
        }))
        .expect("registration settings parse");
    };
    let on = dpop_server(&idp, open);
    let registration = register_with(&on, json!({ "dpop_bound_access_tokens": true })).await;
    let registered = registration.result.as_ref().expect("registered");
    assert!(registered.record.dpop_bound_access_tokens);
    assert_eq!(registered.body()["dpop_bound_access_tokens"], true);
    let registration = register_with(&on, json!({ "dpop_bound_access_tokens": "yes" })).await;
    assert!(matches!(
        registration.result,
        Err(crate::runtime::authorization_server::dcr::RegistrationError::InvalidClientMetadata(_))
    ));

    let mut config = config(&idp);
    open(&mut config);
    let off = server_with(&config);
    let registration = register_with(&off, json!({ "dpop_bound_access_tokens": "yes" })).await;
    let registered = registration.result.as_ref().expect("registered");
    assert!(!registered.record.dpop_bound_access_tokens);
    assert!(registered.body().get("dpop_bound_access_tokens").is_none());
}

// ---------------------------------------------------------------------------
// Records without a key binding
// ---------------------------------------------------------------------------

/// A record without the binding members reads as unbound, and a spent
/// token without a generation as one of generation 0.
#[test]
fn records_without_a_binding_read_as_unbound() {
    use crate::runtime::authorization_server::state::{CodeRecord, DcrClientRecord};
    let gid = "0123456789abcdef0123456789abcdef";
    let grant: GrantRecord = serde_json::from_value(json!({
        "status": "active",
        "principal": "p",
        "identity": { "subject": "s", "idp": "https://idp.test" },
        "client_id": "desktop",
        "client_kind": "static",
        "resource": RESOURCE,
        "redirect_uri": DESKTOP_REDIRECT,
        "issuer": GW_ISSUER,
        "abs_exp": 2,
        "last_used": 1,
        "generation": 1,
        "created": 1,
    }))
    .expect("an older grant record reads");
    assert_eq!(grant.dpop_jkt, None);
    assert_eq!(grant.dpop_bound_generation, 0);
    let spent: crate::runtime::authorization_server::state::RefreshUsedRecord =
        serde_json::from_value(json!({ "gid": gid, "spent_at": 1 }))
            .expect("an older spent record reads");
    assert_eq!(spent.generation, 0);
    let code: CodeRecord = serde_json::from_value(json!({
        "client_id": "desktop",
        "redirect_uri": DESKTOP_REDIRECT,
        "code_challenge": "c".repeat(43),
        "resource": RESOURCE,
        "gid": gid,
        "exp": 2,
    }))
    .expect("an older code record reads");
    assert_eq!(code.dpop_jkt, None);
    let registration: DcrClientRecord = serde_json::from_value(json!({
        "client_id": "mcpgdcr_ABC",
        "client_id_issued_at": 1,
        "redirect_uris": ["http://127.0.0.1/cb"],
        "grant_types": ["authorization_code"],
    }))
    .expect("an older registration reads");
    assert!(!registration.dpop_bound_access_tokens);
}
