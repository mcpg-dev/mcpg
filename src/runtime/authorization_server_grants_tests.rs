//! The authorization code grant at the token endpoint: a code is bound to
//! its client, PKCE verifier, redirect URI and resource and redeems once;
//! a replay revokes its grant on every replica. The grant it activates
//! joins its user's grants within the limit, carries a refresh token only
//! when the client and the kept IdP sign-in allow one, and backs an access
//! token the resource side accepts until the grant is revoked.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::runtime::authorization_server::grants::{
    GRANT_TYPE_AUTHORIZATION_CODE, GrantEvent, REFRESH_TOKEN_PREFIX,
};
use crate::runtime::authorization_server::state::{
    CodeRecord, GrantId, RevocationReason, RevokedId, memory_store,
};
use crate::runtime::authorization_server::{
    EmaBearerOutcome, IssuedToken, OAuthError, TokenRedemption, TokenRequestForm, TokenResponse,
};

/// A code issued to a client, and the verifier of its challenge.
struct Code {
    code: String,
    verifier: String,
}

/// Sign `client_id`'s user in through `idp`, which hands out
/// `refresh_token`, approving consent when it is asked; the code the
/// client receives.
async fn code_for(
    server: &AuthorizationServer,
    idp: &Idp,
    client_id: &str,
    redirect_uri: &str,
    refresh_token: Option<&str>,
) -> Code {
    let verifier = random_token().expect("random");
    let challenge = s256_challenge(&verifier);
    let response = server
        .authorize(
            &authorize_query(client_id, redirect_uri, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    let started = match response.outcome {
        BrowserOutcome::Consent(_) => started(&approve(server, &response).await, &challenge),
        _ => started(&response, &challenge),
    };
    let (_, params) = code_issued(&complete(server, idp, &started, refresh_token).await);
    Code {
        code: params["code"].clone(),
        verifier,
    }
}

async fn web_code(server: &AuthorizationServer, idp: &Idp, refresh_token: Option<&str>) -> Code {
    code_for(server, idp, "web-app", WEB_REDIRECT, refresh_token).await
}

/// The token request of a public client redeeming `code`.
fn code_form(client_id: &str, code: &Code) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_AUTHORIZATION_CODE.to_owned()),
        client_id: Some(client_id.to_owned()),
        code: Some(code.code.clone()),
        code_verifier: Some(code.verifier.clone()),
        ..Default::default()
    }
}

#[track_caller]
fn issued(redemption: &TokenRedemption) -> &(TokenResponse, IssuedToken) {
    redemption
        .result
        .as_ref()
        .unwrap_or_else(|error| panic!("the code should redeem: {error:?}"))
}

#[track_caller]
fn refusal(redemption: &TokenRedemption) -> &OAuthError {
    match redemption.result {
        Err(ref error) => error,
        Ok(_) => panic!("the token request should be refused"),
    }
}

/// Redeem `code` as `client_id`; the access token.
async fn access_token(server: &AuthorizationServer, client_id: &str, code: &Code) -> String {
    issued(&server.redeem(code_form(client_id, code), None).await)
        .0
        .access_token
        .clone()
}

fn grant_of(token: &str) -> GrantId {
    GrantId::parse(minted_claims(token)["gid"].as_str().expect("gid claim")).expect("a grant id")
}

#[track_caller]
fn caller_of(server: &AuthorizationServer, token: &str) -> EmaVerifiedIdentity {
    match server.verify_bearer(token) {
        EmaBearerOutcome::Verified(identity) => identity,
        EmaBearerOutcome::Invalid(reason) => panic!("the token should verify: {reason}"),
        EmaBearerOutcome::Refused(refusal) => {
            panic!("the token should verify: {}", refusal.description)
        }
        EmaBearerOutcome::NotOurs => panic!("the token should be this server's"),
        EmaBearerOutcome::Unavailable => panic!("the token should verify"),
    }
}

/// Why a token presented as a Bearer token is refused, with either
/// challenge.
#[track_caller]
fn refused_bearer(server: &AuthorizationServer, token: &str) -> String {
    match server.verify_bearer(token) {
        EmaBearerOutcome::Invalid(reason) => reason,
        EmaBearerOutcome::Refused(refusal) => refusal.description,
        _ => panic!("the token should be refused"),
    }
}

/// A registered public client of `redirect_uri` with `grant_types`.
fn client_with_grants(
    client_id: &str,
    redirect_uri: &str,
    grant_types: &[&str],
) -> crate::config::AuthorizationServerClientConfig {
    serde_json::from_value(json!({
        "client_id": client_id,
        "redirect_uris": [redirect_uri],
        "grant_types": grant_types,
    }))
    .expect("client parses")
}

// ---------------------------------------------------------------------------
// Redeeming a code
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_code_redeems_for_an_access_token_that_names_its_grant() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let code = web_code(&server, &idp, Some("idp-refresh-1")).await;
    let mut form = code_form("web-app", &code);
    form.redirect_uri = Some(WEB_REDIRECT.to_owned());
    form.resource = Some(format!("{RESOURCE}/"));
    form.scope = Some("openid mcp:admin".to_owned());
    let redemption = server.redeem(form, None).await;
    let (response, issued) = issued(&redemption);

    assert_eq!(response.token_type, "Bearer");
    assert_eq!(
        response.expires_in, 900,
        "the lifetime of interactive tokens, not of ID-JAG ones"
    );
    assert_eq!(
        response.scope.as_deref(),
        Some("mcp:tools"),
        "the approved scopes; the token request's scope is not read"
    );
    assert_eq!(response.resource, RESOURCE);
    let refresh = response
        .refresh_token
        .as_deref()
        .expect("a refresh token for a client that may refresh");
    assert!(refresh.starts_with(REFRESH_TOKEN_PREFIX));
    assert_eq!(refresh.len(), REFRESH_TOKEN_PREFIX.len() + 43);

    let header = jsonwebtoken::decode_header(&response.access_token).expect("JWT");
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let claims = minted_claims(&response.access_token);
    let gid = grant_of(&response.access_token);
    assert_eq!(claims["gty"], "authorization_code");
    assert_eq!(claims["iss"], GW_ISSUER);
    assert_eq!(claims["sub"], USER);
    assert_eq!(claims["idp"], idp.issuer);
    assert_eq!(claims["client_id"], "web-app");
    assert_eq!(claims["aud"], RESOURCE);
    assert_eq!(claims["scope"], "mcp:tools");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["groups"], json!(["engineering"]));
    assert_eq!(claims["amr"], json!(["pwd", "mfa"]));
    let auth_time = claims["auth_time"].as_u64().expect("auth_time");
    assert_eq!(
        claims["exp"].as_u64().expect("exp") - claims["iat"].as_u64().expect("iat"),
        900
    );

    let grant = state
        .get(&keys::grant(&gid))
        .await
        .expect("store")
        .expect("the grant is kept");
    assert_eq!(grant.status, GrantStatus::Active);
    assert_eq!(grant.generation, 1);
    assert!(
        grant.abs_exp.abs_diff(now_unix() + 30 * 86_400) <= 2,
        "{}",
        grant.abs_exp
    );
    assert!(
        state
            .exists(&keys::principal_grant(&principal_of_user(&idp), &gid))
            .await
            .expect("store"),
        "the grant is one of its user's"
    );
    let index = state
        .get(&keys::refresh(refresh))
        .await
        .expect("store")
        .expect("the refresh token is known by its hash");
    assert_eq!(index.gid, gid);
    assert_eq!(index.generation, 1);
    assert_eq!(index.client_id, "web-app");
    for sealed in raw(&server, "").await {
        for secret in [
            refresh,
            code.code.as_str(),
            code.verifier.as_str(),
            response.access_token.as_str(),
        ] {
            assert!(!contains(&sealed, secret), "the store holds no {secret}");
        }
    }

    let caller = caller_of(&server, &response.access_token);
    assert_eq!(
        format!(
            "verified::{}::{}::{}",
            caller.auth_provider, caller.issuer, caller.subject_id
        ),
        principal_of_user(&idp),
        "the principal an ID-JAG of the same user resolves to"
    );
    assert_eq!(caller.attributes["grant_type"], "authorization_code");
    assert_eq!(caller.attributes["grant_id"], gid.as_str());
    assert_eq!(caller.attributes["auth_time"], auth_time.to_string());
    assert_eq!(caller.attributes["client_id"], "web-app");
    assert_eq!(caller.scopes, ["mcp:tools"]);
    assert_eq!(caller.groups, ["engineering"]);

    let issued_grant = issued.grant.as_ref().expect("an interactive grant");
    assert_eq!(issued_grant.gid, gid);
    assert!(issued_grant.refresh_token_issued);
    assert_eq!(issued_grant.client_kind, ClientKind::Static);
    let events = redemption.audit_events("req-1");
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.action, "mcpg.as.token_issued");
    assert_eq!(event.actor.subject_id.as_deref(), Some(USER));
    assert_eq!(event.actor.issuer.as_deref(), Some(idp.issuer));
    assert_eq!(event.actor.auth_provider.as_deref(), Some("ema"));
    assert_eq!(event.resource.as_deref(), Some(RESOURCE));
    assert_eq!(event.details["grant_type"], "authorization_code");
    assert_eq!(event.details["gid"], gid.as_str());
    assert_eq!(event.details["client_id"], "web-app");
    assert_eq!(event.details["idp"], idp.issuer);
    assert_eq!(event.details["refresh_token_issued"], true);
    assert_eq!(event.details["token_jti"], claims["jti"]);
    let text = serde_json::to_string(&events).expect("serializes");
    for secret in [
        refresh,
        code.code.as_str(),
        code.verifier.as_str(),
        response.access_token.as_str(),
    ] {
        assert!(!text.contains(secret), "the audit carries no {secret}");
    }
    let debug = format!("{response:?} {:?}", code_form("web-app", &code));
    for secret in [refresh, code.code.as_str(), code.verifier.as_str()] {
        assert!(!debug.contains(secret), "Debug shows no {secret}: {debug}");
    }
    assert!(!debug.contains(&response.access_token));
}

#[tokio::test]
async fn a_sign_in_without_an_idp_refresh_token_gets_no_refresh_token() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let (response, issued) = issued(&redemption);
    assert!(
        response.refresh_token.is_none(),
        "while refreshes check the IdP, only a kept IdP refresh token allows one"
    );
    assert!(
        !issued
            .grant
            .as_ref()
            .expect("an interactive grant")
            .refresh_token_issued
    );
    let gid = grant_of(&response.access_token);
    let entry = state_of(&server)
        .store()
        .get(keys::grant(&gid).as_str())
        .await
        .expect("store")
        .expect("the grant is kept while its access token lives");
    let until = entry
        .expires_at
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .expect("the grant expires")
        .as_secs();
    assert!(
        until.abs_diff(now_unix() + 900 + server.leeway_secs) <= 2,
        "a grant without a refresh token lives as long as its access token: {until}"
    );
    caller_of(&server, &response.access_token);
}

#[tokio::test]
async fn a_refresh_token_needs_the_clients_grant_type_and_refresh_tokens_on() {
    let idp = Idp::start().await;
    let mut one_shot = config(&idp);
    one_shot.clients.push(client_with_grants(
        "one-shot",
        WEB_REDIRECT,
        &["authorization_code"],
    ));
    let server = server_with(&one_shot);
    let code = code_for(
        &server,
        &idp,
        "one-shot",
        WEB_REDIRECT,
        Some("idp-refresh-1"),
    )
    .await;
    let redemption = server.redeem(code_form("one-shot", &code), None).await;
    assert!(issued(&redemption).0.refresh_token.is_none());

    let mut refresh_off = config(&idp);
    interactive(&mut refresh_off).refresh_tokens.enabled = false;
    let server = server_with(&refresh_off);
    let code = web_code(&server, &idp, Some("idp-refresh-1")).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    assert!(issued(&redemption).0.refresh_token.is_none());

    let mut unchecked = config(&idp);
    interactive(&mut unchecked)
        .refresh_tokens
        .revalidate_with_idp = false;
    let server = server_with(&unchecked);
    let code = web_code(&server, &idp, None).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    assert!(
        issued(&redemption).0.refresh_token.is_some(),
        "without IdP checks no IdP refresh token is needed"
    );
}

// ---------------------------------------------------------------------------
// What a code is bound to
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_code_redeems_only_for_its_own_client() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let redemption = server.redeem(code_form("desktop", &code), None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("another client"), "{error:?}");
    assert!(redemption.context.grant_events.is_empty());
    access_token(&server, "web-app", &code).await;
}

#[tokio::test]
async fn a_wrong_verifier_is_refused_and_revokes_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let wrong = Code {
        code: code.code.clone(),
        verifier: random_token().expect("random"),
    };
    let redemption = server.redeem(code_form("web-app", &wrong), None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(
        error.description.contains("code_verifier"),
        "{}",
        error.description
    );
    assert!(redemption.context.grant_events.is_empty());
    let token = access_token(&server, "web-app", &code).await;

    let again = server.redeem(code_form("web-app", &wrong), None).await;
    assert_eq!(refusal(&again).error, "invalid_grant");
    assert!(
        again.context.grant_events.is_empty(),
        "a replay that fails PKCE revokes nothing (OAuth 2.1 section 7.5.3)"
    );
    caller_of(&server, &token);
}

#[tokio::test]
async fn the_code_and_verifier_must_be_present_and_well_formed() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let cases: [(fn(&mut TokenRequestForm), &str); 4] = [
        (|form| form.code = None, "code is required"),
        (|form| form.code_verifier = None, "code_verifier required"),
        (
            |form| form.code_verifier = Some("a".repeat(42)),
            "43 to 128",
        ),
        (
            |form| form.code_verifier = Some(format!("{}!", "a".repeat(43))),
            "43 to 128",
        ),
    ];
    for (change, expected) in cases {
        let mut form = code_form("web-app", &code);
        change(&mut form);
        let redemption = server.redeem(form, None).await;
        let error = refusal(&redemption);
        assert_eq!(error.error, "invalid_request", "{expected}");
        assert!(
            error.description.contains(expected),
            "{expected}: {}",
            error.description
        );
    }
    access_token(&server, "web-app", &code).await;
}

#[tokio::test]
async fn the_redirect_uri_and_resource_when_named_are_the_requests() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;

    for other in ["https://app.example/cb/", "https://APP.example/cb"] {
        let mut form = code_form("web-app", &code);
        form.redirect_uri = Some(other.to_owned());
        let redemption = server.redeem(form, None).await;
        let error = refusal(&redemption);
        assert_eq!(error.error, "invalid_grant", "{other}");
        assert!(error.description.contains("redirect_uri"), "{error:?}");
    }
    let mut form = code_form("web-app", &code);
    form.resource = Some("https://gw.test/other".to_owned());
    assert_eq!(
        refusal(&server.redeem(form, None).await).error,
        "invalid_target"
    );

    let mut form = code_form("web-app", &code);
    form.redirect_uri = Some(WEB_REDIRECT.to_owned());
    form.resource = Some(RESOURCE.to_owned());
    let redemption = server.redeem(form, None).await;
    assert!(
        redemption.context.grant_events.is_empty(),
        "the refusals before it spent nothing"
    );
    issued(&redemption);
}

#[tokio::test]
async fn an_unknown_or_expired_code_is_refused() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    for unknown in [
        format!(
            "{AUTHORIZATION_CODE_PREFIX}{}",
            random_token().expect("random")
        ),
        "not-a-code".to_owned(),
        format!("{AUTHORIZATION_CODE_PREFIX}{}", "a".repeat(200)),
    ] {
        let form = code_form(
            "web-app",
            &Code {
                code: unknown,
                verifier: random_token().expect("random"),
            },
        );
        let redemption = server.redeem(form, None).await;
        assert_eq!(refusal(&redemption).error, "invalid_grant");
        assert!(redemption.context.gid.is_none());
    }

    let code = web_code(&server, &idp, None).await;
    let key = keys::code(&code.code);
    let record: CodeRecord = state.get(&key).await.expect("store").expect("stored");
    let expired = CodeRecord {
        exp: now_unix() - 1,
        ..record
    };
    state
        .put(&key, &expired, Duration::from_secs(60))
        .await
        .expect("store");
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("expired"), "{error:?}");
}

#[tokio::test]
async fn a_code_whose_pending_grant_is_gone_issues_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let code = web_code(&server, &idp, Some("idp-refresh-1")).await;
    let record = state
        .get(&keys::code(&code.code))
        .await
        .expect("store")
        .expect("stored");
    state
        .delete(&keys::grant(&record.gid))
        .await
        .expect("store");
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("no longer valid"), "{error:?}");
}

/// A reload between the sign-in and the redemption that stops trusting
/// the client for the IdP issues nothing, though the state carries over.
#[tokio::test]
async fn a_code_redeems_only_while_the_idp_still_admits_the_client() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let mut reloaded = config(&idp);
    reloaded.trusted_idps[0].allowed_clients = vec!["desktop".to_owned()];
    let reloaded = build(&reloaded, state_of(&server).clone());
    let redemption = reloaded.redeem(code_form("web-app", &code), None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("no longer issue"), "{error:?}");
}

// ---------------------------------------------------------------------------
// Replay and revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_replayed_code_revokes_its_grant_and_the_tokens_it_issued() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let code = web_code(&server, &idp, Some("idp-refresh-1")).await;
    let first = server.redeem(code_form("web-app", &code), None).await;
    let token = issued(&first).0.access_token.clone();
    let gid = grant_of(&token);
    caller_of(&server, &token);

    let replay = server.redeem(code_form("web-app", &code), None).await;
    let error = refusal(&replay);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("already been redeemed"));
    assert_eq!(
        replay.context.grant_events,
        [
            GrantEvent::CodeReplay {
                gid: gid.clone(),
                client_id: "web-app".to_owned(),
            },
            GrantEvent::Revoked {
                gid: gid.clone(),
                reason: RevocationReason::CodeReplay,
                client_id: Some("web-app".to_owned()),
            },
        ]
    );
    assert_eq!(refused_bearer(&server, &token), "token revoked");
    assert!(
        state
            .exists(&keys::revoked(&RevokedId::Grant(gid.clone())))
            .await
            .expect("store"),
        "the revocation is stored for the other replicas"
    );
    assert!(
        state
            .get(&keys::grant(&gid))
            .await
            .expect("store")
            .is_none(),
        "the grant is gone, and with it every refresh"
    );
    assert!(
        !state
            .exists(&keys::principal_grant(&principal_of_user(&idp), &gid))
            .await
            .expect("store")
    );

    let events = replay.audit_events("req-9");
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "mcpg.as.code_replay_detected",
            "mcpg.as.grant_revoked",
            "mcpg.auth.failed"
        ]
    );
    assert_eq!(events[0].details["gid"], gid.as_str());
    assert_eq!(events[1].details["reason"], "code_replay");
    assert_eq!(events[2].details["auth_method"], "as_token");
    assert_eq!(events[2].details["grant_type"], "authorization_code");
    assert_eq!(events[2].details["gid"], gid.as_str());
    let text = serde_json::to_string(&events).expect("serializes");
    assert!(!text.contains(&code.code) && !text.contains(&code.verifier));

    let again = server.redeem(code_form("web-app", &code), None).await;
    assert_eq!(refusal(&again).error, "invalid_grant");
}

#[tokio::test]
async fn a_revocation_on_one_replica_reaches_the_others_at_their_next_read() {
    let idp = Idp::start().await;
    let kv = memory_store();
    let keyring = Arc::new(StateKeyring::process().expect("key"));
    let replica = || {
        build(
            &config(&idp),
            InteractiveState::new(StateParts {
                kv: Arc::clone(&kv),
                backend: StateBackend::InProcess,
                keyring: Arc::clone(&keyring),
                issuer: GW_ISSUER.to_owned(),
                revoked: Arc::default(),
                revocation_interval: Duration::from_secs(3600),
            })
            .expect("state"),
        )
    };
    let (a, b) = (replica(), replica());
    let code = web_code(&a, &idp, None).await;
    let token = access_token(&a, "web-app", &code).await;
    caller_of(&b, &token);

    let replay = b.redeem(code_form("web-app", &code), None).await;
    assert_eq!(
        refusal(&replay).error,
        "invalid_grant",
        "the code is spent on every replica"
    );
    assert_eq!(refused_bearer(&b, &token), "token revoked");
    caller_of(&a, &token);
    assert_eq!(
        state_of(&a).poll_revocations().await.expect("store"),
        1,
        "one revocation to read"
    );
    assert_eq!(refused_bearer(&a, &token), "token revoked");
}

/// A reload that drops the `login` block leaves no sign-in state, and a
/// replica whose store is unavailable learns no revocation: neither can
/// tell a revoked interactive grant from a live one, so neither accepts
/// its tokens. ID-JAG tokens do not depend on that state.
#[tokio::test]
async fn an_interactive_token_is_refused_where_its_revocation_cannot_be_learned() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    let token = access_token(&server, "web-app", &code).await;
    server.redeem(code_form("web-app", &code), None).await;
    assert_eq!(refused_bearer(&server, &token), "token revoked");

    let mut without_login = config(&idp);
    without_login.trusted_idps[0].login = None;
    let reloaded = AuthorizationServer::from_config(
        &without_login,
        Some(&resource_metadata()),
        ReplayLedger::in_process(),
    )
    .expect("server builds")
    .with_interactive_state(None);
    let unavailable = build(
        &config(&idp),
        InteractiveState::new(StateParts {
            kv: Arc::new(UnavailableStore::new("no coordinator store")),
            backend: StateBackend::Unavailable,
            keyring: Arc::new(StateKeyring::process().expect("key")),
            issuer: GW_ISSUER.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })
        .expect("state"),
    );
    let live = access_token(&server, "web-app", &web_code(&server, &idp, None).await).await;
    caller_of(&server, &live);
    for elsewhere in [&reloaded, &unavailable] {
        for interactive in [&token, &live] {
            let reason = refused_bearer(elsewhere, interactive);
            assert!(reason.contains("interactive sign-in"), "{reason}");
        }
    }
    let assertion = make_id_jag(AssertionOverrides {
        iss: idp.issuer,
        ..Default::default()
    });
    let ema = redeem(&reloaded, &assertion)
        .await
        .expect("an ID-JAG redeems without sign-in state");
    caller_of(&reloaded, &ema.access_token);
}

#[tokio::test]
async fn a_new_grant_beyond_the_limit_revokes_the_users_oldest() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    interactive(&mut config)
        .refresh_tokens
        .max_grants_per_principal = 1;
    let server = server_with(&config);
    let first = web_code(&server, &idp, Some("idp-refresh-1")).await;
    let first = access_token(&server, "web-app", &first).await;
    let second = web_code(&server, &idp, Some("idp-refresh-2")).await;
    let redemption = server.redeem(code_form("web-app", &second), None).await;
    let second = issued(&redemption).0.access_token.clone();
    assert_eq!(
        redemption.context.grant_events,
        [GrantEvent::Revoked {
            gid: grant_of(&first),
            reason: RevocationReason::MaxGrants,
            client_id: Some("web-app".to_owned()),
        }]
    );
    assert_eq!(
        redemption.audit_events("req-3")[0].action,
        "mcpg.as.grant_revoked"
    );
    assert_eq!(refused_bearer(&server, &first), "token revoked");
    caller_of(&server, &second);
}

// ---------------------------------------------------------------------------
// Who may use the grant
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_without_the_grant_type_is_unauthorized() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let form = TokenRequestForm {
        grant_type: Some(GRANT_TYPE_AUTHORIZATION_CODE.to_owned()),
        client_id: Some(CLIENT_ID.to_owned()),
        client_secret: Some(CLIENT_SECRET.to_owned()),
        code: Some(format!("{AUTHORIZATION_CODE_PREFIX}x")),
        code_verifier: Some(random_token().expect("random")),
        ..Default::default()
    };
    let redemption = server.redeem(form, None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "unauthorized_client");
    assert!(
        error.description.contains("authorization_code"),
        "{error:?}"
    );

    let mut form = code_form(
        "web-app",
        &Code {
            code: "c".to_owned(),
            verifier: random_token().expect("random"),
        },
    );
    form.client_secret = Some("stray".to_owned());
    assert_eq!(
        refusal(&server.redeem(form, None).await).error,
        "invalid_client",
        "a public client presents no secret"
    );
}

#[tokio::test]
async fn without_a_login_idp_the_code_grant_is_unsupported() {
    let server = test_server().await;
    let form = TokenRequestForm {
        grant_type: Some(GRANT_TYPE_AUTHORIZATION_CODE.to_owned()),
        client_id: Some(CLIENT_ID.to_owned()),
        client_secret: Some(CLIENT_SECRET.to_owned()),
        code: Some(format!("{AUTHORIZATION_CODE_PREFIX}x")),
        ..Default::default()
    };
    let redemption = server.redeem(form, None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "unsupported_grant_type");
    assert!(error.description.contains("only jwt-bearer"), "{error:?}");
    assert_eq!(redemption.context.grant.as_str(), "authorization_code");
}

#[tokio::test]
async fn a_store_failure_issues_nothing() {
    let idp = Idp::start().await;
    let broken = build(
        &config(&idp),
        InteractiveState::new(StateParts {
            kv: Arc::new(UnavailableStore::new("disk full")),
            backend: StateBackend::InProcess,
            keyring: Arc::new(StateKeyring::process().expect("key")),
            issuer: GW_ISSUER.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })
        .expect("state"),
    );
    let form = code_form(
        "web-app",
        &Code {
            code: format!(
                "{AUTHORIZATION_CODE_PREFIX}{}",
                random_token().expect("random")
            ),
            verifier: random_token().expect("random"),
        },
    );
    let redemption = broken.redeem(form, None).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "temporarily_unavailable");
    assert_eq!(error.status, 503);
}

#[tokio::test]
async fn a_dynamically_registered_id_is_known_only_while_registration_is_on() {
    let idp = Idp::start().await;
    let server = server(&idp);
    assert!(!server.knows_client("mcpgdcr_abc"));
    let mut config = config(&idp);
    interactive(&mut config).dynamic_client_registration.enabled = true;
    let server = server_with(&config);
    assert!(server.knows_client("mcpgdcr_abc"));
    assert!(!server.knows_client("other_abc"));
}

#[tokio::test]
async fn code_grants_are_counted_by_grant_and_revocations_by_reason() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let code = web_code(&server, &idp, None).await;
    access_token(&server, "web-app", &code).await;
    server.redeem(code_form("web-app", &code), None).await;
    for metric in [
        format!(
            "mcpg_ema_token_requests_total{{outcome=issued,error=none,idp={},\
             grant=authorization_code}}",
            idp.issuer
        ),
        format!(
            "mcpg_ema_token_requests_total{{outcome=refused,error=invalid_grant,idp={},\
             grant=authorization_code}}",
            idp.issuer
        ),
        "mcpg_ema_token_latency_ms{outcome=issued,grant=authorization_code}".to_owned(),
        "mcpg_as_grants_revoked_total{reason=code_replay,outcome=ok}".to_owned(),
    ] {
        assert!(
            captured.seen(&metric),
            "{metric}: {:?}",
            captured.recorded()
        );
    }
}

#[path = "authorization_server_refresh_tests.rs"]
mod refresh_grant;

#[path = "authorization_server_revocation_tests.rs"]
mod token_revocation;

#[path = "authorization_server_vault_tests.rs"]
mod idp_session_vault;

#[path = "authorization_server_dcr_tests.rs"]
mod client_registration;

#[path = "authorization_server_dpop_grant_tests.rs"]
mod dpop_grants;

#[path = "authorization_server_rar_grant_tests.rs"]
mod rar_grants;
