//! Token revocation (RFC 7009): a client revokes the grant behind its
//! refresh or access token, or the `jti` of an access token without a
//! grant; another client's token is refused and revokes nothing; an
//! unknown token answers as revoked. The user's last grant takes the IdP
//! sign-in an MCP client's sign-in stored with it.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::runtime::authorization_server::MintedClaims;
use crate::runtime::authorization_server::grants::GRANT_TYPE_REFRESH_TOKEN;
use crate::runtime::authorization_server::revocation::{
    RevocationRequestForm, RevokedTokenKind, TokenRevocation,
};
use crate::runtime::authorization_server::state::{IdpSessionRecord, StateKeyring};
use crate::runtime::authorization_server::vault::IdpSessionEnd;

const IDP_REFRESH: &str = "idp-refresh-1";

/// A signed-in web client's access and refresh tokens.
async fn signed_in(server: &AuthorizationServer, idp: &Idp) -> (String, String) {
    let code = web_code(server, idp, Some(IDP_REFRESH)).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let (response, _) = issued(&redemption);
    (
        response.access_token.clone(),
        response.refresh_token.clone().expect("a refresh token"),
    )
}

fn revoke_form(client_id: &str, token: &str) -> RevocationRequestForm {
    RevocationRequestForm {
        token: Some(token.to_owned()),
        client_id: Some(client_id.to_owned()),
        ..Default::default()
    }
}

async fn revoke(server: &AuthorizationServer, client_id: &str, token: &str) -> TokenRevocation {
    server
        .revoke_token(revoke_form(client_id, token), None)
        .await
}

#[track_caller]
fn revoked_ok(revocation: &TokenRevocation) {
    if let Err(ref error) = revocation.result {
        panic!("the revocation should be answered 200: {error:?}");
    }
}

async fn refreshes(server: &AuthorizationServer, refresh_token: &str) -> bool {
    server
        .redeem(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_REFRESH_TOKEN.to_owned()),
                client_id: Some("web-app".to_owned()),
                refresh_token: Some(refresh_token.to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .result
        .is_ok()
}

async fn stored(server: &AuthorizationServer, idp: &Idp) -> Option<IdpSessionRecord> {
    state_of(server)
        .get(&keys::idp_session(&principal_of_user(idp)))
        .await
        .expect("store")
}

/// Record the fixture user's IdP sign-in as stored long ago, past the
/// window in which a code may still be redeemed for it.
async fn stored_long_ago(server: &AuthorizationServer, idp: &Idp) {
    let mut record = stored(server, idp).await.expect("a sign-in is stored");
    record.obtained_at = now_unix() - 3600;
    state_of(server)
        .put(
            &keys::idp_session(&principal_of_user(idp)),
            &record,
            Duration::from_secs(3600),
        )
        .await
        .expect("store");
}

#[tokio::test]
async fn revoking_a_refresh_token_revokes_its_grant_and_releases_the_idp_sign_in() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (access, refresh) = signed_in(&server, &idp).await;
    let gid = grant_of(&access);
    stored_long_ago(&server, &idp).await;

    let revocation = revoke(&server, "web-app", &refresh).await;
    revoked_ok(&revocation);
    assert_eq!(revocation.token_kind, RevokedTokenKind::RefreshToken);
    assert_eq!(revocation.context.gid.as_ref(), Some(&gid));
    assert_eq!(
        revocation.context.grant_events,
        [
            GrantEvent::Revoked {
                gid: gid.clone(),
                reason: RevocationReason::Client,
                client_id: Some("web-app".to_owned()),
            },
            GrantEvent::IdpSessionRemoved {
                idp: idp.issuer.to_owned(),
                subject: USER.to_owned(),
                reason: IdpSessionEnd::LastGrantRevoked,
            },
        ]
    );
    let released = revocation
        .released
        .as_ref()
        .expect("the IdP refresh token is released for revocation at the IdP");
    assert_eq!(released.refresh_token.expose(), IDP_REFRESH);
    assert_eq!(released.issuer, idp.issuer);
    assert_eq!(released.client_id, LOGIN_CLIENT);
    assert!(stored(&server, &idp).await.is_none());
    assert_eq!(refused_bearer(&server, &access), "token revoked");
    assert!(!refreshes(&server, &refresh).await);

    let events = revocation.audit_events("req-v");
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        ["mcpg.as.grant_revoked", "mcpg.as.idp_session_removed"]
    );
    assert_eq!(events[0].details["reason"], "client");
    let text = serde_json::to_string(&events).expect("serializes");
    assert!(!text.contains(&refresh) && !text.contains(IDP_REFRESH));
    assert!(!format!("{revocation:?}").contains(IDP_REFRESH));

    let again = revoke(&server, "web-app", &refresh).await;
    revoked_ok(&again);
    assert!(
        again.context.grant_events.is_empty(),
        "nothing is left to revoke"
    );
}

#[tokio::test]
async fn the_idp_sign_in_stays_while_the_user_holds_another_grant_or_just_signed_in() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (_, first) = signed_in(&server, &idp).await;
    let (second_access, _) = signed_in(&server, &idp).await;
    stored_long_ago(&server, &idp).await;
    let revocation = revoke(&server, "web-app", &first).await;
    revoked_ok(&revocation);
    assert!(revocation.released.is_none());
    assert!(stored(&server, &idp).await.is_some());
    caller_of(&server, &second_access);

    let server = server_with(&config(&idp));
    let (_, refresh) = signed_in(&server, &idp).await;
    let revocation = revoke(&server, "web-app", &refresh).await;
    revoked_ok(&revocation);
    assert!(
        revocation.released.is_none(),
        "a sign-in stored within a code's lifetime may back a code not yet redeemed"
    );
    assert!(stored(&server, &idp).await.is_some());
}

#[tokio::test]
async fn revoking_an_access_token_revokes_its_grant_even_once_expired() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (access, refresh) = signed_in(&server, &idp).await;
    let revocation = revoke(&server, "web-app", &access).await;
    revoked_ok(&revocation);
    assert_eq!(revocation.token_kind, RevokedTokenKind::AccessToken);
    assert!(matches!(
        revocation.context.grant_events.first(),
        Some(GrantEvent::Revoked {
            reason: RevocationReason::Client,
            ..
        })
    ));
    assert!(!refreshes(&server, &refresh).await, "the grant is gone");

    let (access, refresh) = signed_in(&server, &idp).await;
    let mut claims: MintedClaims = serde_json::from_value(minted_claims(&access)).expect("claims");
    claims.iat = now_unix() - 7200;
    claims.exp = now_unix() - 3600;
    let expired = server.signing_keys[0].sign(&claims).expect("signs");
    assert!(matches!(
        server.verify_bearer(&expired),
        EmaBearerOutcome::Invalid(_)
    ));
    let revocation = revoke(&server, "web-app", &expired).await;
    revoked_ok(&revocation);
    assert!(!revocation.context.grant_events.is_empty());
    assert!(!refreshes(&server, &refresh).await);
}

#[tokio::test]
async fn revoking_an_access_token_without_a_grant_revokes_its_jti() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let token = server.mint_access_token_for_tests(USER, idp.issuer, Some("mcp:tools"));
    caller_of(&server, &token);
    let other = server.mint_access_token_for_tests(USER, idp.issuer, Some("mcp:tools"));
    let revocation = revoke(&server, "web-app", &token).await;
    revoked_ok(&revocation);
    let jti = minted_claims(&token)["jti"]
        .as_str()
        .expect("jti")
        .to_owned();
    assert_eq!(
        revocation.context.grant_events,
        [GrantEvent::TokenRevoked {
            jti: jti.clone(),
            client_id: "web-app".to_owned(),
        }]
    );
    assert_eq!(
        revocation.audit_events("req-j")[0].action,
        "mcpg.as.token_revoked"
    );
    assert_eq!(refused_bearer(&server, &token), "token revoked");
    caller_of(&server, &other);
    assert!(
        state_of(&server)
            .exists(&keys::revoked(&RevokedId::access_token(&jti)))
            .await
            .expect("store"),
        "stored for the other replicas"
    );
}

#[tokio::test]
async fn a_token_of_another_client_is_refused_and_revokes_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (access, refresh) = signed_in(&server, &idp).await;
    for token in [&refresh, &access] {
        let revocation = revoke(&server, "desktop", token).await;
        let error = revocation.result.as_ref().expect_err("refused");
        assert_eq!(error.error, "invalid_grant");
        assert!(revocation.context.grant_events.is_empty());
        let events = revocation.audit_events("req-o");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "mcpg.auth.failed");
        assert_eq!(events[0].details["auth_method"], "as_revoke");
    }
    caller_of(&server, &access);
    assert!(refreshes(&server, &refresh).await);
}

#[tokio::test]
async fn an_unknown_token_answers_as_revoked() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (access, _) = signed_in(&server, &idp).await;
    let mut forged = access.clone();
    forged.push('x');
    let foreign = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({ "iss": "https://elsewhere.test", "exp": now_unix() + 60 }),
        &EncodingKey::from_secret(b"another-issuers-secret-0123456789"),
    )
    .expect("encodes");
    for (token, kind) in [
        (
            format!("{REFRESH_TOKEN_PREFIX}{}", random_token().expect("random")),
            RevokedTokenKind::RefreshToken,
        ),
        (forged, RevokedTokenKind::AccessToken),
        (foreign, RevokedTokenKind::Unknown),
        ("opaque".to_owned(), RevokedTokenKind::Unknown),
    ] {
        let revocation = revoke(&server, "web-app", &token).await;
        revoked_ok(&revocation);
        assert_eq!(revocation.token_kind, kind);
        assert!(revocation.context.grant_events.is_empty());
        assert!(revocation.audit_events("req-u").is_empty());
    }
    caller_of(&server, &access);
}

#[tokio::test]
async fn revocation_authenticates_the_client() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let (_, refresh) = signed_in(&server, &idp).await;
    let revocation = server
        .revoke_token(
            RevocationRequestForm {
                client_secret: Some("wrong-secret".to_owned()),
                ..revoke_form(CLIENT_ID, &refresh)
            },
            None,
        )
        .await;
    assert_eq!(
        revocation.result.as_ref().expect_err("refused").error,
        "invalid_client"
    );
    let missing = server
        .revoke_token(
            RevocationRequestForm {
                token: None,
                ..revoke_form("web-app", "")
            },
            None,
        )
        .await;
    assert_eq!(
        missing.result.as_ref().expect_err("refused").error,
        "invalid_request"
    );
    let stray = server
        .revoke_token(
            RevocationRequestForm {
                client_secret: Some("stray".to_owned()),
                ..revoke_form("web-app", &refresh)
            },
            None,
        )
        .await;
    assert_eq!(
        stray.result.as_ref().expect_err("refused").error,
        "invalid_client"
    );
    assert!(refreshes(&server, &refresh).await);
    let form = RevocationRequestForm {
        token_type_hint: Some("access_token".to_owned()),
        ..revoke_form("web-app", "x")
    };
    assert!(!format!("{:?}", revoke_form("web-app", &refresh)).contains(&refresh));
    revoked_ok(&server.revoke_token(form, None).await);
}

#[tokio::test]
async fn a_revocation_the_store_cannot_record_answers_503() {
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
    let token = format!("{REFRESH_TOKEN_PREFIX}{}", random_token().expect("random"));
    let revocation = revoke(&broken, "web-app", &token).await;
    let error = revocation.result.as_ref().expect_err("refused");
    assert_eq!(error.error, "temporarily_unavailable");
    assert_eq!(error.status, 503);
}

#[tokio::test]
async fn a_revocation_reaches_the_other_replicas_at_their_next_read() {
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
    let (access, refresh) = signed_in(&a, &idp).await;
    revoked_ok(&revoke(&a, "web-app", &refresh).await);
    assert_eq!(refused_bearer(&a, &access), "token revoked");
    caller_of(&b, &access);
    assert!(
        !refreshes(&b, &refresh).await,
        "the grant is gone for every replica"
    );
    state_of(&b).poll_revocations().await.expect("store");
    assert_eq!(refused_bearer(&b, &access), "token revoked");
}

#[tokio::test]
async fn the_metadata_names_the_revocation_endpoint_with_a_login_idp() {
    let idp = Idp::start().await;
    let meta = server(&idp).metadata();
    assert_eq!(
        meta["revocation_endpoint"],
        format!("{GW_ISSUER}/oauth/revoke")
    );
    assert_eq!(
        meta["revocation_endpoint_auth_methods_supported"],
        meta["token_endpoint_auth_methods_supported"]
    );

    let mut ema_only = config(&idp);
    ema_only.trusted_idps[0].login = None;
    ema_only
        .clients
        .retain(|client| client.client_id == CLIENT_ID);
    let meta = AuthorizationServer::from_config(&ema_only, None, ReplayLedger::in_process())
        .expect("builds")
        .metadata();
    assert!(meta.get("revocation_endpoint").is_none());
    assert!(
        meta.get("revocation_endpoint_auth_methods_supported")
            .is_none()
    );
}

#[tokio::test]
async fn revocations_are_counted_by_token_type_and_outcome() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let (_, refresh) = signed_in(&server, &idp).await;
    revoke(&server, "desktop", &refresh).await;
    revoke(&server, "web-app", &refresh).await;
    revoke(&server, "web-app", "opaque").await;
    for metric in [
        "mcpg_as_revocations_total{token_type=refresh_token,outcome=refused}",
        "mcpg_as_revocations_total{token_type=refresh_token,outcome=revoked}",
        "mcpg_as_revocations_total{token_type=unknown,outcome=unknown}",
        "mcpg_as_grants_revoked_total{reason=client,outcome=ok}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}
