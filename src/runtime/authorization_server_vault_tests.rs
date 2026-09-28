//! The stored IdP sign-in as a federation reads it: the refresh token as
//! stored, or an ID token with time left (refreshed at the IdP first, once
//! for concurrent readers), bound to the IdP, its token endpoint and the
//! gateway's client there, under a binding that survives the IdP rotating
//! its tokens. A user with nothing usable stored is not linked.

use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::*;
use crate::runtime::authorization_server::state::{HandleKind, IdpSessionRecord, handle};
use crate::runtime::authorization_server::vault::{
    IdpSessionEnd, IdpSubjectToken, SubjectTokenKind, VaultSubjectToken,
};

const IDP_REFRESH: &str = "idp-refresh-1";

/// A server whose user signed in through the web client, the IdP handing
/// out [`IDP_REFRESH`].
async fn linked_server(idp: &Idp) -> AuthorizationServer {
    let server = server(idp);
    access_token(
        &server,
        "web-app",
        &web_code(&server, idp, Some(IDP_REFRESH)).await,
    )
    .await;
    server
}

#[track_caller]
fn linked(found: IdpSubjectToken) -> VaultSubjectToken {
    match found {
        IdpSubjectToken::Linked(token) => token,
        other => panic!("expected a stored token, got {other:?}"),
    }
}

async fn stored(server: &AuthorizationServer, idp: &Idp) -> IdpSessionRecord {
    state_of(server)
        .get(&keys::idp_session(&principal_of_user(idp)))
        .await
        .expect("store")
        .expect("a sign-in is stored")
}

async fn restore(server: &AuthorizationServer, idp: &Idp, record: &IdpSessionRecord) {
    state_of(server)
        .put(
            &keys::idp_session(&principal_of_user(idp)),
            record,
            Duration::from_secs(3600),
        )
        .await
        .expect("store");
}

/// Answer refreshes of [`IDP_REFRESH`] with a new ID token (when
/// `with_id_token`) and a rotated refresh token, `times` times at most
/// and at least.
async fn idp_refreshes(idp: &Idp, with_id_token: bool, times: u64) {
    let mut body = json!({
        "access_token": "idp-access-2",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "idp-refresh-2",
    });
    if with_id_token {
        body["id_token"] = json!(id_token(
            idp.issuer,
            "",
            json!({ "nonce": null, "auth_time": null })
        ));
    }
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains(format!("refresh_token={IDP_REFRESH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .up_to_n_times(times)
        .expect(times)
        .mount(&idp.server)
        .await;
}

#[tokio::test]
async fn a_federation_reads_the_stored_refresh_token_bound_to_its_idp() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    idp.never_redeems().await;
    let principal = principal_of_user(&idp);
    let token = linked(
        server
            .idp_subject_token(&principal, SubjectTokenKind::RefreshToken)
            .await,
    );
    assert_eq!(token.token.expose(), IDP_REFRESH);
    assert_eq!(token.kind, SubjectTokenKind::RefreshToken);
    assert_eq!(
        token.kind.token_type(),
        "urn:ietf:params:oauth:token-type:refresh_token"
    );
    assert_eq!(token.issuer, idp.issuer);
    assert_eq!(token.token_endpoint, format!("{}/token", idp.issuer));
    assert_eq!(token.client_id, LOGIN_CLIENT);
    assert_eq!(
        token.binding,
        format!(
            "vault:{}:{LOGIN_CLIENT}:refresh_token",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        )
    );
    assert!(!token.binding.contains(USER), "the binding names no user");
    let debug = format!("{token:?}");
    assert!(
        !debug.contains(IDP_REFRESH),
        "Debug shows no token: {debug}"
    );
}

#[tokio::test]
async fn the_binding_stays_while_the_idp_rotates_the_token() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    let principal = principal_of_user(&idp);
    let before = linked(
        server
            .idp_subject_token(&principal, SubjectTokenKind::IdToken)
            .await,
    );
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    idp_refreshes(&idp, true, 1).await;

    let refreshed = linked(
        server
            .idp_subject_token(&principal, SubjectTokenKind::IdToken)
            .await,
    );
    assert_ne!(
        refreshed.token.expose(),
        before.token.expose(),
        "an ID token about to expire is refreshed first"
    );
    assert_eq!(refreshed.binding, before.binding);
    assert_eq!(
        refreshed.kind.token_type(),
        "urn:ietf:params:oauth:token-type:id_token"
    );
    let after = stored(&server, &idp).await;
    assert!(after.id_token_exp > now_unix() + 60);
    let rotated = linked(
        server
            .idp_subject_token(&principal, SubjectTokenKind::RefreshToken)
            .await,
    );
    assert_eq!(rotated.token.expose(), "idp-refresh-2");
    assert_eq!(
        rotated.binding,
        before.binding.replace(":id_token", ":refresh_token")
    );
}

#[tokio::test]
async fn concurrent_readers_refresh_the_id_token_once() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    let principal = principal_of_user(&idp);
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    idp_refreshes(&idp, true, 1).await;
    let (a, b) = tokio::join!(
        server.idp_subject_token(&principal, SubjectTokenKind::IdToken),
        server.idp_subject_token(&principal, SubjectTokenKind::IdToken),
    );
    assert_eq!(linked(a).token.expose(), linked(b).token.expose());
}

/// Longer than the wait for the user's lease.
const SLOW_IDP: Duration = Duration::from_millis(2_500);

/// Two concurrent reads while the IdP, which rotates refresh tokens with
/// no reuse grace, takes longer to refresh than the other waits for the
/// lease: only the holder calls the IdP, and the sign-in and the user's
/// grant survive.
#[tokio::test]
async fn a_read_that_waits_for_the_lease_in_vain_leaves_the_idp_to_its_holder() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let access = access_token(
        &server,
        "web-app",
        &web_code(&server, &idp, Some(IDP_REFRESH)).await,
    )
    .await;
    let principal = principal_of_user(&idp);
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": "idp-access-2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "idp-refresh-2",
                    "id_token": id_token(idp.issuer, "", json!({ "nonce": null, "auth_time": null })),
                }))
                .set_delay(SLOW_IDP),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&idp.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(0)
        .mount(&idp.server)
        .await;

    let (a, b) = tokio::join!(
        server.idp_subject_token(&principal, SubjectTokenKind::IdToken),
        server.idp_subject_token(&principal, SubjectTokenKind::IdToken),
    );
    let outcomes = [&a, &b];
    assert_eq!(
        outcomes
            .iter()
            .filter(|found| matches!(found, IdpSubjectToken::Linked(_)))
            .count(),
        1,
        "{a:?} {b:?}"
    );
    assert!(
        outcomes.iter().any(|found| matches!(
            found,
            IdpSubjectToken::Unavailable { reason } if reason.contains("another request")
        )),
        "the other is told to retry: {a:?} {b:?}"
    );
    let kept = stored(&server, &idp).await;
    assert_eq!(
        kept.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-2"),
        "the holder's rotation is kept"
    );
    caller_of(&server, &access);
    idp.server.verify().await;
}

/// The IdP refuses a refresh while a newer sign-in of the user replaces the
/// stored one: the refusal was for a token no longer kept, so the newer
/// sign-in and the user's grant stay.
#[tokio::test]
async fn a_refusal_of_a_sign_in_replaced_meanwhile_ends_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let access = access_token(
        &server,
        "web-app",
        &web_code(&server, &idp, Some(IDP_REFRESH)).await,
    )
    .await;
    let principal = principal_of_user(&idp);
    let signed_in = stored(&server, &idp).await;
    let mut due = signed_in.clone();
    due.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &due).await;
    let newer = IdpSessionRecord {
        refresh_token: Some(SecretString::new("idp-refresh-newer")),
        obtained_at: now_unix(),
        generation: due.generation + 1,
        ..signed_in
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": "invalid_grant" }))
                .set_delay(Duration::from_millis(500)),
        )
        .expect(1)
        .mount(&idp.server)
        .await;

    let (found, ()) = tokio::join!(
        server.idp_subject_token(&principal, SubjectTokenKind::IdToken),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            restore(&server, &idp, &newer).await;
        },
    );
    let linked = linked(found);
    assert_eq!(linked.token.expose(), newer.id_token.expose());
    let kept = stored(&server, &idp).await;
    assert_eq!(
        kept.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-newer"),
        "the newer sign-in stays"
    );
    caller_of(&server, &access);
    idp.server.verify().await;
}

#[tokio::test]
async fn an_idp_that_refreshes_without_an_id_token_cannot_serve_one() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    let principal = principal_of_user(&idp);
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    idp_refreshes(&idp, false, 1).await;
    match server
        .idp_subject_token(&principal, SubjectTokenKind::IdToken)
        .await
    {
        IdpSubjectToken::Unusable { reason } => {
            assert!(reason.contains("idp_refresh_token"), "{reason}");
        }
        other => panic!("expected an unusable ID token, got {other:?}"),
    }
    assert_eq!(
        linked(
            server
                .idp_subject_token(&principal, SubjectTokenKind::RefreshToken)
                .await
        )
        .token
        .expose(),
        "idp-refresh-2",
        "the refresh still counted"
    );
}

#[tokio::test]
async fn a_user_without_a_usable_sign_in_is_not_linked() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    idp.never_redeems().await;
    let not_linked = |found: IdpSubjectToken| {
        assert!(
            matches!(found, IdpSubjectToken::NotLinked { ref events, .. } if events.is_empty()),
            "{found:?}"
        );
    };
    not_linked(
        server
            .idp_subject_token(
                &format!("verified::ema::{}::someone-else", idp.issuer),
                SubjectTokenKind::RefreshToken,
            )
            .await,
    );
    let mut record = stored(&server, &idp).await;
    record.client_id = "another-login-client".to_owned();
    restore(&server, &idp, &record).await;
    not_linked(
        server
            .idp_subject_token(&principal_of_user(&idp), SubjectTokenKind::RefreshToken)
            .await,
    );

    let mut ema_only = config(&idp);
    ema_only.trusted_idps[0].login = None;
    ema_only
        .clients
        .retain(|client| client.client_id == CLIENT_ID);
    let ema_only = AuthorizationServer::from_config(&ema_only, None, ReplayLedger::in_process())
        .expect("builds");
    assert!(matches!(
        ema_only
            .idp_subject_token(&principal_of_user(&idp), SubjectTokenKind::RefreshToken)
            .await,
        IdpSubjectToken::NoLogin
    ));
}

#[tokio::test]
async fn a_sign_in_without_an_idp_refresh_token_serves_no_refresh_token() {
    let idp = Idp::start().await;
    let server = server(&idp);
    access_token(&server, "web-app", &web_code(&server, &idp, None).await).await;
    assert!(matches!(
        server
            .idp_subject_token(&principal_of_user(&idp), SubjectTokenKind::RefreshToken)
            .await,
        IdpSubjectToken::Unusable { .. }
    ));
}

#[tokio::test]
async fn an_idp_ending_the_sign_in_on_a_read_reports_what_it_ended() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    let principal = principal_of_user(&idp);
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(1)
        .mount(&idp.server)
        .await;
    match server
        .idp_subject_token(&principal, SubjectTokenKind::IdToken)
        .await
    {
        IdpSubjectToken::NotLinked { events, .. } => {
            assert!(events.contains(&GrantEvent::IdpSessionRemoved {
                idp: idp.issuer.to_owned(),
                subject: USER.to_owned(),
                reason: IdpSessionEnd::IdpRefused,
            }));
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, GrantEvent::Revoked { .. })),
                "the user's grant ends with it: {events:?}"
            );
        }
        other => panic!("expected not linked, got {other:?}"),
    }
    assert!(
        state_of(&server)
            .get(&keys::idp_session(&principal))
            .await
            .expect("store")
            .is_none()
    );
}

#[tokio::test]
async fn an_unreachable_idp_or_store_is_reported_unavailable() {
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    let principal = principal_of_user(&idp);
    let mut record = stored(&server, &idp).await;
    record.id_token_exp = now_unix() + 30;
    restore(&server, &idp, &record).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&idp.server)
        .await;
    assert!(matches!(
        server
            .idp_subject_token(&principal, SubjectTokenKind::IdToken)
            .await,
        IdpSubjectToken::Unavailable { .. }
    ));
    assert!(
        state_of(&server)
            .get(&keys::idp_session(&principal))
            .await
            .expect("store")
            .is_some(),
        "an outage ends nothing"
    );

    let broken = build(
        &config(&idp),
        InteractiveState::new(StateParts {
            kv: std::sync::Arc::new(UnavailableStore::new("down")),
            backend: StateBackend::InProcess,
            keyring: std::sync::Arc::new(StateKeyring::process().expect("key")),
            issuer: GW_ISSUER.to_owned(),
            revoked: std::sync::Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })
        .expect("state"),
    );
    assert!(matches!(
        broken
            .idp_subject_token(&principal, SubjectTokenKind::RefreshToken)
            .await,
        IdpSubjectToken::Unavailable { .. }
    ));
}

/// The server is where federations read stored sign-ins, and names the
/// page where a user without one connects it, while it serves the page.
#[tokio::test]
async fn the_server_is_the_federations_source_of_stored_sign_ins() {
    use crate::runtime::federation::idp_sessions::IdpSessionSource;
    let idp = Idp::start().await;
    let server = linked_server(&idp).await;
    idp.never_redeems().await;
    let source: &dyn IdpSessionSource = &server;
    let token = linked(
        source
            .subject_token(&principal_of_user(&idp), SubjectTokenKind::RefreshToken)
            .await,
    );
    assert_eq!(token.token.expose(), IDP_REFRESH);
    assert_eq!(source.login_issuer().as_deref(), Some(idp.issuer));
    assert_eq!(
        source.connect_url(),
        Some(format!("{GW_ISSUER}/oauth/connect"))
    );

    let mut without_page = config(&idp);
    interactive(&mut without_page).idp_sessions.connect_page = false;
    let without_page = server_with(&without_page);
    let source: &dyn IdpSessionSource = &without_page;
    assert_eq!(source.connect_url(), None);
    assert_eq!(source.login_issuer().as_deref(), Some(idp.issuer));

    let mut ema_only = config(&idp);
    ema_only.trusted_idps[0].login = None;
    ema_only
        .clients
        .retain(|client| client.client_id == CLIENT_ID);
    let ema_only = AuthorizationServer::from_config(&ema_only, None, ReplayLedger::in_process())
        .expect("builds");
    let source: &dyn IdpSessionSource = &ema_only;
    assert_eq!(source.connect_url(), None);
    assert_eq!(source.login_issuer(), None);
    assert!(!source.stores_sign_in_for("ema", idp.issuer));
}

/// A sign-in is stored under the principal the login IdP's namespace
/// names: `ema` under its issuer (or a tenant of it, unless one tenant is
/// required), or the SSO provider its `principal_issuer` joins. A caller of
/// any other namespace can never present one.
#[tokio::test]
async fn a_sign_in_is_stored_only_for_callers_of_the_login_namespace() {
    use crate::runtime::federation::idp_sessions::IdpSessionSource;
    let idp = Idp::start().await;
    let issuer = idp.issuer;
    let tenant = format!("{issuer}#acme");
    let server = server(&idp);
    let source: &dyn IdpSessionSource = &server;
    let sso_of_login = format!("oidc_oauth:{issuer}");
    for (auth_provider, namespace, stores) in [
        ("ema", issuer.to_owned(), true),
        ("ema", tenant.clone(), true),
        ("ema", format!("{issuer}#"), false),
        ("ema", format!("{issuer}.evil"), false),
        ("ema", "https://partner.example".to_owned(), false),
        (sso_of_login.as_str(), issuer.to_owned(), false),
        ("inspector_supervisor", "mcpg-gateway".to_owned(), false),
    ] {
        assert_eq!(
            source.stores_sign_in_for(auth_provider, &namespace),
            stores,
            "{auth_provider} {namespace}"
        );
    }

    let mut pinned = config(&idp);
    pinned.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let pinned = server_with(&pinned);
    let source: &dyn IdpSessionSource = &pinned;
    assert!(source.stores_sign_in_for("ema", issuer));
    assert!(
        !source.stores_sign_in_for("ema", &tenant),
        "one required tenant keeps the IdP's issuer as the namespace"
    );

    let sso = "https://sso.example/oauth2/default";
    let mut joined = config(&idp);
    joined.trusted_idps[0].principal_issuer = Some(sso.to_owned());
    let joined = server_with(&joined);
    let source: &dyn IdpSessionSource = &joined;
    assert!(source.stores_sign_in_for(&format!("oidc_oauth:{sso}"), sso));
    assert!(!source.stores_sign_in_for("ema", issuer));
    assert!(!source.stores_sign_in_for(&format!("oidc_oauth:{sso}"), issuer));
}
