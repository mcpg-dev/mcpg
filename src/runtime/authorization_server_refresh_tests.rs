//! The refresh token grant: each refresh rotates the token, a spent token
//! presented again revokes the grant (or, within the reuse grace, receives
//! the successor again), the grant's idle and absolute lifetimes and its
//! admission by the configuration hold, scopes only narrow, and while
//! refreshes check the IdP the user's stored IdP sign-in is refreshed when
//! due: an IdP refusal ends every grant of the user, an unreachable IdP is
//! tolerated within its grace and then leaves the token unspent.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::*;
use crate::runtime::authorization_server::grants::GRANT_TYPE_REFRESH_TOKEN;
use crate::runtime::authorization_server::state::{
    GrantRecord, IdpSessionRecord, RefreshUsedRecord, StateKeyring,
};
use crate::runtime::authorization_server::vault::IdpSessionEnd;

const IDP_REFRESH: &str = "idp-refresh-1";
const IDP_REFRESH_ROTATED: &str = "idp-refresh-2";

/// A signed-in web client's tokens and grant.
struct Signed {
    access: String,
    refresh: String,
    gid: GrantId,
}

/// Sign the web client's user in, the IdP handing out `idp_refresh`, and
/// redeem the code.
async fn signed_in_with(server: &AuthorizationServer, idp: &Idp, idp_refresh: &str) -> Signed {
    let code = web_code(server, idp, Some(idp_refresh)).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let (response, _) = issued(&redemption);
    Signed {
        access: response.access_token.clone(),
        refresh: response
            .refresh_token
            .clone()
            .expect("a refresh token for a client that may refresh"),
        gid: grant_of(&response.access_token),
    }
}

async fn signed_in(server: &AuthorizationServer, idp: &Idp) -> Signed {
    signed_in_with(server, idp, IDP_REFRESH).await
}

fn refresh_form(client_id: &str, refresh_token: &str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_REFRESH_TOKEN.to_owned()),
        client_id: Some(client_id.to_owned()),
        refresh_token: Some(refresh_token.to_owned()),
        ..Default::default()
    }
}

async fn refresh(server: &AuthorizationServer, refresh_token: &str) -> TokenRedemption {
    server
        .redeem(refresh_form("web-app", refresh_token), None)
        .await
}

/// The refresh token and access token a successful refresh answers with.
#[track_caller]
fn rotated(redemption: &TokenRedemption) -> (String, String) {
    let (response, _) = issued(redemption);
    (
        response
            .refresh_token
            .clone()
            .expect("every refresh answers with a refresh token"),
        response.access_token.clone(),
    )
}

fn principal(idp: &Idp) -> String {
    principal_of_user(idp)
}

/// The fixture user's stored IdP sign-in.
async fn vault(server: &AuthorizationServer, idp: &Idp) -> Option<IdpSessionRecord> {
    state_of(server)
        .get(&keys::idp_session(&principal(idp)))
        .await
        .expect("store")
}

/// Change the fixture user's stored IdP sign-in with `change`.
async fn rewrite_vault(
    server: &AuthorizationServer,
    idp: &Idp,
    change: impl FnOnce(&mut IdpSessionRecord),
) {
    let mut record = vault(server, idp).await.expect("a sign-in is stored");
    change(&mut record);
    state_of(server)
        .put(
            &keys::idp_session(&principal(idp)),
            &record,
            Duration::from_secs(3600),
        )
        .await
        .expect("store");
}

/// Record the fixture user's IdP sign-in as last checked `ago` seconds
/// ago.
async fn checked_ago(server: &AuthorizationServer, idp: &Idp, ago: u64) {
    rewrite_vault(server, idp, |record| {
        record.last_refreshed = now_unix() - ago;
    })
    .await;
}

async fn grant_record(server: &AuthorizationServer, gid: &GrantId) -> Option<GrantRecord> {
    state_of(server)
        .get(&keys::grant(gid))
        .await
        .expect("store")
}

async fn rewrite_grant(
    server: &AuthorizationServer,
    gid: &GrantId,
    change: impl FnOnce(&mut GrantRecord),
) {
    let mut grant = grant_record(server, gid).await.expect("the grant is kept");
    change(&mut grant);
    state_of(server)
        .put(&keys::grant(gid), &grant, Duration::from_secs(3600))
        .await
        .expect("store");
}

/// An ID token a refresh at the IdP returns for [`USER`]: no nonce, no
/// `auth_time`, and `extra` over the fixture claims.
fn refreshed_id_token(idp: &Idp, extra: Value) -> String {
    let mut claims = json!({ "nonce": null, "auth_time": null });
    if let Some(extra) = extra.as_object() {
        for (name, value) in extra {
            claims[name] = value.clone();
        }
    }
    id_token(idp.issuer, "", claims)
}

impl Idp {
    /// Answer the one refresh of `refresh_token` at the IdP with `status`
    /// and `body`.
    async fn refreshes(&self, refresh_token: &str, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains(format!(
                "refresh_token={refresh_token}"
            )))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .up_to_n_times(1)
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Answer the one refresh of the fixture sign-in with a rotated
    /// refresh token and an ID token carrying `extra`.
    async fn refreshes_with(&self, extra: Value) {
        self.refreshes(
            IDP_REFRESH,
            200,
            json!({
                "access_token": "idp-access-2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": refreshed_id_token(self, extra),
                "refresh_token": IDP_REFRESH_ROTATED,
            }),
        )
        .await;
    }
}

/// The server configuration of `idp`, its interactive settings changed
/// by `change`.
fn config_with(
    idp: &Idp,
    change: impl FnOnce(&mut crate::config::InteractiveLoginConfig),
) -> AuthorizationServerConfig {
    let mut config = config(idp);
    change(interactive(&mut config));
    config
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_refresh_rotates_the_token_and_keeps_the_grant() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let signed = signed_in(&server, &idp).await;
    idp.never_redeems().await;

    let redemption = refresh(&server, &signed.refresh).await;
    let (response, issued_token) = issued(&redemption);
    let (successor, access) = rotated(&redemption);
    assert_ne!(successor, signed.refresh);
    assert!(successor.starts_with(REFRESH_TOKEN_PREFIX));
    assert_eq!(response.expires_in, 900);
    assert_eq!(response.scope.as_deref(), Some("mcp:tools"));
    assert_eq!(response.resource, RESOURCE);
    assert_eq!(grant_of(&access), signed.gid, "the same grant");
    let caller = caller_of(&server, &access);
    assert_eq!(caller.attributes["grant_type"], "authorization_code");
    assert_eq!(caller.attributes["grant_id"], signed.gid.as_str());
    caller_of(&server, &signed.access);

    let grant = grant_record(&server, &signed.gid).await.expect("kept");
    assert_eq!(grant.generation, 2);
    assert!(
        state
            .get(&keys::refresh(&signed.refresh))
            .await
            .expect("store")
            .is_none(),
        "the spent token's index is gone"
    );
    let spent = state
        .get(&keys::refresh_used(&signed.refresh))
        .await
        .expect("store")
        .expect("the spent token is remembered");
    assert_eq!(spent.gid, signed.gid);
    assert!(
        spent.successor_sealed.is_none(),
        "no successor without a grace"
    );
    let index = state
        .get(&keys::refresh(&successor))
        .await
        .expect("store")
        .expect("the successor is known");
    assert_eq!(index.generation, 2);

    let grant_event = issued_token.grant.as_ref().expect("interactive grant");
    assert!(grant_event.refresh_token_issued);
    let events = redemption.audit_events("req-r");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "mcpg.as.token_issued");
    assert_eq!(events[0].details["grant_type"], "refresh_token");
    assert_eq!(events[0].details["gid"], signed.gid.as_str());
    let text = serde_json::to_string(&events).expect("serializes");
    for secret in [&signed.refresh, &successor, &access] {
        assert!(
            !text.contains(secret.as_str()),
            "the audit carries no token"
        );
    }

    let again = refresh(&server, &successor).await;
    let (third, _) = rotated(&again);
    assert_ne!(third, successor);
    assert_eq!(
        grant_record(&server, &signed.gid)
            .await
            .expect("kept")
            .generation,
        3
    );
}

#[tokio::test]
async fn a_spent_refresh_token_revokes_its_grant() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let first = refresh(&server, &signed.refresh).await;
    let (successor, access) = rotated(&first);

    let reuse = refresh(&server, &signed.refresh).await;
    let error = refusal(&reuse);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("already used"), "{error:?}");
    assert_eq!(
        reuse.context.grant_events,
        [
            GrantEvent::RefreshReuse {
                gid: signed.gid.clone(),
                client_id: "web-app".to_owned(),
            },
            GrantEvent::Revoked {
                gid: signed.gid.clone(),
                reason: RevocationReason::RefreshReuse,
                client_id: Some("web-app".to_owned()),
            },
        ]
    );
    let actions: Vec<String> = reuse
        .audit_events("req-x")
        .into_iter()
        .map(|event| event.action)
        .collect();
    assert_eq!(
        actions,
        [
            "mcpg.as.refresh_reuse_detected",
            "mcpg.as.grant_revoked",
            "mcpg.auth.failed"
        ]
    );
    assert_eq!(refused_bearer(&server, &access), "token revoked");
    assert_eq!(refused_bearer(&server, &signed.access), "token revoked");
    assert_eq!(
        refusal(&refresh(&server, &successor).await).error,
        "invalid_grant",
        "the successor dies with the grant"
    );
}

#[tokio::test]
async fn an_unknown_refresh_token_revokes_nothing() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    for unknown in [
        format!("{REFRESH_TOKEN_PREFIX}{}", random_token().expect("random")),
        random_token().expect("random"),
        format!("{REFRESH_TOKEN_PREFIX}{}", "a".repeat(200)),
    ] {
        let redemption = refresh(&server, &unknown).await;
        assert_eq!(refusal(&redemption).error, "invalid_grant");
        assert!(redemption.context.grant_events.is_empty());
        assert!(redemption.context.gid.is_none());
    }
    let missing = server
        .redeem(
            TokenRequestForm {
                refresh_token: None,
                ..refresh_form("web-app", "")
            },
            None,
        )
        .await;
    assert_eq!(refusal(&missing).error, "invalid_request");
    rotated(&refresh(&server, &signed.refresh).await);
}

#[tokio::test]
async fn a_refresh_token_redeems_only_for_its_client() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let other = server
        .redeem(refresh_form("desktop", &signed.refresh), None)
        .await;
    let error = refusal(&other);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("another client"), "{error:?}");
    assert!(other.context.grant_events.is_empty());

    let ema_client = server
        .redeem(
            TokenRequestForm {
                client_secret: Some(CLIENT_SECRET.to_owned()),
                ..refresh_form(CLIENT_ID, &signed.refresh)
            },
            None,
        )
        .await;
    assert_eq!(
        refusal(&ema_client).error,
        "unauthorized_client",
        "a client without the refresh_token grant type"
    );
    rotated(&refresh(&server, &signed.refresh).await);
}

#[tokio::test]
async fn refresh_tokens_are_unsupported_while_off() {
    let idp = Idp::start().await;
    let server = server_with(&config_with(&idp, |settings| {
        settings.refresh_tokens.enabled = false;
    }));
    let redemption = refresh(&server, "mcpg_rt_x").await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "unsupported_grant_type");
    assert!(
        error
            .description
            .ends_with("supports jwt-bearer ID-JAG redemption and authorization_code"),
        "{}",
        error.description
    );
}

// ---------------------------------------------------------------------------
// The reuse grace
// ---------------------------------------------------------------------------

#[tokio::test]
async fn within_the_grace_a_retry_receives_the_same_successor() {
    let idp = Idp::start().await;
    let server = server_with(&config_with(&idp, |settings| {
        settings.refresh_tokens.reuse_grace_secs = 30;
    }));
    let state = state_of(&server);
    let signed = signed_in(&server, &idp).await;
    let (successor, _) = rotated(&refresh(&server, &signed.refresh).await);
    let spent = state
        .get(&keys::refresh_used(&signed.refresh))
        .await
        .expect("store")
        .expect("spent");
    let sealed = spent
        .successor_sealed
        .expect("the successor is kept for a retry");
    assert!(
        !sealed.contains(&successor),
        "sealed, not stored in the clear"
    );

    let retry = refresh(&server, &signed.refresh).await;
    let (again, access) = rotated(&retry);
    assert_eq!(
        again, successor,
        "the same successor, not a second rotation"
    );
    assert!(retry.context.grant_events.is_empty());
    caller_of(&server, &access);
    assert_eq!(
        grant_record(&server, &signed.gid)
            .await
            .expect("kept")
            .generation,
        2
    );

    // Once the successor is spent, the first token is a reuse.
    rotated(&refresh(&server, &successor).await);
    let reuse = refresh(&server, &signed.refresh).await;
    assert_eq!(refusal(&reuse).error, "invalid_grant");
    assert!(matches!(
        reuse.context.grant_events.as_slice(),
        [GrantEvent::RefreshReuse { .. }, GrantEvent::Revoked { .. }]
    ));
}

#[tokio::test]
async fn after_the_grace_a_retry_revokes_the_grant() {
    let idp = Idp::start().await;
    let server = server_with(&config_with(&idp, |settings| {
        settings.refresh_tokens.reuse_grace_secs = 30;
    }));
    let state = state_of(&server);
    let signed = signed_in(&server, &idp).await;
    let (successor, _) = rotated(&refresh(&server, &signed.refresh).await);
    let key = keys::refresh_used(&signed.refresh);
    let spent: RefreshUsedRecord = state.get(&key).await.expect("store").expect("spent");
    state
        .put(
            &key,
            &RefreshUsedRecord {
                spent_at: now_unix() - 31,
                ..spent
            },
            Duration::from_secs(600),
        )
        .await
        .expect("store");
    let reuse = refresh(&server, &signed.refresh).await;
    assert_eq!(refusal(&reuse).error, "invalid_grant");
    assert_eq!(reuse.context.grant_events.len(), 2);
    assert_eq!(
        refusal(&refresh(&server, &successor).await).error,
        "invalid_grant"
    );
}

#[tokio::test]
async fn of_two_concurrent_refreshes_one_at_most_succeeds() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let (a, b) = tokio::join!(
        refresh(&server, &signed.refresh),
        refresh(&server, &signed.refresh)
    );
    let won = usize::from(a.result.is_ok()) + usize::from(b.result.is_ok());
    assert!(won <= 1, "a token is spent once");
    assert!(
        [&a, &b].iter().any(|redemption| redemption
            .context
            .grant_events
            .iter()
            .any(|event| matches!(event, GrantEvent::RefreshReuse { .. }))),
        "without a grace the second use is a reuse"
    );

    let idp = Idp::start().await;
    let server = server_with(&config_with(&idp, |settings| {
        settings.refresh_tokens.reuse_grace_secs = 30;
    }));
    let signed = signed_in(&server, &idp).await;
    let (a, b) = tokio::join!(
        refresh(&server, &signed.refresh),
        refresh(&server, &signed.refresh)
    );
    assert_eq!(
        rotated(&a).0,
        rotated(&b).0,
        "within the grace both receive the one successor"
    );
}

// ---------------------------------------------------------------------------
// The grant's lifetime and admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_idle_or_expired_grant_refreshes_no_more() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    rewrite_grant(&server, &signed.gid, |grant| {
        grant.last_used = now_unix() - 14 * 86_400 - 1;
    })
    .await;
    let idle = refresh(&server, &signed.refresh).await;
    let error = refusal(&idle);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("unused"), "{error:?}");
    assert!(idle.context.grant_events.is_empty());

    let signed = signed_in(&server, &idp).await;
    rewrite_grant(&server, &signed.gid, |grant| {
        grant.abs_exp = now_unix() - 1;
    })
    .await;
    let expired = refresh(&server, &signed.refresh).await;
    let error = refusal(&expired);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("absolute"), "{error:?}");
}

#[tokio::test]
async fn an_access_token_expires_with_its_grant() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let end = now_unix() + 100;
    rewrite_grant(&server, &signed.gid, |grant| grant.abs_exp = end).await;
    let redemption = refresh(&server, &signed.refresh).await;
    let (response, _) = issued(&redemption);
    assert!(response.expires_in <= 100, "{}", response.expires_in);
    let claims = minted_claims(&response.access_token);
    assert!(claims["exp"].as_u64().expect("exp") <= end);
}

#[tokio::test]
async fn scopes_may_narrow_the_access_token_but_never_widen() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    rewrite_grant(&server, &signed.gid, |grant| {
        grant.scope = vec!["mcp:tools".to_owned(), "mcp:admin".to_owned()];
    })
    .await;

    let mut form = refresh_form("web-app", &signed.refresh);
    form.scope = Some("mcp:everything mcp:tools".to_owned());
    let wider = server.redeem(form, None).await;
    assert_eq!(refusal(&wider).error, "invalid_scope");
    assert!(
        wider.context.grant_events.is_empty(),
        "the token is not spent"
    );

    let mut form = refresh_form("web-app", &signed.refresh);
    form.resource = Some("https://gw.test/other".to_owned());
    assert_eq!(
        refusal(&server.redeem(form, None).await).error,
        "invalid_target"
    );

    let mut form = refresh_form("web-app", &signed.refresh);
    form.scope = Some("offline_access openid mcp:admin".to_owned());
    form.resource = Some(format!("{RESOURCE}/"));
    let narrowed = server.redeem(form, None).await;
    let (response, _) = issued(&narrowed);
    assert_eq!(response.scope.as_deref(), Some("mcp:admin"));
    let (successor, _) = rotated(&narrowed);
    assert_eq!(
        grant_record(&server, &signed.gid)
            .await
            .expect("kept")
            .scope,
        ["mcp:tools", "mcp:admin"],
        "the grant keeps what the user approved"
    );

    let redemption = refresh(&server, &successor).await;
    let (response, _) = issued(&redemption);
    assert_eq!(response.scope.as_deref(), Some("mcp:tools mcp:admin"));
}

#[tokio::test]
async fn a_grant_its_client_or_idp_no_longer_admits_is_revoked() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let mut narrowed = config(&idp);
    narrowed.trusted_idps[0].allowed_clients = vec!["desktop".to_owned()];
    let reloaded = build(&narrowed, state_of(&server).clone());
    let redemption = refresh(&reloaded, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert_eq!(
        redemption.context.grant_events,
        [GrantEvent::Revoked {
            gid: signed.gid.clone(),
            reason: RevocationReason::ClientRemoved,
            client_id: Some("web-app".to_owned()),
        }]
    );
    assert_eq!(refused_bearer(&reloaded, &signed.access), "token revoked");

    let signed = signed_in(&server, &idp).await;
    let mut pinned = config(&idp);
    pinned.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let reloaded = build(&pinned, state_of(&server).clone());
    let redemption = refresh(&reloaded, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert!(matches!(
        redemption.context.grant_events.as_slice(),
        [GrantEvent::Revoked {
            reason: RevocationReason::IdpRemoved,
            ..
        }]
    ));

    let signed = signed_in(&server, &idp).await;
    let mut one_shot = config(&idp);
    one_shot.clients[0] = client_with_grants("web-app", WEB_REDIRECT, &["authorization_code"]);
    let reloaded = build(&one_shot, state_of(&server).clone());
    let redemption = refresh(&reloaded, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "unauthorized_client");
    assert!(
        redemption.context.grant_events.is_empty(),
        "a client that may no longer refresh is refused, its grant kept"
    );
}

#[tokio::test]
async fn a_revocation_on_another_replica_stops_the_refresh() {
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
    let signed = signed_in(&a, &idp).await;
    a.revoke_grant(state_of(&a), &signed.gid, RevocationReason::Client)
        .await;
    let redemption = refresh(&b, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert!(redemption.context.grant_events.is_empty());
}

#[tokio::test]
async fn a_store_failure_refreshes_nothing() {
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
    let error = refusal(&refresh(&broken, &token).await).status;
    assert_eq!(error, 503);
}

// ---------------------------------------------------------------------------
// Checking the IdP sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_due_refresh_checks_the_idp_and_reads_the_new_claims() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    let before = vault(&server, &idp).await.expect("stored");
    checked_ago(&server, &idp, 901).await;
    idp.refreshes_with(json!({ "groups": ["engineering", "admins"] }))
        .await;

    let redemption = refresh(&server, &signed.refresh).await;
    let (_, access) = rotated(&redemption);
    let caller = caller_of(&server, &access);
    assert_eq!(caller.groups, ["engineering", "admins"]);
    let after = vault(&server, &idp).await.expect("stored");
    assert_eq!(
        after.refresh_token.as_ref().map(SecretString::expose),
        Some(IDP_REFRESH_ROTATED),
        "the IdP's rotated refresh token is kept"
    );
    assert!(after.last_refreshed >= now_unix() - 2);
    assert_eq!(after.generation, before.generation + 1);
    assert!(after.id_token.expose() != before.id_token.expose());
    let grant = grant_record(&server, &signed.gid).await.expect("kept");
    assert_eq!(grant.identity.groups, ["engineering", "admins"]);
    assert_eq!(grant.identity.auth_time, before_auth_time(&before));

    // Checked just now: the next refresh leaves the IdP alone.
    idp.never_redeems().await;
    rotated(&refresh(&server, &rotated(&redemption).0).await);
}

fn before_auth_time(record: &IdpSessionRecord) -> Option<u64> {
    crate::runtime::authorization_server::unverified_payload(record.id_token.expose())?
        .get("auth_time")?
        .as_u64()
}

#[tokio::test]
async fn the_idp_refusing_the_sign_in_ends_every_grant_of_the_user() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let first = signed_in(&server, &idp).await;
    let second = signed_in_with(&server, &idp, IDP_REFRESH).await;
    checked_ago(&server, &idp, 901).await;
    idp.refreshes(IDP_REFRESH, 400, json!({ "error": "invalid_grant" }))
        .await;

    let redemption = refresh(&server, &second.refresh).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.description.contains("no longer accepts"), "{error:?}");
    let revoked: Vec<&GrantId> = redemption
        .context
        .grant_events
        .iter()
        .filter_map(|event| match event {
            GrantEvent::Revoked {
                gid,
                reason: RevocationReason::IdpRefused,
                ..
            } => Some(gid),
            _ => None,
        })
        .collect();
    assert_eq!(revoked.len(), 2, "{:?}", redemption.context.grant_events);
    assert!(revoked.contains(&&first.gid) && revoked.contains(&&second.gid));
    assert!(
        redemption
            .context
            .grant_events
            .contains(&GrantEvent::IdpSessionRemoved {
                idp: idp.issuer.to_owned(),
                subject: USER.to_owned(),
                reason: IdpSessionEnd::IdpRefused,
            })
    );
    assert!(
        vault(&server, &idp).await.is_none(),
        "the sign-in is deleted"
    );
    assert_eq!(refused_bearer(&server, &first.access), "token revoked");
    assert_eq!(refused_bearer(&server, &second.access), "token revoked");
    let actions: Vec<String> = redemption
        .audit_events("req-i")
        .into_iter()
        .map(|event| event.action)
        .collect();
    assert!(actions.contains(&"mcpg.as.idp_session_removed".to_owned()));
    assert_eq!(
        refusal(&refresh(&server, &first.refresh).await).error,
        "invalid_grant"
    );
}

#[tokio::test]
async fn a_refreshed_id_token_for_another_user_ends_the_sign_in() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    checked_ago(&server, &idp, 901).await;
    idp.refreshes_with(json!({ "sub": "user-43" })).await;
    let redemption = refresh(&server, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert!(
        redemption
            .context
            .grant_events
            .contains(&GrantEvent::IdpSessionRemoved {
                idp: idp.issuer.to_owned(),
                subject: USER.to_owned(),
                reason: IdpSessionEnd::IdTokenInvalid,
            })
    );
    assert!(vault(&server, &idp).await.is_none());
}

#[tokio::test]
async fn an_unreachable_idp_is_tolerated_within_its_grace() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    checked_ago(&server, &idp, 901 + 60).await;
    idp.refreshes(IDP_REFRESH, 503, json!({})).await;
    let redemption = refresh(&server, &signed.refresh).await;
    let (_, access) = rotated(&redemption);
    caller_of(&server, &access);
    let kept = vault(&server, &idp).await.expect("stored");
    assert!(
        now_unix() - kept.last_refreshed >= 961,
        "an unanswered check does not count as one"
    );
}

#[tokio::test]
async fn past_the_grace_an_unreachable_idp_leaves_the_token_unspent() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    checked_ago(&server, &idp, 900 + 3600 + 5).await;
    idp.refreshes(IDP_REFRESH, 503, json!({})).await;
    let redemption = refresh(&server, &signed.refresh).await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "temporarily_unavailable");
    assert_eq!(error.status, 503);
    assert!(redemption.context.grant_events.is_empty());
    assert!(
        !state_of(&server)
            .exists(&keys::refresh_used(&signed.refresh))
            .await
            .expect("store"),
        "the token's claim is released"
    );

    idp.refreshes_with(json!({})).await;
    let retry = refresh(&server, &signed.refresh).await;
    rotated(&retry);
}

#[tokio::test]
async fn a_grant_whose_idp_sign_in_is_gone_is_revoked() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    state_of(&server)
        .delete(&keys::idp_session(&principal(&idp)))
        .await
        .expect("store");
    let redemption = refresh(&server, &signed.refresh).await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert!(matches!(
        redemption.context.grant_events.as_slice(),
        [GrantEvent::Revoked {
            reason: RevocationReason::IdpSessionExpired,
            ..
        }]
    ));

    let signed = signed_in(&server, &idp).await;
    rewrite_vault(&server, &idp, |record| {
        record.client_id = "other-login".to_owned()
    })
    .await;
    let redemption = refresh(&server, &signed.refresh).await;
    assert_eq!(
        refusal(&redemption).error,
        "invalid_grant",
        "a sign-in of another IdP client cannot be checked"
    );
}

#[tokio::test]
async fn a_check_another_request_just_made_is_not_repeated() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let signed = signed_in(&server, &idp).await;
    checked_ago(&server, &idp, 901).await;
    idp.never_redeems().await;
    let lease = state
        .try_lease(&keys::idp_lease(&principal(&idp)), Duration::from_secs(15))
        .await
        .expect("store")
        .expect("the lease is free");
    let holder = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        checked_ago(&server, &idp, 0).await;
        state.release_lease(&lease).await.expect("store");
    };
    let (redemption, ()) = tokio::join!(refresh(&server, &signed.refresh), holder);
    rotated(&redemption);
}

#[tokio::test]
async fn without_idp_checks_the_stored_sign_in_is_not_read() {
    let idp = Idp::start().await;
    let server = server_with(&config_with(&idp, |settings| {
        settings.refresh_tokens.revalidate_with_idp = false;
    }));
    let code = web_code(&server, &idp, None).await;
    let redemption = server.redeem(code_form("web-app", &code), None).await;
    let refresh_token = issued(&redemption)
        .0
        .refresh_token
        .clone()
        .expect("no IdP refresh token is needed");
    idp.never_redeems().await;
    rotated(&refresh(&server, &refresh_token).await);
}

#[tokio::test]
async fn refreshes_are_counted_by_outcome() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let signed = signed_in(&server, &idp).await;
    rotated(&refresh(&server, &signed.refresh).await);
    refresh(&server, &signed.refresh).await;
    refresh(&server, "mcpg_rt_unknown").await;
    for metric in [
        "mcpg_as_refresh_total{outcome=rotated}".to_owned(),
        "mcpg_as_refresh_total{outcome=reuse_revoked}".to_owned(),
        "mcpg_as_refresh_total{outcome=expired}".to_owned(),
        "mcpg_as_grants_revoked_total{reason=refresh_reuse,outcome=ok}".to_owned(),
        format!(
            "mcpg_ema_token_requests_total{{outcome=issued,error=none,idp={},grant=refresh_token}}",
            idp.issuer
        ),
    ] {
        assert!(
            captured.seen(&metric),
            "{metric}: {:?}",
            captured.recorded()
        );
    }
}
