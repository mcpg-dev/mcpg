//! The sign-in at the login IdP: the transaction an authorization request
//! starts, and the callback that completes it — the binding cookie, single
//! use, the RFC 9207 issuer check, the IdP's errors, the code exchange,
//! the ID token, the user it names, the stored IdP sign-in and the
//! authorization code. The IdP is a wiremock server that serves the
//! fixture keys and redeems one code at a time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::config::OAuthResourceMetadataConfig;
use crate::runtime::authorization_server::interactive::{
    AUTHORIZATION_CODE_PREFIX, BrowserAudit, BrowserCookie, BrowserCookies, BrowserOutcome,
    BrowserResponse, CALLBACK_PATH, ConsentForm, CookieChange, ErrorPage, IdpSessionWrite,
    LoginAudit, SupersededSignIn, TransactionCookies, TransactionTag,
};
use crate::runtime::authorization_server::redirect::s256_challenge;
use crate::runtime::authorization_server::state::{
    ClientKind, ClientSnapshot, GrantStatus, IdpSessionOrigin, InteractiveState, SecretString,
    StateBackend, StateKeyring, StateParts, TransactionPurpose, TransactionRecord,
    UnavailableStore, keys, random_token,
};

const LOGIN_CLIENT: &str = "gateway-login";
const LOGIN_SECRET: &str = "gateway-login-secret-0123456789";
const RESOURCE: &str = "https://gw.test/mcp";
const CALLBACK: &str = "https://gw.test/oauth/callback";
const WEB_REDIRECT: &str = "https://app.example/cb";
const DESKTOP_REDIRECT: &str = "http://127.0.0.1:53682/callback";
const CLIENT_STATE: &str = "client-state-1";
/// The user the IdP signs in; also the `sub` of the fixture ID-JAGs.
const USER: &str = "user-42";
const IDP_CODE: &str = "idp-code-1";
const IDP_SCOPE: &str = "openid profile email offline_access";

// ---------------------------------------------------------------------------
// The IdP
// ---------------------------------------------------------------------------

/// A login IdP on wiremock: its keys at `/jwks`, and the code redemptions
/// each test mounts.
struct Idp {
    server: MockServer,
    issuer: &'static str,
}

impl Idp {
    async fn start() -> Self {
        Self::with_jwks_status(200).await
    }

    async fn with_jwks_status(status: u16) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(status).set_body_raw(IDP_JWKS, "application/json"))
            .mount(&server)
            .await;
        let issuer = leak(server.uri());
        Self { server, issuer }
    }

    /// The login block over this IdP's configured endpoints.
    fn login(&self) -> Value {
        json!({
            "client_id": LOGIN_CLIENT,
            "client_secret": LOGIN_SECRET,
            "display_name": "Acme SSO",
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
            "revocation_endpoint": format!("{}/revoke", self.issuer),
        })
    }

    /// Answer the next token request with `response` when it redeems
    /// [`IDP_CODE`] for the callback with the verifier whose S256 is
    /// `challenge`, under the gateway's client credentials; with
    /// `invalid_grant` otherwise.
    async fn redeems(&self, challenge: &str, response: Value) {
        let challenge = challenge.to_owned();
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(move |request: &wiremock::Request| {
                let form: HashMap<String, String> = url::form_urlencoded::parse(&request.body)
                    .into_owned()
                    .collect();
                let field = |name: &str| form.get(name).map(String::as_str);
                let redeemable = field("grant_type") == Some("authorization_code")
                    && field("code") == Some(IDP_CODE)
                    && field("redirect_uri") == Some(CALLBACK)
                    && field("code_verifier").is_some_and(|v| s256_challenge(v) == challenge)
                    && field("client_secret").is_none()
                    && request.headers.get("authorization").is_some();
                if redeemable {
                    ResponseTemplate::new(200).set_body_json(response.clone())
                } else {
                    ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" }))
                }
            })
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Answer the next token request with `status` and `body`.
    async fn answers(&self, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Fail the test at [`MockServer::verify`] if a token request arrives.
    async fn never_redeems(&self) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&self.server)
            .await;
    }
}

/// An ID token of the IdP at `issuer` for [`USER`], carrying `nonce`, with
/// `extra` set over the claims (`null` removes one), typed `typ`.
fn id_token_typed(issuer: &str, nonce: &str, extra: Value, typ: &str) -> String {
    let now = now_unix();
    let mut claims = json!({
        "iss": issuer,
        "sub": USER,
        "aud": LOGIN_CLIENT,
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        "auth_time": now - 10,
        "email": "alice@example.com",
        "groups": ["engineering"],
        "amr": ["pwd", "mfa"],
    });
    if let Some(extra) = extra.as_object() {
        for (name, value) in extra {
            if value.is_null() {
                claims.as_object_mut().expect("object").remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ema-test-key".to_owned());
    header.typ = Some(typ.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(IDP_PRIVATE_PEM.as_bytes()).expect("fixture key parses"),
    )
    .expect("ID token encodes")
}

fn id_token(issuer: &str, nonce: &str, extra: Value) -> String {
    id_token_typed(issuer, nonce, extra, "JWT")
}

/// A token response with `id_token` and, when given, `refresh_token`.
fn tokens(id_token: &str, refresh_token: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": "idp-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": IDP_SCOPE,
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = json!(refresh_token);
    }
    body
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

fn resource_metadata() -> OAuthResourceMetadataConfig {
    OAuthResourceMetadataConfig {
        resource: RESOURCE.to_owned(),
        additional_resources: Vec::new(),
        authorization_servers: Vec::new(),
        scopes_supported: vec!["mcp:tools".to_owned()],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    }
}

/// A server whose login IdP is `idp`, with a web client (https), a desktop
/// client (loopback) and the ID-JAG client of the fixtures.
fn config(idp: &Idp) -> AuthorizationServerConfig {
    serde_json::from_value(json!({
        "issuer": GW_ISSUER,
        "signing_secret": SIGNING_SECRET,
        "allowed_scopes": ["mcp:tools", "mcp:admin"],
        "trusted_idps": [{
            "issuer": idp.issuer,
            "jwks_uri": format!("{}/jwks", idp.issuer),
            "allow_private_network": true,
            "allowed_algs": ["RS256"],
            "claim_mappings": { "group_claim_paths": ["groups"] },
            "login": idp.login(),
        }],
        "clients": [
            { "client_id": "web-app", "client_name": "Web App", "redirect_uris": [WEB_REDIRECT] },
            { "client_id": "desktop", "redirect_uris": ["http://127.0.0.1/callback"] },
            { "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET },
        ],
    }))
    .expect("config parses")
}

fn build(config: &AuthorizationServerConfig, state: InteractiveState) -> AuthorizationServer {
    AuthorizationServer::from_config(
        config,
        Some(&resource_metadata()),
        ReplayLedger::in_process(),
    )
    .expect("server builds")
    .with_interactive_state(Some(state))
}

fn memory_state() -> InteractiveState {
    InteractiveState::in_memory(GW_ISSUER).expect("state")
}

fn server_with(config: &AuthorizationServerConfig) -> AuthorizationServer {
    build(config, memory_state())
}

fn server(idp: &Idp) -> AuthorizationServer {
    server_with(&config(idp))
}

fn state_of(server: &AuthorizationServer) -> &InteractiveState {
    server.interactive_state().expect("interactive state")
}

fn interactive(
    config: &mut AuthorizationServerConfig,
) -> &mut crate::config::InteractiveLoginConfig {
    config.interactive.get_or_insert_with(Default::default)
}

// ---------------------------------------------------------------------------
// The browser
// ---------------------------------------------------------------------------

fn fresh_challenge() -> String {
    s256_challenge(&random_token().expect("random"))
}

fn params(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .expect("absolute URL")
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn authorize_query(client_id: &str, redirect_uri: &str, challenge: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("scope", "mcp:tools"),
            ("state", CLIENT_STATE),
        ])
        .finish()
}

/// A sign-in the browser was sent to the IdP for.
struct Started {
    /// The client's own PKCE challenge.
    challenge: String,
    /// The parameters of the IdP authorization request.
    idp: HashMap<String, String>,
    tag: TransactionTag,
    binder: String,
}

impl Started {
    fn state(&self) -> &str {
        &self.idp["state"]
    }

    fn nonce(&self) -> &str {
        &self.idp["nonce"]
    }

    fn cookies(&self) -> TransactionCookies {
        let mut cookies = TransactionCookies::default();
        cookies.insert(self.tag, self.binder.clone());
        cookies
    }
}

#[track_caller]
fn started(response: &BrowserResponse, challenge: &str) -> Started {
    let BrowserOutcome::SignIn(ref location) = response.outcome else {
        panic!("expected a redirect to the IdP, got {:?}", response.outcome);
    };
    let idp = params(location);
    let tag = TransactionTag::of_state(&idp["state"]);
    let binder = response
        .cookies
        .iter()
        .find_map(|change| match change {
            CookieChange::Set {
                cookie: BrowserCookie::Transaction(set),
                value,
                ..
            } if *set == tag => Some(value.clone()),
            _ => None,
        })
        .expect("the binding cookie is set, named after the state");
    Started {
        challenge: challenge.to_owned(),
        idp,
        tag,
        binder,
    }
}

/// Send `client_id`'s request to the IdP; the client needs no consent.
async fn start(server: &AuthorizationServer, client_id: &str, redirect_uri: &str) -> Started {
    let challenge = fresh_challenge();
    let response = server
        .authorize(
            &authorize_query(client_id, redirect_uri, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    started(&response, &challenge)
}

async fn start_web(server: &AuthorizationServer) -> Started {
    start(server, "web-app", WEB_REDIRECT).await
}

/// Send the desktop client's request to the IdP through its consent page.
async fn start_desktop(server: &AuthorizationServer) -> Started {
    let challenge = fresh_challenge();
    let page = server
        .authorize(
            &authorize_query("desktop", DESKTOP_REDIRECT, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    started(&approve(server, &page).await, &challenge)
}

/// Approve the consent page `response` shows, in the browser that loaded
/// it.
async fn approve(server: &AuthorizationServer, response: &BrowserResponse) -> BrowserResponse {
    let BrowserOutcome::Consent(ref page) = response.outcome else {
        panic!("expected the consent page, got {:?}", response.outcome);
    };
    let csrf = response
        .cookies
        .iter()
        .find_map(|change| match change {
            CookieChange::Set {
                cookie: BrowserCookie::Csrf,
                value,
                ..
            } => Some(value.clone()),
            _ => None,
        })
        .expect("CSRF cookie");
    server
        .decide_consent(
            &ConsentForm {
                req: Some(page.request.clone()),
                csrf: Some(page.csrf_token.clone()),
                decision: Some("approve".to_owned()),
            },
            &BrowserCookies {
                csrf: Some(csrf),
                consent_memory: None,
            },
        )
        .await
}

/// The callback of `started` with `answer` beside its state, in the
/// browser that started it.
async fn callback(
    server: &AuthorizationServer,
    started: &Started,
    answer: &[(&str, &str)],
) -> BrowserResponse {
    callback_in(server, started, answer, &started.cookies()).await
}

async fn callback_in(
    server: &AuthorizationServer,
    started: &Started,
    answer: &[(&str, &str)],
    cookies: &TransactionCookies,
) -> BrowserResponse {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", started.state())
        .extend_pairs(answer)
        .finish();
    server.callback(&query, cookies).await
}

/// Let the IdP redeem `started`'s code for [`USER`] with `refresh_token`
/// and an ID token carrying `extra`, then take the callback.
async fn complete_with(
    server: &AuthorizationServer,
    idp: &Idp,
    started: &Started,
    refresh_token: Option<&str>,
    extra: Value,
) -> BrowserResponse {
    idp.redeems(
        &started.idp["code_challenge"],
        tokens(&id_token(idp.issuer, started.nonce(), extra), refresh_token),
    )
    .await;
    callback(server, started, &[("code", IDP_CODE), ("iss", idp.issuer)]).await
}

async fn complete(
    server: &AuthorizationServer,
    idp: &Idp,
    started: &Started,
    refresh_token: Option<&str>,
) -> BrowserResponse {
    complete_with(server, idp, started, refresh_token, json!({})).await
}

#[track_caller]
fn code_issued(response: &BrowserResponse) -> (String, HashMap<String, String>) {
    match response.outcome {
        BrowserOutcome::CodeIssued(ref location) => (location.clone(), params(location)),
        ref other => panic!("expected the code, got {other:?}"),
    }
}

#[track_caller]
fn error_redirect(response: &BrowserResponse) -> HashMap<String, String> {
    match response.outcome {
        BrowserOutcome::ErrorRedirect { ref location, .. } => params(location),
        ref other => panic!("expected an error redirect, got {other:?}"),
    }
}

#[track_caller]
fn page(response: &BrowserResponse) -> &ErrorPage {
    match response.outcome {
        BrowserOutcome::Page(ref page) => page,
        ref other => panic!("expected a page, got {other:?}"),
    }
}

#[track_caller]
fn login_audit(response: &BrowserResponse) -> &LoginAudit {
    match response.audit {
        Some(BrowserAudit::Login(ref login)) => login,
        ref other => panic!("expected mcpg.as.login, got {other:?}"),
    }
}

#[track_caller]
fn refusal_reason(response: &BrowserResponse) -> &str {
    match response.audit {
        Some(BrowserAudit::CallbackRefused { ref reason }) => reason,
        ref other => panic!("expected an as_callback refusal, got {other:?}"),
    }
}

fn clears_binding(response: &BrowserResponse, started: &Started) -> bool {
    response
        .cookies
        .contains(&CookieChange::Clear(BrowserCookie::Transaction(
            started.tag,
        )))
}

/// The stored transaction of `started`.
async fn transaction(server: &AuthorizationServer, started: &Started) -> TransactionRecord {
    state_of(server)
        .get(&keys::transaction(started.state()))
        .await
        .expect("store")
        .expect("the transaction is stored")
}

/// Store `record` as `started`'s transaction.
async fn rewrite(server: &AuthorizationServer, started: &Started, record: &TransactionRecord) {
    state_of(server)
        .put(
            &keys::transaction(started.state()),
            record,
            Duration::from_secs(600),
        )
        .await
        .expect("store");
}

/// Every raw record under `prefix`, sealed as stored.
async fn raw(server: &AuthorizationServer, prefix: &str) -> Vec<Vec<u8>> {
    state_of(server)
        .store()
        .list_prefix(&format!("as/v1/{prefix}"), 100)
        .await
        .expect("list")
        .into_iter()
        .map(|(_, entry)| entry.bytes.to_vec())
        .collect()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn principal_of_user(idp: &Idp) -> String {
    format!("verified::ema::{}::{USER}", idp.issuer)
}

// ---------------------------------------------------------------------------
// The transaction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signing_in_stores_a_sealed_transaction_bound_to_a_cookie() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let challenge = fresh_challenge();
    let response = server
        .authorize(
            &authorize_query("web-app", WEB_REDIRECT, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    let started = started(&response, &challenge);
    assert_eq!(
        response.cookies,
        vec![CookieChange::Set {
            cookie: BrowserCookie::Transaction(started.tag),
            value: started.binder.clone(),
            max_age_secs: 600,
        }],
        "one binding cookie, as long as the transaction"
    );
    assert_eq!(started.binder.len(), 43, "256 random bits");
    assert_eq!(started.tag.as_str().len(), 16);

    let record = transaction(&server, &started).await;
    assert_eq!(record.purpose, TransactionPurpose::Authorize);
    assert_eq!(
        record.client,
        Some(ClientSnapshot {
            client_id: "web-app".to_owned(),
            kind: ClientKind::Static,
            name: Some("Web App".to_owned()),
        })
    );
    assert_eq!(record.redirect_uri.as_deref(), Some(WEB_REDIRECT));
    assert!(record.redirect_trusted);
    assert!(!record.consent_approved);
    assert_eq!(record.client_state.as_deref(), Some(CLIENT_STATE));
    assert_eq!(record.code_challenge.as_deref(), Some(challenge.as_str()));
    assert_eq!(record.resource.as_deref(), Some(RESOURCE));
    assert_eq!(record.scope, ["mcp:tools"]);
    assert_eq!(record.idp_issuer, idp.issuer);
    assert_eq!(record.nonce.expose(), started.nonce());
    assert_eq!(
        s256_challenge(record.pkce_verifier.expose()),
        started.idp["code_challenge"],
        "the IdP sees the S256 of the transaction's own verifier"
    );
    assert_ne!(record.binder_hash, started.binder, "only a hash is kept");
    assert!(record.created.abs_diff(now_unix()) <= 2);
    assert!(
        state
            .exists(&keys::pkce_seen("web-app", &challenge))
            .await
            .expect("store"),
        "the client's challenge is claimed"
    );

    let sealed = raw(&server, "txn/").await;
    assert_eq!(sealed.len(), 1);
    for secret in [
        started.nonce(),
        started.binder.as_str(),
        record.pkce_verifier.expose(),
        CLIENT_STATE,
        "app.example",
    ] {
        assert!(!contains(&sealed[0], secret), "{secret} is sealed");
    }
}

#[tokio::test]
async fn a_reused_code_challenge_is_refused() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let challenge = fresh_challenge();
    let query = authorize_query("web-app", WEB_REDIRECT, &challenge);
    started(
        &server.authorize(&query, &BrowserCookies::default()).await,
        &challenge,
    );
    let again = server.authorize(&query, &BrowserCookies::default()).await;
    let params = error_redirect(&again);
    assert_eq!(params["error"], "invalid_request");
    assert!(
        params["error_description"].contains("code_challenge reused"),
        "{params:?}"
    );
    assert_eq!(params["state"], CLIENT_STATE);
    assert_eq!(params["iss"], GW_ISSUER);
    assert!(again.cookies.is_empty(), "no transaction is started");

    let other_client = server
        .authorize(
            &authorize_query("desktop", DESKTOP_REDIRECT, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    assert!(
        matches!(other_client.outcome, BrowserOutcome::Consent(_)),
        "a challenge is claimed per client, and only once the user is sent to the IdP"
    );
}

#[tokio::test]
async fn an_approval_is_recorded_in_the_transaction() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let challenge = fresh_challenge();
    let page = server
        .authorize(
            &authorize_query("desktop", DESKTOP_REDIRECT, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    assert!(
        !state_of(&server)
            .exists(&keys::pkce_seen("desktop", &challenge))
            .await
            .expect("store"),
        "the consent page claims nothing"
    );
    let approved = approve(&server, &page).await;
    let started = started(&approved, &challenge);
    let record = transaction(&server, &started).await;
    assert!(record.consent_approved);
    assert_eq!(record.redirect_uri.as_deref(), Some(DESKTOP_REDIRECT));
    assert_eq!(
        approved.cookies,
        [CookieChange::Set {
            cookie: BrowserCookie::Transaction(started.tag),
            value: started.binder.clone(),
            max_age_secs: 600,
        }],
        "the binding cookie alone; the CSRF cookie stays"
    );
}

// ---------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_callback_issues_a_code_bound_to_the_request() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let started = start_web(&server).await;
    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;

    let (location, params) = code_issued(&response);
    assert!(
        location.starts_with("https://app.example/cb?code=mcpg_ac_"),
        "{location}"
    );
    let code = params["code"].clone();
    assert!(code.starts_with(AUTHORIZATION_CODE_PREFIX));
    assert_eq!(code.len(), AUTHORIZATION_CODE_PREFIX.len() + 43);
    assert_eq!(params["state"], CLIENT_STATE);
    assert_eq!(params["iss"], GW_ISSUER, "RFC 9207 iss");
    assert_eq!(params.len(), 3, "no challenge goes back: {params:?}");
    assert!(clears_binding(&response, &started));
    assert!(response.superseded.is_none());

    let record = state
        .get(&keys::code(&code))
        .await
        .expect("store")
        .expect("the code is stored");
    assert_eq!(record.client_id, "web-app");
    assert_eq!(record.redirect_uri, WEB_REDIRECT);
    assert_eq!(record.code_challenge, started.challenge);
    assert_eq!(record.resource, RESOURCE);
    assert_eq!(record.scope, ["mcp:tools"]);
    assert!(record.exp.abs_diff(now_unix() + 60) <= 2, "{}", record.exp);

    let grant = state
        .get(&keys::grant(&record.gid))
        .await
        .expect("store")
        .expect("the grant is stored");
    assert_eq!(grant.status, GrantStatus::Pending);
    assert_eq!(grant.principal, principal_of_user(&idp));
    assert_eq!(grant.identity.subject, USER);
    assert_eq!(grant.identity.idp, idp.issuer);
    assert_eq!(grant.identity.groups, ["engineering"]);
    assert_eq!(grant.identity.amr, ["pwd", "mfa"]);
    assert_eq!(grant.identity.email.as_deref(), Some("alice@example.com"));
    assert!(grant.identity.auth_time.is_some());
    assert_eq!(grant.client_id, "web-app");
    assert_eq!(grant.client_kind, ClientKind::Static);
    assert_eq!(grant.scope, ["mcp:tools"]);
    assert_eq!(grant.resource, RESOURCE);
    assert_eq!(grant.redirect_uri, WEB_REDIRECT);
    assert_eq!(grant.issuer, GW_ISSUER);
    assert_eq!(grant.generation, 0, "no refresh token before the code");

    let audit = login_audit(&response);
    assert_eq!(audit.purpose, TransactionPurpose::Authorize);
    assert_eq!(audit.client_id.as_deref(), Some("web-app"));
    assert_eq!(audit.gid.as_ref(), Some(&record.gid));
    assert_eq!(audit.idp_session, IdpSessionWrite::Stored);
    assert_eq!(audit.transaction, started.tag.as_str());
    let event = response.audit.as_ref().expect("audit").event("request-1");
    assert_eq!(event.action, "mcpg.as.login");
    assert_eq!(event.actor.subject_id.as_deref(), Some(USER));
    assert_eq!(event.resource.as_deref(), Some(RESOURCE));
    let text = serde_json::to_string(&event).expect("serializes");
    for secret in [
        code.as_str(),
        "idp-refresh-1",
        started.state(),
        started.nonce(),
        started.binder.as_str(),
    ] {
        assert!(
            !text.contains(secret),
            "the audit event carries no {secret}"
        );
    }

    assert!(
        state
            .get(&keys::transaction(started.state()))
            .await
            .expect("store")
            .is_none(),
        "the transaction is gone once taken"
    );
    idp.server.verify().await;
}

#[tokio::test]
async fn a_transaction_is_taken_once() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let started = start_web(&server).await;
    let first = complete(&server, &idp, &started, None).await;
    code_issued(&first);
    assert!(clears_binding(&first, &started));
    let replay = callback(
        &server,
        &started,
        &[("code", IDP_CODE), ("iss", idp.issuer)],
    )
    .await;
    let refused = page(&replay);
    assert_eq!(refused.status, 400);
    assert!(refused.title.contains("expired or was already used"));
    assert!(
        state_of(&server)
            .exists(&keys::transaction_used(started.state()))
            .await
            .expect("store"),
        "the used marker outlives the transaction"
    );

    let raced = start_web(&server).await;
    let record = transaction(&server, &raced).await;
    code_issued(&complete(&server, &idp, &raced, None).await);
    rewrite(&server, &raced, &record).await;
    let replay = callback(&server, &raced, &[("code", IDP_CODE), ("iss", idp.issuer)]).await;
    assert!(
        page(&replay).title.contains("already used"),
        "a transaction read before it was taken is still refused"
    );
    assert!(clears_binding(&replay, &raced));
}

#[tokio::test]
async fn a_missing_unknown_or_expired_state_is_refused() {
    let idp = Idp::start().await;
    let server = server(&idp);
    idp.never_redeems().await;
    let none = TransactionCookies::default();

    let missing = server.callback("code=idp-code-1", &none).await;
    assert_eq!(page(&missing).status, 400);
    assert!(page(&missing).message.contains("no state"));
    let repeated = server.callback("state=a&state=b&code=c", &none).await;
    assert!(page(&repeated).message.contains("`state`"));
    for unknown in ["short", random_token().expect("random").as_str()] {
        let response = server
            .callback(&format!("state={unknown}&code=c"), &none)
            .await;
        assert!(
            page(&response).title.contains("expired"),
            "{unknown}: {response:?}"
        );
    }

    let started = start_web(&server).await;
    let mut record = transaction(&server, &started).await;
    record.created = now_unix() - 601;
    rewrite(&server, &started, &record).await;
    let expired = callback(
        &server,
        &started,
        &[("code", IDP_CODE), ("iss", idp.issuer)],
    )
    .await;
    assert!(page(&expired).title.contains("expired"));
    idp.server.verify().await;
}

#[tokio::test]
async fn the_callback_needs_the_browser_that_started_the_sign_in() {
    let idp = Idp::start().await;
    let server = server(&idp);
    idp.never_redeems().await;
    let answer = [("code", IDP_CODE), ("iss", idp.issuer)];

    let started = start_web(&server).await;
    let without = callback_in(&server, &started, &answer, &TransactionCookies::default()).await;
    let refused = page(&without);
    assert_eq!(refused.status, 400);
    assert!(refused.title.contains("browser that started it"));
    assert!(refusal_reason(&without).contains("binding cookie"));
    assert!(clears_binding(&without, &started));
    let after = callback(&server, &started, &answer).await;
    assert!(
        page(&after).title.contains("expired"),
        "a refused callback spends the transaction"
    );

    let started = start_web(&server).await;
    let mut forged = TransactionCookies::default();
    forged.insert(started.tag, random_token().expect("random"));
    let response = callback_in(&server, &started, &answer, &forged).await;
    assert!(page(&response).title.contains("browser that started it"));

    let started = start_web(&server).await;
    let other = start_web(&server).await;
    let response = callback_in(&server, &started, &answer, &other.cookies()).await;
    assert!(
        page(&response).title.contains("browser that started it"),
        "another sign-in's cookie does not bind this one"
    );
    idp.server.verify().await;
}

#[tokio::test]
async fn an_answer_from_another_issuer_is_refused_and_not_acted_on() {
    let idp = Idp::start().await;
    let server = server(&idp);
    for iss in ["https://evil.test", &format!("{}/", idp.issuer)] {
        let started = start_web(&server).await;
        let response = callback(
            &server,
            &started,
            &[("error", "access_denied"), ("iss", iss)],
        )
        .await;
        let refused = page(&response);
        assert_eq!(refused.status, 400, "{iss}");
        assert!(refused.title.contains("not accepted"), "{refused:?}");
        assert!(
            refused.return_to.is_none(),
            "the IdP's error is not acted on"
        );
        assert!(refusal_reason(&response).contains("another issuer"));
    }

    let started = start_web(&server).await;
    idp.redeems(
        &started.idp["code_challenge"],
        tokens(&id_token(idp.issuer, started.nonce(), json!({})), None),
    )
    .await;
    let response = callback(&server, &started, &[("code", IDP_CODE)]).await;
    code_issued(&response);
}

#[tokio::test]
async fn an_idp_that_always_sends_iss_must_send_it() {
    let idp = Idp::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": idp.issuer,
            "authorization_endpoint": format!("{}/authorize", idp.issuer),
            "token_endpoint": format!("{}/token", idp.issuer),
            "jwks_uri": format!("{}/jwks", idp.issuer),
            "authorization_response_iss_parameter_supported": true,
        })))
        .mount(&idp.server)
        .await;
    let mut config = config(&idp);
    config.trusted_idps[0].login = Some(
        serde_json::from_value(json!({
            "client_id": LOGIN_CLIENT,
            "client_secret": LOGIN_SECRET,
        }))
        .expect("login parses"),
    );
    let server = server_with(&config);

    let started = start_web(&server).await;
    let response = callback(&server, &started, &[("code", IDP_CODE)]).await;
    assert!(page(&response).title.contains("not accepted"));
    assert!(refusal_reason(&response).contains("carries no iss"));

    let started = start_web(&server).await;
    code_issued(&complete(&server, &idp, &started, None).await);
}

#[tokio::test]
async fn idp_errors_reach_the_client_without_the_idps_description() {
    let idp = Idp::start().await;
    let server = server(&idp);
    idp.never_redeems().await;
    let cases = [
        ("access_denied", "access_denied"),
        ("login_required", "access_denied"),
        ("interaction_required", "access_denied"),
        ("consent_required", "access_denied"),
        ("account_selection_required", "access_denied"),
        ("temporarily_unavailable", "temporarily_unavailable"),
        ("invalid_scope", "server_error"),
        ("server_error", "server_error"),
        ("<script>", "server_error"),
    ];
    for (idp_error, expected) in cases {
        let started = start_web(&server).await;
        let response = callback(
            &server,
            &started,
            &[
                ("error", idp_error),
                ("error_description", "internal detail <b>leak</b>"),
                ("error_uri", "https://evil.test/help"),
                ("iss", idp.issuer),
            ],
        )
        .await;
        let params = error_redirect(&response);
        assert_eq!(params["error"], expected, "{idp_error}");
        assert!(!params["error_description"].contains("leak"), "{params:?}");
        assert!(!params.contains_key("error_uri"));
        assert_eq!(params["state"], CLIENT_STATE);
        assert_eq!(params["iss"], GW_ISSUER);
        assert!(clears_binding(&response, &started));
    }
    idp.server.verify().await;
}

#[tokio::test]
async fn an_answer_without_a_code_gets_a_page() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let started = start_web(&server).await;
    let response = callback(&server, &started, &[("iss", idp.issuer)]).await;
    let refused = page(&response);
    assert_eq!(refused.status, 400);
    assert!(refused.message.contains("no authorization code"));
}

#[tokio::test]
async fn token_endpoint_failures_are_retryable_or_server_errors() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let answer = |idp: &Idp| vec![("code", IDP_CODE), ("iss", idp.issuer)];

    let started = start_web(&server).await;
    idp.answers(503, json!({ "error": "temporarily_unavailable" }))
        .await;
    let params = error_redirect(&callback(&server, &started, &answer(&idp)).await);
    assert_eq!(params["error"], "temporarily_unavailable");

    let started = start_web(&server).await;
    idp.answers(
        400,
        json!({ "error": "invalid_grant", "error_description": "code gone" }),
    )
    .await;
    let response = callback(&server, &started, &answer(&idp)).await;
    assert_eq!(error_redirect(&response)["error"], "server_error");
    let reason = refusal_reason(&response);
    assert!(reason.contains("invalid_grant"), "{reason}");
    assert!(
        !reason.contains("code gone"),
        "the IdP's description is dropped"
    );

    let started = start_web(&server).await;
    idp.answers(200, json!({ "access_token": "a", "token_type": "Bearer" }))
        .await;
    let params = error_redirect(&callback(&server, &started, &answer(&idp)).await);
    assert_eq!(params["error"], "server_error", "no ID token");

    let started = start_web(&server).await;
    let id_token = id_token(idp.issuer, started.nonce(), json!({}));
    idp.answers(
        200,
        json!({ "access_token": "a", "token_type": "DPoP", "id_token": id_token }),
    )
    .await;
    let params = error_redirect(&callback(&server, &started, &answer(&idp)).await);
    assert_eq!(params["error"], "server_error", "not a bearer token");
    assert!(
        raw(&server, "grant/").await.is_empty(),
        "nothing is granted"
    );
}

#[tokio::test]
async fn an_id_token_that_fails_a_check_gets_server_error_without_detail() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let now = now_unix();
    let cases = [
        (
            "another nonce",
            json!({ "nonce": "n0nce-of-another-sign-in" }),
        ),
        ("no nonce", json!({ "nonce": null })),
        (
            "an extra audience",
            json!({ "aud": [LOGIN_CLIENT, "other-app"] }),
        ),
        ("another issuer", json!({ "iss": "https://evil.test" })),
        ("expired", json!({ "exp": now - 300 })),
        ("issued long ago", json!({ "iat": now - 3600 })),
        ("an actor", json!({ "act": { "sub": "agent" } })),
    ];
    for (case, extra) in cases {
        let started = start_web(&server).await;
        let response = complete_with(&server, &idp, &started, None, extra).await;
        let params = error_redirect(&response);
        assert_eq!(params["error"], "server_error", "{case}");
        assert_eq!(
            params["error_description"], "the sign-in at the enterprise IdP could not be completed",
            "{case}"
        );
        assert!(
            refusal_reason(&response).starts_with("id_token_invalid:"),
            "{case}: {:?}",
            response.audit
        );
    }
    let started = start_web(&server).await;
    idp.redeems(
        &started.idp["code_challenge"],
        tokens(
            &id_token_typed(idp.issuer, started.nonce(), json!({}), "at+jwt"),
            None,
        ),
    )
    .await;
    let response = callback(
        &server,
        &started,
        &[("code", IDP_CODE), ("iss", idp.issuer)],
    )
    .await;
    assert_eq!(
        error_redirect(&response)["error"],
        "server_error",
        "an access token is no ID token"
    );
    assert!(raw(&server, "grant/").await.is_empty());
}

#[tokio::test]
async fn unreachable_idp_keys_are_retryable() {
    let idp = Idp::with_jwks_status(503).await;
    let server = server(&idp);
    let started = start_web(&server).await;
    let params = error_redirect(&complete(&server, &idp, &started, None).await);
    assert_eq!(params["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn the_users_tenant_must_be_the_one_the_idp_is_trusted_for() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    config.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let server = server_with(&config);
    for extra in [json!({ "tenant": "other" }), json!({})] {
        let started = start_web(&server).await;
        let response = complete_with(&server, &idp, &started, None, extra.clone()).await;
        assert_eq!(
            error_redirect(&response)["error"],
            "access_denied",
            "{extra}"
        );
        assert!(refusal_reason(&response).contains("tenant"));
    }
    let started = start_web(&server).await;
    let (_, params) = code_issued(
        &complete_with(&server, &idp, &started, None, json!({ "tenant": "acme" })).await,
    );
    let code = state_of(&server)
        .get(&keys::code(&params["code"]))
        .await
        .expect("store")
        .expect("code");
    let grant = state_of(&server)
        .get(&keys::grant(&code.gid))
        .await
        .expect("store")
        .expect("grant");
    assert_eq!(grant.identity.tenant.as_deref(), Some("acme"));
    assert_eq!(
        grant.principal,
        principal_of_user(&idp),
        "an IdP pinned to one tenant namespaces by its issuer alone"
    );
}

#[tokio::test]
async fn a_client_must_still_be_admitted_when_the_sign_in_completes() {
    let idp = Idp::start().await;
    let state = memory_state();
    let before = build(&config(&idp), state.clone());

    let mut restricted = config(&idp);
    restricted.trusted_idps[0].allowed_clients = vec!["desktop".to_owned()];
    let after = build(&restricted, state.clone());
    let started = start_web(&before).await;
    let response = complete(&after, &idp, &started, None).await;
    assert_eq!(error_redirect(&response)["error"], "access_denied");

    let mut removed = config(&idp);
    removed
        .clients
        .retain(|client| client.client_id != "web-app");
    let after = build(&removed, state.clone());
    let started = start_web(&before).await;
    let response = complete(&after, &idp, &started, None).await;
    let refused = page(&response);
    assert_eq!(refused.error, "unauthorized_client");
    assert!(
        refused.return_to.is_none(),
        "never to a removed client's URI"
    );

    let other_idp = Idp::start().await;
    let after = build(&config(&other_idp), state);
    let started = start_web(&before).await;
    let response = callback(&after, &started, &[("code", IDP_CODE), ("iss", idp.issuer)]).await;
    assert!(page(&response).message.contains("sign-in service changed"));
}

#[tokio::test]
async fn an_untrusted_redirect_uri_gets_an_error_only_after_approval() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let answer = [("error", "access_denied"), ("iss", idp.issuer)];

    let started = start_web(&server).await;
    let mut record = transaction(&server, &started).await;
    record.redirect_trusted = false;
    rewrite(&server, &started, &record).await;
    let response = callback(&server, &started, &answer).await;
    let refused = page(&response);
    assert_eq!(refused.status, 403);
    let link = refused.return_to.as_ref().expect("a link the user follows");
    assert_eq!(link.host, "app.example");
    let params = params(&link.href);
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["iss"], GW_ISSUER);

    let started = start_web(&server).await;
    let mut record = transaction(&server, &started).await;
    record.redirect_trusted = false;
    record.consent_approved = true;
    rewrite(&server, &started, &record).await;
    assert_eq!(
        error_redirect(&callback(&server, &started, &answer).await)["error"],
        "access_denied"
    );
}

#[tokio::test]
async fn a_store_failure_fails_closed() {
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
    let state = random_token().expect("random");
    let response = broken
        .callback(
            &format!("state={state}&code=c"),
            &TransactionCookies::default(),
        )
        .await;
    assert_eq!(page(&response).status, 503);

    let challenge = fresh_challenge();
    let response = broken
        .authorize(
            &authorize_query("web-app", WEB_REDIRECT, &challenge),
            &BrowserCookies::default(),
        )
        .await;
    assert_eq!(
        page(&response).status,
        503,
        "no sign-in starts without its transaction"
    );
}

// ---------------------------------------------------------------------------
// The stored IdP sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_idp_sign_in_is_kept_sealed_per_user_and_replaced() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let state = state_of(&server);
    let principal = principal_of_user(&idp);

    let first = complete(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-1"),
    )
    .await;
    code_issued(&first);
    assert_eq!(login_audit(&first).idp_session, IdpSessionWrite::Stored);
    assert!(first.superseded.is_none());
    let stored = state
        .get(&keys::idp_session(&principal))
        .await
        .expect("store")
        .expect("the sign-in is kept");
    assert_eq!(stored.v, 1);
    assert_eq!(stored.issuer, idp.issuer);
    assert_eq!(stored.client_id, LOGIN_CLIENT);
    assert_eq!(stored.token_endpoint, format!("{}/token", idp.issuer));
    assert_eq!(stored.sub, USER);
    assert_eq!(
        stored.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-1")
    );
    assert!(!stored.id_token.expose().is_empty());
    assert!(stored.id_token_exp > now_unix());
    assert_eq!(stored.scope, IDP_SCOPE);
    assert_eq!(stored.origin, IdpSessionOrigin::Login);
    assert_eq!(stored.generation, 1);
    assert_eq!(stored.last_refreshed, stored.obtained_at);
    for sealed in raw(&server, "idp/").await {
        assert!(!contains(&sealed, "idp-refresh-1"), "the token is sealed");
        assert!(!contains(&sealed, USER), "the user is sealed");
    }

    let second = complete(
        &server,
        &idp,
        &start_desktop(&server).await,
        Some("idp-refresh-2"),
    )
    .await;
    code_issued(&second);
    assert_eq!(login_audit(&second).idp_session, IdpSessionWrite::Replaced);
    let replaced = state
        .get(&keys::idp_session(&principal))
        .await
        .expect("store")
        .expect("kept");
    assert_eq!(
        replaced.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-2"),
        "one sign-in per user, whichever client signed them in"
    );
    assert_eq!(replaced.generation, 2);
    assert!(
        second.superseded.is_none(),
        "a token of the same user and gateway client is not revoked: an IdP that revokes per \
         user and client would end the new one too"
    );

    let same = complete(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-2"),
    )
    .await;
    assert!(same.superseded.is_none(), "the same token is not revoked");
}

/// Two IdP subjects the claim mappings name one user: signing in as the
/// second replaces the first one's sign-in and revokes its token.
#[tokio::test]
async fn a_replaced_sign_in_of_another_idp_subject_is_revoked() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    config.trusted_idps[0].claim_mappings.subject_claim = "email".to_owned();
    let server = server_with(&config);
    let first = complete(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-1"),
    )
    .await;
    code_issued(&first);
    assert!(first.superseded.is_none());
    let second = complete_with(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-2"),
        json!({ "sub": "user-43" }),
    )
    .await;
    code_issued(&second);
    assert_eq!(login_audit(&second).idp_session, IdpSessionWrite::Replaced);
    let superseded = second.superseded.expect("the replaced token is revoked");
    assert_eq!(superseded.issuer, idp.issuer);
    assert_eq!(superseded.client_id, LOGIN_CLIENT);
    assert_eq!(superseded.refresh_token.expose(), "idp-refresh-1");
    assert!(
        !format!("{superseded:?}").contains("idp-refresh-1"),
        "Debug shows no token"
    );

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=idp-refresh-1"))
        .and(body_string_contains("token_type_hint=refresh_token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&idp.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("idp-refresh-9"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&idp.server)
        .await;
    server.revoke_superseded(superseded).await;
    server
        .revoke_superseded(SupersededSignIn {
            issuer: idp.issuer.to_owned(),
            client_id: "another-login-client".to_owned(),
            refresh_token: SecretString::new("idp-refresh-9"),
        })
        .await;
    idp.server.verify().await;
}

#[tokio::test]
async fn a_replaced_sign_in_is_kept_when_revoke_superseded_is_off() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    config.trusted_idps[0].claim_mappings.subject_claim = "email".to_owned();
    interactive(&mut config).idp_sessions.revoke_superseded = false;
    let server = server_with(&config);
    complete(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-1"),
    )
    .await;
    let second = complete_with(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-2"),
        json!({ "sub": "user-43" }),
    )
    .await;
    assert_eq!(login_audit(&second).idp_session, IdpSessionWrite::Replaced);
    assert!(second.superseded.is_none());
}

#[tokio::test]
async fn the_idp_sign_in_is_not_kept_when_nothing_uses_it() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    interactive(&mut config).refresh_tokens.revalidate_with_idp = false;
    let server = server_with(&config);
    assert!(!server.keeps_idp_sign_in());
    let response = complete(
        &server,
        &idp,
        &start_web(&server).await,
        Some("idp-refresh-1"),
    )
    .await;
    code_issued(&response);
    assert_eq!(login_audit(&response).idp_session, IdpSessionWrite::NotKept);
    assert!(raw(&server, "idp/").await.is_empty());
}

#[tokio::test]
async fn a_connect_sign_in_keeps_the_idp_sign_in_and_issues_no_code() {
    let idp = Idp::start().await;
    let mut config = config(&idp);
    interactive(&mut config).refresh_tokens.revalidate_with_idp = false;
    let server = server_with(&config);
    let started = start_web(&server).await;
    let mut record = transaction(&server, &started).await;
    record.purpose = TransactionPurpose::Connect;
    record.client = None;
    record.redirect_uri = None;
    record.client_state = None;
    record.code_challenge = None;
    record.resource = None;
    record.scope.clear();
    rewrite(&server, &started, &record).await;

    let response = complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    match response.outcome {
        BrowserOutcome::Done(ref notice) => {
            assert_eq!(notice.title, "Connected");
            assert!(notice.message.contains("Acme SSO"), "{notice:?}");
        }
        ref other => panic!("expected the connected page, got {other:?}"),
    }
    assert!(clears_binding(&response, &started));
    let audit = login_audit(&response);
    assert_eq!(audit.purpose, TransactionPurpose::Connect);
    assert_eq!(audit.gid, None);
    assert_eq!(audit.idp_session, IdpSessionWrite::Stored);
    let stored = state_of(&server)
        .get(&keys::idp_session(&principal_of_user(&idp)))
        .await
        .expect("store")
        .expect("kept though no refresh checks it");
    assert_eq!(stored.origin, IdpSessionOrigin::Connect);
    assert!(raw(&server, "code/").await.is_empty());
    assert!(raw(&server, "grant/").await.is_empty());
}

#[tokio::test]
async fn a_link_sign_in_without_a_pending_link_is_refused_before_the_idp_is_asked() {
    let idp = Idp::start().await;
    let server = server(&idp);
    idp.never_redeems().await;
    let started = start_web(&server).await;
    let mut record = transaction(&server, &started).await;
    record.purpose = TransactionPurpose::Link;
    rewrite(&server, &started, &record).await;
    let response = callback(
        &server,
        &started,
        &[("code", IDP_CODE), ("iss", idp.issuer)],
    )
    .await;
    assert_eq!(page(&response), &ErrorPage::link_expired());
    assert!(clears_binding(&response, &started));
    assert!(raw(&server, "idp/").await.is_empty());
    idp.server.verify().await;
}

// ---------------------------------------------------------------------------
// One principal
// ---------------------------------------------------------------------------

/// The principal key of the caller an ID-JAG for [`USER`] from `idp`
/// makes, with `extra` claims, as `/mcp` sees it.
async fn id_jag_principal(server: &AuthorizationServer, idp: &Idp, extra: Value) -> String {
    let assertion = make_id_jag(AssertionOverrides {
        iss: idp.issuer,
        extra,
        ..Default::default()
    });
    let token = redeem(server, &assertion).await.expect("redeems");
    let EmaBearerOutcome::Verified(identity) = server.verify_bearer(&token.access_token) else {
        panic!("the minted token verifies");
    };
    crate::runtime::RequestIdentity::Verified {
        subject_id: identity.subject_id,
        issuer: identity.issuer,
        auth_provider: identity.auth_provider,
        source: crate::runtime::EMA_ACCESS_TOKEN_SOURCE.to_owned(),
        roles: identity.roles,
        groups: identity.groups,
        scopes: identity.scopes,
        attributes: identity.attributes,
    }
    .synthetic_principal_key()
    .expect("a verified caller has a principal key")
}

/// The principal of the grant `response` issued a code for.
async fn grant_principal(server: &AuthorizationServer, response: &BrowserResponse) -> String {
    let (_, params) = code_issued(response);
    let code = state_of(server)
        .get(&keys::code(&params["code"]))
        .await
        .expect("store")
        .expect("code");
    state_of(server)
        .get(&keys::grant(&code.gid))
        .await
        .expect("store")
        .expect("grant")
        .principal
}

#[tokio::test]
async fn a_signed_in_user_is_the_principal_an_id_jag_names() {
    let idp = Idp::start().await;
    let cases = [
        (
            None,
            json!({}),
            format!("verified::ema::{}::{USER}", idp.issuer),
        ),
        (
            None,
            json!({ "tenant": "t1" }),
            format!("verified::ema::{}#t1::{USER}", idp.issuer),
        ),
        (
            Some("https://sso.acme.test/oauth2/default"),
            json!({}),
            "::https://sso.acme.test/oauth2/default::user-42".to_owned(),
        ),
    ];
    for (principal_issuer, extra, expected) in cases {
        let mut config = config(&idp);
        config.trusted_idps[0].principal_issuer = principal_issuer.map(str::to_owned);
        let server = server_with(&config);
        let from_id_jag = id_jag_principal(&server, &idp, extra.clone()).await;
        let started = start_web(&server).await;
        let response = complete_with(&server, &idp, &started, None, extra).await;
        let from_sign_in = grant_principal(&server, &response).await;
        assert_eq!(from_sign_in, from_id_jag, "{principal_issuer:?}");
        assert!(from_sign_in.ends_with(&expected), "{from_sign_in}");
        let audit = login_audit(&response);
        assert_eq!(
            format!(
                "verified::{}::{}::{}",
                audit.auth_provider, audit.principal_issuer, audit.subject
            ),
            from_sign_in
        );
    }
}

// ---------------------------------------------------------------------------
// Metadata and metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metadata_describes_the_authorization_endpoint_with_a_login_idp() {
    let idp = Idp::start().await;
    let server = server(&idp);
    let meta = server.metadata();
    assert_eq!(
        meta["authorization_endpoint"],
        format!("{GW_ISSUER}/oauth/authorize")
    );
    assert_eq!(meta["response_types_supported"], json!(["code"]));
    assert_eq!(meta["response_modes_supported"], json!(["query"]));
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["authorization_response_iss_parameter_supported"],
        json!(true)
    );
    assert_eq!(
        meta["grant_types_supported"],
        json!([GRANT_TYPE_JWT_BEARER, "authorization_code", "refresh_token"])
    );
    assert_eq!(
        meta["authorization_grant_profiles_supported"],
        json!([GRANT_PROFILE_ID_JAG])
    );
    assert!(
        !meta["scopes_supported"]
            .as_array()
            .expect("scopes")
            .contains(&json!("offline_access"))
    );
    assert!(
        meta["token_endpoint_auth_methods_supported"]
            .as_array()
            .expect("methods")
            .contains(&json!("none")),
        "a registered client is public"
    );
    assert!(meta.get("registration_endpoint").is_none());
    assert_eq!(
        server.login_idp().expect("login").redirect_uri(),
        format!("{GW_ISSUER}{CALLBACK_PATH}"),
        "the callback is the redirect URI registered at the IdP"
    );

    let mut documents = config(&idp);
    interactive(&mut documents).refresh_tokens.enabled = false;
    documents
        .clients
        .retain(|client| client.client_id == CLIENT_ID);
    documents.client_id_metadata_documents = crate::config::ClientIdMetadataDocumentsConfig {
        enabled: None,
        allowed_hosts: vec!["app.example".to_owned()],
        allow_private_network: false,
        redirect_uri_policy: Default::default(),
    };
    let meta = server_with(&documents).metadata();
    assert_eq!(
        meta["grant_types_supported"],
        json!([GRANT_TYPE_JWT_BEARER, "authorization_code"])
    );
    assert!(
        meta["token_endpoint_auth_methods_supported"]
            .as_array()
            .expect("methods")
            .contains(&json!("none")),
        "a metadata document may declare a public client"
    );

    let mut ema_only = config(&idp);
    ema_only.trusted_idps[0].login = None;
    ema_only
        .clients
        .retain(|client| client.client_id == CLIENT_ID);
    let meta = AuthorizationServer::from_config(&ema_only, None, ReplayLedger::in_process())
        .expect("builds")
        .metadata();
    assert!(meta.get("authorization_endpoint").is_none());
    assert!(meta.get("code_challenge_methods_supported").is_none());
    assert_eq!(meta["response_types_supported"], json!([]));
    assert_eq!(
        meta["grant_types_supported"],
        json!([GRANT_TYPE_JWT_BEARER])
    );
}

#[tokio::test]
async fn callbacks_are_counted_by_outcome_and_reason() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = server(&idp);
    let started = start_web(&server).await;
    complete(&server, &idp, &started, Some("idp-refresh-1")).await;
    callback(&server, &started, &[("code", IDP_CODE)]).await;
    let other = start_web(&server).await;
    callback_in(
        &server,
        &other,
        &[("code", IDP_CODE)],
        &TransactionCookies::default(),
    )
    .await;
    let other = start_web(&server).await;
    callback(
        &server,
        &other,
        &[("error", "login_required"), ("iss", idp.issuer)],
    )
    .await;
    for metric in [
        "mcpg_as_callback_total{outcome=code_issued,reason=none}",
        "mcpg_as_callback_total{outcome=refused,reason=unknown_state}",
        "mcpg_as_callback_total{outcome=refused,reason=binding}",
        "mcpg_as_callback_total{outcome=refused,reason=idp_error}",
        "mcpg_as_idp_sessions_total{op=store,outcome=ok}",
        "mcpg_as_idp_requests_total{op=code,outcome=ok}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}

#[path = "authorization_server_grants_tests.rs"]
mod code_grant;

#[path = "authorization_server_connect_tests.rs"]
mod connect_links;
