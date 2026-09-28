//! The authorization endpoint and its consent step: the order of the
//! checks, where each error goes, the sealed consent request, the form
//! token that binds it to the browser, and remembered consent.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::config::OAuthResourceMetadataConfig;
use crate::runtime::authorization_server::interactive::{
    AuthorizationRequest, BrowserAudit, BrowserCookie, BrowserCookies, BrowserOutcome,
    BrowserResponse, ConsentDecision, ConsentForm, ConsentPage, ConsentRequest, CookieChange,
    ErrorPage, MAX_CONSENT_COOKIE_BYTES, TransactionTag,
};
use crate::runtime::authorization_server::state::{
    CSRF_KEY_DOMAIN, ClientKind, ConsentApproval, ConsentMemoryRecord, InteractiveState,
    StateBackend, StateKeyring, StateParts, TransactionPurpose, UnavailableStore,
};

const LOGIN_CLIENT: &str = "gateway-login";
const RESOURCE: &str = "https://gw.test/mcp";
const OTHER_RESOURCE: &str = "https://gw.test/reports";
const CALLBACK: &str = "https://gw.test/oauth/callback";
/// The S256 challenge of RFC 7636 Appendix B.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_STATE: &str = "client-state-1";
const WEB_REDIRECT: &str = "https://app.example/cb";
const DESKTOP_REDIRECT: &str = "http://127.0.0.1:53682/callback";
const MIXED_REDIRECT: &str = "https://mixed.example/cb";

fn interactive_config() -> AuthorizationServerConfig {
    serde_json::from_value(serde_json::json!({
        "issuer": GW_ISSUER,
        "signing_secret": SIGNING_SECRET,
        "allowed_scopes": ["mcp:tools", "mcp:admin"],
        "trusted_idps": [{
            "issuer": IDP_ISSUER,
            "jwks_uri": format!("{IDP_ISSUER}/jwks"),
            "allowed_algs": ["RS256"],
            "login": {
                "client_id": LOGIN_CLIENT,
                "client_secret": "gateway-login-secret-0123456789",
                "display_name": "Acme SSO",
                "authorization_endpoint": format!("{IDP_ISSUER}/authorize"),
                "token_endpoint": format!("{IDP_ISSUER}/token"),
                "revocation_endpoint": format!("{IDP_ISSUER}/revoke"),
            },
        }],
        "clients": [
            { "client_id": "web-app", "client_name": "Web App", "redirect_uris": [WEB_REDIRECT] },
            {
                "client_id": "desktop",
                "client_name": "Desktop Agent",
                "redirect_uris": ["http://127.0.0.1/callback"],
            },
            {
                "client_id": "mixed",
                "redirect_uris": [MIXED_REDIRECT, "http://127.0.0.1/cb"],
            },
            {
                "client_id": "always",
                "redirect_uris": ["https://always.example/cb"],
                "consent": "always",
            },
            { "client_id": "jwt-only", "client_secret": "jwt-only-secret-0123456789" },
        ],
    }))
    .expect("config parses")
}

fn resource_metadata() -> OAuthResourceMetadataConfig {
    OAuthResourceMetadataConfig {
        resource: RESOURCE.to_owned(),
        additional_resources: vec![OTHER_RESOURCE.to_owned()],
        authorization_servers: Vec::new(),
        scopes_supported: vec!["mcp:tools".to_owned()],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    }
}

/// A server with interactive sign-in over `config`, its state in memory.
fn server_with(config: AuthorizationServerConfig) -> AuthorizationServer {
    config.validate().expect("config validates");
    AuthorizationServer::from_config(
        &config,
        Some(&resource_metadata()),
        ReplayLedger::in_process(),
    )
    .expect("server builds")
    .with_interactive_state(Some(InteractiveState::in_memory(GW_ISSUER).expect("state")))
}

fn server() -> AuthorizationServer {
    server_with(interactive_config())
}

fn state_of(server: &AuthorizationServer) -> &InteractiveState {
    server.interactive_state().expect("interactive state")
}

/// Stands for a new S256 challenge in each query of a [`Req`]: a
/// challenge is claimed once.
const FRESH_CHALLENGE: &str = "(fresh)";

fn fresh_challenge() -> String {
    crate::runtime::authorization_server::redirect::s256_challenge(
        &crate::runtime::authorization_server::state::random_token().expect("random"),
    )
}

/// An authorization request, parameter by parameter.
#[derive(Clone)]
struct Req(Vec<(String, String)>);

impl Req {
    fn new(client_id: &str, redirect_uri: &str) -> Self {
        Self(
            [
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("code_challenge", FRESH_CHALLENGE),
                ("code_challenge_method", "S256"),
                ("state", CLIENT_STATE),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        )
    }

    fn web() -> Self {
        Self::new("web-app", WEB_REDIRECT)
    }

    fn desktop() -> Self {
        Self::new("desktop", DESKTOP_REDIRECT)
    }

    /// Replace `name`, or add it.
    fn set(mut self, name: &str, value: &str) -> Self {
        self.0.retain(|(kept, _)| kept != name);
        self.0.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Add `name` once more.
    fn add(mut self, name: &str, value: &str) -> Self {
        self.0.push((name.to_owned(), value.to_owned()));
        self
    }

    fn without(mut self, name: &str) -> Self {
        self.0.retain(|(kept, _)| kept != name);
        self
    }

    fn query(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.0.iter().map(|(name, value)| {
                if name == "code_challenge" && value == FRESH_CHALLENGE {
                    (name.clone(), fresh_challenge())
                } else {
                    (name.clone(), value.clone())
                }
            }))
            .finish()
    }
}

async fn authorize(server: &AuthorizationServer, req: &Req) -> BrowserResponse {
    server
        .authorize(&req.query(), &BrowserCookies::default())
        .await
}

async fn authorize_with(
    server: &AuthorizationServer,
    req: &Req,
    cookies: &BrowserCookies,
) -> BrowserResponse {
    server.authorize(&req.query(), cookies).await
}

#[track_caller]
fn page(response: &BrowserResponse) -> &ErrorPage {
    match response.outcome {
        BrowserOutcome::Page(ref page) => page,
        ref other => panic!("expected a page, got {other:?}"),
    }
}

#[track_caller]
fn consent(response: &BrowserResponse) -> &ConsentPage {
    match response.outcome {
        BrowserOutcome::Consent(ref page) => page,
        ref other => panic!("expected the consent page, got {other:?}"),
    }
}

fn params(url: &str) -> HashMap<String, String> {
    let parsed = url::Url::parse(url).expect("absolute URL");
    let mut params = HashMap::new();
    for (name, value) in parsed.query_pairs() {
        assert!(
            params
                .insert(name.clone().into_owned(), value.into_owned())
                .is_none(),
            "{name} repeated in {url}"
        );
    }
    params
}

/// The error redirect `response` answers with, and its parameters.
#[track_caller]
fn error_redirect(response: &BrowserResponse) -> (String, HashMap<String, String>) {
    match response.outcome {
        BrowserOutcome::ErrorRedirect { ref location, .. } => (location.clone(), params(location)),
        ref other => panic!("expected an error redirect, got {other:?}"),
    }
}

/// The IdP authorization request `response` sends the browser to.
#[track_caller]
fn idp_request(response: &BrowserResponse) -> (String, HashMap<String, String>) {
    match response.outcome {
        BrowserOutcome::SignIn(ref location) => (location.clone(), params(location)),
        ref other => panic!("expected a redirect to the IdP, got {other:?}"),
    }
}

/// The value `response` sets the cookie `cookie` to.
fn cookie_set(response: &BrowserResponse, cookie: BrowserCookie) -> Option<(String, u64)> {
    response.cookies.iter().find_map(|change| match change {
        CookieChange::Set {
            cookie: set,
            value,
            max_age_secs,
        } if *set == cookie => Some((value.clone(), *max_age_secs)),
        _ => None,
    })
}

/// The form token of `request` in a browser holding `cookie`: HMAC-SHA256
/// under the consent-form key of the SHA-256 of each.
fn form_token(state: &InteractiveState, request: &str, cookie: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let key = &state.keyring().derive(CSRF_KEY_DOMAIN)[0];
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(sha2::Sha256::digest(request.as_bytes()).as_slice());
    input.extend_from_slice(sha2::Sha256::digest(cookie.as_bytes()).as_slice());
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(hmac_sha256::HMAC::mac(input, key.as_slice()))
}

/// What a browser posts back after loading the consent page `response`.
struct Loaded {
    request: String,
    token: String,
    cookies: BrowserCookies,
}

#[track_caller]
fn loaded(response: &BrowserResponse) -> Loaded {
    let page = consent(response);
    let (csrf, _) = cookie_set(response, BrowserCookie::Csrf).expect("the CSRF cookie is set");
    Loaded {
        request: page.request.clone(),
        token: page.csrf_token.clone(),
        cookies: BrowserCookies {
            csrf: Some(csrf),
            consent_memory: None,
        },
    }
}

fn decision(loaded: &Loaded, decision: &str) -> ConsentForm {
    ConsentForm {
        req: Some(loaded.request.clone()),
        csrf: Some(loaded.token.clone()),
        decision: Some(decision.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Before the client is validated: pages only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_repeated_parameter_is_refused_with_a_page() {
    let server = server();
    for name in [
        "state",
        "client_id",
        "redirect_uri",
        "scope",
        "code_challenge",
    ] {
        let response = authorize(&server, &Req::web().set(name, "first").add(name, "again")).await;
        let page = page(&response);
        assert_eq!(page.status, 400, "{name}");
        assert!(page.message.contains(&format!("`{name}`")), "{page:?}");
        assert!(page.return_to.is_none());
    }
    let response = authorize(
        &server,
        &Req::web()
            .add("unknown\u{7}param", "a")
            .add("unknown\u{7}param", "b"),
    )
    .await;
    assert!(
        !page(&response).message.contains('\u{7}'),
        "a parameter name is repeated back without control characters"
    );
}

#[tokio::test]
async fn request_objects_are_refused_with_a_page() {
    let server = server();
    for name in ["request", "request_uri"] {
        let response = authorize(&server, &Req::web().set(name, "eyJ.x.y")).await;
        let page = page(&response);
        assert_eq!(page.status, 400);
        assert!(page.message.contains("not supported"), "{page:?}");
        assert!(page.return_to.is_none());
    }
    let response = authorize(&server, &Req::web().set("request_uri", "")).await;
    assert!(
        matches!(response.outcome, BrowserOutcome::SignIn(_)),
        "an empty value counts as absent: {:?}",
        response.outcome
    );
}

#[tokio::test]
async fn a_client_or_redirect_uri_that_does_not_validate_gets_a_page() {
    let server = server();
    let cases = [
        (Req::web().without("client_id"), "invalid_request"),
        (Req::web().set("client_id", ""), "invalid_request"),
        (Req::new("nobody", WEB_REDIRECT), "invalid_client"),
        (Req::new("jwt-only", WEB_REDIRECT), "unauthorized_client"),
        (
            Req::web().set("redirect_uri", "https://app.example/cb/"),
            "invalid_request",
        ),
        (
            Req::web().set("redirect_uri", "https://attacker.example/cb"),
            "invalid_request",
        ),
        (Req::desktop().without("redirect_uri"), "invalid_request"),
        (
            Req::desktop().set("redirect_uri", "http://localhost:53682/callback"),
            "invalid_request",
        ),
    ];
    for (req, error) in cases {
        let response = authorize(&server, &req.clone().set("response_type", "token")).await;
        let page = page(&response);
        assert_eq!(page.status, 400, "{:?}", req.query());
        assert_eq!(page.error, error, "{:?}", req.query());
        assert!(page.return_to.is_none(), "never a redirect: {page:?}");
    }
}

#[tokio::test]
async fn a_single_https_redirect_uri_may_be_omitted() {
    let server = server();
    let response = authorize(&server, &Req::web().without("redirect_uri")).await;
    idp_request(&response);
    let response = authorize(
        &server,
        &Req::web()
            .without("redirect_uri")
            .set("response_type", "token"),
    )
    .await;
    let (location, _) = error_redirect(&response);
    assert!(
        location.starts_with("https://app.example/cb?"),
        "{location}"
    );
}

// ---------------------------------------------------------------------------
// After validation: errors go back to a trusted redirect URI
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_error_goes_back_to_a_trusted_redirect_uri_with_state_and_iss() {
    let server = server();
    let cases = [
        (
            Req::web().set("response_type", "token"),
            "unsupported_response_type",
        ),
        (Req::web().without("response_type"), "invalid_request"),
        (
            Req::web().set("response_mode", "fragment"),
            "invalid_request",
        ),
        (
            Req::web().set("response_mode", "form_post"),
            "invalid_request",
        ),
    ];
    for (req, error) in cases {
        let response = authorize(&server, &req).await;
        let (location, params) = error_redirect(&response);
        assert!(
            location.starts_with("https://app.example/cb?"),
            "{location}"
        );
        assert_eq!(params["error"], error, "{location}");
        assert_eq!(params["state"], CLIENT_STATE);
        assert_eq!(params["iss"], GW_ISSUER, "RFC 9207 iss on every error");
        assert!(!params.contains_key("code"));
    }
    idp_request(&authorize(&server, &Req::web().set("response_mode", "query")).await);

    let (_, params) = error_redirect(
        &authorize(
            &server,
            &Req::web().without("state").set("response_type", "token"),
        )
        .await,
    );
    assert!(!params.contains_key("state"), "no state when none was sent");
    assert_eq!(params["iss"], GW_ISSUER);
}

#[tokio::test]
async fn a_loopback_redirect_uri_is_trusted_with_its_own_port() {
    let server = server();
    let response = authorize(&server, &Req::desktop().set("response_type", "token")).await;
    let (location, params) = error_redirect(&response);
    assert!(
        location.starts_with("http://127.0.0.1:53682/callback?"),
        "the requested port is kept: {location}"
    );
    assert_eq!(params["error"], "unsupported_response_type");
}

#[tokio::test]
async fn pkce_s256_is_required() {
    let server = server();
    let cases = [
        (
            Req::web().without("code_challenge"),
            "code_challenge required",
        ),
        (
            Req::web().without("code_challenge_method"),
            "transform algorithm not supported",
        ),
        (
            Req::web().set("code_challenge_method", "plain"),
            "transform algorithm not supported",
        ),
        (
            Req::web().set("code_challenge", "too-short"),
            "code_challenge must be 43",
        ),
        (
            Req::web().set("code_challenge", &format!("{}=", &CHALLENGE[..42])),
            "code_challenge must be 43",
        ),
    ];
    for (req, description) in cases {
        let (_, params) = error_redirect(&authorize(&server, &req).await);
        assert_eq!(params["error"], "invalid_request");
        assert!(
            params["error_description"].contains(description),
            "{params:?}"
        );
    }
}

#[tokio::test]
async fn the_resource_is_one_this_server_serves() {
    let server = server();
    let resource_of = |response: &BrowserResponse| consent(response).resource.clone();
    assert_eq!(
        resource_of(&authorize(&server, &Req::desktop()).await),
        RESOURCE,
        "the default"
    );
    assert_eq!(
        resource_of(&authorize(&server, &Req::desktop().set("resource", OTHER_RESOURCE)).await),
        OTHER_RESOURCE
    );
    assert_eq!(
        resource_of(
            &authorize(
                &server,
                &Req::desktop().set("resource", &format!("{RESOURCE}/"))
            )
            .await
        ),
        RESOURCE,
        "a trailing slash is ignored"
    );
    for req in [
        Req::desktop().set("resource", "https://elsewhere.example/mcp"),
        Req::desktop()
            .set("resource", RESOURCE)
            .add("resource", OTHER_RESOURCE),
    ] {
        let (_, params) = error_redirect(&authorize(&server, &req).await);
        assert_eq!(params["error"], "invalid_target", "{:?}", req.query());
    }
}

#[tokio::test]
async fn scopes_are_narrowed_to_what_this_server_grants() {
    let server = server();
    let scopes_of = |response: &BrowserResponse| {
        consent(response)
            .scopes
            .iter()
            .map(|line| line.scope.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        scopes_of(&authorize(&server, &Req::desktop()).await),
        ["mcp:tools", "mcp:admin"],
        "no scope asks for every grantable one"
    );
    assert_eq!(
        scopes_of(
            &authorize(
                &server,
                &Req::desktop().set("scope", "openid offline_access mcp:admin bogus mcp:admin")
            )
            .await
        ),
        ["mcp:admin"],
        "openid, offline_access and unknown scopes dropped, each scope once"
    );
    assert_eq!(
        scopes_of(
            &authorize(
                &server,
                &Req::desktop().set("scope", "openid offline_access")
            )
            .await
        ),
        ["mcp:tools", "mcp:admin"],
        "only protocol scopes asks for every grantable one"
    );
    assert!(
        scopes_of(&authorize(&server, &Req::desktop().set("scope", "bogus")).await).is_empty(),
        "nothing grantable, and no scope required"
    );

    let mut config = interactive_config();
    config.require_scope = true;
    let strict = server_with(config);
    let (_, params) =
        error_redirect(&authorize(&strict, &Req::desktop().set("scope", "bogus")).await);
    assert_eq!(params["error"], "invalid_scope");
}

#[tokio::test]
async fn prompt_none_is_refused_and_consent_forces_the_page() {
    let server = server();
    for value in ["none", "login none", "bogus"] {
        let (_, params) =
            error_redirect(&authorize(&server, &Req::web().set("prompt", value)).await);
        assert_eq!(params["error"], "invalid_request", "{value}");
    }
    let page = consent(&authorize(&server, &Req::web().set("prompt", "consent")).await).clone();
    assert_eq!(page.client_name, "Web App");
    assert!(!page.loopback);

    let (_, idp) = idp_request(
        &authorize(
            &server,
            &Req::web().set("prompt", "login select_account login"),
        )
        .await,
    );
    assert_eq!(idp["prompt"], "login select_account");
    let (_, idp) = idp_request(&authorize(&server, &Req::web()).await);
    assert!(!idp.contains_key("prompt"));
}

#[tokio::test]
async fn state_and_login_hint_are_bounded() {
    let server = server();
    let long_state = "s".repeat(2049);
    let (_, params) =
        error_redirect(&authorize(&server, &Req::web().set("state", &long_state)).await);
    assert_eq!(params["error"], "invalid_request");
    assert!(
        !params.contains_key("state"),
        "an oversized state is not echoed"
    );
    idp_request(&authorize(&server, &Req::web().set("state", &"s".repeat(2048))).await);

    for hint in ["h".repeat(257), "alice\u{0}@example.com".to_owned()] {
        let (_, params) =
            error_redirect(&authorize(&server, &Req::web().set("login_hint", &hint)).await);
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], CLIENT_STATE);
    }
    let (_, idp) =
        idp_request(&authorize(&server, &Req::web().set("login_hint", "alice@example.com")).await);
    assert_eq!(idp["login_hint"], "alice@example.com");
}

#[tokio::test]
async fn a_client_the_idp_does_not_allow_is_denied() {
    let mut config = interactive_config();
    config.trusted_idps[0].allowed_clients = vec!["desktop".to_owned()];
    let server = server_with(config);
    let (_, params) = error_redirect(&authorize(&server, &Req::web()).await);
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["iss"], GW_ISSUER);
    consent(&authorize(&server, &Req::desktop()).await);
}

// ---------------------------------------------------------------------------
// Sign-in at the IdP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registered_https_client_goes_straight_to_the_idp() {
    let server = server();
    let response = authorize(&server, &Req::web().set("scope", "mcp:tools")).await;
    let (location, idp) = idp_request(&response);
    assert!(
        location.starts_with("https://idp.test/authorize?"),
        "{location}"
    );
    assert_eq!(idp["response_type"], "code");
    assert_eq!(idp["client_id"], LOGIN_CLIENT, "the gateway's own client");
    assert_eq!(idp["redirect_uri"], CALLBACK, "built from the issuer");
    assert_eq!(idp["scope"], "openid profile email offline_access");
    assert_eq!(idp["code_challenge_method"], "S256");
    assert_eq!(idp["code_challenge"].len(), 43);
    assert_ne!(
        idp["code_challenge"], CHALLENGE,
        "the gateway's own verifier"
    );
    assert_eq!(idp["state"].len(), 43);
    assert_ne!(idp["state"], CLIENT_STATE, "the gateway's own state");
    assert_eq!(idp["nonce"].len(), 43);
    assert_eq!(
        response.cookies.len(),
        1,
        "only the binding cookie: {:?}",
        response.cookies
    );
    assert!(
        cookie_set(
            &response,
            BrowserCookie::Transaction(TransactionTag::of_state(&idp["state"]))
        )
        .is_some()
    );
    assert!(response.audit.is_none());

    let (_, again) = idp_request(&authorize(&server, &Req::web()).await);
    assert_ne!(again["state"], idp["state"]);
    assert_ne!(again["nonce"], idp["nonce"]);
}

#[tokio::test]
async fn unreachable_idp_endpoints_answer_503() {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&idp)
        .await;
    let issuer = leak(idp.uri());
    let mut config = interactive_config();
    config.trusted_idps[0] = serde_json::from_value(serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks"),
        "allow_private_network": true,
        "allowed_algs": ["RS256"],
        "login": { "client_id": LOGIN_CLIENT, "client_secret": "gateway-login-secret-0123456789" },
    }))
    .expect("IdP parses");
    let server = server_with(config);
    let response = authorize(&server, &Req::web()).await;
    let page = page(&response);
    assert_eq!(page.status, 503);
    assert_eq!(page.error, "temporarily_unavailable");
}

#[tokio::test]
async fn sign_in_answers_503_without_a_usable_state_store() {
    let without = AuthorizationServer::from_config(
        &interactive_config(),
        Some(&resource_metadata()),
        ReplayLedger::in_process(),
    )
    .expect("server builds");
    assert_eq!(page(&authorize(&without, &Req::web()).await).status, 503);

    let degraded = server().with_interactive_state(Some(
        InteractiveState::new(StateParts {
            kv: Arc::new(UnavailableStore::new("no coordinator store")),
            backend: StateBackend::Unavailable,
            keyring: Arc::new(StateKeyring::process().expect("key")),
            issuer: GW_ISSUER.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })
        .expect("state"),
    ));
    assert_eq!(page(&authorize(&degraded, &Req::web()).await).status, 503);
    let form = ConsentForm::default();
    assert_eq!(
        page(
            &degraded
                .decide_consent(&form, &BrowserCookies::default())
                .await
        )
        .status,
        503
    );
}

// ---------------------------------------------------------------------------
// The consent page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_consent_page_seals_the_request_and_binds_the_browser() {
    let server = server();
    let response = authorize(
        &server,
        &Req::desktop()
            .set("scope", "mcp:tools")
            .set("code_challenge", CHALLENGE),
    )
    .await;
    let page = consent(&response);
    assert_eq!(page.service_name, "gw.test");
    assert_eq!(page.client_name, "Desktop Agent");
    assert_eq!(page.client_kind, ClientKind::Static);
    assert_eq!(page.client_host, None);
    assert_eq!(page.redirect_uri, DESKTOP_REDIRECT);
    assert!(page.loopback);
    assert_eq!(page.idp_name, "Acme SSO");
    assert!(
        page.keeps_idp_sign_in,
        "refresh tokens are checked at the IdP"
    );
    assert_eq!(page.form_action, "https://gw.test/oauth/consent");
    assert!(response.audit.is_none());

    let (csrf, max_age) = cookie_set(&response, BrowserCookie::Csrf).expect("CSRF cookie");
    assert_eq!(max_age, 600, "as long as a sign-in may take");
    assert_eq!(csrf.len(), 43);
    assert_eq!(
        page.csrf_token,
        form_token(state_of(&server), &page.request, &csrf)
    );
    assert!(
        !page.request.contains("desktop"),
        "the request is encrypted"
    );

    let sealed: ConsentRequest = state_of(&server)
        .open_value("consent_req", &page.request)
        .expect("the request opens under its label");
    assert_eq!(sealed.purpose, TransactionPurpose::Authorize);
    let now = now_unix();
    assert!(
        (now + 590..=now + 600).contains(&sealed.exp),
        "{}",
        sealed.exp
    );
    let request = sealed.authorization.expect("the authorization request");
    assert_eq!(
        request,
        AuthorizationRequest {
            client_id: "desktop".to_owned(),
            client_kind: ClientKind::Static,
            client_name: Some("Desktop Agent".to_owned()),
            redirect_uri: DESKTOP_REDIRECT.to_owned(),
            redirect_trusted: true,
            redirect_loopback: true,
            state: Some(CLIENT_STATE.to_owned()),
            code_challenge: CHALLENGE.to_owned(),
            resource: RESOURCE.to_owned(),
            scope: vec!["mcp:tools".to_owned()],
            prompt: None,
            login_hint: None,
            rememberable: false,
            dpop_jkt: None,
            authorization_details: Default::default(),
        }
    );
    assert!(
        state_of(&server)
            .store()
            .list_prefix("as/v1/", 10)
            .await
            .expect("list")
            .is_empty(),
        "showing the consent page writes nothing to the store"
    );
}

#[tokio::test]
async fn the_consent_page_keeps_a_browsers_csrf_cookie() {
    let server = server();
    let first = authorize(&server, &Req::desktop()).await;
    let (csrf, _) = cookie_set(&first, BrowserCookie::Csrf).expect("set");
    let cookies = BrowserCookies {
        csrf: Some(csrf.clone()),
        consent_memory: None,
    };
    let second = authorize_with(&server, &Req::desktop(), &cookies).await;
    assert_eq!(
        cookie_set(&second, BrowserCookie::Csrf)
            .expect("refreshed")
            .0,
        csrf,
        "a page in a second tab keeps the first tab's form valid"
    );
    let first = loaded(&first);
    let response = server
        .decide_consent(&decision(&first, "approve"), &cookies)
        .await;
    idp_request(&response);

    let malformed = BrowserCookies {
        csrf: Some("short".to_owned()),
        consent_memory: None,
    };
    let replaced = authorize_with(&server, &Req::desktop(), &malformed).await;
    assert_ne!(
        cookie_set(&replaced, BrowserCookie::Csrf).expect("set").0,
        "short"
    );
}

#[tokio::test]
async fn a_metadata_document_client_is_shown_unverified_with_its_host() {
    let (_host, url) = document_host(&["https://127.0.0.1/cb", "http://127.0.0.1/cb"]).await;
    let server = server_with(with_documents(interactive_config()));
    let page = consent(&authorize(&server, &Req::new(url, "https://127.0.0.1/cb")).await).clone();
    assert_eq!(page.client_kind, ClientKind::Cimd);
    assert_eq!(page.client_name, "Agent");
    assert_eq!(page.client_host.as_deref(), Some("127.0.0.1"));
    assert!(!page.loopback);
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approving_sends_the_browser_to_the_idp_once() {
    let server = server();
    let page = loaded(&authorize(&server, &Req::desktop()).await);
    let response = server
        .decide_consent(&decision(&page, "approve"), &page.cookies)
        .await;
    let (_, idp) = idp_request(&response);
    assert_eq!(idp["client_id"], LOGIN_CLIENT);
    let tag = TransactionTag::of_state(&idp["state"]);
    assert_eq!(
        response
            .cookies
            .iter()
            .map(|change| match change {
                CookieChange::Set { cookie, .. } => (*cookie, true),
                CookieChange::Clear(cookie) => (*cookie, false),
            })
            .collect::<Vec<_>>(),
        vec![(BrowserCookie::Transaction(tag), true)],
        "a loopback approval is never remembered, and the CSRF cookie stays"
    );
    match response.audit {
        Some(BrowserAudit::Consent {
            decision,
            ref client_id,
            client_kind,
            ref redirect_host,
            ..
        }) => {
            assert_eq!(decision, ConsentDecision::Approved);
            assert_eq!(client_id, "desktop");
            assert_eq!(client_kind, ClientKind::Static);
            assert_eq!(redirect_host, "127.0.0.1");
        }
        ref other => panic!("expected a consent audit, got {other:?}"),
    }

    let again = server
        .decide_consent(&decision(&page, "approve"), &page.cookies)
        .await;
    let refused = self::page(&again);
    assert_eq!(refused.status, 400);
    assert!(refused.title.contains("already answered"), "{refused:?}");
    let denied_after = server
        .decide_consent(&decision(&page, "deny"), &page.cookies)
        .await;
    assert_eq!(
        self::page(&denied_after).status,
        400,
        "one decision per page"
    );
}

#[tokio::test]
async fn a_decision_needs_the_browser_that_loaded_the_page() {
    let server = server();
    let page = loaded(&authorize(&server, &Req::desktop()).await);
    let other = loaded(&authorize(&server, &Req::desktop()).await);
    let refused = [
        (decision(&page, "approve"), BrowserCookies::default()),
        (
            ConsentForm {
                csrf: None,
                ..decision(&page, "approve")
            },
            page.cookies.clone(),
        ),
        (
            ConsentForm {
                csrf: Some(other.token.clone()),
                ..decision(&page, "approve")
            },
            page.cookies.clone(),
        ),
        (decision(&page, "approve"), other.cookies.clone()),
        (
            ConsentForm {
                // The last of 43 base64url characters holds 4 bits: `A`
                // and `E` are both valid there, and differ.
                csrf: Some(format!(
                    "{}{}",
                    &page.token[..42],
                    if page.token.ends_with('A') { 'E' } else { 'A' }
                )),
                ..decision(&page, "approve")
            },
            page.cookies.clone(),
        ),
    ];
    for (form, cookies) in refused {
        let response = server.decide_consent(&form, &cookies).await;
        let refusal = self::page(&response);
        assert_eq!(refusal.status, 403);
        assert!(
            matches!(response.audit, Some(BrowserAudit::Refused { .. })),
            "{:?}",
            response.audit
        );
        assert!(response.cookies.is_empty());
    }
    let response = server
        .decide_consent(&decision(&page, "approve"), &page.cookies)
        .await;
    idp_request(&response);
}

#[tokio::test]
async fn two_pages_under_one_csrf_cookie_are_each_decided() {
    let server = server();
    let first = loaded(&authorize(&server, &Req::desktop()).await);
    let second = authorize_with(&server, &Req::desktop(), &first.cookies).await;
    let second = loaded(&second);
    assert_eq!(
        second.cookies.csrf, first.cookies.csrf,
        "one cookie for both pages"
    );
    let approved = server
        .decide_consent(&decision(&first, "approve"), &first.cookies)
        .await;
    idp_request(&approved);
    let denied = server
        .decide_consent(&decision(&second, "deny"), &first.cookies)
        .await;
    let (_, params) = error_redirect(&denied);
    assert_eq!(params["error"], "access_denied");
    assert!(
        matches!(
            denied.audit,
            Some(BrowserAudit::Consent {
                decision: ConsentDecision::Denied,
                ..
            })
        ),
        "not a forgery: {:?}",
        denied.audit
    );
}

#[tokio::test]
async fn an_expired_altered_or_foreign_request_is_refused() {
    let server = server();
    let state = state_of(&server);
    let cookie = "c".repeat(43);
    let cookies = BrowserCookies {
        csrf: Some(cookie.clone()),
        consent_memory: None,
    };
    let page = consent(&authorize(&server, &Req::desktop()).await).clone();
    let request: ConsentRequest = state
        .open_value("consent_req", &page.request)
        .expect("opens");
    let post = |sealed: &str| ConsentForm {
        req: Some(sealed.to_owned()),
        csrf: Some(form_token(state, sealed, &cookie)),
        decision: Some("approve".to_owned()),
    };

    let expired = state
        .seal_value(
            "consent_req",
            &ConsentRequest {
                exp: now_unix() - 1,
                ..request.clone()
            },
        )
        .expect("seals");
    let connect = state
        .seal_value(
            "consent_req",
            &ConsentRequest {
                purpose: TransactionPurpose::Connect,
                ..request.clone()
            },
        )
        .expect("seals");
    let empty = state
        .seal_value(
            "consent_req",
            &ConsentRequest {
                authorization: None,
                ..request.clone()
            },
        )
        .expect("seals");
    let other_label = state.seal_value("consent_memory", &request).expect("seals");
    let foreign = InteractiveState::in_memory("https://other.test")
        .expect("state")
        .seal_value("consent_req", &request)
        .expect("seals");
    let mut altered = page.request.clone().into_bytes();
    altered[10] = if altered[10] == b'A' { b'B' } else { b'A' };
    let altered = String::from_utf8(altered).expect("ASCII");
    for sealed in [
        expired,
        connect,
        empty,
        other_label,
        foreign,
        altered,
        String::new(),
    ] {
        let response = server.decide_consent(&post(&sealed), &cookies).await;
        let refusal = self::page(&response);
        assert_eq!(refusal.status, 400, "{sealed}");
        assert!(refusal.title.contains("expired"), "{refusal:?}");
    }
    let oversized = "A".repeat(40_000);
    assert_eq!(
        self::page(&server.decide_consent(&post(&oversized), &cookies).await).status,
        400
    );

    let fresh = state.seal_value("consent_req", &request).expect("seals");
    idp_request(&server.decide_consent(&post(&fresh), &cookies).await);
}

#[tokio::test]
async fn a_missing_decision_is_refused_without_spending_the_page() {
    let server = server();
    let page = loaded(&authorize(&server, &Req::desktop()).await);
    for value in [None, Some("maybe")] {
        let form = ConsentForm {
            decision: value.map(str::to_owned),
            ..decision(&page, "approve")
        };
        let response = server.decide_consent(&form, &page.cookies).await;
        assert_eq!(self::page(&response).status, 400);
    }
    idp_request(
        &server
            .decide_consent(&decision(&page, "approve"), &page.cookies)
            .await,
    );
}

#[tokio::test]
async fn a_store_failure_refuses_the_decision() {
    let broken = server().with_interactive_state(Some(
        InteractiveState::new(StateParts {
            kv: Arc::new(UnavailableStore::new("disk full")),
            backend: StateBackend::InProcess,
            keyring: Arc::new(StateKeyring::process().expect("key")),
            issuer: GW_ISSUER.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })
        .expect("state"),
    ));
    let page = loaded(&authorize(&broken, &Req::desktop()).await);
    let response = broken
        .decide_consent(&decision(&page, "approve"), &page.cookies)
        .await;
    assert_eq!(self::page(&response).status, 503, "fails closed");
}

#[tokio::test]
async fn denying_goes_back_only_to_a_trusted_redirect_uri() {
    let server = server();
    let page = loaded(&authorize(&server, &Req::desktop()).await);
    let response = server
        .decide_consent(&decision(&page, "deny"), &page.cookies)
        .await;
    let (location, params) = error_redirect(&response);
    assert!(location.starts_with("http://127.0.0.1:53682/callback?"));
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], CLIENT_STATE);
    assert_eq!(params["iss"], GW_ISSUER);
    assert!(response.cookies.is_empty(), "{:?}", response.cookies);
    assert!(matches!(
        response.audit,
        Some(BrowserAudit::Consent {
            decision: ConsentDecision::Denied,
            ..
        })
    ));

    let (_host, url) = document_host(&["https://127.0.0.1/cb"]).await;
    let server = server_with(with_documents(interactive_config()));
    let page = loaded(&authorize(&server, &Req::new(url, "https://127.0.0.1/cb")).await);
    let response = server
        .decide_consent(&decision(&page, "deny"), &page.cookies)
        .await;
    let refusal = self::page(&response);
    assert_eq!(refusal.status, 403);
    assert_eq!(refusal.error, "access_denied");
    let link = refusal.return_to.as_ref().expect("a link the user follows");
    assert_eq!(link.host, "127.0.0.1");
    let params = self::params(&link.href);
    assert!(link.href.starts_with("https://127.0.0.1/cb?"));
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["iss"], GW_ISSUER);
}

#[tokio::test]
async fn an_error_for_an_untrusted_redirect_uri_is_offered_as_a_link() {
    let (_host, url) = document_host(&["https://127.0.0.1/cb"]).await;
    let server = server_with(with_documents(interactive_config()));
    let response = authorize(
        &server,
        &Req::new(url, "https://127.0.0.1/cb").set("response_type", "token"),
    )
    .await;
    let page = page(&response);
    assert_eq!(page.status, 400);
    assert_eq!(page.error, "unsupported_response_type");
    let link = page.return_to.as_ref().expect("a link");
    let params = params(&link.href);
    assert_eq!(params["error"], "unsupported_response_type");
    assert_eq!(params["state"], CLIENT_STATE);
    assert_eq!(params["iss"], GW_ISSUER);
}

// ---------------------------------------------------------------------------
// Remembered consent
// ---------------------------------------------------------------------------

/// Approve `req` on its consent page in a browser holding `memory`; the
/// consent cookie the approval sets.
async fn approve(server: &AuthorizationServer, req: &Req, memory: Option<&str>) -> Option<String> {
    let cookies = BrowserCookies {
        csrf: None,
        consent_memory: memory.map(str::to_owned),
    };
    let mut page = loaded(&authorize_with(server, req, &cookies).await);
    page.cookies.consent_memory = memory.map(str::to_owned);
    let response = server
        .decide_consent(&decision(&page, "approve"), &page.cookies)
        .await;
    idp_request(&response);
    cookie_set(&response, BrowserCookie::ConsentMemory).map(|(value, max_age)| {
        assert_eq!(max_age, 30 * 86_400);
        value
    })
}

fn remembering(memory: &str) -> BrowserCookies {
    BrowserCookies {
        csrf: None,
        consent_memory: Some(memory.to_owned()),
    }
}

#[tokio::test]
async fn an_approval_is_remembered_for_the_same_client_redirect_uri_resource_and_scopes() {
    let server = server();
    let mixed = Req::new("mixed", MIXED_REDIRECT).set("scope", "mcp:tools");
    let memory = approve(&server, &mixed, None)
        .await
        .expect("an https approval of a registered client is remembered");
    assert!(!memory.contains("mixed"), "the cookie is encrypted");

    let response = authorize_with(&server, &mixed, &remembering(&memory)).await;
    let (_, idp) = idp_request(&response);
    assert!(matches!(
        response.audit,
        Some(BrowserAudit::Consent {
            decision: ConsentDecision::Remembered,
            ..
        })
    ));
    assert_eq!(
        response.cookies.len(),
        1,
        "the binding cookie alone: {:?}",
        response.cookies
    );
    assert!(
        cookie_set(
            &response,
            BrowserCookie::Transaction(TransactionTag::of_state(&idp["state"]))
        )
        .is_some()
    );
    idp_request(
        &authorize_with(
            &server,
            &mixed.clone().set("state", "another"),
            &remembering(&memory),
        )
        .await,
    );
    idp_request(
        &authorize_with(
            &server,
            &mixed.clone().set("resource", &format!("{RESOURCE}/")),
            &remembering(&memory),
        )
        .await,
    );

    let misses = [
        mixed.clone().set("resource", OTHER_RESOURCE),
        mixed.clone().set("scope", "mcp:tools mcp:admin"),
        mixed.clone().without("scope"),
        mixed.clone().set("prompt", "consent"),
        Req::new("mixed", "http://127.0.0.1:4000/cb").set("scope", "mcp:tools"),
        Req::new("always", "https://always.example/cb").set("scope", "mcp:tools"),
    ];
    for req in misses {
        consent(&authorize_with(&server, &req, &remembering(&memory)).await);
    }
    let foreign = server_with(interactive_config());
    consent(&authorize_with(&foreign, &mixed, &remembering(&memory)).await);
    consent(&authorize_with(&server, &mixed, &remembering("garbage")).await);

    let wider = approve(
        &server,
        &mixed.clone().set("scope", "mcp:tools mcp:admin"),
        Some(&memory),
    )
    .await
    .expect("remembered");
    idp_request(&authorize_with(&server, &mixed, &remembering(&wider)).await);
    idp_request(
        &authorize_with(
            &server,
            &mixed.clone().set("scope", "mcp:admin"),
            &remembering(&wider),
        )
        .await,
    );
}

#[tokio::test]
async fn loopback_always_and_zero_day_approvals_are_never_remembered() {
    let server = server();
    assert_eq!(approve(&server, &Req::desktop(), None).await, None);
    assert_eq!(
        approve(
            &server,
            &Req::new("mixed", "http://127.0.0.1:4000/cb"),
            None
        )
        .await,
        None
    );
    assert_eq!(
        approve(
            &server,
            &Req::new("always", "https://always.example/cb"),
            None
        )
        .await,
        None
    );
    let (_host, url) = document_host(&["https://127.0.0.1/cb", "http://127.0.0.1/cb"]).await;
    let documents = server_with(with_documents(interactive_config()));
    assert!(
        approve(&documents, &Req::new(url, "https://127.0.0.1/cb"), None)
            .await
            .is_some(),
        "a metadata document's https redirect URI is remembered"
    );
    assert_eq!(
        approve(&documents, &Req::new(url, "http://127.0.0.1:9/cb"), None).await,
        None,
        "its loopback one is not"
    );

    let mut config = interactive_config();
    config
        .interactive
        .get_or_insert_with(Default::default)
        .consent
        .remember_days = 0;
    let forgetful = server_with(config);
    assert_eq!(
        approve(&forgetful, &Req::new("mixed", MIXED_REDIRECT), None).await,
        None
    );
}

#[tokio::test]
async fn a_remembered_approval_expires_after_remember_days() {
    let server = server();
    let state = state_of(&server);
    let approval = |days_ago: u64| {
        let mut memory = ConsentMemoryRecord::default();
        memory.remember(ConsentApproval {
            client_id: "mixed".to_owned(),
            redirect_uri: MIXED_REDIRECT.to_owned(),
            resource: RESOURCE.to_owned(),
            scopes: vec!["mcp:tools".to_owned()],
            approved_at: now_unix() - days_ago * 86_400,
        });
        state.seal_value("consent_memory", &memory).expect("seals")
    };
    let mixed = Req::new("mixed", MIXED_REDIRECT).set("scope", "mcp:tools");
    idp_request(&authorize_with(&server, &mixed, &remembering(&approval(29))).await);
    consent(&authorize_with(&server, &mixed, &remembering(&approval(31))).await);
}

#[tokio::test]
async fn the_consent_cookie_keeps_the_newest_approvals_within_its_budget() {
    let server = server();
    let state = state_of(&server);
    let request = |n: usize, path_len: usize| AuthorizationRequest {
        client_id: format!("client-{n}"),
        client_kind: ClientKind::Cimd,
        client_name: None,
        redirect_uri: format!("https://app{n}.example/{}", "p".repeat(path_len)),
        redirect_trusted: false,
        redirect_loopback: false,
        state: None,
        code_challenge: CHALLENGE.to_owned(),
        resource: RESOURCE.to_owned(),
        scope: vec!["mcp:tools".to_owned()],
        prompt: None,
        login_hint: None,
        rememberable: true,
        dpop_jkt: None,
        authorization_details: Default::default(),
    };
    let now = now_unix();
    let mut cookies = BrowserCookies::default();
    for n in 0..30 {
        let value = server
            .remember(state, &cookies, &request(n, 200), now + n as u64)
            .expect("fits");
        assert!(value.len() <= MAX_CONSENT_COOKIE_BYTES, "{}", value.len());
        cookies.consent_memory = Some(value);
    }
    let memory: ConsentMemoryRecord = state
        .open_value(
            "consent_memory",
            cookies.consent_memory.as_deref().expect("set"),
        )
        .expect("opens");
    let kept: Vec<&str> = memory
        .approvals
        .iter()
        .map(|approval| approval.client_id.as_str())
        .collect();
    assert!(kept.contains(&"client-29"), "the newest is kept: {kept:?}");
    assert!(!kept.contains(&"client-0"), "the oldest went: {kept:?}");
    assert!(kept.len() < 30);

    assert_eq!(
        server.remember(state, &BrowserCookies::default(), &request(99, 4_000), now),
        None,
        "an approval that alone exceeds the budget is not remembered"
    );
}

// ---------------------------------------------------------------------------
// Host, origin, audit and metrics
// ---------------------------------------------------------------------------

#[test]
fn the_host_must_be_the_issuers() {
    let server = server();
    for host in ["gw.test", "GW.test", "gw.test:443"] {
        assert!(server.is_issuer_host(host), "{host}");
    }
    for host in [
        "",
        "gw.test:8443",
        "evil.test",
        "gw.test.evil.test",
        "user@gw.test",
        "gw.test/path",
        "gw.test?q",
        "gw.test#f",
        "gw.test:443@evil.test",
    ] {
        assert!(!server.is_issuer_host(host), "{host}");
    }

    let mut config = interactive_config();
    config.issuer = "http://127.0.0.1:8080".to_owned();
    let local = server_with(config);
    assert!(local.is_issuer_host("127.0.0.1:8080"));
    assert!(!local.is_issuer_host("127.0.0.1"));
    assert!(!local.is_issuer_host("localhost:8080"));
    assert!(!local.secure_cookies());
    assert!(server.secure_cookies());
}

#[test]
fn a_decision_must_come_from_this_origin() {
    let server = server();
    let admitted = [
        (Some("https://gw.test"), None),
        (Some("https://gw.test:443"), None),
        (Some("https://gw.test"), Some("same-origin")),
        (None, Some("same-origin")),
        // What a browser sends for the form of a page with no referrer.
        (Some("null"), Some("same-origin")),
    ];
    for (origin, site) in admitted {
        assert!(
            server.is_same_origin_post(origin, site),
            "{origin:?} {site:?}"
        );
    }
    let refused = [
        (None, None),
        (None, Some("cross-site")),
        (None, Some("same-site")),
        (None, Some("none")),
        (Some("null"), None),
        (Some("null"), Some("cross-site")),
        (Some("null"), Some("same-site")),
        (Some("null"), Some("none")),
        (Some("https://evil.test"), None),
        (Some("http://gw.test"), None),
        (Some("https://gw.test:8443"), None),
        (Some("https://gw.test.evil.test"), None),
        (Some("https://gw.test"), Some("cross-site")),
        (Some("https://gw.test/path"), None),
    ];
    for (origin, site) in refused {
        assert!(
            !server.is_same_origin_post(origin, site),
            "{origin:?} {site:?}"
        );
    }
}

#[test]
fn audit_events_carry_no_secrets() {
    let consent = BrowserAudit::Consent {
        decision: ConsentDecision::Denied,
        client_id: "desktop".to_owned(),
        client_kind: ClientKind::Static,
        redirect_host: "127.0.0.1".to_owned(),
        scope: vec!["mcp:tools".to_owned()],
        resource: RESOURCE.to_owned(),
        authorization_details_types: Vec::new(),
    }
    .event("request-1");
    assert_eq!(consent.action, "mcpg.as.consent");
    assert_eq!(
        consent.outcome,
        mcpg_plugin_protocol::audit::AuditOutcome::Denied
    );
    assert_eq!(consent.actor.kind, "anonymous");
    assert_eq!(consent.request_id.as_deref(), Some("request-1"));
    assert_eq!(consent.resource.as_deref(), Some(RESOURCE));
    assert_eq!(
        consent.details,
        serde_json::json!({
            "decision": "denied",
            "client_id": "desktop",
            "client_kind": "static",
            "redirect_host": "127.0.0.1",
            "scope": ["mcp:tools"],
            "authorization_details_types": [],
        })
    );
    let refused = BrowserAudit::Refused { reason: "no match" }.event("request-2");
    assert_eq!(refused.action, "mcpg.auth.failed");
    assert_eq!(refused.details["auth_method"], "as_authorize");
}

#[tokio::test]
async fn authorize_and_consent_outcomes_are_counted() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = server();
    authorize(&server, &Req::web()).await;
    authorize(&server, &Req::web().set("response_type", "token")).await;
    authorize(&server, &Req::new("nobody", WEB_REDIRECT)).await;
    let page = loaded(&authorize(&server, &Req::desktop()).await);
    server
        .decide_consent(&decision(&page, "deny"), &page.cookies)
        .await;
    let memory = approve(&server, &Req::new("mixed", MIXED_REDIRECT), None)
        .await
        .expect("remembered");
    authorize_with(
        &server,
        &Req::new("mixed", MIXED_REDIRECT),
        &remembering(&memory),
    )
    .await;
    for metric in [
        "mcpg_as_authorize_total{outcome=idp_redirect,error=none,client_kind=static}",
        "mcpg_as_authorize_total{outcome=refused,error=unsupported_response_type,client_kind=static}",
        "mcpg_as_authorize_total{outcome=refused,error=invalid_client,client_kind=none}",
        "mcpg_as_authorize_total{outcome=consent_shown,error=none,client_kind=static}",
        "mcpg_as_consent_total{decision=denied,client_kind=static}",
        "mcpg_as_consent_total{decision=approved,client_kind=static}",
        "mcpg_as_consent_total{decision=remembered,client_kind=static}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}

// ---------------------------------------------------------------------------
// Client ID Metadata Documents
// ---------------------------------------------------------------------------

fn with_documents(mut config: AuthorizationServerConfig) -> AuthorizationServerConfig {
    config.client_id_metadata_documents = crate::config::ClientIdMetadataDocumentsConfig {
        enabled: None,
        allowed_hosts: vec!["127.0.0.1".to_owned()],
        allow_private_network: true,
        redirect_uri_policy: Default::default(),
    };
    config
}

/// A host serving a sign-in metadata document that lists
/// `redirect_uris`, and the document's URL, its `client_id`.
async fn document_host(redirect_uris: &[&str]) -> (wiremock::MockServer, &'static str) {
    let host = wiremock::MockServer::start().await;
    let url = leak(format!("{}/client.json", host.uri()));
    wiremock::Mock::given(wiremock::matchers::path("/client.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "client_id": url,
                    "client_name": "Agent",
                    "redirect_uris": redirect_uris,
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "none",
                }))
                .insert_header("cache-control", "max-age=300"),
        )
        .mount(&host)
        .await;
    (host, url)
}

// ---------------------------------------------------------------------------
// Authorization details (RFC 9396)
// ---------------------------------------------------------------------------

/// `interactive_config()` with the authorization details types of the
/// fixtures.
fn details_config() -> AuthorizationServerConfig {
    let mut config = interactive_config();
    config.authorization_details = super::rar_details::details_config();
    config
}

fn tool_details(identifier: &str) -> String {
    serde_json::json!([{
        "type": "mcp_tool",
        "actions": ["tools/call"],
        "locations": [RESOURCE],
        "identifier": identifier,
    }])
    .to_string()
}

#[tokio::test]
async fn invalid_details_go_back_to_a_trusted_redirect_uri_and_are_offered_otherwise() {
    let server = server_with(details_config());
    let bad = r#"[{"type":"mcp_tool","actions":["tools/call"],"identifier":"<script>"},{"type":"unknown"}]"#;
    let response = authorize(
        &server,
        &Req::web()
            .set("scope", "mcp:tools")
            .set("authorization_details", bad),
    )
    .await;
    let (_, sent) = error_redirect(&response);
    assert_eq!(sent["error"], "invalid_authorization_details");
    assert_eq!(
        sent["error_description"],
        "authorization_details[1].type is not a type this server accepts"
    );
    assert_eq!(sent["state"], CLIENT_STATE);

    let (_host, url) = document_host(&["https://127.0.0.1/cb"]).await;
    let server = server_with(with_documents(details_config()));
    let response = authorize(
        &server,
        &Req::new(url, "https://127.0.0.1/cb").set("authorization_details", "not json"),
    )
    .await;
    let page = page(&response);
    assert_eq!(page.status, 400);
    assert_eq!(page.error, "invalid_authorization_details");
    let link = page.return_to.as_ref().expect("a link");
    assert_eq!(params(&link.href)["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn a_request_for_details_is_shown_and_never_answered_from_memory() {
    let server = server_with(details_config());
    let mixed = Req::new("mixed", MIXED_REDIRECT).set("scope", "mcp:tools");
    let memory = approve(&server, &mixed, None)
        .await
        .expect("an https approval without details is remembered");
    let with_details = mixed
        .clone()
        .set("authorization_details", &tool_details("search"));
    let response = authorize_with(&server, &with_details, &remembering(&memory)).await;
    let shown = consent(&response);
    assert_eq!(shown.authorization_details.len(), 1);
    assert_eq!(shown.authorization_details[0].label, "Call MCP tools");
    assert_eq!(
        shown.authorization_details[0].identifier.as_deref(),
        Some("search")
    );
    assert_eq!(
        approve(&server, &with_details, Some(&memory)).await,
        None,
        "an approval of details sets no consent cookie"
    );
    let sealed: ConsentRequest = state_of(&server)
        .open_value("consent_req", &shown.request)
        .expect("the sealed request opens");
    let request = sealed.authorization.expect("an authorization request");
    assert!(!request.rememberable);
    assert_eq!(request.authorization_details.types(), ["mcp_tool"]);
    let consent_audit = BrowserAudit::Consent {
        decision: ConsentDecision::Approved,
        client_id: request.client_id.clone(),
        client_kind: request.client_kind,
        redirect_host: "mixed.example".to_owned(),
        scope: request.scope.clone(),
        resource: request.resource.clone(),
        authorization_details_types: vec!["mcp_tool".to_owned()],
    }
    .event("request-rar");
    assert_eq!(
        consent_audit.details["authorization_details_types"],
        serde_json::json!(["mcp_tool"])
    );
    assert!(
        !serde_json::to_string(&consent_audit)
            .expect("serializes")
            .contains("search")
    );
}

#[tokio::test]
async fn with_no_type_configured_the_details_parameter_is_ignored() {
    let server = server();
    let response = authorize(
        &server,
        &Req::web()
            .set("scope", "mcp:tools")
            .set("authorization_details", "not json"),
    )
    .await;
    idp_request(&response);
    let shown = authorize(
        &server,
        &Req::desktop().set("authorization_details", &tool_details("search")),
    )
    .await;
    let consent_page = consent(&shown);
    assert!(consent_page.authorization_details.is_empty());
    assert!(!consent_page.scopes.is_empty(), "every grantable scope");
}
