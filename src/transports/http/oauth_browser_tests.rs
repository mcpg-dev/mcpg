//! The sign-in pages through the router: 404 without a login IdP, host
//! pinning, the per-address budget, the header set, escaping, cookies,
//! the origin and CSRF checks of the consent form, and other methods. Also
//! dynamic client registration, whose clients the consent page marks.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::*;
use crate::config::AppConfig;
use crate::runtime::authorization_server::ReplayLedger;

const ISSUER: &str = "https://gw.test";
const DESKTOP_NAME: &str = "Tom <b>&</b> \"Jerry\" \u{202e}gnp.exe";

fn authorization_server(issuer: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut server = serde_json::json!({
        "issuer": issuer,
        "signing_secret": "integration-signing-secret-0123456789",
        "allowed_scopes": ["mcp:tools", "mcp:admin"],
        "trusted_idps": [{
            "issuer": "https://idp.test",
            "jwks_uri": "https://idp.test/jwks",
            "allowed_algs": ["RS256"],
            "login": {
                "client_id": "gateway-login",
                "client_secret": "gateway-login-secret-0123456789",
                "display_name": "Acme <SSO>",
                "authorization_endpoint": "https://idp.test/authorize",
                "token_endpoint": "https://idp.test/token",
                "revocation_endpoint": "https://idp.test/revoke",
            },
        }],
        "clients": [
            { "client_id": "web-app", "redirect_uris": ["https://app.example/cb"] },
            {
                "client_id": "desktop",
                "client_name": DESKTOP_NAME,
                "redirect_uris": ["http://127.0.0.1/callback"],
            },
            {
                "client_id": "mixed",
                "redirect_uris": ["https://mixed.example/cb", "http://127.0.0.1/cb"],
            },
        ],
        "interactive": {
            "consent": { "scope_descriptions": { "mcp:tools": "Use <i>tools</i>" } },
        },
    });
    if let (Some(server), serde_json::Value::Object(extra)) = (server.as_object_mut(), extra) {
        for (name, value) in extra {
            server.insert(name, value);
        }
    }
    server
}

/// A gateway configured with `authorization_server`, when set.
fn app_state(authorization_server: Option<serde_json::Value>) -> AppState {
    let mut config = AppConfig::default();
    config.gateway.server.trust_proxy_ip = true;
    config.gateway.server.cors = Some(
        serde_json::from_value(serde_json::json!({ "allowed_origins": ["https://app.example"] }))
            .expect("cors parses"),
    );
    config.governance.access.resource_metadata = Some(crate::config::OAuthResourceMetadataConfig {
        resource: format!("{ISSUER}/mcp"),
        additional_resources: Vec::new(),
        authorization_servers: Vec::new(),
        scopes_supported: vec!["mcp:tools".to_owned()],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    });
    config.governance.access.authorization_server = authorization_server
        .map(|value| serde_json::from_value(value).expect("authorization server parses"));
    let mut runtime = crate::runtime::GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        vec![crate::config::SinkConfig {
            kind: "stdout".to_owned(),
            config: serde_json::json!({"format": "json"}),
            level: None,
        }],
        true,
    );
    runtime.set_ema_authorization_server(
        crate::app::build_ema_authorization_server(&config, ReplayLedger::in_process())
            .expect("authorization server builds"),
    );
    AppState {
        config: Arc::new(ArcSwap::from_pointee(config.clone())),
        base_config: Arc::new(ArcSwap::from_pointee(config)),
        registry_overlay: Arc::new(ArcSwap::from_pointee(
            crate::runtime::registry_sync::RegistryOverlay::default(),
        )),
        runtime: Arc::new(ArcSwap::from_pointee(runtime)),
        session_store: Arc::new(
            crate::runtime::session_store::KvBackedSessionStore::new_in_memory(
                crate::runtime::SessionStoreConfig::default(),
            ),
        ),
        observability: Arc::new(crate::observability::ObservabilityHandle::default()),
        config_sources: Vec::new(),
        sse_stream_counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        config_overlay: Arc::new(ArcSwap::from_pointee(serde_json::Value::Object(
            serde_json::Map::new(),
        ))),
        policy_chain: Arc::new(ArcSwap::from_pointee(Vec::new())),
        plugin_health_prober: Arc::new(tokio::sync::Mutex::new(None)),
        secret_watcher: Arc::new(tokio::sync::Mutex::new(None)),
        #[cfg(feature = "governance-quotas")]
        quota_gate: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
    }
}

fn gateway(authorization_server: Option<serde_json::Value>) -> Router {
    router(app_state(authorization_server), "/health", "/mcp")
}

fn signing_in() -> Router {
    gateway(Some(authorization_server(ISSUER, serde_json::json!({}))))
}

/// A new S256 challenge: each is claimed once.
fn fresh_challenge() -> String {
    crate::runtime::authorization_server::redirect::s256_challenge(
        &crate::runtime::authorization_server::state::random_token().expect("random"),
    )
}

fn authorize_path(client_id: &str, redirect_uri: &str, extra: &[(&str, &str)]) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_challenge", &fresh_challenge())
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", "client-state");
    for (name, value) in extra {
        query.append_pair(name, value);
    }
    format!("/oauth/authorize?{}", query.finish())
}

fn desktop_path() -> String {
    authorize_path("desktop", "http://127.0.0.1:53682/callback", &[])
}

fn get(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, "gw.test")
}

async fn send(app: &Router, request: axum::http::request::Builder) -> axum::response::Response {
    app.clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("UTF-8 body")
}

fn header_value<'a>(response: &'a axum::response::Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}

fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("ASCII cookie").to_owned())
        .collect()
}

/// The value of the hidden form field `name` in a consent page.
fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker).expect("field present") + marker.len();
    html[start..]
        .split('"')
        .next()
        .expect("field value")
        .to_owned()
}

/// The `name=value` of the `Set-Cookie` header naming `name`.
fn cookie_pair(response: &axum::response::Response, name: &str) -> String {
    set_cookies(response)
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .and_then(|cookie| cookie.split(';').next().map(str::to_owned))
        .unwrap_or_else(|| panic!("{name} is set"))
}

#[track_caller]
fn assert_protected(response: &axum::response::Response) {
    assert_eq!(header_value(response, "cache-control"), Some("no-store"));
    assert_eq!(header_value(response, "pragma"), Some("no-cache"));
    assert_eq!(
        header_value(response, "referrer-policy"),
        Some("no-referrer")
    );
    assert_eq!(
        header_value(response, "x-content-type-options"),
        Some("nosniff")
    );
    assert!(header_value(response, "x-mcpg-request-id").is_some());
    assert!(
        response
            .headers()
            .keys()
            .all(|name| !name.as_str().starts_with("access-control-")),
        "no CORS on a sign-in page: {:?}",
        response.headers()
    );
}

#[track_caller]
fn assert_page(response: &axum::response::Response) {
    assert_protected(response);
    assert_eq!(
        header_value(response, "content-type"),
        Some("text/html; charset=utf-8")
    );
    let policy = header_value(response, "content-security-policy").expect("CSP");
    assert!(
        policy.starts_with("default-src 'none'; style-src 'sha256-"),
        "{policy}"
    );
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert!(policy.contains("base-uri 'none'"), "{policy}");
    assert!(!policy.contains("form-action"), "{policy}");
    assert!(!policy.contains("script"), "{policy}");
    assert_eq!(header_value(response, "x-frame-options"), Some("DENY"));
    assert_eq!(
        header_value(response, "cross-origin-opener-policy"),
        None,
        "a client's popup keeps its opener"
    );
}

/// The headers a browser sends with the form of a page whose referrer
/// policy is `no-referrer`.
const BROWSER_FORM_POST: [(&str, &str); 2] =
    [("origin", "null"), ("sec-fetch-site", "same-origin")];

/// A consent page loaded in a browser: the form fields and the cookie.
struct ConsentLoaded {
    req: String,
    csrf: String,
    cookie: String,
}

async fn load_consent(app: &Router, path: &str) -> ConsentLoaded {
    let response = send(app, get(path)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_pair(&response, "__Host-mcpg_csrf");
    let html = body_text(response).await;
    ConsentLoaded {
        req: hidden(&html, "req"),
        csrf: hidden(&html, "csrf"),
        cookie,
    }
}

async fn post_consent(
    app: &Router,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> axum::response::Response {
    post_consent_to(app, "gw.test", form, headers).await
}

async fn post_consent_to(
    app: &Router,
    host: &str,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> axum::response::Response {
    post_form(app, host, "/oauth/consent", form, headers).await
}

async fn post_form(
    app: &Router,
    host: &str,
    path: &str,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    app.clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn without_a_login_idp_the_pages_answer_404() {
    let mut without_login = authorization_server(ISSUER, serde_json::json!({}));
    without_login["trusted_idps"][0]
        .as_object_mut()
        .expect("IdP")
        .remove("login");
    without_login
        .as_object_mut()
        .expect("server")
        .remove("interactive");
    without_login["clients"] = serde_json::json!([]);
    for app in [gateway(None), gateway(Some(without_login))] {
        let response = send(&app, get(&desktop_path())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_page(&response);
        assert!(body_text(response).await.contains("not offered"));
        let response = post_consent(&app, &[("req", "x")], &[("origin", ISSUER)]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = send(&app, get("/oauth/connect")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_page(&response);
    }
}

#[tokio::test]
async fn the_connect_page_carries_the_header_set_and_escapes_what_it_shows() {
    let app = signing_in();
    let response = send(&app, get("/oauth/connect")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_page(&response);
    let cookie = set_cookies(&response)
        .into_iter()
        .find(|cookie| cookie.starts_with("__Host-mcpg_csrf="))
        .expect("the CSRF cookie is set");
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    let html = body_text(response).await;
    assert!(
        html.contains("Connect your Acme &lt;SSO&gt; sign-in"),
        "{html}"
    );
    assert!(html.contains("form method=\"post\" action=\"https://gw.test/oauth/connect\""));
    assert!(!html.contains("<script") && !html.contains("<img"));
    assert!(
        !html.contains("Continue only if"),
        "the page opened without a link carries no link warning"
    );

    let off_host = send(
        &app,
        Request::builder()
            .method("GET")
            .uri("/oauth/connect")
            .header(header::HOST, "evil.test"),
    )
    .await;
    assert_eq!(off_host.status(), StatusCode::BAD_REQUEST);

    let unknown_link = send(
        &app,
        get(&format!(
            "/oauth/connect?e={}",
            crate::runtime::authorization_server::state::random_token().expect("random")
        )),
    )
    .await;
    assert_eq!(unknown_link.status(), StatusCode::BAD_REQUEST);
    assert_page(&unknown_link);
    assert!(
        body_text(unknown_link)
            .await
            .contains("expired or was already used")
    );
}

#[tokio::test]
async fn a_connect_decision_from_this_page_goes_to_the_idp_once() {
    let app = signing_in();
    let page = load_consent(&app, "/oauth/connect").await;
    let form = [
        ("req", page.req.as_str()),
        ("csrf", page.csrf.as_str()),
        ("decision", "approve"),
    ];
    let cross_site = post_form(
        &app,
        "gw.test",
        "/oauth/connect",
        &form,
        &[
            ("origin", "https://evil.test"),
            ("cookie", page.cookie.as_str()),
        ],
    )
    .await;
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_page(&cross_site);

    let mut headers = BROWSER_FORM_POST.to_vec();
    headers.push(("cookie", page.cookie.as_str()));
    let response = post_form(&app, "gw.test", "/oauth/connect", &form, &headers).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_protected(&response);
    assert!(
        header_value(&response, "location")
            .is_some_and(|location| location.starts_with("https://idp.test/authorize?")),
        "{:?}",
        response.headers()
    );
    assert!(
        set_cookies(&response)
            .iter()
            .any(|cookie| cookie.starts_with("__Host-mcpg_txn_")),
        "the sign-in is bound to this browser"
    );

    let again = post_form(&app, "gw.test", "/oauth/connect", &form, &headers).await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "taken once");

    let consent_form = post_consent(&app, &form, &headers).await;
    assert_eq!(
        consent_form.status(),
        StatusCode::BAD_REQUEST,
        "a connect form is not a consent decision"
    );
}

#[tokio::test]
async fn a_request_off_the_issuers_host_is_refused() {
    let app = signing_in();
    for host in ["evil.test", "gw.test:8443", "gw.test.evil.test"] {
        let response = send(
            &app,
            Request::builder()
                .uri(desktop_path())
                .header(header::HOST, host),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{host}");
        assert_page(&response);
        assert!(set_cookies(&response).is_empty());
    }
    let response = send(&app, Request::builder().uri(desktop_path())).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "no host at all");

    let proxied = send(
        &app,
        Request::builder()
            .uri(desktop_path())
            .header(header::HOST, "10.0.0.7:8080")
            .header("x-forwarded-host", "gw.test"),
    )
    .await;
    assert_eq!(
        proxied.status(),
        StatusCode::OK,
        "a trusted proxy names the host"
    );
    let response = post_consent_to(&app, "evil.test", &[], &[("origin", ISSUER)]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_consent_page_carries_the_header_set_and_no_active_content() {
    let app = signing_in();
    let response = send(&app, get(&desktop_path())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_page(&response);
    let request_id = header_value(&response, "x-mcpg-request-id")
        .expect("request id")
        .to_owned();
    let policy = header_value(&response, "content-security-policy")
        .expect("CSP")
        .to_owned();
    let html = body_text(response).await;
    assert!(html.contains(&request_id), "the page shows its request id");
    for active in [
        "<script",
        "<img",
        "<iframe",
        "<link",
        "<object",
        "javascript:",
        "src=",
    ] {
        assert!(!html.contains(active), "{active} in {html}");
    }
    let style = html
        .split("<style>")
        .nth(1)
        .and_then(|rest| rest.split("</style>").next())
        .expect("inline style");
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(style.as_bytes()));
    assert!(
        policy.contains(&format!("'sha256-{hash}'")),
        "the policy admits exactly the inline style"
    );
    assert!(html.contains("action=\"https://gw.test/oauth/consent\""));
    assert!(html.contains("value=\"approve\"") && html.contains("value=\"deny\""));
}

#[tokio::test]
async fn the_consent_page_escapes_what_it_shows() {
    let app = signing_in();
    let html = body_text(send(&app, get(&desktop_path())).await).await;
    assert!(
        html.contains("Tom &lt;b&gt;&amp;&lt;/b&gt; &quot;Jerry&quot; gnp.exe"),
        "{html}"
    );
    assert!(
        !html.contains('\u{202e}'),
        "bidirectional overrides are removed"
    );
    assert!(!html.contains("<b>&</b>"));
    assert!(html.contains("Use &lt;i&gt;tools&lt;/i&gt;"));
    assert!(html.contains("Acme &lt;SSO&gt;"));
    assert!(html.contains("http://<strong>127.0.0.1</strong>:53682/callback"));
    assert!(html.contains("This app runs on this computer"));
    assert!(!html.contains("unverified"), "a registered client");
    assert!(html.contains("will keep your Acme &lt;SSO&gt; sign-in"));
}

/// RFC 9396: the consent page shows each authorization details object the
/// request asks for, every value escaped.
#[tokio::test]
async fn the_consent_page_shows_authorization_details_escaped() {
    let app = gateway(Some(authorization_server(
        ISSUER,
        serde_json::json!({
            "authorization_details": {
                "types": [
                    { "type": "mcp_tool", "description": "Call <b>tools</b>", "locations": "any" },
                    { "type": "x<y", "locations": "any" },
                    { "type": "payment", "locations": "any", "schema": { "type": "object" } },
                ],
            },
        }),
    )));
    let details = serde_json::json!([
        {
            "type": "mcp_tool",
            "actions": ["tools/<call>"],
            "locations": ["https://evil.example/\"><script>"],
            "identifier": "<img src=x>",
        },
        { "type": "x<y", "datatypes": ["a&b"], "privileges": ["'p'"] },
        { "type": "payment", "remittance": "x".repeat(2000), "amount": "<9999>" },
    ]);
    let path = authorize_path(
        "desktop",
        "http://127.0.0.1:53682/callback",
        &[("authorization_details", &details.to_string())],
    );
    let response = send(&app, get(&path)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("<dt>Limited to</dt>"), "{html}");
    assert!(
        html.contains("<strong>Call &lt;b&gt;tools&lt;/b&gt;</strong> (<code>mcp_tool</code>)")
    );
    assert!(html.contains("Actions: <code>tools/&lt;call&gt;</code>"));
    assert!(html.contains("Locations: <code>https://evil.example/&quot;&gt;&lt;script&gt;</code>"));
    assert!(html.contains("Identifier: <code>&lt;img src=x&gt;</code>"));
    assert!(html.contains("<strong>x&lt;y</strong>"));
    assert!(html.contains("Data types: <code>a&amp;b</code>"));
    assert!(html.contains("Privileges: <code>&#39;p&#39;</code>"));
    // A long member does not push a later one off the page.
    assert!(html.contains("Also:<pre class=\"detail\">"), "{html}");
    assert!(html.contains(&"x".repeat(2000)));
    assert!(
        html.contains("&quot;amount&quot;: &quot;&lt;9999&gt;&quot;"),
        "{html}"
    );
    for active in ["<script", "<img", "<b>tools", "<9999>"] {
        assert!(!html.contains(active), "{active} in {html}");
    }
}

#[tokio::test]
async fn the_csrf_cookie_is_host_only_strict_and_secure() {
    let app = signing_in();
    let response = send(&app, get(&desktop_path())).await;
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = &cookies[0];
    assert!(cookie.starts_with("__Host-mcpg_csrf="), "{cookie}");
    for attribute in [
        "Path=/",
        "Max-Age=600",
        "HttpOnly",
        "SameSite=Strict",
        "Secure",
    ] {
        assert!(
            cookie.split("; ").any(|part| part == attribute),
            "{attribute} in {cookie}"
        );
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
}

#[tokio::test]
async fn a_loopback_http_issuer_sets_cookies_without_the_host_prefix() {
    let app = gateway(Some(authorization_server(
        "http://127.0.0.1:8080",
        serde_json::json!({}),
    )));
    let response = send(
        &app,
        Request::builder()
            .uri(desktop_path())
            .header(header::HOST, "127.0.0.1:8080"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = set_cookies(&response).remove(0);
    assert!(cookie.starts_with("mcpg_csrf="), "{cookie}");
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
}

#[tokio::test]
async fn a_consent_decision_round_trips_to_the_idp() {
    let app = signing_in();
    let page = load_consent(&app, &desktop_path()).await;
    let mut headers = BROWSER_FORM_POST.to_vec();
    headers.push(("cookie", page.cookie.as_str()));
    let response = post_consent(
        &app,
        &[
            ("req", page.req.as_str()),
            ("csrf", page.csrf.as_str()),
            ("decision", "approve"),
        ],
        &headers,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the form posted the way a browser posts it"
    );
    assert_protected(&response);
    let location = header_value(&response, "location").expect("location");
    assert!(
        location.starts_with("https://idp.test/authorize?"),
        "{location}"
    );
    let cookies = set_cookies(&response);
    assert_eq!(
        cookies.len(),
        1,
        "the CSRF cookie stays for the browser's other pages: {cookies:?}"
    );
    assert!(
        cookies[0].starts_with("__Host-mcpg_txn_"),
        "the sign-in is bound to this browser: {cookies:?}"
    );

    let again = post_consent(
        &app,
        &[
            ("req", page.req.as_str()),
            ("csrf", page.csrf.as_str()),
            ("decision", "approve"),
        ],
        &[("origin", ISSUER), ("cookie", page.cookie.as_str())],
    )
    .await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "taken once");
    assert_page(&again);
}

#[tokio::test]
async fn a_consent_decision_from_another_origin_is_refused() {
    let app = signing_in();
    let page = load_consent(&app, &desktop_path()).await;
    let form = [
        ("req", page.req.as_str()),
        ("csrf", page.csrf.as_str()),
        ("decision", "approve"),
    ];
    let refused: [&[(&str, &str)]; 7] = [
        &[("origin", "https://evil.test")],
        &[("origin", "null")],
        &[("origin", "null"), ("sec-fetch-site", "cross-site")],
        &[("origin", "null"), ("sec-fetch-site", "same-site")],
        &[],
        &[("sec-fetch-site", "cross-site")],
        &[("origin", ISSUER), ("sec-fetch-site", "same-site")],
    ];
    for headers in refused {
        let mut headers = headers.to_vec();
        headers.push(("cookie", page.cookie.as_str()));
        let response = post_consent(&app, &form, &headers).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{headers:?}");
        assert_page(&response);
    }
    let response = post_consent(
        &app,
        &form,
        &[
            ("sec-fetch-site", "same-origin"),
            ("cookie", page.cookie.as_str()),
        ],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a browser that sends no Origin says same-origin"
    );

    let page = load_consent(&app, &desktop_path()).await;
    let mut headers = BROWSER_FORM_POST.to_vec();
    headers.push(("cookie", page.cookie.as_str()));
    let response = post_consent(
        &app,
        &[
            ("req", page.req.as_str()),
            ("csrf", page.csrf.as_str()),
            ("decision", "deny"),
        ],
        &headers,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the page's own form, whose Origin a no-referrer policy makes null"
    );
    assert!(
        header_value(&response, "location")
            .is_some_and(|location| location.contains("error=access_denied"))
    );
}

#[tokio::test]
async fn pages_open_in_two_tabs_are_both_decided() {
    let app = signing_in();
    let first = load_consent(&app, &desktop_path()).await;
    let second = send(
        &app,
        get(&desktop_path()).header("cookie", first.cookie.as_str()),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        cookie_pair(&second, "__Host-mcpg_csrf"),
        first.cookie,
        "the second tab keeps the browser's CSRF cookie"
    );
    let html = body_text(second).await;
    let second = ConsentLoaded {
        req: hidden(&html, "req"),
        csrf: hidden(&html, "csrf"),
        cookie: first.cookie.clone(),
    };
    for (page, decision) in [(&first, "approve"), (&second, "deny")] {
        let mut headers = BROWSER_FORM_POST.to_vec();
        headers.push(("cookie", page.cookie.as_str()));
        let response = post_consent(
            &app,
            &[
                ("req", page.req.as_str()),
                ("csrf", page.csrf.as_str()),
                ("decision", decision),
            ],
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{decision}");
        assert!(
            set_cookies(&response)
                .iter()
                .all(|cookie| !cookie.starts_with("__Host-mcpg_csrf=")),
            "{decision}: a decision leaves the CSRF cookie alone"
        );
    }
}

#[tokio::test]
async fn a_consent_decision_needs_the_csrf_cookie_and_its_token() {
    let app = signing_in();
    let page = load_consent(&app, &desktop_path()).await;
    let other = load_consent(&app, &desktop_path()).await;
    let cases: [(&str, &str); 3] = [
        (page.csrf.as_str(), ""),
        (page.csrf.as_str(), other.cookie.as_str()),
        (other.csrf.as_str(), page.cookie.as_str()),
    ];
    for (token, cookie) in cases {
        let mut headers = vec![("origin", ISSUER)];
        if !cookie.is_empty() {
            headers.push(("cookie", cookie));
        }
        let response = post_consent(
            &app,
            &[
                ("req", page.req.as_str()),
                ("csrf", token),
                ("decision", "approve"),
            ],
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_page(&response);
    }
}

#[tokio::test]
async fn an_unreadable_consent_form_is_refused() {
    let app = signing_in();
    let page = load_consent(&app, &desktop_path()).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/consent")
                .header(header::HOST, "gw.test")
                .header("origin", ISSUER)
                .header("cookie", page.cookie.as_str())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_page(&response);
    let response = post_consent(
        &app,
        &[
            ("req", page.req.as_str()),
            ("req", page.req.as_str()),
            ("csrf", page.csrf.as_str()),
            ("decision", "approve"),
        ],
        &[("origin", ISSUER), ("cookie", page.cookie.as_str())],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a repeated field"
    );
}

#[tokio::test]
async fn other_methods_get_a_405_page() {
    let app = signing_in();
    let cases = [
        ("POST", "/oauth/authorize", "GET"),
        ("PUT", "/oauth/authorize", "GET"),
        ("HEAD", "/oauth/authorize", "GET"),
        ("GET", "/oauth/consent", "POST"),
        ("OPTIONS", "/oauth/consent", "POST"),
        ("PUT", "/oauth/connect", "GET, POST"),
        ("HEAD", "/oauth/connect", "GET, POST"),
        ("OPTIONS", "/oauth/connect", "GET, POST"),
    ];
    for (method, path, allow) in cases {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, "gw.test")
                .header("origin", "https://app.example")
                .header("access-control-request-method", "POST"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(header_value(&response, "allow"), Some(allow));
        assert_page(&response);
    }
}

#[tokio::test]
async fn a_head_request_leaves_the_authorization_request_unspent() {
    let app = signing_in();
    let path = authorize_path("web-app", "https://app.example/cb", &[]);
    let probed = send(
        &app,
        Request::builder()
            .method("HEAD")
            .uri(path.as_str())
            .header(header::HOST, "gw.test"),
    )
    .await;
    assert_eq!(probed.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_value(&probed, "allow"), Some("GET"));
    assert!(set_cookies(&probed).is_empty(), "no sign-in was started");
    assert_protected(&probed);

    let response = send(&app, get(&path)).await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the same challenge still reaches the IdP"
    );
    assert!(
        header_value(&response, "location")
            .is_some_and(|location| location.starts_with("https://idp.test/authorize?"))
    );
}

#[tokio::test]
async fn the_pages_share_a_budget_per_client_address() {
    let app = gateway(Some(authorization_server(
        ISSUER,
        serde_json::json!({
            "interactive": { "rate_limit_per_min": 2 },
        }),
    )));
    let from = |ip: &'static str| get(&desktop_path()).header("x-forwarded-for", ip);
    assert_eq!(
        send(&app, from("198.51.100.71")).await.status(),
        StatusCode::OK
    );
    let consent = post_consent(
        &app,
        &[("decision", "approve")],
        &[("origin", ISSUER), ("x-forwarded-for", "198.51.100.71")],
    )
    .await;
    assert_ne!(consent.status(), StatusCode::TOO_MANY_REQUESTS);
    let limited = send(&app, from("198.51.100.71")).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header_value(&limited, "retry-after"), Some("60"));
    assert_page(&limited);
    let limited = post_consent(
        &app,
        &[("decision", "approve")],
        &[("origin", ISSUER), ("x-forwarded-for", "198.51.100.71")],
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        send(&app, from("198.51.100.72")).await.status(),
        StatusCode::OK,
        "another address has its own budget"
    );
}

#[tokio::test]
async fn a_remembered_approval_rides_a_lax_host_cookie() {
    let app = signing_in();
    let path = authorize_path(
        "mixed",
        "https://mixed.example/cb",
        &[("scope", "mcp:tools")],
    );
    let page = load_consent(&app, &path).await;
    let response = post_consent(
        &app,
        &[
            ("req", page.req.as_str()),
            ("csrf", page.csrf.as_str()),
            ("decision", "approve"),
        ],
        &[("origin", ISSUER), ("cookie", page.cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let memory = set_cookies(&response)
        .into_iter()
        .find(|cookie| cookie.starts_with("__Host-mcpg_consent="))
        .expect("the approval is remembered");
    for attribute in [
        "Path=/",
        "Max-Age=2592000",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
    ] {
        assert!(
            memory.split("; ").any(|part| part == attribute),
            "{attribute} in {memory}"
        );
    }
    let pair = memory.split(';').next().expect("pair").to_owned();

    let path = authorize_path(
        "mixed",
        "https://mixed.example/cb",
        &[("scope", "mcp:tools")],
    );
    let remembered = send(
        &app,
        get(&path).header("cookie", format!("theme=dark; {pair}")),
    )
    .await;
    assert_eq!(remembered.status(), StatusCode::SEE_OTHER);
    assert!(
        header_value(&remembered, "location")
            .is_some_and(|location| location.starts_with("https://idp.test/authorize?"))
    );
    let asked_again = send(
        &app,
        get(&authorize_path(
            "mixed",
            "https://mixed.example/cb",
            &[("scope", "mcp:tools"), ("prompt", "consent")],
        ))
        .header("cookie", pair),
    )
    .await;
    assert_eq!(asked_again.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_error_for_a_trusted_redirect_uri_is_a_303() {
    let app = signing_in();
    let response = send(
        &app,
        get(&authorize_path(
            "web-app",
            "https://app.example/cb",
            &[("code_challenge_method", "plain")],
        )),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "repeated parameter"
    );

    let response = send(
        &app,
        get(&authorize_path(
            "web-app",
            "https://app.example/cb",
            &[("prompt", "none")],
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_protected(&response);
    let location = header_value(&response, "location").expect("location");
    assert!(
        location.starts_with("https://app.example/cb?error=invalid_request"),
        "{location}"
    );
    assert!(location.contains("&state=client-state"), "{location}");
    assert!(
        location.ends_with("&iss=https%3A%2F%2Fgw.test"),
        "{location}"
    );
}

/// The IdP `state` of the redirect `response` answers with.
fn idp_state(response: &axum::response::Response) -> String {
    let location = header_value(response, "location").expect("location");
    url::Url::parse(location)
        .expect("URL")
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state")
}

#[tokio::test]
async fn the_idp_redirect_sets_a_host_only_lax_binding_cookie() {
    let app = signing_in();
    let response = send(
        &app,
        get(&authorize_path("web-app", "https://app.example/cb", &[])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_protected(&response);
    let state = idp_state(&response);
    let name = format!(
        "__Host-mcpg_txn_{}",
        TransactionTag::of_state(&state).as_str()
    );
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = &cookies[0];
    assert!(cookie.starts_with(&format!("{name}=")), "{cookie}");
    for attribute in [
        "Path=/",
        "Max-Age=600",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
    ] {
        assert!(
            cookie.split("; ").any(|part| part == attribute),
            "{attribute} in {cookie}"
        );
    }
    assert!(!cookie.contains("Domain"), "{cookie}");

    let local = gateway(Some(authorization_server(
        "http://127.0.0.1:8080",
        serde_json::json!({}),
    )));
    let response = send(
        &local,
        Request::builder()
            .uri(authorize_path("web-app", "https://app.example/cb", &[]))
            .header(header::HOST, "127.0.0.1:8080"),
    )
    .await;
    let cookie = set_cookies(&response).remove(0);
    assert!(cookie.starts_with("mcpg_txn_"), "{cookie}");
    assert!(!cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn a_callback_error_goes_back_to_the_client_and_clears_the_binding_cookie() {
    let app = signing_in();
    let response = send(
        &app,
        get(&authorize_path("web-app", "https://app.example/cb", &[])),
    )
    .await;
    let state = idp_state(&response);
    let binding = set_cookies(&response)
        .remove(0)
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let path = format!(
        "/oauth/callback?state={state}&error=login_required&error_description=secret%20detail\
         &iss=https%3A%2F%2Fidp.test"
    );
    let callback = send(&app, get(&path).header("cookie", binding.as_str())).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_protected(&callback);
    let location = header_value(&callback, "location").expect("location");
    assert!(
        location.starts_with("https://app.example/cb?error=access_denied&"),
        "{location}"
    );
    assert!(location.contains("&state=client-state&"), "{location}");
    assert!(
        location.ends_with("&iss=https%3A%2F%2Fgw.test"),
        "{location}"
    );
    assert!(!location.contains("secret"), "{location}");
    let cleared = set_cookies(&callback);
    let name = binding.split('=').next().expect("name");
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert!(cleared[0].starts_with(&format!("{name}=;")), "{cleared:?}");
    assert!(cleared[0].contains("Max-Age=0"));

    let replay = send(&app, get(&path).header("cookie", binding.as_str())).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_page(&replay);
    assert!(
        body_text(replay)
            .await
            .contains("expired or was already used")
    );
}

#[tokio::test]
async fn the_callback_answers_get_on_the_issuers_host_only() {
    let unknown = format!(
        "/oauth/callback?state={}&code=c",
        crate::runtime::authorization_server::state::random_token().expect("random")
    );
    let response = send(&gateway(None), get(&unknown)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_page(&response);

    let app = signing_in();
    let response = send(&app, get(&unknown)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_page(&response);
    assert!(
        body_text(response)
            .await
            .contains("expired or was already used")
    );

    let response = send(
        &app,
        Request::builder()
            .uri(unknown.as_str())
            .header(header::HOST, "evil.test"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(response).await.contains("published at"));

    for method in ["POST", "HEAD", "PUT"] {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(unknown.as_str())
                .header(header::HOST, "gw.test"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}: a HEAD would spend the sign-in"
        );
        assert_eq!(header_value(&response, "allow"), Some("GET"));
        assert_protected(&response);
    }
}

#[tokio::test]
async fn the_metadata_offers_the_authorization_endpoint_and_the_prm_only_the_issuer() {
    let app = signing_in();
    let response = send(&app, get("/.well-known/oauth-authorization-server")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata: serde_json::Value =
        serde_json::from_str(&body_text(response).await).expect("JSON");
    assert_eq!(
        metadata["authorization_endpoint"],
        "https://gw.test/oauth/authorize"
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );

    let mut access = crate::config::AccessConfig {
        authorization_server: Some(
            serde_json::from_value(authorization_server(ISSUER, serde_json::json!({})))
                .expect("parses"),
        ),
        oidc_oauth: Some(crate::config::OidcOAuthConfig {
            token_source: crate::config::TokenSourceConfig {
                kind: crate::config::TokenSourceKind::AuthorizationBearer,
                header_name: None,
                header_prefix: None,
            },
            providers: vec![crate::config::OidcProviderConfig {
                issuer: "https://sso.example/".to_owned(),
                discovery_uri: None,
                audiences: vec!["mcpg".to_owned()],
                verification: crate::config::VerificationConfig::OidcJwks {
                    allowed_algs: vec!["RS256".to_owned()],
                    refresh_interval_secs: 3600,
                    timeout_ms: 5000,
                    max_staleness_secs: 86400,
                    allow_hmac: false,
                },
                claim_mappings: Default::default(),
                clock_skew_secs: 60,
                allowed_issuer_hosts: Vec::new(),
                allow_private_issuer: false,
                allow_any_audience: false,
            }],
        }),
        ..Default::default()
    };
    assert_eq!(
        super::super::discovery::derive_authorization_servers(&access),
        [ISSUER],
        "with interactive sign-in the issuer is the one server listed"
    );
    if let Some(ref mut server) = access.authorization_server {
        server.trusted_idps[0].login = None;
    }
    assert_eq!(
        super::super::discovery::derive_authorization_servers(&access),
        [ISSUER, "https://sso.example/"]
    );
}

#[test]
fn binding_cookies_are_read_by_tag() {
    let tag = TransactionTag::of_state("some-state");
    let other = TransactionTag::of_state("other-state");
    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-mcpg_txn_{t}=first; theme=dark; __Host-mcpg_txn_{t}=second; \
             __Host-mcpg_txn_NOT-A-TAG=x; mcpg_txn_{o}=plain",
            t = tag.as_str(),
            o = other.as_str()
        ))
        .expect("header"),
    );
    let secure = read_transaction_cookies(&headers, true);
    assert_eq!(secure.get(tag), Some("first"));
    assert_eq!(
        secure.get(other),
        None,
        "a plain cookie is not a __Host- one"
    );
    assert_eq!(secure.len(), 1);
    let plain = read_transaction_cookies(&headers, false);
    assert_eq!(plain.get(other), Some("plain"));
    assert_eq!(plain.get(tag), None);
}

#[test]
fn escape_removes_invisible_characters_and_escapes_markup() {
    assert_eq!(
        escape("a<b>&\"c\"'d'\u{202e}\u{200b}\u{0}e"),
        "a&lt;b&gt;&amp;&quot;c&quot;&#39;d&#39;e"
    );
    assert_eq!(
        uri_with_bold_host("http://[::1]:8080/cb?x=<1>"),
        "http://<strong>[::1]</strong>:8080/cb?x=&lt;1&gt;"
    );
    assert_eq!(
        uri_with_bold_host("https://app.example/cb"),
        "https://<strong>app.example</strong>/cb"
    );
}

#[test]
fn the_first_cookie_of_each_name_counts() {
    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("a=1; __Host-mcpg_csrf=first; __Host-mcpg_consent=\"m\""),
    );
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("__Host-mcpg_csrf=second; mcpg_csrf=plain"),
    );
    let cookies = read_cookies(&headers, true);
    assert_eq!(cookies.csrf.as_deref(), Some("first"));
    assert_eq!(cookies.consent_memory.as_deref(), Some("m"));
    let plain = read_cookies(&headers, false);
    assert_eq!(plain.csrf.as_deref(), Some("plain"));
    assert_eq!(plain.consent_memory, None);
}

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

/// An initial access token the operator lists; plainly a test value.
const REGISTRATION_TOKEN: &str = "test-initial-access-token-test-initial-access-token";

/// Registration behind an initial access token, one per address and hour,
/// for loopback redirect URIs and `www.cursor.com`.
fn registering() -> Router {
    gateway(Some(authorization_server(
        ISSUER,
        serde_json::json!({
            "interactive": {
                "dynamic_client_registration": {
                    "enabled": true,
                    "initial_access_tokens": [REGISTRATION_TOKEN],
                    "allowed_redirect_hosts": ["www.cursor.com"],
                    "registrations_per_hour_per_ip": 1,
                },
            },
        }),
    )))
}

/// `POST /oauth/register` of `body` from the client address `ip`.
async fn register(
    app: &Router,
    body: &str,
    content_type: &str,
    token: Option<&str>,
    ip: &str,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/oauth/register")
        .header(header::HOST, "gw.test")
        .header(header::CONTENT_TYPE, content_type)
        .header("x-forwarded-for", ip);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_owned())).expect("request"))
        .await
        .expect("response")
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_str(&body_text(response).await).expect("JSON body")
}

#[track_caller]
fn assert_uncacheable(response: &axum::response::Response) {
    assert_eq!(header_value(response, "cache-control"), Some("no-store"));
    assert_eq!(header_value(response, "pragma"), Some("no-cache"));
    assert!(header_value(response, "x-mcpg-request-id").is_some());
}

#[tokio::test]
async fn registration_answers_404_while_it_is_off() {
    let app = signing_in();
    let body = r#"{"redirect_uris":["http://127.0.0.1/cb"]}"#;
    let response = register(&app, body, "application/json", None, "192.0.2.10").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let metadata =
        body_json(send(&app, get("/.well-known/oauth-authorization-server")).await).await;
    assert!(
        metadata.get("registration_endpoint").is_none(),
        "{metadata}"
    );
}

#[tokio::test]
async fn a_registered_client_is_created_and_marked_on_the_consent_page() {
    let app = registering();
    let metadata =
        body_json(send(&app, get("/.well-known/oauth-authorization-server")).await).await;
    assert_eq!(
        metadata["registration_endpoint"],
        "https://gw.test/oauth/register"
    );

    let response = register(
        &app,
        r#"{"redirect_uris":["http://127.0.0.1/callback"],"client_name":"Cursor",
            "grant_types":["authorization_code","refresh_token"],
            "logo_uri":"https://evil.example/logo.png"}"#,
        "application/json; charset=utf-8",
        Some(REGISTRATION_TOKEN),
        "192.0.2.11",
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_uncacheable(&response);
    let registered = body_json(response).await;
    let client_id = registered["client_id"].as_str().expect("client_id");
    assert!(client_id.starts_with("mcpgdcr_"), "{registered}");
    assert_eq!(registered["token_endpoint_auth_method"], "none");
    assert!(registered.get("client_secret").is_none());
    assert!(registered.get("logo_uri").is_none());

    let page = send(
        &app,
        get(&authorize_path(
            client_id,
            "http://127.0.0.1:61234/callback",
            &[],
        )),
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_page(&page);
    let html = body_text(page).await;
    assert!(html.contains("<strong>Cursor</strong>"), "{html}");
    assert!(html.contains("unverified"), "{html}");
    assert!(
        html.contains("registered itself with this gateway"),
        "{html}"
    );
    assert!(!html.contains("evil.example"), "{html}");
}

#[tokio::test]
async fn registration_errors_carry_their_status_and_headers() {
    let app = registering();
    let body = r#"{"redirect_uris":["http://127.0.0.1/callback"]}"#;

    let response = register(&app, body, "application/json", None, "192.0.2.12").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        header_value(&response, "www-authenticate"),
        Some("Bearer"),
        "no error code for a request without a token (RFC 6750 §3.1)"
    );
    assert_uncacheable(&response);
    assert_eq!(body_json(response).await["error"], "invalid_token");

    let response = register(
        &app,
        body,
        "application/json",
        Some("not-a-listed-initial-access-token"),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        header_value(&response, "www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );

    let response = register(
        &app,
        body,
        "application/x-www-form-urlencoded",
        Some(REGISTRATION_TOKEN),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["error"],
        "invalid_client_metadata"
    );

    let oversized = format!(
        r#"{{"redirect_uris":["http://127.0.0.1/callback"],"client_name":"{}"}}"#,
        "x".repeat(9 * 1024)
    );
    let response = register(
        &app,
        &oversized,
        "application/json",
        Some(REGISTRATION_TOKEN),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["error"],
        "invalid_client_metadata"
    );

    let response = register(
        &app,
        r#"{"redirect_uris":["https://evil.example/callback"]}"#,
        "application/json",
        Some(REGISTRATION_TOKEN),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["error"], "invalid_redirect_uri");
    assert!(
        error["error_description"]
            .as_str()
            .is_some_and(|text| text.contains("allowed_redirect_hosts")),
        "{error}"
    );

    let response = register(
        &app,
        body,
        "application/json",
        Some(REGISTRATION_TOKEN),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = register(
        &app,
        body,
        "application/json",
        Some(REGISTRATION_TOKEN),
        "192.0.2.12",
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = header_value(&response, "retry-after")
        .and_then(|value| value.parse().ok())
        .expect("Retry-After");
    assert!((1..=3600).contains(&retry_after), "{retry_after}");
    assert_uncacheable(&response);
    assert_eq!(
        body_json(response).await["error"],
        "temporarily_unavailable"
    );
}
