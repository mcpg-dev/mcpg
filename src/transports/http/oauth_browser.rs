//! The pages of interactive sign-in, `GET /oauth/authorize`, `POST
//! /oauth/consent`, `GET /oauth/callback` and `GET` and `POST
//! /oauth/connect`
//! ([`interactive`](crate::runtime::authorization_server::interactive),
//! [`connect`](crate::runtime::authorization_server::connect)).
//!
//! A request reaches the authorization server only when a login IdP is
//! configured (else 404), when it arrived at the issuer's host (else 400,
//! RFC 9700 §4.13) and within the client address's budget
//! (`interactive.rate_limit_per_min`, else 429). A consent or connect
//! decision must also come from this server's own page: its `Origin` is
//! the issuer's, or with none or `null` (the form of a page that sends no
//! referrer) `Sec-Fetch-Site` is `same-origin` (else 403). The
//! authorization endpoint and the callback answer `GET` only: a `HEAD`
//! would claim the client's one-time PKCE challenge, or spend the one-time
//! sign-in. A completed link tells the MCP session that offered it
//! (`notifications/elicitation/complete`) once the answer is sent.
//!
//! Every response is `no-store`, sends no referrer and is not sniffed, and
//! every redirect is a `303` (RFC 9700 §4.12). A page is HTML without
//! script, image or any other resource, each value escaped and stripped of
//! control and bidirectional characters, under a policy that loads nothing
//! but its own inline style, cannot be framed and sets no base URL. The
//! policy has no `form-action`: a browser checks it against every redirect
//! that follows the consent form, and that chain passes through the IdP to
//! the client. No opener policy either: a client that opened the sign-in
//! in a popup reads the result through `window.opener` once the popup is
//! back on its redirect URI.

use std::sync::{Arc, LazyLock};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::runtime::authorization_server::AuthorizationServer;
use crate::runtime::authorization_server::connect::ConnectPage;
use crate::runtime::authorization_server::interactive::{
    AUTHORIZE_PATH, BrowserCookie, BrowserCookies, BrowserOutcome, BrowserResponse, CALLBACK_PATH,
    CONNECT_PATH, ConsentForm, ConsentPage, CookieChange, ErrorPage, NoticePage,
    TransactionCookies, TransactionTag,
};
use crate::runtime::authorization_server::rar::DetailLine;
use crate::runtime::authorization_server::redirect::is_invisible;
use crate::runtime::authorization_server::state::ClientKind;

type Peer = Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>;

/// The only style a page carries, allowed by its hash.
const STYLE: &str = ":root{color-scheme:light dark;--bg:#f4f4f5;--card:#fff;--text:#18181b;\
--muted:#52525b;--line:#e4e4e7;--accent:#1d4ed8;--on-accent:#fff;--warn:#fef3c7;\
--on-warn:#78350f}\
@media (prefers-color-scheme:dark){:root{--bg:#18181b;--card:#27272a;--text:#f4f4f5;\
--muted:#a1a1aa;--line:#3f3f46;--accent:#60a5fa;--on-accent:#0b1220;--warn:#422006;\
--on-warn:#fde68a}}\
body{margin:0;background:var(--bg);color:var(--text);\
font:16px/1.5 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}\
main{box-sizing:border-box;max-width:36rem;margin:2rem auto;padding:1.5rem;\
background:var(--card);border:1px solid var(--line);border-radius:12px}\
@media (max-width:40rem){main{margin:0;border:0;border-radius:0}}\
h1{font-size:1.25rem;line-height:1.3;margin:0 0 1rem}\
dl{margin:1rem 0}dt{font-weight:600;margin-top:.75rem}dd{margin:.25rem 0 0}\
ul{margin:.25rem 0;padding-left:1.25rem}\
.uri{overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\
font-size:.9rem}\
.detail{margin:.25rem 0 0;padding:.5rem;border:1px solid var(--line);border-radius:6px;\
white-space:pre-wrap;overflow-wrap:anywhere;font:.85rem/1.4 ui-monospace,SFMono-Regular,Menlo,\
monospace}\
.badge{display:inline-block;margin-left:.5rem;padding:0 .5rem;border:1px solid var(--line);\
border-radius:999px;font-size:.75rem;color:var(--muted);vertical-align:middle}\
.warn{background:var(--warn);color:var(--on-warn);padding:.75rem;border-radius:8px}\
.actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}\
button{font:inherit;padding:.6rem 1.2rem;border-radius:8px;cursor:pointer}\
.approve{background:var(--accent);color:var(--on-accent);border:1px solid var(--accent)}\
.deny{background:transparent;color:var(--text);border:1px solid var(--line)}\
a{color:var(--accent)}.muted{color:var(--muted);font-size:.85rem}";

/// `Content-Security-Policy` of every page.
static PAGE_POLICY: LazyLock<String> = LazyLock::new(|| {
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
    format!(
        "default-src 'none'; style-src 'sha256-{hash}'; frame-ancestors 'none'; base-uri 'none'"
    )
});

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /oauth/authorize`: the authorization endpoint.
pub(crate) async fn oauth_authorize_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    uri: axum::http::Uri,
) -> Response {
    let request_id = GatewayRequestId::new();
    let runtime = state.runtime.load_full();
    let config = state.config.load_full();
    let server = match admit(&runtime, &config, &headers, peer, &uri, "authorize") {
        Ok(server) => server,
        Err(page) => return page_response(&page, &request_id),
    };
    let secure = server.secure_cookies();
    let cookies = read_cookies(&headers, secure);
    let response = server
        .authorize(uri.query().unwrap_or_default(), &cookies)
        .await;
    respond(&runtime, response, secure, &request_id).await
}

/// `POST /oauth/consent`: the user's decision on a consent page.
pub(crate) async fn oauth_consent_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    uri: axum::http::Uri,
    form: Result<axum::extract::Form<ConsentForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let request_id = GatewayRequestId::new();
    let runtime = state.runtime.load_full();
    let config = state.config.load_full();
    let server = match admit(&runtime, &config, &headers, peer, &uri, "consent") {
        Ok(server) => server,
        Err(page) => return page_response(&page, &request_id),
    };
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if !server.is_same_origin_post(header("origin"), header("sec-fetch-site")) {
        tracing::debug!("a consent decision posted from another origin was refused");
        return page_response(&ErrorPage::cross_origin(), &request_id);
    }
    let Ok(axum::extract::Form(form)) = form else {
        return page_response(&ErrorPage::unreadable_form(), &request_id);
    };
    let secure = server.secure_cookies();
    let cookies = read_cookies(&headers, secure);
    let response = server.decide_consent(&form, &cookies).await;
    respond(&runtime, response, secure, &request_id).await
}

/// `GET /oauth/callback`: the login IdP's answer to a sign-in.
pub(crate) async fn oauth_callback_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    uri: axum::http::Uri,
) -> Response {
    let request_id = GatewayRequestId::new();
    let runtime = state.runtime.load_full();
    let config = state.config.load_full();
    let server = match admit(&runtime, &config, &headers, peer, &uri, "callback") {
        Ok(server) => server,
        Err(page) => return page_response(&page, &request_id),
    };
    let secure = server.secure_cookies();
    let binders = read_transaction_cookies(&headers, secure);
    let response = server
        .callback(uri.query().unwrap_or_default(), &binders)
        .await;
    respond(&runtime, response, secure, &request_id).await
}

/// `GET /oauth/connect`: the page that asks the user to store their IdP
/// sign-in, for the link `e` names when it does.
pub(crate) async fn oauth_connect_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    uri: axum::http::Uri,
) -> Response {
    let request_id = GatewayRequestId::new();
    let runtime = state.runtime.load_full();
    let config = state.config.load_full();
    let server = match admit(&runtime, &config, &headers, peer, &uri, "connect") {
        Ok(server) => server,
        Err(page) => return page_response(&page, &request_id),
    };
    let secure = server.secure_cookies();
    let cookies = read_cookies(&headers, secure);
    let response = server
        .connect(uri.query().unwrap_or_default(), &cookies)
        .await;
    respond(&runtime, response, secure, &request_id).await
}

/// `POST /oauth/connect`: the user's decision on the connect page.
pub(crate) async fn oauth_connect_decision_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    uri: axum::http::Uri,
    form: Result<axum::extract::Form<ConsentForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let request_id = GatewayRequestId::new();
    let runtime = state.runtime.load_full();
    let config = state.config.load_full();
    let server = match admit(&runtime, &config, &headers, peer, &uri, "connect") {
        Ok(server) => server,
        Err(page) => return page_response(&page, &request_id),
    };
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if !server.is_same_origin_post(header("origin"), header("sec-fetch-site")) {
        tracing::debug!("a connect decision posted from another origin was refused");
        return page_response(&ErrorPage::cross_origin(), &request_id);
    }
    let Ok(axum::extract::Form(form)) = form else {
        return page_response(&ErrorPage::unreadable_form(), &request_id);
    };
    let secure = server.secure_cookies();
    let cookies = read_cookies(&headers, secure);
    let response = server.decide_connect(&form, &cookies).await;
    respond(&runtime, response, secure, &request_id).await
}

/// Any other method on a sign-in page: 405 with the ones it answers.
pub(crate) async fn oauth_browser_method_not_allowed(uri: axum::http::Uri) -> Response {
    let request_id = GatewayRequestId::new();
    let mut response = page_response(&ErrorPage::method_not_allowed(), &request_id);
    let allow = match uri.path() {
        AUTHORIZE_PATH | CALLBACK_PATH => "GET",
        CONNECT_PATH => "GET, POST",
        _ => "POST",
    };
    response
        .headers_mut()
        .insert(axum::http::header::ALLOW, HeaderValue::from_static(allow));
    response
}

/// The authorization server a sign-in page request may reach, or the page
/// that stops it: 404 without a login IdP, 400 off the issuer's host, 429
/// over the client address's budget.
fn admit<'a>(
    runtime: &'a crate::runtime::GatewayRuntime,
    config: &crate::config::AppConfig,
    headers: &HeaderMap,
    peer: Peer,
    uri: &axum::http::Uri,
    endpoint: &'static str,
) -> Result<&'a AuthorizationServer, ErrorPage> {
    let Some(server) = runtime
        .ema_authorization_server()
        .filter(|server| server.login_idp().is_some())
    else {
        return Err(ErrorPage::not_offered());
    };
    let trust_proxy = config.gateway.server.trust_proxy_ip;
    // An HTTP/2 request names its host in the URI rather than a header.
    let host = request_host(headers, trust_proxy).or_else(|| {
        uri.authority()
            .map(|authority| authority.as_str().to_owned())
    });
    if !host.is_some_and(|host| server.is_issuer_host(&host)) {
        return Err(ErrorPage::wrong_host());
    }
    let per_min = server.interactive_settings().rate_limit_per_min;
    if per_min > 0
        && let Some(ip) = crate::transports::anon_limit::client_ip(
            trust_proxy,
            headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
            peer.map(|ext| ext.0.0.ip()),
        )
        && crate::transports::anon_limit::OAUTH_BROWSER
            .acquire(ip, per_min, per_min)
            .is_err()
    {
        metrics::counter!("mcpg_as_rate_limited_total", "endpoint" => endpoint).increment(1);
        return Err(ErrorPage::rate_limited());
    }
    Ok(server)
}

/// `response` as HTTP: its page or redirect, its cookies and its audit
/// record. The revocation of a replaced IdP sign-in runs after the answer,
/// on the server current then, and so does the notification of a
/// completed link.
async fn respond(
    runtime: &Arc<crate::runtime::GatewayRuntime>,
    mut response: BrowserResponse,
    secure: bool,
    request_id: &GatewayRequestId,
) -> Response {
    if let Some(ref audit) = response.audit {
        let _ = runtime
            .plugin_registry()
            .emit_audit_event(&audit.event(request_id.as_str()))
            .await;
    }
    if let Some(superseded) = response.superseded.take() {
        let runtime = Arc::clone(runtime);
        tokio::spawn(async move {
            if let Some(server) = runtime.ema_authorization_server() {
                server.revoke_superseded(superseded).await;
            }
        });
    }
    if let Some(completed) = response.link_completed.take() {
        let runtime = Arc::clone(runtime);
        tokio::spawn(async move {
            runtime
                .notify_session(&completed.session_id, completed.notification())
                .await;
        });
    }
    let mut http = match response.outcome {
        BrowserOutcome::Page(ref page) => page_response(page, request_id),
        BrowserOutcome::Consent(ref page) => {
            html_response(200, &consent_html(page, request_id.as_str()), request_id)
        }
        BrowserOutcome::Connect(ref page) => {
            html_response(200, &connect_html(page, request_id.as_str()), request_id)
        }
        BrowserOutcome::Done(ref page) => {
            html_response(200, &notice_html(page, request_id.as_str()), request_id)
        }
        BrowserOutcome::ErrorRedirect { ref location, .. }
        | BrowserOutcome::SignIn(ref location)
        | BrowserOutcome::CodeIssued(ref location) => redirect_response(location, request_id),
    };
    for change in &response.cookies {
        if let Some(value) = set_cookie(change, secure) {
            http.headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    http
}

// ---------------------------------------------------------------------------
// Headers and cookies
// ---------------------------------------------------------------------------

/// The headers every sign-in response carries, and its request id.
fn protect(response: &mut Response, request_id: &GatewayRequestId) {
    use axum::http::header;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
        headers.insert(REQUEST_ID_RESPONSE_HEADER, value);
    }
}

fn html_response(status: u16, html: &str, request_id: &GatewayRequestId) -> Response {
    use axum::http::header;
    let status =
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_REQUEST);
    let mut response = (status, html.to_owned()).into_response();
    protect(&mut response, request_id);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(policy) = HeaderValue::from_str(&PAGE_POLICY) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn page_response(page: &ErrorPage, request_id: &GatewayRequestId) -> Response {
    let mut response = html_response(
        page.status,
        &error_html(page, request_id.as_str()),
        request_id,
    );
    if page.status == 429 {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("60"),
        );
    }
    response
}

/// `303` to `location` (RFC 9700 §4.12: a `307` would repeat a form post).
fn redirect_response(location: &str, request_id: &GatewayRequestId) -> Response {
    let Ok(value) = HeaderValue::from_str(location) else {
        tracing::error!("a sign-in redirect location is not a valid header value");
        return page_response(
            &ErrorPage {
                status: 500,
                error: "server_error",
                title: "Sign-in failed",
                message: "The sign-in could not continue. Start it again from your application."
                    .to_owned(),
                return_to: None,
            },
            request_id,
        );
    };
    let mut response = axum::http::StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::LOCATION, value);
    protect(&mut response, request_id);
    response
}

/// Every `name=value` pair of the request's `Cookie` headers, in order.
fn cookie_pairs(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|text| text.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(name, value)| (name, value.trim().trim_matches('"')))
}

/// The sign-in cookies in the request's `Cookie` headers; the first of
/// each name counts.
fn read_cookies(headers: &HeaderMap, secure: bool) -> BrowserCookies {
    let csrf = BrowserCookie::Csrf.name(secure);
    let memory = BrowserCookie::ConsentMemory.name(secure);
    let mut cookies = BrowserCookies::default();
    for (name, value) in cookie_pairs(headers) {
        if name == csrf && cookies.csrf.is_none() {
            cookies.csrf = Some(value.to_owned());
        } else if name == memory && cookies.consent_memory.is_none() {
            cookies.consent_memory = Some(value.to_owned());
        }
    }
    cookies
}

/// The binding cookies of the sign-ins in progress in the request's
/// `Cookie` headers, by tag; the first of each tag counts.
fn read_transaction_cookies(headers: &HeaderMap, secure: bool) -> TransactionCookies {
    let prefix = BrowserCookie::transaction_prefix(secure);
    let mut binders = TransactionCookies::default();
    for (name, value) in cookie_pairs(headers) {
        if let Some(tag) = name.strip_prefix(prefix).and_then(TransactionTag::parse) {
            binders.insert(tag, value.to_owned());
        }
    }
    binders
}

/// The `Set-Cookie` value of `change`: `HttpOnly` and `Path=/` always,
/// with `Secure` on an `https://` issuer.
fn set_cookie(change: &CookieChange, secure: bool) -> Option<HeaderValue> {
    let (cookie, value, max_age) = match change {
        CookieChange::Set {
            cookie,
            value,
            max_age_secs,
        } => (*cookie, value.as_str(), *max_age_secs),
        CookieChange::Clear(cookie) => (*cookie, "", 0),
    };
    let mut header = format!(
        "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite={}",
        cookie.name(secure),
        cookie.same_site()
    );
    if secure {
        header.push_str("; Secure");
    }
    HeaderValue::from_str(&header).ok()
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// `text` for HTML content or a quoted attribute: control, format and
/// bidirectional characters removed, and `&`, `<`, `>`, `"` and `'`
/// escaped.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().filter(|&c| !is_invisible(c)) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// `uri`, escaped, with its host in bold.
fn uri_with_bold_host(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return escape(uri);
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_end = if authority.starts_with('[') {
        authority.find(']').map_or(authority.len(), |at| at + 1)
    } else {
        authority.find(':').unwrap_or(authority.len())
    };
    format!(
        "{}://<strong>{}</strong>{}{}",
        escape(scheme),
        escape(&authority[..host_end]),
        escape(&authority[host_end..]),
        escape(&rest[authority_end..])
    )
}

/// A whole page: `title`, `body` and the request id.
fn document(title: &str, body: &str, request_id: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n<title>{title}</title>\n\
         <style>{STYLE}</style>\n</head>\n<body>\n<main>\n{body}\
         <p class=\"muted\">Request ID: <code>{request_id}</code></p>\n</main>\n</body>\n</html>\n",
        title = escape(title),
        request_id = escape(request_id),
    )
}

fn error_html(page: &ErrorPage, request_id: &str) -> String {
    let mut body = format!(
        "<h1>{}</h1>\n<p>{}</p>\n",
        escape(page.title),
        escape(&page.message)
    );
    if let Some(ref link) = page.return_to {
        body.push_str(&format!(
            "<p><a href=\"{}\">Return to {}</a></p>\n",
            escape(&link.href),
            escape(&link.host)
        ));
    }
    body.push_str(&format!(
        "<p class=\"muted\">Error: <code>{}</code></p>\n",
        escape(page.error)
    ));
    document(page.title, &body, request_id)
}

fn notice_html(page: &NoticePage, request_id: &str) -> String {
    let body = format!(
        "<h1>{}</h1>\n<p>{}</p>\n",
        escape(page.title),
        escape(&page.message)
    );
    document(page.title, &body, request_id)
}

fn consent_html(page: &ConsentPage, request_id: &str) -> String {
    let service = escape(&page.service_name);
    let client = escape(&page.client_name);
    let idp = escape(&page.idp_name);
    let unverified = matches!(page.client_kind, ClientKind::Cimd | ClientKind::Dcr);
    let mut body = format!("<h1>Sign in to {service}</h1>\n<p><strong>{client}</strong>");
    if unverified {
        body.push_str("<span class=\"badge\">unverified</span>");
    }
    body.push_str(&format!(" wants to use {service} for you.</p>\n"));
    if page.client_kind == ClientKind::Dcr {
        body.push_str(
            "<p class=\"muted\">This application registered itself with this gateway: its name \
             is its own claim, and nobody has checked it.</p>\n",
        );
    }
    if let Some(ref host) = page.client_host {
        body.push_str(&format!(
            "<p>This application is published at <strong>{}</strong>.</p>\n",
            escape(host)
        ));
    }
    body.push_str(&format!(
        "<dl>\n<dt>After you sign in, you return to</dt>\n<dd class=\"uri\">{}</dd>\n\
         <dt>Resource</dt>\n<dd class=\"uri\">{}</dd>\n<dt>Access</dt>\n<dd>",
        uri_with_bold_host(&page.redirect_uri),
        escape(&page.resource)
    ));
    if page.scopes.is_empty() {
        body.push_str("No named permissions.");
    } else {
        body.push_str("<ul>");
        for line in &page.scopes {
            body.push_str(&format!("<li><code>{}</code>", escape(&line.scope)));
            if let Some(ref description) = line.description {
                body.push_str(&format!(": {}", escape(description)));
            }
            body.push_str("</li>");
        }
        body.push_str("</ul>");
    }
    body.push_str("</dd>\n");
    if !page.authorization_details.is_empty() {
        body.push_str("<dt>Limited to</dt>\n<dd><ul>");
        for line in &page.authorization_details {
            body.push_str(&detail_line_html(line));
        }
        body.push_str("</ul></dd>\n");
    }
    body.push_str("</dl>\n");
    if page.loopback {
        body.push_str(&format!(
            "<p class=\"warn\">This app runs on this computer. Continue only if you just \
             started a sign-in from {client}.</p>\n"
        ));
    }
    body.push_str(&format!("<p>Next: sign in with {idp}.</p>\n"));
    if page.keeps_idp_sign_in {
        body.push_str(&format!(
            "<p class=\"muted\">This gateway will keep your {idp} sign-in to reach connected \
             services for you. It is never given to applications.</p>\n"
        ));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"req\" value=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <div class=\"actions\">\n\
         <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"approve\">Approve</button>\n\
         <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"deny\">Deny</button>\n\
         </div>\n</form>\n",
        escape(&page.form_action),
        escape(&page.request),
        escape(&page.csrf_token)
    ));
    document(
        &format!("Sign in to {}", page.service_name),
        &body,
        request_id,
    )
}

/// One authorization details object on the consent page: its label and
/// type, then each member it names, every value escaped.
fn detail_line_html(line: &DetailLine) -> String {
    let mut html = format!("<li><strong>{}</strong>", escape(&line.label));
    if line.label != line.type_name {
        html.push_str(&format!(" (<code>{}</code>)", escape(&line.type_name)));
    }
    let lists = [
        ("Actions", &line.actions),
        ("Locations", &line.locations),
        ("Data types", &line.datatypes),
        ("Privileges", &line.privileges),
    ];
    let mut parts: Vec<String> = lists
        .into_iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(name, values)| {
            let values: Vec<String> = values
                .iter()
                .map(|value| format!("<code>{}</code>", escape(value)))
                .collect();
            format!("{name}: {}", values.join(", "))
        })
        .collect();
    if let Some(ref identifier) = line.identifier {
        parts.push(format!("Identifier: <code>{}</code>", escape(identifier)));
    }
    if !parts.is_empty() {
        html.push_str(&format!("<br>{}", parts.join("<br>")));
    }
    if let Some(ref other) = line.other {
        html.push_str(&format!(
            "<br>Also:<pre class=\"detail\">{}</pre>",
            escape(other)
        ));
    }
    html.push_str("</li>");
    html
}

fn connect_html(page: &ConnectPage, request_id: &str) -> String {
    let service = escape(&page.service_name);
    let idp = escape(&page.idp_name);
    let mut body = format!(
        "<h1>Connect your {idp} sign-in</h1>\n<p>{service} will keep your {idp} sign-in to reach \
         connected services for you. It is never given to applications.</p>\n"
    );
    if page.link {
        body.push_str(
            "<p class=\"warn\">Continue only if you just asked for this in your application. \
             Sign in as the user you use there: a sign-in as anyone else stores nothing.</p>\n",
        );
    }
    body.push_str(&format!("<p>Next: sign in with {idp}.</p>\n"));
    body.push_str(&format!(
        "<form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"req\" value=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <div class=\"actions\">\n\
         <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"approve\">Connect</button>\n\
         <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"deny\">Cancel</button>\n\
         </div>\n</form>\n",
        escape(&page.form_action),
        escape(&page.request),
        escape(&page.csrf_token)
    ));
    document(
        &format!("Connect your {} sign-in", page.idp_name),
        &body,
        request_id,
    )
}

#[cfg(test)]
#[path = "oauth_browser_tests.rs"]
mod tests;
