//! The authorization endpoint of interactive sign-in, its consent step
//! and the callback the login IdP returns the browser to. `GET
//! /oauth/authorize` checks a request in a fixed order, then shows the
//! consent page or sends the browser to the login IdP; `POST
//! /oauth/consent` takes the user's decision; `GET /oauth/callback`
//! completes the sign-in and issues the client its authorization code.
//!
//! Until the client and its redirect URI are validated, a problem is
//! answered with a page, never a redirect (OAuth 2.1 §4.1.2.1). After
//! that, an error goes back to the redirect URI with `error`, `state` and
//! `iss` (RFC 9207 §2) when the URI is trusted or the user approved the
//! request; otherwise the page offers a link back for the user to follow
//! (OAuth 2.1 §7.12.2).
//!
//! A consent page writes nothing to the store. The validated request
//! travels sealed in the form (`req`), and the form token binds it to a
//! same-site cookie of the browser that loaded the page: an HMAC under a
//! key derived from the state key (RFC 6749 §10.12). A decision is taken
//! once. An approval of an `https://` redirect URI of a registered or
//! metadata document client may be remembered in a sealed cookie of the
//! approving browser, for that client, redirect URI, resource and set of
//! scopes. A request for authorization details (RFC 9396) shows them on
//! the consent page, which only a client registered with `consent: skip`
//! goes without, and its approval is never remembered.
//!
//! Only after consent is a sign-in at the IdP started: the gateway claims
//! the client's PKCE challenge once, stores the transaction sealed under a
//! `state`, `nonce` and PKCE verifier of its own, and binds it to the
//! browser with a cookie named after the `state`. The callback takes the
//! transaction once, only in that browser, only from the IdP it was sent
//! to (RFC 9207 §2.4), redeems the IdP's code, believes the ID token only
//! after every OpenID Connect Core §3.1.3.7 check, and reads the user
//! through the IdP's claim mappings into the principal an ID-JAG of that
//! user names. The user's IdP sign-in is kept sealed per principal, and a
//! grant, pending until its code is redeemed, backs the code.
//!
//! Nothing here logs a `state`, a code, a token, a cookie, a form token or
//! a query string.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::rar::{AuthorizationDetails, DetailLine};
use super::redirect::{
    AuthorizeClient, ConsentRule, RedirectUriKind, check_authorization_pkce, s256_challenge,
    with_response_params,
};
use super::state::{
    CSRF_KEY_DOMAIN, ClientKind, ClientSnapshot, CodeRecord, ConsentApproval, ConsentMemoryRecord,
    GrantId, GrantRecord, GrantStatus, IdentitySnapshot, IdpSessionOrigin, IdpSessionRecord,
    InteractiveState, SecretString, StateError, StateRecord, TransactionPurpose, TransactionRecord,
    keys, random_token,
};
use super::upstream::{
    IdTokenCheck, IdTokenError, IdpAuthorizationRequest, IdpTokens, LoginIdp, RevokeOutcome,
    ValidatedIdToken,
};
use super::{
    AuthorizationServer, MappedIdentity, Principal, ct_eq, error_description, idp_admits_client,
    now_unix,
};

/// Path of the authorization endpoint.
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
/// Path the login IdP returns the browser to: the redirect URI registered
/// at the IdP, under the issuer.
pub const CALLBACK_PATH: &str = "/oauth/callback";
/// Prefix of an authorization code this server issues, which lets secret
/// scanners find a leaked one.
pub const AUTHORIZATION_CODE_PREFIX: &str = "mcpg_ac_";
/// Path the consent form posts to.
pub const CONSENT_PATH: &str = "/oauth/consent";
/// Path of the page where a signed-in user stores their IdP sign-in for
/// federations, without an MCP client.
pub const CONNECT_PATH: &str = "/oauth/connect";
/// Longest client `state` accepted, in bytes.
pub const MAX_STATE_BYTES: usize = 2048;
/// Longest `login_hint` passed on to the IdP, in bytes.
pub const MAX_LOGIN_HINT_BYTES: usize = 256;
/// Largest consent cookie value: a browser keeps a cookie's name and
/// value within 4096 bytes, and the name and attributes need the rest.
pub const MAX_CONSENT_COOKIE_BYTES: usize = 3_800;
/// Longest sealed consent request a form may carry.
pub(super) const MAX_SEALED_REQUEST_CHARS: usize = 32 * 1024;
/// Label a consent form's request is sealed under.
pub(super) const CONSENT_REQUEST_LABEL: &str = "consent_req";
/// Label a browser's consent cookie is sealed under.
const CONSENT_MEMORY_LABEL: &str = "consent_memory";
/// Length of a random value this server generates (a CSRF or binding
/// cookie, the IdP `state`): 32 random bytes in URL-safe base64.
const RANDOM_TOKEN_CHARS: usize = 43;
const SECS_PER_DAY: u64 = 86_400;
/// `prompt` values passed on to the IdP.
const FORWARDED_PROMPTS: [&str; 2] = ["login", "select_account"];
/// Scopes a client asks an OpenID provider for; this server is not one,
/// and refresh tokens do not depend on them.
pub(super) const PROTOCOL_SCOPES: [&str; 2] = ["openid", "offline_access"];
/// Longest parameter name a page repeats back.
const SHOWN_NAME_CHARS: usize = 40;
const TITLE_REFUSED: &str = "This sign-in request cannot be used";
const TITLE_FAILED: &str = "Sign-in failed";
/// Name of a sign-in's binding cookie before its tag, on an `https://`
/// issuer and on an `http://` loopback one.
const TRANSACTION_COOKIE_SECURE: &str = "__Host-mcpg_txn_";
const TRANSACTION_COOKIE_PLAIN: &str = "mcpg_txn_";
/// Hex characters of a binding cookie's tag: 64 bits, enough to keep the
/// sign-ins one browser runs at once apart.
const TRANSACTION_TAG_CHARS: usize = 16;
/// Most binding cookies read from one request.
const MAX_TRANSACTION_COOKIES: usize = 32;
/// How long a sign-in waits for another request's hold on the user's
/// stored IdP sign-in, and how long its own hold lasts at most.
pub(super) const IDP_SESSION_LEASE_WAIT: Duration = Duration::from_secs(2);
pub(super) const IDP_SESSION_LEASE_TTL: Duration = Duration::from_secs(15);
/// Version of the stored IdP sign-in record this server writes.
const IDP_SESSION_RECORD_VERSION: u32 = 1;
/// How long a pending grant outlives its code, so a redemption at the
/// last moment still finds it.
pub(super) const PENDING_GRANT_MARGIN_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// A cookie of the sign-in pages. On an `https://` issuer each carries the
/// `__Host-` prefix, which pins it to this origin, `Secure` and `Path=/`
/// (RFC 6265bis §4.1.3.2); an `http://` loopback issuer, for development,
/// cannot use the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserCookie {
    /// Binds a consent form to the browser that loaded it. Never sent
    /// with a request another site starts (`SameSite=Strict`).
    Csrf,
    /// The approvals the browser remembers. Sent with the top-level
    /// navigation an MCP client starts a sign-in with (`SameSite=Lax`).
    ConsentMemory,
    /// Binds a sign-in at the IdP to the browser that started it; one per
    /// sign-in, named by its tag. Sent with the IdP's top-level redirect
    /// back to the callback (`SameSite=Lax`).
    Transaction(TransactionTag),
}

impl BrowserCookie {
    pub fn name(self, secure: bool) -> Cow<'static, str> {
        match (self, secure) {
            (Self::Csrf, true) => Cow::Borrowed("__Host-mcpg_csrf"),
            (Self::Csrf, false) => Cow::Borrowed("mcpg_csrf"),
            (Self::ConsentMemory, true) => Cow::Borrowed("__Host-mcpg_consent"),
            (Self::ConsentMemory, false) => Cow::Borrowed("mcpg_consent"),
            (Self::Transaction(tag), secure) => Cow::Owned(format!(
                "{}{}",
                Self::transaction_prefix(secure),
                tag.as_str()
            )),
        }
    }

    /// The `SameSite` attribute.
    pub fn same_site(self) -> &'static str {
        match self {
            Self::Csrf => "Strict",
            Self::ConsentMemory | Self::Transaction(_) => "Lax",
        }
    }

    /// What the name of every binding cookie starts with.
    pub fn transaction_prefix(secure: bool) -> &'static str {
        if secure {
            TRANSACTION_COOKIE_SECURE
        } else {
            TRANSACTION_COOKIE_PLAIN
        }
    }
}

/// The tag in a binding cookie's name: 64 bits of a hash of the `state`
/// the sign-in's IdP request carries, so the sign-ins one browser runs at
/// once keep a cookie each and the callback finds its own.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionTag([u8; TRANSACTION_TAG_CHARS]);

impl TransactionTag {
    /// The tag of the sign-in whose IdP request carries `state`.
    pub fn of_state(state: &str) -> Self {
        let digest = blake3::Hasher::new_derive_key("mcpg as v1 txn cookie")
            .update(state.as_bytes())
            .finalize();
        let mut tag = [0u8; TRANSACTION_TAG_CHARS];
        tag.copy_from_slice(&digest.to_hex().as_bytes()[..TRANSACTION_TAG_CHARS]);
        Self(tag)
    }

    /// `value` when it has the form of a tag: lowercase hex.
    pub fn parse(value: &str) -> Option<Self> {
        let bytes: [u8; TRANSACTION_TAG_CHARS] = value.as_bytes().try_into().ok()?;
        bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            .then_some(Self(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl std::fmt::Debug for TransactionTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The binding cookies a request carried, by tag; the first of each tag
/// counts, and at most [`MAX_TRANSACTION_COOKIES`] are kept.
#[derive(Clone, Default)]
pub struct TransactionCookies(Vec<(TransactionTag, String)>);

impl TransactionCookies {
    /// Keep `value` for `tag`, unless the tag has one or the limit is
    /// reached.
    pub fn insert(&mut self, tag: TransactionTag, value: String) {
        if self.0.len() < MAX_TRANSACTION_COOKIES && self.get(tag).is_none() {
            self.0.push((tag, value));
        }
    }

    pub fn get(&self, tag: TransactionTag) -> Option<&str> {
        self.0
            .iter()
            .find(|(kept, _)| *kept == tag)
            .map(|(_, value)| value.as_str())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for TransactionCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(tag, _)| tag))
            .finish()
    }
}

/// The hash a transaction keeps of its binding cookie's value.
fn binder_hash(binder: &str) -> String {
    blake3::Hasher::new_derive_key("mcpg as v1 txn binder")
        .update(binder.as_bytes())
        .finalize()
        .to_hex()
        .to_string()
}

/// The sign-in cookies a request carried.
#[derive(Clone, Default)]
pub struct BrowserCookies {
    pub csrf: Option<String>,
    pub consent_memory: Option<String>,
}

impl std::fmt::Debug for BrowserCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserCookies")
            .field("csrf", &self.csrf.is_some())
            .field("consent_memory", &self.consent_memory.is_some())
            .finish()
    }
}

/// A cookie a response sets or removes.
#[derive(Clone, PartialEq, Eq)]
pub enum CookieChange {
    Set {
        cookie: BrowserCookie,
        value: String,
        max_age_secs: u64,
    },
    Clear(BrowserCookie),
}

impl std::fmt::Debug for CookieChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set {
                cookie,
                max_age_secs,
                ..
            } => f
                .debug_struct("Set")
                .field("cookie", cookie)
                .field("max_age_secs", max_age_secs)
                .finish_non_exhaustive(),
            Self::Clear(cookie) => f.debug_tuple("Clear").field(cookie).finish(),
        }
    }
}

/// Whether `value` has the shape of a random value this server generates:
/// a CSRF cookie, a binding cookie, the `state` sent to the IdP or a link
/// id.
pub(super) fn is_random_token(value: &str) -> bool {
    value.len() == RANDOM_TOKEN_CHARS
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ---------------------------------------------------------------------------
// What a page answers
// ---------------------------------------------------------------------------

/// A page that tells the user why the request stops here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPage {
    /// The HTTP status.
    pub status: u16,
    /// The OAuth error code, for metrics and audit.
    pub error: &'static str,
    pub title: &'static str,
    /// What went wrong, in words this server chose.
    pub message: String,
    /// A link back to the client with the error response, for the user
    /// to follow.
    pub return_to: Option<ReturnLink>,
}

/// A link back to the client that the user follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnLink {
    /// The client's redirect URI with the error response.
    pub href: String,
    /// Its host, which the link names.
    pub host: String,
}

impl ErrorPage {
    pub(super) fn new(
        status: u16,
        error: &'static str,
        title: &'static str,
        message: &str,
    ) -> Self {
        Self {
            status,
            error,
            title,
            message: message.to_owned(),
            return_to: None,
        }
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Self::new(400, "invalid_request", TITLE_REFUSED, "")
        }
    }

    /// 404: this server offers no interactive sign-in.
    pub fn not_offered() -> Self {
        Self::new(
            404,
            "not_found",
            "Sign-in is not offered here",
            "This server does not sign users in through a browser.",
        )
    }

    /// 400: the request did not arrive on the issuer's host.
    pub fn wrong_host() -> Self {
        Self::new(
            400,
            "invalid_request",
            TITLE_REFUSED,
            "The request did not arrive at the address this sign-in service is published at.",
        )
    }

    /// 429: the client address spent its budget.
    pub fn rate_limited() -> Self {
        Self::new(
            429,
            "temporarily_unavailable",
            "Too many sign-in requests",
            "Too many sign-in requests came from your network. Wait a minute, then try again.",
        )
    }

    /// 405: a method the page does not answer.
    pub fn method_not_allowed() -> Self {
        Self::new(
            405,
            "invalid_request",
            TITLE_REFUSED,
            "This page does not accept that kind of request.",
        )
    }

    /// 403: a consent decision posted from another origin.
    pub fn cross_origin() -> Self {
        Self::new(
            403,
            "invalid_request",
            "The decision was not accepted",
            "The decision did not come from this sign-in page. Start the sign-in again from your \
             application.",
        )
    }

    /// 400: a consent form that cannot be read.
    pub fn unreadable_form() -> Self {
        Self::bad_request(
            "The consent form could not be read. Start the sign-in again from your application.",
        )
    }

    pub(super) fn unavailable() -> Self {
        Self::new(
            503,
            "temporarily_unavailable",
            "Sign-in is unavailable",
            "Signing in is not possible right now. Try again in a few minutes.",
        )
    }

    pub(super) fn idp_unavailable() -> Self {
        Self::new(
            503,
            "temporarily_unavailable",
            "Sign-in is unavailable",
            "The sign-in service of your organization cannot be reached right now. Try again in a \
             few minutes.",
        )
    }

    pub(super) fn expired() -> Self {
        Self::new(
            400,
            "invalid_request",
            "This consent page expired",
            "This consent page expired or is not valid. Start the sign-in again from your \
             application.",
        )
    }

    pub(super) fn already_answered() -> Self {
        Self::new(
            400,
            "invalid_request",
            "This consent page was already answered",
            "Your decision on this page was already taken. Start the sign-in again from your \
             application.",
        )
    }

    pub(super) fn forged() -> Self {
        Self::new(
            403,
            "invalid_request",
            "The decision was not accepted",
            "The decision could not be matched to this browser. Start the sign-in again from your \
             application, in this browser.",
        )
    }

    /// 400: a callback whose sign-in is unknown, expired or already
    /// completed.
    fn sign_in_expired() -> Self {
        Self::new(
            400,
            "invalid_request",
            "This sign-in expired or was already used",
            "This sign-in expired or was already used. Start again from your application.",
        )
    }

    /// 400: a callback in a browser without the sign-in's binding cookie.
    fn other_browser() -> Self {
        Self::new(
            400,
            "invalid_request",
            "Finish the sign-in in the browser that started it",
            "This sign-in was started in another browser, or this browser no longer holds its \
             cookie. Start again from your application, and finish the sign-in in the browser \
             that started it.",
        )
    }

    /// 400: an authorization response that did not come from the IdP the
    /// sign-in was sent to (RFC 9207 §2.4).
    fn wrong_issuer() -> Self {
        Self::new(
            400,
            "invalid_request",
            "The sign-in response was not accepted",
            "The response did not come from the sign-in service this sign-in was sent to. Start \
             again from your application.",
        )
    }

    /// 400: the login IdP changed while the user was signing in.
    fn idp_changed() -> Self {
        Self::new(
            400,
            "invalid_request",
            TITLE_FAILED,
            "The sign-in service changed while you were signing in. Start again from your \
             application.",
        )
    }

    /// 400: the client was removed while the user was signing in.
    fn client_removed() -> Self {
        Self::new(
            400,
            "unauthorized_client",
            TITLE_FAILED,
            "The application you are signing in to is no longer registered here.",
        )
    }

    /// 500: a transaction that does not describe the sign-in it is for.
    fn internal() -> Self {
        Self::new(
            500,
            "server_error",
            TITLE_FAILED,
            "The sign-in could not continue. Start it again from your application.",
        )
    }

    /// The status of a page that carries `error`.
    fn status_of(error: &str) -> u16 {
        match error {
            "access_denied" => 403,
            "server_error" => 500,
            "temporarily_unavailable" => 503,
            _ => 400,
        }
    }
}

/// A page that tells the user a step succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticePage {
    pub title: &'static str,
    pub message: String,
}

/// One scope on the consent page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLine {
    pub scope: String,
    /// `consent.scope_descriptions[scope]`.
    pub description: Option<String>,
}

/// What the consent page shows and posts back.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentPage {
    /// The heading: `consent.service_name`, or the issuer's host.
    pub service_name: String,
    /// The client's name, else its `client_id`.
    pub client_name: String,
    pub client_kind: ClientKind,
    /// The host of a metadata document client's `client_id` URL, which
    /// vouches for the client.
    pub client_host: Option<String>,
    /// Where the browser returns after sign-in.
    pub redirect_uri: String,
    /// Whether that is a loopback URI, which any program on the user's
    /// computer can listen on.
    pub loopback: bool,
    pub resource: String,
    pub scopes: Vec<ScopeLine>,
    /// The authorization details (RFC 9396) the request asks for.
    pub authorization_details: Vec<DetailLine>,
    /// The login IdP's name.
    pub idp_name: String,
    /// Whether the gateway keeps the user's IdP sign-in afterwards.
    pub keeps_idp_sign_in: bool,
    /// Where the form posts: the consent endpoint under the issuer.
    pub form_action: String,
    /// The sealed request (`req`).
    pub request: String,
    /// The form token (`csrf`).
    pub csrf_token: String,
}

impl std::fmt::Debug for ConsentPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentPage")
            .field("client_name", &self.client_name)
            .field("client_kind", &self.client_kind)
            .field("redirect_uri", &self.redirect_uri)
            .field("resource", &self.resource)
            .field("scopes", &self.scopes)
            .field("authorization_details", &self.authorization_details)
            .finish_non_exhaustive()
    }
}

/// What a sign-in page answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserOutcome {
    /// A page that says why the request stops.
    Page(ErrorPage),
    /// `303` to the client's redirect URI with an error response.
    ErrorRedirect {
        location: String,
        error: &'static str,
    },
    /// The consent page.
    Consent(Box<ConsentPage>),
    /// The page that asks the user to store their IdP sign-in.
    Connect(Box<super::connect::ConnectPage>),
    /// `303` to the login IdP.
    SignIn(String),
    /// `303` to the client's redirect URI with the authorization code.
    CodeIssued(String),
    /// A page that says the step succeeded.
    Done(NoticePage),
}

/// A sign-in page's answer, the cookies it changes, what the audit log
/// records of it, the IdP refresh token a newer sign-in replaced, and the
/// MCP session a completed link tells.
#[derive(Debug)]
pub struct BrowserResponse {
    pub outcome: BrowserOutcome,
    pub cookies: Vec<CookieChange>,
    pub audit: Option<BrowserAudit>,
    /// Revoke with [`AuthorizationServer::revoke_superseded`] once the
    /// answer is sent.
    pub superseded: Option<SupersededSignIn>,
    /// Send `notifications/elicitation/complete` once the answer is sent.
    pub link_completed: Option<super::connect::CompletedLink>,
}

impl BrowserResponse {
    pub(super) fn page(page: ErrorPage) -> Self {
        Self::outcome(BrowserOutcome::Page(page))
    }

    pub(super) fn outcome(outcome: BrowserOutcome) -> Self {
        Self {
            outcome,
            cookies: Vec::new(),
            audit: None,
            superseded: None,
            link_completed: None,
        }
    }

    pub(super) fn with_audit(mut self, audit: BrowserAudit) -> Self {
        self.audit = Some(audit);
        self
    }
}

/// The IdP refresh token of a stored sign-in the gateway no longer keeps,
/// replaced by a newer sign-in or ended with the user's last grant, which
/// the IdP should stop honouring (RFC 7009). `Debug` shows no token.
#[derive(Debug)]
pub struct SupersededSignIn {
    /// The IdP and the gateway's client there, which the token was issued
    /// to.
    pub issuer: String,
    pub client_id: String,
    pub refresh_token: SecretString,
}

/// The user's answer on a consent page, or the approval the browser
/// remembered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Approved,
    Denied,
    Remembered,
}

impl ConsentDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Remembered => "remembered",
        }
    }
}

/// What the audit log records of a sign-in page's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAudit {
    /// `mcpg.as.consent`.
    Consent {
        decision: ConsentDecision,
        client_id: String,
        client_kind: ClientKind,
        redirect_host: String,
        scope: Vec<String>,
        resource: String,
        /// The types of the authorization details asked for, never their
        /// values.
        authorization_details_types: Vec<String>,
    },
    /// `mcpg.auth.failed` with `auth_method: as_authorize`: a consent
    /// decision refused before it was read.
    Refused { reason: &'static str },
    /// `mcpg.as.login`: a sign-in at the login IdP completed.
    Login(Box<LoginAudit>),
    /// `mcpg.auth.failed` with `auth_method: as_callback`: the answer the
    /// IdP sent the browser back with was refused. The reason quotes no
    /// code, token, `state` or claim value.
    CallbackRefused { reason: String },
    /// `mcpg.as.connect_refused`: someone other than the user a link was
    /// offered to signed in through it, and nothing was stored.
    ConnectRefused(Box<ConnectRefusedAudit>),
}

/// What `mcpg.as.connect_refused` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRefusedAudit {
    /// The login IdP's issuer.
    pub idp: String,
    /// The user who signed in, as the IdP's claim mappings read them.
    pub subject: String,
    pub principal_issuer: String,
    pub auth_provider: String,
    /// The principal key of the user the link was offered to.
    pub offered_to: String,
    /// The MCP client that user called from, when known.
    pub client_id: Option<String>,
    /// The binding cookie's tag.
    pub transaction: String,
}

/// What `mcpg.as.login` records of a completed sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAudit {
    pub purpose: TransactionPurpose,
    pub client_id: Option<String>,
    pub client_kind: Option<ClientKind>,
    /// The login IdP's issuer.
    pub idp: String,
    /// The user, as the IdP's claim mappings read them.
    pub subject: String,
    /// The principal namespace and `auth_provider` the user resolves to.
    pub principal_issuer: String,
    pub auth_provider: String,
    /// The grant the authorization code is for.
    pub gid: Option<GrantId>,
    pub resource: Option<String>,
    pub scope: Vec<String>,
    /// The types of the authorization details the code is for.
    pub authorization_details_types: Vec<String>,
    pub idp_session: IdpSessionWrite,
    /// The binding cookie's tag, which correlates the sign-in with the
    /// redirect that started it.
    pub transaction: String,
}

/// What a completed sign-in did with the user's stored IdP sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpSessionWrite {
    /// Stored; the user had none.
    Stored,
    /// Stored in place of an earlier one.
    Replaced,
    /// Not kept: nothing uses it.
    NotKept,
}

impl IdpSessionWrite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Replaced => "replaced",
            Self::NotKept => "not_kept",
        }
    }
}

impl BrowserAudit {
    fn consent(decision: ConsentDecision, request: &AuthorizationRequest) -> Self {
        Self::Consent {
            decision,
            client_id: request.client_id.clone(),
            client_kind: request.client_kind,
            redirect_host: url_host(&request.redirect_uri).unwrap_or_default(),
            scope: request.scope.clone(),
            resource: request.resource.clone(),
            authorization_details_types: detail_types(&request.authorization_details),
        }
    }

    /// The audit event of this answer to the request `request_id`. It
    /// carries no form token, cookie or `state`.
    pub fn event(&self, request_id: &str) -> mcpg_plugin_protocol::audit::AuditEvent {
        use mcpg_plugin_host::audit_events::{auth_failed_event, new_event_id, now_rfc3339_utc};
        use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
        match self {
            Self::Refused { reason } => {
                auth_failed_event("as_authorize", reason, request_id, "http")
            }
            Self::CallbackRefused { reason } => {
                auth_failed_event("as_callback", reason, request_id, "http")
            }
            Self::ConnectRefused(refused) => AuditEvent {
                event_id: new_event_id(),
                occurred_at: now_rfc3339_utc(),
                actor: mcpg_plugin_protocol::PluginIdentity {
                    kind: "verified".into(),
                    trust_level: "verified".into(),
                    subject_id: Some(refused.subject.clone()),
                    auth_provider: Some(refused.auth_provider.clone()),
                    issuer: Some(refused.principal_issuer.clone()),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: BTreeMap::new(),
                },
                action: "mcpg.as.connect_refused".into(),
                resource: None,
                outcome: AuditOutcome::Denied,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details: serde_json::json!({
                    "reason": "another user signed in",
                    "idp": refused.idp,
                    "offered_to": refused.offered_to,
                    "client_id": refused.client_id,
                    "transaction": refused.transaction,
                }),
                prev_event_hash: None,
            },
            Self::Login(login) => AuditEvent {
                event_id: new_event_id(),
                occurred_at: now_rfc3339_utc(),
                actor: mcpg_plugin_protocol::PluginIdentity {
                    kind: "verified".into(),
                    trust_level: "verified".into(),
                    subject_id: Some(login.subject.clone()),
                    auth_provider: Some(login.auth_provider.clone()),
                    issuer: Some(login.principal_issuer.clone()),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: login.scope.clone(),
                    attributes: BTreeMap::new(),
                },
                action: "mcpg.as.login".into(),
                resource: login.resource.clone(),
                outcome: AuditOutcome::Success,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details: serde_json::json!({
                    "purpose": login.purpose.as_str(),
                    "client_id": login.client_id,
                    "client_kind": login.client_kind.map(ClientKind::as_str),
                    "idp": login.idp,
                    "gid": login.gid.as_ref().map(GrantId::as_str),
                    "scope": login.scope,
                    "authorization_details_types": login.authorization_details_types,
                    "idp_session": login.idp_session.as_str(),
                    "transaction": login.transaction,
                }),
                prev_event_hash: None,
            },
            Self::Consent {
                decision,
                client_id,
                client_kind,
                redirect_host,
                scope,
                resource,
                authorization_details_types,
            } => AuditEvent {
                event_id: new_event_id(),
                occurred_at: now_rfc3339_utc(),
                actor: mcpg_plugin_protocol::PluginIdentity {
                    kind: "anonymous".into(),
                    trust_level: "unauthenticated".into(),
                    subject_id: None,
                    auth_provider: None,
                    issuer: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: BTreeMap::new(),
                },
                action: "mcpg.as.consent".into(),
                resource: Some(resource.clone()),
                outcome: match decision {
                    ConsentDecision::Denied => AuditOutcome::Denied,
                    ConsentDecision::Approved | ConsentDecision::Remembered => {
                        AuditOutcome::Success
                    }
                },
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details: serde_json::json!({
                    "decision": decision.as_str(),
                    "client_id": client_id,
                    "client_kind": client_kind.as_str(),
                    "redirect_host": redirect_host,
                    "scope": scope,
                    "authorization_details_types": authorization_details_types,
                }),
                prev_event_hash: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// An authorization request as validated: what the sign-in at the IdP,
/// and the code issued after it, are bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub client_kind: ClientKind,
    #[serde(default)]
    pub client_name: Option<String>,
    /// The redirect URI as requested, or the one registered when the
    /// request named none.
    pub redirect_uri: String,
    /// Whether an error may go to it before the user approved.
    pub redirect_trusted: bool,
    /// Whether it is a loopback URI.
    #[serde(default)]
    pub redirect_loopback: bool,
    /// The client's `state`, returned to it unchanged.
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub resource: String,
    #[serde(default)]
    pub scope: Vec<String>,
    /// `login` and `select_account`, passed on to the IdP.
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    /// Whether an approval of it may be remembered.
    #[serde(default)]
    pub rememberable: bool,
    /// The thumbprint of the DPoP key the code will be redeemed with
    /// (`dpop_jkt`, RFC 9449 §10), read while DPoP is on.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// The authorization details (RFC 9396) the request asks for, read
    /// while authorization details types are configured.
    #[serde(default, skip_serializing_if = "AuthorizationDetails::is_empty")]
    pub authorization_details: AuthorizationDetails,
}

/// A consent form's request, sealed into the form (`req`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub purpose: TransactionPurpose,
    /// Until when the form may be posted, in Unix seconds.
    pub exp: u64,
    #[serde(default)]
    pub authorization: Option<AuthorizationRequest>,
    /// The link the form completes, for [`TransactionPurpose::Link`].
    #[serde(default)]
    pub link: Option<String>,
}

impl StateRecord for ConsentRequest {}

/// The fields `POST /oauth/consent` reads.
#[derive(Default, Deserialize)]
pub struct ConsentForm {
    #[serde(default)]
    pub req: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
    /// `approve` or `deny`.
    #[serde(default)]
    pub decision: Option<String>,
}

/// The query of a request to a sign-in page, each parameter at most once
/// except those named `repeatable` (RFC 6749 §3.1; RFC 8707 §2 lets
/// `resource` repeat). An empty value counts as absent.
pub(super) struct QueryParams(BTreeMap<String, Vec<String>>);

impl QueryParams {
    pub(super) fn parse(query: &str, repeatable: &[&str]) -> Result<Self, ErrorPage> {
        let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            params
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        if let Some(name) = params
            .iter()
            .find(|(name, values)| values.len() > 1 && !repeatable.contains(&name.as_str()))
            .map(|(name, _)| name)
        {
            return Err(ErrorPage::bad_request(format!(
                "The request repeats the parameter `{}`.",
                name.chars()
                    .filter(|c| !c.is_control())
                    .take(SHOWN_NAME_CHARS)
                    .collect::<String>()
            )));
        }
        Ok(Self(params))
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.0
            .get(name)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .collect()
    }
}

/// The `prompt` of a request (OpenID Connect Core §3.1.2.1).
#[derive(Debug, Default, PartialEq, Eq)]
struct Prompt {
    /// `consent`: show the consent page.
    consent: bool,
    /// `login` and `select_account`, for the IdP.
    forwarded: Option<String>,
}

/// `prompt`, space-separated: `consent`, `login` and `select_account`.
/// `none` is refused, since signing in may need the user (OAuth 2.1
/// §7.12.2), as is any other value.
fn parse_prompt(value: Option<&str>) -> Result<Prompt, &'static str> {
    let mut prompt = Prompt::default();
    let mut forwarded: Vec<&str> = Vec::new();
    for value in value
        .unwrap_or_default()
        .split(' ')
        .filter(|v| !v.is_empty())
    {
        match value {
            "none" => return Err("prompt=none is not supported"),
            "consent" => prompt.consent = true,
            _ if FORWARDED_PROMPTS.contains(&value) => {
                if !forwarded.contains(&value) {
                    forwarded.push(value);
                }
            }
            _ => return Err("prompt may be consent, login or select_account"),
        }
    }
    prompt.forwarded = (!forwarded.is_empty()).then(|| forwarded.join(" "));
    Ok(prompt)
}

/// A request that passed every check.
struct Validated {
    request: AuthorizationRequest,
    /// `prompt=consent`.
    consent_forced: bool,
}

/// The distinct types of `details`, for an audit record.
fn detail_types(details: &AuthorizationDetails) -> Vec<String> {
    details.types().into_iter().map(str::to_owned).collect()
}

/// The host of the URL `uri`.
pub(super) fn url_host(uri: &str) -> Option<String> {
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

/// The form token of the consent form carrying `request` in a browser
/// holding the CSRF cookie `cookie`: HMAC-SHA256 under `key` of the two,
/// each hashed first.
pub(super) fn csrf_token(key: &[u8; 32], request: &str, cookie: &str) -> String {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(Sha256::digest(request.as_bytes()).as_slice());
    input[32..].copy_from_slice(Sha256::digest(cookie.as_bytes()).as_slice());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hmac_sha256::HMAC::mac(input, key))
}

/// Whether `token` is the form token of `request` and `cookie` under any
/// of `keys`, each compared in constant time.
pub(super) fn csrf_matches(
    keys: &[Zeroizing<[u8; 32]>],
    request: &str,
    cookie: &str,
    token: &str,
) -> bool {
    keys.iter().fold(false, |matched, key| {
        matched | ct_eq(&csrf_token(key, request, cookie), token)
    })
}

/// A page's sealed request, bound to the CSRF cookie of the browser it is
/// shown in.
pub(super) struct SealedForm {
    /// The sealed request (`req`).
    pub(super) request: String,
    /// The form token (`csrf`).
    pub(super) csrf_token: String,
    /// The CSRF cookie the page sets.
    pub(super) cookie: CookieChange,
}

/// `consent` sealed into a form for the browser that sent `cookies`, bound
/// to its CSRF cookie. A browser that has one keeps it, so the pages open
/// in its tabs stay valid; the cookie lives as long as the form.
pub(super) fn sealed_form(
    state: &InteractiveState,
    consent: &ConsentRequest,
    cookies: &BrowserCookies,
) -> Result<SealedForm, BrowserResponse> {
    let sealed = state
        .seal_value(CONSENT_REQUEST_LABEL, consent)
        .map_err(|error| {
            tracing::error!(error = %error, "a page's request could not be sealed");
            BrowserResponse::page(ErrorPage::unavailable())
        })?;
    let csrf_cookie = match cookies
        .csrf
        .as_deref()
        .filter(|value| is_random_token(value))
    {
        Some(value) => value.to_owned(),
        None => random_token().map_err(|error| {
            tracing::error!(error = %error, "a CSRF cookie could not be generated");
            BrowserResponse::page(ErrorPage::unavailable())
        })?,
    };
    let keys = state.keyring().derive(CSRF_KEY_DOMAIN);
    Ok(SealedForm {
        csrf_token: csrf_token(&keys[0], &sealed, &csrf_cookie),
        request: sealed,
        cookie: CookieChange::Set {
            cookie: BrowserCookie::Csrf,
            value: csrf_cookie,
            max_age_secs: consent.exp.saturating_sub(now_unix()),
        },
    })
}

/// The request and decision a posted `form` carries: its sealed request
/// opens, is unexpired at `now` and is one `accepts` takes, its form token
/// matches the CSRF cookie of the browser that sent `cookies`, it names a
/// decision, and it is decided once.
pub(super) async fn decided_form(
    state: &InteractiveState,
    form: &ConsentForm,
    cookies: &BrowserCookies,
    now: u64,
    accepts: impl Fn(&ConsentRequest) -> bool,
) -> Result<(ConsentRequest, ConsentDecision), BrowserResponse> {
    let Some(sealed) = form
        .req
        .as_deref()
        .filter(|sealed| !sealed.is_empty() && sealed.len() <= MAX_SEALED_REQUEST_CHARS)
    else {
        return Err(BrowserResponse::page(ErrorPage::expired()));
    };
    let Some(consent) = state
        .open_value::<ConsentRequest>(CONSENT_REQUEST_LABEL, sealed)
        .filter(|consent| consent.exp > now && accepts(consent))
    else {
        return Err(BrowserResponse::page(ErrorPage::expired()));
    };
    let bound = cookies
        .csrf
        .as_deref()
        .filter(|cookie| is_random_token(cookie))
        .zip(form.csrf.as_deref())
        .is_some_and(|(cookie, token)| {
            csrf_matches(
                &state.keyring().derive(CSRF_KEY_DOMAIN),
                sealed,
                cookie,
                token,
            )
        });
    if !bound {
        return Err(BrowserResponse {
            audit: Some(BrowserAudit::Refused {
                reason: "the consent form token does not match the browser's CSRF cookie",
            }),
            ..BrowserResponse::page(ErrorPage::forged())
        });
    }
    let decision = match form.decision.as_deref() {
        Some("approve") => ConsentDecision::Approved,
        Some("deny") => ConsentDecision::Denied,
        _ => {
            return Err(BrowserResponse::page(ErrorPage::bad_request(
                "The consent form carries no decision.",
            )));
        }
    };
    match state
        .claim_once(
            &keys::consent_used(sealed),
            Duration::from_secs(consent.exp.saturating_sub(now)),
        )
        .await
    {
        Ok(true) => Ok((consent, decision)),
        Ok(false) => Err(BrowserResponse::page(ErrorPage::already_answered())),
        Err(error) => {
            tracing::error!(
                error = %error,
                "a consent decision could not be recorded; refusing it"
            );
            Err(BrowserResponse::page(ErrorPage::unavailable()))
        }
    }
}

fn record_authorize(outcome: &BrowserOutcome, client_kind: Option<ClientKind>) {
    let (outcome, error) = match outcome {
        BrowserOutcome::Consent(_) => ("consent_shown", "none"),
        BrowserOutcome::SignIn(_) => ("idp_redirect", "none"),
        BrowserOutcome::Page(page) => ("refused", page.error),
        BrowserOutcome::ErrorRedirect { error, .. } => ("refused", *error),
        BrowserOutcome::CodeIssued(_) | BrowserOutcome::Done(_) | BrowserOutcome::Connect(_) => {
            return;
        }
    };
    metrics::counter!(
        "mcpg_as_authorize_total",
        "outcome" => outcome,
        "error" => error,
        "client_kind" => client_kind.map_or("none", ClientKind::as_str),
    )
    .increment(1);
}

fn record_consent(decision: ConsentDecision, client_kind: ClientKind) {
    metrics::counter!(
        "mcpg_as_consent_total",
        "decision" => decision.as_str(),
        "client_kind" => client_kind.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// The endpoints
// ---------------------------------------------------------------------------

impl AuthorizationServer {
    /// Whether the sign-in cookies carry the `__Host-` prefix and
    /// `Secure`: on an `https://` issuer.
    pub fn secure_cookies(&self) -> bool {
        self.issuer.starts_with("https://")
    }

    /// Whether `host`, the host a browser request arrived at, is the
    /// issuer's: the same host and port, a scheme's default port counting
    /// as absent (RFC 9700 §4.13).
    pub fn is_issuer_host(&self, host: &str) -> bool {
        let Ok(issuer) = url::Url::parse(&self.issuer) else {
            return false;
        };
        let Ok(arrived) = url::Url::parse(&format!("{}://{host}/", issuer.scheme())) else {
            return false;
        };
        arrived.username().is_empty()
            && arrived.password().is_none()
            && arrived.path() == "/"
            && arrived.query().is_none()
            && arrived.fragment().is_none()
            && arrived.host().is_some()
            && arrived.host() == issuer.host()
            && arrived.port_or_known_default() == issuer.port_or_known_default()
    }

    /// Whether a consent decision was posted by this server's own page:
    /// its `Origin` is the issuer's origin, or the browser sends none or
    /// `null` and says `Sec-Fetch-Site: same-origin`. The pages send no
    /// referrer, and under that policy a browser posts their form with
    /// `Origin: null` (Fetch §3.1); `Sec-Fetch-Site` is a forbidden header
    /// name, which no page script can set. A `Sec-Fetch-Site` of anything
    /// else refuses it either way.
    pub fn is_same_origin_post(&self, origin: Option<&str>, sec_fetch_site: Option<&str>) -> bool {
        if sec_fetch_site.is_some_and(|site| site != "same-origin") {
            return false;
        }
        let origin = match origin {
            None | Some("null") => return sec_fetch_site == Some("same-origin"),
            Some(origin) => origin,
        };
        let (Ok(posted), Ok(issuer)) = (url::Url::parse(origin), url::Url::parse(&self.issuer))
        else {
            return false;
        };
        posted.path() == "/"
            && posted.query().is_none()
            && posted.username().is_empty()
            && posted.origin() == issuer.origin()
    }

    /// Whether a sign-in's IdP tokens are kept: refresh tokens are
    /// checked at the IdP, or a federation presents the stored sign-in
    /// upstream.
    pub fn keeps_idp_sign_in(&self) -> bool {
        let refresh = &self.interactive.refresh_tokens;
        (refresh.enabled && refresh.revalidate_with_idp) || self.federated_idp_sessions
    }

    /// The state of interactive sign-in, when it can be used.
    pub(super) fn sign_in_state(&self) -> Option<&InteractiveState> {
        self.interactive_state
            .as_ref()
            .filter(|state| state.is_available())
    }

    /// The name the sign-in pages give this service: `consent.service_name`,
    /// else the issuer's host.
    pub(super) fn service_name(&self) -> String {
        self.interactive
            .consent
            .service_name
            .clone()
            .or_else(|| url_host(&self.issuer))
            .unwrap_or_else(|| self.issuer.clone())
    }

    /// Answer `GET /oauth/authorize` with its raw `query` and the sign-in
    /// cookies the browser sent. The caller has checked the host and the
    /// client address's budget.
    pub async fn authorize(&self, query: &str, cookies: &BrowserCookies) -> BrowserResponse {
        let (response, client_kind) = self.authorize_request(query, cookies).await;
        record_authorize(&response.outcome, client_kind);
        response
    }

    async fn authorize_request(
        &self,
        query: &str,
        cookies: &BrowserCookies,
    ) -> (BrowserResponse, Option<ClientKind>) {
        let Some(state) = self.sign_in_state() else {
            return (BrowserResponse::page(ErrorPage::unavailable()), None);
        };
        let params = match QueryParams::parse(query, &["resource"]) {
            Ok(params) => params,
            Err(page) => return (BrowserResponse::page(page), None),
        };
        if params.get("request").is_some() || params.get("request_uri").is_some() {
            return (
                BrowserResponse::page(ErrorPage::bad_request(
                    "Request objects (the request and request_uri parameters) are not supported.",
                )),
                None,
            );
        }
        let client = match self
            .authorize_client(params.get("client_id"), params.get("redirect_uri"))
            .await
        {
            Ok(client) => client,
            Err(error) => {
                let page = ErrorPage {
                    status: error.status(),
                    error: error.error(),
                    title: TITLE_REFUSED,
                    message: error.description(),
                    return_to: None,
                };
                return (BrowserResponse::page(page), None);
            }
        };
        let kind = Some(client.kind);
        let response = match self.validate_request(&params, &client) {
            Ok(validated) => {
                self.consent_or_sign_in(state, validated, &client, cookies)
                    .await
            }
            Err(outcome) => BrowserResponse::outcome(outcome),
        };
        (response, kind)
    }

    /// The checks after the client and its redirect URI, in order:
    /// `response_type` and `response_mode`, PKCE, `resource`,
    /// `authorization_details` while types are configured, `scope`,
    /// `prompt`, the lengths of `state` and `login_hint`, `dpop_jkt` while
    /// DPoP is on, and the IdP's `allowed_clients`.
    fn validate_request(
        &self,
        params: &QueryParams,
        client: &AuthorizeClient,
    ) -> Result<Validated, BrowserOutcome> {
        let state = params.get("state");
        let echoed_state = state.filter(|state| state.len() <= MAX_STATE_BYTES);
        let refuse = |error: &'static str, description: &str| {
            self.refusal(
                &client.redirect.uri,
                client.redirect.trusted,
                echoed_state,
                error,
                description,
            )
        };
        match params.get("response_type") {
            Some("code") => {}
            None => return Err(refuse("invalid_request", "response_type is required")),
            Some(_) => {
                return Err(refuse(
                    "unsupported_response_type",
                    "the only response_type supported is code",
                ));
            }
        }
        if params
            .get("response_mode")
            .is_some_and(|mode| mode != "query")
        {
            return Err(refuse(
                "invalid_request",
                "the only response_mode supported is query",
            ));
        }
        let code_challenge = check_authorization_pkce(
            params.get("code_challenge"),
            params.get("code_challenge_method"),
        )
        .map_err(|error| refuse(error.error(), error.description()))?;
        let resource = self
            .authorization_resource(&params.all("resource"))
            .map_err(|description| refuse("invalid_target", description))?;
        // RFC 6749 §3.1: while no type is configured the parameter is
        // unknown, and ignored.
        let authorization_details = self
            .authorize_details(params.get("authorization_details"))
            .map_err(|description| refuse("invalid_authorization_details", &description))?;
        let scope = self
            .authorization_scope(params.get("scope"), !authorization_details.is_empty())
            .map_err(|description| refuse("invalid_scope", description))?;
        let prompt = parse_prompt(params.get("prompt"))
            .map_err(|description| refuse("invalid_request", description))?;
        if state.is_some_and(|state| state.len() > MAX_STATE_BYTES) {
            return Err(refuse(
                "invalid_request",
                "state must be at most 2048 bytes",
            ));
        }
        let login_hint = params.get("login_hint");
        if login_hint.is_some_and(|hint| {
            hint.len() > MAX_LOGIN_HINT_BYTES || hint.chars().any(char::is_control)
        }) {
            return Err(refuse(
                "invalid_request",
                "login_hint must be at most 256 bytes of printable characters",
            ));
        }
        // RFC 6749 §3.1: while DPoP is off the parameter is unknown, and
        // ignored.
        let dpop_jkt = match params.get("dpop_jkt") {
            Some(jkt) if self.dpop_enabled() => {
                if !super::dpop::is_thumbprint(jkt) {
                    return Err(refuse(
                        "invalid_request",
                        "dpop_jkt must be the base64url SHA-256 thumbprint of the DPoP key (RFC \
                         9449 section 10)",
                    ));
                }
                Some(jkt.to_owned())
            }
            _ => None,
        };
        let Some(login) = self.login_idp() else {
            return Err(BrowserOutcome::Page(ErrorPage::not_offered()));
        };
        if !idp_admits_client(login.idp(), &client.client_id) {
            return Err(refuse(
                "access_denied",
                "the enterprise IdP does not let this client sign users in",
            ));
        }
        let rememberable = matches!(client.consent, ConsentRule::Ask { rememberable: true })
            && client.kind != ClientKind::Dcr
            && self.interactive.consent.remember_days > 0
            && authorization_details.is_empty();
        Ok(Validated {
            request: AuthorizationRequest {
                client_id: client.client_id.clone(),
                client_kind: client.kind,
                client_name: client.name.clone(),
                redirect_uri: client.redirect.uri.clone(),
                redirect_trusted: client.redirect.trusted,
                redirect_loopback: matches!(client.redirect.kind, RedirectUriKind::Loopback(_)),
                state: state.map(str::to_owned),
                code_challenge: code_challenge.to_owned(),
                resource,
                scope,
                prompt: prompt.forwarded,
                login_hint: login_hint.map(str::to_owned),
                rememberable,
                dpop_jkt,
                authorization_details,
            },
            consent_forced: prompt.consent,
        })
    }

    /// The resource of an authorization request (RFC 8707): the one
    /// `resource` names, which this server must serve, else the default
    /// one. A trailing `/` is ignored.
    fn authorization_resource(&self, requested: &[&str]) -> Result<String, &'static str> {
        match requested {
            [] => Ok(self.resources[0].clone()),
            [one] => {
                let wanted = one.trim_end_matches('/');
                self.resources
                    .iter()
                    .find(|ours| ours.trim_end_matches('/') == wanted)
                    .cloned()
                    .ok_or("the requested resource does not identify this MCP server")
            }
            _ => Err("an authorization request names at most one resource"),
        }
    }

    /// The scopes an authorization request is granted: those it names
    /// that this server grants (`allowed_scopes`, else the protected
    /// resource's `scopes_supported`), each once, less `openid` and
    /// `offline_access`; when it names none, every grantable scope (RFC
    /// 6749 §3.3), or none for a request `with_details`, which says what it
    /// asks for in its authorization details. No scope at all is refused
    /// when `require_scope` is set.
    fn authorization_scope(
        &self,
        requested: Option<&str>,
        with_details: bool,
    ) -> Result<Vec<String>, &'static str> {
        let grantable: &[String] = self.allowed_scopes.as_deref().unwrap_or(&self.known_scopes);
        let asked: Vec<&str> = requested
            .unwrap_or_default()
            .split(' ')
            .filter(|scope| !scope.is_empty() && !PROTOCOL_SCOPES.contains(scope))
            .collect();
        let candidates: Vec<&str> = if asked.is_empty() && with_details {
            Vec::new()
        } else if asked.is_empty() {
            grantable.iter().map(String::as_str).collect()
        } else {
            asked
                .into_iter()
                .filter(|scope| grantable.iter().any(|ours| ours == scope))
                .collect()
        };
        let mut granted: Vec<String> = Vec::new();
        for scope in candidates {
            if !granted.iter().any(|kept| kept == scope) {
                granted.push(scope.to_owned());
            }
        }
        if granted.is_empty() && self.require_scope {
            return Err("none of the requested scopes can be granted");
        }
        Ok(granted)
    }

    /// An error response for `redirect_uri`: sent there when
    /// `may_redirect` (a trusted URI, or the user approved), else offered
    /// on a page as a link the user follows.
    fn refusal(
        &self,
        redirect_uri: &str,
        may_redirect: bool,
        state: Option<&str>,
        error: &'static str,
        description: &str,
    ) -> BrowserOutcome {
        let description = error_description(description);
        let mut params = vec![
            ("error", error),
            ("error_description", description.as_str()),
        ];
        if let Some(state) = state {
            params.push(("state", state));
        }
        params.push(("iss", self.issuer.as_str()));
        let location = with_response_params(redirect_uri, &params);
        if may_redirect {
            return BrowserOutcome::ErrorRedirect { location, error };
        }
        BrowserOutcome::Page(ErrorPage {
            status: ErrorPage::status_of(error),
            error,
            title: TITLE_REFUSED,
            message: format!("The application's request was refused: {description}."),
            return_to: Some(ReturnLink {
                host: url_host(redirect_uri).unwrap_or_default(),
                href: location,
            }),
        })
    }

    async fn consent_or_sign_in(
        &self,
        state: &InteractiveState,
        validated: Validated,
        client: &AuthorizeClient,
        cookies: &BrowserCookies,
    ) -> BrowserResponse {
        let Validated {
            request,
            consent_forced,
        } = validated;
        // The user sees what authorization details grant unless the
        // operator chose never to ask for this client.
        let skip = match client.consent {
            ConsentRule::Skip { explicit } => explicit || request.authorization_details.is_empty(),
            ConsentRule::Ask { .. } => false,
        };
        if !consent_forced && skip {
            return self.sign_in(state, &request, false).await;
        }
        if !consent_forced
            && request.rememberable
            && self.remembered(state, cookies, &request, now_unix())
        {
            record_consent(ConsentDecision::Remembered, request.client_kind);
            return self
                .sign_in(state, &request, true)
                .await
                .with_audit(BrowserAudit::consent(ConsentDecision::Remembered, &request));
        }
        self.consent_page(state, request, cookies)
    }

    /// The oldest approval time a remembered approval may have.
    fn remember_not_before(&self, now: u64) -> u64 {
        now.saturating_sub(u64::from(self.interactive.consent.remember_days) * SECS_PER_DAY)
    }

    /// Whether the browser's consent cookie holds a recent approval of
    /// this client, exact redirect URI, resource and every requested
    /// scope. A request for authorization details is never covered.
    fn remembered(
        &self,
        state: &InteractiveState,
        cookies: &BrowserCookies,
        request: &AuthorizationRequest,
        now: u64,
    ) -> bool {
        if !request.authorization_details.is_empty() {
            return false;
        }
        cookies
            .consent_memory
            .as_deref()
            .filter(|value| value.len() <= MAX_CONSENT_COOKIE_BYTES)
            .and_then(|value| state.open_value::<ConsentMemoryRecord>(CONSENT_MEMORY_LABEL, value))
            .is_some_and(|memory| {
                memory.covers(
                    &request.client_id,
                    &request.redirect_uri,
                    &request.resource,
                    &request.scope,
                    self.remember_not_before(now),
                )
            })
    }

    /// The consent cookie that remembers the approval of `request` beside
    /// the recent ones the browser's cookie holds, dropping the oldest to
    /// fit [`MAX_CONSENT_COOKIE_BYTES`]; `None` when the approval alone
    /// does not fit.
    pub(super) fn remember(
        &self,
        state: &InteractiveState,
        cookies: &BrowserCookies,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Option<String> {
        let mut memory = cookies
            .consent_memory
            .as_deref()
            .filter(|value| value.len() <= MAX_CONSENT_COOKIE_BYTES)
            .and_then(|value| state.open_value::<ConsentMemoryRecord>(CONSENT_MEMORY_LABEL, value))
            .unwrap_or_default();
        memory.forget_before(self.remember_not_before(now));
        memory.remember(ConsentApproval {
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            resource: request.resource.clone(),
            scopes: request.scope.clone(),
            approved_at: now,
        });
        loop {
            let sealed = state.seal_value(CONSENT_MEMORY_LABEL, &memory).ok()?;
            if sealed.len() <= MAX_CONSENT_COOKIE_BYTES {
                return Some(sealed);
            }
            if memory.approvals.len() <= 1 || !memory.forget_oldest() {
                return None;
            }
        }
    }

    /// The consent page for `request`, its request sealed into the form
    /// and bound to the browser's CSRF cookie, which is set, or kept when
    /// the browser has one, so pages open in several tabs stay valid.
    fn consent_page(
        &self,
        state: &InteractiveState,
        request: AuthorizationRequest,
        cookies: &BrowserCookies,
    ) -> BrowserResponse {
        let ttl = self.interactive.transaction_ttl_secs;
        let consent = ConsentRequest {
            purpose: TransactionPurpose::Authorize,
            exp: now_unix() + ttl,
            authorization: Some(request.clone()),
            link: None,
        };
        let form = match sealed_form(state, &consent, cookies) {
            Ok(form) => form,
            Err(response) => return response,
        };
        let descriptions = &self.interactive.consent.scope_descriptions;
        let page = ConsentPage {
            service_name: self.service_name(),
            client_name: request
                .client_name
                .clone()
                .unwrap_or_else(|| request.client_id.clone()),
            client_kind: request.client_kind,
            client_host: (request.client_kind == ClientKind::Cimd)
                .then(|| url_host(&request.client_id))
                .flatten(),
            redirect_uri: request.redirect_uri.clone(),
            loopback: request.redirect_loopback,
            resource: request.resource.clone(),
            scopes: request
                .scope
                .iter()
                .map(|scope| ScopeLine {
                    scope: scope.clone(),
                    description: descriptions.get(scope).cloned(),
                })
                .collect(),
            authorization_details: self.detail_lines(&request.authorization_details),
            idp_name: self
                .login_idp()
                .map(|login| login.display_name())
                .unwrap_or_default(),
            keeps_idp_sign_in: self.keeps_idp_sign_in(),
            form_action: self.endpoint(CONSENT_PATH),
            request: form.request,
            csrf_token: form.csrf_token,
        };
        BrowserResponse {
            cookies: vec![form.cookie],
            ..BrowserResponse::outcome(BrowserOutcome::Consent(Box::new(page)))
        }
    }

    /// Answer `POST /oauth/consent` with the consent `form` and the
    /// sign-in cookies the browser sent. The caller has checked the host,
    /// the client address's budget and that the form came from this
    /// server's page. The sealed request must open and be unexpired, the
    /// form token must match the browser's CSRF cookie, and the decision
    /// is taken once.
    pub async fn decide_consent(
        &self,
        form: &ConsentForm,
        cookies: &BrowserCookies,
    ) -> BrowserResponse {
        let Some(state) = self.sign_in_state() else {
            return BrowserResponse::page(ErrorPage::unavailable());
        };
        let now = now_unix();
        let decided = decided_form(state, form, cookies, now, |consent| {
            consent.purpose == TransactionPurpose::Authorize && consent.authorization.is_some()
        })
        .await;
        let (consent, decision) = match decided {
            Ok(decided) => decided,
            Err(response) => return response,
        };
        let Some(request) = consent.authorization else {
            return BrowserResponse::page(ErrorPage::expired());
        };
        record_consent(decision, request.client_kind);
        let audit = BrowserAudit::consent(decision, &request);
        // The CSRF cookie stays: the browser's other consent pages are
        // bound to it, and each page's request is taken once regardless.
        let mut changes = Vec::new();
        let mut response = match decision {
            ConsentDecision::Approved | ConsentDecision::Remembered => {
                if request.rememberable
                    && let Some(value) = self.remember(state, cookies, &request, now)
                {
                    changes.push(CookieChange::Set {
                        cookie: BrowserCookie::ConsentMemory,
                        value,
                        max_age_secs: u64::from(self.interactive.consent.remember_days)
                            * SECS_PER_DAY,
                    });
                }
                self.sign_in(state, &request, true).await
            }
            ConsentDecision::Denied => BrowserResponse::outcome(self.refusal(
                &request.redirect_uri,
                request.redirect_trusted,
                request.state.as_deref(),
                "access_denied",
                "the user denied the request",
            )),
        };
        changes.append(&mut response.cookies);
        response.cookies = changes;
        response.with_audit(audit)
    }

    /// Start the sign-in at the login IdP for `request`: claim the
    /// client's PKCE challenge once (RFC 9700 §2.1.1), store the
    /// transaction under a fresh `state`, `nonce` and PKCE verifier of the
    /// gateway's own, bind it to this browser with a cookie, and send the
    /// browser to the IdP with the client's `prompt` and `login_hint`.
    /// `consent_approved` records that the user approved the request, so an
    /// error may later go back to an untrusted redirect URI.
    async fn sign_in(
        &self,
        state: &InteractiveState,
        request: &AuthorizationRequest,
        consent_approved: bool,
    ) -> BrowserResponse {
        let redirect = match self
            .idp_redirect(request.prompt.as_deref(), request.login_hint.as_deref())
            .await
        {
            Ok(redirect) => redirect,
            Err(response) => return response,
        };
        let lifetime = Duration::from_secs(self.interactive.transaction_ttl_secs);
        match state
            .claim_once(
                &keys::pkce_seen(&request.client_id, &request.code_challenge),
                lifetime,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return BrowserResponse::outcome(self.refusal(
                    &request.redirect_uri,
                    request.redirect_trusted || consent_approved,
                    request.state.as_deref(),
                    "invalid_request",
                    "code_challenge reused: every authorization request needs a new one",
                ));
            }
            Err(error) => {
                tracing::error!(error = %error, "a PKCE challenge could not be recorded");
                return BrowserResponse::page(ErrorPage::unavailable());
            }
        }
        let transaction = TransactionRecord {
            purpose: TransactionPurpose::Authorize,
            client: Some(ClientSnapshot {
                client_id: request.client_id.clone(),
                kind: request.client_kind,
                name: request.client_name.clone(),
            }),
            redirect_uri: Some(request.redirect_uri.clone()),
            redirect_trusted: request.redirect_trusted,
            consent_approved,
            client_state: request.state.clone(),
            code_challenge: Some(request.code_challenge.clone()),
            resource: Some(request.resource.clone()),
            scope: request.scope.clone(),
            dpop_jkt: request.dpop_jkt.clone(),
            authorization_details: request.authorization_details.clone(),
            ..redirect.transaction(TransactionPurpose::Authorize)
        };
        self.send_to_idp(state, redirect, &transaction).await
    }

    /// The request that sends the browser to the login IdP with a fresh
    /// `state`, `nonce` and PKCE verifier of the gateway's own, and the
    /// binding cookie's value; a page when the IdP's endpoints are
    /// unavailable.
    pub(super) async fn idp_redirect(
        &self,
        prompt: Option<&str>,
        login_hint: Option<&str>,
    ) -> Result<IdpRedirect, BrowserResponse> {
        let Some(login) = self.login_idp() else {
            return Err(BrowserResponse::page(ErrorPage::not_offered()));
        };
        let metadata = login.metadata().await.map_err(|error| {
            tracing::warn!(
                idp = %login.issuer(),
                error = %error,
                "the login IdP's endpoints are unavailable; sign-in answers 503"
            );
            BrowserResponse::page(ErrorPage::idp_unavailable())
        })?;
        let (Ok(idp_state), Ok(nonce), Ok(verifier), Ok(binder)) = (
            random_token(),
            random_token(),
            random_token(),
            random_token(),
        ) else {
            tracing::error!("the operating system's random number generator failed");
            return Err(BrowserResponse::page(ErrorPage::unavailable()));
        };
        let url = login
            .authorization_url(
                &metadata,
                &IdpAuthorizationRequest {
                    state: &idp_state,
                    nonce: &nonce,
                    code_challenge: &s256_challenge(&verifier),
                    prompt,
                    login_hint,
                },
            )
            .map_err(|error| {
                tracing::warn!(
                    idp = %login.issuer(),
                    error = %error,
                    "the login IdP's authorization request cannot be built"
                );
                BrowserResponse::page(ErrorPage::idp_unavailable())
            })?;
        Ok(IdpRedirect {
            idp_issuer: login.issuer().to_owned(),
            idp_state,
            nonce,
            verifier,
            binder,
            url,
        })
    }

    /// Store `transaction` under the `state` of `redirect` and send the
    /// browser to the IdP, bound to it with the binding cookie.
    pub(super) async fn send_to_idp(
        &self,
        state: &InteractiveState,
        redirect: IdpRedirect,
        transaction: &TransactionRecord,
    ) -> BrowserResponse {
        let ttl = self.interactive.transaction_ttl_secs;
        match state
            .put_if_absent(
                &keys::transaction(&redirect.idp_state),
                transaction,
                Duration::from_secs(ttl),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!("a sign-in transaction collided with another; refusing it");
                return BrowserResponse::page(ErrorPage::unavailable());
            }
            Err(error) => {
                tracing::error!(error = %error, "a sign-in transaction could not be stored");
                return BrowserResponse::page(ErrorPage::unavailable());
            }
        }
        BrowserResponse {
            cookies: vec![CookieChange::Set {
                cookie: BrowserCookie::Transaction(TransactionTag::of_state(&redirect.idp_state)),
                value: redirect.binder,
                max_age_secs: ttl,
            }],
            ..BrowserResponse::outcome(BrowserOutcome::SignIn(redirect.url))
        }
    }
}

/// A sign-in at the login IdP about to start: its authorization request
/// and the secrets the transaction keeps. `Debug` shows none of them.
pub(super) struct IdpRedirect {
    idp_issuer: String,
    idp_state: String,
    nonce: String,
    verifier: String,
    binder: String,
    url: String,
}

impl IdpRedirect {
    /// The transaction for `purpose` this sign-in completes, with no
    /// client, redirect URI or scope.
    pub(super) fn transaction(&self, purpose: TransactionPurpose) -> TransactionRecord {
        TransactionRecord {
            purpose,
            client: None,
            redirect_uri: None,
            redirect_trusted: false,
            consent_approved: false,
            client_state: None,
            code_challenge: None,
            resource: None,
            scope: Vec::new(),
            idp_issuer: self.idp_issuer.clone(),
            nonce: SecretString::new(self.nonce.clone()),
            pkce_verifier: SecretString::new(self.verifier.clone()),
            binder_hash: binder_hash(&self.binder),
            created: now_unix(),
            link_id: None,
            dpop_jkt: None,
            authorization_details: AuthorizationDetails::default(),
        }
    }
}

impl std::fmt::Debug for IdpRedirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdpRedirect")
            .field("idp_issuer", &self.idp_issuer)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------

/// Why a callback ended as it did, for `mcpg_as_callback_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallbackReason {
    Completed,
    Malformed,
    UnknownState,
    Used,
    Binding,
    IdpChanged,
    IssuerMismatch,
    IssuerMissing,
    IdpError,
    CodeMissing,
    IdpUnavailable,
    IdpRefused,
    KeysUnavailable,
    IdTokenInvalid,
    Identity,
    Tenant,
    ClientNotAllowed,
    ClientRemoved,
    LinkExpired,
    LinkUsed,
    OtherUser,
    Store,
}

impl CallbackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "none",
            Self::Malformed => "malformed",
            Self::UnknownState => "unknown_state",
            Self::Used => "used",
            Self::Binding => "binding",
            Self::IdpChanged => "idp_changed",
            Self::IssuerMismatch => "iss_mismatch",
            Self::IssuerMissing => "iss_missing",
            Self::IdpError => "idp_error",
            Self::CodeMissing => "code_missing",
            Self::IdpUnavailable => "idp_unavailable",
            Self::IdpRefused => "idp_refused",
            Self::KeysUnavailable => "keys_unavailable",
            Self::IdTokenInvalid => "id_token_invalid",
            Self::Identity => "identity",
            Self::Tenant => "tenant",
            Self::ClientNotAllowed => "client_not_allowed",
            Self::ClientRemoved => "client_removed",
            Self::LinkExpired => "link_expired",
            Self::LinkUsed => "link_used",
            Self::OtherUser => "other_user",
            Self::Store => "store",
        }
    }
}

fn record_callback(outcome: &BrowserOutcome, reason: CallbackReason) {
    let outcome = match outcome {
        BrowserOutcome::CodeIssued(_) => "code_issued",
        BrowserOutcome::Done(_) => "connected",
        BrowserOutcome::Page(page) if page.status >= 500 => "failed",
        BrowserOutcome::ErrorRedirect { error, .. }
            if matches!(*error, "server_error" | "temporarily_unavailable") =>
        {
            "failed"
        }
        _ => "refused",
    };
    metrics::counter!(
        "mcpg_as_callback_total",
        "outcome" => outcome,
        "reason" => reason.as_str(),
    )
    .increment(1);
}

/// The error an MCP client receives for the `error` an IdP answered a
/// sign-in with: the user or the IdP declined, the IdP is briefly
/// unavailable, or anything else. The IdP's description is never passed
/// on.
fn client_error_for_idp_error(error: &str) -> &'static str {
    match error {
        "access_denied"
        | "login_required"
        | "interaction_required"
        | "consent_required"
        | "account_selection_required" => "access_denied",
        "temporarily_unavailable" => "temporarily_unavailable",
        _ => "server_error",
    }
}

/// The description an MCP client receives with `error` at the callback,
/// in words this server chose.
fn callback_description(error: &str) -> &'static str {
    match error {
        "access_denied" => "the sign-in at the enterprise IdP was declined or not completed",
        "temporarily_unavailable" => "the enterprise IdP cannot be reached right now; retry later",
        _ => "the sign-in at the enterprise IdP could not be completed",
    }
}

/// What the IdP's answer to a sign-in established, before the sign-in is
/// kept.
struct SignedIn<'a> {
    login: LoginIdp<'a>,
    /// The IdP token endpoint that redeemed the code, where the sign-in
    /// is refreshed.
    token_endpoint: String,
    tokens: IdpTokens,
    id_token: ValidatedIdToken,
    identity: MappedIdentity,
    principal: Principal,
    principal_key: String,
}

impl AuthorizationServer {
    /// Answer `GET /oauth/callback`, where the login IdP returns the
    /// browser with its raw `query`, and the binding cookies the browser
    /// sent. The caller has checked the host and the client address's
    /// budget. Once the transaction is taken, every answer removes its
    /// binding cookie.
    pub async fn callback(&self, query: &str, binders: &TransactionCookies) -> BrowserResponse {
        let (response, reason) = self.callback_response(query, binders).await;
        record_callback(&response.outcome, reason);
        response
    }

    async fn callback_response(
        &self,
        query: &str,
        binders: &TransactionCookies,
    ) -> (BrowserResponse, CallbackReason) {
        let Some(state) = self.sign_in_state() else {
            return (
                BrowserResponse::page(ErrorPage::unavailable()),
                CallbackReason::Store,
            );
        };
        let params = match QueryParams::parse(query, &[]) {
            Ok(params) => params,
            Err(page) => return (BrowserResponse::page(page), CallbackReason::Malformed),
        };
        let Some(idp_state) = params.get("state") else {
            return (
                BrowserResponse::page(ErrorPage::bad_request(
                    "The answer of the sign-in service carries no state. Start again from your \
                     application.",
                )),
                CallbackReason::Malformed,
            );
        };
        if !is_random_token(idp_state) {
            return (
                BrowserResponse::page(ErrorPage::sign_in_expired()),
                CallbackReason::UnknownState,
            );
        }
        let now = now_unix();
        let ttl = self.interactive.transaction_ttl_secs;
        let transaction = match state.get(&keys::transaction(idp_state)).await {
            Ok(Some(transaction)) if now <= transaction.created.saturating_add(ttl) => transaction,
            Ok(_) => {
                return (
                    BrowserResponse::page(ErrorPage::sign_in_expired()),
                    CallbackReason::UnknownState,
                );
            }
            Err(error) => {
                tracing::error!(error = %error, "a sign-in transaction could not be read");
                return (
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                );
            }
        };
        let tag = TransactionTag::of_state(idp_state);
        let (mut response, reason) = match state
            .claim_once(&keys::transaction_used(idp_state), Duration::from_secs(ttl))
            .await
        {
            Ok(true) => {
                // The used marker refuses a second answer; the sealed nonce
                // and verifier need not wait out their lifetime.
                let _ = state.delete(&keys::transaction(idp_state)).await;
                self.complete_sign_in(state, &params, &transaction, binders.get(tag), tag)
                    .await
            }
            Ok(false) => (
                BrowserResponse::page(ErrorPage::sign_in_expired()),
                CallbackReason::Used,
            ),
            Err(error) => {
                tracing::error!(error = %error, "a sign-in transaction could not be claimed");
                (
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                )
            }
        };
        response
            .cookies
            .push(CookieChange::Clear(BrowserCookie::Transaction(tag)));
        (response, reason)
    }

    /// The error `error` for the sign-in of `transaction`: to the client's
    /// redirect URI when it is trusted or the user approved the request,
    /// else a page, with a link back when there is a client to return to.
    fn callback_refusal(
        &self,
        transaction: &TransactionRecord,
        error: &'static str,
    ) -> BrowserOutcome {
        let description = callback_description(error);
        match (transaction.purpose, transaction.redirect_uri.as_deref()) {
            (TransactionPurpose::Authorize, Some(redirect_uri)) => self.refusal(
                redirect_uri,
                transaction.redirect_trusted || transaction.consent_approved,
                transaction.client_state.as_deref(),
                error,
                description,
            ),
            _ => BrowserOutcome::Page(ErrorPage {
                status: ErrorPage::status_of(error),
                error,
                title: TITLE_FAILED,
                message: format!("The sign-in did not complete: {description}."),
                return_to: None,
            }),
        }
    }

    /// The callback after its transaction was taken: the binding cookie,
    /// the IdP's `iss`, its error or code, the ID token and the user it
    /// names, then the stored IdP sign-in and what the transaction was for.
    async fn complete_sign_in(
        &self,
        state: &InteractiveState,
        params: &QueryParams,
        transaction: &TransactionRecord,
        binder: Option<&str>,
        tag: TransactionTag,
    ) -> (BrowserResponse, CallbackReason) {
        if !binder.is_some_and(|binder| ct_eq(&binder_hash(binder), &transaction.binder_hash)) {
            return (
                BrowserResponse::page(ErrorPage::other_browser()).with_audit(
                    BrowserAudit::CallbackRefused {
                        reason: "the browser does not hold the sign-in's binding cookie".to_owned(),
                    },
                ),
                CallbackReason::Binding,
            );
        }
        let link = match transaction.purpose {
            TransactionPurpose::Link => match self.pending_link(state, transaction).await {
                Ok(link) => Some(link),
                Err(refusal) => return refusal,
            },
            TransactionPurpose::Authorize | TransactionPurpose::Connect => None,
        };
        let Some(login) = self
            .login_idp()
            .filter(|login| login.issuer() == transaction.idp_issuer)
        else {
            return (
                BrowserResponse::page(ErrorPage::idp_changed()),
                CallbackReason::IdpChanged,
            );
        };
        if let Some(refusal) = self
            .check_response_issuer(&login, params, transaction)
            .await
        {
            return refusal;
        }
        if let Some(error) = params.get("error") {
            let error = client_error_for_idp_error(error);
            return (
                BrowserResponse::outcome(self.callback_refusal(transaction, error)),
                CallbackReason::IdpError,
            );
        }
        let Some(code) = params.get("code") else {
            return (
                BrowserResponse::page(ErrorPage::bad_request(
                    "The answer of the sign-in service carries no authorization code. Start again \
                     from your application.",
                )),
                CallbackReason::CodeMissing,
            );
        };
        let signed_in = match self.redeem_idp_code(login, code, transaction).await {
            Ok(signed_in) => signed_in,
            Err(refusal) => return refusal,
        };
        if let Some(ref link) = link {
            if link.record.principal != signed_in.principal_key {
                return self.link_of_another_user(&signed_in, link, tag);
            }
            if let Err(refusal) = self.claim_link(state, link).await {
                return refusal;
            }
        }
        let keep = self.keeps_idp_sign_in() || transaction.purpose != TransactionPurpose::Authorize;
        let (idp_session, superseded) = if keep {
            match self
                .store_idp_session(state, &signed_in, transaction.purpose)
                .await
            {
                Ok(stored) => {
                    if let Some(ref link) = link {
                        self.mark_link_stored(state, link).await;
                    }
                    stored
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "a signed-in user's IdP sign-in could not be stored; refusing the sign-in"
                    );
                    if let Some(ref link) = link {
                        self.unclaim_link(state, link).await;
                    }
                    return (
                        BrowserResponse::page(ErrorPage::unavailable()),
                        CallbackReason::Store,
                    );
                }
            }
        } else {
            (IdpSessionWrite::NotKept, None)
        };
        let (mut response, reason) = match transaction.purpose {
            TransactionPurpose::Authorize => {
                self.issue_code(state, &signed_in, transaction, idp_session, tag)
                    .await
            }
            TransactionPurpose::Connect | TransactionPurpose::Link => (
                BrowserResponse::outcome(BrowserOutcome::Done(NoticePage {
                    title: "Connected",
                    message: format!(
                        "Your {} sign-in is connected. Return to your application.",
                        signed_in.login.display_name()
                    ),
                }))
                .with_audit(self.login_audit(
                    &signed_in,
                    transaction,
                    None,
                    idp_session,
                    tag,
                )),
                CallbackReason::Completed,
            ),
        };
        response.superseded = superseded;
        response.link_completed = link.and_then(super::connect::PendingLink::completion);
        (response, reason)
    }

    /// Someone other than the user a link was offered to signed in through
    /// it: nothing is stored, and the refusal is audited.
    fn link_of_another_user(
        &self,
        signed_in: &SignedIn<'_>,
        link: &super::connect::PendingLink,
        tag: TransactionTag,
    ) -> (BrowserResponse, CallbackReason) {
        tracing::warn!(
            idp = %signed_in.login.issuer(),
            "a link was completed by another user than the one it was offered to; nothing is \
             stored"
        );
        (
            BrowserResponse::page(ErrorPage::another_user(&signed_in.login.display_name()))
                .with_audit(BrowserAudit::ConnectRefused(Box::new(
                    ConnectRefusedAudit {
                        idp: signed_in.login.issuer().to_owned(),
                        subject: signed_in.identity.subject.clone(),
                        principal_issuer: signed_in.principal.issuer.clone(),
                        auth_provider: signed_in.principal.auth_provider.clone(),
                        offered_to: link.record.principal.clone(),
                        client_id: link.record.client_id.clone(),
                        transaction: tag.as_str().to_owned(),
                    },
                ))),
            CallbackReason::OtherUser,
        )
    }

    /// RFC 9207 §2.4: an authorization response that names another issuer
    /// than the IdP the sign-in was sent to is refused, and so is one
    /// without `iss` from an IdP that says it always sends it. Neither is
    /// acted on, not even its `error`.
    async fn check_response_issuer(
        &self,
        login: &LoginIdp<'_>,
        params: &QueryParams,
        transaction: &TransactionRecord,
    ) -> Option<(BrowserResponse, CallbackReason)> {
        let refused = |reason: CallbackReason, text: &str| {
            Some((
                BrowserResponse::page(ErrorPage::wrong_issuer()).with_audit(
                    BrowserAudit::CallbackRefused {
                        reason: text.to_owned(),
                    },
                ),
                reason,
            ))
        };
        match params.get("iss") {
            Some(iss) if iss == login.issuer() => None,
            Some(_) => refused(
                CallbackReason::IssuerMismatch,
                "the authorization response names another issuer than the login IdP",
            ),
            None => match login.metadata().await {
                Ok(metadata) if metadata.authorization_response_iss_parameter_supported => refused(
                    CallbackReason::IssuerMissing,
                    "the authorization response carries no iss, which the login IdP always sends",
                ),
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(
                        idp = %login.issuer(),
                        error = %error,
                        "the login IdP's endpoints are unavailable; a sign-in cannot complete"
                    );
                    Some((
                        BrowserResponse::outcome(
                            self.callback_refusal(transaction, "temporarily_unavailable"),
                        ),
                        CallbackReason::IdpUnavailable,
                    ))
                }
            },
        }
    }

    /// Redeem the IdP's `code` with the transaction's verifier, believe
    /// the ID token only after every check, and read the user through the
    /// IdP's claim mappings. The user must be of the IdP's
    /// `required_tenant`, and the client still one the IdP admits.
    async fn redeem_idp_code<'a>(
        &self,
        login: LoginIdp<'a>,
        code: &str,
        transaction: &TransactionRecord,
    ) -> Result<SignedIn<'a>, (BrowserResponse, CallbackReason)> {
        let refuse = |error: &'static str, reason: CallbackReason| {
            (
                BrowserResponse::outcome(self.callback_refusal(transaction, error)),
                reason,
            )
        };
        let metadata = match login.metadata().await {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(
                    idp = %login.issuer(),
                    error = %error,
                    "the login IdP's endpoints are unavailable; a sign-in cannot complete"
                );
                return Err(refuse(
                    "temporarily_unavailable",
                    CallbackReason::IdpUnavailable,
                ));
            }
        };
        let tokens = match login
            .exchange_code(code, transaction.pkce_verifier.expose())
            .await
        {
            Ok(tokens) => tokens,
            Err(error) if error.is_transient() => {
                return Err(refuse(
                    "temporarily_unavailable",
                    CallbackReason::IdpUnavailable,
                ));
            }
            Err(error) => {
                let (response, reason) = refuse("server_error", CallbackReason::IdpRefused);
                return Err((
                    response.with_audit(BrowserAudit::CallbackRefused {
                        reason: format!("the login IdP did not redeem the code: {error}"),
                    }),
                    reason,
                ));
            }
        };
        let id_token = match login
            .validate_id_token(
                tokens.id_token.expose(),
                IdTokenCheck::SignIn {
                    nonce: transaction.nonce.expose(),
                },
            )
            .await
        {
            Ok(id_token) => id_token,
            Err(IdTokenError::KeysUnavailable) => {
                return Err(refuse(
                    "temporarily_unavailable",
                    CallbackReason::KeysUnavailable,
                ));
            }
            Err(IdTokenError::Invalid(reason)) => {
                tracing::warn!(
                    idp = %login.issuer(),
                    reason = %reason,
                    "the login IdP's ID token was refused"
                );
                let (response, why) = refuse("server_error", CallbackReason::IdTokenInvalid);
                return Err((
                    response.with_audit(BrowserAudit::CallbackRefused {
                        reason: format!("id_token_invalid: {reason}"),
                    }),
                    why,
                ));
            }
        };
        let idp = login.idp();
        let identity = match MappedIdentity::from_assertion(&idp.claim_mappings, &id_token.claims) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(
                    idp = %login.issuer(),
                    reason = %error.description,
                    "the login IdP's ID token names no user through its claim mappings"
                );
                let (response, reason) = refuse("server_error", CallbackReason::Identity);
                return Err((
                    response.with_audit(BrowserAudit::CallbackRefused {
                        reason: format!("the ID token names no user: {}", error.description),
                    }),
                    reason,
                ));
            }
        };
        if let Some(ref required) = idp.required_tenant
            && identity.tenant.as_ref() != Some(required)
        {
            let (response, reason) = refuse("access_denied", CallbackReason::Tenant);
            return Err((
                response.with_audit(BrowserAudit::CallbackRefused {
                    reason: "the ID token's tenant is not the one this enterprise IdP is trusted \
                             for"
                    .to_owned(),
                }),
                reason,
            ));
        }
        if let Some(ref client) = transaction.client {
            if !self.knows_client(&client.client_id) {
                return Err((
                    BrowserResponse::page(ErrorPage::client_removed()),
                    CallbackReason::ClientRemoved,
                ));
            }
            if !idp_admits_client(idp, &client.client_id) {
                return Err(refuse("access_denied", CallbackReason::ClientNotAllowed));
            }
        }
        let principal = Principal::of(idp, identity.tenant.as_deref());
        Ok(SignedIn {
            principal_key: principal.key(&identity.subject),
            principal,
            login,
            token_endpoint: metadata.token_endpoint.clone(),
            tokens,
            id_token,
            identity,
        })
    }

    /// Keep the user's IdP sign-in, sealed under their principal, in place
    /// of any earlier one: one per user, for every MCP client of theirs.
    /// The write is ordered after any refresh of the earlier one another
    /// request holds the lease for. Returns what was done, and the earlier
    /// refresh token to revoke when `idp_sessions.revoke_superseded` asks
    /// for it and the login IdP issued it, to the gateway's client there,
    /// for another subject. One of the same subject stays unrevoked: an
    /// IdP that revokes per user and client (Keycloak, PingFederate) would
    /// end the new sign-in with it.
    async fn store_idp_session(
        &self,
        state: &InteractiveState,
        signed_in: &SignedIn<'_>,
        purpose: TransactionPurpose,
    ) -> Result<(IdpSessionWrite, Option<SupersededSignIn>), StateError> {
        let login = signed_in.login;
        let key = keys::idp_session(&signed_in.principal_key);
        let lease = state
            .acquire_lease(
                &keys::idp_lease(&signed_in.principal_key),
                IDP_SESSION_LEASE_TTL,
                IDP_SESSION_LEASE_WAIT,
            )
            .await?;
        let written = async {
            let previous = state.get(&key).await?;
            let now = now_unix();
            let record = IdpSessionRecord {
                v: IDP_SESSION_RECORD_VERSION,
                issuer: login.issuer().to_owned(),
                client_id: login.client_id().to_owned(),
                token_endpoint: signed_in.token_endpoint.clone(),
                sub: signed_in.id_token.subject.clone(),
                refresh_token: signed_in.tokens.refresh_token.clone(),
                id_token: signed_in.tokens.id_token.clone(),
                id_token_exp: signed_in.id_token.expires_at,
                scope: signed_in
                    .tokens
                    .scope
                    .clone()
                    .unwrap_or_else(|| login.config().scopes.join(" ")),
                obtained_at: now,
                last_refreshed: now,
                origin: IdpSessionOrigin::of(purpose),
                generation: previous
                    .as_ref()
                    .map_or(1, |previous| previous.generation.saturating_add(1)),
            };
            state
                .put(
                    &key,
                    &record,
                    Duration::from_secs(self.interactive.idp_session_max_age_secs()),
                )
                .await?;
            Ok::<_, StateError>(previous)
        }
        .await;
        if let Some(ref lease) = lease {
            let _ = state.release_lease(lease).await;
        }
        let previous = match written {
            Ok(previous) => previous,
            Err(error) => {
                metrics::counter!(
                    "mcpg_as_idp_sessions_total", "op" => "store", "outcome" => "error"
                )
                .increment(1);
                return Err(error);
            }
        };
        let write = if previous.is_some() {
            IdpSessionWrite::Replaced
        } else {
            IdpSessionWrite::Stored
        };
        metrics::counter!(
            "mcpg_as_idp_sessions_total",
            "op" => if previous.is_some() { "replace" } else { "store" },
            "outcome" => "ok",
        )
        .increment(1);
        let superseded = previous.and_then(|previous| {
            let token = previous.refresh_token.clone()?;
            let revocable = previous.issuer == login.issuer()
                && previous.client_id == login.client_id()
                && previous.sub != signed_in.id_token.subject;
            let same_token = signed_in
                .tokens
                .refresh_token
                .as_ref()
                .is_some_and(|current| current.ct_eq(token.expose()));
            (self.interactive.idp_sessions.revoke_superseded && revocable && !same_token).then(
                || SupersededSignIn {
                    issuer: previous.issuer.clone(),
                    client_id: previous.client_id.clone(),
                    refresh_token: token,
                },
            )
        });
        Ok((write, superseded))
    }

    /// Issue the client its authorization code for the sign-in of
    /// `transaction`: a pending grant for the user, and the code bound to
    /// the client, the exact redirect URI, the PKCE challenge, the resource,
    /// the scopes and the DPoP key the request named. The code goes back
    /// with the client's `state` and this server's `iss` (RFC 9207 §2); the
    /// challenge never does.
    async fn issue_code(
        &self,
        state: &InteractiveState,
        signed_in: &SignedIn<'_>,
        transaction: &TransactionRecord,
        idp_session: IdpSessionWrite,
        tag: TransactionTag,
    ) -> (BrowserResponse, CallbackReason) {
        let (Some(client), Some(redirect_uri), Some(code_challenge), Some(resource)) = (
            transaction.client.as_ref(),
            transaction.redirect_uri.as_deref(),
            transaction.code_challenge.as_deref(),
            transaction.resource.as_deref(),
        ) else {
            tracing::error!("a sign-in transaction for a client names no client or redirect URI");
            return (
                BrowserResponse::page(ErrorPage::internal()),
                CallbackReason::Store,
            );
        };
        let (Ok(gid), Ok(code)) = (GrantId::generate(), random_token()) else {
            tracing::error!("the operating system's random number generator failed");
            return (
                BrowserResponse::page(ErrorPage::unavailable()),
                CallbackReason::Store,
            );
        };
        let code = Zeroizing::new(format!("{AUTHORIZATION_CODE_PREFIX}{code}"));
        let now = now_unix();
        let code_ttl = self.interactive.authorization_code_ttl_secs;
        let identity = &signed_in.identity;
        let grant = GrantRecord {
            status: GrantStatus::Pending,
            principal: signed_in.principal_key.clone(),
            identity: IdentitySnapshot {
                subject: identity.subject.clone(),
                idp: signed_in.login.issuer().to_owned(),
                tenant: identity.tenant.clone(),
                groups: identity.groups.clone(),
                roles: identity.roles.clone(),
                attributes: identity.attributes.clone(),
                email: signed_in
                    .id_token
                    .claims
                    .get("email")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                amr: identity.amr.clone(),
                auth_time: signed_in.id_token.auth_time,
            },
            client_id: client.client_id.clone(),
            client_kind: client.kind,
            scope: transaction.scope.clone(),
            resource: resource.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            issuer: self.issuer.clone(),
            abs_exp: now.saturating_add(self.interactive.refresh_tokens.absolute_ttl_secs),
            last_used: now,
            generation: 0,
            created: now,
            dpop_jkt: None,
            dpop_bound_generation: 0,
            authorization_details: transaction.authorization_details.clone(),
        };
        let record = CodeRecord {
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_owned(),
            code_challenge: code_challenge.to_owned(),
            resource: resource.to_owned(),
            scope: transaction.scope.clone(),
            gid: gid.clone(),
            exp: now.saturating_add(code_ttl),
            dpop_jkt: transaction.dpop_jkt.clone(),
            authorization_details: transaction.authorization_details.clone(),
        };
        let stored = async {
            state
                .put(
                    &keys::grant(&gid),
                    &grant,
                    Duration::from_secs(code_ttl.saturating_add(PENDING_GRANT_MARGIN_SECS)),
                )
                .await?;
            state
                .put_if_absent(&keys::code(&code), &record, Duration::from_secs(code_ttl))
                .await
        }
        .await;
        match stored {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!("an authorization code collided with another; refusing it");
                return (
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                );
            }
            Err(error) => {
                tracing::error!(error = %error, "an authorization code could not be stored");
                return (
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                );
            }
        }
        self.renew_registration(&client.client_id).await;
        let mut params = vec![("code", code.as_str())];
        if let Some(ref client_state) = transaction.client_state {
            params.push(("state", client_state.as_str()));
        }
        params.push(("iss", self.issuer.as_str()));
        let location = with_response_params(redirect_uri, &params);
        (
            BrowserResponse::outcome(BrowserOutcome::CodeIssued(location))
                .with_audit(self.login_audit(signed_in, transaction, Some(gid), idp_session, tag)),
            CallbackReason::Completed,
        )
    }

    fn login_audit(
        &self,
        signed_in: &SignedIn<'_>,
        transaction: &TransactionRecord,
        gid: Option<GrantId>,
        idp_session: IdpSessionWrite,
        tag: TransactionTag,
    ) -> BrowserAudit {
        BrowserAudit::Login(Box::new(LoginAudit {
            purpose: transaction.purpose,
            client_id: transaction
                .client
                .as_ref()
                .map(|client| client.client_id.clone()),
            client_kind: transaction.client.as_ref().map(|client| client.kind),
            idp: signed_in.login.issuer().to_owned(),
            subject: signed_in.identity.subject.clone(),
            principal_issuer: signed_in.principal.issuer.clone(),
            auth_provider: signed_in.principal.auth_provider.clone(),
            gid,
            resource: transaction.resource.clone(),
            scope: transaction.scope.clone(),
            authorization_details_types: detail_types(&transaction.authorization_details),
            idp_session,
            transaction: tag.as_str().to_owned(),
        }))
    }

    /// Revoke at the login IdP a refresh token the gateway no longer keeps,
    /// while that IdP and the gateway's client there are still the ones it
    /// was issued to. Best effort: a failure is logged and counted where
    /// the request is made.
    pub async fn revoke_superseded(&self, superseded: SupersededSignIn) {
        let Some(login) = self.login_idp().filter(|login| {
            login.issuer() == superseded.issuer && login.client_id() == superseded.client_id
        }) else {
            return;
        };
        if let Ok(RevokeOutcome::Revoked) = login
            .revoke_refresh_token(superseded.refresh_token.expose())
            .await
        {
            tracing::debug!(
                idp = %login.issuer(),
                "a replaced IdP refresh token was revoked at the login IdP"
            );
        }
    }
}
