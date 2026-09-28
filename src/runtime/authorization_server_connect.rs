//! Storing a user's IdP sign-in for federations without an MCP client's
//! sign-in, and the links that ask a caller to store it.
//!
//! `GET /oauth/connect` shows a page that asks the user to connect their
//! IdP sign-in, and `POST /oauth/connect` takes the decision under the
//! same form token and single use as consent, then sends the browser to
//! the login IdP. The callback stores the sign-in under the principal the
//! ID token names, so a user stores one only for themselves.
//!
//! A federated call whose caller has no stored sign-in may answer with a
//! URL-mode elicitation (MCP Elicitation, `2025-11-25` and `2026-07-28`):
//! the link `/oauth/connect?e=<id>`, offered to that caller only. The id is
//! random and names nobody (Safe URL Handling); the link record binds it to
//! the caller's principal, MCP client and session. The callback stores
//! nothing unless the user who signed in is that principal, and completes
//! a link once (Elicitation, Phishing). The `2025-11-25` session that
//! offered a link is told when it completes
//! (`notifications/elicitation/complete`). On `2026-07-28` the retry
//! carries a sealed `requestState` that names the link, bound to the caller
//! and the tool, and waits a short while for the link to complete.
//!
//! Nothing here logs a link id.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::interactive::{
    BrowserCookies, BrowserOutcome, BrowserResponse, CONNECT_PATH, CallbackReason, ConsentDecision,
    ConsentForm, ConsentRequest, ErrorPage, NoticePage, QueryParams, decided_form, is_random_token,
    sealed_form,
};
use super::state::{
    InteractiveState, LinkRecord, LinkRefRecord, Marker, StateError, StateRecord,
    TransactionPurpose, TransactionRecord, keys, random_token,
};
use super::{AuthorizationServer, now_unix};

/// Query parameter of `/oauth/connect` that names a link.
pub const LINK_PARAMETER: &str = "e";
/// Prefix of a `2026-07-28` `requestState` that names a link, beside the
/// pipeline codec's `c.` and `h.`.
pub const LINK_REQUEST_STATE_PREFIX: &str = "l.";
/// The key of the URL elicitation in `InputRequiredResult.inputRequests`.
pub const LINK_INPUT_KEY: &str = "connect_sign_in";
/// Longest a retry waits for the link it names to complete.
pub const LINK_RESUME_WAIT: Duration = Duration::from_secs(10);
/// How often a waiting retry looks for the link's completion.
const LINK_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Label a link's `requestState` is sealed under.
const LINK_STATE_LABEL: &str = "link_state";
/// A link offered again leaves the user at least this long to complete it;
/// one closer to its expiry is replaced by a new one.
const MIN_RESUMED_LINK_SECS: u64 = 60;
/// How long the mark of a completed link outlives the link.
const LINK_DONE_MARGIN_SECS: u64 = 60;
/// Most new links one principal is offered per link lifetime
/// (`transaction_ttl_secs`), across replicas; a pending link offered again
/// does not count.
pub const MAX_NEW_LINKS_PER_PRINCIPAL: i64 = 20;

/// The page that asks the user to store their IdP sign-in.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectPage {
    /// The heading: `consent.service_name`, or the issuer's host.
    pub service_name: String,
    /// The login IdP's name.
    pub idp_name: String,
    /// Whether an MCP client offered the page to one user, as a link.
    pub link: bool,
    /// Where the form posts: the connect endpoint under the issuer.
    pub form_action: String,
    /// The sealed request (`req`).
    pub request: String,
    /// The form token (`csrf`).
    pub csrf_token: String,
}

impl std::fmt::Debug for ConnectPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectPage")
            .field("idp_name", &self.idp_name)
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

/// A completed link the MCP session that offered it is told of, by the id
/// its elicitation carried.
#[derive(Clone, PartialEq, Eq)]
pub struct CompletedLink {
    pub session_id: String,
    pub elicitation_id: String,
}

impl CompletedLink {
    /// `notifications/elicitation/complete` (MCP `2025-11-25`).
    pub fn notification(&self) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": { "elicitationId": self.elicitation_id },
        })
    }
}

impl std::fmt::Debug for CompletedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedLink").finish_non_exhaustive()
    }
}

/// A link offered to a caller.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectLink {
    /// The link id, which the `2025-11-25` elicitation carries as its
    /// `elicitationId`.
    pub id: String,
    /// `/oauth/connect?e=<id>` under the issuer.
    pub url: String,
    /// Until when it may be completed, in Unix seconds.
    pub expires_at: u64,
    /// The login IdP's name.
    pub idp_name: String,
    /// Whether it is a link offered to the caller before.
    pub resumed: bool,
}

impl std::fmt::Debug for ConnectLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectLink")
            .field("expires_at", &self.expires_at)
            .field("resumed", &self.resumed)
            .finish_non_exhaustive()
    }
}

/// Who a link is for.
#[derive(Debug, Clone, Copy)]
pub struct LinkOffer<'a> {
    /// The principal key of the caller, the only user who may complete it.
    pub principal: &'a str,
    /// The MCP client the caller uses, when its token names one.
    pub client_id: Option<&'a str>,
    /// The MCP session the link is offered on.
    pub session_id: Option<&'a str>,
    /// Whether that session is told when the link completes.
    pub notify: bool,
    /// A link offered to the caller for the same request, offered again
    /// while it is pending.
    pub resume: Option<&'a str>,
}

/// Why no link was offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// No login IdP, or the connect page is off.
    NotOffered,
    /// The principal was offered as many new links as one link lifetime
    /// allows.
    Limited,
    /// The store cannot be used now.
    Unavailable(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOffered => f.write_str("this gateway offers no connect page"),
            Self::Limited => f.write_str("the user was offered as many new links as allowed"),
            Self::Unavailable(reason) => write!(f, "no link can be offered now: {reason}"),
        }
    }
}

/// What became of a link a retry waited for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// The user completed it, and their sign-in is stored.
    Completed,
    /// The user has yet to complete it, or their sign-in is being stored.
    Pending,
    /// It expired, or it is not a link offered to this caller.
    Gone,
}

/// What the `requestState` of a retry names for its caller and tool.
/// `Debug` does not show the link id.
#[derive(Clone, PartialEq, Eq)]
pub enum LinkStateCheck {
    /// The link, which may still be completed.
    Valid(String),
    /// A link offered to this caller for this tool that expired: the call
    /// runs again, and offers a new link when it still needs one.
    Expired,
    /// It does not open under the state keys, or names another caller or
    /// tool.
    Refused,
}

impl std::fmt::Debug for LinkStateCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Valid(_) => "Valid",
            Self::Expired => "Expired",
            Self::Refused => "Refused",
        })
    }
}

/// The `requestState` of a `2026-07-28` result that offers a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LinkRequestState {
    link: String,
    principal: String,
    tool: String,
    exp: u64,
}

impl StateRecord for LinkRequestState {}

/// A link a callback completes.
pub(super) struct PendingLink {
    pub(super) id: String,
    pub(super) record: LinkRecord,
}

impl PendingLink {
    /// The session to tell of the completion, when the link asked for it.
    pub(super) fn completion(self) -> Option<CompletedLink> {
        let session_id = self.record.session_id.filter(|_| self.record.notify)?;
        Some(CompletedLink {
            session_id,
            elicitation_id: self.id,
        })
    }
}

impl std::fmt::Debug for PendingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLink").finish_non_exhaustive()
    }
}

impl ErrorPage {
    /// 400: a link that expired, was completed, or never existed.
    pub(super) fn link_expired() -> Self {
        Self::new(
            400,
            "invalid_request",
            "This link expired or was already used",
            "This link expired or was already used. Retry the request in your application to \
             get a new one.",
        )
    }

    /// 403: someone other than the user a link was made for signed in.
    pub(super) fn another_user(idp_name: &str) -> Self {
        Self {
            message: format!(
                "You signed in to {idp_name} as another user than the one this link was made \
                 for, so nothing was stored. Retry the request in your application, then sign \
                 in as the user you use there."
            ),
            ..Self::new(403, "access_denied", "Signed in as another user", "")
        }
    }
}

fn record_connect(purpose: TransactionPurpose, outcome: &'static str) {
    metrics::counter!(
        "mcpg_as_connect_total",
        "purpose" => purpose.as_str(),
        "outcome" => outcome,
    )
    .increment(1);
}

impl AuthorizationServer {
    /// Whether callers are offered links: a trusted IdP signs users in,
    /// the connect page is on, and the state store can be used.
    pub fn offers_links(&self) -> bool {
        self.login_idp().is_some()
            && self.interactive.idp_sessions.connect_page
            && self.sign_in_state().is_some()
    }

    /// How long the retry of a request that offered a link waits for it.
    pub fn link_resume_wait(&self) -> Duration {
        self.link_resume_wait
    }

    fn link_url(&self, id: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(LINK_PARAMETER, id)
            .finish();
        format!("{}?{query}", self.endpoint(CONNECT_PATH))
    }

    /// A link for the caller `offer` names to store their IdP sign-in: the
    /// link it resumes, or else the one last offered to the principal on
    /// the same session, while that is pending, was offered to the same
    /// principal and leaves time to complete it; else a new one that lives
    /// as long as a sign-in transaction, while the principal has new links
    /// left this lifetime.
    pub async fn offer_link(&self, offer: LinkOffer<'_>) -> Result<ConnectLink, LinkError> {
        if !self.interactive.idp_sessions.connect_page {
            return Err(LinkError::NotOffered);
        }
        let Some(login) = self.login_idp() else {
            return Err(LinkError::NotOffered);
        };
        let Some(state) = self.sign_in_state() else {
            return Err(LinkError::Unavailable(
                "the sign-in state store is unavailable".to_owned(),
            ));
        };
        let idp_name = login.display_name();
        let now = now_unix();
        let unavailable = |error: StateError| LinkError::Unavailable(error.to_string());
        let notify = offer.notify && offer.session_id.is_some();
        let by_session = keys::pending_link(
            offer.principal,
            offer.session_id.unwrap_or_default(),
            notify,
        );
        let last_offered = match offer.resume.filter(|id| is_random_token(id)) {
            Some(resume) => Some(resume.to_owned()),
            None => state
                .get(&by_session)
                .await
                .map_err(unavailable)?
                .map(|pointer| pointer.link),
        };
        if let Some(id) = last_offered {
            let record = self
                .pending_link_record(state, &id, now.saturating_add(MIN_RESUMED_LINK_SECS))
                .await
                .map_err(unavailable)?;
            if let Some(record) = record.filter(|record| record.principal == offer.principal) {
                return Ok(ConnectLink {
                    url: self.link_url(&id),
                    id,
                    expires_at: record.exp,
                    idp_name,
                    resumed: true,
                });
            }
        }
        let ttl = self.interactive.transaction_ttl_secs.max(1);
        let rate = keys::link_rate(offer.principal, now / ttl);
        let taken = state
            .incr(&rate, 1, Some(Duration::from_secs(ttl.saturating_mul(2))))
            .await
            .map_err(unavailable)?;
        if taken > MAX_NEW_LINKS_PER_PRINCIPAL {
            let _ = state.incr(&rate, -1, None).await;
            return Err(LinkError::Limited);
        }
        let id = random_token().map_err(unavailable)?;
        let record = LinkRecord {
            principal: offer.principal.to_owned(),
            client_id: offer.client_id.map(str::to_owned),
            session_id: offer.session_id.map(str::to_owned),
            notify,
            exp: now.saturating_add(ttl),
        };
        let lifetime = Duration::from_secs(ttl);
        let stored = match state
            .put_if_absent(&keys::link(&id), &record, lifetime)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(LinkError::Unavailable(
                "a new link collided with another".to_owned(),
            )),
            Err(error) => Err(unavailable(error)),
        };
        if let Err(error) = stored {
            let _ = state.incr(&rate, -1, None).await;
            return Err(error);
        }
        let pointer = LinkRefRecord { link: id.clone() };
        if let Err(error) = state.put(&by_session, &pointer, lifetime).await {
            tracing::warn!(
                error = %error,
                "a new link could not be recorded for its session; a retry is offered another"
            );
        }
        Ok(ConnectLink {
            url: self.link_url(&id),
            id,
            expires_at: record.exp,
            idp_name,
            resumed: false,
        })
    }

    /// The link `id` while it may still be completed at `at`: offered,
    /// unexpired and not completed.
    async fn pending_link_record(
        &self,
        state: &InteractiveState,
        id: &str,
        at: u64,
    ) -> Result<Option<LinkRecord>, StateError> {
        if !is_random_token(id) {
            return Ok(None);
        }
        let Some(record) = state
            .get(&keys::link(id))
            .await?
            .filter(|record| record.exp > at)
        else {
            return Ok(None);
        };
        if state.exists(&keys::link_done(id)).await? {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// The `requestState` of a `2026-07-28` result that offers the link
    /// `link_id`, which expires at `expires_at`, to `principal` for the
    /// tool `tool`: sealed under the state keys, and valid while the link
    /// is.
    pub fn link_request_state(
        &self,
        link_id: &str,
        expires_at: u64,
        principal: &str,
        tool: &str,
    ) -> Option<String> {
        let state = self.sign_in_state()?;
        let sealed = state
            .seal_value(
                LINK_STATE_LABEL,
                &LinkRequestState {
                    link: link_id.to_owned(),
                    principal: principal.to_owned(),
                    tool: tool.to_owned(),
                    exp: expires_at,
                },
            )
            .ok()?;
        Some(format!("{LINK_REQUEST_STATE_PREFIX}{sealed}"))
    }

    /// What a `requestState` names for `principal` and the tool `tool`:
    /// the link, when it opens under the state keys and was sealed for
    /// them; that the link expired, when it did; else a refusal, as the
    /// client may have altered it, or present it for another user or
    /// request.
    pub fn open_link_request_state(
        &self,
        request_state: &str,
        principal: &str,
        tool: &str,
    ) -> LinkStateCheck {
        let opened = request_state
            .strip_prefix(LINK_REQUEST_STATE_PREFIX)
            .and_then(|sealed| {
                self.sign_in_state()?
                    .open_value::<LinkRequestState>(LINK_STATE_LABEL, sealed)
            });
        match opened {
            Some(opened) if opened.principal == principal && opened.tool == tool => {
                if opened.exp > now_unix() {
                    LinkStateCheck::Valid(opened.link)
                } else {
                    LinkStateCheck::Expired
                }
            }
            _ => LinkStateCheck::Refused,
        }
    }

    /// Wait up to `wait` for the link `id` offered to `principal` to
    /// complete. A store failure ends the wait as pending.
    pub async fn await_link(&self, id: &str, principal: &str, wait: Duration) -> LinkStatus {
        let Some(state) = self.sign_in_state() else {
            return LinkStatus::Gone;
        };
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match self.link_status(state, id, principal).await {
                Ok(LinkStatus::Pending) => {}
                Ok(status) => return status,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "a link's completion could not be read; the retry goes ahead"
                    );
                    return LinkStatus::Pending;
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return LinkStatus::Pending;
            }
            tokio::time::sleep(LINK_POLL_INTERVAL.min(deadline - now)).await;
        }
    }

    async fn link_status(
        &self,
        state: &InteractiveState,
        id: &str,
        principal: &str,
    ) -> Result<LinkStatus, StateError> {
        if !is_random_token(id) {
            return Ok(LinkStatus::Gone);
        }
        match state.get(&keys::link(id)).await? {
            Some(record) if record.principal == principal => {
                if state.exists(&keys::link_stored(id)).await? {
                    Ok(LinkStatus::Completed)
                } else if record.exp > now_unix() {
                    Ok(LinkStatus::Pending)
                } else {
                    Ok(LinkStatus::Gone)
                }
            }
            _ => Ok(LinkStatus::Gone),
        }
    }

    /// Answer `GET /oauth/connect` with its raw `query` and the sign-in
    /// cookies the browser sent: the page that asks the user to store
    /// their IdP sign-in, for the link `e` names when it does. The caller
    /// has checked the host and the client address's budget.
    pub async fn connect(&self, query: &str, cookies: &BrowserCookies) -> BrowserResponse {
        let (response, purpose) = self.connect_page(query, cookies).await;
        let outcome = match response.outcome {
            BrowserOutcome::Connect(_) => "shown",
            _ => "refused",
        };
        record_connect(purpose, outcome);
        response
    }

    async fn connect_page(
        &self,
        query: &str,
        cookies: &BrowserCookies,
    ) -> (BrowserResponse, TransactionPurpose) {
        let purpose_of = |link: Option<&str>| match link {
            Some(_) => TransactionPurpose::Link,
            None => TransactionPurpose::Connect,
        };
        if !self.interactive.idp_sessions.connect_page {
            return (
                BrowserResponse::page(ErrorPage::not_offered()),
                TransactionPurpose::Connect,
            );
        }
        let Some(state) = self.sign_in_state() else {
            return (
                BrowserResponse::page(ErrorPage::unavailable()),
                TransactionPurpose::Connect,
            );
        };
        let params = match QueryParams::parse(query, &[]) {
            Ok(params) => params,
            Err(page) => return (BrowserResponse::page(page), TransactionPurpose::Connect),
        };
        let link = params.get(LINK_PARAMETER);
        let purpose = purpose_of(link);
        let now = now_unix();
        let lifetime_end = now.saturating_add(self.interactive.transaction_ttl_secs);
        let exp = match link {
            None => lifetime_end,
            Some(id) => match self.pending_link_record(state, id, now).await {
                Ok(Some(record)) => record.exp.min(lifetime_end),
                Ok(None) => return (BrowserResponse::page(ErrorPage::link_expired()), purpose),
                Err(error) => {
                    tracing::error!(error = %error, "a link could not be read");
                    return (BrowserResponse::page(ErrorPage::unavailable()), purpose);
                }
            },
        };
        let consent = ConsentRequest {
            purpose,
            exp,
            authorization: None,
            link: link.map(str::to_owned),
        };
        let form = match sealed_form(state, &consent, cookies) {
            Ok(form) => form,
            Err(response) => return (response, purpose),
        };
        let page = ConnectPage {
            service_name: self.service_name(),
            idp_name: self
                .login_idp()
                .map(|login| login.display_name())
                .unwrap_or_default(),
            link: link.is_some(),
            form_action: self.endpoint(CONNECT_PATH),
            request: form.request,
            csrf_token: form.csrf_token,
        };
        (
            BrowserResponse {
                cookies: vec![form.cookie],
                ..BrowserResponse::outcome(BrowserOutcome::Connect(Box::new(page)))
            },
            purpose,
        )
    }

    /// Answer `POST /oauth/connect` with the page's `form` and the sign-in
    /// cookies the browser sent. The caller has checked the host, the
    /// client address's budget and that the form came from this server's
    /// page. As for consent, the sealed request must open and be
    /// unexpired, the form token must match the browser's CSRF cookie, and
    /// the decision is taken once. An approval sends the browser to the
    /// login IdP, while a link it completes is still pending.
    pub async fn decide_connect(
        &self,
        form: &ConsentForm,
        cookies: &BrowserCookies,
    ) -> BrowserResponse {
        if !self.interactive.idp_sessions.connect_page {
            return BrowserResponse::page(ErrorPage::not_offered());
        }
        let Some(state) = self.sign_in_state() else {
            return BrowserResponse::page(ErrorPage::unavailable());
        };
        let now = now_unix();
        let decided = decided_form(state, form, cookies, now, |consent| {
            consent.authorization.is_none()
                && match consent.purpose {
                    TransactionPurpose::Connect => consent.link.is_none(),
                    TransactionPurpose::Link => consent.link.is_some(),
                    TransactionPurpose::Authorize => false,
                }
        })
        .await;
        let (consent, decision) = match decided {
            Ok(decided) => decided,
            Err(response) => return response,
        };
        if decision == ConsentDecision::Denied {
            record_connect(consent.purpose, "denied");
            return BrowserResponse::outcome(BrowserOutcome::Done(NoticePage {
                title: "Not connected",
                message: "Nothing was stored. You can close this page.".to_owned(),
            }));
        }
        if let Some(ref id) = consent.link {
            match self.pending_link_record(state, id, now).await {
                Ok(Some(_)) => {}
                Ok(None) => return BrowserResponse::page(ErrorPage::link_expired()),
                Err(error) => {
                    tracing::error!(error = %error, "a link could not be read");
                    return BrowserResponse::page(ErrorPage::unavailable());
                }
            }
        }
        record_connect(consent.purpose, "approved");
        let redirect = match self.idp_redirect(None, None).await {
            Ok(redirect) => redirect,
            Err(response) => return response,
        };
        let transaction = TransactionRecord {
            link_id: consent.link,
            ..redirect.transaction(consent.purpose)
        };
        self.send_to_idp(state, redirect, &transaction).await
    }

    /// The link a callback of `transaction` completes, while it is
    /// pending; read before the IdP is asked to redeem its code.
    pub(super) async fn pending_link(
        &self,
        state: &InteractiveState,
        transaction: &TransactionRecord,
    ) -> Result<PendingLink, (BrowserResponse, CallbackReason)> {
        let expired = || {
            (
                BrowserResponse::page(ErrorPage::link_expired()),
                CallbackReason::LinkExpired,
            )
        };
        let Some(id) = transaction.link_id.as_deref() else {
            return Err(expired());
        };
        match self.pending_link_record(state, id, now_unix()).await {
            Ok(Some(record)) => Ok(PendingLink {
                id: id.to_owned(),
                record,
            }),
            Ok(None) => Err(expired()),
            Err(error) => {
                tracing::error!(error = %error, "a link could not be read");
                Err((
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                ))
            }
        }
    }

    /// Complete `link` once, across replicas.
    pub(super) async fn claim_link(
        &self,
        state: &InteractiveState,
        link: &PendingLink,
    ) -> Result<(), (BrowserResponse, CallbackReason)> {
        let lifetime = link
            .record
            .exp
            .saturating_sub(now_unix())
            .saturating_add(LINK_DONE_MARGIN_SECS);
        match state
            .claim_once(&keys::link_done(&link.id), Duration::from_secs(lifetime))
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err((
                BrowserResponse::page(ErrorPage::link_expired()),
                CallbackReason::LinkUsed,
            )),
            Err(error) => {
                tracing::error!(error = %error, "a link's completion could not be recorded");
                Err((
                    BrowserResponse::page(ErrorPage::unavailable()),
                    CallbackReason::Store,
                ))
            }
        }
    }

    /// Record that the sign-in `link` completed is stored: what a retry
    /// waiting for the link reads as its completion. The completion claim
    /// comes before the sign-in is stored, so it cannot tell.
    pub(super) async fn mark_link_stored(&self, state: &InteractiveState, link: &PendingLink) {
        let lifetime = link
            .record
            .exp
            .saturating_sub(now_unix())
            .saturating_add(LINK_DONE_MARGIN_SECS);
        if let Err(error) = state
            .put(
                &keys::link_stored(&link.id),
                &Marker::now(),
                Duration::from_secs(lifetime),
            )
            .await
        {
            tracing::warn!(
                error = %error,
                "a link's stored sign-in could not be recorded; a retry waiting for it goes ahead \
                 when its wait ends"
            );
        }
    }

    /// Release the completion of `link`, whose sign-in could not be
    /// stored, so the user can use it again.
    pub(super) async fn unclaim_link(&self, state: &InteractiveState, link: &PendingLink) {
        if let Err(error) = state.unclaim(&keys::link_done(&link.id)).await {
            tracing::warn!(error = %error, "a link's completion could not be released");
        }
    }
}
