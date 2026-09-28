//! The caller's stored enterprise IdP sign-in as the RFC 8693 subject token
//! of an `oauth_impersonation` federation (`upstream.auth.subject_token:
//! idp_refresh_token` or `idp_id_token`).
//!
//! The engine reads the stored token of the caller's principal from an
//! [`IdpSessionSource`] and hands it to the federation's credential issuer
//! under the attributes of [`vault_identity`], which name the only token
//! endpoint and client it may be presented to. The token is never logged,
//! audited or returned to a client.
//!
//! A caller with no stored sign-in is refused before any request. When the
//! request may answer with a URL-mode elicitation ([`ConnectLinkSlot`]),
//! the caller is also offered a link that stores their sign-in, bound to
//! their principal: the MCP layer returns it, and the caller retries.

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::credential::{
    SUBJECT_TOKEN_ATTRIBUTE, SUBJECT_TOKEN_BINDING_ATTRIBUTE, SUBJECT_TOKEN_SOURCE_ATTRIBUTE,
    SUBJECT_TOKEN_SOURCE_IDP_VAULT,
};
use mcpg_plugin_protocol::types::PluginIdentity;

use crate::config::federation::SubjectToken;
use crate::runtime::RequestIdentity;
use crate::runtime::authorization_server::connect::{ConnectLink, LinkError, LinkOffer};
use crate::runtime::authorization_server::vault::{
    IdpSubjectToken, SubjectTokenKind, VaultSubjectToken,
};

/// Prefix of every identity attribute the engine sets on the caller it
/// hands a credential issuer; a caller attribute with it is dropped.
pub(crate) const SUBJECT_ATTRIBUTE_PREFIX: &str = SUBJECT_TOKEN_ATTRIBUTE;
/// RFC 8693 type of the subject token, overriding the issuer's configured
/// `subject_token_type`.
pub(crate) const SUBJECT_TOKEN_TYPE_ATTRIBUTE: &str = "subject_token_type";
/// The IdP that issued a vault subject token.
pub(crate) const SUBJECT_TOKEN_ISSUER_ATTRIBUTE: &str = "subject_token_issuer";
/// The token endpoint that issued a vault subject token, the only one it
/// may be presented to.
pub(crate) const SUBJECT_TOKEN_ENDPOINT_ATTRIBUTE: &str = "subject_token_endpoint";
/// The client a vault subject token was issued to, the only one that may
/// present it.
pub(crate) const SUBJECT_TOKEN_CLIENT_ID_ATTRIBUTE: &str = "subject_token_client_id";

/// Every attribute [`vault_identity`] sets.
pub(crate) const VAULT_ATTRIBUTES: [&str; 7] = [
    SUBJECT_TOKEN_ATTRIBUTE,
    SUBJECT_TOKEN_TYPE_ATTRIBUTE,
    SUBJECT_TOKEN_SOURCE_ATTRIBUTE,
    SUBJECT_TOKEN_ISSUER_ATTRIBUTE,
    SUBJECT_TOKEN_ENDPOINT_ATTRIBUTE,
    SUBJECT_TOKEN_CLIENT_ID_ATTRIBUTE,
    SUBJECT_TOKEN_BINDING_ATTRIBUTE,
];

/// Where the engine finds the IdP sign-in the gateway keeps for each user:
/// the embedded authorization server, whose interactive sign-in stores it.
#[async_trait]
pub(crate) trait IdpSessionSource: Send + Sync {
    /// The stored IdP token of the user whose principal key is `principal`.
    async fn subject_token(&self, principal: &str, kind: SubjectTokenKind) -> IdpSubjectToken;

    /// The page where a signed-in user stores their IdP sign-in once, when
    /// this gateway serves it.
    fn connect_url(&self) -> Option<String>;

    /// The issuer of the trusted IdP users sign in through.
    fn login_issuer(&self) -> Option<String>;

    /// Whether a sign-in through the login IdP is stored under the
    /// principal namespace of a verified caller that reports
    /// `auth_provider` and `issuer`: only such a caller can present one.
    fn stores_sign_in_for(&self, auth_provider: &str, issuer: &str) -> bool;

    /// A link that stores the sign-in of the caller `offer` names, which
    /// only that caller can complete.
    async fn offer_link(&self, offer: LinkOffer<'_>) -> Result<ConnectLink, LinkError>;
}

/// A URL-mode elicitation (MCP Elicitation): the link that stores the
/// caller's sign-in, and why they are asked to open it. `Debug` shows
/// neither the id nor the URL.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UrlElicitation {
    /// The link id: the `elicitationId` of `2025-11-25`.
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) message: String,
    /// Until when the link may be completed, in Unix seconds.
    pub(crate) expires_at: u64,
}

impl std::fmt::Debug for UrlElicitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlElicitation")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a request may do about a caller with no stored sign-in, and the
/// link it offered. One per request, shared by the clones of its context.
#[derive(Debug, Default)]
pub(crate) struct ConnectLinkSlot(Mutex<LinkSlot>);

#[derive(Default)]
enum LinkSlot {
    /// No link is offered.
    #[default]
    Closed,
    /// The user declined the link an earlier attempt offered: none is
    /// offered again.
    Declined,
    /// The retry of a request that offered `link`, which may answer with
    /// it again.
    Resuming { link: String },
    /// The request may answer with a link: the one it resumes, if any, and
    /// the session told when it completes.
    Open {
        resume: Option<String>,
        notify_session: Option<String>,
    },
    /// The link the request answers with.
    Offered(UrlElicitation),
}

impl std::fmt::Debug for LinkSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Closed => "Closed",
            Self::Declined => "Declined",
            Self::Resuming { .. } => "Resuming",
            Self::Open { .. } => "Open",
            Self::Offered(_) => "Offered",
        })
    }
}

/// What an open slot asks of the link it is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkRequest {
    /// The link an earlier attempt of the request offered.
    pub(crate) resume: Option<String>,
    /// The session told when the link completes.
    pub(crate) notify_session: Option<String>,
}

impl ConnectLinkSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, LinkSlot> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This request retries one that offered `link`.
    pub(crate) fn resume(&self, link: String) {
        *self.lock() = LinkSlot::Resuming { link };
    }

    /// The user declined the link this request's earlier attempt offered.
    pub(crate) fn decline(&self) {
        *self.lock() = LinkSlot::Declined;
    }

    /// Let the request answer with a link, telling `notify_session` when
    /// it completes; `false` when the user declined one.
    pub(crate) fn open(&self, notify_session: Option<String>) -> bool {
        let mut slot = self.lock();
        let resume = match std::mem::take(&mut *slot) {
            LinkSlot::Declined => {
                *slot = LinkSlot::Declined;
                return false;
            }
            LinkSlot::Resuming { link } => Some(link),
            LinkSlot::Closed | LinkSlot::Open { .. } | LinkSlot::Offered(_) => None,
        };
        *slot = LinkSlot::Open {
            resume,
            notify_session,
        };
        true
    }

    /// What the request asks of a link, while it may answer with one.
    pub(crate) fn request(&self) -> Option<LinkRequest> {
        match &*self.lock() {
            LinkSlot::Open {
                resume,
                notify_session,
            } => Some(LinkRequest {
                resume: resume.clone(),
                notify_session: notify_session.clone(),
            }),
            _ => None,
        }
    }

    /// Answer the request with `elicitation`, while it may.
    pub(crate) fn offer(&self, elicitation: UrlElicitation) {
        let mut slot = self.lock();
        if matches!(*slot, LinkSlot::Open { .. }) {
            *slot = LinkSlot::Offered(elicitation);
        }
    }

    /// The link the request answers with; the slot closes.
    pub(crate) fn take_offered(&self) -> Option<UrlElicitation> {
        let mut slot = self.lock();
        match std::mem::take(&mut *slot) {
            LinkSlot::Offered(elicitation) => Some(elicitation),
            other => {
                *slot = other;
                None
            }
        }
    }
}

/// Whether a stored sign-in of `identity` can ever exist: only for a
/// verified caller in the principal namespace a sign-in through the login
/// IdP is stored under, since the callback stores it under the principal
/// the IdP names and a link completes only for the principal it was
/// offered to.
pub(crate) fn can_store_sign_in(source: &dyn IdpSessionSource, identity: &RequestIdentity) -> bool {
    match identity {
        RequestIdentity::Verified {
            auth_provider,
            issuer,
            ..
        } => source.stores_sign_in_for(auth_provider, issuer),
        _ => false,
    }
}

/// Where a caller reached the gateway through, for a message: the IdP a
/// token this gateway minted names, else the issuer the caller reports.
fn caller_origin(identity: &RequestIdentity) -> &str {
    let minted_idp = identity
        .is_gateway_minted()
        .then(|| identity.attributes().get("idp"))
        .flatten();
    match (minted_idp, identity) {
        (Some(idp), _) => idp,
        (None, RequestIdentity::Verified { issuer, .. }) => issuer,
        (None, _) => "an unverified identity",
    }
}

/// Longest federation name a caller-facing sign-in message shows.
const MAX_SHOWN_FEDERATION_NAME: usize = 128;

/// How a message about signing in names `federation`: by name when it is
/// plain (`[A-Za-z0-9._-]`), else generically. A registry-synced name
/// carries the registry's server name, which must not put its own text
/// next to a sign-in link.
fn federation_label(federation: &str) -> String {
    let plain = !federation.is_empty()
        && federation.len() <= MAX_SHOWN_FEDERATION_NAME
        && federation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if plain {
        format!("federation `{federation}`")
    } else {
        "a federated tool".to_owned()
    }
}

/// The link a request answers a caller with no stored sign-in with, when
/// its slot is open: offered to the caller's `principal` for `federation`.
pub(crate) async fn offer_link(
    federation: &str,
    source: &dyn IdpSessionSource,
    identity: &RequestIdentity,
    principal: &str,
    slot: &ConnectLinkSlot,
    session_id: Option<&str>,
) {
    let Some(request) = slot.request() else {
        return;
    };
    if !can_store_sign_in(source, identity) {
        return;
    }
    let client_id = identity
        .is_gateway_minted()
        .then(|| identity.attributes().get("client_id"))
        .flatten()
        .map(String::as_str);
    let offer = LinkOffer {
        principal,
        client_id,
        session_id: request.notify_session.as_deref().or(session_id),
        notify: request.notify_session.is_some(),
        resume: request.resume.as_deref(),
    };
    let link = match source.offer_link(offer).await {
        Ok(link) => link,
        Err(LinkError::NotOffered) => return,
        Err(LinkError::Limited) => {
            count_link("limited");
            return;
        }
        Err(LinkError::Unavailable(reason)) => {
            count_link("unavailable");
            tracing::warn!(
                federation = %federation,
                reason = %reason,
                "no link to store the caller's sign-in could be offered"
            );
            return;
        }
    };
    count_link(if link.resumed { "resumed" } else { "offered" });
    let mut needs = federation_label(federation);
    if let Some(first) = needs.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    slot.offer(UrlElicitation {
        message: format!(
            "{needs} needs your {} sign-in, which this gateway keeps for you. Open the link, \
             sign in as yourself, then retry.",
            link.idp_name
        ),
        id: link.id,
        url: link.url,
        expires_at: link.expires_at,
    });
}

fn count_link(outcome: &'static str) {
    metrics::counter!("mcpg_federation_connect_link_total", "outcome" => outcome).increment(1);
}

/// The stored token a `subject_token` mode presents; `None` for
/// `caller_bearer`.
pub(crate) fn subject_token_kind(mode: SubjectToken) -> Option<SubjectTokenKind> {
    match mode {
        SubjectToken::CallerBearer => None,
        SubjectToken::IdpRefreshToken => Some(SubjectTokenKind::RefreshToken),
        SubjectToken::IdpIdToken => Some(SubjectTokenKind::IdToken),
    }
}

/// Drop every attribute of `identity` named like one the engine sets for a
/// credential issuer, so a caller (a mapped claim, say) can neither supply
/// the subject token nor claim the `idp_vault` source.
pub(crate) fn strip_subject_attributes(identity: &mut PluginIdentity) {
    identity
        .attributes
        .retain(|name, _| !name.starts_with(SUBJECT_ATTRIBUTE_PREFIX));
}

/// A short digest of what the credential cache keys the upstream
/// credential of `identity` on besides the stored sign-in: its resolved
/// identity without the attributes the engine sets, with the cache's
/// `key_attributes` folded in.
pub(crate) fn credential_key_digest(
    identity: &RequestIdentity,
    key_attributes: &[String],
) -> String {
    let mut plugin_identity = crate::runtime::plugin_identity_from_request_identity(identity);
    strip_subject_attributes(&mut plugin_identity);
    let mut digest = mcpg_plugin_protocol::credential::identity_hash_with_attrs(
        &plugin_identity,
        key_attributes,
    );
    digest.truncate(16);
    digest
}

/// The identity a credential issuer exchanges the stored sign-in `token`
/// under: the caller's resolved identity without its own subject
/// attributes, and the token with where it came from and where it may go.
pub(crate) fn vault_identity(
    identity: &RequestIdentity,
    token: &VaultSubjectToken,
) -> PluginIdentity {
    let mut plugin_identity = crate::runtime::plugin_identity_from_request_identity(identity);
    strip_subject_attributes(&mut plugin_identity);
    for (name, value) in [
        (SUBJECT_TOKEN_ATTRIBUTE, token.token.expose()),
        (SUBJECT_TOKEN_TYPE_ATTRIBUTE, token.kind.token_type()),
        (
            SUBJECT_TOKEN_SOURCE_ATTRIBUTE,
            SUBJECT_TOKEN_SOURCE_IDP_VAULT,
        ),
        (SUBJECT_TOKEN_ISSUER_ATTRIBUTE, token.issuer.as_str()),
        (
            SUBJECT_TOKEN_ENDPOINT_ATTRIBUTE,
            token.token_endpoint.as_str(),
        ),
        (SUBJECT_TOKEN_CLIENT_ID_ATTRIBUTE, token.client_id.as_str()),
        (SUBJECT_TOKEN_BINDING_ATTRIBUTE, token.binding.as_str()),
    ] {
        plugin_identity
            .attributes
            .insert(name.to_owned(), value.to_owned());
    }
    plugin_identity
}

/// Why a federation could not present the caller's stored sign-in, for
/// the metric, the audit record and the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectTokenOutcome {
    Used,
    NotLinked,
    Refused,
    Unavailable,
}

impl SubjectTokenOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::NotLinked => "not_linked",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Count one use of `mode` that came to `outcome`.
pub(crate) fn count(mode: SubjectToken, outcome: SubjectTokenOutcome) {
    metrics::counter!(
        "mcpg_federation_subject_token_total",
        "mode" => mode.as_str(),
        "outcome" => outcome.as_str()
    )
    .increment(1);
}

/// `mcpg.federation.idp_subject_token`: federation `federation` could not
/// present the stored sign-in of `actor` in `mode`, for `reason`.
pub(crate) fn audit_event(
    federation: &str,
    mode: SubjectToken,
    outcome: SubjectTokenOutcome,
    reason: &str,
    actor: PluginIdentity,
    request_id: Option<&str>,
) -> AuditEvent {
    use mcpg_plugin_host::audit_events::{new_event_id, now_rfc3339_utc};
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.federation.idp_subject_token".into(),
        resource: Some(format!("federation://{federation}")),
        outcome: match outcome {
            SubjectTokenOutcome::Used => AuditOutcome::Success,
            SubjectTokenOutcome::NotLinked | SubjectTokenOutcome::Refused => AuditOutcome::Denied,
            SubjectTokenOutcome::Unavailable => AuditOutcome::Failure,
        },
        request_id: request_id.map(str::to_owned),
        upstream_request_id: None,
        node_id: None,
        details: serde_json::json!({
            "federation": federation,
            "mode": mode.as_str(),
            "outcome": outcome.as_str(),
            "reason": reason,
        }),
        prev_event_hash: None,
    }
}

/// What a caller with no usable stored sign-in is told: sign in once at
/// the connect page, or, when a sign-in through the login IdP could never
/// be stored under their principal, that none can be stored for them.
pub(crate) fn not_linked_message(
    federation: &str,
    source: &dyn IdpSessionSource,
    identity: &RequestIdentity,
    ended: bool,
) -> String {
    let federation = federation_label(federation);
    let login_issuer = source.login_issuer();
    let login = login_issuer.as_deref().unwrap_or("the enterprise IdP");
    if !can_store_sign_in(source, identity) {
        return format!(
            "{federation} presents your stored enterprise sign-in, but none can be stored for \
             you: you signed in through {}, and only users of {login} can store one. The \
             operator joins other callers to those users with the IdP's principal_issuer or \
             required_tenant",
            caller_origin(identity)
        );
    }
    let what = if ended {
        "your stored enterprise sign-in was ended by the IdP"
    } else {
        "no enterprise sign-in is stored for you"
    };
    match source.connect_url() {
        Some(connect) => format!("{federation}: {what}: open {connect} once, then retry"),
        None => format!(
            "{federation}: {what}: sign in to this gateway through {login} from your MCP client \
             once, then retry"
        ),
    }
}

#[cfg(test)]
#[path = "idp_sessions_tests.rs"]
mod tests;
