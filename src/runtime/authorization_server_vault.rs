//! The IdP sign-in the gateway keeps for each user (`idp/h(principal)`):
//! one per principal, shared by every MCP client of the user, and used only
//! toward the login IdP token endpoint that issued it.
//!
//! A stored sign-in is refreshed at the IdP only under a lease on the
//! user, so the concurrent requests of one user make one IdP call: a
//! request that waited reads what the holder stored, and one that waited
//! in vain does not call the IdP with a refresh token the holder may be
//! spending. An IdP that refuses the refresh (`invalid_grant`), or answers
//! with an ID token that fails OpenID Connect Core §12.2, ends the stored
//! sign-in and every grant of the user, unless another request refreshed
//! or replaced the sign-in meanwhile. When a client revokes the user's
//! last grant, a sign-in an MCP client's sign-in stored ends with it.
//!
//! Federations read it through [`AuthorizationServer::idp_subject_token`].
//! Nothing here logs or audits a token.

use std::time::Duration;

use super::grants::GrantEvent;
use super::interactive::{IDP_SESSION_LEASE_TTL, IDP_SESSION_LEASE_WAIT, SupersededSignIn};
use super::state::{
    HandleKind, IdpSessionOrigin, IdpSessionRecord, InteractiveState, RevocationReason,
    SecretString, StateError, handle, keys,
};
use super::upstream::{IdTokenCheck, IdTokenError, LoginIdp};
use super::{AuthorizationServer, now_unix, unverified_payload};

/// An ID token handed to a federation has at least this long left; one
/// closer to its expiry is refreshed at the IdP first.
pub const ID_TOKEN_MIN_REMAINING_SECS: u64 = 60;

/// The stored token a federation presents at the login IdP as its RFC 8693
/// subject token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectTokenKind {
    RefreshToken,
    IdToken,
}

impl SubjectTokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RefreshToken => "refresh_token",
            Self::IdToken => "id_token",
        }
    }

    /// Its RFC 8693 §3 token type identifier.
    pub fn token_type(self) -> &'static str {
        match self {
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
        }
    }
}

/// A user's stored IdP token and the one place it may be presented.
/// `Debug` shows no token.
#[derive(Debug, Clone)]
pub struct VaultSubjectToken {
    pub token: SecretString,
    pub kind: SubjectTokenKind,
    /// The IdP that issued the token, its token endpoint, and the
    /// gateway's client there: the token goes nowhere else, with no other
    /// client.
    pub issuer: String,
    pub token_endpoint: String,
    pub client_id: String,
    /// Stands for the stored sign-in, not the token, so it stays the same
    /// while the IdP rotates the token:
    /// `vault:<hash of the principal>:<client_id>:<kind>`.
    pub binding: String,
}

/// What a federation finds in a user's stored IdP sign-in.
#[derive(Debug)]
pub enum IdpSubjectToken {
    /// The token to present.
    Linked(VaultSubjectToken),
    /// No trusted IdP offers sign-in, so no sign-in is ever stored.
    NoLogin,
    /// Nothing usable is stored for the user: they sign in, or connect at
    /// `/oauth/connect`, once. `events` records a stored sign-in the IdP
    /// ended while it was read.
    NotLinked {
        reason: &'static str,
        events: Vec<GrantEvent>,
    },
    /// The login IdP does not provide this kind of token.
    Unusable { reason: &'static str },
    /// The store or the IdP cannot be reached now; a retry may succeed.
    Unavailable { reason: String },
}

/// Why a stored sign-in was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpSessionEnd {
    /// The IdP refused to refresh it.
    IdpRefused,
    /// The IdP refreshed it with an ID token that fails its checks.
    IdTokenInvalid,
    /// Its client revoked the user's last grant.
    LastGrantRevoked,
}

impl IdpSessionEnd {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdpRefused => "idp_refused",
            Self::IdTokenInvalid => "id_token_invalid",
            Self::LastGrantRevoked => "last_grant_revoked",
        }
    }
}

/// What checking a user's stored sign-in came to.
#[derive(Debug)]
pub(super) enum SessionCheck {
    /// The sign-in, fresh enough for the caller: refreshed at the IdP now,
    /// by another request meanwhile, replaced by a newer sign-in, or not
    /// due.
    Fresh { record: IdpSessionRecord },
    /// Nothing usable is stored: no sign-in, one for another IdP or
    /// another client of the gateway there, one without an IdP refresh
    /// token when a refresh is due, or one whose token endpoint changed.
    Missing,
    /// The IdP ended the sign-in: it is deleted and every grant of the
    /// user revoked.
    Ended { events: Vec<GrantEvent> },
    /// The IdP could not be asked, or another request holds the user's
    /// lease past the wait; `record` is the sign-in as last stored.
    Unavailable {
        record: IdpSessionRecord,
        reason: String,
    },
}

fn count_session(op: &'static str, outcome: &'static str) {
    metrics::counter!("mcpg_as_idp_sessions_total", "op" => op, "outcome" => outcome).increment(1);
}

/// Whether `record` is a sign-in at `login`, by the gateway's client there.
fn usable(login: &LoginIdp<'_>, record: &IdpSessionRecord) -> bool {
    record.issuer == login.issuer() && record.client_id == login.client_id()
}

/// Whether `current`, read from the store now, is still the stored sign-in
/// `before` was: neither refreshed nor replaced since. A sign-in stored
/// after `before` was deleted may start again at the same generation, so
/// the sign-in time and the refresh token must match too.
fn same_sign_in(current: &IdpSessionRecord, before: &IdpSessionRecord) -> bool {
    current.generation == before.generation
        && current.obtained_at == before.obtained_at
        && match (&current.refresh_token, &before.refresh_token) {
            (Some(current), Some(before)) => current.ct_eq(before.expose()),
            (None, None) => true,
            _ => false,
        }
}

/// `auth_time` of the stored ID token, which was verified before it was
/// stored.
fn stored_auth_time(record: &IdpSessionRecord) -> Option<u64> {
    unverified_payload(record.id_token.expose())?
        .get("auth_time")?
        .as_u64()
}

impl AuthorizationServer {
    /// The stored sign-in of `principal`, refreshed at the login IdP first
    /// when `due` holds for it at the time given. Only the holder of the
    /// user's lease calls the IdP, after reading the sign-in again. A
    /// request that waits for the lease in vain reads it again too, and
    /// reports it unavailable while it is still due: the holder may be
    /// spending its refresh token, which an IdP that rotates refresh
    /// tokens without a grace period refuses a second time.
    pub(super) async fn check_idp_session(
        &self,
        state: &InteractiveState,
        principal: &str,
        due: impl Fn(&IdpSessionRecord, u64) -> bool,
    ) -> Result<SessionCheck, StateError> {
        let Some(login) = self.login_idp() else {
            return Ok(SessionCheck::Missing);
        };
        match state.get(&keys::idp_session(principal)).await? {
            Some(record) if usable(&login, &record) => {
                if !due(&record, now_unix()) {
                    return Ok(SessionCheck::Fresh { record });
                }
            }
            _ => return Ok(SessionCheck::Missing),
        }
        let Some(lease) = state
            .acquire_lease(
                &keys::idp_lease(principal),
                IDP_SESSION_LEASE_TTL,
                IDP_SESSION_LEASE_WAIT,
            )
            .await?
        else {
            count_session("refresh", "lease_busy");
            return Ok(
                match state
                    .get(&keys::idp_session(principal))
                    .await?
                    .filter(|record| usable(&login, record))
                {
                    None => SessionCheck::Missing,
                    Some(record) if !due(&record, now_unix()) => SessionCheck::Fresh { record },
                    Some(record) => SessionCheck::Unavailable {
                        record,
                        reason: "another request is checking the user's sign-in at the login IdP"
                            .to_owned(),
                    },
                },
            );
        };
        let checked = self
            .refresh_idp_session(state, login, principal, &due)
            .await;
        let _ = state.release_lease(&lease).await;
        checked
    }

    /// [`Self::check_idp_session`] once its lease is settled.
    async fn refresh_idp_session(
        &self,
        state: &InteractiveState,
        login: LoginIdp<'_>,
        principal: &str,
        due: &impl Fn(&IdpSessionRecord, u64) -> bool,
    ) -> Result<SessionCheck, StateError> {
        let key = keys::idp_session(principal);
        let Some(record) = state.get(&key).await?.filter(|r| usable(&login, r)) else {
            return Ok(SessionCheck::Missing);
        };
        let now = now_unix();
        if !due(&record, now) {
            return Ok(SessionCheck::Fresh { record });
        }
        let Some(refresh_token) = record.refresh_token.clone() else {
            return Ok(SessionCheck::Missing);
        };
        let metadata = match login.metadata().await {
            Ok(metadata) => metadata,
            Err(error) => {
                count_session("refresh", "unavailable");
                return Ok(SessionCheck::Unavailable {
                    record,
                    reason: error.to_string(),
                });
            }
        };
        if metadata.token_endpoint != record.token_endpoint {
            tracing::warn!(
                idp = %login.issuer(),
                "the login IdP's token endpoint changed since the user's sign-in was stored; it \
                 is not sent to the new one"
            );
            return Ok(SessionCheck::Missing);
        }
        let answer = match login.refresh(refresh_token.expose()).await {
            Ok(answer) => answer,
            Err(error) if error.oauth_error() == Some("invalid_grant") => {
                count_session("refresh", "refused");
                return self
                    .end_refused(state, &login, principal, &record, IdpSessionEnd::IdpRefused)
                    .await;
            }
            Err(error) => {
                count_session("refresh", "unavailable");
                return Ok(SessionCheck::Unavailable {
                    record,
                    reason: error.to_string(),
                });
            }
        };
        let mut updated = record.clone();
        if let Some(rotated) = answer.refresh_token {
            updated.refresh_token = Some(rotated);
        }
        if let Some(scope) = answer.scope {
            updated.scope = scope;
        }
        updated.generation = record.generation.saturating_add(1);
        if let Some(id_token) = answer.id_token {
            let check = IdTokenCheck::Refresh {
                subject: &record.sub,
                auth_time: stored_auth_time(&record),
            };
            match login.validate_id_token(id_token.expose(), check).await {
                Ok(validated) => {
                    updated.id_token = id_token;
                    updated.id_token_exp = validated.expires_at;
                }
                Err(IdTokenError::KeysUnavailable) => {
                    // The IdP may have rotated its refresh token: keep it,
                    // without counting the sign-in as checked.
                    count_session("refresh", "unavailable");
                    let kept = self
                        .store_refreshed(state, principal, &record, &updated)
                        .await?;
                    return Ok(kept.map_or(SessionCheck::Missing, |record| {
                        SessionCheck::Unavailable {
                            record,
                            reason: "the login IdP's signing keys cannot be fetched now".to_owned(),
                        }
                    }));
                }
                Err(IdTokenError::Invalid(reason)) => {
                    tracing::warn!(
                        idp = %login.issuer(),
                        reason = %reason,
                        "the login IdP refreshed a stored sign-in with an ID token that fails its \
                         checks; ending the sign-in"
                    );
                    count_session("refresh", "invalid");
                    return self
                        .end_refused(
                            state,
                            &login,
                            principal,
                            &record,
                            IdpSessionEnd::IdTokenInvalid,
                        )
                        .await;
                }
            }
        }
        updated.last_refreshed = now;
        count_session("refresh", "ok");
        let kept = self
            .store_refreshed(state, principal, &record, &updated)
            .await?;
        Ok(match kept {
            Some(record) => SessionCheck::Fresh { record },
            None => SessionCheck::Missing,
        })
    }

    /// Store `updated` as the sign-in of `principal` in place of `before`,
    /// unless another sign-in replaced `before` meanwhile, which then
    /// stays, or the sign-in ended meanwhile; the sign-in stored now.
    async fn store_refreshed(
        &self,
        state: &InteractiveState,
        principal: &str,
        before: &IdpSessionRecord,
        updated: &IdpSessionRecord,
    ) -> Result<Option<IdpSessionRecord>, StateError> {
        let key = keys::idp_session(principal);
        match state.get(&key).await? {
            Some(current) if same_sign_in(&current, before) => {
                state
                    .put(
                        &key,
                        updated,
                        Duration::from_secs(self.interactive.idp_session_max_age_secs()),
                    )
                    .await?;
                Ok(Some(updated.clone()))
            }
            current => Ok(current),
        }
    }

    /// End the stored sign-in `record` of `principal`, whose refresh the
    /// IdP refused as `end`, while it is still the one stored. Another
    /// request may have refreshed it meanwhile (the IdP then refuses the
    /// token it rotated away) or a newer sign-in replaced it: that sign-in
    /// stays and is returned, and no grant of the user is revoked.
    async fn end_refused(
        &self,
        state: &InteractiveState,
        login: &LoginIdp<'_>,
        principal: &str,
        record: &IdpSessionRecord,
        end: IdpSessionEnd,
    ) -> Result<SessionCheck, StateError> {
        match state.get(&keys::idp_session(principal)).await? {
            Some(current) if same_sign_in(&current, record) => {
                let events = self.end_idp_session(state, principal, record, end).await;
                Ok(SessionCheck::Ended { events })
            }
            Some(current) if usable(login, &current) => {
                count_session("refresh", "superseded");
                tracing::debug!(
                    idp = %login.issuer(),
                    "the login IdP refused a stored sign-in that another request has since \
                     refreshed or replaced; keeping the newer one"
                );
                Ok(SessionCheck::Fresh { record: current })
            }
            _ => Ok(SessionCheck::Missing),
        }
    }

    /// Delete the stored sign-in `record` of `principal` and revoke every
    /// grant of the user; the audit records. A sign-in that cannot be
    /// deleted is logged, and ends again at its next refresh.
    pub(super) async fn end_idp_session(
        &self,
        state: &InteractiveState,
        principal: &str,
        record: &IdpSessionRecord,
        end: IdpSessionEnd,
    ) -> Vec<GrantEvent> {
        match state.delete(&keys::idp_session(principal)).await {
            Ok(_) => count_session("delete", "ok"),
            Err(error) => {
                count_session("delete", "error");
                tracing::error!(
                    error = %error,
                    reason = end.as_str(),
                    "an ended IdP sign-in could not be deleted"
                );
            }
        }
        let mut events = self
            .revoke_principal_grants(state, principal, RevocationReason::IdpRefused)
            .await;
        events.push(GrantEvent::IdpSessionRemoved {
            idp: record.issuer.clone(),
            subject: record.sub.clone(),
            reason: end,
        });
        events
    }

    /// After a client revoked a grant of `principal`: when the user holds
    /// no other grant and an MCP client's sign-in stored their IdP
    /// sign-in, end it, record that in `events`, and return its IdP
    /// refresh token for the IdP to revoke. A sign-in stored within the
    /// last authorization-code lifetime may back a code not yet redeemed,
    /// and stays. Best effort: a store failure keeps the sign-in.
    pub(super) async fn release_idp_session(
        &self,
        state: &InteractiveState,
        principal: &str,
        events: &mut Vec<GrantEvent>,
    ) -> Option<SupersededSignIn> {
        let released = async {
            if !state
                .list(&keys::principal_grants(principal), 1)
                .await?
                .is_empty()
            {
                return Ok::<_, StateError>(None);
            }
            let key = keys::idp_session(principal);
            let pending_window = self
                .interactive
                .authorization_code_ttl_secs
                .saturating_add(super::interactive::PENDING_GRANT_MARGIN_SECS);
            let Some(record) = state.get(&key).await?.filter(|record| {
                record.origin == IdpSessionOrigin::Login
                    && now_unix().saturating_sub(record.obtained_at) > pending_window
            }) else {
                return Ok(None);
            };
            state.delete(&key).await?;
            Ok(Some(record))
        }
        .await;
        let record = match released {
            Ok(record) => record?,
            Err(error) => {
                count_session("delete", "error");
                tracing::warn!(
                    error = %error,
                    "a user's stored IdP sign-in could not be released after their last grant was \
                     revoked"
                );
                return None;
            }
        };
        count_session("delete", "ok");
        events.push(GrantEvent::IdpSessionRemoved {
            idp: record.issuer.clone(),
            subject: record.sub.clone(),
            reason: IdpSessionEnd::LastGrantRevoked,
        });
        let IdpSessionRecord {
            issuer,
            client_id,
            refresh_token,
            ..
        } = record;
        refresh_token.map(|refresh_token| SupersededSignIn {
            issuer,
            client_id,
            refresh_token,
        })
    }

    /// The stored IdP token of the user whose principal key is
    /// `principal`, for a federation to present as its subject token at
    /// the login IdP. A refresh token is handed out as stored; an ID token
    /// with less than [`ID_TOKEN_MIN_REMAINING_SECS`] left is refreshed at
    /// the IdP first, under the user's lease.
    pub async fn idp_subject_token(
        &self,
        principal: &str,
        kind: SubjectTokenKind,
    ) -> IdpSubjectToken {
        let Some(login) = self.login_idp() else {
            return IdpSubjectToken::NoLogin;
        };
        let Some(state) = self
            .interactive_state
            .as_ref()
            .filter(|state| state.is_available())
        else {
            return IdpSubjectToken::Unavailable {
                reason: "the sign-in state store is unavailable".to_owned(),
            };
        };
        let checked = match kind {
            SubjectTokenKind::RefreshToken => {
                let stored = state.get(&keys::idp_session(principal)).await;
                stored.map(|record| {
                    record
                        .filter(|record| usable(&login, record))
                        .map_or(SessionCheck::Missing, |record| SessionCheck::Fresh {
                            record,
                        })
                })
            }
            SubjectTokenKind::IdToken => {
                self.check_idp_session(state, principal, |record, now| {
                    record.id_token_exp <= now.saturating_add(ID_TOKEN_MIN_REMAINING_SECS)
                })
                .await
            }
        };
        let record = match checked {
            Ok(SessionCheck::Fresh { record }) => record,
            Ok(SessionCheck::Missing) => {
                return IdpSubjectToken::NotLinked {
                    reason: "no usable enterprise sign-in is stored for this user",
                    events: Vec::new(),
                };
            }
            Ok(SessionCheck::Ended { events }) => {
                return IdpSubjectToken::NotLinked {
                    reason: "the enterprise IdP ended the stored sign-in",
                    events,
                };
            }
            Ok(SessionCheck::Unavailable { reason, .. }) => {
                return IdpSubjectToken::Unavailable { reason };
            }
            Err(error) => {
                return IdpSubjectToken::Unavailable {
                    reason: error.to_string(),
                };
            }
        };
        let token = match kind {
            SubjectTokenKind::RefreshToken => match record.refresh_token {
                Some(ref token) => token.clone(),
                None => {
                    return IdpSubjectToken::Unusable {
                        reason: "the enterprise IdP issued no refresh token at sign-in; add \
                                 offline_access to trusted_idps[].login.scopes",
                    };
                }
            },
            SubjectTokenKind::IdToken => {
                if record.id_token_exp <= now_unix().saturating_add(ID_TOKEN_MIN_REMAINING_SECS) {
                    return IdpSubjectToken::Unusable {
                        reason: "the enterprise IdP returns no ID token on refresh; use \
                                 subject_token: idp_refresh_token",
                    };
                }
                record.id_token.clone()
            }
        };
        IdpSubjectToken::Linked(VaultSubjectToken {
            token,
            kind,
            binding: format!(
                "vault:{}:{}:{}",
                handle(HandleKind::Principal, &[principal.as_bytes()]),
                record.client_id,
                kind.as_str()
            ),
            issuer: record.issuer,
            token_endpoint: record.token_endpoint,
            client_id: record.client_id,
        })
    }
}

#[async_trait::async_trait]
impl crate::runtime::federation::idp_sessions::IdpSessionSource for AuthorizationServer {
    async fn subject_token(&self, principal: &str, kind: SubjectTokenKind) -> IdpSubjectToken {
        self.idp_subject_token(principal, kind).await
    }

    fn connect_url(&self) -> Option<String> {
        self.login_idp()?;
        self.interactive
            .idp_sessions
            .connect_page
            .then(|| self.endpoint(super::interactive::CONNECT_PATH))
    }

    fn login_issuer(&self) -> Option<String> {
        self.login_idp().map(|login| login.issuer().to_owned())
    }

    fn stores_sign_in_for(&self, auth_provider: &str, issuer: &str) -> bool {
        self.login_stores_principal(auth_provider, issuer)
    }

    async fn offer_link(
        &self,
        offer: super::connect::LinkOffer<'_>,
    ) -> Result<super::connect::ConnectLink, super::connect::LinkError> {
        AuthorizationServer::offer_link(self, offer).await
    }
}
