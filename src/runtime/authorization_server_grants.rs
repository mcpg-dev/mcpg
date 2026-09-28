//! The `authorization_code` grant of interactive sign-in at the token
//! endpoint, and the grants it activates.
//!
//! A code redeems once, only for the client it was issued to, with the
//! PKCE verifier of its challenge (RFC 7636 §4.6), for the redirect URI and
//! the resource its authorization request named when the token request
//! names them again (OAuth 2.1 §4.1.3, RFC 8707 §2.2). A code presented
//! again after it was redeemed revokes the grant it issued (OAuth 2.1
//! §4.1.3); a verifier that does not match revokes nothing (§7.5.3).
//!
//! Redeeming activates the grant the callback left pending, records it
//! among the user's grants (revoking the oldest beyond
//! `refresh_tokens.max_grants_per_principal`), and mints the access token
//! an ID-JAG redemption mints, naming the grant (`gid`), how it was
//! obtained (`gty`) and when the user signed in (`auth_time`). A refresh
//! token comes with it when refresh tokens are on, the client's grant
//! types hold `refresh_token`, and, while refreshes check the IdP, the
//! user's stored IdP sign-in holds an IdP refresh token. The IdP is not
//! called here.
//!
//! A revoked grant is refused on every replica: its tombstone outlives
//! every access token it issued, and each replica reads the tombstones
//! into the revocations [`AuthorizationServer::verify_bearer`] checks.
//! Refresh tokens rotate as [`super::refresh`] describes.
//!
//! With DPoP on, a code whose authorization request named a key
//! (`dpop_jkt`) redeems only with a proof of that key, checked before the
//! code is spent. A request with a proof receives an access token bound
//! to the proof's key, and a public client's grant is bound to it too, so
//! its refresh tokens redeem only with a proof of the same key (RFC 9449
//! §5); a confidential client's grant stays unbound.
//!
//! A grant keeps the authorization details (RFC 9396) the user approved;
//! a token request may narrow them for its access token, checked before
//! the code is spent.
//!
//! Nothing here logs or audits a code, a verifier, a proof, a token or a
//! detail's values.

use std::time::Duration;

use zeroize::Zeroizing;

use super::clients::Client;
use super::dcr::Presented;
use super::dpop::ProvenKey;
use super::interactive::AUTHORIZATION_CODE_PREFIX;
use super::rar::{AuthorizationDetails, DetailsSource};
use super::redirect::{
    AuthorizeClientError, PkceError, check_code_verifier, code_verifier_is_valid,
};
use super::state::{
    ClientKind, CodeRecord, CodeUsedRecord, GrantId, GrantRecord, GrantStatus, InteractiveState,
    PrincipalGrantRecord, RefreshRecord, RevocationReason, RevokedId, StateError, keys,
    random_token,
};
use super::vault::IdpSessionEnd;
use super::{
    AuthorizationServer, Confirmation, IssuedToken, MintedClaims, OAuthError, Principal,
    RedemptionContext, TokenRequestForm, TokenResponse, minting_failed, now_unix,
};

/// `grant_type` of the authorization code grant, and the `gty` claim of
/// the access tokens it issues.
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";
/// `grant_type` of the refresh token grant.
pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";
/// Prefix of a refresh token this server issues, which lets secret
/// scanners find a leaked one.
pub const REFRESH_TOKEN_PREFIX: &str = "mcpg_rt_";
/// Longest authorization code looked up; every code this server issues is
/// much shorter.
const MAX_CODE_BYTES: usize = 128;
/// How long a redeemed code's marker outlives the code, so a replay at
/// the end of the code's life is still recognised.
const CODE_USED_MARGIN_SECS: u64 = 600;
/// Grants of one user read beyond `max_grants_per_principal` when the
/// oldest are revoked.
const PRINCIPAL_GRANTS_LIST_MARGIN: usize = 64;
/// Most listings read when every grant of one user is revoked.
const PRINCIPAL_GRANTS_LIST_ROUNDS: usize = 8;

/// The interactive grant an access token was issued under, described
/// without any token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedGrant {
    pub gid: GrantId,
    pub client_kind: ClientKind,
    /// The principal namespace and `auth_provider` the user resolves to,
    /// as the token's verification reports them.
    pub principal_issuer: String,
    pub auth_provider: String,
    pub refresh_token_issued: bool,
}

/// What a token or revocation request did to grants and stored IdP
/// sign-ins beside its answer, for the audit log. None carries a code or
/// a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantEvent {
    /// `mcpg.as.code_replay_detected`: an authorization code was presented
    /// again after it was redeemed.
    CodeReplay { gid: GrantId, client_id: String },
    /// `mcpg.as.refresh_reuse_detected`: a spent refresh token was
    /// presented again.
    RefreshReuse { gid: GrantId, client_id: String },
    /// `mcpg.as.grant_revoked`.
    Revoked {
        gid: GrantId,
        reason: RevocationReason,
        /// The grant's client, when the grant could still be read.
        client_id: Option<String>,
    },
    /// `mcpg.as.token_revoked`: its client revoked an access token issued
    /// without a grant, named by its `jti`.
    TokenRevoked { jti: String, client_id: String },
    /// `mcpg.as.idp_session_removed`: the stored IdP sign-in of the user
    /// the IdP names `subject` was deleted.
    IdpSessionRemoved {
        idp: String,
        subject: String,
        reason: IdpSessionEnd,
    },
}

impl GrantEvent {
    /// The audit event of this, recorded under the request `request_id`.
    pub fn event(&self, request_id: &str) -> mcpg_plugin_protocol::audit::AuditEvent {
        use mcpg_plugin_host::audit_events::{new_event_id, now_rfc3339_utc, system_identity};
        use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
        let (action, outcome, details) = match self {
            Self::CodeReplay { gid, client_id } => (
                "mcpg.as.code_replay_detected",
                AuditOutcome::Denied,
                serde_json::json!({ "gid": gid.as_str(), "client_id": client_id }),
            ),
            Self::RefreshReuse { gid, client_id } => (
                "mcpg.as.refresh_reuse_detected",
                AuditOutcome::Denied,
                serde_json::json!({ "gid": gid.as_str(), "client_id": client_id }),
            ),
            Self::Revoked {
                gid,
                reason,
                client_id,
            } => (
                "mcpg.as.grant_revoked",
                AuditOutcome::Success,
                serde_json::json!({
                    "gid": gid.as_str(),
                    "reason": reason.as_str(),
                    "client_id": client_id,
                }),
            ),
            Self::TokenRevoked { jti, client_id } => (
                "mcpg.as.token_revoked",
                AuditOutcome::Success,
                serde_json::json!({
                    "token_jti": jti,
                    "reason": RevocationReason::Client.as_str(),
                    "client_id": client_id,
                }),
            ),
            Self::IdpSessionRemoved {
                idp,
                subject,
                reason,
            } => (
                "mcpg.as.idp_session_removed",
                AuditOutcome::Success,
                serde_json::json!({
                    "idp": idp,
                    "subject": subject,
                    "reason": reason.as_str(),
                }),
            ),
        };
        AuditEvent {
            event_id: new_event_id(),
            occurred_at: now_rfc3339_utc(),
            actor: system_identity(),
            action: action.into(),
            resource: None,
            outcome,
            request_id: Some(request_id.to_owned()),
            upstream_request_id: None,
            node_id: None,
            details,
            prev_event_hash: None,
        }
    }
}

/// `temporarily_unavailable` for a state store that failed: nothing is
/// issued that could not be recorded.
pub(super) fn store_unavailable(error: StateError) -> OAuthError {
    tracing::error!(error = %error, "the sign-in state store failed; refusing the request");
    OAuthError::temporarily_unavailable("the sign-in state store is unavailable; retry shortly")
}

fn unknown_code() -> OAuthError {
    OAuthError::invalid_grant("the authorization code is invalid, expired or was issued elsewhere")
}

/// A live grant, and what its client receives for it.
pub(super) struct ActiveGrant {
    pub(super) gid: GrantId,
    pub(super) grant: GrantRecord,
    pub(super) refresh_token: Option<Zeroizing<String>>,
    /// The scopes of the access token, when narrower than the grant's.
    pub(super) scope: Option<Vec<String>>,
    /// The DPoP key the access token is bound to.
    pub(super) dpop_jkt: Option<String>,
    /// The authorization details of the access token, when narrower than
    /// the grant's.
    pub(super) authorization_details: Option<AuthorizationDetails>,
}

impl AuthorizationServer {
    /// The state of interactive sign-in, when it has a store.
    pub(super) fn grant_state(&self) -> Result<&InteractiveState, OAuthError> {
        self.interactive_state
            .as_ref()
            .filter(|state| state.is_available())
            .ok_or_else(|| {
                OAuthError::temporarily_unavailable(
                    "the sign-in state store is unavailable; retry shortly",
                )
            })
    }

    /// Redeem an authorization code (OAuth 2.1 §4.1.3), checked in order:
    /// the client and its grant types, the code and verifier present and
    /// well formed, the code known and unexpired, issued to this client,
    /// the verifier's S256 its challenge, the redirect URI and resource
    /// when named again, the DPoP `proof` against the key the request
    /// named, the `authorization_details` against those approved; then the
    /// code is spent once, and a second redemption revokes its grant. The
    /// `scope` parameter is not read: the grant carries the scopes the user
    /// approved.
    pub(super) async fn redeem_code(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        proof: Option<&ProvenKey>,
        context: &mut RedemptionContext,
    ) -> Result<(TokenResponse, IssuedToken), OAuthError> {
        if let Some(login) = self.login_idp() {
            context.idp = Some(login.issuer().to_owned());
        }
        let client = match self.authenticate(&form, basic_auth).await {
            Ok(client) => client,
            Err(error) => {
                if let Some(event) = self
                    .end_removed_registration(
                        form.client_id.as_deref(),
                        Presented::Code(form.code.as_deref().unwrap_or_default()),
                    )
                    .await
                {
                    context.grant_events.push(event);
                }
                return Err(error);
            }
        };
        context.client_id = Some(client.client_id.clone());
        if let Some(refusal) = client.code_grant_refusal() {
            let reason = match refusal {
                AuthorizeClientError::Unauthorized(reason)
                | AuthorizeClientError::InvalidDocument(reason) => reason.clone(),
                other => other.description(),
            };
            return Err(OAuthError::new(
                "unauthorized_client",
                format!("this client may not redeem authorization codes: {reason}"),
            ));
        }
        let code = form
            .code
            .as_deref()
            .filter(|code| !code.is_empty())
            .ok_or_else(|| OAuthError::new("invalid_request", "code is required"))?;
        let verifier = form
            .code_verifier
            .as_deref()
            .filter(|verifier| !verifier.is_empty())
            .ok_or(PkceError::VerifierMissing)?;
        if !code_verifier_is_valid(verifier) {
            return Err(PkceError::VerifierMalformed.into());
        }
        let state = self.grant_state()?;
        if !code.starts_with(AUTHORIZATION_CODE_PREFIX) || code.len() > MAX_CODE_BYTES {
            return Err(unknown_code());
        }
        let now = now_unix();
        let record = match state
            .get(&keys::code(code))
            .await
            .map_err(store_unavailable)?
        {
            Some(record) if now <= record.exp => record,
            _ => return Err(unknown_code()),
        };
        context.gid = Some(record.gid.clone());
        if record.client_id != client.client_id {
            return Err(OAuthError::invalid_grant(
                "the authorization code was issued to another client",
            ));
        }
        check_code_verifier(Some(verifier), &record.code_challenge)?;
        if form
            .redirect_uri
            .as_deref()
            .is_some_and(|redirect_uri| redirect_uri != record.redirect_uri)
        {
            return Err(OAuthError::invalid_grant(
                "redirect_uri is not the redirect URI of the authorization request",
            ));
        }
        if form.resource.as_deref().is_some_and(|resource| {
            resource.trim_end_matches('/') != record.resource.trim_end_matches('/')
        }) {
            return Err(OAuthError::new(
                "invalid_target",
                "the requested resource is not the resource of the authorization request",
            ));
        }
        let dpop_jkt = self.proof_binding(
            record.dpop_jkt.as_deref(),
            proof,
            &client,
            "the authorization request (dpop_jkt)",
        )?;
        let authorization_details = self.requested_details(
            &record.authorization_details,
            form.authorization_details.as_deref(),
            DetailsSource::Token,
        )?;
        let code_ttl = self.interactive.authorization_code_ttl_secs;
        let claimed = state
            .put_if_absent(
                &keys::code_used(code),
                &CodeUsedRecord {
                    gid: record.gid.clone(),
                },
                Duration::from_secs(code_ttl.saturating_add(CODE_USED_MARGIN_SECS)),
            )
            .await
            .map_err(store_unavailable)?;
        if !claimed {
            tracing::warn!(
                client_id = %client.client_id,
                gid = %record.gid,
                "an authorization code was presented again after it was redeemed; revoking its \
                 grant"
            );
            context.grant_events.push(GrantEvent::CodeReplay {
                gid: record.gid.clone(),
                client_id: client.client_id.clone(),
            });
            let revoked = self
                .revoke_grant(state, &record.gid, RevocationReason::CodeReplay)
                .await;
            context.grant_events.push(revoked);
            return Err(OAuthError::invalid_grant(
                "the authorization code has already been redeemed",
            ));
        }
        let active = ActiveGrant {
            authorization_details: Some(authorization_details),
            ..self
                .activate_grant(state, &record, &client, dpop_jkt, now, context)
                .await?
        };
        self.mint_for_grant(active, &client, now)
    }

    /// Activate the pending grant of `record`: `generation` 1, its absolute
    /// expiry from now, recorded among its user's grants; with a refresh
    /// token when the client may refresh it. Its access token is bound to
    /// `dpop_jkt`, and so is the grant of a public client. A grant revoked
    /// meanwhile, on any replica, issues nothing.
    async fn activate_grant(
        &self,
        state: &InteractiveState,
        record: &CodeRecord,
        client: &Client,
        dpop_jkt: Option<String>,
        now: u64,
        context: &mut RedemptionContext,
    ) -> Result<ActiveGrant, OAuthError> {
        let gid = record.gid.clone();
        let key = keys::grant(&gid);
        let mut grant = match state.get(&key).await.map_err(store_unavailable)? {
            Some(grant)
                if grant.status == GrantStatus::Pending
                    && grant.client_id == record.client_id
                    && grant.issuer == self.issuer =>
            {
                grant
            }
            _ => {
                return Err(OAuthError::invalid_grant(
                    "the sign-in behind this authorization code is no longer valid",
                ));
            }
        };
        self.grant_idp(&grant)?;
        let refresh = self
            .refresh_eligible(state, &grant, client)
            .await
            .map_err(store_unavailable)?;
        let absolute_ttl = self.interactive.refresh_tokens.absolute_ttl_secs;
        grant.status = GrantStatus::Active;
        grant.generation = 1;
        grant.abs_exp = now.saturating_add(absolute_ttl);
        grant.last_used = now;
        // RFC 9449 §5: a confidential client's refresh token is bound by
        // its client authentication, a public client's by the key.
        grant.dpop_jkt = dpop_jkt.clone().filter(|_| client.is_public());
        // A grant without a refresh token is needed only as long as its
        // access token is.
        let lifetime = if refresh {
            absolute_ttl
        } else {
            self.interactive
                .access_token_ttl_secs
                .saturating_add(self.leeway_secs)
        };
        let lifetime = Duration::from_secs(lifetime);
        state
            .put(&key, &grant, lifetime)
            .await
            .map_err(store_unavailable)?;
        state
            .put(
                &keys::principal_grant(&grant.principal, &gid),
                &PrincipalGrantRecord {
                    created: grant.created,
                },
                lifetime,
            )
            .await
            .map_err(store_unavailable)?;
        self.enforce_max_grants(state, &grant.principal, &gid, context)
            .await
            .map_err(store_unavailable)?;
        let refresh_token = if refresh {
            Some(self.issue_refresh_token(state, &gid, &grant, now).await?)
        } else {
            None
        };
        let revoked = state.is_revoked(&RevokedId::Grant(gid.clone()))
            || state
                .exists(&keys::revoked(&RevokedId::Grant(gid.clone())))
                .await
                .map_err(store_unavailable)?;
        if revoked {
            if let Some(ref token) = refresh_token {
                let _ = state.delete(&keys::refresh(token)).await;
            }
            return Err(OAuthError::invalid_grant(
                "the grant of this authorization code was revoked",
            ));
        }
        Ok(ActiveGrant {
            gid,
            grant,
            refresh_token,
            scope: None,
            dpop_jkt,
            authorization_details: None,
        })
    }

    /// The trusted IdP the user of `grant` signed in through, while the
    /// configuration still trusts it for the grant's client and user.
    fn grant_idp(&self, grant: &GrantRecord) -> Result<&super::IdpEntry, OAuthError> {
        self.trusted_for(
            &grant.identity.idp,
            &grant.client_id,
            grant.identity.tenant.as_deref(),
        )
        .map_err(|reason| OAuthError::invalid_grant(format!("the sign-in was for {reason}")))
    }

    /// Whether a new grant of `client` gets a refresh token: refresh
    /// tokens are on, the client's grant types hold `refresh_token`, and,
    /// while refreshes check the IdP, the user's stored IdP sign-in is of
    /// the login IdP and its client there and holds an IdP refresh token.
    async fn refresh_eligible(
        &self,
        state: &InteractiveState,
        grant: &GrantRecord,
        client: &Client,
    ) -> Result<bool, StateError> {
        let refresh = &self.interactive.refresh_tokens;
        if !refresh.enabled || !client.refresh_allowed() {
            return Ok(false);
        }
        if !refresh.revalidate_with_idp {
            return Ok(true);
        }
        let Some(login) = self.login_idp() else {
            return Ok(false);
        };
        Ok(state
            .get(&keys::idp_session(&grant.principal))
            .await?
            .is_some_and(|session| {
                session.issuer == login.issuer()
                    && session.client_id == login.client_id()
                    && session.refresh_token.is_some()
            }))
    }

    /// A new refresh token of the grant `gid` at its generation, recorded
    /// by its hash until the grant goes idle or ends.
    pub(super) async fn issue_refresh_token(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        grant: &GrantRecord,
        now: u64,
    ) -> Result<Zeroizing<String>, OAuthError> {
        let random = random_token().map_err(store_unavailable)?;
        let token = Zeroizing::new(format!("{REFRESH_TOKEN_PREFIX}{random}"));
        let ttl = self
            .interactive
            .refresh_tokens
            .idle_ttl_secs
            .min(grant.abs_exp.saturating_sub(now));
        let stored = state
            .put_if_absent(
                &keys::refresh(&token),
                &RefreshRecord {
                    gid: gid.clone(),
                    generation: grant.generation,
                    client_id: grant.client_id.clone(),
                },
                Duration::from_secs(ttl),
            )
            .await
            .map_err(store_unavailable)?;
        if !stored {
            tracing::error!("a refresh token collided with another; refusing it");
            return Err(OAuthError::temporarily_unavailable(
                "a refresh token could not be issued; retry shortly",
            ));
        }
        Ok(token)
    }

    /// Revoke every grant of `principal` for `reason`; the audit records.
    /// A store that cannot list them is logged, and the grants it could
    /// not name stay until they expire or are refreshed.
    pub(super) async fn revoke_principal_grants(
        &self,
        state: &InteractiveState,
        principal: &str,
        reason: RevocationReason,
    ) -> Vec<GrantEvent> {
        let limit = usize::try_from(self.interactive.refresh_tokens.max_grants_per_principal)
            .unwrap_or(usize::MAX)
            .saturating_add(PRINCIPAL_GRANTS_LIST_MARGIN);
        let mut events = Vec::new();
        let mut revoked: Vec<GrantId> = Vec::new();
        // A listing the store cuts short is read again once its grants
        // are gone from the index.
        for _ in 0..PRINCIPAL_GRANTS_LIST_ROUNDS {
            let listed = match state.list(&keys::principal_grants(principal), limit).await {
                Ok(listed) => listed,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        reason = reason.as_str(),
                        "the grants of a user could not be listed to revoke them"
                    );
                    break;
                }
            };
            let fresh: Vec<GrantId> = listed
                .into_iter()
                .filter_map(|(rest, _)| GrantId::parse(&rest))
                .filter(|gid| !revoked.contains(gid))
                .collect();
            if fresh.is_empty() {
                break;
            }
            for gid in fresh {
                events.push(self.revoke_grant(state, &gid, reason).await);
                // Also when the grant itself expired before its index entry.
                let _ = state.delete(&keys::principal_grant(principal, &gid)).await;
                revoked.push(gid);
            }
        }
        events
    }

    /// Revoke the oldest grants of `principal` beyond
    /// `refresh_tokens.max_grants_per_principal`, never `keep`.
    async fn enforce_max_grants(
        &self,
        state: &InteractiveState,
        principal: &str,
        keep: &GrantId,
        context: &mut RedemptionContext,
    ) -> Result<(), StateError> {
        let max = usize::try_from(self.interactive.refresh_tokens.max_grants_per_principal)
            .unwrap_or(usize::MAX);
        let listed = state
            .list(
                &keys::principal_grants(principal),
                max.saturating_add(PRINCIPAL_GRANTS_LIST_MARGIN),
            )
            .await?;
        let excess = listed.len().saturating_sub(max);
        if excess == 0 {
            return Ok(());
        }
        let mut others: Vec<(u64, GrantId)> = listed
            .into_iter()
            .filter_map(|(rest, record)| {
                GrantId::parse(&rest)
                    .filter(|gid| gid != keep)
                    .map(|gid| (record.created, gid))
            })
            .collect();
        others.sort();
        for (_, gid) in others.into_iter().take(excess) {
            let revoked = self
                .revoke_grant(state, &gid, RevocationReason::MaxGrants)
                .await;
            context.grant_events.push(revoked);
        }
        Ok(())
    }

    /// Revoke the grant `gid` for `reason`: refused by this replica at once
    /// and by the others from their next read of the store, for as long as
    /// any access token of the grant lives; the grant and its place among
    /// its user's grants are removed, so none of its refresh tokens
    /// redeems. A store failure is logged and counted, and this replica
    /// refuses the grant regardless. Returns the audit record.
    pub async fn revoke_grant(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        reason: RevocationReason,
    ) -> GrantEvent {
        self.revoke_grant_recorded(state, gid, reason).await.0
    }

    /// [`Self::revoke_grant`], and whether the store recorded it for the
    /// other replicas.
    pub(super) async fn revoke_grant_recorded(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        reason: RevocationReason,
    ) -> (GrantEvent, bool) {
        let key = keys::grant(gid);
        let grant = state.get(&key).await.ok().flatten();
        let until = now_unix()
            .saturating_add(self.interactive.access_token_ttl_secs)
            .saturating_add(self.leeway_secs);
        let mut stored = state
            .record_revocation(&RevokedId::Grant(gid.clone()), reason, until)
            .await
            .is_ok();
        stored &= state.delete(&key).await.is_ok();
        if let Some(ref grant) = grant {
            stored &= state
                .delete(&keys::principal_grant(&grant.principal, gid))
                .await
                .is_ok();
        }
        if !stored {
            tracing::error!(
                gid = %gid,
                reason = reason.as_str(),
                "a revoked grant could not be recorded in the sign-in state store; this replica \
                 refuses it, others may not"
            );
        }
        metrics::counter!(
            "mcpg_as_grants_revoked_total",
            "reason" => reason.as_str(),
            "outcome" => if stored { "ok" } else { "error" },
        )
        .increment(1);
        let event = GrantEvent::Revoked {
            gid: gid.clone(),
            reason,
            client_id: grant.map(|grant| grant.client_id),
        };
        (event, stored)
    }

    /// The access token of the grant `active`, as an ID-JAG redemption
    /// mints it for the same user, naming the grant, bound to the key
    /// `active` names and limited to its authorization details; it expires
    /// with the grant at the latest.
    pub(super) fn mint_for_grant(
        &self,
        active: ActiveGrant,
        client: &Client,
        now: u64,
    ) -> Result<(TokenResponse, IssuedToken), OAuthError> {
        let ActiveGrant {
            gid,
            grant,
            refresh_token,
            scope,
            dpop_jkt,
            authorization_details,
        } = active;
        let authorization_details =
            authorization_details.unwrap_or_else(|| grant.authorization_details.clone());
        let idp = self.grant_idp(&grant)?;
        let Principal {
            issuer: principal_issuer,
            auth_provider,
        } = Principal::of(&idp.config, grant.identity.tenant.as_deref());
        let exp = now
            .saturating_add(self.interactive.access_token_ttl_secs)
            .min(grant.abs_exp);
        let expires_in = exp.saturating_sub(now);
        let scope = Some(scope.unwrap_or(grant.scope).join(" ")).filter(|scope| !scope.is_empty());
        let identity = grant.identity;
        let roles = self.roles_for(&grant.client_id, &identity.roles);
        let minted = MintedClaims {
            iss: self.issuer.clone(),
            sub: identity.subject,
            aud: grant.resource.clone(),
            client_id: grant.client_id,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp,
            scope: scope.clone(),
            email: identity.email,
            idp: identity.idp,
            groups: identity.groups,
            roles: identity.roles,
            attributes: identity.attributes,
            act: None,
            tenant: identity.tenant,
            amr: identity.amr,
            gid: Some(gid.clone()),
            gty: Some(GRANT_TYPE_AUTHORIZATION_CODE.to_owned()),
            auth_time: identity.auth_time,
            cnf: Confirmation::of(dpop_jkt.clone()),
            authorization_details,
        };
        let access_token = self.signing_keys[0].sign(&minted).map_err(minting_failed)?;
        let issued = IssuedToken {
            subject: minted.sub,
            actor: None,
            jti: minted.jti,
            assertion_jti: None,
            scope: scope.clone(),
            resource: grant.resource.clone(),
            expires_in,
            roles,
            groups: minted.groups,
            grant: Some(IssuedGrant {
                gid,
                client_kind: client.kind(),
                principal_issuer,
                auth_provider,
                refresh_token_issued: refresh_token.is_some(),
            }),
            dpop_jkt,
            authorization_details_digest: self.details_digest(&minted.authorization_details),
            authorization_details: minted.authorization_details,
        };
        let response = TokenResponse {
            access_token,
            token_type: issued.token_type(),
            expires_in,
            scope,
            resource: grant.resource,
            refresh_token: refresh_token.map(|token| token.as_str().to_owned()),
            authorization_details: issued.authorization_details.clone(),
        };
        Ok((response, issued))
    }
}
