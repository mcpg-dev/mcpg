//! Token revocation (RFC 7009) at `POST /oauth/revoke`, offered with
//! interactive sign-in.
//!
//! The client authenticates as at the token endpoint and names a token it
//! was issued. A refresh token revokes its grant; so does an access token
//! of a grant, whether or not it has expired. An access token an ID-JAG
//! redemption minted names no grant: its `jti` is revoked until it
//! expires. Every replica refuses what is revoked here within
//! `interactive.revocation_check_interval_secs`, this one at once. When
//! the user holds no other grant, the IdP sign-in an MCP client's sign-in
//! stored for them ends too, and its IdP refresh token is revoked at the
//! IdP.
//!
//! A token of another client is refused and revokes nothing; a token this
//! server does not know answers as revoked (RFC 7009 §2.2). A client whose
//! dynamic registration is gone cannot authenticate, and the grant its
//! token names is revoked all the same ([`super::dcr`]). The
//! `token_type_hint` only orders a search, and every token here is told
//! apart by its form, so it is not read.
//!
//! Nothing here logs or audits a token.

use serde::Deserialize;

use super::clients::Client;
use super::dcr::Presented;
use super::grants::{
    GRANT_TYPE_AUTHORIZATION_CODE, GrantEvent, REFRESH_TOKEN_PREFIX, store_unavailable,
};
use super::interactive::SupersededSignIn;
use super::state::{GrantId, InteractiveState, RevocationReason, RevokedId, keys};
use super::{
    AuthorizationServer, OAuthError, RedemptionContext, TokenRequestForm, now_unix,
    unverified_claim_iss,
};

/// Path of the revocation endpoint.
pub const REVOCATION_PATH: &str = "/oauth/revoke";
/// Longest token looked up; every one this server issues is shorter.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Parsed `POST /oauth/revoke` form body (RFC 7009 §2.1).
#[derive(Default, Deserialize)]
pub struct RevocationRequestForm {
    pub token: Option<String>,
    /// `refresh_token` or `access_token`; not read.
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

impl std::fmt::Debug for RevocationRequestForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let present = |value: &Option<String>| value.as_ref().map(|_| "[redacted]");
        f.debug_struct("RevocationRequestForm")
            .field("token", &present(&self.token))
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field("client_secret", &present(&self.client_secret))
            .field("client_assertion_type", &self.client_assertion_type)
            .field("client_assertion", &present(&self.client_assertion))
            .finish()
    }
}

/// What kind of token a revocation request named, as a bounded metric
/// label.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RevokedTokenKind {
    /// None was read: the request stopped before.
    #[default]
    None,
    RefreshToken,
    AccessToken,
    /// A value this server did not issue.
    Unknown,
}

impl RevokedTokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RefreshToken => "refresh_token",
            Self::AccessToken => "access_token",
            Self::Unknown => "unknown",
        }
    }
}

/// The outcome of one `POST /oauth/revoke` request.
#[derive(Debug)]
pub struct TokenRevocation {
    /// `Ok` is answered 200 with no body, whether or not anything was
    /// revoked.
    pub result: Result<(), OAuthError>,
    /// The client, the login IdP, the grant, and what was revoked.
    pub context: RedemptionContext,
    pub token_kind: RevokedTokenKind,
    /// An IdP refresh token the gateway released: revoke it at the IdP
    /// with [`AuthorizationServer::revoke_superseded`] once the answer is
    /// sent.
    pub released: Option<SupersededSignIn>,
}

impl TokenRevocation {
    /// A request body the endpoint cannot parse.
    pub fn malformed(description: String) -> Self {
        let revocation = Self {
            result: Err(OAuthError::new("invalid_request", description)),
            context: RedemptionContext::default(),
            token_kind: RevokedTokenKind::None,
            released: None,
        };
        revocation.record();
        revocation
    }

    /// Every audit record of the request: what it revoked, then, when it
    /// was refused, `mcpg.auth.failed` with `auth_method` `as_revoke`.
    pub fn audit_events(&self, request_id: &str) -> Vec<mcpg_plugin_protocol::audit::AuditEvent> {
        let mut events: Vec<_> = self
            .context
            .grant_events
            .iter()
            .map(|event| event.event(request_id))
            .collect();
        if let Err(ref error) = self.result {
            let mut event = mcpg_plugin_host::audit_events::auth_failed_event(
                "as_revoke",
                &format!("{}: {}", error.error, error.description),
                request_id,
                "http",
            );
            event.details["error"] = serde_json::json!(error.error);
            event.details["client_id"] = serde_json::json!(self.context.client_id);
            event.details["token_type"] = serde_json::json!(self.token_kind.as_str());
            event.details["gid"] =
                serde_json::json!(self.context.gid.as_ref().map(GrantId::as_str));
            events.push(event);
        }
        events
    }

    fn record(&self) {
        let revoked = self.context.grant_events.iter().any(|event| {
            matches!(
                event,
                GrantEvent::Revoked { .. } | GrantEvent::TokenRevoked { .. }
            )
        });
        let outcome = match self.result {
            Ok(()) if revoked => "revoked",
            Ok(()) => "unknown",
            Err(ref error) if error.status >= 500 => "failed",
            Err(_) => "refused",
        };
        metrics::counter!(
            "mcpg_as_revocations_total",
            "token_type" => self.token_kind.as_str(),
            "outcome" => outcome,
        )
        .increment(1);
    }
}

impl AuthorizationServer {
    /// Answer `POST /oauth/revoke` (RFC 7009 §2.1). `basic_auth` is the raw
    /// `Authorization` header value, if any. The caller has checked that
    /// a login IdP exists and the client address's budget.
    pub async fn revoke_token(
        &self,
        form: RevocationRequestForm,
        basic_auth: Option<&str>,
    ) -> TokenRevocation {
        let mut revocation = TokenRevocation {
            result: Ok(()),
            context: RedemptionContext::default(),
            token_kind: RevokedTokenKind::None,
            released: None,
        };
        if let Some(login) = self.login_idp() {
            revocation.context.idp = Some(login.issuer().to_owned());
        }
        revocation.result = self.revoke(form, basic_auth, &mut revocation).await;
        // Only a token the client held revokes something; an unknown one is
        // answered alike but does not count as using the registration.
        if revocation.result.is_ok()
            && !revocation.context.grant_events.is_empty()
            && let Some(ref client_id) = revocation.context.client_id
        {
            self.renew_registration(client_id).await;
        }
        revocation.record();
        revocation
    }

    async fn revoke(
        &self,
        form: RevocationRequestForm,
        basic_auth: Option<&str>,
        revocation: &mut TokenRevocation,
    ) -> Result<(), OAuthError> {
        let RevocationRequestForm {
            token,
            client_id,
            client_secret,
            client_assertion_type,
            client_assertion,
            ..
        } = form;
        let credentials = TokenRequestForm {
            client_id,
            client_secret,
            client_assertion_type,
            client_assertion,
            ..TokenRequestForm::default()
        };
        let client = match self.authenticate(&credentials, basic_auth).await {
            Ok(client) => client,
            Err(error) => {
                let presented = token.as_deref().unwrap_or_default();
                let presented = if presented.starts_with(REFRESH_TOKEN_PREFIX) {
                    Presented::RefreshToken(presented)
                } else {
                    Presented::AccessToken(presented)
                };
                if let Some(event) = self
                    .end_removed_registration(credentials.client_id.as_deref(), presented)
                    .await
                {
                    revocation.context.grant_events.push(event);
                }
                return Err(error);
            }
        };
        revocation.context.client_id = Some(client.client_id.clone());
        let token = token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| OAuthError::new("invalid_request", "token is required"))?;
        let state = self.grant_state()?;
        if token.len() > MAX_TOKEN_BYTES {
            revocation.token_kind = RevokedTokenKind::Unknown;
            return Ok(());
        }
        if token.starts_with(REFRESH_TOKEN_PREFIX) {
            revocation.token_kind = RevokedTokenKind::RefreshToken;
            self.revoke_refresh_token(state, &token, &client, revocation)
                .await
        } else if unverified_claim_iss(&token).is_some_and(|iss| iss == self.issuer) {
            revocation.token_kind = RevokedTokenKind::AccessToken;
            self.revoke_access_token(state, &token, &client, revocation)
                .await
        } else {
            revocation.token_kind = RevokedTokenKind::Unknown;
            Ok(())
        }
    }

    /// Revoke the grant of a refresh token of `client`, live or spent.
    async fn revoke_refresh_token(
        &self,
        state: &InteractiveState,
        token: &str,
        client: &Client,
        revocation: &mut TokenRevocation,
    ) -> Result<(), OAuthError> {
        let live = state
            .get(&keys::refresh(token))
            .await
            .map_err(store_unavailable)?;
        let gid = match live {
            Some(ref index) => {
                if index.client_id != client.client_id {
                    return Err(issued_to_another_client());
                }
                index.gid.clone()
            }
            None => match state
                .get(&keys::refresh_used(token))
                .await
                .map_err(store_unavailable)?
            {
                Some(spent) => spent.gid,
                None => return Ok(()),
            },
        };
        self.revoke_client_grant(state, &gid, client, revocation)
            .await?;
        if live.is_some() {
            let _ = state.delete(&keys::refresh(token)).await;
        }
        Ok(())
    }

    /// Revoke an access token this server minted for `client`: its grant,
    /// or, for one without a grant, its `jti` until it expires. An
    /// expired token of a grant still revokes the grant (RFC 7009 §2.1).
    async fn revoke_access_token(
        &self,
        state: &InteractiveState,
        token: &str,
        client: &Client,
        revocation: &mut TokenRevocation,
    ) -> Result<(), OAuthError> {
        let Ok(claims) = self.decode_minted_with(token, false) else {
            return Ok(());
        };
        if claims.client_id != client.client_id {
            return Err(issued_to_another_client());
        }
        match (claims.gty.as_deref(), claims.gid) {
            (Some(GRANT_TYPE_AUTHORIZATION_CODE), Some(gid)) => {
                self.revoke_client_grant(state, &gid, client, revocation)
                    .await
            }
            (None, None) => {
                let until = claims.exp.saturating_add(self.leeway_secs);
                if until <= now_unix() {
                    return Ok(());
                }
                state
                    .record_revocation(
                        &RevokedId::access_token(&claims.jti),
                        RevocationReason::Client,
                        until,
                    )
                    .await
                    .map_err(store_unavailable)?;
                revocation
                    .context
                    .grant_events
                    .push(GrantEvent::TokenRevoked {
                        jti: claims.jti,
                        client_id: client.client_id.clone(),
                    });
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Revoke the grant `gid` when `client` holds it, and release the
    /// user's stored IdP sign-in with their last grant. A grant already
    /// gone revokes nothing.
    async fn revoke_client_grant(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        client: &Client,
        revocation: &mut TokenRevocation,
    ) -> Result<(), OAuthError> {
        let Some(grant) = state
            .get(&keys::grant(gid))
            .await
            .map_err(store_unavailable)?
        else {
            return Ok(());
        };
        revocation.context.gid = Some(gid.clone());
        if grant.client_id != client.client_id {
            return Err(issued_to_another_client());
        }
        let (event, stored) = self
            .revoke_grant_recorded(state, gid, RevocationReason::Client)
            .await;
        revocation.context.grant_events.push(event);
        if !stored {
            return Err(OAuthError::temporarily_unavailable(
                "the revocation could not be recorded for every replica; retry shortly",
            ));
        }
        revocation.released = self
            .release_idp_session(
                state,
                &grant.principal,
                &mut revocation.context.grant_events,
            )
            .await;
        Ok(())
    }
}

fn issued_to_another_client() -> OAuthError {
    OAuthError::invalid_grant("the token was issued to another client")
}
