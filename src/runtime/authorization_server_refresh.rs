//! The `refresh_token` grant of interactive sign-in (OAuth 2.1 §4.3).
//!
//! Every refresh rotates the token (RFC 9700 §4.14.2). A refresh token is
//! spent once, only by the client it was issued to, while its grant lives,
//! was used within `idle_ttl_secs` and is younger than `absolute_ttl_secs`,
//! and while the configuration still admits the grant's client, IdP and
//! tenant; a grant no longer admitted is revoked, and so is one whose
//! dynamic registration is gone ([`super::dcr`]). A spent token presented
//! again revokes the grant, unless `reuse_grace_secs` lets a client that
//! lost an answer receive the same successor once more. A `scope` and
//! `authorization_details` (RFC 9396 §6) may only narrow the new access
//! token, never the grant; a `resource` must be the grant's.
//!
//! While refreshes check the IdP, the user's stored IdP sign-in is
//! refreshed at the IdP at most every `revalidate_interval_secs`, one
//! request per user at a time ([`super::vault`]). An IdP that refuses it
//! ends every grant of the user. An IdP that cannot be reached is tolerated
//! for `idp_unavailable_grace_secs` past the interval; after that the
//! refresh answers 503 and the token stays unspent, so the client retries
//! it. The stored ID token's claims, as the IdP's claim mappings read them,
//! become the claims of the grant's next access tokens.
//!
//! A grant bound to a DPoP key redeems its refresh tokens only with a
//! proof of that key, checked before the token is spent, so a refused
//! request leaves the token as it was. A refresh with a proof receives an
//! access token bound to the proof's key, and binds a public client's
//! unbound grant to it (RFC 9449 §5). A spent token issued bound to the
//! key and presented without it is refused without revoking the grant; a
//! spent token issued before the binding revokes the grant as any reuse
//! does, whatever key it comes with, so whoever spent it first cannot keep
//! the grant by binding it to their key.
//!
//! Nothing here logs or audits a token or a proof.

use std::time::{Duration, Instant};

use base64::Engine as _;
use mcpg_plugin_host::credential_cache_cipher::EventCipher;
use zeroize::Zeroizing;

use super::clients::Client;
use super::dcr::Presented;
use super::dpop::ProvenKey;
use super::grants::{ActiveGrant, GrantEvent, REFRESH_TOKEN_PREFIX, store_unavailable};
use super::interactive::PROTOCOL_SCOPES;
use super::rar::{AuthorizationDetails, DetailsSource};
use super::state::{
    GrantId, GrantRecord, GrantStatus, IdpSessionRecord, InteractiveState, RefreshUsedRecord,
    RevocationReason, RevokedId, keys,
};
use super::vault::SessionCheck;
use super::{
    AuthorizationServer, IssuedToken, MappedIdentity, OAuthError, RedemptionContext,
    TokenRequestForm, TokenResponse, idp_admits_client, now_unix, unverified_payload,
};

/// Longest refresh token looked up; every one this server issues is much
/// shorter.
const MAX_REFRESH_TOKEN_BYTES: usize = 128;
/// How long a refresh that lost the race for its token waits for the
/// winner's successor while `reuse_grace_secs` is on: the winner may be
/// checking the IdP.
const SUCCESSOR_WAIT: Duration = Duration::from_secs(10);
const SUCCESSOR_POLL: Duration = Duration::from_millis(100);
/// RFC 5869 `info` of the key a successor is sealed under, derived from
/// the spent token, so only its holder can open it.
const SUCCESSOR_KEY_INFO: &[u8] = b"mcpg as rt successor v1";
const SUCCESSOR_KID: &str = "rt";

/// How a refresh request ended, as a bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOutcome {
    /// A new refresh token was issued.
    Rotated,
    /// Issued while the IdP could not be reached, within the grace.
    IdpUnavailableGrace,
    /// The same successor was issued again, within `reuse_grace_secs`.
    Grace,
    /// A spent token was presented again, and the grant revoked.
    ReuseRevoked,
    /// An unknown, spent-and-gone, idle or expired token or grant.
    Expired,
    /// A request refused without touching the grant.
    Refused,
    /// The grant was revoked: its client or IdP is no longer admitted, or
    /// its stored IdP sign-in is gone.
    Revoked,
    /// The IdP refused the user's sign-in, and every grant of theirs was
    /// revoked.
    IdpRefused,
    /// The IdP could not be reached past the grace.
    IdpUnavailableRefused,
    /// The store failed.
    Error,
}

impl RefreshOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::IdpUnavailableGrace => "idp_unavailable_grace",
            Self::Grace => "grace",
            Self::ReuseRevoked => "reuse_revoked",
            Self::Expired => "expired",
            Self::Refused => "refused",
            Self::Revoked => "revoked",
            Self::IdpRefused => "idp_refused",
            Self::IdpUnavailableRefused => "idp_unavailable_refused",
            Self::Error => "error",
        }
    }
}

/// Why a refresh stops, and whether its token's claim is released so the
/// client can present it again.
struct Stop {
    error: OAuthError,
    outcome: RefreshOutcome,
    unclaim: bool,
}

impl Stop {
    fn new(error: OAuthError, outcome: RefreshOutcome) -> Self {
        Self {
            error,
            outcome,
            unclaim: false,
        }
    }

    fn expired(error: OAuthError) -> Self {
        Self::new(error, RefreshOutcome::Expired)
    }

    fn revoked(error: OAuthError) -> Self {
        Self::new(error, RefreshOutcome::Revoked)
    }

    /// A failure after the token was claimed that leaves the grant as it
    /// was: the claim is released.
    fn retryable(error: OAuthError, outcome: RefreshOutcome) -> Self {
        Self {
            error,
            outcome,
            unclaim: true,
        }
    }
}

impl From<OAuthError> for Stop {
    fn from(error: OAuthError) -> Self {
        let outcome = if error.status >= 500 {
            RefreshOutcome::Error
        } else {
            RefreshOutcome::Refused
        };
        Self::new(error, outcome)
    }
}

fn unknown_refresh_token() -> OAuthError {
    OAuthError::invalid_grant("the refresh token is invalid, expired or was revoked")
}

/// What a refresh request asks for beside its token, and the DPoP proof it
/// carries.
struct Wanted<'a> {
    scope: Option<&'a str>,
    resource: Option<&'a str>,
    authorization_details: Option<&'a str>,
    proof: Option<&'a ProvenKey>,
}

/// What the new access token of a refresh carries, as the request narrowed
/// the grant: its scopes, its authorization details and its DPoP key.
struct Narrowed {
    scope: Vec<String>,
    authorization_details: AuthorizationDetails,
    dpop_jkt: Option<String>,
}

/// What the key check of a refresh names the binding it checks against.
const REFRESH_BINDING: &str = "the refresh token";

/// The key a successor is sealed under: RFC 5869 over the spent token.
fn successor_key(spent: &str) -> Option<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, spent.as_bytes())
        .expand(SUCCESSOR_KEY_INFO, key.as_mut())
        .ok()?;
    Some(key)
}

fn seal_successor(spent: &str, successor: &str, aad: &[u8]) -> Option<String> {
    let key = successor_key(spent)?;
    let sealed = EventCipher::from_raw_key(&key, SUCCESSOR_KID.to_owned())
        .ok()?
        .seal(successor.as_bytes(), aad)
        .ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed))
}

fn open_successor(spent: &str, sealed: &str, aad: &[u8]) -> Option<Zeroizing<String>> {
    let key = successor_key(spent)?;
    let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sealed)
        .ok()?;
    let opened = Zeroizing::new(
        EventCipher::from_raw_key(&key, SUCCESSOR_KID.to_owned())
            .ok()?
            .open(&sealed, aad)
            .ok()?,
    );
    String::from_utf8(opened.to_vec()).ok().map(Zeroizing::new)
}

/// The store TTL of a record that lives as long as a grant ending at
/// `abs_exp` can.
fn until(abs_exp: u64, now: u64) -> Duration {
    Duration::from_secs(abs_exp.saturating_sub(now))
}

/// Whether the spent token `spent` of `grant` was issued bound to the
/// grant's DPoP key, so that only a proof of the key may retry it.
fn spent_under_binding(grant: &GrantRecord, spent: &RefreshUsedRecord) -> bool {
    grant.dpop_jkt.is_some() && spent.generation >= grant.dpop_bound_generation
}

impl AuthorizationServer {
    /// Redeem a refresh token (OAuth 2.1 §4.3): the client and its grant
    /// types; the token known, issued to this client, and its grant alive
    /// and still admitted; the scope, resource and authorization details;
    /// the DPoP `proof` against the grant's key; then the token is spent
    /// once, the user's IdP sign-in checked when due, and a successor
    /// issued with a new access token.
    pub(super) async fn redeem_refresh(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        proof: Option<&ProvenKey>,
        context: &mut RedemptionContext,
    ) -> Result<(TokenResponse, IssuedToken), OAuthError> {
        let (result, outcome) = match self.refresh(form, basic_auth, proof, context).await {
            Ok((answer, outcome)) => (Ok(answer), outcome),
            Err(stop) => (Err(stop.error), stop.outcome),
        };
        metrics::counter!("mcpg_as_refresh_total", "outcome" => outcome.as_str()).increment(1);
        result
    }

    async fn refresh(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        proof: Option<&ProvenKey>,
        context: &mut RedemptionContext,
    ) -> Result<((TokenResponse, IssuedToken), RefreshOutcome), Stop> {
        if let Some(login) = self.login_idp() {
            context.idp = Some(login.issuer().to_owned());
        }
        let client = match self.authenticate(&form, basic_auth).await {
            Ok(client) => client,
            Err(error) => {
                let Some(event) = self
                    .end_removed_registration(
                        form.client_id.as_deref(),
                        Presented::RefreshToken(form.refresh_token.as_deref().unwrap_or_default()),
                    )
                    .await
                else {
                    return Err(error.into());
                };
                context.grant_events.push(event);
                return Err(Stop::revoked(error));
            }
        };
        context.client_id = Some(client.client_id.clone());
        if client.code_grant_refusal().is_some() || !client.refresh_allowed() {
            return Err(OAuthError::new(
                "unauthorized_client",
                "this client may not refresh: its grant types lack refresh_token",
            )
            .into());
        }
        let token = form
            .refresh_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| OAuthError::new("invalid_request", "refresh_token is required"))?;
        let state = self.grant_state()?;
        if !token.starts_with(REFRESH_TOKEN_PREFIX) || token.len() > MAX_REFRESH_TOKEN_BYTES {
            return Err(Stop::expired(unknown_refresh_token()));
        }
        let wanted = Wanted {
            scope: form.scope.as_deref(),
            resource: form.resource.as_deref(),
            authorization_details: form.authorization_details.as_deref(),
            proof,
        };
        let now = now_unix();
        let spent_key = keys::refresh_used(token);
        let Some(index) = state
            .get(&keys::refresh(token))
            .await
            .map_err(store_unavailable)?
        else {
            return match state.get(&spent_key).await.map_err(store_unavailable)? {
                Some(spent) => {
                    self.reused(state, token, spent, &client, &wanted, now, context)
                        .await
                }
                None => Err(Stop::expired(unknown_refresh_token())),
            };
        };
        context.gid = Some(index.gid.clone());
        if index.client_id != client.client_id {
            return Err(Stop::new(
                OAuthError::invalid_grant("the refresh token was issued to another client"),
                RefreshOutcome::Refused,
            ));
        }
        let grant = self.live_grant(state, &index.gid, now).await?;
        if index.generation < grant.generation {
            let spent = state
                .get(&spent_key)
                .await
                .map_err(store_unavailable)?
                .unwrap_or(RefreshUsedRecord {
                    gid: index.gid.clone(),
                    spent_at: 0,
                    generation: index.generation,
                    successor_sealed: None,
                });
            return self
                .reused(state, token, spent, &client, &wanted, now, context)
                .await;
        }
        if index.generation != grant.generation {
            return Err(Stop::expired(unknown_refresh_token()));
        }
        self.admit_refresh(state, &index.gid, &grant, context)
            .await?;
        let scope = refresh_scope(&grant, &wanted)?;
        let authorization_details = self.refresh_details(&grant, &wanted)?;
        let dpop_jkt = self.refresh_binding(&grant, &client, &wanted)?;
        let claimed = state
            .put_if_absent(
                &spent_key,
                &RefreshUsedRecord {
                    gid: index.gid.clone(),
                    spent_at: now,
                    generation: index.generation,
                    successor_sealed: None,
                },
                until(grant.abs_exp, now),
            )
            .await
            .map_err(store_unavailable)?;
        if !claimed {
            let Some(spent) = state.get(&spent_key).await.map_err(store_unavailable)? else {
                return Err(retry_shortly().into());
            };
            return self
                .reused(state, token, spent, &client, &wanted, now, context)
                .await;
        }
        let narrowed = Narrowed {
            scope,
            authorization_details,
            dpop_jkt,
        };
        match self
            .rotate(
                state, token, &index.gid, grant, &client, narrowed, now, context,
            )
            .await
        {
            Ok(answer) => Ok(answer),
            Err(stop) => {
                if stop.unclaim {
                    let _ = state.unclaim(&spent_key).await;
                }
                Err(stop)
            }
        }
    }

    /// The grant `gid` while a refresh may use it: active, of this issuer,
    /// not revoked on any replica that wrote it down, younger than its
    /// absolute lifetime and used within the idle one.
    async fn live_grant(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        now: u64,
    ) -> Result<GrantRecord, Stop> {
        let grant = state
            .get(&keys::grant(gid))
            .await
            .map_err(store_unavailable)?
            .filter(|grant| grant.status == GrantStatus::Active && grant.issuer == self.issuer)
            .ok_or_else(|| Stop::expired(unknown_refresh_token()))?;
        let revoked = RevokedId::Grant(gid.clone());
        if state.is_revoked(&revoked)
            || state
                .exists(&keys::revoked(&revoked))
                .await
                .map_err(store_unavailable)?
        {
            return Err(Stop::expired(unknown_refresh_token()));
        }
        if now >= grant.abs_exp {
            return Err(Stop::expired(OAuthError::invalid_grant(
                "the sign-in reached its absolute lifetime; sign in again",
            )));
        }
        if now.saturating_sub(grant.last_used) > self.interactive.refresh_tokens.idle_ttl_secs {
            return Err(Stop::expired(OAuthError::invalid_grant(
                "the sign-in went unused for too long; sign in again",
            )));
        }
        Ok(grant)
    }

    /// Revoke the grant `gid` unless the configuration still admits it:
    /// its IdP still offers sign-in, still admits its client, which is
    /// still known, and still trusts its user's tenant.
    async fn admit_refresh(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        grant: &GrantRecord,
        context: &mut RedemptionContext,
    ) -> Result<(), Stop> {
        let refusal = match self.login_idp() {
            Some(login) if login.issuer() == grant.identity.idp => {
                let idp = login.idp();
                let client_admitted =
                    self.knows_client(&grant.client_id) && idp_admits_client(idp, &grant.client_id);
                let tenant_admitted = idp
                    .required_tenant
                    .as_deref()
                    .is_none_or(|required| grant.identity.tenant.as_deref() == Some(required));
                if !client_admitted {
                    Some((
                        RevocationReason::ClientRemoved,
                        "the client may no longer use this sign-in",
                    ))
                } else if !tenant_admitted {
                    Some((
                        RevocationReason::IdpRemoved,
                        "the enterprise IdP is no longer trusted for this user's tenant",
                    ))
                } else {
                    None
                }
            }
            _ => Some((
                RevocationReason::IdpRemoved,
                "the enterprise IdP of this sign-in no longer offers sign-in",
            )),
        };
        let Some((reason, description)) = refusal else {
            return Ok(());
        };
        context
            .grant_events
            .push(self.revoke_grant(state, gid, reason).await);
        Err(Stop::revoked(OAuthError::invalid_grant(description)))
    }

    /// The key the access token of a refresh of `grant` by `client` is
    /// bound to, as [`AuthorizationServer::proof_binding`] decides it for
    /// the grant's key; a refusal leaves the refresh token unspent.
    fn refresh_binding(
        &self,
        grant: &GrantRecord,
        client: &Client,
        wanted: &Wanted<'_>,
    ) -> Result<Option<String>, Stop> {
        self.proof_binding(
            grant.dpop_jkt.as_deref(),
            wanted.proof,
            client,
            REFRESH_BINDING,
        )
        .map_err(|error| Stop::new(error, RefreshOutcome::Refused))
    }

    /// The authorization details of the access token of a refresh of
    /// `grant`: the grant's, or the narrowing of them the request asks
    /// for; a refusal leaves the refresh token unspent.
    fn refresh_details(
        &self,
        grant: &GrantRecord,
        wanted: &Wanted<'_>,
    ) -> Result<AuthorizationDetails, Stop> {
        self.requested_details(
            &grant.authorization_details,
            wanted.authorization_details,
            DetailsSource::Refresh,
        )
        .map_err(|error| Stop::new(error, RefreshOutcome::Refused))
    }

    /// With the token spent: check the user's IdP sign-in when due, issue
    /// the successor at the next generation, and mint the access token
    /// `narrowed` describes. A public client's grant without a key is bound
    /// to its key from the successor on. Until the grant is written, a
    /// failure releases the token; after, the rotation stands.
    #[allow(clippy::too_many_arguments)]
    async fn rotate(
        &self,
        state: &InteractiveState,
        spent: &str,
        gid: &GrantId,
        mut grant: GrantRecord,
        client: &Client,
        narrowed: Narrowed,
        now: u64,
        context: &mut RedemptionContext,
    ) -> Result<((TokenResponse, IssuedToken), RefreshOutcome), Stop> {
        let Narrowed {
            scope,
            authorization_details,
            dpop_jkt,
        } = narrowed;
        let within_grace = self
            .revalidate(state, gid, &mut grant, now, context)
            .await?;
        let spent_generation = grant.generation;
        grant.generation = grant.generation.saturating_add(1);
        grant.last_used = now;
        if grant.dpop_jkt.is_none() && client.is_public() && dpop_jkt.is_some() {
            grant.dpop_jkt = dpop_jkt.clone();
            grant.dpop_bound_generation = grant.generation;
        }
        let successor = self
            .issue_refresh_token(state, gid, &grant, now)
            .await
            .map_err(|error| Stop::retryable(error, RefreshOutcome::Error))?;
        if let Err(error) = state
            .put(&keys::grant(gid), &grant, until(grant.abs_exp, now))
            .await
        {
            let _ = state.delete(&keys::refresh(&successor)).await;
            return Err(Stop::retryable(
                store_unavailable(error),
                RefreshOutcome::Error,
            ));
        }
        if self.interactive.refresh_tokens.reuse_grace_secs > 0 {
            let sealed = seal_successor(spent, &successor, &self.successor_aad(gid));
            let stored = match sealed {
                Some(sealed) => state
                    .put(
                        &keys::refresh_used(spent),
                        &RefreshUsedRecord {
                            gid: gid.clone(),
                            spent_at: now,
                            generation: spent_generation,
                            successor_sealed: Some(sealed),
                        },
                        until(grant.abs_exp, now),
                    )
                    .await
                    .is_ok(),
                None => false,
            };
            if !stored {
                tracing::warn!(
                    gid = %gid,
                    "a refresh token's successor could not be kept for a retry; a retry revokes \
                     the grant"
                );
            }
        }
        let _ = state.delete(&keys::refresh(spent)).await;
        let revoked = RevokedId::Grant(gid.clone());
        if state.is_revoked(&revoked)
            || state
                .exists(&keys::revoked(&revoked))
                .await
                .map_err(store_unavailable)?
        {
            let _ = state.delete(&keys::refresh(&successor)).await;
            let _ = state.delete(&keys::grant(gid)).await;
            return Err(Stop::expired(OAuthError::invalid_grant(
                "the grant of this refresh token was revoked",
            )));
        }
        let minted = self.mint_for_grant(
            ActiveGrant {
                gid: gid.clone(),
                grant,
                refresh_token: Some(successor),
                scope: Some(scope),
                dpop_jkt,
                authorization_details: Some(authorization_details),
            },
            client,
            now,
        )?;
        let outcome = if within_grace {
            RefreshOutcome::IdpUnavailableGrace
        } else {
            RefreshOutcome::Rotated
        };
        Ok((minted, outcome))
    }

    /// While refreshes check the IdP: the user's stored sign-in, refreshed
    /// at the IdP when `revalidate_interval_secs` has passed since its last
    /// check, and its ID token's claims read into `grant`. Returns whether
    /// the IdP could not be reached and the grant is served within
    /// `idp_unavailable_grace_secs`.
    async fn revalidate(
        &self,
        state: &InteractiveState,
        gid: &GrantId,
        grant: &mut GrantRecord,
        now: u64,
        context: &mut RedemptionContext,
    ) -> Result<bool, Stop> {
        let refresh = &self.interactive.refresh_tokens;
        if !refresh.revalidate_with_idp {
            return Ok(false);
        }
        let interval = self.interactive.revalidate_interval_secs();
        let checked = self
            .check_idp_session(state, &grant.principal, |record, now| {
                now.saturating_sub(record.last_refreshed) >= interval
            })
            .await
            .map_err(|error| Stop::retryable(store_unavailable(error), RefreshOutcome::Error))?;
        let (record, within_grace) = match checked {
            SessionCheck::Fresh { record } => (record, false),
            SessionCheck::Unavailable { record, reason } => {
                let tolerated = interval.saturating_add(refresh.idp_unavailable_grace_secs);
                if now.saturating_sub(record.last_refreshed) > tolerated {
                    tracing::warn!(
                        gid = %gid,
                        reason = %reason,
                        "the login IdP cannot be reached to check a sign-in, past the \
                         unavailability grace; refusing the refresh"
                    );
                    return Err(Stop::retryable(
                        OAuthError::temporarily_unavailable(
                            "the enterprise IdP cannot be reached to check the sign-in; retry \
                             shortly",
                        ),
                        RefreshOutcome::IdpUnavailableRefused,
                    ));
                }
                tracing::info!(
                    gid = %gid,
                    reason = %reason,
                    "the login IdP cannot be reached to check a sign-in; refreshing within the \
                     unavailability grace"
                );
                (record, true)
            }
            SessionCheck::Missing => {
                context.grant_events.push(
                    self.revoke_grant(state, gid, RevocationReason::IdpSessionExpired)
                        .await,
                );
                return Err(Stop::revoked(OAuthError::invalid_grant(
                    "the sign-in at the enterprise IdP is no longer kept; sign in again",
                )));
            }
            SessionCheck::Ended { events } => {
                let revoked = events.iter().any(
                    |event| matches!(event, GrantEvent::Revoked { gid: revoked, .. } if revoked == gid),
                );
                context.grant_events.extend(events);
                if !revoked {
                    context.grant_events.push(
                        self.revoke_grant(state, gid, RevocationReason::IdpRefused)
                            .await,
                    );
                }
                return Err(Stop::new(
                    OAuthError::invalid_grant(
                        "the enterprise IdP no longer accepts this sign-in; sign in again",
                    ),
                    RefreshOutcome::IdpRefused,
                ));
            }
        };
        if let Err(problem) = self.read_identity(grant, &record) {
            tracing::warn!(gid = %gid, problem, "revoking a grant whose user the IdP now names differently");
            context.grant_events.push(
                self.revoke_grant(state, gid, RevocationReason::IdpRefused)
                    .await,
            );
            return Err(Stop::new(
                OAuthError::invalid_grant(
                    "the enterprise IdP now names another user for this sign-in; sign in again",
                ),
                RefreshOutcome::IdpRefused,
            ));
        }
        Ok(within_grace)
    }

    /// Read the claims of the stored sign-in's ID token, which was
    /// verified before it was stored, into the user `grant` names: groups,
    /// roles, attributes, email, `amr` and `auth_time`. The user and
    /// tenant must stay the same.
    fn read_identity(
        &self,
        grant: &mut GrantRecord,
        record: &IdpSessionRecord,
    ) -> Result<(), &'static str> {
        let (Some(claims), Some(login)) = (
            unverified_payload(record.id_token.expose()),
            self.login_idp(),
        ) else {
            return Ok(());
        };
        let identity = MappedIdentity::from_assertion(&login.idp().claim_mappings, &claims)
            .map_err(|_| "the stored ID token names no user through the claim mappings")?;
        if identity.subject != grant.identity.subject || identity.tenant != grant.identity.tenant {
            return Err("the stored ID token names another user or tenant");
        }
        let snapshot = &mut grant.identity;
        snapshot.groups = identity.groups;
        snapshot.roles = identity.roles;
        snapshot.attributes = identity.attributes;
        snapshot.amr = identity.amr;
        snapshot.email = claims
            .get("email")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let Some(auth_time) = claims.get("auth_time").and_then(serde_json::Value::as_u64) {
            snapshot.auth_time = Some(auth_time);
        }
        Ok(())
    }

    /// A spent token presented again. Within `reuse_grace_secs` of its
    /// spending, the client receives the successor it was issued, while
    /// that is unspent; otherwise the grant is revoked (RFC 9700
    /// §4.14.2). A token of another client's grant revokes nothing, nor
    /// does a token issued bound to the grant's key presented without a
    /// proof of it. A token issued before the grant was bound revokes it
    /// whatever key it comes with.
    #[allow(clippy::too_many_arguments)]
    async fn reused(
        &self,
        state: &InteractiveState,
        token: &str,
        spent: RefreshUsedRecord,
        client: &Client,
        wanted: &Wanted<'_>,
        now: u64,
        context: &mut RedemptionContext,
    ) -> Result<((TokenResponse, IssuedToken), RefreshOutcome), Stop> {
        context.gid = Some(spent.gid.clone());
        let grace = u64::from(self.interactive.refresh_tokens.reuse_grace_secs);
        if grace > 0
            && now.saturating_sub(spent.spent_at) <= grace
            && let Some(answer) = self
                .retry_within_grace(state, token, spent.clone(), client, wanted, now, context)
                .await?
        {
            return Ok((answer, RefreshOutcome::Grace));
        }
        let Some(grant) = state
            .get(&keys::grant(&spent.gid))
            .await
            .map_err(store_unavailable)?
        else {
            return Err(Stop::expired(unknown_refresh_token()));
        };
        if grant.client_id != client.client_id {
            return Err(Stop::new(
                OAuthError::invalid_grant("the refresh token was issued to another client"),
                RefreshOutcome::Refused,
            ));
        }
        // A copy of a key-bound token is useless without the key, so its
        // holder does not get to end the grant.
        if spent_under_binding(&grant, &spent) {
            self.refresh_binding(&grant, client, wanted)?;
        }
        tracing::warn!(
            client_id = %client.client_id,
            gid = %spent.gid,
            "a spent refresh token was presented again; revoking its grant"
        );
        context.grant_events.push(GrantEvent::RefreshReuse {
            gid: spent.gid.clone(),
            client_id: client.client_id.clone(),
        });
        context.grant_events.push(
            self.revoke_grant(state, &spent.gid, RevocationReason::RefreshReuse)
                .await,
        );
        Err(Stop::new(
            OAuthError::invalid_grant("the refresh token was already used"),
            RefreshOutcome::ReuseRevoked,
        ))
    }

    /// The answer a client that lost the answer to its refresh receives
    /// within `reuse_grace_secs`: a new access token with the successor
    /// already issued, while the successor is unspent and the grant alive,
    /// and only with a proof of the grant's key when it has one. `None`
    /// when there is none to give, and when a token issued before the
    /// grant was bound comes without a proof of the key its first spending
    /// bound: two parties spent it.
    #[allow(clippy::too_many_arguments)]
    async fn retry_within_grace(
        &self,
        state: &InteractiveState,
        token: &str,
        mut spent: RefreshUsedRecord,
        client: &Client,
        wanted: &Wanted<'_>,
        now: u64,
        context: &mut RedemptionContext,
    ) -> Result<Option<(TokenResponse, IssuedToken)>, Stop> {
        if spent.successor_sealed.is_none() {
            match self.await_successor(state, token, &spent.gid).await? {
                Some(settled) => spent = settled,
                None => return Ok(None),
            }
        }
        let Some(successor) = spent
            .successor_sealed
            .as_deref()
            .and_then(|sealed| open_successor(token, sealed, &self.successor_aad(&spent.gid)))
        else {
            return Ok(None);
        };
        let Some(index) = state
            .get(&keys::refresh(&successor))
            .await
            .map_err(store_unavailable)?
            .filter(|index| index.gid == spent.gid && index.client_id == client.client_id)
        else {
            return Ok(None);
        };
        let grant = self.live_grant(state, &spent.gid, now).await?;
        if index.generation != grant.generation {
            return Ok(None);
        }
        self.admit_refresh(state, &spent.gid, &grant, context)
            .await?;
        let dpop_jkt = match self.refresh_binding(&grant, client, wanted) {
            Ok(dpop_jkt) => dpop_jkt,
            Err(_) if grant.dpop_jkt.is_some() && !spent_under_binding(&grant, &spent) => {
                return Ok(None);
            }
            Err(stop) => return Err(stop),
        };
        let scope = refresh_scope(&grant, wanted)?;
        let authorization_details = self.refresh_details(&grant, wanted)?;
        let minted = self.mint_for_grant(
            ActiveGrant {
                gid: spent.gid.clone(),
                grant,
                refresh_token: Some(successor),
                scope: Some(scope),
                dpop_jkt,
                authorization_details: Some(authorization_details),
            },
            client,
            now,
        )?;
        Ok(Some(minted))
    }

    /// Wait for the request that spent `token` to record its successor.
    /// `None` once the grant is gone; 503 when that request released the
    /// token or does not finish in time, so the client retries.
    async fn await_successor(
        &self,
        state: &InteractiveState,
        token: &str,
        gid: &GrantId,
    ) -> Result<Option<RefreshUsedRecord>, Stop> {
        let deadline = Instant::now() + SUCCESSOR_WAIT;
        while Instant::now() < deadline {
            tokio::time::sleep(SUCCESSOR_POLL).await;
            match state
                .get(&keys::refresh_used(token))
                .await
                .map_err(store_unavailable)?
            {
                Some(spent) if spent.successor_sealed.is_some() => return Ok(Some(spent)),
                Some(_) => {}
                None => return Err(retry_shortly().into()),
            }
            if !state
                .exists(&keys::grant(gid))
                .await
                .map_err(store_unavailable)?
            {
                return Ok(None);
            }
        }
        Err(retry_shortly().into())
    }

    /// Associated data of a sealed successor: this server and the grant.
    fn successor_aad(&self, gid: &GrantId) -> Vec<u8> {
        format!("mcpg.as.v1\0rt_successor\0{}\0{gid}", self.issuer).into_bytes()
    }
}

/// `temporarily_unavailable` for a token another request is refreshing.
fn retry_shortly() -> OAuthError {
    OAuthError::temporarily_unavailable(
        "the refresh token is being refreshed by another request; retry shortly",
    )
}

/// The scopes of the new access token: those `wanted` names, all of which
/// the grant must hold (OAuth 2.1 §4.3.1), in the grant's order; the
/// grant's when it names none. `openid` and `offline_access` are ignored,
/// as at the authorization endpoint. A `resource` must be the grant's
/// (RFC 8707 §2.2), a trailing `/` aside.
fn refresh_scope(grant: &GrantRecord, wanted: &Wanted<'_>) -> Result<Vec<String>, Stop> {
    if wanted.resource.is_some_and(|resource| {
        resource.trim_end_matches('/') != grant.resource.trim_end_matches('/')
    }) {
        return Err(OAuthError::new(
            "invalid_target",
            "the requested resource is not the resource of the grant",
        )
        .into());
    }
    let requested: Vec<&str> = wanted
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| !PROTOCOL_SCOPES.contains(scope))
        .collect();
    if requested.is_empty() {
        return Ok(grant.scope.clone());
    }
    if requested
        .iter()
        .any(|scope| !grant.scope.iter().any(|granted| granted == scope))
    {
        return Err(OAuthError::new(
            "invalid_scope",
            "the requested scope exceeds the scope the user approved",
        )
        .into());
    }
    Ok(grant
        .scope
        .iter()
        .filter(|granted| requested.contains(&granted.as_str()))
        .cloned()
        .collect())
}
