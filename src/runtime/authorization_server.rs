//! Embedded Enterprise-Managed Authorization server
//! (`governance.access.authorization_server`).
//!
//! The gateway acts as the OAuth *Resource Authorization Server* of the
//! MCP `io.modelcontextprotocol/enterprise-managed-authorization`
//! extension: it redeems Identity Assertion JWT Authorization Grants
//! (ID-JAGs, `draft-ietf-oauth-identity-assertion-authz-grant`) issued
//! by trusted enterprise IdPs and mints audience-restricted access
//! tokens that the gateway itself accepts on `/mcp`
//! (`urn:ietf:params:oauth:grant-type:jwt-bearer` carrying an ID-JAG).
//! Interactive sign-in (`authorization_code` with PKCE through the IdP
//! of the one `trusted_idps[].login` entry, and rotating refresh tokens)
//! exists only when that block is configured; without it there is no
//! authorization endpoint and no refresh token. The authorization
//! endpoint, its consent step and the callback the IdP returns the browser
//! to follow [`interactive`]; the `authorization_code` grant that redeems
//! the callback's code, and the grants it activates, follow [`grants`];
//! the `refresh_token` grant follows [`refresh`], token revocation (RFC
//! 7009) [`revocation`], and the IdP sign-in kept for each user [`vault`].
//! Both paths mint the same access token; one from a sign-in also names
//! its grant, whose revocation refuses it. With DPoP on ([`dpop`]), a
//! token request that carries a proof receives a token bound to the
//! proof's key (`cnf.jkt`, `token_type: DPoP`), and a grant bound to a key
//! (an ID-JAG's `cnf`, a code's `dpop_jkt`, a public client's refresh
//! token) is redeemed only with a proof of that key; with DPoP off, an
//! ID-JAG bound to a key is refused. With authorization details types
//! configured ([`rar`]), a grant may be limited to RFC 9396
//! `authorization_details`, which a token request may narrow and every
//! token carries; without them, an ID-JAG limited so is refused.
//!
//! Minted tokens carry the `kid` of the key that signed them; the public
//! halves of asymmetric keys are published at [`JWKS_PATH`]. Redeemed
//! assertions are recorded in a [`ReplayLedger`], which the gateway puts
//! on the cluster coordinator's key-value store so single use holds
//! across replicas and reloads. The records of interactive sign-in live
//! sealed in an [`InteractiveState`] (see [`state`]).
//!
//! Clients authenticate with a shared secret, a `private_key_jwt`
//! assertion or not at all (public clients), and may identify with a
//! Client ID Metadata Document instead of a registration (`clients`), or,
//! when the operator opts in, register themselves (RFC 7591, [`dcr`]). The
//! redirect URIs and PKCE of the authorization endpoint follow
//! [`redirect`].
//!
//! The user's subject, groups, roles and attributes are read from the
//! ID-JAG through its IdP's `claim_mappings` and travel in the minted
//! token, together with the RFC 8693 actor (`act`), `tenant` and `amr`;
//! `client_roles` and an IdP's `principal_issuer` apply when a token is
//! verified.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, PublicKeyUse, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mcpg_cluster_api::KeyValueStore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use tokio::sync::RwLock;

use crate::config::{
    AuthorizationServerConfig, ClientAuthMethod, OAuthResourceMetadataConfig, SigningAlgorithm,
    SigningKeyConfig, TrustedIdpClaimMappingConfig, TrustedIdpConfig,
};
use mcpg_plugin_identity_oidc_core::resolver::{
    enforce_discovery_url_safety, extract_string_claim, extract_string_list_claims,
    map_key_algorithm, oidc_auth_provider,
};

#[path = "authorization_server_clients.rs"]
mod clients;
#[path = "authorization_server_connect.rs"]
pub mod connect;
#[path = "authorization_server_dcr.rs"]
pub mod dcr;
#[path = "authorization_server_dpop.rs"]
pub mod dpop;
#[path = "authorization_server_grants.rs"]
pub mod grants;
#[path = "authorization_server_interactive.rs"]
pub mod interactive;
#[path = "authorization_server_rar.rs"]
pub mod rar;
#[path = "authorization_server_redirect.rs"]
pub mod redirect;
#[path = "authorization_server_refresh.rs"]
pub mod refresh;
#[path = "authorization_server_revocation.rs"]
pub mod revocation;
#[path = "authorization_server_state.rs"]
pub mod state;
#[path = "authorization_server_upstream.rs"]
pub mod upstream;
#[path = "authorization_server_vault.rs"]
pub mod vault;

pub use clients::CLIENT_ASSERTION_TYPE_JWT_BEARER;
pub use state::InteractiveState;
pub use upstream::LoginIdp;

/// RFC URN of the grant type an ID-JAG is redeemed with.
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Grant profile advertised in authorization-server metadata.
pub const GRANT_PROFILE_ID_JAG: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
/// MCP extension identifier declared under `capabilities.extensions` of
/// `initialize` and `server/discover` while this server is installed.
pub const EXTENSION_ID: &str = "io.modelcontextprotocol/enterprise-managed-authorization";
/// Required `typ` header of an ID-JAG assertion.
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
/// `typ` header stamped on minted access tokens (RFC 9068).
const ACCESS_TOKEN_TYP: &str = "at+jwt";
/// How long a fetched trusted-IdP key set is used before it is refreshed.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// How long the last fetched key set keeps verifying assertions while the
/// IdP cannot be reached.
const JWKS_MAX_STALENESS: Duration = Duration::from_secs(3600);
/// Minimum spacing between JWKS refetches (unknown-kid storms).
const JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Largest discovery, JWKS or token response body read from a trusted IdP.
const MAX_IDP_RESPONSE_BYTES: usize = 1024 * 1024;
/// Timeout of one discovery or JWKS request to a trusted IdP without a
/// `login` block, whose `timeout_ms` applies otherwise.
const IDP_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest claim value echoed back in an error description.
const ECHO_LIMIT: usize = 200;
/// Path of the public key set minted tokens verify against.
pub const JWKS_PATH: &str = "/oauth/jwks";
/// Path of the token endpoint.
pub const TOKEN_PATH: &str = "/oauth/token";
/// Paths of the interactive sign-in pages a browser navigates to. They
/// never answer a CORS request (RFC 9700 §2.6): script on another origin
/// must not read an authorization response.
pub const BROWSER_ONLY_PATHS: [&str; 4] = [
    interactive::AUTHORIZE_PATH,
    interactive::CONSENT_PATH,
    interactive::CALLBACK_PATH,
    interactive::CONNECT_PATH,
];
/// Key namespace of the single-use ledger in a shared key-value store.
const REPLAY_KEY_PREFIX: &str = "ema_jti/";
/// How often an in-process ledger drops expired redemptions.
const LEDGER_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// `auth_provider` of an EMA caller whose IdP sets no `principal_issuer`.
const AUTH_PROVIDER: &str = "ema";
/// The attributes a verified access token sets on its caller, which
/// `claim_mappings.attribute_claim_mappings` may not map to. `dpop_jkt`
/// comes only from a token presented with a DPoP proof, the two
/// `authorization_details` attributes only from a token limited to
/// authorization details, the last two only from a token of an interactive
/// sign-in.
pub const IDENTITY_ATTRIBUTES: [&str; 13] = [
    "client_id",
    "idp",
    "token_issuer",
    "email",
    "actor",
    "tenant",
    "amr",
    "grant_type",
    dpop::DPOP_JKT_ATTRIBUTE,
    rar::AUTHORIZATION_DETAILS_ATTRIBUTE,
    rar::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE,
    "grant_id",
    "auth_time",
];
/// The attributes that only a credential of this gateway gives a caller:
/// which way into the gateway it took, the DPoP key it proved, and the
/// authorization details its token is limited to. A policy trusts them, so
/// no identity resolved elsewhere (an `oidc_oauth` provider, an identity
/// plugin) may carry them.
pub const GATEWAY_SET_ATTRIBUTES: [&str; 6] = [
    "token_issuer",
    "grant_type",
    "grant_id",
    dpop::DPOP_JKT_ATTRIBUTE,
    rar::AUTHORIZATION_DETAILS_ATTRIBUTE,
    rar::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE,
];
/// `grant_type` attribute of a caller whose token an ID-JAG redemption
/// minted.
pub const GRANT_ATTRIBUTE_ID_JAG: &str = "id_jag";

/// OAuth token-endpoint error (RFC 6749 §5.2). `status` is the HTTP
/// status the error is served with (400, 401 for `invalid_client` after
/// HTTP Basic, 500 for `server_error`, 503 for `temporarily_unavailable`).
#[derive(Debug)]
pub struct OAuthError {
    pub status: u16,
    pub error: &'static str,
    pub description: String,
    /// `invalid_client` after an attempted `Authorization: Basic` must
    /// answer with a `WWW-Authenticate: Basic` challenge (RFC 6749 §5.2).
    pub basic_challenge: bool,
}

impl OAuthError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status: 400,
            error,
            description: description.into(),
            basic_challenge: false,
        }
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new("invalid_grant", description)
    }

    /// RFC 6749 §5.2: 401 with a Basic challenge when the client tried
    /// HTTP Basic, else 400, since a 401 must carry a challenge (RFC 9110
    /// §15.5.2) and no HTTP scheme fits the other methods.
    fn invalid_client(description: impl Into<String>, basic_attempted: bool) -> Self {
        Self {
            status: if basic_attempted { 401 } else { 400 },
            error: "invalid_client",
            description: description.into(),
            basic_challenge: basic_attempted,
        }
    }

    fn server_error(description: impl Into<String>) -> Self {
        Self {
            status: 500,
            ..Self::new("server_error", description)
        }
    }

    fn temporarily_unavailable(description: impl Into<String>) -> Self {
        Self {
            status: 503,
            ..Self::new("temporarily_unavailable", description)
        }
    }

    /// RFC 9449 §5: a DPoP proof at the token endpoint that is refused.
    fn invalid_dpop_proof(description: impl Into<String>) -> Self {
        Self::new("invalid_dpop_proof", description)
    }

    /// RFC 9449 §8: a DPoP proof without a current server nonce; the
    /// response carries a fresh one.
    fn use_dpop_nonce(description: impl Into<String>) -> Self {
        Self::new("use_dpop_nonce", description)
    }

    /// RFC 9396 §5: an `authorization_details` parameter that is not valid
    /// or asks for more than the grant holds.
    fn invalid_authorization_details(description: impl Into<String>) -> Self {
        Self::new("invalid_authorization_details", description)
    }

    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.error,
            "error_description": error_description(&self.description),
        })
    }
}

/// `description` in the character set RFC 6749 §5.2 allows an
/// `error_description` (%x20-21 / %x23-5B / %x5D-7E). Descriptions echo
/// client-supplied values, which may hold anything.
fn error_description(description: &str) -> String {
    let mut out = String::with_capacity(description.len());
    for c in description.chars() {
        match c {
            '"' | '\\' => out.push('\''),
            '§' => out.push_str("section "),
            '…' => out.push_str("..."),
            ' '..='~' => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Successful token response (RFC 6749 §5.1). An ID-JAG redemption never
/// carries a refresh token; an interactive grant does when its client may
/// refresh.
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// `DPoP` for a token bound to a key, else `Bearer`.
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The resource identifier the token is audience-restricted to: the
    /// granted resource the ID-JAG profile requires in the response.
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// RFC 9396 §7: the authorization details the token is limited to.
    #[serde(skip_serializing_if = "rar::AuthorizationDetails::is_empty")]
    pub authorization_details: rar::AuthorizationDetails,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Parsed `POST /oauth/token` form body.
#[derive(Default, Deserialize)]
pub struct TokenRequestForm {
    pub grant_type: Option<String>,
    pub assertion: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// RFC 7521 §4.2: `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
    /// for `private_key_jwt`.
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    /// RFC 6749 §3.3 scope request: narrows the grant, never widens it.
    pub scope: Option<String>,
    /// RFC 8707 resource indicator: the resource the token is for.
    pub resource: Option<String>,
    /// The authorization code of an `authorization_code` grant.
    pub code: Option<String>,
    /// RFC 7636 §4.5: the PKCE verifier of the code's challenge.
    pub code_verifier: Option<String>,
    /// The redirect URI the authorization request named, which the code
    /// is bound to (OAuth 2.1 §4.1.3).
    pub redirect_uri: Option<String>,
    /// The refresh token of a `refresh_token` grant.
    pub refresh_token: Option<String>,
    /// RFC 9396 §6: the JSON `authorization_details` the token is to be
    /// limited to, which narrows the grant's.
    pub authorization_details: Option<String>,
}

impl std::fmt::Debug for TokenRequestForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let present = |value: &Option<String>| value.as_ref().map(|_| "[redacted]");
        f.debug_struct("TokenRequestForm")
            .field("grant_type", &self.grant_type)
            .field("assertion", &present(&self.assertion))
            .field("client_id", &self.client_id)
            .field("client_secret", &present(&self.client_secret))
            .field("client_assertion_type", &self.client_assertion_type)
            .field("client_assertion", &present(&self.client_assertion))
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("code", &present(&self.code))
            .field("code_verifier", &present(&self.code_verifier))
            .field("redirect_uri", &self.redirect_uri.as_ref().map(|_| "[set]"))
            .field("refresh_token", &present(&self.refresh_token))
            .field(
                "authorization_details",
                &self.authorization_details.as_ref().map(|_| "[set]"),
            )
            .finish()
    }
}

/// Identity extracted from a gateway-minted EMA access token.
#[derive(Debug, Clone)]
pub struct EmaVerifiedIdentity {
    pub subject_id: String,
    /// The principal namespace: the vouching IdP's issuer, or its
    /// `principal_issuer`.
    pub issuer: String,
    /// `ema`, or the `auth_provider` the `principal_issuer`'s OIDC
    /// provider reports.
    pub auth_provider: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub attributes: BTreeMap<String, String>,
}

/// Outcome of probing an inbound credential against the embedded issuer.
pub enum EmaBearerOutcome {
    /// Bearer's `iss` is not this server — fall through to the next
    /// verifier in the cascade.
    NotOurs,
    /// Bearer claims this issuer and verified.
    Verified(EmaVerifiedIdentity),
    /// Bearer claims this issuer and failed verification — fail closed
    /// with a `Bearer` challenge.
    Invalid(String),
    /// Refused with a `DPoP` challenge (RFC 9449 §7.1): a token presented
    /// with the `DPoP` scheme, or a Bearer token where a bound one is
    /// needed.
    Refused(dpop::EmaRefusal),
    /// The replay ledger cannot record the request's proof, which is
    /// refused for now.
    Unavailable,
}

/// The grant a token request asks for, as a bounded metric label.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TokenGrant {
    /// No `grant_type`, or a body that could not be read.
    #[default]
    None,
    /// An ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`).
    JwtBearer,
    AuthorizationCode,
    RefreshToken,
    /// Any other `grant_type`.
    Unsupported,
}

impl TokenGrant {
    fn of(grant_type: Option<&str>) -> Self {
        match grant_type {
            None => Self::None,
            Some(GRANT_TYPE_JWT_BEARER) => Self::JwtBearer,
            Some(grants::GRANT_TYPE_AUTHORIZATION_CODE) => Self::AuthorizationCode,
            Some(grants::GRANT_TYPE_REFRESH_TOKEN) => Self::RefreshToken,
            Some(_) => Self::Unsupported,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::JwtBearer => "jwt_bearer",
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether the grant belongs to interactive sign-in.
    fn is_interactive(self) -> bool {
        matches!(self, Self::AuthorizationCode | Self::RefreshToken)
    }
}

/// What a token request resolved to before it succeeded or failed.
#[derive(Debug, Default, Clone)]
pub struct RedemptionContext {
    /// The grant the request asked for.
    pub grant: TokenGrant,
    /// The authenticated client.
    pub client_id: Option<String>,
    /// The `trusted_idps` issuer the assertion was routed to, or the login
    /// IdP of an interactive grant.
    pub idp: Option<String>,
    /// The interactive grant an authorization code named.
    pub gid: Option<state::GrantId>,
    /// What the request did to grants beside its answer: a replayed code,
    /// the grants it revoked.
    pub grant_events: Vec<grants::GrantEvent>,
    /// Whether the request carried a DPoP proof that was checked.
    pub dpop_presented: bool,
}

/// A minted access token, described without the token itself.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub subject: String,
    /// `sub` of the ID-JAG's `act` claim: who acts for the subject.
    pub actor: Option<String>,
    /// `jti` of the minted access token.
    pub jti: String,
    /// `jti` of the redeemed ID-JAG, which the IdP's own records carry;
    /// `None` for an interactive grant.
    pub assertion_jti: Option<String>,
    pub scope: Option<String>,
    pub resource: String,
    pub expires_in: u64,
    /// The caller's roles and groups while the token is valid, as mapped
    /// when it was minted.
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    /// The interactive grant the token was issued under; `None` for an
    /// ID-JAG redemption.
    pub grant: Option<grants::IssuedGrant>,
    /// The RFC 7638 thumbprint of the key the token is bound to; `None`
    /// for a Bearer token.
    pub dpop_jkt: Option<String>,
    /// The authorization details the token is limited to.
    pub authorization_details: rar::AuthorizationDetails,
    /// Their keyed digest, as audit records carry the caller's
    /// `authorization_details` attribute; `None` without details.
    pub authorization_details_digest: Option<String>,
}

impl IssuedToken {
    /// The `token_type` of the token.
    pub fn token_type(&self) -> &'static str {
        if self.dpop_jkt.is_some() {
            dpop::TOKEN_TYPE_DPOP
        } else {
            dpop::TOKEN_TYPE_BEARER
        }
    }
}

/// The outcome of one `POST /oauth/token` request.
#[derive(Debug)]
pub struct TokenRedemption {
    /// The token response with a description of the minted token, or the
    /// error.
    pub result: Result<(TokenResponse, IssuedToken), OAuthError>,
    pub context: RedemptionContext,
    /// The server nonce the response carries as `DPoP-Nonce`, while DPoP
    /// proofs at the token endpoint must carry one.
    pub dpop_nonce: Option<dpop::DpopNonce>,
}

impl TokenRedemption {
    /// A request body the token endpoint cannot parse.
    pub fn malformed(description: String) -> Self {
        let redemption = Self {
            result: Err(OAuthError::new("invalid_request", description)),
            context: RedemptionContext::default(),
            dpop_nonce: None,
        };
        redemption.record(Duration::ZERO);
        redemption
    }

    /// Whether the request was answered `use_dpop_nonce`: a normal step of
    /// the protocol (RFC 9449 §8), not a failed redemption.
    pub fn nonce_requested(&self) -> bool {
        matches!(self.result, Err(ref error) if error.error == "use_dpop_nonce")
    }

    /// Every audit record of the request, in the order things happened:
    /// what it did to grants ([`grants::GrantEvent`]), then
    /// [`Self::audit_event`] unless the request was only asked for a nonce.
    pub fn audit_events(&self, request_id: &str) -> Vec<mcpg_plugin_protocol::audit::AuditEvent> {
        let mut events: Vec<_> = self
            .context
            .grant_events
            .iter()
            .map(|event| event.event(request_id))
            .collect();
        if !self.nonce_requested() {
            events.push(self.audit_event(request_id));
        }
        events
    }

    /// The redemption's audit record: `mcpg.ema.token_issued` for an
    /// ID-JAG, `mcpg.as.token_issued` for an interactive grant, or
    /// `mcpg.auth.failed` with `auth_method` `ema_token` or `as_token`.
    /// An issued token's record names its `token_type`, the thumbprint of
    /// the key it is bound to (`dpop_jkt`), and the types and keyed digest
    /// of the authorization details it is limited to; a refusal's says whether
    /// a DPoP proof was checked. None carries an assertion, a code, a
    /// verifier, a DPoP proof, a key, a token or a detail's values.
    pub fn audit_event(&self, request_id: &str) -> mcpg_plugin_protocol::audit::AuditEvent {
        match self.result {
            Ok((_, ref issued)) => self.issued_event(issued, request_id),
            Err(ref error) => {
                let method = if self.context.grant.is_interactive() {
                    "as_token"
                } else {
                    "ema_token"
                };
                let mut event = mcpg_plugin_host::audit_events::auth_failed_event(
                    method,
                    &format!("{}: {}", error.error, error.description),
                    request_id,
                    "http",
                );
                event.details["error"] = serde_json::json!(error.error);
                event.details["client_id"] = serde_json::json!(self.context.client_id);
                event.details["idp"] = serde_json::json!(self.context.idp);
                event.details["dpop_presented"] = serde_json::json!(self.context.dpop_presented);
                if self.context.grant.is_interactive() {
                    event.details["grant_type"] = serde_json::json!(self.context.grant.as_str());
                    event.details["gid"] =
                        serde_json::json!(self.context.gid.as_ref().map(state::GrantId::as_str));
                }
                event
            }
        }
    }

    fn issued_event(
        &self,
        issued: &IssuedToken,
        request_id: &str,
    ) -> mcpg_plugin_protocol::audit::AuditEvent {
        let idp = self.context.idp.clone().unwrap_or_default();
        let client_id = self.context.client_id.clone().unwrap_or_default();
        let scopes = issued
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let (action, auth_provider, principal_issuer) = match issued.grant {
            Some(ref grant) => (
                "mcpg.as.token_issued",
                grant.auth_provider.clone(),
                grant.principal_issuer.clone(),
            ),
            None => (
                "mcpg.ema.token_issued",
                AUTH_PROVIDER.to_owned(),
                idp.clone(),
            ),
        };
        let mut details = serde_json::json!({
            "idp": idp,
            "subject": issued.subject,
            "actor": issued.actor,
            "client_id": client_id,
            "scope": issued.scope,
            "token_jti": issued.jti,
            "assertion_jti": issued.assertion_jti,
            "resource": issued.resource,
            "expires_in": issued.expires_in,
            "token_type": issued.token_type(),
            "dpop_jkt": issued.dpop_jkt,
            "authorization_details_types": issued.authorization_details.types(),
            "authorization_details_digest": issued.authorization_details_digest,
        });
        if let Some(ref grant) = issued.grant {
            details["grant_type"] = serde_json::json!(self.context.grant.as_str());
            details["gid"] = serde_json::json!(grant.gid.as_str());
            details["refresh_token_issued"] = serde_json::json!(grant.refresh_token_issued);
        }
        mcpg_plugin_protocol::audit::AuditEvent {
            event_id: mcpg_plugin_host::audit_events::new_event_id(),
            occurred_at: mcpg_plugin_host::audit_events::now_rfc3339_utc(),
            actor: mcpg_plugin_protocol::PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some(issued.subject.clone()),
                auth_provider: Some(auth_provider),
                issuer: Some(principal_issuer),
                roles: issued.roles.clone(),
                groups: issued.groups.clone(),
                scopes,
                attributes: BTreeMap::from([("client_id".to_owned(), client_id.clone())]),
            },
            action: action.into(),
            resource: Some(issued.resource.clone()),
            outcome: mcpg_plugin_protocol::audit::AuditOutcome::Success,
            request_id: Some(request_id.to_owned()),
            upstream_request_id: None,
            node_id: None,
            details,
            prev_event_hash: None,
        }
    }

    /// Token-endpoint metrics, and one log line per issued token.
    fn record(&self, elapsed: Duration) {
        let (outcome, error) = match &self.result {
            Ok(_) => ("issued", "none"),
            Err(error) if error.status >= 500 => ("failed", error.error),
            Err(error) => ("refused", error.error),
        };
        // A configured issuer, never the assertion's own `iss`: the label
        // set stays bounded by the configuration.
        let idp = self.context.idp.as_deref().unwrap_or("none");
        let grant = self.context.grant.as_str();
        metrics::counter!(
            "mcpg_ema_token_requests_total",
            "outcome" => outcome,
            "error" => error,
            "idp" => idp.to_owned(),
            "grant" => grant,
        )
        .increment(1);
        metrics::histogram!(
            "mcpg_ema_token_latency_ms",
            "outcome" => outcome,
            "grant" => grant,
        )
        .record(elapsed.as_secs_f64() * 1000.0);
        if let Ok((_, ref issued)) = self.result
            && issued.dpop_jkt.is_some()
        {
            metrics::counter!("mcpg_as_dpop_bound_tokens_total", "grant" => grant).increment(1);
        }
        match self.result {
            Ok((_, ref issued)) => match issued.grant {
                Some(ref issued_grant) => tracing::info!(
                    idp = %idp,
                    subject = %issued.subject,
                    client_id = self.context.client_id.as_deref().unwrap_or_default(),
                    scope = issued.scope.as_deref().unwrap_or_default(),
                    jti = %issued.jti,
                    gid = %issued_grant.gid,
                    resource = %issued.resource,
                    expires_in = issued.expires_in,
                    token_type = issued.token_type(),
                    refresh_token_issued = issued_grant.refresh_token_issued,
                    "access token issued for an interactive sign-in"
                ),
                None => tracing::info!(
                    idp = %idp,
                    subject = %issued.subject,
                    client_id = self.context.client_id.as_deref().unwrap_or_default(),
                    scope = issued.scope.as_deref().unwrap_or_default(),
                    jti = %issued.jti,
                    resource = %issued.resource,
                    expires_in = issued.expires_in,
                    token_type = issued.token_type(),
                    "EMA access token issued"
                ),
            },
            Err(ref error) => tracing::debug!(
                idp = %idp,
                grant = grant,
                client_id = self.context.client_id.as_deref().unwrap_or_default(),
                error = error.error,
                description = %error.description,
                "token request refused"
            ),
        }
    }
}

/// Where redeemed ID-JAGs are recorded, so each is redeemed once.
#[derive(Clone)]
pub struct ReplayLedger {
    kv: Arc<dyn KeyValueStore>,
    process_local: bool,
}

impl std::fmt::Debug for ReplayLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayLedger")
            .field("process_local", &self.process_local)
            .finish_non_exhaustive()
    }
}

impl ReplayLedger {
    /// A ledger on a store every replica shares, such as the cluster
    /// coordinator's key-value store.
    pub fn shared(kv: Arc<dyn KeyValueStore>) -> Self {
        Self {
            kv,
            process_local: false,
        }
    }

    /// A ledger in this process's memory.
    pub fn in_process() -> Self {
        let kv = crate::builtins::cluster_primitives::MemoryKv::new();
        // Each `jti` is written once and never touched again, so only a
        // sweep reclaims the expired entries.
        let kv = if tokio::runtime::Handle::try_current().is_ok() {
            kv.with_sweep(LEDGER_SWEEP_INTERVAL)
        } else {
            kv
        };
        Self {
            kv: Arc::new(kv),
            process_local: true,
        }
    }

    /// Held in this process only: another replica does not see it, and a
    /// reload keeps it only by handing it to the next server.
    pub fn is_process_local(&self) -> bool {
        self.process_local
    }

    /// Whether both ledgers record into one store.
    #[cfg(test)]
    pub(crate) fn shares_store_with(&self, other: &ReplayLedger) -> bool {
        Arc::ptr_eq(&self.kv, &other.kv)
    }
}

/// Ledger key of an assertion: a hash, so the store never holds the
/// IdP's identifiers in the clear (state encryption seals values only).
fn replay_key(iss: &str, jti: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("mcpg ema id-jag single-use ledger v1");
    hasher.update(&(iss.len() as u64).to_le_bytes());
    hasher.update(iss.as_bytes());
    hasher.update(jti.as_bytes());
    format!("{REPLAY_KEY_PREFIX}{}", hasher.finalize().to_hex())
}

/// A key minted access tokens are signed or verified with.
pub(crate) struct SigningKey {
    kid: String,
    alg: Algorithm,
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// The public half of an asymmetric key. An HMAC secret has none and
    /// is never published.
    public_jwk: Option<Jwk>,
    /// Also verifies a token that names no key: an HS256 secret configured
    /// without a `kid`, whose tokens from older gateway releases carry none.
    verifies_kidless: bool,
    /// The key DPoP nonces are derived under, from this key's material, so
    /// every replica carrying the key issues and accepts the same nonces.
    nonce_key: zeroize::Zeroizing<[u8; 32]>,
    /// The key audit records digest authorization details under, from this
    /// key's material.
    audit_key: zeroize::Zeroizing<[u8; 32]>,
}

impl SigningKey {
    fn hmac(field: &str, kid: Option<&str>, secret: &str, issuer: &str) -> Result<Self> {
        if secret.len() < 32 {
            anyhow::bail!(
                "{field} must be at least 32 bytes for HS256 (is the `${{…}}` reference resolved?)"
            );
        }
        let encoding = EncodingKey::from_secret(secret.as_bytes());
        Ok(Self {
            kid: kid.map_or_else(|| derived_hmac_kid(secret), str::to_owned),
            alg: Algorithm::HS256,
            nonce_key: dpop::nonce_key(issuer, encoding.as_bytes())?,
            audit_key: rar::audit_digest_key(issuer, encoding.as_bytes())?,
            encoding,
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            public_jwk: None,
            verifies_kidless: kid.is_none(),
        })
    }

    fn asymmetric(field: &str, config: &SigningKeyConfig, pem: &str, issuer: &str) -> Result<Self> {
        let (alg, expected) = match config.alg {
            SigningAlgorithm::Es256 => (
                Algorithm::ES256,
                "a P-256 key in PKCS#8 PEM, as `openssl genpkey -algorithm EC -pkeyopt \
                 ec_paramgen_curve:P-256` writes it",
            ),
            SigningAlgorithm::EdDsa => (
                Algorithm::EdDSA,
                "an Ed25519 key in PKCS#8 v1 PEM, as `openssl genpkey -algorithm ed25519` \
                 writes it",
            ),
            SigningAlgorithm::Rs256 => (
                Algorithm::RS256,
                "an RSA key of at least 2048 bits in PKCS#8 or PKCS#1 PEM",
            ),
            SigningAlgorithm::Hs256 => anyhow::bail!("{field}: an HS256 key takes `secret`"),
        };
        let unusable = |error: jsonwebtoken::errors::Error| {
            anyhow::anyhow!(
                "{field}.private_key is not a usable {} key ({error}): expected {expected}",
                config.alg.as_str()
            )
        };
        let encoding = match alg {
            Algorithm::ES256 => EncodingKey::from_ec_pem(pem.as_bytes()),
            Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes()),
            _ => EncodingKey::from_rsa_pem(pem.as_bytes()),
        }
        .map_err(unusable)?;
        let mut jwk = Jwk::from_encoding_key(&encoding, alg).map_err(unusable)?;
        // Only public members may leave the process.
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            anyhow::bail!("{field}.private_key is not an asymmetric key");
        }
        let kid = match config.kid {
            Some(ref kid) => kid.clone(),
            None => jwk.thumbprint(ThumbprintHash::SHA256).map_err(unusable)?,
        };
        jwk.common.key_id = Some(kid.clone());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        let decoding = DecodingKey::from_jwk(&jwk).map_err(unusable)?;
        let key = Self {
            kid,
            alg,
            nonce_key: dpop::nonce_key(issuer, encoding.as_bytes())?,
            audit_key: rar::audit_digest_key(issuer, encoding.as_bytes())?,
            encoding,
            decoding,
            public_jwk: Some(jwk),
            verifies_kidless: false,
        };
        key.self_test().map_err(unusable)?;
        Ok(key)
    }

    fn sign<T: Serialize>(&self, claims: &T) -> jsonwebtoken::errors::Result<String> {
        let mut header = Header::new(self.alg);
        header.typ = Some(ACCESS_TOKEN_TYP.to_owned());
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding)
    }

    /// Sign and verify a probe, so a key that cannot sign fails at boot
    /// rather than on the first redemption.
    fn self_test(&self) -> jsonwebtoken::errors::Result<()> {
        let token = self.sign(&serde_json::json!({ "probe": true }))?;
        let mut validation = Validation::new(self.alg);
        validation.set_required_spec_claims::<&str>(&[]);
        validation.validate_exp = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<serde_json::Value>(&token, &self.decoding, &validation).map(|_| ())
    }
}

/// The `kid` of an HS256 key configured without one. Derived from the
/// secret, so `signing_secret` and an HS256 `signing_keys` entry holding
/// the same secret name the same key.
fn derived_hmac_kid(secret: &str) -> String {
    let digest = blake3::derive_key("mcpg ema access-token hmac kid v1", secret.as_bytes());
    format!("hs256-{}", hex::encode(&digest[..8]))
}

/// The access-token keys `config` names, the signing key first.
pub(crate) fn load_signing_keys(config: &AuthorizationServerConfig) -> Result<Vec<SigningKey>> {
    let prefix = "governance.access.authorization_server";
    let issuer = config.issuer.as_str();
    let keys = match config.signing_secret {
        Some(ref secret) => vec![SigningKey::hmac(
            &format!("{prefix}.signing_secret"),
            None,
            secret,
            issuer,
        )?],
        None => config
            .signing_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let field = format!("{prefix}.signing_keys[{index}]");
                match (key.alg, &key.secret, &key.private_key) {
                    (SigningAlgorithm::Hs256, Some(secret), None) => SigningKey::hmac(
                        &format!("{field}.secret"),
                        key.kid.as_deref(),
                        secret,
                        issuer,
                    ),
                    (SigningAlgorithm::Hs256, _, _) => {
                        anyhow::bail!("{field}: an HS256 key takes `secret`, and no `private_key`")
                    }
                    (_, None, Some(pem)) => SigningKey::asymmetric(&field, key, pem, issuer),
                    (alg, _, _) => anyhow::bail!(
                        "{field}: an {} key takes `private_key`, and no `secret`",
                        alg.as_str()
                    ),
                }
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if keys.is_empty() {
        anyhow::bail!("{prefix} needs a key to sign access tokens");
    }
    let mut kids = BTreeSet::new();
    for key in &keys {
        if !kids.insert(key.kid.as_str()) {
            anyhow::bail!(
                "{prefix}.signing_keys: two keys carry kid `{}`; a token names its key by kid, so \
                 each must be unique",
                key.kid
            );
        }
    }
    Ok(keys)
}

/// The claims of an ID-JAG the redemption checks. The decoder requires
/// `sub` as a string; the user is read by [`MappedIdentity`].
#[derive(Debug, Deserialize)]
struct IdJagClaims {
    iss: String,
    aud: StringOrVec,
    client_id: String,
    jti: String,
    exp: u64,
    iat: u64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<StringOrVec>,
    #[serde(default)]
    email: Option<String>,
    /// RFC 7800 confirmation: the IdP bound the grant to a key.
    #[serde(default)]
    cnf: Option<serde_json::Value>,
    /// RFC 9396 fine-grained authorization the grant is limited to.
    #[serde(default)]
    authorization_details: Option<serde_json::Value>,
    #[serde(default)]
    tenant: Option<serde_json::Value>,
}

/// A JWT claim that may be a single string or an array (`aud`, RFC 8707
/// `resource`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    fn values(&self) -> Vec<&str> {
        match self {
            StringOrVec::One(v) => vec![v.as_str()],
            StringOrVec::Many(vs) => vs.iter().map(String::as_str).collect(),
        }
    }
}

/// A redeemable ID-JAG, the user it names and the resource the token is
/// minted for.
struct ValidatedGrant {
    claims: IdJagClaims,
    identity: MappedIdentity,
    resource: String,
    /// The thumbprint of the key the IdP bound the grant to (`cnf.jkt`).
    cnf_jkt: Option<String>,
    /// The authorization details the IdP limited the grant to.
    authorization_details: rar::AuthorizationDetails,
}

/// The user an ID-JAG names, read through its IdP's `claim_mappings`, and
/// the delegation and authentication claims a minted token carries on.
#[derive(Debug)]
struct MappedIdentity {
    subject: String,
    groups: Vec<String>,
    roles: Vec<String>,
    attributes: BTreeMap<String, String>,
    act: Option<serde_json::Value>,
    tenant: Option<String>,
    amr: Vec<String>,
}

impl MappedIdentity {
    /// Read `payload`, a verified ID-JAG's claims, through `mappings`. The
    /// assertion is refused when it names no user, or names an actor
    /// without saying who.
    fn from_assertion(
        mappings: &TrustedIdpClaimMappingConfig,
        payload: &serde_json::Value,
    ) -> Result<Self, OAuthError> {
        let subject = extract_string_claim(payload, &mappings.subject_claim)
            .filter(|subject| !subject.trim().is_empty())
            .ok_or_else(|| {
                OAuthError::invalid_grant(format!(
                    "assertion carries no `{}` claim to identify the user by",
                    mappings.subject_claim
                ))
            })?;
        // A delegation the gateway cannot attribute is refused rather than
        // dropped: dropped, the actor's request would pass as the user's own.
        let act = match payload.get("act") {
            None => None,
            Some(act)
                if act
                    .get("sub")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actor| !actor.trim().is_empty()) =>
            {
                Some(act.clone())
            }
            Some(_) => {
                return Err(OAuthError::invalid_grant(
                    "assertion act claim must be an object whose sub names the actor (RFC 8693 \
                     section 4.1)",
                ));
            }
        };
        let mut attributes = BTreeMap::new();
        for (claim, attribute) in &mappings.attribute_claim_mappings {
            if let Some(value) = extract_string_claim(payload, claim) {
                attributes.insert(attribute.clone(), value);
            }
        }
        let amr = payload
            .get("amr")
            .and_then(serde_json::Value::as_array)
            .map(|methods| {
                distinct(
                    methods
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned),
                )
            })
            .unwrap_or_default();
        Ok(Self {
            subject,
            groups: distinct(extract_string_list_claims(
                payload,
                &mappings.group_claim_paths,
            )),
            roles: distinct(extract_string_list_claims(
                payload,
                &mappings.role_claim_paths,
            )),
            attributes,
            act,
            tenant: payload
                .get("tenant")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            amr,
        })
    }

    fn actor(&self) -> Option<String> {
        actor_of(self.act.as_ref())
    }
}

/// `sub` of an RFC 8693 `act` claim.
fn actor_of(act: Option<&serde_json::Value>) -> Option<String> {
    act?.get("sub")?.as_str().map(str::to_owned)
}

/// `values` in their first-seen order, each once.
fn distinct(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MintedClaims {
    iss: String,
    sub: String,
    aud: String,
    client_id: String,
    jti: String,
    iat: u64,
    exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// The enterprise IdP that issued the redeemed ID-JAG.
    idp: String,
    /// RFC 9068 §2.2.3.1 `groups` and `roles`, read by the IdP's
    /// `claim_mappings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<String>,
    /// Attributes read by `claim_mappings.attribute_claim_mappings`.
    #[serde(
        default,
        rename = "mcpg_attributes",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    attributes: BTreeMap<String, String>,
    /// RFC 8693 §4.1 actor of the ID-JAG, kept apart from `sub`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    act: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    amr: Vec<String>,
    /// The interactive grant the token was issued under; revoking it
    /// refuses the token. Absent on a token an ID-JAG redemption minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gid: Option<state::GrantId>,
    /// How the grant was obtained: `authorization_code`. Absent on a token
    /// an ID-JAG redemption minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gty: Option<String>,
    /// When the user last signed in at the IdP (OpenID Connect Core §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_time: Option<u64>,
    /// RFC 9449 §6.1: the key the token is bound to. A token that carries
    /// it is never accepted as a Bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cnf: Option<Confirmation>,
    /// RFC 9396 §9.1: the authorization details the token is limited to.
    #[serde(default, skip_serializing_if = "rar::AuthorizationDetails::is_empty")]
    authorization_details: rar::AuthorizationDetails,
}

/// An RFC 7800 confirmation of a minted token: the RFC 7638 SHA-256
/// thumbprint of its DPoP key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Confirmation {
    jkt: String,
}

impl Confirmation {
    fn of(jkt: Option<String>) -> Option<Self> {
        jkt.map(|jkt| Self { jkt })
    }
}

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

#[derive(Default)]
struct RefreshState {
    /// Last fetch attempt, successful or not — rate-limits refetches.
    last_attempt: Option<Instant>,
    /// Why the last refresh was refused, until a refresh succeeds.
    rejected: Option<String>,
}

/// A key set fetched over the network: reused for [`JWKS_TTL`], refetched
/// for an unknown `kid` at most once per [`JWKS_REFRESH_MIN_INTERVAL`], and
/// kept verifying for up to [`JWKS_MAX_STALENESS`] while its source cannot
/// be reached.
#[derive(Default)]
struct KeyCache {
    jwks: RwLock<Option<CachedJwks>>,
    refresh_state: Mutex<RefreshState>,
    /// Serializes refreshes so concurrent requests share one fetch.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Whose keys a [`KeyCache`] holds, for its metrics and logs.
#[derive(Clone, Copy)]
enum KeyOwner<'a> {
    /// A trusted IdP, by its configured issuer.
    Idp(&'a str),
    /// An OAuth client that authenticates with `private_key_jwt`.
    Client(&'a str),
}

impl KeyOwner<'_> {
    fn count_refresh(self, outcome: &'static str) {
        match self {
            KeyOwner::Idp(issuer) => metrics::counter!(
                "mcpg_ema_jwks_refresh_total",
                "idp" => issuer.to_owned(),
                "outcome" => outcome,
            )
            .increment(1),
            // No client label: metadata-document clients are not bounded
            // by the configuration.
            KeyOwner::Client(_) => {
                metrics::counter!("mcpg_ema_client_jwks_refresh_total", "outcome" => outcome)
                    .increment(1);
            }
        }
    }
}

impl KeyCache {
    fn rejected(&self) -> Option<String> {
        self.refresh_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .rejected
            .clone()
    }

    /// The key that verifies a JWT with header `kid` and `alg`, refreshing
    /// the set through `fetch` when it is missing, expired or lacks the kid.
    async fn key_for<F, Fut>(
        &self,
        owner: KeyOwner<'_>,
        kid: Option<&str>,
        alg: Algorithm,
        fetch: F,
    ) -> Result<DecodingKey, KeyError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<JwkSet, FetchFailure>>,
    {
        let observed = {
            let cache = self.jwks.read().await;
            if let Some(cached) = cache.as_ref()
                && cached.fetched_at.elapsed() < JWKS_TTL
                && let Some(key) = select_key(&cached.keys, kid, alg)?
            {
                return Ok(key);
            }
            cache.as_ref().map(|c| c.fetched_at)
        };
        // Miss, expired set or unknown kid: refresh, one request at a time.
        let _refreshing = self.refresh_lock.lock().await;
        let current = self.jwks.read().await.as_ref().map(|c| c.fetched_at);
        let outcome = if current == observed {
            self.refresh(owner, fetch).await
        } else {
            RefreshOutcome::Refreshed
        };
        let cache = self.jwks.read().await;
        let usable = cache
            .as_ref()
            .filter(|c| c.fetched_at.elapsed() < JWKS_MAX_STALENESS);
        match (outcome, usable) {
            (RefreshOutcome::Rejected(reason), _) => Err(KeyError::Misconfigured(reason)),
            (_, None) => Err(match self.rejected() {
                Some(reason) => KeyError::Misconfigured(reason),
                None => KeyError::Unavailable,
            }),
            (RefreshOutcome::Refreshed | RefreshOutcome::RateLimited, Some(cached)) => {
                select_key(&cached.keys, kid, alg)?
                    .ok_or(KeyError::NoMatch("no published key matches the kid"))
            }
            // The source is unreachable: a key it rotated in since the last
            // fetch cannot be told apart from a bogus kid, so both wait.
            (RefreshOutcome::Failed, Some(cached)) => {
                select_key(&cached.keys, kid, alg)?.ok_or(KeyError::Unavailable)
            }
        }
    }

    /// Refetch the set through `fetch`, at most once per
    /// [`JWKS_REFRESH_MIN_INTERVAL`]. Logs once per attempt that fails.
    async fn refresh<F, Fut>(&self, owner: KeyOwner<'_>, fetch: F) -> RefreshOutcome
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<JwkSet, FetchFailure>>,
    {
        {
            let mut state = self.refresh_state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(at) = state.last_attempt
                && at.elapsed() < JWKS_REFRESH_MIN_INTERVAL
            {
                return RefreshOutcome::RateLimited;
            }
            state.last_attempt = Some(Instant::now());
        }
        match fetch().await {
            Ok(keys) => {
                *self.jwks.write().await = Some(CachedJwks {
                    keys,
                    fetched_at: Instant::now(),
                });
                self.refresh_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .rejected = None;
                owner.count_refresh("ok");
                RefreshOutcome::Refreshed
            }
            Err(FetchFailure::Transient(error)) => {
                let serving_cached = self
                    .jwks
                    .read()
                    .await
                    .as_ref()
                    .is_some_and(|c| c.fetched_at.elapsed() < JWKS_MAX_STALENESS);
                let error = format!("{error:#}");
                match owner {
                    KeyOwner::Idp(issuer) => tracing::warn!(
                        issuer = %issuer,
                        error = %error,
                        serving_cached_keys = serving_cached,
                        "trusted IdP signing keys could not be refreshed"
                    ),
                    KeyOwner::Client(client_id) => tracing::warn!(
                        client_id = %client_id,
                        error = %error,
                        serving_cached_keys = serving_cached,
                        "OAuth client signing keys could not be refreshed"
                    ),
                }
                owner.count_refresh("failed");
                RefreshOutcome::Failed
            }
            Err(FetchFailure::Rejected(reason)) => {
                match owner {
                    KeyOwner::Idp(issuer) => tracing::warn!(
                        issuer = %issuer,
                        reason = %reason,
                        "trusted IdP signing keys refused; ID-JAGs from this IdP fail until it \
                         is fixed"
                    ),
                    KeyOwner::Client(client_id) => tracing::warn!(
                        client_id = %client_id,
                        reason = %reason,
                        "OAuth client signing keys refused; this client cannot authenticate \
                         until they are fixed"
                    ),
                }
                owner.count_refresh("rejected");
                *self.jwks.write().await = None;
                self.refresh_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .rejected = Some(reason.clone());
                RefreshOutcome::Rejected(reason)
            }
        }
    }
}

struct IdpEntry {
    config: TrustedIdpConfig,
    allowed_algs: Vec<Algorithm>,
    /// Keys configured inline (`trusted_idps[].jwks`): never fetched.
    static_keys: Option<JwkSet>,
    keys: KeyCache,
    /// The gateway's own client at this IdP, with a `login` block.
    login: Option<upstream::LoginClient>,
}

impl IdpEntry {
    /// `config`, a trusted IdP of the server `server` configures.
    fn from_config(config: &TrustedIdpConfig, server: &AuthorizationServerConfig) -> Result<Self> {
        let allowed_algs = config
            .allowed_algs
            .iter()
            .map(|alg| mcpg_plugin_identity_oidc_core::parse_algorithm(alg))
            .collect::<Result<Vec<_>>>()
            .map_err(|e| anyhow::anyhow!("trusted_idps[`{}`].allowed_algs: {e}", config.issuer))?;
        let static_keys = config
            .inline_jwks()
            .map_err(|e| anyhow::anyhow!("trusted_idps[`{}`].jwks {e}", config.issuer))?;
        let login = config
            .login
            .as_ref()
            .map(|login| upstream::LoginClient::from_config(config, login, server))
            .transpose()?;
        Ok(Self {
            config: config.clone(),
            allowed_algs,
            static_keys,
            keys: KeyCache::default(),
            login,
        })
    }
}

/// Why no verification key is available for an assertion.
#[derive(Debug)]
enum KeyError {
    /// The key set holds no key for the assertion.
    NoMatch(&'static str),
    /// The key set cannot be fetched now and no usable copy is cached.
    Unavailable,
    /// The IdP's published metadata cannot be used as configured.
    Misconfigured(String),
}

/// Why a discovery or JWKS fetch failed.
#[derive(Debug)]
enum FetchFailure {
    /// Network, server or body problem: may heal on retry.
    Transient(anyhow::Error),
    /// The IdP's answer contradicts the configuration or the outbound
    /// policy. The text is safe to return to the client.
    Rejected(String),
}

/// A non-success `status` from `url`, classed by whether a retry may
/// succeed: a server error, a timeout or a rate limit may heal; a
/// redirect or any other client error answers the same way next time.
fn status_failure(url: &str, status: reqwest::StatusCode) -> FetchFailure {
    use reqwest::StatusCode;
    if status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        )
    {
        FetchFailure::Transient(anyhow::anyhow!("{url} returned {status}"))
    } else if status.is_redirection() {
        FetchFailure::Rejected(format!(
            "{url} answered with a redirect ({status}), and redirects are not followed"
        ))
    } else {
        FetchFailure::Rejected(format!("{url} returned {status}"))
    }
}

enum RefreshOutcome {
    Refreshed,
    RateLimited,
    Failed,
    Rejected(String),
}

/// The embedded EMA authorization server. One instance per gateway
/// runtime; rebuilt on config reload.
pub struct AuthorizationServer {
    issuer: String,
    /// Resource identifiers a token can be minted for: the default first,
    /// then every one the PRM advertises.
    resources: Vec<String>,
    /// The first key signs; every key verifies the tokens naming its kid.
    signing_keys: Vec<SigningKey>,
    /// The public keys of the asymmetric signing keys; `None` when there
    /// are none.
    jwks: Option<serde_json::Value>,
    access_token_ttl: Duration,
    leeway_secs: u64,
    max_assertion_lifetime_secs: u64,
    enforce_single_use: bool,
    allowed_scopes: Option<Vec<String>>,
    /// Scopes a `scope` request parameter may name: `allowed_scopes` and
    /// the PRM `scopes_supported`.
    known_scopes: Vec<String>,
    require_scope: bool,
    clients: Vec<Arc<clients::Client>>,
    /// Roles every caller of a client's tokens carries, by `client_id`.
    client_roles: BTreeMap<String, Vec<String>>,
    /// Clients identified by their metadata document; `None` while
    /// `client_id_metadata_documents` is off.
    client_metadata: Option<clients::ClientMetadataDocuments>,
    rate_limit_per_min: u32,
    advertised_scopes: Vec<String>,
    idps: Vec<IdpEntry>,
    replay: ReplayLedger,
    /// The sealed state of interactive sign-in; `None` without a
    /// `trusted_idps[].login` entry.
    interactive_state: Option<InteractiveState>,
    /// `interactive`, or its defaults.
    interactive: crate::config::InteractiveLoginConfig,
    /// The SHA-256 digests of the initial access tokens that authorize a
    /// dynamic registration; the tokens themselves are not kept.
    registration_token_digests: Vec<dcr::TokenDigest>,
    /// Whether a federation presents the caller's stored IdP sign-in
    /// upstream (`subject_token: idp_refresh_token` or `idp_id_token`).
    federated_idp_sessions: bool,
    /// How long the retry of a request that offered a link waits for the
    /// user to complete it.
    link_resume_wait: Duration,
    /// DPoP proofs and key-bound tokens.
    dpop: dpop::DpopSettings,
    /// The authorization details types grants may be limited to.
    rar: rar::RarSettings,
    http: reqwest::Client,
}

impl std::fmt::Debug for AuthorizationServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationServer")
            .field("issuer", &self.issuer)
            .field("resources", &self.resources)
            .field(
                "signing_kids",
                &self.signing_keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            )
            .field("idps", &self.idps.len())
            .field("clients", &self.clients.len())
            .field(
                "client_id_metadata_documents",
                &self.client_metadata.is_some(),
            )
            .field("replay", &self.replay)
            .field("interactive_state", &self.interactive_state)
            .field("dynamic_client_registration", &self.registers_clients())
            .field("dpop", &self.dpop)
            .field("rar", &self.rar)
            .finish_non_exhaustive()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether a JOSE `typ` names the media subtype `subtype`, with or
/// without the `application/` prefix (RFC 7515 §4.1.9), ignoring case.
fn jose_typ_is(typ: &str, subtype: &str) -> bool {
    const PREFIX: &str = "application/";
    let bare = match typ.get(..PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(PREFIX) => &typ[PREFIX.len()..],
        _ => typ,
    };
    bare.eq_ignore_ascii_case(subtype)
}

/// Whether a JOSE `typ` names an ID-JAG.
fn is_id_jag_typ(typ: &str) -> bool {
    jose_typ_is(typ, ID_JAG_TYP)
}

/// Whether `token` is typed as an ID-JAG (RFC 8725 §3.11): a grant for an
/// authorization server's token endpoint, never an access token, whoever
/// signed it.
pub fn is_id_jag(token: &str) -> bool {
    jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|header| header.typ)
        .is_some_and(|typ| is_id_jag_typ(&typ))
}

/// Constant-time string equality (length differences still leak, which
/// is inherent to comparing variable-length secrets).
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Decode a JWT payload segment WITHOUT verification — used only to
/// route by `iss` and to word error descriptions, never to establish
/// trust.
fn unverified_payload(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn unverified_claim_iss(token: &str) -> Option<String> {
    unverified_claim_str(token, "iss")
}

fn unverified_claim_str(token: &str, claim: &str) -> Option<String> {
    unverified_payload(token)?
        .get(claim)?
        .as_str()
        .map(str::to_owned)
}

/// A claim of the client's own assertion, as JSON, cut to [`ECHO_LIMIT`]
/// characters for an error description.
fn echoed_claim(token: &str, claim: &str) -> String {
    let rendered = unverified_payload(token)
        .and_then(|payload| payload.get(claim).map(serde_json::Value::to_string))
        .unwrap_or_else(|| "(none)".to_owned());
    if rendered.chars().count() > ECHO_LIMIT {
        format!("{}…", rendered.chars().take(ECHO_LIMIT).collect::<String>())
    } else {
        rendered
    }
}

/// The key in `keys` that verifies an assertion with header `kid` and
/// `alg`. `Ok(None)` when none matches.
fn select_key(
    keys: &JwkSet,
    kid: Option<&str>,
    alg: Algorithm,
) -> Result<Option<DecodingKey>, KeyError> {
    let jwk = match kid {
        Some(kid) => keys
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        // No kid: unambiguous only when a single key is published or
        // exactly one matches the assertion's algorithm.
        None => {
            let matching: Vec<_> = keys
                .keys
                .iter()
                .filter(|k| {
                    k.common
                        .key_algorithm
                        .and_then(map_key_algorithm)
                        .map(|a| a == alg)
                        .unwrap_or(true)
                })
                .collect();
            if matching.len() == 1 {
                Some(matching[0])
            } else {
                keys.keys.first().filter(|_| keys.keys.len() == 1)
            }
        }
    };
    let Some(jwk) = jwk else {
        return Ok(None);
    };
    // A JWK declaring its algorithm must agree with the assertion header —
    // mismatches are downgrade attempts.
    if let Some(key_alg) = jwk.common.key_algorithm.and_then(map_key_algorithm)
        && key_alg != alg
    {
        return Err(KeyError::NoMatch(
            "the assertion alg does not match the published key algorithm",
        ));
    }
    DecodingKey::from_jwk(jwk)
        .map(Some)
        .map_err(|_| KeyError::NoMatch("the published key is unusable"))
}

impl AuthorizationServer {
    /// Minted tokens are audience-restricted to the resource the request
    /// or the ID-JAG names, or by default to `authorization_server.resource`,
    /// else the PRM `resource`, else the issuer. Every resource identifier
    /// the PRM advertises (`resource` and `additional_resources`) can be
    /// named, and `scopes_supported` joins the scope vocabulary. Redeemed
    /// assertions are recorded in `replay`.
    pub fn from_config(
        config: &AuthorizationServerConfig,
        resource_metadata: Option<&OAuthResourceMetadataConfig>,
        replay: ReplayLedger,
    ) -> Result<Self> {
        let signing_keys = load_signing_keys(config)?;
        let public_keys: Vec<&Jwk> = signing_keys
            .iter()
            .filter_map(|key| key.public_jwk.as_ref())
            .collect();
        let jwks = (!public_keys.is_empty()).then(|| serde_json::json!({ "keys": public_keys }));
        let issuer = config.issuer.clone();
        let canonical = config
            .resource
            .clone()
            .or_else(|| resource_metadata.map(|rm| rm.resource.clone()))
            .unwrap_or_else(|| issuer.clone());
        let mut resources = vec![canonical];
        for advertised in resource_metadata.into_iter().flat_map(|rm| rm.resources()) {
            if !resources.iter().any(|r| r == advertised) {
                resources.push(advertised.to_owned());
            }
        }
        let known_scopes = config
            .allowed_scopes
            .iter()
            .flatten()
            .chain(
                resource_metadata
                    .into_iter()
                    .flat_map(|rm| rm.scopes_supported.iter()),
            )
            .cloned()
            .collect();
        let advertised_scopes = config.allowed_scopes.clone().unwrap_or_default();
        let interactive = config.interactive_settings().into_owned();
        let registration_token_digests =
            dcr::token_digests(&interactive.dynamic_client_registration)?;
        let dpop = dpop::DpopSettings::from_config(
            &config.dpop,
            config.clock_skew_secs,
            &issuer,
            &resources,
        )?;
        let rar = rar::RarSettings::from_config(&config.authorization_details, &resources)?;
        Ok(Self {
            signing_keys,
            jwks,
            issuer,
            resources,
            access_token_ttl: Duration::from_secs(config.access_token_ttl_secs),
            leeway_secs: config.clock_skew_secs,
            max_assertion_lifetime_secs: config.max_assertion_lifetime_secs,
            enforce_single_use: config.enforce_single_use,
            allowed_scopes: config.allowed_scopes.clone(),
            known_scopes,
            require_scope: config.require_scope,
            clients: config
                .clients
                .iter()
                .map(|client| clients::Client::from_config(client).map(Arc::new))
                .collect::<Result<_>>()?,
            client_roles: config.client_roles.clone(),
            client_metadata: config.client_id_metadata_documents_enabled().then(|| {
                clients::ClientMetadataDocuments::new(config.client_id_metadata_documents.clone())
            }),
            rate_limit_per_min: config.rate_limit_per_min,
            advertised_scopes,
            idps: config
                .trusted_idps
                .iter()
                .map(|idp| IdpEntry::from_config(idp, config))
                .collect::<Result<_>>()?,
            replay,
            interactive_state: None,
            interactive,
            registration_token_digests,
            federated_idp_sessions: false,
            link_resume_wait: connect::LINK_RESUME_WAIT,
            dpop,
            rar,
            http: reqwest::Client::builder()
                .timeout(IDP_FETCH_TIMEOUT)
                // `enforce_discovery_url_safety` vets the URL we are about to
                // request, so following a redirect would reach an address the
                // guard never saw — an open redirect on the IdP's own domain
                // is enough to leave the allowlist.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| {
                    anyhow::anyhow!("building EMA authorization server HTTP client: {e}")
                })?,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The absolute URL of `path` on this server. The issuer may end in
    /// `/`, the RFC 8414 form of an issuer without a path.
    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer.trim_end_matches('/'))
    }

    /// Where redeemed assertions are recorded; a reload hands an
    /// in-process ledger to the server that replaces this one.
    pub fn replay_ledger(&self) -> &ReplayLedger {
        &self.replay
    }

    /// This server with `state` as the state of interactive sign-in.
    pub fn with_interactive_state(mut self, state: Option<InteractiveState>) -> Self {
        self.interactive_state = state;
        self
    }

    /// This server with the login endpoints `previous` discovered at each
    /// trusted IdP whose entry, `login` block included, is unchanged.
    pub fn with_login_endpoints_of(mut self, previous: Option<&AuthorizationServer>) -> Self {
        let Some(previous) = previous else {
            return self;
        };
        for entry in &mut self.idps {
            let Some(login) = entry.login.as_mut() else {
                continue;
            };
            if let Some(old) = previous
                .idps
                .iter()
                .find(|old| old.config == entry.config)
                .and_then(|old| old.login.as_ref())
            {
                login.adopt_discovered(old);
            }
        }
        self
    }

    /// The sealed state of interactive sign-in, present while a trusted
    /// IdP has a `login` block; a reload hands it to the server that
    /// replaces this one.
    pub fn interactive_state(&self) -> Option<&InteractiveState> {
        self.interactive_state.as_ref()
    }

    /// This server knowing whether a federation presents the caller's
    /// stored IdP sign-in upstream, which the consent page tells the user.
    pub fn with_federated_idp_sessions(mut self, federated: bool) -> Self {
        self.federated_idp_sessions = federated;
        self
    }

    /// This server knowing how long the gateway answers a request, which
    /// bounds how long a retry waits for a link to complete: a third of
    /// it, at most [`connect::LINK_RESUME_WAIT`].
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.link_resume_wait = connect::LINK_RESUME_WAIT.min(timeout / 3);
        self
    }

    /// The settings of interactive sign-in: `interactive`, or its
    /// defaults.
    pub fn interactive_settings(&self) -> &crate::config::InteractiveLoginConfig {
        &self.interactive
    }

    /// The JWK Set (RFC 7517) of the asymmetric signing keys, served at
    /// [`JWKS_PATH`]. `None` when every key is an HMAC secret, which is
    /// never published.
    pub fn jwks(&self) -> Option<&serde_json::Value> {
        self.jwks.as_ref()
    }

    /// Refused token requests allowed per minute from one client address;
    /// `0` is unlimited.
    pub fn rate_limit_per_min(&self) -> u32 {
        self.rate_limit_per_min
    }

    /// RFC 8414 authorization-server metadata document. With a login IdP
    /// it also describes the authorization endpoint: the `code` response
    /// in the query, PKCE with `S256` only, and `iss` in every
    /// authorization response (RFC 9207 §3); the RFC 7009 revocation
    /// endpoint, where clients authenticate as at the token endpoint; and,
    /// while dynamic client registration is on, the RFC 7591
    /// `registration_endpoint`. `offline_access` is never a scope here:
    /// refresh tokens do not depend on it. With DPoP on, it names the
    /// algorithms a proof may use; with authorization details on, the
    /// types a grant may be limited to.
    pub fn metadata(&self) -> serde_json::Value {
        let auth_methods = self.token_endpoint_auth_methods();
        let mut metadata = serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": self.endpoint(TOKEN_PATH),
            "grant_types_supported": [GRANT_TYPE_JWT_BEARER],
            "authorization_grant_profiles_supported": [GRANT_PROFILE_ID_JAG],
            "token_endpoint_auth_methods_supported": auth_methods,
            "scopes_supported": self.advertised_scopes,
            "response_types_supported": [],
        });
        if self.login_idp().is_some() {
            use crate::config::ClientGrantType;
            let mut grant_types = vec![
                ClientGrantType::JwtBearer.as_str(),
                ClientGrantType::AuthorizationCode.as_str(),
            ];
            if self.interactive.refresh_tokens.enabled {
                grant_types.push(ClientGrantType::RefreshToken.as_str());
            }
            metadata["authorization_endpoint"] =
                serde_json::json!(self.endpoint(interactive::AUTHORIZE_PATH));
            metadata["grant_types_supported"] = serde_json::json!(grant_types);
            metadata["response_types_supported"] = serde_json::json!(["code"]);
            metadata["response_modes_supported"] = serde_json::json!(["query"]);
            metadata["code_challenge_methods_supported"] =
                serde_json::json!([redirect::PKCE_METHOD_S256]);
            metadata["authorization_response_iss_parameter_supported"] = serde_json::json!(true);
            metadata["revocation_endpoint"] =
                serde_json::json!(self.endpoint(revocation::REVOCATION_PATH));
            metadata["revocation_endpoint_auth_methods_supported"] =
                serde_json::json!(auth_methods);
            if self.registers_clients() {
                metadata["registration_endpoint"] =
                    serde_json::json!(self.endpoint(dcr::REGISTRATION_PATH));
            }
        }
        // RFC 8414 §2: required whenever private_key_jwt is offered.
        if auth_methods.contains(&ClientAuthMethod::PrivateKeyJwt.as_str()) {
            let algs: Vec<&str> = clients::CLIENT_ASSERTION_ALGS
                .iter()
                .map(|(_, name)| *name)
                .collect();
            metadata["token_endpoint_auth_signing_alg_values_supported"] = serde_json::json!(algs);
            if metadata.get("revocation_endpoint").is_some() {
                metadata["revocation_endpoint_auth_signing_alg_values_supported"] =
                    serde_json::json!(algs);
            }
        }
        if self.client_metadata.is_some() {
            metadata["client_id_metadata_document_supported"] = serde_json::json!(true);
        }
        if self.jwks.is_some() {
            metadata["jwks_uri"] = serde_json::json!(self.endpoint(JWKS_PATH));
        }
        // RFC 9449 §5.1.
        if self.dpop.enabled {
            metadata["dpop_signing_alg_values_supported"] =
                serde_json::json!(self.dpop.alg_names());
        }
        // RFC 9396 §10.
        if self.rar.enabled() {
            metadata["authorization_details_types_supported"] =
                serde_json::json!(self.rar.type_names());
        }
        metadata
    }

    /// The client authentication methods some client can use: those of
    /// the registered clients, the two a metadata document may declare
    /// when unregistered documents are admitted, and `none`, which every
    /// dynamically registered client uses, while registration is on.
    fn token_endpoint_auth_methods(&self) -> Vec<&'static str> {
        let mut offered: Vec<ClientAuthMethod> = self
            .clients
            .iter()
            .flat_map(|client| client.methods())
            .collect();
        if self
            .client_metadata
            .as_ref()
            .is_some_and(clients::ClientMetadataDocuments::admits_unregistered)
        {
            offered.extend([ClientAuthMethod::PrivateKeyJwt, ClientAuthMethod::None]);
        }
        if self.registers_clients() {
            offered.push(ClientAuthMethod::None);
        }
        [
            ClientAuthMethod::ClientSecretBasic,
            ClientAuthMethod::ClientSecretPost,
            ClientAuthMethod::PrivateKeyJwt,
            ClientAuthMethod::None,
        ]
        .into_iter()
        .filter(|method| offered.contains(method))
        .map(ClientAuthMethod::as_str)
        .collect()
    }

    /// Handle a `POST /oauth/token` request. `basic_auth` is the raw
    /// `Authorization` header value, if any.
    pub async fn handle_token_request(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        self.redeem(form, basic_auth)
            .await
            .result
            .map(|(response, _)| response)
    }

    /// [`Self::handle_token_request`], with what the request resolved to
    /// for its audit record. Records the token-endpoint metrics and logs
    /// every issued token.
    pub async fn redeem(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
    ) -> TokenRedemption {
        self.redeem_with_dpop(form, basic_auth, &dpop::DpopPresentation::none())
            .await
    }

    /// [`Self::redeem`] of a request whose `DPoP` headers are
    /// `presentation`. While DPoP is off they are ignored.
    pub async fn redeem_with_dpop(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        presentation: &dpop::DpopPresentation<'_>,
    ) -> TokenRedemption {
        let started = Instant::now();
        let mut context = RedemptionContext::default();
        let result = self
            .redeem_grant(form, basic_auth, presentation, &mut context)
            .await;
        if result.is_ok()
            && matches!(
                context.grant,
                TokenGrant::AuthorizationCode | TokenGrant::RefreshToken
            )
            && let Some(ref client_id) = context.client_id
        {
            self.renew_registration(client_id).await;
        }
        let redemption = TokenRedemption {
            result,
            context,
            dpop_nonce: self.token_endpoint_nonce(),
        };
        redemption.record(started.elapsed());
        redemption
    }

    /// Dispatch a token request on its `grant_type`: an ID-JAG, or, with a
    /// login IdP, the authorization code of an interactive sign-in and,
    /// while refresh tokens are on, a refresh token. A DPoP proof is
    /// checked and spent first, before the client authenticates.
    async fn redeem_grant(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        presentation: &dpop::DpopPresentation<'_>,
        context: &mut RedemptionContext,
    ) -> Result<(TokenResponse, IssuedToken), OAuthError> {
        context.grant = TokenGrant::of(form.grant_type.as_deref());
        context.dpop_presented = self.dpop.enabled && presentation.is_present();
        let proof = self.token_request_proof(presentation).await?;
        let proof = proof.as_ref();
        match (context.grant, form.grant_type.as_deref()) {
            (TokenGrant::JwtBearer, _) => {
                self.redeem_id_jag(form, basic_auth, proof, context).await
            }
            (TokenGrant::AuthorizationCode, _) if self.login_idp().is_some() => {
                self.redeem_code(form, basic_auth, proof, context).await
            }
            (TokenGrant::RefreshToken, _) if self.refreshes() => {
                self.redeem_refresh(form, basic_auth, proof, context).await
            }
            (_, Some(other)) => Err(OAuthError::new(
                "unsupported_grant_type",
                format!(
                    "unsupported grant_type `{}`; this server supports {}",
                    other.chars().take(ECHO_LIMIT).collect::<String>(),
                    self.supported_grant_types()
                ),
            )),
            (_, None) => Err(OAuthError::new("invalid_request", "grant_type is required")),
        }
    }

    /// The grant types the token endpoint redeems, for an error
    /// description.
    fn supported_grant_types(&self) -> &'static str {
        if self.refreshes() {
            "jwt-bearer ID-JAG redemption, authorization_code and refresh_token"
        } else if self.login_idp().is_some() {
            "jwt-bearer ID-JAG redemption and authorization_code"
        } else {
            "only jwt-bearer ID-JAG redemption"
        }
    }

    /// Whether the token endpoint redeems refresh tokens: with a login IdP,
    /// while `interactive.refresh_tokens.enabled`.
    fn refreshes(&self) -> bool {
        self.login_idp().is_some() && self.interactive.refresh_tokens.enabled
    }

    /// Redeem an ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`),
    /// with the DPoP `proof` of the request when it carries one.
    async fn redeem_id_jag(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
        proof: Option<&dpop::ProvenKey>,
        context: &mut RedemptionContext,
    ) -> Result<(TokenResponse, IssuedToken), OAuthError> {
        let client = self.authenticate(&form, basic_auth).await?;
        let client_id = client.client_id.clone();
        context.client_id = Some(client_id.clone());
        if !client.redeems_id_jags() {
            return Err(OAuthError::new(
                "unauthorized_client",
                "this client's grant_types lack urn:ietf:params:oauth:grant-type:jwt-bearer",
            ));
        }
        let assertion = form
            .assertion
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| OAuthError::new("invalid_request", "assertion is required"))?;

        let ValidatedGrant {
            claims,
            identity,
            resource,
            cnf_jkt,
            authorization_details,
        } = self
            .validate_id_jag(
                assertion,
                &client_id,
                form.resource.as_deref(),
                &mut context.idp,
            )
            .await?;
        let dpop_jkt = self.id_jag_binding(cnf_jkt.as_deref(), proof, &client)?;
        // ID-JAG §4.4.1: the token request may narrow the details granted.
        let authorization_details = self.requested_details(
            &authorization_details,
            form.authorization_details.as_deref(),
            rar::DetailsSource::IdJag,
        )?;

        let granted = self.grant_scopes(claims.scope.as_deref(), form.scope.as_deref())?;
        if granted.is_empty() && self.require_scope {
            return Err(OAuthError::new(
                "invalid_scope",
                "no scope can be granted: the assertion's scope, narrowed by the scopes this \
                 server allows and by the requested scope, is empty",
            ));
        }
        // Recorded only once the redemption can no longer be refused, so a
        // client may retry the same assertion with another `scope`.
        if self.enforce_single_use {
            self.record_redemption(&claims.iss, &claims.jti, claims.exp)
                .await?;
        }

        let now = now_unix();
        let expires_in = self.access_token_ttl.as_secs();
        let scope = Some(granted.join(" ")).filter(|s| !s.is_empty());
        let actor = identity.actor();
        let roles = self.roles_for(&client_id, &identity.roles);
        let minted = MintedClaims {
            iss: self.issuer.clone(),
            sub: identity.subject,
            aud: resource.clone(),
            client_id,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp: now + expires_in,
            scope: scope.clone(),
            email: claims.email,
            idp: claims.iss,
            groups: identity.groups,
            roles: identity.roles,
            attributes: identity.attributes,
            act: identity.act,
            tenant: identity.tenant,
            amr: identity.amr,
            gid: None,
            gty: None,
            auth_time: None,
            cnf: Confirmation::of(dpop_jkt.clone()),
            authorization_details,
        };
        let access_token = self.signing_keys[0].sign(&minted).map_err(minting_failed)?;
        let issued = IssuedToken {
            subject: minted.sub,
            actor,
            jti: minted.jti,
            assertion_jti: Some(claims.jti),
            scope: scope.clone(),
            resource: resource.clone(),
            expires_in,
            roles,
            groups: minted.groups,
            grant: None,
            dpop_jkt,
            authorization_details_digest: self.details_digest(&minted.authorization_details),
            authorization_details: minted.authorization_details,
        };
        let response = TokenResponse {
            access_token,
            token_type: issued.token_type(),
            expires_in,
            scope,
            resource,
            refresh_token: None,
            authorization_details: issued.authorization_details.clone(),
        };
        Ok((response, issued))
    }

    /// Scopes the minted token carries: the ID-JAG's `scope` ∩
    /// `allowed_scopes` (when set), narrowed to the request's `scope`
    /// parameter when it names any scope this server knows. A request
    /// whose known scopes the grant holds none of is `invalid_scope`: a
    /// response without `scope` would tell the client it got them all
    /// (RFC 6749 §5.1).
    fn grant_scopes<'a>(
        &self,
        assertion_scope: Option<&'a str>,
        requested: Option<&str>,
    ) -> Result<Vec<&'a str>, OAuthError> {
        let mut grantable: Vec<&str> = Vec::new();
        for scope in assertion_scope.unwrap_or_default().split_whitespace() {
            let allowed = self
                .allowed_scopes
                .as_ref()
                .is_none_or(|allowed| allowed.iter().any(|a| a == scope));
            if allowed && !grantable.contains(&scope) {
                grantable.push(scope);
            }
        }
        let recognized: Vec<&str> = requested
            .unwrap_or_default()
            .split_whitespace()
            .filter(|scope| {
                grantable.contains(scope) || self.known_scopes.iter().any(|k| k == scope)
            })
            .collect();
        if recognized.is_empty() {
            return Ok(grantable);
        }
        grantable.retain(|scope| recognized.contains(scope));
        if grantable.is_empty() {
            return Err(OAuthError::new(
                "invalid_scope",
                "the requested scope exceeds what the enterprise IdP granted: the assertion's \
                 scope, narrowed by the scopes this server allows, holds none of it",
            ));
        }
        Ok(grantable)
    }

    /// Probe an inbound bearer: if its (unverified) `iss` names this
    /// server, it MUST verify here — no fall-through once the issuer
    /// claims to be ours. The key is the one the token's `kid` names, and
    /// only with that key's algorithm. The IdP and the client the token
    /// was minted for must still be trusted: removing either from the
    /// configuration revokes the tokens already issued for it. A token of
    /// an interactive grant is refused once its grant is revoked, and any
    /// token once its `jti` is: this replica's revocations at once, other
    /// replicas' within `interactive.revocation_check_interval_secs`. A
    /// token of an interactive grant is refused too while this server
    /// keeps no usable sign-in state (no `login` block any more, or a
    /// store unavailable since boot), which is where its revocation would
    /// be learned. A token bound to a DPoP key (`cnf`) is always refused
    /// here: it is not a Bearer token. While DPoP is `required`, so is a
    /// token bound to no key.
    pub fn verify_bearer(&self, bearer: &str) -> EmaBearerOutcome {
        match unverified_claim_iss(bearer) {
            Some(iss) if iss == self.issuer => {}
            _ => return EmaBearerOutcome::NotOurs,
        }
        let claims = match self.decode_minted(bearer) {
            Ok(claims) => claims,
            Err(reason) => return EmaBearerOutcome::Invalid(reason),
        };
        // RFC 9449 §7.2: whether or not DPoP is still on, a bound token is
        // useless without its key.
        if claims.cnf.is_some() {
            return self.bound_token_as_bearer();
        }
        if let Some(refused) = self.unbound_token_refused() {
            return refused;
        }
        match self.verified_identity(claims) {
            Ok(identity) => EmaBearerOutcome::Verified(identity),
            Err(reason) => EmaBearerOutcome::Invalid(reason),
        }
    }

    /// The caller of `claims`, a token this server minted and whose
    /// signature, audience and lifetime verified, after every check of the
    /// token itself: the grant it names, its revocation, and the trust of
    /// its IdP, client and tenant. Else why it is refused. The authorization
    /// details the token is limited to become attributes whatever the
    /// configuration says now: a restriction outlives a change of it.
    fn verified_identity(&self, claims: MintedClaims) -> Result<EmaVerifiedIdentity, String> {
        let grant_type = match (claims.gty.as_deref(), claims.gid.as_ref()) {
            (None, None) => GRANT_ATTRIBUTE_ID_JAG,
            (Some(grants::GRANT_TYPE_AUTHORIZATION_CODE), Some(_)) => {
                if !self
                    .interactive_state
                    .as_ref()
                    .is_some_and(InteractiveState::is_available)
                {
                    return Err(
                        "token of an interactive sign-in, whose revocation this server can no \
                         longer learn"
                            .to_owned(),
                    );
                }
                grants::GRANT_TYPE_AUTHORIZATION_CODE
            }
            _ => return Err("token names a grant this server does not issue".to_owned()),
        };
        if self.is_revoked(&claims) {
            return Err("token revoked".to_owned());
        }
        let idp = self
            .trusted_for(&claims.idp, &claims.client_id, claims.tenant.as_deref())
            .map_err(|reason| format!("token was minted for {reason}"))?;
        let scopes = claims
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let roles = self.roles_for(&claims.client_id, &claims.roles);
        // No mapped claim can stand in for an attribute the token sets
        // itself, including one this token leaves unset.
        let mut attributes = claims.attributes;
        attributes.retain(|name, _| !IDENTITY_ATTRIBUTES.contains(&name.as_str()));
        attributes.insert("client_id".to_owned(), claims.client_id);
        attributes.insert("idp".to_owned(), claims.idp);
        attributes.insert("token_issuer".to_owned(), claims.iss);
        if let Some(email) = claims.email {
            attributes.insert("email".to_owned(), email);
        }
        if let Some(actor) = actor_of(claims.act.as_ref()) {
            attributes.insert("actor".to_owned(), actor);
        }
        if let Some(ref tenant) = claims.tenant {
            attributes.insert("tenant".to_owned(), tenant.clone());
        }
        if !claims.amr.is_empty() {
            attributes.insert("amr".to_owned(), claims.amr.join(" "));
        }
        attributes.insert("grant_type".to_owned(), grant_type.to_owned());
        if let Some(gid) = claims.gid {
            attributes.insert("grant_id".to_owned(), gid.into());
        }
        if let Some(auth_time) = claims.auth_time {
            attributes.insert("auth_time".to_owned(), auth_time.to_string());
        }
        if !claims.authorization_details.is_empty() {
            attributes.insert(
                rar::AUTHORIZATION_DETAILS_ATTRIBUTE.to_owned(),
                claims.authorization_details.to_json(),
            );
            attributes.insert(
                rar::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_owned(),
                claims.authorization_details.types().join(" "),
            );
        }
        // A principal is namespaced by the IdP that vouched for it, not by
        // this gateway. `sub` is an opaque IdP-chosen string, so two
        // trusted IdPs can issue the same one — deliberately, or simply
        // because both use email as the subject. Reporting the gateway's
        // own issuer here would collapse those two people into one
        // principal key, and with it one session, task list and
        // idempotency scope. This matches what an OIDC-verified identity
        // reports; the minting issuer stays available as an attribute. A
        // `principal_issuer` joins the IdP's users to the principals its
        // OIDC provider reports instead.
        let Principal {
            issuer,
            auth_provider,
        } = Principal::of(&idp.config, claims.tenant.as_deref());
        Ok(EmaVerifiedIdentity {
            subject_id: claims.sub,
            issuer,
            auth_provider,
            roles,
            groups: claims.groups,
            scopes,
            attributes,
        })
    }

    /// The claims of a token this server minted, verified with the key its
    /// `kid` names. A token without a `kid` verifies only as HS256, with a
    /// secret configured without one.
    fn decode_minted(&self, bearer: &str) -> Result<MintedClaims, String> {
        self.decode_minted_with(bearer, true)
    }

    /// [`Self::decode_minted`], checking `exp` only when `check_expiry`:
    /// an expired token is still revoked (RFC 7009 §2.1).
    fn decode_minted_with(&self, bearer: &str, check_expiry: bool) -> Result<MintedClaims, String> {
        let header = jsonwebtoken::decode_header(bearer).map_err(|e| e.to_string())?;
        let keys: Vec<&SigningKey> = match header.kid.as_deref() {
            Some(kid) => vec![
                self.signing_keys
                    .iter()
                    .find(|key| key.kid == kid)
                    .ok_or("token names an unknown signing key")?,
            ],
            None if header.alg == Algorithm::HS256 => self
                .signing_keys
                .iter()
                .filter(|key| key.verifies_kidless)
                .collect(),
            None => Vec::new(),
        };
        if keys.is_empty() {
            return Err("token carries no kid".to_owned());
        }
        let mut refused = String::new();
        for key in keys {
            if header.alg != key.alg {
                return Err("token algorithm does not match its signing key".to_owned());
            }
            let mut validation = Validation::new(key.alg);
            validation.leeway = self.leeway_secs;
            validation.validate_exp = check_expiry;
            validation.set_audience(&self.resources);
            validation.set_issuer(&[self.issuer.as_str()]);
            validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
            match jsonwebtoken::decode::<MintedClaims>(bearer, &key.decoding, &validation) {
                // Only `at+jwt` is minted; anything else claiming this
                // issuer is not a token this server produced.
                Ok(data)
                    if data
                        .header
                        .typ
                        .as_deref()
                        .is_some_and(|t| t.eq_ignore_ascii_case(ACCESS_TOKEN_TYP)) =>
                {
                    return Ok(data.claims);
                }
                Ok(_) => return Err("unexpected token typ".to_owned()),
                Err(e) => refused = e.to_string(),
            }
        }
        Err(refused)
    }

    /// Whether the grant or the `jti` of a token this server minted is
    /// among the revocations this process holds. No store I/O.
    fn is_revoked(&self, claims: &MintedClaims) -> bool {
        let Some(ref state) = self.interactive_state else {
            return false;
        };
        if state.revoked().is_empty() {
            return false;
        }
        claims
            .gid
            .as_ref()
            .is_some_and(|gid| state.is_revoked(&state::RevokedId::Grant(gid.clone())))
            || state.is_revoked(&state::RevokedId::access_token(&claims.jti))
    }

    /// The trusted IdP a token for `client_id`, of a user of `tenant`, is
    /// minted through, while the configuration still trusts it for them:
    /// the IdP is still trusted, the client still known and still one the
    /// IdP admits, and the user of the tenant the IdP is pinned to. Else
    /// what the token would be for, which is no longer trusted.
    fn trusted_for(
        &self,
        idp_issuer: &str,
        client_id: &str,
        tenant: Option<&str>,
    ) -> Result<&IdpEntry, &'static str> {
        let Some(idp) = self.idps.iter().find(|idp| idp.config.issuer == idp_issuer) else {
            return Err("an enterprise IdP that is no longer trusted");
        };
        if !self.knows_client(client_id) {
            return Err("a client that is no longer registered");
        }
        if !idp_admits_client(&idp.config, client_id) {
            return Err("a client its enterprise IdP may no longer issue for");
        }
        if let Some(ref required) = idp.config.required_tenant
            && tenant != Some(required.as_str())
        {
            return Err("a tenant its enterprise IdP is no longer trusted for");
        }
        Ok(idp)
    }

    /// Whether `client_id` can authenticate here: a registered client, a
    /// metadata document URL the configuration admits, or, while dynamic
    /// client registration is on, a dynamically registered id (whether its
    /// registration still exists is checked where it is used).
    fn knows_client(&self, client_id: &str) -> bool {
        self.clients.iter().any(|c| c.client_id == client_id)
            || self
                .client_metadata
                .as_ref()
                .is_some_and(|documents| documents.admits(client_id))
            || (client_id.starts_with(clients::DCR_CLIENT_ID_PREFIX) && self.registers_clients())
    }

    /// The roles of a caller with `mapped` roles whose token was minted for
    /// `client_id`: those, then the client's `client_roles`.
    fn roles_for(&self, client_id: &str, mapped: &[String]) -> Vec<String> {
        distinct(
            mapped
                .iter()
                .chain(self.client_roles.get(client_id).into_iter().flatten())
                .cloned(),
        )
    }

    // ── ID-JAG validation ────────────────────────────────────────────

    /// Validate `assertion` for `authenticated_client_id`, and for the
    /// `requested_resource` of the token request when it names one.
    /// `routed_idp` is set to the trusted IdP it names once that is known.
    async fn validate_id_jag(
        &self,
        assertion: &str,
        authenticated_client_id: &str,
        requested_resource: Option<&str>,
        routed_idp: &mut Option<String>,
    ) -> Result<ValidatedGrant, OAuthError> {
        let header = jsonwebtoken::decode_header(assertion)
            .map_err(|_| OAuthError::invalid_grant("assertion is not a well-formed JWT"))?;
        if !header.typ.as_deref().is_some_and(is_id_jag_typ) {
            return Err(OAuthError::invalid_grant(
                "assertion `typ` must be oauth-id-jag+jwt",
            ));
        }
        // Asymmetric algorithms only: an HMAC alg with a public JWKS
        // would let anyone forge assertions.
        let alg = header.alg;
        if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            return Err(OAuthError::invalid_grant(
                "assertion must use an asymmetric signing algorithm",
            ));
        }
        let iss = unverified_claim_iss(assertion)
            .ok_or_else(|| OAuthError::invalid_grant("assertion carries no iss claim"))?;
        // RFC 7523 §3: `iss` is compared as a simple string.
        let Some(idp) = self.idps.iter().find(|e| e.config.issuer == iss) else {
            return Err(self.untrusted_issuer(&iss));
        };
        *routed_idp = Some(idp.config.issuer.clone());
        if !idp.allowed_algs.contains(&alg) {
            return Err(OAuthError::invalid_grant(format!(
                "assertion alg {alg:?} is not in allowed_algs for this enterprise IdP"
            )));
        }

        let decoding_key = self
            .decoding_key_for(idp, header.kid.as_deref(), alg)
            .await
            .map_err(|e| {
                tracing::debug!(issuer = %iss, error = ?e, "ID-JAG key resolution failed");
                match e {
                    KeyError::NoMatch(reason) => OAuthError::invalid_grant(format!(
                        "assertion signature key could not be resolved: {reason}"
                    )),
                    KeyError::Unavailable => OAuthError::temporarily_unavailable(
                        "the enterprise IdP's signing keys cannot be fetched right now; retry \
                         shortly",
                    ),
                    KeyError::Misconfigured(reason) => OAuthError::invalid_grant(format!(
                        "the enterprise IdP's signing keys cannot be used: {reason}"
                    )),
                }
            })?;

        let mut validation = Validation::new(alg);
        validation.leeway = self.leeway_secs;
        validation.validate_nbf = true;
        validation.set_audience(&[self.issuer.as_str()]);
        validation.set_issuer(&[idp.config.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let payload =
            jsonwebtoken::decode::<serde_json::Value>(assertion, &decoding_key, &validation)
                .map_err(|e| self.assertion_rejected(assertion, &e))?
                .claims;
        let claims = IdJagClaims::deserialize(&payload).map_err(|e| {
            OAuthError::invalid_grant(format!("assertion claims are not valid: {e}"))
        })?;

        // ID-JAG §4.4.1: `aud` is this issuer, as a string or a one-element
        // array. The decoder only checks that it is among the values.
        if claims.aud.values() != [self.issuer.as_str()] {
            return Err(OAuthError::invalid_grant(format!(
                "assertion aud {} must name only this authorization server, `{}`, as a string \
                 or a one-element array",
                echoed_claim(assertion, "aud"),
                self.issuer
            )));
        }
        let now = now_unix();
        if claims.iat > now + self.leeway_secs {
            return Err(OAuthError::invalid_grant("assertion iat is in the future"));
        }
        // With `exp` checked by the decoder, this also bounds how old `iat`
        // can be: `max_assertion_lifetime_secs` plus the leeway.
        let lifetime = claims.exp.saturating_sub(claims.iat);
        if lifetime > self.max_assertion_lifetime_secs {
            return Err(OAuthError::invalid_grant(format!(
                "assertion lifetime (exp - iat) of {lifetime} s exceeds the {} s this \
                 authorization server accepts",
                self.max_assertion_lifetime_secs
            )));
        }
        // ID-JAG §9.8.1.2: a key-bound grant is redeemed only with a proof
        // of its key, which the caller checks.
        let cnf_jkt = match claims.cnf {
            None => None,
            Some(_) if !self.dpop.enabled => {
                return Err(OAuthError::invalid_grant(
                    "proof of possession required: the assertion is bound to a key (cnf), and \
                     this authorization server does not support DPoP",
                ));
            }
            Some(ref cnf) => Some(
                dpop::confirmation_jkt(cnf)
                    .ok_or_else(|| {
                        OAuthError::invalid_grant(
                            "the assertion cnf uses an unsupported confirmation method: only a \
                             DPoP key thumbprint (jkt) is accepted",
                        )
                    })?
                    .to_owned(),
            ),
        };
        // ID-JAG §4.4.1: authorization_details MUST be processed per RFC
        // 9396. Ignored, it would mint a token wider than the IdP granted.
        let authorization_details =
            self.assertion_details(claims.authorization_details.as_ref())?;
        if claims.client_id != authenticated_client_id {
            return Err(OAuthError::invalid_grant(
                "assertion client_id does not match the authenticated client",
            ));
        }
        if !idp_admits_client(&idp.config, authenticated_client_id) {
            return Err(OAuthError::invalid_grant(
                "this enterprise IdP may not issue assertions for the authenticated client",
            ));
        }
        if let Some(ref required) = idp.config.required_tenant {
            match claims.tenant.as_ref().map(serde_json::Value::as_str) {
                Some(Some(tenant)) if tenant == required.as_str() => {}
                None => {
                    return Err(OAuthError::invalid_grant(
                        "assertion carries no tenant claim, which this enterprise IdP requires",
                    ));
                }
                Some(_) => {
                    return Err(OAuthError::invalid_grant(
                        "assertion tenant is not the tenant this enterprise IdP is trusted for",
                    ));
                }
            }
        }
        let identity = MappedIdentity::from_assertion(&idp.config.claim_mappings, &payload)?;
        let resource = self.granted_resource(claims.resource.as_ref(), requested_resource)?;
        Ok(ValidatedGrant {
            claims,
            identity,
            resource,
            cnf_jkt,
            authorization_details,
        })
    }

    /// `invalid_grant` for an `iss` no trusted IdP carries, naming the
    /// near miss an administrator most often makes.
    fn untrusted_issuer(&self, iss: &str) -> OAuthError {
        let near_miss = self
            .idps
            .iter()
            .any(|e| e.config.issuer.trim_end_matches('/') == iss.trim_end_matches('/'));
        if !near_miss {
            return OAuthError::invalid_grant("assertion issuer is not a trusted enterprise IdP");
        }
        tracing::warn!(
            assertion_issuer = %iss,
            "ID-JAG issuer differs from a trusted_idps issuer only by a trailing slash; \
             issuers compare exactly"
        );
        OAuthError::invalid_grant(
            "assertion issuer is not a trusted enterprise IdP: a trusted_idps issuer differs \
             from it only by a trailing `/`, and issuers compare exactly",
        )
    }

    /// `invalid_grant` naming what the decoder refused.
    fn assertion_rejected(
        &self,
        assertion: &str,
        error: &jsonwebtoken::errors::Error,
    ) -> OAuthError {
        let description = match error.kind() {
            ErrorKind::InvalidAudience => format!(
                "assertion aud {} does not name this authorization server: the enterprise IdP \
                 must set aud to exactly `{}`",
                echoed_claim(assertion, "aud"),
                self.issuer
            ),
            ErrorKind::ExpiredSignature => "assertion has expired".to_owned(),
            ErrorKind::ImmatureSignature => "assertion is not valid yet (nbf)".to_owned(),
            ErrorKind::InvalidSignature => "assertion signature is invalid".to_owned(),
            ErrorKind::MissingRequiredClaim(claim) => {
                format!("assertion carries no `{claim}` claim")
            }
            _ => format!("assertion validation failed: {error}"),
        };
        OAuthError::invalid_grant(description)
    }

    /// The resource the token is minted for (RFC 8707). With a `resource`
    /// request parameter, that resource, which the ID-JAG's `resource`
    /// claim must also name when it has one. Without it, the first of the
    /// claim's values this server answers to, or the default one when the
    /// claim is absent. A trailing `/` is ignored in every comparison.
    fn granted_resource(
        &self,
        granted: Option<&StringOrVec>,
        requested: Option<&str>,
    ) -> Result<String, OAuthError> {
        let ours = |wanted: &str| {
            let wanted = wanted.trim_end_matches('/');
            self.resources
                .iter()
                .find(|ours| ours.trim_end_matches('/') == wanted)
        };
        let invalid_target = |description: &str| OAuthError::new("invalid_target", description);
        if let Some(requested) = requested {
            let resource = ours(requested).ok_or_else(|| {
                invalid_target("the requested resource does not identify this MCP server")
            })?;
            let within_grant = granted.is_none_or(|granted| {
                granted
                    .values()
                    .into_iter()
                    .any(|value| ours(value) == Some(resource))
            });
            if !within_grant {
                return Err(invalid_target(
                    "the requested resource is not one the assertion's resource claim names",
                ));
            }
            return Ok(resource.clone());
        }
        let Some(granted) = granted else {
            return Ok(self.resources[0].clone());
        };
        granted
            .values()
            .into_iter()
            .find_map(ours)
            .cloned()
            .ok_or_else(|| invalid_target("assertion resource does not identify this MCP server"))
    }

    /// Claim the assertion `(iss, jti)` in the replay ledger. The entry
    /// lives until the decoder stops accepting the assertion, `exp` plus
    /// the leeway.
    async fn record_redemption(&self, iss: &str, jti: &str, exp: u64) -> Result<(), OAuthError> {
        if self.claim_once(&replay_key(iss, jti), exp).await? {
            Ok(())
        } else {
            Err(OAuthError::invalid_grant(
                "assertion has already been redeemed",
            ))
        }
    }

    /// Record `key` in the replay ledger until `exp` plus the leeway.
    /// `Ok(false)` when it is there already. A ledger that cannot be
    /// written refuses the request: an unrecorded assertion could be
    /// replayed.
    async fn claim_once(&self, key: &str, exp: u64) -> Result<bool, OAuthError> {
        let ttl = exp
            .saturating_add(self.leeway_secs)
            .saturating_sub(now_unix())
            .max(1);
        self.replay
            .kv
            .put_if_absent(
                key,
                Bytes::from_static(b"1"),
                Some(Duration::from_secs(ttl)),
            )
            .await
            .map_err(|error| {
                metrics::counter!("mcpg_ema_jti_store_errors_total").increment(1);
                tracing::error!(
                    error = %error,
                    "EMA replay ledger could not record a single-use assertion; refusing it"
                );
                OAuthError::temporarily_unavailable(
                    "replay protection is unavailable; retry shortly",
                )
            })
    }

    // ── trusted-IdP JWKS resolution ──────────────────────────────────

    async fn decoding_key_for(
        &self,
        idp: &IdpEntry,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, KeyError> {
        if let Some(ref keys) = idp.static_keys {
            return select_key(keys, kid, alg)?.ok_or(KeyError::NoMatch(
                "no configured key matches the assertion kid",
            ));
        }
        idp.keys
            .key_for(KeyOwner::Idp(&idp.config.issuer), kid, alg, || {
                self.fetch_jwks(&idp.config)
            })
            .await
    }

    async fn fetch_jwks(&self, idp: &TrustedIdpConfig) -> Result<JwkSet, FetchFailure> {
        let jwks_uri = match &idp.jwks_uri {
            Some(uri) => uri.clone(),
            None => self.discover_jwks_uri(idp).await?,
        };
        let body = self
            .fetch_idp_document(&jwks_uri, idp)
            .await?
            .found(&jwks_uri)?;
        serde_json::from_slice(&body).map_err(|e| {
            FetchFailure::Transient(anyhow::anyhow!("parsing JWKS from {jwks_uri}: {e}"))
        })
    }

    /// The JWKS URI of the IdP's discovery document.
    async fn discover_jwks_uri(&self, idp: &TrustedIdpConfig) -> Result<String, FetchFailure> {
        let (discovery_url, doc) = self.discover_idp_document(idp).await?;
        doc.get("jwks_uri")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                FetchFailure::Rejected(format!(
                    "the IdP discovery document at {discovery_url} carries no jwks_uri"
                ))
            })
    }

    /// The IdP's OIDC discovery document or, where it serves none, its
    /// RFC 8414 authorization server metadata (the one ID-JAG §7.1
    /// names), with the URL it was read from. The document's `issuer` must
    /// be the configured one exactly (RFC 8414 §3.3).
    async fn discover_idp_document(
        &self,
        idp: &TrustedIdpConfig,
    ) -> Result<(String, serde_json::Value), FetchFailure> {
        let oidc_url = format!(
            "{}/.well-known/openid-configuration",
            idp.issuer.trim_end_matches('/')
        );
        let (discovery_url, body) = match self.fetch_idp_document(&oidc_url, idp).await? {
            IdpDocument::Found(body) => (oidc_url, body),
            IdpDocument::Missing(oidc_status) => {
                let rfc8414_url = authorization_server_metadata_url(&idp.issuer);
                match self.fetch_idp_document(&rfc8414_url, idp).await? {
                    IdpDocument::Found(body) => (rfc8414_url, body),
                    IdpDocument::Missing(status) => {
                        return Err(FetchFailure::Rejected(format!(
                            "the IdP publishes no discovery metadata: {oidc_url} returned \
                             {oidc_status} and {rfc8414_url} returned {status}; check \
                             trusted_idps[].issuer, or set trusted_idps[].jwks_uri"
                        )));
                    }
                }
            }
        };
        let doc: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            FetchFailure::Transient(anyhow::anyhow!(
                "parsing IdP discovery metadata from {discovery_url}: {e}"
            ))
        })?;
        match doc.get("issuer").and_then(serde_json::Value::as_str) {
            Some(published) if published == idp.issuer => {}
            Some(published) => {
                return Err(FetchFailure::Rejected(format!(
                    "trusted_idps issuer `{}` does not match the issuer `{published}` the IdP \
                     publishes at {discovery_url}; set trusted_idps[].issuer to exactly \
                     `{published}`",
                    idp.issuer
                )));
            }
            None => {
                return Err(FetchFailure::Rejected(format!(
                    "the IdP discovery document at {discovery_url} names no issuer"
                )));
            }
        }
        Ok((discovery_url, doc))
    }

    /// GET a trusted-IdP document after the SSRF preflight.
    async fn fetch_idp_document(
        &self,
        url: &str,
        idp: &TrustedIdpConfig,
    ) -> Result<IdpDocument, FetchFailure> {
        enforce_discovery_url_safety(url, &idp.allowed_hosts, idp.allow_private_network)
            .map_err(|e| FetchFailure::Rejected(format!("the IdP URL is refused: {e}")))?;
        let timeout = idp.login.as_ref().map_or(IDP_FETCH_TIMEOUT, |login| {
            Duration::from_millis(login.timeout_ms)
        });
        self.get_capped(url, idp.allow_private_network, timeout)
            .await
    }

    /// GET `url` within `timeout` and read at most
    /// [`MAX_IDP_RESPONSE_BYTES`] of its body, refusing a response served
    /// from a private address unless `allow_private` (the preflight cannot
    /// see what a host name resolves to).
    async fn get_capped(
        &self,
        url: &str,
        allow_private: bool,
        timeout: Duration,
    ) -> Result<IdpDocument, FetchFailure> {
        let mut response = self
            .http
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| FetchFailure::Transient(anyhow::anyhow!("fetching {url}: {e}")))?;
        mcpg_plugin_protocol::security::check_response_remote_addr(
            response.remote_addr(),
            allow_private,
        )
        .map_err(|_| {
            FetchFailure::Rejected(format!(
                "{url} is served from a private address, which trusted_idps[].\
                 allow_private_network: false refuses"
            ))
        })?;
        let status = response.status();
        if matches!(
            status,
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
        ) {
            return Ok(IdpDocument::Missing(status));
        }
        if !status.is_success() {
            return Err(status_failure(url, status));
        }
        let too_large = || {
            FetchFailure::Transient(anyhow::anyhow!(
                "{url} returned more than {MAX_IDP_RESPONSE_BYTES} bytes"
            ))
        };
        if response
            .content_length()
            .is_some_and(|len| len > MAX_IDP_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| FetchFailure::Transient(anyhow::anyhow!("reading {url}: {e}")))?
        {
            if body.len() + chunk.len() > MAX_IDP_RESPONSE_BYTES {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(IdpDocument::Found(body))
    }
}

/// A trusted-IdP document, or the status that says it does not exist.
#[derive(Debug)]
enum IdpDocument {
    Found(Vec<u8>),
    /// `404` or `410`.
    Missing(reqwest::StatusCode),
}

impl IdpDocument {
    /// The body; a missing document is a configuration error.
    fn found(self, url: &str) -> Result<Vec<u8>, FetchFailure> {
        match self {
            IdpDocument::Found(body) => Ok(body),
            IdpDocument::Missing(status) => Err(status_failure(url, status)),
        }
    }
}

/// RFC 8414 §3.1: the metadata URL of `issuer`, the well-known suffix
/// inserted between its origin and its path.
fn authorization_server_metadata_url(issuer: &str) -> String {
    const SUFFIX: &str = "/.well-known/oauth-authorization-server";
    let path_start = issuer
        .find("://")
        .and_then(|scheme_end| {
            issuer[scheme_end + 3..]
                .find('/')
                .map(|at| scheme_end + 3 + at)
        })
        .unwrap_or(issuer.len());
    let (origin, path) = issuer.split_at(path_start);
    format!("{origin}{SUFFIX}{}", path.trim_end_matches('/'))
}

/// Whether `idp` admits `client_id`: its `allowed_clients` is empty or
/// lists the client. A dynamically registered client never satisfies a
/// non-empty list: the operator vets the clients the list names, and a
/// registration is self-asserted.
fn idp_admits_client(idp: &TrustedIdpConfig, client_id: &str) -> bool {
    idp.allowed_clients.is_empty()
        || (!client_id.starts_with(clients::DCR_CLIENT_ID_PREFIX)
            && idp.allowed_clients.iter().any(|c| c == client_id))
}

/// The principal namespace of a caller `idp` vouched for. A multi-tenant
/// IdP's `sub` is unique only within its `tenant` (ID-JAG §3), so an IdP
/// not pinned to one tenant namespaces by both.
fn principal_namespace(idp: &TrustedIdpConfig, tenant: Option<&str>) -> String {
    match tenant {
        Some(tenant) if idp.required_tenant.is_none() => format!("{}#{tenant}", idp.issuer),
        _ => idp.issuer.clone(),
    }
}

/// Where a user a trusted IdP vouched for belongs: the namespace and
/// `auth_provider` a verified caller reports. An ID-JAG redemption and an
/// interactive sign-in through the same IdP resolve alike, so one user is
/// one principal whichever way they arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Principal {
    issuer: String,
    auth_provider: String,
}

impl Principal {
    /// The principal of a user `idp` vouched for with the `tenant` claim
    /// of its token: `principal_issuer` and the `auth_provider` its OIDC
    /// provider reports, else [`principal_namespace`] and `ema`.
    fn of(idp: &TrustedIdpConfig, tenant: Option<&str>) -> Self {
        match idp.principal_issuer {
            Some(ref principal) => Self {
                issuer: principal.clone(),
                auth_provider: oidc_auth_provider(principal),
            },
            None => Self {
                issuer: principal_namespace(idp, tenant),
                auth_provider: AUTH_PROVIDER.to_owned(),
            },
        }
    }

    /// The principal key of `subject` here, as a verified caller's
    /// session, task and idempotency scopes are keyed.
    fn key(&self, subject: &str) -> String {
        format!(
            "verified::{}::{}::{subject}",
            self.auth_provider, self.issuer
        )
    }

    /// Whether a verified caller that reports `auth_provider` and `issuer`
    /// is in the namespace of the users `idp` vouches for, with any
    /// `tenant` claim.
    fn admits(idp: &TrustedIdpConfig, auth_provider: &str, issuer: &str) -> bool {
        match idp.principal_issuer {
            Some(ref principal) => {
                auth_provider == oidc_auth_provider(principal) && issuer == principal
            }
            None => {
                let of_a_tenant = idp.required_tenant.is_none()
                    && issuer
                        .strip_prefix(idp.issuer.as_str())
                        .and_then(|rest| rest.strip_prefix('#'))
                        .is_some_and(|tenant| !tenant.is_empty());
                auth_provider == AUTH_PROVIDER && (issuer == idp.issuer || of_a_tenant)
            }
        }
    }
}

impl AuthorizationServer {
    /// Whether a sign-in through the login IdP is stored under the
    /// principal namespace of a verified caller that reports
    /// `auth_provider` and `issuer`.
    pub(crate) fn login_stores_principal(&self, auth_provider: &str, issuer: &str) -> bool {
        self.idps
            .iter()
            .find(|entry| entry.login.is_some())
            .is_some_and(|entry| Principal::admits(&entry.config, auth_provider, issuer))
    }
}

/// A signing failure is this server's fault, never the client's.
fn minting_failed(error: jsonwebtoken::errors::Error) -> OAuthError {
    tracing::error!(error = %error, "EMA access token encoding failed");
    OAuthError::server_error("token minting failed")
}

/// Percent-decode a form-urlencoded token-endpoint credential
/// component (RFC 6749 §2.3.1 encodes Basic user/pass before base64).
fn percent_decode(input: &str) -> Option<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = bytes.get(i + 1)?;
                let lo = bytes.get(i + 2)?;
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                out.push(hex(*hi)? * 16 + hex(*lo)?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
impl AuthorizationServer {
    /// An access token shaped and signed as a redemption mints it for the
    /// first registered client, for tests outside this module that need a
    /// valid bearer without an IdP.
    pub(crate) fn mint_access_token_for_tests(
        &self,
        subject: &str,
        idp: &str,
        scope: Option<&str>,
    ) -> String {
        self.mint_bound_access_token_for_tests(subject, idp, scope, None)
    }

    /// [`Self::mint_access_token_for_tests`], bound to the DPoP key whose
    /// thumbprint is `jkt` when one is given.
    pub(crate) fn mint_bound_access_token_for_tests(
        &self,
        subject: &str,
        idp: &str,
        scope: Option<&str>,
        jkt: Option<&str>,
    ) -> String {
        let now = now_unix();
        let minted = MintedClaims {
            cnf: Confirmation::of(jkt.map(str::to_owned)),
            iss: self.issuer.clone(),
            sub: subject.to_owned(),
            aud: self.resources[0].clone(),
            client_id: self
                .clients
                .first()
                .map(|client| client.client_id.clone())
                .unwrap_or_default(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp: now + self.access_token_ttl.as_secs(),
            scope: scope.map(str::to_owned),
            idp: idp.to_owned(),
            ..MintedClaims::default()
        };
        self.signing_keys[0]
            .sign(&minted)
            .expect("test token encodes")
    }
}

#[cfg(test)]
#[path = "authorization_server_tests.rs"]
mod tests;
