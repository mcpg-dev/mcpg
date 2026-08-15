//! Embedded Enterprise-Managed Authorization server
//! (`governance.access.authorization_server`).
//!
//! The gateway acts as the OAuth *Resource Authorization Server* of the
//! MCP `io.modelcontextprotocol/enterprise-managed-authorization`
//! extension: it redeems Identity Assertion JWT Authorization Grants
//! (ID-JAGs, `draft-ietf-oauth-identity-assertion-authz-grant`) issued
//! by trusted enterprise IdPs and mints audience-restricted access
//! tokens that the gateway itself accepts on `/mcp`. Exactly one grant
//! is supported (`urn:ietf:params:oauth:grant-type:jwt-bearer` carrying
//! an ID-JAG); there is no authorization endpoint and no refresh
//! tokens, so this surface can never mint long-lived or user-consented
//! credentials.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use tokio::sync::RwLock;

use crate::config::{AuthorizationServerConfig, TrustedIdpConfig};
use mcpg_plugin_identity_oidc_core::resolver::{enforce_discovery_url_safety, map_key_algorithm};

/// RFC URN of the only grant type the token endpoint accepts.
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Grant profile advertised in authorization-server metadata.
pub const GRANT_PROFILE_ID_JAG: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
/// Required `typ` header of an ID-JAG assertion.
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
/// `typ` header stamped on minted access tokens (RFC 9068).
const ACCESS_TOKEN_TYP: &str = "at+jwt";
/// JWKS/discovery cache freshness window.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// Minimum spacing between JWKS refetches (unknown-kid storms).
const JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Upper bound on remembered `jti` values. Entries expire with their
/// assertion (≤ minutes). Reaching the cap means replay detection can no
/// longer be guaranteed, so redemptions are refused until it drains.
const JTI_CACHE_CAP: usize = 100_000;

/// OAuth token-endpoint error (RFC 6749 §5.2). `status` is the HTTP
/// status the error is served with (400, or 401 for `invalid_client`).
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

    fn invalid_client(description: impl Into<String>, basic_attempted: bool) -> Self {
        Self {
            status: 401,
            error: "invalid_client",
            description: description.into(),
            basic_challenge: basic_attempted,
        }
    }

    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        })
    }
}

/// Successful token response (RFC 6749 §5.1; no refresh token by
/// design).
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Parsed `POST /oauth/token` form body.
#[derive(Debug, Default, Deserialize)]
pub struct TokenRequestForm {
    pub grant_type: Option<String>,
    pub assertion: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Identity extracted from a gateway-minted EMA access token.
#[derive(Debug, Clone)]
pub struct EmaVerifiedIdentity {
    pub subject_id: String,
    pub issuer: String,
    pub scopes: Vec<String>,
    pub attributes: BTreeMap<String, String>,
}

/// Outcome of probing an inbound bearer against the embedded issuer.
pub enum EmaBearerOutcome {
    /// Bearer's `iss` is not this server — fall through to the next
    /// verifier in the cascade.
    NotOurs,
    /// Bearer claims this issuer and verified.
    Verified(EmaVerifiedIdentity),
    /// Bearer claims this issuer and failed verification — fail closed.
    Invalid(String),
}

#[derive(Debug, Deserialize)]
struct IdJagClaims {
    iss: String,
    sub: String,
    #[allow(dead_code)]
    aud: serde_json::Value,
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
}

/// RFC 8707 `resource` may be a single value or an array.
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

#[derive(Debug, Serialize, Deserialize)]
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
}

struct CachedJwks {
    keys: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
}

struct IdpEntry {
    config: TrustedIdpConfig,
    jwks: RwLock<Option<CachedJwks>>,
    /// Last fetch attempt, successful or not — rate-limits refetches.
    last_attempt: Mutex<Option<Instant>>,
}

/// The embedded EMA authorization server. One instance per gateway
/// runtime; rebuilt on config reload.
pub struct AuthorizationServer {
    issuer: String,
    resource: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_ttl: Duration,
    leeway_secs: u64,
    enforce_single_use: bool,
    allowed_scopes: Option<Vec<String>>,
    clients: Vec<crate::config::AuthorizationServerClientConfig>,
    advertised_scopes: Vec<String>,
    idps: Vec<IdpEntry>,
    /// `(idp issuer, jti)` → unix expiry. Purged opportunistically.
    seen_jtis: Mutex<HashMap<(String, String), u64>>,
    http: reqwest::Client,
}

impl std::fmt::Debug for AuthorizationServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationServer")
            .field("issuer", &self.issuer)
            .field("resource", &self.resource)
            .field("idps", &self.idps.len())
            .field("clients", &self.clients.len())
            .finish_non_exhaustive()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Constant-time string equality (length differences still leak, which
/// is inherent to comparing variable-length secrets).
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Decode a JWT payload segment WITHOUT verification — used only to
/// route by `iss` before real validation, never to establish trust.
fn unverified_claim_iss(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_owned)
}

impl AuthorizationServer {
    /// `effective_resource` is the RFC 8707 identifier minted tokens are
    /// audience-restricted to: `authorization_server.resource`, else the
    /// PRM `resource`, else the issuer.
    pub fn from_config(
        config: &AuthorizationServerConfig,
        prm_resource: Option<&str>,
    ) -> Result<Self> {
        if config.signing_secret.len() < 32 {
            anyhow::bail!(
                "governance.access.authorization_server.signing_secret must be at least 32 bytes \
                 for HS256 (is the `${{env.…}}` reference resolved?)"
            );
        }
        let issuer = config.issuer.trim_end_matches('/').to_owned();
        let resource = config
            .resource
            .as_deref()
            .or(prm_resource)
            .unwrap_or(issuer.as_str())
            .to_owned();
        let advertised_scopes = config.allowed_scopes.clone().unwrap_or_default();
        Ok(Self {
            encoding_key: EncodingKey::from_secret(config.signing_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.signing_secret.as_bytes()),
            issuer,
            resource,
            access_token_ttl: Duration::from_secs(config.access_token_ttl_secs),
            leeway_secs: config.clock_skew_secs,
            enforce_single_use: config.enforce_single_use,
            allowed_scopes: config.allowed_scopes.clone(),
            clients: config.clients.clone(),
            advertised_scopes,
            idps: config
                .trusted_idps
                .iter()
                .map(|idp| IdpEntry {
                    config: idp.clone(),
                    jwks: RwLock::new(None),
                    last_attempt: Mutex::new(None),
                })
                .collect(),
            seen_jtis: Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                // `enforce_discovery_url_safety` vets the URL we are about to
                // request, so following a redirect would reach an address the
                // guard never saw — an open redirect on the IdP's own domain
                // is enough to leave the allowlist.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("building EMA authorization server HTTP client")?,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// RFC 8414 authorization-server metadata document.
    pub fn metadata(&self) -> serde_json::Value {
        let mut auth_methods = vec![];
        if self.clients.iter().any(|c| c.client_secret.is_some()) {
            auth_methods.push("client_secret_basic");
            auth_methods.push("client_secret_post");
        }
        if self.clients.iter().any(|c| c.client_secret.is_none()) {
            auth_methods.push("none");
        }
        serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{}/oauth/token", self.issuer),
            "grant_types_supported": [GRANT_TYPE_JWT_BEARER],
            "authorization_grant_profiles_supported": [GRANT_PROFILE_ID_JAG],
            "token_endpoint_auth_methods_supported": auth_methods,
            "scopes_supported": self.advertised_scopes,
            // No authorization endpoint exists — no response types.
            "response_types_supported": [],
        })
    }

    /// Handle a `POST /oauth/token` request. `basic_auth` is the raw
    /// `Authorization` header value, if any.
    pub async fn handle_token_request(
        &self,
        form: TokenRequestForm,
        basic_auth: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        match form.grant_type.as_deref() {
            Some(GRANT_TYPE_JWT_BEARER) => {}
            Some(other) => {
                return Err(OAuthError::new(
                    "unsupported_grant_type",
                    format!(
                        "unsupported grant_type `{other}`; only jwt-bearer ID-JAG redemption is supported"
                    ),
                ));
            }
            None => {
                return Err(OAuthError::new("invalid_request", "grant_type is required"));
            }
        }
        let client_id = self.authenticate_client(&form, basic_auth)?;
        let assertion = form
            .assertion
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| OAuthError::new("invalid_request", "assertion is required"))?;

        let claims = self.validate_id_jag(assertion, &client_id).await?;

        // Resource AS narrowing: granted = ID-JAG scope ∩ allowed (when
        // configured). The response reports the granted set (spec MUST).
        let granted_scope = claims.scope.as_deref().map(|s| {
            let idp_scopes: Vec<&str> = s.split_whitespace().collect();
            match &self.allowed_scopes {
                Some(allowed) => idp_scopes
                    .into_iter()
                    .filter(|sc| allowed.iter().any(|a| a == sc))
                    .collect::<Vec<_>>()
                    .join(" "),
                None => idp_scopes.join(" "),
            }
        });

        let now = now_unix();
        let expires_in = self.access_token_ttl.as_secs();
        let minted = MintedClaims {
            iss: self.issuer.clone(),
            sub: claims.sub,
            aud: self.resource.clone(),
            client_id,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp: now + expires_in,
            scope: granted_scope.clone().filter(|s| !s.is_empty()),
            email: claims.email,
            idp: claims.iss,
        };
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(ACCESS_TOKEN_TYP.to_owned());
        let access_token =
            jsonwebtoken::encode(&header, &minted, &self.encoding_key).map_err(|e| {
                tracing::error!(error = %e, "EMA access token encoding failed");
                OAuthError::new("invalid_request", "token minting failed")
            })?;
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            scope: minted.scope,
        })
    }

    /// Probe an inbound bearer: if its (unverified) `iss` names this
    /// server, it MUST verify here — no fall-through once the issuer
    /// claims to be ours.
    pub fn verify_bearer(&self, bearer: &str) -> EmaBearerOutcome {
        match unverified_claim_iss(bearer) {
            Some(iss) if iss == self.issuer => {}
            _ => return EmaBearerOutcome::NotOurs,
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = self.leeway_secs;
        validation.set_audience(&[self.resource.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let data =
            match jsonwebtoken::decode::<MintedClaims>(bearer, &self.decoding_key, &validation) {
                Ok(d) => d,
                Err(e) => return EmaBearerOutcome::Invalid(e.to_string()),
            };
        // We only ever mint `at+jwt`; anything else claiming our issuer
        // is not a token we produced.
        let typ_ok = data
            .header
            .typ
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case(ACCESS_TOKEN_TYP));
        if !typ_ok {
            return EmaBearerOutcome::Invalid("unexpected token typ".to_owned());
        }
        let claims = data.claims;
        let scopes = claims
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let mut attributes = BTreeMap::new();
        attributes.insert("client_id".to_owned(), claims.client_id);
        attributes.insert("idp".to_owned(), claims.idp.clone());
        attributes.insert("token_issuer".to_owned(), claims.iss);
        if let Some(email) = claims.email {
            attributes.insert("email".to_owned(), email);
        }
        EmaBearerOutcome::Verified(EmaVerifiedIdentity {
            subject_id: claims.sub,
            // A principal is namespaced by the IdP that vouched for it, not by
            // this gateway. `sub` is an opaque IdP-chosen string, so two
            // trusted IdPs can issue the same one — deliberately, or simply
            // because both use email as the subject. Reporting the gateway's
            // own issuer here would collapse those two people into one
            // principal key, and with it one session, task list and
            // idempotency scope. This matches what an OIDC-verified identity
            // reports; the minting issuer stays available as an attribute.
            issuer: claims.idp,
            scopes,
            attributes,
        })
    }

    // ── client authentication ────────────────────────────────────────

    /// RFC 6749 §2.3.1: Basic credentials are form-urlencoded before
    /// base64. Returns the authenticated client_id.
    fn authenticate_client(
        &self,
        form: &TokenRequestForm,
        authorization: Option<&str>,
    ) -> Result<String, OAuthError> {
        let basic = authorization.and_then(|v| {
            v.strip_prefix("Basic ")
                .or_else(|| v.strip_prefix("basic "))
        });
        let basic_attempted = basic.is_some();
        let (client_id, client_secret) = if let Some(b64) = basic {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| OAuthError::invalid_client("malformed Basic credentials", true))?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| OAuthError::invalid_client("malformed Basic credentials", true))?;
            let (id, secret) = decoded
                .split_once(':')
                .ok_or_else(|| OAuthError::invalid_client("malformed Basic credentials", true))?;
            let id = percent_decode(id)
                .ok_or_else(|| OAuthError::invalid_client("malformed Basic credentials", true))?;
            let secret = percent_decode(secret)
                .ok_or_else(|| OAuthError::invalid_client("malformed Basic credentials", true))?;
            (id, Some(secret))
        } else {
            let id = form
                .client_id
                .clone()
                .filter(|c| !c.trim().is_empty())
                .ok_or_else(|| {
                    OAuthError::invalid_client("client authentication required", false)
                })?;
            (id, form.client_secret.clone().filter(|s| !s.is_empty()))
        };

        let Some(registered) = self.clients.iter().find(|c| c.client_id == client_id) else {
            return Err(OAuthError::invalid_client(
                "unknown client",
                basic_attempted,
            ));
        };
        match (&registered.client_secret, client_secret) {
            (Some(expected), Some(presented)) if ct_eq(expected, &presented) => Ok(client_id),
            (Some(_), _) => Err(OAuthError::invalid_client(
                "client authentication failed",
                basic_attempted,
            )),
            // Public client: a stray presented secret is refused rather
            // than silently ignored.
            (None, Some(_)) => Err(OAuthError::invalid_client(
                "client is registered without a secret",
                basic_attempted,
            )),
            (None, None) => Ok(client_id),
        }
    }

    // ── ID-JAG validation ────────────────────────────────────────────

    async fn validate_id_jag(
        &self,
        assertion: &str,
        authenticated_client_id: &str,
    ) -> Result<IdJagClaims, OAuthError> {
        let header = jsonwebtoken::decode_header(assertion)
            .map_err(|_| OAuthError::new("invalid_grant", "assertion is not a well-formed JWT"))?;
        let typ_ok = header.typ.as_deref().is_some_and(|t| {
            t.eq_ignore_ascii_case(ID_JAG_TYP)
                || t.eq_ignore_ascii_case(&format!("application/{ID_JAG_TYP}"))
        });
        if !typ_ok {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion `typ` must be oauth-id-jag+jwt",
            ));
        }
        // Asymmetric algorithms only: an HMAC alg with a public JWKS
        // would let anyone forge assertions.
        let alg = header.alg;
        if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion must use an asymmetric signing algorithm",
            ));
        }
        let iss = unverified_claim_iss(assertion)
            .ok_or_else(|| OAuthError::new("invalid_grant", "assertion carries no iss claim"))?;
        let Some(idp) = self
            .idps
            .iter()
            .find(|e| e.config.issuer.trim_end_matches('/') == iss.trim_end_matches('/'))
        else {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion issuer is not a trusted enterprise IdP",
            ));
        };

        let decoding_key = self
            .decoding_key_for(idp, header.kid.as_deref(), alg)
            .await
            .map_err(|e| {
                tracing::warn!(issuer = %iss, error = %e, "ID-JAG key resolution failed");
                OAuthError::new(
                    "invalid_grant",
                    "assertion signature key could not be resolved",
                )
            })?;

        let mut validation = Validation::new(alg);
        validation.leeway = self.leeway_secs;
        validation.validate_nbf = true;
        validation.set_audience(&[self.issuer.as_str()]);
        validation.set_issuer(&[idp.config.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let data = jsonwebtoken::decode::<IdJagClaims>(assertion, &decoding_key, &validation)
            .map_err(|e| {
                OAuthError::new("invalid_grant", format!("assertion validation failed: {e}"))
            })?;
        let claims = data.claims;

        let now = now_unix();
        if claims.iat > now + self.leeway_secs {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion iat is in the future",
            ));
        }
        if claims.client_id != authenticated_client_id {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion client_id does not match the authenticated client",
            ));
        }
        if let Some(ref resource) = claims.resource {
            let ours = self.resource.trim_end_matches('/');
            let matched = resource
                .values()
                .iter()
                .any(|r| r.trim_end_matches('/') == ours);
            if !matched {
                return Err(OAuthError::new(
                    "invalid_target",
                    "assertion resource does not identify this MCP server",
                ));
            }
        }
        if self.enforce_single_use {
            self.check_and_record_jti(&claims.iss, &claims.jti, claims.exp)?;
        }
        Ok(claims)
    }

    fn check_and_record_jti(&self, iss: &str, jti: &str, exp: u64) -> Result<(), OAuthError> {
        let now = now_unix();
        let mut seen = self.seen_jtis.lock().unwrap_or_else(|p| p.into_inner());
        if seen.len() >= 1024 {
            seen.retain(|_, expiry| *expiry > now);
        }
        let key = (iss.to_owned(), jti.to_owned());
        if seen.contains_key(&key) {
            return Err(OAuthError::new(
                "invalid_grant",
                "assertion has already been redeemed",
            ));
        }
        if seen.len() >= JTI_CACHE_CAP {
            // Single-use is a security control: a jti that cannot be recorded
            // cannot be detected on replay. Refuse the redemption rather than
            // admit it unrecorded, which would disable replay detection for
            // every client at once (the cache is shared across IdPs).
            tracing::warn!("EMA jti replay cache at capacity; refusing redemption");
            let mut err = OAuthError::new(
                "temporarily_unavailable",
                "replay-protection cache is saturated; retry shortly",
            );
            err.status = 503;
            return Err(err);
        }
        seen.insert(key, exp.saturating_add(self.leeway_secs));
        Ok(())
    }

    // ── trusted-IdP JWKS resolution ──────────────────────────────────

    async fn decoding_key_for(
        &self,
        idp: &IdpEntry,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey> {
        if let Some(key) = self.cached_key(idp, kid, alg).await? {
            return Ok(key);
        }
        // Miss or unknown kid → (rate-limited) refetch, then retry once.
        self.refresh_jwks(idp).await?;
        match self.cached_key(idp, kid, alg).await? {
            Some(key) => Ok(key),
            None => anyhow::bail!("no JWKS key matches kid {kid:?}"),
        }
    }

    async fn cached_key(
        &self,
        idp: &IdpEntry,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<Option<DecodingKey>> {
        let guard = idp.jwks.read().await;
        let Some(cached) = guard.as_ref() else {
            return Ok(None);
        };
        if cached.fetched_at.elapsed() > JWKS_TTL {
            return Ok(None);
        }
        let jwk = match kid {
            Some(kid) => cached
                .keys
                .keys
                .iter()
                .find(|k| k.common.key_id.as_deref() == Some(kid)),
            // No kid: unambiguous only when a single key is published or
            // exactly one matches the assertion's algorithm.
            None => {
                let matching: Vec<_> = cached
                    .keys
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
                    cached
                        .keys
                        .keys
                        .first()
                        .filter(|_| cached.keys.keys.len() == 1)
                }
            }
        };
        match jwk {
            Some(jwk) => {
                // A JWK declaring its algorithm must agree with the
                // assertion header — mismatches are downgrade attempts.
                if let Some(key_alg) = jwk.common.key_algorithm.and_then(map_key_algorithm)
                    && key_alg != alg
                {
                    anyhow::bail!("assertion alg does not match the published key algorithm");
                }
                Ok(Some(DecodingKey::from_jwk(jwk)?))
            }
            None => Ok(None),
        }
    }

    async fn refresh_jwks(&self, idp: &IdpEntry) -> Result<()> {
        {
            let mut last = idp.last_attempt.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(at) = *last
                && at.elapsed() < JWKS_REFRESH_MIN_INTERVAL
            {
                anyhow::bail!("JWKS refresh rate-limited");
            }
            *last = Some(Instant::now());
        }
        let jwks_uri = match &idp.config.jwks_uri {
            Some(uri) => uri.clone(),
            None => self.discover_jwks_uri(&idp.config).await?,
        };
        enforce_discovery_url_safety(
            &jwks_uri,
            &idp.config.allowed_hosts,
            idp.config.allow_private_network,
        )?;
        let response = self
            .http
            .get(&jwks_uri)
            .send()
            .await
            .with_context(|| format!("fetching JWKS from {jwks_uri}"))?;
        if !response.status().is_success() {
            anyhow::bail!("JWKS fetch from {jwks_uri} returned {}", response.status());
        }
        let keys: jsonwebtoken::jwk::JwkSet = response
            .json()
            .await
            .with_context(|| format!("parsing JWKS from {jwks_uri}"))?;
        *idp.jwks.write().await = Some(CachedJwks {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    async fn discover_jwks_uri(&self, idp: &TrustedIdpConfig) -> Result<String> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            idp.issuer.trim_end_matches('/')
        );
        enforce_discovery_url_safety(
            &discovery_url,
            &idp.allowed_hosts,
            idp.allow_private_network,
        )?;
        let response = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .with_context(|| format!("fetching OIDC discovery from {discovery_url}"))?;
        if !response.status().is_success() {
            anyhow::bail!(
                "OIDC discovery from {discovery_url} returned {}",
                response.status()
            );
        }
        let doc: serde_json::Value = response.json().await.context("parsing OIDC discovery")?;
        doc.get("jwks_uri")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("OIDC discovery document carries no jwks_uri"))
    }
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
#[path = "authorization_server_tests.rs"]
mod tests;
