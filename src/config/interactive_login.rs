//! Interactive sign-in at the embedded authorization server: the
//! `trusted_idps[].login` upstream client, the
//! `authorization_server.interactive` settings, the redirect URI rules
//! shared by registered clients, metadata documents and dynamic
//! registration, and the identity attributes the gateway reserves.
//!
//! An MCP client that cannot present an ID-JAG signs its user in through
//! the browser: the gateway's authorization endpoint sends the user to the
//! enterprise IdP of the one `trusted_idps` entry that has a `login`
//! block, validates the IdP's ID token with that entry's keys and claim
//! mappings, and issues the client an authorization code for the same
//! access token an ID-JAG redemption mints. The IdP sign-in is kept per
//! user, so a federation can present it upstream (`subject_token`).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::AppConfig;
use super::access::{AuthorizationServerConfig, TrustedIdpConfig};
use super::federation::AuthConfig;

// ---------------------------------------------------------------------------
// trusted_idps[].login
// ---------------------------------------------------------------------------

/// The gateway's own OIDC client at a trusted IdP
/// (`governance.access.authorization_server.trusted_idps[].login`). Its
/// presence turns interactive sign-in on through that IdP; at most one
/// entry may have it. The IdP's `issuer`, `allowed_hosts`,
/// `allow_private_network`, `allowed_algs` (the ID token signature),
/// `claim_mappings`, `allowed_clients`, `required_tenant` and
/// `principal_issuer` apply to sign-in exactly as to ID-JAGs, so a user
/// who signs in and the same user arriving with an ID-JAG are one
/// principal. The IdP keeps accepting ID-JAGs. Register
/// `{authorization_server.issuer}/oauth/callback` as the sign-in redirect
/// URI of this client at the IdP (`mcpg config check` prints it). For
/// Okta Cross App Access the issuer is the org authorization server
/// (`https://{org}.okta.com`) and this client is the OIDC app linked to
/// the AI agent. Requires a license with the `sso.interactive_login`
/// feature.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedIdpLoginConfig {
    /// The client identifier the IdP issued to the gateway (1–255
    /// characters).
    pub client_id: String,
    /// How the gateway authenticates at the IdP token endpoint:
    /// `client_secret_basic`, `client_secret_post` or `private_key_jwt`.
    /// Defaults to `private_key_jwt` when `private_key` is set and to
    /// `client_secret_basic` when `client_secret` is set. The gateway is
    /// always a confidential client here, so a stolen IdP refresh token
    /// is useless without this credential.
    #[serde(default)]
    pub client_auth: Option<LoginClientAuth>,
    /// Shared secret for the two secret methods, at least 16 bytes.
    /// Supply via `${secret.NAME}` or `${env.X}`. Set this or
    /// `private_key`, not both.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// `private_key_jwt`: the PEM private key the client assertion is
    /// signed with (PKCS#8, or PKCS#1 for RSA), parsed and trial-signed
    /// at load. Supply via `${secret.NAME}`, which reads the file
    /// verbatim, or `${env.X}`.
    #[serde(default)]
    pub private_key: Option<String>,
    /// `private_key_jwt`: the `kid` header of the client assertion (at most
    /// 128 characters). Unset, the assertion carries no `kid`.
    #[serde(default)]
    pub key_id: Option<String>,
    /// `private_key_jwt`: the assertion's JWS algorithm, `RS256`, `PS256`,
    /// `ES256` or `EdDSA`. Defaults to the one the key type implies (RSA:
    /// `RS256`, P-256: `ES256`, Ed25519: `EdDSA`); a value the key cannot
    /// sign with is refused at load.
    #[serde(default)]
    pub signing_alg: Option<LoginSigningAlg>,
    /// `private_key_jwt`: the assertion's `aud`: `token_endpoint` (the
    /// default: the URL of the endpoint the assertion is posted to, the
    /// token endpoint or, when a stored sign-in is revoked, the revocation
    /// endpoint, as Okta requires) or `issuer` (the IdP's issuer
    /// identifier).
    #[serde(default)]
    pub assertion_audience: Option<LoginAssertionAudience>,
    /// Scopes requested at the IdP. Must include `openid`; at most 20,
    /// each once. Without `offline_access` the IdP issues no refresh
    /// token, so the gateway issues none while `refresh_tokens.
    /// revalidate_with_idp` is on and `idp_refresh_token` federations
    /// cannot work.
    #[serde(default = "default_login_scopes")]
    pub scopes: Vec<String>,
    /// Longest time since the user last authenticated at the IdP that a
    /// sign-in accepts, in seconds (0–86400). Sent as `max_age`; the ID
    /// token must then carry `auth_time`. Unset, any session is accepted.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// Extra parameters for the IdP authorization request, such as
    /// `acr_values` or `domain_hint`. The parameters the gateway sets
    /// itself (`response_type`, `client_id`, `redirect_uri`, `scope`,
    /// `state`, `nonce`, `code_challenge`, `code_challenge_method`,
    /// `request`, `request_uri`, `response_mode`, `prompt`, `max_age`,
    /// `login_hint`) are refused.
    #[serde(default)]
    pub authorize_params: BTreeMap<String, String>,
    /// The IdP's name on the consent and connect pages (1–60 characters).
    /// Defaults to the IdP's host.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The IdP authorization endpoint. Unless this, `token_endpoint` and
    /// `revocation_endpoint` are all set, the endpoints are read from the
    /// IdP's OIDC discovery document (`{issuer}/.well-known/
    /// openid-configuration`, then the RFC 8414 form), whose `issuer` must
    /// equal the configured one exactly. Each endpoint must be `https://`
    /// on the entry's `allowed_hosts` (`http://` and private addresses
    /// only with `allow_private_network`).
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// The IdP token endpoint, where authorization codes are redeemed and
    /// the stored sign-in is refreshed. See `authorization_endpoint`.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// The IdP's RFC 7009 revocation endpoint, where a replaced or
    /// abandoned IdP refresh token is revoked. See
    /// `authorization_endpoint`.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Timeout of each request to the IdP, in milliseconds (500–10000).
    #[serde(default = "default_login_timeout_ms")]
    pub timeout_ms: u64,
}

impl std::fmt::Debug for TrustedIdpLoginConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedIdpLoginConfig")
            .field("client_id", &self.client_id)
            .field("client_auth", &self.client_auth)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[redacted]"),
            )
            .field("key_id", &self.key_id)
            .field("signing_alg", &self.signing_alg)
            .field("assertion_audience", &self.assertion_audience)
            .field("scopes", &self.scopes)
            .field("max_age_secs", &self.max_age_secs)
            .field("authorize_params", &self.authorize_params)
            .field("display_name", &self.display_name)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

/// How the gateway authenticates at the IdP token endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginClientAuth {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

impl LoginClientAuth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// JWS algorithm of the client assertion the gateway signs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub enum LoginSigningAlg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl LoginSigningAlg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }

    pub fn algorithm(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
            Self::Ps256 => jsonwebtoken::Algorithm::PS256,
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
            Self::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        }
    }

    /// The signing key `pem` holds for this algorithm.
    pub fn encoding_key(
        self,
        pem: &[u8],
    ) -> jsonwebtoken::errors::Result<jsonwebtoken::EncodingKey> {
        match self {
            Self::Rs256 | Self::Ps256 => jsonwebtoken::EncodingKey::from_rsa_pem(pem),
            Self::Es256 => jsonwebtoken::EncodingKey::from_ec_pem(pem),
            Self::EdDsa => jsonwebtoken::EncodingKey::from_ed_pem(pem),
        }
    }
}

/// The `aud` of the client assertion.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LoginAssertionAudience {
    /// The URL of the IdP endpoint the assertion is posted to: the token
    /// endpoint, or the revocation endpoint when revoking.
    #[default]
    TokenEndpoint,
    /// The IdP's issuer identifier.
    Issuer,
}

fn default_login_scopes() -> Vec<String> {
    ["openid", "profile", "email", "offline_access"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_login_timeout_ms() -> u64 {
    5_000
}

const MAX_LOGIN_CLIENT_ID_CHARS: usize = 255;
const MIN_LOGIN_CLIENT_SECRET_BYTES: usize = 16;
const MAX_KEY_ID_CHARS: usize = 128;
const MAX_LOGIN_SCOPES: usize = 20;
const MAX_LOGIN_MAX_AGE_SECS: u64 = 86_400;
const MAX_DISPLAY_NAME_CHARS: usize = 60;
const LOGIN_TIMEOUT_MS: std::ops::RangeInclusive<u64> = 500..=10_000;

/// Authorization request parameters the gateway sets itself.
pub const RESERVED_AUTHORIZE_PARAMS: [&str; 14] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "request",
    "request_uri",
    "response_mode",
    "prompt",
    "max_age",
    "login_hint",
];

/// A config value still carrying an unresolved `${…}` placeholder, whose
/// length or format cannot be judged yet.
fn is_placeholder(value: &str) -> bool {
    value.contains("${")
}

/// A PEM passed through an environment variable often carries literal
/// `\n` escapes in place of line breaks.
pub(crate) fn normalize_pem(pem: &str) -> Cow<'_, str> {
    let pem = pem.trim();
    if !pem.contains('\n') && pem.contains("\\n") {
        Cow::Owned(pem.replace("\\n", "\n"))
    } else {
        Cow::Borrowed(pem)
    }
}

/// Whether `alg` loads `pem` and signs with it.
fn signs_with(alg: LoginSigningAlg, pem: &[u8]) -> bool {
    alg.encoding_key(pem).is_ok_and(|key| {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(alg.algorithm()),
            &serde_json::json!({ "probe": true }),
            &key,
        )
        .is_ok()
    })
}

/// The algorithm a login private key signs with: `configured`, which the
/// key must be able to sign with, else the one its key type implies.
pub fn login_key_algorithm(
    pem: &str,
    configured: Option<LoginSigningAlg>,
) -> Result<LoginSigningAlg, String> {
    let pem = normalize_pem(pem);
    match configured {
        Some(alg) if signs_with(alg, pem.as_bytes()) => Ok(alg),
        Some(alg) => Err(format!(
            "cannot sign {}: expected {}",
            alg.as_str(),
            match alg {
                LoginSigningAlg::Rs256 | LoginSigningAlg::Ps256 =>
                    "an RSA key in PKCS#8 or PKCS#1 PEM",
                LoginSigningAlg::Es256 => "a P-256 key in PKCS#8 PEM",
                LoginSigningAlg::EdDsa => "an Ed25519 key in PKCS#8 PEM",
            }
        )),
        None => [
            LoginSigningAlg::Rs256,
            LoginSigningAlg::Es256,
            LoginSigningAlg::EdDsa,
        ]
        .into_iter()
        .find(|alg| signs_with(*alg, pem.as_bytes()))
        .ok_or_else(|| {
            "is not a usable PEM private key: expected an RSA (RS256), P-256 (ES256) or \
             Ed25519 (EdDSA) key in PKCS#8 PEM, or an RSA key in PKCS#1 PEM"
                .to_owned()
        }),
    }
}

/// An RFC 6749 §3.3 scope token: printable ASCII without space, `"` or
/// `\`.
fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

/// Text shown on a page: non-empty after trimming, within `max` characters,
/// and free of control characters.
fn check_display_text(field: &str, value: &str, max: usize) -> Result<()> {
    let chars = value.chars().count();
    if value.trim().is_empty() || chars > max || value.chars().any(char::is_control) {
        bail!("{field} must be 1 to {max} printable characters");
    }
    Ok(())
}

impl TrustedIdpLoginConfig {
    /// `client_auth`, or the method the configured credential implies.
    /// `None` when no credential is set.
    pub fn effective_client_auth(&self) -> Option<LoginClientAuth> {
        self.client_auth
            .or(match (&self.private_key, &self.client_secret) {
                (Some(_), _) => Some(LoginClientAuth::PrivateKeyJwt),
                (None, Some(_)) => Some(LoginClientAuth::ClientSecretBasic),
                (None, None) => None,
            })
    }

    /// `assertion_audience`, or `token_endpoint`.
    pub fn effective_assertion_audience(&self) -> LoginAssertionAudience {
        self.assertion_audience.unwrap_or_default()
    }

    /// The name shown on the consent and connect pages: `display_name`, or
    /// the IdP issuer's host.
    pub fn effective_display_name(&self, issuer: &str) -> String {
        self.display_name.clone().unwrap_or_else(|| {
            url::Url::parse(issuer)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| issuer.to_owned())
        })
    }

    /// Whether every endpoint is configured, so no discovery is needed.
    pub fn endpoints_configured(&self) -> bool {
        self.authorization_endpoint.is_some()
            && self.token_endpoint.is_some()
            && self.revocation_endpoint.is_some()
    }

    /// Every rule a login block must satisfy on its own, at `at`
    /// (`…trusted_idps[`{issuer}`].login`).
    pub(crate) fn validate(&self, at: &str, idp: &TrustedIdpConfig) -> Result<()> {
        let client_id = self.client_id.as_str();
        if client_id.trim().is_empty()
            || client_id.chars().count() > MAX_LOGIN_CLIENT_ID_CHARS
            || client_id.chars().any(char::is_control)
        {
            bail!("{at}.client_id must be 1 to {MAX_LOGIN_CLIENT_ID_CHARS} printable characters");
        }
        self.validate_credential(at)?;
        self.validate_scopes(at)?;
        if let Some(max_age) = self.max_age_secs
            && max_age > MAX_LOGIN_MAX_AGE_SECS
        {
            bail!("{at}.max_age_secs must be at most {MAX_LOGIN_MAX_AGE_SECS}");
        }
        for (name, value) in &self.authorize_params {
            if name.trim().is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                bail!(
                    "{at}.authorize_params names a parameter `{name}` that is empty or not a token"
                );
            }
            if RESERVED_AUTHORIZE_PARAMS.contains(&name.as_str()) {
                bail!(
                    "{at}.authorize_params sets `{name}`, which the gateway sets itself on every \
                     authorization request; remove it"
                );
            }
            if value.chars().any(char::is_control) {
                bail!("{at}.authorize_params[`{name}`] must not contain control characters");
            }
        }
        if let Some(ref name) = self.display_name {
            check_display_text(&format!("{at}.display_name"), name, MAX_DISPLAY_NAME_CHARS)?;
        }
        for (key, endpoint) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("revocation_endpoint", &self.revocation_endpoint),
        ] {
            let Some(endpoint) = endpoint else {
                continue;
            };
            if is_placeholder(endpoint) {
                continue;
            }
            if endpoint.contains('#') {
                bail!("{at}.{key} must not carry a fragment");
            }
            mcpg_plugin_identity_oidc_core::resolver::enforce_discovery_url_safety(
                endpoint,
                &idp.allowed_hosts,
                idp.allow_private_network,
            )
            .map_err(|e| anyhow!("{at}.{key}: {e}"))?;
        }
        if !LOGIN_TIMEOUT_MS.contains(&self.timeout_ms) {
            bail!(
                "{at}.timeout_ms must be between {} and {}",
                LOGIN_TIMEOUT_MS.start(),
                LOGIN_TIMEOUT_MS.end()
            );
        }
        Ok(())
    }

    /// Exactly one credential, the one its method takes, and the
    /// assertion settings only with `private_key_jwt`.
    fn validate_credential(&self, at: &str) -> Result<()> {
        if self.client_secret.is_some() && self.private_key.is_some() {
            bail!(
                "{at}: set client_secret or private_key, not both — the gateway authenticates \
                 at the IdP with exactly one credential"
            );
        }
        if self.client_secret.is_none() && self.private_key.is_none() {
            bail!(
                "{at} needs a credential: client_secret, or private_key for private_key_jwt. The \
                 gateway is a confidential client at the IdP, so a stored IdP refresh token is \
                 useless to anyone without it"
            );
        }
        self.validate_credential_for_method(at)
    }

    /// The one configured credential against the method it is used with.
    fn validate_credential_for_method(&self, at: &str) -> Result<()> {
        let method = self.client_auth.unwrap_or(if self.private_key.is_some() {
            LoginClientAuth::PrivateKeyJwt
        } else {
            LoginClientAuth::ClientSecretBasic
        });
        let assertion_settings = self.key_id.is_some()
            || self.signing_alg.is_some()
            || self.assertion_audience.is_some();
        match method {
            LoginClientAuth::ClientSecretBasic | LoginClientAuth::ClientSecretPost => {
                let Some(ref secret) = self.client_secret else {
                    bail!(
                        "{at}: client_auth {} takes client_secret, not private_key",
                        method.as_str()
                    );
                };
                if assertion_settings {
                    bail!(
                        "{at}: key_id, signing_alg and assertion_audience apply only to \
                         client_auth private_key_jwt"
                    );
                }
                if !is_placeholder(secret) && secret.len() < MIN_LOGIN_CLIENT_SECRET_BYTES {
                    bail!(
                        "{at}.client_secret must be at least {MIN_LOGIN_CLIENT_SECRET_BYTES} bytes"
                    );
                }
            }
            LoginClientAuth::PrivateKeyJwt => {
                let Some(ref pem) = self.private_key else {
                    bail!("{at}: client_auth private_key_jwt takes private_key, not client_secret");
                };
                if let Some(ref kid) = self.key_id
                    && (kid.trim().is_empty() || kid.chars().count() > MAX_KEY_ID_CHARS)
                {
                    bail!("{at}.key_id must be 1 to {MAX_KEY_ID_CHARS} characters when set");
                }
                if !is_placeholder(pem) {
                    login_key_algorithm(pem, self.signing_alg)
                        .map_err(|problem| anyhow!("{at}.private_key {problem}"))?;
                }
            }
        }
        Ok(())
    }

    fn validate_scopes(&self, at: &str) -> Result<()> {
        if !self.scopes.iter().any(|s| s == "openid") {
            bail!(
                "{at}.scopes must include `openid`: sign-in reads the user from the IdP's ID token"
            );
        }
        if self.scopes.len() > MAX_LOGIN_SCOPES {
            bail!("{at}.scopes lists more than {MAX_LOGIN_SCOPES} scopes");
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            if !is_scope_token(scope) {
                bail!("{at}.scopes lists `{scope}`, which is not an OAuth scope token");
            }
            if !seen.insert(scope.as_str()) {
                bail!("{at}.scopes lists `{scope}` more than once");
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// authorization_server.interactive
// ---------------------------------------------------------------------------

/// Settings of interactive sign-in
/// (`governance.access.authorization_server.interactive`). Every key has a
/// default, so the block is needed only to change one; it is refused
/// without a `trusted_idps[].login` entry. Requires a license with the
/// `sso.interactive_login` feature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InteractiveLoginConfig {
    /// Lifetime of the access tokens issued through sign-in, in seconds
    /// (60–3600, and at most `refresh_tokens.idle_ttl_secs`). ID-JAG
    /// redemptions keep `authorization_server.access_token_ttl_secs`. A
    /// revoked grant's access tokens are refused within
    /// `revocation_check_interval_secs`; a short lifetime also bounds how
    /// long a stolen one works.
    #[serde(default = "default_interactive_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// Lifetime of an authorization code, in seconds (10–600). A code is
    /// redeemed once; a second redemption revokes the grant it issued.
    #[serde(default = "default_authorization_code_ttl_secs")]
    pub authorization_code_ttl_secs: u64,
    /// Time a user has to approve consent and sign in at the IdP, in
    /// seconds (60–1800). Also the lifetime of the sign-in `state`.
    #[serde(default = "default_transaction_ttl_secs")]
    pub transaction_ttl_secs: u64,
    /// Requests allowed per minute from one client IP address across the
    /// browser endpoints (`/oauth/authorize`, `/oauth/consent`,
    /// `/oauth/callback`, `/oauth/connect`); the IP is found as for
    /// `authorization_server.rate_limit_per_min`. `0` disables the limit.
    #[serde(default = "default_browser_rate_limit_per_min")]
    pub rate_limit_per_min: u32,
    /// How often each replica reads the revoked grants other replicas
    /// wrote, in seconds (2–60): a revoked grant's access tokens are
    /// refused everywhere within this long.
    #[serde(default = "default_revocation_check_interval_secs")]
    pub revocation_check_interval_secs: u64,
    /// The consent page shown before the user is sent to the IdP.
    #[serde(default)]
    pub consent: ConsentConfig,
    /// Refresh tokens issued to MCP clients that signed in.
    #[serde(default)]
    pub refresh_tokens: RefreshTokensConfig,
    /// The stored IdP sign-in of each user.
    #[serde(default)]
    pub idp_sessions: IdpSessionsConfig,
    /// RFC 7591 dynamic client registration at `POST /oauth/register`.
    #[serde(default)]
    pub dynamic_client_registration: DynamicClientRegistrationConfig,
    /// Where grants, refresh tokens and stored IdP sign-ins live. Unset:
    /// the cluster coordinator's key-value store when
    /// `cluster.kind` is not `single_node`; on a single node, a file store
    /// in the default `store.dir`, so users stay signed in across restarts.
    /// Every record is sealed with the state key (`state_keys`).
    #[serde(default)]
    pub store: Option<InteractiveStoreConfig>,
    /// Keys that seal every stored record (XChaCha20-Poly1305), newest
    /// first: the first seals, every entry opens, so a rotation prepends
    /// the new key and keeps the old one for
    /// `refresh_tokens.absolute_ttl_secs`. Unset, the key derives from
    /// `cluster.state_encryption_key_env` when that is set. Otherwise a
    /// file store generates a key on first start and keeps it at
    /// `state.key` inside the store directory, readable by the gateway's
    /// user only (mode 0600) and never logged: back it up with the store,
    /// since the stored sign-ins cannot be opened without it. To move that
    /// key here, list it with kid `generated` and the file's contents as
    /// its `secret`. A memory store uses a key that lives as long as the
    /// process. The cluster store refuses to start without a key from here
    /// or the cluster.
    #[serde(default)]
    pub state_keys: Vec<StateKeyConfig>,
}

impl Default for InteractiveLoginConfig {
    fn default() -> Self {
        Self {
            access_token_ttl_secs: default_interactive_access_token_ttl_secs(),
            authorization_code_ttl_secs: default_authorization_code_ttl_secs(),
            transaction_ttl_secs: default_transaction_ttl_secs(),
            rate_limit_per_min: default_browser_rate_limit_per_min(),
            revocation_check_interval_secs: default_revocation_check_interval_secs(),
            consent: ConsentConfig::default(),
            refresh_tokens: RefreshTokensConfig::default(),
            idp_sessions: IdpSessionsConfig::default(),
            dynamic_client_registration: DynamicClientRegistrationConfig::default(),
            store: None,
            state_keys: Vec::new(),
        }
    }
}

/// The consent page (`interactive.consent`). It is shown to every
/// dynamically registered client, to every metadata-document client and
/// to a registered client whose redirect URIs are not all https (see
/// `clients[].consent`), before the user is sent to the IdP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentConfig {
    /// How long an approval is remembered in the approving browser, in
    /// days (0–365; `0` never remembers). The browser keeps it in a cookie
    /// sealed with the state key (`__Host-mcpg_consent`), so it cannot be
    /// read or forged, and a replaced state key forgets it. Only approvals
    /// for an `https://` redirect URI of a registered (`clients[]`) or
    /// metadata-document client are remembered, for that exact client,
    /// redirect URI and set of scopes; a loopback redirect URI or a
    /// dynamically registered client asks every time. `prompt=consent`
    /// always asks.
    #[serde(default = "default_consent_remember_days")]
    pub remember_days: u32,
    /// The heading of the consent and connect pages (1–80 characters).
    /// Defaults to the issuer's host.
    #[serde(default)]
    pub service_name: Option<String>,
    /// A description shown next to each scope, keyed by scope. Every key
    /// must be a scope this server grants (`allowed_scopes`, else
    /// `resource_metadata.scopes_supported`); each description is at most
    /// 200 characters.
    #[serde(default)]
    pub scope_descriptions: BTreeMap<String, String>,
}

impl Default for ConsentConfig {
    fn default() -> Self {
        Self {
            remember_days: default_consent_remember_days(),
            service_name: None,
            scope_descriptions: BTreeMap::new(),
        }
    }
}

/// Refresh tokens (`interactive.refresh_tokens`). Every refresh rotates
/// the token; presenting a spent one revokes the whole grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshTokensConfig {
    /// Issue refresh tokens to clients whose grant types include
    /// `refresh_token`.
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// A grant unused for this long expires, in seconds
    /// (3600–7776000; default 14 days).
    #[serde(default = "default_refresh_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
    /// A grant expires this long after sign-in however it is used, in
    /// seconds (`idle_ttl_secs`–7776000; default 30 days).
    #[serde(default = "default_refresh_absolute_ttl_secs")]
    pub absolute_ttl_secs: u64,
    /// How long a spent refresh token may be presented again and receive
    /// the same successor, in seconds (0–60). `0` treats any second use as
    /// theft and revokes the grant.
    #[serde(default)]
    pub reuse_grace_secs: u32,
    /// Grants one user may hold at once (1–1000); a new grant beyond it
    /// revokes the user's oldest.
    #[serde(default = "default_max_grants_per_principal")]
    pub max_grants_per_principal: u32,
    /// Check the user's IdP sign-in on refresh: the stored IdP refresh
    /// token is redeemed at the IdP at most every
    /// `revalidate_interval_secs`, and a user the IdP no longer accepts
    /// loses every grant. While on, a sign-in without an IdP refresh token
    /// gets no gateway refresh token.
    #[serde(default = "super::default_true")]
    pub revalidate_with_idp: bool,
    /// How often a refresh checks the IdP sign-in, in seconds
    /// (60–86400). Defaults to `access_token_ttl_secs`.
    #[serde(default)]
    pub revalidate_interval_secs: Option<u64>,
    /// How long refreshes keep working while the IdP cannot be reached, in
    /// seconds past the last successful check (0–86400).
    #[serde(default = "default_idp_unavailable_grace_secs")]
    pub idp_unavailable_grace_secs: u64,
}

impl Default for RefreshTokensConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_ttl_secs: default_refresh_idle_ttl_secs(),
            absolute_ttl_secs: default_refresh_absolute_ttl_secs(),
            reuse_grace_secs: 0,
            max_grants_per_principal: default_max_grants_per_principal(),
            revalidate_with_idp: true,
            revalidate_interval_secs: None,
            idp_unavailable_grace_secs: default_idp_unavailable_grace_secs(),
        }
    }
}

/// The stored IdP sign-in (`interactive.idp_sessions`): one per user,
/// shared by every MCP client of that user, used only toward the IdP token
/// endpoint that issued it (to check the sign-in, and as the RFC 8693
/// subject token of an `idp_refresh_token` or `idp_id_token` federation).
/// It is never given to an MCP client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdpSessionsConfig {
    /// Revoke at the IdP (RFC 7009) a replaced IdP refresh token of another
    /// IdP subject the claim mappings name the same user, when the IdP has
    /// a revocation endpoint. A replaced token of the same subject is never
    /// revoked: some IdPs (Keycloak, PingFederate) revoke per user and
    /// client, which would end the new sign-in too.
    #[serde(default = "super::default_true")]
    pub revoke_superseded: bool,
    /// Longest a stored sign-in is kept, in seconds (3600–31536000); each
    /// successful refresh at the IdP restarts it. Defaults to
    /// `refresh_tokens.absolute_ttl_secs`.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// Serve `/oauth/connect`, where a user who reaches the gateway with an
    /// ID-JAG signs in once so federations can use their IdP sign-in. It
    /// also lets a federated tool call of a caller with no stored sign-in
    /// answer with a link to it (MCP URL-mode elicitation), when the client
    /// declares `elicitation.url`: the link is for that caller only, and a
    /// sign-in as anyone else through it stores nothing.
    #[serde(default = "super::default_true")]
    pub connect_page: bool,
}

impl Default for IdpSessionsConfig {
    fn default() -> Self {
        Self {
            revoke_superseded: true,
            max_age_secs: None,
            connect_page: true,
        }
    }
}

/// Dynamic client registration (`interactive.dynamic_client_registration`,
/// RFC 7591) at `POST /oauth/register`, for MCP clients that have neither
/// a `clients[]` entry nor a Client ID Metadata Document. A registered
/// client is public (`token_endpoint_auth_method: none`, PKCE), may use
/// only `authorization_code` and, when it registers it, `refresh_token`,
/// never redeems ID-JAGs, always sees the consent page (an approval is
/// never remembered), and never satisfies a non-empty
/// `trusted_idps[].allowed_clients`. What a client registers is its own
/// claim (RFC 7591 §5): the gateway keeps its redirect URIs, grant types,
/// `client_name` (shown on the consent page as unverified),
/// `application_type` and, while `dpop.enabled`, `dpop_bound_access_tokens`
/// (RFC 9449 §5.2), and ignores every other member, logos and URLs
/// included. A registration is kept sealed like every sign-in record and
/// removed after `client_ttl_secs` without use; the client is then
/// unknown, and a grant of it is revoked when the client next presents
/// one of that grant's tokens at the token or revocation endpoint.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DynamicClientRegistrationConfig {
    /// Serve `POST /oauth/register` and advertise it as the
    /// `registration_endpoint`. Needs `initial_access_tokens` or
    /// `allow_open`.
    #[serde(default)]
    pub enabled: bool,
    /// Bearer tokens that authorize a registration (RFC 7591 §3,
    /// `Authorization: Bearer <token>`), each at least 32 bytes. Supply
    /// via `${secret.NAME}`; the server keeps only their SHA-256 digests.
    /// A request that presents a token not listed is refused, with
    /// `allow_open` too.
    #[serde(default)]
    pub initial_access_tokens: Vec<String>,
    /// Accept registrations without an initial access token, from anyone
    /// who can reach the gateway.
    #[serde(default)]
    pub allow_open: bool,
    /// Hosts an `https://` redirect URI of a registration may use: an
    /// exact host, or a parent domain of it. Empty = loopback redirect URIs
    /// only (`http://127.0.0.1`, `http://[::1]`, `http://localhost`, any
    /// port). An `https://` URI on another host is left out of the
    /// registration, whose answer lists the URIs kept (RFC 7591 §3.2.1); a
    /// registration with none left, or one that lists a malformed URI, a
    /// private-use scheme or `http://` off loopback, is refused
    /// (`invalid_redirect_uri`). A URI whose host is later removed from
    /// this list stops matching.
    #[serde(default)]
    pub allowed_redirect_hosts: Vec<String>,
    /// A registration unused for this long is removed, in seconds
    /// (86400–7776000). Only a successful use restarts it: a code issued
    /// to the client, a code or refresh token it redeemed, or a token of
    /// its own it revoked.
    #[serde(default = "default_dcr_client_ttl_secs")]
    pub client_ttl_secs: u64,
    /// Most registrations kept at once, across replicas (1–100000). A
    /// registration beyond it is answered `503` until older ones are
    /// removed.
    #[serde(default = "default_dcr_max_clients")]
    pub max_clients: u32,
    /// Registrations accepted from one client IP address per clock hour,
    /// counted across replicas; the IP is found as for
    /// `authorization_server.rate_limit_per_min`. A registration beyond it
    /// is answered `429` with `Retry-After`. `0` = unlimited.
    #[serde(default = "default_dcr_registrations_per_hour_per_ip")]
    pub registrations_per_hour_per_ip: u32,
}

/// Prefix of the `client_id` of a dynamically registered client, which a
/// `clients[]` entry may not use.
pub const DCR_CLIENT_ID_PREFIX: &str = "mcpgdcr_";

impl DynamicClientRegistrationConfig {
    /// Whether an `https://` redirect URI of a registration may use
    /// `host`, lower-case: `allowed_redirect_hosts` lists it or a parent
    /// domain of it.
    pub fn admits_redirect_host(&self, host: &str) -> bool {
        super::access::host_is_allowed(host, &self.allowed_redirect_hosts)
    }
}

impl Default for DynamicClientRegistrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_access_tokens: Vec::new(),
            allow_open: false,
            allowed_redirect_hosts: Vec::new(),
            client_ttl_secs: default_dcr_client_ttl_secs(),
            max_clients: default_dcr_max_clients(),
            registrations_per_hour_per_ip: default_dcr_registrations_per_hour_per_ip(),
        }
    }
}

impl std::fmt::Debug for DynamicClientRegistrationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicClientRegistrationConfig")
            .field("enabled", &self.enabled)
            .field(
                "initial_access_tokens",
                &format_args!("[{} redacted]", self.initial_access_tokens.len()),
            )
            .field("allow_open", &self.allow_open)
            .field("allowed_redirect_hosts", &self.allowed_redirect_hosts)
            .field("client_ttl_secs", &self.client_ttl_secs)
            .field("max_clients", &self.max_clients)
            .field(
                "registrations_per_hour_per_ip",
                &self.registrations_per_hour_per_ip,
            )
            .finish()
    }
}

/// Where interactive sign-in state lives (`interactive.store`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InteractiveStoreConfig {
    /// `cluster` (the cluster coordinator's key-value store; on
    /// `single_node` that is process memory), `memory` (process memory:
    /// every restart signs every user out) or `file` (a directory on local
    /// disk). A `memory` or `file` store holds one replica's state only,
    /// so it is refused when `cluster.kind` is not `single_node`.
    pub kind: InteractiveStoreKind,
    /// `file` only: the directory. Defaults to `$MCPG_STATE_DIR/oauth`;
    /// else `/var/lib/mcpg/oauth` where `/var/lib/mcpg` exists (the
    /// container image; the operator's runtime volume, which lasts as long
    /// as the pod; the Helm chart's volume with `persistence.enabled`); else
    /// `~/.mcpg/oauth`. A gateway that cannot open it refuses to start. It is
    /// created readable by the gateway's user only, and one gateway process
    /// at a time opens it (a second one refuses to start). Every write is
    /// flushed to disk before it counts, expired records are removed every
    /// minute, and at most 200000 records (256 MiB) are kept: sign-ins
    /// beyond that answer 503.
    #[serde(default)]
    pub dir: Option<String>,
}

/// Kind of `interactive.store`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveStoreKind {
    Cluster,
    Memory,
    File,
}

/// One sealing key of `interactive.state_keys`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateKeyConfig {
    /// Key identifier recorded with every record it seals
    /// (`[A-Za-z0-9._-]`, 1–64 characters), unique in the list.
    pub kid: String,
    /// The key material: 32 bytes, URL-safe base64 (`openssl rand -base64
    /// 32 | tr '+/' '-_'`). Supply via `${secret.NAME}` or `${env.X}`.
    // Named `secret` so log, audit and admin redaction mask it by field name.
    pub secret: String,
}

impl std::fmt::Debug for StateKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateKeyConfig")
            .field("kid", &self.kid)
            .field("secret", &"[redacted]")
            .finish()
    }
}

fn default_interactive_access_token_ttl_secs() -> u64 {
    900
}
fn default_authorization_code_ttl_secs() -> u64 {
    60
}
fn default_transaction_ttl_secs() -> u64 {
    600
}
fn default_browser_rate_limit_per_min() -> u32 {
    120
}
fn default_revocation_check_interval_secs() -> u64 {
    10
}
fn default_consent_remember_days() -> u32 {
    30
}
fn default_refresh_idle_ttl_secs() -> u64 {
    14 * 86_400
}
fn default_refresh_absolute_ttl_secs() -> u64 {
    30 * 86_400
}
fn default_max_grants_per_principal() -> u32 {
    50
}
fn default_idp_unavailable_grace_secs() -> u64 {
    3_600
}
fn default_dcr_client_ttl_secs() -> u64 {
    30 * 86_400
}
fn default_dcr_max_clients() -> u32 {
    1_000
}
fn default_dcr_registrations_per_hour_per_ip() -> u32 {
    20
}

const ACCESS_TOKEN_TTL_SECS: std::ops::RangeInclusive<u64> = 60..=3_600;
const AUTHORIZATION_CODE_TTL_SECS: std::ops::RangeInclusive<u64> = 10..=600;
const TRANSACTION_TTL_SECS: std::ops::RangeInclusive<u64> = 60..=1_800;
const REVOCATION_CHECK_INTERVAL_SECS: std::ops::RangeInclusive<u64> = 2..=60;
const MAX_CONSENT_REMEMBER_DAYS: u32 = 365;
const MAX_SERVICE_NAME_CHARS: usize = 80;
const MAX_SCOPE_DESCRIPTION_CHARS: usize = 200;
const MIN_REFRESH_IDLE_TTL_SECS: u64 = 3_600;
const MAX_REFRESH_TTL_SECS: u64 = 90 * 86_400;
const MAX_REUSE_GRACE_SECS: u32 = 60;
const MAX_GRANTS_PER_PRINCIPAL: std::ops::RangeInclusive<u32> = 1..=1_000;
const REVALIDATE_INTERVAL_SECS: std::ops::RangeInclusive<u64> = 60..=86_400;
const MAX_IDP_UNAVAILABLE_GRACE_SECS: u64 = 86_400;
const IDP_SESSION_MAX_AGE_SECS: std::ops::RangeInclusive<u64> = 3_600..=365 * 86_400;
const MIN_INITIAL_ACCESS_TOKEN_BYTES: usize = 32;
const DCR_CLIENT_TTL_SECS: std::ops::RangeInclusive<u64> = 86_400..=90 * 86_400;
const DCR_MAX_CLIENTS: std::ops::RangeInclusive<u32> = 1..=100_000;
const MAX_STATE_KID_CHARS: usize = 64;
const STATE_KEY_BYTES: usize = 32;

/// Name of the generated state key inside a file store's directory.
pub const GENERATED_STATE_KEY_FILE: &str = "state.key";

fn check_range<T: PartialOrd + std::fmt::Display>(
    field: &str,
    value: T,
    range: std::ops::RangeInclusive<T>,
) -> Result<()> {
    if !range.contains(&value) {
        bail!(
            "{field} must be between {} and {} (got {value})",
            range.start(),
            range.end()
        );
    }
    Ok(())
}

/// Where the state of interactive sign-in resolves to under a cluster
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedInteractiveStore {
    /// The cluster coordinator's key-value store.
    Cluster,
    /// Process memory.
    Memory,
    /// A directory on local disk.
    File { dir: PathBuf },
}

/// Where the key that seals the state comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateKeySource {
    /// `interactive.state_keys`, sealing with the named kid.
    Keyring { kid: String },
    /// Derived from the key named by `cluster.state_encryption_key_env`.
    ClusterKey { env: String },
    /// Generated on first start and kept in this file.
    GeneratedFile { path: PathBuf },
    /// Generated for the lifetime of the process.
    Process,
}

impl std::fmt::Display for StateKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyring { kid } => write!(f, "interactive.state_keys (sealing with `{kid}`)"),
            Self::ClusterKey { env } => {
                write!(f, "derived from cluster.state_encryption_key_env (`{env}`)")
            }
            Self::GeneratedFile { path } => write!(
                f,
                "generated on first start at {} (mode 0600; back it up with the store)",
                path.display()
            ),
            Self::Process => write!(f, "generated per process (lost on restart)"),
        }
    }
}

/// The data directory of the gateway's container image: the operator backs
/// it with the pod's writable runtime volume and the Helm chart with its
/// persistent volume, while the rest of the root filesystem is read-only.
pub const CONTAINER_DATA_DIR: &str = "/var/lib/mcpg";

/// `$MCPG_STATE_DIR/oauth`; else `/var/lib/mcpg/oauth` where
/// `/var/lib/mcpg` is a directory; else `~/.mcpg/oauth`.
pub fn default_file_store_dir() -> PathBuf {
    let state_dir = std::env::var_os("MCPG_STATE_DIR").filter(|dir| !dir.is_empty());
    file_store_dir_under(
        state_dir.map(PathBuf::from),
        std::path::Path::new(CONTAINER_DATA_DIR),
    )
}

/// The default file store directory given `$MCPG_STATE_DIR` and the
/// container data directory.
pub(crate) fn file_store_dir_under(
    state_dir: Option<PathBuf>,
    container_data_dir: &std::path::Path,
) -> PathBuf {
    let base = match state_dir {
        Some(dir) => dir,
        None if container_data_dir.is_dir() => container_data_dir.to_path_buf(),
        None => mcpg_cli_core::paths::default_state_dir(),
    };
    base.join("oauth")
}

impl InteractiveLoginConfig {
    /// `refresh_tokens.revalidate_interval_secs`, else
    /// `access_token_ttl_secs`.
    pub fn revalidate_interval_secs(&self) -> u64 {
        self.refresh_tokens
            .revalidate_interval_secs
            .unwrap_or(self.access_token_ttl_secs)
    }

    /// `idp_sessions.max_age_secs`, else
    /// `refresh_tokens.absolute_ttl_secs`.
    pub fn idp_session_max_age_secs(&self) -> u64 {
        self.idp_sessions
            .max_age_secs
            .unwrap_or(self.refresh_tokens.absolute_ttl_secs)
    }

    /// The store this configuration uses under `cluster`.
    pub fn resolved_store(&self, cluster: &super::ClusterConfig) -> ResolvedInteractiveStore {
        self.resolved_store_under(cluster, default_file_store_dir)
    }

    /// [`Self::resolved_store`], with `default_dir` answering where a file
    /// store without `dir` lives.
    pub(crate) fn resolved_store_under(
        &self,
        cluster: &super::ClusterConfig,
        default_dir: impl FnOnce() -> PathBuf,
    ) -> ResolvedInteractiveStore {
        match self.store {
            Some(InteractiveStoreConfig {
                kind: InteractiveStoreKind::Cluster,
                ..
            }) => ResolvedInteractiveStore::Cluster,
            Some(InteractiveStoreConfig {
                kind: InteractiveStoreKind::Memory,
                ..
            }) => ResolvedInteractiveStore::Memory,
            Some(InteractiveStoreConfig {
                kind: InteractiveStoreKind::File,
                ref dir,
            }) => ResolvedInteractiveStore::File {
                dir: dir
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(default_dir),
            },
            None if cluster.is_single_node() => {
                ResolvedInteractiveStore::File { dir: default_dir() }
            }
            None => ResolvedInteractiveStore::Cluster,
        }
    }

    /// Where the sealing key comes from under `cluster`, or `None` when a
    /// cluster store on a clustered coordinator has no key (refused by
    /// validation).
    pub fn state_key_source(&self, cluster: &super::ClusterConfig) -> Option<StateKeySource> {
        if let Some(first) = self.state_keys.first() {
            return Some(StateKeySource::Keyring {
                kid: first.kid.clone(),
            });
        }
        if let Some(ref env) = cluster.state_encryption_key_env {
            return Some(StateKeySource::ClusterKey { env: env.clone() });
        }
        match self.resolved_store(cluster) {
            ResolvedInteractiveStore::File { dir } => Some(StateKeySource::GeneratedFile {
                path: dir.join(GENERATED_STATE_KEY_FILE),
            }),
            ResolvedInteractiveStore::Memory => Some(StateKeySource::Process),
            ResolvedInteractiveStore::Cluster if cluster.is_single_node() => {
                Some(StateKeySource::Process)
            }
            ResolvedInteractiveStore::Cluster => None,
        }
    }

    /// Every rule of the block on its own, at `prefix`
    /// (`governance.access.authorization_server.interactive`).
    pub(crate) fn validate(&self, prefix: &str) -> Result<()> {
        check_range(
            &format!("{prefix}.access_token_ttl_secs"),
            self.access_token_ttl_secs,
            ACCESS_TOKEN_TTL_SECS,
        )?;
        check_range(
            &format!("{prefix}.authorization_code_ttl_secs"),
            self.authorization_code_ttl_secs,
            AUTHORIZATION_CODE_TTL_SECS,
        )?;
        check_range(
            &format!("{prefix}.transaction_ttl_secs"),
            self.transaction_ttl_secs,
            TRANSACTION_TTL_SECS,
        )?;
        check_range(
            &format!("{prefix}.revocation_check_interval_secs"),
            self.revocation_check_interval_secs,
            REVOCATION_CHECK_INTERVAL_SECS,
        )?;
        self.validate_consent(prefix)?;
        self.validate_refresh_tokens(prefix)?;
        if let Some(max_age) = self.idp_sessions.max_age_secs {
            check_range(
                &format!("{prefix}.idp_sessions.max_age_secs"),
                max_age,
                IDP_SESSION_MAX_AGE_SECS,
            )?;
        }
        self.validate_dynamic_client_registration(prefix)?;
        if let Some(ref store) = self.store {
            match (store.kind, &store.dir) {
                (InteractiveStoreKind::File, Some(dir)) if dir.trim().is_empty() => {
                    bail!("{prefix}.store.dir must not be empty when set");
                }
                (InteractiveStoreKind::Cluster | InteractiveStoreKind::Memory, Some(_)) => {
                    bail!("{prefix}.store.dir applies only to kind `file`");
                }
                _ => {}
            }
        }
        self.validate_state_keys(prefix)
    }

    fn validate_consent(&self, prefix: &str) -> Result<()> {
        let consent = &self.consent;
        if consent.remember_days > MAX_CONSENT_REMEMBER_DAYS {
            bail!("{prefix}.consent.remember_days must be at most {MAX_CONSENT_REMEMBER_DAYS}");
        }
        if let Some(ref name) = consent.service_name {
            check_display_text(
                &format!("{prefix}.consent.service_name"),
                name,
                MAX_SERVICE_NAME_CHARS,
            )?;
        }
        for (scope, description) in &consent.scope_descriptions {
            check_display_text(
                &format!("{prefix}.consent.scope_descriptions[`{scope}`]"),
                description,
                MAX_SCOPE_DESCRIPTION_CHARS,
            )?;
        }
        Ok(())
    }

    fn validate_refresh_tokens(&self, prefix: &str) -> Result<()> {
        let refresh = &self.refresh_tokens;
        let at = format!("{prefix}.refresh_tokens");
        check_range(
            &format!("{at}.idle_ttl_secs"),
            refresh.idle_ttl_secs,
            MIN_REFRESH_IDLE_TTL_SECS..=MAX_REFRESH_TTL_SECS,
        )?;
        check_range(
            &format!("{at}.absolute_ttl_secs"),
            refresh.absolute_ttl_secs,
            refresh.idle_ttl_secs..=MAX_REFRESH_TTL_SECS,
        )
        .map_err(|e| anyhow!("{e}: a grant cannot outlive its absolute lifetime by idling"))?;
        if self.access_token_ttl_secs > refresh.idle_ttl_secs {
            bail!(
                "{prefix}.access_token_ttl_secs ({}) must be at most {at}.idle_ttl_secs ({})",
                self.access_token_ttl_secs,
                refresh.idle_ttl_secs
            );
        }
        if refresh.reuse_grace_secs > MAX_REUSE_GRACE_SECS {
            bail!("{at}.reuse_grace_secs must be at most {MAX_REUSE_GRACE_SECS}");
        }
        check_range(
            &format!("{at}.max_grants_per_principal"),
            refresh.max_grants_per_principal,
            MAX_GRANTS_PER_PRINCIPAL,
        )?;
        if let Some(interval) = refresh.revalidate_interval_secs {
            check_range(
                &format!("{at}.revalidate_interval_secs"),
                interval,
                REVALIDATE_INTERVAL_SECS,
            )?;
        }
        if refresh.idp_unavailable_grace_secs > MAX_IDP_UNAVAILABLE_GRACE_SECS {
            bail!(
                "{at}.idp_unavailable_grace_secs must be at most {MAX_IDP_UNAVAILABLE_GRACE_SECS}"
            );
        }
        Ok(())
    }

    fn validate_dynamic_client_registration(&self, prefix: &str) -> Result<()> {
        let dcr = &self.dynamic_client_registration;
        let at = format!("{prefix}.dynamic_client_registration");
        if dcr.enabled && dcr.initial_access_tokens.is_empty() && !dcr.allow_open {
            bail!(
                "{at}.enabled needs initial_access_tokens, or allow_open: true to accept \
                 registrations from anyone"
            );
        }
        let mut seen = BTreeSet::new();
        for token in &dcr.initial_access_tokens {
            if !is_placeholder(token) && token.len() < MIN_INITIAL_ACCESS_TOKEN_BYTES {
                bail!(
                    "{at}.initial_access_tokens: every token must be at least \
                     {MIN_INITIAL_ACCESS_TOKEN_BYTES} bytes"
                );
            }
            if !seen.insert(token.as_str()) {
                bail!("{at}.initial_access_tokens lists one token more than once");
            }
        }
        for host in &dcr.allowed_redirect_hosts {
            if host.trim().is_empty()
                || host.contains(['/', '@', ':', '*'])
                || host.chars().any(char::is_whitespace)
            {
                bail!(
                    "{at}.allowed_redirect_hosts entry `{host}` must be a bare host name, such as \
                     `www.cursor.com`"
                );
            }
        }
        check_range(
            &format!("{at}.client_ttl_secs"),
            dcr.client_ttl_secs,
            DCR_CLIENT_TTL_SECS,
        )?;
        check_range(
            &format!("{at}.max_clients"),
            dcr.max_clients,
            DCR_MAX_CLIENTS,
        )
    }

    fn validate_state_keys(&self, prefix: &str) -> Result<()> {
        use base64::Engine as _;
        let mut kids = BTreeSet::new();
        for (index, entry) in self.state_keys.iter().enumerate() {
            let at = format!("{prefix}.state_keys[{index}]");
            let kid = entry.kid.as_str();
            if kid.is_empty()
                || kid.chars().count() > MAX_STATE_KID_CHARS
                || !kid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                bail!("{at}.kid must be 1 to {MAX_STATE_KID_CHARS} characters of [A-Za-z0-9._-]");
            }
            if !kids.insert(kid) {
                bail!("{prefix}.state_keys lists kid `{kid}` more than once");
            }
            if is_placeholder(&entry.secret) {
                continue;
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(entry.secret.trim().trim_end_matches('='))
                .ok();
            if decoded.is_none_or(|bytes| bytes.len() != STATE_KEY_BYTES) {
                bail!(
                    "{at}.secret must be {STATE_KEY_BYTES} bytes in URL-safe base64 (generate one: \
                     `openssl rand -base64 32 | tr '+/' '-_'`)"
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// clients[] and client_id_metadata_documents additions
// ---------------------------------------------------------------------------

/// A grant type a registered client may use.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
pub enum ClientGrantType {
    /// Redeem an ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:jwt-bearer")]
    JwtBearer,
    /// Interactive sign-in with PKCE.
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    /// Refresh an interactive grant.
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

impl ClientGrantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// When a registered client's user sees the consent page.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClientConsent {
    /// Skip it when every redirect URI is `https://`, else ask.
    #[default]
    Auto,
    /// Always ask.
    Always,
    /// Never ask; refused for a client with a loopback redirect URI, which
    /// any local program can receive.
    Skip,
}

/// How the `https://` redirect URIs of a Client ID Metadata Document are
/// admitted.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RedirectUriPolicy {
    /// On exactly the host of the document's `client_id` URL.
    #[default]
    SameHost,
    /// On any host `allowed_hosts` admits.
    AllowedHosts,
}

/// Most redirect URIs one registered client may list.
pub const MAX_CLIENT_REDIRECT_URIS: usize = 10;
const MAX_CLIENT_NAME_CHARS: usize = 80;

/// The consistency of one registered client's interactive keys, at `at`.
pub(crate) fn validate_client_interactive_keys(
    at: &str,
    client: &super::AuthorizationServerClientConfig,
    has_login: bool,
) -> Result<()> {
    if client.redirect_uris.len() > MAX_CLIENT_REDIRECT_URIS {
        bail!("{at}.redirect_uris lists more than {MAX_CLIENT_REDIRECT_URIS} URIs");
    }
    let mut seen = BTreeSet::new();
    let mut has_loopback = false;
    for uri in &client.redirect_uris {
        let kind = redirect_uri_kind(uri)
            .map_err(|problem| anyhow!("{at}.redirect_uris entry `{uri}` {problem}"))?;
        has_loopback |= matches!(kind, RedirectUriKind::Loopback(_));
        if !seen.insert(uri.as_str()) {
            bail!("{at}.redirect_uris lists `{uri}` more than once");
        }
    }
    if let Some(ref grants) = client.grant_types {
        let mut unique = BTreeSet::new();
        for grant in grants {
            if !unique.insert(*grant) {
                bail!("{at}.grant_types lists `{}` more than once", grant.as_str());
            }
        }
        if grants.is_empty() {
            bail!("{at}.grant_types must not be empty when set");
        }
    }
    let grants = client.effective_grant_types();
    let code = grants.contains(&ClientGrantType::AuthorizationCode);
    if code && client.redirect_uris.is_empty() {
        bail!(
            "{at}: grant type authorization_code needs redirect_uris, where the authorization \
             response is sent"
        );
    }
    if code && !has_login {
        bail!(
            "{at}: grant type authorization_code needs interactive sign-in: add a login block to \
             one governance.access.authorization_server.trusted_idps entry"
        );
    }
    if grants.contains(&ClientGrantType::RefreshToken) && !code {
        bail!(
            "{at}: grant type refresh_token refreshes interactive grants and needs authorization_code"
        );
    }
    if !client.redirect_uris.is_empty() && !code {
        bail!(
            "{at}.redirect_uris is set, but grant_types lacks authorization_code, which uses them"
        );
    }
    if let Some(ref name) = client.client_name {
        check_display_text(&format!("{at}.client_name"), name, MAX_CLIENT_NAME_CHARS)?;
    }
    if client.consent == ClientConsent::Skip && has_loopback {
        bail!(
            "{at}.consent: skip is refused for a client with a loopback redirect URI: any program \
             on the user's computer can receive it, so the user must confirm each sign-in"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redirect URI syntax
// ---------------------------------------------------------------------------

/// Longest redirect URI accepted, in bytes.
pub const MAX_REDIRECT_URI_BYTES: usize = 2048;

/// Where a registered redirect URI sends the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriKind {
    /// `https://` on any host, matched byte for byte.
    Https,
    /// `http://` on a loopback host, matched with any port (RFC 8252 §7.3).
    Loopback(LoopbackHost),
}

/// The loopback host of a loopback redirect URI, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackHost {
    /// `127.0.0.1`
    Ipv4,
    /// `[::1]`
    Ipv6,
    /// `localhost`, which RFC 8252 §8.3 advises against: it can resolve
    /// elsewhere.
    Localhost,
}

/// The registration syntax of a redirect URI: absolute, ASCII, at most
/// [`MAX_REDIRECT_URI_BYTES`], without a fragment, userinfo, wildcard,
/// backslash, whitespace or control character; `https://` on any host, or
/// `http://` on exactly `127.0.0.1`, `[::1]` or `localhost` as written. A
/// loopback URI's path and query must be the ones a browser navigates to,
/// since they are compared as written. Any other scheme, including a
/// private-use one, is refused. The reason reads after the URI.
pub fn redirect_uri_kind(uri: &str) -> Result<RedirectUriKind, String> {
    if uri.len() > MAX_REDIRECT_URI_BYTES {
        return Err(format!("is longer than {MAX_REDIRECT_URI_BYTES} bytes"));
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("must not contain whitespace or control characters".to_owned());
    }
    if !uri.is_ascii() {
        return Err(
            "must be ASCII: percent-encode other characters, and write an internationalized \
             host in its xn-- form"
                .to_owned(),
        );
    }
    if uri.contains('#') {
        return Err("must not carry a fragment (RFC 6749 §3.1.2)".to_owned());
    }
    // A browser reads `\` as `/`, so the text would name another host or
    // path than the one a browser goes to.
    if uri.contains('\\') {
        return Err("must not contain a backslash".to_owned());
    }
    let (https, rest) = match (uri.strip_prefix("https://"), uri.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        (None, None) => {
            return Err(
                "must be an https:// URL, or http:// on a loopback host (127.0.0.1, [::1] or \
                 localhost); other schemes, private-use ones included, are refused"
                    .to_owned(),
            );
        }
    };
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    if authority.contains('@') {
        return Err("must not carry userinfo".to_owned());
    }
    if authority.contains('*') {
        return Err("must not contain a wildcard".to_owned());
    }
    let host = match authority.strip_prefix('[') {
        Some(inner) => match inner.split_once(']') {
            Some((address, _)) => &authority[..address.len() + 2],
            None => return Err("has an unterminated IPv6 host".to_owned()),
        },
        None => authority.split(':').next().unwrap_or(authority),
    };
    if host.is_empty() {
        return Err("has no host".to_owned());
    }
    let parsed = url::Url::parse(uri).map_err(|e| format!("is not an absolute URL: {e}"))?;
    if https {
        return Ok(RedirectUriKind::Https);
    }
    let kind = match host {
        "127.0.0.1" => RedirectUriKind::Loopback(LoopbackHost::Ipv4),
        "[::1]" => RedirectUriKind::Loopback(LoopbackHost::Ipv6),
        "localhost" => RedirectUriKind::Loopback(LoopbackHost::Localhost),
        other => {
            return Err(format!(
                "uses http:// on host `{other}`: http is accepted only on the loopback hosts \
                 127.0.0.1, [::1] and localhost, written exactly so"
            ));
        }
    };
    let (path, query) = loopback_path_and_query(uri);
    if parsed.path() != path || parsed.query() != query {
        return Err(
            "must be in canonical form: a browser rewrites its path or query (dot segments, \
             encoded dots or characters it escapes), and a loopback URI is matched as written"
                .to_owned(),
        );
    }
    Ok(kind)
}

/// The path of an `http://` loopback redirect URI as written, an empty
/// one read as `/`, and its query as written (`Some("")` after a bare
/// `?`). The port is ignored, as RFC 8252 §7.3 has a native client pick
/// it at run time.
pub fn loopback_path_and_query(uri: &str) -> (&str, Option<&str>) {
    let rest = uri.strip_prefix("http://").unwrap_or(uri);
    let after_authority = &rest[rest.find(['/', '?']).unwrap_or(rest.len())..];
    let (path, query) = match after_authority.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (after_authority, None),
    };
    (if path.is_empty() { "/" } else { path }, query)
}

// ---------------------------------------------------------------------------
// Reserved identity attributes
// ---------------------------------------------------------------------------

/// Prefix of the attributes the gateway sets on the caller it hands a
/// credential issuer.
pub const SUBJECT_TOKEN_ATTRIBUTE_PREFIX: &str = "subject_token";

/// Why `attribute` may not be a mapping target of a
/// `governance.access.oidc_oauth` provider, if it may not: the markers that
/// say which way into the gateway a caller took (`token_issuer`,
/// `grant_type`, `grant_id`, and `dpop_jkt`, which says the caller proved
/// a DPoP key), the authorization details a token of this gateway is
/// limited to (`authorization_details`, `authorization_details_types`,
/// which a policy trusts), and the attributes a credential issuer reads as
/// the subject token. Identity values an SSO token genuinely carries
/// (`email`, `tenant`, `auth_time`, …) stay mappable.
pub fn oidc_reserved_attribute(attribute: &str) -> Option<&'static str> {
    if crate::runtime::authorization_server::GATEWAY_SET_ATTRIBUTES.contains(&attribute) {
        Some("an attribute the gateway sets itself on the callers it issues tokens to")
    } else if attribute.starts_with(SUBJECT_TOKEN_ATTRIBUTE_PREFIX) {
        Some("an attribute the gateway sets itself on the caller it hands a credential issuer")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Whole-config rules
// ---------------------------------------------------------------------------

/// The credential issuers a federation may hand the caller's stored IdP
/// sign-in: the ones that exchange it only at the token endpoint that
/// issued it, by the client it was issued to.
pub const IDP_VAULT_ISSUERS: [&str; 2] = [
    "dev.mcpg.credential.oauth-id-jag",
    "dev.mcpg.credential.oauth-token-exchange",
];

/// The plugin `auth.credential` names (`cred://<plugin>/<target>`), and
/// the manifest id it runs: the `ref` of its `plugins[]` entry, else the
/// plugin id itself.
fn credential_plugin<'a>(
    config: &'a AppConfig,
    auth: &'a AuthConfig,
) -> Option<(&'a str, &'a str)> {
    let plugin = auth
        .credential
        .as_deref()?
        .strip_prefix("cred://")?
        .split_once('/')?
        .0;
    let manifest = config
        .plugins
        .iter()
        .find(|entry| entry.id == plugin)
        .and_then(|entry| entry.r#ref.as_deref())
        .unwrap_or(plugin);
    Some((plugin, manifest))
}

/// Every upstream auth block that reads the caller's stored IdP sign-in, as
/// `(config path, auth)`.
pub fn idp_subject_token_users(config: &AppConfig) -> Vec<(String, &AuthConfig)> {
    let mut users = Vec::new();
    for fed in &config.mcp.federations {
        if fed.upstream.auth.subject_token.is_idp_session() {
            users.push((
                format!("mcp.federations[{}].upstream.auth", fed.name),
                &fed.upstream.auth,
            ));
        }
    }
    for registry in &config.mcp.registries {
        if registry.defaults.auth.subject_token.is_idp_session() {
            users.push((
                format!("mcp.registries[{}].defaults.auth", registry.name),
                &registry.defaults.auth,
            ));
        }
        for (server, over) in &registry.servers {
            if let Some(ref auth) = over.auth
                && auth.subject_token.is_idp_session()
            {
                users.push((
                    format!("mcp.registries[{}].servers[{server}].auth", registry.name),
                    auth,
                ));
            }
        }
    }
    users
}

/// The rules of interactive sign-in that read more than the authorization
/// server block: the store against the cluster, the state key, and the
/// federations that use the stored IdP sign-in.
pub(crate) fn validate_interactive_login(config: &AppConfig) -> Result<()> {
    let authz = config.governance.access.authorization_server.as_ref();
    let has_login = authz.is_some_and(|a| a.login_idp().is_some());
    let users = idp_subject_token_users(config);
    for (path, auth) in &users {
        let issuer = credential_plugin(config, auth);
        if !issuer.is_some_and(|(_, manifest)| IDP_VAULT_ISSUERS.contains(&manifest)) {
            bail!(
                "{path}.subject_token `{}` presents the caller's stored enterprise sign-in, \
                 which only {} may exchange: they send it solely to the token endpoint that \
                 issued it. `{path}.credential` names {}",
                auth.subject_token.as_str(),
                IDP_VAULT_ISSUERS.join(" or "),
                match issuer {
                    Some((plugin, manifest)) if plugin == manifest => format!("`{plugin}`"),
                    Some((plugin, manifest)) => format!("`{plugin}` (`{manifest}`)"),
                    None => "no credential issuer".to_owned(),
                }
            );
        }
    }
    if let Some((path, auth)) = users.into_iter().next()
        && !has_login
    {
        bail!(
            "{path}.subject_token `{}` presents the caller's stored enterprise sign-in, which \
             needs interactive sign-in: add a login block to one \
             governance.access.authorization_server.trusted_idps entry",
            auth.subject_token.as_str()
        );
    }
    let Some(authz) = authz.filter(|_| has_login) else {
        return Ok(());
    };
    let prefix = "governance.access.authorization_server.interactive";
    let settings = authz.interactive_settings();
    let cluster = &config.cluster;
    if !cluster.is_single_node()
        && let Some(ref store) = settings.store
        && store.kind != InteractiveStoreKind::Cluster
    {
        bail!(
            "{prefix}.store.kind `{}` keeps sign-in state on one replica, but cluster.kind `{}` \
             runs replicas that must share it: a sign-in started on one would fail on another, \
             and codes and refresh tokens would be single-use per replica only. Use kind: \
             cluster, or remove store",
            match store.kind {
                InteractiveStoreKind::Memory => "memory",
                _ => "file",
            },
            cluster.kind
        );
    }
    if settings.state_key_source(cluster).is_none() {
        bail!(
            "{prefix}: the cluster store needs a key to seal sign-in state (stored IdP refresh \
             tokens included), and cluster.allow_plaintext_state does not waive it. Set \
             cluster.state_encryption_key_env, or {prefix}.state_keys"
        );
    }
    Ok(())
}

impl AuthorizationServerConfig {
    /// The trusted IdP with a `login` block, and that block.
    pub fn login_idp(&self) -> Option<(&TrustedIdpConfig, &TrustedIdpLoginConfig)> {
        self.trusted_idps
            .iter()
            .find_map(|idp| idp.login.as_ref().map(|login| (idp, login)))
    }

    /// `interactive`, or its defaults.
    pub fn interactive_settings(&self) -> Cow<'_, InteractiveLoginConfig> {
        match self.interactive {
            Some(ref settings) => Cow::Borrowed(settings),
            None => Cow::Owned(InteractiveLoginConfig::default()),
        }
    }

    /// The fixed redirect URI registered at the login IdP.
    pub fn login_callback_url(&self) -> String {
        format!("{}/oauth/callback", self.issuer.trim_end_matches('/'))
    }
}

/// What `mcpg config check` reports about interactive sign-in: one line
/// each, empty without it.
pub fn interactive_login_summary(config: &AppConfig) -> Vec<String> {
    let Some(ref authz) = config.governance.access.authorization_server else {
        return Vec::new();
    };
    let Some((idp, login)) = authz.login_idp() else {
        return Vec::new();
    };
    let settings = authz.interactive_settings();
    let mut lines = vec![
        format!(
            "interactive sign-in through {} (client `{}`); needs a license with the \
             `sso.interactive_login` feature",
            idp.issuer, login.client_id
        ),
        format!(
            "register this sign-in redirect URI at the IdP: {}",
            authz.login_callback_url()
        ),
    ];
    if login.endpoints_configured() {
        lines.push(format!(
            "IdP endpoints: authorization {}, token {}, revocation {}",
            login.authorization_endpoint.as_deref().unwrap_or_default(),
            login.token_endpoint.as_deref().unwrap_or_default(),
            login.revocation_endpoint.as_deref().unwrap_or_default()
        ));
    } else {
        lines.push(format!(
            "IdP endpoints not configured are discovered at boot from {}/.well-known/openid-configuration",
            idp.issuer.trim_end_matches('/')
        ));
    }
    lines.push(format!("IdP scopes: {}", login.scopes.join(" ")));
    let registration = &settings.dynamic_client_registration;
    if registration.enabled {
        let who = match (
            registration.allow_open,
            registration.initial_access_tokens.len(),
        ) {
            (true, 0) => "open to anyone".to_owned(),
            (true, tokens) => {
                format!("open to anyone, or with one of {tokens} initial access tokens")
            }
            (false, tokens) => format!("with one of {tokens} initial access tokens"),
        };
        let redirects = if registration.allowed_redirect_hosts.is_empty() {
            "loopback redirect URIs only".to_owned()
        } else {
            format!(
                "loopback redirect URIs, and https:// on {}",
                registration.allowed_redirect_hosts.join(", ")
            )
        };
        lines.push(format!(
            "dynamic client registration at {}/oauth/register: {who}; {redirects}",
            authz.issuer.trim_end_matches('/')
        ));
    }
    let store = match settings.resolved_store(&config.cluster) {
        ResolvedInteractiveStore::Cluster if config.cluster.is_single_node() => {
            "process memory (the single-node coordinator)".to_owned()
        }
        ResolvedInteractiveStore::Cluster => {
            format!("cluster coordinator ({})", config.cluster.kind)
        }
        ResolvedInteractiveStore::Memory => "process memory".to_owned(),
        ResolvedInteractiveStore::File { dir } => format!("files under {}", dir.display()),
    };
    lines.push(format!("sign-in state: {store}"));
    if let Some(source) = settings.state_key_source(&config.cluster) {
        lines.push(format!("state key: {source}"));
    }
    lines
}

#[cfg(test)]
#[path = "interactive_login_tests.rs"]
mod tests;
