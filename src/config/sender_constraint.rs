//! Constrained access tokens at the embedded authorization server:
//! sender-constrained (`governance.access.authorization_server.dpop`, RFC
//! 9449) and limited to fine-grained authorization details
//! (`governance.access.authorization_server.authorization_details`, RFC
//! 9396).
//!
//! With DPoP on, a client proves at the token endpoint that it holds a
//! private key, and the access token it receives is bound to that key
//! (`cnf.jkt`, `token_type: DPoP`): a copy of the token is useless without
//! the key. An ID-JAG the enterprise IdP bound to a key (`cnf`) is redeemed
//! only with a proof of that key, and a public client's refresh token is
//! bound to the key it was first redeemed with. The resource takes a bound
//! token only with the `DPoP` authorization scheme and a fresh proof of its
//! key on every request.
//!
//! With authorization details on, a grant may be limited to objects of the
//! configured types (`authorization_details`), which the token carries and
//! a policy reads as `identity.authorization_details`.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Largest `dpop.proof_max_age_secs`.
const MAX_PROOF_MAX_AGE_SECS: u64 = 300;
/// Bounds on `dpop.nonce_lifetime_secs`.
const MIN_NONCE_LIFETIME_SECS: u64 = 30;
const MAX_NONCE_LIFETIME_SECS: u64 = 3_600;
/// Longest authorization details `type`, in characters.
const MAX_DETAIL_TYPE_CHARS: usize = 256;
/// Longest authorization details type `description`, in characters.
const MAX_DETAIL_DESCRIPTION_CHARS: usize = 120;
/// Largest `authorization_details.max_entries`.
const MAX_DETAIL_ENTRIES: u32 = 64;

/// DPoP (RFC 9449) at the embedded authorization server
/// (`governance.access.authorization_server.dpop`). Off by default: the
/// token endpoint then ignores `DPoP` headers and the `dpop_jkt`
/// parameter, and an ID-JAG bound to a key (`cnf`) is refused. Turn it on
/// only after every replica runs a build that knows this block: a replica
/// without it drops the key binding of a sign-in's grant when it rotates
/// the grant's refresh token. Turning it on (`enabled: true`) requires a
/// license with the `oauth.dpop` feature; a block that leaves it off needs
/// none.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DpopConfig {
    /// Bind tokens to the client's key. The token endpoint reads one
    /// `DPoP` proof header per request: a token issued with a valid proof
    /// carries `cnf.jkt` and `token_type: DPoP`, and one issued without a
    /// proof stays a Bearer token. An ID-JAG with `cnf.jkt` is redeemed
    /// only with a proof of that key (`invalid_grant` otherwise). The
    /// authorization endpoint reads `dpop_jkt` (RFC 9449 §10), and the code
    /// is then redeemed only with a proof of that key. A public client's
    /// refresh token is bound to its proof key; a confidential client's is
    /// not. The resource (`/mcp` and every endpoint that takes this
    /// server's tokens) accepts a bound token with `Authorization: DPoP`
    /// and a `DPoP` proof of its key for that request (method, URL, `ath`,
    /// single use); a Bearer token keeps working with the `Bearer` scheme.
    /// The caller then carries the key's thumbprint as the `dpop_jkt`
    /// identity attribute, which a policy can require. The authorization
    /// server metadata and the protected resource metadata publish
    /// `dpop_signing_alg_values_supported`. A token bound to a key is never
    /// accepted with the `Bearer` scheme, even after DPoP is turned off.
    /// Requires a license with the `oauth.dpop` feature.
    pub enabled: bool,
    /// Issue and accept only DPoP-bound tokens of this authorization
    /// server: a token request without a proof is refused, with
    /// `invalid_grant` for an ID-JAG (ID-JAG §9.8.1.2) and
    /// `invalid_dpop_proof` for an authorization code or a refresh token;
    /// the resource refuses a token of this server bound to no key, one
    /// issued before this was set included; and a 401 to a caller without
    /// a credential carries a second `WWW-Authenticate: DPoP` challenge.
    /// Credentials that another verifier accepts (an `oidc_oauth` provider,
    /// `jwks` or an identity plugin) are not affected, so the protected
    /// resource metadata publishes `dpop_bound_access_tokens_required:
    /// true` only while this server is the one verifier of access tokens
    /// and the only authorization server listed, and `false` otherwise.
    /// Requires `enabled`.
    pub required: bool,
    /// JWS algorithms a proof may be signed with, published as
    /// `dpop_signing_alg_values_supported`: `ES256`, `ES384`, `EdDSA`,
    /// `PS256`, `PS384`, `PS512`, `RS256`, `RS384` and `RS512`, each at most
    /// once. HMAC algorithms are refused: a proof is verified with the
    /// public key it carries. An RSA proof key must have at least 2048
    /// bits.
    pub allowed_algs: Vec<String>,
    /// How old a proof may be, in seconds (1–300): it is accepted while its
    /// `iat` lies between `proof_max_age_secs` plus `clock_skew_secs` in the
    /// past and `clock_skew_secs` in the future. Each proof is accepted
    /// once: its `jti` is recorded in the replay ledger every replica
    /// shares for `proof_max_age_secs` plus twice `clock_skew_secs`.
    pub proof_max_age_secs: u64,
    /// Server-provided nonces (RFC 9449 §8 and §9): `off`;
    /// `token_endpoint`, where a proof at `POST /oauth/token` must carry a
    /// current nonce or the request answers 400 `use_dpop_nonce` with a
    /// fresh `DPoP-Nonce` header, and every token response carries the
    /// current one; or `always`, which also covers the resource: a proof
    /// there without a current nonce is answered 401 `WWW-Authenticate: DPoP
    /// error="use_dpop_nonce"` with a fresh `DPoP-Nonce`. Nonces need no store:
    /// they are derived from the access-token signing keys, so every
    /// replica accepts every other replica's, and they follow a rotation
    /// of `signing_keys`.
    pub nonce: DpopNonceMode,
    /// How long one nonce window lasts, in seconds (30–3600). A nonce is
    /// accepted in the window it was issued in and in the next one, both
    /// widened by `clock_skew_secs`, so replicas whose clocks differ by up
    /// to that accept each other's nonces.
    pub nonce_lifetime_secs: u64,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            allowed_algs: default_dpop_allowed_algs(),
            proof_max_age_secs: 60,
            nonce: DpopNonceMode::Off,
            nonce_lifetime_secs: 300,
        }
    }
}

/// Where a DPoP proof must carry a server-provided nonce.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DpopNonceMode {
    /// No nonce is required.
    #[default]
    Off,
    /// At the token endpoint.
    TokenEndpoint,
    /// At the token endpoint and at the resource.
    Always,
}

impl DpopNonceMode {
    /// Whether a proof at the token endpoint must carry a nonce.
    pub fn covers_token_endpoint(self) -> bool {
        matches!(self, Self::TokenEndpoint | Self::Always)
    }
}

fn default_dpop_allowed_algs() -> Vec<String> {
    [
        "ES256", "ES384", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

impl DpopConfig {
    /// The algorithms of `allowed_algs`, in order. Refuses an empty list, a
    /// repeated or unknown name, and an HMAC algorithm.
    pub fn algorithms(&self, at: &str) -> Result<Vec<jsonwebtoken::Algorithm>> {
        use jsonwebtoken::Algorithm;
        if self.allowed_algs.is_empty() {
            bail!("{at}.allowed_algs must list at least one algorithm");
        }
        let mut parsed: Vec<Algorithm> = Vec::with_capacity(self.allowed_algs.len());
        for name in &self.allowed_algs {
            let alg = mcpg_plugin_identity_oidc_core::parse_algorithm(name)
                .map_err(|e| anyhow::anyhow!("{at}.allowed_algs: {e}"))?;
            if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
                bail!(
                    "{at}.allowed_algs lists `{name}`: a DPoP proof is verified with the public \
                     key it carries, so HMAC algorithms are never accepted"
                );
            }
            if parsed.contains(&alg) {
                bail!("{at}.allowed_algs lists `{name}` more than once");
            }
            parsed.push(alg);
        }
        Ok(parsed)
    }

    /// The rules of this block, at `at`.
    pub fn validate(&self, at: &str) -> Result<()> {
        if self.required && !self.enabled {
            bail!("{at}.required needs enabled: true; a token cannot be bound while DPoP is off");
        }
        self.algorithms(at)?;
        if self.proof_max_age_secs == 0 || self.proof_max_age_secs > MAX_PROOF_MAX_AGE_SECS {
            bail!("{at}.proof_max_age_secs must be between 1 and {MAX_PROOF_MAX_AGE_SECS}");
        }
        if !(MIN_NONCE_LIFETIME_SECS..=MAX_NONCE_LIFETIME_SECS).contains(&self.nonce_lifetime_secs)
        {
            bail!(
                "{at}.nonce_lifetime_secs must be between {MIN_NONCE_LIFETIME_SECS} and \
                 {MAX_NONCE_LIFETIME_SECS}"
            );
        }
        Ok(())
    }
}

/// Rich Authorization Requests (RFC 9396) at the embedded authorization
/// server (`governance.access.authorization_server.authorization_details`).
/// Off while `types` is empty: an ID-JAG that carries
/// `authorization_details` is then refused (`invalid_grant`), and the
/// `authorization_details` request parameter is ignored. Turn it on only
/// after every replica runs a build that knows this block: a replica
/// without it drops the details of a sign-in's grant when it rotates the
/// grant's refresh token, and the grant's next tokens carry none. Turning
/// it on (a non-empty `types`) requires a license with the
/// `oauth.rich_authorization` feature; a block without a type needs none.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AuthorizationDetailsConfig {
    /// The authorization details types this server accepts. Non-empty turns
    /// RFC 9396 on: the `authorization_details` parameter of the
    /// authorization endpoint (shown on the consent page, which is then
    /// always shown unless the client's `consent` is `skip`, and never
    /// remembered) and of the token endpoint (which may only narrow what
    /// was granted); the `authorization_details` claim of an ID-JAG (every
    /// object must be valid, or the assertion is refused with
    /// `invalid_grant`); the granted details in the token response and in
    /// the access token's `authorization_details` claim; the identity
    /// attributes `authorization_details` (compact JSON, which audit
    /// records carry only as `keyed-blake3:` and its digest under a key
    /// derived from the first signing key, so the value cannot be guessed
    /// back from it) and
    /// `authorization_details_types` (the distinct types, space-separated),
    /// and the policy binding `identity.authorization_details`, a list of
    /// maps (for example `identity.authorization_details.exists(d, d.type
    /// == "mcp_tool" && "tools/call" in d.actions)`); and
    /// `authorization_details_types_supported` in the authorization server
    /// metadata and the protected resource metadata. A parameter that fails
    /// a rule is refused with `invalid_authorization_details`. An
    /// authorization request with details and no `scope` is granted no
    /// scope. Non-empty requires a license with the
    /// `oauth.rich_authorization` feature.
    pub types: Vec<AuthorizationDetailsTypeConfig>,
    /// Most objects one `authorization_details` array may hold (1–64).
    /// The array is also limited to 8 KiB of JSON.
    pub max_entries: u32,
}

impl Default for AuthorizationDetailsConfig {
    fn default() -> Self {
        Self {
            types: Vec::new(),
            max_entries: 16,
        }
    }
}

/// One authorization details type the server accepts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDetailsTypeConfig {
    /// The RFC 9396 `type`, compared exactly: 1–256 characters, no
    /// whitespace or control characters, each type listed once.
    #[serde(rename = "type")]
    pub type_name: String,
    /// What the consent page shows for an object of this type (1–120
    /// characters). Defaults to the type.
    #[serde(default)]
    pub description: Option<String>,
    /// A JSON Schema every object of this type must satisfy, inline. Local
    /// `$ref`s only; its depth and size are bounded. Without it, an object
    /// may carry only `type`, `locations`, `actions`, `datatypes`,
    /// `identifier` and `privileges` (RFC 9396 §2.2); with it, any member
    /// the schema admits. `locations`, `actions`, `datatypes` and
    /// `privileges` are arrays of at most 64 non-empty strings and
    /// `identifier` is a string either way.
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
    /// The values `actions` may hold. Unset: any.
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    /// The values `datatypes` may hold. Unset: any.
    #[serde(default)]
    pub datatypes: Option<Vec<String>>,
    /// The values `privileges` may hold. Unset: any.
    #[serde(default)]
    pub privileges: Option<Vec<String>>,
    /// What `locations` may name: `resource` (the default), one of this
    /// server's resource identifiers (`resource_metadata.resource` and its
    /// `additional_resources`, a trailing `/` ignored); or `any` value.
    #[serde(default)]
    pub locations: AuthorizationDetailLocations,
}

/// What the `locations` of an authorization details object may name.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDetailLocations {
    /// A resource identifier of this server.
    #[default]
    Resource,
    /// Any string.
    Any,
}

impl AuthorizationDetailsConfig {
    /// Whether RFC 9396 is on.
    pub fn enabled(&self) -> bool {
        !self.types.is_empty()
    }

    /// The rules of this block, at `at`, each type's schema compiled.
    pub fn validate(&self, at: &str) -> Result<()> {
        if self.max_entries == 0 || self.max_entries > MAX_DETAIL_ENTRIES {
            bail!("{at}.max_entries must be between 1 and {MAX_DETAIL_ENTRIES}");
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.types.len());
        for (index, rule) in self.types.iter().enumerate() {
            let at = format!("{at}.types[{index}]");
            let name = rule.type_name.as_str();
            if name.is_empty()
                || name.chars().count() > MAX_DETAIL_TYPE_CHARS
                || name.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                bail!(
                    "{at}.type must be 1 to {MAX_DETAIL_TYPE_CHARS} characters without whitespace \
                     or control characters"
                );
            }
            if seen.contains(&name) {
                bail!("{at}.type `{name}` is listed more than once");
            }
            seen.push(name);
            if let Some(ref description) = rule.description
                && (description.trim().is_empty()
                    || description.chars().count() > MAX_DETAIL_DESCRIPTION_CHARS
                    || description.chars().any(char::is_control))
            {
                bail!(
                    "{at}.description must be 1 to {MAX_DETAIL_DESCRIPTION_CHARS} characters \
                     without control characters"
                );
            }
            for (field, values) in [
                ("actions", &rule.actions),
                ("datatypes", &rule.datatypes),
                ("privileges", &rule.privileges),
            ] {
                if let Some(values) = values
                    && (values.is_empty() || values.iter().any(String::is_empty))
                {
                    bail!(
                        "{at}.{field} must list at least one value, none of them empty, when set"
                    );
                }
            }
            if let Some(ref schema) = rule.schema {
                super::schema_safety::compile_checked(schema, &format!("{at}.schema"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "sender_constraint_tests.rs"]
mod tests;
