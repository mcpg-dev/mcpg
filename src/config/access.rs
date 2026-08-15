//! `governance.access:` block — inbound identity (legacy JWKS or
//! enterprise OIDC/OAuth) plus the OAuth Protected Resource
//! Metadata endpoint.
//!
//! This block is identity establishment (who is the caller);
//! authorization (what they can do) lives in
//! `governance.policy:`.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use mcpg_plugin_identity_oidc_core::config::OidcOAuthConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    #[serde(default)]
    pub jwks: Option<JwksConfig>,
    #[serde(default)]
    pub oidc_oauth: Option<OidcOAuthConfig>,
    /// OAuth 2.1 Protected Resource Metadata (RFC 9728).
    /// When set, enables `GET /.well-known/oauth-protected-resource`.
    /// If omitted but oidc_oauth providers are configured, metadata is auto-derived.
    #[serde(default)]
    pub resource_metadata: Option<OAuthResourceMetadataConfig>,
    /// Embedded Enterprise-Managed Authorization server (MCP
    /// `io.modelcontextprotocol/enterprise-managed-authorization`).
    /// When set, the gateway acts as the OAuth Resource Authorization
    /// Server for ID-JAG grants: it serves RFC 8414 metadata at
    /// `GET /.well-known/oauth-authorization-server` advertising the
    /// `urn:ietf:params:oauth:grant-profile:id-jag` grant profile, and
    /// redeems Identity Assertion JWT Authorization Grants issued by the
    /// configured trusted enterprise IdPs at `POST /oauth/token`
    /// (`urn:ietf:params:oauth:grant-type:jwt-bearer`), minting
    /// audience-restricted access tokens the gateway itself accepts.
    /// Only this grant is supported — there is no authorization
    /// endpoint, no refresh tokens, and no dynamic client registration.
    #[serde(default)]
    pub authorization_server: Option<AuthorizationServerConfig>,
}

/// Embedded EMA authorization server (`governance.access.authorization_server`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerConfig {
    /// This authorization server's issuer identifier (RFC 8414). MUST be
    /// the canonical external `http(s)` origin the gateway is reached at
    /// — enterprise IdPs bind ID-JAGs to it as the `aud` claim, compared
    /// exactly. Also the `iss` of every access token this server mints.
    pub issuer: String,
    /// Resource identifier minted access tokens are audience-restricted
    /// to (RFC 8707). Defaults to
    /// `governance.access.resource_metadata.resource` when that block is
    /// configured, else to `issuer`. An ID-JAG carrying a `resource`
    /// claim must match this value or redemption fails with
    /// `invalid_target`.
    #[serde(default)]
    pub resource: Option<String>,
    /// HS256 signing secret for minted access tokens (≥ 32 bytes).
    /// Supply via `${env.X}`. Every gateway instance in a cluster must
    /// share this value so any instance can verify tokens minted by any
    /// other.
    pub signing_secret: String,
    /// Lifetime of minted access tokens, in seconds.
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// Clock-skew leeway applied to ID-JAG `exp`/`iat`/`nbf` validation,
    /// in seconds.
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Enforce single-use ID-JAG redemption per instance: a `jti` seen
    /// once is refused until the assertion expires. Defense-in-depth on
    /// top of the assertion's short lifetime.
    #[serde(default = "default_enforce_single_use")]
    pub enforce_single_use: bool,
    /// When set, the scopes granted on minted tokens are the
    /// intersection of the ID-JAG's `scope` claim with this list (the
    /// resource server may narrow, never widen, IdP-granted scopes).
    /// When omitted, IdP-granted scopes pass through unchanged.
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,
    /// Enterprise IdPs trusted to issue ID-JAGs. An assertion whose
    /// `iss` is not listed here is refused (`invalid_grant`).
    #[serde(default)]
    pub trusted_idps: Vec<TrustedIdpConfig>,
    /// OAuth clients allowed to redeem ID-JAGs at the token endpoint.
    /// Clients with a `client_secret` authenticate via
    /// `client_secret_basic` or `client_secret_post`; clients without
    /// one are public (`none`) — register an MCP client's Client ID
    /// Metadata Document URL as its `client_id` for that case. The
    /// ID-JAG's `client_id` claim must match the presenting client
    /// either way.
    #[serde(default)]
    pub clients: Vec<AuthorizationServerClientConfig>,
}

/// One enterprise IdP trusted to issue ID-JAGs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedIdpConfig {
    /// The IdP's issuer identifier, compared exactly against the
    /// ID-JAG `iss` claim.
    pub issuer: String,
    /// JWKS endpoint override. When omitted, the JWKS URI is taken from
    /// the IdP's OIDC discovery document (`{issuer}/.well-known/openid-configuration`).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Optional host allowlist for discovery/JWKS fetches (exact or
    /// subdomain match). Empty = any public host.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Local-development escape hatch: permit `http://` and
    /// private/loopback IdP addresses. Production deployments leave
    /// this `false`.
    #[serde(default)]
    pub allow_private_network: bool,
}

/// One OAuth client registered with the embedded authorization server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerClientConfig {
    /// The client identifier the enterprise IdP binds into ID-JAGs
    /// (`client_id` claim). For MCP clients identifying via a Client ID
    /// Metadata Document, this is the document URL.
    pub client_id: String,
    /// Client secret for `client_secret_basic` / `client_secret_post`
    /// authentication. Supply via `${env.X}`. Omit to register a public
    /// client (`token_endpoint_auth_method: none`).
    #[serde(default)]
    pub client_secret: Option<String>,
}

fn default_access_token_ttl_secs() -> u64 {
    3600
}

fn default_clock_skew_secs() -> u64 {
    60
}

fn default_enforce_single_use() -> bool {
    true
}

/// A config value still carrying an unresolved `${…}` placeholder —
/// length/strength checks would be judging the placeholder, not the
/// secret.
fn is_unresolved_placeholder(value: &str) -> bool {
    value.contains("${")
}

impl AuthorizationServerConfig {
    pub fn validate(&self) -> Result<()> {
        let prefix = "governance.access.authorization_server";
        if self.issuer.trim().is_empty() {
            return Err(anyhow::anyhow!("{prefix}.issuer must not be empty"));
        }
        if !self.issuer.starts_with("https://") && !self.issuer.starts_with("http://") {
            return Err(anyhow::anyhow!(
                "{prefix}.issuer must be an absolute http(s) URL"
            ));
        }
        if self.issuer.contains('#') || self.issuer.contains('?') {
            return Err(anyhow::anyhow!(
                "{prefix}.issuer must not carry a query or fragment (RFC 8414 issuer identifier)"
            ));
        }
        if let Some(host) = resource_host(&self.issuer)
            && is_wildcard_host(&host)
        {
            return Err(anyhow::anyhow!(
                "{prefix}.issuer host `{host}` is a wildcard/unspecified address — set the \
                 canonical external URL enterprise IdPs bind ID-JAG audiences to"
            ));
        }
        if let Some(ref resource) = self.resource {
            if resource.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{prefix}.resource must not be empty when set"
                ));
            }
            if !resource.starts_with("https://") && !resource.starts_with("http://") {
                return Err(anyhow::anyhow!(
                    "{prefix}.resource must be an absolute http(s) URL"
                ));
            }
            if resource.contains('#') {
                return Err(anyhow::anyhow!(
                    "{prefix}.resource must not contain a fragment (RFC 8707 §2)"
                ));
            }
        }
        // 32 bytes of secret is the floor for HS256 (RFC 7518 §3.2 requires
        // a key at least as large as the hash output).
        if !is_unresolved_placeholder(&self.signing_secret) && self.signing_secret.len() < 32 {
            return Err(anyhow::anyhow!(
                "{prefix}.signing_secret must be at least 32 bytes for HS256"
            ));
        }
        if self.access_token_ttl_secs == 0 {
            return Err(anyhow::anyhow!(
                "{prefix}.access_token_ttl_secs must be greater than zero"
            ));
        }
        if self.trusted_idps.is_empty() {
            return Err(anyhow::anyhow!(
                "{prefix}.trusted_idps must list at least one enterprise IdP"
            ));
        }
        let mut idp_issuers = std::collections::BTreeSet::new();
        for idp in &self.trusted_idps {
            if idp.issuer.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{prefix}.trusted_idps[].issuer must not be empty"
                ));
            }
            if !idp_issuers.insert(idp.issuer.trim_end_matches('/')) {
                return Err(anyhow::anyhow!(
                    "{prefix}.trusted_idps lists issuer `{}` more than once",
                    idp.issuer
                ));
            }
            // Same preflight the runtime applies before every fetch —
            // surface misconfiguration at boot instead of first use.
            mcpg_plugin_identity_oidc_core::resolver::enforce_discovery_url_safety(
                &idp.issuer,
                &idp.allowed_hosts,
                idp.allow_private_network,
            )
            .map_err(|e| anyhow::anyhow!("{prefix}.trusted_idps[].issuer: {e}"))?;
            if let Some(ref jwks_uri) = idp.jwks_uri {
                mcpg_plugin_identity_oidc_core::resolver::enforce_discovery_url_safety(
                    jwks_uri,
                    &idp.allowed_hosts,
                    idp.allow_private_network,
                )
                .map_err(|e| anyhow::anyhow!("{prefix}.trusted_idps[].jwks_uri: {e}"))?;
            }
        }
        if self.clients.is_empty() {
            return Err(anyhow::anyhow!(
                "{prefix}.clients must register at least one OAuth client"
            ));
        }
        let mut client_ids = std::collections::BTreeSet::new();
        for client in &self.clients {
            if client.client_id.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{prefix}.clients[].client_id must not be empty"
                ));
            }
            if !client_ids.insert(client.client_id.as_str()) {
                return Err(anyhow::anyhow!(
                    "{prefix}.clients registers client_id `{}` more than once",
                    client.client_id
                ));
            }
            if let Some(ref secret) = client.client_secret
                && secret.trim().is_empty()
            {
                return Err(anyhow::anyhow!(
                    "{prefix}.clients[].client_secret must not be empty when set (omit it for a public client)"
                ));
            }
        }
        Ok(())
    }
}

/// Configuration for the OAuth Protected Resource Metadata endpoint (RFC 9728).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthResourceMetadataConfig {
    /// The protected resource's canonical resource identifier (RFC 8707
    /// `resource` / RFC 9728 `resource`). MUST be the real external,
    /// absolute URL clients reach the gateway at — the same value the
    /// authorization server binds tokens to as `aud`. A wildcard
    /// (`0.0.0.0`), bare loopback (`localhost`/`127.0.0.1`/`[::1]`), or
    /// derived `bind_address` value is refused at boot: it would publish a
    /// `resource` that does not match the audience the tokens carry, so
    /// audience-bound validation silently fails. Set the canonical
    /// public URL explicitly, or opt into the loopback form for local
    /// development with `allow_loopback_resource: true`.
    pub resource: String,
    /// Authorization server URLs. If empty, derived from OIDC provider issuers.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Scopes supported by this resource.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Bearer token presentation methods. Defaults to `["header"]`.
    #[serde(default = "default_bearer_methods")]
    pub bearer_methods_supported: Vec<String>,
    /// Local-development escape hatch: permit a loopback `resource`
    /// (`localhost` / `127.0.0.1` / `[::1]`). A wildcard host
    /// (`0.0.0.0` / `[::]`) is NEVER a valid resource identifier and is
    /// refused even with this set. Production deployments leave this
    /// `false` and configure the canonical public URL.
    #[serde(default)]
    pub allow_loopback_resource: bool,
}

fn default_bearer_methods() -> Vec<String> {
    vec!["header".to_owned()]
}

/// Hosts that can never be a canonical resource identifier — a token's
/// `aud` is never a wildcard bind address.
fn is_wildcard_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "0.0.0.0" || host == "::" || host.is_empty()
}

/// Bare loopback hosts — valid only behind `allow_loopback_resource`.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// Extract the host (without port) from an `http(s)://host[:port]/...` URL.
fn resource_host(resource: &str) -> Option<String> {
    let after_scheme = resource
        .strip_prefix("https://")
        .or_else(|| resource.strip_prefix("http://"))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // IPv6 literal: `[::1]:8080` — keep the bracketed host, drop the port.
    if let Some(rest) = authority.strip_prefix('[') {
        let host = rest.split(']').next().unwrap_or(rest);
        return Some(host.to_owned());
    }
    Some(authority.split(':').next().unwrap_or(authority).to_owned())
}

impl OAuthResourceMetadataConfig {
    pub fn validate(&self) -> Result<()> {
        if self.resource.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource must not be empty"
            ));
        }
        if !self.resource.starts_with("https://") && !self.resource.starts_with("http://") {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource must be a valid absolute URL (http:// or https://)"
            ));
        }
        // RFC 8707 §2: the resource identifier MUST NOT carry a fragment.
        if self.resource.contains('#') {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource must not contain a fragment (RFC 8707 §2)"
            ));
        }
        let Some(host) = resource_host(&self.resource) else {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource is not a parseable URL: {}",
                self.resource
            ));
        };
        if is_wildcard_host(&host) {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource host `{host}` is a wildcard/unspecified \
                 address — it can never be a token audience. Set the canonical external URL \
                 the gateway is reached at."
            ));
        }
        if is_loopback_host(&host) && !self.allow_loopback_resource {
            return Err(anyhow::anyhow!(
                "governance.access.resource_metadata.resource host `{host}` is loopback; a published \
                 PRM resource must be the canonical external URL clients reach. Set the public URL, \
                 or for local development opt in with \
                 governance.access.resource_metadata.allow_loopback_resource: true"
            ));
        }
        Ok(())
    }

    /// Build the absolute RFC 9728 well-known metadata URL for this
    /// resource. Per RFC 9728 §3.1 the `/.well-known/oauth-protected-resource`
    /// suffix is inserted between the host and any path/query of the
    /// resource identifier (the path-aware form), after stripping a
    /// terminating slash on the host component.
    pub fn well_known_url(&self) -> String {
        well_known_resource_metadata_url(&self.resource)
    }
}

/// RFC 9728 §3.1 path-aware well-known construction. Splits an
/// `scheme://host[:port]/path?query` resource into
/// `scheme://host[:port]` + `/.well-known/oauth-protected-resource` +
/// `/path` (terminating host slash removed first). Inputs are
/// pre-validated as absolute `http(s)` URLs by config validation; a
/// non-conforming input falls back to the root suffix.
fn well_known_resource_metadata_url(resource: &str) -> String {
    const SUFFIX: &str = "/.well-known/oauth-protected-resource";
    let (scheme, rest) = if let Some(r) = resource.strip_prefix("https://") {
        ("https://", r)
    } else if let Some(r) = resource.strip_prefix("http://") {
        ("http://", r)
    } else {
        return format!("{}{SUFFIX}", resource.trim_end_matches('/'));
    };
    // Authority ends at the first `/`, `?`, or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path_and_query = &rest[authority_end..];
    // Drop a query/fragment from the path tail — the well-known suffix
    // carries only the path component (RFC 9728 example).
    let path = path_and_query
        .split(['?', '#'])
        .next()
        .unwrap_or(path_and_query);
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        format!("{scheme}{authority}{SUFFIX}")
    } else {
        format!("{scheme}{authority}{SUFFIX}{path}")
    }
}

impl AccessConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref jwks) = self.jwks {
            jwks.validate()?;
        }
        if let Some(ref oidc) = self.oidc_oauth {
            oidc.validate()?;
        }
        if self.jwks.is_some() && self.oidc_oauth.is_some() {
            return Err(anyhow::anyhow!(
                "governance.access: cannot configure both 'jwks' and 'oidc_oauth' simultaneously; use oidc_oauth for enterprise identity"
            ));
        }
        if let Some(ref rm) = self.resource_metadata {
            rm.validate()?;
        }
        if let Some(ref authz) = self.authorization_server {
            authz.validate()?;
        }
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.jwks.is_some() || self.oidc_oauth.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JwksConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub keys_json: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_jwks_header_name")]
    pub header_name: String,
    #[serde(default = "default_jwks_header_prefix")]
    pub header_prefix: String,
    /// Dev escape-hatch: allow tokens without audience binding.
    /// Production MUST set an audience.
    #[serde(default)]
    pub allow_missing_audience: bool,
}

impl JwksConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let has_url = !self.url.trim().is_empty();
        let has_keys = self
            .keys_json
            .as_ref()
            .is_some_and(|k| !k.trim().is_empty());

        if !has_url && !has_keys {
            return Err(anyhow::anyhow!(
                "governance.access.jwks must have either a 'url' or 'keys_json' field"
            ));
        }
        if has_url && !self.url.starts_with("https://") && !self.url.starts_with("http://") {
            return Err(anyhow::anyhow!(
                "governance.access.jwks.url must start with http:// or https://"
            ));
        }
        if let Some(ref issuer) = self.issuer
            && issuer.trim().is_empty()
        {
            return Err(anyhow::anyhow!(
                "governance.access.jwks.issuer must not be empty when provided"
            ));
        }
        // Security: audience binding prevents accepting tokens intended
        // for other services. Missing audience requires explicit opt-in.
        match (&self.audience, self.allow_missing_audience) {
            (Some(aud), _) if aud.trim().is_empty() => {
                return Err(anyhow::anyhow!(
                    "governance.access.jwks.audience must not be empty when provided"
                ));
            }
            (None, false) => {
                return Err(anyhow::anyhow!(
                    "governance.access.jwks.audience is required (set governance.access.jwks.allow_missing_audience=true only for local development)"
                ));
            }
            _ => {}
        }
        if self.header_name.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "governance.access.jwks.header_name must not be empty"
            ));
        }
        Ok(())
    }
}

pub(crate) fn default_jwks_header_name() -> String {
    "authorization".to_owned()
}

pub(crate) fn default_jwks_header_prefix() -> String {
    "Bearer ".to_owned()
}
