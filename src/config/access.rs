//! `governance.access:` block — inbound identity (legacy JWKS or
//! enterprise OIDC/OAuth) plus the OAuth Protected Resource
//! Metadata endpoint.
//!
//! This block is identity establishment (who is the caller);
//! authorization (what they can do) lives in
//! `governance.policy:`.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use mcpg_plugin_identity_oidc_core::config::OidcOAuthConfig;

pub use super::interactive_login::{
    ClientConsent, ClientGrantType, InteractiveLoginConfig, RedirectUriPolicy,
    TrustedIdpLoginConfig,
};
use super::sender_constraint::{AuthorizationDetailsConfig, DpopConfig};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    #[serde(default)]
    pub jwks: Option<JwksConfig>,
    /// Inbound OIDC: verifies Bearer tokens against each provider. A
    /// provider's `claim_mappings.attribute_claim_mappings` may not map to
    /// an attribute that only a credential of this gateway sets
    /// (`token_issuer`, `grant_type`, `grant_id`, `dpop_jkt`,
    /// `authorization_details`, `authorization_details_types`) or to a name
    /// starting with `subject_token`: such a configuration is refused at
    /// load, whether DPoP and authorization details are on or not. An
    /// identity plugin's attributes of those six names are dropped.
    #[serde(default)]
    pub oidc_oauth: Option<OidcOAuthConfig>,
    /// OAuth 2.1 Protected Resource Metadata (RFC 9728), served at
    /// `GET /.well-known/oauth-protected-resource` and its path-aware
    /// form. Without it that endpoint answers 404: the gateway never
    /// guesses its public `resource` from the bind address. Required
    /// with `authorization_server`.
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
    /// With a `trusted_idps[].login` block it also signs users in
    /// interactively: an authorization endpoint (`authorization_code`
    /// with PKCE) that sends the user to that IdP, rotating refresh
    /// tokens, and optional dynamic client registration (see
    /// `interactive`). Without one there is no authorization endpoint, no
    /// refresh token and no registration endpoint. Requires
    /// `resource_metadata`, which is how clients discover this server.
    #[serde(default)]
    pub authorization_server: Option<AuthorizationServerConfig>,
    /// Refuse every MCP request (`POST`, `GET` and `DELETE` on the MCP
    /// path, every JSON-RPC method including `initialize`, `*/list` and
    /// `server/discover`) from a caller below `verified` with HTTP 401
    /// and the `WWW-Authenticate: Bearer resource_metadata="…"`
    /// challenge. An OAuth or EMA client that authenticates only after
    /// a 401 starts its flow from that challenge; with this off, an
    /// anonymous `initialize` succeeds and such a client never
    /// authenticates. A request whose `Origin` is not allowed is still
    /// refused with 403 first. Only the MCP path is covered: the
    /// well-known metadata, the embedded authorization server's
    /// `/oauth/*` endpoints (`token`, `jwks`, `revoke`, `register`,
    /// `authorize`, `consent`, `callback`, `connect`), the AAuth
    /// resource endpoints, health, readiness, metrics, `/runtime`,
    /// `/v0.1/servers`, the `/webhooks/*` callbacks and the plugin HTTP
    /// routes (`/plugins/{id}/{entity}` and override paths) stay open to
    /// anonymous callers, each gated as it is without this key. Needs at
    /// least one verifier: `jwks`,
    /// `oidc_oauth`, `authorization_server` or an `identity_provider`
    /// plugin.
    #[serde(default)]
    pub require_authentication: bool,
}

/// Embedded EMA authorization server (`governance.access.authorization_server`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerConfig {
    /// This authorization server's issuer identifier (RFC 8414): the
    /// external origin the gateway is reached at, `scheme://host[:port]`,
    /// with no path. The metadata and token endpoints are served at the
    /// root of that origin. Enterprise IdPs bind every ID-JAG to it as the
    /// `aud` claim, compared exactly, so it must be exactly the value
    /// entered as the authorization server's issuer in the IdP (Okta: the
    /// resource app's Issuer URL, which cannot change without resetting
    /// the connection), a trailing `/` included: an issuer that ends in
    /// `/` is published and compared with it. Also the `iss` of every
    /// access token this server mints. One issuer serves every resource
    /// identifier in `resource_metadata`, including
    /// `additional_resources`: keep it on the canonical origin. Use
    /// `https://`; `http://` draws a warning outside loopback, since
    /// clients send assertions and client secrets to the token endpoint.
    pub issuer: String,
    /// Resource identifier (RFC 8707) minted access tokens are
    /// audience-restricted to when neither the token request nor the
    /// ID-JAG names a `resource`. Defaults to
    /// `governance.access.resource_metadata.resource`; keep it one of the
    /// resource identifiers `resource_metadata` advertises. A `resource`
    /// named by the token request or the ID-JAG must be this value,
    /// `resource_metadata.resource` or one of its `additional_resources`
    /// (a trailing `/` is ignored); a request's `resource` must also be
    /// among the ID-JAG's when it carries any. The token is minted for
    /// the one named, and the token response returns it as `resource`.
    /// Any other value fails with `invalid_target`.
    #[serde(default)]
    pub resource: Option<String>,
    /// HS256 signing secret for minted access tokens (≥ 32 bytes), a
    /// shorthand for one `signing_keys` entry `{alg: HS256, secret: …}`.
    /// Supply via `${env.X}` or `${secret.NAME}`. Set this or
    /// `signing_keys`, not both. To rotate to other keys without
    /// invalidating the tokens this secret minted, move it into
    /// `signing_keys` as an HS256 entry without a `kid`, after the new
    /// signing key.
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// Keys that sign and verify minted access tokens. The first entry
    /// signs every new token; every entry verifies the tokens that carry
    /// its `kid`, so a key rotation lists the new key first and keeps
    /// the old one until the tokens it signed have expired
    /// (`access_token_ttl_secs`). A token whose `kid` is not listed is
    /// refused. The public keys of the asymmetric entries (`ES256`,
    /// `EdDSA`, `RS256`) are published at `GET /oauth/jwks`, advertised
    /// as `jwks_uri` in the authorization server metadata, so other
    /// resource servers can verify the tokens; an HS256 secret is never
    /// published. Every gateway instance in a cluster must carry the
    /// same keys.
    #[serde(default)]
    pub signing_keys: Vec<SigningKeyConfig>,
    /// Lifetime of minted access tokens, in seconds (1–86400). The IdP
    /// cannot revoke a minted token, and without interactive sign-in (which
    /// adds `POST /oauth/revoke`) neither can its client, so it stays valid
    /// for up to this long after the IdP revokes the user; values above
    /// 3600 draw a warning.
    /// A longer lifetime means fewer ID-JAG exchanges, which matters
    /// where the IdP meters them (Okta: 250 ID-JAGs per user, per
    /// resource app, per month).
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// Clock-skew leeway applied to ID-JAG `exp`/`iat`/`nbf` validation
    /// and to the expiry of minted tokens, in seconds (at most 300).
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Longest ID-JAG lifetime (`exp` − `iat`) accepted, in seconds
    /// (1–3600). Together with `clock_skew_secs` it also bounds how old
    /// an accepted assertion's `iat` can be. Okta issues ID-JAGs for
    /// 300 seconds.
    #[serde(default = "default_max_assertion_lifetime_secs")]
    pub max_assertion_lifetime_secs: u64,
    /// Enforce single-use ID-JAG redemption: an assertion (`iss` and
    /// `jti`) redeemed once is refused until it expires. Redemptions are
    /// recorded in the cluster coordinator's key-value store, so a replay
    /// is refused on every instance of a clustered deployment and across
    /// configuration reloads. When that store cannot be reached,
    /// redemption answers `temporarily_unavailable` rather than admit an
    /// unrecorded assertion.
    #[serde(default = "default_enforce_single_use")]
    pub enforce_single_use: bool,
    /// When set, the scopes granted on minted tokens are the
    /// intersection of the ID-JAG's `scope` claim with this list (the
    /// resource server may narrow, never widen, IdP-granted scopes).
    /// When omitted, IdP-granted scopes pass through unchanged. A `scope`
    /// parameter on the token request narrows the grant further to the
    /// requested scopes. Requested scopes this server does not know —
    /// listed neither here, in `resource_metadata.scopes_supported`, nor
    /// in the ID-JAG — are ignored, and a request that names no known
    /// scope counts as one without `scope`. A request whose known scopes
    /// the grant holds none of is refused with `invalid_scope`.
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,
    /// Refuse a redemption whose granted scope set is empty with
    /// `invalid_scope`, instead of minting a token without scopes.
    #[serde(default)]
    pub require_scope: bool,
    /// Enterprise IdPs trusted to issue ID-JAGs, and, for the one entry
    /// with a `login` block, to sign users in; at least one is required.
    /// An assertion whose `iss` is not listed here is refused
    /// (`invalid_grant`). The access
    /// tokens minted for an IdP's users are refused as soon as the IdP is
    /// removed, or its `allowed_clients` or `required_tenant` no longer
    /// admit them, and those minted for a client as soon as it can no
    /// longer authenticate here.
    #[serde(default)]
    pub trusted_idps: Vec<TrustedIdpConfig>,
    /// OAuth clients registered here: clients that redeem ID-JAGs at the
    /// token endpoint and clients that sign users in (`redirect_uris`,
    /// `grant_types`), each authenticating with its
    /// `token_endpoint_auth_method`. An ID-JAG's
    /// `client_id` claim must name the authenticated client. A request
    /// that uses more than one client authentication method is refused
    /// (`invalid_request`). A failed client authentication answers
    /// `invalid_client` with 401 and a `Basic` challenge after HTTP Basic,
    /// else with 400 (RFC 6749 §5.2). May be empty when
    /// `client_id_metadata_documents.allowed_hosts` admits clients by
    /// their metadata document instead.
    #[serde(default)]
    pub clients: Vec<AuthorizationServerClientConfig>,
    /// Roles added to `identity.roles` of every caller whose access token
    /// was minted for a client, keyed by `client_id`: a
    /// `clients[].client_id`, or a metadata document URL that
    /// `client_id_metadata_documents.allowed_hosts` admits. They apply to
    /// every user of the client, so they describe the client (for
    /// example `ai-agent`) rather than grant any one user something. Read
    /// on each request, so a change also applies to tokens already
    /// issued.
    #[serde(default)]
    pub client_roles: BTreeMap<String, Vec<String>>,
    /// OAuth Client ID Metadata Documents
    /// (`draft-ietf-oauth-client-id-metadata-document`): an MCP client
    /// identifies itself with the `https://` URL of a JSON document that
    /// describes it, instead of a registration.
    #[serde(default)]
    pub client_id_metadata_documents: ClientIdMetadataDocumentsConfig,
    /// Refused token requests allowed per minute from one client IP
    /// address at `POST /oauth/token`, which `POST /oauth/revoke` and
    /// `POST /oauth/register` share. Every request takes from the budget
    /// and a successful redemption gives it back, so only refused
    /// requests (a bad assertion or client credential, an unknown client)
    /// spend it; the budget refills continuously and a full minute's
    /// worth may arrive at once. While it is spent, requests from that
    /// address are answered `429` with `Retry-After` and the OAuth error
    /// `temporarily_unavailable`. The client IP is the first
    /// `X-Forwarded-For` hop when `gateway.server.trust_proxy_ip` is set,
    /// else the connection's peer, so behind a proxy without
    /// `trust_proxy_ip` every client shares one budget. Clients behind one
    /// egress address — a NAT, or a hosted MCP client calling from its
    /// own servers — also share it. `0` disables the limit.
    #[serde(default = "default_token_rate_limit_per_min")]
    pub rate_limit_per_min: u32,
    /// Settings of interactive sign-in, which a `trusted_idps[].login`
    /// block turns on; every key has a default. Refused without such a
    /// block. Requires a license with the `sso.interactive_login` feature.
    #[serde(default)]
    pub interactive: Option<InteractiveLoginConfig>,
    /// DPoP (RFC 9449): access tokens bound to a key the client proves it
    /// holds. Off by default. `enabled: true` requires a license with the
    /// `oauth.dpop` feature; a block that leaves it off needs none.
    #[serde(default)]
    pub dpop: DpopConfig,
    /// Rich Authorization Requests (RFC 9396): grants and access tokens
    /// limited to fine-grained `authorization_details` of the types listed
    /// here. Off while `types` is empty. A non-empty `types` requires a
    /// license with the `oauth.rich_authorization` feature; a block without
    /// a type needs none.
    #[serde(default)]
    pub authorization_details: AuthorizationDetailsConfig,
}

/// Client ID Metadata Documents at the embedded authorization server
/// (`governance.access.authorization_server.client_id_metadata_documents`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientIdMetadataDocumentsConfig {
    /// Advertise `client_id_metadata_document_supported: true` in the
    /// authorization server metadata, and resolve unregistered URL
    /// `client_id`s on `allowed_hosts`. An MCP client such as Claude
    /// identifies with its metadata document URL only when the metadata
    /// advertises this and `none` among the token endpoint authentication
    /// methods. Defaults to `true` when a `clients[].client_id` is an
    /// `https://` URL or `allowed_hosts` is set, else `false`.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Hosts whose `https://` `client_id` URLs are accepted without a
    /// `clients[]` entry (an exact host, or a parent domain of it). The
    /// gateway fetches such a document with no redirects and at most
    /// 5 KiB, requires its `client_id` to equal the URL exactly, and reads
    /// `token_endpoint_auth_method` from it: `none`, or `private_key_jwt`
    /// with the document's `jwks` or `jwks_uri`, whose host must also be
    /// listed here. Without the member, a document that publishes keys is
    /// `private_key_jwt` and one that publishes none is `none`. A
    /// shared-secret method is refused. While `dpop.enabled`, a document's
    /// `dpop_bound_access_tokens` (RFC 9449 §5.2) is read: any value but
    /// `false` requires a DPoP proof on every token request of the client.
    /// The `client_id` URL must be in
    /// canonical form (lower-case host, no default port, no dot segments).
    /// A document is reused for its `Cache-Control: max-age`, kept
    /// between 60 seconds and 24 hours (5 minutes without one). A
    /// `clients[]` entry with the same `client_id` takes precedence, and
    /// its document is never fetched. Empty = registered clients only.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Local-development escape hatch: permit `http://` document and key
    /// URLs and private/loopback addresses. Production deployments leave
    /// this `false`.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Interactive sign-in: which `https://` redirect URIs a document may
    /// list. `same_host` (the default): only on exactly the host of its
    /// `client_id` URL. `allowed_hosts`: on any host `allowed_hosts`
    /// admits. Loopback redirect URIs (`http://127.0.0.1`, `http://[::1]`,
    /// `http://localhost`, any port) are always allowed; the consent page
    /// is then shown on every sign-in. A listed URI that breaks the rule
    /// is never matched. A document signs users in only when it carries
    /// `client_name` and `redirect_uris`, `response_types` is absent or
    /// `["code"]`, and `grant_types` (`[authorization_code]` when absent)
    /// holds `authorization_code`; the client gets refresh tokens only
    /// when `grant_types` also holds `refresh_token`. Sign-in reads a
    /// document only while it is fresh, and fetches it again (at most
    /// every 30 seconds) when a requested redirect URI is missing from it.
    #[serde(default)]
    pub redirect_uri_policy: RedirectUriPolicy,
}

impl ClientIdMetadataDocumentsConfig {
    /// Whether `url` is a `client_id` this configuration fetches a
    /// document for: an `https://` URL (or `http://` with
    /// `allow_private_network`) whose host `allowed_hosts` admits.
    pub fn admits(&self, url: &str) -> bool {
        client_id_is_url(url, self.allow_private_network)
            && url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|host| host_is_allowed(&host, &self.allowed_hosts))
    }

    /// Whether `allowed_hosts` admits `host`, lower-case: an exact entry
    /// or a subdomain of one.
    pub fn admits_host(&self, host: &str) -> bool {
        host_is_allowed(host, &self.allowed_hosts)
    }
}

/// Whether `client_id` is a Client ID Metadata Document URL: `https://`,
/// or `http://` where private networks are allowed.
pub fn client_id_is_url(client_id: &str, allow_http: bool) -> bool {
    client_id.starts_with("https://") || (allow_http && client_id.starts_with("http://"))
}

/// `host` equals an `allowed` entry or is a subdomain of one, compared
/// case-insensitively — the rule the outbound fetch guard applies.
pub(crate) fn host_is_allowed(host: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        host == entry || host.ends_with(&format!(".{entry}"))
    })
}

/// One enterprise IdP trusted to issue ID-JAGs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedIdpConfig {
    /// The IdP's issuer identifier, compared exactly (a trailing `/`
    /// included) against the ID-JAG `iss` claim and against the `issuer`
    /// of the IdP's discovery document. Okta's org authorization server
    /// issues ID-JAGs as `https://{yourOktaDomain}`, without a trailing
    /// `/`.
    pub issuer: String,
    /// JWKS endpoint override. When neither this nor `jwks` is set, the
    /// JWKS URI is taken from the IdP's OIDC discovery document
    /// (`{issuer}/.well-known/openid-configuration`) or, when the IdP
    /// serves none, from its RFC 8414 metadata
    /// (`/.well-known/oauth-authorization-server`); the document's
    /// `issuer` must equal `issuer`. Fetched keys are reused for 5
    /// minutes; while the IdP cannot be reached or answers with a server
    /// error, a timeout or a rate limit, the last key set that was fetched
    /// keeps verifying for up to an hour, after which redemption answers
    /// `temporarily_unavailable`. Any other client error is a
    /// configuration problem, which redemption names (`invalid_grant`).
    /// Redirects and responses above 1 MiB are refused.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// The IdP's JSON Web Key Set (RFC 7517), inline: an object with a
    /// `keys` array, or the same document as a JSON string (for example
    /// `${env.IDP_JWKS}`). For an IdP the gateway cannot reach: no
    /// discovery or JWKS request is made, and a key rotation at the IdP
    /// needs a config change. Mutually exclusive with `jwks_uri`.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// Optional host allowlist for discovery/JWKS fetches (exact or
    /// subdomain match). Empty = any public host.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Local-development escape hatch: permit `http://` and
    /// private/loopback IdP addresses, including a host name that
    /// resolves to one. Production deployments leave this `false`.
    #[serde(default)]
    pub allow_private_network: bool,
    /// JWS algorithms accepted on this IdP's ID-JAGs: any of `RS256`,
    /// `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`,
    /// `EdDSA`, and by default all of them. An assertion signed with
    /// another algorithm is refused (`invalid_grant`). HMAC algorithms are
    /// never accepted. List only the IdP's own algorithm to refuse any
    /// other (Okta signs with `RS256`). With `login`, the same list applies
    /// to the ID tokens of sign-in.
    #[serde(default = "default_idp_allowed_algs")]
    pub allowed_algs: Vec<String>,
    /// The clients this IdP may issue ID-JAGs for, and with `login` the
    /// clients whose users may sign in through it: `clients[].client_id`
    /// values, or metadata document URLs that
    /// `client_id_metadata_documents.allowed_hosts` admits. An assertion
    /// from this IdP presented by another client is refused
    /// (`invalid_grant`). A dynamically registered client never satisfies
    /// a non-empty list. Empty = every client.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// For a multi-tenant IdP: the `tenant` claim every ID-JAG (and, with
    /// `login`, every ID token) from it
    /// must carry, compared exactly. An assertion without it or with
    /// another value is refused (`invalid_grant`). Unset, a `tenant` claim
    /// is accepted as it comes and joins the principal namespace, since a
    /// multi-tenant IdP's `sub` is unique only within a tenant: the caller
    /// is reported with `identity.issuer` set to `{issuer}#{tenant}`
    /// (unless `principal_issuer` is set).
    #[serde(default)]
    pub required_tenant: Option<String>,
    /// Which ID-JAG claims (and, with `login`, ID token claims) name the
    /// user and become their groups, roles
    /// and attributes. The mapped values travel in the minted access
    /// token, so `identity.groups`, `identity.roles` and
    /// `identity.attributes` in `governance.policy` see them on every MCP
    /// request made with it. Okta's published ID-JAGs carry no group
    /// claim, so there is nothing to map groups from; policy can match
    /// Okta callers on `identity.attributes['client_id']`, and on
    /// `['email']` when the ID-JAG carries one.
    #[serde(default)]
    pub claim_mappings: TrustedIdpClaimMappingConfig,
    /// Make this IdP's users the same principals as the SSO users of the
    /// OIDC provider with this issuer (`governance.access.oidc_oauth` or
    /// the `dev.mcpg.identity.oidc` plugin), such as the Okta custom
    /// authorization server that signs the enterprise's SSO access
    /// tokens. An EMA caller is then reported with `identity.issuer` set
    /// to this value and `identity.auth_provider` set to
    /// `oidc_oauth:<this value>`, exactly as that provider reports its own
    /// users, so sessions, tasks, idempotency and quotas are shared
    /// between the two ways in, provided both name the user with the same
    /// subject (see `claim_mappings.subject_claim`, and the provider's own
    /// `subject_claim`; for Okta, `uid` there and the default `sub` here).
    /// Tell EMA callers apart by `identity.attributes['token_issuer']`.
    /// Unset: principals are namespaced by this IdP's `issuer`, with
    /// `auth_provider` `ema`. No two IdPs may share a value.
    #[serde(default)]
    pub principal_issuer: Option<String>,
    /// The gateway's OIDC client at this IdP, which turns on interactive
    /// sign-in through it (at most one entry). Its users are the same
    /// principals as this IdP's ID-JAG users, and the IdP keeps accepting
    /// ID-JAGs.
    #[serde(default)]
    pub login: Option<TrustedIdpLoginConfig>,
}

/// Claim mapping of one trusted IdP's ID-JAGs
/// (`trusted_idps[].claim_mappings`): the `oidc_oauth` `claim_mappings`
/// shape without `scope_claim_paths`, because a minted token's scopes are
/// the ones the grant allows. Paths are dotted (`realm_access.roles`); a
/// list claim is an array of strings or a space-separated string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedIdpClaimMappingConfig {
    /// The string claim that identifies the user: the minted token's
    /// `sub` and the principal's subject. An ID-JAG without it is refused
    /// (`invalid_grant`). `act` (the actor, never the user) and claims
    /// that identify no user (`client_id`, `iss`, `aud`, `jti`) are
    /// refused. A claim other than `sub`, such as `email`, can be
    /// reassigned to another person by the IdP.
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    /// Claims whose values become `identity.groups`, in order, without
    /// duplicates.
    #[serde(default)]
    pub group_claim_paths: Vec<String>,
    /// Claims whose values become `identity.roles`, before any
    /// `client_roles` of the client.
    #[serde(default)]
    pub role_claim_paths: Vec<String>,
    /// String claims copied into `identity.attributes`, as
    /// `{claim path: attribute name}`, for example `{acr: acr}`. The
    /// attributes the gateway sets itself (`client_id`, `idp`,
    /// `token_issuer`, `email`, `actor`, `tenant`, `amr`, the
    /// `grant_type`, `grant_id` and `auth_time` of interactive sign-in,
    /// `dpop_jkt` of a token presented with a DPoP proof,
    /// `authorization_details` and `authorization_details_types` of a token
    /// limited to authorization details, and every name starting with
    /// `subject_token`, which it reserves for a credential issuer) cannot
    /// be mapped to.
    #[serde(default)]
    pub attribute_claim_mappings: BTreeMap<String, String>,
}

impl Default for TrustedIdpClaimMappingConfig {
    fn default() -> Self {
        Self {
            subject_claim: default_subject_claim(),
            group_claim_paths: Vec::new(),
            role_claim_paths: Vec::new(),
            attribute_claim_mappings: BTreeMap::new(),
        }
    }
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}

/// Claims that never identify a user, so a subject read from one would
/// make every user it carries one principal.
const NON_USER_CLAIMS: [&str; 4] = ["client_id", "iss", "aud", "jti"];

impl TrustedIdpClaimMappingConfig {
    fn validate(&self, at: &str) -> Result<()> {
        let at = format!("{at}.claim_mappings");
        let subject = self.subject_claim.as_str();
        if subject.trim().is_empty() {
            return Err(anyhow::anyhow!("{at}.subject_claim must not be empty"));
        }
        if subject == "act" || subject.starts_with("act.") {
            return Err(anyhow::anyhow!(
                "{at}.subject_claim `{subject}` names the actor, who acts for the user and is \
                 never the user: keep the subject in the user's claim and read the actor from \
                 identity.attributes['actor']"
            ));
        }
        if NON_USER_CLAIMS.contains(&subject) {
            return Err(anyhow::anyhow!(
                "{at}.subject_claim `{subject}` identifies no user: every user whose ID-JAG \
                 carries the same value would be one principal"
            ));
        }
        for path in self.group_claim_paths.iter().chain(&self.role_claim_paths) {
            if path.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{at}.group_claim_paths and role_claim_paths must not list an empty path"
                ));
            }
        }
        for (claim, attribute) in &self.attribute_claim_mappings {
            if claim.trim().is_empty() || attribute.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{at}.attribute_claim_mappings must not map from or to an empty name"
                ));
            }
            if crate::runtime::authorization_server::IDENTITY_ATTRIBUTES
                .contains(&attribute.as_str())
            {
                return Err(anyhow::anyhow!(
                    "{at}.attribute_claim_mappings maps `{claim}` to `{attribute}`, an attribute \
                     the gateway sets itself on the callers of the access tokens it issues; \
                     choose another attribute name"
                ));
            }
            if crate::runtime::federation::engine::ISSUER_SUBJECT_ATTRIBUTES
                .contains(&attribute.as_str())
                || attribute.starts_with(super::interactive_login::SUBJECT_TOKEN_ATTRIBUTE_PREFIX)
            {
                return Err(anyhow::anyhow!(
                    "{at}.attribute_claim_mappings maps `{claim}` to `{attribute}`, an attribute \
                     the gateway sets itself on the caller it hands a credential issuer; choose \
                     another attribute name"
                ));
            }
        }
        Ok(())
    }
}

impl TrustedIdpConfig {
    /// The inline `jwks`, parsed. `Ok(None)` when it is unset.
    pub fn inline_jwks(&self) -> Result<Option<jsonwebtoken::jwk::JwkSet>> {
        self.jwks.as_ref().map(parse_public_jwks).transpose()
    }
}

/// A JSON Web Key Set of public keys, given as an object with a `keys`
/// array or as that document in a JSON string. Every key must load, and a
/// symmetric (`oct`) key is refused: these keys verify signatures others
/// make, so a shared secret here would let anyone who reads it sign.
pub fn parse_public_jwks(value: &serde_json::Value) -> Result<jsonwebtoken::jwk::JwkSet> {
    let keys: jsonwebtoken::jwk::JwkSet = match value {
        serde_json::Value::String(text) => serde_json::from_str(text),
        other => serde_json::from_value(other.clone()),
    }
    .map_err(|e| anyhow::anyhow!("is not a JSON Web Key Set: {e}"))?;
    if keys.keys.is_empty() {
        return Err(anyhow::anyhow!("has no keys"));
    }
    for key in &keys.keys {
        if matches!(
            key.algorithm,
            jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_)
        ) {
            return Err(anyhow::anyhow!(
                "holds a symmetric (`oct`) key; only public keys are accepted"
            ));
        }
        jsonwebtoken::DecodingKey::from_jwk(key).map_err(|e| {
            anyhow::anyhow!(
                "key {} is unusable: {e}",
                key.common.key_id.as_deref().unwrap_or("without kid")
            )
        })?;
    }
    Ok(keys)
}

/// One OAuth client registered with the embedded authorization server.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerClientConfig {
    /// The client identifier the enterprise IdP binds into ID-JAGs
    /// (`client_id` claim). For an MCP client that identifies with a
    /// Client ID Metadata Document, the document URL: this entry then
    /// stands in for the document, which is never fetched.
    pub client_id: String,
    /// Shared secret for `client_secret_basic` / `client_secret_post`.
    /// Supply via `${env.X}` or `${secret.NAME}`.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// How the client authenticates at the token endpoint:
    /// `client_secret_basic` (HTTP Basic), `client_secret_post`
    /// (`client_id` and `client_secret` form fields), `private_key_jwt`
    /// (a signed `client_assertion`, RFC 7523) or `none` (a public
    /// client). Defaults to both secret methods when `client_secret` is
    /// set, to `private_key_jwt` when `jwks` or `jwks_uri` is set, else to
    /// `none`. A request that authenticates any other way is refused
    /// (`invalid_client`). A `private_key_jwt` assertion carries `iss` and
    /// `sub` equal to the `client_id`, `aud` equal to the issuer, an `exp`
    /// at most 5 minutes ahead and a `jti` that is accepted once; it is
    /// signed with `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
    /// `ES256`, `ES384` or `EdDSA`.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<ClientAuthMethod>,
    /// `private_key_jwt`: URL of the client's JSON Web Key Set. Fetched
    /// keys are reused for 5 minutes and refetched on an unknown `kid` at
    /// most every 30 seconds; `https://` only, no redirects, at most
    /// 1 MiB. Mutually exclusive with `jwks`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// `private_key_jwt`: the client's public keys inline, as an object
    /// with a `keys` array or the same document as a JSON string (for
    /// example `${env.CLIENT_JWKS}`).
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// `private_key_jwt`: also accept an assertion whose `aud` is the
    /// token endpoint URL (`{issuer}/oauth/token`), as clients written
    /// for Okta send it. Otherwise `aud` must be the issuer exactly, its
    /// only value.
    #[serde(default)]
    pub accept_token_endpoint_audience: bool,
    /// Local-development escape hatch for `jwks_uri`: permit `http://`
    /// and private/loopback addresses. Production deployments leave this
    /// `false`.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Interactive sign-in: where authorization responses may be sent (at
    /// most 10, each once). `https://` URIs match byte for byte (case,
    /// port, trailing `/` and percent-encoding included). `http://` only
    /// on `127.0.0.1`, `[::1]` or `localhost`, written so, where any port
    /// matches (RFC 8252 §7.3): a native client picks its port at run
    /// time, so register it without one. A loopback URI's path and query
    /// are compared as written, so they may not hold dot segments or
    /// characters a browser rewrites. ASCII only, with no fragment,
    /// userinfo, wildcard, backslash or private-use scheme. A client with
    /// one URI that is not loopback may omit `redirect_uri` in its request.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// The grants this client may use:
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer` (ID-JAG redemption),
    /// `authorization_code` (interactive sign-in, which needs
    /// `redirect_uris` and a `trusted_idps[].login` block) and
    /// `refresh_token` (which needs `authorization_code`). Defaults to
    /// jwt-bearer alone without `redirect_uris`, and to
    /// `[authorization_code, refresh_token]` with them.
    #[serde(default)]
    pub grant_types: Option<Vec<ClientGrantType>>,
    /// The client's name on the consent page (1–80 characters). Defaults
    /// to the `client_id`.
    #[serde(default)]
    pub client_name: Option<String>,
    /// When the consent page is shown before sign-in: `auto` (the
    /// default) skips it when every redirect URI is `https://` and asks
    /// otherwise; `always` asks every time; `skip` never asks and is
    /// refused with a loopback redirect URI. A request with
    /// `prompt=consent` always asks.
    #[serde(default)]
    pub consent: ClientConsent,
    /// RFC 9449 §5.2: every token request of this client must carry a
    /// DPoP proof, and every token it receives is bound to the proof's
    /// key. A request without one is refused. Requires `dpop.enabled`.
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
}

impl std::fmt::Debug for AuthorizationServerClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationServerClientConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("jwks_uri", &self.jwks_uri)
            .field("jwks", &self.jwks.is_some())
            .field(
                "accept_token_endpoint_audience",
                &self.accept_token_endpoint_audience,
            )
            .field("allow_private_network", &self.allow_private_network)
            .field("redirect_uris", &self.redirect_uris)
            .field("grant_types", &self.grant_types)
            .field("client_name", &self.client_name)
            .field("consent", &self.consent)
            .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
            .finish()
    }
}

impl AuthorizationServerClientConfig {
    /// `grant_types`, or the default its `redirect_uris` imply.
    pub fn effective_grant_types(&self) -> Vec<ClientGrantType> {
        match self.grant_types {
            Some(ref grants) => grants.clone(),
            None if self.redirect_uris.is_empty() => vec![ClientGrantType::JwtBearer],
            None => vec![
                ClientGrantType::AuthorizationCode,
                ClientGrantType::RefreshToken,
            ],
        }
    }

    /// Whether this client may use `grant`.
    pub fn allows_grant(&self, grant: ClientGrantType) -> bool {
        self.effective_grant_types().contains(&grant)
    }

    /// `token_endpoint_auth_method`, or the method the configured
    /// material implies. `None` when a secret and keys are both set and
    /// no method picks between them.
    pub fn effective_auth_methods(&self) -> Option<&'static [ClientAuthMethod]> {
        const BASIC: ClientAuthMethod = ClientAuthMethod::ClientSecretBasic;
        const POST: ClientAuthMethod = ClientAuthMethod::ClientSecretPost;
        const KEY: ClientAuthMethod = ClientAuthMethod::PrivateKeyJwt;
        const PUBLIC: ClientAuthMethod = ClientAuthMethod::None;
        let has_secret = self.client_secret.is_some();
        let has_keys = self.jwks.is_some() || self.jwks_uri.is_some();
        match (self.token_endpoint_auth_method, has_secret, has_keys) {
            (Some(BASIC), _, _) => Some(&[BASIC]),
            (Some(POST), _, _) => Some(&[POST]),
            (Some(KEY), _, _) => Some(&[KEY]),
            (Some(PUBLIC), _, _) => Some(&[PUBLIC]),
            (None, true, false) => Some(&[BASIC, POST]),
            (None, false, true) => Some(&[KEY]),
            (None, false, false) => Some(&[PUBLIC]),
            (None, true, true) => None,
        }
    }
}

/// A token endpoint client authentication method (RFC 7591 §2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    None,
}

impl ClientAuthMethod {
    /// The registered name, as metadata documents spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthMethod::ClientSecretBasic => "client_secret_basic",
            ClientAuthMethod::ClientSecretPost => "client_secret_post",
            ClientAuthMethod::PrivateKeyJwt => "private_key_jwt",
            ClientAuthMethod::None => "none",
        }
    }
}

/// One key of `authorization_server.signing_keys`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Key identifier, stamped as the `kid` header of the tokens this key
    /// signs and published with its public key. Defaults to the RFC 7638
    /// thumbprint of an asymmetric key, and to an identifier derived from
    /// the secret of an HS256 key (the same one `signing_secret` uses).
    #[serde(default)]
    pub kid: Option<String>,
    /// JWS algorithm: `HS256` (shared secret), `ES256` (P-256), `EdDSA`
    /// (Ed25519) or `RS256` (RSA, at least 2048 bits).
    pub alg: SigningAlgorithm,
    /// HS256 only: the shared secret, at least 32 bytes. Supply via
    /// `${env.X}` or `${secret.NAME}`.
    #[serde(default)]
    pub secret: Option<String>,
    /// `ES256`, `EdDSA` and `RS256`: the PEM-encoded private key, PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`, as `openssl genpkey` writes it; an
    /// RSA key may also be PKCS#1). Supply via `${secret.NAME}`, which
    /// reads the file verbatim, or `${env.X}`.
    #[serde(default)]
    pub private_key: Option<String>,
}

impl std::fmt::Debug for SigningKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyConfig")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// JWS algorithm of an access-token signing key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub enum SigningAlgorithm {
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "RS256")]
    Rs256,
}

impl SigningAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            SigningAlgorithm::Hs256 => "HS256",
            SigningAlgorithm::Es256 => "ES256",
            SigningAlgorithm::EdDsa => "EdDSA",
            SigningAlgorithm::Rs256 => "RS256",
        }
    }
}

fn default_access_token_ttl_secs() -> u64 {
    3600
}

fn default_clock_skew_secs() -> u64 {
    60
}

fn default_max_assertion_lifetime_secs() -> u64 {
    600
}

fn default_enforce_single_use() -> bool {
    true
}

fn default_token_rate_limit_per_min() -> u32 {
    120
}

fn default_idp_allowed_algs() -> Vec<String> {
    [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Largest `authorization_server.clock_skew_secs`.
const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Largest `authorization_server.access_token_ttl_secs`.
const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 86_400;
/// `authorization_server.access_token_ttl_secs` above which boot and
/// `mcpg config check` warn.
pub const ACCESS_TOKEN_TTL_WARN_SECS: u64 = 3_600;
/// Largest `authorization_server.max_assertion_lifetime_secs`.
const MAX_ASSERTION_LIFETIME_SECS: u64 = 3_600;

/// Why `issuer` is not an origin, `scheme://host[:port]` with at most a
/// trailing `/`, if it is not. Expects the `http(s)://` prefix to be
/// checked already.
fn issuer_origin_problem(issuer: &str) -> Option<String> {
    let (scheme, authority) = issuer
        .strip_prefix("https://")
        .map(|rest| ("https://", rest))
        .or_else(|| issuer.strip_prefix("http://").map(|rest| ("http://", rest)))?;
    // Checked first so no message below echoes a credential.
    if authority.split('/').next().is_some_and(|a| a.contains('@')) {
        return Some("must not carry userinfo".to_owned());
    }
    let (host, path) = authority.split_once('/').unwrap_or((authority, ""));
    if !path.is_empty() {
        return Some(format!(
            "must be a bare origin, scheme://host[:port], without a path: the gateway serves \
             /.well-known/oauth-authorization-server and /oauth/token only at the root of its \
             origin, so clients cannot discover an issuer with a path (RFC 8414 §3). Set it to \
             `{scheme}{host}`"
        ));
    }
    if host.is_empty() || host.starts_with(':') {
        return Some("has no host".to_owned());
    }
    None
}

/// Whether `issuer` is `http://` on a loopback host (`localhost`, or a
/// loopback address).
fn issuer_is_loopback_http(issuer: &str) -> bool {
    url::Url::parse(issuer).is_ok_and(|parsed| {
        parsed.scheme() == "http"
            && parsed.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
            })
    })
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
        if let Some(problem) = issuer_origin_problem(&self.issuer) {
            return Err(anyhow::anyhow!("{prefix}.issuer {problem}"));
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
        self.validate_signing_keys()?;
        if self.access_token_ttl_secs == 0 || self.access_token_ttl_secs > MAX_ACCESS_TOKEN_TTL_SECS
        {
            return Err(anyhow::anyhow!(
                "{prefix}.access_token_ttl_secs must be between 1 and {MAX_ACCESS_TOKEN_TTL_SECS}: \
                 a minted token cannot be revoked, so it stays valid that long after the IdP \
                 revokes the user"
            ));
        }
        if self.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(anyhow::anyhow!(
                "{prefix}.clock_skew_secs must be at most {MAX_CLOCK_SKEW_SECS}"
            ));
        }
        if self.max_assertion_lifetime_secs == 0
            || self.max_assertion_lifetime_secs > MAX_ASSERTION_LIFETIME_SECS
        {
            return Err(anyhow::anyhow!(
                "{prefix}.max_assertion_lifetime_secs must be between 1 and \
                 {MAX_ASSERTION_LIFETIME_SECS}"
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
            // Issuers compare exactly, but two entries differing only by a
            // trailing `/` are one IdP listed twice.
            if !idp_issuers.insert(idp.issuer.trim_end_matches('/')) {
                return Err(anyhow::anyhow!(
                    "{prefix}.trusted_idps lists issuer `{}` more than once",
                    idp.issuer
                ));
            }
            let at = format!("{prefix}.trusted_idps[`{}`]", idp.issuer);
            if idp.jwks.is_some() && idp.jwks_uri.is_some() {
                return Err(anyhow::anyhow!(
                    "{at}: set either jwks (inline keys) or jwks_uri, not both"
                ));
            }
            match idp.jwks {
                Some(serde_json::Value::String(ref text)) if is_unresolved_placeholder(text) => {}
                Some(_) => {
                    idp.inline_jwks()
                        .map_err(|e| anyhow::anyhow!("{at}.jwks {e}"))?;
                }
                None => {
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
            }
            if idp.allowed_algs.is_empty() {
                return Err(anyhow::anyhow!(
                    "{at}.allowed_algs must list at least one algorithm"
                ));
            }
            for alg in &idp.allowed_algs {
                let parsed = mcpg_plugin_identity_oidc_core::parse_algorithm(alg)
                    .map_err(|e| anyhow::anyhow!("{at}.allowed_algs: {e}"))?;
                if matches!(
                    parsed,
                    jsonwebtoken::Algorithm::HS256
                        | jsonwebtoken::Algorithm::HS384
                        | jsonwebtoken::Algorithm::HS512
                ) {
                    return Err(anyhow::anyhow!(
                        "{at}.allowed_algs lists `{alg}`: ID-JAGs are verified against the \
                         IdP's public keys, so HMAC algorithms are never accepted"
                    ));
                }
            }
            for client_id in &idp.allowed_clients {
                if !self.knows_client(client_id) {
                    return Err(anyhow::anyhow!(
                        "{at}.allowed_clients names `{client_id}`, which is neither a registered \
                         {prefix}.clients[].client_id nor a metadata document URL that \
                         {prefix}.client_id_metadata_documents.allowed_hosts admits"
                    ));
                }
            }
            if let Some(ref tenant) = idp.required_tenant
                && tenant.trim().is_empty()
            {
                return Err(anyhow::anyhow!(
                    "{at}.required_tenant must not be empty when set"
                ));
            }
            idp.claim_mappings.validate(&at)?;
            if let Some(ref principal) = idp.principal_issuer {
                if principal.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "{at}.principal_issuer must not be empty when set"
                    ));
                }
                if !principal.starts_with("https://") && !principal.starts_with("http://") {
                    return Err(anyhow::anyhow!(
                        "{at}.principal_issuer must be the http(s) issuer URL of the OIDC \
                         provider that signs these users' SSO tokens"
                    ));
                }
            }
        }
        let mut principal_issuers = std::collections::BTreeSet::new();
        for principal in self
            .trusted_idps
            .iter()
            .filter_map(|idp| idp.principal_issuer.as_deref())
        {
            if !principal_issuers.insert(principal) {
                return Err(anyhow::anyhow!(
                    "{prefix}.trusted_idps: more than one IdP sets principal_issuer `{principal}`; \
                     their users would share one principal namespace, so two people with the \
                     same subject at different IdPs would be one principal"
                ));
            }
        }
        self.validate_interactive_login()?;
        self.dpop.validate(&format!("{prefix}.dpop"))?;
        self.authorization_details
            .validate(&format!("{prefix}.authorization_details"))?;
        self.validate_clients()?;
        self.validate_client_roles()
    }

    /// The login blocks, the `interactive` block, and the issuer a browser
    /// sign-in needs.
    fn validate_interactive_login(&self) -> Result<()> {
        let prefix = "governance.access.authorization_server";
        let logins: Vec<&TrustedIdpConfig> = self
            .trusted_idps
            .iter()
            .filter(|idp| idp.login.is_some())
            .collect();
        if logins.len() > 1 {
            return Err(anyhow::anyhow!(
                "{prefix}.trusted_idps: {} entries have a login block ({}); interactive sign-in \
                 goes through one IdP, and an IdP chooser is not supported yet",
                logins.len(),
                logins
                    .iter()
                    .map(|idp| idp.issuer.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let Some(idp) = logins.first() else {
            if self.interactive.is_some() {
                return Err(anyhow::anyhow!(
                    "{prefix}.interactive configures interactive sign-in, which no IdP offers: add \
                     a login block to the {prefix}.trusted_idps entry users sign in with, or \
                     remove interactive"
                ));
            }
            return Ok(());
        };
        if let Some(ref login) = idp.login {
            login.validate(
                &format!("{prefix}.trusted_idps[`{}`].login", idp.issuer),
                idp,
            )?;
        }
        if !self.issuer.starts_with("https://") && !issuer_is_loopback_http(&self.issuer) {
            return Err(anyhow::anyhow!(
                "{prefix}.issuer must be https:// with interactive sign-in: browsers carry \
                 authorization codes and sign-in cookies to it, and the cookies need a secure \
                 origin. http:// is accepted only on a loopback host, for development"
            ));
        }
        if let Some(ref interactive) = self.interactive {
            interactive.validate(&format!("{prefix}.interactive"))?;
        }
        Ok(())
    }

    /// Every `client_roles` key names a client that can authenticate, and
    /// no role is blank.
    fn validate_client_roles(&self) -> Result<()> {
        let prefix = "governance.access.authorization_server";
        for (client_id, roles) in &self.client_roles {
            if !self.knows_client(client_id) {
                return Err(anyhow::anyhow!(
                    "{prefix}.client_roles names `{client_id}`, which is neither a registered \
                     {prefix}.clients[].client_id nor a metadata document URL that \
                     {prefix}.client_id_metadata_documents.allowed_hosts admits"
                ));
            }
            if roles.iter().any(|role| role.trim().is_empty()) {
                return Err(anyhow::anyhow!(
                    "{prefix}.client_roles[`{client_id}`] must not list an empty role"
                ));
            }
        }
        Ok(())
    }

    /// Whether Client ID Metadata Documents are on: as configured, else
    /// whenever a registered `client_id` is an `https://` URL or
    /// `allowed_hosts` admits unregistered ones.
    pub fn client_id_metadata_documents_enabled(&self) -> bool {
        let documents = &self.client_id_metadata_documents;
        documents.enabled.unwrap_or_else(|| {
            !documents.allowed_hosts.is_empty()
                || self
                    .clients
                    .iter()
                    .any(|client| client.client_id.starts_with("https://"))
        })
    }

    /// Whether `client_id` can authenticate here: a registered client, or
    /// a metadata document URL on `client_id_metadata_documents.allowed_hosts`.
    pub fn knows_client(&self, client_id: &str) -> bool {
        self.clients.iter().any(|c| c.client_id == client_id)
            || (self.client_id_metadata_documents_enabled()
                && self.client_id_metadata_documents.admits(client_id))
    }

    /// Every client carries the material its authentication method needs,
    /// and nothing another method would silently ignore.
    fn validate_clients(&self) -> Result<()> {
        let prefix = "governance.access.authorization_server";
        let documents = &self.client_id_metadata_documents;
        if documents.enabled == Some(false) && !documents.allowed_hosts.is_empty() {
            return Err(anyhow::anyhow!(
                "{prefix}.client_id_metadata_documents.allowed_hosts has no effect while enabled \
                 is false: remove it, or set enabled: true"
            ));
        }
        for host in &documents.allowed_hosts {
            if host.trim().is_empty()
                || host.contains(['/', '@', ':'])
                || host.chars().any(char::is_whitespace)
            {
                return Err(anyhow::anyhow!(
                    "{prefix}.client_id_metadata_documents.allowed_hosts entry `{host}` must be a \
                     bare host name, such as `claude.ai`"
                ));
            }
        }
        let documents_admit_clients =
            self.client_id_metadata_documents_enabled() && !documents.allowed_hosts.is_empty();
        let has_login = self.login_idp().is_some();
        let registration_admits_clients = has_login
            && self
                .interactive_settings()
                .dynamic_client_registration
                .enabled;
        if self.clients.is_empty() && !documents_admit_clients && !registration_admits_clients {
            return Err(anyhow::anyhow!(
                "{prefix}.clients must register at least one OAuth client, or \
                 {prefix}.client_id_metadata_documents.allowed_hosts must admit clients by their \
                 metadata document"
            ));
        }
        let mut client_ids = std::collections::BTreeSet::new();
        for client in &self.clients {
            if client.client_id.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{prefix}.clients[].client_id must not be empty"
                ));
            }
            if client
                .client_id
                .starts_with(super::interactive_login::DCR_CLIENT_ID_PREFIX)
            {
                return Err(anyhow::anyhow!(
                    "{prefix}.clients[`{}`].client_id starts with `{}`, which names dynamically \
                     registered clients; choose another client_id",
                    client.client_id,
                    super::interactive_login::DCR_CLIENT_ID_PREFIX
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
            let at = format!("{prefix}.clients[`{}`]", client.client_id);
            if client.dpop_bound_access_tokens && !self.dpop.enabled {
                return Err(anyhow::anyhow!(
                    "{at}.dpop_bound_access_tokens needs {prefix}.dpop.enabled: true; no token can \
                     be bound while DPoP is off"
                ));
            }
            validate_client_authentication(&at, client)?;
            super::interactive_login::validate_client_interactive_keys(&at, client, has_login)?;
        }
        Ok(())
    }

    /// Exactly one of `signing_secret` and `signing_keys` is set, each key
    /// carries the material its algorithm needs, and every key whose
    /// material is resolved loads.
    fn validate_signing_keys(&self) -> Result<()> {
        let prefix = "governance.access.authorization_server";
        match (&self.signing_secret, self.signing_keys.is_empty()) {
            (Some(_), false) => {
                return Err(anyhow::anyhow!(
                    "{prefix}: set signing_secret or signing_keys, not both. To rotate away from \
                     signing_secret without invalidating the tokens it signed, move it into \
                     signing_keys as `{{alg: HS256, secret: …}}` without a kid, after the new key"
                ));
            }
            (None, true) => {
                return Err(anyhow::anyhow!(
                    "{prefix} needs a key to sign access tokens: set signing_keys, or \
                     signing_secret for a single HS256 secret"
                ));
            }
            _ => {}
        }
        if let Some(ref secret) = self.signing_secret {
            check_hmac_secret(&format!("{prefix}.signing_secret"), secret)?;
        }
        let mut kids = std::collections::BTreeSet::new();
        for (index, key) in self.signing_keys.iter().enumerate() {
            let at = format!("{prefix}.signing_keys[{index}]");
            if let Some(ref kid) = key.kid {
                if kid.trim().is_empty() {
                    return Err(anyhow::anyhow!("{at}.kid must not be empty when set"));
                }
                if !kids.insert(kid.as_str()) {
                    return Err(anyhow::anyhow!(
                        "{prefix}.signing_keys lists kid `{kid}` more than once"
                    ));
                }
            }
            match (key.alg, &key.secret, &key.private_key) {
                (SigningAlgorithm::Hs256, Some(secret), None) => {
                    check_hmac_secret(&format!("{at}.secret"), secret)?;
                }
                (SigningAlgorithm::Hs256, _, _) => {
                    return Err(anyhow::anyhow!(
                        "{at}: an HS256 key takes `secret`, and no `private_key`"
                    ));
                }
                (_, None, Some(_)) => {}
                (alg, _, _) => {
                    return Err(anyhow::anyhow!(
                        "{at}: an {} key takes `private_key`, and no `secret`",
                        alg.as_str()
                    ));
                }
            }
        }
        let mut material = self.signing_secret.iter().chain(
            self.signing_keys
                .iter()
                .flat_map(|key| key.secret.iter().chain(key.private_key.iter())),
        );
        if material.all(|value| !is_unresolved_placeholder(value)) {
            crate::runtime::authorization_server::load_signing_keys(self)?;
        }
        Ok(())
    }
}

/// The client authentication of one `clients[]` entry, at `at`.
fn validate_client_authentication(
    at: &str,
    client: &AuthorizationServerClientConfig,
) -> Result<()> {
    let Some(methods) = client.effective_auth_methods() else {
        return Err(anyhow::anyhow!(
            "{at}: client_secret and jwks/jwks_uri are both set; set token_endpoint_auth_method \
             to say which one the client authenticates with"
        ));
    };
    let has_keys = client.jwks.is_some() || client.jwks_uri.is_some();
    let method = methods[0];
    match method {
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            if client.client_secret.is_none() {
                return Err(anyhow::anyhow!(
                    "{at}: token_endpoint_auth_method {} needs a client_secret",
                    method.as_str()
                ));
            }
            if has_keys {
                return Err(anyhow::anyhow!(
                    "{at}: jwks and jwks_uri authenticate private_key_jwt clients only"
                ));
            }
        }
        ClientAuthMethod::PrivateKeyJwt => {
            if client.client_secret.is_some() {
                return Err(anyhow::anyhow!(
                    "{at}: a private_key_jwt client takes no client_secret"
                ));
            }
            match (&client.jwks, &client.jwks_uri) {
                (Some(_), Some(_)) => {
                    return Err(anyhow::anyhow!("{at}: set jwks or jwks_uri, not both"));
                }
                (None, None) => {
                    return Err(anyhow::anyhow!(
                        "{at}: private_key_jwt needs the client's public keys: set jwks or \
                         jwks_uri"
                    ));
                }
                (Some(serde_json::Value::String(text)), None)
                    if is_unresolved_placeholder(text) => {}
                (Some(jwks), None) => {
                    parse_public_jwks(jwks).map_err(|e| anyhow::anyhow!("{at}.jwks {e}"))?;
                }
                (None, Some(uri)) => {
                    mcpg_plugin_identity_oidc_core::resolver::enforce_discovery_url_safety(
                        uri,
                        &[],
                        client.allow_private_network,
                    )
                    .map_err(|e| anyhow::anyhow!("{at}.jwks_uri: {e}"))?;
                }
            }
        }
        ClientAuthMethod::None => {
            if client.client_secret.is_some() {
                return Err(anyhow::anyhow!(
                    "{at}: a public client (token_endpoint_auth_method none) takes no \
                     client_secret"
                ));
            }
            if has_keys {
                return Err(anyhow::anyhow!(
                    "{at}: jwks and jwks_uri authenticate private_key_jwt clients only"
                ));
            }
        }
    }
    if client.accept_token_endpoint_audience && method != ClientAuthMethod::PrivateKeyJwt {
        return Err(anyhow::anyhow!(
            "{at}.accept_token_endpoint_audience applies to private_key_jwt clients only"
        ));
    }
    Ok(())
}

/// 32 bytes is the HS256 floor: RFC 7518 §3.2 requires a key at least as
/// large as the hash output.
fn check_hmac_secret(field: &str, secret: &str) -> Result<()> {
    if !is_unresolved_placeholder(secret) && secret.len() < 32 {
        return Err(anyhow::anyhow!(
            "{field} must be at least 32 bytes for HS256"
        ));
    }
    Ok(())
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
    /// Further resource identifiers this gateway is reached at — one per
    /// extra hostname (a custom domain in front of the same instance). A
    /// client compares the published `resource` with the URL it connected
    /// to (RFC 9728 §3.3), so the metadata document and the
    /// `WWW-Authenticate` challenge name whichever of `resource` and these
    /// matches the request's `Host`; a request for an unlisted host gets
    /// the canonical `resource`. Each entry is validated like `resource`.
    #[serde(default)]
    pub additional_resources: Vec<String>,
    /// Authorization server issuer URLs published in the metadata. When
    /// empty, derived from the configured verifiers: the
    /// `authorization_server` issuer first, then the `oidc_oauth`
    /// provider issuers, then `jwks.issuer`; with interactive sign-in (a
    /// `trusted_idps[].login` entry) the `authorization_server` issuer
    /// alone, since a client signs in at the first one listed. An
    /// explicit list is published as written, so with
    /// `authorization_server` it must name that issuer exactly as
    /// configured there, a trailing `/` included, or EMA clients cannot
    /// discover it.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Scopes supported by this resource. Also sent as the `scope`
    /// parameter of the `WWW-Authenticate` challenge on an
    /// unauthenticated 401, as the scopes a client requests first; one
    /// that is not an RFC 6749 scope token (a space, `"`, `\`, a control
    /// or non-ASCII character) is left out of the challenge.
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
    Some(host_of_authority(authority))
}

/// The host of a `host[:port]` authority (a URL authority or a request
/// `Host` value), lowercased and without the port. An IPv6 literal keeps
/// its address, without the brackets.
fn host_of_authority(authority: &str) -> String {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let host = rest.split(']').next().unwrap_or(rest);
        return host.to_ascii_lowercase();
    }
    authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

impl OAuthResourceMetadataConfig {
    pub fn validate(&self) -> Result<()> {
        validate_resource_identifier(
            "governance.access.resource_metadata.resource",
            &self.resource,
            self.allow_loopback_resource,
        )?;
        for extra in &self.additional_resources {
            validate_resource_identifier(
                "governance.access.resource_metadata.additional_resources[]",
                extra,
                self.allow_loopback_resource,
            )?;
        }
        Ok(())
    }

    /// Every resource identifier this gateway answers to: the canonical
    /// `resource` first, then `additional_resources`.
    pub fn resources(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.resource.as_str())
            .chain(self.additional_resources.iter().map(String::as_str))
    }

    /// The resource identifier to publish for a request that arrived with
    /// `request_host` (`host[:port]`, as in a `Host` header): the configured
    /// identifier whose host equals it, else the canonical `resource`. Hosts
    /// compare case-insensitively and without ports.
    pub fn resource_for_host(&self, request_host: Option<&str>) -> &str {
        let Some(wanted) = request_host
            .map(host_of_authority)
            .filter(|host| !host.is_empty())
        else {
            return &self.resource;
        };
        self.resources()
            .find(|candidate| resource_host(candidate).as_deref() == Some(wanted.as_str()))
            .unwrap_or(&self.resource)
    }

    /// Build the absolute RFC 9728 well-known metadata URL for this
    /// resource. Per RFC 9728 §3.1 the `/.well-known/oauth-protected-resource`
    /// suffix is inserted between the host and any path/query of the
    /// resource identifier (the path-aware form), after stripping a
    /// terminating slash on the host component.
    pub fn well_known_url(&self) -> String {
        well_known_resource_metadata_url(&self.resource)
    }

    /// [`Self::well_known_url`] for the identifier
    /// [`Self::resource_for_host`] selects.
    pub fn well_known_url_for_host(&self, request_host: Option<&str>) -> String {
        well_known_resource_metadata_url(self.resource_for_host(request_host))
    }
}

/// What every published resource identifier must satisfy: an absolute
/// `http(s)` URL without a fragment (RFC 8707 §2) whose host can be a
/// token audience — never a wildcard, and loopback only by opt-in.
fn validate_resource_identifier(field: &str, resource: &str, allow_loopback: bool) -> Result<()> {
    if resource.trim().is_empty() {
        return Err(anyhow::anyhow!("{field} must not be empty"));
    }
    if !resource.starts_with("https://") && !resource.starts_with("http://") {
        return Err(anyhow::anyhow!(
            "{field} must be a valid absolute URL (http:// or https://)"
        ));
    }
    if resource.contains('#') {
        return Err(anyhow::anyhow!(
            "{field} must not contain a fragment (RFC 8707 §2)"
        ));
    }
    let Some(host) = resource_host(resource) else {
        return Err(anyhow::anyhow!(
            "{field} is not a parseable URL: {resource}"
        ));
    };
    if is_wildcard_host(&host) {
        return Err(anyhow::anyhow!(
            "{field} host `{host}` is a wildcard/unspecified address — it can never be a token \
             audience. Set the canonical external URL the gateway is reached at."
        ));
    }
    if is_loopback_host(&host) && !allow_loopback {
        return Err(anyhow::anyhow!(
            "{field} host `{host}` is loopback; a published PRM resource must be the canonical \
             external URL clients reach. Set the public URL, or for local development opt in \
             with governance.access.resource_metadata.allow_loopback_resource: true"
        ));
    }
    Ok(())
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
            for provider in &oidc.providers {
                for (claim, attribute) in &provider.claim_mappings.attribute_claim_mappings {
                    if let Some(reason) =
                        super::interactive_login::oidc_reserved_attribute(attribute)
                    {
                        return Err(anyhow::anyhow!(
                            "governance.access.oidc_oauth.providers[`{}`].claim_mappings.\
                             attribute_claim_mappings maps `{claim}` to `{attribute}`, {reason}; \
                             choose another attribute name",
                            provider.issuer
                        ));
                    }
                }
            }
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
            if self.resource_metadata.is_none() {
                return Err(anyhow::anyhow!(
                    "governance.access.authorization_server requires \
                     governance.access.resource_metadata: EMA clients discover the embedded \
                     authorization server through the protected resource metadata (RFC 9728). \
                     Set governance.access.resource_metadata.resource to the canonical URL of \
                     the MCP endpoint, e.g. https://mcp.example.com/mcp"
                ));
            }
            if let Some(ref interactive) = authz.interactive {
                let known: &[String] = match (&authz.allowed_scopes, &self.resource_metadata) {
                    (Some(allowed), _) => allowed,
                    (None, Some(rm)) => &rm.scopes_supported,
                    (None, None) => &[],
                };
                for scope in interactive.consent.scope_descriptions.keys() {
                    if !known.contains(scope) {
                        return Err(anyhow::anyhow!(
                            "governance.access.authorization_server.interactive.consent.\
                             scope_descriptions describes `{scope}`, a scope this server never \
                             grants: list it in authorization_server.allowed_scopes (or \
                             resource_metadata.scopes_supported when that is unset), or remove \
                             the description"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// A bearer verifier is configured, so responses carry the RFC 9728
    /// `WWW-Authenticate: Bearer` challenge.
    pub fn is_enabled(&self) -> bool {
        self.jwks.is_some() || self.oidc_oauth.is_some() || self.authorization_server.is_some()
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
    /// Further accepted audiences, alongside `audience` — one per extra
    /// resource identifier the gateway is reached at, so a token bound to
    /// any bound hostname verifies. A token passes when its `aud` names at
    /// least one accepted audience.
    #[serde(default)]
    pub audiences: Vec<String>,
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
            (None, false) if self.audiences.is_empty() => {
                return Err(anyhow::anyhow!(
                    "governance.access.jwks.audience is required (set governance.access.jwks.allow_missing_audience=true only for local development)"
                ));
            }
            _ => {}
        }
        if self.audiences.iter().any(|aud| aud.trim().is_empty()) {
            return Err(anyhow::anyhow!(
                "governance.access.jwks.audiences must not contain an empty entry"
            ));
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
