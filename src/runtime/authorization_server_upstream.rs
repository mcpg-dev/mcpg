//! The gateway's OpenID Connect client at the login IdP
//! (`trusted_idps[].login`): the IdP's endpoints, configured or read from
//! its discovery document; the requests the gateway makes to its token
//! and revocation endpoints; and the checks an ID token passes before a
//! sign-in is believed (OpenID Connect Core §3.1.3.7 and §12.2).
//!
//! Every request to a token or revocation endpoint resolves the host
//! first, refuses a private address unless `allow_private_network`,
//! connects only to the vetted addresses, checks the answering address
//! again, follows no redirect and reads at most 1 MiB within `timeout_ms`.
//! The gateway is a confidential client: each request carries its
//! `client_secret` or a fresh `private_key_jwt` assertion. No error, log
//! line or metric carries a code, a token, a secret or the IdP's
//! `error_description`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::state::{SecretString, random_token};
use super::{
    AuthorizationServer, CLIENT_ASSERTION_TYPE_JWT_BEARER, FetchFailure, IdpEntry,
    JWKS_REFRESH_MIN_INTERVAL, KeyError, MAX_IDP_RESPONSE_BYTES, RefreshState, StringOrVec, ct_eq,
    enforce_discovery_url_safety, jose_typ_is, now_unix,
};
use crate::config::interactive_login::{login_key_algorithm, normalize_pem};
use crate::config::{
    AuthorizationServerConfig, LoginAssertionAudience, LoginClientAuth, TrustedIdpConfig,
    TrustedIdpLoginConfig,
};

/// Lifetime of a client assertion the gateway signs. It is a bearer
/// credential, so it stays well under the five minutes an authorization
/// server accepts.
pub const CLIENT_ASSERTION_LIFETIME_SECS: u64 = 120;
/// Oldest `iat` an ID token may carry, in seconds before now.
pub const ID_TOKEN_MAX_ISSUED_AGE_SECS: u64 = 600;
/// How long discovered endpoints are reused.
const METADATA_TTL: Duration = Duration::from_secs(3_600);
/// How long the last discovered endpoints keep serving while the IdP's
/// discovery document cannot be fetched.
const METADATA_MAX_STALENESS: Duration = Duration::from_secs(86_400);
/// Ceiling on the timeout of a refresh at the IdP: an MCP client's own
/// refresh waits on it.
const REFRESH_TIMEOUT_CEILING: Duration = Duration::from_secs(5);
/// Longest OAuth error code read from an IdP error response.
const MAX_ERROR_CODE_LEN: usize = 64;
/// Longest IdP-supplied value quoted in an error.
const QUOTE_LIMIT: usize = 80;
/// JOSE `typ` values of tokens that are never ID tokens (RFC 8725 §3.11).
const NOT_ID_TOKEN_TYPS: [&str; 3] = ["at+jwt", "oauth-id-jag+jwt", "logout+jwt"];

// ---------------------------------------------------------------------------
// Errors and metrics
// ---------------------------------------------------------------------------

/// Why a request to the login IdP failed. No variant carries a code, a
/// token, a secret or the IdP's `error_description`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// The IdP could not be reached, timed out, or answered with a server
    /// error or a rate limit: a retry may succeed.
    Unavailable(String),
    /// The IdP refused the request with an OAuth error (RFC 6749 §5.2),
    /// such as `invalid_grant` or `invalid_client`.
    Refused { status: u16, error: String },
    /// The IdP's metadata or answer contradicts the configuration, the
    /// outbound policy or the protocol: a redirect, an oversized or
    /// malformed body, an endpoint outside `allowed_hosts`, a private
    /// address. Retrying does not help.
    Misconfigured(String),
}

impl UpstreamError {
    /// Whether a retry may succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    /// The OAuth error code the IdP answered with.
    pub fn oauth_error(&self) -> Option<&str> {
        match self {
            Self::Refused { error, .. } => Some(error),
            _ => None,
        }
    }

    fn outcome(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "unavailable",
            Self::Refused { .. } => "refused",
            Self::Misconfigured(_) => "misconfigured",
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "the login IdP is unavailable: {reason}"),
            Self::Refused { status, error } => {
                write!(f, "the login IdP refused the request ({status} {error})")
            }
            Self::Misconfigured(reason) => write!(f, "the login IdP cannot be used: {reason}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<FetchFailure> for UpstreamError {
    fn from(failure: FetchFailure) -> Self {
        match failure {
            FetchFailure::Transient(error) => Self::Unavailable(format!("{error:#}")),
            FetchFailure::Rejected(reason) => Self::Misconfigured(reason),
        }
    }
}

/// A request the gateway makes to the login IdP, for metrics and logs.
#[derive(Debug, Clone, Copy)]
enum IdpOp {
    Discovery,
    Code,
    Refresh,
    Revoke,
}

impl IdpOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Code => "code",
            Self::Refresh => "refresh",
            Self::Revoke => "revoke",
        }
    }
}

fn record_idp_request(op: IdpOp, outcome: &'static str, elapsed: Duration) {
    metrics::counter!(
        "mcpg_as_idp_requests_total",
        "op" => op.as_str(),
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_as_idp_request_latency_ms", "op" => op.as_str())
        .record(elapsed.as_secs_f64() * 1000.0);
}

/// An IdP-supplied value, quoted and cut to [`QUOTE_LIMIT`] characters.
fn quoted(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_owned()).to_string();
    if quoted.chars().count() > QUOTE_LIMIT {
        format!("{}…", quoted.chars().take(QUOTE_LIMIT).collect::<String>())
    } else {
        quoted
    }
}

// ---------------------------------------------------------------------------
// Pinned outbound HTTP
// ---------------------------------------------------------------------------

/// An HTTP client whose connections to `url`'s host go only to addresses
/// vetted here: the host is resolved first and refused when any address
/// is private (unless `allow_private`), and no redirect is followed.
/// `timeout` bounds the name lookup and the request together. Returns the
/// client and the parsed URL to request.
pub(super) async fn pinned_client(
    url: &str,
    allow_private: bool,
    timeout: Duration,
) -> Result<(reqwest::Client, url::Url), FetchFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let timed_out = || {
        FetchFailure::Transient(anyhow!(
            "{url}: no answer within {} ms",
            timeout.as_millis()
        ))
    };
    let rejected = FetchFailure::Rejected;
    let parsed = url::Url::parse(url).map_err(|e| rejected(format!("{url} is not a URL: {e}")))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| rejected(format!("{url} has no port")))?;
    let (domain, addrs): (Option<String>, Vec<SocketAddr>) = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => (None, vec![SocketAddr::new(ip.into(), port)]),
        Some(url::Host::Ipv6(ip)) => (None, vec![SocketAddr::new(ip.into(), port)]),
        Some(url::Host::Domain(domain)) => {
            let addrs = tokio::time::timeout_at(deadline, tokio::net::lookup_host((domain, port)))
                .await
                .map_err(|_| timed_out())?
                .map_err(|e| FetchFailure::Transient(anyhow!("resolving {domain}: {e}")))?
                .collect();
            (Some(domain.to_owned()), addrs)
        }
        None => return Err(rejected(format!("{url} has no host"))),
    };
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    if addrs.is_empty() {
        return Err(FetchFailure::Transient(anyhow!(
            "{url}: the host did not resolve"
        )));
    }
    if !allow_private
        && addrs
            .iter()
            .any(|addr| crate::runtime::safe_dns::is_private_address(&addr.ip()))
    {
        return Err(rejected(format!(
            "{url} resolves to a private address, which allow_private_network: false refuses"
        )));
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(remaining)
        .connect_timeout(remaining);
    if let Some(ref domain) = domain {
        builder = builder.resolve_to_addrs(domain, &addrs);
    }
    let http = builder
        .build()
        .map_err(|e| FetchFailure::Transient(anyhow!("building the HTTP client: {e}")))?;
    Ok((http, parsed))
}

/// Refuse `response` when it came from a private address and
/// `allow_private` is off: the address the connection reached, checked
/// once more.
pub(super) fn check_answering_address(
    response: &reqwest::Response,
    url: &str,
    allow_private: bool,
) -> Result<(), FetchFailure> {
    mcpg_plugin_protocol::security::check_response_remote_addr(
        response.remote_addr(),
        allow_private,
    )
    .map_err(|_| {
        FetchFailure::Rejected(format!(
            "{url} is served from a private address, which allow_private_network: false \
             refuses"
        ))
    })
}

/// At most `max_bytes` of `response`'s body; a longer body is `Rejected`.
pub(super) async fn read_capped(
    response: &mut reqwest::Response,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchFailure> {
    let too_large =
        || FetchFailure::Rejected(format!("{url} returned more than {max_bytes} bytes"));
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| FetchFailure::Transient(anyhow!("reading {url}: {e}")))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The status and body of a POST to an IdP endpoint.
struct PostedResponse {
    status: reqwest::StatusCode,
    body: Zeroizing<Vec<u8>>,
}

/// POST the form-encoded `body` to `url` over a [`pinned_client`], with
/// `authorization` as the `Authorization` header, and read at most
/// [`MAX_IDP_RESPONSE_BYTES`] of the answer.
async fn post_form_pinned(
    url: &str,
    body: &str,
    authorization: Option<&str>,
    allow_private: bool,
    timeout: Duration,
) -> Result<PostedResponse, UpstreamError> {
    use reqwest::header;
    let (http, parsed) = pinned_client(url, allow_private, timeout).await?;
    let mut request = http
        .post(parsed)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body(body.to_owned());
    if let Some(value) = authorization {
        let mut value = header::HeaderValue::from_str(value).map_err(|_| {
            UpstreamError::Misconfigured(
                "the client credentials do not fit an Authorization header".to_owned(),
            )
        })?;
        value.set_sensitive(true);
        request = request.header(header::AUTHORIZATION, value);
    }
    let mut response = request.send().await.map_err(|e| {
        UpstreamError::Unavailable(if e.is_timeout() {
            format!("{url} did not answer within {} ms", timeout.as_millis())
        } else {
            format!("posting to {url}: {e}")
        })
    })?;
    check_answering_address(&response, url, allow_private)?;
    let status = response.status();
    let body = Zeroizing::new(read_capped(&mut response, url, MAX_IDP_RESPONSE_BYTES).await?);
    Ok(PostedResponse { status, body })
}

/// The error an IdP endpoint's non-success answer amounts to.
fn error_response(url: &str, status: reqwest::StatusCode, body: &[u8]) -> UpstreamError {
    use reqwest::StatusCode;
    if status.is_redirection() {
        return UpstreamError::Misconfigured(format!(
            "{url} answered with a redirect ({status}), and redirects are not followed"
        ));
    }
    if status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        )
    {
        return UpstreamError::Unavailable(format!("{url} returned {status}"));
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(ErrorBody { error }) if is_error_code(&error) => UpstreamError::Refused {
            status: status.as_u16(),
            error,
        },
        _ => UpstreamError::Misconfigured(format!(
            "{url} returned {status} without an OAuth error code"
        )),
    }
}

/// An OAuth error code as IdPs spell them: a short token of letters,
/// digits, `_`, `-` and `.`.
fn is_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_ERROR_CODE_LEN
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

// ---------------------------------------------------------------------------
// Client authentication
// ---------------------------------------------------------------------------

/// How the gateway authenticates at the login IdP (RFC 6749 §2.3.1,
/// RFC 7523 §2.2), with any signing key already parsed. The field names
/// and the assertion rules are those of the `oauth-id-jag` plugin, so the
/// OIDC app both use at an Okta org authenticates the same way.
pub struct LoginCredential {
    client_id: String,
    method: CredentialMethod,
}

enum CredentialMethod {
    SecretBasic(SecretString),
    SecretPost(SecretString),
    PrivateKeyJwt(AssertionSigner),
}

struct AssertionSigner {
    alg: Algorithm,
    key: EncodingKey,
    key_id: Option<String>,
    audience: LoginAssertionAudience,
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: String,
    iat: u64,
    exp: u64,
}

impl std::fmt::Debug for LoginCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCredential")
            .field("client_id", &self.client_id)
            .field("method", &self.method().as_str())
            .finish_non_exhaustive()
    }
}

/// `application/x-www-form-urlencoded` encoding, which RFC 6749 §2.3.1
/// applies to the id and the secret before they enter a Basic header.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

impl LoginCredential {
    /// The credential `login` configures. Errors name settings, never
    /// their values.
    pub fn from_config(login: &TrustedIdpLoginConfig) -> Result<Self> {
        let method = login.effective_client_auth().ok_or_else(|| {
            anyhow!("needs a credential: client_secret, or private_key for private_key_jwt")
        })?;
        let secret = || {
            login
                .client_secret
                .as_deref()
                .filter(|secret| !secret.is_empty())
                .map(SecretString::new)
                .ok_or_else(|| anyhow!("client_auth {} takes client_secret", method.as_str()))
        };
        let method = match method {
            LoginClientAuth::ClientSecretBasic => CredentialMethod::SecretBasic(secret()?),
            LoginClientAuth::ClientSecretPost => CredentialMethod::SecretPost(secret()?),
            LoginClientAuth::PrivateKeyJwt => {
                let pem = login
                    .private_key
                    .as_deref()
                    .ok_or_else(|| anyhow!("client_auth private_key_jwt takes private_key"))?;
                let alg = login_key_algorithm(pem, login.signing_alg)
                    .map_err(|problem| anyhow!("private_key {problem}"))?;
                let key = alg
                    .encoding_key(normalize_pem(pem).as_bytes())
                    .map_err(|_| anyhow!("private_key is not a usable {} key", alg.as_str()))?;
                CredentialMethod::PrivateKeyJwt(AssertionSigner {
                    alg: alg.algorithm(),
                    key,
                    key_id: login.key_id.clone(),
                    audience: login.effective_assertion_audience(),
                })
            }
        };
        Ok(Self {
            client_id: login.client_id.clone(),
            method,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn method(&self) -> LoginClientAuth {
        match self.method {
            CredentialMethod::SecretBasic(_) => LoginClientAuth::ClientSecretBasic,
            CredentialMethod::SecretPost(_) => LoginClientAuth::ClientSecretPost,
            CredentialMethod::PrivateKeyJwt(_) => LoginClientAuth::PrivateKeyJwt,
        }
    }

    /// The credentials of one request to `endpoint` at the IdP `issuer`. A
    /// `private_key_jwt` assertion is signed fresh: `iss` and `sub` are the
    /// client id, `aud` is `endpoint` or `issuer` as `assertion_audience`
    /// says, `jti` is 256 random bits and `exp` lies
    /// [`CLIENT_ASSERTION_LIFETIME_SECS`] after `iat`.
    pub fn authenticate(
        &self,
        endpoint: &str,
        issuer: &str,
    ) -> Result<ClientAuthentication, UpstreamError> {
        let client_id = || SecretString::new(self.client_id.clone());
        Ok(match self.method {
            CredentialMethod::SecretBasic(ref secret) => {
                let pair = Zeroizing::new(format!(
                    "{}:{}",
                    form_encode(&self.client_id),
                    form_encode(secret.expose())
                ));
                ClientAuthentication {
                    form: Vec::new(),
                    authorization: Some(SecretString::new(format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
                    ))),
                }
            }
            CredentialMethod::SecretPost(ref secret) => ClientAuthentication {
                form: vec![
                    ("client_id", client_id()),
                    ("client_secret", secret.clone()),
                ],
                authorization: None,
            },
            CredentialMethod::PrivateKeyJwt(ref signer) => {
                let audience = match signer.audience {
                    LoginAssertionAudience::TokenEndpoint => endpoint,
                    LoginAssertionAudience::Issuer => issuer,
                };
                ClientAuthentication {
                    form: vec![
                        ("client_id", client_id()),
                        (
                            "client_assertion_type",
                            SecretString::new(CLIENT_ASSERTION_TYPE_JWT_BEARER),
                        ),
                        (
                            "client_assertion",
                            SecretString::new(signer.sign(&self.client_id, audience)?),
                        ),
                    ],
                    authorization: None,
                }
            }
        })
    }
}

impl AssertionSigner {
    fn sign(&self, client_id: &str, audience: &str) -> Result<String, UpstreamError> {
        let jti = random_token().map_err(|e| UpstreamError::Misconfigured(e.to_string()))?;
        let now = now_unix();
        let claims = AssertionClaims {
            iss: client_id,
            sub: client_id,
            aud: audience,
            jti,
            iat: now,
            exp: now + CLIENT_ASSERTION_LIFETIME_SECS,
        };
        let mut header = Header::new(self.alg);
        header.kid = self.key_id.clone();
        jsonwebtoken::encode(&header, &claims, &self.key).map_err(|e| {
            UpstreamError::Misconfigured(format!("the client assertion cannot be signed: {e}"))
        })
    }
}

/// One request's client credentials: form fields in the order they are
/// sent, and an `Authorization` header value for `client_secret_basic`.
/// `Debug` names the fields only.
pub struct ClientAuthentication {
    pub form: Vec<(&'static str, SecretString)>,
    pub authorization: Option<SecretString>,
}

impl std::fmt::Debug for ClientAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuthentication")
            .field(
                "form",
                &self.form.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            )
            .field("authorization", &self.authorization.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// The login IdP's endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// The RFC 7009 revocation endpoint; `None` when the IdP has none.
    pub revocation_endpoint: Option<String>,
    /// RFC 9207 §3: the IdP puts `iss` in every authorization response, so
    /// a response without it is refused.
    pub authorization_response_iss_parameter_supported: bool,
}

impl IdpMetadata {
    /// The endpoints `login` configures, the rest read from `discovered`,
    /// the IdP's discovery document and the URL it was read from. Each
    /// must be a URL `idp`'s outbound policy admits.
    fn resolve(
        login: &TrustedIdpLoginConfig,
        idp: &TrustedIdpConfig,
        discovered: Option<(&str, &serde_json::Value)>,
    ) -> Result<Self, String> {
        let endpoint = |key: &str, configured: &Option<String>| -> Result<Option<String>, String> {
            if let Some(url) = configured {
                return check_endpoint(url, idp)
                    .map(|()| Some(url.clone()))
                    .map_err(|problem| format!("login.{key} {problem}"));
            }
            let Some((source, document)) = discovered else {
                return Ok(None);
            };
            match document.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(url)) => {
                    let published =
                        || format!("the IdP publishes {key} {} at {source}", quoted(url));
                    if let Err(problem) = policy_problem(url, idp) {
                        return Err(format!(
                            "{}, which {problem}; list its host in trusted_idps[].allowed_hosts \
                             or set trusted_idps[].login.{key}",
                            published()
                        ));
                    }
                    if let Some(problem) = shape_problem(url) {
                        return Err(format!(
                            "{}, which {problem}; set trusted_idps[].login.{key}",
                            published()
                        ));
                    }
                    Ok(Some(url.clone()))
                }
                Some(_) => Err(format!(
                    "the IdP discovery document at {source} has a {key} that is not a string"
                )),
            }
        };
        let required = |key: &str, value: Option<String>| {
            value.ok_or_else(|| match discovered {
                Some((source, _)) => format!(
                    "the IdP discovery document at {source} carries no {key}; set \
                     trusted_idps[].login.{key}"
                ),
                None => format!("trusted_idps[].login.{key} is not set"),
            })
        };
        let authorization_endpoint = required(
            "authorization_endpoint",
            endpoint("authorization_endpoint", &login.authorization_endpoint)?,
        )?;
        let token_endpoint = required(
            "token_endpoint",
            endpoint("token_endpoint", &login.token_endpoint)?,
        )?;
        let revocation_endpoint = endpoint("revocation_endpoint", &login.revocation_endpoint)?;
        let authorization_response_iss_parameter_supported = discovered.is_some_and(|(_, doc)| {
            doc.get("authorization_response_iss_parameter_supported")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        });
        Ok(Self {
            authorization_endpoint,
            token_endpoint,
            revocation_endpoint,
            authorization_response_iss_parameter_supported,
        })
    }
}

/// Why `url` cannot be an endpoint of `idp`: [`policy_problem`] or
/// [`shape_problem`].
fn check_endpoint(url: &str, idp: &TrustedIdpConfig) -> Result<(), String> {
    policy_problem(url, idp)?;
    shape_problem(url).map_or(Ok(()), |problem| Err(problem.to_owned()))
}

/// Why `idp`'s outbound policy refuses `url`: not `https`, a host outside
/// `allowed_hosts`, or a private address literal, unless
/// `allow_private_network`.
fn policy_problem(url: &str, idp: &TrustedIdpConfig) -> Result<(), String> {
    enforce_discovery_url_safety(url, &idp.allowed_hosts, idp.allow_private_network)
        .map_err(|e| format!("is refused: {e}"))
}

/// Why `url` is no endpoint URL whatever the policy: unparseable, or
/// carrying a fragment or userinfo.
fn shape_problem(url: &str) -> Option<&'static str> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Some("is not a URL");
    };
    if parsed.fragment().is_some() {
        return Some("must not carry a fragment");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("must not carry userinfo");
    }
    None
}

struct CachedMetadata {
    metadata: Arc<IdpMetadata>,
    fetched_at: Instant,
}

/// Discovered endpoints: reused for [`METADATA_TTL`], refetched at most
/// once per [`JWKS_REFRESH_MIN_INTERVAL`], and kept serving for up to
/// [`METADATA_MAX_STALENESS`] while the IdP cannot be reached. A document
/// that contradicts the configuration is dropped and its reason kept
/// until a refetch succeeds.
#[derive(Default)]
struct MetadataCache {
    cached: RwLock<Option<CachedMetadata>>,
    refresh_state: Mutex<RefreshState>,
    /// Serializes refreshes so concurrent requests share one fetch.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl MetadataCache {
    async fn within(&self, age: Duration) -> Option<Arc<IdpMetadata>> {
        self.cached
            .read()
            .await
            .as_ref()
            .filter(|cached| cached.fetched_at.elapsed() < age)
            .map(|cached| cached.metadata.clone())
    }

    async fn get<F, Fut>(&self, issuer: &str, fetch: F) -> Result<Arc<IdpMetadata>, UpstreamError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<IdpMetadata, FetchFailure>>,
    {
        if let Some(fresh) = self.within(METADATA_TTL).await {
            return Ok(fresh);
        }
        let _refreshing = self.refresh_lock.lock().await;
        if let Some(fresh) = self.within(METADATA_TTL).await {
            return Ok(fresh);
        }
        // Inside the retry spacing, the last attempt's outcome answers: its
        // refusal, or whatever endpoints are still usable.
        let spaced_out = {
            let mut state = self.refresh_state.lock().unwrap_or_else(|p| p.into_inner());
            match state.last_attempt {
                Some(at) if at.elapsed() < JWKS_REFRESH_MIN_INTERVAL => {
                    Some(state.rejected.clone())
                }
                _ => {
                    state.last_attempt = Some(Instant::now());
                    None
                }
            }
        };
        match spaced_out {
            Some(Some(reason)) => return Err(UpstreamError::Misconfigured(reason)),
            Some(None) => {
                return self.within(METADATA_MAX_STALENESS).await.ok_or_else(|| {
                    UpstreamError::Unavailable(
                        "the IdP's endpoints cannot be discovered right now".to_owned(),
                    )
                });
            }
            None => {}
        }
        let started = Instant::now();
        let result = fetch().await;
        match result {
            Ok(metadata) => {
                record_idp_request(IdpOp::Discovery, "ok", started.elapsed());
                let metadata = Arc::new(metadata);
                let previous = self.cached.write().await.replace(CachedMetadata {
                    metadata: metadata.clone(),
                    fetched_at: Instant::now(),
                });
                self.refresh_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .rejected = None;
                if previous.is_none_or(|previous| previous.metadata != metadata) {
                    tracing::info!(
                        issuer = %issuer,
                        authorization_endpoint = %metadata.authorization_endpoint,
                        token_endpoint = %metadata.token_endpoint,
                        revocation_endpoint = metadata.revocation_endpoint.as_deref().unwrap_or("none"),
                        iss_parameter_supported = metadata.authorization_response_iss_parameter_supported,
                        "login IdP endpoints discovered"
                    );
                }
                Ok(metadata)
            }
            Err(FetchFailure::Transient(error)) => {
                record_idp_request(IdpOp::Discovery, "unavailable", started.elapsed());
                let stale = self.within(METADATA_MAX_STALENESS).await;
                let error = format!("{error:#}");
                tracing::warn!(
                    issuer = %issuer,
                    error = %error,
                    serving_cached_endpoints = stale.is_some(),
                    "the login IdP's discovery document could not be fetched"
                );
                stale.ok_or(UpstreamError::Unavailable(error))
            }
            Err(FetchFailure::Rejected(reason)) => {
                record_idp_request(IdpOp::Discovery, "misconfigured", started.elapsed());
                tracing::error!(
                    issuer = %issuer,
                    reason = %reason,
                    "the login IdP's discovery document cannot be used; sign-in fails until it \
                     is fixed"
                );
                *self.cached.write().await = None;
                self.refresh_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .rejected = Some(reason.clone());
                Err(UpstreamError::Misconfigured(reason))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The login client
// ---------------------------------------------------------------------------

/// The gateway's client at the one trusted IdP with a `login` block,
/// built with the server that owns it.
pub(super) struct LoginClient {
    config: TrustedIdpLoginConfig,
    credential: LoginCredential,
    /// `{authorization_server.issuer}/oauth/callback`.
    redirect_uri: String,
    /// Every endpoint configured: nothing is discovered.
    configured: Option<Arc<IdpMetadata>>,
    /// Shared with the client a reload replaces when the IdP entry is
    /// unchanged.
    discovered: Arc<MetadataCache>,
}

impl std::fmt::Debug for LoginClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginClient")
            .field("credential", &self.credential)
            .field("redirect_uri", &self.redirect_uri)
            .field("configured", &self.configured)
            .finish_non_exhaustive()
    }
}

impl LoginClient {
    /// The client `login` configures at `idp`, a trusted IdP of `server`.
    /// Configured endpoints are checked against the IdP's outbound policy
    /// and the credential is parsed now, so a problem refuses the
    /// configuration rather than the first sign-in.
    pub(super) fn from_config(
        idp: &TrustedIdpConfig,
        login: &TrustedIdpLoginConfig,
        server: &AuthorizationServerConfig,
    ) -> Result<Self> {
        let at = format!("trusted_idps[`{}`].login", idp.issuer);
        let credential = LoginCredential::from_config(login).map_err(|e| anyhow!("{at}: {e}"))?;
        for (key, url) in [
            ("authorization_endpoint", &login.authorization_endpoint),
            ("token_endpoint", &login.token_endpoint),
            ("revocation_endpoint", &login.revocation_endpoint),
        ] {
            if let Some(url) = url {
                check_endpoint(url, idp).map_err(|problem| anyhow!("{at}.{key} {problem}"))?;
            }
        }
        let configured = if login.endpoints_configured() {
            Some(Arc::new(
                IdpMetadata::resolve(login, idp, None).map_err(|e| anyhow!("{at}: {e}"))?,
            ))
        } else {
            None
        };
        Ok(Self {
            config: login.clone(),
            credential,
            redirect_uri: server.login_callback_url(),
            configured,
            discovered: Arc::default(),
        })
    }

    /// Take over the endpoints `previous` discovered: its IdP entry is the
    /// same, so they still hold, and a reload neither refetches them nor
    /// loses the last ones while the IdP's discovery is down.
    pub(super) fn adopt_discovered(&mut self, previous: &LoginClient) {
        self.discovered = Arc::clone(&previous.discovered);
    }
}

/// The login IdP of an [`AuthorizationServer`]: its configuration, its
/// endpoints, and the requests the gateway makes to it.
#[derive(Clone, Copy)]
pub struct LoginIdp<'a> {
    server: &'a AuthorizationServer,
    entry: &'a IdpEntry,
    client: &'a LoginClient,
}

impl std::fmt::Debug for LoginIdp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginIdp")
            .field("issuer", &self.issuer())
            .field("client", self.client)
            .finish()
    }
}

impl AuthorizationServer {
    /// The trusted IdP users sign in through: the entry with a `login`
    /// block. `None` without interactive sign-in.
    pub fn login_idp(&self) -> Option<LoginIdp<'_>> {
        self.idps.iter().find_map(|entry| {
            entry.login.as_ref().map(|client| LoginIdp {
                server: self,
                entry,
                client,
            })
        })
    }
}

/// The parameters of one authorization request to the IdP that the
/// sign-in transaction decides.
pub struct IdpAuthorizationRequest<'a> {
    pub state: &'a str,
    pub nonce: &'a str,
    /// `BASE64URL(SHA256(verifier))` of the gateway's own PKCE verifier.
    pub code_challenge: &'a str,
    /// `login` or `select_account`, passed on from the client's request.
    pub prompt: Option<&'a str>,
    pub login_hint: Option<&'a str>,
}

/// What the IdP's token endpoint answered for a sign-in. The IdP's access
/// token is never read.
#[derive(Debug)]
pub struct IdpTokens {
    pub id_token: SecretString,
    pub refresh_token: Option<SecretString>,
    /// The scope the IdP granted, when it says.
    pub scope: Option<String>,
}

/// What the IdP's token endpoint answered for a refresh: a new ID token
/// and a rotated refresh token when the IdP issues them.
#[derive(Debug)]
pub struct IdpRefresh {
    pub id_token: Option<SecretString>,
    pub refresh_token: Option<SecretString>,
    pub scope: Option<String>,
}

/// The outcome of revoking a token at the IdP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The IdP accepted the revocation (RFC 7009 §2.2).
    Revoked,
    /// The IdP has no revocation endpoint.
    NoEndpoint,
}

/// The fields of a token response the gateway reads (RFC 6749 §5.1).
#[derive(Deserialize)]
struct TokenEndpointResponse {
    token_type: String,
    #[serde(default)]
    id_token: Option<SecretString>,
    #[serde(default)]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    scope: Option<String>,
}

/// A secret the IdP returned, `None` when absent or empty.
fn present(secret: Option<SecretString>) -> Option<SecretString> {
    secret.filter(|secret| !secret.expose().is_empty())
}

/// The token response in `body` from `endpoint`: a JSON object whose
/// `token_type` is `Bearer`.
fn parse_token_response(
    endpoint: &str,
    body: &[u8],
) -> Result<TokenEndpointResponse, UpstreamError> {
    let malformed = || {
        UpstreamError::Misconfigured(format!(
            "{endpoint} answered with a body that is not an RFC 6749 section 5.1 token response"
        ))
    };
    // A derived struct also reads a JSON array, positionally.
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(|_| malformed())?;
    let response: TokenEndpointResponse =
        serde_json::from_value(serde_json::Value::Object(object)).map_err(|_| malformed())?;
    if !response.token_type.eq_ignore_ascii_case("Bearer") {
        return Err(UpstreamError::Misconfigured(format!(
            "{endpoint} issued a token of type {} rather than Bearer",
            quoted(&response.token_type)
        )));
    }
    Ok(response)
}

impl<'a> LoginIdp<'a> {
    /// The IdP's issuer identifier.
    pub fn issuer(&self) -> &'a str {
        &self.entry.config.issuer
    }

    /// The trusted IdP entry: keys, claim mappings, allowed clients.
    pub fn idp(&self) -> &'a TrustedIdpConfig {
        &self.entry.config
    }

    pub fn config(&self) -> &'a TrustedIdpLoginConfig {
        &self.client.config
    }

    /// The gateway's client id at the IdP.
    pub fn client_id(&self) -> &'a str {
        &self.client.config.client_id
    }

    /// The redirect URI registered at the IdP:
    /// `{authorization_server.issuer}/oauth/callback`.
    pub fn redirect_uri(&self) -> &'a str {
        &self.client.redirect_uri
    }

    /// The IdP's name on the consent and connect pages.
    pub fn display_name(&self) -> String {
        self.client.config.effective_display_name(self.issuer())
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.client.config.timeout_ms)
    }

    /// The IdP's endpoints: those configured, the rest discovered and
    /// cached.
    pub async fn metadata(&self) -> Result<Arc<IdpMetadata>, UpstreamError> {
        if let Some(ref configured) = self.client.configured {
            return Ok(configured.clone());
        }
        self.client
            .discovered
            .get(self.issuer(), || async {
                let (source, document) = self.server.discover_idp_document(self.idp()).await?;
                IdpMetadata::resolve(self.config(), self.idp(), Some((&source, &document)))
                    .map_err(FetchFailure::Rejected)
            })
            .await
    }

    /// The URL of the authorization request that sends the user to the
    /// IdP: the gateway's client id and redirect URI, the configured
    /// scopes, `max_age` and `authorize_params`, and the S256 challenge of
    /// the gateway's own PKCE verifier. A query the endpoint already has
    /// is kept.
    pub fn authorization_url(
        &self,
        metadata: &IdpMetadata,
        request: &IdpAuthorizationRequest<'_>,
    ) -> Result<String, UpstreamError> {
        let config = self.config();
        let mut url = url::Url::parse(&metadata.authorization_endpoint).map_err(|e| {
            UpstreamError::Misconfigured(format!("the authorization endpoint is not a URL: {e}"))
        })?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &config.client_id)
                .append_pair("redirect_uri", self.redirect_uri())
                .append_pair("scope", &config.scopes.join(" "))
                .append_pair("state", request.state)
                .append_pair("nonce", request.nonce)
                .append_pair("code_challenge", request.code_challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(prompt) = request.prompt {
                query.append_pair("prompt", prompt);
            }
            if let Some(max_age) = config.max_age_secs {
                query.append_pair("max_age", &max_age.to_string());
            }
            if let Some(hint) = request.login_hint {
                query.append_pair("login_hint", hint);
            }
            for (name, value) in &config.authorize_params {
                query.append_pair(name, value);
            }
        }
        Ok(url.into())
    }

    /// Redeem the authorization `code` the IdP sent to the callback, with
    /// the PKCE `code_verifier` of the transaction. The answer must carry
    /// an ID token; the IdP's access token is dropped unread.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<IdpTokens, UpstreamError> {
        let metadata = self.metadata().await?;
        let endpoint = metadata.token_endpoint.as_str();
        self.call(
            IdpOp::Code,
            endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri()),
                ("code_verifier", code_verifier),
            ],
            self.timeout(),
            |body| {
                let response = parse_token_response(endpoint, body)?;
                let id_token = present(response.id_token).ok_or_else(|| {
                    UpstreamError::Misconfigured(format!(
                        "{endpoint} returned no id_token; trusted_idps[].login.scopes must \
                         include openid"
                    ))
                })?;
                Ok(IdpTokens {
                    id_token,
                    refresh_token: present(response.refresh_token),
                    scope: response.scope,
                })
            },
        )
        .await
    }

    /// Refresh the stored sign-in with its IdP `refresh_token`, within
    /// the lesser of `timeout_ms` and five seconds. `invalid_grant` means
    /// the IdP ended the sign-in.
    pub async fn refresh(&self, refresh_token: &str) -> Result<IdpRefresh, UpstreamError> {
        let metadata = self.metadata().await?;
        let endpoint = metadata.token_endpoint.as_str();
        self.call(
            IdpOp::Refresh,
            endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
            self.timeout().min(REFRESH_TIMEOUT_CEILING),
            |body| {
                let response = parse_token_response(endpoint, body)?;
                Ok(IdpRefresh {
                    id_token: present(response.id_token),
                    refresh_token: present(response.refresh_token),
                    scope: response.scope,
                })
            },
        )
        .await
    }

    /// Revoke an IdP refresh token (RFC 7009), when the IdP has a
    /// revocation endpoint.
    pub async fn revoke_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<RevokeOutcome, UpstreamError> {
        let metadata = self.metadata().await?;
        let Some(endpoint) = metadata.revocation_endpoint.as_deref() else {
            return Ok(RevokeOutcome::NoEndpoint);
        };
        self.call(
            IdpOp::Revoke,
            endpoint,
            &[
                ("token", refresh_token),
                ("token_type_hint", "refresh_token"),
            ],
            self.timeout(),
            |_| Ok(RevokeOutcome::Revoked),
        )
        .await
    }

    /// POST `params` with the client's credentials to `endpoint`, read the
    /// answer with `parse`, and record the request.
    async fn call<T>(
        &self,
        op: IdpOp,
        endpoint: &str,
        params: &[(&str, &str)],
        timeout: Duration,
        parse: impl FnOnce(&[u8]) -> Result<T, UpstreamError>,
    ) -> Result<T, UpstreamError> {
        let started = Instant::now();
        let result = match self.post_authenticated(endpoint, params, timeout).await {
            Ok(body) => parse(&body),
            Err(error) => Err(error),
        };
        let outcome = match result {
            Ok(_) => "ok",
            Err(ref error) => error.outcome(),
        };
        record_idp_request(op, outcome, started.elapsed());
        if let Err(ref error) = result {
            self.log_failure(op, endpoint, error);
        }
        result
    }

    async fn post_authenticated(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, UpstreamError> {
        let auth = self
            .client
            .credential
            .authenticate(endpoint, self.issuer())?;
        // The serializer is not `Send`, so it must be gone before the await.
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in params {
                form.append_pair(name, value);
            }
            for (name, value) in &auth.form {
                form.append_pair(name, value.expose());
            }
            Zeroizing::new(form.finish())
        };
        let response = post_form_pinned(
            endpoint,
            &body,
            auth.authorization.as_ref().map(SecretString::expose),
            self.idp().allow_private_network,
            timeout,
        )
        .await?;
        if response.status.is_success() {
            Ok(response.body)
        } else {
            Err(error_response(endpoint, response.status, &response.body))
        }
    }

    fn log_failure(&self, op: IdpOp, endpoint: &str, error: &UpstreamError) {
        let issuer = self.issuer();
        let op = op.as_str();
        match error {
            UpstreamError::Refused { error: code, .. } if code == "invalid_client" => {
                tracing::error!(
                    issuer = %issuer,
                    op,
                    endpoint = %endpoint,
                    "the login IdP refused the gateway's client credentials (invalid_client); \
                     check trusted_idps[].login.client_id and its client_secret or private_key"
                );
            }
            UpstreamError::Refused {
                status,
                error: code,
            } => tracing::info!(
                issuer = %issuer,
                op,
                endpoint = %endpoint,
                status,
                error = %code,
                "the login IdP refused a request"
            ),
            UpstreamError::Unavailable(reason) => tracing::warn!(
                issuer = %issuer,
                op,
                reason = %reason,
                "the login IdP is unavailable"
            ),
            UpstreamError::Misconfigured(reason) => tracing::error!(
                issuer = %issuer,
                op,
                reason = %reason,
                "a request to the login IdP failed"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// ID tokens
// ---------------------------------------------------------------------------

/// What an ID token is checked against beyond its signature, issuer,
/// audience and lifetime.
#[derive(Clone, Copy)]
pub enum IdTokenCheck<'a> {
    /// The ID token of a new sign-in: it must carry `nonce`, the value
    /// the authorization request sent, and with `max_age_secs` an
    /// `auth_time` within it.
    SignIn { nonce: &'a str },
    /// An ID token a refresh returned (OpenID Connect Core §12.2): the
    /// `sub` of the sign-in it refreshes and, when both carry one, the
    /// same `auth_time`.
    Refresh {
        subject: &'a str,
        auth_time: Option<u64>,
    },
}

/// A verified ID token.
#[derive(Debug, Clone)]
pub struct ValidatedIdToken {
    /// Its claims, for the IdP's claim mappings.
    pub claims: serde_json::Value,
    pub subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub auth_time: Option<u64>,
}

/// Why an ID token is not believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdTokenError {
    /// The IdP's signing keys cannot be fetched now: retry.
    KeysUnavailable,
    /// The token fails a check, named here for logs and audit. The text
    /// quotes no claim value.
    Invalid(String),
}

impl std::fmt::Display for IdTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeysUnavailable => f.write_str("the IdP's signing keys cannot be fetched now"),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for IdTokenError {}

/// The registered claims an ID token is checked on.
#[derive(Deserialize)]
struct IdTokenClaims {
    sub: String,
    aud: StringOrVec,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    auth_time: Option<u64>,
}

fn invalid(reason: &str) -> IdTokenError {
    IdTokenError::Invalid(reason.to_owned())
}

/// What the decoder refused, without the claim values.
fn id_token_rejected(error: &jsonwebtoken::errors::Error) -> IdTokenError {
    invalid(match error.kind() {
        ErrorKind::InvalidIssuer => "the ID token iss is not the IdP's issuer",
        ErrorKind::InvalidAudience => "the ID token aud does not name the login client",
        ErrorKind::ExpiredSignature => "the ID token has expired",
        ErrorKind::ImmatureSignature => "the ID token is not valid yet (nbf)",
        ErrorKind::InvalidSignature => "the ID token signature is invalid",
        ErrorKind::MissingRequiredClaim(_) => {
            "the ID token lacks a required claim (iss, sub, aud or exp)"
        }
        _ => "the ID token cannot be decoded",
    })
}

impl LoginIdp<'_> {
    /// Verify `id_token` as OpenID Connect Core §3.1.3.7 (and §12.2 for a
    /// refresh) prescribes: a `typ` that names another kind of token is
    /// refused (RFC 8725 §3.11); the algorithm is one of the IdP's
    /// `allowed_algs` and never HMAC; the signature verifies with the
    /// IdP's keys, refetched once for an unknown `kid`; `iss` is the
    /// IdP's issuer exactly; `aud` is the gateway's client id and nothing
    /// else, and `azp`, when present, the same; `exp` has not passed and
    /// `iat` lies within the last [`ID_TOKEN_MAX_ISSUED_AGE_SECS`], both
    /// within the clock skew; an `act` claim is refused; and `check`
    /// holds.
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        check: IdTokenCheck<'_>,
    ) -> Result<ValidatedIdToken, IdTokenError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|_| invalid("the ID token is not a well-formed signed JWT"))?;
        if header
            .typ
            .as_deref()
            .is_some_and(|typ| NOT_ID_TOKEN_TYPS.iter().any(|t| jose_typ_is(typ, t)))
        {
            return Err(invalid(
                "the ID token typ names another kind of token (RFC 8725 section 3.11)",
            ));
        }
        let alg = header.alg;
        if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            return Err(invalid(
                "the ID token is signed with an HMAC algorithm, which is never accepted",
            ));
        }
        if !self.entry.allowed_algs.contains(&alg) {
            return Err(IdTokenError::Invalid(format!(
                "the ID token alg {alg:?} is not in trusted_idps[].allowed_algs"
            )));
        }
        let key = self
            .server
            .decoding_key_for(self.entry, header.kid.as_deref(), alg)
            .await
            .map_err(|error| match error {
                KeyError::NoMatch(reason) => IdTokenError::Invalid(format!(
                    "the ID token signing key could not be resolved: {reason}"
                )),
                KeyError::Unavailable => IdTokenError::KeysUnavailable,
                KeyError::Misconfigured(reason) => IdTokenError::Invalid(format!(
                    "the IdP's signing keys cannot be used: {reason}"
                )),
            })?;
        let skew = self.server.leeway_secs;
        let mut validation = Validation::new(alg);
        validation.leeway = skew;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.issuer()]);
        validation.set_audience(&[self.client_id()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = jsonwebtoken::decode::<serde_json::Value>(id_token, &key, &validation)
            .map_err(|e| id_token_rejected(&e))?
            .claims;
        let registered = IdTokenClaims::deserialize(&claims).map_err(|_| {
            invalid(
                "the ID token's registered claims (sub, aud, exp, iat, azp, nonce, auth_time) do \
                 not have their registered types",
            )
        })?;
        if registered.aud.values() != [self.client_id()] {
            return Err(invalid(
                "the ID token aud names an audience besides the login client (OpenID Connect \
                 Core section 3.1.3.7)",
            ));
        }
        if registered
            .azp
            .as_deref()
            .is_some_and(|azp| azp != self.client_id())
        {
            return Err(invalid("the ID token azp is not the login client"));
        }
        let now = now_unix();
        let Some(issued_at) = registered.iat else {
            return Err(invalid("the ID token carries no iat"));
        };
        if issued_at > now.saturating_add(skew) {
            return Err(invalid("the ID token iat is in the future"));
        }
        if issued_at.saturating_add(ID_TOKEN_MAX_ISSUED_AGE_SECS) < now {
            return Err(IdTokenError::Invalid(format!(
                "the ID token was issued more than {ID_TOKEN_MAX_ISSUED_AGE_SECS} s ago"
            )));
        }
        if registered.sub.trim().is_empty() {
            return Err(invalid("the ID token sub is empty"));
        }
        if claims.get("act").is_some() {
            return Err(invalid(
                "the ID token carries an act claim; a sign-in names the user alone",
            ));
        }
        if registered
            .auth_time
            .is_some_and(|auth_time| auth_time > now.saturating_add(skew))
        {
            return Err(invalid("the ID token auth_time is in the future"));
        }
        match check {
            IdTokenCheck::SignIn { nonce } => {
                if nonce.is_empty()
                    || !registered
                        .nonce
                        .as_deref()
                        .is_some_and(|sent| ct_eq(sent, nonce))
                {
                    return Err(invalid(
                        "the ID token nonce is not the one the authorization request sent",
                    ));
                }
                if let Some(max_age) = self.config().max_age_secs {
                    let Some(auth_time) = registered.auth_time else {
                        return Err(invalid(
                            "the ID token carries no auth_time, which max_age_secs requires",
                        ));
                    };
                    if now.saturating_sub(auth_time) > max_age.saturating_add(skew) {
                        return Err(invalid(
                            "the user authenticated at the IdP longer ago than max_age_secs",
                        ));
                    }
                }
            }
            IdTokenCheck::Refresh { subject, auth_time } => {
                if registered.sub != subject {
                    return Err(invalid(
                        "the refreshed ID token names another sub than the sign-in (OpenID \
                         Connect Core section 12.2)",
                    ));
                }
                if let (Some(before), Some(after)) = (auth_time, registered.auth_time)
                    && before != after
                {
                    return Err(invalid(
                        "the refreshed ID token changes auth_time (OpenID Connect Core section \
                         12.2)",
                    ));
                }
            }
        }
        Ok(ValidatedIdToken {
            subject: registered.sub,
            issued_at,
            expires_at: registered.exp,
            auth_time: registered.auth_time,
            claims,
        })
    }
}

#[cfg(test)]
#[path = "authorization_server_upstream_tests.rs"]
mod tests;
