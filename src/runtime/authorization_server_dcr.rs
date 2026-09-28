//! Dynamic client registration (RFC 7591) at `POST /oauth/register`,
//! offered with a login IdP while
//! `interactive.dynamic_client_registration.enabled`.
//!
//! A request carries an initial access token the operator listed (RFC 7591
//! §3, compared as SHA-256 digests in constant time), or none where
//! `allow_open` accepts anyone. What a client registers is its own claim
//! (RFC 7591 §5), so a registration is public (`token_endpoint_auth_method`
//! `none`, with PKCE), may use `authorization_code` and `refresh_token`
//! only, and may send the browser only to a loopback redirect URI or to an
//! `https://` one on a host the operator lists; an `https://` one on
//! another host is left out of the registration, which is refused only
//! when no redirect URI remains. The server keeps its
//! redirect URIs, grant and response types, `client_name`,
//! `application_type` and, while DPoP is on, `dpop_bound_access_tokens`
//! (RFC 9449 §5.2), and nothing else it sent: no logo or other URL is
//! kept, fetched or shown. The consent page shows the name as unverified,
//! every sign-in of the client asks for consent, and no approval is
//! remembered.
//!
//! Registrations are counted across replicas: per client address and
//! clock hour (`registrations_per_hour_per_ip`, an IPv6 address counted by
//! its /64), and in all (`max_clients`). A registration is a sealed record
//! that lives `client_ttl_secs` (at least a day) from its last successful
//! use: a code issued to the client, a code or refresh token it redeemed,
//! or a token of its own it revoked. A request that merely names its
//! public client id keeps nothing alive. No access token of its grants,
//! which live an hour at most, outlives it. Once it is gone, the
//! client is unknown, and a grant of it is revoked when the client
//! presents that grant's refresh token, code or access token at the token
//! or revocation endpoint.
//!
//! Nothing here logs or audits an initial access token.

use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::clients::{Client, DCR_CLIENT_ID_PREFIX, echo};
use super::grants::{GrantEvent, REFRESH_TOKEN_PREFIX};
use super::interactive::AUTHORIZATION_CODE_PREFIX;
use super::redirect::{
    RedirectUriKind, RegisteredRedirect, client_display_name, registration_redirect,
};
use super::state::{
    CounterKey, DcrClientRecord, GrantId, InteractiveState, RevocationReason, StateError, keys,
    random_bytes,
};
use super::{AuthorizationServer, error_description, now_unix, unverified_claim_iss};
use crate::config::ClientGrantType;
use crate::config::interactive_login::DynamicClientRegistrationConfig;

/// Path of the registration endpoint.
pub const REGISTRATION_PATH: &str = "/oauth/register";
/// Largest registration request read, in bytes.
pub const MAX_REGISTRATION_BYTES: usize = 8 * 1024;
/// Most redirect URIs one registration may list.
pub const MAX_REGISTERED_REDIRECT_URIS: usize = 5;
/// Shortest initial access token accepted, in bytes.
const MIN_INITIAL_ACCESS_TOKEN_BYTES: usize = 32;
/// The window of `registrations_per_hour_per_ip`: one clock hour.
const RATE_WINDOW_SECS: u64 = 3_600;
/// Least time between two recounts of the registrations in the store.
const RECOUNT_SPACING: Duration = Duration::from_secs(60);
/// The response type a registration may use.
const RESPONSE_TYPE_CODE: &str = "code";
/// The one `token_endpoint_auth_method` of a registered client.
const AUTH_METHOD_NONE: &str = "none";
/// Longest refresh token or code looked up for a removed registration.
const MAX_PRESENTED_HANDLE_BYTES: usize = 128;
/// Longest access token looked up for a removed registration.
const MAX_PRESENTED_TOKEN_BYTES: usize = 16 * 1024;

/// The SHA-256 digest of an initial access token.
pub type TokenDigest = [u8; 32];

fn digest(token: &str) -> TokenDigest {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(token.as_bytes()).as_slice());
    out
}

/// The digests of `config`'s initial access tokens, while registration is
/// on. A token shorter than 32 bytes, or a placeholder that did not
/// resolve, is refused: either would let a guess register.
pub(super) fn token_digests(
    config: &DynamicClientRegistrationConfig,
) -> anyhow::Result<Vec<TokenDigest>> {
    if !config.enabled {
        return Ok(Vec::new());
    }
    config
        .initial_access_tokens
        .iter()
        .map(|token| {
            if token.contains("${") {
                anyhow::bail!(
                    "interactive.dynamic_client_registration.initial_access_tokens holds a \
                     placeholder that did not resolve"
                );
            }
            if token.len() < MIN_INITIAL_ACCESS_TOKEN_BYTES {
                anyhow::bail!(
                    "interactive.dynamic_client_registration.initial_access_tokens: every token \
                     must be at least {MIN_INITIAL_ACCESS_TOKEN_BYTES} bytes"
                );
            }
            Ok(digest(token))
        })
        .collect()
}

/// How a registration was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedBy {
    /// One of the operator's initial access tokens.
    InitialAccessToken,
    /// Nothing: `allow_open`.
    Open,
}

impl AuthorizedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitialAccessToken => "initial_access_token",
            Self::Open => "open",
        }
    }
}

/// Why a registration is refused (RFC 7591 §3.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// Registration is not offered.
    NotOffered,
    /// No initial access token where one is required.
    TokenRequired,
    /// An initial access token that is not listed, or not sent as a
    /// bearer token (RFC 6750 §3.1).
    InvalidToken(&'static str),
    /// A redirect URI is missing, malformed or not admitted.
    InvalidRedirectUri(String),
    /// Another member cannot be accepted.
    InvalidClientMetadata(String),
    /// The client address registered its hourly allowance; retry after
    /// this many seconds.
    RateLimited { retry_after_secs: u64 },
    /// `max_clients` registrations are kept.
    TooManyClients,
    /// The state store failed.
    Unavailable,
}

impl RegistrationError {
    /// The HTTP status of the answer.
    pub fn status(&self) -> u16 {
        match self {
            Self::NotOffered => 404,
            Self::TokenRequired | Self::InvalidToken(_) => 401,
            Self::InvalidRedirectUri(_) | Self::InvalidClientMetadata(_) => 400,
            Self::RateLimited { .. } => 429,
            Self::TooManyClients | Self::Unavailable => 503,
        }
    }

    /// The OAuth error code.
    pub fn error(&self) -> &'static str {
        match self {
            Self::NotOffered => "invalid_request",
            Self::TokenRequired | Self::InvalidToken(_) => "invalid_token",
            Self::InvalidRedirectUri(_) => "invalid_redirect_uri",
            Self::InvalidClientMetadata(_) => "invalid_client_metadata",
            Self::RateLimited { .. } | Self::TooManyClients | Self::Unavailable => {
                "temporarily_unavailable"
            }
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::NotOffered => "dynamic client registration is not offered".to_owned(),
            Self::TokenRequired => {
                "an initial access token is required: send it as Authorization: Bearer <token>"
                    .to_owned()
            }
            Self::InvalidToken(reason) => (*reason).to_owned(),
            Self::InvalidRedirectUri(reason) | Self::InvalidClientMetadata(reason) => {
                reason.clone()
            }
            Self::RateLimited { retry_after_secs } => format!(
                "too many registrations from this address this hour; retry in {retry_after_secs} s"
            ),
            Self::TooManyClients => {
                "this server keeps as many client registrations as it allows; retry later"
                    .to_owned()
            }
            Self::Unavailable => {
                "the registration could not be recorded right now; retry shortly".to_owned()
            }
        }
    }

    /// The `WWW-Authenticate` challenge of a `401`: without an error code
    /// when the request sent no token (RFC 6750 §3.1), else
    /// `invalid_token`.
    pub fn www_authenticate(&self) -> Option<&'static str> {
        match self {
            Self::TokenRequired => Some("Bearer"),
            Self::InvalidToken(_) => Some("Bearer error=\"invalid_token\""),
            _ => None,
        }
    }

    /// The RFC 7591 §3.2.2 error body.
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.error(),
            "error_description": error_description(&self.description()),
        })
    }

    /// The `mcpg_as_dcr_total` outcome.
    fn outcome(&self) -> &'static str {
        match self {
            Self::NotOffered => "not_offered",
            Self::TokenRequired => "token_required",
            Self::InvalidToken(_) => "invalid_token",
            Self::InvalidRedirectUri(_) => "invalid_redirect_uri",
            Self::InvalidClientMetadata(_) => "invalid_client_metadata",
            Self::RateLimited { .. } => "rate_limited",
            Self::TooManyClients => "too_many_clients",
            Self::Unavailable => "error",
        }
    }
}

/// A client this request registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredClient {
    pub record: DcrClientRecord,
}

impl RegisteredClient {
    /// The RFC 7591 §3.2.1 response: every member kept, and the
    /// authentication method the client uses. No secret: the client is
    /// public.
    pub fn body(&self) -> serde_json::Value {
        let record = &self.record;
        let mut body = serde_json::json!({
            "client_id": record.client_id,
            "client_id_issued_at": record.client_id_issued_at,
            "redirect_uris": record.redirect_uris,
            "grant_types": record.grant_types,
            "response_types": record.response_types,
            "token_endpoint_auth_method": AUTH_METHOD_NONE,
        });
        if let Some(ref name) = record.client_name {
            body["client_name"] = serde_json::json!(name);
        }
        if let Some(ref application_type) = record.application_type {
            body["application_type"] = serde_json::json!(application_type);
        }
        if record.dpop_bound_access_tokens {
            body["dpop_bound_access_tokens"] = serde_json::json!(true);
        }
        body
    }
}

/// The outcome of one `POST /oauth/register` request.
#[derive(Debug)]
pub struct ClientRegistration {
    pub result: Result<RegisteredClient, RegistrationError>,
    /// How it was authorized, once that was checked.
    pub authorized_by: Option<AuthorizedBy>,
}

impl ClientRegistration {
    /// A request body the endpoint cannot read.
    pub fn malformed(description: String) -> Self {
        let registration = Self {
            result: Err(RegistrationError::InvalidClientMetadata(description)),
            authorized_by: None,
        };
        registration.record();
        registration
    }

    fn record(&self) {
        let outcome = match self.result {
            Ok(_) => "registered",
            Err(ref error) => error.outcome(),
        };
        metrics::counter!("mcpg_as_dcr_total", "outcome" => outcome).increment(1);
    }

    /// The audit record of the request: `mcpg.as.client_registered`, or
    /// `mcpg.auth.failed` with `auth_method` `as_register`. `None` for a
    /// request over the hourly allowance, which a flood would otherwise
    /// write to the audit log, and for one while registration is off.
    pub fn audit_event(&self, request_id: &str) -> Option<mcpg_plugin_protocol::audit::AuditEvent> {
        use mcpg_plugin_host::audit_events::{new_event_id, now_rfc3339_utc, system_identity};
        use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
        let authorized_by = self.authorized_by.map(AuthorizedBy::as_str);
        match self.result {
            Ok(ref registered) => {
                let record = &registered.record;
                Some(AuditEvent {
                    event_id: new_event_id(),
                    occurred_at: now_rfc3339_utc(),
                    actor: system_identity(),
                    action: "mcpg.as.client_registered".into(),
                    resource: None,
                    outcome: AuditOutcome::Success,
                    request_id: Some(request_id.to_owned()),
                    upstream_request_id: None,
                    node_id: None,
                    details: serde_json::json!({
                        "client_id": record.client_id,
                        "client_name": record.client_name,
                        "redirect_uris": record.redirect_uris,
                        "grant_types": record.grant_types,
                        "authorized_by": authorized_by,
                    }),
                    prev_event_hash: None,
                })
            }
            Err(RegistrationError::RateLimited { .. } | RegistrationError::NotOffered) => None,
            Err(ref error) => {
                let mut event = mcpg_plugin_host::audit_events::auth_failed_event(
                    "as_register",
                    &format!("{}: {}", error.error(), error.description()),
                    request_id,
                    "http",
                );
                event.details["error"] = serde_json::json!(error.error());
                event.details["authorized_by"] = serde_json::json!(authorized_by);
                Some(event)
            }
        }
    }
}

/// What a registration keeps of a request.
#[derive(Debug)]
pub(super) struct RegistrationMetadata {
    pub(super) redirect_uris: Vec<String>,
    pub(super) grant_types: Vec<String>,
    pub(super) response_types: Vec<String>,
    pub(super) client_name: Option<String>,
    pub(super) application_type: Option<String>,
    /// RFC 9449 §5.2, as sent; read only while DPoP is on.
    pub(super) dpop_bound_access_tokens: Option<serde_json::Value>,
}

/// A member that must be an array of strings: `Ok(None)` when absent or
/// `null`, the text of the refusal when of another shape.
fn string_list(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{name} holds an entry that is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("{name} must be an array of strings")),
    }
}

/// `values` without repeats, in order.
fn distinct(values: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        if !kept.contains(&value) {
            kept.push(value);
        }
    }
    kept
}

/// The registration a request body asks for, checked against `config`.
pub(super) fn parse_registration(
    body: &[u8],
    config: &DynamicClientRegistrationConfig,
) -> Result<RegistrationMetadata, RegistrationError> {
    use RegistrationError::{InvalidClientMetadata, InvalidRedirectUri};
    if body.len() > MAX_REGISTRATION_BYTES {
        return Err(InvalidClientMetadata(format!(
            "the registration request exceeds {MAX_REGISTRATION_BYTES} bytes"
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| InvalidClientMetadata("the registration request is not JSON".to_owned()))?;
    let object = value.as_object().ok_or_else(|| {
        InvalidClientMetadata("the registration request must be a JSON object".to_owned())
    })?;
    match object.get("token_endpoint_auth_method") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(method)) if method == AUTH_METHOD_NONE => {}
        Some(serde_json::Value::String(method)) => {
            return Err(InvalidClientMetadata(format!(
                "token_endpoint_auth_method {} is not offered: a registered client is public, \
                 uses none, and proves itself with PKCE",
                echo(method)
            )));
        }
        Some(_) => {
            return Err(InvalidClientMetadata(
                "token_endpoint_auth_method must be a string".to_owned(),
            ));
        }
    }
    let redirect_uris = string_list(object, "redirect_uris")
        .map_err(InvalidRedirectUri)?
        .ok_or_else(|| InvalidRedirectUri("redirect_uris is required".to_owned()))?;
    if redirect_uris.is_empty() {
        return Err(InvalidRedirectUri(
            "redirect_uris must list at least one URI".to_owned(),
        ));
    }
    let redirect_uris = distinct(redirect_uris);
    if redirect_uris.len() > MAX_REGISTERED_REDIRECT_URIS {
        return Err(InvalidRedirectUri(format!(
            "redirect_uris may list at most {MAX_REGISTERED_REDIRECT_URIS} URIs"
        )));
    }
    // An `https://` URI on a host the operator does not admit is left out
    // (RFC 7591 §3.2.1 lets the server replace requested values), so a
    // client that also lists loopback URIs still registers; any other
    // problem refuses the request.
    let mut kept = Vec::with_capacity(redirect_uris.len());
    let mut left_out: Option<String> = None;
    for uri in redirect_uris {
        match registration_redirect(&uri, |host| config.admits_redirect_host(host)) {
            Ok(_) => kept.push(uri),
            Err(problem) => {
                let refusal = format!("redirect_uri {} {problem}", echo(&uri));
                if !RegisteredRedirect::parse(&uri)
                    .is_ok_and(|registered| registered.kind == RedirectUriKind::Https)
                {
                    return Err(InvalidRedirectUri(refusal));
                }
                left_out.get_or_insert(refusal);
            }
        }
    }
    if kept.is_empty() {
        return Err(InvalidRedirectUri(left_out.unwrap_or_else(|| {
            "redirect_uris must list at least one URI".to_owned()
        })));
    }
    let redirect_uris = kept;
    let grant_types = distinct(
        string_list(object, "grant_types")
            .map_err(InvalidClientMetadata)?
            .unwrap_or_else(|| vec![ClientGrantType::AuthorizationCode.as_str().to_owned()]),
    );
    let offered = [
        ClientGrantType::AuthorizationCode.as_str(),
        ClientGrantType::RefreshToken.as_str(),
    ];
    if let Some(other) = grant_types
        .iter()
        .find(|grant| !offered.contains(&grant.as_str()))
    {
        return Err(InvalidClientMetadata(format!(
            "grant_type {} is not offered to a registered client, which may use \
             authorization_code and refresh_token",
            echo(other)
        )));
    }
    if !grant_types
        .iter()
        .any(|grant| grant == ClientGrantType::AuthorizationCode.as_str())
    {
        return Err(InvalidClientMetadata(
            "grant_types must include authorization_code, the grant a registered client signs \
             in with"
                .to_owned(),
        ));
    }
    let response_types = distinct(
        string_list(object, "response_types")
            .map_err(InvalidClientMetadata)?
            .unwrap_or_else(|| vec![RESPONSE_TYPE_CODE.to_owned()]),
    );
    if response_types.as_slice() != [RESPONSE_TYPE_CODE] {
        return Err(InvalidClientMetadata(
            "response_types must be [\"code\"]".to_owned(),
        ));
    }
    let client_name = match object.get("client_name") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) => client_display_name(name),
        Some(_) => {
            return Err(InvalidClientMetadata(
                "client_name must be a string".to_owned(),
            ));
        }
    };
    let application_type = object
        .get("application_type")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| matches!(*kind, "web" | "native"))
        .map(str::to_owned);
    Ok(RegistrationMetadata {
        redirect_uris,
        grant_types,
        response_types,
        client_name,
        application_type,
        dpop_bound_access_tokens: object.get("dpop_bound_access_tokens").cloned(),
    })
}

/// Whether the registration `metadata` binds every token of its client to
/// a DPoP key (RFC 9449 §5.2): while DPoP is on, its member, which must be
/// a boolean; while DPoP is off, never.
fn dpop_bound(
    metadata: &RegistrationMetadata,
    dpop_enabled: bool,
) -> Result<bool, RegistrationError> {
    match metadata.dpop_bound_access_tokens {
        _ if !dpop_enabled => Ok(false),
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(bound)) => Ok(bound),
        Some(_) => Err(RegistrationError::InvalidClientMetadata(
            "dpop_bound_access_tokens must be a boolean".to_owned(),
        )),
    }
}

/// What an address is counted by per hour: an IPv4 address, or the /64 of
/// an IPv6 one, which one host commonly holds whole.
pub(super) fn rate_subject(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// What a token or revocation request presents that names a grant of its
/// client.
#[derive(Clone, Copy)]
pub(super) enum Presented<'a> {
    RefreshToken(&'a str),
    Code(&'a str),
    AccessToken(&'a str),
}

fn unavailable(error: StateError) -> RegistrationError {
    tracing::error!(error = %error, "a client registration could not be recorded");
    RegistrationError::Unavailable
}

impl AuthorizationServer {
    /// Whether `POST /oauth/register` is offered: a login IdP, and
    /// `interactive.dynamic_client_registration.enabled`.
    pub fn registers_clients(&self) -> bool {
        self.interactive.dynamic_client_registration.enabled && self.login_idp().is_some()
    }

    /// Answer `POST /oauth/register` with the request `body`, the raw
    /// `Authorization` header value and the client address, when known.
    /// The caller has checked the address's per-minute budget.
    pub async fn register_client(
        &self,
        body: &[u8],
        authorization: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> ClientRegistration {
        let mut authorized_by = None;
        let result = self
            .register(body, authorization, client_ip, &mut authorized_by)
            .await;
        let registration = ClientRegistration {
            result,
            authorized_by,
        };
        registration.record();
        registration
    }

    async fn register(
        &self,
        body: &[u8],
        authorization: Option<&str>,
        client_ip: Option<IpAddr>,
        authorized_by: &mut Option<AuthorizedBy>,
    ) -> Result<RegisteredClient, RegistrationError> {
        if !self.registers_clients() {
            return Err(RegistrationError::NotOffered);
        }
        let state = self
            .grant_state()
            .map_err(|_| RegistrationError::Unavailable)?;
        *authorized_by = Some(self.authorize_registration(authorization)?);
        let config = &self.interactive.dynamic_client_registration;
        let metadata = parse_registration(body, config)?;
        let dpop_bound_access_tokens = dpop_bound(&metadata, self.dpop_enabled())?;
        let now = now_unix();
        let hourly = self.take_hourly_slot(state, client_ip, now).await?;
        if let Err(error) = self.take_client_slot(state).await {
            release(state, hourly.as_ref(), false).await;
            return Err(error);
        }
        let stored = async {
            let client_id = format!(
                "{DCR_CLIENT_ID_PREFIX}{}",
                hex::encode(random_bytes::<16>()?)
            );
            let record = DcrClientRecord {
                client_id,
                client_id_issued_at: now,
                client_name: metadata.client_name,
                redirect_uris: metadata.redirect_uris,
                grant_types: metadata.grant_types,
                response_types: metadata.response_types,
                application_type: metadata.application_type,
                dpop_bound_access_tokens,
            };
            let Some(key) = keys::dcr_client(&record.client_id) else {
                return Ok(None);
            };
            let ttl = Duration::from_secs(config.client_ttl_secs);
            Ok::<_, StateError>(
                state
                    .put_if_absent(&key, &record, ttl)
                    .await?
                    .then_some(record),
            )
        }
        .await;
        match stored {
            Ok(Some(record)) => {
                tracing::info!(
                    client_id = %record.client_id,
                    authorized_by = authorized_by.map_or("", AuthorizedBy::as_str),
                    "a client registered itself"
                );
                Ok(RegisteredClient { record })
            }
            Ok(None) => {
                tracing::error!("a client registration collided with another; refusing it");
                release(state, hourly.as_ref(), true).await;
                Err(RegistrationError::Unavailable)
            }
            Err(error) => {
                release(state, hourly.as_ref(), true).await;
                Err(unavailable(error))
            }
        }
    }

    /// How the request is authorized: an initial access token the operator
    /// listed, compared as a digest against every listed one in constant
    /// time, or none where `allow_open` accepts that. A token that is not
    /// listed is refused either way.
    fn authorize_registration(
        &self,
        authorization: Option<&str>,
    ) -> Result<AuthorizedBy, RegistrationError> {
        let Some(header) = authorization else {
            return if self.interactive.dynamic_client_registration.allow_open {
                Ok(AuthorizedBy::Open)
            } else {
                Err(RegistrationError::TokenRequired)
            };
        };
        let token = header
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
            .ok_or(RegistrationError::InvalidToken(
                "the Authorization header must carry the initial access token as Bearer <token>",
            ))?;
        let presented = digest(token);
        let listed = self
            .registration_token_digests
            .iter()
            .fold(subtle::Choice::from(0), |found, listed| {
                found | listed.as_slice().ct_eq(presented.as_slice())
            });
        if bool::from(listed) {
            Ok(AuthorizedBy::InitialAccessToken)
        } else {
            Err(RegistrationError::InvalidToken(
                "the initial access token is not valid",
            ))
        }
    }

    /// Count this registration against the client address's allowance for
    /// the current clock hour; the counter taken, which a registration
    /// that fails later gives back. An address that cannot be told is not
    /// counted, as on the token endpoint.
    async fn take_hourly_slot(
        &self,
        state: &InteractiveState,
        client_ip: Option<IpAddr>,
        now: u64,
    ) -> Result<Option<CounterKey>, RegistrationError> {
        let limit = self
            .interactive
            .dynamic_client_registration
            .registrations_per_hour_per_ip;
        let Some(ip) = client_ip.filter(|_| limit > 0) else {
            return Ok(None);
        };
        let hour = now / RATE_WINDOW_SECS;
        let key = keys::dcr_rate(&rate_subject(ip), hour);
        let taken = state
            .incr(&key, 1, Some(Duration::from_secs(2 * RATE_WINDOW_SECS)))
            .await
            .map_err(unavailable)?;
        if taken > i64::from(limit) {
            let _ = state.incr(&key, -1, None).await;
            return Err(RegistrationError::RateLimited {
                retry_after_secs: ((hour + 1) * RATE_WINDOW_SECS).saturating_sub(now).max(1),
            });
        }
        Ok(Some(key))
    }

    /// Count this registration against `max_clients`. The counter grows
    /// with each registration while expired ones leave the store on their
    /// own, so once it passes the limit the registrations are counted
    /// again from the store, at most once a minute across replicas.
    async fn take_client_slot(&self, state: &InteractiveState) -> Result<(), RegistrationError> {
        let max = i64::from(self.interactive.dynamic_client_registration.max_clients);
        let counter = keys::dcr_count();
        let counted = state.incr(&counter, 1, None).await.map_err(unavailable)?;
        if counted <= max {
            return Ok(());
        }
        let recounted = match state
            .claim_once(&keys::dcr_recount(), RECOUNT_SPACING)
            .await
        {
            Ok(true) => {
                let limit = usize::try_from(max).unwrap_or(usize::MAX).saturating_add(1);
                match state.count(&keys::dcr_clients(), limit).await {
                    Ok(live) => {
                        let live = i64::try_from(live).unwrap_or(i64::MAX);
                        state
                            .incr(&counter, live.saturating_add(1) - counted, None)
                            .await
                            .ok()
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "the client registrations could not be counted again"
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        match recounted {
            Some(counted) if counted <= max => Ok(()),
            _ => {
                let _ = state.incr(&counter, -1, None).await;
                Err(RegistrationError::TooManyClients)
            }
        }
    }

    /// The dynamically registered client `client_id`; `None` when it is not
    /// registered. Reading it does not restart its registration's
    /// lifetime: its client id is public, and only a use that succeeds
    /// ([`Self::renew_registration`]) keeps it.
    pub(super) async fn registered_client(
        &self,
        client_id: &str,
    ) -> Result<Option<Client>, StateError> {
        let Some(key) = keys::dcr_client(client_id) else {
            return Ok(None);
        };
        let state = self
            .interactive_state
            .as_ref()
            .filter(|state| state.is_available())
            .ok_or_else(|| {
                StateError::Store(mcpg_cluster_api::ClusterError::BackendUnavailable {
                    reason: "the sign-in state store is unavailable".to_owned(),
                })
            })?;
        let Some(record) = state
            .get(&key)
            .await?
            .filter(|record| record.client_id == client_id)
        else {
            return Ok(None);
        };
        Ok(Some(Client::from_registration(
            &record,
            &self.interactive.dynamic_client_registration,
        )))
    }

    /// Restart the lifetime of the registration of `client_id`, when it
    /// names one, after the client used it successfully: a code issued to
    /// it, a code or refresh token it redeemed, or a token of its own it
    /// revoked. A failure only leaves the lifetime running.
    pub(super) async fn renew_registration(&self, client_id: &str) {
        if !client_id.starts_with(DCR_CLIENT_ID_PREFIX) || !self.registers_clients() {
            return;
        }
        let (Some(key), Some(state)) = (keys::dcr_client(client_id), self.sign_in_state()) else {
            return;
        };
        let ttl = Duration::from_secs(self.interactive.dynamic_client_registration.client_ttl_secs);
        if let Err(error) = state.touch(&key, ttl).await {
            tracing::warn!(
                client_id = %client_id,
                error = %error,
                "a client registration's lifetime could not be restarted"
            );
        }
    }

    /// When `client_id` names a dynamic registration that is gone while
    /// registration is on, revoke the grant `presented` names if it is
    /// that client's; the audit record. A failed read revokes nothing.
    pub(super) async fn end_removed_registration(
        &self,
        client_id: Option<&str>,
        presented: Presented<'_>,
    ) -> Option<GrantEvent> {
        let client_id = client_id.filter(|id| id.starts_with(DCR_CLIENT_ID_PREFIX))?;
        if !self.registers_clients() {
            return None;
        }
        let state = self.grant_state().ok()?;
        if state.exists(&keys::dcr_client(client_id)?).await.ok()? {
            return None;
        }
        let gid = self.presented_grant(state, presented).await?;
        let grant = state.get(&keys::grant(&gid)).await.ok()??;
        if grant.client_id != client_id {
            return None;
        }
        tracing::info!(
            client_id = %client_id,
            gid = %gid,
            "a removed client registration presented its grant; revoking it"
        );
        Some(
            self.revoke_grant(state, &gid, RevocationReason::ClientRemoved)
                .await,
        )
    }

    /// The grant `presented` names, read without checking its client.
    async fn presented_grant(
        &self,
        state: &InteractiveState,
        presented: Presented<'_>,
    ) -> Option<GrantId> {
        match presented {
            Presented::RefreshToken(token) => {
                if !token.starts_with(REFRESH_TOKEN_PREFIX)
                    || token.len() > MAX_PRESENTED_HANDLE_BYTES
                {
                    return None;
                }
                match state.get(&keys::refresh(token)).await.ok()? {
                    Some(index) => Some(index.gid),
                    None => state
                        .get(&keys::refresh_used(token))
                        .await
                        .ok()?
                        .map(|spent| spent.gid),
                }
            }
            Presented::Code(code) => {
                if !code.starts_with(AUTHORIZATION_CODE_PREFIX)
                    || code.len() > MAX_PRESENTED_HANDLE_BYTES
                {
                    return None;
                }
                state
                    .get(&keys::code(code))
                    .await
                    .ok()?
                    .map(|record| record.gid)
            }
            Presented::AccessToken(token) => {
                if token.len() > MAX_PRESENTED_TOKEN_BYTES
                    || unverified_claim_iss(token).is_none_or(|iss| iss != self.issuer)
                {
                    return None;
                }
                self.decode_minted_with(token, false).ok()?.gid
            }
        }
    }
}

/// Give back the hourly counter `hourly` and, with `client`, the one of
/// `max_clients`, taken for a registration that was not recorded.
async fn release(state: &InteractiveState, hourly: Option<&CounterKey>, client: bool) {
    if let Some(key) = hourly {
        let _ = state.incr(key, -1, None).await;
    }
    if client {
        let _ = state.incr(&keys::dcr_count(), -1, None).await;
    }
}
