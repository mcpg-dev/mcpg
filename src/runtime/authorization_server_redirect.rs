//! Redirect URIs, PKCE and client resolution at the authorization
//! endpoint.
//!
//! A redirect URI is registered with the syntax of [`redirect_uri_kind`]:
//! `https://` on any host, or `http://` on a loopback host written as
//! `127.0.0.1`, `[::1]` or `localhost`. A requested URI matches a
//! registered one byte for byte (RFC 9700 §2.1), except on loopback: there
//! both name the same loopback host as written, the port is ignored on
//! both sides (RFC 8252 §7.3), an empty path reads as `/`, and the path and
//! query are compared as written. The authorization response goes to the
//! requested string as sent. Before the user approved, an error may be
//! redirected only to a trusted URI: a registered client's `https://` one,
//! or any loopback one.
//!
//! PKCE (RFC 7636) is required of every client, with `S256` only.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::state::ClientKind;
use super::{OAuthError, ct_eq};
use crate::config::interactive_login::loopback_path_and_query;
pub use crate::config::interactive_login::{
    LoopbackHost, MAX_REDIRECT_URI_BYTES, RedirectUriKind, redirect_uri_kind,
};
use crate::config::{ClientConsent, ClientIdMetadataDocumentsConfig, RedirectUriPolicy};

/// The PKCE transformation this server accepts; `plain` is refused, as it
/// gives no protection once the challenge is seen (RFC 9700 §2.1.1).
pub const PKCE_METHOD_S256: &str = "S256";
/// Length of an `S256` code challenge: base64url of 32 bytes, unpadded.
const S256_CHALLENGE_CHARS: usize = 43;
/// Lengths of a code verifier (RFC 7636 §4.1).
const CODE_VERIFIER_CHARS: std::ops::RangeInclusive<usize> = 43..=128;
/// Longest self-asserted client name shown, in characters.
pub const MAX_CLIENT_NAME_CHARS: usize = 80;

// ---------------------------------------------------------------------------
// Registered and requested redirect URIs
// ---------------------------------------------------------------------------

/// A redirect URI a client registered, and where it sends the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredRedirect {
    pub uri: String,
    pub kind: RedirectUriKind,
}

impl RegisteredRedirect {
    /// `uri`, if it has the registration syntax; else why not, reading
    /// after the URI.
    pub fn parse(uri: &str) -> Result<Self, String> {
        Ok(Self {
            kind: redirect_uri_kind(uri)?,
            uri: uri.to_owned(),
        })
    }
}

/// Whether the redirect URI an authorization request names, `requested`,
/// matches `registered`. `requested` must itself have the registration
/// syntax. Two loopback URIs match when they name the same loopback host
/// as written and have the same path (an empty one reads as `/`) and the
/// same query, whatever their ports; any other pair only when equal byte
/// for byte, without case folding, default-port removal or
/// percent-decoding.
pub fn redirect_uri_matches(registered: &RegisteredRedirect, requested: &str) -> bool {
    let Ok(kind) = redirect_uri_kind(requested) else {
        return false;
    };
    match (registered.kind, kind) {
        (RedirectUriKind::Loopback(ours), RedirectUriKind::Loopback(theirs)) if ours == theirs => {
            loopback_path_and_query(&registered.uri) == loopback_path_and_query(requested)
        }
        _ => registered.uri == requested,
    }
}

/// Whether an error may be redirected to a URI of `kind` before the user
/// approved the request: a registered client's `https://` URI, which the
/// operator vetted, or a loopback URI, which stays on the user's computer.
/// A metadata document's or a registration's `https://` URI is
/// self-asserted.
pub fn redirect_is_trusted(client: ClientKind, kind: RedirectUriKind) -> bool {
    match kind {
        RedirectUriKind::Loopback(_) => true,
        RedirectUriKind::Https => client == ClientKind::Static,
    }
}

/// `uri`, listed by the metadata document at a `client_id` on
/// `client_host`, if `config` admits it: the registration syntax, and for
/// an `https://` URI the host `redirect_uri_policy` allows. A loopback URI
/// is always admitted. The reason reads after the URI.
pub fn document_redirect(
    uri: &str,
    client_host: &str,
    config: &ClientIdMetadataDocumentsConfig,
) -> Result<RegisteredRedirect, String> {
    let registered = RegisteredRedirect::parse(uri)?;
    if registered.kind != RedirectUriKind::Https {
        return Ok(registered);
    }
    let host = url::Url::parse(uri)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    match config.redirect_uri_policy {
        RedirectUriPolicy::SameHost if host.is_empty() || host != client_host => Err(format!(
            "is on host `{host}`, and redirect_uri_policy same_host admits only `{client_host}`, \
             the host of the client_id"
        )),
        RedirectUriPolicy::AllowedHosts if !config.admits_host(&host) => Err(format!(
            "is on host `{host}`, which client_id_metadata_documents.allowed_hosts does not admit"
        )),
        _ => Ok(registered),
    }
}

/// `uri`, listed by a dynamic registration, if it is admitted: the
/// registration syntax, and for an `https://` URI a host `admits_host`
/// accepts (lower-case). A loopback URI is always admitted. The reason
/// reads after the URI.
pub fn registration_redirect(
    uri: &str,
    admits_host: impl Fn(&str) -> bool,
) -> Result<RegisteredRedirect, String> {
    let registered = RegisteredRedirect::parse(uri)?;
    if registered.kind != RedirectUriKind::Https {
        return Ok(registered);
    }
    let host = url::Url::parse(uri)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    if host.is_empty() || !admits_host(&host) {
        return Err(format!(
            "is on host `{host}`, which dynamic_client_registration.allowed_redirect_hosts does \
             not admit; a registration may use loopback redirect URIs and https:// on the hosts \
             the operator lists"
        ));
    }
    Ok(registered)
}

/// The redirect URIs a client registered: the usable ones, the ones a
/// metadata document lists but this server refuses (never matched), and
/// how many were listed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectRegistration {
    usable: Vec<RegisteredRedirect>,
    refused: Vec<(String, String)>,
    listed: usize,
}

impl RedirectRegistration {
    /// A registered client's `redirect_uris`, each of which must have the
    /// registration syntax.
    pub fn from_uris(uris: &[String]) -> Result<Self, String> {
        let usable = uris
            .iter()
            .map(|uri| {
                RegisteredRedirect::parse(uri).map_err(|problem| format!("`{uri}` {problem}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            listed: usable.len(),
            usable,
            refused: Vec::new(),
        })
    }

    /// The `redirect_uris` entries of the metadata document at
    /// `client_id`, each admitted by [`document_redirect`] or set aside
    /// with the reason.
    pub fn from_document(
        entries: &[&str],
        client_id: &str,
        config: &ClientIdMetadataDocumentsConfig,
    ) -> Self {
        let client_host = url::Url::parse(client_id)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_default();
        let mut registration = Self {
            listed: entries.len(),
            ..Self::default()
        };
        for &uri in entries {
            match document_redirect(uri, &client_host, config) {
                Ok(registered) => registration.usable.push(registered),
                Err(reason) => registration.refused.push((uri.to_owned(), reason)),
            }
        }
        registration
    }

    /// The `redirect_uris` of a dynamic registration, each admitted by
    /// [`registration_redirect`] under `admits_host` or set aside with the
    /// reason: a host no longer admitted stops matching.
    pub fn from_registration(entries: &[String], admits_host: impl Fn(&str) -> bool) -> Self {
        let mut registration = Self {
            listed: entries.len(),
            ..Self::default()
        };
        for uri in entries {
            match registration_redirect(uri, &admits_host) {
                Ok(registered) => registration.usable.push(registered),
                Err(reason) => registration.refused.push((uri.clone(), reason)),
            }
        }
        registration
    }

    /// The redirect URIs a request may name.
    pub fn usable(&self) -> &[RegisteredRedirect] {
        &self.usable
    }

    /// The listed redirect URIs this server refuses, with why.
    pub fn refused(&self) -> &[(String, String)] {
        &self.refused
    }

    /// Whether every listed redirect URI is a usable `https://` one.
    pub fn all_https(&self) -> bool {
        self.listed > 0
            && self.usable.len() == self.listed
            && self
                .usable
                .iter()
                .all(|registered| registered.kind == RedirectUriKind::Https)
    }

    /// The redirect URI of an authorization request of a `client` with
    /// this registration that names `requested`, empty meaning absent
    /// (RFC 6749 §3.1). A request may omit it only when exactly one URI is
    /// listed and it is not loopback, whose port only the request knows
    /// (OAuth 2.1 §4.1.1).
    pub fn resolve(
        &self,
        client: ClientKind,
        requested: Option<&str>,
    ) -> Result<ResolvedRedirect, RedirectError> {
        let chosen = match requested.filter(|uri| !uri.is_empty()) {
            None => match self.usable.as_slice() {
                [only] if self.listed == 1 && only.kind == RedirectUriKind::Https => only.clone(),
                _ => return Err(RedirectError::Required),
            },
            Some(requested) => {
                let kind = redirect_uri_kind(requested).map_err(RedirectError::Invalid)?;
                if !self
                    .usable
                    .iter()
                    .any(|registered| redirect_uri_matches(registered, requested))
                {
                    return Err(self
                        .refused
                        .iter()
                        .find(|(uri, _)| uri == requested)
                        .map_or(RedirectError::NotRegistered, |(_, reason)| {
                            RedirectError::Refused(reason.clone())
                        }));
                }
                RegisteredRedirect {
                    uri: requested.to_owned(),
                    kind,
                }
            }
        };
        Ok(ResolvedRedirect {
            trusted: redirect_is_trusted(client, chosen.kind),
            uri: chosen.uri,
            kind: chosen.kind,
        })
    }
}

/// The redirect URI an authorization request resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRedirect {
    /// Where the response goes: the requested string byte for byte, or
    /// the one registered URI when the request named none. The code is
    /// bound to it.
    pub uri: String,
    pub kind: RedirectUriKind,
    /// Whether an error may be redirected to it before the user approved
    /// ([`redirect_is_trusted`]).
    pub trusted: bool,
}

/// Why the redirect URI of an authorization request is refused. The
/// request is answered with a page, never a redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectError {
    /// The request names none, and the client registered several or a
    /// loopback one.
    Required,
    /// The URI does not have the registration syntax; the reason reads
    /// after the URI.
    Invalid(String),
    /// It matches no redirect URI the client registered.
    NotRegistered,
    /// The client's metadata document or dynamic registration lists it,
    /// but this server refuses it; the reason reads after the URI.
    Refused(String),
}

impl RedirectError {
    /// What the page says.
    pub fn description(&self) -> String {
        match self {
            Self::Required => "redirect_uri is required: the client registered more than one \
                               redirect URI, or a loopback one whose port only the request names"
                .to_owned(),
            Self::Invalid(problem) => format!("redirect_uri {problem}"),
            Self::NotRegistered => {
                "redirect_uri is not registered for this client; it must match a registered \
                 redirect URI exactly"
                    .to_owned()
            }
            Self::Refused(reason) => format!(
                "redirect_uri is listed by the client's metadata document or registration, but \
                 refused: it {reason}"
            ),
        }
    }
}

/// `redirect_uri` with `params` appended as a form-encoded query: after
/// `?`, or after `&` when it already has a query, which is kept (RFC 6749
/// §3.1.2).
pub fn with_response_params(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let mut out = String::with_capacity(redirect_uri.len() + 1 + encoded.len());
    out.push_str(redirect_uri);
    if !encoded.is_empty() {
        match redirect_uri.find('?') {
            None => out.push('?'),
            Some(at) if at + 1 == redirect_uri.len() || redirect_uri.ends_with('&') => {}
            Some(_) => out.push('&'),
        }
        out.push_str(&encoded);
    }
    out
}

// ---------------------------------------------------------------------------
// The client of an authorization request
// ---------------------------------------------------------------------------

/// Whether the consent page is shown before sign-in, as the client and its
/// redirect URI decide; `prompt=consent` shows it in any case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentRule {
    /// Not shown: a registered client with `consent: skip` (`explicit`),
    /// or with `auto` and only `https://` redirect URIs. A request for
    /// authorization details is shown unless `explicit`.
    Skip { explicit: bool },
    /// Shown, unless `rememberable` and an approval the browser's consent
    /// memory holds covers the request. Only an `https://` redirect URI of
    /// a registered or metadata document client is remembered: any program
    /// on the user's computer can receive a loopback one, and a
    /// registration is self-asserted.
    Ask { rememberable: bool },
}

/// The consent rule of a `client` with `setting` (read for registered
/// clients only) and `registration`, for a request redirected to `redirect`.
pub fn consent_rule(
    client: ClientKind,
    setting: ClientConsent,
    registration: &RedirectRegistration,
    redirect: RedirectUriKind,
) -> ConsentRule {
    let https = redirect == RedirectUriKind::Https;
    match client {
        ClientKind::Static => match setting {
            ClientConsent::Skip => ConsentRule::Skip { explicit: true },
            ClientConsent::Auto if registration.all_https() => {
                ConsentRule::Skip { explicit: false }
            }
            ClientConsent::Auto => ConsentRule::Ask {
                rememberable: https,
            },
            ClientConsent::Always => ConsentRule::Ask {
                rememberable: false,
            },
        },
        ClientKind::Cimd => ConsentRule::Ask {
            rememberable: https,
        },
        ClientKind::Dcr => ConsentRule::Ask {
            rememberable: false,
        },
    }
}

/// A client allowed to sign a user in, with the redirect URI its
/// authorization request resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeClient {
    pub client_id: String,
    pub kind: ClientKind,
    /// The name the consent page shows; `None` shows the `client_id`. A
    /// document's or a registration's is self-asserted
    /// ([`client_display_name`]).
    pub name: Option<String>,
    /// The `application_type` a document or registration declares; it is
    /// recorded, not acted on.
    pub application_type: Option<String>,
    pub redirect: ResolvedRedirect,
    /// Whether the client may use `refresh_token`.
    pub refresh_allowed: bool,
    pub consent: ConsentRule,
}

/// Why the client of an authorization request cannot sign a user in. It is
/// answered with a page, never a redirect: the redirect URI is not
/// validated yet, or is the problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeClientError {
    /// The request names no `client_id`.
    MissingClientId,
    /// No registered client, and no metadata document URL this server
    /// resolves.
    UnknownClient,
    /// The client may not use the authorization code grant (RFC 6749
    /// §5.2 `unauthorized_client`); the text says why.
    Unauthorized(String),
    /// The client's metadata document is refused, or lacks what the
    /// authorization endpoint needs; the text says why.
    InvalidDocument(String),
    /// The client's metadata document cannot be fetched now: retryable.
    DocumentUnavailable,
    /// The client's dynamic registration cannot be read now: retryable.
    RegistrationUnavailable,
    Redirect(RedirectError),
}

impl AuthorizeClientError {
    /// The HTTP status of the page: 503 while a document or a
    /// registration cannot be read, else 400.
    pub fn status(&self) -> u16 {
        match self {
            Self::DocumentUnavailable | Self::RegistrationUnavailable => 503,
            _ => 400,
        }
    }

    /// The OAuth error code, for metrics and audit.
    pub fn error(&self) -> &'static str {
        match self {
            Self::MissingClientId | Self::Redirect(_) => "invalid_request",
            Self::UnknownClient | Self::InvalidDocument(_) => "invalid_client",
            Self::Unauthorized(_) => "unauthorized_client",
            Self::DocumentUnavailable | Self::RegistrationUnavailable => "temporarily_unavailable",
        }
    }

    /// What the page says.
    pub fn description(&self) -> String {
        match self {
            Self::MissingClientId => "the request names no client_id".to_owned(),
            Self::UnknownClient => "the client_id names no client this server knows".to_owned(),
            Self::Unauthorized(reason) => {
                format!("the client may not sign users in here: {reason}")
            }
            Self::InvalidDocument(reason) => {
                format!("the client's metadata document cannot be used to sign in: {reason}")
            }
            Self::DocumentUnavailable => {
                "the client's metadata document cannot be fetched right now; retry shortly"
                    .to_owned()
            }
            Self::RegistrationUnavailable => {
                "the client's registration cannot be read right now; retry shortly".to_owned()
            }
            Self::Redirect(problem) => problem.description(),
        }
    }
}

impl std::fmt::Display for AuthorizeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.description())
    }
}

/// A self-asserted client name as a page may show it: control, format and
/// bidirectional characters removed, runs of whitespace folded to one
/// space, at most [`MAX_CLIENT_NAME_CHARS`] characters. `None` when nothing
/// printable is left.
pub fn client_display_name(raw: &str) -> Option<String> {
    let visible: String = raw.chars().filter(|&c| !is_invisible(c)).collect();
    let folded: String = visible
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_CLIENT_NAME_CHARS)
        .collect();
    let name = folded.trim_end();
    (!name.is_empty()).then(|| name.to_owned())
}

/// Control characters, and the format characters that hide text or turn
/// its direction (soft hyphen, zero-width and bidirectional marks,
/// embeddings, isolates and overrides, the byte order mark).
pub fn is_invisible(c: char) -> bool {
    (c.is_control() && !c.is_whitespace())
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// Why a PKCE parameter is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceError {
    /// The authorization request carries no `code_challenge`.
    ChallengeMissing,
    /// `code_challenge_method` is not `S256`; absent means `plain`.
    MethodUnsupported,
    /// The challenge is not 43 base64url characters.
    ChallengeMalformed,
    /// The token request carries no `code_verifier`.
    VerifierMissing,
    /// The verifier is not 43 to 128 unreserved characters.
    VerifierMalformed,
    /// The verifier's `S256` is not the code's challenge.
    VerifierMismatch,
}

impl PkceError {
    /// The OAuth error code: `invalid_grant` for a verifier that does not
    /// match (RFC 7636 §4.6), else `invalid_request`.
    pub fn error(self) -> &'static str {
        match self {
            Self::VerifierMismatch => "invalid_grant",
            _ => "invalid_request",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::ChallengeMissing => "code_challenge required",
            Self::MethodUnsupported => {
                "transform algorithm not supported: code_challenge_method must be S256"
            }
            Self::ChallengeMalformed => {
                "code_challenge must be 43 base64url characters, the S256 of the code_verifier"
            }
            Self::VerifierMissing => "code_verifier required",
            Self::VerifierMalformed => {
                "code_verifier must be 43 to 128 characters of A-Z, a-z, 0-9, '-', '.', '_' \
                 and '~'"
            }
            Self::VerifierMismatch => "code_verifier does not match the code_challenge",
        }
    }
}

impl From<PkceError> for OAuthError {
    fn from(error: PkceError) -> Self {
        OAuthError::new(error.error(), error.description())
    }
}

/// Whether `challenge` has the form of an `S256` code challenge.
pub fn code_challenge_is_valid(challenge: &str) -> bool {
    challenge.len() == S256_CHALLENGE_CHARS
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Whether `verifier` has the form of a code verifier (RFC 7636 §4.1).
pub fn code_verifier_is_valid(verifier: &str) -> bool {
    CODE_VERIFIER_CHARS.contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// `BASE64URL(SHA256(ASCII(verifier)))`, the `S256` challenge of a
/// verifier (RFC 7636 §4.2).
pub fn s256_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The PKCE parameters of an authorization request, checked in order:
/// a challenge is required, with method `S256`, of the `S256` form (RFC
/// 7636 §4.4.1). Empty counts as absent. Returns the challenge.
pub fn check_authorization_pkce<'a>(
    challenge: Option<&'a str>,
    method: Option<&str>,
) -> Result<&'a str, PkceError> {
    let challenge = challenge
        .filter(|challenge| !challenge.is_empty())
        .ok_or(PkceError::ChallengeMissing)?;
    if method != Some(PKCE_METHOD_S256) {
        return Err(PkceError::MethodUnsupported);
    }
    if !code_challenge_is_valid(challenge) {
        return Err(PkceError::ChallengeMalformed);
    }
    Ok(challenge)
}

/// The `code_verifier` of a token request against the code's `challenge`:
/// present, of the verifier form, and hashing to the challenge, compared
/// in constant time (RFC 7636 §4.6).
pub fn check_code_verifier(verifier: Option<&str>, challenge: &str) -> Result<(), PkceError> {
    let verifier = verifier
        .filter(|verifier| !verifier.is_empty())
        .ok_or(PkceError::VerifierMissing)?;
    if !code_verifier_is_valid(verifier) {
        return Err(PkceError::VerifierMalformed);
    }
    if ct_eq(&s256_challenge(verifier), challenge) {
        Ok(())
    } else {
        Err(PkceError::VerifierMismatch)
    }
}

#[cfg(test)]
#[path = "authorization_server_redirect_tests.rs"]
mod tests;
