//! DPoP (RFC 9449) at the embedded authorization server: the proof a
//! client sends in the `DPoP` header, checked in the order RFC 9449 §4.3
//! gives; the `htu` values a request accepts; the server nonces of §8 and
//! §9; the single-use ledger entry of each proof; and the resource side of
//! §7, where a token bound to a key is accepted only with the `DPoP`
//! scheme and a proof of that key.
//!
//! A proof is accepted for one method at one URL. The accepted URLs come
//! from the configuration alone (the issuer and every resource identifier,
//! custom domains included), never from the request's `Host` or forwarding
//! headers, so a proxy that ends TLS or a spoofed `Host` changes nothing.
//! Nonces need no store: each is an HMAC of its time window under a key
//! derived from an access-token signing key, so every replica issues and
//! accepts the same ones, and they follow a rotation of `signing_keys`.
//! Each proof is accepted once: its `jti`, keyed by the proof key's
//! thumbprint, goes into the replay ledger every replica shares.
//!
//! Nothing here logs or audits a proof, a key, a nonce or a token.

use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::clients::Client;
use super::{
    AuthorizationServer, EmaBearerOutcome, OAuthError, TOKEN_PATH, ct_eq, error_description,
    jose_typ_is, now_unix, unverified_claim_iss,
};
use crate::config::{DpopConfig, DpopNonceMode};

/// Request header that carries a proof.
pub const DPOP_HEADER: &str = "dpop";
/// Response header that carries a server nonce.
pub const DPOP_NONCE_HEADER: &str = "dpop-nonce";
/// `Authorization` scheme of a token bound to a key (RFC 9449 §7.1).
pub const DPOP_SCHEME: &str = "DPoP";
/// Identity attribute of a caller whose token was presented with a proof:
/// the RFC 7638 thumbprint of the proof key.
pub const DPOP_JKT_ATTRIBUTE: &str = "dpop_jkt";
/// `token_type` of a token bound to a key (RFC 9449 §5).
pub const TOKEN_TYPE_DPOP: &str = "DPoP";
/// `token_type` of an unbound token.
pub const TOKEN_TYPE_BEARER: &str = "Bearer";
/// Largest proof read, in bytes.
pub const MAX_PROOF_BYTES: usize = 8 * 1024;
/// Required `typ` header of a proof.
const PROOF_TYP: &str = "dpop+jwt";
/// Longest `jti` accepted, in bytes.
const MAX_JTI_BYTES: usize = 256;
/// Longest `htu` accepted, in bytes.
const MAX_HTU_BYTES: usize = 2048;
/// Longest `nonce` claim read; every nonce this server issues is shorter.
const MAX_NONCE_CHARS: usize = 64;
/// Smallest RSA modulus a proof key may have.
const MIN_RSA_MODULUS_BITS: usize = 2048;
/// Key namespace of spent proofs in the replay ledger.
const LEDGER_KEY_PREFIX: &str = "ema_dpop_jti/";
/// RFC 5869 `info` of the key nonces are derived under.
const NONCE_KEY_INFO: &[u8] = b"mcpg:as-dpop-nonce:v1";
/// Leading input of a nonce's tag.
const NONCE_TAG_LABEL: &[u8] = b"mcpg dpop nonce";
/// Bytes of a nonce's tag, after its 8-byte window.
const NONCE_TAG_BYTES: usize = 16;
/// Characters of an RFC 7638 SHA-256 thumbprint in base64url.
const JKT_CHARS: usize = 43;
/// JWK members that hold private or symmetric key material (RFC 7518 §6).
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The DPoP settings of one server, resolved from its configuration.
pub(super) struct DpopSettings {
    pub(super) enabled: bool,
    pub(super) required: bool,
    algs: Vec<Algorithm>,
    alg_names: Vec<String>,
    /// `alg_names` separated by spaces: the `algs` of a DPoP challenge.
    algs_param: String,
    max_age: u64,
    skew: u64,
    nonce: DpopNonceMode,
    nonce_lifetime: u64,
    /// `scheme://host[:port]` of the issuer and of every resource
    /// identifier: a request path under any of them is a valid `htu`.
    origins: Vec<String>,
    /// Every resource identifier, normalised, which an `htu` may name on
    /// the MCP endpoint.
    resource_urls: Vec<String>,
}

impl std::fmt::Debug for DpopSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopSettings")
            .field("enabled", &self.enabled)
            .field("required", &self.required)
            .field("algs", &self.alg_names)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

impl DpopSettings {
    /// `config`, with `skew` the server's clock skew, for the issuer
    /// `issuer` serving `resources`.
    pub(super) fn from_config(
        config: &DpopConfig,
        skew: u64,
        issuer: &str,
        resources: &[String],
    ) -> Result<Self> {
        let algs = config.algorithms("governance.access.authorization_server.dpop")?;
        let mut origins: Vec<String> = Vec::new();
        for uri in std::iter::once(issuer).chain(resources.iter().map(String::as_str)) {
            if let Some(origin) = web_url(uri).as_ref().and_then(scheme_authority)
                && !origins.contains(&origin)
            {
                origins.push(origin);
            }
        }
        let resource_urls = resources
            .iter()
            .filter_map(|resource| normalize_uri(resource))
            .collect();
        Ok(Self {
            enabled: config.enabled,
            required: config.required,
            algs,
            alg_names: config.allowed_algs.clone(),
            algs_param: config.allowed_algs.join(" "),
            max_age: config.proof_max_age_secs,
            skew,
            nonce: config.nonce,
            nonce_lifetime: config.nonce_lifetime_secs,
            origins,
            resource_urls,
        })
    }

    /// The JWS algorithms a proof may use, by their JWA names.
    pub(super) fn alg_names(&self) -> &[String] {
        &self.alg_names
    }

    /// The `algs` auth-param of a DPoP challenge (RFC 9449 §7.1).
    pub(super) fn algs_param(&self) -> &str {
        &self.algs_param
    }

    /// Whether a proof must carry a server nonce: at the resource when
    /// `at_resource`, else at the token endpoint.
    fn nonce_required(&self, at_resource: bool) -> bool {
        if at_resource {
            self.nonce == DpopNonceMode::Always
        } else {
            self.nonce.covers_token_endpoint()
        }
    }

    /// The nonce window `now` falls in.
    fn nonce_window(&self, now: u64) -> u64 {
        now / self.nonce_lifetime.max(1)
    }

    /// The windows a nonce may have been minted in to be accepted at
    /// `now`: the current one and the one before it, widened by the clock
    /// skew on both sides, so a replica whose clock runs up to the skew
    /// ahead or behind hands out nonces every other replica accepts.
    pub(super) fn accepted_nonce_windows(&self, now: u64) -> RangeInclusive<u64> {
        let oldest = self
            .nonce_window(now.saturating_sub(self.skew))
            .saturating_sub(1);
        oldest..=self.nonce_window(now.saturating_add(self.skew))
    }

    /// Check the one proof of `presentation` for `target` at `now` (RFC
    /// 9449 §4.3): the header, the key, the nonce when one is required
    /// (`nonce_valid` judges it), the signature, the claims, `htm`, `htu`,
    /// `iat`, and `ath` when the proof goes with `access_token`. The proof
    /// is not spent here.
    pub(super) fn check(
        &self,
        presentation: &DpopPresentation<'_>,
        target: &DpopTarget<'_>,
        access_token: Option<&str>,
        nonce_valid: impl Fn(&str) -> bool,
        now: u64,
    ) -> Result<ProvenKey, DpopFailure> {
        use DpopReason as R;
        let proof = match presentation.proofs.as_slice() {
            [one] => *one,
            [] => return Err(invalid(R::Missing, "the request carries no DPoP proof")),
            _ => {
                return Err(invalid(
                    R::Multiple,
                    "the request carries more than one DPoP header",
                ));
            }
        };
        if proof.len() > MAX_PROOF_BYTES {
            return Err(invalid(R::TooLarge, "the DPoP proof exceeds 8192 bytes"));
        }
        let proof = std::str::from_utf8(proof)
            .ok()
            .filter(|proof| proof.bytes().all(|b| (0x21..=0x7e).contains(&b)))
            .ok_or_else(|| invalid(R::Malformed, "the DPoP proof is not a compact JWS"))?;
        let mut segments = proof.split('.');
        let (Some(encoded_header), Some(encoded_claims), Some(_), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(invalid(R::Malformed, "the DPoP proof is not a compact JWS"));
        };
        let header = decode_object(encoded_header).ok_or_else(|| {
            invalid(
                R::Malformed,
                "the DPoP proof header is not a base64url JSON object",
            )
        })?;
        if !header
            .get("typ")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|typ| jose_typ_is(typ, PROOF_TYP))
        {
            return Err(invalid(R::Typ, "the DPoP proof typ must be dpop+jwt"));
        }
        if header.contains_key("crit") {
            return Err(invalid(
                R::Crit,
                "the DPoP proof header carries crit, which this server does not process",
            ));
        }
        let alg_name = header.get("alg").and_then(serde_json::Value::as_str);
        let Some(alg) = alg_name.and_then(|name| {
            self.alg_names
                .iter()
                .position(|allowed| allowed == name)
                .map(|at| self.algs[at])
        }) else {
            return Err(invalid(
                R::Alg,
                format!(
                    "the DPoP proof alg must be one of {}",
                    self.alg_names.join(", ")
                ),
            ));
        };
        let jwk = proof_key(&header, alg, alg_name.unwrap_or_default())?;
        let decoding = DecodingKey::from_jwk(&jwk)
            .map_err(|_| invalid(R::Jwk, "the DPoP proof jwk is not a usable public key"))?;
        // The signature is not checked for a proof sent without a current
        // nonce: that answer costs the token endpoint's rate limit nothing.
        let nonce_required = self.nonce_required(access_token.is_some());
        let nonce_current = |claims: &serde_json::Map<String, serde_json::Value>| {
            claims
                .get("nonce")
                .and_then(serde_json::Value::as_str)
                .filter(|nonce| nonce.len() <= MAX_NONCE_CHARS)
                .is_some_and(&nonce_valid)
        };
        if nonce_required
            && decode_object(encoded_claims).is_some_and(|claims| !nonce_current(&claims))
        {
            return Err(DpopFailure::UseNonce);
        }
        let mut validation = Validation::new(alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<serde_json::Value>(proof, &decoding, &validation)
            .map_err(|error| match error.kind() {
                ErrorKind::Base64(_) => {
                    invalid(R::Malformed, "the DPoP proof is not a compact JWS")
                }
                ErrorKind::Json(_) | ErrorKind::Utf8(_) | ErrorKind::InvalidClaimFormat(_) => {
                    invalid(R::Claims, "the DPoP proof claims are not a JSON object")
                }
                _ => invalid(R::Signature, "the DPoP proof signature does not verify"),
            })?
            .claims;
        let claims = claims
            .as_object()
            .ok_or_else(|| invalid(R::Claims, "the DPoP proof claims are not a JSON object"))?;
        let claim = |name: &str| claims.get(name).and_then(serde_json::Value::as_str);
        let jti = claim("jti")
            .filter(|jti| !jti.is_empty() && jti.len() <= MAX_JTI_BYTES)
            .ok_or_else(|| {
                invalid(
                    R::Claims,
                    "the DPoP proof jti must be a string of 1 to 256 bytes",
                )
            })?;
        let htm = claim("htm")
            .ok_or_else(|| invalid(R::Claims, "the DPoP proof htm must be a string"))?;
        let htu = claim("htu")
            .filter(|htu| htu.len() <= MAX_HTU_BYTES)
            .ok_or_else(|| {
                invalid(
                    R::Claims,
                    "the DPoP proof htu must be a string of at most 2048 bytes",
                )
            })?;
        let iat = claims
            .get("iat")
            .and_then(numeric_date)
            .ok_or_else(|| invalid(R::Claims, "the DPoP proof iat must be a NumericDate"))?;
        // RFC 9110 §9.1: methods are case-sensitive.
        if htm != target.method {
            return Err(invalid(
                R::Htm,
                "the DPoP proof htm is not the method of this request",
            ));
        }
        if !self.htu_accepted(htu, target) {
            return Err(invalid(
                R::Htu,
                "the DPoP proof htu is not the URL of this request",
            ));
        }
        let oldest = now.saturating_sub(self.max_age.saturating_add(self.skew));
        if iat < oldest || iat > now.saturating_add(self.skew) {
            return Err(invalid(
                R::Iat,
                "the DPoP proof iat is outside the window this server accepts; sign a new proof",
            ));
        }
        if nonce_required && !nonce_current(claims) {
            return Err(DpopFailure::UseNonce);
        }
        if let Some(token) = access_token {
            let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(token.as_bytes()));
            if !claim("ath").is_some_and(|ath| ct_eq(ath, &expected)) {
                return Err(invalid(
                    R::Ath,
                    "the DPoP proof ath is not the hash of the access token",
                ));
            }
        }
        let jkt = jwk
            .thumbprint(ThumbprintHash::SHA256)
            .map_err(|_| invalid(R::Jwk, "the DPoP proof jwk has no thumbprint"))?;
        Ok(ProvenKey {
            jkt,
            jti: jti.to_owned(),
            iat,
        })
    }

    /// Whether `htu` names `target`: its method's path under the issuer's
    /// or a resource identifier's origin, or, on the MCP endpoint, one of
    /// the resource identifiers itself (a proxy that maps a public path
    /// onto the MCP path). Both sides are normalised; a trailing `/` of a
    /// resource identifier is ignored.
    pub(super) fn htu_accepted(&self, htu: &str, target: &DpopTarget<'_>) -> bool {
        let (Some(htu), Some(path)) = (normalize_uri(htu), normalize_path(target.path)) else {
            return false;
        };
        if self
            .origins
            .iter()
            .any(|origin| htu.strip_prefix(origin.as_str()) == Some(path.as_str()))
        {
            return true;
        }
        target.mcp_endpoint
            && self
                .resource_urls
                .iter()
                .any(|resource| resource.trim_end_matches('/') == htu.trim_end_matches('/'))
    }
}

/// The public key of a proof's header `header`, signed with `alg`
/// (`alg_name` as written): a JWK with no private member, of the key type
/// and curve `alg` needs, declaring no other `alg`, an RSA key of at least
/// 2048 bits. The raw header is read because [`Jwk`] drops members it does
/// not know.
fn proof_key(
    header: &serde_json::Map<String, serde_json::Value>,
    alg: Algorithm,
    alg_name: &str,
) -> Result<Jwk, DpopFailure> {
    use DpopReason as R;
    let Some(members) = header.get("jwk").and_then(serde_json::Value::as_object) else {
        return Err(invalid(
            R::Jwk,
            "the DPoP proof header carries no jwk object",
        ));
    };
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| members.contains_key(*member))
    {
        return Err(invalid(
            R::PrivateKey,
            "the DPoP proof jwk carries private key material",
        ));
    }
    let jwk: Jwk = serde_json::from_value(serde_json::Value::Object(members.clone()))
        .map_err(|_| invalid(R::Jwk, "the DPoP proof jwk is not a usable public key"))?;
    let fits = match (&jwk.algorithm, alg) {
        (AlgorithmParameters::EllipticCurve(key), Algorithm::ES256) => {
            key.curve == EllipticCurve::P256
        }
        (AlgorithmParameters::EllipticCurve(key), Algorithm::ES384) => {
            key.curve == EllipticCurve::P384
        }
        (AlgorithmParameters::OctetKeyPair(key), Algorithm::EdDSA) => {
            key.curve == EllipticCurve::Ed25519
        }
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        ) => true,
        _ => false,
    };
    if !fits {
        return Err(invalid(
            R::Jwk,
            "the DPoP proof jwk is not a key of the type and curve its alg needs",
        ));
    }
    if members
        .get("alg")
        .is_some_and(|declared| declared.as_str() != Some(alg_name))
    {
        return Err(invalid(
            R::Jwk,
            "the DPoP proof jwk declares an alg other than the proof's",
        ));
    }
    if let AlgorithmParameters::RSA(ref key) = jwk.algorithm
        && modulus_bits(&key.n).is_none_or(|bits| bits < MIN_RSA_MODULUS_BITS)
    {
        return Err(invalid(
            R::WeakKey,
            "the DPoP proof key is an RSA key of fewer than 2048 bits",
        ));
    }
    Ok(jwk)
}

/// The bit length of the base64url big-endian modulus `n`.
fn modulus_bits(n: &str) -> Option<usize> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n)
        .ok()?;
    let at = bytes.iter().position(|byte| *byte != 0)?;
    let significant = &bytes[at..];
    Some(significant.len() * 8 - significant[0].leading_zeros() as usize)
}

/// A JWS segment decoded as a JSON object.
fn decode_object(segment: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        serde_json::Value::Object(object) => Some(object),
        _ => None,
    }
}

/// A JWT NumericDate (RFC 7519 §2): a non-negative number of seconds,
/// whole or not.
fn numeric_date(value: &serde_json::Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0 && *seconds < u64::MAX as f64)
            .map(|seconds| seconds.floor() as u64)
    })
}

fn invalid(reason: DpopReason, description: impl Into<String>) -> DpopFailure {
    DpopFailure::Invalid(reason, description.into())
}

// ---------------------------------------------------------------------------
// The request side
// ---------------------------------------------------------------------------

/// The `DPoP` header values of one request, as sent.
pub struct DpopPresentation<'a> {
    proofs: Vec<&'a [u8]>,
}

impl<'a> DpopPresentation<'a> {
    /// A request without a `DPoP` header.
    pub fn none() -> Self {
        Self { proofs: Vec::new() }
    }

    /// The values of every `DPoP` header of a request.
    pub fn from_values(values: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self {
            proofs: values.into_iter().collect(),
        }
    }

    /// Whether the request carries a `DPoP` header.
    pub fn is_present(&self) -> bool {
        !self.proofs.is_empty()
    }
}

impl std::fmt::Debug for DpopPresentation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopPresentation")
            .field("proofs", &self.proofs.len())
            .finish()
    }
}

/// What a proof is for: the request's method, its path without the query,
/// and whether that path is the MCP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopTarget<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub mcp_endpoint: bool,
}

impl DpopTarget<'static> {
    /// `POST /oauth/token`.
    pub fn token_endpoint() -> Self {
        Self {
            method: "POST",
            path: TOKEN_PATH,
            mcp_endpoint: false,
        }
    }
}

impl<'a> DpopTarget<'a> {
    /// A request of `method` at `request_target` (its path and query as
    /// sent), on the MCP endpoint when its path is `mcp_path`.
    pub fn of_request(method: &'a str, request_target: &'a str, mcp_path: &str) -> Self {
        let path = request_target
            .split_once('?')
            .map_or(request_target, |(path, _)| path);
        Self {
            method,
            path,
            mcp_endpoint: path == mcp_path,
        }
    }
}

/// A proof that passed every check: the RFC 7638 SHA-256 thumbprint of its
/// key, its `jti` and its `iat`. `Debug` shows none of them.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvenKey {
    pub(super) jkt: String,
    pub(super) jti: String,
    pub(super) iat: u64,
}

impl ProvenKey {
    /// The thumbprint of the proof key, which a bound token carries as
    /// `cnf.jkt`.
    pub fn jkt(&self) -> &str {
        &self.jkt
    }
}

impl std::fmt::Debug for ProvenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvenKey").finish_non_exhaustive()
    }
}

/// A server nonce. `Debug` does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopNonce(String);

impl DpopNonce {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DpopNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DpopNonce([redacted])")
    }
}

/// Why a proof is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopFailure {
    /// `invalid_dpop_proof`, for the reason and with the description.
    Invalid(DpopReason, String),
    /// The proof carries no current server nonce: `use_dpop_nonce`.
    UseNonce,
    /// The replay ledger cannot record the proof, which is refused.
    Unavailable,
}

/// Why a proof is invalid, as a bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopReason {
    Multiple,
    TooLarge,
    Malformed,
    Typ,
    Alg,
    Jwk,
    PrivateKey,
    WeakKey,
    Crit,
    Signature,
    Claims,
    Htm,
    Htu,
    Iat,
    Ath,
    /// The proof key is not the key the access token is bound to.
    KeyMismatch,
    Replayed,
    /// The request carries no `DPoP` header.
    Missing,
    /// A token presented with the `DPoP` scheme is not bound to a key.
    NotBound,
    /// The request reached an endpoint that takes no proof.
    NoTarget,
}

impl DpopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Multiple => "multiple",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::Typ => "typ",
            Self::Alg => "alg",
            Self::Jwk => "jwk",
            Self::PrivateKey => "private_key",
            Self::WeakKey => "weak_key",
            Self::Crit => "crit",
            Self::Signature => "signature",
            Self::Claims => "claims",
            Self::Htm => "htm",
            Self::Htu => "htu",
            Self::Iat => "iat",
            Self::Ath => "ath",
            Self::KeyMismatch => "key_mismatch",
            Self::Replayed => "replayed",
            Self::Missing => "missing",
            Self::NotBound => "not_bound",
            Self::NoTarget => "no_target",
        }
    }
}

// ---------------------------------------------------------------------------
// Challenges at the resource
// ---------------------------------------------------------------------------

/// What the resource's challenges say about DPoP while it is on (RFC 9449
/// §7.1): the proof algorithms as the `algs` auth-param, and whether only
/// DPoP-bound tokens are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopChallenge<'a> {
    pub algs: &'a str,
    pub required: bool,
}

/// The `error` of a DPoP challenge (RFC 9449 §7.1 and §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopChallengeError {
    InvalidToken,
    InvalidDpopProof,
    UseDpopNonce,
}

impl DpopChallengeError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
        }
    }
}

/// A credential the resource refuses with a `WWW-Authenticate: DPoP`
/// challenge. `description` is the challenge's `error_description`;
/// `reason` says why for the log and the audit record, and never holds a
/// token, a proof or a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmaRefusal {
    pub error: DpopChallengeError,
    pub description: String,
    pub reason: String,
    /// The nonce a `use_dpop_nonce` refusal hands out as `DPoP-Nonce`.
    pub nonce: Option<DpopNonce>,
    /// The `algs` auth-param of the challenge.
    pub algs: String,
}

impl EmaRefusal {
    /// The `WWW-Authenticate` value of the refusal.
    pub fn challenge(&self) -> String {
        format!(
            "{DPOP_SCHEME} error=\"{}\", error_description=\"{}\", algs=\"{}\"",
            self.error.as_str(),
            error_description(&self.description),
            self.algs
        )
    }

    /// Whether the refusal goes on the audit trail: a request for a nonce
    /// is a normal step of the protocol, not a failed authentication.
    pub fn audited(&self) -> bool {
        self.error != DpopChallengeError::UseDpopNonce
    }
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// `uri` as an absolute `http` or `https` URL with a host and no userinfo.
fn web_url(uri: &str) -> Option<url::Url> {
    let url = url::Url::parse(uri).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some())
    .then_some(url)
}

/// `scheme://host[:port]` of `url`, the port left out when it is the
/// scheme's default.
fn scheme_authority(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// `uri` normalised as RFC 3986 §6.2.2 and §6.2.3 describe, without its
/// query and fragment: `scheme://host[:port]path`, with the scheme and
/// host in lower case, no default port, no dot segments, `/` for an empty
/// path, upper-case percent-encodings and no percent-encoded unreserved
/// character. `None` for anything but an absolute `http(s)` URL with a
/// host and no userinfo.
pub fn normalize_uri(uri: &str) -> Option<String> {
    let url = web_url(uri)?;
    let mut normalized = scheme_authority(&url)?;
    normalized.push_str(&normalize_percent(url.path())?);
    Some(normalized)
}

/// A request path, without its query, normalised as [`normalize_uri`]
/// normalises the path of a URL.
pub fn normalize_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains(['?', '#']) {
        return None;
    }
    let url = url::Url::parse(&format!("http://path.invalid{path}")).ok()?;
    normalize_percent(url.path())
}

/// `path` with every percent-encoding in upper case, and the unreserved
/// characters (RFC 3986 §2.3) among them decoded.
fn normalize_percent(path: &str) -> Option<String> {
    let hex = |digit: u8| (digit as char).to_digit(16).map(|value| value as u8);
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let value = (hex(*bytes.get(at + 1)?)? << 4) | hex(*bytes.get(at + 2)?)?;
        if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~') {
            out.push(value);
        } else {
            out.extend_from_slice(format!("%{value:02X}").as_bytes());
        }
        at += 3;
    }
    String::from_utf8(out).ok()
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// The key the nonces of a signing key are derived under: RFC 5869 with
/// the issuer as salt over the key's material.
pub(super) fn nonce_key(issuer: &str, material: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(issuer.as_bytes()), material)
        .expand(NONCE_KEY_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("the DPoP nonce key cannot be derived"))?;
    Ok(key)
}

fn nonce_tag(key: &[u8; 32], issuer: &str, window: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(NONCE_TAG_LABEL.len() + 16 + issuer.len());
    input.extend_from_slice(NONCE_TAG_LABEL);
    input.extend_from_slice(&(issuer.len() as u64).to_be_bytes());
    input.extend_from_slice(issuer.as_bytes());
    input.extend_from_slice(&window.to_be_bytes());
    hmac_sha256::HMAC::mac(input, key)
}

/// The nonce of `window` under `key`: the window, then the first 16 bytes
/// of its tag, in base64url.
pub(super) fn mint_nonce(key: &[u8; 32], issuer: &str, window: u64) -> DpopNonce {
    let mut raw = [0u8; 8 + NONCE_TAG_BYTES];
    raw[..8].copy_from_slice(&window.to_be_bytes());
    raw[8..].copy_from_slice(&nonce_tag(key, issuer, window)[..NONCE_TAG_BYTES]);
    DpopNonce(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Whether `nonce` is one of `keys` minted for a window of `windows`, each
/// tag compared in constant time.
pub(super) fn nonce_is_current<'k>(
    keys: impl IntoIterator<Item = &'k [u8; 32]>,
    issuer: &str,
    nonce: &str,
    windows: RangeInclusive<u64>,
) -> bool {
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(nonce) else {
        return false;
    };
    let Some((window, tag)) = raw
        .split_first_chunk::<8>()
        .filter(|(_, tag)| tag.len() == NONCE_TAG_BYTES)
    else {
        return false;
    };
    let window = u64::from_be_bytes(*window);
    if !windows.contains(&window) {
        return false;
    }
    keys.into_iter().fold(false, |matched, key| {
        matched | bool::from(nonce_tag(key, issuer, window)[..NONCE_TAG_BYTES].ct_eq(tag))
    })
}

// ---------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------

/// Ledger key of a spent proof: a hash of the key's thumbprint and the
/// proof's `jti`, so a proof under another key cannot spend it.
pub(super) fn ledger_key(jkt: &str, jti: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("mcpg ema dpop-proof single-use ledger v1");
    hasher.update(&(jkt.len() as u64).to_le_bytes());
    hasher.update(jkt.as_bytes());
    hasher.update(jti.as_bytes());
    format!("{LEDGER_KEY_PREFIX}{}", hasher.finalize().to_hex())
}

/// Whether `value` has the shape of an RFC 7638 SHA-256 thumbprint: 43
/// base64url characters.
pub(super) fn is_thumbprint(value: &str) -> bool {
    value.len() == JKT_CHARS
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

impl AuthorizationServer {
    /// Whether DPoP is on: proofs are read and tokens bound.
    pub fn dpop_enabled(&self) -> bool {
        self.dpop.enabled
    }

    /// The current nonce, from the first signing key.
    fn current_dpop_nonce(&self) -> DpopNonce {
        mint_nonce(
            &self.signing_keys[0].nonce_key,
            &self.issuer,
            self.dpop.nonce_window(now_unix()),
        )
    }

    /// Whether `nonce` is current under any signing key.
    fn dpop_nonce_is_valid(&self, nonce: &str) -> bool {
        nonce_is_current(
            self.signing_keys.iter().map(|key| &*key.nonce_key),
            &self.issuer,
            nonce,
            self.dpop.accepted_nonce_windows(now_unix()),
        )
    }

    /// The nonce every token-endpoint response carries while nonces are
    /// required there.
    pub fn token_endpoint_nonce(&self) -> Option<DpopNonce> {
        (self.dpop.enabled && self.dpop.nonce.covers_token_endpoint())
            .then(|| self.current_dpop_nonce())
    }

    /// Check the proof of `presentation` for `target`, with `access_token`
    /// at a resource, then spend it. Counts the outcome.
    pub(super) async fn check_proof(
        &self,
        presentation: &DpopPresentation<'_>,
        target: &DpopTarget<'_>,
        access_token: Option<&str>,
    ) -> Result<ProvenKey, DpopFailure> {
        self.check_bound_proof(presentation, target, access_token, None)
            .await
    }

    /// [`Self::check_proof`], the proof key compared with `bound`, the key
    /// the access token is bound to, before the proof is spent: a proof
    /// refused for any reason costs no ledger write.
    async fn check_bound_proof(
        &self,
        presentation: &DpopPresentation<'_>,
        target: &DpopTarget<'_>,
        access_token: Option<&str>,
        bound: Option<&str>,
    ) -> Result<ProvenKey, DpopFailure> {
        let endpoint = if access_token.is_some() {
            "resource"
        } else {
            "token"
        };
        let checked = self
            .dpop
            .check(
                presentation,
                target,
                access_token,
                |nonce| self.dpop_nonce_is_valid(nonce),
                now_unix(),
            )
            .and_then(|proven| match bound {
                Some(bound) if !ct_eq(bound, &proven.jkt) => Err(invalid(
                    DpopReason::KeyMismatch,
                    "the DPoP proof key is not the key the access token is bound to",
                )),
                _ => Ok(proven),
            });
        let result = match checked {
            Ok(proven) => self.spend_proof(&proven, endpoint).await.map(|()| proven),
            Err(failure) => Err(failure),
        };
        count_proof(endpoint, &result);
        result
    }

    /// Record `proven` in the replay ledger for as long as its proof is
    /// accepted. A proof recorded already is a replay; a ledger that
    /// cannot be written refuses it.
    async fn spend_proof(
        &self,
        proven: &ProvenKey,
        endpoint: &'static str,
    ) -> Result<(), DpopFailure> {
        let accepted_until = proven
            .iat
            .saturating_add(self.dpop.max_age)
            .saturating_add(self.dpop.skew.saturating_mul(2));
        let ttl = accepted_until.saturating_sub(now_unix()).max(1);
        let started = Instant::now();
        let claimed = self
            .replay
            .kv
            .put_if_absent(
                &ledger_key(&proven.jkt, &proven.jti),
                Bytes::from_static(b"1"),
                Some(Duration::from_secs(ttl)),
            )
            .await;
        metrics::histogram!("mcpg_as_dpop_ledger_latency_ms", "endpoint" => endpoint)
            .record(started.elapsed().as_secs_f64() * 1000.0);
        match claimed {
            Ok(true) => Ok(()),
            Ok(false) => Err(invalid(
                DpopReason::Replayed,
                "the DPoP proof has already been used; sign a new proof for each request",
            )),
            Err(error) => {
                metrics::counter!("mcpg_ema_jti_store_errors_total").increment(1);
                tracing::error!(
                    error = %error,
                    "the replay ledger could not record a DPoP proof; refusing it"
                );
                Err(DpopFailure::Unavailable)
            }
        }
    }

    /// The proof of a token request, when DPoP is on and the request
    /// carries one: checked and spent before the client authenticates.
    pub(super) async fn token_request_proof(
        &self,
        presentation: &DpopPresentation<'_>,
    ) -> Result<Option<ProvenKey>, OAuthError> {
        if !self.dpop.enabled || !presentation.is_present() {
            return Ok(None);
        }
        self.check_proof(presentation, &DpopTarget::token_endpoint(), None)
            .await
            .map(Some)
            .map_err(|failure| match failure {
                DpopFailure::Invalid(_, description) => OAuthError::invalid_dpop_proof(description),
                DpopFailure::UseNonce => OAuthError::use_dpop_nonce(
                    "this authorization server requires a nonce in the DPoP proof: sign a new \
                     proof with the value of the DPoP-Nonce header",
                ),
                DpopFailure::Unavailable => OAuthError::temporarily_unavailable(
                    "replay protection is unavailable; retry shortly",
                ),
            })
    }

    /// Whether every token `client` receives must be bound: DPoP is on and
    /// required, or the client registered `dpop_bound_access_tokens`.
    pub(super) fn dpop_required_for(&self, client: &Client) -> bool {
        self.dpop.enabled && (self.dpop.required || client.dpop_bound_access_tokens())
    }

    /// The key the tokens of an authorization code or a refresh token are
    /// bound to. `bound` is the key the code or the grant is already bound
    /// to, which the proof must be of (`what` names that binding), and
    /// `invalid_grant` otherwise, the code or token left unspent. Without
    /// a binding, the proof's key, if any; with neither, a client that
    /// needs a proof is refused with `invalid_dpop_proof`.
    pub(super) fn proof_binding(
        &self,
        bound: Option<&str>,
        proof: Option<&ProvenKey>,
        client: &Client,
        what: &str,
    ) -> Result<Option<String>, OAuthError> {
        match (bound, proof) {
            (Some(bound), Some(proof)) if ct_eq(bound, &proof.jkt) => Ok(Some(proof.jkt.clone())),
            (Some(_), Some(_)) => Err(OAuthError::invalid_grant(format!(
                "the DPoP proof key is not the key {what} is bound to"
            ))),
            (Some(_), None) => Err(OAuthError::invalid_grant(format!(
                "proof of possession required: {what} is bound to a key; send a DPoP proof of it"
            ))),
            (None, Some(proof)) => Ok(Some(proof.jkt.clone())),
            (None, None) if self.dpop_required_for(client) => Err(OAuthError::invalid_dpop_proof(
                "a DPoP proof is required: this client's tokens are bound to its key",
            )),
            (None, None) => Ok(None),
        }
    }

    /// The key the token of an ID-JAG is bound to, as ID-JAG §9.8.1.2
    /// requires: the assertion's `cnf_jkt`, which the proof must be of;
    /// else the proof's key; else none, unless every token of `client`
    /// must be bound. Every refusal is `invalid_grant`.
    pub(super) fn id_jag_binding(
        &self,
        cnf_jkt: Option<&str>,
        proof: Option<&ProvenKey>,
        client: &Client,
    ) -> Result<Option<String>, OAuthError> {
        match (cnf_jkt, proof) {
            (Some(cnf), Some(proof)) if ct_eq(cnf, &proof.jkt) => Ok(Some(proof.jkt.clone())),
            (Some(_), Some(_)) => Err(OAuthError::invalid_grant(
                "the DPoP proof key is not the key the assertion is bound to",
            )),
            (Some(_), None) => Err(OAuthError::invalid_grant(
                "proof of possession required: the assertion is bound to a key (cnf)",
            )),
            (None, Some(proof)) => Ok(Some(proof.jkt.clone())),
            (None, None) if self.dpop.enabled && self.dpop.required => {
                Err(OAuthError::invalid_grant(
                    "this authorization server issues only DPoP-bound tokens; send a DPoP proof",
                ))
            }
            (None, None) if self.dpop_required_for(client) => Err(OAuthError::invalid_grant(
                "this client's tokens are bound to its key (dpop_bound_access_tokens); send a \
                 DPoP proof",
            )),
            (None, None) => Ok(None),
        }
    }
}

/// Count one proof outcome at `endpoint`, and say at debug level why a
/// proof was refused.
fn count_proof(endpoint: &'static str, result: &Result<ProvenKey, DpopFailure>) {
    let (outcome, reason) = match result {
        Ok(_) => ("accepted", "none"),
        Err(DpopFailure::Invalid(DpopReason::Replayed, _)) => ("replayed", "replayed"),
        Err(DpopFailure::Invalid(reason, _)) => ("refused", reason.as_str()),
        Err(DpopFailure::UseNonce) => ("nonce_required", "nonce"),
        Err(DpopFailure::Unavailable) => ("error", "none"),
    };
    metrics::counter!(
        "mcpg_as_dpop_proofs_total",
        "endpoint" => endpoint,
        "outcome" => outcome,
        "reason" => reason,
    )
    .increment(1);
    if let Err(DpopFailure::Invalid(reason, _)) = result {
        tracing::debug!(endpoint, reason = reason.as_str(), "DPoP proof refused");
    }
}

// ---------------------------------------------------------------------------
// The resource
// ---------------------------------------------------------------------------

/// `error_description` of an access token that fails a check of its own,
/// whatever the check: the reason is logged and audited, not echoed.
const INVALID_TOKEN_DESCRIPTION: &str = "the access token is invalid, expired or revoked";

impl AuthorizationServer {
    /// What the resource's challenges say about DPoP, while it is on.
    pub fn dpop_challenge(&self) -> Option<DpopChallenge<'_>> {
        self.dpop.enabled.then(|| DpopChallenge {
            algs: self.dpop.algs_param(),
            required: self.dpop.required,
        })
    }

    /// A refusal with `error`, whose challenge says `description` and whose
    /// log and audit record say `reason`.
    fn dpop_refusal(
        &self,
        error: DpopChallengeError,
        description: &str,
        reason: impl Into<String>,
    ) -> EmaRefusal {
        EmaRefusal {
            error,
            description: description.to_owned(),
            reason: reason.into(),
            nonce: None,
            algs: self.dpop.algs_param().to_owned(),
        }
    }

    /// [`Self::dpop_refusal`] as the outcome of a verification.
    fn dpop_refused(
        &self,
        error: DpopChallengeError,
        description: &str,
        reason: impl Into<String>,
    ) -> EmaBearerOutcome {
        EmaBearerOutcome::Refused(self.dpop_refusal(error, description, reason))
    }

    /// A token bound to a key, presented with the `Bearer` scheme (RFC 9449
    /// §7.2): refused with a DPoP challenge while DPoP is on, and with the
    /// Bearer challenge while DPoP is off, where no DPoP scheme is
    /// accepted.
    pub(super) fn bound_token_as_bearer(&self) -> EmaBearerOutcome {
        const DESCRIPTION: &str =
            "the access token is DPoP-bound; present it with the DPoP scheme and a proof";
        if self.dpop.enabled {
            self.dpop_refused(DpopChallengeError::InvalidToken, DESCRIPTION, DESCRIPTION)
        } else {
            EmaBearerOutcome::Invalid(DESCRIPTION.to_owned())
        }
    }

    /// An unbound token presented with the `Bearer` scheme, refused while
    /// `required` is set: this covers tokens issued before it was.
    pub(super) fn unbound_token_refused(&self) -> Option<EmaBearerOutcome> {
        const DESCRIPTION: &str = "this resource accepts only DPoP-bound tokens";
        (self.dpop.enabled && self.dpop.required)
            .then(|| self.dpop_refused(DpopChallengeError::InvalidToken, DESCRIPTION, DESCRIPTION))
    }

    /// Verify `token`, presented with the `DPoP` scheme (RFC 9449 §7.1), for
    /// a request at `target` carrying `presentation`. `NotOurs` while DPoP
    /// is off, where the scheme is not recognised. Otherwise the token must
    /// be one this server minted, pass every check a Bearer token passes,
    /// and be bound to a key; the proof must pass every check of RFC 9449
    /// §4.3 with `ath`, be of the token's key and be unspent, and is spent
    /// last. A token of another issuer is refused rather than handed to
    /// another verifier: this resource takes the `DPoP` scheme only for its
    /// own tokens. A verified caller carries the key's thumbprint as the
    /// `dpop_jkt` attribute.
    pub async fn verify_dpop(
        &self,
        token: &str,
        presentation: &DpopPresentation<'_>,
        target: Option<&DpopTarget<'_>>,
    ) -> EmaBearerOutcome {
        use DpopChallengeError as E;
        if !self.dpop.enabled {
            return EmaBearerOutcome::NotOurs;
        }
        if unverified_claim_iss(token).as_deref() != Some(self.issuer.as_str()) {
            const DESCRIPTION: &str = "this resource accepts the DPoP scheme only for the access \
                                       tokens of its own authorization server";
            return self.dpop_refused(E::InvalidToken, DESCRIPTION, DESCRIPTION);
        }
        let claims = match self.decode_minted(token) {
            Ok(claims) => claims,
            Err(reason) => {
                return self.dpop_refused(E::InvalidToken, INVALID_TOKEN_DESCRIPTION, reason);
            }
        };
        let bound = claims.cnf.as_ref().map(|cnf| cnf.jkt.clone());
        let mut identity = match self.verified_identity(claims) {
            Ok(identity) => identity,
            Err(reason) => {
                return self.dpop_refused(E::InvalidToken, INVALID_TOKEN_DESCRIPTION, reason);
            }
        };
        let Some(bound) = bound else {
            const DESCRIPTION: &str =
                "the access token is not DPoP-bound; present it with the Bearer scheme";
            count_proof("resource", &Err(invalid(DpopReason::NotBound, DESCRIPTION)));
            return self.dpop_refused(E::InvalidToken, DESCRIPTION, DESCRIPTION);
        };
        let Some(target) = target else {
            const DESCRIPTION: &str = "this endpoint takes no DPoP proof";
            count_proof("resource", &Err(invalid(DpopReason::NoTarget, DESCRIPTION)));
            return self.dpop_refused(E::InvalidDpopProof, DESCRIPTION, DESCRIPTION);
        };
        match self
            .check_bound_proof(presentation, target, Some(token), Some(&bound))
            .await
        {
            Ok(proven) => {
                identity
                    .attributes
                    .insert(DPOP_JKT_ATTRIBUTE.to_owned(), proven.jkt);
                EmaBearerOutcome::Verified(identity)
            }
            // RFC 9449 §7.1 answers a proof of another key as a token
            // failure, not a proof failure.
            Err(DpopFailure::Invalid(DpopReason::KeyMismatch, reason)) => {
                self.dpop_refused(E::InvalidToken, "Invalid DPoP key binding", reason)
            }
            Err(DpopFailure::Invalid(_, description)) => {
                self.dpop_refused(E::InvalidDpopProof, &description, description.clone())
            }
            Err(DpopFailure::UseNonce) => {
                const DESCRIPTION: &str = "this resource requires a nonce in the DPoP proof: sign \
                                           a new proof with the value of the DPoP-Nonce header";
                EmaBearerOutcome::Refused(EmaRefusal {
                    nonce: Some(self.current_dpop_nonce()),
                    ..self.dpop_refusal(E::UseDpopNonce, DESCRIPTION, DESCRIPTION)
                })
            }
            Err(DpopFailure::Unavailable) => EmaBearerOutcome::Unavailable,
        }
    }
}

/// The key thumbprint of an ID-JAG's `cnf` claim: an object whose one
/// member is a `jkt` thumbprint (RFC 9449 §6.1). `None` for any other
/// confirmation method.
pub(super) fn confirmation_jkt(cnf: &serde_json::Value) -> Option<&str> {
    let members = cnf.as_object()?;
    if members.len() != 1 {
        return None;
    }
    members
        .get("jkt")
        .and_then(serde_json::Value::as_str)
        .filter(|jkt| is_thumbprint(jkt))
}
