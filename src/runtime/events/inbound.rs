//! `inbound` event sources: signed webhooks third parties POST to
//! `/webhooks/events/{source_id}`.
//!
//! The route verifies the signature over the raw body by the route's signing
//! profile, answers the profile's handshakes itself, keeps or drops the
//! request by each type's `when` filter, extracts the event id and time, and
//! writes the event to each keeping type's inbox. It answers 2xx only after
//! those writes, so a sender that gets a 2xx can forget the event.
//!
//! No sender is known to this code: a profile is data, built in
//! (`inbound_profiles.yaml`) or declared by the operator.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderName};
use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::Value;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::config::events::{
    HmacAlgorithm, InboundProfileConfig, InboundRateLimitConfig, InboundSourceConfig,
    InboundWhenConfig, SignedPart, TextEncoding, find_inbound_profile, parse_signed_payload,
};

/// Most items of one signature header that are read.
const MAX_SIGNATURE_ITEMS: usize = 32;
/// Most signatures of one request that are checked.
const MAX_SIGNATURES: usize = 8;
/// Longest string a handshake reply echoes.
pub const MAX_ECHO_CHARS: usize = 256;
/// Longest signed timestamp, in digits.
const MAX_TIMESTAMP_DIGITS: usize = 20;

/// Resolved HMAC keys.
type Keys = Vec<Zeroizing<Vec<u8>>>;

/// How a request proves its sender, with the secrets resolved.
pub enum InboundVerifier {
    /// An HMAC by a signing profile.
    Signed { profile: SigningProfile, keys: Keys },
    /// No proof; accepted because the operator set `allow_unsigned`.
    Unsigned,
}

impl fmt::Debug for InboundVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed { profile, keys } => f
                .debug_struct("InboundVerifier::Signed")
                .field("profile", &profile.name)
                .field("secrets", &keys.len())
                .finish(),
            Self::Unsigned => f.write_str("InboundVerifier::Unsigned"),
        }
    }
}

/// A signing profile, ready to check requests.
#[derive(Debug)]
pub struct SigningProfile {
    name: String,
    algorithm: HmacAlgorithm,
    signature_header: HeaderName,
    separator: Option<String>,
    key: Option<String>,
    prefix: String,
    encoding: TextEncoding,
    payload: Vec<Signed>,
    timestamp: Option<TimestampAt>,
    tolerance_secs: u64,
    event_id_header: Option<HeaderName>,
    event_id_pointer: Option<String>,
    event_time_pointer: Option<String>,
    handshakes: Vec<(InboundFilter, BTreeMap<String, String>)>,
}

/// A compiled piece of the signed message.
#[derive(Debug)]
enum Signed {
    Text(Vec<u8>),
    Body,
    Timestamp,
    Header(HeaderName),
}

/// Where the signed timestamp is.
#[derive(Debug)]
enum TimestampAt {
    Header(HeaderName),
    Key(String),
}

/// A request the route answers itself; it never becomes an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handshake {
    /// Acknowledged with `202` and no body.
    Ack,
    /// Answered `200` with this JSON object.
    Reply(serde_json::Map<String, Value>),
    /// A reply field is missing or unsafe to echo.
    Invalid,
}

/// Why an inbound request was refused. Carries no request value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundRejection {
    /// No valid signature, or the signature headers are malformed.
    Unauthorized,
    /// The signed timestamp is outside the tolerance.
    Stale,
}

/// What a verified request established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedInbound {
    /// The sender's event id from a header the profile names.
    pub message_id: Option<String>,
}

impl SigningProfile {
    /// `config` compiled, with the route's tolerance in place of the
    /// profile's when it sets one.
    pub fn compile(config: &InboundProfileConfig, tolerance: Option<u64>) -> anyhow::Result<Self> {
        let name = &config.name;
        let header = |value: &str| {
            HeaderName::try_from(value).map_err(|_| {
                anyhow::anyhow!("inbound profile `{name}`: `{value}` is not a header name")
            })
        };
        let payload = parse_signed_payload(&config.signed_payload)
            .map_err(|e| anyhow::anyhow!("inbound profile `{name}`: signed_payload {e}"))?
            .into_iter()
            .map(|part| {
                Ok(match part {
                    SignedPart::Text(text) => Signed::Text(text.into_bytes()),
                    SignedPart::Body => Signed::Body,
                    SignedPart::Timestamp => Signed::Timestamp,
                    SignedPart::Header(value) => Signed::Header(header(&value)?),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let timestamp = match &config.signed_timestamp {
            None => None,
            Some(stamp) => Some(match (&stamp.header, &stamp.key) {
                (Some(value), _) => TimestampAt::Header(header(value)?),
                (None, Some(key)) => TimestampAt::Key(key.clone()),
                (None, None) => anyhow::bail!(
                    "inbound profile `{name}`: signed_timestamp names neither a header nor a key"
                ),
            }),
        };
        let mut handshakes = Vec::with_capacity(config.handshakes.len());
        for handshake in &config.handshakes {
            handshakes.push((
                InboundFilter::from_when(name, Some(&handshake.when))?,
                handshake.reply.clone(),
            ));
        }
        let event_id = config.event_id.as_ref();
        Ok(Self {
            name: name.clone(),
            algorithm: config.algorithm,
            signature_header: header(&config.signature.header)?,
            separator: config.signature.separator.clone(),
            key: config.signature.key.clone(),
            prefix: config.signature.prefix.clone(),
            encoding: config.signature.encoding,
            payload,
            timestamp,
            tolerance_secs: tolerance
                .or(config.signed_timestamp.as_ref().map(|t| t.tolerance_secs))
                .unwrap_or(0),
            event_id_header: event_id
                .and_then(|e| e.header.as_deref())
                .map(header)
                .transpose()?,
            event_id_pointer: event_id.and_then(|e| e.pointer.clone()),
            event_time_pointer: config.event_time.clone(),
            handshakes,
        })
    }

    /// The signatures, and the signed timestamp when the profile reads it
    /// from the signature header; `None` when the header is unusable.
    fn read_signature<'a>(&self, value: &'a str) -> Option<(Vec<Vec<u8>>, Option<&'a str>)> {
        let items: Vec<&str> = match &self.separator {
            Some(separator) => value
                .split(separator.as_str())
                .take(MAX_SIGNATURE_ITEMS)
                .collect(),
            None => vec![value],
        };
        let stamp_key = match &self.timestamp {
            Some(TimestampAt::Key(key)) => Some(key.as_str()),
            _ => None,
        };
        let mut digests = Vec::new();
        let mut stamp = None;
        for item in items {
            let item = item.trim();
            let candidate = match &self.key {
                Some(key) => {
                    let Some((name, field)) = item.split_once('=') else {
                        continue;
                    };
                    if Some(name) == stamp_key {
                        if stamp.replace(field).is_some() {
                            return None;
                        }
                        continue;
                    }
                    if name != key {
                        continue;
                    }
                    field
                }
                None => item,
            };
            if digests.len() < MAX_SIGNATURES
                && let Some(digest) = candidate
                    .strip_prefix(self.prefix.as_str())
                    .and_then(|d| decode(self.encoding, d))
                    .filter(|d| d.len() == digest_len(self.algorithm))
            {
                digests.push(digest);
            }
        }
        (!digests.is_empty()).then_some((digests, stamp))
    }
}

impl InboundVerifier {
    /// The verifier `config` describes, its profile looked up in
    /// `profiles` and then the built-in ones, with each secret resolved by
    /// `resolve` (`${env.…}` / `${secret.…}`). Errors name the source and
    /// never a secret.
    pub async fn build<F, Fut>(
        config: &InboundSourceConfig,
        profiles: &[InboundProfileConfig],
        resolve: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<String>>,
    {
        let at = &config.source_id;
        let Some(verify) = &config.verify else {
            return Ok(Self::Unsigned);
        };
        let profile = find_inbound_profile(profiles, &verify.profile).ok_or_else(|| {
            anyhow::anyhow!(
                "inbound source `{at}`: verify.profile `{}` is not a known profile",
                verify.profile
            )
        })?;
        let mut keys = Vec::with_capacity(verify.secrets.len());
        for (index, raw) in verify.secrets.iter().enumerate() {
            let value = Zeroizing::new(resolve(raw.clone()).await.map_err(|e| {
                anyhow::anyhow!(
                    "inbound source `{at}`: verify.secrets[{index}] did not resolve: {e}"
                )
            })?);
            let key = secret_key(profile, &value).map_err(|reason| {
                anyhow::anyhow!("inbound source `{at}`: verify.secrets[{index}] {reason}")
            })?;
            keys.push(key);
        }
        Ok(Self::Signed {
            profile: SigningProfile::compile(profile, verify.tolerance_secs)?,
            keys,
        })
    }

    /// The body pointer of the sender's event id the profile names.
    pub fn event_id_pointer(&self) -> Option<&str> {
        match self {
            Self::Signed { profile, .. } => profile.event_id_pointer.as_deref(),
            Self::Unsigned => None,
        }
    }

    /// The body pointer of the event time the profile names.
    pub fn event_time_pointer(&self) -> Option<&str> {
        match self {
            Self::Signed { profile, .. } => profile.event_time_pointer.as_deref(),
            Self::Unsigned => None,
        }
    }

    /// Check the request's proof over its raw `body`. `now` is Unix
    /// seconds.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: u64,
    ) -> Result<VerifiedInbound, InboundRejection> {
        let Self::Signed { profile, keys } = self else {
            return Ok(VerifiedInbound::default());
        };
        let value = single_header(headers, profile.signature_header.as_str())
            .ok_or(InboundRejection::Unauthorized)?;
        let (digests, keyed_stamp) = profile
            .read_signature(value)
            .ok_or(InboundRejection::Unauthorized)?;
        let stamp = match &profile.timestamp {
            None => None,
            Some(TimestampAt::Header(name)) => {
                Some(single_header(headers, name.as_str()).ok_or(InboundRejection::Unauthorized)?)
            }
            Some(TimestampAt::Key(_)) => Some(keyed_stamp.ok_or(InboundRejection::Unauthorized)?),
        };
        let stamp_secs = stamp.map(unix_seconds).transpose()?;
        let mut parts: Vec<&[u8]> = Vec::with_capacity(profile.payload.len());
        for part in &profile.payload {
            parts.push(match part {
                Signed::Text(text) => text.as_slice(),
                Signed::Body => body,
                Signed::Timestamp => stamp.ok_or(InboundRejection::Unauthorized)?.as_bytes(),
                Signed::Header(name) => single_header(headers, name.as_str())
                    .ok_or(InboundRejection::Unauthorized)?
                    .as_bytes(),
            });
        }
        let mut matched = subtle::Choice::from(0);
        for key in keys {
            let want = mac(profile.algorithm, key, &parts);
            for digest in &digests {
                matched |= want.as_slice().ct_eq(digest.as_slice());
            }
        }
        if !bool::from(matched) {
            return Err(InboundRejection::Unauthorized);
        }
        if let Some(at) = stamp_secs
            && now.abs_diff(at) > profile.tolerance_secs
        {
            return Err(InboundRejection::Stale);
        }
        Ok(VerifiedInbound {
            message_id: profile
                .event_id_header
                .as_ref()
                .and_then(|name| single_header(headers, name.as_str()))
                .map(str::to_owned),
        })
    }

    /// The handshake a verified request is, when its profile names one.
    pub fn handshake(&self, headers: &HeaderMap, body: &Value) -> Option<Handshake> {
        let Self::Signed { profile, .. } = self else {
            return None;
        };
        let (_, reply) = profile
            .handshakes
            .iter()
            .find(|(filter, _)| filter.keeps(headers, body))?;
        if reply.is_empty() {
            return Some(Handshake::Ack);
        }
        let mut object = serde_json::Map::with_capacity(reply.len());
        for (key, pointer) in reply {
            match body.pointer(pointer).and_then(Value::as_str) {
                Some(echo) if is_echo_safe(echo) => {
                    object.insert(key.clone(), Value::String(echo.to_owned()));
                }
                _ => return Some(Handshake::Invalid),
            }
        }
        Some(Handshake::Reply(object))
    }
}

/// The HMAC key a configured secret encodes, by the profile's `secret`
/// format. The error never carries the value.
fn secret_key(profile: &InboundProfileConfig, value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let format = &profile.secret;
    let rest = match &format.prefix {
        Some(prefix) => value
            .trim()
            .strip_prefix(prefix.as_str())
            .ok_or("does not start with the profile's secret prefix")?,
        None => value,
    };
    let key = Zeroizing::new(
        match format.encoding {
            TextEncoding::Utf8 => Some(rest.as_bytes().to_vec()),
            encoding => decode(encoding, rest.trim()),
        }
        .ok_or("is not in the profile's secret encoding")?,
    );
    if key.is_empty() {
        return Err("is empty".to_owned());
    }
    let len = key.len() as u64;
    let min = format.min_bytes.map_or(1, u64::from);
    let max = format.max_bytes.map(u64::from);
    if len < min || max.is_some_and(|max| len > max) {
        return Err(match max {
            Some(max) => format!("is not between {min} and {max} bytes once decoded"),
            None => format!("is shorter than {min} bytes once decoded"),
        });
    }
    Ok(key)
}

/// `text` decoded by `encoding`.
fn decode(encoding: TextEncoding, text: &str) -> Option<Vec<u8>> {
    match encoding {
        TextEncoding::Utf8 => Some(text.as_bytes().to_vec()),
        TextEncoding::Hex => hex::decode(text).ok(),
        TextEncoding::Base64 => base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(text.trim_end_matches('='))
            .ok(),
    }
}

/// The digest length of `algorithm`, in bytes.
fn digest_len(algorithm: HmacAlgorithm) -> usize {
    match algorithm {
        HmacAlgorithm::Sha1 => 20,
        HmacAlgorithm::Sha256 => 32,
        HmacAlgorithm::Sha512 => 64,
    }
}

/// The HMAC of the concatenated `parts` under `key`.
fn mac(algorithm: HmacAlgorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    fn run<M: hmac::Mac + hmac::KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <M as hmac::KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }
    match algorithm {
        HmacAlgorithm::Sha1 => run::<hmac::Hmac<sha1::Sha1>>(key, parts),
        HmacAlgorithm::Sha256 => run::<hmac::Hmac<sha2::Sha256>>(key, parts),
        HmacAlgorithm::Sha512 => run::<hmac::Hmac<sha2::Sha512>>(key, parts),
    }
}

/// A signed timestamp as Unix seconds; only ASCII digits are accepted.
fn unix_seconds(stamp: &str) -> Result<u64, InboundRejection> {
    if stamp.is_empty()
        || stamp.len() > MAX_TIMESTAMP_DIGITS
        || !stamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(InboundRejection::Unauthorized);
    }
    stamp.parse().map_err(|_| InboundRejection::Unauthorized)
}

/// Whether `echo` is safe to send back: printable ASCII, bounded.
fn is_echo_safe(echo: &str) -> bool {
    !echo.is_empty() && echo.len() <= MAX_ECHO_CHARS && echo.bytes().all(|b| b.is_ascii_graphic())
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().filter(|v| !v.is_empty()),
        _ => None,
    }
}

/// A `when:` filter, ready to apply.
#[derive(Debug, Clone, Default)]
pub struct InboundFilter {
    header: Vec<(HeaderName, String)>,
    body: BTreeMap<String, Value>,
}

impl InboundFilter {
    /// The filter of `config`; an absent `when` keeps every request.
    pub fn from_config(config: &InboundSourceConfig) -> anyhow::Result<Self> {
        Self::from_when(&config.source_id, config.when.as_ref())
    }

    /// The filter `when` describes for `owner`, a source id or a profile
    /// name that errors carry.
    fn from_when(owner: &str, when: Option<&InboundWhenConfig>) -> anyhow::Result<Self> {
        let Some(when) = when else {
            return Ok(Self::default());
        };
        let mut header = Vec::with_capacity(when.header.len());
        for (name, value) in &when.header {
            let name = HeaderName::try_from(name.as_str()).map_err(|_| {
                anyhow::anyhow!("inbound `{owner}`: when.header `{name}` is not a header name")
            })?;
            header.push((name, value.clone()));
        }
        Ok(Self {
            header,
            body: when.body.clone(),
        })
    }

    /// Whether the request is one the filter keeps.
    pub fn keeps(&self, headers: &HeaderMap, body: &Value) -> bool {
        self.header
            .iter()
            .all(|(name, want)| single_header(headers, name.as_str()) == Some(want.as_str()))
            && self
                .body
                .iter()
                .all(|(pointer, want)| body.pointer(pointer) == Some(want))
    }
}

/// The sender's event id: the value at `pointer` in the body (a string or
/// a number), else the id a header of the profile carried.
pub fn extract_event_id(
    pointer: Option<&str>,
    body: &Value,
    verified: &VerifiedInbound,
) -> Option<String> {
    if let Some(pointer) = pointer {
        return match body.pointer(pointer)? {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        };
    }
    verified.message_id.clone()
}

/// The event time at `pointer` in the body, as RFC 3339 UTC: an RFC 3339
/// string or Unix seconds. `None` when absent or unreadable.
pub fn extract_timestamp(pointer: Option<&str>, body: &Value) -> Option<String> {
    let value = body.pointer(pointer?)?;
    let at = match value {
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()?
            .with_timezone(&chrono::Utc),
        Value::Number(n) => chrono::DateTime::from_timestamp(n.as_i64()?, 0)?,
        _ => return None,
    };
    Some(at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// A token bucket of one source on this replica.
#[derive(Debug)]
pub struct RateLimiter {
    per_sec: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl RateLimiter {
    pub fn new(config: &InboundRateLimitConfig) -> Self {
        let burst = config.burst.max(1) as f64;
        Self {
            per_sec: config.per_sec.max(1) as f64,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    /// Take one token at `now`; `Err` carries how long until one is free.
    pub fn take_at(&self, now: Instant) -> Result<(), Duration> {
        let mut state = self.state.lock();
        let elapsed = now.saturating_duration_since(state.1).as_secs_f64();
        state.0 = (state.0 + elapsed * self.per_sec).min(self.burst);
        state.1 = now;
        if state.0 >= 1.0 {
            state.0 -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - state.0) / self.per_sec))
        }
    }

    pub fn take(&self) -> Result<(), Duration> {
        self.take_at(Instant::now())
    }
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;
