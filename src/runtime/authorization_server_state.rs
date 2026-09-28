//! The sealed state of interactive sign-in: transactions, authorization
//! codes, grants, refresh tokens, the stored IdP sign-in of each user,
//! dynamic registrations and the revocations every replica honours.
//!
//! Every record lives under [`STATE_PREFIX`] in one key-value store: the
//! cluster coordinator's (shared by every replica), a [`FileStore`] on a
//! single node, or process memory. Every value is sealed by the
//! [`StateKeyring`] (XChaCha20-Poly1305) with `mcpg.as.v1`, the record's
//! key and the issuer as associated data, so a record copied under
//! another key, or read by a server with another issuer, does not open; a
//! record that does not open counts as absent. Keys carry hashes of codes,
//! tokens and state values ([`handle`]), never the values. The values a
//! browser holds, a consent form's request and the remembered consent of
//! a browser, are sealed the same way under a label of their own
//! ([`InteractiveState::seal_value`]).
//!
//! Single use rests on [`KeyValueStore::put_if_absent`], atomic on every
//! store this module is given. A reload hands [`InteractiveState`]'s
//! in-process or file store, its key and its revoked set to the state of
//! the server that replaces it.

use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore};
use mcpg_plugin_host::credential_cache_cipher::EventCipher;
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::rar::AuthorizationDetails;

#[path = "authorization_server_file_store.rs"]
pub mod file_store;

pub use file_store::{FileStore, FileStoreLimits};

/// Namespace of every record in the store.
pub const STATE_PREFIX: &str = "as/v1/";
/// First part of the associated data every record is sealed with.
const AAD_LABEL: &str = "mcpg.as.v1";
/// Domain of the state key derived from the cluster state key.
pub const STATE_KEY_DOMAIN: &[u8] = b"mcpg:as-state:v1";
/// Domain of the consent-form key derived from each state key.
pub const CSRF_KEY_DOMAIN: &[u8] = b"mcpg:as-csrf:v1";
/// Largest record, in bytes before sealing.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Key id of a key generated for the life of the process.
pub const PROCESS_KEY_ID: &str = "process";
/// Key id of the key generated into a file store's `state.key`. An
/// operator moving that key into `interactive.state_keys` keeps this kid.
pub const GENERATED_KEY_ID: &str = "generated";
/// Key id of the key derived from the cluster state key when
/// `cluster.state_encryption_key_id` is unset.
pub const CLUSTER_KEY_ID: &str = "cluster";
/// How often process memory drops expired records.
const MEMORY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Most tombstones one listing of the revocation poll reads; a poll lists
/// again, by longer prefixes, until it has read them all.
const REVOCATION_LIST_LIMIT: usize = 100_000;
/// How long a tombstone whose store reports no expiry, and whose record
/// does not open, is honoured.
const TOMBSTONE_FALLBACK_SECS: u64 = 3_600;
/// Pause between attempts to take a busy lease.
const LEASE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// Most approvals one browser's consent cookie keeps.
pub const MAX_REMEMBERED_APPROVALS: usize = 20;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_secs(at: SystemTime) -> Option<u64> {
    at.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// A store TTL of at least one second, the coarsest granularity of the
/// stores this module runs on.
fn store_ttl(ttl: Duration) -> Duration {
    ttl.max(Duration::from_secs(1))
}

fn count_error(op: &'static str) {
    metrics::counter!("mcpg_as_state_errors_total", "op" => op).increment(1);
}

// ---------------------------------------------------------------------------
// Errors and randomness
// ---------------------------------------------------------------------------

/// Why a state operation failed. Every variant fails the request closed
/// (`temporarily_unavailable`); none carries a key, token or record.
#[derive(Debug)]
pub enum StateError {
    /// The key-value store failed or is unavailable.
    Store(ClusterError),
    /// A record could not be sealed.
    Seal,
    /// A record exceeds [`MAX_RECORD_BYTES`].
    TooLarge { bytes: usize },
    /// The operating system's random number generator failed.
    Random,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "the sign-in state store failed: {error}"),
            Self::Seal => f.write_str("a sign-in record could not be sealed"),
            Self::TooLarge { bytes } => write!(
                f,
                "a sign-in record of {bytes} bytes exceeds {MAX_RECORD_BYTES} bytes"
            ),
            Self::Random => f.write_str("the operating system's random number generator failed"),
        }
    }
}

impl std::error::Error for StateError {}

fn store_error(error: ClusterError) -> StateError {
    count_error("kv");
    StateError::Store(error)
}

/// `N` bytes from the operating system's random number generator.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], StateError> {
    use chacha20poly1305::aead::Generate as _;
    <[u8; N]>::try_generate().map_err(|_| StateError::Random)
}

/// 256 random bits in URL-safe base64, without padding.
pub fn random_token() -> Result<String, StateError> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

// ---------------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------------

/// Where the keys of a [`StateKeyring`] come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringSource {
    /// `interactive.state_keys`.
    Configured,
    /// Derived from the cluster state key.
    ClusterKey,
    /// Read from, or generated into, this file.
    File(PathBuf),
    /// Generated for the life of the process.
    Process,
}

struct RingKey {
    kid: String,
    secret: Zeroizing<[u8; 32]>,
    cipher: EventCipher,
}

/// The keys that seal state records, newest first: the first seals, and
/// a record opens under whichever key its kid names.
pub struct StateKeyring {
    keys: Vec<RingKey>,
    source: KeyringSource,
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for StateKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateKeyring")
            .field(
                "kids",
                &self.keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            )
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl StateKeyring {
    /// A keyring of `keys`, `(kid, key)` newest first.
    pub fn new(
        keys: Vec<(String, Zeroizing<[u8; 32]>)>,
        source: KeyringSource,
    ) -> anyhow::Result<Self> {
        if keys.is_empty() {
            anyhow::bail!("a state keyring needs at least one key");
        }
        let mut fingerprint = blake3::Hasher::new_derive_key("mcpg as v1 keyring fingerprint");
        let mut ring = Vec::with_capacity(keys.len());
        for (kid, secret) in keys {
            if ring.iter().any(|k: &RingKey| k.kid == kid) {
                anyhow::bail!("the state keyring lists kid `{kid}` more than once");
            }
            let cipher = EventCipher::from_raw_key(&secret, kid.clone())
                .map_err(|e| anyhow::anyhow!("state key `{kid}`: {e}"))?;
            fingerprint.update(&(kid.len() as u64).to_le_bytes());
            fingerprint.update(kid.as_bytes());
            fingerprint.update(secret.as_slice());
            ring.push(RingKey {
                kid,
                secret,
                cipher,
            });
        }
        Ok(Self {
            keys: ring,
            source,
            fingerprint: *fingerprint.finalize().as_bytes(),
        })
    }

    /// The keyring of `interactive.state_keys`. No secret appears in an
    /// error.
    pub fn from_config(keys: &[crate::config::StateKeyConfig]) -> anyhow::Result<Self> {
        use base64::Engine as _;
        let mut ring = Vec::with_capacity(keys.len());
        for (index, entry) in keys.iter().enumerate() {
            let decoded = Zeroizing::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(entry.secret.trim().trim_end_matches('='))
                    .unwrap_or_default(),
            );
            if decoded.len() != 32 {
                anyhow::bail!(
                    "governance.access.authorization_server.interactive.state_keys[{index}].secret \
                     is not a 32-byte URL-safe base64 key"
                );
            }
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&decoded);
            ring.push((entry.kid.clone(), secret));
        }
        Self::new(ring, KeyringSource::Configured)
    }

    /// The key derived from the cluster state key `base`, identical on
    /// every replica that holds it. `kid` is `cluster.state_encryption_key_id`.
    pub fn from_cluster_key(base: &[u8; 32], kid: Option<&str>) -> anyhow::Result<Self> {
        let derived = Zeroizing::new(crate::app::derive_cluster_subkey(base, STATE_KEY_DOMAIN));
        Self::new(
            vec![(kid.unwrap_or(CLUSTER_KEY_ID).to_owned(), derived)],
            KeyringSource::ClusterKey,
        )
    }

    /// The key in the file at `path`, generated there when absent; and
    /// whether it was generated. Call it only with the file store that
    /// owns `path` open.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<(Self, bool)> {
        let file = file_store::load_or_generate_key(path)?;
        let ring = Self::new(
            vec![(GENERATED_KEY_ID.to_owned(), file.key)],
            KeyringSource::File(path.to_owned()),
        )?;
        Ok((ring, file.generated))
    }

    /// A key generated for the life of this process.
    pub fn process() -> anyhow::Result<Self> {
        let key = Zeroizing::new(random_bytes::<32>()?);
        Self::new(
            vec![(PROCESS_KEY_ID.to_owned(), key)],
            KeyringSource::Process,
        )
    }

    pub fn source(&self) -> &KeyringSource {
        &self.source
    }

    /// The kid new records are sealed under.
    pub fn sealing_kid(&self) -> &str {
        &self.keys[0].kid
    }

    /// Every kid, the sealing one first.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| k.kid.as_str())
    }

    /// Whether both keyrings hold the same kids and keys in the same
    /// order.
    pub fn same_keys(&self, other: &StateKeyring) -> bool {
        self.fingerprint.ct_eq(&other.fingerprint).into()
    }

    /// Seal `plaintext` under the sealing key, bound to `aad`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StateError> {
        self.keys[0].cipher.seal(plaintext, aad).map_err(|_| {
            count_error("seal");
            StateError::Seal
        })
    }

    /// Open a sealed value under the key its kid names; `None` when no
    /// key opens it with `aad`.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        self.keys
            .iter()
            .find_map(|key| key.cipher.open(sealed, aad).ok())
    }

    /// A key per state key for `domain`, the sealing key's first: a
    /// value made with the first verifies under any.
    pub fn derive(&self, domain: &[u8]) -> Vec<Zeroizing<[u8; 32]>> {
        self.keys
            .iter()
            .map(|key| Zeroizing::new(crate::app::derive_cluster_subkey(&key.secret, domain)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// What a hashed handle stands for; each kind hashes in its own domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleKind {
    /// The sealed consent request of a consent form.
    ConsentRequest,
    /// A client and the PKCE challenge it sent.
    PkceChallenge,
    /// The `state` sent to the IdP.
    State,
    /// An authorization code.
    Code,
    /// A refresh token.
    RefreshToken,
    /// A principal key.
    Principal,
    /// A client IP address.
    ClientIp,
    /// The `jti` of an access token.
    Jti,
    /// A link id.
    Link,
}

impl HandleKind {
    fn context(self) -> &'static str {
        match self {
            Self::ConsentRequest => "mcpg as v1 consent_req",
            Self::PkceChallenge => "mcpg as v1 pkce",
            Self::State => "mcpg as v1 state",
            Self::Code => "mcpg as v1 code",
            Self::RefreshToken => "mcpg as v1 rt",
            Self::Principal => "mcpg as v1 principal",
            Self::ClientIp => "mcpg as v1 ip",
            Self::Jti => "mcpg as v1 jti",
            Self::Link => "mcpg as v1 link",
        }
    }
}

/// The hex BLAKE3 hash of `parts` in the domain of `kind`, each part
/// length-prefixed so no two sequences of parts hash alike. The store
/// never holds a usable code, token or state value, only this.
pub fn handle(kind: HandleKind, parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(kind.context());
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

/// A grant id: 128 random bits in lowercase hex. A handle, not a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GrantId(String);

impl GrantId {
    pub fn generate() -> Result<Self, StateError> {
        Ok(Self(hex::encode(random_bytes::<16>()?)))
    }

    /// `value` when it is a grant id.
    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for GrantId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value).ok_or_else(|| "not a grant id".to_owned())
    }
}

impl From<GrantId> for String {
    fn from(id: GrantId) -> Self {
        id.0
    }
}

/// A record type of the store.
pub trait StateRecord: Serialize + DeserializeOwned + Send + Sync + 'static {}

/// The key of one record of type `R`.
pub struct RecordKey<R> {
    key: String,
    record: PhantomData<fn() -> R>,
}

impl<R> RecordKey<R> {
    fn new(logical: impl std::fmt::Display) -> Self {
        Self {
            key: format!("{STATE_PREFIX}{logical}"),
            record: PhantomData,
        }
    }

    /// The key in the store.
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The key within [`STATE_PREFIX`], which the seal binds.
    pub fn logical(&self) -> &str {
        &self.key[STATE_PREFIX.len()..]
    }
}

impl<R> Clone for RecordKey<R> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            record: PhantomData,
        }
    }
}

impl<R> std::fmt::Debug for RecordKey<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.key)
    }
}

/// A key prefix whose records are all of type `R`.
pub struct RecordPrefix<R> {
    prefix: String,
    record: PhantomData<fn() -> R>,
}

impl<R> RecordPrefix<R> {
    fn new(logical: impl std::fmt::Display) -> Self {
        Self {
            prefix: format!("{STATE_PREFIX}{logical}"),
            record: PhantomData,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.prefix
    }
}

/// The key of a counter. Counters hold a count only and are not sealed:
/// the stores add to them in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterKey(String);

impl CounterKey {
    fn new(logical: impl std::fmt::Display) -> Self {
        Self(format!("{STATE_PREFIX}{logical}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The key of every record, by the row of the state table it stores.
pub mod keys {
    use super::{
        CodeRecord, CodeUsedRecord, CounterKey, DcrClientRecord, GrantId, GrantRecord, HandleKind,
        IdpSessionRecord, LeaseRecord, LinkRecord, LinkRefRecord, Marker, PrincipalGrantRecord,
        RecordKey, RecordPrefix, RefreshRecord, RefreshUsedRecord, RevokedId, TombstoneRecord,
        TransactionRecord, handle,
    };

    /// Most bytes of a dynamically registered client id.
    const MAX_DCR_CLIENT_ID_BYTES: usize = 64;

    /// A consent form's request was decided (`consent_used/h(req)`).
    pub fn consent_used(req: &str) -> RecordKey<Marker> {
        RecordKey::new(format_args!(
            "consent_used/{}",
            handle(HandleKind::ConsentRequest, &[req.as_bytes()])
        ))
    }

    /// A client sent this PKCE challenge
    /// (`pkce_seen/h(client_id || challenge)`).
    pub fn pkce_seen(client_id: &str, code_challenge: &str) -> RecordKey<Marker> {
        RecordKey::new(format_args!(
            "pkce_seen/{}",
            handle(
                HandleKind::PkceChallenge,
                &[client_id.as_bytes(), code_challenge.as_bytes()]
            )
        ))
    }

    /// A sign-in in progress at the IdP (`txn/h(state)`).
    pub fn transaction(state: &str) -> RecordKey<TransactionRecord> {
        RecordKey::new(format_args!(
            "txn/{}",
            handle(HandleKind::State, &[state.as_bytes()])
        ))
    }

    /// The IdP's answer to a sign-in was taken (`txn_used/h(state)`).
    pub fn transaction_used(state: &str) -> RecordKey<Marker> {
        RecordKey::new(format_args!(
            "txn_used/{}",
            handle(HandleKind::State, &[state.as_bytes()])
        ))
    }

    /// An authorization code (`code/h(code)`).
    pub fn code(code: &str) -> RecordKey<CodeRecord> {
        RecordKey::new(format_args!(
            "code/{}",
            handle(HandleKind::Code, &[code.as_bytes()])
        ))
    }

    /// An authorization code was redeemed (`code_used/h(code)`).
    pub fn code_used(code: &str) -> RecordKey<CodeUsedRecord> {
        RecordKey::new(format_args!(
            "code_used/{}",
            handle(HandleKind::Code, &[code.as_bytes()])
        ))
    }

    /// A grant (`grant/<gid>`).
    pub fn grant(gid: &GrantId) -> RecordKey<GrantRecord> {
        RecordKey::new(format_args!("grant/{gid}"))
    }

    /// One grant of a principal (`pgrants/h(principal)/<gid>`).
    pub fn principal_grant(principal: &str, gid: &GrantId) -> RecordKey<PrincipalGrantRecord> {
        RecordKey::new(format_args!(
            "pgrants/{}/{gid}",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        ))
    }

    /// Every grant of a principal.
    pub fn principal_grants(principal: &str) -> RecordPrefix<PrincipalGrantRecord> {
        RecordPrefix::new(format_args!(
            "pgrants/{}/",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        ))
    }

    /// A live refresh token (`rt/h(rt)`).
    pub fn refresh(token: &str) -> RecordKey<RefreshRecord> {
        RecordKey::new(format_args!(
            "rt/{}",
            handle(HandleKind::RefreshToken, &[token.as_bytes()])
        ))
    }

    /// A spent refresh token (`rt_used/h(rt)`).
    pub fn refresh_used(token: &str) -> RecordKey<RefreshUsedRecord> {
        RecordKey::new(format_args!(
            "rt_used/{}",
            handle(HandleKind::RefreshToken, &[token.as_bytes()])
        ))
    }

    /// A revocation (`revoked/<gid>` or `revoked/jti.h(jti)`).
    pub fn revoked(id: &RevokedId) -> RecordKey<TombstoneRecord> {
        RecordKey::new(format_args!("revoked/{}", id.suffix()))
    }

    /// Every revocation.
    pub fn revocations() -> RecordPrefix<TombstoneRecord> {
        RecordPrefix::new("revoked/")
    }

    /// The stored IdP sign-in of a principal (`idp/h(principal)`).
    pub fn idp_session(principal: &str) -> RecordKey<IdpSessionRecord> {
        RecordKey::new(format_args!(
            "idp/{}",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        ))
    }

    /// The lease on a principal's IdP sign-in (`idp_lock/h(principal)`).
    pub fn idp_lease(principal: &str) -> RecordKey<LeaseRecord> {
        RecordKey::new(format_args!(
            "idp_lock/{}",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        ))
    }

    /// A dynamically registered client (`dcr/<client_id>`); `None` for an
    /// id that is not 1 to 64 characters of `[A-Za-z0-9_-]`.
    pub fn dcr_client(client_id: &str) -> Option<RecordKey<DcrClientRecord>> {
        let valid = !client_id.is_empty()
            && client_id.len() <= MAX_DCR_CLIENT_ID_BYTES
            && client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        valid.then(|| RecordKey::new(format_args!("dcr/{client_id}")))
    }

    /// Every dynamically registered client.
    pub fn dcr_clients() -> RecordPrefix<DcrClientRecord> {
        RecordPrefix::new("dcr/")
    }

    /// The number of dynamically registered clients.
    pub fn dcr_count() -> CounterKey {
        CounterKey::new("dcr_count")
    }

    /// The registrations were counted again from the store
    /// (`dcr_recount`).
    pub fn dcr_recount() -> RecordKey<Marker> {
        RecordKey::new("dcr_recount")
    }

    /// Registrations from one client IP address in the clock hour `hour`
    /// (Unix seconds / 3600).
    pub fn dcr_rate(ip: &str, hour: u64) -> CounterKey {
        CounterKey::new(format_args!(
            "dcr_rate/{hour}/{}",
            handle(HandleKind::ClientIp, &[ip.as_bytes()])
        ))
    }

    /// A link to an IdP sign-in offered to a user (`link/h(id)`).
    pub fn link(id: &str) -> RecordKey<LinkRecord> {
        RecordKey::new(format_args!(
            "link/{}",
            handle(HandleKind::Link, &[id.as_bytes()])
        ))
    }

    /// A link was completed (`link_done/h(id)`).
    pub fn link_done(id: &str) -> RecordKey<Marker> {
        RecordKey::new(format_args!(
            "link_done/{}",
            handle(HandleKind::Link, &[id.as_bytes()])
        ))
    }

    /// The sign-in a link completed was stored (`link_stored/h(id)`).
    pub fn link_stored(id: &str) -> RecordKey<Marker> {
        RecordKey::new(format_args!(
            "link_stored/{}",
            handle(HandleKind::Link, &[id.as_bytes()])
        ))
    }

    /// The link offered to a principal on one MCP session, told of its
    /// completion or not (`link_by/h(principal || session || notify)`).
    pub fn pending_link(principal: &str, session: &str, notify: bool) -> RecordKey<LinkRefRecord> {
        RecordKey::new(format_args!(
            "link_by/{}",
            handle(
                HandleKind::Principal,
                &[
                    principal.as_bytes(),
                    session.as_bytes(),
                    if notify { b"notify" } else { b"silent" },
                ]
            )
        ))
    }

    /// New links offered to a principal in the window `window` (Unix
    /// seconds / the link lifetime).
    pub fn link_rate(principal: &str, window: u64) -> CounterKey {
        CounterKey::new(format_args!(
            "link_rate/{window}/{}",
            handle(HandleKind::Principal, &[principal.as_bytes()])
        ))
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// A secret string in a record: redacted in `Debug`, wiped on drop, and
/// compared in constant time.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Constant-time equality with `other` (a length difference still
    /// shows).
    pub fn ct_eq(&self, other: &str) -> bool {
        self.0.len() == other.len() && self.0.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(&other.0)
    }
}

impl Eq for SecretString {}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A claim that happened: consent decided, a PKCE challenge seen, a
/// sign-in's IdP answer taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    /// When, in Unix seconds.
    pub at: u64,
}

impl Marker {
    pub fn now() -> Self {
        Self { at: now_unix() }
    }
}

/// How the gateway knows a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// `authorization_server.clients[]`.
    Static,
    /// A Client ID Metadata Document.
    Cimd,
    /// A dynamic registration.
    Dcr,
}

impl ClientKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Cimd => "cimd",
            Self::Dcr => "dcr",
        }
    }
}

/// What a sign-in at the IdP is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPurpose {
    /// An authorization request of an MCP client.
    Authorize,
    /// `/oauth/connect`: store the user's IdP sign-in.
    Connect,
    /// A link offered to a user through elicitation.
    Link,
}

impl TransactionPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Connect => "connect",
            Self::Link => "link",
        }
    }
}

/// The client a sign-in is for, as known when it started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub client_id: String,
    pub kind: ClientKind,
    #[serde(default)]
    pub name: Option<String>,
}

/// A sign-in in progress at the IdP (`txn/h(state)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub purpose: TransactionPurpose,
    /// `None` for [`TransactionPurpose::Connect`].
    #[serde(default)]
    pub client: Option<ClientSnapshot>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub redirect_trusted: bool,
    #[serde(default)]
    pub consent_approved: bool,
    /// The client's `state`, returned to it unchanged.
    #[serde(default)]
    pub client_state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Vec<String>,
    /// The IdP the user signs in at.
    pub idp_issuer: String,
    pub nonce: SecretString,
    /// The PKCE verifier toward the IdP.
    pub pkce_verifier: SecretString,
    /// Hex BLAKE3 of the browser binding cookie.
    pub binder_hash: String,
    pub created: u64,
    #[serde(default)]
    pub link_id: Option<String>,
    /// The thumbprint of the DPoP key the client's authorization request
    /// named (`dpop_jkt`, RFC 9449 §10).
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// The authorization details (RFC 9396) the client's authorization
    /// request asked for.
    #[serde(default, skip_serializing_if = "AuthorizationDetails::is_empty")]
    pub authorization_details: AuthorizationDetails,
}

/// An authorization code (`code/h(code)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRecord {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: String,
    #[serde(default)]
    pub scope: Vec<String>,
    pub gid: GrantId,
    pub exp: u64,
    /// The DPoP key the code redeems only with a proof of.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// The authorization details the user approved.
    #[serde(default, skip_serializing_if = "AuthorizationDetails::is_empty")]
    pub authorization_details: AuthorizationDetails,
}

/// A redeemed authorization code (`code_used/h(code)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUsedRecord {
    pub gid: GrantId,
}

/// Whether a grant's code was redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Pending,
    Active,
}

/// The user a grant was issued to, as the IdP described them at sign-in
/// or at the last check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySnapshot {
    pub subject: String,
    /// The IdP issuer.
    pub idp: String,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub auth_time: Option<u64>,
}

/// A grant (`grant/<gid>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub status: GrantStatus,
    pub principal: String,
    pub identity: IdentitySnapshot,
    pub client_id: String,
    pub client_kind: ClientKind,
    #[serde(default)]
    pub scope: Vec<String>,
    pub resource: String,
    pub redirect_uri: String,
    /// The authorization server's issuer.
    pub issuer: String,
    /// When the grant ends however it is used, in Unix seconds.
    pub abs_exp: u64,
    pub last_used: u64,
    /// Generation of the live refresh token.
    pub generation: u64,
    pub created: u64,
    /// The DPoP key the grant's refresh tokens redeem only with a proof
    /// of: a public client's, from its first proof (RFC 9449 §5).
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// The first generation of refresh tokens issued bound to `dpop_jkt`:
    /// 0 when the code redemption bound the grant. A spent token of an
    /// earlier generation was bound to no key.
    #[serde(default)]
    pub dpop_bound_generation: u64,
    /// The authorization details (RFC 9396) the user approved, which every
    /// access token of the grant carries or narrows.
    #[serde(default, skip_serializing_if = "AuthorizationDetails::is_empty")]
    pub authorization_details: AuthorizationDetails,
}

/// One grant of a principal (`pgrants/h(principal)/<gid>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalGrantRecord {
    pub created: u64,
}

/// A live refresh token (`rt/h(rt)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRecord {
    pub gid: GrantId,
    /// The grant generation this token carries; a lower one than the
    /// grant's is a spent token.
    pub generation: u64,
    pub client_id: String,
}

/// A spent refresh token (`rt_used/h(rt)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshUsedRecord {
    pub gid: GrantId,
    pub spent_at: u64,
    /// The grant generation the spent token carried.
    #[serde(default)]
    pub generation: u64,
    /// The successor, sealed under a key derived from the spent token,
    /// while a retry may still receive it.
    #[serde(default)]
    pub successor_sealed: Option<String>,
}

/// Why a grant or an access token was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The client revoked it.
    Client,
    /// A spent refresh token was presented again.
    RefreshReuse,
    /// A redeemed code was presented again.
    CodeReplay,
    /// The IdP no longer accepts the user.
    IdpRefused,
    /// The client is no longer admitted.
    ClientRemoved,
    /// The IdP no longer offers sign-in.
    IdpRemoved,
    /// The user holds more grants than allowed.
    MaxGrants,
    /// The stored IdP sign-in a refresh must check is gone, or can no
    /// longer be checked.
    IdpSessionExpired,
}

impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::RefreshReuse => "refresh_reuse",
            Self::CodeReplay => "code_replay",
            Self::IdpRefused => "idp_refused",
            Self::ClientRemoved => "client_removed",
            Self::IdpRemoved => "idp_removed",
            Self::MaxGrants => "max_grants",
            Self::IdpSessionExpired => "idp_session_expired",
        }
    }
}

/// A revocation (`revoked/...`). Its presence revokes; the record says
/// why and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstoneRecord {
    pub reason: RevocationReason,
    /// Until when, in Unix seconds.
    pub exp: u64,
}

/// How a stored IdP sign-in was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdpSessionOrigin {
    /// An MCP client's sign-in.
    Login,
    /// `/oauth/connect`.
    Connect,
    /// A link offered through elicitation.
    Link,
}

impl IdpSessionOrigin {
    /// The origin of the sign-in a transaction for `purpose` completes.
    pub fn of(purpose: TransactionPurpose) -> Self {
        match purpose {
            TransactionPurpose::Authorize => Self::Login,
            TransactionPurpose::Connect => Self::Connect,
            TransactionPurpose::Link => Self::Link,
        }
    }
}

/// The stored IdP sign-in of a principal (`idp/h(principal)`). Used only
/// toward the IdP token endpoint that issued it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdpSessionRecord {
    /// Record version.
    pub v: u32,
    /// The IdP issuer.
    pub issuer: String,
    /// The gateway's client id at the IdP.
    pub client_id: String,
    pub token_endpoint: String,
    pub sub: String,
    #[serde(default)]
    pub refresh_token: Option<SecretString>,
    pub id_token: SecretString,
    pub id_token_exp: u64,
    #[serde(default)]
    pub scope: String,
    pub obtained_at: u64,
    pub last_refreshed: u64,
    pub origin: IdpSessionOrigin,
    /// Incremented each time the sign-in is replaced or refreshed.
    pub generation: u64,
}

/// A lease (`idp_lock/h(principal)`): who holds it and the token that
/// releases it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub holder: String,
    pub token: String,
}

/// One remembered approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentApproval {
    pub client_id: String,
    /// The exact redirect URI approved.
    pub redirect_uri: String,
    /// The resource approved (RFC 8707), as this server names it.
    pub resource: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub approved_at: u64,
}

/// The approvals one browser remembers, at most
/// [`MAX_REMEMBERED_APPROVALS`]: sealed into its consent cookie, never
/// stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentMemoryRecord {
    #[serde(default)]
    pub approvals: Vec<ConsentApproval>,
}

impl ConsentMemoryRecord {
    /// Keep `approval` in place of any earlier one for the same client,
    /// redirect URI and resource, dropping the oldest beyond the limit.
    pub fn remember(&mut self, approval: ConsentApproval) {
        self.approvals.retain(|kept| {
            kept.client_id != approval.client_id
                || kept.redirect_uri != approval.redirect_uri
                || kept.resource != approval.resource
        });
        self.approvals.push(approval);
        if self.approvals.len() > MAX_REMEMBERED_APPROVALS {
            self.approvals
                .sort_by_key(|kept| std::cmp::Reverse(kept.approved_at));
            self.approvals.truncate(MAX_REMEMBERED_APPROVALS);
        }
    }

    /// Drop the approvals given before `not_before`.
    pub fn forget_before(&mut self, not_before: u64) {
        self.approvals.retain(|kept| kept.approved_at >= not_before);
    }

    /// Drop the oldest approval; `false` when there was none.
    pub fn forget_oldest(&mut self) -> bool {
        let Some(oldest) = self
            .approvals
            .iter()
            .enumerate()
            .min_by_key(|(_, kept)| kept.approved_at)
            .map(|(index, _)| index)
        else {
            return false;
        };
        self.approvals.remove(oldest);
        true
    }

    /// Whether an approval since `not_before` covers this client, exact
    /// redirect URI, exact resource and every scope of `scopes`.
    pub fn covers(
        &self,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        scopes: &[String],
        not_before: u64,
    ) -> bool {
        self.approvals.iter().any(|kept| {
            kept.client_id == client_id
                && kept.redirect_uri == redirect_uri
                && kept.resource == resource
                && kept.approved_at >= not_before
                && scopes.iter().all(|scope| kept.scopes.contains(scope))
        })
    }
}

/// A dynamically registered client (`dcr/<client_id>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcrClientRecord {
    pub client_id: String,
    pub client_id_issued_at: u64,
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub application_type: Option<String>,
    /// RFC 9449 §5.2: every token request of the client carries a DPoP
    /// proof.
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
}

/// A link to an IdP sign-in offered to one user (`link/h(id)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRecord {
    /// The principal who may complete it.
    pub principal: String,
    /// The MCP client the user called from, when its token names one.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The MCP session the link was offered on.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Whether that session is told when the link completes
    /// (`notifications/elicitation/complete`).
    #[serde(default)]
    pub notify: bool,
    /// Until when the link may be completed, in Unix seconds.
    pub exp: u64,
}

/// The link a principal was offered on one MCP session, offered again
/// while it is pending.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRefRecord {
    pub link: String,
}

impl std::fmt::Debug for LinkRefRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkRefRecord").finish_non_exhaustive()
    }
}

impl StateRecord for Marker {}
impl StateRecord for TransactionRecord {}
impl StateRecord for CodeRecord {}
impl StateRecord for CodeUsedRecord {}
impl StateRecord for GrantRecord {}
impl StateRecord for PrincipalGrantRecord {}
impl StateRecord for RefreshRecord {}
impl StateRecord for RefreshUsedRecord {}
impl StateRecord for TombstoneRecord {}
impl StateRecord for IdpSessionRecord {}
impl StateRecord for LeaseRecord {}
impl StateRecord for ConsentMemoryRecord {}
impl StateRecord for DcrClientRecord {}
impl StateRecord for LinkRecord {}
impl StateRecord for LinkRefRecord {}

// ---------------------------------------------------------------------------
// Revocations
// ---------------------------------------------------------------------------

/// What a revocation names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokedId {
    /// A grant, and every access and refresh token it issued.
    Grant(GrantId),
    /// One access token without a grant, by the hash of its `jti`.
    AccessToken { jti_handle: String },
}

impl RevokedId {
    pub fn access_token(jti: &str) -> Self {
        Self::AccessToken {
            jti_handle: handle(HandleKind::Jti, &[jti.as_bytes()]),
        }
    }

    fn suffix(&self) -> String {
        match self {
            Self::Grant(gid) => gid.to_string(),
            Self::AccessToken { jti_handle } => format!("jti.{jti_handle}"),
        }
    }
}

/// The revocations this process honours, each until its expiry: filled
/// by local revocations and by polling the store for other replicas'.
/// Checked on every request without store I/O.
#[derive(Debug, Default)]
pub struct RevokedSet {
    entries: Mutex<HashMap<String, u64>>,
}

impl RevokedSet {
    /// Whether `id` is revoked now.
    pub fn contains(&self, id: &RevokedId) -> bool {
        self.contains_at(&id.suffix(), now_unix())
    }

    fn contains_at(&self, suffix: &str, now: u64) -> bool {
        self.entries
            .lock()
            .get(suffix)
            .is_some_and(|until| *until > now)
    }

    fn insert(&self, suffix: String, until: u64) {
        let mut entries = self.entries.lock();
        let kept = entries.entry(suffix).or_insert(until);
        *kept = (*kept).max(until);
    }

    fn prune(&self, now: u64) {
        self.entries.lock().retain(|_, until| *until > now);
    }

    /// Revocations held, expired ones not yet pruned included.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// The state handle
// ---------------------------------------------------------------------------

/// Which store holds the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateBackend {
    /// The cluster coordinator's key-value store, shared by every replica.
    Cluster,
    /// This process's memory, handed from server to server on reload.
    InProcess,
    /// A [`FileStore`] in this directory.
    File { dir: PathBuf },
    /// None: a clustered coordinator without a key-value store, booted
    /// degraded. Every operation fails, so sign-in answers 503.
    Unavailable,
}

impl std::fmt::Display for StateBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cluster => f.write_str("the cluster coordinator's key-value store"),
            Self::InProcess => f.write_str("process memory"),
            Self::File { dir } => write!(f, "files under {}", dir.display()),
            Self::Unavailable => f.write_str("unavailable"),
        }
    }
}

/// The key-value store of a degraded cluster: every operation fails.
#[derive(Debug)]
pub struct UnavailableStore {
    reason: String,
}

impl UnavailableStore {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn error(&self) -> ClusterError {
        ClusterError::BackendUnavailable {
            reason: self.reason.clone(),
        }
    }
}

#[async_trait]
impl KeyValueStore for UnavailableStore {
    async fn get(&self, _key: &str) -> Result<Option<Entry>, ClusterError> {
        Err(self.error())
    }

    async fn put(
        &self,
        _key: &str,
        _value: Bytes,
        _ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        Err(self.error())
    }

    async fn put_if_absent(
        &self,
        _key: &str,
        _value: Bytes,
        _ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        Err(self.error())
    }

    async fn delete(&self, _key: &str) -> Result<bool, ClusterError> {
        Err(self.error())
    }

    async fn list_prefix(
        &self,
        _prefix: &str,
        _limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        Err(self.error())
    }

    async fn expire(&self, _key: &str, _ttl: Option<Duration>) -> Result<bool, ClusterError> {
        Err(self.error())
    }

    async fn incr(
        &self,
        _key: &str,
        _delta: i64,
        _ttl: Option<Duration>,
    ) -> Result<i64, ClusterError> {
        Err(self.error())
    }
}

/// A key-value store in this process's memory, swept of expired records.
pub fn memory_store() -> Arc<dyn KeyValueStore> {
    let kv = crate::builtins::cluster_primitives::MemoryKv::new();
    let kv = if tokio::runtime::Handle::try_current().is_ok() {
        kv.with_sweep(MEMORY_SWEEP_INTERVAL)
    } else {
        kv
    };
    Arc::new(kv)
}

/// What an [`InteractiveState`] is built from.
pub struct StateParts {
    pub kv: Arc<dyn KeyValueStore>,
    pub backend: StateBackend,
    pub keyring: Arc<StateKeyring>,
    /// The authorization server's issuer, bound into every seal.
    pub issuer: String,
    pub revoked: Arc<RevokedSet>,
    /// How often the store is read for other replicas' revocations.
    pub revocation_interval: Duration,
}

/// A lease taken with [`InteractiveState::try_lease`].
pub struct Lease {
    key: RecordKey<LeaseRecord>,
    token: String,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// The sealed state of interactive sign-in. Cheap to clone; every clone
/// shares one store, keyring and revoked set.
#[derive(Clone)]
pub struct InteractiveState {
    inner: Arc<StateInner>,
}

struct StateInner {
    kv: Arc<dyn KeyValueStore>,
    backend: StateBackend,
    keyring: Arc<StateKeyring>,
    issuer: String,
    revoked: Arc<RevokedSet>,
    revocation_interval: Duration,
    /// Who holds a lease this process takes.
    holder: String,
}

impl std::fmt::Debug for InteractiveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveState")
            .field("backend", &self.inner.backend)
            .field("keyring", &self.inner.keyring)
            .field("revoked", &self.inner.revoked.len())
            .finish_non_exhaustive()
    }
}

impl InteractiveState {
    /// The state over `parts`. Within a Tokio runtime it reads the store
    /// for revocations now and every `revocation_interval` after, for as
    /// long as a clone of it lives.
    pub fn new(parts: StateParts) -> Result<Self, StateError> {
        let inner = Arc::new(StateInner {
            kv: parts.kv,
            backend: parts.backend,
            keyring: parts.keyring,
            issuer: parts.issuer,
            revoked: parts.revoked,
            revocation_interval: parts.revocation_interval.max(Duration::from_secs(1)),
            holder: format!(
                "{}:{}",
                std::process::id(),
                hex::encode(random_bytes::<8>()?)
            ),
        });
        spawn_revocation_poll(&inner);
        Ok(Self { inner })
    }

    /// State in this process's memory under a key generated for the
    /// process: what a single test server or a memory store uses.
    pub fn in_memory(issuer: &str) -> anyhow::Result<Self> {
        Ok(Self::new(StateParts {
            kv: memory_store(),
            backend: StateBackend::InProcess,
            keyring: Arc::new(StateKeyring::process()?),
            issuer: issuer.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(10),
        })?)
    }

    pub fn backend(&self) -> &StateBackend {
        &self.inner.backend
    }

    /// Whether the state has a store; see [`StateBackend::Unavailable`].
    pub fn is_available(&self) -> bool {
        self.inner.backend != StateBackend::Unavailable
    }

    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    pub fn keyring(&self) -> &Arc<StateKeyring> {
        &self.inner.keyring
    }

    /// The key-value store the records live in.
    pub fn store(&self) -> &Arc<dyn KeyValueStore> {
        &self.inner.kv
    }

    pub fn revoked(&self) -> &Arc<RevokedSet> {
        &self.inner.revoked
    }

    pub fn revocation_interval(&self) -> Duration {
        self.inner.revocation_interval
    }

    /// Whether both states keep their records in one store.
    pub fn shares_store_with(&self, other: &InteractiveState) -> bool {
        Arc::ptr_eq(&self.inner.kv, &other.inner.kv)
    }

    fn aad(&self, logical: &str) -> Vec<u8> {
        let mut aad =
            Vec::with_capacity(AAD_LABEL.len() + logical.len() + self.inner.issuer.len() + 2);
        aad.extend_from_slice(AAD_LABEL.as_bytes());
        aad.push(0);
        aad.extend_from_slice(logical.as_bytes());
        aad.push(0);
        aad.extend_from_slice(self.inner.issuer.as_bytes());
        aad
    }

    /// `record` sealed for `logical`.
    pub fn seal_record<R: StateRecord>(
        &self,
        logical: &str,
        record: &R,
    ) -> Result<Bytes, StateError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(record).map_err(|_| {
            count_error("seal");
            StateError::Seal
        })?);
        if plaintext.len() > MAX_RECORD_BYTES {
            count_error("seal");
            return Err(StateError::TooLarge {
                bytes: plaintext.len(),
            });
        }
        self.inner
            .keyring
            .seal(&plaintext, &self.aad(logical))
            .map(Bytes::from)
    }

    /// The record sealed for `logical`; `None`, counted, when it does not
    /// open or decode.
    pub fn open_record<R: StateRecord>(&self, logical: &str, sealed: &[u8]) -> Option<R> {
        let record = self
            .inner
            .keyring
            .open(sealed, &self.aad(logical))
            .map(Zeroizing::new)
            .and_then(|plaintext| serde_json::from_slice(&plaintext).ok());
        if record.is_none() {
            count_error("open");
            tracing::warn!(
                record = logical.split('/').next().unwrap_or_default(),
                "a sign-in record did not open under the state keys; treating it as absent"
            );
        }
        record
    }

    /// `value` sealed for a browser to hold, in URL-safe base64. `label`
    /// names what it is and holds no `/`, so it opens neither as another
    /// kind of value nor as a stored record, whose keys all do.
    pub fn seal_value<R: StateRecord>(&self, label: &str, value: &R) -> Result<String, StateError> {
        use base64::Engine as _;
        debug_assert!(!label.contains('/'), "a value label holds no `/`");
        let sealed = self.seal_record(label, value)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sealed))
    }

    /// The value sealed for `label` in `encoded`; `None` when it does not
    /// decode, open or parse. Not logged: browsers send stale and altered
    /// values as a matter of course.
    pub fn open_value<R: StateRecord>(&self, label: &str, encoded: &str) -> Option<R> {
        use base64::Engine as _;
        let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()?;
        let plaintext = Zeroizing::new(self.inner.keyring.open(&sealed, &self.aad(label))?);
        serde_json::from_slice(&plaintext).ok()
    }

    /// The record under `key`, when present and it opens.
    pub async fn get<R: StateRecord>(&self, key: &RecordKey<R>) -> Result<Option<R>, StateError> {
        let entry = self.inner.kv.get(key.as_str()).await.map_err(store_error)?;
        Ok(entry.and_then(|entry| self.open_record(key.logical(), &entry.bytes)))
    }

    /// Whether anything is stored under `key`, whether or not it opens:
    /// what a claim marker or a revocation needs.
    pub async fn exists<R: StateRecord>(&self, key: &RecordKey<R>) -> Result<bool, StateError> {
        Ok(self
            .inner
            .kv
            .get(key.as_str())
            .await
            .map_err(store_error)?
            .is_some())
    }

    /// Store `record` under `key` for `ttl`.
    pub async fn put<R: StateRecord>(
        &self,
        key: &RecordKey<R>,
        record: &R,
        ttl: Duration,
    ) -> Result<(), StateError> {
        let sealed = self.seal_record(key.logical(), record)?;
        self.inner
            .kv
            .put(key.as_str(), sealed, Some(store_ttl(ttl)))
            .await
            .map_err(store_error)
    }

    /// Store `record` under `key` for `ttl` unless a live record is there;
    /// `true` when this call stored it. One caller wins across replicas.
    pub async fn put_if_absent<R: StateRecord>(
        &self,
        key: &RecordKey<R>,
        record: &R,
        ttl: Duration,
    ) -> Result<bool, StateError> {
        let sealed = self.seal_record(key.logical(), record)?;
        self.inner
            .kv
            .put_if_absent(key.as_str(), sealed, Some(store_ttl(ttl)))
            .await
            .map_err(store_error)
    }

    /// Claim `key` once for `ttl`: `true` for the one caller that claims
    /// it, `false` for every other until it expires or is released with
    /// [`Self::unclaim`].
    pub async fn claim_once(
        &self,
        key: &RecordKey<Marker>,
        ttl: Duration,
    ) -> Result<bool, StateError> {
        self.put_if_absent(key, &Marker::now(), ttl).await
    }

    /// Release a claim, so the next [`Self::claim_once`] or
    /// [`Self::put_if_absent`] of `key` succeeds; `true` when one was
    /// held.
    pub async fn unclaim<R: StateRecord>(&self, key: &RecordKey<R>) -> Result<bool, StateError> {
        self.delete(key).await
    }

    /// Remove the record under `key`; `true` when one was there.
    pub async fn delete<R: StateRecord>(&self, key: &RecordKey<R>) -> Result<bool, StateError> {
        self.inner
            .kv
            .delete(key.as_str())
            .await
            .map_err(store_error)
    }

    /// Keep the record under `key` for `ttl` from now; `false` when none
    /// is there.
    pub async fn touch<R: StateRecord>(
        &self,
        key: &RecordKey<R>,
        ttl: Duration,
    ) -> Result<bool, StateError> {
        self.inner
            .kv
            .expire(key.as_str(), Some(store_ttl(ttl)))
            .await
            .map_err(store_error)
    }

    /// Up to `limit` records under `prefix` that open, each with its key
    /// after the prefix, in no particular order.
    pub async fn list<R: StateRecord>(
        &self,
        prefix: &RecordPrefix<R>,
        limit: usize,
    ) -> Result<Vec<(String, R)>, StateError> {
        let listed = self
            .inner
            .kv
            .list_prefix(prefix.as_str(), limit)
            .await
            .map_err(store_error)?;
        Ok(listed
            .into_iter()
            .filter_map(|(key, entry)| {
                let rest = key.strip_prefix(prefix.as_str())?.to_owned();
                let logical = key.strip_prefix(STATE_PREFIX)?;
                let record = self.open_record(logical, &entry.bytes)?;
                Some((rest, record))
            })
            .collect())
    }

    /// How many live records are stored under `prefix`, counting at most
    /// `limit`, whether or not they open. Nothing is opened.
    pub async fn count<R: StateRecord>(
        &self,
        prefix: &RecordPrefix<R>,
        limit: usize,
    ) -> Result<usize, StateError> {
        Ok(self
            .inner
            .kv
            .list_prefix(prefix.as_str(), limit)
            .await
            .map_err(store_error)?
            .len())
    }

    /// Add `delta` to the counter under `key` and return the sum; a `ttl`
    /// restarts the counter's lifetime.
    pub async fn incr(
        &self,
        key: &CounterKey,
        delta: i64,
        ttl: Option<Duration>,
    ) -> Result<i64, StateError> {
        self.inner
            .kv
            .incr(key.as_str(), delta, ttl.map(store_ttl))
            .await
            .map_err(store_error)
    }

    /// Take the lease under `key` for `ttl`, when no one holds it.
    pub async fn try_lease(
        &self,
        key: &RecordKey<LeaseRecord>,
        ttl: Duration,
    ) -> Result<Option<Lease>, StateError> {
        let token = random_token()?;
        let record = LeaseRecord {
            holder: self.inner.holder.clone(),
            token: token.clone(),
        };
        Ok(self.put_if_absent(key, &record, ttl).await?.then(|| Lease {
            key: key.clone(),
            token,
        }))
    }

    /// Take the lease under `key` for `ttl`, waiting up to `wait` for its
    /// holder to release it; `None` when it stays taken. A lease orders
    /// work, it does not guard correctness: whoever goes on without it
    /// re-reads what the holder may have changed.
    pub async fn acquire_lease(
        &self,
        key: &RecordKey<LeaseRecord>,
        ttl: Duration,
        wait: Duration,
    ) -> Result<Option<Lease>, StateError> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(lease) = self.try_lease(key, ttl).await? {
                return Ok(Some(lease));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            tokio::time::sleep(remaining.min(LEASE_RETRY_INTERVAL)).await;
        }
    }

    /// Release `lease`, unless it expired and someone else took it.
    pub async fn release_lease(&self, lease: &Lease) -> Result<(), StateError> {
        let held = self.get(&lease.key).await?;
        if held.is_some_and(|record| {
            record.token.len() == lease.token.len()
                && bool::from(record.token.as_bytes().ct_eq(lease.token.as_bytes()))
        }) {
            self.delete(&lease.key).await?;
        }
        Ok(())
    }

    /// Revoke `id` until `until` (Unix seconds): honoured here at once and
    /// by other replicas from their next poll. Honoured here even when
    /// the store write fails, which is then reported.
    pub async fn record_revocation(
        &self,
        id: &RevokedId,
        reason: RevocationReason,
        until: u64,
    ) -> Result<(), StateError> {
        self.inner.revoked.insert(id.suffix(), until);
        let ttl = Duration::from_secs(until.saturating_sub(now_unix()));
        self.put(
            &keys::revoked(id),
            &TombstoneRecord { reason, exp: until },
            ttl,
        )
        .await
    }

    /// Whether `id` is revoked, from the revocations this process holds.
    pub fn is_revoked(&self, id: &RevokedId) -> bool {
        self.inner.revoked.contains(id)
    }

    /// Read every revocation in the store into the revoked set and drop
    /// the expired ones; the number of live revocations read. A failure
    /// keeps the set as it was.
    pub async fn poll_revocations(&self) -> Result<usize, StateError> {
        self.poll_revocations_by(REVOCATION_LIST_LIMIT).await
    }

    /// [`Self::poll_revocations`], listing at most `limit` records at a time.
    async fn poll_revocations_by(&self, limit: usize) -> Result<usize, StateError> {
        let prefix = keys::revocations();
        let listed = match self.list_revocations(prefix.as_str(), limit).await {
            Ok(listed) => listed,
            Err(error) => {
                metrics::counter!("mcpg_as_revocation_poll_total", "outcome" => "error")
                    .increment(1);
                tracing::warn!(
                    error = %error,
                    "reading the revoked sign-in grants failed; the known revocations stay in force"
                );
                return Err(store_error(error));
            }
        };
        let now = now_unix();
        let mut live = 0;
        for (key, entry) in listed {
            let Some(suffix) = key.strip_prefix(prefix.as_str()) else {
                continue;
            };
            let until = entry
                .expires_at
                .and_then(unix_secs)
                .or_else(|| {
                    let logical = key.strip_prefix(STATE_PREFIX)?;
                    self.open_record::<TombstoneRecord>(logical, &entry.bytes)
                        .map(|tombstone| tombstone.exp)
                })
                .unwrap_or(now + TOMBSTONE_FALLBACK_SECS);
            if until > now {
                self.inner.revoked.insert(suffix.to_owned(), until);
                live += 1;
            }
        }
        self.inner.revoked.prune(now);
        metrics::counter!("mcpg_as_revocation_poll_total", "outcome" => "ok").increment(1);
        Ok(live)
    }

    /// Every record under `top`, `limit` at a time. A listing the store
    /// cuts at `limit` is read again as the listings one character longer
    /// that together hold it, so no revocation goes unread; one that cannot
    /// be split further is an error.
    async fn list_revocations(
        &self,
        top: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let mut listed = Vec::new();
        let mut pending = vec![top.to_owned()];
        while let Some(prefix) = pending.pop() {
            let page = self.inner.kv.list_prefix(&prefix, limit).await?;
            if page.len() < limit {
                listed.extend(page);
                continue;
            }
            match revocation_sub_prefixes(top, &prefix) {
                Some(longer) => pending.extend(longer),
                None => {
                    return Err(ClusterError::BackendUnavailable {
                        reason: format!(
                            "the store returns at most {limit} revoked sign-in grants for one key"
                        ),
                    });
                }
            }
        }
        Ok(listed)
    }
}

/// The prefixes one character longer than `prefix` whose listings together
/// hold every revocation under it: a revocation's key is `top` and a grant
/// id (lowercase hex) or `jti.` and a hex hash. `None` once `prefix` is as
/// long as the longest revocation key.
fn revocation_sub_prefixes(top: &str, prefix: &str) -> Option<Vec<String>> {
    const JTI: &str = "jti.";
    const LONGEST_SUFFIX: usize = JTI.len() + 64;
    if prefix.len() >= top.len() + LONGEST_SUFFIX {
        return None;
    }
    let mut longer: Vec<String> = "0123456789abcdef"
        .chars()
        .map(|digit| format!("{prefix}{digit}"))
        .collect();
    if prefix == top {
        longer.push(format!("{top}{JTI}"));
    }
    Some(longer)
}

/// Poll the store for revocations while `inner` lives.
fn spawn_revocation_poll(inner: &Arc<StateInner>) {
    if inner.backend == StateBackend::Unavailable {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let state: Weak<StateInner> = Arc::downgrade(inner);
    runtime.spawn(async move {
        loop {
            let Some(inner) = state.upgrade() else {
                break;
            };
            let interval = inner.revocation_interval;
            let _ = InteractiveState { inner }.poll_revocations().await;
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
#[path = "authorization_server_state_tests.rs"]
mod tests;
