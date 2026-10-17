//! The keys of the events core, every one derived from one base key.
//!
//! Subscription ids, sealed `whsec_` secrets, cursors and the hashed parts of
//! store key names must come out the same on every replica and after a
//! restart, so they derive from a base key every replica holds: the cluster
//! state key, else `mcp.configurations.sessions.synthetic_session_key`. Each
//! use takes its own sub-key, so no two uses can be confused. Without a
//! shared base, a process key stands in; it is only good while nothing has to
//! outlive the process.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead as _, Generate as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mcpg_mcp_wire::shared::canonical::canonical_value_bytes;
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::WebhookSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::cursor::CursorCodec;

/// Domain of the source-key sub-key.
pub const SOURCE_KEY_DOMAIN: &[u8] = b"mcpg:events:source-key:v1";
/// Domain of the subscription-id sub-key.
pub const SUBSCRIPTION_ID_DOMAIN: &[u8] = b"mcpg:events:subscription-id:v1";
/// Domain of the sub-key that hashes values into store key names.
pub const KEY_HASH_DOMAIN: &[u8] = b"mcpg:events:key-hash:v1";
/// Domain of the sub-key that seals `whsec_` secrets.
pub const WHSEC_SEAL_DOMAIN: &[u8] = b"mcpg:events:whsec:v1";
/// Domain of the sub-key the secrets of upstream webhook subscriptions
/// derive from.
pub const UPSTREAM_WHSEC_DOMAIN: &[u8] = b"mcpg:events:upstream-whsec:v1";

/// Prefix of the id of an upstream subscription of an imported type.
pub const UPSTREAM_SUBSCRIPTION_ID_PREFIX: &str = "fsub_";

/// Key id of a key that lives as long as the process.
pub const PROCESS_KID: &str = "process";
/// Key id of a base taken from `sessions.synthetic_session_key`.
pub const SYNTHETIC_SESSION_KID: &str = "synthetic-session";
/// Key id of a base taken from the cluster state key when
/// `cluster.state_encryption_key_id` is unset.
pub const CLUSTER_KID: &str = "cluster";

/// Prefix of every subscription id.
pub const SUBSCRIPTION_ID_PREFIX: &str = "sub_";
/// Hex characters of a subscription id after its prefix (128 bits).
const SUBSCRIPTION_ID_HEX: usize = 32;
/// Hex characters of a hashed key-name part (128 bits).
const KEY_HASH_HEX: usize = 32;

const WHSEC_AAD_LABEL: &[u8] = b"mcpg:events:whsec:v1\0";
const NONCE_BYTES: usize = 24;

/// Where the base key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `cluster.state_encryption_key_env`.
    ClusterStateKey,
    /// `mcp.configurations.sessions.synthetic_session_key`.
    SyntheticSessionKey,
    /// Random, for the life of this process.
    Process,
}

/// A secret sealed for one subscription.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    /// Id of the key that sealed it.
    pub kid: String,
    /// Unpadded base64url of the nonce followed by the sealed value.
    pub sealed: String,
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Every key of the events core.
pub struct EventsKeys {
    source: KeySource,
    kid: String,
    fingerprint: [u8; 32],
    source_key: Zeroizing<[u8; 32]>,
    subscription_id: Zeroizing<[u8; 32]>,
    key_hash: Zeroizing<[u8; 32]>,
    whsec: XChaCha20Poly1305,
    upstream_whsec: Zeroizing<[u8; 32]>,
    cursor: CursorCodec,
}

impl fmt::Debug for EventsKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventsKeys")
            .field("source", &self.source)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl EventsKeys {
    /// The keys derived from `base`, sealing under key id `kid`.
    pub fn from_base(base: &[u8; 32], source: KeySource, kid: impl Into<String>) -> Self {
        let derive =
            |domain: &[u8]| Zeroizing::new(crate::app::derive_cluster_subkey(base, domain));
        let whsec_key = derive(WHSEC_SEAL_DOMAIN);
        let fingerprint = hmac_sha256::HMAC::mac(b"mcpg:events:keys-fingerprint:v1", base);
        Self {
            source,
            kid: kid.into(),
            fingerprint,
            source_key: derive(SOURCE_KEY_DOMAIN),
            subscription_id: derive(SUBSCRIPTION_ID_DOMAIN),
            key_hash: derive(KEY_HASH_DOMAIN),
            whsec: XChaCha20Poly1305::new_from_slice(whsec_key.as_slice())
                .expect("XChaCha20-Poly1305 takes a 32-byte key"),
            upstream_whsec: derive(UPSTREAM_WHSEC_DOMAIN),
            cursor: CursorCodec::from_state_key(base),
        }
    }

    /// Keys from a random base that dies with the process.
    pub fn process() -> Self {
        let base = Zeroizing::new(<[u8; 32]>::generate());
        Self::from_base(&base, KeySource::Process, PROCESS_KID)
    }

    /// The keys `config` names: the cluster state key, else the synthetic
    /// session key, else `None`. Errors only when a named key cannot be
    /// read.
    pub fn from_config(config: &crate::config::AppConfig) -> anyhow::Result<Option<Self>> {
        if let Some(base) = crate::app::cluster_state_key_bytes(&config.cluster)? {
            let base = Zeroizing::new(base);
            let kid = config
                .cluster
                .state_encryption_key_id
                .clone()
                .unwrap_or_else(|| CLUSTER_KID.to_owned());
            return Ok(Some(Self::from_base(
                &base,
                KeySource::ClusterStateKey,
                kid,
            )));
        }
        let synthetic = config
            .mcp
            .configurations
            .sessions
            .synthetic_session_key
            .as_deref()
            .and_then(crate::config::events::decode_synthetic_session_key);
        Ok(synthetic.map(|base| {
            let base = Zeroizing::new(base);
            Self::from_base(&base, KeySource::SyntheticSessionKey, SYNTHETIC_SESSION_KID)
        }))
    }

    /// Where the base came from.
    pub fn source(&self) -> KeySource {
        self.source
    }

    /// Whether every replica, and this process after a restart, derives
    /// the same keys.
    pub fn is_stable(&self) -> bool {
        self.source != KeySource::Process
    }

    /// Id of the key that seals secrets.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// A value that differs between two key sets with different bases,
    /// and reveals nothing about either.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// The cursor codec.
    pub fn cursor(&self) -> &CursorCodec {
        &self.cursor
    }

    /// The source key of event type `name` read under `scope`: the log
    /// and cursors of that pair are bound to it. Holds no cleartext part
    /// of either, because store key names stay readable under encryption.
    pub fn source_key(&self, name: &str, scope: &SourceScope) -> String {
        let input = serde_json::json!(["v1", name, scope.as_str()]);
        let mac = hmac_sha256::HMAC::mac(canonical_value_bytes(&input), self.source_key.as_slice());
        format!("sk{}", &hex::encode(mac)[..KEY_HASH_HEX])
    }

    /// The id of the subscription with this key: a routing handle that is
    /// the same on every replica and that nobody without the key can
    /// compute. `url` is the normalized callback URL; `arguments` compare
    /// by canonical JSON, so key order and number spelling do not matter.
    pub fn subscription_id(
        &self,
        principal: &str,
        url: &str,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> String {
        let input = Value::Array(vec![
            Value::String(principal.to_owned()),
            Value::String(url.to_owned()),
            Value::String(name.to_owned()),
            Value::Object(arguments.clone()),
        ]);
        let mac = hmac_sha256::HMAC::mac(
            canonical_value_bytes(&input),
            self.subscription_id.as_slice(),
        );
        format!(
            "{SUBSCRIPTION_ID_PREFIX}{}",
            &hex::encode(mac)[..SUBSCRIPTION_ID_HEX]
        )
    }

    /// `value` hashed for use inside a store key name, separated by
    /// `domain` from every other hashed value.
    pub fn key_hash(&self, domain: &str, value: &[u8]) -> String {
        let mut input = Vec::with_capacity(domain.len() + 1 + value.len());
        input.extend_from_slice(domain.as_bytes());
        input.push(0);
        input.extend_from_slice(value);
        let mac = hmac_sha256::HMAC::mac(&input, self.key_hash.as_slice());
        hex::encode(mac)[..KEY_HASH_HEX].to_owned()
    }

    /// Subscription `arguments` hashed by their canonical JSON, so two
    /// spellings of the same arguments hash alike.
    pub fn arguments_hash(&self, arguments: &Map<String, Value>) -> String {
        self.key_hash(
            "event-arguments",
            &canonical_value_bytes(&Value::Object(arguments.clone())),
        )
    }

    /// The id of the upstream subscription of `federation` to its type
    /// `upstream_name`, for the readers of the principal `audience` (a
    /// keyed hash, or every principal) and the arguments `arguments` (a
    /// keyed hash): the same on every replica, and the last segment of
    /// the callback an upstream delivers it to.
    pub fn upstream_subscription_id(
        &self,
        federation: &str,
        upstream_name: &str,
        audience: Option<&str>,
        arguments: &str,
    ) -> String {
        let input = serde_json::json!(["v1", federation, upstream_name, audience, arguments]);
        format!(
            "{UPSTREAM_SUBSCRIPTION_ID_PREFIX}{}",
            self.key_hash("upstream-subscription", &canonical_value_bytes(&input))
        )
    }

    /// The `whsec_` secret the upstream signs the deliveries of upstream
    /// subscription `id` with: every replica derives it, nothing stores it.
    pub fn upstream_webhook_secret(&self, id: &str) -> WebhookSecret {
        use base64::engine::general_purpose::STANDARD;
        let mac = Zeroizing::new(hmac_sha256::HMAC::mac(
            id.as_bytes(),
            self.upstream_whsec.as_slice(),
        ));
        let text = Zeroizing::new(format!("whsec_{}", STANDARD.encode(mac.as_slice())));
        WebhookSecret::parse(&text).expect("32 random bytes make a valid secret")
    }

    /// Seal `secret` for subscription `id`. The sealed value opens only
    /// for that id, under this key.
    pub fn seal_secret(&self, id: &str, secret: &WebhookSecret) -> SealedSecret {
        let nonce = XNonce::generate();
        let aad = whsec_aad(id, &self.kid);
        let sealed = self
            .whsec
            .encrypt(
                &nonce,
                Payload {
                    msg: secret.expose_secret().as_bytes(),
                    aad: &aad,
                },
            )
            .expect("sealing a bounded secret cannot fail");
        let mut raw = Vec::with_capacity(NONCE_BYTES + sealed.len());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&sealed);
        SealedSecret {
            kid: self.kid.clone(),
            sealed: URL_SAFE_NO_PAD.encode(raw),
        }
    }

    /// The secret sealed for subscription `id`, or `None` when it was
    /// sealed under another key, for another id, or altered.
    pub fn open_secret(&self, id: &str, sealed: &SealedSecret) -> Option<WebhookSecret> {
        if sealed.kid != self.kid {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(&sealed.sealed).ok()?;
        if raw.len() <= NONCE_BYTES {
            return None;
        }
        let (nonce, body) = raw.split_at(NONCE_BYTES);
        let nonce = XNonce::try_from(nonce).ok()?;
        let aad = whsec_aad(id, &self.kid);
        let plain = Zeroizing::new(
            self.whsec
                .decrypt(
                    &nonce,
                    Payload {
                        msg: body,
                        aad: &aad,
                    },
                )
                .ok()?,
        );
        let text = std::str::from_utf8(&plain).ok()?;
        WebhookSecret::parse(text).ok()
    }
}

fn whsec_aad(id: &str, kid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WHSEC_AAD_LABEL.len() + 16 + id.len() + kid.len());
    aad.extend_from_slice(WHSEC_AAD_LABEL);
    aad.extend_from_slice(&(id.len() as u64).to_be_bytes());
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&(kid.len() as u64).to_be_bytes());
    aad.extend_from_slice(kid.as_bytes());
    aad
}

/// Whose reading of a source a log holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceScope {
    /// The gateway's own reading, shared by every subscriber.
    Shared,
}

impl SourceScope {
    fn as_str(&self) -> &str {
        match self {
            Self::Shared => "shared",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys() -> EventsKeys {
        EventsKeys::from_base(&[3u8; 32], KeySource::ClusterStateKey, "k1")
    }

    fn secret() -> WebhookSecret {
        WebhookSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap()
    }

    fn args(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn subscription_ids_are_deterministic_prefixed_and_hex() {
        let a = keys().subscription_id("p", "https://h.example/x", "orders", &Map::new());
        let b = keys().subscription_id("p", "https://h.example/x", "orders", &Map::new());
        assert_eq!(a, b);
        assert!(a.starts_with("sub_"));
        assert_eq!(a.len(), 4 + 32);
        assert!(a[4..].bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn subscription_ids_compare_arguments_canonically() {
        let k = keys();
        let a: Value = serde_json::from_str(r#"{"a":1.0,"b":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(
            k.subscription_id("p", "u", "n", &args(a)),
            k.subscription_id("p", "u", "n", &args(b))
        );
    }

    #[test]
    fn every_key_part_changes_the_id() {
        let k = keys();
        let base = k.subscription_id("p", "u", "n", &args(json!({"x": 1})));
        for other in
            [
                k.subscription_id("q", "u", "n", &args(json!({"x": 1}))),
                k.subscription_id("p", "v", "n", &args(json!({"x": 1}))),
                k.subscription_id("p", "u", "m", &args(json!({"x": 1}))),
                k.subscription_id("p", "u", "n", &args(json!({"x": 2}))),
                k.subscription_id("p", "u", "n", &Map::new()),
                EventsKeys::from_base(&[4u8; 32], KeySource::ClusterStateKey, "k1")
                    .subscription_id("p", "u", "n", &args(json!({"x": 1}))),
            ]
        {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn parts_cannot_shift_across_boundaries() {
        let k = keys();
        assert_ne!(
            k.subscription_id("ab", "c", "n", &Map::new()),
            k.subscription_id("a", "bc", "n", &Map::new())
        );
        assert_ne!(k.key_hash("ab", b"c"), k.key_hash("a", b"bc"));
    }

    #[test]
    fn source_keys_are_stable_and_opaque() {
        let k = keys();
        let sk = k.source_key("orders.created", &SourceScope::Shared);
        assert_eq!(
            sk,
            keys().source_key("orders.created", &SourceScope::Shared)
        );
        assert_ne!(sk, k.source_key("orders.updated", &SourceScope::Shared));
        assert!(!sk.contains("orders"));
        assert_eq!(sk.len(), 2 + 32);
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_id_and_key() {
        let k = keys();
        let sealed = k.seal_secret("sub_a", &secret());
        assert_eq!(k.open_secret("sub_a", &sealed), Some(secret()));
        assert_eq!(k.open_secret("sub_b", &sealed), None);
        let other_base = EventsKeys::from_base(&[9u8; 32], KeySource::ClusterStateKey, "k1");
        assert_eq!(other_base.open_secret("sub_a", &sealed), None);
        let other_kid = EventsKeys::from_base(&[3u8; 32], KeySource::ClusterStateKey, "k2");
        assert_eq!(other_kid.open_secret("sub_a", &sealed), None);
    }

    #[test]
    fn a_sealed_secret_hides_the_value_and_refuses_tampering() {
        let k = keys();
        let sealed = k.seal_secret("sub_a", &secret());
        assert!(!sealed.sealed.contains("MfKQ9r8"));
        assert!(!format!("{sealed:?}").contains(&sealed.sealed));
        let serialized = serde_json::to_string(&sealed).unwrap();
        assert!(!serialized.contains("whsec_"));
        let mut raw = URL_SAFE_NO_PAD.decode(&sealed.sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let tampered = SealedSecret {
            kid: sealed.kid.clone(),
            sealed: URL_SAFE_NO_PAD.encode(raw),
        };
        assert_eq!(k.open_secret("sub_a", &tampered), None);
        assert_ne!(k.seal_secret("sub_a", &secret()), sealed, "fresh nonce");
    }

    #[test]
    fn process_keys_differ_per_instance_and_are_not_stable() {
        let a = EventsKeys::process();
        let b = EventsKeys::process();
        assert!(!a.is_stable());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert!(keys().is_stable());
        assert!(!format!("{a:?}").contains("source_key: ["));
    }
}
