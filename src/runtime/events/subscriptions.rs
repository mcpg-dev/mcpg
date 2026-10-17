//! Webhook subscription records, in the `event-subscription` store.
//!
//! A subscription is keyed by (principal, callback URL, event name,
//! arguments); its id is an HMAC over that key ([`EventsKeys::subscription_id`]),
//! a routing handle that is never accepted as input. Keys:
//!
//! - `ev:sub:{id}` — the record: identity snapshot, callback, arguments,
//!   sealed secret (and the previous one during a rotation), grant, start
//!   position, revocation tombstone. Written by subscribe and refresh on
//!   any replica.
//! - `ev:sub:w:{id}` — the delivery state: watermark, in-flight retries,
//!   status counters. Written only by the events owner, so a refresh and a
//!   delivery checkpoint never overwrite each other.
//! - `ev:sub:t:{h(type)}:{shard}:{id}` — the index by event type, in 256
//!   shards.
//! - `ev:sub:p:{h(principal)}:{id}` — the index by principal.
//!
//! Every key's TTL is the grant plus a grace period, so a lapsed record is
//! still readable for a while; delivery stops at the grant's end regardless.
//! The secret is sealed with the subscription id as associated data on top
//! of any store encryption, so it stays sealed on a file store and under
//! `allow_plaintext_state`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use mcpg_cluster_api::{ClusterError, KeyValueStore, PubSub};
use mcpg_mcp_wire::v_2026_07_28::extensions::events::errors::{
    EventsError, FEATURE_INPUT_SCHEMA, ForbiddenReason, NotFoundKind,
};
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::{
    DeliveryErrorCategory, DeliveryMode, TtlRequest, WebhookSecret,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::keys::{EventsKeys, SealedSecret};
use super::log::EndReason;
use crate::config::events::EventsConfig;
use crate::runtime::RequestIdentity;

/// Version of every value this module writes.
pub const FORMAT_VERSION: u32 = 1;
/// Topic of the hint sent after every subscription write.
pub const SUBSCRIPTION_TOPIC: &str = "mcpg.events.subscriptions";
/// Shards of the type index.
pub const TYPE_INDEX_SHARDS: usize = 256;
/// How long a record outlives its grant.
pub const RECORD_GRACE: Duration = Duration::from_secs(3_600);
/// Most index rows one listing reads before it falls back to one listing
/// per shard.
const LIST_LIMIT: usize = 20_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a subscription store operation failed.
#[derive(Debug)]
pub enum StoreError {
    /// The store failed.
    Store(ClusterError),
    /// A value could not be encoded or decoded.
    Codec(String),
    /// A record written by a newer format this build does not read.
    Unreadable,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "event subscription store: {error}"),
            Self::Codec(reason) => write!(f, "event subscription value: {reason}"),
            Self::Unreadable => f.write_str("event subscription record of a newer format"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ClusterError> for StoreError {
    fn from(error: ClusterError) -> Self {
        Self::Store(error)
    }
}

/// Facts about the subscriber's credential beyond the identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSnapshot {
    /// Grant id of a token the embedded authorization server minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// `jti` of that token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Expiry of the access token, Unix milliseconds, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_exp_ms: Option<u64>,
}

/// Where delivery starts for a new record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartPosition {
    /// Log epoch of the position.
    pub epoch: u64,
    /// Deliver the rows after this sequence number.
    pub after_seq: u64,
    /// The client was told events were skipped.
    pub truncated: bool,
}

/// When and why a subscription stopped delivering for good.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub at_ms: u64,
    pub reason: TerminationReason,
}

/// Why a subscription, or a stream, ended for good. Stored and counted by
/// its [`label`](Self::label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    /// The subscriber may no longer have the events.
    Forbidden(ForbiddenReason),
    /// The type's schema changed in a way its subscribers cannot follow.
    SchemaChanged,
    /// The type went away.
    TypeRemoved,
    /// The type no longer offers push.
    PushWithdrawn,
    /// Deliveries to the callback failed for too long.
    Suspended,
    /// The upstream of an imported type ended it.
    Upstream(EndReason),
}

impl TerminationReason {
    const FIXED: [Self; 7] = [
        Self::SchemaChanged,
        Self::TypeRemoved,
        Self::PushWithdrawn,
        Self::Suspended,
        Self::Upstream(EndReason::Forbidden),
        Self::Upstream(EndReason::NotFound),
        Self::Upstream(EndReason::ArgumentsRefused),
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Forbidden(reason) => reason.as_str(),
            Self::SchemaChanged => "schema_changed",
            Self::TypeRemoved => "type_removed",
            Self::PushWithdrawn => "push_withdrawn",
            Self::Suspended => "suspended",
            Self::Upstream(reason) => reason.label(),
        }
    }

    /// The reason whose label is `label`. A label no reason has reads as
    /// an unknown denial.
    pub fn from_label(label: &str) -> Self {
        Self::FIXED
            .into_iter()
            .find(|reason| reason.label() == label)
            .unwrap_or_else(|| {
                Self::Forbidden(
                    serde_json::from_value(Value::String(label.to_owned()))
                        .unwrap_or(ForbiddenReason::Unknown),
                )
            })
    }

    /// Whether a config change ended it, not a judgement on the subscriber.
    pub fn ended_by_config(self) -> bool {
        matches!(self, Self::SchemaChanged | Self::TypeRemoved)
    }

    /// What the subscriber is told. `last_failure` names the endpoint
    /// error a suspension ends with.
    pub fn error(self, last_failure: Option<DeliveryErrorCategory>) -> EventsError {
        match self {
            Self::Forbidden(reason) => EventsError::forbidden(reason),
            Self::SchemaChanged => EventsError::schema_changed(FEATURE_INPUT_SCHEMA),
            Self::TypeRemoved => EventsError::not_found(NotFoundKind::Event),
            Self::PushWithdrawn => {
                EventsError::unsupported_delivery_mode(DeliveryMode::Push.as_str())
            }
            Self::Suspended => EventsError::callback_endpoint(
                last_failure
                    .filter(|category| {
                        !matches!(
                            category,
                            DeliveryErrorCategory::Paused | DeliveryErrorCategory::Unknown
                        )
                    })
                    .unwrap_or(DeliveryErrorCategory::ConnectionRefused),
            ),
            Self::Upstream(reason) => reason.error(),
        }
    }
}

impl Serialize for TerminationReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl<'de> Deserialize<'de> for TerminationReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        Ok(Self::from_label(&label))
    }
}

/// A webhook subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub v: u32,
    pub id: String,
    /// The trust-qualified principal key the subscription belongs to.
    pub principal_key: String,
    /// The subscriber's identity when it last subscribed.
    pub identity: RequestIdentity,
    #[serde(default)]
    pub credential: CredentialSnapshot,
    /// The normalized callback URL.
    pub url: String,
    /// The callback host, the unit of per-host limits.
    pub host: String,
    pub name: String,
    pub arguments: Map<String, Value>,
    pub secret: SealedSecret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_secret: Option<SealedSecret>,
    /// Until when the previous secret also signs, Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_secret_until_ms: Option<u64>,
    pub created_at_ms: u64,
    pub refreshed_at_ms: u64,
    /// End of the grant, Unix milliseconds; `None` for a grant with no
    /// expiry. Delivery stops here.
    pub expires_at_ms: Option<u64>,
    /// When the callback endpoint last passed verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at_ms: Option<u64>,
    /// Where delivery starts when no delivery state exists yet.
    pub start: StartPosition,
    /// The schema epoch of the type when the subscription was made.
    #[serde(default)]
    pub schema_epoch: u32,
    /// A refresh asked delivery to resume after a suspension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactivated_at_ms: Option<u64>,
    /// An operator suspended delivery at this time; a later refresh lifts
    /// it, as it lifts a suspension for failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_suspended_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Revocation>,
}

impl SubscriptionRecord {
    /// Whether the grant has ended at `now_ms`.
    pub fn is_lapsed_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_some_and(|end| end <= now_ms)
    }

    /// Whether the record should be delivered to at `now_ms`.
    pub fn is_live_at(&self, now_ms: u64) -> bool {
        !self.is_lapsed_at(now_ms) && self.revoked.is_none()
    }

    /// Whether a config change ended it: its type's schema broke, or the
    /// type went away. Not a judgement on the subscriber.
    pub fn ended_by_config(&self) -> bool {
        self.revoked
            .as_ref()
            .is_some_and(|r| r.reason.ended_by_config())
    }
}

/// One delivery awaiting a retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InFlight {
    pub seq: u64,
    pub attempts: u32,
    pub first_attempt_at_ms: u64,
    pub next_attempt_at_ms: u64,
}

/// Delivery counters of one subscription.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryCounters {
    /// Delivery is suspended since this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_delivery_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<DeliveryErrorCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_since_ms: Option<u64>,
    #[serde(default)]
    pub window_start_ms: u64,
    #[serde(default)]
    pub window_attempts: u64,
    #[serde(default)]
    pub window_failures: u64,
}

/// The owner-written delivery state of one subscription.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryState {
    pub v: u32,
    pub id: String,
    /// Log epoch of the watermark.
    pub epoch: u64,
    /// Every matching sequence number up to here is acknowledged or
    /// abandoned.
    pub ack_seq: u64,
    /// Fence of the owner that wrote this state.
    pub fence: u64,
    #[serde(default)]
    pub in_flight: Vec<InFlight>,
    #[serde(default)]
    pub counters: DeliveryCounters,
    pub updated_at_ms: u64,
}

/// What a create did.
#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    /// A new record; `replaced_lapsed` when it took the place of a record
    /// whose grant had ended.
    Created { replaced_lapsed: bool },
    /// A live record with this id exists.
    Exists(Box<SubscriptionRecord>),
}

/// A row of the type index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeIndexEntry {
    pub v: u32,
    pub id: String,
    pub expires_at_ms: Option<u64>,
}

/// Key prefix of the event type names subscriptions were made to.
const NAME_PREFIX: &str = "ev:sub:n:";

/// One event type name subscriptions were made to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NameEntry {
    v: u32,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrincipalIndexEntry {
    v: u32,
    id: String,
    expires_at_ms: Option<u64>,
    host: String,
}

/// What one principal holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalUsage {
    /// Live subscriptions.
    pub subscriptions: u64,
    /// Hashes of the distinct callback hosts they name.
    pub hosts: BTreeSet<String>,
}

/// A passed callback verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerificationRecord {
    v: u32,
    at_ms: u64,
}

/// Present while an operator has paused every delivery.
const PAUSE_KEY: &str = "ev:ctl:paused";

/// A change to a subscription, broadcast to every replica as a hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionHint {
    pub op: HintOp,
    pub id: String,
    pub name: String,
    pub expires_at_ms: Option<u64>,
}

/// The kind of change a hint reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintOp {
    Upsert,
    Delete,
    /// A poll or stream lease of the type runs until `expires_at_ms`; `id`
    /// is empty.
    Lease,
}

fn encode<T: Serialize>(value: &T) -> Result<Bytes, StoreError> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|e| StoreError::Codec(e.to_string()))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    #[derive(Deserialize)]
    struct Version {
        v: u32,
    }
    let version: Version =
        serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))?;
    if version.v > FORMAT_VERSION {
        return Err(StoreError::Unreadable);
    }
    serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))
}

/// TTL of every key of a subscription whose grant ends at `expires_at_ms`.
fn key_ttl(expires_at_ms: Option<u64>, now: u64) -> Option<Duration> {
    expires_at_ms.map(|end| {
        Duration::from_millis(end.saturating_sub(now))
            .saturating_add(RECORD_GRACE)
            .max(Duration::from_secs(1))
    })
}

/// The webhook subscription store.
pub struct SubscriptionStore {
    kv: Arc<dyn KeyValueStore>,
    bus: Option<Arc<dyn PubSub>>,
    keys: Arc<EventsKeys>,
}

impl std::fmt::Debug for SubscriptionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionStore").finish_non_exhaustive()
    }
}

impl SubscriptionStore {
    pub fn new(
        kv: Arc<dyn KeyValueStore>,
        bus: Option<Arc<dyn PubSub>>,
        keys: Arc<EventsKeys>,
    ) -> Self {
        Self { kv, bus, keys }
    }

    /// The keys ids derive from and secrets seal under.
    pub fn keys(&self) -> &Arc<EventsKeys> {
        &self.keys
    }

    /// The id of the subscription with this key.
    pub fn id_for(
        &self,
        principal_key: &str,
        url: &str,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> String {
        self.keys
            .subscription_id(principal_key, url, name, arguments)
    }

    /// Seal `secret` for subscription `id`.
    pub fn seal_secret(&self, id: &str, secret: &WebhookSecret) -> SealedSecret {
        self.keys.seal_secret(id, secret)
    }

    /// The secret sealed for `id`; `None` when it was sealed under another
    /// key and the subscription needs a refresh.
    pub fn open_secret(&self, id: &str, sealed: &SealedSecret) -> Option<WebhookSecret> {
        self.keys.open_secret(id, sealed)
    }

    fn record_key(id: &str) -> String {
        format!("ev:sub:{id}")
    }

    fn delivery_key(id: &str) -> String {
        format!("ev:sub:w:{id}")
    }

    fn type_prefix(&self, name: &str) -> String {
        format!(
            "ev:sub:t:{}:",
            self.keys.key_hash("event-type", name.as_bytes())
        )
    }

    fn type_key(&self, name: &str, id: &str) -> String {
        format!("{}{}:{id}", self.type_prefix(name), shard_of(id))
    }

    fn principal_prefix(&self, principal_key: &str) -> String {
        format!(
            "ev:sub:p:{}:",
            self.keys.key_hash("principal", principal_key.as_bytes())
        )
    }

    /// The record `id`, whether or not its grant has ended.
    pub async fn get(&self, id: &str) -> Result<Option<SubscriptionRecord>, StoreError> {
        match self.kv.get(&Self::record_key(id)).await? {
            None => Ok(None),
            Some(entry) => decode(&entry.bytes).map(Some),
        }
    }

    /// Create `record` unless a live record with its id exists. A record
    /// whose grant has ended is replaced.
    pub async fn create(&self, record: &SubscriptionRecord) -> Result<CreateOutcome, StoreError> {
        let now = now_ms();
        let ttl = key_ttl(record.expires_at_ms, now);
        let key = Self::record_key(&record.id);
        if self.kv.put_if_absent(&key, encode(record)?, ttl).await? {
            self.write_indexes(record, ttl).await?;
            self.hint(HintOp::Upsert, record).await;
            return Ok(CreateOutcome::Created {
                replaced_lapsed: false,
            });
        }
        let existing = self.get(&record.id).await?;
        match existing {
            Some(existing) if existing.is_lapsed_at(now) => {
                self.kv.delete(&Self::delivery_key(&record.id)).await?;
                self.replace(record).await?;
                Ok(CreateOutcome::Created {
                    replaced_lapsed: true,
                })
            }
            Some(existing) => Ok(CreateOutcome::Exists(Box::new(existing))),
            // Expired between the two reads.
            None => {
                self.replace(record).await?;
                Ok(CreateOutcome::Created {
                    replaced_lapsed: true,
                })
            }
        }
    }

    /// Write `record` over whatever is stored under its id, and slide the
    /// TTL of its delivery state with it.
    pub async fn replace(&self, record: &SubscriptionRecord) -> Result<(), StoreError> {
        let ttl = key_ttl(record.expires_at_ms, now_ms());
        self.kv
            .put(&Self::record_key(&record.id), encode(record)?, ttl)
            .await?;
        self.kv.expire(&Self::delivery_key(&record.id), ttl).await?;
        self.write_indexes(record, ttl).await?;
        self.hint(HintOp::Upsert, record).await;
        Ok(())
    }

    fn name_key(&self, name: &str) -> String {
        format!(
            "{NAME_PREFIX}{}",
            self.keys.key_hash("event-type", name.as_bytes())
        )
    }

    /// Every event type name a subscription was made to and that is not
    /// forgotten yet: how the owner finds the subscriptions of a type the
    /// config no longer declares.
    pub async fn type_names(&self) -> Result<Vec<String>, StoreError> {
        Ok(self
            .kv
            .list_prefix(NAME_PREFIX, LIST_LIMIT)
            .await?
            .into_iter()
            .filter_map(|(_, entry)| decode::<NameEntry>(&entry.bytes).ok())
            .map(|entry| entry.name)
            .collect())
    }

    /// Forget type `name`: it has no subscriptions left.
    pub async fn forget_type_name(&self, name: &str) -> Result<(), StoreError> {
        self.kv.delete(&self.name_key(name)).await?;
        Ok(())
    }

    async fn write_indexes(
        &self,
        record: &SubscriptionRecord,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        let name_entry = NameEntry {
            v: FORMAT_VERSION,
            name: record.name.clone(),
        };
        self.kv
            .put(&self.name_key(&record.name), encode(&name_entry)?, None)
            .await?;
        let type_entry = TypeIndexEntry {
            v: FORMAT_VERSION,
            id: record.id.clone(),
            expires_at_ms: record.expires_at_ms,
        };
        self.kv
            .put(
                &self.type_key(&record.name, &record.id),
                encode(&type_entry)?,
                ttl,
            )
            .await?;
        let principal_entry = PrincipalIndexEntry {
            v: FORMAT_VERSION,
            id: record.id.clone(),
            expires_at_ms: record.expires_at_ms,
            host: self.keys.key_hash("callback-host", record.host.as_bytes()),
        };
        self.kv
            .put(
                &format!(
                    "{}{}",
                    self.principal_prefix(&record.principal_key),
                    record.id
                ),
                encode(&principal_entry)?,
                ttl,
            )
            .await?;
        Ok(())
    }

    /// Delete the subscription `id` with its delivery state and index rows.
    /// Returns the record it held.
    pub async fn delete(&self, id: &str) -> Result<Option<SubscriptionRecord>, StoreError> {
        let record = match self.get(id).await {
            Ok(record) => record,
            Err(StoreError::Unreadable) => None,
            Err(other) => return Err(other),
        };
        self.kv.delete(&Self::record_key(id)).await?;
        self.kv.delete(&Self::delivery_key(id)).await?;
        if let Some(record) = &record {
            self.kv.delete(&self.type_key(&record.name, id)).await?;
            self.kv
                .delete(&format!(
                    "{}{id}",
                    self.principal_prefix(&record.principal_key)
                ))
                .await?;
            self.hint(HintOp::Delete, record).await;
        }
        Ok(record)
    }

    /// The delivery state of `id`.
    pub async fn delivery(&self, id: &str) -> Result<Option<DeliveryState>, StoreError> {
        match self.kv.get(&Self::delivery_key(id)).await? {
            None => Ok(None),
            Some(entry) => decode(&entry.bytes).map(Some),
        }
    }

    /// Write the delivery state of a subscription whose grant ends at
    /// `expires_at_ms`. Only the events owner calls this.
    pub async fn put_delivery(
        &self,
        state: &DeliveryState,
        expires_at_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        let ttl = key_ttl(expires_at_ms, now_ms());
        self.kv
            .put(&Self::delivery_key(&state.id), encode(state)?, ttl)
            .await?;
        Ok(())
    }

    /// The live subscriptions of `principal_key` and the hosts they name.
    pub async fn principal_usage(&self, principal_key: &str) -> Result<PrincipalUsage, StoreError> {
        let now = now_ms();
        let rows = self
            .kv
            .list_prefix(&self.principal_prefix(principal_key), LIST_LIMIT)
            .await?;
        let mut usage = PrincipalUsage::default();
        for (_, entry) in rows {
            let Ok(row) = decode::<PrincipalIndexEntry>(&entry.bytes) else {
                continue;
            };
            if row.expires_at_ms.is_some_and(|end| end <= now) {
                continue;
            }
            usage.subscriptions += 1;
            usage.hosts.insert(row.host);
        }
        Ok(usage)
    }

    /// Every index row of event type `name`, lapsed ones included.
    pub async fn list_type(&self, name: &str) -> Result<Vec<TypeIndexEntry>, StoreError> {
        let prefix = self.type_prefix(name);
        let rows = self.kv.list_prefix(&prefix, LIST_LIMIT).await?;
        let rows = if rows.len() < LIST_LIMIT {
            rows
        } else {
            let mut all = Vec::new();
            for shard in 0..TYPE_INDEX_SHARDS {
                all.extend(
                    self.kv
                        .list_prefix(&format!("{prefix}{shard:02x}:"), LIST_LIMIT)
                        .await?,
                );
            }
            all
        };
        Ok(rows
            .into_iter()
            .filter_map(|(_, entry)| decode::<TypeIndexEntry>(&entry.bytes).ok())
            .collect())
    }

    fn verification_key(&self, principal_key: &str, url: &str) -> String {
        let mut input = Vec::with_capacity(principal_key.len() + 1 + url.len());
        input.extend_from_slice(principal_key.as_bytes());
        input.push(0);
        input.extend_from_slice(url.as_bytes());
        format!(
            "ev:vfy:{}",
            self.keys.key_hash("callback-verification", &input)
        )
    }

    /// When `principal_key` last passed verification of callback `url`,
    /// while that is still reusable.
    pub async fn verified_at(
        &self,
        principal_key: &str,
        url: &str,
    ) -> Result<Option<u64>, StoreError> {
        match self
            .kv
            .get(&self.verification_key(principal_key, url))
            .await?
        {
            None => Ok(None),
            Some(entry) => Ok(decode::<VerificationRecord>(&entry.bytes)
                .ok()
                .map(|r| r.at_ms)),
        }
    }

    /// Remember for `ttl` that `principal_key` passed verification of
    /// callback `url` at `at_ms`.
    pub async fn remember_verification(
        &self,
        principal_key: &str,
        url: &str,
        at_ms: u64,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let record = VerificationRecord {
            v: FORMAT_VERSION,
            at_ms,
        };
        self.kv
            .put(
                &self.verification_key(principal_key, url),
                encode(&record)?,
                Some(ttl),
            )
            .await?;
        Ok(())
    }

    /// Take one verification request to `host` from this minute's budget
    /// of `per_min`, across every replica. `false` when it is spent.
    pub async fn take_verification_slot(
        &self,
        host: &str,
        per_min: u64,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let minute = now_ms / 60_000;
        let key = format!(
            "ev:vrate:{}:{minute}",
            self.keys.key_hash("callback-host", host.as_bytes())
        );
        let used = self
            .kv
            .incr(&key, 1, Some(Duration::from_secs(120)))
            .await?;
        Ok(used >= 1 && (used as u64) <= per_min)
    }

    /// Whether an operator paused every delivery from the admin API.
    pub async fn delivery_paused(&self) -> Result<bool, StoreError> {
        Ok(self.kv.get(PAUSE_KEY).await?.is_some())
    }

    /// Pause (or resume) every delivery, across every replica.
    pub async fn set_delivery_paused(&self, paused: bool) -> Result<(), StoreError> {
        if paused {
            self.kv
                .put(PAUSE_KEY, Bytes::from_static(b"1"), None)
                .await?;
        } else {
            self.kv.delete(PAUSE_KEY).await?;
        }
        Ok(())
    }

    /// Every subscription record of `principal_key`, lapsed ones included.
    pub async fn principal_ids(&self, principal_key: &str) -> Result<Vec<String>, StoreError> {
        let rows = self
            .kv
            .list_prefix(&self.principal_prefix(principal_key), LIST_LIMIT)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, entry)| decode::<PrincipalIndexEntry>(&entry.bytes).ok())
            .map(|row| row.id)
            .collect())
    }

    async fn hint(&self, op: HintOp, record: &SubscriptionRecord) {
        let Some(bus) = &self.bus else {
            return;
        };
        let hint = SubscriptionHint {
            op,
            id: record.id.clone(),
            name: record.name.clone(),
            expires_at_ms: record.expires_at_ms,
        };
        if let Ok(payload) = serde_json::to_vec(&hint) {
            let _ = bus.publish(SUBSCRIPTION_TOPIC, Bytes::from(payload)).await;
        }
    }

    /// A stream of subscription hints from every replica; `None` without a
    /// bus. Hints are at most once: a reader also re-lists periodically.
    pub async fn hints(&self) -> Option<futures::stream::BoxStream<'static, SubscriptionHint>> {
        let bus = self.bus.as_ref()?;
        let stream = bus.subscribe(SUBSCRIPTION_TOPIC, None).await.ok()?;
        Some(
            stream
                .filter_map(|message| async move {
                    let message = message.ok()?;
                    serde_json::from_slice::<SubscriptionHint>(&message.payload).ok()
                })
                .boxed(),
        )
    }
}

/// The dispatcher shard of subscription `id`.
pub(crate) fn dispatch_shard(id: &str) -> u32 {
    u32::from_str_radix(&shard_of(id), 16).unwrap_or(0) % super::engine::DISPATCH_SHARDS
}

fn shard_of(id: &str) -> String {
    let hex = id
        .strip_prefix(super::keys::SUBSCRIPTION_ID_PREFIX)
        .unwrap_or(id);
    match hex.get(..2) {
        Some(prefix) if prefix.bytes().all(|b| b.is_ascii_hexdigit()) => {
            prefix.to_ascii_lowercase()
        }
        _ => "00".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// The lifetime of a subscription grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The granted lifetime; `None` for a grant with no expiry.
    pub ttl_ms: Option<u64>,
    /// The end of the grant, Unix milliseconds; `None` for no expiry.
    pub expires_at_ms: Option<u64>,
}

impl Grant {
    /// `refreshBefore` as the wire carries it.
    pub fn refresh_before(&self) -> Option<String> {
        self.expires_at_ms.map(rfc3339_ms)
    }
}

/// RFC 3339 UTC of Unix milliseconds.
pub fn rfc3339_ms(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// How long a subscribe is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlPolicy {
    pub default_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    pub allow_no_expiry: bool,
    pub clamp_to_token_expiry: bool,
    /// The store loses records on a restart: every grant is capped at
    /// `min_ms`.
    pub ephemeral: bool,
}

impl TtlPolicy {
    /// The policy of `config` over a store that is (or is not) durable.
    pub fn from_config(config: &EventsConfig, durable: bool) -> Self {
        let ttl = &config.webhook.ttl;
        Self {
            default_ms: ttl.default_ms,
            min_ms: ttl.min_ms,
            max_ms: ttl.max_ms,
            allow_no_expiry: ttl.allow_no_expiry,
            clamp_to_token_expiry: ttl.clamp_to_token_expiry,
            ephemeral: !durable,
        }
    }

    /// The grant for a subscribe that asked for `request`, by a caller
    /// whose token expires at `token_exp_ms`, at `now_ms`.
    ///
    /// The grant is the request clamped into `[min_ms, max_ms]`, so it is
    /// never longer than asked except at the floor. `ttlMs: null` gets
    /// `max_ms` unless no-expiry grants are allowed. A known token expiry
    /// caps the grant, but never below `min_ms`.
    pub fn grant(&self, request: TtlRequest, token_exp_ms: Option<u64>, now_ms: u64) -> Grant {
        let mut ttl = match request {
            TtlRequest::ServerDefault => Some(self.default_ms),
            TtlRequest::Millis(ms) => Some(ms.clamp(self.min_ms, self.max_ms)),
            TtlRequest::NoExpiry if self.allow_no_expiry && !self.ephemeral => None,
            TtlRequest::NoExpiry => Some(self.max_ms),
        };
        if self.clamp_to_token_expiry
            && let Some(exp) = token_exp_ms
        {
            let remaining = exp.saturating_sub(now_ms).max(self.min_ms);
            ttl = Some(ttl.map_or(remaining, |t| t.min(remaining)));
        }
        if self.ephemeral {
            ttl = Some(ttl.map_or(self.min_ms, |t| t.min(self.min_ms)));
        }
        Grant {
            ttl_ms: ttl,
            expires_at_ms: ttl.map(|t| now_ms.saturating_add(t)),
        }
    }
}

#[cfg(test)]
#[path = "subscriptions_tests.rs"]
mod tests;
