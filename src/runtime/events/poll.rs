//! `events/poll`: a client reads an event type's log itself.
//!
//! A poll keeps no subscription. A type with replay names its position with
//! the cursor of the poll before, so every replica answers the same
//! sequence. What the gateway keeps is a lease per (principal, type,
//! arguments), in the `event-subscription` store:
//!
//! - `ev:poll:l:{id}` — the lease: when it last read, whether that read
//!   stopped short of the head, and, for a type without replay, where the
//!   next read starts.
//! - `ev:poll:p:{h(principal)}:{id}` — the index by principal, for the
//!   per-principal cap.
//! - `ev:poll:d:{h(type)}` — when the type's last poll or stream lease ends.
//!   The owner runs the type's source while one is live.
//! - `ev:push:p:{h(principal)}:{stream}` — one open `events/stream`, for the
//!   per-principal stream cap; renewed while the stream runs.
//!
//! Every poll key lives `lease_multiplier` × `next_poll_ms` past the last
//! poll. A lease also bounds how often a client reads: a poll sooner than
//! `min_next_poll_ms` after the last read returns no events, the cursor it
//! sent and the time left, without reading the log.
//!
//! [`read_occurrences`] is the read both poll and push deliver from.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mcpg_cluster_api::{KeyValueStore, PubSub};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::catalog::EventType;
use super::cursor::CursorScope;
use super::dispatcher::gate_payload_for;
use super::engine::{EventsCore, EventsStores, audience_hash};
use super::federated::{Demand, LeaseHolder};
use super::handler::policy_key;
use super::keys::EventsKeys;
use super::log::{LogEntry, ResumePoint, RowBody};
use super::subscriptions::{HintOp, SUBSCRIPTION_TOPIC, StoreError, SubscriptionHint};
use super::webhook::{check_arguments, gate_error, subscriber_key};
use crate::config::events::EventReplay;
use crate::protocol::v_2026_07_28::extensions::events::errors::{
    EventsError, FEATURE_INPUT_SCHEMA,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    DeliveryMode, EventOccurrence, PollEventsParams, PollEventsResult,
};
use crate::runtime::RequestContext;
use crate::runtime::policy::PolicyRoute;

/// Version of every value this module writes.
const FORMAT_VERSION: u32 = 1;
/// Most log rows one poll reads; past them the poll answers `hasMore`.
pub const MAX_SCAN_ROWS: u64 = 2_000;
/// Rows read from the log per batch.
const READ_BATCH: u64 = 100;
/// Most stored bytes of the events one poll returns; past them the poll
/// answers `hasMore`.
pub const MAX_POLL_BYTES: u64 = 4 * 1024 * 1024;
/// What a poll answers when the store fails.
const STORE_FAULT: &str = "the event store is unavailable; retry";
/// The unit of a whole-second store. It truncates both the write time and
/// the TTL to this unit, so it may drop an entry up to one unit plus the
/// TTL's fraction before the TTL ends.
const STORE_TTL_GRANULARITY: Duration = Duration::from_secs(1);

/// The store TTL of a demand row that lapses at its `until_ms`, at most
/// `ttl` from now: `ttl` rounded up to whole seconds, plus one second, so
/// a whole-second store never drops the row first.
fn demand_ttl(ttl: Duration) -> Duration {
    Duration::from_secs(ttl.as_secs() + u64::from(ttl.subsec_nanos() > 0)) + STORE_TTL_GRANULARITY
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn store_fault(error: impl std::fmt::Display) -> EventsError {
    tracing::warn!(error = %error, "event poll store access failed");
    EventsError::internal(STORE_FAULT)
}

/// One poll lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollLease {
    pub v: u32,
    pub name: String,
    /// When the lease last read the log, Unix milliseconds.
    pub last_read_ms: u64,
    /// That read stopped before the head, so the next poll may read at once.
    #[serde(default)]
    pub has_more: bool,
    /// Where the next read of a type without replay starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<LeasePosition>,
}

/// A position in a type's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePosition {
    pub epoch: u64,
    pub after_seq: u64,
}

#[derive(Serialize, Deserialize)]
struct PrincipalRow {
    v: u32,
    id: String,
}

#[derive(Serialize, Deserialize)]
struct DemandRow {
    v: u32,
    until_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct StreamRow {
    v: u32,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct ArgumentDemandRow {
    v: u32,
    #[serde(flatten)]
    demand: Demand,
    until_ms: u64,
}

/// The presence of one upstream subscription of an imported type.
#[derive(Serialize, Deserialize)]
struct UpstreamRow {
    v: u32,
}

/// Most sets of arguments of one type read back as demand.
const MAX_ARGUMENT_DEMAND: usize = 1_000;
/// Key prefixes of the poll leases, the open streams and the upstream
/// subscriptions of every type: each lists one kind of reader alone.
const LEASE_PREFIX: &str = "ev:poll:l:";
const STREAM_PREFIX: &str = "ev:push:p:";
const UPSTREAM_PREFIX: &str = "ev:fed:u:";

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

/// The poll and stream leases.
pub struct LeaseStore {
    kv: Arc<dyn KeyValueStore>,
    bus: Option<Arc<dyn PubSub>>,
    keys: Arc<EventsKeys>,
}

impl std::fmt::Debug for LeaseStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseStore").finish_non_exhaustive()
    }
}

impl LeaseStore {
    pub fn new(
        kv: Arc<dyn KeyValueStore>,
        bus: Option<Arc<dyn PubSub>>,
        keys: Arc<EventsKeys>,
    ) -> Self {
        Self { kv, bus, keys }
    }

    /// The id of the lease of `principal_key` on `name` with `arguments`.
    pub fn lease_id(
        &self,
        principal_key: &str,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> String {
        let input = Value::Array(vec![
            Value::String(principal_key.to_owned()),
            Value::String(name.to_owned()),
            Value::Object(arguments.clone()),
        ]);
        self.keys.key_hash(
            "poll-lease",
            &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&input),
        )
    }

    fn lease_key(id: &str) -> String {
        format!("{LEASE_PREFIX}{id}")
    }

    fn principal_prefix(&self, principal_key: &str) -> String {
        format!(
            "ev:poll:p:{}:",
            self.keys.key_hash("principal", principal_key.as_bytes())
        )
    }

    fn demand_key(&self, name: &str) -> String {
        format!(
            "ev:poll:d:{}",
            self.keys.key_hash("event-type", name.as_bytes())
        )
    }

    /// The lease `id`, while it lasts.
    pub async fn get(&self, id: &str) -> Result<Option<PollLease>, StoreError> {
        match self.kv.get(&Self::lease_key(id)).await? {
            Some(entry) => decode(&entry.bytes).map(Some),
            None => Ok(None),
        }
    }

    /// The live leases of `principal_key`, counted up to `limit`.
    pub async fn count_of(&self, principal_key: &str, limit: usize) -> Result<usize, StoreError> {
        Ok(self
            .kv
            .list_prefix(&self.principal_prefix(principal_key), limit)
            .await?
            .len())
    }

    /// Write lease `id` of `principal_key` for `ttl`.
    pub async fn put(
        &self,
        id: &str,
        principal_key: &str,
        lease: &PollLease,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.kv
            .put(&Self::lease_key(id), encode(lease)?, Some(ttl))
            .await?;
        let row = PrincipalRow {
            v: FORMAT_VERSION,
            id: id.to_owned(),
        };
        self.kv
            .put(
                &format!("{}{id}", self.principal_prefix(principal_key)),
                encode(&row)?,
                Some(ttl),
            )
            .await?;
        Ok(())
    }

    fn stream_prefix(&self, principal_key: &str) -> String {
        format!(
            "{STREAM_PREFIX}{}:",
            self.keys.key_hash("principal", principal_key.as_bytes())
        )
    }

    /// The open streams of `principal_key`, counted up to `limit`.
    pub async fn count_streams(
        &self,
        principal_key: &str,
        limit: usize,
    ) -> Result<usize, StoreError> {
        Ok(self
            .kv
            .list_prefix(&self.stream_prefix(principal_key), limit)
            .await?
            .len())
    }

    /// Hold stream `stream_id` of `principal_key` on `name` for `ttl`.
    pub async fn put_stream(
        &self,
        principal_key: &str,
        stream_id: &str,
        name: &str,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let row = StreamRow {
            v: FORMAT_VERSION,
            name: name.to_owned(),
        };
        self.kv
            .put(
                &format!("{}{stream_id}", self.stream_prefix(principal_key)),
                encode(&row)?,
                Some(ttl),
            )
            .await?;
        Ok(())
    }

    /// The live poll leases of every principal, counted up to `limit`.
    pub async fn count_all_leases(&self, limit: usize) -> Result<usize, StoreError> {
        Ok(self.kv.list_prefix(LEASE_PREFIX, limit).await?.len())
    }

    /// The open streams of every principal, counted up to `limit`.
    pub async fn count_all_streams(&self, limit: usize) -> Result<usize, StoreError> {
        Ok(self.kv.list_prefix(STREAM_PREFIX, limit).await?.len())
    }

    fn upstream_key(&self, name: &str, key: &str) -> String {
        format!(
            "{UPSTREAM_PREFIX}{}:{key}",
            self.keys.key_hash("event-type", name.as_bytes())
        )
    }

    /// Record, for `ttl`, that an upstream subscription serves the demand
    /// keyed `key` of the imported type `name`.
    pub(crate) async fn put_upstream(
        &self,
        name: &str,
        key: &str,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let row = UpstreamRow { v: FORMAT_VERSION };
        self.kv
            .put(&self.upstream_key(name, key), encode(&row)?, Some(ttl))
            .await?;
        Ok(())
    }

    /// Forget the upstream subscription of the demand keyed `key` of `name`.
    pub(crate) async fn drop_upstream(&self, name: &str, key: &str) -> Result<(), StoreError> {
        self.kv.delete(&self.upstream_key(name, key)).await?;
        Ok(())
    }

    /// Whether an upstream subscription serves the demand keyed `key` of
    /// `name`.
    pub(crate) async fn has_upstream(&self, name: &str, key: &str) -> Result<bool, StoreError> {
        Ok(self.kv.get(&self.upstream_key(name, key)).await?.is_some())
    }

    /// The upstream subscriptions of every imported type, counted up to
    /// `limit`.
    pub(crate) async fn count_upstreams(&self, limit: usize) -> Result<usize, StoreError> {
        Ok(self.kv.list_prefix(UPSTREAM_PREFIX, limit).await?.len())
    }

    /// Release stream `stream_id` of `principal_key`.
    pub async fn drop_stream(
        &self,
        principal_key: &str,
        stream_id: &str,
    ) -> Result<(), StoreError> {
        self.kv
            .delete(&format!("{}{stream_id}", self.stream_prefix(principal_key)))
            .await?;
        Ok(())
    }

    /// When the last lease of `name` ends, as last written.
    pub async fn demand(&self, name: &str) -> Result<Option<u64>, StoreError> {
        match self.kv.get(&self.demand_key(name)).await? {
            Some(entry) => Ok(Some(decode::<DemandRow>(&entry.bytes)?.until_ms)),
            None => Ok(None),
        }
    }

    /// Record that a lease of `name` runs until `until_ms`, and tell every
    /// replica.
    pub async fn extend_demand(
        &self,
        name: &str,
        until_ms: u64,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let row = DemandRow {
            v: FORMAT_VERSION,
            until_ms,
        };
        self.kv
            .put(&self.demand_key(name), encode(&row)?, Some(demand_ttl(ttl)))
            .await?;
        if let Some(bus) = &self.bus {
            let hint = SubscriptionHint {
                op: HintOp::Lease,
                id: String::new(),
                name: name.to_owned(),
                expires_at_ms: Some(until_ms),
            };
            if let Ok(payload) = serde_json::to_vec(&hint) {
                let _ = bus.publish(SUBSCRIPTION_TOPIC, Bytes::from(payload)).await;
            }
        }
        Ok(())
    }

    fn arguments_prefix(&self, name: &str) -> String {
        format!(
            "ev:poll:a:{}:",
            self.keys.key_hash("event-type", name.as_bytes())
        )
    }

    /// Record that a lease of `name` holds `demand`, keyed `key` among the
    /// demand of `name`, until `until_ms`. Only an imported type reads it:
    /// one upstream subscription serves each key.
    pub(crate) async fn extend_argument_demand(
        &self,
        name: &str,
        key: &str,
        demand: &Demand,
        until_ms: u64,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let row = ArgumentDemandRow {
            v: FORMAT_VERSION,
            demand: demand.clone(),
            until_ms,
        };
        self.kv
            .put(
                &format!("{}{key}", self.arguments_prefix(name)),
                encode(&row)?,
                Some(demand_ttl(ttl)),
            )
            .await?;
        Ok(())
    }

    /// The demand the leases of `name` hold at `now_ms`, by key.
    pub(crate) async fn argument_demand(
        &self,
        name: &str,
        now_ms: u64,
    ) -> Result<HashMap<String, Demand>, StoreError> {
        let prefix = self.arguments_prefix(name);
        let mut demand = HashMap::new();
        for (key, entry) in self.kv.list_prefix(&prefix, MAX_ARGUMENT_DEMAND).await? {
            let Some(key) = key.strip_prefix(&prefix) else {
                continue;
            };
            match decode::<ArgumentDemandRow>(&entry.bytes) {
                Ok(row) if row.until_ms > now_ms => {
                    demand.insert(key.to_owned(), row.demand);
                }
                Ok(_) | Err(StoreError::Unreadable) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(demand)
    }
}

/// What a read of the log found, in log order.
pub(crate) enum ReadItem {
    /// An occurrence the reader receives.
    Event(EventOccurrence),
    /// Events may be missing up to here; the read continues after `after`.
    Gap { after: u64 },
    /// The reader's subscription ends here; always the last item, and the
    /// read stops before it, so every read from there meets it again.
    Ended(super::log::EndReason),
}

/// What one read of the log found.
pub(crate) struct Read {
    pub items: Vec<ReadItem>,
    /// The log epoch the read was in.
    pub epoch: u64,
    /// The last row the read passed.
    pub after: u64,
    /// The start was truncated, or the read passed a gap.
    pub truncated: bool,
    /// The read stopped at a budget before the head.
    pub has_more: bool,
    /// Stored bytes of the events read.
    pub bytes: u64,
}

impl Read {
    /// How many events the read found.
    pub fn event_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| matches!(item, ReadItem::Event(_)))
            .count()
    }
}

/// Who reads, and what bounds one read.
pub(crate) struct Reader<'a> {
    pub identity: &'a crate::runtime::RequestIdentity,
    pub principal_key: &'a str,
    pub arguments: &'a Map<String, Value>,
    pub scope: &'a CursorScope,
    /// `poll` or `push`, for the payload gates.
    pub mode: DeliveryMode,
    pub max_events: usize,
}

impl EventsCore {
    /// `events/poll`.
    pub(crate) async fn poll_events(
        &self,
        ctx: &RequestContext,
        params: PollEventsParams,
    ) -> Result<PollEventsResult, EventsError> {
        let config = self.config();
        let poll = &config.poll;
        if !poll.enabled {
            return Err(EventsError::unsupported_delivery_mode(
                DeliveryMode::Poll.as_str(),
            ));
        }
        let principal_key = subscriber_key(&ctx.identity, poll.require_trust)?;
        let ty = self.offered_type(ctx, &params.name, DeliveryMode::Poll)?;
        check_arguments(&ty, &params.arguments)?;
        let arguments = Value::Object(params.arguments.clone());
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?
            .load_full();
        runtime
            .evaluate_surface_gate_without_waiting(
                "event",
                "event.poll.pre",
                &policy_key(&ty.name),
                PolicyRoute::event(Some(&arguments)),
                &arguments,
                ctx,
                &Value::Null,
            )
            .await
            .map_err(gate_error)?;

        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let now = now_ms();
        let lease_ms = poll.next_poll_ms.saturating_mul(poll.lease_multiplier);
        let ttl = Duration::from_millis(lease_ms.max(1_000));
        let scope = CursorScope::new(&ty.source_key, &arguments);
        let id = stores
            .leases
            .lease_id(&principal_key, &ty.name, &params.arguments);
        let holder = LeaseHolder {
            principal_key: &principal_key,
            identity: &ctx.identity,
            arguments: &params.arguments,
        };
        let lease = stores.leases.get(&id).await.map_err(store_fault)?;
        match &lease {
            None => {
                let cap = poll.max_leases_per_principal;
                let held = stores
                    .leases
                    .count_of(&principal_key, cap as usize)
                    .await
                    .map_err(store_fault)?;
                if held as u64 >= cap {
                    return Err(EventsError::resource_exhausted("poll_leases", Some(cap)));
                }
                self.check_plan_readers(&ty, &holder).await?;
            }
            Some(lease) if !lease.has_more => {
                let next_read = lease.last_read_ms.saturating_add(poll.min_next_poll_ms);
                if now < next_read {
                    metrics::counter!("mcpg_events_polls_total", "event" => ty.name.clone(), "outcome" => "throttled")
                        .increment(1);
                    let cursor = self
                        .unmoved_cursor(&stores, &ty, &scope, params.cursor.as_deref())
                        .await?;
                    return Ok(PollEventsResult::new(
                        Vec::new(),
                        cursor,
                        false,
                        false,
                        next_read - now,
                    ));
                }
            }
            Some(_) => {}
        }

        // A held poll answers no events and the cursor it was given; the
        // events wait in the log.
        if self.delivery_held(&runtime).await {
            metrics::counter!("mcpg_events_polls_total", "event" => ty.name.clone(), "outcome" => "held")
                .increment(1);
            let cursor = self
                .unmoved_cursor(&stores, &ty, &scope, params.cursor.as_deref())
                .await?;
            self.keep_lease(
                &stores,
                &id,
                &ty,
                &holder,
                lease.as_ref(),
                now,
                ttl,
                lease_ms,
            )
            .await?;
            return Ok(PollEventsResult::new(
                Vec::new(),
                cursor,
                false,
                false,
                poll.next_poll_ms,
            ));
        }
        let start = self
            .poll_start(&stores, &ty, &scope, &params, lease.as_ref())
            .await?;
        let max_events = params
            .max_events
            .map(u64::from)
            .unwrap_or(poll.max_events)
            .clamp(1, poll.max_events_cap);
        let read = read_occurrences(
            &stores,
            &runtime,
            &ty,
            &Reader {
                identity: &ctx.identity,
                principal_key: &principal_key,
                arguments: &params.arguments,
                scope: &scope,
                mode: DeliveryMode::Poll,
                max_events: max_events as usize,
            },
            start,
        )
        .await?;
        // The upstream of an imported type ended these arguments: the events
        // before the end come first, then the error.
        let mut read = read;
        if let Some(ReadItem::Ended(reason)) = read.items.last() {
            if read.event_count() == 0 {
                metrics::counter!("mcpg_events_polls_total", "event" => ty.name.clone(), "outcome" => "ended")
                    .increment(1);
                return Err(reason.error());
            }
            read.has_more = true;
        }

        metrics::counter!("mcpg_events_polls_total", "event" => ty.name.clone(), "outcome" => "served")
            .increment(1);
        let count = read.event_count();
        if count > 0 {
            metrics::counter!(
                "mcpg_events_delivered_total",
                "event" => ty.name.clone(),
                "mode" => DeliveryMode::Poll.as_str()
            )
            .increment(count as u64);
            runtime.tool_call_recorder.record_event_usage(
                &ty.name,
                DeliveryMode::Poll.as_str(),
                ty.billable_deliveries(count as u64),
                0,
                read.bytes,
            );
        }
        let next = PollLease {
            v: FORMAT_VERSION,
            name: ty.name.clone(),
            last_read_ms: now,
            has_more: read.has_more,
            position: (ty.replay == EventReplay::None).then_some(LeasePosition {
                epoch: read.epoch,
                after_seq: read.after,
            }),
        };
        stores
            .leases
            .put(&id, &principal_key, &next, ttl)
            .await
            .map_err(store_fault)?;
        self.note_lease_demand(&stores, &ty, &holder, now, lease_ms, ttl)
            .await;
        let cursor = (ty.replay == EventReplay::Log).then(|| {
            stores
                .log
                .seal_cursor(read.epoch, ty.schema_epoch, read.after, &scope)
        });
        let next_poll_ms = if read.has_more {
            poll.min_next_poll_ms
        } else {
            poll.next_poll_ms
        };
        let events = read
            .items
            .into_iter()
            .filter_map(|item| match item {
                ReadItem::Event(event) => Some(event),
                ReadItem::Gap { .. } | ReadItem::Ended(_) => None,
            })
            .collect();
        Ok(PollEventsResult::new(
            events,
            cursor,
            read.truncated,
            read.has_more,
            next_poll_ms,
        ))
    }

    /// The cursor a poll that reads nothing answers: the one it sent, or
    /// the head for a poll from now. `None` for a type without replay.
    async fn unmoved_cursor(
        &self,
        stores: &EventsStores,
        ty: &EventType,
        scope: &CursorScope,
        sent: Option<&str>,
    ) -> Result<Option<String>, EventsError> {
        if ty.replay != EventReplay::Log {
            return Ok(None);
        }
        if let Some(sent) = sent {
            return Ok(Some(sent.to_owned()));
        }
        let bounds = stores
            .log
            .bounds(&ty.source_key)
            .await
            .map_err(store_fault)?;
        Ok(Some(stores.log.seal_cursor(
            bounds.epoch,
            ty.schema_epoch,
            bounds.head,
            scope,
        )))
    }

    /// Renew a lease without reading, so its type keeps its source.
    #[allow(clippy::too_many_arguments)]
    async fn keep_lease(
        &self,
        stores: &EventsStores,
        id: &str,
        ty: &EventType,
        holder: &LeaseHolder<'_>,
        lease: Option<&PollLease>,
        now: u64,
        ttl: Duration,
        lease_ms: u64,
    ) -> Result<(), EventsError> {
        let kept = lease.cloned().unwrap_or(PollLease {
            v: FORMAT_VERSION,
            name: ty.name.clone(),
            last_read_ms: 0,
            has_more: false,
            position: None,
        });
        stores
            .leases
            .put(id, holder.principal_key, &kept, ttl)
            .await
            .map_err(store_fault)?;
        self.note_lease_demand(stores, ty, holder, now, lease_ms, ttl)
            .await;
        Ok(())
    }

    /// Where a poll starts reading: after the cursor it sent for a type
    /// with replay, after the lease's position for one without, and at the
    /// head for a first poll of either.
    async fn poll_start(
        &self,
        stores: &EventsStores,
        ty: &EventType,
        scope: &CursorScope,
        params: &PollEventsParams,
        lease: Option<&PollLease>,
    ) -> Result<ResumePoint, EventsError> {
        match ty.replay {
            EventReplay::Log => {
                resume_point(
                    stores,
                    ty,
                    scope,
                    params.cursor.as_deref(),
                    params.max_age_ms,
                )
                .await
            }
            EventReplay::None => {
                let bounds = stores
                    .log
                    .bounds(&ty.source_key)
                    .await
                    .map_err(store_fault)?;
                Ok(match lease.and_then(|lease| lease.position) {
                    Some(at)
                        if at.epoch == bounds.epoch
                            && at.after_seq.saturating_add(1) >= bounds.floor =>
                    {
                        ResumePoint {
                            epoch: bounds.epoch,
                            after_seq: at.after_seq.min(bounds.head),
                            truncated: false,
                        }
                    }
                    // A lost log, or rows retention dropped before this
                    // lease read them.
                    Some(_) => ResumePoint {
                        epoch: bounds.epoch,
                        after_seq: bounds.floor.saturating_sub(1),
                        truncated: true,
                    },
                    None => ResumePoint {
                        epoch: bounds.epoch,
                        after_seq: bounds.head,
                        truncated: false,
                    },
                })
            }
        }
    }
}

/// Where a reader with `cursor` starts in the log of `ty`, a type with
/// replay; `-32014 schema_changed` for a cursor of an older schema epoch.
pub(crate) async fn resume_point(
    stores: &EventsStores,
    ty: &EventType,
    scope: &CursorScope,
    cursor: Option<&str>,
    max_age_ms: Option<u64>,
) -> Result<ResumePoint, EventsError> {
    match stores
        .log
        .resume(&ty.source_key, cursor, scope, ty.schema_epoch, max_age_ms)
        .await
    {
        Ok(Ok(point)) => Ok(point),
        Ok(Err(_)) => Err(EventsError::schema_changed(FEATURE_INPUT_SCHEMA)),
        Err(error) => Err(store_fault(error)),
    }
}

/// Read the occurrences after `start` that `reader` receives: those meant
/// for it, matching its arguments, and passed by the payload gates. Stops
/// at `max_events`, [`MAX_POLL_BYTES`] or [`MAX_SCAN_ROWS`] rows read, and
/// reports a gap where a lost log, rows retention dropped, a gap marker or
/// a refused payload may have cost the reader events.
pub(crate) async fn read_occurrences(
    stores: &EventsStores,
    runtime: &crate::runtime::GatewayRuntime,
    ty: &EventType,
    reader: &Reader<'_>,
    start: ResumePoint,
) -> Result<Read, EventsError> {
    let bounds = stores
        .log
        .bounds(&ty.source_key)
        .await
        .map_err(store_fault)?;
    let mut read = Read {
        items: Vec::new(),
        epoch: bounds.epoch,
        after: start.after_seq,
        truncated: start.truncated,
        has_more: false,
        bytes: 0,
    };
    if bounds.epoch != start.epoch || read.after.saturating_add(1) < bounds.floor {
        read.after = bounds.floor.saturating_sub(1);
        read.truncated = true;
        read.items.push(ReadItem::Gap { after: read.after });
    }
    let audience = audience_hash(&stores.keys, reader.principal_key);
    let arguments_hash = stores.keys.arguments_hash(reader.arguments);
    let mut found = 0usize;
    let limit = read.after.saturating_add(MAX_SCAN_ROWS).min(bounds.head);
    'scan: while read.after < limit {
        let batch = READ_BATCH.min(limit - read.after);
        let rows = stores
            .log
            .read(&ty.source_key, read.after, batch as usize)
            .await
            .map_err(store_fault)?;
        if rows.is_empty() {
            read.after = read.after.saturating_add(batch);
            continue;
        }
        for entry in rows {
            let seq = entry.seq();
            if seq > limit {
                break 'scan;
            }
            let LogEntry::Row(row) = entry else {
                read.after = seq;
                continue;
            };
            if let Some(reason) = row.body.ends(&audience, &arguments_hash) {
                read.after = seq - 1;
                read.items.push(ReadItem::Ended(reason));
                break 'scan;
            }
            let occurrence = match row.body {
                RowBody::Gap { .. } if row.body.is_gap_for(&audience, &arguments_hash) => {
                    read.truncated = true;
                    read.after = seq;
                    read.items.push(ReadItem::Gap { after: seq });
                    continue;
                }
                RowBody::Gap { .. } | RowBody::Ended { .. } => {
                    read.after = seq;
                    continue;
                }
                RowBody::Event(occurrence) => occurrence,
            };
            if !occurrence.is_for(&audience, &arguments_hash)
                || !ty.matches(reader.arguments, &occurrence, reader.identity)
            {
                read.after = seq;
                continue;
            }
            if found >= reader.max_events || read.bytes >= MAX_POLL_BYTES {
                read.has_more = true;
                break 'scan;
            }
            let Some(data) = gate_payload_for(
                runtime.plugin_registry(),
                reader.identity,
                &ty.name,
                reader.arguments,
                &occurrence.data,
                reader.mode.as_str(),
            )
            .await
            else {
                metrics::counter!("mcpg_events_payload_blocked_total", "event" => ty.name.clone())
                    .increment(1);
                read.truncated = true;
                read.after = seq;
                read.items.push(ReadItem::Gap { after: seq });
                continue;
            };
            read.after = seq;
            read.bytes = read.bytes.saturating_add(row.bytes);
            found += 1;
            read.items.push(ReadItem::Event(EventOccurrence {
                event_id: occurrence.event_id,
                name: ty.name.clone(),
                timestamp: occurrence.timestamp,
                data,
                cursor: (ty.replay == EventReplay::Log).then(|| {
                    stores
                        .log
                        .seal_cursor(bounds.epoch, ty.schema_epoch, seq, reader.scope)
                }),
                meta: None,
            }));
        }
    }
    if read.after < bounds.head {
        read.has_more = true;
    }
    Ok(read)
}

#[cfg(test)]
#[path = "poll_tests.rs"]
mod tests;
