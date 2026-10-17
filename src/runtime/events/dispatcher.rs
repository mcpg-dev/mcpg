//! The webhook dispatcher: delivers each live subscription's events from the
//! log to its callback, on the replica that holds the subscription's shard.
//! The shards are fenced locks the replicas share out (`DISPATCH_SHARDS`).
//!
//! Each event goes in its own signed POST whose `webhook-id` is the event
//! id, the same on every retry, with a fresh timestamp and signature per
//! attempt. A `2xx` acknowledges it; `410` and `413` give it up at once; any
//! other answer is retried with backoff until the attempts or the retry
//! window run out, and then given up. The watermark (`ack_seq`) only moves
//! over events that are acknowledged, given up, or not for this
//! subscription, so a cursor in a body never skips an event still in
//! flight.
//!
//! Delivery state is checkpointed at most once a second per subscription,
//! with its shard's fence, so the store sees writes in proportion to time,
//! not to deliveries. A new holder of a shard resumes from the last
//! checkpoints and may repeat the deliveries after them, with the same
//! `webhook-id`. A replica that gives shards up on purpose, on a rebalance,
//! a reload or a shutdown, checkpoints first.
//!
//! Every subscription's authorization is checked again from its stored
//! identity on an interval and after every config reload, and a revoked
//! token of the embedded authorization server stops delivery at once.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mcpg_safe_egress::SafeEgress;
use mcpg_standard_webhooks::WhsecSecret;
use serde_json::{Map, Value};
use tokio::task::JoinSet;

use super::catalog::EventType;
use super::cursor::CursorScope;
use super::delivery::{Attempt, SignedPost, UNSIGNABLE_ID, random_token};
use super::engine::{EventsCore, OWNER_LEASE_TTL};
use super::handler::policy_key;
use super::log::{EndReason, LogEntry, RowBody, WriterLease};
use super::occurrence::StoredOccurrence;
use super::subscriptions::{
    DeliveryState, FORMAT_VERSION, InFlight, Revocation, SubscriptionRecord, TerminationReason,
    dispatch_shard,
};
use super::verifier::CONTROL_ID_BYTES;
use super::webhook::subscriber_key;
use crate::config::events::{ControlEnvelopeKind, DeliveryAuditMode, EventReplay, EventsConfig};
use crate::protocol::v_2026_07_28::extensions::events::errors::ForbiddenReason;
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    ControlEnvelope, DeliveryErrorCategory, DeliveryMode, EventOccurrence, MAX_WEBHOOK_BODY_BYTES,
};
use crate::runtime::policy::PolicyRoute;
use crate::runtime::{GatewayRequestId, GatewayRuntime, RequestContext, TransportKind};

/// Interval of the dispatcher loop.
pub const DISPATCH_TICK: Duration = Duration::from_millis(250);
/// Shortest interval between two checkpoints of one subscription.
pub const CHECKPOINT_INTERVAL_MS: u64 = 1_000;
/// Longest wait for the attempts in flight when the owner hands off.
const HAND_OFF_TIMEOUT: Duration = Duration::from_secs(5);
/// A subscription record is read again at least this often.
pub const RECORD_MAX_AGE_MS: u64 = 60_000;
/// Most log rows handed out past the watermark of one subscription.
pub const MAX_WINDOW: u64 = 1_000;
/// Most deliveries of one subscription awaiting an answer or a retry.
pub const MAX_RETRY_SET: usize = 100;
/// Rows read from the log per subscription per pass.
const READ_BATCH: usize = 64;
/// Waits before retries 1, 2, 3, ... of one delivery, in 180ths of the
/// retry window: 5 s, 30 s, 2 min, 5 min and 10 min of the default 15.
const BACKOFF_180THS: [u64; 5] = [1, 6, 24, 60, 120];
/// Interval of delivery summary audit records per subscription.
const SUMMARY_INTERVAL_MS: u64 = 300_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What one delivery attempt reported.
#[derive(Debug)]
pub struct Outcome {
    id: String,
    seq: u64,
    /// The `webhook-id` of the attempt: the event id for an event.
    webhook_id: String,
    host: String,
    category: Option<DeliveryErrorCategory>,
    status: Option<u16>,
    retry_after_ms: Option<u64>,
    /// The attempt carried a control envelope, not an event.
    control: bool,
    /// Bytes of the body sent.
    bytes: u64,
    /// Nothing was sent: the `webhook-id` cannot be signed, now or later.
    unsignable: bool,
    /// The type was the gateway's own when the attempt was sent, so its
    /// delivery is not billed even if a reload removes the type meanwhile.
    builtin: bool,
}

/// Counts for the next delivery summary.
#[derive(Debug, Default, Clone, Copy)]
struct Summary {
    since_ms: u64,
    delivered: u64,
    failed: u64,
    abandoned: u64,
}

/// One subscription the dispatcher serves.
struct Sub {
    record: SubscriptionRecord,
    /// Signing keys: the current secret, then the previous one during a
    /// rotation.
    secrets: Vec<WhsecSecret>,
    loaded_at_ms: u64,
    state: DeliveryState,
    /// Sequence numbers above the watermark that are done.
    done: BTreeSet<u64>,
    /// The highest sequence number handed out.
    dispatched: u64,
    /// Sequence numbers with an attempt in flight.
    sending: HashSet<u64>,
    dirty: bool,
    last_checkpoint_ms: u64,
    last_recheck_ms: u64,
    rechecked_generation: u64,
    summary: Summary,
    /// The upstream of an imported type ended this subscription's
    /// arguments at this row: it ends once every row before is done.
    ends_at: Option<(u64, EndReason)>,
}

/// What one delivery of a row carries.
enum Outgoing {
    Event(StoredOccurrence),
    Gap,
}

impl Outgoing {
    /// The delivery of `body`; `None` for a row that is never delivered.
    fn of(body: RowBody) -> Option<Self> {
        match body {
            RowBody::Event(occurrence) => Some(Self::Event(occurrence)),
            RowBody::Gap { .. } => Some(Self::Gap),
            RowBody::Ended { .. } => None,
        }
    }
}

impl Sub {
    /// Move the watermark over every done sequence number right above it.
    fn advance(&mut self) {
        while self.done.remove(&(self.state.ack_seq + 1)) {
            self.state.ack_seq += 1;
        }
        self.dirty = true;
    }

    fn finish(&mut self, seq: u64) {
        self.state.in_flight.retain(|f| f.seq != seq);
        if seq > self.state.ack_seq {
            self.done.insert(seq);
        }
        self.advance();
    }

    fn signing_keys(&self, now: u64) -> Vec<&WhsecSecret> {
        let rotating = self
            .record
            .previous_secret_until_ms
            .is_some_and(|until| until > now);
        self.secrets
            .iter()
            .take(if rotating { 2 } else { 1 })
            .collect()
    }

    /// Shift every retry deadline by `by_ms`: time spent paused or
    /// suspended does not count against the retry window.
    fn shift_retries(&mut self, by_ms: u64) {
        for item in &mut self.state.in_flight {
            item.first_attempt_at_ms = item.first_attempt_at_ms.saturating_add(by_ms);
            item.next_attempt_at_ms = item.next_attempt_at_ms.saturating_add(by_ms);
        }
        self.dirty = true;
    }
}

/// The dispatcher's state: the subscriptions of the shards this replica
/// holds.
#[derive(Default)]
pub struct Dispatcher {
    subs: HashMap<String, Sub>,
    /// Subscriptions whose record ended delivery for good; read again only
    /// when the record changes.
    ended: HashSet<String>,
    tasks: JoinSet<Outcome>,
    host_in_flight: HashMap<String, u64>,
    /// The fence of each held shard, as the subscriptions were loaded under.
    fences: HashMap<u32, u64>,
    paused_since_ms: Option<u64>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("subscriptions", &self.subs.len())
            .field("in_flight", &self.tasks.len())
            .finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// Forget everything: this replica no longer delivers.
    pub(crate) fn step_down(&mut self) {
        self.tasks.abort_all();
        self.subs.clear();
        self.ended.clear();
        self.host_in_flight.clear();
        self.fences.clear();
    }

    /// Forget the subscriptions of `shards`: another replica delivers them
    /// now. Their attempts in flight finish; their outcomes are ignored.
    fn drop_shards(&mut self, shards: &[u32]) {
        let in_shards = |id: &str| shards.contains(&dispatch_shard(id));
        self.subs.retain(|id, _| !in_shards(id));
        self.ended.retain(|id| !in_shards(id));
        for shard in shards {
            self.fences.remove(shard);
        }
    }

    /// Subscriptions served now.
    pub fn served(&self) -> usize {
        self.subs.len()
    }

    fn release_host(&mut self, host: &str) {
        if let Some(n) = self.host_in_flight.get_mut(host) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.host_in_flight.remove(host);
            }
        }
    }
}

/// The wait before retry `attempts` (1-based) inside a retry window of
/// `window_ms`, with up to 10% jitter.
fn backoff_ms(attempts: u32, window_ms: u64) -> u64 {
    let index = (attempts.max(1) as usize - 1).min(BACKOFF_180THS.len() - 1);
    let base = (window_ms.saturating_mul(BACKOFF_180THS[index]) / 180).max(1);
    let jitter = {
        use chacha20poly1305::aead::Generate as _;
        u64::from(u16::from_le_bytes(<[u8; 2]>::generate())) % (base / 10).max(1)
    };
    base + jitter
}

/// `Retry-After` in milliseconds, when it names seconds.
fn retry_after_ms(attempt: &Attempt) -> Option<u64> {
    let Attempt::Refused(response) = attempt else {
        return None;
    };
    response
        .headers
        .get(axum::http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|s| s.saturating_mul(1_000))
}

/// Whether the embedded authorization server revoked the token or grant
/// a subscription was made with.
fn is_revoked(runtime: &GatewayRuntime, record: &SubscriptionRecord) -> bool {
    credential_is_revoked(runtime, &record.credential)
}

/// Whether the embedded authorization server revoked the token or grant of
/// `credential`.
pub(crate) fn credential_is_revoked(
    runtime: &GatewayRuntime,
    credential: &super::subscriptions::CredentialSnapshot,
) -> bool {
    use crate::runtime::authorization_server::state::{GrantId, RevokedId};
    let Some(state) = runtime
        .ema_authorization_server()
        .and_then(|server| server.interactive_state())
    else {
        return false;
    };
    credential
        .grant_id
        .as_deref()
        .and_then(GrantId::parse)
        .is_some_and(|grant| state.is_revoked(&RevokedId::Grant(grant)))
        || credential
            .jti
            .as_deref()
            .is_some_and(|jti| state.is_revoked(&RevokedId::access_token(jti)))
}

/// What the `event.deliver.post` gates (DLP, masking, field encryption)
/// make of `data` for the subscriber of `record`: the data to send, or
/// `None` when a gate refuses it.
async fn gate_payload(
    registry: &mcpg_plugin_host::PluginRegistry,
    record: &SubscriptionRecord,
    data: &Value,
) -> Option<Value> {
    gate_payload_for(
        registry,
        &record.identity,
        &record.name,
        &record.arguments,
        data,
        "webhook",
    )
    .await
}

/// What the `event.deliver.post` gates make of `data` of event `name` for
/// `identity`, reached over `transport`: the data to send, or `None` when
/// a gate refuses it.
pub(crate) async fn gate_payload_for(
    registry: &mcpg_plugin_host::PluginRegistry,
    identity: &crate::runtime::RequestIdentity,
    name: &str,
    arguments: &Map<String, Value>,
    data: &Value,
    transport: &str,
) -> Option<Value> {
    if !registry.has_tool_gate_plugins() {
        return Some(data.clone());
    }
    let ctx = mcpg_plugin_protocol::PluginContext {
        request_id: uuid::Uuid::now_v7().to_string(),
        session_id: None,
        tool_name: policy_key(name),
        surface: "event".to_owned(),
        identity: crate::runtime::util::plugin_identity_from_request_identity(identity),
        transport: transport.to_owned(),
    };
    match registry
        .evaluate_tool_gates_post(&ctx, &Value::Object(arguments.clone()), data, 0, None)
        .await
    {
        mcpg_plugin_protocol::GateDecision::Allow {
            modified_result, ..
        } => Some(modified_result.unwrap_or_else(|| data.clone())),
        _ => None,
    }
}

/// The context a re-check decides under: the stored identity, no session.
fn recheck_context(record: &SubscriptionRecord) -> RequestContext {
    RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        record.identity.clone(),
        TransportKind::Http,
    )
}

/// The `webhook-id` of the gap envelope at `seq`: the same on every retry
/// and on every owner, so a receiver can drop a repeat.
fn gap_webhook_id(core: &EventsCore, record: &SubscriptionRecord, epoch: u64, seq: u64) -> String {
    let random = core
        .stores()
        .map(|s| {
            s.keys.key_hash(
                "gap-envelope",
                format!("{}:{epoch}:{seq}", record.id).as_bytes(),
            )
        })
        .unwrap_or_else(|| random_token(CONTROL_ID_BYTES));
    ControlEnvelope::Gap { cursor: None }.webhook_id(&random)
}

impl EventsCore {
    /// One pass of the dispatcher: apply finished attempts, then hand out
    /// what is due. Public so tests can drive it.
    pub async fn dispatch_tick(self: &Arc<Self>) {
        let mut dispatcher = self.dispatcher().lock().await;
        while let Some(joined) = dispatcher.tasks.try_join_next() {
            if let Ok(outcome) = joined {
                self.apply_outcome(&mut dispatcher, outcome).await;
            }
        }
        self.dispatch_pass(&mut dispatcher).await;
    }

    /// Wait for every attempt in flight and apply it. Public so tests can
    /// drive it.
    pub async fn dispatch_settle(self: &Arc<Self>) {
        let mut dispatcher = self.dispatcher().lock().await;
        while let Some(joined) = dispatcher.tasks.join_next().await {
            if let Ok(outcome) = joined {
                self.apply_outcome(&mut dispatcher, outcome).await;
            }
        }
        self.checkpoint_all(&mut dispatcher, true).await;
    }

    /// Before this replica gives shards up on purpose (`which`, or all):
    /// apply the attempts that finish within `HAND_OFF_TIMEOUT`, checkpoint
    /// every subscription under the fences still held, and stop serving
    /// those shards. The next holder then repeats only what was still in
    /// flight. The caller releases the locks while it holds the returned
    /// guard, so no pass starts between.
    pub(crate) async fn hand_off_delivery(
        &self,
        which: Option<&[u32]>,
    ) -> tokio::sync::MutexGuard<'_, Dispatcher> {
        let mut dispatcher = self.dispatcher().lock().await;
        if dispatcher.fences.is_empty() {
            return dispatcher;
        }
        let deadline = tokio::time::Instant::now() + HAND_OFF_TIMEOUT;
        while let Ok(Some(joined)) =
            tokio::time::timeout_at(deadline, dispatcher.tasks.join_next()).await
        {
            if let Ok(outcome) = joined {
                self.apply_outcome(&mut dispatcher, outcome).await;
            }
        }
        self.checkpoint_all(&mut dispatcher, true).await;
        match which {
            Some(shards) => dispatcher.drop_shards(shards),
            None => dispatcher.step_down(),
        }
        dispatcher
    }

    async fn dispatch_pass(self: &Arc<Self>, dispatcher: &mut Dispatcher) {
        let now = now_ms();
        let config = self.config();
        let leases = self.held_shards(now);
        if leases.is_empty() || !config.enabled || !config.webhook.enabled {
            dispatcher.step_down();
            return;
        }
        // A shard lost, or held again under a new fence, starts over from
        // its checkpoints.
        let moved: Vec<u32> = dispatcher
            .fences
            .iter()
            .filter(|(shard, fence)| leases.get(shard).map(|l| l.fence) != Some(**fence))
            .map(|(shard, _)| *shard)
            .collect();
        dispatcher.drop_shards(&moved);
        for (shard, lease) in &leases {
            dispatcher.fences.insert(*shard, lease.fence);
        }
        let (Some(stores), Some(egress), Some(runtime)) =
            (self.stores(), self.egress(), self.runtime())
        else {
            return;
        };
        let runtime = runtime.load_full();

        // What holds every mode holds webhook delivery; a licence that stops
        // covering webhook delivery holds it alone. Each resumes on its own.
        let paused =
            self.delivery_held(&runtime).await || runtime.license_state().events_hold.is_some();
        match (paused, dispatcher.paused_since_ms) {
            (true, None) => dispatcher.paused_since_ms = Some(now),
            (false, Some(since)) => {
                let by = now.saturating_sub(since);
                for sub in dispatcher.subs.values_mut() {
                    sub.shift_retries(by);
                }
                dispatcher.paused_since_ms = None;
            }
            _ => {}
        }

        let stale = self.take_stale();
        let generation = self.generation();
        let catalog = self.catalog();
        let mut live: HashSet<String> = HashSet::new();
        let mut work: Vec<(Arc<EventType>, String)> = Vec::new();
        for ty in catalog.types() {
            if !ty.offers(DeliveryMode::Webhook) {
                continue;
            }
            for id in self.live_ids(&ty.name, now) {
                if !leases.contains_key(&dispatch_shard(&id)) {
                    continue;
                }
                live.insert(id.clone());
                work.push((Arc::clone(ty), id));
            }
        }
        // A subscription whose type the config no longer declares ends: its
        // receiver is told, and its next refresh finds no such type. The
        // index rebuild finds those this dispatcher never loaded.
        for id in self.take_orphans() {
            if leases.contains_key(&dispatch_shard(&id)) {
                self.load_sub(dispatcher, &id, now).await;
            }
        }
        let removed: Vec<String> = dispatcher
            .subs
            .iter()
            .filter(|(_, sub)| catalog.get(&sub.record.name).is_none())
            .map(|(id, _)| id.clone())
            .collect();
        for id in removed {
            let Some(sub) = dispatcher.subs.remove(&id) else {
                continue;
            };
            if sub.record.is_live_at(now) {
                self.terminate(&egress, &config, sub, TerminationReason::TypeRemoved)
                    .await;
            } else if let Err(error) = stores.subscriptions.delete(&id).await {
                tracing::debug!(error = %error, "an ended subscription of a removed type could not be removed");
            }
        }
        // A subscription that was deleted or expired is no longer served;
        // its state needs no checkpoint.
        dispatcher.subs.retain(|id, _| live.contains(id));

        let mut bounds_cache: HashMap<String, Option<super::cursor::LogBounds>> = HashMap::new();
        dispatcher.ended.retain(|id| live.contains(id));
        for (ty, id) in work {
            if dispatcher.ended.contains(&id) && !stale.contains(&id) {
                continue;
            }
            let was_served = dispatcher.subs.contains_key(&id);
            let reload = dispatcher
                .subs
                .get(&id)
                .is_none_or(|sub| now.saturating_sub(sub.loaded_at_ms) >= RECORD_MAX_AGE_MS)
                || stale.contains(&id);
            if reload && !self.load_sub(dispatcher, &id, now).await {
                continue;
            }
            let Some(sub) = dispatcher.subs.get_mut(&id) else {
                continue;
            };
            if let Some(revocation) = sub.record.revoked.clone() {
                let sub = dispatcher.subs.remove(&id).expect("present");
                dispatcher.ended.insert(id.clone());
                if was_served {
                    self.announce_terminated(&egress, &config, &sub, revocation.reason);
                }
                continue;
            }
            // The id was ended before and is live again: a subscription
            // created anew on the same key.
            dispatcher.ended.remove(&id);
            let sub = dispatcher.subs.get_mut(&id).expect("present");
            if !sub.record.is_live_at(now) {
                dispatcher.subs.remove(&id);
                continue;
            }
            if let Some(reason) = self
                .stop_reason(&runtime, &config, &ty, sub, generation, now)
                .await
            {
                let sub = dispatcher.subs.remove(&id).expect("present");
                self.terminate(&egress, &config, sub, reason).await;
                continue;
            }
            let sub = dispatcher.subs.get_mut(&id).expect("present");
            if let Some((at, ended)) = sub.ends_at
                && sub.state.ack_seq.saturating_add(1) >= at
            {
                let sub = dispatcher.subs.remove(&id).expect("present");
                self.terminate(&egress, &config, sub, TerminationReason::Upstream(ended))
                    .await;
                continue;
            }
            if let Some(at) = sub.record.operator_suspended_at_ms
                && sub.record.reactivated_at_ms.is_none_or(|r| r < at)
                && sub.state.counters.suspended_at_ms.is_none_or(|s| s < at)
            {
                sub.state.counters.suspended_at_ms = Some(at);
                sub.dirty = true;
            }
            // A refresh after a suspension resumes delivery.
            if let (Some(suspended), Some(reactivated)) = (
                sub.state.counters.suspended_at_ms,
                sub.record.reactivated_at_ms,
            ) && reactivated > suspended
            {
                sub.state.counters.suspended_at_ms = None;
                sub.state.counters.window_start_ms = now;
                sub.state.counters.window_attempts = 0;
                sub.state.counters.window_failures = 0;
                sub.shift_retries(now.saturating_sub(suspended));
            }
            if let Some(suspended) = sub.state.counters.suspended_at_ms {
                if sub.record.expires_at_ms.is_none()
                    && now.saturating_sub(suspended)
                        >= config.webhook.suspension.drop_no_expiry_after_ms
                {
                    let sub = dispatcher.subs.remove(&id).expect("present");
                    self.terminate(&egress, &config, sub, TerminationReason::Suspended)
                        .await;
                }
                continue;
            }
            if paused {
                continue;
            }
            let bounds = match bounds_cache.get(&ty.source_key) {
                Some(bounds) => *bounds,
                None => {
                    let bounds = stores.log.bounds(&ty.source_key).await.ok();
                    bounds_cache.insert(ty.source_key.clone(), bounds);
                    bounds
                }
            };
            let (Some(bounds), Some(lease)) = (bounds, leases.get(&dispatch_shard(&id)).copied())
            else {
                continue;
            };
            self.schedule(
                dispatcher, &runtime, &ty, &id, bounds, &egress, &config, lease, now,
            )
            .await;
        }
        self.checkpoint_all(dispatcher, false).await;
        let suspended = dispatcher
            .subs
            .values()
            .filter(|s| s.state.counters.suspended_at_ms.is_some())
            .count();
        let active = if paused {
            0
        } else {
            dispatcher.subs.len() - suspended
        };
        metrics::gauge!("mcpg_events_subscriptions", "state" => "active").set(active as f64);
        metrics::gauge!("mcpg_events_subscriptions", "state" => "suspended").set(suspended as f64);
        metrics::gauge!("mcpg_events_subscriptions", "state" => "paused").set(if paused {
            (dispatcher.subs.len() - suspended) as f64
        } else {
            0.0
        });
        metrics::gauge!("mcpg_events_in_flight").set(dispatcher.tasks.len() as f64);
    }

    /// Read the record and delivery state of `id` into the dispatcher.
    /// `false` when it is gone or unreadable now.
    async fn load_sub(&self, dispatcher: &mut Dispatcher, id: &str, now: u64) -> bool {
        let Some(stores) = self.stores() else {
            return false;
        };
        let record = match stores.subscriptions.get(id).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                dispatcher.subs.remove(id);
                return false;
            }
            Err(error) => {
                tracing::debug!(error = %error, "subscription record read failed; retrying next pass");
                return false;
            }
        };
        let mut secrets = Vec::new();
        match stores
            .subscriptions
            .open_secret(id, &record.secret)
            .map(|s| s.signing_secret())
        {
            Some(current) => secrets.push(current),
            None => {
                // Sealed under another key: nothing can be signed until the
                // client's next refresh seals it again.
                tracing::debug!("subscription secret sealed under another key; awaiting a refresh");
                dispatcher.subs.remove(id);
                return false;
            }
        }
        if let Some(previous) = record
            .previous_secret
            .as_ref()
            .and_then(|sealed| stores.subscriptions.open_secret(id, sealed))
            .map(|s| s.signing_secret())
        {
            secrets.push(previous);
        }
        if let Some(sub) = dispatcher.subs.get_mut(id) {
            sub.record = record;
            sub.secrets = secrets;
            sub.loaded_at_ms = now;
            return true;
        }
        let state = match stores.subscriptions.delivery(id).await {
            Ok(Some(state)) => state,
            Ok(None) => DeliveryState {
                v: FORMAT_VERSION,
                id: id.to_owned(),
                epoch: record.start.epoch,
                ack_seq: record.start.after_seq,
                fence: dispatcher
                    .fences
                    .get(&dispatch_shard(id))
                    .copied()
                    .unwrap_or(0),
                in_flight: Vec::new(),
                counters: Default::default(),
                updated_at_ms: now,
            },
            Err(error) => {
                tracing::debug!(error = %error, "delivery state read failed; retrying next pass");
                return false;
            }
        };
        // Everything handed out before the checkpoint and not still in
        // flight was finished.
        let dispatched = state
            .in_flight
            .iter()
            .map(|f| f.seq)
            .max()
            .unwrap_or(0)
            .max(state.ack_seq);
        let in_flight: HashSet<u64> = state.in_flight.iter().map(|f| f.seq).collect();
        let done = (state.ack_seq + 1..=dispatched)
            .filter(|seq| !in_flight.contains(seq))
            .collect();
        let mut sub = Sub {
            record,
            secrets,
            loaded_at_ms: now,
            state,
            done,
            dispatched,
            sending: HashSet::new(),
            dirty: false,
            last_checkpoint_ms: now,
            last_recheck_ms: now,
            rechecked_generation: self.generation(),
            summary: Summary {
                since_ms: now,
                ..Summary::default()
            },
            ends_at: None,
        };
        sub.advance();
        sub.dirty = false;
        dispatcher.subs.insert(id.to_owned(), sub);
        true
    }

    /// Why `sub` must stop for good now, if it must.
    async fn stop_reason(
        &self,
        runtime: &GatewayRuntime,
        config: &EventsConfig,
        ty: &EventType,
        sub: &mut Sub,
        generation: u64,
        now: u64,
    ) -> Option<TerminationReason> {
        if is_revoked(runtime, &sub.record) {
            return Some(TerminationReason::Forbidden(ForbiddenReason::Revoked));
        }
        if ty.schema_epoch != sub.record.schema_epoch {
            return Some(TerminationReason::SchemaChanged);
        }
        let due = sub.rechecked_generation != generation
            || now.saturating_sub(sub.last_recheck_ms) >= config.reauthorize_interval_ms;
        if !due {
            return None;
        }
        sub.last_recheck_ms = now;
        sub.rechecked_generation = generation;
        match subscriber_key(&sub.record.identity, config.webhook.require_trust) {
            Ok(key) if key == sub.record.principal_key => {}
            _ => {
                return Some(TerminationReason::Forbidden(
                    ForbiddenReason::Unauthenticated,
                ));
            }
        }
        let arguments = Value::Object(sub.record.arguments.clone());
        let ctx = recheck_context(&sub.record);
        let key = policy_key(&ty.name);
        let visible = runtime.surface_is_visible(&ctx, &key, PolicyRoute::event(None));
        if !visible {
            return Some(TerminationReason::Forbidden(ForbiddenReason::Policy));
        }
        match runtime
            .recheck_surface(
                "event",
                "event.recheck",
                &key,
                PolicyRoute::event(Some(&arguments)),
                &arguments,
                &ctx,
            )
            .await
        {
            Ok(()) => None,
            Err(reason) => Some(TerminationReason::Forbidden(reason)),
        }
    }

    /// Hand out the deliveries of subscription `id` that are due: retries
    /// whose time came, then rows after the last one handed out.
    #[allow(clippy::too_many_arguments)]
    async fn schedule(
        self: &Arc<Self>,
        dispatcher: &mut Dispatcher,
        runtime: &GatewayRuntime,
        ty: &Arc<EventType>,
        id: &str,
        bounds: super::cursor::LogBounds,
        egress: &Arc<SafeEgress>,
        config: &EventsConfig,
        lease: WriterLease,
        now: u64,
    ) {
        let Some(stores) = self.stores() else {
            return;
        };
        let limits = &config.webhook.limits;
        let attempt_ms = config.webhook.egress.attempt_timeout_ms;
        // A deposed owner must not post past its lease.
        if lease.expires_at_ms < now.saturating_add(attempt_ms) {
            return;
        }
        let Some(sub) = dispatcher.subs.get_mut(id) else {
            return;
        };
        // A lost and re-created log, or rows retention dropped before they
        // were delivered: deliver everything still there, and say what may
        // be missing. A new log holds only rows the subscriber never saw.
        if sub.state.epoch != bounds.epoch || sub.state.ack_seq.saturating_add(1) < bounds.floor {
            let resume_at = bounds.floor.saturating_sub(1);
            sub.state.epoch = bounds.epoch;
            sub.state.ack_seq = resume_at;
            sub.state.in_flight.clear();
            sub.done.clear();
            sub.dispatched = resume_at;
            sub.dirty = true;
            if config
                .webhook
                .control_envelopes
                .contains(&ControlEnvelopeKind::Gap)
            {
                let cursor = self.cursor_for(ty, sub, resume_at);
                let envelope = ControlEnvelope::Gap { cursor };
                let webhook_id = gap_webhook_id(self, &sub.record, bounds.epoch, resume_at);
                self.post_control(egress, &sub.record, &sub.secrets, &webhook_id, &envelope);
            }
            metrics::counter!("mcpg_events_gaps_total", "event" => ty.name.clone()).increment(1);
        }
        let host = sub.record.host.clone();
        let mut host_used = dispatcher.host_in_flight.get(&host).copied().unwrap_or(0);
        let mut started = Vec::new();

        // Retries first: they hold the watermark back.
        let due: Vec<u64> = sub
            .state
            .in_flight
            .iter()
            .filter(|f| f.next_attempt_at_ms <= now && !sub.sending.contains(&f.seq))
            .map(|f| f.seq)
            .collect();
        for seq in due {
            if sub.sending.len() as u64 >= limits.per_subscription_in_flight
                || host_used >= limits.per_host_concurrency
            {
                break;
            }
            match stores.log.get(&ty.source_key, seq).await {
                Ok(Some(LogEntry::Row(row))) => {
                    let Some(outgoing) = Outgoing::of(row.body) else {
                        sub.finish(seq);
                        continue;
                    };
                    if let Some(item) = sub.state.in_flight.iter_mut().find(|f| f.seq == seq) {
                        item.next_attempt_at_ms = now.saturating_add(attempt_ms);
                    }
                    started.push((seq, outgoing));
                    sub.sending.insert(seq);
                    host_used += 1;
                }
                Ok(_) => {
                    // Retention dropped the row while it was retried.
                    sub.finish(seq);
                    metrics::counter!("mcpg_events_abandoned_total", "event" => ty.name.clone(), "reason" => "evicted").increment(1);
                }
                Err(_) => break,
            }
        }

        // New rows, in order. Retries that wait hold no connection, so the
        // retry set has its own bound: a receiver that is down stops new
        // deliveries there, and the rows wait in the log.
        let audience = super::engine::audience_hash(&stores.keys, &sub.record.principal_key);
        let arguments_hash = stores.keys.arguments_hash(&sub.record.arguments);
        while sub.ends_at.is_none()
            && sub.dispatched < bounds.head
            && sub.dispatched.saturating_sub(sub.state.ack_seq) < MAX_WINDOW
            && sub.state.in_flight.len() < MAX_RETRY_SET
            && (sub.sending.len() as u64) < limits.per_subscription_in_flight
            && host_used < limits.per_host_concurrency
        {
            let rows = match stores
                .log
                .read(&ty.source_key, sub.dispatched, READ_BATCH)
                .await
            {
                Ok(rows) => rows,
                Err(_) => break,
            };
            if rows.is_empty() {
                // Every row of this batch is missing: nothing to send there.
                let end = bounds.head.min(sub.dispatched + READ_BATCH as u64);
                for seq in sub.dispatched + 1..=end {
                    sub.done.insert(seq);
                }
                sub.dispatched = end;
                sub.advance();
                continue;
            }
            let mut full = false;
            for entry in rows {
                let seq = entry.seq();
                // Rows the read skipped are gone; they hold nothing back.
                for missing in sub.dispatched + 1..seq {
                    sub.done.insert(missing);
                }
                if (sub.sending.len() as u64) >= limits.per_subscription_in_flight
                    || host_used >= limits.per_host_concurrency
                    || sub.state.in_flight.len() >= MAX_RETRY_SET
                {
                    full = true;
                    break;
                }
                // The end of this subscription's arguments: nothing past it
                // is delivered.
                if let LogEntry::Row(row) = &entry
                    && let Some(reason) = row.body.ends(&audience, &arguments_hash)
                {
                    sub.ends_at = Some((seq, reason));
                    full = true;
                    break;
                }
                sub.dispatched = seq;
                let send = match &entry {
                    LogEntry::Unreadable { .. } => false,
                    LogEntry::Row(row) => match &row.body {
                        RowBody::Event(occurrence) => {
                            // An occurrence meant for one principal, or for
                            // one set of arguments, reaches only those
                            // subscriptions.
                            occurrence.is_for(&audience, &arguments_hash)
                                && ty.matches(
                                    &sub.record.arguments,
                                    occurrence,
                                    &sub.record.identity,
                                )
                        }
                        RowBody::Gap { .. } => {
                            row.body.is_gap_for(&audience, &arguments_hash)
                                && config
                                    .webhook
                                    .control_envelopes
                                    .contains(&ControlEnvelopeKind::Gap)
                        }
                        RowBody::Ended { .. } => false,
                    },
                };
                let outgoing = match entry {
                    LogEntry::Row(row) if send => Outgoing::of(row.body),
                    _ => None,
                };
                let Some(outgoing) = outgoing else {
                    sub.done.insert(seq);
                    continue;
                };
                sub.state.in_flight.push(InFlight {
                    seq,
                    attempts: 0,
                    first_attempt_at_ms: now,
                    next_attempt_at_ms: now.saturating_add(attempt_ms),
                });
                sub.sending.insert(seq);
                host_used += 1;
                started.push((seq, outgoing));
            }
            sub.advance();
            if full {
                break;
            }
        }
        if started.is_empty() {
            return;
        }
        let Ok(url) = egress.check_url(&sub.record.url) else {
            // The callback is refused by the policy now in force: every
            // attempt fails as a refused connection.
            dispatcher.host_in_flight.insert(host.clone(), host_used);
            for (seq, outgoing) in started {
                let (webhook_id, control) = match &outgoing {
                    Outgoing::Event(occurrence) => (occurrence.event_id.clone(), false),
                    Outgoing::Gap => (String::new(), true),
                };
                dispatcher.tasks.spawn(std::future::ready(Outcome {
                    id: id.to_owned(),
                    seq,
                    webhook_id,
                    host: host.clone(),
                    category: Some(DeliveryErrorCategory::ConnectionRefused),
                    status: None,
                    retry_after_ms: None,
                    control,
                    bytes: 0,
                    unsignable: false,
                    builtin: ty.is_builtin(),
                }));
            }
            metrics::counter!("mcpg_events_egress_blocked_total").increment(1);
            return;
        };
        let scope = CursorScope::new(&ty.source_key, &Value::Object(sub.record.arguments.clone()));
        let secrets: Vec<WhsecSecret> = sub.signing_keys(now).into_iter().cloned().collect();
        for (seq, outgoing) in started {
            let gated = match &outgoing {
                Outgoing::Event(occurrence) => {
                    gate_payload(runtime.plugin_registry(), &sub.record, &occurrence.data).await
                }
                Outgoing::Gap => Some(Value::Null),
            };
            let Some(gated) = gated else {
                // A refused payload is given up on, and the receiver is told
                // events were skipped.
                sub.sending.remove(&seq);
                sub.finish(seq);
                host_used = host_used.saturating_sub(1);
                metrics::counter!("mcpg_events_payload_blocked_total", "event" => ty.name.clone())
                    .increment(1);
                if config
                    .webhook
                    .control_envelopes
                    .contains(&ControlEnvelopeKind::Gap)
                {
                    let envelope = ControlEnvelope::Gap {
                        cursor: self.cursor_for(ty, sub, seq),
                    };
                    let webhook_id = gap_webhook_id(self, &sub.record, sub.state.epoch, seq);
                    self.post_control(egress, &sub.record, &sub.secrets, &webhook_id, &envelope);
                }
                if let Outgoing::Event(occurrence) = &outgoing {
                    self.audit_abandoned(&sub.record, &occurrence.event_id, "payload_blocked")
                        .await;
                }
                continue;
            };
            let (webhook_id, body, control) = match &outgoing {
                Outgoing::Event(occurrence) => {
                    // The cursor never passes an event still awaiting delivery.
                    let cursor_seq = if sub.state.ack_seq.saturating_add(1) >= seq {
                        seq
                    } else {
                        sub.state.ack_seq
                    };
                    let cursor = (ty.replay == EventReplay::Log).then(|| {
                        stores
                            .log
                            .seal_cursor(sub.state.epoch, ty.schema_epoch, cursor_seq, &scope)
                    });
                    let body = EventOccurrence {
                        event_id: occurrence.event_id.clone(),
                        name: ty.name.clone(),
                        timestamp: occurrence.timestamp.clone(),
                        data: gated,
                        cursor,
                        meta: None,
                    };
                    (
                        occurrence.event_id.clone(),
                        serde_json::to_vec(&body),
                        false,
                    )
                }
                Outgoing::Gap => {
                    let cursor = self.cursor_for(ty, sub, seq);
                    (
                        gap_webhook_id(self, &sub.record, sub.state.epoch, seq),
                        serde_json::to_vec(&ControlEnvelope::Gap { cursor }),
                        true,
                    )
                }
            };
            let body = match body {
                Ok(body) if body.len() <= MAX_WEBHOOK_BODY_BYTES => body,
                _ => {
                    sub.sending.remove(&seq);
                    sub.finish(seq);
                    host_used = host_used.saturating_sub(1);
                    metrics::counter!("mcpg_events_abandoned_total", "event" => ty.name.clone(), "reason" => "too_large").increment(1);
                    continue;
                }
            };
            let egress = Arc::clone(egress);
            let url = url.clone();
            let secrets = secrets.clone();
            let id = id.to_owned();
            let host = host.clone();
            let builtin = ty.is_builtin();
            metrics::counter!("mcpg_events_attempts_total", "event" => ty.name.clone())
                .increment(1);
            dispatcher.tasks.spawn(async move {
                let keys: Vec<&WhsecSecret> = secrets.iter().collect();
                let bytes = body.len() as u64;
                let attempt = SignedPost {
                    egress: &egress,
                    url: &url,
                    subscription_id: &id,
                    secrets: &keys,
                    webhook_id: &webhook_id,
                    body: Bytes::from(body),
                }
                .send(now_ms() / 1_000)
                .await;
                Outcome {
                    id,
                    seq,
                    webhook_id,
                    host,
                    category: attempt.category(),
                    status: attempt.status(),
                    retry_after_ms: retry_after_ms(&attempt),
                    control,
                    bytes,
                    unsignable: matches!(attempt, Attempt::Unsignable),
                    builtin,
                }
            });
        }
        dispatcher.host_in_flight.insert(host, host_used);
    }

    /// The sealed cursor of `seq` for `sub`, `None` for a type without
    /// replay.
    fn cursor_for(&self, ty: &EventType, sub: &Sub, seq: u64) -> Option<String> {
        if ty.replay != EventReplay::Log {
            return None;
        }
        let stores = self.stores()?;
        let scope = CursorScope::new(&ty.source_key, &Value::Object(sub.record.arguments.clone()));
        Some(
            stores
                .log
                .seal_cursor(sub.state.epoch, ty.schema_epoch, seq, &scope),
        )
    }

    /// Send a control envelope once, without waiting for it.
    fn post_control(
        &self,
        egress: &Arc<SafeEgress>,
        record: &SubscriptionRecord,
        secrets: &[WhsecSecret],
        webhook_id: &str,
        envelope: &ControlEnvelope,
    ) {
        let Ok(url) = egress.check_url(&record.url) else {
            return;
        };
        let Ok(body) = serde_json::to_vec(envelope) else {
            return;
        };
        let egress = Arc::clone(egress);
        let secrets = secrets.to_vec();
        let id = record.id.clone();
        let webhook_id = webhook_id.to_owned();
        let kind = envelope.kind();
        tokio::spawn(async move {
            let keys: Vec<&WhsecSecret> = secrets.iter().take(1).collect();
            let attempt = SignedPost {
                egress: &egress,
                url: &url,
                subscription_id: &id,
                secrets: &keys,
                webhook_id: &webhook_id,
                body: Bytes::from(body),
            }
            .send(now_ms() / 1_000)
            .await;
            metrics::counter!("mcpg_events_control_envelopes_total", "kind" => kind, "outcome" => attempt.outcome_label())
                .increment(1);
        });
    }

    /// Apply what one attempt reported.
    async fn apply_outcome(&self, dispatcher: &mut Dispatcher, outcome: Outcome) {
        dispatcher.release_host(&outcome.host);
        let config = self.config();
        let now = now_ms();
        let audit_every = config.audit.deliveries == DeliveryAuditMode::Every;
        let Some(sub) = dispatcher.subs.get_mut(&outcome.id) else {
            return;
        };
        sub.sending.remove(&outcome.seq);
        // An unsignable id never reached the receiver, so it says nothing
        // about the receiver's health and counts toward no suspension.
        if !outcome.unsignable {
            let counters = &mut sub.state.counters;
            if now.saturating_sub(counters.window_start_ms) >= config.webhook.suspension.window_ms {
                counters.window_start_ms = now;
                counters.window_attempts = 0;
                counters.window_failures = 0;
            }
            counters.window_attempts += 1;
            match outcome.category {
                None => {
                    counters.last_delivery_at_ms = Some(now);
                    counters.failed_since_ms = None;
                    counters.last_error = None;
                }
                Some(category) => {
                    counters.window_failures += 1;
                    counters.last_error = Some(category);
                    counters.failed_since_ms.get_or_insert(now);
                }
            }
        }
        let name = sub.record.name.clone();
        let started = sub
            .state
            .in_flight
            .iter()
            .find(|f| f.seq == outcome.seq)
            .map(|f| f.first_attempt_at_ms);
        let mut abandoned: Option<&'static str> = None;
        match outcome.category {
            None => {
                sub.finish(outcome.seq);
                sub.summary.delivered += 1;
                if !outcome.control {
                    metrics::counter!(
                        "mcpg_events_delivered_total",
                        "event" => name.clone(),
                        "mode" => DeliveryMode::Webhook.as_str()
                    )
                    .increment(1);
                }
                if let Some(started) = started {
                    metrics::histogram!(
                        "mcpg_events_delivery_latency_seconds",
                        "event" => name.clone()
                    )
                    .record(now.saturating_sub(started) as f64 / 1_000.0);
                }
            }
            Some(_) if outcome.unsignable => {
                tracing::warn!(
                    event = %name,
                    "event id is no valid webhook-id; the event is abandoned"
                );
                abandoned = Some(UNSIGNABLE_ID);
            }
            Some(category) => {
                sub.summary.failed += 1;
                let retry = &config.webhook.retry;
                if matches!(outcome.status, Some(410) | Some(413)) {
                    abandoned = Some(if outcome.status == Some(410) {
                        "gone"
                    } else {
                        "too_large"
                    });
                } else if let Some(item) = sub
                    .state
                    .in_flight
                    .iter_mut()
                    .find(|f| f.seq == outcome.seq)
                {
                    item.attempts += 1;
                    let window_ms = self.plan().retry_window_ms(retry.window_ms);
                    let window_end = item.first_attempt_at_ms.saturating_add(window_ms);
                    let mut wait = backoff_ms(item.attempts, window_ms);
                    if retry.honor_retry_after
                        && let Some(asked) = outcome.retry_after_ms
                    {
                        wait = wait.max(asked);
                    }
                    let next = now.saturating_add(wait);
                    if u64::from(item.attempts) >= retry.max_attempts || next >= window_end {
                        abandoned = Some("exhausted");
                    } else {
                        item.next_attempt_at_ms = next;
                        metrics::counter!("mcpg_events_retried_total", "event" => name.clone(), "category" => category.as_str())
                            .increment(1);
                    }
                }
            }
        }
        if let Some(reason) = abandoned {
            sub.finish(outcome.seq);
            sub.summary.abandoned += 1;
            metrics::counter!("mcpg_events_abandoned_total", "event" => name.clone(), "reason" => reason)
                .increment(1);
        }
        // The usage report: an event counts once, when acknowledged or
        // given up; a retry adds nothing.
        let delivered = outcome.category.is_none();
        if !outcome.control
            && (delivered || abandoned.is_some())
            && let Some(runtime) = self.runtime()
        {
            let billable = if outcome.builtin {
                0
            } else {
                u64::from(delivered)
            };
            runtime.load().tool_call_recorder.record_event_usage(
                &name,
                DeliveryMode::Webhook.as_str(),
                billable,
                u64::from(abandoned.is_some()),
                if delivered { outcome.bytes } else { 0 },
            );
        }
        sub.dirty = true;
        let suspend = {
            let counters = &sub.state.counters;
            let suspension = &config.webhook.suspension;
            counters.suspended_at_ms.is_none()
                && counters.window_attempts >= suspension.min_attempts
                && (counters.window_failures as f64)
                    > suspension.failure_rate.0 * counters.window_attempts as f64
        };
        if suspend {
            sub.state.counters.suspended_at_ms = Some(now);
            metrics::counter!("mcpg_events_suspended_total", "event" => name.clone()).increment(1);
            tracing::info!(event = %name, "event subscription suspended after repeated delivery failures");
        }
        let record = sub.record.clone();
        let event_id = outcome.webhook_id.clone();
        if suspend {
            self.checkpoint_one(dispatcher, &outcome.id, now).await;
        }
        if let Some(reason) = abandoned {
            self.audit_abandoned(&record, &event_id, reason).await;
        }
        if audit_every {
            self.audit_delivery(
                &record,
                serde_json::json!({
                    "seq": outcome.seq,
                    "outcome": if outcome.unsignable {
                        UNSIGNABLE_ID
                    } else {
                        outcome.category.map_or("accepted", |c| c.as_str())
                    },
                    "status": outcome.status,
                }),
            )
            .await;
        }
    }

    /// Write the delivery state of every changed subscription whose last
    /// checkpoint is old enough, or of every changed one when `all`.
    async fn checkpoint_all(&self, dispatcher: &mut Dispatcher, all: bool) {
        let now = now_ms();
        let due: Vec<String> = dispatcher
            .subs
            .iter()
            .filter(|(_, s)| {
                s.dirty
                    && (all || now.saturating_sub(s.last_checkpoint_ms) >= CHECKPOINT_INTERVAL_MS)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            self.checkpoint_one(dispatcher, &id, now).await;
        }
        let summarize = self.config().audit.deliveries == DeliveryAuditMode::Summary;
        if summarize {
            let mut records = Vec::new();
            for sub in dispatcher.subs.values_mut() {
                let summary = sub.summary;
                if now.saturating_sub(summary.since_ms) >= SUMMARY_INTERVAL_MS
                    && summary.delivered + summary.failed + summary.abandoned > 0
                {
                    records.push((sub.record.clone(), summary));
                    sub.summary = Summary {
                        since_ms: now,
                        ..Summary::default()
                    };
                }
            }
            for (record, summary) in records {
                self.audit_delivery(
                    &record,
                    serde_json::json!({
                        "window_ms": now.saturating_sub(summary.since_ms),
                        "delivered": summary.delivered,
                        "failed": summary.failed,
                        "abandoned": summary.abandoned,
                    }),
                )
                .await;
            }
        }
    }

    /// Write the delivery state of `id` under this owner's fence. A state
    /// written by a newer owner means this one was deposed: it stops.
    async fn checkpoint_one(&self, dispatcher: &mut Dispatcher, id: &str, now: u64) {
        let Some(stores) = self.stores() else {
            return;
        };
        let shard = dispatch_shard(id);
        let Some(lease) = self.shard_lease(shard).filter(|l| l.expires_at_ms > now) else {
            dispatcher.drop_shards(&[shard]);
            return;
        };
        // A higher fence on a recent checkpoint is a newer holder of the
        // shard; on an old one it is from before a coordinator restart.
        if let Ok(Some(stored)) = stores.subscriptions.delivery(id).await
            && stored.fence > lease.fence
            && now.saturating_sub(stored.updated_at_ms) < OWNER_LEASE_TTL.as_millis() as u64
        {
            tracing::info!(
                shard,
                "a newer holder of this subscription's shard delivers it; this replica stops"
            );
            dispatcher.drop_shards(&[shard]);
            return;
        }
        let Some(sub) = dispatcher.subs.get_mut(id) else {
            return;
        };
        sub.state.fence = lease.fence;
        sub.state.updated_at_ms = now;
        match stores
            .subscriptions
            .put_delivery(&sub.state, sub.record.expires_at_ms)
            .await
        {
            Ok(()) => {
                sub.dirty = false;
                sub.last_checkpoint_ms = now;
            }
            Err(error) => {
                tracing::debug!(error = %error, "delivery checkpoint failed; retrying");
            }
        }
    }

    /// Stop `sub` for good: tombstone the record until its grant ends, drop
    /// its retries, and tell the receiver when configured.
    async fn terminate(
        &self,
        egress: &Arc<SafeEgress>,
        config: &EventsConfig,
        sub: Sub,
        reason: TerminationReason,
    ) {
        let Some(stores) = self.stores() else {
            return;
        };
        let now = now_ms();
        let mut record = sub.record;
        record.revoked = Some(Revocation { at_ms: now, reason });
        // A tombstone lives until the grant ends; a grant with no expiry
        // would keep it forever, so that record goes at once. A removed
        // type needs none: a refresh finds no such type. Nor does one an
        // upstream ended: a refresh subscribes anew and asks the upstream
        // again.
        let tombstoned = record.expires_at_ms.is_some()
            && !matches!(
                reason,
                TerminationReason::TypeRemoved | TerminationReason::Upstream(_)
            );
        let written = if tombstoned {
            stores.subscriptions.replace(&record).await
        } else {
            stores.subscriptions.delete(&record.id).await.map(|_| ())
        };
        if let Err(error) = written {
            tracing::warn!(error = %error, "terminated subscription could not be tombstoned");
        }
        let mut state = sub.state.clone();
        state.in_flight.clear();
        state.updated_at_ms = now;
        if tombstoned {
            let _ = stores
                .subscriptions
                .put_delivery(&state, record.expires_at_ms)
                .await;
        }
        let ended = Sub {
            record,
            state,
            ..sub
        };
        self.announce_terminated(egress, config, &ended, reason);
        self.audit_terminated(&ended.record, reason.label()).await;
    }

    /// Tell the receiver of `sub` that it ended, when configured.
    fn announce_terminated(
        &self,
        egress: &Arc<SafeEgress>,
        config: &EventsConfig,
        sub: &Sub,
        reason: TerminationReason,
    ) {
        metrics::counter!("mcpg_events_terminated_total", "event" => sub.record.name.clone(), "reason" => reason.label())
            .increment(1);
        if !config
            .webhook
            .control_envelopes
            .contains(&ControlEnvelopeKind::Terminated)
        {
            return;
        }
        let envelope = ControlEnvelope::Terminated {
            error: reason
                .error(sub.state.counters.last_error)
                .numbered(config.error_codes.numbering())
                .to_error_body(),
        };
        let webhook_id = envelope.webhook_id(&random_token(CONTROL_ID_BYTES));
        self.post_control(egress, &sub.record, &sub.secrets, &webhook_id, &envelope);
    }
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
