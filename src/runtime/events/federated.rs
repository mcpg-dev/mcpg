//! The source of an event type a federation imported.
//!
//! One upstream subscription runs per key of demand: per set of arguments
//! in demand and, with `per_principal` sharing, per subscriber too. The
//! demand is that of the type's live webhook subscriptions and of its live
//! poll and stream leases. Each upstream subscription reads the upstream in
//! the type's mode: a webhook subscription that delivers to this gateway,
//! an `events/stream`, or an `events/poll` loop. Its connection carries the
//! federation's catalogue credential or, under `per_principal`, the
//! subscriber's own, minted from their stored sign-in. What it reads is
//! tagged with the keyed hashes of its arguments and subscriber, so only
//! those readers receive it.
//!
//! Each keeps its own resume position, the upstream cursor, under its id,
//! and marks its own gaps: a restart with no cursor to resume from, an
//! upstream that reports events it no longer has, or a schema change
//! upstream. When the upstream ends the subscription for good (forbidden,
//! no such type, arguments refused), the end goes in the log too, and every
//! subscription of those readers ends there.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::catalog::{EventType, SourceSpec, UpstreamMode};
use super::engine::{EventsCore, audience_hash};
use super::keys::EventsKeys;
use super::log::{EndReason, GapReason, RowScope};
use super::occurrence::RawOccurrence;
use super::sources::{SourceContext, SourceItem};
use super::upstream_webhook::{ROUTE_ABANDONED_TTL, UPSTREAM_WEBHOOK_PATH, UpstreamRoute};
use crate::config::federation::UpstreamEventSharing;
use crate::protocol::shared::error::INVALID_PARAMS_CODE;
use crate::protocol::v_2026_07_28::extensions::events::errors::{
    EventsErrorData, REASON_SCHEMA_CHANGED,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    DeliveryMode, EventOccurrence, PollEventsParams, StreamEventsParams, StreamFrame,
    SubscribeEventsParams, TtlRequest, UnsubscribeDelivery, UnsubscribeEventsParams,
    WebhookDelivery,
};
use crate::runtime::RequestIdentity;
use crate::runtime::federation::upstream::{McpUpstream, UpstreamError};

/// How often the demand of a type is read.
const DEMAND_TICK: Duration = Duration::from_secs(2);
/// First wait after a failed upstream read; it doubles up to
/// [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Wait after the upstream refused or ended the subscription: that changes
/// only when its catalogue or its grants do.
const REFUSED_BACKOFF: Duration = Duration::from_secs(300);
/// Bounds of the wait between two upstream polls.
const MIN_UPSTREAM_POLL: Duration = Duration::from_secs(1);
const MAX_UPSTREAM_POLL: Duration = Duration::from_secs(60);
/// A poll loop reconnects after this long, so a credential with a short
/// life is renewed.
const RECONNECT_AFTER: Duration = Duration::from_secs(600);
/// Least time between two positions taken from a heartbeat or a poll
/// without events.
const POSITION_INTERVAL: Duration = Duration::from_secs(60);
/// How often an upstream webhook subscription checks its route for an end
/// the receiver saw.
const WEBHOOK_CHECK: Duration = Duration::from_secs(30);
/// Bounds of the wait before an upstream webhook subscription is refreshed.
const MIN_REFRESH: Duration = Duration::from_secs(60);
const MAX_REFRESH: Duration = Duration::from_secs(3_600);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Who an upstream subscription of a `per_principal` type is held for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Subscriber {
    pub principal_key: String,
    pub identity: RequestIdentity,
}

/// What one upstream subscription is held for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Demand {
    pub arguments: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscriber: Option<Subscriber>,
}

/// A poll or a stream that holds a lease, as its demand sees it.
pub(crate) struct LeaseHolder<'a> {
    pub principal_key: &'a str,
    pub identity: &'a RequestIdentity,
    pub arguments: &'a Map<String, Value>,
}

impl Demand {
    /// The demand of `holder` on a type shared by `sharing`.
    pub(crate) fn of(sharing: UpstreamEventSharing, holder: &LeaseHolder<'_>) -> Self {
        Self {
            arguments: holder.arguments.clone(),
            subscriber: (sharing == UpstreamEventSharing::PerPrincipal).then(|| Subscriber {
                principal_key: holder.principal_key.to_owned(),
                identity: holder.identity.clone(),
            }),
        }
    }

    /// The keyed hash of the principal it serves alone, if any.
    fn audience(&self, keys: &EventsKeys) -> Option<String> {
        self.subscriber
            .as_ref()
            .map(|subscriber| audience_hash(keys, &subscriber.principal_key))
    }

    /// Its key among the demand of one type: one upstream subscription
    /// serves each key.
    pub(crate) fn key(&self, keys: &EventsKeys) -> String {
        let arguments = keys.arguments_hash(&self.arguments);
        match self.audience(keys) {
            Some(audience) => format!("{audience}.{arguments}"),
            None => arguments,
        }
    }
}

/// A running upstream subscription.
struct Running {
    /// Stops it.
    cancel: CancellationToken,
    /// Asks it, as it stops, to end the upstream subscription too: its
    /// demand is gone, not just this replica's turn as the owner.
    retire: CancellationToken,
    last_demand_ms: u64,
    /// When its presence row was last written; `0` before the first.
    presence_at_ms: u64,
}

/// How long the presence row of an upstream subscription lasts unless
/// written again, and how often a running one writes it while the plan caps
/// readers: the cap counts the rows.
const PRESENCE_TTL: Duration = Duration::from_secs(90);
const PRESENCE_REFRESH: Duration = Duration::from_secs(30);

/// Run the upstream subscriptions of `ty` that its demand asks for, until
/// `cancel`.
pub(super) async fn run(
    ty: &Arc<EventType>,
    ctx: &SourceContext,
    tx: mpsc::Sender<SourceItem>,
    cancel: &CancellationToken,
) {
    let SourceSpec::Federation {
        federation,
        upstream_name,
        mode,
        sharing,
    } = &ty.source
    else {
        return;
    };
    let mut running: HashMap<String, Running> = HashMap::new();
    let mut known: HashMap<String, (String, Demand)> = HashMap::new();
    let mut tick = tokio::time::interval(DEMAND_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tick.tick() => {}
        }
        let Some(core) = ctx.core.upgrade() else {
            break;
        };
        let Some(stores) = core.stores() else {
            break;
        };
        let now = now_ms();
        let linger_ms = core.config().sources.linger_ms;
        let demand = demand_of(&core, ty, *sharing, &mut known, now).await;
        drop(core);
        for (key, wanted) in &demand {
            if let Some(running) = running.get_mut(key) {
                running.last_demand_ms = now;
                continue;
            }
            let child = CancellationToken::new();
            let retire = CancellationToken::new();
            let subscription = UpstreamSubscription::new(
                ty,
                federation,
                upstream_name,
                wanted,
                &stores.keys,
                tx.clone(),
            );
            tokio::spawn(read(
                subscription,
                ctx.clone(),
                *mode,
                child.clone(),
                retire.clone(),
            ));
            running.insert(
                key.clone(),
                Running {
                    cancel: child,
                    retire,
                    last_demand_ms: now,
                    presence_at_ms: 0,
                },
            );
            tracing::info!(event = %ty.name, federation = %federation, "upstream event subscription started");
        }
        let mut stopped = Vec::new();
        running.retain(|key, running| {
            let keep =
                demand.contains_key(key) || now.saturating_sub(running.last_demand_ms) <= linger_ms;
            if !keep {
                running.retire.cancel();
                running.cancel.cancel();
                stopped.push(key.clone());
                tracing::debug!(event = %ty.name, "upstream event subscription stopped: no demand");
            }
            keep
        });
        for key in stopped {
            let _ = stores.leases.drop_upstream(&ty.name, &key).await;
        }
        if ctx.plan().readers_limit.is_some() {
            for (key, running) in &mut running {
                if now.saturating_sub(running.presence_at_ms) >= PRESENCE_REFRESH.as_millis() as u64
                    && stores
                        .leases
                        .put_upstream(&ty.name, key, PRESENCE_TTL)
                        .await
                        .is_ok()
                {
                    running.presence_at_ms = now;
                }
            }
        }
        metrics::gauge!("mcpg_events_upstream_subscriptions", "event" => ty.name.clone())
            .set(running.len() as f64);
    }
    // The source stops when its type lost all demand, while the plan holds
    // the sources, when this replica stops owning the logs, or on a reload.
    // The first two end the upstream subscriptions: a held one subscribes
    // again from its stored cursor once the hold ends. The others hand them
    // on.
    let remaining = match ctx.core.upgrade() {
        Some(core) if core.is_owner() && core.ingest_held() => Some(HashMap::new()),
        Some(core) if core.is_owner() => {
            Some(demand_of(&core, ty, *sharing, &mut known, now_ms()).await)
        }
        _ => None,
    };
    // A subscription handed on keeps its presence row: the next owner, or the
    // next run after a reload, writes the same key, and its TTL clears it
    // otherwise.
    let stores = ctx.core.upgrade().and_then(|core| core.stores());
    for (key, running) in running.drain() {
        let retired = remaining
            .as_ref()
            .is_some_and(|demand| !demand.contains_key(&key));
        if retired {
            running.retire.cancel();
        }
        running.cancel.cancel();
        if retired && let Some(stores) = &stores {
            let _ = stores.leases.drop_upstream(&ty.name, &key).await;
        }
    }
    metrics::gauge!("mcpg_events_upstream_subscriptions", "event" => ty.name.clone()).set(0.0);
}

/// The demand of `ty` at `now`, by key: that of its live webhook
/// subscriptions and of its live poll and stream leases. `known` keeps
/// the demand of each subscription read so far.
async fn demand_of(
    core: &EventsCore,
    ty: &EventType,
    sharing: UpstreamEventSharing,
    known: &mut HashMap<String, (String, Demand)>,
    now: u64,
) -> HashMap<String, Demand> {
    let Some(stores) = core.stores() else {
        return HashMap::new();
    };
    let per_principal = sharing == UpstreamEventSharing::PerPrincipal;
    let ids: HashSet<String> = core.live_ids(&ty.name, now).into_iter().collect();
    known.retain(|id, _| ids.contains(id));
    for id in &ids {
        if known.contains_key(id) {
            continue;
        }
        match stores.subscriptions.get(id).await {
            Ok(Some(record)) => {
                let demand = Demand {
                    arguments: record.arguments,
                    subscriber: per_principal.then_some(Subscriber {
                        principal_key: record.principal_key,
                        identity: record.identity,
                    }),
                };
                known.insert(id.clone(), (demand.key(&stores.keys), demand));
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(event = %ty.name, error = %error, "a subscription could not be read for its demand");
            }
        }
    }
    let mut demand: HashMap<String, Demand> = known.values().cloned().collect();
    match stores.leases.argument_demand(&ty.name, now).await {
        Ok(leased) => {
            for mut wanted in leased.into_values() {
                if per_principal && wanted.subscriber.is_none() {
                    continue;
                }
                if !per_principal {
                    wanted.subscriber = None;
                }
                demand.insert(wanted.key(&stores.keys), wanted);
            }
        }
        Err(error) => {
            tracing::debug!(event = %ty.name, error = %error, "lease demand could not be read");
        }
    }
    demand
}

/// What an upstream error means for the subscription it answers.
pub(super) enum Refusal {
    /// The type's schema changed upstream: the cursor is of no use now.
    SchemaChanged,
    /// The upstream ended the subscription for good.
    End(EndReason),
    /// Anything else: retry.
    Other,
}

impl Refusal {
    /// Classify JSON-RPC error `code` with `data`, in either numbering.
    pub(super) fn of(code: i32, data: Option<&Value>) -> Self {
        match EventsErrorData::parse(code, data) {
            Some(EventsErrorData::Unsupported(unsupported))
                if unsupported.reason.as_deref() == Some(REASON_SCHEMA_CHANGED) =>
            {
                Self::SchemaChanged
            }
            Some(EventsErrorData::Forbidden(_)) => Self::End(EndReason::Forbidden),
            Some(EventsErrorData::NotFound(_)) => Self::End(EndReason::NotFound),
            _ if code == INVALID_PARAMS_CODE => Self::End(EndReason::ArgumentsRefused),
            _ => Self::Other,
        }
    }
}

/// How one read of the upstream ended.
enum Ended {
    /// The subscription is no longer wanted, or its queue is gone.
    Cancelled,
    /// The upstream closed the stream, or a reconnect is due.
    Closed,
    /// The read failed; another may succeed.
    Failed(String),
    /// The upstream refused the subscription for now.
    Refused(String),
    /// The upstream ended the subscription of these readers; so do the
    /// subscriptions it serves.
    Terminated(EndReason),
    /// The upstream ended the webhook subscription, and the receiver
    /// already recorded what that means for its readers.
    Gone,
    /// The type's schema changed upstream.
    SchemaChanged,
}

impl Ended {
    fn of(error: UpstreamError) -> Self {
        if let UpstreamError::NotLinked { .. } = error {
            return Self::Refused("the subscriber has no stored sign-in".to_owned());
        }
        // A 429 is the upstream's request ceiling, which clears within
        // seconds: a failure to retry soon, not a refusal to wait out.
        if let UpstreamError::Http { status: 429, .. } = error {
            return Self::Failed(error.to_string());
        }
        match error.jsonrpc_code() {
            // JSON-RPC codes are 32-bit; a wider one is no code this side
            // knows.
            Some(code) => match i32::try_from(code) {
                Ok(code) => Self::answered(code, error.jsonrpc_data()),
                Err(_) => Self::Refused(format!("upstream error {code}")),
            },
            None => Self::Failed(error.to_string()),
        }
    }

    /// The upstream answered with JSON-RPC error `code` and `data`.
    fn answered(code: i32, data: Option<&Value>) -> Self {
        match Refusal::of(code, data) {
            Refusal::SchemaChanged => Self::SchemaChanged,
            Refusal::End(reason) => Self::Terminated(reason),
            Refusal::Other => Self::Refused(format!("upstream error {code}")),
        }
    }
}

/// One upstream subscription and where it stands.
struct UpstreamSubscription {
    ty: Arc<EventType>,
    /// The federation: the namespace of the event ids it reports, so ids
    /// two upstreams chose alike stay apart.
    federation: String,
    upstream_name: String,
    arguments: Map<String, Value>,
    subscriber: Option<Subscriber>,
    /// The keyed hashes of the readers it serves.
    scope: RowScope,
    /// Its id: the slot of its position, and the route of its callback.
    id: String,
    /// The upstream cursor to read on from; `None` reads from now.
    cursor: Option<String>,
    /// When it last queued a position.
    positioned_at: Option<Instant>,
    /// The callback of the webhook subscription this gateway made upstream.
    callback: Option<String>,
    tx: mpsc::Sender<SourceItem>,
}

impl UpstreamSubscription {
    fn new(
        ty: &Arc<EventType>,
        federation: &str,
        upstream_name: &str,
        demand: &Demand,
        keys: &EventsKeys,
        tx: mpsc::Sender<SourceItem>,
    ) -> Self {
        let arguments = keys.arguments_hash(&demand.arguments);
        let audience = demand.audience(keys);
        let id = keys.upstream_subscription_id(
            federation,
            upstream_name,
            audience.as_deref(),
            &arguments,
        );
        Self {
            ty: Arc::clone(ty),
            federation: federation.to_owned(),
            upstream_name: upstream_name.to_owned(),
            arguments: demand.arguments.clone(),
            subscriber: demand.subscriber.clone(),
            scope: RowScope::of(audience, arguments),
            id,
            cursor: None,
            positioned_at: None,
            callback: None,
            tx,
        }
    }

    /// Take the stored position, or start from now. One that ran before
    /// and has no cursor to resume from marks a gap.
    async fn resume(&mut self, ctx: &SourceContext) -> bool {
        match ctx
            .log
            .resume_position(&self.ty.source_key, Some(&self.id))
            .await
        {
            Ok(Some(Value::String(cursor))) => {
                self.cursor = Some(cursor);
                true
            }
            Ok(Some(_)) => self.gap(GapReason::SourceRestart).await,
            Ok(None) => {
                self.send(SourceItem::Position {
                    slot: Some(self.id.clone()),
                    cursor: Value::Null,
                })
                .await
            }
            Err(error) => {
                tracing::warn!(event = %self.ty.name, error = %error, "could not read the position of an upstream subscription");
                self.gap(GapReason::SourceRestart).await
            }
        }
    }

    async fn send(&self, item: SourceItem) -> bool {
        self.tx.send(item).await.is_ok()
    }

    async fn gap(&self, reason: GapReason) -> bool {
        self.send(SourceItem::Gap {
            reason,
            scope: self.scope.clone(),
        })
        .await
    }

    /// End every subscription of these readers, and forget the position:
    /// a later upstream subscription starts from now.
    async fn end(&self, reason: EndReason) -> bool {
        self.send(SourceItem::End {
            reason,
            scope: self.scope.clone(),
        })
        .await
            && self
                .send(SourceItem::Position {
                    slot: Some(self.id.clone()),
                    cursor: Value::Null,
                })
                .await
    }

    /// Queue `occurrence` for the log; its cursor is stored once it is
    /// appended.
    async fn occurrence(&mut self, occurrence: EventOccurrence) -> bool {
        if occurrence.cursor.is_some() {
            self.cursor.clone_from(&occurrence.cursor);
            self.positioned_at = Some(Instant::now());
        }
        self.send(SourceItem::Occurrence(RawOccurrence {
            event_id: Some(format!("{}:{}", self.federation, occurrence.event_id)),
            timestamp: Some(occurrence.timestamp),
            data: occurrence.data,
            audience: self.scope.audience.clone(),
            arguments: self.scope.arguments.clone(),
            upstream_cursor: occurrence.cursor.map(Value::String),
        }))
        .await
    }

    /// The upstream is at `cursor` with no event to report: read on from
    /// it, and store it now and then.
    async fn at(&mut self, cursor: Option<String>) -> bool {
        let Some(cursor) = cursor else {
            return true;
        };
        self.cursor = Some(cursor.clone());
        if self
            .positioned_at
            .is_some_and(|at| at.elapsed() < POSITION_INTERVAL)
        {
            return true;
        }
        self.positioned_at = Some(Instant::now());
        self.send(SourceItem::Position {
            slot: Some(self.id.clone()),
            cursor: Value::String(cursor),
        })
        .await
    }

    /// Read one `events/stream` until it ends.
    async fn stream(&mut self, upstream: &dyn McpUpstream, cancel: &CancellationToken) -> Ended {
        let resumed = self.cursor.is_some();
        let params = StreamEventsParams {
            name: self.upstream_name.clone(),
            arguments: self.arguments.clone(),
            cursor: self.cursor.clone(),
            max_age_ms: None,
            meta: None,
        };
        let mut stream = match upstream.open_event_stream(&params).await {
            Ok(stream) => stream,
            Err(error) => return Ended::of(error),
        };
        loop {
            let next = tokio::select! {
                () = cancel.cancelled() => return Ended::Cancelled,
                next = stream.next() => next,
            };
            let Some(message) = next else {
                return Ended::Closed;
            };
            let queued = match StreamFrame::from_notification(&message) {
                Some(StreamFrame::Active { cursor, truncated }) => {
                    if truncated && resumed && !self.gap(GapReason::UpstreamTruncated).await {
                        return Ended::Cancelled;
                    }
                    self.at(cursor).await
                }
                Some(StreamFrame::Event(occurrence)) => self.occurrence(occurrence).await,
                Some(StreamFrame::Heartbeat { cursor }) => self.at(cursor).await,
                Some(StreamFrame::Error(error)) => {
                    tracing::debug!(event = %self.ty.name, code = error.code, "upstream event stream reported an error");
                    true
                }
                Some(StreamFrame::Terminated(error)) => {
                    return Ended::answered(error.code, error.data.as_ref());
                }
                None => true,
            };
            if !queued {
                return Ended::Cancelled;
            }
        }
    }

    /// Poll the upstream until a reconnect is due.
    async fn poll(&mut self, upstream: &dyn McpUpstream, cancel: &CancellationToken) -> Ended {
        let connected = Instant::now();
        loop {
            let resumed = self.cursor.is_some();
            let params = PollEventsParams {
                name: self.upstream_name.clone(),
                arguments: self.arguments.clone(),
                cursor: self.cursor.clone(),
                max_age_ms: None,
                max_events: None,
                meta: None,
            };
            let result = tokio::select! {
                () = cancel.cancelled() => return Ended::Cancelled,
                result = upstream.poll_events(&params) => match result {
                    Ok(result) => result,
                    Err(error) => return Ended::of(error),
                },
            };
            if result.truncated && resumed && !self.gap(GapReason::UpstreamTruncated).await {
                return Ended::Cancelled;
            }
            let found = !result.events.is_empty();
            for occurrence in result.events {
                if !self.occurrence(occurrence).await {
                    return Ended::Cancelled;
                }
            }
            if !found && !self.at(result.cursor).await {
                return Ended::Cancelled;
            }
            if connected.elapsed() >= RECONNECT_AFTER {
                return Ended::Closed;
            }
            let wait = if result.has_more {
                Duration::ZERO
            } else {
                Duration::from_millis(result.next_poll_ms)
                    .clamp(MIN_UPSTREAM_POLL, MAX_UPSTREAM_POLL)
            };
            tokio::select! {
                () = cancel.cancelled() => return Ended::Cancelled,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Hold an upstream webhook subscription that delivers to this gateway:
    /// subscribe or refresh, then wait until the grant is due for a refresh
    /// or the receiver saw the upstream end it. A due refresh ends the read
    /// `Closed`, so the next runs on a fresh connection and credential.
    async fn webhook(
        &mut self,
        ctx: &SourceContext,
        upstream: &dyn McpUpstream,
        cancel: &CancellationToken,
    ) -> Ended {
        let Some(core) = ctx.core.upgrade() else {
            return Ended::Cancelled;
        };
        let (Some(stores), Some(base)) = (core.stores(), core.callback_base()) else {
            return Ended::Failed("this gateway has no public address yet".to_owned());
        };
        drop(core);
        let url = format!(
            "{base}{UPSTREAM_WEBHOOK_PATH}/{}/{}",
            self.federation, self.id
        );
        // The upstream challenges the callback while it subscribes, so the
        // route has to be there first.
        let route = UpstreamRoute::new(&self.federation, &self.ty.name, self.scope.clone());
        if let Err(error) = stores.routes.put(&self.id, &route, None).await {
            return Ended::Failed(error.to_string());
        }
        let resumed = self.cursor.is_some();
        let params = SubscribeEventsParams {
            name: self.upstream_name.clone(),
            arguments: self.arguments.clone(),
            delivery: WebhookDelivery {
                mode: DeliveryMode::Webhook.as_str().to_owned(),
                url: url.clone(),
                secret: stores.keys.upstream_webhook_secret(&self.id),
            },
            cursor: self.cursor.clone(),
            max_age_ms: None,
            ttl_ms: TtlRequest::ServerDefault,
            meta: None,
        };
        let result = tokio::select! {
            () = cancel.cancelled() => return Ended::Cancelled,
            result = upstream.subscribe_events(&params) => match result {
                Ok(result) => result,
                Err(error) => return Ended::of(error),
            },
        };
        self.callback = Some(url);
        if result.truncated && resumed && !self.gap(GapReason::UpstreamTruncated).await {
            return Ended::Cancelled;
        }
        if !self.at(result.cursor).await {
            return Ended::Cancelled;
        }
        let refresh_in = result
            .refresh_before
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .and_then(|at| {
                let left = at.signed_duration_since(chrono::Utc::now()).to_std().ok()?;
                Some(left.mul_f64(0.8))
            })
            .unwrap_or(MAX_REFRESH)
            .clamp(MIN_REFRESH, MAX_REFRESH);
        let deadline = Instant::now() + refresh_in;
        loop {
            let wait = WEBHOOK_CHECK.min(deadline.saturating_duration_since(Instant::now()));
            tokio::select! {
                () = cancel.cancelled() => return Ended::Cancelled,
                () = tokio::time::sleep(wait) => {}
            }
            if let Ok(Some(route)) = stores.routes.get(&self.id).await
                && route.ended.is_some()
            {
                return Ended::Gone;
            }
            if Instant::now() >= deadline {
                return Ended::Closed;
            }
        }
    }

    /// Stop the upstream webhook subscription this gateway made, and turn
    /// its route away from late deliveries.
    async fn retire(&self, ctx: &SourceContext) {
        let Some(url) = &self.callback else {
            return;
        };
        if let Some(stores) = ctx.core.upgrade().and_then(|core| core.stores()) {
            let mut route = UpstreamRoute::new(&self.federation, &self.ty.name, self.scope.clone());
            route.abandoned = true;
            if let Err(error) = stores
                .routes
                .put(&self.id, &route, Some(ROUTE_ABANDONED_TTL))
                .await
            {
                tracing::debug!(event = %self.ty.name, error = %error, "an upstream route could not be closed; it answers until the upstream stops");
            }
        }
        let identity = self.subscriber.as_ref().map(|s| &s.identity);
        match connect(ctx, &self.federation, identity).await {
            Ok(upstream) => {
                let params = UnsubscribeEventsParams {
                    name: self.upstream_name.clone(),
                    arguments: self.arguments.clone(),
                    delivery: UnsubscribeDelivery {
                        mode: Some(DeliveryMode::Webhook.as_str().to_owned()),
                        url: url.clone(),
                    },
                    meta: None,
                };
                if let Err(error) = upstream.unsubscribe_events(&params).await {
                    tracing::debug!(event = %self.ty.name, error = %error, "the upstream webhook subscription could not be ended; its grant lapses on its own");
                }
                upstream.close().await;
            }
            Err(_) => {
                tracing::debug!(event = %self.ty.name, "the upstream could not be reached to end a webhook subscription; its grant lapses on its own");
            }
        }
    }
}

/// A connection to `federation`'s upstream through the federation engine
/// of the runtime in force, as `subscriber` when one is named.
async fn connect(
    ctx: &SourceContext,
    federation: &str,
    subscriber: Option<&RequestIdentity>,
) -> Result<Arc<dyn McpUpstream>, Ended> {
    let shutting_down = || Ended::Failed("the gateway is shutting down".to_owned());
    let engine = {
        let core = ctx.core.upgrade().ok_or_else(shutting_down)?;
        let runtime = core.runtime().ok_or_else(shutting_down)?;
        let engine = runtime.load().federation_engine();
        engine.ok_or_else(|| Ended::Failed("no federation engine is running".to_owned()))?
    };
    engine
        .events_upstream(federation, subscriber)
        .await
        .map_err(Ended::of)
}

/// Run one upstream subscription until `cancel`, reconnecting after each
/// end. With `retire` cancelled as it stops, the webhook subscription it
/// made upstream ends too.
async fn read(
    mut subscription: UpstreamSubscription,
    ctx: SourceContext,
    mode: UpstreamMode,
    cancel: CancellationToken,
    retire: CancellationToken,
) {
    if !subscription.resume(&ctx).await {
        return;
    }
    let name = subscription.ty.name.clone();
    let federation = subscription.federation.clone();
    let mut backoff = MIN_BACKOFF;
    loop {
        let identity = subscription.subscriber.as_ref().map(|s| s.identity.clone());
        let ended = match connect(&ctx, &federation, identity.as_ref()).await {
            Ok(upstream) => {
                let ended = match mode {
                    UpstreamMode::Webhook => {
                        subscription.webhook(&ctx, upstream.as_ref(), &cancel).await
                    }
                    UpstreamMode::Push => subscription.stream(upstream.as_ref(), &cancel).await,
                    UpstreamMode::Poll => subscription.poll(upstream.as_ref(), &cancel).await,
                };
                upstream.close().await;
                ended
            }
            Err(ended) => ended,
        };
        let wait = match ended {
            Ended::Cancelled => break,
            Ended::Closed => {
                backoff = MIN_BACKOFF;
                MIN_BACKOFF
            }
            Ended::Failed(reason) => {
                tracing::warn!(event = %name, federation = %federation, reason = %reason, "upstream event read failed; retrying");
                metrics::counter!("mcpg_events_upstream_failures_total", "event" => name.clone(), "reason" => "failed")
                    .increment(1);
                let wait = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                wait
            }
            Ended::Refused(reason) => {
                tracing::warn!(event = %name, federation = %federation, reason = %reason, "the upstream refused an event subscription; retrying later");
                metrics::counter!("mcpg_events_upstream_failures_total", "event" => name.clone(), "reason" => "refused")
                    .increment(1);
                REFUSED_BACKOFF
            }
            Ended::Terminated(reason) => {
                tracing::warn!(event = %name, federation = %federation, reason = reason.label(), "the upstream ended an event subscription; so do the subscriptions it served");
                metrics::counter!("mcpg_events_upstream_failures_total", "event" => name.clone(), "reason" => "terminated")
                    .increment(1);
                subscription.cursor = None;
                subscription.positioned_at = None;
                if !subscription.end(reason).await {
                    break;
                }
                REFUSED_BACKOFF
            }
            Ended::Gone => {
                tracing::warn!(event = %name, federation = %federation, "the upstream ended a webhook subscription; subscribing again later");
                metrics::counter!("mcpg_events_upstream_failures_total", "event" => name.clone(), "reason" => "terminated")
                    .increment(1);
                subscription.cursor = None;
                subscription.positioned_at = None;
                subscription.callback = None;
                REFUSED_BACKOFF
            }
            Ended::SchemaChanged => {
                tracing::info!(event = %name, federation = %federation, "the event type's schema changed upstream; reading on from now");
                subscription.cursor = None;
                subscription.positioned_at = None;
                if !subscription.gap(GapReason::UpstreamTruncated).await {
                    break;
                }
                MIN_BACKOFF
            }
        };
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(wait) => {}
        }
    }
    if retire.is_cancelled() {
        subscription.retire(&ctx).await;
    }
}

#[cfg(test)]
#[path = "federated_tests.rs"]
mod tests;
