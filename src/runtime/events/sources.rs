//! Event sources on the events owner.
//!
//! A `watch` or `resource` source runs while its type has demand — a live
//! subscription, or `always_on` — and stops `sources.linger_ms` after the
//! last. Every change it reports becomes a raw occurrence on a bounded queue;
//! a full queue drops the change and counts it rather than stalling the
//! plugin. One consumer per source shapes each occurrence and appends it to
//! the type's log, so the log keeps the order the source reported.
//!
//! A source that cannot resume, started on a log that already holds rows,
//! writes a gap marker first: whatever happened while no source ran is
//! reported as `truncated`, never silently skipped. One whose plugin
//! resumes gets its last position back instead.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::{WatchEvent, WatchEventSink};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::catalog::{
    EventCatalog, EventType, ResourceStrategy, SourceSpec, WatchPayload, watch_source_uri,
};
use super::log::{
    AppendOutcome, EventLog, GapReason, InboxLimits, InboxOutcome, InboxRow, LogError, RowScope,
    WriterLease,
};
use super::occurrence::{RawOccurrence, now_rfc3339, shape};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Changes a source may queue before new ones are dropped.
pub const SINK_CAPACITY: usize = 1_024;
/// Positions a source holds for its plugin to acknowledge; past it, an
/// acknowledgement waits for the upstream's redelivery.
pub const ACK_CAPACITY: usize = 2 * SINK_CAPACITY;
/// Shortest interval of a polled resource.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// How long the position of one of several upstream reads of a source is
/// kept after its last write.
pub const SLOT_POSITION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Reads a resource's text for a polled `resource` source; `None` when the
/// read failed.
pub type ResourceFetcher = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// What a source queues for its log, in the order it saw it.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceItem {
    /// An occurrence to append.
    Occurrence(RawOccurrence),
    /// Where the source resumes from, at `slot` (see
    /// [`EventLog::resume_position`]), with no occurrence to append.
    Position {
        slot: Option<String>,
        cursor: serde_json::Value,
    },
    /// Events may have been missed by the readers of `scope`.
    Gap { reason: GapReason, scope: RowScope },
    /// The subscriptions of the readers of `scope` end here.
    End {
        reason: super::log::EndReason,
        scope: RowScope,
    },
    /// An event of another type: nothing to append, and the plugin may
    /// settle its position, in order with the events before it.
    Skipped(serde_json::Value),
}

/// What a running source needs from the events core.
#[derive(Clone)]
pub struct SourceContext {
    pub log: Arc<EventLog>,
    /// The owner's lease; `None` while this replica is not the owner.
    pub lease: watch::Receiver<Option<WriterLease>>,
    pub registry: Arc<mcpg_plugin_host::PluginRegistry>,
    pub fetcher: Option<ResourceFetcher>,
    pub max_payload_bytes: u64,
    /// Hand occurrences to the owner through the inbox, under these
    /// limits, instead of appending them: a source that runs on every
    /// replica.
    pub inbox: Option<InboxLimits>,
    /// The core, for a federated source: the demand for each set of
    /// arguments and the federation engine to read the upstream with.
    pub core: std::sync::Weak<super::engine::EventsCore>,
    /// Where appended occurrences are metered for the plan's ingest
    /// allowance.
    pub usage: crate::runtime::cp_metrics::ToolCallRecorderHandle,
    /// The plan in force, read at each append: its retention caps.
    pub quota: crate::runtime::cp_quota::QuotaStatusHandle,
}

impl SourceContext {
    /// The plan's MCP Events caps now.
    pub fn plan(&self) -> crate::runtime::cp_quota::EventsPlan {
        self.quota
            .current()
            .map(|status| status.events)
            .unwrap_or_default()
    }
}

/// Meter `appended` occurrences of `ty`, `bytes` in all, for the plan's
/// ingest allowance. Builtin types report the gateway's own work, which is
/// metered as tool calls, and count nothing.
pub(super) fn meter_ingest(
    usage: &crate::runtime::cp_metrics::ToolCallRecorderHandle,
    ty: &EventType,
    appended: u64,
    bytes: u64,
) {
    if appended == 0 || matches!(ty.source, SourceSpec::Builtin(_)) {
        return;
    }
    metrics::counter!(
        "mcpg_events_ingested_total",
        "event" => ty.name.clone(),
        "source" => ty.source.kind()
    )
    .increment(appended);
    usage.record_event_ingest(&ty.name, ty.source.kind(), appended, bytes);
}

struct Running {
    cancel: CancellationToken,
    fingerprint: String,
    generation: u64,
    last_demand_ms: u64,
}

/// The sources running on this replica, by event type name.
#[derive(Default)]
pub struct SourceManager {
    running: HashMap<String, Running>,
}

impl std::fmt::Debug for SourceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceManager")
            .field("running", &self.running.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SourceManager {
    /// Start, keep or stop each source of `catalog`.
    ///
    /// A source runs while `demand(name)` holds or its type is
    /// `always_on`, and for `linger_ms` after. A source whose definition
    /// changed, or that runs on an older plugin registry (`generation`),
    /// restarts.
    pub fn reconcile(
        &mut self,
        catalog: &EventCatalog,
        demand: &dyn Fn(&str) -> bool,
        ctx: &SourceContext,
        generation: u64,
        linger_ms: u64,
        now_ms: u64,
    ) {
        self.reconcile_selected(
            catalog,
            SourceSpec::needs_runner,
            demand,
            ctx,
            generation,
            linger_ms,
            now_ms,
        );
    }

    /// [`Self::reconcile`] over the types whose source `select` picks: the
    /// owner's sources, or those that run on every replica.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_selected(
        &mut self,
        catalog: &EventCatalog,
        select: fn(&SourceSpec) -> bool,
        demand: &dyn Fn(&str) -> bool,
        ctx: &SourceContext,
        generation: u64,
        linger_ms: u64,
        now_ms: u64,
    ) {
        self.running.retain(|name, running| {
            let keep = catalog.get(name).is_some_and(|ty| {
                ty.source_fingerprint == running.fingerprint && select(&ty.source)
            }) && running.generation == generation;
            if !keep {
                running.cancel.cancel();
            }
            keep
        });
        for ty in catalog.types() {
            if !select(&ty.source) {
                continue;
            }
            let wanted = ty.always_on || demand(&ty.name);
            match self.running.get_mut(&ty.name) {
                Some(running) if wanted => running.last_demand_ms = now_ms,
                Some(running) => {
                    if now_ms.saturating_sub(running.last_demand_ms) > linger_ms {
                        running.cancel.cancel();
                        self.running.remove(&ty.name);
                        tracing::debug!(event = %ty.name, "event source stopped: no demand");
                    }
                }
                None if wanted => {
                    let cancel = CancellationToken::new();
                    tokio::spawn(run_source(Arc::clone(ty), ctx.clone(), cancel.clone()));
                    self.running.insert(
                        ty.name.clone(),
                        Running {
                            cancel,
                            fingerprint: ty.source_fingerprint.clone(),
                            generation,
                            last_demand_ms: now_ms,
                        },
                    );
                    tracing::info!(event = %ty.name, source = ty.source.kind(), "event source started");
                }
                None => {}
            }
        }
        metrics::gauge!("mcpg_events_sources_running").set(self.running.len() as f64);
    }

    /// Stop every source.
    pub fn stop_all(&mut self) {
        for (_, running) in self.running.drain() {
            running.cancel.cancel();
        }
        metrics::gauge!("mcpg_events_sources_running").set(0.0);
    }

    /// Names of the running sources, sorted.
    pub fn running(&self) -> Vec<String> {
        let mut names: Vec<String> = self.running.keys().cloned().collect();
        names.sort();
        names
    }
}

impl Drop for SourceManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// Bridges a plugin's change events onto a source's queue.
struct QueueSink {
    tx: mpsc::Sender<SourceItem>,
    uri: Option<String>,
    event: String,
    /// Take the plugin's payload for this event type; `None` reports each
    /// change as a payload-free tick.
    payload: Option<WatchPayload>,
}

#[async_trait]
impl WatchEventSink for QueueSink {
    async fn emit(&self, event: WatchEvent) {
        if event.gap {
            let gap = SourceItem::Gap {
                reason: GapReason::UpstreamTruncated,
                scope: RowScope::default(),
            };
            if self.tx.try_send(gap).is_err() {
                metrics::counter!("mcpg_events_sink_dropped_total", "event" => self.event.clone())
                    .increment(1);
            }
            if event.event_type.is_none() && event.data.is_none() {
                if let Some(position) = event.upstream_cursor {
                    let _ = self.tx.try_send(SourceItem::Skipped(position));
                }
                return;
            }
        }
        let raw = match &self.payload {
            None => RawOccurrence {
                upstream_cursor: event.upstream_cursor,
                ..tick(self.uri.as_deref())
            },
            Some(payload) => match payload_occurrence(payload, event) {
                Ok(raw) => raw,
                // Another of the plugin's event types: this source is done
                // with it once the events before it are.
                Err(position) => {
                    if let Some(position) = position {
                        let _ = self.tx.try_send(SourceItem::Skipped(position));
                    }
                    return;
                }
            },
        };
        if self.tx.try_send(SourceItem::Occurrence(raw)).is_err() {
            metrics::counter!("mcpg_events_sink_dropped_total", "event" => self.event.clone())
                .increment(1);
        }
    }
}

/// The occurrence of a plugin event for a payload-bearing source; for an
/// event of another of the plugin's event types, its position.
fn payload_occurrence(
    payload: &WatchPayload,
    event: WatchEvent,
) -> Result<RawOccurrence, Option<serde_json::Value>> {
    // Every event of a strategy that declares types names its type; one
    // that does not is not this type's.
    if event.event_type.as_deref() != Some(payload.event_type.as_str()) {
        return Err(event.upstream_cursor);
    }
    let timestamp = event
        .occurred_at
        .filter(|at| chrono::DateTime::parse_from_rfc3339(at).is_ok());
    Ok(RawOccurrence {
        event_id: event.event_id,
        timestamp,
        data: event
            .data
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
        upstream_cursor: event.upstream_cursor,
        ..RawOccurrence::default()
    })
}

/// The occurrence of one payload-free change.
fn tick(uri: Option<&str>) -> RawOccurrence {
    let mut data = serde_json::Map::new();
    if let Some(uri) = uri {
        data.insert("uri".to_owned(), serde_json::Value::String(uri.to_owned()));
    }
    data.insert(
        "observedAt".to_owned(),
        serde_json::Value::String(now_rfc3339()),
    );
    RawOccurrence {
        data: serde_json::Value::Object(data),
        ..RawOccurrence::default()
    }
}

async fn run_source(ty: Arc<EventType>, ctx: SourceContext, cancel: CancellationToken) {
    let (tx, rx) = mpsc::channel(SINK_CAPACITY);
    let (acks, handled) = mpsc::channel(ACK_CAPACITY);
    let consumer = tokio::spawn(consume(
        Arc::clone(&ty),
        ctx.clone(),
        rx,
        acks,
        cancel.clone(),
    ));

    // A federated source keeps a position, and marks its gaps, per
    // upstream subscription.
    if matches!(ty.source, SourceSpec::Federation { .. }) {
        super::federated::run(&ty, &ctx, tx, &cancel).await;
        cancel.cancel();
        let _ = consumer.await;
        return;
    }

    // A resumable source picks up where it stopped, so a restart leaves no
    // hole; one with no position yet, or that cannot resume, marks a gap.
    let resume = if ty.source.resumes() {
        match ctx.log.resume_position(&ty.source_key, None).await {
            Ok(position) => position,
            Err(error) => {
                tracing::warn!(event = %ty.name, error = %error, "could not read the source's resume position");
                None
            }
        }
    } else {
        None
    };
    let head = if resume.is_some() || ctx.inbox.is_some() {
        Ok(None)
    } else {
        ctx.log.head(&ty.source_key).await
    };
    match head {
        Ok(Some(head)) if head.seq > 0 => {
            let gap = SourceItem::Gap {
                reason: GapReason::SourceRestart,
                scope: RowScope::default(),
            };
            mark(&ty, &ctx, gap).await;
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(event = %ty.name, error = %error, "could not read the log head at source start");
        }
    }

    match &ty.source {
        SourceSpec::Watch {
            kind,
            spec,
            payload,
            ..
        } => {
            let spec = with_resume(spec, resume);
            run_plugin(
                &ty,
                &ctx,
                kind,
                &spec,
                &watch_source_uri(&ty.name),
                None,
                payload.clone(),
                tx,
                handled,
                &cancel,
            )
            .await
        }
        SourceSpec::Resource {
            uri,
            strategy: ResourceStrategy::Plugin { kind, spec },
        } => {
            run_plugin(
                &ty,
                &ctx,
                kind,
                spec,
                uri,
                Some(uri.as_str()),
                None,
                tx,
                handled,
                &cancel,
            )
            .await
        }
        SourceSpec::Resource {
            uri,
            strategy: ResourceStrategy::Poll { interval_ms },
        } => run_poll(&ty, &ctx, uri, *interval_ms, tx, &cancel).await,
        SourceSpec::Inbound(_) | SourceSpec::Builtin(_) | SourceSpec::Federation { .. } => {
            cancel.cancelled().await
        }
    }
    cancel.cancel();
    let _ = consumer.await;
}

/// `spec` with the resume position under the reserved key, when there is
/// one.
fn with_resume(spec: &serde_json::Value, resume: Option<serde_json::Value>) -> serde_json::Value {
    let Some(position) = resume else {
        return spec.clone();
    };
    let mut spec = match spec {
        serde_json::Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    spec.insert(
        mcpg_plugin_protocol::WATCH_RESUME_SPEC_KEY.to_owned(),
        position,
    );
    serde_json::Value::Object(spec)
}

#[allow(clippy::too_many_arguments)]
async fn run_plugin(
    ty: &EventType,
    ctx: &SourceContext,
    kind: &str,
    spec: &serde_json::Value,
    watch_uri: &str,
    data_uri: Option<&str>,
    payload: Option<WatchPayload>,
    tx: mpsc::Sender<SourceItem>,
    mut handled: mpsc::Receiver<serde_json::Value>,
    cancel: &CancellationToken,
) {
    let Some(plugin) = ctx.registry.watch_strategy(kind) else {
        tracing::warn!(event = %ty.name, kind, "event source: no watch plugin of this kind is loaded");
        cancel.cancelled().await;
        return;
    };
    let sink = Arc::new(QueueSink {
        tx,
        uri: data_uri.map(str::to_owned),
        event: ty.name.clone(),
        payload,
    });
    let handle = match plugin.watch(watch_uri, spec, sink).await {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(event = %ty.name, kind, error = %error, "event source: the watch plugin refused to start");
            metrics::counter!("mcpg_events_source_failures_total", "event" => ty.name.clone())
                .increment(1);
            cancel.cancelled().await;
            return;
        }
    };
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            Some(position) = handled.recv() => handle.acknowledge(&position).await,
        }
    }
    handle.cancel().await;
}

async fn run_poll(
    ty: &EventType,
    ctx: &SourceContext,
    uri: &str,
    interval_ms: u64,
    tx: mpsc::Sender<SourceItem>,
    cancel: &CancellationToken,
) {
    let Some(fetcher) = ctx.fetcher.clone() else {
        tracing::warn!(event = %ty.name, "event source: no resource reader for a polled resource");
        cancel.cancelled().await;
        return;
    };
    let interval = Duration::from_millis(interval_ms).max(MIN_POLL_INTERVAL);
    let mut last: Option<[u8; 32]> = None;
    loop {
        if let Some(body) = fetcher(uri) {
            let hash: [u8; 32] = Sha256::digest(body.as_bytes()).into();
            if last.is_some_and(|prev| prev != hash)
                && tx
                    .try_send(SourceItem::Occurrence(tick(Some(uri))))
                    .is_err()
            {
                metrics::counter!("mcpg_events_sink_dropped_total", "event" => ty.name.clone())
                    .increment(1);
            }
            last = Some(hash);
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// Remember `cursor` as where the source of `ty` resumes, at `slot`.
async fn store_position(
    ty: &EventType,
    ctx: &SourceContext,
    slot: Option<&str>,
    cursor: serde_json::Value,
) {
    let ttl = slot.is_some().then_some(SLOT_POSITION_TTL);
    if let Err(error) = ctx
        .log
        .store_resume_position(&ty.source_key, slot, cursor, ttl)
        .await
    {
        tracing::warn!(event = %ty.name, error = %error, "could not store the source's resume position");
    }
}

/// Append `item`, a gap marker or the end of some subscriptions, to the log
/// of `ty`; `false` once this replica no longer owns the log.
async fn mark(ty: &EventType, ctx: &SourceContext, item: SourceItem) -> bool {
    let current = *ctx.lease.borrow();
    let Some(lease) = current else {
        return true;
    };
    let retention = ctx.plan().retention(&ty.retention);
    let written = match item {
        SourceItem::Gap { reason, scope } => {
            ctx.log
                .append_gap(&ty.source_key, reason, scope, &retention, lease)
                .await
        }
        SourceItem::End { reason, scope } => {
            ctx.log
                .append_end(&ty.source_key, reason, scope, &retention, lease)
                .await
        }
        SourceItem::Occurrence(_) | SourceItem::Position { .. } | SourceItem::Skipped(_) => {
            return true;
        }
    };
    match written {
        Ok(_) => true,
        Err(LogError::Deposed | LogError::LeaseExpired) => false,
        Err(error) => {
            tracing::warn!(event = %ty.name, error = %error, "could not mark the event log");
            true
        }
    }
}

async fn consume(
    ty: Arc<EventType>,
    ctx: SourceContext,
    mut rx: mpsc::Receiver<SourceItem>,
    acks: mpsc::Sender<serde_json::Value>,
    cancel: CancellationToken,
) {
    // Tell the plugin the source is done with a position: stored, or
    // dropped for good. A transient failure tells it nothing, so the
    // upstream redelivers; a full queue only delays that to the redelivery.
    let done = |position: Option<serde_json::Value>| {
        if let Some(position) = position {
            let _ = acks.try_send(position);
        }
    };
    loop {
        let item = tokio::select! {
            () = cancel.cancelled() => return,
            item = rx.recv() => match item {
                Some(item) => item,
                None => return,
            },
        };
        let raw = match item {
            SourceItem::Occurrence(raw) => raw,
            SourceItem::Position { slot, cursor } => {
                store_position(&ty, &ctx, slot.as_deref(), cursor).await;
                continue;
            }
            SourceItem::Skipped(position) => {
                done(Some(position));
                continue;
            }
            marker @ (SourceItem::Gap { .. } | SourceItem::End { .. }) => {
                if !mark(&ty, &ctx, marker).await {
                    tracing::info!(event = %ty.name, "event source stops: this replica no longer owns the log");
                    cancel.cancel();
                    return;
                }
                continue;
            }
        };
        // A source on every replica hands the owner what it saw; the owner
        // shapes and appends it, once, when it drains the inbox.
        if let Some(limits) = ctx.inbox {
            let position = raw.upstream_cursor.clone();
            let row = InboxRow {
                v: super::log::FORMAT_VERSION,
                event_id: Some(
                    raw.event_id
                        .clone()
                        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                ),
                timestamp: raw.timestamp.clone(),
                data: raw.data,
                received_at_ms: now_ms(),
                audience: raw.audience,
                arguments: raw.arguments,
                marker: None,
            };
            match ctx.log.inbox_put(&ty.source_key, row, limits).await {
                Ok(InboxOutcome::Accepted) => done(position),
                Ok(InboxOutcome::Full { .. }) | Err(_) => {
                    metrics::counter!("mcpg_events_sink_dropped_total", "event" => ty.name.clone())
                        .increment(1);
                }
            }
            continue;
        }
        let current = *ctx.lease.borrow();
        let Some(lease) = current else {
            metrics::counter!("mcpg_events_sink_dropped_total", "event" => ty.name.clone())
                .increment(1);
            continue;
        };
        let upstream_cursor = raw.upstream_cursor.clone();
        let slot = raw.arguments.clone();
        let occurrence = match shape(&ty, raw, Some(&ctx.registry), ctx.max_payload_bytes).await {
            Ok(occurrence) => occurrence,
            Err(error) => {
                metrics::counter!(
                    "mcpg_events_payload_dropped_total",
                    "event" => ty.name.clone(),
                    "reason" => error.label()
                )
                .increment(1);
                // The same payload is refused again on every redelivery.
                done(upstream_cursor);
                continue;
            }
        };
        let retention = ctx.plan().retention(&ty.retention);
        match ctx
            .log
            .append(&ty.source_key, occurrence, &retention, lease)
            .await
        {
            Ok(outcome) => {
                if let AppendOutcome::Appended { bytes, .. } = outcome {
                    meter_ingest(&ctx.usage, &ty, 1, bytes);
                }
                // After the append: a crash in between repeats the event,
                // which its id deduplicates, rather than losing it.
                if let Some(cursor) = upstream_cursor.clone().filter(|_| ty.source.resumes()) {
                    store_position(&ty, &ctx, slot.as_deref(), cursor).await;
                }
                done(upstream_cursor);
            }
            Err(LogError::Deposed | LogError::LeaseExpired) => {
                tracing::info!(event = %ty.name, "event source stops: this replica no longer owns the log");
                cancel.cancel();
                return;
            }
            Err(error) => {
                tracing::warn!(event = %ty.name, error = %error, "event append failed; the change is dropped");
                metrics::counter!("mcpg_events_append_failures_total", "event" => ty.name.clone())
                    .increment(1);
            }
        }
    }
}

#[cfg(test)]
#[path = "sources_tests.rs"]
mod tests;
