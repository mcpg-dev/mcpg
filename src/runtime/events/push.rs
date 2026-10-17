//! `events/stream`: push delivery of one subscription over one long-lived
//! response.
//!
//! A stream lives as long as its request, on the replica the client
//! reached, and keeps its position in memory only: a client that
//! reconnects sends the last cursor it received. Each replica watches the
//! head of every log one of its streams reads ([`HeadWatch`]), through the
//! head hint the owner publishes and a read of the head every second as the
//! backstop; a stream reads its rows from the log when the head moves, with
//! the read poll uses.
//!
//! Frames, in order: `active` with the start position (`truncated` when
//! the cursor could not be honoured); then an `event` per occurrence, and
//! `active {truncated: true}` where events may be missing; a `heartbeat`
//! every `push.heartbeat_interval_ms` with the position read up to; an `error` when
//! a read fails. When the gateway ends the stream it sends `terminated`
//! if the subscription ended, then the empty `StreamEventsResult`.
//!
//! A stream holds a lease (`ev:push:p:…`) for the per-principal cap and
//! demand for its type's source, both renewed every half heartbeat and
//! released when it ends.

use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::StreamExt as _;
use serde_json::{Map, Value};
use tokio::sync::{mpsc, watch};

use super::catalog::EventType;
use super::cursor::CursorScope;
use super::dispatcher::credential_is_revoked;
use super::engine::{EventsCore, EventsStores};
use super::handler::policy_key;
use super::log::{HEAD_TOPIC_PREFIX, ResumePoint};
use super::poll::{ReadItem, Reader, read_occurrences, resume_point};
use super::subscriptions::{CredentialSnapshot, TerminationReason};
use super::webhook::{check_arguments, credential_snapshot, gate_error, subscriber_key};
use crate::config::events::EventReplay;
use crate::protocol::v_2026_07_28::extensions::events::errors::{
    CodeNumbering, EventsError, ForbiddenReason,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    DeliveryMode, StreamEventsParams, StreamFrame, stream_events_result,
};
use crate::runtime::policy::PolicyRoute;
use crate::runtime::{GatewayRequestId, RequestContext, RequestIdentity, TransportKind};

/// Frames buffered for a slow client before the stream waits on it.
const FRAME_BUFFER: usize = 64;
/// Events one read of a stream sends at most.
const STREAM_BATCH: usize = 100;
/// Backstop interval of a head watch.
const HEAD_POLL: Duration = Duration::from_secs(1);
/// What a stream answers when the store fails.
const STORE_FAULT: &str = "the event store is unavailable; retry";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn store_fault(error: impl std::fmt::Display) -> EventsError {
    tracing::warn!(error = %error, "event stream store access failed");
    EventsError::internal(STORE_FAULT)
}

/// The head of one log as this replica sees it, shared by its streams.
pub struct HeadWatch {
    rx: watch::Receiver<u64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HeadWatch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Keep `tx` at the head of log `sk`.
async fn follow_head(stores: Arc<EventsStores>, sk: String, tx: watch::Sender<u64>) {
    let mut local = stores.log.watch_head(&sk);
    let mut local_open = true;
    let mut hints = match &stores.bus {
        Some(bus) => bus
            .subscribe(&format!("{HEAD_TOPIC_PREFIX}{sk}"), None)
            .await
            .ok(),
        None => None,
    };
    let mut tick = tokio::time::interval(HEAD_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if let Ok(bounds) = stores.log.bounds(&sk).await {
            tx.send_if_modified(|head| {
                let moved = *head != bounds.head;
                *head = bounds.head;
                moved
            });
        }
        tokio::select! {
            _ = tx.closed() => return,
            _ = tick.tick() => {}
            changed = local.changed(), if local_open => local_open = changed.is_ok(),
            hint = async {
                match hints.as_mut() {
                    Some(hints) => hints.next().await,
                    None => std::future::pending().await,
                }
            } => {
                if hint.is_none() {
                    hints = None;
                }
            }
        }
    }
}

/// How a stream ended.
enum Close {
    /// The client went away; nothing more can be sent.
    Client,
    /// The gateway closes the stream; the client may reconnect at once.
    Server,
    /// The subscription ended for this reason.
    Terminated(TerminationReason),
}

/// One open stream.
struct Stream {
    core: Weak<EventsCore>,
    stores: Arc<EventsStores>,
    ty: Arc<EventType>,
    catalog_version: u64,
    identity: RequestIdentity,
    credential: CredentialSnapshot,
    principal_key: String,
    arguments: Map<String, Value>,
    scope: CursorScope,
    request_id: Value,
    stream_id: String,
    numbering: CodeNumbering,
    heartbeat: Duration,
    reauthorize: Duration,
    epoch: u64,
    after: u64,
    sent: u64,
    tx: mpsc::Sender<Value>,
}

impl EventsCore {
    /// Open an `events/stream` for `ctx`: the checks a subscribe runs, then
    /// a task that writes the stream's frames, as JSON-RPC messages, to the
    /// returned channel until the client drops it or the gateway ends the
    /// stream.
    pub async fn open_stream(
        self: &Arc<Self>,
        ctx: &RequestContext,
        params: StreamEventsParams,
        request_id: Value,
    ) -> Result<mpsc::Receiver<Value>, EventsError> {
        let config = self.config();
        let push = &config.push;
        if !push.enabled {
            return Err(EventsError::unsupported_delivery_mode(
                DeliveryMode::Push.as_str(),
            ));
        }
        let principal_key = subscriber_key(&ctx.identity, push.require_trust)?;
        let ty = self.offered_type(ctx, &params.name, DeliveryMode::Push)?;
        check_arguments(&ty, &params.arguments)?;
        let arguments = Value::Object(params.arguments.clone());
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?
            .load_full();
        runtime
            .evaluate_surface_gate_without_waiting(
                "event",
                "event.stream.pre",
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
        let cap = push.max_streams_per_principal;
        let open = stores
            .leases
            .count_streams(&principal_key, cap as usize)
            .await
            .map_err(store_fault)?;
        if open as u64 >= cap {
            return Err(EventsError::resource_exhausted("streams", Some(cap)));
        }
        let holder = super::federated::LeaseHolder {
            principal_key: &principal_key,
            identity: &ctx.identity,
            arguments: &params.arguments,
        };
        self.check_plan_readers(&ty, &holder).await?;
        let scope = CursorScope::new(&ty.source_key, &arguments);
        let start = match ty.replay {
            EventReplay::Log => {
                resume_point(
                    &stores,
                    &ty,
                    &scope,
                    params.cursor.as_deref(),
                    params.max_age_ms,
                )
                .await?
            }
            EventReplay::None => {
                let bounds = stores
                    .log
                    .bounds(&ty.source_key)
                    .await
                    .map_err(store_fault)?;
                ResumePoint {
                    epoch: bounds.epoch,
                    after_seq: bounds.head,
                    truncated: false,
                }
            }
        };
        let heartbeat = Duration::from_millis(push.heartbeat_interval_ms);
        let stream_id = uuid::Uuid::now_v7().to_string();
        stores
            .leases
            .put_stream(&principal_key, &stream_id, &ty.name, heartbeat * 2)
            .await
            .map_err(store_fault)?;
        self.note_lease_demand(
            &stores,
            &ty,
            &holder,
            now_ms(),
            push.heartbeat_interval_ms,
            heartbeat * 2,
        )
        .await;

        let (tx, rx) = mpsc::channel(FRAME_BUFFER);
        let head = self.head_watch(&stores, &ty.source_key);
        let stream = Stream {
            core: Arc::downgrade(self),
            stores,
            catalog_version: self.catalog_version(),
            identity: ctx.identity.clone(),
            credential: credential_snapshot(ctx),
            principal_key,
            arguments: params.arguments,
            scope,
            request_id,
            stream_id: stream_id.clone(),
            numbering: config.error_codes.numbering(),
            heartbeat,
            reauthorize: Duration::from_millis(config.reauthorize_interval_ms),
            epoch: start.epoch,
            after: start.after_seq,
            sent: 0,
            tx,
            ty,
        };
        metrics::counter!("mcpg_events_streams_opened_total", "event" => stream.ty.name.clone())
            .increment(1);
        metrics::gauge!("mcpg_events_streams").increment(1.0);
        self.open_streams
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.audit_stream_opened(ctx, &stream.ty.name, &stream_id, &stream.arguments)
            .await;
        tokio::spawn(stream.run(head, start.truncated));
        Ok(rx)
    }

    /// The head watch of log `sk`, started on first use and stopped with
    /// the last stream that holds it.
    fn head_watch(&self, stores: &Arc<EventsStores>, sk: &str) -> Arc<HeadWatch> {
        let mut heads = self.heads.lock();
        if let Some(watch) = heads.get(sk).and_then(Weak::upgrade) {
            return watch;
        }
        heads.retain(|_, held| held.strong_count() > 0);
        let (tx, rx) = watch::channel(0);
        let task = tokio::spawn(follow_head(Arc::clone(stores), sk.to_owned(), tx));
        let watch = Arc::new(HeadWatch { rx, task });
        heads.insert(sk.to_owned(), Arc::downgrade(&watch));
        watch
    }
}

impl Stream {
    async fn run(mut self, head: Arc<HeadWatch>, truncated: bool) {
        let close = self.serve(&head, truncated).await;
        drop(head);
        if let Err(error) = self
            .stores
            .leases
            .drop_stream(&self.principal_key, &self.stream_id)
            .await
        {
            tracing::debug!(error = %error, "stream lease release failed; it expires on its own");
        }
        let reason = match close {
            Close::Client => "client",
            Close::Server => "server",
            Close::Terminated(reason) => reason.label(),
        };
        match close {
            Close::Client => {}
            Close::Server => {
                let _ = self.tx.send(stream_events_result(&self.request_id)).await;
            }
            Close::Terminated(reason) => {
                let frame = StreamFrame::Terminated(
                    reason.error(None).numbered(self.numbering).to_error_body(),
                );
                let _ = self.tx.send(frame.to_notification(&self.request_id)).await;
                let _ = self.tx.send(stream_events_result(&self.request_id)).await;
            }
        }
        metrics::gauge!("mcpg_events_streams").decrement(1.0);
        metrics::counter!("mcpg_events_streams_closed_total", "event" => self.ty.name.clone(), "reason" => reason)
            .increment(1);
        if let Some(core) = self.core.upgrade() {
            core.open_streams
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            core.audit_stream_closed(
                &self.identity,
                &self.ty.name,
                &self.stream_id,
                reason,
                self.sent,
            )
            .await;
        }
    }

    async fn serve(&mut self, head: &HeadWatch, truncated: bool) -> Close {
        if !self
            .send(StreamFrame::Active {
                cursor: self.cursor(self.after),
                truncated,
            })
            .await
        {
            return Close::Client;
        }
        let mut head_rx = head.rx.clone();
        let mut beat =
            tokio::time::interval_at(tokio::time::Instant::now() + self.heartbeat, self.heartbeat);
        let renew_every = self.heartbeat / 2;
        let mut renew =
            tokio::time::interval_at(tokio::time::Instant::now() + renew_every, renew_every);
        let mut recheck_at = tokio::time::Instant::now() + self.reauthorize;
        let mut read_now = true;
        loop {
            if read_now {
                if let Some(close) = self.drain().await {
                    return close;
                }
                read_now = false;
            }
            tokio::select! {
                _ = self.tx.closed() => return Close::Client,
                changed = head_rx.changed() => {
                    if changed.is_err() {
                        return Close::Server;
                    }
                    read_now = true;
                }
                _ = beat.tick() => {
                    if !self.send(StreamFrame::Heartbeat { cursor: self.cursor(self.after) }).await {
                        return Close::Client;
                    }
                }
                _ = renew.tick() => {
                    if let Some(close) = self.renew(&mut recheck_at).await {
                        return close;
                    }
                    read_now = true;
                }
            }
        }
    }

    /// Send what the log holds past the stream's position.
    async fn drain(&mut self) -> Option<Close> {
        let core = self.core.upgrade()?;
        let runtime = core.runtime()?.load_full();
        // A held stream sends heartbeats only; the events wait in the log.
        if core.delivery_held(&runtime).await {
            return None;
        }
        loop {
            let reader = Reader {
                identity: &self.identity,
                principal_key: &self.principal_key,
                arguments: &self.arguments,
                scope: &self.scope,
                mode: DeliveryMode::Push,
                max_events: STREAM_BATCH,
            };
            let start = ResumePoint {
                epoch: self.epoch,
                after_seq: self.after,
                truncated: false,
            };
            let read = match read_occurrences(&self.stores, &runtime, &self.ty, &reader, start)
                .await
            {
                Ok(read) => read,
                Err(error) => {
                    let frame = StreamFrame::Error(error.numbered(self.numbering).to_error_body());
                    return (!self.send(frame).await).then_some(Close::Client);
                }
            };
            let count = read.event_count() as u64;
            for item in read.items {
                let frame = match item {
                    ReadItem::Event(event) => StreamFrame::Event(event),
                    ReadItem::Gap { after } => StreamFrame::Active {
                        cursor: self.cursor_in(read.epoch, after),
                        truncated: true,
                    },
                    ReadItem::Ended(reason) => {
                        return Some(Close::Terminated(TerminationReason::Upstream(reason)));
                    }
                };
                if !self.send(frame).await {
                    return Some(Close::Client);
                }
            }
            self.epoch = read.epoch;
            self.after = read.after;
            if count > 0 {
                self.sent += count;
                metrics::counter!(
                    "mcpg_events_delivered_total",
                    "event" => self.ty.name.clone(),
                    "mode" => DeliveryMode::Push.as_str()
                )
                .increment(count);
                runtime.tool_call_recorder.record_event_usage(
                    &self.ty.name,
                    DeliveryMode::Push.as_str(),
                    self.ty.billable_deliveries(count),
                    0,
                    read.bytes,
                );
            }
            if !read.has_more {
                return None;
            }
        }
    }

    /// Hold the lease and the demand another half heartbeat, and end the
    /// stream when the config, the caller's access or its token says so.
    async fn renew(&mut self, recheck_at: &mut tokio::time::Instant) -> Option<Close> {
        let core = self.core.upgrade()?;
        let now = now_ms();
        if let Some(close) = self.follow_config(&core) {
            return Some(close);
        }
        let runtime = core.runtime()?.load_full();
        if self.credential.token_exp_ms.is_some_and(|exp| exp <= now) {
            return Some(Close::Terminated(TerminationReason::Forbidden(
                ForbiddenReason::Expired,
            )));
        }
        if credential_is_revoked(&runtime, &self.credential) {
            return Some(Close::Terminated(TerminationReason::Forbidden(
                ForbiddenReason::Revoked,
            )));
        }
        if tokio::time::Instant::now() >= *recheck_at {
            *recheck_at = tokio::time::Instant::now() + self.reauthorize;
            let arguments = Value::Object(self.arguments.clone());
            let ctx = RequestContext::new(
                GatewayRequestId::new(),
                None,
                None,
                None,
                self.identity.clone(),
                TransportKind::Http,
            );
            let key = policy_key(&self.ty.name);
            if !runtime.surface_is_visible(&ctx, &key, PolicyRoute::event(None)) {
                return Some(Close::Terminated(TerminationReason::Forbidden(
                    ForbiddenReason::Policy,
                )));
            }
            if let Err(reason) = runtime
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
                return Some(Close::Terminated(TerminationReason::Forbidden(reason)));
            }
        }
        let lease = self.heartbeat * 2;
        if let Err(error) = self
            .stores
            .leases
            .put_stream(&self.principal_key, &self.stream_id, &self.ty.name, lease)
            .await
        {
            tracing::debug!(error = %error, "stream lease renewal failed; the next one retries");
        }
        let holder = super::federated::LeaseHolder {
            principal_key: &self.principal_key,
            identity: &self.identity,
            arguments: &self.arguments,
        };
        core.note_lease_demand(
            &self.stores,
            &self.ty,
            &holder,
            now,
            self.heartbeat.as_millis() as u64,
            lease,
        )
        .await;
        None
    }

    /// After a change of the config or the catalog, keep serving the type
    /// as it is now, or end the stream: `terminated` when the type is gone,
    /// its schema broke or it stopped offering push, a plain close when
    /// events stopped or the type reads another log now.
    fn follow_config(&mut self, core: &EventsCore) -> Option<Close> {
        let version = core.catalog_version();
        if version == self.catalog_version {
            return None;
        }
        self.catalog_version = version;
        let config = core.config();
        let same_stores = core
            .stores()
            .is_some_and(|stores| Arc::ptr_eq(&stores, &self.stores));
        if !config.enabled || !same_stores {
            return Some(Close::Server);
        }
        let catalog = core.catalog();
        let Some(ty) = catalog.get(&self.ty.name).cloned() else {
            return Some(Close::Terminated(TerminationReason::TypeRemoved));
        };
        if ty.schema_epoch != self.ty.schema_epoch {
            return Some(Close::Terminated(TerminationReason::SchemaChanged));
        }
        if !ty.offers(DeliveryMode::Push) {
            return Some(Close::Terminated(TerminationReason::PushWithdrawn));
        }
        if ty.source_key != self.ty.source_key {
            return Some(Close::Server);
        }
        self.numbering = config.error_codes.numbering();
        self.reauthorize = Duration::from_millis(config.reauthorize_interval_ms);
        self.ty = ty;
        None
    }

    fn cursor(&self, seq: u64) -> Option<String> {
        self.cursor_in(self.epoch, seq)
    }

    fn cursor_in(&self, epoch: u64, seq: u64) -> Option<String> {
        (self.ty.replay == EventReplay::Log).then(|| {
            self.stores
                .log
                .seal_cursor(epoch, self.ty.schema_epoch, seq, &self.scope)
        })
    }

    /// Send `frame`; `false` once the client is gone.
    async fn send(&self, frame: StreamFrame) -> bool {
        self.tx
            .send(frame.to_notification(&self.request_id))
            .await
            .is_ok()
    }
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
