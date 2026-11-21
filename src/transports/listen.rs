//! `subscriptions/listen`: one long-lived stream of the notifications a
//! request names, on HTTP (an SSE response) and on stdio (JSON lines).
//!
//! [`open_listen`] runs the checks and takes the resources the stream holds:
//! the row of an anonymous caller's session ([`EphemeralRow`]), the caller
//! must own the session, the session has a cap on concurrent streams
//! ([`SseStreamSlot`]), and every `resources/updated` target is a
//! subscription lease with its realtime admission
//! ([`ResourceSubscriptionGuard`]). The returned [`ListenStream`] owns all of
//! them, so what a stream releases when it is dropped is readable in one
//! place.
//!
//! The stream reads the session's delivery bus. Its closures capture weak
//! runtime handles: a strong one would keep a runtime alive past a hot
//! reload for as long as the stream stays open.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use futures::StreamExt as _;
use futures::stream::BoxStream;
use serde_json::Value;

use crate::app::AppState;
use crate::protocol::ProtocolError;
use crate::protocol::v_2026_07_28::wire::subscriptions::{
    self, SubscriptionTarget, SubscriptionsListenParams,
};
use crate::runtime::{GatewayRuntime, RequestContext};

/// Concurrent listen streams per session, keyed by session id.
pub(crate) type SseStreamCounts =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>;

/// RAII reservation of one of a session's
/// [`crate::app::MAX_SSE_STREAMS_PER_SESSION`] concurrent stream slots. Held
/// for the lifetime of the stream; dropping it (client disconnect or orderly
/// end) releases the slot and prunes the map entry at zero, so the cap
/// counts open streams, not streams ever opened.
pub(crate) struct SseStreamSlot {
    counts: SseStreamCounts,
    session_id: String,
}

impl Drop for SseStreamSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            let now_zero = counts.get_mut(&self.session_id).map(|n| {
                *n = n.saturating_sub(1);
                *n == 0
            });
            if now_zero == Some(true) {
                counts.remove(&self.session_id);
            }
        }
    }
}

/// Reserve a concurrent stream slot for `session_id`. Returns the RAII guard,
/// or `None` when the session is already at its cap.
pub(crate) fn acquire_sse_slot(
    counts: &SseStreamCounts,
    session_id: &str,
) -> Option<SseStreamSlot> {
    {
        let mut guard = counts.lock().expect("sse lock");
        let n = guard.entry(session_id.to_owned()).or_insert(0);
        if *n >= crate::app::MAX_SSE_STREAMS_PER_SESSION {
            return None;
        }
        *n += 1;
    }
    Some(SseStreamSlot {
        counts: std::sync::Arc::clone(counts),
        session_id: session_id.to_owned(),
    })
}

/// The row an anonymous caller's listen stream created for its session. No
/// other request can name that session, so the row ends with the stream.
struct EphemeralRow {
    /// Weak: a stream must not keep a runtime alive past a hot reload.
    runtime: Weak<ArcSwap<GatewayRuntime>>,
    session_id: String,
}

impl Drop for EphemeralRow {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let session_id = std::mem::take(&mut self.session_id);
        // Ending a session reaches the session store, which may block, so it
        // runs off the task that drops the stream.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    runtime.load().terminate_session(&session_id);
                });
            }
            Err(_) => {
                runtime.load().terminate_session(&session_id);
            }
        }
    }
}

/// Why a `subscriptions/listen` request gets no stream.
pub(crate) enum ListenRefusal {
    /// The params do not parse, or the realtime admission refused a target.
    Error(ProtocolError),
    /// The caller does not own the session; answered as for an unknown one,
    /// so the session's existence does not leak.
    NotOwner,
    /// The session already holds its maximum of concurrent streams.
    TooManyStreams,
    /// The anonymous caller's session got no row: the session store or the
    /// session cap refused it.
    CapacityExhausted,
}

impl ListenRefusal {
    /// The refusal as a JSON-RPC error of request `id`, for a transport with
    /// no HTTP status to carry it.
    pub(crate) fn into_protocol_error(self, id: Option<Value>) -> ProtocolError {
        match self {
            Self::Error(error) => error,
            Self::CapacityExhausted => {
                let rejection = crate::transports::dispatch::capacity_exhausted(id.clone());
                ProtocolError::application(id, rejection.error_code, rejection.message, None)
            }
            Self::NotOwner => ProtocolError::application(
                id,
                crate::protocol::INVALID_REQUEST_CODE,
                "unknown session",
                None,
            ),
            Self::TooManyStreams => ProtocolError::application(
                id,
                -32000,
                "too many concurrent subscriptions/listen streams on this session",
                None,
            ),
        }
    }
}

/// The frames of one `subscriptions/listen` stream, in order: the
/// `notifications/subscriptions/acknowledged` frame with the honored filter,
/// each matching notification with the subscription id in `_meta`, and —
/// when the server ends the stream because the session ended — the listen
/// request's result. No frame has an SSE event id: a dropped stream is not
/// resumed, the client listens again.
///
/// Owns the session's stream slot, the stream's resource subscriptions and
/// the row of an anonymous caller's session; all are released when the
/// stream is dropped, the row last.
pub(crate) struct ListenStream {
    frames: BoxStream<'static, Value>,
    _slot: SseStreamSlot,
    _resources: Option<ResourceSubscriptionGuard>,
    _row: Option<EphemeralRow>,
}

impl futures::Stream for ListenStream {
    type Item = Value;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Value>> {
        self.get_mut().frames.poll_next_unpin(cx)
    }
}

/// Open the `subscriptions/listen` stream `body` asks for, on `session_id`.
///
/// The stream of an anonymous caller is the only thing its session keeps, so
/// the session's row is created once the params parse and ends with the
/// stream, or with the refusal. The owner check runs before the slot is
/// taken, so a foreign caller cannot use up the owner's slots.
/// `resources/updated` targets are registered before the acknowledgement is
/// built, because the acknowledgement reports what was established: a URI no
/// resource route resolves, one the caller may not read, or one the store
/// rejected is not acknowledged.
pub(crate) async fn open_listen(
    state: &AppState,
    ctx: &RequestContext,
    session_id: &str,
    body: &Value,
) -> Result<ListenStream, ListenRefusal> {
    let request_id = body.get("id").cloned().unwrap_or(Value::Null);
    let Some(params) = body.get("params").cloned() else {
        return Err(ListenRefusal::Error(ProtocolError::invalid_params(
            Some(request_id),
            "missing subscriptions/listen params",
            None,
        )));
    };
    let params: SubscriptionsListenParams = serde_json::from_value(params).map_err(|error| {
        ListenRefusal::Error(ProtocolError::invalid_params(
            Some(request_id.clone()),
            format!("invalid subscriptions/listen params: {error}"),
            None,
        ))
    })?;
    if params
        .subscriptions
        .iter()
        .any(|target| matches!(target, SubscriptionTarget::TasksStatus { .. }))
        && !crate::protocol::v_2026_07_28::dispatch::tasks::client_declared_tasks_extension(ctx)
    {
        use crate::protocol::v_2026_07_28::extensions::tasks::wire::{
            TASKS_CAPABILITY_REQUIRED_MESSAGE, required_capabilities_data,
        };
        return Err(ListenRefusal::Error(ProtocolError::application(
            Some(request_id),
            crate::protocol::MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
            TASKS_CAPABILITY_REQUIRED_MESSAGE,
            Some(required_capabilities_data()),
        )));
    }

    let runtime = state.runtime.load_full();
    let row = if ctx.session_ephemeral {
        if !runtime.materialize_ephemeral_session(session_id) {
            return Err(ListenRefusal::CapacityExhausted);
        }
        Some(EphemeralRow {
            runtime: Arc::downgrade(&state.runtime),
            session_id: session_id.to_owned(),
        })
    } else {
        None
    };
    if !runtime.caller_owns_session(session_id, ctx) {
        return Err(ListenRefusal::NotOwner);
    }
    let Some(slot) = acquire_sse_slot(&state.sse_stream_counts, session_id) else {
        metrics::counter!("mcpg_sse_stream_limit_rejected_total").increment(1);
        return Err(ListenRefusal::TooManyStreams);
    };
    metrics::counter!("mcpg_subscriptions_listen_opened_total").increment(1);

    // `resources/updated` targets are subscriptions, not only a filter: the
    // watch engine produces an update only for a URI that is watched. The
    // guard ends the subscriptions with the stream.
    let watched: Vec<String> = params
        .subscriptions
        .iter()
        .filter_map(|target| match target {
            SubscriptionTarget::ResourcesUpdated { uri } => Some(uri.clone()),
            _ => None,
        })
        .collect();
    let resources = if watched.is_empty() {
        None
    } else {
        Some(
            register_resource_subscriptions(&runtime, &state.runtime, session_id, ctx, &watched)
                .await
                .map_err(|denial| {
                    ListenRefusal::Error(ProtocolError::application(
                        Some(request_id.clone()),
                        denial.code,
                        denial.message,
                        denial.data,
                    ))
                })?,
        )
    };
    let established = resources
        .as_ref()
        .map(ResourceSubscriptionGuard::established)
        .unwrap_or_default();
    let ack = subscriptions::acknowledged_notification(
        &request_id,
        &params.honored_notifications(&established),
    );

    // The bus is keyed by the session, which is internal; the client-facing
    // subscription id is the listen request's JSON-RPC id, as sent.
    let targets = params.subscriptions;
    let subscription_id = request_id.clone();
    let receipts = UpdateReceipts::new(&state.runtime, ctx);
    let ended: Pin<Box<dyn Future<Output = ()> + Send>> =
        match runtime.session_store().session_lifetime(session_id) {
            Some(lifetime) => Box::pin(lifetime.ended()),
            None => Box::pin(std::future::pending()),
        };
    let deliveries = runtime.subscribe_session_delivery(session_id).await;
    let live = tokio_stream::wrappers::ReceiverStream::new(deliveries)
        .filter_map(move |delivery| {
            std::future::ready(listen_frame(
                &targets,
                &subscription_id,
                &receipts,
                delivery.jsonrpc_message,
            ))
        })
        .take_until(ended);
    // The session ended (terminated, or idle everywhere): the result tells
    // the client the close is orderly, not a dropped connection.
    let close = subscriptions::closed_stream_result(&request_id);
    let frames = futures::stream::once(std::future::ready(ack))
        .chain(live)
        .chain(futures::stream::once(std::future::ready(close)))
        .boxed();
    Ok(ListenStream {
        frames,
        _slot: slot,
        _resources: resources,
        _row: row,
    })
}

/// The frame a delivery becomes on a listen stream: `None` when no target
/// matches it, else the notification with the subscription id in `_meta`.
fn listen_frame(
    targets: &[SubscriptionTarget],
    subscription_id: &Value,
    receipts: &UpdateReceipts,
    mut payload: Value,
) -> Option<Value> {
    let method = payload
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !subscriptions::subscription_matches(targets, method, &payload) {
        return None;
    }
    receipts.record(&payload, &subscription_id.to_string());
    subscriptions::inject_subscription_id_meta(&mut payload, subscription_id);
    Some(payload)
}

/// Writes one `mcpg.resource.updated_delivered` receipt for each
/// `notifications/resources/updated` a stream hands its client, through the
/// runtime current at that moment.
struct UpdateReceipts {
    /// Weak: a stream must not keep the runtime (and its delivery bus) alive
    /// past the gateway's own handle.
    runtime: Weak<ArcSwap<GatewayRuntime>>,
    actor: mcpg_plugin_protocol::PluginIdentity,
    request_id: String,
    client: Option<Value>,
}

impl UpdateReceipts {
    fn new(runtime: &Arc<ArcSwap<GatewayRuntime>>, ctx: &RequestContext) -> Self {
        Self {
            runtime: Arc::downgrade(runtime),
            actor: crate::runtime::plugin_identity_from_request(ctx),
            request_id: ctx.request_id.as_str().to_owned(),
            client: ctx
                .client()
                .map(|c| serde_json::json!({ "name": c.name, "version": c.version })),
        }
    }

    fn record(&self, message: &Value, subscription_id: &str) {
        if message.get("method").and_then(Value::as_str) != Some("notifications/resources/updated")
        {
            return;
        }
        let uri = message
            .pointer("/params/uri")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        metrics::counter!("mcpg_resource_updates_delivered_total").increment(1);
        let event = mcpg_plugin_protocol::audit::AuditEvent {
            event_id: mcpg_plugin_host::audit_events::new_event_id(),
            occurred_at: mcpg_plugin_host::audit_events::now_rfc3339_utc(),
            actor: self.actor.clone(),
            action: "mcpg.resource.updated_delivered".to_owned(),
            resource: Some(format!("resource://{uri}")),
            outcome: mcpg_plugin_protocol::audit::AuditOutcome::Success,
            request_id: Some(self.request_id.clone()),
            upstream_request_id: None,
            node_id: None,
            details: serde_json::json!({
                "uri": uri,
                "subscription_id": subscription_id,
                "client": self.client,
            }),
            prev_event_hash: None,
        };
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let runtime = runtime.load_full();
        tokio::spawn(async move {
            let _ = runtime.plugin_registry().emit_audit_event(&event).await;
        });
    }
}

/// Holds the `resources/updated` leases taken for one `subscriptions/listen`
/// stream and releases them when it ends.
///
/// The stream's lifetime is the subscription's, so teardown belongs to
/// `Drop`. Each target is a lease rather than a bare store row because a
/// principal's session is shared by every stream they open: two streams
/// watching one resource must not be able to unsubscribe each other.
struct ResourceSubscriptionGuard {
    leases: Arc<parking_lot::Mutex<Vec<crate::runtime::subscriptions::SubscriptionLease>>>,
    /// What the realtime admission holds for this stream: released when the
    /// stream ends, renewed by `renewal` until then.
    admitted: Option<ListenAdmission>,
    /// The `mcpg.resource.unsubscribe` records the close of the stream
    /// writes, one for each lease, through the runtime current then (the
    /// swappable handle, so a stream keeps no reloaded-away registry).
    on_close: Option<(
        Weak<ArcSwap<GatewayRuntime>>,
        Vec<mcpg_plugin_protocol::audit::AuditEvent>,
    )>,
}

/// The admission leases of one `subscriptions/listen` stream.
struct ListenAdmission {
    runtime: Weak<ArcSwap<GatewayRuntime>>,
    identity: crate::runtime::RequestIdentity,
    client: Option<mcpg_plugin_protocol::ClientInfo>,
    /// The leases still held; a refused renewal takes its lease out.
    held: Arc<parking_lot::Mutex<Vec<crate::runtime::admission::AdmissionLease>>>,
    renewal: tokio::task::JoinHandle<()>,
}

impl Drop for ListenAdmission {
    fn drop(&mut self) {
        self.renewal.abort();
        let held = std::mem::take(&mut *self.held.lock());
        let (Some(runtime), Ok(handle)) = (
            self.runtime.upgrade(),
            tokio::runtime::Handle::try_current(),
        ) else {
            return;
        };
        let (identity, client) = (self.identity.clone(), self.client.clone());
        handle.spawn(async move {
            let runtime = runtime.load_full();
            for lease in &held {
                runtime
                    .realtime_release(&identity, client.as_ref(), lease)
                    .await;
            }
        });
    }
}

/// Renew every lease in `held` at the admission's pace. A refused renewal
/// ends that target's subscription: its lease leaves `held` and its
/// subscription lease leaves `leases`.
async fn renew_listen_admission(
    runtime: Weak<ArcSwap<GatewayRuntime>>,
    identity: crate::runtime::RequestIdentity,
    client: Option<mcpg_plugin_protocol::ClientInfo>,
    held: Arc<parking_lot::Mutex<Vec<crate::runtime::admission::AdmissionLease>>>,
    leases: Arc<parking_lot::Mutex<Vec<crate::runtime::subscriptions::SubscriptionLease>>>,
    mut renew_after: std::time::Duration,
) {
    use crate::runtime::admission::{AdmissionOp, AdmissionTarget};
    loop {
        tokio::time::sleep(renew_after).await;
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        let runtime = runtime.load_full();
        let current = held.lock().clone();
        if current.is_empty() {
            return;
        }
        for lease in current {
            match runtime
                .realtime_admit(AdmissionOp::Renew, &identity, client.as_ref(), &lease)
                .await
            {
                Ok(Some(grant)) => renew_after = renew_after.min(grant.renew_after),
                Ok(None) => return,
                Err(denial) => {
                    let AdmissionTarget::Resource { uri } = &lease.target else {
                        continue;
                    };
                    tracing::info!(
                        uri = %uri,
                        code = denial.code,
                        "the realtime admission refused a renewal; the listen target ends"
                    );
                    held.lock().retain(|kept| kept.id != lease.id);
                    let ended: Vec<_> = {
                        let mut leases = leases.lock();
                        let (ended, kept) = std::mem::take(&mut *leases)
                            .into_iter()
                            .partition(|held| held.uri() == uri);
                        *leases = kept;
                        ended
                    };
                    drop(ended);
                }
            }
        }
    }
}

impl Drop for ResourceSubscriptionGuard {
    fn drop(&mut self) {
        self.admitted.take();
        let Some((runtime, mut events)) = self.on_close.take() else {
            return;
        };
        if events.is_empty() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        let runtime = runtime.load_full();
        let now = mcpg_plugin_host::audit_events::now_rfc3339_utc();
        for event in &mut events {
            event.occurred_at = now.clone();
        }
        handle.spawn(async move {
            for event in &events {
                let _ = runtime.plugin_registry().emit_audit_event(event).await;
            }
        });
    }
}

impl ResourceSubscriptionGuard {
    /// The `resources/updated` URIs this stream established: a subset of
    /// what the client asked for. The acknowledgement's
    /// `resourceSubscriptions` is built from exactly this list.
    fn established(&self) -> Vec<String> {
        self.leases
            .lock()
            .iter()
            .map(|lease| lease.uri().to_owned())
            .collect()
    }
}

/// Take `resources/updated` leases for the targets of a `subscriptions/listen`
/// call.
///
/// An unknown URI, one the caller may not read, and one the subscription
/// store refuses are skipped rather than failing the stream: the other
/// targets of the same call are still legitimate, and the acknowledgement
/// reports only what was established. A refusal by the realtime admission
/// fails the call with the admission's own error, which names what the
/// caller can do about it.
async fn register_resource_subscriptions(
    runtime: &Arc<GatewayRuntime>,
    runtime_handle: &Arc<ArcSwap<GatewayRuntime>>,
    session_id: &str,
    ctx: &RequestContext,
    uris: &[String],
) -> Result<ResourceSubscriptionGuard, crate::runtime::admission::AdmissionDenial> {
    use crate::runtime::admission::AdmissionOp;
    use crate::runtime::stores::subscription_store::SubscriberIdentity;

    let client = ctx.client();
    let mut admitted = Vec::new();
    let mut renew_after: Option<std::time::Duration> = None;

    let identity = Some(SubscriberIdentity::from_request_context(session_id, ctx));

    let subscriptions = runtime.subscriptions();
    let mut leases = Vec::with_capacity(uris.len());
    let mut close_events = Vec::with_capacity(uris.len());
    for uri in uris {
        let Some(route) = runtime.resolve_resource_route(uri) else {
            tracing::debug!(
                uri = %uri,
                "subscriptions/listen: skipping resources/updated target for an unknown resource"
            );
            continue;
        };
        // The authorization `resources/read` runs: a subscription is an
        // ongoing grant of the same access.
        let request_id = serde_json::json!(ctx.request_id.as_str());
        if runtime
            .evaluate_resource_gate(
                "resource",
                "resource.subscribe.pre",
                uri,
                &route,
                ctx,
                &request_id,
            )
            .await
            .is_err()
        {
            tracing::debug!(
                uri = %uri,
                "subscriptions/listen: skipping resources/updated target the caller may not read"
            );
            continue;
        }
        let admission_lease = crate::runtime::admission::listen_resource_lease(uri);
        match runtime
            .realtime_admit(
                AdmissionOp::Admit,
                &ctx.identity,
                client.as_ref(),
                &admission_lease,
            )
            .await
        {
            Ok(Some(grant)) => {
                renew_after =
                    Some(renew_after.map_or(grant.renew_after, |r| r.min(grant.renew_after)));
                admitted.push(admission_lease);
            }
            Ok(None) => {}
            Err(denial) => {
                for lease in &admitted {
                    runtime
                        .realtime_release(&ctx.identity, client.as_ref(), lease)
                        .await;
                }
                return Err(denial);
            }
        }
        if let Some(lease) = subscriptions
            .acquire(session_id, uri, identity.clone())
            .await
        {
            let audit_ctx = mcpg_plugin_protocol::PluginContext {
                request_id: ctx.request_id.as_str().to_owned(),
                session_id: Some(session_id.to_owned()),
                tool_name: uri.clone(),
                identity: crate::runtime::plugin_identity_from_request(ctx),
                transport: crate::runtime::transport_label(&ctx.transport).to_owned(),
                surface: "resource".to_owned(),
            };
            let event = crate::runtime::audit_with_client(
                mcpg_plugin_host::audit_events::resource_subscribe_event(&audit_ctx, uri)
                    .with_upstream_request_id(ctx.upstream_request_id.clone()),
                ctx,
            );
            // Under `on_failure: fail_closed` a target the audit trail lost
            // is skipped: dropping the lease ends the subscription.
            if let Err(failure) = runtime
                .plugin_registry()
                .emit_request_audit_event(&event)
                .await
            {
                tracing::warn!(
                    uri = %uri,
                    error = %failure,
                    "subscriptions/listen: skipping a resources/updated target whose audit record was lost"
                );
                continue;
            }
            let mut closed = crate::runtime::audit_with_client(
                mcpg_plugin_host::audit_events::resource_unsubscribe_event(&audit_ctx, uri, true),
                ctx,
            );
            if let Some(details) = closed.details.as_object_mut() {
                details.insert("reason".to_owned(), serde_json::json!("stream_closed"));
            }
            close_events.push(closed);
            leases.push(lease);
        }
    }
    metrics::counter!("mcpg_subscriptions_listen_resources_registered_total")
        .increment(leases.len() as u64);

    let leases = Arc::new(parking_lot::Mutex::new(leases));
    let admitted = renew_after.map(|renew_after| {
        let held = Arc::new(parking_lot::Mutex::new(admitted));
        let weak = Arc::downgrade(runtime_handle);
        ListenAdmission {
            runtime: weak.clone(),
            identity: ctx.identity.clone(),
            client: client.clone(),
            held: Arc::clone(&held),
            renewal: tokio::spawn(renew_listen_admission(
                weak,
                ctx.identity.clone(),
                client,
                held,
                Arc::clone(&leases),
                renew_after,
            )),
        }
    });
    Ok(ResourceSubscriptionGuard {
        leases,
        admitted,
        on_close: Some((Arc::downgrade(runtime_handle), close_events)),
    })
}
