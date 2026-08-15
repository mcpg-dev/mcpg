//! SSE stream lifecycle for the HTTP transport.
//!
//! Owns what a long-lived stream reserves and releases: the per-session
//! concurrency slot ([`SseStreamSlot`]), the `resources/updated` registrations a
//! `subscriptions/listen` stream holds ([`ResourceSubscriptionGuard`]), and the
//! [`SlottedEventStream`] wrapper that ties both to the response body's
//! lifetime. Every long-lived body goes out through that wrapper, so what a
//! stream releases on drop is readable in one place.
//!
//! Also holds the delivery-bus → SSE-event conversion. Those closures capture
//! the session store rather than the runtime: a strong runtime handle would
//! outlive a hot reload for as long as the stream stays open.

use super::*;

pub(crate) type SseStreamCounts =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>;

/// RAII reservation of one of a session's [`crate::app::MAX_SSE_STREAMS_PER_SESSION`]
/// concurrent SSE slots. Held for the exact lifetime of the SSE response body
/// (see [`SlottedEventStream`]); dropping it — on client disconnect or orderly
/// stream completion — releases the slot and prunes the map entry at zero. This
/// makes the cap CONCURRENT rather than cumulative-per-lifetime: the old
/// open-only counting never decremented, so it leaked one map entry per stream
/// (unbounded for row-less modern sessions, which never terminate) and bricked
/// legitimate SSE reconnects after three drops.
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

/// Reserve a concurrent SSE slot for `session_id`. Returns the RAII guard, or
/// `None` when the session is already at its concurrent cap (caller answers
/// `429`).
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

/// SSE event stream that owns an [`SseStreamSlot`] for its whole lifetime, so
/// the per-session concurrent-stream count is released precisely when the
/// stream is dropped. The boxed inner stream is `Unpin`, so is this wrapper.
pub(crate) struct SlottedEventStream {
    pub(crate) inner:
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>>,
    pub(crate) _slot: Option<SseStreamSlot>,
    /// `resources/updated` registrations owned by this stream, released on
    /// drop. `None` for streams that registered none (every legacy path).
    pub(crate) _resource_subscriptions: Option<ResourceSubscriptionGuard>,
}

impl tokio_stream::Stream for SlottedEventStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}

/// Upgrade a suspended POST request into a long-lived SSE continuation.
///
/// The stream replays any server-initiated messages already buffered in the
/// session (typically the `elicitation/create`, `sampling/createMessage`, or
/// `roots/list` request that caused the pipeline to suspend) and then
/// subscribes to the delivery bus so the terminal JSON-RPC response arrives on
/// the same stream once the pipeline resumes.
pub(crate) async fn open_post_continuation_sse(
    state: &AppState,
    session_id: &str,
    request_id: &GatewayRequestId,
) -> Response {
    let runtime = state.runtime.load();

    // Reserve a concurrent SSE slot, same as `GET /mcp` and
    // `subscriptions/listen`. This is a long-lived body holding a delivery-bus
    // subscription, so it counts against the per-session cap like any other;
    // exempting it left the cap enforceable on two of three stream kinds.
    let sse_slot = match acquire_sse_slot(&state.sse_stream_counts, session_id) {
        Some(slot) => slot,
        None => {
            metrics::counter!(
                "mcpg_sse_stream_limit_rejected_total",
                "session_id" => session_id.to_owned(),
            )
            .increment(1);
            return with_request_id_header(
                axum::http::StatusCode::TOO_MANY_REQUESTS.into_response(),
                request_id,
            );
        }
    };

    // Open a fresh SSE stream on the session. This allocates the per-stream
    // state needed before any `stream_raw_message` call can land events on it,
    // and produces any priming/replay events the session wants to emit first.
    let mut sse_records: Vec<SseEventRecord> = Vec::new();
    let continuation_context = RequestContext::new(
        GatewayRequestId::new(),
        Some(request_id.as_str().to_owned()),
        Some(session_id.to_owned()),
        None::<ResumeCursor>,
        RequestIdentity::Anonymous {
            source: "http-post-continuation".to_owned(),
        },
        TransportKind::Http,
    );
    match runtime.open_sse_stream(&continuation_context) {
        Ok(events) => sse_records.extend(events),
        Err(err) => {
            tracing::warn!(
                session_id = %session_id,
                error = ?err,
                "post continuation: failed to open SSE stream for suspended request"
            );
            return with_request_id_header(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                request_id,
            );
        }
    }

    // Drain any pending deliveries (the server-initiated request that caused
    // the suspension) and convert them into indexed SSE events on the freshly
    // opened stream so they land in the replay window.
    let pending = runtime.take_pending_deliveries(session_id);
    for msg in pending {
        if let Ok(records) = runtime.stream_delivery_message(
            session_id,
            &msg.jsonrpc_message.to_string(),
            &msg.delivery_id,
        ) {
            sse_records.extend(records);
        }
    }
    let initial = iter(sse_records.into_iter().map(sse_event_from_record));

    // Subscribe to the delivery bus so later messages (including the terminal
    // response once the pipeline resumes) stream on this same POST connection.
    // Capture the session store, not the runtime: a strong `Arc<GatewayRuntime>`
    // here would outlive a hot reload for as long as the stream is open, keeping
    // the retired plugin registry and watch engine alive. The store is created
    // once at boot and carried across every reload, so it is both the narrower
    // handle and the correct one — a post-reload stream writes to the same rows
    // it always did.
    let store = state.session_store.clone();
    let sid_owned = session_id.to_owned();
    let live = delivery_bus_sse(&runtime, session_id, move |msg| {
        delivery_to_sse_event(&store, &sid_owned, msg)
    })
    .await;

    // Same wrapper every long-lived SSE body uses, so what this stream releases
    // on drop is readable from one struct.
    let guarded = SlottedEventStream {
        inner: Box::pin(initial.chain(live)),
        _slot: Some(sse_slot),
        _resource_subscriptions: None,
    };
    with_request_id_header(
        Sse::new(guarded)
            .keep_alive(KeepAlive::default())
            .into_response(),
        request_id,
    )
}

/// `subscriptions/listen` long-lived POST-SSE handler.
///
/// The modern wire's replacement for the legacy GET-/mcp delivery
/// channel + `resources/subscribe`/`unsubscribe` methods. The
/// client POSTs a list of subscription targets; the server holds
/// the connection open and streams matching events as SSE
/// messages. The first event is the acknowledgement carrying the
/// `subscriptionId` (= the listen request's JSON-RPC id) and the
/// honored-subset `notifications` object.
///
/// SEP-2567/2575: imposes no `Mcp-Session-Id` requirement on the
/// client and never echoes one. The server-internal synthetic
/// session (principal-derived, minted by `ensure_modern_session`)
/// keys the cross-instance delivery bus; the client-facing
/// `subscriptionId` is decoupled from it.
/// Holds the `resources/updated` leases taken for one `subscriptions/listen`
/// stream and releases them when it ends.
///
/// The modern wire has no `resources/unsubscribe`: the stream's lifetime *is*
/// the subscription's, so teardown belongs to `Drop` rather than to a method
/// the client is expected to call. Each target is a lease rather than a bare
/// store row because a principal's synthetic session is shared by every stream
/// they open — two streams watching one resource must not be able to
/// unsubscribe each other.
pub(crate) struct ResourceSubscriptionGuard {
    leases: Vec<crate::runtime::subscriptions::SubscriptionLease>,
}

impl ResourceSubscriptionGuard {
    /// The `resources/updated` URIs this stream actually established — a
    /// subset of what the client asked for.
    ///
    /// The ack's `resourceSubscriptions` is built from exactly this list, so it
    /// cannot name a target the gateway skipped: the only URIs the client is
    /// told about are the ones this guard holds a lease on.
    pub(crate) fn established(&self) -> Vec<String> {
        self.leases
            .iter()
            .map(|lease| lease.uri().to_owned())
            .collect()
    }
}

/// Take `resources/updated` leases for the targets of a `subscriptions/listen`
/// call.
///
/// Unknown URIs — and targets the subscription store refuses — are skipped
/// rather than failing the stream: the other targets in the same listen call
/// are still legitimate, and the ack reports only what was established.
pub(crate) async fn register_modern_resource_subscriptions(
    runtime: &std::sync::Arc<crate::runtime::GatewayRuntime>,
    session_id: &str,
    request_context: &crate::runtime::RequestContext,
    uris: &[String],
) -> ResourceSubscriptionGuard {
    use crate::runtime::stores::subscription_store::SubscriberIdentity;

    let identity = Some(SubscriberIdentity::from_request_context(
        session_id,
        request_context,
    ));

    let subscriptions = runtime.subscriptions();
    let mut leases = Vec::with_capacity(uris.len());
    for uri in uris {
        if runtime.resolve_resource_route(uri).is_none() {
            tracing::debug!(
                uri = %uri,
                "subscriptions/listen: skipping resources/updated target for an unknown resource"
            );
            continue;
        }
        // Same authz stack `resources/read` and the legacy subscribe arm
        // run. The audit record below already recognises a subscription as
        // "the same grant of ongoing access"; the authorization for that
        // grant was the part still missing on this wire. A denied URI is
        // skipped rather than failing the whole listen, mirroring how an
        // unknown resource is handled above.
        let args_value = serde_json::json!({ "uri": uri });
        let request_id = serde_json::json!(request_context.request_id.as_str());
        if runtime
            .evaluate_surface_gate(
                "resource",
                "resource.subscribe.pre",
                uri,
                &args_value,
                request_context,
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
        if let Some(lease) = subscriptions
            .acquire(session_id, uri, identity.clone())
            .await
        {
            // Same audit record the legacy `resources/subscribe` arm writes.
            // A subscription established here is the same grant of ongoing
            // access, so leaving it unaudited would make the modern wire the
            // way to subscribe without a trail.
            let audit_ctx = mcpg_plugin_protocol::PluginContext {
                request_id: request_context.request_id.as_str().to_owned(),
                session_id: Some(session_id.to_owned()),
                tool_name: uri.clone(),
                identity: crate::runtime::plugin_identity_from_request(request_context),
                transport: crate::runtime::transport_label(&request_context.transport).to_owned(),
                surface: "resource".to_owned(),
            };
            let event = mcpg_plugin_host::audit_events::resource_subscribe_event(&audit_ctx, uri);
            let _ = runtime.plugin_registry().emit_audit_event(&event).await;
            leases.push(lease);
        }
    }
    metrics::counter!("mcpg_subscriptions_listen_resources_registered_total")
        .increment(leases.len() as u64);

    ResourceSubscriptionGuard { leases }
}

/// default reconnect hint in milliseconds. Emitted on every
/// SSE event when the record does not carry an explicit retry_ms so
/// a client that loses the stream always has a usable backoff.
pub(crate) const DEFAULT_SSE_RETRY_MS: u64 = 3_000;

/// Convert an SseEventRecord to an axum SSE Event.
/// Uses explicit `.event("message")` per MCP spec.
pub(crate) fn sse_event_from_record(event: SseEventRecord) -> Result<Event, Infallible> {
    let mut sse_event = Event::default().event("message").id(event.event_id);
    // emit retry: on every event — default when the record
    // does not specify one. Prior implementation only emitted a retry
    // hint when the server-side record carried one, which in practice
    // was almost never.
    let retry_ms = event.retry_ms.unwrap_or(DEFAULT_SSE_RETRY_MS);
    sse_event = sse_event.retry(std::time::Duration::from_millis(retry_ms));
    Ok(sse_event.data(event.data))
}

/// Content-derived dedupe key for a delivery message. Used only to suppress
/// the race-window duplicate when the continuation SSE subscribes before
/// draining the backlog: a delivery that is both still in the backlog and
/// replayed on the live bus would otherwise be emitted twice. Hashing the
/// kind + JSON-RPC body identifies the same logical delivery across the two
/// carriers (KV row and bus message) without a wire-format change.
pub(crate) fn delivery_dedupe_key(msg: &DeliveryMessage) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Kind discriminant via its Debug label keeps distinct kinds with an
    // identical body (rare) from colliding.
    format!("{:?}", msg.kind).hash(&mut hasher);
    msg.jsonrpc_message.to_string().hash(&mut hasher);
    hasher.finish()
}

/// Convert a DeliveryMessage to an SSE event by streaming it through the session store
/// so it gets a proper event ID and is persisted in the replay window.
pub(crate) fn delivery_to_sse_event(
    session_store: &std::sync::Arc<dyn crate::runtime::session_store::SessionStore>,
    session_id: &str,
    msg: DeliveryMessage,
) -> Option<Result<Event, Infallible>> {
    let message_json = msg.jsonrpc_message.to_string();
    // Tag the live event id with the delivery's backlog id so a later
    // reconnect echoing it as Last-Event-Id prunes the backlog row the
    // client already received live.
    match session_store.stream_message(session_id, &message_json, &msg.delivery_id) {
        Ok(records) => records.into_iter().next().map(sse_event_from_record),
        Err(_) => {
            // If streaming fails (session expired, etc.), deliver the raw message
            // without replay support as a best-effort fallback.
            Some(Ok(Event::default().data(message_json)))
        }
    }
}

/// Subscribe to a session's server-push delivery bus and turn each
/// delivered message into an SSE event through `filter`. The
/// subscribe + `ReceiverStream` wrapping is identical at every call
/// site; each site supplies its own `filter` (pass-through with
/// replay tagging, backlog-dedupe, or `subscriptions/listen` target
/// matching).
pub(crate) async fn delivery_bus_sse<F>(
    runtime: &crate::runtime::GatewayRuntime,
    session_id: &str,
    filter: F,
) -> impl tokio_stream::Stream<Item = Result<Event, Infallible>> + Send + use<F>
where
    F: FnMut(DeliveryMessage) -> Option<Result<Event, Infallible>> + Send + 'static,
{
    let delivery_rx = runtime.subscribe_session_delivery(session_id).await;
    ReceiverStream::new(delivery_rx).filter_map(filter)
}

#[cfg(test)]
mod delivery_dedupe_tests {
    use super::delivery_dedupe_key;
    use crate::runtime::pipeline_store::{DeliveryKind, DeliveryMessage};

    fn msg(kind: DeliveryKind, body: serde_json::Value) -> DeliveryMessage {
        DeliveryMessage {
            kind,
            jsonrpc_message: body,
            delivery_id: String::new(),
        }
    }

    #[test]
    fn identical_deliveries_share_a_key() {
        // The KV-persisted copy and the bus-published copy of the same
        // delivery have identical kind + body, so they collapse to one key —
        // letting the continuation SSE suppress the race-window duplicate.
        let a = msg(
            DeliveryKind::DeferredToolResult,
            serde_json::json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}}),
        );
        let b = msg(
            DeliveryKind::DeferredToolResult,
            serde_json::json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}}),
        );
        assert_eq!(delivery_dedupe_key(&a), delivery_dedupe_key(&b));
    }

    #[test]
    fn distinct_bodies_differ() {
        let a = msg(DeliveryKind::ServerRequest, serde_json::json!({"id":1}));
        let b = msg(DeliveryKind::ServerRequest, serde_json::json!({"id":2}));
        assert_ne!(delivery_dedupe_key(&a), delivery_dedupe_key(&b));
    }

    #[test]
    fn same_body_distinct_kinds_differ() {
        let body = serde_json::json!({"x":1});
        let a = msg(DeliveryKind::ServerRequest, body.clone());
        let b = msg(DeliveryKind::DeferredToolResult, body);
        assert_ne!(delivery_dedupe_key(&a), delivery_dedupe_key(&b));
    }
}
