//! `events/stream` — one MCP Events push subscription as a POST whose SSE
//! response carries only `notifications/events/*` frames.
//!
//! The method exists under the same conditions as the other `events/*`
//! methods. A request that is refused gets one JSON-RPC error and no
//! stream. The stream holds no session server-push slot: it is one
//! subscription, bounded by its own per-principal cap. Heartbeats are SSE
//! data frames, never comments, because they carry the cursor; there is no
//! SSE keep-alive and no event id, since a client resumes with its cursor.

use super::*;
use crate::protocol::v_2026_07_28::dispatch::events::{
    events_error_response, events_served, live_events_config, method_not_found, plan_rps_refusal,
};
use crate::protocol::v_2026_07_28::extensions::events::errors::EventsError;
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    METHOD_STREAM_EVENTS, StreamEventsParams,
};

pub(crate) async fn modern_events_stream_handler(
    state: AppState,
    request_context: RequestContext,
    body: Value,
    client_accepts_sse: bool,
) -> Response {
    let request_id = body.get("id").cloned().unwrap_or(Value::Null);
    let services = state.runtime.load().shared_services.load_full();
    let core = services
        .as_ref()
        .filter(|services| {
            events_served(
                &live_events_config(services),
                services,
                &request_context.transport,
            )
        })
        .and_then(|services| services.events_core.get().cloned());
    let (Some(services), Some(core)) = (services, core) else {
        return finish(
            method_not_found(request_id, METHOD_STREAM_EVENTS),
            &request_context,
        );
    };
    let numbering = live_events_config(&services).error_codes.numbering();
    if let Err(limit) = state.runtime.load().admit_plan_rps("events") {
        return finish(
            plan_rps_refusal(Some(request_id.clone()), limit, numbering),
            &request_context,
        );
    }
    let refuse = |error: EventsError| {
        finish(
            events_error_response(Some(request_id.clone()), error, numbering),
            &request_context,
        )
    };
    if !client_accepts_sse {
        return refuse(EventsError::invalid_params(
            "events/stream answers with text/event-stream; the request's Accept must list it",
        ));
    }
    let params: StreamEventsParams =
        match serde_json::from_value(body.get("params").cloned().unwrap_or(Value::Null)) {
            Ok(params) => params,
            Err(_) => {
                return refuse(EventsError::invalid_params(
                    "events/stream params must name the event type",
                ));
            }
        };
    let frames = match core
        .open_stream(&request_context, params, request_id.clone())
        .await
    {
        Ok(frames) => frames,
        Err(error) => return refuse(error),
    };
    let events = tokio_stream::wrappers::ReceiverStream::new(frames).map(|message| {
        Ok::<_, Infallible>(Event::default().event("message").data(message.to_string()))
    });
    let response = Sse::new(events).into_response();
    with_request_id_header(response, &request_context.request_id)
}

fn finish(response: ProtocolHttpResponse, request_context: &RequestContext) -> Response {
    with_request_id_header(
        super::response::map_protocol_http_response(response),
        &request_context.request_id,
    )
}
