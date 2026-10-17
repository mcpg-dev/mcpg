//! The events core behind the `events/*` dispatch seam.
//!
//! `events/list` is served from the catalog: only the types the caller may
//! see, in name order, a page at a time. Visibility runs the same policy gate
//! a listing of any other surface runs, keyed `event:<name>`, so an event
//! type never inherits the rule of a tool with the same name.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::engine::EventsCore;
use crate::protocol::v_2026_07_28::dispatch::events::EventsHandler;
use crate::protocol::v_2026_07_28::extensions::events::errors::EventsError;
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    ListEventsParams, ListEventsResult, PollEventsParams, PollEventsResult, SubscribeEventsParams,
    SubscribeEventsResult, UnsubscribeEventsParams, UnsubscribeEventsResult,
};
use crate::runtime::RequestContext;
use crate::runtime::policy::PolicyRoute;

/// Event types per `events/list` page.
pub const LIST_PAGE_SIZE: usize = 100;
/// Prefix of an `events/list` cursor.
const LIST_CURSOR_PREFIX: &str = "el1.";

/// The policy key of event type `name`.
pub fn policy_key(name: &str) -> String {
    format!("event:{name}")
}

/// The cursor that continues a listing after type `name`. It names only a
/// type the caller was shown, so it discloses nothing new.
fn encode_list_cursor(name: &str) -> String {
    format!("{LIST_CURSOR_PREFIX}{}", URL_SAFE_NO_PAD.encode(name))
}

fn decode_list_cursor(cursor: &str) -> Option<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor.strip_prefix(LIST_CURSOR_PREFIX)?)
        .ok()?;
    let name = String::from_utf8(raw).ok()?;
    crate::config::events::is_event_name(&name).then_some(name)
}

impl EventsCore {
    /// `events/list` for `ctx`.
    pub fn list_events(
        &self,
        ctx: &RequestContext,
        params: &ListEventsParams,
    ) -> Result<ListEventsResult, EventsError> {
        let after = match params.cursor.as_deref() {
            None => None,
            Some(cursor) => Some(
                decode_list_cursor(cursor)
                    .ok_or_else(|| EventsError::invalid_params("cursor is not a valid cursor"))?,
            ),
        };
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?;
        let runtime = runtime.load();
        let catalog = self.catalog();
        let mut page = Vec::with_capacity(LIST_PAGE_SIZE.min(catalog.len()));
        let mut more = false;
        for ty in catalog.types() {
            if after
                .as_deref()
                .is_some_and(|after| ty.name.as_str() <= after)
            {
                continue;
            }
            if !runtime.surface_is_visible(ctx, &policy_key(&ty.name), PolicyRoute::event(None)) {
                continue;
            }
            if page.len() == LIST_PAGE_SIZE {
                more = true;
                break;
            }
            page.push(ty.descriptor());
        }
        let next_cursor = more
            .then(|| page.last().map(|d| encode_list_cursor(&d.name)))
            .flatten();
        Ok(ListEventsResult::new(page, next_cursor))
    }
}

#[async_trait]
impl EventsHandler for EventsCore {
    async fn list(
        &self,
        ctx: &RequestContext,
        params: ListEventsParams,
    ) -> Result<ListEventsResult, EventsError> {
        self.list_events(ctx, &params)
    }

    async fn subscribe(
        &self,
        ctx: &RequestContext,
        params: SubscribeEventsParams,
    ) -> Result<SubscribeEventsResult, EventsError> {
        self.subscribe_webhook(ctx, params).await
    }

    async fn unsubscribe(
        &self,
        ctx: &RequestContext,
        params: UnsubscribeEventsParams,
    ) -> Result<UnsubscribeEventsResult, EventsError> {
        self.unsubscribe_webhook(ctx, params).await
    }

    async fn poll(
        &self,
        ctx: &RequestContext,
        params: PollEventsParams,
    ) -> Result<PollEventsResult, EventsError> {
        self.poll_events(ctx, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_cursors_round_trip_and_refuse_garbage() {
        let cursor = encode_list_cursor("orders.created");
        assert!(cursor.starts_with("el1."));
        assert_eq!(
            decode_list_cursor(&cursor).as_deref(),
            Some("orders.created")
        );
        for bad in [
            "",
            "el1.",
            "orders.created",
            "el1.!!!",
            &format!("el2.{}", URL_SAFE_NO_PAD.encode("orders")),
            &format!("el1.{}", URL_SAFE_NO_PAD.encode("has space")),
            &format!("el1.{}", URL_SAFE_NO_PAD.encode([0xff, 0xfe])),
        ] {
            assert_eq!(decode_list_cursor(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn policy_keys_never_collide_with_tool_names() {
        assert_eq!(policy_key("orders.created"), "event:orders.created");
    }
}
