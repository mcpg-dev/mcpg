//! Upstream webhook subscriptions of imported event types: the routes every
//! replica reads, and the receiver behind
//! `POST /webhooks/mcp-events/{federation}/{id}`.
//!
//! The events owner makes the upstream subscription and writes its route
//! first, because the upstream challenges the callback while it subscribes.
//! Any replica takes a delivery: it checks the Standard Webhooks signature
//! with the secret every replica derives for the route, and hands the
//! occurrence, or the gap or end an envelope reports, to the owner through
//! the type's inbox. The answer is 2xx only once that write is durable; the
//! log deduplicates a delivery repeated by its event id.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mcpg_cluster_api::KeyValueStore;
use mcpg_standard_webhooks::Verifier;
use serde::{Deserialize, Serialize};

use super::catalog::SourceSpec;
use super::engine::EventsCore;
use super::federated::Refusal;
use super::log::{GapReason, InboxLimits, InboxMarker, InboxOutcome, InboxRow, RowScope};
use super::sources::SLOT_POSITION_TTL;
use super::subscriptions::StoreError;
use crate::protocol::v_2026_07_28::extensions::events::wire::{ControlEnvelope, WebhookBody};

/// Path prefix of the callbacks of upstream webhook subscriptions.
pub const UPSTREAM_WEBHOOK_PATH: &str = "/webhooks/mcp-events";
/// How long a stopped upstream subscription's route keeps turning late
/// deliveries away.
pub const ROUTE_ABANDONED_TTL: Duration = Duration::from_secs(3_600);
/// The `ended` mark of a route the upstream ended for a reason that ends
/// nothing downstream.
const UPSTREAM_ERROR: &str = "upstream_error";

const FORMAT_VERSION: u32 = 1;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What the deliveries of one upstream webhook subscription are for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamRoute {
    pub v: u32,
    pub federation: String,
    /// The served type.
    pub name: String,
    /// The readers it serves.
    pub scope: RowScope,
    /// The owner stopped the upstream subscription: late deliveries get
    /// `410`.
    #[serde(default)]
    pub abandoned: bool,
    /// The upstream ended it: the label of the end its readers got, or
    /// `upstream_error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
}

impl UpstreamRoute {
    pub fn new(federation: &str, name: &str, scope: RowScope) -> Self {
        Self {
            v: FORMAT_VERSION,
            federation: federation.to_owned(),
            name: name.to_owned(),
            scope,
            abandoned: false,
            ended: None,
        }
    }
}

/// The routes of the upstream webhook subscriptions, in the subscription
/// store.
pub struct RouteStore {
    kv: Arc<dyn KeyValueStore>,
}

impl std::fmt::Debug for RouteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteStore").finish_non_exhaustive()
    }
}

impl RouteStore {
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Self {
        Self { kv }
    }

    fn key(id: &str) -> String {
        format!("ev:fed:r:{id}")
    }

    /// The route of upstream subscription `id`.
    pub async fn get(&self, id: &str) -> Result<Option<UpstreamRoute>, StoreError> {
        let Some(entry) = self.kv.get(&Self::key(id)).await? else {
            return Ok(None);
        };
        let route: UpstreamRoute =
            serde_json::from_slice(&entry.bytes).map_err(|e| StoreError::Codec(e.to_string()))?;
        if route.v > FORMAT_VERSION {
            return Err(StoreError::Unreadable);
        }
        Ok(Some(route))
    }

    /// Write the route of upstream subscription `id`, for `ttl` or for
    /// good.
    pub async fn put(
        &self,
        id: &str,
        route: &UpstreamRoute,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(route).map_err(|e| StoreError::Codec(e.to_string()))?;
        self.kv.put(&Self::key(id), Bytes::from(bytes), ttl).await?;
        Ok(())
    }
}

/// The outcome of one upstream delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamReply {
    /// Durably taken.
    Accepted,
    /// A verification challenge: answer with this echo.
    Challenge(String),
    /// The signature or its timestamp is wrong.
    Unauthorized,
    /// The body is not a delivery.
    BadRequest,
    /// No upstream subscription has this id now; the upstream retries.
    Unknown,
    /// The upstream subscription was stopped; the upstream should stop
    /// delivering.
    Gone,
    /// The plan refuses it now; retry after the given time.
    RateLimited(Duration),
    /// Not now; retry after the given time.
    Unavailable(Duration),
}

impl EventsCore {
    /// Serve one POST to `/webhooks/mcp-events/{federation}/{id}`.
    pub async fn receive_upstream(
        &self,
        federation: &str,
        id: &str,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> UpstreamReply {
        let config = self.config();
        let Some(stores) = self.stores().filter(|_| config.enabled) else {
            return UpstreamReply::Unknown;
        };
        let route = match stores.routes.get(id).await {
            Ok(Some(route)) if route.federation == federation => route,
            Ok(_) => return UpstreamReply::Unknown,
            Err(error) => {
                tracing::warn!(error = %error, "an upstream route could not be read");
                return UpstreamReply::Unavailable(Duration::from_secs(30));
            }
        };
        if route.abandoned {
            return UpstreamReply::Gone;
        }
        let catalog = self.catalog();
        let Some(ty) = catalog
            .get(&route.name)
            .filter(|ty| matches!(&ty.source, SourceSpec::Federation { federation: f, .. } if f == federation))
            .cloned()
        else {
            return UpstreamReply::Gone;
        };
        let secret = stores.keys.upstream_webhook_secret(id).signing_secret();
        let verified = Verifier::new(vec![secret]).ok().is_some_and(|verifier| {
            verifier
                .verify_headers(headers, body, now_ms() / 1_000)
                .is_ok()
        });
        if !verified {
            metrics::counter!("mcpg_events_upstream_deliveries_total", "outcome" => "unauthorized")
                .increment(1);
            return UpstreamReply::Unauthorized;
        }
        if let Some((outcome, wait)) = self.plan_refusal("upstream") {
            metrics::counter!("mcpg_events_upstream_deliveries_total", "outcome" => outcome)
                .increment(1);
            return UpstreamReply::RateLimited(wait);
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return UpstreamReply::BadRequest;
        };
        let Ok(delivery) = WebhookBody::from_value(value) else {
            return UpstreamReply::BadRequest;
        };
        let limits = InboxLimits {
            ttl: Duration::from_millis(config.log.inbox_ttl_ms),
            max_rows: config.log.inbox_max_rows,
        };
        let marker = |marker: InboxMarker| InboxRow {
            v: super::log::FORMAT_VERSION,
            received_at_ms: now_ms(),
            audience: route.scope.audience.clone(),
            arguments: route.scope.arguments.clone(),
            marker: Some(marker),
            ..InboxRow::default()
        };
        let (row, cursor) = match delivery {
            WebhookBody::Control(ControlEnvelope::Verification { challenge }) => {
                return UpstreamReply::Challenge(challenge);
            }
            WebhookBody::Control(ControlEnvelope::Gap { cursor }) => (
                marker(InboxMarker::Gap {
                    reason: GapReason::UpstreamTruncated,
                }),
                cursor,
            ),
            WebhookBody::Control(ControlEnvelope::Terminated { error }) => {
                let refusal = Refusal::of(error.code, error.data.as_ref());
                let mut ended = route.clone();
                match refusal {
                    Refusal::End(reason) => {
                        let row = marker(InboxMarker::Ended { reason });
                        if let Some(reply) = self.take(&stores, &ty.source_key, row, limits).await {
                            return reply;
                        }
                        ended.ended = Some(reason.label().to_owned());
                    }
                    Refusal::SchemaChanged | Refusal::Other => {
                        ended.ended = Some(UPSTREAM_ERROR.to_owned());
                    }
                }
                if let Err(error) = stores.routes.put(id, &ended, None).await {
                    tracing::warn!(error = %error, "an upstream route could not be marked ended");
                    return UpstreamReply::Unavailable(Duration::from_secs(30));
                }
                metrics::counter!("mcpg_events_upstream_deliveries_total", "outcome" => "terminated")
                    .increment(1);
                return UpstreamReply::Accepted;
            }
            WebhookBody::Event(occurrence) => (
                InboxRow {
                    v: super::log::FORMAT_VERSION,
                    event_id: Some(format!("{federation}:{}", occurrence.event_id)),
                    timestamp: Some(occurrence.timestamp),
                    data: occurrence.data,
                    received_at_ms: now_ms(),
                    audience: route.scope.audience.clone(),
                    arguments: route.scope.arguments.clone(),
                    marker: None,
                },
                occurrence.cursor,
            ),
        };
        if let Some(reply) = self.take(&stores, &ty.source_key, row, limits).await {
            return reply;
        }
        if let Some(cursor) = cursor
            && let Err(error) = stores
                .log
                .store_resume_position(
                    &ty.source_key,
                    Some(id),
                    serde_json::Value::String(cursor),
                    Some(SLOT_POSITION_TTL),
                )
                .await
        {
            tracing::debug!(error = %error, "the position of an upstream delivery could not be stored");
        }
        metrics::counter!("mcpg_events_upstream_deliveries_total", "outcome" => "accepted")
            .increment(1);
        UpstreamReply::Accepted
    }

    /// Write `row` to the inbox of `sk`; `None` once it is durable, else
    /// the answer that asks the upstream to retry.
    async fn take(
        &self,
        stores: &super::engine::EventsStores,
        sk: &str,
        row: InboxRow,
        limits: InboxLimits,
    ) -> Option<UpstreamReply> {
        match stores.log.inbox_put(sk, row, limits).await {
            Ok(InboxOutcome::Accepted) => {
                self.nudge_inbox();
                None
            }
            Ok(InboxOutcome::Full { retry_after }) => {
                metrics::counter!("mcpg_events_upstream_deliveries_total", "outcome" => "inbox_full")
                    .increment(1);
                Some(UpstreamReply::Unavailable(retry_after))
            }
            Err(error) => {
                tracing::warn!(error = %error, "an upstream delivery could not be written to the inbox");
                Some(UpstreamReply::Unavailable(Duration::from_secs(30)))
            }
        }
    }
}
