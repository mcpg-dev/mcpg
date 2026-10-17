//! The operator surface of MCP Events, behind the admin API: list types
//! and subscriptions, suspend or terminate one subscription, pause every
//! delivery, and purge the subscriptions of one principal.
//!
//! Every action writes the subscription record (or the cluster-wide pause
//! flag) that any replica may write; the events owner picks it up from the
//! hint, so an action taken on any replica holds on all of them. Listings
//! show a callback as its origin and a keyed hash of the rest: a URL path or
//! query can carry a credential.

use serde::Serialize;
use serde_json::Value;

use super::audit::callback_summary;
use super::engine::EventsCore;
use super::subscriptions::{
    HintOp, Revocation, SubscriptionHint, SubscriptionRecord, TerminationReason, rfc3339_ms,
};
use super::webhook::delivery_status;
use crate::protocol::v_2026_07_28::extensions::events::errors::ForbiddenReason;

/// Most subscriptions one listing returns.
pub const MAX_LISTING: usize = 1_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why an admin action failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    /// Events are off, or no store is resolved yet.
    Disabled,
    /// No subscription has this id.
    NotFound,
    /// The store failed; retry.
    Store,
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "MCP Events is not enabled",
            Self::NotFound => "subscription not found",
            Self::Store => "the event subscription store is unavailable; retry",
        })
    }
}

/// One event type in a listing.
#[derive(Debug, Clone, Serialize)]
pub struct TypeSummary {
    pub name: String,
    pub delivery: Vec<String>,
    pub source: &'static str,
    pub live_subscriptions: usize,
    pub log_head: Option<u64>,
    pub log_floor: Option<u64>,
}

/// One subscription in a listing.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionSummary {
    pub id: String,
    pub event: String,
    pub principal: String,
    pub callback: Value,
    pub created_at: String,
    pub refresh_before: Option<String>,
    pub state: &'static str,
    pub revoked_reason: Option<&'static str>,
    pub delivery: Value,
    pub ack_seq: Option<u64>,
    pub in_flight: usize,
}

/// The state of the event surface.
#[derive(Debug, Clone, Serialize)]
pub struct EventsStatus {
    pub enabled: bool,
    pub webhook_enabled: bool,
    pub delivery_paused_by_config: bool,
    pub delivery_paused_by_admin: bool,
    pub owner: bool,
    /// Dispatcher shards this replica delivers, of `DISPATCH_SHARDS`.
    pub shards: usize,
    pub types: usize,
    pub live_subscriptions: usize,
    /// Whether `events/poll` and `events/stream` are served.
    pub poll_enabled: bool,
    pub push_enabled: bool,
    /// `events/stream` responses open on this replica.
    pub open_streams: usize,
    /// The plan's MCP Events limits as the control plane last told this
    /// gateway.
    pub plan: PlanStatus,
}

/// The plan's MCP Events limits in an admin status. `null` is no cap.
#[derive(Debug, Clone, Serialize)]
pub struct PlanStatus {
    /// The month's deliveries are used: every mode holds them.
    pub deliveries_held: bool,
    /// The month's ingests are used: every source but the builtin ones
    /// waits.
    pub ingest_held: bool,
    /// When a used allowance comes back.
    pub held_until: Option<String>,
    pub readers_limit: Option<u64>,
    pub types_limit: Option<u64>,
    /// The types configured or imported that the type cap leaves out.
    pub types_not_served: usize,
    pub retention_ms_limit: Option<u64>,
    pub retention_events_limit: Option<u64>,
    pub retention_bytes_limit: Option<u64>,
    pub retry_window_ms_limit: Option<u64>,
}

impl EventsCore {
    fn admin_stores(&self) -> Result<std::sync::Arc<super::engine::EventsStores>, AdminError> {
        if !self.config().enabled {
            return Err(AdminError::Disabled);
        }
        self.stores().ok_or(AdminError::Disabled)
    }

    /// `GET …/events`.
    pub async fn admin_status(&self) -> EventsStatus {
        let config = self.config();
        let admin_paused = match self.stores() {
            Some(stores) => stores
                .subscriptions
                .delivery_paused()
                .await
                .unwrap_or(false),
            None => false,
        };
        EventsStatus {
            enabled: config.enabled,
            webhook_enabled: config.webhook.enabled,
            delivery_paused_by_config: config.delivery_paused,
            delivery_paused_by_admin: admin_paused,
            owner: self.is_owner(),
            shards: self.held_shards(now_ms()).len(),
            types: self.catalog().len(),
            live_subscriptions: self.live_counts("", now_ms()).1,
            poll_enabled: config.poll.enabled,
            push_enabled: config.push.enabled,
            open_streams: self.open_streams(),
            plan: self.plan_status(),
        }
    }

    fn plan_status(&self) -> PlanStatus {
        let plan = self.plan();
        PlanStatus {
            deliveries_held: plan.deliveries_held,
            ingest_held: plan.ingest_held,
            held_until: plan.held_until.map(|at| at.to_rfc3339()),
            readers_limit: plan.readers_limit,
            types_limit: plan.types_limit,
            types_not_served: self.types_not_served(),
            retention_ms_limit: plan.retention_ms_limit,
            retention_events_limit: plan.retention_events_limit,
            retention_bytes_limit: plan.retention_bytes_limit,
            retry_window_ms_limit: plan.retry_window_ms_limit,
        }
    }

    /// `GET …/events/types`.
    pub async fn admin_types(&self) -> Result<Vec<TypeSummary>, AdminError> {
        let stores = self.admin_stores()?;
        let now = now_ms();
        let mut out = Vec::new();
        for ty in self.catalog().types() {
            let bounds = stores.log.bounds(&ty.source_key).await.ok();
            out.push(TypeSummary {
                name: ty.name.clone(),
                delivery: ty.delivery.iter().map(|m| m.as_str().to_owned()).collect(),
                source: ty.source.kind(),
                live_subscriptions: self.live_counts(&ty.name, now).0,
                log_head: bounds.map(|b| b.head),
                log_floor: bounds.map(|b| b.floor),
            });
        }
        Ok(out)
    }

    /// `GET …/events/subscriptions`: the subscriptions of `event` (every
    /// type when `None`), of `principal` when given, at most `limit`.
    pub async fn admin_subscriptions(
        &self,
        event: Option<&str>,
        principal: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SubscriptionSummary>, AdminError> {
        let stores = self.admin_stores()?;
        let limit = limit.clamp(1, MAX_LISTING);
        let ids: Vec<String> = match principal {
            Some(principal) => stores
                .subscriptions
                .principal_ids(principal)
                .await
                .map_err(|_| AdminError::Store)?,
            None => {
                let mut ids = Vec::new();
                for ty in self.catalog().types() {
                    if event.is_some_and(|e| e != ty.name) {
                        continue;
                    }
                    ids.extend(
                        stores
                            .subscriptions
                            .list_type(&ty.name)
                            .await
                            .map_err(|_| AdminError::Store)?
                            .into_iter()
                            .map(|entry| entry.id),
                    );
                }
                ids
            }
        };
        let paused = self.operator_paused().await;
        let now = now_ms();
        let mut out = Vec::new();
        for id in ids {
            if out.len() >= limit {
                break;
            }
            let Ok(Some(record)) = stores.subscriptions.get(&id).await else {
                continue;
            };
            if event.is_some_and(|e| e != record.name) {
                continue;
            }
            let delivery = stores.subscriptions.delivery(&id).await.ok().flatten();
            let state = if record.revoked.is_some() {
                "terminated"
            } else if record.is_lapsed_at(now) {
                "expired"
            } else if delivery
                .as_ref()
                .is_some_and(|d| d.counters.suspended_at_ms.is_some())
            {
                "suspended"
            } else {
                "active"
            };
            out.push(SubscriptionSummary {
                callback: callback_summary(&stores.keys, &record.url),
                created_at: rfc3339_ms(record.created_at_ms),
                refresh_before: record.expires_at_ms.map(rfc3339_ms),
                state,
                revoked_reason: record.revoked.as_ref().map(|r| r.reason.label()),
                delivery: serde_json::to_value(delivery_status(delivery.as_ref(), paused))
                    .unwrap_or(Value::Null),
                ack_seq: delivery.as_ref().map(|d| d.ack_seq),
                in_flight: delivery.as_ref().map_or(0, |d| d.in_flight.len()),
                id: record.id,
                event: record.name,
                principal: record.principal_key,
            });
        }
        Ok(out)
    }

    async fn admin_update(
        &self,
        id: &str,
        change: impl FnOnce(&mut SubscriptionRecord),
    ) -> Result<SubscriptionRecord, AdminError> {
        let stores = self.admin_stores()?;
        let mut record = match stores.subscriptions.get(id).await {
            Ok(Some(record)) => record,
            Ok(None) => return Err(AdminError::NotFound),
            Err(_) => return Err(AdminError::Store),
        };
        change(&mut record);
        stores
            .subscriptions
            .replace(&record)
            .await
            .map_err(|_| AdminError::Store)?;
        self.note_subscription(&SubscriptionHint {
            op: HintOp::Upsert,
            id: record.id.clone(),
            name: record.name.clone(),
            expires_at_ms: record.expires_at_ms,
        });
        Ok(record)
    }

    /// `POST …/events/subscriptions/{id}/suspend`: stop delivery until the
    /// client's next refresh.
    pub async fn admin_suspend(&self, id: &str) -> Result<(), AdminError> {
        let now = now_ms();
        let record = self
            .admin_update(id, |record| record.operator_suspended_at_ms = Some(now))
            .await?;
        self.audit_admin(
            "suspend",
            serde_json::json!({ "subscription_id": record.id }),
        )
        .await;
        Ok(())
    }

    /// `POST …/events/subscriptions/{id}/terminate`: stop delivery for
    /// good; the client's next refresh answers `-32012`.
    pub async fn admin_terminate(&self, id: &str) -> Result<(), AdminError> {
        let now = now_ms();
        let record = self
            .admin_update(id, |record| {
                record.revoked = Some(Revocation {
                    at_ms: now,
                    reason: TerminationReason::Forbidden(ForbiddenReason::Admin),
                });
            })
            .await?;
        self.audit_admin(
            "terminate",
            serde_json::json!({ "subscription_id": record.id }),
        )
        .await;
        Ok(())
    }

    /// `POST …/events:pause` and `…/events:resume`: hold (or release) every
    /// delivery, in every mode, on every replica, keeping every
    /// subscription.
    pub async fn admin_set_paused(&self, paused: bool) -> Result<(), AdminError> {
        let stores = self.admin_stores()?;
        stores
            .subscriptions
            .set_delivery_paused(paused)
            .await
            .map_err(|_| AdminError::Store)?;
        self.note_admin_pause(paused);
        self.audit_admin(
            if paused { "pause" } else { "resume" },
            serde_json::json!({}),
        )
        .await;
        Ok(())
    }

    /// `POST …/events:purge`: delete every subscription of `principal` (its
    /// trust-qualified key, as listings show it). Returns how many.
    pub async fn admin_purge(&self, principal: &str) -> Result<usize, AdminError> {
        let stores = self.admin_stores()?;
        let ids = stores
            .subscriptions
            .principal_ids(principal)
            .await
            .map_err(|_| AdminError::Store)?;
        let mut purged = 0;
        for id in ids {
            match stores.subscriptions.delete(&id).await {
                Ok(Some(record)) => {
                    self.note_subscription(&SubscriptionHint {
                        op: HintOp::Delete,
                        id: record.id.clone(),
                        name: record.name.clone(),
                        expires_at_ms: record.expires_at_ms,
                    });
                    purged += 1;
                }
                Ok(None) => {}
                Err(_) => return Err(AdminError::Store),
            }
        }
        self.audit_admin(
            "purge",
            serde_json::json!({
                "principal_hash": stores.keys.key_hash("audit-principal", principal.as_bytes()),
                "purged": purged,
            }),
        )
        .await;
        Ok(purged)
    }
}
