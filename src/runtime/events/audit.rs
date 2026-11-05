//! Audit records of the event surface.
//!
//! No record holds a callback URL or a secret: a callback is its origin
//! plus a keyed hash of its path and query, and a principal is its keyed
//! hash where no identity is at hand. Arguments are a keyed hash of their
//! canonical JSON, unless the type's `audit.arguments` says `raw` or `none`.

use mcpg_plugin_host::audit_events::{new_event_id, now_rfc3339_utc, system_identity};
use mcpg_plugin_protocol::PluginIdentity;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_safe_egress::CallbackUrl;
use serde_json::{Value, json};

use super::engine::EventsCore;
use super::keys::EventsKeys;
use super::subscriptions::SubscriptionRecord;
use crate::config::events::AuditArguments;
use crate::runtime::RequestContext;
use crate::runtime::util::{plugin_identity_from_request, plugin_identity_from_request_identity};

/// The callback of `url` as audit records carry it.
pub fn callback_summary(keys: &EventsKeys, url: &str) -> Value {
    match url::Url::parse(url) {
        Ok(parsed) => {
            let path = &parsed[url::Position::BeforePath..url::Position::AfterQuery];
            json!({
                "origin": parsed.origin().ascii_serialization(),
                "path_hash": keys.key_hash("audit-callback-path", path.as_bytes()),
            })
        }
        Err(_) => json!({ "origin": null }),
    }
}

/// The arguments of `record` as audit records carry them.
pub fn arguments_hash(keys: &EventsKeys, record: &SubscriptionRecord) -> String {
    keys.key_hash(
        "audit-arguments",
        &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&Value::Object(
            record.arguments.clone(),
        )),
    )
}

/// Pollers whose last heartbeat record a replica remembers before it
/// prunes the ones past three intervals.
const POLLERS_TRACKED: usize = 50_000;

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `arguments` in the form `mode` names: `{arguments}`,
/// `{arguments_hash}` or nothing.
pub(crate) fn arguments_fields(
    keys: Option<&EventsKeys>,
    mode: AuditArguments,
    arguments: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    match mode {
        AuditArguments::None => {}
        AuditArguments::Raw => {
            out.insert("arguments".to_owned(), Value::Object(arguments.clone()));
        }
        AuditArguments::Hash => {
            let hash = keys.map(|keys| {
                keys.key_hash(
                    "audit-arguments",
                    &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&Value::Object(
                        arguments.clone(),
                    )),
                )
            });
            out.insert("arguments_hash".to_owned(), json!(hash));
        }
    }
    out
}

/// Add `arguments` to `details` in the form `mode` names.
fn insert_arguments(
    details: &mut Value,
    keys: Option<&EventsKeys>,
    mode: AuditArguments,
    arguments: &serde_json::Map<String, Value>,
) {
    if let Some(details) = details.as_object_mut() {
        details.extend(arguments_fields(keys, mode, arguments));
    }
}

fn event(
    actor: PluginIdentity,
    action: &str,
    name: &str,
    outcome: AuditOutcome,
    request_id: Option<String>,
    details: Value,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.to_owned(),
        resource: Some(format!("event://{name}")),
        outcome,
        request_id,
        upstream_request_id: None,
        node_id: None,
        details,
        prev_event_hash: None,
    }
}

impl EventsCore {
    async fn emit(&self, event: AuditEvent) {
        if let Some(runtime) = self.runtime() {
            let runtime = runtime.load_full();
            let _ = runtime.plugin_registry().emit_audit_event(&event).await;
        }
    }

    fn subscription_details(&self, record: &SubscriptionRecord, extra: Value) -> Value {
        let Some(stores) = self.stores() else {
            return extra;
        };
        let mut details = json!({
            "subscription_id": record.id,
            "event": record.name,
            "callback": callback_summary(&stores.keys, &record.url),
            "arguments_hash": arguments_hash(&stores.keys, record),
            "expires_at_ms": record.expires_at_ms,
        });
        if let (Value::Object(base), Value::Object(more)) = (&mut details, extra) {
            base.extend(more);
        }
        details
    }

    /// `mcpg.events.poll`, for a poll that returned events (a delivery
    /// receipt) or that started from no cursor (where a consumer began):
    /// the events by id, the cursor the consumer resumes from, the client
    /// and the arguments as the type's `audit.arguments` says. An empty
    /// poll from a cursor writes a record (`heartbeat: true`) only when the
    /// type's `audit.poll_heartbeat_secs` has passed since this poller's
    /// last record on this replica.
    pub(crate) async fn audit_poll(
        &self,
        ctx: &RequestContext,
        name: &str,
        from_cursor: Option<&str>,
        arguments: &serde_json::Map<String, Value>,
        result: &mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::PollEventsResult,
    ) {
        let audit = self
            .catalog()
            .get(name)
            .map(|ty| ty.audit.clone())
            .unwrap_or_default();
        let stores = self.stores();
        let keys = stores.as_deref().map(|s| &*s.keys);
        let empty_from_cursor = result.events.is_empty() && from_cursor.is_some();
        let heartbeat = std::time::Duration::from_secs(audit.poll_heartbeat_secs);
        let mut is_heartbeat = false;
        if audit.poll_heartbeat_secs > 0 {
            let poller = self.poller_key(ctx, name, keys, arguments);
            let now = std::time::Instant::now();
            {
                let mut seen = self.poll_audited.lock();
                let due = seen
                    .get(&poller)
                    .is_none_or(|at| now.duration_since(*at) >= heartbeat);
                if empty_from_cursor && !due {
                    return;
                }
                is_heartbeat = empty_from_cursor;
                if seen.len() >= POLLERS_TRACKED {
                    let keep = heartbeat.saturating_mul(3);
                    seen.retain(|_, at| now.duration_since(*at) < keep);
                }
                seen.insert(poller.clone(), now);
            }
            if let (Some(stores), Some(keys)) = (stores.as_deref(), keys) {
                let at = now_epoch_ms();
                let presence = super::poll::PresenceRow {
                    principal: plugin_identity_from_request(ctx),
                    client: ctx
                        .client()
                        .map(|c| json!({ "name": c.name, "version": c.version })),
                    arguments: arguments_fields(Some(keys), audit.arguments, arguments),
                    transport: Some(crate::runtime::transport_label(&ctx.transport).to_owned()),
                    node: crate::runtime::node_name().map(str::to_owned),
                    since_ms: at,
                    refreshed_ms: at,
                };
                let id = keys.key_hash("poller", poller.as_bytes());
                if let Err(error) = stores
                    .leases
                    .put_poller(&id, name, &presence, heartbeat.saturating_mul(3))
                    .await
                {
                    tracing::debug!(%error, "poller lease not written");
                }
            }
        } else if empty_from_cursor {
            return;
        }
        let mut details = json!({
            "event": name,
            "started": from_cursor.is_none(),
            "delivered": result.events.len(),
            "first_event_id": result.events.first().map(|e| e.event_id.as_str()),
            "last_event_id": result.events.last().map(|e| e.event_id.as_str()),
            "cursor": result.cursor,
            "truncated": result.truncated,
            "has_more": result.has_more,
        });
        if is_heartbeat {
            details["heartbeat"] = json!(true);
        }
        insert_arguments(&mut details, keys, audit.arguments, arguments);
        let event = crate::runtime::audit_with_client(
            event(
                plugin_identity_from_request(ctx),
                "mcpg.events.poll",
                name,
                AuditOutcome::Success,
                Some(ctx.request_id.as_str().to_owned()),
                details,
            ),
            ctx,
        );
        self.emit(event).await;
    }

    /// One poller: the type, the principal, the client and the arguments.
    fn poller_key(
        &self,
        ctx: &RequestContext,
        name: &str,
        keys: Option<&EventsKeys>,
        arguments: &serde_json::Map<String, Value>,
    ) -> String {
        let principal = ctx.identity.synthetic_principal_key().unwrap_or_default();
        let client = ctx.client().map(|c| c.name).unwrap_or_default();
        let args = keys
            .map(|keys| {
                keys.key_hash(
                    "audit-arguments",
                    &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&Value::Object(
                        arguments.clone(),
                    )),
                )
            })
            .unwrap_or_default();
        format!("{name}\u{1f}{principal}\u{1f}{client}\u{1f}{args}")
    }

    /// `mcpg.events.subscribe`: `outcome` is `created`, `refreshed` or
    /// `secret_rotated`.
    pub(crate) async fn audit_subscribe(
        &self,
        ctx: &RequestContext,
        record: &SubscriptionRecord,
        outcome: &str,
    ) {
        let details = self.subscription_details(record, json!({ "outcome": outcome }));
        self.emit(event(
            plugin_identity_from_request(ctx),
            "mcpg.events.subscribe",
            &record.name,
            AuditOutcome::Success,
            Some(ctx.request_id.as_str().to_owned()),
            details,
        ))
        .await;
    }

    /// `mcpg.events.unsubscribe`.
    pub(crate) async fn audit_unsubscribe(
        &self,
        ctx: &RequestContext,
        record: &SubscriptionRecord,
    ) {
        let details = self.subscription_details(record, json!({}));
        self.emit(event(
            plugin_identity_from_request(ctx),
            "mcpg.events.unsubscribe",
            &record.name,
            AuditOutcome::Success,
            Some(ctx.request_id.as_str().to_owned()),
            details,
        ))
        .await;
    }

    /// `mcpg.events.verification`: `outcome` is `passed` or a failure
    /// category.
    pub(crate) async fn audit_verification(
        &self,
        principal_key: &str,
        url: &CallbackUrl,
        outcome: &str,
    ) {
        let Some(stores) = self.stores() else {
            return;
        };
        let details = json!({
            "principal_hash": stores.keys.key_hash("audit-principal", principal_key.as_bytes()),
            "callback": callback_summary(&stores.keys, url.as_str()),
            "outcome": outcome,
        });
        let result = if outcome == "passed" {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        self.emit(AuditEvent {
            resource: None,
            ..event(
                system_identity(),
                "mcpg.events.verification",
                "",
                result,
                None,
                details,
            )
        })
        .await;
    }

    /// `mcpg.events.terminated`: delivery stopped for good for `reason`
    /// (`revoked`, `forbidden`, `type_removed`, `schema_changed`,
    /// `suspended`, `admin`).
    pub(crate) async fn audit_terminated(&self, record: &SubscriptionRecord, reason: &str) {
        let details = self.subscription_details(record, json!({ "reason": reason }));
        self.emit(event(
            plugin_identity_from_request_identity(&record.identity),
            "mcpg.events.terminated",
            &record.name,
            AuditOutcome::Denied,
            None,
            details,
        ))
        .await;
    }

    /// `mcpg.events.abandoned`: an event was given up on for `reason`.
    pub(crate) async fn audit_abandoned(
        &self,
        record: &SubscriptionRecord,
        event_id: &str,
        reason: &str,
    ) {
        let details =
            self.subscription_details(record, json!({ "event_id": event_id, "reason": reason }));
        self.emit(event(
            plugin_identity_from_request_identity(&record.identity),
            "mcpg.events.abandoned",
            &record.name,
            AuditOutcome::Failure,
            None,
            details,
        ))
        .await;
    }

    /// `mcpg.events.delivery`: one delivery request, under
    /// `audit.deliveries: every`; or the counts of one subscription over a
    /// window, under `summary`.
    pub(crate) async fn audit_delivery(&self, record: &SubscriptionRecord, details: Value) {
        let details = self.subscription_details(record, details);
        self.emit(event(
            plugin_identity_from_request_identity(&record.identity),
            "mcpg.events.delivery",
            &record.name,
            AuditOutcome::Success,
            None,
            details,
        ))
        .await;
    }

    /// `mcpg.events.stream_opened`: an `events/stream` began.
    pub(crate) async fn audit_stream_opened(
        &self,
        ctx: &RequestContext,
        name: &str,
        stream_id: &str,
        arguments: &serde_json::Map<String, Value>,
    ) {
        let mode = self
            .catalog()
            .get(name)
            .map(|ty| ty.audit.arguments)
            .unwrap_or_default();
        let stores = self.stores();
        let mut details = json!({ "stream_id": stream_id });
        insert_arguments(
            &mut details,
            stores.as_deref().map(|s| &*s.keys),
            mode,
            arguments,
        );
        self.emit(crate::runtime::audit_with_client(
            event(
                plugin_identity_from_request(ctx),
                "mcpg.events.stream_opened",
                name,
                AuditOutcome::Success,
                Some(ctx.request_id.as_str().to_owned()),
                details,
            ),
            ctx,
        ))
        .await;
    }

    /// `mcpg.events.stream_closed`: an `events/stream` ended. `reason` is
    /// `client`, `server` or the termination reason; `events` is how many
    /// it carried; `client` is the one that opened it.
    pub(crate) async fn audit_stream_closed(
        &self,
        identity: &crate::runtime::RequestIdentity,
        client: Option<&Value>,
        name: &str,
        stream_id: &str,
        reason: &str,
        events: u64,
    ) {
        let mut details = json!({ "stream_id": stream_id, "reason": reason, "events": events });
        if let Some(client) = client {
            details["client"] = client.clone();
        }
        self.emit(event(
            plugin_identity_from_request_identity(identity),
            "mcpg.events.stream_closed",
            name,
            AuditOutcome::Success,
            None,
            details,
        ))
        .await;
    }

    /// `mcpg.events.admin`: an operator action on the event surface.
    pub(crate) async fn audit_admin(&self, action: &str, details: Value) {
        self.emit(AuditEvent {
            resource: None,
            ..event(
                system_identity(),
                "mcpg.events.admin",
                "",
                AuditOutcome::Success,
                None,
                json!({ "action": action, "details": details }),
            )
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::events::test_support::keys;

    #[test]
    fn a_callback_is_its_origin_and_a_keyed_hash_of_the_rest() {
        let keys = keys();
        let summary = callback_summary(&keys, "https://hooks.example.com/u/42?token=abc");
        assert_eq!(summary["origin"], "https://hooks.example.com");
        assert!(summary["path_hash"].is_string());
        assert!(!summary.to_string().contains("/u/42"));
        assert!(!summary.to_string().contains("token=abc"));
        assert_ne!(
            callback_summary(&keys, "https://hooks.example.com/u/43")["path_hash"],
            summary["path_hash"]
        );
    }
}
