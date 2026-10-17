//! Audit records of the event surface.
//!
//! No record holds a callback URL, a secret or raw arguments: a callback is
//! its origin plus a keyed hash of its path and query, arguments are a
//! keyed hash of their canonical JSON, and a principal is its keyed hash
//! where no identity is at hand.

use mcpg_plugin_host::audit_events::{new_event_id, now_rfc3339_utc, system_identity};
use mcpg_plugin_protocol::PluginIdentity;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_safe_egress::CallbackUrl;
use serde_json::{Value, json};

use super::engine::EventsCore;
use super::keys::EventsKeys;
use super::subscriptions::SubscriptionRecord;
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
        let arguments_hash = self.stores().map(|stores| {
            stores.keys.key_hash(
                "audit-arguments",
                &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&Value::Object(
                    arguments.clone(),
                )),
            )
        });
        self.emit(event(
            plugin_identity_from_request(ctx),
            "mcpg.events.stream_opened",
            name,
            AuditOutcome::Success,
            Some(ctx.request_id.as_str().to_owned()),
            json!({ "stream_id": stream_id, "arguments_hash": arguments_hash }),
        ))
        .await;
    }

    /// `mcpg.events.stream_closed`: an `events/stream` ended. `reason` is
    /// `client`, `server` or the termination reason; `events` is how many
    /// it carried.
    pub(crate) async fn audit_stream_closed(
        &self,
        identity: &crate::runtime::RequestIdentity,
        name: &str,
        stream_id: &str,
        reason: &str,
        events: u64,
    ) {
        self.emit(event(
            plugin_identity_from_request_identity(identity),
            "mcpg.events.stream_closed",
            name,
            AuditOutcome::Success,
            None,
            json!({ "stream_id": stream_id, "reason": reason, "events": events }),
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
