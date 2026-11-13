//! Realtime admission (`mcp.realtime.admission`): the gateway asks a tool
//! of its own before a caller gets realtime delivery (`admit`), while the
//! caller holds it (`renew`) and when the caller lets go (`release`).
//!
//! The call runs as the caller through the whole tool-call path, so the
//! tool's backend sees the same identity a caller's own tool call gives it.
//! A denial carries the tool's own JSON-RPC error to the caller.

use std::time::Duration;

use serde_json::{Value, json};

use crate::config::realtime::{AdmissionOnError, RealtimeAdmissionConfig};
use crate::protocol::{ProtocolResponse, ToolCallParams};
use crate::runtime::{
    GatewayRequestId, GatewayRuntime, RequestContext, RequestIdentity, TransportKind,
};

/// The JSON-RPC code of a denial whose error names no numeric code.
pub const DEFAULT_DENIAL_CODE: i32 = -32013;

/// What an admission call asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOp {
    Admit,
    Renew,
    Release,
}

impl AdmissionOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Renew => "renew",
            Self::Release => "release",
        }
    }
}

/// What a caller holds.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionTarget {
    /// An MCP Events type with its subscription arguments.
    Event { name: String, arguments: Value },
    /// A resource subscription.
    Resource { uri: String },
}

/// One held realtime delivery.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionLease {
    /// The same in `admit`, `renew` and `release`, on every replica.
    pub id: String,
    /// `stream`, `poll`, `webhook`, `listen` or `subscribe`.
    pub delivery: &'static str,
    pub target: AdmissionTarget,
}

impl AdmissionLease {
    fn arguments(
        &self,
        op: AdmissionOp,
        client: Option<&mcpg_plugin_protocol::ClientInfo>,
    ) -> Value {
        let mut args = json!({
            "op": op.as_str(),
            "lease_id": self.id,
            "delivery": self.delivery,
        });
        match &self.target {
            AdmissionTarget::Event { name, arguments } => {
                args["kind"] = json!("events");
                args["event"] = json!({ "name": name, "arguments": arguments });
            }
            AdmissionTarget::Resource { uri } => {
                args["kind"] = json!("resource");
                args["resource"] = json!({ "uri": uri });
            }
        }
        if let Some(client) = client {
            args["client"] = json!({ "name": client.name, "version": client.version });
        }
        args
    }
}

/// The caller keeps (or gets) the delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionGrant {
    /// When to renew next.
    pub renew_after: Duration,
}

/// The caller is refused; this is the JSON-RPC error it gets.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionDenial {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl AdmissionDenial {
    /// The denial as an `events/*` error.
    pub fn into_events_error(
        self,
    ) -> crate::protocol::v_2026_07_28::extensions::events::errors::EventsError {
        crate::protocol::v_2026_07_28::extensions::events::errors::EventsError::application(
            self.code,
            self.message,
            self.data,
        )
    }

    fn unavailable() -> Self {
        Self {
            code: -32603,
            message: "realtime admission is unavailable; retry later".to_owned(),
            data: None,
        }
    }
}

/// The admission in force on a runtime.
#[derive(Debug)]
pub struct RealtimeAdmission {
    config: RealtimeAdmissionConfig,
    /// When each caller-paced lease (a poll lease, a webhook subscription)
    /// is renewed next on this replica. Another replica has no entry and
    /// renews at once, which the tool sees as one more renew.
    paced: parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

/// Entries the caller-paced table keeps before it drops the overdue ones.
const PACED_SWEEP_AT: usize = 4_096;

impl RealtimeAdmission {
    pub fn new(config: RealtimeAdmissionConfig) -> Self {
        Self {
            config,
            paced: parking_lot::Mutex::default(),
        }
    }

    fn pace(&self, lease_id: &str, grant: AdmissionGrant) {
        let now = std::time::Instant::now();
        let mut paced = self.paced.lock();
        if paced.len() >= PACED_SWEEP_AT {
            // An entry this far overdue belongs to a caller that stopped.
            let stale = self.renew_interval() * 4;
            paced.retain(|_, due| now.saturating_duration_since(*due) < stale);
        }
        paced.insert(lease_id.to_owned(), now + grant.renew_after);
    }

    fn is_due(&self, lease_id: &str) -> bool {
        self.paced
            .lock()
            .get(lease_id)
            .is_none_or(|due| std::time::Instant::now() >= *due)
    }

    fn forget(&self, lease_id: &str) {
        self.paced.lock().remove(lease_id);
    }

    /// The internal tool the admission calls.
    pub fn tool(&self) -> &str {
        &self.config.tool
    }

    /// The configured renew interval.
    pub fn renew_interval(&self) -> Duration {
        Duration::from_millis(self.config.renew_interval_ms)
    }
}

impl GatewayRuntime {
    /// Install (or remove) the realtime admission.
    pub fn set_realtime_admission(&mut self, config: Option<&RealtimeAdmissionConfig>) {
        self.realtime_admission = config
            .cloned()
            .map(RealtimeAdmission::new)
            .map(std::sync::Arc::new);
    }

    /// Admit or renew a lease the caller paces itself (a poll lease, a
    /// webhook subscription): `admit` when `held` is false, else `renew`
    /// when the last grant's interval has passed.
    pub(crate) async fn realtime_admit_paced(
        &self,
        held: bool,
        identity: &RequestIdentity,
        client: Option<&mcpg_plugin_protocol::ClientInfo>,
        lease: &AdmissionLease,
    ) -> Result<(), AdmissionDenial> {
        let Some(admission) = self.realtime_admission.clone() else {
            return Ok(());
        };
        if held && !admission.is_due(&lease.id) {
            return Ok(());
        }
        let op = if held {
            AdmissionOp::Renew
        } else {
            AdmissionOp::Admit
        };
        match self.realtime_admit(op, identity, client, lease).await {
            Ok(Some(grant)) => {
                admission.pace(&lease.id, grant);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(denial) => {
                admission.forget(&lease.id);
                Err(denial)
            }
        }
    }

    /// Whether `tool` is the admission tool, which only the gateway calls.
    pub(crate) fn is_admission_tool(&self, tool: &str) -> bool {
        self.realtime_admission
            .as_ref()
            .is_some_and(|admission| admission.tool() == tool)
    }

    /// Ask the admission tool about `lease` as `identity`. Without an
    /// admission every `admit` and `renew` is granted. `None` renews at the
    /// caller's own pace.
    pub(crate) async fn realtime_admit(
        &self,
        op: AdmissionOp,
        identity: &RequestIdentity,
        client: Option<&mcpg_plugin_protocol::ClientInfo>,
        lease: &AdmissionLease,
    ) -> Result<Option<AdmissionGrant>, AdmissionDenial> {
        let Some(admission) = self.realtime_admission.clone() else {
            return Ok(None);
        };
        let mut ctx = RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            identity.clone(),
            TransportKind::Http,
        );
        ctx.realtime_admission = true;
        ctx.client = client.cloned();
        let params = ToolCallParams {
            name: admission.tool().to_owned(),
            arguments: Some(lease.arguments(op, client)),
            meta: None,
            task: None,
        };
        let key = format!("realtime-{}:{}", op.as_str(), lease.id);
        let response = self.handle_tools_call(json!(key), params, &ctx).await;
        let answer = match response.response {
            ProtocolResponse::JsonRpcSuccess(success)
                if success.result.get("isError").and_then(Value::as_bool) != Some(true) =>
            {
                decision_of(&success.result)
            }
            ProtocolResponse::JsonRpcSuccess(_) => None,
            ProtocolResponse::JsonRpcError(error) => {
                tracing::warn!(
                    tool = %admission.tool(),
                    op = op.as_str(),
                    code = error.error.code,
                    message = %error.error.message,
                    "the realtime admission tool call was refused"
                );
                None
            }
            ProtocolResponse::NotificationAccepted => None,
        };
        let outcome = match answer {
            Some(decision) => decide(&decision, admission.renew_interval()),
            None => {
                metrics::counter!("mcpg_realtime_admission_errors_total", "op" => op.as_str())
                    .increment(1);
                match admission.config.on_error {
                    AdmissionOnError::Allow => Ok(AdmissionGrant {
                        renew_after: admission.renew_interval(),
                    }),
                    AdmissionOnError::Deny => Err(AdmissionDenial::unavailable()),
                }
            }
        };
        metrics::counter!(
            "mcpg_realtime_admission_total",
            "op" => op.as_str(),
            "delivery" => lease.delivery,
            "outcome" => if outcome.is_ok() { "allow" } else { "deny" },
        )
        .increment(1);
        outcome.map(Some)
    }

    /// Tell the admission tool the caller let go of `lease`. Best effort.
    pub(crate) async fn realtime_release(
        &self,
        identity: &RequestIdentity,
        client: Option<&mcpg_plugin_protocol::ClientInfo>,
        lease: &AdmissionLease,
    ) {
        if let Some(admission) = &self.realtime_admission {
            admission.forget(&lease.id);
            let _ = self
                .realtime_admit(AdmissionOp::Release, identity, client, lease)
                .await;
        }
    }
}

/// What the admission holds for the subscription of `session_id` on `uri`:
/// one lease per session and URI, the same on every replica. The id is a
/// digest, so the tool never sees the session id.
pub(crate) fn session_resource_lease(session_id: &str, uri: &str) -> AdmissionLease {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update([0]);
    hasher.update(uri.as_bytes());
    let digest = hasher.finalize();
    let id: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    AdmissionLease {
        id: format!("sub-{id}"),
        delivery: "subscribe",
        target: AdmissionTarget::Resource {
            uri: uri.to_owned(),
        },
    }
}

/// What the admission holds for one `subscriptions/listen` target: a lease
/// of its own, because streams of one principal share a session.
pub(crate) fn listen_resource_lease(uri: &str) -> AdmissionLease {
    AdmissionLease {
        id: format!("listen-{}", uuid::Uuid::now_v7()),
        delivery: "listen",
        target: AdmissionTarget::Resource {
            uri: uri.to_owned(),
        },
    }
}

impl GatewayRuntime {
    /// Renew `lease` at the admission's pace for as long as `session_id`
    /// stays subscribed to `uri` on this replica. A refused renewal ends
    /// the subscription; a subscription that went away releases the lease.
    pub(crate) fn keep_session_subscription_admitted(
        &self,
        session_id: &str,
        uri: &str,
        identity: &RequestIdentity,
        client: Option<mcpg_plugin_protocol::ClientInfo>,
        lease: AdmissionLease,
        grant: AdmissionGrant,
    ) {
        let Some(handle) = self
            .shared_services
            .load_full()
            .and_then(|services| services.runtime())
        else {
            return;
        };
        let handle = std::sync::Arc::downgrade(&handle);
        let (session_id, uri, identity) = (session_id.to_owned(), uri.to_owned(), identity.clone());
        tokio::spawn(async move {
            let mut renew_after = grant.renew_after;
            loop {
                tokio::time::sleep(renew_after).await;
                let Some(runtime) = handle.upgrade() else {
                    return;
                };
                let runtime = runtime.load_full();
                if !runtime.subscriptions().is_held(&session_id, &uri) {
                    runtime
                        .realtime_release(&identity, client.as_ref(), &lease)
                        .await;
                    return;
                }
                match runtime
                    .realtime_admit(AdmissionOp::Renew, &identity, client.as_ref(), &lease)
                    .await
                {
                    Ok(Some(grant)) => renew_after = grant.renew_after,
                    Ok(None) => return,
                    Err(denial) => {
                        tracing::info!(
                            uri = %uri,
                            code = denial.code,
                            "the realtime admission refused a renewal; the resource subscription ends"
                        );
                        runtime
                            .subscriptions()
                            .unsubscribe_once(&session_id, &uri)
                            .await;
                        return;
                    }
                }
            }
        });
    }
}

/// The decision object in a tool result: the first object with a boolean
/// `allow`, looked for in `structuredContent`, in the text content parsed
/// as JSON, and inside rows and single-value wrappers a SQL backend adds.
fn decision_of(result: &Value) -> Option<Value> {
    if let Some(found) = result
        .get("structuredContent")
        .and_then(|v| find_decision(v, 0))
    {
        return Some(found);
    }
    result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .filter_map(|text| serde_json::from_str::<Value>(text).ok())
        .find_map(|value| find_decision(&value, 0))
}

fn find_decision(value: &Value, depth: usize) -> Option<Value> {
    if depth > 6 {
        return None;
    }
    match value {
        Value::Object(map) if map.get("allow").is_some_and(Value::is_boolean) => {
            Some(value.clone())
        }
        Value::Object(map) => map.values().find_map(|v| find_decision(v, depth + 1)),
        Value::Array(items) => items.iter().find_map(|v| find_decision(v, depth + 1)),
        // A SQL backend can hand a JSON column over as its text.
        Value::String(text) if text.trim_start().starts_with('{') => {
            serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|v| find_decision(&v, depth + 1))
        }
        _ => None,
    }
}

fn decide(decision: &Value, renew_interval: Duration) -> Result<AdmissionGrant, AdmissionDenial> {
    if decision.get("allow").and_then(Value::as_bool) == Some(true) {
        let asked = ["renew_after_seconds", "renewAfterSeconds"]
            .iter()
            .find_map(|key| decision.get(*key).and_then(Value::as_u64))
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs);
        // The tool may ask for an earlier renew, never a later one than the
        // operator set.
        let renew_after = asked.map_or(renew_interval, |asked| asked.min(renew_interval));
        return Ok(AdmissionGrant {
            renew_after: renew_after.max(Duration::from_secs(1)),
        });
    }
    let error = decision.get("error").cloned().unwrap_or(Value::Null);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("realtime delivery is not available to this caller")
        .to_owned();
    let numeric = error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok());
    match numeric {
        Some(code) => Err(AdmissionDenial {
            code,
            message,
            data: error.get("data").or_else(|| error.get("details")).cloned(),
        }),
        None => Err(AdmissionDenial {
            code: DEFAULT_DENIAL_CODE,
            message,
            data: (!error.is_null()).then_some(error),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn the_arguments_name_the_op_the_lease_the_target_and_the_client() {
        let client = mcpg_plugin_protocol::ClientInfo {
            name: "claude-code".into(),
            version: Some("2.1".into()),
        };
        let event = AdmissionLease {
            id: "lease-1".into(),
            delivery: "stream",
            target: AdmissionTarget::Event {
                name: "instruction.updated".into(),
                arguments: json!({"instructionId": "i1"}),
            },
        };
        assert_eq!(
            event.arguments(AdmissionOp::Admit, Some(&client)),
            json!({
                "op": "admit", "lease_id": "lease-1", "delivery": "stream", "kind": "events",
                "event": {"name": "instruction.updated", "arguments": {"instructionId": "i1"}},
                "client": {"name": "claude-code", "version": "2.1"}
            })
        );
        let resource = AdmissionLease {
            id: "lease-2".into(),
            delivery: "subscribe",
            target: AdmissionTarget::Resource {
                uri: "imd://i/1".into(),
            },
        };
        assert_eq!(
            resource.arguments(AdmissionOp::Release, None),
            json!({
                "op": "release", "lease_id": "lease-2", "delivery": "subscribe",
                "kind": "resource", "resource": {"uri": "imd://i/1"}
            })
        );
    }

    #[test]
    fn a_decision_is_found_in_structured_content_text_and_sql_rows() {
        let direct = json!({"structuredContent": {"allow": true}});
        assert_eq!(decision_of(&direct), Some(json!({"allow": true})));
        let text = json!({"content": [{"type": "text", "text": "{\"allow\": false}"}]});
        assert_eq!(decision_of(&text), Some(json!({"allow": false})));
        let rows = json!({"structuredContent": {"rows": [{"realtime": {"allow": true, "ttlSeconds": 120}}]}});
        assert_eq!(
            decision_of(&rows),
            Some(json!({"allow": true, "ttlSeconds": 120}))
        );
        let column_text =
            json!({"structuredContent": {"rows": [{"realtime": "{\"allow\":true}"}]}});
        assert_eq!(decision_of(&column_text), Some(json!({"allow": true})));
        assert_eq!(
            decision_of(&json!({"structuredContent": {"rows": []}})),
            None
        );
        assert_eq!(
            decision_of(&json!({"structuredContent": {"allow": "yes"}})),
            None
        );
    }

    #[test]
    fn an_allow_renews_at_the_configured_pace_or_earlier_when_the_tool_asks() {
        assert_eq!(
            decide(&json!({"allow": true}), MINUTE).unwrap().renew_after,
            MINUTE
        );
        for key in ["renew_after_seconds", "renewAfterSeconds"] {
            let grant = decide(&json!({"allow": true, key: 20}), MINUTE).unwrap();
            assert_eq!(grant.renew_after, Duration::from_secs(20));
        }
        let later = decide(&json!({"allow": true, "renewAfterSeconds": 600}), MINUTE).unwrap();
        assert_eq!(
            later.renew_after, MINUTE,
            "never later than the operator set"
        );
    }

    #[test]
    fn a_denial_with_a_numeric_code_passes_through_with_data_or_details() {
        let denial = decide(
            &json!({"allow": false, "error": {"code": -32013, "message": "limit", "data": {"limit": "realtime", "max": 1}}}),
            MINUTE,
        )
        .unwrap_err();
        assert_eq!(denial.code, -32013);
        assert_eq!(denial.message, "limit");
        assert_eq!(denial.data, Some(json!({"limit": "realtime", "max": 1})));
        let details = decide(
            &json!({"allow": false, "error": {"code": -32050, "message": "m", "details": {"plan": "free"}}}),
            MINUTE,
        )
        .unwrap_err();
        assert_eq!(
            (details.code, details.data),
            (-32050, Some(json!({"plan": "free"})))
        );
    }

    #[test]
    fn a_denial_with_a_named_code_gets_the_default_code_and_the_whole_error_as_data() {
        let error = json!({"code": "limit_reached", "message": "One agent at a time on the free plan.",
            "details": {"limit": "realtime_consumers", "max": 1, "used": 1, "retryAfterSeconds": 60}});
        let denial = decide(&json!({"allow": false, "error": error}), MINUTE).unwrap_err();
        assert_eq!(denial.code, DEFAULT_DENIAL_CODE);
        assert_eq!(denial.message, "One agent at a time on the free plan.");
        assert_eq!(denial.data, Some(error));
        let bare = decide(&json!({"allow": false}), MINUTE).unwrap_err();
        assert_eq!((bare.code, bare.data), (DEFAULT_DENIAL_CODE, None));
    }
}
