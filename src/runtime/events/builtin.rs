//! Events the gateway raises itself, and the catalog-change notification.
//!
//! - `mcp.task.updated`: every status a task store writes. Only the
//!   principal that owns the task receives it: the occurrence names that
//!   principal as its audience, and the dispatcher delivers it to no
//!   other subscription.
//! - `approval.requested` / `approval.resolved`: a tool gate asking a
//!   person to approve a call, and how that ended. Who may see them is the
//!   operator's `event_name` rules and the type's `match`.
//!
//! Each is written to the inbox on whichever replica it happens, so the
//! owner appends it once.

use std::sync::{Arc, Weak};

use serde_json::json;

use super::engine::EventsCore;
use crate::config::events::BuiltinEventSource;
use crate::runtime::approvals::ApprovalObserver;
use crate::runtime::stores::session_store::SessionStore;
use crate::runtime::task_store::{TaskObserver, TaskRecord};
use crate::runtime::{GatewayRuntime, RequestIdentity};

/// Raises `mcp.task.updated` for every task status written.
struct TaskEvents {
    core: Weak<EventsCore>,
}

impl TaskObserver for TaskEvents {
    fn task_changed(&self, record: &TaskRecord) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        // A task is owned by its caller's principal key. An anonymous
        // caller's task is owned by a session id instead and belongs to
        // nobody who can subscribe, so it is not raised at all.
        if !RequestIdentity::is_principal_key(&record.session_id) {
            return;
        }
        let owner = record.session_id.clone();
        let status = serde_json::to_value(record.task.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let mut data = json!({
            "taskId": record.task.task_id,
            "status": status,
            "toolName": record.tool_name,
            "lastUpdatedAt": record.task.last_updated_at,
        });
        if let Some(message) = &record.task.status_message {
            data["statusMessage"] = json!(message);
        }
        // One occurrence per status: a store write repeated for the same
        // status at the same instant is one event.
        let event_id = format!(
            "task:{}:{}:{}",
            record.task.task_id, status, record.task.last_updated_at
        );
        tokio::spawn(async move {
            core.emit_builtin(
                BuiltinEventSource::TaskUpdated,
                Some(event_id),
                data,
                Some(&owner),
            )
            .await;
        });
    }
}

/// Raises `approval.requested` and `approval.resolved`.
struct ApprovalEvents {
    core: Weak<EventsCore>,
}

impl ApprovalObserver for ApprovalEvents {
    fn requested(&self, approval_id: &str, tool_name: &str, summary: &str, deadline_at: &str) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let data = json!({
            "approvalId": approval_id,
            "toolName": tool_name,
            "summary": summary,
            "deadlineAt": deadline_at,
        });
        let event_id = format!("approval:{approval_id}:requested");
        tokio::spawn(async move {
            core.emit_builtin(
                BuiltinEventSource::ApprovalRequested,
                Some(event_id),
                data,
                None,
            )
            .await;
        });
    }

    fn resolved(&self, approval_id: &str, tool_name: &str, outcome: &'static str) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let data = json!({
            "approvalId": approval_id,
            "toolName": tool_name,
            "outcome": outcome,
        });
        let event_id = format!("approval:{approval_id}:{outcome}");
        tokio::spawn(async move {
            core.emit_builtin(
                BuiltinEventSource::ApprovalResolved,
                Some(event_id),
                data,
                None,
            )
            .await;
        });
    }
}

/// Have `runtime`'s task store and approval registry report to `core`.
/// Both are new with every runtime, so boot and every reload call this.
pub fn observe_tasks(core: &Arc<EventsCore>, runtime: &GatewayRuntime) {
    runtime.task_store().set_observer(Arc::new(TaskEvents {
        core: Arc::downgrade(core),
    }));
    runtime
        .approval_registry
        .set_observer(Arc::new(ApprovalEvents {
            core: Arc::downgrade(core),
        }));
}

/// Tell every session that the event types changed, so a
/// `subscriptions/listen` stream that asked for `events/listChanged` hears
/// it.
pub fn announce_list_changed(
    sessions: &Arc<dyn SessionStore>,
    bus: &Arc<dyn crate::runtime::buses::delivery_bus::DeliveryBus>,
) {
    let notification =
        crate::protocol::v_2026_07_28::extensions::events::wire::EventsListChangedParams::default()
            .to_notification();
    for session in sessions.list_sessions() {
        let message = crate::runtime::pipeline_store::DeliveryMessage {
            kind: crate::runtime::pipeline_store::DeliveryKind::Notification,
            jsonrpc_message: notification.clone(),
        };
        let bus = Arc::clone(bus);
        let sid = session.session_id.clone();
        tokio::spawn(async move {
            let _ = bus.publish(&sid, message).await;
        });
    }
    metrics::counter!("mcpg_events_list_changed_total").increment(1);
}

#[cfg(test)]
#[path = "builtin_tests.rs"]
mod tests;
