use super::*;
use crate::protocol::v_2026_07_28::dispatch::tasks::{task_store_error_to_response, wire_task};
use crate::protocol::v_2026_07_28::extensions::tasks::wire::CreateTaskResult;
use crate::protocol::{JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse};

impl GatewayRuntime {
    /// Emit a `mcpg.idempotency.*` audit event. Helper around the
    /// raw `AuditEvent::new` builder used by the dispatcher's
    /// dedupe path.
    pub(crate) async fn emit_idempotency_audit(
        &self,
        action: &str,
        request_context: &RequestContext,
        tool_name: &str,
        details: serde_json::Value,
    ) {
        let event = mcpg_plugin_protocol::audit::AuditEvent {
            event_id: Uuid::now_v7().to_string(),
            occurred_at: Utc::now().to_rfc3339(),
            actor: plugin_identity_from_request(request_context),
            action: action.to_owned(),
            resource: Some(format!("tool://{tool_name}")),
            outcome: mcpg_plugin_protocol::audit::AuditOutcome::Success,
            request_id: Some(request_context.request_id.as_str().to_owned()),
            upstream_request_id: None,
            node_id: None,
            details,
            prev_event_hash: None,
        };
        let _ = self.plugin_registry.emit_audit_event(&event).await;
    }

    /// Build the cached-replay response for an idempotency
    /// `Completed` peek. Stamps the SEP-2133 replay marker on the
    /// envelope, emits the `mcpg.idempotency.replay` audit event,
    /// bumps the per-tool counter, and ships an
    /// `IdempotentReplay` outcome to the CP recorder so the
    /// CP-side aggregation can exclude this from
    /// `tool_calls_per_month` quota math.
    pub(crate) async fn build_idempotency_replay_response(
        &self,
        request_context: &RequestContext,
        request_id: serde_json::Value,
        tool_name: &str,
        key: &str,
        outcome: idempotency::CachedOutcome,
        completed_at: std::time::SystemTime,
    ) -> ProtocolHttpResponse {
        let completed_dt: chrono::DateTime<Utc> = completed_at.into();
        let envelope = idempotency::stamp_replay_marker(outcome.envelope.clone(), completed_dt);
        let _ = self
            .emit_idempotency_audit(
                "mcpg.idempotency.replay",
                request_context,
                tool_name,
                serde_json::json!({
                    "key_hash": idempotency::key_hash_hex(key),
                    "original_completed_at": completed_dt.to_rfc3339(),
                    "original_request_id": outcome.original_request_id,
                    "replay_count": outcome.replay_count,
                }),
            )
            .await;
        metrics::counter!(
            "mcpg_idempotency_replay_total",
            "tool" => tool_name.to_owned(),
        )
        .increment(1);
        // Surface the replay to the CP recorder
        // with the dedicated `IdempotentReplay` outcome so the
        // aggregation can exclude it from quota math.
        self.tool_call_recorder.record(cp_metrics::ToolCallSample {
            plugin_id: "idempotency".to_owned(),
            tool_name: tool_name.to_owned(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: std::time::Duration::from_secs(0),
            outcome: cp_metrics::SampleOutcome::IdempotentReplay,
            // Carry the marker in `error_code` so a CP rev that
            // hasn't grown the dedicated proto variant can still
            // recognise the replay by string match.
            error_code: Some("idempotent_replay".to_owned()),
            error_hash: None,
            // The ORIGINAL's correlation id, not this replay's. A replay
            // asks the control plane not to bill it; naming the call that was
            // already billed is what lets that be checked rather than taken on
            // trust. Falls back to this request's own id for a cache entry
            // written before the original was recorded.
            request_id: Some(if outcome.original_correlation_id.is_empty() {
                request_context.request_id.as_str().to_owned()
            } else {
                outcome.original_correlation_id.clone()
            }),
            caller_subject: request_context.identity.principal_id().map(str::to_owned),
            request_payload: None,
            response_payload: None,
            payload_truncated: false,
        });
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: envelope,
            }),
        }
    }

    /// Build the replay response for a cache hit of a call accepted as a
    /// task. Unlike the unary [`build_idempotency_replay_response`] path,
    /// the cached envelope here carries only the **task handle** — the
    /// task id and, under the persisted `session_id` key, the task-store
    /// owner key — never the eventual task result. The live task store
    /// supplies the task, so the replay is a fresh `resultType:"task"`
    /// answer with the current status rather than a stale "working"
    /// snapshot from the original call.
    ///
    /// When the task store has lost the task (its TTL elapsed inside the
    /// idempotency window — rare, since the idempotency record's TTL is
    /// bounded by the task's TTL at reservation time), the replay answers
    /// as `tasks/get` would: task not found.
    pub(crate) async fn build_tasks_create_replay_response(
        &self,
        request_context: &RequestContext,
        request_id: serde_json::Value,
        tool_name: &str,
        key: &str,
        outcome: idempotency::CachedOutcome,
        completed_at: std::time::SystemTime,
    ) -> ProtocolHttpResponse {
        let completed_dt: chrono::DateTime<Utc> = completed_at.into();
        let cached_task_id = outcome
            .envelope
            .get("task_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let cached_owner = outcome
            .envelope
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        // Reach into the live task store — replay returns the
        // current task state, not the snapshot at first-call time.
        let live_task: Option<crate::protocol::Task> =
            match (cached_task_id.as_deref(), cached_owner.as_deref()) {
                (Some(task_id), Some(owner)) => self
                    .task_store
                    .get_task(task_id, owner)
                    .ok()
                    .map(|rec| rec.task),
                _ => None,
            };
        let _ = self
            .emit_idempotency_audit(
                "mcpg.idempotency.replay",
                request_context,
                tool_name,
                serde_json::json!({
                    "key_hash": idempotency::key_hash_hex(key),
                    "original_completed_at": completed_dt.to_rfc3339(),
                    "original_request_id": outcome.original_request_id,
                    "replay_count": outcome.replay_count,
                    "method": "tasks/create",
                    "task_id": cached_task_id,
                }),
            )
            .await;
        metrics::counter!(
            "mcpg_idempotency_replay_total",
            "tool" => tool_name.to_owned(),
            "method" => "tasks/create",
        )
        .increment(1);
        // Surface the replay to the CP recorder
        // with the dedicated `IdempotentReplay` outcome so the
        // aggregation can exclude it from quota math.
        self.tool_call_recorder.record(cp_metrics::ToolCallSample {
            plugin_id: "idempotency".to_owned(),
            tool_name: tool_name.to_owned(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: std::time::Duration::from_secs(0),
            outcome: cp_metrics::SampleOutcome::IdempotentReplay,
            error_code: Some("idempotent_replay".to_owned()),
            error_hash: None,
            // The ORIGINAL's correlation id, not this replay's. A replay
            // asks the control plane not to bill it; naming the call that was
            // already billed is what lets that be checked rather than taken on
            // trust. Falls back to this request's own id for a cache entry
            // written before the original was recorded.
            request_id: Some(if outcome.original_correlation_id.is_empty() {
                request_context.request_id.as_str().to_owned()
            } else {
                outcome.original_correlation_id.clone()
            }),
            caller_subject: request_context.identity.principal_id().map(str::to_owned),
            request_payload: None,
            response_payload: None,
            payload_truncated: false,
        });
        let Some(task) = live_task else {
            return task_store_error_to_response(
                task_store::TaskStoreError::NotFound,
                Some(request_id),
                "tools/call",
            );
        };
        let envelope = serde_json::to_value(CreateTaskResult::new(wire_task(&task)))
            .expect("create task result serialized");
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: idempotency::stamp_replay_marker(envelope, completed_dt),
            }),
        }
    }
}
