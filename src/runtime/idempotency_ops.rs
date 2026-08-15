use super::*;

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
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: envelope,
            }),
        }
    }

    /// Build the replay response for a
    /// `tasks/create` cache hit. Unlike the unary
    /// [`build_idempotency_replay_response`] path, the cached
    /// envelope here carries only the **task handle** (`task_id` +
    /// `session_id`) — never the eventual task result. We reach
    /// into the live task store with the cached handle and
    /// assemble a fresh `CreateTaskResult` so the caller sees the
    /// current task status (running / completed / cancelled /
    /// expired) rather than a stale "running" snapshot from the
    /// original call.
    ///
    /// If the task store has lost the task (TTL elapsed mid-
    /// idempotency-window — possible but rare since the
    /// idempotency record's TTL is bounded by the task's TTL at
    /// reservation time), we return the cached envelope verbatim
    /// stamped with the replay marker so the caller still gets a
    /// deterministic response. The caller's next `tasks/result`
    /// poll will surface the missing task as `NotFound`.
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
        let cached_session_id = outcome
            .envelope
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        // Reach into the live task store — replay returns the
        // current task state, not the snapshot at first-call time.
        let live_task: Option<crate::protocol::Task> =
            match (cached_task_id.as_deref(), cached_session_id.as_deref()) {
                (Some(task_id), Some(session_id)) => self
                    .task_store
                    .get_task(task_id, session_id)
                    .ok()
                    .map(|rec| rec.task),
                _ => None,
            };
        // Build a fresh `CreateTaskResult` from the live task,
        // falling back to the cached handle when the task itself
        // has expired between first-call and replay.
        let mut envelope = match live_task {
            Some(task) => serde_json::to_value(crate::protocol::CreateTaskResult { task })
                .unwrap_or(outcome.envelope.clone()),
            None => outcome.envelope.clone(),
        };
        envelope = idempotency::stamp_replay_marker(envelope, completed_dt);
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
        ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: envelope,
            }),
        }
    }
}
