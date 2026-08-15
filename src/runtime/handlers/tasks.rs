use super::super::*;

impl GatewayRuntime {
    pub(crate) async fn handle_tasks_operation(
        &self,
        operation: TaskOperation,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        match operation {
            TaskOperation::Get { request_id, params } => {
                let session_id = match request_context.session_id.as_deref() {
                    Some(sid) => sid,
                    None => {
                        return protocol_http_error(
                            400,
                            Some(request_id),
                            -32600,
                            "tasks/get requires an active session",
                            self.debug_error_data(request_context, "Include MCP-Session-Id header"),
                        );
                    }
                };
                match self.task_store.get_task(&params.task_id, session_id) {
                    Ok(record) => ProtocolHttpResponse {
                        http_status: 200,
                        session_id_header: None,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: request_id,
                            result: serde_json::to_value(&record.task).expect("task serialized"),
                        }),
                    },
                    Err(task_store::TaskStoreError::NotFound) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32602,
                        "task not found",
                        self.debug_error_data(
                            request_context,
                            "Task may have expired or does not exist",
                        ),
                    ),
                    Err(task_store::TaskStoreError::Forbidden) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32600,
                        "access denied to task",
                        self.debug_error_data(
                            request_context,
                            "Task belongs to a different session",
                        ),
                    ),
                    Err(e) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32603,
                        format!("task store error: {e}"),
                        None,
                    ),
                }
            }
            TaskOperation::Result { request_id, params } => {
                let session_id = match request_context.session_id.as_deref() {
                    Some(sid) => sid,
                    None => {
                        return protocol_http_error(
                            400,
                            Some(request_id),
                            -32600,
                            "tasks/result requires an active session",
                            self.debug_error_data(request_context, "Include MCP-Session-Id header"),
                        );
                    }
                };
                // tasks/result MUST block until the task reaches a
                // terminal state. Poll the task store on the runtime's
                // delivery cadence up to TASKS_RESULT_WAIT_SECS, then return
                // the terminal envelope. An in-flight task that crosses the
                // timeout still responds with the spec-shaped "not completed"
                // error so the client can retry rather than hang indefinitely.
                let envelope_result = self
                    .wait_for_task_terminal(&params.task_id, session_id)
                    .await;
                match envelope_result {
                    Ok(envelope) => match envelope {
                        task_store::TerminalEnvelope::Success { result } => ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result,
                            }),
                        },
                        task_store::TerminalEnvelope::Error { error } => ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcError(JsonRpcError {
                                jsonrpc: JSONRPC_VERSION,
                                id: Some(request_id),
                                error,
                            }),
                        },
                    },
                    Err(task_store::TaskStoreError::NotFound) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32602,
                        "task not found",
                        self.debug_error_data(request_context, "Task may have expired or does not exist"),
                    ),
                    Err(task_store::TaskStoreError::Forbidden) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32600,
                        "access denied to task",
                        self.debug_error_data(request_context, "Task belongs to a different session"),
                    ),
                    Err(task_store::TaskStoreError::NotCompleted) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32602,
                        "task not yet completed",
                        self.debug_error_data(request_context, "Use tasks/get to check status, then retrieve result when completed or failed"),
                    ),
                    Err(e) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32603,
                        format!("task store error: {e}"),
                        None,
                    ),
                }
            }
            TaskOperation::Cancel { request_id, params } => {
                let session_id = match request_context.session_id.as_deref() {
                    Some(sid) => sid,
                    None => {
                        return protocol_http_error(
                            400,
                            Some(request_id),
                            -32600,
                            "tasks/cancel requires an active session",
                            self.debug_error_data(request_context, "Include MCP-Session-Id header"),
                        );
                    }
                };
                match self.task_store.cancel_task(&params.task_id, session_id) {
                    Ok(record) => {
                        // Legacy-shaped status notification (the modern wire
                        // routes cancel through the tasks extension).
                        self.deliver_task_status_notification(session_id, &record.task, false);
                        self.broadcast_task_cancellation(
                            &params.task_id,
                            session_id,
                            request_context.identity.principal_id(),
                        );

                        ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result: serde_json::to_value(&record.task)
                                    .expect("task serialized"),
                            }),
                        }
                    }
                    Err(task_store::TaskStoreError::NotFound) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32602,
                        "task not found",
                        self.debug_error_data(request_context, "Task may have expired or does not exist"),
                    ),
                    Err(task_store::TaskStoreError::Forbidden) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32600,
                        "access denied to task",
                        self.debug_error_data(request_context, "Task belongs to a different session"),
                    ),
                    Err(task_store::TaskStoreError::AlreadyTerminal) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32602,
                        "task has already reached a terminal state",
                        self.debug_error_data(
                            request_context,
                            "MCP 2025-11-25 forbids cancelling tasks that are already completed, failed, or cancelled",
                        ),
                    ),
                    Err(e) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32603,
                        format!("task store error: {e}"),
                        None,
                    ),
                }
            }
            TaskOperation::List { request_id, params } => {
                let session_id = match request_context.session_id.as_deref() {
                    Some(sid) => sid,
                    None => {
                        return protocol_http_error(
                            400,
                            Some(request_id),
                            -32600,
                            "tasks/list requires an active session",
                            self.debug_error_data(request_context, "Include MCP-Session-Id header"),
                        );
                    }
                };
                match self
                    .task_store
                    .list_tasks(session_id, params.cursor.as_deref(), 50)
                {
                    Ok((tasks, next_cursor)) => ProtocolHttpResponse {
                        http_status: 200,
                        session_id_header: None,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: request_id,
                            result: serde_json::to_value(TasksListResult { tasks, next_cursor })
                                .expect("tasks list serialized"),
                        }),
                    },
                    Err(e) => protocol_http_error(
                        200,
                        Some(request_id),
                        -32603,
                        format!("task store error: {e}"),
                        None,
                    ),
                }
            }
        }
    }

    /// Take all pending deliveries for a session (drain on SSE open).
    /// Block until the given task reaches a terminal state or the wait
    /// budget elapses. This backs `tasks/result`'s terminal-blocking
    /// contract (MCP 2025-11-25).
    ///
    /// We poll the task store rather than subscribe to a task-specific
    /// channel because the delivery bus is session-broadcast and the task
    /// result already lands on the session SSE via
    /// `deliver_task_status_notification`. Polling keeps this path
    /// cluster-safe without introducing a dedicated per-task rendezvous.
    pub async fn wait_for_task_terminal(
        &self,
        task_id: &str,
        session_id: &str,
    ) -> Result<task_store::TerminalEnvelope, task_store::TaskStoreError> {
        use std::time::Duration;
        // upper bound configurable via
        // `task_store.result_wait_ms` (default 30 s). Clients that
        // need longer-running tasks reconnect via GET SSE and resume
        // via Last-Event-Id until the task goes terminal.
        // Milliseconds, as the field is named and as the config default
        // (30_000) intends. Read as seconds this pinned a connection and a
        // worker for 8.3 hours per call.
        let wait_ms = self.task_store.retention_policy().result_wait_ms;
        let tasks_result_wait = Duration::from_millis(wait_ms.max(1));
        const POLL_INTERVAL: Duration = Duration::from_millis(250);

        let deadline = tokio::time::Instant::now() + tasks_result_wait;
        loop {
            match self.task_store.get_task_result(task_id, session_id) {
                Ok(envelope) => return Ok(envelope),
                Err(task_store::TaskStoreError::NotCompleted) => {
                    // Fall through to sleep + retry.
                }
                Err(other) => return Err(other),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(task_store::TaskStoreError::NotCompleted);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

/// Project the internal `protocol::Task` metadata into the modern
/// SEP-2663 `notifications/tasks` notification (bare method, flat
/// params, `ttlMs`/`pollIntervalMs` field names). Carries only the
/// status-level fields a working/awaiting/terminal-status push needs;
/// the terminal `result`/`error` are surfaced authoritatively via
/// `tasks/get`, so the notification is a status ping, not a result
/// carrier.
pub(crate) fn modern_task_status_notification(
    task: &crate::protocol::Task,
) -> crate::protocol::v_2026_07_28::extensions::tasks::wire::TaskStatusNotification {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::{
        Task as ModernTask, TaskStatus as ModernTaskStatus, TaskStatusNotification,
    };
    let status = match task.status {
        crate::protocol::TaskStatus::Working => ModernTaskStatus::Working,
        crate::protocol::TaskStatus::InputRequired => ModernTaskStatus::InputRequired,
        crate::protocol::TaskStatus::Completed => ModernTaskStatus::Completed,
        crate::protocol::TaskStatus::Failed => ModernTaskStatus::Failed,
        crate::protocol::TaskStatus::Cancelled => ModernTaskStatus::Cancelled,
    };
    TaskStatusNotification::new(ModernTask {
        task_id: task.task_id.clone(),
        status,
        status_message: task.status_message.clone(),
        created_at: task.created_at.clone(),
        last_updated_at: task.last_updated_at.clone(),
        ttl_ms: task.ttl,
        poll_interval_ms: task.poll_interval,
        result: None,
        error: None,
        input_requests: None,
        request_state: None,
    })
}
