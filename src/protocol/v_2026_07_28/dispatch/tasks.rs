//! `tasks` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, ProtocolHttpResponse, ProtocolResponse,
};
use crate::protocol::v_2026_07_28::dispatch::mrtr::{
    MrtrResumption, dispatch_mrtr_resumption, resume_did_not_commit,
};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, serialize_jsonrpc_success,
};
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// True when the per-request client capabilities declared the
/// `io.modelcontextprotocol/tasks` extension (SEP-2663). A server
/// MUST NOT surface tasks to a client that did not declare it — both
/// the `tasks/*` methods and the `tools/call` → `resultType:"task"`
/// materialization gate on this.
pub(crate) fn client_declared_tasks_extension(ctx: &RequestContext) -> bool {
    ctx.modern_request_capabilities
        .as_ref()
        .and_then(|caps| caps.extensions.as_ref())
        .map(|ext| {
            ext.contains_key(
                crate::protocol::v_2026_07_28::extensions::tasks::wire::EXTENSION_NAMESPACE,
            )
        })
        .unwrap_or(false)
}

/// Dispatch one of the three bare SEP-2663 tasks methods
/// (`tasks/get` / `tasks/update` / `tasks/cancel`).
///
/// Gated on the per-request extension declaration: a client that did
/// not declare `io.modelcontextprotocol/tasks` gets `-32601` (the
/// methods do not exist for it). Task authorization binds to the
/// request **principal** (`RequestContext::task_owner_key`) so a task
/// minted on one cluster replica is pollable from another.
///
/// `tasks/update` is the client→server `inputResponses` channel: it
/// routes through the MRTR resume codec (`dispatch_mrtr_resumption`)
/// rather than duplicating the resume machinery — a task awaiting
/// input is a suspended MRTR pipeline.
pub(crate) async fn dispatch_tasks_extension(
    ctx: &RequestContext,
    services: &SharedServices,
    op: crate::protocol::v_2026_07_28::wire::operations::TasksExtensionOperation,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::{CancelTaskResult, GetTaskResult};
    use crate::protocol::v_2026_07_28::wire::operations::TasksExtensionOperation;

    // SEP-2663: never surface tasks to a client that did not declare
    // the extension. The methods MUST appear not-to-exist (`-32601`).
    if !client_declared_tasks_extension(ctx) {
        let request_id = op.request_id_owned();
        return ProtocolHttpResponse {
            http_status: 404,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcError(JsonRpcError {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                error: JsonRpcErrorBody {
                    code: -32601,
                    message: "tasks extension not declared by client".to_owned(),
                    data: None,
                },
            }),
        };
    }

    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(op.request_id_owned(), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();
    let task_store = runtime.task_store();

    // Principal-bound ownership: cross-instance pollable.
    let Some(owner_key) = ctx.task_owner_key() else {
        return handler_internal_error(
            op.request_id_owned(),
            "tasks extension requires a bound principal or session",
        );
    };

    match op {
        TasksExtensionOperation::GetTask { request_id, params } => {
            match task_store.get_task(&params.task_id, &owner_key) {
                Ok(record) => serialize_jsonrpc_success(
                    request_id,
                    &GetTaskResult::new(task_record_to_modern_task(&record)),
                    "tasks/get",
                ),
                Err(error) => task_store_error_to_response(error, Some(request_id), "tasks/get"),
            }
        }
        TasksExtensionOperation::CancelTask { request_id, params } => {
            // SEP-2663: cancellation is cooperative and the ack is
            // empty (`resultType:"complete"`), NOT the task body.
            match task_store.cancel_task(&params.task_id, &owner_key) {
                Ok(_) => {
                    // Same cluster broadcast + metric the legacy arm emits, so
                    // a cancel reaches a peer executing the task on either wire.
                    runtime.broadcast_task_cancellation(
                        &params.task_id,
                        &owner_key,
                        ctx.identity.principal_id(),
                    );
                    serialize_jsonrpc_success(
                        request_id,
                        &CancelTaskResult::default(),
                        "tasks/cancel",
                    )
                }
                Err(error) => task_store_error_to_response(error, Some(request_id), "tasks/cancel"),
            }
        }
        TasksExtensionOperation::UpdateTask { request_id, params } => {
            dispatch_tasks_update(ctx, services, &owner_key, request_id, params).await
        }
    }
}

/// SEP-2663 `tasks/update` — feed the client's `inputResponses` to an
/// `input_required` task and acknowledge with an empty result. Fused
/// with MRTR: the answers route through `dispatch_mrtr_resumption`
/// using the resume handle (`requestState`) the task recorded when it
/// suspended, and the resumed outcome drives the task to its next
/// state (terminal or re-suspended). The ack is eventually-consistent
/// per spec — it returns before the task's observable status
/// necessarily reflects the resume.
pub(crate) async fn dispatch_tasks_update(
    ctx: &RequestContext,
    services: &SharedServices,
    owner_key: &str,
    request_id: Value,
    params: crate::protocol::v_2026_07_28::extensions::tasks::wire::UpdateTaskParams,
) -> ProtocolHttpResponse {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::UpdateTaskResult;

    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();
    let task_store = runtime.task_store();

    // Ownership + existence check, and recover the MRTR resume handle
    // recorded at suspension time.
    let request_state = match task_store.task_request_state(&params.task_id, owner_key) {
        Ok(Some(state)) => state,
        Ok(None) => {
            // The task exists and is owned but is not awaiting input.
            // Spec: ignore inputResponses for a task with no
            // outstanding requests; ack empty.
            return serialize_jsonrpc_success(
                request_id,
                &UpdateTaskResult::default(),
                "tasks/update",
            );
        }
        Err(error) => {
            return task_store_error_to_response(error, Some(request_id), "tasks/update");
        }
    };

    // Route the answers through the exact MRTR resume codec (no
    // duplicated resume machinery). A new internal request id is used
    // for the resumption; the resumed outcome is folded back onto the
    // task, and the client gets the empty `tasks/update` ack.
    let resume = MrtrResumption {
        request_state,
        input_responses: params.input_responses.clone(),
    };
    let resume_response = dispatch_mrtr_resumption(ctx, services, request_id.clone(), resume).await;

    // Fold the resume outcome back onto the task record so the next
    // `tasks/get` reflects it.
    fold_resume_outcome_onto_task(
        task_store.as_ref(),
        &params.task_id,
        owner_key,
        &resume_response,
    );

    serialize_jsonrpc_success(request_id, &UpdateTaskResult::default(), "tasks/update")
}

/// Translate the `ProtocolHttpResponse` an MRTR resume produced into
/// a task-store transition: a completed pipeline → terminal
/// `Completed`; a JSON-RPC error → terminal `Failed`; a
/// re-suspension (`resultType:"input_required"`) → record the new
/// `requestState` + `inputRequests` and stay `input_required`.
pub(crate) fn fold_resume_outcome_onto_task(
    task_store: &dyn crate::runtime::task_store::TaskStore,
    task_id: &str,
    owner_key: &str,
    response: &ProtocolHttpResponse,
) {
    use crate::runtime::task_store::TerminalEnvelope;

    match &response.response {
        ProtocolResponse::JsonRpcSuccess(success) => {
            let result = &success.result;
            let is_input_required =
                result.get("resultType").and_then(Value::as_str) == Some("input_required");
            if is_input_required {
                // Re-suspended: capture the fresh resume handle +
                // outstanding requests so the next tasks/get surfaces
                // them.
                if let Some(request_state) = result.get("requestState").and_then(Value::as_str) {
                    let input_requests =
                        result.get("inputRequests").cloned().unwrap_or(Value::Null);
                    let _ = task_store.set_task_awaiting_input(
                        task_id,
                        owner_key,
                        request_state.to_owned(),
                        input_requests,
                    );
                }
            } else {
                // Pipeline ran to completion; the result body is the
                // task's terminal envelope.
                let _ = task_store.store_task_terminal(
                    task_id,
                    crate::protocol::TaskStatus::Completed,
                    TerminalEnvelope::success(result.clone()),
                );
            }
        }
        // Only a genuine (committed) failure latches a terminal `Failed`. A
        // retryable resume error (pending-not-found / expired / transient KV
        // — the codes `resume_did_not_commit` flags) advanced nothing and
        // left the `requestState` blob un-spent, so it falls through to the
        // no-op arm and the task stays `input_required` for a retry. Latching
        // `Failed` there would wedge the task: terminal tasks can't be
        // resumed, yet the blob is still claimable — the two must agree.
        ProtocolResponse::JsonRpcError(err) if !resume_did_not_commit(response) => {
            let _ = task_store.store_task_terminal(
                task_id,
                crate::protocol::TaskStatus::Failed,
                TerminalEnvelope::error(err.error.clone()),
            );
        }
        _ => {}
    }
}

/// Project a stored `TaskRecord` into the modern SEP-2663 `Task`
/// shape. Maps the internal `protocol::Task` metadata, inlines the
/// terminal `result`/`error` from the `TerminalEnvelope`, and surfaces
/// the outstanding `inputRequests` + `requestState` for an
/// `input_required` task.
pub(crate) fn task_record_to_modern_task(
    record: &crate::runtime::task_store::TaskRecord,
) -> crate::protocol::v_2026_07_28::extensions::tasks::wire::Task {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::{
        Task as ModernTask, TaskStatus as ModernTaskStatus,
    };
    use crate::runtime::task_store::TerminalEnvelope;

    let legacy = &record.task;
    let status = match legacy.status {
        crate::protocol::TaskStatus::Working => ModernTaskStatus::Working,
        crate::protocol::TaskStatus::Completed => ModernTaskStatus::Completed,
        crate::protocol::TaskStatus::Failed => ModernTaskStatus::Failed,
        crate::protocol::TaskStatus::Cancelled => ModernTaskStatus::Cancelled,
        crate::protocol::TaskStatus::InputRequired => ModernTaskStatus::InputRequired,
    };

    // SEP-2663 splits the terminal body across `result` (on
    // `completed`) and `error` (on `failed`); the internal envelope
    // carries one or the other.
    let (result, error) = match record.terminal_envelope.as_ref() {
        Some(TerminalEnvelope::Success { result }) => (Some(result.clone()), None),
        Some(TerminalEnvelope::Error { error }) => (
            None,
            Some(serde_json::json!({
                "code": error.code,
                "message": error.message,
                "data": error.data,
            })),
        ),
        None => (None, None),
    };

    let input_requests = record.input_requests.as_ref().and_then(|v| {
        serde_json::from_value::<
            std::collections::BTreeMap<
                String,
                crate::protocol::v_2026_07_28::wire::mrtr::InputRequest,
            >,
        >(v.clone())
        .ok()
    });

    ModernTask {
        task_id: legacy.task_id.clone(),
        status,
        status_message: legacy.status_message.clone(),
        created_at: legacy.created_at.clone(),
        last_updated_at: legacy.last_updated_at.clone(),
        ttl_ms: legacy.ttl,
        poll_interval_ms: legacy.poll_interval,
        result,
        error,
        input_requests,
        request_state: record.request_state.clone(),
    }
}

/// Map a `TaskStoreError` to a JSON-RPC error response with the
/// right code per SEP-2663 + MCP spec § Errors.
pub(crate) fn task_store_error_to_response(
    error: crate::runtime::task_store::TaskStoreError,
    jsonrpc_id: Option<Value>,
    operation_label: &str,
) -> ProtocolHttpResponse {
    use crate::runtime::task_store::TaskStoreError;

    let (http_status, code, message) = match error {
        TaskStoreError::NotFound => (
            200,
            -32602,
            format!("{operation_label}: task not found (may have expired)"),
        ),
        TaskStoreError::Forbidden => (
            200,
            -32600,
            format!("{operation_label}: task belongs to a different session"),
        ),
        TaskStoreError::NotCompleted => (
            200,
            -32602,
            format!("{operation_label}: task is still in flight"),
        ),
        TaskStoreError::AlreadyTerminal => (
            200,
            -32602,
            format!("{operation_label}: task has reached a terminal state"),
        ),
        TaskStoreError::QuotaExceeded { limit } => (
            200,
            -32600,
            format!("{operation_label}: session task quota exceeded (limit {limit})"),
        ),
        TaskStoreError::Internal(detail) => (
            500,
            -32603,
            format!("{operation_label}: task store error: {detail}"),
        ),
    };
    ProtocolHttpResponse {
        http_status,
        session_id_header: None,
        response: ProtocolResponse::JsonRpcError(JsonRpcError {
            jsonrpc: JSONRPC_VERSION,
            id: jsonrpc_id,
            error: JsonRpcErrorBody {
                code,
                message,
                data: None,
            },
        }),
    }
}
