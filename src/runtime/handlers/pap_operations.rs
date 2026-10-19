use serde_json::json;

use super::super::*;
use crate::config::personal_agent::{OPERATIONS_EXTENSION, OPERATIONS_VERSION};
use crate::protocol::ToolCallParams;
use crate::runtime::personal_agent::PersonalAgentCaller;
use crate::runtime::personal_agent_operations::{
    ExecutionOutcome, OperationError, OperationRecord, OperationsService, result_text,
};

/// JSON-RPC error codes of a tool call refused before its backend was
/// reached: the action certainly did not happen. Any other error leaves
/// the outcome unknown.
const NOT_PERFORMED_CODES: [i32; 11] = [
    -32003, -33000, -33001, -33003, -32029, -32044, -32099, -32602, -32601, -32005, -32022,
];

/// How often an ended action's outcome is offered to the store.
const FINISH_ATTEMPTS: u32 = 5;
const FINISH_RETRY: std::time::Duration = std::time::Duration::from_millis(500);

impl GatewayRuntime {
    /// The Personal Agent Protocol operations, while
    /// `personal_agent.operations` is set.
    pub fn pap_operations(&self) -> Option<&OperationsService> {
        self.pap_operations.as_deref()
    }

    /// Install the operations. Called once right after construction (and
    /// after each config-reload rebuild), before the runtime is shared.
    pub fn set_pap_operations(&mut self, operations: Option<std::sync::Arc<OperationsService>>) {
        self.pap_operations = operations;
    }

    /// A call of an operations tool by a Personal Agent that lists the
    /// extension: the operation it proposes, as the tool result (operations
    /// §4.2), instead of running the tool. `None` for any other call, and for
    /// the call that performs a confirmed operation.
    pub(crate) async fn propose_pap_operation(
        &self,
        request_id: &Value,
        params: &ToolCallParams,
        request_context: &RequestContext,
    ) -> Option<ProtocolHttpResponse> {
        let (operations, caller) = self.pap_operations_for(request_context)?;
        if !operations.is_operation_tool(&params.name) {
            return None;
        }
        let tool_result = if let Err(validation_error) = self
            .capability_registry
            .validate_tool_arguments(&params.name, &params.arguments)
        {
            json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Input validation failed for tool '{}': {validation_error}. Inspect the \
                         tool's inputSchema via tools/list and retry.",
                        params.name
                    ),
                }],
                "isError": true,
            })
        } else {
            let arguments = params.arguments.clone().unwrap_or_else(|| json!({}));
            match operations.propose(&params.name, &arguments, caller).await {
                Ok(record) => {
                    metrics::counter!(
                        "mcpg_pap_operations_total",
                        "tool" => params.name.clone(),
                        "event" => if record.revision == 1 { "proposed" } else { "revised" },
                    )
                    .increment(1);
                    self.audit_pap_operation(
                        request_context,
                        if record.revision == 1 {
                            "proposed"
                        } else {
                            "revised"
                        },
                        &record,
                    )
                    .await;
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Proposed: {} Not done until confirmed.", record.summary),
                        }],
                        "structuredContent": { "operation": record.wire() },
                    })
                }
                Err(error) => {
                    tracing::warn!(
                        request_id = %request_context.request_id,
                        tool = %params.name,
                        error = ?error,
                        "a Personal Agent Protocol operation could not be proposed"
                    );
                    let text = match error {
                        OperationError::NotFound => {
                            "The operation could not be proposed: the Session Token names no \
                             Session."
                        }
                        OperationError::Template(_) => {
                            "The operation could not be proposed for these arguments."
                        }
                        _ => "The operation could not be proposed; retry shortly.",
                    };
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "isError": true,
                    })
                }
            }
        };
        Some(ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: "2.0",
                id: request_id.clone(),
                result: tool_result,
            }),
        })
    }

    /// The operations and the Personal Agent of `request_context`, when it
    /// lists the extension and is not performing a confirmed operation.
    fn pap_operations_for<'a>(
        &'a self,
        request_context: &'a RequestContext,
    ) -> Option<(&'a OperationsService, &'a PersonalAgentCaller)> {
        if request_context.pap_operation.is_some() {
            return None;
        }
        let operations = self.pap_operations()?;
        let caller = request_context.personal_agent.as_ref()?;
        (caller.is_personal_agent() && caller.lists(OPERATIONS_EXTENSION, OPERATIONS_VERSION))
            .then_some((operations, caller))
    }

    /// `tools/list` to a Personal Agent that lists the extension: its
    /// operations tools without their `outputSchema`, since their structured
    /// result is the operation.
    pub(crate) fn hide_pap_operation_output_schemas(
        &self,
        request_context: &RequestContext,
        tools: &mut [crate::backends::ToolDescriptor],
    ) {
        let Some((operations, _)) = self.pap_operations_for(request_context) else {
            return;
        };
        for tool in tools
            .iter_mut()
            .filter(|tool| operations.is_operation_tool(&tool.name))
        {
            tool.output_schema = None;
        }
    }

    /// What the tool's access rules refuse `request_context` with, before a
    /// confirm performs `tool` (operations §5.2): the same pre-dispatch
    /// policy a `tools/call` of it meets.
    pub(crate) fn pap_operation_policy_denial(
        &self,
        tool: &str,
        request_context: &RequestContext,
    ) -> Option<policy::PolicyDenial> {
        let Some(route) = self.capability_registry.tool_route(tool) else {
            return Some(policy::PolicyDenial {
                code: -32602,
                http_status: 403,
                message: format!("tool {tool} is not served"),
                audit_reason: format!("pap_operation_unknown_tool:{tool}"),
                insufficient_scope: None,
            });
        };
        let policy_context = ToolPolicyContext::from_request_context(request_context, tool);
        match self
            .pre_dispatch_policy
            .evaluate(&policy_context, PolicyRoute::for_tool(&route))
        {
            PreDispatchPolicyOutcome::Allow => None,
            PreDispatchPolicyOutcome::Deny(denial) => Some(denial),
        }
    }

    /// Perform the confirmed `record` as `request_context`: its call through
    /// the whole tool-call path (policy, gates, transforms, the backend),
    /// with the operation as the idempotency key, then the outcome
    /// recorded.
    pub(crate) async fn execute_pap_operation(
        &self,
        record: OperationRecord,
        mut request_context: RequestContext,
    ) -> Result<OperationRecord, OperationError> {
        let Some(operations) = self.pap_operations() else {
            return Err(OperationError::Unavailable(
                "operations are no longer configured".to_owned(),
            ));
        };
        let key = format!("pap-op:{}", record.operation_id);
        request_context.pap_operation = Some(record.operation_id.clone());
        let mut meta = serde_json::Map::new();
        meta.insert(
            crate::runtime::idempotency::META_KEY_REQUEST.to_owned(),
            Value::String(key.clone()),
        );
        let params = ToolCallParams {
            name: record.tool.clone(),
            arguments: Some(record.terms.clone()),
            meta: Some(Value::Object(meta)),
            task: None,
        };
        let response = self
            .handle_tools_call(json!(key), params, &request_context)
            .await;
        let outcome = match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let result = success.result;
                if result.get("isError").and_then(Value::as_bool) == Some(true) {
                    ExecutionOutcome::Failed {
                        summary: result_text(&result, "The action failed."),
                    }
                } else {
                    ExecutionOutcome::Succeeded {
                        summary: result_text(&result, "Done."),
                        data: result.get("structuredContent").cloned(),
                    }
                }
            }
            ProtocolResponse::JsonRpcError(error) => {
                if NOT_PERFORMED_CODES.contains(&error.error.code) {
                    ExecutionOutcome::Failed {
                        summary: format!("Not performed: {}", error.error.message),
                    }
                } else {
                    ExecutionOutcome::Unknown {
                        reason: format!("{}: {}", error.error.code, error.error.message),
                    }
                }
            }
            ProtocolResponse::NotificationAccepted => ExecutionOutcome::Unknown {
                reason: "the tool call answered with no result".to_owned(),
            },
        };
        if let ExecutionOutcome::Unknown { reason } = &outcome {
            tracing::error!(
                operation_id = %record.operation_id,
                tool = %record.tool,
                reason = %reason,
                "a confirmed Personal Agent Protocol operation ended with an unknown outcome; it \
                 stays in_progress until the action's result is known"
            );
        }
        let event = match &outcome {
            ExecutionOutcome::Succeeded { .. } => "succeeded",
            ExecutionOutcome::Failed { .. } => "failed",
            ExecutionOutcome::Unknown { .. } => "unknown",
        };
        metrics::counter!(
            "mcpg_pap_operations_total",
            "tool" => record.tool.clone(),
            "event" => event,
        )
        .increment(1);
        // The action has ended: a store that is busy for a moment must not
        // leave a known outcome unrecorded.
        let mut attempt = 1;
        let finished = loop {
            match operations
                .finish(&record.operation_id, outcome.clone())
                .await
            {
                Ok(finished) => break finished,
                Err(OperationError::Unavailable(reason)) if attempt < FINISH_ATTEMPTS => {
                    tracing::warn!(
                        operation_id = %record.operation_id,
                        attempt,
                        reason = %reason,
                        "the outcome of a Personal Agent Protocol operation could not be \
                         recorded; retrying"
                    );
                    attempt += 1;
                    tokio::time::sleep(FINISH_RETRY).await;
                }
                Err(error) => return Err(error),
            }
        };
        self.audit_pap_operation(&request_context, event, &finished)
            .await;
        Ok(finished)
    }

    /// Record a step of an operation on the audit trail: its id, revision,
    /// tool, Personal Agent and account, and how it was approved. Never its
    /// terms.
    pub(crate) async fn audit_pap_operation(
        &self,
        request_context: &RequestContext,
        event: &str,
        record: &OperationRecord,
    ) {
        let audit = mcpg_plugin_protocol::audit::AuditEvent {
            event_id: mcpg_plugin_host::audit_events::new_event_id(),
            occurred_at: mcpg_plugin_host::audit_events::now_rfc3339_utc(),
            actor: plugin_identity_from_request(request_context),
            action: format!("pap.operation.{event}"),
            resource: Some(format!("tool://{}", record.tool)),
            outcome: if event == "failed" {
                mcpg_plugin_protocol::audit::AuditOutcome::Failure
            } else {
                mcpg_plugin_protocol::audit::AuditOutcome::Success
            },
            request_id: Some(request_context.request_id.as_str().to_owned()),
            upstream_request_id: request_context.upstream_request_id.clone(),
            node_id: None,
            details: json!({
                "operation_id": record.operation_id,
                "revision": record.revision,
                "state": record.state.as_str(),
                "client_id": record.owner.client_id,
                "account": record.owner.account,
                "approved_by": record.confirmation.as_ref().map(|c| c.approved_by.as_str()),
            }),
            prev_event_hash: None,
        };
        let _ = self.plugin_registry.emit_audit_event(&audit).await;
    }
}
