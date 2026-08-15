use super::*;

impl GatewayRuntime {
    /// Deliver a server-initiated JSON-RPC request to the client's
    /// open SSE stream (`GET /mcp`) for the given session. Persists
    /// the message in `pipeline_store` so a late-arriving reconnect
    /// can replay it, then publishes on the cross-instance delivery
    /// bus so whichever gateway instance currently owns the session's
    /// stream picks it up.
    ///
    /// Async since both call sites — the legacy suspension consumers
    /// in `handle_protocol_operation` and the `v_2025_11_25` handler's
    /// `build_suspension_response` — run inside async contexts.
    /// `pub(crate)` so the per-version `ProtocolHandler` impl in
    /// `protocol/v_2025_11_25/handler.rs` can reach it via
    /// `services.runtime()`.
    pub(crate) async fn deliver_server_request(
        &self,
        session_id: &str,
        request: crate::protocol::ServerJsonRpcRequest,
    ) {
        let mut message = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::ServerRequest,
            jsonrpc_message: serde_json::to_value(&request).expect("server request serialized"),
            delivery_id: String::new(),
        };
        // Store first, then stamp the assigned backlog id onto the live copy
        // so a client that receives it live can ack/prune that exact row on a
        // later reconnect. The store ordering also guarantees the
        // backlog row exists before any live delivery races a drain.
        if let Ok(delivery_id) = self
            .pipeline_store
            .store_pending_delivery(session_id, &message)
        {
            message.delivery_id = delivery_id;
        }
        let _ = self.delivery_bus.publish(session_id, message).await;
    }

    pub(crate) fn deliver_deferred_tool_result(
        &self,
        session_id: &str,
        original_jsonrpc_id: &Value,
        tool_result: crate::protocol::ToolCallResult,
    ) {
        let jsonrpc_response = JsonRpcSuccess {
            jsonrpc: JSONRPC_VERSION,
            id: original_jsonrpc_id.clone(),
            result: serde_json::to_value(&tool_result).expect("tool result serialized"),
        };
        let mut message = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::to_value(&jsonrpc_response)
                .expect("jsonrpc response serialized"),
            delivery_id: String::new(),
        };
        if let Ok(delivery_id) = self
            .pipeline_store
            .store_pending_delivery(session_id, &message)
        {
            message.delivery_id = delivery_id;
        }
        let session_id = session_id.to_owned();
        let bus = &self.delivery_bus;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(bus.publish(&session_id, message))
        })
        .ok();
    }

    /// Deliver a terminal JSON-RPC error for a suspended pipeline to the
    /// original caller via the session's delivery path (the same carrier
    /// `deliver_deferred_tool_result` uses). Used when a suspended pipeline is
    /// cancelled or times out: without this the caller's stream would hang
    /// until its transport timeout because the state is simply deleted.
    ///
    /// `original_jsonrpc_id` is the id of the original request that suspended.
    /// The legacy continuation SSE (and reconnect drain) carry this frame so
    /// the awaiting client unblocks with a real error; the modern wire is
    /// inline (the caller already returned) so this is best-effort there.
    pub(crate) async fn deliver_pipeline_terminal_error(
        &self,
        session_id: &str,
        original_jsonrpc_id: &Value,
        code: i32,
        message: impl Into<String>,
    ) {
        let error = JsonRpcError {
            jsonrpc: JSONRPC_VERSION,
            id: Some(original_jsonrpc_id.clone()),
            error: JsonRpcErrorBody {
                code,
                message: message.into(),
                data: None,
            },
        };
        let mut delivery = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::PipelineError,
            jsonrpc_message: serde_json::to_value(&error).expect("jsonrpc error serialized"),
            delivery_id: String::new(),
        };
        if let Ok(delivery_id) = self
            .pipeline_store
            .store_pending_delivery(session_id, &delivery)
        {
            delivery.delivery_id = delivery_id;
        }
        let _ = self.delivery_bus.publish(session_id, delivery).await;
    }

    /// Deliver a JSON-RPC notification to the client via the session's SSE stream.
    pub(crate) fn deliver_notification(&self, session_id: &str, notification: serde_json::Value) {
        let mut message = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::ServerRequest, // reuse the notification delivery path
            jsonrpc_message: notification,
            delivery_id: String::new(),
        };
        if let Ok(delivery_id) = self
            .pipeline_store
            .store_pending_delivery(session_id, &message)
        {
            message.delivery_id = delivery_id;
        }
        let session_id = session_id.to_owned();
        let bus = &self.delivery_bus;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(bus.publish(&session_id, message))
        })
        .ok();
    }

    /// Emit a task-status notification to the session's delivery
    /// stream, version-aware (CPN-5).
    ///
    /// * Legacy `2025-11-25` ⇒ method `notifications/tasks/status`
    ///   with the `io.modelcontextprotocol/related-task` `_meta` (the
    ///   shape stateful clients expect), byte-identical to the prior
    ///   behaviour.
    /// * Modern `2026-07-28` ⇒ the bare SEP-2663 `notifications/tasks`
    ///   carrying the full flat task state. The transport's
    ///   `subscription_matches` delivers it to a `subscriptions/listen`
    ///   subscriber that opted into `TasksStatus`. Delivery is keyed on
    ///   the synthetic `session_id` (the subscriber's bus key) — the
    ///   cross-instance fan-out rides the cluster delivery bus.
    pub(crate) fn deliver_task_status_notification(
        &self,
        session_id: &str,
        task: &crate::protocol::Task,
        modern: bool,
    ) {
        let notification = if modern {
            serde_json::to_value(modern_task_status_notification(task))
                .expect("modern task status notification serialized")
        } else {
            let legacy = crate::protocol::TaskStatusNotification {
                jsonrpc: JSONRPC_VERSION,
                method: "notifications/tasks/status",
                params: crate::protocol::TaskStatusNotificationParams {
                    task: task.clone(),
                    meta: Some(crate::protocol::related_task_meta(&task.task_id)),
                },
            };
            serde_json::to_value(&legacy).expect("task status notification serialized")
        };
        self.deliver_notification(session_id, notification);
    }

    pub fn take_pending_deliveries(
        &self,
        session_id: &str,
    ) -> Vec<pipeline_store::DeliveryMessage> {
        self.pipeline_store
            .take_pending_deliveries(session_id)
            .unwrap_or_default()
    }

    /// Subscribe to delivery messages for a session.
    pub async fn subscribe_session_delivery(
        &self,
        session_id: &str,
    ) -> tokio::sync::mpsc::Receiver<pipeline_store::DeliveryMessage> {
        self.delivery_bus.subscribe(session_id).await
    }

    pub(crate) async fn handle_server_request_response(
        &self,
        request_context: &RequestContext,
        response_id: Value,
        result: Option<Value>,
        error: Option<JsonRpcErrorBody>,
    ) -> ProtocolHttpResponse {
        let response_id_str = match &response_id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        // P3: a federation server-request bridge may own this id — an upstream
        // asked the client a server-request (sampling/elicitation/roots) mid
        // tool-call and a federation task is awaiting the reply. Route there
        // first; only fall through to the pipeline-resume path on no match.
        if let Some(engine) = self.execution_dispatcher.federation_engine()
            && let Some(bridge) = engine.server_request_bridge()
        {
            let error_value = error.as_ref().and_then(|e| serde_json::to_value(e).ok());
            // Only the session that issued the federated server-request may
            // answer it. A responder with no session can never match.
            let responder_session = request_context.session_id.as_deref().unwrap_or("");
            if bridge
                .deliver_response(
                    &response_id_str,
                    responder_session,
                    result.clone(),
                    error_value,
                )
                .await
            {
                return ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                };
            }
        }

        // 1. Look up the pending server request
        let pending = match self
            .pipeline_store
            .load_pending_server_request(&response_id_str)
        {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                return protocol_http_error(
                    200,
                    None,
                    -32600,
                    "no pending server request found for this response id",
                    self.debug_error_data(
                        request_context,
                        "the server request may have expired or already been handled",
                    ),
                );
            }
            Err(e) => {
                return protocol_http_error(
                    200,
                    None,
                    -32603,
                    format!("failed to load pending request: {}", e),
                    None,
                );
            }
        };

        // 2. Load the pipeline state
        let pipeline_state = match self.pipeline_store.load_pipeline(&pending.pipeline_id) {
            Ok(Some(state)) => state,
            Ok(None) => {
                return protocol_http_error(
                    200,
                    None,
                    -32001,
                    "pipeline execution state expired or already completed",
                    None,
                );
            }
            Err(e) => {
                return protocol_http_error(
                    200,
                    None,
                    -32603,
                    format!("failed to load pipeline state: {}", e),
                    None,
                );
            }
        };

        // 2b. Owner check: only the session/principal that the pipeline was
        // suspended under may resume it (before the CAS claim).
        if let Some(denied) = self.reject_foreign_pipeline_resumer(request_context, &pipeline_state)
        {
            return denied;
        }

        // 3. CAS: atomically claim pipeline for execution
        let claimed = self
            .pipeline_store
            .try_claim_pipeline(&pending.pipeline_id, pipeline_state.state_version);
        if !claimed.unwrap_or(false) {
            return ProtocolHttpResponse {
                http_status: 202,
                session_id_header: None,
                response: ProtocolResponse::NotificationAccepted,
            };
        }

        // 4. Build the step result from the client's response
        let step_result = if let Some(err) = error {
            pipeline_store::StepResult {
                output: serde_json::json!({"error": err.message}),
                is_error: true,
                duration_ms: 0,
            }
        } else {
            pipeline_store::StepResult {
                output: result.unwrap_or(Value::Null),
                is_error: false,
                duration_ms: 0,
            }
        };

        // 5. Resume pipeline execution
        let original_jsonrpc_id = pipeline_state.original_jsonrpc_id.clone();
        let related_task_id = pipeline_state.related_task_id.clone();
        // Capture the originating surface before the state is consumed
        // so the Complete arm can project the result onto the right
        // wire shape (tool / prompt / resource).
        let pipeline_surface = pipeline_state.surface;
        // Capture the tool name before resume_pipeline consumes the state;
        // the Complete arm enforces the tool's outputSchema on the result.
        let pipeline_tool_name = pipeline_state.tool_name.clone();
        let outcome = self.execution_dispatcher.resume_pipeline(
            pipeline_state,
            step_result,
            &*self.pipeline_store,
        );

        // 6. Handle the outcome
        match outcome {
            execution::PipelineOutcome::Complete(mut tool_result) => {
                let _ = self.pipeline_store.delete_pipeline(&pending.pipeline_id);
                let _ = self
                    .pipeline_store
                    .delete_pending_server_request(&response_id_str);

                // strict outputSchema parity with the direct path: a
                // suspending tool that declared an outputSchema must
                // still return conforming structuredContent. No-op for
                // prompt/resource surfaces (no tool-output validator).
                if !tool_result.is_error
                    && let Err(validation_err) =
                        self.capability_registry.validate_structured_output(
                            &pipeline_tool_name,
                            &tool_result.structured_content,
                        )
                {
                    warn!(
                        request_id = %request_context.request_id,
                        tool_name = %pipeline_tool_name,
                        "structuredContent failed outputSchema validation, failing tool"
                    );
                    tool_result.structured_content = None;
                    tool_result.is_error = true;
                    tool_result.content.push(crate::protocol::ToolContent::text(format!(
                        "tool '{pipeline_tool_name}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}"
                    )));
                }

                // task-augmented resume completes the owning task with
                // the tool result as its terminal Success envelope and emits
                // one final tasks/status notification. Non-task pipelines
                // keep the legacy deferred-tool-result delivery.
                if let Some(task_id) = related_task_id.as_deref() {
                    let is_error = tool_result.is_error;
                    let status = if is_error {
                        crate::protocol::TaskStatus::Failed
                    } else {
                        crate::protocol::TaskStatus::Completed
                    };
                    let envelope = task_store::TerminalEnvelope::success(
                        serde_json::to_value(&tool_result).unwrap_or(serde_json::json!({})),
                    );
                    let _ = self
                        .task_store
                        .store_task_terminal(task_id, status, envelope);
                    if let Ok(final_record) = self.task_store.get_task(task_id, &pending.session_id)
                    {
                        // Legacy `2025-11-25` continuation-resume path
                        // (HTTP 202 + SSE delivery); modern task resume folds
                        // through the tasks extension, not here.
                        self.deliver_task_status_notification(
                            &pending.session_id,
                            &final_record.task,
                            false,
                        );
                    }
                    return ProtocolHttpResponse {
                        http_status: 202,
                        session_id_header: None,
                        response: ProtocolResponse::NotificationAccepted,
                    };
                }

                // Invariant: deferred_tool_result only fires on
                // non-task pipelines. Task-augmented pipelines returned
                // above via the `related_task_id.is_some()` branch. If
                // the branch and this delivery ever overlap on the same
                // pipeline run (e.g. a future code change), both the
                // client and the task store would observe the terminal
                // envelope — a correctness bug. The debug_assert below
                // pins the invariant for future maintainers.
                debug_assert!(
                    related_task_id.is_none(),
                    "deliver_deferred_tool_result must not run when the pipeline is task-augmented"
                );

                // Modern wire returns the completed
                // result inline (HTTP 200) instead of delivering it
                // over the SSE bus + 202. The original request's
                // jsonrpc id was saved on the pipeline state at
                // suspension time; restore it here.
                //
                // Project the completed pipeline result onto
                // the surface that originated it. A `tools/call`
                // returns the raw `ToolCallResult`; a suspending
                // `prompts/get` must project onto `PromptGetResult`
                // (`{ messages: [...] }`) so the client's MRTR round 2
                // sees a spec-shaped GetPromptResult, not a tool
                // envelope.
                if request_context.negotiated_version
                    == crate::protocol::version::ProtocolVersion::V_2026_07_28
                {
                    let result_value = match pipeline_surface {
                        pipeline_store::PipelineSurface::Prompt => {
                            match invocation::decode_prompt_result(&tool_result) {
                                Ok(prompt_result) => serde_json::to_value(prompt_result)
                                    .expect("prompt get result serialized"),
                                Err(decode_err) => {
                                    return protocol_http_error(
                                        200,
                                        Some(original_jsonrpc_id),
                                        -32603,
                                        format!(
                                            "prompt backend produced a non-conforming response: {decode_err}"
                                        ),
                                        self.debug_error_data(
                                            request_context,
                                            "The backend for this prompt binding must return `{ messages: [...] }` with spec-shaped entries.",
                                        ),
                                    );
                                }
                            }
                        }
                        pipeline_store::PipelineSurface::Resource => {
                            // Resource MRTR resumption is not yet a
                            // reachable scenario (no resources/read
                            // binding suspends today); fall back to the
                            // raw result so the path is total.
                            serde_json::to_value(&tool_result).expect("tool call result serialized")
                        }
                        pipeline_store::PipelineSurface::Tool => {
                            match serde_json::to_value(&tool_result) {
                                Ok(v) => v,
                                Err(error) => {
                                    tracing::error!(error = %error, "tool result serialize failed");
                                    return protocol_http_error(
                                        500,
                                        Some(original_jsonrpc_id),
                                        -32603,
                                        "failed to serialize ToolCallResult",
                                        None,
                                    );
                                }
                            }
                        }
                    };
                    return ProtocolHttpResponse {
                        http_status: 200,
                        session_id_header: None,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: original_jsonrpc_id,
                            result: result_value,
                        }),
                    };
                }

                self.deliver_deferred_tool_result(
                    &pending.session_id,
                    &original_jsonrpc_id,
                    tool_result,
                );
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            execution::PipelineOutcome::Suspended(mut server_request) => {
                let _ = self
                    .pipeline_store
                    .delete_pending_server_request(&response_id_str);
                // carry related-task correlation onto subsequent
                // suspension points so every task-correlated server request
                // continues to advertise the owning task.
                if let Some(task_id) = related_task_id.as_deref() {
                    server_request.params =
                        crate::protocol::v_2025_11_25::wire::tasks::inject_related_task_meta(
                            std::mem::take(&mut server_request.params),
                            task_id,
                        );
                    let _ = self.task_store.update_task_status(
                        task_id,
                        &pending.session_id,
                        crate::protocol::TaskStatus::InputRequired,
                        Some("Pipeline suspended, awaiting input".into()),
                    );
                }
                // Modern wire mints a fresh
                // InputRequiredResult inline (200) for chained
                // suspensions instead of delivering via the SSE bus.
                if request_context.negotiated_version
                    == crate::protocol::version::ProtocolVersion::V_2026_07_28
                {
                    return self
                        .build_modern_input_required_response(
                            request_context,
                            original_jsonrpc_id,
                            server_request,
                            &pending.pipeline_id,
                        )
                        .await;
                }
                self.deliver_server_request(&pending.session_id, server_request)
                    .await;
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            execution::PipelineOutcome::SuspendedMulti(server_requests) => {
                // A resumed pipeline reached another `gather` step
                // (chained multi-entry MRTR). Modern wire only — emit
                // the next batch as one inline InputRequiredResult.
                let _ = self
                    .pipeline_store
                    .delete_pending_server_request(&response_id_str);
                if request_context.negotiated_version
                    == crate::protocol::version::ProtocolVersion::V_2026_07_28
                {
                    return self
                        .build_modern_input_required_response_multi(
                            request_context,
                            original_jsonrpc_id,
                            server_requests,
                            &pending.pipeline_id,
                        )
                        .await;
                }
                protocol_http_error(
                    200,
                    Some(original_jsonrpc_id),
                    -32603,
                    "multi-entry MRTR (gather step) is only supported on the modern wire",
                    None,
                )
            }
        }
    }

    /// SEP-2322 multi-entry MRTR resumption. The client answered a
    /// `gather` step's batch of inputs in one `inputResponses` map;
    /// `responses` is keyed by each input's correlation token. Records
    /// every answer into the gather step's combined output
    /// (`steps.<gather_id>.output.<token>`), resumes the pipeline from
    /// the step after the gather, and projects the completed result
    /// onto the originating surface. Modern wire only — the multi-entry
    /// shape has no legacy SSE+202 representation.
    pub(crate) async fn handle_multi_input_resumption(
        &self,
        request_context: &RequestContext,
        pipeline_id: &str,
        responses: std::collections::BTreeMap<String, Value>,
    ) -> ProtocolHttpResponse {
        // Load the suspended pipeline.
        let pipeline_state = match self.pipeline_store.load_pipeline(pipeline_id) {
            Ok(Some(state)) => state,
            Ok(None) => {
                return protocol_http_error(
                    200,
                    None,
                    -32001,
                    "pipeline execution state expired or already completed",
                    None,
                );
            }
            Err(e) => {
                return protocol_http_error(
                    200,
                    None,
                    -32603,
                    format!("failed to load pipeline state: {e}"),
                    None,
                );
            }
        };

        // Owner check: only the session/principal that the pipeline was
        // suspended under may resume it.
        if let Some(denied) = self.reject_foreign_pipeline_resumer(request_context, &pipeline_state)
        {
            return denied;
        }

        // The current step must be the suspended `gather`. Reject
        // otherwise — a multi-entry resumption against a single-input
        // suspension is a malformed client round-trip.
        let gather_step = pipeline_state.steps.get(pipeline_state.current_step_index);
        let Some(crate::config::PipelineStepConfig::Gather(gather)) = gather_step else {
            return protocol_http_error(
                200,
                None,
                -32600,
                "multi-entry inputResponses but the suspended pipeline step is not a gather step",
                None,
            );
        };
        // `resume_pipeline` records the combined result under the
        // current step's id (the gather), so we only need the input
        // tokens here for pending-request cleanup.
        let expected_tokens: Vec<String> = gather
            .inputs
            .iter()
            .map(|i| i.correlation_token().to_owned())
            .collect();

        // CAS: atomically claim the pipeline for execution.
        let claimed = self
            .pipeline_store
            .try_claim_pipeline(pipeline_id, pipeline_state.state_version);
        if !claimed.unwrap_or(false) {
            return ProtocolHttpResponse {
                http_status: 202,
                session_id_header: None,
                response: ProtocolResponse::NotificationAccepted,
            };
        }

        // Build the gather step's combined output: one entry per
        // answered token. Unanswered tokens (pruned inputs the client
        // never received) are simply absent.
        let mut combined = serde_json::Map::new();
        for (token, value) in &responses {
            combined.insert(token.clone(), value.clone());
        }
        let original_jsonrpc_id = pipeline_state.original_jsonrpc_id.clone();
        let related_task_id = pipeline_state.related_task_id.clone();
        let pipeline_surface = pipeline_state.surface;
        let session_id = pipeline_state.session_id.clone();
        // Capture the tool name before resume_pipeline consumes the state;
        // the Complete arm enforces the tool's outputSchema on the result.
        let pipeline_tool_name = pipeline_state.tool_name.clone();

        let step_result = pipeline_store::StepResult {
            output: Value::Object(combined),
            is_error: false,
            duration_ms: 0,
        };
        let outcome = self.execution_dispatcher.resume_pipeline(
            pipeline_state,
            step_result,
            &*self.pipeline_store,
        );

        // Best-effort cleanup of the per-token pending-request rows.
        for token in &expected_tokens {
            let _ = self.pipeline_store.delete_pending_server_request(token);
        }

        match outcome {
            execution::PipelineOutcome::Complete(mut tool_result) => {
                let _ = self.pipeline_store.delete_pipeline(pipeline_id);

                // strict outputSchema parity with the direct path (no-op
                // for prompt/resource surfaces without a tool validator).
                if !tool_result.is_error
                    && let Err(validation_err) =
                        self.capability_registry.validate_structured_output(
                            &pipeline_tool_name,
                            &tool_result.structured_content,
                        )
                {
                    warn!(
                        request_id = %request_context.request_id,
                        tool_name = %pipeline_tool_name,
                        "structuredContent failed outputSchema validation, failing tool"
                    );
                    tool_result.structured_content = None;
                    tool_result.is_error = true;
                    tool_result.content.push(crate::protocol::ToolContent::text(format!(
                        "tool '{pipeline_tool_name}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}"
                    )));
                }
                if let Some(task_id) = related_task_id.as_deref() {
                    let status = if tool_result.is_error {
                        crate::protocol::TaskStatus::Failed
                    } else {
                        crate::protocol::TaskStatus::Completed
                    };
                    let envelope = task_store::TerminalEnvelope::success(
                        serde_json::to_value(&tool_result).unwrap_or(serde_json::json!({})),
                    );
                    let _ = self
                        .task_store
                        .store_task_terminal(task_id, status, envelope);
                    if let Ok(final_record) = self.task_store.get_task(task_id, &session_id) {
                        // Legacy `2025-11-25` continuation-resume path.
                        self.deliver_task_status_notification(
                            &session_id,
                            &final_record.task,
                            false,
                        );
                    }
                    return ProtocolHttpResponse {
                        http_status: 202,
                        session_id_header: None,
                        response: ProtocolResponse::NotificationAccepted,
                    };
                }
                let result_value = match pipeline_surface {
                    pipeline_store::PipelineSurface::Prompt => {
                        match invocation::decode_prompt_result(&tool_result) {
                            Ok(prompt_result) => serde_json::to_value(prompt_result)
                                .expect("prompt get result serialized"),
                            Err(decode_err) => {
                                return protocol_http_error(
                                    200,
                                    Some(original_jsonrpc_id),
                                    -32603,
                                    format!(
                                        "prompt backend produced a non-conforming response: {decode_err}"
                                    ),
                                    None,
                                );
                            }
                        }
                    }
                    pipeline_store::PipelineSurface::Tool
                    | pipeline_store::PipelineSurface::Resource => {
                        serde_json::to_value(&tool_result).expect("tool call result serialized")
                    }
                };
                ProtocolHttpResponse {
                    http_status: 200,
                    session_id_header: None,
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: original_jsonrpc_id,
                        result: result_value,
                    }),
                }
            }
            execution::PipelineOutcome::Suspended(server_request) => {
                // Pipeline chained into a single suspending step after
                // the gather. Emit it as a fresh InputRequiredResult.
                self.build_modern_input_required_response(
                    request_context,
                    original_jsonrpc_id,
                    server_request,
                    pipeline_id,
                )
                .await
            }
            execution::PipelineOutcome::SuspendedMulti(server_requests) => {
                self.build_modern_input_required_response_multi(
                    request_context,
                    original_jsonrpc_id,
                    server_requests,
                    pipeline_id,
                )
                .await
            }
        }
    }

    /// Translate a legacy-style suspension (a
    /// `ServerJsonRpcRequest` minted by the pipeline engine
    /// for one of `elicitation/create`, `sampling/createMessage`,
    /// `roots/list`) into the modern wire's MRTR
    /// `InputRequiredResult` inline body.
    ///
    /// The `requestState` field is the codec-encoded `pipeline_id`
    /// — small enough to ride the encrypted-inline path
    /// (`"c.<base64url>"`). Clients echo it back on resumption,
    /// the gateway decodes to recover the
    /// `pipeline_id`, and the pipeline picks up where it left off.
    pub(crate) async fn build_modern_input_required_response(
        &self,
        ctx: &RequestContext,
        request_id: serde_json::Value,
        server_request: crate::protocol::ServerJsonRpcRequest,
        pipeline_id: &str,
    ) -> ProtocolHttpResponse {
        self.build_modern_input_required_response_multi(
            ctx,
            request_id,
            vec![server_request],
            pipeline_id,
        )
        .await
    }

    /// SEP-2322 multi-entry variant: maps every entry in
    /// `server_requests` into the one `InputRequiredResult.inputRequests`
    /// map (keyed by each request's server-minted id / correlation
    /// token) under a single `requestState`. The single-entry
    /// [`Self::build_modern_input_required_response`] delegates here
    /// with a one-element vec.
    pub(crate) async fn build_modern_input_required_response_multi(
        &self,
        ctx: &RequestContext,
        request_id: serde_json::Value,
        server_requests: Vec<crate::protocol::ServerJsonRpcRequest>,
        pipeline_id: &str,
    ) -> ProtocolHttpResponse {
        use crate::protocol::v_2026_07_28::wire::mrtr::{InputRequest, InputRequiredResult};

        let Some(services) = self.shared_services.load_full() else {
            tracing::error!(
                request_id = ctx.request_id.as_str(),
                "MRTR suspension requested but SharedServices not installed; \
                 boot ordering bug"
            );
            return protocol_http_error(
                500,
                Some(request_id),
                -32603,
                "modern MRTR codec is not installed",
                None,
            );
        };
        let codec = &services.request_state_codec;
        // Bind the blob to the suspending principal so a leaked/replayed
        // requestState fails AEAD verification if presented by anyone else.
        let owner_aad = crate::protocol::v_2026_07_28::dispatch::request_state::owner_aad(
            ctx.identity.principal_id(),
        );
        let request_state = match codec.encode(pipeline_id.as_bytes(), &owner_aad).await {
            Ok(s) => s,
            Err(error) => {
                tracing::error!(error = %error, "MRTR requestState encode failed");
                return protocol_http_error(
                    500,
                    Some(request_id),
                    -32603,
                    format!("modern MRTR requestState encode failed: {error}"),
                    None,
                );
            }
        };

        let mut input_requests = std::collections::BTreeMap::new();
        for server_request in server_requests {
            let input_request = match server_request.method.as_str() {
                "elicitation/create" => InputRequest::Elicitation {
                    params: server_request.params,
                },
                "sampling/createMessage" => InputRequest::Sampling {
                    params: server_request.params,
                },
                "roots/list" => InputRequest::Roots {
                    params: server_request.params,
                },
                other => {
                    tracing::error!(
                        request_id = ctx.request_id.as_str(),
                        method = other,
                        "modern MRTR cannot translate unknown server-initiated method"
                    );
                    return protocol_http_error(
                        500,
                        Some(request_id),
                        -32603,
                        format!("modern MRTR cannot translate `{other}` to InputRequest"),
                        None,
                    );
                }
            };
            // Correlation token = the server-minted request id. The
            // client echoes it back as the `inputResponses` key on
            // resumption so the gateway knows which input each answer
            // belongs to.
            let correlation_token = match &server_request.id {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            input_requests.insert(correlation_token, input_request);
        }

        let result = InputRequiredResult::new(request_state, input_requests);
        let result_value = match serde_json::to_value(&result) {
            Ok(v) => v,
            Err(error) => {
                tracing::error!(error = %error, "InputRequiredResult serialize failed");
                return protocol_http_error(
                    500,
                    Some(request_id),
                    -32603,
                    "failed to serialize InputRequiredResult",
                    None,
                );
            }
        };

        ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: result_value,
            }),
        }
    }

    /// Try to dispatch `prompts/get` against a binding whose
    /// pipeline contains suspending steps (`elicitation` / `sampling` /
    /// `roots_list`). Mirrors the `tools/call` suspending arm:
    /// on `PipelineOutcome::Suspended` the modern wire returns
    /// `InputRequiredResult` inline; the legacy wire returns
    /// HTTP 202 + delivers the suspended request via the session bus.
    /// On `PipelineOutcome::Complete` the result is projected onto
    /// the `PromptGetResult` surface with the strict codec.
    ///
    /// Returns `None` when the route doesn't reference a suspending
    /// pipeline — the caller falls through to the fast `prompt_get_result`
    /// path (a binding without elicitation/sampling/roots) so we don't
    /// pay the suspending-path overhead on every non-MRTR prompt.
    pub(crate) async fn try_dispatch_prompt_with_suspension(
        &self,
        route: &PromptRoute,
        params: &crate::protocol::PromptGetParams,
        request_context: &RequestContext,
        request_id: &Value,
    ) -> Option<ProtocolHttpResponse> {
        let PromptRoute::Binding { profile } = route else {
            tracing::debug!(
                request_id = request_context.request_id.as_str(),
                "try_dispatch_prompt_with_suspension: route is not Binding"
            );
            return None;
        };
        let has_suspending = self
            .execution_dispatcher
            .pipeline_has_suspending_steps(profile);
        tracing::debug!(
            request_id = request_context.request_id.as_str(),
            profile = %profile,
            has_suspending = has_suspending,
            "try_dispatch_prompt_with_suspension: checking pipeline"
        );
        if !has_suspending {
            return None;
        }
        let execution_request = execution::BackendInvocationRequest {
            context: request_context.clone(),
            tool_name: profile.clone(),
            arguments: params.arguments.clone(),
            expr_ctx: request_context.to_expr_context(profile, params.arguments.as_ref()),
            progress_token: None,
            request_log_level: extract_request_log_level(
                params.meta.as_ref(),
                request_context.negotiated_version,
            )
            .unwrap_or(None),
            legacy_session_log_level: self.legacy_session_log_level(request_context),
            client_capabilities: self.client_capabilities_for_context(request_context),
            cancellation_token: None,
            idempotency_hint: None,
        };
        let outcome = self.execution_dispatcher.execute_pipeline(
            profile,
            &execution_request,
            &*self.pipeline_store,
            pipeline_store::PipelineSurface::Prompt,
        );
        match outcome {
            execution::PipelineOutcome::Complete(result) => {
                match invocation::decode_prompt_result(&result) {
                    Ok(prompt_result) => Some(ProtocolHttpResponse {
                        http_status: 200,
                        session_id_header: None,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: request_id.clone(),
                            result: serde_json::to_value(prompt_result)
                                .expect("prompt get result serialized"),
                        }),
                    }),
                    Err(decode_err) => Some(protocol_http_error(
                        200,
                        Some(request_id.clone()),
                        -32603,
                        format!(
                            "prompt backend produced a non-conforming response: {decode_err}"
                        ),
                        self.debug_error_data(
                            request_context,
                            "The backend for this prompt binding must return `{ messages: [...] }` with spec-shaped entries.",
                        ),
                    )),
                }
            }
            execution::PipelineOutcome::Suspended(server_request) => {
                let pipeline_id_str = execution_request.context.request_id.as_str().to_owned();
                if let Ok(Some(state)) = self.pipeline_store.load_pipeline(&pipeline_id_str) {
                    let _ = self.pipeline_store.set_original_jsonrpc_id_if_version(
                        &pipeline_id_str,
                        state.state_version,
                        request_id,
                    );
                }
                if request_context.negotiated_version
                    == crate::protocol::version::ProtocolVersion::V_2026_07_28
                {
                    Some(
                        self.build_modern_input_required_response(
                            request_context,
                            request_id.clone(),
                            server_request,
                            &pipeline_id_str,
                        )
                        .await,
                    )
                } else {
                    let session_id = request_context.session_id.as_deref().unwrap_or("");
                    self.deliver_server_request(session_id, server_request)
                        .await;
                    Some(ProtocolHttpResponse {
                        http_status: 202,
                        session_id_header: None,
                        response: ProtocolResponse::NotificationAccepted,
                    })
                }
            }
            execution::PipelineOutcome::SuspendedMulti(server_requests) => {
                // A prompt backed by a `gather` step. Multi-entry MRTR
                // is modern-only.
                let pipeline_id_str = execution_request.context.request_id.as_str().to_owned();
                if let Ok(Some(state)) = self.pipeline_store.load_pipeline(&pipeline_id_str) {
                    let _ = self.pipeline_store.set_original_jsonrpc_id_if_version(
                        &pipeline_id_str,
                        state.state_version,
                        request_id,
                    );
                }
                if request_context.negotiated_version
                    == crate::protocol::version::ProtocolVersion::V_2026_07_28
                {
                    Some(
                        self.build_modern_input_required_response_multi(
                            request_context,
                            request_id.clone(),
                            server_requests,
                            &pipeline_id_str,
                        )
                        .await,
                    )
                } else {
                    Some(protocol_http_error(
                        200,
                        Some(request_id.clone()),
                        -32603,
                        "multi-entry MRTR (gather step) is only supported on the modern wire",
                        None,
                    ))
                }
            }
        }
    }
}
