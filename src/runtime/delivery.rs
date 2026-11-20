use super::*;

impl GatewayRuntime {
    /// Run the post-dispatch tool-gate chain and the post-dispatch result
    /// transforms on the result of a resumed tool pipeline, against the
    /// context of the call that started it, as the first-round path does.
    /// A post gate that does not allow the result turns it into an error
    /// result, which the resume answers in its success slot.
    pub(crate) async fn finish_resumed_tool_pipeline(
        &self,
        origin: &PipelineOrigin,
        tool_result: crate::protocol::ToolCallResult,
    ) -> crate::protocol::ToolCallResult {
        let has_gates = self.plugin_registry.has_tool_gate_plugins();
        let has_transforms = self.plugin_registry.has_transform_plugins();
        if !has_gates && !has_transforms && !self.plugin_registry.emits_tool_call_completed() {
            return tool_result;
        }
        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: origin.request_context.request_id.as_str().to_owned(),
            session_id: origin.request_context.session_id.clone(),
            tool_name: origin.tool_name.clone(),
            identity: plugin_identity_from_request(&origin.request_context),
            transport: transport_label(&origin.request_context.transport).to_owned(),
            surface: "tool".to_owned(),
        };
        let execution_ms = (Utc::now() - origin.started_at).num_milliseconds().max(0) as u64;
        let mut result_json =
            serde_json::to_value(&tool_result).expect("tool call result serialized");
        if has_gates || self.plugin_registry.emits_tool_call_completed() {
            let gate_input = if has_gates {
                result_json.clone()
            } else {
                Value::Null
            };
            match self
                .plugin_registry
                .evaluate_tool_gates_post(
                    &plugin_ctx,
                    &origin.arguments,
                    &gate_input,
                    execution_ms,
                    origin.request_context.upstream_request_id.as_deref(),
                )
                .await
            {
                mcpg_plugin_protocol::GateDecision::Allow {
                    modified_result, ..
                } => {
                    if let Some(modified) = modified_result {
                        result_json = modified;
                    }
                }
                mcpg_plugin_protocol::GateDecision::Deny { message, .. }
                | mcpg_plugin_protocol::GateDecision::Challenge { message, .. } => {
                    return post_gate_error_result(message);
                }
                mcpg_plugin_protocol::GateDecision::PendingApproval { approval_id, .. } => {
                    warn!(
                        tool_name = %origin.tool_name,
                        approval_id = %approval_id,
                        "post-dispatch tool gate returned PendingApproval on a resumed pipeline; treating as deny",
                    );
                    return post_gate_error_result(format!(
                        "tool '{}' post-dispatch gate returned invalid PendingApproval decision",
                        origin.tool_name
                    ));
                }
            }
        }
        if has_transforms {
            result_json = self
                .plugin_registry
                .apply_transforms_post(&plugin_ctx, &result_json)
                .await;
        }
        serde_json::from_value(result_json).unwrap_or_else(|e| {
            post_gate_error_result(format!(
                "tool '{}' post-dispatch plugins produced a result that is not a tool result: {e}",
                origin.tool_name
            ))
        })
    }

    /// Publish the SEP-2663 `notifications/tasks` notification carrying the
    /// full task state on the session's delivery bus. The transport's
    /// `subscription_matches` delivers it to a `subscriptions/listen`
    /// subscriber that opted into `TasksStatus`; the cluster delivery bus
    /// carries it to whichever replica holds that stream. It belongs to no
    /// request, so no response drains it.
    pub(crate) fn deliver_task_status_notification(
        &self,
        session_id: &str,
        task: &crate::protocol::Task,
    ) {
        let message = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::Notification,
            jsonrpc_message: serde_json::to_value(task_status_notification(task))
                .expect("task status notification serialized"),
        };
        super::stores::block_on_store(self.delivery_bus.publish(session_id, message)).ok();
    }

    pub fn take_pending_deliveries(
        &self,
        session_id: &str,
    ) -> Vec<pipeline_store::DeliveryMessage> {
        self.pipeline_store
            .take_pending_deliveries(session_id)
            .unwrap_or_default()
    }

    /// Drop the notifications a session still buffers, unread: no request
    /// that could drain them comes.
    pub(crate) fn discard_pending_deliveries(&self, session_id: &str) {
        let _ = self.pipeline_store.take_pending_deliveries(session_id);
    }

    /// Subscribe to delivery messages for a session.
    pub async fn subscribe_session_delivery(
        &self,
        session_id: &str,
    ) -> tokio::sync::mpsc::Receiver<pipeline_store::DeliveryMessage> {
        self.delivery_bus.subscribe(session_id).await
    }

    /// Resume the suspended pipeline `pipeline_id` with the client's answer
    /// to its server-to-client request `token` (MRTR `inputResponses` with
    /// one entry), and answer under `reply_id`, the id of the request that
    /// carries the answer.
    ///
    /// `pipeline_id` comes from the AEAD-sealed `requestState`, so it alone
    /// names the pipeline; `token` must be the request the pipeline awaits.
    /// Checks that the caller owns the pipeline, claims it exactly once
    /// across replicas, resumes it, and answers inline: the completed
    /// result projected onto the surface that started it, or a fresh
    /// `InputRequiredResult` when the pipeline suspends again. A `gather`
    /// step takes the answer as a batch of one.
    pub(crate) async fn resume_single_input(
        &self,
        request_context: &RequestContext,
        reply_id: Value,
        pipeline_id: &str,
        token: &str,
        result: Option<Value>,
        error: Option<JsonRpcErrorBody>,
    ) -> ProtocolHttpResponse {
        let pipeline_state = match self.load_resumable_pipeline(pipeline_id, &reply_id) {
            Ok(state) => state,
            Err(answer) => return answer,
        };
        if let Some(denied) =
            self.reject_foreign_pipeline_resumer(request_context, &pipeline_state, &reply_id)
        {
            return denied;
        }
        if matches!(
            pipeline_state.steps.get(pipeline_state.current_step_index),
            Some(crate::config::PipelineStepConfig::Gather(_))
        ) {
            let answer = match error {
                Some(err) => serde_json::json!({ "error": {
                    "code": err.code,
                    "message": err.message,
                    "data": err.data,
                }}),
                None => result.unwrap_or(Value::Null),
            };
            let answers = std::collections::BTreeMap::from([(token.to_owned(), answer)]);
            return self
                .resume_gather(request_context, reply_id, pipeline_state, answers)
                .await;
        }
        if pipeline_state.pending_server_request_id.as_deref() != Some(token) {
            return self.no_pending_request(request_context, reply_id);
        }

        // A resume that loses the race finds the pipeline already taken.
        let claimed = self
            .pipeline_store
            .try_claim_pipeline(pipeline_id, pipeline_state.state_version);
        if !claimed.unwrap_or(false) {
            return pipeline_gone(reply_id);
        }

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

        let related_task_id = pipeline_state.related_task_id.clone();
        let pipeline_surface = pipeline_state.surface;
        let session_id = pipeline_state.session_id.clone();
        // Captured before resume_pipeline consumes the state; the Complete
        // arm enforces the tool's outputSchema on the result.
        let pipeline_tool_name = pipeline_state.tool_name.clone();
        let origin = PipelineOrigin::of(&pipeline_state);
        let outcome = self.execution_dispatcher.resume_pipeline(
            pipeline_state,
            step_result,
            &*self.pipeline_store,
        );
        self.delete_pending_request_of(token, pipeline_id);

        self.answer_resumed_pipeline(
            request_context,
            outcome,
            ResumedPipeline {
                pipeline_id,
                reply_id,
                related_task_id: related_task_id.as_deref(),
                surface: pipeline_surface,
                session_id: &session_id,
                tool_name: &pipeline_tool_name,
                origin: &origin,
            },
        )
        .await
    }

    /// SEP-2322 multi-entry MRTR resumption. The client answered a
    /// `gather` step's batch of inputs in one `inputResponses` map;
    /// `responses` is keyed by each input's correlation token. Answers
    /// under `reply_id` as [`Self::resume_single_input`] does.
    pub(crate) async fn handle_multi_input_resumption(
        &self,
        request_context: &RequestContext,
        reply_id: Value,
        pipeline_id: &str,
        responses: std::collections::BTreeMap<String, Value>,
    ) -> ProtocolHttpResponse {
        let pipeline_state = match self.load_resumable_pipeline(pipeline_id, &reply_id) {
            Ok(state) => state,
            Err(answer) => return answer,
        };
        if let Some(denied) =
            self.reject_foreign_pipeline_resumer(request_context, &pipeline_state, &reply_id)
        {
            return denied;
        }
        self.resume_gather(request_context, reply_id, pipeline_state, responses)
            .await
    }

    /// The suspended pipeline `pipeline_id`, or the answer to a resume of
    /// one that is gone or cannot be read.
    fn load_resumable_pipeline(
        &self,
        pipeline_id: &str,
        reply_id: &Value,
    ) -> Result<pipeline_store::PipelineExecutionState, ProtocolHttpResponse> {
        match self.pipeline_store.load_pipeline(pipeline_id) {
            Ok(Some(state)) => Ok(state),
            Ok(None) => Err(pipeline_gone(reply_id.clone())),
            Err(e) => Err(protocol_http_error(
                200,
                Some(reply_id.clone()),
                -32603,
                format!("failed to load pipeline state: {e}"),
                None,
            )),
        }
    }

    /// The answer to a resume whose answer names no request the pipeline
    /// awaits. `-32600` is a code of a resume that committed nothing.
    pub(crate) fn no_pending_request(
        &self,
        request_context: &RequestContext,
        reply_id: Value,
    ) -> ProtocolHttpResponse {
        protocol_http_error(
            200,
            Some(reply_id),
            -32600,
            "no pending server request found for this response id",
            self.debug_error_data(
                request_context,
                "the server request may have expired or already been handled",
            ),
        )
    }

    /// Delete the pending-request row of `token` when it belongs to
    /// `pipeline_id`. A correlation token can be a configured constant, so
    /// another caller's suspension may hold the row under the same token.
    pub(crate) fn delete_pending_request_of(&self, token: &str, pipeline_id: &str) {
        if let Ok(Some(pending)) = self.pipeline_store.load_pending_server_request(token)
            && pending.pipeline_id == pipeline_id
        {
            let _ = self.pipeline_store.delete_pending_server_request(token);
        }
    }

    /// Record the answers to a suspended `gather` step's batch into the
    /// step's combined output (`steps.<gather_id>.output.<token>`), resume
    /// the pipeline from the step after the gather, and answer under
    /// `reply_id`. The caller has checked that it owns the pipeline.
    async fn resume_gather(
        &self,
        request_context: &RequestContext,
        reply_id: Value,
        pipeline_state: pipeline_store::PipelineExecutionState,
        responses: std::collections::BTreeMap<String, Value>,
    ) -> ProtocolHttpResponse {
        let pipeline_id_owned = pipeline_state.pipeline_id.clone();
        let pipeline_id = pipeline_id_owned.as_str();
        // A multi-entry resumption against a single-input suspension is a
        // malformed client round-trip.
        let gather_step = pipeline_state.steps.get(pipeline_state.current_step_index);
        let Some(crate::config::PipelineStepConfig::Gather(gather)) = gather_step else {
            return protocol_http_error(
                200,
                Some(reply_id),
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
            return pipeline_gone(reply_id);
        }

        // Build the gather step's combined output: one entry per
        // answered token. Unanswered tokens (pruned inputs the client
        // never received) are simply absent.
        let mut combined = serde_json::Map::new();
        for (token, value) in &responses {
            combined.insert(token.clone(), value.clone());
        }
        let related_task_id = pipeline_state.related_task_id.clone();
        let pipeline_surface = pipeline_state.surface;
        let session_id = pipeline_state.session_id.clone();
        let pipeline_tool_name = pipeline_state.tool_name.clone();

        let step_result = pipeline_store::StepResult {
            output: Value::Object(combined),
            is_error: false,
            duration_ms: 0,
        };
        let origin = PipelineOrigin::of(&pipeline_state);
        let outcome = self.execution_dispatcher.resume_pipeline(
            pipeline_state,
            step_result,
            &*self.pipeline_store,
        );

        // Best-effort cleanup of this pipeline's per-token pending-request
        // rows.
        for token in &expected_tokens {
            self.delete_pending_request_of(token, pipeline_id);
        }

        self.answer_resumed_pipeline(
            request_context,
            outcome,
            ResumedPipeline {
                pipeline_id,
                reply_id,
                related_task_id: related_task_id.as_deref(),
                surface: pipeline_surface,
                session_id: &session_id,
                tool_name: &pipeline_tool_name,
                origin: &origin,
            },
        )
        .await
    }

    /// The answer to a resume: a completed pipeline's result inline, or a
    /// fresh `InputRequiredResult` when it suspends again. A completed
    /// pipeline that runs for a task also latches the task terminal and
    /// tells the session of its final status.
    async fn answer_resumed_pipeline(
        &self,
        request_context: &RequestContext,
        outcome: execution::PipelineOutcome,
        resumed: ResumedPipeline<'_>,
    ) -> ProtocolHttpResponse {
        match outcome {
            execution::PipelineOutcome::Complete(mut tool_result) => {
                let _ = self.pipeline_store.delete_pipeline(resumed.pipeline_id);

                // strict outputSchema parity with the direct path: a
                // suspending tool that declared an outputSchema must
                // still return conforming structuredContent. No-op for
                // prompt/resource surfaces (no tool-output validator).
                if !tool_result.is_error
                    && let Err(validation_err) =
                        self.capability_registry.validate_structured_output(
                            resumed.tool_name,
                            &tool_result.structured_content,
                        )
                {
                    warn!(
                        request_id = %request_context.request_id,
                        tool_name = %resumed.tool_name,
                        "structuredContent failed outputSchema validation, failing tool"
                    );
                    tool_result.structured_content = None;
                    tool_result.is_error = true;
                    tool_result.content.push(crate::protocol::ToolContent::text(format!(
                        "tool '{}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}",
                        resumed.tool_name
                    )));
                }
                if resumed.surface == pipeline_store::PipelineSurface::Tool {
                    tool_result = self
                        .finish_resumed_tool_pipeline(resumed.origin, tool_result)
                        .await;
                }
                if let Some(task_id) = resumed.related_task_id {
                    self.complete_resumed_task(task_id, &resumed, &tool_result);
                }
                self.pipeline_result_response(
                    request_context,
                    resumed.reply_id,
                    resumed.surface,
                    &tool_result,
                )
            }
            execution::PipelineOutcome::Suspended(server_request) => {
                self.build_input_required_response(
                    request_context,
                    resumed.reply_id,
                    server_request,
                    resumed.pipeline_id,
                )
                .await
            }
            execution::PipelineOutcome::SuspendedMulti(server_requests) => {
                self.build_input_required_response_multi(
                    request_context,
                    resumed.reply_id,
                    server_requests,
                    resumed.pipeline_id,
                )
                .await
            }
        }
    }

    /// Latch the task a resumed pipeline ran for with the pipeline's
    /// result, and send the session that suspended it the task's final
    /// status. The first terminal write wins, so a later fold of the same
    /// result onto the task changes nothing.
    fn complete_resumed_task(
        &self,
        task_id: &str,
        resumed: &ResumedPipeline<'_>,
        tool_result: &crate::protocol::ToolCallResult,
    ) {
        let status = if tool_result.is_error {
            crate::protocol::TaskStatus::Failed
        } else {
            crate::protocol::TaskStatus::Completed
        };
        let envelope = task_store::TerminalEnvelope::success(
            serde_json::to_value(tool_result).unwrap_or(serde_json::json!({})),
        );
        let _ = self
            .task_store
            .store_task_terminal(task_id, status, envelope);
        if let Some(owner) = resumed.origin.request_context.task_owner_key()
            && let Ok(record) = self.task_store.get_task(task_id, &owner)
        {
            self.deliver_task_status_notification(resumed.session_id, &record.task);
        }
    }

    /// The JSON-RPC success of a completed pipeline under `reply_id`, the id
    /// of the request it answers, projected onto the surface that started
    /// it. A `tools/call` returns the raw `ToolCallResult`; a suspending
    /// `prompts/get` projects onto `PromptGetResult` (`{ messages: [...] }`)
    /// so the client's MRTR round 2 sees a spec-shaped result, not a tool
    /// envelope.
    fn pipeline_result_response(
        &self,
        request_context: &RequestContext,
        reply_id: Value,
        surface: pipeline_store::PipelineSurface,
        tool_result: &crate::protocol::ToolCallResult,
    ) -> ProtocolHttpResponse {
        let result_value = match surface {
            pipeline_store::PipelineSurface::Prompt => {
                match invocation::decode_prompt_result(tool_result) {
                    Ok(prompt_result) => {
                        serde_json::to_value(prompt_result).expect("prompt get result serialized")
                    }
                    Err(decode_err) => {
                        return protocol_http_error(
                            200,
                            Some(reply_id),
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
            // No resources/read binding suspends, so a resource surface
            // answers with the raw result.
            pipeline_store::PipelineSurface::Tool | pipeline_store::PipelineSurface::Resource => {
                match serde_json::to_value(tool_result) {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::error!(error = %error, "tool result serialize failed");
                        return protocol_http_error(
                            500,
                            Some(reply_id),
                            -32603,
                            "failed to serialize ToolCallResult",
                            None,
                        );
                    }
                }
            }
        };
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: reply_id,
                result: result_value,
            }),
        }
    }

    /// Translate a suspension (a `ServerJsonRpcRequest` minted by the
    /// pipeline engine for one of `elicitation/create`,
    /// `sampling/createMessage`, `roots/list`) into the MRTR
    /// `InputRequiredResult` inline body.
    ///
    /// The `requestState` field is the codec-encoded `pipeline_id`
    /// — small enough to ride the encrypted-inline path
    /// (`"c.<base64url>"`). Clients echo it back on resumption,
    /// the gateway decodes to recover the
    /// `pipeline_id`, and the pipeline picks up where it left off.
    pub(crate) async fn build_input_required_response(
        &self,
        ctx: &RequestContext,
        request_id: serde_json::Value,
        server_request: crate::protocol::ServerJsonRpcRequest,
        pipeline_id: &str,
    ) -> ProtocolHttpResponse {
        self.build_input_required_response_multi(ctx, request_id, vec![server_request], pipeline_id)
            .await
    }

    /// SEP-2322 multi-entry variant: maps every entry in
    /// `server_requests` into the one `InputRequiredResult.inputRequests`
    /// map (keyed by each request's server-minted id / correlation
    /// token) under a single `requestState`. The single-entry
    /// [`Self::build_input_required_response`] delegates here
    /// with a one-element vec.
    pub(crate) async fn build_input_required_response_multi(
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
                "MRTR codec is not installed",
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
                    format!("MRTR requestState encode failed: {error}"),
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
                        "MRTR cannot translate unknown server-initiated method"
                    );
                    return protocol_http_error(
                        500,
                        Some(request_id),
                        -32603,
                        format!("MRTR cannot translate `{other}` to InputRequest"),
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
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: result_value,
            }),
        }
    }

    /// Try to dispatch `prompts/get` against a binding whose
    /// pipeline contains suspending steps (`elicitation` / `sampling` /
    /// `roots_list` / `gather`). Mirrors the `tools/call` suspending arm:
    /// a suspension answers with an inline `InputRequiredResult`; a
    /// completed pipeline is projected onto the `PromptGetResult` surface
    /// with the strict codec.
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
            context: Arc::new(request_context.clone()),
            tool_name: profile.clone(),
            arguments: params.arguments.clone(),
            expr_ctx: request_context.to_expr_context(profile, params.arguments.as_ref()),
            progress_token: None,
            request_log_level: extract_request_log_level(params.meta.as_ref()).unwrap_or(None),
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
        let server_requests = match outcome {
            execution::PipelineOutcome::Complete(result) => {
                return Some(self.pipeline_result_response(
                    request_context,
                    request_id.clone(),
                    pipeline_store::PipelineSurface::Prompt,
                    &result,
                ));
            }
            execution::PipelineOutcome::Suspended(server_request) => vec![server_request],
            execution::PipelineOutcome::SuspendedMulti(server_requests) => server_requests,
        };
        let pipeline_id = execution_request.context.request_id.as_str().to_owned();
        if let Ok(Some(state)) = self.pipeline_store.load_pipeline(&pipeline_id) {
            let _ = self.pipeline_store.set_original_jsonrpc_id_if_version(
                &pipeline_id,
                state.state_version,
                request_id,
            );
        }
        Some(
            self.build_input_required_response_multi(
                request_context,
                request_id.clone(),
                server_requests,
                &pipeline_id,
            )
            .await,
        )
    }
}

/// The answer to a resume whose pipeline is gone: expired, completed, or
/// claimed by a concurrent resume. `-32001` is a code of a resume that
/// committed nothing, so this caller's `requestState` stays unspent.
fn pipeline_gone(reply_id: Value) -> ProtocolHttpResponse {
    protocol_http_error(
        200,
        Some(reply_id),
        -32001,
        "pipeline execution state expired or already completed",
        None,
    )
}

/// What a resume needs of a pipeline after `resume_pipeline` consumed
/// its stored state.
struct ResumedPipeline<'a> {
    pipeline_id: &'a str,
    /// The id of the request that carries the answer, which the resume
    /// answers under.
    reply_id: Value,
    related_task_id: Option<&'a str>,
    surface: pipeline_store::PipelineSurface,
    session_id: &'a str,
    tool_name: &'a str,
    origin: &'a PipelineOrigin,
}

/// The call that started a suspended tool pipeline, captured before the
/// resume consumes its stored state.
pub(crate) struct PipelineOrigin {
    pub(crate) request_context: RequestContext,
    pub(crate) tool_name: String,
    pub(crate) arguments: Value,
    pub(crate) started_at: DateTime<Utc>,
}

impl PipelineOrigin {
    pub(crate) fn of(state: &pipeline_store::PipelineExecutionState) -> Self {
        Self {
            request_context: state.request_context.clone(),
            tool_name: state.tool_name.clone(),
            arguments: state.original_args.clone(),
            started_at: state.created_at,
        }
    }
}

fn post_gate_error_result(message: String) -> crate::protocol::ToolCallResult {
    crate::protocol::ToolCallResult {
        content: vec![crate::protocol::ToolContent::text(message)],
        structured_content: None,
        is_error: true,
        meta: None,
    }
}
