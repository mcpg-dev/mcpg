use super::*;

impl ExecutionDispatcher {
    /// Run the pipeline's step list from `state.current_step_index`
    /// onward, advancing the index after each completed step so that a
    /// resume re-enters at the next pending one.
    ///
    /// Backend steps (HTTP / SQL / NATS / Kafka / gRPC / GraphQL /
    /// pipeline / mock / log) run inline and feed their output into the
    /// next step's expression context. Steps that need client input
    /// (elicitation, sampling, roots/list, and the SEP-2322 `gather`
    /// fan-out) cannot complete synchronously: the loop returns
    /// `Suspended` / `SuspendedMulti` with the server-to-client request
    /// to send, having already persisted `state` so `resume_pipeline`
    /// can pick up where it left off once the client answers.
    ///
    /// At each step boundary the loop also enforces the overall
    /// pipeline timeout and honours cooperative cancellation, returning
    /// an `is_error` `Complete` in either case. Returns `Complete`,
    /// `Suspended`, or `SuspendedMulti`.
    pub(super) fn execute_pipeline_steps(
        &self,
        state: &mut PipelineExecutionState,
        profile: &str,
        request: &BackendInvocationRequest,
        // Backend steps build their own per-step context locally; the
        // caller's context is no longer threaded through (all backend
        // step types now dispatch via plugin helpers).
        _execution_context: &ToolExecutionContext,
        pipeline_store: &dyn PipelineStore,
    ) -> PipelineOutcome {
        let pipeline_start = state.created_at;
        let mut last_step_output = Value::Null;

        let args = state.original_args.clone();

        // Build the expression context for pipeline steps, carrying identity / transport info
        let mut pipeline_expr_ctx = request.expr_ctx.clone();

        while state.current_step_index < state.steps.len() {
            let i = state.current_step_index;
            let step = state.steps[i].clone();
            let step_id = step.id().to_owned();

            // Check overall pipeline timeout
            let elapsed_ms = (chrono::Utc::now() - pipeline_start)
                .num_milliseconds()
                .max(0) as u64;
            if elapsed_ms >= state.pipeline_timeout_ms {
                return PipelineOutcome::Complete(ToolCallResult {
                    content: vec![ToolContent::text("pipeline execution timed out".to_owned())],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                });
            }

            // cooperative cancellation at step boundary. When the
            // cancellation-bus subscriber (T4-05) flipped the token for
            // this request or its owning task, abort here rather than
            // starting another downstream call.
            if let Some(token) = request.cancellation_token.as_ref()
                && token.is_cancelled()
            {
                metrics::counter!(
                    "mcpg_pipeline_cancelled_between_steps_total",
                    "pipeline" => profile.to_owned(),
                )
                .increment(1);
                return PipelineOutcome::Complete(ToolCallResult {
                    content: vec![ToolContent::text(
                        "pipeline cancelled before next step".to_owned(),
                    )],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                });
            }

            // Enforce capability negotiation before emitting
            // any server-to-client request, and additionally enforce per-mode
            // elicitation capabilities for form vs URL mode.
            let caps = &state.client_capabilities;
            let gating_error: Option<String> = match &step {
                crate::config::PipelineStepConfig::Elicitation(elicit)
                    if !caps.supports_elicitation() =>
                {
                    Some(
                        "client did not advertise elicitation capability; cannot emit elicitation/create"
                            .to_owned(),
                    )
                }
                crate::config::PipelineStepConfig::Elicitation(elicit)
                    if matches!(
                        elicit.mode,
                        crate::config::PipelineElicitationMode::Form
                    ) && !caps.supports_elicitation_form() =>
                {
                    Some(
                        "client did not advertise form-mode elicitation; this pipeline step requires it"
                            .to_owned(),
                    )
                }
                crate::config::PipelineStepConfig::Elicitation(elicit)
                    if matches!(
                        elicit.mode,
                        crate::config::PipelineElicitationMode::Url
                    ) && !caps.supports_elicitation_url() =>
                {
                    Some(
                        "client did not advertise url-mode elicitation; configure the step with mode: form or upgrade the client"
                            .to_owned(),
                    )
                }
                crate::config::PipelineStepConfig::Sampling(_) if !caps.supports_sampling() => {
                    Some(
                        "client did not advertise sampling capability; cannot emit sampling/createMessage"
                            .to_owned(),
                    )
                }
                crate::config::PipelineStepConfig::RootsList(_) if !caps.supports_roots() => {
                    Some(
                        "client did not advertise roots capability; cannot emit roots/list"
                            .to_owned(),
                    )
                }
                _ => None,
            };
            if let Some(message) = gating_error {
                // SEP-2322 capability-aware pruning. When the operator
                // marked this suspending step `skip_if_unsupported`, a
                // missing client capability skips the step (records an
                // empty skipped result and advances) rather than failing
                // the pipeline — so a pipeline offering elicitation +
                // sampling can still suspend on sampling for a
                // sampling-only client. Default (flag unset) keeps the
                // fail-closed contract.
                let skip_if_unsupported = match &step {
                    crate::config::PipelineStepConfig::Elicitation(s) => s.skip_if_unsupported,
                    crate::config::PipelineStepConfig::Sampling(s) => s.skip_if_unsupported,
                    crate::config::PipelineStepConfig::RootsList(s) => s.skip_if_unsupported,
                    _ => false,
                };
                if skip_if_unsupported {
                    info!(
                        pipeline = %profile,
                        step_id = %step.id(),
                        reason = %message,
                        "pipeline step skipped (capability not advertised, skip_if_unsupported set)"
                    );
                    state.completed_steps.insert(
                        step.id().to_owned(),
                        StepResult {
                            output: serde_json::json!({ "skipped": true, "reason": message }),
                            is_error: false,
                            duration_ms: 0,
                        },
                    );
                    state.current_step_index += 1;
                    continue;
                }
                return PipelineOutcome::Complete(ToolCallResult {
                    content: vec![ToolContent::text(message)],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                });
            }

            // Handle elicitation/sampling steps → suspend
            match &step {
                crate::config::PipelineStepConfig::Elicitation(elicitation) => {
                    let server_request_id = elicitation
                        .correlation_token
                        .clone()
                        .unwrap_or_else(|| mint_server_request_id(&request.context));
                    // project the full elicitation surface onto the
                    // outgoing params, including URL-mode fields.
                    //
                    // URL-mode `elicitationId` is set to the same
                    // `server_request_id` used for the pending-request
                    // lookup so the cluster-safe
                    // `pipeline_store.load_pending_server_request` resolves
                    // the owning pipeline when the client later posts
                    // `notifications/elicitation/complete`, regardless of
                    // which instance receives the notification.
                    // Operator-pinned `elicitation_id` in config is
                    // ignored in favour of the request_id to preserve
                    // resumability; the operator override was originally
                    // intended only for deduplication across retries.
                    let (mode_string, elicitation_id, url) = match elicitation.mode {
                        crate::config::PipelineElicitationMode::Form => {
                            ("form".to_owned(), None, None)
                        }
                        crate::config::PipelineElicitationMode::Url => (
                            "url".to_owned(),
                            Some(server_request_id.clone()),
                            elicitation.url.clone(),
                        ),
                    };
                    // (SEP-414 draft): propagate trace context via _meta.
                    let meta_with_trace = inject_trace_into_meta(
                        elicitation.meta.clone(),
                        request.context.trace_context.as_ref(),
                    );
                    // (SEP-1330): reject schemas that would
                    // require a non-primitive form widget. Returning
                    // an error envelope (instead of suspending the
                    // pipeline) gives the client a clear failure.
                    if let Err(reason) =
                        validate_elicitation_requested_schema(elicitation.requested_schema.as_ref())
                    {
                        metrics::counter!("mcpg_elicitation_schema_rejected_total").increment(1);
                        return PipelineOutcome::Complete(ToolCallResult {
                            content: vec![ToolContent::text(format!(
                                "elicitation/create rejected: {reason}"
                            ))],
                            structured_content: None,
                            is_error: true,
                            meta: None,
                        });
                    }
                    let server_request = ServerJsonRpcRequest {
                        jsonrpc: JSONRPC_VERSION,
                        id: Value::String(server_request_id.clone()),
                        method: "elicitation/create".to_owned(),
                        params: serde_json::to_value(ElicitationCreateParams {
                            mode: mode_string.clone(),
                            message: elicitation.message.clone(),
                            requested_schema: elicitation.requested_schema.clone(),
                            elicitation_id,
                            url,
                            task: None,
                            presentation_hint: elicitation.presentation_hint.clone(),
                            meta: meta_with_trace,
                        })
                        .expect("elicitation params serialized"),
                    };

                    // Persist the suspended state (and an index entry
                    // keyed by the server request id) BEFORE returning
                    // the request to the client. `resume_pipeline`
                    // reloads this state when the client's response
                    // arrives, so the save must happen first or a fast
                    // reply could race ahead of durable state.
                    state.suspended_at = Some(chrono::Utc::now());
                    state.pending_server_request_id = Some(server_request_id.clone());
                    state.elicitation_timeout_ms = Some(elicitation.timeout_ms);
                    state.state_version += 1;
                    let _ = pipeline_store.save_pipeline(state);
                    let _ = pipeline_store.save_pending_server_request(&PendingServerRequest {
                        server_request_id,
                        pipeline_id: state.pipeline_id.clone(),
                        session_id: state.session_id.clone(),
                        step_id: elicitation.id.clone(),
                        timeout_ms: elicitation.timeout_ms,
                        created_at: chrono::Utc::now(),
                    });

                    metrics::counter!(
                        "mcpg_pipeline_suspensions_total",
                        "step_type" => "elicitation",
                        "pipeline" => profile.to_owned(),
                    )
                    .increment(1);
                    // Audit the elicitation/create request.
                    if let Some(registry) = self.plugin_registry.clone() {
                        let actor = crate::runtime::plugin_identity_from_request(&request.context);
                        let request_id = request.context.request_id.as_str().to_owned();
                        let session_id = state.session_id.clone();
                        let pipeline_id = state.pipeline_id.clone();
                        let step_id = elicitation.id.clone();
                        let server_request_id_owned =
                            state.pending_server_request_id.clone().unwrap_or_default();
                        let mode_owned = mode_string.clone();
                        tokio::spawn(async move {
                            let event = mcpg_plugin_host::audit_events::elicitation_requested_event(
                                actor,
                                &request_id,
                                Some(&session_id),
                                &pipeline_id,
                                &step_id,
                                &server_request_id_owned,
                                &mode_owned,
                            );
                            let _ = registry.emit_audit_event(&event).await;
                        });
                    }
                    return PipelineOutcome::Suspended(server_request);
                }
                crate::config::PipelineStepConfig::Sampling(sampling) => {
                    // Project the full sampling surface and
                    // enforce capability gating on every capability-scoped
                    // field. Either `tools` or `tool_choice` requires the
                    // client to advertise `sampling.tools`; silently
                    // stripping them would hide a misconfiguration and
                    // violate the MCP outbound-capability contract, so
                    // this fails-closed instead.
                    let uses_tools_surface =
                        sampling.tools.is_some() || sampling.tool_choice.is_some();
                    if uses_tools_surface && !caps.supports_sampling_tools() {
                        return PipelineOutcome::Complete(ToolCallResult {
                            content: vec![ToolContent::text(
                                "step configured with sampling tools / toolChoice but client did not advertise sampling.tools"
                                    .to_owned(),
                            )],
                            structured_content: None,
                            is_error: true,
                            meta: None,
                        });
                    }
                    if sampling.include_context.is_some() && !caps.supports_sampling_context() {
                        return PipelineOutcome::Complete(ToolCallResult {
                            content: vec![ToolContent::text(
                                "step configured with includeContext but client did not advertise sampling.context"
                                    .to_owned(),
                            )],
                            structured_content: None,
                            is_error: true,
                            meta: None,
                        });
                    }
                    let version_is_modern = request.context.negotiated_version
                        == crate::protocol::version::ProtocolVersion::V_2026_07_28;
                    // SEP-2577: Sampling is deprecated on the modern wire.
                    if version_is_modern {
                        crate::protocol::shared::deprecation::meter_deprecated_feature(
                            crate::protocol::shared::deprecation::FEATURE_SAMPLING,
                        );
                        // SEP-2596: the `includeContext` values
                        // `"thisServer"`/`"allServers"` are deprecated.
                        // Don't silently forward them — warn so the
                        // emission is steered toward removal.
                        use crate::protocol::SamplingIncludeContext;
                        if matches!(
                            sampling.include_context,
                            Some(SamplingIncludeContext::ThisServer)
                                | Some(SamplingIncludeContext::AllServers)
                        ) {
                            tracing::warn!(
                                step = %sampling.id,
                                "sampling step uses the deprecated includeContext value \
                                 (SEP-2596 thisServer/allServers); migrate before removal"
                            );
                            crate::protocol::shared::deprecation::meter_deprecated_feature(
                                "include_context",
                            );
                        }
                    }
                    let server_request_id = sampling
                        .correlation_token
                        .clone()
                        .unwrap_or_else(|| mint_server_request_id(&request.context));
                    let messages: Vec<SamplingMessage> = sampling
                        .messages
                        .iter()
                        .map(|m| SamplingMessage {
                            role: m.role.clone(),
                            content: SamplingMessageContent::Text {
                                text: m.content.clone(),
                                annotations: None,
                            },
                            meta: None,
                        })
                        .collect();
                    // (SEP-414 draft): inject W3C trace context into
                    // `_meta` so the client can correlate sampling requests
                    // with the originating gateway span without requiring a
                    // transport-layer header round-trip.
                    let meta_with_trace = inject_trace_into_meta(
                        sampling.meta.clone(),
                        request.context.trace_context.as_ref(),
                    );

                    let server_request = ServerJsonRpcRequest {
                        jsonrpc: JSONRPC_VERSION,
                        id: Value::String(server_request_id.clone()),
                        method: "sampling/createMessage".to_owned(),
                        params: serde_json::to_value(SamplingCreateMessageParams {
                            messages,
                            // max_tokens is REQUIRED on the wire.
                            // Pipeline config sentinel `0` coerces to
                            // DEFAULT_SAMPLING_MAX_TOKENS so the
                            // outbound envelope is always spec-shaped.
                            max_tokens: coerce_sampling_max_tokens(sampling.max_tokens),
                            model_preferences: sampling.model_preferences.clone(),
                            system_prompt: sampling.system_prompt.clone(),
                            include_context: sampling.include_context.clone(),
                            temperature: sampling.temperature,
                            stop_sequences: sampling.stop_sequences.clone(),
                            metadata: sampling.metadata.clone(),
                            tools: sampling.tools.clone(),
                            tool_choice: sampling.tool_choice.clone(),
                            task: None,
                            meta: meta_with_trace,
                        })
                        .expect("sampling params serialized"),
                    };

                    state.suspended_at = Some(chrono::Utc::now());
                    state.pending_server_request_id = Some(server_request_id.clone());
                    state.elicitation_timeout_ms = Some(sampling.timeout_ms);
                    state.state_version += 1;
                    let _ = pipeline_store.save_pipeline(state);
                    let _ = pipeline_store.save_pending_server_request(&PendingServerRequest {
                        server_request_id,
                        pipeline_id: state.pipeline_id.clone(),
                        session_id: state.session_id.clone(),
                        step_id: sampling.id.clone(),
                        timeout_ms: sampling.timeout_ms,
                        created_at: chrono::Utc::now(),
                    });

                    metrics::counter!(
                        "mcpg_pipeline_suspensions_total",
                        "step_type" => "sampling",
                        "pipeline" => profile.to_owned(),
                    )
                    .increment(1);
                    // Record the gateway-proxied LLM call on the audit
                    // lane per AI-governance + cost-attribution
                    // requirements. Prompt hash (BLAKE3 of canonical
                    // messages) is the correlation key; full prompt
                    // never lands on the audit lane.
                    if let Some(registry) = self.plugin_registry.clone() {
                        let prompt_hash = hash_sampling_messages(&sampling.messages);
                        let actor = crate::runtime::plugin_identity_from_request(&request.context);
                        let request_id = request.context.request_id.as_str().to_owned();
                        let session_id = state.session_id.clone();
                        let pipeline_id = state.pipeline_id.clone();
                        let step_id = sampling.id.clone();
                        let server_request_id_owned =
                            state.pending_server_request_id.clone().unwrap_or_default();
                        let message_count = sampling.messages.len() as u64;
                        let max_tokens = coerce_sampling_max_tokens(sampling.max_tokens) as i64;
                        // Best-effort model hint — if the operator
                        // pinned a preference (an opaque JSON
                        // Value on the wire), pull the first
                        // `hints[0].name` string. The builder
                        // falls back to `sampling://any` when this
                        // is None.
                        let model_hint: Option<String> = sampling
                            .model_preferences
                            .as_ref()
                            .and_then(|v| v.get("hints"))
                            .and_then(|h| h.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|h0| h0.get("name"))
                            .and_then(|n| n.as_str())
                            .map(str::to_owned);
                        // include_context is a typed enum — render
                        // through serde_json (camelCase) to get the
                        // canonical "thisServer"/"allServers"/"none"
                        // wire form for the audit detail.
                        let include_context: Option<String> = sampling
                            .include_context
                            .as_ref()
                            .and_then(|ic| serde_json::to_value(ic).ok())
                            .and_then(|v| v.as_str().map(str::to_owned));
                        tokio::spawn(async move {
                            let event = mcpg_plugin_host::audit_events::sampling_requested_event(
                                actor,
                                &request_id,
                                Some(&session_id),
                                &pipeline_id,
                                &step_id,
                                &server_request_id_owned,
                                &prompt_hash,
                                message_count,
                                max_tokens,
                                model_hint.as_deref(),
                                include_context.as_deref(),
                            );
                            let _ = registry.emit_audit_event(&event).await;
                        });
                    }
                    return PipelineOutcome::Suspended(server_request);
                }
                crate::config::PipelineStepConfig::RootsList(roots_list) => {
                    let server_request_id = roots_list
                        .correlation_token
                        .clone()
                        .unwrap_or_else(|| mint_server_request_id(&request.context));
                    // (SEP-414): propagate trace context via _meta
                    // on server-initiated roots/list so clients can
                    // correlate with the originating gateway span.
                    let params = match inject_trace_into_meta(
                        None,
                        request.context.trace_context.as_ref(),
                    ) {
                        Some(meta) => serde_json::json!({ "_meta": meta }),
                        None => serde_json::json!({}),
                    };
                    let server_request = ServerJsonRpcRequest {
                        jsonrpc: JSONRPC_VERSION,
                        id: Value::String(server_request_id.clone()),
                        method: "roots/list".to_owned(),
                        params,
                    };

                    state.suspended_at = Some(chrono::Utc::now());
                    state.pending_server_request_id = Some(server_request_id.clone());
                    state.elicitation_timeout_ms = Some(roots_list.timeout_ms);
                    state.state_version += 1;
                    let _ = pipeline_store.save_pipeline(state);
                    let _ = pipeline_store.save_pending_server_request(&PendingServerRequest {
                        server_request_id,
                        pipeline_id: state.pipeline_id.clone(),
                        session_id: state.session_id.clone(),
                        step_id: roots_list.id.clone(),
                        timeout_ms: roots_list.timeout_ms,
                        created_at: chrono::Utc::now(),
                    });

                    metrics::counter!(
                        "mcpg_pipeline_suspensions_total",
                        "step_type" => "roots_list",
                        "pipeline" => profile.to_owned(),
                    )
                    .increment(1);
                    // SEP-2577: Roots is deprecated on the modern wire.
                    // Meter use so operators can track migration pressure
                    // during the SEP-2596 deprecation window.
                    if request.context.negotiated_version
                        == crate::protocol::version::ProtocolVersion::V_2026_07_28
                    {
                        crate::protocol::shared::deprecation::meter_deprecated_feature(
                            crate::protocol::shared::deprecation::FEATURE_ROOTS,
                        );
                    }
                    // Audit the roots/list request.
                    if let Some(registry) = self.plugin_registry.clone() {
                        let actor = crate::runtime::plugin_identity_from_request(&request.context);
                        let request_id = request.context.request_id.as_str().to_owned();
                        let session_id = state.session_id.clone();
                        let pipeline_id = state.pipeline_id.clone();
                        let step_id = roots_list.id.clone();
                        let server_request_id_owned =
                            state.pending_server_request_id.clone().unwrap_or_default();
                        tokio::spawn(async move {
                            let event = mcpg_plugin_host::audit_events::roots_requested_event(
                                actor,
                                &request_id,
                                Some(&session_id),
                                &pipeline_id,
                                &step_id,
                                &server_request_id_owned,
                            );
                            let _ = registry.emit_audit_event(&event).await;
                        });
                    }
                    return PipelineOutcome::Suspended(server_request);
                }
                crate::config::PipelineStepConfig::Gather(gather) => {
                    // SEP-2322 multi-entry MRTR. Build one server
                    // request per input, pruning any whose required
                    // client capability wasn't advertised (the modern
                    // wire's "only emit supported inputRequests"
                    // contract). All surviving requests are emitted in
                    // one suspension; the pipeline resumes when the
                    // client answers them together.
                    let mut requests: Vec<ServerJsonRpcRequest> = Vec::new();
                    let mut longest_timeout_ms: u64 = 0;
                    for input in &gather.inputs {
                        let token = input.correlation_token().to_owned();
                        let (request_opt, timeout_ms) = match input {
                            crate::config::GatherInputConfig::Elicitation {
                                message,
                                requested_schema,
                                ..
                            } => {
                                if !caps.supports_elicitation() {
                                    (None, 0)
                                } else {
                                    let meta = inject_trace_into_meta(
                                        None,
                                        request.context.trace_context.as_ref(),
                                    );
                                    let params = serde_json::to_value(ElicitationCreateParams {
                                        mode: "form".to_owned(),
                                        message: message.clone(),
                                        requested_schema: requested_schema.clone(),
                                        elicitation_id: None,
                                        url: None,
                                        task: None,
                                        presentation_hint: None,
                                        meta,
                                    })
                                    .expect("gather elicitation params serialized");
                                    (
                                        Some(ServerJsonRpcRequest {
                                            jsonrpc: JSONRPC_VERSION,
                                            id: Value::String(token.clone()),
                                            method: "elicitation/create".to_owned(),
                                            params,
                                        }),
                                        60_000,
                                    )
                                }
                            }
                            crate::config::GatherInputConfig::Sampling {
                                messages,
                                max_tokens,
                                system_prompt,
                                ..
                            } => {
                                if !caps.supports_sampling() {
                                    (None, 0)
                                } else {
                                    let msgs: Vec<SamplingMessage> = messages
                                        .iter()
                                        .map(|m| SamplingMessage {
                                            role: m.role.clone(),
                                            content: SamplingMessageContent::Text {
                                                text: m.content.clone(),
                                                annotations: None,
                                            },
                                            meta: None,
                                        })
                                        .collect();
                                    let meta = inject_trace_into_meta(
                                        None,
                                        request.context.trace_context.as_ref(),
                                    );
                                    let params =
                                        serde_json::to_value(SamplingCreateMessageParams {
                                            messages: msgs,
                                            max_tokens: coerce_sampling_max_tokens(*max_tokens),
                                            model_preferences: None,
                                            system_prompt: system_prompt.clone(),
                                            include_context: None,
                                            temperature: None,
                                            stop_sequences: None,
                                            metadata: None,
                                            tools: None,
                                            tool_choice: None,
                                            task: None,
                                            meta,
                                        })
                                        .expect("gather sampling params serialized");
                                    (
                                        Some(ServerJsonRpcRequest {
                                            jsonrpc: JSONRPC_VERSION,
                                            id: Value::String(token.clone()),
                                            method: "sampling/createMessage".to_owned(),
                                            params,
                                        }),
                                        60_000,
                                    )
                                }
                            }
                            crate::config::GatherInputConfig::Roots { .. } => {
                                if !caps.supports_roots() {
                                    (None, 0)
                                } else {
                                    let params = match inject_trace_into_meta(
                                        None,
                                        request.context.trace_context.as_ref(),
                                    ) {
                                        Some(meta) => serde_json::json!({ "_meta": meta }),
                                        None => serde_json::json!({}),
                                    };
                                    (
                                        Some(ServerJsonRpcRequest {
                                            jsonrpc: JSONRPC_VERSION,
                                            id: Value::String(token.clone()),
                                            method: "roots/list".to_owned(),
                                            params,
                                        }),
                                        30_000,
                                    )
                                }
                            }
                        };
                        if let Some(server_request) = request_opt {
                            longest_timeout_ms = longest_timeout_ms.max(timeout_ms);
                            let _ =
                                pipeline_store.save_pending_server_request(&PendingServerRequest {
                                    server_request_id: token.clone(),
                                    pipeline_id: state.pipeline_id.clone(),
                                    session_id: state.session_id.clone(),
                                    step_id: gather.id.clone(),
                                    timeout_ms,
                                    created_at: chrono::Utc::now(),
                                });
                            requests.push(server_request);
                        }
                    }

                    if requests.is_empty() {
                        // Every input pruned (client advertised none of
                        // the required capabilities). Complete the step
                        // with an empty output and continue rather than
                        // suspend on nothing.
                        info!(
                            pipeline = %profile,
                            step_id = %gather.id,
                            "gather step produced no inputRequests (no capabilities advertised); skipping"
                        );
                        state.completed_steps.insert(
                            gather.id.clone(),
                            StepResult {
                                output: serde_json::json!({}),
                                is_error: false,
                                duration_ms: 0,
                            },
                        );
                        state.current_step_index += 1;
                        continue;
                    }

                    state.suspended_at = Some(chrono::Utc::now());
                    // The gather step tracks its pending requests via the
                    // per-token PendingServerRequest rows (saved above)
                    // keyed to this step id; the single
                    // `pending_server_request_id` slot is left None.
                    state.pending_server_request_id = None;
                    state.elicitation_timeout_ms = Some(longest_timeout_ms);
                    state.state_version += 1;
                    let _ = pipeline_store.save_pipeline(state);

                    metrics::counter!(
                        "mcpg_pipeline_suspensions_total",
                        "step_type" => "gather",
                        "pipeline" => profile.to_owned(),
                    )
                    .increment(1);
                    return PipelineOutcome::SuspendedMulti(requests);
                }
                _ => {}
            }

            // Update expression context with current step results
            pipeline_expr_ctx.steps = Some(completed_steps_to_value(&state.completed_steps));
            pipeline_expr_ctx.arguments = args.clone();

            // Non-suspending steps: execute synchronously
            let step_start = std::time::Instant::now();
            let step_input = match resolve_step_input(&step, &pipeline_expr_ctx) {
                Ok(input) => input,
                Err(err_msg) => {
                    return PipelineOutcome::Complete(ToolCallResult {
                        content: vec![ToolContent::text(format!(
                            "step '{}' input_transform failed: {}",
                            step_id, err_msg
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    });
                }
            };

            let step_outcome = match &step {
                crate::config::PipelineStepConfig::CelGate(gate) => {
                    execute_cel_gate_step(gate, &pipeline_expr_ctx)
                }
                crate::config::PipelineStepConfig::Transform(transform) => {
                    execute_transform_step(&transform.expression, &pipeline_expr_ctx)
                }
                crate::config::PipelineStepConfig::PluginTransform(pt) => {
                    execute_plugin_transform_step(
                        self.plugin_registry.as_ref(),
                        pt,
                        &pipeline_expr_ctx,
                        request,
                    )
                }
                crate::config::PipelineStepConfig::Log(log_step) => {
                    publish_log_notification(
                        self.delivery_bus.as_ref(),
                        self.pipeline_store.as_ref(),
                        &state.session_id,
                        &log_step.level,
                        log_step.logger.as_deref().or(Some(profile)),
                        &log_step.data,
                        request.context.negotiated_version
                            == crate::protocol::version::ProtocolVersion::V_2026_07_28,
                        request.request_log_level,
                        request.legacy_session_log_level,
                    );
                    // Log steps don't produce useful step outputs; return
                    // the configured payload so downstream steps that
                    // reference `steps.<id>` see the logged value.
                    StepOutcome::Success(log_step.data.clone())
                }
                crate::config::PipelineStepConfig::Progress(progress_step) => {
                    publish_progress_notification(
                        self.delivery_bus.as_ref(),
                        self.pipeline_store.as_ref(),
                        &state.session_id,
                        request.progress_token.as_ref(),
                        progress_step.progress,
                        progress_step.total,
                        progress_step.message.as_deref(),
                    );
                    let body = serde_json::json!({
                        "progress": progress_step.progress,
                        "total": progress_step.total,
                        "message": progress_step.message,
                    });
                    StepOutcome::Success(body)
                }
                crate::config::PipelineStepConfig::SqlTx(sql_tx) => {
                    match self.plugin_registry.as_ref().and_then(|r| r.backend("sql")) {
                        Some(plugin) => tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(execute_sql_tx_step(
                                plugin.as_ref(),
                                sql_tx,
                                &step_input,
                            ))
                        }),
                        None => StepOutcome::Error(
                            "sql_tx pipeline step: no 'sql' backend is registered".to_owned(),
                        ),
                    }
                }
                crate::config::PipelineStepConfig::SqlAwait(sql_await) => {
                    match self.plugin_registry.as_ref().and_then(|r| r.backend("sql")) {
                        Some(plugin) => tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(execute_sql_await_step(
                                plugin.as_ref(),
                                sql_await,
                                &step_input,
                                request,
                            ))
                        }),
                        None => StepOutcome::Error(
                            "sql_await pipeline step: no 'sql' backend is registered".to_owned(),
                        ),
                    }
                }
                // Backend steps dispatch by their declared plugin kind.
                // `http`/`nats`/`kafka` keep their dedicated dispatch
                // helpers; `mock` runs the inline mock evaluator; every
                // other kind goes through the generic envelope plugin.
                crate::config::PipelineStepConfig::Backend(backend_step) => {
                    if backend_step.kind == "mock" {
                        let mock_config =
                            serde_json::from_value::<crate::config::MockBackendConfig>(
                                serde_json::Value::Object(backend_step.spec.clone()),
                            )
                            .unwrap_or_default();
                        execute_pipeline_mock_step(&mock_config, &step_input)
                    } else {
                        let sub_request = build_step_request(request, &step_input);
                        let step_profile = format!("{}._step_.{}", profile, step_id);
                        match backend_step.kind.as_str() {
                            "nats" => StepOutcome::from_tool_result(execute_nats_request(
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                            "kafka" => StepOutcome::from_tool_result(execute_kafka_request(
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                            "http" => StepOutcome::from_tool_result(execute_http_request(
                                &step_profile,
                                HttpDispatchMode::JsonBody,
                                &sub_request,
                                self.network_profiles.as_ref(),
                                self.plugin_registry.as_ref(),
                            )),
                            kind => StepOutcome::from_tool_result(execute_envelope_plugin(
                                kind,
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                        }
                    }
                }
                // Suspending steps are resolved by the suspend/resume
                // driver before reaching this synchronous dispatch match.
                crate::config::PipelineStepConfig::Elicitation(_)
                | crate::config::PipelineStepConfig::Sampling(_)
                | crate::config::PipelineStepConfig::RootsList(_)
                | crate::config::PipelineStepConfig::Gather(_) => {
                    unreachable!("suspending steps are handled before synchronous dispatch")
                }
            };

            let step_duration_ms = step_start.elapsed().as_millis() as u64;
            match step_outcome {
                StepOutcome::Success(output) => {
                    info!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        duration_ms = step_duration_ms,
                        "pipeline step completed"
                    );
                    metrics::histogram!(
                        "mcpg_pipeline_step_duration_seconds",
                        "pipeline" => profile.to_owned(),
                        "step_id" => step_id.clone(),
                        "outcome" => "success",
                    )
                    .record(step_duration_ms as f64 / 1000.0);
                    last_step_output = output.clone();
                    state.completed_steps.insert(
                        step_id,
                        StepResult {
                            output,
                            is_error: false,
                            duration_ms: step_duration_ms,
                        },
                    );
                    state.current_step_index += 1;

                    // Emit progress notification if progressToken was provided
                    if let Some(ref token) = request.progress_token {
                        self.emit_pipeline_progress(
                            &request.context,
                            token,
                            state.current_step_index as f64,
                            state.steps.len() as f64,
                        );
                    }
                }
                StepOutcome::Error(err) => {
                    warn!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        duration_ms = step_duration_ms,
                        error = %err,
                        "pipeline step failed"
                    );
                    return PipelineOutcome::Complete(ToolCallResult {
                        content: vec![ToolContent::text(err)],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    });
                }
                StepOutcome::GateAbort(msg) => {
                    warn!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        "pipeline gate aborted execution"
                    );
                    return PipelineOutcome::Complete(ToolCallResult {
                        content: vec![ToolContent::text(msg)],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    });
                }
            }
        }

        info!(
            pipeline = %profile,
            steps_completed = state.completed_steps.len(),
            "pipeline execution completed"
        );
        metrics::counter!(
            "mcpg_pipeline_completions_total",
            "pipeline" => profile.to_owned(),
        )
        .increment(1);

        PipelineOutcome::Complete(ToolCallResult {
            content: vec![ToolContent::text(
                serde_json::to_string_pretty(&last_step_output)
                    .unwrap_or_else(|_| last_step_output.to_string()),
            )],
            structured_content: Some(last_step_output),
            is_error: false,
            meta: None,
        })
    }

    #[tracing::instrument(skip(self, request, _execution_context), fields(pipeline = %profile))]
    pub(super) fn execute_pipeline_binding(
        &self,
        profile: &str,
        request: &BackendInvocationRequest,
        // Backend steps dispatch via plugin helpers now; the caller's
        // context is no longer threaded into per-step dispatch.
        _execution_context: &ToolExecutionContext,
    ) -> ToolCallResult {
        use crate::config::PipelineStepConfig;

        let pipeline_config = match self.pipeline_configs.get(profile) {
            Some(config) => config,
            None => {
                return ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "pipeline '{}' not found",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                };
            }
        };

        let pipeline_start = Instant::now();
        let pipeline_timeout = Duration::from_millis(pipeline_config.pipeline_timeout_ms);
        let args = request.arguments.clone().unwrap_or(serde_json::json!({}));

        // Build expression context for pipeline steps
        let mut pipeline_expr_ctx = request.expr_ctx.clone();

        let mut step_results_map: std::collections::BTreeMap<String, StepResult> =
            std::collections::BTreeMap::new();
        let mut last_step_output = Value::Null;
        let step_count = pipeline_config.steps.len();

        for (i, step) in pipeline_config.steps.iter().enumerate() {
            // Check pipeline timeout
            if pipeline_start.elapsed() >= pipeline_timeout {
                return ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "pipeline '{}' timed out after {}ms at step '{}'",
                        profile,
                        pipeline_config.pipeline_timeout_ms,
                        step.id()
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                };
            }

            let step_start = Instant::now();
            let step_id = step.id().to_owned();

            info!(
                pipeline = %profile,
                step_id = %step_id,
                step_index = i,
                step_type = step.type_label(),
                "pipeline step started"
            );

            // Update expression context with current step results
            pipeline_expr_ctx.steps = Some(completed_steps_to_value(&step_results_map));
            pipeline_expr_ctx.arguments = args.clone();

            let step_input = match resolve_step_input(step, &pipeline_expr_ctx) {
                Ok(input) => input,
                Err(err_msg) => {
                    return ToolCallResult {
                        content: vec![ToolContent::text(format!(
                            "pipeline '{}' step '{}' input_transform failed: {}",
                            profile, step_id, err_msg
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    };
                }
            };

            let outcome = match step {
                PipelineStepConfig::Transform(transform_step) => {
                    execute_transform_step(&transform_step.expression, &pipeline_expr_ctx)
                }
                PipelineStepConfig::PluginTransform(pt) => execute_plugin_transform_step(
                    self.plugin_registry.as_ref(),
                    pt,
                    &pipeline_expr_ctx,
                    request,
                ),
                PipelineStepConfig::CelGate(gate_step) => {
                    execute_cel_gate_step(gate_step, &pipeline_expr_ctx)
                }
                // Backend step: dispatch by its declared plugin kind, the
                // kind being data rather than a literal. `mock` runs the
                // inline mock evaluator; `http` reads its method off the
                // flattened spec to pick the dispatch mode; `nats`/`kafka`
                // use their dedicated helpers; everything else routes
                // through the generic envelope plugin.
                PipelineStepConfig::Backend(backend_step) => {
                    if backend_step.kind == "mock" {
                        let mock_config =
                            serde_json::from_value::<crate::config::MockBackendConfig>(
                                serde_json::Value::Object(backend_step.spec.clone()),
                            )
                            .unwrap_or_default();
                        execute_pipeline_mock_step(&mock_config, &step_input)
                    } else {
                        let sub_request = build_step_request(request, &step_input);
                        let step_profile = format!("{}._step_.{}", profile, step_id);
                        match backend_step.kind.as_str() {
                            "http" => {
                                let mode = match serde_json::from_value::<
                                    crate::config::HttpBackendConfig,
                                >(
                                    serde_json::Value::Object(backend_step.spec.clone()),
                                ) {
                                    Ok(http) => match http.method {
                                        crate::config::HttpBackendMethod::Post => {
                                            HttpDispatchMode::JsonBody
                                        }
                                        crate::config::HttpBackendMethod::Get => {
                                            HttpDispatchMode::QueryString
                                        }
                                    },
                                    Err(_) => HttpDispatchMode::JsonBody,
                                };
                                StepOutcome::from_tool_result(execute_http_request(
                                    &step_profile,
                                    mode,
                                    &sub_request,
                                    self.network_profiles.as_ref(),
                                    self.plugin_registry.as_ref(),
                                ))
                            }
                            "nats" => StepOutcome::from_tool_result(execute_nats_request(
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                            "kafka" => StepOutcome::from_tool_result(execute_kafka_request(
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                            kind => StepOutcome::from_tool_result(execute_envelope_plugin(
                                kind,
                                &step_profile,
                                &sub_request,
                                self.plugin_registry.as_ref(),
                            )),
                        }
                    }
                }
                PipelineStepConfig::Elicitation(_)
                | PipelineStepConfig::Sampling(_)
                | PipelineStepConfig::RootsList(_)
                | PipelineStepConfig::Gather(_) => {
                    // Suspending steps (elicitation / sampling / roots /
                    // gather) require the suspend/resume pipeline, which
                    // uses execute_pipeline + PipelineOutcome::Suspended.
                    // The synchronous execute_pipeline_binding path does
                    // not support them.
                    StepOutcome::Error(
                        "suspending steps require the pipeline execution path".to_owned(),
                    )
                }
                PipelineStepConfig::Log(log_step) => {
                    publish_log_notification(
                        self.delivery_bus.as_ref(),
                        self.pipeline_store.as_ref(),
                        request.context.session_id.as_deref().unwrap_or(""),
                        &log_step.level,
                        log_step.logger.as_deref().or(Some(profile)),
                        &log_step.data,
                        request.context.negotiated_version
                            == crate::protocol::version::ProtocolVersion::V_2026_07_28,
                        request.request_log_level,
                        request.legacy_session_log_level,
                    );
                    StepOutcome::Success(log_step.data.clone())
                }
                PipelineStepConfig::Progress(progress_step) => {
                    publish_progress_notification(
                        self.delivery_bus.as_ref(),
                        self.pipeline_store.as_ref(),
                        request.context.session_id.as_deref().unwrap_or(""),
                        request.progress_token.as_ref(),
                        progress_step.progress,
                        progress_step.total,
                        progress_step.message.as_deref(),
                    );
                    StepOutcome::Success(serde_json::json!({
                        "progress": progress_step.progress,
                        "total": progress_step.total,
                        "message": progress_step.message,
                    }))
                }
                PipelineStepConfig::SqlTx(sql_tx) => {
                    match self.plugin_registry.as_ref().and_then(|r| r.backend("sql")) {
                        Some(plugin) => tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(execute_sql_tx_step(
                                plugin.as_ref(),
                                sql_tx,
                                &step_input,
                            ))
                        }),
                        None => StepOutcome::Error(
                            "sql_tx pipeline step: no 'sql' backend is registered".to_owned(),
                        ),
                    }
                }
                PipelineStepConfig::SqlAwait(sql_await) => {
                    match self.plugin_registry.as_ref().and_then(|r| r.backend("sql")) {
                        Some(plugin) => tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(execute_sql_await_step(
                                plugin.as_ref(),
                                sql_await,
                                &step_input,
                                request,
                            ))
                        }),
                        None => StepOutcome::Error(
                            "sql_await pipeline step: no 'sql' backend is registered".to_owned(),
                        ),
                    }
                }
            };

            let step_duration_ms = step_start.elapsed().as_millis() as u64;

            match outcome {
                StepOutcome::Success(output) => {
                    info!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        duration_ms = step_duration_ms,
                        "pipeline step completed"
                    );
                    last_step_output = output.clone();
                    step_results_map.insert(
                        step_id,
                        StepResult {
                            output,
                            is_error: false,
                            duration_ms: step_duration_ms,
                        },
                    );
                }
                StepOutcome::Error(error_msg) => {
                    warn!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        duration_ms = step_duration_ms,
                        error = %error_msg,
                        "pipeline step failed"
                    );
                    return ToolCallResult {
                        content: vec![ToolContent::text(format!(
                            "pipeline '{}' failed at step '{}': {}",
                            profile, step_id, error_msg
                        ))],
                        structured_content: Some(serde_json::json!({
                            "pipeline": profile,
                            "failed_step": step_id,
                            "error": error_msg,
                            "completed_steps": i,
                            "total_steps": step_count,
                        })),
                        is_error: true,
                        meta: None,
                    };
                }
                StepOutcome::GateAbort(error_msg) => {
                    info!(
                        pipeline = %profile,
                        step_id = %step_id,
                        step_index = i,
                        duration_ms = step_duration_ms,
                        reason = %error_msg,
                        "pipeline gate aborted"
                    );
                    return ToolCallResult {
                        content: vec![ToolContent::text(error_msg.clone())],
                        structured_content: Some(serde_json::json!({
                            "pipeline": profile,
                            "gate_step": step_id,
                            "reason": error_msg,
                            "completed_steps": i,
                            "total_steps": step_count,
                        })),
                        is_error: true,
                        meta: None,
                    };
                }
            }
        }

        let pipeline_duration_ms = pipeline_start.elapsed().as_millis() as u64;

        info!(
            pipeline = %profile,
            completed_steps = step_count,
            duration_ms = pipeline_duration_ms,
            "pipeline completed"
        );

        // The pipeline result is the last step's output
        let result_text = match &last_step_output {
            Value::String(s) => s.clone(),
            other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_owned()),
        };

        ToolCallResult {
            content: vec![ToolContent::text(result_text)],
            structured_content: Some(serde_json::json!({
                "pipeline": profile,
                "result": last_step_output,
                "completed_steps": step_count,
                "total_steps": step_count,
                "duration_ms": pipeline_duration_ms,
            })),
            is_error: false,
            meta: None,
        }
    }
}

/// Result of running a single non-suspending pipeline step. (Steps
/// that need client input never produce a `StepOutcome` — they short-
/// circuit the loop with `Suspended`/`SuspendedMulti` instead.)
pub(super) enum StepOutcome {
    /// Step ran and produced an output value to feed forward.
    Success(Value),
    /// Step failed (backend error, bad transform, etc.); the whole
    /// pipeline ends as an `is_error` result.
    Error(String),
    /// A CEL gate step evaluated to `false`. Distinct from `Error`
    /// because it's an intentional, operator-defined stop rather than
    /// a failure — but it still ends the pipeline as an `is_error`
    /// result with the gate's configured message.
    GateAbort(String),
}

impl StepOutcome {
    fn from_tool_result(result: ToolCallResult) -> Self {
        if result.is_error {
            let text = result
                .content
                .first()
                .map(|c| match c {
                    ToolContent::Text { text, .. } => text.clone(),
                    _ => "step execution failed (non-text content)".to_owned(),
                })
                .unwrap_or_else(|| "step execution failed".to_owned());
            Self::Error(text)
        } else {
            let output = result
                .structured_content
                .or_else(|| {
                    result.content.first().and_then(|c| match c {
                        ToolContent::Text { text, .. } => serde_json::from_str(text).ok(),
                        _ => None,
                    })
                })
                .unwrap_or(Value::Null);
            Self::Success(output)
        }
    }
}

pub(super) fn resolve_step_input(
    step: &crate::config::PipelineStepConfig,
    expr_ctx: &super::expr::ExprContext,
) -> Result<Value, String> {
    let input_transform = step.input_transform();
    match input_transform {
        Some(expr) => evaluate_pipeline_cel_transform(expr, expr_ctx),
        None => Ok(expr_ctx.arguments.clone()),
    }
}

pub(super) fn build_step_request(
    original_request: &BackendInvocationRequest,
    step_input: &Value,
) -> BackendInvocationRequest {
    let mut expr_ctx = original_request.expr_ctx.clone();
    expr_ctx.arguments = step_input.clone();
    BackendInvocationRequest {
        context: original_request.context.clone(),
        tool_name: original_request.tool_name.clone(),
        arguments: Some(step_input.clone()),
        expr_ctx,
        progress_token: original_request.progress_token.clone(),
        request_log_level: original_request.request_log_level,
        legacy_session_log_level: original_request.legacy_session_log_level,
        client_capabilities: original_request.client_capabilities.clone(),
        cancellation_token: original_request.cancellation_token.clone(),
        // Sub-steps inherit the same hint (no per-hop derivation;
        // design doc §5), which is surfaced to backend plugins via
        // `BackendRequest.idempotency`.
        idempotency_hint: original_request.idempotency_hint.clone(),
    }
}

/// Convert `BTreeMap<String, StepResult>` to `serde_json::Value` for the expr context.
pub(super) fn completed_steps_to_value(
    completed: &std::collections::BTreeMap<String, StepResult>,
) -> Value {
    let mut map = serde_json::Map::new();
    for (id, result) in completed {
        map.insert(
            id.clone(),
            serde_json::json!({
                "output": result.output,
                "is_error": result.is_error,
                "duration_ms": result.duration_ms,
            }),
        );
    }
    Value::Object(map)
}

pub(super) fn execute_pipeline_mock_step(
    config: &crate::config::MockBackendConfig,
    _step_input: &Value,
) -> StepOutcome {
    if config.delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(config.delay_ms));
    }
    if config.error {
        let msg = config.error_message.as_deref().unwrap_or("mock step error");
        StepOutcome::Error(msg.to_owned())
    } else {
        StepOutcome::Success(config.response.clone())
    }
}

pub(super) fn execute_transform_step(
    expression: &str,
    expr_ctx: &super::expr::ExprContext,
) -> StepOutcome {
    match evaluate_pipeline_cel_transform(expression, expr_ctx) {
        Ok(value) => StepOutcome::Success(value),
        Err(e) => StepOutcome::Error(format!("transform evaluation failed: {}", e)),
    }
}

/// The `plugin_transform` step — reshape the pipeline context by invoking
/// a named `transform` plugin. The plugin receives the full pipeline context
/// (`steps` / `arguments` / `context` / `tool_name`, the same surface CEL
/// sees) and its `config`; its `Modified` output becomes the step result.
pub(super) fn execute_plugin_transform_step(
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
    step: &crate::config::backend::PipelinePluginTransformStepConfig,
    expr_ctx: &super::expr::ExprContext,
    request: &BackendInvocationRequest,
) -> StepOutcome {
    let plugin = match plugin_registry.and_then(|r| r.transform_by_id(&step.plugin)) {
        Some(p) => p,
        None => {
            return StepOutcome::Error(format!(
                "plugin_transform step references transform plugin '{}' which is not registered",
                step.plugin
            ));
        }
    };

    let rc = &expr_ctx.context;
    let context_value = serde_json::json!({
        "arguments": expr_ctx.arguments,
        "tool_name": expr_ctx.tool_name,
        "steps": expr_ctx.steps.clone().unwrap_or(Value::Null),
        "context": {
            "principal_id": rc.principal_id,
            "trust_level": rc.trust_level,
            "session_id": rc.session_id,
            "transport": rc.transport,
            "roles": rc.roles,
            "groups": rc.groups,
            "scopes": rc.scopes,
            "attributes": rc.attributes,
        },
    });

    let plugin_ctx = mcpg_plugin_protocol::PluginContext {
        request_id: request.context.request_id.as_str().to_owned(),
        session_id: request.context.session_id.clone(),
        tool_name: request.tool_name.clone(),
        surface: "tool".to_owned(),
        identity: crate::runtime::plugin_identity_from_request(&request.context),
        transport: crate::runtime::transport_label(&request.context.transport).to_owned(),
    };

    match run_transform_in_sync_context(plugin, &plugin_ctx, &context_value, &step.config) {
        mcpg_plugin_protocol::TransformResult::Modified { value } => StepOutcome::Success(value),
        mcpg_plugin_protocol::TransformResult::Unchanged => StepOutcome::Success(context_value),
        mcpg_plugin_protocol::TransformResult::Error { message } => StepOutcome::Error(format!(
            "plugin_transform '{}' failed: {message}",
            step.plugin
        )),
    }
}

/// Block on a transform plugin's async `transform_result` from the sync
/// pipeline loop (mirrors `run_async_in_sync_context`).
pub(super) fn run_transform_in_sync_context(
    plugin: &dyn mcpg_plugin_protocol::TransformPlugin,
    ctx: &mcpg_plugin_protocol::PluginContext,
    value: &Value,
    config: &Value,
) -> mcpg_plugin_protocol::TransformResult {
    if let Ok(handle) = tokio::runtime::Handle::try_current()
        && matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    {
        return tokio::task::block_in_place(|| {
            handle.block_on(plugin.transform_result(ctx, value, config))
        });
    }
    std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build temporary runtime");
            rt.block_on(plugin.transform_result(ctx, value, config))
        })
        .join()
        .expect("transform thread panicked")
    })
}

/// Publish a `notifications/message` on a session's delivery bus.
/// Used by the `log` pipeline step; non-suspending so the pipeline
/// proceeds immediately to the next step after the bus accepts.
///
/// When `bus` is `None` (test executor without a delivery bus
/// installed, or the runtime's bus dropped), the notification is
/// silently swallowed — the caller's `StepOutcome::Success` is
/// returned regardless so the pipeline doesn't break on the
/// observability side-effect.
///
/// `request_log_level` carries the per-request SEP-2575 emission gate.
/// It is `Some(_)` **only** on the modern (`2026-07-28`) wire when the
/// request set `_meta.io.modelcontextprotocol/logLevel`, in which case
/// `version_is_modern` is `true` and only messages at or above that
/// floor are emitted. On the modern wire with no floor set
/// (`request_log_level == None && version_is_modern`), the spec MUST
/// applies: emit nothing. On the legacy wire (`version_is_modern ==
/// false`) the gate is bypassed entirely — log notifications are
/// emitted unconditionally, preserving byte-identical 2025-11-25
/// behaviour, except the session-wide `logging/setLevel` floor is now
/// applied (LOG-2): `legacy_session_log_level` carries the session's
/// stored minimum and a pipeline `log` step below it is suppressed.
/// Decide whether a pipeline `log` step's `notifications/message` is
/// suppressed by the active log-level floor.
///
/// - Modern wire (`version_is_modern`): the SEP-2575 per-request
///   `request_log_level` gate applies — absent ⇒ suppress all; present
///   ⇒ suppress below the floor. An unrecognised level string emits.
/// - Legacy wire: the session-wide `logging/setLevel` floor
///   (`legacy_session_log_level`) applies (LOG-2) — a message below the
///   session minimum is suppressed; `None` floor or an unrecognised
///   level string emits unconditionally (byte-identical default).
pub(super) fn log_step_suppressed(
    level: &str,
    version_is_modern: bool,
    request_log_level: Option<crate::protocol::v_2026_07_28::wire::meta::LogLevel>,
    legacy_session_log_level: Option<crate::protocol::LoggingLevel>,
) -> bool {
    if version_is_modern {
        use crate::protocol::v_2026_07_28::wire::meta::LogLevel;
        match request_log_level {
            None => true,
            Some(minimum) => LogLevel::parse_str(level)
                .map(|msg_level| !msg_level.permits(minimum))
                .unwrap_or(false),
        }
    } else if let Some(min) = legacy_session_log_level {
        serde_json::from_value::<crate::protocol::LoggingLevel>(Value::String(level.to_owned()))
            .map(|msg_level| msg_level < min)
            .unwrap_or(false)
    } else {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_log_notification(
    bus: Option<&std::sync::Arc<dyn super::delivery_bus::DeliveryBus>>,
    pipeline_store: Option<&std::sync::Arc<dyn super::pipeline_store::PipelineStore>>,
    session_id: &str,
    level: &str,
    logger: Option<&str>,
    data: &Value,
    version_is_modern: bool,
    request_log_level: Option<crate::protocol::v_2026_07_28::wire::meta::LogLevel>,
    legacy_session_log_level: Option<crate::protocol::LoggingLevel>,
) {
    if log_step_suppressed(
        level,
        version_is_modern,
        request_log_level,
        legacy_session_log_level,
    ) {
        return;
    }
    // SEP-2577: Logging is deprecated on the modern wire. Meter each
    // emission that passes the level floor.
    if version_is_modern {
        crate::protocol::shared::deprecation::meter_deprecated_feature(
            crate::protocol::shared::deprecation::FEATURE_LOGGING,
        );
    }
    if bus.is_none() && pipeline_store.is_none() {
        return;
    }
    let mut params = serde_json::Map::new();
    params.insert("level".to_owned(), Value::String(level.to_owned()));
    if let Some(logger) = logger {
        params.insert("logger".to_owned(), Value::String(logger.to_owned()));
    }
    params.insert("data".to_owned(), data.clone());
    let notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": Value::Object(params),
    });
    let message = super::pipeline_store::DeliveryMessage {
        kind: super::pipeline_store::DeliveryKind::Notification,
        jsonrpc_message: notification,
        delivery_id: String::new(),
    };
    if let Some(store) = pipeline_store
        && let Err(error) = store.store_pending_delivery(session_id, &message)
    {
        tracing::warn!(
            session_id = %session_id,
            error = %error,
            "pipeline log: failed to buffer notification for late-subscriber replay"
        );
    }
    let Some(bus) = bus else { return };
    let bus = bus.clone();
    let session_id = session_id.to_owned();
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            let _ = bus.publish(&session_id, message).await;
        })
    });
}

/// Publish a `notifications/progress` on a session's delivery bus.
/// Used by the `progress` pipeline step. Silently no-ops when the
/// inbound request didn't include a progress token (the client
/// didn't ask for streaming progress).
pub(super) fn publish_progress_notification(
    bus: Option<&std::sync::Arc<dyn super::delivery_bus::DeliveryBus>>,
    pipeline_store: Option<&std::sync::Arc<dyn super::pipeline_store::PipelineStore>>,
    session_id: &str,
    progress_token: Option<&Value>,
    progress: f64,
    total: Option<f64>,
    message_text: Option<&str>,
) {
    let Some(token) = progress_token else { return };
    if bus.is_none() && pipeline_store.is_none() {
        return;
    }
    let mut params = serde_json::Map::new();
    params.insert("progressToken".to_owned(), token.clone());
    let number =
        serde_json::Number::from_f64(progress).unwrap_or_else(|| serde_json::Number::from(0));
    params.insert("progress".to_owned(), Value::Number(number));
    if let Some(t) = total
        && let Some(total_num) = serde_json::Number::from_f64(t)
    {
        params.insert("total".to_owned(), Value::Number(total_num));
    }
    if let Some(message) = message_text {
        params.insert("message".to_owned(), Value::String(message.to_owned()));
    }
    let notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": Value::Object(params),
    });
    let message = super::pipeline_store::DeliveryMessage {
        kind: super::pipeline_store::DeliveryKind::ProgressNotification,
        jsonrpc_message: notification,
        delivery_id: String::new(),
    };
    if let Some(store) = pipeline_store
        && let Err(error) = store.store_pending_delivery(session_id, &message)
    {
        tracing::warn!(
            session_id = %session_id,
            error = %error,
            "pipeline progress: failed to buffer notification for late-subscriber replay"
        );
    }
    let Some(bus) = bus else { return };
    let bus_clone = bus.clone();
    let session_id = session_id.to_owned();
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            let _ = bus_clone.publish(&session_id, message).await;
        })
    });
}

/// Dispatch a `type: sql_tx` pipeline step (P4.1).
///
/// Serializes the nested-step group + step input into the opaque
/// `tx_group` and forwards it to the SQL plugin's
/// `BackendPlugin::execute_transaction`, which opens one transaction,
/// runs every statement, and commits — rolling back the whole group on
/// any per-statement failure. The step's JSON output wraps per-statement
/// results keyed by their nested step IDs so downstream steps can
/// reference `steps.<tx_step_id>.output.steps.<nested_id>` via CEL.
/// Dispatch a `kind: sql_await` pipeline step (P3.4).
///
/// Forwards the step input as the binding payload to the plugin's
/// `execute()` trait method. The plugin's profile-router auto-routes
/// to `execute_await_loop` because the referenced binding declares an
/// `await:` block; same machinery as a direct `tools/call` against
/// the underlying SQL binding. On match the response payload becomes
/// the step output; on timeout the step errors and the pipeline aborts.
pub(super) async fn execute_sql_await_step(
    plugin: &dyn mcpg_plugin_protocol::BackendPlugin,
    cfg: &crate::config::PipelineSqlAwaitStepConfig,
    step_input: &Value,
    request: &BackendInvocationRequest,
) -> StepOutcome {
    use mcpg_plugin_protocol::BackendRequest;

    let payload = match serde_json::to_vec(step_input) {
        Ok(bytes) => bytes,
        Err(e) => {
            return StepOutcome::Error(format!(
                "sql_await '{}': failed to serialize step input as binding payload: {e}",
                cfg.id
            ));
        }
    };

    let mut headers = Vec::new();
    if let Some(tc) = request.context.trace_context.as_ref() {
        headers.push(("traceparent".to_owned(), tc.child_traceparent()));
        if let Some(ts) = tc.tracestate.as_deref() {
            headers.push(("tracestate".to_owned(), ts.to_owned()));
        }
    }

    let binding_request = BackendRequest {
        payload,
        headers,
        request_id: format!("{}::{}", request.context.request_id.as_str(), cfg.id),
        session_id: request.context.session_id.clone(),
        identity: Some(crate::runtime::plugin_identity_from_request(
            &request.context,
        )),
        // Sub-step backends inherit the same hint as the parent
        // tool-call (no per-hop derivation; design doc §5).
        idempotency: request
            .idempotency_hint
            .as_ref()
            .map(|h| h.to_plugin_hint()),
    };

    match plugin.execute(&cfg.backend, binding_request).await {
        Ok(response) => match serde_json::from_slice::<Value>(&response.payload) {
            Ok(value) => StepOutcome::Success(value),
            Err(_) => StepOutcome::Success(Value::String(
                String::from_utf8_lossy(&response.payload).into_owned(),
            )),
        },
        Err(e) => StepOutcome::Error(format!(
            "sql_await '{}' on binding '{}': {e}",
            cfg.id, cfg.backend
        )),
    }
}

pub(super) async fn execute_sql_tx_step(
    plugin: &dyn mcpg_plugin_protocol::BackendPlugin,
    cfg: &PipelineSqlTxStepConfig,
    step_input: &Value,
) -> StepOutcome {
    // The whole transaction lifecycle (begin / per-step / commit-or-rollback
    // + the rewrite/bind/shape) lives plugin-side behind `execute_transaction`.
    // This dispatcher just serializes the nested steps + the step input into
    // the opaque tx_group and surfaces the result through the trait — no
    // host-side SQL machinery. The nested steps are independent (each binds
    // against `step_input`), so a single round-trip carries the whole
    // transaction.
    let tx_group = serde_json::json!({
        "steps": cfg.steps,
        "step_input": step_input,
    });
    match plugin.execute_transaction(&cfg.backend, &tx_group).await {
        Ok(value) => StepOutcome::Success(value),
        Err(e) => StepOutcome::Error(format!("sql_tx '{}': {e}", cfg.id)),
    }
}

pub(super) fn execute_cel_gate_step(
    gate: &crate::config::PipelineCelGateStepConfig,
    expr_ctx: &super::expr::ExprContext,
) -> StepOutcome {
    match evaluate_pipeline_cel_bool(&gate.expression, expr_ctx) {
        Ok(true) => StepOutcome::Success(serde_json::json!(true)),
        Ok(false) => {
            let msg = gate
                .error_message
                .as_deref()
                .map(|m| m.to_owned())
                .unwrap_or_else(|| crate::config::default_cel_gate_error_message(&gate.id));
            StepOutcome::GateAbort(msg)
        }
        Err(e) => StepOutcome::Error(format!("gate expression evaluation failed: {}", e)),
    }
}

/// Evaluate a pipeline CEL expression as a boolean.
///
/// Pipeline expressions are raw CEL (not `${...}` wrapped) and use the standard
/// variable registry: `args`, `context`, `steps`, `tool_name`.
pub(super) fn evaluate_pipeline_cel_bool(
    expression: &str,
    expr_ctx: &super::expr::ExprContext,
) -> Result<bool, String> {
    let trimmed = expression.trim();
    if trimmed == "true" {
        return Ok(true);
    }
    if trimmed == "false" {
        return Ok(false);
    }

    let program =
        cel::Program::compile(trimmed).map_err(|e| format!("failed to compile CEL: {}", e))?;
    let cel_ctx = expr_ctx
        .to_cel_context()
        .map_err(|e| format!("failed to build CEL context: {}", e))?;
    let result = program
        .execute(&cel_ctx)
        .map_err(|e| format!("CEL execution failed: {}", e))?;

    match result {
        cel::Value::Bool(b) => Ok(b),
        other => Err(format!(
            "gate expression must return boolean, got: {:?}",
            other
        )),
    }
}

/// Evaluate a pipeline CEL transform expression, returning a JSON value.
pub(super) fn evaluate_pipeline_cel_transform(
    expression: &str,
    expr_ctx: &super::expr::ExprContext,
) -> Result<Value, String> {
    let trimmed = expression.trim();
    let program =
        cel::Program::compile(trimmed).map_err(|e| format!("failed to compile CEL: {}", e))?;
    let cel_ctx = expr_ctx
        .to_cel_context()
        .map_err(|e| format!("failed to build CEL context: {}", e))?;
    let result = program
        .execute(&cel_ctx)
        .map_err(|e| format!("CEL execution failed: {}", e))?;

    Ok(super::expr::cel_value_to_json(&result))
}

/// cooperative cancellation check at backend-adapter entry and at
/// retry boundaries. Returns `Some(ToolCallResult)` when the caller
/// should short-circuit.
///
/// Sync adapters cannot hard-preempt an in-flight syscall; the best
/// they can do is (a) never *start* a call whose owning request has
/// been cancelled, and (b) drop out between retries / response reads.
/// Each adapter calls this helper at entry; HTTP additionally polls the
/// same token between response chunks via [`token_cancelled`].
pub(super) fn early_cancel_check(
    request: &BackendInvocationRequest,
    profile_name: &str,
    adapter_kind: &str,
) -> Option<ToolCallResult> {
    if let Some(token) = request.cancellation_token.as_ref()
        && token.is_cancelled()
    {
        metrics::counter!(
            "mcpg_adapter_cancelled_on_entry_total",
            "adapter" => adapter_kind.to_owned(),
            "profile" => profile_name.to_owned(),
        )
        .increment(1);
        return Some(ToolCallResult {
            content: vec![ToolContent::text(format!(
                "backend adapter '{adapter_kind}' aborted: request cancelled before dispatch"
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        });
    }
    None
}

pub(super) fn token_cancelled(token: Option<&tokio_util::sync::CancellationToken>) -> bool {
    token.map(|t| t.is_cancelled()).unwrap_or(false)
}
