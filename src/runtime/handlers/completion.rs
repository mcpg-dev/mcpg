use super::super::*;
use crate::protocol::CompletionCompleteParams;

impl GatewayRuntime {
    pub(crate) async fn handle_completion(
        &self,
        request_id: Value,
        params: CompletionCompleteParams,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        match request_context.load_session_cached(&*self.session_store, true) {
            Ok(_) => {
                // enforce per-session completion rate limit
                // before running plugins or the registry lookup so
                // a noisy autocomplete UI cannot DoS the surface.
                if !self.allow_completion(request_context.session_id.as_deref()) {
                    metrics::counter!("mcpg_completion_rate_limited_total").increment(1);
                    return protocol_http_error(
                        429,
                        Some(request_id),
                        -32099,
                        "completion rate limit exceeded",
                        None,
                    );
                }
                // the registry now takes the full completion
                // params (ref, argument, context) so it can honor
                // `context.arguments` for prompt completions and
                // handle `ref/resource` against the compiled
                // template catalog.
                // run surface-aware gate plugins before serving
                // completion values.
                let backend_name = params
                    .reference
                    .name
                    .clone()
                    .or_else(|| params.reference.uri.clone())
                    .unwrap_or_else(|| params.reference.ref_type.clone());
                let args_value =
                    serde_json::to_value(&params.argument).unwrap_or(serde_json::json!({}));
                if let Err(gate_response) = self
                    .evaluate_surface_gate(
                        "completion",
                        "completion.complete.pre",
                        &backend_name,
                        &args_value,
                        request_context,
                        &request_id,
                    )
                    .await
                {
                    return gate_response;
                }
                let mut result = self.capability_registry.complete_argument(&params);
                // Third tier: dynamic resource template completion.
                // Dispatched when (a) the static path returned no
                // values and (b) the operator declared
                // `variable_completions: { var: { kind: dynamic, … } }`
                // for this template+variable. Backend errors and
                // missing-plugin lookups degrade silently to the
                // empty result already in `result` — completion is
                // a UX hint, not load-bearing.
                if result.values.is_empty()
                    && let Some(dyn_entry) =
                        self.capability_registry.dynamic_completion_target(&params)
                    && let Some(plugin) = self.plugin_registry.backend(&dyn_entry.kind)
                {
                    const DYNAMIC_COMPLETION_TIMEOUT_MS: u64 = 3_000;
                    // Forward the MCP completion `context.arguments`
                    // to the backend so it can do owner-scoped
                    // lookups (`SELECT … WHERE owner = :ctx_owner
                    // …`). The static path above already filtered
                    // these values for the variable as a fallback;
                    // here we hand the raw map to the plugin.
                    let context_args = params
                        .context
                        .as_ref()
                        .map(|c| c.arguments.clone())
                        .unwrap_or_default();
                    let fut = plugin.complete_template_variable(
                        &dyn_entry.backend_name,
                        &params.argument.name,
                        &params.argument.value,
                        &dyn_entry.config,
                        &context_args,
                    );
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(DYNAMIC_COMPLETION_TIMEOUT_MS),
                        fut,
                    )
                    .await
                    {
                        Ok(Ok(values)) => {
                            result = crate::backends::clamp_completion_values(values);
                        }
                        Ok(Err(e)) => {
                            warn!(
                                backend = %dyn_entry.backend_name,
                                kind = %dyn_entry.kind,
                                error = %e,
                                "completion/complete: dynamic dispatch failed; returning empty"
                            );
                        }
                        Err(_) => {
                            warn!(
                                backend = %dyn_entry.backend_name,
                                kind = %dyn_entry.kind,
                                timeout_ms = DYNAMIC_COMPLETION_TIMEOUT_MS,
                                "completion/complete: dynamic dispatch timed out; returning empty"
                            );
                        }
                    }
                }
                // Audit: completion/complete.
                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                    request_id: request_context.request_id.as_str().to_owned(),
                    session_id: request_context.session_id.clone(),
                    tool_name: backend_name.clone(),
                    identity: plugin_identity_from_request(request_context),
                    transport: transport_label(&request_context.transport).to_owned(),
                    surface: "completion".to_owned(),
                };
                let event = mcpg_plugin_host::audit_events::completion_requested_event(
                    &audit_ctx,
                    &params.reference.ref_type,
                    &backend_name,
                    &params.argument.name,
                    result.values.len() as u64,
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                ProtocolHttpResponse {
                    http_status: 200,
                    session_id_header: None,
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: request_id,
                        result: serde_json::to_value(CompletionResult { completion: result })
                            .expect("completion result serialized"),
                    }),
                }
            }
            Err(error) => self.map_session_error_to_protocol_response(error, Some(request_id)),
        }
    }

    /// Configure the per-session completion rate limit.
    pub fn set_completion_rate_limit(&mut self, per_sec: Option<u64>) {
        self.completion_rate_limit_per_sec = per_sec;
    }

    /// Per-session token-bucket check for completion/complete.
    /// Returns true when the caller is allowed to proceed.
    fn allow_completion(&self, session_id: Option<&str>) -> bool {
        let Some(cap) = self.completion_rate_limit_per_sec else {
            return true;
        };
        if cap == 0 {
            return true;
        }
        let key = session_id.unwrap_or("anon").to_owned();
        let now = std::time::Instant::now();
        let mut entry = self.completion_limiter.entry(key).or_insert((cap, now));
        let (tokens, last) = entry.value_mut();
        let elapsed = now.duration_since(*last).as_secs_f64();
        let refill = (elapsed * cap as f64).floor() as u64;
        if refill > 0 {
            *tokens = tokens.saturating_add(refill).min(cap);
            *last = now;
        }
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }
}
