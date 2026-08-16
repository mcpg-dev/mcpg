use super::*;

impl GatewayRuntime {
    /// Evaluate policy for a tool+identity pair (used by admin policy:preview).
    pub fn evaluate_policy_for_preview(
        &self,
        tool_name: &str,
        identity: &crate::admin::service::TestIdentity,
    ) -> String {
        let trust_level = match identity.trust_level.as_str() {
            "unauthenticated" => RequestTrustLevel::Unauthenticated,
            "header_asserted" => RequestTrustLevel::HeaderAsserted,
            "verified" => RequestTrustLevel::Verified,
            _ => RequestTrustLevel::Unauthenticated,
        };

        let policy_ctx = ToolPolicyContext {
            tool_name: tool_name.to_owned(),
            trust_level,
            principal_id: identity.subject_id.clone(),
            issuer: None,
            auth_provider: None,
            identity_kind: identity.kind.clone(),
            roles: identity.roles.clone(),
            groups: identity.groups.clone(),
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        };

        match self.pre_dispatch_policy.evaluate_tool_call(&policy_ctx) {
            PreDispatchPolicyOutcome::Allow => "allow".to_owned(),
            PreDispatchPolicyOutcome::Deny(_) => "deny".to_owned(),
        }
    }

    /// Evaluate the operator-bound `policy_engine` chain for a
    /// pre-dispatch tool call. Walks the chain in
    /// **operator-declared order** from
    /// `governance.policy.engine[]`; first Deny short-circuits,
    /// Allow advances, all NotApplicable → NotApplicable. Returns
    /// the outcome so the caller can short-circuit on Deny +
    /// audit-record the deciding engine.
    ///
    /// This sits BEFORE the gateway's trust-level
    /// `pre_dispatch_policy` so operators delegate authz to OPA /
    /// Cedar / Casbin without losing the trust-level safety net.
    /// `decision_point` is `"tool.call.pre"` for pre-dispatch and
    /// `"tool.call.post"` for post-dispatch evaluation.
    ///
    /// The chain is the explicit `policy_chain` carried on this runtime,
    /// computed + cross-checked at boot from `governance.policy.engine[]` —
    /// operators control which engines participate AND in what order.
    pub async fn evaluate_pre_dispatch_policy_chain(
        &self,
        decision_point: &str,
        plugin_ctx: &mcpg_plugin_protocol::PluginContext,
        input: &serde_json::Value,
    ) -> mcpg_plugin_host::PolicyChainOutcome {
        self.plugin_registry
            .evaluate_policy_chain(&self.policy_chain, decision_point, input, plugin_ctx)
            .await
    }

    /// Narrow seam for policy consumers. Dispatches
    /// through `registry.evaluate_policy` — looks up the named
    /// engine, calls its `evaluate` with the given decision
    /// point + input + context, returns the `PolicyDecision`.
    /// When the engine isn't registered, returns
    /// `PolicyEffect::NotApplicable` with an empty
    /// policy_version (the registry helper's behaviour).
    ///
    /// **Intended consumers:** future subsystem delegation (tool_
    /// gate consulting a centralized engine, http_route asking
    /// before dispatching to an overridden route, admin mutations
    /// checking against a policy). The gateway's current
    /// `pre_dispatch_policy` is a pre-entity-kind system that
    /// doesn't go through this seam — migrating subsystems to
    /// delegate here is a separate effort when a driver emerges
    /// (operator demanding OPA / Cedar authz).
    pub async fn evaluate_policy(
        &self,
        engine_name: &str,
        decision_point: &str,
        input: &serde_json::Value,
        context: &mcpg_plugin_protocol::PluginContext,
    ) -> mcpg_plugin_protocol::policy::PolicyDecision {
        self.plugin_registry
            .evaluate_policy(engine_name, decision_point, input, context)
            .await
    }

    /// Authorize a non-tool surface (prompts, resources, completion, ...)
    /// before dispatch. Runs the SAME three pre-dispatch layers as
    /// `tools/call`, in order: first the operator-bound external policy_engine
    /// chain (OPA / Cedar / Casbin / yaml-rules); then the built-in
    /// trust-floor and CEL `allow_if` gate (`governance.minimum_trust` /
    /// `governance.access`); finally the surface-aware tool_gate plugin chain.
    /// Returns `Err(http_response)` when any layer denies/challenges; `Ok(())`
    /// on allow.
    ///
    /// Layers 1 and 2 are built-in and run even when no tool_gate PLUGIN is
    /// loaded — a non-tool surface must never silently skip the operator's
    /// declarative authz (the historical short-circuit did exactly that).
    pub(crate) async fn evaluate_surface_gate(
        &self,
        surface: &str,
        decision_point: &str,
        backend_name: &str,
        arguments: &Value,
        request_context: &RequestContext,
        request_id: &Value,
    ) -> Result<(), ProtocolHttpResponse> {
        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: backend_name.to_owned(),
            surface: surface.to_owned(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
        };

        // 1. External policy_engine chain (mirrors tools/call). On Deny the
        //    surface is refused before any backend dispatch.
        if let mcpg_plugin_host::PolicyChainOutcome::Deny {
            engine,
            reason,
            policy_version,
        } = self
            .evaluate_pre_dispatch_policy_chain(decision_point, &plugin_ctx, arguments)
            .await
        {
            metrics::counter!(
                "mcpg_policy_chain_denials_total",
                "engine" => engine.clone(),
                "binding" => backend_name.to_owned(),
            )
            .increment(1);
            self.record_policy_denial(
                request_context,
                backend_name,
                &format!("policy_chain:{engine}:{policy_version}"),
            );
            return Err(protocol_http_error(
                403,
                Some(request_id.clone()),
                -33000,
                format!("Policy `{engine}` denied {surface} '{backend_name}': {reason}"),
                self.debug_error_data(
                    request_context,
                    &format!("Policy engine `{engine}` denied {surface} '{backend_name}'."),
                ),
            ));
        }

        // 2. Built-in trust-floor + CEL `allow_if` (the operator's primary
        //    declarative authz — `governance.minimum_trust` was bypassed on
        //    these surfaces before). Surface-scoped name = prompt name /
        //    resource URI / completion ref.
        let policy_context = ToolPolicyContext::from_request_context(request_context, backend_name);
        if let PreDispatchPolicyOutcome::Deny(denial) =
            self.pre_dispatch_policy.evaluate_tool_call(&policy_context)
        {
            metrics::counter!(
                "mcpg_policy_evaluations_total",
                "decision" => "deny",
                "reason" => denial.audit_reason.clone(),
            )
            .increment(1);
            self.record_policy_denial(request_context, backend_name, &denial.audit_reason);
            let error_data =
                self.policy_denial_error_data(&denial, request_context, &denial.audit_reason);
            return Err(protocol_http_error(
                denial.http_status,
                Some(request_id.clone()),
                denial.code,
                denial.message.clone(),
                error_data,
            ));
        }

        // 3. Surface-aware tool_gate plugin chain (DLP / approval / rate-limit).
        //    Only this layer is plugin-backed, so it (and only it) is skipped
        //    when no tool_gate plugin is loaded.
        if !self.plugin_registry.has_tool_gate_plugins() {
            return Ok(());
        }
        match self
            .plugin_registry
            .evaluate_tool_gates_pre(&plugin_ctx, arguments, None)
            .await
        {
            mcpg_plugin_protocol::GateDecision::Allow { .. } => Ok(()),
            mcpg_plugin_protocol::GateDecision::Deny {
                http_status,
                code,
                message,
                error_data,
            } => Err(protocol_http_error(
                http_status,
                Some(request_id.clone()),
                code,
                message,
                error_data,
            )),
            mcpg_plugin_protocol::GateDecision::Challenge {
                http_status,
                code,
                message,
                challenge_data,
            } => Err(protocol_http_error(
                http_status,
                Some(request_id.clone()),
                code,
                message,
                Some(challenge_data),
            )),
            mcpg_plugin_protocol::GateDecision::PendingApproval {
                approval_id,
                deadline_at,
                summary,
                target_notifiers,
                metadata,
            } => {
                let outcome = approvals::await_pending_approval(approvals::AwaitContext {
                    approval_id,
                    deadline_at,
                    summary,
                    target_notifiers,
                    gate_metadata: metadata,
                    request_id: request_id.to_string(),
                    tool_name: backend_name.to_owned(),
                    identity: plugin_identity_from_request(request_context),
                    arguments: Some(arguments.clone()),
                    registry: &self.approval_registry,
                    plugin_registry: &self.plugin_registry,
                })
                .await;
                match outcome {
                    approvals::AwaitOutcome::Approved { .. } => Ok(()),
                    approvals::AwaitOutcome::Denied {
                        http_status,
                        code,
                        message,
                    } => Err(protocol_http_error(
                        http_status,
                        Some(request_id.clone()),
                        code,
                        message,
                        None,
                    )),
                }
            }
        }
    }

    /// Resolve the client's negotiated capabilities for the given request
    /// context. Used by non-tool surfaces (prompts, resources) that share the
    /// tool execution plumbing so pipeline steps can enforce capability gating.
    pub(crate) fn client_capabilities_for_context(
        &self,
        context: &RequestContext,
    ) -> crate::protocol::ClientCapabilities {
        // SEP-2575 stateless: a per-request `_meta.io.modelcontextprotocol/clientCapabilities`
        // wins over the session-bound capabilities. Stateless clients
        // never call `initialize`, so the synthetic session has empty
        // caps; reading from the per-request envelope is what makes
        // suspending steps (elicitation / sampling / roots) reachable.
        if let Some(caps) = context.modern_request_capabilities.as_ref() {
            return caps.clone();
        }
        context
            .load_session_cached(&*self.session_store, false)
            .ok()
            .map(|snap| snap.client_capabilities.clone())
            .unwrap_or_default()
    }

    pub(crate) fn record_policy_denial(
        &self,
        request_context: &RequestContext,
        tool_name: &str,
        reason: &str,
    ) {
        warn!(
            request_id = %request_context.request_id,
            upstream_request_id = request_context.upstream_request_id.as_deref().unwrap_or(""),
            identity_kind = request_context.identity.label(),
            identity_trust = ?request_context.identity.trust_level(),
            principal_id = request_context.identity.principal_id().unwrap_or(""),
            auth_provider = request_context.identity.auth_provider().unwrap_or(""),
            tool_name,
            policy_stage = "pre_dispatch",
            reason,
            "tool execution denied by policy"
        );
    }

    /// Build the JSON-RPC `error.data` for a pre-dispatch policy denial.
    /// Always carries the SEP-2350 insufficient-scope marker when present
    /// (independent of debug mode — the HTTP transport lifts it into the
    /// step-up `WWW-Authenticate` challenge); folds in the optional
    /// debug payload when debug is enabled.
    pub(crate) fn policy_denial_error_data(
        &self,
        denial: &policy::PolicyDenial,
        request_context: &RequestContext,
        hint: &str,
    ) -> Option<serde_json::Value> {
        let mut obj = match self.debug_error_data(request_context, hint) {
            Some(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        if let Some(scopes) = &denial.insufficient_scope {
            obj.insert(
                crate::transports::http::INSUFFICIENT_SCOPE_DATA_KEY.to_owned(),
                serde_json::Value::String(scopes.join(" ")),
            );
        }
        if obj.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(obj))
        }
    }

    /// Build diagnostic error data when debug mode is enabled.
    /// Returns `None` when debug is off, preserving minimal error responses in production.
    pub(crate) fn debug_error_data(
        &self,
        request_context: &RequestContext,
        hint: &str,
    ) -> Option<serde_json::Value> {
        if !self.debug_enabled {
            return None;
        }
        Some(serde_json::json!({
            "requestId": request_context.request_id.to_string(),
            "timestamp": Utc::now().to_rfc3339(),
            "hint": hint,
        }))
    }

    pub(crate) fn map_session_error_to_protocol_response(
        &self,
        error: SessionAccessError,
        id: Option<serde_json::Value>,
    ) -> ProtocolHttpResponse {
        match error {
            SessionAccessError::MissingSessionId => {
                metrics::counter!("mcpg_errors_total", "error_kind" => "session_missing_id")
                    .increment(1);
                protocol_http_error(
                    400,
                    id,
                    -32600,
                    format!("missing {} header", SESSION_ID_HEADER),
                    None,
                )
            }
            SessionAccessError::UnknownSession => {
                metrics::counter!("mcpg_errors_total", "error_kind" => "session_not_found")
                    .increment(1);
                protocol_http_error(404, id, -32001, "unknown or expired MCP session", None)
            }
            SessionAccessError::NotInitialized => {
                metrics::counter!("mcpg_errors_total", "error_kind" => "session_not_initialized")
                    .increment(1);
                protocol_http_error(
                    400,
                    id,
                    -32600,
                    "session has not completed notifications/initialized",
                    None,
                )
            }
        }
    }

    /// Resume a suspended pipeline after receiving a client response to a
    /// server-initiated request (elicitation, sampling, or roots/list).
    /// Looks up the pending request in the pipeline store, records the step
    /// result, resumes execution from the next step, and delivers the final
    /// result via the delivery bus to the client's SSE stream.
    /// Reject a pipeline-resume whose caller doesn't own the suspended
    /// pipeline. The owning session/principal is captured at suspension in
    /// `pipeline_state`; a resumer that learned/observed a pending
    /// `server_request_id` or replayed a `requestState` blob from another
    /// session must not drive the victim's pipeline forward (its later steps
    /// run under the OWNER's stored identity — privilege escalation +
    /// answer injection). Mirrors the federation server-request bridge's
    /// responder-session check.
    ///
    /// Returns `Some(error_response)` to deny (a 200 not-found-style envelope
    /// that doesn't leak the pipeline's existence), `None` to proceed.
    ///
    /// Binds on PRINCIPAL first — the escalation-critical axis, stable across
    /// requests on both wires; a cross-principal (incl. anonymous→identified)
    /// resumer is rejected. Session binding is additionally enforced when the
    /// owner is an identified caller (legacy stateful / principal-derived
    /// modern session), and skipped for anonymous owners whose modern
    /// synthetic session is per-request ephemeral — replay of those is
    /// covered by the requestState single-use guard instead.
    pub(crate) fn reject_foreign_pipeline_resumer(
        &self,
        request_context: &RequestContext,
        pipeline_state: &pipeline_store::PipelineExecutionState,
    ) -> Option<ProtocolHttpResponse> {
        if resumer_owns_pipeline(
            pipeline_state.request_context.identity.principal_id(),
            pipeline_state.session_id.as_str(),
            request_context.identity.principal_id(),
            request_context.session_id.as_deref(),
        ) {
            return None;
        }
        metrics::counter!("mcpg_pipeline_resume_owner_mismatch_total").increment(1);
        tracing::warn!(
            pipeline_id = %pipeline_state.pipeline_id,
            "pipeline resume denied: resumer session/principal does not own the suspended pipeline"
        );
        Some(protocol_http_error(
            200,
            None,
            -32600,
            "no pending server request found for this response id",
            self.debug_error_data(
                request_context,
                "the server request may have expired or already been handled",
            ),
        ))
    }
}
