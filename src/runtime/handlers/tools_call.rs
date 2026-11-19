use super::super::*;
use super::task_status_notification;
use crate::protocol::v_2026_07_28::dispatch::tasks::wire_task;
use crate::protocol::v_2026_07_28::extensions::tasks::wire::CreateTaskResult;
use crate::protocol::{
    JSONRPC_VERSION, JsonRpcErrorBody, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse,
    ToolCallParams,
};
use serde_json::Value;

impl GatewayRuntime {
    /// Run `tools/call` through the full pipeline. With
    /// `materialize_as_task` the call is accepted as a SEP-2663 task: the
    /// answer is `resultType:"task"`, and the backend runs in the
    /// background under the caller's task owner key.
    pub(crate) async fn handle_tools_call(
        &self,
        request_id: Value,
        params: ToolCallParams,
        materialize_as_task: bool,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        // The realtime admission tool answers only the gateway's own calls;
        // to a caller it is an unknown tool.
        if self.is_admission_tool(&params.name) && !request_context.realtime_admission {
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown tool: {}", params.name),
                self.debug_error_data(
                    request_context,
                    "Use tools/list to discover available tool names.",
                ),
            );
        }
        match self.capability_registry.tool_route(&params.name) {
            Some(route) => {
                // A tool with `taskSupport: forbidden` never runs as a
                // task.
                if materialize_as_task
                    && matches!(
                        self.capability_registry.tool_task_support(&params.name),
                        Some(crate::backends::TaskSupport::Forbidden)
                    )
                {
                    return protocol_http_error(
                        400,
                        Some(request_id),
                        -32602,
                        format!(
                            "Tool '{}' does not support task execution (taskSupport = forbidden)",
                            params.name
                        ),
                        None,
                    );
                }

                let expr_ctx =
                    request_context.to_expr_context(&params.name, params.arguments.as_ref());
                // progressToken MUST be a string or number per the
                // Progress spec. Reject object/array/bool/null up front
                // so a broken client cannot inject a structured token
                // that downstream correlation would mis-key.
                let progress_token = match extract_request_progress_token(params.meta.as_ref()) {
                    Ok(token) => token,
                    Err(message) => {
                        return protocol_http_error(400, Some(request_id), -32602, message, None);
                    }
                };
                // SEP-2575 per-request log-level floor; absent, the
                // request's pipeline sends no `notifications/message`.
                let request_log_level = match extract_request_log_level(params.meta.as_ref()) {
                    Ok(level) => level,
                    Err(message) => {
                        return protocol_http_error(400, Some(request_id), -32602, message, None);
                    }
                };
                // SEP-2133 `dev.mcpg/idempotency` — peel
                // the caller-supplied idempotency key
                // out of `_meta` and validate format
                // up-front. Malformed values short-
                // circuit with `-33013 IdempotencyKeyMalformed`
                // before any further work.
                let idempotency_key: Option<String> =
                    match idempotency::extract_request_key(params.meta.as_ref()) {
                        idempotency::KeyValidation::Absent => None,
                        idempotency::KeyValidation::Valid(k) => Some(k),
                        idempotency::KeyValidation::Invalid(reason) => {
                            return protocol_http_error(
                                400,
                                Some(request_id),
                                idempotency::ERROR_CODE_KEY_MALFORMED,
                                reason.as_message(),
                                None,
                            );
                        }
                    };
                // Idempotency PEEK: when the feature is
                // enabled AND the
                // caller supplied a key, look up any
                // existing record. Replay-on-hit
                // bypasses every gate below this point
                // (QGATE / tool-gate plugins / dispatch).
                //
                // The decision tree:
                //   - hit Completed   → replay envelope
                //                       with `_meta` marker;
                //                       audit + counter +
                //                       `IdempotentReplay`
                //                       outcome.
                //   - hit InFlight    → 409 +
                //                       `IdempotencyInFlight`
                //                       (HTTP transport
                //                       additionally adds
                //                       `Retry-After: 1`).
                //   - hit Conflict    → 422 +
                //                       `IdempotencyConflict`.
                //   - miss / disabled → fall through.
                //
                // The reservation itself happens later
                // (atomic, just before dispatch) so we
                // don't claim a slot for a request that
                // policy / tool-gate plugins might still
                // deny.
                let idempotency_advertised = self.idempotency_capability.is_some();
                // A call accepted as a task and an inline call live in
                // DIFFERENT dedupe namespaces, so an inline charge and a
                // task charge with the same key + body don't collide.
                // The scope's `method` field carries the distinction.
                let idempotency_method: &'static str = if materialize_as_task {
                    "tasks/create"
                } else {
                    "tools/call"
                };
                // Isolate the idempotency namespace per
                // caller. An anonymous identity has no principal,
                // so the original scope collapsed every anonymous
                // caller onto a single shared "anonymous" tenant +
                // constant identity_hash — letting one
                // unauthenticated caller replay (or block, via
                // InFlight) another's result under a guessed key.
                // Authenticated callers scope by principal (stable
                // across reconnects, the point of idempotency).
                // Anonymous callers scope by the server-issued
                // session id instead, so each anonymous session is
                // its own namespace: within-session retry still
                // dedupes, but distinct anonymous callers can't
                // collide. An anonymous request with no session id
                // has no safe discriminator → scope is None and
                // dedupe is skipped (peek + reserve_or_get below
                // both gate on `Some(scope)`).
                let idempotency_scope: Option<idempotency::IdempotencyScope> =
                    idempotency_key.as_ref().and_then(|_| {
                        if request_context.identity.is_anonymous() {
                            let sid = request_context
                                .session_id
                                .as_deref()
                                .filter(|s| !s.is_empty())?;
                            Some(idempotency::IdempotencyScope {
                                tenant_id: format!("anon-session:{sid}"),
                                identity_hash: idempotency::hash_identity(
                                    Some(sid),
                                    Some("anonymous-session"),
                                    None,
                                ),
                                method: idempotency_method.to_owned(),
                                tool_name: params.name.clone(),
                            })
                        } else {
                            Some(idempotency::IdempotencyScope {
                                tenant_id: request_context
                                    .identity
                                    .principal_id()
                                    .unwrap_or("anonymous")
                                    .to_owned(),
                                identity_hash: idempotency::hash_identity(
                                    request_context.identity.principal_id(),
                                    request_context.identity.auth_provider(),
                                    request_context.identity.issuer(),
                                ),
                                method: idempotency_method.to_owned(),
                                tool_name: params.name.clone(),
                            })
                        }
                    });
                // Only the dedupe lookups read the body hash, and they run
                // only with a key, a scope and the feature on.
                let idempotency_request_hash: Option<[u8; 32]> =
                    (idempotency_advertised && idempotency_scope.is_some()).then(|| {
                        idempotency::hash_request_body(
                            idempotency_method,
                            &params.name,
                            params.arguments.as_ref(),
                        )
                    });
                if idempotency_advertised
                    && let (Some(key), Some(scope), Some(request_hash)) = (
                        idempotency_key.as_deref(),
                        idempotency_scope.as_ref(),
                        idempotency_request_hash.as_ref(),
                    )
                {
                    match self.idempotency_store.peek(scope, key, request_hash).await {
                        Ok(Some(idempotency::PeekOutcome::Completed {
                            outcome,
                            completed_at,
                        })) => {
                            // A completed-replay below
                            // short-circuits the policy / quota /
                            // tool-gate chain. Re-run the built-in
                            // pre-dispatch policy gate (trust floor
                            // + CEL allow_if) so a caller whose
                            // authorization was revoked since the
                            // original call cannot replay a cached
                            // Allow under a still-valid key. On Deny
                            // we do NOT replay — fall through so the
                            // normal gate path below re-evaluates
                            // and returns the proper denial.
                            // (The external policy-engine chain +
                            // tool-gate plugins remain replay-
                            // bypassed by design — they may carry
                            // side effects and replay is excluded
                            // from quota math; the trust+CEL floor
                            // is the security-critical layer.)
                            // By default the replay re-check is the
                            // built-in trust-floor + CEL gate only
                            // (cheap, side-effect-free). With
                            // idempotency.replay_revalidation enabled,
                            // re-run the FULL pre-dispatch stack
                            // (external policy_engine chain + tool_gate
                            // plugins) so authorization revoked in
                            // those layers is honored on replay; on a
                            // denial we return the gate's response
                            // directly rather than serving the cached
                            // Allow.
                            let replay_authorized = if self.idempotency_replay_revalidation {
                                match self
                                    .evaluate_surface_gate(
                                        "tool",
                                        "tool.call.pre",
                                        &params.name,
                                        PolicyRoute::for_tool(&route),
                                        params.arguments.as_ref().unwrap_or(&serde_json::json!({})),
                                        request_context,
                                        &request_id,
                                    )
                                    .await
                                {
                                    Ok(()) => true,
                                    Err(denied) => return denied,
                                }
                            } else {
                                matches!(
                                    self.pre_dispatch_policy.evaluate(
                                        &ToolPolicyContext::from_request_context(
                                            request_context,
                                            &params.name,
                                        ),
                                        PolicyRoute::for_tool(&route),
                                    ),
                                    PreDispatchPolicyOutcome::Allow
                                )
                            };
                            // A record marked
                            // `payload_truncated` was
                            // committed BUT could not
                            // safely cache the over-cap
                            // envelope. Treat as a
                            // cache miss so the call
                            // executes fresh; future
                            // retries with the same
                            // key + body collide on
                            // the body-hash invariant
                            // and the new reservation
                            // overwrites the truncated
                            // marker (LWW).
                            if outcome.payload_truncated {
                                // fall through — peek
                                // observed truncation
                                // marker; dispatcher
                                // proceeds without
                                // dedupe (and reserves
                                // a fresh slot below).
                            } else if !replay_authorized {
                                // Authorization revoked
                                // since the cached call — do not
                                // replay; fall through to the
                                // normal gate which denies with the
                                // correct error + audit.
                            } else if materialize_as_task {
                                // A task replay's cached envelope
                                // carries only the task handle; it is
                                // joined with the live task store
                                // snapshot so the caller sees the
                                // current task status rather than a
                                // stale "working" placeholder.
                                return self
                                    .build_tasks_create_replay_response(
                                        request_context,
                                        request_id,
                                        &params.name,
                                        key,
                                        outcome,
                                        completed_at,
                                    )
                                    .await;
                            } else {
                                return self
                                    .build_idempotency_replay_response(
                                        request_context,
                                        request_id,
                                        &params.name,
                                        key,
                                        outcome,
                                        completed_at,
                                    )
                                    .await;
                            }
                        }
                        Ok(Some(idempotency::PeekOutcome::InFlight { started_at })) => {
                            let _ = self
                                .emit_idempotency_audit(
                                    "mcpg.idempotency.in_flight",
                                    request_context,
                                    &params.name,
                                    serde_json::json!({
                                        "key_hash": idempotency::key_hash_hex(key),
                                        "started_at": chrono::DateTime::<chrono::Utc>::from(
                                            started_at,
                                        )
                                        .to_rfc3339(),
                                        "method": idempotency_method,
                                    }),
                                )
                                .await;
                            metrics::counter!(
                                "mcpg_idempotency_in_flight_total",
                                "tool" => params.name.clone(),
                                "method" => idempotency_method,
                            )
                            .increment(1);
                            return protocol_http_error(
                                409,
                                Some(request_id),
                                idempotency::ERROR_CODE_IN_FLIGHT,
                                "another request with this idempotency key is in progress",
                                Some(serde_json::json!({"retry_after_ms": 1000u64})),
                            );
                        }
                        Ok(Some(idempotency::PeekOutcome::Conflict {
                            stored_request_hash,
                        })) => {
                            let _ = self
                                .emit_idempotency_audit(
                                    "mcpg.idempotency.body_mismatch",
                                    request_context,
                                    &params.name,
                                    serde_json::json!({
                                        "key_hash": idempotency::key_hash_hex(key),
                                        "stored_hash": hex::encode(stored_request_hash),
                                        "new_hash": hex::encode(request_hash),
                                        "method": idempotency_method,
                                    }),
                                )
                                .await;
                            metrics::counter!(
                                "mcpg_idempotency_conflict_total",
                                "tool" => params.name.clone(),
                                "method" => idempotency_method,
                            )
                            .increment(1);
                            return protocol_http_error(
                                422,
                                Some(request_id),
                                idempotency::ERROR_CODE_CONFLICT,
                                "request body differs from cached request for this idempotency key",
                                Some(serde_json::json!({
                                    "stored_hash": hex::encode(stored_request_hash),
                                })),
                            );
                        }
                        Ok(None) => { /* miss — fall through */ }
                        Err(err) => {
                            warn!(
                                request_id = %request_context.request_id,
                                tool_name = %params.name,
                                error = %err,
                                "idempotency peek failed; proceeding without dedupe",
                            );
                        }
                    }
                }
                // Snapshot the client's capabilities — the per-request
                // `_meta.io.modelcontextprotocol/clientCapabilities`
                // the transport lifted onto the context (SEP-2575) — so
                // pipeline execution can reject capability-gated server
                // requests. prompts/get and resources/read read them
                // through the same helper.
                let client_capabilities = self.client_capabilities_for_context(request_context);
                // register a cancellation token for the
                // duration of this synchronous tool call so
                // `notifications/cancelled` published between
                // now and completion can abort at the next
                // pipeline step boundary. The RAII cleanup
                // drops the registry entry on any exit path.
                // Filed under the CLIENT's JSON-RPC id, which is the only
                // handle `notifications/cancelled` can name it by — the
                // internal request UUID never reaches the wire.
                let cancel_key = Self::request_cancellation_key(
                    request_context.session_id.as_deref(),
                    &request_id.to_string(),
                );
                let cancel_token = self.register_cancellation_token(
                    &cancel_key,
                    request_context.session_id.as_deref(),
                    request_context.identity.principal_id(),
                );
                let _cancel_cleanup =
                    scopeguard_cancellation(self.cancellation_tokens.clone(), cancel_key.clone());
                // Surface the
                // caller-supplied idempotency key on
                // the per-request hint so pipeline
                // sub-steps and backend
                // plugins can read it without re-
                // parsing `_meta`. The scope_hash
                // mirrors the gateway-side dedupe
                // boundary so backends scope their own
                // per-upstream dedupe consistently.
                let idempotency_hint =
                    match (idempotency_key.as_deref(), idempotency_scope.as_ref()) {
                        (Some(key), Some(scope)) => {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(scope.tenant_id.as_bytes());
                            hasher.update(b":");
                            hasher.update(scope.identity_hash.as_slice());
                            hasher.update(b":");
                            hasher.update(scope.method.as_bytes());
                            hasher.update(b":");
                            hasher.update(scope.tool_name.as_bytes());
                            Some(execution::IdempotencyHint {
                                key: key.to_owned(),
                                scope_hash: *hasher.finalize().as_bytes(),
                            })
                        }
                        _ => None,
                    };
                let execution_request = BackendInvocationRequest {
                    context: request_context.clone(),
                    tool_name: params.name.clone(),
                    arguments: params.arguments.clone(),
                    expr_ctx,
                    progress_token,
                    request_log_level,
                    client_capabilities,
                    cancellation_token: Some(cancel_token),
                    idempotency_hint,
                };
                // Tool-call rate limiting runs in the tool-gate
                // plugin chain: operators load `dev.mcpg.rate-limit`
                // (or any other tool-gate plugin) via `plugins[]`.
                // See `libs/plugins/reliability/rate-limit/`.
                // Operator-bound policy_engine chain
                // (OPA / Cedar / Casbin / yaml-rules)
                // runs BEFORE the gateway's trust-level
                // pre_dispatch_policy so external authz
                // can deny before any trust check, but
                // the trust-level safety net still
                // applies if no engine takes the
                // decision (Allow + NotApplicable).
                let empty_arguments = Value::Object(serde_json::Map::new());
                let chain_input = params.arguments.as_ref().unwrap_or(&empty_arguments);
                // An empty chain decides NotApplicable without reading
                // its context.
                let chain_outcome = if self.policy_chain.is_empty() {
                    mcpg_plugin_host::PolicyChainOutcome::NotApplicable
                } else {
                    let policy_chain_ctx = mcpg_plugin_protocol::PluginContext {
                        request_id: request_context.request_id.as_str().to_owned(),
                        session_id: request_context.session_id.clone(),
                        tool_name: params.name.clone(),
                        identity: plugin_identity_from_request(request_context),
                        transport: transport_label(&request_context.transport).to_owned(),
                        surface: "tool".to_owned(),
                    };
                    self.evaluate_pre_dispatch_policy_chain(
                        "tool.call.pre",
                        &policy_chain_ctx,
                        chain_input,
                    )
                    .await
                };
                if let mcpg_plugin_host::PolicyChainOutcome::Deny {
                    engine,
                    reason,
                    policy_version,
                } = chain_outcome
                {
                    metrics::counter!(
                        "mcpg_policy_chain_denials_total",
                        "engine" => engine.clone(),
                        "binding" => params.name.clone(),
                    )
                    .increment(1);
                    self.record_policy_denial(
                        request_context,
                        &params.name,
                        &format!("policy_chain:{engine}:{policy_version}"),
                    );
                    // CP sample: pre-dispatch policy denial.
                    // No backend dispatch happens; duration ≈ 0.
                    // error_code carries the engine name so
                    // operators can filter by which engine
                    // denied. error_hash hashes the human
                    // reason for log correlation.
                    // Also capture the request
                    // arguments on policy-chain deny so operators
                    // can answer "what request triggered this?".
                    // No `response_payload` — the call never
                    // executed. `chain_input` is in scope
                    // already (line above); reuse it.
                    let (req_payload, req_truncated) =
                        if self.tool_call_recorder.payload_capture_enabled() {
                            cp_metrics::serialize_payload(chain_input)
                        } else {
                            (None, false)
                        };
                    if req_truncated {
                        cp_metrics::note_truncation("policy_chain_deny");
                    }
                    self.tool_call_recorder.record(cp_metrics::ToolCallSample {
                        plugin_id: cp_metrics::plugin_id_from_kind(&binding_type_label(&route)),
                        tool_name: params.name.clone(),
                        binding_id: None,
                        started_at: chrono::Utc::now(),
                        duration: std::time::Duration::from_secs(0),
                        outcome: cp_metrics::SampleOutcome::PolicyDenied,
                        error_code: Some(format!("policy:{engine}")),
                        error_hash: cp_metrics::hash_error(&reason),
                        request_id: Some(request_context.request_id.as_str().to_owned()),
                        caller_subject: request_context.identity.principal_id().map(str::to_owned),
                        request_payload: req_payload,
                        response_payload: None,
                        payload_truncated: req_truncated,
                    });
                    return protocol_http_error(
                                    403,
                                    Some(request_id),
                                    -33000,
                                    format!(
                                        "Policy `{engine}` denied tool '{}': {reason}",
                                        params.name
                                    ),
                                    self.debug_error_data(
                                        request_context,
                                        &format!(
                                            "Policy engine `{engine}` denied tool '{}'. Check the engine's bundle and request shape.",
                                            params.name
                                        ),
                                    ),
                                );
                }
                let policy_context =
                    ToolPolicyContext::from_request_context(request_context, &params.name);
                match self
                    .pre_dispatch_policy
                    .evaluate(&policy_context, PolicyRoute::for_tool(&route))
                {
                    PreDispatchPolicyOutcome::Allow => {
                        metrics::counter!("mcpg_policy_evaluations_total", "decision" => "allow")
                            .increment(1);
                    }
                    PreDispatchPolicyOutcome::Deny(denial) => {
                        metrics::counter!("mcpg_policy_evaluations_total", "decision" => "deny", "reason" => denial.audit_reason.clone()).increment(1);
                        metrics::counter!("mcpg_errors_total", "error_kind" => "policy_denial", "binding" => params.name.clone()).increment(1);
                        self.record_policy_denial(
                            request_context,
                            &params.name,
                            &denial.audit_reason,
                        );
                        // Audit: every access denial
                        // (pre-dispatch policy gate) on record per
                        // SOC2 CC6.1 / PCI-DSS 10.2.2.
                        let audit_ctx = mcpg_plugin_protocol::PluginContext {
                            request_id: request_context.request_id.as_str().to_owned(),
                            session_id: request_context.session_id.clone(),
                            tool_name: params.name.clone(),
                            identity: plugin_identity_from_request(request_context),
                            transport: transport_label(&request_context.transport).to_owned(),
                            surface: "tool".to_owned(),
                        };
                        let event = mcpg_plugin_host::audit_events::tool_call_access_denied_event(
                            &audit_ctx,
                            &denial.audit_reason,
                        )
                        .with_upstream_request_id(request_context.upstream_request_id.clone());
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        // CP sample: pre-dispatch policy denial
                        // from the static built-in gate; capture
                        // request args on static-policy deny.
                        let (req_payload, req_truncated) =
                            if self.tool_call_recorder.payload_capture_enabled() {
                                let args = params
                                    .arguments
                                    .clone()
                                    .unwrap_or_else(|| serde_json::json!({}));
                                cp_metrics::serialize_payload(&args)
                            } else {
                                (None, false)
                            };
                        if req_truncated {
                            cp_metrics::note_truncation("policy_static_deny");
                        }
                        self.tool_call_recorder.record(cp_metrics::ToolCallSample {
                            plugin_id: cp_metrics::plugin_id_from_kind(&binding_type_label(&route)),
                            tool_name: params.name.clone(),
                            binding_id: None,
                            started_at: chrono::Utc::now(),
                            duration: std::time::Duration::from_secs(0),
                            outcome: cp_metrics::SampleOutcome::PolicyDenied,
                            error_code: Some("policy:pre_dispatch".to_owned()),
                            error_hash: cp_metrics::hash_error(&denial.audit_reason),
                            request_id: Some(request_context.request_id.as_str().to_owned()),
                            caller_subject: request_context
                                .identity
                                .principal_id()
                                .map(str::to_owned),
                            request_payload: req_payload,
                            response_payload: None,
                            payload_truncated: req_truncated,
                        });
                        let error_data = self.policy_denial_error_data(
                                        &denial,
                                        request_context,
                                        &format!(
                                            "Policy denied tool '{}'. Check identity trust level and policy rules.",
                                            params.name
                                        ),
                                    );
                        return protocol_http_error(
                            denial.http_status,
                            Some(request_id),
                            denial.code,
                            denial.message,
                            error_data,
                        );
                    }
                }

                // An operations tool proposes an operation instead of
                // acting, for a Personal Agent that lists the extension;
                // the gates and the backend run when it is confirmed.
                if let Some(proposed) = self
                    .propose_pap_operation(&request_id, &params, request_context)
                    .await
                {
                    return proposed;
                }

                // A tool gate the license gate withheld cannot judge this
                // call, and an item it holds is one the gateway cannot
                // serve without, so the call does not run without either.
                if let Some(hold) = self.license_state.tool_hold.as_deref() {
                    metrics::counter!("mcpg_license_tool_call_refusals_total", "surface" => "tool")
                        .increment(1);
                    return protocol_http_error(
                        503,
                        Some(request_id),
                        -33003,
                        hold.to_owned(),
                        self.debug_error_data(
                            request_context,
                            "A licence-gated tool gate is withheld, or an item the gateway \
                                 cannot run without is held, because no licence covers it. Tool \
                                 calls resume once one does.",
                        ),
                    );
                }

                // License quota refusal. The CP
                // pushes a `QuotaStatus` on each heartbeat;
                // when `exhausted: true`, refuse the call
                // ahead of any backend dispatch with a
                // 429-style JSON-RPC error and a
                // `governance.quota.exceeded` audit event.
                // Lock-free hot-path read; no-op when no CP
                // is attached (provider returns `None`).
                // License RPS safeguard. A ceiling on requests per
                // second for THIS gateway, so a runaway caller sheds load
                // instead of burning a month's allowance in minutes. It
                // refuses like the quota gate does, and the refusal is
                // recorded as `QuotaExceeded` — a call we declined to run
                // is never billable.
                if let Err(rps) = self.admit_plan_rps("tools") {
                    let reason = format!("per-gateway rate limit exceeded (limit={rps}/s)");
                    let event = mcpg_plugin_host::audit_events::quota_exceeded_event(
                        plugin_identity_from_request(request_context),
                        request_context.request_id.as_str(),
                        &params.name,
                        "cp_license",
                        "rps_per_gateway",
                        &reason,
                    )
                    .with_upstream_request_id(request_context.upstream_request_id.clone());
                    let _ = self.plugin_registry.emit_audit_event(&event).await;
                    self.tool_call_recorder.record(cp_metrics::ToolCallSample {
                        plugin_id: cp_metrics::plugin_id_from_kind(&binding_type_label(&route)),
                        tool_name: params.name.clone(),
                        binding_id: None,
                        started_at: chrono::Utc::now(),
                        duration: std::time::Duration::from_secs(0),
                        outcome: cp_metrics::SampleOutcome::QuotaExceeded,
                        error_code: Some("cp:rps_exceeded".to_owned()),
                        error_hash: cp_metrics::hash_error(&reason),
                        request_id: Some(request_context.request_id.as_str().to_owned()),
                        caller_subject: request_context.identity.principal_id().map(str::to_owned),
                        request_payload: None,
                        response_payload: None,
                        payload_truncated: false,
                    });
                    return protocol_http_error(
                        429,
                        Some(request_id),
                        -33002,
                        format!(
                            "Per-gateway rate limit of {rps} requests/second exceeded. \
                                 Retry shortly."
                        ),
                        crate::transports::http::retry_after_data(
                            self.debug_error_data(
                                request_context,
                                &format!(
                                    "The license caps this gateway at {rps} requests/second. \
                                         Requests above it are shed before dispatch and are not \
                                         billed. Add replicas or raise the plan to lift it."
                                ),
                            ),
                            1,
                        ),
                    );
                }

                if let Some(qs) = self.cp_quota_status.current()
                    && qs.exhausted
                {
                    metrics::counter!(
                        "mcpg_cp_quota_refusals_total",
                        "tool" => params.name.clone(),
                    )
                    .increment(1);
                    let until_str = qs
                        .until
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_owned());
                    let reason = format!(
                        "tool-call quota exhausted (limit={:?}, remaining={:?}, resets_at={until_str})",
                        qs.limit, qs.remaining
                    );
                    let event = mcpg_plugin_host::audit_events::quota_exceeded_event(
                        plugin_identity_from_request(request_context),
                        request_context.request_id.as_str(),
                        &params.name,
                        "cp_license",
                        "tool_calls_per_month",
                        &reason,
                    )
                    .with_upstream_request_id(request_context.upstream_request_id.clone());
                    let _ = self.plugin_registry.emit_audit_event(&event).await;
                    self.tool_call_recorder.record(cp_metrics::ToolCallSample {
                        plugin_id: cp_metrics::plugin_id_from_kind(&binding_type_label(&route)),
                        tool_name: params.name.clone(),
                        binding_id: None,
                        started_at: chrono::Utc::now(),
                        duration: std::time::Duration::from_secs(0),
                        outcome: cp_metrics::SampleOutcome::QuotaExceeded,
                        error_code: Some("cp:quota_exhausted".to_owned()),
                        error_hash: cp_metrics::hash_error(&reason),
                        request_id: Some(request_context.request_id.as_str().to_owned()),
                        caller_subject: request_context.identity.principal_id().map(str::to_owned),
                        request_payload: None,
                        response_payload: None,
                        payload_truncated: false,
                    });
                    return protocol_http_error(
                                    429,
                                    Some(request_id),
                                    -33002,
                                    format!(
                                        "Tool-call quota exhausted for this organization. Resets at {until_str}.",
                                    ),
                                    crate::transports::http::retry_after_data(
                                        self.debug_error_data(
                                            request_context,
                                            &format!(
                                                "Control-plane reported tool-call quota exhausted; new calls will be refused until {until_str}. Contact your billing admin to raise the limit."
                                            ),
                                        ),
                                        crate::runtime::cp::cp_quota::secs_until(qs.until),
                                    ),
                                );
                }

                // Quota gate. Slots
                // between the trust-level pre-dispatch policy
                // and the plugin tool-gate chain. Refuses on
                // rate-limit / budget / concurrency cap with
                // a 429-style JSON-RPC error and the
                // `governance.quota.exceeded` audit event.
                // `_quota_permit` (when Some) holds the
                // concurrency permit through the binding's
                // execution; dropping it after dispatch
                // returns releases the in-flight slot.
                // Off-feature or no quota gate installed →
                // arm vanishes and the path is unchanged.
                #[cfg(feature = "governance-quotas")]
                let _quota_permit = if let Some(gate) = self.quota_gate.as_ref() {
                    let session_id_view = request_context.session_id.as_deref();
                    match gate
                        .evaluate_for_tool(&params.name, session_id_view, &request_context.identity)
                        .await
                    {
                        Ok(crate::runtime::quota_gate::QuotaDecision::Allow {
                            permit,
                            warnings,
                        }) => {
                            emit_quota_warnings(
                                &self.plugin_registry,
                                request_context,
                                &params.name,
                                &warnings,
                            )
                            .await;
                            permit
                        }
                        Ok(crate::runtime::quota_gate::QuotaDecision::Deny {
                            policy_id,
                            kind,
                            reason,
                        }) => {
                            metrics::counter!(
                                "mcpg_quota_denials_total",
                                "kind" => kind.as_str(),
                                "policy_id" => policy_id.clone(),
                                "binding" => params.name.clone(),
                            )
                            .increment(1);
                            let event = mcpg_plugin_host::audit_events::quota_exceeded_event(
                                plugin_identity_from_request(request_context),
                                request_context.request_id.as_str(),
                                &params.name,
                                &policy_id,
                                kind.as_str(),
                                &reason,
                            )
                            .with_upstream_request_id(request_context.upstream_request_id.clone());
                            let _ = self.plugin_registry.emit_audit_event(&event).await;
                            return protocol_http_error(
                                            429,
                                            Some(request_id),
                                            -33001,
                                            format!(
                                                "Quota policy `{policy_id}` ({}) refused tool '{}': {reason}",
                                                kind.as_str(),
                                                params.name
                                            ),
                                            self.debug_error_data(
                                                request_context,
                                                &format!(
                                                    "Quota gate denied tool '{}' under policy `{}` ({}). Check governance.quotas.{}[].id and the binding's quotas: ref.",
                                                    params.name,
                                                    policy_id,
                                                    kind.as_str(),
                                                    kind.as_str()
                                                ),
                                            ),
                                        );
                        }
                        Err(e) => {
                            // A gate-internal failure (e.g. a quota-store
                            // outage). Default posture is fail-closed: refuse
                            // the call so the outage cannot silently disable
                            // rate-limit / budget / concurrency enforcement.
                            // Operators opt into fail-open via
                            // governance.quotas.on_error: allow.
                            if gate.fail_open_on_error() {
                                warn!(
                                    error = %e,
                                    tool = %params.name,
                                    "quota gate failed; on_error=allow, proceeding without a permit"
                                );
                                None
                            } else {
                                metrics::counter!(
                                    "mcpg_quota_denials_total",
                                    "kind" => "error",
                                    "policy_id" => "none",
                                    "binding" => params.name.clone(),
                                )
                                .increment(1);
                                let event = mcpg_plugin_host::audit_events::quota_exceeded_event(
                                    plugin_identity_from_request(request_context),
                                    request_context.request_id.as_str(),
                                    &params.name,
                                    "none",
                                    "error",
                                    &e.to_string(),
                                )
                                .with_upstream_request_id(
                                    request_context.upstream_request_id.clone(),
                                );
                                let _ = self.plugin_registry.emit_audit_event(&event).await;
                                warn!(
                                    error = %e,
                                    tool = %params.name,
                                    "quota gate failed; on_error=deny, refusing the call"
                                );
                                return protocol_http_error(
                                                503,
                                                Some(request_id),
                                                -33002,
                                                format!(
                                                    "Quota enforcement is temporarily unavailable for tool '{}'",
                                                    params.name
                                                ),
                                                self.debug_error_data(
                                                    request_context,
                                                    "The quota store errored and governance.quotas.on_error is `deny` (fail-closed). Retry, or set governance.quotas.on_error: allow to fail open.",
                                                ),
                                            );
                            }
                        }
                    }
                } else {
                    None
                };

                // Payment + plugin tool-gate chain: pre-dispatch
                // Payment evaluation is handled by the registered payment plugin
                // (e.g. MPP PaymentGatePlugin) within the plugin chain. The chain
                // captures Allow metadata (e.g. payment receipts) for result merging.
                //
                // A pre-dispatch gate may also return Allow.modified_arguments to
                // rewrite the tool arguments before they reach the transform chain
                // and backend. Captured here, applied just below.
                let mut gate_modified_arguments: Option<serde_json::Value> = None;
                // A pre-dispatch gate may hand back a pre-computed
                // result (response-cache hit). Captured here and
                // routed through the same post-dispatch pipeline a
                // real backend result takes — the cached value is
                // untrusted plugin output, not a finished response.
                let mut cached_result_short_circuit: Option<serde_json::Value> = None;
                // Enter even with no tool_gate plugins loaded when the
                // operator wants tool-call audit records — the empty-chain
                // branch of `evaluate_tool_gates_pre` owns the
                // `mcpg.tool.call.allowed` emission.
                let plugin_gate_meta = if self.plugin_registry.has_tool_gate_plugins()
                    || self.plugin_registry.emits_tool_call_allowed()
                {
                    let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                        request_id: request_context.request_id.as_str().to_owned(),
                        session_id: request_context.session_id.clone(),
                        tool_name: params.name.clone(),
                        identity: plugin_identity_from_request(request_context),
                        transport: transport_label(&request_context.transport).to_owned(),
                        surface: "tool".to_owned(),
                    };
                    match self
                        .plugin_registry
                        .evaluate_tool_gates_pre_from(
                            &plugin_ctx,
                            params.arguments.as_ref().unwrap_or(&serde_json::json!({})),
                            params.meta.as_ref(),
                            request_context.upstream_request_id.as_deref(),
                            request_context.client_ip,
                        )
                        .await
                    {
                        mcpg_plugin_protocol::GateDecision::Allow {
                            metadata,
                            modified_arguments,
                            modified_result,
                        } => {
                            if let Some(cached_result) = modified_result {
                                // Plugin provided a pre-computed result — skip backend
                                // dispatch. Defer to after the gate metadata is bound,
                                // then run it through the post-dispatch pipeline.
                                metrics::counter!("mcpg_plugin_cache_hits_total",
                                                "tool" => params.name.clone())
                                .increment(1);
                                cached_result_short_circuit = Some(cached_result);
                            }
                            gate_modified_arguments = modified_arguments;
                            metadata
                        }
                        mcpg_plugin_protocol::GateDecision::Deny {
                            http_status,
                            code,
                            message,
                            error_data,
                        } => {
                            return protocol_http_error(
                                http_status,
                                Some(request_id),
                                code,
                                message,
                                error_data,
                            );
                        }
                        mcpg_plugin_protocol::GateDecision::Challenge {
                            http_status,
                            code,
                            message,
                            challenge_data,
                        } => {
                            return protocol_http_error(
                                http_status,
                                Some(request_id),
                                code,
                                message,
                                Some(challenge_data),
                            );
                        }
                        mcpg_plugin_protocol::GateDecision::PendingApproval {
                            approval_id,
                            deadline_at,
                            summary,
                            target_notifiers,
                            metadata,
                        } => {
                            let outcome =
                                approvals::await_pending_approval(approvals::AwaitContext {
                                    approval_id,
                                    deadline_at,
                                    summary,
                                    target_notifiers,
                                    gate_metadata: metadata,
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    tool_name: params.name.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    arguments: params.arguments.clone(),
                                    registry: &self.approval_registry,
                                    plugin_registry: &self.plugin_registry,
                                })
                                .await;
                            match outcome {
                                approvals::AwaitOutcome::Approved { .. } => None,
                                approvals::AwaitOutcome::Denied {
                                    http_status,
                                    code,
                                    message,
                                } => {
                                    return protocol_http_error(
                                        http_status,
                                        Some(request_id),
                                        code,
                                        message,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                } else {
                    None
                };

                // A pre-dispatch cache gate supplied a result: route
                // it through the SAME post-dispatch pipeline a real
                // backend result takes (outputSchema enforcement →
                // post-dispatch tool_gate DLP/redaction chain → post
                // transform chain → metadata merge) before returning,
                // instead of shipping the untrusted cached value raw.
                if let Some(cached) = cached_result_short_circuit {
                    let cached_result = crate::protocol::ToolCallResult {
                        content: serde_json::from_value(
                            cached
                                .get("content")
                                .cloned()
                                .unwrap_or(serde_json::json!([])),
                        )
                        .unwrap_or_default(),
                        structured_content: cached.get("structuredContent").cloned(),
                        is_error: cached
                            .get("isError")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                        meta: cached.get("_meta").cloned(),
                    };
                    let cache_args = params.arguments.clone().unwrap_or(serde_json::json!({}));
                    return self
                        .finalize_tool_result(
                            request_context,
                            request_id,
                            &params.name,
                            &cache_args,
                            cached_result,
                            0,
                            &plugin_gate_meta,
                        )
                        .await;
                }
                // tool input validation failures are
                // tool-execution errors, not protocol errors.
                // MCP reserves -32602 for malformed
                // JSON-RPC envelopes / unknown tools; arguments
                // that fail inputSchema validation must come back
                // as a normal tool result with isError: true so
                // the model can self-correct.
                if let Err(validation_error) = self
                    .capability_registry
                    .validate_tool_arguments(&params.name, &params.arguments)
                {
                    warn!(
                        request_id = %request_context.request_id,
                        upstream_request_id = request_context.upstream_request_id.as_deref().unwrap_or(""),
                        identity_kind = request_context.identity.label(),
                        identity_trust = ?request_context.identity.trust_level(),
                        principal_id = request_context.identity.principal_id().unwrap_or(""),
                        tool_name = %params.name,
                        validation_stage = "pre_dispatch",
                        "tool input validation returned as tool execution error"
                    );
                    // The pre-dispatch gates already ran, so the result
                    // goes through the post-dispatch chain too: an audit
                    // trail that holds a pre record also gets its post record.
                    let refused = crate::protocol::ToolCallResult {
                        content: vec![crate::protocol::ToolContent::text(format!(
                            "Input validation failed for tool '{}': {}. Inspect the tool's inputSchema via tools/list and retry.",
                            params.name, validation_error,
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    };
                    let refused_args = params.arguments.clone().unwrap_or(serde_json::json!({}));
                    return self
                        .finalize_tool_result(
                            request_context,
                            request_id,
                            &params.name,
                            &refused_args,
                            refused,
                            0,
                            &plugin_gate_meta,
                        )
                        .await;
                }
                let backend = binding_type_label(&route);

                // Apply any pre-dispatch tool-gate argument rewrite
                // (Allow.modified_arguments) before the transform chain,
                // so transforms + the backend both observe the rewrite.
                let mut args_mutated = gate_modified_arguments.is_some();
                let execution_request = match gate_modified_arguments {
                    Some(modified) => {
                        let mut req = execution_request;
                        req.arguments = Some(modified);
                        req
                    }
                    None => execution_request,
                };

                // Pre-dispatch transform plugin chain
                let execution_request = if self.plugin_registry.has_transform_plugins() {
                    let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                        request_id: request_context.request_id.as_str().to_owned(),
                        session_id: request_context.session_id.clone(),
                        tool_name: params.name.clone(),
                        identity: plugin_identity_from_request(request_context),
                        transport: transport_label(&request_context.transport).to_owned(),
                        surface: "tool".to_owned(),
                    };
                    let current_args = execution_request
                        .arguments
                        .clone()
                        .unwrap_or(serde_json::json!({}));
                    let transformed = self
                        .plugin_registry
                        .apply_transforms_pre(&plugin_ctx, &current_args)
                        .await;
                    if transformed != current_args {
                        args_mutated = true;
                        let mut req = execution_request.clone();
                        req.arguments = Some(transformed);
                        req
                    } else {
                        execution_request
                    }
                } else {
                    execution_request
                };

                // Re-validate the FINAL arguments against the tool's
                // inputSchema when a gate/transform plugin rewrote
                // them (opt-in). The first validation only saw the
                // caller's original args; a plugin could otherwise
                // inject a payload that violates the published schema.
                if args_mutated
                    && self.revalidate_mutated_tool_arguments
                    && let Err(validation_error) = self
                        .capability_registry
                        .validate_tool_arguments(&params.name, &execution_request.arguments)
                {
                    warn!(
                        request_id = %request_context.request_id,
                        tool_name = %params.name,
                        validation_stage = "post_mutation",
                        "rewritten tool arguments failed inputSchema validation"
                    );
                    let refused = crate::protocol::ToolCallResult {
                        content: vec![crate::protocol::ToolContent::text(format!(
                            "Input validation failed for tool '{}' after a gate/transform plugin rewrote its arguments: {}.",
                            params.name, validation_error,
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    };
                    let refused_args = execution_request
                        .arguments
                        .clone()
                        .unwrap_or(serde_json::json!({}));
                    return self
                        .finalize_tool_result(
                            request_context,
                            request_id,
                            &params.name,
                            &refused_args,
                            refused,
                            0,
                            &plugin_gate_meta,
                        )
                        .await;
                }

                let binding_start = std::time::Instant::now();
                // Capture wall-clock at dispatch
                // start for the per-tool-call sample shipped to
                // the CP. The dispatcher uses Instant for
                // duration; chrono is for the sample's
                // started_at field which is informational.
                let binding_started_at = self
                    .tool_call_recorder
                    .records_tool_calls()
                    .then(chrono::Utc::now);

                // A call accepted as a task: create the task record and
                // return `resultType:"task"` immediately. The binding
                // runs in the background (tokio::spawn).
                if materialize_as_task {
                    // A task is owned by the request PRINCIPAL
                    // (SEP-2663), so it is pollable from any cluster
                    // replica via `tasks/get`; the per-replica synthetic
                    // session id is not portable. The delivery bus stays
                    // keyed on the synthetic `session_id` — the key a
                    // `subscriptions/listen` subscriber holds.
                    let Some(task_owner) = request_context.task_owner_key() else {
                        return protocol_http_error(
                            200,
                            Some(request_id),
                            -32603,
                            "a task needs a bound principal or session",
                            None,
                        );
                    };
                    let session_id = request_context
                        .session_id
                        .as_deref()
                        .unwrap_or("")
                        .to_owned();
                    // RESERVE the
                    // idempotency slot atomically before
                    // we create the task. The reservation
                    // TTL is bounded by the task's own
                    // wall-clock (`min(idempotency, task)`)
                    // so the dedupe handle never outlives
                    // the task it points at — closes the
                    // "key still valid but task is gone"
                    // footgun.
                    //
                    // The peek above already short-
                    // circuited the Completed / InFlight
                    // / Conflict cases; only the miss
                    // path falls through here. We still
                    // reserve atomically because peek →
                    // reserve isn't a single-atomic
                    // operation, and a concurrent retry
                    // can land between the two. Reserve
                    // observing Completed / InFlight /
                    // Conflict gets the same handling
                    // the peek would have given.
                    let task_ttl_ms = self.task_store.retention_policy().default_ttl_ms;
                    let task_idempotency_reservation: Option<()> = if idempotency_advertised
                        && let (Some(key), Some(scope), Some(request_hash)) = (
                            idempotency_key.as_deref(),
                            idempotency_scope.as_ref(),
                            idempotency_request_hash.as_ref(),
                        ) {
                        let ttl_override = std::time::Duration::from_millis(task_ttl_ms.max(1));
                        match self
                            .idempotency_store
                            .reserve_or_get(scope, key, request_hash, Some(ttl_override))
                            .await
                        {
                            Ok(idempotency::ReservationOutcome::Reserved { .. }) => Some(()),
                            Ok(idempotency::ReservationOutcome::InFlight { started_at }) => {
                                let _ = self
                                    .emit_idempotency_audit(
                                        "mcpg.idempotency.in_flight",
                                        request_context,
                                        &params.name,
                                        serde_json::json!({
                                            "key_hash": idempotency::key_hash_hex(key),
                                            "started_at": chrono::DateTime::<chrono::Utc>::from(
                                                started_at,
                                            )
                                            .to_rfc3339(),
                                            "method": "tasks/create",
                                        }),
                                    )
                                    .await;
                                metrics::counter!(
                                    "mcpg_idempotency_in_flight_total",
                                    "tool" => params.name.clone(),
                                    "method" => "tasks/create",
                                )
                                .increment(1);
                                return protocol_http_error(
                                    409,
                                    Some(request_id),
                                    idempotency::ERROR_CODE_IN_FLIGHT,
                                    "another task with this idempotency key is in progress",
                                    Some(serde_json::json!({"retry_after_ms": 1000u64})),
                                );
                            }
                            Ok(idempotency::ReservationOutcome::Completed {
                                outcome,
                                completed_at,
                            }) => {
                                // Truncation-marker path.
                                if outcome.payload_truncated {
                                    Some(())
                                } else {
                                    return self
                                        .build_tasks_create_replay_response(
                                            request_context,
                                            request_id,
                                            &params.name,
                                            key,
                                            outcome,
                                            completed_at,
                                        )
                                        .await;
                                }
                            }
                            Ok(idempotency::ReservationOutcome::Conflict {
                                stored_request_hash,
                            }) => {
                                let _ = self
                                    .emit_idempotency_audit(
                                        "mcpg.idempotency.body_mismatch",
                                        request_context,
                                        &params.name,
                                        serde_json::json!({
                                            "key_hash": idempotency::key_hash_hex(key),
                                            "stored_hash": hex::encode(stored_request_hash),
                                            "new_hash": hex::encode(request_hash),
                                            "method": "tasks/create",
                                        }),
                                    )
                                    .await;
                                metrics::counter!(
                                    "mcpg_idempotency_conflict_total",
                                    "tool" => params.name.clone(),
                                    "method" => "tasks/create",
                                )
                                .increment(1);
                                return protocol_http_error(
                                    422,
                                    Some(request_id),
                                    idempotency::ERROR_CODE_CONFLICT,
                                    "request body differs from the cached task request for this idempotency key",
                                    Some(serde_json::json!({
                                        "stored_hash": hex::encode(stored_request_hash),
                                    })),
                                );
                            }
                            Err(err) => {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    error = %err,
                                    "task idempotency reserve_or_get failed; proceeding without dedupe",
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let record = match self.task_store.create_task(
                        &task_owner,
                        request_id.clone(),
                        &params.name,
                    ) {
                        Ok(record) => record,
                        Err(task_store::TaskStoreError::QuotaExceeded { limit }) => {
                            return protocol_http_error(
                                200,
                                Some(request_id),
                                -32603,
                                format!(
                                    "the caller already owns the maximum concurrent tasks ({limit})"
                                ),
                                self.debug_error_data(
                                    request_context,
                                    "Cancel or wait for existing tasks before creating more",
                                ),
                            );
                        }
                        Err(err) => {
                            return protocol_http_error(
                                200,
                                Some(request_id),
                                -32603,
                                format!("failed to create task: {err}"),
                                None,
                            );
                        }
                    };
                    let task_id = record.task.task_id.clone();
                    // Emit initial working notification
                    self.deliver_task_status_notification(&session_id, &record.task);

                    // Spawn background execution
                    let task_store = self.task_store.clone();
                    let dispatcher = self.execution_dispatcher.clone();
                    let runtime_snap = route
                        .needs_runtime_snapshot()
                        .then(|| self.runtime_snapshot());
                    let pipeline_store = self.pipeline_store.clone();
                    let delivery_bus = self.delivery_bus.clone();
                    let route_clone = route.clone();
                    let mut exec_req = execution_request.clone();
                    let task_id_clone = task_id.clone();
                    let session_id_clone = session_id.clone();
                    let pipeline_id_for_task = exec_req.context.request_id.as_str().to_owned();
                    let session_id_for_spawn = session_id_clone.clone();
                    // The task's own cancellation token, owned by the
                    // task's owner key: `tasks/cancel` broadcasts that
                    // key, which every replica derives alike. The
                    // background run checks it at each step boundary.
                    let cancel_token = self.register_cancellation_token(
                        &task_id_clone,
                        Some(task_owner.as_str()),
                        request_context.identity.principal_id(),
                    );
                    exec_req.cancellation_token = Some(cancel_token.clone());
                    let tokens_registry = self.cancellation_tokens.clone();
                    let task_id_for_cleanup = task_id_clone.clone();
                    // Hold the concurrency permit for the
                    // lifetime of the BACKGROUND task. The handler
                    // returns CreateTaskResult immediately, so the
                    // permit must move into the spawn — otherwise
                    // the in-flight slot frees the instant the task
                    // is accepted, defeating the concurrency cap.
                    #[cfg(feature = "governance-quotas")]
                    let quota_permit_for_task = _quota_permit;
                    // Capture state moved into the
                    // spawn for the per-call sample. Each is
                    // owned because the spawn closure outlives
                    // the dispatch caller.
                    let recorder_for_task = self.tool_call_recorder.clone();
                    let plugin_id_for_task = backend.to_owned();
                    let tool_name_for_task = params.name.clone();
                    // Capture the schema registry so the spawned
                    // task can enforce the tool's outputSchema on a
                    // suspending-pipeline result before it becomes
                    // the task's terminal envelope.
                    let capability_registry_for_task =
                        std::sync::Arc::clone(&self.capability_registry);
                    let request_id_for_task = request_context.request_id.as_str().to_owned();
                    let caller_subject_for_task =
                        request_context.identity.principal_id().map(str::to_owned);
                    // Capture payload-capture
                    // entitlement + serialize args at spawn time
                    // (not at join site — by the time the closure
                    // resumes the runtime config could have
                    // hot-reloaded; we want the value as of when
                    // the call was admitted). Args are cloned
                    // here whether capture is on or off, but only
                    // serialized inside the spawn — so the cost
                    // when capture is off is one Value clone +
                    // one bool, dropped when the closure ends.
                    let payload_capture_for_task =
                        self.tool_call_recorder.payload_capture_enabled();
                    let args_for_task = if payload_capture_for_task {
                        Some(
                            execution_request
                                .arguments
                                .clone()
                                .unwrap_or_else(|| serde_json::json!({})),
                        )
                    } else {
                        None
                    };
                    // Task-store owner key + the MRTR resume codec,
                    // captured into the spawn so a suspending pipeline
                    // can record its `requestState` + `inputRequests` on
                    // the task (SEP-2663 `input_required`).
                    let task_owner_for_spawn = task_owner.clone();
                    let request_state_codec_for_task = self
                        .shared_services
                        .load_full()
                        .map(|s| s.request_state_codec.clone());
                    let owner_principal_for_task =
                        request_context.identity.principal_id().map(str::to_owned);
                    let usage_charger_for_task = self.usage_charger();
                    tokio::spawn(async move {
                        let _cleanup =
                            scopeguard_cancellation(tokens_registry, task_id_for_cleanup);
                        // Drop the concurrency permit only when the
                        // background task finishes (any exit arm),
                        // not when the handler returned.
                        #[cfg(feature = "governance-quotas")]
                        let _task_quota_permit = quota_permit_for_task;
                        // Dispatch-only wall-clock (not the
                        // request-to-completion span — tasks
                        // can sit in the queue for seconds).
                        let dispatch_started_at = chrono::Utc::now();
                        let dispatch_start = std::time::Instant::now();
                        if cancel_token.is_cancelled() {
                            // Cancellation arrived before execution started.
                            let _ = task_store.store_task_terminal(
                                &task_id_clone,
                                crate::protocol::TaskStatus::Cancelled,
                                task_store::TerminalEnvelope::cancelled(Some(
                                    "cancelled before execution".to_owned(),
                                )),
                            );
                            return;
                        }
                        let result = if matches!(
                            &route_clone,
                            BackendInvocationRoute::Pipeline { .. }
                        ) {
                            let profile = match &route_clone {
                                BackendInvocationRoute::Pipeline { profile } => profile.clone(),
                                _ => unreachable!(),
                            };
                            match dispatcher.execute_pipeline(
                                &profile,
                                &exec_req,
                                &*pipeline_store,
                                pipeline_store::PipelineSurface::Tool,
                            ) {
                                execution::PipelineOutcome::Complete(mut r) => {
                                    // strict outputSchema parity with the
                                    // direct path: fail the task closed if a
                                    // declared outputSchema is violated.
                                    if !r.is_error
                                        && let Err(validation_err) = capability_registry_for_task
                                            .validate_structured_output(
                                                &tool_name_for_task,
                                                &r.structured_content,
                                            )
                                    {
                                        warn!(
                                            task_id = %task_id_clone,
                                            tool_name = %tool_name_for_task,
                                            "structuredContent failed outputSchema validation, failing task"
                                        );
                                        r.structured_content = None;
                                        r.is_error = true;
                                        r.content.push(crate::protocol::ToolContent::text(format!(
                                                        "tool '{tool_name_for_task}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}"
                                                    )));
                                    }
                                    r
                                }
                                execution::PipelineOutcome::Suspended(server_request) => {
                                    // Tag the suspended pipeline with the
                                    // owning task so the resume handler can
                                    // find it.
                                    if let Ok(Some(mut state)) =
                                        pipeline_store.load_pipeline(&pipeline_id_for_task)
                                    {
                                        state.related_task_id = Some(task_id_clone.clone());
                                        let _ = pipeline_store.save_pipeline(&state);
                                    }

                                    // A task awaiting input surfaces the
                                    // outstanding request on `tasks/get` via
                                    // `inputRequests`, and the client answers
                                    // via `tasks/update` (SEP-2663). Encode the
                                    // same principal-bound MRTR `requestState`
                                    // the inline `InputRequiredResult` would
                                    // carry and the `inputRequests` map, and
                                    // record both on the task; `tasks/update`
                                    // feeds the answers back through the MRTR
                                    // resume codec.
                                    let fail_task = |message: String| {
                                        let _ = task_store.store_task_terminal(
                                            &task_id_clone,
                                            crate::protocol::TaskStatus::Failed,
                                            task_store::TerminalEnvelope::error(JsonRpcErrorBody {
                                                code: -32603,
                                                message,
                                                data: None,
                                            }),
                                        );
                                    };
                                    let Some(codec) = request_state_codec_for_task.as_ref() else {
                                        fail_task("MRTR codec is not installed".to_owned());
                                        return;
                                    };
                                    let owner_aad = crate::protocol::v_2026_07_28::dispatch::request_state::owner_aad(
                                            owner_principal_for_task.as_deref(),
                                        );
                                    let request_state = match codec
                                        .encode(pipeline_id_for_task.as_bytes(), &owner_aad)
                                        .await
                                    {
                                        Ok(s) => s,
                                        Err(error) => {
                                            fail_task(format!(
                                                "MRTR requestState encode failed: {error}"
                                            ));
                                            return;
                                        }
                                    };
                                    let input_requests =
                                        match input_requests_from_server_request(&server_request) {
                                            Ok(m) => m,
                                            Err(error) => {
                                                fail_task(error);
                                                return;
                                            }
                                        };
                                    let _ = task_store.set_task_awaiting_input(
                                        &task_id_clone,
                                        &task_owner_for_spawn,
                                        request_state,
                                        input_requests,
                                    );
                                    // A status ping tells a
                                    // `subscriptions/listen` subscriber the
                                    // task awaits input without an extra
                                    // `tasks/get`.
                                    if let Ok(record) =
                                        task_store.get_task(&task_id_clone, &task_owner_for_spawn)
                                    {
                                        let msg = pipeline_store::DeliveryMessage {
                                            kind: pipeline_store::DeliveryKind::Notification,
                                            jsonrpc_message: serde_json::to_value(
                                                task_status_notification(&record.task),
                                            )
                                            .expect("task status notification serialized"),
                                        };
                                        let _ =
                                            delivery_bus.publish(&session_id_for_spawn, msg).await;
                                    }
                                    return;
                                }
                                execution::PipelineOutcome::SuspendedMulti(_) => {
                                    // A `gather` step asks for several inputs
                                    // at once; a task records one input
                                    // request.
                                    let _ = task_store.store_task_terminal(
                                        &task_id_clone,
                                        crate::protocol::TaskStatus::Failed,
                                        task_store::TerminalEnvelope::error(JsonRpcErrorBody {
                                            code: -32603,
                                            message: "a gather step that asks for several inputs \
                                                          at once cannot run as a task"
                                                .to_owned(),
                                            data: None,
                                        }),
                                    );
                                    return;
                                }
                            }
                        } else {
                            dispatcher.dispatch_tool_call(route_clone, &exec_req, runtime_snap)
                        };
                        let mut result = result;
                        usage_charger_for_task
                            .charge(&exec_req.context, &tool_name_for_task, &mut result)
                            .await;

                        // Record the per-call sample
                        // for the task-augmented dispatch path.
                        // The pipeline-Suspended branch above
                        // returns early without producing a
                        // `result` — that's correct, since
                        // Suspended isn't a terminal outcome.
                        let dispatch_duration = dispatch_start.elapsed();
                        let (sample_outcome, error_code, error_hash) =
                            cp_metrics::classify_result(&result);
                        // The args were
                        // cloned at spawn time (above); serialize
                        // here under the cap, then serialize the
                        // result the same way. `args_for_task`
                        // is `Some(...)` iff capture was enabled
                        // when the spawn was admitted.
                        let (req_payload, req_truncated) =
                            if let Some(args) = args_for_task.as_ref() {
                                cp_metrics::serialize_payload(args)
                            } else {
                                (None, false)
                            };
                        let (resp_payload, resp_truncated) = if payload_capture_for_task {
                            cp_metrics::serialize_result_payload(&result)
                        } else {
                            (None, false)
                        };
                        if req_truncated || resp_truncated {
                            cp_metrics::note_truncation("task_augmented");
                        }
                        recorder_for_task.record(cp_metrics::ToolCallSample {
                            plugin_id: cp_metrics::plugin_id_from_kind(&plugin_id_for_task),
                            tool_name: tool_name_for_task,
                            binding_id: None,
                            started_at: dispatch_started_at,
                            duration: dispatch_duration,
                            outcome: sample_outcome,
                            error_code,
                            error_hash,
                            request_id: Some(request_id_for_task),
                            caller_subject: caller_subject_for_task,
                            request_payload: req_payload,
                            response_payload: resp_payload,
                            payload_truncated: req_truncated || resp_truncated,
                        });

                        // persist the exact JSON-RPC
                        // envelope the wrapped `tools/call` would
                        // have returned. Per the tools spec an
                        // `isError: true` ToolCallResult is still
                        // a successful JSON-RPC response, so both
                        // error-free and tool-execution-error
                        // outcomes are wrapped as Success here.
                        let is_error = result.is_error;
                        let status = if is_error {
                            crate::protocol::TaskStatus::Failed
                        } else {
                            crate::protocol::TaskStatus::Completed
                        };
                        let result_json =
                            serde_json::to_value(&result).unwrap_or(serde_json::json!({}));
                        let envelope = task_store::TerminalEnvelope::success(result_json);
                        let _ = task_store.store_task_terminal(&task_id_clone, status, envelope);
                        // Emit the terminal status notification on the
                        // delivery bus. The task is owned by
                        // `task_owner_for_spawn`; the bus stays keyed on
                        // the synthetic `session_id`.
                        if let Ok(final_record) =
                            task_store.get_task(&task_id_clone, &task_owner_for_spawn)
                        {
                            let msg = pipeline_store::DeliveryMessage {
                                kind: pipeline_store::DeliveryKind::Notification,
                                jsonrpc_message: serde_json::to_value(task_status_notification(
                                    &final_record.task,
                                ))
                                .expect("task status notification serialized"),
                            };
                            let _ = delivery_bus.publish(&session_id_clone, msg).await;
                        }
                    });

                    // Return `resultType:"task"` immediately.
                    let create_envelope =
                        serde_json::to_value(CreateTaskResult::new(wire_task(&record.task)))
                            .expect("create task result serialized");
                    // COMPLETE the idempotency record with the task
                    // handle. The envelope is slim — the task id and its
                    // owner key — because the task store is the
                    // durability boundary for the eventual result. A
                    // replay fetches the live status from the task store
                    // and assembles a fresh `CreateTaskResult` (see
                    // `build_tasks_create_replay_response`).
                    if task_idempotency_reservation.is_some()
                        && let (Some(key), Some(scope)) =
                            (idempotency_key.as_deref(), idempotency_scope.as_ref())
                    {
                        let cached = idempotency::CachedOutcome {
                            // The persisted `session_id` key holds the
                            // task-store OWNER key the replay re-fetches
                            // with.
                            envelope: serde_json::json!({
                                "task_id": task_id,
                                "session_id": task_owner,
                            }),
                            original_request_id: request_id.clone(),
                            original_correlation_id: request_context.request_id.as_str().to_owned(),
                            replay_count: 0,
                            payload_truncated: false,
                        };
                        if let Err(err) = self.idempotency_store.complete(scope, key, cached).await
                        {
                            warn!(
                                request_id = %request_context.request_id,
                                tool_name = %params.name,
                                error = %err,
                                "task idempotency complete failed; replay will not be served from cache",
                            );
                        }
                    }
                    return ProtocolHttpResponse {
                        http_status: 200,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: request_id,
                            result: create_envelope,
                        }),
                    };
                }

                // Check if this is a pipeline with suspending steps
                let is_suspendable_pipeline = matches!(
                    &route,
                    BackendInvocationRoute::Pipeline { profile }
                    if self.execution_dispatcher.pipeline_has_suspending_steps(profile)
                );

                if is_suspendable_pipeline {
                    let profile = match &route {
                        BackendInvocationRoute::Pipeline { profile } => profile.clone(),
                        _ => unreachable!(),
                    };
                    let outcome = self.execution_dispatcher.execute_pipeline(
                        &profile,
                        &execution_request,
                        &*self.pipeline_store,
                        pipeline_store::PipelineSurface::Tool,
                    );
                    let binding_elapsed = binding_start.elapsed().as_secs_f64();
                    match outcome {
                        execution::PipelineOutcome::Complete(mut result) => {
                            let outcome_label = if result.is_error { "error" } else { "success" };
                            metrics::counter!(
                                "mcpg_binding_executions_total",
                                "backend_name" => params.name.clone(),
                                "backend" => backend.clone(),
                                "outcome" => outcome_label,
                            )
                            .increment(1);
                            metrics::histogram!(
                                "mcpg_binding_execution_duration_seconds",
                                "backend_name" => params.name.clone(),
                                "backend" => backend.clone(),
                                "outcome" => outcome_label,
                            )
                            .record(binding_elapsed);
                            // strict outputSchema parity with the direct
                            // path: a suspending pipeline that declared an
                            // outputSchema must still return conforming
                            // structuredContent or the call fails closed.
                            if !result.is_error
                                && let Err(validation_err) =
                                    self.capability_registry.validate_structured_output(
                                        &params.name,
                                        &result.structured_content,
                                    )
                            {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    "structuredContent failed outputSchema validation, failing tool"
                                );
                                result.structured_content = None;
                                result.is_error = true;
                                result.content.push(crate::protocol::ToolContent::text(
                                                format!(
                                                    "tool '{}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}",
                                                    params.name,
                                                ),
                                            ));
                            }
                            // Post-dispatch plugin gate chain (pipeline path)
                            let final_result = result;
                            let execution_ms = (binding_elapsed * 1000.0) as u64;
                            // A post-dispatch gate may rewrite the result via
                            // Allow.modified_result. Captured here,
                            // applied below before the result transform chain.
                            let mut gate_modified_result: Option<serde_json::Value> = None;
                            // Enter even with no gates loaded when the operator
                            // wants `mcpg.tool.call.completed` records — the
                            // empty-chain branch owns that emission.
                            let has_gates = self.plugin_registry.has_tool_gate_plugins();
                            if has_gates || self.plugin_registry.emits_tool_call_completed() {
                                let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    session_id: request_context.session_id.clone(),
                                    tool_name: params.name.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    transport: transport_label(&request_context.transport)
                                        .to_owned(),
                                    surface: "tool".to_owned(),
                                };
                                // With no gates the chain never reads the result;
                                // skip the serialization on the audit-only path.
                                let result_json = if has_gates {
                                    serde_json::to_value(&final_result)
                                        .unwrap_or(serde_json::json!({}))
                                } else {
                                    serde_json::Value::Null
                                };
                                match self
                                    .plugin_registry
                                    .evaluate_tool_gates_post(
                                        &plugin_ctx,
                                        execution_request
                                            .arguments
                                            .as_ref()
                                            .unwrap_or(&serde_json::json!({})),
                                        &result_json,
                                        execution_ms,
                                        request_context.upstream_request_id.as_deref(),
                                    )
                                    .await
                                {
                                    mcpg_plugin_protocol::GateDecision::Allow {
                                        modified_result,
                                        ..
                                    } => {
                                        gate_modified_result = modified_result;
                                    }
                                    mcpg_plugin_protocol::GateDecision::Deny {
                                        http_status,
                                        code,
                                        message,
                                        error_data,
                                    } => {
                                        return protocol_http_error(
                                            http_status,
                                            Some(request_id),
                                            code,
                                            message,
                                            error_data,
                                        );
                                    }
                                    mcpg_plugin_protocol::GateDecision::Challenge {
                                        http_status,
                                        code,
                                        message,
                                        challenge_data,
                                    } => {
                                        return protocol_http_error(
                                            http_status,
                                            Some(request_id),
                                            code,
                                            message,
                                            Some(challenge_data),
                                        );
                                    }
                                    mcpg_plugin_protocol::GateDecision::PendingApproval {
                                        approval_id,
                                        ..
                                    } => {
                                        warn!(
                                            request_id = %request_context.request_id,
                                            tool_name = %params.name,
                                            approval_id = %approval_id,
                                            "post-dispatch tool gate returned PendingApproval; treating as deny (approvals only valid pre-dispatch)",
                                        );
                                        return protocol_http_error(
                                            500,
                                            Some(request_id),
                                            -32603,
                                            format!(
                                                "tool '{}' post-dispatch gate returned invalid PendingApproval decision",
                                                params.name,
                                            ),
                                            None,
                                        );
                                    }
                                }
                            }
                            // Post-dispatch result transform chain (pipeline path).
                            // A post-gate Allow.modified_result replaces the result
                            // wholesale; otherwise serialize the backend result.
                            let final_result_json = match gate_modified_result {
                                Some(modified) => modified,
                                None => serde_json::to_value(final_result)
                                    .expect("tool call result serialized"),
                            };
                            let final_result_json = if self.plugin_registry.has_transform_plugins()
                            {
                                let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    session_id: request_context.session_id.clone(),
                                    tool_name: params.name.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    transport: transport_label(&request_context.transport)
                                        .to_owned(),
                                    surface: "tool".to_owned(),
                                };
                                self.plugin_registry
                                    .apply_transforms_post(&plugin_ctx, &final_result_json)
                                    .await
                            } else {
                                final_result_json
                            };
                            ProtocolHttpResponse {
                                http_status: 200,
                                response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: request_id,
                                    result: merge_plugin_gate_meta(
                                        final_result_json,
                                        &plugin_gate_meta,
                                    ),
                                }),
                            }
                        }
                        execution::PipelineOutcome::Suspended(server_request) => {
                            metrics::counter!(
                                "mcpg_binding_executions_total",
                                "backend_name" => params.name.clone(),
                                "backend" => backend.clone(),
                                "outcome" => "suspended",
                            )
                            .increment(1);
                            metrics::histogram!(
                                "mcpg_binding_execution_duration_seconds",
                                "backend_name" => params.name.clone(),
                                "backend" => backend.clone(),
                                "outcome" => "suspended",
                            )
                            .record(binding_elapsed);
                            // Patch the original JSON-RPC request id onto the
                            // just-suspended row. Version-guarded so this second
                            // write cannot resurrect a row a concurrent reaper
                            // deleted nor clobber one a concurrent claim/resume has
                            // already advanced.
                            let pipeline_id_str =
                                execution_request.context.request_id.as_str().to_owned();
                            if let Ok(Some(state)) =
                                self.pipeline_store.load_pipeline(&pipeline_id_str)
                            {
                                let _ = self.pipeline_store.set_original_jsonrpc_id_if_version(
                                    &pipeline_id_str,
                                    state.state_version,
                                    &request_id,
                                );
                            }
                            // MRTR: the suspension answers inline with an
                            // `InputRequiredResult`.
                            self.build_input_required_response(
                                request_context,
                                request_id,
                                server_request,
                                &pipeline_id_str,
                            )
                            .await
                        }
                        // SEP-2322 multi-entry MRTR — a `gather` step
                        // suspended on several inputs at once, answered
                        // as one `InputRequiredResult.inputRequests` map.
                        execution::PipelineOutcome::SuspendedMulti(server_requests) => {
                            metrics::counter!(
                                "mcpg_binding_executions_total",
                                "backend_name" => params.name.clone(),
                                "backend" => backend.clone(),
                                "outcome" => "suspended_multi",
                            )
                            .increment(1);
                            let pipeline_id_str =
                                execution_request.context.request_id.as_str().to_owned();
                            // Version-guarded patch (see the single-suspend arm):
                            // never resurrect a reaped row or clobber an advanced one.
                            if let Ok(Some(state)) =
                                self.pipeline_store.load_pipeline(&pipeline_id_str)
                            {
                                let _ = self.pipeline_store.set_original_jsonrpc_id_if_version(
                                    &pipeline_id_str,
                                    state.state_version,
                                    &request_id,
                                );
                            }
                            self.build_input_required_response_multi(
                                request_context,
                                request_id,
                                server_requests,
                                &pipeline_id_str,
                            )
                            .await
                        }
                    }
                } else {
                    // Route through the
                    // streaming dispatcher when the call is
                    // eligible. LLM bindings always stream
                    // when a progressToken is set; non-LLM
                    // bindings (HTTP today, more later)
                    // stream only when the caller opted in
                    // via progressToken AND the route shape
                    // points at a backend that overrides
                    // BackendPlugin::execute_streaming. The
                    // gate factors into is_streaming_route
                    // so adding NATS/Kafka/SQL Progress
                    // support is one match-arm flip.
                    let is_streaming_route = matches!(
                        route,
                        crate::backends::BackendInvocationRoute::LlmRequest { .. }
                            | crate::backends::BackendInvocationRoute::NetworkJsonCall { .. }
                            | crate::backends::BackendInvocationRoute::NetworkQueryCall { .. }
                    );
                    let stream_eligible = is_streaming_route
                        && execution_request.progress_token.is_some()
                        && execution_request.context.session_id.is_some();
                    // Idempotency RESERVE — atomic
                    // claim of the slot just before
                    // dispatch. Streaming-eligible
                    // calls are included: the gateway accumulates
                    // the assembled `BackendResponse`
                    // when the stream completes and
                    // caches it as a unary envelope.
                    // Hits found here are the result
                    // of a peek-miss-then-record-
                    // appeared race; we still honour
                    // the second-writer-wins contract.
                    let idempotency_reserved: bool = if idempotency_advertised
                        && let (Some(key), Some(scope), Some(request_hash)) = (
                            idempotency_key.as_deref(),
                            idempotency_scope.as_ref(),
                            idempotency_request_hash.as_ref(),
                        ) {
                        match self
                            .idempotency_store
                            .reserve_or_get(scope, key, request_hash, None)
                            .await
                        {
                            Ok(idempotency::ReservationOutcome::Reserved { .. }) => true,
                            Ok(idempotency::ReservationOutcome::InFlight { started_at }) => {
                                let _ = self
                                    .emit_idempotency_audit(
                                        "mcpg.idempotency.in_flight",
                                        request_context,
                                        &params.name,
                                        serde_json::json!({
                                            "key_hash": idempotency::key_hash_hex(key),
                                            "started_at": chrono::DateTime::<chrono::Utc>::from(
                                                started_at,
                                            )
                                            .to_rfc3339(),
                                        }),
                                    )
                                    .await;
                                metrics::counter!(
                                    "mcpg_idempotency_in_flight_total",
                                    "tool" => params.name.clone(),
                                )
                                .increment(1);
                                return protocol_http_error(
                                    409,
                                    Some(request_id),
                                    idempotency::ERROR_CODE_IN_FLIGHT,
                                    "another request with this idempotency key is in progress",
                                    Some(serde_json::json!({"retry_after_ms": 1000u64})),
                                );
                            }
                            Ok(idempotency::ReservationOutcome::Completed {
                                outcome,
                                completed_at,
                            }) => {
                                // A
                                // truncation-marker
                                // record at this point
                                // means a previous
                                // assembly was over the
                                // payload cap. Treat
                                // as miss so this call
                                // executes fresh; the
                                // resulting COMPLETE
                                // overwrites the
                                // marker (LWW).
                                if outcome.payload_truncated {
                                    true
                                } else {
                                    return self
                                        .build_idempotency_replay_response(
                                            request_context,
                                            request_id,
                                            &params.name,
                                            key,
                                            outcome,
                                            completed_at,
                                        )
                                        .await;
                                }
                            }
                            Ok(idempotency::ReservationOutcome::Conflict {
                                stored_request_hash,
                            }) => {
                                let _ = self
                                    .emit_idempotency_audit(
                                        "mcpg.idempotency.body_mismatch",
                                        request_context,
                                        &params.name,
                                        serde_json::json!({
                                            "key_hash": idempotency::key_hash_hex(key),
                                            "stored_hash": hex::encode(stored_request_hash),
                                            "new_hash": hex::encode(request_hash),
                                        }),
                                    )
                                    .await;
                                metrics::counter!(
                                    "mcpg_idempotency_conflict_total",
                                    "tool" => params.name.clone(),
                                )
                                .increment(1);
                                return protocol_http_error(
                                    422,
                                    Some(request_id),
                                    idempotency::ERROR_CODE_CONFLICT,
                                    "request body differs from cached request for this idempotency key",
                                    Some(serde_json::json!({
                                        "stored_hash": hex::encode(stored_request_hash),
                                    })),
                                );
                            }
                            Err(err) => {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    error = %err,
                                    "idempotency reserve_or_get failed; proceeding without dedupe",
                                );
                                false
                            }
                        }
                    } else {
                        false
                    };
                    let snapshot = route
                        .needs_runtime_snapshot()
                        .then(|| self.runtime_snapshot());
                    // A federated call whose caller has no stored IdP
                    // sign-in may answer with a link that stores it
                    // (URL-mode elicitation), when the client declared
                    // URL mode and no idempotency record awaits the
                    // call's result.
                    let may_offer_link = !idempotency_reserved
                        && matches!(
                            route,
                            crate::backends::BackendInvocationRoute::Federated { .. }
                        )
                        && execution_request
                            .client_capabilities
                            .supports_elicitation_url()
                        && request_context.connect_link.open();
                    let mut result = if stream_eligible {
                        self.execution_dispatcher
                            .dispatch_tool_call_streaming(route, &execution_request, snapshot)
                            .await
                    } else {
                        self.execution_dispatcher
                            .dispatch_tool_call_async(route, &execution_request, snapshot)
                            .await
                    };
                    self.usage_charger()
                        .charge(request_context, &params.name, &mut result)
                        .await;
                    if may_offer_link
                        && let Some(elicitation) = request_context.connect_link.take_offered()
                        && let Some(response) = self.connect_link_response(
                            request_context,
                            request_id.clone(),
                            &params.name,
                            &elicitation,
                        )
                    {
                        return response;
                    }
                    let binding_duration = binding_start.elapsed();
                    let binding_elapsed = binding_duration.as_secs_f64();
                    let outcome = if result.is_error { "error" } else { "success" };
                    metrics::counter!(
                        "mcpg_binding_executions_total",
                        "backend_name" => params.name.clone(),
                        "backend" => backend.clone(),
                        "outcome" => outcome,
                    )
                    .increment(1);
                    metrics::histogram!(
                        "mcpg_binding_execution_duration_seconds",
                        "backend_name" => params.name.clone(),
                        "backend" => backend.clone(),
                        "outcome" => outcome,
                    )
                    .record(binding_elapsed);

                    // Ship per-call sample to CP via
                    // the registered recorder (no-op when no CP
                    // is attached). Privacy: only names + agg
                    // stats; no args/responses; error message
                    // travels as a BLAKE3 hash.
                    if let Some(started_at) = binding_started_at {
                        let (sample_outcome, error_code, error_hash) =
                            cp_metrics::classify_result(&result);
                        // Optional payload capture
                        // (Enterprise opt-in). Off by default;
                        // gated by `capture_payloads` runtime flag
                        // which the cp-attached integrator sets
                        // when license entitles. Bytes are JSON-
                        // serialized under PAYLOAD_CAPTURE_CAP_BYTES;
                        // CP encrypts at ingest.
                        let (req_payload, req_truncated, resp_payload, resp_truncated) =
                            if self.tool_call_recorder.payload_capture_enabled() {
                                let (req, req_t) = execution_request
                                    .arguments
                                    .as_ref()
                                    .map(cp_metrics::serialize_payload)
                                    .unwrap_or((None, false));
                                let (resp, resp_t) = cp_metrics::serialize_result_payload(&result);
                                (req, req_t, resp, resp_t)
                            } else {
                                (None, false, None, false)
                            };
                        if req_truncated || resp_truncated {
                            cp_metrics::note_truncation("direct");
                        }
                        self.tool_call_recorder.record(cp_metrics::ToolCallSample {
                            plugin_id: cp_metrics::plugin_id_from_kind(&backend),
                            tool_name: params.name.clone(),
                            binding_id: None,
                            started_at,
                            duration: binding_duration,
                            outcome: sample_outcome,
                            error_code,
                            error_hash,
                            request_id: Some(request_context.request_id.as_str().to_owned()),
                            caller_subject: request_context
                                .identity
                                .principal_id()
                                .map(str::to_owned),
                            request_payload: req_payload,
                            response_payload: resp_payload,
                            payload_truncated: req_truncated || resp_truncated,
                        });
                    }
                    // strict outputSchema: MCP requires a
                    // tool that declared an `outputSchema` to return
                    // conforming structured output. Non-conforming
                    // structuredContent fails the call with isError: true
                    // so the contract violation is visible and
                    // self-correctable rather than silently stripped.
                    if !result.is_error
                        && let Err(validation_err) = self
                            .capability_registry
                            .validate_structured_output(&params.name, &result.structured_content)
                    {
                        warn!(
                            request_id = %request_context.request_id,
                            tool_name = %params.name,
                            "structuredContent failed outputSchema validation, failing tool"
                        );
                        result.structured_content = None;
                        result.is_error = true;
                        result.content.push(crate::protocol::ToolContent::text(
                                            format!(
                                                "tool '{}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}",
                                                params.name,
                                            ),
                                        ));
                    }
                    // Post-dispatch plugin gate chain (direct path)
                    let final_result = result;
                    let execution_ms = (binding_elapsed * 1000.0) as u64;
                    // A post-dispatch gate may rewrite the result via
                    // Allow.modified_result. Captured here,
                    // applied below before the result transform chain.
                    let mut gate_modified_result: Option<serde_json::Value> = None;
                    // Enter even with no gates loaded when the operator
                    // wants `mcpg.tool.call.completed` records — the
                    // empty-chain branch owns that emission.
                    let has_gates = self.plugin_registry.has_tool_gate_plugins();
                    if has_gates || self.plugin_registry.emits_tool_call_completed() {
                        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                            request_id: request_context.request_id.as_str().to_owned(),
                            session_id: request_context.session_id.clone(),
                            tool_name: params.name.clone(),
                            identity: plugin_identity_from_request(request_context),
                            transport: transport_label(&request_context.transport).to_owned(),
                            surface: "tool".to_owned(),
                        };
                        // With no gates the chain never reads the result;
                        // skip the serialization on the audit-only path.
                        let result_json = if has_gates {
                            serde_json::to_value(&final_result).unwrap_or(serde_json::json!({}))
                        } else {
                            serde_json::Value::Null
                        };
                        match self
                            .plugin_registry
                            .evaluate_tool_gates_post(
                                &plugin_ctx,
                                execution_request
                                    .arguments
                                    .as_ref()
                                    .unwrap_or(&serde_json::json!({})),
                                &result_json,
                                execution_ms,
                                request_context.upstream_request_id.as_deref(),
                            )
                            .await
                        {
                            mcpg_plugin_protocol::GateDecision::Allow {
                                modified_result, ..
                            } => {
                                gate_modified_result = modified_result;
                            }
                            mcpg_plugin_protocol::GateDecision::Deny {
                                http_status,
                                code,
                                message,
                                error_data,
                            } => {
                                return protocol_http_error(
                                    http_status,
                                    Some(request_id),
                                    code,
                                    message,
                                    error_data,
                                );
                            }
                            mcpg_plugin_protocol::GateDecision::Challenge {
                                http_status,
                                code,
                                message,
                                challenge_data,
                            } => {
                                return protocol_http_error(
                                    http_status,
                                    Some(request_id),
                                    code,
                                    message,
                                    Some(challenge_data),
                                );
                            }
                            mcpg_plugin_protocol::GateDecision::PendingApproval {
                                approval_id,
                                ..
                            } => {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    approval_id = %approval_id,
                                    "post-dispatch tool gate returned PendingApproval; treating as deny (approvals only valid pre-dispatch)",
                                );
                                return protocol_http_error(
                                    500,
                                    Some(request_id),
                                    -32603,
                                    format!(
                                        "tool '{}' post-dispatch gate returned invalid PendingApproval decision",
                                        params.name,
                                    ),
                                    None,
                                );
                            }
                        }
                    }
                    // Post-dispatch result transform chain (direct path).
                    // A post-gate Allow.modified_result replaces the result
                    // wholesale; otherwise serialize the backend result.
                    let final_result_json = match gate_modified_result {
                        Some(modified) => modified,
                        None => {
                            serde_json::to_value(final_result).expect("tool call result serialized")
                        }
                    };
                    let final_result_json = if self.plugin_registry.has_transform_plugins() {
                        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                            request_id: request_context.request_id.as_str().to_owned(),
                            session_id: request_context.session_id.clone(),
                            tool_name: params.name.clone(),
                            identity: plugin_identity_from_request(request_context),
                            transport: transport_label(&request_context.transport).to_owned(),
                            surface: "tool".to_owned(),
                        };
                        self.plugin_registry
                            .apply_transforms_post(&plugin_ctx, &final_result_json)
                            .await
                    } else {
                        final_result_json
                    };
                    let final_envelope =
                        merge_plugin_gate_meta(final_result_json, &plugin_gate_meta);
                    // Idempotency COMPLETE — persist
                    // the terminal envelope for replay.
                    // Best-effort: a store failure
                    // here MUST NOT fail the outer
                    // call — the request DID succeed,
                    // and the next retry will simply
                    // re-execute (the worst case is
                    // we miss a dedupe, not a
                    // double-dispatch).
                    //
                    // When this
                    // call streamed, the assembled
                    // envelope sitting in
                    // `final_envelope` may exceed the
                    // gateway's payload cap
                    // (`PAYLOAD_CAPTURE_CAP_BYTES`,
                    // 256 KiB). Caching an over-cap
                    // envelope risks unbounded KV
                    // memory growth, so we measure
                    // before persisting; on overflow
                    // we log a warn, emit a dedicated
                    // audit event, and SKIP caching
                    // (the next retry will execute
                    // fresh against the upstream).
                    if idempotency_reserved
                        && let (Some(key), Some(scope)) =
                            (idempotency_key.as_deref(), idempotency_scope.as_ref())
                    {
                        let envelope_bytes = serde_json::to_vec(&final_envelope).map(|b| b.len());
                        let over_cap = envelope_bytes
                            .as_ref()
                            .ok()
                            .map(|n| *n > cp_metrics::PAYLOAD_CAPTURE_CAP_BYTES)
                            .unwrap_or(false);
                        if over_cap {
                            let bytes_for_audit = envelope_bytes.unwrap_or(0);
                            warn!(
                                request_id = %request_context.request_id,
                                tool_name = %params.name,
                                bytes = bytes_for_audit,
                                cap = cp_metrics::PAYLOAD_CAPTURE_CAP_BYTES,
                                "idempotency assembled envelope exceeds cap; persisting truncation marker (next retry will execute fresh)",
                            );
                            let _ = self
                                .emit_idempotency_audit(
                                    "mcpg.idempotency.payload_truncated",
                                    request_context,
                                    &params.name,
                                    serde_json::json!({
                                        "key_hash": idempotency::key_hash_hex(key),
                                        "bytes": bytes_for_audit,
                                        "cap": cp_metrics::PAYLOAD_CAPTURE_CAP_BYTES,
                                    }),
                                )
                                .await;
                            metrics::counter!(
                                "mcpg_idempotency_payload_truncated_total",
                                "tool" => params.name.clone(),
                            )
                            .increment(1);
                            // Persist a truncation
                            // sentinel — keeps the
                            // reservation from being
                            // stuck in InFlight while
                            // signalling "this record
                            // can't replay; treat as
                            // miss" to subsequent
                            // retries (peek + reserve
                            // both check the flag).
                            let truncated = idempotency::CachedOutcome {
                                envelope: serde_json::Value::Null,
                                original_request_id: request_id.clone(),
                                original_correlation_id: request_context
                                    .request_id
                                    .as_str()
                                    .to_owned(),
                                replay_count: 0,
                                payload_truncated: true,
                            };
                            if let Err(err) =
                                self.idempotency_store.complete(scope, key, truncated).await
                            {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    error = %err,
                                    "idempotency truncation marker persist failed; reservation may stick in InFlight until TTL",
                                );
                            }
                        } else {
                            let cached = idempotency::CachedOutcome {
                                envelope: final_envelope.clone(),
                                original_request_id: request_id.clone(),
                                original_correlation_id: request_context
                                    .request_id
                                    .as_str()
                                    .to_owned(),
                                replay_count: 0,
                                payload_truncated: false,
                            };
                            if let Err(err) =
                                self.idempotency_store.complete(scope, key, cached).await
                            {
                                warn!(
                                    request_id = %request_context.request_id,
                                    tool_name = %params.name,
                                    error = %err,
                                    "idempotency complete failed; replay will not be served from cache",
                                );
                            } else if stream_eligible {
                                // Dedicated audit
                                // event when a stream
                                // assembly successfully
                                // lands in the cache.
                                // Lets operators see
                                // streaming-replay
                                // hit-rates.
                                let _ = self
                                    .emit_idempotency_audit(
                                        "mcpg.idempotency.stream_completion_cached",
                                        request_context,
                                        &params.name,
                                        serde_json::json!({
                                            "key_hash": idempotency::key_hash_hex(key),
                                            "bytes": envelope_bytes.unwrap_or(0),
                                        }),
                                    )
                                    .await;
                                metrics::counter!(
                                    "mcpg_idempotency_stream_completion_cached_total",
                                    "tool" => params.name.clone(),
                                )
                                .increment(1);
                            }
                        }
                    }
                    ProtocolHttpResponse {
                        http_status: 200,
                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                            jsonrpc: JSONRPC_VERSION,
                            id: request_id,
                            result: final_envelope,
                        }),
                    }
                }
            }
            None => {
                // Audit: every unknown-tool attempt on
                // record per SOC2 CC6.1. Distinguishes attacker
                // enumeration from a typo'd legitimate caller.
                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                    request_id: request_context.request_id.as_str().to_owned(),
                    session_id: request_context.session_id.clone(),
                    tool_name: params.name.clone(),
                    identity: plugin_identity_from_request(request_context),
                    transport: transport_label(&request_context.transport).to_owned(),
                    surface: "tool".to_owned(),
                };
                let event = mcpg_plugin_host::audit_events::tool_call_unknown_event(&audit_ctx)
                    .with_upstream_request_id(request_context.upstream_request_id.clone());
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                protocol_http_error(
                    200,
                    Some(request_id),
                    -32602,
                    format!("unknown tool: {}", params.name),
                    self.debug_error_data(
                        request_context,
                        "Use tools/list to discover available tool names.",
                    ),
                )
            }
        }
    }
}

/// Emit `governance.quota.warn` for each budget a call moved past its
/// `warn_at_pct`.
#[cfg(feature = "governance-quotas")]
async fn emit_quota_warnings(
    registry: &mcpg_plugin_host::PluginRegistry,
    request_context: &RequestContext,
    tool_name: &str,
    warnings: &[crate::runtime::quota_gate::QuotaWarning],
) {
    for warning in warnings {
        metrics::counter!(
            "mcpg_quota_warnings_total",
            "measure" => warning.measure,
            "policy_id" => warning.policy_id.clone(),
        )
        .increment(1);
        let event = mcpg_plugin_host::audit_events::quota_warn_event(
            plugin_identity_from_request(request_context),
            request_context.request_id.as_str(),
            tool_name,
            &warning.policy_id,
            warning.measure,
            warning.used,
            warning.cap,
            warning.warn_at_pct,
        )
        .with_upstream_request_id(request_context.upstream_request_id.clone());
        let _ = registry.emit_audit_event(&event).await;
    }
}

/// Charges the usage a backend reported with a call's result to the call's
/// budget; built before a dispatch so a background task can carry it.
pub(crate) struct UsageCharger {
    #[cfg(feature = "governance-quotas")]
    gate: Option<Arc<crate::runtime::quota_gate::QuotaGate>>,
    registry: Arc<mcpg_plugin_host::PluginRegistry>,
}

impl GatewayRuntime {
    pub(crate) fn usage_charger(&self) -> UsageCharger {
        UsageCharger {
            #[cfg(feature = "governance-quotas")]
            gate: self.quota_gate.clone(),
            registry: Arc::clone(&self.plugin_registry),
        }
    }
}

impl UsageCharger {
    /// Take the usage the backend reported out of `result` and charge it.
    /// The usage never reaches the client; a failed charge is logged, as
    /// the call has already run.
    pub(crate) async fn charge(
        &self,
        request_context: &RequestContext,
        tool_name: &str,
        result: &mut crate::protocol::ToolCallResult,
    ) {
        let Some(usage) = crate::runtime::execution::take_reported_usage(result) else {
            return;
        };
        #[cfg(feature = "governance-quotas")]
        if let Some(gate) = &self.gate {
            match gate
                .charge_usage(
                    tool_name,
                    request_context.session_id.as_deref(),
                    &request_context.identity,
                    &usage,
                )
                .await
            {
                Ok(warnings) => {
                    emit_quota_warnings(&self.registry, request_context, tool_name, &warnings)
                        .await;
                }
                Err(error) => {
                    metrics::counter!("mcpg_quota_charge_failures_total").increment(1);
                    warn!(%error, tool = %tool_name, "budget charge failed; the call's usage is not counted");
                }
            }
        }
        #[cfg(not(feature = "governance-quotas"))]
        let _ = (usage, &self.registry, request_context, tool_name);
    }
}

#[cfg(all(test, feature = "governance-quotas"))]
mod usage_charger_tests {
    use super::*;
    use crate::config::quotas::{BackendQuotasRef, BudgetPolicy, QuotasConfig};
    use crate::runtime::quota_gate::{QuotaDecision, QuotaGate, QuotaStore};

    /// The charge takes the reported usage out of the result the client
    /// gets, and counts it against the call's budget.
    #[tokio::test]
    async fn the_charge_takes_the_usage_out_and_counts_it() {
        let mut quotas = QuotasConfig::default();
        quotas.budgets.push(BudgetPolicy {
            id: "tokens".into(),
            kind: "token_count".into(),
            scope: "global".into(),
            identity_claim: None,
            cap_usd: None,
            cap_token_count: Some(100),
            cap_calls: None,
            window: "24h".into(),
            warn_at_pct: None,
            on_exceeded: "deny".into(),
            acknowledge_unenforced: false,
        });
        let mut refs = std::collections::HashMap::new();
        refs.insert(
            "llm.tool".to_owned(),
            BackendQuotasRef {
                budget: Some("tokens".into()),
                ..Default::default()
            },
        );
        let gate = Arc::new(QuotaGate::new(
            &quotas,
            refs,
            QuotaStore::new(Arc::new(
                crate::builtins::cluster_primitives::MemoryKv::new(),
            )),
            true,
        ));
        let charger = UsageCharger {
            gate: Some(Arc::clone(&gate)),
            registry: Arc::new(mcpg_plugin_host::PluginRegistry::new()),
        };
        let context = RequestContext::new(
            crate::runtime::GatewayRequestId::new(),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            crate::runtime::TransportKind::Http,
        );
        let mut result = crate::protocol::ToolCallResult {
            content: Vec::new(),
            structured_content: None,
            is_error: false,
            meta: Some(serde_json::json!({
                "audit": { "backend_kind": "openai.chat" },
                crate::runtime::execution::USAGE_META_KEY: { "input_tokens": 70, "output_tokens": 40 },
            })),
        };
        charger.charge(&context, "llm.tool", &mut result).await;

        let meta = result.meta.expect("meta");
        assert!(
            meta.get(crate::runtime::execution::USAGE_META_KEY)
                .is_none()
        );
        assert!(meta.get("audit").is_some());
        assert!(matches!(
            gate.evaluate_for_tool("llm.tool", None, &context.identity)
                .await
                .unwrap(),
            QuotaDecision::Deny { .. }
        ));
    }
}
