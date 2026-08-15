use super::*;

impl GatewayRuntime {
    /// Route an incoming `notifications/cancelled` into the
    /// principal-partitioned, cross-instance cancellation bus, emit the
    /// audit + metric records, and short-circuit a cancel targeting the
    /// `initialize` request (spec MUST-NOT).
    ///
    /// Shared by both wire eras: the legacy `2025-11-25`
    /// `process_protocol_operation` arm and the modern `2026-07-28`
    /// handler's `NotificationCancelled` dispatch call this so a modern
    /// cancel reaches the same machinery that already cancels suspended
    /// pipelines (`cancel_suspended_pipeline`) on every replica. The
    /// caller is responsible for returning the HTTP 202
    /// `NotificationAccepted` envelope; this method performs the
    /// side-effects only.
    pub(crate) async fn handle_request_cancellation(
        &self,
        request_context: &RequestContext,
        cancelled_request_id: &Value,
        reason: Option<&str>,
    ) {
        // per MCP §Cancellation, the initialize request MUST NOT be
        // cancelled via `notifications/cancelled`. Silently drop such
        // notifications — acting on them would race the lifecycle
        // handshake and could leave the session in an indeterminate
        // state. (Inert on the modern wire, which has no `initialize`,
        // but kept here so the shared path is uniformly safe.)
        if let Value::String(s) = cancelled_request_id
            && (s == "init" || s.eq_ignore_ascii_case("initialize"))
        {
            tracing::warn!(
                request_id = %s,
                "ignoring notifications/cancelled targeting initialize"
            );
            return;
        }

        info!(
            cancelled_request_id = %cancelled_request_id,
            reason = ?reason,
            "notifications/cancelled received"
        );

        // Broadcast cancellation to all cluster nodes via the cancellation bus.
        let session_id = request_context.session_id.clone().unwrap_or_default();
        let bus = self.cancellation_bus.clone();
        let event = cancellation_bus::CancellationEvent {
            target_id: cancelled_request_id.to_string(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id,
            principal_id: request_context.identity.principal_id().map(str::to_owned),
            reason: reason.map(str::to_owned),
        };
        tokio::spawn(async move {
            if let Err(e) = bus.publish(event).await {
                tracing::warn!(error = %e, "failed to broadcast cancellation event");
            }
        });

        metrics::counter!("mcpg_cancellations_broadcast_total", "kind" => "request").increment(1);
        // Audit: operation-cancelled record for incident
        // reconstruction. Pairs with the matching tool.call.completed
        // (or its absence) to answer "did the operation actually run
        // before cancel?".
        let audit_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: cancelled_request_id.to_string(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
            surface: "lifecycle".to_owned(),
        };
        let event = mcpg_plugin_host::audit_events::operation_cancelled_event(
            &audit_ctx,
            &cancelled_request_id.to_string(),
            reason,
        );
        let _ = self.plugin_registry.emit_audit_event(&event).await;
    }

    /// Replace the default approval registry with one built from
    /// operator config. Idempotent — callers may invoke
    /// at most once during boot. After the swap, the runtime spawns
    /// the cluster subscriber + expiry GC tasks if a coordinator is
    /// available on the plugin registry.
    pub async fn apply_approvals_config(
        &mut self,
        config: &crate::config::ApprovalsConfig,
        node_id: String,
        // Opt-in cluster state cipher; when set, the approvals
        // backstop KV is sealed like every other capability store.
        state_cipher: Option<
            std::sync::Arc<mcpg_plugin_host::credential_cache_cipher::EventCipher>,
        >,
        // When true, the backstop tolerates plaintext (non-envelope) reads
        // during a key-rollout migration window; default false (fail closed).
        allow_plaintext_reads: bool,
        // Opt-in per-deployment tenant segment; prefixes the backstop
        // KV keys like every other capability store.
        tenant_segment: Option<String>,
    ) -> anyhow::Result<()> {
        let signing_key = if let Some(env_var) = config.signing_key_env.as_deref() {
            let raw = std::env::var(env_var).map_err(|_| {
                anyhow::anyhow!("approvals.signing_key_env={env_var} but the env var is not set")
            })?;
            if raw.len() < 32 {
                anyhow::bail!(
                    "approvals.signing_key_env={env_var}: key must be at least 32 bytes \
                     (got {} bytes)",
                    raw.len()
                );
            }
            raw.into_bytes()
        } else {
            // Fall back to the random key built at construction.
            // Re-extract via the existing registry (the random
            // bytes live there; no public accessor — generate
            // fresh random instead so this call is still
            // idempotent across multiple invocations).
            let mut key = vec![0u8; 32];
            let a = *uuid::Uuid::new_v4().as_bytes();
            let b = *uuid::Uuid::new_v4().as_bytes();
            key[..16].copy_from_slice(&a);
            key[16..].copy_from_slice(&b);
            key
        };
        let callback_base_url = config.callback_base_url.clone().unwrap_or_default();
        let grace = std::time::Duration::from_millis(config.callback_grace_ms);
        let mut registry = approvals::ApprovalRegistry::new(signing_key, callback_base_url, grace);
        if let Some(coordinator) = self.plugin_registry.cluster_backend() {
            registry = registry.with_cluster(
                coordinator,
                node_id,
                state_cipher,
                allow_plaintext_reads,
                tenant_segment,
            );
        }
        let registry = Arc::new(registry);
        registry
            .start_cluster_subscriber()
            .await
            .map_err(|e| anyhow::anyhow!("approval cluster subscriber failed to start: {e}"))?;
        registry.start_expiry_gc(approvals::DEFAULT_EXPIRY_GC_INTERVAL);
        self.approval_registry = registry;
        info!("approval registry installed");
        Ok(())
    }

    /// Registry key for an in-flight *request*'s cancellation token.
    ///
    /// `notifications/cancelled` names the request by its client JSON-RPC id,
    /// so that is what the token must be filed under — the gateway's internal
    /// request UUID is never spoken on the wire and can never be looked up.
    /// Client ids are unique per session but not across them, hence the
    /// session scope; tasks keep their globally-unique task id as the key.
    ///
    /// `rendered_request_id` is the id already rendered the way
    /// [`CancellationEvent::target_id`](cancellation_bus::CancellationEvent)
    /// renders it — `Value::to_string`. Taking the rendered form (rather than
    /// the `Value`) is deliberate: it is the one spelling both sides can
    /// agree on, and it makes double-encoding a string id impossible.
    pub(crate) fn request_cancellation_key(
        session_id: Option<&str>,
        rendered_request_id: &str,
    ) -> String {
        format!(
            "req:{}:{}",
            session_id.unwrap_or_default(),
            rendered_request_id
        )
    }

    /// Register a cancellation token for an in-flight request or task so the
    /// cancellation-bus subscriber can cooperatively interrupt it.
    /// `owner_session`/`owner_principal` identify who started the work; the
    /// subscriber only fires the token for a matching requester (see
    /// [`Self::spawn_cancellation_subscriber`]). Callers must call
    /// [`Self::unregister_cancellation_token`] when the operation finishes
    /// (success or failure) to avoid leaking entries.
    pub fn register_cancellation_token(
        &self,
        target_id: &str,
        owner_session: Option<&str>,
        owner_principal: Option<&str>,
    ) -> tokio_util::sync::CancellationToken {
        let token = tokio_util::sync::CancellationToken::new();
        self.cancellation_tokens.insert(
            target_id.to_owned(),
            RegisteredCancellation {
                token: token.clone(),
                owner_session: owner_session.filter(|s| !s.is_empty()).map(str::to_owned),
                owner_principal: owner_principal.map(str::to_owned),
            },
        );
        token
    }

    pub fn unregister_cancellation_token(&self, target_id: &str) {
        self.cancellation_tokens.remove(target_id);
    }

    /// Spawn a background task that subscribes to the cancellation bus and
    /// cancels any locally-registered token whose `target_id` matches an
    /// incoming event. Safe to call once per runtime — idempotence is the
    /// caller's responsibility.
    pub fn spawn_cancellation_subscriber(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let runtime = Arc::clone(self);
        let bus = self.cancellation_bus.clone();
        tokio::spawn(async move {
            let mut rx = bus.subscribe().await;
            while let Some(event) = rx.recv().await {
                let kind = event.kind.clone();
                // Requests are filed session-scoped under their client
                // JSON-RPC id; tasks under their globally-unique task id.
                let target_id = match kind {
                    cancellation_bus::CancellationKind::Request => Self::request_cancellation_key(
                        Some(event.session_id.as_str()),
                        &event.target_id,
                    ),
                    cancellation_bus::CancellationKind::Task => event.target_id.clone(),
                };
                let registered = runtime
                    .cancellation_tokens
                    .get(&target_id)
                    .map(|r| r.value().clone());
                if let Some(registered) = registered {
                    // Authorize the cancellation before firing the token:
                    // the requester (carried on the event) must own the
                    // in-flight work it targets.
                    if !cancellation_requester_is_owner(&registered, &event) {
                        metrics::counter!("mcpg_cancellation_owner_mismatch_total").increment(1);
                        tracing::warn!(
                            target_id = %target_id,
                            kind = ?kind,
                            "cancellation denied: requester does not own the target request/task"
                        );
                        continue;
                    }
                    let token = registered.token;
                    tracing::info!(
                        target_id = %target_id,
                        kind = ?kind,
                        "cancellation subscriber: interrupting in-flight execution"
                    );
                    token.cancel();
                    metrics::counter!(
                        "mcpg_cancellation_applied_total",
                        "kind" => match kind {
                            cancellation_bus::CancellationKind::Request => "request",
                            cancellation_bus::CancellationKind::Task => "task",
                        },
                    )
                    .increment(1);
                } else if kind == cancellation_bus::CancellationKind::Request {
                    // No live token matched on this replica. The target may be
                    // a SUSPENDED pipeline (awaiting an elicitation/sampling
                    // answer) which registered no token on any replica. Locate
                    // its persisted state by the original JSON-RPC id, claim it
                    // exactly-once across replicas, and deliver a terminal
                    // cancelled error to the caller before deleting it.
                    runtime.cancel_suspended_pipeline(&event).await;
                }
            }
        })
    }

    /// Cancel a SUSPENDED pipeline targeted by a `notifications/cancelled`
    /// whose request id matches no live token. Finds the persisted state by
    /// `(session, original_jsonrpc_id)`, authorizes the requester against the
    /// persisted owner, then CAS-claims it (exactly-once across replicas) and
    /// delivers a terminal cancelled error to the caller before deletion.
    pub(crate) async fn cancel_suspended_pipeline(
        self: &Arc<Self>,
        event: &cancellation_bus::CancellationEvent,
    ) {
        if event.session_id.is_empty() {
            return;
        }
        let state = match self
            .pipeline_store
            .find_suspended_by_jsonrpc_id(&event.session_id, &event.target_id)
        {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "cancel: failed to look up suspended pipeline");
                return;
            }
        };
        // Authorize: the cancel requester must own the suspended pipeline,
        // mirroring resume ownership (principal match; identified owners also
        // session-bound). The persisted owner is the request context captured
        // at suspension. The owner principal is compared on the same key the
        // cancellation event carries — the raw `principal_id` — exactly as
        // `reject_foreign_pipeline_resumer` does on the resume leg, so an
        // identified principal that suspended on A is recognised as the owner
        // when its cancel lands on B.
        let owner_principal = state.request_context.identity.principal_id();
        if !resumer_owns_pipeline(
            owner_principal,
            &state.session_id,
            event.principal_id.as_deref(),
            Some(event.session_id.as_str()),
        ) {
            metrics::counter!("mcpg_cancellation_owner_mismatch_total").increment(1);
            tracing::warn!(
                target_id = %event.target_id,
                "cancellation denied: requester does not own the suspended pipeline"
            );
            return;
        }
        // Exactly-once claim across replicas at the current version. The loser
        // does nothing (the winner delivers the terminal error + deletes).
        match self
            .pipeline_store
            .try_claim_pipeline(&state.pipeline_id, state.state_version)
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::warn!(error = %e, "cancel: claim of suspended pipeline failed");
                return;
            }
        }
        self.deliver_pipeline_terminal_error(
            &state.session_id,
            &state.original_jsonrpc_id,
            -32800,
            "request cancelled by client",
        )
        .await;
        if let Some(srv_req_id) = &state.pending_server_request_id {
            let _ = self
                .pipeline_store
                .delete_pending_server_request(srv_req_id);
        }
        let _ = self.pipeline_store.delete_pipeline(&state.pipeline_id);
        metrics::counter!(
            "mcpg_cancellation_applied_total",
            "kind" => "suspended_pipeline",
        )
        .increment(1);
    }

    /// Bump the cancelled-task metric and broadcast the cancellation onto the
    /// cluster bus so a peer running the task's background work interrupts it too.
    /// Shared by the legacy `tasks/cancel` arm and the modern tasks-extension
    /// CancelTask arm — without it, a modern cancel never reaches the replica
    /// executing the task.
    pub(crate) fn broadcast_task_cancellation(
        &self,
        task_id: &str,
        session_id: &str,
        principal_id: Option<&str>,
    ) {
        metrics::counter!("mcpg_tasks_cancelled_total").increment(1);
        let bus = self.cancellation_bus.clone();
        let event = cancellation_bus::CancellationEvent {
            target_id: task_id.to_owned(),
            kind: cancellation_bus::CancellationKind::Task,
            session_id: session_id.to_owned(),
            principal_id: principal_id.map(str::to_owned),
            reason: None,
        };
        tokio::spawn(async move {
            if let Err(e) = bus.publish(event).await {
                tracing::warn!(error = %e, "failed to broadcast task cancellation");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registration side holds the client id as a `Value`; the bus side
    /// only ever sees `CancellationEvent::target_id`, already rendered by
    /// `Value::to_string`. If those two renderings disagree the lookup misses
    /// silently and the token never fires — which is what happened when
    /// registration keyed on the gateway's internal request UUID instead.
    #[test]
    fn registration_and_bus_lookup_agree_on_the_key() {
        for client_id in [
            serde_json::json!(42),
            serde_json::json!("abc"),
            serde_json::json!("42"),
        ] {
            let registered =
                GatewayRuntime::request_cancellation_key(Some("sess-1"), &client_id.to_string());
            // How `handle_request_cancellation` builds `target_id`.
            let event_target_id = client_id.to_string();
            let looked_up =
                GatewayRuntime::request_cancellation_key(Some("sess-1"), &event_target_id);
            assert_eq!(registered, looked_up, "key mismatch for {client_id}");
        }
    }

    /// Client JSON-RPC ids are unique per session but not across them, so two
    /// sessions using id 1 must not collide on one registry entry.
    #[test]
    fn key_is_session_scoped() {
        let a = GatewayRuntime::request_cancellation_key(Some("sess-a"), "1");
        let b = GatewayRuntime::request_cancellation_key(Some("sess-b"), "1");
        assert_ne!(a, b);
    }

    /// A numeric id and the string of the same digits are distinct JSON-RPC
    /// ids; `Value::to_string` keeps them apart (`1` vs `"1"`).
    #[test]
    fn numeric_and_string_ids_do_not_alias() {
        let numeric =
            GatewayRuntime::request_cancellation_key(Some("s"), &serde_json::json!(1).to_string());
        let string = GatewayRuntime::request_cancellation_key(
            Some("s"),
            &serde_json::json!("1").to_string(),
        );
        assert_ne!(numeric, string);
    }
}
