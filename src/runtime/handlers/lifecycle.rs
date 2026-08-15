use super::super::*;

impl GatewayRuntime {
    pub(crate) async fn handle_lifecycle_operation(
        &self,
        operation: LifecycleOperation,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        match operation {
            LifecycleOperation::Initialize { request_id, params } => {
                if request_context.session_id.is_some() {
                    return protocol_http_error(
                        400,
                        Some(request_id),
                        -32600,
                        "initialize must not include an MCP-Session-Id header",
                        self.debug_error_data(
                            request_context,
                            "Remove the MCP-Session-Id header from the initialize request. Initialize creates a new session.",
                        ),
                    );
                }

                let negotiated_version = negotiate_protocol_version(&params.protocol_version);
                let session = self
                    .session_store
                    .create_session(negotiated_version, &params);
                // The store signals "global cap reached" by returning a
                // snapshot with an empty `session_id`. Surface this as
                // HTTP 503 so clients retry rather than treating it as a
                // successful initialize with a bogus zero-length id.
                if session.session_id.is_empty() {
                    return protocol_http_error(
                        503,
                        Some(request_id),
                        -32099,
                        "gateway session capacity exhausted",
                        self.debug_error_data(
                            request_context,
                            "raise store.max_sessions, release idle sessions, or scale out",
                        ),
                    );
                }
                // Bind the session to its creating principal so
                // session-scoped operations can be owner-checked. The key
                // is trust-qualified so a header-asserted caller can't
                // match a verified owner with the same subject string.
                self.session_store.bind_session_owner(
                    &session.session_id,
                    request_context
                        .identity
                        .synthetic_principal_key()
                        .as_deref(),
                );
                // enforce per-tenant quota AFTER the session
                // store accepted (it owns the global cap). Roll back
                // the session if the tenant cap rejects.
                //
                // Keyed on the full principal, not the bare subject: `sub` is
                // opaque and per-issuer, so two identities from different
                // IdPs (or one header-asserted and one verified) would
                // otherwise share — and exhaust — a single quota bucket.
                // `None` only for an anonymous caller, which carries nothing
                // to separate callers by; those share a bucket and are
                // metered per-IP by `anonymous_rate_limit_per_min` instead.
                let namespaced = request_context.identity.synthetic_principal_key();
                let tenant = namespaced.as_deref();
                if self
                    .try_acquire_tenant_session(&session.session_id, tenant)
                    .is_err()
                {
                    self.session_store.terminate_session(&session.session_id);
                    return protocol_http_error(
                        429,
                        Some(request_id),
                        -32099,
                        "per-tenant session quota exceeded",
                        self.debug_error_data(
                            request_context,
                            "lower max_sessions_per_tenant or release an existing session",
                        ),
                    );
                }
                metrics::gauge!("mcpg_active_sessions").increment(1.0);
                info!(
                    session_id = %session.session_id,
                    client_name = %session.client_info.name,
                    protocol_version = %session.protocol_version,
                    "session created"
                );
                // Audit: session opened. SOC2 wants
                // session-time bracketing per identity. Emitted only
                // after the global cap + tenant quota checks pass.
                let event = mcpg_plugin_host::audit_events::session_opened_event(
                    plugin_identity_from_request(request_context),
                    &session.session_id,
                    &session.protocol_version,
                    &session.client_info.name,
                    &session.client_info.version,
                    transport_label(&request_context.transport),
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                // SEP-2133 extension advertisements. Each
                // operator-enabled extension contributes one entry
                // here; absent block ⇒ wire-omitted.
                let extensions = {
                    let mut map = serde_json::Map::new();
                    if let Some(idem) = self.idempotency_capability.as_ref() {
                        map.insert(idempotency::EXTENSION_ID.to_owned(), idem.clone());
                    }
                    // SEP-1865 MCP Apps — advertised when
                    // `mcp.configurations.apps.enabled`.
                    if let Some(apps) = self.apps_capability.as_ref() {
                        map.insert(
                            crate::protocol::shared::apps::EXTENSION_ID.to_owned(),
                            apps.clone(),
                        );
                    }
                    if map.is_empty() { None } else { Some(map) }
                };
                let result = InitializeResult {
                    protocol_version: negotiated_version.to_owned(),
                    capabilities: ServerCapabilities {
                        completions: if self.capability_registry.has_completions() {
                            Some(CapabilityFlag {})
                        } else {
                            None
                        },
                        logging: Some(CapabilityFlag {}),
                        prompts: Some(ListCapability { list_changed: true }),
                        resources: Some(ResourceCapability {
                            list_changed: true,
                            subscribe: true,
                        }),
                        tools: Some(ListCapability { list_changed: true }),
                        tasks: Some(TasksCapability {
                            list: Some(CapabilityFlag {}),
                            cancel: Some(CapabilityFlag {}),
                            // MCPG runs task-augmented tool calls natively
                            // (tasks/create wraps tools/call), so advertise
                            // the request-specific capability.
                            requests: Some(
                                crate::protocol::ServerTaskRequestsCapability {
                                    tools: Some(
                                        crate::protocol::ServerTaskToolsCapability {
                                            call: Some(CapabilityFlag {}),
                                        },
                                    ),
                                },
                            ),
                        }),
                        // echo the client's experimental block
                        // so clients can confirm we observed — not
                        // silently discarded — their declarations.
                        experimental: params.capabilities.experimental.clone(),
                        extensions,
                    },
                    server_info: ImplementationInfo {
                        name: self.service_name.clone(),
                        title: Some("Model Context Protocol Gateway".to_owned()),
                        version: self.service_version.clone(),
                        description: Some(
                            "MCPG lifecycle bootstrap and gateway runtime server".to_owned(),
                        ),
                        website_url: None,
                        icons: None,
                    },
                    instructions: Some(
                        "Complete lifecycle bootstrap by sending notifications/initialized before normal MCP operations.".to_owned(),
                    ),
                };

                ProtocolHttpResponse {
                    http_status: 200,
                    session_id_header: Some(session.session_id),
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: request_id,
                        result: serde_json::to_value(result).expect("initialize result serialized"),
                    }),
                }
            }
            LifecycleOperation::Initialized => {
                match request_context.load_session_cached(&*self.session_store, false) {
                    Ok(session) => {
                        if let Err(error) = self
                            .session_store
                            .transition_session_to_operational(&session.session_id)
                        {
                            return self.map_session_error_to_protocol_response(error, None);
                        }
                        // Audit: handshake ack on the audit
                        // lane. Bookends the `mcpg.session.opened` event.
                        let event = mcpg_plugin_host::audit_events::session_initialized_acked_event(
                            plugin_identity_from_request(request_context),
                            request_context.session_id.as_deref(),
                            transport_label(&request_context.transport),
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        ProtocolHttpResponse {
                            http_status: 202,
                            session_id_header: None,
                            response: ProtocolResponse::NotificationAccepted,
                        }
                    }
                    Err(error) => self.map_session_error_to_protocol_response(error, None),
                }
            }
            LifecycleOperation::Ping { request_id } => {
                // Audit: keepalive ping. Low-volume on
                // typical traffic; high-volume installations should
                // route this through a separate sink with retention
                // tuning to keep the SIEM clean.
                let event = mcpg_plugin_host::audit_events::ping_received_event(
                    plugin_identity_from_request(request_context),
                    request_context.request_id.as_str(),
                    request_context.session_id.as_deref(),
                    transport_label(&request_context.transport),
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                ProtocolHttpResponse {
                    http_status: 200,
                    session_id_header: None,
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: request_id,
                        result: serde_json::json!({}),
                    }),
                }
            }
            LifecycleOperation::NotificationAccepted => ProtocolHttpResponse {
                http_status: 202,
                session_id_header: None,
                response: ProtocolResponse::NotificationAccepted,
            },
            LifecycleOperation::NotificationCancelled {
                request_id: cancelled_request_id,
                reason,
            } => {
                self.handle_request_cancellation(
                    request_context,
                    &cancelled_request_id,
                    reason.as_deref(),
                )
                .await;
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            LifecycleOperation::ElicitationComplete { params } => {
                // URL-mode elicitation completion from the client.
                //
                // The server-initiated `elicitation/create` encoded
                // `elicitationId = pending_server_request_id` so the
                // cluster-wide `pipeline_store.load_pending_server_request`
                // resolves the owning pipeline regardless of which instance
                // handled the original suspension. We reuse the standard
                // server-request resumption path by synthesizing a
                // JSON-RPC response from the notification payload:
                //   accept  → result = { action: "accept", content: <body> }
                //   decline → result = { action: "decline" }
                //   cancel  → result = { action: "cancel" }
                // Downstream pipeline steps can branch on `steps.<id>.output.action`.
                info!(
                    elicitation_id = ?params.elicitation_id,
                    action = ?params.action,
                    "notifications/elicitation/complete received"
                );
                let user_action_label = match params.action {
                    crate::protocol::ElicitationAction::Accept => "accept",
                    crate::protocol::ElicitationAction::Decline => "decline",
                    crate::protocol::ElicitationAction::Cancel => "cancel",
                };
                metrics::counter!(
                    "mcpg_elicitation_complete_total",
                    "action" => user_action_label,
                )
                .increment(1);
                // Audit: pairs with the elicitation-requested
                // event keyed by elicitation_id.
                let elicitation_id_str = match &params.elicitation_id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                    request_id: request_context.request_id.as_str().to_owned(),
                    session_id: request_context.session_id.clone(),
                    tool_name: elicitation_id_str.clone(),
                    identity: plugin_identity_from_request(request_context),
                    transport: transport_label(&request_context.transport).to_owned(),
                    surface: "lifecycle".to_owned(),
                };
                let event = mcpg_plugin_host::audit_events::elicitation_completed_event(
                    &audit_ctx,
                    &elicitation_id_str,
                    user_action_label,
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                let mut payload = serde_json::json!({
                    "action": match params.action {
                        crate::protocol::ElicitationAction::Accept => "accept",
                        crate::protocol::ElicitationAction::Decline => "decline",
                        crate::protocol::ElicitationAction::Cancel => "cancel",
                    }
                });
                if let Some(content) = params.content.clone()
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert("content".to_owned(), content);
                }
                let response_id_str = match &params.elicitation_id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                match self
                    .pipeline_store
                    .load_pending_server_request(&response_id_str)
                {
                    Ok(Some(_)) => {
                        // Resumption fires the pipeline forward via the
                        // standard server-request-response handler and
                        // returns a normal 202 for the notification.
                        let _ = self
                            .handle_server_request_response(
                                request_context,
                                params.elicitation_id.clone(),
                                Some(payload),
                                None,
                            )
                            .await;
                    }
                    Ok(None) => {
                        // Unknown or already-resolved id: notifications
                        // never produce a JSON-RPC error response; silently
                        // accept.
                        tracing::debug!(
                            elicitation_id = %response_id_str,
                            "elicitation/complete for unknown or already-resolved id; accepting"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "elicitation/complete pipeline lookup failed");
                    }
                }
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            LifecycleOperation::RootsListChanged => {
                // record the change and publish an internal runtime
                // signal so bound pipelines / gate plugins can invalidate
                // any cached roots snapshot. Today no runtime component
                // caches roots/list results, so this is observability-only;
                // once a cache is introduced it should subscribe here.
                info!(
                    session_id = ?request_context.session_id,
                    "notifications/roots/list_changed received"
                );
                metrics::counter!("mcpg_roots_list_changed_total").increment(1);
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
        }
    }
}
