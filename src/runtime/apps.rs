use super::*;

impl GatewayRuntime {
    pub fn set_apps_config(
        &mut self,
        capability: Option<serde_json::Value>,
        federate_upstream: bool,
        policy: Option<crate::protocol::shared::apps::AppsPolicy>,
        registry: &[crate::config::apps::GatewayAppConfig],
    ) {
        self.apps_capability = capability;
        self.apps_federate_upstream = federate_upstream;
        // Snapshot the bound tools' schemas so omitted columns/fields can
        // be derived by introspection at compile time.
        let tools: std::collections::BTreeMap<String, gateway_apps::ToolIo> = self
            .capability_registry
            .tools()
            .into_iter()
            .map(|t| {
                (
                    t.name,
                    gateway_apps::ToolIo {
                        input_schema: Some(t.input_schema),
                        output_schema: t.output_schema,
                    },
                )
            })
            .collect();
        let compiled = gateway_apps::compile_apps(registry, policy.as_ref(), &tools);
        self.gateway_apps = compiled
            .into_iter()
            .map(|app| {
                // Key on the canonical URI so resolve_resource_route's
                // normalized lookup is symmetric with the stored key.
                (
                    crate::backends::normalize_resource_uri(&app.uri),
                    std::sync::Arc::new(app),
                )
            })
            .collect();
        self.apps_policy = policy;
    }

    /// Resolve a `resources/read`/`resources/list` URI to a route,
    /// checking the gateway-authored app registry first (it owns the
    /// `ui://mcpg/<id>` authority) before delegating to the capability
    /// registry.
    pub(crate) fn resolve_resource_route(
        &self,
        uri: &str,
    ) -> Option<crate::backends::ResourceRoute> {
        // Match the canonicalization the capability registry uses, so a
        // case-/encoding-variant `ui://mcpg/<id>` still resolves (the map is
        // keyed on the canonical compiled URI).
        let normalized = crate::backends::normalize_resource_uri(uri);
        if let Some(app) = self.gateway_apps.get(&normalized) {
            return Some(crate::backends::ResourceRoute::GatewayApp { id: app.id.clone() });
        }
        self.capability_registry.resource_route(uri)
    }

    /// Apply the SEP-1865 MCP Apps egress policy to a set of serialized
    /// resource descriptors or `resources/read` content blocks (each a
    /// JSON object that may carry `_meta.ui`). Intersects CSP, strips
    /// out-of-allow-list permissions, and drops out-of-allow-list
    /// sandbox domains in place; emits metrics for each narrowing.
    ///
    /// No-op (returns `Ok`) when Apps is disabled. In `strict` mode,
    /// returns `Err(message)` when any item's `_meta.ui` escaped the
    /// policy, so the caller can reject the response instead of serving
    /// the sanitized form. `uri` is used only for logs/metrics context.
    pub(crate) fn apply_apps_policy_to_items(
        &self,
        items: &mut [serde_json::Value],
        uri: &str,
    ) -> Result<(), String> {
        let Some(policy) = self.apps_policy.as_ref() else {
            return Ok(());
        };
        let mut violated = false;
        for item in items.iter_mut() {
            let Some(meta) = item.get_mut("_meta") else {
                continue;
            };
            let report = policy.apply_to_resource_meta(meta);
            for axis in &report.csp_axes_narrowed {
                metrics::counter!("mcpg_apps_csp_intersected_total", "axis" => *axis).increment(1);
            }
            for perm in &report.permissions_stripped {
                metrics::counter!(
                    "mcpg_apps_permission_stripped_total",
                    "permission" => perm.clone()
                )
                .increment(1);
            }
            if report.domain_dropped {
                metrics::counter!("mcpg_apps_domain_dropped_total").increment(1);
            }
            if report.has_violations() {
                violated = true;
                tracing::debug!(
                    uri = %uri,
                    violations = ?report.violations,
                    "mcp-apps: narrowed _meta.ui to operator policy"
                );
            }
        }
        if policy.strict && violated {
            return Err(format!(
                "MCP Apps strict mode: '{uri}' _meta.ui escaped operator policy \
                 (apps.strict = true)"
            ));
        }
        Ok(())
    }

    /// MCP Apps audit: record which UI apps a
    /// `tools/list` reply offered a principal, so the audit trail can
    /// answer "which apps did user X see?". Scans the page for tools
    /// carrying `_meta.ui.resourceUri` and, if any, emits one
    /// `mcp_apps.offered` audit event pairing the caller's identity with
    /// the `{tool, resourceUri}` list. No event when no tool is
    /// UI-enabled (so non-Apps deployments pay nothing beyond the scan).
    pub(crate) async fn audit_apps_offered(
        &self,
        request_context: &RequestContext,
        tools: &[crate::backends::ToolDescriptor],
    ) {
        let offered = apps_offered_from_tools(tools);
        if offered.is_empty() {
            return;
        }
        let event = mcpg_plugin_host::audit_events::apps_offered_event(
            plugin_identity_from_request(request_context),
            request_context.request_id.as_str(),
            request_context.session_id.as_deref(),
            transport_label(&request_context.transport),
            serde_json::Value::Array(offered),
        );
        let _ = self.plugin_registry.emit_audit_event(&event).await;
    }

    /// Run a tool result through the same post-dispatch pipeline a real
    /// backend result takes — outputSchema enforcement, the post-dispatch
    /// tool_gate chain (DLP/redaction/masking), the post transform chain,
    /// and the pre-chain metadata merge — then build the 200 response.
    /// Used by the pre-dispatch cache short-circuit so a plugin-supplied
    /// cached result is constrained exactly like genuine backend output
    /// (cached values are untrusted within the gateway trust boundary).
    pub(crate) async fn finalize_tool_result(
        &self,
        request_context: &RequestContext,
        request_id: Value,
        tool_name: &str,
        arguments: &Value,
        mut result: crate::protocol::ToolCallResult,
        execution_ms: u64,
        plugin_gate_meta: &Option<Value>,
    ) -> ProtocolHttpResponse {
        // outputSchema enforcement: fail closed on non-conforming output.
        if !result.is_error
            && let Err(validation_err) = self
                .capability_registry
                .validate_structured_output(tool_name, &result.structured_content)
        {
            warn!(
                request_id = %request_context.request_id,
                tool_name = %tool_name,
                "structuredContent failed outputSchema validation, failing tool"
            );
            result.structured_content = None;
            result.is_error = true;
            result.content.push(crate::protocol::ToolContent::text(format!(
                "tool '{tool_name}' declared an outputSchema but returned non-conforming structuredContent: {validation_err}"
            )));
        }

        // Post-dispatch tool_gate chain (DLP / redaction / masking).
        let mut gate_modified_result: Option<Value> = None;
        if self.plugin_registry.has_tool_gate_plugins() {
            let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                request_id: request_context.request_id.as_str().to_owned(),
                session_id: request_context.session_id.clone(),
                tool_name: tool_name.to_owned(),
                identity: plugin_identity_from_request(request_context),
                transport: transport_label(&request_context.transport).to_owned(),
                surface: "tool".to_owned(),
            };
            let result_json = serde_json::to_value(&result).unwrap_or(serde_json::json!({}));
            match self
                .plugin_registry
                .evaluate_tool_gates_post(&plugin_ctx, arguments, &result_json, execution_ms)
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
                mcpg_plugin_protocol::GateDecision::PendingApproval { approval_id, .. } => {
                    warn!(
                        request_id = %request_context.request_id,
                        tool_name = %tool_name,
                        approval_id = %approval_id,
                        "post-dispatch tool gate returned PendingApproval; treating as deny (approvals only valid pre-dispatch)",
                    );
                    return protocol_http_error(
                        500,
                        Some(request_id),
                        -32603,
                        format!(
                            "tool '{tool_name}' post-dispatch gate returned invalid PendingApproval decision"
                        ),
                        None,
                    );
                }
            }
        }

        // Post-dispatch result transform chain.
        let final_result_json = match gate_modified_result {
            Some(modified) => modified,
            None => serde_json::to_value(result).expect("tool call result serialized"),
        };
        let final_result_json = if self.plugin_registry.has_transform_plugins() {
            let plugin_ctx = mcpg_plugin_protocol::PluginContext {
                request_id: request_context.request_id.as_str().to_owned(),
                session_id: request_context.session_id.clone(),
                tool_name: tool_name.to_owned(),
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

        ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: "2.0",
                id: request_id,
                result: merge_plugin_gate_meta(final_result_json, plugin_gate_meta),
            }),
        }
    }

    /// Walk a slice of dynamic-list providers (each with its own
    /// optional cursor), append their returned resources onto the
    /// in-flight `resources/list` response, and return the subset
    /// of providers that reported a non-null `next_cursor` along
    /// with that cursor — the caller threads this back into the
    /// outgoing composite cursor.
    ///
    /// `targets` items are `(backend_name, kind, cursor)`. Each
    /// provider runs with a per-call deadline so a slow listing
    /// query can't hold up the whole response.
    pub(crate) async fn merge_dynamic_resources(
        &self,
        page: &mut Vec<crate::backends::ResourceDescriptor>,
        targets: &[(String, String, Option<String>)],
    ) -> Vec<DynCursor> {
        const PER_PROVIDER_TIMEOUT_MS: u64 = 3_000;
        let mut remaining = Vec::new();
        for (backend_name, kind, cursor) in targets {
            let Some(plugin) = self.plugin_registry.backend(kind) else {
                continue;
            };
            let fut = plugin.list_resources(backend_name, cursor.as_deref());
            let result = match tokio::time::timeout(
                std::time::Duration::from_millis(PER_PROVIDER_TIMEOUT_MS),
                fut,
            )
            .await
            {
                Ok(Ok(page)) => page,
                Ok(Err(e)) => {
                    warn!(
                        backend = %backend_name,
                        kind = %kind,
                        error = %e,
                        "resources/list: dynamic provider list_resources failed; skipping"
                    );
                    continue;
                }
                Err(_) => {
                    warn!(
                        backend = %backend_name,
                        kind = %kind,
                        timeout_ms = PER_PROVIDER_TIMEOUT_MS,
                        "resources/list: dynamic provider timed out; skipping"
                    );
                    continue;
                }
            };
            if let Some(next) = result.next_cursor {
                remaining.push(DynCursor {
                    b: backend_name.clone(),
                    c: next,
                });
            }
            for listed in result.resources {
                page.push(crate::backends::ResourceDescriptor {
                    uri: listed.uri,
                    name: listed.name.unwrap_or_else(|| backend_name.clone()),
                    title: None,
                    description: listed.description,
                    mime_type: listed.mime_type,
                    size: None,
                    icons: None,
                    annotations: None,
                    meta: None,
                });
            }
        }
        remaining
    }
}
