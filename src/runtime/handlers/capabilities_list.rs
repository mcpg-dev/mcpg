//! `prompts/get` and `resources/read`: the runtime reads the dispatch arms
//! call, behind the same pre-dispatch gate as `tools/call`.

use super::super::*;
use crate::protocol::{
    JSONRPC_VERSION, JsonRpcSuccess, PromptGetParams, PromptGetResult, PromptMessage,
    PromptMessageContent, ProtocolHttpResponse, ProtocolResponse, ResourceContents,
    ResourceReadParams, ResourceReadResult, ResourceTextContents,
};
use serde_json::Value;

impl GatewayRuntime {
    /// `prompts/get`: the surface gate, then the prompt's backend. A binding
    /// whose pipeline suspends answers with an MRTR `InputRequiredResult`.
    pub(crate) async fn handle_prompt_get(
        &self,
        request_id: Value,
        params: PromptGetParams,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        let audit_ctx = |surface: &str| mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: params.name.clone(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
            surface: surface.to_owned(),
        };
        let Some(route) = self.capability_registry.prompt_route(&params.name) else {
            // Audit: prompts/get against an unregistered name.
            let event = mcpg_plugin_host::audit_events::prompt_get_not_found_event(
                &audit_ctx("prompt"),
                &params.name,
            );
            let _ = self.plugin_registry.emit_audit_event(&event).await;
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown prompt: {}", params.name),
                self.debug_error_data(
                    request_context,
                    "Use prompts/list to discover available prompt names.",
                ),
            );
        };
        // Surface-aware gate plugins run before the backend, so prompt
        // traffic is mediated the same way tool traffic is.
        let args_value = params.arguments.clone().unwrap_or(serde_json::json!({}));
        if let Err(gate_response) = self
            .evaluate_surface_gate(
                "prompt",
                "prompt.get.pre",
                &params.name,
                PolicyRoute::for_prompt(&route),
                &args_value,
                request_context,
                &request_id,
            )
            .await
        {
            // Audit: prompts/get denied.
            let event = mcpg_plugin_host::audit_events::prompt_get_denied_event(
                &audit_ctx("prompt"),
                &params.name,
                "surface_gate",
            );
            let _ = self.plugin_registry.emit_audit_event(&event).await;
            return gate_response;
        }
        // A binding whose pipeline carries elicitation / sampling /
        // roots_list steps runs the suspending pipeline path, which answers
        // a suspension with an MRTR `InputRequiredResult`. The synchronous
        // path (`prompt_get_result` → `dispatch_tool_call` →
        // `execute_pipeline_binding`) cannot suspend.
        if let Some(response) = self
            .try_dispatch_prompt_with_suspension(&route, &params, request_context, &request_id)
            .await
        {
            return response;
        }
        match self.prompt_get_result(route, &params, request_context) {
            Ok(result) => {
                // Audit: prompts/get success.
                let event = mcpg_plugin_host::audit_events::prompt_get_success_event(
                    &audit_ctx("prompt"),
                    &params.name,
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                ProtocolHttpResponse {
                    http_status: 200,
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: request_id,
                        result: serde_json::to_value(result).expect("prompt get result serialized"),
                    }),
                }
            }
            Err(decode_err) => protocol_http_error(
                200,
                Some(request_id),
                -32603,
                format!("prompt backend produced a non-conforming response: {decode_err}"),
                self.debug_error_data(
                    request_context,
                    "The backend for this prompt binding must return `{ messages: [...] }` with \
                     spec-shaped entries.",
                ),
            ),
        }
    }

    /// `resources/read`: a gateway-managed `mcpg-resource://` read, a skill
    /// file, or an operator-configured resource, each behind the surface
    /// gate.
    pub(crate) async fn handle_resource_read(
        &self,
        request_id: Value,
        params: ResourceReadParams,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        // Gateway-managed dynamic resources produced by bindings via
        // `host.store_content` surface under the `mcpg-resource://` scheme
        // and are served from the content store.
        if let Some(rest) = params.uri.strip_prefix("mcpg-resource://") {
            // Managed reads run the same pre-dispatch authz stack as
            // operator-configured resources — they must not bypass the trust
            // floor / CEL / policy chain just because the content is
            // gateway-produced.
            let args_value = serde_json::json!({ "uri": params.uri });
            if let Err(gate_response) = self
                .evaluate_surface_gate(
                    "resource",
                    "resource.read.pre",
                    &params.uri,
                    PolicyRoute::gateway().on(PolicySurface::Resource),
                    &args_value,
                    request_context,
                    &request_id,
                )
                .await
            {
                return gate_response;
            }
            return self
                .resource_read_managed(rest, &params.uri, request_id, request_context)
                .await;
        }
        if let Some(response) = self
            .read_skill_file(&params.uri, &request_id, request_context)
            .await
        {
            return response;
        }
        let audit_ctx = |surface: &str| mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: params.uri.clone(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
            surface: surface.to_owned(),
        };
        let Some(route) = self.resolve_resource_route(&params.uri) else {
            // Audit: resources/read against an unregistered URI.
            // Distinguishes attacker enumeration from a typo'd legitimate
            // caller.
            let event = mcpg_plugin_host::audit_events::resource_read_not_found_event(
                &audit_ctx("resource"),
                &params.uri,
            );
            let _ = self.plugin_registry.emit_audit_event(&event).await;
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown resource: {}", params.uri),
                self.debug_error_data(
                    request_context,
                    "Use resources/list to discover available resource URIs.",
                ),
            );
        };
        let surface_label = match &route {
            ResourceRoute::Template { .. } => "resource_template",
            _ => "resource",
        };
        if let Err(gate_response) = self
            .evaluate_resource_gate(
                surface_label,
                "resource.read.pre",
                &params.uri,
                &route,
                request_context,
                &request_id,
            )
            .await
        {
            // Audit: resources/read denied.
            let event = mcpg_plugin_host::audit_events::resource_read_denied_event(
                &audit_ctx(surface_label),
                &params.uri,
                "surface_gate",
            );
            let _ = self.plugin_registry.emit_audit_event(&event).await;
            return gate_response;
        }
        let mut result = match self.resource_read_result(route, &params, request_context) {
            Ok(result) => result,
            Err(decode_err) => {
                return protocol_http_error(
                    200,
                    Some(request_id),
                    -32603,
                    format!("resource backend produced a non-conforming response: {decode_err}"),
                    self.debug_error_data(
                        request_context,
                        "The backend for this resource binding must return `{ contents: [...] }` \
                         with spec-shaped entries.",
                    ),
                );
            }
        };
        // SEP-1865 MCP Apps: a `ui://` resource body may embed
        // session-shaped data, so never let it land in a shared cache —
        // force `private` scope regardless of what the backend/upstream
        // declared.
        if crate::protocol::shared::apps::is_ui_uri(&params.uri) {
            result.cache_scope = Some(crate::protocol::shared::caching::CacheScope::Private);
        }
        // Audit: resources/read success.
        let bytes = serde_json::to_string(&result)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        let event = mcpg_plugin_host::audit_events::resource_read_success_event(
            &audit_ctx(surface_label),
            &params.uri,
            bytes,
        );
        let _ = self.plugin_registry.emit_audit_event(&event).await;
        // SEP-1865 MCP Apps: clamp `_meta.ui` (CSP / permissions / domain)
        // on each content block before egress. No-op unless Apps is
        // enabled; `strict` rejects an out-of-policy `ui://`.
        let mut result_value =
            serde_json::to_value(result).expect("resource read result serialized");
        if let Some(contents) = result_value
            .get_mut("contents")
            .and_then(|c| c.as_array_mut())
            && let Err(msg) = self.apply_apps_policy_to_items(contents, &params.uri)
        {
            return protocol_http_error(200, Some(request_id), -32603, msg, None);
        }
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: result_value,
            }),
        }
    }

    fn prompt_get_result(
        &self,
        route: PromptRoute,
        params: &PromptGetParams,
        request_context: &RequestContext,
    ) -> Result<PromptGetResult, invocation::SurfaceDecodeError> {
        match route {
            PromptRoute::OperationalOverview => Ok(PromptGetResult {
                messages: vec![PromptMessage {
                    role: "system".to_owned(),
                    content: PromptMessageContent::Text {
                        text: format!(
                            "MCPG {} is running at {} with MCP endpoint {}. Available tools: {}. Available prompts: {}. Available resources: {}.",
                            self.service_version,
                            self.server_bind_address,
                            self.mcp_path,
                            self.capability_registry.tools().len(),
                            self.capability_registry.prompts().len(),
                            self.capability_registry.resources().len(),
                        ),
                        annotations: None,
                    },
                    meta: None,
                }],
            }),
            PromptRoute::Binding { ref profile } => {
                let execution_request = execution::BackendInvocationRequest {
                    context: Arc::new(request_context.clone()),
                    tool_name: profile.clone(),
                    arguments: params.arguments.clone(),
                    expr_ctx: request_context.to_expr_context(profile, params.arguments.as_ref()),
                    progress_token: None,
                    request_log_level: extract_request_log_level(params.meta.as_ref())
                        .unwrap_or(None),
                    client_capabilities: self.client_capabilities_for_context(request_context),
                    cancellation_token: None,
                    idempotency_hint: None,
                };
                let route = self.tool_route_for_binding(profile);
                let snapshot = route
                    .needs_runtime_snapshot()
                    .then(|| self.runtime_snapshot());
                let result = self.execution_dispatcher.dispatch_tool_call(
                    route,
                    &execution_request,
                    snapshot,
                );
                // project the backend response onto the prompt surface
                // with a strict codec — a malformed backend produces a
                // JSON-RPC error rather than a wrapped-text fallback.
                invocation::decode_prompt_result(&result)
            }
            PromptRoute::Federated {
                ref source,
                ref upstream_name,
            } => {
                let Some(engine) = self.execution_dispatcher.federation_engine() else {
                    return Err(invocation::SurfaceDecodeError::BackendError {
                        message: "federation engine not configured".to_owned(),
                    });
                };
                let source = source.clone();
                let upstream_name = upstream_name.clone();
                let args = params.arguments.clone();
                let principal = request_context.identity.synthetic_principal_key();
                let caller_identity = request_context.identity.clone();
                let session_id = request_context.session_id.clone();
                let caller_bearer = request_context.inbound_bearer.clone();
                let outcome = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(engine.get_prompt(
                        &source,
                        &upstream_name,
                        args.as_ref(),
                        crate::runtime::federation::FederationCaller {
                            principal: principal.as_deref(),
                            session_id: session_id.as_deref(),
                            bearer: caller_bearer.as_deref(),
                            identity: Some(&caller_identity),
                            request_id: Some(request_context.request_id.as_str()),
                            connect_link: None,
                        },
                    ))
                });
                match outcome {
                    Ok(value) => federated_prompt_get_result(value),
                    Err(crate::runtime::federation::upstream::UpstreamError::NotLinked {
                        message,
                    }) => Err(invocation::SurfaceDecodeError::BackendError {
                        message: format!(
                            "federated prompt '{}' failed: {message} (request id: {})",
                            params.name,
                            request_context.request_id.as_str()
                        ),
                    }),
                    Err(e) => {
                        // The upstream error carries issuer diagnostics — a
                        // preview of the raw Vault response body, provider
                        // names and endpoint status, upstream URLs and
                        // internal hostnames. They stay in the operator log;
                        // the caller gets the request id.
                        tracing::warn!(
                            request_id = %request_context.request_id.as_str(),
                            prompt = %params.name,
                            error = %e,
                            "federated prompt get failed"
                        );
                        Err(invocation::SurfaceDecodeError::BackendError {
                            message: format!(
                                "federated prompt '{}' failed (request id: {})",
                                params.name,
                                request_context.request_id.as_str()
                            ),
                        })
                    }
                }
            }
        }
    }

    fn resource_read_result(
        &self,
        route: ResourceRoute,
        params: &ResourceReadParams,
        request_context: &RequestContext,
    ) -> Result<ResourceReadResult, invocation::SurfaceDecodeError> {
        match route {
            ResourceRoute::RuntimeOverview => Ok(ResourceReadResult {
                contents: vec![ResourceContents::Text(ResourceTextContents {
                    uri: "mcpg://runtime/overview".to_owned(),
                    mime_type: Some("application/json".to_owned()),
                    text: serde_json::to_string_pretty(&self.runtime_snapshot())
                        .expect("runtime overview serialized"),
                    meta: None,
                })],
                ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
                cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
                cache_token: None,
            }),
            ResourceRoute::GatewayApp { ref id } => {
                let uri = format!("ui://mcpg/{id}");
                let app = self
                    .gateway_apps
                    .get(&crate::backends::normalize_resource_uri(&uri))
                    .ok_or_else(|| invocation::SurfaceDecodeError::BackendError {
                        message: format!("gateway app '{id}' is not registered"),
                    })?;
                metrics::counter!("mcpg_gateway_app_reads_total", "app" => id.clone()).increment(1);
                Ok(ResourceReadResult {
                    contents: vec![ResourceContents::Text(ResourceTextContents {
                        uri,
                        mime_type: Some(crate::protocol::shared::apps::UI_MIME_TYPE.to_owned()),
                        text: app.html.clone(),
                        meta: Some(app.descriptor_meta.clone()),
                    })],
                    ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
                    cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
                    cache_token: Some(app.cache_token.clone()),
                })
            }
            ResourceRoute::Binding { ref profile } => {
                let args = serde_json::json!({ "uri": params.uri });
                let execution_request = execution::BackendInvocationRequest {
                    context: Arc::new(request_context.clone()),
                    tool_name: profile.clone(),
                    arguments: Some(args.clone()),
                    expr_ctx: request_context.to_expr_context(profile, Some(&args)),
                    progress_token: None,
                    request_log_level: extract_request_log_level(params.meta.as_ref())
                        .unwrap_or(None),
                    client_capabilities: self.client_capabilities_for_context(request_context),
                    cancellation_token: None,
                    idempotency_hint: None,
                };
                let route = self.tool_route_for_binding(profile);
                let snapshot = route
                    .needs_runtime_snapshot()
                    .then(|| self.runtime_snapshot());
                let result = self.execution_dispatcher.dispatch_tool_call(
                    route.clone(),
                    &execution_request,
                    snapshot,
                );
                invocation::decode_binding_resource_result(
                    &route,
                    &result,
                    &params.uri,
                    self.capability_registry
                        .resource_mime_type(&params.uri, profile)
                        .as_deref(),
                )
            }
            ResourceRoute::Template {
                ref profile,
                ref template_vars,
            } => {
                // template-expanded resource reads invoke the bound
                // profile with the captured template variables materialized
                // into `arguments` alongside the concrete requested URI.
                let mut args = serde_json::Map::new();
                args.insert(
                    "uri".to_owned(),
                    serde_json::Value::String(params.uri.clone()),
                );
                let mut vars_map = serde_json::Map::new();
                for (k, v) in template_vars {
                    vars_map.insert(k.clone(), serde_json::Value::String(v.clone()));
                    // Also expose the variable at the top level so simple
                    // backends can bind directly to `{name}`.
                    args.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
                args.insert(
                    "template_vars".to_owned(),
                    serde_json::Value::Object(vars_map),
                );
                let args_value = serde_json::Value::Object(args);
                let execution_request = execution::BackendInvocationRequest {
                    context: Arc::new(request_context.clone()),
                    tool_name: profile.clone(),
                    arguments: Some(args_value.clone()),
                    expr_ctx: request_context.to_expr_context(profile, Some(&args_value)),
                    progress_token: None,
                    request_log_level: None,
                    client_capabilities: self.client_capabilities_for_context(request_context),
                    cancellation_token: None,
                    idempotency_hint: None,
                };
                let route = self.tool_route_for_binding(profile);
                let snapshot = route
                    .needs_runtime_snapshot()
                    .then(|| self.runtime_snapshot());
                let result = self.execution_dispatcher.dispatch_tool_call(
                    route.clone(),
                    &execution_request,
                    snapshot,
                );
                invocation::decode_binding_resource_result(
                    &route,
                    &result,
                    &params.uri,
                    self.capability_registry
                        .resource_mime_type(&params.uri, profile)
                        .as_deref(),
                )
            }
            ResourceRoute::Federated {
                ref source,
                ref upstream_uri,
                ..
            } => {
                let Some(engine) = self.execution_dispatcher.federation_engine() else {
                    return Err(invocation::SurfaceDecodeError::BackendError {
                        message: "federation engine not configured".to_owned(),
                    });
                };
                let source = source.clone();
                let upstream_uri = upstream_uri.clone();
                let principal = request_context.identity.synthetic_principal_key();
                let caller_identity = request_context.identity.clone();
                let session_id = request_context.session_id.clone();
                let caller_bearer = request_context.inbound_bearer.clone();
                let outcome = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(engine.read_resource(
                        &source,
                        &upstream_uri,
                        crate::runtime::federation::FederationCaller {
                            principal: principal.as_deref(),
                            session_id: session_id.as_deref(),
                            bearer: caller_bearer.as_deref(),
                            identity: Some(&caller_identity),
                            request_id: Some(request_context.request_id.as_str()),
                            connect_link: None,
                        },
                    ))
                });
                match outcome {
                    Ok(value) => Ok(federated_resource_read_result(value)),
                    Err(crate::runtime::federation::upstream::UpstreamError::NotLinked {
                        message,
                    }) => Err(invocation::SurfaceDecodeError::BackendError {
                        message: format!(
                            "federated resource '{}' failed: {message} (request id: {})",
                            params.uri,
                            request_context.request_id.as_str()
                        ),
                    }),
                    Err(e) => {
                        // Same operator-only diagnostics as the prompt path.
                        tracing::warn!(
                            request_id = %request_context.request_id.as_str(),
                            uri = %params.uri,
                            error = %e,
                            "federated resource read failed"
                        );
                        Err(invocation::SurfaceDecodeError::BackendError {
                            message: format!(
                                "federated resource '{}' failed (request id: {})",
                                params.uri,
                                request_context.request_id.as_str()
                            ),
                        })
                    }
                }
            }
        }
    }

    /// Serve a `resources/read` against an `mcpg-resource://<id>` URI
    /// from the gateway-managed content store.
    ///
    /// Three failure modes return 200 + JSON-RPC error per MCP spec:
    /// - No store configured (operator opted out): generic
    ///   "unknown resource".
    /// - Id not found / expired / evicted: same generic error so
    ///   existence isn't leaked.
    /// - Cross-session resource: same generic error — the
    ///   session-ACL refusal is opaque to the caller.
    ///
    /// Success returns a `BlobResourceContents` for non-text mime
    /// types (base64-encoded) or a `ResourceTextContents` when the
    /// mime starts with `text/` and the bytes are valid UTF-8.
    async fn resource_read_managed(
        &self,
        id: &str,
        full_uri: &str,
        request_id: Value,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        let Some(registry) = self.content_stores.as_ref() else {
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown resource: {full_uri}"),
                self.debug_error_data(
                    request_context,
                    "Gateway is configured with no `storage.providers:` block; mcpg-resource:// URIs are not served.",
                ),
            );
        };

        // Parse `mcpg-resource://<id>/<resource>` (or the bare-resource
        // form). The `id` arg is what was already stripped of the
        // `mcpg-resource://` scheme; `full_uri` is the original.
        let (storage_id, resolved_id) = registry.parse_resource_uri(full_uri);
        // Fall back to the passed `id` when parse returned a bare value.
        let resolved_id = if resolved_id.is_empty() {
            id.to_owned()
        } else {
            resolved_id
        };
        let Some(store) = registry.by_id(&storage_id) else {
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown resource: {full_uri}"),
                self.debug_error_data(
                    request_context,
                    &format!(
                        "Storage provider '{storage_id}' is not configured. Add it to the top-level `storage.providers:` block."
                    ),
                ),
            );
        };

        let lookup = match store.get(&resolved_id).await {
            Ok(opt) => opt,
            Err(err) => {
                tracing::warn!(uri = %full_uri, error = %err, "content store get failed");
                return protocol_http_error(
                    200,
                    Some(request_id),
                    -32603,
                    "content store error",
                    self.debug_error_data(request_context, &err.to_string()),
                );
            }
        };
        let Some(content) = lookup else {
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown resource: {full_uri}"),
                self.debug_error_data(
                    request_context,
                    "Resource not found, expired, or evicted from the content store.",
                ),
            );
        };

        // Session-ACL: a resource tagged with one session must not
        // be readable by another session, mirroring the host-side
        // enforcement in `GatewayBackendHost::fetch_content`. Surface
        // as the same generic "unknown resource" so existence isn't
        // leaked.
        if let Some(owner) = content.session_id.as_deref()
            && Some(owner) != request_context.session_id.as_deref()
        {
            metrics::counter!(
                "mcpg_resources_read_acl_refusals_total",
                "reason" => "cross_session",
            )
            .increment(1);
            return protocol_http_error(
                200,
                Some(request_id),
                -32602,
                format!("unknown resource: {full_uri}"),
                self.debug_error_data(
                    request_context,
                    "Session-scoped resources cannot be read from a different session.",
                ),
            );
        }

        // Build the result. Text-shaped mime types with valid UTF-8
        // come back as `ResourceTextContents` so MCP clients can
        // render them inline; everything else is base64 blob.
        let is_text = content.mime_type.starts_with("text/")
            || content.mime_type == "application/json"
            || content.mime_type == "application/xml";
        let text = is_text
            .then(|| std::str::from_utf8(&content.bytes).ok())
            .flatten();
        let contents = match text {
            Some(text) => ResourceContents::Text(ResourceTextContents {
                uri: full_uri.to_owned(),
                mime_type: Some(content.mime_type.clone()),
                text: text.to_owned(),
                meta: None,
            }),
            None => {
                use base64::Engine;
                ResourceContents::Blob(crate::protocol::BlobResourceContents {
                    uri: full_uri.to_owned(),
                    mime_type: Some(content.mime_type.clone()),
                    blob: base64::engine::general_purpose::STANDARD.encode(&content.bytes),
                    meta: None,
                })
            }
        };

        let result = ResourceReadResult {
            contents: vec![contents],
            ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
            cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
            cache_token: None,
        };
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: serde_json::to_value(result)
                    .expect("managed resource read result serialized"),
            }),
        }
    }
}
