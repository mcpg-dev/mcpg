use super::super::*;

impl GatewayRuntime {
    pub(crate) async fn handle_capabilities_list_operation(
        &self,
        operation: CapabilityOperation,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        match operation {
            CapabilityOperation::ToolsList { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        // An opaque cursor that does not decode is invalid
                        // params (-32602), not a silent restart at page 1.
                        if !self.cursor_is_valid(
                            params.cursor.as_deref(),
                            request_context.session_id.as_deref(),
                        ) {
                            return protocol_http_error(
                                200,
                                Some(request_id),
                                -32602,
                                "invalid pagination cursor".to_owned(),
                                self.debug_error_data(
                                    request_context,
                                    "Omit `cursor` to start from the first page; \
                                     reuse only a `nextCursor` returned by this server.",
                                ),
                            );
                        }
                        let (page, next_cursor) = self
                            .enumerate_tools_page(request_context, params.cursor.as_deref())
                            .await;
                        // Audit: tool catalog enumeration.
                        let event = mcpg_plugin_host::audit_events::list_call_event(
                            plugin_identity_from_request(request_context),
                            request_context.request_id.as_str(),
                            request_context.session_id.as_deref(),
                            "tool",
                            page.len() as u64,
                            transport_label(&request_context.transport),
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        // MCP Apps audit: which UI apps
                        // this listing offered the caller.
                        self.audit_apps_offered(request_context, &page).await;
                        ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result: serde_json::to_value(ToolsListResult {
                                    tools: page,
                                    next_cursor,
                                    ttl_ms: Some(
                                        crate::protocol::shared::caching::DEFAULT_LIST_TTL_MS,
                                    ),
                                    cache_scope: Some(
                                        crate::protocol::shared::caching::CacheScope::Private,
                                    ),
                                    cache_token: None,
                                })
                                .expect("tools list serialized"),
                            }),
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::PromptsList { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        let (page, next_cursor) =
                            self.enumerate_prompts_page(request_context, params.cursor.as_deref());
                        // Audit: prompt catalog enumeration.
                        let event = mcpg_plugin_host::audit_events::list_call_event(
                            plugin_identity_from_request(request_context),
                            request_context.request_id.as_str(),
                            request_context.session_id.as_deref(),
                            "prompt",
                            page.len() as u64,
                            transport_label(&request_context.transport),
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result: serde_json::to_value(PromptsListResult {
                                    prompts: page,
                                    next_cursor,
                                    ttl_ms: Some(
                                        crate::protocol::shared::caching::DEFAULT_LIST_TTL_MS,
                                    ),
                                    cache_scope: Some(
                                        crate::protocol::shared::caching::CacheScope::Private,
                                    ),
                                    cache_token: None,
                                })
                                .expect("prompts list serialized"),
                            }),
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::PromptsGet { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => match self.capability_registry.prompt_route(&params.name) {
                        Some(route) => {
                            // run surface-aware gate plugins before
                            // dispatching to the backend so prompt traffic is
                            // mediated the same way tool traffic is.
                            let args_value =
                                params.arguments.clone().unwrap_or(serde_json::json!({}));
                            if let Err(gate_response) = self
                                .evaluate_surface_gate(
                                    "prompt",
                                    "prompt.get.pre",
                                    &params.name,
                                    &args_value,
                                    request_context,
                                    &request_id,
                                )
                                .await
                            {
                                // Audit: prompts/get denied.
                                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    session_id: request_context.session_id.clone(),
                                    tool_name: params.name.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    transport: transport_label(&request_context.transport)
                                        .to_owned(),
                                    surface: "prompt".to_owned(),
                                };
                                let event = mcpg_plugin_host::audit_events::prompt_get_denied_event(
                                    &audit_ctx,
                                    &params.name,
                                    "surface_gate",
                                );
                                let _ = self.plugin_registry.emit_audit_event(&event).await;
                                return gate_response;
                            }
                            // `prompts/get` against a binding whose
                            // pipeline carries elicitation / sampling /
                            // roots_list steps goes through the suspending
                            // pipeline path. The synchronous fast path
                            // (`prompt_get_result` → `dispatch_tool_call`
                            // → `execute_pipeline_binding`) errors on
                            // suspending steps because the fast executor
                            // can't suspend; route those bindings to
                            // `execute_pipeline` and translate the
                            // suspended outcome into an MRTR
                            // `InputRequiredResult` (modern) or HTTP 202 +
                            // bus-delivered server request (legacy).
                            if let Some(response) = self
                                .try_dispatch_prompt_with_suspension(
                                    &route,
                                    &params,
                                    request_context,
                                    &request_id,
                                )
                                .await
                            {
                                return response;
                            }
                            match self.prompt_get_result(route, &params, request_context) {
                                Ok(result) => {
                                    // Audit: prompts/get success.
                                    let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                        request_id: request_context
                                            .request_id
                                            .as_str()
                                            .to_owned(),
                                        session_id: request_context.session_id.clone(),
                                        tool_name: params.name.clone(),
                                        identity: plugin_identity_from_request(request_context),
                                        transport: transport_label(&request_context.transport)
                                            .to_owned(),
                                        surface: "prompt".to_owned(),
                                    };
                                    let event = mcpg_plugin_host::audit_events::prompt_get_success_event(
                                        &audit_ctx,
                                        &params.name,
                                    );
                                    let _ = self
                                        .plugin_registry
                                        .emit_audit_event(&event)
                                        .await;
                                    ProtocolHttpResponse {
                                        http_status: 200,
                                        session_id_header: None,
                                        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                            jsonrpc: JSONRPC_VERSION,
                                            id: request_id,
                                            result: serde_json::to_value(result)
                                                .expect("prompt get result serialized"),
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
                                        "The backend for this prompt binding must return `{ messages: [...] }` with spec-shaped entries.",
                                    ),
                                ),
                            }
                        }
                        None => {
                            // Audit: prompts/get against an
                            // unregistered name.
                            let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                request_id: request_context.request_id.as_str().to_owned(),
                                session_id: request_context.session_id.clone(),
                                tool_name: params.name.clone(),
                                identity: plugin_identity_from_request(request_context),
                                transport: transport_label(&request_context.transport).to_owned(),
                                surface: "prompt".to_owned(),
                            };
                            let event = mcpg_plugin_host::audit_events::prompt_get_not_found_event(
                                &audit_ctx,
                                &params.name,
                            );
                            let _ = self.plugin_registry.emit_audit_event(&event).await;
                            protocol_http_error(
                                200,
                                Some(request_id),
                                -32602,
                                format!("unknown prompt: {}", params.name),
                                self.debug_error_data(
                                    request_context,
                                    "Use prompts/list to discover available prompt names.",
                                ),
                            )
                        }
                    },
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ResourcesList { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        let (page, next_cursor) = self
                            .enumerate_resources_page(request_context, params.cursor.as_deref())
                            .await;

                        // Audit: resource catalog enumeration.
                        let event = mcpg_plugin_host::audit_events::list_call_event(
                            plugin_identity_from_request(request_context),
                            request_context.request_id.as_str(),
                            request_context.session_id.as_deref(),
                            "resource",
                            page.len() as u64,
                            transport_label(&request_context.transport),
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        // SEP-1865 MCP Apps: clamp each list entry's `_meta.ui`
                        // (CSP / permissions / domain) to operator policy on
                        // the legacy wire too; no-op unless Apps is enabled,
                        // strict rejects an out-of-policy descriptor.
                        let mut result_value = serde_json::to_value(ResourcesListResult {
                            resources: page,
                            next_cursor,
                            ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_LIST_TTL_MS),
                            cache_scope: Some(
                                crate::protocol::shared::caching::CacheScope::Private,
                            ),
                            cache_token: None,
                        })
                        .expect("resources list serialized");
                        if let Some(entries) = result_value
                            .get_mut("resources")
                            .and_then(|r| r.as_array_mut())
                            && let Err(msg) =
                                self.apply_apps_policy_to_items(entries, "resources/list")
                        {
                            return protocol_http_error(200, Some(request_id), -32603, msg, None);
                        }
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
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ResourcesRead { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        // Gateway-managed dynamic resources
                        // produced by bindings via `host.store_content`
                        // surface here under the `mcpg-resource://`
                        // scheme. Serve directly from the content store
                        // before falling through to operator-configured
                        // resource bindings.
                        if let Some(rest) = params.uri.strip_prefix("mcpg-resource://") {
                            // Managed `mcpg-resource://` reads run the same
                            // pre-dispatch authz stack as operator-configured
                            // resources — they must not bypass the trust floor
                            // / CEL / policy chain just because the content is
                            // gateway-produced.
                            let args_value = serde_json::json!({ "uri": params.uri });
                            if let Err(gate_response) = self
                                .evaluate_surface_gate(
                                    "resource",
                                    "resource.read.pre",
                                    &params.uri,
                                    &args_value,
                                    request_context,
                                    &request_id,
                                )
                                .await
                            {
                                return gate_response;
                            }
                            return self
                                .resource_read_managed(
                                    rest,
                                    &params.uri,
                                    request_id,
                                    request_context,
                                )
                                .await;
                        }
                        match self.resolve_resource_route(&params.uri) {
                            Some(route) => {
                                // surface-aware gate for resources/read.
                                let surface_label = match &route {
                                    ResourceRoute::Template { .. } => "resource_template",
                                    _ => "resource",
                                };
                                let args_value = serde_json::json!({ "uri": params.uri });
                                if let Err(gate_response) = self
                                    .evaluate_surface_gate(
                                        surface_label,
                                        "resource.read.pre",
                                        &params.uri,
                                        &args_value,
                                        request_context,
                                        &request_id,
                                    )
                                    .await
                                {
                                    // Audit: resources/read denied.
                                    let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                        request_id: request_context.request_id.as_str().to_owned(),
                                        session_id: request_context.session_id.clone(),
                                        tool_name: params.uri.clone(),
                                        identity: plugin_identity_from_request(request_context),
                                        transport: transport_label(&request_context.transport)
                                            .to_owned(),
                                        surface: surface_label.to_owned(),
                                    };
                                    let event =
                                        mcpg_plugin_host::audit_events::resource_read_denied_event(
                                            &audit_ctx,
                                            &params.uri,
                                            "surface_gate",
                                        );
                                    let _ = self.plugin_registry.emit_audit_event(&event).await;
                                    return gate_response;
                                }
                                match self.resource_read_result(route, &params, request_context) {
                                Ok(mut result) => {
                                    // SEP-1865 MCP Apps: a `ui://` resource
                                    // body may embed session-shaped data, so
                                    // never let it land in a shared cache —
                                    // force `private` scope regardless of what
                                    // the backend/upstream declared.
                                    if crate::protocol::shared::apps::is_ui_uri(&params.uri) {
                                        result.cache_scope = Some(
                                            crate::protocol::shared::caching::CacheScope::Private,
                                        );
                                    }
                                    // Audit: resources/read success.
                                    let bytes = serde_json::to_string(&result)
                                        .map(|s| s.len() as u64)
                                        .unwrap_or(0);
                                    let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                        request_id: request_context
                                            .request_id
                                            .as_str()
                                            .to_owned(),
                                        session_id: request_context.session_id.clone(),
                                        tool_name: params.uri.clone(),
                                        identity: plugin_identity_from_request(request_context),
                                        transport: transport_label(&request_context.transport)
                                            .to_owned(),
                                        surface: surface_label.to_owned(),
                                    };
                                    let event = mcpg_plugin_host::audit_events::resource_read_success_event(
                                        &audit_ctx,
                                        &params.uri,
                                        bytes,
                                    );
                                    let _ = self
                                        .plugin_registry
                                        .emit_audit_event(&event)
                                        .await;
                                    // SEP-1865 MCP Apps: clamp `_meta.ui`
                                    // (CSP / permissions / domain) on each
                                    // content block before egress. No-op
                                    // unless Apps is enabled; `strict`
                                    // rejects an out-of-policy `ui://`.
                                    let mut result_value = serde_json::to_value(result)
                                        .expect("resource read result serialized");
                                    if let Some(contents) = result_value
                                        .get_mut("contents")
                                        .and_then(|c| c.as_array_mut())
                                        && let Err(msg) = self
                                            .apply_apps_policy_to_items(contents, &params.uri)
                                    {
                                        return protocol_http_error(
                                            200,
                                            Some(request_id),
                                            -32603,
                                            msg,
                                            None,
                                        );
                                    }
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
                                Err(decode_err) => protocol_http_error(
                                    200,
                                    Some(request_id),
                                    -32603,
                                    format!("resource backend produced a non-conforming response: {decode_err}"),
                                    self.debug_error_data(
                                        request_context,
                                        "The backend for this resource binding must return `{ contents: [...] }` with spec-shaped entries.",
                                    ),
                                ),
                            }
                            }
                            None => {
                                // Audit: resources/read against an
                                // unregistered URI. Distinguishes attacker
                                // enumeration from a typo'd legitimate caller.
                                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    session_id: request_context.session_id.clone(),
                                    tool_name: params.uri.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    transport: transport_label(&request_context.transport)
                                        .to_owned(),
                                    surface: "resource".to_owned(),
                                };
                                let event =
                                    mcpg_plugin_host::audit_events::resource_read_not_found_event(
                                        &audit_ctx,
                                        &params.uri,
                                    );
                                let _ = self.plugin_registry.emit_audit_event(&event).await;
                                protocol_http_error(
                                    200,
                                    Some(request_id),
                                    -32602,
                                    format!("unknown resource: {}", params.uri),
                                    self.debug_error_data(
                                        request_context,
                                        "Use resources/list to discover available resource URIs.",
                                    ),
                                )
                            }
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ResourcesSubscribe { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        let session_id = request_context.session_id.as_deref().unwrap_or("");
                        // Verify the resource exists
                        if self.resolve_resource_route(&params.uri).is_none() {
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
                        }
                        // A subscription is a read that keeps arriving, and the
                        // first holder starts a backend poll watcher, so it runs
                        // the same authz stack `resources/read` does. Without
                        // this the trust floor, CEL `allow_if`, the policy chain
                        // and the per-resource governance a federated import
                        // attaches were all skipped for the streaming surface.
                        let args_value = serde_json::json!({ "uri": params.uri });
                        if let Err(gate_response) = self
                            .evaluate_surface_gate(
                                "resource",
                                "resource.subscribe.pre",
                                &params.uri,
                                &args_value,
                                request_context,
                                &request_id,
                            )
                            .await
                        {
                            return gate_response;
                        }
                        // Subscriber identity, for subject-scoped notification
                        // filtering.
                        let subscriber_identity =
                            Some(crate::runtime::subscription_store::SubscriberIdentity::
                                from_request_context(session_id, request_context));
                        match self
                            .subscriptions()
                            .subscribe_once(session_id, &params.uri, subscriber_identity)
                            .await
                        {
                            Ok(_established) => {
                                // Audit: resources/subscribe success.
                                let audit_ctx = mcpg_plugin_protocol::PluginContext {
                                    request_id: request_context.request_id.as_str().to_owned(),
                                    session_id: request_context.session_id.clone(),
                                    tool_name: params.uri.clone(),
                                    identity: plugin_identity_from_request(request_context),
                                    transport: transport_label(&request_context.transport)
                                        .to_owned(),
                                    surface: "resource".to_owned(),
                                };
                                let event =
                                    mcpg_plugin_host::audit_events::resource_subscribe_event(
                                        &audit_ctx,
                                        &params.uri,
                                    );
                                let _ = self.plugin_registry.emit_audit_event(&event).await;
                                ProtocolHttpResponse {
                                    http_status: 200,
                                    session_id_header: None,
                                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                        jsonrpc: JSONRPC_VERSION,
                                        id: request_id,
                                        result: serde_json::to_value(EmptyResult {})
                                            .expect("empty result serialized"),
                                    }),
                                }
                            }
                            Err(e) => protocol_http_error(
                                200,
                                Some(request_id),
                                -32602,
                                e.to_string(),
                                None,
                            ),
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ResourcesUnsubscribe { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        let session_id = request_context.session_id.as_deref().unwrap_or("");
                        let was_subscribed = self
                            .subscriptions()
                            .unsubscribe_once(session_id, &params.uri)
                            .await;
                        // Audit: resources/unsubscribe.
                        let audit_ctx = mcpg_plugin_protocol::PluginContext {
                            request_id: request_context.request_id.as_str().to_owned(),
                            session_id: request_context.session_id.clone(),
                            tool_name: params.uri.clone(),
                            identity: plugin_identity_from_request(request_context),
                            transport: transport_label(&request_context.transport).to_owned(),
                            surface: "resource".to_owned(),
                        };
                        let event = mcpg_plugin_host::audit_events::resource_unsubscribe_event(
                            &audit_ctx,
                            &params.uri,
                            was_subscribed,
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        if was_subscribed {
                            let watch = self.watch_engine.clone();
                            let uri = params.uri.clone();
                            tokio::spawn(async move {
                                watch.notify_unsubscribe(&uri).await;
                            });
                        }
                        ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result: serde_json::to_value(EmptyResult {})
                                    .expect("empty result serialized"),
                            }),
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ResourcesTemplatesList { request_id, params } => {
                match request_context.load_session_cached(&*self.session_store, true) {
                    Ok(_) => {
                        let (page, next_cursor) = self.enumerate_resource_templates_page(
                            request_context,
                            params.cursor.as_deref(),
                        );
                        // Audit: resource-template enumeration.
                        let event = mcpg_plugin_host::audit_events::list_call_event(
                            plugin_identity_from_request(request_context),
                            request_context.request_id.as_str(),
                            request_context.session_id.as_deref(),
                            "resource_template",
                            page.len() as u64,
                            transport_label(&request_context.transport),
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        // SEP-1865 MCP Apps: clamp each template's `_meta.ui`
                        // to operator policy on the legacy wire too; no-op
                        // unless Apps is enabled, strict rejects out-of-policy.
                        let mut result_value = serde_json::to_value(ResourceTemplatesListResult {
                            resource_templates: page,
                            next_cursor,
                            ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_LIST_TTL_MS),
                            cache_scope: Some(
                                crate::protocol::shared::caching::CacheScope::Private,
                            ),
                            cache_token: None,
                        })
                        .expect("resource templates list serialized");
                        if let Some(entries) = result_value
                            .get_mut("resourceTemplates")
                            .and_then(|r| r.as_array_mut())
                            && let Err(msg) =
                                self.apply_apps_policy_to_items(entries, "resources/templates/list")
                        {
                            return protocol_http_error(200, Some(request_id), -32603, msg, None);
                        }
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
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            CapabilityOperation::ToolsCall { .. } | CapabilityOperation::Complete { .. } => {
                unreachable!("tools/call and completion are dispatched before list operations")
            }
        }
    }

    fn prompt_get_result(
        &self,
        route: PromptRoute,
        params: &crate::protocol::PromptGetParams,
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
                        },
                    ))
                });
                match outcome {
                    Ok(value) => federated_prompt_get_result(value),
                    Err(e) => {
                        // The upstream error carries issuer diagnostics — a
                        // preview of the raw Vault response body, provider
                        // names and endpoint status, upstream URLs and
                        // internal hostnames. `tools/call` already keeps
                        // those operator-only; these sibling surfaces
                        // returned them straight to the caller.
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
        params: &crate::protocol::ResourceReadParams,
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
                    context: request_context.clone(),
                    tool_name: profile.clone(),
                    arguments: Some(args.clone()),
                    expr_ctx: request_context.to_expr_context(profile, Some(&args)),
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
                let route = self.tool_route_for_binding(profile);
                let snapshot = route
                    .needs_runtime_snapshot()
                    .then(|| self.runtime_snapshot());
                let result = self.execution_dispatcher.dispatch_tool_call(
                    route,
                    &execution_request,
                    snapshot,
                );
                // resource surface uses a strict native codec.
                invocation::decode_resource_result(&result, &params.uri)
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
                    context: request_context.clone(),
                    tool_name: profile.clone(),
                    arguments: Some(args_value.clone()),
                    expr_ctx: request_context.to_expr_context(profile, Some(&args_value)),
                    progress_token: None,
                    request_log_level: None,
                    legacy_session_log_level: self.legacy_session_log_level(request_context),
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
                invocation::decode_resource_result(&result, &params.uri)
            }
            ResourceRoute::Federated {
                ref source,
                ref upstream_uri,
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
                        },
                    ))
                });
                match outcome {
                    Ok(value) => Ok(federated_resource_read_result(value)),
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
        request_id: serde_json::Value,
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

        // Parse `mcpg-resource://<id>/<resource>` (or bare-resource
        // legacy form). The `id` arg is what was already stripped of
        // the `mcpg-resource://` scheme; `full_uri` is the original.
        let (storage_id, resolved_id) = registry.parse_resource_uri(full_uri);
        // Fall back to the passed `id` when parse returned a bare value —
        // keeps callers that pre-stripped the scheme working.
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
        let contents = if is_text {
            match std::str::from_utf8(&content.bytes) {
                Ok(s) => {
                    crate::protocol::ResourceContents::Text(crate::protocol::ResourceTextContents {
                        uri: full_uri.to_owned(),
                        mime_type: Some(content.mime_type.clone()),
                        text: s.to_owned(),
                        meta: None,
                    })
                }
                Err(_) => {
                    crate::protocol::ResourceContents::Blob(crate::protocol::BlobResourceContents {
                        uri: full_uri.to_owned(),
                        mime_type: Some(content.mime_type.clone()),
                        blob: {
                            use base64::Engine;
                            base64::engine::general_purpose::STANDARD.encode(&content.bytes)
                        },
                        meta: None,
                    })
                }
            }
        } else {
            crate::protocol::ResourceContents::Blob(crate::protocol::BlobResourceContents {
                uri: full_uri.to_owned(),
                mime_type: Some(content.mime_type.clone()),
                blob: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(&content.bytes)
                },
                meta: None,
            })
        };

        let result = crate::protocol::ResourceReadResult {
            contents: vec![contents],
            ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
            cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
            cache_token: None,
        };
        ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: serde_json::to_value(result)
                    .expect("managed resource read result serialized"),
            }),
        }
    }
}
