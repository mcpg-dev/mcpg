use super::*;

impl GatewayRuntime {
    /// Enumerate the visible + curated tool catalog page for a
    /// request. Shared by both the legacy `tools/list` dispatch arm
    /// and the modern handler's `tools/list` implementation.
    /// Filters by the operator-configured pre-dispatch
    /// policy, walks the operator-configured catalog provider
    /// chain, and paginates with the session-bound
    /// cursor key.
    ///
    /// Returns `(page, next_cursor)` where `page` is a `Vec` of
    /// backend [`crate::backends::ToolDescriptor`] (legacy shape).
    /// The modern handler converts each entry to its wire shape and
    /// stamps the SEP-2549 cache fields onto the result envelope.
    pub(crate) async fn enumerate_tools_page(
        &self,
        request_context: &RequestContext,
        cursor: Option<&str>,
    ) -> (Vec<crate::backends::ToolDescriptor>, Option<String>) {
        let all_tools = self.capability_registry.tools();
        let visible_tools: Vec<_> = all_tools
            .into_iter()
            .filter(|tool| {
                let policy_context =
                    ToolPolicyContext::from_request_context(request_context, &tool.name);
                self.pre_dispatch_policy.is_tool_visible(&policy_context)
            })
            .collect();
        // Walk the catalog provider chain on every
        // tools/list. Empty chain ⇒ no-op.
        let curated_tools = self
            .apply_catalog_chain(visible_tools, request_context)
            .await;
        paginate_list_bound(
            &curated_tools,
            cursor,
            Some(&self.cursor_binding_key(request_context.session_id.as_deref())),
        )
    }

    /// Enumerate the prompt catalog page for a request. Mirror of
    /// [`Self::enumerate_tools_page`] for prompts. Shared by the
    /// legacy `prompts/list` arm and the modern handler's modern
    /// `prompts/list`.
    pub(crate) fn enumerate_prompts_page(
        &self,
        request_context: &RequestContext,
        cursor: Option<&str>,
    ) -> (Vec<crate::backends::PromptDescriptor>, Option<String>) {
        // Same per-caller gate `tools/list` applies. `prompts/get` already
        // enforces `minimum_trust` / `allow_if` for these names, so listing
        // them unfiltered disclosed exactly the catalog those rules exist to
        // withhold. Filtered before pagination so a caller's cursors stay
        // consistent with what they can actually see.
        let all_prompts: Vec<_> = self
            .capability_registry
            .prompts()
            .into_iter()
            .filter(|prompt| self.surface_is_visible(request_context, &prompt.name))
            .collect();
        paginate_list_bound(
            &all_prompts,
            cursor,
            Some(&self.cursor_binding_key(request_context.session_id.as_deref())),
        )
    }

    /// Per-caller visibility for a non-tool surface, keyed by the same
    /// surface-scoped name the read path gates on.
    pub(crate) fn surface_is_visible(&self, request_context: &RequestContext, name: &str) -> bool {
        let policy_context = ToolPolicyContext::from_request_context(request_context, name);
        self.pre_dispatch_policy.is_tool_visible(&policy_context)
    }

    /// Enumerate the resource catalog page for a request,
    /// handling the composite (static + dynamic-fanout) cursor
    /// shape. Shared by the legacy `resources/list` arm and the
    /// modern handler's `resources/list`.
    ///
    /// Three cursor cases:
    /// 1. `None` ⇒ page 1: walk static + fan out every dynamic
    ///    provider's first page.
    /// 2. Composite (`c.…`) ⇒ page N: page static if more remains;
    ///    else walk only the providers still mid-stream.
    /// 3. Bare-offset ⇒ legacy backward-compat: behaves as the
    ///    pre-composite paginator did.
    pub(crate) async fn enumerate_resources_page(
        &self,
        request_context: &RequestContext,
        cursor: Option<&str>,
    ) -> (Vec<crate::backends::ResourceDescriptor>, Option<String>) {
        let bind_key = self.cursor_binding_key(request_context.session_id.as_deref());
        let mut all_resources = self.capability_registry.resources();
        // Gateway-authored apps are synthetic resources held
        // on the runtime, not in the capability registry — surface them
        // in `resources/list` alongside the registered ones. Skip any whose
        // URI a registered resource already claims (the app still wins on
        // read via resolve_resource_route) so the list never double-lists.
        for app in self.gateway_apps.values() {
            let descriptor = app.to_descriptor();
            if !all_resources.iter().any(|r| r.uri == descriptor.uri) {
                all_resources.push(descriptor);
            }
        }
        // Same per-caller gate `tools/list` applies, keyed on the URI the
        // read path gates on. Applied before pagination so cursors stay
        // consistent with what this caller can see.
        all_resources.retain(|r| self.surface_is_visible(request_context, &r.uri));
        let composite = cursor.and_then(|c| decode_composite_cursor(c, Some(&bind_key)));
        let (mut page, outgoing_static, outgoing_dyn);
        match composite {
            None if cursor.is_none() => {
                let (p, next_static) = paginate_list_bound(&all_resources, None, Some(&bind_key));
                page = p;
                let static_offset = next_static
                    .as_deref()
                    .and_then(|c| decode_cursor(c, Some(&bind_key)));
                let targets: Vec<(String, String, Option<String>)> = self
                    .dynamic_list_bindings
                    .iter()
                    .map(|(b, k)| (b.clone(), k.clone(), None))
                    .collect();
                let remaining = self.merge_dynamic_resources(&mut page, &targets).await;
                page.retain(|r| self.surface_is_visible(request_context, &r.uri));
                outgoing_static = static_offset;
                outgoing_dyn = remaining;
            }
            None => {
                let (p, next_static) = paginate_list_bound(&all_resources, cursor, Some(&bind_key));
                page = p;
                outgoing_static = next_static
                    .as_deref()
                    .and_then(|c| decode_cursor(c, Some(&bind_key)));
                outgoing_dyn = Vec::new();
            }
            Some(c) => {
                page = Vec::new();
                if let Some(offset) = c.s {
                    let cursor_for_static = encode_cursor(offset, Some(&bind_key));
                    let (p, next_static) = paginate_list_bound(
                        &all_resources,
                        Some(&cursor_for_static),
                        Some(&bind_key),
                    );
                    page = p;
                    outgoing_static = next_static
                        .as_deref()
                        .and_then(|c| decode_cursor(c, Some(&bind_key)));
                    outgoing_dyn = c.d;
                } else {
                    let targets: Vec<(String, String, Option<String>)> =
                        c.d.into_iter()
                            .filter_map(|dc| {
                                self.dynamic_list_bindings
                                    .iter()
                                    .find(|(b, _)| b == &dc.b)
                                    .map(|(b, k)| (b.clone(), k.clone(), Some(dc.c)))
                            })
                            .collect();
                    let remaining = self.merge_dynamic_resources(&mut page, &targets).await;
                    page.retain(|r| self.surface_is_visible(request_context, &r.uri));
                    outgoing_static = None;
                    outgoing_dyn = remaining;
                }
            }
        }
        let outgoing = CompositeCursor {
            s: outgoing_static,
            d: outgoing_dyn,
        };
        let next_cursor = if outgoing.is_done() {
            None
        } else {
            Some(encode_composite_cursor(&outgoing, Some(&bind_key)))
        };
        (page, next_cursor)
    }

    /// Enumerate the resource-template catalog page. Simple wrapper
    /// around [`paginate_list_bound`] with the session-bound cursor
    /// key. Shared by the legacy `resources/templates/list` arm and
    /// the modern handler's same method.
    pub(crate) fn enumerate_resource_templates_page(
        &self,
        request_context: &RequestContext,
        cursor: Option<&str>,
    ) -> (Vec<crate::protocol::ResourceTemplate>, Option<String>) {
        // A URI template names the resource family it expands to, so an
        // unfiltered list leaks the same shape `resources/read` gates.
        let all_templates: Vec<_> = self
            .capability_registry
            .resource_templates()
            .into_iter()
            .filter(|t| self.surface_is_visible(request_context, &t.uri_template))
            .collect();
        paginate_list_bound(
            &all_templates,
            cursor,
            Some(&self.cursor_binding_key(request_context.session_id.as_deref())),
        )
    }

    /// Walk the bound `catalog_provider` chain on every
    /// `tools/list` request. Each provider receives the previous
    /// provider's filtered + enriched output. Returns the curated
    /// tool list with `_meta.mcpg.catalog` annotations injected.
    ///
    /// Empty chain → input flows through unchanged (no allocation
    /// beyond the `visible_tools` Vec already passed in).
    pub(crate) async fn apply_catalog_chain(
        &self,
        visible_tools: Vec<crate::backends::ToolDescriptor>,
        request_context: &RequestContext,
    ) -> Vec<crate::backends::ToolDescriptor> {
        let chain = self.plugin_registry.catalog_chain();
        if chain.is_empty() {
            return visible_tools;
        }

        // Index original ToolDescriptors by name so we can preserve
        // every field (annotations, execution, icons, _meta) when
        // we rebuild the response — the catalog chain only sees a
        // narrow projection (ProtocolToolDescriptor).
        let mut by_name: std::collections::BTreeMap<String, crate::backends::ToolDescriptor> =
            visible_tools
                .into_iter()
                .map(|t| (t.name.clone(), t))
                .collect();

        // Build the chain input from the indexed tools.
        let mut in_progress: Vec<mcpg_plugin_protocol::catalog::EnrichedToolDescriptor> = by_name
            .values()
            .map(|t| {
                mcpg_plugin_protocol::catalog::EnrichedToolDescriptor::from_base(
                    mcpg_plugin_protocol::catalog::ProtocolToolDescriptor {
                        name: t.name.clone(),
                        title: t.title.clone(),
                        description: t.description.clone(),
                        input_schema: t.input_schema.clone(),
                        output_schema: t.output_schema.clone(),
                    },
                )
            })
            .collect();

        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: "tools/list".to_owned(),
            surface: "tool".to_owned(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
        };

        // Audit: accumulate per-provider hidden names so
        // operators can answer "did Alice see tool X in tools/list?"
        // from the audit lane. The chain is sequential, so the first
        // provider that drops a tool gets the attribution.
        let before_count = in_progress.len() as u64;
        let mut hidden: Vec<(String, String)> = Vec::new();
        for provider in chain {
            let plugin_id = provider.manifest().id.clone();
            let names_before: std::collections::BTreeSet<String> =
                in_progress.iter().map(|t| t.base.name.clone()).collect();
            in_progress = provider.filter_and_enrich(&plugin_ctx, &in_progress).await;
            let names_after: std::collections::BTreeSet<String> =
                in_progress.iter().map(|t| t.base.name.clone()).collect();
            for removed in names_before.difference(&names_after) {
                hidden.push((removed.clone(), plugin_id.clone()));
            }
        }
        let after_count = in_progress.len() as u64;
        let event = mcpg_plugin_host::audit_events::catalog_filtered_event(
            plugin_identity_from_request(request_context),
            request_context.request_id.as_str(),
            request_context.session_id.as_deref(),
            "tool",
            before_count,
            after_count,
            hidden,
        );
        let _ = self.plugin_registry.emit_audit_event(&event).await;

        // Rebuild the response: for each surviving descriptor in
        // chain order, look up the original ToolDescriptor and
        // inject the catalog metadata into its `_meta` field
        // (under `mcpg.catalog`).
        let mut out = Vec::with_capacity(in_progress.len());
        for enriched in in_progress {
            let Some(mut original) = by_name.remove(&enriched.base.name) else {
                // Defensive: a buggy provider could in principle add
                // tools (the trait forbids it). Drop silently — the
                // gateway's binding registry remains the source of
                // truth.
                continue;
            };
            if let Some(catalog) = enriched.catalog
                && !catalog.is_empty()
            {
                let catalog_value = match serde_json::to_value(&catalog) {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(
                            tool_name = %enriched.base.name,
                            error = %err,
                            "failed to serialize catalog metadata; \
                             sending tool without _meta enrichment",
                        );
                        out.push(original);
                        continue;
                    }
                };
                let meta = original
                    .meta
                    .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                if let serde_json::Value::Object(map) = meta {
                    let mcpg_entry = map
                        .entry("mcpg")
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                    if let serde_json::Value::Object(mcpg_map) = mcpg_entry {
                        mcpg_map.insert("catalog".into(), catalog_value);
                    }
                }
            }
            out.push(original);
        }
        out
    }

    /// Look up the BackendInvocationRoute for a prompt/resource binding by profile name.
    pub(crate) fn tool_route_for_binding(&self, profile: &str) -> BackendInvocationRoute {
        self.capability_registry.binding_route(profile).unwrap_or(
            BackendInvocationRoute::MockResponse {
                profile: profile.to_owned(),
            },
        )
    }
}
