use super::*;
use crate::config::BackendConfig;
use arc_swap::ArcSwap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Compiled registry of all MCP capabilities (tools, prompts, resources, resource
/// templates) built from operator config at startup. Holds pre-compiled JSON Schema
/// validators, URI template matchers, and route maps for dispatch. Lists are
/// returned in deterministic (insertion) order; pagination uses HMAC-bound cursors
/// so a cursor from one session cannot be replayed on another.
#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    tools: Vec<RegisteredTool>,
    prompts: Vec<RegisteredPrompt>,
    resources: Vec<RegisteredResource>,
    resource_templates: Vec<crate::protocol::ResourceTemplate>,
    /// Compiled templates for `resources/read` URI matching. Stores the
    /// raw template, the binding profile name (for backend dispatch), and the
    /// ordered list of variable names so matching can capture them.
    resource_template_routes: Vec<CompiledResourceTemplate>,
    schema_validators: HashMap<String, Arc<jsonschema::Validator>>,
    /// Compiled output schema validators for tools that declare `outputSchema`.
    output_schema_validators: HashMap<String, Arc<jsonschema::Validator>>,
    /// Route map for *all* bindings (tool, prompt, resource) — used to dispatch
    /// prompt/resource bindings through the same execution engine as tools.
    binding_routes: HashMap<String, BackendInvocationRoute>,
    /// Completion values for prompt arguments: (prompt_name, arg_name) → values.
    prompt_completions: HashMap<(String, String), Vec<String>>,
    /// Completion values for resource template variables:
    /// (template_profile, variable_name) → values. Populated at binding
    /// registration from `BackendConfig.variable_completions`; consumed
    /// by `complete_argument` for `ref/resource` requests.
    resource_template_completions: HashMap<(String, String), Vec<String>>,
    /// Dynamic completion entries: (template_profile, variable_name) →
    /// (backend_kind, opaque config). Populated when the operator
    /// declares `variable_completions: { var: { kind: dynamic, backend,
    /// config } }`. The dispatcher calls
    /// `BackendPlugin::complete_template_variable(backend, var, prefix,
    /// &config)` and clamps the result to 100.
    resource_template_dynamic_completions: HashMap<(String, String), DynamicCompletionEntry>,
    /// Runtime-mutable overlay of federated capabilities.
    /// Swapped atomically by the `FederationEngine`; the native
    /// slices above stay immutable. Shared with the engine via
    /// [`Self::federated_overlay`].
    federated: Arc<ArcSwap<FederatedCatalog>>,
    /// Client-facing keys already reported as shadowed, so a standing
    /// misconfiguration is logged once rather than on every list call.
    /// Keyed `"<surface>:<key>"`.
    reported_shadowed: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

/// One dynamic-completion target stored on the registry. The
/// `backend_name` is the operator's binding name (passed verbatim to
/// the plugin's `complete_template_variable` call); `kind` is the
/// `BackendPlugin::kind()` selector used to look the plugin up in the
/// `PluginRegistry`. `config` is forwarded as-is.
#[derive(Debug, Clone)]
pub struct DynamicCompletionEntry {
    pub backend_name: String,
    pub kind: String,
    pub config: serde_json::Value,
}

/// Compiled `uri_template` (RFC 6570 simple level-1 form like `scheme://{var}/...`)
/// used for resource-template URI matching.
#[derive(Debug, Clone)]
pub(crate) struct CompiledResourceTemplate {
    /// Backend binding profile to dispatch template reads through.
    profile: String,
    /// Literal segments interleaved with variable names, in order.
    parts: Vec<TemplatePart>,
    /// Original `{var}` names in declaration order.
    variables: Vec<String>,
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(String),
    Variable(String),
}

/// Profile name bindings for built-in debug tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugToolBackends {
    pub command_probe_profile: String,
    pub network_probe_profile: String,
    pub network_json_call_profile: String,
}

impl Default for DebugToolBackends {
    fn default() -> Self {
        Self {
            command_probe_profile: DEFAULT_COMMAND_PROFILE.to_owned(),
            network_probe_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
            network_json_call_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
        }
    }
}

/// Controls which debug tools are visible in `tools/list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugToolExposure {
    pub command_probe: bool,
    pub network_probe: bool,
    pub network_json_call: bool,
    pub operational_overview_prompt: bool,
    pub runtime_overview_resource: bool,
}

impl Default for DebugToolExposure {
    fn default() -> Self {
        Self {
            command_probe: true,
            network_probe: true,
            network_json_call: false,
            operational_overview_prompt: true,
            runtime_overview_resource: true,
        }
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new(
            false,
            DebugToolBackends::default(),
            DebugToolExposure::default(),
            &[],
            &[],
            &[],
            &[],
            None,
        )
    }
}

impl CapabilityRegistry {
    /// Build a capability registry from operator-declared bindings.
    ///
    /// Bindings arrive as four typed lists keyed by MCP capability
    /// (tool / prompt / resource / resource-template) rather than a
    /// single `bindings: Vec<BackendConfig>`, so the registry can
    /// dispatch by list membership rather than re-checking a `kind:`
    /// field on every entry.
    pub fn new(
        debug_enabled: bool,
        debug_tool_bindings: DebugToolBackends,
        debug_tool_exposure: DebugToolExposure,
        tool_bindings: &[BackendConfig],
        prompt_bindings: &[BackendConfig],
        resource_bindings: &[BackendConfig],
        resource_template_bindings: &[BackendConfig],
        plugin_registry: Option<&mcpg_plugin_host::PluginRegistry>,
    ) -> Self {
        let mut tools = Vec::new();

        if debug_enabled {
            tools.extend([
                RegisteredTool {
                    descriptor: ToolDescriptor {
                        name: "mcpg.runtime.snapshot".to_owned(),
                        title: Some("MCPG Runtime Snapshot".to_owned()),
                        description: "Return the current MCPG runtime snapshot.".to_owned(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "additionalProperties": false,
                        }),
                        output_schema: None,
                        annotations: None,
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    route: BackendInvocationRoute::RuntimeSnapshot,
                },
                RegisteredTool {
                    descriptor: ToolDescriptor {
                        name: "mcpg.request.echo".to_owned(),
                        title: Some("MCPG Request Echo".to_owned()),
                        description: "Return normalized request and argument details through the adapter-facing execution seam.".to_owned(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "additionalProperties": true,
                        }),
                        output_schema: None,
                        annotations: None,
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    route: BackendInvocationRoute::RequestEcho,
                },
            ]);

            if debug_tool_exposure.command_probe {
                tools.push(RegisteredTool {
                    descriptor: ToolDescriptor {
                        name: "mcpg.debug.command_probe".to_owned(),
                        title: Some("MCPG Debug Command Probe".to_owned()),
                        description: "Execute the configured debug command through the command-based execution path.".to_owned(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "additionalProperties": true,
                        }),
                        output_schema: None,
                        annotations: None,
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    route: BackendInvocationRoute::CommandProbe {
                        profile: debug_tool_bindings.command_probe_profile.clone(),
                    },
                });
            }

            if debug_tool_exposure.network_probe {
                tools.push(RegisteredTool {
                    descriptor: ToolDescriptor {
                        name: "mcpg.debug.network_probe".to_owned(),
                        title: Some("MCPG Debug Network Probe".to_owned()),
                        description: "Execute the configured debug network probe through the network-based execution path.".to_owned(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "additionalProperties": true,
                        }),
                        output_schema: None,
                        annotations: None,
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    route: BackendInvocationRoute::NetworkProbe {
                        profile: debug_tool_bindings.network_probe_profile.clone(),
                    },
                });
            }

            if debug_tool_exposure.network_json_call {
                tools.push(RegisteredTool {
                    descriptor: ToolDescriptor {
                        name: "mcpg.debug.network_json_call".to_owned(),
                        title: Some("MCPG Debug Network JSON Call".to_owned()),
                        description: "POST the tool arguments as JSON to the configured debug network endpoint through the network-based execution path.".to_owned(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "additionalProperties": true,
                        }),
                        output_schema: None,
                        annotations: None,
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    route: BackendInvocationRoute::NetworkJsonCall {
                        profile: debug_tool_bindings.network_json_call_profile.clone(),
                    },
                });
            }
        }

        // Register operator-defined bindings. Each list dispatches
        // through its own per-capability path; the list itself encodes
        // the binding kind.
        let mut prompts = Vec::new();
        let mut resources = Vec::new();
        let mut schema_validators: HashMap<String, Arc<jsonschema::Validator>> = HashMap::new();
        let mut output_schema_validators: HashMap<String, Arc<jsonschema::Validator>> =
            HashMap::new();
        let mut prompt_completions: HashMap<(String, String), Vec<String>> = HashMap::new();
        for binding in tool_bindings {
            {
                {
                    let default_schema = serde_json::json!({
                        "type": "object",
                        "additionalProperties": true,
                    });
                    // Compose input schema: plugin-derived base (if the
                    // plugin exposes one) with operator-supplied overlay
                    // on top. Operator fields win at every key so
                    // hand-authored descriptions and enums stick.
                    let derived_input = binding_plugin_kind(&binding.backend)
                        .and_then(|kind| plugin_registry?.backend(kind))
                        .and_then(|plugin| plugin.input_schema(&binding.name));
                    let input_schema = match (binding.input_schema.clone(), derived_input) {
                        (Some(operator), Some(derived)) => {
                            mcpg_plugin_protocol::schema::merge_schema(derived, operator)
                        }
                        (Some(operator), None) => operator,
                        (None, Some(derived)) => derived,
                        (None, None) => default_schema,
                    };
                    // Same composition for output schema (P9.12): the
                    // plugin (SQL) may derive one from prepared-statement
                    // column metadata; operator can override or extend.
                    let derived_output = binding_plugin_kind(&binding.backend)
                        .and_then(|kind| plugin_registry?.backend(kind))
                        .and_then(|plugin| plugin.output_schema(&binding.name));
                    let composed_output_schema =
                        match (binding.output_schema.clone(), derived_output) {
                            (Some(operator), Some(derived)) => Some(
                                mcpg_plugin_protocol::schema::merge_schema(derived, operator),
                            ),
                            (Some(operator), None) => Some(operator),
                            (None, Some(derived)) => Some(derived),
                            (None, None) => None,
                        };
                    let route = classify_behavioral_route(binding);
                    tools.push(RegisteredTool {
                        descriptor: ToolDescriptor {
                            name: binding.name.clone(),
                            title: binding.title.clone(),
                            description: binding.description.clone(),
                            input_schema,
                            output_schema: composed_output_schema.clone(),
                            annotations: build_tool_annotations(binding),
                            execution: build_tool_execution(binding),
                            icons: None,
                            meta: None,
                        },
                        route,
                    });

                    // Compile schema validator for bindings with explicit input_schema.
                    // Operator-supplied schemas are already compile-checked
                    // fail-closed at config-validate; a failure here can only
                    // come from a plugin-derived schema, which the operator
                    // cannot fix in config. Surface it loudly rather than
                    // dropping the validator silently (which would leave the
                    // tool running unvalidated — fail-open).
                    if let Some(ref schema) = binding.input_schema {
                        match crate::config::schema_safety::compile_checked(
                            schema,
                            &format!("binding '{}' input_schema", binding.name),
                        ) {
                            Ok(validator) => {
                                schema_validators.insert(binding.name.clone(), Arc::new(validator));
                            }
                            Err(e) => {
                                tracing::error!(
                                    binding = %binding.name,
                                    error = %e,
                                    "input schema failed to compile at registration; tool will \
                                     run UNVALIDATED — fix the plugin-derived schema"
                                );
                            }
                        }
                    }
                    // Compile output schema validator for bindings
                    // with any effective output_schema — operator-
                    // supplied or plugin-derived (P9.12).
                    if let Some(ref schema) = composed_output_schema {
                        match crate::config::schema_safety::compile_checked(
                            schema,
                            &format!("binding '{}' output_schema", binding.name),
                        ) {
                            Ok(validator) => {
                                output_schema_validators
                                    .insert(binding.name.clone(), Arc::new(validator));
                            }
                            Err(e) => {
                                tracing::error!(
                                    binding = %binding.name,
                                    error = %e,
                                    "output schema failed to compile at registration; output \
                                     validation disabled for this tool"
                                );
                            }
                        }
                    }
                }
            }
        }
        for binding in prompt_bindings {
            {
                {
                    let arguments = binding
                        .prompt_arguments
                        .as_ref()
                        .map(|args| {
                            args.iter()
                                .map(|a| {
                                    // Store completions if provided
                                    if let Some(ref completions) = a.completions {
                                        prompt_completions.insert(
                                            (binding.name.clone(), a.name.clone()),
                                            completions.clone(),
                                        );
                                    }
                                    PromptArgument {
                                        name: a.name.clone(),
                                        title: None,
                                        description: a.description.clone(),
                                        required: a.required,
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    prompts.push(RegisteredPrompt {
                        descriptor: PromptDescriptor {
                            name: binding.name.clone(),
                            title: binding.title.clone(),
                            description: Some(binding.description.clone()),
                            arguments,
                            icons: None,
                            meta: None,
                        },
                        route: PromptRoute::Binding {
                            profile: binding.name.clone(),
                        },
                    });
                }
            }
        }
        for binding in resource_bindings {
            {
                {
                    let uri = binding
                        .uri
                        .clone()
                        .unwrap_or_else(|| format!("mcpg://resources/{}", binding.name));
                    // Merge mcpAppUrl into _meta if configured.
                    let meta = merge_mcp_app_url(
                        binding.descriptor_meta.clone(),
                        binding.mcp_app_url.as_deref(),
                    );
                    // Store the pattern for dynamic resolution only if it
                    // contains CEL expressions; static URLs are already in _meta.
                    let app_url_pattern = binding
                        .mcp_app_url
                        .as_ref()
                        .filter(|u| u.contains("${"))
                        .cloned();
                    resources.push(RegisteredResource {
                        descriptor: ResourceDescriptor {
                            uri,
                            name: binding.name.clone(),
                            title: binding.title.clone(),
                            description: Some(binding.description.clone()),
                            mime_type: binding.mime_type.clone(),
                            size: binding.resource_size,
                            icons: crate::config::binding_icons(binding.icons.as_ref()),
                            annotations: binding
                                .resource_annotations
                                .as_ref()
                                .map(|a| a.to_protocol()),
                            meta,
                        },
                        app_url_pattern,
                        route: ResourceRoute::Binding {
                            profile: binding.name.clone(),
                        },
                    });
                }
            }
        }
        // Resource templates are registered separately below — they
        // still need a route for resource reads with expanded URIs.

        // Add debug prompts
        if debug_enabled && debug_tool_exposure.operational_overview_prompt {
            prompts.push(RegisteredPrompt {
                descriptor: PromptDescriptor {
                    name: "mcpg_operational_overview".to_owned(),
                    title: Some("MCPG Operational Overview".to_owned()),
                    description: Some(
                        "Summarize the current MCPG server posture and capability surface."
                            .to_owned(),
                    ),
                    arguments: vec![],
                    icons: None,
                    meta: None,
                },
                route: PromptRoute::OperationalOverview,
            });
        }

        // Add debug resources
        if debug_enabled && debug_tool_exposure.runtime_overview_resource {
            resources.push(RegisteredResource {
                descriptor: ResourceDescriptor {
                    uri: "mcpg://runtime/overview".to_owned(),
                    name: "runtime-overview".to_owned(),
                    title: Some("MCPG Runtime Overview".to_owned()),
                    description: Some(
                        "Current runtime and readiness details for the gateway.".to_owned(),
                    ),
                    mime_type: Some("application/json".to_owned()),
                    size: None,
                    annotations: None,
                    icons: None,
                    meta: None,
                },
                route: ResourceRoute::RuntimeOverview,
                app_url_pattern: None,
            });
        }

        // Build route map for ALL bindings (used for prompt/resource dispatch)
        let mut binding_routes: HashMap<String, BackendInvocationRoute> = HashMap::new();
        let all_binding_lists = [
            tool_bindings,
            prompt_bindings,
            resource_bindings,
            resource_template_bindings,
        ];
        for binding in all_binding_lists.iter().copied().flatten() {
            let route = classify_behavioral_route(binding);
            binding_routes.insert(binding.name.clone(), route);
        }

        // Build a (binding name → plugin kind) lookup so dynamic
        // completion entries can be validated against registered
        // bindings at boot. Dangling backend names log a warning and
        // drop the entry — the variable then falls through to the
        // empty-completion path at request time (spec-valid empty
        // result).
        //
        // The kind is what the dispatch path uses to look up the
        // plugin in the host registry; bindings without a routable
        // kind (HTTP / Command / Mock — they don't go through a
        // BackendPlugin in production) get a sentinel `"mock"` here
        // so test infrastructure can register a mock plugin under
        // that kind and observe completion dispatch end-to-end. In
        // production a missing plugin lookup degrades silently to
        // empty completion (UX hint, not load-bearing).
        let mut binding_kinds: HashMap<String, String> = HashMap::new();
        for list in [
            tool_bindings,
            prompt_bindings,
            resource_bindings,
            resource_template_bindings,
        ] {
            for b in list {
                let kind = binding_plugin_kind(&b.backend)
                    .map(str::to_owned)
                    .unwrap_or_default();
                binding_kinds.insert(b.name.clone(), kind);
            }
        }

        // Register resource templates from resource_template bindings
        let mut resource_templates = Vec::new();
        let mut resource_template_routes: Vec<CompiledResourceTemplate> = Vec::new();
        let mut resource_template_completions: HashMap<(String, String), Vec<String>> =
            HashMap::new();
        let mut resource_template_dynamic_completions: HashMap<
            (String, String),
            DynamicCompletionEntry,
        > = HashMap::new();
        for binding in resource_template_bindings {
            if let Some(ref uri_template) = binding.uri_template {
                let meta = merge_mcp_app_url(
                    binding.descriptor_meta.clone(),
                    binding.mcp_app_url.as_deref(),
                );
                resource_templates.push(crate::protocol::ResourceTemplate {
                    uri_template: uri_template.clone(),
                    name: binding.name.clone(),
                    title: binding.title.clone(),
                    description: Some(binding.description.clone()),
                    mime_type: binding.mime_type.clone(),
                    annotations: None,
                    icons: crate::config::binding_icons(binding.icons.as_ref()),
                    meta,
                });
                if let Some(compiled) = compile_resource_template(&binding.name, uri_template) {
                    if let Some(ref completions_map) = binding.variable_completions {
                        for (var_name, source) in completions_map {
                            if !compiled.variables.iter().any(|v| v == var_name) {
                                tracing::warn!(
                                    backend = %binding.name,
                                    template = %uri_template,
                                    variable = %var_name,
                                    "variable_completions key does not match a `{{variable}}` declared in uri_template; entry dropped"
                                );
                                continue;
                            }
                            if let Some(values) = source.as_static_values() {
                                resource_template_completions.insert(
                                    (binding.name.clone(), var_name.clone()),
                                    values.to_vec(),
                                );
                            } else if let Some((dyn_backend, dyn_config)) = source.as_dynamic() {
                                let Some(kind) = binding_kinds.get(dyn_backend) else {
                                    tracing::warn!(
                                        backend = %binding.name,
                                        template = %uri_template,
                                        variable = %var_name,
                                        dynamic_backend = %dyn_backend,
                                        "variable_completions: dynamic backend does not resolve to a registered binding; entry dropped"
                                    );
                                    continue;
                                };
                                resource_template_dynamic_completions.insert(
                                    (binding.name.clone(), var_name.clone()),
                                    DynamicCompletionEntry {
                                        backend_name: dyn_backend.to_owned(),
                                        kind: kind.clone(),
                                        config: dyn_config.clone(),
                                    },
                                );
                            }
                        }
                    }
                    resource_template_routes.push(compiled);
                }
            }
        }

        Self {
            tools,
            schema_validators,
            output_schema_validators,
            prompts,
            resources,
            resource_templates,
            resource_template_routes,
            binding_routes,
            prompt_completions,
            resource_template_completions,
            resource_template_dynamic_completions,
            federated: Arc::new(ArcSwap::from_pointee(FederatedCatalog::default())),
            reported_shadowed: Arc::default(),
        }
    }

    /// Validate tool arguments against the binding's compiled JSON Schema.
    /// Returns Ok(()) if no schema is registered for this tool (debug tools, bindings without explicit schema).
    /// Returns Err with a human-readable message if validation fails.
    pub fn validate_tool_arguments(
        &self,
        tool_name: &str,
        arguments: &Option<Value>,
    ) -> Result<(), String> {
        let Some(validator) = self.schema_validators.get(tool_name) else {
            return Ok(());
        };
        let args = arguments
            .as_ref()
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let result = validator.validate(&args);
        if result.is_ok() {
            return Ok(());
        }
        let errors: Vec<String> = validator
            .iter_errors(&args)
            .map(|e| {
                if e.instance_path.as_str().is_empty() {
                    e.to_string()
                } else {
                    format!("{}: {}", e.instance_path, e)
                }
            })
            .collect();
        Err(format!(
            "arguments validation failed: {}",
            errors.join("; ")
        ))
    }

    /// Validate structured output of a tool call against the tool's `outputSchema`.
    /// Per MCP spec: servers MUST validate `structuredContent` before returning it.
    /// Returns Ok(()) if no output schema is registered for this tool.
    /// Returns Ok(()) if `structured_content` is None.
    /// Returns Err with a human-readable message if validation fails.
    pub fn validate_structured_output(
        &self,
        tool_name: &str,
        structured_content: &Option<Value>,
    ) -> Result<(), String> {
        let Some(content) = structured_content.as_ref() else {
            return Ok(());
        };
        let Some(validator) = self.output_schema_validators.get(tool_name) else {
            return Ok(());
        };
        if validator.validate(content).is_ok() {
            return Ok(());
        }
        let errors: Vec<String> = validator
            .iter_errors(content)
            .map(|e| {
                if e.instance_path.as_str().is_empty() {
                    e.to_string()
                } else {
                    format!("{}: {}", e.instance_path, e)
                }
            })
            .collect();
        Err(format!(
            "structuredContent validation against outputSchema failed: {}",
            errors.join("; ")
        ))
    }

    // `tools/list`, `prompts/list`, `resources/list`, and
    // `resources/templates/list` return deterministic, lexicographic
    // orderings. The spec does not MANDATE a sort, but a stable order
    // is a strong SHOULD: clients paginate by stable cursor and
    // operators rely on the output being diff-friendly.

    /// Drop entries whose client-facing key was already taken, keeping the
    /// first — and the native entries are always first in the chain.
    ///
    /// A federated catalog's names come from the upstream server, and
    /// `naming.tool_prefix` defaults to empty, so an upstream can name a tool
    /// whatever a native binding is called. Dispatch already resolves
    /// native-first, so the duplicate was never reachable; it was still
    /// *listed*, with its own description and input schema, and clients feed
    /// both to a model. Authorization made it worse: `per_tool_rules` is
    /// consulted before the overlay, so the shadowing entry was governed by
    /// the native tool's rule and the federation's own `minimum_trust` never
    /// applied. Listing what dispatch would actually run removes both.
    fn native_first<T>(&self, items: Vec<T>, surface: &str, key: impl Fn(&T) -> String) -> Vec<T> {
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(items.len());
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let k = key(&item);
            if seen.insert(k.clone()) {
                out.push(item);
            } else {
                self.report_shadowed(surface, &k);
            }
        }
        out
    }

    /// Log a shadowed federated entry once per registry instance. A reload
    /// rebuilds the registry, so a collision that survives a config change is
    /// reported again.
    fn report_shadowed(&self, surface: &str, key: &str) {
        let mut reported = self
            .reported_shadowed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if reported.insert(format!("{surface}:{key}")) {
            tracing::error!(
                surface = %surface,
                name = %key,
                "federated capability collides with a name already served natively; \
                 the federated entry is withheld from listings and is not dispatchable. \
                 Set the federation's naming.tool_prefix, or rename the native binding"
            );
        }
    }

    pub fn tools(&self) -> Vec<ToolDescriptor> {
        let overlay = self.federated.load();
        let merged: Vec<ToolDescriptor> = self
            .tools
            .iter()
            .chain(overlay.tools.iter())
            .map(|binding| binding.descriptor.clone())
            .collect();
        let mut out = self.native_first(merged, "tool", |d| d.name.clone());
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Shared handle to the federated-capability overlay.
    /// The `FederationEngine` holds a clone and `store`s a fresh
    /// [`FederatedCatalog`] on import / refresh; reads here observe it
    /// atomically.
    #[must_use]
    pub fn federated_overlay(&self) -> Arc<ArcSwap<FederatedCatalog>> {
        Arc::clone(&self.federated)
    }

    pub fn prompts(&self) -> Vec<PromptDescriptor> {
        let overlay = self.federated.load();
        let merged: Vec<PromptDescriptor> = self
            .prompts
            .iter()
            .chain(overlay.prompts.iter())
            .map(|binding| binding.descriptor.clone())
            .collect();
        let mut out = self.native_first(merged, "prompt", |d| d.name.clone());
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn resources(&self) -> Vec<ResourceDescriptor> {
        let overlay = self.federated.load();
        let merged: Vec<ResourceDescriptor> = self
            .resources
            .iter()
            .chain(overlay.resources.iter())
            .map(|binding| binding.descriptor.clone())
            .collect();
        let mut out = self.native_first(merged, "resource", |d| d.uri.clone());
        out.sort_by(|a, b| a.uri.cmp(&b.uri));
        out
    }

    /// Returns registered resource templates from binding config.
    pub fn resource_templates(&self) -> Vec<crate::protocol::ResourceTemplate> {
        let mut merged = self.resource_templates.clone();
        merged.extend(self.federated.load().resource_templates.iter().cloned());
        let mut out = self.native_first(merged, "resource_template", |t| t.uri_template.clone());
        out.sort_by(|a, b| a.uri_template.cmp(&b.uri_template));
        out
    }

    pub fn tool_route(&self, name: &str) -> Option<BackendInvocationRoute> {
        if let Some(binding) = self.tools.iter().find(|b| b.descriptor.name == name) {
            return Some(binding.route.clone());
        }
        self.federated
            .load()
            .tools
            .iter()
            .find(|b| b.descriptor.name == name)
            .map(|b| b.route.clone())
    }

    /// Resolve the effective `TaskSupport` for a tool.
    /// Returns `None` if the tool is not found.
    /// Per MCP spec, absent `execution.taskSupport` defaults to `Forbidden`.
    pub fn tool_task_support(&self, name: &str) -> Option<TaskSupport> {
        let support = |binding: &RegisteredTool| {
            binding
                .descriptor
                .execution
                .as_ref()
                .and_then(|e| e.task_support.clone())
                .unwrap_or(TaskSupport::Forbidden)
        };
        if let Some(binding) = self.tools.iter().find(|b| b.descriptor.name == name) {
            return Some(support(binding));
        }
        self.federated
            .load()
            .tools
            .iter()
            .find(|b| b.descriptor.name == name)
            .map(support)
    }

    pub fn prompt_route(&self, name: &str) -> Option<PromptRoute> {
        if let Some(binding) = self.prompts.iter().find(|b| b.descriptor.name == name) {
            return Some(binding.route.clone());
        }
        self.federated
            .load()
            .prompts
            .iter()
            .find(|b| b.descriptor.name == name)
            .map(|b| b.route.clone())
    }

    pub fn prompt_descriptor(&self, name: &str) -> Option<PromptDescriptor> {
        if let Some(binding) = self.prompts.iter().find(|b| b.descriptor.name == name) {
            return Some(binding.descriptor.clone());
        }
        self.federated
            .load()
            .prompts
            .iter()
            .find(|b| b.descriptor.name == name)
            .map(|b| b.descriptor.clone())
    }

    pub fn resource_route(&self, uri: &str) -> Option<ResourceRoute> {
        // RFC 3986 normalization. Case-insensitive scheme and
        // host, collapse duplicate slashes in the path, strip default
        // ports, decode unreserved percent-escapes, etc. Without this
        // `HTTPS://Example.com/Foo` and `https://example.com/Foo`
        // would not collide on exact-match lookup.
        let normalized = normalize_resource_uri(uri);
        // Exact resource bindings win over templates (precedence rule).
        if let Some(binding) = self
            .resources
            .iter()
            .find(|binding| normalize_resource_uri(&binding.descriptor.uri) == normalized)
        {
            return Some(binding.route.clone());
        }
        // Fall back to template matching. First-declared template wins when
        // multiple templates could match — authors should order them from
        // most-specific to most-generic in config.
        for template in &self.resource_template_routes {
            if let Some(vars) = template.match_uri(uri) {
                return Some(ResourceRoute::Template {
                    profile: template.profile.clone(),
                    template_vars: vars,
                });
            }
            // Try normalized form for templates with literal segments.
            if let Some(vars) = template.match_uri(&normalized) {
                return Some(ResourceRoute::Template {
                    profile: template.profile.clone(),
                    template_vars: vars,
                });
            }
        }
        // Federated resources (exact, prefixed URIs) match next.
        let federated = self.federated.load();
        if let Some(binding) = federated
            .resources
            .iter()
            .find(|binding| normalize_resource_uri(&binding.descriptor.uri) == normalized)
        {
            return Some(binding.route.clone());
        }
        // Federated *templates* match last: on a hit, de-prefix the URI back
        // to the upstream URI and reuse the exact-resource federated route so
        // dispatch is identical to a concrete federated read.
        for tmpl in &federated.resource_template_routes {
            if tmpl.matcher.match_uri(uri).is_some()
                || tmpl.matcher.match_uri(&normalized).is_some()
            {
                let upstream_uri = uri.strip_prefix(&tmpl.prefix).unwrap_or(uri).to_owned();
                return Some(ResourceRoute::Federated {
                    source: tmpl.source.clone(),
                    upstream_uri,
                });
            }
        }
        None
    }

    pub fn resource_descriptor(&self, uri: &str) -> Option<ResourceDescriptor> {
        let normalized = normalize_resource_uri(uri);
        if let Some(binding) = self
            .resources
            .iter()
            .find(|binding| normalize_resource_uri(&binding.descriptor.uri) == normalized)
        {
            return Some(binding.descriptor.clone());
        }
        self.federated
            .load()
            .resources
            .iter()
            .find(|binding| normalize_resource_uri(&binding.descriptor.uri) == normalized)
            .map(|binding| binding.descriptor.clone())
    }

    /// Return the raw `mcp_app_url` pattern for a resource binding, if it
    /// contains dynamic expressions. Static URLs are already in `_meta`;
    /// this is only non-None when CEL resolution is needed at read time.
    pub fn resource_app_url_pattern(&self, uri: &str) -> Option<String> {
        let normalized = normalize_resource_uri(uri);
        self.resources
            .iter()
            .find(|b| normalize_resource_uri(&b.descriptor.uri) == normalized)
            .and_then(|b| b.app_url_pattern.clone())
    }

    /// Look up the tool route for any binding by profile name (works for tool, prompt, and resource bindings).
    pub fn binding_route(&self, profile: &str) -> Option<BackendInvocationRoute> {
        self.binding_routes.get(profile).cloned()
    }

    /// Returns true if any prompt arguments have completion values configured.
    pub fn has_completions(&self) -> bool {
        !self.prompt_completions.is_empty()
    }

    /// Look up the dynamic-completion entry, if any, matching the
    /// given `ref/resource` completion request. Returns `None` if the
    /// reference is not `ref/resource`, the URI doesn't match a
    /// registered template, the variable isn't declared on that
    /// template, or no dynamic source is configured for it.
    ///
    /// Used by the runtime to decide between the sync static path and
    /// async dynamic dispatch — see
    /// [`crate::runtime::GatewayRuntime`]'s `completion/complete`
    /// handler.
    pub fn dynamic_completion_target(
        &self,
        params: &crate::protocol::CompletionCompleteParams,
    ) -> Option<&DynamicCompletionEntry> {
        if params.reference.ref_type != "ref/resource" {
            return None;
        }
        let template_uri = params.reference.uri.as_deref()?;
        let template = self.resource_template_routes.iter().find(|t| {
            let mut rebuilt = String::new();
            for part in &t.parts {
                match part {
                    TemplatePart::Literal(lit) => rebuilt.push_str(lit),
                    TemplatePart::Variable(name) => {
                        rebuilt.push('{');
                        rebuilt.push_str(name);
                        rebuilt.push('}');
                    }
                }
            }
            rebuilt == template_uri
        })?;
        if !template
            .variables
            .iter()
            .any(|v| v == &params.argument.name)
        {
            return None;
        }
        let key = (template.profile.clone(), params.argument.name.clone());
        self.resource_template_dynamic_completions.get(&key)
    }

    /// Return matching completion values for a prompt argument, filtered by prefix.
    pub fn complete_argument(
        &self,
        params: &crate::protocol::CompletionCompleteParams,
    ) -> crate::protocol::CompletionValues {
        let reference = &params.reference;
        let argument = &params.argument;
        match reference.ref_type.as_str() {
            "ref/prompt" => {
                if let Some(ref name) = reference.name {
                    let key = (name.clone(), argument.name.clone());
                    if let Some(completions) = self.prompt_completions.get(&key) {
                        // when the client has already resolved other
                        // arguments, avoid suggesting them again.
                        let already_used: std::collections::HashSet<&String> = params
                            .context
                            .as_ref()
                            .map(|c| c.arguments.values().collect())
                            .unwrap_or_default();
                        let filtered: Vec<String> = completions
                            .iter()
                            .filter(|v| v.starts_with(&argument.value))
                            .filter(|v| !already_used.contains(v))
                            .cloned()
                            .collect();
                        // MCP 2025-11-25 caps completion values
                        // at 100. Clamp and set `hasMore` / `total`
                        // accordingly so clients that paginate manually
                        // can tell they should refine the prefix.
                        return clamp_completion_values(filtered);
                    }
                }
            }
            "ref/resource" => {
                // completion against a registered resource template.
                // Match precedence mirrors `ref/prompt`: prefer prefix
                // matches projected from `context.arguments` (already-
                // filled-in values from sibling variables); fall back to
                // the operator-declared static `variable_completions`
                // list. Only fall through to empty when neither yields
                // a match AND the variable is declared on the template.
                if let Some(template_uri) = reference.uri.as_deref()
                    && let Some(template) = self.resource_template_routes.iter().find(|t| {
                        // Rebuild the original template string to compare.
                        let mut rebuilt = String::new();
                        for part in &t.parts {
                            match part {
                                TemplatePart::Literal(lit) => rebuilt.push_str(lit),
                                TemplatePart::Variable(name) => {
                                    rebuilt.push('{');
                                    rebuilt.push_str(name);
                                    rebuilt.push('}');
                                }
                            }
                        }
                        rebuilt == template_uri
                    })
                {
                    // Only respond if the argument name is one of the
                    // template's declared variables.
                    if template.variables.iter().any(|v| v == &argument.name) {
                        let context_values: Vec<String> = params
                            .context
                            .as_ref()
                            .map(|c| c.arguments.values().cloned().collect())
                            .unwrap_or_default();
                        let filtered: Vec<String> = context_values
                            .into_iter()
                            .filter(|v| v.starts_with(&argument.value))
                            .collect();
                        if !filtered.is_empty() {
                            return clamp_completion_values(filtered);
                        }
                        let key = (template.profile.clone(), argument.name.clone());
                        if let Some(values) = self.resource_template_completions.get(&key) {
                            let static_filtered: Vec<String> = values
                                .iter()
                                .filter(|v| v.starts_with(&argument.value))
                                .cloned()
                                .collect();
                            return clamp_completion_values(static_filtered);
                        }
                    }
                }
            }
            _ => {}
        }
        crate::protocol::CompletionValues {
            values: vec![],
            has_more: Some(false),
            total: Some(0),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredTool {
    pub(crate) descriptor: ToolDescriptor,
    pub(crate) route: BackendInvocationRoute,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredPrompt {
    pub(crate) descriptor: PromptDescriptor,
    pub(crate) route: PromptRoute,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredResource {
    pub(crate) descriptor: ResourceDescriptor,
    pub(crate) route: ResourceRoute,
    /// Raw app_url pattern for dynamic resolution at resources/read time.
    /// Static URLs are already baked into descriptor._meta; this is only
    /// stored when the URL contains `${...}` expressions that need
    /// per-read resolution.
    pub(crate) app_url_pattern: Option<String>,
}

/// MCP 2025-11-25 `completion/complete` caps the returned `values`
/// array at 100. This helper truncates and sets `hasMore` / `total`
/// so clients can tell when they should refine their prefix.
pub(crate) fn clamp_completion_values(
    mut filtered: Vec<String>,
) -> crate::protocol::CompletionValues {
    const MAX_COMPLETION_VALUES: usize = 100;
    let total = filtered.len() as u64;
    let has_more = if filtered.len() > MAX_COMPLETION_VALUES {
        filtered.truncate(MAX_COMPLETION_VALUES);
        Some(true)
    } else {
        Some(false)
    };
    crate::protocol::CompletionValues {
        total: Some(total),
        has_more,
        values: filtered,
    }
}

impl CompiledResourceTemplate {
    /// Attempt to match a concrete URI against this template. Returns the
    /// captured variables in declaration order if the URI matches, otherwise
    /// `None`. The matcher enforces that:
    /// - literal segments match exactly (case-sensitive)
    /// - variables bind to non-empty substrings that do NOT contain the
    ///   immediately-following literal delimiter
    /// - the entire URI is consumed (no trailing data)
    fn match_uri(&self, uri: &str) -> Option<std::collections::BTreeMap<String, String>> {
        let mut remaining = uri;
        let mut captured: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let parts = &self.parts;
        for idx in 0..parts.len() {
            match &parts[idx] {
                TemplatePart::Literal(lit) => {
                    if !remaining.starts_with(lit.as_str()) {
                        return None;
                    }
                    remaining = &remaining[lit.len()..];
                }
                TemplatePart::Variable(name) => {
                    // The variable runs until the next literal (or end of input).
                    // Peek at the next part to decide where the capture ends.
                    let capture_end = match parts.get(idx + 1) {
                        Some(TemplatePart::Literal(next_lit)) => {
                            remaining.find(next_lit.as_str())?
                        }
                        Some(TemplatePart::Variable(_)) => {
                            // Adjacent variables are ambiguous and rejected at
                            // compile-time, but guard anyway.
                            return None;
                        }
                        None => remaining.len(),
                    };
                    if capture_end == 0 {
                        return None;
                    }
                    let value = &remaining[..capture_end];
                    // Disallow `/` inside a captured variable by default so
                    // `scheme://{a}/{b}` stays unambiguous.
                    if value.contains('/') {
                        return None;
                    }
                    captured.insert(name.clone(), value.to_owned());
                    remaining = &remaining[capture_end..];
                }
            }
        }
        if !remaining.is_empty() {
            return None;
        }
        // Require all declared variables appeared.
        for var in &self.variables {
            if !captured.contains_key(var) {
                return None;
            }
        }
        Some(captured)
    }
}

pub(crate) fn compile_resource_template(
    profile: &str,
    template: &str,
) -> Option<CompiledResourceTemplate> {
    // RFC 6570 simple level-1 matcher: literals interleaved with `{var}`
    // placeholders. Adjacent variables (`{a}{b}`) are rejected because they
    // cannot be unambiguously matched.
    let mut parts = Vec::new();
    let mut variables = Vec::new();
    let mut buf = String::new();
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            if !buf.is_empty() {
                parts.push(TemplatePart::Literal(std::mem::take(&mut buf)));
            }
            let mut name = String::new();
            let mut closed = false;
            for nc in chars.by_ref() {
                if nc == '}' {
                    closed = true;
                    break;
                }
                name.push(nc);
            }
            if !closed || name.is_empty() {
                tracing::warn!(
                    template = %template,
                    "resource template has a malformed `{{var}}` expression; skipping"
                );
                return None;
            }
            if let Some(TemplatePart::Variable(_)) = parts.last() {
                tracing::warn!(
                    template = %template,
                    "resource template has adjacent variables without a separating literal; skipping"
                );
                return None;
            }
            variables.push(name.clone());
            parts.push(TemplatePart::Variable(name));
        } else {
            buf.push(ch);
        }
    }
    if !buf.is_empty() {
        parts.push(TemplatePart::Literal(buf));
    }
    if variables.is_empty() {
        return None;
    }
    Some(CompiledResourceTemplate {
        profile: profile.to_owned(),
        parts,
        variables,
    })
}

/// Build `ToolAnnotations` from binding config fields. Returns `None` if no
/// annotation hints are configured.
fn build_tool_annotations(binding: &BackendConfig) -> Option<ToolAnnotations> {
    let ann = binding.annotations.as_ref()?;
    if ann.read_only.is_none()
        && ann.destructive.is_none()
        && ann.idempotent.is_none()
        && ann.open_world.is_none()
    {
        return None;
    }
    Some(ToolAnnotations {
        title: None,
        read_only_hint: ann.read_only,
        destructive_hint: ann.destructive,
        idempotent_hint: ann.idempotent,
        open_world_hint: ann.open_world,
    })
}

/// RFC 3986 syntax-based URI normalization for
/// resource-URI exact-match lookup. Normalizes scheme + host case,
/// strips default ports, collapses `./` and `../` path segments, and
/// normalizes percent-escapes of unreserved characters.
///
/// input whose scheme isn't in the curated allow-list is
/// lower-cased and *syntactically* canonicalized (no crate support) so
/// `CUSTOM:Foo` and `custom:Foo` still collide, while unknown and
/// unparseable schemes cannot silently bypass normalization by
/// falling through to the raw string.
/// process-wide extra-scheme allow-list. Operators add
/// custom schemes via `server.extra_resource_uri_schemes` in app
/// config; bootstrap sets this once via
/// `set_extra_resource_uri_schemes`. Subsequent calls are no-ops
/// (OnceLock semantics) so config hot-reload cannot mutate the
/// allow-list mid-flight; restart to change.
static EXTRA_RESOURCE_URI_SCHEMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Merge `mcpAppUrl` into an existing `_meta` object (or create one).
/// Returns `None` when both `existing_meta` and `app_url` are absent.
fn merge_mcp_app_url(
    existing_meta: Option<serde_json::Value>,
    app_url: Option<&str>,
) -> Option<serde_json::Value> {
    match (existing_meta, app_url) {
        (None, None) => None,
        (Some(meta), None) => Some(meta),
        (None, Some(url)) => Some(serde_json::json!({ "mcpAppUrl": url })),
        (Some(serde_json::Value::Object(mut map)), Some(url)) => {
            map.insert(
                "mcpAppUrl".to_owned(),
                serde_json::Value::String(url.to_owned()),
            );
            Some(serde_json::Value::Object(map))
        }
        (Some(other), Some(url)) => {
            // Non-object _meta; wrap it and add mcpAppUrl alongside.
            Some(serde_json::json!({
                "_original": other,
                "mcpAppUrl": url,
            }))
        }
    }
}

pub fn set_extra_resource_uri_schemes(schemes: Vec<String>) {
    let _ = EXTRA_RESOURCE_URI_SCHEMES.set(
        schemes
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
    );
}

fn extra_schemes() -> &'static [String] {
    EXTRA_RESOURCE_URI_SCHEMES
        .get()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

pub fn normalize_resource_uri(uri: &str) -> String {
    const ALLOWED_SCHEMES: &[&str] = &[
        "http", "https", "ws", "wss", "ftp", "ftps", "file",
        // MCP-specific and commonly-used custom resource schemes.
        "mcp", "mcp-res", "resource", "blob", "data", "urn", "s3", "gs", "az",
    ];

    let trimmed = uri.trim();

    // Extract the scheme portion for the allow-list check without
    // depending on url::Url parsing (some `urn:` / `file:///` shapes
    // normalize but don't parse cleanly under all versions).
    let scheme_end = trimmed.find(':');
    if let Some(idx) = scheme_end {
        let scheme = &trimmed[..idx];
        let lower_scheme = scheme.to_ascii_lowercase();
        let scheme_allowed = ALLOWED_SCHEMES.iter().any(|s| *s == lower_scheme)
            || extra_schemes().iter().any(|s| s == &lower_scheme);

        match url::Url::parse(trimmed) {
            Ok(mut u) => {
                let _ = u.set_scheme(&lower_scheme);
                if let Some(host) = u.host_str() {
                    let lower_host = host.to_ascii_lowercase();
                    if lower_host != host {
                        let _ = u.set_host(Some(&lower_host));
                    }
                }
                let default_port = match lower_scheme.as_str() {
                    "http" | "ws" => Some(80),
                    "https" | "wss" => Some(443),
                    "ftp" => Some(21),
                    "ftps" => Some(990),
                    _ => None,
                };
                if let Some(dp) = default_port
                    && u.port() == Some(dp)
                {
                    let _ = u.set_port(None);
                }
                u.as_str().to_owned()
            }
            Err(_) => {
                if scheme_allowed {
                    // Known scheme but parse failed → emit the loud
                    // raw form to preserve diagnosis.
                    tracing::warn!(
                        uri = %trimmed,
                        scheme = %lower_scheme,
                        "allow-listed URI scheme failed to parse; falling back to raw form"
                    );
                    trimmed.to_owned()
                } else {
                    // Unknown scheme AND unparseable. Lower-case the
                    // scheme portion so two callers referring to the
                    // same resource with different scheme casing still
                    // collide in exact-match lookup.
                    tracing::warn!(
                        uri = %trimmed,
                        scheme = %lower_scheme,
                        "unknown URI scheme in resource lookup; \
                         applying syntactic canonicalization only"
                    );
                    metrics::counter!(
                        "mcpg_resource_uri_scheme_unknown_total",
                        "scheme" => lower_scheme.clone(),
                    )
                    .increment(1);
                    format!("{lower_scheme}:{}", &trimmed[idx + 1..])
                }
            }
        }
    } else {
        // No scheme at all. Preserve verbatim — this is either a
        // relative reference or malformed; either way caller-level
        // matching decides.
        trimmed.to_owned()
    }
}

/// Build `ToolExecution` from binding config. Returns `None` if no task support
/// is configured.
fn build_tool_execution(binding: &BackendConfig) -> Option<ToolExecution> {
    let task_support = binding.task_support.as_deref().and_then(|s| match s {
        "forbidden" => Some(TaskSupport::Forbidden),
        "optional" => Some(TaskSupport::Optional),
        "required" => Some(TaskSupport::Required),
        _ => None,
    });
    task_support.map(|ts| ToolExecution {
        task_support: Some(ts),
    })
}
