use super::*;

/// Auto-exposed bindings synthesized from the openapi backend, grouped by
/// the capability list they belong to.
pub(crate) struct OpenapiExpansion {
    pub(crate) tools: Vec<crate::config::BackendConfig>,
    pub(crate) resource_templates: Vec<crate::config::BackendConfig>,
}

/// Ask the openapi backend which capabilities to
/// auto-expose from its `sources` and synthesize ordinary bindings per
/// result. The plugin owns spec parsing + filtering; the gateway stays
/// domain-agnostic, rebuilding each binding from the generic `backend_kind`
/// plus `backend_spec` and inheriting the relayed governance/retry. A name
/// already present in config (an explicit Tier-1 binding) wins.
pub(crate) async fn expand_openapi_bindings(
    config: &AppConfig,
    registry: &mcpg_plugin_host::PluginRegistry,
) -> Result<OpenapiExpansion> {
    let mut expansion = OpenapiExpansion {
        tools: Vec::new(),
        resource_templates: Vec::new(),
    };
    let Some(plugin) = registry.backend("openapi") else {
        return Ok(expansion);
    };
    let set = mcpg_plugin_protocol::BackendPlugin::expand_capabilities(plugin.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("openapi expand_capabilities failed: {e:?}"))?;

    let existing_tools: std::collections::HashSet<&str> = config
        .mcp
        .capabilities
        .tools
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    for tool in set.tools {
        if existing_tools.contains(tool.name.as_str()) {
            tracing::debug!(tool = %tool.name, "openapi: explicit binding overrides auto-exposed tool");
            continue;
        }
        expansion.tools.push(synthetic_tool_binding(tool)?);
    }

    let existing_templates: std::collections::HashSet<&str> = config
        .mcp
        .capabilities
        .resource_templates
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    for rt in set.resource_templates {
        if existing_templates.contains(rt.name.as_str()) {
            tracing::debug!(template = %rt.name, "openapi: explicit binding overrides auto-exposed resource template");
            continue;
        }
        expansion
            .resource_templates
            .push(synthetic_resource_template_binding(rt)?);
    }

    if !expansion.tools.is_empty() || !expansion.resource_templates.is_empty() {
        tracing::info!(
            tools = expansion.tools.len(),
            resource_templates = expansion.resource_templates.len(),
            "openapi: auto-exposed capabilities from sources"
        );
    }
    Ok(expansion)
}

/// Common binding JSON shared by tools + resource templates. The binding
/// enum is reconstructed from `backend_kind` + `backend_spec` so the gateway
/// never special-cases the producing backend.
pub(crate) fn compose_synthetic_binding(
    backend_kind: String,
    backend_spec: serde_json::Value,
    name: &str,
    description: String,
    governance: Option<serde_json::Value>,
    retry: Option<serde_json::Value>,
    meta: Option<serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut backend = backend_spec.as_object().cloned().unwrap_or_default();
    backend.insert("kind".to_owned(), serde_json::Value::String(backend_kind));
    let mut obj = serde_json::Map::new();
    obj.insert(
        "name".to_owned(),
        serde_json::Value::String(name.to_owned()),
    );
    obj.insert(
        "description".to_owned(),
        serde_json::Value::String(description),
    );
    obj.insert("backend".to_owned(), serde_json::Value::Object(backend));
    if let Some(g) = governance {
        obj.insert("governance".to_owned(), g);
    }
    if let Some(r) = retry {
        obj.insert("retry".to_owned(), r);
    }
    if let Some(m) = meta {
        obj.insert("descriptor_meta".to_owned(), m);
    }
    obj
}

pub(crate) fn deserialize_binding(
    obj: serde_json::Map<String, serde_json::Value>,
    kind: &str,
    name: &str,
) -> Result<crate::config::BackendConfig> {
    serde_json::from_value::<crate::config::BackendConfig>(serde_json::Value::Object(obj))
        .map_err(|e| anyhow::anyhow!("synthesize openapi {kind} binding '{name}': {e}"))
}

/// Synthesize a tool `BackendConfig` from one [`mcpg_plugin_protocol::ExpandedTool`].
pub(crate) fn synthetic_tool_binding(
    t: mcpg_plugin_protocol::ExpandedTool,
) -> Result<crate::config::BackendConfig> {
    let name = t.name.clone();
    let mut obj = compose_synthetic_binding(
        t.backend_kind,
        t.backend_spec,
        &name,
        t.description,
        t.governance,
        t.retry,
        t.meta,
    );
    if let Some(title) = t.title {
        obj.insert("title".to_owned(), serde_json::Value::String(title));
    }
    obj.insert("input_schema".to_owned(), t.input_schema);
    if let Some(os) = t.output_schema {
        obj.insert("output_schema".to_owned(), os);
    }
    deserialize_binding(obj, "tool", &name)
}

/// Synthesize a `resource_template` `BackendConfig` from one
/// [`mcpg_plugin_protocol::ExpandedResourceTemplate`].
pub(crate) fn synthetic_resource_template_binding(
    rt: mcpg_plugin_protocol::ExpandedResourceTemplate,
) -> Result<crate::config::BackendConfig> {
    let name = rt.name.clone();
    let mut obj = compose_synthetic_binding(
        rt.backend_kind,
        rt.backend_spec,
        &name,
        rt.description,
        rt.governance,
        rt.retry,
        rt.meta,
    );
    obj.insert(
        "uri_template".to_owned(),
        serde_json::Value::String(rt.uri_template),
    );
    if let Some(mt) = rt.mime_type {
        obj.insert("mime_type".to_owned(), serde_json::Value::String(mt));
    }
    deserialize_binding(obj, "resource template", &name)
}
