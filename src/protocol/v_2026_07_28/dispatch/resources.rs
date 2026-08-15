//! `resources` dispatch arms for MCP revision `2026-07-28`.

use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, ProtocolResponse};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, serialize_jsonrpc_success,
};
use crate::protocol::v_2026_07_28::wire::resources::{
    ResourceDescriptor as ModernResourceDescriptor, ResourceReadParams as ModernResourceReadParams,
    ResourceTemplate as ModernResourceTemplate,
    ResourceTemplatesListParams as ModernResourceTemplatesListParams,
    ResourceTemplatesListResult as ModernResourceTemplatesListResult,
    ResourcesListParams as ModernResourcesListParams,
    ResourcesListResult as ModernResourcesListResult,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;
use serde_json::Value;

/// Default `ttlMs` advertised on modern `resources/list` results.
/// 30 seconds — resources can change moderately fast (operator
/// edits, dynamic bindings); the short TTL backstops staleness.
pub(crate) const DEFAULT_RESOURCES_LIST_TTL_MS: u64 = 30_000;

/// Default `ttlMs` advertised on modern `resources/templates/list`.
/// 10 minutes — templates change as slowly as prompts.
pub(crate) const DEFAULT_RESOURCE_TEMPLATES_LIST_TTL_MS: u64 = 600_000;

/// Dispatch `resources/list` on the modern wire.
pub(crate) async fn dispatch_resources_list(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernResourcesListParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    let (page, next_cursor) = runtime
        .enumerate_resources_page(ctx, params.cursor.as_deref())
        .await;
    let modern_resources: Vec<ModernResourceDescriptor> =
        page.iter().map(legacy_resource_to_modern).collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "resource",
        modern_resources.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = ModernResourcesListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        resources: modern_resources,
        next_cursor,
        ttl_ms: DEFAULT_RESOURCES_LIST_TTL_MS,
        // Per-principal filtered — private-cacheable only (see tools/list).
        cache_scope: CacheScope::Private,
        meta: None,
    };

    // SEP-1865 MCP Apps: clamp `_meta.ui` on list entries to operator
    // policy (no-op unless Apps is enabled). Authoritative enforcement
    // is at `resources/read`; this narrows the preload hints too.
    let mut result_value = serde_json::to_value(&result).expect("resources list result serialized");
    if let Some(entries) = result_value
        .get_mut("resources")
        .and_then(|r| r.as_array_mut())
        && let Err(msg) = runtime.apply_apps_policy_to_items(entries, "resources/list")
    {
        return handler_internal_error(Some(request_id), &msg);
    }

    serialize_jsonrpc_success(request_id, &result_value, "resources/list")
}

/// Dispatch `resources/templates/list` on the modern wire.
pub(crate) async fn dispatch_resources_templates_list(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernResourceTemplatesListParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    let (page, next_cursor) =
        runtime.enumerate_resource_templates_page(ctx, params.cursor.as_deref());
    let modern_templates: Vec<ModernResourceTemplate> = page
        .iter()
        .map(legacy_resource_template_to_modern)
        .collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "resource_template",
        modern_templates.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = ModernResourceTemplatesListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        resource_templates: modern_templates,
        next_cursor,
        ttl_ms: DEFAULT_RESOURCE_TEMPLATES_LIST_TTL_MS,
        // Per-principal filtered — private-cacheable only (see tools/list).
        cache_scope: CacheScope::Private,
        meta: None,
    };

    // SEP-1865 MCP Apps: clamp `_meta.ui` on template entries.
    let mut result_value =
        serde_json::to_value(&result).expect("resource templates list result serialized");
    if let Some(entries) = result_value
        .get_mut("resourceTemplates")
        .and_then(|r| r.as_array_mut())
        && let Err(msg) = runtime.apply_apps_policy_to_items(entries, "resources/templates/list")
    {
        return handler_internal_error(Some(request_id), &msg);
    }

    serialize_jsonrpc_success(request_id, &result_value, "resources/templates/list")
}

/// Dispatch `resources/read` on the modern wire.
///
/// The read pipeline (policy, federation, MCP-Apps `_meta.ui` clamp)
/// is version-blind, so delegate to the legacy
/// `handle_protocol_operation`, then project the success into the
/// modern `CacheableResult` envelope — stamping `resultType:"complete"`
/// plus the required `ttlMs` + `cacheScope` that the legacy shape
/// lacks (RES-03 / SEP-2549/2322). A suspended (MRTR) or error
/// response passes through unchanged.
pub(crate) async fn dispatch_resources_read(
    ctx: &RequestContext,
    services: &SharedServices,
    request_id: Value,
    params: ModernResourceReadParams,
) -> ProtocolHttpResponse {
    let Some(runtime_handle) = services.runtime() else {
        return handler_internal_error(Some(request_id), "gateway runtime is shutting down");
    };
    let runtime = runtime_handle.load();

    let legacy_params = crate::protocol::v_2025_11_25::wire::resources::ResourceReadParams {
        uri: params.uri,
        meta: params.meta,
    };
    let legacy_op =
        crate::protocol::v_2025_11_25::wire::operations::ProtocolOperation::Capabilities(
            crate::protocol::v_2025_11_25::wire::operations::CapabilityOperation::ResourcesRead {
                request_id,
                params: legacy_params,
            },
        );

    let response = runtime.handle_protocol_operation(legacy_op, ctx).await;
    stamp_modern_resource_read(response)
}

/// Project a backend [`crate::backends::ResourceDescriptor`] into
/// the modern wire shape. Carries `annotations` through (RES-08); adds
/// `cache_scope: None` so the page-level scope applies.
pub(crate) fn legacy_resource_to_modern(
    r: &crate::backends::ResourceDescriptor,
) -> ModernResourceDescriptor {
    ModernResourceDescriptor {
        uri: r.uri.clone(),
        name: r.name.clone(),
        title: r.title.clone(),
        description: r.description.clone(),
        mime_type: r.mime_type.clone(),
        size: r.size,
        icons: r.icons.clone(),
        annotations: r.annotations.clone(),
        cache_scope: None,
        meta: r.meta.clone(),
    }
}

/// Project a legacy [`crate::protocol::ResourceTemplate`] into the
/// modern wire shape. Carries `annotations` through (RES-08);
/// field-set otherwise identical.
pub(crate) fn legacy_resource_template_to_modern(
    t: &crate::protocol::ResourceTemplate,
) -> ModernResourceTemplate {
    ModernResourceTemplate {
        uri_template: t.uri_template.clone(),
        name: t.name.clone(),
        title: t.title.clone(),
        description: t.description.clone(),
        mime_type: t.mime_type.clone(),
        icons: t.icons.clone(),
        annotations: t.annotations.clone(),
        meta: t.meta.clone(),
    }
}

/// Project a delegated `resources/read` success into the modern
/// `CacheableResult` envelope (SEP-2549/2322): stamp
/// `resultType:"complete"` plus the required `ttlMs` + `cacheScope`
/// (already-present values are preserved). The read pipeline (policy,
/// federation, MCP-Apps `_meta.ui` clamp) runs unchanged in the
/// runtime; this only enriches the result envelope so the modern
/// wire's `resources/read` matches `resources/list`. A suspended
/// (MRTR) or error response passes through untouched.
pub(crate) fn stamp_modern_resource_read(
    mut response: ProtocolHttpResponse,
) -> ProtocolHttpResponse {
    if let ProtocolResponse::JsonRpcSuccess(success) = &mut response.response
        && let Some(obj) = success.result.as_object_mut()
        && !obj.contains_key("resultType")
    {
        obj.insert(
            "resultType".to_owned(),
            Value::String(crate::protocol::shared::caching::RESULT_TYPE_COMPLETE.to_owned()),
        );
        obj.entry("ttlMs").or_insert_with(|| {
            Value::Number(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS.into())
        });
        // Private, like every sibling surface. A read is identity-bound: it
        // runs the policy gate and, for a federated resource, fetches with the
        // caller's own upstream credentials. Defaulting to `public` invites a
        // downstream cache to serve one principal's resource body to another.
        // A binding that really is public says so explicitly, and that value
        // is preserved.
        obj.entry("cacheScope")
            .or_insert_with(|| Value::String("private".to_owned()));
    }
    response
}
