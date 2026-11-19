//! `resources/list`, `resources/templates/list` and `resources/read`
//! dispatch arms.

use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, ProtocolResponse};
use crate::protocol::v_2026_07_28::dispatch::support::{
    handler_internal_error, serialize_jsonrpc_success,
};
use crate::protocol::v_2026_07_28::wire::resources::{
    ResourceDescriptor, ResourceReadParams, ResourceTemplate, ResourceTemplatesListParams,
    ResourceTemplatesListResult, ResourcesListParams, ResourcesListResult,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::{GatewayRuntime, RequestContext};
use serde_json::Value;

/// Default `ttlMs` advertised on `resources/list` results.
/// 30 seconds — resources can change moderately fast (operator
/// edits, dynamic bindings); the short TTL backstops staleness.
pub(crate) const DEFAULT_RESOURCES_LIST_TTL_MS: u64 = 30_000;

/// Default `ttlMs` advertised on `resources/templates/list`.
/// 10 minutes — templates change as slowly as prompts.
pub(crate) const DEFAULT_RESOURCE_TEMPLATES_LIST_TTL_MS: u64 = 600_000;

/// Dispatch `resources/list`.
pub(crate) async fn dispatch_resources_list(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: ResourcesListParams,
) -> ProtocolHttpResponse {
    let (page, next_cursor) = runtime
        .enumerate_resources_page(ctx, params.cursor.as_deref())
        .await;
    let resources: Vec<ResourceDescriptor> = page.iter().map(resource_descriptor).collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "resource",
        resources.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = ResourcesListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        resources,
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

/// Dispatch `resources/templates/list`.
pub(crate) async fn dispatch_resources_templates_list(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: ResourceTemplatesListParams,
) -> ProtocolHttpResponse {
    let (page, next_cursor) =
        runtime.enumerate_resource_templates_page(ctx, params.cursor.as_deref());
    let resource_templates: Vec<ResourceTemplate> = page.iter().map(resource_template).collect();

    let event = mcpg_plugin_host::audit_events::list_call_event(
        crate::runtime::plugin_identity_from_request(ctx),
        ctx.request_id.as_str(),
        ctx.session_id.as_deref(),
        "resource_template",
        resource_templates.len() as u64,
        match ctx.transport {
            crate::runtime::TransportKind::Http => "http",
            crate::runtime::TransportKind::Stdio => "stdio",
        },
    );
    let registry = runtime.plugin_registry_handle();
    let _ = registry.emit_audit_event(&event).await;

    let result = ResourceTemplatesListResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        resource_templates,
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

/// Dispatch `resources/read`.
///
/// The runtime's read (policy, federation, MCP-Apps `_meta.ui` clamp)
/// answers it; the success is stamped into the `CacheableResult`
/// envelope (SEP-2549/2322). An error passes through unchanged.
pub(crate) async fn dispatch_resources_read(
    ctx: &RequestContext,
    runtime: &GatewayRuntime,
    request_id: Value,
    params: ResourceReadParams,
) -> ProtocolHttpResponse {
    let read = crate::protocol::ResourceReadParams {
        uri: params.uri,
        meta: params.meta,
    };
    stamp_resource_read(runtime.handle_resource_read(request_id, read, ctx).await)
}

/// Project a backend [`crate::backends::ResourceDescriptor`] into the
/// wire shape. Carries `annotations` through; `cache_scope: None` so the
/// page-level scope applies.
pub(crate) fn resource_descriptor(r: &crate::backends::ResourceDescriptor) -> ResourceDescriptor {
    ResourceDescriptor {
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

/// Project the catalog's [`crate::protocol::ResourceTemplate`] into the
/// wire shape. Carries `annotations` through; the field set is otherwise
/// identical.
pub(crate) fn resource_template(t: &crate::protocol::ResourceTemplate) -> ResourceTemplate {
    ResourceTemplate {
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

/// Stamp a `resources/read` success into the `CacheableResult` envelope
/// (SEP-2549/2322): `resultType:"complete"` plus the required `ttlMs` +
/// `cacheScope` (already-present values are preserved), so
/// `resources/read` matches `resources/list`. A result that already names
/// its `resultType`, and an error, pass through untouched.
pub(crate) fn stamp_resource_read(mut response: ProtocolHttpResponse) -> ProtocolHttpResponse {
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
