//! `lifecycle` dispatch arms for MCP revision `2026-07-28`.

use serde_json::{Value, json};

use crate::protocol::shared::deprecation::{
    DEPRECATIONS_META_KEY, FEATURE_LOGGING, FEATURE_ROOTS, FEATURE_SAMPLING,
};
use crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION;
use crate::protocol::v_2026_07_28::wire::lifecycle::{
    CacheCapability, CompletionCapability, DiscoverResult, ImplementationInfo, PromptsCapability,
    ResourcesCapability, ServerCapabilities, ToolsCapability,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::shared_services::SharedServices;

pub(crate) fn build_discover_result(services: &SharedServices) -> DiscoverResult {
    use crate::protocol::v_2026_07_28::extensions::tasks::wire::{
        EXTENSION_NAMESPACE as TASKS_EXTENSION_NAMESPACE, METHOD_CANCEL_TASK, METHOD_GET_TASK,
        METHOD_UPDATE_TASK,
    };

    // Gate each capability on whether the operator actually wired
    // anything that surfaces it. SEP-2575's
    // `DiscoverCapabilitiesMatchHandlers` says advertising a
    // capability MUST mean its handler returns real results, not
    // `-32601` (the operator hasn't configured it). Advertising
    // an empty surface is acceptable only if the operator did
    // configure backends and the catalog is genuinely empty —
    // we treat "configured backends > 0" as the gate.
    //
    // Config is only half the catalog. Federated, registry-synthesized and
    // gateway-app capabilities arrive after boot and live in the capability
    // registry, so gating on the config snapshot alone made a gateway whose
    // tools ALL come from upstreams — the registry-sync mainline — advertise
    // no tools at all, while legacy `initialize` advertised them fine.
    let caps = &services.config_snapshot.mcp.capabilities;
    let live = services.runtime().map(|swap| swap.load_full());
    let live = live.as_deref();
    let has_tools = !caps.tools.is_empty() || live.is_some_and(|rt| rt.has_live_tools());
    let has_prompts = !caps.prompts.is_empty() || live.is_some_and(|rt| rt.has_live_prompts());
    let has_resources = !caps.resources.is_empty()
        || !caps.resource_templates.is_empty()
        || live.is_some_and(|rt| rt.has_live_resources());
    let has_completions =
        caps.has_completions() || live.is_some_and(|rt| rt.has_live_completions());

    // SEP-2133 extensions map. Each entry is keyed by the
    // extension's reverse-DNS namespace; the value is a free-form
    // capability object the extension owns. Tasks is advertised
    // whenever any operator tool has `task_support` enabled —
    // matches the legacy initialize behaviour.
    let mut extensions = serde_json::Map::new();
    // `task_support` is an opt-in per-tool string (e.g.
    // `"required"` / `"optional"`). Any tool declaring it
    // means the tasks extension is reachable on this gateway.
    let tasks_enabled = caps.tools.iter().any(|t| t.task_support.is_some());
    if tasks_enabled {
        extensions.insert(
            TASKS_EXTENSION_NAMESPACE.to_owned(),
            serde_json::json!({
                "methods": [
                    METHOD_GET_TASK,
                    METHOD_UPDATE_TASK,
                    METHOD_CANCEL_TASK,
                ],
            }),
        );
    }

    // SEP-1865 MCP Apps — advertised when
    // `mcp.configurations.apps.enabled`. The extension carries no MCP
    // methods (the `ui/*` protocol is host↔iframe over postMessage), so
    // the value is just the supported `mimeTypes`.
    if services.config_snapshot.mcp.configurations.apps.enabled {
        extensions.insert(
            crate::protocol::shared::apps::EXTENSION_ID.to_owned(),
            crate::protocol::shared::apps::capability_value(&[]),
        );
    }

    // Same supported-versions surface as the unsupported-version
    // error response — keep the two correlated so the conformance
    // suite's `ServerUnsupportedVersionError` check sees a strict
    // subset relationship.
    let mut supported_versions: Vec<String> = crate::protocol::LEGACY_PROTOCOL_VERSIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    supported_versions.push(crate::protocol::SUPPORTED_PROTOCOL_VERSION.to_owned());
    supported_versions.push(SUPPORTED_PROTOCOL_VERSION.to_owned());

    DiscoverResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        supported_versions,
        server_info: ImplementationInfo {
            name: "mcpg".to_owned(),
            title: Some("MCPG — MCP Gateway".to_owned()),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            description: Some(
                "Cluster-aware MCP gateway with policy, quota, and observability plugins."
                    .to_owned(),
            ),
            icons: None,
            website_url: None,
        },
        capabilities: ServerCapabilities {
            tools: has_tools.then_some(ToolsCapability {
                list_changed: Some(true),
                cache: Some(CacheCapability {}),
            }),
            prompts: has_prompts.then_some(PromptsCapability {
                list_changed: Some(true),
                cache: Some(CacheCapability {}),
            }),
            resources: has_resources.then_some(ResourcesCapability {
                list_changed: Some(true),
                // The runtime's `subscriptions/listen` delivery bus +
                // watch engine surface per-resource `resources/updated`
                // events whenever resources are configured.
                subscribe: Some(true),
                cache: Some(CacheCapability {}),
            }),
            // SEP-2575 / PR-02: advertise the `completions` capability
            // (plural wire key) only when the operator wired an
            // argument-completion source, matching the legacy
            // `initialize` gate.
            completions: has_completions.then_some(CompletionCapability {}),
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        },
        instructions: Some(
            "MCPG is speaking 2026-07-28. Capabilities reflect the operator's configured \
             bindings; absence of a capability means no backend is wired for it."
                .to_owned(),
        ),
        // Discovery is identical for every client of this gateway, so
        // the result is publicly cacheable.
        ttl_ms: crate::protocol::shared::caching::DEFAULT_LIST_TTL_MS,
        cache_scope: CacheScope::Public,
        // SEP-2596 feature-lifecycle advisory: surface the SEP-2577
        // Roots/Sampling/Logging deprecation status under the
        // vendor-namespaced `_meta` key so a modern client can steer
        // migration before the removal window closes.
        meta: Some(discover_meta_advisory()),
    }
}

/// Build the SEP-2596 deprecation advisory value for the modern
/// `server/discover` result `_meta`. Each entry names the feature, its
/// lifecycle state, the deprecating SEP, and the migration pointer the
/// spec prose carries.
pub(crate) fn discover_meta_advisory() -> Value {
    json!({
        DEPRECATIONS_META_KEY: {
            "policy": "SEP-2596",
            "features": [
                {
                    "feature": FEATURE_ROOTS,
                    "state": "deprecated",
                    "sep": "SEP-2577",
                    "since": "2026-07-28",
                },
                {
                    "feature": FEATURE_SAMPLING,
                    "state": "deprecated",
                    "sep": "SEP-2577",
                    "since": "2026-07-28",
                },
                {
                    "feature": FEATURE_LOGGING,
                    "state": "deprecated",
                    "sep": "SEP-2577",
                    "since": "2026-07-28",
                },
            ],
        }
    })
}

#[cfg(test)]
mod advisory_tests {
    use super::*;

    #[test]
    fn advisory_carries_all_three_deprecated_features() {
        let v = discover_meta_advisory();
        let features = v[DEPRECATIONS_META_KEY]["features"].as_array().unwrap();
        let names: Vec<&str> = features
            .iter()
            .map(|f| f["feature"].as_str().unwrap())
            .collect();
        assert!(names.contains(&FEATURE_ROOTS));
        assert!(names.contains(&FEATURE_SAMPLING));
        assert!(names.contains(&FEATURE_LOGGING));
        for f in features {
            assert_eq!(f["state"], "deprecated");
            assert_eq!(f["sep"], "SEP-2577");
        }
    }
}
