//! `lifecycle` dispatch arms for MCP revision `2026-07-28`.

use serde_json::{Value, json};

use crate::protocol::shared::deprecation::{
    DEPRECATIONS_META_KEY, FEATURE_LOGGING, FEATURE_ROOTS, FEATURE_SAMPLING,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::EXTENSION_ID as EVENTS_EXTENSION_ID;
use crate::protocol::v_2026_07_28::wire::lifecycle::{
    CacheCapability, CompletionCapability, DiscoverResult, EventsCapability, ImplementationInfo,
    PromptsCapability, ResourcesCapability, ServerCapabilities, ToolsCapability,
};
use crate::protocol::v_2026_07_28::wire::tools::CacheScope;
use crate::runtime::TransportKind;
use crate::runtime::shared_services::SharedServices;

/// `server/discover`'s `instructions` when `mcp.instructions` is unset.
const DEFAULT_INSTRUCTIONS: &str = "MCPG is speaking 2026-07-28. Capabilities reflect the \
     operator's configured bindings; absence of a capability means no backend is wired for it.";

pub(crate) fn build_discover_result(
    services: &SharedServices,
    transport: &TransportKind,
) -> DiscoverResult {
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

    // Enterprise-Managed Authorization: declared while the embedded
    // authorization server is installed. The live runtime is authoritative
    // because a reload rebuilds the server but not this config snapshot.
    // An HTTP-transport auth flow; stdio carries no bearer.
    let ema_installed = match live {
        Some(rt) => rt.ema_authorization_server().is_some(),
        None => services
            .config_snapshot
            .governance
            .access
            .authorization_server
            .is_some(),
    };
    if ema_installed && *transport == TransportKind::Http {
        extensions.insert(
            crate::runtime::authorization_server::EXTENSION_ID.to_owned(),
            serde_json::json!({}),
        );
    }

    // `dev.mcpg/idempotency`, advertised exactly as legacy `initialize`
    // advertises it: only while the operator enabled the extension.
    if let Some(idempotency) = live.and_then(|rt| rt.idempotency_capability()) {
        extensions.insert(
            crate::runtime::idempotency::EXTENSION_ID.to_owned(),
            idempotency.clone(),
        );
    }

    // MCP Events, in each location the operator chose. Config and the
    // installed core decide it, never the caller, because this result is
    // publicly cacheable.
    let events_config =
        crate::protocol::v_2026_07_28::dispatch::events::live_events_config(services);
    let events_served = crate::protocol::v_2026_07_28::dispatch::events::events_served(
        &events_config,
        services,
        transport,
    );
    // A reload that changes the event types sends
    // `notifications/events/list_changed` to `subscriptions/listen`.
    let served_capability = EventsCapability {
        list_changed: Some(true),
    };
    let events_capability =
        (events_served && events_config.advertises_capability()).then(|| served_capability.clone());
    if events_served && events_config.advertises_extension() {
        extensions.insert(EVENTS_EXTENSION_ID.to_owned(), served_capability.to_value());
    }

    // Same supported-versions surface as the unsupported-version
    // error response — keep the two correlated so the conformance
    // suite's `ServerUnsupportedVersionError` check sees a strict
    // subset relationship.
    let supported_versions = crate::protocol::served_protocol_versions(
        services.config_snapshot.gateway.server.legacy_wire,
    );

    let identity = &services.config_snapshot.mcp.server_info;
    DiscoverResult {
        result_type: crate::protocol::shared::caching::default_result_type_complete(),
        supported_versions,
        server_info: ImplementationInfo {
            name: identity.name.clone().unwrap_or_else(|| "mcpg".to_owned()),
            title: Some(
                identity
                    .title
                    .clone()
                    .unwrap_or_else(|| "MCPG — MCP Gateway".to_owned()),
            ),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            description: Some(identity.description.clone().unwrap_or_else(|| {
                "Cluster-aware MCP gateway with policy, quota, and observability plugins."
                    .to_owned()
            })),
            icons: crate::config::binding_icons(identity.icons.as_ref()),
            website_url: identity.website_url.clone(),
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
            events: events_capability,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        },
        instructions: Some(
            services
                .config_snapshot
                .mcp
                .instructions
                .clone()
                .unwrap_or_else(|| DEFAULT_INSTRUCTIONS.to_owned()),
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
mod events_advertisement_tests {
    use super::*;
    use crate::config::{AppConfig, EventsAdvertiseLocation};
    use crate::protocol::v_2026_07_28::dispatch::events::EventsHandler;
    use crate::protocol::v_2026_07_28::extensions::events::errors::EventsError;
    use crate::protocol::v_2026_07_28::extensions::events::wire::{
        ListEventsParams, ListEventsResult, PollEventsParams, PollEventsResult,
        SubscribeEventsParams, SubscribeEventsResult, UnsubscribeEventsParams,
        UnsubscribeEventsResult,
    };
    use crate::runtime::RequestContext;
    use std::sync::Arc;

    struct NoCore;

    #[async_trait::async_trait]
    impl EventsHandler for NoCore {
        async fn list(
            &self,
            _: &RequestContext,
            _: ListEventsParams,
        ) -> Result<ListEventsResult, EventsError> {
            Ok(ListEventsResult::new(Vec::new(), None))
        }
        async fn subscribe(
            &self,
            _: &RequestContext,
            _: SubscribeEventsParams,
        ) -> Result<SubscribeEventsResult, EventsError> {
            Err(EventsError::internal("unused"))
        }
        async fn unsubscribe(
            &self,
            _: &RequestContext,
            _: UnsubscribeEventsParams,
        ) -> Result<UnsubscribeEventsResult, EventsError> {
            Ok(UnsubscribeEventsResult::default())
        }
        async fn poll(
            &self,
            _: &RequestContext,
            _: PollEventsParams,
        ) -> Result<PollEventsResult, EventsError> {
            Err(EventsError::internal("unused"))
        }
    }

    fn services(
        enabled: bool,
        advertise: Vec<EventsAdvertiseLocation>,
        installed: bool,
    ) -> SharedServices {
        let mut config = AppConfig::default();
        config.mcp.configurations.events.enabled = enabled;
        config.mcp.configurations.events.advertise = advertise;
        let services = SharedServices::with_no_runtime(Arc::new(config));
        if installed {
            services
                .events
                .install(Arc::new(NoCore))
                .unwrap_or_else(|_| panic!("first install"));
        }
        services
    }

    fn capabilities(services: &SharedServices, transport: TransportKind) -> Value {
        let result = build_discover_result(services, &transport);
        serde_json::to_value(&result).unwrap()["capabilities"].clone()
    }

    fn both() -> Vec<EventsAdvertiseLocation> {
        vec![
            EventsAdvertiseLocation::Capability,
            EventsAdvertiseLocation::Extension,
        ]
    }

    #[test]
    fn enabled_events_are_advertised_in_both_locations() {
        let caps = capabilities(&services(true, both(), true), TransportKind::Http);
        assert_eq!(caps["events"], json!({"listChanged": true}));
        assert_eq!(
            caps["extensions"]["io.modelcontextprotocol/events"],
            json!({"listChanged": true})
        );
    }

    #[test]
    fn each_location_is_switchable() {
        let capability_only = capabilities(
            &services(true, vec![EventsAdvertiseLocation::Capability], true),
            TransportKind::Http,
        );
        assert_eq!(capability_only["events"], json!({"listChanged": true}));
        assert!(capability_only.get("extensions").is_none());

        let extension_only = capabilities(
            &services(true, vec![EventsAdvertiseLocation::Extension], true),
            TransportKind::Http,
        );
        assert!(extension_only.get("events").is_none());
        assert_eq!(
            extension_only["extensions"]["io.modelcontextprotocol/events"],
            json!({"listChanged": true})
        );
    }

    /// With events off, discover carries no `events` key and no extensions
    /// entry.
    #[test]
    fn disabled_events_leave_discover_unchanged() {
        let off = build_discover_result(&services(false, both(), true), &TransportKind::Http);
        let baseline = build_discover_result(
            &SharedServices::with_no_runtime(Arc::new(AppConfig::default())),
            &TransportKind::Http,
        );
        let off = serde_json::to_string(&off).unwrap();
        assert_eq!(off, serde_json::to_string(&baseline).unwrap());
        assert!(!off.contains("events"), "{off}");
    }

    /// Advertising a capability promises a handler behind it, so nothing
    /// is advertised until the events core is installed.
    #[test]
    fn nothing_is_advertised_without_a_core() {
        let caps = capabilities(&services(true, both(), false), TransportKind::Http);
        assert!(caps.get("events").is_none());
        assert!(caps.get("extensions").is_none());
    }

    #[test]
    fn stdio_never_advertises_events() {
        let caps = capabilities(&services(true, both(), true), TransportKind::Stdio);
        assert!(caps.get("events").is_none());
        assert!(caps.get("extensions").is_none());
    }
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
