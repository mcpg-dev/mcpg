//! Per-entity registration for native (cdylib) plugins.
//!
//! A cdylib declares its entities as a vec of [`EntityRegistration`]
//! variants; a multi-vtable plugin (e.g. tool-gate-slack-approval, which
//! exports ToolGate + ApprovalNotifier + HttpRoute) emits one entry per
//! vtable. Every load path — loose `.so`/`.dylib`/`.dll` and packaged
//! (`.zip` / OCI) — walks that vec through here, so what a plugin exports
//! is what the gateway registers regardless of how the operator shipped it.

use anyhow::Result;
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::host_services::HostServices;
use mcpg_plugin_host::native_loader::LoadedNativePlugin;
use mcpg_plugin_protocol::abi::EntityRegistration;
use std::sync::Arc;

/// The operator-supplied half of a native plugin registration: the fields
/// that come from the `plugins[]` entry rather than from the cdylib.
pub(crate) struct NativeEntryOptions {
    /// Operator alias (`entry.id`). Doubles as the host-services bridge
    /// alias and the granted-capability lookup key, so every adapter built
    /// below MUST pass it verbatim as its `with_services` alias — an
    /// adapter built under a different alias fail-closed denies its
    /// host-service calls.
    pub alias: String,
    /// Verbatim `entry.config` JSON; the plugin's `make` vtable consumes it.
    pub config: serde_json::Value,
    /// Operator-trusted inline fast-slot dispatch (no ferry/timeout).
    pub inline_dispatch: bool,
    /// `false` puts tool gates in shadow mode (evaluate + log, Deny→Allow).
    pub enforce: bool,
    /// Per-entry `http_route` overrides. The registry still refuses
    /// `allow_path_override` unless the plugin declares the typed
    /// `HttpRouteServe` capability, so an unset value is the safe default.
    pub http_route: mcpg_plugin_host::HttpRouteOverrides,
}

/// Project a plugin entry's `http_route:` block onto the registry's
/// override shape (the registry crate stays independent of gateway config
/// types, so the two structs are mirrored rather than shared).
pub(crate) fn native_http_route_overrides(
    entry: &crate::config::PluginEntryConfig,
) -> mcpg_plugin_host::HttpRouteOverrides {
    entry
        .http_route
        .as_ref()
        .map(|h| mcpg_plugin_host::HttpRouteOverrides {
            max_body_bytes: h.max_body_bytes,
            requires_identity: h.requires_identity,
            allow_path_override: h.allow_path_override,
        })
        .unwrap_or_default()
}

/// Bridge the ABI vtables onto the in-tree async trait objects and register
/// every class the cdylib exports.
///
/// The match is exhaustive — adding a kind to the FFI enum forces a new arm
/// here, so no load path can silently forget one.
pub(crate) fn register_native_entities(
    registry: &mut PluginRegistry,
    loaded: &Arc<LoadedNativePlugin>,
    svc: Arc<dyn HostServices>,
    opts: &NativeEntryOptions,
) -> Result<()> {
    for entity in &loaded.registration.entities {
        // A multi-entity cdylib registers each entity under a DISTINCT
        // registry alias derived from its `inner_name`, so the global
        // `check_duplicate_alias` (which spans all kinds) doesn't reject the
        // 2nd+ entity of the same plugin. A single-entity plugin
        // (`inner_name == ""`) keeps `alias == opts.alias`. The
        // host-services bridge alias stays `opts.alias` — only the registry
        // row alias is composed.
        let registry_alias = if entity.inner_name().is_empty() {
            opts.alias.clone()
        } else {
            format!("{}:{}", opts.alias, entity.inner_name())
        };
        match entity {
            EntityRegistration::ToolGate { .. } => {
                let mut adapter = mcpg_plugin_host::native_loader::NativeToolGateAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                adapter.set_inline_fast(opts.inline_dispatch);
                registry.register_tool_gate_with_alias(
                    Some(registry_alias.clone()),
                    Box::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    opts.config.clone(),
                    opts.enforce,
                )?;
            }
            EntityRegistration::Transform { .. } => {
                let mut adapter = mcpg_plugin_host::native_loader::NativeTransformAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                adapter.set_inline_fast(opts.inline_dispatch);
                registry.register_transform_with_alias(
                    Some(registry_alias.clone()),
                    Box::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    opts.config.clone(),
                )?;
            }
            EntityRegistration::IdentityProvider { .. } => {
                // Identity `make` takes the host-filled cluster ref so
                // cluster-aware providers (workload, …) can opt in; `None`
                // when no coordinator is registered.
                let cluster_ref = registry.cluster_backend_ffi_ref();
                let mut adapter =
                    mcpg_plugin_host::native_loader::NativeIdentityProviderAdapter::new(
                        loaded.clone(),
                        opts.config.clone(),
                        opts.alias.clone(),
                        svc.clone(),
                        cluster_ref,
                    )?;
                adapter.set_inline_fast(opts.inline_dispatch);
                registry.register_identity_with_alias(
                    Some(registry_alias.clone()),
                    Box::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    opts.config.clone(),
                )?;
            }
            EntityRegistration::ApprovalNotifier { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeApprovalNotifierAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_approval_notifier_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::PolicyEngine { .. } => {
                // Policy engines take the cluster ref the same way identity
                // providers do: Cedar / Casbin use it for entity-set sync,
                // OPA to coordinate bundle reload across replicas.
                let cluster_ref = registry.cluster_backend_ffi_ref();
                let adapter = mcpg_plugin_host::native_loader::NativePolicyEngineAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                    cluster_ref,
                )?;
                registry.register_policy_engine_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::Backend { .. } => {
                let mut adapter = mcpg_plugin_host::native_loader::NativeBackendAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                adapter.set_inline_fast(opts.inline_dispatch);
                registry.register_backend_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::WatchStrategy { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeWatchStrategyAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_watch_strategy_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::HttpRoute { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeHttpRouteAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                // entity_name keys the (plugin_id, entity_name) mount and is
                // embedded in the mount path: for a single-entity plugin it
                // stays the operator alias, for a multi-entity cdylib it's
                // the per-entity inner_name so each route gets a distinct
                // path.
                let route_entity_name = if entity.inner_name().is_empty() {
                    opts.alias.clone()
                } else {
                    entity.inner_name().to_owned()
                };
                registry.register_http_route_with_alias_and_overrides(
                    Some(registry_alias.clone()),
                    route_entity_name,
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    opts.http_route.clone(),
                    &loaded.required_capabilities,
                )?;
            }
            EntityRegistration::AuditSink { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeAuditSinkAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_audit_sink_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::LogSink { .. } => {
                let mut adapter = mcpg_plugin_host::native_loader::NativeLogSinkAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                adapter.set_inline_fast(opts.inline_dispatch);
                registry.register_log_sink_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::TelemetrySink { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeTelemetrySinkAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_telemetry_sink_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::MetricsSink { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeMetricsSinkAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_metrics_sink_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::Store { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeStoreAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_store_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::Cache { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeCacheAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_cache_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::SecretProvider { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeSecretProviderAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_secret_provider_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::ConfigProvider { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeConfigProviderAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_config_provider_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::Transport { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeTransportAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_transport_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::Cluster { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeClusterAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_cluster_backend_with_ffi(
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    None,
                )?;
            }
            EntityRegistration::CatalogProvider { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeCatalogProviderAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_catalog_provider_with_alias(
                    Some(registry_alias.clone()),
                    Box::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                    opts.config.clone(),
                )?;
            }
            EntityRegistration::CredentialIssuer { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeCredentialIssuerAdapter::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_credential_issuer_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
            EntityRegistration::ContentStore { .. } => {
                let adapter = mcpg_plugin_host::native_loader::NativeContentStorePlugin::new(
                    loaded.clone(),
                    opts.config.clone(),
                    opts.alias.clone(),
                    svc.clone(),
                )?;
                registry.register_content_store_with_alias(
                    Some(registry_alias.clone()),
                    Arc::new(adapter),
                    mcpg_plugin_protocol::PluginTier::Native,
                )?;
            }
        }
        // Host-derive the manifest's typed capability projection from the
        // cdylib's authoritative FFI decls (a plugin's manifest() ships an
        // empty list) so admin inventory reflects what's enforced.
        registry.set_manifest_caps(&registry_alias, &loaded.required_capabilities);
    }
    Ok(())
}

/// Refuse a package whose descriptor `class` names a kind the binary does
/// not export. Same failure class as the capability cross-check: plugin.yaml
/// and the cdylib are two locations for one fact, and a mismatch means the
/// package was assembled from a stale build.
pub(crate) fn cross_check_descriptor_class(
    plugin_id: &str,
    class: mcpg_plugin_protocol::PluginClass,
    loaded: &LoadedNativePlugin,
) -> Result<()> {
    let exported: Vec<&str> = loaded
        .registration
        .entities
        .iter()
        .map(|e| e.kind())
        .collect();
    check_declared_class_is_exported(plugin_id, class, &exported)
}

/// Kind-string half of [`cross_check_descriptor_class`], split out so the
/// comparison is testable without a dlopen'd library.
fn check_declared_class_is_exported(
    plugin_id: &str,
    class: mcpg_plugin_protocol::PluginClass,
    exported: &[&str],
) -> Result<()> {
    let declared = class.to_string();
    if exported.contains(&declared.as_str()) {
        return Ok(());
    }
    anyhow::bail!(
        "plugin '{plugin_id}': descriptor declares class '{declared}' but the \
         library exports {exported:?} — rebuild the package from the current cdylib"
    )
}

#[cfg(test)]
mod tests {
    use super::check_declared_class_is_exported;
    use mcpg_plugin_protocol::PluginClass;

    /// The descriptor's class must name one of the kinds the binary really
    /// exports — a multi-entity cdylib satisfies it via any of them.
    #[test]
    fn declared_class_matching_any_exported_kind_passes() {
        let exported = ["tool_gate", "approval_notifier", "http_route"];
        for class in [
            PluginClass::ToolGate,
            PluginClass::ApprovalNotifier,
            PluginClass::HttpRoute,
        ] {
            assert!(
                check_declared_class_is_exported("dev.mcpg.test", class, &exported).is_ok(),
                "{class} is exported but was rejected"
            );
        }
    }

    /// plugin.yaml and the cdylib are two locations for one fact; a
    /// descriptor naming a kind the binary does not export means the package
    /// was assembled from a stale build, and boot must refuse it.
    #[test]
    fn declared_class_absent_from_the_library_is_refused() {
        let err = check_declared_class_is_exported(
            "dev.mcpg.test",
            PluginClass::Backend,
            &["tool_gate", "http_route"],
        )
        .expect_err("a class the library does not export must fail boot");
        let msg = err.to_string();
        assert!(msg.contains("dev.mcpg.test"), "{msg}");
        assert!(msg.contains("backend"), "{msg}");
        assert!(msg.contains("tool_gate"), "{msg}");
    }

    /// An empty entity vec is the degenerate stale-package case.
    #[test]
    fn library_exporting_nothing_is_refused() {
        assert!(
            check_declared_class_is_exported("dev.mcpg.test", PluginClass::ToolGate, &[]).is_err()
        );
    }

    /// `PluginClass: Display` and `EntityRegistration::kind()` are two
    /// hand-written matches over the same vocabulary; the cross-check
    /// compares them as strings, so any divergence would silently reject
    /// valid packages.
    #[test]
    fn every_plugin_class_has_a_matching_entity_kind() {
        let kinds = [
            "tool_gate",
            "transform",
            "identity_provider",
            "backend",
            "watch_strategy",
            "http_route",
            "audit_sink",
            "log_sink",
            "telemetry_sink",
            "metrics_sink",
            "store",
            "cache",
            "secret_provider",
            "config_provider",
            "policy_engine",
            "cluster",
            "transport",
            "catalog_provider",
            "credential_issuer",
            "approval_notifier",
            "content_store",
        ];
        for class in PluginClass::ALL {
            assert!(
                kinds.contains(&class.to_string().as_str()),
                "PluginClass::{class} has no EntityRegistration::kind() counterpart"
            );
        }
        assert_eq!(
            PluginClass::ALL.len(),
            kinds.len(),
            "entity-kind list drifted from PluginClass::ALL"
        );
    }
}
