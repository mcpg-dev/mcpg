//! Packaged (`.zip`) plugin loading: local-path patching for the
//! OCI-pull path, archive unpack + verify + load, and path-safe id
//! sanitisation.

use super::*;

/// Return a shallow copy of `entry` whose `source.path` points at
/// `local`. Used by the OCI pull path so the downstream
/// `load_packaged_plugin` sees a plain local-path entry.
pub(crate) fn patch_entry_with_local_path(
    entry: &crate::config::PluginEntryConfig,
    local: std::path::PathBuf,
) -> crate::config::PluginEntryConfig {
    let mut patched = entry.clone();
    patched.source = crate::config::PluginSourceConfig {
        path: Some(local.display().to_string()),
        oci: None,
    };
    patched
}

/// Load a plugin from a packaged `.zip` archive (see
/// `mcpg_plugin_host::package`).
///
/// Unpacks the archive into a stable per-plugin cache directory
/// under the OS temp dir, renames the embedded `plugin.sig` (if
/// present) to `<artifact>.sig` so the existing co-located
/// signature verification path finds it, and dispatches to the
/// native-cdylib or WASI loader based on the descriptor's
/// `runtime` field. Registration runs through
/// [`FirstPartyRegistrar::register_with_descriptor`] so the
/// declared descriptor is cross-checked against the plugin's
/// runtime-reported manifest — a tampered zip whose artifact
/// disagrees with the descriptor fails startup loudly.
///
/// `default_policy` + `revocation_list` provide the gateway-wide
/// fallbacks; the entry's own `signature.*` block (if present)
/// overrides the policy and contributes its own trusted keys.
/// Drives Ed25519 verification for BOTH `native-cdylib-v1` and
/// `wasi-v1` packages: Wasmtime sandboxes the guest at
/// runtime, but the artifact bytes still get the same SHA-256 pin +
/// signature + revocation gate before load.
pub(crate) fn load_packaged_plugin(
    registry: &mut mcpg_plugin_host::PluginRegistry,
    entry: &crate::config::PluginEntryConfig,
    registry_cfg: &crate::config::PluginRegistryConfig,
    revocation_list: Option<mcpg_plugin_host::revocation::RevocationList>,
    host_services_late: std::sync::Arc<mcpg_plugin_host::host_services::LateBoundHostServices>,
) -> Result<()> {
    #[cfg(feature = "wasm-plugins")]
    use mcpg_plugin_protocol::PluginClass;
    use mcpg_plugin_protocol::RuntimeClass;

    let zip_path_str =
        entry.source.path.as_deref().ok_or_else(|| {
            anyhow::anyhow!("plugin '{}': packaged source has empty path", entry.id)
        })?;
    let zip_path = std::path::Path::new(zip_path_str);
    if !zip_path.exists() {
        return Err(anyhow::anyhow!(
            "plugin '{}': package not found at {}",
            entry.id,
            zip_path.display()
        ));
    }

    // Sha256-keyed unpack cache: `<tmp>/mcpg-plugin-cache/<id>/<hash>/`.
    // On repeat boots with an unchanged archive, the previous
    // extraction is reused without touching the zip again beyond
    // computing the hash. When the archive changes the hash
    // changes and a fresh directory is populated; old hash dirs
    // are left in place (a separate `mcpg-plugin cache gc` tool
    // could prune them in the future).
    let base_cache_dir = std::env::temp_dir()
        .join("mcpg-plugin-cache")
        .join(sanitize_for_path(&entry.id));

    let unpacked = mcpg_plugin_host::Package::unpack_cached_to(zip_path, &base_cache_dir)?;

    // Cross-check the packaged descriptor's
    // manifest id against the entry's effective ref (`ref` if set,
    // else `id`). Single-instance configs unaffected.
    let expected_ref = entry.ref_or_id();
    if unpacked.descriptor.id != expected_ref {
        return Err(anyhow::anyhow!(
            "plugin alias '{}': packaged descriptor declares manifest id {:?} \
             but entry expects ref '{}'",
            entry.id,
            unpacked.descriptor.id,
            expected_ref,
        ));
    }

    // Put the signature on the sidecar path
    // `<artifact>.sig` so `verify::verify_file_signature` finds
    // it without changes. Idempotent: on a cache hit the
    // `plugin.sig` has been renamed on the previous boot, so we
    // skip. On a fresh unpack the file is renamed exactly once.
    if let Some(sig_src) = &unpacked.signature_path {
        let sig_dst = unpacked.artifact_path.with_file_name(format!(
            "{}.sig",
            unpacked
                .artifact_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
        ));
        if sig_src != &sig_dst && sig_src.exists() && !sig_dst.exists() {
            std::fs::rename(sig_src, &sig_dst).map_err(|e| {
                anyhow::anyhow!("plugin '{}': cannot rename signature file: {e}", entry.id)
            })?;
        }
    }

    let config_json = entry.config.clone();
    let enforce = entry.enforce;
    let plugin_id = entry.id.clone();
    let artifact_path = unpacked.artifact_path.clone();
    let descriptor = unpacked.descriptor.clone();

    match descriptor.runtime {
        RuntimeClass::StaticFirstparty => {
            return Err(anyhow::anyhow!(
                "plugin '{}': packaged plugins cannot declare runtime static-firstparty-v1 \
                 — static plugins are compiled into the gateway",
                entry.id
            ));
        }
        RuntimeClass::NativeCdylib => {
            let verify_opts =
                derive_native_verify_options_for_entry(entry, registry_cfg, revocation_list)?;
            let ffi_limits = derive_ffi_limits_for_entry(entry);
            let loaded = mcpg_plugin_host::native_loader::load_native_plugin(
                &artifact_path,
                &verify_opts,
                ffi_limits,
            )?;
            info!(
                plugin_id = %plugin_id,
                path = %artifact_path.display(),
                hash = %loaded.meta.artifact_hash.as_deref().unwrap_or(""),
                signature_verified = loaded.meta.signature_verified,
                "packaged native plugin loaded"
            );
            // Run plugin.lifecycle.register policy chain. Use
            // block_in_place + block_on so the surrounding sync
            // function doesn't have to plumb async; the only
            // caller (entries-load loop in `build_from_config`)
            // runs inside a tokio context.
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(enforce_plugin_registration_policy(
                    registry,
                    &loaded,
                    config_json.clone(),
                    &entry.id,
                ))
            })?;
            // Cross-check descriptor vs cdylib
            // capability declarations. They are the same concept in
            // two file locations; a mismatch is a packaging bug
            // (e.g. plugin.yaml updated but cdylib not rebuilt). Fail
            // boot rather than silently picking one.
            mcpg_plugin_host::cross_check_cdylib_capabilities(
                &descriptor.id,
                &descriptor.required_capabilities,
                &loaded.required_capabilities,
            )?;
            // A cdylib's exported entities are authoritative for what gets
            // registered; the descriptor's `class` is the packaging claim.
            // Refuse the mismatch rather than register a surface the operator
            // did not audit.
            super::entities::cross_check_descriptor_class(&entry.id, descriptor.class, &loaded)?;
            let opts = super::entities::NativeEntryOptions {
                alias: entry.id.clone(),
                config: config_json,
                inline_dispatch: entry.inline_dispatch,
                enforce,
                http_route: super::entities::native_http_route_overrides(entry),
            };
            let svc = host_services_late.resolve();
            // Record the operator's granted capabilities under this entry's
            // alias (entry.id — the alias the host bridge carries into every
            // host-service callback) so GatewayHostServices can filter per
            // call. Same as the inline native path; packaged (.zip/OCI)
            // cdylibs need it too.
            //
            // INVARIANT: the registrar closure below builds every adapter with
            // `alias_for_adapter = entry.id`, so the bridge alias == this record
            // key. A future arm that hands the bridge a different alias would
            // fail-closed deny — keep the record key and the adapter alias equal.
            registry
                .record_granted_capabilities(entry.id.clone(), entry.granted_capabilities.clone());
            // Config-origin `cred://` allowlist: a cdylib may resolve only
            // the credential issuers — and the exact targets — its own config
            // references.
            registry.record_cred_resolve_allowlist(
                entry.id.clone(),
                mcpg_plugin_host::credential_resolver::collect_cred_issuers(&entry.config),
            );
            registry.record_cred_resolve_ref_allowlist(
                entry.id.clone(),
                mcpg_plugin_host::credential_resolver::collect_cred_refs(&entry.config),
            );
            mcpg_plugin_host::FirstPartyRegistrar::new(registry).register_with_descriptor(
                &descriptor,
                &entry.granted_capabilities,
                (),
                move |registry, _host| {
                    super::entities::register_native_entities(registry, &loaded, svc, &opts)
                },
            )?;
        }
        RuntimeClass::Wasi => {
            #[cfg(not(feature = "wasm-plugins"))]
            {
                let _ = (artifact_path, config_json, enforce, plugin_id);
                return Err(anyhow::anyhow!(
                    "plugin '{}': WASI package but this gateway build has no wasm-plugins feature",
                    entry.id
                ));
            }
            #[cfg(feature = "wasm-plugins")]
            {
                let wasm_engine = mcpg_plugin_host::wasm::create_wasm_engine()?;
                // Hold a packaged / OCI WASI guest to the SAME
                // integrity bar as the loose-`.wasm` and native-cdylib paths
                // — SHA-256 pin + Ed25519 signature (per-entry policy, with
                // gateway-wide `default_policy` fallback) + revocation —
                // instead of `WasmLoadOptions::default()` (policy=Warn, no
                // keys), which would load an OCI/packaged WASM plugin UNVERIFIED
                // even under `signature.policy: enforce`.
                let load_options = mcpg_plugin_host::wasm::WasmLoadOptions {
                    verify: derive_native_verify_options_for_entry(
                        entry,
                        registry_cfg,
                        revocation_list,
                    )?,
                    limits: {
                        let mut limits = mcpg_plugin_host::wasm::WasmResourceLimits::default();
                        if let Some(rl) = &entry.limits {
                            if let Some(mem) = rl.memory_mb {
                                limits.memory_limit_bytes = mem as usize * 1024 * 1024;
                            }
                            if let Some(fuel) = rl.fuel {
                                limits.fuel_per_invocation = fuel;
                            }
                            if let Some(timeout) = rl.timeout_ms {
                                limits.timeout_ms = timeout;
                            }
                        }
                        limits
                    },
                };
                let artifact = mcpg_plugin_host::wasm::load_wasm_component(
                    &wasm_engine,
                    &artifact_path,
                    &load_options,
                )?;
                info!(
                    plugin_id = %plugin_id,
                    path = %artifact_path.display(),
                    "packaged wasm plugin loaded"
                );
                let desc_for_reg = descriptor.clone();
                mcpg_plugin_host::FirstPartyRegistrar::new(registry).register_with_descriptor(
                    &descriptor,
                    &entry.granted_capabilities,
                    (),
                    move |registry, _host| match desc_for_reg.class {
                        PluginClass::ToolGate => {
                            let p = mcpg_plugin_host::wasm::WasmToolGatePlugin::new(
                                wasm_engine,
                                artifact,
                            )?;
                            registry.register_tool_gate_with_enforce(
                                Box::new(p),
                                mcpg_plugin_protocol::PluginTier::Wasm,
                                config_json,
                                enforce,
                            )
                        }
                        PluginClass::Transform => {
                            let p = mcpg_plugin_host::wasm::WasmTransformPlugin::new(
                                wasm_engine,
                                artifact,
                            )?;
                            registry.register_transform(
                                Box::new(p),
                                mcpg_plugin_protocol::PluginTier::Wasm,
                                config_json,
                            )
                        }
                        PluginClass::IdentityProvider => {
                            let p = mcpg_plugin_host::wasm::WasmIdentityPlugin::new(
                                wasm_engine,
                                artifact,
                            )?;
                            registry.register_identity(
                                Box::new(p),
                                mcpg_plugin_protocol::PluginTier::Wasm,
                                config_json,
                            )
                        }
                        other => Err(anyhow::anyhow!(
                            "packaged wasm plugin declared unsupported class: {other}"
                        )),
                    },
                )?;
            }
        }
    }

    Ok(())
}

/// Strip characters unsafe in path components from a plugin id so
/// the unpack cache dir name is always valid on every host FS.
pub(crate) fn sanitize_for_path(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
