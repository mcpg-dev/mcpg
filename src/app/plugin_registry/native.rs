//! Native cdylib plugin verification: per-entry signature options
//! and FFI-limit derivation.

use super::*;

/// Official mcpg plugin-signing public keys, compiled into the binary
/// so a stock gateway can verify first-party plugins with zero key
/// configuration. PEM blocks; the file may be empty (no anchors yet).
const OFFICIAL_SIGNING_KEYS_PEM: &str =
    include_str!("../../runtime/assets/official_plugin_signing_keys.pem");

/// Decode every PEM block in the built-in bundle. Cheap enough to run
/// per entry; a malformed bundle is a build defect and aborts boot.
fn official_signing_keys() -> Result<Vec<[u8; 32]>> {
    let mut keys = Vec::new();
    let mut block = String::new();
    let mut in_block = false;
    for line in OFFICIAL_SIGNING_KEYS_PEM.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            block.clear();
        }
        if in_block {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END") {
            in_block = false;
            keys.push(
                mcpg_plugin_host::verify::decode_pem_ed25519_public_key(&block)
                    .context("built-in official signing key bundle: PEM decode failed")?,
            );
        }
    }
    Ok(keys)
}

/// Build `NativeVerifyOptions` from the per-entry signature
/// configuration on a [`PluginEntryConfig`].
///
/// Resolution rules:
/// - **Policy** — `entry.signature.policy` if set, else fall back
///   to `gateway.plugin_registry.default_signature_policy`.
/// - **Trusted keys** — an entry that carries its own
///   `signature.trusted_keys` verifies against exactly those (PEM,
///   PKCS#8 SPKI for Ed25519; a malformed PEM aborts boot with the
///   offending plugin id + key id). An entry with none inherits the
///   gateway-wide `plugin_registry.trusted_keys` plus the built-in
///   official mcpg release keys.
/// - **Expected SHA-256** — `entry.signature.sha256` when set.
/// - **Revocation list** — single registry-wide list shared
///   across all entries; loaded once at gateway startup.
pub(crate) fn derive_native_verify_options_for_entry(
    entry: &crate::config::PluginEntryConfig,
    registry: &crate::config::PluginRegistryConfig,
    revocation_list: Option<mcpg_plugin_host::revocation::RevocationList>,
) -> Result<mcpg_plugin_host::native::NativeVerifyOptions> {
    let signature_cfg = entry.signature.as_ref();
    let policy: mcpg_plugin_host::SignaturePolicy = signature_cfg
        .and_then(|s| s.policy)
        .unwrap_or(registry.default_signature_policy)
        .into();
    let decode_all = |keys: &[crate::config::TrustedKeyConfig],
                      scope: &str|
     -> Result<Vec<[u8; 32]>> {
        keys.iter()
            .map(|k| {
                mcpg_plugin_host::verify::decode_pem_ed25519_public_key(&k.pem).with_context(|| {
                    format!(
                        "plugin '{}' {scope}.trusted_keys[id={}]: PEM decode failed",
                        entry.id, k.id
                    )
                })
            })
            .collect()
    };
    let per_entry = signature_cfg.map(|s| &s.trusted_keys[..]).unwrap_or(&[]);
    let trusted_public_keys: Vec<[u8; 32]> = if per_entry.is_empty() {
        let mut keys = decode_all(&registry.trusted_keys, "plugin_registry")?;
        keys.extend(official_signing_keys()?);
        keys
    } else {
        decode_all(per_entry, "signature")?
    };
    let expected_sha256 = signature_cfg.and_then(|s| s.sha256.clone());
    Ok(mcpg_plugin_host::native::NativeVerifyOptions {
        expected_sha256,
        trusted_public_keys,
        policy,
        revocation_list,
    })
}

/// Derive per-entry `FfiLimits` from `plugins[].ffi_limits`.
/// Missing fields inherit the spec constants in
/// `mcpg_plugin_protocol::abi`.
pub(crate) fn derive_ffi_limits_for_entry(
    entry: &crate::config::PluginEntryConfig,
) -> mcpg_plugin_host::native_loader::FfiLimits {
    let mut limits = mcpg_plugin_host::native_loader::FfiLimits::default();
    if let Some(cfg) = entry.ffi_limits.as_ref() {
        if let Some(ms) = cfg.lifecycle_timeout_ms {
            limits.lifecycle_timeout = std::time::Duration::from_millis(ms);
        }
        if let Some(ms) = cfg.control_timeout_ms {
            limits.control_timeout = std::time::Duration::from_millis(ms);
        }
        if let Some(ms) = cfg.data_timeout_ms {
            limits.data_timeout = std::time::Duration::from_millis(ms);
        }
        if let Some(bytes) = cfg.max_payload_bytes {
            limits.max_payload_bytes = bytes;
        }
    }
    limits
}
