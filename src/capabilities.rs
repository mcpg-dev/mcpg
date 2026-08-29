//! Capability manifest — what this gateway build accepts, as data.
//!
//! `mcpg capabilities` prints one JSON document describing the contracts a
//! control plane must validate a tenant config against before handing it to
//! THIS build: the full config JSON schema (so schema validation happens
//! against the target version, not whatever the CP was compiled beside), the
//! plugin ABI/protocol versions the loader enforces at dlopen, the MCP
//! revisions the wire speaks, and the plugin ids baked into the image.
//!
//! The manifest is versioned data, not prose: a control plane caches it per
//! image DIGEST (a tag can be rebuilt and moved; a digest cannot) and treats
//! an unknown `manifest_version` as unvalidatable — fail closed.

use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::Digest;

/// Bumped only when a FIELD changes meaning or disappears. Additive fields
/// do not bump it — consumers must ignore what they do not know.
const MANIFEST_VERSION: u32 = 1;

/// Where gateway images bake their plugins (`<dir>/<plugin id>/plugin.so`).
const BAKED_PLUGINS_DIR: &str = "/usr/local/lib/mcpg/plugins";

#[derive(Debug, Serialize)]
pub struct CapabilityManifest {
    pub manifest_version: u32,
    /// The gateway crate version this binary was built from.
    pub gateway_version: &'static str,
    /// FFI ABI generation the plugin loader refuses mismatches on.
    pub plugin_abi_version: u32,
    /// Plugin wire-protocol version (semver-of-`major.minor`).
    pub plugin_protocol_version: &'static str,
    /// MCP spec revisions this build serves.
    pub mcp_protocol_versions: Vec<&'static str>,
    /// SHA-256 of the canonical (compact) `config_schema` serialization —
    /// the cache key a consumer can compare without hauling the schema.
    pub config_schema_sha256: String,
    /// The full JSON Schema of `AppConfig` for THIS build.
    pub config_schema: serde_json::Value,
    /// Plugins shipped inside the image, discovered from the baked dir.
    pub baked_plugins: Vec<BakedPlugin>,
}

#[derive(Debug, Serialize)]
pub struct BakedPlugin {
    /// Plugin id (`dev.mcpg.<class>.<name>`), from the baked directory name.
    pub id: String,
    /// `class:` from the sidecar `plugin.yaml`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

/// Build the manifest for this binary, scanning `dir` for baked plugins.
pub fn manifest(baked_dir: &Path) -> CapabilityManifest {
    let schema = serde_json::to_value(schemars::schema_for!(crate::config::AppConfig))
        .expect("AppConfig schema serializes");
    let canonical = serde_json::to_vec(&schema).expect("schema value re-serializes compactly");
    let config_schema_sha256 = hex(&sha2::Sha256::digest(&canonical));

    CapabilityManifest {
        manifest_version: MANIFEST_VERSION,
        gateway_version: env!("CARGO_PKG_VERSION"),
        plugin_abi_version: mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_VERSION,
        plugin_protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION,
        mcp_protocol_versions: mcp_versions(),
        config_schema_sha256,
        config_schema: schema,
        baked_plugins: scan_baked(baked_dir),
    }
}

/// Entry point behind `mcpg capabilities`. `MCPG_BAKED_PLUGINS_DIR`
/// overrides the image-convention path for tests and unusual layouts.
pub fn print() -> anyhow::Result<()> {
    let dir = std::env::var_os("MCPG_BAKED_PLUGINS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BAKED_PLUGINS_DIR));
    let m = manifest(&dir);
    println!("{}", serde_json::to_string_pretty(&m)?);
    Ok(())
}

fn mcp_versions() -> Vec<&'static str> {
    use mcpg_mcp_wire::version::ProtocolVersion as V;
    // Listed explicitly; the match below fails to compile when a revision is
    // added, which is the reminder to extend this list.
    let all = [V::V_2025_11_25, V::V_2026_07_28];
    for v in all {
        match v {
            V::V_2025_11_25 | V::V_2026_07_28 => {}
        }
    }
    all.iter().map(|v| v.as_str()).collect()
}

/// One baked plugin per subdirectory that holds a plugin artifact. The dir
/// name IS the id (the image layout every gateway Dockerfile follows); the
/// sidecar `plugin.yaml` contributes `class` when it parses.
fn scan_baked(dir: &Path) -> Vec<BakedPlugin> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<BakedPlugin> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter(|e| {
            ["plugin.so", "plugin.dylib", "plugin.dll", "plugin.wasm"]
                .iter()
                .any(|a| e.path().join(a).is_file())
        })
        .map(|e| {
            let id = e.file_name().to_string_lossy().into_owned();
            let class = std::fs::read_to_string(e.path().join("plugin.yaml"))
                .ok()
                .and_then(|y| {
                    y.lines()
                        .find_map(|l| l.strip_prefix("class:").map(|v| v.trim().to_owned()))
                })
                .filter(|c| !c.is_empty());
            BakedPlugin { id, class }
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_complete_and_hash_matches_schema() {
        let m = manifest(Path::new("/nonexistent"));
        assert_eq!(m.manifest_version, 1);
        assert_eq!(
            m.plugin_abi_version,
            mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_VERSION
        );
        assert!(m.mcp_protocol_versions.contains(&"2025-11-25"));
        assert!(m.mcp_protocol_versions.contains(&"2026-07-28"));
        let canonical = serde_json::to_vec(&m.config_schema).unwrap();
        assert_eq!(
            m.config_schema_sha256,
            hex(&sha2::Sha256::digest(&canonical))
        );
        assert!(m.baked_plugins.is_empty());
        // The schema is the real one, not a stub.
        assert!(
            m.config_schema.get("definitions").is_some() || m.config_schema.get("$defs").is_some()
        );
    }

    #[test]
    fn baked_scan_reads_ids_and_classes() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("dev.mcpg.backend.http");
        std::fs::create_dir(&a).unwrap();
        std::fs::write(a.join("plugin.so"), b"x").unwrap();
        std::fs::write(
            a.join("plugin.yaml"),
            "id: dev.mcpg.backend.http\nclass: backend\n",
        )
        .unwrap();
        let b = dir.path().join("dev.mcpg.transform.masking");
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("plugin.wasm"), b"x").unwrap();
        // No artifact ⇒ not a plugin dir.
        std::fs::create_dir(dir.path().join("stray")).unwrap();

        let got = scan_baked(dir.path());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, "dev.mcpg.backend.http");
        assert_eq!(got[0].class.as_deref(), Some("backend"));
        assert_eq!(got[1].id, "dev.mcpg.transform.masking");
        assert_eq!(got[1].class, None);
    }
}
