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

/// The layout a baked plugin would occupy (`<dir>/<plugin id>/plugin.so`).
/// Published images ship none, so this scan reports an empty list for them —
/// an image that carries plugins is the exception the field exists to report.
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
    /// Cargo features this binary was built with, of the ones that change
    /// what it can do for a platform. A control plane blessing a release
    /// reads this: a gateway without `cp-attached` ignores the
    /// `gateway.control_plane` block it renders and never enrols.
    pub features: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct BakedPlugin {
    /// Plugin id (`dev.mcpg.<class>.<name>`), from the baked directory name.
    pub id: String,
    /// `class:` from the sidecar `plugin.yaml`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

/// Drop `description` keywords so the schema hash answers "did the config
/// CONTRACT change", not "did a doc comment change". `schemars` renders every
/// doc comment into the schema, so hashing it whole makes an edited sentence
/// indistinguishable from a renamed field — a consumer comparing the hash
/// across releases reads a docstring as a breaking change.
///
/// The keys of `properties` and friends are FIELD NAMES, not keywords, and the
/// config really does have fields called `description`. Those maps are
/// recursed through by value so such a field keeps its place in the hash;
/// removing the key there would silently drop a real part of the contract,
/// which is the failure this function exists to avoid.
fn strip_doc_text(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("description");
            for (key, child) in map.iter_mut() {
                if matches!(
                    key.as_str(),
                    "properties" | "patternProperties" | "$defs" | "definitions"
                ) {
                    if let serde_json::Value::Object(named) = child {
                        for (_, sub) in named.iter_mut() {
                            strip_doc_text(sub);
                        }
                    }
                } else {
                    strip_doc_text(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_doc_text(item);
            }
        }
        _ => {}
    }
}

/// Build the manifest for this binary, scanning `dir` for baked plugins.
pub fn manifest(baked_dir: &Path) -> CapabilityManifest {
    let schema = serde_json::to_value(schemars::schema_for!(crate::config::AppConfig))
        .expect("AppConfig schema serializes");
    let mut structural = schema.clone();
    strip_doc_text(&mut structural);
    let canonical = serde_json::to_vec(&structural).expect("schema value re-serializes compactly");
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
        features: built_features(),
    }
}

/// The product-relevant features compiled in. Listed by hand: a feature is
/// only worth reporting when a platform decides something on it.
fn built_features() -> Vec<&'static str> {
    let mut out = Vec::new();
    if cfg!(feature = "cp-attached") {
        out.push("cp-attached");
    }
    if cfg!(feature = "governance-quotas") {
        out.push("governance-quotas");
    }
    out
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
        // The published schema keeps its prose; the hash is taken over the
        // structure alone, so reproducing it means stripping the doc text the
        // same way.
        let mut structural = m.config_schema.clone();
        strip_doc_text(&mut structural);
        let canonical = serde_json::to_vec(&structural).unwrap();
        assert_eq!(
            m.config_schema_sha256,
            hex(&sha2::Sha256::digest(&canonical))
        );
        assert!(
            serde_json::to_string(&m.config_schema)
                .unwrap()
                .contains("\"description\""),
            "the published schema should still carry its documentation"
        );
        assert!(m.baked_plugins.is_empty());
        // The manifest reports what this build carries — a control plane
        // reads it before blessing — and it must agree with the compiler.
        assert_eq!(
            m.features.contains(&"cp-attached"),
            cfg!(feature = "cp-attached"),
            "features: {:?}",
            m.features
        );
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

    /// A doc-comment edit must not move the hash: the signal answers "did the
    /// config contract change", and a consumer that sees it move reads a
    /// breaking change. Structural edits must still move it, or it says nothing.
    #[test]
    fn schema_hash_covers_structure_not_prose() {
        use serde_json::json;
        let hash = |v: &serde_json::Value| {
            let mut c = v.clone();
            super::strip_doc_text(&mut c);
            super::hex(&sha2::Sha256::digest(
                serde_json::to_vec(&c).expect("re-serializes"),
            ))
        };
        let base = json!({
            "type": "object",
            "description": "the gateway config",
            "properties": {
                "port": { "type": "integer", "description": "listening port" }
            }
        });
        let mut reworded = base.clone();
        reworded["description"] = json!("THE GATEWAY CONFIGURATION");
        reworded["properties"]["port"]["description"] = json!("the port it listens on");
        assert_eq!(hash(&base), hash(&reworded), "a docstring moved the hash");

        let mut retyped = base.clone();
        retyped["properties"]["port"]["type"] = json!("string");
        assert_ne!(
            hash(&base),
            hash(&retyped),
            "a type change did not move the hash"
        );

        let mut added = base.clone();
        added["properties"]["host"] = json!({ "type": "string" });
        assert_ne!(
            hash(&base),
            hash(&added),
            "a new field did not move the hash"
        );
    }

    /// The config really has fields NAMED `description`, and the keys of a
    /// `properties` map are field names rather than keywords. Dropping them
    /// would remove part of the contract from the very signal that reports it.
    #[test]
    fn a_field_named_description_survives_stripping() {
        use serde_json::json;
        let mut schema = json!({
            "type": "object",
            "description": "prose that must go",
            "properties": {
                "description": { "type": "string", "description": "prose that must go" }
            }
        });
        super::strip_doc_text(&mut schema);
        assert!(
            schema["properties"]["description"].is_object(),
            "the field named `description` was dropped from the hashed structure"
        );
        assert_eq!(schema["properties"]["description"]["type"], json!("string"));
        assert!(schema.get("description").is_none(), "the keyword survived");
        assert!(
            schema["properties"]["description"]
                .get("description")
                .is_none(),
            "the field's own doc text survived"
        );
    }
}
