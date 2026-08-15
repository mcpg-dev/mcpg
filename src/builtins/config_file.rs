//! Built-in `config_provider` plugin — `dev.mcpg.builtin.config.file`.
//!
//! Resolves `file:///absolute/path.(yaml|yml|json)` references by
//! reading + parsing the document from the local filesystem. Watch
//! is unsupported — native inotify / kqueue / ReadDirectoryChangesW
//! semantics are subtle enough to deserve a dedicated plugin. For
//! reload-on-change, a consumer polls `snapshot` at its own cadence
//! (gateway reconciliation loop typically runs every 30s).
//!
//! # Version identifier
//!
//! The snapshot's `version` is a SHA-256 digest of the file's raw
//! bytes, prefixed `sha256:`. That keeps it:
//! - **Stable** — same bytes ⇒ same version across restarts.
//! - **Collision-safe** — backends that swap documents semantically
//!   but preserve structure (common for Consul KV edits) get a
//!   fresh version on any byte-level change.
//! - **Dep-free** — no mtime vs content-hash ambiguity; we already
//!   pull sha2 for audit receipts.
//!
//! # Security
//!
//! Same trust model as `secret.file`: `..` traversal is NOT filtered;
//! operator configs are trusted input; the OS-level sandbox enforces
//! what paths the gateway process can actually read.

use std::path::PathBuf;
use std::sync::Arc;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    config::{ConfigError, ConfigProvider, ConfigSnapshot, parse_config_ref},
};
use sha2::{Digest, Sha256};

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.config.file
name: Built-in File Config Provider
description: |
  Gateway-bundled config provider: resolves file:///path.(yaml|yml|json)
  URIs against the local filesystem. YAML and JSON are both accepted;
  the document must be a JSON-compatible map at the top level. Watch
  is unsupported — native filesystem watchers belong in a dedicated
  plugin; consumers poll snapshot on a reconciliation timer instead.
  Always auto-bound to the `file` scheme unless the operator
  overrides via plugins.configs.file.
class: config_provider
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

pub struct FileConfigProvider {
    manifest: PluginManifest,
}

impl FileConfigProvider {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.config.file".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in File Config Provider".into(),
                plugin_class: PluginClass::ConfigProvider,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
        })
    }
}

/// Same parsing rules as `secret.file` — anchor stripped, the rest
/// read verbatim as a filesystem path. The fragment (`#...`) is
/// reserved for provider-specific addressing into the document;
/// the file provider ignores it for now.
fn parse_file_path(rest: &str) -> PathBuf {
    let no_anchor = rest.split('#').next().unwrap_or(rest);
    PathBuf::from(no_anchor)
}

/// Parse bytes as YAML first, JSON second. YAML is a superset of
/// JSON so a YAML parse that succeeds on JSON input is fine; the
/// fallback to JSON exists so strict JSON configs that hit a
/// theoretical YAML 1.1 edge-case still round-trip.
fn parse_document(bytes: &[u8]) -> Result<serde_json::Value, ConfigError> {
    // YAML first.
    match serde_yaml::from_slice::<serde_yaml::Value>(bytes) {
        Ok(yaml) => yaml_to_json(yaml),
        Err(yaml_err) => {
            // Try JSON as a fallback before reporting the YAML error
            // — if neither parses, return the YAML diagnostic (it's
            // strictly more permissive so a JSON failure rarely
            // tells a clearer story).
            match serde_json::from_slice::<serde_json::Value>(bytes) {
                Ok(v) => Ok(v),
                Err(_) => Err(ConfigError::ParseError {
                    reason: format!("neither YAML nor JSON: {yaml_err}"),
                }),
            }
        }
    }
}

/// Convert a `serde_yaml::Value` into a `serde_json::Value`. YAML
/// allows non-string map keys; we reject those because the protocol
/// contract is "JSON tree". Consumers either fix their config or
/// pick a provider that normalises elsewhere.
fn yaml_to_json(v: serde_yaml::Value) -> Result<serde_json::Value, ConfigError> {
    serde_json::to_value(&v).map_err(|e| ConfigError::ParseError {
        reason: format!("YAML document is not JSON-compatible: {e}"),
    })
}

fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn now_rfc3339() -> String {
    // Seconds precision is enough for a snapshot's `fetched_at` —
    // the version hash is the authoritative change signal.
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[mcpg_plugin_protocol::async_trait]
impl ConfigProvider for FileConfigProvider {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        vec!["file".to_owned()]
    }

    async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError> {
        let (scheme, rest) =
            parse_config_ref(reference).ok_or_else(|| ConfigError::InvalidReference {
                message: format!("not a valid scheme://path URI: '{reference}'"),
            })?;
        if scheme != "file" {
            return Err(ConfigError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        }
        let path = parse_file_path(rest);
        if path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidReference {
                message: "file:// URI has empty path".into(),
            });
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::NotFound);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(ConfigError::PermissionDenied);
            }
            Err(e) => {
                return Err(ConfigError::Backend {
                    reason: format!("read {}: {e}", path.display()),
                });
            }
        };
        let values = parse_document(&bytes)?;
        Ok(ConfigSnapshot {
            version: digest(&bytes),
            values,
            fetched_at: now_rfc3339(),
            source: reference.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(contents: &[u8], ext: &str) -> (tempfile::TempDir, PathBuf, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("cfg.{ext}"));
        std::fs::write(&path, contents).unwrap();
        let uri = format!("file://{}", path.display());
        (dir, path, uri)
    }

    #[tokio::test]
    async fn snapshot_parses_yaml_document() {
        let (_dir, _path, uri) =
            write_tmp(b"feature_x: true\nrpm_cap: 60\nname: gateway\n", "yaml");
        let p = FileConfigProvider::new();
        let snap = p.snapshot(&uri).await.unwrap();
        assert_eq!(snap.values["feature_x"], true);
        assert_eq!(snap.values["rpm_cap"], 60);
        assert_eq!(snap.values["name"], "gateway");
        assert!(snap.version.starts_with("sha256:"));
        assert_eq!(snap.source, uri);
    }

    #[tokio::test]
    async fn snapshot_parses_json_document() {
        let (_dir, _path, uri) = write_tmp(br#"{"feature_x": true, "rpm_cap": 60}"#, "json");
        let p = FileConfigProvider::new();
        let snap = p.snapshot(&uri).await.unwrap();
        assert_eq!(snap.values["feature_x"], true);
        assert_eq!(snap.values["rpm_cap"], 60);
    }

    #[tokio::test]
    async fn snapshot_version_is_stable_across_reads() {
        let (_dir, _path, uri) = write_tmp(b"k: v\n", "yaml");
        let p = FileConfigProvider::new();
        let a = p.snapshot(&uri).await.unwrap();
        let b = p.snapshot(&uri).await.unwrap();
        assert_eq!(a.version, b.version, "same bytes ⇒ same version");
    }

    #[tokio::test]
    async fn snapshot_version_changes_on_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.yaml");
        std::fs::write(&path, b"k: 1\n").unwrap();
        let uri = format!("file://{}", path.display());
        let p = FileConfigProvider::new();
        let a = p.snapshot(&uri).await.unwrap();
        std::fs::write(&path, b"k: 2\n").unwrap();
        let b = p.snapshot(&uri).await.unwrap();
        assert_ne!(a.version, b.version);
        assert_eq!(a.values["k"], 1);
        assert_eq!(b.values["k"], 2);
    }

    #[tokio::test]
    async fn snapshot_missing_file_returns_not_found() {
        let p = FileConfigProvider::new();
        let err = p
            .snapshot("file:///tmp/mcpg-config-does-not-exist-xyz-123.yaml")
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "not_found");
    }

    #[tokio::test]
    async fn snapshot_malformed_document_is_parse_error() {
        // Syntactically invalid YAML (unterminated flow sequence).
        let (_dir, _path, uri) = write_tmp(b"key: [\n", "yaml");
        let p = FileConfigProvider::new();
        let err = p.snapshot(&uri).await.unwrap_err();
        assert_eq!(err.kind_label(), "parse_error");
    }

    #[tokio::test]
    async fn snapshot_wrong_scheme_errors_cleanly() {
        let p = FileConfigProvider::new();
        let err = p.snapshot("consul://kv/mcpg/config").await.unwrap_err();
        assert_eq!(err.kind_label(), "unsupported_scheme");
    }

    #[tokio::test]
    async fn snapshot_empty_path_is_invalid_reference() {
        let p = FileConfigProvider::new();
        let err = p.snapshot("file://").await.unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
    }

    #[tokio::test]
    async fn watch_is_unsupported() {
        let p = FileConfigProvider::new();
        match p.watch("file:///etc/anything.yaml").await {
            Err(e) => assert_eq!(e.kind_label(), "unsupported_scheme"),
            Ok(_) => panic!("expected watch to be unsupported"),
        }
    }

    #[test]
    fn supported_schemes_contains_file() {
        let p = FileConfigProvider::new();
        assert_eq!(p.supported_schemes(), vec!["file".to_string()]);
    }

    #[test]
    fn descriptor_yaml_parses_as_config_provider() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.config.file");
        assert_eq!(d.class, PluginClass::ConfigProvider);
    }
}
