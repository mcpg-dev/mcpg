//! Built-in `secret_provider` plugin — `dev.mcpg.builtin.secret.file`.
//!
//! Resolves `file:///absolute/path` references by reading bytes
//! from the local filesystem. Watch is unsupported — filesystem-
//! watch semantics across OSes (inotify / kqueue / ReadDirectory
//! ChangesW) are subtle enough to deserve their own plugin. For
//! rotation use a proper backend (Vault / AWS-SM).
//!
//! # Security
//!
//! Every `get` calls `std::fs::read` on the path verbatim. The
//! host's `filesystem_read` capability gates what paths
//! the gateway process can see at the OS level — the plugin wraps
//! this surface so plugin consumers referencing `file://` don't
//! need to declare the capability themselves. `..` traversal is
//! NOT filtered; operator configs are trusted input.

use std::path::PathBuf;
use std::sync::Arc;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    secret::{SecretError, SecretProvider, SecretValue, parse_secret_ref},
};

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.secret.file
name: Built-in File Secret Provider
description: |
  Gateway-bundled secret provider: resolves file:///path URIs
  against the local filesystem. Watch is unsupported (OS-specific
  filesystem-watch semantics belong in a dedicated plugin).
  Always auto-bound to the `file` scheme unless the operator
  overrides via plugins.secrets.file.
class: secret_provider
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

pub struct FileSecretProvider {
    manifest: PluginManifest,
}

impl FileSecretProvider {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.secret.file".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in File Secret Provider".into(),
                plugin_class: PluginClass::SecretProvider,
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

/// Parse `file://...` into the local-filesystem path. Accepts
/// both the conventional `file:///absolute/path` form (three
/// slashes, leading slash implied) and the host-elided
/// `file://path` form. Anchor (`#...`) is stripped before
/// returning.
fn parse_file_path(rest: &str) -> PathBuf {
    let no_anchor = rest.split('#').next().unwrap_or(rest);
    // `file:///etc/foo` → rest is `/etc/foo` after the `://` split.
    // `file://./relative` → rest is `./relative`. Keep both.
    PathBuf::from(no_anchor)
}

#[mcpg_plugin_protocol::async_trait]
impl SecretProvider for FileSecretProvider {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        vec!["file".to_owned()]
    }

    async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        let (scheme, rest) =
            parse_secret_ref(secret_ref).ok_or_else(|| SecretError::InvalidReference {
                message: format!("not a valid scheme://path URI: '{secret_ref}'"),
            })?;
        if scheme != "file" {
            return Err(SecretError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        }
        let path = parse_file_path(rest);
        if path.as_os_str().is_empty() {
            return Err(SecretError::InvalidReference {
                message: "file:// URI has empty path".into(),
            });
        }
        match std::fs::read(&path) {
            Ok(bytes) => Ok(SecretValue::new(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SecretError::NotFound),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(SecretError::PermissionDenied)
            }
            Err(e) => Err(SecretError::Backend {
                reason: format!("read {}: {e}", path.display()),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_returns_bytes_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"hunter2").unwrap();
        let uri = format!("file://{}", path.display());

        let p = FileSecretProvider::new();
        let v = p.get(&uri).await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"hunter2");
    }

    #[tokio::test]
    async fn get_missing_file_returns_not_found() {
        let p = FileSecretProvider::new();
        let err = p
            .get("file:///tmp/mcpg-this-path-should-not-exist-xyz-123")
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "not_found");
    }

    #[tokio::test]
    async fn get_ignores_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"v").unwrap();
        let uri = format!("file://{}#ignored", path.display());
        let p = FileSecretProvider::new();
        let v = p.get(&uri).await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"v");
    }

    #[tokio::test]
    async fn get_with_wrong_scheme_errors_cleanly() {
        let p = FileSecretProvider::new();
        let err = p.get("vault://secret/data/db").await.unwrap_err();
        assert_eq!(err.kind_label(), "unsupported_scheme");
    }

    #[tokio::test]
    async fn get_empty_path_is_invalid_reference() {
        let p = FileSecretProvider::new();
        let err = p.get("file://").await.unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
    }

    #[tokio::test]
    async fn watch_is_unsupported() {
        let p = FileSecretProvider::new();
        match p.watch("file:///etc/anything").await {
            Err(e) => assert_eq!(e.kind_label(), "unsupported_scheme"),
            Ok(_) => panic!("expected watch to be unsupported"),
        }
    }

    #[test]
    fn supported_schemes_contains_file() {
        let p = FileSecretProvider::new();
        assert_eq!(p.supported_schemes(), vec!["file".to_string()]);
    }

    #[test]
    fn descriptor_yaml_parses_as_secret_provider() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.secret.file");
        assert_eq!(d.class, PluginClass::SecretProvider);
    }
}
