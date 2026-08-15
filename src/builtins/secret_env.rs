//! Built-in `secret_provider` plugin — `dev.mcpg.builtin.secret.env`.
//!
//! Resolves `env://VAR_NAME` references against the gateway's
//! process environment. Watch is unsupported (env vars don't
//! rotate without a restart); consumers that need rotation
//! bind their critical secrets to a provider that does.
//!
//! # Security
//!
//! The built-in resolves env vars at boot + on every `get`. The
//! host's `secrets_read` capability on the `env` scheme gates what
//! the gateway process can see; this plugin inherits that
//! restriction automatically (it calls `std::env::var`).

use std::sync::Arc;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    secret::{SecretError, SecretProvider, SecretValue, parse_secret_ref},
};

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.secret.env
name: Built-in Env Secret Provider
description: |
  Gateway-bundled secret provider: resolves env://VAR_NAME URIs
  against the process environment. Watch is unsupported
  (environment vars don't rotate without a gateway restart).
  Always auto-bound to the `env` scheme unless the operator
  overrides via plugins.secrets.env.
class: secret_provider
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

pub struct EnvSecretProvider {
    manifest: PluginManifest,
    /// Snapshot of the process environment captured at construction
    /// (gateway boot — before plugin load and before any opt-in
    /// post-boot env scrub). Resolution reads this snapshot, NOT live
    /// `std::env::var`, so `env://` references keep resolving even after
    /// `server.scrub_process_env_after_boot` removes the vars from the
    /// live process environment. Behaviour is unchanged when no scrub
    /// runs: the snapshot equals the live env at boot, and env vars are
    /// not expected to mutate at runtime.
    snapshot: std::collections::HashMap<String, String>,
}

impl EnvSecretProvider {
    pub fn new() -> Arc<Self> {
        // `vars_os` (not `vars`) so a single non-UTF-8 var anywhere in
        // the environment cannot panic the gateway at boot; non-UTF-8
        // entries are dropped (they resolve to NotFound).
        let snapshot = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        Arc::new(Self {
            snapshot,
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.secret.env".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in Env Secret Provider".into(),
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

#[mcpg_plugin_protocol::async_trait]
impl SecretProvider for EnvSecretProvider {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        vec!["env".to_owned()]
    }

    async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        let (scheme, rest) =
            parse_secret_ref(secret_ref).ok_or_else(|| SecretError::InvalidReference {
                message: format!("not a valid scheme://path URI: '{secret_ref}'"),
            })?;
        if scheme != "env" {
            return Err(SecretError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        }
        // Var name is everything up to `#` — anchor (`#field`) is
        // ignored since env values are flat strings. An empty var
        // name is a config bug.
        let var_name = rest.split('#').next().unwrap_or(rest);
        if var_name.is_empty() {
            return Err(SecretError::InvalidReference {
                message: "env:// URI has empty variable name".into(),
            });
        }
        // Read the boot snapshot, never live `std::env::var`, so resolution
        // survives the opt-in post-boot scrub. Non-UTF-8 vars were dropped at
        // snapshot time and resolve to NotFound (as they effectively did
        // before via the UTF-8-only contract).
        match self.snapshot.get(var_name) {
            Some(v) => Ok(SecretValue::new(v.clone().into_bytes())),
            None => Err(SecretError::NotFound),
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
    async fn get_returns_value_for_present_var() {
        // Use a deterministically-named var so parallel tests
        // don't stomp. SAFETY: single-threaded within this test.
        let key = "MCPGTEST_ENV_PRESENT";
        unsafe {
            std::env::set_var(key, "hunter2");
        }
        let p = EnvSecretProvider::new();
        let v = p.get(&format!("env://{key}")).await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"hunter2");
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn snapshot_survives_post_boot_scrub() {
        // The provider snapshots env at construction (boot). After a scrub
        // removes the var from the live process env, resolution must still
        // succeed from the snapshot — this is what lets the opt-in
        // `server.scrub_process_env_after_boot` blind plugins' direct
        // `std::env::var` reads without breaking the host's own env://
        // resolver.
        let key = "MCPGTEST_ENV_SCRUB_SURVIVES";
        unsafe {
            std::env::set_var(key, "boot-value");
        }
        let p = EnvSecretProvider::new();
        unsafe {
            std::env::remove_var(key); // simulate the post-boot scrub
        }
        assert!(std::env::var(key).is_err(), "var is gone from live env");
        let v = p.get(&format!("env://{key}")).await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"boot-value");
    }

    #[tokio::test]
    async fn get_missing_var_returns_not_found() {
        let p = EnvSecretProvider::new();
        let err = p
            .get("env://MCPG_TEST_DEFINITELY_NOT_SET")
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "not_found");
    }

    #[tokio::test]
    async fn get_with_wrong_scheme_errors_cleanly() {
        let p = EnvSecretProvider::new();
        let err = p.get("vault://secret/data/db").await.unwrap_err();
        assert_eq!(err.kind_label(), "unsupported_scheme");
    }

    #[tokio::test]
    async fn get_empty_var_name_is_invalid_reference() {
        let p = EnvSecretProvider::new();
        let err = p.get("env://").await.unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
    }

    #[tokio::test]
    async fn get_ignores_anchor_on_env_scheme() {
        let key = "MCPG_TEST_ANCHOR_IGNORED";
        unsafe {
            std::env::set_var(key, "v");
        }
        let p = EnvSecretProvider::new();
        // env:// URIs have no meaningful anchor; a value after
        // `#` is silently ignored.
        let v = p.get(&format!("env://{key}#ignored-anchor")).await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"v");
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn watch_is_unsupported() {
        let p = EnvSecretProvider::new();
        // `BoxSecretRotationStream` doesn't impl Debug, so
        // `unwrap_err` isn't usable — pattern-match instead.
        match p.watch("env://ANYTHING").await {
            Err(e) => assert_eq!(e.kind_label(), "unsupported_scheme"),
            Ok(_) => panic!("expected watch to be unsupported"),
        }
    }

    #[test]
    fn supported_schemes_contains_env() {
        let p = EnvSecretProvider::new();
        assert_eq!(p.supported_schemes(), vec!["env".to_string()]);
    }

    #[test]
    fn descriptor_yaml_parses_as_secret_provider() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.secret.env");
        assert_eq!(d.class, PluginClass::SecretProvider);
    }
}
