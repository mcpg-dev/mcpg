//! `gateway.secrets:` — the directory behind `${secret.NAME}`.
//!
//! A secret is one file per key: `${secret.API_TOKEN}` reads
//! `<dir>/API_TOKEN` verbatim (no trimming) at config load, in the same
//! pass as `${env.X}`. On Kubernetes the directory is a mounted Secret
//! volume, whose entries are symlinks into `..data/`; the reader follows
//! them. Self-hosted gateways point `dir` at a plain directory.
//!
//! [`SecretsSource`] is the reader the config resolver threads through
//! every string leaf it walks. It remembers which keys the config
//! referenced so the boot / reload path can publish
//! [`SecretsSource::digest`] — the value the control plane compares
//! against its own record to tell whether a rotation has landed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Longest NAME `${secret.NAME}` accepts.
pub const SECRET_NAME_MAX_LEN: usize = 64;

/// The grammar a secret name must match, as operators read it in errors.
pub const SECRET_NAME_GRAMMAR: &str = "^[A-Za-z_][A-Za-z0-9_]{0,63}$";

/// `gateway.secrets:` — directory-backed `${secret.NAME}` values, hot-reloaded
/// on change. Every `${secret.NAME}` in the config resolves to the exact
/// bytes of `<dir>/<NAME>` at config load. With `dir` unset, any
/// `${secret.*}` reference is a config error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Directory holding one file per secret; `${secret.NAME}` reads
    /// `<dir>/<NAME>` (symlinks followed, so a mounted Kubernetes Secret
    /// volume works as-is). NAME must match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.
    /// Unset: the config may not reference any `${secret.*}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,

    /// Poll `dir` and hot-reload the gateway when any file in it changes
    /// (added, removed, or rewritten). The reload re-resolves every
    /// `${secret.*}` reference, so a rotated value is live within one
    /// poll interval — no restart, no config publish. Only meaningful when
    /// `dir` is set.
    #[serde(default = "super::default_true")]
    pub watch: bool,

    /// Poll interval in milliseconds for `watch`. Values below 1000 are
    /// clamped to 1000 at spawn time (a warning is logged at validate
    /// time) — sub-second polling burns I/O for no operator-visible
    /// benefit.
    #[serde(default = "default_secrets_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            dir: None,
            watch: true,
            poll_interval_ms: default_secrets_poll_interval_ms(),
        }
    }
}

fn default_secrets_poll_interval_ms() -> u64 {
    5000
}

/// Whether `name` is a valid secret name (`^[A-Za-z_][A-Za-z0-9_]{0,63}$`).
/// The grammar doubles as a file-name check: a name can never carry a path
/// separator or a `..` component.
pub fn is_secret_name(name: &str) -> bool {
    let mut chars = name.chars();
    let leads = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
    leads
        && name.len() <= SECRET_NAME_MAX_LEN
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Reader for `${secret.NAME}` values, threaded through the config-load
/// resolver. Records every key it served, so one resolution pass sees one
/// snapshot per key; [`Self::digest`] describes the whole directory.
pub struct SecretsSource {
    dir: Option<PathBuf>,
    referenced: Mutex<BTreeMap<String, String>>,
}

impl SecretsSource {
    /// A source over `cfg.dir`; with `dir` unset every lookup is an error
    /// that says the block is missing.
    pub fn from_config(cfg: &SecretsConfig) -> Self {
        Self {
            dir: cfg.dir.clone(),
            referenced: Mutex::new(BTreeMap::new()),
        }
    }

    /// A source with no directory: `${secret.*}` references are refused.
    pub fn unconfigured() -> Self {
        Self::from_config(&SecretsConfig::default())
    }

    /// The exact bytes of `<dir>/<name>` as UTF-8. Errors name the key,
    /// never a value. A key already served during this resolution pass
    /// returns the same value again, so one config sees one consistent
    /// snapshot even while the directory is being rotated underneath it.
    pub fn lookup(&self, name: &str) -> Result<String> {
        if !is_secret_name(name) {
            anyhow::bail!("`${{secret.{name}}}`: secret names must match {SECRET_NAME_GRAMMAR}");
        }
        let Some(dir) = self.dir.as_ref() else {
            anyhow::bail!(
                "`${{secret.{name}}}` is referenced but gateway.secrets.dir is not set; \
                 mount the secrets directory and set gateway.secrets.dir"
            );
        };
        if let Some(value) = self.referenced.lock().expect("secrets lock").get(name) {
            return Ok(value.clone());
        }
        let path = dir.join(name);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "`${{secret.{name}}}`: cannot read {} (gateway.secrets.dir = {})",
                path.display(),
                dir.display()
            )
        })?;
        let value = String::from_utf8(bytes).map_err(|_| {
            anyhow::anyhow!(
                "`${{secret.{name}}}`: {} is not valid UTF-8",
                path.display()
            )
        })?;
        self.referenced
            .lock()
            .expect("secrets lock")
            .insert(name.to_owned(), value.clone());
        Ok(value)
    }

    /// Names of the keys served so far, sorted.
    pub fn referenced_keys(&self) -> Vec<String> {
        self.referenced
            .lock()
            .expect("secrets lock")
            .keys()
            .cloned()
            .collect()
    }

    /// Hex SHA-256 over `NAME=VALUE\n` for every file in the directory, in
    /// sorted order — the same recipe the control plane applies to the set
    /// it registered, so equal digests mean the delivered set is the
    /// registered set. The whole directory, not only the keys the config
    /// referenced: a registered key the config does not use is still
    /// delivered, and a digest over references alone would report it as
    /// pending forever. Read once, when the runtime is built, so the value
    /// describes what this runtime loaded; a later change to the files is a
    /// difference until the reload that picks it up succeeds. Empty when no
    /// directory is configured or it holds no readable regular file.
    pub fn digest(&self) -> String {
        let Some(dir) = self.dir.as_ref() else {
            return String::new();
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return String::new();
        };
        // Follow symlinks: a Kubernetes Secret volume is `..data/` links,
        // and the `..data` / `..YYYY` bookkeeping entries are directories
        // or dot-prefixed names outside the key grammar.
        let mut files: Vec<(String, Vec<u8>)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                if !is_secret_name(&name) {
                    return None;
                }
                let path = e.path();
                if !std::fs::metadata(&path).ok()?.is_file() {
                    return None;
                }
                Some((name, std::fs::read(&path).ok()?))
            })
            .collect();
        if files.is_empty() {
            return String::new();
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut h = Sha256::new();
        for (name, value) in &files {
            h.update(name.as_bytes());
            h.update(b"=");
            h.update(value);
            h.update(b"\n");
        }
        format!("{:x}", h.finalize())
    }
}

/// The first `${secret.NAME}` token in any string leaf of `value`, so
/// validation can name the offending reference when `dir` is unset.
pub(crate) fn first_secret_ref(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            let start = s.find("${secret.")?;
            let end = s[start..].find('}')?;
            Some(s[start..=start + end].to_owned())
        }
        serde_json::Value::Array(items) => items.iter().find_map(first_secret_ref),
        serde_json::Value::Object(map) => map.values().find_map(first_secret_ref),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_over(dir: &std::path::Path) -> SecretsSource {
        SecretsSource::from_config(&SecretsConfig {
            dir: Some(dir.to_path_buf()),
            ..SecretsConfig::default()
        })
    }

    #[test]
    fn defaults_watch_on_at_five_seconds_without_a_dir() {
        let cfg = SecretsConfig::default();
        assert!(cfg.dir.is_none());
        assert!(cfg.watch);
        assert_eq!(cfg.poll_interval_ms, 5000);
        let parsed: SecretsConfig = serde_yaml::from_str("dir: /var/run/mcpg/secrets\n").unwrap();
        assert_eq!(
            parsed.dir.as_deref(),
            Some(std::path::Path::new("/var/run/mcpg/secrets"))
        );
        assert!(parsed.watch);
        assert_eq!(parsed.poll_interval_ms, 5000);
    }

    #[test]
    fn grammar_accepts_identifiers_and_refuses_paths() {
        for ok in ["A", "_", "API_TOKEN", "a1", "_x9", &"A".repeat(64)] {
            assert!(is_secret_name(ok), "{ok}");
        }
        for bad in [
            "",
            "1A",
            "A-B",
            "a.b",
            "../etc",
            "a/b",
            "A B",
            "café",
            &"A".repeat(65),
        ] {
            assert!(!is_secret_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn lookup_reads_exact_bytes_without_trimming() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("API_TOKEN"), "tok-123\n").unwrap();
        let src = source_over(dir.path());
        assert_eq!(src.lookup("API_TOKEN").unwrap(), "tok-123\n");
        assert_eq!(src.referenced_keys(), ["API_TOKEN"]);
    }

    #[cfg(unix)]
    #[test]
    fn lookup_follows_symlinks_like_a_kubernetes_secret_volume() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("..2026_09_12");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("API_TOKEN"), "linked").unwrap();
        std::os::unix::fs::symlink(&data, dir.path().join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/API_TOKEN", dir.path().join("API_TOKEN")).unwrap();
        let src = source_over(dir.path());
        assert_eq!(src.lookup("API_TOKEN").unwrap(), "linked");
    }

    #[test]
    fn lookup_errors_name_the_key_never_the_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PRESENT"), "s3cret-value").unwrap();
        std::fs::write(dir.path().join("BINARY"), [0xff, 0xfe, 0x00]).unwrap();
        let src = source_over(dir.path());
        src.lookup("PRESENT").unwrap();

        let missing = format!("{:#}", src.lookup("MISSING").unwrap_err());
        assert!(missing.contains("${secret.MISSING}"), "{missing}");
        assert!(!missing.contains("s3cret-value"), "{missing}");

        let binary = format!("{:#}", src.lookup("BINARY").unwrap_err());
        assert!(binary.contains("${secret.BINARY}"), "{binary}");
        assert!(binary.contains("UTF-8"), "{binary}");

        let bad_name = format!("{:#}", src.lookup("../PRESENT").unwrap_err());
        assert!(bad_name.contains(SECRET_NAME_GRAMMAR), "{bad_name}");
        assert!(!bad_name.contains("s3cret-value"), "{bad_name}");
    }

    #[test]
    fn lookup_without_a_dir_says_the_block_is_missing() {
        let src = SecretsSource::unconfigured();
        let err = format!("{:#}", src.lookup("API_TOKEN").unwrap_err());
        assert!(err.contains("${secret.API_TOKEN}"), "{err}");
        assert!(err.contains("gateway.secrets.dir"), "{err}");
    }

    #[test]
    fn lookup_of_a_missing_dir_names_the_key() {
        let src = SecretsSource::from_config(&SecretsConfig {
            dir: Some(PathBuf::from("/nonexistent/mcpg-secrets")),
            ..SecretsConfig::default()
        });
        let err = format!("{:#}", src.lookup("API_TOKEN").unwrap_err());
        assert!(err.contains("${secret.API_TOKEN}"), "{err}");
        assert!(err.contains("/nonexistent/mcpg-secrets"), "{err}");
    }

    /// The digest describes the whole delivered set, referenced or not,
    /// and ignores what is not a key: the `..data` bookkeeping of a Secret
    /// volume, a subdirectory, a name outside the grammar.
    #[test]
    fn digest_covers_every_key_in_the_directory_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("B"), "2").unwrap();
        std::fs::write(dir.path().join("A"), "1").unwrap();
        std::fs::write(dir.path().join("UNUSED"), "x").unwrap();
        std::fs::write(dir.path().join("..data"), "bookkeeping").unwrap();
        std::fs::write(dir.path().join("not-a-key"), "dash").unwrap();
        std::fs::create_dir(dir.path().join("SUBDIR")).unwrap();
        let src = source_over(dir.path());
        let expected = format!("{:x}", Sha256::digest(b"A=1\nB=2\nUNUSED=x\n"));
        assert_eq!(src.digest(), expected, "unreferenced keys count too");

        src.lookup("B").unwrap();
        src.lookup("A").unwrap();
        assert_eq!(
            src.digest(),
            expected,
            "referencing a key does not change it"
        );
        assert_eq!(src.referenced_keys(), ["A", "B"]);

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(source_over(empty.path()).digest(), "");
        assert_eq!(SecretsSource::unconfigured().digest(), "");
    }

    #[test]
    fn lookup_serves_one_snapshot_per_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("K"), "v1").unwrap();
        let src = source_over(dir.path());
        assert_eq!(src.lookup("K").unwrap(), "v1");
        std::fs::write(dir.path().join("K"), "v2").unwrap();
        assert_eq!(src.lookup("K").unwrap(), "v1");
        assert_eq!(
            source_over(dir.path()).lookup("K").unwrap(),
            "v2",
            "a fresh source (next boot / reload) sees the new value"
        );
    }

    #[test]
    fn first_secret_ref_extracts_the_token_from_nested_leaves() {
        let cfg = serde_json::json!({
            "plain": "${env.X}",
            "nested": { "list": ["a", "Bearer ${secret.API_TOKEN} x"] },
        });
        assert_eq!(
            first_secret_ref(&cfg).as_deref(),
            Some("${secret.API_TOKEN}")
        );
        assert_eq!(
            first_secret_ref(&serde_json::json!({"k": "${env.X}"})),
            None
        );
    }
}
