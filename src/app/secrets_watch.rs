//! Secrets-directory reload trigger — the fourth reload path alongside
//! SIGHUP, `POST /admin/v1/config:reload`, and the config file-watch.
//!
//! A background task polls `gateway.secrets.dir` and triggers
//! [`super::reload_config`] when any file in it changes, so a rotated
//! `${secret.NAME}` value is live within one poll interval without a
//! restart or a config publish. On by default whenever `dir` is set;
//! `gateway.secrets.watch: false` turns it off. Independent of
//! `gateway.config_watch.enabled`.
//!
//! Same design as [`super::config_watch`]: interval-driven SHA-256
//! fingerprinting rather than inotify, because a Kubernetes Secret
//! volume rotates by swapping the `..data` symlink — a polling reader
//! that follows symlinks sees the new bytes whichever way the write
//! landed. A reload failure keeps the previous fingerprint set as the
//! baseline so the next tick retries.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::AppState;

/// Floor for `poll_interval_ms`, matching the config watcher.
const MIN_POLL_INTERVAL_MS: u64 = 1000;

/// Spawn the secrets-watch background task.
///
/// Returns the [`JoinHandle`] so the graceful-shutdown path can abort the
/// watcher; `None` when `gateway.secrets.dir` is unset or `watch` is off.
pub fn spawn(state: AppState) -> Option<JoinHandle<()>> {
    let secrets_cfg = state.config.load().gateway.secrets.clone();

    let dir = secrets_cfg.dir?;
    if !secrets_cfg.watch {
        info!("secrets-watch: disabled (gateway.secrets.watch = false)");
        return None;
    }
    if !dir.is_dir() {
        warn!(
            dir = %dir.display(),
            "secrets-watch: gateway.secrets.dir is not a directory yet; watching for it to appear"
        );
    }

    let interval_ms = secrets_cfg.poll_interval_ms.max(MIN_POLL_INTERVAL_MS);
    let interval = Duration::from_millis(interval_ms);
    info!(
        interval_ms,
        dir = %dir.display(),
        "secrets-watch: spawning polling task"
    );

    Some(tokio::spawn(watch_loop(state, dir, interval)))
}

/// SHA-256 per regular file in `dir`, keyed by file name. Symlinks are
/// followed (a Kubernetes Secret volume is `NAME -> ..data/NAME`); the
/// `..data` / `..<timestamp>` directories and anything unreadable are
/// left out. An unreadable directory fingerprints as empty, so a
/// directory that appears later shows up as a delta.
pub fn fingerprint_dir(dir: &Path) -> BTreeMap<String, [u8; 32]> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !std::fs::metadata(&path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let mut h = Sha256::new();
        h.update(&bytes);
        out.insert(
            entry.file_name().to_string_lossy().into_owned(),
            h.finalize().into(),
        );
    }
    out
}

/// Names of the files whose digest differs between two snapshots — added,
/// removed, or rewritten — sorted. Names only; the audit trail never sees
/// a value.
pub fn diff_keys(
    prev: &BTreeMap<String, [u8; 32]>,
    next: &BTreeMap<String, [u8; 32]>,
) -> Vec<String> {
    prev.keys()
        .chain(next.keys())
        .filter(|k| prev.get(*k) != next.get(*k))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn watch_loop(state: AppState, dir: PathBuf, interval: Duration) {
    let mut last = fingerprint_dir(&dir);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; the baseline is already taken.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let next = fingerprint_dir(&dir);
        let changed = diff_keys(&last, &next);
        if changed.is_empty() {
            continue;
        }
        info!(
            keys_changed = ?changed,
            "secrets-watch: secrets directory changed; triggering reload"
        );
        let started = Instant::now();
        let prev_sha = state.config.load().canonical_sha256();
        let outcome = super::reload_config(&state).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        metrics::counter!("mcpg_config_reloads_total").increment(1);
        metrics::counter!("mcpg_admin_reload_triggers_total", "trigger" => "secrets_watch")
            .increment(1);

        let (success, err_msg) = match &outcome {
            Ok(()) => {
                info!(
                    duration_ms,
                    keys_changed = ?changed,
                    "secrets-watch: reload successful"
                );
                (true, None)
            }
            Err(e) => {
                warn!(
                    error = %format!("{e:#}"),
                    duration_ms,
                    keys_changed = ?changed,
                    "secrets-watch: reload failed; keeping current config and retrying on next poll"
                );
                (false, Some(format!("{e:#}")))
            }
        };

        let next_sha_owned: Option<String> = if success {
            Some(state.config.load().canonical_sha256())
        } else {
            None
        };

        let registry = state.runtime.load().plugin_registry_arc();
        let mut event = mcpg_plugin_host::audit_events::config_reloaded_event(
            "secrets_watch",
            success,
            err_msg.as_deref(),
            Some(prev_sha.as_str()),
            next_sha_owned.as_deref(),
        );
        if let serde_json::Value::Object(ref mut map) = event.details {
            map.insert("keys_changed".into(), serde_json::json!(changed));
            map.insert("duration_ms".into(), serde_json::json!(duration_ms));
        }
        let _ = registry.emit_audit_event(&event).await;

        if success {
            last = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_lists_regular_files_by_name_and_tracks_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("API_TOKEN"), "v1").unwrap();
        std::fs::write(dir.path().join("HOST"), "h").unwrap();
        std::fs::create_dir(dir.path().join("..2026_09_12")).unwrap();

        let fp1 = fingerprint_dir(dir.path());
        assert_eq!(fp1.keys().collect::<Vec<_>>(), ["API_TOKEN", "HOST"]);
        assert_eq!(fingerprint_dir(dir.path()), fp1);
        assert!(diff_keys(&fp1, &fp1).is_empty());

        std::fs::write(dir.path().join("API_TOKEN"), "v2").unwrap();
        let fp2 = fingerprint_dir(dir.path());
        assert_eq!(diff_keys(&fp1, &fp2), ["API_TOKEN"]);
    }

    #[test]
    fn diff_reports_added_and_removed_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("A"), "1").unwrap();
        let fp1 = fingerprint_dir(dir.path());
        std::fs::remove_file(dir.path().join("A")).unwrap();
        std::fs::write(dir.path().join("B"), "2").unwrap();
        let fp2 = fingerprint_dir(dir.path());
        assert_eq!(diff_keys(&fp1, &fp2), ["A", "B"]);
    }

    #[cfg(unix)]
    #[test]
    fn fingerprint_follows_a_kubernetes_style_symlink_swap() {
        let dir = tempfile::tempdir().unwrap();
        let gen1 = dir.path().join("..2026_09_12_01");
        let gen2 = dir.path().join("..2026_09_12_02");
        std::fs::create_dir(&gen1).unwrap();
        std::fs::create_dir(&gen2).unwrap();
        std::fs::write(gen1.join("API_TOKEN"), "v1").unwrap();
        std::fs::write(gen2.join("API_TOKEN"), "v2").unwrap();
        std::os::unix::fs::symlink(&gen1, dir.path().join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/API_TOKEN", dir.path().join("API_TOKEN")).unwrap();

        let fp1 = fingerprint_dir(dir.path());
        assert_eq!(fp1.keys().collect::<Vec<_>>(), ["API_TOKEN"]);

        // The kubelet swaps `..data` atomically: rename a fresh link over it.
        std::os::unix::fs::symlink(&gen2, dir.path().join("..data_tmp")).unwrap();
        std::fs::rename(dir.path().join("..data_tmp"), dir.path().join("..data")).unwrap();
        let fp2 = fingerprint_dir(dir.path());
        assert_eq!(diff_keys(&fp1, &fp2), ["API_TOKEN"]);
    }

    #[test]
    fn missing_dir_fingerprints_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-yet");
        assert!(fingerprint_dir(&missing).is_empty());
        std::fs::create_dir(&missing).unwrap();
        std::fs::write(missing.join("K"), "v").unwrap();
        assert_eq!(
            diff_keys(&BTreeMap::new(), &fingerprint_dir(&missing)),
            ["K"]
        );
    }
}
