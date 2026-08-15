//! File-watch config reload — third reload trigger alongside SIGHUP
//! and `POST /admin/v1/config:reload`.
//!
//! A background task polls the gateway's `MCPG_CONFIG` source set on
//! disk and triggers [`super::reload_config`] when contents change.
//! Default disabled; operators opt in via
//! `gateway.config_watch.enabled: true`.
//!
//! # Design
//!
//! Polling, not `inotify` / `notify`. The codebase deliberately
//! avoids those crates — every other in-process file-watcher (OPA /
//! Cedar / Casbin / workload-identity bundles, see the
//! `mcpg-bundle-reload` library) uses interval-driven SHA-256
//! fingerprinting because it handles editor-write-via-rename
//! (vim/emacs) and
//! K8s ConfigMap atomic-symlink-swap transparently — a polling
//! reader sees the new bytes regardless of how the write landed,
//! whereas inode-watching APIs miss rename-style writes unless
//! re-watched on every event. Fingerprint round-trips are sub-
//! millisecond at the sizes operator configs land at, so even the
//! 1s floor is invisible in I/O profiles.
//!
//! # Concurrency
//!
//! [`super::reload_config`] is not internally serialized — multiple
//! triggers (SIGHUP + admin endpoint + this watcher) could
//! theoretically race. We don't add a mutex: the underlying
//! [`arc_swap::ArcSwap::store`] is atomic and the final state
//! converges on the last-winner config. In practice operators
//! trigger reloads via one path at a time.
//!
//! # Reload-error behaviour
//!
//! On a reload failure (e.g. validation error in the new config) we
//! keep the *old* fingerprint as the baseline so the next poll
//! retries. Operators get back-pressure-style retry instead of a
//! single shot at a bad config — fix the YAML, save again, and the
//! next poll picks it up.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::AppState;

/// Floor for `poll_interval_ms`. Sub-second polling burns disk I/O
/// for no operator-visible benefit — config edits are not a high-
/// frequency event.
const MIN_POLL_INTERVAL_MS: u64 = 1000;

/// Spawn the config-watch background task if enabled.
///
/// Returns the [`JoinHandle`] so a graceful-shutdown path can abort
/// the watcher; returns `None` when the feature is disabled or the
/// gateway has no on-disk config paths to watch (defaults + env-only
/// mode).
pub fn spawn(state: AppState) -> Option<JoinHandle<()>> {
    let cfg = state.config.load();
    let watch_cfg = cfg.gateway.config_watch.clone();
    // Only on-disk FILE layers are watchable; inline (remote/base64) layers
    // are boot snapshots with nothing on disk to poll.
    let paths: Vec<PathBuf> = state
        .config_sources
        .iter()
        .filter_map(|s| match s {
            crate::config::ConfigSource::File(p) => Some(p.clone()),
            crate::config::ConfigSource::Inline { .. } => None,
        })
        .collect();
    drop(cfg);

    if !watch_cfg.enabled {
        info!("config-watch: disabled (gateway.config_watch.enabled = false)");
        return None;
    }
    if paths.is_empty() {
        info!(
            "config-watch: no config files to watch (gateway booted on defaults + env only); not spawning"
        );
        return None;
    }

    let interval_ms = watch_cfg.poll_interval_ms.max(MIN_POLL_INTERVAL_MS);
    let interval = Duration::from_millis(interval_ms);
    info!(
        interval_ms,
        path_count = paths.len(),
        "config-watch: spawning polling task"
    );

    Some(tokio::spawn(watch_loop(state, paths, interval)))
}

/// Per-path SHA-256 fingerprint snapshot. Carrying per-path digests
/// (rather than one digest across all files) lets the audit event
/// list exactly which paths changed between poll ticks — useful when
/// an operator rolls one of several layered config files and wants
/// to see in the audit trail which one they touched.
fn fingerprint_paths(paths: &[PathBuf]) -> Vec<(PathBuf, Option<[u8; 32]>)> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let digest = match std::fs::read(path) {
            Ok(bytes) => {
                let mut h = Sha256::new();
                h.update(&bytes);
                Some(h.finalize().into())
            }
            // Path missing / unreadable mid-flight: record `None` so
            // a delete is visible as a delta to the next poll. We
            // don't fail the watcher — operators may stage-replace a
            // file and the gap window is benign.
            Err(_) => None,
        };
        out.push((path.clone(), digest));
    }
    out
}

fn diff_paths(
    prev: &[(PathBuf, Option<[u8; 32]>)],
    next: &[(PathBuf, Option<[u8; 32]>)],
) -> Vec<String> {
    debug_assert_eq!(prev.len(), next.len());
    let mut changed = Vec::new();
    for ((path_a, digest_a), (path_b, digest_b)) in prev.iter().zip(next.iter()) {
        debug_assert_eq!(path_a, path_b);
        if digest_a != digest_b {
            changed.push(path_b.display().to_string());
        }
    }
    changed
}

async fn watch_loop(state: AppState, paths: Vec<PathBuf>, interval: Duration) {
    let mut last = fingerprint_paths(&paths);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately — drop it; we already snapshotted
    // the baseline above and don't want to reload right after boot.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let next = fingerprint_paths(&paths);
        let changed = diff_paths(&last, &next);
        if changed.is_empty() {
            continue;
        }
        info!(
            paths_changed = ?changed,
            "config-watch: fingerprint delta detected; triggering reload"
        );
        let started = Instant::now();
        let prev_sha = state.config.load().canonical_sha256();
        let outcome = super::reload_config(&state).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        metrics::counter!("mcpg_config_reloads_total").increment(1);
        metrics::counter!("mcpg_admin_reload_triggers_total", "trigger" => "file_watch")
            .increment(1);

        let (success, err_msg) = match &outcome {
            Ok(()) => {
                info!(
                    duration_ms,
                    paths_changed = ?changed,
                    "config-watch: reload successful"
                );
                (true, None)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    duration_ms,
                    paths_changed = ?changed,
                    "config-watch: reload failed; keeping current config and retrying on next poll"
                );
                (false, Some(e.to_string()))
            }
        };

        let next_sha_owned: Option<String> = if success {
            Some(state.config.load().canonical_sha256())
        } else {
            None
        };

        let registry = state.runtime.load().plugin_registry_arc();
        let mut event = mcpg_plugin_host::audit_events::config_reloaded_event(
            "file_watch",
            success,
            err_msg.as_deref(),
            Some(prev_sha.as_str()),
            next_sha_owned.as_deref(),
        );
        // Augment the standard event with the per-path delta so the
        // audit trail shows exactly which files the watcher saw
        // change. Mirrors the SIGHUP / admin path's event shape but
        // adds `paths_changed` + `duration_ms` because file-watch
        // is the only trigger that can attribute the change to
        // specific files.
        if let serde_json::Value::Object(ref mut map) = event.details {
            map.insert("paths_changed".into(), serde_json::json!(changed));
            map.insert("duration_ms".into(), serde_json::json!(duration_ms));
        }
        let _ = registry.emit_audit_event(&event).await;

        if success {
            // Adopt the new fingerprint as the baseline. On failure
            // we deliberately keep `last` unchanged so the next poll
            // sees the same delta and retries.
            last = next;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn fingerprint_round_trip_detects_content_change() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            &dir,
            "mcpg.yaml",
            "gateway:\n  server:\n    bind_address: \"127.0.0.1:9090\"\n",
        );
        let paths = vec![path.clone()];

        let fp1 = fingerprint_paths(&paths);
        // Bytes-identical re-read produces an identical fingerprint.
        let fp1b = fingerprint_paths(&paths);
        assert_eq!(fp1, fp1b);
        assert!(diff_paths(&fp1, &fp1b).is_empty());

        // Mutate the file → fingerprint changes + diff carries the path.
        let _ = write_file(
            &dir,
            "mcpg.yaml",
            "gateway:\n  server:\n    bind_address: \"127.0.0.1:9091\"\n",
        );
        let fp2 = fingerprint_paths(&paths);
        assert_ne!(fp1, fp2);
        let changed = diff_paths(&fp1, &fp2);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], path.display().to_string());
    }

    #[test]
    fn fingerprint_handles_missing_path_as_none_digest() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.yaml");
        let fp = fingerprint_paths(std::slice::from_ref(&missing));
        assert_eq!(fp.len(), 1);
        assert!(fp[0].1.is_none());

        // Creating the file changes the digest from None → Some.
        let _ = write_file(&dir, "does-not-exist.yaml", "gateway: {}\n");
        let fp2 = fingerprint_paths(std::slice::from_ref(&missing));
        assert!(fp2[0].1.is_some());
        assert_eq!(diff_paths(&fp, &fp2).len(), 1);
    }

    #[test]
    fn diff_paths_lists_only_changed_files() {
        let dir = TempDir::new().unwrap();
        let a = write_file(&dir, "a.yaml", "v1");
        let b = write_file(&dir, "b.yaml", "v1");
        let paths = vec![a.clone(), b.clone()];

        let fp1 = fingerprint_paths(&paths);
        // Mutate only `b`.
        std::fs::write(&b, b"v2").unwrap();
        let fp2 = fingerprint_paths(&paths);

        let changed = diff_paths(&fp1, &fp2);
        assert_eq!(changed, vec![b.display().to_string()]);
    }
}
