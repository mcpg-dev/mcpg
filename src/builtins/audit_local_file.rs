//! Built-in `audit_sink` plugin — `dev.mcpg.builtin.audit.local-file`.
//!
//! The gateway's bundled `audit_sink`. Writes each event as one JSON
//! line to a configured file, makes it durable before returning the
//! receipt, and maintains a SHA-256 hash chain (`prev_event_hash`
//! field on each emitted event).
//!
//! # Durability contract
//!
//! `emit` MUST not return `Ok` until the event is durably on disk
//! (spec §9.12 "synchronous-ack"). This impl achieves that by:
//!
//! 1. Serialising the event to canonical JSON.
//! 2. Computing its SHA-256 (the `durable_hash` the receipt
//!    advertises).
//! 3. Writing the line + a newline via `write_all`.
//! 4. Calling `sync_all` on the file handle to force the write
//!    past the kernel's page cache.
//! 5. Only then advancing the internal `last_hash` and returning
//!    `Ok`.
//!
//! Step 4 (`fsync`) is the expensive part. Doing it per event under
//! a held lock serialises every emit behind a full disk sync — fatal
//! when a tool-gate is loaded, since each tool call emits two audit
//! events (`tool.call.allowed` + `.completed`) and so pays two
//! serialised fsyncs (~5 ms each ⇒ a hard ~100 req/s ceiling).
//!
//! # Concurrency — group commit
//!
//! A single background writer task owns the file handle + hash chain.
//! `emit` serialises the event, hands it to the writer over a channel,
//! and awaits a durability reply. The writer drains **all** currently
//! queued events into one batch, appends their lines in receive order
//! (so the SHA-256 chain stays deterministic), then issues **one**
//! `sync_all` for the whole batch and replies to every waiter. Under
//! load the fsync count drops from per-event to per-batch, so emit
//! throughput scales with batch size instead of fsync latency — while
//! each caller still blocks until *its* event is durably on disk.
//! A serial hash chain is preserved because exactly one task writes.
//!
//! # Rotation
//!
//! The sink never rotates the file itself; operators rotate it
//! externally (`logrotate` or equivalent). Its default strategy renames
//! the live file and creates a fresh one, which leaves an append-only
//! handle bound to the renamed inode — and once that file is compressed
//! away, to an unlinked one. Every write would keep succeeding while
//! the records went nowhere, so the writer compares the open handle's
//! file identity against whatever the path resolves to at each **batch**
//! boundary and reopens append-only when they diverge. The cost is one
//! `stat` per batch, not per event. A path rotated away but not yet
//! recreated is recreated by that reopen, so no batch is lost.
//!
//! The identity comparison is Unix-only — Windows exposes the
//! equivalent (`volume_serial_number` / `file_index`) only behind the
//! unstable `windows_by_handle` feature. Off Unix the writer still
//! recreates a path that has vanished, but a path swapped underneath it
//! goes unnoticed; rotation there belongs to the log collector.
//!
//! The hash chain belongs to the writer, not to any one file: it
//! continues across a rotation, so a rotated file begins mid-chain.
//! Verify the concatenation of the rotated files in write order rather
//! than each file in isolation — only the very first file starts at
//! genesis (`prev_event_hash: null`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OnceCell, mpsc, oneshot};

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    audit::{AuditError, AuditEvent, AuditReceipt, AuditSink},
};

/// Plugin id — operators opt this sink into the audit fan-out by
/// listing it under `audit.sinks[].kind`.
pub const PLUGIN_ID: &str = "dev.mcpg.builtin.audit.local-file";

/// Descriptor shipped alongside the code. `FirstPartyRegistrar`
/// parses this at registration time + cross-checks against the
/// in-code manifest.
pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.audit.local-file
name: Built-in Audit Local File Sink
description: |
  Gateway-bundled audit sink: appends each event as one JSON line to
  a configured file path, fsyncs after every write, and chains events
  with SHA-256 hashes per spec §9.12. Single-node durability.
  Production deployments SHOULD also register an off-node sink
  (AWS CloudTrail, Datadog Audit Logs, object-storage archival).
class: audit_sink
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// A unit of work for the background writer task.
enum Cmd {
    /// Append + chain an event, then durably sync it (in a batch) and
    /// reply with the receipt.
    Write {
        event: AuditEvent,
        reply: oneshot::Sender<Result<AuditReceipt, AuditError>>,
    },
    /// Force a durable sync of everything written so far.
    Flush {
        reply: oneshot::Sender<Result<(), AuditError>>,
    },
}

/// Built-in local-file audit sink. Emits are funnelled to a single
/// background writer that group-commits batches (one fsync per batch);
/// see the module docs.
pub struct LocalFileAuditSink {
    manifest: PluginManifest,
    path: PathBuf,
    /// Holds the opened file until the writer task is lazily spawned on
    /// first emit (spawning needs a runtime, which `open` — a sync fn —
    /// may not have; the first `emit` always does). Taken exactly once.
    pending_file: std::sync::Mutex<Option<File>>,
    /// Channel to the writer task, created on first emit.
    writer: OnceCell<mpsc::UnboundedSender<Cmd>>,
}

impl LocalFileAuditSink {
    /// Open or create the audit file at `path` and return a sink
    /// ready for registration. Fails if the file cannot be opened
    /// append-only. Sync I/O — callable from either async or sync
    /// contexts (the gateway's `build_plugin_registry` is
    /// intentionally sync so it runs under either the multi-thread
    /// or single-thread tokio runtime).
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Arc<Self>> {
        let path = path.into();
        let std_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening audit log file {}", path.display()))?;
        let file = File::from_std(std_file);
        Ok(Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.audit.local-file".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in Audit Local File Sink".into(),
                plugin_class: PluginClass::AuditSink,
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
            pending_file: std::sync::Mutex::new(Some(file)),
            writer: OnceCell::new(),
            path,
        }))
    }

    /// Absolute path this sink writes to. Exposed for logging.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lazily start the background writer task and return its sender.
    /// The first caller hands the opened file to the writer; subsequent
    /// callers reuse the cached sender.
    async fn sender(&self) -> Result<&mpsc::UnboundedSender<Cmd>, AuditError> {
        self.writer
            .get_or_try_init(|| async {
                let file = self.pending_file.lock().unwrap().take().ok_or_else(|| {
                    AuditError::WriteFailed {
                        reason: "audit writer file already consumed".into(),
                    }
                })?;
                let (tx, rx) = mpsc::unbounded_channel();
                tokio::spawn(writer_loop(
                    file,
                    self.path.clone(),
                    rx,
                    self.manifest.id.clone(),
                ));
                Ok(tx)
            })
            .await
    }
}

/// Identity the OS assigns a file independently of its path: device +
/// inode. Comparing the open handle's identity against the one the path
/// resolves to is what makes an external rotation observable.
type FileId = (u64, u64);

/// Whether the platform exposes a comparable file identity at all.
/// Where it does not, the writer still recreates a path that has
/// vanished, but cannot see one that was swapped underneath it.
const FILE_ID_SUPPORTED: bool = cfg!(unix);

#[cfg(unix)]
fn metadata_id(meta: &std::fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

/// Windows exposes the equivalent pair only through the unstable
/// `windows_by_handle` feature (`volume_serial_number` / `file_index`),
/// so there is no identity to compare on stable. Rotation there is a
/// log-collector concern rather than a `logrotate` one.
#[cfg(not(unix))]
fn metadata_id(_meta: &std::fs::Metadata) -> Option<FileId> {
    None
}

/// Identity of an open handle. `None` when the platform exposes none,
/// or when the `fstat` itself fails — the caller re-derives it on the
/// next batch rather than treating the absence as permanent.
async fn open_file_id(file: &File) -> Option<FileId> {
    metadata_id(&file.metadata().await.ok()?)
}

/// Rebind `file` to whatever `path` resolves to now, when the two have
/// diverged because the path was rotated out from under the handle.
///
/// Called once per batch (see the module docs). `open_id` caches the
/// handle's identity so the steady state costs a single `stat` of
/// `path`. A path that no longer exists is recreated, so the batch that
/// triggered the check still lands on disk.
async fn follow_rotation(
    file: &mut File,
    open_id: &mut Option<FileId>,
    path: &Path,
) -> std::io::Result<()> {
    if FILE_ID_SUPPORTED && open_id.is_none() {
        *open_id = open_file_id(file).await;
    }
    let reopen = match tokio::fs::metadata(path).await {
        Ok(on_disk) => match (*open_id, metadata_id(&on_disk)) {
            (Some(open), Some(current)) => open != current,
            // No comparable identity: keep the handle rather than
            // reopen on every batch.
            _ => false,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(e),
    };
    if !reopen {
        return Ok(());
    }

    let reopened = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    *open_id = open_file_id(&reopened).await;
    *file = reopened;
    Ok(())
}

/// Fail every waiter in `batch` with the same `WriteFailed` error the
/// fsync path reports. Used when the batch cannot be written at all, so
/// the hash chain is left exactly where it was.
fn fail_batch(batch: Vec<Cmd>, reason: &str) {
    for cmd in batch {
        match cmd {
            Cmd::Write { reply, .. } => {
                let _ = reply.send(Err(AuditError::WriteFailed {
                    reason: reason.to_owned(),
                }));
            }
            Cmd::Flush { reply } => {
                let _ = reply.send(Err(AuditError::WriteFailed {
                    reason: reason.to_owned(),
                }));
            }
        }
    }
}

/// Background writer: owns the file + hash chain, group-commits batches.
async fn writer_loop(
    mut file: File,
    path: PathBuf,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    sink_id: String,
) {
    // Hex-encoded SHA-256 of the most recently *durably persisted*
    // event. `None` before the first event (genesis). Advanced as each
    // line is written within a batch, then rolled back if the batch's
    // fsync fails so a retry re-derives from the last durable hash.
    let mut last_hash: Option<String> = None;
    let mut open_id = open_file_id(&file).await;

    while let Some(first) = rx.recv().await {
        // Coalesce: this event plus everything already queued.
        let mut batch = vec![first];
        while let Ok(c) = rx.try_recv() {
            batch.push(c);
        }

        // Before the batch is written, not after: the records must land
        // in the live file, never in a renamed or unlinked inode. A
        // reopen failure fails the batch on the fsync path — the chain
        // has not moved, so a retry re-derives from the same hash.
        if let Err(e) = follow_rotation(&mut file, &mut open_id, &path).await {
            fail_batch(batch, &format!("reopen audit log {}: {e}", path.display()));
            continue;
        }

        let chain_before = last_hash.clone();
        let mut write_replies: Vec<(oneshot::Sender<Result<AuditReceipt, AuditError>>, String)> =
            Vec::new();
        let mut flush_replies: Vec<oneshot::Sender<Result<(), AuditError>>> = Vec::new();

        for cmd in batch {
            match cmd {
                Cmd::Write { event, reply } => {
                    let bytes = match canonical_bytes(&event, last_hash.clone()) {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = reply.send(Err(e));
                            continue;
                        }
                    };
                    let durable_hash = sha256_hex(&bytes);
                    let mut line = bytes;
                    line.push(b'\n');
                    if let Err(e) = file.write_all(&line).await {
                        let _ = reply.send(Err(AuditError::WriteFailed {
                            reason: format!("write audit event: {e}"),
                        }));
                        continue;
                    }
                    // Chain advances for subsequent events in the batch;
                    // made durable by the single fsync below.
                    last_hash = Some(durable_hash.clone());
                    write_replies.push((reply, durable_hash));
                }
                Cmd::Flush { reply } => flush_replies.push(reply),
            }
        }

        // One fsync for the whole batch — the group-commit payoff.
        match file.sync_all().await {
            Ok(()) => {
                let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                for (reply, durable_hash) in write_replies {
                    let _ = reply.send(Ok(AuditReceipt {
                        sink_id: sink_id.clone(),
                        persisted_at: now.clone(),
                        durable_hash,
                    }));
                }
                for reply in flush_replies {
                    let _ = reply.send(Ok(()));
                }
            }
            Err(e) => {
                // The batch is not durable. Roll the chain back to the
                // last durable hash and fail every waiter (FailClosed-safe:
                // no request proceeds without a durable audit trail).
                last_hash = chain_before;
                let reason = format!("fsync audit log: {e}");
                for (reply, _) in write_replies {
                    let _ = reply.send(Err(AuditError::WriteFailed {
                        reason: reason.clone(),
                    }));
                }
                for reply in flush_replies {
                    let _ = reply.send(Err(AuditError::WriteFailed {
                        reason: reason.clone(),
                    }));
                }
            }
        }
    }
}

/// Compute the hex-encoded SHA-256 of `bytes`. Shared between
/// `emit` and tests.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Serialise `event` with the provided `prev_event_hash` overriding
/// whatever the caller put on it. Returned bytes are what the sink
/// actually writes to disk, and what `durable_hash` is computed over
/// — consumers can replay the chain by re-deriving the SAME bytes
/// from the events they read back.
fn canonical_bytes(
    event: &AuditEvent,
    prev_event_hash: Option<String>,
) -> Result<Vec<u8>, AuditError> {
    let mut override_event = event.clone();
    override_event.prev_event_hash = prev_event_hash;
    serde_json::to_vec(&override_event).map_err(|e| AuditError::WriteFailed {
        reason: format!("serialize audit event: {e}"),
    })
}

#[mcpg_plugin_protocol::async_trait]
impl AuditSink for LocalFileAuditSink {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
        // The writer stamps prev_event_hash + hashes + writes; we just
        // hand off the event and await durability. The hash chain stays
        // deterministic because exactly one task writes, in receive order.
        let tx = self.sender().await?;
        let (reply, rx) = oneshot::channel();
        tx.send(Cmd::Write {
            event: event.clone(),
            reply,
        })
        .map_err(|_| AuditError::WriteFailed {
            reason: "audit writer task stopped".into(),
        })?;
        rx.await.map_err(|_| AuditError::WriteFailed {
            reason: "audit writer dropped reply".into(),
        })?
    }

    async fn flush(&self, _timeout_ms: u64) -> Result<(), AuditError> {
        // Nothing written yet ⇒ nothing to sync.
        let Some(tx) = self.writer.get() else {
            return Ok(());
        };
        let (reply, rx) = oneshot::channel();
        tx.send(Cmd::Flush { reply })
            .map_err(|_| AuditError::WriteFailed {
                reason: "audit writer task stopped".into(),
            })?;
        rx.await.map_err(|_| AuditError::WriteFailed {
            reason: "audit writer dropped reply".into(),
        })?
    }

    async fn shutdown(&self) {
        // Best-effort final flush. Any error here is already on
        // the happy path — the gateway is shutting down; we log
        // and move on.
        if let Err(e) = self.flush(0).await {
            tracing::warn!(
                plugin_id = %self.manifest.id,
                error = %e,
                "audit local-file flush on shutdown failed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;
    use mcpg_plugin_protocol::audit::AuditOutcome;

    fn test_event(event_id: &str, action: &str) -> AuditEvent {
        AuditEvent {
            event_id: event_id.into(),
            occurred_at: "2026-04-24T12:00:00Z".into(),
            actor: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            action: action.into(),
            resource: None,
            outcome: AuditOutcome::Success,
            request_id: None,
            node_id: None,
            details: serde_json::json!({}),
            prev_event_hash: None,
        }
    }

    #[tokio::test]
    async fn emit_writes_jsonl_line_and_fsyncs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();

        sink.emit(&test_event("e1", "test.event"))
            .await
            .expect("emit ok");

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(contents.ends_with('\n'), "line terminated");
        let line = contents.trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["event_id"], "e1");
        assert_eq!(v["action"], "test.event");
    }

    #[tokio::test]
    async fn hash_chain_links_successive_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();

        let r1 = sink.emit(&test_event("e1", "a")).await.unwrap();
        let r2 = sink.emit(&test_event("e2", "b")).await.unwrap();
        let r3 = sink.emit(&test_event("e3", "c")).await.unwrap();

        assert_ne!(r1.durable_hash, r2.durable_hash);
        assert_ne!(r2.durable_hash, r3.durable_hash);

        // Re-read the file and verify each line's prev_event_hash
        // matches the previous event's durable_hash.
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].get("prev_event_hash").is_none());
        assert_eq!(lines[1]["prev_event_hash"], r1.durable_hash);
        assert_eq!(lines[2]["prev_event_hash"], r2.durable_hash);
    }

    #[tokio::test]
    async fn durable_hash_matches_line_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();
        let r = sink.emit(&test_event("e1", "x")).await.unwrap();
        // Re-derive the hash from the exact bytes written (excluding the newline).
        let contents = tokio::fs::read(&path).await.unwrap();
        let line = contents.strip_suffix(b"\n").unwrap();
        let derived = sha256_hex(line);
        assert_eq!(derived, r.durable_hash);
    }

    #[tokio::test]
    async fn receipt_reports_sink_id() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalFileAuditSink::open(dir.path().join("a.log")).unwrap();
        let r = sink.emit(&test_event("e1", "x")).await.unwrap();
        assert_eq!(r.sink_id, "dev.mcpg.builtin.audit.local-file");
    }

    #[tokio::test]
    async fn concurrent_emits_serialise_into_hash_chain() {
        // Three in-flight emits — the Mutex must serialise them or
        // the hash chain breaks. Each iteration hashes the previous
        // event's on-disk form, so a missed lock would produce
        // duplicate / wrong prev_event_hash entries that don't
        // chain. The test asserts the chain still chains.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();
        let s = sink.clone();
        let h1 = tokio::spawn(async move { s.emit(&test_event("e1", "a")).await });
        let s = sink.clone();
        let h2 = tokio::spawn(async move { s.emit(&test_event("e2", "b")).await });
        let s = sink.clone();
        let h3 = tokio::spawn(async move { s.emit(&test_event("e3", "c")).await });
        h1.await.unwrap().unwrap();
        h2.await.unwrap().unwrap();
        h3.await.unwrap().unwrap();

        // Read the raw bytes — not parsed JSON — because the chain
        // is defined over the exact on-disk form. Parsing through
        // `serde_json::Value` would sort keys alphabetically on
        // re-serialize and break the comparison.
        let raw = tokio::fs::read(&path).await.unwrap();
        let line_bytes: Vec<&[u8]> = raw
            .strip_suffix(b"\n")
            .unwrap_or(&raw)
            .split(|b| *b == b'\n')
            .collect();
        assert_eq!(line_bytes.len(), 3);

        let parsed: Vec<serde_json::Value> = line_bytes
            .iter()
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        // Genesis — no prev.
        assert!(parsed[0].get("prev_event_hash").is_none());
        // Events 2 + 3 must point at their predecessors' hashes.
        for i in 1..3 {
            let expected = sha256_hex(line_bytes[i - 1]);
            assert_eq!(parsed[i]["prev_event_hash"], expected);
        }
    }

    /// `logrotate`'s default strategy: rename the live file, let the
    /// sink create a new one. Without rotation-following every write
    /// after the rename still succeeds — into the renamed inode — and
    /// the records never reach the path operators collect from.
    #[cfg(unix)]
    #[tokio::test]
    async fn writes_follow_an_externally_renamed_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let rotated = dir.path().join("audit.log.1");
        let sink = LocalFileAuditSink::open(&path).unwrap();

        sink.emit(&test_event("e1", "a")).await.unwrap();
        tokio::fs::rename(&path, &rotated).await.unwrap();
        let rotated_len = tokio::fs::metadata(&rotated).await.unwrap().len();

        sink.emit(&test_event("e2", "b")).await.unwrap();
        sink.emit(&test_event("e3", "c")).await.unwrap();

        // The post-rotation events are in the new file, and only those.
        let fresh = tokio::fs::read(&path).await.unwrap();
        let fresh_lines: Vec<&[u8]> = fresh
            .strip_suffix(b"\n")
            .unwrap_or(&fresh)
            .split(|b| *b == b'\n')
            .collect();
        assert_eq!(fresh_lines.len(), 2, "both events landed in the new file");
        let ids: Vec<String> = fresh_lines
            .iter()
            .map(|l| {
                serde_json::from_slice::<serde_json::Value>(l).unwrap()["event_id"].to_string()
            })
            .collect();
        assert_eq!(ids, vec!["\"e2\"".to_owned(), "\"e3\"".to_owned()]);

        // The renamed file stopped growing the moment it was rotated.
        assert_eq!(
            tokio::fs::metadata(&rotated).await.unwrap().len(),
            rotated_len,
            "renamed file must not receive further writes"
        );
        let old = tokio::fs::read(&rotated).await.unwrap();
        let old_last = old.strip_suffix(b"\n").unwrap();
        assert_eq!(old_last.split(|b| *b == b'\n').count(), 1);

        // The chain spans the rotation boundary: the new file starts
        // mid-chain, pointing at the last line of its predecessor.
        let first_new: serde_json::Value = serde_json::from_slice(fresh_lines[0]).unwrap();
        assert_eq!(first_new["prev_event_hash"], sha256_hex(old_last));
    }

    /// Rotated away and deleted before the sink writes again — the
    /// pathological case, where the handle points at an unlinked inode
    /// and the batch has nowhere to go unless the path is recreated.
    #[cfg(unix)]
    #[tokio::test]
    async fn writes_recreate_a_path_rotated_away_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();

        sink.emit(&test_event("e1", "a")).await.unwrap();
        tokio::fs::remove_file(&path).await.unwrap();

        let receipt = sink.emit(&test_event("e2", "b")).await.expect("emit ok");

        let contents = tokio::fs::read(&path).await.expect("path recreated");
        let line = contents.strip_suffix(b"\n").unwrap();
        assert_eq!(line.split(|b| *b == b'\n').count(), 1);
        let v: serde_json::Value = serde_json::from_slice(line).unwrap();
        assert_eq!(v["event_id"], "e2");
        // The receipt still describes the bytes actually on disk.
        assert_eq!(receipt.durable_hash, sha256_hex(line));
    }

    #[test]
    fn descriptor_yaml_parses_as_audit_sink() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.audit.local-file");
        assert_eq!(d.class, PluginClass::AuditSink);
    }

    #[test]
    fn canonical_bytes_respects_prev_hash_override() {
        let event = test_event("e1", "a");
        let b1 = canonical_bytes(&event, None).unwrap();
        let b2 = canonical_bytes(&event, Some("hash".repeat(16))).unwrap();
        assert_ne!(b1, b2);
        // Even when the caller tries to pre-stamp prev_event_hash,
        // the override wins — deterministic chaining.
        let mut pre_stamped = event.clone();
        pre_stamped.prev_event_hash = Some("lies".into());
        let b3 = canonical_bytes(&pre_stamped, None).unwrap();
        assert_eq!(b1, b3);
    }
}
