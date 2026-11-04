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
//! A single writer task, on a thread and runtime of its own, owns the
//! file handle + hash chain.
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
//! # One writer per file
//!
//! `path` may hold a `{node}` placeholder, replaced by the node id, so
//! replicas that share a volume each write their own file. A file has
//! exactly one writer: sinks opened on the same path in one process
//! (a config reload) share one writer, and an exclusive lock on
//! `<path>.lock` refuses a second process. Two writers would interleave
//! two hash chains in one file.
//!
//! On open, the chain continues from the last complete line of the live
//! file (or, when it is empty, of the newest backup), so a restart does
//! not start a new genesis. A torn last line, left by a crash mid-write,
//! is closed with a newline before the next record.
//!
//! # Rotation
//!
//! With `max_size_mb` set (the default is 100), the writer rotates the
//! file itself before a batch would take it past that size: the live
//! file is renamed to `<stem>-<UTC timestamp>.<ext>` and a fresh one is
//! created. `max_backups` and `max_age_days` prune old backups; both
//! default to 0, which keeps every backup. `max_size_mb: 0` leaves
//! rotation to an external tool.
//!
//! External rotation (`logrotate` or equivalent) still works. Its
//! default strategy renames the live file and creates a fresh one, which
//! leaves an append-only handle bound to the renamed inode — and once
//! that file is compressed away, to an unlinked one. Every write would
//! keep succeeding while the records went nowhere, so the writer compares
//! the open handle's file identity against whatever the path resolves to
//! at each **batch** boundary and reopens append-only when they diverge.
//! The cost is one `stat` per batch, not per event. A path rotated away
//! but not yet recreated is recreated by that reopen, so no batch is lost.
//!
//! The identity comparison is Unix-only — Windows exposes the
//! equivalent (`volume_serial_number` / `file_index`) only behind the
//! unstable `windows_by_handle` feature. Off Unix the writer still
//! recreates a path that has vanished, but a path swapped underneath it
//! goes unnoticed; rotation there belongs to the log collector.
//!
//! The hash chain belongs to the file's writer, not to any one file: it
//! continues across a rotation, so a rotated file begins mid-chain.
//! Verify the concatenation of the rotated files in write order rather
//! than each file in isolation — only the very first file starts at
//! genesis (`prev_event_hash: null`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

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
  with SHA-256 hashes per spec §9.12. One file per node (`{node}` in
  the path), rotated by size. Single-node durability.
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

/// The sink's `config:` block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalFileConfig {
    /// File to append to. `{node}` is replaced by the node id.
    pub path: String,
    /// Rotate before the file grows past this many MiB; 0 never rotates.
    pub max_size_mb: u64,
    /// Rotated files to keep, newest first; 0 keeps all.
    pub max_backups: u32,
    /// Delete rotated files older than this many days; 0 keeps all.
    pub max_age_days: u32,
}

impl Default for LocalFileConfig {
    fn default() -> Self {
        Self {
            path: "./mcpg-audit.log".to_owned(),
            max_size_mb: 100,
            max_backups: 0,
            max_age_days: 0,
        }
    }
}

impl LocalFileConfig {
    /// `path` with `{node}` replaced by `node` (`unknown` when absent),
    /// reduced to characters that are safe in one file name.
    #[must_use]
    pub fn resolved_path(&self, node: Option<&str>) -> PathBuf {
        if !self.path.contains("{node}") {
            return PathBuf::from(&self.path);
        }
        let safe: String = node
            .unwrap_or_default()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let safe = if safe.is_empty() || safe == "." || safe == ".." {
            "unknown".to_owned()
        } else {
            safe
        };
        PathBuf::from(self.path.replace("{node}", &safe))
    }

    fn rotation(&self) -> Rotation {
        Rotation {
            max_bytes: self.max_size_mb.saturating_mul(1024 * 1024),
            max_backups: self.max_backups as usize,
            max_age: (self.max_age_days > 0)
                .then(|| chrono::Duration::days(i64::from(self.max_age_days))),
        }
    }
}

/// The size and retention limits the writer applies.
#[derive(Debug, Clone, Default)]
struct Rotation {
    max_bytes: u64,
    max_backups: usize,
    max_age: Option<chrono::Duration>,
}

/// Where the chain resumes when the writer starts.
struct WriterSeed {
    file: File,
    last_hash: Option<String>,
    /// The file ends in a torn line, which the first batch must close.
    torn: bool,
}

/// The one writer of one file, shared by every sink open on its path.
struct SharedWriter {
    path: PathBuf,
    rotation: Arc<Mutex<Rotation>>,
    /// To the writer, which runs on a thread of its own: no caller's
    /// runtime can end it while another caller still writes. It stops
    /// once the last sender is dropped.
    sender: mpsc::UnboundedSender<Cmd>,
    /// Held for the writer's life: the exclusive lock on `<path>.lock`.
    _lock: std::fs::File,
}

static WRITERS: LazyLock<Mutex<HashMap<PathBuf, Weak<SharedWriter>>>> =
    LazyLock::new(Default::default);

impl SharedWriter {
    fn open(path: &Path, rotation: Rotation) -> anyhow::Result<Arc<Self>> {
        let path = absolute_path(path)?;
        let mut writers = WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = writers.get(&path).and_then(Weak::upgrade) {
            *existing
                .rotation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = rotation;
            return Ok(existing);
        }
        let mut lock_path = path.clone().into_os_string();
        lock_path.push(".lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening audit log lock {}", lock_path.display()))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "audit log {} is in use by another process; give each replica its own \
                 file with `{{node}}` in the path",
                path.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).with_context(|| format!("locking {}", lock_path.display()));
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening audit log file {}", path.display()))?;
        let (last_hash, torn) = chain_tip(&path)
            .with_context(|| format!("reading the hash chain tip of {}", path.display()))?;
        let rotation = Arc::new(Mutex::new(rotation));
        let (tx, rx) = mpsc::unbounded_channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building the audit writer runtime")?;
        let (thread_path, thread_rotation) = (path.clone(), Arc::clone(&rotation));
        std::thread::Builder::new()
            .name("mcpg-audit-writer".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let seed = WriterSeed {
                        file: File::from_std(file),
                        last_hash,
                        torn,
                    };
                    writer_loop(seed, thread_path, thread_rotation, rx, PLUGIN_ID.to_owned()).await;
                });
            })
            .context("starting the audit writer thread")?;
        let writer = Arc::new(Self {
            path: path.clone(),
            rotation,
            sender: tx,
            _lock: lock,
        });
        writers.retain(|_, w| w.strong_count() > 0);
        writers.insert(path, Arc::downgrade(&writer));
        Ok(writer)
    }
}

/// `path` made absolute with its directory's symlinks resolved, so two
/// spellings of one file share one writer.
fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("audit log path {} names no file", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir = std::fs::canonicalize(parent)
        .with_context(|| format!("audit log directory {}", parent.display()))?;
    Ok(dir.join(name))
}

/// The last complete line of `path`, and whether a torn line follows it.
fn last_complete_line(path: &Path) -> std::io::Result<(Option<Vec<u8>>, bool)> {
    use std::io::{Read, Seek, SeekFrom};
    const CHUNK: u64 = 64 * 1024;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, false)),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok((None, false));
    }
    let mut tail: Vec<u8> = Vec::new();
    let mut pos = len;
    let mut torn = None;
    loop {
        let start = pos.saturating_sub(CHUNK);
        let mut chunk = vec![0; usize::try_from(pos - start).unwrap_or(0)];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        pos = start;
        let torn = *torn.get_or_insert_with(|| tail.last() != Some(&b'\n'));
        if let Some(end) = tail.iter().rposition(|b| *b == b'\n') {
            if let Some(nl) = tail[..end].iter().rposition(|b| *b == b'\n') {
                return Ok((Some(tail[nl + 1..end].to_vec()), torn));
            }
            if pos == 0 {
                return Ok((Some(tail[..end].to_vec()), torn));
            }
        } else if pos == 0 {
            return Ok((None, torn));
        }
    }
}

/// The hash the next record chains to: the live file's last complete
/// line, or the newest backup's when the live file holds none.
fn chain_tip(path: &Path) -> std::io::Result<(Option<String>, bool)> {
    let (line, torn) = last_complete_line(path)?;
    let line = match line {
        Some(line) => Some(line),
        None => match list_backups(path)?.into_iter().next() {
            Some((_, backup)) => last_complete_line(&backup)?.0,
            None => None,
        },
    };
    Ok((line.map(|l| sha256_hex(&l)), torn))
}

const BACKUP_TIME_FORMAT: &str = "%Y-%m-%dT%H-%M-%S%.3f";

/// `audit.log` → (`audit`, `.log`); `audit` → (`audit`, ``).
fn stem_and_ext(path: &Path) -> (String, String) {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (stem, ext)
}

fn backup_path(path: &Path, at: chrono::DateTime<chrono::Utc>) -> PathBuf {
    let (stem, ext) = stem_and_ext(path);
    path.with_file_name(format!("{stem}-{}{ext}", at.format(BACKUP_TIME_FORMAT)))
}

/// Rotated files of `path`, newest first.
fn list_backups(path: &Path) -> std::io::Result<Vec<(chrono::DateTime<chrono::Utc>, PathBuf)>> {
    let (stem, ext) = stem_and_ext(path);
    let prefix = format!("{stem}-");
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stamp) = name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(ext.as_str()))
        else {
            continue;
        };
        if let Ok(at) = chrono::NaiveDateTime::parse_from_str(stamp, BACKUP_TIME_FORMAT) {
            out.push((at.and_utc(), entry.path()));
        }
    }
    out.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    Ok(out)
}

/// Delete the backups past `max_backups` or older than `max_age`.
fn prune_backups(path: &Path, rotation: &Rotation, now: chrono::DateTime<chrono::Utc>) {
    let backups = match list_backups(path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "listing audit log backups failed");
            return;
        }
    };
    for (i, (at, backup)) in backups.iter().enumerate() {
        let over_count = rotation.max_backups > 0 && i >= rotation.max_backups;
        let over_age = rotation.max_age.is_some_and(|age| *at < now - age);
        if (over_count || over_age)
            && let Err(e) = std::fs::remove_file(backup)
        {
            tracing::warn!(path = %backup.display(), error = %e, "deleting an audit log backup failed");
        }
    }
}

/// Rename the live file to a timestamped backup, start a fresh one, and
/// prune. On an error the handle still points at a file that keeps the
/// records: the renamed one, or the live one when the rename failed.
async fn rotate(
    file: &mut File,
    open_id: &mut Option<FileId>,
    path: &Path,
    rotation: &Rotation,
) -> std::io::Result<()> {
    let mut at = chrono::Utc::now();
    let mut backup = backup_path(path, at);
    while tokio::fs::try_exists(&backup).await.unwrap_or(false) {
        at += chrono::Duration::milliseconds(1);
        backup = backup_path(path, at);
    }
    tokio::fs::rename(path, &backup).await?;
    let fresh = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    *open_id = open_file_id(&fresh).await;
    *file = fresh;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        // The rename is durable only once the directory entry is.
        if let Ok(d) = File::open(dir).await {
            let _ = d.sync_all().await;
        }
    }
    let path = path.to_owned();
    let rotation = rotation.clone();
    let _ = tokio::task::spawn_blocking(move || prune_backups(&path, &rotation, at)).await;
    metrics::counter!("mcpg_audit_local_file_rotations_total").increment(1);
    Ok(())
}

/// Built-in local-file audit sink. Emits are funnelled to a single
/// background writer that group-commits batches (one fsync per batch);
/// see the module docs.
pub struct LocalFileAuditSink {
    manifest: PluginManifest,
    writer: Arc<SharedWriter>,
}

impl LocalFileAuditSink {
    /// Open or create the audit file at `path`, without rotation.
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Arc<Self>> {
        Self::open_with(&path.into(), Rotation::default())
    }

    /// Open the file `config` names for `node`, with its rotation
    /// limits. Sync I/O — `build_plugin_registry` runs under either
    /// the multi-thread or the single-thread tokio runtime.
    pub fn open_config(config: &LocalFileConfig, node: Option<&str>) -> anyhow::Result<Arc<Self>> {
        Self::open_with(&config.resolved_path(node), config.rotation())
    }

    fn open_with(path: &Path, rotation: Rotation) -> anyhow::Result<Arc<Self>> {
        let writer = SharedWriter::open(path, rotation)?;
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
            writer,
        }))
    }

    /// Absolute path this sink writes to. Exposed for logging.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.writer.path
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
/// triggered the check still lands on disk. `Ok(true)` when it reopened.
async fn follow_rotation(
    file: &mut File,
    open_id: &mut Option<FileId>,
    path: &Path,
) -> std::io::Result<bool> {
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
        return Ok(false);
    }

    let reopened = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    *open_id = open_file_id(&reopened).await;
    *file = reopened;
    Ok(true)
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
    seed: WriterSeed,
    path: PathBuf,
    rotation: Arc<Mutex<Rotation>>,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    sink_id: String,
) {
    let WriterSeed {
        mut file,
        // Hex-encoded SHA-256 of the most recently *durably persisted*
        // event; `None` at genesis. Advanced as each line of a batch is
        // encoded, then rolled back if the batch's write or fsync fails
        // so a retry re-derives from the last durable hash.
        mut last_hash,
        mut torn,
    } = seed;
    let mut open_id = open_file_id(&file).await;
    let mut size = file.metadata().await.map_or(0, |m| m.len());

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
        match follow_rotation(&mut file, &mut open_id, &path).await {
            Ok(false) => {}
            Ok(true) => {
                size = file.metadata().await.map_or(0, |m| m.len());
                torn = false;
            }
            Err(e) => {
                fail_batch(batch, &format!("reopen audit log {}: {e}", path.display()));
                continue;
            }
        }

        let chain_before = last_hash.clone();
        let mut write_replies: Vec<(oneshot::Sender<Result<AuditReceipt, AuditError>>, String)> =
            Vec::new();
        let mut flush_replies: Vec<oneshot::Sender<Result<(), AuditError>>> = Vec::new();
        let mut lines: Vec<u8> = Vec::new();
        if torn {
            lines.push(b'\n');
        }

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
                    lines.extend_from_slice(&bytes);
                    lines.push(b'\n');
                    // Chain advances for subsequent events in the batch;
                    // made durable by the single write and fsync below.
                    last_hash = Some(durable_hash.clone());
                    write_replies.push((reply, durable_hash));
                }
                Cmd::Flush { reply } => flush_replies.push(reply),
            }
        }

        let limits = rotation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if limits.max_bytes > 0 && size > 0 && size + lines.len() as u64 > limits.max_bytes {
            match rotate(&mut file, &mut open_id, &path, &limits).await {
                Ok(()) => {
                    size = 0;
                    // A fresh file has no torn line to close.
                    if torn {
                        lines.remove(0);
                    }
                }
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "audit log rotation failed; writing on to the current file"
                ),
            }
        }

        // One write and one fsync for the whole batch — the group-commit
        // payoff: each write of a tokio `File` is a blocking-pool hand-off.
        let committed = match file.write_all(&lines).await {
            Ok(()) => file
                .sync_all()
                .await
                .map_err(|e| format!("fsync audit log: {e}")),
            Err(e) => Err(format!("write audit log: {e}")),
        };
        match committed {
            Ok(()) => {
                size += lines.len() as u64;
                torn = false;
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
            Err(reason) => {
                // The batch is not durable. Roll the chain back to the
                // last durable hash and fail every waiter (FailClosed-safe:
                // no request proceeds without a durable audit trail).
                last_hash = chain_before;
                // A failed write may have left part of the batch behind.
                size = file.metadata().await.map_or(size, |m| m.len());
                let probe = path.clone();
                torn = tokio::task::spawn_blocking(move || last_complete_line(&probe))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .is_some_and(|(_, torn)| torn);
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
        let (reply, rx) = oneshot::channel();
        self.writer
            .sender
            .send(Cmd::Write {
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
        let (reply, rx) = oneshot::channel();
        self.writer
            .sender
            .send(Cmd::Flush { reply })
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
            upstream_request_id: None,
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

    fn lines_of(bytes: &[u8]) -> Vec<Vec<u8>> {
        bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }

    /// Every line of `files`, in order, chains to the line before it.
    fn assert_one_chain(files: &[PathBuf]) -> usize {
        let mut prev: Option<String> = None;
        let mut count = 0;
        for f in files {
            for line in lines_of(&std::fs::read(f).unwrap()) {
                let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
                assert_eq!(
                    v.get("prev_event_hash")
                        .and_then(|h| h.as_str())
                        .map(str::to_owned),
                    prev,
                    "{} breaks the chain",
                    f.display()
                );
                prev = Some(sha256_hex(&line));
                count += 1;
            }
        }
        count
    }

    fn rotation(max_bytes: u64, max_backups: usize) -> Rotation {
        Rotation {
            max_bytes,
            max_backups,
            max_age: None,
        }
    }

    #[tokio::test]
    async fn rotates_by_size_and_keeps_one_chain_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = LocalFileAuditSink::open_with(&path, rotation(1, 0)).unwrap();
        for id in ["e1", "e2", "e3"] {
            sink.emit(&test_event(id, "a")).await.unwrap();
        }
        let backups = list_backups(&path).unwrap();
        assert_eq!(
            backups.len(),
            2,
            "each batch past the limit starts a new file"
        );
        let mut files: Vec<PathBuf> = backups.into_iter().rev().map(|(_, p)| p).collect();
        for f in &files {
            let name = f.file_name().unwrap().to_str().unwrap();
            assert!(
                name.starts_with("audit-") && name.ends_with(".jsonl"),
                "{name}"
            );
        }
        files.push(path.clone());
        assert_eq!(assert_one_chain(&files), 3);
        assert_eq!(lines_of(&std::fs::read(&path).unwrap()).len(), 1);
    }

    #[tokio::test]
    async fn max_backups_deletes_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = LocalFileAuditSink::open_with(&path, rotation(1, 2)).unwrap();
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            sink.emit(&test_event(id, "a")).await.unwrap();
        }
        let backups = list_backups(&path).unwrap();
        assert_eq!(backups.len(), 2);
        let kept: Vec<String> = backups
            .iter()
            .map(|(_, p)| {
                let line = lines_of(&std::fs::read(p).unwrap()).remove(0);
                serde_json::from_slice::<serde_json::Value>(&line).unwrap()["event_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(kept, vec!["e4", "e3"], "newest first, oldest deleted");
    }

    #[test]
    fn max_age_deletes_old_backups_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let now = chrono::Utc::now();
        let old = backup_path(&path, now - chrono::Duration::days(10));
        let new = backup_path(&path, now - chrono::Duration::days(1));
        let other = dir.path().join("audit-gw-1.log");
        for f in [&old, &new, &other] {
            std::fs::write(f, b"x\n").unwrap();
        }
        let limits = Rotation {
            max_bytes: 1,
            max_backups: 0,
            max_age: Some(chrono::Duration::days(7)),
        };
        prune_backups(&path, &limits, now);
        assert!(!old.exists());
        assert!(new.exists());
        assert!(
            other.exists(),
            "a file that is not a backup is never touched"
        );
    }

    #[tokio::test]
    async fn a_reopened_file_continues_its_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let first = LocalFileAuditSink::open(&path).unwrap();
        first.emit(&test_event("e1", "a")).await.unwrap();
        drop(first);
        let second = LocalFileAuditSink::open(&path).unwrap();
        second.emit(&test_event("e2", "b")).await.unwrap();
        assert_eq!(assert_one_chain(&[path]), 2, "no second genesis");
    }

    #[tokio::test]
    async fn a_torn_last_line_is_closed_and_skipped_by_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();
        let r1 = sink.emit(&test_event("e1", "a")).await.unwrap();
        drop(sink);
        let mut torn = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut torn, b"{\"event_id\":\"half").unwrap();
        drop(torn);

        let sink = LocalFileAuditSink::open(&path).unwrap();
        sink.emit(&test_event("e2", "b")).await.unwrap();
        let lines = lines_of(&std::fs::read(&path).unwrap());
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], b"{\"event_id\":\"half");
        let e2: serde_json::Value = serde_json::from_slice(&lines[2]).unwrap();
        assert_eq!(e2["event_id"], "e2");
        assert_eq!(e2["prev_event_hash"], r1.durable_hash);
    }

    #[tokio::test]
    async fn sinks_on_one_path_in_one_process_share_one_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let a = LocalFileAuditSink::open(&path).unwrap();
        let b = LocalFileAuditSink::open(dir.path().join(".").join("audit.log")).unwrap();
        a.emit(&test_event("e1", "a")).await.unwrap();
        b.emit(&test_event("e2", "b")).await.unwrap();
        a.emit(&test_event("e3", "c")).await.unwrap();
        assert_eq!(assert_one_chain(&[path]), 3);
    }

    #[test]
    fn the_writer_outlives_the_runtime_of_its_first_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = LocalFileAuditSink::open(&path).unwrap();
        for id in ["e1", "e2"] {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(sink.emit(&test_event(id, "a")))
                .expect("emit on a fresh runtime");
        }
        assert_eq!(assert_one_chain(&[path]), 2);
    }

    #[test]
    fn a_file_another_writer_holds_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let other = std::fs::File::create(dir.path().join("audit.log.lock")).unwrap();
        other.try_lock().unwrap();
        let err = LocalFileAuditSink::open(&path).err().expect("refused");
        assert!(err.to_string().contains("{node}"), "{err}");
        drop(other);
        assert!(LocalFileAuditSink::open(&path).is_ok());
    }

    #[test]
    fn node_placeholder_resolves_to_a_safe_file_name() {
        let config = LocalFileConfig {
            path: "/var/log/mcpg/audit-{node}.log".into(),
            ..LocalFileConfig::default()
        };
        assert_eq!(
            config.resolved_path(Some("gw-0")),
            PathBuf::from("/var/log/mcpg/audit-gw-0.log")
        );
        assert_eq!(
            config.resolved_path(Some("../../etc/x")),
            PathBuf::from("/var/log/mcpg/audit-.._.._etc_x.log")
        );
        assert_eq!(
            config.resolved_path(Some("..")),
            PathBuf::from("/var/log/mcpg/audit-unknown.log")
        );
        assert_eq!(
            config.resolved_path(None),
            PathBuf::from("/var/log/mcpg/audit-unknown.log")
        );
    }

    #[test]
    fn config_defaults_rotate_at_100_mib_and_keep_every_backup() {
        let c: LocalFileConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(c, LocalFileConfig::default());
        assert_eq!(c.rotation().max_bytes, 100 * 1024 * 1024);
        assert_eq!(c.rotation().max_backups, 0);
        assert!(c.rotation().max_age.is_none());
        assert!(
            serde_json::from_value::<LocalFileConfig>(serde_json::json!({ "max_size": 1 }))
                .is_err(),
            "a mistyped key is refused"
        );
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
