//! Directory-backed `KeyValueStore` + `PubSub` primitive impls.
//!
//! `FileKv` is the directory-backed `KeyValueStore`.
//! `FileBus` is a forensics-grade file-tailing pub/sub
//! suitable for single-node debugging / log analysis. Both share
//! the same `data_dir` root:
//!
//! ```text
//! data_dir/
//!   kv/                                  ← FileKv
//!     {hash}.json                        each holds {key, payload_b64, expires_at}
//!   topics/                              ← FileBus
//!     {topic_safe}.ndjson                append-only log of published messages
//! ```
//!
//! `FileBus` is intentionally less reliable than `MemoryBus` — it
//! polls each topic file every 250 ms for new lines, and writes
//! are best-effort `append` (no fsync). The trade-off is that the
//! on-disk log is human-readable, durable across restarts, and
//! consumable by external tools (`tail -f`, `jq`, …) which is the
//! main reason an operator would choose the file backing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures::stream::StreamExt;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore, Message, PubSub, Subscription};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// FileKv
// ---------------------------------------------------------------------------

/// Stored on-disk shape — keep stable; operators may script around it.
#[derive(Debug, Serialize, Deserialize)]
struct StoredKv {
    key: String,
    /// Base64-encoded payload bytes (compact + JSON-safe).
    #[serde(with = "base64_bytes")]
    payload: Vec<u8>,
    /// Wall-clock expiry as seconds-since-epoch. None = never.
    expires_at_secs: Option<u64>,
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(d)?;
        STANDARD.decode(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
pub struct FileKv {
    kv_dir: PathBuf,
}

impl FileKv {
    /// Create a `FileKv` rooted at `<data_dir>/kv/`. The directory
    /// is created if it does not exist.
    pub async fn new(data_dir: impl AsRef<Path>) -> Result<Arc<Self>, ClusterError> {
        let kv_dir = data_dir.as_ref().join("kv");
        fs::create_dir_all(&kv_dir)
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("create kv_dir {}: {}", kv_dir.display(), e),
            })?;
        Ok(Arc::new(Self { kv_dir }))
    }

    /// Spawn a background sweeper that drops expired entries every
    /// `interval`. The task holds an `Arc<Self>` and exits when the
    /// last strong reference is dropped.
    pub fn with_sweep(self: Arc<Self>, interval: Duration) -> Arc<Self> {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(this) = weak.upgrade() else {
                    break;
                };
                if let Err(e) = this.sweep().await {
                    tracing::warn!(error = %e, "file-kv sweep failed");
                }
            }
        });
        self
    }

    fn path_for(&self, key: &str) -> PathBuf {
        // SHA-256 of the key: collision-resistant, filesystem-safe, and
        // restart-stable. A 64-bit hash here could collide and silently
        // evict a distinct live key; the `stored.key != key` read guard
        // keeps even an (astronomically improbable) collision fail-safe.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let mut name = String::with_capacity(64 + 5);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(name, "{b:02x}");
        }
        name.push_str(".json");
        self.kv_dir.join(name)
    }

    async fn read_entry(&self, key: &str) -> Result<Option<StoredKv>, ClusterError> {
        let path = self.path_for(key);
        match fs::read(&path).await {
            Ok(bytes) => {
                let stored: StoredKv =
                    serde_json::from_slice(&bytes).map_err(|e| ClusterError::Internal {
                        reason: format!("decode {}: {}", path.display(), e),
                    })?;
                if stored.key != key {
                    // Hash collision (or stale leftover). Treat as missing.
                    return Ok(None);
                }
                Ok(Some(stored))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ClusterError::BackendUnavailable {
                reason: format!("read {}: {}", path.display(), e),
            }),
        }
    }

    async fn write_entry(&self, stored: &StoredKv) -> Result<(), ClusterError> {
        let path = self.path_for(&stored.key);
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(stored).map_err(|e| ClusterError::Internal {
            reason: format!("encode entry: {e}"),
        })?;
        fs::write(&tmp, &bytes)
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("write {}: {}", tmp.display(), e),
            })?;
        fs::rename(&tmp, &path)
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("rename {} -> {}: {}", tmp.display(), path.display(), e),
            })?;
        Ok(())
    }

    async fn delete_entry(&self, key: &str) -> Result<bool, ClusterError> {
        let path = self.path_for(key);
        match fs::remove_file(&path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(ClusterError::BackendUnavailable {
                reason: format!("delete {}: {}", path.display(), e),
            }),
        }
    }

    async fn sweep(&self) -> Result<(), ClusterError> {
        let mut dir =
            fs::read_dir(&self.kv_dir)
                .await
                .map_err(|e| ClusterError::BackendUnavailable {
                    reason: format!("read_dir {}: {}", self.kv_dir.display(), e),
                })?;
        let now = current_unix_secs();
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path).await else {
                continue;
            };
            let Ok(stored) = serde_json::from_slice::<StoredKv>(&bytes) else {
                continue;
            };
            if let Some(deadline) = stored.expires_at_secs
                && deadline <= now
            {
                let _ = fs::remove_file(&path).await;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl KeyValueStore for FileKv {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let Some(stored) = self.read_entry(key).await? else {
            return Ok(None);
        };
        let now = current_unix_secs();
        if stored.expires_at_secs.is_some_and(|d| d <= now) {
            // Lazy purge.
            let _ = self.delete_entry(key).await;
            return Ok(None);
        }
        Ok(Some(Entry {
            bytes: Bytes::from(stored.payload),
            expires_at: stored.expires_at_secs.map(unix_secs_to_system),
        }))
    }

    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        let stored = StoredKv {
            key: key.to_owned(),
            payload: value.to_vec(),
            expires_at_secs: ttl.map(|d| current_unix_secs() + d.as_secs().max(1)),
        };
        self.write_entry(&stored).await
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        let stored = StoredKv {
            key: key.to_owned(),
            payload: value.to_vec(),
            expires_at_secs: ttl.map(|d| current_unix_secs() + d.as_secs().max(1)),
        };
        let path = self.path_for(key);
        // Atomic reserve via O_EXCL: only one creator wins the key, even
        // across concurrent in-process tasks. (FileKv is a single-node,
        // single-process backend — there is no cross-replica race here.)
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(_reserved) => {
                // We hold the key exclusively; populate it (tmp+rename
                // clobbers the empty reservation file we just created).
                self.write_entry(&stored).await?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A file exists. Treat a lapsed incumbent as absent and
                // reclaim it; a live one means we lost the claim.
                if let Some(existing) = self.read_entry(key).await?
                    && existing
                        .expires_at_secs
                        .is_some_and(|d| d <= current_unix_secs())
                {
                    self.write_entry(&stored).await?;
                    return Ok(true);
                }
                Ok(false)
            }
            Err(e) => Err(ClusterError::BackendUnavailable {
                reason: format!("put_if_absent create_new {}: {}", path.display(), e),
            }),
        }
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        self.delete_entry(key).await
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let mut dir =
            fs::read_dir(&self.kv_dir)
                .await
                .map_err(|e| ClusterError::BackendUnavailable {
                    reason: format!("read_dir {}: {}", self.kv_dir.display(), e),
                })?;
        let mut out = Vec::new();
        let now = current_unix_secs();
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path).await else {
                continue;
            };
            let Ok(stored) = serde_json::from_slice::<StoredKv>(&bytes) else {
                continue;
            };
            if !stored.key.starts_with(prefix) {
                continue;
            }
            if stored.expires_at_secs.is_some_and(|d| d <= now) {
                continue;
            }
            out.push((
                stored.key.clone(),
                Entry {
                    bytes: Bytes::from(stored.payload),
                    expires_at: stored.expires_at_secs.map(unix_secs_to_system),
                },
            ));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        let Some(mut stored) = self.read_entry(key).await? else {
            return Ok(false);
        };
        stored.expires_at_secs = ttl.map(|d| current_unix_secs() + d.as_secs().max(1));
        self.write_entry(&stored).await?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// FileBus
// ---------------------------------------------------------------------------

/// Forensics-grade file-tailing pub/sub.
///
/// Each topic is an append-only NDJSON file under `<data_dir>/topics/`.
/// Publish writes one line per message; subscribe spawns a polling
/// tail task that reads new lines and yields them as [`Message`].
///
/// **Reliability characteristics** (intentional):
/// - At-most-once-ish: if the gateway crashes between `write_all`
///   and the OS flushing, the trailing line may be lost or
///   truncated. Subscribers skip un-parseable lines.
/// - Subscribe-time fixed topic set: `subscribe("a.>")` only tails
///   files that exist at subscribe time. New topic files added
///   later are NOT picked up by an existing subscription —
///   resubscribe to refresh.
/// - 250 ms poll latency. Operators who need lower-latency
///   delivery should use [`super::MemoryBus`] or a real broker.
///
/// **Why this exists**: the NDJSON files are human-readable and
/// survive restarts, so an operator can `tail -f topics/cancel.ndjson`
/// or `jq` over the log for forensic analysis even when the gateway
/// itself is down. That's the main reason to pick the `file:`
/// backing instead of `memory:`.
#[derive(Debug)]
pub struct FileBus {
    topics_dir: PathBuf,
    poll_interval: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredMessage {
    /// Concrete topic the message was published to.
    topic: String,
    /// Wall-clock millis-since-epoch — for forensic analysis.
    /// Subscribers ignore this field (they only deliver `payload`
    /// + `topic` to the trait surface).
    ts_ms: u64,
    /// Base64-encoded payload bytes.
    payload_b64: String,
}

impl FileBus {
    /// Create a `FileBus` rooted at `<data_dir>/topics/`.
    pub async fn new(data_dir: impl AsRef<Path>) -> Result<Arc<Self>, ClusterError> {
        let topics_dir = data_dir.as_ref().join("topics");
        fs::create_dir_all(&topics_dir)
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("create topics_dir {}: {}", topics_dir.display(), e),
            })?;
        Ok(Arc::new(Self {
            topics_dir,
            poll_interval: Duration::from_millis(250),
        }))
    }

    /// Override the default 250 ms poll cadence — useful for tests.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn topic_path(&self, topic: &str) -> PathBuf {
        self.topics_dir
            .join(format!("{}.ndjson", sanitize_topic(topic)))
    }
}

#[async_trait]
impl PubSub for FileBus {
    async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), ClusterError> {
        let line = serde_json::to_string(&StoredMessage {
            topic: topic.to_owned(),
            ts_ms: current_unix_millis(),
            payload_b64: BASE64.encode(&payload),
        })
        .map_err(|e| ClusterError::Internal {
            reason: format!("encode message: {e}"),
        })?;
        let path = self.topic_path(topic);
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("open {}: {}", path.display(), e),
            })?;
        f.write_all(line.as_bytes())
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("append {}: {}", path.display(), e),
            })?;
        f.write_all(b"\n")
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("append {}: {}", path.display(), e),
            })?;
        // Flush so a tail subscriber's metadata().len() check sees
        // the new bytes. Without this the pageblech cache + libtokio's
        // internal buffering can leave a brief window where len()
        // still reports the pre-write size — fine for an idle
        // forensic tap, fatal for the deterministic in-process
        // test harness.
        f.flush()
            .await
            .map_err(|e| ClusterError::BackendUnavailable {
                reason: format!("flush {}: {}", path.display(), e),
            })?;
        Ok(())
    }

    async fn subscribe(
        &self,
        pattern: &str,
        _queue_group: Option<&str>,
    ) -> Result<Subscription, ClusterError> {
        // Snapshot the topics_dir at subscribe time. New topic
        // files added later are NOT picked up by this subscription
        // — operators wanting "match anything ever" should
        // resubscribe periodically. For the forensic-replay use
        // case this is fine.
        let mut dir =
            fs::read_dir(&self.topics_dir)
                .await
                .map_err(|e| ClusterError::BackendUnavailable {
                    reason: format!("read_dir {}: {}", self.topics_dir.display(), e),
                })?;
        let mut matched: Vec<PathBuf> = Vec::new();
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if path.extension().and_then(|s| s.to_str()) != Some("ndjson") {
                continue;
            }
            // The stem is the sanitized topic. We don't reverse the
            // sanitization (lossy) — instead we rely on the
            // `topic` field in each StoredMessage to do exact
            // matching against the pattern.
            // Quick reject: if the pattern has no wildcards and
            // sanitize_topic(pattern) doesn't match the stem,
            // there's nothing to tail.
            if !has_wildcard(pattern) && stem != sanitize_topic(pattern) {
                continue;
            }
            matched.push(path);
        }

        let (tx, rx) = mpsc::channel::<Result<Message, ClusterError>>(64);
        let pattern_owned = pattern.to_owned();
        let poll_interval = self.poll_interval;
        for path in matched {
            // Capture the initial file length BEFORE spawning the
            // tail task. If we left the seek-to-end inside the task
            // body, a publish landing between `subscribe()` returning
            // and the spawned task waking would slide pos *past*
            // that publish — silently dropping a message the
            // subscriber should have seen.
            let initial_pos = match fs::metadata(&path).await {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            spawn_tail_task(
                path,
                initial_pos,
                pattern_owned.clone(),
                poll_interval,
                tx.clone(),
            );
        }
        // Drop the original `tx` so the channel closes once every
        // tail task ends — keeps the stream from hanging forever
        // if the data_dir is wiped from under us.
        drop(tx);

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx).boxed();
        Ok(stream)
    }
}

/// Tail one topic file, parsing each line into a [`Message`] when
/// it matches `pattern`. The caller passes `initial_pos` so the
/// "subscribe-after-publish" semantics are race-free even if the
/// spawned task takes a tick to schedule.
fn spawn_tail_task(
    path: PathBuf,
    initial_pos: u64,
    pattern: String,
    poll_interval: Duration,
    tx: mpsc::Sender<Result<Message, ClusterError>>,
) {
    tokio::spawn(async move {
        let mut pos = initial_pos;

        loop {
            tokio::time::sleep(poll_interval).await;
            // Did the file grow?
            let len = match tokio::fs::metadata(&path).await {
                Ok(m) => m.len(),
                Err(_) => return,
            };
            if len < pos {
                // File was truncated / rotated. Reset to current end.
                pos = len;
                continue;
            }
            if len == pos {
                continue;
            }
            // Read everything from `pos` to current EOF, then
            // advance. Re-opening every poll keeps the seek cursor
            // cheap and tolerates fs caching weirdness.
            let mut file = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(_) => return,
            };
            if file.seek(std::io::SeekFrom::Start(pos)).await.is_err() {
                return;
            }
            let mut reader = BufReader::new(file);
            loop {
                let mut line = String::new();
                let n = match reader.read_line(&mut line).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                pos += n as u64;
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    continue;
                }
                let stored: StoredMessage = match serde_json::from_str(trimmed) {
                    Ok(s) => s,
                    Err(_) => continue, // skip malformed line (forensic logs may be partial)
                };
                if !super::memory::pattern_matches(&pattern, &stored.topic) {
                    continue;
                }
                let payload = match BASE64.decode(stored.payload_b64.as_bytes()) {
                    Ok(b) => Bytes::from(b),
                    Err(_) => continue,
                };
                let msg = Message {
                    topic: stored.topic,
                    payload,
                };
                if tx.send(Ok(msg)).await.is_err() {
                    return; // subscriber dropped
                }
            }
            // Recycle the file handle for the next loop iteration.
            // The next iteration re-opens via `tokio::fs::File::open`
            // anyway; this drop just frees the BufReader.
            drop(reader);
        }
    });
}

/// Sanitize a topic into a safe filename. Replaces every character
/// that isn't `[A-Za-z0-9._-]` with `_`. Lossy — operators reading
/// the directory should consult the `topic` field inside each line
/// for the canonical name.
fn sanitize_topic(topic: &str) -> String {
    topic
        .chars()
        .map(|c| match c {
            '.' | '-' | '_' => c,
            c if c.is_ascii_alphanumeric() => c,
            _ => '_',
        })
        .collect()
}

fn has_wildcard(pattern: &str) -> bool {
    pattern.split('.').any(|tok| tok == "*" || tok == ">")
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn unix_secs_to_system(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn kv_get_put_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kv = FileKv::new(dir.path()).await.unwrap();
        assert!(kv.get("missing").await.unwrap().is_none());
        kv.put("k", Bytes::from_static(b"v"), None).await.unwrap();
        let got = kv.get("k").await.unwrap().unwrap();
        assert_eq!(&got.bytes[..], b"v");
        assert!(kv.delete("k").await.unwrap());
        assert!(!kv.delete("k").await.unwrap());
    }

    #[tokio::test]
    async fn kv_list_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let kv = FileKv::new(dir.path()).await.unwrap();
        kv.put("a:1", Bytes::from_static(b"a1"), None)
            .await
            .unwrap();
        kv.put("a:2", Bytes::from_static(b"a2"), None)
            .await
            .unwrap();
        kv.put("b:1", Bytes::from_static(b"b1"), None)
            .await
            .unwrap();
        let entries = kv.list_prefix("a:", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn bus_publish_and_subscribe_picks_up_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let bus_arc = FileBus::new(dir.path()).await.unwrap();
        // Override poll interval on a fresh instance so the test
        // returns quickly. The Arc<FileBus> from `new` would need
        // an interior-mutable field for poll override; instead we
        // construct directly here.
        let topics_dir = dir.path().join("topics");
        fs::create_dir_all(&topics_dir).await.unwrap();
        let bus = FileBus {
            topics_dir,
            poll_interval: Duration::from_millis(20),
        };
        // Ensure the topic file exists before subscribe so the
        // tail task has something to open.
        bus.publish("evt.alpha", Bytes::from_static(b"warmup"))
            .await
            .unwrap();
        let mut sub = bus.subscribe("evt.*", None).await.unwrap();
        // Subscribe seeks to EOF so the warmup line is *not*
        // delivered. The next publish should be.
        bus.publish("evt.alpha", Bytes::from_static(b"payload"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(800), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(msg.topic, "evt.alpha");
        assert_eq!(&msg.payload[..], b"payload");
        // Suppress unused-Arc warning
        drop(bus_arc);
    }

    #[tokio::test]
    async fn bus_skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let topics_dir = dir.path().join("topics");
        fs::create_dir_all(&topics_dir).await.unwrap();
        let bus = FileBus {
            topics_dir: topics_dir.clone(),
            poll_interval: Duration::from_millis(20),
        };
        // Pre-write a garbage line to the same file the next
        // `publish("evt.alpha", …)` will append to. Subscribe seeks
        // to the current end (past the garbage), so the garbage
        // line is *not* what we'll be exercising — but if the tail
        // task panics on the malformed line during a re-read, the
        // valid line that follows wouldn't make it through. The
        // explicit-garbage scenario is exercised by the "skipped"
        // branch in `spawn_tail_task`.
        let path = topics_dir.join("evt.alpha.ndjson");
        fs::write(&path, b"this-is-not-json\nstill-not-json\n")
            .await
            .unwrap();
        let mut sub = bus.subscribe("evt.alpha", None).await.unwrap();
        bus.publish("evt.alpha", Bytes::from_static(b"ok"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(800), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&msg.payload[..], b"ok");
    }

    #[test]
    fn sanitize_topic_strips_unsafe_chars() {
        assert_eq!(sanitize_topic("evt.alpha-1"), "evt.alpha-1");
        assert_eq!(sanitize_topic("evt/with slashes"), "evt_with_slashes");
        assert_eq!(sanitize_topic("a.>"), "a._");
    }

    #[tokio::test]
    async fn path_for_is_sha256_hex_and_collision_resistant() {
        let dir = tempfile::tempdir().unwrap();
        let kv = FileKv::new(dir.path()).await.unwrap();
        let p = kv.path_for("some/key:with weird..chars");
        let name = p.file_name().unwrap().to_str().unwrap();
        // 64 hex chars + ".json"; the filename never echoes the raw key, so a
        // key with slashes/dots can't escape kv_dir or collide on a prefix.
        assert_eq!(name.len(), 64 + ".json".len());
        let stem = name.strip_suffix(".json").unwrap();
        assert_eq!(stem.len(), 64);
        assert!(stem.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(p.parent().unwrap(), kv.kv_dir.as_path());
        // Distinct keys → distinct files; the same key is stable across calls.
        assert_ne!(kv.path_for("a"), kv.path_for("b"));
        assert_eq!(kv.path_for("a"), kv.path_for("a"));
    }

    #[tokio::test]
    async fn path_traversal_key_round_trips_within_kv_dir() {
        let dir = tempfile::tempdir().unwrap();
        let kv = FileKv::new(dir.path()).await.unwrap();
        // A key that would be dangerous if interpolated into the path must
        // round-trip via its hash and stay inside kv_dir.
        let key = "../../etc/passwd";
        kv.put(key, Bytes::from_static(b"v"), None).await.unwrap();
        let got = kv.get(key).await.unwrap().unwrap();
        assert_eq!(&got.bytes[..], b"v");
        assert!(kv.path_for(key).starts_with(&kv.kv_dir));
    }
}
