//! In-process `KeyValueStore` + `PubSub` primitive impls.
//!
//! Used by the single-node cluster built-in when no `dir:` is configured.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::StreamExt;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore, Message, PubSub, Subscription};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// MemoryKv
// ---------------------------------------------------------------------------

/// In-process key/value store backed by a sharded `DashMap`.
///
/// TTL semantics: `put`/`expire` record a deadline (`Instant`).
/// Lookups check the deadline lazily; expired entries are removed
/// on touch. A background sweeper (started by [`MemoryKv::with_sweep`])
/// periodically scans and drops expired entries so the map size
/// reflects live state — handy for `list_prefix` to avoid leaking
/// dead keys to callers.
#[derive(Debug, Default)]
pub struct MemoryKv {
    inner: Arc<DashMap<String, StoredEntry>>,
}

#[derive(Debug, Clone)]
struct StoredEntry {
    bytes: Bytes,
    /// Wall-clock SystemTime for the trait surface (Entry.expires_at).
    expires_system: Option<SystemTime>,
    /// Monotonic Instant for purge logic (insulated from clock jumps).
    expires_instant: Option<Instant>,
}

impl StoredEntry {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_instant.is_some_and(|d| d <= now)
    }
}

impl MemoryKv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a background sweeper that drops expired entries every
    /// `interval`. Returns the same instance for chaining; the task
    /// holds an `Arc` of the inner map and exits when the last
    /// strong reference is dropped.
    pub fn with_sweep(self, interval: Duration) -> Self {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                if Arc::strong_count(&inner) == 1 {
                    break; // owner dropped; nothing else holds the map
                }
                let now = Instant::now();
                inner.retain(|_, e| !e.is_expired(now));
            }
        });
        self
    }
}

#[async_trait]
impl KeyValueStore for MemoryKv {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let now = Instant::now();
        match self.inner.get(key) {
            Some(entry) => {
                if entry.is_expired(now) {
                    drop(entry);
                    self.inner.remove(key);
                    Ok(None)
                } else {
                    Ok(Some(Entry {
                        bytes: entry.bytes.clone(),
                        expires_at: entry.expires_system,
                    }))
                }
            }
            None => Ok(None),
        }
    }

    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        let (expires_system, expires_instant) = compute_deadline(ttl);
        self.inner.insert(
            key.to_owned(),
            StoredEntry {
                bytes: value,
                expires_system,
                expires_instant,
            },
        );
        Ok(())
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        use dashmap::mapref::entry::Entry as DmEntry;
        let now = Instant::now();
        let (expires_system, expires_instant) = compute_deadline(ttl);
        // Compare-and-insert under the shard lock the `entry` API holds —
        // atomic against concurrent in-process callers. An expired
        // incumbent is treated as absent and overwritten.
        let inserted = match self.inner.entry(key.to_owned()) {
            DmEntry::Occupied(mut occ) if occ.get().is_expired(now) => {
                occ.insert(StoredEntry {
                    bytes: value,
                    expires_system,
                    expires_instant,
                });
                true
            }
            DmEntry::Occupied(_) => false,
            DmEntry::Vacant(vac) => {
                vac.insert(StoredEntry {
                    bytes: value,
                    expires_system,
                    expires_instant,
                });
                true
            }
        };
        Ok(inserted)
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        Ok(self.inner.remove(key).is_some())
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let now = Instant::now();
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            if !entry.key().starts_with(prefix) {
                continue;
            }
            if entry.is_expired(now) {
                continue;
            }
            out.push((
                entry.key().clone(),
                Entry {
                    bytes: entry.bytes.clone(),
                    expires_at: entry.expires_system,
                },
            ));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        let (expires_system, expires_instant) = compute_deadline(ttl);
        match self.inner.get_mut(key) {
            Some(mut entry) => {
                entry.expires_system = expires_system;
                entry.expires_instant = expires_instant;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn incr(
        &self,
        key: &str,
        delta: i64,
        ttl: Option<Duration>,
    ) -> Result<i64, ClusterError> {
        use dashmap::mapref::entry::Entry as DmEntry;
        let now = Instant::now();
        // Read-add-write under the shard lock the `entry` API holds —
        // atomic against concurrent in-process callers. An expired
        // incumbent restarts the counter at 0.
        match self.inner.entry(key.to_owned()) {
            DmEntry::Occupied(mut occ) => {
                let live = !occ.get().is_expired(now);
                let current = if live {
                    mcpg_cluster_api::parse_counter(&occ.get().bytes)?
                } else {
                    0
                };
                let next = current
                    .checked_add(delta)
                    .ok_or_else(mcpg_cluster_api::counter_overflow)?;
                let (expires_system, expires_instant) = if ttl.is_some() {
                    compute_deadline(ttl)
                } else if live {
                    // ttl=None leaves an existing expiry untouched.
                    (occ.get().expires_system, occ.get().expires_instant)
                } else {
                    (None, None)
                };
                occ.insert(StoredEntry {
                    bytes: Bytes::from(next.to_string()),
                    expires_system,
                    expires_instant,
                });
                Ok(next)
            }
            DmEntry::Vacant(vac) => {
                let (expires_system, expires_instant) = compute_deadline(ttl);
                vac.insert(StoredEntry {
                    bytes: Bytes::from(delta.to_string()),
                    expires_system,
                    expires_instant,
                });
                Ok(delta)
            }
        }
    }
}

fn compute_deadline(ttl: Option<Duration>) -> (Option<SystemTime>, Option<Instant>) {
    match ttl {
        Some(d) => {
            let inst = Instant::now() + d;
            let sys = SystemTime::now() + d;
            (Some(sys), Some(inst))
        }
        None => (None, None),
    }
}

// ---------------------------------------------------------------------------
// MemoryBus
// ---------------------------------------------------------------------------

/// In-process topic bus.
///
/// Each topic gets its own `tokio::sync::broadcast::Sender`,
/// created on first publish/subscribe. Subscribers receive every
/// message published *after* their `subscribe` call (no replay of
/// past messages). Slow subscribers that lag the channel buffer
/// observe a `Lagged` error — the impl converts these to a
/// terminal `ClusterError::BackendUnavailable` on the stream so
/// callers can resubscribe to recover.
///
/// Wildcards (`*`, `>`) are supported: `subscribe("a.*")` matches
/// `a.foo` but not `a.foo.bar`; `subscribe("a.>")` matches both.
/// Queue groups are ignored — there's no cross-replica fan-out
/// in-process to balance, so every subscriber gets every message.
#[derive(Debug, Default)]
pub struct MemoryBus {
    /// Per-pattern broadcast channels. Sized at 256 by default;
    /// override via [`MemoryBus::with_capacity`].
    senders: Arc<DashMap<String, broadcast::Sender<Bytes>>>,
    capacity: usize,
}

impl MemoryBus {
    pub fn new() -> Self {
        Self {
            senders: Arc::new(DashMap::new()),
            capacity: 256,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            senders: Arc::new(DashMap::new()),
            capacity,
        }
    }

    fn sender_for(&self, topic: &str) -> broadcast::Sender<Bytes> {
        self.senders
            .entry(topic.to_owned())
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .clone()
    }
}

#[async_trait]
impl PubSub for MemoryBus {
    async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), ClusterError> {
        // Iterate every existing channel that matches `topic`. For
        // an in-process bus, we treat the publish topic as concrete
        // and the subscribed topic as the pattern — so we lookup
        // every channel whose subscribed pattern matches `topic`.
        // Channels are keyed by *subscribed pattern* — linear scan;
        // for a small number of patterns (< 100) this is fine.
        for entry in self.senders.iter() {
            if pattern_matches(entry.key(), topic) {
                // Best-effort send; ignore RecvError::Closed (no
                // active subscribers).
                let _ = entry.value().send(payload.clone());
            }
        }
        // Even if no subscriber is listening, publish is Ok — the
        // contract is fire-and-forget.
        Ok(())
    }

    async fn subscribe(
        &self,
        pattern: &str,
        _queue_group: Option<&str>,
    ) -> Result<Subscription, ClusterError> {
        let sender = self.sender_for(pattern);
        let receiver = sender.subscribe();
        let pattern_owned = pattern.to_owned();
        let stream =
            tokio_stream::wrappers::BroadcastStream::new(receiver).map(move |item| match item {
                Ok(payload) => Ok(Message {
                    topic: pattern_owned.clone(),
                    payload,
                }),
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    Err(ClusterError::BackendUnavailable {
                        reason: format!(
                            "subscriber lagged by {n} messages; resubscribe to recover"
                        ),
                    })
                }
            });
        Ok(Box::pin(stream))
    }
}

/// True iff `pattern` matches `topic`. Tokens are split on `.`.
/// `*` matches any single token; `>` matches one-or-more tokens
/// (only valid as the trailing element).
pub(super) fn pattern_matches(pattern: &str, topic: &str) -> bool {
    let pat: Vec<&str> = pattern.split('.').collect();
    let top: Vec<&str> = topic.split('.').collect();
    let mut pi = 0;
    let mut ti = 0;
    while pi < pat.len() && ti < top.len() {
        let p = pat[pi];
        if p == ">" {
            return pi == pat.len() - 1;
        }
        if p != "*" && p != top[ti] {
            return false;
        }
        pi += 1;
        ti += 1;
    }
    pi == pat.len() && ti == top.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn kv_get_put_delete() {
        let kv = MemoryKv::new();
        assert!(kv.get("k").await.unwrap().is_none());
        kv.put("k", Bytes::from_static(b"v"), None).await.unwrap();
        let got = kv.get("k").await.unwrap().unwrap();
        assert_eq!(&got.bytes[..], b"v");
        assert!(kv.delete("k").await.unwrap());
        assert!(!kv.delete("k").await.unwrap());
    }

    #[tokio::test]
    async fn kv_put_if_absent_single_winner() {
        // Atomic claim. First wins, second loses without
        // overwriting; an expired entry is reclaimable; a delete frees
        // the slot.
        let kv = MemoryKv::new();
        assert!(
            kv.put_if_absent("c", Bytes::from_static(b"a"), None)
                .await
                .unwrap(),
            "first claim wins"
        );
        assert!(
            !kv.put_if_absent("c", Bytes::from_static(b"b"), None)
                .await
                .unwrap(),
            "second claim loses"
        );
        assert_eq!(&kv.get("c").await.unwrap().unwrap().bytes[..], b"a");

        // Expired incumbent counts as absent → reclaimable.
        kv.put(
            "e",
            Bytes::from_static(b"old"),
            Some(Duration::from_millis(20)),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            kv.put_if_absent("e", Bytes::from_static(b"new"), None)
                .await
                .unwrap(),
            "expired entry must be reclaimable"
        );
        assert_eq!(&kv.get("e").await.unwrap().unwrap().bytes[..], b"new");

        // Delete frees the slot for a fresh claim.
        assert!(kv.delete("c").await.unwrap());
        assert!(
            kv.put_if_absent("c", Bytes::from_static(b"z"), None)
                .await
                .unwrap(),
            "claim after delete wins"
        );
    }

    #[tokio::test]
    async fn kv_list_prefix_filters() {
        let kv = MemoryKv::new();
        kv.put("a:1", Bytes::from_static(b"1"), None).await.unwrap();
        kv.put("a:2", Bytes::from_static(b"2"), None).await.unwrap();
        kv.put("b:1", Bytes::from_static(b"3"), None).await.unwrap();
        let entries = kv.list_prefix("a:", 100).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn pub_sub_literal() {
        let bus = MemoryBus::new();
        let mut sub = bus.subscribe("a.b.c", None).await.unwrap();
        bus.publish("a.b.c", Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(500), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&msg.payload[..], b"hello");
    }

    #[tokio::test]
    async fn pub_sub_wildcard_single_token() {
        let bus = MemoryBus::new();
        let mut sub = bus.subscribe("a.*.c", None).await.unwrap();
        bus.publish("a.x.c", Bytes::from_static(b"x"))
            .await
            .unwrap();
        bus.publish("a.x.d", Bytes::from_static(b"miss"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(500), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&msg.payload[..], b"x");
    }

    #[tokio::test]
    async fn pub_sub_wildcard_trailing_chevron() {
        let bus = MemoryBus::new();
        let mut sub = bus.subscribe("a.>", None).await.unwrap();
        bus.publish("a.x.y.z", Bytes::from_static(b"deep"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(500), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&msg.payload[..], b"deep");
    }

    #[test]
    fn pattern_match_examples() {
        assert!(pattern_matches("a.b", "a.b"));
        assert!(!pattern_matches("a.b", "a.c"));
        assert!(pattern_matches("a.*", "a.foo"));
        assert!(!pattern_matches("a.*", "a.foo.bar"));
        assert!(pattern_matches("a.>", "a.foo"));
        assert!(pattern_matches("a.>", "a.foo.bar"));
        assert!(!pattern_matches("a.>", "b.foo"));
    }

    #[tokio::test]
    async fn kv_incr_counts_and_respects_expiry() {
        let kv = MemoryKv::new();
        assert_eq!(kv.incr("c", 5, None).await.unwrap(), 5);
        assert_eq!(kv.incr("c", -2, None).await.unwrap(), 3);
        assert_eq!(&kv.get("c").await.unwrap().unwrap().bytes[..], b"3");

        // A TTL'd counter left idle restarts at 0.
        kv.incr("t", 9, Some(Duration::from_millis(20)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(kv.incr("t", 1, None).await.unwrap(), 1);

        // Non-integer values refuse the incr and stay intact.
        kv.put("blob", Bytes::from_static(b"json{}"), None)
            .await
            .unwrap();
        assert!(kv.incr("blob", 1, None).await.is_err());
        assert_eq!(&kv.get("blob").await.unwrap().unwrap().bytes[..], b"json{}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn kv_incr_atomic_across_threads() {
        // Real OS-thread parallelism (the contract suite interleaves on
        // one task): 8 tasks × 100 increments must never lose a count.
        let kv = Arc::new(MemoryKv::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let kv = Arc::clone(&kv);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    kv.incr("c", 1, None).await.unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(kv.incr("c", 0, None).await.unwrap(), 800);
    }

    #[tokio::test]
    async fn kv_contract_battery() {
        mcpg_cluster_api::test_suite::run_kv_contract(|| async {
            Arc::new(MemoryKv::new()) as Arc<dyn KeyValueStore>
        })
        .await;
    }
}
