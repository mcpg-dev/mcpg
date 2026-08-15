//! Built-in `cache` plugin — `dev.mcpg.builtin.cache.memory`.
//!
//! The gateway's bundled `cache`. In-process DashMap-backed cache
//! with TTL lazy eviction + atomic `incr`.
//! Serves any operator-named namespace (`serves_any_namespace =
//! true`) — one instance covers `response-cache`, `jwks`,
//! `rate-limit`, and any custom namespace the operator wires up.
//!
//! # Scope
//!
//! Single-node. Process restart loses every cached value (which is
//! the point — "cache loss is always safe" per spec §9.9). Counter
//! values persisted via `incr` are similarly process-scoped — a
//! multi-node rate limiter MUST use a distributed backend
//! (Redis, NATS KV) instead.
//!
//! # TTL
//!
//! Honoured lazily: a key with expired TTL is filtered on read + the
//! entry is evicted. No background sweeper. Cold expired keys waste
//! bytes until something reads that key; in practice the
//! response-cache + JWKS namespaces cycle fast enough that this is
//! a non-issue.
//!
//! # Atomic `incr`
//!
//! Implemented via DashMap's entry API — `and_modify` inside the
//! shard lock is atomic on the counter load + bump + store. Returns
//! the value AFTER the increment. Initialises a missing key to
//! `by` (spec §9.9 contract). `ttl` sets the entry's expiry on
//! first access AND refreshes on every subsequent `incr` — the
//! refresh behaviour matches what rate-limiters expect (sliding
//! window with the TTL as the window size).

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    cache::{Cache, CacheError},
};

/// Descriptor shipped alongside the code. `FirstPartyRegistrar`
/// parses this at registration time + cross-checks against the
/// in-code manifest.
pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.cache.memory
name: Built-in In-Memory Cache
description: |
  Gateway-bundled cache: in-process DashMap-backed, TTL lazy
  eviction, atomic incr. Serves any operator-named namespace
  (response-cache / jwks / rate-limit / custom). Single-node, zero
  durability — which is fine for a cache. Production multi-node
  deployments swap in a distributed backend (Redis, NATS KV) for
  the rate-limit namespace; response-cache + jwks are safe
  per-node even at scale.
class: cache
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

#[derive(Debug, Clone)]
struct Entry {
    bytes: Option<bytes::Bytes>,
    /// `Some(x)` = counter with value `x`, used by `incr`. `None`
    /// means the entry is a plain `put` value (bytes above).
    counter: Option<i64>,
    expires_at: Instant,
}

impl Entry {
    fn is_live(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// The memory cache.
pub struct MemoryCache {
    manifest: PluginManifest,
    /// Per-namespace entries. Namespaces are allocated lazily on
    /// first access — the plugin does not need to know which
    /// namespaces the operator will bind it to.
    namespaces: DashMap<String, Arc<DashMap<String, Entry>>>,
}

impl MemoryCache {
    /// Build a fresh instance. No pre-allocated namespaces —
    /// lazy on first access.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.cache.memory".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in In-Memory Cache".into(),
                plugin_class: PluginClass::Cache,
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
            namespaces: DashMap::new(),
        })
    }

    fn ns(&self, ns: &str) -> Arc<DashMap<String, Entry>> {
        if let Some(existing) = self.namespaces.get(ns) {
            return Arc::clone(existing.value());
        }
        let new = Arc::new(DashMap::new());
        self.namespaces
            .entry(ns.to_owned())
            .or_insert_with(|| Arc::clone(&new));
        Arc::clone(self.namespaces.get(ns).expect("just inserted").value())
    }
}

#[mcpg_plugin_protocol::async_trait]
impl Cache for MemoryCache {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_namespaces(&self) -> Vec<String> {
        // Empty list + serves_any = true → accept any namespace
        // the operator binds. Generic KV backend pattern.
        vec![]
    }

    fn serves_any_namespace(&self) -> bool {
        true
    }

    async fn get(&self, ns: &str, key: &str) -> Option<bytes::Bytes> {
        let ns = self.ns(ns);
        let live_bytes = ns
            .get(key)
            .filter(|e| e.value().is_live())
            .and_then(|e| e.value().bytes.clone());
        if live_bytes.is_none() {
            // Lazy evict on miss. Racy with concurrent writers
            // but safe: a writer that reinserts between our read +
            // remove wins on the next read.
            ns.remove_if(key, |_, e| !e.is_live());
        }
        live_bytes
    }

    async fn put(
        &self,
        ns: &str,
        key: &str,
        value: bytes::Bytes,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let ns = self.ns(ns);
        ns.insert(
            key.to_owned(),
            Entry {
                bytes: Some(value),
                counter: None,
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn delete(&self, ns: &str, key: &str) {
        let ns = self.ns(ns);
        ns.remove(key);
    }

    async fn clear(&self, ns: &str) -> Result<(), CacheError> {
        let ns = self.ns(ns);
        ns.clear();
        Ok(())
    }

    async fn incr(&self, ns: &str, key: &str, by: i64, ttl: Duration) -> Result<i64, CacheError> {
        let ns = self.ns(ns);
        // DashMap's entry API gives us an atomic and_modify — the
        // counter load + bump + store happens inside the shard
        // lock. Rate-limit correctness requires this.
        let mut result = 0;
        ns.entry(key.to_owned())
            .and_modify(|entry| {
                if !entry.is_live() {
                    // Expired counter treated as "fresh init".
                    entry.counter = Some(by);
                    entry.expires_at = Instant::now() + ttl;
                } else {
                    let current = entry.counter.unwrap_or(0);
                    let new = current.saturating_add(by);
                    entry.counter = Some(new);
                    // Refresh TTL — sliding-window rate limit
                    // expectation.
                    entry.expires_at = Instant::now() + ttl;
                }
                result = entry.counter.unwrap_or(0);
            })
            .or_insert_with(|| {
                result = by;
                Entry {
                    bytes: None,
                    counter: Some(by),
                    expires_at: Instant::now() + ttl,
                }
            });
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_missing_returns_none() {
        let cache = MemoryCache::new();
        assert!(cache.get("jwks", "nope").await.is_none());
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let cache = MemoryCache::new();
        cache
            .put(
                "response-cache",
                "k",
                bytes::Bytes::from_static(b"v"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let v = cache.get("response-cache", "k").await.unwrap();
        assert_eq!(v.as_ref(), b"v");
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let cache = MemoryCache::new();
        cache
            .put(
                "ns",
                "k",
                bytes::Bytes::from_static(b"v"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        cache.delete("ns", "k").await;
        assert!(cache.get("ns", "k").await.is_none());
    }

    #[tokio::test]
    async fn clear_wipes_namespace() {
        let cache = MemoryCache::new();
        cache
            .put(
                "ns",
                "a",
                bytes::Bytes::from_static(b"1"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        cache
            .put(
                "ns",
                "b",
                bytes::Bytes::from_static(b"2"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        cache.clear("ns").await.unwrap();
        assert!(cache.get("ns", "a").await.is_none());
        assert!(cache.get("ns", "b").await.is_none());
    }

    #[tokio::test]
    async fn ttl_evicts_on_read() {
        let cache = MemoryCache::new();
        cache
            .put(
                "ns",
                "k",
                bytes::Bytes::from_static(b"v"),
                Duration::from_millis(20),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(cache.get("ns", "k").await.is_none());
    }

    #[tokio::test]
    async fn incr_starts_at_delta_for_missing_key() {
        let cache = MemoryCache::new();
        let v = cache
            .incr("rate-limit", "rps:user-1", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(v, 1);
    }

    #[tokio::test]
    async fn incr_accumulates_on_existing_key() {
        let cache = MemoryCache::new();
        for expected in 1..=5 {
            let v = cache
                .incr("rate-limit", "rps:user-1", 1, Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(v, expected);
        }
    }

    #[tokio::test]
    async fn incr_accepts_negative_delta() {
        let cache = MemoryCache::new();
        cache
            .incr("ns", "k", 10, Duration::from_secs(60))
            .await
            .unwrap();
        let v = cache
            .incr("ns", "k", -3, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(v, 7);
    }

    #[tokio::test]
    async fn incr_reinitialises_after_ttl_expiry() {
        let cache = MemoryCache::new();
        cache
            .incr("ns", "k", 5, Duration::from_millis(20))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let v = cache
            .incr("ns", "k", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(v, 1, "expired counter re-init to the delta");
    }

    #[tokio::test]
    async fn incr_is_atomic_under_concurrent_callers() {
        let cache = MemoryCache::new();
        let mut handles = Vec::new();
        for _ in 0..100 {
            let c = cache.clone();
            handles.push(tokio::spawn(async move {
                c.incr("ns", "k", 1, Duration::from_secs(60)).await.unwrap()
            }));
        }
        for h in handles {
            let _ = h.await.unwrap();
        }
        // Final value must be exactly 100 — a racy incr would
        // drop bumps and land below.
        let final_value = cache
            .incr("ns", "k", 0, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(final_value, 100);
    }

    #[tokio::test]
    async fn namespaces_are_isolated() {
        let cache = MemoryCache::new();
        cache
            .put(
                "a",
                "k",
                bytes::Bytes::from_static(b"from-a"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        cache
            .put(
                "b",
                "k",
                bytes::Bytes::from_static(b"from-b"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(cache.get("a", "k").await.unwrap().as_ref(), b"from-a");
        assert_eq!(cache.get("b", "k").await.unwrap().as_ref(), b"from-b");
    }

    #[test]
    fn serves_any_namespace_declared() {
        let cache = MemoryCache::new();
        assert!(cache.serves_any_namespace());
        assert!(cache.supported_namespaces().is_empty());
    }

    #[test]
    fn descriptor_yaml_parses_as_cache() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.cache.memory");
        assert_eq!(d.class, PluginClass::Cache);
    }
}
