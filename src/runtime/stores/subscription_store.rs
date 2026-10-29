//! Subscription store — tracks which sessions are subscribed to
//! which resource URIs for `notifications/resources/updated` delivery.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mcpg_cluster_api::{ClusterError, KeyValueStore};
use serde::{Deserialize, Serialize};

/// Identity context captured at subscribe time, used by the notification
/// filter to scope delivery to matching subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriberIdentity {
    pub session_id: String,
    pub principal_id: Option<String>,
    pub trust_level: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub attributes: BTreeMap<String, String>,
}

impl SubscriberIdentity {
    /// Snapshot the caller's identity for a subscription made on `session_id`.
    ///
    /// Both wires subscribe through this, so the filter sees the same shape
    /// whichever one the subscription came in on — `trust_level` in particular
    /// is a lowercased debug rendering the filter compares by string, which two
    /// independent builders would eventually disagree about.
    pub fn from_request_context(
        session_id: &str,
        request_context: &crate::runtime::RequestContext,
    ) -> Self {
        let identity = &request_context.identity;
        Self {
            session_id: session_id.to_owned(),
            principal_id: identity.principal_id().map(str::to_owned),
            trust_level: format!("{:?}", identity.trust_level()).to_ascii_lowercase(),
            roles: identity.roles().to_vec(),
            groups: identity.groups().to_vec(),
            scopes: identity.scopes().to_vec(),
            attributes: identity.attributes().clone(),
        }
    }
}

/// Error from subscription operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    /// The resource URI does not support subscriptions.
    NotSubscribable,
    /// Maximum subscriptions per session exceeded.
    LimitExceeded,
    /// Backend storage failure.
    BackendError(String),
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSubscribable => write!(f, "resource does not support subscriptions"),
            Self::LimitExceeded => write!(f, "subscription limit exceeded"),
            Self::BackendError(msg) => write!(f, "subscription store error: {msg}"),
        }
    }
}

/// Manages resource subscription state.
///
/// Tracks which sessions are subscribed to which resource URIs.
/// All operations are thread-safe (Mutex-guarded).
pub trait SubscriptionStore: Send + Sync + std::fmt::Debug {
    /// Subscribe a session to a resource URI. Returns Ok(()) if new, or if already subscribed.
    /// When `identity` is provided, it is stored alongside the subscription for
    /// subject-scoped notification filtering.
    fn subscribe(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Result<(), SubscriptionError>;

    /// Unsubscribe a session from a resource URI. Returns Ok(true) if was subscribed.
    fn unsubscribe(&self, session_id: &str, uri: &str) -> Result<bool, SubscriptionError>;

    /// Get all session IDs subscribed to a URI.
    fn subscribers_for(&self, uri: &str) -> Vec<String>;

    /// Get all subscribers with their identity context for a URI.
    /// Used by the notification filter to scope delivery.
    fn subscribers_with_identity(&self, uri: &str) -> Vec<(String, Option<SubscriberIdentity>)>;

    /// Get all URIs a session is subscribed to.
    fn subscriptions_for_session(&self, session_id: &str) -> Vec<String>;

    /// Clear all subscriptions for a session (called on session termination).
    fn clear_session(&self, session_id: &str);

    /// Total subscription count (for metrics).
    fn total_subscriptions(&self) -> usize;

    /// [`Self::subscribe`] for a subscription that lives as long as
    /// `holder` (a watch-engine member id), not as long as the session: the
    /// watch engine removes the row once the holder has left the fleet.
    fn subscribe_held(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
        holder: &str,
    ) -> Result<(), SubscriptionError> {
        let _ = holder;
        self.subscribe(session_id, uri, identity)
    }

    /// The fleet-wide watch state kept beside the rows, when this store
    /// keeps one.
    fn watch_state(&self) -> Option<WatchState> {
        None
    }
}

// ---------------------------------------------------------------------------
// Key layout, shared by the rows and the watch state
// ---------------------------------------------------------------------------

/// Rows keyed by URI, the index the fan-out reads.
const URI_PREFIX: &str = "sub:u:";
/// Demand markers: one per URI that has at least one subscriber.
const DEMAND_PREFIX: &str = "sub:w:";
/// Content hash of the last poll of a URI.
const BASELINE_PREFIX: &str = "sub:b:";
/// Liveness of a watch-engine member.
const MEMBER_PREFIX: &str = "sub:m:";
/// A poll baseline outlives a watcher that moves to another replica, and
/// no longer than this once no watcher writes it.
const BASELINE_TTL: Duration = Duration::from_secs(3 * 3600);

fn enc(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn dec(s: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

fn session_key(session_id: &str, uri: &str) -> String {
    format!("sub:s:{session_id}:{}", enc(uri))
}

fn uri_key(uri: &str, session_id: &str) -> String {
    format!("{URI_PREFIX}{}:{session_id}", enc(uri))
}

fn session_prefix(session_id: &str) -> String {
    format!("sub:s:{session_id}:")
}

fn uri_prefix(uri: &str) -> String {
    format!("{URI_PREFIX}{}:", enc(uri))
}

fn demand_key(uri: &str) -> String {
    format!("{DEMAND_PREFIX}{}", enc(uri))
}

fn baseline_key(uri: &str) -> String {
    format!("{BASELINE_PREFIX}{}", enc(uri))
}

fn member_key(member: &str) -> String {
    format!("{MEMBER_PREFIX}{member}")
}

/// A row's value: the subscriber's identity, plus the holder of a
/// subscription a stream holds. Readers that predate the holder decode the
/// identity and ignore it.
fn row_value(
    identity: &Option<SubscriberIdentity>,
    holder: Option<&str>,
) -> Result<Bytes, SubscriptionError> {
    let encode = |e: serde_json::Error| SubscriptionError::BackendError(format!("encode row: {e}"));
    let mut value = serde_json::to_value(identity).map_err(encode)?;
    if let Some(holder) = holder {
        match value.as_object_mut() {
            Some(object) => {
                object.insert("holder".to_owned(), holder.into());
            }
            None => value = serde_json::json!({ "holder": holder }),
        }
    }
    serde_json::to_vec(&value).map(Bytes::from).map_err(encode)
}

fn row_identity(bytes: &[u8]) -> Option<SubscriberIdentity> {
    serde_json::from_slice::<Option<SubscriberIdentity>>(bytes)
        .ok()
        .flatten()
}

fn row_holder(bytes: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Holder {
        holder: Option<String>,
    }
    serde_json::from_slice::<Option<Holder>>(bytes)
        .ok()
        .flatten()
        .and_then(|h| h.holder)
}

async fn has_subscribers(kv: &dyn KeyValueStore, uri: &str) -> Result<bool, ClusterError> {
    Ok(!kv.list_prefix(&uri_prefix(uri), 1).await?.is_empty())
}

/// Remove the demand marker of `uri` when no row is left under it.
///
/// A subscribe writes its row before its marker, so a row seen after the
/// delete may belong to a subscribe whose marker the delete just removed:
/// the marker is then written again.
async fn drop_demand_if_unsubscribed(
    kv: &dyn KeyValueStore,
    uri: &str,
) -> Result<bool, ClusterError> {
    if has_subscribers(kv, uri).await? {
        return Ok(false);
    }
    kv.delete(&demand_key(uri)).await?;
    if has_subscribers(kv, uri).await? {
        kv.put(&demand_key(uri), Bytes::from_static(b"1"), None)
            .await?;
        return Ok(false);
    }
    Ok(true)
}

/// One subscription row, as the watch engine's collector reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchRow {
    pub session_id: String,
    /// The member whose stream holds the subscription; `None` for one that
    /// lives as long as its session.
    pub holder: Option<String>,
}

/// The fleet-wide state of resource watching, in the subscription store's
/// KV: which URIs have subscribers, the last poll of each, and which
/// watch-engine members are alive.
#[derive(Clone)]
pub struct WatchState {
    kv: Arc<dyn KeyValueStore>,
}

impl std::fmt::Debug for WatchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchState").finish_non_exhaustive()
    }
}

impl WatchState {
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Self {
        Self { kv }
    }

    /// Every URI with a demand marker.
    pub async fn demanded(&self) -> Result<Vec<String>, ClusterError> {
        Ok(mcpg_cluster_api::list_all(&*self.kv, DEMAND_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(key, _)| key.strip_prefix(DEMAND_PREFIX).and_then(dec))
            .collect())
    }

    pub async fn has_demand(&self, uri: &str) -> Result<bool, ClusterError> {
        Ok(self.kv.get(&demand_key(uri)).await?.is_some())
    }

    /// Write the demand marker of `uri` again; a subscriber this replica
    /// holds makes it true.
    pub async fn assert_demand(&self, uri: &str) -> Result<(), ClusterError> {
        self.kv
            .put(&demand_key(uri), Bytes::from_static(b"1"), None)
            .await
    }

    /// Remove the demand marker of `uri` when no row is left under it.
    /// Returns whether it was removed.
    pub async fn drop_demand_if_unsubscribed(&self, uri: &str) -> Result<bool, ClusterError> {
        drop_demand_if_unsubscribed(&*self.kv, uri).await
    }

    /// Every subscription row of `uri`.
    pub async fn rows(&self, uri: &str) -> Result<Vec<WatchRow>, ClusterError> {
        let prefix = uri_prefix(uri);
        Ok(mcpg_cluster_api::list_all(&*self.kv, &prefix)
            .await?
            .into_iter()
            .filter_map(|(key, entry)| {
                Some(WatchRow {
                    session_id: key.strip_prefix(&prefix)?.to_owned(),
                    holder: row_holder(&entry.bytes),
                })
            })
            .collect())
    }

    /// Write the demand marker of every URI that has a row and no marker:
    /// rows an older build wrote, or a subscribe whose replica stopped
    /// between its row and its marker. Returns how many it wrote.
    pub async fn backfill_demand(&self) -> Result<usize, ClusterError> {
        let mut subscribed = std::collections::HashSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .kv
                .list_page(
                    URI_PREFIX,
                    cursor.as_deref(),
                    mcpg_cluster_api::LIST_PAGE_SIZE,
                )
                .await?;
            for (key, _) in page.entries {
                let Some(rest) = key.strip_prefix(URI_PREFIX) else {
                    continue;
                };
                if let Some(uri) = rest.split_once(':').and_then(|(encoded, _)| dec(encoded)) {
                    subscribed.insert(uri);
                }
            }
            match page.next {
                Some(next) if cursor.as_deref() != Some(next.as_str()) => cursor = Some(next),
                _ => break,
            }
        }
        let demanded: std::collections::HashSet<String> =
            self.demanded().await?.into_iter().collect();
        let mut written = 0;
        for uri in subscribed.difference(&demanded) {
            // The rows may have gone since the listing.
            if has_subscribers(&*self.kv, uri).await? {
                self.assert_demand(uri).await?;
                written += 1;
            }
        }
        Ok(written)
    }

    /// Remove the row of `session_id` on `uri` from both indices.
    pub async fn remove_row(&self, session_id: &str, uri: &str) -> Result<(), ClusterError> {
        self.kv.delete(&uri_key(uri, session_id)).await?;
        self.kv.delete(&session_key(session_id, uri)).await?;
        Ok(())
    }

    /// SHA-256 of the last poll of `uri`, as the last watcher left it.
    pub async fn baseline(&self, uri: &str) -> Result<Option<[u8; 32]>, ClusterError> {
        let Some(entry) = self.kv.get(&baseline_key(uri)).await? else {
            return Ok(None);
        };
        Ok(<[u8; 32]>::try_from(entry.bytes.as_ref()).ok())
    }

    pub async fn set_baseline(&self, uri: &str, hash: [u8; 32]) -> Result<(), ClusterError> {
        self.kv
            .put(
                &baseline_key(uri),
                Bytes::copy_from_slice(&hash),
                Some(BASELINE_TTL),
            )
            .await
    }

    pub async fn clear_baseline(&self, uri: &str) -> Result<(), ClusterError> {
        self.kv.delete(&baseline_key(uri)).await.map(|_| ())
    }

    /// Mark `member` alive for `ttl`.
    pub async fn beat(&self, member: &str, ttl: Duration) -> Result<(), ClusterError> {
        self.kv
            .put(&member_key(member), Bytes::from_static(b"1"), Some(ttl))
            .await
    }

    /// Mark `member` gone at once.
    pub async fn leave(&self, member: &str) -> Result<(), ClusterError> {
        self.kv.delete(&member_key(member)).await.map(|_| ())
    }

    /// Every live member, in order.
    pub async fn members(&self) -> Result<Vec<String>, ClusterError> {
        Ok(mcpg_cluster_api::list_all(&*self.kv, MEMBER_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(key, _)| key.strip_prefix(MEMBER_PREFIX).map(str::to_owned))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// KvBackedSubscriptionStore — single impl over the orthogonal KvState primitive
// ---------------------------------------------------------------------------

/// Subscription store backed by any [`mcpg_cluster_api::KeyValueStore`] impl.
///
/// Replaces the per-backend `RedisSubscriptionStore` /
/// `NatsKvSubscriptionStore` impls that lived in
/// `mcpg-plugin-backend-{redis,nats}` before the substrate was
/// unified behind the cluster API.
///
/// Two-index scheme keeps both `subscribers_for(uri)` (notification
/// fan-out, hot path) and `subscriptions_for_session(session)` /
/// `clear_session` O(matching) instead of O(total):
///
/// - `sub:s:{session_id}:{uri_b64}` → identity JSON (`Option<SubscriberIdentity>`)
/// - `sub:u:{uri_b64}:{session_id}` → identity JSON (duplicate)
/// - `sub:w:{uri_b64}` → demand marker, present while the URI has a row
///
/// URIs are URL-safe-base64 encoded (no padding) before being embedded
/// in keys; session_ids are UUIDs and contain no colons. Both indices
/// store the identity inline so `subscribers_with_identity(uri)` doesn't
/// need a follow-up GET per session.
///
/// The trait surface stays sync; the impl bridges via
/// `tokio::task::block_in_place` + `Handle::current().block_on(...)`.
pub struct KvBackedSubscriptionStore {
    state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    max_per_session: usize,
}

impl std::fmt::Debug for KvBackedSubscriptionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedSubscriptionStore")
            .field("max_per_session", &self.max_per_session)
            .finish()
    }
}

impl KvBackedSubscriptionStore {
    pub fn new(
        state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        max_per_session: usize,
    ) -> Self {
        Self {
            state,
            max_per_session,
        }
    }

    /// Convenience: in-process `MemoryKv` backing.
    pub fn new_in_memory(max_per_session: usize) -> Self {
        Self::new(
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()),
            max_per_session,
        )
    }

    fn block<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        super::block_on_store(fut)
    }

    fn write(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
        holder: Option<&str>,
    ) -> Result<(), SubscriptionError> {
        Self::block(async {
            if self.max_per_session > 0 {
                let prefix = session_prefix(session_id);
                let entries =
                    self.state.list_prefix(&prefix, 4096).await.map_err(|e| {
                        SubscriptionError::BackendError(format!("kv list_prefix: {e}"))
                    })?;
                let already = entries.iter().any(|(k, _)| {
                    k.strip_prefix(&prefix)
                        .and_then(dec)
                        .map(|u| u == uri)
                        .unwrap_or(false)
                });
                if !already && entries.len() >= self.max_per_session {
                    return Err(SubscriptionError::LimitExceeded);
                }
            }
            let payload = row_value(&identity, holder)?;
            self.state
                .put(&session_key(session_id, uri), payload.clone(), None)
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv put session-idx: {e}")))?;
            self.state
                .put(&uri_key(uri, session_id), payload, None)
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv put uri-idx: {e}")))?;
            // After the row: a marker drop that races this subscribe looks
            // for rows after its delete (see `drop_demand_if_unsubscribed`).
            self.state
                .put(&demand_key(uri), Bytes::from_static(b"1"), None)
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv put demand: {e}")))?;
            Ok(())
        })
    }
}

impl SubscriptionStore for KvBackedSubscriptionStore {
    fn subscribe(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Result<(), SubscriptionError> {
        self.write(session_id, uri, identity, None)
    }

    fn subscribe_held(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
        holder: &str,
    ) -> Result<(), SubscriptionError> {
        self.write(session_id, uri, identity, Some(holder))
    }

    fn watch_state(&self) -> Option<WatchState> {
        Some(WatchState::new(Arc::clone(&self.state)))
    }

    fn unsubscribe(&self, session_id: &str, uri: &str) -> Result<bool, SubscriptionError> {
        Self::block(async {
            let removed_session = self
                .state
                .delete(&session_key(session_id, uri))
                .await
                .map_err(|e| {
                    SubscriptionError::BackendError(format!("kv delete session-idx: {e}"))
                })?;
            let removed_uri = self
                .state
                .delete(&uri_key(uri, session_id))
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv delete uri-idx: {e}")))?;
            // A marker left behind only keeps a watcher up until the
            // watch engine's collector finds the URI without rows.
            if let Err(error) = drop_demand_if_unsubscribed(&*self.state, uri).await {
                tracing::debug!(uri = %uri, %error, "subscription demand marker not dropped");
            }
            Ok(removed_session || removed_uri)
        })
    }

    fn subscribers_for(&self, uri: &str) -> Vec<String> {
        Self::block(async {
            let prefix = uri_prefix(uri);
            let entries = match mcpg_cluster_api::list_all(&*self.state, &prefix).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };
            entries
                .into_iter()
                .filter_map(|(k, _)| k.strip_prefix(&prefix).map(|s| s.to_owned()))
                .collect()
        })
    }

    fn subscribers_with_identity(&self, uri: &str) -> Vec<(String, Option<SubscriberIdentity>)> {
        Self::block(async {
            let prefix = uri_prefix(uri);
            let entries = match mcpg_cluster_api::list_all(&*self.state, &prefix).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };
            entries
                .into_iter()
                .filter_map(|(k, v)| {
                    let session_id = k.strip_prefix(&prefix)?.to_owned();
                    Some((session_id, row_identity(&v.bytes)))
                })
                .collect()
        })
    }

    fn subscriptions_for_session(&self, session_id: &str) -> Vec<String> {
        Self::block(async {
            let prefix = session_prefix(session_id);
            let entries = match mcpg_cluster_api::list_all(&*self.state, &prefix).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };
            entries
                .into_iter()
                .filter_map(|(k, _)| k.strip_prefix(&prefix).and_then(dec))
                .collect()
        })
    }

    fn clear_session(&self, session_id: &str) {
        Self::block(async {
            let prefix = session_prefix(session_id);
            let Ok(entries) = mcpg_cluster_api::list_all(&*self.state, &prefix).await else {
                return;
            };
            for (k, _) in entries {
                let Some(uri) = k.strip_prefix(&prefix).and_then(dec) else {
                    continue;
                };
                let _ = self.state.delete(&k).await;
                let _ = self.state.delete(&uri_key(&uri, session_id)).await;
                if let Err(error) = drop_demand_if_unsubscribed(&*self.state, &uri).await {
                    tracing::debug!(uri = %uri, %error, "subscription demand marker not dropped");
                }
            }
        })
    }

    fn total_subscriptions(&self) -> usize {
        Self::block(async {
            mcpg_cluster_api::list_all(&*self.state, "sub:s:")
                .await
                .map(|e| e.len())
                .unwrap_or(0)
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_query() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store
            .subscribe("sess-1", "file:///config.yaml", None)
            .unwrap();
        store
            .subscribe("sess-2", "file:///config.yaml", None)
            .unwrap();
        store
            .subscribe("sess-1", "file:///other.yaml", None)
            .unwrap();

        let subscribers = store.subscribers_for("file:///config.yaml");
        assert_eq!(subscribers.len(), 2);
        assert!(subscribers.contains(&"sess-1".to_owned()));
        assert!(subscribers.contains(&"sess-2".to_owned()));

        let session_subs = store.subscriptions_for_session("sess-1");
        assert_eq!(session_subs.len(), 2);

        assert_eq!(store.total_subscriptions(), 3);
    }

    #[test]
    fn unsubscribe_removes_mapping() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-1", "file:///b", None).unwrap();

        assert!(store.unsubscribe("sess-1", "file:///a").unwrap());
        assert!(!store.unsubscribe("sess-1", "file:///a").unwrap()); // already removed

        assert_eq!(store.subscribers_for("file:///a").len(), 0);
        assert_eq!(store.subscriptions_for_session("sess-1").len(), 1);
    }

    #[test]
    fn clear_session_removes_all() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-1", "file:///b", None).unwrap();
        store.subscribe("sess-2", "file:///a", None).unwrap();

        store.clear_session("sess-1");

        assert_eq!(store.subscriptions_for_session("sess-1").len(), 0);
        // sess-2 still has its subscription
        assert_eq!(store.subscribers_for("file:///a").len(), 1);
        assert_eq!(store.total_subscriptions(), 1);
    }

    #[test]
    fn duplicate_subscribe_is_idempotent() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-1", "file:///a", None).unwrap();

        assert_eq!(store.subscribers_for("file:///a").len(), 1);
        assert_eq!(store.total_subscriptions(), 1);
    }

    #[test]
    fn limit_enforced() {
        let store = KvBackedSubscriptionStore::new_in_memory(2);
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-1", "file:///b", None).unwrap();
        let result = store.subscribe("sess-1", "file:///c", None);
        assert_eq!(result, Err(SubscriptionError::LimitExceeded));

        // Re-subscribe to existing is fine even at limit
        store.subscribe("sess-1", "file:///a", None).unwrap();
    }

    #[test]
    fn empty_queries_return_empty() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        assert!(store.subscribers_for("nonexistent").is_empty());
        assert!(store.subscriptions_for_session("nonexistent").is_empty());
        assert_eq!(store.total_subscriptions(), 0);
    }

    #[test]
    fn clear_nonexistent_session_is_safe() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.clear_session("nonexistent"); // should not panic
    }

    // ── Subject-Scoped Notification Tests (F1) ──────────────────────────

    #[test]
    fn subscribe_with_identity_stores_it() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        let identity = SubscriberIdentity {
            session_id: "sess-1".to_owned(),
            principal_id: Some("user-42".to_owned()),
            trust_level: "verified".to_owned(),
            roles: vec!["admin".to_owned()],
            groups: vec!["engineering".to_owned()],
            scopes: vec!["read".to_owned(), "write".to_owned()],
            attributes: BTreeMap::from([("tenant".to_owned(), "acme".to_owned())]),
        };
        store
            .subscribe("sess-1", "file:///config.yaml", Some(identity.clone()))
            .unwrap();

        let subs = store.subscribers_with_identity("file:///config.yaml");
        assert_eq!(subs.len(), 1);
        let (sid, id) = &subs[0];
        assert_eq!(sid, "sess-1");
        let id = id.as_ref().expect("identity should be present");
        assert_eq!(id.principal_id.as_deref(), Some("user-42"));
        assert_eq!(id.trust_level, "verified");
        assert_eq!(id.roles, vec!["admin"]);
        assert_eq!(id.groups, vec!["engineering"]);
        assert_eq!(id.scopes, vec!["read", "write"]);
        assert_eq!(
            id.attributes.get("tenant").map(|s| s.as_str()),
            Some("acme")
        );
    }

    #[test]
    fn subscribers_with_identity_returns_none_when_no_identity() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.subscribe("sess-1", "file:///a", None).unwrap();

        let subs = store.subscribers_with_identity("file:///a");
        assert_eq!(subs.len(), 1);
        let (sid, id) = &subs[0];
        assert_eq!(sid, "sess-1");
        assert!(id.is_none());
    }

    #[test]
    fn clear_session_clears_identity() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        let identity = SubscriberIdentity {
            session_id: "sess-1".to_owned(),
            principal_id: Some("user-42".to_owned()),
            ..Default::default()
        };
        store
            .subscribe("sess-1", "file:///a", Some(identity))
            .unwrap();
        store.subscribe("sess-2", "file:///a", None).unwrap();

        store.clear_session("sess-1");

        // Subscribers list reflects the cleared identity — only sess-2
        // remains, and its identity (None in this case) is unchanged.
        let subs = store.subscribers_with_identity("file:///a");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].0, "sess-2");
        assert!(subs[0].1.is_none());
    }

    fn demand(store: &KvBackedSubscriptionStore, uri: &str) -> bool {
        futures::executor::block_on(store.watch_state().expect("watch state").has_demand(uri))
            .expect("demand read")
    }

    #[test]
    fn a_uri_has_demand_until_its_last_row_goes() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        assert!(!demand(&store, "file:///a"));
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-2", "file:///a", None).unwrap();
        assert!(demand(&store, "file:///a"));

        store.unsubscribe("sess-1", "file:///a").unwrap();
        assert!(demand(&store, "file:///a"), "sess-2 still subscribes");
        store.unsubscribe("sess-2", "file:///a").unwrap();
        assert!(!demand(&store, "file:///a"));
    }

    #[test]
    fn clearing_a_session_drops_only_the_demand_it_alone_made() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        store.subscribe("sess-1", "file:///a", None).unwrap();
        store.subscribe("sess-1", "file:///b", None).unwrap();
        store.subscribe("sess-2", "file:///b", None).unwrap();

        store.clear_session("sess-1");
        assert!(!demand(&store, "file:///a"));
        assert!(demand(&store, "file:///b"));
        let state = store.watch_state().unwrap();
        assert_eq!(
            futures::executor::block_on(state.demanded()).unwrap(),
            vec!["file:///b".to_owned()]
        );
    }

    #[test]
    fn a_held_row_names_its_holder_and_reads_as_its_identity() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        let identity = SubscriberIdentity {
            session_id: "sess-1".to_owned(),
            principal_id: Some("user-42".to_owned()),
            ..Default::default()
        };
        store
            .subscribe_held("sess-1", "file:///a", Some(identity), "member-1")
            .unwrap();
        store
            .subscribe_held("sess-2", "file:///a", None, "member-1")
            .unwrap();
        store.subscribe("sess-3", "file:///a", None).unwrap();

        let state = store.watch_state().unwrap();
        let mut rows = futures::executor::block_on(state.rows("file:///a")).unwrap();
        rows.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        let holders: Vec<(&str, Option<&str>)> = rows
            .iter()
            .map(|r| (r.session_id.as_str(), r.holder.as_deref()))
            .collect();
        assert_eq!(
            holders,
            vec![
                ("sess-1", Some("member-1")),
                ("sess-2", Some("member-1")),
                ("sess-3", None),
            ]
        );

        let subscribers = store.subscribers_with_identity("file:///a");
        let principal = |session: &str| {
            subscribers
                .iter()
                .find(|(s, _)| s == session)
                .and_then(|(_, id)| id.as_ref())
                .and_then(|id| id.principal_id.clone())
        };
        assert_eq!(principal("sess-1").as_deref(), Some("user-42"));
        assert_eq!(principal("sess-2"), None);

        // A reader that predates the holder decodes the bare identity.
        let raw = futures::executor::block_on(store.state.get(&uri_key("file:///a", "sess-1")))
            .unwrap()
            .unwrap();
        let older: Option<SubscriberIdentity> = serde_json::from_slice(&raw.bytes).unwrap();
        assert_eq!(older.unwrap().principal_id.as_deref(), Some("user-42"));
    }

    /// Runs a whole subscribe (row, then marker) right before the first
    /// delete of the demand marker of `uri`: the subscribe a marker drop can
    /// race.
    #[derive(Debug)]
    struct SubscribeBeforeDelete {
        inner: crate::builtins::cluster_primitives::MemoryKv,
        uri: String,
        raced: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl KeyValueStore for SubscribeBeforeDelete {
        async fn get(&self, key: &str) -> Result<Option<mcpg_cluster_api::Entry>, ClusterError> {
            self.inner.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            value: Bytes,
            ttl: Option<Duration>,
        ) -> Result<(), ClusterError> {
            self.inner.put(key, value, ttl).await
        }
        async fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            ttl: Option<Duration>,
        ) -> Result<bool, ClusterError> {
            self.inner.put_if_absent(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
            if key == demand_key(&self.uri)
                && !self.raced.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                self.inner
                    .put(
                        &uri_key(&self.uri, "sess-racer"),
                        Bytes::from_static(b"null"),
                        None,
                    )
                    .await?;
                self.inner
                    .put(&demand_key(&self.uri), Bytes::from_static(b"1"), None)
                    .await?;
            }
            self.inner.delete(key).await
        }
        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> Result<mcpg_cluster_api::KvPage, ClusterError> {
            self.inner.list_page(prefix, cursor, limit).await
        }
        async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
            self.inner.expire(key, ttl).await
        }
        async fn incr(
            &self,
            key: &str,
            delta: i64,
            ttl: Option<Duration>,
        ) -> Result<i64, ClusterError> {
            self.inner.incr(key, delta, ttl).await
        }
    }

    /// The last unsubscribe of a URI drops its marker while another replica
    /// subscribes: the marker must survive, or the new subscriber's watcher
    /// never starts.
    #[test]
    fn a_marker_drop_that_races_a_subscribe_keeps_the_marker() {
        let uri = "file:///raced";
        let store = KvBackedSubscriptionStore::new(
            Arc::new(SubscribeBeforeDelete {
                inner: crate::builtins::cluster_primitives::MemoryKv::new(),
                uri: uri.to_owned(),
                raced: std::sync::atomic::AtomicBool::new(false),
            }),
            100,
        );
        store.subscribe("sess-1", uri, None).unwrap();
        store.unsubscribe("sess-1", uri).unwrap();
        assert_eq!(store.subscribers_for(uri), vec!["sess-racer".to_owned()]);
        assert!(
            demand(&store, uri),
            "the racing subscriber keeps its marker"
        );
    }

    /// Rows written without a marker (an older build) get one from the
    /// backfill; a URI that has its marker is left alone.
    #[test]
    fn the_backfill_marks_rows_written_without_a_marker() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        futures::executor::block_on(async {
            for (uri, session) in [("file:///old", "sess-1"), ("file:///old", "sess-2")] {
                store
                    .state
                    .put(&uri_key(uri, session), Bytes::from_static(b"null"), None)
                    .await
                    .unwrap();
                store
                    .state
                    .put(
                        &session_key(session, uri),
                        Bytes::from_static(b"null"),
                        None,
                    )
                    .await
                    .unwrap();
            }
        });
        store.subscribe("sess-3", "file:///new", None).unwrap();
        assert!(!demand(&store, "file:///old"));

        let state = store.watch_state().unwrap();
        assert_eq!(
            futures::executor::block_on(state.backfill_demand()).unwrap(),
            1
        );
        assert!(demand(&store, "file:///old"));
        assert!(demand(&store, "file:///new"));
        assert_eq!(
            futures::executor::block_on(state.backfill_demand()).unwrap(),
            0,
            "a second pass finds nothing to write"
        );
    }

    #[test]
    fn baselines_and_members() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        let state = store.watch_state().unwrap();
        futures::executor::block_on(async {
            assert_eq!(state.baseline("file:///a").await.unwrap(), None);
            state.set_baseline("file:///a", [7u8; 32]).await.unwrap();
            assert_eq!(state.baseline("file:///a").await.unwrap(), Some([7u8; 32]));
            state.clear_baseline("file:///a").await.unwrap();
            assert_eq!(state.baseline("file:///a").await.unwrap(), None);

            state.beat("m2", Duration::from_secs(20)).await.unwrap();
            state.beat("m1", Duration::from_secs(20)).await.unwrap();
            assert_eq!(state.members().await.unwrap(), vec!["m1", "m2"]);
            state.leave("m1").await.unwrap();
            assert_eq!(state.members().await.unwrap(), vec!["m2"]);
        });
    }

    #[test]
    fn unsubscribe_clears_identity() {
        let store = KvBackedSubscriptionStore::new_in_memory(100);
        let identity = SubscriberIdentity {
            session_id: "sess-1".to_owned(),
            principal_id: Some("user-42".to_owned()),
            ..Default::default()
        };
        store
            .subscribe("sess-1", "file:///a", Some(identity))
            .unwrap();

        store.unsubscribe("sess-1", "file:///a").unwrap();

        // After unsubscribe, the subscriber is gone from both indices.
        assert!(store.subscribers_for("file:///a").is_empty());
        assert!(store.subscriptions_for_session("sess-1").is_empty());
    }
}
