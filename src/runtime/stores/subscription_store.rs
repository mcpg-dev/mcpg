//! Subscription store — tracks which sessions are subscribed to
//! which resource URIs for `notifications/resources/updated` delivery.

use std::collections::BTreeMap;

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
        format!("sub:s:{session_id}:{}", Self::enc(uri))
    }

    fn uri_key(uri: &str, session_id: &str) -> String {
        format!("sub:u:{}:{session_id}", Self::enc(uri))
    }

    fn session_prefix(session_id: &str) -> String {
        format!("sub:s:{session_id}:")
    }

    fn uri_prefix(uri: &str) -> String {
        format!("sub:u:{}:", Self::enc(uri))
    }

    fn block<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::try_current() {
            Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| h.block_on(fut))
            }
            _ => futures::executor::block_on(fut),
        }
    }
}

impl SubscriptionStore for KvBackedSubscriptionStore {
    fn subscribe(
        &self,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Result<(), SubscriptionError> {
        Self::block(async {
            if self.max_per_session > 0 {
                let entries = self
                    .state
                    .list_prefix(&Self::session_prefix(session_id), 4096)
                    .await
                    .map_err(|e| SubscriptionError::BackendError(format!("kv list_prefix: {e}")))?;
                let already = entries.iter().any(|(k, _)| {
                    k.strip_prefix(&Self::session_prefix(session_id))
                        .and_then(Self::dec)
                        .map(|u| u == uri)
                        .unwrap_or(false)
                });
                if !already && entries.len() >= self.max_per_session {
                    return Err(SubscriptionError::LimitExceeded);
                }
            }
            let bytes = serde_json::to_vec(&identity)
                .map_err(|e| SubscriptionError::BackendError(format!("encode identity: {e}")))?;
            let payload = bytes::Bytes::from(bytes);
            self.state
                .put(&Self::session_key(session_id, uri), payload.clone(), None)
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv put session-idx: {e}")))?;
            self.state
                .put(&Self::uri_key(uri, session_id), payload, None)
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv put uri-idx: {e}")))?;
            Ok(())
        })
    }

    fn unsubscribe(&self, session_id: &str, uri: &str) -> Result<bool, SubscriptionError> {
        Self::block(async {
            let removed_session = self
                .state
                .delete(&Self::session_key(session_id, uri))
                .await
                .map_err(|e| {
                    SubscriptionError::BackendError(format!("kv delete session-idx: {e}"))
                })?;
            let removed_uri = self
                .state
                .delete(&Self::uri_key(uri, session_id))
                .await
                .map_err(|e| SubscriptionError::BackendError(format!("kv delete uri-idx: {e}")))?;
            Ok(removed_session || removed_uri)
        })
    }

    fn subscribers_for(&self, uri: &str) -> Vec<String> {
        Self::block(async {
            let prefix = Self::uri_prefix(uri);
            let entries = match self.state.list_prefix(&prefix, 4096).await {
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
            let prefix = Self::uri_prefix(uri);
            let entries = match self.state.list_prefix(&prefix, 4096).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };
            entries
                .into_iter()
                .filter_map(|(k, v)| {
                    let session_id = k.strip_prefix(&prefix)?.to_owned();
                    let identity: Option<SubscriberIdentity> =
                        serde_json::from_slice(&v.bytes).ok().flatten();
                    Some((session_id, identity))
                })
                .collect()
        })
    }

    fn subscriptions_for_session(&self, session_id: &str) -> Vec<String> {
        Self::block(async {
            let prefix = Self::session_prefix(session_id);
            let entries = match self.state.list_prefix(&prefix, 4096).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };
            entries
                .into_iter()
                .filter_map(|(k, _)| k.strip_prefix(&prefix).and_then(Self::dec))
                .collect()
        })
    }

    fn clear_session(&self, session_id: &str) {
        Self::block(async {
            let prefix = Self::session_prefix(session_id);
            let Ok(entries) = self.state.list_prefix(&prefix, 4096).await else {
                return;
            };
            for (k, _) in entries {
                let Some(uri) = k.strip_prefix(&prefix).and_then(Self::dec) else {
                    continue;
                };
                let _ = self.state.delete(&k).await;
                let _ = self.state.delete(&Self::uri_key(&uri, session_id)).await;
            }
        })
    }

    fn total_subscriptions(&self) -> usize {
        Self::block(async {
            self.state
                .list_prefix("sub:s:", 4096)
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
