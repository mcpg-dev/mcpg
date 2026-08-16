//! Resource-subscription ownership.
//!
//! A `resources/updated` subscription is not one piece of state — it is three
//! that have to agree:
//!
//! 1. a row in the [`SubscriptionStore`], which the notification fan-out reads
//!    to decide who receives an update;
//! 2. a per-URI entry in the [`WatchEngine`], which is what actually *produces*
//!    updates and refcounts how many subscribers still want them;
//! 3. a holder — a legacy `resources/subscribe` call, or a modern
//!    `subscriptions/listen` stream — whose lifetime says how long the other
//!    two should exist.
//!
//! Spreading that across the two transports made the three disagree in both
//! directions: two `subscriptions/listen` streams over the same principal's
//! synthetic session shared one store row, so whichever ended first deleted the
//! row the other was still being served by; and session teardown dropped the
//! rows without telling the watch engine, leaving a watcher polling a resource
//! nobody was subscribed to for the life of the process.
//!
//! This module owns all three together. Callers hold a [`SubscriptionLease`]
//! and nothing else: acquiring one creates the row and the watcher on the first
//! holder, dropping it releases them after the last. Every count transition
//! goes through one mutex, so "how many holders does this `(session, uri)`
//! have" has exactly one answer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::mpsc;

use super::stores::subscription_store::{SubscriberIdentity, SubscriptionError, SubscriptionStore};
use super::watch_engine::WatchEngine;

/// `(session_id, uri)` — the granularity at which the store keys a
/// subscription, and therefore the granularity a lease refcounts.
type Key = (String, String);

/// Owns the store rows, the watch-engine refcounts, and the holder counts that
/// tie them together.
pub struct SubscriptionService {
    store: Arc<dyn SubscriptionStore>,
    watch: WatchEngine,
    /// Live holders per `(session, uri)`.
    ///
    /// An entry exists from the moment the store row is created until the
    /// reaper tears it down; a count of zero means "released, teardown
    /// pending", which is deliberately still an entry — see
    /// [`SubscriptionService::acquire`].
    holders: Mutex<HashMap<Key, usize>>,
    /// Keys posted by [`SubscriptionLease::drop`], drained by the reaper.
    ///
    /// `Drop` may run on any thread, inside or outside a reactor, so it cannot
    /// do the release itself: the store's trait surface is sync but blocks on a
    /// runtime internally, and the watch engine's channel is async. Both belong
    /// on a task, and a task cannot be spawned from a `Drop` that is running on
    /// a thread with no reactor.
    release_tx: mpsc::UnboundedSender<Key>,
}

impl std::fmt::Debug for SubscriptionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionService")
            .field("store", &self.store)
            .field(
                "keys",
                &self.holders.lock().map(|h| h.len()).unwrap_or_default(),
            )
            .finish()
    }
}

impl SubscriptionService {
    /// Build the service and start its release reaper.
    ///
    /// Without a reactor (synchronous test construction) the reaper is not
    /// spawned; releases then accumulate in the channel and the store rows
    /// outlive their holders. That matches the watch engine, which is likewise
    /// inert when built off-reactor, so no update is being produced for those
    /// rows either.
    pub fn new(store: Arc<dyn SubscriptionStore>, watch: WatchEngine) -> Arc<Self> {
        let (release_tx, release_rx) = mpsc::unbounded_channel();
        let service = Arc::new(Self {
            store,
            watch,
            holders: Mutex::new(HashMap::new()),
            release_tx,
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(reap_releases(Arc::downgrade(&service), release_rx));
        }
        service
    }

    /// Take a lease on `(session_id, uri)`.
    ///
    /// The first holder creates the store row and starts the watcher; later
    /// holders join the existing ones. Returns `None` when the store refused
    /// the subscription (per-session limit, backend failure) — the caller must
    /// then treat the target as not established rather than reporting it back
    /// to the client.
    pub async fn acquire(
        self: &Arc<Self>,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Option<SubscriptionLease> {
        match self.acquire_inner(session_id, uri, identity).await {
            Ok(lease) => Some(lease),
            Err(error) => {
                tracing::debug!(
                    session_id = %session_id,
                    uri = %uri,
                    %error,
                    "subscription refused by the store"
                );
                None
            }
        }
    }

    async fn acquire_inner(
        self: &Arc<Self>,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Result<SubscriptionLease, SubscriptionError> {
        let key = (session_id.to_owned(), uri.to_owned());
        let fresh = {
            let mut holders = self.lock_holders();
            match holders.get_mut(&key) {
                // Includes the zero-count case: a release is queued but the row
                // and the watcher are still up, so this holder rejoins them
                // instead of re-creating them. The queued release then finds a
                // non-zero count and does nothing, which is what keeps
                // acquire/release from racing.
                Some(count) => {
                    *count += 1;
                    false
                }
                None => {
                    holders.insert(key.clone(), 1);
                    true
                }
            }
        };

        if fresh {
            if let Err(error) = self.store.subscribe(session_id, uri, identity) {
                self.lock_holders().remove(&key);
                return Err(error);
            }
            // Only the transition into existence starts a watcher, so the
            // engine's per-URI count stays equal to the number of live keys
            // for that URI.
            self.watch.notify_subscribe(uri).await;
        }
        Ok(SubscriptionLease {
            service: Arc::downgrade(self),
            key,
        })
    }

    /// Release every lease this session holds, whatever their counts.
    ///
    /// Session teardown outranks the individual holders: their streams are
    /// being torn down with it. Leases that outlive this call release into a
    /// key that no longer exists, which is a no-op — so the store row and the
    /// watcher are torn down exactly once.
    pub fn release_session(self: &Arc<Self>, session_id: &str) {
        let released: Vec<String> = {
            let mut holders = self.lock_holders();
            let keys: Vec<Key> = holders
                .keys()
                .filter(|(session, _)| session == session_id)
                .cloned()
                .collect();
            for key in &keys {
                holders.remove(key);
            }
            keys.into_iter().map(|(_, uri)| uri).collect()
        };
        // Rows can exist with no local key — written by another replica, or by
        // a lease whose reaper never ran. The store is the source of truth for
        // the fan-out, so clear it whether or not this replica held anything.
        self.store.clear_session(session_id);
        if released.is_empty() {
            return;
        }
        // Teardown is synchronous but the engine's channel is not; hand the
        // decrements to the reactor. Only URIs this replica actually held are
        // decremented, so the engine's count cannot go negative.
        let watch = self.watch.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                for uri in released {
                    watch.notify_unsubscribe(&uri).await;
                }
            });
        }
    }

    /// Legacy `resources/subscribe`: one idempotent holder per
    /// `(session, uri)`.
    ///
    /// The legacy wire has no per-stream identity — `resources/unsubscribe`
    /// means "this session is done with this URI", so a repeat subscribe must
    /// not add a holder that a single unsubscribe then fails to remove.
    /// Returns whether this call established the subscription.
    pub async fn subscribe_once(
        self: &Arc<Self>,
        session_id: &str,
        uri: &str,
        identity: Option<SubscriberIdentity>,
    ) -> Result<bool, SubscriptionError> {
        let key = (session_id.to_owned(), uri.to_owned());
        {
            let mut holders = self.lock_holders();
            if let Some(count) = holders.get_mut(&key) {
                // Also revives a zero count whose release is still queued.
                *count = 1;
                return Ok(false);
            }
            holders.insert(key.clone(), 1);
        }
        if let Err(error) = self.store.subscribe(session_id, uri, identity) {
            self.lock_holders().remove(&key);
            return Err(error);
        }
        self.watch.notify_subscribe(uri).await;
        Ok(true)
    }

    /// Legacy `resources/unsubscribe`: drop the session's holder on this URI
    /// regardless of count. Returns whether there was one.
    pub async fn unsubscribe_once(self: &Arc<Self>, session_id: &str, uri: &str) -> bool {
        let key = (session_id.to_owned(), uri.to_owned());
        let had_holder = self.lock_holders().remove(&key).is_some();
        // The row can outlive this replica's holder table (restart, cross-
        // replica subscribe), so delete unconditionally; only the watch-engine
        // decrement is conditional, since that count is this replica's.
        let removed_row = self.store.unsubscribe(session_id, uri).unwrap_or(false);
        if had_holder {
            self.watch.notify_unsubscribe(uri).await;
        }
        had_holder || removed_row
    }

    /// Stop the watch engine and every watcher it started.
    ///
    /// Called when the runtime that owns this service is retired — process
    /// shutdown or a config reload. Without it the engine's control loop only
    /// ends when its last sender drops, and ending that way leaves the spawned
    /// per-URI watchers running: their cancellation tokens are held by the
    /// loop's table, and dropping a `CancellationToken` does not cancel it.
    pub async fn shutdown(&self) {
        self.watch.shutdown().await;
    }

    /// Number of `(session, uri)` keys with at least one live holder.
    pub fn live_keys(&self) -> usize {
        self.lock_holders()
            .values()
            .filter(|count| **count > 0)
            .count()
    }

    fn lock_holders(&self) -> std::sync::MutexGuard<'_, HashMap<Key, usize>> {
        // A panic under this lock would leave a count wrong, not memory
        // unsound; recovering keeps subscriptions working rather than
        // poisoning every later call.
        self.holders.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reaper step: tear the key down if it is still at zero holders.
    async fn reap(self: &Arc<Self>, key: Key) {
        {
            let mut holders = self.lock_holders();
            match holders.get(&key) {
                // Re-acquired between the release and now — the row and the
                // watcher are still wanted.
                Some(count) if *count > 0 => return,
                Some(_) => {
                    holders.remove(&key);
                }
                None => return,
            }
        }
        let (session_id, uri) = key;
        let _ = self.store.unsubscribe(&session_id, &uri);
        self.watch.notify_unsubscribe(&uri).await;
    }
}

async fn reap_releases(service: Weak<SubscriptionService>, mut rx: mpsc::UnboundedReceiver<Key>) {
    while let Some(key) = rx.recv().await {
        let Some(service) = service.upgrade() else {
            return;
        };
        service.reap(key).await;
    }
}

/// One holder of a `(session, uri)` subscription.
///
/// Dropping it releases the holder; the store row and the watcher survive until
/// the last one goes. The service handle is weak on purpose: a lease lives
/// inside an SSE response body, and a strong handle would keep the retired
/// runtime's watch engine — and so the sender the stream is waiting on — alive
/// across a reload, leaving the stream unable to end.
pub struct SubscriptionLease {
    service: Weak<SubscriptionService>,
    key: Key,
}

impl SubscriptionLease {
    /// The URI this lease holds.
    pub fn uri(&self) -> &str {
        &self.key.1
    }
}

impl Drop for SubscriptionLease {
    fn drop(&mut self) {
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let hit_zero = {
            let mut holders = service.lock_holders();
            match holders.get_mut(&self.key) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => false,
            }
        };
        if hit_zero {
            // Deliberately leaves the zero-count entry in place: the reaper
            // removes it, and until then a re-acquire can revive it without
            // re-creating a row that was never deleted.
            let _ = service.release_tx.send(self.key.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::stores::subscription_store::KvBackedSubscriptionStore;

    fn service() -> Arc<SubscriptionService> {
        SubscriptionService::new(
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100)),
            WatchEngine::noop(),
        )
    }

    /// Release is deliberately asynchronous — `Drop` posts, the reaper acts —
    /// so tests wait on the outcome rather than on a scheduler yield, which is
    /// not a synchronisation primitive under load.
    async fn eventually(mut condition: impl FnMut() -> bool) {
        for _ in 0..400 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Two `subscriptions/listen` streams from one principal share a synthetic
    /// session, so they share a `(session, uri)` key. Ending one must not
    /// delete the row the other is still served by.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_holder_keeps_the_row_alive() {
        let service = service();
        let first = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("first lease");
        let second = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("second lease");

        drop(first);
        // Give the reaper every chance to get this wrong before asserting it
        // did not: a bare `drop` used to delete the shared row outright.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            service.store.subscribers_for("file:///a").len(),
            1,
            "the surviving stream must still be a subscriber"
        );

        drop(second);
        let store = Arc::clone(&service.store);
        eventually(|| store.subscribers_for("file:///a").is_empty()).await;
        assert!(
            service.store.subscribers_for("file:///a").is_empty(),
            "the last holder leaving must release the row"
        );
    }

    /// A lease taken while a release is queued rejoins the existing row rather
    /// than racing the reaper into a deleted one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reacquire_before_the_reaper_keeps_the_row() {
        let service = service();
        let lease = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("lease");
        drop(lease);
        // No yield: the release is posted but unprocessed.
        let revived = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("re-acquire");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            service.store.subscribers_for("file:///a").len(),
            1,
            "the queued release must not delete a row a live lease holds"
        );
        drop(revived);
    }

    /// Session teardown must reach the watch engine, not just the store.
    ///
    /// Clearing the rows alone leaves the engine counting this session as a
    /// subscriber, so its watcher keeps running — one leaked background task
    /// per watched URI, for the life of the process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_session_stops_the_watcher() {
        use crate::runtime::watch_engine::{WatchConfig, WatchStrategy};
        use std::collections::HashMap;

        let uri = "mem://watched";
        let mut configs = HashMap::new();
        configs.insert(
            uri.to_owned(),
            WatchConfig {
                uri: uri.to_owned(),
                // A webhook watcher runs until cancelled and does nothing else,
                // so the engine's watcher table is the only thing under test.
                strategy: WatchStrategy::Webhook {
                    token: "t".to_owned(),
                    previous_tokens: Vec::new(),
                },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );
        let store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        let engine = WatchEngine::start(
            configs,
            store.clone(),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );
        let service = SubscriptionService::new(store, engine.clone());

        let lease = service.acquire("sess", uri, None).await.expect("lease");
        assert_eq!(
            engine.active_watch_count().await,
            1,
            "subscribing must start the watcher"
        );

        service.release_session("sess");
        for _ in 0..400 {
            if engine.active_watch_count().await == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            engine.active_watch_count().await,
            0,
            "session teardown must stop the watcher it started"
        );
        drop(lease);
    }

    /// Session teardown outranks the holders: it releases every key the
    /// session owns, and the leases that outlive it release into nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_session_drops_every_key() {
        let service = service();
        let a = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("lease a");
        let b = service
            .acquire("sess", "file:///b", None)
            .await
            .expect("lease b");
        assert_eq!(service.live_keys(), 2);

        service.release_session("sess");
        assert_eq!(service.live_keys(), 0);
        assert!(service.store.subscriptions_for_session("sess").is_empty());

        // Dropping the orphaned leases must not resurrect or double-release.
        drop(a);
        drop(b);
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(service.live_keys(), 0);
    }

    /// The legacy wire's contract: subscribing twice then unsubscribing once
    /// leaves the session unsubscribed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_subscribe_is_idempotent() {
        let service = service();
        assert!(
            service
                .subscribe_once("sess", "file:///a", None)
                .await
                .expect("first subscribe"),
            "the first subscribe establishes the subscription"
        );
        assert!(
            !service
                .subscribe_once("sess", "file:///a", None)
                .await
                .expect("second subscribe"),
            "a repeat subscribe must not establish a second holder"
        );

        assert!(service.unsubscribe_once("sess", "file:///a").await);
        assert!(
            service.store.subscribers_for("file:///a").is_empty(),
            "one unsubscribe must fully unsubscribe"
        );
        assert!(!service.unsubscribe_once("sess", "file:///a").await);
    }

    /// A store that refuses the subscription must not leave a holder behind —
    /// otherwise the key is occupied forever and every later acquire silently
    /// "joins" a subscription that does not exist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_subscribe_leaves_no_holder() {
        let service = SubscriptionService::new(
            Arc::new(KvBackedSubscriptionStore::new_in_memory(1)),
            WatchEngine::noop(),
        );
        let _held = service
            .acquire("sess", "file:///a", None)
            .await
            .expect("first lease");
        assert!(
            service.acquire("sess", "file:///b", None).await.is_none(),
            "the store's per-session limit must surface as a refusal"
        );
        assert_eq!(
            service.live_keys(),
            1,
            "the refused key must not be left occupied"
        );
    }
}
