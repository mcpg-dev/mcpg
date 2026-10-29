//! A counting semaphore that the replicas of a fleet share through the quota
//! store.
//!
//! A scope with a cap of N has N slots in the store,
//! `quotas.slots.<scope>.<N>.<i>`. An acquire takes a free one with
//! `put_if_absent`, which exactly one writer wins, and a release deletes it.
//! So the fleet never holds more than N permits, and a refused acquire writes
//! nothing: no attempt can make another one look over the cap.
//!
//! A slot lives [`SLOT_TTL`] after its last write, and its holder writes it
//! again every [`REFRESH`] while it holds it, so the permits of a replica that
//! dies come back within the TTL.
//!
//! A replica never needs more than N at once, so an acquire first takes a
//! slot of a local semaphore of N, and only a local slot holder tries the
//! store: a full replica refuses without a store operation. An acquire that
//! finds every store slot taken refuses the next ones of the scope on this
//! replica for [`FULL_HOLD`], or until a permit of the scope comes back here.

#![cfg(feature = "governance-quotas")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use mcpg_cluster_api::KeyValueStore;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// How long a slot outlives its last write.
pub const SLOT_TTL: Duration = Duration::from_secs(30);
/// How often a holder writes its slots again.
pub const REFRESH: Duration = Duration::from_secs(10);
/// How long an acquire that found the fleet full refuses the next ones of
/// its scope here without the store.
pub const FULL_HOLD: Duration = Duration::from_millis(20);
const KEY_PREFIX: &str = "quotas.slots.";
/// Back-off between two tries of a queued acquire, before jitter.
const RETRY_MIN: Duration = Duration::from_millis(20);
const RETRY_MAX: Duration = Duration::from_millis(250);

fn encode(scope: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(scope.as_bytes())
}

/// The store key of slot `index` of `scope` under the cap `max`.
fn slot_key(scope: &str, max: u32, index: u32) -> String {
    format!("{KEY_PREFIX}{}.{max}.{index}", encode(scope))
}

/// The fleet-wide semaphore of one quota store.
pub struct FleetSemaphore {
    kv: Arc<dyn KeyValueStore>,
    /// The value of this semaphore's slots; one per instance, so the slots of
    /// a gate that a reload replaced stay theirs until their permits end.
    holder: Bytes,
    /// The store slots held here.
    held: DashMap<String, ()>,
    /// The local slots of each scope and cap.
    slots: DashMap<(String, u32), Arc<Semaphore>>,
    /// When an acquire of a scope and cap last found every store slot taken.
    full: DashMap<(String, u32), Instant>,
    /// The slot the next acquire tries first, so acquires spread over them.
    next: AtomicUsize,
    released: Notify,
}

impl std::fmt::Debug for FleetSemaphore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetSemaphore")
            .field("held", &self.held.len())
            .finish()
    }
}

impl FleetSemaphore {
    /// A semaphore over `kv`, with its refresher on the current reactor.
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Arc<Self> {
        let semaphore = Arc::new(Self {
            kv,
            holder: Bytes::from(uuid::Uuid::new_v4().simple().to_string()),
            held: DashMap::new(),
            slots: DashMap::new(),
            full: DashMap::new(),
            next: AtomicUsize::new(0),
            released: Notify::new(),
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(refresh(Arc::downgrade(&semaphore)));
        }
        semaphore
    }

    /// The local slots of `scope` under the cap `max`.
    fn slots_of(&self, scope: &str, max: u32) -> Arc<Semaphore> {
        Arc::clone(
            self.slots
                .entry((scope.to_owned(), max))
                .or_insert_with(|| Arc::new(Semaphore::new(max as usize)))
                .value(),
        )
    }

    /// Whether an acquire of `scope` found the fleet full less than
    /// [`FULL_HOLD`] ago.
    fn recently_full(&self, scope: &str, max: u32) -> bool {
        self.full
            .get(&(scope.to_owned(), max))
            .is_some_and(|at| at.elapsed() < FULL_HOLD)
    }

    /// One permit of `scope` if fewer than `max` are held in the fleet.
    pub async fn try_acquire(
        self: &Arc<Self>,
        scope: &str,
        max: u32,
    ) -> Result<Option<FleetPermit>, mcpg_cluster_api::ClusterError> {
        let Ok(local) = self.slots_of(scope, max).try_acquire_owned() else {
            // This replica holds or is taking `max` permits already.
            return Ok(None);
        };
        if self.recently_full(scope, max) {
            return Ok(None);
        }
        Ok(self.take(scope, max, local).await?.ok())
    }

    /// Take a free store slot of `scope` for the holder of the local slot
    /// `local`: the permit, or `local` back when every slot is taken.
    async fn take(
        self: &Arc<Self>,
        scope: &str,
        max: u32,
        local: OwnedSemaphorePermit,
    ) -> Result<Result<FleetPermit, OwnedSemaphorePermit>, mcpg_cluster_api::ClusterError> {
        let first = self.next.fetch_add(1, Ordering::Relaxed);
        for n in 0..max as usize {
            let index = ((first + n) % max as usize) as u32;
            let key = slot_key(scope, max, index);
            if self
                .kv
                .put_if_absent(&key, self.holder.clone(), Some(SLOT_TTL))
                .await?
            {
                self.held.insert(key.clone(), ());
                return Ok(Ok(FleetPermit {
                    semaphore: Arc::clone(self),
                    key,
                    scope: (scope.to_owned(), max),
                    local: Some(local),
                }));
            }
        }
        self.full.insert((scope.to_owned(), max), Instant::now());
        Ok(Err(local))
    }

    /// [`Self::try_acquire`], trying again until `timeout` has passed. A
    /// permit given back on this replica wakes the waiters at once; one given
    /// back elsewhere is found on the next try.
    pub async fn acquire_within(
        self: &Arc<Self>,
        scope: &str,
        max: u32,
        timeout: Duration,
    ) -> Result<Option<FleetPermit>, mcpg_cluster_api::ClusterError> {
        let deadline = Instant::now() + timeout;
        let Ok(Ok(mut local)) =
            tokio::time::timeout(timeout, self.slots_of(scope, max).acquire_owned()).await
        else {
            return Ok(None);
        };
        let mut backoff = RETRY_MIN;
        loop {
            // Registered before the try, so a release during it is not missed.
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if !self.recently_full(scope, max) {
                local = match self.take(scope, max, local).await? {
                    Ok(permit) => return Ok(Some(permit)),
                    Err(local) => local,
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = jitter(backoff).min(deadline - now);
            tokio::select! {
                () = released => {}
                () = tokio::time::sleep(wait) => {}
            }
            backoff = (backoff * 2).min(RETRY_MAX);
        }
    }

    /// Free the store slot `key`. A slot that could not be freed is taken
    /// until its TTL ends; that only refuses.
    async fn free(&self, key: &str) {
        for attempt in 0..3u32 {
            match self.kv.delete(key).await {
                Ok(_) => return,
                Err(error) if attempt == 2 => {
                    tracing::warn!(key, %error, "fleet concurrency slot not freed; it ends with its TTL");
                }
                Err(_) => tokio::time::sleep(RETRY_MIN * (attempt + 1)).await,
            }
        }
    }

    /// Give a permit back: free its store slot, then its local slot, and wake
    /// the waiters of this replica.
    fn release(
        self: &Arc<Self>,
        key: String,
        scope: (String, u32),
        local: Option<OwnedSemaphorePermit>,
    ) {
        self.held.remove(&key);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // The slot ends with its TTL; nothing refreshes it now.
            return;
        };
        let semaphore = Arc::clone(self);
        handle.spawn(async move {
            semaphore.free(&key).await;
            semaphore.full.remove(&scope);
            drop(local);
            semaphore.released.notify_waiters();
        });
    }

    /// Drop the local slots of scopes that hold none now, and the marks of
    /// scopes found full longer ago than [`FULL_HOLD`].
    fn prune(&self) {
        self.slots
            .retain(|(_, max), slots| slots.available_permits() < *max as usize);
        // A pass that races an acquire can leave two slot sets of one scope
        // for a moment; the store's slots still hold the cap.
        self.full.retain(|_, at| at.elapsed() < FULL_HOLD);
    }
}

/// A permit of a [`FleetSemaphore`]; dropping it gives the permit back.
pub struct FleetPermit {
    semaphore: Arc<FleetSemaphore>,
    key: String,
    scope: (String, u32),
    /// The local slot, freed after the store slot.
    local: Option<OwnedSemaphorePermit>,
}

impl std::fmt::Debug for FleetPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetPermit")
            .field("key", &self.key)
            .finish()
    }
}

impl Drop for FleetPermit {
    fn drop(&mut self) {
        self.semaphore.release(
            std::mem::take(&mut self.key),
            std::mem::take(&mut self.scope),
            self.local.take(),
        );
    }
}

/// Write every slot this semaphore holds again, so it does not end under a
/// live permit. A slot found gone (the store lost it, or this replica could
/// not reach it for a TTL) is taken again when it is still free.
async fn refresh(semaphore: Weak<FleetSemaphore>) {
    let mut tick = tokio::time::interval(REFRESH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(semaphore) = semaphore.upgrade() else {
            return;
        };
        semaphore.prune();
        let held: Vec<String> = semaphore
            .held
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for key in held {
            match semaphore.kv.expire(&key, Some(SLOT_TTL)).await {
                Ok(true) => {}
                Ok(false) => {
                    let taken = semaphore
                        .kv
                        .put_if_absent(&key, semaphore.holder.clone(), Some(SLOT_TTL))
                        .await;
                    if matches!(taken, Ok(false)) {
                        tracing::warn!(
                            key,
                            "fleet concurrency slot was gone and another holder has it; the fleet holds one permit over its cap until this one ends"
                        );
                    } else {
                        tracing::warn!(key, "fleet concurrency slot was gone; written again");
                    }
                }
                Err(error) => {
                    tracing::debug!(key, %error, "fleet concurrency slot not refreshed; next pass");
                }
            }
        }
    }
}

/// `base` stretched by up to half again, so queued callers on different
/// replicas do not retry in step.
fn jitter(base: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let spread = base.as_micros().max(1) as u64 / 2;
    base + Duration::from_micros(u64::from(nanos) % spread.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::cluster_primitives::MemoryKv;

    fn kv() -> Arc<dyn KeyValueStore> {
        Arc::new(MemoryKv::new())
    }

    /// A store that takes `latency` for every operation, as a coordinator
    /// over the network does, and counts the operations.
    #[derive(Debug)]
    struct SlowKv {
        inner: MemoryKv,
        latency: Duration,
        ops: std::sync::atomic::AtomicU64,
    }

    impl SlowKv {
        fn new(latency: Duration) -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryKv::new(),
                latency,
                ops: std::sync::atomic::AtomicU64::new(0),
            })
        }

        async fn wait(&self) {
            self.ops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(self.latency).await;
        }

        fn ops(&self) -> u64 {
            self.ops.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    type KvResult<T> = Result<T, mcpg_cluster_api::ClusterError>;

    #[async_trait::async_trait]
    impl KeyValueStore for SlowKv {
        async fn get(&self, key: &str) -> KvResult<Option<mcpg_cluster_api::Entry>> {
            self.wait().await;
            self.inner.get(key).await
        }

        async fn put(&self, key: &str, value: bytes::Bytes, ttl: Option<Duration>) -> KvResult<()> {
            self.wait().await;
            self.inner.put(key, value, ttl).await
        }

        async fn put_if_absent(
            &self,
            key: &str,
            value: bytes::Bytes,
            ttl: Option<Duration>,
        ) -> KvResult<bool> {
            self.wait().await;
            self.inner.put_if_absent(key, value, ttl).await
        }

        async fn delete(&self, key: &str) -> KvResult<bool> {
            self.wait().await;
            self.inner.delete(key).await
        }

        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> KvResult<mcpg_cluster_api::KvPage> {
            self.wait().await;
            self.inner.list_page(prefix, cursor, limit).await
        }

        async fn expire(&self, key: &str, ttl: Option<Duration>) -> KvResult<bool> {
            self.wait().await;
            self.inner.expire(key, ttl).await
        }

        async fn incr(&self, key: &str, delta: i64, ttl: Option<Duration>) -> KvResult<i64> {
            self.wait().await;
            self.inner.incr(key, delta, ttl).await
        }
    }

    /// Callers spread over `replicas` that each try again at once when
    /// refused, holding an admitted permit for 10 ms, for one second over a
    /// store with a network's latency: the calls admitted, and the most in
    /// flight at once.
    async fn hammer(replicas: &[Arc<FleetSemaphore>], callers: usize, cap: u32) -> (u32, i64) {
        let in_flight = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut tasks = Vec::new();
        for n in 0..callers {
            let semaphore = Arc::clone(&replicas[n % replicas.len()]);
            let (in_flight, peak) = (Arc::clone(&in_flight), Arc::clone(&peak));
            tasks.push(tokio::spawn(async move {
                use std::sync::atomic::Ordering::SeqCst;
                let mut admitted = 0u32;
                while Instant::now() < deadline {
                    match semaphore.try_acquire("busy", cap).await.unwrap() {
                        Some(permit) => {
                            peak.fetch_max(in_flight.fetch_add(1, SeqCst) + 1, SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            in_flight.fetch_sub(1, SeqCst);
                            drop(permit);
                            admitted += 1;
                        }
                        None => tokio::time::sleep(Duration::from_micros(100)).await,
                    }
                }
                admitted
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += task.await.unwrap();
        }
        (admitted, peak.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Many callers on one replica: it admits up to the cap, and never more.
    #[tokio::test(start_paused = true)]
    async fn a_busy_replica_is_not_starved_by_its_own_refusals() {
        let store = SlowKv::new(Duration::from_millis(1));
        let semaphore = FleetSemaphore::new(Arc::clone(&store) as Arc<dyn KeyValueStore>);
        let (admitted, peak) = hammer(&[semaphore], 64, 4).await;
        assert!(peak <= 4, "at most 4 in flight, saw {peak}");
        // Four slots of 10 ms each, with a few ms of store work between
        // holders: well over 200 in the second.
        assert!(admitted > 200, "admitted {admitted}");
    }

    /// Many callers over four replicas: the fleet admits up to the cap, never
    /// more, and keeps admitting while every replica is refused most of the
    /// time.
    #[tokio::test(start_paused = true)]
    async fn a_busy_fleet_is_not_starved_by_its_own_refusals() {
        let store = SlowKv::new(Duration::from_millis(1));
        let replicas: Vec<Arc<FleetSemaphore>> = (0..4)
            .map(|_| FleetSemaphore::new(Arc::clone(&store) as Arc<dyn KeyValueStore>))
            .collect();
        let (admitted, peak) = hammer(&replicas, 64, 4).await;
        assert!(peak <= 4, "at most 4 in flight in the fleet, saw {peak}");
        assert!(admitted > 200, "admitted {admitted}");
    }

    /// An acquire on a replica that holds the cap is refused without a store
    /// operation.
    #[tokio::test]
    async fn a_full_replica_refuses_without_the_store() {
        let store = SlowKv::new(Duration::ZERO);
        let semaphore = FleetSemaphore::new(Arc::clone(&store) as Arc<dyn KeyValueStore>);
        let _first = semaphore.try_acquire("s", 2).await.unwrap().unwrap();
        let _second = semaphore.try_acquire("s", 2).await.unwrap().unwrap();
        let before = store.ops();
        for _ in 0..10 {
            assert!(semaphore.try_acquire("s", 2).await.unwrap().is_none());
        }
        assert_eq!(store.ops(), before);
    }

    /// A replica that found every slot taken refuses without the store for a
    /// moment, then asks it again.
    #[tokio::test(start_paused = true)]
    async fn a_full_fleet_is_refused_here_for_a_moment() {
        let store = SlowKv::new(Duration::ZERO);
        let kv = Arc::clone(&store) as Arc<dyn KeyValueStore>;
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(kv);
        let _held = a.try_acquire("s", 1).await.unwrap().unwrap();
        assert!(b.try_acquire("s", 1).await.unwrap().is_none());
        let asked = store.ops();
        assert!(b.try_acquire("s", 1).await.unwrap().is_none());
        assert_eq!(store.ops(), asked, "refused here, without the store");
        tokio::time::sleep(FULL_HOLD).await;
        assert!(b.try_acquire("s", 1).await.unwrap().is_none());
        assert!(
            store.ops() > asked,
            "after the hold the store decides again"
        );
    }

    #[tokio::test]
    async fn a_scope_admits_up_to_its_cap_across_replicas() {
        let kv = kv();
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(Arc::clone(&kv));
        let first = a.try_acquire("tool", 2).await.unwrap().expect("first");
        let second = b.try_acquire("tool", 2).await.unwrap().expect("second");
        assert!(a.try_acquire("tool", 2).await.unwrap().is_none());
        assert!(b.try_acquire("tool", 2).await.unwrap().is_none());
        assert!(
            a.try_acquire("other", 2).await.unwrap().is_some(),
            "scopes count apart"
        );

        drop(second);
        // The release is spawned; then A's mark of a full fleet ends.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(FULL_HOLD).await;
        let third = a.try_acquire("tool", 2).await.unwrap();
        assert!(third.is_some(), "a permit given back on B is free for A");
        drop(first);
    }

    /// A scope key that is another's prefix does not share its slots.
    #[tokio::test]
    async fn scopes_that_share_a_prefix_count_apart() {
        let semaphore = FleetSemaphore::new(kv());
        let _held = semaphore.try_acquire("alice", 1).await.unwrap().unwrap();
        assert!(
            semaphore
                .try_acquire("alice.evil", 1)
                .await
                .unwrap()
                .is_some()
        );
        assert!(semaphore.try_acquire("alice", 1).await.unwrap().is_none());
    }

    /// Many acquires at once never hold more than the cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_acquires_never_exceed_the_cap() {
        let kv = kv();
        let replicas: Vec<Arc<FleetSemaphore>> = (0..4)
            .map(|_| FleetSemaphore::new(Arc::clone(&kv)))
            .collect();
        let in_flight = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let mut tasks = Vec::new();
        for n in 0..64 {
            let semaphore = Arc::clone(&replicas[n % replicas.len()]);
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            tasks.push(tokio::spawn(async move {
                use std::sync::atomic::Ordering::SeqCst;
                let mut admitted = 0;
                for _ in 0..20 {
                    if let Some(permit) = semaphore.try_acquire("hot", 3).await.unwrap() {
                        let now = in_flight.fetch_add(1, SeqCst) + 1;
                        peak.fetch_max(now, SeqCst);
                        tokio::task::yield_now().await;
                        in_flight.fetch_sub(1, SeqCst);
                        drop(permit);
                        admitted += 1;
                    }
                }
                admitted
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += task.await.unwrap();
        }
        let peak = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak <= 3, "at most 3 in flight, saw {peak}");
        assert!(admitted > 0, "the cap admits work");
    }

    /// A refused acquire writes nothing: the store holds the held slot only.
    #[tokio::test]
    async fn a_refused_acquire_writes_nothing() {
        let kv = kv();
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(Arc::clone(&kv));
        let _held = a.try_acquire("s", 1).await.unwrap().unwrap();
        assert!(b.try_acquire("s", 1).await.unwrap().is_none());
        let slots = mcpg_cluster_api::list_all(&*kv, KEY_PREFIX).await.unwrap();
        assert_eq!(slots.len(), 1, "only the held permit's slot");
        assert_eq!(slots[0].1.bytes, a.holder);
    }

    /// A queued acquire gets the permit a holder on the same replica gives
    /// back, without waiting for its timeout.
    #[tokio::test]
    async fn a_queued_acquire_takes_a_released_permit() {
        let semaphore = FleetSemaphore::new(kv());
        let held = semaphore.try_acquire("q", 1).await.unwrap().unwrap();
        let waiter = {
            let semaphore = Arc::clone(&semaphore);
            tokio::spawn(async move {
                semaphore
                    .acquire_within("q", 1, Duration::from_secs(5))
                    .await
                    .unwrap()
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(held);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("the waiter wakes")
            .unwrap();
        assert!(got.is_some());
    }

    /// A queued acquire gets the permit another replica gives back.
    #[tokio::test]
    async fn a_queued_acquire_takes_a_permit_given_back_elsewhere() {
        let kv = kv();
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(kv);
        let held = a.try_acquire("q", 1).await.unwrap().unwrap();
        let waiter = {
            let b = Arc::clone(&b);
            tokio::spawn(async move {
                b.acquire_within("q", 1, Duration::from_secs(5))
                    .await
                    .unwrap()
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(held);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("the waiter finds the slot")
            .unwrap();
        assert!(got.is_some());
    }

    #[tokio::test]
    async fn a_queued_acquire_gives_up_at_its_timeout() {
        let semaphore = FleetSemaphore::new(kv());
        let _held = semaphore.try_acquire("q", 1).await.unwrap().unwrap();
        let started = Instant::now();
        let got = semaphore
            .acquire_within("q", 1, Duration::from_millis(120))
            .await
            .unwrap();
        assert!(got.is_none());
        assert!(started.elapsed() >= Duration::from_millis(120));
    }

    /// A slot whose holder stopped writing it ends with its TTL, as the store
    /// removes it, and another replica takes it then.
    #[tokio::test]
    async fn a_slot_the_store_removed_is_free_for_another_replica() {
        let kv = kv();
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(Arc::clone(&kv));
        let held = a.try_acquire("s", 1).await.unwrap().unwrap();
        assert!(kv.delete(&slot_key("s", 1, 0)).await.unwrap());
        assert!(b.try_acquire("s", 1).await.unwrap().is_some());
        // A stops holding the slot without a store write.
        std::mem::forget(held);
    }

    /// A held slot that the store lost is written again on the holder's next
    /// refresh.
    #[tokio::test(start_paused = true)]
    async fn a_lost_slot_is_written_again_while_its_permit_is_held() {
        let kv = kv();
        let live = FleetSemaphore::new(Arc::clone(&kv));
        let _held = live.try_acquire("s", 1).await.unwrap().unwrap();
        let key = slot_key("s", 1, 0);
        assert!(kv.delete(&key).await.unwrap());

        tokio::time::sleep(REFRESH * 2 + Duration::from_millis(1)).await;
        let entry = kv.get(&key).await.unwrap().expect("written again");
        assert_eq!(entry.bytes, live.holder);
        assert!(entry.expires_at.is_some());
    }
}
