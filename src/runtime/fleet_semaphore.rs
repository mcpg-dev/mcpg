//! A counting semaphore that the replicas of a fleet share through the quota
//! store.
//!
//! Each replica keeps one counter per scope, `quotas.concurrency.<scope>.<holder>`,
//! of the permits it holds. An acquire adds one to its own counter, then sums
//! the counters of the scope, and keeps the permit only when the sum is within
//! the cap. That never admits more than the cap: of any set of acquires that
//! hold permits at once, the one whose sum started last counted every other's
//! increment, so it saw more than the cap if the set did. Under contention two
//! acquires can both see the other and both give up; a caller in `queue` mode
//! tries again. A refused acquire takes its increment back before it returns,
//! so it does not count against the acquires after it.
//!
//! A counter lives [`COUNTER_TTL`] after its last write, and its holder writes
//! it again every [`REFRESH`] while it holds permits, so the permits of a
//! replica that dies come back within the TTL.

#![cfg(feature = "governance-quotas")]

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use mcpg_cluster_api::KeyValueStore;
use tokio::sync::Notify;

/// How long a counter outlives its last write.
pub const COUNTER_TTL: Duration = Duration::from_secs(30);
/// How often a holder writes its counters again.
pub const REFRESH: Duration = Duration::from_secs(10);
const KEY_PREFIX: &str = "quotas.concurrency.";
/// Back-off between two tries of a queued acquire, before jitter.
const RETRY_MIN: Duration = Duration::from_millis(20);
const RETRY_MAX: Duration = Duration::from_millis(250);

fn encode(scope: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(scope.as_bytes())
}

/// The fleet-wide semaphore of one quota store.
pub struct FleetSemaphore {
    kv: Arc<dyn KeyValueStore>,
    /// This semaphore's counter suffix; one per instance, so the permits of
    /// a gate that a reload replaced keep their own counter until they end.
    holder: String,
    /// Permits held here, per own counter key.
    held: DashMap<String, usize>,
    released: Notify,
}

impl std::fmt::Debug for FleetSemaphore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetSemaphore")
            .field("holder", &self.holder)
            .field("scopes", &self.held.len())
            .finish()
    }
}

impl FleetSemaphore {
    /// A semaphore over `kv`, with its refresher on the current reactor.
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Arc<Self> {
        let semaphore = Arc::new(Self {
            kv,
            holder: uuid::Uuid::new_v4().simple().to_string(),
            held: DashMap::new(),
            released: Notify::new(),
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(refresh(Arc::downgrade(&semaphore)));
        }
        semaphore
    }

    /// One permit of `scope` if fewer than `max` are held in the fleet.
    pub async fn try_acquire(
        self: &Arc<Self>,
        scope: &str,
        max: u32,
    ) -> Result<Option<FleetPermit>, mcpg_cluster_api::ClusterError> {
        let prefix = format!("{KEY_PREFIX}{}.", encode(scope));
        let own = format!("{prefix}{}", self.holder);
        let mine = self.kv.incr(&own, 1, Some(COUNTER_TTL)).await?;
        *self.held.entry(own.clone()).or_default() += 1;
        // From here a drop gives the permit back, also on an error below.
        let permit = FleetPermit {
            semaphore: Arc::clone(self),
            key: own,
        };
        if mine > i64::from(max) {
            permit.give_back().await;
            return Ok(None);
        }
        let total: i64 = mcpg_cluster_api::list_all(&*self.kv, &prefix)
            .await?
            .iter()
            .filter_map(|(_, entry)| mcpg_cluster_api::parse_counter(&entry.bytes).ok())
            .map(|count| count.max(0))
            .sum();
        if total > i64::from(max) {
            permit.give_back().await;
            return Ok(None);
        }
        Ok(Some(permit))
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
        let mut backoff = RETRY_MIN;
        loop {
            // Registered before the try, so a release during it is not missed.
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if let Some(permit) = self.try_acquire(scope, max).await? {
                return Ok(Some(permit));
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

    /// Stop counting one permit of `key` as held here.
    fn forget(&self, key: &str) {
        if let Some(mut held) = self.held.get_mut(key) {
            *held = held.saturating_sub(1);
        }
        self.held.remove_if(key, |_, held| *held == 0);
    }

    /// Take one permit off the counter `key` in the store.
    async fn give_back_count(&self, key: &str) {
        for attempt in 0..3u32 {
            match self.kv.incr(key, -1, Some(COUNTER_TTL)).await {
                Ok(_) => break,
                Err(error) if attempt == 2 => {
                    // The counter overstates this replica's permits until it
                    // expires or is written again; that only denies.
                    tracing::warn!(key, %error, "fleet concurrency permit not given back");
                }
                Err(_) => tokio::time::sleep(RETRY_MIN * (attempt + 1)).await,
            }
        }
    }

    /// Give a held permit back and wake the waiters of this replica. A
    /// refused acquire gives its count back without the wake, or a waiter
    /// would wake itself on each of its own refusals.
    fn release(self: &Arc<Self>, key: String) {
        self.forget(&key);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // The counter expires with its TTL; nothing refreshes it now.
            return;
        };
        let semaphore = Arc::clone(self);
        handle.spawn(async move {
            semaphore.give_back_count(&key).await;
            semaphore.released.notify_waiters();
        });
    }
}

/// A permit of a [`FleetSemaphore`]; dropping it gives the permit back.
pub struct FleetPermit {
    semaphore: Arc<FleetSemaphore>,
    key: String,
}

impl std::fmt::Debug for FleetPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetPermit")
            .field("key", &self.key)
            .finish()
    }
}

impl FleetPermit {
    /// Give a refused permit back, and return once the store has it: an
    /// acquire that is refused must not count against the acquires after it.
    async fn give_back(mut self) {
        let key = std::mem::take(&mut self.key);
        self.semaphore.forget(&key);
        self.semaphore.give_back_count(&key).await;
    }
}

impl Drop for FleetPermit {
    fn drop(&mut self) {
        // Empty once `give_back` took the key.
        if !self.key.is_empty() {
            self.semaphore.release(std::mem::take(&mut self.key));
        }
    }
}

/// Write every counter this semaphore holds permits on again, so it does not
/// expire under live permits. A counter found gone (the store lost it, or this
/// replica could not reach it for a TTL) is written back with the permits
/// held here.
async fn refresh(semaphore: Weak<FleetSemaphore>) {
    let mut tick = tokio::time::interval(REFRESH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(semaphore) = semaphore.upgrade() else {
            return;
        };
        let held: Vec<(String, usize)> = semaphore
            .held
            .iter()
            .filter(|entry| *entry.value() > 0)
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        for (key, count) in held {
            match semaphore.kv.expire(&key, Some(COUNTER_TTL)).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        key,
                        count,
                        "fleet concurrency counter was gone; written again"
                    );
                    let _ = semaphore
                        .kv
                        .incr(&key, count as i64, Some(COUNTER_TTL))
                        .await;
                }
                Err(error) => {
                    tracing::debug!(key, %error, "fleet concurrency counter not refreshed; next pass");
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
        // The give-back is spawned.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        let third = a.try_acquire("tool", 2).await.unwrap();
        assert!(third.is_some(), "a permit given back on B is free for A");
        drop(first);
    }

    /// A scope key that is another's prefix does not share its count.
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

    /// A refused acquire has taken its increment back when it returns: a
    /// give-back left to a background task would still count here, as this
    /// runtime runs no other task before the next statement.
    #[tokio::test]
    async fn a_refused_acquire_leaves_no_count_behind() {
        let kv = kv();
        let a = FleetSemaphore::new(Arc::clone(&kv));
        let b = FleetSemaphore::new(Arc::clone(&kv));
        let _held = a.try_acquire("s", 1).await.unwrap().unwrap();
        assert!(b.try_acquire("s", 1).await.unwrap().is_none());
        let counted: i64 =
            mcpg_cluster_api::list_all(&*kv, &format!("{KEY_PREFIX}{}.", encode("s")))
                .await
                .unwrap()
                .iter()
                .filter_map(|(_, entry)| mcpg_cluster_api::parse_counter(&entry.bytes).ok())
                .sum();
        assert_eq!(counted, 1, "only the held permit counts");
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

    /// A holder's counter that the store lost is written back with the
    /// permits the holder still has, on its next refresh.
    #[tokio::test(start_paused = true)]
    async fn a_lost_counter_is_written_back_while_permits_are_held() {
        let kv = kv();
        let live = FleetSemaphore::new(Arc::clone(&kv));
        let _first = live.try_acquire("s", 5).await.unwrap().unwrap();
        let _second = live.try_acquire("s", 5).await.unwrap().unwrap();
        let own = format!("{KEY_PREFIX}{}.{}", encode("s"), live.holder);
        assert!(kv.delete(&own).await.unwrap());

        tokio::time::sleep(REFRESH * 2 + Duration::from_millis(1)).await;
        let entry = kv.get(&own).await.unwrap().expect("written back");
        assert_eq!(mcpg_cluster_api::parse_counter(&entry.bytes).unwrap(), 2);
        assert!(entry.expires_at.is_some());
    }
}
