//! Which replica runs the watcher of a resource.
//!
//! A subscribed URI hashes to one of [`WATCH_SHARDS`] shards, and each shard is
//! a fenced coordinator lock. The replica that holds a shard runs the watchers
//! of its URIs and fans each change out to every subscriber in the fleet, so a
//! change is detected once and told once, however many replicas serve the
//! subscribers. The replicas share the shards out evenly; the shards of a
//! replica that stops are free at once, those of one that dies when their
//! leases expire.
//!
//! Without a coordinator this replica holds every shard.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mcpg_cluster_api::{BoxActiveLease, ClusterBackend};

/// Watch shards.
pub const WATCH_SHARDS: u32 = 32;
/// TTL of a shard lease.
pub const SHARD_LEASE_TTL: Duration = Duration::from_secs(15);
/// Lock key prefix of a watch shard.
const SHARD_LOCK_PREFIX: &str = "watch-shard-";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The shard of `uri`.
pub fn shard_of(uri: &str) -> u32 {
    let digest = hmac_sha256::Hash::hash(uri.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % WATCH_SHARDS
}

/// Where a member starts looking for free shards, so members that start
/// together reach for different ones first.
fn shard_offset(member: &str) -> u32 {
    shard_of(member)
}

/// The shards this replica holds, readable by every watcher without a lock.
#[derive(Debug)]
pub struct ShardSet {
    /// Per shard, the end of its held lease in Unix milliseconds; 0 when not
    /// held.
    held_until: [AtomicU64; WATCH_SHARDS as usize],
}

impl ShardSet {
    /// Every shard, for good.
    pub fn all() -> Self {
        Self {
            held_until: std::array::from_fn(|_| AtomicU64::new(u64::MAX)),
        }
    }

    /// No shard.
    pub fn none() -> Self {
        Self {
            held_until: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Whether this replica holds `shard` now. A lease past its end is not
    /// held, even before a renewal has failed: another replica may hold it.
    pub fn owns(&self, shard: u32) -> bool {
        self.held_until
            .get(shard as usize)
            .is_some_and(|until| until.load(Ordering::Acquire) > now_ms())
    }

    /// Whether this replica runs the watcher of `uri` now.
    pub fn owns_uri(&self, uri: &str) -> bool {
        self.owns(shard_of(uri))
    }

    /// The shards this replica holds now, in order.
    pub fn owned(&self) -> Vec<u32> {
        (0..WATCH_SHARDS)
            .filter(|shard| self.owns(*shard))
            .collect()
    }

    /// Hold every shard for good: this replica has no coordinator to share
    /// them on.
    pub fn hold_all(&self) {
        for slot in &self.held_until {
            slot.store(u64::MAX, Ordering::Release);
        }
    }

    fn hold(&self, shard: u32, until_ms: u64) {
        if let Some(slot) = self.held_until.get(shard as usize) {
            slot.store(until_ms, Ordering::Release);
        }
    }

    fn drop_shard(&self, shard: u32) {
        self.hold(shard, 0);
    }

    fn drop_all(&self) {
        for slot in &self.held_until {
            slot.store(0, Ordering::Release);
        }
    }
}

/// What one [`ShardLeases::maintain`] pass changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShardChange {
    pub taken: Vec<u32>,
    pub released: Vec<u32>,
    pub lost: Vec<u32>,
}

impl ShardChange {
    pub fn is_empty(&self) -> bool {
        self.taken.is_empty() && self.released.is_empty() && self.lost.is_empty()
    }
}

/// This replica's leases on the watch shards of a coordinator.
pub struct ShardLeases {
    backend: Arc<dyn ClusterBackend>,
    lock_prefix: String,
    leases: BTreeMap<u32, BoxActiveLease>,
    set: Arc<ShardSet>,
}

impl ShardLeases {
    /// Leases on `backend`, published through `set`. Two deployments that
    /// share a coordinator under different tenant segments hold shards of
    /// their own.
    pub fn new(
        backend: Arc<dyn ClusterBackend>,
        tenant_segment: Option<&str>,
        set: Arc<ShardSet>,
    ) -> Self {
        set.drop_all();
        let lock_prefix = match tenant_segment {
            Some(segment) => format!("{SHARD_LOCK_PREFIX}{segment}-"),
            None => SHARD_LOCK_PREFIX.to_owned(),
        };
        Self {
            backend,
            lock_prefix,
            leases: BTreeMap::new(),
            set,
        }
    }

    /// The coordinator these leases are on.
    pub fn backend(&self) -> &Arc<dyn ClusterBackend> {
        &self.backend
    }

    /// Renew the held shards, give back those above this replica's share of
    /// `members` live members, and take free shards up to it. `me` is this
    /// replica's member id.
    pub async fn maintain(&mut self, me: &str, members: usize) -> ShardChange {
        let mut change = ShardChange::default();
        for (shard, lease) in &self.leases {
            let started = now_ms();
            match lease.renew().await {
                Ok(()) => self.set.hold(*shard, held_until(lease, started)),
                Err(error) => {
                    tracing::warn!(shard, %error, "lost a watch shard lease; another replica takes it");
                    self.set.drop_shard(*shard);
                    change.lost.push(*shard);
                }
            }
        }
        for shard in &change.lost {
            self.leases.remove(shard);
        }

        let share = WATCH_SHARDS.div_ceil(members.max(1) as u32) as usize;
        let extra: Vec<u32> = self
            .leases
            .keys()
            .rev()
            .take(self.leases.len().saturating_sub(share))
            .copied()
            .collect();
        for shard in &extra {
            self.release(*shard).await;
        }
        change.released = extra;

        let start = shard_offset(me);
        for i in 0..WATCH_SHARDS {
            if self.leases.len() >= share {
                break;
            }
            let shard = (start + i) % WATCH_SHARDS;
            if self.leases.contains_key(&shard) {
                continue;
            }
            let started = now_ms();
            match self
                .backend
                .try_acquire_lock(&self.lock_key(shard), SHARD_LEASE_TTL)
                .await
            {
                Ok(Some(lease)) => {
                    self.set.hold(shard, held_until(&lease, started));
                    self.leases.insert(shard, lease);
                    change.taken.push(shard);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(shard, %error, "watch shard acquire failed; next pass");
                    break;
                }
            }
        }
        if !change.is_empty() {
            tracing::info!(
                taken = ?change.taken,
                released = ?change.released,
                lost = ?change.lost,
                held = self.leases.len(),
                share,
                members,
                "watch shards changed"
            );
        }
        metrics::gauge!("mcpg_watch_owned_shards").set(self.leases.len() as f64);
        change
    }

    /// Give every shard back, so the other replicas take them at once
    /// rather than on expiry.
    pub async fn release_all(&mut self) {
        let shards: Vec<u32> = self.leases.keys().copied().collect();
        for shard in shards {
            self.release(shard).await;
        }
        metrics::gauge!("mcpg_watch_owned_shards").set(0.0);
    }

    async fn release(&mut self, shard: u32) {
        self.set.drop_shard(shard);
        if let Some(lease) = self.leases.remove(&shard)
            && let Err(error) = lease.release().await
        {
            tracing::debug!(shard, %error, "watch shard release failed; it expires on its own");
        }
    }

    fn lock_key(&self, shard: u32) -> String {
        format!("{}{shard}", self.lock_prefix)
    }
}

/// The end of `lease` as this replica may count on it: never later than its
/// TTL from `started_ms`, taken before the call that granted or renewed it,
/// so a coordinator's clock cannot stretch it.
fn held_until(lease: &BoxActiveLease, started_ms: u64) -> u64 {
    let local = started_ms + SHARD_LEASE_TTL.as_millis() as u64;
    chrono::DateTime::parse_from_rfc3339(&lease.expires_at())
        .map(|t| (t.timestamp_millis().max(0) as u64).min(local))
        .unwrap_or(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::cluster_single_node::SingleNodeClusterBackend;

    fn backend() -> Arc<dyn ClusterBackend> {
        SingleNodeClusterBackend::with_node_id("n1")
    }

    #[test]
    fn a_uri_always_hashes_to_the_same_shard() {
        let shard = shard_of("file:///a.yaml");
        assert!(shard < WATCH_SHARDS);
        assert_eq!(shard_of("file:///a.yaml"), shard);
        let spread: std::collections::BTreeSet<u32> =
            (0..512).map(|i| shard_of(&format!("res://{i}"))).collect();
        assert_eq!(
            spread.len(),
            WATCH_SHARDS as usize,
            "512 URIs reach every shard"
        );
    }

    #[test]
    fn all_and_none() {
        assert_eq!(ShardSet::all().owned().len(), WATCH_SHARDS as usize);
        assert!(ShardSet::none().owned().is_empty());
    }

    #[test]
    fn a_lease_past_its_end_is_not_held() {
        let set = ShardSet::none();
        set.hold(3, now_ms() + 60_000);
        set.hold(4, now_ms().saturating_sub(1));
        assert!(set.owns(3));
        assert!(!set.owns(4), "an expired lease is not held");
        assert!(!set.owns(WATCH_SHARDS), "out of range is not held");
    }

    #[tokio::test]
    async fn one_member_takes_every_shard() {
        let set = Arc::new(ShardSet::none());
        let mut leases = ShardLeases::new(backend(), None, Arc::clone(&set));
        let change = leases.maintain("m1", 1).await;
        assert_eq!(change.taken.len(), WATCH_SHARDS as usize);
        assert_eq!(set.owned().len(), WATCH_SHARDS as usize);

        let again = leases.maintain("m1", 1).await;
        assert!(again.is_empty(), "a second pass renews and changes nothing");

        leases.release_all().await;
        assert!(set.owned().is_empty());
    }

    /// Two members on one coordinator split the shards; when one stops, the
    /// other takes them all on its next pass.
    #[tokio::test]
    async fn two_members_split_the_shards_and_one_takes_over() {
        let backend = backend();
        let a_set = Arc::new(ShardSet::none());
        let b_set = Arc::new(ShardSet::none());
        let mut a = ShardLeases::new(Arc::clone(&backend), None, Arc::clone(&a_set));
        let mut b = ShardLeases::new(Arc::clone(&backend), None, Arc::clone(&b_set));

        a.maintain("a", 1).await;
        assert_eq!(a_set.owned().len(), WATCH_SHARDS as usize);

        // B joins: A gives back what is above its share, B takes it.
        a.maintain("a", 2).await;
        b.maintain("b", 2).await;
        let half = (WATCH_SHARDS / 2) as usize;
        assert_eq!(a_set.owned().len(), half);
        assert_eq!(b_set.owned().len(), half);
        for shard in 0..WATCH_SHARDS {
            assert!(
                a_set.owns(shard) ^ b_set.owns(shard),
                "shard {shard} has exactly one holder"
            );
        }

        a.release_all().await;
        b.maintain("b", 1).await;
        assert_eq!(b_set.owned().len(), WATCH_SHARDS as usize);
    }

    /// Tenants that share a coordinator do not contend for each other's
    /// shards.
    #[tokio::test]
    async fn tenant_segments_hold_shards_of_their_own() {
        let backend = backend();
        let t1 = Arc::new(ShardSet::none());
        let t2 = Arc::new(ShardSet::none());
        let mut a = ShardLeases::new(Arc::clone(&backend), Some("t1"), Arc::clone(&t1));
        let mut b = ShardLeases::new(Arc::clone(&backend), Some("t2"), Arc::clone(&t2));
        a.maintain("a", 1).await;
        b.maintain("b", 1).await;
        assert_eq!(t1.owned().len(), WATCH_SHARDS as usize);
        assert_eq!(t2.owned().len(), WATCH_SHARDS as usize);
    }
}
