//! CP-pushed quota status surface.
//!
//! Mirrors the recorder pattern in [`cp_metrics`]: the gateway
//! holds a small handle that the dispatch hot-path consults
//! before invoking a tool. The cp-attached integrator wires a
//! real provider that reads from the cp-client's
//! `Arc<ArcSwap<Option<QuotaStatus>>>`; the standalone gateway
//! stays on the no-op default with zero cost.
//!
//! The types here mirror the proto `QuotaStatus` shape but are
//! defined outside the cp-client crate so the runtime doesn't
//! need a feature-gated `mcpg-control-plane-core` dep.

use std::sync::Arc;

/// Snapshot of the latest quota signal the CP has pushed for
/// this gateway's org. `None` from the provider means
/// unmetered or not-yet-known — the dispatch hot-path falls
/// through.
#[derive(Clone, Debug)]
pub struct QuotaStatusInfo {
    pub exhausted: bool,
    /// Wall-clock the CP says the quota window resets at.
    /// Used for the `Retry-After` header on refused calls.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    /// Per-gateway requests-per-second ceiling from the licence. A SAFEGUARD
    /// against runaway usage, not a meter: load above it is shed so a loop
    /// cannot burn a month's allowance in minutes. `None` when uncapped.
    pub rps_limit: Option<u32>,
}

/// Sliding one-second counter enforcing the licence's per-gateway RPS ceiling.
///
/// Deliberately per-PROCESS, not cluster-wide. It is a blast-radius cap on one
/// gateway, and a coordinated limiter would need a round-trip on the hot path
/// to protect against something a local counter already bounds. N replicas may
/// therefore serve up to N x the ceiling in aggregate — which is consistent
/// with the ceiling being *per gateway*, and with replicas being a paid axis.
/// Window and count in ONE atomic word: the epoch second in the high bits, the
/// requests counted in that second in the low bits.
///
/// They cannot be two atomics. Resetting the counter on a new second and
/// incrementing it are a single logical step, and split across two words a
/// thread that lost the window swap can increment *before* the winner zeroes
/// the count — its request vanishes and the ceiling admits more than it
/// should. One CAS over the pair makes the reset-and-count indivisible.
#[derive(Debug)]
pub struct RpsLimiter {
    state: std::sync::atomic::AtomicU64,
}

/// Low bits hold the per-second count. 20 bits caps a window at ~1.05M
/// requests, far above any licence ceiling; the remaining 44 bits carry epoch
/// seconds well past any date this will run on.
const COUNT_BITS: u32 = 20;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;

impl Default for RpsLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RpsLimiter {
    pub fn new() -> Self {
        Self {
            state: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record one request against `limit`; `false` means shed it.
    ///
    /// `limit` is read per call rather than stored, so a plan change takes
    /// effect on the next CP push with no restart and no re-plumbing.
    pub fn allow(&self, limit: u32, now_secs: u64) -> bool {
        use std::sync::atomic::Ordering;
        if limit == 0 {
            return true; // uncapped
        }
        let mut cur = self.state.load(Ordering::Relaxed);
        loop {
            let window = cur >> COUNT_BITS;
            let count = cur & COUNT_MASK;
            // A new second starts the budget over; otherwise this is the next
            // request within the current one.
            let next_count = if window == now_secs { count + 1 } else { 1 };
            if next_count > COUNT_MASK {
                return false; // saturated: shed rather than wrap
            }
            let next = (now_secs << COUNT_BITS) | next_count;
            match self
                .state
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                // This request is the Nth of its window; admit the first
                // `limit` of them.
                Ok(_) => return next_count <= u64::from(limit),
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Read-only handle to the latest CP quota status. Cheap to
/// clone (Arc bump). `record`-style providers must be lock-free
/// or short-critical-section — `current()` is called on every
/// tool dispatch.
pub trait QuotaStatusProvider: Send + Sync {
    fn current(&self) -> Option<QuotaStatusInfo>;
}

/// No-op provider used when no CP is attached. Returns `None`
/// — dispatch falls through.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopQuotaStatusProvider;

impl QuotaStatusProvider for NoopQuotaStatusProvider {
    fn current(&self) -> Option<QuotaStatusInfo> {
        None
    }
}

/// Cheap-to-clone wrapper with a default no-op backing.
#[derive(Clone)]
pub struct QuotaStatusHandle(Arc<dyn QuotaStatusProvider>);

impl QuotaStatusHandle {
    pub fn new(inner: Arc<dyn QuotaStatusProvider>) -> Self {
        Self(inner)
    }
    pub fn noop() -> Self {
        Self(Arc::new(NoopQuotaStatusProvider))
    }
    pub fn current(&self) -> Option<QuotaStatusInfo> {
        self.0.current()
    }
}

impl Default for QuotaStatusHandle {
    fn default() -> Self {
        Self::noop()
    }
}

impl std::fmt::Debug for QuotaStatusHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuotaStatusHandle").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test provider that returns whatever the test puts in its
    /// slot — proves the dispatch hot-path goes through the
    /// trait, not a concrete type.
    struct FixedProvider(Mutex<Option<QuotaStatusInfo>>);

    impl QuotaStatusProvider for FixedProvider {
        fn current(&self) -> Option<QuotaStatusInfo> {
            self.0.lock().unwrap().clone()
        }
    }

    #[test]
    fn default_handle_returns_none() {
        let h = QuotaStatusHandle::default();
        assert!(h.current().is_none());
    }

    #[test]
    fn handle_routes_to_provider() {
        let info = QuotaStatusInfo {
            exhausted: true,
            until: None,
            remaining: Some(0),
            limit: Some(1000),
            rps_limit: None,
        };
        let h = QuotaStatusHandle::new(Arc::new(FixedProvider(Mutex::new(Some(info.clone())))));
        let got = h.current().unwrap();
        assert!(got.exhausted);
        assert_eq!(got.remaining, Some(0));
        assert_eq!(got.limit, Some(1000));
    }
}

#[cfg(test)]
mod rps_tests {
    use super::*;

    /// The ceiling admits exactly `limit` requests in a second and sheds the
    /// rest — the safeguard is worthless if it is off by a factor.
    #[test]
    fn admits_up_to_the_limit_then_sheds() {
        let l = RpsLimiter::new();
        for i in 0..10 {
            assert!(l.allow(10, 1_000), "request {i} within the limit was shed");
        }
        assert!(
            !l.allow(10, 1_000),
            "the 11th request in the same second must shed"
        );
        assert!(!l.allow(10, 1_000));
    }

    /// The window is a second, not the process lifetime — a shed caller
    /// recovers on the next tick rather than being locked out.
    #[test]
    fn the_window_resets_each_second() {
        let l = RpsLimiter::new();
        for _ in 0..5 {
            assert!(l.allow(5, 1_000));
        }
        assert!(!l.allow(5, 1_000));
        assert!(l.allow(5, 1_001), "a new second opens a fresh budget");
    }

    /// A limit of zero is the licence vocabulary's "uncapped", not "refuse
    /// everything" — reading it the other way would take a tenant offline.
    #[test]
    fn zero_means_uncapped_not_closed() {
        let l = RpsLimiter::new();
        for _ in 0..10_000 {
            assert!(l.allow(0, 1_000));
        }
    }

    /// A plan change arrives as a new pushed limit; the next call must respect
    /// it without a restart.
    #[test]
    fn a_raised_limit_takes_effect_immediately() {
        let l = RpsLimiter::new();
        for _ in 0..3 {
            assert!(l.allow(3, 1_000));
        }
        assert!(!l.allow(3, 1_000), "shed under the old ceiling");
        assert!(
            l.allow(10, 1_000),
            "a raised ceiling admits the same second"
        );
    }

    /// Counting must be shared across threads: a per-task counter would let
    /// concurrency multiply the ceiling, which is the case the safeguard is
    /// for.
    #[test]
    fn the_ceiling_holds_under_concurrency() {
        use std::sync::Arc;
        let l = Arc::new(RpsLimiter::new());
        let admitted = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let l = l.clone();
            let admitted = admitted.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    if l.allow(50, 2_000) {
                        admitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let n = admitted.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            n, 50,
            "800 concurrent requests against a 50/s ceiling admitted {n}"
        );
    }

    /// The window reset and the increment must be ONE step. Split across two
    /// atomics, a thread that lost the window swap could increment before the
    /// winner zeroed the count — that increment vanished and the ceiling
    /// admitted more than it should.
    ///
    /// Every thread here starts on a window the limiter has not seen, which is
    /// exactly when the reset races, and the run repeats because a race that
    /// loses one time in ten passes a single attempt happily. This is the case
    /// that failed in CI while passing locally.
    #[test]
    fn the_window_reset_does_not_lose_requests() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        for round in 0..25u64 {
            let l = Arc::new(RpsLimiter::new());
            let admitted = Arc::new(AtomicU32::new(0));
            let start = Arc::new(std::sync::Barrier::new(8));
            let second = 9_000 + round; // never yet seen by this limiter
            let mut handles = Vec::new();
            for _ in 0..8 {
                let (l, admitted, start) = (l.clone(), admitted.clone(), start.clone());
                handles.push(std::thread::spawn(move || {
                    start.wait(); // pile into the reset together
                    for _ in 0..50 {
                        if l.allow(20, second) {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            let n = admitted.load(Ordering::Relaxed);
            assert_eq!(
                n, 20,
                "round {round}: threads racing the window reset admitted {n} against a 20/s ceiling"
            );
        }
    }
}
