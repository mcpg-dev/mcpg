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
    /// What the plan allows MCP Events on this gateway.
    pub events: EventsPlan,
}

/// What the org's plan allows MCP Events on this gateway. A `None` cap and a
/// `false` hold are no limit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsPlan {
    /// Cap on live readers: webhook subscriptions, poll leases and open
    /// streams, plus the upstream subscriptions held for imported types.
    pub readers_limit: Option<u64>,
    /// The month's deliveries are used: they wait until `held_until`.
    pub deliveries_held: bool,
    /// The month's ingests are used: sources wait until `held_until`.
    pub ingest_held: bool,
    /// When a used allowance comes back: the start of the next period.
    pub held_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Cap on the event types served, declared and imported.
    pub types_limit: Option<u64>,
    /// Caps on what one event log keeps.
    pub retention_ms_limit: Option<u64>,
    pub retention_events_limit: Option<u64>,
    pub retention_bytes_limit: Option<u64>,
    /// Cap on the webhook retry window, in milliseconds.
    pub retry_window_ms_limit: Option<u64>,
}

impl EventsPlan {
    /// `retention` within the plan's caps: each bound the smaller of the
    /// configured one and the plan's. The byte bound never drops below the
    /// largest occurrence a log holds.
    pub fn retention(
        &self,
        retention: &crate::config::events::EventRetentionConfig,
    ) -> crate::config::events::EventRetentionConfig {
        let within = |configured: u64, cap: Option<u64>| {
            cap.map_or(configured, |cap| configured.min(cap.max(1)))
        };
        let max_bytes = match self.retention_bytes_limit {
            Some(cap) => Some(
                retention
                    .max_bytes_or_default()
                    .min(cap.max(crate::config::events::MAX_WEBHOOK_BODY_BYTES)),
            ),
            None => retention.max_bytes,
        };
        crate::config::events::EventRetentionConfig {
            max_age_ms: within(retention.max_age_ms, self.retention_ms_limit),
            max_events: within(retention.max_events, self.retention_events_limit),
            max_bytes,
        }
    }

    /// The webhook retry window in force: the configured one, or the plan's
    /// cap when that is shorter.
    pub fn retry_window_ms(&self, configured: u64) -> u64 {
        self.retry_window_ms_limit
            .map_or(configured, |cap| configured.min(cap.max(1)))
    }

    /// The seconds a held source or webhook sender waits: until the period
    /// ends.
    pub fn retry_after_secs(&self) -> u64 {
        secs_until(self.held_until)
    }
}

/// Whole seconds from now to `until`, at least 1; a minute when `until` is
/// unknown.
pub fn secs_until(until: Option<chrono::DateTime<chrono::Utc>>) -> u64 {
    match until {
        Some(until) => {
            let secs = (until - chrono::Utc::now()).num_seconds();
            u64::try_from(secs).unwrap_or(0).max(1)
        }
        None => 60,
    }
}

/// Fixed one-second window enforcing the licence's per-gateway RPS ceiling.
/// The count starts over at each epoch second, so a burst across a second
/// boundary can see up to twice the ceiling.
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

/// A provider whose status a test sets and changes, in place of an attached
/// control plane.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestQuota(Arc<parking_lot::Mutex<Option<QuotaStatusInfo>>>);

#[cfg(test)]
impl TestQuota {
    /// Tell the gateway about the events part of a plan.
    pub(crate) fn set_events(&self, events: EventsPlan) {
        self.set(QuotaStatusInfo {
            exhausted: false,
            until: None,
            remaining: None,
            limit: None,
            rps_limit: None,
            events,
        });
    }

    pub(crate) fn set(&self, status: QuotaStatusInfo) {
        *self.0.lock() = Some(status);
    }
}

#[cfg(test)]
impl QuotaStatusProvider for TestQuota {
    fn current(&self) -> Option<QuotaStatusInfo> {
        self.0.lock().clone()
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
            events: EventsPlan::default(),
        };
        let h = QuotaStatusHandle::new(Arc::new(FixedProvider(Mutex::new(Some(info.clone())))));
        let got = h.current().unwrap();
        assert!(got.exhausted);
        assert_eq!(got.remaining, Some(0));
        assert_eq!(got.limit, Some(1000));
    }

    #[test]
    fn the_plan_lowers_retention_and_the_retry_window_never_raises_them() {
        use crate::config::events::{EventRetentionConfig, MAX_WEBHOOK_BODY_BYTES};
        let configured = EventRetentionConfig::default();
        let unlimited = EventsPlan::default();
        assert_eq!(unlimited.retention(&configured), configured);
        assert_eq!(unlimited.retry_window_ms(900_000), 900_000);

        let free = EventsPlan {
            retention_ms_limit: Some(3_600_000),
            retention_events_limit: Some(1_000),
            retention_bytes_limit: Some(1 << 20),
            retry_window_ms_limit: Some(300_000),
            ..EventsPlan::default()
        };
        let held = free.retention(&configured);
        assert_eq!(held.max_age_ms, 3_600_000);
        assert_eq!(held.max_events, 1_000);
        assert_eq!(held.max_bytes, Some(1 << 20));
        assert_eq!(free.retry_window_ms(900_000), 300_000);
        assert_eq!(free.retry_window_ms(60_000), 60_000, "a shorter one stays");

        let small = EventRetentionConfig {
            max_age_ms: 60_000,
            max_events: 10,
            max_bytes: Some(MAX_WEBHOOK_BODY_BYTES),
        };
        assert_eq!(free.retention(&small), small, "never raised");

        let tiny = EventsPlan {
            retention_bytes_limit: Some(1),
            ..EventsPlan::default()
        };
        assert_eq!(
            tiny.retention(&configured).max_bytes,
            Some(MAX_WEBHOOK_BODY_BYTES),
            "a log still holds its largest occurrence"
        );
    }

    #[test]
    fn a_hold_names_the_seconds_to_the_period_end() {
        let plan = EventsPlan {
            ingest_held: true,
            held_until: Some(chrono::Utc::now() + chrono::Duration::seconds(90)),
            ..EventsPlan::default()
        };
        let secs = plan.retry_after_secs();
        assert!((88..=90).contains(&secs), "{secs}");
        assert_eq!(secs_until(None), 60);
        assert_eq!(
            secs_until(Some(chrono::Utc::now() - chrono::Duration::seconds(5))),
            1,
            "a passed end waits a second, not none"
        );
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
