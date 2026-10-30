//! Runtime quota gate — enforces operator-declared rate limits,
//! budgets, and concurrency caps from `governance.quotas:` against
//! incoming requests.
//!
//! # Where this lives in the dispatch pipeline
//!
//! The gate sits between the policy gate and the binding executor:
//!
//! ```text
//! request → policy_chain (tool.call.pre)
//!        → trust-level pre-dispatch policy
//!        → QUOTA GATE  (this module)         ← refuses on limit hit
//!        → binding dispatch
//! ```
//!
//! When [`QuotaGate::evaluate`] returns
//! [`QuotaDecision::Deny`], the caller emits an audit event and
//! turns the deny into a 429-style JSON-RPC error before ever
//! reaching the binding. When it returns [`QuotaDecision::Allow`],
//! dispatch proceeds normally and the gate's bookkeeping (counter
//! decrement, concurrency permit acquisition) is committed.
//!
//! # Atomicity
//!
//! Rate-limit state rides [`mcpg_cluster_api::KeyValueStore::incr`],
//! the coordinator's atomic add-and-get, so replicas sharing a KV
//! cannot double-spend the same bucket: every consume is one atomic
//! counter advance (see [`consume_token_bucket`] for the encoding).
//! An in-process per-key `Mutex` still serializes local callers —
//! that keeps single-instance allow/deny decisions exactly
//! sequential; across replicas the only contention artifact is a
//! bounded, self-healing over-deny at the limit boundary (a denied
//! call's refund racing another replica's consume), never an
//! over-grant.
//!
//! A budget is atomic counters too: the window's calls, tokens and
//! micro-dollars each move only by `incr` under keys of the window
//! ([`BudgetWindow`]), so replicas sharing the store never lose a
//! charge. A `call_count` cap is exact: the call counts itself and
//! gives the count back when that went over. Tokens and cost are known
//! only after the call ([`QuotaGate::charge_usage`] charges what the
//! backend reported), so a call starts while the spend is under the
//! cap, and the one call that crosses it can go over.
//!
//! A concurrency cap counts the fleet. In a fleet the permits are
//! slots in the quota store ([`super::fleet_semaphore::FleetSemaphore`]:
//! `max_concurrent` slots per scope, each taken by one acquire), so
//! `max_concurrent` is the number of calls in flight across every
//! replica; a replica that dies gives its slots back within the slot
//! TTL. On a
//! single node an in-process [`tokio::sync::Semaphore`] per scope
//! is exact and costs no store call. `on_exceeded: queue` waits up
//! to `queue_timeout_ms` for a permit in both cases.

#![cfg(feature = "governance-quotas")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};

use crate::config::quotas::{
    BackendQuotasRef, BudgetPolicy, ConcurrencyPolicy, QuotasConfig, RateLimitPolicy,
};
use crate::runtime::RequestIdentity;
use mcpg_cluster_api::KeyValueStore;

/// Outcome of a single quota evaluation.
#[derive(Debug)]
pub enum QuotaDecision {
    /// The request may proceed. `permit` is `Some` when the
    /// gate acquired a concurrency permit that must be released
    /// when the request finishes (or fails). The caller holds
    /// the permit through the binding execution and drops it on
    /// completion. `warnings` are the budgets this call moved past
    /// their `warn_at_pct`.
    Allow {
        permit: Option<ConcurrencyPermit>,
        warnings: Vec<QuotaWarning>,
    },
    /// The request must be refused. `policy_id` names the
    /// specific policy that blocked it; `kind` says whether it
    /// was a rate / budget / concurrency policy. Higher layers
    /// translate this into a 429-style error and emit the
    /// `governance.quota.exceeded` audit event.
    Deny {
        policy_id: String,
        kind: QuotaKind,
        reason: String,
    },
}

/// A budget whose spend one call moved past its `warn_at_pct`; the caller
/// emits `governance.quota.warn` for it.
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaWarning {
    pub policy_id: String,
    /// `calls`, `tokens` or `usd`.
    pub measure: &'static str,
    pub used: f64,
    pub cap: f64,
    pub warn_at_pct: u8,
}

/// Which policy kind blocked a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    RateLimit,
    Budget,
    Concurrency,
}

impl QuotaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            QuotaKind::RateLimit => "rate_limit",
            QuotaKind::Budget => "budget",
            QuotaKind::Concurrency => "concurrency",
        }
    }
}

/// RAII permit returned by the gate for `scope: per_*` concurrency
/// policies. Dropping the permit (or letting it fall out of scope)
/// releases the in-flight slot, regardless of whether the request
/// succeeded. The caller is expected to drop after binding
/// dispatch returns; we don't tie permit lifetime to the
/// `QuotaDecision` itself so the consumer can move it.
#[must_use = "permit must outlive the binding execution; drop after dispatch returns"]
pub struct ConcurrencyPermit {
    _inner: PermitInner,
}

enum PermitInner {
    Replica {
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
    Fleet {
        _permit: super::fleet_semaphore::FleetPermit,
    },
}

impl std::fmt::Debug for ConcurrencyPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyPermit").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// QuotaStore — KV wrapper with per-key serialization.
// ---------------------------------------------------------------------------

/// Wrapper around the operator-resolved
/// [`mcpg_cluster_api::KeyValueStore`] that adds in-process
/// per-key serialization on top of the KV's own atomicity.
/// Rate-limit accounting drives the KV's atomic `incr` under the
/// per-key lock (locally sequential decisions, cross-replica-atomic
/// spend); budget counters use `incr` alone.
#[derive(Debug)]
pub struct QuotaStore {
    kv: Arc<dyn KeyValueStore>,
    /// The same keyspace without the state cipher, for the rate-limit and
    /// budget counters: `incr` keeps them plaintext, and a sealed view
    /// refuses to read one.
    counters: Arc<dyn KeyValueStore>,
    locks: DashMap<String, Arc<Mutex<()>>>,
    /// Refusals this replica knows to hold, so it refuses without the store.
    refusals: Refusals,
}

/// How long a refused budget is refused here without asking the store
/// again: a call the budget counted and gave back can make room.
const BUDGET_REFUSAL_HOLD_MS: i64 = 1_000;
/// How far past a full bucket's horizon a rate bucket may be before a
/// consume brings it back. Refused consumes that have not given their token
/// back yet move it by an interval each, far less than this.
const TAT_REPAIR_SLACK_US: i64 = 60_000_000;
/// Entries a refusal map keeps before it drops the ended ones.
const REFUSALS_PRUNE_AT: usize = 4_096;

/// Rate-limit buckets and budgets that refuse every call until a known
/// time.
#[derive(Debug, Default)]
struct Refusals {
    /// Per bucket key: the µs until which no consume fits, with the
    /// bucket's emission interval and capacity it was worked out for.
    buckets: DashMap<String, (i64, i64, i64)>,
    /// Per budget base: the ms until which it refuses, and the measure.
    budgets: DashMap<String, (i64, &'static str)>,
}

impl Refusals {
    fn bucket_refuses(&self, key: &str, interval_us: i64, capacity_us: i64, now_us: i64) -> bool {
        self.buckets.get(key).is_some_and(|refusal| {
            let (until_us, interval, capacity) = *refusal;
            until_us > now_us && interval == interval_us && capacity == capacity_us
        })
    }

    fn refuse_bucket(
        &self,
        key: &str,
        until_us: i64,
        interval_us: i64,
        capacity_us: i64,
        now_us: i64,
    ) {
        if until_us <= now_us {
            return;
        }
        // No longer than an empty bucket takes to fill, so a bucket another
        // replica brought back is asked again soon.
        let until_us = until_us.min(
            now_us
                .saturating_add(capacity_us)
                .saturating_add(interval_us),
        );
        if self.buckets.len() >= REFUSALS_PRUNE_AT {
            self.buckets.retain(|_, refusal| refusal.0 > now_us);
        }
        self.buckets
            .insert(key.to_owned(), (until_us, interval_us, capacity_us));
    }

    fn budget_refuses(&self, base: &str, now_ms: i64) -> Option<&'static str> {
        self.budgets
            .get(base)
            .filter(|refusal| refusal.0 > now_ms)
            .map(|refusal| refusal.1)
    }

    fn refuse_budget(&self, base: &str, until_ms: i64, measure: &'static str, now_ms: i64) {
        if until_ms <= now_ms {
            return;
        }
        if self.budgets.len() >= REFUSALS_PRUNE_AT {
            self.budgets.retain(|_, refusal| refusal.0 > now_ms);
        }
        self.budgets.insert(base.to_owned(), (until_ms, measure));
    }
}

impl QuotaStore {
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Arc<Self> {
        Self::with_counters(Arc::clone(&kv), kv)
    }

    /// A store that keeps its sealed values in `kv` and its counters in
    /// `counters`, the same keyspace without the state cipher.
    pub fn with_counters(
        kv: Arc<dyn KeyValueStore>,
        counters: Arc<dyn KeyValueStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kv,
            counters,
            locks: DashMap::new(),
            refusals: Refusals::default(),
        })
    }

    /// Acquire (or create) the per-key serialization lock.
    fn lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        self.locks
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

// ---------------------------------------------------------------------------
// Token bucket primitive.
// ---------------------------------------------------------------------------

/// Maximum bucket capacity for a policy. Defaults to one second's
/// worth of refill (matches the doc on [`RateLimitPolicy::burst`]).
fn capacity_for(rate_per_min: u32, burst: Option<u32>) -> f64 {
    if let Some(b) = burst
        && b > 0
    {
        return f64::from(b);
    }
    // Default: one second's worth of refill = rate/60.
    (f64::from(rate_per_min) / 60.0).max(1.0)
}

/// Microseconds one token takes to refill (the GCRA emission
/// interval). Rounded division; config validation guarantees
/// `rate_per_min > 0`, the two `.max(1)`s are belts against a zero
/// sneaking past it and against a >60M/min rate rounding the
/// interval down to nothing.
fn emission_interval_us(rate_per_min: u32) -> i64 {
    let rate = i64::from(rate_per_min.max(1));
    ((60_000_000 + rate / 2) / rate).max(1)
}

/// Try to consume one token from the named bucket. Denied calls
/// consume nothing.
///
/// The bucket is GCRA — the continuous-refill token bucket expressed
/// as a single **theoretical-arrival-time (TAT) counter**, in µs since
/// the Unix epoch:
///
/// 1. consume: `TAT = max(TAT, now) + interval`, one atomic step of the
///    store ([`KeyValueStore::incr_floor`]) — a fresh or idle bucket starts
///    from now, so its refill caps at capacity (the `min(capacity, …)`
///    clamp of the classic formulation);
/// 2. decide: allow iff the new TAT ≤ `now + capacity·interval`;
/// 3. deny: refund the interval, so the denied call spent nothing.
///
/// Each step is one atomic operation on the shared counter, so replicas
/// can never grant the same token, and a refund racing a consume can only
/// over-deny. A store without `incr_floor` gets the raise and the add as
/// two operations ([`clamped_consume`]): replicas that find an idle bucket
/// at once then each count the time it lagged.
///
/// A refusal tells when the next consume can fit: TAT only grows while
/// replicas consume, so until `TAT + interval - capacity` every consume is
/// refused, and the replica refuses those without the store.
///
/// `key` is the operator-stable bucket key (typically
/// `quotas.rate_limit.<policy_id>.<scope_key>`).
/// `now_ms` is the wall-clock at evaluation time (passed in for
/// deterministic tests).
async fn consume_token_bucket(
    store: &QuotaStore,
    key: &str,
    policy: &RateLimitPolicy,
    now_ms: i64,
) -> Result<bool> {
    let interval_us = emission_interval_us(policy.rate.calls_per_minute);
    let capacity_us =
        (capacity_for(policy.rate.calls_per_minute, policy.burst) * interval_us as f64) as i64;
    let now_us = now_ms.saturating_mul(1000);
    // Storage hygiene: an hour idle and the counter is gone; the next
    // consume then starts from a full bucket. Sliding — every touch
    // re-arms it.
    let ttl = Some(Duration::from_secs(3600));

    let refused = || {
        store
            .refusals
            .bucket_refuses(key, interval_us, capacity_us, now_us)
    };
    if refused() {
        return Ok(false);
    }
    let lock = store.lock_for(key);
    let _guard = lock.lock().await;
    // A caller that waited for the lock behind a refused consume.
    if refused() {
        return Ok(false);
    }
    let mut tat = match store
        .counters
        .incr_floor(key, interval_us, now_us, ttl)
        .await
    {
        Ok(tat) => tat,
        Err(mcpg_cluster_api::ClusterError::Unsupported { .. }) => {
            clamped_consume(store, key, interval_us, now_us, ttl).await?
        }
        Err(e) => {
            return Err(anyhow::Error::from(e)
                .context(format!("quota_store: incr_floor failed for `{key}`")));
        }
    };
    // A bucket far past any consume — left by two-step clamps that counted
    // the idle time twice (on a new key, about the clock's epoch) — would
    // refuse for good. Bring it back to this one.
    if tat
        > now_us
            .saturating_add(capacity_us)
            .saturating_add(TAT_REPAIR_SLACK_US)
    {
        tat = store
            .counters
            .incr(key, now_us + interval_us - tat, ttl)
            .await
            .with_context(|| format!("quota_store: incr repair failed for `{key}`"))?;
    }
    let allowed = tat <= now_us.saturating_add(capacity_us);
    if !allowed {
        // Refund the consume. Best-effort: if the refund itself fails,
        // the deny stands (one token stays burned until refill) rather
        // than flipping an already-made decision onto the gate's
        // fail-open/fail-closed error path.
        match store.counters.incr(key, -interval_us, ttl).await {
            Ok(after) => store.refusals.refuse_bucket(
                key,
                after
                    .saturating_add(interval_us)
                    .saturating_sub(capacity_us),
                interval_us,
                capacity_us,
                now_us,
            ),
            Err(e) => {
                tracing::warn!(key, error = %e, "quota rate-limit refund failed; token stays burned");
            }
        }
    }
    Ok(allowed)
}

/// The consume of [`consume_token_bucket`] on a store without
/// `incr_floor`: add the interval, then, when the TAT before it was behind
/// `now` (a fresh or idle bucket), add the gap so the bucket refills to
/// exactly full. Two operations, so replicas that find an idle bucket at
/// once each add the gap.
async fn clamped_consume(
    store: &QuotaStore,
    key: &str,
    interval_us: i64,
    now_us: i64,
    ttl: Option<Duration>,
) -> Result<i64> {
    let tat = store
        .counters
        .incr(key, interval_us, ttl)
        .await
        .with_context(|| format!("quota_store: incr failed for `{key}`"))?;
    let behind = now_us - (tat - interval_us);
    if behind <= 0 {
        return Ok(tat);
    }
    store
        .counters
        .incr(key, behind, ttl)
        .await
        .with_context(|| format!("quota_store: incr clamp failed for `{key}`"))
}

// ---------------------------------------------------------------------------
// Concurrency primitive.
// ---------------------------------------------------------------------------

/// Per-scope-key concurrency tracker. One [`Semaphore`] per
/// `<policy_id, scope_key>` pair, sized to `max_concurrent`.
/// Acquisition returns an `OwnedSemaphorePermit` that the caller
/// holds for the duration of the binding execution.
#[derive(Debug, Default)]
struct ConcurrencyTracker {
    semaphores: DashMap<String, Arc<Semaphore>>,
}

impl ConcurrencyTracker {
    fn semaphore_for(&self, key: &str, max: u32) -> Arc<Semaphore> {
        self.semaphores
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(max as usize)))
            .clone()
    }

    /// Try to acquire a permit without blocking. Returns `None`
    /// when no permits are available — the caller turns that into
    /// a deny.
    fn try_acquire(&self, key: &str, max: u32) -> Option<ConcurrencyPermit> {
        let sem = self.semaphore_for(key, max);
        sem.try_acquire_owned().ok().map(|p| ConcurrencyPermit {
            _inner: PermitInner::Replica { _permit: p },
        })
    }

    /// Wait up to `timeout` for a permit.
    async fn acquire_within(
        &self,
        key: &str,
        max: u32,
        timeout: Duration,
    ) -> Option<ConcurrencyPermit> {
        let sem = self.semaphore_for(key, max);
        tokio::time::timeout(timeout, sem.acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
            .map(|p| ConcurrencyPermit {
                _inner: PermitInner::Replica { _permit: p },
            })
    }
}

/// Where a concurrency cap is counted.
#[derive(Debug)]
enum Concurrency {
    /// One process serves every call: an in-process semaphore is exact.
    Replica(ConcurrencyTracker),
    /// A fleet: the permits are counted in the quota store.
    Fleet(Arc<super::fleet_semaphore::FleetSemaphore>),
}

// ---------------------------------------------------------------------------
// Budget primitive (call / token / cost counters).
// ---------------------------------------------------------------------------

/// The record of the read-modify-write accounting the counters replace,
/// under `quotas.budget.<policy_id>.<scope_key>`: it seeds the count of
/// the window it was in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct BudgetState {
    cost_usd: f64,
    tokens: u64,
    calls: u64,
    window_started_unix_ms: i64,
}

/// A measure's cap as a counter value: whole calls and tokens, and
/// micro-dollars for cost.
fn usd_to_micro(usd: f64) -> i64 {
    (usd * 1_000_000.0).round() as i64
}

/// The current window of a budget scope.
///
/// The first call of a window writes its anchor `<base>.window`
/// (`put_if_absent`, TTL the window) with the window's start; the
/// window's counters are `<base>.<start>.calls|tokens|micro_usd`, which
/// move only by `incr` and live twice the window. A new window starts
/// from zero because its counters have new keys.
struct BudgetWindow {
    prefix: String,
    ttl: Duration,
    /// When the window ends, in Unix ms.
    ends_ms: i64,
}

impl BudgetWindow {
    async fn open(store: &QuotaStore, base: &str, window_ms: i64, now_ms: i64) -> Result<Self> {
        let window_ms = window_ms.max(1);
        let anchor = format!("{base}.window");
        let start = match read_start(store, &anchor).await? {
            Some(start) => start,
            None => {
                let legacy = legacy_budget(store, base, window_ms, now_ms).await;
                let start = legacy
                    .as_ref()
                    .map(|state| state.window_started_unix_ms)
                    .unwrap_or(now_ms);
                let left = Duration::from_millis((window_ms - (now_ms - start)).max(1) as u64);
                let opened = store
                    .kv
                    .put_if_absent(&anchor, Bytes::from(start.to_string()), Some(left))
                    .await
                    .with_context(|| {
                        format!("quota_store: budget window open failed for `{base}`")
                    })?;
                if opened {
                    if let Some(state) = legacy
                        && state.calls > 0
                    {
                        let calls = format!("{base}.{start}.calls");
                        let ttl = Duration::from_millis((window_ms as u64).saturating_mul(2));
                        // A counter: `add` adds to the stored digits.
                        let _ = store
                            .counters
                            .put_if_absent(&calls, Bytes::from(state.calls.to_string()), Some(ttl))
                            .await;
                    }
                    start
                } else {
                    // Another replica opened the window first.
                    read_start(store, &anchor).await?.unwrap_or(start)
                }
            }
        };
        Ok(Self {
            prefix: format!("{base}.{start}"),
            ttl: Duration::from_millis((window_ms as u64).saturating_mul(2)),
            ends_ms: start.saturating_add(window_ms),
        })
    }

    async fn read(&self, store: &QuotaStore, measure: &str) -> Result<i64> {
        let key = format!("{}.{measure}", self.prefix);
        match store
            .counters
            .get(&key)
            .await
            .with_context(|| format!("quota_store: get failed for `{key}`"))?
        {
            Some(entry) => Ok(mcpg_cluster_api::parse_counter(&entry.bytes).unwrap_or(0)),
            None => Ok(0),
        }
    }

    async fn add(&self, store: &QuotaStore, measure: &str, delta: i64) -> Result<i64> {
        let key = format!("{}.{measure}", self.prefix);
        store
            .counters
            .incr(&key, delta, Some(self.ttl))
            .await
            .with_context(|| format!("quota_store: incr failed for `{key}`"))
    }

    /// Give back the count of a call that did not run.
    async fn give_back_call(&self, store: &QuotaStore, policy_id: &str) {
        if let Err(error) = self.add(store, "calls", -1).await {
            // The count stays one high until the window ends; that only
            // denies.
            tracing::warn!(policy = %policy_id, %error, "budget call count not given back");
        }
    }
}

async fn read_start(store: &QuotaStore, anchor: &str) -> Result<Option<i64>> {
    Ok(store
        .kv
        .get(anchor)
        .await
        .with_context(|| format!("quota_store: get failed for `{anchor}`"))?
        .and_then(|entry| std::str::from_utf8(&entry.bytes).ok()?.parse().ok()))
}

/// The legacy record of `base`, while its window is still open.
async fn legacy_budget(
    store: &QuotaStore,
    base: &str,
    window_ms: i64,
    now_ms: i64,
) -> Option<BudgetState> {
    let entry = store.kv.get(base).await.ok()??;
    let state: BudgetState = serde_json::from_slice(&entry.bytes).ok()?;
    (now_ms - state.window_started_unix_ms < window_ms && state.window_started_unix_ms <= now_ms)
        .then_some(state)
}

/// The warning for a measure that moved from `before` to `after` past the
/// policy's `warn_at_pct` of `cap`.
fn crossing(
    policy: &BudgetPolicy,
    measure: &'static str,
    before: i64,
    after: i64,
    cap: i64,
    scale: f64,
) -> Option<QuotaWarning> {
    let pct = policy.warn_at_pct?;
    let threshold = (cap as f64 * f64::from(pct) / 100.0).ceil() as i64;
    (before < threshold && after >= threshold).then(|| QuotaWarning {
        policy_id: policy.id.clone(),
        measure,
        used: after as f64 / scale,
        cap: cap as f64 / scale,
        warn_at_pct: pct,
    })
}

/// The pre-flight result of a budget.
enum BudgetCheck {
    /// `counted` is the window the call was counted in, to give the count
    /// back if a later check refuses the call.
    Allowed {
        warnings: Vec<QuotaWarning>,
        counted: Option<BudgetWindow>,
    },
    Denied(&'static str),
}

/// Pre-flight: deny when spent tokens or cost already reach their caps;
/// count the call and deny (giving the count back) when that goes over
/// `cap_calls`. Caps set together deny on the first one reached. A
/// refused budget is refused here without the store for
/// [`BUDGET_REFUSAL_HOLD_MS`], at most to the end of its window.
async fn check_budget_pre_flight(
    store: &QuotaStore,
    base: &str,
    policy: &BudgetPolicy,
    now_ms: i64,
) -> Result<BudgetCheck> {
    if let Some(measure) = store.refusals.budget_refuses(base, now_ms) {
        return Ok(BudgetCheck::Denied(measure));
    }
    let window_ms = window_to_ms(&policy.window).unwrap_or(86_400_000);
    let window = BudgetWindow::open(store, base, window_ms, now_ms).await?;
    let refuse = |measure: &'static str| {
        let until = now_ms
            .saturating_add(BUDGET_REFUSAL_HOLD_MS)
            .min(window.ends_ms);
        store.refusals.refuse_budget(base, until, measure, now_ms);
        BudgetCheck::Denied(measure)
    };
    if let Some(cap) = policy.cap_token_count
        && window.read(store, "tokens").await? >= cap as i64
    {
        return Ok(refuse("tokens"));
    }
    if let Some(cap) = policy.cap_usd
        && window.read(store, "micro_usd").await? >= usd_to_micro(cap)
    {
        return Ok(refuse("usd"));
    }
    let Some(cap) = policy.cap_calls else {
        return Ok(BudgetCheck::Allowed {
            warnings: Vec::new(),
            counted: None,
        });
    };
    let cap = cap as i64;
    let calls = window.add(store, "calls", 1).await?;
    if calls > cap {
        window.give_back_call(store, &policy.id).await;
        return Ok(refuse("calls"));
    }
    Ok(BudgetCheck::Allowed {
        warnings: crossing(policy, "calls", calls - 1, calls, cap, 1.0)
            .into_iter()
            .collect(),
        counted: Some(window),
    })
}

/// Charge what a call used to its budget's token and cost counters.
async fn charge_budget(
    store: &QuotaStore,
    base: &str,
    policy: &BudgetPolicy,
    usage: &mcpg_plugin_protocol::BackendUsage,
    now_ms: i64,
) -> Result<Vec<QuotaWarning>> {
    let window_ms = window_to_ms(&policy.window).unwrap_or(86_400_000);
    let window = BudgetWindow::open(store, base, window_ms, now_ms).await?;
    let mut warnings = Vec::new();
    let tokens = usage.input_tokens.saturating_add(usage.output_tokens);
    if let Some(cap) = policy.cap_token_count
        && tokens > 0
    {
        let delta = i64::try_from(tokens).unwrap_or(i64::MAX);
        let after = window.add(store, "tokens", delta).await?;
        warnings.extend(crossing(
            policy,
            "tokens",
            after.saturating_sub(delta),
            after,
            cap as i64,
            1.0,
        ));
    }
    if let Some(cap) = policy.cap_usd
        && let Some(cost) = usage.cost_usd.filter(|cost| *cost > 0.0)
    {
        let delta = usd_to_micro(cost);
        let after = window.add(store, "micro_usd", delta).await?;
        warnings.extend(crossing(
            policy,
            "usd",
            after.saturating_sub(delta),
            after,
            usd_to_micro(cap),
            1_000_000.0,
        ));
    }
    Ok(warnings)
}

/// Convert a window string ("60s", "5m", "24h", "1d") to ms.
/// Returns `None` for unknown forms — caller falls back to
/// 24h. Strict validation is done at config-load time
/// (`BudgetPolicy::validate`); this is a runtime decode.
fn window_to_ms(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (digits, unit): (String, char) = {
        let mut chars = trimmed.chars().peekable();
        let mut d = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                d.push(c);
                chars.next();
            } else {
                break;
            }
        }
        let u = chars.next()?;
        (d, u)
    };
    let n: i64 = digits.parse().ok()?;
    let mult = match unit {
        's' => 1_000,
        'm' => 60_000,
        'h' => 3_600_000,
        'd' => 86_400_000,
        _ => return None,
    };
    Some(n * mult)
}

// ---------------------------------------------------------------------------
// Gate dispatcher.
// ---------------------------------------------------------------------------

/// Gate state held by the runtime. Built once at boot from
/// `governance.quotas` + the resolved KV + the per-binding
/// `quotas:` references; then queried via [`Self::evaluate`] on
/// every dispatch.
#[derive(Debug)]
pub struct QuotaGate {
    store: Arc<QuotaStore>,
    rate_limits: HashMap<String, RateLimitPolicy>,
    budgets: HashMap<String, BudgetPolicy>,
    concurrency_policies: HashMap<String, ConcurrencyPolicy>,
    concurrency: Concurrency,
    /// Per-binding `quotas:` reference, keyed by binding name
    /// (the operator-facing tool/prompt/resource id used at
    /// dispatch time). Built at boot from
    /// `mcp.capabilities.{tools,prompts,resources,resource_templates}[].quotas`
    /// — bindings without a `quotas:` block are absent from
    /// the map and skip the gate entirely.
    binding_refs: HashMap<String, BackendQuotasRef>,
    /// When true, a gate-internal error (e.g. quota-store failure) is
    /// treated as Allow (fail-open). Default false: a gate error denies
    /// the call so a storage outage can't silently disable enforcement.
    fail_open_on_error: bool,
}

impl QuotaGate {
    /// Construct from the operator's `governance.quotas:` registry
    /// and the per-binding `quotas:` references collected from
    /// every `mcp.capabilities.*[]` entry. The dispatch hook in
    /// the runtime calls [`Self::evaluate_for_tool`] which looks
    /// up the binding's ref by name. `fleet` counts concurrency caps
    /// in the store, for a store the replicas of a fleet share.
    pub fn new(
        quotas: &QuotasConfig,
        binding_refs: HashMap<String, BackendQuotasRef>,
        store: Arc<QuotaStore>,
        fleet: bool,
    ) -> Self {
        let rate_limits = quotas
            .rate_limits
            .iter()
            .map(|p| (p.id.clone(), p.clone()))
            .collect();
        let budgets = quotas
            .budgets
            .iter()
            .map(|p| (p.id.clone(), p.clone()))
            .collect();
        let concurrency_policies = quotas
            .concurrency
            .iter()
            .map(|p| (p.id.clone(), p.clone()))
            .collect();
        let concurrency = if fleet {
            Concurrency::Fleet(super::fleet_semaphore::FleetSemaphore::new(Arc::clone(
                &store.kv,
            )))
        } else {
            Concurrency::Replica(ConcurrencyTracker::default())
        };
        Self {
            store,
            rate_limits,
            budgets,
            concurrency_policies,
            concurrency,
            binding_refs,
            fail_open_on_error: quotas.fail_open_on_error(),
        }
    }

    /// A permit of the concurrency `scope`, waiting up to `queue` for one.
    async fn acquire_concurrency(
        &self,
        scope: &str,
        max: u32,
        queue: Option<Duration>,
    ) -> Result<Option<ConcurrencyPermit>> {
        match &self.concurrency {
            Concurrency::Replica(tracker) => Ok(match queue {
                None => tracker.try_acquire(scope, max),
                Some(timeout) => tracker.acquire_within(scope, max, timeout).await,
            }),
            Concurrency::Fleet(semaphore) => {
                let permit = match queue {
                    None => semaphore.try_acquire(scope, max).await,
                    Some(timeout) => semaphore.acquire_within(scope, max, timeout).await,
                }
                .with_context(|| format!("fleet concurrency count failed for `{scope}`"))?;
                Ok(permit.map(|p| ConcurrencyPermit {
                    _inner: PermitInner::Fleet { _permit: p },
                }))
            }
        }
    }

    /// Operator posture when the gate itself errors: `true` = proceed
    /// without a permit (fail-open), `false` (default) = refuse the call.
    #[must_use]
    pub fn fail_open_on_error(&self) -> bool {
        self.fail_open_on_error
    }

    /// True when no policies AND no per-binding refs are
    /// configured — the dispatch hook short-circuits to Allow
    /// without taking any locks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rate_limits.is_empty()
            && self.budgets.is_empty()
            && self.concurrency_policies.is_empty()
            && self.binding_refs.is_empty()
    }

    /// Convenience wrapper used by the dispatch hook: given a
    /// tool name, look up the binding's `quotas:` reference; if
    /// none is declared, fast-path Allow without per-key locks
    /// or KV round-trips. Otherwise dispatch to [`Self::evaluate`].
    pub async fn evaluate_for_tool(
        &self,
        tool_name: &str,
        session_id: Option<&str>,
        identity: &RequestIdentity,
    ) -> Result<QuotaDecision> {
        let allow = || QuotaDecision::Allow {
            permit: None,
            warnings: Vec::new(),
        };
        let Some(bref) = self.binding_refs.get(tool_name) else {
            return Ok(allow());
        };
        if bref.is_empty() {
            return Ok(allow());
        }
        self.evaluate(QuotaEvalContext {
            bref,
            tool_name,
            session_id,
            identity,
        })
        .await
    }

    /// Charge what a call to `tool_name` used to its budget's token and
    /// cost counters, after the call. Returns the budgets the charge moved
    /// past their `warn_at_pct`.
    pub async fn charge_usage(
        &self,
        tool_name: &str,
        session_id: Option<&str>,
        identity: &RequestIdentity,
        usage: &mcpg_plugin_protocol::BackendUsage,
    ) -> Result<Vec<QuotaWarning>> {
        let Some(bref) = self.binding_refs.get(tool_name) else {
            return Ok(Vec::new());
        };
        let Some(policy) = bref.budget.as_deref().and_then(|id| self.budgets.get(id)) else {
            return Ok(Vec::new());
        };
        if policy.cap_token_count.is_none() && policy.cap_usd.is_none() {
            return Ok(Vec::new());
        }
        let ctx = QuotaEvalContext {
            bref,
            tool_name,
            session_id,
            identity,
        };
        let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
        let key = format!("quotas.budget.{}.{}", policy.id, scope_key);
        charge_budget(
            &self.store,
            &key,
            policy,
            usage,
            Utc::now().timestamp_millis(),
        )
        .await
    }

    /// Evaluate the binding's `quotas:` block against the
    /// runtime's policies. Order: rate limit → budget →
    /// concurrency. The first deny wins; concurrency is acquired
    /// last so a deny upstream doesn't leak permits.
    pub async fn evaluate(&self, ctx: QuotaEvalContext<'_>) -> Result<QuotaDecision> {
        let now_ms = Utc::now().timestamp_millis();

        // Rate limit check.
        if let Some(id) = ctx.bref.rate_limit.as_deref()
            && let Some(policy) = self.rate_limits.get(id)
        {
            let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
            let key = format!("quotas.rate_limit.{}.{}", policy.id, scope_key);
            let allowed = consume_token_bucket(&self.store, &key, policy, now_ms).await?;
            if !allowed {
                return Ok(QuotaDecision::Deny {
                    policy_id: policy.id.clone(),
                    kind: QuotaKind::RateLimit,
                    reason: format!(
                        "rate-limit `{}` exhausted for scope `{}`",
                        policy.id, scope_key
                    ),
                });
            }
        }

        // Budget check.
        let mut warnings = Vec::new();
        let mut counted: Option<(BudgetWindow, &str)> = None;
        if let Some(id) = ctx.bref.budget.as_deref()
            && let Some(policy) = self.budgets.get(id)
        {
            let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
            let key = format!("quotas.budget.{}.{}", policy.id, scope_key);
            match check_budget_pre_flight(&self.store, &key, policy, now_ms).await? {
                BudgetCheck::Allowed {
                    warnings: crossed,
                    counted: window,
                } => {
                    warnings = crossed;
                    counted = window.map(|window| (window, policy.id.as_str()));
                }
                BudgetCheck::Denied(measure) => {
                    return Ok(QuotaDecision::Deny {
                        policy_id: policy.id.clone(),
                        kind: QuotaKind::Budget,
                        reason: format!(
                            "budget `{}` exhausted for scope `{}` ({measure})",
                            policy.id, scope_key
                        ),
                    });
                }
            }
        }

        // Concurrency permit (last — acquire only when everything
        // else has passed, otherwise we'd leak permits on rate /
        // budget denies).
        let permit = if let Some(id) = ctx.bref.concurrency.as_deref()
            && let Some(policy) = self.concurrency_policies.get(id)
        {
            let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
            // A separator no policy id carries, so `a.b`+`c` and `a`+`b.c`
            // count apart.
            let key = format!("{}\u{1f}{}", policy.id, scope_key);
            let queue = (policy.on_exceeded == "queue")
                .then(|| Duration::from_millis(policy.queue_timeout_ms));
            let acquired = self
                .acquire_concurrency(&key, policy.max_concurrent, queue)
                .await;
            if !matches!(acquired, Ok(Some(_)))
                && let Some((window, budget_id)) = &counted
            {
                // The call the budget counted does not run.
                window.give_back_call(&self.store, budget_id).await;
            }
            match acquired? {
                Some(p) => Some(p),
                None => {
                    let waited = queue
                        .map(|q| format!("; waited {} ms", q.as_millis()))
                        .unwrap_or_default();
                    return Ok(QuotaDecision::Deny {
                        policy_id: policy.id.clone(),
                        kind: QuotaKind::Concurrency,
                        reason: format!(
                            "concurrency cap `{}` reached for scope `{}` ({}/{} in flight{waited})",
                            policy.id, scope_key, policy.max_concurrent, policy.max_concurrent,
                        ),
                    });
                }
            }
        } else {
            None
        };

        Ok(QuotaDecision::Allow { permit, warnings })
    }
}

/// Per-call context passed to [`QuotaGate::evaluate`].
pub struct QuotaEvalContext<'a> {
    /// The binding's per-binding quotas reference.
    pub bref: &'a BackendQuotasRef,
    /// Tool name (used for `scope: per_tool` keying).
    pub tool_name: &'a str,
    /// Session id (used for `scope: per_session` keying). `None`
    /// for sessionless requests.
    pub session_id: Option<&'a str>,
    /// Caller identity (used for `scope: per_identity` keying via
    /// the policy's `identity_claim:` path).
    pub identity: &'a RequestIdentity,
}

/// Compute the scope key for a policy. The key forms part of the
/// KV bucket path / concurrency-tracker map key and determines
/// who shares a bucket.
fn scope_key(scope: &str, identity_claim: Option<&str>, ctx: &QuotaEvalContext<'_>) -> String {
    match scope {
        "per_identity" => {
            // Claim-path lookup: resolve the configured claim
            // against the identity's attributes. Falls back to
            // `principal_id()` (subject_id for HttpHeader/Verified)
            // when no claim path was named. Anonymous callers
            // share an `anonymous` bucket.
            if let Some(claim) = identity_claim {
                if let RequestIdentity::Verified { attributes, .. } = ctx.identity
                    && let Some(v) = attributes.get(claim)
                {
                    return v.clone();
                }
                // Fallback to subject_id when claim is absent.
                ctx.identity
                    .principal_id()
                    .unwrap_or("anonymous")
                    .to_owned()
            } else {
                ctx.identity
                    .principal_id()
                    .unwrap_or("anonymous")
                    .to_owned()
            }
        }
        "per_session" => ctx.session_id.unwrap_or("no-session").to_owned(),
        "per_tool" => ctx.tool_name.to_owned(),
        // `global` and any unknown scope (RFC compatibility — new
        // scope names land schema-side first; runtime gracefully
        // degrades to a single shared bucket).
        _ => "global".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::quotas::RateLimitRate;
    use mcpg_cluster_api::Entry;

    /// Minimal in-memory KV for unit tests. The real backend
    /// (cluster.MemoryKv) lives in builtins/cluster_primitives,
    /// which we'd need to thread through; for unit-level tests
    /// of the bucket/budget logic this stub suffices.
    #[derive(Debug, Default)]
    struct StubKv {
        inner: tokio::sync::Mutex<HashMap<String, Bytes>>,
    }

    #[async_trait::async_trait]
    impl mcpg_cluster_api::KeyValueStore for StubKv {
        async fn get(
            &self,
            key: &str,
        ) -> std::result::Result<Option<Entry>, mcpg_cluster_api::error::ClusterError> {
            Ok(self
                .inner
                .lock()
                .await
                .get(key)
                .cloned()
                .map(|bytes| Entry {
                    bytes,
                    expires_at: None,
                }))
        }

        async fn put(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Option<Duration>,
        ) -> std::result::Result<(), mcpg_cluster_api::error::ClusterError> {
            self.inner.lock().await.insert(key.to_owned(), value);
            Ok(())
        }

        async fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Option<Duration>,
        ) -> std::result::Result<bool, mcpg_cluster_api::error::ClusterError> {
            use std::collections::hash_map::Entry as HmEntry;
            match self.inner.lock().await.entry(key.to_owned()) {
                HmEntry::Occupied(_) => Ok(false),
                HmEntry::Vacant(v) => {
                    v.insert(value);
                    Ok(true)
                }
            }
        }

        async fn delete(
            &self,
            key: &str,
        ) -> std::result::Result<bool, mcpg_cluster_api::error::ClusterError> {
            Ok(self.inner.lock().await.remove(key).is_some())
        }

        async fn list_page(
            &self,
            _prefix: &str,
            _cursor: Option<&str>,
            _limit: usize,
        ) -> std::result::Result<mcpg_cluster_api::KvPage, mcpg_cluster_api::error::ClusterError>
        {
            Ok(mcpg_cluster_api::KvPage::default())
        }

        async fn expire(
            &self,
            _key: &str,
            _ttl: Option<Duration>,
        ) -> std::result::Result<bool, mcpg_cluster_api::error::ClusterError> {
            Ok(true)
        }

        async fn incr(
            &self,
            key: &str,
            delta: i64,
            _ttl: Option<Duration>,
        ) -> std::result::Result<i64, mcpg_cluster_api::error::ClusterError> {
            let mut m = self.inner.lock().await;
            let current = match m.get(key) {
                Some(b) => mcpg_cluster_api::parse_counter(b)?,
                None => 0,
            };
            let next = current + delta;
            m.insert(key.to_owned(), Bytes::from(next.to_string()));
            Ok(next)
        }

        async fn incr_floor(
            &self,
            key: &str,
            delta: i64,
            floor: i64,
            _ttl: Option<Duration>,
        ) -> std::result::Result<i64, mcpg_cluster_api::error::ClusterError> {
            let mut m = self.inner.lock().await;
            let current = match m.get(key) {
                Some(b) => mcpg_cluster_api::parse_counter(b)?,
                None => 0,
            };
            let next = mcpg_cluster_api::floor_add(current, floor, delta)?;
            m.insert(key.to_owned(), Bytes::from(next.to_string()));
            Ok(next)
        }
    }

    fn store() -> Arc<QuotaStore> {
        QuotaStore::new(Arc::new(StubKv::default()))
    }

    /// [`StubKv`] that counts the operations it serves.
    #[derive(Debug, Default)]
    struct CountingKv {
        inner: StubKv,
        ops: std::sync::atomic::AtomicU64,
    }

    impl CountingKv {
        fn count(&self) {
            self.ops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn ops(&self) -> u64 {
            self.ops.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    type KvResult<T> = std::result::Result<T, mcpg_cluster_api::error::ClusterError>;

    #[async_trait::async_trait]
    impl mcpg_cluster_api::KeyValueStore for CountingKv {
        async fn get(&self, key: &str) -> KvResult<Option<Entry>> {
            self.count();
            self.inner.get(key).await
        }

        async fn put(&self, key: &str, value: Bytes, ttl: Option<Duration>) -> KvResult<()> {
            self.count();
            self.inner.put(key, value, ttl).await
        }

        async fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            ttl: Option<Duration>,
        ) -> KvResult<bool> {
            self.count();
            self.inner.put_if_absent(key, value, ttl).await
        }

        async fn delete(&self, key: &str) -> KvResult<bool> {
            self.count();
            self.inner.delete(key).await
        }

        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> KvResult<mcpg_cluster_api::KvPage> {
            self.count();
            self.inner.list_page(prefix, cursor, limit).await
        }

        async fn expire(&self, key: &str, ttl: Option<Duration>) -> KvResult<bool> {
            self.count();
            self.inner.expire(key, ttl).await
        }

        async fn incr(&self, key: &str, delta: i64, ttl: Option<Duration>) -> KvResult<i64> {
            self.count();
            self.inner.incr(key, delta, ttl).await
        }

        async fn incr_floor(
            &self,
            key: &str,
            delta: i64,
            floor: i64,
            ttl: Option<Duration>,
        ) -> KvResult<i64> {
            self.count();
            self.inner.incr_floor(key, delta, floor, ttl).await
        }
    }

    /// A counter store whose first `PARTIES` counter calls all wait, after
    /// they took effect, until every one of them has: what replicas that
    /// consume an idle bucket at the same moment see.
    #[derive(Debug)]
    struct LockstepKv {
        inner: StubKv,
        arrived: std::sync::atomic::AtomicUsize,
        barrier: tokio::sync::Barrier,
        /// Answer `incr_floor` as a store without it.
        without_floor: bool,
    }

    impl LockstepKv {
        const PARTIES: usize = 4;

        fn new(without_floor: bool) -> Self {
            Self {
                inner: StubKv::default(),
                arrived: std::sync::atomic::AtomicUsize::new(0),
                barrier: tokio::sync::Barrier::new(Self::PARTIES),
                without_floor,
            }
        }

        async fn lockstep(&self) {
            if self
                .arrived
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                < Self::PARTIES
            {
                self.barrier.wait().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl mcpg_cluster_api::KeyValueStore for LockstepKv {
        async fn get(&self, key: &str) -> KvResult<Option<Entry>> {
            self.inner.get(key).await
        }

        async fn put(&self, key: &str, value: Bytes, ttl: Option<Duration>) -> KvResult<()> {
            self.inner.put(key, value, ttl).await
        }

        async fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            ttl: Option<Duration>,
        ) -> KvResult<bool> {
            self.inner.put_if_absent(key, value, ttl).await
        }

        async fn delete(&self, key: &str) -> KvResult<bool> {
            self.inner.delete(key).await
        }

        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> KvResult<mcpg_cluster_api::KvPage> {
            self.inner.list_page(prefix, cursor, limit).await
        }

        async fn expire(&self, key: &str, ttl: Option<Duration>) -> KvResult<bool> {
            self.inner.expire(key, ttl).await
        }

        async fn incr(&self, key: &str, delta: i64, ttl: Option<Duration>) -> KvResult<i64> {
            let v = self.inner.incr(key, delta, ttl).await?;
            self.lockstep().await;
            Ok(v)
        }

        async fn incr_floor(
            &self,
            key: &str,
            delta: i64,
            floor: i64,
            ttl: Option<Duration>,
        ) -> KvResult<i64> {
            if self.without_floor {
                return Err(mcpg_cluster_api::ClusterError::Unsupported {
                    reason: "test store without incr_floor".into(),
                });
            }
            let v = self.inner.incr_floor(key, delta, floor, ttl).await?;
            self.lockstep().await;
            Ok(v)
        }
    }

    /// Four replicas that consume an idle bucket at the same moment admit
    /// exactly its burst at that moment, and exactly the rate after it.
    #[tokio::test]
    async fn replicas_that_find_an_idle_bucket_at_once_admit_exactly_its_burst() {
        let kv = Arc::new(LockstepKv::new(false));
        let replicas: Vec<Arc<QuotaStore>> = (0..LockstepKv::PARTIES)
            .map(|_| QuotaStore::new(Arc::clone(&kv) as Arc<dyn KeyValueStore>))
            .collect();
        // 600/min, burst 10: one token every 100 ms, ten at once.
        let p = rate_limit_policy("p", 600, Some(10));
        let now_ms = 1_793_000_000_000;
        let first = futures::future::join_all(
            replicas
                .iter()
                .map(|r| consume_token_bucket(r, "k", &p, now_ms)),
        )
        .await;
        let mut admitted = first.into_iter().filter(|r| *r.as_ref().unwrap()).count();
        for i in 0..20 {
            let r = &replicas[i % replicas.len()];
            if consume_token_bucket(r, "k", &p, now_ms).await.unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 10, "the burst, no more and no fewer");
        let mut later = 0;
        for i in 0..20 {
            let r = &replicas[i % replicas.len()];
            if consume_token_bucket(r, "k", &p, now_ms + 1_000)
                .await
                .unwrap()
            {
                later += 1;
            }
        }
        assert_eq!(later, 10, "a second later, a second's worth of tokens");
    }

    /// On a store without `incr_floor` one replica still gets the burst and
    /// then the rate through the two-step consume.
    #[tokio::test]
    async fn a_store_without_incr_floor_keeps_the_two_step_consume() {
        let kv = Arc::new(LockstepKv::new(true));
        kv.arrived
            .store(LockstepKv::PARTIES, std::sync::atomic::Ordering::SeqCst);
        let s = QuotaStore::new(Arc::clone(&kv) as Arc<dyn KeyValueStore>);
        let p = rate_limit_policy("p", 600, Some(10));
        let now_ms = 1_793_000_000_000;
        let mut admitted = 0;
        for _ in 0..20 {
            if consume_token_bucket(&s, "k", &p, now_ms).await.unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 10);
        assert!(
            consume_token_bucket(&s, "k", &p, now_ms + 100)
                .await
                .unwrap()
        );
        assert!(
            !consume_token_bucket(&s, "k", &p, now_ms + 100)
                .await
                .unwrap()
        );
    }

    /// A refused consume tells when the next one can fit; until then the
    /// replica refuses without the store, and from then the store decides.
    #[tokio::test]
    async fn a_refused_bucket_skips_the_store_until_a_token_fits() {
        let kv = Arc::new(CountingKv::default());
        let s = QuotaStore::new(Arc::clone(&kv) as Arc<dyn KeyValueStore>);
        let p = rate_limit_policy("p", 60, Some(1));
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        assert!(!consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        let asked = kv.ops();
        for t in [1, 500, 999] {
            assert!(!consume_token_bucket(&s, "k", &p, t).await.unwrap());
        }
        assert_eq!(kv.ops(), asked, "refused here, without the store");
        assert!(consume_token_bucket(&s, "k", &p, 1_000).await.unwrap());
        assert!(kv.ops() > asked);
        // Another rate for the same key does not read this refusal.
        let faster = rate_limit_policy("p", 120, Some(1));
        assert!(!consume_token_bucket(&s, "k", &p, 1_000).await.unwrap());
        let asked = kv.ops();
        consume_token_bucket(&s, "k", &faster, 1_001).await.unwrap();
        assert!(kv.ops() > asked, "a reloaded policy asks the store");
    }

    /// Two replicas that find a new bucket idle at once each add the clock's
    /// epoch to it; the next consume brings it back, and the rate holds.
    #[tokio::test]
    async fn a_bucket_two_racing_clamps_sent_far_ahead_is_brought_back() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(1));
        let now_ms = 1_793_000_000_000;
        s.counters.incr("k", 2 * now_ms * 1000, None).await.unwrap();
        assert!(
            consume_token_bucket(&s, "k", &p, now_ms).await.unwrap(),
            "the next consume is admitted"
        );
        assert!(!consume_token_bucket(&s, "k", &p, now_ms).await.unwrap());
        assert!(
            consume_token_bucket(&s, "k", &p, now_ms + 1_000)
                .await
                .unwrap()
        );
    }

    /// A refusal is held here no longer than an empty bucket takes to fill.
    #[tokio::test]
    async fn a_refusal_is_held_here_no_longer_than_the_bucket_takes_to_fill() {
        let kv = Arc::new(CountingKv::default());
        let s = QuotaStore::new(Arc::clone(&kv) as Arc<dyn KeyValueStore>);
        let p = rate_limit_policy("p", 60, Some(1));
        // 30 s ahead: refused, but too close for a repair.
        s.counters.incr("k", 30_000_000, None).await.unwrap();
        assert!(!consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        let asked = kv.ops();
        assert!(!consume_token_bucket(&s, "k", &p, 1_999).await.unwrap());
        assert_eq!(kv.ops(), asked, "refused here, without the store");
        consume_token_bucket(&s, "k", &p, 2_000).await.unwrap();
        assert!(
            kv.ops() > asked,
            "asked again once an empty bucket could have filled"
        );
    }

    /// A refused budget is refused here without the store for a second, and
    /// then the store decides again.
    #[tokio::test]
    async fn a_refused_budget_is_held_here_for_a_second() {
        let kv = Arc::new(CountingKv::default());
        let s = QuotaStore::new(Arc::clone(&kv) as Arc<dyn KeyValueStore>);
        let policy = BudgetPolicy {
            cap_calls: Some(1),
            ..budget_policy("24h")
        };
        let now = Utc::now().timestamp_millis();
        let check = |at| check_budget_pre_flight(&s, "b", &policy, at);
        assert!(matches!(
            check(now).await.unwrap(),
            BudgetCheck::Allowed { .. }
        ));
        assert!(matches!(
            check(now).await.unwrap(),
            BudgetCheck::Denied("calls")
        ));
        let asked = kv.ops();
        assert!(matches!(
            check(now + 999).await.unwrap(),
            BudgetCheck::Denied("calls")
        ));
        assert_eq!(kv.ops(), asked, "refused here, without the store");
        assert!(matches!(
            check(now + 1_000).await.unwrap(),
            BudgetCheck::Denied("calls")
        ));
        assert!(kv.ops() > asked, "after the hold the store decides again");
    }

    fn rate_limit_policy(id: &str, calls_per_minute: u32, burst: Option<u32>) -> RateLimitPolicy {
        RateLimitPolicy {
            id: id.into(),
            kind: "token_bucket".into(),
            scope: "global".into(),
            identity_claim: None,
            rate: RateLimitRate { calls_per_minute },
            burst,
            on_exceeded: "deny".into(),
        }
    }

    // -- token bucket -------------------------------------------------

    #[tokio::test]
    async fn token_bucket_allows_first_call_with_full_capacity() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(5));
        let allowed = consume_token_bucket(&s, "k", &p, 0).await.unwrap();
        assert!(allowed, "first call hits a full bucket");
    }

    #[tokio::test]
    async fn token_bucket_denies_when_burst_drained() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(2));
        // Two calls drain the burst-2 bucket at the same instant.
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        // Third hits an empty bucket (refill at 1/sec; 0 ms elapsed).
        assert!(!consume_token_bucket(&s, "k", &p, 0).await.unwrap());
    }

    #[tokio::test]
    async fn token_bucket_refills_over_time() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(1));
        // Drain.
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        assert!(!consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        // 1100 ms later: refill rate 1/sec → ~1.1 tokens accumulated.
        assert!(consume_token_bucket(&s, "k", &p, 1100).await.unwrap());
    }

    #[tokio::test]
    async fn token_bucket_caps_at_capacity() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(2));
        // Drain.
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        assert!(consume_token_bucket(&s, "k", &p, 0).await.unwrap());
        // Hours later — refill should cap at capacity (2), not
        // accumulate unboundedly.
        assert!(consume_token_bucket(&s, "k", &p, 3_600_000).await.unwrap());
        assert!(consume_token_bucket(&s, "k", &p, 3_600_000).await.unwrap());
        assert!(!consume_token_bucket(&s, "k", &p, 3_600_000).await.unwrap());
    }

    #[tokio::test]
    async fn token_bucket_separate_keys_dont_share_state() {
        let s = store();
        let p = rate_limit_policy("p", 60, Some(1));
        assert!(consume_token_bucket(&s, "alice", &p, 0).await.unwrap());
        // Bob's bucket is independent — full 1-token capacity.
        assert!(consume_token_bucket(&s, "bob", &p, 0).await.unwrap());
        assert!(!consume_token_bucket(&s, "alice", &p, 0).await.unwrap());
    }

    // -- window_to_ms -------------------------------------------------

    #[test]
    fn window_to_ms_handles_basic_units() {
        assert_eq!(window_to_ms("60s"), Some(60_000));
        assert_eq!(window_to_ms("5m"), Some(300_000));
        assert_eq!(window_to_ms("24h"), Some(86_400_000));
        assert_eq!(window_to_ms("1d"), Some(86_400_000));
    }

    #[test]
    fn window_to_ms_returns_none_on_garbage() {
        assert_eq!(window_to_ms(""), None);
        assert_eq!(window_to_ms("60"), None);
        assert_eq!(window_to_ms("60x"), None);
        assert_eq!(window_to_ms("abc"), None);
    }

    // -- scope_key ----------------------------------------------------

    #[tokio::test]
    async fn scope_key_per_tool_uses_tool_name() {
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let bref = BackendQuotasRef::default();
        let ctx = QuotaEvalContext {
            bref: &bref,
            tool_name: "my-tool",
            session_id: None,
            identity: &identity,
        };
        assert_eq!(scope_key("per_tool", None, &ctx), "my-tool");
    }

    #[tokio::test]
    async fn scope_key_per_identity_falls_back_to_anonymous() {
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let bref = BackendQuotasRef::default();
        let ctx = QuotaEvalContext {
            bref: &bref,
            tool_name: "my-tool",
            session_id: None,
            identity: &identity,
        };
        assert_eq!(scope_key("per_identity", None, &ctx), "anonymous");
    }

    #[tokio::test]
    async fn scope_key_per_identity_resolves_claim_from_attributes() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("org_id".into(), "acme-corp".into());
        let identity = RequestIdentity::Verified {
            subject_id: "user-1".into(),
            issuer: "iss".into(),
            auth_provider: "oidc".into(),
            source: "test".into(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: attrs,
        };
        let bref = BackendQuotasRef::default();
        let ctx = QuotaEvalContext {
            bref: &bref,
            tool_name: "my-tool",
            session_id: None,
            identity: &identity,
        };
        assert_eq!(scope_key("per_identity", Some("org_id"), &ctx), "acme-corp");
    }

    #[tokio::test]
    async fn scope_key_global_is_constant() {
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let bref = BackendQuotasRef::default();
        let ctx = QuotaEvalContext {
            bref: &bref,
            tool_name: "my-tool",
            session_id: Some("sess-1"),
            identity: &identity,
        };
        assert_eq!(scope_key("global", None, &ctx), "global");
    }

    // -- gate end-to-end ----------------------------------------------

    #[tokio::test]
    async fn gate_allows_when_no_refs_set() {
        let qc = QuotasConfig::default();
        let gate = QuotaGate::new(&qc, HashMap::new(), store(), false);
        let bref = BackendQuotasRef::default();
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let decision = gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap();
        assert!(matches!(decision, QuotaDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn gate_denies_on_drained_rate_limit() {
        let mut qc = QuotasConfig::default();
        qc.rate_limits.push(rate_limit_policy("rl", 60, Some(1)));
        let gate = QuotaGate::new(&qc, HashMap::new(), store(), false);
        let bref = BackendQuotasRef {
            rate_limit: Some("rl".into()),
            ..Default::default()
        };
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        // First call passes (burst=1 → 1 token).
        assert!(matches!(
            gate.evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap(),
            QuotaDecision::Allow { .. }
        ));
        // Second call denied.
        match gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap()
        {
            QuotaDecision::Deny {
                policy_id, kind, ..
            } => {
                assert_eq!(policy_id, "rl");
                assert_eq!(kind, QuotaKind::RateLimit);
            }
            QuotaDecision::Allow { .. } => panic!("expected Deny"),
        }
    }

    #[tokio::test]
    async fn gate_denies_on_full_concurrency_cap() {
        let mut qc = QuotasConfig::default();
        qc.concurrency.push(ConcurrencyPolicy {
            id: "cc".into(),
            max_concurrent: 1,
            scope: "global".into(),
            identity_claim: None,
            on_exceeded: "deny".into(),
            queue_timeout_ms: 0,
        });
        let gate = QuotaGate::new(&qc, HashMap::new(), store(), false);
        let bref = BackendQuotasRef {
            concurrency: Some("cc".into()),
            ..Default::default()
        };
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        // Acquire the only permit; hold it for the duration of
        // the test (don't drop until end).
        let first = gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap();
        assert!(matches!(
            first,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));

        // Second concurrent attempt while permit is still held → deny.
        let second = gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap();
        match second {
            QuotaDecision::Deny { kind, .. } => {
                assert_eq!(kind, QuotaKind::Concurrency);
            }
            QuotaDecision::Allow { .. } => panic!("expected Deny on cap"),
        }

        // Drop the first permit; a third attempt should now pass.
        drop(first);
        let third = gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "my-tool",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap();
        assert!(matches!(
            third,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));
    }

    // -- evaluate_for_tool (runtime hook) -----------------------------

    #[tokio::test]
    async fn evaluate_for_tool_short_circuits_when_no_binding_ref() {
        // Registry has policies, but no binding declared a `quotas:`
        // ref → the gate's binding-name lookup returns None → fast
        // Allow without touching the KV.
        let mut qc = QuotasConfig::default();
        qc.rate_limits.push(rate_limit_policy("rl", 60, Some(1)));
        let gate = QuotaGate::new(&qc, HashMap::new(), store(), false);
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        // Drain the bucket via direct evaluate first to prove the
        // policy is real…
        let bref = BackendQuotasRef {
            rate_limit: Some("rl".into()),
            ..Default::default()
        };
        let _ = gate
            .evaluate(QuotaEvalContext {
                bref: &bref,
                tool_name: "drained",
                session_id: None,
                identity: &identity,
            })
            .await
            .unwrap();
        // …but `evaluate_for_tool` doesn't care about that policy
        // because no binding-name lookup matches.
        for _ in 0..10 {
            let dec = gate
                .evaluate_for_tool("any-tool", None, &identity)
                .await
                .unwrap();
            assert!(
                matches!(dec, QuotaDecision::Allow { permit: None, .. }),
                "no binding ref → fast Allow"
            );
        }
    }

    #[tokio::test]
    async fn evaluate_for_tool_uses_binding_ref_when_present() {
        let mut qc = QuotasConfig::default();
        qc.rate_limits.push(rate_limit_policy("rl", 60, Some(1)));
        let mut refs = HashMap::new();
        refs.insert(
            "my-tool".to_owned(),
            BackendQuotasRef {
                rate_limit: Some("rl".into()),
                ..Default::default()
            },
        );
        let gate = QuotaGate::new(&qc, refs, store(), false);
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        // First call passes (burst-1 → 1 token).
        let first = gate
            .evaluate_for_tool("my-tool", None, &identity)
            .await
            .unwrap();
        assert!(matches!(first, QuotaDecision::Allow { .. }));
        // Second is denied.
        let second = gate
            .evaluate_for_tool("my-tool", None, &identity)
            .await
            .unwrap();
        assert!(matches!(second, QuotaDecision::Deny { .. }));
        // A different binding name is unconfigured → fast Allow,
        // confirming the ref-map keys are exact.
        let other = gate
            .evaluate_for_tool("other-tool", None, &identity)
            .await
            .unwrap();
        assert!(matches!(other, QuotaDecision::Allow { permit: None, .. }));
    }

    #[tokio::test]
    async fn evaluate_for_tool_skips_empty_ref() {
        let qc = QuotasConfig::default();
        let mut refs = HashMap::new();
        refs.insert("my-tool".to_owned(), BackendQuotasRef::default());
        let gate = QuotaGate::new(&qc, refs, store(), false);
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let dec = gate
            .evaluate_for_tool("my-tool", None, &identity)
            .await
            .unwrap();
        assert!(
            matches!(dec, QuotaDecision::Allow { permit: None, .. }),
            "empty BackendQuotasRef short-circuits to Allow"
        );
    }

    #[test]
    fn is_empty_returns_true_when_no_refs_or_policies() {
        let qc = QuotasConfig::default();
        let gate = QuotaGate::new(&qc, HashMap::new(), store(), false);
        assert!(gate.is_empty());
    }

    #[test]
    fn is_empty_returns_false_when_refs_present() {
        let qc = QuotasConfig::default();
        let mut refs = HashMap::new();
        refs.insert("tool".into(), BackendQuotasRef::default());
        let gate = QuotaGate::new(&qc, refs, store(), false);
        assert!(!gate.is_empty());
    }

    fn one_permit(on_exceeded: &str, queue_timeout_ms: u64) -> QuotasConfig {
        let mut qc = QuotasConfig::default();
        qc.concurrency.push(ConcurrencyPolicy {
            id: "cc".into(),
            max_concurrent: 1,
            scope: "global".into(),
            identity_claim: None,
            on_exceeded: on_exceeded.into(),
            queue_timeout_ms,
        });
        qc
    }

    async fn call(gate: &QuotaGate) -> QuotaDecision {
        let bref = BackendQuotasRef {
            concurrency: Some("cc".into()),
            ..Default::default()
        };
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        gate.evaluate(QuotaEvalContext {
            bref: &bref,
            tool_name: "my-tool",
            session_id: None,
            identity: &identity,
        })
        .await
        .unwrap()
    }

    fn shared_kv() -> Arc<dyn KeyValueStore> {
        Arc::new(crate::builtins::cluster_primitives::MemoryKv::new())
    }

    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// Two replicas' gates over one store share one cap.
    #[tokio::test]
    async fn a_fleet_cap_counts_every_replica() {
        let qc = one_permit("deny", 0);
        let kv = shared_kv();
        let a = QuotaGate::new(&qc, HashMap::new(), QuotaStore::new(Arc::clone(&kv)), true);
        let b = QuotaGate::new(&qc, HashMap::new(), QuotaStore::new(Arc::clone(&kv)), true);

        let held = call(&a).await;
        assert!(matches!(
            held,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));
        assert!(
            matches!(
                call(&b).await,
                QuotaDecision::Deny {
                    kind: QuotaKind::Concurrency,
                    ..
                }
            ),
            "the permit A holds counts on B"
        );
        drop(held);
        settle().await;
        // B found the fleet full, so it refuses without the store until the
        // hold ends.
        tokio::time::sleep(super::super::fleet_semaphore::FULL_HOLD).await;
        assert!(matches!(
            call(&b).await,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));
    }

    /// Gates that count per replica do not see each other.
    #[tokio::test]
    async fn a_replica_cap_counts_one_process() {
        let qc = one_permit("deny", 0);
        let kv = shared_kv();
        let a = QuotaGate::new(&qc, HashMap::new(), QuotaStore::new(Arc::clone(&kv)), false);
        let b = QuotaGate::new(&qc, HashMap::new(), QuotaStore::new(Arc::clone(&kv)), false);
        let _a = call(&a).await;
        assert!(matches!(
            call(&b).await,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));
    }

    /// `on_exceeded: queue` waits for the permit a holder gives back, on a
    /// replica and in a fleet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queued_call_takes_the_permit_given_back() {
        for fleet in [false, true] {
            let qc = one_permit("queue", 5_000);
            let gate = Arc::new(QuotaGate::new(
                &qc,
                HashMap::new(),
                QuotaStore::new(shared_kv()),
                fleet,
            ));
            let held = call(&gate).await;
            assert!(matches!(
                held,
                QuotaDecision::Allow {
                    permit: Some(_),
                    ..
                }
            ));
            let queued = {
                let gate = Arc::clone(&gate);
                tokio::spawn(async move { call(&gate).await })
            };
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!queued.is_finished(), "fleet={fleet}: the call waits");
            drop(held);
            let got = tokio::time::timeout(Duration::from_secs(3), queued)
                .await
                .expect("the queued call ends")
                .unwrap();
            assert!(
                matches!(
                    got,
                    QuotaDecision::Allow {
                        permit: Some(_),
                        ..
                    }
                ),
                "fleet={fleet}: the queued call gets the permit"
            );
        }
    }

    #[tokio::test]
    async fn a_queued_call_is_denied_at_its_timeout() {
        for fleet in [false, true] {
            let qc = one_permit("queue", 100);
            let gate = QuotaGate::new(&qc, HashMap::new(), QuotaStore::new(shared_kv()), fleet);
            let _held = call(&gate).await;
            let started = std::time::Instant::now();
            match call(&gate).await {
                QuotaDecision::Deny { reason, .. } => {
                    assert!(reason.contains("waited 100 ms"), "{reason}");
                }
                QuotaDecision::Allow { .. } => panic!("fleet={fleet}: expected a deny"),
            }
            assert!(started.elapsed() >= Duration::from_millis(100));
        }
    }

    fn budget_policy(window: &str) -> BudgetPolicy {
        BudgetPolicy {
            id: "bb".into(),
            kind: "call_count".into(),
            scope: "global".into(),
            identity_claim: None,
            cap_usd: None,
            cap_token_count: None,
            cap_calls: None,
            window: window.into(),
            warn_at_pct: None,
            on_exceeded: "deny".into(),
            acknowledge_unenforced: false,
        }
    }

    fn budget_gate(policy: BudgetPolicy, kv: Arc<dyn KeyValueStore>) -> QuotaGate {
        budget_gate_on(policy, QuotaStore::new(kv))
    }

    fn budget_gate_on(policy: BudgetPolicy, store: Arc<QuotaStore>) -> QuotaGate {
        let mut qc = QuotasConfig::default();
        qc.budgets.push(policy);
        let mut refs = HashMap::new();
        refs.insert(
            "my-tool".to_owned(),
            BackendQuotasRef {
                budget: Some("bb".into()),
                ..Default::default()
            },
        );
        QuotaGate::new(&qc, refs, store, true)
    }

    /// The quota store of a gateway with a state key: its sealed values
    /// under the cipher, its counters without it.
    fn store_under_state_key(kv: &Arc<dyn KeyValueStore>) -> Arc<QuotaStore> {
        let cipher = Arc::new(
            mcpg_plugin_host::credential_cache_cipher::EventCipher::from_raw_key(
                &[3u8; 32],
                "k1".into(),
            )
            .unwrap(),
        );
        let sealed: Arc<dyn KeyValueStore> = Arc::new(
            mcpg_plugin_host::cluster_encryption::EncryptingKeyValueStore::new(
                Arc::clone(kv),
                cipher,
            ),
        );
        QuotaStore::with_counters(sealed, Arc::clone(kv))
    }

    /// A state key seals the store's values but not its counters, which a
    /// sealed view refuses to read or list: the replicas still count one
    /// another's permits and spend.
    #[tokio::test]
    async fn the_replicas_count_one_another_under_a_state_key() {
        let kv = shared_kv();
        let qc = one_permit("deny", 0);
        let a = QuotaGate::new(&qc, HashMap::new(), store_under_state_key(&kv), true);
        let b = QuotaGate::new(&qc, HashMap::new(), store_under_state_key(&kv), true);
        let _held = call(&a).await;
        assert!(
            matches!(
                call(&b).await,
                QuotaDecision::Deny {
                    kind: QuotaKind::Concurrency,
                    ..
                }
            ),
            "the permit A holds counts on B"
        );

        let kv = shared_kv();
        let policy = BudgetPolicy {
            kind: "token_count".into(),
            cap_token_count: Some(1_000),
            ..budget_policy("24h")
        };
        let a = budget_gate_on(policy.clone(), store_under_state_key(&kv));
        let b = budget_gate_on(policy, store_under_state_key(&kv));
        for _ in 0..2 {
            assert!(matches!(budget_call(&a).await, QuotaDecision::Allow { .. }));
            a.charge_usage("my-tool", None, &anonymous(), &used(400, 300, None))
                .await
                .unwrap();
        }
        assert!(
            matches!(
                budget_call(&b).await,
                QuotaDecision::Deny {
                    kind: QuotaKind::Budget,
                    ..
                }
            ),
            "the tokens A charged stop B"
        );
    }

    fn anonymous() -> RequestIdentity {
        RequestIdentity::Anonymous {
            source: "test".into(),
        }
    }

    async fn budget_call(gate: &QuotaGate) -> QuotaDecision {
        gate.evaluate_for_tool("my-tool", None, &anonymous())
            .await
            .unwrap()
    }

    fn used(
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: Option<f64>,
    ) -> mcpg_plugin_protocol::BackendUsage {
        mcpg_plugin_protocol::BackendUsage {
            input_tokens,
            output_tokens,
            cost_usd,
        }
    }

    /// A call cap holds exactly across replicas that call at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_call_cap_is_exact_across_replicas() {
        let kv = shared_kv();
        let mut policy = budget_policy("24h");
        policy.cap_calls = Some(5);
        let gates: Vec<Arc<QuotaGate>> = (0..2)
            .map(|_| Arc::new(budget_gate(policy.clone(), Arc::clone(&kv))))
            .collect();
        let mut calls = Vec::new();
        for n in 0..24 {
            let gate = Arc::clone(&gates[n % 2]);
            calls.push(tokio::spawn(async move { budget_call(&gate).await }));
        }
        let mut allowed = 0;
        for call in calls {
            if matches!(call.await.unwrap(), QuotaDecision::Allow { .. }) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5, "exactly the cap is admitted");
    }

    /// Tokens and cost are charged after the call; a call starts while the
    /// spend is under the cap, and the next one after it reached the cap is
    /// denied, on any replica.
    #[tokio::test]
    async fn charged_tokens_and_cost_stop_the_next_call() {
        for (policy, usage) in [
            (
                BudgetPolicy {
                    kind: "token_count".into(),
                    cap_token_count: Some(1_000),
                    ..budget_policy("24h")
                },
                used(400, 300, None),
            ),
            (
                BudgetPolicy {
                    kind: "cost".into(),
                    cap_usd: Some(0.05),
                    ..budget_policy("24h")
                },
                used(1, 1, Some(0.03)),
            ),
        ] {
            let kv = shared_kv();
            let a = budget_gate(policy.clone(), Arc::clone(&kv));
            let b = budget_gate(policy.clone(), Arc::clone(&kv));
            for _ in 0..2 {
                assert!(matches!(budget_call(&a).await, QuotaDecision::Allow { .. }));
                a.charge_usage("my-tool", None, &anonymous(), &usage)
                    .await
                    .unwrap();
            }
            match budget_call(&b).await {
                QuotaDecision::Deny { kind, .. } => assert_eq!(kind, QuotaKind::Budget),
                QuotaDecision::Allow { .. } => {
                    panic!("{}: the spend A charged stops B", policy.kind)
                }
            }
        }
    }

    /// `warn_at_pct` warns once in a window: on the charge or the call that
    /// crosses it.
    #[tokio::test]
    async fn the_warn_threshold_warns_once() {
        let kv = shared_kv();
        let policy = BudgetPolicy {
            cap_calls: Some(10),
            warn_at_pct: Some(50),
            ..budget_policy("24h")
        };
        let gate = budget_gate(policy, Arc::clone(&kv));
        let mut warned = Vec::new();
        for n in 1..=10 {
            if let QuotaDecision::Allow { warnings, .. } = budget_call(&gate).await
                && !warnings.is_empty()
            {
                assert_eq!(warnings[0].measure, "calls");
                warned.push(n);
            }
        }
        assert_eq!(warned, vec![5], "the fifth call of ten crosses 50 %");

        let policy = BudgetPolicy {
            kind: "cost".into(),
            cap_usd: Some(1.0),
            warn_at_pct: Some(80),
            ..budget_policy("24h")
        };
        let gate = budget_gate(policy, shared_kv());
        let mut warnings = Vec::new();
        for _ in 0..5 {
            warnings.extend(
                gate.charge_usage("my-tool", None, &anonymous(), &used(0, 0, Some(0.3)))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(warnings.len(), 1, "0.9 USD crosses 80 % of 1 USD once");
        assert_eq!(warnings[0].measure, "usd");
        assert!((warnings[0].used - 0.9).abs() < 1e-9);
    }

    /// A new window starts from zero.
    #[tokio::test]
    async fn a_new_window_starts_from_zero() {
        let policy = BudgetPolicy {
            cap_calls: Some(1),
            ..budget_policy("1s")
        };
        let gate = budget_gate(policy, shared_kv());
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Allow { .. }
        ));
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Deny { .. }
        ));
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Allow { .. }
        ));
    }

    /// A record of the accounting the counters replace counts the calls of
    /// the window it was in.
    #[tokio::test]
    async fn a_legacy_record_seeds_its_window() {
        let kv = shared_kv();
        let legacy = BudgetState {
            cost_usd: 0.0,
            tokens: 0,
            calls: 2,
            window_started_unix_ms: Utc::now().timestamp_millis() - 1_000,
        };
        kv.put(
            "quotas.budget.bb.global",
            Bytes::from(serde_json::to_vec(&legacy).unwrap()),
            None,
        )
        .await
        .unwrap();
        let gate = budget_gate(
            BudgetPolicy {
                cap_calls: Some(3),
                ..budget_policy("24h")
            },
            kv,
        );
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Allow { .. }
        ));
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Deny { .. }
        ));
    }

    /// A call the concurrency cap refuses does not count against the
    /// budget.
    #[tokio::test]
    async fn a_call_refused_by_concurrency_is_not_counted() {
        let kv = shared_kv();
        let mut qc = QuotasConfig::default();
        qc.budgets.push(BudgetPolicy {
            cap_calls: Some(2),
            ..budget_policy("24h")
        });
        qc.concurrency.push(ConcurrencyPolicy {
            id: "cc".into(),
            max_concurrent: 1,
            scope: "global".into(),
            identity_claim: None,
            on_exceeded: "deny".into(),
            queue_timeout_ms: 0,
        });
        let mut refs = HashMap::new();
        refs.insert(
            "my-tool".to_owned(),
            BackendQuotasRef {
                budget: Some("bb".into()),
                concurrency: Some("cc".into()),
                ..Default::default()
            },
        );
        let gate = QuotaGate::new(&qc, refs, QuotaStore::new(kv), true);
        let held = budget_call(&gate).await;
        assert!(matches!(
            held,
            QuotaDecision::Allow {
                permit: Some(_),
                ..
            }
        ));
        assert!(matches!(
            budget_call(&gate).await,
            QuotaDecision::Deny {
                kind: QuotaKind::Concurrency,
                ..
            }
        ));
        drop(held);
        settle().await;
        assert!(
            matches!(budget_call(&gate).await, QuotaDecision::Allow { .. }),
            "the refused call gave its count back, so the second of two runs"
        );
    }
}
