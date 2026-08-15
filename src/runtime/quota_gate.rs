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
//! # Atomicity caveat
//!
//! The [`mcpg_cluster_api::KeyValueStore`] trait does not expose
//! atomic increment or compare-and-swap. Token-bucket and budget
//! state therefore use a local read-modify-write loop serialized
//! by an in-process `Mutex` keyed by the bucket's KV-key. For a
//! single-instance gateway this is correct; for a multi-instance
//! deployment that shares a KV (cluster mode), two replicas can
//! race the same bucket and either over-grant or over-deny by a
//! small constant. Pre-1.0 we accept that — operators who need
//! cluster-correct quota enforcement should pin the
//! `governance.quotas.store:` to a backend that grows native CAS
//! support (a future cluster-api evolution) or accept the bounded
//! drift.
//!
//! Concurrency caps don't suffer from this: in-flight permits are
//! tracked entirely in-process via a [`tokio::sync::Semaphore`]
//! per policy (no KV round-trip), so the cap is exact within
//! a single gateway instance. Multi-instance concurrency caps
//! become per-instance caps; operators who want a cluster-wide
//! cap split it across replicas at config time.

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
    /// completion.
    Allow { permit: Option<ConcurrencyPermit> },
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
    _inner: tokio::sync::OwnedSemaphorePermit,
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
/// per-key serialization. Token-bucket and budget read-modify-
/// write must be atomic w.r.t. concurrent requests touching the
/// same bucket key; the underlying KV trait has no incr/CAS today.
#[derive(Debug)]
pub struct QuotaStore {
    kv: Arc<dyn KeyValueStore>,
    locks: DashMap<String, Arc<Mutex<()>>>,
}

impl QuotaStore {
    pub fn new(kv: Arc<dyn KeyValueStore>) -> Arc<Self> {
        Arc::new(Self {
            kv,
            locks: DashMap::new(),
        })
    }

    /// Acquire (or create) the per-key serialization lock.
    fn lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        self.locks
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Read-modify-write under the per-key lock. The closure
    /// receives the previous bytes (or `None` if absent), returns
    /// the new bytes + optional TTL + caller's return value.
    /// On success the new bytes are stored.
    pub async fn read_modify_write<F, R>(&self, key: &str, f: F) -> Result<R>
    where
        F: FnOnce(Option<Bytes>) -> Result<(Bytes, Option<Duration>, R)>,
    {
        let lock = self.lock_for(key);
        let _guard = lock.lock().await;
        let entry = self
            .kv
            .get(key)
            .await
            .with_context(|| format!("quota_store: get failed for `{key}`"))?;
        let prev = entry.map(|e| e.bytes);
        let (next, ttl, ret) = f(prev)?;
        self.kv
            .put(key, next, ttl)
            .await
            .with_context(|| format!("quota_store: put failed for `{key}`"))?;
        Ok(ret)
    }
}

// ---------------------------------------------------------------------------
// Token bucket primitive.
// ---------------------------------------------------------------------------

/// Persisted token-bucket state. Stored as JSON in the quota KV
/// under `quotas.rate_limit.<policy_id>.<scope_key>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TokenBucketState {
    /// Tokens currently in the bucket. Float so refill granularity
    /// finer than 1/min works (e.g. 100 calls / min refills 1 token
    /// every 600 ms — partial tokens accumulate).
    tokens: f64,
    /// Last refill instant, UTC epoch milliseconds. Used to compute
    /// elapsed time for refill on each consume.
    last_refill_unix_ms: i64,
}

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

/// Tokens-per-millisecond refill rate.
fn refill_rate_per_ms(rate_per_min: u32) -> f64 {
    f64::from(rate_per_min) / 60_000.0
}

/// Try to consume one token from the named bucket. Refills based
/// on elapsed wall-clock since the last consume; if the bucket
/// has < 1 token after refill, the call is denied and no token
/// is consumed.
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
    let capacity = capacity_for(policy.rate.calls_per_minute, policy.burst);
    let refill_per_ms = refill_rate_per_ms(policy.rate.calls_per_minute);
    // Keep state alive for at least 2x the time it would take a
    // full bucket to drain at min refill — long-idle entries roll
    // back to "full" via the absent-key fast path below.
    let ttl = Some(Duration::from_secs(3600));

    store
        .read_modify_write(key, move |prev| {
            let mut state = match prev {
                Some(b) => {
                    serde_json::from_slice::<TokenBucketState>(&b).unwrap_or(TokenBucketState {
                        tokens: capacity,
                        last_refill_unix_ms: now_ms,
                    })
                }
                None => TokenBucketState {
                    tokens: capacity,
                    last_refill_unix_ms: now_ms,
                },
            };
            // Refill since last consume.
            let elapsed_ms = (now_ms - state.last_refill_unix_ms).max(0);
            let refill = (elapsed_ms as f64) * refill_per_ms;
            state.tokens = (state.tokens + refill).min(capacity);
            state.last_refill_unix_ms = now_ms;

            // Consume if at least one token is available.
            let allowed = state.tokens >= 1.0;
            if allowed {
                state.tokens -= 1.0;
            }
            let bytes = Bytes::from(serde_json::to_vec(&state)?);
            Ok((bytes, ttl, allowed))
        })
        .await
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
        sem.try_acquire_owned()
            .ok()
            .map(|p| ConcurrencyPermit { _inner: p })
    }
}

// ---------------------------------------------------------------------------
// Budget primitive (cost / token / call accumulator).
// ---------------------------------------------------------------------------

/// Persisted budget state. Stored as JSON in the quota KV under
/// `quotas.budget.<policy_id>.<scope_key>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct BudgetState {
    /// Accumulated cost in dollars. `f64` to match `cap_usd` shape;
    /// precision loss at floating-point edges is fine — budgets
    /// are policy estimates, not invoicing.
    cost_usd: f64,
    /// Accumulated token count (for `cap_token_count` budgets).
    tokens: u64,
    /// Accumulated call count (for `cap_calls` budgets).
    calls: u64,
    /// UTC epoch ms when the current window started. The window's
    /// length is `policy.window`; rollover resets all counters and
    /// updates this stamp.
    window_started_unix_ms: i64,
}

/// Window roll: if `now_ms - window_started >= window_ms`, reset.
fn maybe_roll_window(state: &mut BudgetState, window_ms: i64, now_ms: i64) -> bool {
    let elapsed = now_ms - state.window_started_unix_ms;
    if elapsed >= window_ms {
        state.cost_usd = 0.0;
        state.tokens = 0;
        state.calls = 0;
        state.window_started_unix_ms = now_ms;
        true
    } else {
        false
    }
}

/// Pre-flight check: would charging zero (i.e. the binding hasn't
/// run yet, we're checking only the cap) deny? For pre-flight we
/// only deny if the cap is already met or exceeded. A future
/// post-dispatch `record_*` call applies the actual charge; the gate
/// today does pre-flight only and approximates "denied if cap
/// reached".
async fn check_budget_pre_flight(
    store: &QuotaStore,
    key: &str,
    policy: &BudgetPolicy,
    now_ms: i64,
) -> Result<bool> {
    let window_ms = window_to_ms(&policy.window).unwrap_or(86_400_000);
    let cap_usd = policy.cap_usd;
    let cap_tokens = policy.cap_token_count;
    let cap_calls = policy.cap_calls;
    let ttl = Some(Duration::from_millis((window_ms as u64).saturating_mul(2)));

    store
        .read_modify_write(key, move |prev| {
            let mut state = match prev {
                Some(b) => serde_json::from_slice::<BudgetState>(&b).unwrap_or(BudgetState {
                    cost_usd: 0.0,
                    tokens: 0,
                    calls: 0,
                    window_started_unix_ms: now_ms,
                }),
                None => BudgetState {
                    cost_usd: 0.0,
                    tokens: 0,
                    calls: 0,
                    window_started_unix_ms: now_ms,
                },
            };
            maybe_roll_window(&mut state, window_ms, now_ms);

            // Pre-flight: deny when the cap is already exhausted.
            // Because the gate doesn't yet integrate post-flight
            // accounting (binding-emitted cost / token deltas), it
            // approximates: the budget acts as a per-window call
            // counter, and exceeding any declared cap denies.
            // Operators who set BOTH cap_usd and cap_calls today
            // get an OR semantics — first-tripped wins.
            let denied_by_calls = cap_calls.is_some_and(|c| state.calls >= c);
            let denied_by_cost = cap_usd.is_some_and(|c| state.cost_usd >= c);
            let denied_by_tokens = cap_tokens.is_some_and(|c| state.tokens >= c);
            let allowed = !(denied_by_calls || denied_by_cost || denied_by_tokens);

            // Pre-flight reservation: count this call upfront. If
            // the binding fails post-dispatch, the count remains
            // (over-counts on errors). A future refinement could
            // separate reserve / commit / refund.
            if allowed {
                state.calls = state.calls.saturating_add(1);
            }
            let bytes = Bytes::from(serde_json::to_vec(&state)?);
            Ok((bytes, ttl, allowed))
        })
        .await
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
    concurrency: ConcurrencyTracker,
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
    /// up the binding's ref by name.
    pub fn new(
        quotas: &QuotasConfig,
        binding_refs: HashMap<String, BackendQuotasRef>,
        store: Arc<QuotaStore>,
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
        Self {
            store,
            rate_limits,
            budgets,
            concurrency_policies,
            concurrency: ConcurrencyTracker::default(),
            binding_refs,
            fail_open_on_error: quotas.fail_open_on_error(),
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
        let Some(bref) = self.binding_refs.get(tool_name) else {
            return Ok(QuotaDecision::Allow { permit: None });
        };
        if bref.is_empty() {
            return Ok(QuotaDecision::Allow { permit: None });
        }
        self.evaluate(QuotaEvalContext {
            bref,
            tool_name,
            session_id,
            identity,
        })
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
        if let Some(id) = ctx.bref.budget.as_deref()
            && let Some(policy) = self.budgets.get(id)
        {
            let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
            let key = format!("quotas.budget.{}.{}", policy.id, scope_key);
            let allowed = check_budget_pre_flight(&self.store, &key, policy, now_ms).await?;
            if !allowed {
                return Ok(QuotaDecision::Deny {
                    policy_id: policy.id.clone(),
                    kind: QuotaKind::Budget,
                    reason: format!("budget `{}` exhausted for scope `{}`", policy.id, scope_key),
                });
            }
        }

        // Concurrency permit (last — acquire only when everything
        // else has passed, otherwise we'd leak permits on rate /
        // budget denies).
        let permit = if let Some(id) = ctx.bref.concurrency.as_deref()
            && let Some(policy) = self.concurrency_policies.get(id)
        {
            let scope_key = scope_key(&policy.scope, policy.identity_claim.as_deref(), &ctx);
            let key = format!("{}.{}", policy.id, scope_key);
            match self.concurrency.try_acquire(&key, policy.max_concurrent) {
                Some(p) => Some(p),
                None => {
                    return Ok(QuotaDecision::Deny {
                        policy_id: policy.id.clone(),
                        kind: QuotaKind::Concurrency,
                        reason: format!(
                            "concurrency cap `{}` reached for scope `{}` ({}/{} in flight)",
                            policy.id, scope_key, policy.max_concurrent, policy.max_concurrent,
                        ),
                    });
                }
            }
        } else {
            None
        };

        Ok(QuotaDecision::Allow { permit })
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

        async fn list_prefix(
            &self,
            _prefix: &str,
            _limit: usize,
        ) -> std::result::Result<Vec<(String, Entry)>, mcpg_cluster_api::error::ClusterError>
        {
            Ok(Vec::new())
        }

        async fn expire(
            &self,
            _key: &str,
            _ttl: Option<Duration>,
        ) -> std::result::Result<bool, mcpg_cluster_api::error::ClusterError> {
            Ok(true)
        }
    }

    fn store() -> Arc<QuotaStore> {
        QuotaStore::new(Arc::new(StubKv::default()))
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
        let gate = QuotaGate::new(&qc, HashMap::new(), store());
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
        let gate = QuotaGate::new(&qc, HashMap::new(), store());
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
        let gate = QuotaGate::new(&qc, HashMap::new(), store());
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
        assert!(matches!(first, QuotaDecision::Allow { permit: Some(_) }));

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
        assert!(matches!(third, QuotaDecision::Allow { permit: Some(_) }));
    }

    // -- evaluate_for_tool (runtime hook) -----------------------------

    #[tokio::test]
    async fn evaluate_for_tool_short_circuits_when_no_binding_ref() {
        // Registry has policies, but no binding declared a `quotas:`
        // ref → the gate's binding-name lookup returns None → fast
        // Allow without touching the KV.
        let mut qc = QuotasConfig::default();
        qc.rate_limits.push(rate_limit_policy("rl", 60, Some(1)));
        let gate = QuotaGate::new(&qc, HashMap::new(), store());
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
                matches!(dec, QuotaDecision::Allow { permit: None }),
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
        let gate = QuotaGate::new(&qc, refs, store());
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
        assert!(matches!(other, QuotaDecision::Allow { permit: None }));
    }

    #[tokio::test]
    async fn evaluate_for_tool_skips_empty_ref() {
        let qc = QuotasConfig::default();
        let mut refs = HashMap::new();
        refs.insert("my-tool".to_owned(), BackendQuotasRef::default());
        let gate = QuotaGate::new(&qc, refs, store());
        let identity = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        let dec = gate
            .evaluate_for_tool("my-tool", None, &identity)
            .await
            .unwrap();
        assert!(
            matches!(dec, QuotaDecision::Allow { permit: None }),
            "empty BackendQuotasRef short-circuits to Allow"
        );
    }

    #[test]
    fn is_empty_returns_true_when_no_refs_or_policies() {
        let qc = QuotasConfig::default();
        let gate = QuotaGate::new(&qc, HashMap::new(), store());
        assert!(gate.is_empty());
    }

    #[test]
    fn is_empty_returns_false_when_refs_present() {
        let qc = QuotasConfig::default();
        let mut refs = HashMap::new();
        refs.insert("tool".into(), BackendQuotasRef::default());
        let gate = QuotaGate::new(&qc, refs, store());
        assert!(!gate.is_empty());
    }
}
