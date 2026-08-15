//! `governance.quotas:` block — operator-declared rate-limit /
//! budget / concurrency policies.
//!
//! Limit configuration that used to be scattered across the
//! rate-limit plugin (per-binding
//! token-bucket), per-binding LLM `budget:` fields, and payment
//! plugins (MPP per-call) is consolidated into a single registry
//! of named policies that bindings opt into by id (mirroring the
//! `schema_registry:` and `storage:` registry pattern).
//!
//! ## Registry shape
//!
//! ```yaml
//! governance:
//!   quotas:
//!     store:
//!       kind: cluster                # or in-process / memory / <plugin-id>
//!     rate_limits:
//!       - id: tier-pro
//!         kind: token_bucket
//!         scope: per_identity
//!         identity_claim: sub
//!         rate: { calls_per_minute: 1000 }
//!         burst: 100
//!         on_exceeded: deny
//!     budgets:
//!       - id: llm-daily-100usd
//!         kind: cost
//!         scope: per_identity
//!         identity_claim: sub
//!         cap_usd: 100
//!         window: 24h
//!         warn_at_pct: 80
//!         on_exceeded: deny
//!     concurrency:
//!       - id: heavy-tools
//!         max_concurrent: 10
//!         scope: per_tool
//!         on_exceeded: queue
//!         queue_timeout_ms: 30000
//! ```
//!
//! ## Status
//!
//! The **schema** + **validation** are live. The runtime gate that
//! actually enforces quotas lives behind a cargo feature
//! (`governance-quotas`); the gate stub exists but does not yet
//! decrement counters or emit the `governance.quota.exceeded` audit
//! event. Both gate enforcement and per-binding references
//! (`tools[].quotas: { rate_limit, … }`) can ship incrementally
//! without breaking this schema.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use super::wiring::KindRef;

/// `governance.quotas:` registry.
///
/// Three named-policy lists (rate_limits / budgets / concurrency)
/// plus the storage backend that holds the runtime counters.
/// Bindings opt into specific policies by id via their own
/// per-binding `quotas:` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuotasConfig {
    /// Storage backend for quota counters / token-buckets /
    /// in-flight concurrency. Uses the standard `KindRef`
    /// discriminator. `kind: cluster` (default) routes through
    /// the cluster coordinator's KV role; `kind: memory` resets
    /// on restart (dev-only); `kind: <plugin-id>` pins to a
    /// loaded KV plugin.
    #[serde(default)]
    pub store: KindRef,

    /// Named rate-limit policies. Bindings reference by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitPolicy>,

    /// Named cost / call-count / token-count budgets. Bindings
    /// reference by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budgets: Vec<BudgetPolicy>,

    /// Named concurrency caps. Bindings reference by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency: Vec<ConcurrencyPolicy>,

    /// Posture when the quota gate itself errors (e.g. a quota-store
    /// read/write failure): `deny` (default, fail-closed — refuse the
    /// call so a storage outage cannot silently disable rate-limit /
    /// budget / concurrency enforcement) or `allow` (fail-open —
    /// proceed without a permit). An empty value is treated as `deny`.
    #[serde(default = "default_on_error")]
    pub on_error: String,
}

impl QuotasConfig {
    /// Validate the registry. Refuses duplicate ids within each
    /// list, validates per-policy shape, and asserts cross-policy
    /// invariants (per_identity scope requires identity_claim,
    /// cost budgets require either `cap_usd` or `cap_token_count`,
    /// etc.).
    pub fn validate(&self) -> Result<()> {
        let mut seen_rate_limit_ids: BTreeSet<&str> = BTreeSet::new();
        for (i, p) in self.rate_limits.iter().enumerate() {
            let path = format!("governance.quotas.rate_limits[{i}]");
            p.validate(&path)?;
            if !seen_rate_limit_ids.insert(p.id.as_str()) {
                return Err(anyhow!(
                    "{path}: duplicate id `{}` (rate_limit ids must be unique)",
                    p.id
                ));
            }
        }
        let mut seen_budget_ids: BTreeSet<&str> = BTreeSet::new();
        for (i, p) in self.budgets.iter().enumerate() {
            let path = format!("governance.quotas.budgets[{i}]");
            p.validate(&path)?;
            if !seen_budget_ids.insert(p.id.as_str()) {
                return Err(anyhow!(
                    "{path}: duplicate id `{}` (budget ids must be unique)",
                    p.id
                ));
            }
        }
        let mut seen_concurrency_ids: BTreeSet<&str> = BTreeSet::new();
        for (i, p) in self.concurrency.iter().enumerate() {
            let path = format!("governance.quotas.concurrency[{i}]");
            p.validate(&path)?;
            if !seen_concurrency_ids.insert(p.id.as_str()) {
                return Err(anyhow!(
                    "{path}: duplicate id `{}` (concurrency ids must be unique)",
                    p.id
                ));
            }
        }
        validate_on_error("governance.quotas.on_error", &self.on_error)?;
        Ok(())
    }

    /// True when the operator opted into fail-open on a quota-gate error.
    /// Default / empty / `deny` → false (fail-closed).
    #[must_use]
    pub fn fail_open_on_error(&self) -> bool {
        self.on_error == "allow"
    }

    /// True when no policies are declared. The runtime quota gate
    /// short-circuits when this is true (no work to do).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rate_limits.is_empty() && self.budgets.is_empty() && self.concurrency.is_empty()
    }

    /// Validate that every non-`None` id named by a binding's
    /// `quotas:` block resolves to a registered policy in the
    /// matching list. Boot fails on any unknown id with a path-
    /// qualified message — operators get the binding name + the
    /// kind of policy + the missing id so the typo is obvious.
    pub fn validate_binding_ref(&self, bref: &BackendQuotasRef, binding_path: &str) -> Result<()> {
        if let Some(id) = &bref.rate_limit
            && !self.rate_limits.iter().any(|p| &p.id == id)
        {
            return Err(anyhow!(
                "{binding_path}.quotas.rate_limit: id `{id}` not found in \
                 governance.quotas.rate_limits[]"
            ));
        }
        if let Some(id) = &bref.budget
            && !self.budgets.iter().any(|p| &p.id == id)
        {
            return Err(anyhow!(
                "{binding_path}.quotas.budget: id `{id}` not found in \
                 governance.quotas.budgets[]"
            ));
        }
        if let Some(id) = &bref.concurrency
            && !self.concurrency.iter().any(|p| &p.id == id)
        {
            return Err(anyhow!(
                "{binding_path}.quotas.concurrency: id `{id}` not found in \
                 governance.quotas.concurrency[]"
            ));
        }
        Ok(())
    }
}

/// Per-binding quota reference — operator names at most one of each
/// policy kind by id. The runtime gate that consults these refs is
/// gated behind the `governance-quotas` cargo feature.
///
/// All three fields are independent options; an absent field means
/// "no policy of that kind for this binding". A binding may name
/// more than one kind at once (e.g. both a rate limit AND a
/// concurrency cap), but at most one policy of each kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackendQuotasRef {
    /// Id from `governance.quotas.rate_limits[].id`. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<String>,
    /// Id from `governance.quotas.budgets[].id`. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<String>,
    /// Id from `governance.quotas.concurrency[].id`. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<String>,
}

impl BackendQuotasRef {
    /// True when no policy is referenced. Empty refs short-circuit
    /// the runtime gate's per-binding lookup.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rate_limit.is_none() && self.budget.is_none() && self.concurrency.is_none()
    }
}

/// One named rate-limit policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPolicy {
    /// Operator-chosen id. Bindings reference this via
    /// `tools[].quotas.rate_limit: <id>`.
    pub id: String,

    /// Algorithm. v1.0 ships `token_bucket` only; `leaky_bucket`
    /// and `sliding_window` are not implemented.
    #[serde(default = "default_rate_limit_kind")]
    pub kind: String,

    /// Scope discriminator: how the bucket is keyed.
    /// `per_identity` keys by the JWT claim path in
    /// `identity_claim`; `global` shares one bucket across all
    /// callers; `per_session`, `per_tool` are also valid.
    #[serde(default = "default_scope")]
    pub scope: String,

    /// JWT claim path used to key the bucket when `scope:
    /// per_identity`. Required for that scope; rejected for
    /// others. Common values: `sub`, `org_id`, `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claim: Option<String>,

    /// Refill rate. Today only `calls_per_minute` is supported;
    /// future variants will land here.
    pub rate: RateLimitRate,

    /// Bucket burst capacity — number of calls a caller can spend
    /// in quick succession before refill rate kicks in. Defaults
    /// to the per-second equivalent of `rate` (i.e., one second's
    /// worth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,

    /// Action when the bucket runs dry. `deny` returns a 429-style
    /// error; `queue` is reserved and currently aliases to `deny` for
    /// rate limits; `shed_load` drops silently.
    #[serde(default = "default_on_exceeded")]
    pub on_exceeded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitRate {
    /// Calls allowed per minute. Bucket refills at this rate.
    pub calls_per_minute: u32,
}

impl RateLimitPolicy {
    pub fn validate(&self, path: &str) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(anyhow!("{path}.id must not be empty"));
        }
        if !matches!(self.kind.as_str(), "token_bucket") {
            return Err(anyhow!(
                "{path}.kind: only `token_bucket` is supported in v1.0 (got `{}`)",
                self.kind
            ));
        }
        validate_scope(path, &self.scope, &self.identity_claim)?;
        if self.rate.calls_per_minute == 0 {
            return Err(anyhow!("{path}.rate.calls_per_minute must be > 0"));
        }
        validate_on_exceeded(&format!("{path}.on_exceeded"), &self.on_exceeded)?;
        Ok(())
    }
}

/// One named budget policy (cost cap / call count / token count).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetPolicy {
    pub id: String,

    /// Budget kind: `cost` (USD), `call_count`, or `token_count`.
    #[serde(default = "default_budget_kind")]
    pub kind: String,

    /// Scope discriminator (same vocabulary as RateLimitPolicy).
    #[serde(default = "default_scope")]
    pub scope: String,

    /// JWT claim path for `per_identity` scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claim: Option<String>,

    /// Cost cap in USD when `kind: cost`. Required for that kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_usd: Option<f64>,

    /// Token cap when `kind: token_count`. Required for that kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_token_count: Option<u64>,

    /// Call cap when `kind: call_count`. Required for that kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_calls: Option<u64>,

    /// Rolling window over which the cap applies. Suffixes `s`/`m`/
    /// `h`/`d`. Maximum `30d`.
    pub window: String,

    /// Emit `governance.quota.warn` when drawdown crosses this
    /// percentage of the cap. Defaults to no warning. `0..=100`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_at_pct: Option<u8>,

    /// Action when the cap is hit (same vocabulary as
    /// RateLimitPolicy).
    #[serde(default = "default_on_exceeded")]
    pub on_exceeded: String,

    /// Acknowledge that a `cost` / `token_count` budget is advisory.
    /// Per-call USD spend and token usage are not available to the
    /// gateway after dispatch, so these caps cannot be enforced at
    /// runtime — only `call_count` is. A `cost`/`token_count` budget
    /// must set this to load, making the no-op posture an explicit
    /// operator choice rather than a silent fail-open. No effect for
    /// `call_count`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acknowledge_unenforced: bool,
}

impl BudgetPolicy {
    pub fn validate(&self, path: &str) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(anyhow!("{path}.id must not be empty"));
        }
        match self.kind.as_str() {
            "cost" => {
                if self.cap_usd.is_none() {
                    return Err(anyhow!(
                        "{path}: `kind: cost` requires `cap_usd:` to be set"
                    ));
                }
                if !self.acknowledge_unenforced {
                    return Err(anyhow!(
                        "{path}: `kind: cost` budgets are not enforced at runtime — per-call USD \
                         spend is not reported back to the gateway after dispatch, so `cap_usd` \
                         cannot be charged. Set `acknowledge_unenforced: true` to accept an \
                         advisory budget, or use `kind: call_count`."
                    ));
                }
            }
            "call_count" => {
                if self.cap_calls.is_none() {
                    return Err(anyhow!(
                        "{path}: `kind: call_count` requires `cap_calls:` to be set"
                    ));
                }
            }
            "token_count" => {
                if self.cap_token_count.is_none() {
                    return Err(anyhow!(
                        "{path}: `kind: token_count` requires `cap_token_count:` to be set"
                    ));
                }
                if !self.acknowledge_unenforced {
                    return Err(anyhow!(
                        "{path}: `kind: token_count` budgets are not enforced at runtime — per-call \
                         token usage is not reported back to the gateway after dispatch, so \
                         `cap_token_count` cannot be charged. Set `acknowledge_unenforced: true` to \
                         accept an advisory budget, or use `kind: call_count`."
                    ));
                }
            }
            other => {
                return Err(anyhow!(
                    "{path}.kind: must be `cost` | `call_count` | `token_count` (got `{other}`)"
                ));
            }
        }
        validate_scope(path, &self.scope, &self.identity_claim)?;
        validate_window(&format!("{path}.window"), &self.window)?;
        if let Some(pct) = self.warn_at_pct
            && pct > 100
        {
            return Err(anyhow!("{path}.warn_at_pct must be 0..=100 (got {pct})"));
        }
        validate_on_exceeded(&format!("{path}.on_exceeded"), &self.on_exceeded)?;
        Ok(())
    }
}

/// One named concurrency cap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyPolicy {
    pub id: String,
    /// Maximum simultaneous in-flight calls.
    pub max_concurrent: u32,
    /// Scope (typically `per_tool`, `global`, or `per_identity`).
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claim: Option<String>,
    /// Action when the cap is hit. `deny` returns immediately;
    /// `queue` waits up to `queue_timeout_ms`.
    #[serde(default = "default_on_exceeded_concurrency")]
    pub on_exceeded: String,
    /// Timeout for queued callers when `on_exceeded: queue`.
    /// Default 30s.
    #[serde(default = "default_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
}

impl ConcurrencyPolicy {
    pub fn validate(&self, path: &str) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(anyhow!("{path}.id must not be empty"));
        }
        if self.max_concurrent == 0 {
            return Err(anyhow!("{path}.max_concurrent must be > 0"));
        }
        validate_scope(path, &self.scope, &self.identity_claim)?;
        match self.on_exceeded.as_str() {
            "deny" | "queue" => {}
            other => {
                return Err(anyhow!(
                    "{path}.on_exceeded: must be `deny` or `queue` (got `{other}`)"
                ));
            }
        }
        if self.on_exceeded == "queue" && self.queue_timeout_ms == 0 {
            return Err(anyhow!(
                "{path}.queue_timeout_ms must be > 0 when on_exceeded: queue"
            ));
        }
        Ok(())
    }
}

fn validate_scope(path: &str, scope: &str, identity_claim: &Option<String>) -> Result<()> {
    match scope {
        "per_identity" => {
            if identity_claim.is_none() {
                return Err(anyhow!(
                    "{path}.scope: `per_identity` requires `identity_claim:` (e.g. `sub`, `org_id`)"
                ));
            }
        }
        "global" | "per_session" | "per_tool" | "per_claim" => {
            if identity_claim.is_some() {
                return Err(anyhow!(
                    "{path}.identity_claim: only valid when `scope: per_identity` \
                     (got scope `{scope}`)"
                ));
            }
        }
        other => {
            return Err(anyhow!(
                "{path}.scope: must be one of `per_identity` | `global` | `per_session` | \
                 `per_tool` | `per_claim` (got `{other}`)"
            ));
        }
    }
    Ok(())
}

fn validate_on_exceeded(path: &str, value: &str) -> Result<()> {
    match value {
        "deny" | "queue" | "shed_load" => Ok(()),
        other => Err(anyhow!(
            "{path}: must be `deny` | `queue` | `shed_load` (got `{other}`)"
        )),
    }
}

fn validate_on_error(path: &str, value: &str) -> Result<()> {
    match value {
        // Empty is accepted so a `derive(Default)`-constructed config (which
        // yields "") behaves as the fail-closed default.
        "" | "deny" | "allow" => Ok(()),
        other => Err(anyhow!("{path}: must be `deny` | `allow` (got `{other}`)")),
    }
}

fn validate_window(path: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("{path} must not be empty"));
    }
    let (num_part, unit) = value.split_at(value.len().saturating_sub(1));
    let num: u64 = num_part
        .parse()
        .map_err(|_| anyhow!("{path}: invalid duration `{value}` (expected like `24h`, `30d`)"))?;
    match unit {
        "s" | "m" | "h" => Ok(()),
        "d" => {
            if num > 30 {
                return Err(anyhow!("{path}: `{value}` exceeds maximum `30d` window"));
            }
            Ok(())
        }
        other => Err(anyhow!(
            "{path}: invalid window unit `{other}` (expected `s` | `m` | `h` | `d`)"
        )),
    }
}

fn default_rate_limit_kind() -> String {
    "token_bucket".to_owned()
}

fn default_budget_kind() -> String {
    "cost".to_owned()
}

fn default_scope() -> String {
    "per_identity".to_owned()
}

fn default_on_exceeded() -> String {
    "deny".to_owned()
}

fn default_on_error() -> String {
    "deny".to_owned()
}

fn default_on_exceeded_concurrency() -> String {
    "deny".to_owned()
}

fn default_queue_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate_limit(id: &str) -> RateLimitPolicy {
        RateLimitPolicy {
            id: id.to_owned(),
            kind: "token_bucket".to_owned(),
            scope: "per_identity".to_owned(),
            identity_claim: Some("sub".to_owned()),
            rate: RateLimitRate {
                calls_per_minute: 60,
            },
            burst: None,
            on_exceeded: "deny".to_owned(),
        }
    }

    fn budget(id: &str) -> BudgetPolicy {
        BudgetPolicy {
            id: id.to_owned(),
            kind: "cost".to_owned(),
            scope: "per_identity".to_owned(),
            identity_claim: Some("sub".to_owned()),
            cap_usd: Some(100.0),
            cap_token_count: None,
            cap_calls: None,
            window: "24h".to_owned(),
            warn_at_pct: Some(80),
            on_exceeded: "deny".to_owned(),
            acknowledge_unenforced: true,
        }
    }

    fn concurrency(id: &str) -> ConcurrencyPolicy {
        ConcurrencyPolicy {
            id: id.to_owned(),
            max_concurrent: 10,
            scope: "per_tool".to_owned(),
            identity_claim: None,
            on_exceeded: "queue".to_owned(),
            queue_timeout_ms: 30_000,
        }
    }

    #[test]
    fn empty_quotas_validate() {
        let q = QuotasConfig::default();
        q.validate().unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn rate_limit_round_trip_validates() {
        let mut q = QuotasConfig::default();
        q.rate_limits.push(rate_limit("tier-pro"));
        q.budgets.push(budget("daily-100"));
        q.concurrency.push(concurrency("heavy"));
        q.validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_rate_limit_ids() {
        let mut q = QuotasConfig::default();
        q.rate_limits.push(rate_limit("dup"));
        q.rate_limits.push(rate_limit("dup"));
        let err = q.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate id `dup`"), "{err}");
    }

    #[test]
    fn rejects_per_identity_without_claim() {
        let mut policy = rate_limit("x");
        policy.identity_claim = None;
        let err = policy.validate("path").unwrap_err().to_string();
        assert!(err.contains("requires `identity_claim:`"), "{err}");
    }

    #[test]
    fn rejects_identity_claim_with_global_scope() {
        let mut policy = rate_limit("x");
        policy.scope = "global".to_owned();
        // identity_claim still Some(_)
        let err = policy.validate("path").unwrap_err().to_string();
        assert!(
            err.contains("only valid when `scope: per_identity`"),
            "{err}"
        );
    }

    #[test]
    fn cost_budget_requires_cap_usd() {
        let mut p = budget("x");
        p.cap_usd = None;
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("`kind: cost` requires `cap_usd:`"), "{err}");
    }

    #[test]
    fn token_budget_requires_cap_token_count() {
        let mut p = budget("x");
        p.kind = "token_count".to_owned();
        p.cap_usd = None;
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("`kind: token_count` requires"), "{err}");
    }

    #[test]
    fn rejects_window_over_30_days() {
        let mut p = budget("x");
        p.window = "31d".to_owned();
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("exceeds maximum `30d`"), "{err}");
    }

    #[test]
    fn rejects_invalid_window_unit() {
        let mut p = budget("x");
        p.window = "5y".to_owned();
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("invalid window unit"), "{err}");
    }

    #[test]
    fn warn_at_pct_clamped_to_100() {
        let mut p = budget("x");
        p.warn_at_pct = Some(150);
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("warn_at_pct must be 0..=100"), "{err}");
    }

    #[test]
    fn concurrency_zero_rejected() {
        let mut c = concurrency("x");
        c.max_concurrent = 0;
        let err = c.validate("path").unwrap_err().to_string();
        assert!(err.contains("max_concurrent must be > 0"), "{err}");
    }

    #[test]
    fn rejects_unknown_on_exceeded() {
        let mut p = rate_limit("x");
        p.on_exceeded = "panic".to_owned();
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("must be `deny`"), "{err}");
    }

    #[test]
    fn cost_budget_without_acknowledge_is_rejected() {
        let mut p = budget("x");
        p.acknowledge_unenforced = false;
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("not enforced at runtime"), "{err}");
    }

    #[test]
    fn token_budget_without_acknowledge_is_rejected() {
        let mut p = budget("x");
        p.kind = "token_count".to_owned();
        p.cap_usd = None;
        p.cap_token_count = Some(1000);
        p.acknowledge_unenforced = false;
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("not enforced at runtime"), "{err}");
    }

    #[test]
    fn cost_budget_with_acknowledge_validates() {
        let p = budget("x"); // helper sets acknowledge_unenforced: true
        assert!(p.validate("path").is_ok());
    }

    #[test]
    fn call_count_budget_validates_without_acknowledge() {
        let mut p = budget("x");
        p.kind = "call_count".to_owned();
        p.cap_usd = None;
        p.cap_calls = Some(100);
        p.acknowledge_unenforced = false;
        assert!(p.validate("path").is_ok());
    }

    #[test]
    fn cost_budget_missing_cap_errors_before_acknowledge_guard() {
        let mut p = budget("x");
        p.cap_usd = None;
        p.acknowledge_unenforced = false;
        let err = p.validate("path").unwrap_err().to_string();
        assert!(err.contains("requires `cap_usd:`"), "{err}");
    }

    #[test]
    fn defaults_on_error_to_deny() {
        // Omitted in YAML -> serde default "deny".
        let q: QuotasConfig = serde_yaml::from_str("rate_limits: []\n").unwrap();
        assert_eq!(q.on_error, "deny");
        assert!(!q.fail_open_on_error());
        // Derive-Default construction yields "" which validates and is
        // treated as deny (fail-closed).
        let d = QuotasConfig::default();
        assert!(d.validate().is_ok());
        assert!(!d.fail_open_on_error());
    }

    #[test]
    fn rejects_unknown_on_error() {
        let q = QuotasConfig {
            on_error: "panic".to_owned(),
            ..Default::default()
        };
        let err = q.validate().unwrap_err().to_string();
        assert!(err.contains("must be `deny` | `allow`"), "{err}");
    }

    #[test]
    fn accepts_on_error_allow() {
        let q = QuotasConfig {
            on_error: "allow".to_owned(),
            ..Default::default()
        };
        assert!(q.validate().is_ok());
        assert!(q.fail_open_on_error());
    }

    #[test]
    fn yaml_round_trip_minimal() {
        let yaml = r#"
rate_limits:
  - id: tier-free
    kind: token_bucket
    scope: per_identity
    identity_claim: sub
    rate:
      calls_per_minute: 60
budgets:
  - id: daily
    kind: cost
    scope: per_identity
    identity_claim: sub
    cap_usd: 100
    window: 24h
    acknowledge_unenforced: true
"#;
        let q: QuotasConfig = serde_yaml::from_str(yaml).unwrap();
        q.validate().unwrap();
        assert_eq!(q.rate_limits.len(), 1);
        assert_eq!(q.budgets.len(), 1);
    }

    // -- BackendQuotasRef + validate_binding_ref ----------------

    fn registry_with_one_of_each() -> QuotasConfig {
        serde_yaml::from_str(
            r#"
rate_limits:
  - id: tier-pro
    kind: token_bucket
    scope: per_identity
    identity_claim: sub
    rate: { calls_per_minute: 1000 }
budgets:
  - id: daily-100usd
    kind: cost
    scope: per_identity
    identity_claim: sub
    cap_usd: 100
    window: 24h
    acknowledge_unenforced: true
concurrency:
  - id: heavy-tools
    max_concurrent: 10
    scope: per_tool
"#,
        )
        .unwrap()
    }

    #[test]
    fn binding_quotas_ref_empty_is_default() {
        let r = BackendQuotasRef::default();
        assert!(r.is_empty());
    }

    #[test]
    fn validate_binding_ref_passes_on_known_ids() {
        let q = registry_with_one_of_each();
        let r = BackendQuotasRef {
            rate_limit: Some("tier-pro".into()),
            budget: Some("daily-100usd".into()),
            concurrency: Some("heavy-tools".into()),
        };
        q.validate_binding_ref(&r, "test").unwrap();
    }

    #[test]
    fn validate_binding_ref_passes_on_partial_ref() {
        let q = registry_with_one_of_each();
        // Only rate_limit named — budget + concurrency absent.
        let r = BackendQuotasRef {
            rate_limit: Some("tier-pro".into()),
            budget: None,
            concurrency: None,
        };
        q.validate_binding_ref(&r, "test").unwrap();
    }

    #[test]
    fn validate_binding_ref_passes_on_empty_ref() {
        // Empty registry, empty ref — nothing to validate.
        let q = QuotasConfig::default();
        let r = BackendQuotasRef::default();
        q.validate_binding_ref(&r, "test").unwrap();
    }

    #[test]
    fn validate_binding_ref_refuses_unknown_rate_limit_id() {
        let q = registry_with_one_of_each();
        let r = BackendQuotasRef {
            rate_limit: Some("does-not-exist".into()),
            ..Default::default()
        };
        let err = q.validate_binding_ref(&r, "test").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does-not-exist"), "id surfaced: {msg}");
        assert!(msg.contains("rate_limit"), "field surfaced: {msg}");
    }

    #[test]
    fn validate_binding_ref_refuses_unknown_budget_id() {
        let q = registry_with_one_of_each();
        let r = BackendQuotasRef {
            budget: Some("budget-typo".into()),
            ..Default::default()
        };
        let err = q.validate_binding_ref(&r, "test").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("budget-typo"), "id surfaced: {msg}");
        assert!(msg.contains("budget"), "field surfaced: {msg}");
    }

    #[test]
    fn validate_binding_ref_refuses_unknown_concurrency_id() {
        let q = registry_with_one_of_each();
        let r = BackendQuotasRef {
            concurrency: Some("conc-typo".into()),
            ..Default::default()
        };
        let err = q.validate_binding_ref(&r, "test").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("conc-typo"), "id surfaced: {msg}");
        assert!(msg.contains("concurrency"), "field surfaced: {msg}");
    }

    #[test]
    fn validate_binding_ref_path_is_path_qualified() {
        let q = registry_with_one_of_each();
        let r = BackendQuotasRef {
            rate_limit: Some("missing".into()),
            ..Default::default()
        };
        let err = q
            .validate_binding_ref(&r, "mcp.capabilities.tools[name=`my-tool`]")
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mcp.capabilities.tools"),
            "path surfaced: {msg}"
        );
        assert!(msg.contains("my-tool"), "binding name surfaced: {msg}");
    }
}
