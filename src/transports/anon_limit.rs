//! Per-IP token-bucket rate limiters for unauthenticated surfaces:
//! **anonymous** `/mcp` traffic, the OAuth token endpoint and the pages of
//! interactive sign-in.
//!
//! An anonymous gateway (`cloud.allow_anonymous: true`, or any request that
//! resolves to `RequestIdentity::Anonymous`) has no per-tenant identity to
//! meter against, so before this limiter a single client could flood the
//! dispatch path unboundedly (the per-session caps only bite after a session
//! exists). The check runs ONLY when the resolved identity is anonymous —
//! authenticated traffic never touches it, so the authed hot path pays
//! nothing. `POST /oauth/token` is reachable before any identity exists, so
//! it has a budget of its own, [`OAUTH_TOKEN`], and so do the sign-in pages
//! a browser visits, [`OAUTH_BROWSER`].
//!
//! Data-plane design (vs the control-plane `cp-core::ratelimit` Mutex map):
//! buckets live in a `DashMap` keyed by client IP — per-entry sharded locking,
//! no global mutex on the request path. Limits are NOT stored here; callers
//! pass the current config values on every check, so a config hot-reload
//! takes effect immediately without rebuilding the map. Each budget is a
//! process-wide static (matches the `feature_flags` / `span_sampling`
//! precedent for process-level gateway state) so it survives runtime swaps.

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Stop tracking idle buckets once the map grows past this, to bound memory
/// under a spray of distinct source IPs. Evicts buckets idle longer than
/// [`IDLE_EVICT_SECS`]; active attackers stay tracked (that's the point).
const MAX_TRACKED_IPS: usize = 100_000;
const IDLE_EVICT_SECS: u64 = 600;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// One per-IP budget: a token bucket for every client address.
#[derive(Default)]
pub struct IpRateLimiter {
    buckets: DashMap<IpAddr, Bucket>,
}

/// The anonymous `/mcp` budget. See module docs for why a static.
static BUCKETS: LazyLock<IpRateLimiter> = LazyLock::new(IpRateLimiter::default);

/// The `POST /oauth/token` budget
/// (`governance.access.authorization_server.rate_limit_per_min`).
pub static OAUTH_TOKEN: LazyLock<IpRateLimiter> = LazyLock::new(IpRateLimiter::default);

/// The budget the interactive sign-in pages (`/oauth/authorize`,
/// `/oauth/consent`, `/oauth/callback`, `/oauth/connect`) share
/// (`governance.access.authorization_server.interactive.rate_limit_per_min`).
pub static OAUTH_BROWSER: LazyLock<IpRateLimiter> = LazyLock::new(IpRateLimiter::default);

/// Resolve the client IP for limiting: the first `X-Forwarded-For` hop when
/// the operator trusts the fronting proxy (`server.trust_proxy_ip`), else the
/// transport peer. `None` when the source is unattributable (no trusted XFF
/// and no `ConnectInfo` — an in-process test, or a transport that didn't
/// stamp the peer): the caller SKIPS limiting then, because lumping every
/// unattributable caller into one shared bucket would collectively throttle
/// them on each other's traffic — worse than not limiting at all. Both real
/// serve paths always stamp the peer, so production traffic is always
/// attributable.
pub fn client_ip(trust_proxy: bool, xff: Option<&str>, peer: Option<IpAddr>) -> Option<IpAddr> {
    if trust_proxy
        && let Some(xff) = xff
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    peer
}

/// Take one token for `ip` from the anonymous `/mcp` budget, a bucket
/// refilled at `per_min`/60 tokens per second with `burst` capacity.
/// `true` = allowed. `per_min == 0` disables (always allowed).
pub fn check(ip: IpAddr, per_min: u32, burst: u32) -> bool {
    check_at(ip, per_min, burst, Instant::now())
}

/// [`check`] at an explicit instant — the seam unit tests use to exercise
/// refill deterministically without sleeping.
pub fn check_at(ip: IpAddr, per_min: u32, burst: u32, now: Instant) -> bool {
    BUCKETS.acquire_at(ip, per_min, burst, now).is_ok()
}

impl IpRateLimiter {
    /// Take one token for `ip` from a bucket refilled at `per_min`/60
    /// tokens per second with `burst` capacity. `Err` carries how long
    /// until the next token. `per_min == 0` disables (always allowed).
    pub fn acquire(&self, ip: IpAddr, per_min: u32, burst: u32) -> Result<(), Duration> {
        self.acquire_at(ip, per_min, burst, Instant::now())
    }

    /// [`Self::acquire`] at an explicit instant.
    pub fn acquire_at(
        &self,
        ip: IpAddr,
        per_min: u32,
        burst: u32,
        now: Instant,
    ) -> Result<(), Duration> {
        if per_min == 0 {
            return Ok(());
        }
        let capacity = burst.max(1) as f64;
        let refill_per_sec = per_min as f64 / 60.0;

        // Bound memory under an IP spray. Amortised: only when the map is
        // oversized, and DashMap::retain locks shard-by-shard (no global stall).
        if self.buckets.len() > MAX_TRACKED_IPS {
            self.buckets
                .retain(|_, b| now.saturating_duration_since(b.last).as_secs() < IDLE_EVICT_SECS);
        }

        let mut entry = self.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let b = entry.value_mut();
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        // Refill against the CURRENT config (limits can hot-reload between
        // checks); clamp to the current capacity so a lowered burst applies.
        b.tokens = (b.tokens + elapsed * refill_per_sec).min(capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - b.tokens) / refill_per_sec))
        }
    }

    /// Give back the token an [`Self::acquire`] for `ip` took, for a
    /// request that turned out not to count against the budget. Never
    /// fills the bucket past `burst`.
    pub fn refund(&self, ip: IpAddr, per_min: u32, burst: u32) {
        if per_min == 0 {
            return;
        }
        if let Some(mut bucket) = self.buckets.get_mut(&ip) {
            bucket.tokens = (bucket.tokens + 1.0).min(burst.max(1) as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    // Distinct per-test IPs — the bucket map is a process-wide static shared
    // across tests in this binary.
    fn ip(a: u8, b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 99, a, b))
    }

    #[test]
    fn allows_burst_then_denies() {
        let t = Instant::now();
        let i = ip(1, 1);
        assert!(check_at(i, 60, 3, t));
        assert!(check_at(i, 60, 3, t));
        assert!(check_at(i, 60, 3, t));
        assert!(
            !check_at(i, 60, 3, t),
            "burst exhausted at the same instant"
        );
    }

    #[test]
    fn refills_over_time() {
        let t = Instant::now();
        let i = ip(1, 2);
        assert!(check_at(i, 60, 2, t)); // 1 token/sec
        assert!(check_at(i, 60, 2, t));
        assert!(!check_at(i, 60, 2, t));
        assert!(check_at(i, 60, 2, t + Duration::from_secs(1)));
        assert!(!check_at(i, 60, 2, t + Duration::from_secs(1)));
    }

    #[test]
    fn buckets_are_per_ip() {
        let t = Instant::now();
        assert!(check_at(ip(1, 3), 60, 1, t));
        assert!(!check_at(ip(1, 3), 60, 1, t), "first ip exhausted");
        assert!(check_at(ip(1, 4), 60, 1, t), "second ip has its own bucket");
    }

    #[test]
    fn zero_per_min_disables() {
        let t = Instant::now();
        for _ in 0..1000 {
            assert!(check_at(ip(1, 5), 0, 0, t));
        }
    }

    #[test]
    fn lowered_burst_applies_on_reload() {
        let t = Instant::now();
        let i = ip(1, 6);
        // Bucket created at burst 10 (one token spent → 9 left); the config
        // then drops to burst 2 — the clamp caps the carried tokens at 2, so
        // exactly two more checks pass before deny.
        assert!(check_at(i, 60, 10, t));
        assert!(check_at(i, 60, 2, t));
        assert!(check_at(i, 60, 2, t));
        assert!(!check_at(i, 60, 2, t), "clamped to the lowered burst");
    }

    #[test]
    fn a_denial_says_when_the_next_token_arrives() {
        let limiter = IpRateLimiter::default();
        let t = Instant::now();
        let i = ip(2, 1);
        // 2 per minute: one token every 30 s.
        assert!(limiter.acquire_at(i, 2, 2, t).is_ok());
        assert!(limiter.acquire_at(i, 2, 2, t).is_ok());
        let wait = limiter.acquire_at(i, 2, 2, t).expect_err("budget spent");
        assert!((wait.as_secs_f64() - 30.0).abs() < 0.01, "{wait:?}");
        let wait = limiter
            .acquire_at(i, 2, 2, t + Duration::from_secs(20))
            .expect_err("a third of a token short");
        assert!((wait.as_secs_f64() - 10.0).abs() < 0.01, "{wait:?}");
        assert!(
            limiter
                .acquire_at(i, 2, 2, t + Duration::from_secs(31))
                .is_ok()
        );
    }

    #[test]
    fn a_refund_gives_the_token_back_up_to_the_burst() {
        let limiter = IpRateLimiter::default();
        let t = Instant::now();
        let i = ip(2, 3);
        for _ in 0..5 {
            assert!(limiter.acquire_at(i, 2, 2, t).is_ok());
            limiter.refund(i, 2, 2);
        }
        limiter.refund(i, 2, 2);
        assert!(limiter.acquire_at(i, 2, 2, t).is_ok());
        assert!(limiter.acquire_at(i, 2, 2, t).is_ok());
        assert!(
            limiter.acquire_at(i, 2, 2, t).is_err(),
            "a refund never lifts the bucket past its burst"
        );
    }

    #[test]
    fn budgets_are_independent() {
        let t = Instant::now();
        let i = ip(2, 2);
        let token_endpoint = IpRateLimiter::default();
        assert!(check_at(i, 60, 1, t));
        assert!(!check_at(i, 60, 1, t), "the anonymous budget is spent");
        assert!(
            token_endpoint.acquire_at(i, 60, 1, t).is_ok(),
            "another budget still has its token"
        );
    }

    #[test]
    fn xff_used_only_when_trusted() {
        let xff = Some("203.0.113.7, 10.0.0.1");
        let peer = Some(ip(1, 7));
        assert_eq!(
            client_ip(false, xff, peer),
            Some(ip(1, 7)),
            "ignore XFF untrusted"
        );
        assert_eq!(
            client_ip(true, xff, peer),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );
        assert_eq!(client_ip(true, None, peer), Some(ip(1, 7)), "no XFF → peer");
        assert_eq!(
            client_ip(true, None, None),
            None,
            "unattributable source → caller skips limiting"
        );
    }
}
