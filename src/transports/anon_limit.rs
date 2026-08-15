//! Per-IP token-bucket rate limiter for **anonymous** `/mcp` traffic.
//!
//! An anonymous gateway (`cloud.allow_anonymous: true`, or any request that
//! resolves to `RequestIdentity::Anonymous`) has no per-tenant identity to
//! meter against, so before this limiter a single client could flood the
//! dispatch path unboundedly (the per-session caps only bite after a session
//! exists). The check runs ONLY when the resolved identity is anonymous —
//! authenticated traffic never touches it, so the authed hot path pays
//! nothing.
//!
//! Data-plane design (vs the control-plane `cp-core::ratelimit` Mutex map):
//! buckets live in a `DashMap` keyed by client IP — per-entry sharded locking,
//! no global mutex on the request path. Limits are NOT stored here; callers
//! pass the current config values on every check, so a config hot-reload
//! takes effect immediately without rebuilding the map. The map itself is a
//! process-wide static (matches the `feature_flags` / `span_sampling`
//! precedent for process-level gateway state) so it survives runtime swaps.

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Instant;

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

/// Process-wide bucket map. See module docs for why a static.
static BUCKETS: LazyLock<DashMap<IpAddr, Bucket>> = LazyLock::new(DashMap::new);

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

/// Take one token for `ip` against a bucket refilled at `per_min`/60 tokens
/// per second with `burst` capacity. `true` = allowed. `per_min == 0`
/// disables (always allowed).
pub fn check(ip: IpAddr, per_min: u32, burst: u32) -> bool {
    check_at(ip, per_min, burst, Instant::now())
}

/// [`check`] at an explicit instant — the seam unit tests use to exercise
/// refill deterministically without sleeping.
pub fn check_at(ip: IpAddr, per_min: u32, burst: u32, now: Instant) -> bool {
    if per_min == 0 {
        return true;
    }
    let capacity = burst.max(1) as f64;
    let refill_per_sec = per_min as f64 / 60.0;

    // Bound memory under an IP spray. Amortised: only when the map is
    // oversized, and DashMap::retain locks shard-by-shard (no global stall).
    if BUCKETS.len() > MAX_TRACKED_IPS {
        BUCKETS.retain(|_, b| now.saturating_duration_since(b.last).as_secs() < IDLE_EVICT_SECS);
    }

    let mut entry = BUCKETS.entry(ip).or_insert(Bucket {
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
        true
    } else {
        false
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
