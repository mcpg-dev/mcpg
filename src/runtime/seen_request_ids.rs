use super::*;

/// A locally-registered cancellation token plus the identity that owns
/// the in-flight request/task it can interrupt. The cancellation-bus
/// subscriber checks an incoming event's principal/session against these
/// before firing the token, so one principal cannot abort another's
/// in-flight work by guessing its request/task id.
#[derive(Clone)]
pub(crate) struct RegisteredCancellation {
    pub(super) token: tokio_util::sync::CancellationToken,
    /// Session that owns the in-flight work. `None` when the owner had
    /// no session (anonymous modern-stateless caller).
    pub(super) owner_session: Option<String>,
    /// Principal (OIDC `sub` claim or equivalent) that owns the work.
    /// `None` for an unauthenticated owner.
    pub(super) owner_principal: Option<String>,
}

/// Per-session seen-request-id window. A `HashSet` answers membership in
/// O(1); the `VecDeque` records insertion order so the oldest id can be
/// evicted when the window is full. The two stay in lockstep — every id
/// is in both, and eviction removes from both — so an aged-out id can be
/// re-presented (it is no longer a duplicate) while still-resident ids
/// stay rejected.
///
/// Entries are fixed-width digests rather than the ids themselves. The
/// window only ever answers "have I seen this before", so it never needs
/// the original bytes, and storing them made a caller-supplied string the
/// unit of server memory — twice over, once per collection.
#[derive(Default)]
pub(super) struct SeenRequestIds {
    order: std::collections::VecDeque<u128>,
    set: std::collections::HashSet<u128>,
}

/// Digest an id down to the fixed width the window stores.
///
/// A collision lets one id be mistaken for another *within a single
/// session's window*, whose only effect is rejecting a request as a
/// duplicate. At 128 bits and a 65 536-entry window that is not reachable,
/// and the failure mode is a refused request rather than a granted one.
fn digest(id: &str) -> u128 {
    let h = blake3::hash(id.as_bytes());
    let bytes = h.as_bytes();
    u128::from_le_bytes(bytes[..16].try_into().expect("blake3 digest is 32 bytes"))
}

impl SeenRequestIds {
    /// Record `id`, evicting the oldest entry when the window reaches
    /// `cap`. Returns `true` when `id` was newly recorded, `false` when
    /// it was already present (a duplicate on this session).
    pub(super) fn insert(&mut self, id: String, cap: usize) -> bool {
        let key = digest(&id);
        if self.set.contains(&key) {
            return false;
        }
        if self.order.len() >= cap
            && let Some(evicted) = self.order.pop_front()
        {
            self.set.remove(&evicted);
            metrics::counter!("mcpg_request_id_window_evicted_total").increment(1);
        }
        self.order.push_back(key);
        self.set.insert(key);
        true
    }
}

/// Decide whether a resuming caller owns a suspended pipeline. Ownership
/// requires the same principal; for an identified owner the session must
/// also match. An anonymous owner (`None` principal) is matched by
/// principal alone — its modern synthetic session is per-request
/// ephemeral, so replay of anonymous resumes is covered by the
/// requestState single-use guard rather than a session comparison.
/// Missing/empty sessions never satisfy the identified-owner case.
pub(super) fn resumer_owns_pipeline(
    owner_principal: Option<&str>,
    owner_session: &str,
    resumer_principal: Option<&str>,
    resumer_session: Option<&str>,
) -> bool {
    let principal_match = owner_principal == resumer_principal;
    let session_match = owner_principal.is_none()
        || (!owner_session.is_empty() && resumer_session == Some(owner_session));
    principal_match && session_match
}

/// Decide whether a caller may operate on a session. The caller's
/// trust-qualified principal key (see `synthetic_principal_key` — embeds
/// trust tier + provider + issuer, so a header-asserted `alice` can't
/// match a verified `alice`) must equal the session creator's. An
/// anonymous-owned session (`None`) is matched only by an anonymous
/// caller, and an identified caller cannot claim an anonymous session
/// (or vice versa).
pub(super) fn session_owner_matches(owner_key: Option<&str>, caller_key: Option<&str>) -> bool {
    owner_key == caller_key
}

/// Decide whether a cancellation event's requester owns the in-flight
/// work the token interrupts. Mirrors [`resumer_owns_pipeline`]: the
/// requester must be the same principal; an identified owner must also
/// share the session. Anonymous owners are matched by principal alone.
pub(super) fn cancellation_requester_is_owner(
    registered: &RegisteredCancellation,
    event: &cancellation_bus::CancellationEvent,
) -> bool {
    let principal_match = registered.owner_principal.as_deref() == event.principal_id.as_deref();
    let session_match = registered.owner_principal.is_none()
        || registered
            .owner_session
            .as_deref()
            .is_some_and(|owner| owner == event.session_id);
    principal_match && session_match
}

#[cfg(test)]
mod seen_request_ids_tests {
    use super::SeenRequestIds;

    #[test]
    fn rejects_exact_duplicate() {
        let mut w = SeenRequestIds::default();
        assert!(w.insert("a".to_owned(), 4));
        assert!(!w.insert("a".to_owned(), 4));
    }

    #[test]
    fn allows_distinct_ids() {
        let mut w = SeenRequestIds::default();
        for id in ["a", "b", "c"] {
            assert!(w.insert(id.to_owned(), 4));
        }
    }

    #[test]
    fn fifo_eviction_allows_reinsert_of_evicted_only() {
        let mut w = SeenRequestIds::default();
        assert!(w.insert("a".to_owned(), 2)); // [a]
        assert!(w.insert("b".to_owned(), 2)); // [a, b]
        // Window full; inserting "c" evicts the oldest ("a") -> [b, c].
        assert!(w.insert("c".to_owned(), 2));
        // "b" is still resident, so it is rejected (window unchanged).
        assert!(!w.insert("b".to_owned(), 2));
        // "a" aged out, so it is no longer a duplicate (re-inserting it
        // evicts the now-oldest "b") -> [c, a].
        assert!(w.insert("a".to_owned(), 2));
        // "b" was just evicted, so it is re-insertable again.
        assert!(w.insert("b".to_owned(), 2));
    }

    #[test]
    fn set_and_order_stay_in_lockstep_past_cap() {
        let mut w = SeenRequestIds::default();
        for i in 0..100 {
            w.insert(format!("id-{i}"), 8);
        }
        assert_eq!(w.order.len(), 8);
        assert_eq!(w.set.len(), 8);
    }
}
