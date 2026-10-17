//! The owner's in-memory view of which subscriptions exist per event type.
//!
//! Built from the type index of the subscription store when this replica
//! becomes the owner and again periodically, and kept current in between by
//! the hints every replica broadcasts after a subscription write. Hints are at
//! most once, so the periodic rebuild is what bounds a missed one. Demand for
//! a source, and the fan-out of an occurrence, read this view instead of the
//! store. Poll and stream leases count as demand too, by type and the end of
//! the last lease, never as subscriptions.

use std::collections::HashMap;

use super::subscriptions::{HintOp, SubscriptionHint, TypeIndexEntry};

/// Subscription ids per event type, with the end of each grant.
#[derive(Debug, Default, Clone)]
pub struct SubscriptionIndex {
    by_type: HashMap<String, HashMap<String, Option<u64>>>,
    /// When the last poll or stream lease of each type ends.
    leased_until: HashMap<String, u64>,
}

impl SubscriptionIndex {
    /// Apply one hint.
    pub fn apply(&mut self, hint: &SubscriptionHint) {
        match hint.op {
            HintOp::Upsert => {
                self.by_type
                    .entry(hint.name.clone())
                    .or_default()
                    .insert(hint.id.clone(), hint.expires_at_ms);
            }
            HintOp::Delete => self.remove(&hint.name, &hint.id),
            HintOp::Lease => {
                if let Some(until) = hint.expires_at_ms {
                    self.note_lease(&hint.name, until);
                }
            }
        }
    }

    /// A poll or stream lease of type `name` runs until `until_ms`.
    pub fn note_lease(&mut self, name: &str, until_ms: u64) {
        let until = self.leased_until.entry(name.to_owned()).or_default();
        *until = (*until).max(until_ms);
    }

    /// Keep the leases `other` knows of.
    pub fn keep_leases_of(&mut self, other: &Self) {
        for (name, until) in &other.leased_until {
            self.note_lease(name, *until);
        }
    }

    /// Whether type `name` has demand at `now_ms`: a live subscription or
    /// a poll or stream lease.
    pub fn has_demand(&self, name: &str, now_ms: u64) -> bool {
        self.has_live(name, now_ms)
            || self
                .leased_until
                .get(name)
                .is_some_and(|until| *until > now_ms)
    }

    /// Replace what is known of type `name` with a fresh listing.
    pub fn replace_type(&mut self, name: &str, entries: Vec<TypeIndexEntry>) {
        let ids = entries
            .into_iter()
            .map(|e| (e.id, e.expires_at_ms))
            .collect::<HashMap<_, _>>();
        if ids.is_empty() {
            self.by_type.remove(name);
        } else {
            self.by_type.insert(name.to_owned(), ids);
        }
    }

    /// Keep only the types in `names`.
    pub fn retain_types(&mut self, names: &[&str]) {
        self.by_type
            .retain(|name, _| names.contains(&name.as_str()));
        self.leased_until
            .retain(|name, _| names.contains(&name.as_str()));
    }

    /// Forget subscription `id` of type `name`.
    pub fn remove(&mut self, name: &str, id: &str) {
        if let Some(ids) = self.by_type.get_mut(name) {
            ids.remove(id);
            if ids.is_empty() {
                self.by_type.remove(name);
            }
        }
    }

    /// Whether type `name` has a subscription whose grant runs at `now_ms`.
    pub fn has_live(&self, name: &str, now_ms: u64) -> bool {
        self.by_type
            .get(name)
            .is_some_and(|ids| ids.values().any(|end| end.is_none_or(|e| e > now_ms)))
    }

    /// Ids of the subscriptions of `name` whose grant runs at `now_ms`,
    /// sorted.
    pub fn live_ids(&self, name: &str, now_ms: u64) -> Vec<String> {
        let mut ids: Vec<String> = self
            .by_type
            .get(name)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter(|(_, end)| end.is_none_or(|e| e > now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// `(name, id)` of every subscription whose grant ended more than
    /// `grace_ms` before `now_ms`.
    pub fn expired(&self, now_ms: u64, grace_ms: u64) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .by_type
            .iter()
            .flat_map(|(name, ids)| {
                ids.iter().filter_map(move |(id, end)| {
                    end.filter(|e| e.saturating_add(grace_ms) <= now_ms)
                        .map(|_| (name.clone(), id.clone()))
                })
            })
            .collect();
        out.sort();
        out
    }

    /// Live subscriptions of `name` at `now_ms`.
    pub fn live_count(&self, name: &str, now_ms: u64) -> usize {
        self.live_ids(name, now_ms).len()
    }

    /// Live subscriptions of every type at `now_ms`.
    pub fn total_live(&self, now_ms: u64) -> usize {
        self.by_type
            .values()
            .map(|ids| {
                ids.values()
                    .filter(|end| end.is_none_or(|e| e > now_ms))
                    .count()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(op: HintOp, id: &str, name: &str, end: Option<u64>) -> SubscriptionHint {
        SubscriptionHint {
            op,
            id: id.to_owned(),
            name: name.to_owned(),
            expires_at_ms: end,
        }
    }

    #[test]
    fn hints_add_and_remove_subscriptions() {
        let mut index = SubscriptionIndex::default();
        index.apply(&hint(HintOp::Upsert, "sub_a", "orders", Some(100)));
        index.apply(&hint(HintOp::Upsert, "sub_b", "orders", None));
        assert!(index.has_live("orders", 50));
        assert_eq!(index.live_ids("orders", 50), vec!["sub_a", "sub_b"]);
        assert_eq!(index.live_ids("orders", 100), vec!["sub_b"]);
        index.apply(&hint(HintOp::Delete, "sub_b", "orders", None));
        assert!(!index.has_live("orders", 100));
        assert!(index.has_live("orders", 99));
        index.apply(&hint(HintOp::Delete, "sub_a", "orders", None));
        assert!(!index.has_live("orders", 0));
        assert_eq!(index.total_live(0), 0);
    }

    #[test]
    fn a_refresh_moves_the_end_of_the_grant() {
        let mut index = SubscriptionIndex::default();
        index.apply(&hint(HintOp::Upsert, "sub_a", "orders", Some(100)));
        index.apply(&hint(HintOp::Upsert, "sub_a", "orders", Some(500)));
        assert!(index.has_live("orders", 300));
        assert_eq!(index.live_count("orders", 300), 1);
    }

    #[test]
    fn a_listing_replaces_the_type() {
        let mut index = SubscriptionIndex::default();
        index.apply(&hint(HintOp::Upsert, "sub_stale", "orders", None));
        index.replace_type(
            "orders",
            vec![TypeIndexEntry {
                v: 1,
                id: "sub_fresh".to_owned(),
                expires_at_ms: Some(10),
            }],
        );
        assert_eq!(index.live_ids("orders", 0), vec!["sub_fresh"]);
        index.replace_type("orders", Vec::new());
        assert!(!index.has_live("orders", 0));
    }

    #[test]
    fn a_lease_is_demand_but_not_a_subscription() {
        let mut index = SubscriptionIndex::default();
        index.apply(&hint(HintOp::Lease, "", "orders", Some(100)));
        index.apply(&hint(HintOp::Lease, "", "orders", Some(50)));
        assert!(index.has_demand("orders", 99));
        assert!(!index.has_demand("orders", 100));
        assert!(!index.has_live("orders", 0));
        assert!(index.live_ids("orders", 0).is_empty());
        assert_eq!(index.total_live(0), 0);
        index.replace_type("orders", Vec::new());
        assert!(
            index.has_demand("orders", 99),
            "a listing keeps lease demand"
        );
        index.retain_types(&[]);
        assert!(!index.has_demand("orders", 0));
    }

    #[test]
    fn expired_lists_only_grants_past_the_grace() {
        let mut index = SubscriptionIndex::default();
        index.apply(&hint(HintOp::Upsert, "sub_old", "a", Some(100)));
        index.apply(&hint(HintOp::Upsert, "sub_recent", "a", Some(900)));
        index.apply(&hint(HintOp::Upsert, "sub_forever", "b", None));
        assert_eq!(
            index.expired(1_000, 500),
            vec![("a".to_owned(), "sub_old".to_owned())]
        );
        index.retain_types(&["b"]);
        assert!(index.expired(10_000, 0).is_empty());
        assert_eq!(index.total_live(10_000), 1);
    }
}
