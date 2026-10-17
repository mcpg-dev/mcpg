use super::*;
use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv};
use crate::runtime::events::test_support::keys;
use serde_json::json;

const WHSEC: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const HOUR_MS: u64 = 3_600_000;

fn store_over(kv: &Arc<MemoryKv>) -> SubscriptionStore {
    SubscriptionStore::new(Arc::clone(kv) as Arc<dyn KeyValueStore>, None, keys())
}

fn identity(subject: &str) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: subject.to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: "test".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: Default::default(),
    }
}

fn record(
    store: &SubscriptionStore,
    principal: &str,
    url: &str,
    host: &str,
    name: &str,
    expires_at_ms: Option<u64>,
) -> SubscriptionRecord {
    let principal_key = format!("verified::oidc::https://idp.example::{principal}");
    let id = store.id_for(&principal_key, url, name, &Map::new());
    let secret = WebhookSecret::parse(WHSEC).unwrap();
    SubscriptionRecord {
        v: FORMAT_VERSION,
        secret: store.seal_secret(&id, &secret),
        id,
        principal_key,
        identity: identity(principal),
        credential: CredentialSnapshot::default(),
        url: url.to_owned(),
        host: host.to_owned(),
        name: name.to_owned(),
        arguments: Map::new(),
        previous_secret: None,
        previous_secret_until_ms: None,
        created_at_ms: now_ms(),
        refreshed_at_ms: now_ms(),
        expires_at_ms,
        verified_at_ms: Some(now_ms()),
        start: StartPosition::default(),
        schema_epoch: 0,
        reactivated_at_ms: None,
        operator_suspended_at_ms: None,
        revoked: None,
    }
}

fn hour_from_now() -> Option<u64> {
    Some(now_ms() + HOUR_MS)
}

#[tokio::test]
async fn a_created_record_reads_back_with_its_secret_sealed() {
    let kv = Arc::new(MemoryKv::new());
    let store = store_over(&kv);
    let rec = record(
        &store,
        "alice",
        "https://h.example/a",
        "h.example",
        "orders",
        hour_from_now(),
    );
    assert_eq!(
        store.create(&rec).await.unwrap(),
        CreateOutcome::Created {
            replaced_lapsed: false
        }
    );
    let back = store.get(&rec.id).await.unwrap().unwrap();
    assert_eq!(back, rec);
    assert_eq!(
        store.open_secret(&back.id, &back.secret),
        Some(WebhookSecret::parse(WHSEC).unwrap())
    );
    // Nothing stored holds the secret in the clear.
    for (key, entry) in kv.list_prefix("ev:", 100).await.unwrap() {
        let text = String::from_utf8_lossy(&entry.bytes);
        assert!(!text.contains("whsec_"), "{key}");
        assert!(!text.contains("MfKQ9r8"), "{key}");
        assert!(!key.contains("alice") && !key.contains("orders"), "{key}");
    }
}

#[tokio::test]
async fn a_second_create_finds_the_live_record() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    let rec = record(
        &store,
        "alice",
        "https://h.example/a",
        "h.example",
        "orders",
        hour_from_now(),
    );
    store.create(&rec).await.unwrap();
    let mut again = rec.clone();
    again.refreshed_at_ms += 1;
    match store.create(&again).await.unwrap() {
        CreateOutcome::Exists(existing) => assert_eq!(*existing, rec),
        other => panic!("expected the live record, got {other:?}"),
    }
}

#[tokio::test]
async fn a_lapsed_record_is_replaced_by_a_create() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    let lapsed = record(
        &store,
        "alice",
        "https://h.example/a",
        "h.example",
        "orders",
        Some(now_ms().saturating_sub(1)),
    );
    store.create(&lapsed).await.unwrap();
    store
        .put_delivery(
            &DeliveryState {
                v: FORMAT_VERSION,
                id: lapsed.id.clone(),
                ack_seq: 7,
                ..DeliveryState::default()
            },
            lapsed.expires_at_ms,
        )
        .await
        .unwrap();
    let fresh = SubscriptionRecord {
        expires_at_ms: hour_from_now(),
        ..lapsed.clone()
    };
    assert_eq!(
        store.create(&fresh).await.unwrap(),
        CreateOutcome::Created {
            replaced_lapsed: true
        }
    );
    assert_eq!(store.get(&fresh.id).await.unwrap().unwrap(), fresh);
    assert!(
        store.delivery(&fresh.id).await.unwrap().is_none(),
        "a new grant starts from its own position"
    );
}

#[tokio::test]
async fn replace_updates_the_record_and_its_indexes() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    let rec = record(
        &store,
        "alice",
        "https://h.example/a",
        "h.example",
        "orders",
        hour_from_now(),
    );
    store.create(&rec).await.unwrap();
    let later = Some(now_ms() + 2 * HOUR_MS);
    let refreshed = SubscriptionRecord {
        expires_at_ms: later,
        revoked: Some(Revocation {
            at_ms: now_ms(),
            reason: TerminationReason::Forbidden(ForbiddenReason::Revoked),
        }),
        ..rec.clone()
    };
    store.replace(&refreshed).await.unwrap();
    assert_eq!(store.get(&rec.id).await.unwrap().unwrap(), refreshed);
    let listed = store.list_type("orders").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].expires_at_ms, later);
    assert!(!refreshed.is_live_at(now_ms()));
}

#[tokio::test]
async fn delete_removes_the_record_its_state_and_index_rows() {
    let kv = Arc::new(MemoryKv::new());
    let store = store_over(&kv);
    let rec = record(
        &store,
        "alice",
        "https://h.example/a",
        "h.example",
        "orders",
        hour_from_now(),
    );
    store.create(&rec).await.unwrap();
    store
        .put_delivery(
            &DeliveryState {
                v: FORMAT_VERSION,
                id: rec.id.clone(),
                ..DeliveryState::default()
            },
            rec.expires_at_ms,
        )
        .await
        .unwrap();
    assert_eq!(store.delete(&rec.id).await.unwrap(), Some(rec.clone()));
    assert!(store.get(&rec.id).await.unwrap().is_none());
    assert!(store.delivery(&rec.id).await.unwrap().is_none());
    let left: Vec<String> = kv
        .list_prefix("ev:sub", 100)
        .await
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    assert!(
        left.iter().all(|key| key.starts_with(NAME_PREFIX)),
        "only the type's name stays: {left:?}"
    );
    assert_eq!(store.delete(&rec.id).await.unwrap(), None, "idempotent");
}

#[tokio::test]
async fn the_names_of_subscribed_types_stay_until_forgotten() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    assert!(store.type_names().await.unwrap().is_empty());
    for (who, name) in [
        ("alice", "orders"),
        ("bob", "orders"),
        ("alice", "invoices"),
    ] {
        let rec = record(
            &store,
            who,
            "https://h.example/a",
            "h.example",
            name,
            hour_from_now(),
        );
        store.create(&rec).await.unwrap();
    }
    let mut names = store.type_names().await.unwrap();
    names.sort();
    assert_eq!(names, ["invoices", "orders"]);
    store.forget_type_name("orders").await.unwrap();
    assert_eq!(store.type_names().await.unwrap(), ["invoices"]);
}

#[tokio::test]
async fn principal_usage_counts_live_subscriptions_and_distinct_hosts() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    for (url, host, name) in [
        ("https://a.example/1", "a.example", "orders"),
        ("https://a.example/2", "a.example", "orders"),
        ("https://b.example/1", "b.example", "orders"),
        ("https://b.example/1", "b.example", "refunds"),
    ] {
        store
            .create(&record(&store, "alice", url, host, name, hour_from_now()))
            .await
            .unwrap();
    }
    store
        .create(&record(
            &store,
            "bob",
            "https://c.example/",
            "c.example",
            "orders",
            hour_from_now(),
        ))
        .await
        .unwrap();
    store
        .create(&record(
            &store,
            "alice",
            "https://d.example/",
            "d.example",
            "orders",
            Some(now_ms().saturating_sub(1)),
        ))
        .await
        .unwrap();
    let alice = store
        .principal_usage("verified::oidc::https://idp.example::alice")
        .await
        .unwrap();
    assert_eq!(alice.subscriptions, 4, "the lapsed one does not count");
    assert_eq!(alice.hosts.len(), 2);
    let nobody = store.principal_usage("verified::x::y::z").await.unwrap();
    assert_eq!(nobody, PrincipalUsage::default());
}

#[tokio::test]
async fn list_type_reads_every_shard() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    let mut ids = Vec::new();
    for i in 0..40 {
        let rec = record(
            &store,
            &format!("p{i}"),
            "https://h.example/",
            "h.example",
            "orders",
            hour_from_now(),
        );
        ids.push(rec.id.clone());
        store.create(&rec).await.unwrap();
    }
    store
        .create(&record(
            &store,
            "p0",
            "https://h.example/",
            "h.example",
            "other",
            None,
        ))
        .await
        .unwrap();
    let mut listed: Vec<String> = store
        .list_type("orders")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect();
    listed.sort();
    ids.sort();
    assert_eq!(listed, ids);
    let shards: std::collections::BTreeSet<String> = ids.iter().map(|id| shard_of(id)).collect();
    assert!(shards.len() > 10, "ids spread over shards: {shards:?}");
    assert_eq!(
        store.list_type("other").await.unwrap()[0].expires_at_ms,
        None
    );
    assert!(store.list_type("unknown").await.unwrap().is_empty());
}

#[tokio::test]
async fn delivery_state_round_trips() {
    let store = store_over(&Arc::new(MemoryKv::new()));
    let state = DeliveryState {
        v: FORMAT_VERSION,
        id: "sub_x".to_owned(),
        epoch: 42,
        ack_seq: 9,
        fence: 3,
        in_flight: vec![InFlight {
            seq: 10,
            attempts: 2,
            first_attempt_at_ms: 1,
            next_attempt_at_ms: 2,
        }],
        counters: DeliveryCounters {
            last_error: Some(DeliveryErrorCategory::Http5xx),
            window_attempts: 3,
            window_failures: 2,
            ..DeliveryCounters::default()
        },
        updated_at_ms: 5,
    };
    store.put_delivery(&state, hour_from_now()).await.unwrap();
    assert_eq!(store.delivery("sub_x").await.unwrap(), Some(state));
}

#[tokio::test]
async fn a_record_of_a_newer_format_is_refused_not_misread() {
    let kv = Arc::new(MemoryKv::new());
    let store = store_over(&kv);
    kv.put(
        "ev:sub:sub_new",
        Bytes::from(r#"{"v":2,"id":"sub_new"}"#),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        store.get("sub_new").await,
        Err(StoreError::Unreadable)
    ));
}

#[tokio::test]
async fn writes_broadcast_hints_to_every_replica() {
    let bus: Arc<dyn PubSub> = Arc::new(MemoryBus::new());
    let kv: Arc<dyn KeyValueStore> = Arc::new(MemoryKv::new());
    let writer = SubscriptionStore::new(Arc::clone(&kv), Some(Arc::clone(&bus)), keys());
    let reader = SubscriptionStore::new(kv, Some(bus), keys());
    let mut hints = reader.hints().await.unwrap();
    let rec = record(
        &writer,
        "alice",
        "https://h.example/",
        "h.example",
        "orders",
        hour_from_now(),
    );
    writer.create(&rec).await.unwrap();
    writer.delete(&rec.id).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), hints.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first,
        SubscriptionHint {
            op: HintOp::Upsert,
            id: rec.id.clone(),
            name: "orders".to_owned(),
            expires_at_ms: rec.expires_at_ms,
        }
    );
    let second = tokio::time::timeout(Duration::from_secs(2), hints.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.op, HintOp::Delete);
    assert!(
        store_over(&Arc::new(MemoryKv::new()))
            .hints()
            .await
            .is_none()
    );
}

#[test]
fn hints_carry_no_principal_url_or_secret() {
    let hint = SubscriptionHint {
        op: HintOp::Upsert,
        id: "sub_x".to_owned(),
        name: "orders".to_owned(),
        expires_at_ms: None,
    };
    assert_eq!(
        serde_json::to_value(&hint).unwrap(),
        json!({"op": "upsert", "id": "sub_x", "name": "orders", "expires_at_ms": null})
    );
}

fn policy() -> TtlPolicy {
    TtlPolicy::from_config(&EventsConfig::default(), true)
}

const NOW: u64 = 1_000_000_000_000;

#[test]
fn a_grant_follows_the_request_within_the_bounds() {
    let p = policy();
    let grant = |r| p.grant(r, None, NOW);
    assert_eq!(grant(TtlRequest::ServerDefault).ttl_ms, Some(HOUR_MS));
    assert_eq!(grant(TtlRequest::Millis(600_000)).ttl_ms, Some(600_000));
    assert_eq!(
        grant(TtlRequest::Millis(1)).ttl_ms,
        Some(300_000),
        "raised to min"
    );
    assert_eq!(
        grant(TtlRequest::Millis(10 * 86_400_000)).ttl_ms,
        Some(86_400_000),
        "lowered to max"
    );
    let no_expiry = grant(TtlRequest::NoExpiry);
    assert_eq!(
        no_expiry.ttl_ms,
        Some(86_400_000),
        "no expiry needs opting in"
    );
    assert_eq!(no_expiry.expires_at_ms, Some(NOW + 86_400_000));
    assert!(no_expiry.refresh_before().is_some());
}

#[test]
fn no_expiry_is_granted_only_when_allowed() {
    let mut config = EventsConfig::default();
    config.webhook.ttl.allow_no_expiry = true;
    let p = TtlPolicy::from_config(&config, true);
    let grant = p.grant(TtlRequest::NoExpiry, None, NOW);
    assert_eq!(
        grant,
        Grant {
            ttl_ms: None,
            expires_at_ms: None
        }
    );
    assert_eq!(grant.refresh_before(), None);
    // A known token expiry still bounds it.
    let bounded = p.grant(TtlRequest::NoExpiry, Some(NOW + 600_000), NOW);
    assert_eq!(bounded.ttl_ms, Some(600_000));
}

#[test]
fn a_grant_never_outlives_the_token_but_never_drops_below_min() {
    let p = policy();
    assert_eq!(
        p.grant(TtlRequest::ServerDefault, Some(NOW + 600_000), NOW)
            .ttl_ms,
        Some(600_000)
    );
    assert_eq!(
        p.grant(TtlRequest::ServerDefault, Some(NOW + 1_000), NOW)
            .ttl_ms,
        Some(300_000)
    );
    assert_eq!(
        p.grant(TtlRequest::ServerDefault, Some(NOW - 1_000), NOW)
            .ttl_ms,
        Some(300_000)
    );
    let mut config = EventsConfig::default();
    config.webhook.ttl.clamp_to_token_expiry = false;
    let unclamped = TtlPolicy::from_config(&config, true);
    assert_eq!(
        unclamped
            .grant(TtlRequest::ServerDefault, Some(NOW + 600_000), NOW)
            .ttl_ms,
        Some(HOUR_MS)
    );
}

#[test]
fn an_ephemeral_store_caps_every_grant_at_min() {
    let mut config = EventsConfig::default();
    config.webhook.ttl.allow_no_expiry = true;
    let p = TtlPolicy::from_config(&config, false);
    for request in [
        TtlRequest::ServerDefault,
        TtlRequest::Millis(86_400_000),
        TtlRequest::NoExpiry,
    ] {
        assert_eq!(
            p.grant(request, None, NOW).ttl_ms,
            Some(300_000),
            "{request:?}"
        );
    }
}

#[test]
fn termination_reasons_are_stored_by_their_labels() {
    for reason in [
        TerminationReason::Forbidden(ForbiddenReason::Revoked),
        TerminationReason::Forbidden(ForbiddenReason::Admin),
        TerminationReason::Forbidden(ForbiddenReason::PolicyEngine),
        TerminationReason::SchemaChanged,
        TerminationReason::TypeRemoved,
        TerminationReason::PushWithdrawn,
        TerminationReason::Suspended,
        TerminationReason::Upstream(EndReason::Forbidden),
        TerminationReason::Upstream(EndReason::NotFound),
        TerminationReason::Upstream(EndReason::ArgumentsRefused),
    ] {
        let stored = serde_json::to_value(reason).unwrap();
        assert_eq!(stored, json!(reason.label()));
        assert_eq!(
            serde_json::from_value::<TerminationReason>(stored).unwrap(),
            reason
        );
    }
    assert_eq!(
        TerminationReason::from_label("quarantined"),
        TerminationReason::Forbidden(ForbiddenReason::Unknown)
    );
    assert!(TerminationReason::SchemaChanged.ended_by_config());
    assert!(!TerminationReason::Forbidden(ForbiddenReason::Revoked).ended_by_config());
}

#[test]
fn a_suspension_ends_with_the_last_endpoint_failure() {
    let error = TerminationReason::Suspended.error(Some(DeliveryErrorCategory::Timeout));
    assert_eq!(error.data(), Some(&json!({ "reason": "timeout" })));
    let error = TerminationReason::Suspended.error(Some(DeliveryErrorCategory::Paused));
    assert_eq!(
        error.data(),
        Some(&json!({ "reason": "connection_refused" }))
    );
}

#[test]
fn refresh_before_is_rfc3339_utc() {
    assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(rfc3339_ms(1_790_000_000_123), "2026-09-21T14:13:20.123Z");
}
