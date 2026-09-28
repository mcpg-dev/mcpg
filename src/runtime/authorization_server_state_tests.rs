use super::*;
use crate::builtins::cluster_primitives::MemoryKv;

const ISSUER: &str = "https://mcp.example.com";

fn key_bytes(fill: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([fill; 32])
}

fn keyring(keys: &[(&str, u8)]) -> Arc<StateKeyring> {
    Arc::new(
        StateKeyring::new(
            keys.iter()
                .map(|(kid, fill)| ((*kid).to_owned(), key_bytes(*fill)))
                .collect(),
            KeyringSource::Configured,
        )
        .expect("keyring"),
    )
}

fn state_over(
    kv: &Arc<dyn KeyValueStore>,
    keyring: &Arc<StateKeyring>,
    issuer: &str,
) -> InteractiveState {
    InteractiveState::new(StateParts {
        kv: Arc::clone(kv),
        backend: StateBackend::InProcess,
        keyring: Arc::clone(keyring),
        issuer: issuer.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(60),
    })
    .expect("state")
}

fn memory() -> Arc<dyn KeyValueStore> {
    Arc::new(MemoryKv::new())
}

/// A grant of `principal`, the same for every call: the times are read
/// once, so two calls a second tick apart compare equal.
fn grant(principal: &str) -> GrantRecord {
    static NOW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let now = *NOW.get_or_init(now_unix);
    GrantRecord {
        status: GrantStatus::Active,
        principal: principal.to_owned(),
        identity: IdentitySnapshot {
            subject: "00u1".to_owned(),
            idp: "https://acme.okta.com".to_owned(),
            groups: vec!["eng".to_owned()],
            ..IdentitySnapshot::default()
        },
        client_id: "mcp-client".to_owned(),
        client_kind: ClientKind::Static,
        scope: vec!["mcp:tools".to_owned()],
        resource: "https://mcp.example.com/mcp".to_owned(),
        redirect_uri: "https://app.example.com/cb".to_owned(),
        issuer: ISSUER.to_owned(),
        abs_exp: now + 3_600,
        last_used: now,
        generation: 1,
        created: now,
        dpop_jkt: None,
        dpop_bound_generation: 0,
        authorization_details: Default::default(),
    }
}

/// Authorization details of one `mcp_tool` object.
fn details() -> crate::runtime::authorization_server::rar::AuthorizationDetails {
    serde_json::from_value(serde_json::json!([
        { "type": "mcp_tool", "actions": ["tools/call"], "identifier": "search" }
    ]))
    .expect("details parse")
}

const TTL: Duration = Duration::from_secs(600);

/// Open the file store in `dir` once the tasks of the state that last
/// held it, a revocation poll in flight included, have let it go.
async fn reopen(dir: &std::path::Path) -> FileStore {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match FileStore::open(dir, FileStoreLimits::default()) {
            Ok(store) => return store,
            Err(error) if Instant::now() < deadline => {
                assert!(
                    error.to_string().contains("another gateway process"),
                    "{error}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("the store stays locked: {error}"),
        }
    }
}

#[tokio::test]
async fn a_record_round_trips_sealed() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let gid = GrantId::generate().expect("gid");
    let key = keys::grant(&gid);
    state.put(&key, &grant("p"), TTL).await.expect("put");
    assert_eq!(state.get(&key).await.expect("get"), Some(grant("p")));

    let stored = kv.get(key.as_str()).await.expect("get").expect("stored");
    let raw = String::from_utf8_lossy(&stored.bytes);
    assert!(raw.contains("\"kid\":\"k1\""), "{raw}");
    for clear in ["00u1", "mcp-client", "eng", "app.example.com"] {
        assert!(
            !raw.contains(clear),
            "`{clear}` is stored in the clear: {raw}"
        );
    }
}

#[tokio::test]
async fn a_record_moved_to_another_key_does_not_open() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let a = keys::grant(&GrantId::generate().expect("gid"));
    let b = keys::grant(&GrantId::generate().expect("gid"));
    state.put(&a, &grant("p"), TTL).await.expect("put");
    let sealed = kv.get(a.as_str()).await.expect("get").expect("stored");
    kv.put(b.as_str(), sealed.bytes, None).await.expect("copy");
    assert_eq!(state.get(&b).await.expect("get"), None);
    assert!(state.exists(&b).await.expect("exists"), "yet it is present");
}

#[tokio::test]
async fn a_record_of_another_issuer_does_not_open() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let key = keys::grant(&GrantId::generate().expect("gid"));
    state_over(&kv, &ring, ISSUER)
        .put(&key, &grant("p"), TTL)
        .await
        .expect("put");
    let other = state_over(&kv, &ring, "https://other.example.com");
    assert_eq!(other.get(&key).await.expect("get"), None);
}

#[tokio::test]
async fn a_tampered_record_does_not_open() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let key = keys::grant(&GrantId::generate().expect("gid"));
    state.put(&key, &grant("p"), TTL).await.expect("put");
    let sealed = kv.get(key.as_str()).await.expect("get").expect("stored");
    let mut envelope: serde_json::Value = serde_json::from_slice(&sealed.bytes).expect("json");
    let ciphertext = envelope["c"].as_str().expect("c").to_owned();
    let flipped = if ciphertext.starts_with('A') {
        "B"
    } else {
        "A"
    };
    envelope["c"] = serde_json::Value::String(format!("{flipped}{}", &ciphertext[1..]));
    kv.put(
        key.as_str(),
        Bytes::from(serde_json::to_vec(&envelope).expect("json")),
        None,
    )
    .await
    .expect("tamper");
    assert_eq!(state.get(&key).await.expect("get"), None);
}

#[tokio::test]
async fn a_rotated_keyring_still_opens_what_the_old_key_sealed() {
    let kv = memory();
    let key_old = keys::grant(&GrantId::generate().expect("gid"));
    let key_new = keys::grant(&GrantId::generate().expect("gid"));
    state_over(&kv, &keyring(&[("old", 1)]), ISSUER)
        .put(&key_old, &grant("before"), TTL)
        .await
        .expect("put");

    let rotated = state_over(&kv, &keyring(&[("new", 2), ("old", 1)]), ISSUER);
    assert_eq!(rotated.keyring().sealing_kid(), "new");
    assert_eq!(
        rotated.get(&key_old).await.expect("get"),
        Some(grant("before"))
    );
    rotated
        .put(&key_new, &grant("after"), TTL)
        .await
        .expect("put");
    let sealed = kv
        .get(key_new.as_str())
        .await
        .expect("get")
        .expect("stored");
    assert!(String::from_utf8_lossy(&sealed.bytes).contains("\"kid\":\"new\""));

    let retired = state_over(&kv, &keyring(&[("new", 2)]), ISSUER);
    assert_eq!(retired.get(&key_old).await.expect("get"), None);
    assert_eq!(
        retired.get(&key_new).await.expect("get"),
        Some(grant("after"))
    );
}

#[tokio::test]
async fn replicas_holding_one_cluster_key_derive_one_state_key() {
    let kv = memory();
    let base = [9u8; 32];
    let a = Arc::new(StateKeyring::from_cluster_key(&base, None).expect("a"));
    let b = Arc::new(StateKeyring::from_cluster_key(&base, None).expect("b"));
    assert!(a.same_keys(&b));
    assert_eq!(a.sealing_kid(), CLUSTER_KEY_ID);
    assert_eq!(*a.derive(CSRF_KEY_DOMAIN)[0], *b.derive(CSRF_KEY_DOMAIN)[0]);
    assert_ne!(
        *a.derive(CSRF_KEY_DOMAIN)[0],
        crate::app::derive_cluster_subkey(&base, STATE_KEY_DOMAIN),
        "each domain has its own key"
    );

    let key = keys::grant(&GrantId::generate().expect("gid"));
    state_over(&kv, &a, ISSUER)
        .put(&key, &grant("p"), TTL)
        .await
        .expect("put");
    assert_eq!(
        state_over(&kv, &b, ISSUER).get(&key).await.expect("get"),
        Some(grant("p"))
    );

    let other = Arc::new(StateKeyring::from_cluster_key(&[8u8; 32], None).expect("other"));
    assert!(!a.same_keys(&other));
    assert_eq!(
        state_over(&kv, &other, ISSUER)
            .get(&key)
            .await
            .expect("get"),
        None
    );
    let labelled = StateKeyring::from_cluster_key(&base, Some("2026-09")).expect("labelled");
    assert_eq!(labelled.sealing_kid(), "2026-09");
}

#[test]
fn every_process_key_is_its_own() {
    let a = StateKeyring::process().expect("a");
    let b = StateKeyring::process().expect("b");
    assert!(!a.same_keys(&b));
    let sealed = a.seal(b"x", b"aad").expect("seal");
    assert!(b.open(&sealed, b"aad").is_none());
    assert_eq!(a.open(&sealed, b"aad").as_deref(), Some(b"x".as_slice()));
    assert!(a.open(&sealed, b"other").is_none());
}

#[test]
fn a_configured_keyring_names_the_bad_entry_but_never_its_secret() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let full = engine.encode((0u8..32).collect::<Vec<_>>());
    let short = engine.encode(b"not-32-bytes");
    let keys: Vec<crate::config::StateKeyConfig> = serde_yaml::from_str(&format!(
        "- kid: new\n  secret: {full}\n- kid: old\n  secret: {short}\n"
    ))
    .expect("keys parse");
    let refused = StateKeyring::from_config(&keys).expect_err("the second is short");
    let message = refused.to_string();
    assert!(message.contains("state_keys[1].secret"), "{message}");
    assert!(!message.contains(&short), "{message}");

    let ring = StateKeyring::from_config(&keys[..1]).expect("the first is valid");
    assert_eq!(ring.kids().collect::<Vec<_>>(), ["new"]);
    assert_eq!(*ring.source(), KeyringSource::Configured);
    let padded: Vec<crate::config::StateKeyConfig> =
        serde_yaml::from_str(&format!("- kid: new\n  secret: {full}=\n")).expect("keys parse");
    assert!(
        StateKeyring::from_config(&padded)
            .expect("padded")
            .same_keys(&ring)
    );
    StateKeyring::new(
        vec![
            ("a".to_owned(), key_bytes(1)),
            ("a".to_owned(), key_bytes(2)),
        ],
        KeyringSource::Configured,
    )
    .expect_err("a kid appears once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_claim_wins_across_handles_over_one_store() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let a = state_over(&kv, &ring, ISSUER);
    let b = state_over(&kv, &ring, ISSUER);
    let key = keys::code_used("mcpg_ac_code");
    let mut claims = Vec::new();
    for n in 0..16 {
        let state = if n % 2 == 0 { a.clone() } else { b.clone() };
        let key = keys::transaction_used("state-up");
        claims.push(tokio::spawn(async move {
            state.claim_once(&key, TTL).await.expect("claim")
        }));
    }
    let mut winners = 0;
    for claim in claims {
        winners += usize::from(claim.await.expect("task"));
    }
    assert_eq!(winners, 1);

    let gid = GrantId::generate().expect("gid");
    assert!(
        a.put_if_absent(&key, &CodeUsedRecord { gid: gid.clone() }, TTL)
            .await
            .expect("claim")
    );
    assert!(
        !b.put_if_absent(&key, &CodeUsedRecord { gid: gid.clone() }, TTL)
            .await
            .expect("claim")
    );
    assert_eq!(
        b.get(&key).await.expect("get"),
        Some(CodeUsedRecord { gid })
    );
}

#[tokio::test]
async fn an_unclaimed_key_can_be_claimed_again() {
    let state = state_over(&memory(), &keyring(&[("k1", 1)]), ISSUER);
    let key = keys::consent_used("sealed-req");
    assert!(state.claim_once(&key, TTL).await.expect("claim"));
    assert!(!state.claim_once(&key, TTL).await.expect("claim"));
    assert!(state.unclaim(&key).await.expect("unclaim"));
    assert!(!state.unclaim(&key).await.expect("unclaim"), "nothing held");
    assert!(state.claim_once(&key, TTL).await.expect("claim"));
}

#[tokio::test]
async fn a_lease_has_one_holder_until_released() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let a = state_over(&kv, &ring, ISSUER);
    let b = state_over(&kv, &ring, ISSUER);
    let key = keys::idp_lease("principal");
    let lease = a.try_lease(&key, TTL).await.expect("lease").expect("free");
    assert!(b.try_lease(&key, TTL).await.expect("lease").is_none());
    let waited = b
        .acquire_lease(&key, TTL, Duration::from_millis(250))
        .await
        .expect("lease");
    assert!(waited.is_none(), "still held after the wait");

    let foreign = Lease {
        key: key.clone(),
        token: "not-the-holders".to_owned(),
    };
    b.release_lease(&foreign).await.expect("release");
    assert!(
        b.try_lease(&key, TTL).await.expect("lease").is_none(),
        "only the holder's token releases it"
    );
    a.release_lease(&lease).await.expect("release");
    assert!(b.try_lease(&key, TTL).await.expect("lease").is_some());
}

#[tokio::test]
async fn a_waiting_lease_is_taken_once_released() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let a = state_over(&kv, &ring, ISSUER);
    let b = state_over(&kv, &ring, ISSUER);
    let key = keys::idp_lease("principal");
    let lease = a.try_lease(&key, TTL).await.expect("lease").expect("free");
    let releaser = {
        let a = a.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            a.release_lease(&lease).await.expect("release");
        })
    };
    let waited = b
        .acquire_lease(&key, TTL, Duration::from_secs(2))
        .await
        .expect("lease");
    assert!(waited.is_some());
    releaser.await.expect("task");
}

#[tokio::test]
async fn another_replicas_revocation_arrives_with_the_poll_and_leaves_at_expiry() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let a = state_over(&kv, &ring, ISSUER);
    let b = state_over(&kv, &ring, ISSUER);
    a.poll_revocations().await.expect("poll");
    let gid = GrantId::generate().expect("gid");
    let revoked = RevokedId::Grant(gid.clone());
    let until = now_unix() + 900;
    b.record_revocation(&revoked, RevocationReason::RefreshReuse, until)
        .await
        .expect("revoke");
    assert!(b.is_revoked(&revoked), "at once where it was revoked");
    assert!(!a.is_revoked(&revoked), "elsewhere from the next poll");
    assert_eq!(a.poll_revocations().await.expect("poll"), 1);
    assert!(a.is_revoked(&revoked));
    assert!(!a.is_revoked(&RevokedId::Grant(GrantId::generate().expect("gid"))));

    let suffix = revoked.suffix();
    assert!(a.revoked().contains_at(&suffix, until - 1));
    assert!(!a.revoked().contains_at(&suffix, until));
    a.revoked().prune(until);
    assert!(a.revoked().is_empty(), "an expired revocation is dropped");
    assert_eq!(
        b.get(&keys::revoked(&revoked)).await.expect("get"),
        Some(TombstoneRecord {
            reason: RevocationReason::RefreshReuse,
            exp: until,
        })
    );
}

/// A listing the store cuts at its limit is read again by longer prefixes,
/// so a poll honours every revocation however many there are.
#[tokio::test]
async fn a_poll_reads_every_revocation_past_its_listing_limit() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let writer = state_over(&kv, &ring, ISSUER);
    let reader = state_over(&kv, &ring, ISSUER);
    let until = now_unix() + 900;
    let mut revoked = Vec::new();
    for n in 0..48 {
        let id = if n % 2 == 0 {
            RevokedId::Grant(GrantId::generate().expect("gid"))
        } else {
            RevokedId::access_token(&format!("jti-{n}"))
        };
        writer
            .record_revocation(&id, RevocationReason::Client, until)
            .await
            .expect("revoke");
        revoked.push(id);
    }
    assert_eq!(
        reader.poll_revocations_by(3).await.expect("poll"),
        revoked.len(),
        "every tombstone is read, not the first listing's"
    );
    for id in &revoked {
        assert!(reader.is_revoked(id), "{id:?}");
    }
}

#[test]
fn a_revocation_listing_splits_by_hex_digit_down_to_a_whole_key() {
    let top = keys::revocations();
    let top = top.as_str();
    let first = revocation_sub_prefixes(top, top).expect("the top splits");
    assert_eq!(first.len(), 17);
    assert!(first.contains(&format!("{top}jti.")));
    assert!(first.contains(&format!("{top}0")) && first.contains(&format!("{top}f")));
    assert_eq!(
        revocation_sub_prefixes(top, &format!("{top}jti."))
            .expect("splits")
            .len(),
        16
    );
    let whole_jti = format!("{top}jti.{}", "0".repeat(64));
    assert!(revocation_sub_prefixes(top, &whole_jti).is_none());
}

#[tokio::test(start_paused = true)]
async fn the_poll_task_picks_up_revocations_on_its_own() {
    let kv = memory();
    let ring = keyring(&[("k1", 1)]);
    let a = InteractiveState::new(StateParts {
        kv: Arc::clone(&kv),
        backend: StateBackend::InProcess,
        keyring: Arc::clone(&ring),
        issuer: ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(2),
    })
    .expect("state");
    let b = state_over(&kv, &ring, ISSUER);
    let revoked = RevokedId::access_token("jti-1");
    b.record_revocation(&revoked, RevocationReason::Client, now_unix() + 60)
        .await
        .expect("revoke");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(a.is_revoked(&revoked));
}

#[tokio::test]
async fn a_failed_poll_keeps_the_known_revocations() {
    let state = InteractiveState::new(StateParts {
        kv: Arc::new(UnavailableStore::new("down")),
        backend: StateBackend::Unavailable,
        keyring: keyring(&[("k1", 1)]),
        issuer: ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(60),
    })
    .expect("state");
    let revoked = RevokedId::Grant(GrantId::generate().expect("gid"));
    let failed = state
        .record_revocation(&revoked, RevocationReason::Client, now_unix() + 60)
        .await;
    assert!(matches!(failed, Err(StateError::Store(_))));
    assert!(
        state.is_revoked(&revoked),
        "honoured here though the store write failed"
    );
    assert!(state.poll_revocations().await.is_err());
    assert!(state.is_revoked(&revoked));
}

#[tokio::test]
async fn an_unavailable_state_fails_every_operation() {
    let state = InteractiveState::new(StateParts {
        kv: Arc::new(UnavailableStore::new("no coordinator store")),
        backend: StateBackend::Unavailable,
        keyring: keyring(&[("k1", 1)]),
        issuer: ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(60),
    })
    .expect("state");
    assert!(!state.is_available());
    let key = keys::transaction("s");
    assert!(state.get(&key).await.is_err());
    assert!(
        state
            .claim_once(&keys::transaction_used("s"), TTL)
            .await
            .is_err()
    );
    assert!(state.incr(&keys::dcr_count(), 1, None).await.is_err());
    assert!(state.try_lease(&keys::idp_lease("p"), TTL).await.is_err());
}

#[tokio::test]
async fn a_listing_returns_what_opens_under_the_prefix() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let gids: Vec<GrantId> = (0..3).map(|_| GrantId::generate().expect("gid")).collect();
    for (n, gid) in gids.iter().enumerate() {
        state
            .put(
                &keys::principal_grant("alice", gid),
                &PrincipalGrantRecord { created: n as u64 },
                TTL,
            )
            .await
            .expect("put");
    }
    state
        .put(
            &keys::principal_grant("bob", &GrantId::generate().expect("gid")),
            &PrincipalGrantRecord { created: 9 },
            TTL,
        )
        .await
        .expect("put");
    let planted = keys::principal_grant("alice", &GrantId::generate().expect("gid"));
    kv.put(planted.as_str(), Bytes::from_static(b"{}"), None)
        .await
        .expect("plant");

    let mut listed = state
        .list(&keys::principal_grants("alice"), 100)
        .await
        .expect("list");
    listed.sort_by_key(|(_, record)| record.created);
    let mut expected: Vec<(String, PrincipalGrantRecord)> = gids
        .iter()
        .enumerate()
        .map(|(n, gid)| (gid.to_string(), PrincipalGrantRecord { created: n as u64 }))
        .collect();
    expected.sort_by_key(|(_, record)| record.created);
    assert_eq!(listed, expected);
}

#[tokio::test]
async fn counters_add_up_unsealed() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let key = keys::dcr_rate("203.0.113.9", 494_000);
    assert_eq!(state.incr(&key, 1, Some(TTL)).await.expect("incr"), 1);
    assert_eq!(state.incr(&key, 1, Some(TTL)).await.expect("incr"), 2);
    assert_eq!(
        state
            .incr(&keys::dcr_rate("203.0.113.9", 494_001), 1, Some(TTL))
            .await
            .expect("incr"),
        1,
        "each clock hour counts on its own"
    );
    assert_eq!(
        &kv.get(key.as_str())
            .await
            .expect("get")
            .expect("stored")
            .bytes[..],
        b"2"
    );
    assert!(
        !key.as_str().contains("203.0.113.9"),
        "the address is hashed"
    );
}

#[tokio::test]
async fn a_record_too_large_is_refused_before_the_store() {
    let kv = memory();
    let state = state_over(&kv, &keyring(&[("k1", 1)]), ISSUER);
    let mut huge = grant("p");
    huge.identity.groups = vec!["g".repeat(MAX_RECORD_BYTES)];
    let key = keys::grant(&GrantId::generate().expect("gid"));
    let refused = state.put(&key, &huge, TTL).await;
    assert!(matches!(refused, Err(StateError::TooLarge { .. })));
    assert!(kv.get(key.as_str()).await.expect("get").is_none());
}

#[tokio::test]
async fn every_record_type_round_trips() {
    let state = state_over(&memory(), &keyring(&[("k1", 1)]), ISSUER);
    let gid = GrantId::generate().expect("gid");

    async fn round_trip<R: StateRecord + PartialEq + std::fmt::Debug>(
        state: &InteractiveState,
        key: RecordKey<R>,
        record: R,
    ) {
        state.put(&key, &record, TTL).await.expect("put");
        assert_eq!(state.get(&key).await.expect("get"), Some(record), "{key:?}");
    }

    round_trip(&state, keys::consent_used("req"), Marker::now()).await;
    round_trip(&state, keys::pkce_seen("c", "challenge"), Marker::now()).await;
    round_trip(
        &state,
        keys::transaction("state-up"),
        TransactionRecord {
            purpose: TransactionPurpose::Authorize,
            client: Some(ClientSnapshot {
                client_id: "https://app.example.com/client.json".to_owned(),
                kind: ClientKind::Cimd,
                name: Some("App".to_owned()),
            }),
            redirect_uri: Some("http://127.0.0.1/cb".to_owned()),
            redirect_trusted: true,
            consent_approved: true,
            client_state: Some("xyz".to_owned()),
            code_challenge: Some("c".repeat(43)),
            resource: Some("https://mcp.example.com/mcp".to_owned()),
            scope: vec!["mcp:tools".to_owned()],
            idp_issuer: "https://acme.okta.com".to_owned(),
            nonce: SecretString::new("nonce"),
            pkce_verifier: SecretString::new("verifier"),
            binder_hash: "ab".repeat(32),
            created: 1,
            link_id: None,
            dpop_jkt: Some("k".repeat(43)),
            authorization_details: details(),
        },
    )
    .await;
    round_trip(&state, keys::transaction_used("state-up"), Marker::now()).await;
    round_trip(
        &state,
        keys::code("mcpg_ac_x"),
        CodeRecord {
            client_id: "c".to_owned(),
            redirect_uri: "https://app.example.com/cb".to_owned(),
            code_challenge: "c".repeat(43),
            resource: "https://mcp.example.com/mcp".to_owned(),
            scope: vec![],
            gid: gid.clone(),
            exp: 2,
            dpop_jkt: Some("k".repeat(43)),
            authorization_details: details(),
        },
    )
    .await;
    round_trip(
        &state,
        keys::code_used("mcpg_ac_x"),
        CodeUsedRecord { gid: gid.clone() },
    )
    .await;
    round_trip(&state, keys::grant(&gid), grant("p")).await;
    round_trip(
        &state,
        keys::grant(&gid),
        GrantRecord {
            authorization_details: details(),
            ..grant("p")
        },
    )
    .await;
    round_trip(
        &state,
        keys::grant(&gid),
        GrantRecord {
            dpop_jkt: Some("k".repeat(43)),
            dpop_bound_generation: 3,
            ..grant("p")
        },
    )
    .await;
    round_trip(
        &state,
        keys::principal_grant("p", &gid),
        PrincipalGrantRecord { created: 3 },
    )
    .await;
    round_trip(
        &state,
        keys::refresh("mcpg_rt_x"),
        RefreshRecord {
            gid: gid.clone(),
            generation: 1,
            client_id: "c".to_owned(),
        },
    )
    .await;
    round_trip(
        &state,
        keys::refresh_used("mcpg_rt_x"),
        RefreshUsedRecord {
            gid: gid.clone(),
            spent_at: 4,
            generation: 2,
            successor_sealed: Some("sealed".to_owned()),
        },
    )
    .await;
    round_trip(
        &state,
        keys::revoked(&RevokedId::access_token("jti")),
        TombstoneRecord {
            reason: RevocationReason::Client,
            exp: 5,
        },
    )
    .await;
    round_trip(
        &state,
        keys::idp_session("p"),
        IdpSessionRecord {
            v: 1,
            issuer: "https://acme.okta.com".to_owned(),
            client_id: "0oa1agent".to_owned(),
            token_endpoint: "https://acme.okta.com/oauth2/v1/token".to_owned(),
            sub: "00u1".to_owned(),
            refresh_token: Some(SecretString::new("idp-refresh")),
            id_token: SecretString::new("idp.id.token"),
            id_token_exp: 6,
            scope: "openid offline_access".to_owned(),
            obtained_at: 7,
            last_refreshed: 7,
            origin: IdpSessionOrigin::Login,
            generation: 1,
        },
    )
    .await;
    round_trip(
        &state,
        keys::idp_lease("p"),
        LeaseRecord {
            holder: "node".to_owned(),
            token: "t".to_owned(),
        },
    )
    .await;
    round_trip(
        &state,
        keys::dcr_client("mcpgdcr_ABC").expect("valid id"),
        DcrClientRecord {
            client_id: "mcpgdcr_ABC".to_owned(),
            client_id_issued_at: 9,
            client_name: None,
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            response_types: vec!["code".to_owned()],
            application_type: Some("native".to_owned()),
            dpop_bound_access_tokens: true,
        },
    )
    .await;
    round_trip(
        &state,
        keys::link("link-id"),
        LinkRecord {
            principal: "p".to_owned(),
            client_id: Some("c".to_owned()),
            session_id: Some("s".to_owned()),
            notify: true,
            exp: 1_900_000_000,
        },
    )
    .await;
}

#[test]
fn keys_hold_hashes_under_the_prefix() {
    let code = "mcpg_ac_secret-code-value";
    let key = keys::code(code);
    assert!(key.as_str().starts_with(STATE_PREFIX));
    assert_eq!(key.logical(), &key.as_str()[STATE_PREFIX.len()..]);
    assert!(!key.as_str().contains(code));
    assert_ne!(keys::code(code).as_str(), keys::code_used(code).as_str());
    assert_eq!(
        keys::code(code).logical().rsplit('/').next(),
        keys::code_used(code).logical().rsplit('/').next(),
        "a code and its redemption share one handle"
    );
    for (value, key) in [
        ("rt", keys::refresh("rt").as_str().to_owned()),
        ("state", keys::transaction("state").as_str().to_owned()),
        ("alice", keys::idp_session("alice").as_str().to_owned()),
        ("link", keys::link("link").as_str().to_owned()),
        ("link", keys::link_done("link").as_str().to_owned()),
    ] {
        assert!(!key.ends_with(value), "{key}");
    }
    assert_ne!(
        keys::link("link").as_str(),
        keys::link_done("link").as_str()
    );
    assert!(
        keys::principal_grant("alice", &GrantId::parse(&"a".repeat(32)).expect("gid"))
            .as_str()
            .starts_with(keys::principal_grants("alice").as_str())
    );
    assert_eq!(
        keys::revoked(&RevokedId::Grant(
            GrantId::parse(&"b".repeat(32)).expect("gid")
        ))
        .logical(),
        format!("revoked/{}", "b".repeat(32))
    );
    assert!(
        keys::revoked(&RevokedId::access_token("j"))
            .logical()
            .starts_with("revoked/jti.")
    );
}

#[test]
fn handles_separate_kinds_and_parts() {
    let a = handle(HandleKind::Code, &[b"x"]);
    assert_eq!(a, handle(HandleKind::Code, &[b"x"]));
    assert_eq!(a.len(), 64);
    assert_ne!(a, handle(HandleKind::RefreshToken, &[b"x"]));
    assert_ne!(
        handle(HandleKind::PkceChallenge, &[b"ab", b"c"]),
        handle(HandleKind::PkceChallenge, &[b"a", b"bc"])
    );
}

#[test]
fn grant_ids_are_128_bit_hex() {
    let gid = GrantId::generate().expect("gid");
    assert_eq!(gid.as_str().len(), 32);
    assert_eq!(GrantId::parse(gid.as_str()), Some(gid.clone()));
    assert_ne!(gid, GrantId::generate().expect("gid"));
    for bad in [
        "".to_owned(),
        "A".repeat(32),
        "a".repeat(31),
        format!("{}/", "a".repeat(31)),
        "g".repeat(32),
    ] {
        assert_eq!(GrantId::parse(&bad), None, "{bad}");
    }
    assert!(serde_json::from_str::<GrantId>("\"../../x\"").is_err());
    assert_eq!(
        serde_json::from_str::<GrantId>(&serde_json::to_string(&gid).expect("json")).expect("json"),
        gid
    );
}

#[test]
fn a_registration_key_takes_only_a_registration_id() {
    assert!(keys::dcr_client("mcpgdcr_AbC-1").is_some());
    for bad in ["", "a/b", "../x", "a b", &"a".repeat(65)] {
        assert!(keys::dcr_client(bad).is_none(), "{bad}");
    }
}

#[test]
fn secrets_stay_out_of_debug_output() {
    let session = IdpSessionRecord {
        v: 1,
        issuer: "https://acme.okta.com".to_owned(),
        client_id: "0oa1agent".to_owned(),
        token_endpoint: "https://acme.okta.com/oauth2/v1/token".to_owned(),
        sub: "00u1".to_owned(),
        refresh_token: Some(SecretString::new("idp-refresh-token")),
        id_token: SecretString::new("idp.id.token"),
        id_token_exp: 0,
        scope: String::new(),
        obtained_at: 0,
        last_refreshed: 0,
        origin: IdpSessionOrigin::Connect,
        generation: 0,
    };
    let rendered = format!("{session:?}");
    assert!(!rendered.contains("idp-refresh-token"), "{rendered}");
    assert!(!rendered.contains("idp.id.token"), "{rendered}");
    let ring = keyring(&[("k1", 1)]);
    assert!(format!("{ring:?}").contains("k1"));
    assert!(SecretString::new("abc").ct_eq("abc"));
    assert!(!SecretString::new("abc").ct_eq("abd"));
    assert!(!SecretString::new("abc").ct_eq("abcd"));
}

#[test]
fn remembered_consent_keeps_the_newest_approvals() {
    const CB: &str = "https://app.example.com/cb";
    const MCP: &str = "https://gw.example.com/mcp";
    let approval = |n: u64, scopes: &[&str]| ConsentApproval {
        client_id: format!("client-{n}"),
        redirect_uri: CB.to_owned(),
        resource: MCP.to_owned(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        approved_at: 1_000 + n,
    };
    let mut record = ConsentMemoryRecord::default();
    for n in 0..25 {
        record.remember(approval(n, &["mcp:tools"]));
    }
    assert_eq!(record.approvals.len(), MAX_REMEMBERED_APPROVALS);
    let tools = ["mcp:tools".to_owned()];
    assert!(!record.covers("client-4", CB, MCP, &tools, 0));
    assert!(record.covers("client-5", CB, MCP, &tools, 0));

    record.remember(approval(5, &["mcp:tools", "mcp:resources"]));
    assert_eq!(record.approvals.len(), MAX_REMEMBERED_APPROVALS);
    let both = ["mcp:tools".to_owned(), "mcp:resources".to_owned()];
    assert!(record.covers("client-5", CB, MCP, &both, 0));
    assert!(!record.covers("client-6", CB, MCP, &both, 0));
    assert!(!record.covers("client-5", "https://app.example.com/cb/", MCP, &tools, 0));
    assert!(!record.covers("client-5", CB, MCP, &tools, 1_006));

    record.forget_before(1_020);
    assert_eq!(record.approvals.len(), 5, "approvals 20 to 24 are kept");
    assert!(record.forget_oldest());
    assert!(!record.covers("client-20", CB, MCP, &tools, 0));
    assert!(record.covers("client-21", CB, MCP, &tools, 0));
    while record.forget_oldest() {}
    assert!(record.approvals.is_empty());
}

#[test]
fn a_remembered_approval_is_for_one_resource() {
    const CB: &str = "https://app.example.com/cb";
    const MCP: &str = "https://gw.example.com/mcp";
    const REPORTS: &str = "https://gw.example.com/reports";
    let tools = ["mcp:tools".to_owned()];
    let approval = |resource: &str| ConsentApproval {
        client_id: "client".to_owned(),
        redirect_uri: CB.to_owned(),
        resource: resource.to_owned(),
        scopes: tools.to_vec(),
        approved_at: 1_000,
    };
    let mut record = ConsentMemoryRecord::default();
    record.remember(approval(MCP));
    assert!(record.covers("client", CB, MCP, &tools, 0));
    assert!(!record.covers("client", CB, REPORTS, &tools, 0));
    assert!(!record.covers("client", CB, "https://gw.example.com/mcp/", &tools, 0));

    record.remember(approval(REPORTS));
    assert_eq!(record.approvals.len(), 2, "one approval per resource");
    assert!(record.covers("client", CB, MCP, &tools, 0));
    assert!(record.covers("client", CB, REPORTS, &tools, 0));
}

#[test]
fn a_value_a_browser_holds_opens_only_under_its_label_issuer_and_keys() {
    let ring = keyring(&[("k1", 1)]);
    let state = state_over(&memory(), &ring, ISSUER);
    let mut record = ConsentMemoryRecord::default();
    record.remember(ConsentApproval {
        client_id: "c".to_owned(),
        redirect_uri: "https://app.example.com/cb".to_owned(),
        resource: "https://gw.example.com/mcp".to_owned(),
        scopes: vec!["mcp:tools".to_owned()],
        approved_at: 8,
    });
    let sealed = state.seal_value("consent_memory", &record).expect("seals");
    assert!(
        sealed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "URL-safe base64 without padding: {sealed}"
    );
    assert!(
        !sealed.contains("app.example.com"),
        "the value is encrypted"
    );
    assert_eq!(
        state.open_value::<ConsentMemoryRecord>("consent_memory", &sealed),
        Some(record.clone())
    );

    assert_eq!(
        state.open_value::<ConsentMemoryRecord>("consent_req", &sealed),
        None,
        "another label"
    );
    let other_issuer = state_over(&memory(), &ring, "https://other.example.com");
    assert_eq!(
        other_issuer.open_value::<ConsentMemoryRecord>("consent_memory", &sealed),
        None,
        "another issuer"
    );
    let other_keys = state_over(&memory(), &keyring(&[("k1", 2)]), ISSUER);
    assert_eq!(
        other_keys.open_value::<ConsentMemoryRecord>("consent_memory", &sealed),
        None,
        "another key under the same kid"
    );
    let rotated = state_over(&memory(), &keyring(&[("k2", 3), ("k1", 1)]), ISSUER);
    assert_eq!(
        rotated.open_value::<ConsentMemoryRecord>("consent_memory", &sealed),
        Some(record),
        "a rotated keyring still opens it"
    );

    let mut tampered = sealed.clone().into_bytes();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ASCII");
    assert_eq!(
        state.open_value::<ConsentMemoryRecord>("consent_memory", &tampered),
        None
    );
    assert_eq!(
        state.open_value::<ConsentMemoryRecord>("consent_memory", "not base64!"),
        None
    );
    assert_eq!(
        state.open_value::<ConsentMemoryRecord>("consent_memory", ""),
        None
    );
}

#[tokio::test]
async fn a_file_store_keeps_sign_ins_across_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("state.key");
    let gid = GrantId::generate().expect("gid");
    {
        let store = FileStore::open(dir.path(), FileStoreLimits::default()).expect("opens");
        let (ring, generated) = StateKeyring::from_file(&key_path).expect("key");
        assert!(generated);
        assert_eq!(ring.sealing_kid(), GENERATED_KEY_ID);
        let state = InteractiveState::new(StateParts {
            kv: Arc::new(store.clone()),
            backend: StateBackend::File {
                dir: store.dir().to_owned(),
            },
            keyring: Arc::new(ring),
            issuer: ISSUER.to_owned(),
            revoked: Arc::default(),
            revocation_interval: Duration::from_secs(60),
        })
        .expect("state");
        state
            .put(&keys::grant(&gid), &grant("p"), TTL)
            .await
            .expect("put");
    }
    let store = reopen(dir.path()).await;
    let (ring, generated) = StateKeyring::from_file(&key_path).expect("key");
    assert!(!generated, "the key is read back, not replaced");
    let state = InteractiveState::new(StateParts {
        kv: Arc::new(store),
        backend: StateBackend::InProcess,
        keyring: Arc::new(ring),
        issuer: ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(60),
    })
    .expect("state");
    assert_eq!(
        state.get(&keys::grant(&gid)).await.expect("get"),
        Some(grant("p"))
    );
}
