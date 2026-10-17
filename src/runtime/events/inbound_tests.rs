use super::*;
use crate::config::events::{InboundSourceConfig, builtin_inbound_profiles};
use axum::http::{HeaderMap, HeaderValue};
use mcpg_standard_webhooks::{WhsecSecret, sign_message};
use serde_json::json;

const WHSEC: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const OTHER_WHSEC: &str = "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn source(yaml: &str) -> InboundSourceConfig {
    serde_yaml::from_str(yaml).unwrap()
}

fn profiles(yaml: &str) -> Vec<InboundProfileConfig> {
    serde_yaml::from_str(yaml).unwrap()
}

async fn verifier(yaml: &str) -> InboundVerifier {
    declared_verifier(yaml, &[]).await
}

async fn declared_verifier(yaml: &str, declared: &[InboundProfileConfig]) -> InboundVerifier {
    InboundVerifier::build(&source(yaml), declared, |raw| async move { Ok(raw) })
        .await
        .unwrap()
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            HeaderName::try_from(*name).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

fn standard_headers(secret: &str, id: &str, at: u64, body: &[u8]) -> HeaderMap {
    let secret = WhsecSecret::parse(secret).unwrap();
    let mut headers = HeaderMap::new();
    sign_message(&[&secret], id, at, body)
        .unwrap()
        .insert_into(&mut headers)
        .unwrap();
    headers
}

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256::HMAC::mac(message, secret))
}

const NOW: u64 = 1_790_000_000;

#[test]
fn every_built_in_profile_is_valid() {
    let names: Vec<&str> = builtin_inbound_profiles()
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, ["standard_webhooks", "github", "stripe", "slack"]);
    for profile in builtin_inbound_profiles() {
        crate::config::events::validate_inbound_profile(&profile.name, profile).unwrap();
        SigningProfile::compile(profile, None).unwrap();
    }
}

#[tokio::test]
async fn the_standard_webhooks_profile_checks_what_the_reference_signer_signs() {
    let v = verifier(&format!(
        "source_id: s\nverify: {{ profile: standard_webhooks, secrets: ['{OTHER_WHSEC}', '{WHSEC}'] }}"
    ))
    .await;
    let body = br#"{"a":1}"#;
    let headers = standard_headers(WHSEC, "msg_1", NOW, body);
    assert_eq!(
        v.verify(&headers, body, NOW),
        Ok(VerifiedInbound {
            message_id: Some("msg_1".to_owned())
        })
    );
    let mut rotated = HeaderMap::new();
    sign_message(
        &[
            &WhsecSecret::parse(OTHER_WHSEC).unwrap(),
            &WhsecSecret::parse(WHSEC).unwrap(),
        ],
        "msg_2",
        NOW,
        body,
    )
    .unwrap()
    .insert_into(&mut rotated)
    .unwrap();
    assert!(v.verify(&rotated, body, NOW).is_ok());
}

#[tokio::test]
async fn the_standard_webhooks_profile_checks_the_official_rust_library_vector() {
    // standardwebhooks 1.0.1, `test_sign`.
    let v = verifier(
        "source_id: s\nverify: { profile: standard_webhooks, secrets: ['whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD'] }",
    )
    .await;
    let body = br#"{"email":"test@example.com","username":"test_user"}"#;
    let signed = headers(&[
        ("webhook-id", "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"),
        ("webhook-timestamp", "1649367553"),
        (
            "webhook-signature",
            "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=",
        ),
    ]);
    assert_eq!(
        v.verify(&signed, body, 1_649_367_553),
        Ok(VerifiedInbound {
            message_id: Some("msg_27UH4WbU6Z5A5EzD8u03UvzRbpk".to_owned())
        })
    );
    let negative = headers(&[
        ("webhook-id", "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"),
        ("webhook-timestamp", "1649367553"),
        (
            "webhook-signature",
            "v1,R3PTzyfHASBKHH98a7yexTwaJ4yNIcGhFQc1yuN+BPU=",
        ),
    ]);
    assert_eq!(
        v.verify(&negative, body, 1_649_367_553),
        Err(InboundRejection::Unauthorized)
    );
}

#[tokio::test]
async fn the_standard_webhooks_profile_takes_keys_of_24_to_64_bytes_only() {
    use base64::Engine as _;
    let whsec = |len: usize| {
        let key: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(key)
        )
    };
    let build = |secret: String| async move {
        InboundVerifier::build(
            &source(&format!(
                "source_id: s\nverify: {{ profile: standard_webhooks, secrets: ['{secret}'] }}"
            )),
            &[],
            |raw| async move { Ok(raw) },
        )
        .await
    };
    for len in [24, 64] {
        assert!(build(whsec(len)).await.is_ok(), "{len} bytes");
    }
    for len in [23, 65] {
        let secret = whsec(len);
        let error = build(secret.clone()).await.unwrap_err().to_string();
        assert!(error.contains("verify.secrets[0]"), "{error}");
        assert!(error.contains("between 24 and 64 bytes"), "{error}");
        assert!(!error.contains(&secret["whsec_".len()..]), "{error}");
    }
}

#[tokio::test]
async fn a_declared_profile_bounds_its_key_length() {
    let declared = profiles(
        "- name: acme\n  secret: { min_bytes: 16 }\n  signature: { header: X-Acme-Signature }",
    );
    crate::config::events::validate_inbound_profile("acme", &declared[0]).unwrap();
    let build = |secret: &str| {
        let yaml = format!("source_id: a\nverify: {{ profile: acme, secrets: ['{secret}'] }}");
        let declared = declared.clone();
        async move {
            InboundVerifier::build(&source(&yaml), &declared, |raw| async move { Ok(raw) }).await
        }
    };
    assert!(build("sixteen-bytes-ok").await.is_ok());
    let error = build("too-short").await.unwrap_err().to_string();
    assert!(
        error.contains("is shorter than 16 bytes once decoded"),
        "{error}"
    );
    assert!(!error.contains("too-short"), "{error}");
}

#[tokio::test]
async fn the_standard_webhooks_profile_refuses_tampering_wrong_keys_and_old_messages() {
    let v = verifier(&format!(
        "source_id: s\nverify: {{ profile: standard_webhooks, secrets: ['{WHSEC}'], tolerance_secs: 60 }}"
    ))
    .await;
    let body = br#"{"a":1}"#;
    let signed = standard_headers(WHSEC, "msg_1", NOW, body);
    assert_eq!(
        v.verify(&signed, br#"{"a":2}"#, NOW),
        Err(InboundRejection::Unauthorized)
    );
    let foreign = standard_headers(OTHER_WHSEC, "msg_1", NOW, body);
    assert_eq!(
        v.verify(&foreign, body, NOW),
        Err(InboundRejection::Unauthorized)
    );
    assert_eq!(
        v.verify(&signed, body, NOW + 61),
        Err(InboundRejection::Stale)
    );
    assert_eq!(
        v.verify(&signed, body, NOW - 61),
        Err(InboundRejection::Stale)
    );
    assert!(v.verify(&signed, body, NOW + 60).is_ok());
    let mut renamed = signed.clone();
    renamed.insert("webhook-id", HeaderValue::from_static("msg_other"));
    assert_eq!(
        v.verify(&renamed, body, NOW),
        Err(InboundRejection::Unauthorized),
        "the id is signed"
    );
    assert_eq!(
        v.verify(&HeaderMap::new(), body, NOW),
        Err(InboundRejection::Unauthorized)
    );
}

#[tokio::test]
async fn a_secret_outside_the_profile_format_fails_the_build_without_echoing_it() {
    let error = InboundVerifier::build(
        &source(
            "source_id: s\nverify: { profile: standard_webhooks, secrets: ['plain-text-value'] }",
        ),
        &[],
        |raw| async move { Ok(raw) },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("verify.secrets[0]"), "{error}");
    assert!(!error.contains("plain-text-value"), "{error}");

    let not_base64 = InboundVerifier::build(
        &source("source_id: s\nverify: { profile: standard_webhooks, secrets: ['whsec_%%%%'] }"),
        &[],
        |raw| async move { Ok(raw) },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(not_base64.contains("secret encoding"), "{not_base64}");
    assert!(!not_base64.contains("%%%%"), "{not_base64}");

    let unresolved = InboundVerifier::build(
        &source("source_id: s\nverify: { profile: github, secrets: ['${secret.MISSING}'] }"),
        &[],
        |_| async move { anyhow::bail!("`${{secret.MISSING}}` is not set") },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unresolved.contains("did not resolve"), "{unresolved}");

    let unknown = InboundVerifier::build(
        &source("source_id: s\nverify: { profile: nobody, secrets: [k] }"),
        &[],
        |raw| async move { Ok(raw) },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unknown.contains("`nobody`"), "{unknown}");
}

#[tokio::test]
async fn the_github_profile_checks_the_published_vector_and_every_secret() {
    let v = verifier(
        "source_id: gh\nverify: { profile: github, secrets: [old, \"It's a Secret to Everybody\"] }",
    )
    .await;
    let body = b"Hello, World!";
    let signed = headers(&[
        (
            "x-hub-signature-256",
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        ),
        ("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958"),
    ]);
    assert_eq!(
        v.verify(&signed, body, NOW),
        Ok(VerifiedInbound {
            message_id: Some("72d3162e-cc78-11e3-81ab-4c9367dc0958".to_owned())
        })
    );
    let with_old = headers(&[(
        "x-hub-signature-256",
        &format!("sha256={}", hmac_hex(b"old", body)),
    )]);
    assert_eq!(
        v.verify(&with_old, body, NOW),
        Ok(VerifiedInbound { message_id: None })
    );
    let refused = |value: &str| v.verify(&headers(&[("x-hub-signature-256", value)]), body, NOW);
    let good = format!("sha256={}", hmac_hex(b"old", body));
    assert_eq!(
        refused(&format!("sha256={}", hmac_hex(b"other", body))),
        Err(InboundRejection::Unauthorized)
    );
    assert_eq!(
        refused(good.trim_start_matches("sha256=")),
        Err(InboundRejection::Unauthorized)
    );
    assert_eq!(refused("sha256=zz"), Err(InboundRejection::Unauthorized));
    assert_eq!(refused("sha256=abcd"), Err(InboundRejection::Unauthorized));
    let twice = headers(&[
        ("x-hub-signature-256", &good),
        ("x-hub-signature-256", &good),
    ]);
    assert_eq!(
        v.verify(&twice, body, NOW),
        Err(InboundRejection::Unauthorized)
    );
    assert!(!format!("{v:?}").contains("Everybody"));
    assert!(format!("{v:?}").contains("github"));
}

#[tokio::test]
async fn the_stripe_profile_reads_the_timestamp_and_every_v1_signature() {
    let v =
        verifier("source_id: st\nverify: { profile: stripe, secrets: [whsec_test_secret] }").await;
    let body = br#"{"id":"evt_1","type":"invoice.paid","created":1790000000}"#;
    let message = [format!("{NOW}.").as_bytes(), body].concat();
    let good = hmac_hex(b"whsec_test_secret", &message);
    let other = hmac_hex(b"whsec_other", &message);
    let sign = |value: &str| headers(&[("stripe-signature", value)]);

    assert!(
        v.verify(&sign(&format!("t={NOW},v1={good}")), body, NOW)
            .is_ok()
    );
    assert!(
        v.verify(
            &sign(&format!("t={NOW},v1={other},v1={good},v0=deadbeef")),
            body,
            NOW
        )
        .is_ok(),
        "any v1 of a rolling secret signs it"
    );
    assert_eq!(
        v.verify(&sign(&format!("t={NOW},v1={other}")), body, NOW),
        Err(InboundRejection::Unauthorized)
    );
    assert_eq!(
        v.verify(&sign(&format!("t={},v1={good}", NOW + 1)), body, NOW),
        Err(InboundRejection::Unauthorized),
        "the timestamp is signed"
    );
    assert_eq!(
        v.verify(&sign(&format!("t={NOW},t={NOW},v1={good}")), body, NOW),
        Err(InboundRejection::Unauthorized),
        "one timestamp only"
    );
    assert_eq!(
        v.verify(&sign(&format!("v1={good}")), body, NOW),
        Err(InboundRejection::Unauthorized)
    );
    assert_eq!(
        v.verify(&sign(&format!("t={NOW},v1={good}")), body, NOW + 301),
        Err(InboundRejection::Stale)
    );
}

#[tokio::test]
async fn the_slack_profile_checks_the_published_vector_and_its_age() {
    let v = verifier(
        "source_id: sl\nverify: { profile: slack, secrets: [8f742231b10e8888abcd99yyyzzz85a5], tolerance_secs: 600 }",
    )
    .await;
    let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    let at = 1_531_420_618;
    let signed = headers(&[
        ("x-slack-request-timestamp", "1531420618"),
        (
            "x-slack-signature",
            "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
        ),
    ]);
    assert_eq!(
        v.verify(&signed, body, at + 600),
        Ok(VerifiedInbound { message_id: None })
    );
    assert_eq!(
        v.verify(&signed, body, at + 601),
        Err(InboundRejection::Stale)
    );
    let mut moved = signed.clone();
    moved.insert(
        "x-slack-request-timestamp",
        HeaderValue::from_static("1531420619"),
    );
    assert_eq!(
        v.verify(&moved, body, at),
        Err(InboundRejection::Unauthorized)
    );
    let mut signed_plus = signed.clone();
    signed_plus.insert(
        "x-slack-request-timestamp",
        HeaderValue::from_static("+1531420618"),
    );
    assert_eq!(
        v.verify(&signed_plus, body, at),
        Err(InboundRejection::Unauthorized),
        "a timestamp is digits only"
    );
}

#[tokio::test]
async fn handshakes_are_answered_by_the_profile_not_the_code() {
    let github = verifier("source_id: gh\nverify: { profile: github, secrets: [k] }").await;
    assert_eq!(
        github.handshake(
            &headers(&[("x-github-event", "ping")]),
            &json!({"zen": "x"})
        ),
        Some(Handshake::Ack)
    );
    assert_eq!(
        github.handshake(&headers(&[("x-github-event", "issues")]), &json!({})),
        None
    );

    let slack = verifier("source_id: sl\nverify: { profile: slack, secrets: [k] }").await;
    let challenge = json!({"type": "url_verification", "challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"});
    let mut reply = serde_json::Map::new();
    reply.insert(
        "challenge".to_owned(),
        json!("3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"),
    );
    assert_eq!(
        slack.handshake(&HeaderMap::new(), &challenge),
        Some(Handshake::Reply(reply))
    );
    for unusable in [
        json!({"type": "url_verification"}),
        json!({"type": "url_verification", "challenge": "has space"}),
        json!({"type": "url_verification", "challenge": "x".repeat(MAX_ECHO_CHARS + 1)}),
        json!({"type": "url_verification", "challenge": 7}),
    ] {
        assert_eq!(
            slack.handshake(&HeaderMap::new(), &unusable),
            Some(Handshake::Invalid),
            "{unusable}"
        );
    }
    assert_eq!(
        slack.handshake(&HeaderMap::new(), &json!({"type": "event_callback"})),
        None
    );
    let unsigned = verifier("source_id: s\nallow_unsigned: true").await;
    assert_eq!(unsigned.handshake(&HeaderMap::new(), &challenge), None);
}

#[tokio::test]
async fn an_operator_profile_describes_a_sender_the_gateway_does_not_know() {
    let declared = profiles(
        r#"
- name: acme
  algorithm: sha512
  secret: { encoding: hex }
  signature: { header: X-Acme-Signature, separator: ";", key: sig, encoding: base64 }
  signed_payload: "{header:x-acme-id}|{timestamp}|{body}"
  signed_timestamp: { key: ts, tolerance_secs: 30 }
  event_id: { header: X-Acme-Id }
  event_time: /at
  handshakes:
    - when: { body: { /kind: hello } }
      reply: { echo: /nonce }
"#,
    );
    crate::config::events::validate_inbound_profile("acme", &declared[0]).unwrap();
    let v = declared_verifier(
        "source_id: acme\nverify: { profile: acme, secrets: ['6b6579'] }",
        &declared,
    )
    .await;
    assert_eq!(v.event_time_pointer(), Some("/at"));
    let body = br#"{"kind":"order","at":1790000000}"#;
    let message = [format!("a-1|{NOW}|").as_bytes(), body].concat();
    let mut mac = <hmac::Hmac<sha2::Sha512> as hmac::KeyInit>::new_from_slice(b"key").unwrap();
    hmac::Mac::update(&mut mac, &message);
    let digest =
        base64::engine::general_purpose::STANDARD.encode(hmac::Mac::finalize(mac).into_bytes());
    let signed = headers(&[
        ("x-acme-signature", &format!("ts={NOW}; sig={digest}")),
        ("x-acme-id", "a-1"),
    ]);
    assert_eq!(
        v.verify(&signed, body, NOW),
        Ok(VerifiedInbound {
            message_id: Some("a-1".to_owned())
        })
    );
    assert_eq!(
        v.verify(&signed, body, NOW + 31),
        Err(InboundRejection::Stale)
    );
    let mut renamed = signed.clone();
    renamed.insert("x-acme-id", HeaderValue::from_static("a-2"));
    assert_eq!(
        v.verify(&renamed, body, NOW),
        Err(InboundRejection::Unauthorized)
    );
    let mut reply = serde_json::Map::new();
    reply.insert("echo".to_owned(), json!("n-1"));
    assert_eq!(
        v.handshake(&HeaderMap::new(), &json!({"kind": "hello", "nonce": "n-1"})),
        Some(Handshake::Reply(reply))
    );
}

#[tokio::test]
async fn unsigned_sources_accept_anything_and_name_no_sender_id() {
    let v = verifier("source_id: s\nallow_unsigned: true").await;
    assert_eq!(
        v.verify(&HeaderMap::new(), b"{}", NOW),
        Ok(VerifiedInbound { message_id: None })
    );
    assert_eq!(
        v.verify(&headers(&[("webhook-id", "msg_9")]), b"{}", NOW),
        Ok(VerifiedInbound { message_id: None })
    );
    assert_eq!(v.event_id_pointer(), None);
}

#[test]
fn the_when_filter_matches_headers_and_body_pointers() {
    let filter = InboundFilter::from_config(&source(
        "source_id: gh\nallow_unsigned: true\nwhen: { header: { X-GitHub-Event: issues }, body: { /action: opened, /issue/locked: false } }",
    ))
    .unwrap();
    let issues = headers(&[("x-github-event", "issues")]);
    let body = json!({"action": "opened", "issue": {"locked": false}});
    assert!(filter.keeps(&issues, &body));
    assert!(!filter.keeps(
        &issues,
        &json!({"action": "closed", "issue": {"locked": false}})
    ));
    assert!(!filter.keeps(&issues, &json!({"action": "opened"})));
    assert!(!filter.keeps(&headers(&[("x-github-event", "push")]), &body));
    assert!(!filter.keeps(&HeaderMap::new(), &body));

    let none = InboundFilter::from_config(&source("source_id: s\nallow_unsigned: true")).unwrap();
    assert!(none.keeps(&HeaderMap::new(), &json!({})));
}

#[test]
fn event_ids_and_times_come_from_the_body_or_a_header() {
    let body = json!({"delivery_id": "d-1", "n": 42, "issue": {"created_at": "2026-10-03T14:30:00+02:00", "unix": 1790000000}});
    let signed = VerifiedInbound {
        message_id: Some("msg_1".to_owned()),
    };
    assert_eq!(
        extract_event_id(Some("/delivery_id"), &body, &signed).as_deref(),
        Some("d-1")
    );
    assert_eq!(
        extract_event_id(Some("/n"), &body, &signed).as_deref(),
        Some("42")
    );
    assert_eq!(extract_event_id(Some("/missing"), &body, &signed), None);
    assert_eq!(extract_event_id(Some("/issue"), &body, &signed), None);
    assert_eq!(
        extract_event_id(None, &body, &signed).as_deref(),
        Some("msg_1")
    );
    assert_eq!(
        extract_event_id(None, &body, &VerifiedInbound::default()),
        None
    );

    assert_eq!(
        extract_timestamp(Some("/issue/created_at"), &body).as_deref(),
        Some("2026-10-03T12:30:00.000Z")
    );
    assert_eq!(
        extract_timestamp(Some("/issue/unix"), &body).as_deref(),
        Some("2026-09-21T14:13:20.000Z")
    );
    assert_eq!(extract_timestamp(Some("/delivery_id"), &body), None);
    assert_eq!(extract_timestamp(None, &body), None);
}

#[test]
fn the_rate_limiter_allows_a_burst_then_refills() {
    let limiter = RateLimiter::new(&crate::config::events::InboundRateLimitConfig {
        per_sec: 10,
        burst: 3,
    });
    let start = Instant::now();
    for _ in 0..3 {
        assert!(limiter.take_at(start).is_ok());
    }
    let wait = limiter.take_at(start).unwrap_err();
    assert!(
        wait <= Duration::from_millis(100) && wait > Duration::ZERO,
        "{wait:?}"
    );
    assert!(limiter.take_at(start + Duration::from_millis(100)).is_ok());
    assert!(limiter.take_at(start + Duration::from_millis(100)).is_err());
    assert!(limiter.take_at(start + Duration::from_secs(10)).is_ok());
    assert!(limiter.take_at(start + Duration::from_secs(10)).is_ok());
    assert!(limiter.take_at(start + Duration::from_secs(10)).is_ok());
    assert!(limiter.take_at(start + Duration::from_secs(10)).is_err());
}
