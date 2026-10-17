use std::sync::Arc;
use std::time::Duration;

use mcpg_standard_webhooks::{Verifier, WhsecSecret};

use super::*;
use crate::runtime::events::test_support::{Receiver, Reply, echo_reply, loopback_egress};

const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn run(receiver: &Receiver) -> Result<(), DeliveryErrorCategory> {
    let egress = loopback_egress();
    let url = egress.check_url(&receiver.url("/hook")).unwrap();
    let secret = WhsecSecret::parse(SECRET).unwrap();
    challenge(
        &egress,
        &url,
        "sub_abc",
        &secret,
        Duration::from_secs(2),
        now_s(),
    )
    .await
}

#[tokio::test]
async fn an_endpoint_that_echoes_the_signed_challenge_passes() {
    let receiver = Receiver::start(echo_reply()).await;
    assert_eq!(run(&receiver).await, Ok(()));
    let requests = receiver.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let body = request.json();
    assert_eq!(body["type"], "verification");
    let nonce = body["challenge"].as_str().unwrap();
    assert_eq!(
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce)
            .unwrap()
            .len(),
        CHALLENGE_BYTES
    );
    let id = request.header("webhook-id").unwrap();
    assert!(id.starts_with("msg_verification_"), "{id}");
    assert_eq!(
        request.header("x-mcp-subscription-id").as_deref(),
        Some("sub_abc")
    );
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json")
    );
    let verifier = Verifier::new(vec![WhsecSecret::parse(SECRET).unwrap()]).unwrap();
    verifier
        .verify_headers(&request.headers, &request.body, now_s())
        .expect("the challenge is signed with the subscription secret");
}

#[tokio::test]
async fn a_wrong_echo_a_bad_body_or_an_error_status_fails() {
    let cases: Vec<(Reply, DeliveryErrorCategory)> = vec![
        (
            Arc::new(|_| (200, br#"{"challenge":"not-it"}"#.to_vec())),
            DeliveryErrorCategory::ChallengeFailed,
        ),
        (
            Arc::new(|_| (200, b"ok".to_vec())),
            DeliveryErrorCategory::ChallengeFailed,
        ),
        (
            Arc::new(|_| (200, Vec::new())),
            DeliveryErrorCategory::ChallengeFailed,
        ),
        (
            Arc::new(|_| (404, Vec::new())),
            DeliveryErrorCategory::Http4xx,
        ),
        (
            Arc::new(|_| (503, Vec::new())),
            DeliveryErrorCategory::Http5xx,
        ),
        (
            Arc::new(|_| (302, Vec::new())),
            DeliveryErrorCategory::ConnectionRefused,
        ),
    ];
    for (reply, expected) in cases {
        let receiver = Receiver::start(reply).await;
        assert_eq!(run(&receiver).await, Err(expected));
    }
}

#[tokio::test]
async fn an_oversized_echo_fails() {
    let receiver = Receiver::start(Arc::new(|request| {
        let body = request.json();
        let echo = serde_json::json!({ "challenge": body["challenge"], "pad": "x".repeat(8_192) });
        (200, serde_json::to_vec(&echo).unwrap())
    }))
    .await;
    assert_eq!(
        run(&receiver).await,
        Err(DeliveryErrorCategory::ChallengeFailed)
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_reads_as_refused() {
    let egress = loopback_egress();
    // A port held by a socket that never listens: refused, and no other
    // process can bind it meanwhile.
    let held = tokio::net::TcpSocket::new_v4().unwrap();
    held.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = held.local_addr().unwrap().port();
    let url = egress
        .check_url(&format!("http://gone.test:{port}/hook"))
        .unwrap();
    let secret = WhsecSecret::parse(SECRET).unwrap();
    let outcome = challenge(
        &egress,
        &url,
        "sub_abc",
        &secret,
        Duration::from_secs(2),
        now_s(),
    )
    .await;
    assert_eq!(outcome, Err(DeliveryErrorCategory::ConnectionRefused));
}

#[test]
fn the_allowlist_admits_only_listed_hosts_in_allowlist_mode() {
    let mut config = WebhookVerificationConfig {
        allowlist: vec!["hooks.example.com.".to_owned()],
        ..WebhookVerificationConfig::default()
    };
    assert!(!is_allowlisted(&config, "hooks.example.com"));
    config.modes.push(VerificationMode::Allowlist);
    assert!(is_allowlisted(&config, "hooks.example.com"));
    assert!(is_allowlisted(&config, "HOOKS.example.com"));
    assert!(!is_allowlisted(&config, "evil.hooks.example.com"));
}

#[test]
fn a_document_entry_names_its_url_or_the_urls_under_its_prefix() {
    let egress = loopback_egress();
    let url = |raw: &str| egress.check_url(raw).unwrap();
    let hook = url("https://127.0.0.1:8443/mcp/hooks/a?x=1");
    assert!(names_callback(
        "https://127.0.0.1:8443/mcp/hooks/a?x=1",
        &hook
    ));
    assert!(names_callback("https://127.0.0.1:8443/mcp/", &hook));
    assert!(
        !names_callback("https://127.0.0.1:8443/mcp", &hook),
        "a prefix ends in /"
    );
    assert!(
        !names_callback("https://127.0.0.1:9443/mcp/", &hook),
        "another origin"
    );
    assert!(!names_callback("not a url", &hook));
}

#[tokio::test]
async fn a_receiver_document_admits_the_callbacks_it_names() {
    let receiver = Receiver::start(echo_reply()).await;
    let prefix = receiver.url("/hooks/");
    receiver.set_reply(Arc::new(
        move |request: &crate::runtime::events::test_support::Received| {
            if request.method == axum::http::Method::GET && request.path == RECEIVER_DOCUMENT_PATH {
                let document = serde_json::json!({ "callbacks": [prefix.clone()] });
                (200, serde_json::to_vec(&document).unwrap())
            } else {
                (404, Vec::new())
            }
        },
    ));
    let egress = loopback_egress();
    let timeout = Duration::from_secs(2);
    let named = egress.check_url(&receiver.url("/hooks/a")).unwrap();
    let other = egress.check_url(&receiver.url("/other")).unwrap();
    assert_eq!(
        receiver_document_admits(&egress, &named, timeout).await,
        Ok(true)
    );
    assert_eq!(
        receiver_document_admits(&egress, &other, timeout).await,
        Ok(false)
    );

    receiver.set_reply(Arc::new(
        |_: &crate::runtime::events::test_support::Received| (404, Vec::new()),
    ));
    assert_eq!(
        receiver_document_admits(&egress, &named, timeout).await,
        Ok(false),
        "no document names nothing"
    );
}

#[tokio::test]
async fn a_receiver_document_in_the_sketch_shape_admits_its_path_prefixes() {
    let receiver = Receiver::start(echo_reply()).await;
    receiver.set_reply(Arc::new(
        |request: &crate::runtime::events::test_support::Received| {
            if request.method == axum::http::Method::GET && request.path == RECEIVER_DOCUMENT_PATH {
                let document = serde_json::json!({ "receivers": ["/hooks/", "/exact"] });
                (200, serde_json::to_vec(&document).unwrap())
            } else {
                (404, Vec::new())
            }
        },
    ));
    let egress = loopback_egress();
    let timeout = Duration::from_secs(2);
    for (path, admitted) in [
        ("/hooks/a", true),
        ("/hooks/", true),
        ("/exact", true),
        ("/exact/below", true),
        ("/exactly", false),
        ("/hooks", false),
        ("/other", false),
    ] {
        let url = egress.check_url(&receiver.url(path)).unwrap();
        assert_eq!(
            receiver_document_admits(&egress, &url, timeout).await,
            Ok(admitted),
            "{path}"
        );
    }
}

#[test]
fn a_path_prefix_must_be_a_path() {
    let egress = loopback_egress();
    let url = egress.check_url("http://receiver.test:1/hooks/a").unwrap();
    assert!(covers_path("/hooks/", &url));
    assert!(!covers_path("hooks/", &url));
    assert!(!covers_path("http://receiver.test:1/hooks/", &url));
}

#[test]
fn in_flight_slots_are_bounded_per_host_and_freed_on_drop() {
    let hosts = Arc::new(InFlightHosts::default());
    let a = hosts.take("a.example", 2).unwrap();
    let _b = hosts.take("a.example", 2).unwrap();
    assert!(hosts.take("a.example", 2).is_none());
    assert!(hosts.take("b.example", 2).is_some());
    drop(a);
    assert!(hosts.take("a.example", 2).is_some());
}
