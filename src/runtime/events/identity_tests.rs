use super::*;
use crate::config::events::WebhookSigningKeyConfig;

/// An Ed25519 private key in PKCS#8 v1 PEM: a fixed DER prefix, then the
/// 32-byte seed.
pub(crate) fn ed25519_pem(seed: u8) -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[seed; 32]);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    )
}

fn webhook_config(keys: &[(Option<&str>, u8)], ranges: &[&str]) -> EventsWebhookConfig {
    EventsWebhookConfig {
        signing_keys: keys
            .iter()
            .map(|(kid, seed)| WebhookSigningKeyConfig {
                kid: kid.map(str::to_owned),
                private_key: ed25519_pem(*seed),
            })
            .collect(),
        egress_ip_ranges: ranges.iter().map(|r| (*r).to_owned()).collect(),
        ..EventsWebhookConfig::default()
    }
}

#[test]
fn no_keys_no_identity_and_nothing_to_publish() {
    let config = EventsWebhookConfig::default();
    assert!(ServerIdentity::from_config(&config).unwrap().is_none());
    assert_eq!(webhooks_info(&config, None), None);
}

#[test]
fn the_first_key_signs_and_every_key_is_published() {
    let config = webhook_config(&[(Some("new"), 1), (Some("old"), 2)], &["203.0.113.0/24"]);
    let identity = ServerIdentity::from_config(&config).unwrap().unwrap();
    let info = webhooks_info(&config, Some(&identity)).unwrap();
    let keys = info["webhooks"]["signingKeys"]["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    for key in keys {
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert!(key.get("d").is_none(), "no private member leaves: {key}");
    }
    assert_eq!(keys[0]["kid"], "new");
    assert_eq!(
        info["webhooks"]["egressIpRanges"],
        json!(["203.0.113.0/24"])
    );

    let signature = identity
        .sign("msg_abc", 1_739_980_800, b"{\"a\":1}")
        .unwrap();
    assert!(signature.starts_with("v1a,"));
    let card = json!({
        "remotes": [{
            "type": "streamable-http",
            "url": "https://gw.example/mcp",
            "extensionsInfo": { "io.modelcontextprotocol/events": info }
        }]
    });
    let published = published_signing_keys(&card, "https://gw.example/mcp/").unwrap();
    let header = format!("v1,AAAA {signature}");
    assert!(verify_asymmetric(
        &published,
        "msg_abc",
        1_739_980_800,
        b"{\"a\":1}",
        &header
    ));
    assert!(!verify_asymmetric(
        &published,
        "msg_abc",
        1_739_980_800,
        b"{\"a\":2}",
        &header
    ));
    assert!(!verify_asymmetric(
        &published,
        "msg_abd",
        1_739_980_800,
        b"{\"a\":1}",
        &header
    ));
    assert!(!verify_asymmetric(
        &published,
        "msg_abc",
        1_739_980_800,
        b"{\"a\":1}",
        "v1,AAAA"
    ));

    let other = ServerIdentity::from_config(&webhook_config(&[(None, 3)], &[]))
        .unwrap()
        .unwrap();
    let forged = other.sign("msg_abc", 1_739_980_800, b"{\"a\":1}").unwrap();
    assert!(!verify_asymmetric(
        &published,
        "msg_abc",
        1_739_980_800,
        b"{\"a\":1}",
        &forged
    ));
}

#[test]
fn a_card_for_another_remote_publishes_no_keys() {
    let config = webhook_config(&[(None, 1)], &[]);
    let identity = ServerIdentity::from_config(&config).unwrap().unwrap();
    let card = json!({
        "remotes": [{
            "type": "streamable-http",
            "url": "https://other.example/mcp",
            "extensionsInfo": {
                "io.modelcontextprotocol/events": webhooks_info(&config, Some(&identity)).unwrap()
            }
        }]
    });
    assert!(published_signing_keys(&card, "https://gw.example/mcp").is_none());
    assert!(published_signing_keys(&json!({}), "https://gw.example/mcp").is_none());
}

/// The Server Card names the MCP endpoint as its one remote and carries the
/// events entry there; the receiving side finds the keys under it.
#[test]
fn the_server_card_publishes_the_keys_under_its_remote() {
    use crate::transports::http::discovery::{SERVER_CARD_SCHEMA, server_card};
    let mut config = crate::config::AppConfig::default();
    assert!(
        server_card(&config, serde_json::Map::new()).is_none(),
        "no public URL"
    );
    config.gateway.server.canonical_url = Some("https://gw.example/".to_owned());
    let webhook = webhook_config(&[(Some("k1"), 4)], &["198.51.100.0/24"]);
    let identity = ServerIdentity::from_config(&webhook).unwrap().unwrap();
    let mut info = serde_json::Map::new();
    info.insert(
        crate::protocol::v_2026_07_28::extensions::events::wire::EXTENSION_ID.to_owned(),
        webhooks_info(&webhook, Some(&identity)).unwrap(),
    );
    let card = server_card(&config, info).unwrap();
    assert_eq!(card["$schema"], SERVER_CARD_SCHEMA);
    assert!(card["name"].as_str().unwrap().contains('/'));
    assert!(card["description"].is_string());
    let remote = &card["remotes"][0];
    assert_eq!(remote["type"], "streamable-http");
    let url = format!("https://gw.example{}", config.gateway.server.mcp_path);
    assert_eq!(remote["url"], url);
    let keys = published_signing_keys(&card, &url).unwrap();
    assert_eq!(keys[0].common.key_id.as_deref(), Some("k1"));
    assert_eq!(
        remote["extensionsInfo"]["io.modelcontextprotocol/events"]["webhooks"]["egressIpRanges"],
        json!(["198.51.100.0/24"])
    );
}

#[test]
fn unusable_or_duplicate_keys_are_refused() {
    let mut config = webhook_config(&[(None, 1)], &[]);
    config.signing_keys[0].private_key = "not a pem".to_owned();
    let error = ServerIdentity::from_config(&config)
        .unwrap_err()
        .to_string();
    assert!(error.contains("signing_keys[0].private_key"), "{error}");

    let twice = webhook_config(&[(Some("k"), 1), (Some("k"), 2)], &[]);
    let error = ServerIdentity::from_config(&twice).unwrap_err().to_string();
    assert!(error.contains("kid `k`"), "{error}");
}
