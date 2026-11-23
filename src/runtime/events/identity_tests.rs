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

/// The card presents the server as `server/discover` does: its version,
/// the configured title, and the configured description when the registry
/// sets none.
#[test]
fn the_server_card_carries_the_configured_server_identity() {
    use crate::transports::http::discovery::server_card;
    let mut config = crate::config::AppConfig::default();
    config.gateway.server.canonical_url = Some("https://gw.example".to_owned());
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert_eq!(card["name"], "dev.mcpg/gateway");
    assert_eq!(card["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(card["description"], "MCP gateway");
    assert!(card.get("title").is_none(), "no title unless one is set");

    config.mcp.server_info.title = Some("Acme Docs".to_owned());
    config.mcp.server_info.description = Some("Search the Acme docs.".to_owned());
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert_eq!(card["title"], "Acme Docs");
    assert_eq!(card["description"], "Search the Acme docs.");
    assert_eq!(card["version"], env!("CARGO_PKG_VERSION"));

    // The registry's name and description come first.
    config.mcp.registry.name = "com.acme/docs".to_owned();
    config.mcp.registry.description = Some("Acme docs over MCP.".to_owned());
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert_eq!(card["name"], "com.acme/docs");
    assert_eq!(card["description"], "Acme docs over MCP.");
    config.mcp.registry.description = Some("x".repeat(101));
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert_eq!(card["description"], "MCP gateway");

    // Text the card schema does not take (empty, over 100 characters) is
    // left out.
    config.mcp.registry.description = None;
    config.mcp.server_info.title = Some("t".repeat(101));
    config.mcp.server_info.description = Some(String::new());
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert!(card.get("title").is_none());
    assert_eq!(card["description"], "MCP gateway");
    config.mcp.server_info.title = Some("é".repeat(100));
    let card = server_card(&config, serde_json::Map::new()).unwrap();
    assert_eq!(card["title"], "é".repeat(100), "the limit is in characters");
}

/// The card takes `mcp.registry.name` only when the Server Card schema
/// does: 3 to 200 characters of `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`. Any
/// other name gives the default.
#[test]
fn the_server_card_name_follows_the_card_schema() {
    use crate::transports::http::discovery::server_card;
    let mut config = crate::config::AppConfig::default();
    config.gateway.server.canonical_url = Some("https://gw.example".to_owned());
    let longest = format!("{}/{}", "a".repeat(100), "b".repeat(99));
    for name in [
        "a/b",
        "com.acme/docs",
        "io-acme.dev/my_server.v2",
        "A-1/z",
        longest.as_str(),
    ] {
        config.mcp.registry.name = name.to_owned();
        let card = server_card(&config, serde_json::Map::new()).unwrap();
        assert_eq!(card["name"], name, "{name}");
    }
    let too_long = format!("{}/{}", "a".repeat(100), "b".repeat(100));
    for name in [
        "",
        "/",
        "a/",
        "/b",
        "ab",
        "com.acme/docs/v2",
        "com acme/docs",
        "com_acme/docs",
        "com.acme/do cs",
        "com.acme/döcs",
        too_long.as_str(),
    ] {
        config.mcp.registry.name = name.to_owned();
        let card = server_card(&config, serde_json::Map::new()).unwrap();
        assert_eq!(card["name"], "dev.mcpg/gateway", "{name:?}");
    }
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
