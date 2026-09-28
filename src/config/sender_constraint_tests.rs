use super::*;
use crate::config::{AppConfig, AuthorizationServerConfig};

/// An authorization server that redeems ID-JAGs for one registered client.
const BASE: &str = r#"
governance:
  access:
    resource_metadata:
      resource: https://mcp.example.com/mcp
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: ema-signing-secret-0123456789abcdef
      trusted_idps:
        - issuer: https://acme.okta.com
          allowed_hosts: [acme.okta.com]
      clients:
        - client_id: mcp-client
"#;

fn base() -> AppConfig {
    let config: AppConfig = serde_yaml::from_str(BASE).expect("test config parses");
    config.validate().expect("the base config validates");
    config
}

fn authz(config: &mut AppConfig) -> &mut AuthorizationServerConfig {
    config
        .governance
        .access
        .authorization_server
        .as_mut()
        .expect("authorization_server")
}

#[track_caller]
fn refused(config: &AppConfig, named: &str) {
    let error = config
        .validate()
        .expect_err("the config must be refused")
        .to_string();
    assert!(error.contains(named), "{error}");
}

#[test]
fn dpop_is_off_by_default_with_the_documented_defaults() {
    let mut config = base();
    let dpop = &authz(&mut config).dpop;
    assert_eq!(*dpop, DpopConfig::default());
    assert!(!dpop.enabled && !dpop.required);
    assert_eq!(dpop.proof_max_age_secs, 60);
    assert_eq!(dpop.nonce, DpopNonceMode::Off);
    assert_eq!(dpop.nonce_lifetime_secs, 300);
    assert_eq!(
        dpop.allowed_algs,
        [
            "ES256", "ES384", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"
        ]
    );
    assert!(!authz(&mut config).clients[0].dpop_bound_access_tokens);
}

#[test]
fn a_partial_block_keeps_the_other_defaults_and_unknown_keys_are_refused() {
    let yaml = BASE.replace(
        "      clients:",
        "      dpop:\n        enabled: true\n        nonce: token_endpoint\n      clients:",
    );
    let mut config: AppConfig = serde_yaml::from_str(&yaml).expect("parses");
    config.validate().expect("validates");
    let dpop = &authz(&mut config).dpop;
    assert!(dpop.enabled);
    assert_eq!(dpop.nonce, DpopNonceMode::TokenEndpoint);
    assert_eq!(dpop.proof_max_age_secs, 60);

    let unknown = BASE.replace(
        "      clients:",
        "      dpop:\n        enable: true\n      clients:",
    );
    assert!(serde_yaml::from_str::<AppConfig>(&unknown).is_err());
    let unknown_mode = BASE.replace(
        "      clients:",
        "      dpop:\n        nonce: sometimes\n      clients:",
    );
    assert!(serde_yaml::from_str::<AppConfig>(&unknown_mode).is_err());
}

#[test]
fn required_needs_enabled() {
    let mut config = base();
    authz(&mut config).dpop.required = true;
    refused(&config, "dpop.required needs enabled");
    authz(&mut config).dpop.enabled = true;
    config.validate().expect("required with enabled validates");
}

#[test]
fn allowed_algs_are_asymmetric_known_and_unique() {
    for (algs, named) in [
        (vec![], "at least one algorithm"),
        (vec!["HS256"], "HMAC algorithms are never accepted"),
        (vec!["none"], "unsupported algorithm"),
        (vec!["ES512"], "unsupported algorithm"),
        (vec!["ES256", "ES256"], "more than once"),
    ] {
        let mut config = base();
        let dpop = &mut authz(&mut config).dpop;
        dpop.enabled = true;
        dpop.allowed_algs = algs.into_iter().map(str::to_owned).collect();
        refused(&config, named);
    }
    let mut config = base();
    authz(&mut config).dpop.allowed_algs = vec!["EdDSA".to_owned(), "PS256".to_owned()];
    config.validate().expect("asymmetric algorithms validate");
}

#[test]
fn the_proof_age_and_nonce_lifetime_are_bounded() {
    for (age, lifetime, named) in [
        (0, 300, "proof_max_age_secs"),
        (301, 300, "proof_max_age_secs"),
        (60, 29, "nonce_lifetime_secs"),
        (60, 3_601, "nonce_lifetime_secs"),
    ] {
        let mut config = base();
        let dpop = &mut authz(&mut config).dpop;
        dpop.proof_max_age_secs = age;
        dpop.nonce_lifetime_secs = lifetime;
        refused(&config, named);
    }
    for (age, lifetime) in [(1, 30), (300, 3_600)] {
        let mut config = base();
        let dpop = &mut authz(&mut config).dpop;
        dpop.proof_max_age_secs = age;
        dpop.nonce_lifetime_secs = lifetime;
        config.validate().expect("the bounds validate");
    }
}

#[test]
fn a_client_bound_to_dpop_needs_dpop_on() {
    let mut config = base();
    authz(&mut config).clients[0].dpop_bound_access_tokens = true;
    refused(&config, "dpop_bound_access_tokens needs");
    authz(&mut config).dpop.enabled = true;
    config
        .validate()
        .expect("the client flag validates with DPoP on");
}

#[test]
fn the_nonce_mode_names_the_endpoints_it_covers() {
    assert!(!DpopNonceMode::Off.covers_token_endpoint());
    assert!(DpopNonceMode::TokenEndpoint.covers_token_endpoint());
    assert!(DpopNonceMode::Always.covers_token_endpoint());
}

// ---------------------------------------------------------------------------
// Authorization details (RFC 9396)
// ---------------------------------------------------------------------------

/// `BASE` with `block` as its `authorization_details`.
fn with_details(block: &str) -> String {
    let indented: String = block
        .lines()
        .map(|line| format!("        {line}\n"))
        .collect();
    BASE.replace(
        "      clients:",
        &format!("      authorization_details:\n{indented}      clients:"),
    )
}

/// A type named `name` with no other rule.
fn detail_type(name: &str) -> AuthorizationDetailsTypeConfig {
    AuthorizationDetailsTypeConfig {
        type_name: name.to_owned(),
        description: None,
        schema: None,
        actions: None,
        datatypes: None,
        privileges: None,
        locations: AuthorizationDetailLocations::default(),
    }
}

#[test]
fn authorization_details_are_off_by_default() {
    let mut config = base();
    let details = &authz(&mut config).authorization_details;
    assert_eq!(*details, AuthorizationDetailsConfig::default());
    assert!(details.types.is_empty() && !details.enabled());
    assert_eq!(details.max_entries, 16);
}

#[test]
fn a_type_block_parses_with_its_defaults_and_unknown_keys_are_refused() {
    let yaml = with_details(
        "types:\n  - type: mcp_tool\n    description: Call these MCP tools\n    actions: \
         [tools/call]\n    locations: any\n  - type: https://example.com/payment\nmax_entries: 4",
    );
    let mut config: AppConfig = serde_yaml::from_str(&yaml).expect("parses");
    config.validate().expect("validates");
    let details = &authz(&mut config).authorization_details;
    assert!(details.enabled());
    assert_eq!(details.max_entries, 4);
    assert_eq!(details.types[0].type_name, "mcp_tool");
    assert_eq!(
        details.types[0].description.as_deref(),
        Some("Call these MCP tools")
    );
    assert_eq!(
        details.types[0].locations,
        AuthorizationDetailLocations::Any
    );
    assert_eq!(
        details.types[1].locations,
        AuthorizationDetailLocations::Resource,
        "locations defaults to the resource identifiers"
    );
    for refused_yaml in [
        with_details("typs: []"),
        with_details("types:\n  - type: t\n    action: [read]"),
        with_details("types:\n  - type: t\n    locations: anywhere"),
        with_details("types:\n  - description: no type"),
    ] {
        assert!(
            serde_yaml::from_str::<AppConfig>(&refused_yaml).is_err(),
            "{refused_yaml}"
        );
    }
}

#[test]
fn detail_types_are_named_once_without_whitespace_or_control_characters() {
    for (name, named) in [
        (String::new(), "types[0].type must be 1 to 256"),
        ("t".repeat(257), "types[0].type must be 1 to 256"),
        ("mcp tool".to_owned(), "without whitespace"),
        ("mcp\u{7}tool".to_owned(), "control characters"),
    ] {
        let mut config = base();
        authz(&mut config).authorization_details.types = vec![detail_type(&name)];
        refused(&config, named);
    }
    let mut config = base();
    authz(&mut config).authorization_details.types =
        vec![detail_type("mcp_tool"), detail_type("mcp_tool")];
    refused(&config, "types[1].type `mcp_tool` is listed more than once");

    let mut config = base();
    authz(&mut config).authorization_details.types = vec![detail_type(&"t".repeat(256))];
    config.validate().expect("256 characters validate");
}

#[test]
fn a_detail_type_description_is_short_and_printable() {
    for description in [" ", &"d".repeat(121), "line\nbreak"] {
        let mut config = base();
        authz(&mut config).authorization_details.types = vec![AuthorizationDetailsTypeConfig {
            description: Some(description.to_owned()),
            ..detail_type("mcp_tool")
        }];
        refused(&config, "types[0].description must be 1 to 120");
    }
}

#[test]
fn detail_allowlists_name_at_least_one_value() {
    for (field, empty) in [
        ("actions", vec![]),
        ("datatypes", vec![String::new()]),
        ("privileges", vec![]),
    ] {
        let mut rule = detail_type("mcp_tool");
        match field {
            "actions" => rule.actions = Some(empty),
            "datatypes" => rule.datatypes = Some(empty),
            _ => rule.privileges = Some(empty),
        }
        let mut config = base();
        authz(&mut config).authorization_details.types = vec![rule];
        refused(
            &config,
            &format!("types[0].{field} must list at least one value"),
        );
    }
}

#[test]
fn a_detail_schema_is_compiled_with_the_schema_safety_rules() {
    let with_schema = |schema: serde_json::Value| {
        let mut config = base();
        authz(&mut config).authorization_details.types = vec![AuthorizationDetailsTypeConfig {
            schema: Some(schema),
            ..detail_type("mcp_tool")
        }];
        config
    };
    with_schema(serde_json::json!({
        "type": "object",
        "properties": { "tools": { "type": "array", "items": { "type": "string" } } },
    }))
    .validate()
    .expect("a local schema validates");
    refused(
        &with_schema(serde_json::json!({ "type": "no-such-type" })),
        "types[0].schema is not a valid JSON Schema",
    );
    refused(
        &with_schema(serde_json::json!({ "$ref": "https://schemas.example/tool.json" })),
        "types[0].schema",
    );
}

#[test]
fn max_entries_is_bounded() {
    for max in [0, 65] {
        let mut config = base();
        authz(&mut config).authorization_details.max_entries = max;
        refused(
            &config,
            "authorization_details.max_entries must be between 1 and 64",
        );
    }
    for max in [1, 64] {
        let mut config = base();
        authz(&mut config).authorization_details.max_entries = max;
        config.validate().expect("the bounds validate");
    }
}
