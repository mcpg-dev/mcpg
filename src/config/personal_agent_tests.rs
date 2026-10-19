use super::*;
use crate::config::AppConfig;

/// A resource that verifies a Company's Session Tokens with `jwks`, with
/// `personal_agent` set to `block`.
fn with(block: &str) -> AppConfig {
    let yaml = format!(
        "governance:\n  access:\n    jwks:\n      url: https://auth.example.com/jwks\n      \
         issuer: https://auth.example.com\n      audience: https://mcp.example.com/mcp\n    \
         personal_agent: {block}\n"
    );
    serde_yaml::from_str(&yaml).expect("test config parses")
}

#[track_caller]
fn refused(block: &str, named: &str) {
    let error = with(block)
        .validate()
        .expect_err("the config must be refused")
        .to_string();
    assert!(error.contains(named), "{error}");
}

#[test]
fn an_empty_block_has_the_documented_defaults() {
    let config = with("{}");
    config.validate().expect("validates");
    let block = config
        .governance
        .access
        .personal_agent
        .expect("personal_agent");
    assert_eq!(block.attributes, PersonalAgentAttributes::default());
    assert_eq!(block.attributes.client_id, "client_id");
    assert_eq!(block.attributes.signed_in, "signed_in");
    assert_eq!(
        block.agent_extensions.source,
        AgentExtensionsSource::ClientMetadata
    );
    assert_eq!(block.agent_extensions.cache_secs, 3_600);
    assert!(block.require_extensions.is_empty());
    assert!(block.discovery.is_none());
}

#[test]
fn it_needs_a_verifier_of_the_companys_tokens() {
    let config: AppConfig =
        serde_yaml::from_str("governance:\n  access:\n    personal_agent: {}\n").expect("parses");
    let error = config.validate().expect_err("refused").to_string();
    assert!(error.contains("needs `oidc_oauth` or `jwks`"), "{error}");
}

#[test]
fn extension_names_are_plain_or_start_with_a_domain() {
    for good in ["operations", "gift_wrap-2", "example.com/gift-wrap"] {
        assert!(valid_extension_name(good), "{good}");
    }
    for bad in [
        "",
        "two words",
        "example/x",
        "example.com/",
        "/x",
        "ex_ample.com/x",
    ] {
        assert!(!valid_extension_name(bad), "{bad}");
    }
    with("{ require_extensions: [operations, example.com/gift-wrap] }")
        .validate()
        .expect("validates");
    refused(
        "{ require_extensions: [\"no way\"] }",
        "is not an extension name",
    );
    refused(
        "{ require_extensions: [operations, operations] }",
        "more than once",
    );
    refused(
        "{ require_extensions: [operations], agent_extensions: { source: none } }",
        "every Personal Agent would be refused",
    );
}

#[test]
fn the_cache_and_attribute_names_are_checked() {
    refused(
        "{ agent_extensions: { cache_secs: 10 } }",
        "cache_secs must be between 60 and 86400",
    );
    refused(
        "{ attributes: { account: \" \" } }",
        "attributes.account must name an identity attribute",
    );
    refused(
        "{ agent_extensions: { source: attribute, attribute: \"\" } }",
        "agent_extensions.attribute must name",
    );
    let unknown = serde_yaml::from_str::<PersonalAgentConfig>("{ attributes: { unknown: x } }")
        .expect_err("an unknown key is refused")
        .to_string();
    assert!(unknown.contains("unknown field `unknown`"), "{unknown}");
}

#[test]
fn the_discovery_document_is_checked() {
    let good = r#"{ discovery: { document: {
        protocol_version: "0.2",
        organization: { name: Example, domain: example.com },
        auth: { issuer: "https://auth.example.com" },
        apis: [ { type: mcp, url: "https://mcp.example.com/mcp", description: Search } ] } } }"#;
    with(good).validate().expect("validates");

    refused(
        r#"{ discovery: { document: [] } }"#,
        "document must be a JSON object",
    );
    refused(
        r#"{ discovery: { document: { protocol_version: "1.0", organization: { name: E, domain: e.com } } } }"#,
        "is not a 0.x version",
    );
    refused(
        r#"{ discovery: { document: { protocol_version: "0.2", organization: { name: E } } } }"#,
        "organization.domain must be a non-empty string",
    );
    refused(
        r#"{ discovery: { document: { protocol_version: "0.2", organization: { name: E, domain: "https://e.com" } } } }"#,
        "must be a host name",
    );
    refused(
        r#"{ discovery: { document: { protocol_version: "0.2", organization: { name: E, domain: e.com }, auth: { issuer: "http://auth.e.com" } } } }"#,
        "auth.issuer `http://auth.e.com` must be an https URL",
    );
    refused(
        r#"{ discovery: { document: { protocol_version: "0.2", organization: { name: E, domain: e.com }, apis: [ { type: mcp } ] } } }"#,
        "apis[0].url must be an https URL",
    );
}

/// A resource at `https://mcp.example.com/mcp` that takes the Company's
/// tokens with DPoP when `dpop`, with `personal_agent` set to `block`.
fn with_resource(block: &str, dpop: bool) -> AppConfig {
    let yaml = format!(
        "governance:\n  access:\n    jwks:\n      url: https://auth.example.com/jwks\n      \
         issuer: https://auth.example.com\n      audience: https://mcp.example.com/mcp\n    \
         resource_metadata:\n      resource: https://mcp.example.com/mcp\n    dpop: {{ enabled: \
         {dpop} }}\n    personal_agent: {block}\n"
    );
    serde_yaml::from_str(&yaml).expect("test config parses")
}

const OPERATIONS: &str = r#"{ operations: { endpoint: "https://mcp.example.com/poppy/operations",
    tools: [ { tool: refund, summary: "Refund order ${arguments.order_id}.",
               action_key: "${arguments.order_id}" } ] } }"#;

#[test]
fn operations_have_the_documented_defaults() {
    let config = with_resource(OPERATIONS, true);
    config.validate().expect("validates");
    let operations = config
        .governance
        .access
        .personal_agent
        .and_then(|block| block.operations)
        .expect("operations");
    assert_eq!(
        operations.without_extension,
        OperationsWithoutExtension::Perform
    );
    assert_eq!(operations.confirm_wait_secs, 5);
    assert_eq!(operations.retain_final_secs, 7 * 86_400);
    assert_eq!(operations.tools[0].expires_after_secs, 900);
    assert!(!operations.tools[0].user_approval_required);
}

#[track_caller]
fn operations_refused(operations: &str, named: &str) {
    let block = format!("{{ operations: {operations} }}");
    let error = with_resource(&block, true)
        .validate()
        .expect_err("the config must be refused")
        .to_string();
    assert!(error.contains(named), "{error}");
}

#[test]
fn the_operations_block_is_checked() {
    let tools = r#"tools: [ { tool: refund, summary: "Refund." } ]"#;
    operations_refused(
        &format!(r#"{{ endpoint: "http://mcp.example.com/poppy/operations", {tools} }}"#),
        "must be an https URL whose path is `/poppy/operations`",
    );
    operations_refused(
        &format!(r#"{{ endpoint: "https://mcp.example.com/ops", {tools} }}"#),
        "must be an https URL whose path is `/poppy/operations`",
    );
    operations_refused(
        &format!(r#"{{ endpoint: "https://other.example.com/poppy/operations", {tools} }}"#),
        "must be on the origin of a resource_metadata resource",
    );
    operations_refused(
        r#"{ endpoint: "https://mcp.example.com/poppy/operations", tools: [] }"#,
        "tools must list at least one tool",
    );
    operations_refused(
        r#"{ endpoint: "https://mcp.example.com/poppy/operations",
             tools: [ { tool: refund, summary: "A." }, { tool: refund, summary: "B." } ] }"#,
        "lists `refund` more than once",
    );
    operations_refused(
        r#"{ endpoint: "https://mcp.example.com/poppy/operations",
             tools: [ { tool: refund, summary: "A.", expires_after_secs: 30 } ] }"#,
        "expires_after_secs must be between 60 and 86400",
    );
    operations_refused(
        &format!(
            r#"{{ endpoint: "https://mcp.example.com/poppy/operations", {tools}, confirm_wait_secs: 0 }}"#
        ),
        "confirm_wait_secs must be between 1 and 30",
    );
    operations_refused(
        r#"{ endpoint: "https://mcp.example.com/poppy/operations",
             tools: [ { tool: refund, summary: "Token ${cred://vault/refund-key}" } ] }"#,
        "summary may not name a `cred://` reference",
    );

    let error = with_resource(OPERATIONS, false)
        .validate()
        .expect_err("operations need DPoP")
        .to_string();
    assert!(error.contains("takes DPoP Session Tokens only"), "{error}");
}

#[test]
fn poppy_json_lists_the_operations_endpoint() {
    let document = r#"discovery: { document: {
        protocol_version: "0.2",
        organization: { name: Example, domain: example.com } } }"#;
    let block = format!("{{ {document}, {} }}", &OPERATIONS[1..OPERATIONS.len() - 1]);
    let config = with_resource(&block, true);
    config.validate().expect("validates");
    let served = config
        .governance
        .access
        .personal_agent
        .and_then(|block| block.poppy_document())
        .expect("a document");
    assert_eq!(
        served["extensions"]["operations"],
        serde_json::json!({
            "version": "1",
            "endpoint": "https://mcp.example.com/poppy/operations",
        })
    );

    let listed = r#"discovery: { document: {
        protocol_version: "0.2",
        organization: { name: Example, domain: example.com },
        extensions: { operations: { version: "1", endpoint: "https://mcp.example.com/poppy/operations" },
                      "example.com/gift-wrap": { version: "2" } } } }"#;
    let block = format!("{{ {listed}, {} }}", &OPERATIONS[1..OPERATIONS.len() - 1]);
    let config = with_resource(&block, true);
    config.validate().expect("a matching entry validates");
    let served = config
        .governance
        .access
        .personal_agent
        .and_then(|block| block.poppy_document())
        .expect("a document");
    assert_eq!(
        served["extensions"]["example.com/gift-wrap"]["version"],
        "2"
    );

    let wrong = r#"discovery: { document: {
        protocol_version: "0.2",
        organization: { name: Example, domain: example.com },
        extensions: { operations: { version: "1", endpoint: "https://mcp.example.com/elsewhere" } } } }"#;
    let block = format!("{{ {wrong}, {} }}", &OPERATIONS[1..OPERATIONS.len() - 1]);
    let error = with_resource(&block, true)
        .validate()
        .expect_err("a different endpoint is refused")
        .to_string();
    assert!(error.contains("extensions.operations must be"), "{error}");
}
