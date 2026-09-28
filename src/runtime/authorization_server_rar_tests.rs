//! Rich Authorization Requests (RFC 9396): each rule an
//! `authorization_details` array must pass, and that no refusal names a
//! value; the narrowing a token request may apply (§6); the details of an
//! ID-JAG (ID-JAG §4.4.1), echoed in the token response (§7) and carried in
//! the access token (§9.1); the attributes a verified caller carries; the
//! metadata; the audit record and the metrics.

use serde_json::{Value, json};

use super::*;
use crate::config::AuthorizationDetailsConfig;
use crate::runtime::authorization_server::rar::{
    AUTHORIZATION_DETAILS_ATTRIBUTE, AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE, AuthorizationDetails,
    MAX_DETAILS_BYTES, RarSettings,
};

/// A value no refusal or audit record may repeat.
const SENTINEL: &str = "sentinel-value-7f3a";
const RESOURCE: &str = "https://gw.test/mcp";
const CUSTOM_DOMAIN_RESOURCE: &str = "https://mcp.acme.example/mcp";

/// Three types: `mcp_tool` with an action allowlist and resource locations,
/// `payment_initiation` with a schema, allowlists and any location, and
/// `open_type` with no rule but any location.
pub(super) fn details_config() -> AuthorizationDetailsConfig {
    serde_json::from_value(json!({
        "types": [
            {
                "type": "mcp_tool",
                "description": "Call MCP tools",
                "actions": ["tools/call", "tools/list"],
            },
            {
                "type": "payment_initiation",
                "locations": "any",
                "datatypes": ["iban"],
                "privileges": ["initiate"],
                "schema": {
                    "type": "object",
                    "required": ["instructedAmount"],
                    "properties": {
                        "instructedAmount": {
                            "type": "object",
                            "required": ["currency", "amount"],
                            "properties": {
                                "currency": { "type": "string" },
                                "amount": { "type": "string" },
                            },
                        },
                    },
                },
            },
            { "type": "open_type", "locations": "any" },
        ],
        "max_entries": 4,
    }))
    .expect("the details config parses")
}

fn settings() -> RarSettings {
    RarSettings::from_config(
        &details_config(),
        &[RESOURCE.to_owned(), CUSTOM_DOMAIN_RESOURCE.to_owned()],
    )
    .expect("the settings resolve")
}

fn details(value: Value) -> AuthorizationDetails {
    serde_json::from_value(value).expect("details parse")
}

/// Why `settings()` refuses `value`, which never repeats [`SENTINEL`].
#[track_caller]
fn refused(value: Value) -> String {
    let problem = settings()
        .parse(&value)
        .expect_err("the details must be refused");
    assert!(!problem.contains(SENTINEL), "{problem}");
    problem
}

/// The ID-JAG test server with authorization details on, serving the
/// canonical resource and one custom domain.
pub(super) async fn rar_server() -> AuthorizationServer {
    let mut config = test_config();
    config.authorization_details = details_config();
    test_server_with_metadata(config, &resource_metadata()).await
}

/// An ID-JAG carrying `authorization_details`.
fn assertion_with_details(value: Value) -> String {
    make_id_jag(AssertionOverrides {
        extra: json!({ "authorization_details": value }),
        ..Default::default()
    })
}

/// A token request for `assertion` asking for `requested` details.
fn narrowing_form(assertion: &str, requested: &Value) -> TokenRequestForm {
    TokenRequestForm {
        authorization_details: Some(requested.to_string()),
        ..token_form(assertion)
    }
}

fn tool(actions: &[&str], identifier: &str) -> Value {
    json!({
        "type": "mcp_tool",
        "actions": actions,
        "locations": [RESOURCE],
        "identifier": identifier,
    })
}

#[track_caller]
fn verified(outcome: EmaBearerOutcome) -> EmaVerifiedIdentity {
    match outcome {
        EmaBearerOutcome::Verified(identity) => identity,
        other => panic!("expected Verified, got {}", discriminant_name(&other)),
    }
}

// ---------------------------------------------------------------------------
// The rules (RFC 9396 §5)
// ---------------------------------------------------------------------------

#[test]
fn a_valid_array_parses_in_order() {
    let value = json!([
        tool(&["tools/call"], "search"),
        {
            "type": "payment_initiation",
            "locations": ["https://bank.example/payments"],
            "datatypes": ["iban"],
            "privileges": ["initiate"],
            "instructedAmount": { "currency": "EUR", "amount": "12.00" },
        },
        { "type": "open_type", "locations": ["anything at all"], "identifier": "x" },
    ]);
    let parsed = settings().parse(&value).expect("valid details");
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed.types(),
        ["mcp_tool", "payment_initiation", "open_type"]
    );
    assert_eq!(
        serde_json::to_value(&parsed).expect("serializes"),
        value,
        "kept as given"
    );
}

#[test]
fn the_array_and_its_objects_are_refused_when_malformed() {
    assert!(refused(json!({ "type": "mcp_tool" })).contains("must be a JSON array"));
    assert!(refused(json!(SENTINEL)).contains("must be a JSON array"));
    assert!(refused(json!([])).contains("1 to 4 objects"));
    assert!(refused(json!([SENTINEL])).contains("authorization_details[0] is not a JSON object"));
    assert!(refused(json!([{ "actions": [SENTINEL] }])).contains("[0].type is missing"));
    assert!(refused(json!([{ "type": 7 }])).contains("[0].type is missing or not a string"));
    let unknown = refused(json!([tool(&["tools/call"], "a"), { "type": SENTINEL }]));
    assert!(
        unknown.contains("authorization_details[1].type is not a type this server accepts"),
        "{unknown}"
    );
}

#[test]
fn an_unknown_member_is_refused_without_a_schema() {
    let mut entry = json!({ "type": "open_type" });
    entry[SENTINEL] = json!(SENTINEL);
    let problem = refused(json!([entry]));
    assert!(
        problem.contains("[0] carries a member its type does not define"),
        "{problem}"
    );
    settings()
        .parse(&json!([{ "type": "open_type", "identifier": "i", "privileges": ["p"] }]))
        .expect("every common member is known");
}

#[test]
fn a_schema_admits_its_members_and_refuses_what_breaks_it() {
    let payment = |amount: Value| {
        json!([{
            "type": "payment_initiation",
            "instructedAmount": amount,
            "creditorName": "Merchant",
        }])
    };
    settings()
        .parse(&payment(json!({ "currency": "EUR", "amount": "1.00" })))
        .expect("the schema admits other members");
    let problem = refused(payment(json!({ "currency": SENTINEL })));
    assert!(
        problem.contains("[0] does not satisfy the schema of its type"),
        "{problem}"
    );
    assert!(refused(json!([{ "type": "payment_initiation" }])).contains("schema"));
}

#[test]
fn common_members_have_their_shape() {
    for (member, value, named) in [
        ("actions", json!(SENTINEL), "[0].actions must be an array"),
        ("actions", json!([""]), "[0].actions must be an array"),
        ("actions", json!([1]), "[0].actions must be an array"),
        (
            "locations",
            json!({ "a": SENTINEL }),
            "[0].locations must be an array",
        ),
        ("datatypes", json!([null]), "[0].datatypes must be an array"),
        (
            "privileges",
            json!(vec!["p"; 65]),
            "[0].privileges must be an array of at most 64",
        ),
        (
            "identifier",
            json!(["id"]),
            "[0].identifier must be a string",
        ),
    ] {
        let mut entry = json!({ "type": "open_type" });
        entry[member] = value;
        let problem = refused(json!([entry]));
        assert!(problem.contains(named), "{member}: {problem}");
    }
    let mut entry = json!({ "type": "open_type" });
    entry["privileges"] = json!(vec!["p"; 64]);
    settings()
        .parse(&json!([entry]))
        .expect("64 values are allowed");
}

#[test]
fn values_stay_within_the_allowlists_of_their_type() {
    for (entry, named) in [
        (
            json!({ "type": "mcp_tool", "actions": ["tools/call", SENTINEL] }),
            "[0].actions holds a value its type does not allow",
        ),
        (
            json!({
                "type": "payment_initiation",
                "datatypes": [SENTINEL],
                "instructedAmount": { "currency": "EUR", "amount": "1" },
            }),
            "[0].datatypes holds a value its type does not allow",
        ),
        (
            json!({
                "type": "payment_initiation",
                "privileges": ["initiate", SENTINEL],
                "instructedAmount": { "currency": "EUR", "amount": "1" },
            }),
            "[0].privileges holds a value its type does not allow",
        ),
    ] {
        let problem = refused(json!([entry]));
        assert!(problem.contains(named), "{problem}");
    }
    settings()
        .parse(&json!([{ "type": "open_type", "actions": [SENTINEL] }]))
        .expect("a type without an allowlist takes any action");
}

#[test]
fn locations_name_a_resource_of_this_server_unless_the_type_allows_any() {
    settings()
        .parse(&json!([{
            "type": "mcp_tool",
            "locations": [format!("{RESOURCE}/"), CUSTOM_DOMAIN_RESOURCE],
        }]))
        .expect("the resource identifiers, a trailing slash ignored");
    let problem = refused(json!([{
        "type": "mcp_tool",
        "locations": [RESOURCE, format!("https://{SENTINEL}.example/mcp")],
    }]));
    assert!(
        problem.contains("[0].locations names a location that is not a resource of this server"),
        "{problem}"
    );
    settings()
        .parse(&json!([{ "type": "open_type", "locations": ["https://elsewhere.example"] }]))
        .expect("`any` takes any location");
}

#[test]
fn the_number_of_objects_and_the_size_are_bounded() {
    let five: Vec<Value> = (0..5)
        .map(|n| tool(&["tools/call"], &n.to_string()))
        .collect();
    assert!(refused(json!(five)).contains("1 to 4 objects"));
    let four: Vec<Value> = (0..4)
        .map(|n| tool(&["tools/call"], &n.to_string()))
        .collect();
    settings()
        .parse(&json!(four))
        .expect("max_entries objects are allowed");

    let big = json!([{ "type": "open_type", "identifier": "i".repeat(MAX_DETAILS_BYTES) }]);
    assert!(refused(big.clone()).contains("exceeds 8192 bytes"));
    let problem = settings()
        .parse_parameter(&big.to_string())
        .expect_err("a parameter over 8 KiB is refused before it is parsed");
    assert!(problem.contains("exceeds 8192 bytes"), "{problem}");
    let problem = settings()
        .parse_parameter(&format!("[{{\"type\": \"{SENTINEL}\""))
        .expect_err("not JSON");
    assert_eq!(problem, "authorization_details is not valid JSON");
}

#[test]
fn a_schema_is_compiled_once_with_the_schema_safety_rules() {
    let mut config = details_config();
    config.types[1].schema = Some(json!({ "$ref": "https://schemas.example/payment.json" }));
    let error = RarSettings::from_config(&config, &[RESOURCE.to_owned()])
        .expect_err("an off-document reference is refused")
        .to_string();
    assert!(error.contains("types[1].schema"), "{error}");
}

// ---------------------------------------------------------------------------
// Narrowing (RFC 9396 §6)
// ---------------------------------------------------------------------------

#[test]
fn a_request_is_covered_by_what_was_granted() {
    let granted = details(json!([
        tool(&["tools/call", "tools/list"], "search"),
        { "type": "open_type", "identifier": "report", "limits": { "rows": 10 } },
    ]));
    let covered = |requested: Value| granted.covers(&details(requested));
    assert!(covered(json!([tool(
        &["tools/call", "tools/list"],
        "search"
    )])));
    assert!(covered(json!([tool(&["tools/list"], "search")])));
    assert!(covered(json!([
        { "type": "open_type", "identifier": "report", "limits": { "rows": 10 } },
        tool(&["tools/call"], "search"),
    ])));
    assert!(covered(json!([
        { "limits": { "rows": 10 }, "identifier": "report", "type": "open_type" }
    ])));

    assert!(!covered(json!([tool(
        &["tools/call", "tools/delete"],
        "search"
    )])));
    assert!(!covered(json!([tool(&["tools/call"], "other")])));
    assert!(!covered(
        json!([{ "type": "open_type", "actions": ["tools/call"] }])
    ));
    assert!(!covered(json!([
        { "type": "open_type", "identifier": "report", "limits": { "rows": 11 } }
    ])));
    assert!(
        !covered(
            json!([{ "type": "mcp_tool", "actions": ["tools/call"], "identifier": "search" }])
        ),
        "leaving out `locations` asks for every location"
    );
    assert!(
        !covered(json!([{ "type": "open_type", "identifier": "report" }])),
        "leaving out a member asks for more"
    );
}

#[test]
fn details_are_described_without_their_values() {
    let parsed = details(json!([
        tool(&["tools/call"], SENTINEL),
        { "type": "open_type" },
        tool(&["tools/list"], "b"),
    ]));
    assert_eq!(parsed.types(), ["mcp_tool", "open_type"]);
    let rendered = format!("{parsed:?}");
    assert!(!rendered.contains(SENTINEL), "{rendered}");
    assert!(rendered.contains("mcp_tool"), "{rendered}");

    let reordered = details(json!([
        { "identifier": SENTINEL, "locations": [RESOURCE], "actions": ["tools/call"], "type": "mcp_tool" },
        { "type": "open_type" },
        tool(&["tools/list"], "b"),
    ]));
    let key = [5u8; 32];
    assert_eq!(parsed.audit_digest(&key), reordered.audit_digest(&key));
    assert!(parsed.audit_digest(&key).starts_with("keyed-blake3:"));
    assert_ne!(
        parsed.audit_digest(&key),
        details(json!([{ "type": "open_type" }])).audit_digest(&key)
    );
    assert_ne!(
        parsed.audit_digest(&key),
        parsed.audit_digest(&[6u8; 32]),
        "the digest depends on the key"
    );
    let form = TokenRequestForm {
        authorization_details: Some(json!([tool(&["tools/call"], SENTINEL)]).to_string()),
        ..Default::default()
    };
    let rendered = format!("{form:?}");
    assert!(!rendered.contains(SENTINEL), "{rendered}");
}

#[test]
fn consent_lines_read_each_object() {
    let parsed = details(json!([
        tool(&["tools/call"], "search"),
        {
            "type": "open_type",
            "datatypes": ["rows"],
            "privileges": ["admin"],
            "extra": "x".repeat(6000),
            "limit": 250_000,
        },
    ]));
    let lines = settings().consent_lines(&parsed);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].label, "Call MCP tools");
    assert_eq!(lines[0].type_name, "mcp_tool");
    assert_eq!(lines[0].actions, ["tools/call"]);
    assert_eq!(lines[0].locations, [RESOURCE]);
    assert_eq!(lines[0].identifier.as_deref(), Some("search"));
    assert_eq!(lines[0].other, None);
    assert_eq!(lines[1].label, "open_type");
    assert_eq!(lines[1].datatypes, ["rows"]);
    assert_eq!(lines[1].privileges, ["admin"]);
    let other = lines[1].other.as_deref().expect("the other members");
    let shown: serde_json::Value = serde_json::from_str(other).expect("the members as JSON");
    assert_eq!(
        shown,
        json!({ "extra": "x".repeat(6000), "limit": 250_000 }),
        "every member whole, however long the one before it"
    );
    assert!(!format!("{:?}", lines[0]).contains("search"));
}

// ---------------------------------------------------------------------------
// ID-JAG redemption (ID-JAG §4.4.1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_assertions_details_are_echoed_and_carried_in_the_token() {
    let server = rar_server().await;
    let granted = json!([
        tool(&["tools/call", "tools/list"], "search"),
        { "type": "open_type", "identifier": "report" },
    ]);
    let redemption = server
        .redeem(token_form(&assertion_with_details(granted.clone())), None)
        .await;
    let (response, issued) = redemption.result.as_ref().expect("redeemed");
    let body = serde_json::to_value(response).expect("serializes");
    assert_eq!(body["authorization_details"], granted);
    assert_eq!(
        minted_claims(&response.access_token)["authorization_details"],
        granted
    );
    assert_eq!(
        issued.authorization_details.types(),
        ["mcp_tool", "open_type"]
    );

    let identity = verified(server.verify_bearer(&response.access_token));
    assert_eq!(
        identity.attributes[AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE],
        "mcp_tool open_type"
    );
    let attribute: Value =
        serde_json::from_str(&identity.attributes[AUTHORIZATION_DETAILS_ATTRIBUTE])
            .expect("compact JSON");
    assert_eq!(attribute, granted);
}

#[tokio::test]
async fn a_token_request_narrows_the_assertions_details() {
    let server = rar_server().await;
    let assertion = assertion_with_details(json!([
        tool(&["tools/call", "tools/list"], "search"),
        { "type": "open_type", "identifier": "report" },
    ]));
    let requested = json!([tool(&["tools/list"], "search")]);
    let redemption = server
        .redeem(narrowing_form(&assertion, &requested), None)
        .await;
    let (response, _) = redemption.result.as_ref().expect("narrowed");
    assert_eq!(
        serde_json::to_value(response).expect("serializes")["authorization_details"],
        requested
    );
    assert_eq!(
        minted_claims(&response.access_token)["authorization_details"],
        requested
    );
}

#[tokio::test]
async fn a_request_for_more_than_the_assertion_grants_is_refused_and_leaves_it_redeemable() {
    let server = rar_server().await;
    let assertion = assertion_with_details(json!([tool(&["tools/list"], "search")]));
    for (requested, named) in [
        (
            json!([tool(&["tools/call"], "search")]).to_string(),
            "exceed what was granted",
        ),
        (
            json!([{ "type": SENTINEL }]).to_string(),
            "[0].type is not a type this server accepts",
        ),
        ("not json".to_owned(), "not valid JSON"),
    ] {
        let form = TokenRequestForm {
            authorization_details: Some(requested),
            ..token_form(&assertion)
        };
        let error = server
            .handle_token_request(form, None)
            .await
            .expect_err("more than granted");
        assert_eq!(error.error, "invalid_authorization_details");
        assert_eq!(error.status, 400);
        assert!(error.description.contains(named), "{}", error.description);
        assert!(!error.description.contains(SENTINEL));
    }
    redeem(&server, &assertion)
        .await
        .expect("a refused narrowing does not spend the assertion");
}

#[tokio::test]
async fn a_request_for_details_the_assertion_does_not_carry_is_refused() {
    let server = rar_server().await;
    let form = narrowing_form(
        &make_id_jag(AssertionOverrides::default()),
        &json!([tool(&["tools/list"], "search")]),
    );
    let error = server
        .handle_token_request(form, None)
        .await
        .expect_err("nothing to narrow");
    assert_eq!(error.error, "invalid_authorization_details");
    assert!(error.description.contains("no authorization_details"));
}

#[tokio::test]
async fn an_assertion_with_invalid_details_is_an_invalid_grant() {
    let server = rar_server().await;
    for (claim, named) in [
        (json!([{ "type": SENTINEL }]), "[0].type is not a type"),
        (json!({ "type": "mcp_tool" }), "must be a JSON array"),
        (json!([]), "1 to 4 objects"),
        (
            json!([{ "type": "mcp_tool", "actions": ["tools/delete"] }]),
            "[0].actions holds a value",
        ),
    ] {
        let error = redeem(&server, &assertion_with_details(claim))
            .await
            .expect_err("the assertion's details are refused, not dropped");
        assert_eq!(error.error, "invalid_grant");
        assert!(
            error
                .description
                .starts_with("the assertion's authorization_details"),
            "{}",
            error.description
        );
        assert!(error.description.contains(named), "{}", error.description);
        assert!(!error.description.contains(SENTINEL));
    }
}

#[tokio::test]
async fn with_no_type_configured_the_claim_is_refused_and_the_parameter_ignored() {
    let server = test_server().await;
    let error = redeem(
        &server,
        &assertion_with_details(json!([tool(&["tools/call"], "search")])),
    )
    .await
    .expect_err("RFC 9396 is off");
    assert_eq!(error.error, "invalid_grant");
    assert_eq!(
        error.description,
        "the assertion carries authorization_details, which this authorization server does not \
         support (RFC 9396)"
    );
    let response = server
        .handle_token_request(
            narrowing_form(
                &make_id_jag(AssertionOverrides::default()),
                &json!([tool(&["tools/call"], "search")]),
            ),
            None,
        )
        .await
        .expect("an unknown parameter is ignored");
    let body = serde_json::to_value(&response).expect("serializes");
    assert!(body.get("authorization_details").is_none(), "{body}");
    assert!(
        minted_claims(&response.access_token)
            .get("authorization_details")
            .is_none()
    );
    assert!(
        server
            .metadata()
            .get("authorization_details_types_supported")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

/// The attributes come only from the token's own claim: a mapped attribute
/// of the same name is dropped.
#[tokio::test]
async fn the_details_attributes_cannot_be_carried_by_mapped_attributes() {
    let server = rar_server().await;
    let now = now_unix();
    let claims = MintedClaims {
        iss: GW_ISSUER.to_owned(),
        sub: "user-42".to_owned(),
        aud: RESOURCE.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp: now + 600,
        idp: IDP_ISSUER.to_owned(),
        attributes: BTreeMap::from([
            (
                AUTHORIZATION_DETAILS_ATTRIBUTE.to_owned(),
                json!([tool(&["tools/call"], "spoofed")]).to_string(),
            ),
            (
                AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_owned(),
                "mcp_tool".to_owned(),
            ),
        ]),
        ..MintedClaims::default()
    };
    let token = server.signing_keys[0].sign(&claims).expect("signs");
    let identity = verified(server.verify_bearer(&token));
    assert!(
        !identity
            .attributes
            .contains_key(AUTHORIZATION_DETAILS_ATTRIBUTE)
            && !identity
                .attributes
                .contains_key(AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE),
        "{:?}",
        identity.attributes
    );
    for reserved in [
        AUTHORIZATION_DETAILS_ATTRIBUTE,
        AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE,
    ] {
        assert!(IDENTITY_ATTRIBUTES.contains(&reserved));
    }
}

/// An audit record carries the caller's details attribute only as the
/// digest the issuance record names, keyed from the signing key: replicas
/// sharing the key agree, and another key digests differently.
#[tokio::test]
async fn audit_records_carry_the_details_attribute_as_the_issued_digest() {
    use mcpg_plugin_host::audit_events::{
        DIGESTED_ACTOR_ATTRIBUTES, system_identity, tool_call_unknown_event,
        with_digested_actor_attributes,
    };
    assert!(DIGESTED_ACTOR_ATTRIBUTES.contains(&AUTHORIZATION_DETAILS_ATTRIBUTE));
    let server = rar_server().await;
    let replica = rar_server().await;
    assert_eq!(*server.audit_digest_key(), *replica.audit_digest_key());
    let mut other = test_config();
    other.signing_secret = Some("another-transport-signing-secret-0123".to_owned());
    let other = test_server_with_metadata(other, &resource_metadata()).await;
    assert_ne!(*server.audit_digest_key(), *other.audit_digest_key());

    let parsed = details(json!([tool(&["tools/call"], SENTINEL)]));
    let event = tool_call_unknown_event(&mcpg_plugin_protocol::PluginContext {
        request_id: "req-rar".into(),
        session_id: None,
        tool_name: "deploy".into(),
        surface: "tool".into(),
        identity: mcpg_plugin_protocol::PluginIdentity {
            attributes: BTreeMap::from([(
                AUTHORIZATION_DETAILS_ATTRIBUTE.to_owned(),
                parsed.to_json(),
            )]),
            ..system_identity()
        },
        transport: "http".into(),
    });
    let key = server.audit_digest_key();
    let digested = with_digested_actor_attributes(&event, Some(&key)).expect("digested");
    assert_eq!(
        Some(&digested.actor.attributes[AUTHORIZATION_DETAILS_ATTRIBUTE]),
        server.details_digest(&parsed).as_ref()
    );
    let recorded = serde_json::to_string(&digested).expect("serializes");
    assert!(!recorded.contains(SENTINEL), "{recorded}");
}

/// A restriction outlives a change of the configuration: a token limited
/// to details still carries them after the types are removed.
#[tokio::test]
async fn a_token_keeps_its_details_after_the_types_are_removed() {
    let server = rar_server().await;
    let response = redeem(
        &server,
        &assertion_with_details(json!([tool(&["tools/call"], "search")])),
    )
    .await
    .expect("redeemed");
    let off = test_server_with_metadata(test_config(), &resource_metadata()).await;
    let identity = verified(off.verify_bearer(&response.access_token));
    assert_eq!(
        identity.attributes[AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE],
        "mcp_tool"
    );
}

// ---------------------------------------------------------------------------
// Metadata, audit and metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_metadata_names_the_types_only_while_they_are_configured() {
    let server = rar_server().await;
    assert_eq!(
        server.metadata()["authorization_details_types_supported"],
        json!(["mcp_tool", "payment_initiation", "open_type"])
    );
    assert!(server.authorization_details_enabled());
    let off = test_server().await;
    assert!(!off.authorization_details_enabled());
    assert!(
        off.metadata()
            .get("authorization_details_types_supported")
            .is_none()
    );
}

#[tokio::test]
async fn the_issued_record_names_the_types_and_a_digest_but_no_value() {
    let server = rar_server().await;
    let granted = json!([tool(&["tools/call"], SENTINEL)]);
    let redemption = server
        .redeem(token_form(&assertion_with_details(granted.clone())), None)
        .await;
    let event = redemption.audit_event("req-rar");
    assert_eq!(event.action, "mcpg.ema.token_issued");
    assert_eq!(
        event.details["authorization_details_types"],
        json!(["mcp_tool"])
    );
    assert_eq!(
        event.details["authorization_details_digest"],
        json!(details(granted).audit_digest(&server.audit_digest_key()))
    );
    let recorded = serde_json::to_string(&event).expect("serializes");
    assert!(!recorded.contains(SENTINEL), "{recorded}");

    let refused = server
        .redeem(
            token_form(&assertion_with_details(json!([{ "type": SENTINEL }]))),
            None,
        )
        .await
        .audit_event("req-rar-2");
    assert_eq!(refused.action, "mcpg.auth.failed");
    let recorded = serde_json::to_string(&refused).expect("serializes");
    assert!(!recorded.contains(SENTINEL), "{recorded}");

    let plain = test_server()
        .await
        .redeem(
            token_form(&make_id_jag(AssertionOverrides::default())),
            None,
        )
        .await
        .audit_event("req-plain");
    assert_eq!(plain.details["authorization_details_types"], json!([]));
    assert!(plain.details["authorization_details_digest"].is_null());
}

#[tokio::test]
async fn details_are_counted_by_source_and_outcome() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = rar_server().await;
    let granted = json!([tool(&["tools/call", "tools/list"], "search")]);
    let _ = server
        .redeem(token_form(&assertion_with_details(granted.clone())), None)
        .await;
    let _ = server
        .redeem(
            narrowing_form(
                &assertion_with_details(granted.clone()),
                &json!([tool(&["tools/list"], "search")]),
            ),
            None,
        )
        .await;
    let _ = server
        .redeem(
            token_form(&assertion_with_details(json!([{ "type": "nope" }]))),
            None,
        )
        .await;
    for metric in [
        "mcpg_as_authorization_details_total{source=id_jag,outcome=granted}",
        "mcpg_as_authorization_details_total{source=id_jag,outcome=narrowed}",
        "mcpg_as_authorization_details_total{source=id_jag,outcome=refused}",
        "mcpg_ema_token_requests_total{outcome=refused,error=invalid_grant,idp=https://idp.test,grant=jwt_bearer}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}

/// A record without details reads as unlimited, and a record without
/// details omits the member when written.
#[test]
fn records_without_details_read_as_unlimited_and_omit_the_member() {
    use crate::runtime::authorization_server::state::{CodeRecord, GrantRecord};
    let grant: GrantRecord = serde_json::from_value(json!({
        "status": "active",
        "principal": "p",
        "identity": { "subject": "s", "idp": "https://idp.test" },
        "client_id": "desktop",
        "client_kind": "static",
        "resource": RESOURCE,
        "redirect_uri": "http://127.0.0.1/cb",
        "issuer": GW_ISSUER,
        "abs_exp": 2,
        "last_used": 1,
        "generation": 1,
        "created": 1,
    }))
    .expect("an older grant record reads");
    assert!(grant.authorization_details.is_empty());
    assert!(
        serde_json::to_value(&grant)
            .expect("serializes")
            .get("authorization_details")
            .is_none()
    );
    let code: CodeRecord = serde_json::from_value(json!({
        "client_id": "desktop",
        "redirect_uri": "http://127.0.0.1/cb",
        "code_challenge": "c".repeat(43),
        "resource": RESOURCE,
        "gid": "0123456789abcdef0123456789abcdef",
        "exp": 2,
    }))
    .expect("an older code record reads");
    assert!(code.authorization_details.is_empty());
}
