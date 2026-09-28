//! The identity an ID-JAG yields: claim mappings, the actor, tenant and
//! `amr`, per-client roles and the principal alias.

use super::*;
use crate::config::TrustedIdpClaimMappingConfig;
use crate::runtime::policy::{
    PreDispatchPolicyGate, PreDispatchPolicyOutcome, ToolAccessPolicyConfig, ToolPolicyContext,
};
use crate::runtime::{GatewayRequestId, RequestContext, RequestIdentity, TransportKind};

const SSO_ISSUER: &str = "https://idp.test/oauth2/default";

fn mappings(
    group_claim_paths: &[&str],
    role_claim_paths: &[&str],
    attributes: &[(&str, &str)],
) -> TrustedIdpClaimMappingConfig {
    TrustedIdpClaimMappingConfig {
        group_claim_paths: group_claim_paths.iter().map(|p| (*p).to_owned()).collect(),
        role_claim_paths: role_claim_paths.iter().map(|p| (*p).to_owned()).collect(),
        attribute_claim_mappings: attributes
            .iter()
            .map(|(claim, attribute)| ((*claim).to_owned(), (*attribute).to_owned()))
            .collect(),
        ..Default::default()
    }
}

fn config_with_mappings(claim_mappings: TrustedIdpClaimMappingConfig) -> AuthorizationServerConfig {
    let mut config = test_config();
    config.trusted_idps[0].claim_mappings = claim_mappings;
    config
}

fn assertion_with(extra: serde_json::Value) -> String {
    make_id_jag(AssertionOverrides {
        extra,
        ..Default::default()
    })
}

/// Redeem `assertion` and verify the minted token, as `/mcp` would.
async fn caller(server: &AuthorizationServer, assertion: &str) -> EmaVerifiedIdentity {
    let token = redeem(server, assertion)
        .await
        .expect("redemption succeeds");
    verified(server, &token.access_token)
}

fn verified(server: &AuthorizationServer, token: &str) -> EmaVerifiedIdentity {
    match server.verify_bearer(token) {
        EmaBearerOutcome::Verified(identity) => identity,
        other => panic!("expected Verified, got {}", discriminant_name(&other)),
    }
}

/// The request identity the transport builds from a verified EMA token.
fn request_identity(identity: EmaVerifiedIdentity) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: identity.subject_id,
        issuer: identity.issuer,
        auth_provider: identity.auth_provider,
        source: crate::runtime::EMA_ACCESS_TOKEN_SOURCE.to_owned(),
        roles: identity.roles,
        groups: identity.groups,
        scopes: identity.scopes,
        attributes: identity.attributes,
    }
}

/// The request identity an `oidc_oauth` provider reports for `subject`.
fn sso_identity(issuer: &str, subject: &str) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: subject.to_owned(),
        issuer: issuer.to_owned(),
        auth_provider: format!("oidc_oauth:{issuer}"),
        source: "authorization:oidc_oauth".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: BTreeMap::new(),
    }
}

/// Whether the tool-access gate with global `cel_allow_if` admits `identity`.
fn admitted_by(cel_allow_if: &str, identity: RequestIdentity) -> bool {
    let gate = PreDispatchPolicyGate::try_new(ToolAccessPolicyConfig {
        default_minimum_trust: crate::runtime::RequestTrustLevel::Verified,
        cel_allow_if: Some(cel_allow_if.to_owned()),
        rules: Vec::new(),
    })
    .expect("policy compiles");
    let context = RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        identity,
        TransportKind::Http,
    );
    matches!(
        gate.evaluate_tool_call(&ToolPolicyContext::from_request_context(&context, "deploy")),
        PreDispatchPolicyOutcome::Allow
    )
}

// ── claim mappings ───────────────────────────────────────────────────

#[tokio::test]
async fn mapped_groups_roles_and_attributes_reach_the_caller() {
    let server = test_server_with(config_with_mappings(mappings(
        &["groups"],
        &["realm_access.roles"],
        &[("department", "department"), ("acr", "acr")],
    )))
    .await;
    let identity = caller(
        &server,
        &assertion_with(serde_json::json!({
            "groups": ["eng", "ops", "eng"],
            "realm_access": { "roles": "reader writer" },
            "department": "R&D",
            "acr": "phr",
        })),
    )
    .await;
    assert_eq!(identity.groups, ["eng", "ops"]);
    assert_eq!(identity.roles, ["reader", "writer"]);
    assert_eq!(identity.attributes["department"], "R&D");
    assert_eq!(identity.attributes["acr"], "phr");
    assert_eq!(identity.subject_id, "user-42");
    assert_eq!(identity.auth_provider, "ema");
}

/// Group-based policy works for an EMA caller once the IdP's groups are
/// mapped, and not before.
#[tokio::test]
async fn a_cel_rule_on_mapped_groups_admits_the_caller() {
    let assertion = || assertion_with(serde_json::json!({ "groups": ["eng"] }));
    let rule = r#""eng" in identity.groups"#;

    let mapped = test_server_with(config_with_mappings(mappings(&["groups"], &[], &[]))).await;
    assert!(admitted_by(
        rule,
        request_identity(caller(&mapped, &assertion()).await)
    ));

    let unmapped = test_server().await;
    let identity = caller(&unmapped, &assertion()).await;
    assert!(identity.groups.is_empty());
    assert!(!admitted_by(rule, request_identity(identity)));
}

/// Mapped values travel in the minted token under their standard names;
/// claims no mapping names stay behind.
#[tokio::test]
async fn the_minted_token_carries_only_mapped_claims() {
    let server = test_server_with(config_with_mappings(mappings(
        &["groups"],
        &["roles"],
        &[("department", "department")],
    )))
    .await;
    let token = redeem(
        &server,
        &assertion_with(serde_json::json!({
            "groups": ["eng"],
            "roles": ["reader"],
            "department": "R&D",
            "salary_band": "7",
        })),
    )
    .await
    .expect("redemption succeeds");
    let claims = minted_claims(&token.access_token);
    assert_eq!(claims["groups"], serde_json::json!(["eng"]));
    assert_eq!(claims["roles"], serde_json::json!(["reader"]));
    assert_eq!(
        claims["mcpg_attributes"],
        serde_json::json!({ "department": "R&D" })
    );
    assert!(claims.get("salary_band").is_none());

    let plain = test_server().await;
    let token = redeem(
        &plain,
        &assertion_with(serde_json::json!({ "groups": ["eng"] })),
    )
    .await
    .expect("redemption succeeds");
    let claims = minted_claims(&token.access_token);
    for absent in ["groups", "roles", "mcpg_attributes", "act", "tenant", "amr"] {
        assert!(claims.get(absent).is_none(), "{absent}: {claims}");
    }
}

#[tokio::test]
async fn subject_claim_chooses_the_subject() {
    let mut claim_mappings = mappings(&[], &[], &[]);
    claim_mappings.subject_claim = "email".to_owned();
    let server = test_server_with(config_with_mappings(claim_mappings)).await;
    let identity = caller(&server, &assertion_with(serde_json::json!({}))).await;
    assert_eq!(identity.subject_id, "user@acme.test");

    let mut claim_mappings = mappings(&[], &[], &[]);
    claim_mappings.subject_claim = "uid".to_owned();
    let server = test_server_with(config_with_mappings(claim_mappings)).await;
    let err = redeem(&server, &assertion_with(serde_json::json!({})))
        .await
        .expect_err("an assertion without the subject claim names no user");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("`uid`"), "{}", err.description);

    let err = redeem(&server, &assertion_with(serde_json::json!({ "uid": " " })))
        .await
        .expect_err("a blank subject names no user");
    assert_eq!(err.error, "invalid_grant");

    let identity = caller(
        &server,
        &assertion_with(serde_json::json!({ "uid": "00u42" })),
    )
    .await;
    assert_eq!(identity.subject_id, "00u42");
}

// ── actor, tenant and authentication methods ─────────────────────────

/// ID-JAG §9.7: the actor stays apart from the subject.
#[tokio::test]
async fn act_names_the_actor_and_never_the_subject() {
    let server = test_server().await;
    let token = redeem(
        &server,
        &assertion_with(serde_json::json!({
            "act": { "sub": "agent-9", "act": { "sub": "orchestrator" } },
        })),
    )
    .await
    .expect("redemption succeeds");
    let identity = verified(&server, &token.access_token);
    assert_eq!(identity.subject_id, "user-42");
    assert_eq!(identity.attributes["actor"], "agent-9");
    assert_eq!(
        minted_claims(&token.access_token)["act"],
        serde_json::json!({ "sub": "agent-9", "act": { "sub": "orchestrator" } })
    );
    assert!(admitted_by(
        r#"identity.attributes["actor"] == "agent-9" && principal_id == "user-42""#,
        request_identity(identity)
    ));

    let direct = caller(&server, &assertion_with(serde_json::json!({}))).await;
    assert!(!direct.attributes.contains_key("actor"));
}

/// An actor the gateway cannot name is refused, never passed off as the
/// user acting directly.
#[tokio::test]
async fn an_actor_without_a_subject_is_refused() {
    let server = test_server().await;
    for act in [
        serde_json::json!("agent-9"),
        serde_json::json!({}),
        serde_json::json!({ "sub": "" }),
        serde_json::json!({ "sub": 9 }),
        serde_json::Value::Null,
    ] {
        let err = redeem(&server, &assertion_with(serde_json::json!({ "act": act })))
            .await
            .expect_err("a malformed act is refused");
        assert_eq!(err.error, "invalid_grant");
        assert!(err.description.contains("act"), "{}", err.description);
    }
}

#[tokio::test]
async fn tenant_and_amr_become_attributes() {
    let server = test_server().await;
    let identity = caller(
        &server,
        &assertion_with(serde_json::json!({
            "tenant": "acme",
            "amr": ["pwd", "mfa", "mfa", 7],
        })),
    )
    .await;
    assert_eq!(identity.attributes["tenant"], "acme");
    assert_eq!(identity.attributes["amr"], "pwd mfa");
    assert!(admitted_by(
        r#"identity.attributes["amr"].matches("(^| )mfa( |$)")"#,
        request_identity(identity)
    ));

    let identity = caller(
        &server,
        &assertion_with(serde_json::json!({ "tenant": 7, "amr": "mfa" })),
    )
    .await;
    assert!(!identity.attributes.contains_key("tenant"));
    assert!(!identity.attributes.contains_key("amr"));
}

/// A multi-tenant IdP's `sub` is unique only within its tenant (ID-JAG
/// §3): two tenants' users with one `sub` are two principals, unless the
/// IdP is pinned to one tenant.
#[tokio::test]
async fn the_tenant_joins_the_principal_namespace() {
    let server = test_server().await;
    let in_tenant = |tenant: &str| assertion_with(serde_json::json!({ "tenant": tenant }));
    let acme = caller(&server, &in_tenant("acme")).await;
    let globex = caller(&server, &in_tenant("globex")).await;
    assert_eq!(acme.subject_id, globex.subject_id);
    assert_eq!(acme.issuer, format!("{IDP_ISSUER}#acme"));
    assert_eq!(globex.issuer, format!("{IDP_ISSUER}#globex"));
    assert_eq!(acme.attributes["idp"], IDP_ISSUER);

    let untenanted = caller(&server, &assertion_with(serde_json::json!({}))).await;
    assert_eq!(untenanted.issuer, IDP_ISSUER);

    let mut pinned = test_config();
    pinned.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let pinned = test_server_with(pinned).await;
    assert_eq!(caller(&pinned, &in_tenant("acme")).await.issuer, IDP_ISSUER);
}

/// Every attribute a verified token sets is one mappings may not claim,
/// and the reserved list names nothing a token cannot set: an ID-JAG's
/// Bearer token sets all but the grant id and `auth_time`, which only a
/// token of an interactive sign-in carries, `dpop_jkt`, which only a
/// token presented with a DPoP proof carries, and the two
/// `authorization_details` attributes, which only a token limited to
/// authorization details carries.
#[tokio::test]
async fn the_reserved_attributes_are_the_ones_a_token_sets() {
    let server = signing_in_server().await;
    let identity = caller(
        &server,
        &assertion_with(serde_json::json!({
            "act": { "sub": "agent-9" },
            "tenant": "acme",
            "amr": ["mfa"],
        })),
    )
    .await;
    let set: BTreeSet<&str> = identity.attributes.keys().map(String::as_str).collect();
    let interactive_only = BTreeSet::from(["grant_id", "auth_time"]);
    let proof_only = BTreeSet::from([dpop::DPOP_JKT_ATTRIBUTE]);
    let details_only = BTreeSet::from([
        rar::AUTHORIZATION_DETAILS_ATTRIBUTE,
        rar::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE,
    ]);
    assert_eq!(
        set,
        BTreeSet::from(IDENTITY_ATTRIBUTES)
            .difference(&interactive_only)
            .copied()
            .collect::<BTreeSet<_>>()
            .difference(&proof_only)
            .copied()
            .collect::<BTreeSet<_>>()
            .difference(&details_only)
            .copied()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(identity.attributes["grant_type"], "id_jag");

    let signed_in = verified(&server, &interactive_token(&server, BTreeMap::new()));
    for attribute in interactive_only {
        assert!(
            signed_in.attributes.contains_key(attribute),
            "{attribute}: {:?}",
            signed_in.attributes
        );
    }
    assert_eq!(signed_in.attributes["grant_type"], "authorization_code");
}

/// [`test_server`] keeping the state of interactive sign-in, without which
/// the tokens of interactive grants are refused.
async fn signing_in_server() -> AuthorizationServer {
    test_server().await.with_interactive_state(Some(
        state::InteractiveState::in_memory(GW_ISSUER).expect("state"),
    ))
}

/// A token as the authorization code grant mints it, carrying
/// `attributes` as mapped claims.
fn interactive_token(server: &AuthorizationServer, attributes: BTreeMap<String, String>) -> String {
    let now = now_unix();
    server.signing_keys[0]
        .sign(&MintedClaims {
            iss: GW_ISSUER.to_owned(),
            sub: "user-42".to_owned(),
            aud: GW_ISSUER.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            jti: "minted-2".to_owned(),
            iat: now,
            exp: now + 60,
            idp: IDP_ISSUER.to_owned(),
            attributes,
            gid: Some(state::GrantId::generate().expect("random")),
            gty: Some("authorization_code".to_owned()),
            auth_time: Some(now - 5),
            ..MintedClaims::default()
        })
        .expect("token signs")
}

/// A mapped attribute never replaces one the token sets itself, even in
/// a token whose mapping was not validated.
#[tokio::test]
async fn mapped_attributes_cannot_stand_in_for_the_tokens_own() {
    let server = signing_in_server().await;
    let now = now_unix();
    let token = server.signing_keys[0]
        .sign(&MintedClaims {
            iss: GW_ISSUER.to_owned(),
            sub: "user-42".to_owned(),
            aud: GW_ISSUER.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            jti: "minted-1".to_owned(),
            iat: now,
            exp: now + 60,
            idp: IDP_ISSUER.to_owned(),
            attributes: BTreeMap::from([
                ("client_id".to_owned(), "someone-else".to_owned()),
                ("idp".to_owned(), "https://evil.test".to_owned()),
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("grant_id".to_owned(), "planted".to_owned()),
            ]),
            ..MintedClaims::default()
        })
        .expect("token signs");
    let identity = verified(&server, &token);
    assert_eq!(identity.attributes["client_id"], CLIENT_ID);
    assert_eq!(identity.attributes["idp"], IDP_ISSUER);
    assert_eq!(identity.attributes["grant_type"], "id_jag");
    assert!(!identity.attributes.contains_key("grant_id"));

    let planted = BTreeMap::from([
        ("grant_id".to_owned(), "planted".to_owned()),
        ("auth_time".to_owned(), "0".to_owned()),
    ]);
    let identity = verified(&server, &interactive_token(&server, planted));
    assert_ne!(identity.attributes["grant_id"], "planted");
    assert_ne!(identity.attributes["auth_time"], "0");
}

/// A token that names a grant type this server never issues, or an
/// interactive grant without its id, is refused.
#[tokio::test]
async fn a_token_naming_an_unknown_grant_is_refused() {
    let server = test_server().await;
    let now = now_unix();
    let sign = |gid: Option<state::GrantId>, gty: Option<&str>| {
        server.signing_keys[0]
            .sign(&MintedClaims {
                iss: GW_ISSUER.to_owned(),
                sub: "user-42".to_owned(),
                aud: GW_ISSUER.to_owned(),
                client_id: CLIENT_ID.to_owned(),
                jti: "minted-3".to_owned(),
                iat: now,
                exp: now + 60,
                idp: IDP_ISSUER.to_owned(),
                gid,
                gty: gty.map(str::to_owned),
                ..MintedClaims::default()
            })
            .expect("token signs")
    };
    let gid = || Some(state::GrantId::generate().expect("random"));
    for token in [
        sign(None, Some("authorization_code")),
        sign(gid(), None),
        sign(gid(), Some("client_credentials")),
    ] {
        assert!(
            matches!(server.verify_bearer(&token), EmaBearerOutcome::Invalid(ref reason)
                if reason.contains("grant")),
        );
    }
}

// ── client roles ─────────────────────────────────────────────────────

/// `client_roles` follow the mapped roles, and are read when the token is
/// used rather than when it was minted.
#[tokio::test]
async fn client_roles_join_the_mapped_roles_when_the_token_is_used() {
    let mut config = config_with_mappings(mappings(&[], &["roles"], &[]));
    config.client_roles = BTreeMap::from([(
        CLIENT_ID.to_owned(),
        vec!["ai-agent".to_owned(), "reader".to_owned()],
    )]);
    let server = test_server_with(config.clone()).await;
    let redemption = server
        .redeem(
            token_form(&assertion_with(serde_json::json!({ "roles": ["reader"] }))),
            None,
        )
        .await;
    let (response, issued) = redemption.result.as_ref().expect("redemption succeeds");
    assert_eq!(issued.roles, ["reader", "ai-agent"]);
    assert_eq!(
        minted_claims(&response.access_token)["roles"],
        serde_json::json!(["reader"]),
        "client roles are not frozen into the token"
    );
    let identity = verified(&server, &response.access_token);
    assert_eq!(identity.roles, ["reader", "ai-agent"]);
    assert!(admitted_by(
        r#""ai-agent" in identity.roles"#,
        request_identity(identity)
    ));

    config.client_roles.clear();
    let reloaded = test_server_with(config).await;
    assert_eq!(
        verified(&reloaded, &response.access_token).roles,
        ["reader"]
    );
}

// ── principal alias ──────────────────────────────────────────────────

/// With `principal_issuer`, an EMA caller is the same principal as the
/// SSO user its OIDC provider reports under that issuer and subject;
/// without it the two stay apart.
#[tokio::test]
async fn principal_issuer_joins_the_sso_principal() {
    let sso = sso_identity(SSO_ISSUER, "user-42");

    let unaliased = request_identity(
        caller(&test_server().await, &assertion_with(serde_json::json!({}))).await,
    );
    assert_eq!(unaliased.issuer(), Some(IDP_ISSUER));
    assert_eq!(unaliased.auth_provider(), Some("ema"));
    assert_ne!(
        unaliased.synthetic_principal_key(),
        sso.synthetic_principal_key()
    );

    let mut config = test_config();
    config.trusted_idps[0].principal_issuer = Some(SSO_ISSUER.to_owned());
    let server = test_server_with(config).await;
    let identity = caller(&server, &assertion_with(serde_json::json!({}))).await;
    assert_eq!(identity.attributes["idp"], IDP_ISSUER);
    assert_eq!(identity.attributes["token_issuer"], GW_ISSUER);
    let aliased = request_identity(identity);
    assert_eq!(aliased.issuer(), Some(SSO_ISSUER));
    assert_eq!(
        aliased.auth_provider(),
        Some(format!("oidc_oauth:{SSO_ISSUER}").as_str())
    );
    assert_eq!(
        aliased.synthetic_principal_key(),
        sso.synthetic_principal_key()
    );
    assert_ne!(
        aliased.synthetic_principal_key(),
        sso_identity(SSO_ISSUER, "user-43").synthetic_principal_key(),
        "the subject still separates users"
    );
    assert!(
        aliased.is_gateway_minted(),
        "the alias must not hide that this gateway minted the bearer"
    );
    assert!(unaliased.is_gateway_minted());
    assert!(!sso.is_gateway_minted());
}

/// A rule that admits this server's ID-JAG callers only through named
/// clients holds whether or not the IdP sets `principal_issuer`, and
/// leaves callers of other verifiers alone. Keyed on `auth_provider`, it
/// stops applying once `principal_issuer` is set.
#[tokio::test]
async fn a_client_rule_keyed_on_the_grant_holds_under_principal_issuer() {
    // Every caller of the embedded server, and its ID-JAG callers alone.
    let rules_for = |client: &str| {
        [
            format!(
                r#"!("token_issuer" in identity.attributes) || identity.attributes["client_id"] in ["{client}"]"#
            ),
            format!(
                r#"!("token_issuer" in identity.attributes) || identity.attributes["grant_type"] != "id_jag" || identity.attributes["client_id"] in ["{client}"]"#
            ),
        ]
    };
    let mut aliased = test_config();
    aliased.trusted_idps[0].principal_issuer = Some(SSO_ISSUER.to_owned());
    for server in [test_server().await, test_server_with(aliased).await] {
        for (named, other) in rules_for(CLIENT_ID)
            .into_iter()
            .zip(rules_for("another-client"))
        {
            let identity = caller(&server, &assertion_with(serde_json::json!({}))).await;
            assert!(admitted_by(&named, request_identity(identity)), "{named}");
            let identity = caller(&server, &assertion_with(serde_json::json!({}))).await;
            assert!(!admitted_by(&other, request_identity(identity)), "{other}");
            assert!(
                admitted_by(&other, sso_identity(SSO_ISSUER, "user-42")),
                "{other}"
            );
        }
    }

    let mut aliased = test_config();
    aliased.trusted_idps[0].principal_issuer = Some(SSO_ISSUER.to_owned());
    let server = test_server_with(aliased).await;
    let identity = caller(&server, &assertion_with(serde_json::json!({}))).await;
    assert!(
        admitted_by(
            r#"identity.auth_provider != "ema" || identity.attributes["client_id"] == "another-client""#,
            request_identity(identity)
        ),
        "keyed on auth_provider, the rule no longer sees the caller as an ID-JAG caller"
    );
}

/// The issuance record names the IdP that vouched, whatever the alias,
/// and carries the roles, groups and actor the token grants.
#[tokio::test]
async fn the_issuance_record_names_roles_groups_and_actor() {
    let mut config = config_with_mappings(mappings(&["groups"], &["roles"], &[]));
    config.trusted_idps[0].principal_issuer = Some(SSO_ISSUER.to_owned());
    config.client_roles = BTreeMap::from([(CLIENT_ID.to_owned(), vec!["ai-agent".to_owned()])]);
    let server = test_server_with(config).await;
    let redemption = server
        .redeem(
            token_form(&assertion_with(serde_json::json!({
                "groups": ["eng"],
                "roles": ["reader"],
                "act": { "sub": "agent-9" },
            }))),
            None,
        )
        .await;
    let event = redemption.audit_event("req-1");
    assert_eq!(event.actor.issuer.as_deref(), Some(IDP_ISSUER));
    assert_eq!(event.actor.groups, ["eng"]);
    assert_eq!(event.actor.roles, ["reader", "ai-agent"]);
    assert_eq!(event.details["actor"], "agent-9");
}

// ── configuration ────────────────────────────────────────────────────

#[test]
fn claim_mappings_are_validated() {
    let refused = |claim_mappings: TrustedIdpClaimMappingConfig| {
        validation_error(&config_with_mappings(claim_mappings))
    };
    let with_subject = |subject: &str| TrustedIdpClaimMappingConfig {
        subject_claim: subject.to_owned(),
        ..Default::default()
    };
    assert!(refused(with_subject(" ")).contains("subject_claim"));
    for actor in ["act", "act.sub"] {
        let err = refused(with_subject(actor));
        assert!(err.contains("actor"), "{err}");
    }
    for claim in ["client_id", "iss", "aud", "jti"] {
        let err = refused(with_subject(claim));
        assert!(err.contains("identifies no user"), "{err}");
    }
    assert!(refused(mappings(&[""], &[], &[])).contains("empty path"));
    assert!(refused(mappings(&[], &[" "], &[])).contains("empty path"));
    assert!(refused(mappings(&[], &[], &[("dept", "")])).contains("empty name"));
    for reserved in IDENTITY_ATTRIBUTES {
        let err = refused(mappings(&[], &[], &[("some_claim", reserved)]));
        assert!(err.contains("sets itself"), "{reserved}: {err}");
    }
    for reserved in crate::runtime::federation::engine::ISSUER_SUBJECT_ATTRIBUTES {
        let err = refused(mappings(&[], &[], &[("some_claim", reserved)]));
        assert!(
            err.contains("sets itself") && err.contains("credential issuer"),
            "{reserved}: {err}"
        );
    }

    config_with_mappings(TrustedIdpClaimMappingConfig {
        subject_claim: "email".to_owned(),
        ..mappings(&["groups"], &["realm_access.roles"], &[("acr", "acr")])
    })
    .validate()
    .expect("a mapping of user claims is valid");
}

#[test]
fn principal_issuers_and_client_roles_are_validated() {
    let mut config = test_config();
    config.trusted_idps[0].principal_issuer = Some(" ".to_owned());
    assert!(validation_error(&config).contains("principal_issuer"));
    config.trusted_idps[0].principal_issuer = Some("idp.test/oauth2/default".to_owned());
    assert!(validation_error(&config).contains("http(s) issuer URL"));
    config.trusted_idps[0].principal_issuer = Some(SSO_ISSUER.to_owned());
    config.validate().expect("an issuer URL is valid");

    let mut second = config.trusted_idps[0].clone();
    second.issuer = "https://other-idp.test".to_owned();
    config.trusted_idps.push(second);
    let err = validation_error(&config);
    assert!(
        err.contains("more than one IdP") && err.contains(SSO_ISSUER),
        "{err}"
    );

    let mut config = test_config();
    config.client_roles = BTreeMap::from([("unregistered".to_owned(), vec!["x".to_owned()])]);
    assert!(validation_error(&config).contains("`unregistered`"));
    config.client_roles = BTreeMap::from([(CLIENT_ID.to_owned(), vec![" ".to_owned()])]);
    assert!(validation_error(&config).contains("empty role"));
    config.client_roles = BTreeMap::from([(CLIENT_ID.to_owned(), vec!["ai-agent".to_owned()])]);
    config
        .validate()
        .expect("roles for a registered client are valid");
}
