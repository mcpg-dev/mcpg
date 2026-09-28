use super::*;
use crate::runtime::authorization_server::state::SecretString;

fn caller(source: &str, attributes: &[(&str, &str)]) -> RequestIdentity {
    caller_in(source, "ema", "https://acme.okta.com", attributes)
}

fn caller_in(
    source: &str,
    auth_provider: &str,
    issuer: &str,
    attributes: &[(&str, &str)],
) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: "00u-alice".to_owned(),
        issuer: issuer.to_owned(),
        auth_provider: auth_provider.to_owned(),
        source: source.to_owned(),
        roles: vec!["reader".to_owned()],
        groups: Vec::new(),
        scopes: vec!["mcp:tools".to_owned()],
        attributes: attributes
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn stored(kind: SubjectTokenKind) -> VaultSubjectToken {
    VaultSubjectToken {
        token: SecretString::new("idp-stored-token"),
        kind,
        issuer: "https://acme.okta.com".to_owned(),
        token_endpoint: "https://acme.okta.com/oauth2/v1/token".to_owned(),
        client_id: "0oa-login".to_owned(),
        binding: format!("vault:handle:0oa-login:{}", kind.as_str()),
    }
}

struct Source {
    connect: Option<&'static str>,
}

#[async_trait]
impl IdpSessionSource for Source {
    async fn subject_token(&self, _principal: &str, _kind: SubjectTokenKind) -> IdpSubjectToken {
        IdpSubjectToken::NoLogin
    }

    fn connect_url(&self) -> Option<String> {
        self.connect.map(str::to_owned)
    }

    fn login_issuer(&self) -> Option<String> {
        Some("https://acme.okta.com".to_owned())
    }

    fn stores_sign_in_for(&self, auth_provider: &str, issuer: &str) -> bool {
        auth_provider == "ema" && issuer == "https://acme.okta.com"
    }

    async fn offer_link(&self, _offer: LinkOffer<'_>) -> Result<ConnectLink, LinkError> {
        Err(LinkError::NotOffered)
    }
}

fn elicitation(id: &str) -> UrlElicitation {
    UrlElicitation {
        id: id.to_owned(),
        url: format!("https://gw.example/oauth/connect?e={id}"),
        message: "connect".to_owned(),
        expires_at: 1_900_000_000,
    }
}

/// A slot offers a link only while open: opened by the request that may
/// answer with one, after which it holds the one link it answers with.
#[test]
fn a_slot_holds_a_link_only_while_its_request_may_answer_with_one() {
    let slot = ConnectLinkSlot::default();
    assert_eq!(slot.request(), None, "a slot starts closed");
    slot.offer(elicitation("link-1"));
    assert_eq!(slot.take_offered(), None, "a closed slot takes no link");

    assert!(slot.open(Some("sess-1".to_owned())));
    assert_eq!(
        slot.request(),
        Some(LinkRequest {
            resume: None,
            notify_session: Some("sess-1".to_owned()),
        })
    );
    slot.offer(elicitation("link-1"));
    assert_eq!(
        slot.request(),
        None,
        "an offered slot asks for no second link"
    );
    slot.offer(elicitation("link-2"));
    assert_eq!(slot.take_offered(), Some(elicitation("link-1")));
    assert_eq!(slot.take_offered(), None);
}

/// A retry resumes its link when the slot opens; a declined link keeps the
/// slot shut.
#[test]
fn a_retry_resumes_its_link_and_a_declined_one_stays_shut() {
    let resumed = ConnectLinkSlot::default();
    resumed.resume("link-7".to_owned());
    assert_eq!(resumed.request(), None, "resuming is not yet open");
    assert!(resumed.open(None));
    assert_eq!(
        resumed.request(),
        Some(LinkRequest {
            resume: Some("link-7".to_owned()),
            notify_session: None,
        })
    );

    let declined = ConnectLinkSlot::default();
    declined.decline();
    assert!(!declined.open(Some("sess-1".to_owned())));
    assert_eq!(declined.request(), None);
    declined.offer(elicitation("link-1"));
    assert_eq!(declined.take_offered(), None);
}

/// No link id reaches a log through `Debug`.
#[test]
fn neither_a_slot_nor_an_elicitation_shows_its_link() {
    let slot = ConnectLinkSlot::default();
    slot.resume("secret-link-id".to_owned());
    assert!(!format!("{slot:?}").contains("secret-link-id"));
    slot.open(None);
    slot.offer(elicitation("secret-link-id"));
    assert!(!format!("{slot:?}").contains("secret-link-id"));
    assert!(!format!("{:?}", elicitation("secret-link-id")).contains("secret-link-id"));
}

/// Only a verified caller in the namespace a sign-in through the login IdP
/// is stored under can ever store one, however it authenticated; what an
/// attribute claims does not decide.
#[test]
fn only_a_caller_in_the_login_namespace_can_store_a_sign_in() {
    let source = Source { connect: None };
    for (identity, stores) in [
        (
            caller(
                crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
                &[("idp", "https://acme.okta.com")],
            ),
            true,
        ),
        (
            caller(
                "authorization:oidc_oauth",
                &[("idp", "https://partner.example")],
            ),
            true,
        ),
        (
            caller_in(
                crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
                "ema",
                "https://partner.example",
                &[("idp", "https://acme.okta.com")],
            ),
            false,
        ),
        (
            caller_in(
                "authorization:oidc_oauth",
                "oidc_oauth:https://acme.okta.com/oauth2/default",
                "https://acme.okta.com/oauth2/default",
                &[],
            ),
            false,
        ),
        (
            caller_in(
                crate::runtime::INSPECTOR_TOKEN_SOURCE,
                "inspector_supervisor",
                "mcpg-gateway",
                &[],
            ),
            false,
        ),
        (
            RequestIdentity::HttpHeader {
                subject_id: "alice".to_owned(),
                source: "x-user".to_owned(),
            },
            false,
        ),
    ] {
        assert_eq!(
            can_store_sign_in(&source, &identity),
            stores,
            "{identity:?}"
        );
    }
}

#[test]
fn a_federation_is_named_in_a_sign_in_message_only_when_plain() {
    assert_eq!(federation_label("crm"), "federation `crm`");
    assert_eq!(
        federation_label("corp--com.acme--crm_v2"),
        "federation `corp--com.acme--crm_v2`"
    );
    let long = "a".repeat(129);
    for foreign in [
        "",
        "crm`. Sign in at https://evil.example",
        "crm\nopen https://evil.example",
        "crm/tools",
        long.as_str(),
    ] {
        assert_eq!(federation_label(foreign), "a federated tool", "{foreign:?}");
    }
}

#[test]
fn only_the_idp_modes_read_a_stored_token() {
    assert_eq!(subject_token_kind(SubjectToken::CallerBearer), None);
    assert_eq!(
        subject_token_kind(SubjectToken::IdpRefreshToken),
        Some(SubjectTokenKind::RefreshToken)
    );
    assert_eq!(
        subject_token_kind(SubjectToken::IdpIdToken),
        Some(SubjectTokenKind::IdToken)
    );
}

#[test]
fn the_vault_identity_replaces_every_planted_subject_attribute() {
    let identity = caller(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[
            ("token_issuer", "https://mcp.acme.example"),
            ("grant_type", "authorization_code"),
            ("subject_token", "planted"),
            ("subject_token_endpoint", "https://collector.example/token"),
            ("subject_token_extra", "planted"),
        ],
    );
    let issued = vault_identity(&identity, &stored(SubjectTokenKind::RefreshToken));
    let expected: std::collections::BTreeMap<String, String> = [
        ("token_issuer", "https://mcp.acme.example"),
        ("grant_type", "authorization_code"),
        ("subject_token", "idp-stored-token"),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:refresh_token",
        ),
        ("subject_token_source", "idp_vault"),
        ("subject_token_issuer", "https://acme.okta.com"),
        (
            "subject_token_endpoint",
            "https://acme.okta.com/oauth2/v1/token",
        ),
        ("subject_token_client_id", "0oa-login"),
        (
            "subject_token_binding",
            "vault:handle:0oa-login:refresh_token",
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect();
    assert_eq!(issued.attributes, expected);
    assert_eq!(issued.trust_level, "verified");
    assert_eq!(issued.subject_id.as_deref(), Some("00u-alice"));
    assert_eq!(issued.scopes, vec!["mcp:tools".to_owned()]);
    for name in VAULT_ATTRIBUTES {
        assert!(issued.attributes.contains_key(name), "{name}");
        assert!(name.starts_with(SUBJECT_ATTRIBUTE_PREFIX), "{name}");
    }

    let id_token = vault_identity(&identity, &stored(SubjectTokenKind::IdToken));
    assert_eq!(
        id_token.attributes["subject_token_type"],
        "urn:ietf:params:oauth:token-type:id_token"
    );
}

#[test]
fn a_vault_token_is_never_shown_by_debug() {
    let token = stored(SubjectTokenKind::RefreshToken);
    assert!(!format!("{token:?}").contains("idp-stored-token"));
}

#[test]
fn stripping_keeps_every_other_attribute() {
    let mut identity = crate::runtime::plugin_identity_from_request_identity(&caller(
        "authorization:oidc_oauth",
        &[
            ("subject_token", "x"),
            ("subject_tokens", "y"),
            ("acr", "mfa"),
        ],
    ));
    strip_subject_attributes(&mut identity);
    assert_eq!(
        identity.attributes.keys().collect::<Vec<_>>(),
        vec![&"acr".to_owned()]
    );
}

#[test]
fn the_not_linked_message_names_the_connect_page_or_the_login_idp() {
    let signed_in = caller(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[("idp", "https://acme.okta.com")],
    );
    let with_page = Source {
        connect: Some("https://mcp.acme.example/oauth/connect"),
    };
    assert_eq!(
        not_linked_message("vendor", &with_page, &signed_in, false),
        "federation `vendor`: no enterprise sign-in is stored for you: open \
         https://mcp.acme.example/oauth/connect once, then retry"
    );
    assert_eq!(
        not_linked_message("vendor", &with_page, &signed_in, true),
        "federation `vendor`: your stored enterprise sign-in was ended by the IdP: open \
         https://mcp.acme.example/oauth/connect once, then retry"
    );
    let without_page = Source { connect: None };
    let message = not_linked_message("vendor", &without_page, &signed_in, false);
    assert!(
        message.contains("sign in to this gateway through https://acme.okta.com from your MCP"),
        "{message}"
    );

    let partner = caller_in(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        "ema",
        "https://partner.example#t1",
        &[("idp", "https://partner.example")],
    );
    let message = not_linked_message("vendor", &with_page, &partner, false);
    assert_eq!(
        message,
        "federation `vendor` presents your stored enterprise sign-in, but none can be stored \
         for you: you signed in through https://partner.example, and only users of \
         https://acme.okta.com can store one. The operator joins other callers to those users \
         with the IdP's principal_issuer or required_tenant"
    );
    // Only a token this gateway minted names the IdP it came from; an
    // `idp` attribute of another caller is a claim like any other.
    let sso = caller_in(
        "authorization:oidc_oauth",
        "oidc_oauth:https://sso.example",
        "https://sso.example",
        &[("idp", "https://acme.okta.com")],
    );
    let message = not_linked_message("vendor", &with_page, &sso, false);
    assert!(
        message.contains("you signed in through https://sso.example")
            && !message.contains("/oauth/connect"),
        "{message}"
    );
    let signed_in_sso = caller(
        "authorization:oidc_oauth",
        &[("idp", "https://partner.example")],
    );
    assert!(
        not_linked_message("vendor", &with_page, &signed_in_sso, false).contains("/oauth/connect"),
        "a caller in the login namespace is sent to the connect page"
    );
}

#[test]
fn the_audit_record_names_the_federation_mode_and_outcome() {
    let actor = crate::runtime::plugin_identity_from_request_identity(&caller(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[],
    ));
    for (outcome, expected) in [
        (SubjectTokenOutcome::Used, AuditOutcome::Success),
        (SubjectTokenOutcome::NotLinked, AuditOutcome::Denied),
        (SubjectTokenOutcome::Refused, AuditOutcome::Denied),
        (SubjectTokenOutcome::Unavailable, AuditOutcome::Failure),
    ] {
        let event = audit_event(
            "vendor",
            SubjectToken::IdpIdToken,
            outcome,
            "a reason",
            actor.clone(),
            Some("req-1"),
        );
        assert_eq!(event.action, "mcpg.federation.idp_subject_token");
        assert_eq!(event.outcome, expected);
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert_eq!(
            event.details,
            serde_json::json!({
                "federation": "vendor",
                "mode": "idp_id_token",
                "outcome": outcome.as_str(),
                "reason": "a reason",
            })
        );
    }
}
