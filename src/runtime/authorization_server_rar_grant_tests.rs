//! Rich Authorization Requests (RFC 9396) in interactive sign-in: the
//! details an authorization request asks for travel sealed with the
//! sign-in into its code and grant; the token request that redeems the
//! code, and each refresh, may narrow them for its access token (§6)
//! while the grant keeps what the user approved; a refused request leaves
//! its code or refresh token unspent.

use serde_json::{Value, json};

use super::*;
use crate::runtime::authorization_server::grants::GRANT_TYPE_REFRESH_TOKEN;
use crate::runtime::authorization_server::state::GrantRecord;
use crate::runtime::authorization_server::tests::rar_details::details_config;

const IDP_REFRESH: &str = "idp-refresh-rar";

fn tool(actions: &[&str], identifier: &str) -> Value {
    json!({
        "type": "mcp_tool",
        "actions": actions,
        "locations": [RESOURCE],
        "identifier": identifier,
    })
}

/// The server of `idp` with the authorization details types of the
/// fixtures, and `change` applied.
fn rar_server(
    idp: &Idp,
    change: impl FnOnce(&mut AuthorizationServerConfig),
) -> AuthorizationServer {
    let mut config = config(idp);
    config.authorization_details = details_config();
    change(&mut config);
    server_with(&config)
}

/// The authorization request of `client_id` with `scope` (none when
/// `None`) asking for `details`.
fn details_query(
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    scope: Option<&str>,
    details: &Value,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", CLIENT_STATE),
    ]);
    if let Some(scope) = scope {
        query.append_pair("scope", scope);
    }
    query.append_pair("authorization_details", &details.to_string());
    query.finish()
}

/// The code `client_id` receives for a request of `scope` asking for
/// `details`, the user approving the consent page, and the IdP handing
/// out a refresh token. Also the consent and login audit records.
async fn code_with(
    server: &AuthorizationServer,
    idp: &Idp,
    client_id: &str,
    redirect_uri: &str,
    scope: Option<&str>,
    details: &Value,
) -> (Code, BrowserAudit, LoginAudit) {
    let verifier = random_token().expect("random");
    let challenge = s256_challenge(&verifier);
    let response = server
        .authorize(
            &details_query(client_id, redirect_uri, &challenge, scope, details),
            &BrowserCookies::default(),
        )
        .await;
    let BrowserOutcome::Consent(ref page) = response.outcome else {
        panic!(
            "a request for details shows the consent page, got {:?}",
            response.outcome
        );
    };
    assert_eq!(
        page.authorization_details.len(),
        details.as_array().map_or(0, Vec::len)
    );
    let approved = approve(server, &response).await;
    assert!(
        !approved.cookies.iter().any(|change| matches!(
            change,
            CookieChange::Set {
                cookie: BrowserCookie::ConsentMemory,
                ..
            }
        )),
        "an approval of details is never remembered"
    );
    let consent = approved.audit.clone().expect("the consent is audited");
    let started = started(&approved, &challenge);
    let completed = complete(server, idp, &started, Some(IDP_REFRESH)).await;
    let login = login_audit(&completed).clone();
    let (_, params) = code_issued(&completed);
    (
        Code {
            code: params["code"].clone(),
            verifier,
        },
        consent,
        login,
    )
}

fn with_details(form: TokenRequestForm, details: &Value) -> TokenRequestForm {
    TokenRequestForm {
        authorization_details: Some(details.to_string()),
        ..form
    }
}

fn refresh_form(client_id: &str, refresh_token: &str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_REFRESH_TOKEN.to_owned()),
        client_id: Some(client_id.to_owned()),
        refresh_token: Some(refresh_token.to_owned()),
        ..Default::default()
    }
}

#[track_caller]
fn details_of(response: &TokenResponse) -> Value {
    let claim = minted_claims(&response.access_token)["authorization_details"].clone();
    assert_eq!(
        serde_json::to_value(response).expect("serializes")["authorization_details"],
        claim,
        "the response echoes the claim"
    );
    claim
}

async fn grant_record(server: &AuthorizationServer, token: &str) -> GrantRecord {
    state_of(server)
        .get(&keys::grant(&grant_of(token)))
        .await
        .expect("store")
        .expect("the grant is kept")
}

#[tokio::test]
async fn approved_details_travel_with_the_code_and_may_be_narrowed_at_redemption() {
    let idp = Idp::start().await;
    let server = rar_server(&idp, |_| {});
    let approved = json!([
        tool(&["tools/call", "tools/list"], "search"),
        { "type": "open_type", "identifier": "report" },
    ]);
    let (code, consent, login) = code_with(
        &server,
        &idp,
        "desktop",
        DESKTOP_REDIRECT,
        Some("mcp:tools"),
        &approved,
    )
    .await;
    let BrowserAudit::Consent {
        ref authorization_details_types,
        ..
    } = consent
    else {
        panic!("expected the consent record, got {consent:?}");
    };
    assert_eq!(authorization_details_types, &["mcp_tool", "open_type"]);
    assert_eq!(login.authorization_details_types, ["mcp_tool", "open_type"]);
    let stored: CodeRecord = state_of(&server)
        .get(&keys::code(&code.code))
        .await
        .expect("store")
        .expect("the code is kept");
    assert_eq!(
        serde_json::to_value(&stored.authorization_details).expect("serializes"),
        approved
    );

    for (requested, named) in [
        (
            json!([tool(&["tools/list"], "other")]),
            "exceed what was granted",
        ),
        (
            json!([{ "type": "mcp_tool", "actions": ["tools/delete"] }]),
            "[0].actions holds a value",
        ),
    ] {
        let refused = server
            .redeem(with_details(code_form("desktop", &code), &requested), None)
            .await;
        let error = refusal(&refused);
        assert_eq!(error.error, "invalid_authorization_details");
        assert!(error.description.contains(named), "{error:?}");
    }

    let narrowed = json!([tool(&["tools/list"], "search")]);
    let redeemed = server
        .redeem(with_details(code_form("desktop", &code), &narrowed), None)
        .await;
    let (response, issued) = issued(&redeemed);
    assert_eq!(
        details_of(response),
        narrowed,
        "the refusals left the code unspent"
    );
    assert_eq!(issued.authorization_details.types(), ["mcp_tool"]);
    let event = redeemed.audit_event("req-code");
    assert_eq!(event.action, "mcpg.as.token_issued");
    assert_eq!(
        event.details["authorization_details_types"],
        json!(["mcp_tool"])
    );
    assert_eq!(
        serde_json::to_value(
            grant_record(&server, &response.access_token)
                .await
                .authorization_details
        )
        .expect("serializes"),
        approved,
        "the grant keeps what the user approved"
    );
    let caller = caller_of(&server, &response.access_token);
    assert_eq!(caller.attributes["authorization_details_types"], "mcp_tool");
}

#[tokio::test]
async fn a_refresh_may_narrow_the_approved_details_and_the_grant_keeps_them() {
    let idp = Idp::start().await;
    let server = rar_server(&idp, |_| {});
    let approved = json!([tool(&["tools/call", "tools/list"], "search")]);
    let (code, _, _) = code_with(
        &server,
        &idp,
        "desktop",
        DESKTOP_REDIRECT,
        Some("mcp:tools"),
        &approved,
    )
    .await;
    let redeemed = server.redeem(code_form("desktop", &code), None).await;
    let (response, _) = issued(&redeemed);
    assert_eq!(details_of(response), approved);
    let refresh_token = response.refresh_token.clone().expect("a refresh token");

    let wider = server
        .redeem(
            with_details(
                refresh_form("desktop", &refresh_token),
                &json!([tool(&["tools/call"], "elsewhere")]),
            ),
            None,
        )
        .await;
    assert_eq!(refusal(&wider).error, "invalid_authorization_details");

    let narrowed = json!([tool(&["tools/call"], "search")]);
    let refreshed = server
        .redeem(
            with_details(refresh_form("desktop", &refresh_token), &narrowed),
            None,
        )
        .await;
    let (response, _) = issued(&refreshed);
    assert_eq!(
        details_of(response),
        narrowed,
        "the refused refresh left the token unspent"
    );
    let successor = response.refresh_token.clone().expect("a successor");

    let again = server
        .redeem(refresh_form("desktop", &successor), None)
        .await;
    let (response, _) = issued(&again);
    assert_eq!(
        details_of(response),
        approved,
        "the grant keeps what was approved"
    );
}

#[tokio::test]
async fn a_request_for_details_without_scope_is_granted_no_scope() {
    let idp = Idp::start().await;
    let server = rar_server(&idp, |_| {});
    let details = json!([tool(&["tools/call"], "search")]);
    let (code, _, login) =
        code_with(&server, &idp, "desktop", DESKTOP_REDIRECT, None, &details).await;
    assert!(login.scope.is_empty(), "{:?}", login.scope);
    let redeemed = server.redeem(code_form("desktop", &code), None).await;
    let (response, _) = issued(&redeemed);
    assert_eq!(response.scope, None);
    assert_eq!(details_of(response), details);

    let strict = rar_server(&idp, |config| config.require_scope = true);
    let response = strict
        .authorize(
            &details_query(
                "desktop",
                DESKTOP_REDIRECT,
                &fresh_challenge(),
                None,
                &details,
            ),
            &BrowserCookies::default(),
        )
        .await;
    assert_eq!(error_redirect(&response)["error"], "invalid_scope");
}

#[tokio::test]
async fn only_a_client_registered_to_skip_consent_goes_without_the_page() {
    let idp = Idp::start().await;
    let server = rar_server(&idp, |config| {
        config.clients.push(
            serde_json::from_value(json!({
                "client_id": "skipper",
                "redirect_uris": [WEB_REDIRECT],
                "consent": "skip",
            }))
            .expect("client parses"),
        );
    });
    let details = json!([tool(&["tools/call"], "search")]);
    let web = server
        .authorize(
            &details_query(
                "web-app",
                WEB_REDIRECT,
                &fresh_challenge(),
                Some("mcp:tools"),
                &details,
            ),
            &BrowserCookies::default(),
        )
        .await;
    assert!(
        matches!(web.outcome, BrowserOutcome::Consent(_)),
        "an https-only client that skips by default is asked about details: {:?}",
        web.outcome
    );
    let challenge = fresh_challenge();
    let skipper = server
        .authorize(
            &details_query(
                "skipper",
                WEB_REDIRECT,
                &challenge,
                Some("mcp:tools"),
                &details,
            ),
            &BrowserCookies::default(),
        )
        .await;
    let started = started(&skipper, &challenge);
    assert_eq!(
        serde_json::to_value(transaction(&server, &started).await.authorization_details)
            .expect("serializes"),
        details
    );
}
