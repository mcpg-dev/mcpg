//! Dynamic client registration: off unless the operator turns it on, an
//! initial access token or an open door, RFC 7591 §3.2.2 refusals, what a
//! registration keeps of what a client claims, the hourly allowance per
//! address and the cap on registrations across replicas, the sealed
//! record whose lifetime restarts with each use, and a registered client
//! that is public, asks for consent every time, is never admitted by an
//! IdP's allowed_clients and loses its grants once its registration is
//! gone.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::config::interactive_login::DCR_CLIENT_ID_PREFIX;
use crate::runtime::authorization_server::dcr::{
    AuthorizedBy, ClientRegistration, REGISTRATION_PATH, RegistrationError, parse_registration,
    rate_subject, token_digests,
};
use crate::runtime::authorization_server::grants::GRANT_TYPE_REFRESH_TOKEN;
use crate::runtime::authorization_server::redirect::AuthorizeClientError;
use crate::runtime::authorization_server::revocation::RevocationRequestForm;
use crate::runtime::authorization_server::state::{
    ConsentApproval, ConsentMemoryRecord, DcrClientRecord, RecordKey,
};

/// An initial access token the operator lists; long, and plainly a test
/// value.
const IAT: &str = "test-initial-access-token-test-initial-access-token";
const LOOPBACK: &str = "http://127.0.0.1/callback";
const LOOPBACK_REQUEST: &str = "http://127.0.0.1:61234/callback";
const CURSOR_REDIRECT: &str = "https://www.cursor.com/oauth/callback";
const ADDRESS: &str = "203.0.113.7";

fn address(ip: &str) -> Option<IpAddr> {
    Some(ip.parse().expect("an IP address"))
}

fn with_registration(idp: &Idp, registration: Value) -> AuthorizationServerConfig {
    let mut config = config(idp);
    interactive(&mut config).dynamic_client_registration =
        serde_json::from_value(registration).expect("registration settings parse");
    config
}

/// Open registration, loopback and `www.cursor.com` redirect URIs.
fn open_registration() -> Value {
    json!({
        "enabled": true,
        "allow_open": true,
        "allowed_redirect_hosts": ["www.cursor.com"],
    })
}

fn registering(idp: &Idp) -> AuthorizationServer {
    server_with(&with_registration(idp, open_registration()))
}

async fn register_from(
    server: &AuthorizationServer,
    body: &Value,
    authorization: Option<&str>,
    ip: &str,
) -> ClientRegistration {
    server
        .register_client(body.to_string().as_bytes(), authorization, address(ip))
        .await
}

async fn register(server: &AuthorizationServer, body: &Value) -> ClientRegistration {
    register_from(server, body, None, ADDRESS).await
}

#[track_caller]
fn registered(registration: &ClientRegistration) -> &DcrClientRecord {
    match registration.result {
        Ok(ref registered) => &registered.record,
        Err(ref error) => panic!("the registration should succeed: {error:?}"),
    }
}

#[track_caller]
fn refused_registration(registration: &ClientRegistration) -> &RegistrationError {
    match registration.result {
        Err(ref error) => error,
        Ok(ref registered) => panic!("the registration should be refused: {registered:?}"),
    }
}

/// Register a loopback client with `grant_types`; its client_id.
async fn register_desktop(server: &AuthorizationServer, grant_types: &[&str]) -> String {
    let registration = register(
        server,
        &json!({
            "redirect_uris": [LOOPBACK],
            "grant_types": grant_types,
            "client_name": "Local Agent",
        }),
    )
    .await;
    registered(&registration).client_id.clone()
}

fn registration_key(client_id: &str) -> RecordKey<DcrClientRecord> {
    keys::dcr_client(client_id).expect("a registration id")
}

/// Remove `client_id`'s registration, as its lifetime ending does.
async fn remove_registration(server: &AuthorizationServer, client_id: &str) {
    assert!(
        state_of(server)
            .delete(&registration_key(client_id))
            .await
            .expect("store"),
        "the registration was stored"
    );
}

fn refresh_form_for(client_id: &str, refresh_token: &str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_REFRESH_TOKEN.to_owned()),
        client_id: Some(client_id.to_owned()),
        refresh_token: Some(refresh_token.to_owned()),
        ..Default::default()
    }
}

/// A registered loopback client's user signed in and the code redeemed:
/// the client_id, the access token and the refresh token.
async fn signed_in_desktop(server: &AuthorizationServer, idp: &Idp) -> (String, String, String) {
    let client_id = register_desktop(server, &["authorization_code", "refresh_token"]).await;
    let code = code_for(
        server,
        idp,
        &client_id,
        LOOPBACK_REQUEST,
        Some("idp-refresh-1"),
    )
    .await;
    let redemption = server.redeem(code_form(&client_id, &code), None).await;
    let (response, _) = issued(&redemption);
    (
        client_id,
        response.access_token.clone(),
        response
            .refresh_token
            .clone()
            .expect("a refresh token for a client that registered refresh_token"),
    )
}

// ---------------------------------------------------------------------------
// Offering registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_is_off_by_default_and_needs_a_login_idp() {
    let idp = Idp::start().await;
    let server = server(&idp);
    assert!(!server.registers_clients());
    assert!(server.metadata().get("registration_endpoint").is_none());
    let registration = register(&server, &json!({ "redirect_uris": [LOOPBACK] })).await;
    let error = refused_registration(&registration);
    assert_eq!(*error, RegistrationError::NotOffered);
    assert_eq!(error.status(), 404);
    assert!(registration.audit_event("req").is_none());

    let mut without_login = with_registration(&idp, open_registration());
    without_login.trusted_idps[0].login = None;
    let server = server_with(&without_login);
    assert!(!server.registers_clients());
    assert!(server.metadata().get("registration_endpoint").is_none());
}

#[tokio::test]
async fn the_metadata_offers_the_registration_endpoint_and_public_clients() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let metadata = server.metadata();
    assert_eq!(
        metadata["registration_endpoint"],
        format!("{GW_ISSUER}{REGISTRATION_PATH}")
    );
    let methods = metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("methods");
    assert!(methods.contains(&json!("none")), "{methods:?}");
    assert!(
        methods.contains(&json!("client_secret_basic")),
        "{methods:?}"
    );
}

// ---------------------------------------------------------------------------
// Initial access tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registration_needs_a_listed_initial_access_token_unless_open() {
    let idp = Idp::start().await;
    let server = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "initial_access_tokens": [IAT] }),
    ));
    let body = json!({ "redirect_uris": [LOOPBACK] });
    let invalid_token = Some("Bearer error=\"invalid_token\"");
    for (authorization, why, challenge) in [
        (None, "an initial access token is required", Some("Bearer")),
        (
            Some("Bearer not-the-listed-token"),
            "is not valid",
            invalid_token,
        ),
        (
            Some(format!("Basic {IAT}").as_str()),
            "as Bearer <token>",
            invalid_token,
        ),
        (Some("Bearer "), "as Bearer <token>", invalid_token),
    ] {
        let registration = register_from(&server, &body, authorization, ADDRESS).await;
        let error = refused_registration(&registration);
        assert_eq!(error.error(), "invalid_token", "{authorization:?}");
        assert_eq!(error.status(), 401);
        assert!(error.description().contains(why), "{error:?}");
        assert_eq!(
            error.www_authenticate(),
            challenge,
            "no error code without a token (RFC 6750 §3.1): {authorization:?}"
        );
        let audit = registration.audit_event("req").expect("audited");
        assert_eq!(audit.action, "mcpg.auth.failed");
        assert_eq!(audit.details["auth_method"], "as_register");
        assert!(!serde_json::to_string(&audit).expect("JSON").contains(IAT));
    }

    let bearer = format!("Bearer {IAT}");
    let registration = register_from(&server, &body, Some(&bearer), ADDRESS).await;
    registered(&registration);
    assert_eq!(
        registration.authorized_by,
        Some(AuthorizedBy::InitialAccessToken)
    );
    let lower = format!("bearer {IAT}");
    registered(&register_from(&server, &body, Some(&lower), ADDRESS).await);
    let audit = registration.audit_event("req-1").expect("audited");
    assert_eq!(audit.action, "mcpg.as.client_registered");
    assert_eq!(audit.details["authorized_by"], "initial_access_token");
    assert!(!serde_json::to_string(&audit).expect("JSON").contains(IAT));
    assert!(!format!("{server:?}").contains(IAT));

    let open = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true, "initial_access_tokens": [IAT] }),
    ));
    let registration = register_from(&open, &body, None, ADDRESS).await;
    registered(&registration);
    assert_eq!(registration.authorized_by, Some(AuthorizedBy::Open));
    let registration =
        register_from(&open, &body, Some("Bearer not-the-listed-token"), ADDRESS).await;
    assert_eq!(
        refused_registration(&registration).error(),
        "invalid_token",
        "a token that is presented is checked, open or not"
    );
}

#[test]
fn initial_access_tokens_are_kept_as_digests_of_resolved_tokens() {
    let settings =
        |value: Value| -> crate::config::interactive_login::DynamicClientRegistrationConfig {
            serde_json::from_value(value).expect("settings parse")
        };
    let digests = token_digests(&settings(
        json!({ "enabled": true, "initial_access_tokens": [IAT] }),
    ))
    .expect("digests");
    assert_eq!(digests.len(), 1);
    assert_ne!(&digests[0][..], IAT.as_bytes());
    assert!(
        token_digests(&settings(json!({
            "enabled": true,
            "initial_access_tokens": ["${secret.DCR_TOKEN}"],
        })))
        .is_err(),
        "a placeholder that did not resolve is refused"
    );
    assert!(
        token_digests(&settings(
            json!({ "enabled": true, "initial_access_tokens": ["short"] })
        ))
        .is_err()
    );
    assert!(
        token_digests(&settings(json!({ "initial_access_tokens": ["short"] })))
            .expect("off")
            .is_empty(),
        "nothing is read while registration is off"
    );
}

// ---------------------------------------------------------------------------
// What a registration may ask for
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registration_is_refused_with_the_rfc_7591_error() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let six: Vec<String> = (0..6).map(|n| format!("http://127.0.0.1/cb{n}")).collect();
    for (body, error) in [
        (
            json!({ "redirect_uris": ["https://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["cursor://anysphere.cursor-retrieval/oauth/callback"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["http://app.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["http://127.0.0.1/cb#fragment"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["https://www.cursor.com.evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (json!({}), "invalid_redirect_uri"),
        (json!({ "redirect_uris": [] }), "invalid_redirect_uri"),
        (json!({ "redirect_uris": LOOPBACK }), "invalid_redirect_uri"),
        (json!({ "redirect_uris": six }), "invalid_redirect_uri"),
        (
            json!({ "redirect_uris": [LOOPBACK], "token_endpoint_auth_method": "client_secret_basic" }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "token_endpoint_auth_method": "private_key_jwt" }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "grant_types": ["client_credentials"] }),
            "invalid_client_metadata",
        ),
        (
            json!({
                "redirect_uris": [LOOPBACK],
                "grant_types": ["authorization_code", GRANT_TYPE_JWT_BEARER],
            }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "grant_types": ["refresh_token"] }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "grant_types": ["implicit"] }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "response_types": ["token"] }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "response_types": [] }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [LOOPBACK], "client_name": 7 }),
            "invalid_client_metadata",
        ),
        (json!([LOOPBACK]), "invalid_client_metadata"),
    ] {
        let registration = register(&server, &body).await;
        let refused = refused_registration(&registration);
        assert_eq!(refused.error(), error, "{body}: {refused:?}");
        assert_eq!(refused.status(), 400);
    }
    let not_json = server
        .register_client(b"redirect_uris=x", None, address(ADDRESS))
        .await;
    assert_eq!(
        refused_registration(&not_json).error(),
        "invalid_client_metadata"
    );
    let oversized = json!({
        "redirect_uris": [LOOPBACK],
        "client_name": "x".repeat(9 * 1024),
    });
    assert_eq!(
        refused_registration(&register(&server, &oversized).await).error(),
        "invalid_client_metadata"
    );
    assert_eq!(
        state_of(&server)
            .count(&keys::dcr_clients(), 100)
            .await
            .expect("store"),
        0,
        "nothing refused is kept"
    );
}

#[tokio::test]
async fn a_registration_keeps_only_what_it_may_use() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let registration = register(
        &server,
        &json!({
            "redirect_uris": [CURSOR_REDIRECT, LOOPBACK, CURSOR_REDIRECT],
            "grant_types": ["authorization_code", "refresh_token", "authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_name": "Cursor\u{202e} \u{200b}Agent",
            "application_type": "native",
            "logo_uri": "https://evil.example/logo.png",
            "client_uri": "https://evil.example/",
            "tos_uri": "https://evil.example/tos",
            "policy_uri": "https://evil.example/policy",
            "contacts": ["admin@evil.example"],
            "jwks_uri": "https://evil.example/jwks",
            "scope": "mcp:admin",
            "software_statement": "eyJhbGciOiJub25lIn0.e30.",
        }),
    )
    .await;
    let record = registered(&registration).clone();
    assert!(record.client_id.starts_with(DCR_CLIENT_ID_PREFIX));
    assert_eq!(record.client_id.len(), DCR_CLIENT_ID_PREFIX.len() + 32);
    assert_eq!(record.client_name.as_deref(), Some("Cursor Agent"));
    assert_eq!(record.redirect_uris, [CURSOR_REDIRECT, LOOPBACK]);
    assert_eq!(record.grant_types, ["authorization_code", "refresh_token"]);
    assert_eq!(record.response_types, ["code"]);
    assert_eq!(record.application_type.as_deref(), Some("native"));

    let body = match registration.result {
        Ok(ref registered) => registered.body(),
        Err(ref error) => panic!("{error:?}"),
    };
    let mut members: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "application_type",
            "client_id",
            "client_id_issued_at",
            "client_name",
            "grant_types",
            "redirect_uris",
            "response_types",
            "token_endpoint_auth_method",
        ],
        "no secret, and nothing the server does not keep"
    );
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(body["client_id"], record.client_id);

    let key = registration_key(&record.client_id);
    assert_eq!(
        state_of(&server).get(&key).await.expect("store").as_ref(),
        Some(&record)
    );
    let raw = state_of(&server)
        .store()
        .get(key.as_str())
        .await
        .expect("store")
        .expect("stored");
    let raw = String::from_utf8_lossy(&raw.bytes);
    assert!(
        !raw.contains("cursor.com") && !raw.contains("Cursor"),
        "the record is sealed"
    );
    let expires = raw_expiry_secs(&server, &record.client_id).await;
    assert!(
        (30 * 86_400 - 5..=30 * 86_400).contains(&expires),
        "{expires}"
    );
}

/// VS Code's registration request, as its desktop build sends it to this
/// server when it offers no client metadata documents: the grant types it
/// supports that the server's metadata lists.
fn vscode_registration() -> Value {
    json!({
        "client_name": "Visual Studio Code",
        "client_uri": "https://code.visualstudio.com",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [
            "https://insiders.vscode.dev/redirect",
            "https://vscode.dev/redirect",
            "http://127.0.0.1/",
            "http://127.0.0.1:33418/",
        ],
        "scope": "mcp:tools",
        "token_endpoint_auth_method": "none",
    })
}

/// An `https://` redirect URI on a host the operator does not admit is
/// left out of the registration (RFC 7591 §3.2.1), so a client that also
/// lists loopback URIs registers with those; a malformed URI, a
/// private-use scheme or plain http on another host still refuses the
/// request, and so does a request with nothing left.
#[tokio::test]
async fn an_https_redirect_uri_the_operator_does_not_admit_is_left_out() {
    let idp = Idp::start().await;
    let loopback_only = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true }),
    ));
    let body = vscode_registration();
    let registration = register(&loopback_only, &body).await;
    let record = registered(&registration);
    assert_eq!(
        record.redirect_uris,
        ["http://127.0.0.1/", "http://127.0.0.1:33418/"]
    );
    let Ok(ref kept) = registration.result else {
        panic!("registered");
    };
    assert_eq!(
        kept.body()["redirect_uris"],
        json!(["http://127.0.0.1/", "http://127.0.0.1:33418/"]),
        "the answer lists what was registered"
    );
    loopback_only
        .authorize_client(Some(&record.client_id), Some("http://127.0.0.1:50123/"))
        .await
        .expect("a loopback redirect on any port");
    assert!(
        loopback_only
            .authorize_client(Some(&record.client_id), Some("https://vscode.dev/redirect"))
            .await
            .is_err(),
        "a URI left out is never matched"
    );

    let admitting = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true, "allowed_redirect_hosts": ["vscode.dev"] }),
    ));
    assert_eq!(
        registered(&register(&admitting, &body).await).redirect_uris,
        [
            "https://insiders.vscode.dev/redirect",
            "https://vscode.dev/redirect",
            "http://127.0.0.1/",
            "http://127.0.0.1:33418/",
        ]
    );

    for (uris, why) in [
        (
            json!(["https://vscode.dev/redirect", "cursor://anysphere/cb"]),
            "cursor://",
        ),
        (
            json!(["http://127.0.0.1/", "http://app.example/cb"]),
            "http://app.example/cb",
        ),
        (
            json!(["http://127.0.0.1/", "https://vscode.dev/cb#fragment"]),
            "#fragment",
        ),
        (
            json!(["https://vscode.dev/redirect", "https://evil.example/cb"]),
            "allowed_redirect_hosts",
        ),
    ] {
        let registration = register(&loopback_only, &json!({ "redirect_uris": uris })).await;
        let refused = refused_registration(&registration);
        assert_eq!(refused.error(), "invalid_redirect_uri", "{uris}");
        assert!(refused.description().contains(why), "{uris}: {refused:?}");
    }
}

#[test]
fn registration_metadata_defaults_to_the_code_grant() {
    let settings: crate::config::interactive_login::DynamicClientRegistrationConfig =
        serde_json::from_value(json!({ "enabled": true, "allow_open": true }))
            .expect("settings parse");
    let metadata = parse_registration(
        json!({ "redirect_uris": [LOOPBACK], "application_type": "desktop" })
            .to_string()
            .as_bytes(),
        &settings,
    )
    .expect("accepted");
    assert_eq!(metadata.grant_types, ["authorization_code"]);
    assert_eq!(metadata.response_types, ["code"]);
    assert_eq!(metadata.client_name, None);
    assert_eq!(
        metadata.application_type, None,
        "only web or native is kept"
    );
    let refused = parse_registration(
        json!({ "redirect_uris": [CURSOR_REDIRECT] })
            .to_string()
            .as_bytes(),
        &settings,
    )
    .expect_err("refused");
    assert!(
        refused.description().contains("allowed_redirect_hosts"),
        "{refused:?}"
    );
}

/// Seconds until the registration of `client_id` expires in the store.
async fn raw_expiry_secs(server: &AuthorizationServer, client_id: &str) -> u64 {
    let entry = state_of(server)
        .store()
        .get(registration_key(client_id).as_str())
        .await
        .expect("store")
        .expect("stored");
    entry
        .expires_at
        .expect("a registration expires")
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// How many registrations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registrations_are_counted_per_address_and_clock_hour() {
    let idp = Idp::start().await;
    let server = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true, "registrations_per_hour_per_ip": 2 }),
    ));
    let body = json!({ "redirect_uris": [LOOPBACK] });
    let invalid = json!({ "redirect_uris": ["https://evil.example/cb"] });
    refused_registration(&register(&server, &invalid).await);
    registered(&register(&server, &body).await);
    registered(&register(&server, &body).await);
    let over = register(&server, &body).await;
    let error = refused_registration(&over);
    let RegistrationError::RateLimited { retry_after_secs } = *error else {
        panic!("expected the hourly allowance, got {error:?}");
    };
    assert!((1..=3600).contains(&retry_after_secs), "{retry_after_secs}");
    assert_eq!(error.status(), 429);
    assert!(over.audit_event("req").is_none(), "a flood is not audited");
    refused_registration(&register(&server, &body).await);
    registered(&register_from(&server, &body, None, "198.51.100.4").await);

    registered(&register_from(&server, &body, None, "2001:db8:1:2::10").await);
    registered(&register_from(&server, &body, None, "2001:db8:1:2:aaaa::20").await);
    refused_registration(&register_from(&server, &body, None, "2001:db8:1:2:ffff::30").await);
    registered(&register_from(&server, &body, None, "2001:db8:1:3::10").await);

    let replica = build(
        &with_registration(
            &idp,
            json!({ "enabled": true, "allow_open": true, "registrations_per_hour_per_ip": 2 }),
        ),
        state_of(&server).clone(),
    );
    registered(&register_from(&replica, &body, None, "198.51.100.4").await);
    assert!(
        matches!(
            refused_registration(&register_from(&server, &body, None, "198.51.100.4").await),
            RegistrationError::RateLimited { .. }
        ),
        "the allowance is counted across replicas"
    );

    let unlimited = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true, "registrations_per_hour_per_ip": 0 }),
    ));
    for _ in 0..3 {
        registered(&register(&unlimited, &body).await);
    }
    for _ in 0..3 {
        registered(
            &unlimited
                .register_client(body.to_string().as_bytes(), None, None)
                .await,
        );
    }
}

#[test]
fn an_address_is_counted_by_itself_or_its_ipv6_64() {
    let subject = |ip: &str| rate_subject(ip.parse().expect("IP"));
    assert_eq!(subject("203.0.113.7"), "203.0.113.7");
    assert_eq!(subject("::ffff:203.0.113.7"), "203.0.113.7");
    assert_eq!(subject("2001:db8:1:2::10"), subject("2001:db8:1:2:ffff::1"));
    assert_ne!(subject("2001:db8:1:2::10"), subject("2001:db8:1:3::10"));
}

#[tokio::test]
async fn max_clients_caps_registrations_until_older_ones_are_gone() {
    let idp = Idp::start().await;
    let server = server_with(&with_registration(
        &idp,
        json!({ "enabled": true, "allow_open": true, "max_clients": 2 }),
    ));
    let body = json!({ "redirect_uris": [LOOPBACK] });
    let first = registered(&register(&server, &body).await)
        .client_id
        .clone();
    registered(&register(&server, &body).await);
    let over = register(&server, &body).await;
    let error = refused_registration(&over);
    assert_eq!(*error, RegistrationError::TooManyClients);
    assert_eq!(error.status(), 503);
    assert_eq!(error.error(), "temporarily_unavailable");

    remove_registration(&server, &first).await;
    refused_registration(&register(&server, &body).await);
    state_of(&server)
        .unclaim(&keys::dcr_recount())
        .await
        .expect("store");
    registered(&register(&server, &body).await);
    assert_eq!(
        state_of(&server)
            .count(&keys::dcr_clients(), 100)
            .await
            .expect("store"),
        2
    );
    refused_registration(&register(&server, &body).await);
}

#[tokio::test]
async fn an_unavailable_store_registers_nothing_and_resolves_nothing() {
    let idp = Idp::start().await;
    let unavailable = InteractiveState::new(StateParts {
        kv: Arc::new(UnavailableStore::new("no coordinator store")),
        backend: StateBackend::Unavailable,
        keyring: Arc::new(StateKeyring::process().expect("key")),
        issuer: GW_ISSUER.to_owned(),
        revoked: Arc::default(),
        revocation_interval: Duration::from_secs(60),
    })
    .expect("state");
    let server = build(&with_registration(&idp, open_registration()), unavailable);
    let registration = register(&server, &json!({ "redirect_uris": [LOOPBACK] })).await;
    assert_eq!(
        *refused_registration(&registration),
        RegistrationError::Unavailable
    );
    let error = server
        .authorize_client(Some("mcpgdcr_0123456789abcdef"), Some(LOOPBACK_REQUEST))
        .await
        .expect_err("no store");
    assert_eq!(error.status(), 503);
    let redemption = server
        .redeem(
            refresh_form_for("mcpgdcr_0123456789abcdef", "mcpg_rt_x"),
            None,
        )
        .await;
    assert_eq!(refusal(&redemption).error, "temporarily_unavailable");
}

// ---------------------------------------------------------------------------
// A registered client signing its user in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registered_client_signs_in_through_consent_every_time() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let client_id = registered(
        &register(
            &server,
            &json!({
                "redirect_uris": [CURSOR_REDIRECT],
                "grant_types": ["authorization_code", "refresh_token"],
                "client_name": "Cursor",
            }),
        )
        .await,
    )
    .client_id
    .clone();
    state_of(&server)
        .touch(&registration_key(&client_id), Duration::from_secs(90))
        .await
        .expect("store");

    let response = server
        .authorize(
            &authorize_query(&client_id, CURSOR_REDIRECT, &fresh_challenge()),
            &BrowserCookies::default(),
        )
        .await;
    let BrowserOutcome::Consent(ref page) = response.outcome else {
        panic!(
            "a registered client sees the consent page: {:?}",
            response.outcome
        );
    };
    assert_eq!(page.client_kind, ClientKind::Dcr);
    assert_eq!(page.client_name, "Cursor");
    assert!(
        raw_expiry_secs(&server, &client_id).await <= 90,
        "an authorization request anyone can send keeps nothing alive"
    );
    let approved = approve(&server, &response).await;
    assert!(
        !approved.cookies.iter().any(|change| matches!(
            change,
            CookieChange::Set {
                cookie: BrowserCookie::ConsentMemory,
                ..
            }
        )),
        "an approval of a registered client is never remembered"
    );
    assert!(matches!(approved.outcome, BrowserOutcome::SignIn(_)));

    let remembered = state_of(&server)
        .seal_value(
            "consent_memory",
            &ConsentMemoryRecord {
                approvals: vec![ConsentApproval {
                    client_id: client_id.clone(),
                    redirect_uri: CURSOR_REDIRECT.to_owned(),
                    resource: RESOURCE.to_owned(),
                    scopes: vec!["mcp:tools".to_owned()],
                    approved_at: now_unix(),
                }],
            },
        )
        .expect("sealed");
    let again = server
        .authorize(
            &authorize_query(&client_id, CURSOR_REDIRECT, &fresh_challenge()),
            &BrowserCookies {
                csrf: None,
                consent_memory: Some(remembered),
            },
        )
        .await;
    assert!(
        matches!(again.outcome, BrowserOutcome::Consent(_)),
        "a consent cookie naming a registered client counts for nothing: {:?}",
        again.outcome
    );
}

/// Shorten the registration of `client_id` to 90 s.
async fn shorten(server: &AuthorizationServer, client_id: &str) {
    assert!(
        state_of(server)
            .touch(&registration_key(client_id), Duration::from_secs(90))
            .await
            .expect("store")
    );
}

/// Whether the registration of `client_id` lives its whole lifetime again.
async fn alive(server: &AuthorizationServer, client_id: &str) -> bool {
    raw_expiry_secs(server, client_id).await > 29 * 86_400
}

/// A client id is public, so a request that names it keeps nothing alive:
/// only a code issued to the client, a code or refresh token it redeemed,
/// or a token of its own it revoked restarts the registration's lifetime.
#[tokio::test]
async fn only_a_successful_use_restarts_a_registrations_lifetime() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let client_id = register_desktop(&server, &["authorization_code", "refresh_token"]).await;
    shorten(&server, &client_id).await;

    server
        .authorize_client(Some(&client_id), Some(LOOPBACK_REQUEST))
        .await
        .expect("known");
    let bad_code = server
        .redeem(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_AUTHORIZATION_CODE.to_owned()),
                client_id: Some(client_id.clone()),
                code: Some("mcpg_ac_not-a-code".to_owned()),
                code_verifier: Some("v".repeat(43)),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(bad_code.result.is_err());
    let bad_refresh = server
        .redeem(refresh_form_for(&client_id, "mcpg_rt_not-a-token"), None)
        .await;
    assert!(bad_refresh.result.is_err());
    let unknown = server
        .revoke_token(
            RevocationRequestForm {
                token: Some("mcpg_rt_not-a-token".to_owned()),
                client_id: Some(client_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(unknown.result.is_ok(), "an unknown token is answered 200");
    assert!(
        !alive(&server, &client_id).await,
        "requests that name the client id keep nothing alive"
    );

    let code = code_for(
        &server,
        &idp,
        &client_id,
        LOOPBACK_REQUEST,
        Some("idp-refresh-1"),
    )
    .await;
    assert!(alive(&server, &client_id).await, "a code issued to it");

    shorten(&server, &client_id).await;
    let redemption = server.redeem(code_form(&client_id, &code), None).await;
    let (response, _) = issued(&redemption);
    let refresh = response.refresh_token.clone().expect("a refresh token");
    assert!(alive(&server, &client_id).await, "a code it redeemed");

    shorten(&server, &client_id).await;
    let refreshed = server
        .redeem(refresh_form_for(&client_id, &refresh), None)
        .await;
    let rotated = issued(&refreshed).0.refresh_token.clone().expect("rotated");
    assert!(
        alive(&server, &client_id).await,
        "a refresh token it redeemed"
    );

    shorten(&server, &client_id).await;
    let revoked = server
        .revoke_token(
            RevocationRequestForm {
                token: Some(rotated),
                client_id: Some(client_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(revoked.result.is_ok(), "{:?}", revoked.result);
    assert!(
        alive(&server, &client_id).await,
        "a token of its own it revoked"
    );
}

#[tokio::test]
async fn a_registered_client_redeems_refreshes_and_is_known_by_its_registration() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let (client_id, access, refresh) = signed_in_desktop(&server, &idp).await;
    let caller = caller_of(&server, &access);
    assert_eq!(caller.attributes["client_id"], client_id);

    let redemption = server
        .redeem(refresh_form_for(&client_id, &refresh), None)
        .await;
    let (response, issued_token) = issued(&redemption);
    assert!(response.refresh_token.is_some());
    assert_eq!(
        issued_token.grant.as_ref().map(|grant| grant.client_kind),
        Some(ClientKind::Dcr)
    );
    let revocation = server
        .revoke_token(
            RevocationRequestForm {
                token: response.refresh_token.clone(),
                client_id: Some(client_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(revocation.result.is_ok(), "{:?}", revocation.result);
    assert_eq!(
        refused_bearer(&server, &response.access_token),
        "token revoked"
    );

    let code_only = register_desktop(&server, &["authorization_code"]).await;
    let code = code_for(
        &server,
        &idp,
        &code_only,
        LOOPBACK_REQUEST,
        Some("idp-refresh-2"),
    )
    .await;
    let redemption = server.redeem(code_form(&code_only, &code), None).await;
    assert!(
        issued(&redemption).0.refresh_token.is_none(),
        "no refresh token for a client that did not register refresh_token"
    );
    let refused = server
        .redeem(refresh_form_for(&code_only, "mcpg_rt_unused"), None)
        .await;
    assert_eq!(refusal(&refused).error, "unauthorized_client");
}

#[tokio::test]
async fn a_registered_client_is_public_and_never_redeems_id_jags() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let client_id = register_desktop(&server, &["authorization_code"]).await;
    let with_secret = server
        .redeem(
            TokenRequestForm {
                client_secret: Some("a-secret-it-never-had".to_owned()),
                ..refresh_form_for(&client_id, "mcpg_rt_x")
            },
            None,
        )
        .await;
    assert_eq!(refusal(&with_secret).error, "invalid_client");
    assert!(
        refusal(&with_secret).description.contains("public"),
        "{:?}",
        refusal(&with_secret)
    );
    let id_jag = server
        .redeem(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                client_id: Some(client_id.clone()),
                assertion: Some("an.id.jag".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await;
    assert_eq!(refusal(&id_jag).error, "unauthorized_client");
}

#[tokio::test]
async fn an_idp_with_allowed_clients_never_admits_a_registered_client() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let (client_id, access, refresh) = signed_in_desktop(&server, &idp).await;

    let mut restricted = with_registration(&idp, open_registration());
    restricted.trusted_idps[0].allowed_clients = vec![client_id.clone(), "web-app".to_owned()];
    let reloaded = build(&restricted, state_of(&server).clone());
    let response = reloaded
        .authorize(
            &authorize_query(&client_id, LOOPBACK_REQUEST, &fresh_challenge()),
            &BrowserCookies::default(),
        )
        .await;
    assert_eq!(
        error_redirect(&response)["error"],
        "access_denied",
        "not even when the list names the registration"
    );
    assert!(
        refused_bearer(&reloaded, &access).contains("no longer issue"),
        "its tokens are refused"
    );
    let redemption = reloaded
        .redeem(refresh_form_for(&client_id, &refresh), None)
        .await;
    assert_eq!(refusal(&redemption).error, "invalid_grant");
    assert!(matches!(
        redemption.context.grant_events.as_slice(),
        [GrantEvent::Revoked {
            reason: RevocationReason::ClientRemoved,
            ..
        }]
    ));
}

#[tokio::test]
async fn a_redirect_host_the_policy_no_longer_admits_stops_matching() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let client_id =
        registered(&register(&server, &json!({ "redirect_uris": [CURSOR_REDIRECT] })).await)
            .client_id
            .clone();
    let reloaded = build(
        &with_registration(&idp, json!({ "enabled": true, "allow_open": true })),
        state_of(&server).clone(),
    );
    let error = reloaded
        .authorize_client(Some(&client_id), Some(CURSOR_REDIRECT))
        .await
        .expect_err("the host is no longer admitted");
    assert!(
        error.description().contains("allowed_redirect_hosts"),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// A registration that is gone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_removed_registration_is_unknown_and_its_refresh_revokes_the_grant() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let (client_id, access, refresh) = signed_in_desktop(&server, &idp).await;
    let gid = grant_of(&access);
    remove_registration(&server, &client_id).await;

    let error = server
        .authorize_client(Some(&client_id), Some(LOOPBACK_REQUEST))
        .await
        .expect_err("unknown");
    assert_eq!(error.error(), "invalid_client");

    let redemption = server
        .redeem(refresh_form_for(&client_id, &refresh), None)
        .await;
    let error = refusal(&redemption);
    assert_eq!(error.error, "invalid_client");
    assert!(error.description.contains("register again"), "{error:?}");
    assert_eq!(
        redemption.context.grant_events,
        [GrantEvent::Revoked {
            gid,
            reason: RevocationReason::ClientRemoved,
            client_id: Some(client_id.clone()),
        }]
    );
    assert_eq!(refused_bearer(&server, &access), "token revoked");
}

#[tokio::test]
async fn a_removed_registrations_code_or_revocation_revokes_the_grant() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let client_id = register_desktop(&server, &["authorization_code"]).await;
    let code = code_for(&server, &idp, &client_id, LOOPBACK_REQUEST, None).await;
    remove_registration(&server, &client_id).await;
    let redemption = server.redeem(code_form(&client_id, &code), None).await;
    assert_eq!(refusal(&redemption).error, "invalid_client");
    assert!(matches!(
        redemption.context.grant_events.as_slice(),
        [GrantEvent::Revoked {
            reason: RevocationReason::ClientRemoved,
            ..
        }]
    ));

    let (client_id, access, _) = signed_in_desktop(&server, &idp).await;
    remove_registration(&server, &client_id).await;
    let revocation = server
        .revoke_token(
            RevocationRequestForm {
                token: Some(access.clone()),
                client_id: Some(client_id.clone()),
                ..Default::default()
            },
            None,
        )
        .await;
    assert_eq!(
        revocation.result.as_ref().expect_err("unknown").error,
        "invalid_client"
    );
    assert!(matches!(
        revocation.context.grant_events.as_slice(),
        [GrantEvent::Revoked {
            reason: RevocationReason::ClientRemoved,
            ..
        }]
    ));
    assert_eq!(refused_bearer(&server, &access), "token revoked");
}

#[tokio::test]
async fn only_the_registrations_own_grant_is_revoked() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let (_, access, refresh) = signed_in_desktop(&server, &idp).await;
    let other = register_desktop(&server, &["authorization_code", "refresh_token"]).await;
    remove_registration(&server, &other).await;
    let redemption = server
        .redeem(refresh_form_for(&other, &refresh), None)
        .await;
    assert_eq!(refusal(&redemption).error, "invalid_client");
    assert!(redemption.context.grant_events.is_empty());
    caller_of(&server, &access);

    let redemption = server
        .redeem(refresh_form_for("web-app-typo", &refresh), None)
        .await;
    assert!(redemption.context.grant_events.is_empty());
    caller_of(&server, &access);
}

#[tokio::test]
async fn turning_registration_off_refuses_registered_clients_without_revoking() {
    let idp = Idp::start().await;
    let server = registering(&idp);
    let (client_id, access, refresh) = signed_in_desktop(&server, &idp).await;
    let off = build(
        &with_registration(&idp, json!({ "enabled": false })),
        state_of(&server).clone(),
    );
    assert!(refused_bearer(&off, &access).contains("no longer registered"));
    let redemption = off
        .redeem(refresh_form_for(&client_id, &refresh), None)
        .await;
    assert_eq!(refusal(&redemption).error, "invalid_client");
    assert!(redemption.context.grant_events.is_empty());
    assert_eq!(
        off.authorize_client(Some(&client_id), Some(LOOPBACK_REQUEST))
            .await
            .expect_err("unknown"),
        AuthorizeClientError::UnknownClient
    );
    caller_of(&server, &access);
}

#[tokio::test]
async fn registration_outcomes_are_counted() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = Idp::start().await;
    let server = registering(&idp);
    registered(&register(&server, &json!({ "redirect_uris": [LOOPBACK] })).await);
    refused_registration(
        &register(
            &server,
            &json!({ "redirect_uris": ["https://evil.example/cb"] }),
        )
        .await,
    );
    ClientRegistration::malformed("not JSON".to_owned());
    for metric in [
        "mcpg_as_dcr_total{outcome=registered}",
        "mcpg_as_dcr_total{outcome=invalid_redirect_uri}",
        "mcpg_as_dcr_total{outcome=invalid_client_metadata}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}
