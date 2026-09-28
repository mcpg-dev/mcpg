//! Token endpoint client authentication: shared secrets, `private_key_jwt`
//! and Client ID Metadata Documents; the client of an authorization
//! request.

use super::*;
use crate::config::{
    ClientAuthMethod, ClientGrantType, ClientIdMetadataDocumentsConfig, RedirectUriPolicy,
};
use crate::runtime::authorization_server::redirect::{
    AuthorizeClient, AuthorizeClientError, ConsentRule, LoopbackHost, RedirectError,
    RedirectUriKind,
};
use crate::runtime::authorization_server::state::ClientKind;

const KEY_CLIENT: &str = "agent-with-keys";

/// A P-256 key a `private_key_jwt` client signs with, and its public JWKS.
struct ClientKey {
    encoding: EncodingKey,
    kid: String,
    jwks: serde_json::Value,
}

fn client_key(kid: &str) -> ClientKey {
    let encoding = EncodingKey::from_ec_pem(es256_pem().as_bytes()).expect("P-256 key parses");
    let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("public JWK");
    jwk.common.key_id = Some(kid.to_owned());
    ClientKey {
        encoding,
        kid: kid.to_owned(),
        jwks: serde_json::json!({ "keys": [jwk] }),
    }
}

/// The claims of a valid assertion for `client_id`.
fn assertion_claims(client_id: &str) -> serde_json::Value {
    let now = now_unix();
    serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": GW_ISSUER,
        "iat": now,
        "exp": now + 120,
        "jti": uuid::Uuid::new_v4().to_string(),
    })
}

fn sign_assertion(key: &ClientKey, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("client-authentication+jwt".to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding).expect("assertion encodes")
}

/// `claims` with `changes` set last.
fn with(mut claims: serde_json::Value, changes: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Object(changes) = changes {
        for (name, value) in changes {
            claims[name.as_str()] = value;
        }
    }
    claims
}

fn key_client(client_id: &str, jwks: serde_json::Value) -> AuthorizationServerClientConfig {
    AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
        jwks: Some(jwks),
        ..public_client(client_id)
    }
}

async fn server_with_clients(clients: Vec<AuthorizationServerClientConfig>) -> AuthorizationServer {
    let mut config = test_config();
    config.clients.extend(clients);
    config.validate().expect("client config validates");
    test_server_with(config).await
}

/// A `private_key_jwt` request redeeming an ID-JAG bound to `client_id`.
fn assertion_form(client_id: &'static str, client_assertion: String) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
        assertion: Some(make_id_jag(AssertionOverrides {
            client_id,
            ..Default::default()
        })),
        client_id: Some(client_id.to_owned()),
        client_assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned()),
        client_assertion: Some(client_assertion),
        ..Default::default()
    }
}

/// A request that presents no client credential beyond `client_id`.
fn public_form(client_id: &'static str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
        assertion: Some(make_id_jag(AssertionOverrides {
            client_id,
            ..Default::default()
        })),
        client_id: Some(client_id.to_owned()),
        ..Default::default()
    }
}

async fn refusal(server: &AuthorizationServer, form: TokenRequestForm) -> OAuthError {
    server
        .handle_token_request(form, None)
        .await
        .expect_err("the request is refused")
}

// ── private_key_jwt ──────────────────────────────────────────────────

#[tokio::test]
async fn a_private_key_jwt_client_redeems_its_id_jag() {
    let key = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let token = server
        .handle_token_request(
            assertion_form(
                KEY_CLIENT,
                sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
            ),
            None,
        )
        .await
        .expect("the client authenticates with its assertion");
    assert_eq!(minted_claims(&token.access_token)["client_id"], KEY_CLIENT);

    let meta = server.metadata();
    assert!(
        meta["token_endpoint_auth_methods_supported"]
            .as_array()
            .expect("methods")
            .contains(&serde_json::json!("private_key_jwt")),
        "{meta}"
    );
    let algs = meta["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .expect("RFC 8414 requires the algorithms with private_key_jwt");
    assert!(algs.contains(&serde_json::json!("ES256")));
    assert!(algs.contains(&serde_json::json!("RS256")));
    assert!(
        !algs
            .iter()
            .any(|alg| alg.as_str().is_some_and(|a| a.starts_with("HS")))
    );
}

/// RFC 7523 §3: without `client_id`, the assertion's `sub` names the
/// client.
#[tokio::test]
async fn the_assertion_sub_names_the_client_when_client_id_is_absent() {
    let key = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let mut form = assertion_form(
        KEY_CLIENT,
        sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
    );
    form.client_id = None;
    server
        .handle_token_request(form, None)
        .await
        .expect("sub identifies the client");

    // A client_id naming another client is judged by that client's method.
    let mut form = assertion_form(
        KEY_CLIENT,
        sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
    );
    form.client_id = Some(CLIENT_ID.to_owned());
    let err = refusal(&server, form).await;
    assert_eq!(err.error, "invalid_client");
}

#[tokio::test]
async fn the_assertion_audience_is_the_issuer_alone() {
    let key = client_key("k1");
    let token_endpoint = format!("{GW_ISSUER}{TOKEN_PATH}");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    for (aud, expected) in [
        (serde_json::json!(token_endpoint), "token endpoint"),
        (serde_json::json!("https://other.test"), "issuer"),
        (
            serde_json::json!([GW_ISSUER, "https://other.test"]),
            "exactly one value",
        ),
    ] {
        let claims = with(
            assertion_claims(KEY_CLIENT),
            serde_json::json!({ "aud": aud }),
        );
        let err = refusal(
            &server,
            assertion_form(KEY_CLIENT, sign_assertion(&key, &claims)),
        )
        .await;
        assert_eq!(err.error, "invalid_client", "aud {aud}");
        assert_eq!(
            err.status, 400,
            "no HTTP authentication scheme to challenge"
        );
        assert!(
            err.description.contains("aud") && err.description.contains(GW_ISSUER),
            "{}",
            err.description
        );
        if expected == "exactly one value" {
            assert!(err.description.contains(expected), "{}", err.description);
        }
    }
    // A one-element array naming the issuer is the issuer alone.
    let claims = with(
        assertion_claims(KEY_CLIENT),
        serde_json::json!({ "aud": [GW_ISSUER] }),
    );
    server
        .handle_token_request(
            assertion_form(KEY_CLIENT, sign_assertion(&key, &claims)),
            None,
        )
        .await
        .expect("a one-element aud is accepted");
}

#[tokio::test]
async fn the_token_endpoint_audience_is_accepted_only_by_opt_in() {
    let key = client_key("k1");
    let mut client = key_client(KEY_CLIENT, key.jwks.clone());
    client.accept_token_endpoint_audience = true;
    let server = server_with_clients(vec![client]).await;
    for aud in [format!("{GW_ISSUER}{TOKEN_PATH}"), GW_ISSUER.to_owned()] {
        let claims = with(
            assertion_claims(KEY_CLIENT),
            serde_json::json!({ "aud": aud }),
        );
        server
            .handle_token_request(
                assertion_form(KEY_CLIENT, sign_assertion(&key, &claims)),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("aud {aud} is accepted: {}", e.description));
    }
}

#[tokio::test]
async fn a_client_assertion_is_accepted_once() {
    let key = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let client_assertion = sign_assertion(&key, &assertion_claims(KEY_CLIENT));
    server
        .handle_token_request(assertion_form(KEY_CLIENT, client_assertion.clone()), None)
        .await
        .expect("first use");
    // A fresh ID-JAG, the same client assertion.
    let err = refusal(&server, assertion_form(KEY_CLIENT, client_assertion)).await;
    assert_eq!(err.error, "invalid_client");
    assert!(
        err.description.contains("already been used"),
        "{}",
        err.description
    );
}

/// The ledger that refuses a replayed ID-JAG also refuses a replayed
/// client assertion on another replica.
#[tokio::test]
async fn a_client_assertion_replay_is_refused_on_another_replica() {
    let key = client_key("k1");
    let mut config = test_config();
    config
        .clients
        .push(key_client(KEY_CLIENT, key.jwks.clone()));
    let ledger = ReplayLedger::shared(Arc::new(
        crate::builtins::cluster_primitives::MemoryKv::new(),
    ));
    let first = test_server_on(config.clone(), ledger.clone()).await;
    let second = test_server_on(config, ledger).await;
    let client_assertion = sign_assertion(&key, &assertion_claims(KEY_CLIENT));
    first
        .handle_token_request(assertion_form(KEY_CLIENT, client_assertion.clone()), None)
        .await
        .expect("first use");
    let err = refusal(&second, assertion_form(KEY_CLIENT, client_assertion)).await;
    assert!(
        err.description.contains("already been used"),
        "{}",
        err.description
    );
}

#[tokio::test]
async fn client_assertion_claims_are_enforced() {
    let key = client_key("k1");
    let stranger = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let now = now_unix();
    let cases = [
        (
            "far exp",
            sign_assertion(
                &key,
                &with(
                    assertion_claims(KEY_CLIENT),
                    serde_json::json!({ "exp": now + 3600 }),
                ),
            ),
            "more than 300 s ahead",
        ),
        (
            "expired",
            sign_assertion(
                &key,
                &with(
                    assertion_claims(KEY_CLIENT),
                    serde_json::json!({ "iat": now - 900, "exp": now - 600 }),
                ),
            ),
            "expired",
        ),
        (
            "no jti",
            sign_assertion(
                &key,
                &with(
                    assertion_claims(KEY_CLIENT),
                    serde_json::json!({ "jti": null }),
                ),
            ),
            "jti",
        ),
        (
            "iss is not the client",
            sign_assertion(
                &key,
                &with(
                    assertion_claims(KEY_CLIENT),
                    serde_json::json!({ "iss": "someone-else" }),
                ),
            ),
            "iss and sub",
        ),
        (
            "another key",
            sign_assertion(&stranger, &assertion_claims(KEY_CLIENT)),
            "signature",
        ),
    ];
    for (case, client_assertion, expected) in cases {
        let err = refusal(&server, assertion_form(KEY_CLIENT, client_assertion)).await;
        assert_eq!(err.error, "invalid_client", "{case}");
        assert!(
            err.description.contains(expected),
            "{case}: {}",
            err.description
        );
    }

    // A shared-secret signature is never a client assertion.
    let hmac = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &assertion_claims(KEY_CLIENT),
        &EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .expect("HS256 encodes");
    let err = refusal(&server, assertion_form(KEY_CLIENT, hmac)).await;
    assert!(err.description.contains("alg"), "{}", err.description);

    // A JWT typed as another kind of token is not a client assertion.
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("at+jwt".to_owned());
    let typed = jsonwebtoken::encode(&header, &assertion_claims(KEY_CLIENT), &key.encoding)
        .expect("assertion encodes");
    let err = refusal(&server, assertion_form(KEY_CLIENT, typed)).await;
    assert!(err.description.contains("typ"), "{}", err.description);
}

#[tokio::test]
async fn each_client_authenticates_only_its_own_way() {
    let key = client_key("k1");
    let basic_only = AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
        ..secret_client("basic-only", "basic-secret-0123")
    };
    let server =
        server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone()), basic_only]).await;

    // A private_key_jwt client presenting a secret.
    let mut form = public_form(KEY_CLIENT);
    form.client_secret = Some("guess".to_owned());
    let err = refusal(&server, form).await;
    assert_eq!(err.error, "invalid_client");
    assert!(
        err.description.contains("private_key_jwt"),
        "{}",
        err.description
    );

    // ...or nothing at all.
    let err = refusal(&server, public_form(KEY_CLIENT)).await;
    assert!(
        err.description.contains("private_key_jwt"),
        "{}",
        err.description
    );

    // A public client presenting an assertion.
    let err = refusal(
        &server,
        assertion_form(
            "public-client",
            sign_assertion(&key, &assertion_claims("public-client")),
        ),
    )
    .await;
    assert_eq!(err.error, "invalid_client");
    assert!(
        err.description.contains("public client"),
        "{}",
        err.description
    );

    // A client_secret_basic client posting its secret in the form.
    let mut form = public_form("basic-only");
    form.client_secret = Some("basic-secret-0123".to_owned());
    let err = refusal(&server, form).await;
    assert!(
        err.description.contains("client_secret_basic"),
        "{}",
        err.description
    );

    // ...and the same secret over HTTP Basic.
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("basic-only:basic-secret-0123")
    );
    let mut form = public_form("basic-only");
    form.client_id = None;
    server
        .handle_token_request(form, Some(&basic))
        .await
        .expect("client_secret_basic authenticates");
}

/// RFC 6749 §2.3: one authentication method per request.
#[tokio::test]
async fn two_authentication_methods_are_refused() {
    let key = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    let err = server
        .handle_token_request(
            token_form(&make_id_jag(AssertionOverrides::default())),
            Some(&basic),
        )
        .await
        .expect_err("Basic plus a form secret");
    assert_eq!(err.error, "invalid_request");
    assert_eq!(err.status, 400);

    let mut form = assertion_form(
        KEY_CLIENT,
        sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
    );
    form.client_secret = Some("also-a-secret".to_owned());
    let err = refusal(&server, form).await;
    assert_eq!(err.error, "invalid_request");
}

#[tokio::test]
async fn the_assertion_type_is_jwt_bearer() {
    let key = client_key("k1");
    let server = server_with_clients(vec![key_client(KEY_CLIENT, key.jwks.clone())]).await;
    let mut form = assertion_form(
        KEY_CLIENT,
        sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
    );
    form.client_assertion_type =
        Some("urn:ietf:params:oauth:client-assertion-type:saml2-bearer".to_owned());
    let err = refusal(&server, form).await;
    assert_eq!(err.error, "invalid_client");

    let mut form = assertion_form(
        KEY_CLIENT,
        sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
    );
    form.client_assertion_type = None;
    let err = refusal(&server, form).await;
    assert_eq!(err.error, "invalid_request");
}

async fn jwks_host(jwks: &serde_json::Value, fetches: u64) -> wiremock::MockServer {
    let host = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/client-jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(jwks))
        .expect(fetches)
        .mount(&host)
        .await;
    host
}

#[tokio::test]
async fn client_keys_are_fetched_from_jwks_uri_and_reused() {
    let key = client_key("k1");
    let host = jwks_host(&key.jwks, 1).await;
    let client = AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
        jwks_uri: Some(format!("{}/client-jwks", host.uri())),
        allow_private_network: true,
        ..public_client(KEY_CLIENT)
    };
    let server = server_with_clients(vec![client]).await;
    for _ in 0..2 {
        server
            .handle_token_request(
                assertion_form(
                    KEY_CLIENT,
                    sign_assertion(&key, &assertion_claims(KEY_CLIENT)),
                ),
                None,
            )
            .await
            .expect("the fetched key verifies");
    }
    host.verify().await;
}

// ── Client ID Metadata Documents ─────────────────────────────────────

/// A document host serving `document` (with `{url}` replaced by the
/// document's own URL) at `/client.json`, expecting `fetches` requests.
async fn document_host(
    document: serde_json::Value,
    fetches: u64,
) -> (wiremock::MockServer, &'static str) {
    let host = wiremock::MockServer::start().await;
    let url = leak(format!("{}/client.json", host.uri()));
    let body = document.to_string().replace("{url}", url);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/client.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_raw(body, "application/json")
                .insert_header("cache-control", "max-age=600"),
        )
        .expect(fetches)
        .mount(&host)
        .await;
    (host, url)
}

/// Metadata documents admitted from the loopback wiremock host.
fn documents_from_loopback() -> ClientIdMetadataDocumentsConfig {
    ClientIdMetadataDocumentsConfig {
        enabled: None,
        allowed_hosts: vec!["127.0.0.1".to_owned()],
        allow_private_network: true,
        redirect_uri_policy: Default::default(),
    }
}

async fn server_with_documents(
    clients: Vec<AuthorizationServerClientConfig>,
) -> AuthorizationServer {
    let mut config = test_config();
    config.clients.extend(clients);
    config.client_id_metadata_documents = documents_from_loopback();
    config.validate().expect("document config validates");
    test_server_with(config).await
}

#[tokio::test]
async fn a_metadata_document_client_redeems_as_a_public_client() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let (host, url) = document_host(
        serde_json::json!({
            "client_id": "{url}",
            "client_name": "Agent",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }),
        1,
    )
    .await;
    let server = server_with_documents(Vec::new()).await;
    for _ in 0..2 {
        let token = server
            .handle_token_request(public_form(url), None)
            .await
            .expect("the document identifies the client");
        assert_eq!(minted_claims(&token.access_token)["client_id"], url);
    }
    host.verify().await;
    assert!(
        captured.seen("mcpg_ema_client_metadata_fetch_total{outcome=ok}"),
        "{:?}",
        captured.recorded()
    );
}

#[tokio::test]
async fn a_metadata_document_must_name_its_own_url() {
    let (_host, url) = document_host(
        serde_json::json!({ "client_id": "https://elsewhere.test/client.json" }),
        1,
    )
    .await;
    let server = server_with_documents(Vec::new()).await;
    let err = refusal(&server, public_form(url)).await;
    assert_eq!(err.error, "invalid_client");
    assert!(
        err.description.contains("not the document URL"),
        "{}",
        err.description
    );
    // The refusal is remembered rather than refetched.
    let err = refusal(&server, public_form(url)).await;
    assert!(err.description.contains("not the document URL"));
}

#[tokio::test]
async fn only_allowed_hosts_are_fetched() {
    let (host, url) = document_host(serde_json::json!({ "client_id": "{url}" }), 0).await;
    let mut config = test_config();
    config.client_id_metadata_documents = ClientIdMetadataDocumentsConfig {
        allowed_hosts: vec!["agents.example".to_owned()],
        ..documents_from_loopback()
    };
    let server = test_server_with(config).await;
    let err = refusal(&server, public_form(url)).await;
    assert_eq!(err.error, "invalid_client");
    assert_eq!(err.description, "unknown client");
    host.verify().await;
}

/// A URL the draft does not allow is refused before it is fetched,
/// cached or echoed.
#[tokio::test]
async fn a_malformed_document_url_is_refused_before_any_fetch() {
    let server = server_with_documents(Vec::new()).await;
    let long = leak(format!("http://127.0.0.1:9/{}", "a".repeat(4096)));
    let err = refusal(&server, public_form(long)).await;
    assert_eq!(err.error, "invalid_client");
    assert_eq!(err.description, "the client_id is too long");
    let dotted = leak("http://127.0.0.1:9/agents/../client.json".to_owned());
    let err = refusal(&server, public_form(dotted)).await;
    assert!(
        err.description.contains("path segments"),
        "{}",
        err.description
    );
}

#[tokio::test]
async fn a_registered_entry_stands_in_for_the_document() {
    let (host, url) = document_host(
        serde_json::json!({ "client_id": "{url}", "token_endpoint_auth_method": "private_key_jwt" }),
        0,
    )
    .await;
    let server = server_with_documents(vec![public_client(url)]).await;
    server
        .handle_token_request(public_form(url), None)
        .await
        .expect("the registered public client needs no document");
    host.verify().await;
}

#[tokio::test]
async fn a_metadata_document_may_use_private_key_jwt() {
    let key = client_key("doc-key");
    let (_host, url) = document_host(
        serde_json::json!({
            "client_id": "{url}",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": key.jwks,
        }),
        1,
    )
    .await;
    let server = server_with_documents(Vec::new()).await;
    let err = refusal(&server, public_form(url)).await;
    assert!(
        err.description.contains("private_key_jwt"),
        "{}",
        err.description
    );
    server
        .handle_token_request(
            assertion_form(url, sign_assertion(&key, &assertion_claims(url))),
            None,
        )
        .await
        .expect("the document's key verifies the assertion");
}

#[tokio::test]
async fn unusable_metadata_documents_are_refused() {
    for (document, expected) in [
        (
            serde_json::json!({ "client_id": "{url}", "token_endpoint_auth_method": "client_secret_basic" }),
            "shared secret",
        ),
        (
            serde_json::json!({ "client_id": "{url}", "client_secret": "s3cret" }),
            "shared secret",
        ),
        (
            serde_json::json!({ "client_id": "{url}", "token_endpoint_auth_method": "tls_client_auth" }),
            "does not support",
        ),
        (
            serde_json::json!({ "client_id": "{url}", "token_endpoint_auth_method": "private_key_jwt" }),
            "without jwks",
        ),
        (
            serde_json::json!({ "token_endpoint_auth_method": "none" }),
            "no client_id",
        ),
        (
            serde_json::json!(["not", "an", "object"]),
            "not a client metadata document",
        ),
    ] {
        let (_host, url) = document_host(document.clone(), 1).await;
        let server = server_with_documents(Vec::new()).await;
        let err = refusal(&server, public_form(url)).await;
        assert_eq!(err.error, "invalid_client", "{document}");
        assert!(
            err.description.contains(expected),
            "{document}: {}",
            err.description
        );
    }
}

/// A document that publishes keys but names no method authenticates with
/// them: read as public, anyone holding one of its ID-JAGs could redeem
/// it without the client's key.
#[tokio::test]
async fn a_document_with_keys_and_no_method_is_private_key_jwt() {
    let key = client_key("doc-key");
    let (_host, url) = document_host(
        serde_json::json!({ "client_id": "{url}", "jwks": key.jwks }),
        1,
    )
    .await;
    let server = server_with_documents(Vec::new()).await;
    let err = refusal(&server, public_form(url)).await;
    assert_eq!(err.error, "invalid_client");
    assert!(
        err.description.contains("private_key_jwt"),
        "{}",
        err.description
    );
    server
        .handle_token_request(
            assertion_form(url, sign_assertion(&key, &assertion_claims(url))),
            None,
        )
        .await
        .expect("the document's key verifies the assertion");
}

/// A rate limit or a timeout from the document host may heal: the last
/// document that validated keeps serving, as for any outage.
#[tokio::test]
async fn a_rate_limited_refresh_keeps_the_cached_document() {
    let host = wiremock::MockServer::start().await;
    let url = leak(format!("{}/client.json", host.uri()));
    wiremock::Mock::given(wiremock::matchers::path("/client.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "client_id": url }))
                .insert_header("cache-control", "max-age=60"),
        )
        .up_to_n_times(1)
        .mount(&host)
        .await;
    wiremock::Mock::given(wiremock::matchers::path("/client.json"))
        .respond_with(wiremock::ResponseTemplate::new(429))
        .mount(&host)
        .await;
    let server = server_with_documents(Vec::new()).await;
    server
        .handle_token_request(public_form(url), None)
        .await
        .expect("the first fetch succeeds");

    server
        .client_metadata
        .as_ref()
        .expect("documents on")
        .age_document(url, Duration::from_secs(120))
        .await;
    server
        .handle_token_request(public_form(url), None)
        .await
        .expect("a 429 on refresh serves the cached document");
    assert_eq!(
        host.received_requests().await.map(|r| r.len()),
        Some(2),
        "the refresh was attempted"
    );
}

#[tokio::test]
async fn document_fetches_follow_no_redirect_and_read_a_bounded_body() {
    let host = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::path("/moved.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(302).insert_header("location", "/client.json"),
        )
        .mount(&host)
        .await;
    wiremock::Mock::given(wiremock::matchers::path("/big.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_raw(vec![b' '; 6 * 1024], "application/json"),
        )
        .mount(&host)
        .await;
    wiremock::Mock::given(wiremock::matchers::path("/page.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_raw("<html></html>", "text/html"),
        )
        .mount(&host)
        .await;
    wiremock::Mock::given(wiremock::matchers::path("/down.json"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&host)
        .await;
    let server = server_with_documents(Vec::new()).await;
    for (path, error, expected) in [
        ("/moved.json", "invalid_client", "redirect"),
        ("/big.json", "invalid_client", "more than 5120 bytes"),
        ("/page.json", "invalid_client", "application/json"),
        ("/down.json", "temporarily_unavailable", "retry shortly"),
    ] {
        let url = leak(format!("{}{path}", host.uri()));
        let err = refusal(&server, public_form(url)).await;
        assert_eq!(err.error, error, "{path}: {}", err.description);
        assert!(
            err.description.contains(expected),
            "{path}: {}",
            err.description
        );
    }
}

#[tokio::test]
async fn metadata_advertises_what_clients_can_use() {
    // No URL client: no metadata documents, the registered methods only.
    let meta = test_server().await.metadata();
    assert!(
        meta.get("client_id_metadata_document_supported").is_none(),
        "{meta}"
    );
    assert!(
        meta.get("token_endpoint_auth_signing_alg_values_supported")
            .is_none()
    );
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
    );

    // A registered URL client turns metadata documents on.
    let mut config = test_config();
    config.clients = vec![public_client("https://claude.example/oauth/client.json")];
    let meta = test_server_with(config).await.metadata();
    assert_eq!(meta["client_id_metadata_document_supported"], true);
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none"])
    );

    // Admitted hosts add both methods a document may declare.
    let mut config = test_config();
    config.clients.clear();
    config.client_id_metadata_documents.allowed_hosts = vec!["claude.example".to_owned()];
    config
        .validate()
        .expect("documents alone may admit clients");
    let meta = test_server_with(config).await.metadata();
    assert_eq!(meta["client_id_metadata_document_supported"], true);
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        serde_json::json!(["private_key_jwt", "none"])
    );
    assert!(meta["token_endpoint_auth_signing_alg_values_supported"].is_array());

    // Turned off explicitly, a URL client is just a client.
    let mut config = test_config();
    config.clients = vec![public_client("https://claude.example/oauth/client.json")];
    config.client_id_metadata_documents.enabled = Some(false);
    let meta = test_server_with(config).await.metadata();
    assert!(meta.get("client_id_metadata_document_supported").is_none());
}

#[test]
fn document_lifetime_follows_cache_control() {
    let lifetime = |value: Option<&str>| {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(
                reqwest::header::CACHE_CONTROL,
                value.parse().expect("header value"),
            );
        }
        clients::document_lifetime(&headers).as_secs()
    };
    assert_eq!(lifetime(None), 300);
    assert_eq!(lifetime(Some("public, max-age=900")), 900);
    assert_eq!(lifetime(Some("max-age=5")), 60, "the floor");
    assert_eq!(lifetime(Some("max-age=31536000")), 86_400, "the ceiling");
    assert_eq!(lifetime(Some("no-store")), 60);
    assert_eq!(lifetime(Some("max-age=nonsense")), 300);
}

#[test]
fn client_id_urls_follow_the_draft() {
    let problem = |url: &str| clients::client_id_url_problem(url, false);
    assert_eq!(problem("https://agent.example/client.json"), None);
    assert_eq!(problem("https://agent.example/c?v=1"), None);
    assert!(problem("http://agent.example/client.json").is_some());
    assert!(problem("https://agent.example").is_some(), "no path");
    assert!(problem("https://agent.example/a/../client.json").is_some());
    assert!(problem("https://agent.example/./client.json").is_some());
    assert!(problem("https://user:pw@agent.example/client.json").is_some());
    assert!(problem("https://agent.example/client.json#frag").is_some());
    // The fetch requests the parsed URL, so any rewrite the parser makes
    // would fetch a document other than the one the client_id names.
    for rewritten in [
        "https://agent.example/a/%2e%2e/client.json",
        "https://agent.example/a/%2E/client.json",
        "https://agent.example/a\\client.json",
        "https://agent.example/client.json\r\nx: y",
        "https://agent.example/cli\tent.json",
        "https://Agent.Example/client.json",
        "https://agent.example:443/client.json",
        "https://agent.example?x/y",
    ] {
        assert!(
            problem(rewritten).is_some_and(|p| p.contains("canonical") || p.contains("path")),
            "{rewritten:?}: {:?}",
            problem(rewritten)
        );
    }
    assert_eq!(
        clients::client_id_url_problem("http://127.0.0.1:8080/client.json", true),
        None,
        "http only with allow_private_network"
    );
}

// ── configuration ────────────────────────────────────────────────────

#[test]
fn client_authentication_config_is_validated() {
    let jwks = client_key("k1").jwks;
    let refused = |client: AuthorizationServerClientConfig| {
        let mut config = test_config();
        config.clients.push(client);
        validation_error(&config)
    };
    let err = refused(AuthorizationServerClientConfig {
        jwks: Some(jwks.clone()),
        ..secret_client("both", "s3cret")
    });
    assert!(err.contains("set token_endpoint_auth_method"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretPost),
        ..public_client("no-secret")
    });
    assert!(err.contains("needs a client_secret"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
        ..public_client("no-keys")
    });
    assert!(err.contains("set jwks or jwks_uri"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        jwks_uri: Some("https://keys.example/jwks".to_owned()),
        ..key_client("both-keys", jwks.clone())
    });
    assert!(err.contains("not both"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::None),
        ..secret_client("public-with-secret", "s3cret")
    });
    assert!(err.contains("takes no client_secret"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        accept_token_endpoint_audience: true,
        ..public_client("public-with-aud")
    });
    assert!(err.contains("private_key_jwt clients only"), "{err}");
    let err = refused(key_client(
        "symmetric",
        serde_json::json!({ "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] }),
    ));
    assert!(err.contains("symmetric"), "{err}");
    let err = refused(AuthorizationServerClientConfig {
        token_endpoint_auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
        jwks_uri: Some("http://keys.internal/jwks".to_owned()),
        ..public_client("http-keys")
    });
    assert!(err.contains("jwks_uri"), "{err}");

    // Keys alone imply private_key_jwt; a placeholder is judged after
    // expansion.
    let mut config = test_config();
    config.clients.push(AuthorizationServerClientConfig {
        jwks: Some(serde_json::json!("${env.CLIENT_JWKS}")),
        ..public_client("keys-from-env")
    });
    config
        .validate()
        .expect("a placeholder waits for expansion");
    assert_eq!(
        config.clients[2].effective_auth_methods(),
        Some(&[ClientAuthMethod::PrivateKeyJwt][..])
    );
}

#[test]
fn metadata_document_config_is_validated() {
    let mut config = test_config();
    config.client_id_metadata_documents.enabled = Some(false);
    config.client_id_metadata_documents.allowed_hosts = vec!["claude.example".to_owned()];
    assert!(validation_error(&config).contains("no effect while enabled is false"));

    let mut config = test_config();
    config.client_id_metadata_documents.allowed_hosts = vec!["https://claude.example".to_owned()];
    assert!(validation_error(&config).contains("bare host name"));

    // No client at all, and no document admitted.
    let mut config = test_config();
    config.clients.clear();
    assert!(validation_error(&config).contains("at least one OAuth client"));

    // allowed_clients may name a document URL on an admitted host.
    let mut config = test_config();
    config.client_id_metadata_documents.allowed_hosts = vec!["claude.example".to_owned()];
    config.trusted_idps[0].allowed_clients =
        vec!["https://agents.claude.example/client.json".to_owned()];
    config
        .validate()
        .expect("an admitted document URL is a known client");
    config.trusted_idps[0].allowed_clients = vec!["https://other.example/client.json".to_owned()];
    assert!(validation_error(&config).contains("allowed_clients"));
}

#[test]
fn client_secrets_never_reach_debug_output() {
    let rendered = format!("{:?}", secret_client("c", "do-not-print-me"));
    assert!(!rendered.contains("do-not-print-me"), "{rendered}");
    assert!(rendered.contains("[redacted]"));
}

// ── The client of an authorization request ───────────────────────────

const CLAUDE_URL: &str = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const CLAUDE_DOCUMENT: &str = r#"{
  "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
  "client_name": "Claude",
  "client_uri": "https://claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}"#;
const CLAUDE_CODE_URL: &str = "https://claude.ai/oauth/claude-code-client-metadata";
const CLAUDE_CODE_DOCUMENT: &str = r#"{
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "client_name": "Claude Code",
  "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}"#;
const VSCODE_URL: &str = "https://vscode.dev/oauth/client-metadata.json";
const VSCODE_DOCUMENT: &str = r#"{
  "client_id": "https://vscode.dev/oauth/client-metadata.json",
  "client_name": "Visual Studio Code",
  "client_uri": "https://code.visualstudio.com",
  "redirect_uris": ["http://127.0.0.1:33418/", "https://vscode.dev/redirect"],
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "native"
}"#;

/// Documents admitted from `hosts` under `policy`.
fn documents_on(hosts: &[&str], policy: RedirectUriPolicy) -> ClientIdMetadataDocumentsConfig {
    ClientIdMetadataDocumentsConfig {
        enabled: None,
        allowed_hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        allow_private_network: false,
        redirect_uri_policy: policy,
    }
}

/// The client the document `body` served at `url` describes.
fn document_client(
    url: &str,
    body: &str,
    config: &ClientIdMetadataDocumentsConfig,
) -> clients::Client {
    match clients::client_from_document_body(url, body.as_bytes(), config) {
        Ok(client) => client,
        Err(error) => panic!("{url}: {error:?}"),
    }
}

fn fixture_client(url: &str, body: &str) -> clients::Client {
    document_client(
        url,
        body,
        &documents_on(&["claude.ai", "vscode.dev"], RedirectUriPolicy::SameHost),
    )
}

fn redirect_refusal(result: Result<AuthorizeClient, AuthorizeClientError>) -> RedirectError {
    match result {
        Err(AuthorizeClientError::Redirect(problem)) => problem,
        other => panic!("expected a redirect URI refusal, got {other:?}"),
    }
}

#[test]
fn claude_signs_in_through_its_hosted_callback() {
    let client = fixture_client(CLAUDE_URL, CLAUDE_DOCUMENT);
    let callback = "https://claude.ai/api/mcp/auth_callback";
    let signed_in = client
        .authorize(Some(callback))
        .expect("the hosted callback is registered");
    assert_eq!(signed_in.client_id, CLAUDE_URL);
    assert_eq!(signed_in.kind, ClientKind::Cimd);
    assert_eq!(signed_in.name.as_deref(), Some("Claude"));
    assert_eq!(signed_in.redirect.uri, callback);
    assert_eq!(signed_in.redirect.kind, RedirectUriKind::Https);
    assert!(
        !signed_in.redirect.trusted,
        "a document's https URI is self-asserted"
    );
    assert!(signed_in.refresh_allowed);
    assert_eq!(signed_in.consent, ConsentRule::Ask { rememberable: true });
    assert_eq!(
        client
            .authorize(None)
            .expect("one https URI may be omitted")
            .redirect
            .uri,
        callback
    );
    for requested in [
        "https://claude.ai/api/mcp/auth_callback/",
        "https://claude.ai/api/mcp/auth_callback?x=1",
        "https://claude.com/api/mcp/auth_callback",
    ] {
        assert_eq!(
            redirect_refusal(client.authorize(Some(requested))),
            RedirectError::NotRegistered,
            "{requested}"
        );
    }
}

#[test]
fn claude_code_signs_in_on_any_loopback_port() {
    let client = fixture_client(CLAUDE_CODE_URL, CLAUDE_CODE_DOCUMENT);
    for (requested, host) in [
        ("http://localhost:3118/callback", LoopbackHost::Localhost),
        ("http://localhost:54012/callback", LoopbackHost::Localhost),
        ("http://127.0.0.1:3118/callback", LoopbackHost::Ipv4),
    ] {
        let signed_in = client
            .authorize(Some(requested))
            .expect("a portless loopback registration takes any port");
        assert_eq!(signed_in.redirect.uri, requested, "sent byte for byte");
        assert_eq!(signed_in.redirect.kind, RedirectUriKind::Loopback(host));
        assert!(signed_in.redirect.trusted);
        assert_eq!(
            signed_in.consent,
            ConsentRule::Ask {
                rememberable: false
            },
            "a loopback sign-in is never remembered"
        );
    }
    assert_eq!(
        redirect_refusal(client.authorize(None)),
        RedirectError::Required,
        "only the request knows the port"
    );
    for requested in [
        "http://[::1]:3118/callback",
        "http://localhost:3118/callback/",
    ] {
        assert_eq!(
            redirect_refusal(client.authorize(Some(requested))),
            RedirectError::NotRegistered,
            "{requested}"
        );
    }
}

#[test]
fn vs_code_signs_in_with_or_without_the_slash() {
    let client = fixture_client(VSCODE_URL, VSCODE_DOCUMENT);
    for requested in [
        "http://127.0.0.1:33418/",
        "http://127.0.0.1:50123",
        "http://127.0.0.1:50123/",
    ] {
        let signed_in = client
            .authorize(Some(requested))
            .expect("the loopback port and an empty path match");
        assert_eq!(signed_in.redirect.uri, requested);
        assert_eq!(signed_in.application_type.as_deref(), Some("native"));
    }
    let web = client
        .authorize(Some("https://vscode.dev/redirect"))
        .expect("an https URI on the document's own host");
    assert!(!web.redirect.trusted);
    assert_eq!(
        redirect_refusal(client.authorize(Some("http://localhost:33418/"))),
        RedirectError::NotRegistered
    );
    assert!(matches!(
        redirect_refusal(client.authorize(Some("vscode://vscode.github-authentication/cb"))),
        RedirectError::Invalid(ref problem) if problem.contains("private-use")
    ));
}

/// What a document member does to sign-in.
enum SignIn {
    Allowed { refresh: bool },
    Unauthorized,
    Invalid(&'static str),
}

#[test]
fn a_documents_members_gate_sign_in_but_not_client_authentication() {
    const URL: &str = "https://agent.example/client.json";
    let config = documents_on(&["agent.example"], RedirectUriPolicy::SameHost);
    let base = serde_json::json!({
        "client_id": URL,
        "client_name": "Agent",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "token_endpoint_auth_method": "none",
    });
    for (changes, expected) in [
        (serde_json::json!({}), SignIn::Allowed { refresh: false }),
        (
            serde_json::json!({ "grant_types": ["authorization_code"] }),
            SignIn::Allowed { refresh: false },
        ),
        (
            serde_json::json!({ "grant_types": ["authorization_code", "refresh_token"] }),
            SignIn::Allowed { refresh: true },
        ),
        (
            serde_json::json!({ "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"] }),
            SignIn::Unauthorized,
        ),
        (
            serde_json::json!({ "grant_types": ["refresh_token"] }),
            SignIn::Unauthorized,
        ),
        (
            serde_json::json!({ "grant_types": "authorization_code" }),
            SignIn::Invalid("grant_types is not an array"),
        ),
        (
            serde_json::json!({ "response_types": ["code"] }),
            SignIn::Allowed { refresh: false },
        ),
        (
            serde_json::json!({ "response_types": ["token"] }),
            SignIn::Invalid("response_types"),
        ),
        (
            serde_json::json!({ "response_types": ["code", "token"] }),
            SignIn::Invalid("response_types"),
        ),
        (
            serde_json::json!({ "response_types": [] }),
            SignIn::Invalid("response_types"),
        ),
        (
            serde_json::json!({ "redirect_uris": null }),
            SignIn::Invalid("lists no redirect_uris"),
        ),
        (
            serde_json::json!({ "redirect_uris": [] }),
            SignIn::Invalid("lists no redirect_uris"),
        ),
        (
            serde_json::json!({ "redirect_uris": [7] }),
            SignIn::Invalid("not a string"),
        ),
        (
            serde_json::json!({ "redirect_uris": "http://127.0.0.1/callback" }),
            SignIn::Invalid("redirect_uris is not an array"),
        ),
        (
            serde_json::json!({ "client_name": null }),
            SignIn::Invalid("client_name"),
        ),
        (
            serde_json::json!({ "client_name": "\u{200B}\u{202E}" }),
            SignIn::Invalid("client_name"),
        ),
        (
            serde_json::json!({ "client_name": 5 }),
            SignIn::Invalid("client_name"),
        ),
    ] {
        let body = with(base.clone(), changes.clone()).to_string();
        // The token endpoint reads the document whatever these members hold.
        let client = document_client(URL, &body, &config);
        let result = client.authorize(Some("http://127.0.0.1:7/callback"));
        match (expected, result) {
            (SignIn::Allowed { refresh }, Ok(signed_in)) => {
                assert_eq!(signed_in.refresh_allowed, refresh, "{changes}");
            }
            (SignIn::Unauthorized, Err(AuthorizeClientError::Unauthorized(reason))) => {
                assert!(reason.contains("authorization_code"), "{changes}: {reason}");
            }
            (SignIn::Invalid(expected), Err(AuthorizeClientError::InvalidDocument(reason))) => {
                assert!(reason.contains(expected), "{changes}: {reason}");
            }
            (_, other) => panic!("{changes}: {other:?}"),
        }
    }

    let typed = |application_type: &str| {
        let body = with(
            base.clone(),
            serde_json::json!({ "application_type": application_type }),
        )
        .to_string();
        document_client(URL, &body, &config)
            .authorize(Some("http://127.0.0.1:7/callback"))
            .expect("signs in")
            .application_type
    };
    assert_eq!(typed("web").as_deref(), Some("web"));
    assert_eq!(typed("desktop"), None);
}

#[test]
fn a_document_redirects_only_to_hosts_its_policy_admits() {
    const URL: &str = "https://agent.example/client.json";
    let body = serde_json::json!({
        "client_id": URL,
        "client_name": "Agent",
        "redirect_uris": ["https://agent.example/cb", "https://partner.example/cb"],
    })
    .to_string();
    let same_host = document_client(
        URL,
        &body,
        &documents_on(&["agent.example"], RedirectUriPolicy::SameHost),
    );
    same_host
        .authorize(Some("https://agent.example/cb"))
        .expect("the document's own host");
    let refused = redirect_refusal(same_host.authorize(Some("https://partner.example/cb")));
    assert!(
        matches!(refused, RedirectError::Refused(ref reason) if reason.contains("same_host")),
        "{refused:?}"
    );

    let allowed = document_client(
        URL,
        &body,
        &documents_on(
            &["agent.example", "partner.example"],
            RedirectUriPolicy::AllowedHosts,
        ),
    );
    allowed
        .authorize(Some("https://partner.example/cb"))
        .expect("an admitted host under allowed_hosts");
}

/// A sign-in document for `url` listing `redirect_uris`.
fn sign_in_document(url: &str, redirect_uris: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "client_id": url,
        "client_name": "Agent",
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
    })
}

async fn requests(host: &wiremock::MockServer) -> usize {
    host.received_requests().await.map_or(0, |seen| seen.len())
}

fn documents_of(server: &AuthorizationServer) -> &clients::ClientMetadataDocuments {
    server.client_metadata.as_ref().expect("documents on")
}

#[tokio::test]
async fn sign_in_reads_only_a_fresh_document() {
    let host = wiremock::MockServer::start().await;
    let url = leak(format!("{}/client.json", host.uri()));
    wiremock::Mock::given(wiremock::matchers::path("/client.json"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(sign_in_document(url, &["http://127.0.0.1/callback"]))
                .insert_header("cache-control", "max-age=60"),
        )
        .up_to_n_times(1)
        .mount(&host)
        .await;
    wiremock::Mock::given(wiremock::matchers::path("/client.json"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&host)
        .await;
    let server = server_with_documents(Vec::new()).await;
    let redirect = Some("http://127.0.0.1:4000/callback");
    server
        .authorize_client(Some(url), redirect)
        .await
        .expect("a fresh document serves sign-in");

    documents_of(&server)
        .age_document(url, Duration::from_secs(120))
        .await;
    let err = server
        .authorize_client(Some(url), redirect)
        .await
        .expect_err("a stale document never serves sign-in");
    assert_eq!(err, AuthorizeClientError::DocumentUnavailable);
    assert_eq!(err.status(), 503);
    assert_eq!(requests(&host).await, 2, "the refresh was attempted");

    server
        .handle_token_request(public_form(url), None)
        .await
        .expect("client authentication still takes the stale document");
    assert_eq!(requests(&host).await, 2);
}

#[tokio::test]
async fn a_redirect_uri_missing_from_a_cached_document_refetches_it_once() {
    let host = wiremock::MockServer::start().await;
    let url = leak(format!("{}/client.json", host.uri()));
    let added = "https://127.0.0.1/added";
    for (document, times) in [
        (
            sign_in_document(url, &["http://127.0.0.1/callback"]),
            Some(1),
        ),
        (
            sign_in_document(url, &["http://127.0.0.1/callback", added]),
            None,
        ),
    ] {
        let mock = wiremock::Mock::given(wiremock::matchers::path("/client.json")).respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(document)
                .insert_header("cache-control", "max-age=600"),
        );
        match times {
            Some(times) => mock.up_to_n_times(times).mount(&host).await,
            None => mock.mount(&host).await,
        }
    }
    let server = server_with_documents(Vec::new()).await;

    // A miss on the document just fetched fetches nothing more.
    assert_eq!(
        redirect_refusal(server.authorize_client(Some(url), Some(added)).await),
        RedirectError::NotRegistered
    );
    assert_eq!(requests(&host).await, 1);
    // Within the retry spacing the cached document answers.
    assert_eq!(
        redirect_refusal(server.authorize_client(Some(url), Some(added)).await),
        RedirectError::NotRegistered
    );
    assert_eq!(requests(&host).await, 1);

    // Once the spacing allows, a miss fetches the document again.
    documents_of(&server)
        .age_document(url, Duration::ZERO)
        .await;
    let signed_in = server
        .authorize_client(Some(url), Some(added))
        .await
        .expect("the refetched document lists it");
    assert_eq!(signed_in.redirect.uri, added);
    assert_eq!(requests(&host).await, 2);
    // A hit on the cached document fetches nothing.
    server
        .authorize_client(Some(url), Some("http://127.0.0.1:9/callback"))
        .await
        .expect("still registered");
    assert_eq!(requests(&host).await, 2);
}

#[tokio::test]
async fn a_document_signs_in_only_with_a_name_and_redirect_uris() {
    for (document, missing) in [
        (
            serde_json::json!({
                "client_id": "{url}",
                "client_name": "Agent",
                "token_endpoint_auth_method": "none",
            }),
            "redirect_uris",
        ),
        (
            serde_json::json!({
                "client_id": "{url}",
                "redirect_uris": ["http://127.0.0.1/callback"],
                "token_endpoint_auth_method": "none",
            }),
            "client_name",
        ),
    ] {
        let (host, url) = document_host(document, 1).await;
        let server = server_with_documents(Vec::new()).await;
        let err = server
            .authorize_client(Some(url), Some("http://127.0.0.1:9/callback"))
            .await
            .expect_err("sign-in needs the member");
        assert!(
            matches!(err, AuthorizeClientError::InvalidDocument(ref reason) if reason.contains(missing)),
            "{err:?}"
        );
        assert_eq!(err.status(), 400);
        server
            .handle_token_request(public_form(url), None)
            .await
            .expect("the document still authenticates its client");
        host.verify().await;
    }
}

/// `config` with a login block on its trusted IdP.
fn with_login(mut config: AuthorizationServerConfig) -> AuthorizationServerConfig {
    config.trusted_idps[0].login = Some(
        serde_json::from_value(serde_json::json!({
            "client_id": "gw-login",
            "client_secret": "login-secret-0123456789",
        }))
        .expect("login block parses"),
    );
    config
}

fn interactive_client(client_id: &str, redirect_uris: &[&str]) -> AuthorizationServerClientConfig {
    AuthorizationServerClientConfig {
        redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
        ..public_client(client_id)
    }
}

/// A registered client redeems ID-JAGs only when its `grant_types` hold
/// jwt-bearer: the defaults of a client with `redirect_uris` do not, and
/// those of a client without them do.
#[tokio::test]
async fn registered_clients_redeem_id_jags_by_their_grant_types() {
    let mut config = with_login(test_config());
    let mut both = interactive_client("both", &["https://app.example/cb"]);
    both.grant_types = Some(vec![
        ClientGrantType::JwtBearer,
        ClientGrantType::AuthorizationCode,
    ]);
    config.clients.extend([
        interactive_client("sign-in-only", &["https://app.example/cb"]),
        both,
    ]);
    config.validate().expect("clients validate");
    let server = test_server_with(config).await;

    let err = refusal(&server, public_form("sign-in-only")).await;
    assert_eq!(err.error, "unauthorized_client");
    assert_eq!(err.status, 400);
    assert!(
        err.description.contains("jwt-bearer"),
        "{}",
        err.description
    );

    server
        .handle_token_request(public_form("both"), None)
        .await
        .expect("jwt-bearer is among its grant_types");
    server
        .handle_token_request(public_form("public-client"), None)
        .await
        .expect("a client without redirect_uris redeems ID-JAGs by default");
}

#[tokio::test]
async fn registered_clients_sign_in_by_their_grant_types() {
    let mut config = with_login(test_config());
    let mut code_only = interactive_client("code-only", &["https://app.example/cb"]);
    code_only.grant_types = Some(vec![ClientGrantType::AuthorizationCode]);
    code_only.client_name = Some("Code Only".to_owned());
    config.clients.extend([
        interactive_client(
            "desktop",
            &["https://app.example/cb", "http://127.0.0.1/callback"],
        ),
        code_only,
    ]);
    config.validate().expect("interactive clients validate");
    let server = test_server_with(config).await;

    let err = server
        .authorize_client(Some(CLIENT_ID), Some("https://app.example/cb"))
        .await
        .expect_err("a client registered for ID-JAGs only");
    assert!(
        matches!(err, AuthorizeClientError::Unauthorized(ref reason) if reason.contains("authorization_code")),
        "{err:?}"
    );
    assert_eq!(err.error(), "unauthorized_client");

    let loopback = server
        .authorize_client(Some("desktop"), Some("http://127.0.0.1:5555/callback"))
        .await
        .expect("any port of the registered loopback URI");
    assert_eq!(loopback.kind, ClientKind::Static);
    assert_eq!(loopback.redirect.uri, "http://127.0.0.1:5555/callback");
    assert!(loopback.redirect.trusted);
    assert!(
        loopback.refresh_allowed,
        "redirect_uris imply refresh_token"
    );
    assert_eq!(
        loopback.consent,
        ConsentRule::Ask {
            rememberable: false
        }
    );
    let https = server
        .authorize_client(Some("desktop"), Some("https://app.example/cb"))
        .await
        .expect("the registered https URI");
    assert!(https.redirect.trusted, "the operator vetted it");
    assert_eq!(https.consent, ConsentRule::Ask { rememberable: true });
    assert_eq!(
        redirect_refusal(server.authorize_client(Some("desktop"), None).await),
        RedirectError::Required
    );

    let code_only = server
        .authorize_client(Some("code-only"), None)
        .await
        .expect("its one https URI is used");
    assert!(!code_only.refresh_allowed);
    assert_eq!(code_only.name.as_deref(), Some("Code Only"));
    assert_eq!(code_only.redirect.uri, "https://app.example/cb");
    assert_eq!(code_only.consent, ConsentRule::Skip { explicit: false });
}

#[tokio::test]
async fn unknown_or_missing_clients_are_refused() {
    let server = test_server().await;
    for (client_id, expected) in [
        (None, AuthorizeClientError::MissingClientId),
        (Some(""), AuthorizeClientError::MissingClientId),
        (Some("nobody"), AuthorizeClientError::UnknownClient),
        (
            Some("https://agents.example/client.json"),
            AuthorizeClientError::UnknownClient,
        ),
    ] {
        assert_eq!(
            server.authorize_client(client_id, None).await,
            Err(expected),
            "{client_id:?}"
        );
    }

    // A document URL the configuration admits must be canonical before
    // anything is fetched.
    let server = server_with_documents(Vec::new()).await;
    let err = server
        .authorize_client(Some("http://127.0.0.1:9/agents/../client.json"), None)
        .await
        .expect_err("dot segments are refused");
    assert!(
        matches!(err, AuthorizeClientError::InvalidDocument(ref reason) if reason.contains("path segments")),
        "{err:?}"
    );
}
