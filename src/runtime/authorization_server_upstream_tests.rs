use super::*;
use crate::runtime::authorization_server::{CachedJwks, ReplayLedger};
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const IDP_PRIVATE_PEM: &str = include_str!("testdata/idp_private.pem");
const IDP_JWKS: &str = include_str!("testdata/idp_jwks.json");
const IDP_KID: &str = "ema-test-key";
const IDP_ISSUER: &str = "https://idp.test";
const GW_ISSUER: &str = "https://gw.test";
const CALLBACK: &str = "https://gw.test/oauth/callback";
const LOGIN_CLIENT_ID: &str = "gw-login";
const LOGIN_SECRET: &str = "login-secret-0123456789";
const NONCE: &str = "n0nce-from-the-transaction";
const SUBJECT: &str = "00u-user-1";

// ── fixtures ─────────────────────────────────────────────────────────

/// `base` with every member of `extra` set over it; `null` unsets.
fn merged(mut base: Value, extra: Value) -> Value {
    if let Some(extra) = extra.as_object() {
        for (key, value) in extra {
            base[key] = value.clone();
        }
    }
    base
}

/// A server whose one trusted IdP, `issuer`, has a login block of
/// `login` over a `client_secret_basic` default, and `idp` over the entry.
fn config(issuer: &str, login: Value, idp: Value) -> AuthorizationServerConfig {
    let login = merged(
        json!({ "client_id": LOGIN_CLIENT_ID, "client_secret": LOGIN_SECRET }),
        login,
    );
    let idp = merged(
        json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "allow_private_network": true,
            "allowed_algs": ["RS256", "ES256"],
            "login": login,
        }),
        idp,
    );
    serde_json::from_value(json!({
        "issuer": GW_ISSUER,
        "signing_secret": "integration-signing-secret-0123456789",
        "clock_skew_secs": 60,
        "trusted_idps": [idp],
    }))
    .expect("authorization server config parses")
}

fn build(config: &AuthorizationServerConfig) -> AuthorizationServer {
    AuthorizationServer::from_config(config, None, ReplayLedger::in_process())
        .expect("server builds")
}

/// A server for `issuer` whose key cache holds the fixture keys.
async fn seeded(login: Value, idp: Value) -> AuthorizationServer {
    let server = build(&config(IDP_ISSUER, login, idp));
    *server.idps[0].keys.jwks.write().await = Some(CachedJwks {
        keys: serde_json::from_str(IDP_JWKS).expect("fixture JWKS parses"),
        fetched_at: Instant::now(),
    });
    server
}

/// The login endpoints of `idp`, configured.
fn endpoints(idp: &MockServer) -> Value {
    json!({
        "authorization_endpoint": format!("{}/authorize", idp.uri()),
        "token_endpoint": format!("{}/token", idp.uri()),
        "revocation_endpoint": format!("{}/revoke", idp.uri()),
    })
}

/// A server whose login endpoints are `idp`'s, with `login` over them.
fn endpoint_server(idp: &MockServer, login: Value) -> AuthorizationServer {
    build(&config(
        &idp.uri(),
        merged(endpoints(idp), login),
        json!({}),
    ))
}

fn login(server: &AuthorizationServer) -> LoginIdp<'_> {
    server.login_idp().expect("a login IdP is configured")
}

fn id_token_claims(issuer: &str) -> Value {
    let now = now_unix();
    json!({
        "iss": issuer,
        "sub": SUBJECT,
        "aud": LOGIN_CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "nonce": NONCE,
        "auth_time": now - 30,
        "email": "user@example.com",
    })
}

fn sign_with(claims: &Value, header: Header) -> String {
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(IDP_PRIVATE_PEM.as_bytes()).expect("fixture key parses"),
    )
    .expect("ID token encodes")
}

/// An RS256 ID token signed by the fixture IdP key, typed `typ`.
fn id_token_typed(claims: &Value, typ: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(IDP_KID.to_owned());
    header.typ = typ.map(str::to_owned);
    sign_with(claims, header)
}

fn id_token(claims: &Value) -> String {
    id_token_typed(claims, Some("JWT"))
}

const SIGN_IN: IdTokenCheck<'static> = IdTokenCheck::SignIn { nonce: NONCE };

async fn refused(server: &AuthorizationServer, token: &str, check: IdTokenCheck<'_>) -> String {
    match login(server).validate_id_token(token, check).await {
        Err(IdTokenError::Invalid(reason)) => reason,
        other => panic!("expected an invalid ID token, got {other:?}"),
    }
}

fn b64(value: &Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
}

// ── ID tokens ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_sign_in_id_token_that_passes_every_check_is_believed() {
    let server = seeded(json!({}), json!({})).await;
    let claims = id_token_claims(IDP_ISSUER);
    let validated = login(&server)
        .validate_id_token(&id_token(&claims), SIGN_IN)
        .await
        .expect("valid ID token");
    assert_eq!(validated.subject, SUBJECT);
    assert_eq!(validated.auth_time, claims["auth_time"].as_u64());
    assert_eq!(validated.expires_at, claims["exp"].as_u64().unwrap());
    assert_eq!(validated.claims["email"], "user@example.com");
}

/// One claim changed from a valid sign-in token, and the check it fails.
#[tokio::test]
async fn every_claim_check_refuses_its_mutation() {
    let server = seeded(json!({}), json!({})).await;
    let now = now_unix();
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "issuer with a trailing slash",
            json!({ "iss": "https://idp.test/" }),
            "iss",
        ),
        (
            "another issuer",
            json!({ "iss": "https://evil.test" }),
            "iss",
        ),
        (
            "an extra audience",
            json!({ "aud": [LOGIN_CLIENT_ID, "other-app"] }),
            "besides the login client",
        ),
        (
            "another audience",
            json!({ "aud": "other-app" }),
            "aud does not name",
        ),
        (
            "azp of another client",
            json!({ "azp": "other-app" }),
            "azp",
        ),
        ("no nonce", json!({ "nonce": null }), "nonce"),
        ("an empty nonce", json!({ "nonce": "" }), "nonce"),
        (
            "another nonce",
            json!({ "nonce": "n0nce-of-another-sign-in" }),
            "nonce",
        ),
        (
            "expired past the skew",
            json!({ "exp": now - 120 }),
            "expired",
        ),
        (
            "issued in the future",
            json!({ "iat": now + 120 }),
            "future",
        ),
        ("issued too long ago", json!({ "iat": now - 700 }), "600 s"),
        ("no iat", json!({ "iat": null }), "no iat"),
        ("an empty sub", json!({ "sub": " " }), "sub is empty"),
        ("no sub", json!({ "sub": null }), "sub"),
        ("an actor", json!({ "act": { "sub": "agent" } }), "act"),
        (
            "auth_time in the future",
            json!({ "auth_time": now + 600 }),
            "auth_time",
        ),
        ("nbf ahead", json!({ "nbf": now + 600 }), "nbf"),
    ];
    for (case, change, expected) in cases {
        let mut claims = id_token_claims(IDP_ISSUER);
        for (key, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(key);
            } else {
                claims[key] = value.clone();
            }
        }
        let reason = refused(&server, &id_token(&claims), SIGN_IN).await;
        assert!(reason.contains(expected), "{case}: {reason}");
        assert!(
            !reason.contains(SUBJECT) && !reason.contains(NONCE),
            "{case}: a claim value is quoted: {reason}"
        );
    }
}

#[tokio::test]
async fn tolerated_variations_still_verify() {
    let server = seeded(json!({}), json!({})).await;
    let now = now_unix();
    for change in [
        json!({ "aud": [LOGIN_CLIENT_ID] }),
        json!({ "azp": LOGIN_CLIENT_ID }),
        json!({ "exp": now - 30 }),
        json!({ "iat": now + 30 }),
        json!({ "iat": now - 590 }),
    ] {
        let claims = merged(id_token_claims(IDP_ISSUER), change.clone());
        login(&server)
            .validate_id_token(&id_token(&claims), SIGN_IN)
            .await
            .unwrap_or_else(|e| panic!("{change}: {e}"));
    }
}

/// RFC 8725 §3.11: a token typed as another kind is never an ID token,
/// whatever it says; an ID token typed `JWT` or untyped is.
#[tokio::test]
async fn a_token_typed_as_another_kind_is_refused() {
    let server = seeded(json!({}), json!({})).await;
    let claims = id_token_claims(IDP_ISSUER);
    for typ in [
        "at+jwt",
        "AT+JWT",
        "application/at+jwt",
        "oauth-id-jag+jwt",
        "application/oauth-id-jag+jwt",
        "logout+jwt",
    ] {
        let reason = refused(&server, &id_token_typed(&claims, Some(typ)), SIGN_IN).await;
        assert!(reason.contains("typ"), "{typ}: {reason}");
    }
    for typ in [Some("JWT"), None] {
        login(&server)
            .validate_id_token(&id_token_typed(&claims, typ), SIGN_IN)
            .await
            .unwrap_or_else(|e| panic!("{typ:?}: {e}"));
    }
}

#[tokio::test]
async fn unsigned_and_hmac_id_tokens_are_refused() {
    let server = seeded(json!({}), json!({})).await;
    let claims = id_token_claims(IDP_ISSUER);
    let unsigned = format!(
        "{}.{}.",
        b64(&json!({ "alg": "none", "typ": "JWT" })),
        b64(&claims)
    );
    let reason = refused(&server, &unsigned, SIGN_IN).await;
    assert!(reason.contains("well-formed"), "{reason}");

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(IDP_KID.to_owned());
    let hmac = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let reason = refused(&server, &hmac, SIGN_IN).await;
    assert!(reason.contains("HMAC"), "{reason}");
}

/// A sign-in checked against an empty nonce matches nothing, not even an
/// ID token whose nonce is empty too.
#[tokio::test]
async fn an_empty_expected_nonce_matches_nothing() {
    let server = seeded(json!({}), json!({})).await;
    let claims = merged(id_token_claims(IDP_ISSUER), json!({ "nonce": "" }));
    let reason = refused(
        &server,
        &id_token(&claims),
        IdTokenCheck::SignIn { nonce: "" },
    )
    .await;
    assert!(reason.contains("nonce"), "{reason}");
}

#[tokio::test]
async fn an_alg_outside_allowed_algs_is_refused() {
    let server = seeded(json!({}), json!({ "allowed_algs": ["ES256"] })).await;
    let reason = refused(&server, &id_token(&id_token_claims(IDP_ISSUER)), SIGN_IN).await;
    assert!(reason.contains("allowed_algs"), "{reason}");
}

#[tokio::test]
async fn a_tampered_id_token_is_refused() {
    let server = seeded(json!({}), json!({})).await;
    let token = id_token(&id_token_claims(IDP_ISSUER));
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    parts[1] = b64(&merged(
        id_token_claims(IDP_ISSUER),
        json!({ "sub": "00u-someone-else" }),
    ));
    let reason = refused(&server, &parts.join("."), SIGN_IN).await;
    assert!(reason.contains("signature"), "{reason}");
}

/// A key the IdP rotated in is fetched once; a kid it never published
/// stays unknown.
#[tokio::test]
async fn an_unknown_kid_refetches_the_keys_once() {
    let idp = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(IDP_JWKS, "application/json"))
        .expect(1)
        .mount(&idp)
        .await;
    let issuer = idp.uri();
    let server = build(&config(&issuer, json!({}), json!({})));
    let mut retired: JwkSet = serde_json::from_str(IDP_JWKS).unwrap();
    retired.keys[0].common.key_id = Some("retired-key".to_owned());
    *server.idps[0].keys.jwks.write().await = Some(CachedJwks {
        keys: retired,
        fetched_at: Instant::now(),
    });

    login(&server)
        .validate_id_token(&id_token(&id_token_claims(&issuer)), SIGN_IN)
        .await
        .expect("the refetched key set holds the kid");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("never-published".to_owned());
    let reason = refused(
        &server,
        &sign_with(&id_token_claims(&issuer), header),
        SIGN_IN,
    )
    .await;
    assert!(reason.contains("no published key"), "{reason}");
}

#[tokio::test]
async fn unreachable_keys_are_not_an_invalid_token() {
    let idp = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&idp)
        .await;
    let issuer = idp.uri();
    let server = build(&config(&issuer, json!({}), json!({})));
    let outcome = login(&server)
        .validate_id_token(&id_token(&id_token_claims(&issuer)), SIGN_IN)
        .await;
    assert_eq!(outcome.unwrap_err(), IdTokenError::KeysUnavailable);
}

#[tokio::test]
async fn max_age_requires_a_recent_auth_time_at_sign_in_only() {
    let server = seeded(json!({ "max_age_secs": 300 }), json!({})).await;
    let now = now_unix();
    let mut without = id_token_claims(IDP_ISSUER);
    without.as_object_mut().unwrap().remove("auth_time");
    let reason = refused(&server, &id_token(&without), SIGN_IN).await;
    assert!(reason.contains("auth_time"), "{reason}");

    let stale = merged(
        id_token_claims(IDP_ISSUER),
        json!({ "auth_time": now - 1000 }),
    );
    let reason = refused(&server, &id_token(&stale), SIGN_IN).await;
    assert!(reason.contains("max_age"), "{reason}");

    let recent = merged(
        id_token_claims(IDP_ISSUER),
        json!({ "auth_time": now - 100 }),
    );
    login(&server)
        .validate_id_token(&id_token(&recent), SIGN_IN)
        .await
        .expect("authenticated within max_age");

    // A refresh keeps the original auth_time, which max_age does not bound.
    let refreshed = merged(
        id_token_claims(IDP_ISSUER),
        json!({ "auth_time": now - 1000, "nonce": null }),
    );
    login(&server)
        .validate_id_token(
            &id_token(&refreshed),
            IdTokenCheck::Refresh {
                subject: SUBJECT,
                auth_time: Some(now - 1000),
            },
        )
        .await
        .expect("a refreshed token is not held to max_age");
}

/// OpenID Connect Core §12.2: the refreshed token names the same user and
/// the same authentication; it needs no nonce.
#[tokio::test]
async fn a_refreshed_id_token_must_name_the_same_sign_in() {
    let server = seeded(json!({}), json!({})).await;
    let now = now_unix();
    let mut claims = id_token_claims(IDP_ISSUER);
    claims.as_object_mut().unwrap().remove("nonce");
    let auth_time = claims["auth_time"].as_u64();
    let refresh = IdTokenCheck::Refresh {
        subject: SUBJECT,
        auth_time,
    };
    login(&server)
        .validate_id_token(&id_token(&claims), refresh)
        .await
        .expect("same sub and auth_time");
    login(&server)
        .validate_id_token(
            &id_token(&claims),
            IdTokenCheck::Refresh {
                subject: SUBJECT,
                auth_time: None,
            },
        )
        .await
        .expect("no auth_time to compare");

    let other_user = merged(claims.clone(), json!({ "sub": "00u-user-2" }));
    let reason = refused(&server, &id_token(&other_user), refresh).await;
    assert!(reason.contains("sub"), "{reason}");

    let reauthenticated = merged(claims, json!({ "auth_time": now - 5 }));
    let reason = refused(&server, &id_token(&reauthenticated), refresh).await;
    assert!(reason.contains("auth_time"), "{reason}");
}

// ── endpoints ────────────────────────────────────────────────────────

fn discovery_document(idp: &MockServer, extra: Value) -> Value {
    let uri = idp.uri();
    merged(
        json!({
            "issuer": uri,
            "authorization_endpoint": format!("{uri}/authorize"),
            "token_endpoint": format!("{uri}/token"),
            "revocation_endpoint": format!("{uri}/revoke"),
            "jwks_uri": format!("{uri}/jwks"),
            "authorization_response_iss_parameter_supported": true,
        }),
        extra,
    )
}

async fn serve_discovery(idp: &MockServer, document: Value, times: u64) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .expect(times)
        .mount(idp)
        .await;
}

#[tokio::test]
async fn discovery_reads_the_login_endpoints_once() {
    let idp = MockServer::start().await;
    serve_discovery(&idp, discovery_document(&idp, json!({})), 1).await;
    let server = build(&config(&idp.uri(), json!({}), json!({})));
    let uri = idp.uri();
    for _ in 0..2 {
        let metadata = login(&server).metadata().await.expect("discovered");
        assert_eq!(
            *metadata,
            IdpMetadata {
                authorization_endpoint: format!("{uri}/authorize"),
                token_endpoint: format!("{uri}/token"),
                revocation_endpoint: Some(format!("{uri}/revoke")),
                authorization_response_iss_parameter_supported: true,
            }
        );
    }
}

#[tokio::test]
async fn an_idp_without_a_revocation_endpoint_or_iss_support_is_usable() {
    let idp = MockServer::start().await;
    serve_discovery(
        &idp,
        discovery_document(
            &idp,
            json!({
                "revocation_endpoint": null,
                "authorization_response_iss_parameter_supported": null,
            }),
        ),
        1,
    )
    .await;
    let server = build(&config(&idp.uri(), json!({}), json!({})));
    let metadata = login(&server).metadata().await.expect("discovered");
    assert_eq!(metadata.revocation_endpoint, None);
    assert!(!metadata.authorization_response_iss_parameter_supported);
    assert_eq!(
        login(&server).revoke_refresh_token("rt-1").await,
        Ok(RevokeOutcome::NoEndpoint)
    );
}

/// RFC 8414 §3.3: the published issuer must be the configured one
/// exactly. The refusal holds without refetching until the retry spacing
/// passes.
#[tokio::test]
async fn a_discovered_issuer_that_differs_is_refused() {
    let idp = MockServer::start().await;
    let published = format!("{}/", idp.uri());
    serve_discovery(
        &idp,
        discovery_document(&idp, json!({ "issuer": published })),
        1,
    )
    .await;
    let server = build(&config(&idp.uri(), json!({}), json!({})));
    for _ in 0..2 {
        match login(&server).metadata().await {
            Err(UpstreamError::Misconfigured(reason)) => {
                assert!(reason.contains(&format!("`{published}`")), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_discovered_endpoint_outside_the_outbound_policy_is_refused() {
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({ "token_endpoint": "https://evil.example/token" }),
            "evil.example",
        ),
        (
            json!({ "authorization_endpoint": "https://idp.other.example/authorize" }),
            "idp.other.example",
        ),
        (
            json!({ "revocation_endpoint": "https://evil.example/revoke" }),
            "evil.example",
        ),
    ];
    for (change, host) in cases {
        let idp = MockServer::start().await;
        serve_discovery(&idp, discovery_document(&idp, change.clone()), 1).await;
        let server = build(&config(
            &idp.uri(),
            json!({}),
            json!({ "allowed_hosts": ["127.0.0.1"] }),
        ));
        match login(&server).metadata().await {
            Err(UpstreamError::Misconfigured(reason)) => {
                assert!(
                    reason.contains(host) && reason.contains("allowed_hosts"),
                    "{change}: {reason}"
                );
            }
            other => panic!("{change}: expected a refusal, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_discovered_endpoint_with_a_fragment_or_userinfo_is_refused() {
    for (change, expected) in [
        (
            json!({ "token_endpoint": "https://idp.example/token#x" }),
            "fragment",
        ),
        (
            json!({ "token_endpoint": "https://user:pw@idp.example/token" }),
            "userinfo",
        ),
        (
            json!({ "token_endpoint": null }),
            "carries no token_endpoint",
        ),
        (json!({ "token_endpoint": 7 }), "not a string"),
    ] {
        let idp = MockServer::start().await;
        serve_discovery(&idp, discovery_document(&idp, change.clone()), 1).await;
        let server = build(&config(&idp.uri(), json!({}), json!({})));
        match login(&server).metadata().await {
            Err(UpstreamError::Misconfigured(reason)) => {
                assert!(reason.contains(expected), "{change}: {reason}");
                assert!(
                    !reason.contains("allowed_hosts"),
                    "{change}: the host list cannot fix this: {reason}"
                );
            }
            other => panic!("{change}: expected a refusal, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn configured_endpoints_need_no_discovery() {
    let idp = MockServer::start().await;
    serve_discovery(&idp, discovery_document(&idp, json!({})), 0).await;
    let server = endpoint_server(&idp, json!({}));
    let metadata = login(&server).metadata().await.expect("configured");
    assert_eq!(metadata.token_endpoint, format!("{}/token", idp.uri()));
    assert!(!metadata.authorization_response_iss_parameter_supported);
}

#[tokio::test]
async fn a_configured_endpoint_wins_over_the_discovered_one() {
    let idp = MockServer::start().await;
    serve_discovery(&idp, discovery_document(&idp, json!({})), 1).await;
    let token_endpoint = format!("{}/custom/token", idp.uri());
    let server = build(&config(
        &idp.uri(),
        json!({ "token_endpoint": token_endpoint }),
        json!({}),
    ));
    let metadata = login(&server).metadata().await.expect("discovered");
    assert_eq!(metadata.token_endpoint, token_endpoint);
    assert_eq!(
        metadata.authorization_endpoint,
        format!("{}/authorize", idp.uri())
    );
}

#[test]
fn a_configured_endpoint_outside_the_outbound_policy_refuses_the_server() {
    let config = config(
        IDP_ISSUER,
        json!({ "token_endpoint": "https://evil.example/token" }),
        json!({ "allowed_hosts": ["idp.test"], "allow_private_network": false }),
    );
    let err = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
        .expect_err("the endpoint is refused");
    assert!(err.to_string().contains("login.token_endpoint"), "{err}");
}

/// A discovery outage with no endpoints ever read answers "unavailable",
/// and retries inside the spacing do not reach the IdP.
#[tokio::test]
async fn a_discovery_outage_is_transient() {
    let idp = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&idp)
        .await;
    let server = build(&config(&idp.uri(), json!({}), json!({})));
    for _ in 0..2 {
        let err = login(&server).metadata().await.expect_err("outage");
        assert!(err.is_transient(), "{err}");
    }
}

/// Endpoints past their reuse period keep serving while the IdP is down.
#[tokio::test]
async fn stale_endpoints_serve_through_a_discovery_outage() {
    let idp = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&idp)
        .await;
    let server = build(&config(&idp.uri(), json!({}), json!({})));
    let cached = Arc::new(IdpMetadata {
        authorization_endpoint: "https://idp.test/authorize".to_owned(),
        token_endpoint: "https://idp.test/token".to_owned(),
        revocation_endpoint: None,
        authorization_response_iss_parameter_supported: false,
    });
    let client = server.idps[0].login.as_ref().unwrap();
    *client.discovered.cached.write().await = Some(CachedMetadata {
        metadata: cached.clone(),
        fetched_at: Instant::now()
            .checked_sub(METADATA_TTL + Duration::from_secs(10))
            .unwrap(),
    });
    let metadata = login(&server).metadata().await.expect("stale but usable");
    assert_eq!(metadata, cached);
}

/// The timeout of an outbound request bounds the name lookup too: with no
/// time left, the request fails as transient before any connection.
#[tokio::test]
async fn the_timeout_covers_the_name_lookup() {
    let refused = pinned_client("http://localhost:9/token", true, Duration::ZERO)
        .await
        .expect_err("no time is left");
    assert!(
        matches!(refused, FetchFailure::Transient(ref error) if format!("{error:#}").contains("no answer within 0 ms")),
        "{refused:?}"
    );
}

/// A reload hands the discovered endpoints to the server it builds while
/// the IdP entry is unchanged, so the discovery document is not fetched
/// again; a changed entry discovers afresh.
#[tokio::test]
async fn a_reload_keeps_the_endpoints_of_an_unchanged_login_idp() {
    let idp = MockServer::start().await;
    serve_discovery(&idp, discovery_document(&idp, json!({})), 2).await;
    let unchanged = config(&idp.uri(), json!({}), json!({}));
    let booted = build(&unchanged);
    let discovered = login(&booted).metadata().await.expect("discovered");

    let reloaded = build(&unchanged).with_login_endpoints_of(Some(&booted));
    assert_eq!(
        login(&reloaded).metadata().await.expect("handed over"),
        discovered
    );

    let changed = build(&config(
        &idp.uri(),
        json!({ "scopes": ["openid", "email", "offline_access"] }),
        json!({}),
    ))
    .with_login_endpoints_of(Some(&reloaded));
    assert_eq!(
        login(&changed).metadata().await.expect("discovered again"),
        discovered
    );
}

// ── authorization request ────────────────────────────────────────────

#[tokio::test]
async fn the_authorization_url_carries_the_transaction_and_the_configuration() {
    let server = seeded(
        json!({
            "scopes": ["openid", "email", "offline_access"],
            "max_age_secs": 600,
            "authorize_params": { "acr_values": "phr", "domain_hint": "example.com" },
        }),
        json!({}),
    )
    .await;
    let metadata = IdpMetadata {
        authorization_endpoint: "https://idp.test/authorize?tenant=a".to_owned(),
        token_endpoint: "https://idp.test/token".to_owned(),
        revocation_endpoint: None,
        authorization_response_iss_parameter_supported: false,
    };
    let url = login(&server)
        .authorization_url(
            &metadata,
            &IdpAuthorizationRequest {
                state: "st&te",
                nonce: NONCE,
                code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                prompt: Some("login"),
                login_hint: Some("user@example.com"),
            },
        )
        .unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.path(), "/authorize");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    let expected: Vec<(&str, &str)> = vec![
        ("tenant", "a"),
        ("response_type", "code"),
        ("client_id", LOGIN_CLIENT_ID),
        ("redirect_uri", CALLBACK),
        ("scope", "openid email offline_access"),
        ("state", "st&te"),
        ("nonce", NONCE),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
        ("prompt", "login"),
        ("max_age", "600"),
        ("login_hint", "user@example.com"),
        ("acr_values", "phr"),
        ("domain_hint", "example.com"),
    ];
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(pairs, expected);

    let bare = login(&server)
        .authorization_url(
            &metadata,
            &IdpAuthorizationRequest {
                state: "s",
                nonce: "n",
                code_challenge: "c",
                prompt: None,
                login_hint: None,
            },
        )
        .unwrap();
    assert!(
        !bare.contains("prompt=") && !bare.contains("login_hint="),
        "{bare}"
    );
}

// ── client authentication ────────────────────────────────────────────

fn form_of(body: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn token_response(extra: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(merged(
        json!({
            "access_token": "idp-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "id_token": "header.payload.signature",
            "refresh_token": "idp-refresh-1",
            "scope": "openid offline_access",
        }),
        extra,
    ))
}

async fn the_only_request(idp: &MockServer) -> wiremock::Request {
    let mut requests = idp.received_requests().await.expect("recording is on");
    assert_eq!(requests.len(), 1, "one request");
    requests.remove(0)
}

fn fixture_jwks() -> JwkSet {
    serde_json::from_str(IDP_JWKS).unwrap()
}

/// Decode a client assertion signed with the fixture key.
fn assertion_claims(assertion: &str, audience: &str) -> (jsonwebtoken::Header, Value) {
    let key = DecodingKey::from_jwk(&fixture_jwks().keys[0]).unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[LOGIN_CLIENT_ID]);
    let data = jsonwebtoken::decode::<Value>(assertion, &key, &validation)
        .expect("the assertion verifies");
    (data.header, data.claims)
}

#[tokio::test]
async fn a_code_is_redeemed_with_client_secret_basic() {
    let idp = MockServer::start().await;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{LOGIN_CLIENT_ID}:{LOGIN_SECRET}"))
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", basic.as_str()))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(token_response(json!({})))
        .expect(1)
        .mount(&idp)
        .await;
    let server = endpoint_server(&idp, json!({}));
    let tokens = login(&server)
        .exchange_code("idp-code-1", "verifier-0123456789")
        .await
        .expect("redeemed");
    assert_eq!(tokens.id_token.expose(), "header.payload.signature");
    assert_eq!(
        tokens.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-1")
    );
    assert_eq!(tokens.scope.as_deref(), Some("openid offline_access"));

    let request = the_only_request(&idp).await;
    let form = form_of(&request.body);
    assert_eq!(field(&form, "code"), Some("idp-code-1"));
    assert_eq!(field(&form, "code_verifier"), Some("verifier-0123456789"));
    assert_eq!(field(&form, "redirect_uri"), Some(CALLBACK));
    assert_eq!(
        field(&form, "client_secret"),
        None,
        "the secret stays in the header"
    );
    assert!(!format!("{tokens:?}").contains("idp-refresh-1"));
}

#[tokio::test]
async fn a_code_is_redeemed_with_client_secret_post() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response(json!({})))
        .mount(&idp)
        .await;
    let server = endpoint_server(&idp, json!({ "client_auth": "client_secret_post" }));
    login(&server)
        .exchange_code("idp-code-1", "verifier-0123456789")
        .await
        .expect("redeemed");
    let request = the_only_request(&idp).await;
    assert!(request.headers.get("authorization").is_none());
    let form = form_of(&request.body);
    assert_eq!(field(&form, "client_id"), Some(LOGIN_CLIENT_ID));
    assert_eq!(field(&form, "client_secret"), Some(LOGIN_SECRET));
}

/// `private_key_jwt`: a fresh assertion per request, `iss` and `sub` the
/// client, `aud` the endpoint it is posted to (or the issuer), living
/// [`CLIENT_ASSERTION_LIFETIME_SECS`].
#[tokio::test]
async fn private_key_jwt_signs_a_fresh_assertion_per_request() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response(json!({})))
        .mount(&idp)
        .await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&idp)
        .await;
    let server = endpoint_server(
        &idp,
        json!({
            "client_secret": null,
            "private_key": IDP_PRIVATE_PEM,
            "key_id": "login-key-1",
        }),
    );
    let login = login(&server);
    login
        .exchange_code("c1", "verifier-0123456789")
        .await
        .unwrap();
    login.refresh("idp-refresh-1").await.unwrap();
    assert_eq!(
        login.revoke_refresh_token("idp-refresh-1").await,
        Ok(RevokeOutcome::Revoked)
    );

    let requests = idp.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let mut jtis = Vec::new();
    for request in &requests {
        let form = form_of(&request.body);
        assert!(request.headers.get("authorization").is_none());
        assert_eq!(field(&form, "client_id"), Some(LOGIN_CLIENT_ID));
        assert_eq!(
            field(&form, "client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
        );
        let endpoint = format!("{}{}", idp.uri(), request.url.path());
        let (header, claims) =
            assertion_claims(field(&form, "client_assertion").unwrap(), &endpoint);
        assert_eq!(header.kid.as_deref(), Some("login-key-1"));
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(claims["sub"], LOGIN_CLIENT_ID);
        assert_eq!(claims["aud"], endpoint.as_str());
        let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
        assert_eq!(lifetime, CLIENT_ASSERTION_LIFETIME_SECS);
        jtis.push(claims["jti"].as_str().unwrap().to_owned());
    }
    jtis.sort();
    jtis.dedup();
    assert_eq!(jtis.len(), 3, "every assertion has its own jti");
    assert!(jtis.iter().all(|jti| jti.len() >= 43), "{jtis:?}");
}

#[tokio::test]
async fn private_key_jwt_can_name_the_issuer_as_audience() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response(json!({})))
        .mount(&idp)
        .await;
    let server = endpoint_server(
        &idp,
        json!({
            "client_secret": null,
            "private_key": IDP_PRIVATE_PEM,
            "assertion_audience": "issuer",
        }),
    );
    login(&server).exchange_code("c1", "v").await.unwrap();
    let request = the_only_request(&idp).await;
    let form = form_of(&request.body);
    let (header, claims) = assertion_claims(field(&form, "client_assertion").unwrap(), &idp.uri());
    assert_eq!(header.kid, None, "no key_id, no kid");
    assert_eq!(claims["aud"], idp.uri().as_str());
}

#[test]
fn credential_errors_name_settings_never_values() {
    let login_config = |extra: Value| -> TrustedIdpLoginConfig {
        serde_json::from_value(merged(json!({ "client_id": LOGIN_CLIENT_ID }), extra)).unwrap()
    };
    let cases = [
        (json!({}), "needs a credential"),
        (
            json!({ "private_key": "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----" }),
            "private_key",
        ),
        (
            json!({ "private_key": IDP_PRIVATE_PEM, "signing_alg": "ES256" }),
            "ES256",
        ),
        (
            json!({ "client_auth": "private_key_jwt", "client_secret": LOGIN_SECRET }),
            "takes private_key",
        ),
    ];
    for (settings, expected) in cases {
        let err = LoginCredential::from_config(&login_config(settings.clone()))
            .expect_err("refused")
            .to_string();
        assert!(err.contains(expected), "{settings}: {err}");
        assert!(
            !err.contains("BEGIN") && !err.contains(LOGIN_SECRET),
            "{err}"
        );
    }
}

#[test]
fn credentials_never_reach_debug_output() {
    let secret: TrustedIdpLoginConfig = serde_json::from_value(json!({
        "client_id": LOGIN_CLIENT_ID,
        "client_secret": LOGIN_SECRET,
        "client_auth": "client_secret_post",
    }))
    .unwrap();
    let credential = LoginCredential::from_config(&secret).unwrap();
    let auth = credential
        .authenticate("https://idp.test/token", IDP_ISSUER)
        .unwrap();
    for rendered in [format!("{credential:?}"), format!("{auth:?}")] {
        assert!(!rendered.contains(LOGIN_SECRET), "{rendered}");
    }

    let jwt: TrustedIdpLoginConfig = serde_json::from_value(json!({
        "client_id": LOGIN_CLIENT_ID,
        "private_key": IDP_PRIVATE_PEM,
    }))
    .unwrap();
    let credential = LoginCredential::from_config(&jwt).unwrap();
    assert_eq!(credential.method(), LoginClientAuth::PrivateKeyJwt);
    let auth = credential
        .authenticate("https://idp.test/token", IDP_ISSUER)
        .unwrap();
    let assertion = auth
        .form
        .iter()
        .find(|(name, _)| *name == "client_assertion")
        .unwrap()
        .1
        .expose()
        .to_owned();
    let rendered = format!("{credential:?} {auth:?}");
    assert!(
        !rendered.contains(&assertion) && !rendered.contains("PRIVATE KEY"),
        "{rendered}"
    );
}

// ── token endpoint answers ───────────────────────────────────────────

async fn token_endpoint_answering(response: ResponseTemplate) -> MockServer {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(response)
        .mount(&idp)
        .await;
    idp
}

/// A redirect from the token endpoint is never followed: the code and the
/// credentials would go wherever it points.
#[tokio::test]
async fn a_redirect_from_the_token_endpoint_is_not_followed() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/elsewhere", idp.uri())),
        )
        .expect(1)
        .mount(&idp)
        .await;
    Mock::given(path("/elsewhere"))
        .respond_with(token_response(json!({})))
        .expect(0)
        .mount(&idp)
        .await;
    let server = endpoint_server(&idp, json!({}));
    match login(&server).exchange_code("c1", "v").await {
        Err(UpstreamError::Misconfigured(reason)) => {
            assert!(reason.contains("redirect"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversized_token_response_is_refused() {
    let idp = token_endpoint_answering(
        ResponseTemplate::new(200)
            .set_body_raw(vec![b' '; MAX_IDP_RESPONSE_BYTES + 1], "application/json"),
    )
    .await;
    let server = endpoint_server(&idp, json!({}));
    match login(&server).exchange_code("c1", "v").await {
        Err(UpstreamError::Misconfigured(reason)) => {
            assert!(reason.contains("more than"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn server_errors_rate_limits_and_timeouts_are_transient() {
    for status in [500, 502, 503, 429, 408] {
        let idp = token_endpoint_answering(ResponseTemplate::new(status)).await;
        let server = endpoint_server(&idp, json!({}));
        let err = login(&server).exchange_code("c1", "v").await.unwrap_err();
        assert!(err.is_transient(), "{status}: {err}");
    }
    let idp =
        token_endpoint_answering(token_response(json!({})).set_delay(Duration::from_secs(3))).await;
    let server = endpoint_server(&idp, json!({ "timeout_ms": 500 }));
    let started = Instant::now();
    let err = login(&server).refresh("idp-refresh-1").await.unwrap_err();
    assert!(err.is_transient(), "{err}");
    assert!(err.to_string().contains("500 ms"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// An OAuth error is read by its code; the IdP's description, which may
/// quote what was sent, is never kept.
#[tokio::test]
async fn an_oauth_error_is_refused_by_its_code_alone() {
    for (status, code) in [(400, "invalid_grant"), (401, "invalid_client")] {
        let idp = token_endpoint_answering(ResponseTemplate::new(status).set_body_json(json!({
            "error": code,
            "error_description": "code idp-code-1 is not valid",
        })))
        .await;
        let server = endpoint_server(&idp, json!({}));
        let err = login(&server)
            .exchange_code("idp-code-1", "v")
            .await
            .unwrap_err();
        assert_eq!(err.oauth_error(), Some(code));
        assert!(!err.is_transient());
        assert_eq!(
            err,
            UpstreamError::Refused {
                status,
                error: code.to_owned()
            }
        );
        assert!(!err.to_string().contains("idp-code-1"), "{err}");
    }
}

#[tokio::test]
async fn malformed_answers_are_misconfigurations() {
    let cases: Vec<(ResponseTemplate, &str)> = vec![
        (
            ResponseTemplate::new(400).set_body_string("nope"),
            "without an OAuth error",
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({ "error": "bad error\ncode" })),
            "without an OAuth error",
        ),
        (token_response(json!({ "id_token": null })), "no id_token"),
        (token_response(json!({ "id_token": "" })), "no id_token"),
        (token_response(json!({ "token_type": "DPoP" })), "DPoP"),
        (
            token_response(json!({ "token_type": null })),
            "token response",
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!(["bearer", "x"])),
            "token response",
        ),
    ];
    for (response, expected) in cases {
        let idp = token_endpoint_answering(response).await;
        let server = endpoint_server(&idp, json!({}));
        match login(&server).exchange_code("c1", "v").await {
            Err(UpstreamError::Misconfigured(reason)) => {
                assert!(reason.contains(expected), "{expected}: {reason}");
            }
            other => panic!("{expected}: expected a refusal, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_refresh_returns_what_the_idp_rotated() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=idp-refresh-1"))
        .respond_with(token_response(json!({ "refresh_token": "idp-refresh-2" })))
        .up_to_n_times(1)
        .mount(&idp)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=idp-refresh-2"))
        .respond_with(token_response(
            json!({ "refresh_token": null, "id_token": null }),
        ))
        .mount(&idp)
        .await;
    let server = endpoint_server(&idp, json!({}));
    let first = login(&server).refresh("idp-refresh-1").await.unwrap();
    assert_eq!(
        first.refresh_token.as_ref().map(SecretString::expose),
        Some("idp-refresh-2")
    );
    assert!(first.id_token.is_some());
    let second = login(&server).refresh("idp-refresh-2").await.unwrap();
    assert!(second.refresh_token.is_none() && second.id_token.is_none());
}

#[tokio::test]
async fn a_revocation_posts_the_token_with_its_hint() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=idp-refresh-1"))
        .and(body_string_contains("token_type_hint=refresh_token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&idp)
        .await;
    let server = endpoint_server(&idp, json!({}));
    assert_eq!(
        login(&server).revoke_refresh_token("idp-refresh-1").await,
        Ok(RevokeOutcome::Revoked)
    );

    let down = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let server = endpoint_server(&down, json!({}));
    assert!(
        login(&server)
            .revoke_refresh_token("idp-refresh-1")
            .await
            .unwrap_err()
            .is_transient()
    );
}

/// The POST refuses a private address before connecting unless the IdP
/// allows the private network, for an address literal and for a name
/// that resolves to one.
#[tokio::test]
async fn a_private_address_is_refused_before_any_request() {
    let idp = token_endpoint_answering(token_response(json!({}))).await;
    let port = idp.address().port();
    for url in [
        format!("http://127.0.0.1:{port}/token"),
        format!("http://localhost:{port}/token"),
    ] {
        match post_form_pinned(&url, "a=b", None, false, Duration::from_secs(2)).await {
            Err(UpstreamError::Misconfigured(reason)) => {
                assert!(reason.contains("private address"), "{url}: {reason}");
            }
            Err(other) => panic!("{url}: expected a refusal, got {other:?}"),
            Ok(_) => panic!("{url}: expected a refusal, got an answer"),
        }
    }
    assert_eq!(idp.received_requests().await.unwrap().len(), 0);
    let answered = post_form_pinned(
        &format!("http://127.0.0.1:{port}/token"),
        "a=b",
        None,
        true,
        Duration::from_secs(2),
    )
    .await
    .map(|response| response.status.as_u16());
    assert_eq!(answered.ok(), Some(200));
}
