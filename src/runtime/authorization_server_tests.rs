use super::*;
use crate::config::{AuthorizationServerClientConfig, AuthorizationServerConfig, TrustedIdpConfig};

const IDP_PRIVATE_PEM: &str = include_str!("testdata/idp_private.pem");
const IDP_JWKS: &str = include_str!("testdata/idp_jwks.json");
const IDP_ISSUER: &str = "https://idp.test";
const GW_ISSUER: &str = "https://gw.test";
const CLIENT_ID: &str = "mcp-client";
const CLIENT_SECRET: &str = "portal-secret";
const SIGNING_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn test_config() -> AuthorizationServerConfig {
    AuthorizationServerConfig {
        issuer: GW_ISSUER.to_owned(),
        resource: None,
        signing_secret: SIGNING_SECRET.to_owned(),
        access_token_ttl_secs: 3600,
        clock_skew_secs: 60,
        enforce_single_use: true,
        allowed_scopes: None,
        trusted_idps: vec![TrustedIdpConfig {
            issuer: IDP_ISSUER.to_owned(),
            jwks_uri: Some(format!("{IDP_ISSUER}/jwks")),
            allowed_hosts: Vec::new(),
            allow_private_network: false,
        }],
        clients: vec![
            AuthorizationServerClientConfig {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
            },
            AuthorizationServerClientConfig {
                client_id: "public-client".to_owned(),
                client_secret: None,
            },
        ],
    }
}

async fn test_server_with(config: AuthorizationServerConfig) -> AuthorizationServer {
    let server = AuthorizationServer::from_config(&config, None).expect("server builds");
    // Seed the trusted-IdP JWKS cache so validation stays offline.
    *server.idps[0].jwks.write().await = Some(CachedJwks {
        keys: serde_json::from_str(IDP_JWKS).expect("fixture JWKS parses"),
        fetched_at: Instant::now(),
    });
    server
}

async fn test_server() -> AuthorizationServer {
    test_server_with(test_config()).await
}

struct AssertionOverrides {
    typ: Option<&'static str>,
    alg: Algorithm,
    iss: &'static str,
    aud: &'static str,
    client_id: &'static str,
    exp_offset: i64,
    scope: Option<&'static str>,
    resource: Option<serde_json::Value>,
    jti: String,
}

impl Default for AssertionOverrides {
    fn default() -> Self {
        Self {
            typ: Some(ID_JAG_TYP),
            alg: Algorithm::RS256,
            iss: IDP_ISSUER,
            aud: GW_ISSUER,
            client_id: CLIENT_ID,
            exp_offset: 300,
            scope: Some("mcp:tools mcp:resources"),
            resource: None,
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }
}

fn make_id_jag(overrides: AssertionOverrides) -> String {
    let now = now_unix() as i64;
    let mut header = Header::new(overrides.alg);
    header.typ = overrides.typ.map(str::to_owned);
    header.kid = Some("ema-test-key".to_owned());
    let mut claims = serde_json::json!({
        "iss": overrides.iss,
        "sub": "user-42",
        "aud": overrides.aud,
        "client_id": overrides.client_id,
        "jti": overrides.jti,
        "iat": now,
        "exp": now + overrides.exp_offset,
        "email": "user@acme.test",
    });
    if let Some(scope) = overrides.scope {
        claims["scope"] = serde_json::Value::String(scope.to_owned());
    }
    if let Some(resource) = overrides.resource {
        claims["resource"] = resource;
    }
    let key = EncodingKey::from_rsa_pem(IDP_PRIVATE_PEM.as_bytes()).expect("fixture key parses");
    jsonwebtoken::encode(&header, &claims, &key).expect("assertion encodes")
}

/// Corrupt a JWS signature so verification cannot succeed.
///
/// The replacement is chosen against the signature's current first character:
/// a fixed one silently leaves the signature intact whenever it already starts
/// with that character, and the token stays valid.
fn corrupt_signature(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let signature = &parts[2];
    let first = signature.chars().next().expect("signature is non-empty");
    let swap = if first == 'A' { 'B' } else { 'A' };
    parts[2] = format!("{swap}{}", &signature[1..]);
    parts.join(".")
}

fn token_form(assertion: &str) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
        assertion: Some(assertion.to_owned()),
        client_id: Some(CLIENT_ID.to_owned()),
        client_secret: Some(CLIENT_SECRET.to_owned()),
    }
}

async fn redeem(
    server: &AuthorizationServer,
    assertion: &str,
) -> Result<TokenResponse, OAuthError> {
    server
        .handle_token_request(token_form(assertion), None)
        .await
}

// ── metadata ─────────────────────────────────────────────────────────

#[tokio::test]
async fn metadata_advertises_id_jag_grant_profile() {
    let server = test_server().await;
    let meta = server.metadata();
    assert_eq!(meta["issuer"], GW_ISSUER);
    assert_eq!(meta["token_endpoint"], format!("{GW_ISSUER}/oauth/token"));
    assert_eq!(
        meta["grant_types_supported"],
        serde_json::json!([GRANT_TYPE_JWT_BEARER])
    );
    assert_eq!(
        meta["authorization_grant_profiles_supported"],
        serde_json::json!([GRANT_PROFILE_ID_JAG])
    );
    let methods = meta["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods array");
    assert!(methods.contains(&serde_json::json!("client_secret_basic")));
    assert!(methods.contains(&serde_json::json!("none")));
    assert_eq!(meta["response_types_supported"], serde_json::json!([]));
}

// ── happy path + minted-token verification ───────────────────────────

#[tokio::test]
async fn redeems_valid_id_jag_and_accepts_minted_token() {
    let server = test_server().await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, 3600);
    assert_eq!(token.scope.as_deref(), Some("mcp:tools mcp:resources"));

    match server.verify_bearer(&token.access_token) {
        EmaBearerOutcome::Verified(identity) => {
            assert_eq!(identity.subject_id, "user-42");
            // The vouching IdP, not this gateway — see
            // `identity_is_namespaced_by_the_vouching_idp`.
            assert_eq!(identity.issuer, IDP_ISSUER);
            assert_eq!(identity.scopes, vec!["mcp:tools", "mcp:resources"]);
            assert_eq!(
                identity.attributes.get("email").map(String::as_str),
                Some("user@acme.test")
            );
            assert_eq!(
                identity.attributes.get("idp").map(String::as_str),
                Some(IDP_ISSUER)
            );
            assert_eq!(
                identity.attributes.get("token_issuer").map(String::as_str),
                Some(GW_ISSUER)
            );
            assert_eq!(
                identity.attributes.get("client_id").map(String::as_str),
                Some(CLIENT_ID)
            );
        }
        other => panic!("expected Verified, got {:?}", discriminant_name(&other)),
    }
}

/// `trusted_idps` is a list, and `sub` is an opaque per-IdP string, so two
/// trusted IdPs can issue the same subject — hostilely, or just because both
/// use email. If the verified identity reported this gateway's own issuer,
/// those two people would share one principal key, and with it one synthetic
/// session, task list and idempotency scope. The identity must therefore be
/// namespaced by the IdP that vouched for it.
#[tokio::test]
async fn identity_is_namespaced_by_the_vouching_idp() {
    let server = test_server().await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    match server.verify_bearer(&token.access_token) {
        EmaBearerOutcome::Verified(identity) => {
            assert_eq!(
                identity.issuer, IDP_ISSUER,
                "identity must be scoped to the vouching IdP, not the gateway"
            );
            assert_ne!(
                identity.issuer, GW_ISSUER,
                "reporting the gateway issuer collapses every IdP into one principal namespace"
            );
        }
        other => panic!("expected Verified, got {:?}", discriminant_name(&other)),
    }
}

fn discriminant_name(outcome: &EmaBearerOutcome) -> &'static str {
    match outcome {
        EmaBearerOutcome::NotOurs => "NotOurs",
        EmaBearerOutcome::Verified(_) => "Verified",
        EmaBearerOutcome::Invalid(_) => "Invalid",
    }
}

#[tokio::test]
async fn minted_token_for_other_audience_is_rejected() {
    let server = test_server().await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");

    // A second deployment with the same secret but another resource id
    // must refuse the token (audience restriction).
    let mut other_config = test_config();
    other_config.resource = Some("https://other.test/mcp".to_owned());
    let other = test_server_with(other_config).await;
    match other.verify_bearer(&token.access_token) {
        EmaBearerOutcome::Invalid(_) => {}
        other_outcome => panic!(
            "expected Invalid, got {}",
            discriminant_name(&other_outcome)
        ),
    }
}

#[tokio::test]
async fn foreign_issuer_bearer_falls_through() {
    let server = test_server().await;
    // An assertion-shaped token issued by the IdP: iss != our issuer →
    // NotOurs (the OIDC/JWKS cascade owns it).
    let outcome = server.verify_bearer(&make_id_jag(AssertionOverrides::default()));
    assert!(matches!(outcome, EmaBearerOutcome::NotOurs));
}

#[tokio::test]
async fn tampered_minted_token_is_rejected() {
    let server = test_server().await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds")
        .access_token;
    let tampered = corrupt_signature(&token);
    assert!(matches!(
        server.verify_bearer(&tampered),
        EmaBearerOutcome::Invalid(_)
    ));
}

// ── ID-JAG validation matrix ─────────────────────────────────────────

#[tokio::test]
async fn rejects_wrong_typ() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            typ: Some("JWT"),
            ..Default::default()
        }),
    )
    .await
    .expect_err("wrong typ must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("typ"));
}

#[tokio::test]
async fn rejects_symmetric_algorithm() {
    let server = test_server().await;
    // HS256 assertion "signed" with a guessable key — must be refused
    // on algorithm class alone, before any key lookup.
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some(ID_JAG_TYP.to_owned());
    let now = now_unix();
    let claims = serde_json::json!({
        "iss": IDP_ISSUER, "sub": "user-42", "aud": GW_ISSUER,
        "client_id": CLIENT_ID, "jti": "j1", "iat": now, "exp": now + 300,
    });
    let assertion = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"guessable"))
        .expect("encodes");
    let err = redeem(&server, &assertion)
        .await
        .expect_err("HS256 must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("asymmetric"));
}

#[tokio::test]
async fn rejects_untrusted_issuer() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            iss: "https://rogue.test",
            ..Default::default()
        }),
    )
    .await
    .expect_err("untrusted issuer must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("trusted"));
}

#[tokio::test]
async fn rejects_wrong_audience() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            aud: "https://some-other-as.test",
            ..Default::default()
        }),
    )
    .await
    .expect_err("wrong audience must fail");
    assert_eq!(err.error, "invalid_grant");
}

#[tokio::test]
async fn rejects_expired_assertion() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            exp_offset: -3600,
            ..Default::default()
        }),
    )
    .await
    .expect_err("expired assertion must fail");
    assert_eq!(err.error, "invalid_grant");
}

#[tokio::test]
async fn rejects_client_id_mismatch() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            client_id: "someone-else",
            ..Default::default()
        }),
    )
    .await
    .expect_err("client binding must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("client_id"));
}

#[tokio::test]
async fn rejects_replayed_jti() {
    let server = test_server().await;
    let jti = uuid::Uuid::new_v4().to_string();
    let first = make_id_jag(AssertionOverrides {
        jti: jti.clone(),
        ..Default::default()
    });
    redeem(&server, &first)
        .await
        .expect("first redemption succeeds");
    let second = make_id_jag(AssertionOverrides {
        jti,
        ..Default::default()
    });
    let err = redeem(&server, &second)
        .await
        .expect_err("replayed jti must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("already"));
}

#[tokio::test]
async fn saturated_jti_cache_refuses_rather_than_admitting_unrecorded() {
    let server = test_server().await;
    // Fill the replay cache with entries that outlive the request so the
    // opportunistic purge cannot reclaim them.
    let far_future = now_unix() + 86_400;
    {
        let mut seen = server.seen_jtis.lock().expect("cache lock");
        for i in 0..JTI_CACHE_CAP {
            seen.insert((IDP_ISSUER.to_owned(), format!("filler-{i}")), far_future);
        }
    }
    let assertion = make_id_jag(AssertionOverrides::default());
    let err = redeem(&server, &assertion)
        .await
        .expect_err("a jti that cannot be recorded must not be admitted");
    assert_eq!(err.error, "temporarily_unavailable");
    assert_eq!(err.status, 503);
}

#[tokio::test]
async fn resource_mismatch_is_invalid_target() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!("https://other-resource.test")),
            ..Default::default()
        }),
    )
    .await
    .expect_err("foreign resource must fail");
    assert_eq!(err.error, "invalid_target");
}

#[tokio::test]
async fn matching_resource_in_array_is_accepted() {
    let server = test_server().await;
    let token = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!([
                "https://other-resource.test",
                GW_ISSUER,
            ])),
            ..Default::default()
        }),
    )
    .await
    .expect("matching resource array succeeds");
    assert_eq!(token.token_type, "Bearer");
}

#[tokio::test]
async fn narrows_scopes_to_allowed_set() {
    let mut config = test_config();
    config.allowed_scopes = Some(vec!["mcp:tools".to_owned()]);
    let server = test_server_with(config).await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    assert_eq!(token.scope.as_deref(), Some("mcp:tools"));
}

#[tokio::test]
async fn rejects_bad_signature() {
    let server = test_server().await;
    let assertion = corrupt_signature(&make_id_jag(AssertionOverrides::default()));
    let err = redeem(&server, &assertion)
        .await
        .expect_err("bad signature must fail");
    assert_eq!(err.error, "invalid_grant");
}

// ── token endpoint request handling ──────────────────────────────────

#[tokio::test]
async fn rejects_unsupported_grant_type() {
    let server = test_server().await;
    let err = server
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some("client_credentials".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("unsupported grant must fail");
    assert_eq!(err.error, "unsupported_grant_type");
}

#[tokio::test]
async fn rejects_missing_assertion() {
    let server = test_server().await;
    let err = server
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                client_id: Some(CLIENT_ID.to_owned()),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                assertion: None,
            },
            None,
        )
        .await
        .expect_err("missing assertion must fail");
    assert_eq!(err.error, "invalid_request");
}

// ── client authentication ────────────────────────────────────────────

#[tokio::test]
async fn rejects_unknown_client() {
    let server = test_server().await;
    let mut form = token_form(&make_id_jag(AssertionOverrides::default()));
    form.client_id = Some("nope".to_owned());
    let err = server
        .handle_token_request(form, None)
        .await
        .expect_err("unknown client must fail");
    assert_eq!(err.error, "invalid_client");
    assert_eq!(err.status, 401);
}

#[tokio::test]
async fn rejects_wrong_secret() {
    let server = test_server().await;
    let mut form = token_form(&make_id_jag(AssertionOverrides::default()));
    form.client_secret = Some("wrong".to_owned());
    let err = server
        .handle_token_request(form, None)
        .await
        .expect_err("wrong secret must fail");
    assert_eq!(err.error, "invalid_client");
}

#[tokio::test]
async fn authenticates_via_basic_with_percent_encoding() {
    let server = test_server().await;
    let mut config_with_special = test_config();
    config_with_special
        .clients
        .push(AuthorizationServerClientConfig {
            client_id: "special client".to_owned(),
            client_secret: Some("p@ss word%".to_owned()),
        });
    let server_special = test_server_with(config_with_special).await;
    drop(server);

    // RFC 6749 §2.3.1: id/secret are form-urlencoded before base64.
    let creds = format!("{}:{}", "special+client", "p%40ss+word%25");
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(creds)
    );
    let assertion = make_id_jag(AssertionOverrides {
        client_id: "special-client-unused",
        ..Default::default()
    });
    // The client authenticates, but the assertion is bound to another
    // client — proves Basic parsing ran AND binding still gates.
    let err = server_special
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                assertion: Some(assertion),
                client_id: None,
                client_secret: None,
            },
            Some(&basic),
        )
        .await
        .expect_err("binding mismatch must fail after successful auth");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("client_id"));
}

#[tokio::test]
async fn public_client_with_stray_secret_is_refused() {
    let server = test_server().await;
    let err = server
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                assertion: Some(make_id_jag(AssertionOverrides::default())),
                client_id: Some("public-client".to_owned()),
                client_secret: Some("anything".to_owned()),
            },
            None,
        )
        .await
        .expect_err("stray secret must fail");
    assert_eq!(err.error, "invalid_client");
}

#[tokio::test]
async fn public_client_redeems_its_own_assertion() {
    let server = test_server().await;
    let token = server
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                assertion: Some(make_id_jag(AssertionOverrides {
                    client_id: "public-client",
                    ..Default::default()
                })),
                client_id: Some("public-client".to_owned()),
                client_secret: None,
            },
            None,
        )
        .await
        .expect("public client redemption succeeds");
    assert_eq!(token.token_type, "Bearer");
}

// ── helpers ──────────────────────────────────────────────────────────

#[test]
fn percent_decode_handles_reserved_characters() {
    assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
    assert_eq!(percent_decode("a%3Ab").as_deref(), Some("a:b"));
    assert_eq!(percent_decode("a+b").as_deref(), Some("a b"));
    assert_eq!(percent_decode("%zz"), None);
}

#[test]
fn config_validation_catches_misconfiguration() {
    let mut config = test_config();
    config.validate().expect("test config is valid");

    config.signing_secret = "short".to_owned();
    assert!(config.validate().is_err());
    config.signing_secret = SIGNING_SECRET.to_owned();

    config.trusted_idps.clear();
    assert!(config.validate().is_err());
    config = test_config();

    config.clients.clear();
    assert!(config.validate().is_err());
    config = test_config();

    config.clients.push(config.clients[0].clone());
    assert!(config.validate().is_err());
    config = test_config();

    config.issuer = "gw.test".to_owned();
    assert!(config.validate().is_err());
    config = test_config();

    config.trusted_idps[0].issuer = "http://idp.internal".to_owned();
    assert!(
        config.validate().is_err(),
        "http issuer requires allow_private_network"
    );
    config.trusted_idps[0].allow_private_network = true;
    config
        .validate()
        .expect("allow_private_network permits http");
}
