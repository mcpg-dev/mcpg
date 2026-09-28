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
        signing_secret: Some(SIGNING_SECRET.to_owned()),
        signing_keys: Vec::new(),
        access_token_ttl_secs: 3600,
        clock_skew_secs: 60,
        max_assertion_lifetime_secs: 600,
        enforce_single_use: true,
        allowed_scopes: None,
        require_scope: false,
        trusted_idps: vec![TrustedIdpConfig {
            issuer: IDP_ISSUER.to_owned(),
            jwks_uri: Some(format!("{IDP_ISSUER}/jwks")),
            jwks: None,
            allowed_hosts: Vec::new(),
            allow_private_network: false,
            allowed_algs: vec!["RS256".to_owned(), "ES256".to_owned()],
            allowed_clients: Vec::new(),
            required_tenant: None,
            claim_mappings: Default::default(),
            principal_issuer: None,
            login: None,
        }],
        clients: vec![
            secret_client(CLIENT_ID, CLIENT_SECRET),
            public_client("public-client"),
        ],
        client_roles: Default::default(),
        client_id_metadata_documents: Default::default(),
        rate_limit_per_min: 120,
        interactive: None,
        dpop: Default::default(),
        authorization_details: Default::default(),
    }
}

/// A registered client with the method `client_secret` implies.
fn secret_client(client_id: &str, client_secret: &str) -> AuthorizationServerClientConfig {
    AuthorizationServerClientConfig {
        client_secret: Some(client_secret.to_owned()),
        ..public_client(client_id)
    }
}

/// A registered public client (`none`).
fn public_client(client_id: &str) -> AuthorizationServerClientConfig {
    AuthorizationServerClientConfig {
        client_id: client_id.to_owned(),
        client_secret: None,
        token_endpoint_auth_method: None,
        jwks_uri: None,
        jwks: None,
        accept_token_endpoint_audience: false,
        allow_private_network: false,
        redirect_uris: Vec::new(),
        grant_types: None,
        client_name: None,
        consent: Default::default(),
        dpop_bound_access_tokens: false,
    }
}

async fn test_server_with(config: AuthorizationServerConfig) -> AuthorizationServer {
    test_server_on(config, ReplayLedger::in_process()).await
}

/// [`test_server_with`] recording redemptions in `ledger`.
async fn test_server_on(
    config: AuthorizationServerConfig,
    ledger: ReplayLedger,
) -> AuthorizationServer {
    let server = AuthorizationServer::from_config(&config, None, ledger).expect("server builds");
    // Seed the trusted-IdP JWKS cache so validation stays offline.
    *server.idps[0].keys.jwks.write().await = Some(CachedJwks {
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
    kid: &'static str,
    /// Claims set last, replacing any of the above.
    extra: serde_json::Value,
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
            kid: "ema-test-key",
            extra: serde_json::json!({}),
        }
    }
}

fn make_id_jag(overrides: AssertionOverrides) -> String {
    let now = now_unix() as i64;
    let mut header = Header::new(overrides.alg);
    header.typ = overrides.typ.map(str::to_owned);
    header.kid = Some(overrides.kid.to_owned());
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
    if let serde_json::Value::Object(extra) = overrides.extra {
        for (name, value) in extra {
            claims[name.as_str()] = value;
        }
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
        ..Default::default()
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
        EmaBearerOutcome::Refused(_) => "Refused",
        EmaBearerOutcome::Unavailable => "Unavailable",
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

/// A token outlives neither the IdP nor the client it was minted for: a
/// server rebuilt from a configuration that no longer trusts either, with
/// the same signing key, refuses it.
#[tokio::test]
async fn a_token_is_refused_once_its_idp_or_client_is_no_longer_trusted() {
    let server = test_server().await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds")
        .access_token;

    let mut without_idp = test_config();
    without_idp.trusted_idps[0].issuer = "https://other-idp.test".to_owned();
    let reason = invalid_reason(&test_server_with(without_idp).await, &token);
    assert!(reason.contains("IdP that is no longer trusted"), "{reason}");

    let mut without_client = test_config();
    without_client.clients.retain(|c| c.client_id != CLIENT_ID);
    let reason = invalid_reason(&test_server_with(without_client).await, &token);
    assert!(reason.contains("no longer registered"), "{reason}");

    let mut narrowed = test_config();
    narrowed.trusted_idps[0].allowed_clients = vec!["public-client".to_owned()];
    let reason = invalid_reason(&test_server_with(narrowed).await, &token);
    assert!(reason.contains("may no longer issue"), "{reason}");

    let mut pinned = test_config();
    pinned.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let reason = invalid_reason(&test_server_with(pinned).await, &token);
    assert!(reason.contains("tenant"), "{reason}");

    assert!(matches!(
        test_server().await.verify_bearer(&token),
        EmaBearerOutcome::Verified(_)
    ));
}

/// A metadata-document client needs no `clients[]` entry: its tokens stay
/// valid while `allowed_hosts` admits its URL, and no longer.
#[tokio::test]
async fn a_metadata_document_clients_tokens_follow_allowed_hosts() {
    const DOCUMENT_CLIENT: &str = "https://agent.example/client.json";
    let mut config = test_config();
    config.client_id_metadata_documents.allowed_hosts = vec!["agent.example".to_owned()];
    let server = test_server_with(config.clone()).await;
    let now = now_unix();
    let token = server.signing_keys[0]
        .sign(&MintedClaims {
            iss: GW_ISSUER.to_owned(),
            sub: "user-42".to_owned(),
            aud: GW_ISSUER.to_owned(),
            client_id: DOCUMENT_CLIENT.to_owned(),
            jti: "document-client".to_owned(),
            iat: now,
            exp: now + 60,
            idp: IDP_ISSUER.to_owned(),
            ..MintedClaims::default()
        })
        .expect("encodes");
    assert!(matches!(
        server.verify_bearer(&token),
        EmaBearerOutcome::Verified(_)
    ));

    config.client_id_metadata_documents.allowed_hosts = vec!["other.example".to_owned()];
    let reason = invalid_reason(&test_server_with(config).await, &token);
    assert!(reason.contains("no longer registered"), "{reason}");
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

// ── single use across replicas and reloads ───────────────────────────

fn shared_ledger() -> (
    Arc<crate::builtins::cluster_primitives::MemoryKv>,
    ReplayLedger,
) {
    let kv = Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
    let ledger = ReplayLedger::shared(Arc::clone(&kv) as Arc<dyn KeyValueStore>);
    (kv, ledger)
}

/// Two replicas over one cluster KV: the second presentation of an
/// assertion is refused wherever it lands.
#[tokio::test]
async fn replay_is_refused_on_another_replica() {
    let (_, ledger) = shared_ledger();
    let replica_a = test_server_on(test_config(), ledger.clone()).await;
    let replica_b = test_server_on(test_config(), ledger).await;
    let assertion = make_id_jag(AssertionOverrides::default());
    redeem(&replica_a, &assertion)
        .await
        .expect("first redemption succeeds");
    let err = redeem(&replica_b, &assertion)
        .await
        .expect_err("the replay on another replica must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("already"), "{}", err.description);
}

/// A reload builds a new server; handed the previous ledger, it still
/// refuses an assertion redeemed before the reload.
#[tokio::test]
async fn replay_is_refused_after_a_reload() {
    let before = test_server().await;
    assert!(before.replay_ledger().is_process_local());
    let assertion = make_id_jag(AssertionOverrides::default());
    redeem(&before, &assertion)
        .await
        .expect("first redemption succeeds");
    let after = test_server_on(test_config(), before.replay_ledger().clone()).await;
    let err = redeem(&after, &assertion)
        .await
        .expect_err("the replay after the reload must fail");
    assert_eq!(err.error, "invalid_grant");
}

/// A cluster KV that cannot be reached.
#[derive(Debug)]
struct UnreachableKv;

fn unreachable() -> mcpg_cluster_api::ClusterError {
    mcpg_cluster_api::ClusterError::BackendUnavailable {
        reason: "connection refused".to_owned(),
    }
}

#[async_trait::async_trait]
impl KeyValueStore for UnreachableKv {
    async fn get(
        &self,
        _: &str,
    ) -> Result<Option<mcpg_cluster_api::Entry>, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn put(
        &self,
        _: &str,
        _: Bytes,
        _: Option<Duration>,
    ) -> Result<(), mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn put_if_absent(
        &self,
        _: &str,
        _: Bytes,
        _: Option<Duration>,
    ) -> Result<bool, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn delete(&self, _: &str) -> Result<bool, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn list_prefix(
        &self,
        _: &str,
        _: usize,
    ) -> Result<Vec<(String, mcpg_cluster_api::Entry)>, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn expire(
        &self,
        _: &str,
        _: Option<Duration>,
    ) -> Result<bool, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
    async fn incr(
        &self,
        _: &str,
        _: i64,
        _: Option<Duration>,
    ) -> Result<i64, mcpg_cluster_api::ClusterError> {
        Err(unreachable())
    }
}

#[tokio::test]
async fn an_unwritable_ledger_refuses_rather_than_admitting_unrecorded() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = test_server_on(test_config(), ReplayLedger::shared(Arc::new(UnreachableKv))).await;
    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("an assertion that cannot be recorded must not be admitted");
    assert_eq!(err.error, "temporarily_unavailable");
    assert_eq!(err.status, 503);
    assert!(captured.seen("mcpg_ema_jti_store_errors_total{}"));
    assert!(captured.seen(&format!(
        "mcpg_ema_token_requests_total{{outcome=failed,error=temporarily_unavailable,idp={IDP_ISSUER},\
         grant=jwt_bearer}}"
    )));
}

#[tokio::test]
async fn single_use_off_leaves_the_ledger_alone() {
    let mut config = test_config();
    config.enforce_single_use = false;
    let server = test_server_on(config, ReplayLedger::shared(Arc::new(UnreachableKv))).await;
    let assertion = make_id_jag(AssertionOverrides::default());
    for _ in 0..2 {
        redeem(&server, &assertion)
            .await
            .expect("without single use the ledger is never consulted");
    }
}

/// The ledger holds a hash, not the IdP's identifiers, until the decoder
/// stops accepting the assertion: `exp` plus the leeway.
#[tokio::test]
async fn ledger_entries_are_hashed_and_live_as_long_as_the_assertion() {
    let (kv, ledger) = shared_ledger();
    let server = test_server_on(test_config(), ledger).await;
    let jti = "jti-7f3e-readable-nowhere";
    redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            jti: jti.to_owned(),
            ..Default::default()
        }),
    )
    .await
    .expect("redemption succeeds");
    let entries = kv.list_prefix(REPLAY_KEY_PREFIX, 10).await.expect("lists");
    assert_eq!(entries.len(), 1);
    let (key, entry) = &entries[0];
    assert_eq!(key, &replay_key(IDP_ISSUER, jti));
    assert!(!key.contains(jti) && !key.contains("idp.test"), "{key}");
    let remaining = entry
        .expires_at
        .expect("the entry expires")
        .duration_since(SystemTime::now())
        .expect("in the future")
        .as_secs();
    // `make_id_jag` sets exp 300 s ahead; the test config allows 60 s of skew.
    assert!((355..=360).contains(&remaining), "{remaining}");
}

#[test]
fn replay_keys_separate_issuer_and_jti() {
    assert_ne!(replay_key("https://a", "bc"), replay_key("https://ab", "c"));
    assert_eq!(replay_key("https://a", "b"), replay_key("https://a", "b"));
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
                ..Default::default()
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
    // RFC 6749 §5.2: 401 only after HTTP Basic, which it must challenge.
    assert_eq!(err.status, 400);
    assert!(!err.basic_challenge);

    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("nope:secret")
    );
    let err = server
        .handle_token_request(
            TokenRequestForm {
                grant_type: Some(GRANT_TYPE_JWT_BEARER.to_owned()),
                assertion: Some(make_id_jag(AssertionOverrides::default())),
                ..Default::default()
            },
            Some(&basic),
        )
        .await
        .expect_err("unknown client must fail");
    assert_eq!(err.error, "invalid_client");
    assert_eq!(err.status, 401);
    assert!(err.basic_challenge);
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
        .push(secret_client("special client", "p@ss word%"));
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            },
            None,
        )
        .await
        .expect("public client redemption succeeds");
    assert_eq!(token.token_type, "Bearer");
}

// ── ID-JAG profile conformance ───────────────────────────────────────

/// The protected resource metadata of a gateway reached at its canonical
/// host and one custom domain.
fn resource_metadata() -> OAuthResourceMetadataConfig {
    OAuthResourceMetadataConfig {
        resource: "https://gw.test/mcp".to_owned(),
        additional_resources: vec!["https://mcp.acme.example/mcp".to_owned()],
        authorization_servers: Vec::new(),
        scopes_supported: vec!["mcp:tools".to_owned(), "mcp:admin".to_owned()],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    }
}

async fn test_server_with_metadata(
    config: AuthorizationServerConfig,
    metadata: &OAuthResourceMetadataConfig,
) -> AuthorizationServer {
    let server =
        AuthorizationServer::from_config(&config, Some(metadata), ReplayLedger::in_process())
            .expect("server builds");
    *server.idps[0].keys.jwks.write().await = Some(CachedJwks {
        keys: serde_json::from_str(IDP_JWKS).expect("fixture JWKS parses"),
        fetched_at: Instant::now(),
    });
    server
}

/// The claims of a minted token, read without verification.
fn minted_claims(token: &str) -> serde_json::Value {
    unverified_payload(token).expect("minted token has a JSON payload")
}

/// ID-JAG §9.8: without DPoP support, a key-bound grant MUST fail rather
/// than be redeemed for a bearer token.
#[tokio::test]
async fn key_bound_assertion_is_refused() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("a cnf-bound assertion must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("proof of possession"),
        "{}",
        err.description
    );
}

/// ID-JAG §4.4.1: `aud` is the issuer, as a string or a one-element array.
#[tokio::test]
async fn aud_must_name_only_this_authorization_server() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "aud": [GW_ISSUER, "https://other-as.test"] }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("a multi-valued aud must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("one-element array"),
        "{}",
        err.description
    );

    redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "aud": [GW_ISSUER] }),
            ..Default::default()
        }),
    )
    .await
    .expect("a one-element aud array naming the issuer is accepted");
}

/// The Okta "Issuer URL" typed with a trailing slash is the hardest
/// mismatch to spot, so the description names both values.
#[tokio::test]
async fn aud_with_a_trailing_slash_names_the_expected_issuer() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            aud: "https://gw.test/",
            ..Default::default()
        }),
    )
    .await
    .expect_err("aud is compared exactly");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("\"https://gw.test/\"")
            && err.description.contains("exactly `https://gw.test`"),
        "{}",
        err.description
    );
}

/// ID-JAG §4.4.1: the token response carries the granted resource.
#[tokio::test]
async fn token_response_names_the_granted_resource() {
    let server = test_server_with_metadata(test_config(), &resource_metadata()).await;
    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    assert_eq!(token.resource, "https://gw.test/mcp");
    assert_eq!(
        minted_claims(&token.access_token)["aud"],
        "https://gw.test/mcp"
    );
    let body = serde_json::to_value(&token).expect("response serializes");
    assert_eq!(body["resource"], "https://gw.test/mcp");
}

/// A client that discovered the gateway on a custom domain asks the IdP for
/// that resource; the token is minted for it and the gateway accepts it.
#[tokio::test]
async fn custom_domain_resource_mints_that_audience() {
    let server = test_server_with_metadata(test_config(), &resource_metadata()).await;
    let token = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!("https://mcp.acme.example/mcp/")),
            ..Default::default()
        }),
    )
    .await
    .expect("a custom-domain resource is accepted");
    assert_eq!(token.resource, "https://mcp.acme.example/mcp");
    assert_eq!(
        minted_claims(&token.access_token)["aud"],
        "https://mcp.acme.example/mcp"
    );
    assert!(matches!(
        server.verify_bearer(&token.access_token),
        EmaBearerOutcome::Verified(_)
    ));
    assert_eq!(
        minted_claims(&token.access_token)["iss"],
        GW_ISSUER,
        "one issuer serves every resource"
    );

    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!("https://unknown.example/mcp")),
            ..Default::default()
        }),
    )
    .await
    .expect_err("an unknown resource must fail");
    assert_eq!(err.error, "invalid_target");
}

/// `authorization_server.resource` picks the default audience only: the
/// resource the PRM advertises stays redeemable, as EMA requires the
/// ID-JAG `resource` claim to name it.
#[tokio::test]
async fn the_advertised_resource_stays_redeemable_beside_a_configured_one() {
    let mut config = test_config();
    config.resource = Some("https://gw.test/other".to_owned());
    let server = test_server_with_metadata(config, &resource_metadata()).await;

    let token = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    assert_eq!(token.resource, "https://gw.test/other", "the default");

    let token = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!("https://gw.test/mcp")),
            ..Default::default()
        }),
    )
    .await
    .expect("the advertised resource is redeemable");
    assert_eq!(token.resource, "https://gw.test/mcp");
    assert!(matches!(
        server.verify_bearer(&token.access_token),
        EmaBearerOutcome::Verified(_)
    ));
}

async fn redeem_for_resource(
    server: &AuthorizationServer,
    assertion: &str,
    resource: &str,
) -> Result<TokenResponse, OAuthError> {
    let mut form = token_form(assertion);
    form.resource = Some(resource.to_owned());
    server.handle_token_request(form, None).await
}

/// RFC 8707: the token request's `resource` picks the audience among the
/// resources this server answers to, within the ID-JAG's `resource` claim
/// when it carries one, and anything else is `invalid_target`.
#[tokio::test]
async fn the_requested_resource_binds_the_audience() {
    let server = test_server_with_metadata(test_config(), &resource_metadata()).await;
    let unclaimed = || make_id_jag(AssertionOverrides::default());

    let token = redeem_for_resource(&server, &unclaimed(), "https://mcp.acme.example/mcp/")
        .await
        .expect("an advertised resource is granted");
    assert_eq!(token.resource, "https://mcp.acme.example/mcp");
    assert_eq!(
        minted_claims(&token.access_token)["aud"],
        "https://mcp.acme.example/mcp"
    );

    let err = redeem_for_resource(&server, &unclaimed(), "https://elsewhere.test/mcp")
        .await
        .expect_err("a foreign resource");
    assert_eq!(err.error, "invalid_target");

    let claimed = || {
        make_id_jag(AssertionOverrides {
            resource: Some(serde_json::json!([
                "https://gw.test/mcp",
                "https://mcp.acme.example/mcp"
            ])),
            ..Default::default()
        })
    };
    let token = redeem_for_resource(&server, &claimed(), "https://mcp.acme.example/mcp")
        .await
        .expect("a resource the claim names");
    assert_eq!(token.resource, "https://mcp.acme.example/mcp");

    let only_canonical = make_id_jag(AssertionOverrides {
        resource: Some(serde_json::json!("https://gw.test/mcp")),
        ..Default::default()
    });
    let err = redeem_for_resource(&server, &only_canonical, "https://mcp.acme.example/mcp")
        .await
        .expect_err("a resource the claim does not name");
    assert_eq!(err.error, "invalid_target");
    assert!(
        err.description.contains("resource claim"),
        "{}",
        err.description
    );
}

/// ID-JAG §4.4.1: `authorization_details` must be processed per RFC 9396;
/// without that support, the grant is refused rather than widened.
#[tokio::test]
async fn an_assertion_with_authorization_details_is_refused() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({
                "authorization_details": [{ "type": "payment_initiation", "actions": ["read"] }]
            }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("authorization_details is not supported");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("authorization_details"),
        "{}",
        err.description
    );
}

/// RFC 6749 §5.2: an `error_description` holds printable ASCII other than
/// `"` and `\`, however much of a client's own value it echoes.
#[tokio::test]
async fn error_descriptions_stay_in_the_rfc_6749_character_set() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "aud": ["https://gw.test/\"é\\\u{7}§", "x"] }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("a foreign aud");
    let body = err.body();
    let description = body["error_description"].as_str().expect("a description");
    assert!(
        description
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)),
        "{description}"
    );
    assert!(description.contains("https://gw.test/"), "{description}");
    assert_eq!(
        error_description("RFC 8693 §4.1 “quoted” …"),
        "RFC 8693 section 4.1 ?quoted? ..."
    );
}

/// An issuer that ends in `/` is published and compared with it, and the
/// endpoints it names sit at the origin's root.
#[tokio::test]
async fn a_trailing_slash_issuer_is_kept_verbatim() {
    let mut config = test_config();
    config.issuer = "https://gw.test/".to_owned();
    config.signing_secret = None;
    config.signing_keys = vec![asymmetric_key(SigningAlgorithm::Es256, None, es256_pem())];
    config.validate().expect("valid");
    let server = test_server_with(config).await;
    let metadata = server.metadata();
    assert_eq!(metadata["issuer"], "https://gw.test/");
    assert_eq!(metadata["token_endpoint"], "https://gw.test/oauth/token");
    assert_eq!(metadata["jwks_uri"], "https://gw.test/oauth/jwks");

    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("aud must be the issuer exactly");
    assert_eq!(err.error, "invalid_grant");
    let token = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            aud: "https://gw.test/",
            ..Default::default()
        }),
    )
    .await
    .expect("an aud naming the issuer verbatim redeems");
    assert_eq!(
        minted_claims(&token.access_token)["iss"],
        "https://gw.test/"
    );
    assert!(matches!(
        server.verify_bearer(&token.access_token),
        EmaBearerOutcome::Verified(_)
    ));
}

#[tokio::test]
async fn trusted_issuer_is_compared_exactly() {
    let mut config = test_config();
    config.trusted_idps[0].issuer = format!("{IDP_ISSUER}/");
    let server = test_server_with(config).await;
    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("a trailing slash is a different issuer");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("trailing"), "{}", err.description);
}

#[tokio::test]
async fn assertion_lifetime_is_bounded() {
    let server = test_server().await;
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            exp_offset: 3600,
            ..Default::default()
        }),
    )
    .await
    .expect_err("a one-hour assertion exceeds the 600 s default");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("lifetime"), "{}", err.description);

    // An old `iat` is refused through the same bound.
    let now = now_unix();
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "iat": now - 700, "exp": now + 100 }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("an assertion issued 700 s ago must fail");
    assert_eq!(err.error, "invalid_grant");
    assert!(err.description.contains("lifetime"), "{}", err.description);

    redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "iat": now - 500, "exp": now + 100 }),
            ..Default::default()
        }),
    )
    .await
    .expect("an assertion within the bound redeems");
}

// ── scope ────────────────────────────────────────────────────────────

async fn redeem_with_scope(
    server: &AuthorizationServer,
    assertion: &str,
    scope: Option<&str>,
) -> Result<TokenResponse, OAuthError> {
    let mut form = token_form(assertion);
    form.scope = scope.map(str::to_owned);
    server.handle_token_request(form, None).await
}

#[tokio::test]
async fn scope_parameter_narrows_the_grant() {
    let server = test_server().await;
    let token = redeem_with_scope(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some("mcp:tools"),
    )
    .await
    .expect("redemption succeeds");
    assert_eq!(token.scope.as_deref(), Some("mcp:tools"));
}

/// Scopes a client requests out of habit (`openid profile`) are not a
/// narrowing: the parameter is ignored when it names nothing known.
#[tokio::test]
async fn unknown_requested_scopes_are_ignored() {
    let server = test_server().await;
    let token = redeem_with_scope(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some("openid profile"),
    )
    .await
    .expect("redemption succeeds");
    assert_eq!(token.scope.as_deref(), Some("mcp:tools mcp:resources"));

    let token = redeem_with_scope(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some("openid mcp:resources"),
    )
    .await
    .expect("redemption succeeds");
    assert_eq!(token.scope.as_deref(), Some("mcp:resources"));
}

/// A requested scope the IdP did not grant is never added, even when this
/// server knows it.
#[tokio::test]
async fn requested_scope_never_widens_the_grant() {
    let server = test_server_with_metadata(test_config(), &resource_metadata()).await;
    let assertion = || {
        make_id_jag(AssertionOverrides {
            scope: Some("mcp:tools"),
            ..Default::default()
        })
    };
    let token = redeem_with_scope(&server, &assertion(), Some("mcp:tools mcp:admin"))
        .await
        .expect("redemption succeeds");
    assert_eq!(token.scope.as_deref(), Some("mcp:tools"));

    // RFC 6749 §5.1: a response without `scope` would say the requested
    // scope was granted, so a request the grant holds none of is refused,
    // with or without require_scope.
    let assertion = assertion();
    let err = redeem_with_scope(&server, &assertion, Some("mcp:admin"))
        .await
        .expect_err("none of the requested scope is granted");
    assert_eq!(err.error, "invalid_scope");
    assert_eq!(err.status, 400);
    redeem_with_scope(&server, &assertion, None)
        .await
        .expect("the refusal leaves the assertion redeemable");
}

#[tokio::test]
async fn require_scope_refuses_an_empty_grant() {
    let mut config = test_config();
    config.allowed_scopes = Some(vec!["mcp:admin".to_owned()]);
    config.require_scope = true;
    let server = test_server_with(config).await;
    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("no allowed scope is granted");
    assert_eq!(err.error, "invalid_scope");
    assert_eq!(err.status, 400);
}

/// A redemption refused for its scope does not consume the assertion.
#[tokio::test]
async fn refused_scope_leaves_the_assertion_redeemable() {
    let mut config = test_config();
    config.require_scope = true;
    let server = test_server_with_metadata(config, &resource_metadata()).await;
    let assertion = make_id_jag(AssertionOverrides {
        scope: Some("mcp:tools"),
        ..Default::default()
    });
    let err = redeem_with_scope(&server, &assertion, Some("mcp:admin"))
        .await
        .expect_err("mcp:admin is not granted");
    assert_eq!(err.error, "invalid_scope");
    let token = redeem_with_scope(&server, &assertion, None)
        .await
        .expect("the same assertion redeems");
    assert_eq!(token.scope.as_deref(), Some("mcp:tools"));
}

// ── per-IdP policy ───────────────────────────────────────────────────

#[tokio::test]
async fn algorithm_outside_the_allowlist_is_refused() {
    let server = test_server().await;
    // PS256 verifies with the fixture's RSA key but is not allowed.
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            alg: Algorithm::PS256,
            ..Default::default()
        }),
    )
    .await
    .expect_err("PS256 is not in allowed_algs");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("allowed_algs"),
        "{}",
        err.description
    );

    // The fixture key declares RS256; the same key without `alg` serves PS256.
    let mut jwks: serde_json::Value = serde_json::from_str(IDP_JWKS).expect("fixture parses");
    jwks["keys"][0]
        .as_object_mut()
        .expect("fixture key is an object")
        .remove("alg");
    let mut config = test_config();
    config.trusted_idps[0].jwks_uri = None;
    config.trusted_idps[0].jwks = Some(jwks);
    config.trusted_idps[0].allowed_algs = vec!["PS256".to_owned()];
    let server = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
        .expect("builds");
    redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            alg: Algorithm::PS256,
            ..Default::default()
        }),
    )
    .await
    .expect("PS256 redeems once allowed");
}

#[tokio::test]
async fn client_not_allowed_for_the_idp_is_refused() {
    let mut config = test_config();
    config.trusted_idps[0].allowed_clients = vec!["public-client".to_owned()];
    let server = test_server_with(config).await;
    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("mcp-client may not redeem this IdP's assertions");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("may not issue"),
        "{}",
        err.description
    );
}

#[tokio::test]
async fn required_tenant_is_enforced() {
    let mut config = test_config();
    config.trusted_idps[0].required_tenant = Some("acme".to_owned());
    let server = test_server_with(config).await;

    let err = redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect_err("an assertion without tenant must fail");
    assert!(err.description.contains("no tenant"), "{}", err.description);

    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "tenant": "globex" }),
            ..Default::default()
        }),
    )
    .await
    .expect_err("another tenant must fail");
    assert_eq!(err.error, "invalid_grant");

    redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            extra: serde_json::json!({ "tenant": "acme" }),
            ..Default::default()
        }),
    )
    .await
    .expect("the required tenant redeems");
}

// ── error codes ──────────────────────────────────────────────────────

#[test]
fn minting_failure_is_a_server_error() {
    let err = minting_failed(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into());
    assert_eq!(err.error, "server_error");
    assert_eq!(err.status, 500);
}

// ── trusted-IdP keys ─────────────────────────────────────────────────

/// A config whose only IdP is `idp` (a wiremock), keys fetched from
/// `{idp}/jwks`.
fn config_for_idp(idp: &str) -> AuthorizationServerConfig {
    let mut config = test_config();
    config.trusted_idps[0].issuer = idp.to_owned();
    config.trusted_idps[0].jwks_uri = Some(format!("{idp}/jwks"));
    config.trusted_idps[0].allow_private_network = true;
    config
}

fn assertion_from(idp: &'static str) -> String {
    make_id_jag(AssertionOverrides {
        iss: idp,
        ..Default::default()
    })
}

/// `'static` view of a mock server's URI for [`AssertionOverrides`].
fn leak(uri: String) -> &'static str {
    Box::leak(uri.into_boxed_str())
}

async fn jwks_mock(status: u16) -> wiremock::MockServer {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(status).set_body_raw(IDP_JWKS, "application/json"),
        )
        .mount(&idp)
        .await;
    idp
}

/// Seed `server`'s key cache as if fetched `age` ago.
async fn seed_keys(server: &AuthorizationServer, age: Duration) {
    *server.idps[0].keys.jwks.write().await = Some(CachedJwks {
        keys: serde_json::from_str(IDP_JWKS).expect("fixture JWKS parses"),
        fetched_at: Instant::now()
            .checked_sub(age)
            .expect("monotonic clock is past the seeded age"),
    });
}

#[tokio::test]
async fn unreachable_idp_answers_temporarily_unavailable() {
    let idp = jwks_mock(500).await;
    let issuer = leak(idp.uri());
    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    let err = redeem(&server, &assertion_from(issuer))
        .await
        .expect_err("no keys can be fetched");
    assert_eq!(err.error, "temporarily_unavailable");
    assert_eq!(err.status, 503);

    // Rate-limited retries answer the same, not invalid_grant.
    let err = redeem(&server, &assertion_from(issuer))
        .await
        .expect_err("still no keys");
    assert_eq!(err.error, "temporarily_unavailable");
}

#[tokio::test]
async fn unknown_kid_is_invalid_grant() {
    let idp = jwks_mock(200).await;
    let issuer = leak(idp.uri());
    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    let err = redeem(
        &server,
        &make_id_jag(AssertionOverrides {
            iss: issuer,
            kid: "rotated-away",
            ..Default::default()
        }),
    )
    .await
    .expect_err("no published key has that kid");
    assert_eq!(err.error, "invalid_grant");
    assert_eq!(err.status, 400);
}

/// The last fetched key set keeps verifying while the IdP is down, up to
/// the maximum staleness.
#[tokio::test]
async fn stale_keys_serve_while_the_idp_is_unreachable() {
    let idp = jwks_mock(503).await;
    let issuer = leak(idp.uri());

    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    seed_keys(&server, JWKS_TTL + Duration::from_secs(100)).await;
    redeem(&server, &assertion_from(issuer))
        .await
        .expect("expired but not yet stale keys still verify");

    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    seed_keys(&server, JWKS_MAX_STALENESS + Duration::from_secs(100)).await;
    let err = redeem(&server, &assertion_from(issuer))
        .await
        .expect_err("keys past the maximum staleness are not used");
    assert_eq!(err.error, "temporarily_unavailable");
}

/// Concurrent redemptions against a cold cache share one fetch.
#[tokio::test]
async fn concurrent_cold_redemptions_share_one_fetch() {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_raw(IDP_JWKS, "application/json")
                .set_delay(Duration::from_millis(200)),
        )
        .expect(1)
        .mount(&idp)
        .await;
    let issuer = leak(idp.uri());
    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    let (first, second) = (assertion_from(issuer), assertion_from(issuer));
    let (a, b) = tokio::join!(redeem(&server, &first), redeem(&server, &second));
    a.expect("first redemption succeeds");
    b.expect("second redemption succeeds");
}

/// The configured issuer carries a trailing slash, the IdP publishes it
/// without one. Discovery refuses, naming both values, and the refusal
/// holds without refetching until the next refresh.
#[tokio::test]
async fn discovery_issuer_must_equal_the_configured_issuer() {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/.well-known/openid-configuration",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": idp.uri(),
                "jwks_uri": format!("{}/jwks", idp.uri()),
            })),
        )
        .expect(1)
        .mount(&idp)
        .await;
    let configured = leak(format!("{}/", idp.uri()));
    let mut config = config_for_idp(configured);
    config.trusted_idps[0].jwks_uri = None;
    let server = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
        .expect("builds");

    for _ in 0..2 {
        let err = redeem(&server, &assertion_from(configured))
            .await
            .expect_err("the discovery issuer differs");
        assert_eq!(err.error, "invalid_grant");
        assert!(
            err.description.contains(&format!("`{configured}`"))
                && err.description.contains(&format!("`{}`", idp.uri())),
            "{}",
            err.description
        );
    }
}

/// A client error from the IdP's key URL answers the same way on retry,
/// so the client is told what is wrong (`invalid_grant`) rather than to
/// retry; a rate limit or a timeout may heal and stays retryable.
#[tokio::test]
async fn a_client_error_from_the_idp_is_a_configuration_problem() {
    for (status, error) in [
        (404, "invalid_grant"),
        (403, "invalid_grant"),
        (429, "temporarily_unavailable"),
        (408, "temporarily_unavailable"),
    ] {
        let idp = jwks_mock(status).await;
        let issuer = leak(idp.uri());
        let server = AuthorizationServer::from_config(
            &config_for_idp(issuer),
            None,
            ReplayLedger::in_process(),
        )
        .expect("builds");
        let err = redeem(&server, &assertion_from(issuer))
            .await
            .expect_err("no keys can be fetched");
        assert_eq!(err.error, error, "{status}: {}", err.description);
        if error == "invalid_grant" {
            assert!(
                err.description.contains(&format!("returned {status}")),
                "{}",
                err.description
            );
        }
    }
}

/// An IdP that publishes RFC 8414 metadata and no OIDC discovery document
/// (the metadata ID-JAG §7.1 names) is discovered through the former.
#[tokio::test]
async fn discovery_falls_back_to_authorization_server_metadata() {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/.well-known/oauth-authorization-server",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": idp.uri(),
                "jwks_uri": format!("{}/jwks", idp.uri()),
            })),
        )
        .mount(&idp)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_raw(IDP_JWKS, "application/json"),
        )
        .mount(&idp)
        .await;
    let issuer = leak(idp.uri());
    let mut config = config_for_idp(issuer);
    config.trusted_idps[0].jwks_uri = None;
    let server = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
        .expect("builds");
    redeem(&server, &assertion_from(issuer))
        .await
        .expect("keys are found through the RFC 8414 metadata");
}

/// An IdP with neither discovery document is misconfigured, and the error
/// names both URLs tried.
#[tokio::test]
async fn an_idp_without_discovery_metadata_is_a_configuration_problem() {
    let idp = wiremock::MockServer::start().await;
    let issuer = leak(idp.uri());
    let mut config = config_for_idp(issuer);
    config.trusted_idps[0].jwks_uri = None;
    let server = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
        .expect("builds");
    let err = redeem(&server, &assertion_from(issuer))
        .await
        .expect_err("no discovery document");
    assert_eq!(err.error, "invalid_grant");
    assert!(
        err.description.contains("openid-configuration")
            && err.description.contains("oauth-authorization-server")
            && err.description.contains("jwks_uri"),
        "{}",
        err.description
    );
}

#[test]
fn authorization_server_metadata_urls_insert_the_well_known_suffix() {
    for (issuer, url) in [
        (
            "https://idp.test",
            "https://idp.test/.well-known/oauth-authorization-server",
        ),
        (
            "https://idp.test/",
            "https://idp.test/.well-known/oauth-authorization-server",
        ),
        (
            "https://idp.test/tenant/a",
            "https://idp.test/.well-known/oauth-authorization-server/tenant/a",
        ),
        (
            "https://idp.test:8443/t/",
            "https://idp.test:8443/.well-known/oauth-authorization-server/t",
        ),
    ] {
        assert_eq!(authorization_server_metadata_url(issuer), url, "{issuer}");
    }
}

#[tokio::test]
async fn idp_response_from_a_private_address_is_refused() {
    let idp = jwks_mock(200).await;
    let server = test_server().await;
    let url = format!("{}/jwks", idp.uri());
    match server.get_capped(&url, false, IDP_FETCH_TIMEOUT).await {
        Err(FetchFailure::Rejected(reason)) => {
            assert!(reason.contains("private address"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    server
        .get_capped(&url, true, IDP_FETCH_TIMEOUT)
        .await
        .expect("allow_private_network admits the loopback IdP");
}

#[tokio::test]
async fn oversized_idp_response_is_refused() {
    let idp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_raw(vec![b' '; MAX_IDP_RESPONSE_BYTES + 1], "application/json"),
        )
        .mount(&idp)
        .await;
    let server = test_server().await;
    match server
        .get_capped(&format!("{}/jwks", idp.uri()), true, IDP_FETCH_TIMEOUT)
        .await
    {
        Err(FetchFailure::Transient(error)) => {
            assert!(error.to_string().contains("more than"), "{error}");
        }
        other => panic!("expected an oversize refusal, got {other:?}"),
    }
}

/// Inline keys verify with no IdP endpoint at all.
#[tokio::test]
async fn inline_jwks_verify_without_network() {
    for jwks in [
        serde_json::from_str::<serde_json::Value>(IDP_JWKS).expect("fixture parses"),
        serde_json::Value::String(IDP_JWKS.to_owned()),
    ] {
        let mut config = test_config();
        config.trusted_idps[0].jwks_uri = None;
        config.trusted_idps[0].jwks = Some(jwks);
        config.validate().expect("inline keys validate");
        let server = AuthorizationServer::from_config(&config, None, ReplayLedger::in_process())
            .expect("builds");
        redeem(&server, &make_id_jag(AssertionOverrides::default()))
            .await
            .expect("inline keys verify");
        let err = redeem(
            &server,
            &make_id_jag(AssertionOverrides {
                kid: "unknown",
                ..Default::default()
            }),
        )
        .await
        .expect_err("an unknown kid has no inline key");
        assert_eq!(err.error, "invalid_grant");
    }
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

    config.signing_secret = Some("short".to_owned());
    assert!(config.validate().is_err());
    config.signing_secret = Some(SIGNING_SECRET.to_owned());

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

fn validation_error(config: &AuthorizationServerConfig) -> String {
    config
        .validate()
        .expect_err("config must be refused")
        .to_string()
}

/// The issuer is the origin the metadata and token endpoints are served
/// at, compared exactly by every IdP.
#[test]
fn issuer_must_be_a_bare_origin() {
    let mut config = test_config();
    // RFC 8414 §3.1: an issuer without a path may end in `/`, which Okta
    // keeps in the ID-JAG `aud` once the connection has it.
    config.issuer = "https://gw.test/".to_owned();
    config
        .validate()
        .expect("an origin with a trailing slash is valid");

    for issuer in ["https://gw.test//", "https://gw.test/tenant-a"] {
        config.issuer = issuer.to_owned();
        let err = validation_error(&config);
        assert!(
            err.contains("without a path") && err.contains("`https://gw.test`"),
            "{err}"
        );
    }

    config.issuer = "https:///".to_owned();
    assert!(validation_error(&config).contains("has no host"));

    config.issuer = "https://gw.test/tenant-a".to_owned();
    let err = validation_error(&config);
    assert!(
        err.contains("without a path") && err.contains("`https://gw.test`"),
        "{err}"
    );

    config.issuer = "https://admin:hunter2@gw.test".to_owned();
    let err = validation_error(&config);
    assert!(
        err.contains("userinfo") && !err.contains("hunter2"),
        "{err}"
    );

    config.issuer = "https://gw.test:8443".to_owned();
    config.validate().expect("an origin with a port is valid");
}

#[test]
fn lifetimes_are_bounded() {
    let mut config = test_config();
    config.clock_skew_secs = 301;
    assert!(validation_error(&config).contains("clock_skew_secs"));
    config.clock_skew_secs = 300;
    config.validate().expect("300 s of skew is the ceiling");

    config.access_token_ttl_secs = 86_401;
    assert!(validation_error(&config).contains("access_token_ttl_secs"));
    config.access_token_ttl_secs = 86_400;
    config.validate().expect("a day is the ceiling");

    for lifetime in [0, 3601] {
        config.max_assertion_lifetime_secs = lifetime;
        assert!(validation_error(&config).contains("max_assertion_lifetime_secs"));
    }
}

#[test]
fn trusted_idp_policy_is_validated() {
    let mut config = test_config();
    config.trusted_idps[0].jwks = serde_json::from_str(IDP_JWKS).ok();
    assert!(validation_error(&config).contains("not both"));

    config.trusted_idps[0].jwks_uri = None;
    config.trusted_idps[0].jwks = Some(serde_json::json!({ "keys": [] }));
    assert!(validation_error(&config).contains("no keys"));
    config.trusted_idps[0].jwks = Some(serde_json::json!({
        "keys": [{ "kty": "oct", "k": "c2VjcmV0" }]
    }));
    assert!(validation_error(&config).contains("symmetric"));
    config.trusted_idps[0].jwks = Some(serde_json::json!("not json"));
    assert!(validation_error(&config).contains("JSON Web Key Set"));
    config.trusted_idps[0].jwks = Some(serde_json::json!("${env.IDP_JWKS}"));
    config
        .validate()
        .expect("an unresolved placeholder is judged after expansion");

    let mut config = test_config();
    config.trusted_idps[0].allowed_algs = vec!["HS256".to_owned()];
    assert!(validation_error(&config).contains("HMAC"));
    config.trusted_idps[0].allowed_algs = vec!["none".to_owned()];
    assert!(validation_error(&config).contains("allowed_algs"));
    config.trusted_idps[0].allowed_algs = Vec::new();
    assert!(validation_error(&config).contains("allowed_algs"));

    let mut config = test_config();
    config.trusted_idps[0].allowed_clients = vec!["not-registered".to_owned()];
    assert!(validation_error(&config).contains("not-registered"));
    config.trusted_idps[0].allowed_clients = vec![CLIENT_ID.to_owned()];
    config.validate().expect("a registered client is valid");

    config.trusted_idps[0].required_tenant = Some(" ".to_owned());
    assert!(validation_error(&config).contains("required_tenant"));
}

// ── access-token signing keys ────────────────────────────────────────

fn es256_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generates")
        .serialize_pem()
}

/// An Ed25519 private key in PKCS#8 v1 PEM, the form `openssl genpkey`
/// writes: a fixed DER prefix, then the 32-byte seed.
fn ed25519_pem(seed: u8) -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[seed; 32]);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn asymmetric_key(alg: SigningAlgorithm, kid: Option<&str>, pem: String) -> SigningKeyConfig {
    SigningKeyConfig {
        kid: kid.map(str::to_owned),
        alg,
        secret: None,
        private_key: Some(pem),
    }
}

fn hmac_key(kid: Option<&str>, secret: &str) -> SigningKeyConfig {
    SigningKeyConfig {
        kid: kid.map(str::to_owned),
        alg: SigningAlgorithm::Hs256,
        secret: Some(secret.to_owned()),
        private_key: None,
    }
}

fn config_with_keys(keys: Vec<SigningKeyConfig>) -> AuthorizationServerConfig {
    let mut config = test_config();
    config.signing_secret = None;
    config.signing_keys = keys;
    config
}

async fn minted_token(server: &AuthorizationServer) -> String {
    redeem(server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds")
        .access_token
}

fn header_of(token: &str) -> Header {
    jsonwebtoken::decode_header(token).expect("minted token has a JWS header")
}

fn invalid_reason(server: &AuthorizationServer, token: &str) -> String {
    match server.verify_bearer(token) {
        EmaBearerOutcome::Invalid(reason) => reason,
        other => panic!("expected Invalid, got {}", discriminant_name(&other)),
    }
}

#[tokio::test]
async fn signing_secret_tokens_carry_a_kid_derived_from_it() {
    let server = test_server().await;
    let header = header_of(&minted_token(&server).await);
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ.as_deref(), Some(ACCESS_TOKEN_TYP));
    let kid = header.kid.expect("a minted token names its key");
    assert_eq!(kid, derived_hmac_kid(SIGNING_SECRET));
    assert!(
        kid.starts_with("hs256-") && !kid.contains(SIGNING_SECRET),
        "{kid}"
    );
}

/// A rotation lists the new key first and keeps the old one: tokens the
/// old key signed verify until it is removed, new tokens use the new key.
#[tokio::test]
async fn a_listed_kid_verifies_and_a_removed_one_is_refused() {
    let before = test_server_with(config_with_keys(vec![hmac_key(
        Some("2026-06"),
        SIGNING_SECRET,
    )]))
    .await;
    let old_token = minted_token(&before).await;

    let ec_key = es256_pem();
    let rotated = test_server_with(config_with_keys(vec![
        asymmetric_key(SigningAlgorithm::Es256, Some("2026-09"), ec_key.clone()),
        hmac_key(Some("2026-06"), SIGNING_SECRET),
    ]))
    .await;
    assert!(matches!(
        rotated.verify_bearer(&old_token),
        EmaBearerOutcome::Verified(_)
    ));
    let new_token = minted_token(&rotated).await;
    let header = header_of(&new_token);
    assert_eq!(header.kid.as_deref(), Some("2026-09"));
    assert_eq!(header.alg, Algorithm::ES256);

    let retired = test_server_with(config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::Es256,
        Some("2026-09"),
        ec_key,
    )]))
    .await;
    assert!(invalid_reason(&retired, &old_token).contains("unknown signing key"));
    assert!(matches!(
        retired.verify_bearer(&new_token),
        EmaBearerOutcome::Verified(_)
    ));
}

/// `signing_secret` moved into `signing_keys` without a kid names the same
/// key, so the tokens it signed survive the move.
#[tokio::test]
async fn a_secret_moved_into_signing_keys_keeps_its_tokens() {
    let token = minted_token(&test_server().await).await;
    let moved = test_server_with(config_with_keys(vec![
        asymmetric_key(SigningAlgorithm::EdDsa, None, ed25519_pem(7)),
        hmac_key(None, SIGNING_SECRET),
    ]))
    .await;
    assert!(matches!(
        moved.verify_bearer(&token),
        EmaBearerOutcome::Verified(_)
    ));
}

#[tokio::test]
async fn an_es256_key_publishes_only_its_public_half() {
    let server = test_server_with(config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::Es256,
        None,
        es256_pem(),
    )]))
    .await;
    let jwks = server
        .jwks()
        .expect("an asymmetric key is published")
        .clone();
    let keys = jwks["keys"].as_array().expect("a key array");
    assert_eq!(keys.len(), 1);
    let published = &keys[0];
    assert_eq!(published["kty"], "EC");
    assert_eq!(published["crv"], "P-256");
    assert_eq!(published["alg"], "ES256");
    assert_eq!(published["use"], "sig");
    assert!(published.get("d").is_none(), "{published}");
    assert_eq!(
        server.metadata()["jwks_uri"],
        format!("{GW_ISSUER}{JWKS_PATH}")
    );

    // Another resource server verifies the token from the published key.
    let token = minted_token(&server).await;
    assert_eq!(header_of(&token).kid.as_deref(), published["kid"].as_str());
    let jwk: Jwk = serde_json::from_value(published.clone()).expect("a JWK");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[GW_ISSUER]);
    validation.set_issuer(&[GW_ISSUER]);
    jsonwebtoken::decode::<serde_json::Value>(
        &token,
        &DecodingKey::from_jwk(&jwk).expect("usable JWK"),
        &validation,
    )
    .expect("the token verifies against the published key");
}

#[tokio::test]
async fn eddsa_and_rs256_keys_mint_tokens_their_published_keys_verify() {
    for (alg, pem, kty) in [
        (SigningAlgorithm::EdDsa, ed25519_pem(9), "OKP"),
        (SigningAlgorithm::Rs256, IDP_PRIVATE_PEM.to_owned(), "RSA"),
    ] {
        let server = test_server_with(config_with_keys(vec![asymmetric_key(alg, None, pem)])).await;
        let token = minted_token(&server).await;
        assert!(matches!(
            server.verify_bearer(&token),
            EmaBearerOutcome::Verified(_)
        ));
        let published = server.jwks().expect("published")["keys"][0].clone();
        assert_eq!(published["kty"], kty);
        assert_eq!(published["alg"], alg.as_str());
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                published.get(private).is_none(),
                "{alg:?} publishes {private}"
            );
        }
        // Without a configured kid, the RFC 7638 thumbprint names the key.
        let jwk: Jwk = serde_json::from_value(published.clone()).expect("a JWK");
        assert_eq!(
            published["kid"],
            jwk.thumbprint(ThumbprintHash::SHA256).expect("thumbprint")
        );
        assert_eq!(header_of(&token).kid.as_deref(), published["kid"].as_str());
    }
}

#[tokio::test]
async fn hmac_secrets_are_never_published() {
    let server = test_server().await;
    assert!(server.jwks().is_none());
    assert!(server.metadata().get("jwks_uri").is_none());

    let mixed = test_server_with(config_with_keys(vec![
        asymmetric_key(SigningAlgorithm::Es256, Some("ec"), es256_pem()),
        hmac_key(Some("hs"), SIGNING_SECRET),
    ]))
    .await;
    let jwks = mixed.jwks().expect("the EC key is published").to_string();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SIGNING_SECRET);
    assert!(
        !jwks.contains("\"oct\"")
            && !jwks.contains("\"hs\"")
            && !jwks.contains(&encoded)
            && !jwks.contains(SIGNING_SECRET),
        "{jwks}"
    );
}

/// A token without a `kid`, as gateways that stamped none minted with
/// `signing_secret`, verifies against an HS256 secret configured without a
/// `kid` (the shorthand, or the same secret moved into `signing_keys`),
/// and against nothing else.
#[tokio::test]
async fn a_kidless_token_verifies_only_against_a_kidless_hs256_secret() {
    let now = now_unix();
    let claims = serde_json::json!({
        "iss": GW_ISSUER, "sub": "user-42", "aud": GW_ISSUER, "client_id": CLIENT_ID,
        "jti": "legacy", "iat": now, "exp": now + 60, "idp": IDP_ISSUER,
    });
    let secret = EncodingKey::from_secret(SIGNING_SECRET.as_bytes());
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some(ACCESS_TOKEN_TYP.to_owned());
    let kidless = jsonwebtoken::encode(&header, &claims, &secret).expect("encodes");

    let server = test_server().await;
    match server.verify_bearer(&kidless) {
        EmaBearerOutcome::Verified(identity) => assert_eq!(identity.subject_id, "user-42"),
        other => panic!("expected Verified, got {}", discriminant_name(&other)),
    }
    let rotated = test_server_with(config_with_keys(vec![
        asymmetric_key(SigningAlgorithm::Es256, None, es256_pem()),
        hmac_key(None, SIGNING_SECRET),
    ]))
    .await;
    assert!(matches!(
        rotated.verify_bearer(&kidless),
        EmaBearerOutcome::Verified(_)
    ));

    let named = test_server_with(config_with_keys(vec![hmac_key(
        Some("2026-09"),
        SIGNING_SECRET,
    )]))
    .await;
    assert!(invalid_reason(&named, &kidless).contains("no kid"));

    let other_secret = test_server_with(config_with_keys(vec![hmac_key(
        None,
        "another-secret-of-at-least-32-bytes!",
    )]))
    .await;
    assert!(matches!(
        other_secret.verify_bearer(&kidless),
        EmaBearerOutcome::Invalid(_)
    ));

    header.alg = Algorithm::HS384;
    let hs384 = jsonwebtoken::encode(&header, &claims, &secret).expect("encodes");
    assert!(invalid_reason(&server, &hs384).contains("no kid"));
}

#[tokio::test]
async fn a_token_with_another_alg_than_its_key_is_refused() {
    let server = test_server().await;
    let now = now_unix();
    let claims = serde_json::json!({
        "iss": GW_ISSUER, "sub": "user-42", "aud": GW_ISSUER, "client_id": CLIENT_ID,
        "jti": "forged", "iat": now, "exp": now + 60, "idp": IDP_ISSUER,
    });
    let secret = EncodingKey::from_secret(SIGNING_SECRET.as_bytes());
    let mut header = Header::new(Algorithm::HS384);
    header.typ = Some(ACCESS_TOKEN_TYP.to_owned());
    header.kid = Some(derived_hmac_kid(SIGNING_SECRET));
    let other_alg = jsonwebtoken::encode(&header, &claims, &secret).expect("encodes");
    assert!(invalid_reason(&server, &other_alg).contains("algorithm"));
}

#[test]
fn signing_key_configuration_is_validated() {
    let mut config = test_config();
    config.signing_keys = vec![hmac_key(None, SIGNING_SECRET)];
    assert!(validation_error(&config).contains("not both"));
    config.signing_secret = None;
    config.signing_keys.clear();
    assert!(validation_error(&config).contains("needs a key"));

    let mixed_up = |alg, secret: bool, pem: bool| {
        config_with_keys(vec![SigningKeyConfig {
            kid: None,
            alg,
            secret: secret.then(|| SIGNING_SECRET.to_owned()),
            private_key: pem.then(es256_pem),
        }])
    };
    let err = validation_error(&mixed_up(SigningAlgorithm::Hs256, true, true));
    assert!(err.contains("takes `secret`"), "{err}");
    let err = validation_error(&mixed_up(SigningAlgorithm::Es256, true, false));
    assert!(err.contains("takes `private_key`"), "{err}");
    let err = validation_error(&config_with_keys(vec![hmac_key(None, "short")]));
    assert!(
        err.contains("signing_keys[0].secret") && err.contains("32 bytes"),
        "{err}"
    );
    let err = validation_error(&config_with_keys(vec![hmac_key(Some(" "), SIGNING_SECRET)]));
    assert!(err.contains("kid must not be empty"), "{err}");
    let err = validation_error(&config_with_keys(vec![
        hmac_key(Some("k"), SIGNING_SECRET),
        asymmetric_key(SigningAlgorithm::Es256, Some("k"), es256_pem()),
    ]));
    assert!(err.contains("more than once"), "{err}");
    let err = validation_error(&config_with_keys(vec![
        hmac_key(None, SIGNING_SECRET),
        hmac_key(None, SIGNING_SECRET),
    ]));
    assert!(err.contains("two keys carry kid"), "{err}");

    // Unusable key material is refused without being echoed.
    let err = validation_error(&config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::Es256,
        None,
        IDP_PRIVATE_PEM.to_owned(),
    )]));
    assert!(
        err.contains("not a usable ES256 key") && !err.contains("PRIVATE KEY"),
        "{err}"
    );
    let err = validation_error(&config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::Rs256,
        None,
        "not a pem".to_owned(),
    )]));
    assert!(err.contains("not a usable RS256 key"), "{err}");
    let pkcs8_v2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("Ed25519 key generates")
        .serialize_pem();
    let err = validation_error(&config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::EdDsa,
        None,
        pkcs8_v2,
    )]));
    assert!(err.contains("PKCS#8 v1"), "{err}");

    config_with_keys(vec![asymmetric_key(
        SigningAlgorithm::Es256,
        None,
        "${secret.ema-signing-key}".to_owned(),
    )])
    .validate()
    .expect("unresolved key material is judged after expansion");
    config_with_keys(vec![
        asymmetric_key(SigningAlgorithm::Es256, None, es256_pem()),
        hmac_key(None, SIGNING_SECRET),
    ])
    .validate()
    .expect("a rotation from the shorthand secret is valid");
}

#[test]
fn key_material_never_reaches_debug_output() {
    let key = hmac_key(Some("k1"), SIGNING_SECRET);
    let rendered = format!("{key:?}");
    assert!(
        rendered.contains("k1") && !rendered.contains(SIGNING_SECRET),
        "{rendered}"
    );
    let server = AuthorizationServer::from_config(&test_config(), None, ReplayLedger::in_process())
        .expect("builds");
    let rendered = format!("{server:?}");
    assert!(
        rendered.contains(&derived_hmac_kid(SIGNING_SECRET)) && !rendered.contains(SIGNING_SECRET),
        "{rendered}"
    );
}

// ── audit record and metrics ─────────────────────────────────────────

#[tokio::test]
async fn an_issued_token_is_audited_without_the_token() {
    let server = test_server().await;
    let assertion = make_id_jag(AssertionOverrides {
        jti: "idp-jti-1".to_owned(),
        ..Default::default()
    });
    let redemption = server.redeem(token_form(&assertion), None).await;
    let (response, issued) = redemption.result.as_ref().expect("redemption succeeds");
    let event = redemption.audit_event("req-1");
    assert_eq!(event.action, "mcpg.ema.token_issued");
    assert_eq!(
        event.outcome,
        mcpg_plugin_protocol::audit::AuditOutcome::Success
    );
    assert_eq!(event.request_id.as_deref(), Some("req-1"));
    assert_eq!(event.actor.subject_id.as_deref(), Some("user-42"));
    assert_eq!(event.actor.issuer.as_deref(), Some(IDP_ISSUER));
    assert_eq!(event.details["idp"], IDP_ISSUER);
    assert_eq!(event.details["subject"], "user-42");
    assert_eq!(event.details["client_id"], CLIENT_ID);
    assert_eq!(event.details["scope"], "mcp:tools mcp:resources");
    assert_eq!(event.details["token_jti"], issued.jti.as_str());
    assert_eq!(
        event.details["token_jti"],
        minted_claims(&response.access_token)["jti"]
    );
    assert_eq!(event.details["assertion_jti"], "idp-jti-1");
    let recorded = serde_json::to_string(&event).expect("serializes");
    for secret_part in [
        response.access_token.as_str(),
        assertion.as_str(),
        response.access_token.split('.').nth(2).expect("signature"),
        assertion.split('.').nth(2).expect("signature"),
    ] {
        assert!(!recorded.contains(secret_part), "{recorded}");
    }
}

#[tokio::test]
async fn a_refused_request_is_audited_as_an_authentication_failure() {
    let server = test_server().await;
    let mut form = token_form(&make_id_jag(AssertionOverrides::default()));
    form.client_secret = Some("wrong".to_owned());
    let event = server.redeem(form, None).await.audit_event("req-2");
    assert_eq!(event.action, "mcpg.auth.failed");
    assert_eq!(event.details["auth_method"], "ema_token");
    assert_eq!(event.details["error"], "invalid_client");
    assert!(event.details["client_id"].is_null());
    assert!(event.details["idp"].is_null());

    // Past client authentication and routing, both are known.
    let other_client = make_id_jag(AssertionOverrides {
        client_id: "someone-else",
        ..Default::default()
    });
    let event = server
        .redeem(token_form(&other_client), None)
        .await
        .audit_event("req-3");
    assert_eq!(event.details["error"], "invalid_grant");
    assert_eq!(event.details["client_id"], CLIENT_ID);
    assert_eq!(event.details["idp"], IDP_ISSUER);
}

/// Records every metric the code under test touches, as `name{k=v,…}`.
#[derive(Default)]
struct CapturedMetrics(Mutex<Vec<String>>);

impl CapturedMetrics {
    fn push(&self, key: &metrics::Key) {
        let labels: Vec<String> = key
            .labels()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect();
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(format!("{}{{{}}}", key.name(), labels.join(",")));
    }

    fn recorded(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn seen(&self, metric: &str) -> bool {
        self.recorded().iter().any(|m| m == metric)
    }
}

impl metrics::Recorder for CapturedMetrics {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        self.push(key);
        metrics::Counter::noop()
    }
    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        self.push(key);
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        key: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        self.push(key);
        metrics::Histogram::noop()
    }
}

#[tokio::test]
async fn token_requests_are_counted_by_outcome_error_and_idp() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = test_server().await;
    redeem(&server, &make_id_jag(AssertionOverrides::default()))
        .await
        .expect("redemption succeeds");
    let untrusted = make_id_jag(AssertionOverrides {
        iss: "https://evil.test",
        ..Default::default()
    });
    redeem(&server, &untrusted)
        .await
        .expect_err("an untrusted issuer is refused");
    let _ = TokenRedemption::malformed("malformed token request".to_owned());

    let recorded = captured.recorded();
    for expected in [
        format!(
            "mcpg_ema_token_requests_total{{outcome=issued,error=none,idp={IDP_ISSUER},\
             grant=jwt_bearer}}"
        ),
        "mcpg_ema_token_requests_total{outcome=refused,error=invalid_grant,idp=none,\
         grant=jwt_bearer}"
            .to_owned(),
        "mcpg_ema_token_requests_total{outcome=refused,error=invalid_request,idp=none,grant=none}"
            .to_owned(),
        "mcpg_ema_token_latency_ms{outcome=issued,grant=jwt_bearer}".to_owned(),
        "mcpg_ema_token_latency_ms{outcome=refused,grant=jwt_bearer}".to_owned(),
        "mcpg_ema_token_latency_ms{outcome=refused,grant=none}".to_owned(),
    ] {
        assert!(
            recorded.contains(&expected),
            "{expected} not in {recorded:?}"
        );
    }
    // The assertion's own `iss` never becomes a label value.
    assert!(
        !recorded.iter().any(|m| m.contains("evil.test")),
        "{recorded:?}"
    );
}

#[tokio::test]
async fn key_set_refreshes_are_counted_per_idp() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let idp = jwks_mock(200).await;
    let issuer = leak(idp.uri());
    let server =
        AuthorizationServer::from_config(&config_for_idp(issuer), None, ReplayLedger::in_process())
            .expect("builds");
    redeem(&server, &assertion_from(issuer))
        .await
        .expect("redeems after fetching the IdP's keys");
    assert!(
        captured.seen(&format!(
            "mcpg_ema_jwks_refresh_total{{idp={issuer},outcome=ok}}"
        )),
        "{:?}",
        captured.recorded()
    );
}

#[path = "authorization_server_client_tests.rs"]
mod client_auth;

#[path = "authorization_server_identity_tests.rs"]
mod identity_claims;

#[path = "authorization_server_interactive_tests.rs"]
mod interactive_flow;

#[path = "authorization_server_callback_tests.rs"]
mod callback_flow;

#[path = "authorization_server_dpop_tests.rs"]
mod dpop_proofs;

#[path = "authorization_server_rar_tests.rs"]
mod rar_details;

#[path = "authorization_server_dpop_resource_tests.rs"]
mod dpop_resource;
