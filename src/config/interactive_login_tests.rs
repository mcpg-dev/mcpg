use super::*;
use crate::config::{AppConfig, access_posture_warnings};

/// An authorization server with interactive sign-in through one IdP, a
/// registered EMA client and nothing else: valid, and warning-free.
const BASE: &str = r#"
gateway:
  secrets:
    dir: /run/mcpg/secrets
governance:
  access:
    require_authentication: true
    resource_metadata:
      resource: https://mcp.example.com/mcp
      scopes_supported: [mcp:tools, mcp:resources]
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: ema-signing-secret-0123456789abcdef
      trusted_idps:
        - issuer: https://acme.okta.com
          allowed_hosts: [acme.okta.com]
          login:
            client_id: 0oa1agent
            client_secret: login-client-secret-0123
      clients:
        - client_id: mcp-client
"#;

/// The RSA key the authorization-server tests sign with.
const RSA_PEM: &str = include_str!("../runtime/testdata/idp_private.pem");

fn p256_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generates")
        .serialize_pem()
}

/// An Ed25519 private key in PKCS#8 v1 PEM: a fixed DER prefix, then the
/// 32-byte seed.
fn ed25519_pem() -> String {
    use base64::Engine as _;
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[7; 32]);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn parse(yaml: &str) -> AppConfig {
    serde_yaml::from_str(yaml).expect("test config parses")
}

fn base() -> AppConfig {
    let config = parse(BASE);
    config.validate().expect("the base config validates");
    config
}

fn authz(config: &mut AppConfig) -> &mut AuthorizationServerConfig {
    config
        .governance
        .access
        .authorization_server
        .as_mut()
        .expect("authorization_server")
}

fn login(config: &mut AppConfig) -> &mut TrustedIdpLoginConfig {
    authz(config).trusted_idps[0]
        .login
        .as_mut()
        .expect("login block")
}

fn interactive(config: &mut AppConfig) -> &mut InteractiveLoginConfig {
    authz(config)
        .interactive
        .get_or_insert_with(InteractiveLoginConfig::default)
}

/// The validation error of `config`, with its causes.
fn refused(config: &AppConfig) -> String {
    format!(
        "{:#}",
        config.validate().expect_err("the config must be refused")
    )
}

fn public_client(
    client_id: &str,
    redirect_uris: &[&str],
) -> crate::config::AuthorizationServerClientConfig {
    serde_json::from_value(serde_json::json!({
        "client_id": client_id,
        "redirect_uris": redirect_uris,
    }))
    .expect("client parses")
}

// ── defaults ─────────────────────────────────────────────────────────

/// A login block alone turns interactive sign-in on with the documented
/// defaults; a single node keeps the state in a sealed file store.
#[test]
fn login_and_interactive_settings_take_their_defaults() {
    let mut config = base();
    let login = login(&mut config).clone();
    assert_eq!(
        login.scopes,
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(login.timeout_ms, 5_000);
    assert_eq!(
        login.effective_client_auth(),
        Some(LoginClientAuth::ClientSecretBasic)
    );
    assert_eq!(
        login.effective_assertion_audience(),
        LoginAssertionAudience::TokenEndpoint
    );
    assert_eq!(
        login.effective_display_name("https://acme.okta.com"),
        "acme.okta.com"
    );
    assert!(!login.endpoints_configured());

    let authz = authz(&mut config).clone();
    assert!(authz.interactive.is_none());
    assert_eq!(
        authz.login_idp().map(|(idp, _)| idp.issuer.as_str()),
        Some("https://acme.okta.com")
    );
    assert_eq!(
        authz.login_callback_url(),
        "https://mcp.example.com/oauth/callback"
    );
    let settings = authz.interactive_settings();
    assert_eq!(settings.access_token_ttl_secs, 900);
    assert_eq!(settings.authorization_code_ttl_secs, 60);
    assert_eq!(settings.transaction_ttl_secs, 600);
    assert_eq!(settings.rate_limit_per_min, 120);
    assert_eq!(settings.revocation_check_interval_secs, 10);
    assert_eq!(settings.consent.remember_days, 30);
    let refresh = &settings.refresh_tokens;
    assert!(refresh.enabled && refresh.revalidate_with_idp);
    assert_eq!(refresh.idle_ttl_secs, 14 * 86_400);
    assert_eq!(refresh.absolute_ttl_secs, 30 * 86_400);
    assert_eq!(refresh.reuse_grace_secs, 0);
    assert_eq!(refresh.max_grants_per_principal, 50);
    assert_eq!(refresh.idp_unavailable_grace_secs, 3_600);
    assert_eq!(settings.revalidate_interval_secs(), 900);
    assert!(settings.idp_sessions.revoke_superseded && settings.idp_sessions.connect_page);
    assert_eq!(settings.idp_session_max_age_secs(), 30 * 86_400);
    let dcr = &settings.dynamic_client_registration;
    assert!(!dcr.enabled && !dcr.allow_open && dcr.allowed_redirect_hosts.is_empty());
    assert_eq!(dcr.client_ttl_secs, 30 * 86_400);
    assert_eq!(dcr.max_clients, 1_000);
    assert_eq!(dcr.registrations_per_hour_per_ip, 20);

    let ResolvedInteractiveStore::File { dir } = settings.resolved_store(&config.cluster) else {
        panic!("a single node defaults to the file store");
    };
    assert!(dir.ends_with("oauth"), "{}", dir.display());
    assert_eq!(
        settings.state_key_source(&config.cluster),
        Some(StateKeySource::GeneratedFile {
            path: dir.join(GENERATED_STATE_KEY_FILE)
        })
    );

    // Existing clients keep ID-JAG redemption only.
    let client = &authz.clients[0];
    assert_eq!(client.effective_grant_types(), [ClientGrantType::JwtBearer]);
    assert_eq!(client.consent, ClientConsent::Auto);
    assert_eq!(
        authz.client_id_metadata_documents.redirect_uri_policy,
        RedirectUriPolicy::SameHost
    );
}

/// Every key as an operator writes it.
#[test]
fn every_interactive_key_parses() {
    let yaml = format!(
        "{BASE}      interactive:
        access_token_ttl_secs: 600
        authorization_code_ttl_secs: 30
        transaction_ttl_secs: 300
        rate_limit_per_min: 0
        revocation_check_interval_secs: 5
        consent:
          remember_days: 0
          service_name: Acme MCP Gateway
          scope_descriptions:
            mcp:tools: Use the tools this gateway exposes
        refresh_tokens:
          enabled: false
          idle_ttl_secs: 86400
          absolute_ttl_secs: 604800
          reuse_grace_secs: 10
          max_grants_per_principal: 5
          revalidate_with_idp: false
          revalidate_interval_secs: 3600
          idp_unavailable_grace_secs: 0
        idp_sessions:
          revoke_superseded: false
          max_age_secs: 86400
          connect_page: false
        dynamic_client_registration:
          enabled: true
          initial_access_tokens: [\"${{secret.DCR_TOKEN}}\"]
          allowed_redirect_hosts: [www.cursor.com]
          client_ttl_secs: 86400
          max_clients: 10
          registrations_per_hour_per_ip: 0
        store:
          kind: file
          dir: /var/lib/mcpg/oauth
        state_keys:
          - kid: as-state-2026-09
            secret: \"${{secret.AS_STATE_KEY}}\"
      client_id_metadata_documents:
        allowed_hosts: [claude.ai]
        redirect_uri_policy: allowed_hosts
"
    );
    let config = parse(&yaml);
    config.validate().expect("every key validates");
    let authz = config
        .governance
        .access
        .authorization_server
        .as_ref()
        .unwrap();
    let settings = authz.interactive.as_ref().unwrap();
    assert_eq!(settings.revalidate_interval_secs(), 3_600);
    assert_eq!(settings.idp_session_max_age_secs(), 86_400);
    assert_eq!(
        settings.resolved_store(&config.cluster),
        ResolvedInteractiveStore::File {
            dir: PathBuf::from("/var/lib/mcpg/oauth")
        }
    );
    assert_eq!(
        settings.state_key_source(&config.cluster),
        Some(StateKeySource::Keyring {
            kid: "as-state-2026-09".to_owned()
        })
    );
    assert_eq!(
        authz.client_id_metadata_documents.redirect_uri_policy,
        RedirectUriPolicy::AllowedHosts
    );
}

/// Secrets never reach a `Debug` rendering.
#[test]
fn debug_renderings_redact_secrets() {
    let mut config = base();
    login(&mut config).client_secret = Some("LOGIN-SECRET-SENTINEL-0123".to_owned());
    let settings = interactive(&mut config);
    settings.state_keys.push(StateKeyConfig {
        kid: "k1".to_owned(),
        secret: "STATE-KEY-SENTINEL".to_owned(),
    });
    settings.dynamic_client_registration.initial_access_tokens =
        vec!["DCR-TOKEN-SENTINEL-0123456789abcdef".to_owned()];
    let mut keyed = config.clone();
    login(&mut keyed).client_secret = None;
    login(&mut keyed).private_key = Some("PRIVATE-KEY-SENTINEL".to_owned());
    let rendered = format!("{config:?}{keyed:?}");
    for secret in [
        "LOGIN-SECRET-SENTINEL",
        "STATE-KEY-SENTINEL",
        "DCR-TOKEN-SENTINEL",
        "PRIVATE-KEY-SENTINEL",
    ] {
        assert!(!rendered.contains(secret), "{secret} leaked");
    }
    assert!(rendered.contains("0oa1agent"));
}

// ── the login block and the issuer ───────────────────────────────────

#[test]
fn only_one_idp_may_have_a_login_block() {
    let mut config = base();
    let mut second = authz(&mut config).trusted_idps[0].clone();
    second.issuer = "https://other.example.com".to_owned();
    second.allowed_hosts = vec!["other.example.com".to_owned()];
    authz(&mut config).trusted_idps.push(second.clone());
    let err = refused(&config);
    assert!(
        err.contains("2 entries have a login block") && err.contains("chooser"),
        "{err}"
    );
    // A second IdP without login is ID-JAG-only and fine.
    authz(&mut config).trusted_idps[1].login = None;
    config.validate().expect("one login IdP and one EMA IdP");
}

#[test]
fn the_login_credential_matches_its_method() {
    let set = |secret: Option<&str>, key: Option<String>, method: Option<LoginClientAuth>| {
        let mut config = base();
        let login = login(&mut config);
        login.client_secret = secret.map(str::to_owned);
        login.private_key = key;
        login.client_auth = method;
        config
    };
    let err = refused(&set(None, None, None));
    assert!(err.contains("needs a credential"), "{err}");
    let err = refused(&set(
        Some("login-client-secret-0123"),
        Some(RSA_PEM.to_owned()),
        None,
    ));
    assert!(err.contains("not both"), "{err}");
    let err = refused(&set(
        None,
        Some(RSA_PEM.to_owned()),
        Some(LoginClientAuth::ClientSecretPost),
    ));
    assert!(err.contains("takes client_secret"), "{err}");
    let err = refused(&set(
        Some("login-client-secret-0123"),
        None,
        Some(LoginClientAuth::PrivateKeyJwt),
    ));
    assert!(err.contains("takes private_key"), "{err}");
    let err = refused(&set(Some("too-short"), None, None));
    assert!(err.contains("at least 16 bytes"), "{err}");
    set(Some("${secret.OKTA_SECRET}"), None, None)
        .validate()
        .expect("a placeholder secret is judged once resolved");

    let mut with_key_settings = set(Some("login-client-secret-0123"), None, None);
    login(&mut with_key_settings).key_id = Some("k1".to_owned());
    let err = refused(&with_key_settings);
    assert!(
        err.contains("apply only to client_auth private_key_jwt"),
        "{err}"
    );

    // The key type decides the default algorithm; a mismatch is refused.
    for (pem, alg) in [
        (RSA_PEM.to_owned(), LoginSigningAlg::Rs256),
        (p256_pem(), LoginSigningAlg::Es256),
        (ed25519_pem(), LoginSigningAlg::EdDsa),
    ] {
        assert_eq!(login_key_algorithm(&pem, None), Ok(alg));
        let config = set(None, Some(pem), None);
        config.validate().expect("a usable key validates");
    }
    assert_eq!(
        login_key_algorithm(RSA_PEM, Some(LoginSigningAlg::Ps256)),
        Ok(LoginSigningAlg::Ps256)
    );
    assert_eq!(
        login_key_algorithm(&RSA_PEM.replace('\n', "\\n"), None),
        Ok(LoginSigningAlg::Rs256),
        "an env-escaped PEM loads"
    );
    let mut mismatched = set(None, Some(RSA_PEM.to_owned()), None);
    login(&mut mismatched).signing_alg = Some(LoginSigningAlg::Es256);
    let err = refused(&mismatched);
    assert!(err.contains("private_key cannot sign ES256"), "{err}");
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .expect("P-384 key generates")
        .serialize_pem();
    let err = refused(&set(None, Some(p384), None));
    assert!(err.contains("is not a usable PEM private key"), "{err}");
    let err = refused(&set(None, Some("not a pem".to_owned()), None));
    assert!(err.contains("is not a usable PEM private key"), "{err}");
    set(None, Some("${secret.OKTA_AGENT_KEY}".to_owned()), None)
        .validate()
        .expect("a placeholder key is judged once resolved");
    let mut long_kid = set(None, Some(RSA_PEM.to_owned()), None);
    login(&mut long_kid).key_id = Some("k".repeat(129));
    assert!(refused(&long_kid).contains("key_id"));
}

#[test]
fn login_scopes_need_openid_once_each() {
    let with_scopes = |scopes: &[&str]| {
        let mut config = base();
        login(&mut config).scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        config
    };
    assert!(
        refused(&with_scopes(&["profile", "offline_access"])).contains("must include `openid`")
    );
    assert!(refused(&with_scopes(&["openid", "email", "email"])).contains("more than once"));
    assert!(refused(&with_scopes(&["openid", "bad scope"])).contains("not an OAuth scope token"));
    let many: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
    let mut too_many = with_scopes(&["openid"]);
    login(&mut too_many).scopes.extend(many);
    assert!(refused(&too_many).contains("more than 20"));
    with_scopes(&["openid"])
        .validate()
        .expect("openid alone is enough");
}

#[test]
fn reserved_authorize_params_are_refused() {
    for name in RESERVED_AUTHORIZE_PARAMS {
        let mut config = base();
        login(&mut config)
            .authorize_params
            .insert(name.to_owned(), "x".to_owned());
        let err = refused(&config);
        assert!(err.contains(&format!("sets `{name}`")), "{name}: {err}");
    }
    let mut config = base();
    login(&mut config)
        .authorize_params
        .insert("acr_values".to_owned(), "phr".to_owned());
    config
        .validate()
        .expect("an IdP-specific parameter is allowed");
}

#[test]
fn login_endpoints_are_https_on_the_allowed_hosts() {
    let with_endpoint = |url: &str, allow_private: bool| {
        let mut config = base();
        authz(&mut config).trusted_idps[0].allow_private_network = allow_private;
        login(&mut config).token_endpoint = Some(url.to_owned());
        config
    };
    with_endpoint("https://acme.okta.com/oauth2/v1/token", false)
        .validate()
        .expect("https on the IdP host");
    let err = refused(&with_endpoint(
        "http://acme.okta.com/oauth2/v1/token",
        false,
    ));
    assert!(
        err.contains("token_endpoint") && err.contains("https"),
        "{err}"
    );
    let err = refused(&with_endpoint("https://evil.example.com/token", false));
    assert!(
        err.contains("token_endpoint") && err.contains("allowed"),
        "{err}"
    );
    let err = refused(&with_endpoint("https://acme.okta.com/token#x", false));
    assert!(err.contains("fragment"), "{err}");
    let mut local = with_endpoint("http://127.0.0.1:9000/token", true);
    authz(&mut local).trusted_idps[0].allowed_hosts.clear();
    local
        .validate()
        .expect("http and loopback with allow_private_network");
    let mut timeout = base();
    login(&mut timeout).timeout_ms = 100;
    assert!(refused(&timeout).contains("timeout_ms"));
    let mut name = base();
    login(&mut name).display_name = Some("x".repeat(61));
    assert!(refused(&name).contains("display_name"));
}

#[test]
fn a_login_needs_an_https_issuer_except_on_loopback() {
    let with_issuer = |issuer: &str, resource: &str| {
        let mut config = base();
        authz(&mut config).issuer = issuer.to_owned();
        let rm = config.governance.access.resource_metadata.as_mut().unwrap();
        rm.resource = resource.to_owned();
        rm.allow_loopback_resource = true;
        config
    };
    let err = refused(&with_issuer(
        "http://mcp.example.com",
        "http://mcp.example.com/mcp",
    ));
    assert!(
        err.contains("must be https:// with interactive sign-in"),
        "{err}"
    );
    for issuer in ["http://127.0.0.1:8080", "http://localhost:8080"] {
        with_issuer(issuer, &format!("{issuer}/mcp"))
            .validate()
            .expect(issuer);
    }
    // Without a login block the EMA server keeps its warning-only rule.
    let mut ema = with_issuer("http://mcp.example.com", "http://mcp.example.com/mcp");
    authz(&mut ema).trusted_idps[0].login = None;
    ema.validate().expect("EMA alone accepts an http issuer");
}

#[test]
fn interactive_settings_need_a_login_idp() {
    let mut config = base();
    authz(&mut config).trusted_idps[0].login = None;
    interactive(&mut config);
    let err = refused(&config);
    assert!(
        err.contains("interactive configures interactive sign-in, which no IdP offers"),
        "{err}"
    );
}

// ── registered clients ───────────────────────────────────────────────

#[test]
fn grant_types_and_redirect_uris_agree() {
    let with_client = |client: crate::config::AuthorizationServerClientConfig| {
        let mut config = base();
        authz(&mut config).clients.push(client);
        config
    };
    let cli = public_client("acme-cli", &["http://127.0.0.1/callback"]);
    assert_eq!(
        cli.effective_grant_types(),
        [
            ClientGrantType::AuthorizationCode,
            ClientGrantType::RefreshToken
        ]
    );
    assert!(cli.allows_grant(ClientGrantType::RefreshToken));
    assert!(!cli.allows_grant(ClientGrantType::JwtBearer));
    with_client(cli.clone())
        .validate()
        .expect("an interactive public client validates");

    let mut no_login = with_client(cli.clone());
    authz(&mut no_login).trusted_idps[0].login = None;
    assert!(refused(&no_login).contains("needs interactive sign-in"));

    let mut no_uris = public_client("acme-cli", &[]);
    no_uris.grant_types = Some(vec![ClientGrantType::AuthorizationCode]);
    assert!(refused(&with_client(no_uris)).contains("needs redirect_uris"));

    let mut refresh_only = cli.clone();
    refresh_only.grant_types = Some(vec![ClientGrantType::RefreshToken]);
    assert!(refused(&with_client(refresh_only)).contains("needs authorization_code"));

    let mut jwt_with_uris = cli.clone();
    jwt_with_uris.grant_types = Some(vec![ClientGrantType::JwtBearer]);
    assert!(refused(&with_client(jwt_with_uris)).contains("lacks authorization_code"));

    let mut twice = cli.clone();
    twice.grant_types = Some(vec![
        ClientGrantType::AuthorizationCode,
        ClientGrantType::AuthorizationCode,
    ]);
    assert!(refused(&with_client(twice)).contains("more than once"));

    let mut empty = cli.clone();
    empty.grant_types = Some(Vec::new());
    assert!(refused(&with_client(empty)).contains("must not be empty"));

    let mut both = cli.clone();
    both.grant_types = Some(vec![
        ClientGrantType::JwtBearer,
        ClientGrantType::AuthorizationCode,
    ]);
    with_client(both)
        .validate()
        .expect("one client may redeem ID-JAGs and sign users in");

    let mut named = cli.clone();
    named.client_name = Some("x".repeat(81));
    assert!(refused(&with_client(named)).contains("client_name"));

    let parsed: crate::config::AuthorizationServerClientConfig = serde_yaml::from_str(
        "client_id: c\nredirect_uris: [https://app.example.com/cb]\ngrant_types: \
         [urn:ietf:params:oauth:grant-type:jwt-bearer, authorization_code, refresh_token]\n\
         consent: always\n",
    )
    .expect("grant type names parse");
    assert_eq!(parsed.effective_grant_types().len(), 3);
    assert_eq!(parsed.consent, ClientConsent::Always);
}

#[test]
fn registered_redirect_uris_follow_the_syntax() {
    for (uri, kind) in [
        ("https://app.example.com/callback", RedirectUriKind::Https),
        (
            "https://app.example.com:8443/cb?x=1",
            RedirectUriKind::Https,
        ),
        ("https://127.0.0.1/cb", RedirectUriKind::Https),
        (
            "http://127.0.0.1/callback",
            RedirectUriKind::Loopback(LoopbackHost::Ipv4),
        ),
        (
            "http://127.0.0.1:33418",
            RedirectUriKind::Loopback(LoopbackHost::Ipv4),
        ),
        (
            "http://[::1]:8080/cb",
            RedirectUriKind::Loopback(LoopbackHost::Ipv6),
        ),
        (
            "http://localhost/callback",
            RedirectUriKind::Loopback(LoopbackHost::Localhost),
        ),
    ] {
        assert_eq!(redirect_uri_kind(uri), Ok(kind), "{uri}");
    }
    for (uri, reason) in [
        ("https://app.example.com/cb#frag", "fragment"),
        ("https://user:pw@app.example.com/cb", "userinfo"),
        ("https://*.example.com/cb", "wildcard"),
        ("http://app.example.com/cb", "loopback hosts"),
        ("http://127.0.0.1.evil.com/cb", "loopback hosts"),
        ("http://localhost.evil/cb", "loopback hosts"),
        ("http://0x7f000001/cb", "loopback hosts"),
        ("http://127.1/cb", "loopback hosts"),
        ("http://LOCALHOST/cb", "loopback hosts"),
        ("cursor://anysphere.cursor-retrieval/cb", "private-use"),
        ("com.example.app:/oauth2redirect", "private-use"),
        ("HTTPS://app.example.com/cb", "private-use"),
        ("/relative/cb", "private-use"),
        ("https:///cb", "no host"),
        ("https://app.example.com/a b", "whitespace"),
        ("http://[::1/cb", "unterminated"),
        ("https://app.example.com\\@evil.example/cb", "backslash"),
        ("https://cl\u{0430}ude.ai/cb", "ASCII"),
        ("https://app.example.com/caf\u{e9}", "ASCII"),
        ("http://127.0.0.1:8080\\cb", "backslash"),
        ("http://127.0.0.1/a/../callback", "canonical form"),
        ("http://127.0.0.1/./callback", "canonical form"),
        ("http://127.0.0.1/%2e%2e/callback", "canonical form"),
        ("http://localhost/cb?a=<b>", "canonical form"),
    ] {
        let err = redirect_uri_kind(uri).expect_err(uri);
        assert!(err.contains(reason), "{uri}: {err}");
    }
    for (uri, path, query) in [
        ("http://127.0.0.1:33418", "/", None),
        ("http://127.0.0.1:33418/", "/", None),
        ("http://localhost/callback?x=1", "/callback", Some("x=1")),
        ("http://[::1]:8080?", "/", Some("")),
    ] {
        assert!(redirect_uri_kind(uri).is_ok(), "{uri}");
        assert_eq!(loopback_path_and_query(uri), (path, query), "{uri}");
    }
    let long = format!(
        "https://app.example.com/{}",
        "a".repeat(MAX_REDIRECT_URI_BYTES)
    );
    assert!(redirect_uri_kind(&long).unwrap_err().contains("longer"));

    let with_uris = |uris: &[&str]| {
        let mut config = base();
        authz(&mut config)
            .clients
            .push(public_client("acme-cli", uris));
        config
    };
    let err = refused(&with_uris(&["http://app.example.com/cb"]));
    assert!(
        err.contains("redirect_uris entry `http://app.example.com/cb`"),
        "{err}"
    );
    let err = refused(&with_uris(&[
        "https://a.example.com/cb",
        "https://a.example.com/cb",
    ]));
    assert!(err.contains("more than once"), "{err}");
    let eleven: Vec<String> = (0..11)
        .map(|i| format!("https://a.example.com/{i}"))
        .collect();
    let err = refused(&with_uris(
        &eleven.iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    assert!(err.contains("more than 10"), "{err}");
}

#[test]
fn consent_skip_is_refused_with_a_loopback_redirect_uri() {
    let with_consent = |uris: &[&str]| {
        let mut config = base();
        let mut client = public_client("acme-cli", uris);
        client.consent = ClientConsent::Skip;
        authz(&mut config).clients.push(client);
        config
    };
    let err = refused(&with_consent(&[
        "https://app.example.com/cb",
        "http://127.0.0.1/cb",
    ]));
    assert!(err.contains("consent: skip is refused"), "{err}");
    with_consent(&["https://app.example.com/cb"])
        .validate()
        .expect("an https-only client may skip consent");
}

// ── interactive settings ─────────────────────────────────────────────

#[test]
fn lifetimes_stay_in_bounds_and_in_order() {
    let cases: [(&str, fn(&mut InteractiveLoginConfig)); 13] = [
        ("access_token_ttl_secs", |s| s.access_token_ttl_secs = 59),
        ("access_token_ttl_secs", |s| s.access_token_ttl_secs = 3_601),
        ("authorization_code_ttl_secs", |s| {
            s.authorization_code_ttl_secs = 601
        }),
        ("transaction_ttl_secs", |s| s.transaction_ttl_secs = 30),
        ("revocation_check_interval_secs", |s| {
            s.revocation_check_interval_secs = 61
        }),
        ("refresh_tokens.idle_ttl_secs", |s| {
            s.refresh_tokens.idle_ttl_secs = 60
        }),
        ("refresh_tokens.absolute_ttl_secs", |s| {
            s.refresh_tokens.absolute_ttl_secs = s.refresh_tokens.idle_ttl_secs - 1
        }),
        ("refresh_tokens.absolute_ttl_secs", |s| {
            s.refresh_tokens.absolute_ttl_secs = 91 * 86_400
        }),
        ("reuse_grace_secs", |s| {
            s.refresh_tokens.reuse_grace_secs = 61
        }),
        ("max_grants_per_principal", |s| {
            s.refresh_tokens.max_grants_per_principal = 0
        }),
        ("revalidate_interval_secs", |s| {
            s.refresh_tokens.revalidate_interval_secs = Some(59)
        }),
        ("idp_unavailable_grace_secs", |s| {
            s.refresh_tokens.idp_unavailable_grace_secs = 86_401
        }),
        ("idp_sessions.max_age_secs", |s| {
            s.idp_sessions.max_age_secs = Some(60)
        }),
    ];
    for (field, break_it) in cases {
        let mut config = base();
        break_it(interactive(&mut config));
        let err = refused(&config);
        assert!(err.contains(field), "{field}: {err}");
    }
    let mut config = base();
    let settings = interactive(&mut config);
    settings.refresh_tokens.idle_ttl_secs = 3_600;
    settings.refresh_tokens.absolute_ttl_secs = 3_600;
    settings.access_token_ttl_secs = 3_600;
    config.validate().expect("equal bounds are allowed");
    let settings = interactive(&mut config);
    settings.refresh_tokens.idle_ttl_secs = 3_600;
    settings.refresh_tokens.absolute_ttl_secs = 7_200;
    settings.access_token_ttl_secs = 3_600;
    config.validate().expect("access at most idle");
}

#[test]
fn consent_settings_are_bounded() {
    let mut config = base();
    interactive(&mut config).consent.remember_days = 366;
    assert!(refused(&config).contains("remember_days"));
    let mut config = base();
    interactive(&mut config).consent.service_name = Some(" ".to_owned());
    assert!(refused(&config).contains("service_name"));
    let mut config = base();
    interactive(&mut config)
        .consent
        .scope_descriptions
        .insert("mcp:tools".to_owned(), "x".repeat(201));
    assert!(refused(&config).contains("scope_descriptions[`mcp:tools`]"));
}

#[test]
fn the_store_kind_is_cluster_memory_or_file() {
    for kind in ["redis", "dev.mcpg.kv.redis", "nats"] {
        let yaml = format!("{BASE}      interactive:\n        store: {{ kind: {kind} }}\n");
        let err = serde_yaml::from_str::<AppConfig>(&yaml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown variant"), "{kind}: {err}");
    }
    let mut config = base();
    interactive(&mut config).store = Some(InteractiveStoreConfig {
        kind: InteractiveStoreKind::Memory,
        dir: Some("/tmp/x".to_owned()),
    });
    assert!(refused(&config).contains("applies only to kind `file`"));
    interactive(&mut config).store = Some(InteractiveStoreConfig {
        kind: InteractiveStoreKind::File,
        dir: Some(" ".to_owned()),
    });
    assert!(refused(&config).contains("store.dir must not be empty"));
    let yaml = format!("{BASE}      interactive:\n        store: {{ kind: file, path: /x }}\n");
    assert!(
        serde_yaml::from_str::<AppConfig>(&yaml).is_err(),
        "unknown store key"
    );
}

/// A clustered store needs a sealing key, whatever
/// `allow_plaintext_state` says; per-replica stores are refused there.
#[test]
fn a_clustered_store_needs_a_state_key_and_shared_state() {
    let clustered = |cluster: &str| {
        let mut config = base();
        config.cluster = serde_yaml::from_str(cluster).expect("cluster parses");
        config
    };
    const KEYED: &str =
        "kind: redis\nurl: rediss://r:6379\nstate_encryption_key_env: MCPG_STATE_KEY\n";
    const PLAINTEXT: &str = "kind: redis\nurl: rediss://r:6379\nallow_plaintext_state: true\n";

    let keyed = clustered(KEYED);
    keyed.validate().expect("the cluster key seals the store");
    let settings = keyed
        .governance
        .access
        .authorization_server
        .as_ref()
        .unwrap()
        .interactive_settings();
    assert_eq!(
        settings.resolved_store(&keyed.cluster),
        ResolvedInteractiveStore::Cluster
    );
    assert_eq!(
        settings.state_key_source(&keyed.cluster),
        Some(StateKeySource::ClusterKey {
            env: "MCPG_STATE_KEY".to_owned()
        })
    );

    let err = refused(&clustered(PLAINTEXT));
    assert!(
        err.contains("needs a key to seal sign-in state")
            && err.contains("allow_plaintext_state does not waive it"),
        "{err}"
    );
    let mut with_keyring = clustered(PLAINTEXT);
    interactive(&mut with_keyring)
        .state_keys
        .push(StateKeyConfig {
            kid: "k1".to_owned(),
            secret: "${secret.AS_STATE_KEY}".to_owned(),
        });
    with_keyring.validate().expect("state_keys seal the store");

    for kind in [InteractiveStoreKind::File, InteractiveStoreKind::Memory] {
        let mut per_replica = clustered(KEYED);
        interactive(&mut per_replica).store = Some(InteractiveStoreConfig { kind, dir: None });
        let err = refused(&per_replica);
        assert!(
            err.contains("keeps sign-in state on one replica"),
            "{kind:?}: {err}"
        );
    }

    // On a single node every store works; memory and the in-process
    // coordinator use a per-process key.
    for (kind, expected) in [
        (
            InteractiveStoreKind::Memory,
            ResolvedInteractiveStore::Memory,
        ),
        (
            InteractiveStoreKind::Cluster,
            ResolvedInteractiveStore::Cluster,
        ),
    ] {
        let mut single = base();
        interactive(&mut single).store = Some(InteractiveStoreConfig { kind, dir: None });
        single.validate().expect("single node");
        let settings = single
            .governance
            .access
            .authorization_server
            .as_ref()
            .unwrap()
            .interactive_settings();
        assert_eq!(settings.resolved_store(&single.cluster), expected);
        assert_eq!(
            settings.state_key_source(&single.cluster),
            Some(StateKeySource::Process)
        );
    }
}

/// The default file store is under `$MCPG_STATE_DIR`, else under the
/// container data directory where it exists (the one path the operator
/// and the Helm chart make writable), else under the home state directory.
#[test]
fn the_default_file_store_prefers_the_state_dir_then_the_container_data_dir() {
    let root = tempfile::tempdir().expect("tempdir");
    let state_dir = root.path().join("state");
    let data_dir = root.path().join("data");
    std::fs::create_dir(&data_dir).expect("data dir");

    assert_eq!(
        file_store_dir_under(Some(state_dir.clone()), &data_dir),
        state_dir.join("oauth")
    );
    assert_eq!(
        file_store_dir_under(None, &data_dir),
        data_dir.join("oauth")
    );
    let missing = root.path().join("missing");
    assert_eq!(
        file_store_dir_under(None, &missing),
        mcpg_cli_core::paths::default_state_dir().join("oauth")
    );

    let config = base();
    let settings = config
        .governance
        .access
        .authorization_server
        .as_ref()
        .unwrap()
        .interactive_settings();
    assert_eq!(
        settings.resolved_store_under(&config.cluster, || data_dir.join("oauth")),
        ResolvedInteractiveStore::File {
            dir: data_dir.join("oauth")
        }
    );
}

#[test]
fn state_keys_follow_their_syntax() {
    let key = |kid: &str, secret: &str| StateKeyConfig {
        kid: kid.to_owned(),
        secret: secret.to_owned(),
    };
    const GOOD: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    let with_keys = |keys: Vec<StateKeyConfig>| {
        let mut config = base();
        interactive(&mut config).state_keys = keys;
        config
    };
    with_keys(vec![
        key("as-2026.09_a", GOOD),
        key("old", &format!("{GOOD}=")),
    ])
    .validate()
    .expect("URL-safe base64 with or without padding");
    assert!(refused(&with_keys(vec![key("bad kid", GOOD)])).contains("state_keys[0].kid"));
    assert!(refused(&with_keys(vec![key(&"k".repeat(65), GOOD)])).contains("kid"));
    assert!(refused(&with_keys(vec![key("a", GOOD), key("a", GOOD)])).contains("more than once"));
    let err = refused(&with_keys(vec![key("a", "c2hvcnQ")]));
    assert!(
        err.contains("state_keys[0].secret must be 32 bytes") && !err.contains("c2hvcnQ"),
        "{err}"
    );
    assert!(refused(&with_keys(vec![key("a", "+/+/")])).contains("32 bytes"));
}

/// The key material is read from `secret`; any other field name is refused.
#[test]
fn a_state_key_holds_its_material_in_secret() {
    let parsed: Vec<StateKeyConfig> =
        serde_yaml::from_str("- kid: k1\n  secret: \"${secret.AS_STATE_KEY}\"\n")
            .expect("secret parses");
    assert_eq!(parsed[0].kid, "k1");
    assert_eq!(parsed[0].secret, "${secret.AS_STATE_KEY}");

    let err = serde_yaml::from_str::<Vec<StateKeyConfig>>(
        "- kid: k1\n  key: \"${secret.AS_STATE_KEY}\"\n",
    )
    .expect_err("an unknown field is refused")
    .to_string();
    assert!(err.contains("unknown field `key`"), "{err}");
    assert!(
        serde_yaml::from_str::<Vec<StateKeyConfig>>("- kid: k1\n").is_err(),
        "secret is required"
    );
}

/// Log, audit and admin redaction mask the key material by field name and
/// keep the kid.
#[test]
fn redaction_masks_state_key_material_by_field_name() {
    let keys = vec![StateKeyConfig {
        kid: "as-state-2026-09".to_owned(),
        secret: "STATE-KEY-SENTINEL".to_owned(),
    }];
    let value = serde_json::to_value(&keys).expect("serializes");
    assert_eq!(value[0]["secret"], "STATE-KEY-SENTINEL");

    let logged = crate::runtime::redact::redact_credentials(&value);
    assert_eq!(logged[0]["secret"], "[redacted]");
    assert_eq!(logged[0]["kid"], "as-state-2026-09");

    let admin = crate::admin::service::redact_sensitive(value);
    assert_eq!(admin[0]["secret"], "***");
    assert_eq!(admin[0]["kid"], "as-state-2026-09");
}

#[test]
fn dynamic_registration_needs_tokens_or_an_open_door() {
    let with_dcr = |edit: fn(&mut DynamicClientRegistrationConfig)| {
        let mut config = base();
        let dcr = &mut interactive(&mut config).dynamic_client_registration;
        dcr.enabled = true;
        edit(dcr);
        config
    };
    assert!(refused(&with_dcr(|_| {})).contains("needs initial_access_tokens, or allow_open"));
    with_dcr(|d| d.allow_open = true)
        .validate()
        .expect("open registration");
    with_dcr(|d| d.initial_access_tokens = vec!["${secret.DCR_TOKEN}".to_owned()])
        .validate()
        .expect("a placeholder token");
    let err = refused(&with_dcr(|d| {
        d.initial_access_tokens = vec!["short".to_owned()]
    }));
    assert!(
        err.contains("at least 32 bytes") && !err.contains("short`"),
        "{err}"
    );
    let err = refused(&with_dcr(|d| {
        d.allow_open = true;
        d.allowed_redirect_hosts = vec!["https://www.cursor.com".to_owned()];
    }));
    assert!(err.contains("bare host name"), "{err}");
    let err = refused(&with_dcr(|d| {
        d.allow_open = true;
        d.client_ttl_secs = 60;
    }));
    assert!(err.contains("client_ttl_secs"), "{err}");
    let err = refused(&with_dcr(|d| {
        d.allow_open = true;
        d.max_clients = 0;
    }));
    assert!(err.contains("max_clients"), "{err}");
}

#[test]
fn a_registered_client_id_may_not_take_the_registration_prefix() {
    let mut config = base();
    authz(&mut config).clients.push(public_client(
        &format!("{DCR_CLIENT_ID_PREFIX}operator"),
        &["http://127.0.0.1/cb"],
    ));
    let err = refused(&config);
    assert!(
        err.contains("starts with `mcpgdcr_`") && err.contains("dynamically registered"),
        "{err}"
    );
}

#[test]
fn dynamic_registration_alone_admits_clients() {
    let mut config = base();
    authz(&mut config).clients.clear();
    assert!(refused(&config).contains("must register at least one OAuth client"));
    let dcr = &mut interactive(&mut config).dynamic_client_registration;
    dcr.enabled = true;
    dcr.allow_open = true;
    config
        .validate()
        .expect("clients may come only by registration");
}

#[test]
fn a_registration_redirect_host_is_an_exact_host_or_a_subdomain() {
    let dcr = DynamicClientRegistrationConfig {
        allowed_redirect_hosts: vec!["Cursor.com".to_owned()],
        ..Default::default()
    };
    assert!(dcr.admits_redirect_host("cursor.com"));
    assert!(dcr.admits_redirect_host("www.cursor.com"));
    assert!(!dcr.admits_redirect_host("evilcursor.com"));
    assert!(!dcr.admits_redirect_host("cursor.com.evil.example"));
    assert!(!DynamicClientRegistrationConfig::default().admits_redirect_host("cursor.com"));
}

#[test]
fn config_check_describes_dynamic_registration() {
    let mut config = base();
    assert!(
        !interactive_login_summary(&config)
            .join("\n")
            .contains("dynamic client registration"),
        "off by default"
    );
    let dcr = &mut interactive(&mut config).dynamic_client_registration;
    dcr.enabled = true;
    dcr.initial_access_tokens = vec!["${secret.DCR_TOKEN}".to_owned()];
    let text = interactive_login_summary(&config).join("\n");
    assert!(
        text.contains(
            "dynamic client registration at https://mcp.example.com/oauth/register: with one of \
             1 initial access tokens; loopback redirect URIs only"
        ),
        "{text}"
    );
    assert!(!text.contains("DCR_TOKEN"), "{text}");
    interactive(&mut config)
        .dynamic_client_registration
        .allow_open = true;
    let text = interactive_login_summary(&config).join("\n");
    assert!(
        text.contains("open to anyone, or with one of 1 initial access tokens"),
        "{text}"
    );
    let dcr = &mut interactive(&mut config).dynamic_client_registration;
    dcr.initial_access_tokens.clear();
    dcr.allowed_redirect_hosts = vec!["www.cursor.com".to_owned()];
    let text = interactive_login_summary(&config).join("\n");
    assert!(
        text.contains("open to anyone; loopback redirect URIs, and https:// on www.cursor.com"),
        "{text}"
    );
}

// ── subject tokens, reserved attributes, scope descriptions ──────────

const IDP_FEDERATION: &str = r#"
mcp:
  federations:
    - name: vendor
      upstream:
        url: https://mcp.vendor.example/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/vendor
          subject_token: idp_refresh_token
"#;

#[test]
fn the_stored_sign_in_is_a_subject_token_for_impersonation_only() {
    let with_federation = |yaml: &str, keep_login: bool| {
        let mut config = parse(&format!("{BASE}{yaml}"));
        if !keep_login {
            authz(&mut config).trusted_idps[0].login = None;
        }
        config
    };
    let config = with_federation(IDP_FEDERATION, true);
    config
        .validate()
        .expect("an idp_refresh_token federation with a login IdP");
    assert_eq!(
        config.mcp.federations[0].upstream.auth.subject_token,
        crate::config::SubjectToken::IdpRefreshToken
    );

    let err = refused(&with_federation(IDP_FEDERATION, false));
    assert!(
        err.contains("mcp.federations[vendor].upstream.auth.subject_token `idp_refresh_token`")
            && err.contains("login block"),
        "{err}"
    );
    let err = refused(&with_federation(
        &IDP_FEDERATION.replace(
            "mode: oauth_impersonation\n          credential: cred://dev.mcpg.credential.oauth-id-jag/vendor\n",
            "mode: pass_through\n",
        ),
        true,
    ));
    assert!(
        err.contains("applies only to mode `oauth_impersonation`"),
        "{err}"
    );
    let err = refused(&with_federation(
        &IDP_FEDERATION.replace(
            "          subject_token: idp_refresh_token\n",
            "          import:\n            mode: service_token\n            token: t\n            \
             subject_token: idp_id_token\n",
        ),
        true,
    ));
    assert!(err.contains("import: `subject_token` is refused"), "{err}");

    let registry = "
mcp:
  registries:
    - name: corp
      url: https://registry.example.com
      defaults:
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/corp
          subject_token: idp_id_token
";
    let err = refused(&with_federation(registry, false));
    assert!(
        err.contains("mcp.registries[corp].defaults.auth.subject_token"),
        "{err}"
    );
    with_federation(registry, true)
        .validate()
        .expect("registry defaults with a login IdP");

    let per_server = "
mcp:
  registries:
    - name: corp
      url: https://registry.example.com
      servers:
        com.acme/crm:
          auth:
            mode: oauth_impersonation
            credential: cred://dev.mcpg.credential.oauth-id-jag/{server}
            subject_token: idp_refresh_token
";
    let err = refused(&with_federation(per_server, false));
    assert!(
        err.contains("mcp.registries[corp].servers[com.acme/crm].auth.subject_token"),
        "{err}"
    );
    with_federation(per_server, true)
        .validate()
        .expect("a per-server override with a login IdP");
    let err = refused(&with_federation(
        &per_server.replace(
            "mode: oauth_impersonation\n            credential: cred://dev.mcpg.credential.oauth-id-jag/{server}\n",
            "mode: pass_through\n",
        ),
        true,
    ));
    assert!(
        err.contains("applies only to mode `oauth_impersonation`"),
        "{err}"
    );

    // The default stays the caller's bearer and is not serialized.
    let plain: crate::config::federation::AuthConfig = Default::default();
    assert!(plain.subject_token.is_caller_bearer());
    assert!(
        !serde_json::to_string(&plain)
            .unwrap()
            .contains("subject_token")
    );
}

#[test]
fn reserved_attribute_names_cannot_be_mapping_targets() {
    let mut off = base();
    assert!(
        !authz(&mut off).dpop.enabled && !authz(&mut off).authorization_details.enabled(),
        "the names are reserved while DPoP and authorization details are off too"
    );
    for attribute in [
        "grant_type",
        "grant_id",
        "auth_time",
        "dpop_jkt",
        "authorization_details",
        "authorization_details_types",
        "subject_token_binding",
        "subject_token_issuer",
    ] {
        let mut config = base();
        authz(&mut config).trusted_idps[0]
            .claim_mappings
            .attribute_claim_mappings
            .insert("some_claim".to_owned(), attribute.to_owned());
        let err = refused(&config);
        assert!(err.contains("sets itself"), "{attribute}: {err}");
    }

    let with_oidc_mapping = |attribute: &str| {
        let mut config = base();
        config.governance.access.oidc_oauth = Some(
            serde_json::from_value(serde_json::json!({
                "providers": [{
                    "issuer": "https://acme.okta.com/oauth2/default",
                    "audiences": ["https://mcp.example.com/mcp"],
                    "verification": { "kind": "oidc_jwks" },
                    "claim_mappings": { "attribute_claim_mappings": { "claim": attribute } },
                }]
            }))
            .expect("OIDC config parses"),
        );
        config
    };
    for attribute in [
        "token_issuer",
        "grant_type",
        "grant_id",
        "dpop_jkt",
        "authorization_details",
        "authorization_details_types",
        "subject_token",
        "subject_token_source",
    ] {
        let err = refused(&with_oidc_mapping(attribute));
        assert!(
            err.contains(
                "governance.access.oidc_oauth.providers[`https://acme.okta.com/oauth2/default`]"
            ) && err.contains("sets itself"),
            "{attribute}: {err}"
        );
    }
    for attribute in ["email", "tenant", "auth_time", "department"] {
        with_oidc_mapping(attribute)
            .validate()
            .expect("an identity value an SSO token carries stays mappable");
    }
}

#[test]
fn scope_descriptions_name_scopes_this_server_grants() {
    let mut config = base();
    interactive(&mut config)
        .consent
        .scope_descriptions
        .insert("mcp:admin".to_owned(), "Administer".to_owned());
    let err = refused(&config);
    assert!(err.contains("describes `mcp:admin`"), "{err}");
    interactive(&mut config).consent.scope_descriptions.clear();
    interactive(&mut config)
        .consent
        .scope_descriptions
        .insert("mcp:resources".to_owned(), "Read resources".to_owned());
    config.validate().expect("a resource_metadata scope");
    authz(&mut config).allowed_scopes = Some(vec!["mcp:tools".to_owned()]);
    assert!(
        refused(&config).contains("describes `mcp:resources`"),
        "allowed_scopes wins"
    );
}

// ── warnings and the config check summary ──────────────────────────

fn warnings(config: &AppConfig) -> Vec<String> {
    access_posture_warnings(config)
}

#[test]
fn the_base_config_draws_no_warning() {
    assert_eq!(warnings(&base()), Vec::<String>::new());
}

#[test]
fn the_issuer_is_listed_first() {
    let mut config = base();
    config
        .governance
        .access
        .resource_metadata
        .as_mut()
        .unwrap()
        .authorization_servers = vec![
        "https://acme.okta.com".to_owned(),
        "https://mcp.example.com".to_owned(),
    ];
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("but not first"), "{}", found[0]);
}

#[test]
fn a_custom_okta_authorization_server_cannot_serve_idp_federations() {
    let mut config = parse(&format!("{BASE}{IDP_FEDERATION}"));
    authz(&mut config).trusted_idps[0].issuer = "https://acme.okta.com/oauth2/default".to_owned();
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("custom authorization server")
            && found[0].contains("mcp.federations[vendor]"),
        "{}",
        found[0]
    );
    let mut without_federation = base();
    authz(&mut without_federation).trusted_idps[0].issuer =
        "https://acme.okta.com/oauth2/default".to_owned();
    assert!(warnings(&without_federation).is_empty());
}

#[test]
fn the_issuer_plugin_must_use_the_login_client_and_token_endpoint() {
    let plugins = |client_id: &str, token_url: &str| {
        format!(
            "plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    class: credential_issuer
    source: {{ path: /tmp/oauth-id-jag.so }}
    config:
      providers:
        vendor:
          idp_token_url: {token_url}
          client_id: {client_id}
"
        )
    };
    let with_plugins = |client_id: &str, token_url: &str| {
        let mut config = parse(&format!(
            "{BASE}{IDP_FEDERATION}{}",
            plugins(client_id, token_url)
        ));
        login(&mut config).token_endpoint =
            Some("https://acme.okta.com/oauth2/v1/token".to_owned());
        config
    };
    assert!(
        warnings(&with_plugins(
            "0oa1agent",
            "https://acme.okta.com/oauth2/v1/token"
        ))
        .is_empty()
    );
    let found = warnings(&with_plugins(
        "other-client",
        "https://acme.okta.com/oauth2/v2/token",
    ));
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].contains("client_id `other-client`"),
        "{}",
        found[0]
    );
    assert!(
        found[1].contains("idp_token_url `https://acme.okta.com/oauth2/v2/token`"),
        "{}",
        found[1]
    );
    // An unresolved value is not judged.
    assert!(
        warnings(&with_plugins(
            "${secret.CLIENT}",
            "https://acme.okta.com/oauth2/v1/token"
        ))
        .is_empty()
    );
}

/// Only the two first-party exchange issuers confine the stored sign-in to
/// the token endpoint that issued it, so validation refuses any other
/// issuer: by its plugin id, or by the manifest a `plugins[]` entry runs.
#[test]
fn only_an_issuer_that_confines_the_stored_sign_in_may_present_it() {
    let plugin = |id: &str, manifest: &str| {
        format!(
            "plugins:
  - id: {id}
    ref: {manifest}
    class: credential_issuer
    source: {{ path: /tmp/issuer.so }}
"
        )
    };
    let with_credential = |credential: &str, plugins: &str| {
        parse(&format!(
            "{BASE}{}{plugins}",
            IDP_FEDERATION.replace("cred://dev.mcpg.credential.oauth-id-jag/vendor", credential)
        ))
    };

    let err = refused(&with_credential(
        "cred://corp-sts/vendor",
        &plugin("corp-sts", "com.example.credential.sts"),
    ));
    assert!(
        err.contains("mcp.federations[vendor].upstream.auth.subject_token `idp_refresh_token`")
            && err.contains("`corp-sts` (`com.example.credential.sts`)")
            && err.contains(
                "dev.mcpg.credential.oauth-id-jag or dev.mcpg.credential.oauth-token-exchange"
            ),
        "{err}"
    );
    let err = refused(&with_credential(
        "cred://dev.mcpg.credential.jwt-mint/vendor",
        "",
    ));
    assert!(
        err.contains("names `dev.mcpg.credential.jwt-mint`"),
        "{err}"
    );
    let err = refused(&with_credential(
        "cred://dev.mcpg.credential.oauth-id-jag/vendor",
        &plugin(
            "dev.mcpg.credential.oauth-id-jag",
            "com.example.credential.sts",
        ),
    ));
    assert!(
        err.contains("(`com.example.credential.sts`)"),
        "an entry that runs another manifest under a confining id: {err}"
    );

    with_credential("cred://dev.mcpg.credential.oauth-token-exchange/vendor", "")
        .validate()
        .expect("oauth-token-exchange confines it");
    with_credential(
        "cred://corp-xaa/vendor",
        &plugin("corp-xaa", "dev.mcpg.credential.oauth-id-jag"),
    )
    .validate()
    .expect("an alias of oauth-id-jag confines it");

    let registry = |credential: &str| {
        parse(&format!(
            "{BASE}
mcp:
  registries:
    - name: corp
      url: https://registry.example.com
      servers:
        com.acme/crm:
          auth:
            mode: oauth_impersonation
            credential: {credential}
            subject_token: idp_id_token
"
        ))
    };
    let err = refused(&registry("cred://com.example.sts/{server}"));
    assert!(
        err.contains("mcp.registries[corp].servers[com.acme/crm].auth.subject_token"),
        "{err}"
    );
    registry("cred://dev.mcpg.credential.oauth-id-jag/{server}")
        .validate()
        .expect("a per-server override through oauth-id-jag");
}

#[test]
fn a_login_without_offline_access_warns() {
    let mut config = base();
    login(&mut config).scopes = vec!["openid".to_owned(), "email".to_owned()];
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("lacks `offline_access`"), "{}", found[0]);
}

#[test]
fn a_canonical_url_on_another_origin_warns() {
    let mut config = base();
    config.gateway.server.canonical_url = Some("https://gw.example.com".to_owned());
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("canonical_url"), "{}", found[0]);
    config.gateway.server.canonical_url = Some("https://mcp.example.com/".to_owned());
    assert!(warnings(&config).is_empty());
}

#[test]
fn anonymous_access_warns_as_for_ema() {
    let mut config = base();
    config.governance.access.require_authentication = false;
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("require_authentication"), "{}", found[0]);
}

#[test]
fn a_memory_store_on_a_single_node_warns() {
    for kind in [InteractiveStoreKind::Memory, InteractiveStoreKind::Cluster] {
        let mut config = base();
        interactive(&mut config).store = Some(InteractiveStoreConfig { kind, dir: None });
        let found = warnings(&config);
        assert_eq!(found.len(), 1, "{kind:?}: {found:?}");
        assert!(found[0].contains("process memory"), "{}", found[0]);
    }
    let mut file = base();
    interactive(&mut file).store = Some(InteractiveStoreConfig {
        kind: InteractiveStoreKind::File,
        dir: None,
    });
    assert!(warnings(&file).is_empty());
}

#[test]
fn a_localhost_redirect_uri_warns() {
    let mut config = base();
    authz(&mut config).clients.push(public_client(
        "acme-cli",
        &["http://localhost/cb", "http://127.0.0.1/cb"],
    ));
    let found = warnings(&config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("`http://localhost/cb` names `localhost`"),
        "{}",
        found[0]
    );
}

#[test]
fn config_check_names_the_callback_scopes_store_and_key() {
    let lines = interactive_login_summary(&base());
    let text = lines.join("\n");
    for expected in [
        "interactive sign-in through https://acme.okta.com (client `0oa1agent`)",
        "`sso.interactive_login`",
        "register this sign-in redirect URI at the IdP: https://mcp.example.com/oauth/callback",
        "discovered at boot from https://acme.okta.com/.well-known/openid-configuration",
        "IdP scopes: openid profile email offline_access",
        "sign-in state: files under",
        "state key: generated on first start at",
    ] {
        assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
    }
    let mut ema = base();
    authz(&mut ema).trusted_idps[0].login = None;
    assert!(interactive_login_summary(&ema).is_empty());
    assert!(interactive_login_summary(&AppConfig::default()).is_empty());
}
