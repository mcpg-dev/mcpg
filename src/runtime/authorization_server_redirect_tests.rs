//! Redirect URI matching, trust and response building; PKCE.

use super::*;
use crate::runtime::authorization_server::state::random_token;

const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_CODE_LOCALHOST: &str = "http://localhost/callback";
const CLAUDE_CODE_LOOPBACK: &str = "http://127.0.0.1/callback";
const VSCODE_LOOPBACK: &str = "http://127.0.0.1:33418/";
const VSCODE_WEB: &str = "https://vscode.dev/redirect";

fn registered(uri: &str) -> RegisteredRedirect {
    RegisteredRedirect::parse(uri).expect("registered URI has the syntax")
}

fn documents(policy: RedirectUriPolicy, allowed_hosts: &[&str]) -> ClientIdMetadataDocumentsConfig {
    ClientIdMetadataDocumentsConfig {
        enabled: None,
        allowed_hosts: allowed_hosts.iter().map(|h| (*h).to_owned()).collect(),
        allow_private_network: false,
        redirect_uri_policy: policy,
    }
}

/// `registered_uri` matches every URI of `matching` and none of `others`.
fn assert_matches_only(registered_uri: &str, matching: &[&str], others: &[&str]) {
    let reg = registered(registered_uri);
    for requested in matching {
        assert!(
            redirect_uri_matches(&reg, requested),
            "{registered_uri} must match {requested}"
        );
    }
    for requested in others {
        assert!(
            !redirect_uri_matches(&reg, requested),
            "{registered_uri} must not match {requested}"
        );
    }
}

// ── matching ─────────────────────────────────────────────────────────

#[test]
fn a_hosted_callback_matches_byte_for_byte() {
    assert_matches_only(
        CLAUDE_CALLBACK,
        &[CLAUDE_CALLBACK],
        &[
            "https://claude.ai/api/mcp/auth_callback/",
            "https://Claude.ai/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/Auth_callback",
            "https://claude.ai:443/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth%5Fcallback",
            "https://claude.ai/api/mcp/auth_callback#x",
            "https://claude.ai/api/mcp/auth_callback?x=1",
            "https://user@claude.ai/api/mcp/auth_callback",
            "https://claude.ai.evil.com/api/mcp/auth_callback",
            "https://claude.ai\\@evil.com/api/mcp/auth_callback",
            "http://claude.ai/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/./auth_callback",
        ],
    );
    assert_matches_only(
        VSCODE_WEB,
        &[VSCODE_WEB],
        &[
            "https://vscode.dev/redirect/",
            "https://vscode.dev:443/redirect",
            "vscode://vscode.github-authentication/did-authenticate",
        ],
    );
    // An https URI on a loopback host is matched exactly too.
    assert_matches_only(
        "https://localhost/cb",
        &["https://localhost/cb"],
        &["https://localhost:8443/cb", "http://localhost:8443/cb"],
    );
}

#[test]
fn a_portless_loopback_uri_matches_any_port() {
    assert_matches_only(
        CLAUDE_CODE_LOCALHOST,
        &[
            "http://localhost:3118/callback",
            "http://localhost:54012/callback",
            "http://localhost/callback",
        ],
        &[
            "http://localhost:3118/callback/",
            "http://localhost:3118/Callback",
            "http://localhost:3118/callback?x=1",
            "http://localhost:3118/callback?",
            "http://LOCALHOST:3118/callback",
            "http://localhost.evil:3118/callback",
            "https://localhost:3118/callback",
            // 127.0.0.1 and localhost are never one another.
            "http://127.0.0.1:3118/callback",
        ],
    );
    assert_matches_only(
        CLAUDE_CODE_LOOPBACK,
        &["http://127.0.0.1:3118/callback"],
        &[
            "http://localhost:3118/callback",
            "http://[::1]:3118/callback",
            "http://127.0.0.1.evil.com:3118/callback",
            "http://127.1:3118/callback",
            "http://0x7f000001:3118/callback",
            "http://127.0.0.1:3118/x/../callback",
            "http://127.0.0.1:3118/%63allback",
            "http://127.0.0.1:3118\\callback",
        ],
    );
}

#[test]
fn a_loopback_port_and_an_empty_path_are_free() {
    assert_matches_only(
        VSCODE_LOOPBACK,
        &[
            "http://127.0.0.1:33418/",
            "http://127.0.0.1:50123",
            "http://127.0.0.1:50123/",
        ],
        &[
            "http://127.0.0.1:50123/callback",
            "http://127.0.0.1:50123/?code=x",
            "http://localhost:33418/",
        ],
    );
    // A registered query is part of the URI.
    assert_matches_only(
        "http://[::1]/cb?x=1",
        &["http://[::1]:8080/cb?x=1"],
        &["http://[::1]:8080/cb?x=2", "http://[::1]:8080/cb"],
    );
}

/// `uri` with the port after a loopback host removed and an empty path
/// written `/`: loopback URIs that differ only there are one place a
/// native client may listen.
fn loopback_normal_form(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("http://")?;
    let host = ["127.0.0.1", "[::1]", "localhost"]
        .into_iter()
        .find(|host| rest.starts_with(host))?;
    let mut after = &rest[host.len()..];
    if let Some(port) = after.strip_prefix(':') {
        after = port.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    if after.is_empty() || after.starts_with('?') {
        Some(format!("http://{host}/{after}"))
    } else if after.starts_with('/') {
        Some(format!("http://{host}{after}"))
    } else {
        None
    }
}

/// Every insertion, deletion and substitution of one character in a
/// registered URI: none matches, except a changed loopback port (or a
/// loopback path `/` written empty).
#[test]
fn no_single_character_mutation_matches_except_a_loopback_port() {
    let mut alphabet: Vec<char> = (' '..='~').collect();
    alphabet.extend([
        '\t', '\n', '\0', 'é', '\u{202E}', '\u{3002}', '\u{FF0F}', 'Ａ', '\u{200B}',
    ]);
    let mut loopback_ports_matched = 0;
    for uri in [
        CLAUDE_CALLBACK,
        CLAUDE_CODE_LOCALHOST,
        CLAUDE_CODE_LOOPBACK,
        VSCODE_LOOPBACK,
        VSCODE_WEB,
        "http://[::1]:8080/cb?x=1",
        "https://app.example:8443/cb?a=b",
    ] {
        let reg = registered(uri);
        let chars: Vec<char> = uri.chars().collect();
        let mut mutations = Vec::new();
        for at in 0..=chars.len() {
            for &c in &alphabet {
                let mut inserted = chars.clone();
                inserted.insert(at, c);
                mutations.push(inserted);
                if at < chars.len() && chars[at] != c {
                    let mut substituted = chars.clone();
                    substituted[at] = c;
                    mutations.push(substituted);
                }
            }
            if at < chars.len() {
                let mut deleted = chars.clone();
                deleted.remove(at);
                mutations.push(deleted);
            }
        }
        for mutation in mutations {
            let requested: String = mutation.into_iter().collect();
            if !redirect_uri_matches(&reg, &requested) {
                continue;
            }
            let port_change = loopback_normal_form(uri).is_some()
                && loopback_normal_form(uri) == loopback_normal_form(&requested);
            assert!(port_change, "{uri} matched its mutation {requested:?}");
            loopback_ports_matched += 1;
        }
    }
    assert!(
        loopback_ports_matched > 0,
        "a changed loopback port must still match"
    );
}

#[test]
fn the_requested_uri_needs_the_registration_syntax() {
    // A request cannot reach a registered loopback URI through a spelling
    // the browser rewrites.
    let long = format!("http://127.0.0.1/{}", "a".repeat(MAX_REDIRECT_URI_BYTES));
    assert_matches_only(
        CLAUDE_CODE_LOOPBACK,
        &[],
        &[
            "http://127.0.0.1:3118/./callback",
            "http://127.0.0.1:3118/%2e/callback",
            "http://127.0.0.1:3118/callback#",
            "http://127.0.0.1:3118/call back",
            "HTTP://127.0.0.1:3118/callback",
            "http://127.0.0.1:99999/callback",
            &long,
        ],
    );
}

// ── resolution ───────────────────────────────────────────────────────

fn static_registration(uris: &[&str]) -> RedirectRegistration {
    RedirectRegistration::from_uris(&uris.iter().map(|u| (*u).to_owned()).collect::<Vec<_>>())
        .expect("static URIs have the syntax")
}

#[test]
fn a_request_may_omit_the_redirect_uri_only_with_one_https_uri() {
    let one = static_registration(&["https://app.example/cb"]);
    for requested in [None, Some("")] {
        let resolved = one
            .resolve(ClientKind::Static, requested)
            .expect("the one https URI is used");
        assert_eq!(resolved.uri, "https://app.example/cb");
        assert!(resolved.trusted);
    }
    let loopback = static_registration(&[CLAUDE_CODE_LOOPBACK]);
    assert_eq!(
        loopback.resolve(ClientKind::Static, None),
        Err(RedirectError::Required),
        "only the request knows the port"
    );
    let two = static_registration(&["https://app.example/cb", "https://app.example/cb2"]);
    assert_eq!(
        two.resolve(ClientKind::Static, None),
        Err(RedirectError::Required)
    );
}

#[test]
fn the_requested_string_is_kept_byte_for_byte() {
    let registration = static_registration(&[VSCODE_LOOPBACK]);
    let resolved = registration
        .resolve(ClientKind::Cimd, Some("http://127.0.0.1:50123"))
        .expect("another port matches");
    assert_eq!(resolved.uri, "http://127.0.0.1:50123");
    assert_eq!(resolved.kind, RedirectUriKind::Loopback(LoopbackHost::Ipv4));
    assert!(resolved.trusted, "a loopback URI stays on the computer");

    assert_eq!(
        registration.resolve(ClientKind::Static, Some("https://evil.example/cb")),
        Err(RedirectError::NotRegistered)
    );
    assert!(matches!(
        registration.resolve(ClientKind::Static, Some("cursor://anysphere/cb")),
        Err(RedirectError::Invalid(problem)) if problem.contains("private-use")
    ));
}

#[test]
fn a_registered_uri_without_the_syntax_is_refused() {
    let err = RedirectRegistration::from_uris(&["cursor://anysphere/cb".to_owned()])
        .expect_err("a private-use scheme is refused");
    assert!(err.contains("cursor://anysphere/cb"), "{err}");
}

#[test]
fn documents_keep_https_redirect_uris_on_their_own_host() {
    let client_id = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    let same_host = documents(RedirectUriPolicy::SameHost, &["claude.ai"]);
    let entries = [
        CLAUDE_CALLBACK,
        "https://claude.com/api/mcp/auth_callback",
        "https://www.claude.ai/cb",
        "http://127.0.0.1/callback",
        "cursor://anysphere/cb",
    ];
    let registration = RedirectRegistration::from_document(&entries, client_id, &same_host);
    assert_eq!(
        registration
            .usable()
            .iter()
            .map(|r| r.uri.as_str())
            .collect::<Vec<_>>(),
        [CLAUDE_CALLBACK, "http://127.0.0.1/callback"],
        "loopback is always admitted"
    );
    assert_eq!(registration.refused().len(), 3);
    assert!(!registration.all_https());

    let refused = registration
        .resolve(
            ClientKind::Cimd,
            Some("https://claude.com/api/mcp/auth_callback"),
        )
        .expect_err("another host is refused under same_host");
    assert!(
        matches!(refused, RedirectError::Refused(ref reason) if reason.contains("same_host")),
        "{refused:?}"
    );
    assert!(
        refused.description().contains("claude.com"),
        "{}",
        refused.description()
    );
    let resolved = registration
        .resolve(ClientKind::Cimd, Some(CLAUDE_CALLBACK))
        .expect("the document's own host is admitted");
    assert!(!resolved.trusted, "a document's https URI is self-asserted");
    assert_eq!(
        registration.resolve(ClientKind::Cimd, None),
        Err(RedirectError::Required),
        "every listed URI counts, refused ones included"
    );

    // Under allowed_hosts, an admitted host (or a subdomain of it) passes.
    let hosts = ["claude.ai", "claude.com"];
    let allowed = documents(RedirectUriPolicy::AllowedHosts, &hosts);
    let registration = RedirectRegistration::from_document(&entries, client_id, &allowed);
    assert_eq!(registration.usable().len(), 4);
    let (uri, reason) = &registration.refused()[0];
    assert_eq!(uri, "cursor://anysphere/cb");
    assert!(reason.contains("private-use"), "{reason}");
    let narrow = documents(RedirectUriPolicy::AllowedHosts, &["claude.ai"]);
    let registration = RedirectRegistration::from_document(&entries, client_id, &narrow);
    assert!(
        registration
            .refused()
            .iter()
            .any(|(uri, reason)| uri.contains("claude.com") && reason.contains("allowed_hosts")),
        "{:?}",
        registration.refused()
    );
}

#[test]
fn trusted_redirects_are_vetted_or_local() {
    let loopback = RedirectUriKind::Loopback(LoopbackHost::Ipv4);
    let https = RedirectUriKind::Https;
    assert!(redirect_is_trusted(ClientKind::Static, https));
    assert!(redirect_is_trusted(ClientKind::Static, loopback));
    assert!(!redirect_is_trusted(ClientKind::Cimd, https));
    assert!(redirect_is_trusted(ClientKind::Cimd, loopback));
    assert!(!redirect_is_trusted(ClientKind::Dcr, https));
    assert!(redirect_is_trusted(ClientKind::Dcr, loopback));
}

#[test]
fn response_parameters_keep_the_registered_query() {
    let params = [
        ("code", "mcpg_ac_x"),
        ("state", "a b&c"),
        ("iss", "https://gw.test"),
    ];
    let code = &params[..1];
    assert_eq!(
        with_response_params("https://app.example/cb", &params),
        "https://app.example/cb?code=mcpg_ac_x&state=a+b%26c&iss=https%3A%2F%2Fgw.test"
    );
    assert_eq!(
        with_response_params("https://app.example/cb?tenant=a", code),
        "https://app.example/cb?tenant=a&code=mcpg_ac_x"
    );
    assert_eq!(
        with_response_params("https://app.example/cb?", code),
        "https://app.example/cb?code=mcpg_ac_x"
    );
    assert_eq!(
        with_response_params("https://app.example/cb?a=1&", code),
        "https://app.example/cb?a=1&code=mcpg_ac_x"
    );
    assert_eq!(
        with_response_params("http://127.0.0.1:50123", code),
        "http://127.0.0.1:50123?code=mcpg_ac_x"
    );
    assert_eq!(
        with_response_params("https://app.example/cb", &[]),
        "https://app.example/cb"
    );
}

#[test]
fn consent_follows_the_client_and_its_redirect_uri() {
    use ClientConsent::{Always, Auto, Skip};
    use ClientKind::{Cimd, Dcr, Static};

    let https_only = static_registration(&["https://app.example/cb"]);
    let mixed = static_registration(&["https://app.example/cb", CLAUDE_CODE_LOOPBACK]);
    let loopback = RedirectUriKind::Loopback(LoopbackHost::Ipv4);
    let https = RedirectUriKind::Https;
    let ask = |rememberable| ConsentRule::Ask { rememberable };
    let rule = consent_rule;

    // A registered client: `auto` skips only with every URI https, and
    // only `skip` is an explicit choice of the operator.
    assert_eq!(
        rule(Static, Auto, &https_only, https),
        ConsentRule::Skip { explicit: false }
    );
    assert_eq!(rule(Static, Auto, &mixed, https), ask(true));
    assert_eq!(rule(Static, Auto, &mixed, loopback), ask(false));
    assert_eq!(rule(Static, Always, &https_only, https), ask(false));
    assert_eq!(
        rule(Static, Skip, &https_only, https),
        ConsentRule::Skip { explicit: true }
    );
    // A document always asks, remembered only for https.
    assert_eq!(rule(Cimd, Always, &https_only, https), ask(true));
    assert_eq!(rule(Cimd, Skip, &mixed, loopback), ask(false));
    // A registration always asks and is never remembered.
    assert_eq!(rule(Dcr, Skip, &https_only, https), ask(false));
}

#[test]
fn self_asserted_client_names_are_cleaned_for_display() {
    let shown = client_display_name;
    assert_eq!(shown("Claude").as_deref(), Some("Claude"));
    assert_eq!(
        shown("  Visual \n  Studio\tCode ").as_deref(),
        Some("Visual Studio Code")
    );
    assert_eq!(
        shown("Invoice\u{202E}fdp.exe").as_deref(),
        Some("Invoicefdp.exe")
    );
    assert_eq!(shown("a\u{0}b\u{200B}c").as_deref(), Some("abc"));
    assert_eq!(shown("\u{200B}\u{2066} \u{FEFF}"), None);
    assert_eq!(shown(""), None);
    assert_eq!(
        shown(&"x".repeat(200)).map(|n| n.chars().count()),
        Some(MAX_CLIENT_NAME_CHARS)
    );
}

#[test]
fn client_errors_are_pages_with_an_oauth_code() {
    let reason = || "x".to_owned();
    let cases = [
        (AuthorizeClientError::MissingClientId, "invalid_request"),
        (AuthorizeClientError::UnknownClient, "invalid_client"),
        (
            AuthorizeClientError::Unauthorized(reason()),
            "unauthorized_client",
        ),
        (
            AuthorizeClientError::InvalidDocument(reason()),
            "invalid_client",
        ),
        (
            AuthorizeClientError::DocumentUnavailable,
            "temporarily_unavailable",
        ),
        (
            AuthorizeClientError::Redirect(RedirectError::NotRegistered),
            "invalid_request",
        ),
    ];
    for (error, code) in cases {
        let status = if code == "temporarily_unavailable" {
            503
        } else {
            400
        };
        assert_eq!(error.status(), status, "{error:?}");
        assert_eq!(error.error(), code, "{error:?}");
        assert!(!error.to_string().is_empty());
    }
}

// ── PKCE ─────────────────────────────────────────────────────────────

/// RFC 7636 Appendix B.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn s256_matches_the_rfc_7636_vector() {
    assert_eq!(s256_challenge(RFC_VERIFIER), RFC_CHALLENGE);
    assert!(code_verifier_is_valid(RFC_VERIFIER));
    assert!(code_challenge_is_valid(RFC_CHALLENGE));
    let checked = check_code_verifier(Some(RFC_VERIFIER), RFC_CHALLENGE);
    assert_eq!(checked, Ok(()));
}

#[test]
fn verifier_length_and_characters_are_bounded() {
    for (length, valid) in [(42, false), (43, true), (128, true), (129, false)] {
        let verifier = "a".repeat(length);
        assert_eq!(code_verifier_is_valid(&verifier), valid, "length {length}");
    }
    let base = "a".repeat(42);
    for c in ['-', '.', '_', '~', 'Z', '9'] {
        assert!(code_verifier_is_valid(&format!("{base}{c}")), "{c:?}");
    }
    for c in ['+', '/', '=', ' ', '%', 'é'] {
        assert!(!code_verifier_is_valid(&format!("{base}{c}")), "{c:?}");
    }
    let verifier = random_token().expect("OS randomness");
    assert!(
        code_verifier_is_valid(&verifier),
        "a random token is a verifier"
    );
    assert!(code_challenge_is_valid(&s256_challenge(&verifier)));
}

#[test]
fn challenges_are_43_base64url_characters() {
    let padded = format!("{}=", &RFC_CHALLENGE[..42]);
    for challenge in [
        RFC_CHALLENGE[..42].to_owned(),
        format!("{RFC_CHALLENGE}A"),
        padded,
        RFC_CHALLENGE.replace('-', "+"),
        RFC_CHALLENGE.replace('-', "."),
    ] {
        assert!(!code_challenge_is_valid(&challenge), "{challenge}");
    }
}

#[test]
fn authorization_pkce_is_checked_in_order() {
    let check = check_authorization_pkce;
    let good = Some(RFC_CHALLENGE);
    let s256 = Some("S256");
    assert_eq!(check(good, s256), Ok(RFC_CHALLENGE));
    assert_eq!(check(Some(RFC_VERIFIER), s256), Ok(RFC_VERIFIER));
    // A challenge is required first.
    for (challenge, method) in [(None, s256), (Some(""), s256), (None, None)] {
        assert_eq!(check(challenge, method), Err(PkceError::ChallengeMissing));
    }
    // Then S256; absent means plain.
    for method in [None, Some("plain"), Some("s256"), Some("")] {
        assert_eq!(check(good, method), Err(PkceError::MethodUnsupported));
    }
    let short = Some("short");
    assert_eq!(check(short, None), Err(PkceError::MethodUnsupported));
    // Then its form.
    assert_eq!(check(short, s256), Err(PkceError::ChallengeMalformed));

    assert_eq!(
        PkceError::ChallengeMissing.description(),
        "code_challenge required"
    );
    assert!(
        PkceError::MethodUnsupported
            .description()
            .starts_with("transform algorithm not supported")
    );
}

#[test]
fn a_code_verifier_must_hash_to_the_challenge() {
    let check = |verifier| check_code_verifier(verifier, RFC_CHALLENGE);
    assert_eq!(check(None), Err(PkceError::VerifierMissing));
    assert_eq!(check(Some("")), Err(PkceError::VerifierMissing));
    assert_eq!(
        check(Some(&RFC_VERIFIER[..42])),
        Err(PkceError::VerifierMalformed)
    );
    let other = "b".repeat(43);
    for wrong in [RFC_CHALLENGE, other.as_str()] {
        assert_eq!(check(Some(wrong)), Err(PkceError::VerifierMismatch));
    }
    assert_eq!(check(Some(RFC_VERIFIER)), Ok(()));
}

#[test]
fn pkce_errors_are_oauth_errors() {
    let mismatch = OAuthError::from(PkceError::VerifierMismatch);
    assert_eq!(mismatch.error, "invalid_grant");
    assert_eq!(mismatch.status, 400);
    for error in [
        PkceError::ChallengeMissing,
        PkceError::MethodUnsupported,
        PkceError::ChallengeMalformed,
        PkceError::VerifierMissing,
        PkceError::VerifierMalformed,
    ] {
        let oauth = OAuthError::from(error);
        assert_eq!(oauth.error, "invalid_request", "{error:?}");
        assert_eq!(oauth.description, error.description());
    }
}
