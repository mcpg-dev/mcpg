//! DPoP (RFC 9449) at the token endpoint of an ID-JAG redemption: each
//! check of a proof in its order, the `htu` a request accepts, the `iat`
//! window, server nonces, `ath`, the single-use ledger, the key an ID-JAG
//! is bound to (ID-JAG §9.8.1.2), and the token a proof binds.

use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use serde_json::{Value, json};

use super::*;
use crate::config::{DpopConfig, DpopNonceMode};
use crate::runtime::authorization_server::dpop::{
    DpopFailure, DpopPresentation, DpopReason, DpopSettings, DpopTarget, ProvenKey, mint_nonce,
    nonce_is_current, normalize_path, normalize_uri,
};

/// The URL of the token endpoint of the test issuer.
pub(super) const TOKEN_HTU: &str = "https://gw.test/oauth/token";
const SKEW: u64 = 60;
/// RFC 7638 §3.1: the example RSA key and its SHA-256 thumbprint.
const RFC7638_MODULUS: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// ---------------------------------------------------------------------------
// Client keys and proofs
// ---------------------------------------------------------------------------

/// A client's DPoP key, generated for the test: the signer and its public
/// JWK.
pub(super) struct ProofKey {
    encoding: EncodingKey,
    alg: Algorithm,
    alg_name: &'static str,
    jwk: Value,
}

impl ProofKey {
    fn from_encoding(encoding: EncodingKey, alg: Algorithm, alg_name: &'static str) -> Self {
        let jwk = serde_json::to_value(Jwk::from_encoding_key(&encoding, alg).expect("public JWK"))
            .expect("the JWK serializes");
        Self {
            encoding,
            alg,
            alg_name,
            jwk,
        }
    }

    fn ec(
        algorithm: &'static rcgen::SignatureAlgorithm,
        alg: Algorithm,
        name: &'static str,
    ) -> Self {
        let pem = rcgen::KeyPair::generate_for(algorithm)
            .expect("the key generates")
            .serialize_pem();
        Self::from_encoding(
            EncodingKey::from_ec_pem(pem.as_bytes()).expect("the key parses"),
            alg,
            name,
        )
    }

    pub(super) fn p256() -> Self {
        Self::ec(&rcgen::PKCS_ECDSA_P256_SHA256, Algorithm::ES256, "ES256")
    }

    fn p384() -> Self {
        Self::ec(&rcgen::PKCS_ECDSA_P384_SHA384, Algorithm::ES384, "ES384")
    }

    /// An Ed25519 key in PKCS#8 v1: a fixed DER prefix, then a random seed.
    fn ed25519() -> Self {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        der.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self::from_encoding(EncodingKey::from_ed_der(&der), Algorithm::EdDSA, "EdDSA")
    }

    /// The fixture IdP's RSA key, used as a client's, signing with `alg`.
    fn rsa(alg: Algorithm, name: &'static str) -> Self {
        let encoding = EncodingKey::from_rsa_pem(IDP_PRIVATE_PEM.as_bytes()).expect("fixture key");
        let mut jwk =
            serde_json::from_str::<Value>(IDP_JWKS).expect("fixture JWKS")["keys"][0].clone();
        for member in ["alg", "kid", "use"] {
            jwk.as_object_mut().expect("a JWK object").remove(member);
        }
        Self {
            encoding,
            alg,
            alg_name: name,
            jwk,
        }
    }

    pub(super) fn jkt(&self) -> String {
        serde_json::from_value::<Jwk>(self.jwk.clone())
            .expect("a JWK")
            .thumbprint(ThumbprintHash::SHA256)
            .expect("a thumbprint")
    }

    fn header(&self) -> Value {
        json!({ "typ": "dpop+jwt", "alg": self.alg_name, "jwk": self.jwk })
    }

    /// A compact JWS of `header` and `claims` under this key.
    fn sign(&self, header: &Value, claims: &Value) -> String {
        let encode = |value: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(value).expect("JSON"))
        };
        let message = format!("{}.{}", encode(header), encode(claims));
        let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &self.encoding, self.alg)
            .expect("the proof signs");
        format!("{message}.{signature}")
    }

    pub(super) fn proof(&self, claims: &Value) -> String {
        self.sign(&self.header(), claims)
    }

    /// A fresh proof of `method` at `htu`.
    pub(super) fn proof_for(&self, method: &str, htu: &str) -> String {
        self.proof(&proof_claims(method, htu))
    }

    /// A proof whose header `change` alters.
    fn proof_with_header(&self, change: impl FnOnce(&mut Value)) -> String {
        let mut header = self.header();
        change(&mut header);
        self.sign(&header, &proof_claims("POST", TOKEN_HTU))
    }
}

/// The claims of a fresh proof of `method` at `htu`.
pub(super) fn proof_claims(method: &str, htu: &str) -> Value {
    json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method,
        "htu": htu,
        "iat": now_unix(),
    })
}

pub(super) fn presented(proof: &str) -> DpopPresentation<'_> {
    DpopPresentation::from_values([proof.as_bytes()])
}

// ---------------------------------------------------------------------------
// The checks of one proof
// ---------------------------------------------------------------------------

fn resources() -> Vec<String> {
    vec![
        format!("{GW_ISSUER}/mcp"),
        "https://mcp.custom.example/mcp".to_owned(),
        "https://edge.example/acme/mcp/".to_owned(),
    ]
}

fn settings_with(change: impl FnOnce(&mut DpopConfig)) -> DpopSettings {
    let mut config = DpopConfig {
        enabled: true,
        ..DpopConfig::default()
    };
    change(&mut config);
    DpopSettings::from_config(&config, SKEW, GW_ISSUER, &resources()).expect("settings resolve")
}

fn settings() -> DpopSettings {
    settings_with(|_| {})
}

fn checked(settings: &DpopSettings, proof: &str) -> Result<ProvenKey, DpopFailure> {
    settings.check(
        &presented(proof),
        &DpopTarget::token_endpoint(),
        None,
        |_| true,
        now_unix(),
    )
}

#[track_caller]
fn refused_for(settings: &DpopSettings, proof: &str) -> DpopReason {
    match checked(settings, proof) {
        Err(DpopFailure::Invalid(reason, _)) => reason,
        other => panic!("expected an invalid proof, got {other:?}"),
    }
}

#[test]
fn a_proof_of_each_key_type_is_accepted_with_its_thumbprint() {
    let settings = settings();
    for key in [
        ProofKey::p256(),
        ProofKey::p384(),
        ProofKey::ed25519(),
        ProofKey::rsa(Algorithm::RS256, "RS256"),
        ProofKey::rsa(Algorithm::PS256, "PS256"),
    ] {
        let proven = checked(&settings, &key.proof_for("POST", TOKEN_HTU))
            .unwrap_or_else(|failure| panic!("{}: {failure:?}", key.alg_name));
        assert_eq!(proven.jkt(), key.jkt(), "{}", key.alg_name);
    }
}

#[test]
fn the_thumbprint_is_the_rfc_7638_one() {
    let jwk: Jwk =
        serde_json::from_value(json!({ "kty": "RSA", "n": RFC7638_MODULUS, "e": "AQAB" }))
            .expect("the RFC 7638 key parses");
    assert_eq!(
        jwk.thumbprint(ThumbprintHash::SHA256).expect("thumbprint"),
        RFC7638_THUMBPRINT
    );
    assert!(dpop::is_thumbprint(RFC7638_THUMBPRINT));
    assert!(!dpop::is_thumbprint(&RFC7638_THUMBPRINT[1..]));
    let padded = format!("{}=", &RFC7638_THUMBPRINT[1..]);
    assert!(!dpop::is_thumbprint(&padded));
}

#[test]
fn exactly_one_printable_header_of_at_most_8_kib_is_read() {
    let settings = settings();
    let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
    let target = DpopTarget::token_endpoint();
    let reason = |presentation: DpopPresentation<'_>| {
        let checked = settings.check(&presentation, &target, None, |_| true, now_unix());
        match checked {
            Err(DpopFailure::Invalid(reason, _)) => reason,
            other => panic!("expected an invalid proof, got {other:?}"),
        }
    };
    assert_eq!(reason(DpopPresentation::none()), DpopReason::Missing);
    assert_eq!(
        reason(DpopPresentation::from_values([
            proof.as_bytes(),
            proof.as_bytes()
        ])),
        DpopReason::Multiple
    );
    let large = "a".repeat(dpop::MAX_PROOF_BYTES + 1);
    assert_eq!(reason(presented(&large)), DpopReason::TooLarge);
    for unreadable in [
        format!("{proof} "),
        format!("{proof}\u{e9}"),
        format!("\t{proof}"),
    ] {
        assert_eq!(reason(presented(&unreadable)), DpopReason::Malformed);
    }
    let bytes: &[u8] = &[0xff, 0xfe, 0x2e];
    assert_eq!(
        reason(DpopPresentation::from_values([bytes])),
        DpopReason::Malformed
    );
}

#[test]
fn a_proof_that_is_not_a_compact_jws_is_malformed() {
    let settings = settings();
    let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
    let encoded_array = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("[1,2]");
    for malformed in [
        "only.two".to_owned(),
        format!("{proof}.fourth"),
        "!!!.e30.sig".to_owned(),
        format!("{encoded_array}.e30.sig"),
    ] {
        assert_eq!(
            refused_for(&settings, &malformed),
            DpopReason::Malformed,
            "{malformed}"
        );
    }
}

#[test]
fn typ_must_be_dpop_jwt() {
    let settings = settings();
    let key = ProofKey::p256();
    for accepted in ["dpop+jwt", "application/dpop+jwt", "DPoP+JWT"] {
        let proof = key.proof_with_header(|header| header["typ"] = json!(accepted));
        checked(&settings, &proof).unwrap_or_else(|f| panic!("{accepted}: {f:?}"));
    }
    for refused in [json!("JWT"), json!("at+jwt"), json!(7)] {
        let proof = key.proof_with_header(|header| header["typ"] = refused.clone());
        assert_eq!(refused_for(&settings, &proof), DpopReason::Typ, "{refused}");
    }
    let untyped = key.proof_with_header(|header| {
        header.as_object_mut().expect("object").remove("typ");
    });
    assert_eq!(refused_for(&settings, &untyped), DpopReason::Typ);
}

#[test]
fn a_critical_header_is_refused() {
    let proof = ProofKey::p256().proof_with_header(|header| header["crit"] = json!(["exp"]));
    assert_eq!(refused_for(&settings(), &proof), DpopReason::Crit);
}

#[test]
fn alg_must_be_an_allowed_asymmetric_algorithm() {
    let key = ProofKey::p256();
    for alg in [json!("none"), json!("HS256"), json!("ES512"), json!(null)] {
        let proof = key.proof_with_header(|header| header["alg"] = alg.clone());
        assert_eq!(refused_for(&settings(), &proof), DpopReason::Alg, "{alg}");
    }
    let es256_only = settings_with(|config| config.allowed_algs = vec!["ES256".to_owned()]);
    let proof = ProofKey::ed25519().proof_for("POST", TOKEN_HTU);
    assert_eq!(refused_for(&es256_only, &proof), DpopReason::Alg);
    checked(&es256_only, &key.proof_for("POST", TOKEN_HTU)).expect("ES256 is allowed");
}

#[test]
fn the_key_is_a_public_jwk_that_fits_the_alg() {
    let settings = settings();
    let key = ProofKey::p256();
    let without = key.proof_with_header(|header| {
        header.as_object_mut().expect("object").remove("jwk");
    });
    assert_eq!(refused_for(&settings, &without), DpopReason::Jwk);
    let not_an_object = key.proof_with_header(|header| header["jwk"] = json!("key"));
    assert_eq!(refused_for(&settings, &not_an_object), DpopReason::Jwk);
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let proof = key.proof_with_header(|header| header["jwk"][member] = json!("AQAB"));
        assert_eq!(
            refused_for(&settings, &proof),
            DpopReason::PrivateKey,
            "{member}"
        );
    }
    let symmetric = key.proof_with_header(|header| {
        header["jwk"] = json!({ "kty": "oct", "k": "c2VjcmV0" });
    });
    assert_eq!(refused_for(&settings, &symmetric), DpopReason::PrivateKey);
    let unusable = key.proof_with_header(|header| {
        header["jwk"] = json!({ "kty": "EC", "crv": "P-256", "x": "!!", "y": "!!" });
    });
    assert_eq!(refused_for(&settings, &unusable), DpopReason::Jwk);
}

#[test]
fn the_key_type_and_curve_must_be_the_algs() {
    let settings = settings();
    let p256 = ProofKey::p256();
    let ed25519 = ProofKey::ed25519();
    let cases = [
        (&p256, "ES384"),
        (&p256, "EdDSA"),
        (&p256, "RS256"),
        (&ed25519, "ES256"),
    ];
    for (key, alg) in cases {
        let proof = key.proof_with_header(|header| header["alg"] = json!(alg));
        assert_eq!(refused_for(&settings, &proof), DpopReason::Jwk, "{alg}");
    }
    let declared_other = p256.proof_with_header(|header| header["jwk"]["alg"] = json!("ES384"));
    assert_eq!(refused_for(&settings, &declared_other), DpopReason::Jwk);
}

#[test]
fn an_rsa_key_under_2048_bits_is_weak() {
    let modulus = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x80u8; 128]);
    let proof = ProofKey::rsa(Algorithm::RS256, "RS256").proof_with_header(|header| {
        header["jwk"] = json!({ "kty": "RSA", "n": modulus, "e": "AQAB" });
    });
    assert_eq!(refused_for(&settings(), &proof), DpopReason::WeakKey);
}

#[test]
fn a_signature_of_another_key_is_refused() {
    let settings = settings();
    let key = ProofKey::p256();
    let other = ProofKey::p256();
    let forged = other.sign(&key.header(), &proof_claims("POST", TOKEN_HTU));
    assert_eq!(refused_for(&settings, &forged), DpopReason::Signature);
    let proof = key.proof_for("POST", TOKEN_HTU);
    assert_eq!(
        refused_for(&settings, &corrupt_signature(&proof)),
        DpopReason::Signature
    );
}

#[test]
fn every_claim_has_its_type_and_bounds() {
    let settings = settings();
    let key = ProofKey::p256();
    let with = |name: &str, value: Value| {
        let mut claims = proof_claims("POST", TOKEN_HTU);
        if value.is_null() {
            claims.as_object_mut().expect("object").remove(name);
        } else {
            claims[name] = value;
        }
        key.proof(&claims)
    };
    for (name, value) in [
        ("jti", Value::Null),
        ("jti", json!(5)),
        ("jti", json!("")),
        ("jti", json!("j".repeat(257))),
        ("htm", Value::Null),
        ("htm", json!(["POST"])),
        ("htu", Value::Null),
        ("htu", json!(format!("{TOKEN_HTU}?{}", "q".repeat(2048)))),
        ("iat", Value::Null),
        ("iat", json!("now")),
        ("iat", json!(-5)),
    ] {
        assert_eq!(
            refused_for(&settings, &with(name, value.clone())),
            DpopReason::Claims,
            "{name}: {value}"
        );
    }
    for (name, value) in [
        ("jti", json!("j".repeat(256))),
        ("iat", json!(now_unix() as f64 + 0.5)),
    ] {
        checked(&settings, &with(name, value)).unwrap_or_else(|f| panic!("{name}: {f:?}"));
    }
}

#[test]
fn htm_is_the_request_method_exactly() {
    let key = ProofKey::p256();
    for method in ["post", "GET", "Post"] {
        assert_eq!(
            refused_for(&settings(), &key.proof_for(method, TOKEN_HTU)),
            DpopReason::Htm,
            "{method}"
        );
    }
}

#[test]
fn htu_is_compared_normalised_against_the_configured_origins() {
    let settings = settings();
    let token = DpopTarget::token_endpoint();
    for htu in [
        TOKEN_HTU,
        "HTTPS://GW.TEST/oauth/token",
        "https://gw.test:443/oauth/token",
        "https://gw.test/oauth/./x/../token",
        "https://gw.test/oauth/%74oken",
        "https://gw.test/oauth/token?x=1#fragment",
        "https://mcp.custom.example/oauth/token",
        "https://edge.example/oauth/token",
    ] {
        assert!(settings.htu_accepted(htu, &token), "{htu}");
    }
    for htu in [
        "http://gw.test/oauth/token",
        "https://gw.test:8443/oauth/token",
        "https://attacker.example/oauth/token",
        "https://gw.test.attacker.example/oauth/token",
        "https://gw.test/oauth/Token",
        "https://gw.test/oauth/token/",
        "https://user@gw.test/oauth/token",
        "/oauth/token",
        "https://gw.test/oauth/%zz",
    ] {
        assert!(!settings.htu_accepted(htu, &token), "{htu}");
    }
    let proof = ProofKey::p256().proof_for("POST", "https://attacker.example/oauth/token");
    assert_eq!(refused_for(&settings, &proof), DpopReason::Htu);
}

#[test]
fn htu_percent_encodings_compare_by_their_meaning() {
    let settings = settings();
    let tilde = DpopTarget {
        method: "GET",
        path: "/files/a~b",
        mcp_endpoint: false,
    };
    for htu in [
        "https://gw.test/files/a~b",
        "https://gw.test/files/a%7eb",
        "https://gw.test/files/a%7Eb",
    ] {
        assert!(settings.htu_accepted(htu, &tilde), "{htu}");
    }
    let slash = DpopTarget {
        method: "GET",
        path: "/files/a%2fb",
        mcp_endpoint: false,
    };
    assert!(settings.htu_accepted("https://gw.test/files/a%2Fb", &slash));
    assert!(!settings.htu_accepted("https://gw.test/files/a/b", &slash));
    let root = DpopTarget {
        method: "GET",
        path: "/",
        mcp_endpoint: false,
    };
    assert!(settings.htu_accepted("https://gw.test", &root));
}

/// A proxy that maps a public path onto the MCP path: the resource
/// identifier is a valid `htu` for the MCP endpoint, and only there.
#[test]
fn a_resource_identifier_is_an_htu_of_the_mcp_endpoint_only() {
    let settings = settings();
    let mcp = DpopTarget {
        method: "POST",
        path: "/mcp",
        mcp_endpoint: true,
    };
    for htu in [
        "https://edge.example/acme/mcp",
        "https://edge.example/acme/mcp/",
        "https://gw.test/mcp",
        "https://mcp.custom.example/mcp",
    ] {
        assert!(settings.htu_accepted(htu, &mcp), "{htu}");
    }
    let other = DpopTarget {
        method: "POST",
        path: "/other",
        mcp_endpoint: false,
    };
    assert!(!settings.htu_accepted("https://edge.example/acme/mcp", &other));
    assert!(!settings.htu_accepted("https://edge.example/other/mcp", &mcp));
}

#[test]
fn uris_normalise_as_rfc_3986_describes() {
    for (uri, normalized) in [
        ("HTTPS://Gw.Test:443", "https://gw.test/"),
        ("http://gw.test:80/a/../b?q=1#f", "http://gw.test/b"),
        (
            "https://gw.test:8443/%7e%2f%2E",
            "https://gw.test:8443/~%2F.",
        ),
        ("https://[::1]:8443/x", "https://[::1]:8443/x"),
    ] {
        assert_eq!(normalize_uri(uri).as_deref(), Some(normalized), "{uri}");
    }
    for refused in [
        "ftp://gw.test/",
        "https://user:pw@gw.test/",
        "/relative",
        "mailto:user@gw.test",
        "https://gw.test/%zz",
    ] {
        assert_eq!(normalize_uri(refused), None, "{refused}");
    }
    assert_eq!(normalize_path("/a/%7E/./b").as_deref(), Some("/a/~/b"));
    for refused in ["relative", "/a?b", "/a#b", "/bad%z"] {
        assert_eq!(normalize_path(refused), None, "{refused}");
    }
}

#[test]
fn iat_lies_within_the_proof_age_and_the_skew() {
    let settings = settings();
    let key = ProofKey::p256();
    let now = 2_000_000_000;
    let at = |iat: u64| {
        let mut claims = proof_claims("POST", TOKEN_HTU);
        claims["iat"] = json!(iat);
        settings.check(
            &presented(&key.proof(&claims)),
            &DpopTarget::token_endpoint(),
            None,
            |_| true,
            now,
        )
    };
    at(now - 60 - SKEW).expect("the oldest accepted iat");
    at(now + SKEW).expect("the newest accepted iat");
    for iat in [now - 60 - SKEW - 1, now + SKEW + 1] {
        assert!(
            matches!(at(iat), Err(DpopFailure::Invalid(DpopReason::Iat, _))),
            "{iat}"
        );
    }
}

#[test]
fn ath_is_the_hash_of_the_access_token() {
    let settings = settings();
    let key = ProofKey::p256();
    let token = "an-access-token";
    let mcp = DpopTarget {
        method: "POST",
        path: "/mcp",
        mcp_endpoint: true,
    };
    let with_ath = |ath: Option<&str>| {
        let mut claims = proof_claims("POST", "https://gw.test/mcp");
        if let Some(ath) = ath {
            claims["ath"] = json!(ath);
        }
        settings.check(
            &presented(&key.proof(&claims)),
            &mcp,
            Some(token),
            |_| true,
            now_unix(),
        )
    };
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()));
    with_ath(Some(&expected)).expect("the right ath");
    let other = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<sha2::Sha256 as sha2::Digest>::digest(b"another-token"));
    for ath in [None, Some(other.as_str()), Some("")] {
        assert!(
            matches!(with_ath(ath), Err(DpopFailure::Invalid(DpopReason::Ath, _))),
            "{ath:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

#[test]
fn a_nonce_is_current_in_its_window_and_the_next() {
    let first = [1u8; 32];
    let second = [2u8; 32];
    let nonce = mint_nonce(&first, GW_ISSUER, 10);
    assert_eq!(nonce.as_str().len(), 32);
    assert_ne!(nonce, mint_nonce(&first, GW_ISSUER, 11));
    let under_first = |windows| nonce_is_current([&first], GW_ISSUER, nonce.as_str(), windows);
    assert!(under_first(9..=10));
    assert!(under_first(10..=11));
    assert!(!under_first(11..=12));
    assert!(!under_first(8..=9));
    let issuer = "https://other.test";
    assert!(!nonce_is_current([&first], issuer, nonce.as_str(), 9..=10));
    // A key listed after the signing key still verifies; one removed does not.
    let rotated = [&second, &first];
    assert!(nonce_is_current(rotated, GW_ISSUER, nonce.as_str(), 9..=10));
    let under_second = nonce_is_current([&second], GW_ISSUER, nonce.as_str(), 9..=10);
    assert!(!under_second);
    let mut forged = nonce.as_str().to_owned();
    let last = forged.pop().expect("non-empty");
    forged.push(if last == 'A' { 'B' } else { 'A' });
    assert!(!nonce_is_current([&first], GW_ISSUER, &forged, 9..=10));
    for garbage in ["", "not-a-nonce", "AAAA"] {
        let current = nonce_is_current([&first], GW_ISSUER, garbage, 9..=10);
        assert!(!current, "{garbage}");
    }
}

/// A nonce is accepted in the window it was minted in and the next one,
/// each widened by the clock skew: a replica whose clock runs ahead by up
/// to the skew has already moved to the next window, one behind has not.
#[test]
fn nonce_windows_allow_for_the_clock_skew() {
    let settings = settings_with(|config| config.nonce_lifetime_secs = 300);
    // Mid-window, further than the skew from either edge.
    assert_eq!(settings.accepted_nonce_windows(10 * 300 + 150), 9..=10);
    // Within the skew of the next window: a replica ahead already mints it.
    assert_eq!(
        settings.accepted_nonce_windows(11 * 300 - SKEW),
        9..=11,
        "the next window, from a replica ahead by the skew"
    );
    assert_eq!(settings.accepted_nonce_windows(11 * 300 - SKEW - 1), 9..=10);
    // Just into a window: a replica behind still mints the one before, and
    // the one before that is kept for the skew too.
    assert_eq!(settings.accepted_nonce_windows(11 * 300), 9..=11);
    assert_eq!(settings.accepted_nonce_windows(11 * 300 + SKEW), 10..=11);
    assert_eq!(settings.accepted_nonce_windows(0), 0..=0);
}

#[test]
fn a_required_nonce_must_be_present_and_valid() {
    let settings = settings_with(|config| config.nonce = DpopNonceMode::TokenEndpoint);
    let key = ProofKey::p256();
    let with_nonce = |nonce: Option<&str>, valid: bool| {
        let mut claims = proof_claims("POST", TOKEN_HTU);
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        settings.check(
            &presented(&key.proof(&claims)),
            &DpopTarget::token_endpoint(),
            None,
            |_| valid,
            now_unix(),
        )
    };
    assert_eq!(with_nonce(None, true), Err(DpopFailure::UseNonce));
    assert_eq!(with_nonce(Some("stale"), false), Err(DpopFailure::UseNonce));
    let long = "n".repeat(65);
    assert_eq!(with_nonce(Some(&long), true), Err(DpopFailure::UseNonce));
    with_nonce(Some("current"), true).expect("a current nonce");

    // The nonce is asked for before the signature is checked, so that
    // answer costs no signature verification; with a current nonce, the
    // signature still decides.
    let forged_with = |nonce: Option<&str>, valid: bool| {
        let mut claims = proof_claims("POST", TOKEN_HTU);
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let proof = key.proof(&claims);
        let (signed, _) = proof.rsplit_once('.').expect("a compact JWS");
        settings.check(
            &presented(&format!("{signed}.c2lnbmF0dXJl")),
            &DpopTarget::token_endpoint(),
            None,
            |_| valid,
            now_unix(),
        )
    };
    assert_eq!(forged_with(None, true), Err(DpopFailure::UseNonce));
    assert_eq!(
        forged_with(Some("stale"), false),
        Err(DpopFailure::UseNonce)
    );
    assert!(matches!(
        forged_with(Some("current"), true),
        Err(DpopFailure::Invalid(DpopReason::Signature, _))
    ));
    // Without a required nonce, one in the proof is not read.
    let off = settings_with(|_| {});
    let mut claims = proof_claims("POST", TOKEN_HTU);
    claims["nonce"] = json!("anything");
    off.check(
        &presented(&key.proof(&claims)),
        &DpopTarget::token_endpoint(),
        None,
        |_| false,
        now_unix(),
    )
    .expect("the nonce is ignored");
}

// ---------------------------------------------------------------------------
// The server: ledger, metrics, redaction
// ---------------------------------------------------------------------------

pub(super) fn dpop_config() -> AuthorizationServerConfig {
    let mut config = test_config();
    config.dpop.enabled = true;
    config
}

pub(super) async fn dpop_server_with(
    change: impl FnOnce(&mut AuthorizationServerConfig),
) -> AuthorizationServer {
    let mut config = dpop_config();
    change(&mut config);
    test_server_with(config).await
}

pub(super) async fn dpop_server() -> AuthorizationServer {
    dpop_server_with(|_| {}).await
}

#[tokio::test]
async fn a_proof_is_spent_once_under_its_key() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let claims = proof_claims("POST", TOKEN_HTU);
    let proof = key.proof(&claims);
    let target = DpopTarget::token_endpoint();
    let proven = server
        .check_proof(&presented(&proof), &target, None)
        .await
        .expect("the first use");
    assert_eq!(proven.jkt(), key.jkt());
    assert!(matches!(
        server.check_proof(&presented(&proof), &target, None).await,
        Err(DpopFailure::Invalid(DpopReason::Replayed, _))
    ));
    // The same `jti` under another key is another proof.
    let other = ProofKey::p256();
    server
        .check_proof(&presented(&other.proof(&claims)), &target, None)
        .await
        .expect("another key's proof");
    assert_ne!(
        dpop::ledger_key(&key.jkt(), "jti-1"),
        dpop::ledger_key(&other.jkt(), "jti-1")
    );
    assert!(dpop::ledger_key(&key.jkt(), "jti-1").starts_with("ema_dpop_jti/"));
}

#[tokio::test]
async fn an_unwritable_ledger_refuses_the_proof() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = test_server_on(dpop_config(), ReplayLedger::shared(Arc::new(UnreachableKv))).await;
    let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
    assert_eq!(
        server
            .check_proof(&presented(&proof), &DpopTarget::token_endpoint(), None)
            .await,
        Err(DpopFailure::Unavailable)
    );
    let redemption = server
        .redeem_with_dpop(
            token_form(&make_id_jag(AssertionOverrides::default())),
            None,
            &presented(&ProofKey::p256().proof_for("POST", TOKEN_HTU)),
        )
        .await;
    let error = redemption.result.expect_err("the proof cannot be recorded");
    assert_eq!(error.status, 503);
    assert_eq!(error.error, "temporarily_unavailable");
    assert!(captured.seen("mcpg_ema_jti_store_errors_total{}"));
}

#[tokio::test]
async fn proofs_are_counted_by_outcome_and_reason() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let target = DpopTarget::token_endpoint();
    let proof = key.proof_for("POST", TOKEN_HTU);
    let _ = server.check_proof(&presented(&proof), &target, None).await;
    let _ = server.check_proof(&presented(&proof), &target, None).await;
    let _ = server
        .check_proof(&presented(&key.proof_for("GET", TOKEN_HTU)), &target, None)
        .await;
    for metric in [
        "mcpg_as_dpop_proofs_total{endpoint=token,outcome=accepted,reason=none}",
        "mcpg_as_dpop_proofs_total{endpoint=token,outcome=replayed,reason=replayed}",
        "mcpg_as_dpop_proofs_total{endpoint=token,outcome=refused,reason=htm}",
        "mcpg_as_dpop_ledger_latency_ms{endpoint=token}",
    ] {
        assert!(captured.seen(metric), "{metric}: {:?}", captured.recorded());
    }
}

#[test]
fn debug_output_shows_no_proof_key_or_nonce() {
    let key = ProofKey::p256();
    let proof = key.proof_for("POST", TOKEN_HTU);
    let proven = checked(&settings(), &proof).expect("a valid proof");
    let rendered = format!("{proven:?} {:?}", presented(&proof));
    assert!(!rendered.contains(&key.jkt()), "{rendered}");
    assert!(!rendered.contains(&proof), "{rendered}");
    let nonce = mint_nonce(&[3u8; 32], GW_ISSUER, 1);
    assert!(!format!("{nonce:?}").contains(nonce.as_str()));
}

// ---------------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------------

pub(super) async fn redeem_presenting(
    server: &AuthorizationServer,
    assertion: &str,
    proof: Option<&str>,
) -> TokenRedemption {
    let presentation = proof.map_or_else(DpopPresentation::none, presented);
    server
        .redeem_with_dpop(token_form(assertion), None, &presentation)
        .await
}

#[track_caller]
pub(super) fn issued_by(redemption: &TokenRedemption) -> &(TokenResponse, IssuedToken) {
    redemption
        .result
        .as_ref()
        .unwrap_or_else(|error| panic!("the request should succeed: {error:?}"))
}

#[track_caller]
fn refused_with(redemption: &TokenRedemption) -> &OAuthError {
    match redemption.result {
        Err(ref error) => error,
        Ok(_) => panic!("the request should be refused"),
    }
}

fn bound_assertion(jkt: &str) -> String {
    make_id_jag(AssertionOverrides {
        extra: json!({ "cnf": { "jkt": jkt } }),
        ..Default::default()
    })
}

#[tokio::test]
async fn a_proof_binds_the_minted_token_to_its_key() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let proof = key.proof_for("POST", TOKEN_HTU);
    let assertion = make_id_jag(AssertionOverrides::default());
    let redemption = redeem_presenting(&server, &assertion, Some(&proof)).await;
    let (response, issued) = issued_by(&redemption);
    assert_eq!(response.token_type, "DPoP");
    assert_eq!(issued.dpop_jkt.as_deref(), Some(key.jkt().as_str()));
    assert_eq!(
        minted_claims(&response.access_token)["cnf"],
        json!({ "jkt": key.jkt() })
    );
    match server.verify_bearer(&response.access_token) {
        EmaBearerOutcome::Refused(refusal) => {
            assert!(refusal.description.contains("DPoP-bound"), "{refusal:?}");
        }
        other => panic!("expected a DPoP refusal, got {}", discriminant_name(&other)),
    }

    let event = redemption.audit_event("req-dpop");
    assert_eq!(event.details["token_type"], "DPoP");
    assert_eq!(event.details["dpop_jkt"], key.jkt());
    let recorded = serde_json::to_string(&event).expect("serializes");
    for secret_part in [
        proof.as_str(),
        proof.split('.').nth(2).expect("signature"),
        response.access_token.as_str(),
    ] {
        assert!(!recorded.contains(secret_part), "{recorded}");
    }
}

#[tokio::test]
async fn without_a_proof_the_token_stays_a_bearer_token() {
    let server = dpop_server().await;
    let redemption =
        redeem_presenting(&server, &make_id_jag(AssertionOverrides::default()), None).await;
    let (response, issued) = issued_by(&redemption);
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(issued.dpop_jkt, None);
    assert!(minted_claims(&response.access_token).get("cnf").is_none());
    assert!(matches!(
        server.verify_bearer(&response.access_token),
        EmaBearerOutcome::Verified(_)
    ));
    let event = redemption.audit_event("req-bearer");
    assert_eq!(event.details["token_type"], "Bearer");
    assert!(event.details["dpop_jkt"].is_null());
    assert_eq!(redemption.dpop_nonce, None);
}

/// Off, nothing changes: a `DPoP` header is not read, the metadata names
/// no proof algorithm, and a bound token minted earlier stays refused.
#[tokio::test]
async fn while_dpop_is_off_proofs_are_ignored_and_bound_tokens_refused() {
    let bound_token = {
        let server = dpop_server().await;
        let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
        let redemption = redeem_presenting(
            &server,
            &make_id_jag(AssertionOverrides::default()),
            Some(&proof),
        )
        .await;
        issued_by(&redemption).0.access_token.clone()
    };
    let server = test_server().await;
    let redemption = redeem_presenting(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some("not-a-proof"),
    )
    .await;
    assert_eq!(issued_by(&redemption).0.token_type, "Bearer");
    assert!(!redemption.context.dpop_presented);
    let metadata = server.metadata();
    assert!(metadata.get("dpop_signing_alg_values_supported").is_none());
    let reason = invalid_reason(&server, &bound_token);
    assert!(reason.contains("DPoP-bound"), "{reason}");
}

#[tokio::test]
async fn the_metadata_names_the_proof_algorithms_while_dpop_is_on() {
    let server = dpop_server_with(|config| {
        config.dpop.allowed_algs = vec!["EdDSA".to_owned(), "ES256".to_owned()];
    })
    .await;
    assert_eq!(
        server.metadata()["dpop_signing_alg_values_supported"],
        json!(["EdDSA", "ES256"])
    );
}

/// A refused proof spends nothing: the same assertion then redeems with a
/// valid one.
#[tokio::test]
async fn an_invalid_proof_is_refused_before_the_assertion_is_spent() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let assertion = make_id_jag(AssertionOverrides::default());
    let redemption =
        redeem_presenting(&server, &assertion, Some(&key.proof_for("GET", TOKEN_HTU))).await;
    let error = refused_with(&redemption);
    assert_eq!((error.status, error.error), (400, "invalid_dpop_proof"));
    assert!(!error.basic_challenge);
    let event = redemption.audit_event("req-refused");
    assert_eq!(event.details["dpop_presented"], true);
    assert_eq!(event.details["error"], "invalid_dpop_proof");

    let redemption =
        redeem_presenting(&server, &assertion, Some(&key.proof_for("POST", TOKEN_HTU))).await;
    assert_eq!(issued_by(&redemption).0.token_type, "DPoP");
}

/// ID-JAG §9.8.1.2: an assertion bound to a key redeems only with a proof
/// of that key, and only a `jkt` confirmation is understood.
#[tokio::test]
async fn an_assertion_bound_to_a_key_redeems_only_with_a_proof_of_it() {
    let server = dpop_server().await;
    let key = ProofKey::p256();
    let other = ProofKey::p256();
    let assertion = bound_assertion(&key.jkt());

    let mismatch = redeem_presenting(
        &server,
        &assertion,
        Some(&other.proof_for("POST", TOKEN_HTU)),
    )
    .await;
    let error = refused_with(&mismatch);
    assert_eq!(error.error, "invalid_grant");
    assert!(
        error
            .description
            .contains("not the key the assertion is bound to"),
        "{error:?}"
    );
    let missing = redeem_presenting(&server, &assertion, None).await;
    let error = refused_with(&missing);
    assert_eq!(error.error, "invalid_grant");
    assert!(
        error.description.contains("proof of possession required"),
        "{error:?}"
    );

    // Neither refusal spent the assertion.
    let redemption =
        redeem_presenting(&server, &assertion, Some(&key.proof_for("POST", TOKEN_HTU))).await;
    let (response, _) = issued_by(&redemption);
    assert_eq!(response.token_type, "DPoP");
    assert_eq!(
        minted_claims(&response.access_token)["cnf"]["jkt"],
        key.jkt()
    );

    for cnf in [
        json!({ "jkt": key.jkt(), "kid": "k1" }),
        json!({ "x5t#S256": key.jkt() }),
        json!({ "jwk": key.jwk }),
        json!({ "jkt": "too-short" }),
        json!({ "jkt": 7 }),
        json!(key.jkt()),
        json!([key.jkt()]),
    ] {
        let assertion = make_id_jag(AssertionOverrides {
            extra: json!({ "cnf": cnf }),
            ..Default::default()
        });
        let redemption =
            redeem_presenting(&server, &assertion, Some(&key.proof_for("POST", TOKEN_HTU))).await;
        let error = refused_with(&redemption);
        assert_eq!(error.error, "invalid_grant", "{cnf}");
        assert!(
            error
                .description
                .contains("unsupported confirmation method"),
            "{cnf}: {error:?}"
        );
    }
}

/// RFC 9449 §5.2 in a Client ID Metadata Document: any value but `false`
/// asks for bound tokens.
#[test]
fn a_metadata_document_may_ask_for_bound_tokens() {
    const URL: &str = "https://app.example/client.json";
    let config = crate::config::ClientIdMetadataDocumentsConfig {
        allowed_hosts: vec!["app.example".to_owned()],
        ..Default::default()
    };
    for (member, bound) in [
        (None, false),
        (Some(json!(false)), false),
        (Some(json!(true)), true),
        (Some(json!("yes")), true),
    ] {
        let mut document = json!({
            "client_id": URL,
            "client_name": "App",
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "none",
        });
        if let Some(ref value) = member {
            document["dpop_bound_access_tokens"] = value.clone();
        }
        let client = crate::runtime::authorization_server::clients::client_from_document_body(
            URL,
            document.to_string().as_bytes(),
            &config,
        )
        .expect("the document describes a client");
        assert_eq!(client.dpop_bound_access_tokens(), bound, "{member:?}");
        assert!(client.is_public());
    }
}

#[tokio::test]
async fn required_or_the_client_flag_refuse_an_unbound_redemption() {
    let required = dpop_server_with(|config| config.dpop.required = true).await;
    let flagged =
        dpop_server_with(|config| config.clients[0].dpop_bound_access_tokens = true).await;
    for (server, named) in [
        (&required, "issues only DPoP-bound tokens"),
        (&flagged, "dpop_bound_access_tokens"),
    ] {
        let redemption =
            redeem_presenting(server, &make_id_jag(AssertionOverrides::default()), None).await;
        let error = refused_with(&redemption);
        assert_eq!(error.error, "invalid_grant");
        assert!(error.description.contains(named), "{error:?}");
        let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
        let redemption = redeem_presenting(
            server,
            &make_id_jag(AssertionOverrides::default()),
            Some(&proof),
        )
        .await;
        assert_eq!(issued_by(&redemption).0.token_type, "DPoP");
    }
}

/// RFC 9449 §8: without a current nonce the answer is `use_dpop_nonce`
/// with one; a proof that carries it redeems, and every answer names the
/// current nonce.
#[tokio::test]
async fn a_nonce_is_handed_out_and_then_required() {
    let server = dpop_server_with(|config| config.dpop.nonce = DpopNonceMode::TokenEndpoint).await;
    let key = ProofKey::p256();
    let assertion = make_id_jag(AssertionOverrides::default());
    let first =
        redeem_presenting(&server, &assertion, Some(&key.proof_for("POST", TOKEN_HTU))).await;
    let error = refused_with(&first);
    assert_eq!((error.status, error.error), (400, "use_dpop_nonce"));
    assert!(first.nonce_requested());
    assert!(
        first.audit_events("req-nonce").is_empty(),
        "a nonce round trip is not a failed authentication"
    );
    let nonce = first.dpop_nonce.clone().expect("a nonce to use");

    let mut claims = proof_claims("POST", TOKEN_HTU);
    claims["nonce"] = json!(nonce.as_str());
    let retried = redeem_presenting(&server, &assertion, Some(&key.proof(&claims))).await;
    assert_eq!(issued_by(&retried).0.token_type, "DPoP");
    assert!(!retried.nonce_requested());
    assert_eq!(retried.audit_events("req-issued").len(), 1);
    assert!(retried.dpop_nonce.is_some());
    // The nonce does not replace the single use of the proof.
    let replayed = redeem_presenting(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some(&key.proof(&claims)),
    )
    .await;
    assert_eq!(refused_with(&replayed).error, "invalid_dpop_proof");
}

/// Nonces come from the signing keys: a replica that lists the key a nonce
/// was minted under accepts it, one that dropped the key does not.
#[tokio::test]
async fn nonces_follow_the_signing_keys() {
    let old = hmac_key(Some("old"), "old-signing-secret-0123456789abcdef");
    let new = hmac_key(Some("new"), "new-signing-secret-0123456789abcdef");
    let with_keys = |keys: Vec<SigningKeyConfig>| {
        let mut config = config_with_keys(keys);
        config.dpop.enabled = true;
        config.dpop.nonce = DpopNonceMode::Always;
        config
    };
    let before = test_server_with(with_keys(vec![old.clone()])).await;
    let nonce = before.token_endpoint_nonce().expect("nonces are on");
    let rotated = test_server_with(with_keys(vec![new.clone(), old])).await;
    let after = test_server_with(with_keys(vec![new])).await;
    let key = ProofKey::p256();
    for (server, accepted) in [(&rotated, true), (&after, false)] {
        let mut claims = proof_claims("POST", TOKEN_HTU);
        claims["nonce"] = json!(nonce.as_str());
        let redemption = redeem_presenting(
            server,
            &make_id_jag(AssertionOverrides::default()),
            Some(&key.proof(&claims)),
        )
        .await;
        if accepted {
            assert_eq!(issued_by(&redemption).0.token_type, "DPoP");
        } else {
            assert_eq!(refused_with(&redemption).error, "use_dpop_nonce");
        }
    }
}

#[tokio::test]
async fn bound_tokens_are_counted_by_grant() {
    let captured = CapturedMetrics::default();
    let _recording = metrics::set_default_local_recorder(&captured);
    let server = dpop_server().await;
    let proof = ProofKey::p256().proof_for("POST", TOKEN_HTU);
    let redemption = redeem_presenting(
        &server,
        &make_id_jag(AssertionOverrides::default()),
        Some(&proof),
    )
    .await;
    issued_by(&redemption);
    assert!(
        captured.seen("mcpg_as_dpop_bound_tokens_total{grant=jwt_bearer}"),
        "{:?}",
        captured.recorded()
    );
}
