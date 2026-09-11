//! Config sources for `--config`. A gateway config layer can come from more
//! than a local file: a `--config` value is resolved into a [`ConfigSource`]
//! that is either a local file (re-read on hot-reload) or an in-memory YAML
//! snapshot fetched from a remote URL or decoded from inline base64 — so a
//! gateway can boot from a config it never writes to disk.
//!
//! A layer may be **client-encrypted**: the host stores ciphertext it cannot
//! read, and the gateway decrypts it here (see [`super::encrypted`]). That is
//! its own scheme, `mcpg+enc:`, and never a guess about what a plain `https://`
//! URL turned out to contain. Sniffing would be the wrong instinct twice over —
//! YAML is a superset of JSON, so a legitimate config can look like an
//! envelope, and there is nowhere in a plain `https://` fetch to say which
//! secret opens it.
//!
//! Layers merge in the order given, later winning, exactly like a
//! path-separator-joined `MCPG_CONFIG` list. The flag outranks the
//! environment: when `--config` is given, `MCPG_CONFIG` is not read.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use mcpg_sensitive::Sensitive;

use super::encrypted::{self, EncryptedPayload};

/// Cap on bytes accepted from a remote config fetch. A config that large is
/// almost certainly a misconfiguration, and an unbounded read is a DoS
/// foot-gun for a boot-critical fetch.
const MAX_REMOTE_CONFIG_BYTES: u64 = 5 * 1024 * 1024;
/// Remote config fetch timeout — boot must not hang on a slow config host.
const REMOTE_CONFIG_TIMEOUT: Duration = Duration::from_secs(10);
/// Opt-in env flag permitting a plaintext `http://` config URL (MITM risk).
const ALLOW_INSECURE_ENV: &str = "MCPG_CONFIG_ALLOW_INSECURE_HTTP";

/// One resolved config layer.
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// A local YAML file. Re-read from disk on every hot-reload.
    File(PathBuf),
    /// YAML text captured at boot — from a remote URL or inline base64. The
    /// `origin` is a human/audit label (the URL, or `base64:`/`data:`); an
    /// inline layer is NOT re-fetched on reload, its boot snapshot is reused.
    Inline { origin: String, yaml: String },
}

impl ConfigSource {
    /// Label for diagnostics and the `mcpg.config.loaded` audit event.
    #[must_use]
    pub fn origin_label(&self) -> String {
        match self {
            ConfigSource::File(p) => p.display().to_string(),
            ConfigSource::Inline { origin, .. } => origin.clone(),
        }
    }
}

/// Resolve one `--config` spec into a [`ConfigSource`], classifying by scheme:
/// - `base64:<b64>` or `data:[...];base64,<b64>` (RFC 2397) → decoded inline
/// - `mcpg+enc:<address>` → a client-encrypted config, fetched and decrypted now
/// - `https://…` (or `http://…` with [`ALLOW_INSECURE_ENV`]) → fetched now as
///   plaintext YAML
/// - `file://<path>` or a bare path → a local file, read at load time
pub async fn resolve(spec: &str) -> Result<ConfigSource> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        bail!("empty --config source");
    }
    if let Some(rest) = trimmed.strip_prefix("base64:") {
        return decode_base64("base64", rest);
    }
    if let Some(rest) = trimmed.strip_prefix("data:") {
        return decode_data_uri(rest);
    }
    if let Some(rest) = trimmed.strip_prefix(encrypted::SCHEME) {
        // Split the fragment off before anything else touches the value, so a
        // pasted secret cannot reach the fetch, the error text, or the origin
        // label that lands in `mcpg.config.loaded`.
        let (address, fragment_secret) = encrypted::split_fragment(rest);
        if fragment_secret.is_some() {
            tracing::warn!(
                "the config secret was passed on the command line; it is visible in `ps` and in \
                 your shell history. Prefer {}.",
                encrypted::SECRET_FILE_ENV
            );
        }
        return fetch_encrypted(address, fragment_secret.as_ref()).await;
    }
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return fetch_remote(trimmed).await;
    }
    if let Some(path) = trimmed.strip_prefix("file://") {
        return Ok(ConfigSource::File(PathBuf::from(path)));
    }
    Ok(ConfigSource::File(PathBuf::from(trimmed)))
}

fn decode_base64(scheme: &str, b64: &str) -> Result<ConfigSource> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .with_context(|| format!("--config {scheme}: payload is not valid standard base64"))?;
    let yaml = String::from_utf8(bytes)
        .with_context(|| format!("--config {scheme}: payload is not valid UTF-8 YAML"))?;
    Ok(ConfigSource::Inline {
        origin: format!("{scheme}:<{} bytes>", yaml.len()),
        yaml,
    })
}

/// RFC 2397 data URI: `data:[<mediatype>][;base64],<data>`. Only the base64
/// form is accepted — a percent-encoded YAML body would be ambiguous.
fn decode_data_uri(rest: &str) -> Result<ConfigSource> {
    let (meta, data) = rest
        .split_once(',')
        .context("--config data: URI is missing the comma before its payload")?;
    if !meta.split(';').any(|t| t.eq_ignore_ascii_case("base64")) {
        bail!("--config data: URI must be base64-encoded (data:...;base64,<payload>)");
    }
    decode_base64("data", data)
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REMOTE_CONFIG_TIMEOUT)
        .build()
        .context("build config-fetch HTTP client")
}

fn check_transport(url: &str) -> Result<()> {
    let insecure_ok = std::env::var(ALLOW_INSECURE_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if url.starts_with("http://") && !insecure_ok {
        bail!(
            "refusing to fetch config over plaintext http:// ({url}): a network attacker can \
             rewrite the gateway's config. Use https://, or set {ALLOW_INSECURE_ENV}=1 to override."
        );
    }
    Ok(())
}

/// A tombstone says WHETHER, never WHAT: `410` carries the reason a config
/// stopped being servable, and the two reasons need different operator actions.
async fn fail_by_status(url: &str, resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    if status == reqwest::StatusCode::GONE {
        let reason = resp
            .text()
            .await
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|v| {
                v.get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        return match reason.as_deref() {
            Some("burned") => anyhow::anyhow!(
                "config at {url} was burned: it was published for a single read and its \
                 ciphertext has been destroyed. No secret recovers it — ask the publisher for a \
                 new link."
            ),
            Some("expired") => anyhow::anyhow!(
                "config at {url} has expired and the host no longer serves its ciphertext. Ask \
                 the publisher to re-publish it."
            ),
            _ => anyhow::anyhow!("config at {url} is gone (HTTP 410) and cannot be fetched"),
        };
    }
    anyhow::anyhow!("fetch config from {url}: HTTP {status}")
}

fn check_declared_len(url: &str, declared: Option<u64>) -> Result<()> {
    if let Some(len) = declared
        && len > MAX_REMOTE_CONFIG_BYTES
    {
        bail!("remote config {url} is {len} bytes, over the {MAX_REMOTE_CONFIG_BYTES}-byte cap");
    }
    Ok(())
}

/// A plain `https://` layer: whatever the host serves, verbatim, as YAML. No
/// content-type dance and no envelope sniffing — an encrypted config arrives
/// through `mcpg+enc:` and nowhere else.
async fn fetch_remote(url: &str) -> Result<ConfigSource> {
    check_transport(url)?;
    let resp = http_client()?
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetch config from {url}"))?;
    if !resp.status().is_success() {
        return Err(fail_by_status(url, resp).await);
    }
    check_declared_len(url, resp.content_length())?;
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read config body from {url}"))?;
    // Re-checked after reading, for chunked responses with no declared length.
    if bytes.len() as u64 > MAX_REMOTE_CONFIG_BYTES {
        bail!("remote config {url} exceeds the {MAX_REMOTE_CONFIG_BYTES}-byte cap");
    }
    let yaml = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("config from {url} is not valid UTF-8"))?;
    Ok(ConfigSource::Inline {
        origin: url.to_string(),
        yaml,
    })
}

/// Fetch and open one client-encrypted layer.
///
/// The address names the config; the response supplies the parameters; the
/// operator supplies the secret. The id the tag is checked against comes from
/// the address, so a host that answers one config's address with another
/// config's authentic payload fails authentication rather than booting the
/// wrong configuration under the right label.
async fn fetch_encrypted(
    address: &str,
    fragment_secret: Option<&Sensitive<String>>,
) -> Result<ConfigSource> {
    let addr = encrypted::parse_address(address)
        .with_context(|| format!("--config {}{address}", encrypted::SCHEME))?;
    check_transport(&addr.fetch_url)?;

    let resp = http_client()?
        .get(&addr.fetch_url)
        // The raw form: bytes plus parameters in headers, so a config does not
        // make a base64 round trip on the way into a boot.
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .send()
        .await
        .with_context(|| format!("fetch encrypted config from {}", addr.fetch_url))?;
    if !resp.status().is_success() {
        return Err(fail_by_status(address, resp).await);
    }
    check_declared_len(&addr.fetch_url, resp.content_length())?;

    let header = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let require = |name: &'static str| -> Result<String> {
        header(name).with_context(|| {
            format!(
                "the host answered {} without the `{name}` header, so it is not serving an \
                 {} payload. Check the address.",
                addr.fetch_url,
                encrypted::CONSTRUCTION
            )
        })
    };
    let parse_num = |name: &'static str, raw: &str| -> Result<i64> {
        raw.trim()
            .parse()
            .with_context(|| format!("`{name}` is {raw:?}, which is not a number"))
    };

    let version_raw = require("x-mcpg-version")?;
    let version = u64::try_from(parse_num("x-mcpg-version", &version_raw)?)
        .context("`x-mcpg-version` is negative")?;
    let expires_at = parse_num("x-mcpg-expires-at", &require("x-mcpg-expires-at")?)?;
    let one_time_read = require("x-mcpg-one-time")?
        .trim()
        .eq_ignore_ascii_case("true");
    let kdf = require("x-mcpg-kdf")?;
    let kdf_salt = encrypted::decode_b64("x-mcpg-kdf-salt", &require("x-mcpg-kdf-salt")?)?;
    let nonce = encrypted::decode_b64("x-mcpg-nonce", &require("x-mcpg-nonce")?)?;
    let served_aad = header("x-mcpg-aad");

    // A pinned address is only pinned if the answer is checked. The service
    // enforces it too; this is the half that does not depend on the service.
    if let Some(want) = addr.version
        && want != version
    {
        bail!(
            "asked {} for version {want} and got version {version}. The address pins a version \
             precisely so a host cannot answer with a different one.",
            addr.fetch_url
        );
    }
    // The floor is applied before the secret is resolved, so a refused payload
    // never prompts anyone for one.
    if let Some(floor) = encrypted::min_version()?
        && version < floor
    {
        bail!(
            "encrypted config {} is version {version}, below the {}={floor} floor — the host may \
             be serving an older authentic version. Pin the version in the address \
             (`.../c/<id>/v/<n>`) to rule it out.",
            addr.id,
            encrypted::MIN_VERSION_ENV
        );
    }

    let ciphertext = resp
        .bytes()
        .await
        .with_context(|| format!("read encrypted config from {}", addr.fetch_url))?;
    if ciphertext.len() as u64 > MAX_REMOTE_CONFIG_BYTES {
        bail!(
            "encrypted config {} exceeds the {MAX_REMOTE_CONFIG_BYTES}-byte cap",
            addr.fetch_url
        );
    }

    let payload = EncryptedPayload {
        id: addr.id.clone(),
        version,
        expires_at,
        one_time_read,
        kdf,
        kdf_salt,
        nonce,
        ciphertext: ciphertext.to_vec(),
        served_aad,
    };

    let secret = encrypted::resolve_secret(&addr.id, fragment_secret)
        .with_context(|| format!("encrypted config {}", addr.id))?;
    let opened = encrypted::open(&payload, &secret, chrono::Utc::now().timestamp())
        .with_context(|| format!("encrypted config {}", addr.id))?;

    // The version rides in the origin label, and therefore in the
    // `mcpg.config.loaded` audit event: a rollback the pinned form would have
    // prevented is at least visible after the fact. The secret never does.
    Ok(ConfigSource::Inline {
        origin: format!("{}{address}@v{}", encrypted::SCHEME, opened.version),
        yaml: opened.yaml,
    })
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload as AeadPayload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::STANDARD as B64;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// Every test here that reaches a `MockServer` needs the plaintext-http
    /// opt-in, and one test needs it *absent* — serialise them so neither can
    /// observe the other's process-wide environment. Async-aware because each
    /// test holds it across the mock server's own awaits.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const TEST_ID: &str = "0k3n8xq2vftr7bdyw5m1jhpz6c";
    const OTHER_ID: &str = "1a2b3c4d5e6f7g8h9j0kmnpqrs";
    const SAMPLE_YAML: &str = "gateway:\n  server:\n    bind_address: \"127.0.0.1:9100\"\n";
    const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

    fn allow_insecure_http() {
        // SAFETY: the caller holds ENV_LOCK, which serialises every test in
        // this module that reads or writes this variable.
        unsafe {
            std::env::set_var(ALLOW_INSECURE_ENV, "1");
        }
    }

    /// The publisher's presentation form, written out longhand so the tests
    /// exercise the contract rather than the implementation's own inverse.
    fn secret_text(bytes: &[u8; 32]) -> String {
        let mut bits = 0u32;
        let mut value = 0u32;
        let mut out = String::new();
        for b in bytes {
            value = (value << 8) | u32::from(*b);
            bits += 8;
            while bits >= 5 {
                out.push(CROCKFORD[((value >> (bits - 5)) & 31) as usize] as char);
                bits -= 5;
            }
        }
        // 32 bytes is 51 whole groups plus one leftover bit, which the encoder
        // pads out to a 52nd character. Dropping it would produce a 51-character
        // string no decoder accepts.
        if bits > 0 {
            out.push(CROCKFORD[((value << (5 - bits)) & 31) as usize] as char);
        }
        format!("mcpg_sk_{}", &out[..52])
    }

    /// What a publisher stores. Longhand for the same reason.
    struct Sealed {
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        salt: [u8; 16],
        expires_at: i64,
        one_time: bool,
        version: u64,
    }

    fn seal(secret: &[u8; 32], id: &str, version: u64, expires_at: i64, yaml: &str) -> Sealed {
        let salt = [2u8; 16];
        let nonce = [9u8; 12];
        let one_time = false;
        let plaintext = serde_json::json!({
            "doc": "mcpg.config/v1",
            "name": "acme prod gateway",
            "description": "",
            "format": "yaml",
            "config": yaml,
            "updated_at": "2026-08-27T09:41:12Z",
        })
        .to_string();
        let aad = format!(
            "mcpg-config-v1|{id}|{version}|{expires_at}|{}|{}",
            u8::from(one_time),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt)
        );
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), secret);
        let mut key = [0u8; 32];
        hk.expand(b"mcpg-config-v1/key", &mut key).unwrap();
        let ciphertext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                AeadPayload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        Sealed {
            ciphertext,
            nonce,
            salt,
            expires_at,
            one_time,
            version,
        }
    }

    fn far_future() -> i64 {
        chrono::Utc::now().timestamp() + 86_400
    }

    /// Stand in for the service's raw payload route, headers included.
    async fn serve_payload(id: &str, sealed: &Sealed) -> MockServer {
        serve_payload_as(id, id, sealed).await
    }

    /// `route_id` is the address the caller asks for; `blob_id` is the config
    /// the payload was actually sealed for. They differ only in the
    /// substitution test.
    async fn serve_payload_as(route_id: &str, blob_id: &str, sealed: &Sealed) -> MockServer {
        let aad = format!(
            "mcpg-config-v1|{blob_id}|{}|{}|{}|{}",
            sealed.version,
            sealed.expires_at,
            u8::from(sealed.one_time),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed.salt)
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/configs/{route_id}/ciphertext")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(sealed.ciphertext.clone(), "application/octet-stream")
                    .append_header("x-mcpg-nonce", B64.encode(sealed.nonce).as_str())
                    .append_header("x-mcpg-kdf", "hkdf-sha256")
                    .append_header("x-mcpg-kdf-salt", B64.encode(sealed.salt).as_str())
                    .append_header("x-mcpg-expires-at", sealed.expires_at.to_string().as_str())
                    .append_header("x-mcpg-one-time", sealed.one_time.to_string().as_str())
                    .append_header("x-mcpg-version", sealed.version.to_string().as_str())
                    .append_header("x-mcpg-aad", aad.as_str()),
            )
            .mount(&server)
            .await;
        server
    }

    async fn serve_status(id: &str, status: u16, body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/configs/{id}/ciphertext")))
            .respond_with(
                ResponseTemplate::new(status).set_body_raw(body.to_string(), "application/json"),
            )
            .mount(&server)
            .await;
        server
    }

    fn spec(server: &MockServer, id: &str, secret: &[u8; 32]) -> String {
        format!("mcpg+enc:{}/c/{id}#k={}", server.uri(), secret_text(secret))
    }

    #[tokio::test]
    async fn an_encrypted_layer_round_trips_through_resolve() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        let sealed = seal(&secret, TEST_ID, 3, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        match resolve(&spec(&server, TEST_ID, &secret)).await.unwrap() {
            ConfigSource::Inline { origin, yaml } => {
                assert_eq!(yaml, SAMPLE_YAML);
                // The resolved version rides in the origin (and so into the
                // `mcpg.config.loaded` audit event); the secret never does.
                assert!(origin.ends_with(&format!("/c/{TEST_ID}@v3")), "{origin}");
                assert!(origin.starts_with("mcpg+enc:"), "{origin}");
                assert!(!origin.contains('#'), "{origin}");
                assert!(
                    !origin.contains("mcpg_sk_"),
                    "secret leaked into origin: {origin}"
                );
            }
            other => panic!("expected inline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_wrong_secret_is_rejected_and_says_so() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let sealed = seal(&[42u8; 32], TEST_ID, 1, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&spec(&server, TEST_ID, &[43u8; 32]))
                .await
                .unwrap_err()
        );
        assert!(err.contains("wrong config secret"), "{err}");
        assert!(err.contains(TEST_ID), "{err}");
    }

    #[tokio::test]
    async fn a_value_that_is_not_a_config_secret_fails_before_any_decryption() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let sealed = seal(&[42u8; 32], TEST_ID, 1, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&format!("mcpg+enc:{}/c/{TEST_ID}#k=hunter2", server.uri()))
                .await
                .unwrap_err()
        );
        assert!(err.contains("malformed encrypted config"), "{err}");
        assert!(!err.contains("wrong config secret"), "{err}");
    }

    /// The host holds the ciphertext and could answer one address with another
    /// config's genuinely authentic payload. The id the tag is built from comes
    /// from the address, so the substitution fails authentication instead of
    /// booting the wrong configuration under the right audit label.
    #[tokio::test]
    async fn a_payload_sealed_for_another_config_does_not_open_at_this_address() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        let sealed = seal(&secret, OTHER_ID, 1, far_future(), SAMPLE_YAML);
        let server = serve_payload_as(TEST_ID, OTHER_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&spec(&server, TEST_ID, &secret)).await.unwrap_err()
        );
        // Caught by the AAD disagreement before the AEAD pass; either way the
        // layer is refused rather than loaded.
        assert!(err.contains("different construction") || err.contains("wrong config secret"));
        assert!(err.contains(TEST_ID), "{err}");
    }

    #[tokio::test]
    async fn an_expired_payload_is_refused_after_decryption() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        // Authenticated expiry in the past: the tag verifies, the layer is
        // still refused.
        let sealed = seal(&secret, TEST_ID, 1, 1_700_000_000, SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&spec(&server, TEST_ID, &secret)).await.unwrap_err()
        );
        assert!(err.contains("expired at unix 1700000000"), "{err}");
    }

    /// The host could rewrite the metadata beside the ciphertext. Every one of
    /// those values is inside the tag, so rewriting one breaks authentication
    /// rather than quietly changing the terms of a config it cannot read.
    #[tokio::test]
    async fn rewriting_an_authenticated_parameter_breaks_authentication() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        let real = far_future();
        let sealed = seal(&secret, TEST_ID, 3, real, SAMPLE_YAML);

        // Expiry pushed out by a year, version rewound, one-time flag flipped,
        // salt swapped for one the host chose.
        for (name, lie) in [
            ("x-mcpg-expires-at", (real + 31_536_000).to_string()),
            ("x-mcpg-version", "2".to_owned()),
            ("x-mcpg-one-time", "true".to_owned()),
            ("x-mcpg-kdf-salt", B64.encode([3u8; 16])),
        ] {
            let mut headers = vec![
                ("x-mcpg-nonce", B64.encode(sealed.nonce)),
                ("x-mcpg-kdf", "hkdf-sha256".to_owned()),
                ("x-mcpg-kdf-salt", B64.encode(sealed.salt)),
                ("x-mcpg-expires-at", real.to_string()),
                ("x-mcpg-one-time", "false".to_owned()),
                ("x-mcpg-version", "3".to_owned()),
            ];
            for h in &mut headers {
                if h.0 == name {
                    h.1 = lie.clone();
                }
            }
            // No `x-mcpg-aad`: a host rewriting a parameter would rewrite that
            // string too, so the test exercises the tag rather than the
            // consistency check in front of it.
            let mut template = ResponseTemplate::new(200)
                .set_body_raw(sealed.ciphertext.clone(), "application/octet-stream");
            for (k, v) in &headers {
                template = template.append_header(*k, v.as_str());
            }
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/configs/{TEST_ID}/ciphertext")))
                .respond_with(template)
                .mount(&server)
                .await;

            let err = format!(
                "{:#}",
                resolve(&spec(&server, TEST_ID, &secret)).await.unwrap_err()
            );
            assert!(
                err.contains("wrong config secret"),
                "rewriting {name} was not caught: {err}"
            );
        }
    }

    #[tokio::test]
    async fn a_burned_config_gets_its_own_message() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let server = serve_status(
            TEST_ID,
            410,
            serde_json::json!({ "error": "burned", "id": TEST_ID }),
        )
        .await;

        let err = format!(
            "{:#}",
            resolve(&format!("mcpg+enc:{}/c/{TEST_ID}", server.uri()))
                .await
                .unwrap_err()
        );
        assert!(err.contains("was burned"), "{err}");
        assert!(!err.contains("has expired"), "{err}");
    }

    #[tokio::test]
    async fn a_server_expired_config_is_distinct_from_burned() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let server = serve_status(
            TEST_ID,
            410,
            serde_json::json!({ "error": "expired", "id": TEST_ID }),
        )
        .await;

        let err = format!(
            "{:#}",
            resolve(&format!("mcpg+enc:{}/c/{TEST_ID}", server.uri()))
                .await
                .unwrap_err()
        );
        assert!(err.contains("has expired"), "{err}");
        assert!(!err.contains("burned"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_secret_names_the_id_and_every_way_to_supply_one() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let sealed = seal(&[42u8; 32], TEST_ID, 1, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&format!("mcpg+enc:{}/c/{TEST_ID}", server.uri()))
                .await
                .unwrap_err()
        );
        assert!(err.contains(TEST_ID), "{err}");
        for var in [
            encrypted::SECRET_FILE_ENV,
            encrypted::SECRET_ENV,
            encrypted::SECRETS_FILE_ENV,
        ] {
            assert!(err.contains(var), "{err}");
        }
    }

    #[tokio::test]
    async fn the_version_floor_refuses_an_older_authentic_payload() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        // SAFETY: the ENV_LOCK guard serialises every test in this module that
        // reads or writes the process environment.
        unsafe {
            std::env::set_var(encrypted::MIN_VERSION_ENV, "7");
        }
        let secret = [42u8; 32];
        let sealed = seal(&secret, TEST_ID, 5, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;

        let err = format!(
            "{:#}",
            resolve(&spec(&server, TEST_ID, &secret)).await.unwrap_err()
        );
        // SAFETY: as above.
        unsafe {
            std::env::remove_var(encrypted::MIN_VERSION_ENV);
        }
        assert!(err.contains("below the"), "{err}");
        assert!(err.contains("version 5"), "{err}");
    }

    /// A pinned address is only pinned if the answer is checked. The service
    /// enforces the pin too; this is the half that does not depend on it.
    #[tokio::test]
    async fn a_pinned_address_refuses_a_different_version() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        let sealed = seal(&secret, TEST_ID, 2, far_future(), SAMPLE_YAML);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/configs/{TEST_ID}/versions/7/ciphertext")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(sealed.ciphertext.clone(), "application/octet-stream")
                    .append_header("x-mcpg-nonce", B64.encode(sealed.nonce).as_str())
                    .append_header("x-mcpg-kdf", "hkdf-sha256")
                    .append_header("x-mcpg-kdf-salt", B64.encode(sealed.salt).as_str())
                    .append_header("x-mcpg-expires-at", sealed.expires_at.to_string().as_str())
                    .append_header("x-mcpg-one-time", "false")
                    .append_header("x-mcpg-version", "2"),
            )
            .mount(&server)
            .await;

        let err = format!(
            "{:#}",
            resolve(&format!(
                "mcpg+enc:{}/c/{TEST_ID}/v/7#k={}",
                server.uri(),
                secret_text(&secret)
            ))
            .await
            .unwrap_err()
        );
        assert!(err.contains("version 7"), "{err}");
        assert!(err.contains("version 2"), "{err}");
    }

    /// The gateway asks for the raw form so a config does not make a base64
    /// round trip into a boot.
    #[tokio::test]
    async fn the_payload_route_is_addressed_with_an_octet_stream_accept() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let secret = [42u8; 32];
        let sealed = seal(&secret, TEST_ID, 1, far_future(), SAMPLE_YAML);
        let server = serve_payload(TEST_ID, &sealed).await;
        resolve(&spec(&server, TEST_ID, &secret)).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            format!("/v1/configs/{TEST_ID}/ciphertext")
        );
        assert_eq!(requests[0].headers["accept"], "application/octet-stream");
    }

    #[tokio::test]
    async fn an_address_that_names_no_config_is_refused_without_a_fetch() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let err = format!(
            "{:#}",
            resolve("mcpg+enc:https://config.mcpg.cloud/downloads")
                .await
                .unwrap_err()
        );
        assert!(err.contains("not a config address"), "{err}");
    }

    #[tokio::test]
    async fn plaintext_yaml_over_http_is_unchanged() {
        let _env = ENV_LOCK.lock().await;
        allow_insecure_http();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gw.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(SAMPLE_YAML, "application/yaml"))
            .mount(&server)
            .await;
        let url = format!("{}/gw.yaml", server.uri());

        match resolve(&url).await.unwrap() {
            ConfigSource::Inline { origin, yaml } => {
                assert_eq!(yaml, SAMPLE_YAML);
                assert_eq!(origin, url);
            }
            other => panic!("expected inline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bare_path_and_file_uri_are_file_sources() {
        assert!(
            matches!(resolve("gw.yaml").await.unwrap(), ConfigSource::File(p) if p.as_path() == std::path::Path::new("gw.yaml"))
        );
        assert!(
            matches!(resolve("file:///etc/mcpg/gw.yaml").await.unwrap(), ConfigSource::File(p) if p.as_path() == std::path::Path::new("/etc/mcpg/gw.yaml"))
        );
    }

    #[tokio::test]
    async fn base64_prefix_decodes_inline() {
        let b64 = base64::engine::general_purpose::STANDARD
            .encode("gateway:\n  server:\n    bind_address: \"127.0.0.1:9000\"\n");
        let src = resolve(&format!("base64:{b64}")).await.unwrap();
        match src {
            ConfigSource::Inline { yaml, origin } => {
                assert!(yaml.contains("bind_address"));
                assert!(origin.starts_with("base64:<"));
            }
            other => panic!("expected inline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn data_uri_requires_base64_marker() {
        let b64 = base64::engine::general_purpose::STANDARD.encode("gateway: {}\n");
        let ok = resolve(&format!("data:application/yaml;base64,{b64}"))
            .await
            .unwrap();
        assert!(matches!(ok, ConfigSource::Inline { .. }));
        // Non-base64 data URI is rejected (ambiguous body).
        assert!(resolve("data:application/yaml,gateway: {}").await.is_err());
    }

    #[tokio::test]
    async fn invalid_base64_is_a_clear_error() {
        let err = resolve("base64:not valid base64 %%%").await.unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    #[tokio::test]
    async fn plaintext_http_is_refused_without_the_optin() {
        let _env = ENV_LOCK.lock().await;
        // SAFETY: the ENV_LOCK guard serialises every test in this module that
        // reads or writes this variable.
        unsafe {
            std::env::remove_var(ALLOW_INSECURE_ENV);
        }
        let err = resolve("http://config.internal/gw.yaml").await.unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
        // The encrypted scheme goes through the same guard.
        let err = format!(
            "{:#}",
            resolve(&format!("mcpg+enc:http://config.internal/c/{TEST_ID}"))
                .await
                .unwrap_err()
        );
        assert!(err.contains("http://"), "{err}");
    }

    #[tokio::test]
    async fn empty_source_is_rejected() {
        assert!(resolve("   ").await.is_err());
    }
}
