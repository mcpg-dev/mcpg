//! Config sources for `--config`. A gateway config layer can come from more
//! than a local file: a `--config` value is resolved into a [`ConfigSource`]
//! that is either a local file (re-read on hot-reload) or an in-memory YAML
//! snapshot fetched from a remote `https://` URL or decoded from inline
//! base64 — so a gateway can boot from a config it never writes to disk.
//!
//! Layers merge in the order given, later winning, exactly like a
//! path-separator-joined `MCPG_CONFIG` list; `--config` layers apply after the
//! `MCPG_CONFIG` files.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;

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
/// - `https://…` (or `http://…` with [`ALLOW_INSECURE_ENV`]) → fetched now
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

async fn fetch_remote(url: &str) -> Result<ConfigSource> {
    let insecure_ok = std::env::var(ALLOW_INSECURE_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if url.starts_with("http://") && !insecure_ok {
        bail!(
            "refusing to fetch config over plaintext http:// ({url}): a network attacker can \
             rewrite the gateway's config. Use https://, or set {ALLOW_INSECURE_ENV}=1 to override."
        );
    }
    let client = reqwest::Client::builder()
        .timeout(REMOTE_CONFIG_TIMEOUT)
        .build()
        .context("build config-fetch HTTP client")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetch config from {url}"))?;
    if !resp.status().is_success() {
        bail!("fetch config from {url}: HTTP {}", resp.status());
    }
    // Reject an over-cap body up front when the server declares its length…
    if let Some(len) = resp.content_length()
        && len > MAX_REMOTE_CONFIG_BYTES
    {
        bail!("remote config {url} is {len} bytes, over the {MAX_REMOTE_CONFIG_BYTES}-byte cap");
    }
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read config body from {url}"))?;
    // …and re-check after reading, for chunked responses with no declared length.
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // SAFETY: single-threaded test; no other thread reads this var here.
        unsafe {
            std::env::remove_var(ALLOW_INSECURE_ENV);
        }
        let err = resolve("http://config.internal/gw.yaml").await.unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
    }

    #[tokio::test]
    async fn empty_source_is_rejected() {
        assert!(resolve("   ").await.is_err());
    }
}
