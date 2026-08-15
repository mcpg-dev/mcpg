//! HTTP client for the MCP Registry API (the generic `/v0.1` OpenAPI
//! the official registry and enterprise sub-registries implement).
//!
//! Read-only consumer: cursor-paginated `GET /v0.1/servers` filtered to
//! latest versions, plus single-version fetches for pinned servers.
//! Deserialization is deliberately tolerant (no `deny_unknown_fields`)
//! — registries inject their own `_meta` extensions and the schema
//! grows without a version bump.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::config::registry::{McpRegistryConfig, RegistryAuthMode};
use crate::runtime::safe_dns;

/// Per-request timeout against the registry.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on a single registry response body.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
/// Page size requested from the registry (spec ceiling is typically 100).
const PAGE_LIMIT: u32 = 100;
/// Hard stop on pagination, over and above the configured server cap —
/// a registry that never terminates its cursor cannot wedge the syncer.
const MAX_PAGES: u32 = 200;

/// Failure modes of a registry crawl.
#[derive(Debug)]
pub(crate) enum RegistryError {
    Connect(String),
    Transport(String),
    Http { status: u16 },
    Protocol(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "registry connect error: {m}"),
            Self::Transport(m) => write!(f, "registry transport error: {m}"),
            Self::Http { status } => write!(f, "registry returned HTTP {status}"),
            Self::Protocol(m) => write!(f, "registry protocol error: {m}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// One registry server entry (the `{ server, _meta }` list envelope,
/// flattened to what federation synthesis needs).
#[derive(Debug, Clone)]
pub(crate) struct RegistryEntry {
    pub server: ServerJson,
    /// Lifecycle from `_meta["io.modelcontextprotocol.registry/official"]`;
    /// `active` + latest when the registry omits the block.
    pub status: EntryStatus,
    pub is_latest: bool,
    /// The registry's `updatedAt` timestamp (RFC 3339), when published.
    /// Drives the incremental-crawl watermark; status flips (including
    /// deletion) bump it.
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryStatus {
    Active,
    Deprecated,
    Deleted,
}

/// The `server.json` subset the syncer consumes. Descriptive fields
/// beyond what mapping needs are kept for the status/debug surfaces.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct ServerJson {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub remotes: Vec<RemoteJson>,
    #[serde(default)]
    pub packages: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteJson {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<InputJson>,
    #[serde(default)]
    pub variables: BTreeMap<String, InputJson>,
}

/// The registry schema's Input / KeyValueInput shape (headers carry
/// `name`; URL variables are keyed by the map).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct InputJson {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub is_required: bool,
    #[serde(default)]
    pub is_secret: bool,
}

impl InputJson {
    /// The registry-provided value, if any (explicit value wins over
    /// the declared default).
    pub(crate) fn provided(&self) -> Option<&str> {
        self.value.as_deref().or(self.default.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    servers: Vec<EntryEnvelope>,
    #[serde(default)]
    metadata: Option<ListMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMetadata {
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EntryEnvelope {
    server: ServerJson,
    #[serde(default, rename = "_meta")]
    meta: Value,
}

const OFFICIAL_META_KEY: &str = "io.modelcontextprotocol.registry/official";

impl EntryEnvelope {
    fn into_entry(self) -> RegistryEntry {
        let official = self.meta.get(OFFICIAL_META_KEY);
        let status = match official
            .and_then(|o| o.get("status"))
            .and_then(Value::as_str)
        {
            Some("deprecated") => EntryStatus::Deprecated,
            Some("deleted") => EntryStatus::Deleted,
            _ => EntryStatus::Active,
        };
        let is_latest = official
            .and_then(|o| o.get("isLatest"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let updated_at = official
            .and_then(|o| o.get("updatedAt"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        RegistryEntry {
            server: self.server,
            status,
            is_latest,
            updated_at,
        }
    }
}

pub(crate) struct RegistryClient {
    base: String,
    client: reqwest::Client,
    bearer: Option<String>,
    headers: BTreeMap<String, String>,
}

impl RegistryClient {
    /// Build a guarded client for one registry: resolve the host, refuse
    /// private/loopback addresses unless opted in, and pin the vetted
    /// address so a DNS rebind between checks cannot redirect the crawl.
    /// `cred_bearer` is the issuer-minted token consumed by auth mode
    /// `cred` (resolved by the syncer per crawl so refresh follows the
    /// issuer's TTL).
    pub(crate) async fn connect(
        config: &McpRegistryConfig,
        cred_bearer: Option<String>,
    ) -> Result<Self, RegistryError> {
        let url = url::Url::parse(&config.url)
            .map_err(|e| RegistryError::Connect(format!("invalid url '{}': {e}", config.url)))?;
        let host = url
            .host_str()
            .ok_or_else(|| RegistryError::Connect("url has no host".to_owned()))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| RegistryError::Connect("url has no known port".to_owned()))?;
        let addrs = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| {
                RegistryError::Connect(format!("DNS resolution failed for {host}: {e}"))
            })?;
        let mut chosen = None;
        for addr in addrs {
            if config.registry_safety.allow_private_registry
                || !safe_dns::is_private_address(&addr.ip())
            {
                chosen = Some(addr);
                break;
            }
        }
        let resolved = chosen.ok_or_else(|| {
            RegistryError::Connect(format!(
                "registry host '{host}' resolved only to private/loopback addresses; \
                 set registry_safety.allow_private_registry: true to permit it"
            ))
        })?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .resolve(&host, resolved)
            // The address pin binds only this host, and the crawl carries the
            // operator's registry credentials — a redirect would re-resolve a
            // registry-chosen host and forward those headers to it.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RegistryError::Connect(format!("client build failed: {e}")))?;
        let (bearer, headers) = match config.auth.mode {
            RegistryAuthMode::None => (None, BTreeMap::new()),
            RegistryAuthMode::Bearer => (config.auth.token.clone(), BTreeMap::new()),
            RegistryAuthMode::Headers => (None, config.auth.headers.clone()),
            RegistryAuthMode::Cred => (cred_bearer, BTreeMap::new()),
        };
        Ok(Self {
            base: config.url.trim_end_matches('/').to_owned(),
            client,
            bearer,
            headers,
        })
    }

    /// Crawl the registry's latest server versions in full, including
    /// tombstones (`include_deleted=true`) so removals are observed on
    /// every sync without a separate backstop.
    pub(crate) async fn list_latest(&self) -> Result<Vec<RegistryEntry>, RegistryError> {
        self.list(None).await
    }

    /// Crawl only entries updated since `watermark` (RFC 3339). Status
    /// flips bump `updatedAt`, so tombstones appear in the delta too.
    pub(crate) async fn list_since(
        &self,
        watermark: &str,
    ) -> Result<Vec<RegistryEntry>, RegistryError> {
        self.list(Some(watermark)).await
    }

    async fn list(&self, updated_since: Option<&str>) -> Result<Vec<RegistryEntry>, RegistryError> {
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        for _page in 0..MAX_PAGES {
            let mut url = format!(
                "{}/v0.1/servers?limit={PAGE_LIMIT}&version=latest&include_deleted=true",
                self.base
            );
            if let Some(since) = updated_since {
                url.push_str("&updated_since=");
                url.push_str(&urlencoding_encode(since));
            }
            if let Some(c) = &cursor {
                url.push_str("&cursor=");
                url.push_str(&urlencoding_encode(c));
            }
            let body: ListResponse = self.get_json(&url).await?;
            entries.extend(body.servers.into_iter().map(EntryEnvelope::into_entry));
            cursor = body
                .metadata
                .and_then(|m| m.next_cursor)
                .filter(|c| !c.is_empty());
            if cursor.is_none() {
                return Ok(entries);
            }
        }
        Err(RegistryError::Protocol(format!(
            "cursor pagination did not terminate within {MAX_PAGES} pages"
        )))
    }

    /// Fetch one pinned server version.
    pub(crate) async fn get_version(
        &self,
        server_name: &str,
        version: &str,
    ) -> Result<RegistryEntry, RegistryError> {
        let url = format!(
            "{}/v0.1/servers/{}/versions/{}",
            self.base,
            urlencoding_encode(server_name),
            urlencoding_encode(version)
        );
        let envelope: EntryEnvelope = self.get_json(&url).await?;
        Ok(envelope.into_entry())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, RegistryError> {
        let mut req = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");
        for (name, value) in &self.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(token) = &self.bearer {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RegistryError::Transport(format!("request to {url} failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(RegistryError::Http {
                status: status.as_u16(),
            });
        }
        // Streamed with the cap applied per chunk. Buffering the whole body
        // and checking its length afterwards means the allocation has already
        // happened — the limit only reported the overrun, it never prevented
        // it, and the body size is the remote registry's choice.
        let mut bytes = bytes::BytesMut::new();
        let mut stream = resp.bytes_stream();
        let mut overflowed = false;
        while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
            let chunk =
                chunk.map_err(|e| RegistryError::Transport(format!("body read failed: {e}")))?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                overflowed = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        let bytes = bytes.freeze();
        if overflowed {
            return Err(RegistryError::Protocol(format!(
                "response exceeded {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| RegistryError::Protocol(format!("invalid registry response: {e}")))
    }
}

/// Percent-encode a path/query component (server names contain `/`;
/// cursors are opaque).
fn urlencoding_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_v01_list_envelope() {
        let body = r#"{
          "servers": [
            {
              "server": {
                "name": "com.acme/crm",
                "description": "CRM tools",
                "version": "2.3.1",
                "remotes": [{
                  "type": "streamable-http",
                  "url": "https://{tenant}.crm.acme.example/mcp",
                  "variables": { "tenant": { "description": "Tenant", "isRequired": true } },
                  "headers": [{ "name": "X-API-Key", "isRequired": true, "isSecret": true }]
                }]
              },
              "_meta": {
                "io.modelcontextprotocol.registry/official": {
                  "status": "active", "isLatest": true,
                  "publishedAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-07-01T00:00:00Z"
                }
              }
            },
            {
              "server": {
                "name": "com.acme/legacy",
                "description": "gone",
                "version": "0.9.0",
                "packages": [{ "registryType": "npm", "identifier": "acme-legacy" }]
              },
              "_meta": {
                "io.modelcontextprotocol.registry/official": { "status": "deleted", "isLatest": true }
              }
            }
          ],
          "metadata": { "count": 2 }
        }"#;
        let parsed: ListResponse = serde_json::from_str(body).expect("parse");
        let entries: Vec<RegistryEntry> = parsed
            .servers
            .into_iter()
            .map(EntryEnvelope::into_entry)
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].server.name, "com.acme/crm");
        assert_eq!(entries[0].status, EntryStatus::Active);
        assert!(entries[0].is_latest);
        let remote = &entries[0].server.remotes[0];
        assert_eq!(remote.kind, "streamable-http");
        assert!(remote.variables["tenant"].is_required);
        assert_eq!(remote.headers[0].name.as_deref(), Some("X-API-Key"));
        assert!(remote.headers[0].is_secret);
        assert_eq!(entries[1].status, EntryStatus::Deleted);
        assert!(entries[1].server.remotes.is_empty());
        assert_eq!(entries[1].server.packages.len(), 1);
    }

    #[test]
    fn missing_official_meta_defaults_to_active_latest() {
        let body = r#"{ "servers": [ { "server": { "name": "com.a/b", "version": "1.0.0" } } ] }"#;
        let parsed: ListResponse = serde_json::from_str(body).expect("parse");
        let entry = parsed.servers.into_iter().next().unwrap().into_entry();
        assert_eq!(entry.status, EntryStatus::Active);
        assert!(entry.is_latest);
    }

    #[test]
    fn percent_encoding_covers_names_and_cursors() {
        assert_eq!(urlencoding_encode("com.acme/crm"), "com.acme%2Fcrm");
        assert_eq!(urlencoding_encode("a b:1.0.0"), "a%20b%3A1.0.0");
    }
}
