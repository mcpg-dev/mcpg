//! `mcp.registries:` — MCP registries whose servers MCPG auto-federates.
//!
//! A registry entry points at an MCP Registry API endpoint (the generic
//! `/v0.1` OpenAPI the official registry and enterprise sub-registries
//! implement). A background syncer crawls it, synthesizes one
//! `mcp.federations[]` entry per usable server, and keeps the set in
//! sync as servers are added, updated, deprecated, and deleted. The
//! registry decides *which* servers exist; this config decides *how
//! much* they are trusted — the gateway's default-deny rails
//! (no stdio, no insecure HTTP, SSRF guard) are not overridable from
//! registry data.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::backend::BackendGovernanceConfig;
use super::federation::{AuthConfig, FederationCacheConfig, ImportConfig, SynthesizeConfig};

/// One MCP registry to auto-federate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpRegistryConfig {
    /// Registry id. Prefixes every synthesized federation name
    /// (`<registry>--<server>`), so it must be stable and unique.
    /// Lowercase alphanumeric + `-`.
    pub name: String,

    /// Registry base URL; the syncer appends the standard API paths
    /// (`/v0.1/servers`, …).
    pub url: String,

    /// How MCPG authenticates to the registry (consumer side).
    #[serde(default)]
    pub auth: RegistryAuthConfig,

    /// Network posture for the REGISTRY endpoint itself. Distinct from
    /// the per-server `defaults.upstream_safety`: a private registry URL
    /// is normal for enterprises, but stays an explicit opt-in.
    #[serde(default)]
    pub registry_safety: RegistrySafetyConfig,

    /// Sync cadence + size bounds.
    #[serde(default)]
    pub sync: RegistrySyncConfig,

    /// Which registry servers are eligible for federation.
    #[serde(default)]
    pub filter: RegistryFilterConfig,

    /// What happens to servers the registry marks `deprecated`.
    /// (`deleted` servers are always removed.)
    #[serde(default)]
    pub on_deprecated: OnDeprecated,

    /// Applied to every synthesized federation.
    #[serde(default)]
    pub defaults: RegistryDefaultsConfig,

    /// Per-server overrides, keyed by the server's registry name
    /// (e.g. `com.acme/crm`).
    #[serde(default)]
    pub servers: BTreeMap<String, RegistryServerOverride>,
}

impl McpRegistryConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let path = format!("mcp.registries[{}]", self.name);
        if self.name.trim().is_empty() {
            bail!("mcp.registries[]: every registry needs a non-empty `name`");
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            bail!("{path}: `name` must be lowercase alphanumeric + '-'");
        }
        let is_https = self.url.starts_with("https://");
        let is_http = self.url.starts_with("http://");
        if !is_https && !is_http {
            bail!("{path}.url must be an http(s) URL");
        }
        if is_http && !self.registry_safety.allow_insecure_http {
            bail!(
                "{path}.url uses http://; set registry_safety.allow_insecure_http: true to permit it"
            );
        }
        self.auth.validate(&path)?;
        if self.sync.interval_secs < 30 {
            bail!("{path}.sync.interval_secs must be at least 30");
        }
        crate::config::require_positive(&path, "sync.max_servers", self.sync.max_servers)?;
        crate::config::require_positive(
            &path,
            "sync.full_resync_hours",
            self.sync.full_resync_hours,
        )?;
        self.defaults.validate(&path)?;
        crate::config::require_positive(
            &path,
            "defaults.cache.capability_ttl_secs",
            self.defaults.cache.capability_ttl_secs,
        )?;
        crate::config::require_positive(
            &path,
            "defaults.synthesize.poll_interval_ms",
            self.defaults.synthesize.poll_interval_ms,
        )?;
        for (server, over) in &self.servers {
            if server.trim().is_empty() {
                bail!("{path}.servers: server keys must be non-empty registry names");
            }
            if let Some(auth) = &over.auth {
                auth.validate(&format!("{path}.servers[{server}]"))?;
            }
        }
        Ok(())
    }
}

/// Consumer auth presented to the registry API.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryAuthConfig {
    #[serde(default)]
    pub mode: RegistryAuthMode,
    /// Bearer token for `bearer` (supports `${env.X}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Arbitrary request headers for `headers` (e.g. `X-API-Key`);
    /// values support `${env.X}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Credential-issuer reference for `cred`: a standard
    /// `cred://<plugin_id>/<target>` URI. The issuer mints + refreshes
    /// the registry bearer under the gateway's machine identity; no
    /// static token lives in the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl RegistryAuthConfig {
    fn validate(&self, path: &str) -> Result<()> {
        match self.mode {
            RegistryAuthMode::None => {}
            RegistryAuthMode::Bearer => {
                if self.token.as_deref().unwrap_or("").is_empty() {
                    bail!("{path}.auth: mode `bearer` requires a non-empty `token`");
                }
            }
            RegistryAuthMode::Headers => {
                if self.headers.is_empty() {
                    bail!("{path}.auth: mode `headers` requires at least one header");
                }
            }
            RegistryAuthMode::Cred => {
                let cred = self.credential.as_deref().unwrap_or("");
                if !cred.starts_with("cred://")
                    || cred
                        .strip_prefix("cred://")
                        .and_then(|r| r.split_once('/'))
                        .is_none()
                {
                    bail!(
                        "{path}.auth: mode `cred` requires `credential` as a \
                         cred://<plugin_id>/<target> URI"
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAuthMode {
    /// Anonymous reads (the generic spec's default).
    #[default]
    None,
    /// `Authorization: Bearer <token>`.
    Bearer,
    /// Arbitrary static headers (API-key style sub-registries).
    Headers,
    /// Bearer minted by a credential-issuer plugin (`credential` is a
    /// `cred://` URI) under the gateway's machine identity.
    Cred,
}

/// Network posture for the registry endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrySafetyConfig {
    /// Permit a private / loopback registry address (normal for
    /// enterprise sub-registries; still an explicit opt-in).
    #[serde(default)]
    pub allow_private_registry: bool,
    /// Permit `http://` (non-TLS) registry endpoints.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

/// Sync cadence + bounds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrySyncConfig {
    /// Seconds between crawls. Each crawl lists the registry's latest
    /// server versions in full (cursor-paginated), so deletions are
    /// observed without a separate backstop. Floor 30.
    #[serde(default = "default_sync_interval_secs")]
    pub interval_secs: u64,
    /// Hard cap on federated servers from this registry. Servers beyond
    /// the cap (name-sorted) are skipped and reported — back-pressure
    /// against unbounded task/connection growth.
    #[serde(default = "default_max_servers")]
    pub max_servers: u64,
    /// Crawl with `updated_since=<watermark>` between periodic full
    /// crawls instead of listing everything each tick. Status flips
    /// (including deletions) bump `updatedAt`, so deltas carry
    /// tombstones too; the periodic full crawl is the backstop for
    /// anything missed. Engages only once the registry has yielded
    /// `updatedAt` timestamps.
    #[serde(default)]
    pub incremental: bool,
    /// Hours between full crawls when `incremental` is on. Floor 1.
    #[serde(default = "default_full_resync_hours")]
    pub full_resync_hours: u64,
}

impl Default for RegistrySyncConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_sync_interval_secs(),
            max_servers: default_max_servers(),
            incremental: false,
            full_resync_hours: default_full_resync_hours(),
        }
    }
}

/// Which registry servers are eligible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryFilterConfig {
    /// Server-name globs to include (exact or trailing-`*`).
    #[serde(default = "default_include_all")]
    pub include: Vec<String>,
    /// Server-name globs to exclude (exclude wins).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Publisher-namespace allowlist (the part before `/`, e.g.
    /// `com.acme`). Empty = all namespaces. The anti-typosquatting rail:
    /// registry namespace ownership is publisher-verified, so pinning
    /// namespaces pins trust.
    #[serde(default)]
    pub namespaces: Vec<String>,
}

impl Default for RegistryFilterConfig {
    fn default() -> Self {
        Self {
            include: default_include_all(),
            exclude: Vec::new(),
            namespaces: Vec::new(),
        }
    }
}

/// Policy for `deprecated` servers.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OnDeprecated {
    /// Keep federating; log + count the deprecation.
    #[default]
    ServeAndWarn,
    /// Drop the federation (clients see `list_changed`).
    Exclude,
}

/// Defaults applied to every synthesized federation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryDefaultsConfig {
    /// Governance inherited by every synthesized federation (trust
    /// floor + CEL), exactly like a hand-written federation's block.
    #[serde(default)]
    pub governance: BackendGovernanceConfig,
    /// Surfaces to import. Defaults to everything — the point of
    /// auto-federation is the full surface; narrow it here if not.
    #[serde(default = "default_registry_import")]
    pub import: ImportConfig,
    /// Per-server upstream network posture. Only
    /// `allow_private_backends` is honored — stdio and insecure HTTP
    /// stay denied for registry-driven servers regardless.
    #[serde(default)]
    pub upstream_safety: RegistryUpstreamSafetyConfig,
    /// Upstream auth for synthesized federations (same modes as a
    /// hand-written federation; per-server `servers.<name>.auth`
    /// overrides win).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Change-notification synthesis for push-less servers.
    #[serde(default)]
    pub synthesize: SynthesizeConfig,
    /// Capability-cache TTL refresh.
    #[serde(default)]
    pub cache: FederationCacheConfig,
    /// Sync-time OAuth discovery (RFC 9728 protected-resource metadata
    /// → RFC 8414 AS metadata) for synthesized federations whose auth
    /// uses an OAuth credential mode: derives each server's audience +
    /// token endpoint and injects them as the issuer's per-call config
    /// (`auth.credential_config`). Off by default.
    #[serde(default)]
    pub oauth_discovery: RegistryOauthDiscoveryConfig,
}

impl Default for RegistryDefaultsConfig {
    fn default() -> Self {
        Self {
            governance: Default::default(),
            import: default_registry_import(),
            upstream_safety: Default::default(),
            auth: Default::default(),
            synthesize: Default::default(),
            cache: Default::default(),
            oauth_discovery: Default::default(),
        }
    }
}

/// `mcp.registry:` — serve a v0.1 MCP-Registry view of this
/// gateway. The catalog exposed is exactly one server entry: the
/// gateway itself (its whole governed surface hangs off one MCP
/// endpoint), so pointing a registry-driven client policy here yields
/// "the approved server is MCPG".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServedRegistryConfig {
    /// Serve `GET /v0.1/servers` (+ per-version fetches). Default off.
    #[serde(default)]
    pub enabled: bool,
    /// Published server name, reverse-DNS namespaced
    /// (`com.acme/gateway`). Required when enabled.
    #[serde(default)]
    pub name: String,
    /// Human description shown by registry clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Canonical external MCP endpoint published in the entry's
    /// `remotes[]`. Defaults to
    /// `governance.access.resource_metadata.resource` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl ServedRegistryConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let (namespace, name) = self.name.split_once('/').ok_or_else(|| {
            anyhow::anyhow!(
                "mcp.registry.name must be reverse-DNS namespaced \
                     (`<namespace>/<name>`, e.g. `com.acme/gateway`)"
            )
        })?;
        if namespace.trim().is_empty() || name.trim().is_empty() {
            bail!("mcp.registry.name must be `<namespace>/<name>` with both parts non-empty");
        }
        if let Some(url) = self.url.as_deref()
            && !url.starts_with("https://")
            && !url.starts_with("http://")
        {
            bail!("mcp.registry.url must be an http(s) URL");
        }
        Ok(())
    }
}

/// Sync-time OAuth discovery for registry servers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryOauthDiscoveryConfig {
    /// Fetch each OAuth-mode server's RFC 9728 + RFC 8414 metadata at
    /// sync time. Servers whose discovery fails (and that have no prior
    /// discovered snapshot) are skipped — a server that cannot be
    /// authenticated against would only fail at dispatch.
    #[serde(default)]
    pub enabled: bool,
}

impl RegistryDefaultsConfig {
    fn validate(&self, path: &str) -> Result<()> {
        self.import.validate(path)?;
        self.auth.validate(path)?;
        Ok(())
    }
}

/// Upstream network posture defaults for synthesized federations.
/// Deliberately narrower than a hand-written federation's
/// `upstream_safety`: the registry chooses which servers exist, so the
/// dangerous knobs are not registry-reachable.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpstreamSafetyConfig {
    /// Permit private / loopback server addresses (internal remotes —
    /// the common enterprise case; still an explicit opt-in).
    #[serde(default)]
    pub allow_private_backends: bool,
}

/// Per-server override, keyed by registry server name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryServerOverride {
    /// Set false to exclude this server regardless of filters.
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Pin an exact registry version (default: track the registry's
    /// latest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Values for `{variable}` templates in the server's remote URL.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, String>,
    /// Values for the remote's declared request headers (secrets via
    /// `${env.X}`). Required-header declarations without a value here
    /// (or a registry-provided default) skip the server.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Upstream auth override for this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,
}

impl Default for RegistryServerOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            version: None,
            variables: BTreeMap::new(),
            headers: BTreeMap::new(),
            auth: None,
        }
    }
}

fn default_sync_interval_secs() -> u64 {
    300
}
fn default_max_servers() -> u64 {
    100
}
fn default_full_resync_hours() -> u64 {
    24
}
fn default_include_all() -> Vec<String> {
    vec!["*".to_owned()]
}
fn default_registry_import() -> ImportConfig {
    ImportConfig {
        tools: true,
        resources: true,
        resource_templates: true,
        prompts: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> McpRegistryConfig {
        serde_yaml::from_str(yaml).expect("parse registry config")
    }

    #[test]
    fn minimal_config_parses_and_validates() {
        let c = cfg(r#"
name: acme
url: "https://registry.acme.example"
"#);
        c.validate().expect("valid");
        assert_eq!(c.sync.interval_secs, 300);
        assert_eq!(c.sync.max_servers, 100);
        assert!(matches!(c.on_deprecated, OnDeprecated::ServeAndWarn));
        assert!(c.defaults.import.tools && c.defaults.import.resources);
        assert!(!c.registry_safety.allow_private_registry);
    }

    #[test]
    fn name_charset_and_url_scheme_enforced() {
        let bad_name = cfg(r#"
name: "Acme Registry"
url: "https://r.example"
"#);
        assert!(
            bad_name
                .validate()
                .unwrap_err()
                .to_string()
                .contains("lowercase")
        );

        let http = cfg(r#"
name: acme
url: "http://r.internal"
"#);
        assert!(
            http.validate()
                .unwrap_err()
                .to_string()
                .contains("allow_insecure_http")
        );

        let http_ok = cfg(r#"
name: acme
url: "http://r.internal"
registry_safety: { allow_insecure_http: true }
"#);
        http_ok.validate().expect("opted-in http valid");
    }

    #[test]
    fn auth_modes_validate() {
        let bearer_missing = cfg(r#"
name: acme
url: "https://r.example"
auth: { mode: bearer }
"#);
        assert!(bearer_missing.validate().is_err());

        let headers = cfg(r#"
name: acme
url: "https://r.example"
auth:
  mode: headers
  headers: { X-API-Key: "${env.KEY}" }
"#);
        headers.validate().expect("headers auth valid");

        let cred_missing = cfg(r#"
name: acme
url: "https://r.example"
auth: { mode: cred }
"#);
        assert!(
            cred_missing
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cred://")
        );

        let cred_bad_shape = cfg(r#"
name: acme
url: "https://r.example"
auth: { mode: cred, credential: "cred://no-target" }
"#);
        assert!(cred_bad_shape.validate().is_err());

        let cred_ok = cfg(r#"
name: acme
url: "https://r.example"
auth:
  mode: cred
  credential: "cred://dev.mcpg.credential.oauth-client-credentials/registry"
"#);
        cred_ok.validate().expect("cred auth valid");
    }

    #[test]
    fn interval_floor_and_cap_enforced() {
        let fast = cfg(r#"
name: acme
url: "https://r.example"
sync: { interval_secs: 5 }
"#);
        assert!(
            fast.validate()
                .unwrap_err()
                .to_string()
                .contains("at least 30")
        );

        let zero_cap = cfg(r#"
name: acme
url: "https://r.example"
sync: { max_servers: 0 }
"#);
        assert!(zero_cap.validate().is_err());
    }

    #[test]
    fn served_registry_validation() {
        // Disabled: no constraints.
        ServedRegistryConfig::default()
            .validate()
            .expect("disabled is valid");

        // Enabled requires a reverse-DNS name.
        let bad = ServedRegistryConfig {
            enabled: true,
            name: "gateway".into(),
            ..Default::default()
        };
        assert!(
            bad.validate()
                .unwrap_err()
                .to_string()
                .contains("reverse-DNS")
        );

        let ok = ServedRegistryConfig {
            enabled: true,
            name: "com.acme/gateway".into(),
            url: Some("https://gw.acme.example/mcp".into()),
            ..Default::default()
        };
        ok.validate().expect("valid surface");

        let bad_url = ServedRegistryConfig {
            enabled: true,
            name: "com.acme/gateway".into(),
            url: Some("ftp://gw.acme.example".into()),
            ..Default::default()
        };
        assert!(bad_url.validate().is_err());
    }

    #[test]
    fn server_overrides_parse() {
        let c = cfg(r#"
name: acme
url: "https://r.example"
servers:
  "com.acme/crm":
    version: "2.3.1"
    variables: { tenant_id: acme-prod }
    headers: { X-API-Key: "${env.CRM_KEY}" }
    auth: { mode: service_token, token: "${env.CRM_TOKEN}" }
  "com.acme/legacy":
    enabled: false
"#);
        c.validate().expect("valid");
        assert_eq!(c.servers["com.acme/crm"].version.as_deref(), Some("2.3.1"));
        assert!(!c.servers["com.acme/legacy"].enabled);
    }
}
