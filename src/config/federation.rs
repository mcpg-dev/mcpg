//! `mcp.federations:` — upstream MCP servers federated through this
//! gateway.
//!
//! A federation is a *capability source*: one entry connects to an
//! upstream MCP server, imports its capabilities, and re-serves them
//! under an operator prefix. This is deliberately NOT an
//! `mcp.capabilities.tools[]` entry (those are 1:1 — one entry = one
//! tool) and NOT a `backend: { kind: … }` variant (that is the
//! per-call execution discriminator).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::backend::{BackendGovernanceConfig, RetryConfig};

/// One federated upstream MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// Source id. Also the default capability-prefix namespace and the
    /// `federated_from` label on synthetic capabilities.
    pub name: String,

    /// Governance inherited by every capability imported from this
    /// upstream — identical block to a native binding's, so the gate
    /// chain treats a federated call exactly like a native one.
    #[serde(default)]
    pub governance: BackendGovernanceConfig,

    /// Per-call retry policy for upstream dispatch.
    #[serde(default)]
    pub retry: Option<RetryConfig>,

    /// Upstream connection (url, transport, auth, safety).
    pub upstream: UpstreamConfig,

    /// Which capability surfaces to import.
    #[serde(default)]
    pub import: ImportConfig,

    /// Prefixes applied to imported capability names / URIs.
    #[serde(default)]
    pub naming: NamingConfig,

    /// Allow/deny filtering of imported tool names.
    #[serde(default)]
    pub filter: FilterConfig,

    /// Capability-cache behaviour (TTL refresh).
    #[serde(default)]
    pub cache: FederationCacheConfig,

    /// Change-notification synthesis for upstreams that cannot push.
    #[serde(default)]
    pub synthesize: SynthesizeConfig,

    /// Upstream-session behaviour.
    #[serde(default)]
    pub session: SessionConfig,

    /// Per-call response limits enforced gateway-side.
    #[serde(default)]
    pub response: ResponseConfig,
}

impl FederationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let path = format!("mcp.federations[{}]", self.name);
        if self.name.trim().is_empty() {
            bail!("mcp.federations[]: every federation needs a non-empty `name`");
        }
        // `mcpg` is the gateway-owned `ui://mcpg/<id>` authority for
        // templated apps; a federation may not claim it or its `ui://`
        // resources would collide with authored apps.
        if self.name.trim().eq_ignore_ascii_case("mcpg") {
            bail!("{path}: federation name 'mcpg' is reserved for gateway-authored resources");
        }
        self.upstream.validate(&path)?;
        self.import.validate(&path)?;
        if let Some(retry) = &self.retry {
            retry.validate(&path)?;
        }
        crate::config::require_positive(
            &path,
            "cache.capability_ttl_secs",
            self.cache.capability_ttl_secs,
        )?;
        crate::config::require_positive(
            &path,
            "session.idle_timeout_secs",
            self.session.idle_timeout_secs,
        )?;
        crate::config::require_positive(
            &path,
            "synthesize.poll_interval_ms",
            self.synthesize.poll_interval_ms,
        )?;
        crate::config::require_positive(
            &path,
            "response.max_response_bytes",
            self.response.max_response_bytes,
        )?;
        Ok(())
    }

    /// The effective tool-name prefix (empty string when unset).
    #[must_use]
    pub fn tool_prefix(&self) -> &str {
        self.naming.tool_prefix.as_deref().unwrap_or("")
    }
}

/// Upstream connection details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Base MCP endpoint URL (the upstream's `/mcp`). Required for the
    /// `streamable_http` transport; unused (empty) for `stdio`.
    #[serde(default)]
    pub url: String,
    /// Wire transport.
    #[serde(default)]
    pub transport: UpstreamTransport,
    /// MCP wire revision MCPG speaks to this upstream as a client.
    ///
    /// Default `v2025_11_25` (the session-bound wire) keeps the
    /// federation client byte-identical to legacy traffic. Set
    /// `v2026_07_28` to speak the stateless modern client wire: no
    /// `initialize` handshake, no `Mcp-Session-Id`, per-request `_meta`
    /// identity, and the SEP-2243 `Mcp-Method` / `Mcp-Name` /
    /// `Mcp-Param-{Name}` routing headers. Only the `streamable_http`
    /// transport honors `v2026_07_28`.
    #[serde(default)]
    pub protocol_version: UpstreamProtocolVersion,
    /// Command to spawn for the `stdio` transport (ignored otherwise).
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments passed to the stdio `command`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment for the stdio `command`.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// How MCPG authenticates to the upstream.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Static request headers sent on every upstream call (API-key
    /// style upstreams, e.g. `X-API-Key`); values support `${env.X}`.
    /// Reserved protocol headers (`authorization`, `mcp-*`,
    /// `content-type`, `accept`) are rejected — auth goes through
    /// `auth`, the wire headers stay MCPG's.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// SSRF / DNS-rebinding posture (http) + local-exec posture (stdio).
    #[serde(default)]
    pub upstream_safety: UpstreamSafetyConfig,
}

impl UpstreamConfig {
    fn validate(&self, path: &str) -> Result<()> {
        match self.transport {
            UpstreamTransport::StreamableHttp => {
                if self.url.trim().is_empty() {
                    bail!("{path}.upstream.url must be set for the streamable_http transport");
                }
                let is_https = self.url.starts_with("https://");
                let is_http = self.url.starts_with("http://");
                // A `tunnel://<name>/<path>` reverse-federation URL reaches
                // a same-org private gateway through the relay's federation
                // ingress; it is resolved to an https ingress URL at connect time.
                let is_tunnel = self.url.starts_with("tunnel://");
                if !is_https && !is_http && !is_tunnel {
                    bail!("{path}.upstream.url must be an http(s) or tunnel:// URL");
                }
                if is_http && !self.upstream_safety.allow_insecure_http {
                    bail!(
                        "{path}.upstream.url uses http://; set upstream_safety.allow_insecure_http: true to permit it"
                    );
                }
                if is_tunnel {
                    let name = self
                        .url
                        .strip_prefix("tunnel://")
                        .unwrap_or_default()
                        .split('/')
                        .next()
                        .unwrap_or_default();
                    if name.trim().is_empty() {
                        bail!(
                            "{path}.upstream.url: a tunnel:// upstream needs a name (tunnel://<name>/<path>)"
                        );
                    }
                }
            }
            UpstreamTransport::Stdio => {
                if self.protocol_version.is_modern() {
                    bail!(
                        "{path}.upstream.protocol_version: `2026-07-28` is only supported on the streamable_http transport"
                    );
                }
                if self.command.as_deref().unwrap_or("").trim().is_empty() {
                    bail!("{path}.upstream.command must be set for the stdio transport");
                }
                // stdio spawns a local process — a different threat model than
                // the HTTP SSRF guard, so it is default-deny.
                if !self.upstream_safety.allow_stdio {
                    bail!(
                        "{path}.upstream: the stdio transport spawns a local process; set upstream_safety.allow_stdio: true to permit it"
                    );
                }
            }
        }
        self.auth.validate(path)?;
        for name in self.headers.keys() {
            let lower = name.to_ascii_lowercase();
            if lower == "authorization"
                || lower == "content-type"
                || lower == "accept"
                || lower.starts_with("mcp-")
            {
                bail!(
                    "{path}.upstream.headers: `{name}` is a reserved protocol header                      (use `auth` for credentials; the MCP wire headers are MCPG's)"
                );
            }
        }
        Ok(())
    }
}

/// MCP wire revision the federation client speaks to an upstream.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
pub enum UpstreamProtocolVersion {
    /// Detect the upstream's wire at connect time (the default): attempt
    /// the modern `server/discover`, and fall back to the legacy
    /// `initialize` handshake when the peer rejects it (the SEP-2575
    /// backward-compatibility probe). The detected wire is cached per
    /// federation for the engine's lifetime. Pin one of the dated
    /// revisions to skip probing. The `stdio` transport never probes
    /// (it is legacy-only).
    #[default]
    #[serde(rename = "auto")]
    Auto,
    /// Session-bound `2025-11-25` wire (`initialize` handshake,
    /// `Mcp-Session-Id`, no SEP-2243 headers) — byte-identical to the
    /// legacy federation client.
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
    /// Stateless `2026-07-28` wire (no handshake / session, per-request
    /// `_meta` identity, SEP-2243 routing headers).
    #[serde(rename = "2026-07-28")]
    V2026_07_28,
}

impl UpstreamProtocolVersion {
    /// Whether this pins the modern stateless wire (`auto` is not
    /// modern until a probe proves the upstream is).
    #[must_use]
    pub fn is_modern(self) -> bool {
        self.pinned().is_some_and(|version| {
            version == crate::protocol::version::ProtocolVersion::V_2026_07_28
        })
    }

    /// Whether the wire is probed at connect time.
    #[must_use]
    pub fn is_auto(self) -> bool {
        self.pinned().is_none()
    }

    /// The revision this pins, or `None` for `auto`.
    ///
    /// The single mapping from the config vocabulary to
    /// [`crate::protocol::version::ProtocolVersion`]. Callers that need to know
    /// "which wire" go through this rather than re-matching the config enum,
    /// so a new revision is added to the protocol type and mapped once.
    #[must_use]
    pub fn pinned(self) -> Option<crate::protocol::version::ProtocolVersion> {
        match self {
            Self::Auto => None,
            Self::V2025_11_25 => Some(crate::protocol::version::ProtocolVersion::V_2025_11_25),
            Self::V2026_07_28 => Some(crate::protocol::version::ProtocolVersion::V_2026_07_28),
        }
    }
}

pub use mcpg_mcp_client::transport::UpstreamTransport;

/// How MCPG authenticates to the upstream.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
    /// Static bearer token for `service_token` (supports `${env.X}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Credential-issuer reference for `oauth_client_credentials`: a standard
    /// `cred://<plugin_id>/<target>` URI, e.g.
    /// `cred://dev.mcpg.credential.oauth-client-credentials/notion`. The
    /// referenced issuer plugin mints + refreshes the upstream bearer; no
    /// client secret lives in the federation config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// Per-issuance config object forwarded verbatim to the credential
    /// issuer on the OAuth modes (a template issuer's `audience` /
    /// `resource` / `redeem_token_url` overrides). Registry OAuth
    /// discovery populates this on synthesized federations; hand-written
    /// federations may set it to steer a template provider without a
    /// per-target issuer entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_config: Option<serde_json::Value>,
}

impl AuthConfig {
    pub(crate) fn validate(&self, path: &str) -> Result<()> {
        match self.mode {
            AuthMode::None | AuthMode::PassThrough => {}
            AuthMode::ServiceToken => {
                if self.token.as_deref().unwrap_or("").is_empty() {
                    bail!(
                        "{path}.upstream.auth: mode `service_token` requires a non-empty `token`"
                    );
                }
            }
            // Both OAuth modes resolve their bearer through a credential-issuer
            // plugin referenced by a `cred://<plugin_id>/<target>` URI:
            // `oauth_client_credentials` → a client-credentials issuer (machine
            // identity); `oauth_impersonation` → a token-exchange (RFC 8693)
            // issuer that exchanges the caller's bearer.
            AuthMode::OauthClientCredentials | AuthMode::OauthImpersonation => {
                let cred = self.credential.as_deref().unwrap_or("");
                if !cred.starts_with("cred://")
                    || cred
                        .strip_prefix("cred://")
                        .and_then(|r| r.split_once('/'))
                        .is_none()
                {
                    bail!(
                        "{path}.upstream.auth: mode `{:?}` requires `credential` as a cred://<plugin_id>/<target> URI",
                        self.mode
                    );
                }
            }
        }
        if let Some(config) = &self.credential_config
            && !config.is_object()
        {
            bail!("{path}.upstream.auth: `credential_config` must be a JSON object");
        }
        Ok(())
    }
}

/// Identity-propagation mode: what the gateway presents to the upstream.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// No auth sent.
    #[default]
    None,
    /// Static bearer token.
    ServiceToken,
    /// Forward the inbound `Authorization` header verbatim.
    PassThrough,
    /// Machine-identity token via an OAuth provider.
    OauthClientCredentials,
    /// Per-caller token-exchange (RFC 8693).
    OauthImpersonation,
}

/// SSRF / DNS-rebinding posture for the upstream URL. Mirrors the HTTP
/// binding's guard (`runtime/safe_dns.rs`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSafetyConfig {
    /// Permit private / loopback upstream addresses.
    #[serde(default)]
    pub allow_private_backends: bool,
    /// Permit `http://` (non-TLS) upstreams.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Permit the `stdio` transport, which spawns a local child process
    /// (arbitrary local execution — default-deny).
    #[serde(default)]
    pub allow_stdio: bool,
}

/// Which capability surfaces to import.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportConfig {
    #[serde(default = "super::default_true")]
    pub tools: bool,
    #[serde(default)]
    pub resources: bool,
    #[serde(default)]
    pub resource_templates: bool,
    #[serde(default)]
    pub prompts: bool,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            tools: true,
            resources: false,
            resource_templates: false,
            prompts: false,
        }
    }
}

impl ImportConfig {
    pub(crate) fn validate(&self, path: &str) -> Result<()> {
        if !self.tools && !self.resources && !self.resource_templates && !self.prompts {
            bail!(
                "{path}.import: nothing to import (set tools / resources / resource_templates / prompts: true)"
            );
        }
        Ok(())
    }
}

/// Prefixes applied to imported capability names / URIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamingConfig {
    /// Prepended to every imported tool name (e.g. `"notion."`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_prefix: Option<String>,
    /// Prepended to every imported resource URI (e.g. `"mcp://notion/"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_uri_prefix: Option<String>,
    /// Prepended to every imported prompt name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_prefix: Option<String>,
}

/// Allow/deny filtering of imported tool names (glob `*` suffix).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    #[serde(default = "default_include_all")]
    pub include_tools: Vec<String>,
    #[serde(default)]
    pub exclude_tools: Vec<String>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            include_tools: default_include_all(),
            exclude_tools: Vec::new(),
        }
    }
}

impl FilterConfig {
    /// Whether an upstream tool name passes the include/exclude filter.
    /// Exclude wins over include. Patterns are exact or a single
    /// trailing-`*` prefix glob (e.g. `internal_*`).
    #[must_use]
    pub fn admits(&self, tool_name: &str) -> bool {
        if self.exclude_tools.iter().any(|p| glob_match(p, tool_name)) {
            return false;
        }
        self.include_tools.iter().any(|p| glob_match(p, tool_name))
    }
}

/// Minimal glob: exact match, or `*` (all), or `prefix*` (prefix glob).
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// Capability-cache behaviour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationCacheConfig {
    /// Re-list the upstream's capabilities every N seconds even without
    /// a `list_changed` notification.
    #[serde(default = "default_capability_ttl_secs")]
    pub capability_ttl_secs: u64,
}

impl Default for FederationCacheConfig {
    fn default() -> Self {
        Self {
            capability_ttl_secs: default_capability_ttl_secs(),
        }
    }
}

/// Change-notification synthesis: when the upstream has no server→client
/// push channel, the gateway can manufacture `notifications/resources/updated`
/// for subscribed federated resources by polling them through the normal
/// read path and hash-diffing the content (the watch engine's poll
/// strategy). `list_changed` synthesis rides the existing capability TTL
/// refresh (`cache.capability_ttl_secs`) and needs no knob here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SynthesizeConfig {
    /// When to poll-synthesize `resources/updated` for subscribed
    /// federated resources.
    #[serde(default)]
    pub resources_updated: SynthesizeMode,
    /// Poll cadence for synthesized resource updates. Watchers are
    /// subscriber-gated: no subscribers, no polling.
    #[serde(default = "default_synthesize_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

impl Default for SynthesizeConfig {
    fn default() -> Self {
        Self {
            resources_updated: SynthesizeMode::default(),
            poll_interval_ms: default_synthesize_poll_interval_ms(),
        }
    }
}

/// Gate on synthesized change notifications.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SynthesizeMode {
    /// Synthesize only when the upstream demonstrably cannot push
    /// resource updates: the modern (`2026-07-28`) wire and the `stdio`
    /// transport. A legacy streamable-http upstream keeps its GET-SSE
    /// push path and is not polled.
    #[default]
    Auto,
    /// Always poll, even for upstreams with a push channel (covers
    /// legacy servers that only emit `resources/updated` for
    /// subscriptions the gateway does not place upstream).
    Poll,
    /// Never synthesize.
    Off,
}

/// Upstream-session behaviour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

/// Per-call response limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseConfig {
    /// Cap on a single upstream call's response, enforced gateway-side.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: default_max_response_bytes(),
        }
    }
}

fn default_include_all() -> Vec<String> {
    vec!["*".to_owned()]
}
fn default_capability_ttl_secs() -> u64 {
    300
}
fn default_synthesize_poll_interval_ms() -> u64 {
    30_000
}
fn default_idle_timeout_secs() -> u64 {
    600
}
fn default_max_response_bytes() -> u64 {
    2 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> FederationConfig {
        serde_yaml::from_str(yaml).expect("parse federation config")
    }

    fn minimal() -> &'static str {
        r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
naming:
  tool_prefix: "notion."
"#
    }

    #[test]
    fn minimal_config_parses_and_validates() {
        let c = cfg(minimal());
        c.validate().expect("valid");
        assert_eq!(c.name, "notion");
        assert_eq!(c.tool_prefix(), "notion.");
        // Defaults.
        assert!(c.import.tools);
        assert_eq!(c.cache.capability_ttl_secs, 300);
        assert_eq!(c.response.max_response_bytes, 2 * 1024 * 1024);
        assert!(matches!(
            c.upstream.transport,
            UpstreamTransport::StreamableHttp
        ));
        assert!(matches!(c.upstream.auth.mode, AuthMode::None));
    }

    #[test]
    fn protocol_version_defaults_to_auto_and_parses_pins() {
        // Default probes the upstream's wire at connect (SEP-2575
        // backward-compat sequence); a probe is not a modern pin.
        let c = cfg(minimal());
        assert!(c.upstream.protocol_version.is_auto());
        assert!(!c.upstream.protocol_version.is_modern());

        // Both dated pins parse and skip probing.
        let legacy = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  protocol_version: "2025-11-25"
"#);
        legacy.validate().expect("legacy pin valid");
        assert!(!legacy.upstream.protocol_version.is_auto());
        assert!(!legacy.upstream.protocol_version.is_modern());

        let modern = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  protocol_version: "2026-07-28"
naming:
  tool_prefix: "notion."
"#);
        modern.validate().expect("modern streamable_http valid");
        assert!(modern.upstream.protocol_version.is_modern());
    }

    #[test]
    fn synthesize_defaults_and_parses_modes() {
        let c = cfg(minimal());
        assert!(matches!(
            c.synthesize.resources_updated,
            SynthesizeMode::Auto
        ));
        assert_eq!(c.synthesize.poll_interval_ms, 30_000);

        let polled = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
synthesize:
  resources_updated: poll
  poll_interval_ms: 5000
"#);
        polled.validate().expect("synthesize block valid");
        assert!(matches!(
            polled.synthesize.resources_updated,
            SynthesizeMode::Poll
        ));
        assert_eq!(polled.synthesize.poll_interval_ms, 5000);

        let zero = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
synthesize:
  poll_interval_ms: 0
"#);
        assert!(
            zero.validate()
                .unwrap_err()
                .to_string()
                .contains("synthesize.poll_interval_ms")
        );
    }

    #[test]
    fn modern_protocol_version_rejected_on_stdio() {
        let c = cfg(r#"
name: local
upstream:
  transport: stdio
  command: "/bin/echo"
  protocol_version: "2026-07-28"
  upstream_safety: { allow_stdio: true }
"#);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("only supported on the streamable_http transport")
        );
    }

    #[test]
    fn http_upstream_requires_explicit_opt_in() {
        let c = cfg(r#"
name: internal
upstream:
  url: "http://llm.internal/mcp"
"#);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("allow_insecure_http")
        );

        let ok = cfg(r#"
name: internal
upstream:
  url: "http://llm.internal/mcp"
  upstream_safety: { allow_insecure_http: true }
"#);
        ok.validate().expect("http permitted when opted in");
    }

    #[test]
    fn tunnel_upstream_is_accepted_with_a_name() {
        let c = cfg(r#"
name: private-gw
upstream:
  url: "tunnel://acme-internal/mcp"
"#);
        c.validate()
            .expect("tunnel:// upstream with a name is valid");
    }

    #[test]
    fn tunnel_upstream_requires_a_name() {
        let c = cfg(r#"
name: private-gw
upstream:
  url: "tunnel:///mcp"
"#);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("tunnel:// upstream needs a name")
        );
    }

    #[test]
    fn service_token_requires_token() {
        let c = cfg(r#"
name: jira
upstream:
  url: "https://jira-mcp.example.com/mcp"
  auth: { mode: service_token }
"#);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("service_token")
        );
    }

    #[test]
    fn oauth_client_credentials_requires_cred_uri() {
        // A cred:// reference is mandatory and must carry a /<target>.
        let bad = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth: { mode: oauth_client_credentials, credential: "notion-oauth" }
"#);
        assert!(
            bad.validate()
                .unwrap_err()
                .to_string()
                .contains("cred://<plugin_id>/<target>")
        );

        // A well-formed cred:// URI validates.
        let ok = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth:
    mode: oauth_client_credentials
    credential: "cred://dev.mcpg.credential.oauth-client-credentials/notion"
"#);
        ok.validate()
            .expect("oauth_client_credentials with a cred:// URI should validate");
    }

    #[test]
    fn oauth_impersonation_requires_cred_uri() {
        // Like client_credentials, impersonation resolves its bearer through a
        // credential-issuer plugin (a token-exchange issuer); the cred:// URI
        // is mandatory.
        let bad = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth: { mode: oauth_impersonation }
"#);
        assert!(
            bad.validate()
                .unwrap_err()
                .to_string()
                .contains("cred://<plugin_id>/<target>")
        );

        // A well-formed cred:// URI (pointing at a token-exchange issuer) validates.
        let ok = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth:
    mode: oauth_impersonation
    credential: "cred://dev.mcpg.credential.oauth-token-exchange/notion"
"#);
        ok.validate()
            .expect("oauth_impersonation with a cred:// URI should validate");
    }

    #[test]
    fn credential_config_must_be_an_object() {
        let bad = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth:
    mode: oauth_impersonation
    credential: "cred://dev.mcpg.credential.oauth-token-exchange/notion"
    credential_config: "not-an-object"
"#);
        assert!(
            bad.validate()
                .unwrap_err()
                .to_string()
                .contains("credential_config")
        );

        let ok = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
  auth:
    mode: oauth_impersonation
    credential: "cred://dev.mcpg.credential.oauth-token-exchange/notion"
    credential_config:
      audience: "https://notion-mcp.example.com"
      redeem_token_url: "https://as.example.com/oauth2/token"
"#);
        ok.validate().expect("object credential_config validates");
    }

    #[test]
    fn resource_templates_import_supported() {
        // resource_templates is a supported import surface.
        let c = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
import: { tools: false, resource_templates: true }
"#);
        c.validate()
            .expect("resource_templates import should validate");
    }

    #[test]
    fn empty_import_rejected() {
        // No surface enabled at all is a config error.
        let c = cfg(r#"
name: notion
upstream:
  url: "https://notion-mcp.example.com/mcp"
import: { tools: false }
"#);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("nothing to import")
        );
    }

    #[test]
    fn stdio_transport_requires_command_and_allow_stdio() {
        // stdio needs a command.
        let no_cmd = cfg(r#"
name: notion
upstream:
  transport: stdio
  upstream_safety: { allow_stdio: true }
"#);
        assert!(
            no_cmd
                .validate()
                .unwrap_err()
                .to_string()
                .contains("command must be set")
        );

        // ...and the explicit allow_stdio opt-in (local exec is default-deny).
        let no_optin = cfg(r#"
name: notion
upstream:
  transport: stdio
  command: "my-mcp-server"
"#);
        assert!(
            no_optin
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allow_stdio")
        );

        // With both, it validates (no url needed).
        let ok = cfg(r#"
name: notion
upstream:
  transport: stdio
  command: "my-mcp-server"
  args: ["--flag"]
  upstream_safety: { allow_stdio: true }
"#);
        ok.validate()
            .expect("stdio with command + allow_stdio validates");
    }

    #[test]
    fn filter_admits_with_glob_and_exclude_wins() {
        let f = FilterConfig {
            include_tools: vec!["*".to_owned()],
            exclude_tools: vec!["internal_*".to_owned(), "debug".to_owned()],
        };
        assert!(f.admits("search"));
        assert!(!f.admits("internal_reset"));
        assert!(!f.admits("debug"));

        let only = FilterConfig {
            include_tools: vec!["search".to_owned(), "create_*".to_owned()],
            exclude_tools: vec![],
        };
        assert!(only.admits("search"));
        assert!(only.admits("create_page"));
        assert!(!only.admits("delete_page"));
    }
}
