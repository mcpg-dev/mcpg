//! Top-level `server:` block — HTTP listener, transport mode,
//! TLS / mTLS, request timeouts, body cap, session quotas, the
//! binding-backend health prober.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::HealthCheckConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_mcp_path")]
    pub mcp_path: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_replay_window_limit")]
    pub replay_window_limit: usize,
    #[serde(default = "default_session_idle_timeout_ms")]
    pub session_idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_timeout_ms")]
    pub shutdown_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Per-tenant session quota. 0 = unlimited. The stricter of this and
    /// the global cap wins.
    ///
    /// A "tenant" is the trust-qualified principal, so the same subject
    /// string asserted by a header and verified by an IdP are separate
    /// tenants and cannot exhaust each other's quota.
    ///
    /// Two limits worth knowing before setting this:
    ///
    /// - **It is a per-replica cap.** The counter lives in this process,
    ///   so a fleet of N replicas admits up to N x this value per tenant,
    ///   and a reconnect that lands on another replica starts fresh.
    ///   Divide by the replica count if you need a fleet-wide ceiling.
    /// - **Anonymous callers share one bucket**, because an unauthenticated
    ///   request carries nothing to separate them by. Aggregate anonymous
    ///   usage is capped rather than per-caller usage; per-caller
    ///   protection for anonymous traffic is
    ///   `anonymous_rate_limit_per_min`, which meters by source IP.
    #[serde(default)]
    pub max_sessions_per_tenant: usize,
    /// Extra resource-URI schemes (beyond the built-in allow-list)
    /// treated as first-class by the resource normalizer.
    /// Matched case-insensitively.
    #[serde(default)]
    pub extra_resource_uri_schemes: Vec<String>,
    /// Emit a server-initiated `ping` to each active session's SSE stream
    /// on this cadence. `None` or `0` disables. Reasonable value: 30s.
    #[serde(default)]
    pub server_ping_interval_ms: Option<u64>,
    /// Per-session rate limit on `completion/complete` requests (cap per
    /// second). `None` disables. Guards against broken autocomplete UIs.
    #[serde(default)]
    pub completion_rate_limit_per_sec: Option<u64>,
    /// Per-IP request-rate cap on the MCP endpoint for requests below
    /// cryptographically-verified trust — i.e. anonymous AND header-asserted
    /// identities (sustained requests/minute, with `anonymous_rate_limit_burst`
    /// headroom). A self-asserted `x-mcpg-subject-id` does NOT buy an
    /// exemption. Only Verified traffic (a real OIDC/JWKS/identity-plugin
    /// credential) skips this — it is attributable and metered per tenant.
    /// Defaults generous (600/min = 10 rps sustained per client IP), far above
    /// interactive agent use; `0` disables (e.g. when an upstream WAF
    /// throttles, or for single-IP load testing).
    #[serde(default = "default_anonymous_rate_limit_per_min")]
    pub anonymous_rate_limit_per_min: u32,
    /// Burst allowance for `anonymous_rate_limit_per_min`.
    #[serde(default = "default_anonymous_rate_limit_burst")]
    pub anonymous_rate_limit_burst: u32,
    /// Trust `X-Forwarded-For` for the client IP used by the anonymous rate
    /// limit. Set ONLY when a trusted reverse proxy / edge fronts this gateway
    /// (the managed-cloud Envoy edge does) — the header is spoofable
    /// otherwise. When false (default) the TCP peer address is used.
    #[serde(default)]
    pub trust_proxy_ip: bool,
    /// Trust the `x-mcpg-subject-id` request header as a header-asserted
    /// identity. The header carries no proof of who the caller is, so when
    /// false (default) it is IGNORED and such requests resolve to Anonymous —
    /// only a verified credential (OIDC/JWKS/identity plugin) yields a
    /// non-anonymous principal. Set true ONLY behind a trusted upstream that
    /// authenticates the caller and injects this header.
    #[serde(default)]
    pub trust_subject_header: bool,
    /// AAuth resource metadata. When set, the gateway serves the document at
    /// `/.well-known/aauth-resource.json` and attaches the
    /// `AAuth-Requirement: requirement=agent-token` challenge (plus
    /// `Accept-Signature-Scheme` / `Accept-Signature-Alg`) to
    /// authentication-required 401 responses, so AAuth-capable agents can
    /// discover that signing with an agent token would succeed. Pair with the
    /// `dev.mcpg.identity.aauth` identity plugin, which does the verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aauth_resource_metadata: Option<AauthResourceMetadataConfig>,
    /// Re-validate tool arguments against the tool's inputSchema after a
    /// tool_gate / transform plugin rewrites them. When false (default)
    /// only the caller's original arguments are validated. Opt-in
    /// defense-in-depth — plugins are operator-signed, so a rewrite that
    /// diverges from the published schema is normally trusted.
    #[serde(default)]
    pub revalidate_mutated_tool_arguments: bool,
    /// Relax the per-session JSON-RPC request-id uniqueness rule. When
    /// false (default) a client-supplied `id` that has already been used
    /// on the same MCP session is rejected with `-32600` (JSON-RPC
    /// forbids id reuse). Set `true` only for load generators that
    /// replay a fixed request body (e.g. the fortio proxy-overhead
    /// benchmark in `tools/bench/fortio/`), where every request carries
    /// the same `id`. Never enable in production — it removes a
    /// duplicate-delivery / replay guard.
    #[serde(default)]
    pub relax_request_id_uniqueness: bool,
    /// On the legacy (`2025-11-25`) wire, answer a unary request whose result
    /// is immediately available and that emitted NO server→client
    /// notifications (`log` / `progress`) with a single `application/json`
    /// response instead of a one-frame `text/event-stream` reply. This is
    /// spec-permitted (Streamable HTTP lets the server pick JSON or SSE) and
    /// mirrors what the modern (`2026-07-28`) wire already does; it skips the
    /// per-request SSE stream bookkeeping (replay-window append, priming +
    /// logging frames, session snapshot) that otherwise runs under the session
    /// lock, which materially raises tool-call throughput. Default `false`
    /// (unchanged SSE behaviour). A request that DOES emit notifications, or
    /// suspends (MRTR), still streams regardless of this flag.
    #[serde(default)]
    pub unary_json_fast_path: bool,
    /// Emit the per-request access log (`request received` / `request
    /// completed` INFO events, one pair per request). Default `true` (the
    /// gateway logs every request's lifecycle). Set `false` to suppress the
    /// access log on latency/throughput-sensitive deployments: it removes two
    /// structured-log events — and their field formatting + sink write — from
    /// every request. Audit events, error/warn logs, metrics, and traces are
    /// unaffected. Leave `true` unless request-level access logging is
    /// provided elsewhere (an ingress/sidecar) or not required.
    #[serde(default = "crate::config::default_true")]
    pub access_log: bool,
    /// Enforce the SEP-2575 per-request `_meta` identity triple
    /// (`io.modelcontextprotocol/{protocolVersion, clientInfo,
    /// clientCapabilities}`) on EVERY id-bearing modern (`2026-07-28`)
    /// request, not just `server/discover`. When false (the
    /// default), only `server/discover` requires the triple and other
    /// modern methods may carry minimal `_meta`. Has no effect
    /// on the `2025-11-25` wire. Opt-in so existing modern clients are
    /// unaffected until they adopt the triple.
    #[serde(default)]
    pub enforce_modern_request_meta: bool,
    /// After boot (plugins loaded, config-origin `env://` / `${env.X}`
    /// secrets already captured by the env secret provider's snapshot),
    /// remove those referenced env vars from the live process
    /// environment so a loaded cdylib can no longer read them via
    /// `std::env::var` / shared-process env. Opt-in defense-in-depth,
    /// default off. NOTE: this is NOT a hard boundary — it does not
    /// clear `/proc/self/environ` (the exec-time copy), so a hostile
    /// in-process plugin can still recover the original values there;
    /// it raises the bar against accidental/casual exposure. Enable
    /// only once every plugin resolves its secrets via the host
    /// (`cred://` / `env://`) rather than reading env directly.
    #[serde(default)]
    pub scrub_process_env_after_boot: bool,
    /// Maximum POST body accepted on the MCP endpoint, in MiB.
    /// Defaults to 4 MiB. `0` falls back to the default — an unbounded
    /// body is never acceptable on a public endpoint.
    #[serde(default = "default_max_request_body_mb")]
    pub max_request_body_mb: usize,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Reverse-tunnel egress: dial out to an MCPG-Cloud relay and
    /// serve this gateway's MCP surface through the tunnel. `mcpg --tunnel`
    /// populates this. Absent / `enabled: false` = no tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelConfig>,
    /// Reverse-federation ingress: how this gateway reaches
    /// same-org `tunnel://<name>` federation upstreams through the relay's
    /// federation ingress. Independent of `tunnel` (egress) — a gateway can
    /// federate other gateways' tunnels without dialing one of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_federation: Option<TunnelFederationConfig>,
    #[serde(default)]
    pub transport: TransportMode,
    /// Additional plugin-supplied transports started at boot
    /// alongside the primary HTTP / stdio listener (which
    /// continues to be governed by `transport:` and
    /// `bind_address:`). Each entry is a [`KindRef`] —
    /// `kind:` resolves to either a built-in transport
    /// keyword (today only `dev.mcpg.builtin.transport.memory`
    /// is wired; `builtin-http` / `builtin-stdio` map to the
    /// in-tree HTTP / stdio paths and don't need a list entry)
    /// or a registered Transport plugin id. The plugin's
    /// `Transport::start(config, dispatcher)` runs once per
    /// list entry; transports that fail to start halt the
    /// boot. Empty list = no extra transports beyond the
    /// primary listener — today's default.
    ///
    /// Beyond the primary HTTP/stdio listener, additional
    /// transport plugins (websocket, grpc, custom RPC) ship as
    /// cdylibs under `plugins[]` and are wired to a session loop
    /// via this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<crate::config::wiring::KindRef>,
    /// Allow outbound connections to private/loopback/link-local IPs.
    /// Default `false` enables the DNS rebinding guard. Set `true` for
    /// container-network deployments where backends live on RFC 1918.
    #[serde(default)]
    pub allow_private_backends: bool,
    /// Periodic prober for every binding's backend (SQL server
    /// reachability, gRPC endpoint, REST upstream, ...). Distinct
    /// from `health_path:` above — that's the gateway's own
    /// liveness endpoint for load balancers; this prober actively
    /// pings each binding's underlying service and updates
    /// `PluginState::{Active, Degraded}` based on results.
    ///
    /// Lives under `server:` (rather than `observability:`) to
    /// reflect that it's binding-management infrastructure, not an
    /// observability concern.
    #[serde(default)]
    pub health_check: HealthCheckConfig,
}

/// Transport mode determines whether MCPG runs as an HTTP server or a stdio JSON-RPC process.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Http,
    Stdio,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            health_path: default_health_path(),
            mcp_path: default_mcp_path(),
            allowed_origins: Vec::new(),
            replay_window_limit: default_replay_window_limit(),
            session_idle_timeout_ms: default_session_idle_timeout_ms(),
            shutdown_timeout_ms: default_shutdown_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            completion_rate_limit_per_sec: None,
            anonymous_rate_limit_per_min: default_anonymous_rate_limit_per_min(),
            anonymous_rate_limit_burst: default_anonymous_rate_limit_burst(),
            trust_proxy_ip: false,
            trust_subject_header: false,
            aauth_resource_metadata: None,
            revalidate_mutated_tool_arguments: false,
            relax_request_id_uniqueness: false,
            unary_json_fast_path: false,
            access_log: true,
            enforce_modern_request_meta: false,
            scrub_process_env_after_boot: false,
            server_ping_interval_ms: None,
            max_sessions_per_tenant: 0,
            extra_resource_uri_schemes: Vec::new(),
            max_request_body_mb: default_max_request_body_mb(),
            tls: None,
            tunnel: None,
            tunnel_federation: None,
            transport: TransportMode::Http,
            transports: Vec::new(),
            allow_private_backends: false,
            health_check: HealthCheckConfig::default(),
        }
    }
}

/// AAuth resource metadata (`/.well-known/aauth-resource.json`,
/// draft-hardt-oauth-aauth-protocol "Resource Metadata"). Field names follow
/// the spec so an operator can paste a spec-shaped document; unrecognized
/// spec fields ride through `extra` verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct AauthResourceMetadataConfig {
    /// The gateway's AAuth server identifier — HTTPS scheme+host only, no
    /// port/path/trailing slash, lowercase (e.g. `https://gw.example`). MUST
    /// match the origin the document is fetched from.
    pub issuer: String,
    /// The credential flow agents should expect. Defaults to `agent-token`
    /// (identity-based access — what `dev.mcpg.identity.aauth` verifies);
    /// set `person-token` when the plugin's person-token mode is the primary
    /// credential.
    #[serde(default = "default_aauth_access_mode")]
    pub access_mode: String,
    /// Signature validity window advertised to agents, seconds. Mirror the
    /// identity plugin's `signature_window_secs` when overriding the 60 s
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_window: Option<u64>,
    /// Covered components agents MUST include beyond the profile's base set.
    /// Mirror the identity plugin's `additional_covered_components`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_signature_components: Vec<String>,
    /// Exactly the fully-specified JWS algorithms the verifier accepts.
    /// Defaults to what `dev.mcpg.identity.aauth` implements.
    #[serde(default = "default_aauth_accept_signature_algs")]
    pub accept_signature_algs: Vec<String>,
    /// Scope values this resource grants, each with a Markdown description
    /// the person server shows at consent. A resource token may only request
    /// scopes declared here (plus the standard OpenID identity scopes); tool
    /// `required_scopes` should name values from this map.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub scope_descriptions: std::collections::BTreeMap<String, String>,
    /// The Ed25519 key that signs resource tokens (`aa-resource+jwt`); its
    /// public half is published at `jwks_uri`. Required for
    /// `access_mode: auth-token`, unused otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<AauthSigningKeyConfig>,
    /// Resource-token lifetime, seconds (protocol ceiling 300).
    #[serde(default = "default_aauth_resource_token_ttl_secs")]
    pub resource_token_ttl_secs: u64,
    /// Development escape hatch for the revocation endpoint's outbound
    /// person-server key fetch: admit `http://` and private addresses.
    /// NEVER set in production.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure_dev_mode: bool,
    /// Any further spec fields (`name`, `description`, `documentation_uri`,
    /// `logo_uri`, …) — published verbatim.
    #[serde(default, flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Where the AAuth resource signing key comes from — exactly one source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AauthSigningKeyConfig {
    /// File holding the 32-byte Ed25519 seed — raw bytes or base64url text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_file: Option<std::path::PathBuf>,
    /// The seed inline as unpadded base64url (typically `${env.X}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// Generate a fresh key at every start. Development only: tokens minted
    /// before a restart cannot be verified after it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

pub(crate) fn default_aauth_resource_token_ttl_secs() -> u64 {
    300
}

impl Default for AauthResourceMetadataConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            access_mode: default_aauth_access_mode(),
            signature_window: None,
            additional_signature_components: Vec::new(),
            accept_signature_algs: default_aauth_accept_signature_algs(),
            scope_descriptions: std::collections::BTreeMap::new(),
            signing_key: None,
            resource_token_ttl_secs: default_aauth_resource_token_ttl_secs(),
            insecure_dev_mode: false,
            extra: serde_json::Map::new(),
        }
    }
}

pub(crate) fn default_aauth_access_mode() -> String {
    "agent-token".to_owned()
}

pub(crate) fn default_aauth_accept_signature_algs() -> Vec<String> {
    vec!["Ed25519".to_owned(), "ES256".to_owned()]
}

impl AauthResourceMetadataConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let iss = self.issuer.trim();
        if mcpg_aauth_core::ident::validate_server_identifier(iss, self.insecure_dev_mode).is_err()
        {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.issuer must be an AAuth server identifier — \
                 https scheme + lowercase host only, no port/path/trailing slash \
                 (got {iss:?}; insecure_dev_mode admits http:// and a port)"
            ));
        }
        if self.access_mode.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.access_mode must not be empty"
            ));
        }
        if self.accept_signature_algs.is_empty() {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.accept_signature_algs must not be empty — the \
                 list states exactly what the verifier accepts"
            ));
        }
        if !matches!(
            self.access_mode.as_str(),
            "agent-token" | "person-token" | "auth-token" | "session-token"
        ) {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.access_mode must be one of agent-token, \
                 person-token, auth-token, session-token (got {:?})",
                self.access_mode
            ));
        }
        if self.access_mode == "auth-token" && self.signing_key.is_none() {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.access_mode `auth-token` requires `signing_key` \
                 (resource tokens are signed; set seed_file / seed, or ephemeral: true for \
                 development)"
            ));
        }
        if let Some(k) = &self.signing_key {
            let sources = usize::from(k.seed_file.is_some())
                + usize::from(k.seed.is_some())
                + usize::from(k.ephemeral);
            if sources != 1 {
                return Err(anyhow::anyhow!(
                    "server.aauth_resource_metadata.signing_key needs exactly one of seed_file, \
                     seed, ephemeral"
                ));
            }
        }
        if self.resource_token_ttl_secs == 0 || self.resource_token_ttl_secs > 300 {
            return Err(anyhow::anyhow!(
                "server.aauth_resource_metadata.resource_token_ttl_secs must be 1..=300"
            ));
        }
        for (scope, desc) in &self.scope_descriptions {
            if scope.trim().is_empty() || scope.contains(char::is_whitespace) {
                return Err(anyhow::anyhow!(
                    "server.aauth_resource_metadata.scope_descriptions has an invalid scope \
                     value {scope:?} (non-empty, no whitespace)"
                ));
            }
            if desc.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "server.aauth_resource_metadata.scope_descriptions[{scope:?}] needs a \
                     description"
                ));
            }
        }
        Ok(())
    }

    /// The document served at `/.well-known/aauth-resource.json`.
    pub fn document(&self) -> serde_json::Value {
        let mut doc = serde_json::Map::new();
        doc.insert("issuer".into(), self.issuer.clone().into());
        doc.insert("access_mode".into(), self.access_mode.clone().into());
        if let Some(w) = self.signature_window {
            doc.insert("signature_window".into(), w.into());
        }
        if !self.additional_signature_components.is_empty() {
            doc.insert(
                "additional_signature_components".into(),
                self.additional_signature_components
                    .iter()
                    .map(|s| serde_json::Value::from(s.as_str()))
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        doc.insert(
            "accept_signature_algs".into(),
            self.accept_signature_algs
                .iter()
                .map(|s| serde_json::Value::from(s.as_str()))
                .collect::<Vec<_>>()
                .into(),
        );
        if !self.scope_descriptions.is_empty() {
            doc.insert(
                "scope_descriptions".into(),
                self.scope_descriptions
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::from(v.as_str())))
                    .collect::<serde_json::Map<_, _>>()
                    .into(),
            );
        }
        for (k, v) in &self.extra {
            doc.entry(k.clone()).or_insert_with(|| v.clone());
        }
        serde_json::Value::Object(doc)
    }
}

/// TLS configuration for the HTTP transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    /// Minimum TLS version: `"1.2"` or `"1.3"`. Default `"1.2"`.
    #[serde(default = "default_min_tls_version")]
    pub min_tls_version: String,
    /// Optional path to a PEM bundle of CA certs that gate-keep
    /// client cert acceptance for mTLS. Required whenever
    /// `client_cert_required` is `"optional"` or `"mandatory"`;
    /// must be empty / absent when `"none"`.
    #[serde(default)]
    pub client_ca_certs_path: Option<String>,
    /// Client cert acceptance mode for mTLS connections:
    ///
    /// - `"none"` (default) — server-only TLS, no client certs.
    /// - `"optional"` — present-cert is verified against
    ///   `client_ca_certs_path`; no-cert is allowed and surfaces
    ///   as `client_cert_present: false` in `TlsInfo`. Operators
    ///   layer policy plugins to decide what to do with anonymous
    ///   connections.
    /// - `"mandatory"` — handshake fails when no client cert is
    ///   presented; surface is `client_cert_present: true` for
    ///   any successful connection.
    ///
    /// The mode populates the gateway's
    /// `transport_listen` capability bit, which
    /// identity plugins like `dev.mcpg.identity.workload` and
    /// `dev.mcpg.identity.mtls` (direct_mtls source) require.
    #[serde(default)]
    pub client_cert_required: ClientCertMode,
}

/// Operator-facing client-cert acceptance mode.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertMode {
    #[default]
    None,
    Optional,
    Mandatory,
}

impl ClientCertMode {
    pub fn requires_ca(self) -> bool {
        matches!(self, Self::Optional | Self::Mandatory)
    }
}

fn default_min_tls_version() -> String {
    "1.2".to_owned()
}

/// Reverse-tunnel egress config. The gateway dials out to a relay
/// and answers tunnelled MCP traffic through its own request path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// Master switch. `false` (default) dials no tunnel.
    #[serde(default)]
    pub enabled: bool,
    /// Relay endpoint to dial (e.g. `wss://relay.tunnels.mcpg.cloud`).
    #[serde(default = "default_tunnel_relay_url")]
    pub relay_url: String,
    /// Optional stable tunnel name; the relay allocates one when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `public` allocates a `<id>.tunnels.mcpg.cloud` URL (dev preview,
    /// third-party MCP clients); `private` (federation-only) allocates no
    /// public address and is reachable only as a `tunnel://` federation
    /// upstream from the same org.
    #[serde(default)]
    pub exposure: TunnelExposure,
    /// `relay_terminated` (the relay sees plaintext) or `e2ee` (relay splices
    /// ciphertext — requires `private` exposure, mcpg-to-mcpg only).
    #[serde(default)]
    pub mode: TunnelTrustMode,
}

/// Whether a tunnel gets a public hostname.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TunnelExposure {
    #[default]
    Public,
    Private,
}

/// Who can read tunnelled payloads.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TunnelTrustMode {
    #[default]
    RelayTerminated,
    E2ee,
}

pub(crate) fn default_tunnel_relay_url() -> String {
    "wss://relay.tunnels.mcpg.cloud".to_owned()
}

impl TunnelConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.relay_url.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "server.tunnel.relay_url must not be empty when the tunnel is enabled"
            ));
        }
        // End-to-end encryption only works when both ends are mcpg, which is a
        // private (federation-only) tunnel — a public tunnel must terminate a
        // third-party client's TLS at the relay.
        if self.mode == TunnelTrustMode::E2ee && self.exposure == TunnelExposure::Public {
            return Err(anyhow::anyhow!(
                "server.tunnel: e2ee mode requires private exposure (mcpg-to-mcpg only)"
            ));
        }
        Ok(())
    }
}

/// Reverse-federation ingress config. A `tunnel://<name>/<path>`
/// federation upstream resolves through the relay's federation ingress to
/// `<relay_ingress_url>/federate/<name>/<path>`. This gateway authenticates its
/// ORG to the relay with the `token` field below (carried in the
/// `X-MCPG-Tunnel-Token` header, which the relay consumes and never forwards);
/// the end-user's `Authorization` bearer flows through, untouched, to the
/// tunnelled gateway as the MCP caller identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TunnelFederationConfig {
    /// Relay federation-ingress base URL, e.g.
    /// `https://relay.tunnels.mcpg.cloud`. Must be `http(s)`.
    pub relay_ingress_url: String,
    /// Org token presented to the relay in `X-MCPG-Tunnel-Token`. When unset,
    /// the gateway falls back to the `MCPG_TUNNEL_TOKEN` environment variable
    /// (the same org token used for egress dial), so a gateway that both dials
    /// and federates needs the token in one place. Supports `${env.X}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl TunnelFederationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let url = self.relay_ingress_url.trim();
        if url.is_empty() {
            return Err(anyhow::anyhow!(
                "server.tunnel_federation.relay_ingress_url must not be empty"
            ));
        }
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(anyhow::anyhow!(
                "server.tunnel_federation.relay_ingress_url must be an http(s) URL, got {url:?}"
            ));
        }
        Ok(())
    }
}

impl TlsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.cert_path.trim().is_empty() {
            return Err(anyhow::anyhow!("server.tls.cert_path must not be empty"));
        }
        if self.key_path.trim().is_empty() {
            return Err(anyhow::anyhow!("server.tls.key_path must not be empty"));
        }
        match self.min_tls_version.trim() {
            "1.2" | "1.3" => {}
            other => {
                return Err(anyhow::anyhow!(
                    "server.tls.min_tls_version must be \"1.2\" or \"1.3\", got {other:?}"
                ));
            }
        }
        match self.client_cert_required {
            ClientCertMode::None => {
                if self.client_ca_certs_path.is_some() {
                    return Err(anyhow::anyhow!(
                        "server.tls.client_ca_certs_path must be unset when \
                         client_cert_required is `none`"
                    ));
                }
            }
            ClientCertMode::Optional | ClientCertMode::Mandatory => {
                let path = self.client_ca_certs_path.as_deref().unwrap_or("");
                if path.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "server.tls.client_ca_certs_path must be set (PEM bundle of \
                         CA certs) when client_cert_required is `optional` or \
                         `mandatory`"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:8787".to_owned()
}

fn default_health_path() -> String {
    "/health".to_owned()
}

fn default_mcp_path() -> String {
    "/mcp".to_owned()
}

fn default_replay_window_limit() -> usize {
    16
}

fn default_session_idle_timeout_ms() -> u64 {
    900000
}

fn default_shutdown_timeout_ms() -> u64 {
    30000
}

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_max_request_body_mb() -> usize {
    4
}

fn default_anonymous_rate_limit_per_min() -> u32 {
    600
}

fn default_anonymous_rate_limit_burst() -> u32 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aauth_metadata_validates_issuer_shape() {
        let ok = AauthResourceMetadataConfig {
            issuer: "https://gw.example".into(),
            access_mode: default_aauth_access_mode(),
            accept_signature_algs: default_aauth_accept_signature_algs(),
            ..Default::default()
        };
        ok.validate().unwrap();

        for bad in [
            "http://gw.example",     // not https
            "https://gw.example/",   // trailing slash
            "https://gw.example:88", // port
            "https://GW.example",    // uppercase
            "",
        ] {
            let cfg = AauthResourceMetadataConfig {
                issuer: bad.into(),
                access_mode: default_aauth_access_mode(),
                accept_signature_algs: default_aauth_accept_signature_algs(),
                ..Default::default()
            };
            assert!(cfg.validate().is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn aauth_metadata_document_shape() {
        let mut extra = serde_json::Map::new();
        extra.insert("name".into(), serde_json::json!("Example Gateway"));
        let cfg = AauthResourceMetadataConfig {
            issuer: "https://gw.example".into(),
            access_mode: default_aauth_access_mode(),
            signature_window: Some(90),
            additional_signature_components: vec!["content-digest".into()],
            accept_signature_algs: default_aauth_accept_signature_algs(),
            extra,
            ..Default::default()
        };
        let doc = cfg.document();
        assert_eq!(doc["issuer"], "https://gw.example");
        assert_eq!(doc["access_mode"], "agent-token");
        assert_eq!(doc["signature_window"], 90);
        assert_eq!(doc["additional_signature_components"][0], "content-digest");
        assert_eq!(doc["accept_signature_algs"][0], "Ed25519");
        assert_eq!(doc["accept_signature_algs"][1], "ES256");
        assert_eq!(doc["name"], "Example Gateway");
    }

    /// The spec-shaped YAML parses: field names match the wire document, and
    /// unknown spec fields ride through `extra` verbatim.
    #[test]
    fn aauth_metadata_accepts_spec_shaped_input() {
        let cfg: AauthResourceMetadataConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://gw.example",
            "access_mode": "agent-token",
            "additional_signature_components": ["content-digest"],
            "documentation_uri": "https://gw.example/docs",
        }))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.document()["documentation_uri"],
            "https://gw.example/docs"
        );
    }

    fn base_tls() -> TlsConfig {
        TlsConfig {
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
            min_tls_version: default_min_tls_version(),
            client_ca_certs_path: None,
            client_cert_required: ClientCertMode::None,
        }
    }

    #[test]
    fn tls_validate_accepts_known_versions() {
        for v in ["1.2", "1.3", " 1.3 "] {
            let cfg = TlsConfig {
                min_tls_version: v.into(),
                ..base_tls()
            };
            assert!(cfg.validate().is_ok(), "version {v:?} should validate");
        }
    }

    #[test]
    fn tls_validate_rejects_unknown_version() {
        let cfg = TlsConfig {
            min_tls_version: "1.1".into(),
            ..base_tls()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("min_tls_version"), "got: {err}");
    }

    #[test]
    fn tunnel_federation_validate_accepts_http_urls() {
        for url in ["https://relay.mcpg.cloud", "http://localhost:8081"] {
            let cfg = TunnelFederationConfig {
                relay_ingress_url: url.into(),
                token: None,
            };
            assert!(cfg.validate().is_ok(), "{url} should validate");
        }
    }

    #[test]
    fn tunnel_federation_validate_rejects_empty_and_non_http() {
        let empty = TunnelFederationConfig {
            relay_ingress_url: "  ".into(),
            token: None,
        };
        assert!(empty.validate().unwrap_err().to_string().contains("empty"));
        let bad = TunnelFederationConfig {
            relay_ingress_url: "wss://relay.mcpg.cloud".into(),
            token: None,
        };
        assert!(
            bad.validate()
                .unwrap_err()
                .to_string()
                .contains("http(s) URL")
        );
    }
}
