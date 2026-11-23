pub mod aauth_resource;
pub mod approvals;
pub mod authorization_server;
pub mod backend_health;
mod builder;
pub mod buses;
pub use buses::{cancellation_bus, delivery_bus};
pub(crate) mod cel_guard_plugin;
pub mod cp;
pub use cp::{cp_metrics, cp_quota};
mod cursor;
pub mod events;
mod execution;
pub(crate) mod expr;
pub(crate) mod feature_flags;
pub(crate) mod federation;
pub mod fleet_semaphore;
pub(crate) mod gateway_apps;
mod handlers;
pub mod idempotency;
pub mod identity;
pub mod inspector_identity;
pub(crate) use identity::identity_plugin;
pub use identity::oidc;
pub mod invocation;
pub mod personal_agent;
pub mod personal_agent_operations;
pub(crate) mod policy;
#[cfg(feature = "governance-quotas")]
pub mod quota_gate;
pub mod reapers;
pub(crate) use reapers::reaper_leadership;
pub use reapers::{pipeline_reaper, task_reaper};
pub mod admission;
pub mod redact;
pub mod safe_dns;
pub(crate) mod session_fleet;
pub mod shared_services;
pub mod skills;
pub mod stores;
pub use stores::{
    content_store_registry, pipeline_store, request_state_store, session_store, subscription_store,
    task_store,
};
mod accessors;
mod apps;
mod cancellation;
mod delivery;
mod diagnostics;
mod enumeration;
mod federation_glue;
mod idempotency_ops;
mod policy_eval;
pub mod registry_sync;
mod sessions;
pub mod subscriptions;
mod types;
mod util;
pub mod watch_engine;
#[cfg(test)]
mod watch_fleet_tests;
pub mod watch_shards;
pub use types::*;
pub(crate) use util::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tracing::{info, warn};
use uuid::Uuid;

use arc_swap::ArcSwapOption;

/// Coordinator-health gauge backing. A periodic probe
/// ([`GatewayRuntime::spawn_cluster_health_probe`]) updates it from a
/// fallible KV ping, independent of any lease consumer;
/// [`GatewayRuntime::readiness_snapshot`] reads it to optionally gate
/// `/ready` per `cluster.readiness_gate`. Values:
/// `2` = not probed (single_node / KV-less coordinator), `1` = up,
/// `0` = down. Process-global: there is one coordinator per process, and
/// a config reload keeps probing the same one.
static CLUSTER_BACKEND_UP: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2);
const CLUSTER_UP_NOT_PROBED: u8 = 2;
const CLUSTER_UP_DOWN: u8 = 0;
const CLUSTER_UP_HEALTHY: u8 = 1;

use crate::backends::{BackendInvocationRoute, CapabilityRegistry, PromptRoute, ResourceRoute};
use crate::config::{BackendConfig, SinkConfig};
use crate::protocol::shared::messages::ProtocolMessage;
use crate::protocol::{
    BlobResourceContents, JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, JsonRpcSuccess,
    PromptGetResult, PromptMessage, ProtocolHttpResponse, ProtocolResponse, ResourceContents,
    ResourceReadResult, ResourceTextContents,
};
use crate::runtime::shared_services::SharedServices;

use cursor::{
    CompositeCursor, DynCursor, decode_composite_cursor, decode_cursor, encode_composite_cursor,
    encode_cursor, paginate_list_bound,
};
use delivery_bus::DeliveryBus;
use execution::{BackendInvocationRequest, ExecutionDispatcher};
pub use execution::{CommandToolRuntimeConfig, NetworkToolRuntimeConfig, RuntimeDebugConfig};
use handlers::task_status_notification;
use policy::{PolicyRoute, PreDispatchPolicyGate, PreDispatchPolicyOutcome, ToolPolicyContext};
pub use policy::{PolicySurface, ToolAccessPolicyConfig, ToolTrustRule};
use session_store::{EndedSession, SessionStore};
pub use session_store::{SessionSnapshot, SessionStoreConfig};
pub(crate) use sessions::SessionOutcome;
use sessions::{RegisteredCancellation, cancellation_requester_is_owner, resumer_owns_pipeline};
use subscription_store::SubscriptionStore;

/// Unique identifier for a single gateway request, used for correlation across logs, metrics, and traces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRequestId(String);

impl Default for GatewayRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayRequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GatewayRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which MCP transport is carrying this request (HTTP Streamable or stdio).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Http,
    Stdio,
}

/// `source` of a caller authenticated by an access token the embedded
/// authorization server minted.
pub const EMA_ACCESS_TOKEN_SOURCE: &str = "authorization:ema_access_token";
/// `source` of the supervised inspector's loopback credential.
pub const INSPECTOR_TOKEN_SOURCE: &str = "supervised_inspector_token";

/// Caller identity resolved from transport headers during request intake.
/// The variant determines the trust level applied by the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestIdentity {
    Anonymous {
        source: String,
    },
    HttpHeader {
        subject_id: String,
        source: String,
    },
    Verified {
        subject_id: String,
        issuer: String,
        auth_provider: String,
        source: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        roles: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        groups: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        attributes: std::collections::BTreeMap<String, String>,
    },
}

/// Ordered trust tiers for the policy engine. Policy rules match on this level
/// so operators can gate sensitive tools behind cryptographic verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RequestTrustLevel {
    Unauthenticated,
    HeaderAsserted,
    Verified,
}

impl RequestIdentity {
    /// Short string label for metrics and structured logging.
    pub fn label(&self) -> &str {
        match self {
            RequestIdentity::Anonymous { .. } => "anonymous",
            RequestIdentity::HttpHeader { .. } => "http_header",
            RequestIdentity::Verified { .. } => "verified",
        }
    }

    /// Map the identity variant to its corresponding trust tier for policy evaluation.
    pub fn trust_level(&self) -> RequestTrustLevel {
        match self {
            RequestIdentity::Anonymous { .. } => RequestTrustLevel::Unauthenticated,
            RequestIdentity::HttpHeader { .. } => RequestTrustLevel::HeaderAsserted,
            RequestIdentity::Verified { .. } => RequestTrustLevel::Verified,
        }
    }

    /// Extract the authenticated subject identifier, if any.
    pub fn principal_id(&self) -> Option<&str> {
        match self {
            RequestIdentity::Anonymous { .. } => None,
            RequestIdentity::HttpHeader { subject_id, .. } => Some(subject_id),
            RequestIdentity::Verified { subject_id, .. } => Some(subject_id),
        }
    }

    pub fn auth_provider(&self) -> Option<&str> {
        match self {
            RequestIdentity::Verified { auth_provider, .. } => Some(auth_provider),
            _ => None,
        }
    }

    pub fn issuer(&self) -> Option<&str> {
        match self {
            RequestIdentity::Verified { issuer, .. } => Some(issuer),
            _ => None,
        }
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self, RequestIdentity::Anonymous { .. })
    }

    /// True when the caller's bearer was minted by this gateway process: an
    /// EMA access token or the supervised inspector's credential. Only this
    /// gateway can validate such a bearer. Read from `source`, which a
    /// `principal_issuer` alias leaves alone while it rewrites `issuer` and
    /// `auth_provider`.
    pub fn is_gateway_minted(&self) -> bool {
        match self {
            RequestIdentity::Verified { source, .. } => {
                source == EMA_ACCESS_TOKEN_SOURCE || source == INSPECTOR_TOKEN_SOURCE
            }
            _ => false,
        }
    }

    /// True for any identity whose trust tier is below cryptographic
    /// verification — Anonymous **and** header-asserted. Header-asserted
    /// callers present no proof, so security controls that must not be
    /// bought off with a self-asserted header (per-IP rate limiting) key
    /// on this rather than [`Self::is_anonymous`].
    pub fn is_below_verified(&self) -> bool {
        self.trust_level() < RequestTrustLevel::Verified
    }

    /// Trust-qualified principal key for synthetic-session continuity.
    /// Embeds the trust tier and (for verified identities) the auth
    /// provider + issuer so a header-asserted `alice` can never collide
    /// with a verified `alice`, nor `alice` from one IdP with `alice`
    /// from another. `None` for anonymous callers (no stable principal).
    pub(crate) fn synthetic_principal_key(&self) -> Option<String> {
        match self {
            RequestIdentity::Anonymous { .. } => None,
            RequestIdentity::HttpHeader { subject_id, .. } => {
                Some(format!("header_asserted::{subject_id}"))
            }
            RequestIdentity::Verified {
                subject_id,
                issuer,
                auth_provider,
                ..
            } => Some(format!("verified::{auth_provider}::{issuer}::{subject_id}")),
        }
    }

    /// True when `owner_key` is a key [`Self::synthetic_principal_key`]
    /// returns, not the session id that owns an anonymous caller's task.
    pub(crate) fn is_principal_key(owner_key: &str) -> bool {
        owner_key.starts_with("verified::") || owner_key.starts_with("header_asserted::")
    }

    pub fn roles(&self) -> &[String] {
        match self {
            RequestIdentity::Verified { roles, .. } => roles,
            _ => &[],
        }
    }

    pub fn groups(&self) -> &[String] {
        match self {
            RequestIdentity::Verified { groups, .. } => groups,
            _ => &[],
        }
    }

    pub fn scopes(&self) -> &[String] {
        match self {
            RequestIdentity::Verified { scopes, .. } => scopes,
            _ => &[],
        }
    }

    pub fn attributes(&self) -> &std::collections::BTreeMap<String, String> {
        static EMPTY: OnceLock<std::collections::BTreeMap<String, String>> = OnceLock::new();
        match self {
            RequestIdentity::Verified { attributes, .. } => attributes,
            _ => EMPTY.get_or_init(std::collections::BTreeMap::new),
        }
    }
}

/// Per-request metadata carried through the entire gateway pipeline: identity,
/// session binding, transport origin, and timing. Built once at intake and
/// threaded immutably into every downstream operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: GatewayRequestId,
    pub upstream_request_id: Option<String>,
    /// The internal session this request is bound to, set by
    /// [`GatewayRuntime::ensure_session`] at dispatch.
    pub session_id: Option<String>,
    pub identity: RequestIdentity,
    pub transport: TransportKind,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<crate::transports::TraceContext>,
    /// The client capabilities the request carries in
    /// `_meta["io.modelcontextprotocol/clientCapabilities"]`. `None` when
    /// it names none; the request then has the default (empty) capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_capabilities: Option<crate::protocol::ClientCapabilities>,
    /// Raw inbound bearer token (from `Authorization: Bearer …`),
    /// captured by the HTTP transport for `auth.mode: pass_through`
    /// federation dispatch. `#[serde(skip)]` — kept in-memory only,
    /// never persisted (pipeline store) or logged.
    #[serde(skip)]
    pub inbound_bearer: Option<String>,
    /// The session id was minted for this request only and has no row in
    /// the session store. Every session-keyed structure (deliveries,
    /// cancellation) works on the id string alone, and a continuation
    /// point (task materialization, MRTR suspension,
    /// `subscriptions/listen`) creates the row on demand via
    /// `GatewayRuntime::materialize_ephemeral_session`. Anonymous requests
    /// run this way, so sustained anonymous traffic performs no
    /// session-store operations.
    #[serde(default)]
    pub session_ephemeral: bool,
    /// The link a federated call of this request offers a caller with no
    /// stored IdP sign-in, while the request may answer with a URL-mode
    /// elicitation. Shared by the clones of the context; in memory only.
    #[serde(skip)]
    pub(crate) connect_link: Arc<federation::idp_sessions::ConnectLinkSlot>,
    /// The caller as a Personal Agent Protocol Session, while
    /// `governance.access.personal_agent` is set and the caller is
    /// verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_agent: Option<personal_agent::PersonalAgentCaller>,
    /// The confirmed Personal Agent Protocol operation this tool call
    /// performs: it runs outside any MCP session and proposes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pap_operation: Option<String>,
    /// This is the gateway's own call of the realtime admission tool: it
    /// runs outside any MCP session, and only such a call may reach that
    /// tool.
    #[serde(skip)]
    pub(crate) realtime_admission: bool,
    /// The caller's address: the first `X-Forwarded-For` hop when
    /// `server.trust_proxy_ip` is set, else the transport peer. `None` for
    /// a transport without a peer address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<std::net::IpAddr>,
    /// The client the request names in
    /// `_meta["io.modelcontextprotocol/clientInfo"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<mcpg_plugin_protocol::ClientInfo>,
    /// The `Mcp-Param-{Name}` headers of a `tools/call` or `events/*`
    /// request over HTTP, as lower-case name after the prefix and raw
    /// value, for the runtime to check against the `x-mcp-header`
    /// annotations of the tool's or event type's input schema. `None`
    /// where no routing headers exist.
    #[serde(skip)]
    pub(crate) param_headers: Option<Arc<Vec<(String, String)>>>,
}

impl RequestContext {
    /// A context with no session yet: dispatch binds one through
    /// [`GatewayRuntime::ensure_session`].
    pub fn new(
        request_id: GatewayRequestId,
        upstream_request_id: Option<String>,
        identity: RequestIdentity,
        transport: TransportKind,
    ) -> Self {
        Self {
            request_id,
            upstream_request_id,
            session_id: None,
            identity,
            transport,
            started_at: Utc::now(),
            trace_context: None,
            request_capabilities: None,
            inbound_bearer: None,
            session_ephemeral: false,
            connect_link: Arc::default(),
            personal_agent: None,
            pap_operation: None,
            realtime_admission: false,
            client_ip: None,
            client: None,
            param_headers: None,
        }
    }

    /// The MCP client that sent this request, as its `clientInfo` names
    /// it. `None` for a request that names none.
    pub fn client(&self) -> Option<mcpg_plugin_protocol::ClientInfo> {
        self.client.clone()
    }

    /// Bind this context to the ephemeral (row-less) session `snapshot`
    /// names.
    pub(crate) fn with_ephemeral_session(mut self, snapshot: SessionSnapshot) -> Self {
        self.session_id = Some(snapshot.session_id);
        self.session_ephemeral = true;
        self
    }

    /// Install the client capabilities the request carries in
    /// `_meta["io.modelcontextprotocol/clientCapabilities"]`. The pipeline
    /// steps that send a request to the client (elicitation, sampling,
    /// roots) are gated on them.
    pub fn with_request_capabilities(
        mut self,
        capabilities: crate::protocol::ClientCapabilities,
    ) -> Self {
        self.request_capabilities = Some(capabilities);
        self
    }

    /// Capture the raw inbound bearer for `pass_through` federation
    /// dispatch. Stored in-memory only (serde-skipped).
    pub fn with_inbound_bearer(mut self, bearer: Option<String>) -> Self {
        self.inbound_bearer = bearer;
        self
    }

    pub fn with_trace_context(
        mut self,
        trace_context: Option<crate::transports::TraceContext>,
    ) -> Self {
        self.trace_context = trace_context;
        self
    }

    /// Build the identity-derived portion of the expression context.
    /// Cached per request — the identity, transport, and session do not
    /// change within a single request's lifetime. Avoids re-cloning
    /// roles/groups/scopes/attributes on every tools/call dispatch.
    fn cached_expr_request_context(&self) -> expr::ExprRequestContext {
        let client = self.client();
        expr::ExprRequestContext {
            principal_id: self.identity.principal_id().map(str::to_owned),
            trust_level: match self.identity.trust_level() {
                RequestTrustLevel::Unauthenticated => "unauthenticated",
                RequestTrustLevel::HeaderAsserted => "header_asserted",
                RequestTrustLevel::Verified => "verified",
            }
            .to_owned(),
            auth_provider: self.identity.auth_provider().map(str::to_owned),
            session_id: self.session_id.clone(),
            transport: match self.transport {
                TransportKind::Http => "http",
                TransportKind::Stdio => "stdio",
            }
            .to_owned(),
            client_name: client.as_ref().map(|c| c.name.clone()),
            client_version: client.and_then(|c| c.version),
            roles: self.identity.roles().to_vec(),
            groups: self.identity.groups().to_vec(),
            scopes: self.identity.scopes().to_vec(),
            attributes: self.identity.attributes().clone(),
        }
    }

    /// Owner key for task authorization (SEP-2663). Binds a task to the
    /// request **principal**, so a task created on one cluster replica
    /// is pollable from another. Falls back to the session id for an
    /// anonymous caller, which presents no stable principal.
    pub fn task_owner_key(&self) -> Option<String> {
        self.identity
            .synthetic_principal_key()
            .or_else(|| self.session_id.clone())
    }

    /// Build an expression context from this request context and tool call
    /// parameters. Only `arguments` and `tool_name` vary per dispatch;
    /// the identity-derived fields are built once via
    /// `cached_expr_request_context`.
    pub(crate) fn to_expr_context(
        &self,
        tool_name: &str,
        arguments: Option<&Value>,
    ) -> expr::ExprContext {
        expr::ExprContext {
            arguments: arguments.cloned().unwrap_or(serde_json::json!({})),
            tool_name: tool_name.to_owned(),
            context: self.cached_expr_request_context(),
            steps: None,
            env: std::sync::Arc::new(std::collections::HashMap::new()),
        }
    }
}

/// A diagnostics probe. MCP messages enter through
/// [`GatewayRuntime::handle_protocol_message`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsOperation {
    Readiness,
    Runtime,
}

impl DiagnosticsOperation {
    pub fn label(&self) -> &'static str {
        match self {
            DiagnosticsOperation::Readiness => "diagnostics.readiness",
            DiagnosticsOperation::Runtime => "diagnostics.runtime",
        }
    }
}

/// Gateway response envelope pairing the originating request ID with the response payload.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayResponse {
    pub request_id: GatewayRequestId,
    pub payload: GatewayResponsePayload,
}

/// The body of a diagnostics probe's answer.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum GatewayResponsePayload {
    Readiness(ReadinessSnapshot),
    Runtime(RuntimeSnapshot),
}

/// Central gateway runtime holding all shared state: session store, capability
/// registry, plugin chain, execution dispatcher, and cluster infrastructure.
/// Built once at startup and shared via `Arc` across all request handlers.
///
/// Sessions are internal: [`Self::ensure_session`] binds every request to
/// one, keyed by the caller's principal (a fresh row-less one for an
/// anonymous caller), and a session ends on idle timeout or when an
/// operator terminates it.
pub struct GatewayRuntime {
    pub service_name: String,
    pub service_version: String,
    pub started_at: DateTime<Utc>,
    server_bind_address: String,
    health_path: String,
    mcp_path: String,
    log_level: String,
    log_sinks: Vec<SinkConfig>,
    logging_initialized: bool,
    debug_enabled: bool,
    /// When true, re-run inputSchema validation on the FINAL tool
    /// arguments after a tool_gate / transform plugin rewrote them, so a
    /// plugin can't inject args that violate the published inputSchema.
    /// Opt-in (default false) — plugins are operator-signed, so this is
    /// defense-in-depth.
    revalidate_mutated_tool_arguments: bool,
    /// When true, a completed-idempotency-replay hit re-runs the FULL
    /// pre-dispatch stack (external policy chain + tool_gate plugins) —
    /// not just the trust+CEL floor — before serving the cached envelope,
    /// so authorization revoked since the original call is honored within
    /// the record TTL. Opt-in (default false). Wired from
    /// `idempotency.replay_revalidation` at boot + reload.
    idempotency_replay_revalidation: bool,
    /// When true, session-scoped operations (`subscriptions/listen`)
    /// require the caller's principal to match the session's creator.
    /// Opt-in (default false). Wired from `sessions.bind_session_owner`
    /// at boot + reload.
    bind_session_owner: bool,
    capability_registry: Arc<CapabilityRegistry>,
    /// (backend_name, plugin_kind) pairs for bindings that may
    /// surface dynamic resources via
    /// `BackendPlugin::list_resources` (the dynamic-resource
    /// fan-out). Populated
    /// from binding_configs at construction so the
    /// `resources/list` handler doesn't re-scan on every request.
    dynamic_list_bindings: Vec<(String, String)>,
    pre_dispatch_policy: Arc<PreDispatchPolicyGate>,
    plugin_registry: Arc<mcpg_plugin_host::PluginRegistry>,
    /// Operator-declared `policy_engine` chain in
    /// [`crate::config::governance.policy.engine`] order. Walked
    /// at every runtime decision point via
    /// [`PluginRegistry::evaluate_policy_chain`]. Empty when no
    /// chain is configured → every decision returns
    /// `NotApplicable`, callers fall through to their own
    /// defaults. The chain is computed + cross-checked in
    /// `app::build_plugin_registry::build_policy_chain` (each
    /// entry's resolved engine name is verified registered) so
    /// runtime never sees an entry the operator didn't declare or
    /// that resolves to a missing engine.
    policy_chain: Vec<String>,
    /// Operator-configured runtime quota gate.
    /// `Some` when the `governance-quotas` cargo feature is on AND
    /// `governance.quotas:` declared at least one policy. `None`
    /// otherwise — `evaluate_quotas` short-circuits.
    /// Bootstrap installs the gate via [`Self::set_quota_gate`]
    /// after the runtime is constructed (mirrors the
    /// `set_content_stores` pattern). Hot-swapped on
    /// SIGHUP / reload by `app::reload_config` together with the
    /// `AppState::quota_gate` ArcSwap.
    #[cfg(feature = "governance-quotas")]
    quota_gate: Option<std::sync::Arc<crate::runtime::quota_gate::QuotaGate>>,
    /// Pre-rendered `dev.mcpg/idempotency` capability advertisement
    /// `server/discover` declares under `capabilities.extensions[…]`.
    /// `None` when the `idempotency.enabled` feature flag is off —
    /// discovery then omits the extension entirely so SEP-2133-aware
    /// clients fall through to non-idempotent calls. Populated from
    /// [`crate::config::IdempotencyConfig`] at boot; defaults to `None`
    /// when idempotency is disabled.
    idempotency_capability: Option<serde_json::Value>,
    /// Idempotency record store. Always present — when the feature
    /// is disabled the boot path installs a `NoopIdempotencyStore`
    /// so the dispatcher can hold a stable Arc without
    /// pattern-matching on `Option`. The dispatcher gates access on
    /// `idempotency_capability.is_some()` to keep the no-op cost zero.
    idempotency_store: std::sync::Arc<dyn idempotency::IdempotencyStore>,
    /// Whether MCPG declares the Apps extension in the client
    /// capabilities it sends to federated upstreams, so they emit
    /// UI-enabled tools. Mirrors `apps.federate_upstream` (inherits
    /// `enabled`).
    apps_federate_upstream: bool,
    /// The skills `mcp.skills` serves over the Skills extension. `None`
    /// when no source is configured: the extension is then not declared
    /// and its methods are unknown.
    skills: Option<Arc<skills::SkillCatalog>>,
    /// `mcp.realtime.admission`: the tool asked before, during and after a
    /// caller holds realtime delivery. `None` admits every caller.
    realtime_admission: Option<Arc<admission::RealtimeAdmission>>,
    /// `mcp.configurations.events` of the config this runtime was built
    /// from. Read per request by `server/discover` and the `events/*`
    /// arms, so a reload that turns events on or off takes effect at
    /// once.
    events_config: crate::config::EventsConfig,
    /// Reverse-federation ingress, resolved from
    /// `gateway.server.tunnel_federation`. `Some` lets `tunnel://<name>`
    /// federation upstreams resolve through the relay's federation ingress.
    tunnel_federation: Option<federation::engine::TunnelFederation>,
    /// Entries one page of a list holds (`mcp.list_page_size`).
    list_page_size: usize,
    /// The MCP Events types this runtime's federations imported, as the
    /// federation engine last published them; the events core serves them
    /// beside the configured types.
    federated_events: Arc<tokio::sync::watch::Sender<events::catalog::FederatedEvents>>,
    /// Compiled tighten-only CSP/permission egress policy. `Some` when
    /// Apps is enabled; applied to `_meta.ui` on resource list/read
    /// egress. `None` ⇒ pure passthrough.
    apps_policy: Option<crate::protocol::shared::apps::AppsPolicy>,
    /// Compiled gateway-authored apps, keyed by their
    /// `ui://mcpg/<id>` URI. Empty ⇒ no authored apps. Installed by
    /// [`Self::set_apps_config`] at boot / hot-reload.
    gateway_apps: std::collections::BTreeMap<String, std::sync::Arc<gateway_apps::CompiledApp>>,
    /// L1 credential cache, wrapped in
    /// `ClusteredCredentialCache` when operator config opts in
    /// AND a cluster_backend is bound. Held here so the
    /// (deferred) credential resolver call site at request
    /// dispatch time can reach it via `&self`. Today only the
    /// admin probe + boot logging consume it; binding adapters
    /// are not yet wired.
    pub(crate) credential_cache:
        Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind>,
    /// Operator-configured content store registry.
    /// Multi-provider map keyed by storage id; backs the
    /// `mcpg-resource://<id>/<resource>` branch of the
    /// `resources/read` handler. `None` when the operator opted out
    /// by setting `storage.providers: []` AND no bindings need a
    /// content surface. Bootstrap installs the registry via
    /// [`Self::set_content_stores`] after the runtime is constructed.
    content_stores: Option<Arc<content_store_registry::ContentStoreRegistry>>,
    /// Digest of the `${secret.NAME}` values the config this runtime was
    /// built from resolved with; empty when it referenced none. Installed
    /// via [`Self::set_secrets_digest`] by the boot and reload paths and
    /// reported to the control plane in every status report.
    secrets_digest: String,
    pub(crate) execution_dispatcher: Arc<ExecutionDispatcher>,
    session_store: Arc<dyn SessionStore>,
    jwt_verifier: Option<identity::JwtVerifier>,
    oidc_resolver: Option<std::sync::Arc<oidc::OidcOAuthResolver>>,
    /// Embedded EMA authorization server
    /// (`governance.access.authorization_server`). Installed via
    /// [`Self::set_ema_authorization_server`] after construction.
    ema_authorization_server: Option<std::sync::Arc<authorization_server::AuthorizationServer>>,
    /// DPoP for the access tokens `oidc_oauth` or `jwks` verifies
    /// (`governance.access.dpop`). Installed via
    /// [`Self::set_external_dpop`] after construction.
    external_dpop: Option<std::sync::Arc<authorization_server::ExternalDpop>>,
    /// The Personal Agent Protocol profile
    /// (`governance.access.personal_agent`). Installed via
    /// [`Self::set_personal_agent`] after construction.
    personal_agent: Option<std::sync::Arc<personal_agent::PersonalAgentProfile>>,
    /// The Personal Agent Protocol operations
    /// (`governance.access.personal_agent.operations`). Installed via
    /// [`Self::set_pap_operations`] after construction.
    pap_operations: Option<std::sync::Arc<personal_agent_operations::OperationsService>>,
    /// The gateway's AAuth resource role (`server.aauth_resource_metadata`):
    /// resource-token minting, revocation state, discovery endpoints.
    /// Installed via [`Self::set_aauth_resource`] after construction.
    aauth_resource: Option<std::sync::Arc<aauth_resource::AauthResource>>,
    pipeline_store: std::sync::Arc<dyn pipeline_store::PipelineStore>,
    task_store: std::sync::Arc<dyn task_store::TaskStore>,
    delivery_bus: Arc<dyn DeliveryBus>,
    subscription_store: Arc<dyn SubscriptionStore>,
    pub watch_engine: watch_engine::WatchEngine,
    /// Owns resource subscriptions: the store rows, the watch engine's per-URI
    /// refcounts, and the holders that keep both alive. Every subscribe and
    /// release goes through it, so the three cannot drift apart.
    subscription_service: Arc<subscriptions::SubscriptionService>,
    backend_health: backend_health::BackendHealthMap,
    cancellation_bus: Arc<dyn cancellation_bus::CancellationBus>,
    /// Local `target_id` → cancellation registry. When the
    /// cancellation-bus subscriber (spawned at startup) receives an event
    /// matching a live `target_id` AND the event's principal/session owns
    /// that entry, it cancels the token so the registered in-flight
    /// pipeline/task execution can cooperatively abort at its next check
    /// point. The owner identity travels in each entry so a foreign
    /// principal cannot cancel work it does not own. A config reload hands
    /// the registry to the next runtime, so the work in flight across the
    /// reload stays cancellable.
    cancellation_tokens: Arc<dashmap::DashMap<String, RegisteredCancellation>>,
    /// The bus this runtime tells and hears the ends of sessions on.
    session_fleet: session_fleet::SessionFleet,
    /// What this runtime hears the fleet through: the cancellation
    /// subscriber and the listener for the ends of sessions. Started by
    /// [`Self::start_cluster_listeners`], stopped when a reload retires the
    /// runtime.
    cluster_listeners: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Completion rate limiter: one token bucket per key.
    /// `completion_rate_limit_per_sec` of `None` disables it.
    /// Perf: DashMap avoids Mutex contention on the completion hot path.
    completion_limiter: dashmap::DashMap<String, (u64, std::time::Instant)>,
    completion_rate_limit_per_sec: Option<u64>,
    /// Session rows held per principal on this replica, for the
    /// `max_sessions_per_tenant` cap when the session store keeps no
    /// fleet-wide count. 0 disables the cap.
    tenant_session_counts: dashmap::DashMap<String, usize>,
    max_sessions_per_tenant: usize,
    /// The principal each counted session belongs to, so its count drops
    /// when the session ends.
    session_tenants: dashmap::DashMap<String, String>,
    /// Emit the per-request access log (`request received` / `request
    /// completed`). Default true; `server.access_log = false` suppresses it
    /// to shed two structured-log events per request on hot deployments.
    access_log: bool,
    /// Per-process cursor HMAC key. Session-bound so cursors from one
    /// session cannot be replayed from another.
    cursor_hmac_key: [u8; 32],
    /// Tool-gate human approval state machine. Holds
    /// in-flight `PendingApproval` entries; resolved by
    /// HMAC-signed webhooks, notifier callbacks, and cluster
    /// broadcast. Always present — gateways without notifiers
    /// configured simply never store anything.
    pub(crate) approval_registry: Arc<approvals::ApprovalRegistry>,
    /// Per-tool-call observability hook for the Control Plane.
    /// Default is a no-op recorder; integrators
    /// (e.g. `mcpg --enroll <URL>` running CP-attached) wire a real
    /// recorder via [`set_tool_call_recorder`] at boot. The
    /// dispatch hot path calls this on every tool call.
    pub(crate) tool_call_recorder: cp_metrics::ToolCallRecorderHandle,
    /// Read-only handle to the latest CP-pushed quota status.
    /// Default is a no-op provider; the cp-attached
    /// integrator wires a real one that reads the cp-client's
    /// `ArcSwap<Option<QuotaStatus>>`. Consulted on every tool
    /// dispatch — when `current().exhausted == true`, dispatch
    /// returns 429 with `Retry-After` instead of invoking the
    /// backend — and by MCP Events for the plan's event caps.
    pub(crate) cp_quota_status: cp_quota::QuotaStatusHandle,
    /// Enforces the licence's per-gateway RPS ceiling. Shared across the
    /// process and carried across reloads, so every counted request lands
    /// in the same window ([`Self::admit_plan_rps`]).
    pub(crate) cp_rps_limiter: std::sync::Arc<cp_quota::RpsLimiter>,
    /// What the license gate left running: the gated items this runtime
    /// loaded, which a reload keeps, and the refusal every tool call gets
    /// while a withheld tool gate waits for a licence.
    pub(crate) license_state: std::sync::Arc<crate::license_gate::LicenseRuntimeState>,
    /// Bundle of services [`crate::protocol::Handler`] receives at dispatch
    /// beside the runtime. Installed at boot via
    /// [`Self::set_shared_services`], after the runtime is built, so it
    /// lives in an `ArcSwapOption`.
    pub(crate) shared_services: ArcSwapOption<SharedServices>,

    /// Principal key → the session [`Self::ensure_session`] minted for it
    /// on this replica, so two requests of one principal share a session
    /// (task and subscription continuity) when no synthetic-session key
    /// derives the id. Anonymous callers have no entry.
    pub(crate) session_aliases: dashmap::DashMap<String, String>,
}

impl GatewayRuntime {
    /// Entry point for a diagnostics probe. Emits operation-scoped
    /// metrics (request count, duration histogram).
    #[tracing::instrument(skip(self, context), fields(operation = operation.label()))]
    pub async fn handle_request(
        &self,
        context: RequestContext,
        operation: DiagnosticsOperation,
    ) -> GatewayResponse {
        let start = std::time::Instant::now();
        let operation_label = operation.label();
        self.record_request_received(&context, operation_label);

        let transport_label = transport_label(&context.transport);

        metrics::counter!("mcpg_requests_total", "operation" => operation_label, "transport" => transport_label).increment(1);

        let payload = match operation {
            DiagnosticsOperation::Readiness => {
                GatewayResponsePayload::Readiness(self.readiness_snapshot())
            }
            DiagnosticsOperation::Runtime => {
                GatewayResponsePayload::Runtime(self.runtime_snapshot())
            }
        };

        self.record_request_completed(&context, operation_label);

        let elapsed = start.elapsed().as_secs_f64();
        metrics::histogram!("mcpg_request_duration_seconds", "operation" => operation_label, "transport" => transport_label).record(elapsed);

        GatewayResponse {
            request_id: context.request_id,
            payload,
        }
    }

    /// Entry point for a parsed MCP request or notification. Emits the
    /// same request metrics and access log as [`Self::handle_request`],
    /// then dispatches through [`crate::protocol::Handler`]. Answers
    /// `-32603` while the shared services are not installed (boot
    /// incomplete).
    pub async fn handle_protocol_message(
        &self,
        context: &Arc<RequestContext>,
        message: ProtocolMessage,
    ) -> ProtocolHttpResponse {
        let start = std::time::Instant::now();
        let operation_label = message.label;
        self.record_request_received(context, operation_label);

        let transport_label = transport_label(&context.transport);

        metrics::counter!("mcpg_requests_total", "operation" => operation_label, "transport" => transport_label).increment(1);

        let response = self.dispatch_protocol_message(context, message).await;

        self.record_request_completed(context, operation_label);

        let elapsed = start.elapsed().as_secs_f64();
        metrics::histogram!("mcpg_request_duration_seconds", "operation" => operation_label, "transport" => transport_label).record(elapsed);

        response
    }

    /// Hand `message` to [`crate::protocol::Handler`] with the installed
    /// shared services; a `-32603` envelope while they are not installed.
    async fn dispatch_protocol_message(
        &self,
        context: &Arc<RequestContext>,
        message: ProtocolMessage,
    ) -> ProtocolHttpResponse {
        let Some(services) = self.shared_services.load_full() else {
            tracing::error!(
                request_id = context.request_id.as_str(),
                "handle_protocol_message reached without the shared services installed; \
                 this is a boot ordering bug"
            );
            return protocol_http_error(
                500,
                message.jsonrpc_id,
                -32603,
                "gateway runtime not fully initialized",
                None,
            );
        };
        crate::protocol::Handler
            .dispatch(context, self, message, services.as_ref())
            .await
    }
}

// Surface decoding lives in `runtime/invocation.rs`
// (`decode_prompt_result`, `decode_resource_result`) with strict native
// contracts: a malformed backend response produces a JSON-RPC error.

#[cfg(test)]
mod resume_cancel_ownership_tests {
    use super::sessions::session_owner_matches;
    use super::*;

    #[test]
    fn identified_owner_requires_principal_and_session() {
        // Same principal + same session → owns.
        assert!(resumer_owns_pipeline(
            Some("alice"),
            "sess-1",
            Some("alice"),
            Some("sess-1"),
        ));
        // Same principal, different session → denied.
        assert!(!resumer_owns_pipeline(
            Some("alice"),
            "sess-1",
            Some("alice"),
            Some("sess-2"),
        ));
        // Different principal → denied even with the same session.
        assert!(!resumer_owns_pipeline(
            Some("alice"),
            "sess-1",
            Some("bob"),
            Some("sess-1"),
        ));
        // Identified owner with a missing resumer session → denied.
        assert!(!resumer_owns_pipeline(
            Some("alice"),
            "sess-1",
            Some("alice"),
            None,
        ));
    }

    #[test]
    fn anonymous_owner_is_matched_by_principal_alone() {
        // Anonymous owner + anonymous resumer (session ignored) → owns.
        assert!(resumer_owns_pipeline(None, "", None, Some("whatever")));
        assert!(resumer_owns_pipeline(None, "ephemeral", None, None));
        // An identified resumer cannot claim an anonymous pipeline.
        assert!(!resumer_owns_pipeline(None, "", Some("alice"), Some("s")));
    }

    fn registered(
        owner_principal: Option<&str>,
        owner_session: Option<&str>,
    ) -> RegisteredCancellation {
        RegisteredCancellation {
            token: tokio_util::sync::CancellationToken::new(),
            owner_session: owner_session.map(str::to_owned),
            owner_principal: owner_principal.map(str::to_owned),
        }
    }

    fn cancel_event(
        principal_id: Option<&str>,
        session_id: &str,
    ) -> cancellation_bus::CancellationEvent {
        cancellation_bus::CancellationEvent {
            target_id: "t-1".to_owned(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id: session_id.to_owned(),
            principal_id: principal_id.map(str::to_owned),
            reason: None,
        }
    }

    #[test]
    fn cancellation_requires_owning_principal_and_session() {
        let owner = registered(Some("alice"), Some("sess-1"));
        // Owner cancels own work.
        assert!(cancellation_requester_is_owner(
            &owner,
            &cancel_event(Some("alice"), "sess-1"),
        ));
        // Foreign principal cannot cancel.
        assert!(!cancellation_requester_is_owner(
            &owner,
            &cancel_event(Some("bob"), "sess-1"),
        ));
        // Same principal, foreign session cannot cancel.
        assert!(!cancellation_requester_is_owner(
            &owner,
            &cancel_event(Some("alice"), "sess-2"),
        ));
    }

    #[test]
    fn anonymous_cancellation_is_matched_by_principal_alone() {
        let owner = registered(None, None);
        assert!(cancellation_requester_is_owner(
            &owner,
            &cancel_event(None, "any-session"),
        ));
        // An identified requester cannot cancel anonymous work.
        assert!(!cancellation_requester_is_owner(
            &owner,
            &cancel_event(Some("alice"), "any-session"),
        ));
    }

    #[test]
    fn session_owner_binding_requires_principal_match() {
        // Identified owner: only the same principal matches.
        assert!(session_owner_matches(Some("alice"), Some("alice")));
        assert!(!session_owner_matches(Some("alice"), Some("bob")));
        // An anonymous caller cannot claim an identified-owned session.
        assert!(!session_owner_matches(Some("alice"), None));
        // An identified caller cannot claim an anonymous-owned session.
        assert!(!session_owner_matches(None, Some("alice")));
        // Anonymous owner + anonymous caller match (residual: any
        // anonymous caller — anonymous sessions carry no privileged id).
        assert!(session_owner_matches(None, None));
    }

    fn test_runtime() -> Arc<GatewayRuntime> {
        Arc::new(GatewayRuntime::new(
            "mcpg",
            "0.1.0",
            "127.0.0.1:8787",
            "/health",
            "/mcp",
            "info",
            vec![crate::config::SinkConfig {
                kind: "stdout".to_owned(),
                config: serde_json::json!({"format": "json"}),
                level: None,
            }],
            true,
        ))
    }

    fn idle_end(session_id: &str, recorded: bool) -> EndedSession {
        EndedSession {
            session_id: session_id.to_owned(),
            reason: session_store::SessionEndReason::IdleExpired,
            recorded,
            snapshot: None,
        }
    }

    /// Seed the principal count a live session `sid` of `tenant` holds.
    fn count_session(runtime: &GatewayRuntime, sid: &str, tenant: &str) {
        runtime.tenant_session_counts.insert(tenant.to_owned(), 1);
        runtime
            .session_tenants
            .insert(sid.to_owned(), tenant.to_owned());
    }

    #[test]
    fn on_session_end_runs_cleanup_cascade() {
        // Idle eviction runs the same per-session cleanup as an explicit
        // terminate: it releases the principal's count, else the principal
        // hard-locks at its cap.
        let runtime = test_runtime();
        let sid = "evict-me";
        count_session(&runtime, sid, "tenant-a");

        // The store holds no live session under this id, so the cascade runs.
        assert!(!runtime.session_store.contains_active_session(sid));
        runtime.on_session_end(&idle_end(sid, true));

        assert!(
            !runtime.session_tenants.contains_key(sid),
            "tenant mapping must be released on idle eviction"
        );
        assert!(
            !runtime.tenant_session_counts.contains_key("tenant-a"),
            "tenant counter must be decremented (and pruned at zero)"
        );
    }

    /// A replica that did not record the end drops what it keeps for the
    /// session too: the replica that served it may not be the one that ended
    /// it.
    #[test]
    fn an_end_recorded_elsewhere_still_cleans_up_here() {
        let runtime = test_runtime();
        let sid = "ended-elsewhere";
        count_session(&runtime, sid, "tenant-c");
        runtime.on_session_end(&idle_end(sid, false));
        assert!(!runtime.session_tenants.contains_key(sid));
        assert!(!runtime.tenant_session_counts.contains_key("tenant-c"));
    }

    #[test]
    fn on_session_end_skips_reused_live_session() {
        // If a live session now holds the evicted id (a principal-derived id
        // was derived again), its id-keyed state is legitimate and must NOT
        // be wiped.
        let runtime = test_runtime();
        let snap = runtime.session_store.create_session_with_id("reused-id");
        assert_eq!(snap.session_id, "reused-id");
        runtime
            .session_tenants
            .insert("reused-id".to_owned(), "tenant-b".to_owned());
        runtime
            .tenant_session_counts
            .insert("tenant-b".to_owned(), 1);

        // A stale eviction for the same id arrives after re-creation.
        runtime.on_session_end(&idle_end("reused-id", true));

        assert!(
            runtime.session_tenants.contains_key("reused-id"),
            "a live re-created session's state must survive a stale eviction"
        );
        assert!(runtime.tenant_session_counts.contains_key("tenant-b"));
    }

    /// A context of `identity` bound to `session_id`.
    fn context_in(session_id: &str, identity: RequestIdentity) -> RequestContext {
        let mut context =
            RequestContext::new(GatewayRequestId::new(), None, identity, TransportKind::Http);
        context.session_id = Some(session_id.to_owned());
        context
    }

    fn suspended_anonymous_pipeline(
        session_id: &str,
        jsonrpc_id: Value,
    ) -> pipeline_store::PipelineExecutionState {
        pipeline_store::PipelineExecutionState {
            pipeline_id: GatewayRequestId::new().as_str().to_owned(),
            session_id: session_id.to_owned(),
            original_jsonrpc_id: jsonrpc_id,
            tool_name: "t".to_owned(),
            steps: vec![],
            current_step_index: 0,
            completed_steps: std::collections::BTreeMap::new(),
            original_args: serde_json::json!({}),
            request_context: context_in(
                session_id,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
            ),
            created_at: chrono::Utc::now(),
            suspended_at: Some(chrono::Utc::now()),
            pipeline_timeout_ms: 300_000,
            pending_server_request_id: Some("srv-req-1".to_owned()),
            elicitation_timeout_ms: Some(60_000),
            related_task_id: None,
            client_capabilities: crate::protocol::ClientCapabilities::default(),
            state_version: 1,
            surface: pipeline_store::PipelineSurface::Tool,
        }
    }

    /// Cancelling a SUSPENDED pipeline (no live token on any replica) must
    /// reach the persisted state: claim it and delete the state + pending
    /// request, so a later resume finds nothing to drive.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_suspended_pipeline_claims_and_deletes() {
        let runtime = test_runtime();
        let state = suspended_anonymous_pipeline("sess-c", Value::Number(7.into()));
        let pipeline_id = state.pipeline_id.clone();
        runtime.pipeline_store.save_pipeline(&state).unwrap();
        runtime
            .pipeline_store
            .save_pending_server_request(&pipeline_store::PendingServerRequest {
                server_request_id: "srv-req-1".to_owned(),
                pipeline_id: pipeline_id.clone(),
                session_id: "sess-c".to_owned(),
                step_id: "s".to_owned(),
                timeout_ms: 60_000,
                created_at: chrono::Utc::now(),
            })
            .unwrap();

        // Anonymous cancel for the same session + rendered id "7".
        let event = cancellation_bus::CancellationEvent {
            target_id: "7".to_owned(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id: "sess-c".to_owned(),
            principal_id: None,
            reason: Some("user".to_owned()),
        };
        runtime.cancel_suspended_pipeline(&event).await;

        // State + pending request are gone.
        assert!(
            runtime
                .pipeline_store
                .load_pipeline(&pipeline_id)
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .pipeline_store
                .load_pending_server_request("srv-req-1")
                .unwrap()
                .is_none()
        );
    }

    /// A cancel from a different (identified) requester must not cancel an
    /// anonymous-owned suspended pipeline.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_suspended_pipeline_rejects_foreign_requester() {
        let runtime = test_runtime();
        let state = suspended_anonymous_pipeline("sess-d", Value::Number(8.into()));
        let pipeline_id = state.pipeline_id.clone();
        runtime.pipeline_store.save_pipeline(&state).unwrap();

        let event = cancellation_bus::CancellationEvent {
            target_id: "8".to_owned(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id: "sess-d".to_owned(),
            principal_id: Some("mallory".to_owned()),
            reason: None,
        };
        runtime.cancel_suspended_pipeline(&event).await;

        // The anonymous pipeline survives a foreign-principal cancel.
        assert!(
            runtime
                .pipeline_store
                .load_pipeline(&pipeline_id)
                .unwrap()
                .is_some()
        );
    }

    /// An IDENTIFIED (Verified) principal that suspended on one replica must be
    /// recognised as the owner when its `notifications/cancelled` lands on
    /// another — the event carries the raw `principal_id`, so the owner check
    /// must compare on the same key (not the trust-qualified synthetic key).
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_suspended_pipeline_owned_by_identified_principal_is_authorized() {
        let runtime = test_runtime();
        let mut state = suspended_anonymous_pipeline("sess-e", Value::Number(9.into()));
        // Re-stamp the persisted owner as a Verified principal `alice`.
        state.request_context = context_in(
            "sess-e",
            RequestIdentity::Verified {
                subject_id: "alice".to_owned(),
                issuer: "iss".to_owned(),
                auth_provider: "prov".to_owned(),
                source: "test".to_owned(),
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            },
        );
        let pipeline_id = state.pipeline_id.clone();
        runtime.pipeline_store.save_pipeline(&state).unwrap();

        // Same raw principal id + same session → authorized → cancelled.
        let event = cancellation_bus::CancellationEvent {
            target_id: "9".to_owned(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id: "sess-e".to_owned(),
            principal_id: Some("alice".to_owned()),
            reason: Some("user abort".to_owned()),
        };
        runtime.cancel_suspended_pipeline(&event).await;

        assert!(
            runtime
                .pipeline_store
                .load_pipeline(&pipeline_id)
                .unwrap()
                .is_none(),
            "identified owner's cross-replica cancel must delete the suspended pipeline"
        );
    }
}

#[cfg(test)]
mod request_scoped_meta_tests {
    use super::*;
    use crate::protocol::v_2026_07_28::wire::meta::LogLevel;
    use serde_json::json;

    // --- progress token: the namespaced key, else the bare one ---

    #[test]
    fn progress_token_read_from_namespaced_key() {
        let meta = json!({ "io.modelcontextprotocol/progressToken": "p-9" });
        let tok = extract_request_progress_token(Some(&meta)).unwrap();
        assert_eq!(tok, Some(json!("p-9")));
    }

    #[test]
    fn progress_token_falls_back_to_bare_key() {
        let meta = json!({ "progressToken": 7 });
        let tok = extract_request_progress_token(Some(&meta)).unwrap();
        assert_eq!(tok, Some(json!(7)));
    }

    #[test]
    fn malformed_progress_token_is_rejected() {
        let meta = json!({ "progressToken": { "bad": true } });
        assert!(extract_request_progress_token(Some(&meta)).is_err());
    }

    // --- log level (SEP-2575): namespaced ---

    #[test]
    fn log_level_parsed_from_namespaced_key() {
        let meta = json!({ "io.modelcontextprotocol/logLevel": "warning" });
        let lvl = extract_request_log_level(Some(&meta)).unwrap();
        assert_eq!(lvl, Some(LogLevel::Warning));
    }

    #[test]
    fn log_level_absent_is_none() {
        // None ⇒ the emission site applies the spec MUST (suppress all).
        let meta = json!({});
        assert_eq!(extract_request_log_level(Some(&meta)).unwrap(), None);
        assert_eq!(extract_request_log_level(None).unwrap(), None);
    }

    #[test]
    fn malformed_log_level_is_rejected() {
        let bad_str = json!({ "io.modelcontextprotocol/logLevel": "louder" });
        assert!(extract_request_log_level(Some(&bad_str)).is_err());
        let bad_type = json!({ "io.modelcontextprotocol/logLevel": 3 });
        assert!(extract_request_log_level(Some(&bad_type)).is_err());
    }

    #[test]
    fn log_level_permits_at_or_above_threshold() {
        // At/above the floor → emitted; below → suppressed.
        assert!(LogLevel::Warning.permits(LogLevel::Info)); // above
        assert!(LogLevel::Info.permits(LogLevel::Info)); // at
        assert!(!LogLevel::Debug.permits(LogLevel::Info)); // below
        assert!(LogLevel::Emergency.permits(LogLevel::Debug)); // far above
    }
}

#[cfg(test)]
mod tests;
