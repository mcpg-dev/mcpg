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
mod execution;
pub(crate) mod expr;
pub(crate) mod feature_flags;
pub(crate) mod federation;
pub(crate) mod gateway_apps;
mod handlers;
pub mod idempotency;
pub mod identity;
pub mod inspector_identity;
pub(crate) use identity::identity_plugin;
pub use identity::oidc;
pub mod invocation;
pub mod message_dispatcher;
pub mod ping_driver;
pub(crate) mod policy;
#[cfg(feature = "governance-quotas")]
pub mod quota_gate;
pub mod reapers;
pub(crate) use reapers::reaper_leadership;
pub use reapers::{pipeline_reaper, task_reaper};
pub mod redact;
pub mod safe_dns;
mod seen_request_ids;
pub mod shared_services;
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
mod streaming;
pub mod subscriptions;
mod types;
mod util;
pub mod watch_engine;
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
use crate::protocol::registry::ProtocolRegistry;
use crate::protocol::shared::messages::ProtocolMessage;
use crate::protocol::{
    BlobResourceContents, CapabilityFlag, CapabilityOperation, CompletionResult, EmptyResult,
    ImplementationInfo, InitializeResult, JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody,
    JsonRpcSuccess, LifecycleOperation, ListCapability, LoggingOperation, PromptGetResult,
    PromptMessage, PromptMessageContent, PromptsListResult, ProtocolHttpResponse,
    ProtocolOperation, ProtocolResponse, ResourceCapability, ResourceContents, ResourceReadResult,
    ResourceTemplatesListResult, ResourceTextContents, ResourcesListResult, SESSION_ID_HEADER,
    SUPPORTED_PROTOCOL_VERSION, ServerCapabilities, TaskOperation, TasksCapability,
    TasksListResult, ToolsListResult,
};
use crate::runtime::shared_services::SharedServices;

use cursor::{
    CompositeCursor, DynCursor, decode_composite_cursor, decode_cursor, encode_composite_cursor,
    encode_cursor, paginate_list_bound,
};
use delivery_bus::DeliveryBus;
use execution::{BackendInvocationRequest, ExecutionDispatcher};
pub use execution::{CommandToolRuntimeConfig, NetworkToolRuntimeConfig, RuntimeDebugConfig};
use handlers::modern_task_status_notification;
use policy::{PreDispatchPolicyGate, PreDispatchPolicyOutcome, ToolPolicyContext};
pub use policy::{ToolAccessPolicyConfig, ToolTrustRule};
use seen_request_ids::{
    RegisteredCancellation, SeenRequestIds, cancellation_requester_is_owner, resumer_owns_pipeline,
    session_owner_matches,
};
use session_store::{SessionAccessError, SessionStore};
pub use session_store::{SessionSnapshot, SessionStoreConfig, SseEventRecord, StreamAccessError};
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
        static EMPTY: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
            std::sync::OnceLock::new();
        match self {
            RequestIdentity::Verified { attributes, .. } => attributes,
            _ => EMPTY.get_or_init(std::collections::BTreeMap::new),
        }
    }
}

/// Serde default for `RequestContext::negotiated_version` — the
/// registry's compile-time default. Used both for fresh
/// constructions and for in-place deserialization of contexts
/// persisted before the field was added.
fn default_negotiated_version() -> crate::protocol::version::ProtocolVersion {
    crate::protocol::registry::ProtocolRegistry::COMPILE_TIME_DEFAULT
}

/// Per-request metadata carried through the entire gateway pipeline: identity,
/// session binding, transport origin, and timing. Built once at intake and
/// threaded immutably into every downstream operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: GatewayRequestId,
    pub upstream_request_id: Option<String>,
    pub session_id: Option<String>,
    pub resume_cursor: Option<ResumeCursor>,
    pub identity: RequestIdentity,
    pub transport: TransportKind,
    pub started_at: DateTime<Utc>,
    /// Protocol revision negotiated for this request. Stamped by
    /// the transport after `ProtocolRegistry::select(...)`; threaded
    /// through `handle_protocol_operation` so version-blind code
    /// paths can branch on it (e.g., MRTR's `InputRequiredResult`
    /// inline body vs the legacy SSE+202 suspension envelope).
    /// Defaults to the registry's `COMPILE_TIME_DEFAULT`
    /// (`V_2025_11_25`) when constructed outside the transport
    /// (tests, stdio).
    #[serde(default = "default_negotiated_version")]
    pub negotiated_version: crate::protocol::version::ProtocolVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<crate::transports::TraceContext>,
    /// SEP-2575 stateless: per-request client capabilities the modern
    /// wire carries in `_meta.io.modelcontextprotocol/clientCapabilities`.
    /// Populated by the transport on parse and consulted by
    /// `client_capabilities_for_context` ahead of the session-derived
    /// caps. `None` ⇒ fall back to session caps (the legacy default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modern_request_capabilities: Option<crate::protocol::ClientCapabilities>,
    /// Raw inbound bearer token (from `Authorization: Bearer …`),
    /// captured by the HTTP transport for `auth.mode: pass_through`
    /// federation dispatch. `#[serde(skip)]` — kept in-memory only,
    /// never persisted (pipeline store) or logged.
    #[serde(skip)]
    pub inbound_bearer: Option<String>,
    /// The session id was minted for this request only and has NO row in
    /// the session store: `load_session_cached` is pre-seeded with a
    /// synthetic Operational snapshot, and every session-keyed structure
    /// (deliveries, request-id dedup, cancellation) works on the id
    /// string alone. Continuation points (task materialization, MRTR
    /// suspension, `subscriptions/listen`) create the real row on demand
    /// via `GatewayRuntime::materialize_ephemeral_session`. Anonymous
    /// modern stateless requests run this way so sustained traffic
    /// performs zero session-store operations.
    #[serde(default)]
    pub session_ephemeral: bool,
    // Per-request session-snapshot cache. The first `load_session_cached`
    // call populates the OnceLock; subsequent calls within the same
    // request lifecycle skip the SessionStore Mutex / Redis RTT.
    // `Arc<OnceLock<...>>` so a Clone of RequestContext shares the cache —
    // continuations that build a fresh `RequestContext::new` start with a
    // fresh empty cache (correct: a continuation is logically a new
    // request, even if it inherits identity/session_id).
    #[serde(skip)]
    cached_session: Arc<OnceLock<Result<Arc<SessionSnapshot>, SessionAccessError>>>,
}

impl RequestContext {
    pub fn new(
        request_id: GatewayRequestId,
        upstream_request_id: Option<String>,
        session_id: Option<String>,
        resume_cursor: Option<ResumeCursor>,
        identity: RequestIdentity,
        transport: TransportKind,
    ) -> Self {
        Self {
            request_id,
            upstream_request_id,
            session_id,
            resume_cursor,
            identity,
            transport,
            started_at: Utc::now(),
            negotiated_version: default_negotiated_version(),
            trace_context: None,
            modern_request_capabilities: None,
            inbound_bearer: None,
            session_ephemeral: false,
            cached_session: Arc::new(OnceLock::new()),
        }
    }

    /// Bind this context to an ephemeral (row-less) session: the id is
    /// installed and the per-request session cache is pre-seeded with the
    /// synthetic snapshot, so every `load_session_cached` call resolves
    /// without touching the session store.
    pub(crate) fn with_ephemeral_session(mut self, snapshot: SessionSnapshot) -> Self {
        self.session_id = Some(snapshot.session_id.clone());
        self.session_ephemeral = true;
        let cache = OnceLock::new();
        let _ = cache.set(Ok(Arc::new(snapshot)));
        self.cached_session = Arc::new(cache);
        self
    }

    /// Override the negotiated protocol version. Transports call
    /// this after `ProtocolRegistry::select(...)` resolves the
    /// inbound version to a handler.
    pub fn with_negotiated_version(
        mut self,
        version: crate::protocol::version::ProtocolVersion,
    ) -> Self {
        self.negotiated_version = version;
        self
    }

    /// Install the per-request `_meta.io.modelcontextprotocol/clientCapabilities`
    /// for modern stateless requests. The runtime's
    /// `client_capabilities_for_context` prefers this value over the
    /// session-bound capabilities so each modern call announces its
    /// own surface (the synthetic session minted for stateless
    /// traffic carries empty caps).
    pub fn with_modern_request_capabilities(
        mut self,
        capabilities: crate::protocol::ClientCapabilities,
    ) -> Self {
        self.modern_request_capabilities = Some(capabilities);
        self
    }

    /// Capture the raw inbound bearer for `pass_through` federation
    /// dispatch. Stored in-memory only (serde-skipped).
    pub fn with_inbound_bearer(mut self, bearer: Option<String>) -> Self {
        self.inbound_bearer = bearer;
        self
    }

    /// Load the session snapshot bound to this request's `session_id`,
    /// caching the underlying lookup so repeat calls within the same
    /// request lifecycle skip the SessionStore Mutex round-trip
    /// (in-memory) or network RTT (Redis/NATS). The first call drives
    /// the underlying `store.load_session(session_id, false)` (raw
    /// shape, ignoring `require_operational`); each call applies its
    /// own `require_operational` filter against the cached snapshot's
    /// `phase`. Errors (`MissingSessionId`, `UnknownSession`) are
    /// cached too — re-asking the store would yield the same answer.
    ///
    /// **Side-effect note.** The cached path skips the in-memory
    /// store's `session.touch()` + `persist_session()` for subsequent
    /// reads. This is intentional: a single MCP request issuing N
    /// internal capability lookups should count as one session
    /// "touch", not N. The first `load_session_cached` per request
    /// performs the touch; later reads serve from cache.
    ///
    /// Returns owned `SessionSnapshot` (cloned from the cached `Arc`)
    /// to match the existing `SessionStore::load_session` API; future
    /// API churn could return `Arc<SessionSnapshot>` to drop the clone
    /// cost as well.
    pub(crate) fn load_session_cached(
        &self,
        store: &dyn SessionStore,
        require_operational: bool,
    ) -> Result<SessionSnapshot, SessionAccessError> {
        // Populate the cache on first miss. `OnceLock::get_or_init`
        // takes `FnOnce() -> T`, so we map the store call into the
        // cached `Result<Arc<SessionSnapshot>, _>` shape directly.
        let cached = self.cached_session.get_or_init(|| {
            store
                .load_session(self.session_id.as_deref(), false)
                .map(Arc::new)
        });
        match cached {
            Ok(snap) => {
                if require_operational && snap.phase != session_store::SessionPhase::Operational {
                    Err(SessionAccessError::NotInitialized)
                } else {
                    Ok((**snap).clone())
                }
            }
            Err(e) => Err(e.clone()),
        }
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
            roles: self.identity.roles().to_vec(),
            groups: self.identity.groups().to_vec(),
            scopes: self.identity.scopes().to_vec(),
            attributes: self.identity.attributes().clone(),
        }
    }

    /// Owner key for task authorization (SEP-2663 / CPN-4). Binds a
    /// task to the request **principal** so a task created on one
    /// cluster replica is pollable from another (the principal is the
    /// same everywhere; the per-replica synthetic session is not).
    /// Falls back to the session id only for anonymous callers that
    /// have no stable principal — those tasks remain per-replica
    /// (documented residual; an anonymous caller cannot federate its
    /// own task across instances because it presents no stable
    /// identity).
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

/// Opaque cursor from the `Last-Event-Id` SSE header, enabling stream resumption
/// after a disconnect without replaying already-delivered events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeCursor {
    pub last_event_id: String,
}

/// Fully-resolved gateway request ready for dispatch to the runtime.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayRequest {
    pub context: RequestContext,
    pub operation: GatewayOperation,
}

impl GatewayRequest {
    pub fn new(context: RequestContext, operation: GatewayOperation) -> Self {
        Self { context, operation }
    }
}

/// Top-level operation discriminant: either a diagnostics probe or an MCP protocol operation.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatewayOperation {
    Diagnostics(DiagnosticsOperation),
    Protocol(ProtocolOperation),
}

impl GatewayOperation {
    pub fn label(&self) -> &'static str {
        match self {
            GatewayOperation::Diagnostics(DiagnosticsOperation::Readiness) => {
                "diagnostics.readiness"
            }
            GatewayOperation::Diagnostics(DiagnosticsOperation::Runtime) => "diagnostics.runtime",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize { .. },
            )) => "protocol.lifecycle.initialize",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )) => "protocol.lifecycle.initialized",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Ping { .. },
            )) => "protocol.lifecycle.ping",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::NotificationAccepted,
            )) => "protocol.lifecycle.notification_accepted",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::NotificationCancelled { .. },
            )) => "protocol.lifecycle.notification_cancelled",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::ElicitationComplete { .. },
            )) => "protocol.lifecycle.elicitation_complete",
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::RootsListChanged,
            )) => "protocol.lifecycle.roots_list_changed",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsList { .. },
            )) => "protocol.capabilities.tools_list",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::PromptsList { .. },
            )) => "protocol.capabilities.prompts_list",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::PromptsGet { .. },
            )) => "protocol.capabilities.prompts_get",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesList { .. },
            )) => "protocol.capabilities.resources_list",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesRead { .. },
            )) => "protocol.capabilities.resources_read",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesSubscribe { .. },
            )) => "protocol.capabilities.resources_subscribe",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesUnsubscribe { .. },
            )) => "protocol.capabilities.resources_unsubscribe",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesTemplatesList { .. },
            )) => "protocol.capabilities.resources_templates_list",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsCall { .. },
            )) => "protocol.capabilities.tools_call",
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::Complete { .. },
            )) => "protocol.capabilities.completion_complete",
            GatewayOperation::Protocol(ProtocolOperation::Tasks(TaskOperation::Get { .. })) => {
                "protocol.tasks.get"
            }
            GatewayOperation::Protocol(ProtocolOperation::Tasks(TaskOperation::Result {
                ..
            })) => "protocol.tasks.result",
            GatewayOperation::Protocol(ProtocolOperation::Tasks(TaskOperation::Cancel {
                ..
            })) => "protocol.tasks.cancel",
            GatewayOperation::Protocol(ProtocolOperation::Tasks(TaskOperation::List {
                ..
            })) => "protocol.tasks.list",
            GatewayOperation::Protocol(ProtocolOperation::Logging(
                LoggingOperation::SetLevel { .. },
            )) => "protocol.logging.set_level",
            GatewayOperation::Protocol(ProtocolOperation::ServerRequestResponse { .. }) => {
                "protocol.server_request_response"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsOperation {
    Readiness,
    Runtime,
}

/// Gateway response envelope pairing the originating request ID with the response payload.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayResponse {
    pub request_id: GatewayRequestId,
    pub payload: GatewayResponsePayload,
}

/// Discriminated response body: readiness/runtime diagnostics or an MCP protocol HTTP response.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum GatewayResponsePayload {
    Readiness(ReadinessSnapshot),
    Runtime(RuntimeSnapshot),
    Protocol(ProtocolHttpResponse),
}

/// Central gateway runtime holding all shared state: session store, capability
/// registry, plugin chain, execution dispatcher, and cluster infrastructure.
/// Built once at startup and shared via `Arc` across all request handlers.
///
/// Session lifecycle: create (Initialize) -> initialized (notifications/initialized)
/// -> operational (all capability methods) -> terminated (DELETE or idle timeout).
/// The session store tracks the current phase; requests against a non-operational
/// session receive a protocol error.
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
    /// When true, session-scoped HTTP operations (GET→SSE, DELETE,
    /// subscriptions, POST→SSE continuation) require the caller's
    /// principal to match the session's creator. Opt-in (default false).
    /// Wired from `sessions.bind_session_owner` at boot + reload.
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
    /// the initialize handler embeds under
    /// `result.capabilities.extensions[…]`. `None` when the
    /// `idempotency.enabled` feature flag is off — the handshake
    /// then omits the extension entirely so SEP-2133-aware clients
    /// fall through to non-idempotent calls. Populated from
    /// [`crate::config::IdempotencyConfig`] at boot; defaults to `None`
    /// when idempotency is disabled.
    idempotency_capability: Option<serde_json::Value>,
    /// Idempotency record store. Always present — when the feature
    /// is disabled the boot path installs a `NoopIdempotencyStore`
    /// so the dispatcher can hold a stable Arc without
    /// pattern-matching on `Option`. The dispatcher gates access on
    /// `idempotency_capability.is_some()` to keep the no-op cost zero.
    idempotency_store: std::sync::Arc<dyn idempotency::IdempotencyStore>,
    /// Pre-rendered `io.modelcontextprotocol/ui` (SEP-1865 MCP Apps)
    /// capability advertisement embedded under
    /// `result.capabilities.extensions[…]` on the legacy `initialize`
    /// handshake. `None` when `mcp.configurations.apps.enabled` is off
    /// (the handshake then omits the extension). Populated from
    /// [`crate::config::apps::AppsConfig`] at boot. The modern
    /// `server/discover` builder reads the config snapshot directly
    /// instead (see `build_discover_result`).
    apps_capability: Option<serde_json::Value>,
    /// Whether MCPG advertises the Apps capability on its outgoing
    /// (client→upstream) `initialize`, so federated servers emit
    /// UI-enabled tools. Mirrors
    /// `apps.federate_upstream` (inherits `enabled`).
    apps_federate_upstream: bool,
    /// Reverse-federation ingress, resolved from
    /// `gateway.server.tunnel_federation`. `Some` lets `tunnel://<name>`
    /// federation upstreams resolve through the relay's federation ingress.
    tunnel_federation: Option<federation::engine::TunnelFederation>,
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
    pub(crate) execution_dispatcher: Arc<ExecutionDispatcher>,
    session_store: Arc<dyn SessionStore>,
    jwt_verifier: Option<identity::JwtVerifier>,
    oidc_resolver: Option<std::sync::Arc<oidc::OidcOAuthResolver>>,
    /// Embedded EMA authorization server
    /// (`governance.access.authorization_server`). Installed via
    /// [`Self::set_ema_authorization_server`] after construction.
    ema_authorization_server: Option<std::sync::Arc<authorization_server::AuthorizationServer>>,
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
    /// refcounts, and the holders that keep both alive. Every subscribe /
    /// unsubscribe on either wire goes through it, so the three cannot drift
    /// apart.
    subscription_service: Arc<subscriptions::SubscriptionService>,
    backend_health: backend_health::BackendHealthMap,
    cancellation_bus: Arc<dyn cancellation_bus::CancellationBus>,
    /// Local `target_id` → cancellation registry. When the
    /// cancellation-bus subscriber (spawned at startup) receives an event
    /// matching a live `target_id` AND the event's principal/session owns
    /// that entry, it cancels the token so the registered in-flight
    /// pipeline/task execution can cooperatively abort at its next check
    /// point. The owner identity travels in each entry so a foreign
    /// principal cannot cancel work it does not own.
    cancellation_tokens: Arc<dashmap::DashMap<String, RegisteredCancellation>>,
    /// Per-session completion rate limiter. `None` means disabled.
    /// Perf: DashMap avoids Mutex contention on the tools/call hot path.
    completion_limiter: dashmap::DashMap<String, (u64, std::time::Instant)>,
    completion_rate_limit_per_sec: Option<u64>,
    /// Per-tenant active-session counter. 0 disables the cap.
    /// Perf: DashMap for lock-free reads during initialize.
    tenant_session_counts: dashmap::DashMap<String, usize>,
    max_sessions_per_tenant: usize,
    /// Tracks which tenant owns a session for counter decrement on terminate.
    session_tenants: dashmap::DashMap<String, String>,
    /// Per-session set of seen client request ids. Duplicate ids are
    /// rejected. Bounded per session — oldest ids age out when full.
    /// Perf: DashMap avoids global Mutex contention; each session's
    /// window is only accessed by that session's request path, and
    /// membership is an O(1) HashSet lookup (the VecDeque only orders
    /// FIFO eviction).
    seen_request_ids: dashmap::DashMap<String, SeenRequestIds>,
    /// When true, skip the per-session request-id uniqueness check in
    /// [`Self::record_client_request_id`]. Opt-in, off by default; only
    /// load generators replaying a fixed request body set it (see
    /// `server.relax_request_id_uniqueness`).
    relax_request_id_uniqueness: bool,
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
    /// backend, gated behind the `governance-quotas` feature.
    pub(crate) cp_quota_status: cp_quota::QuotaStatusHandle,
    /// Enforces the licence's per-gateway RPS ceiling. Shared across the
    /// process so every dispatch counts into the same window.
    pub(crate) cp_rps_limiter: std::sync::Arc<cp_quota::RpsLimiter>,
    /// Multi-version protocol dispatcher. Installed at boot via
    /// [`Self::set_protocol_registry`] after the runtime is wrapped
    /// in `ArcSwap` (so we can downgrade the swap handle into
    /// `SharedServices.runtime`). Until installation requests fall
    /// through to the legacy direct path
    /// ([`Self::handle_protocol_operation`]). Once installed,
    /// [`Self::handle_request`]'s Protocol arm routes through
    /// [`crate::protocol::shared::traits::ProtocolHandler::dispatch`].
    ///
    /// Stored via `ArcSwapOption` so post-construction installation
    /// works without `&mut self` (the runtime is already shared by
    /// the time we have a swap handle for `SharedServices` to
    /// downgrade).
    pub(crate) protocol_registry: ArcSwapOption<ProtocolRegistry>,
    /// Bundle of version-blind services handed to every
    /// `ProtocolHandler` during dispatch. Paired with
    /// `protocol_registry` — both populated or both empty. Installed
    /// at boot via [`Self::set_shared_services`].
    pub(crate) shared_services: ArcSwapOption<SharedServices>,

    /// Modern stateless mode — stable mapping from authenticated
    /// principal id → synthetic
    /// session id, so two requests from the same principal land on
    /// the SAME synthetic session and get task / subscription
    /// continuity. Empty for anonymous traffic (which still mints
    /// per-request synthetic sessions; documented gap).
    pub(crate) modern_session_aliases: dashmap::DashMap<String, String>,
}

/// Outcome of [`GatewayRuntime::ensure_modern_session`]: the (possibly
/// session-stamped) context, or an explicit signal that the session store
/// refused a new row (`sessions.max_sessions`) so the transport answers
/// with honest backpressure instead of dispatching against a session that
/// was never stored.
pub(crate) enum ModernSessionOutcome {
    Ready(RequestContext),
    CapacityExhausted,
}

impl GatewayRuntime {
    /// Entry point for all gateway operations. Enforces per-session request-id
    /// uniqueness, then dispatches to diagnostics or protocol handling. Emits
    /// operation-scoped metrics (request count, duration histogram).
    #[tracing::instrument(skip(self, request), fields(operation = request.operation.label()))]
    pub async fn handle_request(&self, request: GatewayRequest) -> GatewayResponse {
        let start = std::time::Instant::now();
        let GatewayRequest { context, operation } = request;
        let operation_label = operation.label();
        self.record_request_received(&context, operation_label);

        let transport_label = match &context.transport {
            TransportKind::Http => "http",
            TransportKind::Stdio => "stdio",
        };

        metrics::counter!("mcpg_requests_total", "operation" => operation_label, "transport" => transport_label).increment(1);

        let payload = match operation {
            GatewayOperation::Diagnostics(DiagnosticsOperation::Readiness) => {
                GatewayResponsePayload::Readiness(self.readiness_snapshot())
            }
            GatewayOperation::Diagnostics(DiagnosticsOperation::Runtime) => {
                GatewayResponsePayload::Runtime(self.runtime_snapshot())
            }
            GatewayOperation::Protocol(protocol_operation) => {
                // reject client-initiated requests whose JSON-RPC
                // id has already been used on the same MCP session.
                if let Some(req_id) = client_request_id(&protocol_operation) {
                    if self
                        .record_client_request_id(
                            context.session_id.as_deref(),
                            context.session_ephemeral,
                            &req_id,
                        )
                        .is_err()
                    {
                        metrics::counter!("mcpg_duplicate_request_id_total").increment(1);
                        GatewayResponsePayload::Protocol(protocol_http_error(
                            400,
                            Some(req_id.clone()),
                            -32600,
                            "duplicate request id on this session",
                            None,
                        ))
                    } else {
                        GatewayResponsePayload::Protocol(
                            self.dispatch_protocol(protocol_operation, &context).await,
                        )
                    }
                } else {
                    GatewayResponsePayload::Protocol(
                        self.dispatch_protocol(protocol_operation, &context).await,
                    )
                }
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

    /// Entry point for already-parsed protocol messages — used by
    /// the modern HTTP transport path where the
    /// version is negotiated *before* parsing so the right
    /// `ProtocolHandler::parse` runs.
    ///
    /// Mirrors [`Self::handle_request`]'s cross-cutting concerns
    /// (metrics, audit, request-id uniqueness) but operates on a
    /// version-erased [`ProtocolMessage`] instead of a legacy
    /// `ProtocolOperation`. Dispatch goes straight to
    /// `handler.dispatch(ctx, message, services)` for the
    /// `message.negotiated_version`; if either the registry or
    /// services are missing (boot incomplete) the caller gets a
    /// `-32603` diagnostic.
    pub async fn handle_protocol_message(
        &self,
        context: RequestContext,
        message: ProtocolMessage,
    ) -> GatewayResponse {
        let start = std::time::Instant::now();
        let operation_label = message.label;
        self.record_request_received(&context, operation_label);

        let transport_label = match &context.transport {
            TransportKind::Http => "http",
            TransportKind::Stdio => "stdio",
        };

        metrics::counter!("mcpg_requests_total", "operation" => operation_label, "transport" => transport_label).increment(1);

        let payload = if let Some(req_id) = message.jsonrpc_id.clone() {
            if self
                .record_client_request_id(
                    context.session_id.as_deref(),
                    context.session_ephemeral,
                    &req_id,
                )
                .is_err()
            {
                metrics::counter!("mcpg_duplicate_request_id_total").increment(1);
                GatewayResponsePayload::Protocol(protocol_http_error(
                    400,
                    Some(req_id),
                    -32600,
                    "duplicate request id on this session",
                    None,
                ))
            } else {
                GatewayResponsePayload::Protocol(
                    self.dispatch_protocol_message(&context, message).await,
                )
            }
        } else {
            GatewayResponsePayload::Protocol(
                self.dispatch_protocol_message(&context, message).await,
            )
        };

        self.record_request_completed(&context, operation_label);

        let elapsed = start.elapsed().as_secs_f64();
        metrics::histogram!("mcpg_request_duration_seconds", "operation" => operation_label, "transport" => transport_label).record(elapsed);

        GatewayResponse {
            request_id: context.request_id,
            payload,
        }
    }

    /// Look up the handler for `message.negotiated_version` in the
    /// registry installed on this runtime, and call its `dispatch`.
    /// `-32603` envelope when registry/services aren't installed or
    /// when no handler is registered for the negotiated version.
    async fn dispatch_protocol_message(
        &self,
        context: &RequestContext,
        message: ProtocolMessage,
    ) -> ProtocolHttpResponse {
        let (Some(registry), Some(services)) = (
            self.protocol_registry.load_full(),
            self.shared_services.load_full(),
        ) else {
            tracing::error!(
                request_id = context.request_id.as_str(),
                "handle_protocol_message reached without registry+services installed; \
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

        let version = message.negotiated_version;
        let Some(handler) = registry.get(version).cloned() else {
            tracing::warn!(
                version = %version,
                "no ProtocolHandler registered for negotiated version"
            );
            return protocol_http_error(
                500,
                message.jsonrpc_id,
                -32603,
                "no handler registered for the negotiated protocol version",
                None,
            );
        };

        handler.dispatch(context, message, services.as_ref()).await
    }

    /// Dispatch a parsed `ProtocolOperation`, routing through the
    /// multi-version `ProtocolRegistry` when one is installed and
    /// falling back to direct
    /// [`Self::handle_protocol_operation`] otherwise (tests and any
    /// path that constructed a `GatewayRuntime` without calling
    /// [`Self::set_protocol_registry`] /
    /// [`Self::set_shared_services`]).
    ///
    /// The registry path is identical in behaviour to the direct
    /// path for the 2025-11-25 handler — the handler downcasts back
    /// to `ProtocolOperation` and calls `handle_protocol_operation`
    /// via the [`SharedServices`] runtime handle. This level of
    /// indirection is the seam that lets a modern handler
    /// (DRAFT-2026-v1) be swapped in without touching the runtime.
    async fn dispatch_protocol(
        &self,
        operation: ProtocolOperation,
        context: &RequestContext,
    ) -> ProtocolHttpResponse {
        let (Some(registry), Some(services)) = (
            self.protocol_registry.load_full(),
            self.shared_services.load_full(),
        ) else {
            // No registry/services installed yet (boot incomplete or
            // a test that didn't wire them). Fall through to the
            // legacy direct-dispatch path so behaviour is preserved
            // for every existing test and call site.
            return self.handle_protocol_operation(operation, context).await;
        };

        // This method's operand is a `v_2025_11_25::ProtocolOperation` (built
        // just below from `map_client_message_to_operation`), so the handler it
        // needs is the legacy one by construction — not whatever the registry
        // currently defaults to. Naming the version explicitly keeps a future
        // change of `COMPILE_TIME_DEFAULT` from routing a legacy operation into
        // the modern handler, where the downcast fails and every stdio request
        // answers -32603.
        let version = crate::protocol::version::ProtocolVersion::V_2025_11_25;
        let Some(handler) = registry.get(version).cloned() else {
            tracing::warn!(
                version = %version,
                "no ProtocolHandler registered for negotiated version; \
                 falling back to direct dispatch"
            );
            return self.handle_protocol_operation(operation, context).await;
        };

        let label = operation.label();
        let jsonrpc_id = operation.client_request_id();
        let message = ProtocolMessage {
            label,
            inner: Box::new(operation),
            jsonrpc_id,
            mcp_method: None,
            negotiated_version: version,
        };
        handler.dispatch(context, message, services.as_ref()).await
    }

    /// Route an MCP protocol operation to the correct handler.
    ///
    /// Lifecycle operations drive the session state machine (initialize -> initialized -> ping/cancel).
    /// Capability operations (tools/call, prompts/get, resources/read, etc.) require an operational
    /// session and go through: schema validation -> rate limit -> policy gate -> plugin chain ->
    /// backend dispatch -> post-dispatch plugins -> response.
    pub(crate) async fn handle_protocol_operation(
        &self,
        operation: ProtocolOperation,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        match operation {
            ProtocolOperation::Lifecycle(operation) => {
                self.handle_lifecycle_operation(operation, request_context)
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ToolsCall {
                request_id,
                params,
            }) => {
                self.handle_tools_call(request_id, params, request_context)
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::Complete {
                request_id,
                params,
            }) => {
                self.handle_completion(request_id, params, request_context)
                    .await
            }
            ProtocolOperation::Capabilities(operation) => {
                self.handle_capabilities_list_operation(operation, request_context)
                    .await
            }
            ProtocolOperation::Tasks(operation) => {
                self.handle_tasks_operation(operation, request_context)
                    .await
            }
            ProtocolOperation::Logging(LoggingOperation::SetLevel { request_id, params }) => {
                let level_label = format!("{:?}", params.level).to_ascii_lowercase();
                match self
                    .session_store
                    .set_session_log_level(request_context.session_id.as_deref(), params.level)
                {
                    Ok(()) => {
                        // Audit: client-driven log-level
                        // change. Optional sensitivity if a future
                        // client uses level changes for adversarial
                        // purposes (lowering verbosity to evade
                        // detection). Cheap to log at typical rates.
                        let event = mcpg_plugin_host::audit_events::logging_level_set_event(
                            plugin_identity_from_request(request_context),
                            request_context.request_id.as_str(),
                            request_context.session_id.as_deref(),
                            &level_label,
                        );
                        let _ = self.plugin_registry.emit_audit_event(&event).await;
                        ProtocolHttpResponse {
                            http_status: 200,
                            session_id_header: None,
                            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id: request_id,
                                result: serde_json::to_value(EmptyResult {})
                                    .expect("empty result serialized"),
                            }),
                        }
                    }
                    Err(error) => {
                        self.map_session_error_to_protocol_response(error, Some(request_id))
                    }
                }
            }
            ProtocolOperation::ServerRequestResponse {
                response_id,
                result,
                error,
            } => match request_context.load_session_cached(&*self.session_store, true) {
                Ok(_session) => {
                    self.handle_server_request_response(request_context, response_id, result, error)
                        .await
                }
                Err(error) => self.map_session_error_to_protocol_response(error, None),
            },
        }
    }
}

// Surface decoding lives in `runtime/invocation.rs`
// (`decode_prompt_result`, `decode_resource_result`) with strict native
// contracts: a malformed backend response produces a JSON-RPC error.

#[cfg(test)]
mod resume_cancel_ownership_tests {
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

    #[test]
    fn on_session_evicted_runs_cleanup_cascade() {
        // Idle eviction of a session whose client never sent DELETE must run
        // the same per-session cleanup as explicit terminate: release the
        // tenant quota slot (else the tenant hard-locks) and drop the
        // request-id tracker (else it leaks one entry per idle session).
        let runtime = test_runtime();
        let sid = "evict-me";

        // Seed the id-keyed runtime state a live session would hold.
        runtime
            .tenant_session_counts
            .insert("tenant-a".to_owned(), 1);
        runtime
            .session_tenants
            .insert(sid.to_owned(), "tenant-a".to_owned());
        let _ = runtime.record_client_request_id(Some(sid), false, &serde_json::json!("req-1"));
        assert!(runtime.seen_request_ids.contains_key(sid));
        assert!(runtime.session_tenants.contains_key(sid));

        // The store holds no live session under this id, so the cascade runs.
        assert!(!runtime.session_store.contains_active_session(sid));
        runtime.on_session_evicted(sid);

        assert!(
            !runtime.session_tenants.contains_key(sid),
            "tenant mapping must be released on idle eviction"
        );
        assert!(
            !runtime.tenant_session_counts.contains_key("tenant-a"),
            "tenant counter must be decremented (and pruned at zero)"
        );
        assert!(
            !runtime.seen_request_ids.contains_key(sid),
            "request-id tracker must be dropped on idle eviction"
        );
    }

    #[test]
    fn on_session_evicted_skips_reused_live_session() {
        // If a live session now holds the evicted id (client re-created it, or
        // a deterministic-modern id was re-derived), its id-keyed state is
        // legitimate and must NOT be wiped.
        let runtime = test_runtime();
        let params = GatewayRuntime::modern_synthetic_init_params();
        let snap = runtime
            .session_store
            .create_session_with_id("reused-id", "2025-11-25", &params);
        assert_eq!(snap.session_id, "reused-id");
        runtime
            .session_tenants
            .insert("reused-id".to_owned(), "tenant-b".to_owned());
        runtime
            .tenant_session_counts
            .insert("tenant-b".to_owned(), 1);

        // A stale eviction for the same id arrives after re-creation.
        runtime.on_session_evicted("reused-id");

        assert!(
            runtime.session_tenants.contains_key("reused-id"),
            "a live re-created session's state must survive a stale eviction"
        );
        assert!(runtime.tenant_session_counts.contains_key("tenant-b"));
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
            request_context: RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.to_owned()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
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

    /// Reconnect dedupe: a terminal result delivered LIVE leaves its
    /// backlog row in the coordinator KV. When the client reconnects echoing
    /// the delivery-tagged Last-Event-Id, the row is pruned so the later drain
    /// does NOT replay it (no double-delivery).
    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_with_delivery_cursor_prunes_acked_backlog_row() {
        let runtime = test_runtime();
        let session_id = "sess-ack";
        let msg = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}),
            delivery_id: String::new(),
        };
        let delivery_id = runtime
            .pipeline_store
            .store_pending_delivery(session_id, &msg)
            .unwrap();

        // The client received it live; it reconnects echoing the tagged id.
        let cursor = format!("stream-0:5@{delivery_id}");
        runtime.ack_delivery_from_cursor(session_id, &cursor);

        // The acked row is gone → the reconnect drain replays nothing.
        let drained = runtime.take_pending_deliveries(session_id);
        assert!(
            drained.is_empty(),
            "an acked live-delivered result must not be replayed on reconnect"
        );
    }

    /// The mirror case: a result that was NEVER delivered live (the client's
    /// Last-Event-Id carries no delivery suffix, or none at all) must STILL be
    /// drained on reconnect (no lost-delivery).
    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_without_delivery_cursor_still_delivers_backlog() {
        let runtime = test_runtime();
        let session_id = "sess-noack";
        let msg = pipeline_store::DeliveryMessage {
            kind: pipeline_store::DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}),
            delivery_id: String::new(),
        };
        runtime
            .pipeline_store
            .store_pending_delivery(session_id, &msg)
            .unwrap();

        // A plain (non-delivery) cursor acks nothing.
        runtime.ack_delivery_from_cursor(session_id, "stream-0:5");

        let drained = runtime.take_pending_deliveries(session_id);
        assert_eq!(
            drained.len(),
            1,
            "a never-delivered result must be drained on reconnect"
        );
    }

    /// Cancelling a SUSPENDED pipeline (no live token on any replica) must
    /// reach the persisted state: deliver a terminal cancelled error to the
    /// caller and delete the state + pending request.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_suspended_pipeline_delivers_terminal_error_and_deletes() {
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

        // Subscribe to the delivery bus before cancelling so we observe the
        // terminal error frame.
        let mut rx = runtime.subscribe_session_delivery("sess-c").await;

        // Anonymous cancel for the same session + rendered id "7".
        let event = cancellation_bus::CancellationEvent {
            target_id: "7".to_owned(),
            kind: cancellation_bus::CancellationKind::Request,
            session_id: "sess-c".to_owned(),
            principal_id: None,
            reason: Some("user".to_owned()),
        };
        runtime.cancel_suspended_pipeline(&event).await;

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("terminal error delivered")
            .expect("a delivery message");
        assert_eq!(msg.kind, pipeline_store::DeliveryKind::PipelineError);
        assert_eq!(msg.jsonrpc_message["id"], serde_json::json!(7));
        assert_eq!(
            msg.jsonrpc_message["error"]["code"],
            serde_json::json!(-32800)
        );

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
    /// This is the cross-replica legacy-cancel path validated live on nats.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_suspended_pipeline_owned_by_identified_principal_is_authorized() {
        let runtime = test_runtime();
        let mut state = suspended_anonymous_pipeline("sess-e", Value::Number(9.into()));
        // Re-stamp the persisted owner as a Verified principal `alice`.
        state.request_context = RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some("sess-e".to_owned()),
            None,
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
            TransportKind::Http,
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
    use crate::protocol::version::ProtocolVersion;
    use serde_json::json;

    const MODERN: ProtocolVersion = ProtocolVersion::V_2026_07_28;
    const LEGACY: ProtocolVersion = ProtocolVersion::V_2025_11_25;

    // --- progress token (PROG-2 / RPN-3): namespaced on modern, bare on legacy ---

    #[test]
    fn modern_progress_token_read_from_namespaced_key() {
        let meta = json!({ "io.modelcontextprotocol/progressToken": "p-9" });
        let tok = extract_request_progress_token(Some(&meta), MODERN).unwrap();
        assert_eq!(tok, Some(json!("p-9")));
    }

    #[test]
    fn modern_progress_token_falls_back_to_bare_key() {
        // A transitional client that sent the bare key on the modern
        // wire still tokens progress.
        let meta = json!({ "progressToken": 7 });
        let tok = extract_request_progress_token(Some(&meta), MODERN).unwrap();
        assert_eq!(tok, Some(json!(7)));
    }

    #[test]
    fn legacy_progress_token_ignores_namespaced_key() {
        // On 2025-11-25 the namespaced key is not a thing — only the
        // bare key is honored, byte-identical to pre-Phase-5 behaviour.
        let meta = json!({ "io.modelcontextprotocol/progressToken": "p-9" });
        let tok = extract_request_progress_token(Some(&meta), LEGACY).unwrap();
        assert_eq!(tok, None);

        let bare = json!({ "progressToken": "p-1" });
        assert_eq!(
            extract_request_progress_token(Some(&bare), LEGACY).unwrap(),
            Some(json!("p-1"))
        );
    }

    #[test]
    fn malformed_progress_token_is_rejected() {
        let meta = json!({ "progressToken": { "bad": true } });
        assert!(extract_request_progress_token(Some(&meta), MODERN).is_err());
    }

    // --- log level (LOG-1, SEP-2575): modern-only, namespaced ---

    #[test]
    fn modern_log_level_parsed_from_namespaced_key() {
        let meta = json!({ "io.modelcontextprotocol/logLevel": "warning" });
        let lvl = extract_request_log_level(Some(&meta), MODERN).unwrap();
        assert_eq!(lvl, Some(LogLevel::Warning));
    }

    #[test]
    fn modern_log_level_absent_is_none() {
        // None ⇒ the emission site applies the spec MUST (suppress all).
        let meta = json!({});
        assert_eq!(
            extract_request_log_level(Some(&meta), MODERN).unwrap(),
            None
        );
        assert_eq!(extract_request_log_level(None, MODERN).unwrap(), None);
    }

    #[test]
    fn legacy_never_reads_log_level() {
        // Even if a (non-spec) logLevel key rides along, the legacy wire
        // ignores it — it keeps the session logging/setLevel model.
        let meta = json!({ "io.modelcontextprotocol/logLevel": "error" });
        assert_eq!(
            extract_request_log_level(Some(&meta), LEGACY).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_log_level_is_rejected() {
        let bad_str = json!({ "io.modelcontextprotocol/logLevel": "louder" });
        assert!(extract_request_log_level(Some(&bad_str), MODERN).is_err());
        let bad_type = json!({ "io.modelcontextprotocol/logLevel": 3 });
        assert!(extract_request_log_level(Some(&bad_type), MODERN).is_err());
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
