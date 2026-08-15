//! The in-gateway federation engine.
//!
//! At boot, connect to each configured upstream, import its tools, and
//! publish them as synthetic capabilities into the
//! [`CapabilityRegistry`](crate::backends::CapabilityRegistry) federated
//! overlay. Dispatch runs through per-client satellite sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde_json::{Value, json};

use crate::backends::{
    BackendInvocationRoute, FederatedCatalog, FederatedPrompt, FederatedResource,
    FederatedResourceTemplate, FederatedTool, PromptArgument, PromptDescriptor, PromptRoute,
    ResourceDescriptor, ResourceRoute, ToolDescriptor,
};
use crate::config::{AuthMode, FederationConfig, SynthesizeMode, UpstreamTransport};
use crate::protocol::{
    ClientCapabilities, JSONRPC_VERSION, ListChangedNotification, ResourceTemplate,
    ResourceUpdatedNotification, ResourceUpdatedParams,
};
use crate::runtime::RequestTrustLevel;
use crate::runtime::delivery_bus::DeliveryBus;
use crate::runtime::pipeline_store::{DeliveryKind, DeliveryMessage};
use crate::runtime::policy::{FederatedToolPolicies, ToolTrustRule};
use crate::runtime::session_store::{SessionPhase, SessionStore};
use crate::runtime::subscription_store::SubscriptionStore;
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind;
use mcpg_plugin_protocol::types::PluginIdentity;

use super::bridge::ServerRequestBridge;
use super::upstream::{
    McpUpstream, UpstreamConnectOptions, UpstreamError, UpstreamServerRequestHandler,
    connect_upstream,
};
use super::wire::{UpstreamPrompt, UpstreamResource, UpstreamResourceTemplate, UpstreamTool};

/// Time budget for a capability-import connect + list round-trip.
const IMPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a bridged server-request waits for the downstream client (P3).
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Mint a fresh, namespaced id for a bridged server-request. The `fed-` prefix
/// keeps it disjoint from the gateway's pipeline server-request ids and from
/// any upstream-chosen id. The random UUID makes the id unguessable
/// (defense-in-depth; the authoritative guard is the per-waiter
/// session-ownership check in [`ServerRequestBridge::deliver_response`]).
fn next_bridge_id() -> String {
    format!("fed-{}", uuid::Uuid::new_v4())
}

/// Map an upstream resource URI to the gateway-side URI MCPG re-serves
/// it under.
///
/// For ordinary resources this is the configured
/// `naming.resource_uri_prefix` prepended (the historical behaviour).
/// For SEP-1865 **`ui://`** resources, the prefix would destroy the
/// `ui://` scheme the host special-cases (`mcp://notion/ui://…` is no
/// longer a UI resource), so we instead namespace inside the scheme:
/// `ui://srv/widget` → `ui://<federation>/srv/widget`. The federation
/// name namespaces the URI (collision-free across sources), and the
/// `ResourceRoute::Federated { upstream_uri }` map handles reversal at
/// read time, so the encoding only needs to be deterministic.
///
/// Tool `_meta.ui.resourceUri` references are rewritten through this
/// same function ([`FederationEngine::to_federated_tool`]) so they keep
/// pointing at the resource MCPG actually serves.
fn federated_resource_uri(fed: &FederationConfig, upstream_uri: &str) -> String {
    use crate::protocol::shared::apps::{UI_URI_SCHEME, is_ui_uri};
    if is_ui_uri(upstream_uri) {
        let rest = &upstream_uri[UI_URI_SCHEME.len()..];
        format!("{UI_URI_SCHEME}{}/{rest}", fed.name)
    } else {
        let prefix = fed.naming.resource_uri_prefix.as_deref().unwrap_or("");
        format!("{prefix}{upstream_uri}")
    }
}

/// Merge MCPG's `mcpg.source.federatedFrom` tag into an upstream
/// descriptor's `_meta`, **preserving** every other upstream `_meta`
/// key — crucially `_meta.ui`, the SEP-1865 Apps metadata, which the
/// gateway must pass through rather than discard.
fn merge_source_tag(upstream_meta: Option<Value>, fed_name: &str) -> Value {
    let mut meta = match upstream_meta {
        Some(Value::Object(m)) => Value::Object(m),
        _ => json!({}),
    };
    if let Value::Object(obj) = &mut meta {
        obj.insert(
            "mcpg".to_owned(),
            json!({ "source": { "federatedFrom": fed_name } }),
        );
    }
    meta
}

/// The downstream caller a federated dispatch runs on behalf of. Drives
/// satellite keying (per-caller isolation) and per-mode upstream auth.
#[derive(Clone, Copy, Default)]
pub struct FederationCaller<'a> {
    /// Trust-qualified principal key
    /// ([`RequestIdentity::synthetic_principal_key`](crate::runtime::RequestIdentity));
    /// `None` for anonymous callers.
    pub principal: Option<&'a str>,
    /// Downstream mcpg session id (capability lookup + server-request
    /// bridge routing; satellite-key fallback for anonymous callers).
    pub session_id: Option<&'a str>,
    /// Inbound `Authorization` bearer (`pass_through` forwarding; the
    /// RFC 8693 subject token for the impersonation modes).
    pub bearer: Option<&'a str>,
    /// The caller's resolved transport identity (absent on
    /// import/listen sessions, which have no caller) — the
    /// impersonation modes issue credentials under it, so issuer trust
    /// gates and cache keys see the real subject.
    pub identity: Option<&'a crate::runtime::RequestIdentity>,
}

/// A per-caller upstream session. Keyed by
/// `(caller_key, federation_name)` — see [`satellite_caller_key`] —
/// lazily created on first dispatch and reused for that caller's
/// subsequent federated calls.
struct Satellite {
    upstream: Arc<dyn McpUpstream>,
    /// The resolved bearer this connection authenticated with. Compared
    /// against a fresh resolution on every reuse so a rotated credential
    /// replaces the connection instead of riding a stale token.
    bearer: Option<String>,
    last_used: Mutex<Instant>,
}

impl Satellite {
    fn new(upstream: Arc<dyn McpUpstream>, bearer: Option<String>) -> Self {
        Self {
            upstream,
            bearer,
            last_used: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        *self.last_used.lock().expect("satellite last_used lock") = Instant::now();
    }
}

/// First element of the satellite map key: the caller's principal
/// (stable across that principal's sessions and replicas), falling back
/// to the session id for anonymous callers (unique per anonymous modern
/// request, per-session on legacy). For the auth modes whose upstream
/// credential derives from the caller's own bearer, a fingerprint of
/// that bearer joins the key so two tokens of the same principal (e.g.
/// different scopes, or a mid-session rotation) never share an upstream
/// session.
fn satellite_caller_key(fed: &FederationConfig, caller: &FederationCaller<'_>) -> String {
    let mut key = caller
        .principal
        .or(caller.session_id)
        .unwrap_or_default()
        .to_owned();
    if matches!(
        fed.upstream.auth.mode,
        AuthMode::PassThrough | AuthMode::OauthImpersonation
    ) && let Some(bearer) = caller.bearer
    {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bearer.as_bytes());
        key.push_str("#b");
        for byte in &digest[..8] {
            use std::fmt::Write;
            let _ = write!(key, "{byte:02x}");
        }
    }
    key
}

/// What the engine needs to resolve `oauth_client_credentials` bearers
/// through the gateway's credential-issuer subsystem: look up the
/// issuer plugin by id and get-or-issue a cached, auto-refreshed token. The
/// engine never holds raw client secrets — the issuer plugin owns those.
struct FederationCredentials {
    registry: Arc<PluginRegistry>,
    cache: Arc<CredentialCacheKind>,
}

/// Lets the engine push notifications to MCPG's own connected clients when an
/// upstream signals a change: broadcast `*/list_changed` after a refresh.
/// Wired from the runtime (which owns the session + delivery machinery);
/// `None` in unit tests. Best-effort — a publish failure is logged, never
/// fatal.
struct FederationNotifier {
    session_store: Arc<dyn SessionStore>,
    delivery_bus: Arc<dyn DeliveryBus>,
    subscription_store: Arc<dyn SubscriptionStore>,
}

impl FederationNotifier {
    /// Broadcast the given `*/list_changed` methods to every operational
    /// client session (mirrors the config-reload broadcast in `app::mod`).
    async fn broadcast_list_changed(&self, methods: &[&'static str]) {
        let sessions = self.session_store.list_sessions();
        for session in sessions
            .iter()
            .filter(|s| s.phase == SessionPhase::Operational)
        {
            for method in methods {
                let notification = ListChangedNotification {
                    jsonrpc: JSONRPC_VERSION,
                    method,
                };
                if let Ok(jsonrpc_message) = serde_json::to_value(&notification) {
                    let message = DeliveryMessage {
                        kind: DeliveryKind::Notification,
                        jsonrpc_message,
                        delivery_id: String::new(),
                    };
                    if let Err(e) = self
                        .delivery_bus
                        .publish(&session.session_id, message)
                        .await
                    {
                        tracing::debug!(
                            session = %session.session_id, %method, error = %e,
                            "federation list_changed publish failed"
                        );
                    }
                }
            }
        }
    }

    /// Forward an upstream `resources/updated` to every MCPG client subscribed
    /// to the (already-prefixed) federated URI. Mirrors the watch engine's
    /// resource-update fan-out.
    async fn forward_resource_updated(&self, prefixed_uri: &str) {
        let subscribers = self.subscription_store.subscribers_for(prefixed_uri);
        if subscribers.is_empty() {
            return;
        }
        let notification = ResourceUpdatedNotification {
            jsonrpc: JSONRPC_VERSION,
            method: "notifications/resources/updated",
            params: ResourceUpdatedParams {
                uri: prefixed_uri.to_owned(),
            },
        };
        let Ok(jsonrpc_message) = serde_json::to_value(&notification) else {
            return;
        };
        for session_id in &subscribers {
            let message = DeliveryMessage {
                kind: DeliveryKind::ResourceUpdated,
                jsonrpc_message: jsonrpc_message.clone(),
                delivery_id: String::new(),
            };
            if let Err(e) = self.delivery_bus.publish(session_id, message).await {
                tracing::debug!(
                    session = %session_id, uri = %prefixed_uri, error = %e,
                    "federation resource_updated publish failed"
                );
            }
        }
    }
}

/// Bridges an upstream server→client request to the downstream client during a
/// federated tool call (P3). Built per dispatch from the engine's bridge +
/// the calling session's capabilities. Declines anything the downstream client
/// didn't advertise (never surface a request it can't handle).
struct FederatedBridgeHandler {
    bridge: Option<Arc<ServerRequestBridge>>,
    session_id: Option<String>,
    caps: ClientCapabilities,
}

#[async_trait::async_trait]
impl UpstreamServerRequestHandler for FederatedBridgeHandler {
    async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        let (Some(bridge), Some(session_id)) = (self.bridge.as_ref(), self.session_id.as_ref())
        else {
            return Err((
                -32601,
                format!("server-request '{method}' cannot be bridged (no client session)"),
            ));
        };
        // Bridge only the server-request methods the downstream client
        // advertised (never surface a request it can't handle).
        let supported = match method {
            "elicitation/create" => self.caps.supports_elicitation(),
            "sampling/createMessage" => self.caps.supports_sampling(),
            "roots/list" => self.caps.supports_roots(),
            _ => false,
        };
        if !supported {
            return Err((
                -32601,
                format!("server-request '{method}' not supported by the downstream client"),
            ));
        }
        bridge
            .ask_client(session_id, next_bridge_id(), method, params, BRIDGE_TIMEOUT)
            .await
            .map_err(|e| (-32603, e.to_string()))
    }

    async fn forward_notification(&self, method: &str, params: Value) {
        // Relay only progress; other upstream notifications aren't surfaced to
        // the client. (Upstream and downstream progress tokens are not yet
        // translated — forwarded as-is; token mapping is a follow-up.)
        if method != "notifications/progress" {
            return;
        }
        let (Some(bridge), Some(session_id)) = (self.bridge.as_ref(), self.session_id.as_ref())
        else {
            return;
        };
        let jsonrpc_message =
            json!({ "jsonrpc": JSONRPC_VERSION, "method": method, "params": params });
        bridge
            .forward_notification(session_id, jsonrpc_message)
            .await;
    }
}

/// One federation's last successful import, cached so a single upstream's
/// `list_changed` (or TTL refresh) re-imports just that federation and
/// republishes the merged overlay — without re-listing every other upstream.
#[derive(Default, Clone)]
struct ImportedParts {
    tools: Vec<FederatedTool>,
    resources: Vec<FederatedResource>,
    resource_templates: Vec<FederatedResourceTemplate>,
    prompts: Vec<FederatedPrompt>,
    rules: Vec<ToolTrustRule>,
}

impl ImportedParts {
    /// Per-kind fingerprints over the client-visible descriptors (routes /
    /// rules are dispatch detail — a change there is not a list change).
    /// Templates fold into the resources fingerprint: both surface under
    /// `notifications/resources/list_changed`.
    fn fingerprints(&self) -> [u64; 3] {
        fn digest(parts: &[impl serde::Serialize]) -> u64 {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            for part in parts {
                serde_json::to_vec(part)
                    .unwrap_or_default()
                    .hash(&mut hasher);
            }
            hasher.finish()
        }
        let tool_descriptors: Vec<_> = self.tools.iter().map(|t| &t.descriptor).collect();
        let resource_descriptors: Vec<_> = self.resources.iter().map(|r| &r.descriptor).collect();
        let template_descriptors: Vec<_> = self
            .resource_templates
            .iter()
            .map(|t| &t.descriptor)
            .collect();
        let prompt_descriptors: Vec<_> = self.prompts.iter().map(|p| &p.descriptor).collect();
        [
            digest(&tool_descriptors),
            digest(&resource_descriptors) ^ digest(&template_descriptors).rotate_left(1),
            digest(&prompt_descriptors),
        ]
    }
}

/// Which capability kinds a re-import actually changed, computed by
/// descriptor fingerprint against the previous import — so `list_changed`
/// broadcasts fire only when the client-visible catalog moved (and a
/// TTL-poll refresh against a push-less upstream synthesizes them).
#[derive(Clone, Copy, Default)]
struct ChangedKinds {
    tools: bool,
    resources: bool,
    prompts: bool,
}

impl ChangedKinds {
    fn from_fingerprints(prior: [u64; 3], new: [u64; 3]) -> Self {
        Self {
            tools: prior[0] != new[0],
            resources: prior[1] != new[1],
            prompts: prior[2] != new[2],
        }
    }

    fn any(self) -> bool {
        self.tools || self.resources || self.prompts
    }

    fn methods(self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.tools {
            methods.push("notifications/tools/list_changed");
        }
        if self.resources {
            methods.push("notifications/resources/list_changed");
        }
        if self.prompts {
            methods.push("notifications/prompts/list_changed");
        }
        methods
    }
}

pub(crate) struct FederationEngine {
    federations: Vec<FederationConfig>,
    /// Shared with `CapabilityRegistry` (D2): the engine `store`s a fresh
    /// overlay after import / refresh; the registry reads it atomically.
    overlay: Arc<ArcSwap<FederatedCatalog>>,
    /// Loop-detection id sent as `Mcpg-Upstream-Via` on every upstream
    /// request.
    gateway_via: String,
    /// Federated-tool governance rules (prefixed tool name → rule),
    /// shared with the `PreDispatchPolicyGate` so synthetic tools enforce
    /// their federation's `minimum_trust` / `allow_if`.
    policy: Arc<ArcSwap<FederatedToolPolicies>>,
    /// Per-(mcpg session, federation) upstream sessions used for
    /// dispatch (D5), separate from the transient import sessions.
    satellites: DashMap<(String, String), Satellite>,
    /// Credential subsystem handle. `Some` in production (wired from the
    /// runtime), `None` in unit tests. Required only by federations using
    /// `oauth_client_credentials`.
    credentials: Option<FederationCredentials>,
    /// Client-notification sink. `Some` in production; `None` in unit tests
    /// (re-import still happens, the client broadcast is just skipped).
    notifier: Option<Arc<FederationNotifier>>,
    /// Server-request bridge (P3): ask the downstream client a server-request
    /// (sampling/elicitation/roots) on behalf of an upstream and await the
    /// reply. `Some` in production; `None` in unit tests without bridging.
    server_request_bridge: Option<Arc<ServerRequestBridge>>,
    /// Per-federation last-import cache (keyed by federation name), so a
    /// single upstream's refresh republishes the overlay without re-listing
    /// the others.
    imported: Mutex<HashMap<String, ImportedParts>>,
    /// Wire detected per `protocol_version: auto` federation (name →
    /// modern?). Written after any successful probing connect; read by
    /// `connect_opts` so later satellites / listeners skip the probe.
    /// Cleared by engine replacement (config reload) — the next connect
    /// re-probes.
    detected_wires: DashMap<String, bool>,
    /// When true, MCPG advertises the SEP-1865
    /// `io.modelcontextprotocol/ui` extension on every outgoing upstream
    /// `initialize` (including the transient import session). A
    /// spec-compliant upstream checks this client capability before
    /// emitting UI-enabled tools, so without it federated servers
    /// withhold their UI tools. Mirrors
    /// `mcp.configurations.apps.federate_upstream`.
    apps_advertise_upstream: bool,
    /// Reverse-federation ingress. `Some` when
    /// `gateway.server.tunnel_federation` is configured; resolves
    /// `tunnel://<name>/<path>` upstreams to the relay's federation ingress.
    tunnel_federation: Option<TunnelFederation>,
}

/// Resolved reverse-federation ingress: the relay federation-ingress base URL
/// (trailing slash trimmed) and the org token presented in `X-MCPG-Tunnel-Token`.
#[derive(Clone)]
pub(crate) struct TunnelFederation {
    pub relay_ingress_url: String,
    pub token: Option<String>,
}

impl TunnelFederation {
    /// Resolve from `gateway.server.tunnel_federation`. The org token falls back
    /// to `MCPG_TUNNEL_TOKEN` (the same token used for egress dial) when the
    /// config leaves `token` unset. Read at boot, before any post-boot env scrub.
    pub(crate) fn from_config(cfg: &crate::config::TunnelFederationConfig) -> Self {
        Self {
            relay_ingress_url: cfg.relay_ingress_url.trim_end_matches('/').to_owned(),
            token: cfg
                .token
                .clone()
                .or_else(|| std::env::var("MCPG_TUNNEL_TOKEN").ok()),
        }
    }
}

impl FederationEngine {
    pub fn new(
        federations: Vec<FederationConfig>,
        overlay: Arc<ArcSwap<FederatedCatalog>>,
        policy: Arc<ArcSwap<FederatedToolPolicies>>,
        gateway_via: impl Into<String>,
    ) -> Self {
        Self {
            federations,
            overlay,
            policy,
            gateway_via: gateway_via.into(),
            satellites: DashMap::new(),
            credentials: None,
            notifier: None,
            server_request_bridge: None,
            imported: Mutex::new(HashMap::new()),
            detected_wires: DashMap::new(),
            apps_advertise_upstream: false,
            tunnel_federation: None,
        }
    }

    /// Opt into advertising the SEP-1865 `io.modelcontextprotocol/ui`
    /// extension on outgoing upstream `initialize` requests, so
    /// federated servers emit their UI-enabled tools.
    #[must_use]
    pub fn with_apps_upstream_advertisement(mut self, enabled: bool) -> Self {
        self.apps_advertise_upstream = enabled;
        self
    }

    /// Configure the reverse-federation ingress that resolves
    /// `tunnel://<name>/<path>` upstreams to the relay's federation ingress.
    #[must_use]
    pub fn with_tunnel_federation(mut self, tf: Option<TunnelFederation>) -> Self {
        self.tunnel_federation = tf;
        self
    }

    /// Attach the credential subsystem so `oauth_client_credentials`
    /// federations can resolve upstream bearers via the issuer plugins.
    #[must_use]
    pub fn with_credentials(
        mut self,
        registry: Arc<PluginRegistry>,
        cache: Arc<CredentialCacheKind>,
    ) -> Self {
        self.credentials = Some(FederationCredentials { registry, cache });
        self
    }

    /// Attach the client-notification sink so upstream-signalled changes can
    /// be forwarded as `*/list_changed` to MCPG's own connected clients.
    #[must_use]
    pub fn with_notifier(
        mut self,
        session_store: Arc<dyn SessionStore>,
        delivery_bus: Arc<dyn DeliveryBus>,
        subscription_store: Arc<dyn SubscriptionStore>,
    ) -> Self {
        self.notifier = Some(Arc::new(FederationNotifier {
            session_store,
            delivery_bus,
            subscription_store,
        }));
        self
    }

    /// Attach the server-request bridge (P3) so upstream-initiated
    /// sampling/elicitation/roots requests can be bridged to the downstream
    /// client and awaited in-task.
    #[must_use]
    pub fn with_server_request_bridge(mut self, bridge: Arc<ServerRequestBridge>) -> Self {
        self.server_request_bridge = Some(bridge);
        self
    }

    /// The server-request bridge, if wired. The HTTP response intake routes a
    /// matching server-request response here before the pipeline-resume path.
    pub(crate) fn server_request_bridge(&self) -> Option<&Arc<ServerRequestBridge>> {
        self.server_request_bridge.as_ref()
    }

    /// Whether any upstream is configured.
    pub fn is_enabled(&self) -> bool {
        !self.federations.is_empty()
    }

    /// Connect to every configured upstream, import its tools, and
    /// publish the merged synthetic-tool set into the overlay.
    ///
    /// A failing upstream is logged and skipped — its capabilities simply
    /// are not registered; other federations and native
    /// bindings are unaffected. Replaces the overlay wholesale, so this
    /// is also the refresh path.
    pub async fn import_all(&self) {
        let mut cache: HashMap<String, ImportedParts> = HashMap::new();
        for fed in &self.federations {
            match self.import_one(fed).await {
                Ok((tools, resources, resource_templates, prompts, rules)) => {
                    tracing::info!(
                        federation = %fed.name,
                        tools = tools.len(),
                        resources = resources.len(),
                        resource_templates = resource_templates.len(),
                        prompts = prompts.len(),
                        "federation capabilities imported"
                    );
                    cache.insert(
                        fed.name.clone(),
                        ImportedParts {
                            tools,
                            resources,
                            resource_templates,
                            prompts,
                            rules,
                        },
                    );
                }
                Err(e) => {
                    tracing::error!(
                        federation = %fed.name,
                        error = %e,
                        "federation import failed; its capabilities are not registered"
                    );
                }
            }
        }
        *self.imported.lock().expect("imported lock") = cache;
        self.republish();
    }

    /// Re-import a single federation (on its `list_changed` push or TTL
    /// refresh) and republish the merged overlay, preserving every other
    /// federation's capabilities. Returns which kinds the re-import
    /// changed (fingerprint diff against the prior import) so the caller
    /// can broadcast precise `*/list_changed` notifications; `None` when
    /// the re-import failed (previous import kept).
    async fn reimport_one(&self, fed_name: &str) -> Option<ChangedKinds> {
        let fed = self
            .federations
            .iter()
            .find(|f| f.name == fed_name)
            .cloned()?;
        match self.import_one(&fed).await {
            Ok((tools, resources, resource_templates, prompts, rules)) => {
                let parts = ImportedParts {
                    tools,
                    resources,
                    resource_templates,
                    prompts,
                    rules,
                };
                let new_fingerprints = parts.fingerprints();
                let changed = {
                    let mut imported = self.imported.lock().expect("imported lock");
                    let prior_fingerprints = imported
                        .get(fed_name)
                        .map(ImportedParts::fingerprints)
                        .unwrap_or_default();
                    imported.insert(fed_name.to_owned(), parts);
                    ChangedKinds::from_fingerprints(prior_fingerprints, new_fingerprints)
                };
                self.republish();
                Some(changed)
            }
            Err(e) => {
                tracing::warn!(
                    federation = %fed_name, error = %e,
                    "single-federation re-import failed; keeping previous capabilities"
                );
                None
            }
        }
    }

    /// Rebuild + atomically swap the overlay and governance from the
    /// per-federation import cache. Synchronous (no await) so holding the
    /// cache lock is safe.
    fn republish(&self) {
        let cache = self.imported.lock().expect("imported lock");
        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut resource_templates = Vec::new();
        let mut prompts = Vec::new();
        let mut rules = Vec::new();
        for parts in cache.values() {
            tools.extend(parts.tools.iter().cloned());
            resources.extend(parts.resources.iter().cloned());
            resource_templates.extend(parts.resource_templates.iter().cloned());
            prompts.extend(parts.prompts.iter().cloned());
            rules.extend(parts.rules.iter().cloned());
        }
        drop(cache);
        self.overlay.store(Arc::new(FederatedCatalog::from_parts(
            tools,
            resources,
            resource_templates,
            prompts,
        )));
        // Prefix rules let a federation's governance reach surfaces whose
        // exact client-facing name isn't known at import — concrete reads of
        // a federated resource template arrive as `<resource_uri_prefix>…`.
        // One entry per federation that declares a resource URI prefix.
        let prefix_rules: Vec<(String, ToolTrustRule)> = self
            .federations
            .iter()
            .filter_map(|fed| {
                let prefix = fed.naming.resource_uri_prefix.as_deref().unwrap_or("");
                if prefix.is_empty() {
                    return None;
                }
                Some((prefix.to_owned(), self.governance_rule(fed, prefix)))
            })
            .collect();
        match FederatedToolPolicies::compile(rules, prefix_rules) {
            Ok(policies) => self.policy.store(Arc::new(policies)),
            Err(e) => tracing::error!(
                error = %e,
                "failed to compile federated tool governance; synthetic tools fall back to the global policy"
            ),
        }
    }

    async fn import_one(
        &self,
        fed: &FederationConfig,
    ) -> Result<
        (
            Vec<FederatedTool>,
            Vec<FederatedResource>,
            Vec<FederatedResourceTemplate>,
            Vec<FederatedPrompt>,
            Vec<ToolTrustRule>,
        ),
        UpstreamError,
    > {
        let bearer = self.bearer_for(fed, FederationCaller::default()).await?;
        let upstream = connect_upstream(self.connect_opts(fed, None, bearer).await?).await?;
        self.record_detected_wire(fed, upstream.as_ref());
        let listed_tools = if fed.import.tools {
            upstream.list_tools().await
        } else {
            Ok(Vec::new())
        };
        let listed_resources = if fed.import.resources {
            upstream.list_resources().await
        } else {
            Ok(Vec::new())
        };
        let listed_templates = if fed.import.resource_templates {
            upstream.list_resource_templates().await
        } else {
            Ok(Vec::new())
        };
        let listed_prompts = if fed.import.prompts {
            upstream.list_prompts().await
        } else {
            Ok(Vec::new())
        };
        // The import session is transient — dispatch uses its own
        // per-client satellites.
        upstream.close().await;

        let mut tools = Vec::new();
        let mut rules = Vec::new();
        for tool in listed_tools?
            .into_iter()
            .filter(|t| fed.filter.admits(&t.name))
        {
            let federated = self.to_federated_tool(fed, tool);
            rules.push(self.governance_rule(fed, &federated.descriptor.name));
            tools.push(federated);
        }
        // The federation's `governance` block applies to ALL imported
        // surfaces, not just tools — prompts/get, resources/read and
        // completion now run the trust floor, so each federated prompt
        // (keyed by name), resource (keyed by prefixed URI) and resource
        // template (keyed by prefixed URI template) needs its inherited
        // rule too, or it would fall back to the gateway's global default
        // trust instead of the federation's declared level.
        let resources: Vec<_> = listed_resources?
            .into_iter()
            .map(|r| self.to_federated_resource(fed, r))
            .collect();
        for r in &resources {
            rules.push(self.governance_rule(fed, &r.descriptor.uri));
        }
        let resource_templates: Vec<_> = listed_templates?
            .into_iter()
            .map(|t| self.to_federated_resource_template(fed, t))
            .collect();
        for t in &resource_templates {
            rules.push(self.governance_rule(fed, &t.descriptor.uri_template));
        }
        let prompts: Vec<_> = listed_prompts?
            .into_iter()
            .map(|p| self.to_federated_prompt(fed, p))
            .collect();
        for p in &prompts {
            rules.push(self.governance_rule(fed, &p.descriptor.name));
        }
        Ok((tools, resources, resource_templates, prompts, rules))
    }

    /// Build the per-tool governance rule for a synthetic (prefixed)
    /// federated tool, inheriting the federation's `governance` block so
    /// the policy gate treats it exactly like a native tool.
    fn governance_rule(&self, fed: &FederationConfig, tool_name: &str) -> ToolTrustRule {
        ToolTrustRule {
            tool_name: tool_name.to_owned(),
            minimum_trust: trust_from_config(fed.governance.minimum_trust),
            cel_allow_if: fed.governance.allow_if.clone(),
            required_scopes: Vec::new(),
        }
    }

    /// Record the wire a probing connect resolved so later connects to
    /// this federation (satellites, listeners, refreshes) skip the probe.
    fn record_detected_wire(&self, fed: &FederationConfig, upstream: &dyn McpUpstream) {
        if fed.upstream.protocol_version.is_auto() {
            self.detected_wires
                .insert(fed.name.clone(), upstream.wire_is_modern());
        }
    }

    /// The `(modern, probe)` pair a connect to `fed` should use: pinned
    /// versions never probe; `auto` probes once and then reuses the
    /// detected wire; stdio never probes (legacy-only transport).
    fn wire_hint(&self, fed: &FederationConfig) -> (bool, bool) {
        if fed.upstream.protocol_version.pinned().is_some() {
            return (fed.upstream.protocol_version.is_modern(), false);
        }
        match self.detected_wires.get(&fed.name) {
            Some(modern) => (*modern, false),
            None => (
                false,
                matches!(fed.upstream.transport, UpstreamTransport::StreamableHttp),
            ),
        }
    }

    /// Whether `source` should have `resources/updated` synthesized by
    /// polling (the watch engine asks on the first downstream subscribe).
    /// `Some(interval_ms)` = poll at that cadence; `None` = don't. `auto`
    /// polls exactly the push-less upstreams: the modern stateless wire
    /// (its listener carries only `*/list_changed`) and stdio (no
    /// standalone notification channel at all).
    pub(crate) fn synthesized_poll_interval_ms(&self, source: &str) -> Option<u64> {
        let fed = self.federations.iter().find(|f| f.name == source)?;
        let poll = match fed.synthesize.resources_updated {
            SynthesizeMode::Off => false,
            SynthesizeMode::Poll => true,
            SynthesizeMode::Auto => match fed.upstream.transport {
                UpstreamTransport::Stdio => true,
                UpstreamTransport::StreamableHttp => {
                    if fed.upstream.protocol_version.is_auto() {
                        self.detected_wires
                            .get(source)
                            .is_some_and(|modern| *modern)
                    } else {
                        fed.upstream.protocol_version.is_modern()
                    }
                }
            },
        };
        poll.then_some(fed.synthesize.poll_interval_ms)
    }

    async fn connect_opts(
        &self,
        fed: &FederationConfig,
        session_id: Option<&str>,
        bearer_token: Option<String>,
    ) -> Result<UpstreamConnectOptions, UpstreamError> {
        // Advertise to the upstream the bridgeable client capabilities the
        // downstream session actually has (P3), so it knows it may issue
        // sampling/elicitation/roots. Empty for import/listener sessions.
        let mut client_capabilities =
            serde_json::to_value(self.downstream_caps(session_id)).unwrap_or_else(|_| json!({}));
        // SEP-1865: advertise MCP Apps support upstream so the server
        // emits its UI-enabled tools. Applies to the import session too
        // (that's when tools are listed), independent of any downstream
        // client session.
        if self.apps_advertise_upstream {
            let obj = client_capabilities
                .as_object_mut()
                .expect("client capabilities serialise to a JSON object");
            let extensions = obj.entry("extensions").or_insert_with(|| json!({}));
            if let Some(ext_obj) = extensions.as_object_mut() {
                ext_obj.insert(
                    crate::protocol::shared::apps::EXTENSION_ID.to_owned(),
                    crate::protocol::shared::apps::capability_value(&[]),
                );
            }
        }
        let (url, tunnel_token) = self.resolve_upstream_url(fed)?;
        let (modern, probe) = self.wire_hint(fed);
        Ok(UpstreamConnectOptions {
            url,
            tunnel_token,
            bearer_token,
            allow_private: fed.upstream.upstream_safety.allow_private_backends,
            max_response_bytes: fed.response.max_response_bytes,
            timeout: IMPORT_TIMEOUT,
            gateway_via: self.gateway_via.clone(),
            client_capabilities,
            transport: fed.upstream.transport,
            headers: fed.upstream.headers.clone(),
            command: fed.upstream.command.clone(),
            args: fed.upstream.args.clone(),
            env: fed.upstream.env.clone(),
            modern,
            probe,
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        })
    }

    /// Resolve a federation upstream URL to the effective `(url, tunnel_token)`.
    /// A direct `http(s)`/`stdio` upstream passes through unchanged with no
    /// tunnel token. A `tunnel://<name>/<path>` reverse-federation
    /// upstream rewrites to `<relay_ingress>/federate/<name>/<path>` and
    /// carries the org token: the relay resolves the token to an org, enforces
    /// same-org isolation, strips the token, and forwards the rest onto the
    /// named tunnel. Fails closed if `tunnel://` is used without a configured
    /// `tunnel_federation` ingress (a boot-time cross-check also catches this).
    fn resolve_upstream_url(
        &self,
        fed: &FederationConfig,
    ) -> Result<(String, Option<String>), UpstreamError> {
        let Some(rest) = fed.upstream.url.strip_prefix("tunnel://") else {
            return Ok((fed.upstream.url.clone(), None));
        };
        let tf = self.tunnel_federation.as_ref().ok_or_else(|| {
            UpstreamError::Connect(
                "tunnel:// upstream requires gateway.server.tunnel_federation (relay ingress)"
                    .to_owned(),
            )
        })?;
        let (name, path) = match rest.split_once('/') {
            Some((n, p)) => (n, p),
            None => (rest, ""),
        };
        if name.is_empty() {
            return Err(UpstreamError::Connect(
                "tunnel:// upstream needs a name: tunnel://<name>/<path>".to_owned(),
            ));
        }
        let base = tf.relay_ingress_url.trim_end_matches('/');
        let url = if path.is_empty() {
            format!("{base}/federate/{name}")
        } else {
            format!("{base}/federate/{name}/{path}")
        };
        Ok((url, tf.token.clone()))
    }

    /// The downstream client's MCP capabilities for `session_id`, via the
    /// notifier's session store. Empty (bridge nothing) when there's no
    /// notifier, no session, or the session can't be loaded.
    fn downstream_caps(&self, session_id: Option<&str>) -> ClientCapabilities {
        let (Some(notifier), Some(sid)) = (self.notifier.as_ref(), session_id) else {
            return ClientCapabilities::default();
        };
        notifier
            .session_store
            .load_session(Some(sid), false)
            .map(|s| s.client_capabilities)
            .unwrap_or_default()
    }

    /// Bearer credential for an upstream session. `service_token` uses
    /// the static token; `pass_through` forwards the inbound caller's
    /// bearer (only present at dispatch — `None` at import time);
    /// `oauth_client_credentials` mints a machine token via the
    /// credential-issuer subsystem (cached + auto-refreshed);
    /// `oauth_impersonation` exchanges the caller's bearer for an upstream
    /// token via the same subsystem (the caller bearer is the RFC 8693
    /// subject token) — and, like `pass_through`, has no caller to
    /// impersonate at import/listen time, so it lists anonymously then;
    /// `none` => no auth.
    async fn bearer_for(
        &self,
        fed: &FederationConfig,
        caller: FederationCaller<'_>,
    ) -> Result<Option<String>, UpstreamError> {
        match fed.upstream.auth.mode {
            AuthMode::ServiceToken => Ok(fed.upstream.auth.token.clone()),
            AuthMode::PassThrough => Ok(caller.bearer.map(str::to_owned)),
            AuthMode::OauthClientCredentials => self
                .resolve_oauth_credential(fed, machine_identity())
                .await
                .map(Some),
            AuthMode::OauthImpersonation => match caller.bearer {
                // Dispatch: exchange the caller's bearer (the subject
                // token) under the caller's resolved identity — issuer
                // plugins gate on its trust level and the credential
                // cache keys on its subject/scopes.
                Some(bearer) => self
                    .resolve_oauth_credential(fed, impersonation_identity(caller.identity, bearer))
                    .await
                    .map(Some),
                // Import / listen: no caller to impersonate — list anonymously
                // (same as `pass_through`).
                None => Ok(None),
            },
            AuthMode::None => Ok(None),
        }
    }

    /// Resolve an OAuth bearer through the credential-issuer
    /// subsystem. The federation's `auth.credential` is a standard
    /// `cred://<plugin_id>/<target>` URI; we look up the issuer plugin and
    /// `get_or_issue` (host-cached per identity). `identity` is the fixed
    /// machine identity for `oauth_client_credentials` (one shared token per
    /// `(plugin_id, target)`) or the per-caller identity carrying the subject
    /// token for `oauth_impersonation` (token exchange, cached per caller).
    /// Secrets / subject tokens stay inside the issuer plugin.
    async fn resolve_oauth_credential(
        &self,
        fed: &FederationConfig,
        identity: PluginIdentity,
    ) -> Result<String, UpstreamError> {
        let creds = self.credentials.as_ref().ok_or_else(|| {
            UpstreamError::Connect(
                "oauth credential modes require the credential subsystem (not wired)".into(),
            )
        })?;
        let uri = fed.upstream.auth.credential.as_deref().ok_or_else(|| {
            UpstreamError::Connect(
                "oauth credential modes require auth.credential (a cred:// URI)".into(),
            )
        })?;
        let (plugin_id, target) = uri
            .strip_prefix("cred://")
            .and_then(|rest| rest.split_once('/'))
            .ok_or_else(|| {
                UpstreamError::Connect(format!(
                    "auth.credential {uri:?} must be cred://<plugin_id>/<target>"
                ))
            })?;
        let issuer = creds.registry.credential_issuer(plugin_id).ok_or_else(|| {
            UpstreamError::Connect(format!("no credential_issuer plugin id={plugin_id:?}"))
        })?;
        // Per-call issuer config from the federation (registry OAuth
        // discovery / operator overrides for template issuers).
        let call_config = fed
            .upstream
            .auth
            .credential_config
            .clone()
            .unwrap_or(Value::Null);
        let issued = creds
            .cache
            .get_or_issue(&issuer, &identity, target, &call_config)
            .await
            .map_err(|e| UpstreamError::Connect(format!("credential issue failed: {e}")))?;
        issued.value.ok_or_else(|| {
            UpstreamError::Connect("credential issuer returned no token value".into())
        })
    }

    /// Dispatch a federated tool call: get-or-create the caller's satellite
    /// for `(caller, source)` and forward the call, bridging any upstream
    /// server-requests (sampling/elicitation/roots) back to the downstream
    /// client (P3).
    pub async fn call_tool(
        &self,
        source: &str,
        upstream_name: &str,
        args: Option<&Value>,
        caller: FederationCaller<'_>,
        progress_token: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let satellite = self.get_or_connect_satellite(source, caller).await?;
        // The upstream tool's declared `inputSchema` drives SEP-2243
        // `Mcp-Param-{Name}` promotion on the modern wire (ignored on the
        // legacy wire).
        let input_schema = self.upstream_input_schema(source, upstream_name);
        satellite
            .call_tool_bridged(
                upstream_name,
                args,
                input_schema.as_ref(),
                &self.bridge_handler(caller.session_id),
                progress_token,
            )
            .await
    }

    /// The declared `inputSchema` of a federated tool, looked up from the
    /// last successful import of its owning federation (keyed by `source`
    /// → `upstream_name`). `None` when the federation/tool is unknown
    /// (e.g. before the first import). Used only to promote SEP-2243
    /// `Mcp-Param-{Name}` headers on the modern wire.
    fn upstream_input_schema(&self, source: &str, upstream_name: &str) -> Option<Value> {
        let imported = self.imported.lock().ok()?;
        let parts = imported.get(source)?;
        parts.tools.iter().find_map(|t| match &t.route {
            BackendInvocationRoute::Federated {
                source: s,
                upstream_name: u,
            } if s == source && u == upstream_name => Some(t.descriptor.input_schema.clone()),
            _ => None,
        })
    }

    /// Dispatch a federated resource read, bridging any upstream
    /// server-requests to the downstream client (P3-C). Returns the upstream
    /// `resources/read` result.
    pub async fn read_resource(
        &self,
        source: &str,
        upstream_uri: &str,
        caller: FederationCaller<'_>,
    ) -> Result<Value, UpstreamError> {
        let satellite = self.get_or_connect_satellite(source, caller).await?;
        satellite
            .read_resource_bridged(upstream_uri, &self.bridge_handler(caller.session_id))
            .await
    }

    /// Dispatch a federated prompt fetch, bridging any upstream server-requests
    /// to the downstream client (P3-C). Returns the upstream `prompts/get`
    /// result.
    pub async fn get_prompt(
        &self,
        source: &str,
        upstream_name: &str,
        args: Option<&Value>,
        caller: FederationCaller<'_>,
    ) -> Result<Value, UpstreamError> {
        let satellite = self.get_or_connect_satellite(source, caller).await?;
        satellite
            .get_prompt_bridged(upstream_name, args, &self.bridge_handler(caller.session_id))
            .await
    }

    /// Build the per-dispatch server-request bridge handler for `session_id`
    /// (the engine's bridge + the session's advertised capabilities).
    fn bridge_handler(&self, session_id: Option<&str>) -> FederatedBridgeHandler {
        FederatedBridgeHandler {
            bridge: self.server_request_bridge.clone(),
            session_id: session_id.map(str::to_owned),
            caps: self.downstream_caps(session_id),
        }
    }

    async fn get_or_connect_satellite(
        &self,
        source: &str,
        caller: FederationCaller<'_>,
    ) -> Result<Arc<dyn McpUpstream>, UpstreamError> {
        let fed = self
            .federations
            .iter()
            .find(|f| f.name == source)
            .ok_or_else(|| UpstreamError::Connect(format!("unknown federation '{source}'")))?;
        let key = (satellite_caller_key(fed, &caller), source.to_owned());
        // Resolve the bearer on every dispatch (cheap: a static clone,
        // the caller's own token, or a credential-cache lookup) so a
        // rotated credential replaces the satellite instead of riding
        // the connect-time token to an upstream 401.
        let bearer = self.bearer_for(fed, caller).await?;
        if let Some(entry) = self.satellites.get(&key)
            && entry.bearer == bearer
        {
            entry.touch();
            return Ok(Arc::clone(&entry.upstream));
        }
        let upstream = connect_upstream(
            self.connect_opts(fed, caller.session_id, bearer.clone())
                .await?,
        )
        .await?;
        self.record_detected_wire(fed, upstream.as_ref());
        // Check-then-insert can race two concurrent first calls; the
        // loser's session is dropped and idle-reaped upstream — bounded
        // and acceptable. A displaced STALE-bearer satellite is torn down
        // deliberately (in-flight calls on the rotated-out token fail
        // with it).
        if let Some(prev) = self
            .satellites
            .insert(key, Satellite::new(Arc::clone(&upstream), bearer.clone()))
            && prev.bearer != bearer
        {
            prev.upstream.close().await;
        }
        Ok(upstream)
    }

    /// Close + drop satellites idle longer than `idle`. Driven by a
    /// background sweeper wired at boot (increment C).
    pub async fn sweep_idle(&self, idle: Duration) {
        let now = Instant::now();
        let stale: Vec<(String, String)> = self
            .satellites
            .iter()
            .filter(|e| {
                now.duration_since(*e.value().last_used.lock().expect("last_used lock")) > idle
            })
            .map(|e| e.key().clone())
            .collect();
        for key in stale {
            if let Some((_, satellite)) = self.satellites.remove(&key) {
                satellite.upstream.close().await;
            }
        }
    }

    /// Adopt still-valid satellites from a `prior` engine across a config
    /// reload: keep a `(caller, federation)` upstream session only when that
    /// federation's config is byte-identical in both engines (so its URL /
    /// auth / safety are unchanged). Satellites for added, removed, or changed
    /// federations are left behind and re-established lazily — carrying one
    /// with stale auth or a stale target would be a correctness/security bug.
    /// Best-effort: a satellite created on `prior` during the reload window may
    /// be missed and simply re-established on the next call. The detected
    /// wires of unchanged `auto` federations carry over the same way so a
    /// reload does not re-probe every upstream.
    pub(crate) fn adopt_satellites(&self, prior: &FederationEngine) {
        let unchanged = |fed_name: &String| {
            matches!(
                (
                    prior.federations.iter().find(|f| &f.name == fed_name),
                    self.federations.iter().find(|f| &f.name == fed_name),
                ),
                (Some(old), Some(new)) if old == new
            )
        };
        let mut carried = 0usize;
        for entry in prior.satellites.iter() {
            let (_caller, fed_name) = entry.key();
            if unchanged(fed_name) {
                self.satellites.insert(
                    entry.key().clone(),
                    Satellite::new(
                        Arc::clone(&entry.value().upstream),
                        entry.value().bearer.clone(),
                    ),
                );
                carried += 1;
            }
        }
        for entry in prior.detected_wires.iter() {
            if unchanged(entry.key()) {
                self.detected_wires
                    .insert(entry.key().clone(), *entry.value());
            }
        }
        if carried > 0 {
            tracing::debug!(carried, "carried federated satellites across reload");
        }
    }

    /// Carry the prior engine's per-federation import cache across a reload.
    ///
    /// [`Self::republish`] rebuilds the whole overlay from this cache, so a
    /// fresh engine that starts empty publishes an empty catalog the first
    /// time anything republishes — and a TTL refresh or an upstream
    /// `list_changed` for ONE federation is enough to trigger that, wiping
    /// every other federation's tools and resources even though the reload
    /// seeded the overlay correctly. The seeded overlay only survives until
    /// the first republish; the cache is what has to be carried.
    ///
    /// Scoped to federations this engine still declares: a removed one must
    /// not be resurrected. Entries for changed federations are carried so
    /// clients keep seeing them, and the re-import that a config change
    /// triggers refreshes them.
    pub(crate) fn adopt_imported(&self, prior: &FederationEngine) {
        let Ok(prior_cache) = prior.imported.lock() else {
            return;
        };
        let Ok(mut cache) = self.imported.lock() else {
            return;
        };
        let mut carried = 0usize;
        for (fed_name, parts) in prior_cache.iter() {
            if !self.federations.iter().any(|f| &f.name == fed_name) {
                continue;
            }
            cache.insert(fed_name.clone(), parts.clone());
            carried += 1;
        }
        if carried > 0 {
            tracing::debug!(carried, "carried federated import cache across reload");
        }
    }

    /// Spawn one persistent notification-listener task per federation (P2-D).
    /// Each opens the upstream's server→client SSE stream and, on a
    /// `*/list_changed` push, refreshes the overlay and forwards the change to
    /// MCPG's own clients. Tasks hold a `Weak` so they exit when the engine is
    /// dropped (e.g. replaced on a config reload), like the idle sweeper.
    pub fn spawn_listeners(self: &Arc<Self>) {
        for fed in &self.federations {
            // stdio has no separate notification channel (notifications are
            // drained during call cycles) — a listener would just park holding
            // an idle child, so skip it. TTL refresh (below) still applies.
            if matches!(
                fed.upstream.transport,
                crate::config::UpstreamTransport::Stdio
            ) {
                continue;
            }
            let weak = Arc::downgrade(self);
            let name = fed.name.clone();
            tokio::spawn(async move { Self::run_listener(weak, name).await });
        }
    }

    /// Spawn one TTL poll-refresh task per federation: a
    /// fallback that re-imports `cache.capability_ttl_secs` apart even when the
    /// upstream never pushes `list_changed` (e.g. no standalone SSE stream).
    /// A refresh whose fingerprint diff shows the catalog moved broadcasts
    /// the changed `*/list_changed` kinds to connected clients — for a
    /// push-less upstream this poll IS the `list_changed` source.
    /// `Weak`-held, so it exits when the engine is dropped.
    pub fn spawn_refreshers(self: &Arc<Self>) {
        for fed in &self.federations {
            let secs = fed.cache.capability_ttl_secs;
            if secs == 0 {
                continue;
            }
            let weak = Arc::downgrade(self);
            let name = fed.name.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(secs));
                tick.tick().await; // consume the immediate first tick
                loop {
                    tick.tick().await;
                    match weak.upgrade() {
                        Some(engine) => {
                            if let Some(changed) = engine.reimport_one(&name).await
                                && changed.any()
                                && let Some(notifier) = &engine.notifier
                            {
                                notifier.broadcast_list_changed(&changed.methods()).await;
                            }
                        }
                        None => return,
                    }
                }
            });
        }
    }

    /// Reconnecting listen loop for one federation. Backs off (capped) when
    /// the stream ends or the upstream has no standalone SSE stream, and exits
    /// once the engine is gone.
    async fn run_listener(weak: Weak<Self>, fed_name: String) {
        const MAX_BACKOFF: Duration = Duration::from_secs(60);
        let mut backoff = Duration::from_secs(1);
        loop {
            let Some(engine) = weak.upgrade() else { return };
            let Some(fed) = engine
                .federations
                .iter()
                .find(|f| f.name == fed_name)
                .cloned()
            else {
                return;
            };
            match engine.listen_once(&fed).await {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(e) => tracing::debug!(
                    federation = %fed_name, error = %e,
                    "federation notification stream ended; will reconnect"
                ),
            }
            drop(engine); // don't hold the Arc across the sleep
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Open one notification stream and process pushes until it ends.
    async fn listen_once(&self, fed: &FederationConfig) -> Result<(), UpstreamError> {
        use futures::StreamExt;
        let bearer = self.bearer_for(fed, FederationCaller::default()).await?;
        let upstream = connect_upstream(self.connect_opts(fed, None, bearer).await?).await?;
        self.record_detected_wire(fed, upstream.as_ref());
        // The trait returns a boxed (Unpin) stream, so no `pin_mut!` needed.
        let mut stream = upstream.open_notifications().await?;
        while let Some(notif) = stream.next().await {
            self.handle_notification(fed, &notif).await;
        }
        upstream.close().await;
        Ok(())
    }

    /// React to one upstream notification. `*/list_changed` refreshes the
    /// overlay (re-import) and forwards the same kind to MCPG's clients;
    /// `resources/updated` re-prefixes the URI and forwards it to subscribers.
    /// Other methods are ignored (the engine advertises no
    /// server-request capability upstream).
    async fn handle_notification(&self, fed: &FederationConfig, notif: &Value) {
        let Some(method) = notif.get("method").and_then(Value::as_str) else {
            return;
        };
        let is_list_changed = matches!(
            method,
            "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/prompts/list_changed"
        );
        if is_list_changed {
            tracing::info!(
                federation = %fed.name, %method,
                "upstream signalled list_changed; refreshing federated capabilities"
            );
            // Re-import just this federation (not every upstream) and
            // republish; broadcast only the kinds whose client-visible
            // catalog actually moved (an upstream churn our filters
            // exclude wakes nobody).
            if let Some(changed) = self.reimport_one(&fed.name).await
                && changed.any()
                && let Some(notifier) = &self.notifier
            {
                notifier.broadcast_list_changed(&changed.methods()).await;
            }
        } else if method == "notifications/resources/updated" {
            let Some(notifier) = &self.notifier else {
                return;
            };
            let Some(upstream_uri) = notif
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(Value::as_str)
            else {
                return;
            };
            // The client subscribed to the *gateway-side* URI; re-apply
            // the same mapping used at import (scheme-aware for `ui://`)
            // so the update reaches the right subscriptions.
            let prefixed = federated_resource_uri(fed, upstream_uri);
            tracing::info!(
                federation = %fed.name, uri = %prefixed,
                "upstream resource updated; forwarding to subscribers"
            );
            notifier.forward_resource_updated(&prefixed).await;
        }
    }

    /// Map an upstream tool to a synthetic gateway tool: prefix the name,
    /// tag the source in `_meta`, and route it back to the upstream.
    fn to_federated_tool(&self, fed: &FederationConfig, tool: UpstreamTool) -> FederatedTool {
        let name = format!("{}{}", fed.tool_prefix(), tool.name);
        // Preserve the upstream tool's `_meta` (notably SEP-1865
        // `_meta.ui`) and tag the source. Then rewrite any
        // `_meta.ui.resourceUri` through the same URI mapping the
        // federated resources use, so a UI tool still points at the
        // `ui://` resource MCPG re-serves.
        let mut meta = merge_source_tag(tool.meta, &fed.name);
        crate::protocol::shared::apps::rewrite_tool_resource_uri(&mut meta, |uri| {
            Some(federated_resource_uri(fed, uri))
        });
        FederatedTool {
            descriptor: ToolDescriptor {
                name,
                title: tool.title,
                description: tool.description.unwrap_or_default(),
                input_schema: tool
                    .input_schema
                    .unwrap_or_else(|| json!({ "type": "object" })),
                output_schema: tool.output_schema,
                annotations: None,
                execution: None,
                icons: None,
                meta: Some(meta),
            },
            route: BackendInvocationRoute::Federated {
                source: fed.name.clone(),
                upstream_name: tool.name,
            },
        }
    }

    /// Map an upstream resource to a synthetic gateway resource: prefix
    /// the URI, tag the source, and route reads back to the upstream.
    fn to_federated_resource(
        &self,
        fed: &FederationConfig,
        resource: UpstreamResource,
    ) -> FederatedResource {
        FederatedResource {
            descriptor: ResourceDescriptor {
                uri: federated_resource_uri(fed, &resource.uri),
                name: resource.name,
                title: resource.title,
                description: resource.description,
                mime_type: resource.mime_type,
                size: None,
                icons: None,
                annotations: None,
                // Preserve upstream `_meta` (notably SEP-1865
                // `_meta.ui` carrying csp/permissions/domain) + tag
                // the source. Operator CSP/permission policy is applied
                // later, on egress.
                meta: Some(merge_source_tag(resource.meta, &fed.name)),
            },
            route: ResourceRoute::Federated {
                source: fed.name.clone(),
                upstream_uri: resource.uri,
            },
        }
    }

    /// Map an upstream resource *template* to a synthetic gateway template:
    /// prefix the `uriTemplate`, tag the source, and carry the prefix so a
    /// matched concrete URI can be de-prefixed back to the upstream URI at
    /// read time (read dispatch reuses [`ResourceRoute::Federated`]).
    fn to_federated_resource_template(
        &self,
        fed: &FederationConfig,
        tmpl: UpstreamResourceTemplate,
    ) -> FederatedResourceTemplate {
        let prefix = fed
            .naming
            .resource_uri_prefix
            .as_deref()
            .unwrap_or("")
            .to_owned();
        FederatedResourceTemplate {
            descriptor: ResourceTemplate {
                uri_template: format!("{prefix}{}", tmpl.uri_template),
                name: tmpl.name,
                title: tmpl.title,
                description: tmpl.description,
                mime_type: tmpl.mime_type,
                annotations: None,
                icons: None,
                // Preserve upstream `_meta` + tag the source. NOTE:
                // unlike concrete `ui://` resources, a `ui://` resource
                // *template* is not scheme-namespaced here — the read
                // path de-prefixes a matched concrete URI by stripping
                // `prefix`, which only works for plain string prefixing.
                // SEP-1865 UI resources are concrete `ui://` URIs in
                // practice, so this is a rare/unsupported shape.
                meta: Some(merge_source_tag(tmpl.meta, &fed.name)),
            },
            source: fed.name.clone(),
            prefix,
        }
    }

    /// Map an upstream prompt to a synthetic gateway prompt: prefix the
    /// name, tag the source, and route `get` back to the upstream.
    fn to_federated_prompt(
        &self,
        fed: &FederationConfig,
        prompt: UpstreamPrompt,
    ) -> FederatedPrompt {
        let prefix = fed.naming.prompt_prefix.as_deref().unwrap_or("");
        FederatedPrompt {
            descriptor: PromptDescriptor {
                name: format!("{prefix}{}", prompt.name),
                title: prompt.title,
                description: prompt.description,
                arguments: prompt
                    .arguments
                    .into_iter()
                    .map(|a| PromptArgument {
                        name: a.name,
                        title: None,
                        description: a.description,
                        required: a.required,
                    })
                    .collect(),
                icons: None,
                meta: Some(merge_source_tag(prompt.meta, &fed.name)),
            },
            route: PromptRoute::Federated {
                source: fed.name.clone(),
                upstream_name: prompt.name,
            },
        }
    }
}

/// Map operator-config trust level to the runtime trust level (the same
/// mapping the native binding path uses).
fn trust_from_config(level: crate::config::policy::TrustLevelConfig) -> RequestTrustLevel {
    use crate::config::policy::TrustLevelConfig;
    match level {
        TrustLevelConfig::Unauthenticated => RequestTrustLevel::Unauthenticated,
        TrustLevelConfig::HeaderAsserted => RequestTrustLevel::HeaderAsserted,
        TrustLevelConfig::Verified => RequestTrustLevel::Verified,
    }
}

/// Fixed machine identity for `oauth_client_credentials` issuance. The grant
/// authenticates MCPG-as-itself (identity-independent), so a constant
/// identity lets the credential cache share one token per `(plugin_id,
/// target)` across all sessions rather than minting one per caller.
pub(crate) fn machine_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "anonymous".into(),
        trust_level: "unauthenticated".into(),
        subject_id: None,
        auth_provider: None,
        issuer: None,
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    }
}

/// Per-caller identity for `oauth_impersonation`: the caller's fully
/// resolved transport identity (subject, trust level, scopes — the
/// credential-cache key and the issuer trust gate both read them) with
/// the caller's bearer attached as the RFC 8693 `subject_token`
/// attribute (the key the token-exchange issuers read). Callers without
/// a resolved identity (legacy paths, tests) degrade to a minimal
/// header-asserted identity — which credential issuers requiring
/// `verified` trust will refuse, exactly as an unverified caller should
/// never be impersonated.
fn impersonation_identity(
    identity: Option<&crate::runtime::RequestIdentity>,
    subject_token: &str,
) -> PluginIdentity {
    let mut plugin_identity = match identity {
        Some(identity) => crate::runtime::plugin_identity_from_request_identity(identity),
        None => PluginIdentity {
            kind: "header_asserted".into(),
            trust_level: "header_asserted".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        },
    };
    plugin_identity
        .attributes
        .insert("subject_token".to_owned(), subject_token.to_owned());
    plugin_identity
}

#[cfg(test)]
mod tests {
    use super::super::upstream::StreamableHttpUpstream;
    use super::*;
    use crate::backends::CapabilityRegistry;
    use axum::Json;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Router, http::StatusCode};
    use serde_json::Value;

    async fn mock_handler(headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let id = body.get("id").cloned();
        match method {
            "initialize" => {
                let mut resp = Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "protocolVersion": "2025-11-25", "capabilities": {},
                                "serverInfo": { "name": "mock", "version": "1" } }
                }))
                .into_response();
                resp.headers_mut()
                    .insert("mcp-session-id", "s1".parse().unwrap());
                resp
            }
            "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
            "tools/list" => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [
                    { "name": "search", "description": "Search", "inputSchema": {"type": "object"} },
                    { "name": "create_page", "description": "Create" },
                    { "name": "internal_reset", "description": "danger" }
                ] }
            }))
            .into_response(),
            "tools/call" => {
                let name = body
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // Echo the inbound Authorization so tests can assert
                // auth-mode plumbing (e.g. pass_through bearer forwarding).
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": format!("ran {name} auth={auth}") }],
                                "isError": false }
                }))
                .into_response()
            }
            _ => Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"nope"}}))
                .into_response(),
        }
    }

    async fn spawn_mock() -> String {
        let app = Router::new().route("/mcp", post(mock_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    fn empty_policy() -> Arc<ArcSwap<FederatedToolPolicies>> {
        Arc::new(ArcSwap::from_pointee(FederatedToolPolicies::default()))
    }

    fn fed_config(url: &str) -> FederationConfig {
        serde_yaml::from_str(&format!(
            r#"
name: notion
upstream:
  url: "{url}"
  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}
naming: {{ tool_prefix: "notion." }}
filter: {{ exclude_tools: ["internal_*"] }}
"#
        ))
        .expect("parse fed config")
    }

    fn caller<'a>(session_id: Option<&'a str>, bearer: Option<&'a str>) -> FederationCaller<'a> {
        FederationCaller {
            principal: None,
            session_id,
            bearer,
            identity: None,
        }
    }

    fn engine_with_tunnel(tf: Option<TunnelFederation>) -> FederationEngine {
        let registry = CapabilityRegistry::default();
        FederationEngine::new(
            vec![],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        )
        .with_tunnel_federation(tf)
    }

    #[test]
    fn resolve_upstream_url_passes_through_http_with_no_token() {
        let engine = engine_with_tunnel(None);
        let (url, token) = engine
            .resolve_upstream_url(&fed_config("https://api.example.com/mcp"))
            .unwrap();
        assert_eq!(url, "https://api.example.com/mcp");
        assert_eq!(token, None);
    }

    #[test]
    fn resolve_upstream_url_rewrites_tunnel_scheme_and_carries_org_token() {
        // Trailing slash on the ingress base is trimmed so the join is clean.
        let engine = engine_with_tunnel(Some(TunnelFederation {
            relay_ingress_url: "https://relay.example.com/".to_owned(),
            token: Some("org-tok".to_owned()),
        }));
        let (url, token) = engine
            .resolve_upstream_url(&fed_config("tunnel://acme-gw/mcp"))
            .unwrap();
        assert_eq!(url, "https://relay.example.com/federate/acme-gw/mcp");
        assert_eq!(token.as_deref(), Some("org-tok"));
    }

    #[test]
    fn resolve_upstream_url_tunnel_without_path_targets_the_named_tunnel_root() {
        let engine = engine_with_tunnel(Some(TunnelFederation {
            relay_ingress_url: "https://relay.example.com".to_owned(),
            token: None,
        }));
        let (url, token) = engine
            .resolve_upstream_url(&fed_config("tunnel://acme-gw"))
            .unwrap();
        assert_eq!(url, "https://relay.example.com/federate/acme-gw");
        assert_eq!(token, None);
    }

    #[test]
    fn resolve_upstream_url_tunnel_without_ingress_config_fails_closed() {
        let engine = engine_with_tunnel(None);
        let err = engine
            .resolve_upstream_url(&fed_config("tunnel://acme-gw/mcp"))
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Connect(_)), "got {err:?}");
    }

    #[test]
    fn to_federated_tool_prefixes_and_tags_source() {
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let fed = fed_config("https://x/mcp");
        let ft = engine.to_federated_tool(
            &fed,
            UpstreamTool {
                name: "search".into(),
                title: None,
                description: Some("Search".into()),
                input_schema: Some(json!({"type": "object"})),
                output_schema: None,
                annotations: None,
                meta: None,
            },
        );
        assert_eq!(ft.descriptor.name, "notion.search");
        assert_eq!(
            ft.descriptor.meta.unwrap()["mcpg"]["source"]["federatedFrom"],
            "notion"
        );
        match ft.route {
            BackendInvocationRoute::Federated {
                source,
                upstream_name,
            } => {
                assert_eq!(source, "notion");
                assert_eq!(upstream_name, "search"); // unprefixed
            }
            other => panic!("expected Federated route, got {other:?}"),
        }
    }

    fn fed_config_with_resource_prefix(url: &str) -> FederationConfig {
        serde_yaml::from_str(&format!(
            r#"
name: notion
upstream:
  url: "{url}"
  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}
naming: {{ tool_prefix: "notion.", resource_uri_prefix: "mcp://notion/" }}
import: {{ resources: true }}
"#
        ))
        .expect("parse fed config")
    }

    #[test]
    fn to_federated_tool_preserves_ui_meta_and_rewrites_resource_uri() {
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let fed = fed_config("https://x/mcp");
        let ft = engine.to_federated_tool(
            &fed,
            UpstreamTool {
                name: "chart".into(),
                title: None,
                description: Some("Chart".into()),
                input_schema: Some(json!({"type": "object"})),
                output_schema: None,
                annotations: None,
                // SEP-1865 Apps metadata on the upstream tool.
                meta: Some(json!({
                    "ui": { "resourceUri": "ui://srv/chart", "visibility": ["model", "app"] }
                })),
            },
        );
        let meta = ft.descriptor.meta.unwrap();
        // source tag added …
        assert_eq!(meta["mcpg"]["source"]["federatedFrom"], "notion");
        // … upstream `_meta.ui` preserved (NOT discarded) …
        assert_eq!(meta["ui"]["visibility"], json!(["model", "app"]));
        // … and resourceUri rewritten scheme-preserving to the URI the
        // gateway re-serves the `ui://` resource under.
        assert_eq!(meta["ui"]["resourceUri"], "ui://notion/srv/chart");
    }

    #[test]
    fn to_federated_resource_rewrites_ui_uri_scheme_preserving() {
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let fed = fed_config_with_resource_prefix("https://x/mcp");
        let fr = engine.to_federated_resource(
            &fed,
            UpstreamResource {
                uri: "ui://srv/chart".into(),
                name: "chart-ui".into(),
                title: None,
                description: None,
                mime_type: Some("text/html;profile=mcp-app".into()),
                meta: Some(json!({ "ui": { "csp": { "connectDomains": ["api.example.com"] } } })),
            },
        );
        // ui:// scheme preserved + namespaced by federation (NOT
        // mcp://notion/ui://… which would destroy the scheme).
        assert_eq!(fr.descriptor.uri, "ui://notion/srv/chart");
        // resource `_meta.ui` (csp) preserved for the egress policy stage.
        assert_eq!(
            fr.descriptor.meta.unwrap()["ui"]["csp"]["connectDomains"],
            json!(["api.example.com"])
        );
        // the route still de-prefixes back to the original upstream URI.
        match fr.route {
            ResourceRoute::Federated {
                source,
                upstream_uri,
            } => {
                assert_eq!(source, "notion");
                assert_eq!(upstream_uri, "ui://srv/chart");
            }
            other => panic!("expected Federated route, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_opts_advertises_apps_upstream_when_enabled() {
        let registry = CapabilityRegistry::default();
        let engine =
            FederationEngine::new(vec![], registry.federated_overlay(), empty_policy(), "via")
                .with_apps_upstream_advertisement(true);
        let fed = fed_config("https://x/mcp");
        let opts = engine
            .connect_opts(&fed, None, None)
            .await
            .expect("connect opts build");
        // The Apps capability is advertised upstream so the server emits
        // its UI tools — including on this (import) session.
        assert_eq!(
            opts.client_capabilities["extensions"]["io.modelcontextprotocol/ui"]["mimeTypes"],
            json!(["text/html;profile=mcp-app"])
        );
    }

    #[tokio::test]
    async fn connect_opts_omits_apps_upstream_by_default() {
        let registry = CapabilityRegistry::default();
        let engine =
            FederationEngine::new(vec![], registry.federated_overlay(), empty_policy(), "via");
        let fed = fed_config("https://x/mcp");
        let opts = engine
            .connect_opts(&fed, None, None)
            .await
            .expect("connect opts build");
        let has_ui = opts
            .client_capabilities
            .get("extensions")
            .and_then(|e| e.get("io.modelcontextprotocol/ui"))
            .is_some();
        assert!(
            !has_ui,
            "apps capability must not be advertised upstream by default"
        );
    }

    #[test]
    fn to_federated_resource_plain_uri_uses_string_prefix() {
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let fed = fed_config_with_resource_prefix("https://x/mcp");
        let fr = engine.to_federated_resource(
            &fed,
            UpstreamResource {
                uri: "file:///doc.txt".into(),
                name: "doc".into(),
                title: None,
                description: None,
                mime_type: Some("text/plain".into()),
                meta: None,
            },
        );
        // non-ui resources keep the historical string-prefix behaviour.
        assert_eq!(fr.descriptor.uri, "mcp://notion/file:///doc.txt");
    }

    #[tokio::test]
    async fn import_all_publishes_filtered_prefixed_tools_into_overlay() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![fed_config(&url)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );

        engine.import_all().await;

        // `internal_reset` is filtered out; `search` + `create_page` import.
        let names: Vec<String> = registry.tools().into_iter().map(|t| t.name).collect();
        assert!(names.contains(&"notion.search".to_owned()), "{names:?}");
        assert!(
            names.contains(&"notion.create_page".to_owned()),
            "{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("internal_reset")),
            "{names:?}"
        );

        // The route resolves and points back to the upstream.
        match registry.tool_route("notion.search") {
            Some(BackendInvocationRoute::Federated {
                source,
                upstream_name,
            }) => {
                assert_eq!(source, "notion");
                assert_eq!(upstream_name, "search");
            }
            other => panic!("expected Federated route, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_upstream_leaves_overlay_empty() {
        let registry = CapabilityRegistry::default();
        // Nothing listening on this loopback port → connect fails.
        let engine = FederationEngine::new(
            vec![fed_config("http://127.0.0.1:1/mcp")],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        engine.import_all().await;
        assert!(registry.federated_overlay().load().is_empty());
        assert!(registry.tools().is_empty());
    }

    #[tokio::test]
    async fn call_tool_dispatches_via_satellite_and_reuses_it() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![fed_config(&url)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );

        let result = engine
            .call_tool(
                "notion",
                "search",
                Some(&json!({ "q": "x" })),
                caller(Some("sess-1"), None),
                None,
            )
            .await
            .expect("call_tool");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("ran search")
        );
        assert_eq!(result["isError"], false);

        // Same (session, source) reuses the satellite; a second call
        // still succeeds.
        let again = engine
            .call_tool(
                "notion",
                "create_page",
                None,
                caller(Some("sess-1"), None),
                None,
            )
            .await
            .expect("reuse satellite");
        assert!(
            again["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("ran create_page")
        );
    }

    #[tokio::test]
    async fn pass_through_forwards_caller_bearer_to_upstream() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let mut fed = fed_config(&url);
        fed.upstream.auth.mode = crate::config::AuthMode::PassThrough;
        let engine = FederationEngine::new(
            vec![fed],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let result = engine
            .call_tool(
                "notion",
                "search",
                None,
                caller(Some("sess-1"), Some("caller-tok")),
                None,
            )
            .await
            .expect("call_tool");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("auth=Bearer caller-tok"),
            "expected forwarded caller bearer, got {result:?}"
        );
    }

    #[tokio::test]
    async fn distinct_principals_never_share_a_satellite() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![fed_config(&url)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        // Two principals presenting the SAME session id (e.g. a shared or
        // stolen `Mcp-Session-Id`) each get their own upstream session.
        for principal in ["verified::idp::iss::alice", "verified::idp::iss::bob"] {
            engine
                .call_tool(
                    "notion",
                    "search",
                    None,
                    FederationCaller {
                        principal: Some(principal),
                        session_id: Some("shared-sess"),
                        bearer: None,
                        identity: None,
                    },
                    None,
                )
                .await
                .expect("call_tool");
        }
        assert_eq!(engine.satellites.len(), 2);
    }

    #[tokio::test]
    async fn same_principal_coalesces_across_sessions() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![fed_config(&url)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        for session in ["sess-1", "sess-2"] {
            engine
                .call_tool(
                    "notion",
                    "search",
                    None,
                    FederationCaller {
                        principal: Some("verified::idp::iss::alice"),
                        session_id: Some(session),
                        bearer: None,
                        identity: None,
                    },
                    None,
                )
                .await
                .expect("call_tool");
        }
        assert_eq!(engine.satellites.len(), 1);
    }

    #[tokio::test]
    async fn pass_through_bearer_partitions_satellites() {
        let url = spawn_mock().await;
        let registry = CapabilityRegistry::default();
        let mut fed = fed_config(&url);
        fed.upstream.auth.mode = crate::config::AuthMode::PassThrough;
        let engine = FederationEngine::new(
            vec![fed],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        // Same principal, two tokens (scope change / rotation): each token
        // gets its own upstream session — never a call on the other's.
        for bearer in ["tok-scope-read", "tok-scope-admin"] {
            engine
                .call_tool(
                    "notion",
                    "search",
                    None,
                    FederationCaller {
                        principal: Some("verified::idp::iss::alice"),
                        session_id: Some("sess-1"),
                        bearer: Some(bearer),
                        identity: None,
                    },
                    None,
                )
                .await
                .expect("call_tool");
        }
        assert_eq!(engine.satellites.len(), 2);
    }

    #[test]
    fn satellite_caller_key_prefers_principal_and_fingerprints_bearer() {
        let fed = fed_config("http://127.0.0.1:1/mcp");
        let with_principal = satellite_caller_key(
            &fed,
            &FederationCaller {
                principal: Some("verified::idp::iss::alice"),
                session_id: Some("sess-1"),
                bearer: Some("tok"),
                identity: None,
            },
        );
        assert_eq!(with_principal, "verified::idp::iss::alice");

        let session_fallback = satellite_caller_key(
            &fed,
            &FederationCaller {
                principal: None,
                session_id: Some("sess-1"),
                bearer: Some("tok"),
                identity: None,
            },
        );
        assert_eq!(session_fallback, "sess-1");

        let mut pass_through = fed.clone();
        pass_through.upstream.auth.mode = crate::config::AuthMode::PassThrough;
        let keyed_a = satellite_caller_key(
            &pass_through,
            &FederationCaller {
                principal: Some("verified::idp::iss::alice"),
                session_id: None,
                bearer: Some("tok-a"),
                identity: None,
            },
        );
        let keyed_b = satellite_caller_key(
            &pass_through,
            &FederationCaller {
                principal: Some("verified::idp::iss::alice"),
                session_id: None,
                bearer: Some("tok-b"),
                identity: None,
            },
        );
        assert!(keyed_a.starts_with("verified::idp::iss::alice#b"));
        assert_ne!(keyed_a, keyed_b);
    }

    #[test]
    fn reimport_fingerprints_flag_only_changed_kinds() {
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            Vec::new(),
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        let fed = fed_config("http://127.0.0.1:1/mcp");
        let tool = |desc: &str| {
            engine.to_federated_tool(
                &fed,
                UpstreamTool {
                    name: "search".into(),
                    title: None,
                    description: Some(desc.into()),
                    input_schema: Some(json!({ "type": "object" })),
                    output_schema: None,
                    annotations: None,
                    meta: None,
                },
            )
        };
        let base = ImportedParts {
            tools: vec![tool("v1")],
            ..ImportedParts::default()
        };
        let unchanged = ChangedKinds::from_fingerprints(
            base.fingerprints(),
            ImportedParts {
                tools: vec![tool("v1")],
                ..ImportedParts::default()
            }
            .fingerprints(),
        );
        assert!(!unchanged.any());

        // A description edit is a client-visible catalog change even
        // though the tool NAME set is identical.
        let description_changed = ChangedKinds::from_fingerprints(
            base.fingerprints(),
            ImportedParts {
                tools: vec![tool("v2")],
                ..ImportedParts::default()
            }
            .fingerprints(),
        );
        assert!(description_changed.tools);
        assert!(!description_changed.resources);
        assert!(!description_changed.prompts);
        assert_eq!(
            description_changed.methods(),
            vec!["notifications/tools/list_changed"]
        );
    }

    struct StubIssuer {
        manifest: mcpg_plugin_protocol::manifest::PluginManifest,
    }

    #[async_trait::async_trait]
    impl mcpg_plugin_protocol::credential::CredentialIssuer for StubIssuer {
        fn manifest(&self) -> &mcpg_plugin_protocol::manifest::PluginManifest {
            &self.manifest
        }
        async fn issue(
            &self,
            _identity: &PluginIdentity,
            _target: &str,
            config: &Value,
        ) -> Result<
            mcpg_plugin_protocol::credential::IssuedCredential,
            mcpg_plugin_protocol::credential::CredentialError,
        > {
            // Echo a per-call config audience into the token so tests can
            // prove the engine forwarded `credential_config`.
            let token = match config.get("audience").and_then(Value::as_str) {
                Some(audience) => format!("tok-for-{audience}"),
                None => "tok-oauth-123".to_owned(),
            };
            Ok(mcpg_plugin_protocol::credential::IssuedCredential::from_value(token, 60))
        }
    }

    #[tokio::test]
    async fn oauth_client_credentials_mints_bearer_for_upstream() {
        use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
        let url = spawn_mock().await;

        // Register a stub credential issuer that mints a known token, then
        // wire it into the engine via the credential subsystem.
        let mut registry = PluginRegistry::new();
        registry
            .register_credential_issuer(
                Arc::new(StubIssuer {
                    manifest: PluginManifest {
                        id: "stub.oauth".into(),
                        version: "0.0.1".into(),
                        name: "stub".into(),
                        plugin_class: PluginClass::CredentialIssuer,
                        protocol_version: "1.0".into(),
                        license: None,
                        required_capabilities: vec![],
                        tags: vec![],
                        provides: vec![],
                        provides_schemes: vec![],
                        module_path_prefix: "stub".into(),
                        backend_profile: None,
                    },
                }),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .expect("register issuer");
        let cache = Arc::new(CredentialCacheKind::Local(Arc::new(
            mcpg_plugin_host::credential_cache::CredentialCache::default(),
        )));

        let mut fed = fed_config(&url);
        fed.upstream.auth.mode = crate::config::AuthMode::OauthClientCredentials;
        fed.upstream.auth.credential = Some("cred://stub.oauth/notion".into());

        let cap = CapabilityRegistry::default();
        let engine =
            FederationEngine::new(vec![fed], cap.federated_overlay(), empty_policy(), "via-1")
                .with_credentials(Arc::new(registry), cache);

        // Dispatch mints + attaches the machine token; the mock echoes it.
        let result = engine
            .call_tool("notion", "search", None, caller(Some("sess-1"), None), None)
            .await
            .expect("call_tool");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("auth=Bearer tok-oauth-123"),
            "expected minted client-credentials bearer, got {result:?}"
        );
    }

    #[tokio::test]
    async fn oauth_credential_config_reaches_the_issuer() {
        use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
        let url = spawn_mock().await;

        let mut registry = PluginRegistry::new();
        registry
            .register_credential_issuer(
                Arc::new(StubIssuer {
                    manifest: PluginManifest {
                        id: "stub.oauth".into(),
                        version: "0.0.1".into(),
                        name: "stub".into(),
                        plugin_class: PluginClass::CredentialIssuer,
                        protocol_version: "1.0".into(),
                        license: None,
                        required_capabilities: vec![],
                        tags: vec![],
                        provides: vec![],
                        provides_schemes: vec![],
                        module_path_prefix: "stub".into(),
                        backend_profile: None,
                    },
                }),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .expect("register issuer");
        let cache = Arc::new(CredentialCacheKind::Local(Arc::new(
            mcpg_plugin_host::credential_cache::CredentialCache::default(),
        )));

        let mut fed = fed_config(&url);
        fed.upstream.auth.mode = crate::config::AuthMode::OauthClientCredentials;
        fed.upstream.auth.credential = Some("cred://stub.oauth/notion".into());
        // The federation's per-call issuer config (what registry OAuth
        // discovery injects) must reach the issuer's `config` argument.
        fed.upstream.auth.credential_config =
            Some(serde_json::json!({ "audience": "https://aud.example" }));

        let cap = CapabilityRegistry::default();
        let engine =
            FederationEngine::new(vec![fed], cap.federated_overlay(), empty_policy(), "via-1")
                .with_credentials(Arc::new(registry), cache);

        let result = engine
            .call_tool("notion", "search", None, caller(Some("sess-1"), None), None)
            .await
            .expect("call_tool");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("auth=Bearer tok-for-https://aud.example"),
            "expected the issuer to receive credential_config, got {result:?}"
        );
    }

    /// Stub token-exchange issuer: echoes the caller's `subject_token` (from
    /// the identity attributes) as `exchanged-<subject>`, so a test can prove
    /// the caller's bearer was passed through + exchanged.
    struct ExchangeStubIssuer {
        manifest: mcpg_plugin_protocol::manifest::PluginManifest,
    }

    #[async_trait::async_trait]
    impl mcpg_plugin_protocol::credential::CredentialIssuer for ExchangeStubIssuer {
        fn manifest(&self) -> &mcpg_plugin_protocol::manifest::PluginManifest {
            &self.manifest
        }
        async fn issue(
            &self,
            identity: &PluginIdentity,
            _target: &str,
            _config: &Value,
        ) -> Result<
            mcpg_plugin_protocol::credential::IssuedCredential,
            mcpg_plugin_protocol::credential::CredentialError,
        > {
            let subject = identity
                .attributes
                .get("subject_token")
                .cloned()
                .unwrap_or_default();
            Ok(
                mcpg_plugin_protocol::credential::IssuedCredential::from_value(
                    format!("exchanged-{subject}"),
                    60,
                ),
            )
        }
    }

    #[tokio::test]
    async fn oauth_impersonation_exchanges_caller_bearer_for_upstream() {
        use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
        let url = spawn_mock().await;

        let mut registry = PluginRegistry::new();
        registry
            .register_credential_issuer(
                Arc::new(ExchangeStubIssuer {
                    manifest: PluginManifest {
                        id: "stub.exchange".into(),
                        version: "0.0.1".into(),
                        name: "stub-exchange".into(),
                        plugin_class: PluginClass::CredentialIssuer,
                        protocol_version: "1.0".into(),
                        license: None,
                        required_capabilities: vec![],
                        tags: vec![],
                        provides: vec![],
                        provides_schemes: vec![],
                        module_path_prefix: "stub".into(),
                        backend_profile: None,
                    },
                }),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .expect("register issuer");
        let cache = Arc::new(CredentialCacheKind::Local(Arc::new(
            mcpg_plugin_host::credential_cache::CredentialCache::default(),
        )));

        let mut fed = fed_config(&url);
        fed.upstream.auth.mode = crate::config::AuthMode::OauthImpersonation;
        fed.upstream.auth.credential = Some("cred://stub.exchange/notion".into());

        let cap = CapabilityRegistry::default();
        let engine =
            FederationEngine::new(vec![fed], cap.federated_overlay(), empty_policy(), "via-1")
                .with_credentials(Arc::new(registry), cache);

        // Dispatch carries the caller's bearer; it is exchanged and the
        // upstream sees the exchanged (not the original) token.
        let result = engine
            .call_tool(
                "notion",
                "search",
                None,
                caller(Some("sess-1"), Some("caller-xyz")),
                None,
            )
            .await
            .expect("call_tool");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("auth=Bearer exchanged-caller-xyz"),
            "expected the exchanged caller token at the upstream, got {result:?}"
        );
    }

    /// Mock that serves the normal POST endpoint plus a GET SSE stream which
    /// pushes one `notifications/tools/list_changed` frame then ends.
    async fn spawn_mock_with_list_changed_push() -> String {
        async fn push_handler() -> Response {
            let frame = format!(
                "data: {}\n\n",
                json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })
            );
            let mut resp = Response::new(axum::body::Body::from(frame));
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                "text/event-stream".parse().unwrap(),
            );
            resp
        }
        let app = Router::new().route("/mcp", post(mock_handler).get(push_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    #[tokio::test]
    async fn listener_reimports_on_upstream_list_changed() {
        let url = spawn_mock_with_list_changed_push().await;
        let registry = CapabilityRegistry::default();
        let engine = Arc::new(FederationEngine::new(
            vec![fed_config(&url)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        ));
        // No boot import — the overlay starts empty.
        assert!(registry.tools().is_empty());

        engine.spawn_listeners();

        // The listener connects, receives the pushed tools/list_changed, and
        // refreshes the overlay by re-importing.
        let mut imported = false;
        for _ in 0..40 {
            if registry.tools().iter().any(|t| t.name == "notion.search") {
                imported = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            imported,
            "listener should re-import on upstream list_changed"
        );
    }

    #[tokio::test]
    async fn resource_updated_is_reprefixed_and_forwarded_to_subscriber() {
        use crate::runtime::delivery_bus::BusBackedDeliveryBus;
        use crate::runtime::session_store::{KvBackedSessionStore, SessionStoreConfig};
        use crate::runtime::subscription_store::KvBackedSubscriptionStore;

        let delivery_bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let subscription_store: Arc<dyn SubscriptionStore> =
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        let session_store: Arc<dyn SessionStore> = Arc::new(KvBackedSessionStore::new_in_memory(
            SessionStoreConfig::default(),
        ));

        // A client subscribed to the PREFIXED federated URI, listening on its
        // delivery stream.
        let prefixed = "mcp://notion/notes/1";
        subscription_store
            .subscribe("sess-1", prefixed, None)
            .unwrap();
        let mut rx = delivery_bus.subscribe("sess-1").await;

        let mut fed = fed_config("http://127.0.0.1:1/mcp");
        fed.naming.resource_uri_prefix = Some("mcp://notion/".into());
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![fed.clone()],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        )
        .with_notifier(session_store, delivery_bus, subscription_store);

        // Upstream pushes `resources/updated` for the UNPREFIXED uri; the
        // gateway re-prefixes it so the subscription matches.
        let notif = json!({
            "jsonrpc": "2.0", "method": "notifications/resources/updated",
            "params": { "uri": "notes/1" }
        });
        engine.handle_notification(&fed, &notif).await;

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("delivery within timeout")
            .expect("a delivery message");
        assert_eq!(
            msg.jsonrpc_message["method"],
            "notifications/resources/updated"
        );
        assert_eq!(msg.jsonrpc_message["params"]["uri"], prefixed);
    }

    /// Mock whose `tools/call` answers with an SSE stream: an
    /// `elicitation/create` server-request followed by the terminal result.
    /// Any POSTed JSON-RPC response (the client's answer) is acked.
    async fn spawn_mock_with_elicitation() -> String {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "initialize" => {
                    let mut resp = Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "protocolVersion": "2025-11-25", "capabilities": {},
                                    "serverInfo": { "name": "mock", "version": "1" } }
                    }))
                    .into_response();
                    resp.headers_mut()
                        .insert("mcp-session-id", "s1".parse().unwrap());
                    resp
                }
                "tools/call" => {
                    let call_id = id.unwrap_or(json!(1));
                    let frames = format!(
                        "data: {}\n\ndata: {}\n\n",
                        json!({ "jsonrpc": "2.0", "id": "u1", "method": "elicitation/create",
                                "params": { "message": "name?" } }),
                        json!({ "jsonrpc": "2.0", "id": call_id,
                                "result": { "content": [{ "type": "text", "text": "elicited:ada" }],
                                            "isError": false } }),
                    );
                    let mut resp = Response::new(axum::body::Body::from(frames));
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/event-stream".parse().unwrap(),
                    );
                    resp
                }
                // notifications/initialized + the client's elicitation answer.
                _ => StatusCode::ACCEPTED.into_response(),
            }
        }
        let app = Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    #[tokio::test]
    async fn call_tool_bridges_upstream_elicitation_to_client() {
        use crate::runtime::delivery_bus::BusBackedDeliveryBus;
        let url = spawn_mock_with_elicitation().await;
        let upstream = StreamableHttpUpstream::connect(UpstreamConnectOptions {
            url,
            bearer_token: None,
            tunnel_token: None,
            allow_private: true,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(5),
            gateway_via: "via-1".into(),
            client_capabilities: json!({ "elicitation": {} }),
            transport: crate::config::UpstreamTransport::StreamableHttp,
            headers: std::collections::BTreeMap::new(),
            command: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            modern: false,
            probe: false,
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        })
        .await
        .expect("connect");

        // A bridge + a fake client that answers the elicitation it receives.
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));
        let mut rx = bus.subscribe("sess-1").await;
        let answerer = Arc::clone(&bridge);
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let id = msg.jsonrpc_message["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                answerer
                    .deliver_response(
                        &id,
                        "sess-1",
                        Some(json!({ "action": "accept", "content": { "name": "ada" } })),
                        None,
                    )
                    .await;
            }
        });

        struct Bridger {
            bridge: Arc<ServerRequestBridge>,
        }
        #[async_trait::async_trait]
        impl UpstreamServerRequestHandler for Bridger {
            async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
                // Downstream-facing id differs from the upstream's request id.
                self.bridge
                    .ask_client(
                        "sess-1",
                        "fed-test-1".into(),
                        method,
                        params,
                        Duration::from_secs(5),
                    )
                    .await
                    .map_err(|e| (-32603, e.to_string()))
            }
        }
        let handler = Bridger {
            bridge: Arc::clone(&bridge),
        };

        let result = upstream
            .call_tool_bridged("ask", None, None, &handler, None)
            .await
            .expect("bridged call");
        // The terminal result arrives only after the interleaved elicitation
        // was bridged to the client and answered.
        assert_eq!(
            result["content"][0]["text"], "elicited:ada",
            "expected terminal result after bridging, got {result:?}"
        );
    }

    /// Subscribe to `session`'s delivery stream (so no publish is missed) and
    /// spawn a task answering every bridged server-request with `answer` (the
    /// fake downstream client). Must be awaited before any bridging begins.
    async fn spawn_answering_client(
        bridge: Arc<ServerRequestBridge>,
        bus: &Arc<dyn DeliveryBus>,
        session: &str,
        answer: Value,
    ) {
        let mut rx = bus.subscribe(session).await;
        let session = session.to_owned();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Some(id) = msg.jsonrpc_message["id"].as_str() {
                    bridge
                        .deliver_response(id, &session, Some(answer.clone()), None)
                        .await;
                }
            }
        });
    }

    #[tokio::test]
    async fn bridge_handler_gates_on_downstream_caps() {
        use crate::runtime::delivery_bus::BusBackedDeliveryBus;
        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));
        spawn_answering_client(Arc::clone(&bridge), &bus, "sess-1", json!({ "ok": true })).await;

        // The session advertised sampling + roots, but NOT elicitation.
        let caps: ClientCapabilities =
            serde_json::from_value(json!({ "sampling": {}, "roots": {} })).unwrap();
        let handler = FederatedBridgeHandler {
            bridge: Some(Arc::clone(&bridge)),
            session_id: Some("sess-1".into()),
            caps,
        };

        // Advertised methods bridge through to the answering client.
        assert!(
            handler
                .handle("sampling/createMessage", json!({}))
                .await
                .is_ok()
        );
        assert!(handler.handle("roots/list", json!({})).await.is_ok());
        // Un-advertised + unknown methods are declined (-32601), never surfaced.
        assert_eq!(
            handler
                .handle("elicitation/create", json!({}))
                .await
                .unwrap_err()
                .0,
            -32601
        );
        assert_eq!(
            handler.handle("foo/bar", json!({})).await.unwrap_err().0,
            -32601
        );
    }

    /// Mock whose `resources/read` interleaves a `sampling/createMessage`
    /// server-request before the terminal read result.
    async fn spawn_mock_resource_with_sampling() -> String {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "initialize" => {
                    let mut resp = Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "protocolVersion": "2025-11-25", "capabilities": {},
                                    "serverInfo": { "name": "mock", "version": "1" } }
                    }))
                    .into_response();
                    resp.headers_mut()
                        .insert("mcp-session-id", "s1".parse().unwrap());
                    resp
                }
                "resources/read" => {
                    let read_id = id.unwrap_or(json!(1));
                    let frames = format!(
                        "data: {}\n\ndata: {}\n\n",
                        json!({ "jsonrpc": "2.0", "id": "u9", "method": "sampling/createMessage",
                                "params": { "messages": [] } }),
                        json!({ "jsonrpc": "2.0", "id": read_id,
                                "result": { "contents": [{ "uri": "notes/1", "text": "read-after-sampling" }] } }),
                    );
                    let mut resp = Response::new(axum::body::Body::from(frames));
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/event-stream".parse().unwrap(),
                    );
                    resp
                }
                _ => StatusCode::ACCEPTED.into_response(),
            }
        }
        let app = Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    #[tokio::test]
    async fn read_resource_bridges_upstream_sampling() {
        use crate::runtime::delivery_bus::BusBackedDeliveryBus;
        let url = spawn_mock_resource_with_sampling().await;
        let upstream = StreamableHttpUpstream::connect(UpstreamConnectOptions {
            url,
            bearer_token: None,
            tunnel_token: None,
            allow_private: true,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(5),
            gateway_via: "via-1".into(),
            client_capabilities: json!({ "sampling": {} }),
            transport: crate::config::UpstreamTransport::StreamableHttp,
            headers: std::collections::BTreeMap::new(),
            command: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            modern: false,
            probe: false,
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        })
        .await
        .expect("connect");

        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));
        spawn_answering_client(
            Arc::clone(&bridge),
            &bus,
            "sess-1",
            json!({ "role": "assistant", "content": { "type": "text", "text": "sampled" } }),
        )
        .await;

        struct Bridger {
            bridge: Arc<ServerRequestBridge>,
        }
        #[async_trait::async_trait]
        impl UpstreamServerRequestHandler for Bridger {
            async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
                self.bridge
                    .ask_client(
                        "sess-1",
                        next_bridge_id(),
                        method,
                        params,
                        Duration::from_secs(5),
                    )
                    .await
                    .map_err(|e| (-32603, e.to_string()))
            }
        }
        let handler = Bridger {
            bridge: Arc::clone(&bridge),
        };

        let result = upstream
            .read_resource_bridged("notes/1", &handler)
            .await
            .expect("bridged read");
        assert_eq!(
            result["contents"][0]["text"], "read-after-sampling",
            "expected read result after bridging the interleaved sampling, got {result:?}"
        );
    }

    /// Mock whose `tools/call` emits a `notifications/progress` before the result.
    async fn spawn_mock_with_progress() -> String {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "initialize" => {
                    let mut resp = Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "protocolVersion": "2025-11-25", "capabilities": {},
                                    "serverInfo": { "name": "mock", "version": "1" } }
                    }))
                    .into_response();
                    resp.headers_mut()
                        .insert("mcp-session-id", "s1".parse().unwrap());
                    resp
                }
                "tools/call" => {
                    let call_id = id.unwrap_or(json!(1));
                    // Report progress under the token the client passed in
                    // `_meta.progressToken` (proves pass-through correlation).
                    let token = body
                        .get("params")
                        .and_then(|p| p.get("_meta"))
                        .and_then(|m| m.get("progressToken"))
                        .cloned()
                        .unwrap_or(json!("none"));
                    let frames = format!(
                        "data: {}\n\ndata: {}\n\n",
                        json!({ "jsonrpc": "2.0", "method": "notifications/progress",
                                "params": { "progressToken": token, "progress": 50, "total": 100 } }),
                        json!({ "jsonrpc": "2.0", "id": call_id,
                                "result": { "content": [{ "type": "text", "text": "done" }],
                                            "isError": false } }),
                    );
                    let mut resp = Response::new(axum::body::Body::from(frames));
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/event-stream".parse().unwrap(),
                    );
                    resp
                }
                _ => StatusCode::ACCEPTED.into_response(),
            }
        }
        let app = Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    #[tokio::test]
    async fn call_tool_forwards_upstream_progress_to_client() {
        use crate::runtime::delivery_bus::BusBackedDeliveryBus;
        let url = spawn_mock_with_progress().await;
        let upstream = StreamableHttpUpstream::connect(UpstreamConnectOptions {
            url,
            bearer_token: None,
            tunnel_token: None,
            allow_private: true,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(5),
            gateway_via: "via-1".into(),
            client_capabilities: json!({}),
            transport: crate::config::UpstreamTransport::StreamableHttp,
            headers: std::collections::BTreeMap::new(),
            command: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            modern: false,
            probe: false,
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        })
        .await
        .expect("connect");

        let bus: Arc<dyn DeliveryBus> = Arc::new(BusBackedDeliveryBus::new_in_memory());
        let bridge = Arc::new(ServerRequestBridge::new(Arc::clone(&bus)));
        let mut rx = bus.subscribe("sess-1").await;

        struct ProgressForwarder {
            bridge: Arc<ServerRequestBridge>,
        }
        #[async_trait::async_trait]
        impl UpstreamServerRequestHandler for ProgressForwarder {
            async fn handle(&self, _m: &str, _p: Value) -> Result<Value, (i64, String)> {
                Err((-32601, "no requests in this test".into()))
            }
            async fn forward_notification(&self, method: &str, params: Value) {
                let jsonrpc = json!({ "jsonrpc": "2.0", "method": method, "params": params });
                self.bridge.forward_notification("sess-1", jsonrpc).await;
            }
        }
        let handler = ProgressForwarder {
            bridge: Arc::clone(&bridge),
        };

        // Pass the client's progress token; the upstream echoes it on progress.
        let result = upstream
            .call_tool_bridged("work", None, None, &handler, Some(&json!("client-tok")))
            .await
            .expect("bridged call");
        assert_eq!(result["content"][0]["text"], "done");

        // The interleaved progress reached the client's delivery stream, under
        // the client's own token (correlatable).
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("delivery within timeout")
            .expect("a delivery message");
        assert_eq!(msg.jsonrpc_message["method"], "notifications/progress");
        assert_eq!(msg.jsonrpc_message["params"]["progressToken"], "client-tok");
        assert_eq!(msg.jsonrpc_message["params"]["progress"], 50);
    }

    #[tokio::test]
    async fn reimport_one_preserves_other_federations() {
        let url_a = spawn_mock().await;
        let url_b = spawn_mock().await;
        let cfg = |name: &str, url: &str| -> FederationConfig {
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"{url}\"\n  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}\nnaming: {{ tool_prefix: \"{name}.\" }}"
            ))
            .expect("parse fed config")
        };
        let registry = CapabilityRegistry::default();
        let engine = FederationEngine::new(
            vec![cfg("aaa", &url_a), cfg("bbb", &url_b)],
            registry.federated_overlay(),
            empty_policy(),
            "via-1",
        );

        // Boot import registers both federations' tools.
        engine.import_all().await;
        let names: Vec<String> = registry.tools().into_iter().map(|t| t.name).collect();
        assert!(names.iter().any(|n| n == "aaa.search"), "{names:?}");
        assert!(names.iter().any(|n| n == "bbb.search"), "{names:?}");

        // Re-importing only `aaa` must leave `bbb`'s capabilities in place.
        engine.reimport_one("aaa").await;
        let names: Vec<String> = registry.tools().into_iter().map(|t| t.name).collect();
        assert!(
            names.iter().any(|n| n == "aaa.search"),
            "aaa refreshed: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "bbb.search"),
            "bbb preserved after re-importing only aaa: {names:?}"
        );
    }

    /// A reload seeds the fresh engine's overlay from the prior runtime, so
    /// federated tools survive the swap itself. But `republish` rebuilds the
    /// overlay solely from the per-federation import cache, and a fresh engine
    /// starts with that cache empty — so the first TTL refresh or upstream
    /// `list_changed` for ONE federation republished a catalog containing only
    /// that federation, atomically wiping every other one. Carrying the cache
    /// across is what keeps the seeded overlay true.
    #[tokio::test]
    async fn adopt_imported_survives_a_single_federation_refresh_after_reload() {
        let url_a = spawn_mock().await;
        let url_b = spawn_mock().await;
        let cfg = |name: &str, url: &str| -> FederationConfig {
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"{url}\"\n  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}\nnaming: {{ tool_prefix: \"{name}.\" }}"
            ))
            .expect("parse fed config")
        };

        // Prior engine: both federations imported.
        let reg_old = CapabilityRegistry::default();
        let old = FederationEngine::new(
            vec![cfg("aaa", &url_a), cfg("bbb", &url_b)],
            reg_old.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        old.import_all().await;

        // Reload: same config, fresh engine, no re-import (config unchanged).
        let reg_new = CapabilityRegistry::default();
        let new = FederationEngine::new(
            vec![cfg("aaa", &url_a), cfg("bbb", &url_b)],
            reg_new.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        new.adopt_imported(&old);

        // A TTL refresh / list_changed push for one federation republishes.
        new.reimport_one("aaa").await;
        let names: Vec<String> = reg_new.tools().into_iter().map(|t| t.name).collect();
        assert!(
            names.iter().any(|n| n == "aaa.search"),
            "refreshed federation present: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "bbb.search"),
            "the OTHER federation must survive a single-federation refresh \
             after reload: {names:?}"
        );
    }

    /// A federation dropped from the config must not come back with the cache.
    #[tokio::test]
    async fn adopt_imported_does_not_resurrect_removed_federations() {
        let url_a = spawn_mock().await;
        let url_b = spawn_mock().await;
        let cfg = |name: &str, url: &str| -> FederationConfig {
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"{url}\"\n  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}\nnaming: {{ tool_prefix: \"{name}.\" }}"
            ))
            .expect("parse fed config")
        };
        let reg_old = CapabilityRegistry::default();
        let old = FederationEngine::new(
            vec![cfg("aaa", &url_a), cfg("bbb", &url_b)],
            reg_old.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        old.import_all().await;

        // Reload drops `bbb`.
        let reg_new = CapabilityRegistry::default();
        let new = FederationEngine::new(
            vec![cfg("aaa", &url_a)],
            reg_new.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        new.adopt_imported(&old);
        new.reimport_one("aaa").await;

        let names: Vec<String> = reg_new.tools().into_iter().map(|t| t.name).collect();
        assert!(names.iter().any(|n| n == "aaa.search"), "{names:?}");
        assert!(
            !names.iter().any(|n| n == "bbb.search"),
            "a federation removed from config must not be carried: {names:?}"
        );
    }

    #[tokio::test]
    async fn adopt_satellites_carries_only_unchanged_federations() {
        let url = spawn_mock().await;
        let cfg = |name: &str, url: &str| -> FederationConfig {
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"{url}\"\n  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}\nnaming: {{ tool_prefix: \"{name}.\" }}"
            ))
            .expect("parse fed config")
        };

        // Old engine: two federations, each with an established dispatch
        // satellite for session "s".
        let reg_old = CapabilityRegistry::default();
        let old = FederationEngine::new(
            vec![cfg("aaa", &url), cfg("bbb", &url)],
            reg_old.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        old.call_tool("aaa", "search", None, caller(Some("s"), None), None)
            .await
            .expect("aaa call");
        old.call_tool("bbb", "search", None, caller(Some("s"), None), None)
            .await
            .expect("bbb call");
        assert_eq!(old.satellites.len(), 2);

        // New engine (reload): `aaa` byte-identical (carry), `bbb` URL changed
        // (must drop — its satellite could hold a stale target/auth).
        let reg_new = CapabilityRegistry::default();
        let new = FederationEngine::new(
            vec![cfg("aaa", &url), cfg("bbb", "http://127.0.0.1:1/mcp")],
            reg_new.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        new.adopt_satellites(&old);

        assert!(
            new.satellites
                .contains_key(&("s".to_owned(), "aaa".to_owned())),
            "unchanged federation's satellite should be carried across reload"
        );
        assert!(
            !new.satellites
                .contains_key(&("s".to_owned(), "bbb".to_owned())),
            "changed federation's satellite must be dropped"
        );
    }

    /// Mock whose every `initialize` bumps a shared counter, so a test can tell
    /// whether a dispatch reused a warm satellite or re-established one.
    async fn spawn_mock_counting_inits(inits: Arc<std::sync::atomic::AtomicUsize>) -> String {
        use std::sync::atomic::Ordering;
        let app = Router::new().route(
            "/mcp",
            post(move |Json(body): Json<Value>| {
                let inits = Arc::clone(&inits);
                async move {
                    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
                    let id = body.get("id").cloned();
                    match method {
                        "initialize" => {
                            inits.fetch_add(1, Ordering::Relaxed);
                            let mut resp = Json(json!({
                                "jsonrpc": "2.0", "id": id,
                                "result": { "protocolVersion": "2025-11-25", "capabilities": {},
                                            "serverInfo": { "name": "mock", "version": "1" } }
                            }))
                            .into_response();
                            resp.headers_mut()
                                .insert("mcp-session-id", "s1".parse().unwrap());
                            resp
                        }
                        "tools/list" => Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "tools": [
                                { "name": "search", "description": "s", "inputSchema": {"type":"object"} }
                            ] }
                        }))
                        .into_response(),
                        "tools/call" => Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "content": [{ "type": "text", "text": "ok" }], "isError": false }
                        }))
                        .into_response(),
                        // Unknown request (e.g. the `server/discover`
                        // wire probe): method-not-found, so the probing
                        // client falls back to the legacy handshake.
                        _ if id.is_some() => Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32601, "message": "method not found" }
                        }))
                        .into_response(),
                        _ => StatusCode::ACCEPTED.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/mcp")
    }

    /// The reload-preservation guarantee, end to end at the engine level: a
    /// dispatch satellite established on the old engine and adopted by the new
    /// one (unchanged federation) is *reused* — the upstream never sees a
    /// second `initialize`. (A full HTTP-driven `reload_config` e2e is
    /// impractical: that path rebuilds the plugin registry — environment-
    /// fragile, see `admin_reload_e2e` — and the per-federation SSE listener's
    /// reconnect loop makes a global initialize count non-deterministic. This
    /// drives the real `call_tool` → satellite → `adopt_satellites` → reuse
    /// path deterministically instead.)
    #[tokio::test]
    async fn adopted_satellite_is_reused_without_reconnecting() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let inits = Arc::new(AtomicUsize::new(0));
        let url = spawn_mock_counting_inits(Arc::clone(&inits)).await;
        let cfg = |name: &str, url: &str| -> FederationConfig {
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"{url}\"\n  upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}\nnaming: {{ tool_prefix: \"{name}.\" }}"
            ))
            .expect("parse fed config")
        };

        // Establish a dispatch satellite on the old engine (one initialize).
        let reg = CapabilityRegistry::default();
        let old = FederationEngine::new(
            vec![cfg("aaa", &url)],
            reg.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        old.call_tool("aaa", "search", None, caller(Some("s"), None), None)
            .await
            .expect("establish satellite");
        assert_eq!(
            inits.load(Ordering::Relaxed),
            1,
            "satellite established with exactly one initialize"
        );

        // Reload: the new engine adopts the unchanged federation's satellite.
        let reg2 = CapabilityRegistry::default();
        let new = FederationEngine::new(
            vec![cfg("aaa", &url)],
            reg2.federated_overlay(),
            empty_policy(),
            "via-1",
        );
        new.adopt_satellites(&old);

        // Dispatching on the new engine reuses the carried session — no second
        // initialize handshake to the upstream.
        new.call_tool("aaa", "search", None, caller(Some("s"), None), None)
            .await
            .expect("reuse carried satellite");
        assert_eq!(
            inits.load(Ordering::Relaxed),
            1,
            "carried satellite reused across reload, not reconnected"
        );
    }
}
