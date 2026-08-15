//! `GatewayBackendHost` — concrete [`BackendHost`] backed by the
//! gateway's plugin registry.
//!
//! Bindings (currently only the LLM Generator binding) call
//! `host.invoke_tool(...)` to dispatch a child tool call. This host
//! resolves the tool name to a plugin kind + profile, looks up the
//! plugin in the registry, and forwards the call. Returns the
//! plugin's response parsed as JSON.
//!
//! ## Scope
//!
//! Every cdylib-backed tool binding is reachable as a child tool: the
//! host resolves the binding's kind to a registry plugin and dispatches
//! `plugin.execute(&profile, request)` directly — the same inline
//! dispatch the gateway's `execute_envelope_plugin` performs, and the
//! same dispatch `invoke_tool` already runs below. A few binding kinds
//! are deliberately excluded for reasons unrelated to dispatch:
//! `command` (process exec side-effect), `mock` (test fixture),
//! `openapi` (synthetic tool names produced at boot, not 1:1 with the
//! binding), and `pipeline` (multi-step recursion routed through the
//! execution dispatcher, not a single plugin profile).
//!
//! ## Safety guarantees
//!
//! - **Depth cap**: `invoke_tool` refuses calls when
//!   `ctx.depth >= max_depth`. Backstop against runaway recursion if
//!   cycle detection misses an edge.
//! - **Cycle detection**: not yet implemented in this host (single
//!   layer of agentic dispatch is the common case; multi-layer cycles
//!   are rare in practice and the depth cap is sufficient). When
//!   federation lands and child chains can include remote MCPs, this
//!   host will track an `initiating_backend` chain and refuse loops.
//! - **Opt-in authorization**: with
//!   `governance.child_invoke.enforce_gates` set, child calls run the
//!   SAME three-gate stack a direct tools/call runs, in the same order:
//!   first the external policy_engine chain, then the built-in trust
//!   floor and per-tool CEL `allow_if` gate (`governance.minimum_trust`
//!   and `allow_if`) evaluated against the child tool name with the
//!   caller's inherited identity, then the `ToolGatePlugin` chain — all
//!   before dispatch. Off by default, in which case the child surface is
//!   ungated; only enable child tools you'd allow the binding's principal
//!   to call directly. The gate fails closed: a missing identity is
//!   treated as anonymous/unauthenticated, and the built-in policy layer
//!   denies rather than being skipped if its handle isn't wired.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mcpg_backend_llm_shared::cache::{CacheKey, ResponseCache};
use mcpg_backend_llm_shared::content_store::{ContentStoreError, ContentToStore};
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendHostError, BackendInvocationContext, BackendRequest,
    BackendResource, async_trait,
};
use serde_json::Value;

use crate::config::BackendConfig;
use crate::runtime::content_store_registry::ContentStoreRegistry;

/// Namespace a plugin-supplied host-cache key by the calling binding so
/// the shared `response_cache` can't be read or poisoned across bindings:
/// binding A's `cache_get("k")` and binding B's never collide. The NUL
/// separator can't appear in the alias (a plugin id) so the prefix is
/// unambiguous. Closes the cross-binding cache read/poison surface on the
/// `cache_*` host-FFI slots.
fn namespaced_cache_key(ctx: &BackendInvocationContext, key: &str) -> String {
    format!("{}\u{0}{}", ctx.initiating_backend, key)
}

/// Backend kinds that are never eligible as LLM child tools: process
/// exec side-effects (`command`), the test fixture (`mock`), the
/// synthetic boot-time tool source (`openapi`), and multi-step
/// recursion (`pipeline`). This is a distinct concern from
/// [`crate::backends::binding_plugin_kind`]'s `http`/`pipeline`
/// registry-dispatch exclusion — the two lists overlap only on
/// `pipeline` and must not be conflated.
const CHILD_TOOL_INELIGIBLE_KINDS: &[&str] = &["command", "mock", "openapi", "pipeline"];

/// One child-tool routing entry: which plugin handles a given tool
/// name, and what profile to call within it.
#[derive(Debug, Clone)]
struct ChildToolRoute {
    /// Plugin kind for [`PluginRegistry::binding`] lookup. Owned because
    /// the generic `{ kind, …spec }` binding carries a runtime kind string
    /// (the typed variants supply a `&'static str` literal).
    kind: String,
    /// Per-binding profile name.
    profile: String,
}

/// In-process broadcast list for [`mcpg_plugin_protocol::SecretRotationCallback`]
/// subscribers. Cheap to clone — interior state lives behind an
/// `Arc<Mutex>`. Mirrors `mcpg_plugin_host::credential_cache`'s
/// `RevocationSubscription` shape.
#[derive(Clone, Default)]
pub struct SecretRotationBroadcaster {
    inner: Arc<Mutex<RotationBroadcasterInner>>,
}

#[derive(Default)]
struct RotationBroadcasterInner {
    /// `(subscription_id, callback)` pairs. Drop of a
    /// [`SecretRotationGuard`] removes the matching id.
    subscribers: Vec<(u64, mcpg_plugin_protocol::SecretRotationCallback)>,
    next_id: u64,
}

impl SecretRotationBroadcaster {
    /// Construct an empty broadcaster.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a callback. Returns a guard whose drop unsubscribes.
    pub fn subscribe(
        &self,
        cb: mcpg_plugin_protocol::SecretRotationCallback,
    ) -> SecretRotationGuard {
        let mut guard = self
            .inner
            .lock()
            .expect("rotation broadcaster mutex poisoned");
        let id = guard.next_id;
        guard.next_id = id.wrapping_add(1);
        guard.subscribers.push((id, cb));
        SecretRotationGuard {
            inner: Arc::clone(&self.inner),
            id,
        }
    }

    /// Fan a rotation event out to every registered subscriber. The
    /// per-callback closure runs synchronously inside the lock — keep
    /// closures short and let them spawn for any long work.
    pub fn notify(&self, secret_ref: &str, version: u64) -> usize {
        let guard = self
            .inner
            .lock()
            .expect("rotation broadcaster mutex poisoned");
        let count = guard.subscribers.len();
        for (_, cb) in guard.subscribers.iter() {
            cb(secret_ref, version);
        }
        count
    }

    /// Number of currently-registered subscribers (test helper).
    #[cfg(test)]
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .lock()
            .expect("rotation broadcaster mutex poisoned")
            .subscribers
            .len()
    }
}

/// Guard held by a `subscribe_secret_rotation` caller. Drops the
/// subscription on drop; mirrors `RevocationSubscription`.
pub struct SecretRotationGuard {
    inner: Arc<Mutex<RotationBroadcasterInner>>,
    id: u64,
}

impl Drop for SecretRotationGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.subscribers.retain(|(id, _)| *id != self.id);
        }
    }
}

/// `BackendHost` implementation backed by the gateway's plugin
/// registry.
pub struct GatewayBackendHost {
    plugin_registry: Arc<PluginRegistry>,
    /// Tool name → child route. Built at construction; immutable
    /// thereafter. Operators who need hot reload of this map go
    /// through a fresh runtime / fresh host.
    routes: HashMap<String, ChildToolRoute>,
    /// Per-call depth cap. Calls with `ctx.depth >= max_depth` are
    /// refused before reaching the plugin.
    max_depth: u32,
    /// Operator-configured content store registry. `None` means the
    /// gateway is running without any
    /// content surface and `store_content` / `fetch_content` return
    /// [`BackendHostError::NotImplemented`] (matching the no-op host).
    /// When set, the host uses `ctx.initiating_backend` to pick the
    /// right storage instance via the registry's per-binding routing
    /// rules.
    content_stores: Option<Arc<ContentStoreRegistry>>,
    /// Operator-configured response cache. `None`
    /// makes `cache_get` / `cache_put` / `cache_invalidate`
    /// degrade to no-ops — bindings see no error, just no
    /// dedup acceleration.
    response_cache: Option<Arc<dyn ResponseCache>>,
    /// Per-binding response-cache overrides.
    /// Looked up by `ctx.initiating_backend`:
    /// - present + `Some(cache)` — operator declared `cache: { kind:
    ///   in-process, ... }` on this binding; route to that instance
    ///   instead of the gateway-wide cache.
    /// - present + `None` — operator declared `cache: { kind: disabled }`;
    ///   suppress caching for this binding even when the gateway-wide
    ///   cache is enabled.
    /// - absent — fall through to `response_cache` above.
    response_cache_overrides: HashMap<String, Option<Arc<dyn ResponseCache>>>,
    /// Credential cache + revocation broadcaster (`Local` or
    /// `Clustered`). `None` means the gateway is running without a
    /// credential surface — `resolve_credentials` returns
    /// `NotImplemented` and `subscribe_credential_revoked` returns a
    /// no-op guard. When `Some`, backend adapters with `cred://`
    /// references resolve per-call against this cache and subscribe
    /// to per-(plugin_id, target) revocation events for pool
    /// eviction.
    credential_cache:
        Option<Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind>>,
    /// In-process secret-rotation broadcaster. Backend plugins
    /// subscribe at `register_profile` time via
    /// `BackendHost::subscribe_secret_rotation`; the gateway's
    /// secret-watch task fans Vault events through
    /// [`Self::secret_rotation_broadcaster`]`().notify(...)`.
    secret_rotation_broadcaster: SecretRotationBroadcaster,
    /// Opt-in authorization for child `invoke_tool` calls. When true,
    /// child invocations run the external policy_engine chain
    /// (`child_invoke_policy_chain`) + the tool_gate plugin chain before
    /// reaching the backend, mirroring a direct `tools/call`. Default
    /// off — the agentic child surface is ungated until an operator opts
    /// in via `governance.child_invoke.enforce_gates`.
    child_invoke_enforce_gates: bool,
    /// Ordered policy-engine plugin names (the same chain the gateway
    /// runs for a direct tools/call). Empty unless wired at boot.
    child_invoke_policy_chain: Vec<String>,
    /// Shared handle to the gateway's built-in pre-dispatch policy gate
    /// (trust floor + per-tool CEL `allow_if`). `None` until wired via
    /// [`Self::set_child_invoke_gates`]; when child-invoke gates are
    /// enforced this runs on the child path between the external
    /// policy_chain and the tool_gate chain, mirroring a direct
    /// `tools/call`.
    child_invoke_pre_dispatch_policy: Option<Arc<crate::runtime::policy::PreDispatchPolicyGate>>,
}

impl std::fmt::Debug for GatewayBackendHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayBackendHost")
            .field("registered_routes", &self.routes.len())
            .field("max_depth", &self.max_depth)
            .field("content_stores", &self.content_stores.is_some())
            .finish()
    }
}

impl GatewayBackendHost {
    /// Build a host from the gateway's plugin registry plus the list
    /// of binding configs the gateway is starting with. Only
    /// plugin-backed bindings appear in the routing table; adapter-
    /// backed ones (HTTP, command, etc.) are skipped — see module
    /// docs for the rationale.
    ///
    /// `content_stores` is the operator-configured registry of named
    /// content store instances. Pass `None` to disable the
    /// content surface entirely; the host will respond with
    /// [`BackendHostError::NotImplemented`] just like the no-op host.
    /// The registry's per-binding routing chooses which named storage
    /// each `store_content` / `fetch_content` call hits.
    pub fn new(
        plugin_registry: Arc<PluginRegistry>,
        tool_bindings: &[BackendConfig],
        max_depth: u32,
        content_stores: Option<Arc<ContentStoreRegistry>>,
        response_cache: Option<Arc<dyn ResponseCache>>,
        response_cache_overrides: HashMap<String, Option<Arc<dyn ResponseCache>>>,
        credential_cache: Option<
            Arc<mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind>,
        >,
    ) -> Self {
        let mut routes = HashMap::new();
        // The host only registers tool-kind bindings — the LLM emits
        // `tool_calls`, not resource reads — so the caller passes the
        // already-narrowed `mcp.tools[]` list directly.
        for binding in tool_bindings {
            if CHILD_TOOL_INELIGIBLE_KINDS.contains(&binding.backend.kind.as_str()) {
                continue;
            }
            // Registry key normalization (LLM underscore→dotted) is shared
            // with the boot / register / pipeline paths. `http` has no
            // registry plugin (returns `None`) but is still a valid child
            // tool routed by its verbatim kind, so fall back to it.
            let kind: String = crate::backends::registry_lookup_kind(&binding.backend)
                .unwrap_or_else(|| binding.backend.kind.clone());
            routes.insert(
                binding.name.clone(),
                ChildToolRoute {
                    kind,
                    profile: binding.name.clone(),
                },
            );
        }
        Self {
            plugin_registry,
            routes,
            max_depth,
            content_stores,
            response_cache,
            response_cache_overrides,
            credential_cache,
            secret_rotation_broadcaster: SecretRotationBroadcaster::new(),
            child_invoke_enforce_gates: false,
            child_invoke_policy_chain: Vec::new(),
            child_invoke_pre_dispatch_policy: None,
        }
    }

    /// Enable authorization on the child `invoke_tool` path. `policy_chain`
    /// is the ordered list of policy-engine plugin names and
    /// `pre_dispatch_policy` is the gateway's built-in trust-floor and CEL
    /// `allow_if` gate — the same two layers (plus the tool_gate chain) a
    /// direct tools/call runs. Wired at boot and reload from
    /// `governance.child_invoke.enforce_gates`, the gateway policy chain,
    /// and the runtime's policy gate. With `enforce` false (default) the
    /// child path is ungated, preserving prior behaviour.
    pub(crate) fn set_child_invoke_gates(
        &mut self,
        enforce: bool,
        policy_chain: Vec<String>,
        pre_dispatch_policy: Arc<crate::runtime::policy::PreDispatchPolicyGate>,
    ) {
        self.child_invoke_enforce_gates = enforce;
        self.child_invoke_policy_chain = policy_chain;
        self.child_invoke_pre_dispatch_policy = Some(pre_dispatch_policy);
    }

    /// Run the same pre-dispatch authorization a direct tools/call gets,
    /// on a child invocation, in the same order: (1) the external
    /// policy_engine chain, (2) the built-in trust-floor + per-tool CEL
    /// `allow_if` gate evaluated against the CHILD tool name with the
    /// caller's inherited identity, then (3) the tool_gate plugin chain.
    /// Returns `Some(PolicyDenied)` when any layer refuses (Deny /
    /// Challenge / PendingApproval — the latter two are not answerable on
    /// the agentic child path). Fails closed: a missing identity maps to
    /// the anonymous/unauthenticated least-privileged context, and a
    /// missing built-in policy handle denies rather than skipping the
    /// gate. The runtime-owned quota gate is charged pre-flight at the
    /// top-level call and not re-run here.
    async fn evaluate_child_gates(
        &self,
        ctx: &BackendInvocationContext,
        tool_name: &str,
        args: &Value,
    ) -> Option<BackendHostError> {
        let identity =
            ctx.identity
                .clone()
                .unwrap_or_else(|| mcpg_plugin_protocol::PluginIdentity {
                    kind: "anonymous".to_owned(),
                    trust_level: "unauthenticated".to_owned(),
                    subject_id: None,
                    auth_provider: None,
                    issuer: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: std::collections::BTreeMap::new(),
                });
        let plugin_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: format!(
                "{}:child:{}:{}",
                ctx.parent_request_id, ctx.depth, tool_name
            ),
            session_id: ctx.session_id.clone(),
            tool_name: tool_name.to_owned(),
            surface: "tool".to_owned(),
            identity,
            transport: "internal".to_owned(),
        };
        let deny = |layer: &'static str| {
            metrics::counter!(
                "mcpg_binding_host_gate_denials_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
                "tool" => tool_name.to_owned(),
                "layer" => layer,
            )
            .increment(1);
            BackendHostError::PolicyDenied {
                tool_name: tool_name.to_owned(),
            }
        };
        // 1. External policy_engine chain (OPA / Cedar / Casbin).
        if let mcpg_plugin_host::PolicyChainOutcome::Deny { .. } = self
            .plugin_registry
            .evaluate_policy_chain(
                &self.child_invoke_policy_chain,
                "tool.call.pre",
                args,
                &plugin_ctx,
            )
            .await
        {
            return Some(deny("policy_chain"));
        }
        // 2. Built-in trust-floor + per-tool CEL `allow_if`, evaluated
        //    against the child tool with the caller's inherited identity.
        //    Fail closed when the handle isn't wired: if gates are
        //    enforced this layer must run, so a missing gate denies.
        let Some(pre_dispatch_policy) = self.child_invoke_pre_dispatch_policy.as_ref() else {
            return Some(deny("policy"));
        };
        let policy_context = crate::runtime::policy::ToolPolicyContext::from_plugin_identity(
            &plugin_ctx.identity,
            tool_name,
        );
        if let crate::runtime::policy::PreDispatchPolicyOutcome::Deny(_) =
            pre_dispatch_policy.evaluate_tool_call(&policy_context)
        {
            return Some(deny("policy"));
        }
        // 3. Tool-gate plugin chain (payment / rate-limit / step-up / DLP).
        match self
            .plugin_registry
            .evaluate_tool_gates_pre(&plugin_ctx, args, None)
            .await
        {
            mcpg_plugin_protocol::GateDecision::Allow { .. } => None,
            _ => Some(deny("tool_gate")),
        }
    }

    /// Shared handle to the secret-rotation broadcaster. The
    /// gateway's secret-watch task clones this so it can call
    /// [`SecretRotationBroadcaster::notify`] from an out-of-band
    /// task without needing a `&self` reference to the whole host.
    #[must_use]
    pub fn secret_rotation_broadcaster(&self) -> SecretRotationBroadcaster {
        self.secret_rotation_broadcaster.clone()
    }

    /// Pick the cache to route this call through. Per-binding
    /// override wins; `None` from an explicit `kind: disabled` arm
    /// suppresses caching entirely; absent override falls through
    /// to the gateway-wide default.
    fn cache_for_call(&self, ctx: &BackendInvocationContext) -> Option<&Arc<dyn ResponseCache>> {
        if let Some(slot) = self.response_cache_overrides.get(&ctx.initiating_backend) {
            return slot.as_ref();
        }
        self.response_cache.as_ref()
    }

    /// Routes count — exposed for tests / debug.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[async_trait]
impl BackendHost for GatewayBackendHost {
    async fn invoke_tool(
        &self,
        ctx: &BackendInvocationContext,
        tool_name: &str,
        args: &Value,
    ) -> Result<Value, BackendHostError> {
        // Depth cap first — cheap pre-check before lookup or transport.
        if ctx.depth >= self.max_depth {
            metrics::counter!(
                "mcpg_binding_host_depth_refusals_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
                "tool" => tool_name.to_owned(),
            )
            .increment(1);
            return Err(BackendHostError::DepthExceeded {
                tool_name: tool_name.to_owned(),
                depth: ctx.depth,
            });
        }

        // Resolve the named tool to a plugin + profile.
        let route = self.routes.get(tool_name).ok_or_else(|| {
            metrics::counter!(
                "mcpg_binding_host_tool_not_found_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
                "tool" => tool_name.to_owned(),
            )
            .increment(1);
            BackendHostError::NotFound {
                tool_name: tool_name.to_owned(),
            }
        })?;

        // Refuse direct self-calls — same-binding recursion is almost
        // always an LLM hallucination ("call myself with different
        // args") and the depth cap alone gives ~8 layers of expensive
        // wasted calls before refusal.
        if route.profile == ctx.initiating_backend {
            return Err(BackendHostError::Cycle {
                tool_name: tool_name.to_owned(),
                path: vec![ctx.initiating_backend.clone(), tool_name.to_owned()],
            });
        }

        // Opt-in authorization for the agentic child surface: route the
        // call through the same policy_engine chain + tool_gate plugin
        // chain a direct tools/call gets before dispatching the backend.
        if self.child_invoke_enforce_gates
            && let Some(denied) = self.evaluate_child_gates(ctx, tool_name, args).await
        {
            return Err(denied);
        }

        let plugin = self
            .plugin_registry
            .backend(&route.kind)
            .ok_or_else(|| BackendHostError::Backend {
                tool_name: tool_name.to_owned(),
                cause: BackendError::Transport {
                    message: format!(
                        "child tool '{}' resolved to plugin kind '{}' but no such plugin is registered",
                        tool_name, route.kind
                    ),
                },
            })?;

        // Build the BackendRequest for the child plugin. The child
        // request_id is derived so audit/trace can chain it back to
        // the parent. Headers are not propagated yet (W3C traceparent
        // would require regenerating with a child span — a follow-up).
        let payload = serde_json::to_vec(args).map_err(|e| BackendHostError::Backend {
            tool_name: tool_name.to_owned(),
            cause: BackendError::Transport {
                message: format!("serialize child args: {e}"),
            },
        })?;
        let request = BackendRequest {
            payload,
            headers: vec![],
            request_id: format!(
                "{}:child:{}:{}",
                ctx.parent_request_id, ctx.depth, tool_name
            ),
            session_id: ctx.session_id.clone(),
            // Inherit the parent's identity so per-caller credential
            // resolution stays consistent across the dispatch chain.
            identity: ctx.identity.clone(),
            // Child invocations through the host helper are issued by
            // backends mid-call; the parent's idempotency hint isn't
            // threaded here today (would require widening
            // `BackendInvocationContext`). Leaf-call propagation
            // covers the dominant integration shape; child-invocation
            // propagation is a future enhancement if a use case
            // emerges.
            idempotency: None,
        };

        metrics::counter!(
            "mcpg_binding_host_invocations_total",
            "initiating_backend" => ctx.initiating_backend.clone(),
            "tool" => tool_name.to_owned(),
            "kind" => route.kind.to_owned(),
        )
        .increment(1);

        let response = plugin
            .execute(&route.profile, request)
            .await
            .map_err(|cause| BackendHostError::Backend {
                tool_name: tool_name.to_owned(),
                cause,
            })?;

        // Parse the response payload as JSON. Plugin-backed bindings
        // (SQL rows, LLM structured output) all return JSON. Fall
        // back to a `{ "text": ... }` envelope if not — preserves
        // the structured-shape contract upward.
        let value: Value = serde_json::from_slice(&response.payload).unwrap_or_else(|_| {
            serde_json::json!({
                "text": String::from_utf8_lossy(&response.payload).to_string()
            })
        });
        Ok(value)
    }

    async fn store_content(
        &self,
        ctx: &BackendInvocationContext,
        bytes: bytes::Bytes,
        mime_type: String,
        ttl: Option<std::time::Duration>,
    ) -> Result<BackendResource, BackendHostError> {
        let Some(registry) = self.content_stores.as_ref() else {
            return Err(BackendHostError::NotImplemented);
        };
        // Route by the initiating binding's name → operator-configured
        // storage provider. Falls back to the operator's default
        // provider when the binding doesn't declare one (or when the
        // named provider is missing — `for_binding` returns the
        // default in that case).
        let storage_id = registry.storage_id_for_binding(&ctx.initiating_backend);
        let Some(store) = registry.for_binding(&ctx.initiating_backend) else {
            return Err(BackendHostError::Backend {
                tool_name: "content_store".into(),
                cause: BackendError::Transport {
                    message: format!(
                        "no content store available for binding {} (storage '{storage_id}' not registered)",
                        ctx.initiating_backend
                    ),
                },
            });
        };
        let size = bytes.len();
        let to_store = ContentToStore {
            bytes,
            mime_type: mime_type.clone(),
            alias: None,
            session_id: ctx.session_id.clone(),
            tenant_id: None,
            ttl,
        };
        let handle = store
            .put(to_store)
            .await
            .map_err(map_store_err_to_host_err)?;

        metrics::counter!(
            "mcpg_binding_host_content_stored_total",
            "initiating_backend" => ctx.initiating_backend.clone(),
            "storage" => storage_id.to_owned(),
            "mime" => mime_type.clone(),
        )
        .increment(1);
        metrics::histogram!(
            "mcpg_binding_host_content_stored_bytes",
            "initiating_backend" => ctx.initiating_backend.clone(),
            "storage" => storage_id.to_owned(),
        )
        .record(size as f64);

        Ok(BackendResource {
            id: handle.id.clone(),
            uri: registry.format_resource_uri(storage_id, &handle.id),
            size_bytes: handle.size_bytes,
            mime_type: handle.mime_type,
            content_hash: handle.content_hash,
            expires_at_unix: handle.expires_at.map(|t| t.timestamp()),
        })
    }

    async fn fetch_content(
        &self,
        ctx: &BackendInvocationContext,
        uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let Some(registry) = self.content_stores.as_ref() else {
            return Err(BackendHostError::NotImplemented);
        };
        // The URI carries the storage prefix; the registry resolves
        // it to the right backend. Bare-id legacy form falls back to
        // the operator's default provider.
        let (storage_id, id) = registry.parse_resource_uri(uri);
        let Some(store) = registry.by_id(&storage_id) else {
            return Ok(None);
        };
        let content = store.get(&id).await.map_err(map_store_err_to_host_err)?;
        let Some(content) = content else {
            return Ok(None);
        };
        // Session-ACL enforcement: a resource tagged with one
        // session must not be readable by another session, to keep
        // generated artifacts (screenshots, PII-bearing docs)
        // confined to the originating conversation. The gateway's
        // `resources/read` handler enforces the same rule for
        // direct client reads — this path covers the binding-side
        // dispatch.
        if let Some(owner) = content.session_id.as_deref()
            && Some(owner) != ctx.session_id.as_deref()
        {
            metrics::counter!(
                "mcpg_binding_host_content_acl_refusals_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
                "reason" => "cross_session",
            )
            .increment(1);
            // Translate the gateway-internal `Forbidden` into a
            // public `PolicyDenied`; existence isn't leaked.
            return Err(BackendHostError::PolicyDenied {
                tool_name: format!("resource:{id}"),
            });
        }
        metrics::counter!(
            "mcpg_binding_host_content_fetched_total",
            "initiating_backend" => ctx.initiating_backend.clone(),
        )
        .increment(1);
        Ok(Some(content.bytes))
    }

    async fn cache_get(
        &self,
        ctx: &BackendInvocationContext,
        key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let Some(cache) = self.cache_for_call(ctx) else {
            return Ok(None);
        };
        let cache_key = CacheKey::from_hash(namespaced_cache_key(ctx, key));
        let result = cache.get(&cache_key).await;
        if result.is_some() {
            metrics::counter!(
                "mcpg_binding_host_cache_hits_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
            )
            .increment(1);
        } else {
            metrics::counter!(
                "mcpg_binding_host_cache_misses_total",
                "initiating_backend" => ctx.initiating_backend.clone(),
            )
            .increment(1);
        }
        Ok(result)
    }

    async fn cache_put(
        &self,
        ctx: &BackendInvocationContext,
        key: String,
        value: bytes::Bytes,
        ttl: std::time::Duration,
    ) -> Result<(), BackendHostError> {
        let Some(cache) = self.cache_for_call(ctx) else {
            return Ok(());
        };
        let bytes_len = value.len();
        cache
            .put(
                CacheKey::from_hash(namespaced_cache_key(ctx, &key)),
                value,
                ttl,
            )
            .await;
        metrics::histogram!(
            "mcpg_binding_host_cache_put_bytes",
            "initiating_backend" => ctx.initiating_backend.clone(),
        )
        .record(bytes_len as f64);
        Ok(())
    }

    async fn cache_invalidate(
        &self,
        ctx: &BackendInvocationContext,
        key: &str,
    ) -> Result<(), BackendHostError> {
        let Some(cache) = self.cache_for_call(ctx) else {
            return Ok(());
        };
        cache
            .invalidate(&CacheKey::from_hash(namespaced_cache_key(ctx, key)))
            .await;
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        ctx: &BackendInvocationContext,
        value: &mut serde_json::Value,
    ) -> Result<usize, BackendHostError> {
        let Some(cache_kind) = self.credential_cache.as_ref() else {
            // Gateway running without a credential surface — only OK
            // when the caller's value carries no `cred://` references.
            // The cheapest check is to refuse: backends that hit this
            // arm should be operating under a static-cred profile.
            return Err(BackendHostError::NotImplemented);
        };
        let Some(identity) = ctx.identity.as_ref() else {
            // System-initiated dispatch (await runtime, watch fetcher).
            // Refuse cred:// resolution rather than silently succeed
            // with an arbitrary identity.
            return Err(BackendHostError::Backend {
                tool_name: ctx.initiating_backend.clone(),
                cause: mcpg_plugin_protocol::BackendError::Transport {
                    message: "credential resolution requires caller identity \
                              (system-initiated calls cannot use `cred://`)"
                        .to_owned(),
                },
            });
        };
        let count = match mcpg_plugin_host::credential_resolver::resolve_credential_refs(
            value,
            identity,
            &self.plugin_registry,
            cache_kind.local(),
        )
        .await
        {
            Ok(n) => n,
            Err(err) => {
                // Operator-visible audit + structured fields for SIEM.
                let fields = err.audit_fields();
                let event = mcpg_plugin_host::audit_events::credential_resolution_failed_event(
                    identity.clone(),
                    Some(ctx.parent_request_id.clone()),
                    &fields.plugin_id,
                    &fields.target,
                    fields.part.as_deref(),
                    fields.kind,
                    &fields.detail,
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                tracing::warn!(
                    target: "mcpg::credentials",
                    request_id = %ctx.parent_request_id,
                    plugin_id = %fields.plugin_id,
                    target = %fields.target,
                    error_kind = %fields.kind,
                    error = %err.operator_message(),
                    "credential resolution failed"
                );
                // Caller-visible message — opaque + correlation id.
                return Err(BackendHostError::Backend {
                    tool_name: ctx.initiating_backend.clone(),
                    cause: mcpg_plugin_protocol::BackendError::Transport {
                        message: err.caller_message(&ctx.parent_request_id),
                    },
                });
            }
        };
        Ok(count)
    }

    fn subscribe_credential_revoked(
        &self,
        cb: mcpg_plugin_protocol::CredentialRevocationCallback,
    ) -> mcpg_plugin_protocol::CredentialRevocationSubscription {
        match self.credential_cache.as_ref() {
            Some(cache_kind) => {
                let sub = cache_kind.on_revoked(cb);
                mcpg_plugin_protocol::CredentialRevocationSubscription::new(sub)
            }
            None => mcpg_plugin_protocol::CredentialRevocationSubscription::noop(),
        }
    }

    fn subscribe_secret_rotation(
        &self,
        cb: mcpg_plugin_protocol::SecretRotationCallback,
    ) -> mcpg_plugin_protocol::SecretRotationSubscription {
        let guard = self.secret_rotation_broadcaster.subscribe(cb);
        mcpg_plugin_protocol::SecretRotationSubscription::new(guard)
    }
}

fn map_store_err_to_host_err(err: ContentStoreError) -> BackendHostError {
    match err {
        ContentStoreError::SizeLimit { .. } | ContentStoreError::Storage { .. } => {
            BackendHostError::Backend {
                tool_name: "content_store".into(),
                cause: BackendError::Transport {
                    message: err.to_string(),
                },
            }
        }
        ContentStoreError::SignedUrlNotSupported => BackendHostError::Backend {
            tool_name: "content_store".into(),
            cause: BackendError::Transport {
                message: err.to_string(),
            },
        },
        ContentStoreError::Forbidden => BackendHostError::PolicyDenied {
            tool_name: "content_store".into(),
        },
        ContentStoreError::NotFound => BackendHostError::NotFound {
            tool_name: "content_store".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;
    use mcpg_plugin_protocol::{BackendPlugin, BackendResponse, PluginManifest, noop_backend_host};

    /// A minimal BackendPlugin used as a stand-in for a child tool.
    /// Records the profile name + payload it received and returns a
    /// canned JSON value.
    struct StubPlugin {
        manifest: PluginManifest,
        kind: &'static str,
        last_call: std::sync::Mutex<Option<(String, Vec<u8>)>>,
    }

    impl StubPlugin {
        fn new(kind: &'static str) -> Arc<Self> {
            Arc::new(Self {
                manifest: PluginManifest {
                    id: format!("test.stub.{kind}"),
                    version: "0.1.0".into(),
                    name: "stub".into(),
                    plugin_class: mcpg_plugin_protocol::PluginClass::ToolGate,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: vec![],
                    tags: vec![],
                    provides: vec![],
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                kind,
                last_call: std::sync::Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl BackendPlugin for StubPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            self.kind
        }
        async fn register_profile(
            &self,
            _name: &str,
            _spec: &Value,
            _host: Arc<dyn BackendHost>,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        async fn execute(
            &self,
            profile: &str,
            request: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            *self.last_call.lock().unwrap() = Some((profile.to_owned(), request.payload));
            let body = serde_json::json!({"echoed_profile": profile});
            Ok(BackendResponse {
                payload: serde_json::to_vec(&body).unwrap(),
                truncated: false,
            })
        }
    }

    /// Build a minimal `BackendConfig` for tests.
    ///
    /// The binding nests its implementation under an explicit
    /// `backend:` object — `{ type: <kind>, …kind-specific fields… }` —
    /// rather than flattening the discriminator onto the binding. This
    /// helper hides that shape so tests stay short.
    fn tool_binding(name: &str, bt_kind: &str, bt_inner: serde_json::Value) -> BackendConfig {
        let mut backend = serde_json::json!({ "kind": bt_kind });
        if let serde_json::Value::Object(extra) = bt_inner {
            for (k, v) in extra {
                backend[k] = v;
            }
        }
        let spec = serde_json::json!({
            "name": name,
            "description": "test",
            "backend": backend,
        });
        serde_json::from_value(spec).expect("valid binding config")
    }

    fn registry_with(plugin: Arc<dyn BackendPlugin>) -> Arc<PluginRegistry> {
        let mut r = PluginRegistry::new();
        r.register_backend(plugin, mcpg_plugin_protocol::PluginTier::Native)
            .unwrap();
        Arc::new(r)
    }

    #[tokio::test]
    async fn invoke_tool_routes_to_correct_kind_and_profile() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin.clone());

        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        assert_eq!(host.route_count(), 1);

        let ctx = BackendInvocationContext::root("parent-req", None, "incident.triage");
        let result = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 7}))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"echoed_profile": "orders"}));

        let last = plugin.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(last.0, "orders");
        let parsed: Value = serde_json::from_slice(&last.1).unwrap();
        assert_eq!(parsed, serde_json::json!({"id": 7}));
    }

    #[tokio::test]
    async fn unknown_tool_returns_not_found() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let bindings = vec![];
        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );

        let ctx = BackendInvocationContext::root("r1", None, "init");
        let err = host
            .invoke_tool(&ctx, "nope", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotFound { .. }));
    }

    #[tokio::test]
    async fn depth_cap_refuses_call() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let bindings = vec![tool_binding("x", "sql", serde_json::json!({}))];
        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            3,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );

        let ctx = BackendInvocationContext {
            parent_request_id: "r1".into(),
            session_id: None,
            initiating_backend: "init".into(),
            depth: 3,
            identity: None,
        };
        let err = host
            .invoke_tool(&ctx, "x", &serde_json::json!({}))
            .await
            .unwrap_err();
        match err {
            BackendHostError::DepthExceeded { depth, .. } => assert_eq!(depth, 3),
            other => panic!("expected DepthExceeded, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn self_call_returns_cycle_error() {
        let plugin = StubPlugin::new("openai.chat");
        let registry = registry_with(plugin);
        let bindings = vec![tool_binding(
            "incident.triage",
            "openai_chat",
            serde_json::json!({
                "model": "gpt-4o-mini",
                "api_key": { "value": "k" },
                "prompt": { "system": "x", "user": "y" }
            }),
        )];
        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );

        let ctx = BackendInvocationContext::root("r1", None, "incident.triage");
        let err = host
            .invoke_tool(&ctx, "incident.triage", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::Cycle { .. }));
    }

    #[tokio::test]
    async fn adapter_backed_bindings_are_invisible_to_phase2_host() {
        // Mock binding is adapter-backed; should NOT appear in routes.
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let bindings = vec![
            tool_binding("mock.binding", "mock", serde_json::json!({"response": {}})),
            tool_binding("sql.binding", "sql", serde_json::json!({})),
        ];
        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        assert_eq!(host.route_count(), 1, "only sql.binding should route");

        let ctx = BackendInvocationContext::root("r1", None, "init");
        let err = host
            .invoke_tool(&ctx, "mock.binding", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotFound { .. }));
    }

    #[tokio::test]
    async fn cdylib_envelope_bindings_produce_child_routes() {
        // Each cdylib envelope backend resolves to a ChildToolRoute whose
        // kind matches its registry kind; command/mock/openapi/pipeline stay
        // out of the route map.
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        // (binding name, serde config tag, expected route dispatch kind, body).
        let cases: &[(&str, &str, &str, serde_json::Value)] = &[
            (
                "ddb",
                "dynamodb",
                "dynamodb",
                serde_json::json!({
                    "region": "us-east-1", "table": "t", "operation": "scan",
                    "partition_key": { "name": "pk", "type": "S" }
                }),
            ),
            (
                "es",
                "elasticsearch",
                "elasticsearch",
                serde_json::json!({}),
            ),
            (
                "ora",
                "oracle",
                "oracle",
                serde_json::json!({
                    "dsn": "//h:1521/S", "username": "u", "password": "p",
                    "query": "SELECT 1 FROM dual"
                }),
            ),
            ("snow", "snowflake", "snowflake", serde_json::json!({})),
            ("duck", "duckdb", "duckdb", serde_json::json!({})),
            ("ch", "clickhouse", "clickhouse", serde_json::json!({})),
            ("odbc", "odbc", "odbc", serde_json::json!({})),
            ("hana", "hana", "hana", serde_json::json!({})),
            ("tw", "twilio", "twilio", serde_json::json!({})),
            ("bq", "bigquery", "bigquery", serde_json::json!({})),
            (
                "ftp",
                "ftp",
                "ftp",
                serde_json::json!({
                    "host": "h", "username": "u", "password": "p"
                }),
            ),
            (
                "smb",
                "smb",
                "smb",
                serde_json::json!({
                    "host": "h", "share": "public", "username": "u", "password": "p"
                }),
            ),
        ];
        let mut bindings = Vec::new();
        for (name, tag, _kind, body) in cases {
            bindings.push(tool_binding(name, tag, body.clone()));
        }
        // Skipped kinds, present to confirm they do not route.
        bindings.push(tool_binding(
            "mock.binding",
            "mock",
            serde_json::json!({"response": {}}),
        ));
        bindings.push(tool_binding(
            "pipeline.binding",
            "pipeline",
            serde_json::json!({"steps": []}),
        ));

        let host = GatewayBackendHost::new(
            registry,
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );

        assert_eq!(
            host.route_count(),
            cases.len(),
            "only the cdylib envelope bindings should route"
        );
        for (name, _tag, kind, _body) in cases {
            let route = host
                .routes
                .get(*name)
                .unwrap_or_else(|| panic!("{name} should have a child route"));
            assert_eq!(route.kind, *kind, "kind for {name}");
            assert_eq!(route.profile, *name, "profile for {name}");
        }
        assert!(!host.routes.contains_key("mock.binding"));
        assert!(!host.routes.contains_key("pipeline.binding"));
    }

    /// Sanity: a noop_backend_host can be set on the late-bound
    /// wrapper if the host is not wired — confirms that the gateway
    /// host is interchangeable with the no-op for tests.
    #[tokio::test]
    async fn host_object_safety_matches_late_bound() {
        let _: Arc<dyn BackendHost> = Arc::new(GatewayBackendHost {
            plugin_registry: registry_with(StubPlugin::new("sql")),
            routes: HashMap::new(),
            max_depth: 8,
            content_stores: None,
            response_cache: None,
            response_cache_overrides: HashMap::new(),
            credential_cache: None,
            secret_rotation_broadcaster: SecretRotationBroadcaster::new(),
            child_invoke_enforce_gates: false,
            child_invoke_policy_chain: Vec::new(),
            child_invoke_pre_dispatch_policy: None,
        });
        // And the noop is interchangeable.
        let _: Arc<dyn BackendHost> = noop_backend_host();
    }

    /// An allow-all built-in policy gate (least-restrictive trust floor,
    /// no CEL) so child-gate tests that target a different layer (the
    /// tool_gate chain) aren't short-circuited by the trust floor.
    fn allow_all_pre_dispatch_policy() -> Arc<crate::runtime::policy::PreDispatchPolicyGate> {
        let config = crate::runtime::ToolAccessPolicyConfig {
            default_minimum_trust: crate::runtime::RequestTrustLevel::Unauthenticated,
            cel_allow_if: None,
            rules: Vec::new(),
        };
        Arc::new(
            crate::runtime::policy::PreDispatchPolicyGate::try_new(config)
                .expect("allow-all policy config is valid"),
        )
    }

    /// A built-in policy gate that denies a single tool via a
    /// `Verified` trust floor on that tool (anonymous/unauthenticated
    /// child callers can never meet it). Other tools stay allow-all.
    fn deny_tool_pre_dispatch_policy(
        tool: &str,
    ) -> Arc<crate::runtime::policy::PreDispatchPolicyGate> {
        let config = crate::runtime::ToolAccessPolicyConfig {
            default_minimum_trust: crate::runtime::RequestTrustLevel::Unauthenticated,
            cel_allow_if: None,
            rules: vec![crate::runtime::ToolTrustRule {
                tool_name: tool.to_owned(),
                minimum_trust: crate::runtime::RequestTrustLevel::Verified,
                cel_allow_if: None,
                required_scopes: Vec::new(),
            }],
        };
        Arc::new(
            crate::runtime::policy::PreDispatchPolicyGate::try_new(config)
                .expect("deny-tool policy config is valid"),
        )
    }

    /// A tool_gate that denies every pre-dispatch evaluation — used to
    /// prove child invocations are (or are not) routed through the gate.
    struct DenyAllGate(PluginManifest);

    #[mcpg_plugin_protocol::async_trait]
    impl mcpg_plugin_protocol::ToolGatePlugin for DenyAllGate {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &mcpg_plugin_protocol::PluginContext,
            _args: &Value,
            _meta: Option<&Value>,
            _config: &Value,
        ) -> mcpg_plugin_protocol::GateDecision {
            mcpg_plugin_protocol::GateDecision::Deny {
                http_status: 403,
                code: -32010,
                message: "child denied".into(),
                error_data: None,
            }
        }
        async fn evaluate_post_dispatch(
            &self,
            _ctx: &mcpg_plugin_protocol::PluginContext,
            _args: &Value,
            _result: &Value,
            _duration_ms: u64,
            _config: &Value,
        ) -> mcpg_plugin_protocol::GateDecision {
            mcpg_plugin_protocol::GateDecision::allow()
        }
    }

    fn registry_with_backend_and_deny_gate() -> Arc<PluginRegistry> {
        let mut r = PluginRegistry::new();
        r.register_backend(
            StubPlugin::new("sql"),
            mcpg_plugin_protocol::PluginTier::Native,
        )
        .unwrap();
        r.register_tool_gate(
            Box::new(DenyAllGate(PluginManifest {
                id: "dev.test.gate.denyall".to_owned(),
                version: "0.1.0".into(),
                name: "deny-all".into(),
                plugin_class: mcpg_plugin_protocol::PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: "mcpg".to_owned(),
                backend_profile: None,
            })),
            mcpg_plugin_protocol::PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        Arc::new(r)
    }

    #[tokio::test]
    async fn child_invoke_skips_gates_when_disabled() {
        // Default (enforce off): a deny-all tool_gate is present but the
        // child path does not consult it — dispatch proceeds.
        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let host = GatewayBackendHost::new(
            registry_with_backend_and_deny_gate(),
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        let ctx = BackendInvocationContext::root("parent", None, "agent");
        let result = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 1}))
            .await
            .expect("ungated child dispatch succeeds");
        assert_eq!(result, serde_json::json!({"echoed_profile": "orders"}));
    }

    #[tokio::test]
    async fn child_invoke_denied_by_tool_gate_when_enabled() {
        // enforce on: the same deny-all tool_gate now refuses the child.
        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let mut host = GatewayBackendHost::new(
            registry_with_backend_and_deny_gate(),
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        // Allow-all built-in policy so the deny comes from the tool_gate
        // layer, not the trust floor.
        host.set_child_invoke_gates(true, Vec::new(), allow_all_pre_dispatch_policy());
        let ctx = BackendInvocationContext::root("parent", None, "agent");
        let err = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 1}))
            .await
            .expect_err("gated child dispatch is refused");
        assert!(
            matches!(err, BackendHostError::PolicyDenied { .. }),
            "{err:?}"
        );
    }

    /// A registry with a backend but NO tool_gate, so a denial can only
    /// originate from the built-in trust-floor / CEL policy layer.
    fn registry_with_backend_no_gate() -> Arc<PluginRegistry> {
        let mut r = PluginRegistry::new();
        r.register_backend(
            StubPlugin::new("sql"),
            mcpg_plugin_protocol::PluginTier::Native,
        )
        .unwrap();
        Arc::new(r)
    }

    #[tokio::test]
    async fn child_invoke_denied_by_builtin_policy_when_enabled() {
        // enforce on, no tool_gate: the built-in trust-floor gate denies
        // an anonymous child caller against a Verified-floor tool.
        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let mut host = GatewayBackendHost::new(
            registry_with_backend_no_gate(),
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        host.set_child_invoke_gates(true, Vec::new(), deny_tool_pre_dispatch_policy("orders"));
        let ctx = BackendInvocationContext::root("parent", None, "agent");
        let err = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 1}))
            .await
            .expect_err("built-in policy refuses the child");
        assert!(
            matches!(err, BackendHostError::PolicyDenied { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn child_invoke_passes_builtin_policy_then_dispatches_when_allowed() {
        // enforce on, no tool_gate, allow-all built-in policy: the child
        // clears the built-in layer and reaches the backend.
        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let mut host = GatewayBackendHost::new(
            registry_with_backend_no_gate(),
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        host.set_child_invoke_gates(true, Vec::new(), allow_all_pre_dispatch_policy());
        let ctx = BackendInvocationContext::root("parent", None, "agent");
        let result = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 1}))
            .await
            .expect("allowed child dispatch succeeds");
        assert_eq!(result, serde_json::json!({"echoed_profile": "orders"}));
    }

    #[tokio::test]
    async fn child_invoke_fails_closed_without_builtin_policy_handle() {
        // enforce on but the built-in policy handle was never wired: the
        // gate must deny rather than silently skip the built-in layer.
        let bindings = vec![tool_binding("orders", "sql", serde_json::json!({}))];
        let mut host = GatewayBackendHost::new(
            registry_with_backend_no_gate(),
            &bindings,
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        host.child_invoke_enforce_gates = true;
        host.child_invoke_policy_chain = Vec::new();
        host.child_invoke_pre_dispatch_policy = None;
        let ctx = BackendInvocationContext::root("parent", None, "agent");
        let err = host
            .invoke_tool(&ctx, "orders", &serde_json::json!({"id": 1}))
            .await
            .expect_err("missing built-in policy handle fails closed");
        assert!(
            matches!(err, BackendHostError::PolicyDenied { .. }),
            "{err:?}"
        );
    }

    fn default_content_registry(
        store: Arc<dyn mcpg_backend_llm_shared::ContentStore>,
    ) -> Arc<ContentStoreRegistry> {
        let mut stores = std::collections::HashMap::new();
        stores.insert("default".into(), store);
        Arc::new(ContentStoreRegistry::new(
            stores,
            std::collections::HashMap::new(),
            "default".to_owned(),
        ))
    }

    #[tokio::test]
    async fn store_and_fetch_content_round_trip_via_host() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let store = mcpg_backend_llm_shared::InProcessContentStore::new(1024);
        let host = GatewayBackendHost::new(
            registry,
            &[],
            8,
            Some(default_content_registry(store)),
            None,
            std::collections::HashMap::new(),
            None,
        );
        let ctx = BackendInvocationContext::root("r1", Some("sess-1".into()), "image-gen");
        let resource = host
            .store_content(
                &ctx,
                bytes::Bytes::from_static(b"PNGDATA"),
                "image/png".into(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(resource.size_bytes, 7);
        assert!(resource.uri.starts_with("mcpg-resource://"));
        // Fetch through the same host, same session.
        let bytes = host
            .fetch_content(&ctx, &resource.uri)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_ref(), b"PNGDATA");
    }

    #[tokio::test]
    async fn fetch_refuses_cross_session_resource() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let store = mcpg_backend_llm_shared::InProcessContentStore::new(1024);
        let host = GatewayBackendHost::new(
            registry,
            &[],
            8,
            Some(default_content_registry(store)),
            None,
            std::collections::HashMap::new(),
            None,
        );
        let owner_ctx = BackendInvocationContext::root("r1", Some("sess-1".into()), "image-gen");
        let resource = host
            .store_content(
                &owner_ctx,
                bytes::Bytes::from_static(b"secret"),
                "text/plain".into(),
                None,
            )
            .await
            .unwrap();
        // Different session attempts the read.
        let other_ctx =
            BackendInvocationContext::root("r2", Some("sess-other".into()), "summarize");
        let err = host
            .fetch_content(&other_ctx, &resource.uri)
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::PolicyDenied { .. }));
    }

    #[tokio::test]
    async fn store_without_content_store_returns_not_implemented() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let host = GatewayBackendHost::new(
            registry,
            &[],
            8,
            None,
            None,
            std::collections::HashMap::new(),
            None,
        );
        let ctx = BackendInvocationContext::root("r", None, "x");
        let err = host
            .store_content(
                &ctx,
                bytes::Bytes::from_static(b"x"),
                "text/plain".into(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
        let err = host
            .fetch_content(&ctx, "mcpg-resource://hash:abc")
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
    }

    #[tokio::test]
    async fn fetch_unknown_uri_returns_none() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let store = mcpg_backend_llm_shared::InProcessContentStore::new(1024);
        let host = GatewayBackendHost::new(
            registry,
            &[],
            8,
            Some(default_content_registry(store)),
            None,
            std::collections::HashMap::new(),
            None,
        );
        let ctx = BackendInvocationContext::root("r", None, "x");
        assert!(
            host.fetch_content(&ctx, "mcpg-resource://hash:doesnotexist")
                .await
                .unwrap()
                .is_none()
        );
    }

    // -- per-binding cache override -------------

    fn lru_cache(max_bytes: usize) -> Arc<dyn ResponseCache> {
        mcpg_backend_llm_shared::LruResponseCache::new(max_bytes) as Arc<dyn ResponseCache>
    }

    #[tokio::test]
    async fn cache_get_uses_default_when_no_override() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let default = lru_cache(1024);
        let ctx = BackendInvocationContext::root("r", None, "tool-x");
        // Seed under the binding-namespaced key the host computes, so the
        // default-cache path can serve it back.
        default
            .put(
                CacheKey::from_hash(namespaced_cache_key(&ctx, "k1")),
                bytes::Bytes::from_static(b"shared"),
                std::time::Duration::from_secs(60),
            )
            .await;
        let host =
            GatewayBackendHost::new(registry, &[], 8, None, Some(default), HashMap::new(), None);
        let got = host.cache_get(&ctx, "k1").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"shared".as_slice()));
    }

    #[tokio::test]
    async fn cache_get_disabled_override_short_circuits_to_none() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let default = lru_cache(1024);
        // Pre-populate the default cache; the override should
        // suppress this lookup entirely.
        default
            .put(
                CacheKey::from_hash("k1".to_owned()),
                bytes::Bytes::from_static(b"shared"),
                std::time::Duration::from_secs(60),
            )
            .await;
        let mut overrides: HashMap<String, Option<Arc<dyn ResponseCache>>> = HashMap::new();
        overrides.insert("tool-x".into(), None);
        let host = GatewayBackendHost::new(registry, &[], 8, None, Some(default), overrides, None);
        let ctx = BackendInvocationContext::root("r", None, "tool-x");
        assert!(host.cache_get(&ctx, "k1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cache_get_routes_to_per_binding_override_when_present() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let bound_ctx = BackendInvocationContext::root("r", None, "tool-x");
        let unbound_ctx = BackendInvocationContext::root("r", None, "tool-y");
        let default = lru_cache(1024);
        // Default has an entry the unbound tool will read (seeded under its
        // binding-namespaced key)…
        default
            .put(
                CacheKey::from_hash(namespaced_cache_key(&unbound_ctx, "k1")),
                bytes::Bytes::from_static(b"default-body"),
                std::time::Duration::from_secs(60),
            )
            .await;
        // …override has the bound tool's `k1` with a different body. A
        // request from the per-binding tool must see the override's body.
        let override_cache = lru_cache(1024);
        override_cache
            .put(
                CacheKey::from_hash(namespaced_cache_key(&bound_ctx, "k1")),
                bytes::Bytes::from_static(b"override-body"),
                std::time::Duration::from_secs(60),
            )
            .await;
        let mut overrides: HashMap<String, Option<Arc<dyn ResponseCache>>> = HashMap::new();
        overrides.insert("tool-x".into(), Some(override_cache));
        let host = GatewayBackendHost::new(registry, &[], 8, None, Some(default), overrides, None);

        let got_bound = host.cache_get(&bound_ctx, "k1").await.unwrap();
        assert_eq!(got_bound.as_deref(), Some(b"override-body".as_slice()));

        let got_unbound = host.cache_get(&unbound_ctx, "k1").await.unwrap();
        assert_eq!(got_unbound.as_deref(), Some(b"default-body".as_slice()));
    }

    #[tokio::test]
    async fn cache_put_writes_through_per_binding_override() {
        let plugin = StubPlugin::new("sql");
        let registry = registry_with(plugin);
        let default = lru_cache(1024);
        let override_cache = lru_cache(1024);
        let override_clone = override_cache.clone();
        let default_clone = default.clone();
        let mut overrides: HashMap<String, Option<Arc<dyn ResponseCache>>> = HashMap::new();
        overrides.insert("tool-x".into(), Some(override_cache));
        let host = GatewayBackendHost::new(registry, &[], 8, None, Some(default), overrides, None);
        let ctx = BackendInvocationContext::root("r", None, "tool-x");
        host.cache_put(
            &ctx,
            "k1".to_owned(),
            bytes::Bytes::from_static(b"v"),
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap();
        // Override saw it (under the binding-namespaced key).
        let got_override = override_clone
            .get(&CacheKey::from_hash(namespaced_cache_key(&ctx, "k1")))
            .await;
        assert_eq!(got_override.as_deref(), Some(b"v".as_slice()));
        // Default did NOT see it — write isolation by binding.
        let got_default = default_clone
            .get(&CacheKey::from_hash(namespaced_cache_key(&ctx, "k1")))
            .await;
        assert!(got_default.is_none());
    }
}
