//! Backend execution engine — dispatches tool/prompt/resource calls
//! to command, HTTP, gRPC, NATS, and Kafka adapters.
//!
//! Manages pipeline step execution including suspension/resumption
//! for elicitation and sampling server requests.

use std::sync::Arc;
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use super::pipeline_store::{
    PendingServerRequest, PipelineExecutionState, PipelineStore, StepResult,
};
use crate::protocol::{
    ElicitationCreateParams, JSONRPC_VERSION, SamplingCreateMessageParams, SamplingMessage,
    SamplingMessageContent, ServerJsonRpcRequest,
};

mod command_adapter;
mod http_adapter;
mod pipeline;
mod retry;

use command_adapter::*;
use http_adapter::*;
use pipeline::*;
use retry::*;

// Re-exported so the split adapter/pipeline submodules can name sibling
// runtime modules through their own `super::` path.
use super::{delivery_bus, expr, pipeline_store, safe_dns};

/// Returns `"debug_tool"` for built-in MCPG tools, `"operator_binding"` for operator-defined bindings.
fn backend_kind(tool_name: &str) -> &'static str {
    if tool_name.starts_with("mcpg.") {
        "debug_tool"
    } else {
        "operator_binding"
    }
}

use crate::{
    backends::{
        BackendInvocationRoute, DEFAULT_COMMAND_PROFILE, DEFAULT_NETWORK_PROFILE,
        DebugToolBackends, DebugToolExposure,
    },
    config::{BackendConfig, PipelineBackendConfig, PipelineSqlTxStepConfig},
    protocol::{ToolCallResult, ToolContent},
    runtime::{RequestContext, RuntimeSnapshot},
};

// `sql_tx`/`sql_await` resolve the `sql` backend from the plugin
// registry and dispatch through the `BackendPlugin::execute_transaction`
// / `execute` trait surface; runtime code never reaches into the sql
// crate directly. The concrete type is only named by the in-tree tests
// below.
#[cfg(test)]
use mcpg_plugin_backend_sql::SqlBackendPlugin;

/// Outcome of executing a pipeline that may contain elicitation/sampling steps.
pub(crate) enum PipelineOutcome {
    /// Pipeline executed all steps to completion.
    Complete(ToolCallResult),
    /// Pipeline suspended for elicitation/sampling — a server request to send to the client.
    Suspended(ServerJsonRpcRequest),
    /// SEP-2322 multi-entry MRTR — a `gather` step suspended on
    /// several server-to-client requests at once. All are emitted in
    /// one `InputRequiredResult.inputRequests` map; the pipeline
    /// resumes when the client answers them together. Always carries
    /// at least one request (an all-pruned gather completes instead).
    SuspendedMulti(Vec<ServerJsonRpcRequest>),
}

/// All context needed to dispatch a single tool/prompt/resource call to a backend adapter.
/// Carries the caller identity, resolved arguments, expression context, and cancellation token.
#[derive(Debug, Clone)]
pub(crate) struct BackendInvocationRequest {
    pub context: RequestContext,
    pub tool_name: String,
    pub arguments: Option<Value>,
    /// Expression context for resolving dynamic config fields at call time.
    pub expr_ctx: super::expr::ExprContext,
    /// Progress token from the client's `_meta.progressToken`, if provided.
    /// On the modern (`2026-07-28`) wire this is read from the namespaced
    /// `_meta.io.modelcontextprotocol/progressToken` key; on `2025-11-25`
    /// from the bare `_meta.progressToken`.
    pub progress_token: Option<Value>,
    /// SEP-2575 per-request log-level floor for `notifications/message`
    /// emitted by this request's pipeline (`log` steps).
    ///
    /// Modern (`2026-07-28`) wire only — parsed from
    /// `_meta.io.modelcontextprotocol/logLevel`. Semantics:
    /// - `Some(level)` → emit only messages at or above `level`;
    /// - `None` on the modern wire → emit **nothing** (the spec MUST:
    ///   "If absent, the server MUST NOT send any `notifications/message`
    ///   notifications for this request.").
    ///
    /// On the legacy `2025-11-25` wire this field is always `None` and is
    /// **not** consulted — that wire keeps its session-`logging/setLevel`
    /// model and emits log notifications unconditionally (byte-identical
    /// behaviour preserved).
    pub request_log_level: Option<crate::protocol::v_2026_07_28::wire::meta::LogLevel>,
    /// Legacy (`2025-11-25`) session-wide `logging/setLevel` floor.
    /// Populated from the loaded session snapshot on the legacy wire so
    /// pipeline `log` steps honor the session minimum (LOG-2). `None`
    /// on the modern wire (which uses the per-request `request_log_level`
    /// gate instead) and in tests that don't load a session.
    pub legacy_session_log_level: Option<crate::protocol::LoggingLevel>,
    /// Snapshot of the client's negotiated capabilities. The executor uses
    /// this to reject pipeline steps that would require a server-to-client
    /// request the client never declared support for (T2-02).
    pub client_capabilities: crate::protocol::ClientCapabilities,
    /// Cooperative cancellation token. Pipeline execution checks
    /// `is_cancelled()` at step boundaries and aborts with an isError
    /// tool result if the owning request or task has been cancelled.
    /// The token is also threaded mid-call into `execute_http_probe`
    /// so an in-flight network probe aborts on cancellation.
    pub cancellation_token: Option<tokio_util::sync::CancellationToken>,
    /// Idempotency hint threaded from the caller's
    /// `_meta["dev.mcpg/idempotency-key"]`. Pipeline sub-steps inherit
    /// the SAME key so backend plugins propagating to upstreams
    /// (HTTP / SQL / NATS / Kafka) dedupe at their own upstreams
    /// independently of the gateway's pipeline-level cache.
    ///
    /// The field is plumbed through the runtime; backends read it from
    /// `BackendRequest.idempotency` at the FFI boundary.
    pub idempotency_hint: Option<IdempotencyHint>,
}

/// Hint carried on every `BackendInvocationRequest` whose owning
/// tool-call carried a `dev.mcpg/idempotency-key`. Sub-step
/// backends in a pipeline see the SAME hint as the pipeline-level
/// call (no per-hop derivation — design doc §5).
///
/// The hint is read from `BackendRequest.idempotency` at the FFI
/// boundary so HTTP / SQL / NATS / Kafka backends propagate the key
/// to their upstreams.
#[derive(Debug, Clone)]
pub(crate) struct IdempotencyHint {
    /// The caller-supplied key, validated for format (ASCII, ≤255
    /// bytes, non-empty after trim) by `idempotency::validate_request_key`.
    pub key: String,
    /// BLAKE3 hash of the gateway-side dedupe scope
    /// (tenant + identity + method + tool_name). Lets backend
    /// plugins scope their own per-upstream dedupe with the same
    /// boundary the gateway uses, without re-deriving the scope.
    pub scope_hash: [u8; 32],
}

impl IdempotencyHint {
    /// Convert the gateway-internal hint (32-byte BLAKE3) to the
    /// plugin-protocol hint (hex-encoded, truncated to 16 bytes / 32
    /// hex chars). The truncation gives ~128 bits of collision-
    /// resistance — plenty for metadata used only to scope per-call
    /// caches in propagating backends. NOT a security boundary: the
    /// gateway already validates scope inside `IdempotencyRecord`.
    pub fn to_plugin_hint(&self) -> mcpg_plugin_protocol::IdempotencyHint {
        mcpg_plugin_protocol::IdempotencyHint {
            key: self.key.clone(),
            scope_hash: hex::encode(&self.scope_hash[..16]),
        }
    }
}

/// Configuration for the built-in debug tools (command probe, network probe, etc.)
/// that ship with the gateway for operator diagnostics.
#[derive(Debug, Clone)]
pub struct RuntimeDebugConfig {
    pub enabled: bool,
    pub command_profiles: std::collections::BTreeMap<String, CommandToolRuntimeConfig>,
    pub network_profiles: std::collections::BTreeMap<String, NetworkToolRuntimeConfig>,
    pub bindings: DebugToolBackends,
    pub exposure: DebugToolExposure,
    /// Dispatcher-level default for `allow_private_backends`. Used by the
    /// gRPC and GraphQL dispatch paths which don't have their own per-profile
    /// override path (unlike HTTP/network-probe profiles where the flag
    /// lives on `NetworkToolRuntimeConfig`). Defaults to false. At bootstrap
    /// the app should set this from `ServerConfig.allow_private_backends` so
    /// operator-intended private-backend configurations pass through the
    /// DNS guard uniformly across binding types.
    pub default_allow_private_backends: bool,
}

impl Default for RuntimeDebugConfig {
    fn default() -> Self {
        let mut command_profiles = std::collections::BTreeMap::new();
        command_profiles.insert(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        );
        let mut network_profiles = std::collections::BTreeMap::new();
        network_profiles.insert(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        );
        Self {
            enabled: false,
            command_profiles,
            network_profiles,
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: false,
        }
    }
}

/// Runtime config for command-based (subprocess) backend adapters.
#[derive(Debug, Clone)]
pub struct CommandToolRuntimeConfig {
    pub command: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl Default for CommandToolRuntimeConfig {
    fn default() -> Self {
        Self {
            command: "printf".to_owned(),
            args: vec!["mcpg-debug-command\n".to_owned()],
            timeout_ms: 2_000,
            max_output_bytes: 4_096,
        }
    }
}

/// Runtime config for HTTP-based backend adapters, including URL, timeouts,
/// expected status codes, and the DNS rebinding guard flag.
#[derive(Debug, Clone)]
pub struct NetworkToolRuntimeConfig {
    pub url: String,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub expected_status_codes: Vec<u16>,
    pub require_json_response: bool,
    pub headers: std::collections::BTreeMap<String, String>,
    /// allow connections to private/loopback/link-local IPs.
    /// When false (default), the DNS rebinding guard rejects resolved
    /// addresses in RFC 1918, loopback, link-local, CGNAT, etc.
    pub allow_private_backends: bool,
}

impl Default for NetworkToolRuntimeConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8787/health".to_owned(),
            timeout_ms: 2_000,
            max_response_bytes: 4_096,
            expected_status_codes: vec![200],
            require_json_response: false,
            headers: std::collections::BTreeMap::new(),
            allow_private_backends: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Expression resolution for runtime configs
// ---------------------------------------------------------------------------

/// Resolve dynamic expressions in a `NetworkToolRuntimeConfig`.
///
/// Evaluates `${...}` expressions in `url` and header values using the request's
/// expression context. Returns a new config with all expressions resolved.
fn resolve_network_config(
    config: &NetworkToolRuntimeConfig,
    expr_ctx: &super::expr::ExprContext,
) -> Result<NetworkToolRuntimeConfig, String> {
    let url = resolve_field(&config.url, expr_ctx, "url")?;
    let headers = resolve_headers(&config.headers, expr_ctx)?;
    Ok(NetworkToolRuntimeConfig {
        url,
        headers,
        timeout_ms: config.timeout_ms,
        max_response_bytes: config.max_response_bytes,
        expected_status_codes: config.expected_status_codes.clone(),
        require_json_response: config.require_json_response,
        allow_private_backends: config.allow_private_backends,
    })
}

/// Resolve dynamic expressions in a `CommandToolRuntimeConfig`.
fn resolve_command_config(
    config: &CommandToolRuntimeConfig,
    expr_ctx: &super::expr::ExprContext,
) -> Result<CommandToolRuntimeConfig, String> {
    let mut resolved_args = Vec::with_capacity(config.args.len());
    for (i, arg) in config.args.iter().enumerate() {
        resolved_args.push(resolve_field(arg, expr_ctx, &format!("args[{}]", i))?);
    }
    Ok(CommandToolRuntimeConfig {
        command: config.command.clone(), // command is never dynamic (security)
        args: resolved_args,
        timeout_ms: config.timeout_ms,
        max_output_bytes: config.max_output_bytes,
    })
}

/// Resolve a single string field that may contain `${...}` expressions.
fn resolve_field(
    value: &str,
    expr_ctx: &super::expr::ExprContext,
    field_name: &str,
) -> Result<String, String> {
    if !value.contains("${") {
        return Ok(value.to_owned());
    }
    let dv = super::expr::DynamicValue::parse(value)
        .map_err(|e| format!("{}: failed to parse expression: {}", field_name, e))?;
    dv.resolve(expr_ctx)
        .map_err(|e| format!("{}: expression evaluation failed: {}", field_name, e))
}

/// Resolve `${...}` expressions in header values. Keys are never dynamic.
fn resolve_headers(
    headers: &std::collections::BTreeMap<String, String>,
    expr_ctx: &super::expr::ExprContext,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut resolved = std::collections::BTreeMap::new();
    for (key, value) in headers {
        let resolved_value = resolve_field(value, expr_ctx, &format!("header[{}]", key))?;
        super::expr::validate_header_value(key, &resolved_value).map_err(|e| e.to_string())?;
        resolved.insert(key.clone(), resolved_value);
    }
    Ok(resolved)
}

/// Central dispatcher that routes tool/prompt/resource invocations to the
/// correct backend adapter (HTTP, command, gRPC, GraphQL, NATS, Kafka, mock)
/// and orchestrates multi-step pipeline execution with suspension points.
pub(crate) struct ExecutionDispatcher {
    adapter_executor: Arc<dyn ToolExecutionAdapter>,
    /// Operator-supplied HTTP profiles (post-config-time secret/env
    /// expansion, but pre-CEL request-time evaluation).
    /// `dispatch_with_retries` reads from here for `NetworkJsonCall` /
    /// `NetworkQueryCall` arms, CEL-resolves per call against
    /// `request.expr_ctx`, then routes through the
    /// `dev.mcpg.backend.http` plugin via `execute_http_request`. The
    /// `DebugToolExecutor` keeps its own copy too so the inline
    /// `NetworkProbe` arm and gRPC/GraphQL helpers continue to work;
    /// both maps share the same source data.
    network_profiles: Arc<std::collections::BTreeMap<String, NetworkToolRuntimeConfig>>,
    pipeline_configs: std::collections::BTreeMap<String, PipelineBackendConfig>,
    retry_configs: std::collections::BTreeMap<String, crate::config::RetryConfig>,
    /// Delivery bus for emitting progress notifications during pipeline execution.
    delivery_bus: Option<Arc<dyn super::delivery_bus::DeliveryBus>>,
    /// Plugin registry for routing binding-plugin dispatch (`kind: "nats"`,
    /// `kind: "kafka"`, …). `None` in tests that build the dispatcher
    /// standalone; all production call paths set this from the runtime.
    plugin_registry: Option<Arc<mcpg_plugin_host::PluginRegistry>>,
    /// In-gateway federation engine for dispatching `Federated` routes to
    /// upstream MCP servers. `None` in standalone-test
    /// dispatchers and until the runtime wires it.
    federation_engine:
        arc_swap::ArcSwapOption<crate::runtime::federation::engine::FederationEngine>,
    /// Pipeline store handle for buffering `log` / `progress`
    /// notifications emitted by non-suspending pipeline steps. The
    /// pipeline executor publishes each notification to the delivery
    /// bus (live subscribers) AND stores it here, so a GET-SSE channel
    /// that subscribes AFTER the publish drains them on open via
    /// `take_pending_deliveries`. `None` in tests that build the
    /// dispatcher standalone.
    pipeline_store: Option<Arc<dyn super::pipeline_store::PipelineStore>>,
    /// last emitted `progress` value per
    /// (session_id, progress_token_string). MCP 2025-11-25 §Progress
    /// requires progress to be strictly non-decreasing — any emission
    /// that would go backwards is dropped with an observability
    /// counter.
    ///
    /// pruned on session terminate (see
    /// `clear_progress_state_for_session`) so a long-running gateway
    /// does not retain a row per (session, token) for the lifetime
    /// of the process.
    /// Perf: DashMap avoids global Mutex contention on progress emission.
    progress_state: dashmap::DashMap<(String, String), f64>,
}

impl ExecutionDispatcher {
    /// Drop every (session_id, *) entry from the progress
    /// monotonicity tracker on session terminate.
    pub(crate) fn clear_progress_state_for_session(&self, session_id: &str) {
        self.progress_state.retain(|(sid, _), _| sid != session_id);
    }
}

impl std::fmt::Debug for ExecutionDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExecutionDispatcher")
    }
}

impl Default for ExecutionDispatcher {
    fn default() -> Self {
        Self::from_runtime_debug_config(RuntimeDebugConfig::default(), &[])
    }
}

impl ExecutionDispatcher {
    /// Build the dispatcher from config, compiling binding configs into per-adapter
    /// profiles keyed by binding name. Each binding type (HTTP, command, gRPC, etc.)
    /// gets its own runtime config entry; pipeline bindings additionally register
    /// per-step sub-profiles under `{binding}._step_.{step_id}`.
    pub(crate) fn from_runtime_debug_config(
        config: RuntimeDebugConfig,
        binding_configs: &[BackendConfig],
    ) -> Self {
        // `command_profiles` now carries only the debug CommandProbe
        // profile from the debug config (operator command bindings +
        // pipeline steps dispatch via the command plugin), so it is no
        // longer mutated here.
        let command_profiles = config.command_profiles;
        let mut network_profiles = config.network_profiles;
        let mut pipeline_configs = std::collections::BTreeMap::new();
        let mut retry_configs = std::collections::BTreeMap::new();

        // Inject binding execution configs as profiles keyed by binding name
        for binding in binding_configs {
            // Collect retry config if present
            if let Some(ref retry) = binding.retry {
                retry_configs.insert(binding.name.clone(), retry.clone());
            }
            // Only `http` (debug network adapter) and `pipeline` (per-step
            // adapter profiles) pre-register adapter profiles here; every
            // other kind executes via its registry plugin / connection
            // manager. The typed config structs are reused purely to read the
            // spec — the binding itself is the generic `{ kind, spec }` form.
            match binding.backend.kind.as_str() {
                "http" => {
                    if let Ok(http) = serde_json::from_value::<crate::config::HttpBackendConfig>(
                        serde_json::Value::Object(binding.backend.spec.clone()),
                    ) {
                        network_profiles.insert(
                            binding.name.clone(),
                            NetworkToolRuntimeConfig {
                                url: http.url,
                                timeout_ms: http.timeout_ms,
                                max_response_bytes: http.max_response_bytes,
                                expected_status_codes: http.expected_status_codes,
                                require_json_response: http.require_json_response,
                                headers: http.headers,
                                allow_private_backends: config.default_allow_private_backends,
                            },
                        );
                    }
                }
                "pipeline" => {
                    if let Ok(pipeline) =
                        serde_json::from_value::<crate::config::PipelineBackendConfig>(
                            serde_json::Value::Object(binding.backend.spec.clone()),
                        )
                    {
                        for step in &pipeline.steps {
                            let step_profile = format!("{}._step_.{}", binding.name, step.id());
                            if let crate::config::PipelineStepConfig::Backend(s) = step
                                && s.kind == "http"
                                && let Ok(http) =
                                    serde_json::from_value::<crate::config::HttpBackendConfig>(
                                        serde_json::Value::Object(s.spec.clone()),
                                    )
                            {
                                network_profiles.insert(
                                    step_profile,
                                    NetworkToolRuntimeConfig {
                                        url: http.url,
                                        timeout_ms: http.timeout_ms,
                                        max_response_bytes: http.max_response_bytes,
                                        expected_status_codes: http.expected_status_codes,
                                        require_json_response: http.require_json_response,
                                        headers: http.headers,
                                        allow_private_backends: config
                                            .default_allow_private_backends,
                                    },
                                );
                            }
                        }
                        pipeline_configs.insert(binding.name.clone(), pipeline);
                    }
                }
                _ => {}
            }
        }

        let network_profiles_arc = Arc::new(network_profiles.clone());
        Self {
            adapter_executor: Arc::new(DebugToolExecutor::new(command_profiles, network_profiles)),
            network_profiles: network_profiles_arc,
            pipeline_configs,
            retry_configs,
            delivery_bus: None,
            plugin_registry: None,
            federation_engine: arc_swap::ArcSwapOption::empty(),
            pipeline_store: None,
            progress_state: dashmap::DashMap::new(),
        }
    }

    #[cfg(test)]
    fn with_adapter_executor(adapter_executor: Arc<dyn ToolExecutionAdapter>) -> Self {
        Self {
            adapter_executor,
            network_profiles: Arc::new(std::collections::BTreeMap::new()),
            pipeline_configs: std::collections::BTreeMap::new(),
            retry_configs: std::collections::BTreeMap::new(),
            delivery_bus: None,
            plugin_registry: None,
            federation_engine: arc_swap::ArcSwapOption::empty(),
            pipeline_store: None,
            progress_state: dashmap::DashMap::new(),
        }
    }

    /// Set the delivery bus for progress notification delivery.
    pub(crate) fn set_delivery_bus(&mut self, bus: Arc<dyn super::delivery_bus::DeliveryBus>) {
        self.delivery_bus = Some(bus);
    }

    /// Set the pipeline store handle. Used by `log` / `progress`
    /// pipeline steps to buffer notifications so a late-subscribing
    /// GET-SSE channel can drain them on open.
    pub(crate) fn set_pipeline_store(
        &mut self,
        store: Arc<dyn super::pipeline_store::PipelineStore>,
    ) {
        self.pipeline_store = Some(store);
    }

    /// Streaming counterpart of [`dispatch_tool_call`]. Used by the
    /// runtime when the tool-call request:
    /// 1. Routes to a streaming-capable binding (currently only
    ///    `LlmRequest`).
    /// 2. Carries a client-supplied `progress_token` (the client
    ///    signals interest in incremental updates).
    /// 3. Has an active session_id (delivery bus is keyed on
    ///    sessions; without one, there is no SSE channel to ride).
    ///
    /// On entry the function is in an async context (the runtime's
    /// `handle_request` await chain), so we don't `block_in_place`.
    /// The function awaits the binding's `execute_streaming` and
    /// drains it, publishing each chunk to the delivery bus as a
    /// `notifications/progress` event. The terminal `Done` chunk's
    /// `BackendResponse` becomes the returned `ToolCallResult`.
    ///
    /// If `route` doesn't match a streaming-capable variant, this
    /// function falls back to the synchronous `dispatch_tool_call` so
    /// callers don't have to branch on route shape.
    pub(crate) async fn dispatch_tool_call_streaming(
        &self,
        route: BackendInvocationRoute,
        request: &BackendInvocationRequest,
        runtime_snapshot: Option<RuntimeSnapshot>,
    ) -> ToolCallResult {
        let progress_token = match request.progress_token.as_ref() {
            Some(t) => t.clone(),
            None => {
                // No progress token → caller didn't actually want
                // streaming; fall back to the sync path.
                return self.dispatch_tool_call(route, request, runtime_snapshot);
            }
        };
        let Some(ref bus) = self.delivery_bus else {
            return self.dispatch_tool_call(route, request, runtime_snapshot);
        };
        let _ = runtime_snapshot;

        match route {
            BackendInvocationRoute::LlmRequest { profile, kind } => {
                if let Some(cancelled) = early_cancel_check(request, &profile, "llm") {
                    return cancelled;
                }
                execute_llm_request_streaming(
                    kind,
                    &profile,
                    request,
                    self.plugin_registry.as_ref(),
                    bus,
                    &progress_token,
                )
                .await
            }
            // HTTP backend-driven progress. The plugin's
            // `execute_streaming` override emits one
            // `BackendChunk::Progress` per upstream body chunk for
            // chunked / SSE / no-Content-Length responses; the
            // gateway forwards each chunk as a
            // `notifications/progress` frame on the delivery bus.
            // Buffered upstreams (Content-Length set, not SSE) emit
            // a single Done with no Progress.
            BackendInvocationRoute::NetworkJsonCall { profile } => {
                if let Some(cancelled) = early_cancel_check(request, &profile, "http") {
                    return cancelled;
                }
                execute_http_request_streaming(
                    &profile,
                    request,
                    self.network_profiles.as_ref(),
                    self.plugin_registry.as_ref(),
                    bus,
                    &progress_token,
                )
                .await
            }
            BackendInvocationRoute::NetworkQueryCall { profile } => {
                if let Some(cancelled) = early_cancel_check(request, &profile, "http") {
                    return cancelled;
                }
                execute_http_request_streaming(
                    &profile,
                    request,
                    self.network_profiles.as_ref(),
                    self.plugin_registry.as_ref(),
                    bus,
                    &progress_token,
                )
                .await
            }
            other => {
                // Other routes don't yet stream incrementally —
                // fall through to the buffered sync dispatcher,
                // which still publishes the final result as
                // structured content.
                self.dispatch_tool_call(other, request, runtime_snapshot)
            }
        }
    }

    /// Set the plugin registry used to look up binding / watch-strategy plugins
    /// at dispatch time.
    pub(crate) fn set_plugin_registry(&mut self, registry: Arc<mcpg_plugin_host::PluginRegistry>) {
        self.plugin_registry = Some(registry);
    }

    /// Set the federation engine used to dispatch `Federated` routes.
    /// Stored behind `ArcSwapOption` so the runtime can wire it after the
    /// dispatcher is already `Arc`-shared (boot + reload).
    pub(crate) fn set_federation_engine(
        &self,
        engine: Arc<crate::runtime::federation::engine::FederationEngine>,
    ) {
        self.federation_engine.store(Some(engine));
    }

    /// The wired federation engine, if any. Used by the federated
    /// resource / prompt read paths.
    pub(crate) fn federation_engine(
        &self,
    ) -> Option<Arc<crate::runtime::federation::engine::FederationEngine>> {
        self.federation_engine.load_full()
    }

    /// Emit a pipeline progress notification via the delivery bus.
    ///
    /// progress emission is inherently rate-limited because a
    /// notification is only produced *between pipeline steps* —
    /// per-step backend latency sets the emission cadence. We do not
    /// forward backend-produced progress notifications from the
    /// outbound adapter layer today, so there is no flood vector
    /// here. If a future change introduces backend-forwarded progress,
    /// a token-bucket per `session_id` MUST be added here before the
    /// bus publish.
    fn emit_pipeline_progress(
        &self,
        context: &RequestContext,
        progress_token: &Value,
        completed: f64,
        total: f64,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let Some(ref session_id) = context.session_id else {
            return;
        };

        // enforce strictly-non-decreasing progress per
        // (session_id, progress_token). MCP 2025-11-25 §Progress
        // requires monotonic emission; any caller that would go
        // backwards is dropped with an observability counter.
        let token_str = match progress_token {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        };
        if !token_str.is_empty() {
            let key = (session_id.clone(), token_str);
            let prev = self
                .progress_state
                .get(&key)
                .map(|v| *v)
                .unwrap_or(f64::NEG_INFINITY);
            if completed < prev {
                metrics::counter!("mcpg_progress_non_monotonic_dropped_total").increment(1);
                tracing::warn!(
                    session_id = %key.0,
                    progress_token = %key.1,
                    previous = prev,
                    attempted = completed,
                    "dropping non-monotonic progress emission (spec MUST)"
                );
                return;
            }
            self.progress_state.insert(key, completed);
        }

        let notification = crate::protocol::ProgressNotification {
            jsonrpc: crate::protocol::JSONRPC_VERSION,
            method: "notifications/progress",
            params: crate::protocol::ProgressParams {
                progress_token: progress_token.clone(),
                progress: completed,
                total: Some(total),
                message: Some(format!(
                    "Step {}/{} completed",
                    completed as u64, total as u64
                )),
            },
        };
        let jsonrpc_message = match serde_json::to_value(&notification) {
            Ok(v) => v,
            Err(_) => return,
        };
        let message = super::pipeline_store::DeliveryMessage {
            kind: super::pipeline_store::DeliveryKind::ProgressNotification,
            jsonrpc_message,
            delivery_id: String::new(),
        };
        // Use the tokio runtime handle to publish synchronously
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let bus = Arc::clone(bus);
            let session_id_owned = session_id.clone();
            // Spawn a fire-and-forget task — don't block the pipeline loop
            handle.spawn(async move {
                let _ = bus.publish(&session_id_owned, message).await;
            });
            // Every progress emission lands on the audit lane
            // (high-volume; operators wanting low cadence can route
            // this action through a dedicated sink).
            if let Some(registry) = self.plugin_registry.clone() {
                let actor = crate::runtime::plugin_identity_from_request(context);
                let session_for_audit = session_id.clone();
                let token_for_audit = match progress_token {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                handle.spawn(async move {
                    let event = mcpg_plugin_host::audit_events::progress_notified_event(
                        actor,
                        &token_for_audit,
                        Some(&session_for_audit),
                        completed,
                        Some(total),
                    );
                    let _ = registry.emit_audit_event(&event).await;
                });
            }
        }
    }

    /// Check if a pipeline profile has any suspending (elicitation/sampling) steps.
    pub(crate) fn pipeline_has_suspending_steps(&self, profile: &str) -> bool {
        self.pipeline_configs
            .get(profile)
            .is_some_and(|cfg| cfg.steps.iter().any(|s| s.is_suspending()))
    }

    /// Execute a pipeline that may contain elicitation/sampling steps (suspendable).
    /// Returns `Complete` if the pipeline finishes, `Suspended` if it pauses for client input.
    ///
    /// `surface` records which MCP surface initiated the call so that,
    /// on suspension, the persisted state carries it for the resume
    /// path to project the completed result onto the right wire shape
    /// (tool / prompt / resource).
    pub(crate) fn execute_pipeline(
        &self,
        profile: &str,
        request: &BackendInvocationRequest,
        pipeline_store: &dyn PipelineStore,
        surface: crate::runtime::pipeline_store::PipelineSurface,
    ) -> PipelineOutcome {
        let pipeline_config = match self.pipeline_configs.get(profile) {
            Some(cfg) => cfg.clone(),
            None => {
                return PipelineOutcome::Complete(ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "pipeline config not found for profile '{}'",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                });
            }
        };

        // Emit the pipeline-started audit event. Bookended by the
        // matching mcpg.pipeline.{completed,failed} event the
        // outcome dispatch below emits. Only fire for pipelines
        // that actually orchestrate multiple steps; single-step
        // synchronous binding dispatch is already covered by the
        // tool-call audit lane.
        let pipeline_started_at = std::time::Instant::now();
        let pipeline_id = request.context.request_id.as_str().to_owned();
        let session_id = request.context.session_id.clone();
        let profile_owned = profile.to_owned();
        let actor = crate::runtime::plugin_identity_from_request(&request.context);
        let request_id = request.context.request_id.as_str().to_owned();
        let step_count = pipeline_config.steps.len() as u64;
        if let Some(registry) = self.plugin_registry.clone() {
            let actor_started = actor.clone();
            let request_id_started = request_id.clone();
            let session_id_started = session_id.clone();
            let pipeline_id_started = pipeline_id.clone();
            let profile_started = profile_owned.clone();
            tokio::spawn(async move {
                let event = mcpg_plugin_host::audit_events::pipeline_started_event(
                    actor_started,
                    &request_id_started,
                    session_id_started.as_deref(),
                    &pipeline_id_started,
                    &profile_started,
                    step_count,
                );
                let _ = registry.emit_audit_event(&event).await;
            });
        }

        // Check for suspending steps — if none, use the fast synchronous path.
        // Pipeline steps never read the runtime snapshot (only the internal
        // diagnostics tools do, and those dispatch through their own route).
        let has_suspending_steps = pipeline_config.steps.iter().any(|s| s.is_suspending());
        if !has_suspending_steps {
            let execution_context = ToolExecutionContext {
                runtime_snapshot: None,
            };
            let result = self.execute_pipeline_binding(profile, request, &execution_context);
            // Audit the synchronous fast-path completion.
            self.audit_pipeline_terminal(
                &actor,
                &request_id,
                session_id.as_deref(),
                &pipeline_id,
                &profile_owned,
                !result.is_error,
                step_count,
                pipeline_started_at.elapsed().as_millis() as u64,
                if result.is_error {
                    extract_error_message(&result)
                } else {
                    None
                },
            );
            return PipelineOutcome::Complete(result);
        }

        // Build initial pipeline execution state
        let mut state = PipelineExecutionState {
            pipeline_id: request.context.request_id.as_str().to_owned(),
            session_id: request.context.session_id.clone().unwrap_or_default(),
            original_jsonrpc_id: serde_json::Value::Null, // will be set by runtime
            tool_name: request.tool_name.clone(),
            steps: pipeline_config.steps.clone(),
            current_step_index: 0,
            completed_steps: std::collections::BTreeMap::new(),
            original_args: request.arguments.clone().unwrap_or(Value::Null),
            request_context: request.context.clone(),
            created_at: chrono::Utc::now(),
            suspended_at: None,
            pipeline_timeout_ms: pipeline_config.pipeline_timeout_ms,
            pending_server_request_id: None,
            elicitation_timeout_ms: None,
            related_task_id: None,
            client_capabilities: request.client_capabilities.clone(),
            state_version: 0,
            surface,
        };

        let execution_context = ToolExecutionContext {
            runtime_snapshot: None,
        };
        let outcome = self.execute_pipeline_steps(
            &mut state,
            profile,
            request,
            &execution_context,
            pipeline_store,
        );
        // Emit the terminal-state audit event when the pipeline
        // reaches Complete on the initial run (no suspension). The
        // resume path emits its own terminal event below.
        if let PipelineOutcome::Complete(ref result) = outcome {
            self.audit_pipeline_terminal(
                &actor,
                &request_id,
                session_id.as_deref(),
                &pipeline_id,
                &profile_owned,
                !result.is_error,
                state.completed_steps.len() as u64,
                pipeline_started_at.elapsed().as_millis() as u64,
                if result.is_error {
                    extract_error_message(result)
                } else {
                    None
                },
            );
        }
        outcome
    }

    /// Resume a suspended pipeline after receiving a client response.
    pub(crate) fn resume_pipeline(
        &self,
        mut state: PipelineExecutionState,
        step_result: StepResult,
        pipeline_store: &dyn PipelineStore,
    ) -> PipelineOutcome {
        // Record the elicitation/sampling step result
        if state.current_step_index < state.steps.len() {
            let step_id = state.steps[state.current_step_index].id().to_owned();
            state.completed_steps.insert(step_id, step_result);
            state.current_step_index += 1;
        }

        let profile = state.tool_name.clone();
        let expr_ctx = state
            .request_context
            .to_expr_context(&state.tool_name, Some(&state.original_args));
        let request = BackendInvocationRequest {
            context: state.request_context.clone(),
            tool_name: state.tool_name.clone(),
            arguments: Some(state.original_args.clone()),
            expr_ctx,
            progress_token: None,
            // Resume path: like `progress_token`, the per-request log
            // floor was a property of the original (now-returned)
            // request. A modern resume that re-runs `log` steps thus
            // suppresses them (None ⇒ modern suppress-all), which is the
            // spec-safe default; legacy ignores this field regardless.
            request_log_level: None,
            // Resume path: the session store isn't reachable from the
            // executor, so the legacy floor is not re-applied on resume.
            // `None` preserves the prior unfiltered behaviour for the
            // rare resume-of-`log`-step case.
            legacy_session_log_level: None,
            client_capabilities: state.client_capabilities.clone(),
            // Resume path: the token was dropped when the original
            // request returned; cancellation during resume is picked up
            // from the bus by a fresh subscription in the runtime.
            cancellation_token: None,
            // Resume path: idempotency hint is not re-derived; the
            // first-call sub-step requests carried it forward through
            // their persisted state, so resumed sub-steps re-build a
            // fresh request without the hint. This is consistent with
            // current behaviour for `progress_token` (also dropped on
            // resume).
            idempotency_hint: None,
        };
        let execution_context = ToolExecutionContext {
            runtime_snapshot: None,
        };
        let resume_started_at = std::time::Instant::now();
        let actor = crate::runtime::plugin_identity_from_request(&state.request_context);
        let request_id = state.request_context.request_id.as_str().to_owned();
        let session_id = state.request_context.session_id.clone();
        let pipeline_id = state.pipeline_id.clone();
        let profile_owned = profile.clone();

        let outcome = self.execute_pipeline_steps(
            &mut state,
            &profile,
            &request,
            &execution_context,
            pipeline_store,
        );
        // Emit the terminal-state audit event on the resume path.
        // A Suspended outcome means the pipeline went back to wait for
        // another client response; the next resume call will emit
        // when it reaches Complete.
        if let PipelineOutcome::Complete(ref result) = outcome {
            self.audit_pipeline_terminal(
                &actor,
                &request_id,
                session_id.as_deref(),
                &pipeline_id,
                &profile_owned,
                !result.is_error,
                state.completed_steps.len() as u64,
                resume_started_at.elapsed().as_millis() as u64,
                if result.is_error {
                    extract_error_message(result)
                } else {
                    None
                },
            );
        }
        outcome
    }

    /// Internal helper that fans the pipeline-terminal audit event
    /// out via tokio::spawn (callers are sync). Reads the registry
    /// through `self.plugin_registry` and bails silently if no
    /// registry is wired (test paths).
    #[allow(clippy::too_many_arguments)]
    fn audit_pipeline_terminal(
        &self,
        actor: &mcpg_plugin_protocol::PluginIdentity,
        request_id: &str,
        session_id: Option<&str>,
        pipeline_id: &str,
        profile: &str,
        success: bool,
        steps_completed: u64,
        duration_ms: u64,
        error_message: Option<String>,
    ) {
        let Some(registry) = self.plugin_registry.clone() else {
            return;
        };
        let actor = actor.clone();
        let request_id = request_id.to_owned();
        let session_id = session_id.map(str::to_owned);
        let pipeline_id = pipeline_id.to_owned();
        let profile = profile.to_owned();
        tokio::spawn(async move {
            let event = mcpg_plugin_host::audit_events::pipeline_completed_event(
                actor,
                &request_id,
                session_id.as_deref(),
                &pipeline_id,
                &profile,
                success,
                steps_completed,
                duration_ms,
                error_message.as_deref(),
            );
            let _ = registry.emit_audit_event(&event).await;
        });
    }

    /// Synchronous (buffered) backend dispatch with retry handling.
    ///
    /// Resolves the route to a concrete backend (internal adapter vs.
    /// plugin-backed NATS / Kafka / SQL / LLM / HTTP / gRPC / GraphQL /
    /// command / mock / pipeline) and invokes it. On an `is_error`
    /// result it consults the tool's `RetryConfig`: retryable errors
    /// are re-attempted up to `max_attempts` with exponential backoff,
    /// returning the last result once retries are exhausted or the
    /// error is non-retryable. For clients that supplied a
    /// `progressToken`, a single 0/1 -> 1/1 progress pair brackets the
    /// call (pipelines emit their own per-step progress instead).
    #[tracing::instrument(skip(self, request, runtime_snapshot), fields(tool_name = %request.tool_name))]
    pub(crate) fn dispatch_tool_call(
        &self,
        route: BackendInvocationRoute,
        request: &BackendInvocationRequest,
        runtime_snapshot: Option<RuntimeSnapshot>,
    ) -> ToolCallResult {
        // A pipeline binding runs a sequence of independently-committing
        // steps; re-running the whole pipeline here would replay earlier steps
        // that already committed (possibly non-idempotent) side effects. A
        // binding that routes to a pipeline therefore never retries as a unit
        // — a step failure surfaces to the caller instead of silently redoing
        // committed work.
        let retry_config = if matches!(route, BackendInvocationRoute::Pipeline { .. }) {
            None
        } else {
            self.retry_configs.get(&request.tool_name)
        };
        let max_attempts = retry_config.map_or(1, |rc| 1 + rc.max_attempts);

        let backend_kind = backend_kind(&request.tool_name);
        let span = tracing::info_span!(
            "binding_call",
            binding.name = %request.tool_name,
            binding.type_ = %backend_kind,
        );
        let _guard = span.enter();

        // Single-step progress: emit 0/1 "started" if client provided a progressToken
        // and this is not a pipeline (pipelines emit their own granular progress).
        let emit_single_step_progress = request.progress_token.is_some()
            && !matches!(route, BackendInvocationRoute::Pipeline { .. });
        if emit_single_step_progress && let Some(ref token) = request.progress_token {
            self.emit_pipeline_progress(&request.context, token, 0.0, 1.0);
        }

        let mut last_result = None;
        for attempt in 0..max_attempts {
            let execution_context = ToolExecutionContext {
                runtime_snapshot: runtime_snapshot.clone(),
            };
            let result = match ToolExecutionTarget::from_route(route.clone()) {
                ToolExecutionTarget::Internal(adapter) => {
                    adapter.execute(request, &execution_context)
                }
                ToolExecutionTarget::Federated {
                    ref source,
                    ref upstream_name,
                } => match self.federation_engine.load_full() {
                    Some(engine) => {
                        let source = source.clone();
                        let upstream_name = upstream_name.clone();
                        let args = request.arguments.clone();
                        let principal = request.context.identity.synthetic_principal_key();
                        let caller_identity = request.context.identity.clone();
                        let session_id = request.context.session_id.clone();
                        let caller_bearer = request.context.inbound_bearer.clone();
                        // Forward the client's progress token so upstream
                        // progress correlates for the client.
                        let progress_token = request.progress_token.clone();
                        // Federated dispatch is async (a network call to the
                        // upstream); bridge to the sync dispatch path the same
                        // way binding plugins do. Upstream server-requests
                        // (sampling/elicitation/roots) + progress are bridged
                        // to the client.
                        let outcome = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(engine.call_tool(
                                &source,
                                &upstream_name,
                                args.as_ref(),
                                crate::runtime::federation::FederationCaller {
                                    principal: principal.as_deref(),
                                    session_id: session_id.as_deref(),
                                    bearer: caller_bearer.as_deref(),
                                    identity: Some(&caller_identity),
                                },
                                progress_token.as_ref(),
                            ))
                        });
                        match outcome {
                            Ok(value) => federated_value_to_result(value),
                            Err(e) => {
                                // Opaque client message + correlation id. The
                                // detailed `UpstreamError` can carry upstream
                                // URLs and credential-issuer / STS error bodies
                                // — operator-debug detail that must never reach
                                // an arbitrary caller. It goes to the gateway
                                // log only; the caller gets the request id to
                                // correlate. Mirrors the opaque cred-resolution
                                // failure message in `backends::host`.
                                let request_id = request.context.request_id.as_str().to_owned();
                                tracing::warn!(
                                    target: "mcpg::federation",
                                    tool = %request.tool_name,
                                    request_id = %request_id,
                                    error = %e,
                                    "federated tool call failed"
                                );
                                ToolCallResult {
                                    content: vec![ToolContent::text(format!(
                                        "federated tool '{}' failed (request id: {request_id})",
                                        request.tool_name
                                    ))],
                                    structured_content: None,
                                    is_error: true,
                                    meta: None,
                                }
                            }
                        }
                    }
                    None => ToolCallResult {
                        content: vec![ToolContent::text(format!(
                            "federated tool '{}' unavailable: federation engine not configured",
                            request.tool_name
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    },
                },
                ToolExecutionTarget::Adapter(AdapterToolRoute::NatsRequest { profile }) => {
                    execute_nats_request(&profile, request, self.plugin_registry.as_ref())
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::KafkaRequest { profile }) => {
                    execute_kafka_request(&profile, request, self.plugin_registry.as_ref())
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::SqlRequest { profile }) => {
                    execute_sql_request(&profile, request, self.plugin_registry.as_ref())
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::LlmRequest { profile, kind }) => {
                    execute_llm_request(kind, &profile, request, self.plugin_registry.as_ref())
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::Pipeline { profile }) => {
                    self.execute_pipeline_binding(&profile, request, &execution_context)
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::NetworkJsonCall { profile }) => {
                    execute_http_request(
                        &profile,
                        HttpDispatchMode::JsonBody,
                        request,
                        self.network_profiles.as_ref(),
                        self.plugin_registry.as_ref(),
                    )
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::NetworkQueryCall { profile }) => {
                    execute_http_request(
                        &profile,
                        HttpDispatchMode::QueryString,
                        request,
                        self.network_profiles.as_ref(),
                        self.plugin_registry.as_ref(),
                    )
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::GraphqlCall { profile }) => {
                    execute_envelope_plugin(
                        "graphql",
                        &profile,
                        request,
                        self.plugin_registry.as_ref(),
                    )
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::OpenapiCall { profile }) => {
                    execute_envelope_plugin(
                        "openapi",
                        &profile,
                        request,
                        self.plugin_registry.as_ref(),
                    )
                }
                // The command BINDING routes through the
                // `dev.mcpg.backend.command` plugin; `require_json_stdout`
                // comes from the plugin's registered profile, so the
                // route-level flag is unused here. (The debug CommandProbe
                // tool stays on the inline adapter path below.)
                ToolExecutionTarget::Adapter(AdapterToolRoute::CommandJsonCall { profile }) => {
                    execute_envelope_plugin(
                        "command",
                        &profile,
                        request,
                        self.plugin_registry.as_ref(),
                    )
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::MockResponse { profile }) => {
                    execute_envelope_plugin(
                        "mock",
                        &profile,
                        request,
                        self.plugin_registry.as_ref(),
                    )
                }
                ToolExecutionTarget::Adapter(AdapterToolRoute::EnvelopePlugin {
                    kind,
                    profile,
                }) => {
                    execute_envelope_plugin(&kind, &profile, request, self.plugin_registry.as_ref())
                }
                ToolExecutionTarget::Adapter(adapter) => {
                    self.adapter_executor
                        .execute(adapter, request, &execution_context)
                }
            };

            // If no retry config, return immediately
            let rc = match retry_config {
                Some(rc) if result.is_error => rc,
                _ => {
                    if emit_single_step_progress && let Some(ref token) = request.progress_token {
                        self.emit_pipeline_progress(&request.context, token, 1.0, 1.0);
                    }
                    return result;
                }
            };

            // Check if the error is retryable based on config
            let retryable = self.is_retryable_error(&result, rc);
            if !retryable || attempt + 1 >= max_attempts {
                if attempt > 0 {
                    tracing::warn!(
                        tool_name = %request.tool_name,
                        attempt = attempt + 1,
                        max_attempts = max_attempts,
                        "retry exhausted, returning last error"
                    );
                    metrics::counter!(
                        "mcpg_binding_retries_exhausted_total",
                        "backend_name" => request.tool_name.clone(),
                    )
                    .increment(1);
                }
                if emit_single_step_progress && let Some(ref token) = request.progress_token {
                    self.emit_pipeline_progress(&request.context, token, 1.0, 1.0);
                }
                return result;
            }

            // Calculate backoff
            let backoff_ms = rc.initial_backoff_ms * 2u64.saturating_pow(attempt);
            tracing::info!(
                tool_name = %request.tool_name,
                attempt = attempt + 1,
                max_attempts = max_attempts,
                backoff_ms = backoff_ms,
                "binding call failed, retrying"
            );
            metrics::counter!(
                "mcpg_binding_retries_total",
                "backend_name" => request.tool_name.clone(),
            )
            .increment(1);

            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            last_result = Some(result);
        }

        let final_result = last_result.unwrap_or_else(|| ToolCallResult {
            content: vec![ToolContent::text("unexpected retry loop exit".to_owned())],
            structured_content: None,
            is_error: true,
            meta: None,
        });
        if emit_single_step_progress && let Some(ref token) = request.progress_token {
            self.emit_pipeline_progress(&request.context, token, 1.0, 1.0);
        }
        final_result
    }

    /// Check if a tool call error matches the retry configuration.
    fn is_retryable_error(&self, result: &ToolCallResult, rc: &crate::config::RetryConfig) -> bool {
        error_result_is_retryable(result, rc)
    }
}

// --- Pipeline step helpers ---

#[tracing::instrument(skip(request, plugin_registry), fields(profile = %profile))]
fn execute_nats_request(
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, "nats") {
        return cancelled;
    }

    match plugin_registry.and_then(|r| r.backend("nats")) {
        Some(plugin) => {
            execute_binding_plugin("nats", profile, request, plugin.as_ref(), plugin_registry)
        }
        None => ToolCallResult {
            content: vec![ToolContent::text(format!(
                "NATS execution for '{}' failed: NATS binding plugin not registered",
                request.tool_name
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        },
    }
}

/// Dispatch a binding call through a `BackendPlugin` registered in the
/// plugin registry. Shared between the NATS and Kafka routes — any future
/// transport plugin (MQTT, RabbitMQ, …) will flow through this path as well.
fn execute_binding_plugin(
    kind: &str,
    profile: &str,
    request: &BackendInvocationRequest,
    plugin: &dyn mcpg_plugin_protocol::BackendPlugin,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    let args = request.arguments.clone().unwrap_or(serde_json::json!({}));
    let payload = match serde_json::to_vec(&args) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "failed to serialize {kind} request payload: {e}"
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };
    let payload_bytes = payload.len() as u64;

    let mut headers = Vec::new();
    if let Some(tc) = request.context.trace_context.as_ref() {
        headers.push(("traceparent".to_owned(), tc.child_traceparent()));
        if let Some(ts) = tc.tracestate.as_deref() {
            headers.push(("tracestate".to_owned(), ts.to_owned()));
        }
    }

    let binding_request = mcpg_plugin_protocol::BackendRequest {
        payload,
        headers,
        request_id: request.context.request_id.to_string(),
        session_id: request.context.session_id.clone(),
        identity: Some(crate::runtime::plugin_identity_from_request(
            &request.context,
        )),
        // Leaf backends propagate the operator-supplied key to their
        // upstreams (HTTP / SQL / NATS / Kafka).
        idempotency: request
            .idempotency_hint
            .as_ref()
            .map(|h| h.to_plugin_hint()),
    };

    let profile_owned = profile.to_owned();
    let started = std::time::Instant::now();
    let result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(plugin.execute(&profile_owned, binding_request))
    });
    let duration_ms = started.elapsed().as_millis() as u64;

    // Every backend dispatch lands on the audit lane (today metered
    // only). Hash-free; payload + response sizes give auditors enough
    // signal to spot anomalies without storing the bytes themselves.
    if let Some(registry) = plugin_registry {
        let actor = crate::runtime::plugin_identity_from_request(&request.context);
        let request_id = request.context.request_id.as_str().to_owned();
        let session_id = request.context.session_id.clone();
        let kind_owned = kind.to_owned();
        let profile_owned_for_audit = profile.to_owned();
        let registry_arc = registry.clone();
        let (success, response_bytes, error_message) = match &result {
            Ok(reply) => (true, reply.payload.len() as u64, None),
            Err(e) => (false, 0u64, Some(e.to_string())),
        };
        // Collect plugin-supplied audit fields (e.g. SQL's `db.driver` +
        // `db.query_ref`) before crossing the spawn boundary; the plugin
        // reference doesn't outlive this scope.
        let extra_details = plugin.audit_metadata(profile);
        tokio::spawn(async move {
            let event = mcpg_plugin_host::audit_events::backend_executed_event(
                actor,
                &request_id,
                session_id.as_deref(),
                &kind_owned,
                &profile_owned_for_audit,
                success,
                duration_ms,
                payload_bytes,
                response_bytes,
                error_message.as_deref(),
                extra_details,
            );
            let _ = registry_arc.emit_audit_event(&event).await;
        });
    }

    match result {
        Ok(reply) => {
            let reply_text = String::from_utf8_lossy(&reply.payload);
            let structured: Option<serde_json::Value> = serde_json::from_slice(&reply.payload).ok();
            // Verbatim-result convention: a plugin may wrap a full
            // CallToolResult under `__mcpg_verbatim_result` to control
            // `is_error` + a literal multi-block `content` array.
            if let Some(verbatim) = structured.as_ref().and_then(|v| v.get(VERBATIM_RESULT_KEY))
                && let Ok(mut projected) =
                    serde_json::from_value::<ToolCallResult>(verbatim.clone())
            {
                projected.meta = Some(binding_audit_meta(kind, profile, projected.is_error));
                return projected;
            }
            // A non-null `downstreamError` slot is the plugin's tool-level
            // error signal. Honour it the same way `execute_envelope_plugin`
            // does so a backend's error contract is identical whether it is
            // invoked as a top-level binding or as a pipeline step.
            let envelope_is_error = structured
                .as_ref()
                .and_then(|v| v.get("downstreamError"))
                .map(|d| !d.is_null())
                .unwrap_or(false);
            let mut content_text = reply_text.to_string();
            if reply.truncated {
                content_text.push_str("\n[response truncated]");
            }
            ToolCallResult {
                content: vec![ToolContent::text(content_text)],
                structured_content: structured,
                is_error: envelope_is_error,
                meta: Some(binding_audit_meta(kind, profile, envelope_is_error)),
            }
        }
        Err(e) => ToolCallResult {
            content: vec![ToolContent::text(format!("{kind} request failed: {e}"))],
            structured_content: None,
            is_error: true,
            meta: Some(binding_audit_meta(kind, profile, true)),
        },
    }
}

/// Streaming counterpart of [`execute_binding_plugin`]. Drives the
/// plugin's `execute_streaming` and forwards every `BackendChunk` to
/// the gateway's delivery bus as a `notifications/progress` JSON-RPC
/// event tagged with the operator's `progressToken` and the chunk
/// payload under `_meta["mcpg.backend.chunk"]`.
///
/// The terminal `BackendChunk::Done(BackendResponse)` chunk is
/// captured and converted to the same `ToolCallResult` shape the
/// non-streaming path returns, so the rest of the dispatch pipeline
/// (audit, retry, payment receipt, etc.) is unchanged.
///
/// This function is only called for routes the runtime has classified
/// as streaming-eligible (LLM bindings with a client-supplied
/// `progressToken` and a session). Other paths remain on the
/// synchronous `execute_binding_plugin`. See `should_stream_tool_call`
/// in `runtime/mod.rs`.
async fn execute_binding_plugin_streaming(
    kind: &str,
    profile: &str,
    request: &BackendInvocationRequest,
    plugin: &dyn mcpg_plugin_protocol::BackendPlugin,
    delivery_bus: &Arc<dyn crate::runtime::delivery_bus::DeliveryBus>,
    progress_token: &serde_json::Value,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    let args = request.arguments.clone().unwrap_or(serde_json::json!({}));
    let payload = match serde_json::to_vec(&args) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "failed to serialize {kind} streaming request payload: {e}"
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };

    let mut headers = Vec::new();
    if let Some(tc) = request.context.trace_context.as_ref() {
        headers.push(("traceparent".to_owned(), tc.child_traceparent()));
        if let Some(ts) = tc.tracestate.as_deref() {
            headers.push(("tracestate".to_owned(), ts.to_owned()));
        }
    }
    // Surface the tool name to backends that include it in their
    // response envelope (HTTP today). Non-tool-aware backends
    // (LLM, NATS, …) ignore unknown header names.
    headers.push(("mcpg-tool-name".to_owned(), request.tool_name.clone()));

    let binding_request = mcpg_plugin_protocol::BackendRequest {
        payload,
        headers,
        request_id: request.context.request_id.to_string(),
        session_id: request.context.session_id.clone(),
        identity: Some(crate::runtime::plugin_identity_from_request(
            &request.context,
        )),
        // Streaming leaf backends also propagate the key to their
        // upstreams; the gateway's own assembled-envelope cache is
        // independent of this.
        idempotency: request
            .idempotency_hint
            .as_ref()
            .map(|h| h.to_plugin_hint()),
    };

    let session_id = match request.context.session_id.as_deref() {
        Some(s) => s.to_owned(),
        None => {
            // Should not happen — the gateway gates streaming behind
            // session_id presence — but be defensive.
            return execute_binding_plugin(kind, profile, request, plugin, plugin_registry);
        }
    };

    let mut stream = match plugin.execute_streaming(profile, binding_request).await {
        Ok(s) => s,
        Err(e) => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "{kind} streaming request failed: {e}"
                ))],
                structured_content: None,
                is_error: true,
                meta: Some(binding_audit_meta(kind, profile, true)),
            };
        }
    };

    use futures::StreamExt;

    let mut chunk_index: u64 = 0;
    let mut final_response: Option<mcpg_plugin_protocol::BackendResponse> = None;
    let mut stream_error: Option<String> = None;

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                stream_error = Some(format!("{kind} streaming chunk error: {e}"));
                break;
            }
        };

        // Forward EVERY chunk (including Done) as a progress event so
        // clients can reconstruct the full chunk timeline if they
        // care. The Done chunk doubles as the stream terminator and
        // is also used to build the final ToolCallResult.
        emit_chunk_notification(
            delivery_bus,
            &session_id,
            progress_token,
            chunk_index,
            &chunk,
        );
        chunk_index += 1;

        if let mcpg_plugin_protocol::BackendChunk::Done(resp) = chunk {
            final_response = Some(resp);
            // Stream MUST end after Done per the BackendChunk
            // contract. Defensive: drain any trailing chunks so the
            // upstream task can clean up.
            while stream.next().await.is_some() {}
            break;
        }
    }

    if let Some(err) = stream_error {
        return ToolCallResult {
            content: vec![ToolContent::text(err)],
            structured_content: None,
            is_error: true,
            meta: Some(binding_audit_meta(kind, profile, true)),
        };
    }

    let Some(reply) = final_response else {
        return ToolCallResult {
            content: vec![ToolContent::text(format!(
                "{kind} streaming ended without a terminal Done chunk"
            ))],
            structured_content: None,
            is_error: true,
            meta: Some(binding_audit_meta(kind, profile, true)),
        };
    };

    let reply_text = String::from_utf8_lossy(&reply.payload);
    let structured: Option<serde_json::Value> = serde_json::from_slice(&reply.payload).ok();
    let mut content_text = reply_text.to_string();
    if reply.truncated {
        content_text.push_str("\n[response truncated]");
    }
    // Match the buffered HTTP path's envelope-as-error semantics.
    // When a binding plugin returns a structured envelope with a
    // non-null `downstreamError` (HTTP today), surface it as
    // `is_error: true` so the dispatch retry layer + operator-
    // visible errors line up with the sync path.
    let envelope_is_error = structured
        .as_ref()
        .and_then(|v| v.get("downstreamError"))
        .map(|d| !d.is_null())
        .unwrap_or(false);
    ToolCallResult {
        content: vec![ToolContent::text(content_text)],
        structured_content: structured,
        is_error: envelope_is_error,
        meta: Some(binding_audit_meta(kind, profile, envelope_is_error)),
    }
}

/// Convert a `BackendChunk` to a JSON-RPC `notifications/progress`
/// frame and publish it on the delivery bus for the client's
/// session. Each chunk gets a monotonic `progress` index so MCP's
/// strictly-increasing requirement holds.
///
/// The chunk's full structure travels under
/// `params._meta["mcpg.backend.chunk"]`. Clients that don't
/// recognize the extension still see the standard `progress` /
/// `message` fields and can render a generic "step N of …" UI; rich
/// clients parse the chunk and render text deltas / tool calls /
/// usage in their native shapes.
fn emit_chunk_notification(
    delivery_bus: &Arc<dyn crate::runtime::delivery_bus::DeliveryBus>,
    session_id: &str,
    progress_token: &serde_json::Value,
    chunk_index: u64,
    chunk: &mcpg_plugin_protocol::BackendChunk,
) {
    let chunk_value = match serde_json::to_value(chunk) {
        Ok(v) => v,
        Err(_) => return,
    };
    let message = chunk_human_label(chunk);
    let notification = serde_json::json!({
        "jsonrpc": crate::protocol::JSONRPC_VERSION,
        "method": "notifications/progress",
        "params": {
            "progressToken": progress_token,
            "progress": chunk_index as f64,
            "message": message,
            "_meta": {
                "mcpg.backend.chunk": chunk_value,
            }
        }
    });
    let delivery = crate::runtime::pipeline_store::DeliveryMessage {
        kind: crate::runtime::pipeline_store::DeliveryKind::ProgressNotification,
        jsonrpc_message: notification,
        delivery_id: String::new(),
    };
    let bus = Arc::clone(delivery_bus);
    let session = session_id.to_owned();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = bus.publish(&session, delivery).await;
        });
    }
}

/// Short human-readable label for a chunk, surfaced in the
/// `params.message` field of the progress notification. Gives clients
/// a sensible fallback when they don't read `_meta`.
fn chunk_human_label(chunk: &mcpg_plugin_protocol::BackendChunk) -> String {
    use mcpg_plugin_protocol::BackendChunk;
    match chunk {
        BackendChunk::TextDelta { delta } => {
            // Keep label bounded — full delta is in _meta.
            let preview: String = delta.chars().take(40).collect();
            format!("text_delta: {preview}")
        }
        BackendChunk::ToolCall { name, .. } => format!("tool_call: {name}"),
        BackendChunk::ToolResult { id, .. } => format!("tool_result: {id}"),
        BackendChunk::Usage {
            input_tokens,
            output_tokens,
            ..
        } => format!("usage: in={input_tokens} out={output_tokens}"),
        BackendChunk::IterationBoundary { iteration } => format!("iteration: {iteration}"),
        BackendChunk::Progress { message, .. } => {
            // Backend-emitted Progress carries its own human label;
            // forward it verbatim so clients see exactly what the
            // plugin authored (e.g. "received 16 KiB").
            message.clone()
        }
        BackendChunk::Done(_) => "done".to_owned(),
    }
}

/// Build the `_meta.audit` object every binding-plugin dispatch
/// attaches to its `ToolCallResult`. The gateway's audit
/// plugin copies this onto `AuditEvent.meta` so downstream SIEM
/// ingestion sees a single record per call with the transport
/// kind tagged. Richer per-engine fields (SQL driver, NATS
/// subject, …) flow through the same object when the plugin
/// extends its response envelope in the future.
fn binding_audit_meta(kind: &str, profile: &str, is_error: bool) -> serde_json::Value {
    serde_json::json!({
        "audit": {
            "backend_kind": kind,
            "binding_profile": profile,
            "outcome": if is_error { "error" } else { "success" },
        }
    })
}

#[tracing::instrument(skip(request, plugin_registry), fields(profile = %profile))]
fn execute_kafka_request(
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, "kafka") {
        return cancelled;
    }

    match plugin_registry.and_then(|r| r.backend("kafka")) {
        Some(plugin) => {
            execute_binding_plugin("kafka", profile, request, plugin.as_ref(), plugin_registry)
        }
        None => ToolCallResult {
            content: vec![ToolContent::text(format!(
                "Kafka execution for '{}' failed: Kafka binding plugin not registered",
                request.tool_name
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        },
    }
}

/// Dispatch a binding invocation through the plugin registry, bridging
/// the sync `dispatch_tool_call` to the async `BackendPlugin::execute`
/// without depending on the runtime's flavor.
///
/// On production multi-thread runtimes we first poll the future once with
/// a no-op waker: an inline-dispatch (operator-trusted, in-process) backend
/// has no `.await` point and resolves on that first poll, so we return its
/// result directly and skip `block_in_place` — which otherwise parks this
/// worker and spins up a replacement for every call. A genuinely async
/// backend (network I/O, or the default `spawn_blocking` ferry) returns
/// `Pending`; we then move the task off the worker with `block_in_place`.
/// Re-polling after `Pending` is sound: `block_on` installs its own waker.
///
/// Under `#[tokio::test]`'s default current-thread runtime — and inside
/// non-tokio `#[test]` — `block_in_place` panics, so we spin up a transient
/// runtime on a fresh OS thread and run the future to completion there.
/// `std::thread::scope` keeps borrows safe.
fn run_async_in_sync_context(
    plugin: &dyn mcpg_plugin_protocol::BackendPlugin,
    profile: &str,
    request: mcpg_plugin_protocol::BackendRequest,
) -> Result<mcpg_plugin_protocol::BackendResponse, mcpg_plugin_protocol::BackendError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current()
        && matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    {
        let mut fut = std::pin::pin!(plugin.execute(profile, request));
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        if let std::task::Poll::Ready(out) = std::future::Future::poll(fut.as_mut(), &mut cx) {
            return out;
        }
        return tokio::task::block_in_place(|| handle.block_on(fut.as_mut()));
    }
    std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build temporary runtime");
            rt.block_on(plugin.execute(profile, request))
        })
        .join()
        .expect("worker thread joined")
    })
}

/// Dispatch a tool call to an envelope-shaped backend plugin (grpc /
/// graphql / command / mock — the backends migrated off the inline
/// `DebugToolExecutor` path).
///
/// Shares the http backend's contract: the plugin returns a structured
/// JSON envelope as its `BackendResponse.payload`, and a non-null
/// `downstreamError` slot signals a tool-level error (so the dispatch
/// retry layer + operator-visible `is_error` match the legacy inline
/// path). The gateway forwards the tool name as the `mcpg-tool-name`
/// header + W3C trace context; the plugin owns CEL / `cred://`
/// resolution and family-specific request shaping.
///
/// This is the non-streaming, non-`mode` cousin of
/// [`execute_http_request`]: there is no `network_profiles` existence
/// pre-check (the plugin owns its profile map) and no GET/POST mode
/// (the plugin recovers any transport specifics from its registered
/// profile).
/// Map an upstream MCP `CallToolResult` value into the gateway's
/// [`ToolCallResult`]. The upstream speaks the same protocol, so the
/// shape matches; fields are extracted defensively and a malformed
/// `content` array falls back to a single text block.
fn federated_value_to_result(value: Value) -> ToolCallResult {
    let is_error = value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let structured_content = value.get("structuredContent").cloned();
    let meta = value.get("_meta").cloned();
    let content = value
        .get("content")
        .and_then(|c| serde_json::from_value::<Vec<ToolContent>>(c.clone()).ok())
        .unwrap_or_else(|| vec![ToolContent::text(value.to_string())]);
    ToolCallResult {
        content,
        structured_content,
        is_error,
        meta,
    }
}

#[cfg(test)]
mod federated_value_tests {
    use super::*;

    #[test]
    fn maps_upstream_call_tool_result_fields() {
        let v = serde_json::json!({
            "content": [{ "type": "text", "text": "hi" }],
            "isError": true,
            "structuredContent": { "k": 1 }
        });
        let r = federated_value_to_result(v);
        assert_eq!(r.content.len(), 1);
        assert!(r.is_error);
        assert_eq!(r.structured_content.unwrap()["k"], 1);
    }

    #[test]
    fn malformed_content_falls_back_to_text() {
        let r = federated_value_to_result(serde_json::json!({ "content": "oops" }));
        assert_eq!(r.content.len(), 1);
        assert!(!r.is_error);
    }
}

#[cfg(test)]
mod log_filter_tests {
    use super::*;
    use crate::protocol::LoggingLevel;

    #[test]
    fn legacy_no_floor_emits_everything() {
        // Byte-identical 2025-11-25 default: no session floor ⇒ emit.
        assert!(!log_step_suppressed("debug", false, None, None));
        assert!(!log_step_suppressed("info", false, None, None));
    }

    #[test]
    fn legacy_session_floor_suppresses_below_minimum() {
        // Session set to Warning: debug/info suppressed, warning/error emit.
        assert!(log_step_suppressed(
            "debug",
            false,
            None,
            Some(LoggingLevel::Warning)
        ));
        assert!(log_step_suppressed(
            "info",
            false,
            None,
            Some(LoggingLevel::Warning)
        ));
        assert!(!log_step_suppressed(
            "warning",
            false,
            None,
            Some(LoggingLevel::Warning)
        ));
        assert!(!log_step_suppressed(
            "error",
            false,
            None,
            Some(LoggingLevel::Warning)
        ));
    }

    #[test]
    fn legacy_unrecognised_level_emits() {
        assert!(!log_step_suppressed(
            "bogus",
            false,
            None,
            Some(LoggingLevel::Error)
        ));
    }

    #[test]
    fn modern_no_request_floor_suppresses_all() {
        assert!(log_step_suppressed("error", true, None, None));
    }
}

fn execute_envelope_plugin(
    kind: &str,
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, kind) {
        return cancelled;
    }

    let plugin = match plugin_registry.and_then(|r| r.backend(kind)) {
        Some(p) => p,
        None => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "{kind} execution for '{}' failed: {kind} backend plugin not registered",
                    request.tool_name
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };

    let args = request.arguments.clone().unwrap_or(serde_json::json!({}));
    let payload = match serde_json::to_vec(&args) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "failed to serialize {kind} request payload: {e}"
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };
    let payload_bytes = payload.len() as u64;

    let mut headers = Vec::new();
    if let Some(tc) = request.context.trace_context.as_ref() {
        headers.push(("traceparent".to_owned(), tc.child_traceparent()));
        if let Some(ts) = tc.tracestate.as_deref() {
            headers.push(("tracestate".to_owned(), ts.to_owned()));
        }
    }
    headers.push(("mcpg-tool-name".to_owned(), request.tool_name.clone()));

    let binding_request = mcpg_plugin_protocol::BackendRequest {
        payload,
        headers,
        request_id: request.context.request_id.to_string(),
        session_id: request.context.session_id.clone(),
        identity: Some(crate::runtime::plugin_identity_from_request(
            &request.context,
        )),
        idempotency: request
            .idempotency_hint
            .as_ref()
            .map(|h| h.to_plugin_hint()),
    };

    let profile_owned = profile.to_owned();
    let started = std::time::Instant::now();
    let result = run_async_in_sync_context(plugin.as_ref(), &profile_owned, binding_request);
    let duration_ms = started.elapsed().as_millis() as u64;

    if let Some(registry) = plugin_registry {
        let actor = crate::runtime::plugin_identity_from_request(&request.context);
        let request_id = request.context.request_id.as_str().to_owned();
        let session_id = request.context.session_id.clone();
        let kind_owned = kind.to_owned();
        let profile_owned_for_audit = profile.to_owned();
        let registry_arc = registry.clone();
        let (success, response_bytes, error_message) = match &result {
            Ok(reply) => (true, reply.payload.len() as u64, None),
            Err(e) => (false, 0u64, Some(e.to_string())),
        };
        let extra_details = plugin.audit_metadata(profile);
        tokio::spawn(async move {
            let event = mcpg_plugin_host::audit_events::backend_executed_event(
                actor,
                &request_id,
                session_id.as_deref(),
                &kind_owned,
                &profile_owned_for_audit,
                success,
                duration_ms,
                payload_bytes,
                response_bytes,
                error_message.as_deref(),
                extra_details,
            );
            let _ = registry_arc.emit_audit_event(&event).await;
        });
    }

    match result {
        Ok(reply) => {
            let reply_text = String::from_utf8_lossy(&reply.payload);
            let structured: Option<serde_json::Value> = serde_json::from_slice(&reply.payload).ok();
            // Verbatim-result convention: a plugin (mock) that needs to
            // control `is_error` + a literal multi-block `content` array
            // (which the standard projection can't express) wraps a full
            // CallToolResult under `__mcpg_verbatim_result`. Project it
            // directly; the audit meta still reflects the kind/profile.
            if let Some(verbatim) = structured.as_ref().and_then(|v| v.get(VERBATIM_RESULT_KEY))
                && let Ok(mut projected) =
                    serde_json::from_value::<ToolCallResult>(verbatim.clone())
            {
                projected.meta = Some(binding_audit_meta(kind, profile, projected.is_error));
                return projected;
            }
            // A non-null `downstreamError` slot is the plugin's
            // tool-level error signal — mirror the http path so the
            // retry layer + operator-visible `is_error` match the
            // legacy inline contract.
            let envelope_is_error = structured
                .as_ref()
                .and_then(|v| v.get("downstreamError"))
                .map(|d| !d.is_null())
                .unwrap_or(false);
            let mut content_text = reply_text.to_string();
            if reply.truncated {
                content_text.push_str("\n[response truncated]");
            }
            ToolCallResult {
                content: vec![ToolContent::text(content_text)],
                structured_content: structured,
                is_error: envelope_is_error,
                meta: Some(binding_audit_meta(kind, profile, envelope_is_error)),
            }
        }
        Err(e) => ToolCallResult {
            content: vec![ToolContent::text(format!("{kind} request failed: {e}"))],
            structured_content: None,
            is_error: true,
            meta: Some(binding_audit_meta(kind, profile, true)),
        },
    }
}

/// Envelope sentinel a plugin sets to have the gateway project a literal
/// [`ToolCallResult`] verbatim (operator-controlled `is_error` + content)
/// instead of the standard payload→envelope projection. Used by the mock
/// backend (`passthrough` / simulated `error`). Mirrors
/// `mcpg_plugin_backend_mock::VERBATIM_RESULT_KEY`.
const VERBATIM_RESULT_KEY: &str = "__mcpg_verbatim_result";

/// HTTP backend dispatch. Calls the `dev.mcpg.backend.http` plugin
/// via the same `execute_binding_plugin` shape NATS / Kafka / SQL
/// use. The plugin owns its CEL evaluator
/// (via the shared `mcpg-expr` crate), per-cred client caching,
/// DNS-rebinding guard, body-limit truncation, structured envelope
/// shaping, and `cred://` resolution. The gateway only hands over
/// the call's `arguments` payload + `identity` — the plugin re-runs
/// the operator templates against `$arguments` / `$context` per call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpDispatchMode {
    JsonBody,
    QueryString,
}

/// Mirrors [`execute_nats_request`] / [`execute_kafka_request`] — the
/// shared [`execute_binding_plugin`] carries the actual call.
#[tracing::instrument(skip(request, plugin_registry), fields(profile = %profile))]
fn execute_sql_request(
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, "sql") {
        return cancelled;
    }

    match plugin_registry.and_then(|r| r.backend("sql")) {
        Some(plugin) => {
            execute_binding_plugin("sql", profile, request, plugin.as_ref(), plugin_registry)
        }
        None => ToolCallResult {
            content: vec![ToolContent::text(format!(
                "SQL execution for '{}' failed: SQL binding plugin not registered",
                request.tool_name
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        },
    }
}

/// Mirror of [`execute_sql_request`] for the per-provider LLM binding
/// plugins. `kind` selects the registered plugin
/// (`openai.chat` / `azure_openai.chat` / `anthropic.chat` /
/// `gemini.chat` / `compat.chat`).
#[tracing::instrument(skip(request, plugin_registry), fields(profile = %profile, kind = ?kind))]
fn execute_llm_request(
    kind: crate::backends::LlmKind,
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, "llm") {
        return cancelled;
    }

    let plugin_kind = kind.plugin_kind();
    match plugin_registry.and_then(|r| r.backend(plugin_kind)) {
        Some(plugin) => execute_binding_plugin(
            plugin_kind,
            profile,
            request,
            plugin.as_ref(),
            plugin_registry,
        ),
        None => ToolCallResult {
            content: vec![ToolContent::text(format!(
                "LLM execution for '{}' failed: {} binding plugin not registered",
                request.tool_name, plugin_kind
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        },
    }
}

/// Streaming counterpart of [`execute_llm_request`]. Used when the
/// runtime detects a streaming-eligible call (LLM route + client
/// supplied a `progressToken` + session is active) and routes through
/// `ExecutionDispatcher::dispatch_tool_call_streaming`. The chunks
/// land on the gateway's delivery bus as `notifications/progress`
/// events and are forwarded to the client over its existing SSE
/// channel (the HTTP transport already streams `notifications/*`
/// frames during a `tools/call` round-trip).
#[tracing::instrument(skip(request, plugin_registry, delivery_bus, progress_token), fields(profile = %profile, kind = ?kind))]
async fn execute_llm_request_streaming(
    kind: crate::backends::LlmKind,
    profile: &str,
    request: &BackendInvocationRequest,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
    delivery_bus: &Arc<dyn crate::runtime::delivery_bus::DeliveryBus>,
    progress_token: &serde_json::Value,
) -> ToolCallResult {
    if let Some(cancelled) = early_cancel_check(request, profile, "llm") {
        return cancelled;
    }

    let plugin_kind = kind.plugin_kind();
    match plugin_registry.and_then(|r| r.backend(plugin_kind)) {
        Some(plugin) => {
            execute_binding_plugin_streaming(
                plugin_kind,
                profile,
                request,
                plugin.as_ref(),
                delivery_bus,
                progress_token,
                plugin_registry,
            )
            .await
        }
        None => ToolCallResult {
            content: vec![ToolContent::text(format!(
                "LLM streaming execution for '{}' failed: {} binding plugin not registered",
                request.tool_name, plugin_kind
            ))],
            structured_content: None,
            is_error: true,
            meta: None,
        },
    }
}

// --- Pipeline execution engine ---

#[derive(Debug, Clone)]
struct ToolExecutionContext {
    /// Present only when the dispatched route's executor reads it (see
    /// [`BackendInvocationRoute::needs_runtime_snapshot`]); `None` on
    /// every other tool call so the allocation-heavy snapshot build is
    /// skipped on the hot path.
    runtime_snapshot: Option<RuntimeSnapshot>,
}

#[derive(Debug, Clone)]
enum ToolExecutionTarget {
    Internal(InternalToolAdapter),
    Adapter(AdapterToolRoute),
    /// Federated tool — handled inline in `dispatch_tool_call` by the
    /// `FederationEngine`; never reaches the adapter executor.
    Federated {
        source: String,
        upstream_name: String,
    },
}

impl ToolExecutionTarget {
    fn from_route(route: BackendInvocationRoute) -> Self {
        match route {
            BackendInvocationRoute::RuntimeSnapshot => {
                Self::Internal(InternalToolAdapter::RuntimeSnapshot)
            }
            BackendInvocationRoute::RequestEcho => Self::Adapter(AdapterToolRoute::RequestEcho),
            BackendInvocationRoute::CommandProbe { profile } => {
                Self::Adapter(AdapterToolRoute::CommandProbe { profile })
            }
            // `require_json_stdout` is recovered from the command
            // plugin's registered profile, not threaded through the
            // adapter route.
            BackendInvocationRoute::CommandJsonCall { profile, .. } => {
                Self::Adapter(AdapterToolRoute::CommandJsonCall { profile })
            }
            BackendInvocationRoute::NetworkProbe { profile } => {
                Self::Adapter(AdapterToolRoute::NetworkProbe { profile })
            }
            BackendInvocationRoute::NetworkJsonCall { profile } => {
                Self::Adapter(AdapterToolRoute::NetworkJsonCall { profile })
            }
            BackendInvocationRoute::NetworkQueryCall { profile } => {
                Self::Adapter(AdapterToolRoute::NetworkQueryCall { profile })
            }
            BackendInvocationRoute::NatsRequest { profile } => {
                Self::Adapter(AdapterToolRoute::NatsRequest { profile })
            }
            BackendInvocationRoute::GraphqlCall { profile } => {
                Self::Adapter(AdapterToolRoute::GraphqlCall { profile })
            }
            BackendInvocationRoute::KafkaRequest { profile } => {
                Self::Adapter(AdapterToolRoute::KafkaRequest { profile })
            }
            BackendInvocationRoute::MockResponse { profile } => {
                Self::Adapter(AdapterToolRoute::MockResponse { profile })
            }
            BackendInvocationRoute::Pipeline { profile } => {
                Self::Adapter(AdapterToolRoute::Pipeline { profile })
            }
            BackendInvocationRoute::SqlRequest { profile } => {
                Self::Adapter(AdapterToolRoute::SqlRequest { profile })
            }
            BackendInvocationRoute::OpenapiCall { profile } => {
                Self::Adapter(AdapterToolRoute::OpenapiCall { profile })
            }
            BackendInvocationRoute::LlmRequest { profile, kind } => {
                Self::Adapter(AdapterToolRoute::LlmRequest { profile, kind })
            }
            BackendInvocationRoute::Federated {
                source,
                upstream_name,
            } => Self::Federated {
                source,
                upstream_name,
            },
            BackendInvocationRoute::EnvelopePlugin { kind, profile } => {
                Self::Adapter(AdapterToolRoute::EnvelopePlugin { kind, profile })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum InternalToolAdapter {
    RuntimeSnapshot,
}

impl InternalToolAdapter {
    fn execute(
        self,
        request: &BackendInvocationRequest,
        execution_context: &ToolExecutionContext,
    ) -> ToolCallResult {
        match self {
            Self::RuntimeSnapshot => {
                let Some(snapshot) = execution_context.runtime_snapshot.as_ref() else {
                    return ToolCallResult {
                        content: vec![ToolContent::text(format!(
                            "runtime snapshot unavailable for tool {}",
                            request.tool_name
                        ))],
                        structured_content: None,
                        is_error: true,
                        meta: None,
                    };
                };
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Returned current MCPG runtime snapshot for tool {}.",
                        request.tool_name
                    ))],
                    structured_content: Some(
                        serde_json::to_value(snapshot).expect("runtime snapshot serialized"),
                    ),
                    is_error: false,
                    meta: None,
                }
            }
        }
    }
}

trait ToolExecutionAdapter: Send + Sync {
    fn execute(
        &self,
        route: AdapterToolRoute,
        request: &BackendInvocationRequest,
        execution_context: &ToolExecutionContext,
    ) -> ToolCallResult;
}

#[derive(Debug, Clone)]
enum AdapterToolRoute {
    RequestEcho,
    CommandProbe {
        profile: String,
    },
    CommandJsonCall {
        profile: String,
    },
    NetworkProbe {
        profile: String,
    },
    NetworkJsonCall {
        profile: String,
    },
    NetworkQueryCall {
        profile: String,
    },
    NatsRequest {
        profile: String,
    },
    GraphqlCall {
        profile: String,
    },
    KafkaRequest {
        profile: String,
    },
    MockResponse {
        profile: String,
    },
    Pipeline {
        profile: String,
    },
    /// SQL binding — dispatches through the SQL plugin registered
    /// at boot. Same shape as `NatsRequest` / `KafkaRequest`.
    SqlRequest {
        profile: String,
    },
    /// OpenAPI binding — dispatches through the openapi plugin via
    /// `execute_envelope_plugin`. Same shape as `GrpcCall` / `GraphqlCall`.
    OpenapiCall {
        profile: String,
    },
    /// Per-provider LLM binding — dispatches through one of the
    /// LLM plugins registered at boot. `kind` picks the plugin.
    LlmRequest {
        profile: String,
        kind: crate::backends::LlmKind,
    },
    /// Generic backend dispatch by `kind` string. Dispatches through the
    /// plugin registered under `kind` via `execute_envelope_plugin(kind,
    /// profile, …)` — the single path every kind will eventually take.
    /// Nothing routes here yet; it runs alongside the per-vendor `*Call`
    /// adapter variants until the migration flips kinds onto it.
    EnvelopePlugin {
        kind: String,
        profile: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum HttpCallMode {
    JsonBody,
    QueryString,
}

impl HttpCallMode {
    fn request_kind(self) -> &'static str {
        match self {
            Self::JsonBody => "json_body",
            Self::QueryString => "query_string",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::JsonBody => "HTTP JSON call",
            Self::QueryString => "HTTP query call",
        }
    }

    fn retry_safety_context(self) -> RetrySafetyContext {
        match self {
            Self::JsonBody => RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
            Self::QueryString => RetrySafetyContext::ReadOnlyProbe,
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedHttpCallRequest {
    arguments: Value,
    request_body: Option<Value>,
    request_query: Option<String>,
}

#[derive(Debug, Clone)]
struct DebugToolExecutor {
    command_profiles: std::collections::BTreeMap<String, CommandToolRuntimeConfig>,
    network_profiles: std::collections::BTreeMap<String, NetworkToolRuntimeConfig>,
}

impl DebugToolExecutor {
    fn new(
        command_profiles: std::collections::BTreeMap<String, CommandToolRuntimeConfig>,
        network_profiles: std::collections::BTreeMap<String, NetworkToolRuntimeConfig>,
    ) -> Self {
        Self {
            command_profiles,
            network_profiles,
        }
    }

    fn execute_command_probe(
        &self,
        request: &BackendInvocationRequest,
        profile_name: &str,
    ) -> ToolCallResult {
        let Some(command_tool_static) = self.command_profiles.get(profile_name) else {
            return missing_profile_result(request, profile_name, "command");
        };
        if let Some(cancelled) = early_cancel_check(request, profile_name, "command_probe") {
            return cancelled;
        }

        // Resolve dynamic expressions in args
        let command_tool = match resolve_command_config(command_tool_static, &request.expr_ctx) {
            Ok(resolved) => resolved,
            Err(err) => {
                return ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "expression resolution failed for tool '{}': {}",
                        request.tool_name, err
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                };
            }
        };
        let command_tool = &command_tool;

        match execute_command_with_limits(command_tool, request.context.trace_context.as_ref()) {
            Ok(result) => {
                let is_error = result.timed_out || !result.success || result.read_error.is_some();
                log_command_probe_outcome(request, profile_name, command_tool, &result, is_error);
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Executed configured debug command for tool {}.",
                        request.tool_name
                    ))],
                    structured_content: Some(serde_json::json!({
                        "toolName": request.tool_name,
                        "profile": profile_name,
                        "command": command_tool.command,
                        "args": command_tool.args,
                        "timeoutMs": command_tool.timeout_ms,
                        "maxOutputBytes": command_tool.max_output_bytes,
                        "durationMs": result.duration_ms,
                        "exitCode": result.exit_code,
                        "success": result.success,
                        "timedOut": result.timed_out,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "stdoutTruncated": result.stdout_truncated,
                        "stderrTruncated": result.stderr_truncated,
                        "readError": result.read_error,
                    })),
                    is_error,
                    meta: None,
                }
            }
            Err(error) => {
                warn!(
                    request_id = %request.context.request_id,
                    tool_name = %request.tool_name,
                    backend_kind = backend_kind(&request.tool_name),
                    profile = %profile_name,
                    command = %command_tool.command,
                    arg_count = command_tool.args.len(),
                    timeout_ms = command_tool.timeout_ms,
                    max_output_bytes = command_tool.max_output_bytes,
                    error = %error,
                    "debug command probe execution failed"
                );
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Failed to execute configured debug command for tool {}.",
                        request.tool_name
                    ))],
                    structured_content: Some(serde_json::json!({
                        "toolName": request.tool_name,
                        "profile": profile_name,
                        "command": command_tool.command,
                        "args": command_tool.args,
                        "timeoutMs": command_tool.timeout_ms,
                        "maxOutputBytes": command_tool.max_output_bytes,
                        "error": error.to_string(),
                    })),
                    is_error: true,
                    meta: None,
                }
            }
        }
    }

    fn execute_network_probe(
        &self,
        request: &BackendInvocationRequest,
        profile_name: &str,
    ) -> ToolCallResult {
        let Some(network_tool) = self.network_profiles.get(profile_name) else {
            return missing_profile_result(request, profile_name, "network");
        };
        if let Some(cancelled) = early_cancel_check(request, profile_name, "http_probe") {
            return cancelled;
        }

        match execute_http_probe(network_tool, request.cancellation_token.as_ref()) {
            Ok(response) => {
                let downstream_errors = validate_expected_status_codes(
                    &network_tool.expected_status_codes,
                    response.status_code,
                    response.retry_after_ms,
                    RetrySafetyContext::ReadOnlyProbe,
                )
                .into_iter()
                .collect::<Vec<_>>();
                let primary_downstream_error = downstream_errors.first().cloned();
                let is_error = primary_downstream_error.is_some();
                log_network_probe_outcome(
                    request,
                    profile_name,
                    network_tool,
                    &response,
                    primary_downstream_error.as_ref(),
                );
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Executed configured debug network probe for tool {}.",
                        request.tool_name
                    ))],
                    structured_content: Some(serde_json::json!({
                        "toolName": request.tool_name,
                        "profile": profile_name,
                        "url": network_tool.url,
                        "timeoutMs": network_tool.timeout_ms,
                        "maxResponseBytes": network_tool.max_response_bytes,
                        "expectedStatusCodes": network_tool.expected_status_codes,
                        "requestHeaders": network_tool.headers,
                        "durationMs": response.duration_ms,
                        "statusCode": response.status_code,
                        "responseContentType": response.content_type,
                        "body": response.body,
                        "bodyTruncated": response.body_truncated,
                        "downstreamError": primary_downstream_error,
                        "downstreamErrors": downstream_errors,
                    })),
                    is_error,
                    meta: None,
                }
            }
            Err(error) => {
                let downstream_error =
                    transport_downstream_error(&error, RetrySafetyContext::ReadOnlyProbe);
                warn!(
                    request_id = %request.context.request_id,
                    tool_name = %request.tool_name,
                    backend_kind = backend_kind(&request.tool_name),
                    profile = %profile_name,
                    url = %network_tool.url,
                    timeout_ms = network_tool.timeout_ms,
                    max_response_bytes = network_tool.max_response_bytes,
                    downstream_error_kind = %downstream_error.kind,
                    retryable = downstream_error.retryable,
                    error = %error,
                    "debug network probe execution failed"
                );
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Failed to execute configured debug network probe for tool {}.",
                        request.tool_name
                    ))],
                    structured_content: Some(serde_json::json!({
                        "toolName": request.tool_name,
                        "profile": profile_name,
                        "url": network_tool.url,
                        "timeoutMs": network_tool.timeout_ms,
                        "maxResponseBytes": network_tool.max_response_bytes,
                        "expectedStatusCodes": network_tool.expected_status_codes,
                        "requestHeaders": network_tool.headers,
                        "downstreamError": downstream_error.clone(),
                        "downstreamErrors": vec![downstream_error],
                        "error": error,
                    })),
                    is_error: true,
                    meta: None,
                }
            }
        }
    }

    fn execute_network_json_call(
        &self,
        request: &BackendInvocationRequest,
        profile_name: &str,
    ) -> ToolCallResult {
        self.execute_http_call(request, profile_name, HttpCallMode::JsonBody)
    }

    fn execute_network_query_call(
        &self,
        request: &BackendInvocationRequest,
        profile_name: &str,
    ) -> ToolCallResult {
        self.execute_http_call(request, profile_name, HttpCallMode::QueryString)
    }

    fn execute_http_call(
        &self,
        request: &BackendInvocationRequest,
        profile_name: &str,
        call_mode: HttpCallMode,
    ) -> ToolCallResult {
        let Some(network_tool_static) = self.network_profiles.get(profile_name) else {
            return missing_profile_result(request, profile_name, "network");
        };
        let adapter_kind = match call_mode {
            HttpCallMode::JsonBody => "http_json_call",
            HttpCallMode::QueryString => "http_query_call",
        };
        if let Some(cancelled) = early_cancel_check(request, profile_name, adapter_kind) {
            return cancelled;
        }

        // Resolve dynamic expressions in config fields
        let network_tool = match resolve_network_config(network_tool_static, &request.expr_ctx) {
            Ok(resolved) => resolved,
            Err(err) => {
                return ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "expression resolution failed for tool '{}': {}",
                        request.tool_name, err
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                };
            }
        };
        let network_tool = &network_tool;

        let request_arguments = request
            .arguments
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let prepared_request = match prepare_http_call_request(call_mode, request_arguments.clone())
        {
            Ok(prepared_request) => prepared_request,
            Err(error) => {
                return ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Failed to shape configured {} request for tool {}.",
                        call_mode.display_name(),
                        request.tool_name
                    ))],
                    structured_content: Some(build_http_call_structured_content(
                        request,
                        profile_name,
                        network_tool,
                        call_mode,
                        &request_arguments,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        &[],
                        Some(error.as_str()),
                    )),
                    is_error: true,
                    meta: None,
                };
            }
        };

        match execute_http_call_request(
            call_mode,
            network_tool,
            &prepared_request,
            request.context.trace_context.as_ref(),
        ) {
            Ok(response) => {
                let mut downstream_errors = validate_expected_status_codes(
                    &network_tool.expected_status_codes,
                    response.status_code,
                    response.retry_after_ms,
                    call_mode.retry_safety_context(),
                )
                .into_iter()
                .collect::<Vec<_>>();
                let (response_json, response_json_parse_error, json_validation_error) =
                    parse_and_validate_json_response(&response, network_tool.require_json_response);
                if let Some(error) = json_validation_error {
                    downstream_errors.push(error);
                }
                let primary_downstream_error = downstream_errors.first().cloned();
                let is_error = primary_downstream_error.is_some();
                log_http_call_outcome(
                    request,
                    profile_name,
                    network_tool,
                    call_mode,
                    &response,
                    prepared_request.request_query.as_deref(),
                    primary_downstream_error.as_ref(),
                );
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Executed configured {} for tool {}.",
                        call_mode.display_name(),
                        request.tool_name
                    ))],
                    structured_content: Some(build_http_call_structured_content(
                        request,
                        profile_name,
                        network_tool,
                        call_mode,
                        &prepared_request.arguments,
                        prepared_request.request_body.as_ref(),
                        prepared_request.request_query.as_deref(),
                        Some(&response),
                        response_json.as_ref(),
                        response_json_parse_error.as_deref(),
                        primary_downstream_error.as_ref(),
                        &downstream_errors,
                        None,
                    )),
                    is_error,
                    meta: None,
                }
            }
            Err(error) => {
                let downstream_error =
                    transport_downstream_error(&error, call_mode.retry_safety_context());
                warn!(
                    request_id = %request.context.request_id,
                    tool_name = %request.tool_name,
                    backend_kind = backend_kind(&request.tool_name),
                    profile = %profile_name,
                    url = %network_tool.url,
                    timeout_ms = network_tool.timeout_ms,
                    max_response_bytes = network_tool.max_response_bytes,
                    request_kind = call_mode.request_kind(),
                    downstream_error_kind = %downstream_error.kind,
                    retryable = downstream_error.retryable,
                    error = %error,
                    "HTTP call execution failed"
                );
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Failed to execute configured {} for tool {}.",
                        call_mode.display_name(),
                        request.tool_name
                    ))],
                    structured_content: Some(build_http_call_structured_content(
                        request,
                        profile_name,
                        network_tool,
                        call_mode,
                        &prepared_request.arguments,
                        prepared_request.request_body.as_ref(),
                        prepared_request.request_query.as_deref(),
                        None,
                        None,
                        None,
                        Some(&downstream_error),
                        std::slice::from_ref(&downstream_error),
                        Some(error.as_str()),
                    )),
                    is_error: true,
                    meta: None,
                }
            }
        }
    }
}

impl ToolExecutionAdapter for DebugToolExecutor {
    fn execute(
        &self,
        route: AdapterToolRoute,
        request: &BackendInvocationRequest,
        execution_context: &ToolExecutionContext,
    ) -> ToolCallResult {
        match route {
            AdapterToolRoute::RequestEcho => {
                let structured = serde_json::json!({
                    "toolName": request.tool_name,
                    "arguments": request.arguments.clone().unwrap_or(serde_json::json!({})),
                    "request": {
                        "requestId": request.context.request_id.as_str(),
                        "upstreamRequestId": request.context.upstream_request_id.clone(),
                        "sessionId": request.context.session_id.clone(),
                        "identityKind": request.context.identity.label(),
                        "trustLevel": match request.context.identity.trust_level() {
                            crate::runtime::RequestTrustLevel::Unauthenticated => "unauthenticated",
                            crate::runtime::RequestTrustLevel::HeaderAsserted => "header_asserted",
                            crate::runtime::RequestTrustLevel::Verified => "verified",
                        },
                        "principalId": request.context.identity.principal_id(),
                        "transport": match request.context.transport {
                            crate::runtime::TransportKind::Http => "http",
                            crate::runtime::TransportKind::Stdio => "stdio",
                        },
                    },
                    "runtime": {
                        "service": execution_context
                            .runtime_snapshot
                            .as_ref()
                            .map(|s| s.service.as_str())
                            .unwrap_or(""),
                        "version": execution_context
                            .runtime_snapshot
                            .as_ref()
                            .map(|s| s.version.as_str())
                            .unwrap_or(""),
                    }
                });

                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Echoed normalized execution request for tool {} through the adapter-facing seam.",
                        request.tool_name
                    ))],
                    structured_content: Some(structured),
                    is_error: false,
                    meta: None,
                }
            }
            AdapterToolRoute::CommandProbe { profile } => {
                self.execute_command_probe(request, &profile)
            }
            AdapterToolRoute::CommandJsonCall { profile } => {
                // Command bindings are dispatched via the
                // `dev.mcpg.backend.command` plugin (`execute_envelope_plugin`)
                // in the main + pipeline dispatch paths, before reaching the
                // adapter executor — this arm is unreachable in practice.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "command request for profile '{}' is dispatched via the dev.mcpg.backend.command plugin",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::NetworkProbe { profile } => {
                self.execute_network_probe(request, &profile)
            }
            AdapterToolRoute::NetworkJsonCall { profile } => {
                self.execute_network_json_call(request, &profile)
            }
            AdapterToolRoute::NetworkQueryCall { profile } => {
                self.execute_network_query_call(request, &profile)
            }
            AdapterToolRoute::NatsRequest { profile } => {
                // NATS execution is dispatched via NatsConnectionManager (async path),
                // not through the synchronous adapter. Reaching here means the
                // async dispatch path was not used.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "NATS request for profile '{}' requires async execution via NatsConnectionManager",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::GraphqlCall { profile } => {
                // GraphQL is dispatched via the `dev.mcpg.backend.graphql`
                // plugin (`execute_envelope_plugin`) in the main +
                // pipeline dispatch paths, before reaching the adapter
                // executor — this arm is unreachable in practice.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "GraphQL request for profile '{}' is dispatched via the dev.mcpg.backend.graphql plugin",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::OpenapiCall { profile } => {
                // OpenAPI is dispatched via the `dev.mcpg.backend.openapi`
                // plugin (`execute_envelope_plugin`) in the main + pipeline
                // dispatch paths, before reaching the adapter executor —
                // this arm is unreachable in practice.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "OpenAPI request for profile '{}' is dispatched via the dev.mcpg.backend.openapi plugin",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::KafkaRequest { profile } => {
                // Kafka execution is dispatched via KafkaConnectionManager (async path).
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Kafka request for profile '{}' requires async execution via KafkaConnectionManager",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::MockResponse { profile } => {
                // Mock bindings are dispatched via the
                // `dev.mcpg.backend.mock` plugin (`execute_envelope_plugin`)
                // in the main dispatch path, before reaching the adapter
                // executor — this arm is unreachable in practice. (Mock
                // *pipeline steps* still run inline via
                // `execute_pipeline_mock_step`.)
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "mock response for profile '{}' is dispatched via the dev.mcpg.backend.mock plugin",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::Pipeline { profile } => {
                // Pipeline execution is handled by execute_pipeline in dispatch_tool_call
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "Pipeline '{}' requires execution via the pipeline engine",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::SqlRequest { profile } => {
                // SQL execution dispatches through the SqlBackendPlugin
                // on the async path (mirrors NATS / Kafka). The sync
                // adapter surface returns a placeholder so the
                // exhaustive match compiles.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "SQL request for profile '{}' requires async execution via the SQL plugin",
                        profile
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::LlmRequest { profile, kind } => {
                // LLM execution dispatches through the per-provider
                // BackendPlugin on the async path. Same reason as SQL:
                // the sync adapter surface returns a placeholder.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "LLM request for profile '{}' (kind {}) requires async execution via the binding plugin",
                        profile,
                        kind.plugin_kind()
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
            AdapterToolRoute::EnvelopePlugin { kind, profile } => {
                // Generic backend dispatch resolves through
                // `execute_envelope_plugin` on the async path (handled in
                // `dispatch_tool_call`); the sync adapter surface returns a
                // placeholder so the exhaustive match compiles.
                ToolCallResult {
                    content: vec![ToolContent::text(format!(
                        "{kind} request for profile '{profile}' requires async execution via the binding plugin"
                    ))],
                    structured_content: None,
                    is_error: true,
                    meta: None,
                }
            }
        }
    }
}

/// Cross-family shared envelope for binding result semantics.
///
/// Both HTTP and command binding families produce structured
/// content with these common top-level fields. Family-specific content
/// (execution config, request shaping, response details, error objects)
/// is plugged in through `Value` sections so the envelope stays neutral
/// while each family keeps its own result semantics.
struct BackendResultEnvelope {
    tool_name: String,
    profile: String,
    request_kind: String,
    request: Value,
    response: Option<Value>,
    primary_error_key: String,
    primary_error: Option<Value>,
    errors_key: String,
    errors: Value,
    error: Option<String>,
    family_fields: Value,
}

impl BackendResultEnvelope {
    fn into_value(self) -> Value {
        let mut base = serde_json::json!({
            "toolName": self.tool_name,
            "profile": self.profile,
            "requestKind": self.request_kind,
            "request": self.request,
            "response": self.response,
            "error": self.error,
        });
        let base_map = base.as_object_mut().expect("base is object");
        base_map.insert(self.primary_error_key, self.primary_error.into());
        base_map.insert(self.errors_key, self.errors);

        if let Value::Object(family) = self.family_fields {
            for (key, value) in family {
                base_map.insert(key, value);
            }
        }

        base
    }
}

fn missing_profile_result(
    request: &BackendInvocationRequest,
    profile_name: &str,
    profile_kind: &str,
) -> ToolCallResult {
    warn!(
        request_id = %request.context.request_id,
        tool_name = %request.tool_name,
        backend_kind = backend_kind(&request.tool_name),
        profile = %profile_name,
        profile_kind = %profile_kind,
        "debug probe execution profile missing"
    );
    ToolCallResult {
        content: vec![ToolContent::text(format!(
            "Missing configured {} execution profile '{}' for tool {}.",
            profile_kind, profile_name, request.tool_name
        ))],
        structured_content: Some(serde_json::json!({
            "toolName": request.tool_name,
            "profile": profile_name,
            "profileKind": profile_kind,
            "error": "missing_profile",
        })),
        is_error: true,
        meta: None,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownstreamHttpError {
    kind: String,
    code: String,
    message: String,
    retryable: bool,
    retry_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
    idempotency_hint: String,
    caller_retry_decision: String,
    retry_safety: String,
    backoff_strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum_backoff_ms: Option<u64>,
    suggested_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    details: Value,
}

fn log_command_probe_outcome(
    request: &BackendInvocationRequest,
    profile_name: &str,
    command_tool: &CommandToolRuntimeConfig,
    result: &CommandExecutionResult,
    is_error: bool,
) {
    let read_error_present = result.read_error.is_some();
    if is_error {
        warn!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            command = %command_tool.command,
            arg_count = command_tool.args.len(),
            timeout_ms = command_tool.timeout_ms,
            max_output_bytes = command_tool.max_output_bytes,
            duration_ms = result.duration_ms,
            exit_code = result.exit_code,
            success = result.success,
            timed_out = result.timed_out,
            stdout_truncated = result.stdout_truncated,
            stderr_truncated = result.stderr_truncated,
            read_error_present,
            "debug command probe completed with warning"
        );
    } else {
        info!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            command = %command_tool.command,
            arg_count = command_tool.args.len(),
            timeout_ms = command_tool.timeout_ms,
            max_output_bytes = command_tool.max_output_bytes,
            duration_ms = result.duration_ms,
            exit_code = result.exit_code,
            stdout_truncated = result.stdout_truncated,
            stderr_truncated = result.stderr_truncated,
            "debug command probe completed"
        );
    }
}

fn log_network_probe_outcome(
    request: &BackendInvocationRequest,
    profile_name: &str,
    network_tool: &NetworkToolRuntimeConfig,
    response: &NetworkProbeResponse,
    downstream_error: Option<&DownstreamHttpError>,
) {
    if let Some(downstream_error) = downstream_error {
        warn!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            url = %network_tool.url,
            timeout_ms = network_tool.timeout_ms,
            max_response_bytes = network_tool.max_response_bytes,
            duration_ms = response.duration_ms,
            status_code = response.status_code,
            body_truncated = response.body_truncated,
            downstream_error_kind = %downstream_error.kind,
            downstream_error_code = %downstream_error.code,
            retryable = downstream_error.retryable,
            retry_class = %downstream_error.retry_class,
            retry_after_ms = downstream_error.retry_after_ms,
            idempotency_hint = %downstream_error.idempotency_hint,
            caller_retry_decision = %downstream_error.caller_retry_decision,
            suggested_action = %downstream_error.suggested_action,
            "debug network probe completed with warning"
        );
    } else {
        info!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            url = %network_tool.url,
            timeout_ms = network_tool.timeout_ms,
            max_response_bytes = network_tool.max_response_bytes,
            duration_ms = response.duration_ms,
            status_code = response.status_code,
            body_truncated = response.body_truncated,
            "debug network probe completed"
        );
    }
}

fn log_http_call_outcome(
    request: &BackendInvocationRequest,
    profile_name: &str,
    network_tool: &NetworkToolRuntimeConfig,
    call_mode: HttpCallMode,
    response: &NetworkProbeResponse,
    request_query: Option<&str>,
    downstream_error: Option<&DownstreamHttpError>,
) {
    if let Some(downstream_error) = downstream_error {
        warn!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            url = %network_tool.url,
            request_kind = call_mode.request_kind(),
            timeout_ms = network_tool.timeout_ms,
            max_response_bytes = network_tool.max_response_bytes,
            duration_ms = response.duration_ms,
            status_code = response.status_code,
            body_truncated = response.body_truncated,
            has_arguments = request.arguments.is_some(),
            request_query = request_query.unwrap_or(""),
            downstream_error_kind = %downstream_error.kind,
            downstream_error_code = %downstream_error.code,
            retryable = downstream_error.retryable,
            retry_class = %downstream_error.retry_class,
            retry_after_ms = downstream_error.retry_after_ms,
            idempotency_hint = %downstream_error.idempotency_hint,
            caller_retry_decision = %downstream_error.caller_retry_decision,
            suggested_action = %downstream_error.suggested_action,
            "HTTP call completed with warning"
        );
    } else {
        info!(
            request_id = %request.context.request_id,
            tool_name = %request.tool_name,
            backend_kind = backend_kind(&request.tool_name),
            profile = %profile_name,
            url = %network_tool.url,
            request_kind = call_mode.request_kind(),
            timeout_ms = network_tool.timeout_ms,
            max_response_bytes = network_tool.max_response_bytes,
            duration_ms = response.duration_ms,
            status_code = response.status_code,
            body_truncated = response.body_truncated,
            has_arguments = request.arguments.is_some(),
            request_query = request_query.unwrap_or(""),
            "HTTP call completed"
        );
    }
}

fn validate_expected_status_codes(
    expected_status_codes: &[u16],
    actual_status_code: u16,
    retry_after_ms: Option<u64>,
    retry_safety_context: RetrySafetyContext,
) -> Option<DownstreamHttpError> {
    if expected_status_codes.contains(&actual_status_code) {
        None
    } else {
        let retryable = actual_status_code == 429 || actual_status_code >= 500;
        let retry_class = if retryable {
            if retry_after_ms.is_some() {
                "after_delay"
            } else {
                "with_backoff"
            }
        } else {
            "do_not_retry"
        };
        let suggested_action = if retryable {
            if retry_after_ms.is_some() {
                "retry_after_indicated_delay"
            } else {
                "retry_with_backoff_or_check_downstream_capacity"
            }
        } else {
            "inspect_downstream_http_contract"
        };
        Some(with_retry_guidance(
            DownstreamHttpError {
                kind: "unexpected_status_code".to_owned(),
                code: "mcpg.downstream_http.unexpected_status_code".to_owned(),
                message: format!(
                    "Downstream response status {} did not match the configured expected status codes.",
                    actual_status_code
                ),
                retryable,
                retry_class: retry_class.to_owned(),
                retry_after_ms,
                idempotency_hint: "pending_idempotency_evaluation".to_owned(),
                caller_retry_decision: "pending_caller_retry_decision".to_owned(),
                retry_safety: "pending_retry_safety_evaluation".to_owned(),
                backoff_strategy: "pending_backoff_strategy_evaluation".to_owned(),
                minimum_backoff_ms: None,
                suggested_action: suggested_action.to_owned(),
                status_code: Some(actual_status_code),
                details: serde_json::json!({
                    "actualStatusCode": actual_status_code,
                    "expectedStatusCodes": expected_status_codes,
                    "retryAfterMs": retry_after_ms,
                }),
            },
            retry_safety_context,
        ))
    }
}

fn parse_and_validate_json_response(
    response: &NetworkProbeResponse,
    require_json_response: bool,
) -> (Option<Value>, Option<String>, Option<DownstreamHttpError>) {
    let content_type_is_json = response
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type);

    if !content_type_is_json {
        if require_json_response {
            return (
                None,
                None,
                Some(json_content_type_downstream_error(
                    response.content_type.as_deref(),
                )),
            );
        }
        return (None, None, None);
    }

    match serde_json::from_str::<Value>(&response.body) {
        Ok(value) => (Some(value), None, None),
        Err(error) => {
            let parse_error = error.to_string();
            let validation_error = if require_json_response {
                Some(json_body_downstream_error(&parse_error))
            } else {
                None
            };
            (None, Some(parse_error), validation_error)
        }
    }
}

fn transport_downstream_error(
    error: &str,
    retry_safety_context: RetrySafetyContext,
) -> DownstreamHttpError {
    with_retry_guidance(
        DownstreamHttpError {
            kind: "transport_error".to_owned(),
            code: "mcpg.downstream_http.transport_error".to_owned(),
            message: "Downstream HTTP execution failed before a valid response was received."
                .to_owned(),
            retryable: true,
            retry_class: "with_backoff".to_owned(),
            retry_after_ms: None,
            idempotency_hint: "pending_idempotency_evaluation".to_owned(),
            caller_retry_decision: "pending_caller_retry_decision".to_owned(),
            retry_safety: "safe_for_automatic_retry".to_owned(),
            backoff_strategy: "exponential_backoff".to_owned(),
            minimum_backoff_ms: Some(DEFAULT_BACKOFF_BASE_MS),
            suggested_action: "check_downstream_connectivity_and_retry".to_owned(),
            status_code: None,
            details: serde_json::json!({
                "error": error,
            }),
        },
        retry_safety_context,
    )
}

fn json_content_type_downstream_error(content_type: Option<&str>) -> DownstreamHttpError {
    DownstreamHttpError {
        kind: "invalid_content_type".to_owned(),
        code: "mcpg.downstream_http.invalid_content_type".to_owned(),
        message: "Downstream HTTP JSON call required a JSON response content type, but the response was not JSON.".to_owned(),
        retryable: false,
        retry_class: "do_not_retry".to_owned(),
        retry_after_ms: None,
        idempotency_hint: "potentially_non_idempotent".to_owned(),
        caller_retry_decision: "do_not_retry".to_owned(),
        retry_safety: "do_not_retry".to_owned(),
        backoff_strategy: "no_retry".to_owned(),
        minimum_backoff_ms: None,
        suggested_action: "inspect_downstream_response_content_type".to_owned(),
        status_code: None,
        details: serde_json::json!({
            "responseContentType": content_type,
        }),
    }
}

fn json_body_downstream_error(parse_error: &str) -> DownstreamHttpError {
    DownstreamHttpError {
        kind: "invalid_json_body".to_owned(),
        code: "mcpg.downstream_http.invalid_json_body".to_owned(),
        message: "Downstream HTTP JSON call returned a JSON content type, but the body was not valid JSON.".to_owned(),
        retryable: false,
        retry_class: "do_not_retry".to_owned(),
        retry_after_ms: None,
        idempotency_hint: "potentially_non_idempotent".to_owned(),
        caller_retry_decision: "do_not_retry".to_owned(),
        retry_safety: "do_not_retry".to_owned(),
        backoff_strategy: "no_retry".to_owned(),
        minimum_backoff_ms: None,
        suggested_action: "inspect_downstream_json_payload".to_owned(),
        status_code: None,
        details: serde_json::json!({
            "parseError": parse_error,
        }),
    }
}

/// Coerce `max_tokens` for outbound `sampling/createMessage` requests.
/// MCP marks `maxTokens` as REQUIRED on the wire, but operators may
/// not care about the value and omit it (defaulting to 0). The sentinel
/// `0` is replaced with `DEFAULT_SAMPLING_MAX_TOKENS` (4096) so the
/// outbound envelope is always spec-shaped without forcing operators
/// to pick a number.
pub(crate) fn coerce_sampling_max_tokens(configured: u64) -> u64 {
    if configured == 0 {
        crate::protocol::DEFAULT_SAMPLING_MAX_TOKENS
    } else {
        configured
    }
}

/// Extract a human-readable error string from a failed
/// `ToolCallResult`. Pipelines surface failures as `is_error: true`
/// with a `Text` content variant carrying the reason; this helper
/// grabs the first text fragment so the audit `details.error_message`
/// field has the operator-facing description.
pub(crate) fn extract_error_message(result: &ToolCallResult) -> Option<String> {
    if !result.is_error {
        return None;
    }
    result.content.iter().find_map(|c| match c {
        ToolContent::Text { text, .. } => Some(text.clone()),
        _ => None,
    })
}

/// Stable correlation hash for the audit-event prompt surface.
/// BLAKE3 of the canonical role+content concatenation —
/// short enough to be cheap on the hot path, collision-resistant
/// enough that audit consumers can join `prompt_hash` across
/// events without storing the prompt plaintext on the audit lane.
pub(crate) fn hash_sampling_messages(messages: &[crate::config::SamplingMessageConfig]) -> String {
    let mut hasher = blake3::Hasher::new();
    for m in messages {
        hasher.update(m.role.as_bytes());
        hasher.update(b"\x1f"); // unit separator — keep delimiter unambiguous
        hasher.update(m.content.as_bytes());
        hasher.update(b"\x1e"); // record separator
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

/// (SEP-1330): elicitation `requestedSchema` is restricted to
/// a flat JSON Schema where every property is a *primitive* type
/// (string, number, integer, boolean, enum, plus null). Nested
/// objects and arrays MUST be rejected so client UIs can render a
/// simple form. Returns `Err(reason)` when the schema violates the
/// restriction; `Ok(())` when absent or compliant.
pub(crate) fn validate_elicitation_requested_schema(schema: Option<&Value>) -> Result<(), String> {
    let Some(schema) = schema else {
        return Ok(());
    };
    let obj = match schema.as_object() {
        Some(o) => o,
        None => return Err("requestedSchema must be a JSON object".to_owned()),
    };
    // Top-level type must be `object` per SEP-1330.
    if let Some(t) = obj.get("type")
        && t != "object"
    {
        return Err(format!(
            "requestedSchema top-level type must be 'object', got {t}"
        ));
    }
    let Some(props) = obj.get("properties").and_then(|v| v.as_object()) else {
        // No properties → nothing to enumerate is acceptable; the form
        // would just be empty, which is degenerate but not invalid.
        return Ok(());
    };
    const PRIMITIVES: &[&str] = &["string", "number", "integer", "boolean", "null"];
    for (name, prop) in props {
        let pobj = match prop.as_object() {
            Some(o) => o,
            None => {
                return Err(format!(
                    "requestedSchema.properties.{name} must be an object schema"
                ));
            }
        };
        // `enum` covers a closed set of primitive choices.
        if pobj.contains_key("enum") {
            continue;
        }
        // SEP-1330 titled enum — `oneOf` of `{const, title}` pairs.
        if pobj.contains_key("oneOf") || pobj.contains_key("anyOf") {
            continue;
        }
        match pobj.get("type") {
            Some(Value::String(s)) if s == "array" => {
                // SEP-1330 multi-select — `items` shape carries the
                // per-element constraint (enum / anyOf-titled). We
                // accept the array wrapper without recursing into
                // `items`: the spec's intent is that operator-authored
                // schemas can declare multi-select form widgets, and
                // the client is responsible for honouring the inner
                // shape. Bracket bounds (`minItems`/`maxItems`) are
                // free-form metadata for the renderer.
                if !pobj.contains_key("items") {
                    return Err(format!(
                        "requestedSchema.properties.{name} is type 'array' but lacks `items`"
                    ));
                }
            }
            Some(Value::String(s)) => {
                if !PRIMITIVES.contains(&s.as_str()) {
                    return Err(format!(
                        "requestedSchema.properties.{name}.type {s:?} \
                         is not a primitive (allowed: {PRIMITIVES:?}, 'array', \
                         or one of 'enum' / 'oneOf' / 'anyOf')"
                    ));
                }
            }
            Some(Value::Array(items)) => {
                // Type unions like ["string", "null"] — every entry MUST
                // be a primitive.
                for t in items {
                    let s = match t.as_str() {
                        Some(s) => s,
                        None => {
                            return Err(format!(
                                "requestedSchema.properties.{name}.type entries must be strings"
                            ));
                        }
                    };
                    if !PRIMITIVES.contains(&s) {
                        return Err(format!(
                            "requestedSchema.properties.{name}.type union \
                             contains non-primitive {s:?}"
                        ));
                    }
                }
            }
            Some(other) => {
                return Err(format!(
                    "requestedSchema.properties.{name}.type must be a string \
                     or array, got {other}"
                ));
            }
            None => {
                return Err(format!(
                    "requestedSchema.properties.{name} must declare a primitive 'type' \
                     (or 'enum' / 'oneOf' / 'anyOf')"
                ));
            }
        }
    }
    Ok(())
}

/// (SEP-2260): mint a server-request id for an elicitation /
/// sampling / roots-list emission, asserting that the originating
/// client request id is non-empty so server-initiated requests are
/// always traceable back to the inbound JSON-RPC envelope. Cheap
/// runtime check + a debug_assert that fails loudly in tests.
fn mint_server_request_id(context: &RequestContext) -> String {
    debug_assert!(
        !context.request_id.as_str().is_empty(),
        "SEP-2260: server-initiated request must have a non-empty originating client request id"
    );
    if context.request_id.as_str().is_empty() {
        metrics::counter!("mcpg_sep2260_orphan_server_request_total").increment(1);
        // operators that prefer fail-loud-in-prod can set
        // `feature_flags.sep2260_panic_on_orphan: true` to upgrade the
        // metric path to a panic. Default stays warn+metric so a
        // single misrouted code path does not take the gateway down
        // in production.
        if crate::runtime::feature_flags::sep2260_panic() {
            panic!(
                "SEP-2260: server-initiated request without an originating \
                 client request id (feature_flags.sep2260_panic_on_orphan: true)"
            );
        }
        tracing::error!("SEP-2260 violation: server-initiated request lacks originating client id");
    }
    format!("srv-req-{}", uuid::Uuid::new_v4())
}

/// Merge a trace-context `_meta` payload into an existing `meta:
/// Option<Value>` slot (SEP-414 draft). Copies in the current
/// trace-context's CHILD `traceparent` (a fresh child span, not the
/// inherited parent) plus tracestate; existing `meta` keys are preserved
/// (lossless merge). Returns `meta` unchanged when `tc` is `None`.
pub(crate) fn inject_trace_into_meta(
    meta: Option<Value>,
    tc: Option<&crate::transports::TraceContext>,
) -> Option<Value> {
    let Some(tc) = tc else {
        return meta;
    };
    let trace_obj = tc.to_meta_object();
    let trace_map = match trace_obj {
        Value::Object(m) => m,
        _ => return meta,
    };
    let mut out = match meta {
        Some(Value::Object(existing)) => existing,
        Some(other) => {
            // Existing meta isn't an object (spec-unusual). Preserve it
            // under a sentinel key so trace injection is still lossless.
            let mut m = serde_json::Map::new();
            m.insert("_original".to_owned(), other);
            m
        }
        None => serde_json::Map::new(),
    };
    for (k, v) in trace_map {
        out.insert(k, v);
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests;
