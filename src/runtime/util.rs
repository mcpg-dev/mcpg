use super::*;

/// RAII guard that removes a task's cancellation token from the registry
/// when the guard drops. Prevents token leaks when the task
/// background future returns early.
pub(crate) struct CancellationCleanup {
    registry: Arc<dashmap::DashMap<String, RegisteredCancellation>>,
    target_id: String,
}

/// Default page size for cursor-based list pagination.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 100;

/// Bindings whose backend kind opts into dynamic `resources/list`
/// enumeration via its manifest [`BackendProfile::dynamic_list`] flag. A
/// kind that does not declare `dynamic_list` is skipped so the gateway does
/// not pay for a per-binding default-empty `list_resources` call on every
/// `resources/list`. The returned kind is the registry-lookup key (LLM
/// bindings normalize from the underscore config form to the dotted plugin
/// kind) so dispatch can resolve the plugin directly.
///
/// `is_dynamic_list` is the per-kind predicate, supplied by the caller from
/// `registry.backend_profile(kind).dynamic_list`, so the gateway holds no
/// hardcoded per-kind list here.
pub(crate) fn extract_dynamic_list_bindings(
    resource_bindings: &[BackendConfig],
    resource_template_bindings: &[BackendConfig],
    is_dynamic_list: impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    resource_bindings
        .iter()
        .chain(resource_template_bindings.iter())
        .filter_map(|b| {
            let lookup_kind = crate::backends::registry_lookup_kind(&b.backend)?;
            is_dynamic_list(&lookup_kind).then(|| (b.name.clone(), lookup_kind))
        })
        .collect()
}

/// Translate per-binding `watch:` YAML into the engine's
/// `WatchConfig` map at bootstrap. Bindings without `uri`
/// are skipped — watch is meaningful on `kind: resource` and
/// `kind: resource_template`, and only concrete URIs show up in
/// subscribe state. Template URIs don't yet support watch
/// (the runtime doesn't synthesize concrete instances).
pub(crate) fn build_watch_configs(
    binding_configs: &[BackendConfig],
) -> HashMap<String, watch_engine::WatchConfig> {
    use crate::config::WatchStrategyConfig;
    let mut out = HashMap::new();
    for binding in binding_configs {
        let Some(watch) = &binding.watch else {
            continue;
        };
        let Some(uri) = binding.uri.as_deref() else {
            continue;
        };
        let strategy = match &watch.strategy {
            WatchStrategyConfig::Poll { interval_ms } => watch_engine::WatchStrategy::Poll {
                interval_ms: *interval_ms,
            },
            WatchStrategyConfig::Webhook { token } => watch_engine::WatchStrategy::Webhook {
                token: token.clone(),
            },
            WatchStrategyConfig::NatsTopic { subject } => watch_engine::WatchStrategy::Plugin {
                kind: "nats_topic".into(),
                spec: serde_json::json!({ "subject": subject }),
            },
            WatchStrategyConfig::KafkaTopic { topic, group_id } => {
                watch_engine::WatchStrategy::Plugin {
                    kind: "kafka_topic".into(),
                    spec: serde_json::json!({
                        "topic": topic,
                        "group_id": group_id,
                    }),
                }
            }
            WatchStrategyConfig::SqlPolling { spec } => {
                // Pass the operator-supplied spec through unchanged —
                // the SQL polling plugin owns the schema and validates
                // at register time. Every replica runs its own watcher
                // (DB load × N) and emits to the cluster delivery bus,
                // which routes per-session to whichever replica holds
                // the SSE stream.
                watch_engine::WatchStrategy::Plugin {
                    kind: "sql_polling".into(),
                    spec: serde_json::Value::Object(spec.clone()),
                }
            }
            WatchStrategyConfig::PostgresListenNotify { url, channel } => {
                watch_engine::WatchStrategy::Plugin {
                    kind: "postgres_listen_notify".into(),
                    spec: serde_json::json!({
                        "url": url,
                        "channel": channel,
                    }),
                }
            }
            WatchStrategyConfig::Plugin { kind, spec } => watch_engine::WatchStrategy::Plugin {
                kind: kind.clone(),
                spec: serde_json::Value::Object(spec.clone()),
            },
        };
        // Compile the CEL filter eagerly so the engine's per-event
        // fast-path skips re-parse. `Expression` is the only mode
        // that needs a program; the others use scope-based logic.
        let compiled_filter_program = match &watch.notification_filter {
            Some(crate::config::NotificationFilterConfig::Expression { expression }) => {
                watch_engine::compile_notification_filter(expression)
            }
            _ => None,
        };
        out.insert(
            uri.to_owned(),
            watch_engine::WatchConfig {
                uri: uri.to_owned(),
                strategy,
                notification_filter: watch.notification_filter.clone(),
                compiled_filter_program,
            },
        );
    }
    out
}

/// Bridge the engine's sync publish closure onto the async
/// [`DeliveryBus::publish`] method. Each emit runs in a spawned
/// task so the watcher loop never blocks on delivery I/O.
pub(crate) fn watch_engine_delivery_publish(
    bus: Arc<dyn crate::runtime::delivery_bus::DeliveryBus>,
) -> Arc<dyn Fn(&str, crate::runtime::pipeline_store::DeliveryMessage) + Send + Sync> {
    Arc::new(move |session_id: &str, msg| {
        let bus = Arc::clone(&bus);
        let sid = session_id.to_owned();
        tokio::spawn(async move {
            if let Err(err) = bus.publish(&sid, msg).await {
                warn!(
                    session_id = %sid,
                    error = %err,
                    "watch: delivery bus publish failed"
                );
            }
        });
    })
}

/// Build the resource fetcher the WatchEngine uses to compare poll
/// snapshots. Closes over the same `CapabilityRegistry` and
/// `ExecutionDispatcher` the request path uses, so a watcher resolves
/// `mcpg://orders/123` (or any operator-defined resource URI) through
/// the same backend pipeline a `resources/read` call would. The
/// returned closure is sync because the WatchEngine poll loop calls
/// it inline; `dispatch_tool_call` itself is sync, and adapters that
/// need async wrap their own `Handle::block_on` internally — same as
/// the request-path call site does.
///
/// `None` is returned when:
/// - The URI doesn't match any registered resource (deleted binding).
/// - The route is `RuntimeOverview` — the synthetic `mcpg://runtime/...`
///   surfaces are not watchable.
/// - The dispatched call comes back as an error (`ToolCallResult.is_error`).
/// - The result decoded but contained no text content (e.g. blob-only
///   resources — poll-mode change detection runs over text hashes).
///
/// On `None` the WatchEngine treats the snapshot as unchanged, which
/// matches the prior no-op behaviour for poll-mode watchers and avoids
/// emitting spurious `resources/updated` notifications when a backend
/// transiently fails.
pub(crate) fn build_watch_resource_fetcher(
    capability_registry: Arc<CapabilityRegistry>,
    execution_dispatcher: Arc<execution::ExecutionDispatcher>,
) -> Arc<dyn Fn(&str) -> Option<String> + Send + Sync> {
    Arc::new(move |uri: &str| -> Option<String> {
        let route = capability_registry.resource_route(uri)?;

        // Build the binding profile + arguments shape that
        // `resource_read_result` uses. Keep the two paths in sync —
        // the watcher needs to see the same content the
        // resources/read response would deliver to a client.
        let (profile, args_value) = match &route {
            ResourceRoute::RuntimeOverview | ResourceRoute::GatewayApp { .. } => {
                // Synthetic gateway-authored surface; nothing to poll.
                return None;
            }
            // A federated resource polls through the same engine
            // dispatch a `resources/read` uses. System-initiated: the
            // machine identity, no caller bearer — per-caller upstream
            // resources are not poll-watchable.
            ResourceRoute::Federated {
                source,
                upstream_uri,
            } => {
                let engine = execution_dispatcher.federation_engine()?;
                let outcome = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(engine.read_resource(
                        source,
                        upstream_uri,
                        crate::runtime::federation::engine::FederationCaller::default(),
                    ))
                });
                let value = match outcome {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(
                            resource_uri = uri, error = %e,
                            "watch resource fetcher: federated read failed; \
                             leaving snapshot unchanged for this poll tick"
                        );
                        return None;
                    }
                };
                let decoded = federated_resource_read_result(value);
                return decoded.contents.into_iter().find_map(|c| match c {
                    crate::protocol::ResourceContents::Text(t) => Some(t.text),
                    crate::protocol::ResourceContents::Blob(_) => None,
                });
            }
            ResourceRoute::Binding { profile } => {
                (profile.clone(), serde_json::json!({ "uri": uri }))
            }
            ResourceRoute::Template {
                profile,
                template_vars,
            } => {
                let mut args = serde_json::Map::new();
                args.insert("uri".to_owned(), serde_json::Value::String(uri.to_owned()));
                let mut vars_map = serde_json::Map::new();
                for (k, v) in template_vars {
                    vars_map.insert(k.clone(), serde_json::Value::String(v.clone()));
                    args.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
                args.insert(
                    "template_vars".to_owned(),
                    serde_json::Value::Object(vars_map),
                );
                (profile.clone(), serde_json::Value::Object(args))
            }
        };

        let binding_route = capability_registry.binding_route(&profile)?;

        let request_context = synthetic_watch_request_context();
        let execution_request = execution::BackendInvocationRequest {
            context: request_context.clone(),
            tool_name: profile.clone(),
            arguments: Some(args_value.clone()),
            expr_ctx: request_context.to_expr_context(&profile, Some(&args_value)),
            progress_token: None,
            request_log_level: None,
            // Synthetic watch context — no client session, so no
            // legacy `logging/setLevel` floor applies.
            legacy_session_log_level: None,
            client_capabilities: crate::protocol::ClientCapabilities::default(),
            cancellation_token: None,
            idempotency_hint: None,
        };
        let result =
            execution_dispatcher.dispatch_tool_call(binding_route, &execution_request, None);

        if result.is_error {
            warn!(
                resource_uri = uri,
                profile = %profile,
                "watch resource fetcher: backend returned error result; \
                 leaving snapshot unchanged for this poll tick"
            );
            return None;
        }

        let decoded = invocation::decode_resource_result(&result, uri).ok()?;
        decoded.contents.into_iter().find_map(|c| match c {
            crate::protocol::ResourceContents::Text(t) => Some(t.text),
            crate::protocol::ResourceContents::Blob(_) => None,
        })
    })
}

/// Build a synthetic [`RequestContext`] for the watch-engine fetcher.
/// The fetcher is system-initiated — there's no real session, identity,
/// or transport — so we pin every field to a fixed anonymous value.
/// The request id changes on every poll so request-id de-dup logic
/// further down the stack doesn't accidentally treat a series of polls
/// as one repeated client call.
pub(crate) fn synthetic_watch_request_context() -> RequestContext {
    RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        RequestIdentity::Anonymous {
            source: "watch-resource-fetcher".to_owned(),
        },
        TransportKind::Http,
    )
}

/// Version-aware extraction of the request progress token from a
/// request's `_meta`.
///
/// - Modern (`2026-07-28`): the token lives under the reverse-DNS
///   key `io.modelcontextprotocol/progressToken` (SEP-2575 moved every
///   per-request hint under the spec namespace). Falls back to the
///   bare `progressToken` so a transitional client that mixes shapes
///   still tokens progress.
/// - Legacy (`2025-11-25`): the bare `_meta.progressToken`.
///
/// Returns the validated token (`String` or `Number`) or an error
/// message when present but the wrong JSON type. Absent ⇒ `Ok(None)`.
pub(crate) fn extract_request_progress_token(
    meta: Option<&Value>,
    version: crate::protocol::version::ProtocolVersion,
) -> Result<Option<Value>, &'static str> {
    use crate::protocol::v_2026_07_28::wire::meta::META_KEY_PROGRESS_TOKEN;
    let raw = meta.and_then(|m| {
        if version == crate::protocol::version::ProtocolVersion::V_2026_07_28 {
            m.get(META_KEY_PROGRESS_TOKEN)
                .or_else(|| m.get("progressToken"))
        } else {
            m.get("progressToken")
        }
    });
    match raw {
        None => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(Value::String(s.clone()))),
        Some(Value::Number(n)) => Ok(Some(Value::Number(n.clone()))),
        Some(_) => Err("_meta.progressToken MUST be a non-empty string or a number"),
    }
}

/// SEP-2575 per-request log-level floor. Modern (`2026-07-28`) wire
/// only: parse `_meta.io.modelcontextprotocol/logLevel` into the typed
/// [`LogLevel`](crate::protocol::v_2026_07_28::wire::meta::LogLevel).
///
/// Returns `Ok(None)` on the legacy wire (the field is never consulted
/// there) and when the key is absent on the modern wire. Returns
/// `Err` when present but not a recognised level string — a malformed
/// hint should surface as a `-32602`, not silently emit everything.
///
/// Note the *meaning* of `None` differs by wire and is interpreted at
/// the emission site: on the modern wire `None` means "suppress every
/// `notifications/message` for this request" (the spec MUST), while on
/// the legacy wire log notifications are emitted unconditionally.
pub(crate) fn extract_request_log_level(
    meta: Option<&Value>,
    version: crate::protocol::version::ProtocolVersion,
) -> Result<Option<crate::protocol::v_2026_07_28::wire::meta::LogLevel>, &'static str> {
    use crate::protocol::v_2026_07_28::wire::meta::{LogLevel, META_KEY_LOG_LEVEL};
    if version != crate::protocol::version::ProtocolVersion::V_2026_07_28 {
        return Ok(None);
    }
    match meta.and_then(|m| m.get(META_KEY_LOG_LEVEL)) {
        None => Ok(None),
        Some(Value::String(s)) => LogLevel::parse_str(s).map(Some).ok_or(
            "_meta.io.modelcontextprotocol/logLevel must be one of the eight RFC-5424 levels",
        ),
        Some(_) => Err("_meta.io.modelcontextprotocol/logLevel must be a string"),
    }
}

pub(crate) fn negotiate_protocol_version(requested_version: &str) -> &str {
    // Echo the client's requested revision when the gateway serves it
    // through the session-based `initialize` lifecycle; otherwise fall back
    // to the gateway's preferred revision. The stateless modern revision
    // has no `initialize`, so the served set here is exactly the
    // session-requiring revisions.
    match crate::protocol::version::ProtocolVersion::parse(requested_version) {
        Some(version) if version.requires_session() => version.as_str(),
        _ => SUPPORTED_PROTOCOL_VERSION,
    }
}

/// Identify bindings that may return dynamic resources from
/// their plugin's `list_resources` surface. The match is
/// shape-based — any binding whose `backend` routes through
/// a plugin kind and whose `kind` is resource or resource_template
/// is a candidate. Plugins that don't implement `list_resources`
/// inherit the default empty page, so including them here is
/// effectively free.
/// Build a default `ApprovalRegistry` for runtimes constructed
/// without explicit approval config. Uses two v4 UUIDs as 32 bytes
/// of system-CSPRNG-backed randomness (same pattern as
/// `generate_cursor_hmac_key`) and an empty callback base url.
/// Production deploys overwrite this via
/// [`GatewayRuntime::set_approval_config`] with operator-supplied
/// settings sourced from `approvals.signing_key_env` +
/// `approvals.callback_base_url`. Callbacks generated under a
/// default registry don't survive a gateway restart — fine for
/// tests + dev, not for prod.
pub(crate) fn build_default_approval_registry() -> Arc<approvals::ApprovalRegistry> {
    let mut key = vec![0u8; 32];
    let a = *uuid::Uuid::new_v4().as_bytes();
    let b = *uuid::Uuid::new_v4().as_bytes();
    key[..16].copy_from_slice(&a);
    key[16..].copy_from_slice(&b);
    Arc::new(approvals::ApprovalRegistry::new(
        key,
        String::new(),
        approvals::DEFAULT_CALLBACK_GRACE,
    ))
}

/// Map an upstream MCP `prompts/get` result into the gateway's
/// `PromptGetResult`. `PromptMessage` is `Deserialize`, so the messages
/// array maps directly.
pub(crate) fn federated_prompt_get_result(
    value: serde_json::Value,
) -> Result<PromptGetResult, invocation::SurfaceDecodeError> {
    let messages = value
        .get("messages")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let messages: Vec<PromptMessage> = serde_json::from_value(messages).map_err(|e| {
        invocation::SurfaceDecodeError::MalformedResponse {
            reason: format!("invalid federated prompt messages: {e}"),
        }
    })?;
    Ok(PromptGetResult { messages })
}

/// Map an upstream MCP `resources/read` result into the gateway's
/// `ResourceReadResult`. `ResourceContents` is serialize-only, so each
/// content item is reconstructed by inspecting `text` / `blob`.
pub(crate) fn federated_resource_read_result(value: serde_json::Value) -> ResourceReadResult {
    let contents = value
        .get("contents")
        .and_then(|c| c.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(federated_resource_content)
                .collect()
        })
        .unwrap_or_default();
    ResourceReadResult {
        contents,
        ttl_ms: None,
        cache_scope: None,
        cache_token: None,
    }
}

/// SEP-1865: scan a `tools/list` page for UI-enabled tools, returning
/// `{tool, resourceUri}` for each tool carrying `_meta.ui.resourceUri`
/// (nested or deprecated-alias form). Pure so it can be unit-tested
/// independently of the audit sink; see [`GatewayRuntime::audit_apps_offered`].
pub(crate) fn apps_offered_from_tools(
    tools: &[crate::backends::ToolDescriptor],
) -> Vec<serde_json::Value> {
    tools
        .iter()
        .filter_map(|t| {
            let meta = t.meta.as_ref()?;
            let uri = crate::protocol::shared::apps::tool_resource_uri(meta)?;
            Some(serde_json::json!({ "tool": t.name, "resourceUri": uri }))
        })
        .collect()
}

pub(crate) fn federated_resource_content(item: &serde_json::Value) -> Option<ResourceContents> {
    let uri = item.get("uri").and_then(|v| v.as_str())?.to_owned();
    let mime_type = item
        .get("mimeType")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    // Preserve the upstream content's `_meta` (notably SEP-1865
    // `_meta.ui` carrying CSP / permissions for a `ui://` resource).
    let meta = item.get("_meta").cloned();
    if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
        Some(ResourceContents::Text(ResourceTextContents {
            uri,
            mime_type,
            text: text.to_owned(),
            meta,
        }))
    } else {
        item.get("blob").and_then(|v| v.as_str()).map(|blob| {
            ResourceContents::Blob(BlobResourceContents {
                uri,
                mime_type,
                blob: blob.to_owned(),
                meta,
            })
        })
    }
}

pub(crate) fn binding_type_label(route: &BackendInvocationRoute) -> String {
    match route {
        BackendInvocationRoute::RuntimeSnapshot | BackendInvocationRoute::RequestEcho => {
            "internal".to_owned()
        }
        BackendInvocationRoute::CommandProbe { .. }
        | BackendInvocationRoute::CommandJsonCall { .. } => "command".to_owned(),
        BackendInvocationRoute::NetworkProbe { .. }
        | BackendInvocationRoute::NetworkJsonCall { .. }
        | BackendInvocationRoute::NetworkQueryCall { .. } => "http".to_owned(),
        BackendInvocationRoute::NatsRequest { .. } => "nats".to_owned(),
        BackendInvocationRoute::GraphqlCall { .. } => "graphql".to_owned(),
        BackendInvocationRoute::KafkaRequest { .. } => "kafka".to_owned(),
        BackendInvocationRoute::MockResponse { .. } => "mock".to_owned(),
        BackendInvocationRoute::Pipeline { .. } => "pipeline".to_owned(),
        BackendInvocationRoute::SqlRequest { .. } => "sql".to_owned(),
        BackendInvocationRoute::OpenapiCall { .. } => "openapi".to_owned(),
        BackendInvocationRoute::LlmRequest { .. } => "llm".to_owned(),
        BackendInvocationRoute::Federated { .. } => "federated".to_owned(),
        // Generic backend dispatch — the metric label is the backend `kind`
        // string itself (e.g. `soap`, `dynamodb`), since every per-vendor
        // backend kind routes through this arm.
        BackendInvocationRoute::EnvelopePlugin { kind, .. } => kind.clone(),
    }
}

/// Merge payment receipt `_meta` into a serialized `ToolCallResult` JSON value.
/// If `payment_meta` is `None`, returns the value unchanged.
pub(crate) fn merge_plugin_gate_meta(
    mut result_value: serde_json::Value,
    plugin_meta: &Option<serde_json::Value>,
) -> serde_json::Value {
    if let Some(meta) = plugin_meta
        && let Some(obj) = result_value.as_object_mut()
    {
        obj.insert("_meta".to_owned(), meta.clone());
    }
    result_value
}

/// Map a single suspended server request into the modern SEP-2322
/// `inputRequests` map (keyed by the server-minted correlation token),
/// serialized as the `Value` the task store persists. Mirrors the
/// translation in `build_modern_input_required_response_multi` so a
/// task awaiting input surfaces the same `inputRequests` shape on
/// `tasks/get` that the inline MRTR path emits.
pub(crate) fn modern_input_requests_from_server_request(
    server_request: &crate::protocol::ServerJsonRpcRequest,
) -> Result<serde_json::Value, String> {
    use crate::protocol::v_2026_07_28::wire::mrtr::InputRequest;

    let input_request = match server_request.method.as_str() {
        "elicitation/create" => InputRequest::Elicitation {
            params: server_request.params.clone(),
        },
        "sampling/createMessage" => InputRequest::Sampling {
            params: server_request.params.clone(),
        },
        "roots/list" => InputRequest::Roots {
            params: server_request.params.clone(),
        },
        other => {
            return Err(format!(
                "modern task input cannot translate `{other}` to InputRequest"
            ));
        }
    };
    let correlation_token = match &server_request.id {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut map = std::collections::BTreeMap::new();
    map.insert(correlation_token, input_request);
    serde_json::to_value(&map).map_err(|e| format!("failed to serialize task inputRequests: {e}"))
}

pub(crate) fn scopeguard_cancellation(
    registry: Arc<dashmap::DashMap<String, RegisteredCancellation>>,
    target_id: String,
) -> CancellationCleanup {
    CancellationCleanup {
        registry,
        target_id,
    }
}

/// Extract the JSON-RPC `id` of a client-initiated request operation.
///
/// Delegates to [`ProtocolOperation::client_request_id`] rather than
/// re-matching the variants: the two copies drifted once already, and the
/// consequence was silent — the duplicate kept reporting the id that
/// `notifications/cancelled` merely *targets*, so the dedup gate rejected
/// every cancellation of a request the client had actually issued.
pub(crate) fn client_request_id(op: &ProtocolOperation) -> Option<Value> {
    op.client_request_id()
}

pub(crate) fn protocol_http_error(
    http_status: u16,
    id: Option<serde_json::Value>,
    code: i32,
    message: impl Into<String>,
    data: Option<serde_json::Value>,
) -> ProtocolHttpResponse {
    let msg = message.into();
    metrics::counter!(
        "mcpg_protocol_errors_total",
        "http_status" => http_status.to_string(),
        "jsonrpc_code" => code.to_string(),
    )
    .increment(1);
    ProtocolHttpResponse {
        http_status,
        session_id_header: None,
        response: ProtocolResponse::JsonRpcError(JsonRpcError {
            jsonrpc: JSONRPC_VERSION,
            id,
            error: JsonRpcErrorBody {
                code,
                message: msg,
                data,
            },
        }),
    }
}

/// Map gateway `RequestContext` identity to the plugin API identity type.
pub(crate) fn plugin_identity_from_request(
    ctx: &RequestContext,
) -> mcpg_plugin_protocol::PluginIdentity {
    plugin_identity_from_request_identity(&ctx.identity)
}

/// Convert a resolved transport identity into the FFI identity shape.
/// Federation threads this through upstream credential resolution so
/// issuer plugins see the caller's real trust level, subject and scopes
/// (the trust gate and the per-caller credential-cache key both depend
/// on them).
pub(crate) fn plugin_identity_from_request_identity(
    identity: &RequestIdentity,
) -> mcpg_plugin_protocol::PluginIdentity {
    let empty_map = std::collections::BTreeMap::new();
    match identity {
        RequestIdentity::Anonymous { .. } => mcpg_plugin_protocol::PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: empty_map,
        },
        RequestIdentity::HttpHeader { subject_id, .. } => mcpg_plugin_protocol::PluginIdentity {
            kind: "http_header".into(),
            trust_level: "header_asserted".into(),
            subject_id: Some(subject_id.clone()),
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: empty_map,
        },
        RequestIdentity::Verified {
            subject_id,
            auth_provider,
            issuer,
            roles,
            groups,
            scopes,
            attributes,
            ..
        } => mcpg_plugin_protocol::PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some(subject_id.clone()),
            auth_provider: Some(auth_provider.clone()),
            issuer: Some(issuer.clone()),
            roles: roles.clone(),
            groups: groups.clone(),
            scopes: scopes.clone(),
            attributes: attributes.clone(),
        },
    }
}

pub(crate) fn transport_label(t: &TransportKind) -> &'static str {
    match t {
        TransportKind::Http => "http",
        TransportKind::Stdio => "stdio",
    }
}

impl Drop for CancellationCleanup {
    fn drop(&mut self) {
        self.registry.remove(&self.target_id);
    }
}
