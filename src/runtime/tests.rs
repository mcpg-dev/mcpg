use super::*;

#[test]
fn uptime_is_non_negative() {
    let runtime = GatewayRuntime::new(
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
    );

    assert!(runtime.uptime_secs() >= 0);
}

#[test]
fn readiness_snapshot_reports_ready_for_valid_runtime() {
    let runtime = GatewayRuntime::new(
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
    );

    let snapshot = runtime.readiness_snapshot();

    assert_eq!(snapshot.status, ReadinessStatus::Ready);
    assert_eq!(snapshot.checks.len(), 4);
    assert_eq!(snapshot.checks[0].name, "config_valid");
}

#[test]
fn request_context_keeps_gateway_and_upstream_request_ids() {
    let context = RequestContext::new(
        GatewayRequestId::new(),
        Some("upstream-123".to_owned()),
        header_asserted("user-1"),
        TransportKind::Http,
    );

    assert_eq!(context.upstream_request_id.as_deref(), Some("upstream-123"));
    assert_eq!(context.identity.label(), "http_header");
    assert!(!context.request_id.as_str().is_empty());
    assert!(context.session_id.is_none(), "dispatch binds the session");
}

// -- Dispatch through the protocol handler ----------------------------

fn test_runtime() -> GatewayRuntime {
    GatewayRuntime::new(
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
    )
}

/// A context of `identity` with no session yet.
fn request_context(identity: RequestIdentity) -> RequestContext {
    RequestContext::new(GatewayRequestId::new(), None, identity, TransportKind::Http)
}

fn anonymous() -> RequestIdentity {
    RequestIdentity::Anonymous {
        source: "test".to_owned(),
    }
}

fn header_asserted(subject: &str) -> RequestIdentity {
    RequestIdentity::HttpHeader {
        subject_id: subject.to_owned(),
        source: "x-mcpg-subject-id".to_owned(),
    }
}

fn verified(subject: &str) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: subject.to_owned(),
        issuer: "https://auth.example.com/".to_owned(),
        auth_provider: "jwks".to_owned(),
        source: "authorization:jwt".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    }
}

/// `runtime` behind the swap cell boot keeps it in, with the shared
/// services installed, so [`GatewayRuntime::handle_protocol_message`]
/// dispatches.
fn serve(runtime: GatewayRuntime) -> Arc<arc_swap::ArcSwap<GatewayRuntime>> {
    use crate::protocol::v_2026_07_28::dispatch::request_state::{
        InMemoryRequestStateStore, RequestStateCodec,
    };
    let gateway = Arc::new(arc_swap::ArcSwap::from_pointee(runtime));
    let services = shared_services::SharedServices::new(
        Arc::new(crate::config::AppConfig::default()),
        Arc::new(RequestStateCodec::new(
            RequestStateCodec::ephemeral_key(),
            Arc::new(InMemoryRequestStateStore::new()),
        )),
    );
    gateway.load().set_shared_services(Arc::new(services));
    gateway
}

/// Dispatch the JSON-RPC message `body` from `identity` as the transport
/// does: bind the request to its session, parse the body, and hand both
/// to the runtime.
async fn send(
    gateway: &Arc<arc_swap::ArcSwap<GatewayRuntime>>,
    identity: RequestIdentity,
    body: Value,
) -> ProtocolHttpResponse {
    let runtime = gateway.load_full();
    let context = match runtime.ensure_session(request_context(identity)) {
        SessionOutcome::Ready(context) => context,
        SessionOutcome::CapacityExhausted => panic!("the session store has room"),
    };
    let message = crate::protocol::Handler
        .parse(body)
        .expect("a well-formed message");
    runtime
        .handle_protocol_message(&Arc::new(context), message)
        .await
}

/// The `result` of a JSON-RPC success.
fn success_result(response: ProtocolHttpResponse) -> Value {
    match response.response {
        ProtocolResponse::JsonRpcSuccess(success) => success.result,
        other => panic!("expected a JSON-RPC success, got {other:?}"),
    }
}

/// The `error.code` of a JSON-RPC error.
fn error_code(response: &ProtocolHttpResponse) -> i32 {
    match &response.response {
        ProtocolResponse::JsonRpcError(error) => error.error.code,
        other => panic!("expected a JSON-RPC error, got {other:?}"),
    }
}

fn tools_list(id: u64) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {} })
}

fn tools_call(id: u64, name: &str, arguments: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

/// The tool names a `tools/list` result carries, in order.
fn tool_names(result: &Value) -> Vec<String> {
    result["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn runtime_handles_readiness_gateway_request() {
    let runtime = test_runtime();
    let response = runtime
        .handle_request(
            request_context(anonymous()),
            DiagnosticsOperation::Readiness,
        )
        .await;

    match response.payload {
        GatewayResponsePayload::Readiness(snapshot) => {
            assert_eq!(snapshot.status, ReadinessStatus::Ready);
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

/// Before boot installs the shared services, a message answers `-32603`
/// under its own id instead of reaching a handler.
#[tokio::test]
async fn a_message_before_the_shared_services_are_installed_is_an_internal_error() {
    let runtime = test_runtime();
    let message = crate::protocol::Handler
        .parse(tools_list(7))
        .expect("a well-formed message");

    let response = runtime
        .handle_protocol_message(&Arc::new(request_context(anonymous())), message)
        .await;

    assert_eq!(response.http_status, 500);
    let ProtocolResponse::JsonRpcError(error) = response.response else {
        panic!("expected a JSON-RPC error");
    };
    assert_eq!(error.id, Some(serde_json::json!(7)));
    assert_eq!(error.error.code, -32603);
}

#[tokio::test]
async fn runtime_handles_tools_list_protocol_request() {
    let gateway = serve(test_runtime());

    let names = tool_names(&success_result(
        send(&gateway, header_asserted("user-1"), tools_list(2)).await,
    ));

    // tools are returned lexicographically. The first debug tool
    // registered for this runtime is `mcpg.debug.command_probe`;
    // `mcpg.runtime.snapshot` still appears later in the list.
    assert_eq!(
        names.first().map(String::as_str),
        Some("mcpg.debug.command_probe")
    );
    assert!(names.iter().any(|n| n == "mcpg.runtime.snapshot"));
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        names, sorted,
        "tools/list must be lexicographically ordered"
    );
}

#[tokio::test]
async fn tools_list_invalid_cursor_returns_invalid_params() {
    let gateway = serve(test_runtime());

    // A cursor that does not decode against the request's bound key must
    // surface -32602, not silently restart at page 1.
    let response = send(
        &gateway,
        header_asserted("user-1"),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": { "cursor": "not-a-valid-cursor" },
        }),
    )
    .await;

    assert_eq!(error_code(&response), -32602, "invalid cursor → -32602");
}

#[tokio::test]
async fn runtime_handles_prompts_get_protocol_request() {
    let gateway = serve(test_runtime());

    let result = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "prompts/get",
                "params": { "name": "mcpg_operational_overview" },
            }),
        )
        .await,
    );

    assert_eq!(result["messages"][0]["role"], "system");
    assert!(
        result["messages"][0]["content"]["text"]
            .as_str()
            .expect("prompt text")
            .contains("Available tools")
    );
}

#[tokio::test]
async fn runtime_handles_resources_read_protocol_request() {
    let gateway = serve(test_runtime());

    let result = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "resources/read",
                "params": { "uri": "mcpg://runtime/overview" },
            }),
        )
        .await,
    );

    assert_eq!(result["contents"][0]["uri"], "mcpg://runtime/overview");
    assert_eq!(result["contents"][0]["mimeType"], "application/json");
    assert!(
        result["contents"][0]["text"]
            .as_str()
            .expect("resource text")
            .contains("\"service\": \"mcpg\"")
    );
}

#[tokio::test]
async fn runtime_handles_resources_templates_list() {
    let gateway = serve(test_runtime());

    let result = success_result(
        send(
            &gateway,
            anonymous(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "resources/templates/list",
                "params": {},
            }),
        )
        .await,
    );

    // This runtime binds no resource templates.
    assert_eq!(result["resourceTemplates"], serde_json::json!([]));
}

#[tokio::test]
async fn runtime_handles_notification_cancelled() {
    let gateway = serve(test_runtime());

    let response = send(
        &gateway,
        anonymous(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": 999, "reason": "user abort" },
        }),
    )
    .await;

    assert_eq!(response.http_status, 202);
}

/// A `notifications/cancelled` reaches the principal-partitioned
/// cancellation bus, which carries it to the replica running the request.
#[tokio::test]
async fn notification_cancelled_reaches_cancellation_bus() {
    use crate::runtime::cancellation_bus::{BusBackedCancellationBus, CancellationBus};

    let mut runtime = test_runtime();
    let bus = std::sync::Arc::new(BusBackedCancellationBus::new_in_memory());
    let mut rx = bus.subscribe().await;
    runtime.set_cancellation_bus(bus);

    let mut ctx = request_context(anonymous());
    ctx.session_id = Some("sess-1".to_owned());

    runtime
        .handle_request_cancellation(&ctx, &serde_json::json!("req-42"), Some("user abort"))
        .await;

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("cancellation event should be broadcast within timeout")
        .expect("bus should deliver the event");
    // target_id is the JSON-RPC id stringified (a JSON string value
    // serialises with surrounding quotes).
    assert_eq!(event.target_id, serde_json::json!("req-42").to_string());
    assert_eq!(event.session_id, "sess-1");
    assert_eq!(event.reason.as_deref(), Some("user abort"));
    assert!(matches!(
        event.kind,
        crate::runtime::cancellation_bus::CancellationKind::Request
    ));
}

#[tokio::test]
async fn session_termination_clears_subscriptions() {
    let runtime = test_runtime();
    let session_id = runtime.session_store.create_session().session_id;
    let _lease = runtime
        .subscriptions()
        .acquire(&session_id, "mcpg://runtime/overview", None)
        .await
        .expect("the store takes the subscription");
    assert_eq!(
        runtime
            .subscription_store
            .subscriptions_for_session(&session_id)
            .len(),
        1
    );

    runtime.terminate_session(&session_id);
    assert_eq!(
        runtime
            .subscription_store
            .subscriptions_for_session(&session_id)
            .len(),
        0
    );
}

#[tokio::test]
async fn runtime_handles_adapter_backed_tool_call_protocol_request() {
    let gateway = serve(test_runtime());

    let result = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            tools_call(
                33,
                "mcpg.request.echo",
                serde_json::json!({ "message": "hello" }),
            ),
        )
        .await,
    );

    assert_eq!(result["structuredContent"]["toolName"], "mcpg.request.echo");
    assert_eq!(result["structuredContent"]["arguments"]["message"], "hello");
    assert_eq!(
        result["structuredContent"]["request"]["principalId"],
        "user-1"
    );
}

#[tokio::test]
async fn runtime_rejects_anonymous_tool_call_before_dispatch() {
    let gateway = serve(test_runtime());

    let response = send(
        &gateway,
        anonymous(),
        tools_call(404, "mcpg.runtime.snapshot", serde_json::json!({})),
    )
    .await;

    assert_eq!(response.http_status, 403);
    assert_eq!(error_code(&response), -32003);
}

#[tokio::test]
async fn runtime_allows_anonymous_tool_call_when_policy_lowers_required_trust() {
    let runtime = GatewayRuntime::new_with_configs(
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
        SessionStoreConfig::default(),
        ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::HeaderAsserted,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                required_scopes: Vec::new(),
                surface: None,
            }],
        },
    );
    let gateway = serve(runtime);

    let response = send(
        &gateway,
        anonymous(),
        tools_call(405, "mcpg.runtime.snapshot", serde_json::json!({})),
    )
    .await;

    assert_eq!(response.http_status, 200);
    assert_eq!(
        success_result(response)["structuredContent"]["service"],
        "mcpg"
    );
}

#[tokio::test]
async fn runtime_handles_tool_call_protocol_request() {
    let gateway = serve(test_runtime());

    let result = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            tools_call(3, "mcpg.runtime.snapshot", serde_json::json!({})),
        )
        .await,
    );

    assert_eq!(result["content"][0]["type"], "text");
    assert_eq!(result["structuredContent"]["service"], "mcpg");
}

#[test]
fn verified_identity_has_correct_trust_level_and_fields() {
    let identity = RequestIdentity::Verified {
        subject_id: "user-42".to_owned(),
        issuer: "https://auth.example.com/".to_owned(),
        auth_provider: "jwks".to_owned(),
        source: "authorization_bearer".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    };
    assert_eq!(identity.trust_level(), RequestTrustLevel::Verified);
    assert_eq!(identity.label(), "verified");
    assert_eq!(identity.principal_id(), Some("user-42"));
    assert_eq!(identity.auth_provider(), Some("jwks"));
    assert_eq!(identity.issuer(), Some("https://auth.example.com/"));
    assert!(!identity.is_anonymous());
}

#[test]
fn trust_level_ordering_is_unauthenticated_lt_header_asserted_lt_verified() {
    assert!(RequestTrustLevel::Unauthenticated < RequestTrustLevel::HeaderAsserted);
    assert!(RequestTrustLevel::HeaderAsserted < RequestTrustLevel::Verified);
    assert!(RequestTrustLevel::Unauthenticated < RequestTrustLevel::Verified);
}

#[test]
fn anonymous_and_header_asserted_have_no_auth_provider_or_issuer() {
    let anon = RequestIdentity::Anonymous {
        source: "test".to_owned(),
    };
    assert_eq!(anon.auth_provider(), None);
    assert_eq!(anon.issuer(), None);

    let header = RequestIdentity::HttpHeader {
        subject_id: "user-1".to_owned(),
        source: "x-mcpg-subject-id".to_owned(),
    };
    assert_eq!(header.auth_provider(), None);
    assert_eq!(header.issuer(), None);
}

/// A task owner key is a principal key exactly when a principal owns the
/// task; an anonymous caller's task is owned by a session id.
#[test]
fn principal_keys_are_told_apart_from_session_ids() {
    for identity in [header_asserted("alice"), verified("alice")] {
        let key = identity.synthetic_principal_key().expect("a principal key");
        assert!(RequestIdentity::is_principal_key(&key), "{key}");
    }
    assert!(anonymous().synthetic_principal_key().is_none());
    for session_id in [
        uuid::Uuid::new_v4().to_string(),
        GatewayRuntime::derive_synthetic_session_id(&[7u8; 32], "verified::p::i::alice"),
    ] {
        assert!(
            !RequestIdentity::is_principal_key(&session_id),
            "{session_id}"
        );
    }
}

#[test]
fn runtime_default_policy_chain_is_empty() {
    // The simpler `try_new_with_runtime_controls` constructor
    // forwards `Vec::new()` for the chain — operators with no
    // `governance.policy.engine[]` declared get the implicit
    // empty chain → every decision returns `NotApplicable`.
    let runtime = GatewayRuntime::new(
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
    );
    assert!(runtime.policy_chain().is_empty());
}

#[tokio::test]
async fn evaluate_pre_dispatch_policy_chain_returns_not_applicable_for_empty_chain() {
    // Empty chain → NotApplicable, not Allow / not Deny. The
    // caller (dispatch pipeline) decides what NotApplicable
    // means in its own context (typically: fall through to
    // the trust-level gate).
    let runtime = GatewayRuntime::new(
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
    );
    let ctx = mcpg_plugin_protocol::PluginContext {
        request_id: "test-req".to_owned(),
        session_id: None,
        tool_name: "any.tool".to_owned(),
        surface: "tool".to_owned(),
        identity: mcpg_plugin_host::audit_events::system_identity(),
        transport: "internal".to_owned(),
    };
    let outcome = runtime
        .evaluate_pre_dispatch_policy_chain("tool.call.pre", &ctx, &serde_json::json!({}))
        .await;
    assert!(matches!(
        outcome,
        mcpg_plugin_host::PolicyChainOutcome::NotApplicable
    ));
}

#[tokio::test]
async fn tools_list_filters_tools_by_caller_identity() {
    use policy::ToolTrustRule;

    // Create a runtime with a binding that requires `Verified` trust
    let runtime = GatewayRuntime::try_new_with_runtime_controls(
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
        Arc::new(session_store::KvBackedSessionStore::new_in_memory(
            SessionStoreConfig::default(),
        )),
        policy::ToolAccessPolicyConfig {
            default_minimum_trust: RequestTrustLevel::Unauthenticated,
            cel_allow_if: None,
            rules: vec![ToolTrustRule {
                tool_name: "mcpg.runtime.snapshot".to_owned(),
                minimum_trust: RequestTrustLevel::Verified,
                cel_allow_if: None,
                required_scopes: Vec::new(),
                surface: None,
            }],
        },
        execution::RuntimeDebugConfig {
            enabled: true,
            ..execution::RuntimeDebugConfig::default()
        },
        &[],
        &[],
        &[],
        &[],
        None, // jwt_verifier
        None, // oidc_resolver
        std::sync::Arc::new(pipeline_store::KvBackedPipelineStore::new_in_memory()),
        Arc::new(delivery_bus::BusBackedDeliveryBus::new_in_memory()),
    )
    .expect("valid runtime config");
    let gateway = serve(runtime);

    // HeaderAsserted caller should NOT see mcpg.runtime.snapshot (requires Verified)
    let header_tools = tool_names(&success_result(
        send(&gateway, header_asserted("user-1"), tools_list(2)).await,
    ));
    assert!(
        !header_tools.contains(&"mcpg.runtime.snapshot".to_owned()),
        "header-asserted caller should not see verified-only tool, got: {:?}",
        header_tools
    );

    // Verified caller SHOULD see mcpg.runtime.snapshot
    let verified_tools = tool_names(&success_result(
        send(&gateway, verified("user-1"), tools_list(3)).await,
    ));
    assert!(
        verified_tools.contains(&"mcpg.runtime.snapshot".to_owned()),
        "verified caller should see verified-only tool, got: {:?}",
        verified_tools
    );
}

/// One page at the default `mcp.list_page_size`.
fn paginate_one_page<T: Clone>(
    items: &[T],
    cursor: Option<&str>,
    bind_key: Option<&[u8]>,
) -> (Vec<T>, Option<String>) {
    super::paginate_list_bound(
        items,
        cursor,
        bind_key,
        crate::config::mcp::DEFAULT_LIST_PAGE_SIZE,
    )
}

#[test]
fn paginate_list_returns_all_when_small() {
    let items: Vec<i32> = (0..5).collect();
    let (page, cursor) = paginate_one_page(&items, None, None);
    assert_eq!(page.len(), 5);
    assert!(cursor.is_none());
}

#[test]
fn paginate_list_paginates_large_set() {
    let items: Vec<i32> = (0..250).collect();
    let (page1, cursor1) = paginate_one_page(&items, None, None);
    assert_eq!(page1.len(), crate::config::mcp::DEFAULT_LIST_PAGE_SIZE);
    assert_eq!(page1[0], 0);
    assert!(cursor1.is_some());

    let (page2, cursor2) = paginate_one_page(&items, cursor1.as_deref(), None);
    assert_eq!(page2.len(), crate::config::mcp::DEFAULT_LIST_PAGE_SIZE);
    assert_eq!(page2[0], 100);
    assert!(cursor2.is_some());

    let (page3, cursor3) = paginate_one_page(&items, cursor2.as_deref(), None);
    assert_eq!(page3.len(), 50);
    assert_eq!(page3[0], 200);
    assert!(cursor3.is_none());
}

#[test]
fn paginate_list_invalid_cursor_returns_first_page() {
    let items: Vec<i32> = (0..5).collect();
    let (page, cursor) = paginate_one_page(&items, Some("garbage_cursor"), None);
    assert_eq!(page.len(), 5);
    assert!(cursor.is_none());
}

#[test]
fn paginate_list_empty_input() {
    let items: Vec<i32> = vec![];
    let (page, cursor) = paginate_one_page(&items, None, None);
    assert!(page.is_empty());
    assert!(cursor.is_none());
}

/// a MAC-bound cursor round-trips and carries the offset.
#[test]
fn bound_cursor_roundtrips_for_same_session() {
    let items: Vec<i32> = (0..250).collect();
    let key = b"session-A-key";
    let (_p1, c1) = paginate_one_page(&items, None, Some(key));
    assert!(c1.is_some());
    let (p2, _) = paginate_one_page(&items, c1.as_deref(), Some(key));
    assert_eq!(p2[0], 100);
}

/// Replicas sharing the cluster state key sign list cursors with one key, so
/// a page-2 cursor from one verifies on another; without the key each process
/// keeps its own.
#[test]
fn cursor_signing_key_is_shared_through_the_cluster_state_key() {
    let var = "MCPG_TEST_LIST_CURSOR_STATE_KEY";
    // 32 zero bytes, URL-safe base64 without padding.
    unsafe { std::env::set_var(var, "A".repeat(43)) };
    let cluster = crate::config::ClusterConfig {
        state_encryption_key_env: Some(var.to_owned()),
        ..Default::default()
    };
    let (process_a, process_b) = ([1u8; 32], [2u8; 32]);
    let key_a = super::cursor::cursor_signing_key(process_a, &cluster);
    let key_b = super::cursor::cursor_signing_key(process_b, &cluster);
    assert_eq!(key_a, key_b);
    assert_ne!(key_a, process_a);

    let items: Vec<i32> = (0..250).collect();
    let bind = |key: [u8; 32]| hmac_sha256::HMAC::mac(b"anonymous", key).to_vec();
    let (_page, next) = paginate_one_page(&items, None, Some(&bind(key_a)));
    let (page_two, _) = paginate_one_page(&items, next.as_deref(), Some(&bind(key_b)));
    assert_eq!(page_two[0], 100);

    unsafe { std::env::remove_var(var) };
    let no_key = crate::config::ClusterConfig::default();
    assert_eq!(
        super::cursor::cursor_signing_key(process_a, &no_key),
        process_a
    );
}

/// An ephemeral session's id is new on every request, so its cursors bind to
/// the principal: the caller's page-2 cursor verifies on its next request,
/// and never for another principal. A stored session still binds to its own
/// id.
#[test]
fn ephemeral_session_cursors_bind_to_the_principal() {
    let runtime = GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        Vec::new(),
        true,
    );
    let context = |session: &str, ephemeral: bool, identity: RequestIdentity| {
        let mut ctx = request_context(identity);
        ctx.session_id = Some(session.to_owned());
        ctx.session_ephemeral = ephemeral;
        ctx
    };
    let anonymous = || RequestIdentity::Anonymous {
        source: "test".to_owned(),
    };
    let asserted = |subject: &str| RequestIdentity::HttpHeader {
        subject_id: subject.to_owned(),
        source: "test".to_owned(),
    };

    let key = |ctx: &RequestContext| runtime.cursor_binding_key(ctx);
    assert_eq!(
        key(&context("e-1", true, anonymous())),
        key(&context("e-2", true, anonymous()))
    );
    assert_eq!(
        key(&context("e-1", true, asserted("alice"))),
        key(&context("e-2", true, asserted("alice")))
    );
    assert_ne!(
        key(&context("e-1", true, asserted("alice"))),
        key(&context("e-1", true, asserted("bob")))
    );
    assert_ne!(
        key(&context("s-1", false, anonymous())),
        key(&context("s-2", false, anonymous()))
    );
}

/// a cursor minted under session A MUST NOT advance
/// pagination when presented under session B — it restarts at 0.
#[test]
fn bound_cursor_rejects_cross_session_replay() {
    let items: Vec<i32> = (0..250).collect();
    let key_a = b"session-A-key";
    let key_b = b"session-B-key";
    let (_p1, c1) = paginate_one_page(&items, None, Some(key_a));
    let (replay_page, _) = paginate_one_page(&items, c1.as_deref(), Some(key_b));
    // Replay resets to offset 0 rather than advancing.
    assert_eq!(replay_page[0], 0);
}

/// unbound cursor (from a client that used paginate_list
/// without a key) is rejected by the bound decoder.
#[test]
fn bound_cursor_rejects_unbound_input() {
    let items: Vec<i32> = (0..250).collect();
    let (_p1, c1) = paginate_one_page(&items, None, None);
    assert!(c1.is_some());
    let (page, _) = paginate_one_page(&items, c1.as_deref(), Some(b"key"));
    assert_eq!(page[0], 0, "mixed-mode cursor must restart");
}

// --- Composite cursor (P2.3) -----------------------------------------

#[test]
fn composite_cursor_roundtrips_with_static_and_dynamic() {
    let key = b"sess-A-key";
    let original = super::CompositeCursor {
        s: Some(200),
        d: vec![
            super::DynCursor {
                b: "orders".into(),
                c: "row-id-42".into(),
            },
            super::DynCursor {
                b: "audit_log".into(),
                c: "ts-2026-04-30T12:00".into(),
            },
        ],
    };
    let encoded = super::encode_composite_cursor(&original, Some(key));
    assert!(encoded.starts_with("c."), "got: {encoded}");
    let decoded = super::decode_composite_cursor(&encoded, Some(key)).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn composite_cursor_rejects_cross_session_replay() {
    let original = super::CompositeCursor {
        s: Some(100),
        d: vec![],
    };
    let encoded = super::encode_composite_cursor(&original, Some(b"sess-A"));
    let decoded = super::decode_composite_cursor(&encoded, Some(b"sess-B"));
    assert!(decoded.is_none(), "MAC mismatch must reject");
}

#[test]
fn composite_cursor_rejects_bare_offset() {
    // A bare-offset cursor (from `encode_cursor`) is NOT a
    // composite cursor — the resources/list handler pages the
    // static catalog on one, but `decode_composite_cursor`
    // alone should reject it cleanly.
    let bare = super::encode_cursor(100, Some(b"key"));
    assert!(super::decode_composite_cursor(&bare, Some(b"key")).is_none());
}

#[test]
fn composite_cursor_done_when_static_exhausted_and_no_dyn() {
    let c = super::CompositeCursor { s: None, d: vec![] };
    assert!(c.is_done());
}

#[test]
fn composite_cursor_not_done_when_dyn_remaining() {
    let c = super::CompositeCursor {
        s: None,
        d: vec![super::DynCursor {
            b: "orders".into(),
            c: "row-100".into(),
        }],
    };
    assert!(!c.is_done());
}

#[test]
fn composite_cursor_not_done_when_static_remaining() {
    let c = super::CompositeCursor {
        s: Some(100),
        d: vec![],
    };
    assert!(!c.is_done());
}

#[test]
fn composite_cursor_garbage_input_decodes_to_none() {
    assert!(super::decode_composite_cursor("not-a-cursor", Some(b"key")).is_none());
    assert!(super::decode_composite_cursor("c.bogus.bogus", Some(b"key")).is_none());
    assert!(super::decode_composite_cursor("c.bogus", None).is_none());
}

// --- P2.6 WatchEngine bootstrap --------------------------------------

#[test]
fn build_watch_configs_skips_bindings_without_uri() {
    use crate::config::{MockBackendConfig, ResourceWatchConfig, WatchStrategyConfig};

    let mut template_binding = sample_binding_mock("no-uri-template");
    template_binding.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Poll { interval_ms: 60 },
        notification_filter: None,
    });
    template_binding.uri = None;
    template_binding.uri_template = Some("res://{slug}".to_owned());

    let mut resource_binding = sample_binding_mock("has-uri");
    resource_binding.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Poll { interval_ms: 30 },
        notification_filter: None,
    });
    resource_binding.uri = Some("res://readme".to_owned());

    let configs = super::build_watch_configs(&[template_binding, resource_binding]);
    assert_eq!(configs.len(), 1, "template-only entries are skipped");
    assert!(configs.contains_key("res://readme"));
    let _ = MockBackendConfig {
        // keep import warning happy when features shift
        response: serde_json::json!(null),
        error: false,
        error_message: None,
        delay_ms: 0,
        passthrough: false,
    };
}

#[test]
fn build_watch_configs_maps_each_strategy_variant() {
    use crate::config::{ResourceWatchConfig, WatchStrategyConfig};

    let mut poll = sample_binding_mock("poll");
    poll.uri = Some("r://poll".into());
    poll.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Poll { interval_ms: 42 },
        notification_filter: None,
    });

    let mut webhook = sample_binding_mock("webhook");
    webhook.uri = Some("r://webhook".into());
    webhook.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Webhook {
            token: "t1".into(),
            previous_tokens: vec!["t0".into()],
        },
        notification_filter: None,
    });

    let mut nats = sample_binding_mock("nats");
    nats.uri = Some("r://nats".into());
    nats.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::NatsTopic {
            subject: "orders.changed".into(),
        },
        notification_filter: None,
    });

    let mut kafka = sample_binding_mock("kafka");
    kafka.uri = Some("r://kafka".into());
    kafka.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::KafkaTopic {
            topic: "events".into(),
            group_id: Some("grp".into()),
        },
        notification_filter: None,
    });

    let mut sql_poll = sample_binding_mock("sql_poll");
    sql_poll.uri = Some("r://sql_poll".into());
    let mut sql_spec = serde_json::Map::new();
    sql_spec.insert("driver".into(), serde_json::json!("postgres"));
    sql_spec.insert("url".into(), serde_json::json!("postgres://app@db/orders"));
    sql_spec.insert("interval_ms".into(), serde_json::json!(2_000));
    sql_poll.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::SqlPolling { spec: sql_spec },
        notification_filter: None,
    });

    let mut pg_listen = sample_binding_mock("pg_listen");
    pg_listen.uri = Some("r://pg_listen".into());
    pg_listen.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::PostgresListenNotify {
            url: "postgres://app@db/orders".into(),
            channel: "orders_changed".into(),
            uri_match: None,
        },
        notification_filter: None,
    });

    let configs = super::build_watch_configs(&[poll, webhook, nats, kafka, sql_poll, pg_listen]);
    assert_eq!(configs.len(), 6);

    match &configs["r://poll"].strategy {
        watch_engine::WatchStrategy::Poll { interval_ms } => {
            assert_eq!(*interval_ms, 42);
        }
        other => panic!("expected Poll, got {other:?}"),
    }
    match &configs["r://webhook"].strategy {
        watch_engine::WatchStrategy::Webhook {
            token,
            previous_tokens,
        } => {
            assert_eq!(token, "t1");
            assert_eq!(previous_tokens, &vec!["t0".to_owned()]);
        }
        other => panic!("expected Webhook, got {other:?}"),
    }
    match &configs["r://nats"].strategy {
        watch_engine::WatchStrategy::Plugin { kind, spec } => {
            assert_eq!(kind, "nats_topic");
            assert_eq!(spec["subject"], "orders.changed");
        }
        other => panic!("expected Plugin(nats_topic), got {other:?}"),
    }
    match &configs["r://kafka"].strategy {
        watch_engine::WatchStrategy::Plugin { kind, spec } => {
            assert_eq!(kind, "kafka_topic");
            assert_eq!(spec["topic"], "events");
            assert_eq!(spec["group_id"], "grp");
        }
        other => panic!("expected Plugin(kafka_topic), got {other:?}"),
    }
    match &configs["r://sql_poll"].strategy {
        watch_engine::WatchStrategy::Plugin { kind, spec } => {
            assert_eq!(kind, "sql_polling");
            assert_eq!(spec["driver"], "postgres");
            assert_eq!(spec["url"], "postgres://app@db/orders");
            assert_eq!(spec["interval_ms"], 2_000);
        }
        other => panic!("expected Plugin(sql_polling), got {other:?}"),
    }
    match &configs["r://pg_listen"].strategy {
        watch_engine::WatchStrategy::Plugin { kind, spec } => {
            assert_eq!(kind, "postgres_listen_notify");
            assert_eq!(spec["url"], "postgres://app@db/orders");
            assert_eq!(spec["channel"], "orders_changed");
        }
        other => panic!("expected Plugin(postgres_listen_notify), got {other:?}"),
    }
}

#[test]
fn watch_strategy_config_parses_sql_polling_yaml() {
    // Verify the operator-facing YAML shape: spec fields sit
    // alongside `type: sql_polling` (flat, no nested `spec:` key).
    use crate::config::WatchStrategyConfig;
    let yaml = r#"
type: sql_polling
driver: postgres
url: postgres://app@db/orders
interval_ms: 2000
query:
  sql: "SELECT MAX(updated_at) FROM orders"
  row_mode: scalar
"#;
    let parsed: WatchStrategyConfig = serde_yaml::from_str(yaml).unwrap();
    match parsed {
        WatchStrategyConfig::SqlPolling { spec } => {
            assert_eq!(spec.get("driver").unwrap(), "postgres");
            assert_eq!(spec.get("interval_ms").unwrap(), 2_000);
            assert!(spec.get("query").is_some());
        }
        other => panic!("expected SqlPolling, got {other:?}"),
    }
}

#[test]
fn watch_strategy_config_parses_postgres_listen_notify_yaml() {
    use crate::config::WatchStrategyConfig;
    let yaml = r#"
type: postgres_listen_notify
url: postgres://app@db/orders
channel: orders_changed
"#;
    let parsed: WatchStrategyConfig = serde_yaml::from_str(yaml).unwrap();
    match parsed {
        WatchStrategyConfig::PostgresListenNotify {
            url,
            channel,
            uri_match,
        } => {
            assert_eq!(url, "postgres://app@db/orders");
            assert_eq!(channel, "orders_changed");
            assert!(uri_match.is_none());
        }
        other => panic!("expected PostgresListenNotify, got {other:?}"),
    }
}

#[test]
fn the_short_postgres_listen_notify_form_passes_uri_match_to_the_plugin() {
    use crate::config::{ResourceWatchConfig, WatchStrategyConfig};
    let strategy: WatchStrategyConfig = serde_yaml::from_str(
        r#"
type: postgres_listen_notify
url: postgres://app@db/orders
channel: imd_refs
uri_match: { payload_field: u, uris: ["{value}"] }
"#,
    )
    .unwrap();
    let watch = ResourceWatchConfig {
        strategy,
        notification_filter: None,
    };
    let config = super::watch_config_for(&watch, "instruction://ins_a@latest");
    match config.strategy {
        watch_engine::WatchStrategy::Plugin { kind, spec } => {
            assert_eq!(kind, "postgres_listen_notify");
            assert_eq!(
                spec["uri_match"],
                serde_json::json!({ "payload_field": "u", "uris": ["{value}"] })
            );
        }
        other => panic!("expected Plugin, got {other:?}"),
    }
    assert!(
        serde_yaml::from_str::<WatchStrategyConfig>(
            "{ type: postgres_listen_notify, url: x, channel: c, uri_match: { field: u, uris: [x] } }"
        )
        .is_err(),
        "a mistyped uri_match key is refused"
    );
}

#[test]
fn extract_dynamic_list_bindings_picks_only_sql_resource_shapes() {
    use mcpg_plugin_backend_sql::config::{
        DriverKind, PoolConfig, QueryBody, QueryShape, RowMode, SqlBackendConfig,
    };

    let sql_spec = serde_json::to_value(SqlBackendConfig {
        driver: DriverKind::Sqlite,
        url: "sqlite::memory:".into(),
        pool: PoolConfig::default(),
        allow_private_backends: false,
        query: QueryShape {
            body: QueryBody::Sql {
                sql: "SELECT 1".into(),
            },
            params: vec![],
            param_exprs: std::collections::BTreeMap::new(),
            row_mode: RowMode::Scalar,
            max_rows: 1,
            timeout_ms: None,
            read_only: true,
            progress_heartbeat_ms: None,
            stream: None,
        },
        session_vars: std::collections::BTreeMap::new(),
        schema: Default::default(),
        circuit_breaker: None,
        list_query: None,
        r#await: None,
        isolation_level: None,
        cache: None,
        cost: None,
        auth: None,
        sqlite: None,
    })
    .unwrap();

    let mut resource_sql = sample_binding_mock("resource-sql");
    resource_sql.uri = Some("sql://doc".into());
    resource_sql.backend = crate::config::BackendImpl::from_typed("sql", sql_spec.clone());

    let mut template_sql = sample_binding_mock("template-sql");
    template_sql.uri_template = Some("sql://{slug}".into());
    template_sql.backend = crate::config::BackendImpl::from_typed("sql", sql_spec);

    let mut resource_mock = sample_binding_mock("resource-mock");
    resource_mock.uri = Some("mock://r".into());
    // mock backend stays as default Mock from helper.

    // tool-sql is intentionally NOT passed: extract_dynamic_list_bindings
    // takes only resources + resource-templates, so the dispatch
    // already happened at the call-site. The function under test only
    // filters resource-shaped bindings by backend kind.
    let resources = vec![resource_sql, resource_mock];
    let templates = vec![template_sql];
    // `sql` declares `dynamic_list: true`; `mock` does not. The predicate
    // mirrors the registry-backed `backend_profile(kind).dynamic_list` the
    // production caller supplies.
    let out = super::extract_dynamic_list_bindings(&resources, &templates, |kind| kind == "sql");
    // Only resource-sql + template-sql qualify:
    // - resource-mock routes through no plugin we list_resources against
    assert_eq!(out.len(), 2);
    assert!(out.iter().any(|(n, k)| n == "resource-sql" && k == "sql"));
    assert!(out.iter().any(|(n, k)| n == "template-sql" && k == "sql"));
}

#[test]
fn template_watch_configs_capture_template_bindings_for_lazy_synthesis() {
    use crate::config::{ResourceWatchConfig, WatchStrategyConfig};

    // A resource_templates[] binding: uri_template (no exact uri) + watch.
    let mut tmpl = sample_binding_mock("instruction_read");
    tmpl.uri = None;
    tmpl.uri_template = Some("instruction://{id}".into());
    tmpl.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Plugin {
            kind: "instruction_events".into(),
            spec: serde_json::Map::new(),
        },
        notification_filter: None,
    });

    // An exact-URI binding with watch — belongs to build_watch_configs.
    let mut exact = sample_binding_mock("static_res");
    exact.uri = Some("r://static".into());
    exact.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Poll { interval_ms: 10 },
        notification_filter: None,
    });

    // A template binding without watch — excluded from both maps.
    let mut no_watch = sample_binding_mock("plain_tmpl");
    no_watch.uri = None;
    no_watch.uri_template = Some("plain://{x}".into());

    let bindings = [tmpl, exact, no_watch];

    // build_watch_configs maps only the exact-URI binding; templates are skipped.
    let exact_map = super::build_watch_configs(&bindings);
    assert_eq!(exact_map.len(), 1);
    assert!(exact_map.contains_key("r://static"));

    // build_template_watch_configs captures only the watch-carrying template,
    // keyed by binding name (the `profile` a Template route carries).
    let tmpl_map = super::build_template_watch_configs(&bindings);
    assert_eq!(tmpl_map.len(), 1);
    let watch = tmpl_map
        .get("instruction_read")
        .expect("template watch keyed by binding name");

    // watch_config_for synthesizes the concrete-URI config with the template's
    // strategy — exactly what the subscribe-time probe does on a matched URI.
    let cfg = super::watch_config_for(watch, "instruction://ins_x");
    assert_eq!(cfg.uri, "instruction://ins_x");
    match &cfg.strategy {
        watch_engine::WatchStrategy::Plugin { kind, .. } => {
            assert_eq!(kind, "instruction_events");
        }
        other => panic!("expected the template's Plugin strategy, got {other:?}"),
    }
}

#[test]
fn build_watch_configs_compiles_expression_filter() {
    use crate::config::{NotificationFilterConfig, ResourceWatchConfig, WatchStrategyConfig};

    let mut b = sample_binding_mock("cel");
    b.uri = Some("r://cel".into());
    b.watch = Some(ResourceWatchConfig {
        strategy: WatchStrategyConfig::Poll { interval_ms: 60 },
        notification_filter: Some(NotificationFilterConfig::Expression {
            expression: "subscriber.trust_level == \"verified\"".into(),
        }),
    });

    let configs = super::build_watch_configs(&[b]);
    let wc = &configs["r://cel"];
    assert!(
        wc.compiled_filter_program.is_some(),
        "Expression-mode filter must be pre-compiled"
    );
}

fn sample_binding_mock(name: &str) -> crate::config::BackendConfig {
    crate::config::BackendConfig {
        name: name.to_owned(),
        title: None,
        description: String::new(),
        input_schema: None,
        output_schema: None,
        backend: crate::config::BackendImpl::from_typed(
            "mock",
            crate::config::MockBackendConfig {
                response: serde_json::json!(null),
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: Default::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        uri_template: None,
        variable_completions: None,
        watch: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }
}

/// Build a `kind: Resource` Mock binding whose response is a
/// well-formed `{contents: [{uri, text, mimeType}]}` payload — the
/// shape `decode_resource_result` expects to round-trip out of
/// `dispatch_tool_call`.
fn sample_resource_binding(name: &str, uri: &str, text: &str) -> crate::config::BackendConfig {
    let response = serde_json::json!({
        "contents": [
            {
                "uri": uri,
                "text": text,
                "mimeType": "text/plain",
            }
        ]
    });
    crate::config::BackendConfig {
        name: name.to_owned(),
        title: None,
        description: String::new(),
        input_schema: None,
        output_schema: None,
        backend: crate::config::BackendImpl::from_typed(
            "mock",
            crate::config::MockBackendConfig {
                response,
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: Default::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: Some(uri.to_owned()),
        mime_type: Some("text/plain".to_owned()),
        uri_template: None,
        variable_completions: None,
        watch: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }
}

/// Build a runtime fetcher closure given a list of configured
/// resource bindings; mirrors the wiring inside
/// `try_new_with_runtime_controls_and_cache`.
fn build_test_fetcher(
    bindings: &[crate::config::BackendConfig],
) -> Arc<dyn Fn(&str) -> Option<String> + Send + Sync> {
    use crate::backends::{DebugToolBackends, DebugToolExposure};
    use crate::runtime::execution::{ExecutionDispatcher, RuntimeDebugConfig};
    // Resource fixtures are mock- or http-backed; register those in-tree
    // plugins + their per-binding profiles so the fetcher's dispatch resolves
    // (the bare dispatcher bypasses the Runtime's #[cfg(test)] fallback).
    let mut plugin_registry = mcpg_plugin_host::PluginRegistry::new();
    register_test_backend(
        &mut plugin_registry,
        "mock",
        mcpg_plugin_backend_mock::BINDING_DESCRIPTOR_YAML,
        &[],
        Arc::new(mcpg_plugin_backend_mock::MockBackendPlugin::new()),
        bindings,
    );
    register_test_backend(
        &mut plugin_registry,
        "http",
        mcpg_plugin_backend_http::BINDING_DESCRIPTOR_YAML,
        &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
        Arc::new(mcpg_plugin_backend_http::HttpBackendPlugin::new()),
        bindings,
    );
    let plugin_registry = Arc::new(plugin_registry);
    let registry = Arc::new(CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        bindings,
        &[],
        Some(plugin_registry.as_ref()),
    ));
    let mut dispatcher =
        ExecutionDispatcher::from_runtime_debug_config(RuntimeDebugConfig::default(), bindings);
    dispatcher.set_plugin_registry(Arc::clone(&plugin_registry));
    let dispatcher = Arc::new(dispatcher);
    build_watch_resource_fetcher(registry, dispatcher)
}

/// Register `plugin` for `kind`, with the capabilities a `plugins[]` entry
/// would grant it, and the profile of every binding of that kind.
fn register_test_backend<P: mcpg_plugin_protocol::BackendPlugin + 'static>(
    plugin_registry: &mut mcpg_plugin_host::PluginRegistry,
    kind: &str,
    descriptor_yaml: &str,
    granted: &[mcpg_plugin_protocol::capability::Capability],
    plugin: Arc<P>,
    bindings: &[crate::config::BackendConfig],
) {
    let kind_bindings: Vec<&crate::config::BackendConfig> =
        bindings.iter().filter(|b| b.backend.kind == kind).collect();
    if kind_bindings.is_empty() {
        return;
    }
    mcpg_plugin_host::FirstPartyRegistrar::new(plugin_registry)
        .register(descriptor_yaml, granted, (), |reg, _host| {
            reg.register_backend(plugin.clone(), mcpg_plugin_protocol::PluginTier::Native)
        })
        .unwrap_or_else(|e| panic!("register {kind} plugin: {e}"));
    let host = mcpg_plugin_protocol::noop_backend_host();
    for binding in kind_bindings {
        if let Some(spec) = crate::backends::dynamic_register_spec(&binding.backend, true) {
            futures::executor::block_on(mcpg_plugin_protocol::BackendPlugin::register_profile(
                plugin.as_ref(),
                &binding.name,
                &spec,
                host.clone(),
            ))
            .unwrap_or_else(|e| panic!("register {kind} profile {}: {e:?}", binding.name));
        }
    }
}

#[tokio::test]
async fn watch_fetcher_returns_text_for_known_resource() {
    let bindings = vec![sample_resource_binding(
        "greeting",
        "test://greeting",
        "hello",
    )];
    let fetcher = build_test_fetcher(&bindings);
    let content = fetcher("test://greeting");
    assert_eq!(content.as_deref(), Some("hello"));
}

#[tokio::test]
async fn watch_fetcher_detects_content_change() {
    // Two separate fetcher instances back two different in-memory
    // resource snapshots — simulates the operator updating the
    // backend between poll ticks. Hash differs, so the WatchEngine
    // would emit `resources/updated`.
    let v1 = vec![sample_resource_binding("greet", "test://greet", "hello")];
    let v2 = vec![sample_resource_binding("greet", "test://greet", "world")];
    let f1 = build_test_fetcher(&v1);
    let f2 = build_test_fetcher(&v2);
    let c1 = f1("test://greet").expect("v1 content");
    let c2 = f2("test://greet").expect("v2 content");
    assert_ne!(
        c1, c2,
        "fetcher must surface backend content changes so the \
         WatchEngine can detect them via hash compare"
    );
}

#[tokio::test]
async fn watch_fetcher_returns_none_for_unknown_uri() {
    let bindings = vec![sample_resource_binding(
        "greeting",
        "test://greeting",
        "hello",
    )];
    let fetcher = build_test_fetcher(&bindings);
    let content = fetcher("test://does-not-exist");
    assert_eq!(content, None);
}

#[tokio::test]
async fn watch_fetcher_returns_none_for_runtime_overview() {
    // The synthetic runtime overview surface is not watchable.
    let fetcher = build_test_fetcher(&[]);
    let content = fetcher("mcpg://runtime/overview");
    assert_eq!(content, None);
}

/// A watched `http` resource polls its upstream's body, as a read serves it.
#[tokio::test]
async fn watch_fetcher_polls_the_body_of_an_http_resource() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener bound");
    let addr = listener.local_addr().expect("local addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buffer = [0_u8; 1024];
        let count = stream.read(&mut buffer).expect("read request");
        let request = String::from_utf8_lossy(&buffer[..count]).to_string();
        assert!(request.starts_with("GET /notes/today"), "{request}");
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\n# Today";
        stream.write_all(response).expect("write response");
    });
    let binding: crate::config::BackendConfig = serde_json::from_value(serde_json::json!({
        "name": "notes",
        "description": "Today's notes.",
        "uri": "notes://today",
        "backend": {
            "kind": "http",
            "url": format!("http://{addr}/notes/today"),
            "method": "get",
        },
    }))
    .expect("resource binding");

    let fetcher = build_test_fetcher(&[binding]);
    assert_eq!(fetcher("notes://today").as_deref(), Some("# Today"));
    server.join().expect("server joined");
}

// ── MCP Apps: resources/read `_meta.ui` passthrough ──────────

#[test]
fn federated_resource_read_preserves_ui_meta() {
    // An upstream `ui://` read result carrying `_meta.ui` (CSP +
    // permissions) must survive MCPG's federated read mapping — the
    // host needs it to build the iframe CSP.
    let upstream = serde_json::json!({
        "contents": [{
            "uri": "ui://srv/chart",
            "mimeType": "text/html;profile=mcp-app",
            "text": "<html></html>",
            "_meta": {
                "ui": {
                    "csp": { "connectDomains": ["api.example.com"] },
                    "permissions": { "camera": {} }
                }
            }
        }]
    });
    let result = super::federated_resource_read_result(upstream);
    let v = serde_json::to_value(&result).expect("serialize read result");
    let content = &v["contents"][0];
    // mimeType preserved byte-exact (the `;profile=mcp-app` parameter
    // is load-bearing).
    assert_eq!(content["mimeType"], "text/html;profile=mcp-app");
    // `_meta.ui` preserved.
    assert_eq!(
        content["_meta"]["ui"]["csp"]["connectDomains"],
        serde_json::json!(["api.example.com"])
    );
    assert!(content["_meta"]["ui"]["permissions"]["camera"].is_object());
}

// ── MCP Apps: tools/list offered-apps audit scan ────

#[test]
fn apps_offered_from_tools_picks_ui_enabled_tools() {
    let mk = |name: &str, meta: Option<serde_json::Value>| crate::backends::ToolDescriptor {
        name: name.to_owned(),
        title: None,
        description: String::new(),
        input_schema: serde_json::json!({ "type": "object" }),
        output_schema: None,
        annotations: None,
        execution: None,
        icons: None,
        meta,
    };
    let tools = vec![
        // UI-enabled (nested form)
        mk(
            "chart",
            Some(serde_json::json!({ "ui": { "resourceUri": "ui://srv/chart" } })),
        ),
        // plain tool, no _meta.ui
        mk(
            "search",
            Some(serde_json::json!({ "mcpg": { "source": "x" } })),
        ),
        // no _meta at all
        mk("ping", None),
        // deprecated flat alias
        mk(
            "legacy",
            Some(serde_json::json!({ "ui/resourceUri": "ui://srv/legacy" })),
        ),
    ];
    let offered = super::apps_offered_from_tools(&tools);
    assert_eq!(offered.len(), 2);
    assert_eq!(
        offered[0],
        serde_json::json!({ "tool": "chart", "resourceUri": "ui://srv/chart" })
    );
    assert_eq!(
        offered[1],
        serde_json::json!({ "tool": "legacy", "resourceUri": "ui://srv/legacy" })
    );
}

#[test]
fn apps_offered_from_tools_empty_when_no_ui_tools() {
    let plain = vec![crate::backends::ToolDescriptor {
        name: "x".to_owned(),
        title: None,
        description: String::new(),
        input_schema: serde_json::json!({}),
        output_schema: None,
        annotations: None,
        execution: None,
        icons: None,
        meta: None,
    }];
    assert!(super::apps_offered_from_tools(&plain).is_empty());
}

// Deterministic synthetic session id derivation.
#[test]
fn derive_synthetic_session_id_is_deterministic_and_principal_scoped() {
    let key = [7u8; 32];
    let a1 = GatewayRuntime::derive_synthetic_session_id(&key, "user:alice");
    let a2 = GatewayRuntime::derive_synthetic_session_id(&key, "user:alice");
    // Same key + principal → same id on every replica.
    assert_eq!(a1, a2);
    // Namespaced + hex-encoded HMAC: "mcpg-m-" + 64 hex chars.
    assert!(a1.starts_with("mcpg-m-"), "got {a1}");
    assert_eq!(a1.len(), "mcpg-m-".len() + 64);
    assert!(a1["mcpg-m-".len()..].bytes().all(|b| b.is_ascii_hexdigit()));
    // Different principal → different id (no cross-principal collision).
    let b = GatewayRuntime::derive_synthetic_session_id(&key, "user:bob");
    assert_ne!(a1, b);
}

#[test]
fn derive_synthetic_session_id_changes_with_the_key() {
    // The id is an HMAC, not a bare hash: a client that knows the principal
    // id but not the (deployment-shared, secret) key cannot compute it.
    let id_k1 = GatewayRuntime::derive_synthetic_session_id(&[1u8; 32], "user:alice");
    let id_k2 = GatewayRuntime::derive_synthetic_session_id(&[2u8; 32], "user:alice");
    assert_ne!(id_k1, id_k2);
}

/// The derived id is the lowercase hex HMAC-SHA256 over the domain prefix,
/// the principal key and the client the request names.
#[test]
fn derived_session_ids_keep_their_bytes() {
    assert_eq!(
        GatewayRuntime::derive_synthetic_session_id(&[7u8; 32], "verified::p::i::alice"),
        "mcpg-m-8732e1b1170bf0cdefaffa7aa2b0bc513c40ee3b67d79dd8fbe712e08086c0f7"
    );
    let mut config = crate::config::AppConfig::default();
    // Bytes 0..32.
    config.mcp.configurations.sessions.synthetic_session_key =
        Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned());
    let runtime = test_runtime();
    runtime.set_shared_services(Arc::new(shared_services::SharedServices::for_tests(
        Arc::new(config),
    )));
    let session = |client: Option<&str>| {
        let mut context = request_context(verified("alice"));
        context.client = client.map(|name| mcpg_plugin_protocol::ClientInfo {
            name: name.to_owned(),
            version: None,
        });
        match runtime.ensure_session(context) {
            SessionOutcome::Ready(bound) => bound.session_id.expect("a derived session"),
            SessionOutcome::CapacityExhausted => panic!("the session store has room"),
        }
    };
    assert_eq!(
        session(None),
        "mcpg-m-0d7d7e2f304a538177fd2b4cf2891c94e0b2b648d4e9c784e9ed93e66b72144e"
    );
    assert_eq!(
        session(Some("claude")),
        "mcpg-m-f7d138cb8e386ea23c1f523f6b50b5fe9b87a618405a4a33b150ed648fce6bb6"
    );
}

#[tokio::test]
async fn gateway_apps_listed_and_read_end_to_end() {
    // Templated-app integration: a registered templated app must appear in
    // resources/list and serve its authored HTML + _meta.ui on resources/read.
    let mut runtime = GatewayRuntime::new(
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
    );

    let apps_cfg: crate::config::apps::AppsConfig = serde_yaml::from_str(
        "enabled: true\nregistry:\n  - { id: customers, kind: table, title: Customers, data_tool: crm.list, columns: [{ field: $.name, header: Name }] }\n",
    )
    .unwrap();
    runtime.set_apps_config(
        apps_cfg.federate_upstream_enabled(),
        Some(apps_cfg.compiled_policy()),
        &apps_cfg.registry,
    );
    let gateway = serve(runtime);

    // resources/list includes the gateway app descriptor
    let list = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {} }),
        )
        .await,
    );
    let found = list["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .find(|r| r["uri"] == "ui://mcpg/customers")
        .expect("gateway app listed");
    assert_eq!(found["mimeType"], "text/html;profile=mcp-app");

    // resources/read serves the authored body + clamped _meta.ui
    let read = success_result(
        send(
            &gateway,
            header_asserted("user-1"),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": { "uri": "ui://mcpg/customers" },
            }),
        )
        .await,
    );
    let content = &read["contents"][0];
    assert_eq!(content["uri"], "ui://mcpg/customers");
    assert_eq!(content["mimeType"], "text/html;profile=mcp-app");
    assert_eq!(content["_meta"]["ui"]["resourceUri"], "ui://mcpg/customers");
    let html = content["text"].as_str().expect("html body");
    assert!(
        html.contains("id=\"mcpg-app-config\""),
        "data island present"
    );
    assert!(
        html.contains("\"kind\":\"table\""),
        "compiled binding injected"
    );
}

/// A pre gate that asks for an approval on every request.
struct ApprovalGate(mcpg_plugin_protocol::PluginManifest);

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::ToolGatePlugin for ApprovalGate {
    fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
        &self.0
    }

    async fn evaluate_pre_dispatch(
        &self,
        _ctx: &mcpg_plugin_protocol::PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> mcpg_plugin_protocol::GateDecision {
        mcpg_plugin_protocol::GateDecision::PendingApproval {
            approval_id: "appr_test".to_owned(),
            deadline_at: "2099-01-01T00:00:00Z".to_owned(),
            summary: "needs a human".to_owned(),
            target_notifiers: Vec::new(),
            metadata: None,
        }
    }
}

#[tokio::test]
async fn a_surface_gate_that_cannot_wait_refuses_a_pending_approval() {
    let mut runtime = GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        Vec::new(),
        true,
    );
    let mut registry = mcpg_plugin_host::PluginRegistry::new();
    registry
        .register_tool_gate(
            Box::new(ApprovalGate(mcpg_plugin_protocol::PluginManifest {
                id: "test.gate.approval".to_owned(),
                version: "0.1.0".to_owned(),
                name: "Approval gate".to_owned(),
                plugin_class: mcpg_plugin_protocol::PluginClass::ToolGate,
                protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION.to_owned(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: module_path!().split("::").next().unwrap_or("").to_owned(),
                backend_profile: None,
            })),
            mcpg_plugin_protocol::PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
    runtime.plugin_registry = Arc::new(registry);
    let ctx = request_context(RequestIdentity::Verified {
        subject_id: "alice".to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: "test".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: Default::default(),
    });
    let arguments = serde_json::json!({});
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        runtime.evaluate_surface_gate_without_waiting(
            "event",
            "event.poll.pre",
            "event:orders.created",
            crate::runtime::policy::PolicyRoute::event(Some(&arguments)),
            &arguments,
            &ctx,
            &serde_json::Value::Null,
        ),
    )
    .await
    .expect("it answers at once")
    .unwrap_err();
    assert_eq!(refused.http_status, 403);
    let crate::protocol::ProtocolResponse::JsonRpcError(error) = refused.response else {
        panic!("a JSON-RPC error");
    };
    assert_eq!(error.error.code, super::policy_eval::APPROVAL_REQUIRED_CODE);
    assert_eq!(
        error.error.data.unwrap()["reason"],
        serde_json::json!("approval_required")
    );
}
