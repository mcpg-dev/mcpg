use crate::config::BackendImpl;
use chrono::Utc;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use super::*;
use crate::{
    backends::{
        DEFAULT_COMMAND_PROFILE, DEFAULT_NETWORK_PROFILE, DebugToolBackends, DebugToolExposure,
    },
    config::{BackendGovernanceConfig, KafkaBackendConfig},
    runtime::{
        GatewayRequestId, LoggingSnapshot, ReadinessSnapshot, ReadinessStatus, RequestIdentity,
        TransportKind,
    },
};

fn command_profiles(
    profile: CommandToolRuntimeConfig,
) -> std::collections::BTreeMap<String, CommandToolRuntimeConfig> {
    std::collections::BTreeMap::from([(DEFAULT_COMMAND_PROFILE.to_owned(), profile)])
}

fn network_profiles(
    profile: NetworkToolRuntimeConfig,
) -> std::collections::BTreeMap<String, NetworkToolRuntimeConfig> {
    std::collections::BTreeMap::from([(DEFAULT_NETWORK_PROFILE.to_owned(), profile)])
}

fn sample_request() -> BackendInvocationRequest {
    let ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        Some("session-1".to_owned()),
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    let expr_ctx = ctx.to_expr_context("mcpg.runtime.snapshot", Some(&serde_json::json!({})));
    BackendInvocationRequest {
        context: ctx,
        tool_name: "mcpg.runtime.snapshot".to_owned(),
        arguments: Some(serde_json::json!({})),
        expr_ctx,
        progress_token: None,
        request_log_level: None,
        legacy_session_log_level: None,
        client_capabilities: crate::protocol::ClientCapabilities::default(),
        cancellation_token: None,
        idempotency_hint: None,
    }
}

fn sample_snapshot() -> RuntimeSnapshot {
    RuntimeSnapshot {
        service: "mcpg".to_owned(),
        version: "0.1.0".to_owned(),
        started_at: Utc::now(),
        uptime_secs: 0,
        bind_address: "127.0.0.1:8787".to_owned(),
        health_path: "/health".to_owned(),
        mcp_path: "/mcp".to_owned(),
        logging: LoggingSnapshot {
            level: "info".to_owned(),
            sinks: vec!["stdout".to_owned()],
            initialized: true,
        },
        readiness: ReadinessSnapshot {
            status: ReadinessStatus::Ready,
            checks: vec![],
        },
        plugins: crate::runtime::PluginSnapshot {
            total_count: 0,
            loaded: vec![],
        },
    }
}

#[test]
fn dispatcher_routes_runtime_snapshot_tool() {
    let dispatcher = ExecutionDispatcher::default();
    let mut request = sample_request();
    request.context.identity = crate::runtime::RequestIdentity::HttpHeader {
        subject_id: "user-1".to_owned(),
        source: "x-mcpg-subject-id".to_owned(),
    };
    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::RuntimeSnapshot,
        &request,
        Some(sample_snapshot()),
    );

    assert_eq!(result.content.len(), 1);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert_eq!(
                text,
                "Returned current MCPG runtime snapshot for tool mcpg.runtime.snapshot."
            );
        }
        _ => panic!("unexpected content type"),
    }
    assert_eq!(
        result.structured_content.expect("structured content")["service"],
        "mcpg"
    );
}

#[test]
fn dispatcher_routes_adapter_backed_request_echo_tool() {
    let dispatcher = ExecutionDispatcher::default();
    let mut request = sample_request();
    request.tool_name = "mcpg.request.echo".to_owned();
    request.arguments = Some(serde_json::json!({
        "message": "hello"
    }));
    request.context.identity = crate::runtime::RequestIdentity::HttpHeader {
        subject_id: "user-1".to_owned(),
        source: "x-mcpg-subject-id".to_owned(),
    };

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::RequestEcho,
        &request,
        Some(sample_snapshot()),
    );

    assert_eq!(result.content.len(), 1);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("adapter-facing seam"));
        }
        _ => panic!("unexpected content type"),
    }
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["toolName"], "mcpg.request.echo");
    assert_eq!(structured["arguments"]["message"], "hello");
    assert_eq!(structured["request"]["principalId"], "user-1");
    assert_eq!(structured["runtime"]["service"], "mcpg");
}

#[test]
fn dispatcher_routes_command_probe_tool() {
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: command_profiles(CommandToolRuntimeConfig {
                command: "printf".to_owned(),
                args: vec!["command-ok".to_owned()],
                timeout_ms: 2_000,
                max_output_bytes: 4_096,
            }),
            network_profiles: network_profiles(NetworkToolRuntimeConfig::default()),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.command_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::CommandProbe {
            profile: DEFAULT_COMMAND_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(!result.is_error);
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["stdout"], "command-ok");
    assert_eq!(structured["success"], true);
}

#[test]
fn dispatcher_marks_command_probe_timeout_explicitly() {
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: command_profiles(CommandToolRuntimeConfig {
                command: "sleep".to_owned(),
                args: vec!["1".to_owned()],
                timeout_ms: 20,
                max_output_bytes: 4_096,
            }),
            network_profiles: network_profiles(NetworkToolRuntimeConfig::default()),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.command_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::CommandProbe {
            profile: DEFAULT_COMMAND_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["timedOut"], true);
}

#[test]
fn dispatcher_marks_command_probe_truncation_explicitly() {
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: command_profiles(CommandToolRuntimeConfig {
                command: "printf".to_owned(),
                args: vec!["abcdef".to_owned()],
                timeout_ms: 2_000,
                max_output_bytes: 3,
            }),
            network_profiles: network_profiles(NetworkToolRuntimeConfig::default()),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.command_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::CommandProbe {
            profile: DEFAULT_COMMAND_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["stdout"], "abc");
    assert_eq!(structured["stdoutTruncated"], true);
}

#[test]
fn dispatcher_routes_network_probe_tool() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener bound");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buffer = [0_u8; 512];
        let _ = stream.read(&mut buffer);
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnetwork-ok";
        stream.write_all(response).expect("write response");
    });

    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: command_profiles(CommandToolRuntimeConfig::default()),
            network_profiles: network_profiles(NetworkToolRuntimeConfig {
                url: format!("http://{}/probe", addr),
                timeout_ms: 2_000,
                max_response_bytes: 4_096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: std::collections::BTreeMap::new(),
                allow_private_backends: true,
            }),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.network_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::NetworkProbe {
            profile: DEFAULT_NETWORK_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    server.join().expect("server joined");
    assert!(!result.is_error);
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["statusCode"], 200);
    assert_eq!(structured["responseContentType"], "text/plain");
    assert_eq!(structured["body"], "network-ok");
}

#[test]
fn dispatcher_marks_network_probe_truncation_explicitly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener bound");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buffer = [0_u8; 512];
        let _ = stream.read(&mut buffer);
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabcdefghij";
        stream.write_all(response).expect("write response");
    });

    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: command_profiles(CommandToolRuntimeConfig::default()),
            network_profiles: network_profiles(NetworkToolRuntimeConfig {
                url: format!("http://{}/probe", addr),
                timeout_ms: 2_000,
                max_response_bytes: 5,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: std::collections::BTreeMap::new(),
                allow_private_backends: true,
            }),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.network_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::NetworkProbe {
            profile: DEFAULT_NETWORK_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    server.join().expect("server joined");
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["body"], "abcde");
    assert_eq!(structured["bodyTruncated"], true);
}

#[test]
fn dispatcher_reports_missing_command_profile() {
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            enabled: true,
            command_profiles: std::collections::BTreeMap::new(),
            network_profiles: network_profiles(NetworkToolRuntimeConfig::default()),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        &[],
    );
    let mut request = sample_request();
    request.tool_name = "mcpg.debug.command_probe".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::CommandProbe {
            profile: DEFAULT_COMMAND_PROFILE.to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["error"], "missing_profile");
    assert_eq!(structured["profile"], DEFAULT_COMMAND_PROFILE);
}

#[derive(Debug)]
struct TestAdapterExecutor;

impl ToolExecutionAdapter for TestAdapterExecutor {
    fn execute(
        &self,
        route: AdapterToolRoute,
        request: &BackendInvocationRequest,
        _execution_context: &ToolExecutionContext,
    ) -> ToolCallResult {
        let route_name = match route {
            AdapterToolRoute::RequestEcho => "request_echo",
            AdapterToolRoute::CommandProbe { .. } => "command_probe",
            AdapterToolRoute::CommandJsonCall { .. } => "command_json_call",
            AdapterToolRoute::NetworkProbe { .. } => "network_probe",
            AdapterToolRoute::NetworkJsonCall { .. } => "network_json_call",
            AdapterToolRoute::NetworkQueryCall { .. } => "network_query_call",
            AdapterToolRoute::NatsRequest { .. } => "nats_request",
            AdapterToolRoute::GraphqlCall { .. } => "graphql_call",
            AdapterToolRoute::KafkaRequest { .. } => "kafka_request",
            AdapterToolRoute::MockResponse { .. } => "mock_response",
            AdapterToolRoute::Pipeline { .. } => "pipeline",
            AdapterToolRoute::SqlRequest { .. } => "sql_request",
            AdapterToolRoute::OpenapiCall { .. } => "openapi_call",
            AdapterToolRoute::LlmRequest { .. } => "llm_request",
            AdapterToolRoute::EnvelopePlugin { .. } => "envelope_plugin",
        };

        ToolCallResult {
            content: vec![ToolContent::text(format!(
                "custom adapter handled {}",
                request.tool_name
            ))],
            structured_content: Some(serde_json::json!({
                "route": route_name,
                "toolName": request.tool_name,
                "handledBy": "test_adapter"
            })),
            is_error: false,
            meta: None,
        }
    }
}

#[test]
fn dispatcher_can_inject_custom_adapter_executor() {
    let dispatcher = ExecutionDispatcher::with_adapter_executor(Arc::new(TestAdapterExecutor));
    let mut request = sample_request();
    request.tool_name = "mcpg.request.echo".to_owned();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::RequestEcho,
        &request,
        Some(sample_snapshot()),
    );

    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("custom adapter handled mcpg.request.echo"));
        }
        _ => panic!("unexpected content type"),
    }
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["handledBy"], "test_adapter");
    assert_eq!(structured["route"], "request_echo");
}

// ---- Cross-family substrate tests ----

#[test]
fn promoted_tool_result_envelope_carries_shared_keys() {
    let envelope = BackendResultEnvelope {
        tool_name: "test.tool".to_owned(),
        profile: "test-profile".to_owned(),
        request_kind: "test_kind".to_owned(),
        request: serde_json::json!({"kind": "test_kind"}),
        response: Some(serde_json::json!({"status": 200})),
        primary_error_key: "primaryError".to_owned(),
        primary_error: None,
        errors_key: "errors".to_owned(),
        errors: serde_json::json!([]),
        error: None,
        family_fields: serde_json::json!({"familySpecific": true}),
    };
    let value = envelope.into_value();

    assert_eq!(value["toolName"], "test.tool");
    assert_eq!(value["profile"], "test-profile");
    assert_eq!(value["requestKind"], "test_kind");
    assert_eq!(value["request"]["kind"], "test_kind");
    assert_eq!(value["response"]["status"], 200);
    assert!(value["primaryError"].is_null());
    assert_eq!(value["errors"], serde_json::json!([]));
    assert!(value["error"].is_null());
    assert_eq!(value["familySpecific"], true);
}

#[test]
fn promoted_tool_result_envelope_merges_family_fields_at_top_level() {
    let envelope = BackendResultEnvelope {
        tool_name: "t".to_owned(),
        profile: "p".to_owned(),
        request_kind: "k".to_owned(),
        request: serde_json::json!({}),
        response: None,
        primary_error_key: "err".to_owned(),
        primary_error: Some(serde_json::json!({"kind": "timeout"})),
        errors_key: "errs".to_owned(),
        errors: serde_json::json!([{"kind": "timeout"}]),
        error: Some("fail".to_owned()),
        family_fields: serde_json::json!({
            "url": "http://example.com",
            "timeoutMs": 5000,
        }),
    };
    let value = envelope.into_value();

    assert_eq!(value["err"]["kind"], "timeout");
    assert_eq!(value["errs"][0]["kind"], "timeout");
    assert_eq!(value["error"], "fail");
    assert_eq!(value["url"], "http://example.com");
    assert_eq!(value["timeoutMs"], 5000);
}

#[test]
fn http_and_command_envelopes_share_cross_family_structure() {
    // Build an HTTP-family envelope
    let http_envelope = BackendResultEnvelope {
        tool_name: "mcpg.http.json_call".to_owned(),
        profile: "net-profile".to_owned(),
        request_kind: "json_body".to_owned(),
        request: serde_json::json!({"kind": "json_body", "body": {"x": 1}}),
        response: Some(serde_json::json!({"statusCode": 200})),
        primary_error_key: "downstreamError".to_owned(),
        primary_error: None,
        errors_key: "downstreamErrors".to_owned(),
        errors: serde_json::json!([]),
        error: None,
        family_fields: serde_json::json!({"url": "http://localhost"}),
    }
    .into_value();

    // Build a command-family envelope
    let cmd_envelope = BackendResultEnvelope {
        tool_name: "mcpg.command.json_call".to_owned(),
        profile: "cmd-profile".to_owned(),
        request_kind: "json_stdin".to_owned(),
        request: serde_json::json!({"kind": "json_stdin", "body": {"x": 1}}),
        response: Some(serde_json::json!({"exitCode": 0})),
        primary_error_key: "commandError".to_owned(),
        primary_error: None,
        errors_key: "commandErrors".to_owned(),
        errors: serde_json::json!([]),
        error: None,
        family_fields: serde_json::json!({"command": "cat"}),
    }
    .into_value();

    // Both share the same cross-family top-level keys
    let shared_keys = [
        "toolName",
        "profile",
        "requestKind",
        "request",
        "response",
        "error",
    ];
    for key in &shared_keys {
        assert!(
            http_envelope.get(key).is_some(),
            "HTTP envelope missing shared key: {key}"
        );
        assert!(
            cmd_envelope.get(key).is_some(),
            "command envelope missing shared key: {key}"
        );
    }

    // Family-specific keys differ
    assert!(http_envelope.get("downstreamError").is_some());
    assert!(http_envelope.get("url").is_some());
    assert!(cmd_envelope.get("commandError").is_some());
    assert!(cmd_envelope.get("command").is_some());

    // Families don't leak into each other
    assert!(http_envelope.get("commandError").is_none());
    assert!(cmd_envelope.get("downstreamError").is_none());
}

#[test]
fn binding_kind_returns_debug_tool_for_mcpg_prefixed_names() {
    assert_eq!(backend_kind("mcpg.runtime.snapshot"), "debug_tool");
    assert_eq!(backend_kind("mcpg.debug.command_probe"), "debug_tool");
    assert_eq!(backend_kind("mcpg.debug.network_probe"), "debug_tool");
    assert_eq!(backend_kind("mcpg.debug.network_json_call"), "debug_tool");
    assert_eq!(backend_kind("mcpg.request.echo"), "debug_tool");
}

#[test]
fn binding_kind_returns_operator_binding_for_non_mcpg_names() {
    assert_eq!(backend_kind("my.http.api"), "operator_binding");
    assert_eq!(backend_kind("search.tool"), "operator_binding");
    assert_eq!(backend_kind("org.tools.query"), "operator_binding");
}

#[test]
fn nats_request_without_manager_returns_error() {
    let request = sample_request();
    let result = execute_nats_request("nats-profile", &request, None);
    assert!(result.is_error);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("NATS binding plugin not registered"));
        }
        _ => panic!("unexpected content type"),
    }
}

#[test]
fn nats_route_dispatched_via_adapter_without_manager_returns_error() {
    let dispatcher = ExecutionDispatcher::default();
    let request = sample_request();
    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::NatsRequest {
            profile: "nats-profile".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );
    assert!(result.is_error);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("NATS binding plugin not registered"));
        }
        _ => panic!("unexpected content type"),
    }
}

// --- Kafka binding dispatch test (no broker available) ---

#[test]
fn dispatcher_kafka_call_without_manager_returns_error() {
    let kafka_binding = BackendConfig {
        name: "event.publish".to_owned(),
        title: None,
        description: "Publish event via Kafka".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "kafka",
            KafkaBackendConfig {
                bootstrap_servers: "localhost:9092".to_owned(),
                group_id: "mcpg".to_owned(),
                request_topic: "requests".to_owned(),
                response_topic: "responses".to_owned(),
                timeout_ms: 10000,
                max_response_bytes: 65536,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        watch: None,
        uri_template: None,
        variable_completions: None,
        annotations: None,
        output_schema: None,
        task_support: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    };

    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[kafka_binding],
    );
    let mut request = sample_request();
    request.tool_name = "event.publish".to_owned();
    request.arguments = Some(serde_json::json!({"event": "order_placed"}));

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::KafkaRequest {
            profile: "event.publish".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("Kafka binding plugin not registered"));
        }
        _ => panic!("unexpected content type"),
    }
}

// --- Pipeline execution tests ---

use crate::config::{
    BackendConfig, MockBackendConfig, PipelineBackendConfig, PipelineCelGateStepConfig,
    PipelineStepConfig, PipelineTransformStepConfig,
};

fn mock_step(id: &str, response: serde_json::Value) -> PipelineStepConfig {
    PipelineStepConfig::backend_from_typed(
        id.to_owned(),
        "mock",
        MockBackendConfig {
            response,
            delay_ms: 0,
            error: false,
            error_message: None,
            passthrough: false,
        },
        None,
    )
}

fn error_mock_step(id: &str, msg: &str) -> PipelineStepConfig {
    PipelineStepConfig::backend_from_typed(
        id.to_owned(),
        "mock",
        MockBackendConfig {
            response: serde_json::json!(null),
            delay_ms: 0,
            error: true,
            error_message: Some(msg.to_owned()),
            passthrough: false,
        },
        None,
    )
}

fn pipeline_binding(name: &str, steps: Vec<PipelineStepConfig>) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: None,
        description: "test pipeline".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 5000,
                steps,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        watch: None,
        uri_template: None,
        variable_completions: None,
        annotations: None,
        output_schema: None,
        task_support: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }
}

#[test]
fn pipeline_two_mock_steps_returns_last_output() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("s1", serde_json::json!({"first": true})),
            mock_step("s2", serde_json::json!({"second": true})),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(!result.is_error, "pipeline should succeed");
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["result"]["second"], true);
    assert_eq!(structured["completed_steps"], 2);
    assert_eq!(structured["total_steps"], 2);
}

#[test]
fn pipeline_transform_step_produces_derived_value() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("fetch", serde_json::json!({"data": "hello"})),
            PipelineStepConfig::Transform(PipelineTransformStepConfig {
                id: "reshape".to_owned(),
                expression: "steps.fetch.output.data".to_owned(),
            }),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(!result.is_error, "pipeline should succeed");
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["result"], "hello");
}

#[test]
fn pipeline_cel_gate_pass_allows_continuation() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("s1", serde_json::json!({"ok": true})),
            PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
                id: "gate".to_owned(),
                expression: "true".to_owned(),
                error_message: None,
            }),
            mock_step("s2", serde_json::json!({"final": "done"})),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(!result.is_error, "pipeline should pass gate");
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["result"]["final"], "done");
}

#[test]
fn pipeline_cel_gate_abort_returns_error() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("s1", serde_json::json!({"ok": false})),
            PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
                id: "gate".to_owned(),
                expression: "false".to_owned(),
                error_message: Some("access denied by gate".to_owned()),
            }),
            mock_step("s2", serde_json::json!({"should": "not reach"})),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error, "gate should abort pipeline");
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("access denied by gate"));
        }
        _ => panic!("unexpected content type"),
    }
}

#[test]
fn pipeline_cel_gate_default_error_message() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("s1", serde_json::json!({})),
            PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
                id: "gate1".to_owned(),
                expression: "false".to_owned(),
                error_message: None,
            }),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("gate failed at step gate1"));
        }
        _ => panic!("unexpected content type"),
    }
}

#[test]
fn pipeline_step_error_aborts_pipeline() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            error_mock_step("failing", "backend unavailable"),
            mock_step("unreachable", serde_json::json!({"should": "not reach"})),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["failed_step"], "failing");
    assert_eq!(structured["completed_steps"], 0);
}

#[test]
fn pipeline_context_accumulates_across_steps() {
    let binding = pipeline_binding(
        "pipe",
        vec![
            mock_step("step1", serde_json::json!({"val": 42})),
            mock_step("step2", serde_json::json!({"val": 99})),
            PipelineStepConfig::Transform(PipelineTransformStepConfig {
                id: "combine".to_owned(),
                expression: r#"{"a": steps.step1.output.val, "b": steps.step2.output.val}"#
                    .to_owned(),
            }),
        ],
    );
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(!result.is_error, "pipeline should succeed");
    let structured = result.structured_content.expect("structured content");
    assert_eq!(structured["result"]["a"], 42);
    assert_eq!(structured["result"]["b"], 99);
}

#[test]
fn pipeline_not_found_returns_error() {
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "nonexistent".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error);
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("nonexistent"));
        }
        _ => panic!("unexpected content type"),
    }
}

#[test]
fn pipeline_timeout_aborts_execution() {
    let binding = BackendConfig {
        name: "slow_pipe".to_owned(),
        title: None,
        description: "slow pipeline".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 1, // 1ms timeout — will be exceeded
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "slow".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({}),
                            delay_ms: 50,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    mock_step("after", serde_json::json!({})),
                ],
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        watch: None,
        uri_template: None,
        variable_completions: None,
        annotations: None,
        output_schema: None,
        task_support: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    };
    let dispatcher = ExecutionDispatcher::from_runtime_debug_config(
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        &[binding],
    );
    let request = sample_request();

    let result = dispatcher.dispatch_tool_call(
        BackendInvocationRoute::Pipeline {
            profile: "slow_pipe".to_owned(),
        },
        &request,
        Some(sample_snapshot()),
    );

    assert!(result.is_error, "pipeline should timeout");
    match &result.content[0] {
        ToolContent::Text { text, .. } => {
            assert!(text.contains("timed out"));
        }
        _ => panic!("unexpected content type"),
    }
}

#[test]
fn pipeline_cel_evaluator_resolves_json_path() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"name": "test"}),
        tool_name: "t".to_owned(),
        steps: Some(serde_json::json!({"s1": {"output": {"data": "hello"}}})),
        ..Default::default()
    };
    let result = super::evaluate_pipeline_cel_transform("args.name", &expr_ctx).unwrap();
    assert_eq!(result, "test");

    let result2 =
        super::evaluate_pipeline_cel_transform("steps.s1.output.data", &expr_ctx).unwrap();
    assert_eq!(result2, "hello");
}

#[test]
fn pipeline_cel_evaluator_equality() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"x": 1}),
        tool_name: "t".to_owned(),
        ..Default::default()
    };
    let result = super::evaluate_pipeline_cel_transform("args.x == 1", &expr_ctx).unwrap();
    assert_eq!(result, serde_json::json!(true));

    let result2 = super::evaluate_pipeline_cel_transform("args.x != 1", &expr_ctx).unwrap();
    assert_eq!(result2, serde_json::json!(false));
}

#[test]
fn pipeline_cel_evaluator_string_concat() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"first": "hello", "second": " world"}),
        tool_name: "t".to_owned(),
        ..Default::default()
    };
    let result =
        super::evaluate_pipeline_cel_transform(r#"args.first + args.second"#, &expr_ctx).unwrap();
    assert_eq!(result, serde_json::json!("hello world"));
}

#[test]
fn pipeline_cel_evaluator_map_construction() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"val": 42}),
        tool_name: "t".to_owned(),
        ..Default::default()
    };
    let result =
        super::evaluate_pipeline_cel_transform(r#"{"result": args.val}"#, &expr_ctx).unwrap();
    assert_eq!(result, serde_json::json!({"result": 42}));
}

#[test]
fn pipeline_cel_evaluator_boolean_ops() {
    let expr_ctx = super::super::expr::ExprContext::default();
    assert_eq!(
        super::evaluate_pipeline_cel_transform("true && true", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("true && false", &expr_ctx).unwrap(),
        serde_json::json!(false)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("false || true", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("!false", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
}

#[test]
fn pipeline_cel_evaluator_compound_boolean_precedence() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"x": 1, "y": 2}),
        tool_name: "t".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x == 1 && args.y == 2", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x == 1 && args.y == 99", &expr_ctx).unwrap(),
        serde_json::json!(false)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x == 99 || args.y == 2", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x == 99 || args.y == 99", &expr_ctx).unwrap(),
        serde_json::json!(false)
    );
}

#[test]
fn pipeline_cel_evaluator_not_equals_not_confused_with_not() {
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({"x": 1}),
        tool_name: "t".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x != 2", &expr_ctx).unwrap(),
        serde_json::json!(true)
    );
    assert_eq!(
        super::evaluate_pipeline_cel_transform("args.x != 1", &expr_ctx).unwrap(),
        serde_json::json!(false)
    );
}

#[test]
fn format_request_headers_injects_traceparent() {
    let tc = crate::transports::TraceContext::parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        Some("vendor=value"),
    )
    .unwrap();
    let headers = std::collections::BTreeMap::new();
    let formatted = super::format_request_headers(&headers, true, 0, Some(&tc));

    assert!(
        formatted.contains("traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-"),
        "should contain traceparent with same trace_id, got: {formatted}"
    );
    assert!(
        formatted.contains("tracestate: vendor=value\r\n"),
        "should contain tracestate, got: {formatted}"
    );
    // Verify child span ID is different from parent
    assert!(
        !formatted.contains("00f067aa0ba902b7"),
        "child span ID should differ from parent span ID"
    );
}

#[test]
fn format_request_headers_without_trace_context() {
    let headers = std::collections::BTreeMap::new();
    let formatted = super::format_request_headers(&headers, true, 0, None);
    assert!(!formatted.contains("traceparent:"));
    assert!(!formatted.contains("tracestate:"));
}

/// injecting a trace context into an absent meta creates
/// a fresh object carrying traceparent.
#[test]
fn inject_trace_into_meta_creates_object_when_none() {
    let tc = crate::transports::TraceContext::parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        Some("vendor=abc"),
    )
    .unwrap();
    let out = super::inject_trace_into_meta(None, Some(&tc)).unwrap();
    assert!(out.get("traceparent").is_some());
    assert_eq!(out["tracestate"], "vendor=abc");
}

/// existing _meta fields are preserved; trace fields add alongside.
#[test]
fn inject_trace_into_meta_preserves_existing_fields() {
    let tc = crate::transports::TraceContext::parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        None,
    )
    .unwrap();
    let existing = serde_json::json!({"app.note": "hello"});
    let out = super::inject_trace_into_meta(Some(existing), Some(&tc)).unwrap();
    assert_eq!(out["app.note"], "hello");
    assert!(out.get("traceparent").is_some());
}

/// passing no trace context leaves meta untouched.
#[test]
fn inject_trace_into_meta_pass_through_when_no_context() {
    let existing = serde_json::json!({"a": 1});
    let out = super::inject_trace_into_meta(Some(existing.clone()), None);
    assert_eq!(out, Some(existing));
}

#[test]
fn format_request_headers_trace_context_without_tracestate() {
    let tc = crate::transports::TraceContext::parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        None,
    )
    .unwrap();
    let headers = std::collections::BTreeMap::new();
    let formatted = super::format_request_headers(&headers, false, 0, Some(&tc));

    assert!(formatted.contains("traceparent:"));
    assert!(!formatted.contains("tracestate:"));
}

/// pipeline-config sentinel `0` substitutes the spec
/// default; non-zero values pass through verbatim.
#[test]
fn coerce_sampling_max_tokens_sentinel_zero_yields_default() {
    assert_eq!(
        super::coerce_sampling_max_tokens(0),
        crate::protocol::DEFAULT_SAMPLING_MAX_TOKENS,
    );
}

#[test]
fn coerce_sampling_max_tokens_passes_through_nonzero() {
    assert_eq!(super::coerce_sampling_max_tokens(1), 1);
    assert_eq!(super::coerce_sampling_max_tokens(2048), 2048);
    assert_eq!(super::coerce_sampling_max_tokens(u64::MAX), u64::MAX);
}

/// SEP-1330: primitive properties accepted.
#[test]
fn requested_schema_accepts_primitives() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age":  {"type": "integer"},
            "ok":   {"type": "boolean"},
            "kind": {"enum": ["a","b","c"]},
            "opt":  {"type": ["string","null"]}
        }
    });
    super::validate_elicitation_requested_schema(Some(&s)).unwrap();
}

/// SEP-1330: nested objects rejected.
#[test]
fn requested_schema_rejects_nested_object() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {"addr": {"type": "object"}}
    });
    let err = super::validate_elicitation_requested_schema(Some(&s)).unwrap_err();
    assert!(err.contains("not a primitive"), "got: {err}");
}

/// SEP-1330: arrays rejected.
#[test]
fn requested_schema_rejects_array_property() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {"tags": {"type": "array"}}
    });
    assert!(super::validate_elicitation_requested_schema(Some(&s)).is_err());
}

/// SEP-1330: top-level non-object rejected.
#[test]
fn requested_schema_rejects_non_object_top_level() {
    let s = serde_json::json!({"type": "array"});
    assert!(super::validate_elicitation_requested_schema(Some(&s)).is_err());
}

/// SEP-1330: absent schema is fine (URL mode).
#[test]
fn requested_schema_absent_is_ok() {
    super::validate_elicitation_requested_schema(None).unwrap();
}

// --- P4.1: sql_tx executor runtime ------------------------------------

async fn register_sqlite_profile(
    plugin: &SqlBackendPlugin,
    backend_name: &str,
    url: &str,
    sql: &str,
    params: &[&str],
    row_mode: &str,
) {
    let spec = serde_json::json!({
        "driver": "sqlite",
        "url": url,
        "query": {
            "sql": sql,
            "params": params.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "row_mode": row_mode,
        },
    });
    <SqlBackendPlugin as mcpg_plugin_protocol::BackendPlugin>::register_profile(
        plugin,
        backend_name,
        &spec,
        mcpg_plugin_protocol::noop_backend_host(),
    )
    .await
    .unwrap_or_else(|e| panic!("register {backend_name}: {e}"));
}

async fn plugin_exec(
    plugin: &SqlBackendPlugin,
    backend_name: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let req = mcpg_plugin_protocol::BackendRequest {
        payload: serde_json::to_vec(&args).unwrap(),
        headers: vec![],
        request_id: format!("req-{backend_name}"),
        session_id: None,
        identity: None,
        idempotency: None,
    };
    let resp = <SqlBackendPlugin as mcpg_plugin_protocol::BackendPlugin>::execute(
        plugin,
        backend_name,
        req,
    )
    .await
    .unwrap_or_else(|e| panic!("execute {backend_name}: {e}"));
    serde_json::from_slice(&resp.payload).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_tx_commits_nested_statements() {
    let url = "sqlite:file:sqltx_commit?mode=memory&cache=shared";
    let plugin = Arc::new(SqlBackendPlugin::new());

    // Bootstrap schema via the plugin's own execute path — keeps
    // this test sqlx-free at the crate boundary.
    register_sqlite_profile(
        &plugin,
        "setup_inv",
        url,
        "CREATE TABLE inv (id INTEGER PRIMARY KEY, qty INTEGER)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_inv", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "setup_orders",
        url,
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item_id INTEGER)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_orders", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "seed_inv",
        url,
        "INSERT INTO inv (id, qty) VALUES (1, 5)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "seed_inv", serde_json::json!({})).await;

    // Register the sql_tx target binding (query body is a no-op —
    // the tx bypasses it).
    register_sqlite_profile(&plugin, "tx_target", url, "SELECT 1", &[], "scalar").await;

    // Register a verifier binding for post-commit assertions.
    register_sqlite_profile(
        &plugin,
        "verify_inv",
        url,
        "SELECT qty FROM inv WHERE id = 1",
        &[],
        "scalar",
    )
    .await;
    register_sqlite_profile(
        &plugin,
        "verify_orders_count",
        url,
        "SELECT COUNT(*) AS n FROM orders",
        &[],
        "scalar",
    )
    .await;

    let cfg = crate::config::PipelineSqlTxStepConfig {
        id: "charge_flow".into(),
        backend: "tx_target".into(),
        steps: vec![
            crate::config::PipelineSqlTxNestedStep {
                id: "deduct".into(),
                sql: "UPDATE inv SET qty = qty - 1 WHERE id = :id".into(),
                params: vec!["id".into()],
                row_mode: "affected_rows".into(),
                input_transform: None,
            },
            crate::config::PipelineSqlTxNestedStep {
                id: "order".into(),
                sql: "INSERT INTO orders (user_id, item_id) VALUES (:u, :i)".into(),
                params: vec!["u".into(), "i".into()],
                row_mode: "affected_rows".into(),
                input_transform: None,
            },
        ],
        input_transform: None,
    };

    let input = serde_json::json!({"id": 1, "u": 42, "i": 1});
    let outcome = super::execute_sql_tx_step(plugin.as_ref(), &cfg, &input).await;

    let value = match outcome {
        super::StepOutcome::Success(v) => v,
        super::StepOutcome::Error(e) => panic!("expected Success, got Error: {e}"),
        super::StepOutcome::GateAbort(m) => panic!("expected Success, got GateAbort: {m}"),
    };
    assert_eq!(
        value["steps"]["deduct"]["rows_affected"],
        serde_json::json!(1)
    );
    assert_eq!(
        value["steps"]["order"]["rows_affected"],
        serde_json::json!(1)
    );

    // Post-commit assertions via the plugin itself.
    let qty = plugin_exec(&plugin, "verify_inv", serde_json::json!({})).await;
    assert_eq!(qty, serde_json::json!(4), "inventory decrement must commit");
    let n = plugin_exec(&plugin, "verify_orders_count", serde_json::json!({})).await;
    assert_eq!(n, serde_json::json!(1), "order row must commit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_tx_rolls_back_on_nested_failure() {
    let url = "sqlite:file:sqltx_rollback?mode=memory&cache=shared";
    let plugin = Arc::new(SqlBackendPlugin::new());

    register_sqlite_profile(
        &plugin,
        "setup_inv_rb",
        url,
        "CREATE TABLE inv (id INTEGER PRIMARY KEY, qty INTEGER)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_inv_rb", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "setup_orders_rb",
        url,
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, item_id INTEGER)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_orders_rb", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "seed_inv_rb",
        url,
        "INSERT INTO inv (id, qty) VALUES (1, 5)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "seed_inv_rb", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "seed_order_rb",
        url,
        "INSERT INTO orders (user_id, item_id) VALUES (42, 99)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "seed_order_rb", serde_json::json!({})).await;

    register_sqlite_profile(&plugin, "tx_target_rb", url, "SELECT 1", &[], "scalar").await;
    register_sqlite_profile(
        &plugin,
        "verify_inv_rb",
        url,
        "SELECT qty FROM inv WHERE id = 1",
        &[],
        "scalar",
    )
    .await;

    let cfg = crate::config::PipelineSqlTxStepConfig {
        id: "charge_flow".into(),
        backend: "tx_target_rb".into(),
        steps: vec![
            crate::config::PipelineSqlTxNestedStep {
                id: "deduct".into(),
                sql: "UPDATE inv SET qty = qty - 1 WHERE id = :id".into(),
                params: vec!["id".into()],
                row_mode: "affected_rows".into(),
                input_transform: None,
            },
            // Conflict: user_id=42 already exists — this INSERT fails.
            crate::config::PipelineSqlTxNestedStep {
                id: "order".into(),
                sql: "INSERT INTO orders (user_id, item_id) VALUES (:u, :i)".into(),
                params: vec!["u".into(), "i".into()],
                row_mode: "affected_rows".into(),
                input_transform: None,
            },
        ],
        input_transform: None,
    };

    let input = serde_json::json!({"id": 1, "u": 42, "i": 1});
    let outcome = super::execute_sql_tx_step(plugin.as_ref(), &cfg, &input).await;

    match outcome {
        super::StepOutcome::Error(msg) => {
            assert!(
                msg.contains("sql_tx") && msg.contains("order"),
                "unexpected error message: {msg}"
            );
        }
        super::StepOutcome::Success(v) => panic!("expected Error, got Success: {v}"),
        super::StepOutcome::GateAbort(m) => panic!("expected Error, got GateAbort: {m}"),
    }

    // Rollback verification: qty must still be 5 (no UPDATE persisted).
    let qty = plugin_exec(&plugin, "verify_inv_rb", serde_json::json!({})).await;
    assert_eq!(
        qty,
        serde_json::json!(5),
        "nested-step failure must roll back the earlier UPDATE"
    );
}

// --- P3.4: sql_await pipeline step ------------------------------------

/// Register a SQL profile with an `[bindings.sql.await]` block, then
/// dispatch through the gateway's `execute_sql_await_step` helper.
/// The check query matches on first poll, so the step succeeds with
/// the matched row as its output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_await_pipeline_step_returns_matched_row() {
    let url = "sqlite:file:sqlawait_pipeline_match?mode=memory&cache=shared";
    let plugin = Arc::new(SqlBackendPlugin::new());

    register_sqlite_profile(
        &plugin,
        "setup_jobs_await",
        url,
        "CREATE TABLE jobs_await (id INTEGER PRIMARY KEY, status TEXT)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_jobs_await", serde_json::json!({})).await;

    // Seed a row that already satisfies the predicate so the first
    // check poll terminates the loop deterministically.
    register_sqlite_profile(
        &plugin,
        "seed_jobs_await",
        url,
        "INSERT INTO jobs_await (id, status) VALUES (1, 'done')",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "seed_jobs_await", serde_json::json!({})).await;

    // Profile with await — trigger noop, check selects status,
    // predicate matches when status == "done".
    let spec = serde_json::json!({
        "driver": "sqlite",
        "url": url,
        "query": {
            "sql": "SELECT 1",
            "row_mode": "scalar",
        },
        "await": {
            "trigger": {
                "sql": "SELECT 1",
            },
            "check": {
                "sql": "SELECT id, status FROM jobs_await WHERE id = :id",
                "params": ["id"],
            },
            "predicate": "row.status == 'done'",
            "poll_interval_ms": 100,
            "timeout_ms": 2_000,
        },
    });
    <SqlBackendPlugin as mcpg_plugin_protocol::BackendPlugin>::register_profile(
        plugin.as_ref(),
        "wait_for_done",
        &spec,
        mcpg_plugin_protocol::noop_backend_host(),
    )
    .await
    .expect("register wait_for_done");

    let cfg = crate::config::PipelineSqlAwaitStepConfig {
        id: "await_done".into(),
        backend: "wait_for_done".into(),
        input_transform: None,
    };
    let request = sample_request();
    let step_input = serde_json::json!({"id": 1});

    let outcome = super::execute_sql_await_step(plugin.as_ref(), &cfg, &step_input, &request).await;

    match outcome {
        super::StepOutcome::Success(v) => {
            assert_eq!(v["status"], serde_json::json!("done"));
            assert_eq!(v["id"], serde_json::json!(1));
        }
        super::StepOutcome::Error(e) => panic!("expected Success, got Error: {e}"),
        super::StepOutcome::GateAbort(m) => panic!("expected Success, got GateAbort: {m}"),
    }
}

/// Predicate never matches: the await loop exhausts the deadline and
/// the pipeline step surfaces a binding-error string the dispatcher
/// turns into pipeline abort.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_await_pipeline_step_errors_on_timeout() {
    let url = "sqlite:file:sqlawait_pipeline_timeout?mode=memory&cache=shared";
    let plugin = Arc::new(SqlBackendPlugin::new());

    register_sqlite_profile(
        &plugin,
        "setup_jobs_await_to",
        url,
        "CREATE TABLE jobs_await_to (id INTEGER PRIMARY KEY, status TEXT)",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "setup_jobs_await_to", serde_json::json!({})).await;

    register_sqlite_profile(
        &plugin,
        "seed_jobs_await_to",
        url,
        "INSERT INTO jobs_await_to (id, status) VALUES (1, 'pending')",
        &[],
        "affected_rows",
    )
    .await;
    plugin_exec(&plugin, "seed_jobs_await_to", serde_json::json!({})).await;

    let spec = serde_json::json!({
        "driver": "sqlite",
        "url": url,
        "query": {
            "sql": "SELECT 1",
            "row_mode": "scalar",
        },
        "await": {
            "check": {
                "sql": "SELECT id, status FROM jobs_await_to WHERE id = :id",
                "params": ["id"],
            },
            "predicate": "row.status == 'done'",
            "poll_interval_ms": 100,
            "timeout_ms": 300,
        },
    });
    <SqlBackendPlugin as mcpg_plugin_protocol::BackendPlugin>::register_profile(
        plugin.as_ref(),
        "wait_for_done_timeout",
        &spec,
        mcpg_plugin_protocol::noop_backend_host(),
    )
    .await
    .expect("register wait_for_done_timeout");

    let cfg = crate::config::PipelineSqlAwaitStepConfig {
        id: "await_timeout".into(),
        backend: "wait_for_done_timeout".into(),
        input_transform: None,
    };
    let request = sample_request();
    let step_input = serde_json::json!({"id": 1});

    let outcome = super::execute_sql_await_step(plugin.as_ref(), &cfg, &step_input, &request).await;

    match outcome {
        super::StepOutcome::Error(msg) => {
            assert!(
                msg.contains("sql_await") && msg.contains("wait_for_done_timeout"),
                "expected sql_await timeout error, got: {msg}"
            );
        }
        super::StepOutcome::Success(v) => {
            panic!("expected Error on timeout, got Success: {v}")
        }
        super::StepOutcome::GateAbort(m) => panic!("expected Error, got GateAbort: {m}"),
    }
}

/// Pipeline sub-steps inherit the same
/// idempotency hint as the parent tool-call. Asserts the
/// `build_step_request` plumbing in isolation; the e2e test
/// `pipeline_replay_returns_assembled_envelope` covers the
/// full dispatcher-to-backend path.
#[test]
fn build_step_request_propagates_idempotency_hint() {
    let mut parent = sample_request();
    parent.idempotency_hint = Some(super::IdempotencyHint {
        key: "pipeline-hint-test-key".to_owned(),
        scope_hash: [42u8; 32],
    });
    let step_input = serde_json::json!({"step": 1});
    let child = super::build_step_request(&parent, &step_input);
    let parent_hint = parent.idempotency_hint.as_ref().expect("parent hint");
    let child_hint = child
        .idempotency_hint
        .as_ref()
        .expect("sub-step inherits hint");
    assert_eq!(
        child_hint.key, parent_hint.key,
        "sub-step MUST inherit the key (no per-hop derivation)"
    );
    assert_eq!(
        child_hint.scope_hash, parent_hint.scope_hash,
        "sub-step MUST inherit the scope_hash"
    );
}

/// When the parent has no hint (no key
/// supplied by the caller), sub-steps see `None` too — no
/// hint synthesis happens at the per-step boundary.
#[test]
fn build_step_request_propagates_absent_hint_as_none() {
    let parent = sample_request();
    assert!(parent.idempotency_hint.is_none());
    let step_input = serde_json::json!({"step": 1});
    let child = super::build_step_request(&parent, &step_input);
    assert!(
        child.idempotency_hint.is_none(),
        "absent parent hint must propagate as None"
    );
}

/// The gateway-internal `IdempotencyHint`
/// (32-byte BLAKE3) maps to the plugin-protocol hint as a
/// hex-encoded 16-byte truncation (32 hex chars). Backends
/// receive a stable, opaque scope tag they can use to scope
/// per-call caches consistently with the gateway's dedupe
/// boundary, without re-deriving the scope themselves.
#[test]
fn idempotency_hint_to_plugin_hint_truncates_and_hex_encodes() {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let hint = super::IdempotencyHint {
        key: "01J9X8N3QKHA0V9C4D8TYR2ABC".to_owned(),
        scope_hash: bytes,
    };
    let plugin_hint = hint.to_plugin_hint();
    assert_eq!(plugin_hint.key, "01J9X8N3QKHA0V9C4D8TYR2ABC");
    assert_eq!(
        plugin_hint.scope_hash, "000102030405060708090a0b0c0d0e0f",
        "first 16 bytes lower-hex"
    );
    assert_eq!(
        plugin_hint.scope_hash.len(),
        32,
        "16-byte truncation = 32 hex chars"
    );
}

// Pipeline `plugin_transform` bridge: a JSONata transform plugin,
// registered in-process, reshapes the pipeline context into a step output.
#[test]
fn plugin_transform_step_reshapes_via_jsonata() {
    use mcpg_plugin_sdk::adapters::SyncTransformAdapter;

    let mut registry = mcpg_plugin_host::PluginRegistry::new();
    registry
        .register_transform(
            Box::new(SyncTransformAdapter::new(
                mcpg_plugin_transform_jsonata::JsonataTransform::new("{}"),
            )),
            mcpg_plugin_protocol::PluginTier::Native,
            serde_json::json!({}),
        )
        .expect("register jsonata transform in-process");
    let registry = std::sync::Arc::new(registry);

    let request = sample_request();
    let expr_ctx = super::super::expr::ExprContext {
        arguments: serde_json::json!({}),
        tool_name: "t".to_owned(),
        steps: Some(serde_json::json!({
            "fetch": { "output": { "orders": [ {"id": 1}, {"id": 2}, {"id": 3} ] } }
        })),
        ..Default::default()
    };
    let step = crate::config::backend::PipelinePluginTransformStepConfig {
        id: "reshape".to_owned(),
        plugin: "dev.mcpg.transform.jsonata".to_owned(),
        config: serde_json::json!({ "expression": "{ \"ids\": steps.fetch.output.orders.id }" }),
    };

    match super::execute_plugin_transform_step(Some(&registry), &step, &expr_ctx, &request) {
        super::StepOutcome::Success(value) => {
            assert_eq!(value, serde_json::json!({ "ids": [1, 2, 3] }));
        }
        super::StepOutcome::Error(e) => panic!("expected Success, got Error: {e}"),
        _ => panic!("expected Success, got a non-success outcome"),
    }
}

#[test]
fn plugin_transform_step_unknown_plugin_is_error() {
    let registry = std::sync::Arc::new(mcpg_plugin_host::PluginRegistry::new());
    let request = sample_request();
    let expr_ctx = super::super::expr::ExprContext::default();
    let step = crate::config::backend::PipelinePluginTransformStepConfig {
        id: "x".to_owned(),
        plugin: "dev.mcpg.transform.nonexistent".to_owned(),
        config: serde_json::json!({ "expression": "$" }),
    };
    assert!(matches!(
        super::execute_plugin_transform_step(Some(&registry), &step, &expr_ctx, &request),
        super::StepOutcome::Error(_)
    ));
}

// ---------------------------------------------------------------------------
// LOG-1 (SEP-2575) — per-request logLevel suppression on the modern wire.
// publish_log_notification gates `notifications/message` by the per-request
// floor only when the negotiated wire is modern; the legacy wire emits
// unconditionally (byte-identical to pre-Phase-5 behaviour).
// ---------------------------------------------------------------------------

use crate::protocol::v_2026_07_28::wire::meta::LogLevel;
use crate::runtime::delivery_bus::DeliveryBus;
use crate::runtime::pipeline_store::DeliveryMessage;
use std::sync::Mutex as StdMutex;

/// Recording delivery bus that captures every published message so a
/// test can assert what (if anything) was emitted.
#[derive(Debug, Default)]
struct RecordingDeliveryBus {
    published: StdMutex<Vec<(String, DeliveryMessage)>>,
}

impl RecordingDeliveryBus {
    fn count(&self) -> usize {
        self.published.lock().unwrap().len()
    }
    fn levels(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, m)| {
                m.jsonrpc_message
                    .get("params")
                    .and_then(|p| p.get("level"))
                    .and_then(|l| l.as_str())
                    .map(str::to_owned)
            })
            .collect()
    }
}

impl DeliveryBus for RecordingDeliveryBus {
    fn subscribe(
        &self,
        _session_id: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = tokio::sync::mpsc::Receiver<DeliveryMessage>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            rx
        })
    }

    fn publish(
        &self,
        session_id: &str,
        message: DeliveryMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        self.published
            .lock()
            .unwrap()
            .push((session_id.to_owned(), message));
        Box::pin(async move { Ok(()) })
    }
}

fn emit(bus: &Arc<RecordingDeliveryBus>, level: &str, modern: bool, floor: Option<LogLevel>) {
    let dyn_bus: Arc<dyn DeliveryBus> = Arc::clone(bus) as Arc<dyn DeliveryBus>;
    super::publish_log_notification(
        Some(&dyn_bus),
        None,
        "sess-1",
        level,
        Some("test"),
        &serde_json::json!("hello"),
        modern,
        floor,
        None,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn modern_log_below_floor_is_suppressed() {
    let bus = Arc::new(RecordingDeliveryBus::default());
    // Floor = warning. An `info` message is below → suppressed.
    emit(&bus, "info", true, Some(LogLevel::Warning));
    assert_eq!(bus.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn modern_log_at_or_above_floor_is_emitted() {
    let bus = Arc::new(RecordingDeliveryBus::default());
    // Floor = info: `info` (at) and `error` (above) emit; `debug` (below) drops.
    emit(&bus, "debug", true, Some(LogLevel::Info));
    emit(&bus, "info", true, Some(LogLevel::Info));
    emit(&bus, "error", true, Some(LogLevel::Info));
    assert_eq!(bus.levels(), vec!["info".to_owned(), "error".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn modern_log_absent_floor_suppresses_everything() {
    // SEP-2575 MUST: absent logLevel on the modern wire → emit nothing.
    let bus = Arc::new(RecordingDeliveryBus::default());
    emit(&bus, "emergency", true, None);
    emit(&bus, "error", true, None);
    assert_eq!(bus.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_log_emits_unconditionally_ignoring_floor() {
    // Legacy wire: the per-request floor is never consulted — every
    // message emits, byte-identical to pre-Phase-5 behaviour.
    let bus = Arc::new(RecordingDeliveryBus::default());
    emit(&bus, "debug", false, None);
    emit(&bus, "info", false, Some(LogLevel::Emergency));
    assert_eq!(bus.count(), 2);
}

#[test]
fn structured_retry_classification_is_authoritative_over_transport_words() {
    fn err_result(text: &str) -> ToolCallResult {
        ToolCallResult {
            content: vec![ToolContent::text(text.to_owned())],
            structured_content: None,
            is_error: true,
            meta: None,
        }
    }
    let rc = crate::config::RetryConfig {
        max_attempts: 3,
        initial_backoff_ms: 1,
        retry_on_status_codes: vec![503],
        retry_on_transport_error: true,
    };

    // An explicit structured `retryable:false` must win even though the
    // message text mentions "connection" — the heuristic must not override it.
    let classified_no = err_result(
        r#"{"retryable": false, "message": "connection refused permanently, do not retry"}"#,
    );
    assert!(!error_result_is_retryable(&classified_no, &rc));

    // A structured non-retryable status code (not in the retry set) with a
    // transport word likewise stays non-retryable.
    let status_no = err_result(r#"{"statusCode": 400, "message": "connection to db invalid"}"#);
    assert!(!error_result_is_retryable(&status_no, &rc));

    // Explicit structured signals still retry.
    assert!(error_result_is_retryable(
        &err_result(r#"{"retryable": true, "message": "try again"}"#),
        &rc
    ));
    assert!(error_result_is_retryable(
        &err_result(r#"{"statusCode": 503, "message": "unavailable"}"#),
        &rc
    ));
    assert!(error_result_is_retryable(
        &err_result(r#"{"kind": "transport_error", "message": "x"}"#),
        &rc
    ));

    // Unstructured error text still falls back to the transport-word heuristic.
    assert!(error_result_is_retryable(
        &err_result("upstream connection reset by peer"),
        &rc
    ));
    assert!(!error_result_is_retryable(
        &err_result("invalid argument: name too long"),
        &rc
    ));
}
