use super::*;
use crate::config::{
    BackendConfig, BackendGovernanceConfig, BackendImpl, HttpBackendConfig, HttpBackendMethod,
    KafkaBackendConfig, MockBackendConfig,
};

fn http_post_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "http",
            HttpBackendConfig {
                url: "http://localhost:9000/api".to_owned(),
                method: HttpBackendMethod::Post,
                timeout_ms: 2000,
                max_response_bytes: 4096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: Default::default(),
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

fn http_get_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "http",
            HttpBackendConfig {
                url: "http://localhost:9000/query".to_owned(),
                method: HttpBackendMethod::Get,
                timeout_ms: 2000,
                max_response_bytes: 4096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: Default::default(),
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

fn command_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "command",
            serde_json::json!({
                "command": "/usr/bin/test",
                "args": [],
                "timeout_ms": 2000,
                "max_output_bytes": 4096,
                "require_json_stdout": true,
            }),
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
fn registry_exposes_all_capability_kinds() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 4);
    assert_eq!(registry.prompts().len(), 1);
    assert_eq!(registry.resources().len(), 1);
}

/// A federated catalog's names come from the upstream server, and
/// `tool_prefix` defaults to empty, so an upstream can claim a name a
/// native binding already serves. Dispatch resolves native-first, so the
/// duplicate was never reachable — but it was listed, and clients feed
/// every listed description and schema to a model. Authorization also read
/// the NATIVE rule for both entries, so the federation's own trust floor
/// never governed the shadowing one.
#[test]
fn federated_entry_cannot_shadow_a_native_name_in_listings() {
    let native = http_post_binding("search");
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        std::slice::from_ref(&native),
        &[],
        &[],
        &[],
        None,
    );
    assert_eq!(registry.tools().len(), 1);
    let native_descriptor = registry.tools()[0].clone();

    // An upstream exporting the same unprefixed name.
    let mut impostor = native_descriptor.clone();
    impostor.description = "upstream-controlled description".to_owned();
    registry
        .federated_overlay()
        .store(std::sync::Arc::new(FederatedCatalog::from_parts(
            vec![crate::backends::federation::FederatedTool {
                descriptor: impostor,
                route: BackendInvocationRoute::Federated {
                    source: "upstream".to_owned(),
                    upstream_name: "search".to_owned(),
                },
            }],
            vec![],
            vec![],
            vec![],
        )));

    let listed = registry.tools();
    assert_eq!(listed.len(), 1, "shadowing entry must not be listed");
    assert_eq!(
        listed[0].description, native_descriptor.description,
        "the native entry is the one that survives"
    );
}

#[test]
fn registry_hides_debug_capabilities_when_debug_disabled() {
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[],
        None,
    );

    assert!(registry.tools().is_empty());
    assert!(registry.prompts().is_empty());
    assert!(registry.resources().is_empty());
}

#[test]
fn registry_uses_configured_debug_profile_bindings() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends {
            command_probe_profile: "cmd-profile-b".to_owned(),
            network_probe_profile: "net-profile-b".to_owned(),
            network_json_call_profile: "net-json-profile-b".to_owned(),
        },
        DebugToolExposure {
            network_json_call: true,
            ..DebugToolExposure::default()
        },
        &[],
        &[],
        &[],
        &[],
        None,
    );

    let command_route = registry
        .tool_route("mcpg.debug.command_probe")
        .expect("command route");
    let network_route = registry
        .tool_route("mcpg.debug.network_probe")
        .expect("network route");
    let network_json_route = registry
        .tool_route("mcpg.debug.network_json_call")
        .expect("network json route");

    match command_route {
        BackendInvocationRoute::CommandProbe { profile } => {
            assert_eq!(profile, "cmd-profile-b")
        }
        other => panic!("unexpected route: {other:?}"),
    }
    match network_route {
        BackendInvocationRoute::NetworkProbe { profile } => {
            assert_eq!(profile, "net-profile-b")
        }
        other => panic!("unexpected route: {other:?}"),
    }
    match network_json_route {
        BackendInvocationRoute::NetworkJsonCall { profile } => {
            assert_eq!(profile, "net-json-profile-b")
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_omits_hidden_debug_tools() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure {
            command_probe: false,
            network_probe: true,
            ..DebugToolExposure::default()
        },
        &[],
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 3);
    assert!(registry.tool_route("mcpg.debug.command_probe").is_none());
    assert!(registry.tool_route("mcpg.debug.network_probe").is_some());
    assert!(
        registry
            .tool_route("mcpg.debug.network_json_call")
            .is_none()
    );
}

#[test]
fn registry_exposes_network_json_call_when_enabled() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure {
            network_json_call: true,
            ..DebugToolExposure::default()
        },
        &[],
        &[],
        &[],
        &[],
        None,
    );

    assert!(
        registry
            .tool_route("mcpg.debug.network_json_call")
            .is_some()
    );
}

#[test]
fn registry_omits_hidden_debug_prompt_and_resource() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure {
            operational_overview_prompt: false,
            runtime_overview_resource: false,
            ..DebugToolExposure::default()
        },
        &[],
        &[],
        &[],
        &[],
        None,
    );

    assert!(registry.prompt_route("mcpg_operational_overview").is_none());
    assert!(registry.resource_route("mcpg://runtime/overview").is_none());
    assert!(registry.prompts().is_empty());
    assert!(registry.resources().is_empty());
}

#[test]
fn registry_exposes_http_post_binding_as_network_json_call() {
    let bindings = vec![http_post_binding("weather.get_forecast")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let tool = &registry.tools()[0];
    assert_eq!(tool.name, "weather.get_forecast");
    assert_eq!(tool.title.as_deref(), Some("weather.get_forecast Title"));

    let route = registry
        .tool_route("weather.get_forecast")
        .expect("binding route");
    match route {
        BackendInvocationRoute::NetworkJsonCall { profile } => {
            assert_eq!(profile, "weather.get_forecast");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_exposes_http_get_binding_as_network_query_call() {
    let bindings = vec![http_get_binding("analytics.query")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let route = registry
        .tool_route("analytics.query")
        .expect("binding route");
    match route {
        BackendInvocationRoute::NetworkQueryCall { profile } => {
            assert_eq!(profile, "analytics.query");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_exposes_command_binding_as_command_json_call() {
    let bindings = vec![command_binding("system.diagnostic")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let route = registry
        .tool_route("system.diagnostic")
        .expect("binding route");
    match route {
        BackendInvocationRoute::CommandJsonCall {
            profile,
            require_json_stdout,
        } => {
            assert_eq!(profile, "system.diagnostic");
            assert!(require_json_stdout);
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_exposes_bindings_alongside_debug_tools() {
    let bindings = vec![
        http_post_binding("weather.get_forecast"),
        command_binding("system.diagnostic"),
    ];
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    // 4 debug tools + 2 bindings
    assert_eq!(registry.tools().len(), 6);
    assert!(registry.tool_route("mcpg.runtime.snapshot").is_some());
    assert!(registry.tool_route("weather.get_forecast").is_some());
    assert!(registry.tool_route("system.diagnostic").is_some());
}

#[test]
fn registry_uses_custom_input_schema_when_provided() {
    let mut binding = http_post_binding("custom.tool");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" }
        },
        "required": ["query"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let tool = &registry.tools()[0];
    assert!(tool.input_schema["properties"]["query"].is_object());
}

#[test]
fn registry_uses_default_schema_when_input_schema_omitted() {
    let binding = http_post_binding("default.schema");
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let tool = &registry.tools()[0];
    assert_eq!(tool.input_schema["type"], "object");
    assert_eq!(tool.input_schema["additionalProperties"], true);
}

#[test]
fn validate_arguments_passes_when_no_schema_registered() {
    let binding = http_post_binding("no.schema");
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let result =
        registry.validate_tool_arguments("no.schema", &Some(serde_json::json!({"anything": true})));
    assert!(result.is_ok());
}

#[test]
fn validate_arguments_passes_for_unknown_tool() {
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[],
        None,
    );

    let result = registry.validate_tool_arguments("does.not.exist", &Some(serde_json::json!({})));
    assert!(result.is_ok());
}

#[test]
fn validate_arguments_passes_with_valid_arguments() {
    let mut binding = http_post_binding("schema.test");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "limit": { "type": "integer", "minimum": 1 }
        },
        "required": ["query"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let result = registry.validate_tool_arguments(
        "schema.test",
        &Some(serde_json::json!({"query": "hello", "limit": 5})),
    );
    assert!(result.is_ok());
}

#[test]
fn validate_arguments_fails_missing_required_property() {
    let mut binding = http_post_binding("schema.required");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" }
        },
        "required": ["query"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let result = registry.validate_tool_arguments("schema.required", &Some(serde_json::json!({})));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("arguments validation failed"));
    assert!(err.contains("query"));
}

#[test]
fn validate_arguments_fails_wrong_type() {
    let mut binding = http_post_binding("schema.types");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "count": { "type": "integer" }
        }
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let result = registry.validate_tool_arguments(
        "schema.types",
        &Some(serde_json::json!({"count": "not-a-number"})),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("arguments validation failed"));
}

#[test]
fn validate_arguments_treats_none_as_empty_object() {
    let mut binding = http_post_binding("schema.none");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "optional": { "type": "string" }
        }
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    // None arguments should be treated as empty object and pass for optional-only schemas
    let result = registry.validate_tool_arguments("schema.none", &None);
    assert!(result.is_ok());
}

#[test]
fn validate_arguments_fails_none_when_required_fields_exist() {
    let mut binding = http_post_binding("schema.none_required");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" }
        },
        "required": ["query"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let result = registry.validate_tool_arguments("schema.none_required", &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("query"));
}

#[test]
fn validate_arguments_skips_debug_tools() {
    let registry = CapabilityRegistry::new(
        true,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[],
        None,
    );

    // Debug tools have no schema validator, so any arguments pass
    let result = registry.validate_tool_arguments(
        "mcpg.runtime.snapshot",
        &Some(serde_json::json!({"unexpected": true})),
    );
    assert!(result.is_ok());
}

#[test]
fn nats_binding_registers_as_tool_with_nats_request_route() {
    let nats_binding = BackendConfig {
        name: "orders-search".to_owned(),
        title: Some("Search Orders".to_owned()),
        description: "Search orders via NATS".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "nats",
            crate::config::NatsBackendConfig {
                url: "nats://localhost:4222".to_owned(),
                credentials_path: None,
                subject: "mcpg.exec.request.tools.orders-search".to_owned(),
                timeout_ms: 5000,
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

    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[nats_binding],
        &[],
        &[],
        &[],
        None,
    );

    let tools = registry.tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "orders-search");
    assert_eq!(tools[0].title, Some("Search Orders".to_owned()));
    assert_eq!(tools[0].description, "Search orders via NATS");

    let route = registry.tool_route("orders-search");
    assert!(route.is_some());
    assert!(matches!(
        route.unwrap(),
        BackendInvocationRoute::NatsRequest { .. }
    ));
}

#[test]
fn nats_binding_and_http_binding_coexist() {
    let bindings = vec![
        http_post_binding("http-tool"),
        BackendConfig {
            name: "nats-tool".to_owned(),
            title: None,
            description: "NATS tool".to_owned(),
            input_schema: None,
            backend: BackendImpl::from_typed(
                "nats",
                crate::config::NatsBackendConfig {
                    url: "nats://localhost:4222".to_owned(),
                    credentials_path: None,
                    subject: "mcpg.exec.request.tools.test".to_owned(),
                    timeout_ms: 2000,
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
        },
    ];

    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    let tools = registry.tools();
    assert_eq!(tools.len(), 2);
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"http-tool"));
    assert!(tool_names.contains(&"nats-tool"));
}

// --- gRPC, GraphQL, Kafka binding registration tests ---

fn grpc_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "grpc",
            serde_json::json!({
                "url": "http://localhost:50051",
                "service": "mypackage.MyService",
                "method": "MyMethod",
                "timeout_ms": 5000,
                "max_response_bytes": 65536,
                "headers": {},
            }),
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

fn http_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "http",
            HttpBackendConfig {
                url: "https://api.example.com".to_owned(),
                method: HttpBackendMethod::Post,
                timeout_ms: 5000,
                max_response_bytes: 65536,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: Default::default(),
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

fn graphql_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "graphql",
            serde_json::json!({
                "url": "http://localhost:4000/graphql",
                "operation": "query { users { name } }",
                "timeout_ms": 5000,
                "max_response_bytes": 65536,
                "headers": {},
            }),
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

fn kafka_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
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
    }
}

#[test]
fn dynamic_register_spec_kafka_matches_static_block() {
    // The generic dynamic-registration path must build the same
    // per-binding spec the kafka static block in app/mod.rs builds:
    // request_topic / response_topic / timeout_ms / max_response_bytes
    // (connection params reach a cdylib plugin via its plugins[]
    // entry config, not this spec).
    let binding = kafka_binding("event.publish");
    let spec = super::dynamic_register_spec(&binding.backend, false).expect("kafka has a spec");
    assert_eq!(spec["request_topic"], "requests");
    assert_eq!(spec["response_topic"], "responses");
    assert_eq!(spec["timeout_ms"], 10000);
    assert_eq!(spec["max_response_bytes"], 65536);
}

#[test]
fn dynamic_register_spec_http_threads_allow_private_backends() {
    // The http spec mirrors the old static block, incl. the
    // server-level allow_private_backends SSRF toggle.
    let binding = http_binding("svc.call");
    let spec = super::dynamic_register_spec(&binding.backend, true).expect("http has a spec");
    assert_eq!(spec["url"], "https://api.example.com");
    assert_eq!(spec["allow_private_backends"], true);
    let denied = super::dynamic_register_spec(&binding.backend, false).expect("http has a spec");
    assert_eq!(denied["allow_private_backends"], false);
}

#[test]
fn dynamic_register_spec_grpc_threads_fields_and_allow_private_backends() {
    // gRPC is a cdylib backend plugin now — the generic
    // dynamic-registration path claims it, mirroring the http spec
    // (service/method structural, allow_private_backends threaded).
    let binding = grpc_binding("order.create");
    let spec = super::dynamic_register_spec(&binding.backend, true).expect("grpc has a spec");
    assert_eq!(spec["service"], "mypackage.MyService");
    assert_eq!(spec["method"], "MyMethod");
    assert_eq!(spec["allow_private_backends"], true);
    let denied = super::dynamic_register_spec(&binding.backend, false).expect("grpc has a spec");
    assert_eq!(denied["allow_private_backends"], false);
}

#[test]
fn registry_exposes_grpc_binding_as_envelope_plugin() {
    let bindings = vec![grpc_binding("order.create")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let tool = &registry.tools()[0];
    assert_eq!(tool.name, "order.create");

    let route = registry.tool_route("order.create").expect("binding route");
    match route {
        BackendInvocationRoute::EnvelopePlugin { kind, profile } => {
            assert_eq!(kind, "grpc");
            assert_eq!(profile, "order.create");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_exposes_graphql_binding_as_graphql_call() {
    let bindings = vec![graphql_binding("user.list")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let tool = &registry.tools()[0];
    assert_eq!(tool.name, "user.list");

    let route = registry.tool_route("user.list").expect("binding route");
    match route {
        BackendInvocationRoute::GraphqlCall { profile } => {
            assert_eq!(profile, "user.list");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_exposes_kafka_binding_as_kafka_request() {
    let bindings = vec![kafka_binding("event.publish")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let tool = &registry.tools()[0];
    assert_eq!(tool.name, "event.publish");

    let route = registry.tool_route("event.publish").expect("binding route");
    match route {
        BackendInvocationRoute::KafkaRequest { profile } => {
            assert_eq!(profile, "event.publish");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_registers_all_binding_types_together() {
    let bindings = vec![
        http_post_binding("http.tool"),
        command_binding("cmd.tool"),
        grpc_binding("grpc.tool"),
        graphql_binding("gql.tool"),
        kafka_binding("kafka.tool"),
    ];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 5);
    assert!(matches!(
        registry.tool_route("http.tool"),
        Some(BackendInvocationRoute::NetworkJsonCall { .. })
    ));
    assert!(matches!(
        registry.tool_route("cmd.tool"),
        Some(BackendInvocationRoute::CommandJsonCall { .. })
    ));
    assert!(matches!(
        registry.tool_route("grpc.tool"),
        Some(BackendInvocationRoute::EnvelopePlugin { .. })
    ));
    assert!(matches!(
        registry.tool_route("gql.tool"),
        Some(BackendInvocationRoute::GraphqlCall { .. })
    ));
    assert!(matches!(
        registry.tool_route("kafka.tool"),
        Some(BackendInvocationRoute::KafkaRequest { .. })
    ));
}

fn mock_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} description", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({"fixture": true}),
                delay_ms: 0,
                error: false,
                error_message: None,
                passthrough: false,
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
fn registry_exposes_mock_binding_as_envelope_plugin() {
    let bindings = vec![mock_binding("test.mock")];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 1);
    let tool = &registry.tools()[0];
    assert_eq!(tool.name, "test.mock");

    let route = registry.tool_route("test.mock").expect("binding route");
    match route {
        BackendInvocationRoute::EnvelopePlugin { kind, profile } => {
            assert_eq!(kind, "mock");
            assert_eq!(profile, "test.mock");
        }
        other => panic!("unexpected route: {other:?}"),
    }
}

#[test]
fn registry_registers_all_binding_types_including_mock() {
    let bindings = vec![
        http_post_binding("http.tool"),
        command_binding("cmd.tool"),
        grpc_binding("grpc.tool"),
        graphql_binding("gql.tool"),
        kafka_binding("kafka.tool"),
        mock_binding("mock.tool"),
    ];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &bindings,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(registry.tools().len(), 6);
    assert!(matches!(
        registry.tool_route("mock.tool"),
        Some(BackendInvocationRoute::EnvelopePlugin { .. })
    ));
}

// ── Output Schema Validation Tests ─────────────────────────────────

#[test]
fn output_schema_validates_conforming_content() {
    let mut binding = http_post_binding("validated.tool");
    binding.output_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "result": { "type": "string" }
        },
        "required": ["result"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let valid = Some(serde_json::json!({ "result": "ok" }));
    assert!(
        registry
            .validate_structured_output("validated.tool", &valid)
            .is_ok()
    );
}

#[test]
fn output_schema_rejects_non_conforming_content() {
    let mut binding = http_post_binding("validated.tool");
    binding.output_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "result": { "type": "string" }
        },
        "required": ["result"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let invalid = Some(serde_json::json!({ "wrong_field": 42 }));
    let err = registry.validate_structured_output("validated.tool", &invalid);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("structuredContent validation"));
}

#[test]
fn output_schema_passes_when_no_schema_defined() {
    let binding = http_post_binding("no.schema");
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    let content = Some(serde_json::json!({ "anything": true }));
    assert!(
        registry
            .validate_structured_output("no.schema", &content)
            .is_ok()
    );
}

#[test]
fn output_schema_passes_when_content_is_none() {
    let mut binding = http_post_binding("with.schema");
    binding.output_schema = Some(serde_json::json!({
        "type": "object",
        "required": ["x"]
    }));
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        None,
    );

    assert!(
        registry
            .validate_structured_output("with.schema", &None)
            .is_ok()
    );
}

#[test]
fn tool_task_support_returns_none_for_missing_tool() {
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[],
        None,
    );
    assert!(registry.tool_task_support("nonexistent").is_none());
}

#[test]
fn resource_template_registered_from_binding_config() {
    let bindings = vec![BackendConfig {
        name: "weather-city".to_owned(),
        title: Some("Weather by city".to_owned()),
        description: "Forecast by city".to_owned(),
        input_schema: None,
        output_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!("sunny"),
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: None,
        mime_type: Some("application/json".to_owned()),
        uri_template: Some("weather://{city}/forecast".to_owned()),
        variable_completions: None,
        watch: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &bindings,
        None,
    );
    let templates = registry.resource_templates();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0].name, "weather-city");
    assert_eq!(templates[0].uri_template, "weather://{city}/forecast");
    assert_eq!(templates[0].title, Some("Weather by city".to_owned()));
    assert_eq!(templates[0].mime_type, Some("application/json".to_owned()));
}

#[test]
fn resource_template_not_included_in_resources_list() {
    let bindings = vec![BackendConfig {
        name: "weather-city".to_owned(),
        title: None,
        description: "Forecast by city".to_owned(),
        input_schema: None,
        output_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!("sunny"),
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        uri_template: Some("weather://{city}/forecast".to_owned()),
        variable_completions: None,
        watch: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }];
    let registry = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &bindings,
        None,
    );
    // Resource templates should NOT appear in the regular resources list
    assert_eq!(registry.resources().len(), 0);
    assert_eq!(registry.resource_templates().len(), 1);
}

// URI normalization.
#[test]
fn normalize_lowercases_scheme_and_host() {
    assert_eq!(
        super::normalize_resource_uri("HTTPS://Example.COM/foo"),
        "https://example.com/foo",
    );
}

#[test]
fn normalize_strips_default_port() {
    assert_eq!(
        super::normalize_resource_uri("https://example.com:443/foo"),
        "https://example.com/foo",
    );
}

#[test]
fn normalize_collapses_dot_segments() {
    assert_eq!(
        super::normalize_resource_uri("https://example.com/a/./b/../c"),
        "https://example.com/a/c",
    );
}

#[test]
fn normalize_passthrough_on_unparseable() {
    // Custom scheme that url::Url accepts but does no special handling for
    let normalized = super::normalize_resource_uri("custom:Foo");
    assert!(normalized.starts_with("custom:"));
}

// URI scheme allow-list + unknown-scheme syntactic canonicalization.
#[test]
fn normalize_lowercases_unknown_scheme() {
    let out = super::normalize_resource_uri("CUSTOM:Foo");
    assert_eq!(out, "custom:Foo", "unknown scheme must be lower-cased");
}

#[test]
fn normalize_unknown_and_known_collide_after_scheme_lower() {
    // Two callers referring to the same custom resource with
    // different scheme casing must produce identical keys.
    let a = super::normalize_resource_uri("XYZ:my-resource");
    let b = super::normalize_resource_uri("xyz:my-resource");
    assert_eq!(a, b);
}

#[test]
fn normalize_known_scheme_parsed_normally() {
    let out = super::normalize_resource_uri("MCP://Server/Path");
    assert!(out.starts_with("mcp://"));
}

#[test]
fn normalize_schemeless_input_preserved() {
    let out = super::normalize_resource_uri("no-scheme");
    assert_eq!(out, "no-scheme");
}

/// operator-supplied scheme is treated as first-class
/// once registered. Uses an isolated scheme name to avoid OnceLock
/// contention with other tests in the same process.
#[test]
fn normalize_honors_operator_supplied_scheme() {
    super::set_extra_resource_uri_schemes(vec!["tenant-internal".to_owned()]);
    // After registration, the unknown-scheme path should still
    // lower-case the scheme but the warn-level "unknown" log
    // does not fire (allow-list hit). The output shape matches
    // the unknown branch only because url::Url cannot parse
    // most custom-scheme URIs without authority — what we lock
    // here is "no panic + scheme lower-cased".
    let out = super::normalize_resource_uri("TENANT-INTERNAL:foo");
    assert!(out.starts_with("tenant-internal:"));
}

// ------------------------------------------------------------------
// Plugin-derived input schema composition
// ------------------------------------------------------------------

struct FakeSchemaBackendPlugin {
    manifest: mcpg_plugin_protocol::PluginManifest,
    derived: std::collections::HashMap<String, serde_json::Value>,
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::BackendPlugin for FakeSchemaBackendPlugin {
    fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
        &self.manifest
    }
    fn kind(&self) -> &str {
        "sql"
    }
    fn input_schema(&self, backend_name: &str) -> Option<serde_json::Value> {
        self.derived.get(backend_name).cloned()
    }
    async fn register_profile(
        &self,
        _name: &str,
        _spec: &serde_json::Value,
        _host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
    ) -> Result<(), mcpg_plugin_protocol::BackendError> {
        Ok(())
    }
    async fn execute(
        &self,
        _name: &str,
        _req: mcpg_plugin_protocol::BackendRequest,
    ) -> Result<mcpg_plugin_protocol::BackendResponse, mcpg_plugin_protocol::BackendError> {
        Ok(mcpg_plugin_protocol::BackendResponse {
            payload: vec![],
            truncated: false,
        })
    }
}

fn sql_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: None,
        description: String::new(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "sql",
            serde_json::json!({
                "driver": "sqlite",
                "url": "sqlite::memory:",
                "query": { "sql": "SELECT 1", "row_mode": "scalar" }
            }),
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

fn registry_with_fake_sql(
    derived_for: Option<(&str, serde_json::Value)>,
) -> mcpg_plugin_host::PluginRegistry {
    let mut reg = mcpg_plugin_host::PluginRegistry::new();
    let mut derived = std::collections::HashMap::new();
    if let Some((n, v)) = derived_for {
        derived.insert(n.to_owned(), v);
    }
    let fake = std::sync::Arc::new(FakeSchemaBackendPlugin {
        manifest: mcpg_plugin_protocol::PluginManifest {
            id: "test.fake_sql".into(),
            version: "0.0.0".into(),
            name: "Fake SQL".into(),
            plugin_class: mcpg_plugin_protocol::PluginClass::ToolGate,
            protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION.to_owned(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        },
        derived,
    });
    reg.register_backend(fake, mcpg_plugin_protocol::PluginTier::Native)
        .unwrap();
    reg
}

#[test]
fn input_schema_uses_plugin_derived_when_operator_omits() {
    let plugin_reg = registry_with_fake_sql(Some((
        "orders.lookup",
        serde_json::json!({
            "type": "object",
            "properties": {"tenant": {"type": "string", "format": "uuid"}},
            "required": ["tenant"]
        }),
    )));
    let binding = sql_binding("orders.lookup");
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        Some(&plugin_reg),
    );
    let tools = reg.tools();
    let schema = &tools
        .iter()
        .find(|t| t.name == "orders.lookup")
        .unwrap()
        .input_schema;
    assert_eq!(schema["properties"]["tenant"]["format"], "uuid");
}

#[test]
fn input_schema_merges_operator_overlay_on_plugin_derived() {
    let plugin_reg = registry_with_fake_sql(Some((
        "orders.lookup",
        serde_json::json!({
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "format": "uuid"}
            }
        }),
    )));
    let mut binding = sql_binding("orders.lookup");
    binding.input_schema = Some(serde_json::json!({
        "properties": {
            "tenant": {"description": "customer tenant id"}
        }
    }));
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        Some(&plugin_reg),
    );
    let tools = reg.tools();
    let schema = &tools
        .iter()
        .find(|t| t.name == "orders.lookup")
        .unwrap()
        .input_schema;
    assert_eq!(schema["properties"]["tenant"]["format"], "uuid");
    assert_eq!(
        schema["properties"]["tenant"]["description"],
        "customer tenant id"
    );
}

#[test]
fn input_schema_falls_back_to_operator_when_plugin_returns_none() {
    // Plugin registered but has no derived schema for this binding.
    let plugin_reg = registry_with_fake_sql(None);
    let mut binding = sql_binding("orders.lookup");
    binding.input_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {"id": {"type": "integer"}}
    }));
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[binding],
        &[],
        &[],
        &[],
        Some(&plugin_reg),
    );
    let tools = reg.tools();
    let schema = &tools
        .iter()
        .find(|t| t.name == "orders.lookup")
        .unwrap()
        .input_schema;
    assert_eq!(schema["properties"]["id"]["type"], "integer");
}

fn resource_template_binding_with_completions(
    name: &str,
    uri_template: &str,
    completions: std::collections::BTreeMap<String, Vec<String>>,
) -> BackendConfig {
    let variable_completions: std::collections::BTreeMap<
        String,
        crate::config::backend::VariableCompletionSource,
    > = completions
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                crate::config::backend::VariableCompletionSource::BareList(v),
            )
        })
        .collect();
    BackendConfig {
        name: name.to_owned(),
        title: None,
        description: format!("{name} description"),
        input_schema: None,
        output_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!("ok"),
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        uri_template: Some(uri_template.to_owned()),
        variable_completions: Some(variable_completions),
        watch: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }
}

fn complete_request(
    uri_template: &str,
    argument_name: &str,
    argument_value: &str,
) -> crate::protocol::CompletionCompleteParams {
    crate::protocol::CompletionCompleteParams {
        reference: crate::protocol::CompletionReference {
            ref_type: "ref/resource".to_owned(),
            name: None,
            uri: Some(uri_template.to_owned()),
        },
        argument: crate::protocol::CompletionArgument {
            name: argument_name.to_owned(),
            value: argument_value.to_owned(),
        },
        context: None,
        meta: None,
    }
}

#[test]
fn resource_template_static_completions_filtered_by_prefix() {
    let mut completions = std::collections::BTreeMap::new();
    completions.insert(
        "owner".to_owned(),
        vec!["acme".to_owned(), "anthropic".to_owned()],
    );
    completions.insert(
        "repo".to_owned(),
        vec!["mcpg".to_owned(), "agent".to_owned()],
    );
    let binding = resource_template_binding_with_completions(
        "github-issues",
        "github://repos/{owner}/{repo}/issues/{number}",
        completions,
    );
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[binding],
        None,
    );

    // Empty prefix returns all configured values for that variable.
    let result = reg.complete_argument(&complete_request(
        "github://repos/{owner}/{repo}/issues/{number}",
        "repo",
        "",
    ));
    let mut values = result.values.clone();
    values.sort();
    assert_eq!(values, vec!["agent".to_owned(), "mcpg".to_owned()]);
    assert_eq!(result.total, Some(2));
    assert_eq!(result.has_more, Some(false));

    // Non-empty prefix narrows the result.
    let result = reg.complete_argument(&complete_request(
        "github://repos/{owner}/{repo}/issues/{number}",
        "owner",
        "ant",
    ));
    assert_eq!(result.values, vec!["anthropic".to_owned()]);
}

#[test]
fn resource_template_completions_empty_for_unknown_variable() {
    let mut completions = std::collections::BTreeMap::new();
    completions.insert("owner".to_owned(), vec!["acme".to_owned()]);
    let binding = resource_template_binding_with_completions(
        "github-issues",
        "github://repos/{owner}/{repo}/issues/{number}",
        completions,
    );
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[binding],
        None,
    );
    // `not_a_variable` is not declared on the template — must return empty.
    let result = reg.complete_argument(&complete_request(
        "github://repos/{owner}/{repo}/issues/{number}",
        "not_a_variable",
        "",
    ));
    assert!(result.values.is_empty());
    assert_eq!(result.total, Some(0));
}

#[test]
fn resource_template_without_completions_returns_empty() {
    // Backwards-compat: a resource template binding with no
    // `variable_completions` field returns empty (today's behavior).
    let binding = resource_template_binding_with_completions(
        "billing",
        "billing://{account}/invoice/{invoice_id}",
        std::collections::BTreeMap::new(),
    );
    // Strip the completions to reproduce the no-field path:
    let mut binding = binding;
    binding.variable_completions = None;
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[binding],
        None,
    );
    let result = reg.complete_argument(&complete_request(
        "billing://{account}/invoice/{invoice_id}",
        "invoice_id",
        "in_",
    ));
    assert!(result.values.is_empty());
}

#[test]
fn resource_template_completions_drops_keys_not_declared_in_template() {
    let mut completions = std::collections::BTreeMap::new();
    completions.insert("owner".to_owned(), vec!["acme".to_owned()]);
    // `not_in_template` is not a declared variable; the registration
    // logger drops it but the build must still succeed.
    completions.insert("not_in_template".to_owned(), vec!["bogus".to_owned()]);
    let binding = resource_template_binding_with_completions(
        "github-issues",
        "github://repos/{owner}/{repo}/issues/{number}",
        completions,
    );
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[binding],
        None,
    );
    // The dropped key must not surface as a completion result.
    let result = reg.complete_argument(&complete_request(
        "github://repos/{owner}/{repo}/issues/{number}",
        "not_in_template",
        "",
    ));
    assert!(result.values.is_empty());
    // The valid key is still wired and returns its values.
    let result = reg.complete_argument(&complete_request(
        "github://repos/{owner}/{repo}/issues/{number}",
        "owner",
        "",
    ));
    assert_eq!(result.values, vec!["acme".to_owned()]);
}

#[test]
fn resource_template_context_arguments_take_precedence_over_static() {
    // Match-precedence: `context.arguments` matches first (mirrors
    // the prompt-completion rule), then falls back to the static
    // `variable_completions` list.
    let mut completions = std::collections::BTreeMap::new();
    completions.insert(
        "owner".to_owned(),
        vec!["acme".to_owned(), "anthropic".to_owned()],
    );
    let binding = resource_template_binding_with_completions(
        "github-issues",
        "github://repos/{owner}/{repo}/issues/{number}",
        completions,
    );
    let reg = CapabilityRegistry::new(
        false,
        DebugToolBackends::default(),
        DebugToolExposure::default(),
        &[],
        &[],
        &[],
        &[binding],
        None,
    );

    let mut context_args = std::collections::BTreeMap::new();
    context_args.insert("repo".to_owned(), "from-context".to_owned());
    let params = crate::protocol::CompletionCompleteParams {
        reference: crate::protocol::CompletionReference {
            ref_type: "ref/resource".to_owned(),
            name: None,
            uri: Some("github://repos/{owner}/{repo}/issues/{number}".to_owned()),
        },
        argument: crate::protocol::CompletionArgument {
            name: "owner".to_owned(),
            value: "from".to_owned(),
        },
        context: Some(crate::protocol::CompletionContext {
            arguments: context_args,
        }),
        meta: None,
    };
    let result = reg.complete_argument(&params);
    // context.arguments has a value matching the prefix, so it wins.
    assert_eq!(result.values, vec!["from-context".to_owned()]);
}
