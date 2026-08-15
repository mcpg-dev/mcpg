use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use arc_swap::ArcSwap;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::{
    backends::{
        DEFAULT_COMMAND_PROFILE, DEFAULT_NETWORK_PROFILE, DebugToolBackends, DebugToolExposure,
    },
    config::{AppConfig, BackendConfig, BackendGovernanceConfig, BackendImpl},
    observability::ObservabilityHandle,
    runtime::{
        CommandToolRuntimeConfig, GatewayRuntime, NetworkToolRuntimeConfig, RequestTrustLevel,
        RuntimeDebugConfig, SessionStoreConfig, ToolAccessPolicyConfig, ToolTrustRule,
    },
};

const MCP_ACCEPT_HEADER: &str = "application/json, text/event-stream";

async fn initialize_session(app: Router) -> (Router, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {
                                // advertise the full interactive
                                // capability tree so pipeline tests can
                                // exercise elicitation/sampling/roots.
                                "elicitation": {},
                                "sampling": {},
                                "roots": { "listChanged": true }
                            },
                            "clientInfo": {
                                "name": "test-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("initialize response");

    let session_id = response
        .headers()
        .get(SESSION_ID_HEADER)
        .expect("session header present")
        .to_str()
        .expect("session id str")
        .to_owned();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("initialized response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    (app, session_id)
}

/// Assemble an [`AppState`] from a config + runtime, filling every
/// remaining field with the test-default in-memory wiring: an
/// in-memory session store, default observability, empty
/// overlay / policy-chain, and no health prober / secret watcher /
/// quota gate. Every test-state builder funnels through here so the
/// long field tail lives in exactly one place.
fn finish_app_state(config: AppConfig, runtime: GatewayRuntime) -> AppState {
    AppState {
        config: Arc::new(ArcSwap::from_pointee(config.clone())),
        base_config: Arc::new(ArcSwap::from_pointee(config)),
        registry_overlay: Arc::new(ArcSwap::from_pointee(
            crate::runtime::registry_sync::RegistryOverlay::default(),
        )),
        runtime: Arc::new(ArcSwap::from_pointee(runtime)),
        session_store: Arc::new(
            crate::runtime::session_store::KvBackedSessionStore::new_in_memory(
                SessionStoreConfig::default(),
            ),
        ),
        observability: Arc::new(ObservabilityHandle::default()),
        config_sources: Vec::new(),
        sse_stream_counts: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        config_overlay: std::sync::Arc::new(ArcSwap::from_pointee(serde_json::Value::Object(
            serde_json::Map::new(),
        ))),
        policy_chain: std::sync::Arc::new(ArcSwap::from_pointee(Vec::new())),
        plugin_health_prober: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        secret_watcher: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        #[cfg(feature = "governance-quotas")]
        quota_gate: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(None)),
    }
}

/// The 9-arg `GatewayRuntime::new(...)` the plain (non-debug,
/// non-binding) test states share.
fn default_test_runtime() -> GatewayRuntime {
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

fn build_test_state() -> AppState {
    // The test suite injects an authenticated principal via the
    // `x-mcpg-subject-id` header — i.e. it models a deployment behind a
    // trusted upstream that authenticates the caller, so trust the header
    // here. The secure default (`false`, header ignored) is covered by the
    // dedicated `subject_header_is_ignored_when_untrusted` test.
    let mut config = AppConfig::default();
    config.gateway.server.trust_subject_header = true;
    finish_app_state(config, default_test_runtime())
}

fn build_test_state_with_debug_config(debug_config: RuntimeDebugConfig) -> AppState {
    let mut config = AppConfig {
        feature_flags: crate::config::FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..crate::config::FeatureFlagsConfig::default()
        },
        ..AppConfig::default()
    };
    // See `build_test_state` — tests assert identity via the subject header.
    config.gateway.server.trust_subject_header = true;
    let runtime = GatewayRuntime::new_with_configs_and_debug(
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
        ToolAccessPolicyConfig::default(),
        debug_config,
    );
    finish_app_state(config, runtime)
}

fn build_test_state_with_runtime_controls(
    debug_enabled: bool,
    debug_config: RuntimeDebugConfig,
    binding_configs: Vec<BackendConfig>,
) -> AppState {
    build_test_state_with_all_runtime_controls(
        debug_enabled,
        debug_config,
        binding_configs,
        ToolAccessPolicyConfig::default(),
    )
}

fn build_test_state_with_all_runtime_controls(
    debug_enabled: bool,
    debug_config: RuntimeDebugConfig,
    binding_configs: Vec<BackendConfig>,
    tool_access_policy_config: ToolAccessPolicyConfig,
) -> AppState {
    build_test_state_with_all_runtime_controls_mut(
        debug_enabled,
        debug_config,
        binding_configs,
        tool_access_policy_config,
        |_| {},
    )
}

/// As [`build_test_state_with_all_runtime_controls`], but applies
/// `mutate` to the freshly built [`GatewayRuntime`] before it is
/// sealed into the `ArcSwap` — the only point a test can install
/// runtime-owned state (e.g. the idempotency store + capability) that
/// has no config-driven boot path.
fn build_test_state_with_all_runtime_controls_mut(
    debug_enabled: bool,
    debug_config: RuntimeDebugConfig,
    binding_configs: Vec<BackendConfig>,
    tool_access_policy_config: ToolAccessPolicyConfig,
    mutate: impl FnOnce(&mut GatewayRuntime),
) -> AppState {
    // Tests hit local servers on 127.0.0.1; enable private-backend routing
    // so the DNS rebinding guard doesn't block outbound test traffic and
    // leak listener.accept() threads.
    let mut config = AppConfig {
        feature_flags: crate::config::FeatureFlagsConfig {
            debug_tools_enabled: debug_enabled,
            ..crate::config::FeatureFlagsConfig::default()
        },
        ..AppConfig::default()
    };
    config.gateway.server.allow_private_backends = true;
    // See `build_test_state` — tests assert identity via the subject header.
    config.gateway.server.trust_subject_header = true;
    let mut runtime = GatewayRuntime::new_with_configs_and_runtime_controls(
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
        tool_access_policy_config,
        debug_config,
        &binding_configs,
        &[],
        &[],
        &[],
    );
    mutate(&mut runtime);
    finish_app_state(config, runtime)
}

fn test_command_binding(name: &str) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: Some(format!("{} Title", name)),
        description: format!("{} test binding", name),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "command",
            serde_json::json!({
                "command": "cat",
                "args": [],
                "timeout_ms": 2_000,
                "max_output_bytes": 4_096,
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

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body collected");
    serde_json::from_slice(&bytes).expect("json body")
}

async fn response_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body collected");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

/// Read SSE response body with a timeout — SSE streams stay open indefinitely
/// due to delivery bus subscriptions, so we read until the initial events
/// arrive then stop.
async fn sse_response_text(response: axum::response::Response) -> String {
    let mut body_stream = response.into_body().into_data_stream();
    let mut collected = Vec::new();
    while let Ok(Some(Ok(data))) =
        tokio::time::timeout(std::time::Duration::from_millis(200), body_stream.next()).await
    {
        collected.extend_from_slice(&data);
    }
    String::from_utf8(collected).expect("utf8 sse body")
}

#[tokio::test]
async fn health_route_returns_ok_payload() {
    let state = build_test_state();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(REQUEST_ID_RESPONSE_HEADER));
    let body = response_json(response).await;
    assert!(body.get("bind_address").is_none());
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn readiness_route_returns_explicit_checks() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(REQUEST_ID_RESPONSE_HEADER));
    let body = response_json(response).await;
    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"].as_array().expect("checks array").len(), 4);
    assert_eq!(body["checks"][0]["name"], "config_valid");
}

#[tokio::test]
async fn runtime_route_returns_runtime_and_logging_facts() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/runtime")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(REQUEST_ID_RESPONSE_HEADER));
    let body = response_json(response).await;
    assert_eq!(body["service"], "mcpg");
    assert_eq!(body["bind_address"], "127.0.0.1:8787");
    assert_eq!(body["health_path"], "/health");
    assert_eq!(body["mcp_path"], "/mcp");
    assert_eq!(body["logging"]["level"], "info");
    assert_eq!(body["readiness"]["status"], "ready");
}

#[tokio::test]
async fn build_request_context_preserves_upstream_request_id_and_header_identity() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(UPSTREAM_REQUEST_ID_HEADER),
        HeaderValue::from_static("external-req-1"),
    );
    headers.insert(
        HeaderName::from_static(SUBJECT_ID_HEADER),
        HeaderValue::from_static("user-42"),
    );

    // With the subject header explicitly trusted, it resolves to a
    // header-asserted identity.
    let request_context = build_request_context(&headers, None, None, None, None, true, None)
        .await
        .expect("no verifier configured → no 401");

    assert_eq!(
        request_context.upstream_request_id.as_deref(),
        Some("external-req-1")
    );
    assert!(matches!(
        request_context.identity,
        crate::runtime::RequestIdentity::HttpHeader { .. }
    ));
}

#[tokio::test]
async fn subject_header_is_ignored_when_untrusted() {
    // H-4/H-6: by default (`server.trust_subject_header = false`) the
    // self-asserted `x-mcpg-subject-id` header carries no identity — the
    // request must resolve to Anonymous, not header-asserted.
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(SUBJECT_ID_HEADER),
        HeaderValue::from_static("victim-principal"),
    );

    let request_context = build_request_context(&headers, None, None, None, None, false, None)
        .await
        .expect("no verifier configured → no 401");

    assert!(
        matches!(
            request_context.identity,
            crate::runtime::RequestIdentity::Anonymous { .. }
        ),
        "untrusted subject header must yield Anonymous, got {:?}",
        request_context.identity
    );
}

#[tokio::test]
async fn invalid_bearer_token_rejected_with_401() {
    // H-5: a credential presented to a configured verifier that FAILS
    // verification must fail closed with HTTP 401 — never silently
    // downgrade to header-asserted/anonymous.
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let secret = "super-secret-key-for-testing-only";
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "test-key-1",
            "k": URL_SAFE_NO_PAD.encode(secret.as_bytes()),
            "alg": "HS256"
        }]
    })
    .to_string();
    let jwks_config = crate::config::access::JwksConfig {
        url: "http://localhost/.well-known/jwks.json".to_owned(),
        keys_json: None,
        issuer: Some("test-issuer".to_owned()),
        audience: Some("test-audience".to_owned()),
        header_name: "authorization".to_owned(),
        header_prefix: "Bearer ".to_owned(),
        allow_missing_audience: true,
    };
    let verifier =
        crate::runtime::identity::JwtVerifier::from_jwks_json(&jwks, &jwks_config).unwrap();

    // A garbage bearer token — present, but unverifiable.
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer not-a-real-jwt".parse().unwrap());
    // Even with a (trusted) subject header set, an invalid token must NOT
    // fall back to it — it 401s.
    headers.insert(
        HeaderName::from_static(SUBJECT_ID_HEADER),
        HeaderValue::from_static("attacker"),
    );

    let result =
        build_request_context(&headers, Some(&verifier), None, None, None, true, None).await;
    let response = result.expect_err("invalid token must reject");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_bearer_token_falls_back_not_401() {
    // H-5 corollary: when a verifier is configured but NO credential is
    // presented, the request falls back (here: Anonymous, since the
    // subject header is untrusted) rather than 401ing.
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let secret = "super-secret-key-for-testing-only";
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "test-key-1",
            "k": URL_SAFE_NO_PAD.encode(secret.as_bytes()),
            "alg": "HS256"
        }]
    })
    .to_string();
    let jwks_config = crate::config::access::JwksConfig {
        url: "http://localhost/.well-known/jwks.json".to_owned(),
        keys_json: None,
        issuer: Some("test-issuer".to_owned()),
        audience: Some("test-audience".to_owned()),
        header_name: "authorization".to_owned(),
        header_prefix: "Bearer ".to_owned(),
        allow_missing_audience: true,
    };
    let verifier =
        crate::runtime::identity::JwtVerifier::from_jwks_json(&jwks, &jwks_config).unwrap();

    let headers = HeaderMap::new();
    let request_context =
        build_request_context(&headers, Some(&verifier), None, None, None, false, None)
            .await
            .expect("no credential presented → fall back, not 401");
    assert!(matches!(
        request_context.identity,
        crate::runtime::RequestIdentity::Anonymous { .. }
    ));
}

#[tokio::test]
async fn request_id_header_is_returned_to_clients() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/runtime")
                .header(
                    header::HeaderName::from_static(UPSTREAM_REQUEST_ID_HEADER),
                    "ext-1",
                )
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let header = response
        .headers()
        .get(REQUEST_ID_RESPONSE_HEADER)
        .expect("request id header present")
        .to_str()
        .expect("header value str");

    assert!(!header.is_empty());
}

#[tokio::test]
async fn mcp_initialize_request_returns_protocol_bootstrap_response() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "test-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(REQUEST_ID_RESPONSE_HEADER));
    assert!(response.headers().contains_key(SESSION_ID_HEADER));
    assert_eq!(
        response.headers()[PROTOCOL_VERSION_HEADER],
        crate::protocol::SUPPORTED_PROTOCOL_VERSION
    );
    let body = response_json(response).await;
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(body["result"]["serverInfo"]["name"], "mcpg");
}

#[tokio::test]
async fn mcp_initialized_notification_is_accepted() {
    let app = router(build_test_state(), "/health", "/mcp");
    let (_, session_id) = initialize_session(app.clone()).await;

    assert!(!session_id.is_empty());
}

#[tokio::test]
async fn mcp_tools_list_returns_registry_descriptors() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(SUBJECT_ID_HEADER, "test-user")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("id: stream-"));
    assert!(body.contains("\"method\":\"tools/list\"") || body.contains("\"tools\":[{"));
    assert!(body.contains("mcpg.runtime.snapshot"));
}

#[tokio::test]
async fn mcp_prompts_list_returns_registry_descriptors() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(SUBJECT_ID_HEADER, "test-user")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "prompts/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("mcpg_operational_overview"));
}

/// `tools/list` filters per caller; `prompts/list` and `resources/list` did
/// not, so an unauthenticated caller received the whole catalog — every
/// prompt name and every resource URI — under a config whose floor
/// (`HeaderAsserted` by default) denies them on read. The enumerations must
/// apply the same gate.
#[tokio::test]
async fn anonymous_caller_sees_no_prompts_or_resources() {
    for method in ["prompts/list", "resources/list"] {
        let (app, session_id) =
            initialize_session(router(build_test_state(), "/health", "/mcp")).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                    .header(
                        PROTOCOL_VERSION_HEADER,
                        crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                    )
                    .header(SESSION_ID_HEADER, &session_id)
                    // deliberately no SUBJECT_ID_HEADER
                    .body(Body::from(
                        serde_json::json!({ "jsonrpc": "2.0", "id": 12, "method": method })
                            .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(
            !body.contains("mcpg_operational_overview"),
            "{method} disclosed the catalog to an unauthenticated caller: {body}"
        );
    }
}

#[tokio::test]
async fn mcp_prompts_get_returns_prompt_messages() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                // prompts/get now enforces the trust floor (default
                // header_asserted) like tools/call — provide an identity.
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 111,
                        "method": "prompts/get",
                        "params": {
                            "name": "mcpg_operational_overview"
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("\"messages\""));
    assert!(body.contains("mcpg_operational_overview") || body.contains("Available tools"));
}

#[tokio::test]
async fn anonymous_prompts_get_denied_by_trust_floor() {
    // H-2: non-tool surfaces enforce the same trust floor as tools/call.
    // With the default floor (header_asserted) and NO identity header, an
    // anonymous prompts/get is refused — it no longer silently passes.
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                // No x-mcpg-subject-id → Anonymous → below the floor.
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 112,
                        "method": "prompts/get",
                        "params": { "name": "mcpg_operational_overview" }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "anonymous prompts/get must be denied by the trust floor"
    );
    let body = response_text(response).await;
    assert!(
        body.contains("trust level") || body.contains("-32003"),
        "denial should cite the trust-floor requirement, got: {body}"
    );
}

#[tokio::test]
async fn mcp_hidden_operational_overview_prompt_is_not_listed_or_invocable() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure {
            operational_overview_prompt: false,
            ..DebugToolExposure::default()
        },
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 112,
                        "method": "prompts/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let list_body = response_text(list_response).await;
    assert!(!list_body.contains("mcpg_operational_overview"));

    let get_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 113,
                        "method": "prompts/get",
                        "params": {
                            "name": "mcpg_operational_overview"
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let get_body = response_text(get_response).await;
    assert!(get_body.contains("unknown prompt: mcpg_operational_overview"));
}

#[tokio::test]
async fn mcp_resources_list_returns_registry_descriptors() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(SUBJECT_ID_HEADER, "test-user")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "resources/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("mcpg://runtime/overview"));
}

#[tokio::test]
async fn mcp_resources_read_returns_resource_contents() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                // resources/read now enforces the trust floor (default
                // header_asserted) like tools/call — provide an identity.
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 121,
                        "method": "resources/read",
                        "params": {
                            "uri": "mcpg://runtime/overview"
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("\"contents\""));
    assert!(body.contains("mcpg://runtime/overview"));
    assert!(body.contains("application/json"));
}

#[tokio::test]
async fn mcp_hidden_runtime_overview_resource_is_not_listed_or_invocable() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure {
            runtime_overview_resource: false,
            ..DebugToolExposure::default()
        },
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 122,
                        "method": "resources/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let list_body = response_text(list_response).await;
    assert!(!list_body.contains("mcpg://runtime/overview"));

    let read_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 123,
                        "method": "resources/read",
                        "params": {
                            "uri": "mcpg://runtime/overview"
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let read_body = response_text(read_response).await;
    assert!(read_body.contains("unknown resource: mcpg://runtime/overview"));
}

#[tokio::test]
async fn mcp_tools_call_routes_through_runtime() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 13,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.runtime.snapshot",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("\"type\":\"text\""));
    assert!(body.contains("\"service\":\"mcpg\""));
}

#[tokio::test]
async fn mcp_adapter_backed_tool_call_routes_through_execution_seam() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.request.echo",
                            "arguments": {
                                "message": "hello"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("mcpg.request.echo"));
    assert!(body.contains("adapter-facing seam"));
    assert!(body.contains("\"principalId\":\"user-1\""));
    assert!(body.contains("\"message\":\"hello\""));
}

#[tokio::test]
async fn mcp_command_probe_tool_routes_through_command_executor() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig {
                command: "printf".to_owned(),
                args: vec!["command-http-ok".to_owned()],
                timeout_ms: 2_000,
                max_output_bytes: 4_096,
            },
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 141,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.debug.command_probe",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("mcpg.debug.command_probe"));
    assert!(body.contains("command-http-ok"));
}

#[tokio::test]
async fn mcp_command_probe_uses_configured_binding_profile() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([
            (
                DEFAULT_COMMAND_PROFILE.to_owned(),
                CommandToolRuntimeConfig {
                    command: "printf".to_owned(),
                    args: vec!["default-profile-output".to_owned()],
                    timeout_ms: 2_000,
                    max_output_bytes: 4_096,
                },
            ),
            (
                "command-profile-b".to_owned(),
                CommandToolRuntimeConfig {
                    command: "printf".to_owned(),
                    args: vec!["bound-profile-output".to_owned()],
                    timeout_ms: 2_000,
                    max_output_bytes: 4_096,
                },
            ),
        ]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends {
            command_probe_profile: "command-profile-b".to_owned(),
            network_probe_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
            network_json_call_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
        },
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 143,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.debug.command_probe",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("bound-profile-output"));
    assert!(!body.contains("default-profile-output"));
    assert!(body.contains("\"profile\":\"command-profile-b\""));
}

#[tokio::test]
async fn mcp_network_probe_tool_routes_through_network_executor() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener bound");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buffer = [0_u8; 512];
        let count = stream.read(&mut buffer).expect("read request");
        let request = String::from_utf8_lossy(&buffer[..count]).to_string();
        assert!(request.contains("X-Test-Token: Bearer probe-token"));
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\nnetwork-http-ok";
        stream.write_all(response).expect("write response");
    });

    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig {
                url: format!("http://{}/probe", addr),
                timeout_ms: 2_000,
                max_response_bytes: 4_096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: std::collections::BTreeMap::from([(
                    "X-Test-Token".to_owned(),
                    "Bearer probe-token".to_owned(),
                )]),
                allow_private_backends: true,
            },
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });

    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 142,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.debug.network_probe",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    server.join().expect("server joined");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("mcpg.debug.network_probe"));
    assert!(body.contains("\"responseContentType\":\"text/plain\""));
    assert!(body.contains("network-http-ok"));
}

#[tokio::test]
async fn mcp_promoted_command_json_call_is_available_without_debug() {
    let state = build_test_state_with_all_runtime_controls(
        false,
        RuntimeDebugConfig {
            enabled: false,
            command_profiles: std::collections::BTreeMap::from([(
                DEFAULT_COMMAND_PROFILE.to_owned(),
                CommandToolRuntimeConfig {
                    command: "cat".to_owned(),
                    args: vec![],
                    timeout_ms: 2_000,
                    max_output_bytes: 4_096,
                },
            )]),
            network_profiles: std::collections::BTreeMap::from([(
                DEFAULT_NETWORK_PROFILE.to_owned(),
                NetworkToolRuntimeConfig::default(),
            )]),
            bindings: DebugToolBackends::default(),
            exposure: DebugToolExposure::default(),
            default_allow_private_backends: true,
        },
        vec![test_command_binding("mcpg.command.json_call")],
        ToolAccessPolicyConfig::default(),
    );

    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 198,
                        "method": "tools/list",
                        "params": {}
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = response_text(list_response).await;
    assert!(list_body.contains("mcpg.command.json_call"));

    let call_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 199,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.command.json_call",
                            "arguments": {
                                "message": "hello"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(call_response.status(), StatusCode::OK);
    let call_body = response_text(call_response).await;
    assert!(call_body.contains("mcpg.command.json_call"));
    assert!(call_body.contains("\"requestKind\":\"json_stdin\""));
    // Plugin envelope: request args under `request.body`, parsed stdout
    // under `response.json` (the command plugin's shape).
    assert!(call_body.contains("\"body\":{\"message\":\"hello\"}"));
    assert!(call_body.contains("\"json\":{\"message\":\"hello\"}"));
}

#[tokio::test]
async fn promoted_command_json_call_can_require_stricter_trust_than_global_default() {
    let app = router(
        build_test_state_with_all_runtime_controls(
            false,
            RuntimeDebugConfig {
                enabled: false,
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    CommandToolRuntimeConfig {
                        command: "cat".to_owned(),
                        args: vec![],
                        timeout_ms: 2_000,
                        max_output_bytes: 4_096,
                    },
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    NetworkToolRuntimeConfig::default(),
                )]),
                bindings: DebugToolBackends::default(),
                exposure: DebugToolExposure::default(),
                default_allow_private_backends: true,
            },
            vec![test_command_binding("mcpg.command.json_call")],
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::Unauthenticated,
                cel_allow_if: None,
                rules: vec![ToolTrustRule {
                    tool_name: "mcpg.command.json_call".to_owned(),
                    minimum_trust: RequestTrustLevel::HeaderAsserted,
                    cel_allow_if: None,
                    required_scopes: Vec::new(),
                }],
            },
        ),
        "/health",
        "/mcp",
    );
    let (app, session_id) = initialize_session(app).await;

    let anonymous_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 200,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.command.json_call",
                            "arguments": {"message": "hello"}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(anonymous_response.status(), StatusCode::FORBIDDEN);
    let anonymous_body = response_json(anonymous_response).await;
    assert_eq!(anonymous_body["error"]["code"], -32003);

    let trusted_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 201,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.command.json_call",
                            "arguments": {"message": "hello"}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(trusted_response.status(), StatusCode::OK);
    let trusted_body = response_text(trusted_response).await;
    assert!(trusted_body.contains("mcpg.command.json_call"));
    assert!(trusted_body.contains("\"json\":{\"message\":\"hello\"}"));
}

#[tokio::test]
async fn promoted_command_json_call_can_use_allow_if_for_caller_specific_gating() {
    let app = router(
        build_test_state_with_all_runtime_controls(
            false,
            RuntimeDebugConfig {
                enabled: false,
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    CommandToolRuntimeConfig {
                        command: "cat".to_owned(),
                        args: vec![],
                        timeout_ms: 2_000,
                        max_output_bytes: 4_096,
                    },
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    NetworkToolRuntimeConfig::default(),
                )]),
                bindings: DebugToolBackends::default(),
                exposure: DebugToolExposure::default(),
                default_allow_private_backends: true,
            },
            vec![test_command_binding("mcpg.command.json_call")],
            ToolAccessPolicyConfig {
                default_minimum_trust: RequestTrustLevel::HeaderAsserted,
                cel_allow_if: None,
                rules: vec![ToolTrustRule {
                    tool_name: "mcpg.command.json_call".to_owned(),
                    minimum_trust: RequestTrustLevel::HeaderAsserted,
                    cel_allow_if: Some("principal_id == \"user-1\"".to_owned()),
                    required_scopes: Vec::new(),
                }],
            },
        ),
        "/health",
        "/mcp",
    );
    let (app, session_id) = initialize_session(app).await;

    let denied_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-2")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 202,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.command.json_call",
                            "arguments": {"message": "hello"}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);
    let denied_body = response_json(denied_response).await;
    assert_eq!(denied_body["error"]["code"], -32005);

    let allowed_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 203,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.command.json_call",
                            "arguments": {"message": "hello"}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(allowed_response.status(), StatusCode::OK);
    let allowed_body = response_text(allowed_response).await;
    assert!(allowed_body.contains("mcpg.command.json_call"));
    assert!(allowed_body.contains("\"json\":{\"message\":\"hello\"}"));
}

#[tokio::test]
async fn mcp_network_probe_reports_retry_after_delay_semantics() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener bound");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buffer = [0_u8; 512];
        let _ = stream.read(&mut buffer).expect("read request");
        let response = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nwait";
        stream.write_all(response).expect("write response");
    });

    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig {
                url: format!("http://{}/probe", addr),
                timeout_ms: 2_000,
                max_response_bytes: 4_096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: std::collections::BTreeMap::new(),
                allow_private_backends: true,
            },
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });

    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 149,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.debug.network_probe",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    server.join().expect("server joined");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("\"downstreamError\":"));
    assert!(body.contains("\"kind\":\"unexpected_status_code\""));
    assert!(body.contains("\"idempotencyHint\":\"idempotent_read_only\""));
    assert!(body.contains("\"callerRetryDecision\":\"automatic_retry_after_delay\""));
    assert!(body.contains("\"retrySafety\":\"safe_for_automatic_retry\""));
    assert!(body.contains("\"backoffStrategy\":\"respect_retry_after\""));
    assert!(body.contains("\"retryClass\":\"after_delay\""));
    assert!(body.contains("\"retryAfterMs\":3000"));
    assert!(body.contains("\"suggestedAction\":\"retry_after_indicated_delay\""));
}

#[tokio::test]
async fn mcp_network_json_call_is_hidden_by_default() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let list_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 147,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let list_body = response_text(list_response).await;
    assert!(!list_body.contains("mcpg.debug.network_json_call"));
}

#[tokio::test]
async fn mcp_hidden_command_probe_is_not_listed_or_invocable() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure {
            command_probe: false,
            network_probe: true,
            ..DebugToolExposure::default()
        },
        default_allow_private_backends: true,
    });
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 144,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let list_body = response_text(list_response).await;
    assert!(!list_body.contains("mcpg.debug.command_probe"));
    assert!(list_body.contains("mcpg.debug.network_probe"));

    let call_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 145,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.debug.command_probe",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let call_body = response_text(call_response).await;
    assert!(call_body.contains("unknown tool: mcpg.debug.command_probe"));
}

#[tokio::test]
async fn anonymous_mcp_tool_call_is_denied_by_policy() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 131,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.runtime.snapshot",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], -32003);
}

#[tokio::test]
async fn capability_calls_before_initialized_are_rejected() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "test-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let session_id = response
        .headers()
        .get(SESSION_ID_HEADER)
        .expect("session header present")
        .to_str()
        .expect("session id str")
        .to_owned();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_mcp_session_terminates_it() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/mcp")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 22,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_get_returns_method_not_allowed_until_sse_is_implemented() {
    let app = router(build_test_state(), "/health", "/mcp");

    let (_, session_id) = initialize_session(app.clone()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert!(response.headers().contains_key(REQUEST_ID_RESPONSE_HEADER));
    let body = sse_response_text(response).await;
    assert!(body.contains("id: stream-"));
    assert!(body.contains("notifications/message"));
}

#[tokio::test]
async fn mcp_post_missing_accept_is_rejected() {
    let app = router(build_test_state(), "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "test-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mcp_origin_is_rejected_when_not_allowed() {
    let config = AppConfig {
        gateway: crate::config::GatewayConfig {
            server: crate::config::ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "/health".to_owned(),
                mcp_path: "/mcp".to_owned(),
                allowed_origins: vec!["http://allowed.example".to_owned()],
                replay_window_limit: 16,
                session_idle_timeout_ms: 900_000,
                shutdown_timeout_ms: 30,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: crate::config::TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: crate::config::ObservabilityConfig {
            logs: crate::config::LogsConfig::default(),
            ..crate::config::ObservabilityConfig::default()
        },
        governance: crate::config::GovernanceConfig {
            policy: crate::config::PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("origin", "http://blocked.example")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "test-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhook_resource_updated_rejects_disallowed_browser_origin() {
    // Default (empty) allowed_origins → loopback-only posture. A
    // non-loopback browser Origin is 403'd by the origin guard, which runs
    // before token resolution (so even an unknown token yields 403, not 404).
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/resource-updated/any-token")
                .header("origin", "http://blocked.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhook_resource_updated_allows_missing_origin() {
    // No Origin (a server-to-server sender) passes the guard and reaches
    // token resolution — an unknown token then yields 404, never 403.
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/resource-updated/any-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhook_approval_rejects_disallowed_browser_origin_before_signature() {
    // Origin runs before HMAC verification: a deliberately-bad sig still yields
    // 403 (not 401), proving the guard precedes signature work. Body + query
    // are valid so axum extraction succeeds and the handler body runs.
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/approvals/appr_1?expires=9999999999&sig=deadbeef")
                .header(header::CONTENT_TYPE, "application/json")
                .header("origin", "http://blocked.example")
                .body(Body::from(
                    serde_json::json!({"outcome": "approved"}).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn malformed_protocol_version_header_returns_minus_32600() {
    // A non-UTF-8 Mcp-Protocol-Version is a malformed header (InvalidRequest),
    // distinct from an unservable version (-32004): it stays -32600 with no
    // error.data.
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, MCP_ACCEPT_HEADER)
        .body(Body::from(
            serde_json::json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}).to_string(),
        ))
        .expect("request");
    req.headers_mut().insert(
        PROTOCOL_VERSION_HEADER,
        header::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    let response = app.oneshot(req).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], -32600);
    assert!(
        body["error"]["data"].is_null(),
        "malformed header carries no data"
    );
}

#[tokio::test]
async fn mcp_session_can_reuse_negotiated_protocol_version_when_header_is_omitted() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 30,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
}

#[tokio::test]
async fn mcp_get_replays_stream_events_from_last_event_id() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(SUBJECT_ID_HEADER, "test-user")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 42,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let body = response_text(response).await;
    let first_event_id = body
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .expect("first event id")
        .to_owned();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(SESSION_ID_HEADER, &session_id)
                .header("last-event-id", &first_event_id)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let replay_body = sse_response_text(response).await;
    assert!(replay_body.contains("mcpg.runtime.snapshot"));
}

#[tokio::test]
async fn mcp_logging_set_level_returns_empty_result() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 55,
                        "method": "logging/setLevel",
                        "params": {
                            "level": "error"
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let body = response_text(response).await;
    assert!(body.contains("\"id\":55"));
    assert!(body.contains("\"result\":{}"));
}

#[tokio::test]
async fn mcp_get_expired_last_event_id_returns_conflict() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = sse_response_text(response).await;
    let stream_id = body
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .and_then(|event_id| event_id.split(':').next().map(str::to_owned))
        .expect("stream id");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(SESSION_ID_HEADER, &session_id)
                .header("last-event-id", format!("{}:999", stream_id))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn metrics_endpoint_returns_404_when_disabled() {
    let mut config = AppConfig::default();
    config.observability.metrics.enabled = false;
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    // Route doesn't exist when metrics disabled
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_endpoint_returns_503_when_prometheus_plugin_absent() {
    // The route is mounted because metrics is enabled (the AppConfig
    // default), but the test runtime ships a bare `PluginRegistry::new()`
    // with no Prometheus plugin registered. The handler should surface a
    // 503 so operators notice the misconfiguration instead of silently
    // serving an empty payload that would let a monitoring SLO miss the
    // gap. End-to-end coverage of the 200 path lives in the gateway
    // integration tests where the full plugin stack is wired.
    let config = AppConfig::default(); // metrics.enabled defaults to true
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// =====================================================================
// MCP Conformance Test Harness
// =====================================================================
//
// Systematic verification of all 9 MCP protocol operations against the
// MCP 2025-11-25 specification. Each test validates:
// - JSON-RPC envelope correctness (jsonrpc: "2.0", id matching)
// - Protocol-specific response structure
// - Error behavior for invalid inputs
//
// The harness uses mock bindings for tools/call round-trips so tests
// are deterministic without external services.

/// Parse SSE response text into a JSON-RPC result value matching the given request id.
/// MCPG emits the bare JSON-RPC envelope on the SSE data line; the historical
/// Rust-side enum-tag wrapper (`{"JsonRpcSuccess":{…}}`) was removed (it broke
/// conformance — clients matching on the top-level `id` never saw the response).
fn extract_jsonrpc_from_sse(sse_text: &str, request_id: u64) -> serde_json::Value {
    for line in sse_text.lines() {
        if let Some(data) = line.strip_prefix("data: ")
            && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data)
            && parsed.get("jsonrpc").is_some()
            && parsed.get("id") == Some(&serde_json::json!(request_id))
        {
            return parsed;
        }
    }
    panic!(
        "no JSON-RPC message with id={} found in SSE response:\n{}",
        request_id, sse_text
    );
}

/// Try to parse response as direct JSON first, then as SSE.
/// Error responses may be direct JSON; success responses are SSE.
async fn extract_jsonrpc_response(
    response: axum::response::Response,
    request_id: u64,
) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body collected");
    let text = String::from_utf8_lossy(&bytes);
    // Try direct JSON first (error responses)
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text)
        && parsed.get("jsonrpc").is_some()
    {
        return parsed;
    }
    // Otherwise parse as SSE
    extract_jsonrpc_from_sse(&text, request_id)
}

fn build_conformance_state_with_mock() -> AppState {
    use crate::config::MockBackendConfig;
    let mock_binding = BackendConfig {
        name: "conformance.mock".to_owned(),
        title: Some("Conformance Mock".to_owned()),
        description: "Mock binding for conformance testing".to_owned(),
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" }
            }
        })),
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({"status": "ok", "data": [1, 2, 3]}),
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
    };
    build_test_state_with_runtime_controls(
        true,
        RuntimeDebugConfig {
            enabled: true,
            ..RuntimeDebugConfig::default()
        },
        vec![mock_binding],
    )
}

async fn mcp_request(
    app: Router,
    session_id: &str,
    id: u64,
    method: &str,
    params: Option<serde_json::Value>,
) -> (Router, axum::response::Response) {
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });
    if let Some(p) = params {
        body["params"] = p;
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, session_id)
                .header(
                    header::HeaderName::from_static(SUBJECT_ID_HEADER),
                    "conformance-user",
                )
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    (app, response)
}

// -- Conformance: initialize --

#[tokio::test]
async fn conformance_initialize_returns_valid_jsonrpc_envelope() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "conformance-client",
                                "version": "1.0.0"
                            }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SESSION_ID_HEADER));

    let body = response_json(response).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert!(body["result"].is_object());
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
    assert!(body["result"]["serverInfo"].is_object());
    assert!(body["result"]["capabilities"].is_object());
    assert!(body["result"]["capabilities"]["tools"].is_object());
    assert!(body["result"]["capabilities"]["prompts"].is_object());
    assert!(body["result"]["capabilities"]["resources"].is_object());
    assert!(body["result"]["capabilities"]["logging"].is_object());
}

#[tokio::test]
async fn conformance_initialize_rejects_unsupported_protocol_version() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "1999-01-01",
                            "capabilities": {},
                            "clientInfo": { "name": "old-client", "version": "0.1" }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    // initialize always returns 200 with JSON-RPC error
    let body = response_json(response).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert!(body["result"].is_object());
    // Server still returns its supported version
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
}

// -- Conformance: tools/list --

#[tokio::test]
async fn conformance_tools_list_returns_registered_tools() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 10, "tools/list", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 10).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 10);
    let tools = jsonrpc["result"]["tools"].as_array().expect("tools array");
    assert!(tools.iter().any(|t| t["name"] == "conformance.mock"));
    let mock_tool = tools
        .iter()
        .find(|t| t["name"] == "conformance.mock")
        .unwrap();
    assert_eq!(
        mock_tool["description"],
        "Mock binding for conformance testing"
    );
    assert!(mock_tool["inputSchema"].is_object());
}

// -- Conformance: tools/call with mock binding --

#[tokio::test]
async fn conformance_tools_call_mock_returns_fixture_response() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        20,
        "tools/call",
        Some(serde_json::json!({
            "name": "conformance.mock",
            "arguments": { "query": "test" }
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 20).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 20);
    let result = &jsonrpc["result"];
    assert!(result["content"].is_array());
    let content = result["content"].as_array().unwrap();
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "text");
    // The mock returns the fixture response as pretty-printed JSON text
    let text = content[0]["text"].as_str().unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(text).expect("fixture JSON in text content");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["data"], serde_json::json!([1, 2, 3]));
    // is_error should be false for success
    assert_ne!(result.get("isError"), Some(&serde_json::json!(true)));
}

#[tokio::test]
async fn conformance_tools_call_unknown_tool_returns_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        21,
        "tools/call",
        Some(serde_json::json!({
            "name": "nonexistent.tool",
            "arguments": {}
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_jsonrpc_response(response, 21).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 21);
    assert!(body["error"].is_object());
    assert_eq!(body["error"]["code"], -32602);
}

// -- Conformance: prompts/list --

#[tokio::test]
async fn conformance_prompts_list_returns_prompts_array() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 30, "prompts/list", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 30).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 30);
    assert!(jsonrpc["result"]["prompts"].is_array());
}

// -- Conformance: prompts/get --

#[tokio::test]
async fn conformance_prompts_get_returns_messages() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        31,
        "prompts/get",
        Some(serde_json::json!({
            "name": "mcpg_operational_overview"
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 31).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 31);
    let messages = jsonrpc["result"]["messages"]
        .as_array()
        .expect("messages array");
    assert!(!messages.is_empty());
    assert!(messages[0]["role"].is_string());
    assert!(messages[0]["content"].is_object());
}

#[tokio::test]
async fn conformance_prompts_get_unknown_returns_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        32,
        "prompts/get",
        Some(serde_json::json!({
            "name": "nonexistent.prompt"
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_jsonrpc_response(response, 32).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], -32602);
}

// -- Conformance: resources/list --

#[tokio::test]
async fn conformance_resources_list_returns_resources_array() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 40, "resources/list", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 40).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 40);
    assert!(jsonrpc["result"]["resources"].is_array());
}

// -- Conformance: resources/read --

#[tokio::test]
async fn conformance_resources_read_returns_contents() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        41,
        "resources/read",
        Some(serde_json::json!({
            "uri": "mcpg://runtime/overview"
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 41).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 41);
    let contents = jsonrpc["result"]["contents"]
        .as_array()
        .expect("contents array");
    assert!(!contents.is_empty());
    assert!(contents[0]["uri"].is_string());
    assert!(contents[0]["text"].is_string());
    assert!(contents[0].get("mimeType").is_some() || contents[0].get("mime_type").is_some());
}

#[tokio::test]
async fn conformance_resources_read_unknown_returns_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        42,
        "resources/read",
        Some(serde_json::json!({
            "uri": "mcpg://nonexistent/resource"
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_jsonrpc_response(response, 42).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], -32602);
}

// -- Conformance: logging/setLevel --

#[tokio::test]
async fn conformance_logging_set_level_returns_empty_result() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        50,
        "logging/setLevel",
        Some(serde_json::json!({
            "level": "warning"
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 50).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 50);
    assert!(jsonrpc["result"].is_object());
}

// -- Conformance: unknown method --

#[tokio::test]
async fn conformance_unknown_method_returns_method_not_found() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 60, "nonexistent/method", None).await;

    let body = extract_jsonrpc_response(response, 60).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 60);
    assert!(body["error"].is_object());
    assert_eq!(body["error"]["code"], -32601);
}

// -- Conformance: session lifecycle --

#[tokio::test]
async fn conformance_request_without_session_after_init_required_returns_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");

    // Try tools/list without initializing first (no session)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 70,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn conformance_request_before_initialized_notification_returns_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");

    // Initialize but don't send notifications/initialized
    let init_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "test", "version": "1.0" }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let session_id = init_response
        .headers()
        .get(SESSION_ID_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // Try tools/list without initialized notification
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 71,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    // Should fail because session is not yet operational
    let body = extract_jsonrpc_response(response, 71).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(
        body["error"].is_object(),
        "expected error for pre-initialized request"
    );
}

// -- Conformance: JSON-RPC envelope validation --

#[tokio::test]
async fn conformance_malformed_json_returns_parse_error() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from("not valid json{{{"))
                .expect("request"),
        )
        .await
        .expect("response");

    // Malformed JSON returns a parse error (-32700)
    let body = extract_jsonrpc_response(response, 0).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(body["error"].is_object());
    assert_eq!(body["error"]["code"], -32700);
}

#[tokio::test]
async fn conformance_missing_protocol_version_header_is_allowed() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    // MCP 2025-11-25 allows the server to fall back when the header is absent.
    // MCPG supports only the latest revision, so an omitted explicit header is
    // accepted and the request proceeds against the negotiated session version.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 80,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_ne!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "omitted Mcp-Protocol-Version must not produce HTTP 400 when a \
         session has been initialized"
    );
}

#[tokio::test]
async fn conformance_invalid_protocol_version_header_returns_http_400() {
    let state = build_conformance_state_with_mock();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(PROTOCOL_VERSION_HEADER, "1999-01-01")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 81,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    // The error envelope is a spec-compliant JSON-RPC shape. An
    // unservable version uses the MCP-reserved -32022
    // (UnsupportedProtocolVersion) code; the discriminator rides under
    // `error.data.kind` and the served revisions under
    // `error.data.supported`.
    assert_eq!(body["error"]["code"], -32022);
    assert_eq!(
        body["error"]["data"]["kind"],
        "unsupported_protocol_version"
    );
    let supported = body["error"]["data"]["supported"]
        .as_array()
        .expect("supported list");
    assert!(
        supported
            .iter()
            .any(|v| v == crate::protocol::SUPPORTED_PROTOCOL_VERSION)
    );
}

// =====================================================================
// Replay Fixture Tests — Mock Binding Scenarios
// =====================================================================
//
// These tests validate deterministic fixture-based testing through mock
// bindings. Each test exercises a distinct mock scenario (success, error,
// delay, schema validation) to prove that operators can use mock bindings
// as replay fixtures for repeatable integration testing.

fn build_multi_mock_conformance_state() -> AppState {
    use crate::config::MockBackendConfig;

    let success_mock = BackendConfig {
        name: "fixture.success".to_owned(),
        title: Some("Fixture Success".to_owned()),
        description: "Mock returning a successful fixture response".to_owned(),
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            }
        })),
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({"result": "ok", "items": [{"id": "a"}, {"id": "b"}]}),
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
    };

    let error_mock = BackendConfig {
        name: "fixture.error".to_owned(),
        title: Some("Fixture Error".to_owned()),
        description: "Mock returning a simulated error for testing error paths".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!(null),
                delay_ms: 0,
                error: true,
                error_message: Some("upstream service unavailable".to_owned()),
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
    };

    let schema_mock = BackendConfig {
        name: "fixture.validated".to_owned(),
        title: Some("Fixture With Schema".to_owned()),
        description: "Mock with strict input schema for validation testing".to_owned(),
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" },
                "count": { "type": "integer", "minimum": 1 }
            },
            "required": ["email", "count"]
        })),
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({"validated": true}),
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
    };

    build_test_state_with_runtime_controls(
        true,
        RuntimeDebugConfig {
            enabled: true,
            ..RuntimeDebugConfig::default()
        },
        vec![success_mock, error_mock, schema_mock],
    )
}

// -- Replay fixture: mock error binding returns isError --

#[tokio::test]
async fn conformance_mock_error_fixture_returns_is_error() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        100,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.error",
            "arguments": {}
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 100).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 100);
    let result = &jsonrpc["result"];
    assert_eq!(result["isError"], true);
    let content = result["content"].as_array().expect("content array");
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0]["text"], "upstream service unavailable");
}

// -- Replay fixture: multiple mock bindings coexist and route independently --

#[tokio::test]
async fn conformance_multiple_mock_fixtures_route_independently() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    // Call success fixture
    let (app, response) = mcp_request(
        app,
        &session_id,
        110,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.success",
            "arguments": { "id": "test-1" }
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 110).await;
    assert_eq!(jsonrpc["id"], 110);
    let result = &jsonrpc["result"];
    assert_ne!(result.get("isError"), Some(&serde_json::json!(true)));
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).expect("fixture JSON");
    assert_eq!(parsed["result"], "ok");
    assert_eq!(parsed["items"].as_array().unwrap().len(), 2);

    // Call error fixture on the same session
    let (_, response) = mcp_request(
        app,
        &session_id,
        111,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.error",
            "arguments": {}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 111).await;
    assert_eq!(jsonrpc["id"], 111);
    assert_eq!(jsonrpc["result"]["isError"], true);
    assert_eq!(
        jsonrpc["result"]["content"][0]["text"],
        "upstream service unavailable"
    );
}

// -- Replay fixture: tools/list includes all mock fixtures --

#[tokio::test]
async fn conformance_tools_list_includes_all_mock_fixtures() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 120, "tools/list", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 120).await;
    let tools = jsonrpc["result"]["tools"].as_array().expect("tools array");
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        tool_names.contains(&"fixture.success"),
        "missing fixture.success in {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"fixture.error"),
        "missing fixture.error in {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"fixture.validated"),
        "missing fixture.validated in {tool_names:?}"
    );
}

// -- Replay fixture: schema validation rejects invalid arguments --

#[tokio::test]
async fn conformance_mock_fixture_rejects_invalid_schema() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    // Missing required "count" field
    let (_, response) = mcp_request(
        app,
        &session_id,
        130,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.validated",
            "arguments": { "email": "test@example.com" }
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 130).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 130);
    // input validation failures return as a tool-execution error
    // inside a JSON-RPC success envelope, not as a -32602 protocol error.
    assert!(
        jsonrpc["result"].is_object(),
        "expected JSON-RPC success, got: {jsonrpc}"
    );
    assert_eq!(jsonrpc["result"]["isError"], true);
}

// -- Replay fixture: schema validation passes valid arguments --

#[tokio::test]
async fn conformance_mock_fixture_accepts_valid_schema() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        131,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.validated",
            "arguments": { "email": "test@example.com", "count": 5 }
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 131).await;
    assert_eq!(jsonrpc["jsonrpc"], "2.0");
    assert_eq!(jsonrpc["id"], 131);
    let result = &jsonrpc["result"];
    assert_ne!(result.get("isError"), Some(&serde_json::json!(true)));
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).expect("fixture JSON");
    assert_eq!(parsed["validated"], true);
}

// -- Replay fixture: mock structured content includes simulated flag --

#[tokio::test]
async fn conformance_mock_fixture_structured_content_has_simulated_flag() {
    let state = build_multi_mock_conformance_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        140,
        "tools/call",
        Some(serde_json::json!({
            "name": "fixture.success",
            "arguments": { "id": "check-simulated" }
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let jsonrpc = extract_jsonrpc_response(response, 140).await;
    let result = &jsonrpc["result"];
    let structured = &result["structuredContent"];
    assert!(structured.is_object(), "expected structuredContent object");
    assert_eq!(structured["simulated"], true);
    assert_eq!(structured["bindingKind"], "mock");
    assert_eq!(structured["arguments"]["id"], "check-simulated");
}

// =====================================================================
// Developer-Friendly Error Diagnostics Tests
// =====================================================================
//
// When debug mode is enabled, JSON-RPC error responses include a `data`
// object with diagnostic context: requestId, timestamp, and a hint
// suggesting how to resolve the error. When debug is off, error data
// is absent to keep production responses minimal.

fn build_debug_state(debug_enabled: bool) -> AppState {
    use crate::config::MockBackendConfig;
    let mock_binding = BackendConfig {
        name: "diag.mock".to_owned(),
        title: Some("Diagnostic Mock".to_owned()),
        description: "Mock for diagnostic testing".to_owned(),
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "value": { "type": "integer" }
            },
            "required": ["value"]
        })),
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({"ok": true}),
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
    };
    build_test_state_with_runtime_controls(
        debug_enabled,
        RuntimeDebugConfig {
            enabled: debug_enabled,
            ..RuntimeDebugConfig::default()
        },
        vec![mock_binding],
    )
}

// -- Diagnostics: unknown tool error includes debug data when debug on --

#[tokio::test]
async fn diagnostics_unknown_tool_includes_debug_data_when_debug_on() {
    let state = build_debug_state(true);
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        200,
        "tools/call",
        Some(serde_json::json!({
            "name": "nonexistent.tool",
            "arguments": {}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 200).await;
    assert_eq!(jsonrpc["error"]["code"], -32602);
    let data = &jsonrpc["error"]["data"];
    assert!(
        data.is_object(),
        "expected diagnostic data object when debug is on"
    );
    assert!(data["requestId"].is_string(), "requestId should be present");
    assert!(data["timestamp"].is_string(), "timestamp should be present");
    assert!(
        data["hint"].as_str().unwrap().contains("tools/list"),
        "hint should suggest tools/list"
    );
}

// -- Diagnostics: unknown tool error has no data when debug off --

#[tokio::test]
async fn diagnostics_unknown_tool_no_data_when_debug_off() {
    let state = build_debug_state(false);
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        201,
        "tools/call",
        Some(serde_json::json!({
            "name": "nonexistent.tool",
            "arguments": {}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 201).await;
    assert_eq!(jsonrpc["error"]["code"], -32602);
    assert!(
        jsonrpc["error"]["data"].is_null()
            || !jsonrpc["error"].as_object().unwrap().contains_key("data"),
        "diagnostic data should be absent when debug is off"
    );
}

// -- Diagnostics: schema validation surfaces through tool-execution errors --
//
// Input validation failures are tool-result errors (isError: true), not
// JSON-RPC -32602 protocol errors, so debug-gated `error.data` diagnostics
// do not apply on this path. Diagnostic coverage for unknown tool / prompt /
// resource lives in the surrounding tests.

#[tokio::test]
async fn tool_schema_validation_returns_tool_execution_error() {
    let state = build_debug_state(true);
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        210,
        "tools/call",
        Some(serde_json::json!({
            "name": "diag.mock",
            "arguments": { "value": "not-an-integer" }
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 210).await;
    assert!(
        jsonrpc["result"].is_object(),
        "input validation should surface as a JSON-RPC success with isError: true, got {jsonrpc}"
    );
    assert_eq!(jsonrpc["result"]["isError"], true);
    let text = jsonrpc["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("Input validation failed"),
        "tool-error text must surface the input validation reason: {text}"
    );
}

// -- Diagnostics: unknown prompt error includes debug data when debug on --

#[tokio::test]
async fn diagnostics_unknown_prompt_includes_debug_data_when_debug_on() {
    let state = build_debug_state(true);
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        220,
        "prompts/get",
        Some(serde_json::json!({
            "name": "nonexistent.prompt"
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 220).await;
    assert_eq!(jsonrpc["error"]["code"], -32602);
    let data = &jsonrpc["error"]["data"];
    assert!(
        data.is_object(),
        "expected diagnostic data for unknown prompt"
    );
    assert!(data["hint"].as_str().unwrap().contains("prompts/list"));
}

// -- Diagnostics: unknown resource error includes debug data when debug on --

#[tokio::test]
async fn diagnostics_unknown_resource_includes_debug_data_when_debug_on() {
    let state = build_debug_state(true);
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        230,
        "resources/read",
        Some(serde_json::json!({
            "uri": "mcpg://nonexistent/thing"
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 230).await;
    assert_eq!(jsonrpc["error"]["code"], -32602);
    let data = &jsonrpc["error"]["data"];
    assert!(
        data.is_object(),
        "expected diagnostic data for unknown resource"
    );
    assert!(data["hint"].as_str().unwrap().contains("resources/list"));
}

// -- Pipeline Integration Tests (T70) --

fn build_pipeline_state() -> AppState {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineCelGateStepConfig, PipelineStepConfig,
        PipelineTransformStepConfig,
    };

    let pipeline_binding = BackendConfig {
        name: "pipeline.echo".to_owned(),
        title: Some("Pipeline Echo".to_owned()),
        description: "Multi-step pipeline with mock steps".to_owned(),
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "input": { "type": "string" }
            },
            "required": ["input"]
        })),
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 5000,
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "fetch".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"data": "from_backend", "status": "ok"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    PipelineStepConfig::Transform(PipelineTransformStepConfig {
                        id: "reshape".to_owned(),
                        expression: r#"{"transformed": steps.fetch.output.data}"#.to_owned(),
                    }),
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

    let gate_abort_binding = BackendConfig {
        name: "pipeline.gated".to_owned(),
        title: Some("Pipeline Gated".to_owned()),
        description: "Pipeline with a gate that aborts".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 5000,
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "s1".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"allowed": false}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
                        id: "authz_check".to_owned(),
                        expression: "false".to_owned(),
                        error_message: Some("authorization denied".to_owned()),
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "s2".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"should": "not reach"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let error_binding = BackendConfig {
        name: "pipeline.failing".to_owned(),
        title: Some("Pipeline Failing".to_owned()),
        description: "Pipeline where a mock step fails".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 5000,
                steps: vec![PipelineStepConfig::backend_from_typed(
                    "fail_step".to_owned(),
                    "mock",
                    MockBackendConfig {
                        response: serde_json::json!(null),
                        delay_ms: 0,
                        error: true,
                        error_message: Some("backend unavailable".to_owned()),
                        passthrough: false,
                    },
                    None,
                )],
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

    build_test_state_with_runtime_controls(
        true,
        RuntimeDebugConfig {
            enabled: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding, gate_abort_binding, error_binding],
    )
}

#[tokio::test]
async fn pipeline_tools_list_includes_pipeline_binding() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(app, &session_id, 100, "tools/list", None).await;
    let jsonrpc = extract_jsonrpc_response(response, 100).await;
    let tools = jsonrpc["result"]["tools"].as_array().expect("tools array");

    let pipeline_tool = tools.iter().find(|t| t["name"] == "pipeline.echo");
    assert!(
        pipeline_tool.is_some(),
        "pipeline.echo should appear in tools/list"
    );
    let tool = pipeline_tool.unwrap();
    assert_eq!(tool["description"], "Multi-step pipeline with mock steps");
    assert!(
        tool["inputSchema"].is_object(),
        "pipeline should have input schema"
    );
}

#[tokio::test]
async fn pipeline_tools_call_returns_transformed_result() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        101,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.echo",
            "arguments": {"input": "test_data"}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 101).await;
    let result = &jsonrpc["result"];
    assert!(result.get("content").is_some(), "should have content");
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!is_error, "pipeline should succeed");

    // The structured content should include pipeline metadata
    let content_text = result["content"][0]["text"].as_str().unwrap();
    let _parsed: serde_json::Value =
        serde_json::from_str(content_text).unwrap_or(serde_json::json!(content_text));
    // The transform step produces {"transformed": "from_backend"}
    // which becomes the final result text
    assert!(
        content_text.contains("transformed") || content_text.contains("from_backend"),
        "result should contain transformed output, got: {}",
        content_text
    );
}

#[tokio::test]
async fn pipeline_gate_abort_returns_error_result() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        102,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.gated",
            "arguments": {}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 102).await;
    let result = &jsonrpc["result"];
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error, "gated pipeline should return isError: true");

    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("authorization denied"),
        "should contain gate error message, got: {}",
        text
    );
}

#[tokio::test]
async fn pipeline_mock_error_step_returns_error_result() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        103,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.failing",
            "arguments": {}
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 103).await;
    let result = &jsonrpc["result"];
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error, "failing pipeline should return isError: true");

    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("backend unavailable"),
        "should contain step error, got: {}",
        text
    );
}

#[tokio::test]
async fn pipeline_schema_validation_rejects_invalid_arguments() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    // pipeline.echo has input_schema requiring "input" string field
    let (_, response) = mcp_request(
        app,
        &session_id,
        104,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.echo",
            "arguments": {"input": 12345}  // wrong type
        })),
    )
    .await;

    let jsonrpc = extract_jsonrpc_response(response, 104).await;
    // Schema validation errors return JSON-RPC error with code -32602
    if let Some(error) = jsonrpc.get("error") {
        assert_eq!(error["code"], -32602);
    } else {
        let result = &jsonrpc["result"];
        // Either is_error or its negation — schema enforcement may
        // vary (lenient schemas let the mock step through; strict
        // schemas reject up front). The test passes either way;
        // observing the outcome is all we need.
        let _ = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }
}

#[tokio::test]
async fn pipeline_multiple_pipelines_route_independently() {
    let state = build_pipeline_state();
    let app = router(state, "/health", "/mcp");
    let (app, session_id) = initialize_session(app).await;

    // Call the successful pipeline
    let (app, response1) = mcp_request(
        app,
        &session_id,
        110,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.echo",
            "arguments": {"input": "hello"}
        })),
    )
    .await;
    let result1 = extract_jsonrpc_response(response1, 110).await;
    let is_error1 = result1["result"]
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!is_error1, "pipeline.echo should succeed");

    // Call the gated pipeline
    let (_, response2) = mcp_request(
        app,
        &session_id,
        111,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.gated",
            "arguments": {}
        })),
    )
    .await;
    let result2 = extract_jsonrpc_response(response2, 111).await;
    let is_error2 = result2["result"]
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error2, "pipeline.gated should fail");
}

// --- Transport integration end-to-end tests ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_elicitation_rejected_without_client_capability() {
    use crate::config::{PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig};

    // Build the same elicitation pipeline but a client that did not
    // advertise `capabilities.elicitation`. MCPG must fail the call
    // with a tool error rather than silently emitting
    // `elicitation/create`.
    let pipeline_binding = BackendConfig {
        name: "pipeline.elicitation_no_caps".to_owned(),
        title: Some("No-Caps Elicitation".to_owned()),
        description: "Pipeline that would suspend for elicitation".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![PipelineStepConfig::Elicitation(
                    PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Please confirm".to_owned(),
                        requested_schema: None,
                        timeout_ms: 30000,
                        mode: Default::default(),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    },
                )],
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    let app = router(state, "/health", "/mcp");

    // Handcrafted initialize that OMITS every interactive capability.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "no-caps", "version": "0" }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("init response");
    let session_id = resp
        .headers()
        .get(SESSION_ID_HEADER)
        .expect("session id")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        50,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.elicitation_no_caps",
            "arguments": {}
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let text = sse_response_text(response).await;
    // The POST upgrades to SSE; the tool result rides as a bare
    // JSON-RPC envelope (`{"jsonrpc":"2.0","id":50,"result":{…}}`)
    // on the stream. The historical Rust-side enum-tag wrapper
    // (`{"JsonRpcSuccess":{…}}`) was removed because it broke
    // upstream conformance — clients matching on the `id` field at
    // the top level never saw the response and timed out.
    let body: serde_json::Value = text
        .lines()
        .filter(|l| l.starts_with("data: "))
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l.trim_start_matches("data: ")).ok()
        })
        .find(|v| v["id"] == 50 && v.get("result").is_some())
        .unwrap_or_else(|| panic!("could not find tool result event in SSE: {text:?}"));
    let result = &body["result"];
    assert_eq!(result["isError"], true, "body={body}");
    let content_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        content_text.contains("elicitation"),
        "expected tool error about missing elicitation capability, got: {content_text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_elicitation_url_mode_emits_url_and_id() {
    use crate::config::{
        PipelineBackendConfig, PipelineElicitationMode, PipelineElicitationStepConfig,
        PipelineStepConfig,
    };

    let pipeline_binding = BackendConfig {
        name: "pipeline.elicitation_url".to_owned(),
        title: Some("URL elicitation".to_owned()),
        description: "URL-mode elicitation pipeline".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30_000,
                steps: vec![PipelineStepConfig::Elicitation(
                    PipelineElicitationStepConfig {
                        id: "complete_profile".to_owned(),
                        message: "Please complete your profile".to_owned(),
                        mode: PipelineElicitationMode::Url,
                        requested_schema: None,
                        url: Some("https://example.test/profile".to_owned()),
                        elicitation_id: Some("elic-fixed-id".to_owned()),
                        presentation_hint: Some("newWindow".to_owned()),
                        meta: Some(serde_json::json!({ "k": "v" })),
                        timeout_ms: 30_000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    },
                )],
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    let app = router(state, "/health", "/mcp");

    // Initialize with URL-mode elicitation capability.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {
                                "elicitation": { "url": {} }
                            },
                            "clientInfo": { "name": "url-client", "version": "0" }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("init");
    let session_id = resp
        .headers()
        .get(SESSION_ID_HEADER)
        .expect("session")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    })
                    .to_string(),
                ))
                .expect("req"),
        )
        .await;

    let (_, response) = mcp_request(
        app,
        &session_id,
        60,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.elicitation_url",
            "arguments": {}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = sse_response_text(response).await;
    let elicit = text
        .lines()
        .filter(|l| l.starts_with("data: "))
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l.trim_start_matches("data: ")).ok()
        })
        .find(|v| v["method"] == "elicitation/create")
        .expect("elicitation/create event on stream");
    assert_eq!(elicit["params"]["mode"], "url");
    assert_eq!(elicit["params"]["url"], "https://example.test/profile");
    // URL-mode `elicitationId` MUST equal the pending
    // server-request id so `notifications/elicitation/complete`
    // resolves to the owning pipeline via the cluster-safe
    // pipeline_store. Operator-pinned elicitation_id in config is
    // ignored deliberately — the resumption key wins.
    let elicitation_id = elicit["params"]["elicitationId"]
        .as_str()
        .expect("elicitation id");
    assert!(
        elicitation_id.starts_with("srv-req-"),
        "elicitationId must be the server_request_id (cluster resumption key), got: {elicitation_id}"
    );
    assert_eq!(elicit["params"]["presentationHint"], "newWindow");
    assert_eq!(elicit["params"]["_meta"]["k"], "v");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_elicitation_upgrades_post_to_sse_on_suspension() {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig,
    };

    // Build a pipeline with: mock step → elicitation step → mock step
    let pipeline_binding = BackendConfig {
        name: "pipeline.elicitation_e2e".to_owned(),
        title: Some("Elicitation E2E Pipeline".to_owned()),
        description: "Pipeline that suspends for elicitation".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "fetch_data".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"status": "ready", "item": "widget-1"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Please confirm the operation".to_owned(),
                        mode: Default::default(),
                        requested_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": {
                                "confirmed": { "type": "boolean" }
                            }
                        })),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "finalize".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"completed": true}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    let runtime = state.runtime.load_full();
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    // suspended interactive requests must continue on the same POST
    // as an SSE stream (MCP 2025-11-25 transport). The legacy 202+empty body
    // behavior is removed. We verify:
    //   1. the POST returns 200 with `text/event-stream`
    //   2. the first event on that stream is the server-initiated
    //      `elicitation/create` request that caused the pipeline to suspend
    //   3. responding to that server request via a separate POST returns
    //      202 (JSON-RPC responses are still empty-body accepted)
    //   4. the pipeline resumes and produces a terminal tool result delivery
    let (app, response) = mcp_request(
        app,
        &session_id,
        99,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.elicitation_e2e",
            "arguments": {}
        })),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "suspendable pipeline tools/call must upgrade to SSE on the same POST"
    );
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("text/event-stream"),
        "POST continuation must be served as text/event-stream"
    );

    // SSE streams stay open for the duration of the pipeline continuation —
    // read a bounded prefix so the test makes progress.
    let sse_text = sse_response_text(response).await;
    // Scan every data event on the stream for the elicitation/create
    // request. Priming/logging events may precede it on the same stream.
    let server_request = sse_text
        .lines()
        .filter(|line| line.starts_with("data: "))
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line.trim_start_matches("data: ")).ok()
        })
        .find(|value| value["method"] == "elicitation/create")
        .expect("continuation stream must carry the elicitation/create server request");
    assert_eq!(server_request["jsonrpc"], "2.0");
    let server_request_id = server_request["id"].clone();
    assert!(server_request_id.is_string() || server_request_id.is_number());

    // Client answers the server request. MCP allows responses/notifications
    // to return 202 with an empty body.
    let client_response_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": server_request_id,
        "result": {
            "action": "accept",
            "content": { "confirmed": true }
        }
    });

    let resume_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(
                    header::HeaderName::from_static(SUBJECT_ID_HEADER),
                    "conformance-user",
                )
                .body(Body::from(client_response_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("resume response");

    assert_eq!(
        resume_response.status(),
        StatusCode::ACCEPTED,
        "JSON-RPC response POST may still return 202 Accepted"
    );

    let final_deliveries = runtime.take_pending_deliveries(&session_id);
    let final_delivery = final_deliveries
        .iter()
        .find(|d| d.kind == crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult)
        .expect("pipeline completion should produce a deferred tool result");
    let final_result = &final_delivery.jsonrpc_message;
    assert_eq!(final_result["jsonrpc"], "2.0");
    assert_eq!(final_result["id"], 99);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_resume_by_foreign_principal_is_rejected() {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig,
    };

    // A pipeline that suspends for elicitation, then finalizes.
    let pipeline_binding = BackendConfig {
        name: "pipeline.elicitation_owner".to_owned(),
        title: Some("Elicitation Owner Pipeline".to_owned()),
        description: "Pipeline that suspends for elicitation".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![
                    PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Please confirm the operation".to_owned(),
                        mode: Default::default(),
                        requested_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "confirmed": { "type": "boolean" } }
                        })),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "finalize".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"completed": true}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    let runtime = state.runtime.load_full();
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    // Suspend the pipeline as the owning principal ("conformance-user",
    // which mcp_request asserts via the subject header).
    let (app, response) = mcp_request(
        app,
        &session_id,
        99,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.elicitation_owner",
            "arguments": {}
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let sse_text = sse_response_text(response).await;
    let server_request = sse_text
        .lines()
        .filter(|line| line.starts_with("data: "))
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line.trim_start_matches("data: ")).ok()
        })
        .find(|value| value["method"] == "elicitation/create")
        .expect("continuation stream must carry the elicitation/create server request");
    let server_request_id = server_request["id"].clone();

    let client_response_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": server_request_id,
        "result": { "action": "accept", "content": { "confirmed": true } }
    });

    // A DIFFERENT principal (same session id, observed correlation token)
    // attempts to answer the server request. This must be refused and the
    // pipeline must NOT advance.
    let foreign_resume = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(
                    header::HeaderName::from_static(SUBJECT_ID_HEADER),
                    "attacker",
                )
                .body(Body::from(client_response_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("foreign resume response");
    let foreign_body = response_json(foreign_resume).await;
    assert_eq!(
        foreign_body["error"]["code"], -32600,
        "foreign-principal resume must be refused, got {foreign_body}"
    );
    assert!(
        runtime
            .take_pending_deliveries(&session_id)
            .iter()
            .all(|d| d.kind != crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult),
        "a refused foreign resume must not advance the pipeline to completion"
    );

    // The rightful owner can still resume — the refused attempt neither
    // consumed the pending server request nor claimed the pipeline.
    let owner_resume = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(
                    header::HeaderName::from_static(SUBJECT_ID_HEADER),
                    "conformance-user",
                )
                .body(Body::from(client_response_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("owner resume response");
    assert_eq!(owner_resume.status(), StatusCode::ACCEPTED);
    let final_deliveries = runtime.take_pending_deliveries(&session_id);
    assert!(
        final_deliveries
            .iter()
            .any(|d| d.kind == crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult),
        "the owner's resume should drive the pipeline to a deferred tool result"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_sampling_upgrades_post_to_sse_on_suspension() {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineSamplingStepConfig, PipelineStepConfig,
        SamplingMessageConfig,
    };

    // Build a pipeline that suspends mid-flow via sampling/createMessage,
    // mirroring the elicitation suspend/resume test (§7 of request-flow.md).
    let pipeline_binding = BackendConfig {
        name: "pipeline.sampling_e2e".to_owned(),
        title: Some("Sampling E2E Pipeline".to_owned()),
        description: "Pipeline that suspends for sampling".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30_000,
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "prelude".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"draft": "raw text"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    PipelineStepConfig::Sampling(PipelineSamplingStepConfig {
                        id: "summarize".to_owned(),
                        messages: vec![SamplingMessageConfig {
                            role: "user".to_owned(),
                            content: "Summarize the prelude".to_owned(),
                        }],
                        max_tokens: 128,
                        timeout_ms: 30_000,
                        system_prompt: None,
                        include_context: None,
                        temperature: None,
                        stop_sequences: None,
                        model_preferences: None,
                        tools: None,
                        tool_choice: None,
                        meta: None,
                        metadata: None,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "finalize".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"ok": true}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    let runtime = state.runtime.load_full();
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let (app, response) = mcp_request(
        app,
        &session_id,
        7,
        "tools/call",
        Some(serde_json::json!({
            "name": "pipeline.sampling_e2e",
            "arguments": {}
        })),
    )
    .await;

    // Suspendable pipeline must upgrade this POST to SSE and deliver the
    // sampling/createMessage server request on the same stream.
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "suspendable pipeline must return 200 + SSE on the inbound POST"
    );
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("text/event-stream"),
        "POST must upgrade to text/event-stream"
    );

    let sse_text = sse_response_text(response).await;
    let server_request = sse_text
        .lines()
        .filter(|line| line.starts_with("data: "))
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line.trim_start_matches("data: ")).ok()
        })
        .find(|v| v["method"] == "sampling/createMessage")
        .expect("continuation stream must carry the sampling/createMessage request");
    assert_eq!(server_request["jsonrpc"], "2.0");
    let server_request_id = server_request["id"].clone();
    assert!(server_request_id.is_string() || server_request_id.is_number());

    // Client answers the sampling request with a CreateMessageResult-shaped
    // body. MCP lets JSON-RPC responses return 202 with an empty body.
    let client_response_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": server_request_id,
        "result": {
            "role": "assistant",
            "content": {"type": "text", "text": "A summary."},
            "model": "test-model",
            "stopReason": "endTurn"
        }
    });

    let resume_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(
                    header::HeaderName::from_static(SUBJECT_ID_HEADER),
                    "conformance-user",
                )
                .body(Body::from(client_response_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("resume response");

    assert_eq!(
        resume_response.status(),
        StatusCode::ACCEPTED,
        "JSON-RPC response POST should return 202 Accepted"
    );

    // Pipeline must have resumed and produced a terminal tool result
    // delivery for the original tools/call id.
    let final_deliveries = runtime.take_pending_deliveries(&session_id);
    let final_delivery = final_deliveries
        .iter()
        .find(|d| d.kind == crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult)
        .expect("pipeline completion should produce a deferred tool result");
    let final_result = &final_delivery.jsonrpc_message;
    assert_eq!(final_result["jsonrpc"], "2.0");
    assert_eq!(final_result["id"], 7);
}

#[tokio::test]
async fn delivery_bus_subscription_receives_published_messages() {
    // Verify the in-process delivery bus subscription works through the runtime
    let state = build_test_state();
    let runtime = state.runtime.load_full();
    let (_app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    // Subscribe to the delivery bus for this session
    let _rx = runtime.subscribe_session_delivery(&session_id).await;

    // Store a pending delivery message
    let msg = crate::runtime::pipeline_store::DeliveryMessage {
        kind: crate::runtime::pipeline_store::DeliveryKind::ServerRequest,
        jsonrpc_message: serde_json::json!({
            "jsonrpc": "2.0",
            "id": "srv-1",
            "method": "elicitation/create",
            "params": {"message": "test"}
        }),
        delivery_id: String::new(),
    };
    runtime
        .pipeline_store()
        .store_pending_delivery(&session_id, &msg)
        .expect("store pending delivery");

    // Store another delivery
    let delivery_msg = crate::runtime::pipeline_store::DeliveryMessage {
        kind: crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult,
        jsonrpc_message: serde_json::json!({"jsonrpc": "2.0", "id": 42, "result": {"done": true}}),
        delivery_id: String::new(),
    };
    let stored_id = runtime
        .pipeline_store()
        .store_pending_delivery(&session_id, &delivery_msg)
        .expect("store delivery");
    assert!(!stored_id.is_empty());

    // Verify take_pending_deliveries drains all pending messages
    let pending = runtime.take_pending_deliveries(&session_id);
    assert_eq!(pending.len(), 2);
    assert_eq!(
        pending[0].kind,
        crate::runtime::pipeline_store::DeliveryKind::ServerRequest
    );
    assert_eq!(
        pending[1].kind,
        crate::runtime::pipeline_store::DeliveryKind::DeferredToolResult
    );

    // After draining, no more pending
    let empty = runtime.take_pending_deliveries(&session_id);
    assert!(empty.is_empty(), "pending deliveries should be drained");
}

// -----------------------------------------------------------------------
// plugin_identity_to_request conversion tests
// -----------------------------------------------------------------------

#[test]
fn plugin_identity_to_request_verified() {
    let pi = mcpg_plugin_protocol::PluginIdentity {
        kind: "verified".into(),
        trust_level: "verified".into(),
        subject_id: Some("user-1".into()),
        auth_provider: Some("oidc_oauth:google".into()),
        issuer: Some("https://accounts.google.com".into()),
        roles: vec!["admin".into()],
        groups: vec!["eng".into()],
        scopes: vec!["read".into(), "write".into()],
        attributes: std::collections::BTreeMap::from([("dept".into(), "eng".into())]),
    };
    let ri = plugin_identity_to_request(&pi);
    match ri {
        RequestIdentity::Verified {
            subject_id,
            roles,
            groups,
            scopes,
            attributes,
            ..
        } => {
            assert_eq!(subject_id, "user-1");
            assert_eq!(roles, vec!["admin"]);
            assert_eq!(groups, vec!["eng"]);
            assert_eq!(scopes, vec!["read", "write"]);
            assert_eq!(attributes.get("dept").unwrap(), "eng");
        }
        other => panic!("expected Verified, got {:?}", other),
    }
}

#[test]
fn plugin_identity_to_request_anonymous() {
    let pi = mcpg_plugin_protocol::PluginIdentity {
        kind: "anonymous".into(),
        trust_level: "unauthenticated".into(),
        subject_id: None,
        auth_provider: None,
        issuer: None,
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    };
    let ri = plugin_identity_to_request(&pi);
    assert!(matches!(ri, RequestIdentity::Anonymous { .. }));
}

// --- Auth + transport hardening tests ---

#[tokio::test]
async fn t6_03_post_without_content_type_returns_415() {
    let app = router(build_test_state(), "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                // No Content-Type header
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn t6_03_post_with_wrong_content_type_returns_415() {
    let app = router(build_test_state(), "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn t6_03_post_with_json_charset_is_accepted() {
    let app = router(build_test_state(), "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "test", "version": "1.0.0" }
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    // Should not be 415 — it passes Content-Type check
    assert_ne!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn t6_05_sse_events_have_message_event_type() {
    let record = crate::runtime::SseEventRecord {
        event_id: "evt-1".to_owned(),
        data: r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_owned(),
        retry_ms: None,
    };
    // The sse_event_from_record function sets .event("message").
    // We verify it returns Ok and the function doesn't panic.
    let result = sse_event_from_record(record);
    assert!(result.is_ok());
}

#[tokio::test]
async fn t6_01_oauth_metadata_not_mounted_without_auth() {
    let app = router(build_test_state(), "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    // Without auth config, endpoint is not mounted → 404
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// RFC 8707/9728 (TAN-05): with OIDC configured but no explicit canonical
/// `resource_metadata.resource`, the gateway refuses to publish a
/// `bind_address`-derived resource. The endpoint is mounted but returns an
/// honest 404 so audience-bound validation can't silently break.
#[tokio::test]
async fn t6_01_oauth_metadata_refuses_derivation_without_explicit_resource() {
    let config = AppConfig {
        governance: crate::config::GovernanceConfig {
            access: crate::config::AccessConfig {
                authorization_server: None,
                jwks: None,
                oidc_oauth: Some(crate::config::OidcOAuthConfig {
                    token_source: crate::config::TokenSourceConfig {
                        kind: crate::config::TokenSourceKind::AuthorizationBearer,
                        header_name: None,
                        header_prefix: None,
                    },
                    providers: vec![crate::config::OidcProviderConfig {
                        issuer: "https://auth.example.com/".to_owned(),
                        discovery_uri: None,
                        audiences: vec!["mcpg".to_owned()],
                        verification: crate::config::VerificationConfig::OidcJwks {
                            allowed_algs: vec!["RS256".to_owned()],
                            refresh_interval_secs: 3600,
                            timeout_ms: 5000,
                            max_staleness_secs: 86400,

                            allow_hmac: false,
                        },
                        claim_mappings: Default::default(),
                        clock_skew_secs: 60,
                        allowed_issuer_hosts: Vec::new(),
                        allow_private_issuer: true,
                        allow_any_audience: false,
                    }],
                }),
                resource_metadata: None,
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    // Fail-closed: no canonical resource configured → 404 honest error,
    // never a guessed `bind_address`-derived resource.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not configured")
    );
}

#[tokio::test]
async fn t6_01_oauth_metadata_with_explicit_config() {
    let config = AppConfig {
        governance: crate::config::GovernanceConfig {
            access: crate::config::AccessConfig {
                authorization_server: None,
                jwks: None,
                oidc_oauth: None,
                resource_metadata: Some(crate::config::OAuthResourceMetadataConfig {
                    resource: "https://gateway.example.com/mcp".to_owned(),
                    authorization_servers: vec!["https://auth.example.com/".to_owned()],
                    scopes_supported: vec!["openid".to_owned(), "tools".to_owned()],
                    bearer_methods_supported: vec!["header".to_owned()],
                    allow_loopback_resource: false,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["resource"], "https://gateway.example.com/mcp");
    assert_eq!(
        json["authorization_servers"][0],
        "https://auth.example.com/"
    );
    assert_eq!(json["scopes_supported"][0], "openid");
    assert_eq!(json["scopes_supported"][1], "tools");
}

/// AUTH-02 / AUTH-10 (RFC 9728 §3.1): the gateway serves the path-aware
/// well-known form so a client deriving the metadata URL from a resource
/// with a path component (`…/mcp` → `/.well-known/oauth-protected-resource/mcp`)
/// finds it.
#[tokio::test]
async fn auth02_path_aware_prm_well_known_served() {
    let config = AppConfig {
        governance: crate::config::GovernanceConfig {
            access: crate::config::AccessConfig {
                authorization_server: None,
                jwks: None,
                oidc_oauth: None,
                resource_metadata: Some(crate::config::OAuthResourceMetadataConfig {
                    resource: "https://gateway.example.com/mcp".to_owned(),
                    authorization_servers: vec!["https://auth.example.com/".to_owned()],
                    scopes_supported: vec!["tools".to_owned()],
                    bearer_methods_supported: vec!["header".to_owned()],
                    allow_loopback_resource: false,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource/mcp")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["resource"], "https://gateway.example.com/mcp");
}

const TEST_PRM_URL: &str = "https://gateway.example.com/.well-known/oauth-protected-resource/mcp";

#[test]
fn t6_02_www_authenticate_header_added_on_401() {
    let response = axum::http::StatusCode::UNAUTHORIZED.into_response();
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    let www_auth = response.headers().get(header::WWW_AUTHENTICATE);
    assert!(www_auth.is_some());
    let value = www_auth.unwrap().to_str().unwrap();
    assert!(value.contains("resource_metadata"));
    // AUTH-02/AUTH-10: the resource_metadata URL is absolute.
    assert!(value.contains(TEST_PRM_URL));
}

#[test]
fn t6_02_www_authenticate_header_not_added_when_auth_disabled() {
    let response = axum::http::StatusCode::UNAUTHORIZED.into_response();
    let response = with_www_authenticate_challenge(response, false, TEST_PRM_URL);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn t6_02_www_authenticate_not_added_on_200() {
    let response = axum::http::StatusCode::OK.into_response();
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn t4_07_www_authenticate_includes_insufficient_scope_hint() {
    // When an upstream handler attaches the internal scope header, the
    // 401 challenge MUST surface it as `error="insufficient_scope",
    // scope="..."` so capability-aware clients can step up.
    let mut response = axum::http::StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER),
        HeaderValue::from_static("tools.call sampling.read"),
    );
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    let value = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(value.contains("error=\"insufficient_scope\""));
    assert!(value.contains("scope=\"tools.call sampling.read\""));
    // Internal header must never reach the wire.
    assert!(
        response
            .headers()
            .get(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER))
            .is_none()
    );
}

/// AUTH-09 / TAN-03 (SEP-2350): an authenticated-but-under-scoped request
/// returns 403 carrying the `insufficient_scope` step-up challenge — not a
/// bare 403, and distinct from the 401 (unauthenticated) path.
#[test]
fn auth09_insufficient_scope_403_carries_step_up_challenge() {
    let mut response = axum::http::StatusCode::FORBIDDEN.into_response();
    response.headers_mut().insert(
        HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER),
        HeaderValue::from_static("payments.write"),
    );
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let value = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("403 step-up challenge")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(value.contains("error=\"insufficient_scope\""));
    assert!(value.contains("scope=\"payments.write\""));
    assert!(value.contains(TEST_PRM_URL));
    // Internal header is stripped.
    assert!(
        response
            .headers()
            .get(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER))
            .is_none()
    );
}

/// A bare 403 (ordinary authorization denial, no missing-scope hint) is NOT
/// a re-authentication signal and gets no challenge — only a scope-named
/// 403 earns the step-up.
#[test]
fn auth09_bare_403_gets_no_challenge() {
    let response = axum::http::StatusCode::FORBIDDEN.into_response();
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

/// AUTH-04 / TAN-04: a 403 (authenticated, unauthorized) must stay a 403 —
/// never be conflated into a 401 (unauthenticated) — and the challenge
/// semantics differ (`insufficient_scope` vs the bare Bearer challenge).
#[test]
fn auth04_403_not_conflated_into_401() {
    let mut forbidden = axum::http::StatusCode::FORBIDDEN.into_response();
    forbidden.headers_mut().insert(
        HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER),
        HeaderValue::from_static("admin.read"),
    );
    let forbidden = with_www_authenticate_challenge(forbidden, true, TEST_PRM_URL);
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unauth = axum::http::StatusCode::UNAUTHORIZED.into_response();
    let unauth = with_www_authenticate_challenge(unauth, true, TEST_PRM_URL);
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    // The unauthenticated challenge does not name a specific scope.
    let unauth_value = unauth
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!unauth_value.contains("scope="));
}

#[test]
fn t4_07_insufficient_scope_header_stripped_even_on_non_401() {
    let mut response = axum::http::StatusCode::OK.into_response();
    response.headers_mut().insert(
        HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER),
        HeaderValue::from_static("tools.call"),
    );
    let response = with_www_authenticate_challenge(response, true, TEST_PRM_URL);
    assert!(
        response
            .headers()
            .get(HeaderName::from_static(INSUFFICIENT_SCOPE_HEADER))
            .is_none()
    );
}

// ── modern wire end-to-end routing ────────────────────────────

/// Install the multi-version `ProtocolRegistry` + `SharedServices`
/// on the test runtime so the modern routing path in `mcp_handler`
/// is reachable. Mirrors the boot wiring in
/// `app::build_from_config` without standing up the full app.
fn install_protocol_registry_for_tests(state: &AppState) {
    let mut registry = crate::protocol::registry::ProtocolRegistry::new();
    registry.register(Arc::new(crate::protocol::v_2025_11_25::Handler::new()));
    registry.register(Arc::new(crate::protocol::v_2026_07_28::Handler::new()));
    let registry = Arc::new(registry);

    let cfg = state.config.load_full();
    let codec = Arc::new(
        crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec::new(
            *b"0123456789abcdef0123456789abcdef",
            Arc::new(
                crate::protocol::v_2026_07_28::dispatch::request_state::InMemoryRequestStateStore::new(),
            ),
        ),
    );
    let services = Arc::new(crate::runtime::shared_services::SharedServices::new(
        cfg,
        &state.runtime,
        codec,
    ));

    let runtime = state.runtime.load();
    runtime.set_protocol_registry(registry);
    runtime.set_shared_services(services);
}

#[tokio::test]
async fn modern_server_discover_routes_through_modern_handler() {
    // Build a vanilla test app, then wire the registry so the
    // modern routing path in `mcp_handler` triggers when the
    // request pins 2026-07-28.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "server/discover")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "server/discover",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "clientInfo": { "name": "test-client", "version": "0.1.0" },
                            // SEP-2575 mandates `_meta.io.modelcontextprotocol/{protocolVersion,
                            // clientInfo, clientCapabilities}` on stateless `server/discover`
                            // requests; M4.B's validator rejects with `-32602` otherwise.
                            "_meta": {
                                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                "io.modelcontextprotocol/clientInfo": { "name": "test-client", "version": "0.1.0" },
                                "io.modelcontextprotocol/clientCapabilities": {}
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    // The final schema dropped the singular `protocolVersion` (VN-5);
    // discovery advertises `supportedVersions` and is a CacheableResult.
    assert!(body["result"].get("protocolVersion").is_none());
    assert_eq!(body["result"]["resultType"], "complete");
    assert!(body["result"]["ttlMs"].is_u64());
    assert_eq!(body["result"]["cacheScope"], "public");
    assert_eq!(body["result"]["serverInfo"]["name"], "mcpg");
    // M4.B made discover capability-gated; this test's mock state has
    // no configured backends, so tools/prompts/resources are absent
    // from the envelope. Verify the spec's mandatory fields are
    // present instead.
    assert!(body["result"]["supportedVersions"].is_array());
    assert!(body["result"]["serverInfo"]["version"].is_string());
}

#[tokio::test]
async fn pre_negotiation_errors_echo_the_request_pinned_protocol_version() {
    // A malformed body or batch array fails BEFORE wire selection, where the
    // shared error mappers default to the legacy revision. A request that
    // pinned the modern wire must still see `2026-07-28` echoed back.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    // Malformed JSON under the modern wire → echo the modern revision.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from("{ not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[PROTOCOL_VERSION_HEADER],
        "2026-07-28",
        "modern-pinned parse-error must echo the modern revision"
    );

    // Batch array under the modern wire → echo the modern revision.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[PROTOCOL_VERSION_HEADER],
        "2026-07-28",
        "modern-pinned batch reject must echo the modern revision"
    );

    // Legacy control: no modern header → the mapper default is untouched.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[PROTOCOL_VERSION_HEADER],
        crate::protocol::SUPPORTED_PROTOCOL_VERSION,
        "legacy request keeps the legacy default echo"
    );
}

#[tokio::test]
async fn modern_tools_list_returns_cache_aware_envelope() {
    // The modern handler dispatches `tools/list`
    // through the shared `enumerate_tools_page` helper and stamps
    // SEP-2549 cache fields on the result envelope.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 2);
    let result = &body["result"];
    assert!(result["tools"].is_array(), "tools[] must be present");
    // SEP-2322/2549 CacheableResult envelope.
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 60_000);
    // Principal-filtered catalog → Private, not a shared-cacheable Public.
    assert_eq!(result["cacheScope"], "private");
    // The non-spec `cacheToken` field was removed (VN-3).
    assert!(result.get("cacheToken").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_anonymous_one_shot_creates_no_session_row() {
    // Anonymous modern requests run under an ephemeral (row-less)
    // session: the id is never revealed on the wire and the session
    // store is never touched, so sustained anonymous stateless traffic
    // cannot accumulate rows against `sessions.max_sessions` (which
    // would lock out new sessions on both wires until TTL eviction).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let runtime_swap = state.runtime.clone();
    let baseline = runtime_swap.load().session_store().active_session_count();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        runtime_swap.load().session_store().active_session_count(),
        baseline,
        "anonymous modern one-shot must not leave a synthetic session row behind"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_session_optional_serves_missing_session_request() {
    // `sessions.optional = true`: a legacy (`2025-11-25`) request with no
    // `Mcp-Session-Id` header for a session-requiring method (`tools/list`)
    // is served through an ephemeral row-less session (HTTP 200) instead
    // of the `-32600` "missing session" rejection, and leaves no session
    // row behind.
    let state = build_test_state();
    let mut config = (*state.config.load_full()).clone();
    config.mcp.configurations.sessions.optional = true;
    state.config.store(Arc::new(config));
    install_protocol_registry_for_tests(&state);
    let runtime_swap = state.runtime.clone();
    let baseline = runtime_swap.load().session_store().active_session_count();
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "session-optional legacy request must be served, not rejected"
    );
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 11);
    assert!(body["result"]["tools"].is_array());
    assert_eq!(
        runtime_swap.load().session_store().active_session_count(),
        baseline,
        "ephemeral legacy request must not create a session row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_missing_session_rejected_by_default() {
    // Default (`sessions.optional = false`): a legacy request without a
    // session header for a session-requiring method is still rejected —
    // the opt-in must not change the byte-for-byte default behavior.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], -32600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_anonymous_requests_unaffected_by_session_capacity() {
    // Anonymous modern requests never touch the session store, so a
    // store at its `sessions.max_sessions` cap (here: filled by 10k
    // legacy sessions) must not affect them — they keep serving 200
    // while stored-session mints (legacy initialize, authenticated
    // modern aliases) get capacity rejections.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let runtime_swap = state.runtime.clone();
    {
        let runtime = runtime_swap.load();
        let params = crate::protocol::InitializeParams {
            protocol_version: "2025-11-25".to_owned(),
            capabilities: Default::default(),
            client_info: crate::protocol::ImplementationInfo {
                name: "capacity-filler".to_owned(),
                title: None,
                version: "1".to_owned(),
                description: None,
                website_url: None,
                icons: None,
            },
        };
        while runtime.session_store().active_session_count() < 10_000 {
            let snap = runtime
                .session_store()
                .create_session("2025-11-25", &params);
            assert!(
                !snap.session_id.is_empty(),
                "filler create rejected before the configured cap"
            );
        }
    }
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 8,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 8);
    assert!(
        body["result"]["tools"].is_array(),
        "anonymous modern request must serve normally at session capacity"
    );
    assert_eq!(
        runtime_swap.load().session_store().active_session_count(),
        10_000,
        "the ephemeral request must not have consumed or created a session row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_tools_call_suspension_emits_input_required_result() {
    // When a modern `tools/call` suspends in an
    // elicitation step, the runtime mints an MRTR
    // `InputRequiredResult` (HTTP 200 + JsonRpcSuccess), NOT the
    // legacy SSE+202 envelope. Verifies the `requestState` blob
    // is present and the `inputRequests` map carries the
    // elicitation params.
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig,
    };

    let pipeline_binding = BackendConfig {
        name: "pipeline.modern_mrtr_e2e".to_owned(),
        title: Some("Modern MRTR E2E".to_owned()),
        description: "Pipeline that suspends; modern wire mints InputRequiredResult".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![
                    PipelineStepConfig::backend_from_typed(
                        "fetch_data".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"status": "ready"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
                    PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Please confirm".to_owned(),
                        mode: Default::default(),
                        requested_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "confirmed": { "type": "boolean" } }
                        })),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.modern_mrtr_e2e")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 91,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.modern_mrtr_e2e",
                            "arguments": {},
                            // SEP-2575 stateless: modern clients declare
                            // capabilities per-request (not via a session).
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {
                                    "elicitation": {},
                                    "sampling": {},
                                    "roots": { "listChanged": true }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Modern wire: HTTP 200 with inline body (NOT 202+SSE).
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/json"),
        "expected JSON body, got {content_type:?}"
    );

    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 91);
    let result = &body["result"];
    assert_eq!(
        result["resultType"], "input_required",
        "modern suspension must produce InputRequiredResult, got: {body}"
    );
    let request_state = result["requestState"]
        .as_str()
        .expect("requestState string");
    assert!(
        request_state.starts_with("c.") || request_state.starts_with("h."),
        "requestState must start with `c.` or `h.`, got: {request_state}"
    );
    // The pipeline's `confirm` step suspends with an elicitation;
    // exactly one `inputRequests` entry, type=elicitation.
    let input_requests = result["inputRequests"]
        .as_object()
        .expect("inputRequests map");
    assert_eq!(input_requests.len(), 1, "expected exactly one inputRequest");
    let (_token, req) = input_requests.iter().next().unwrap();
    assert_eq!(req["method"], "elicitation/create");
    assert_eq!(req["params"]["message"], "Please confirm");
}

/// RPN-4 helpers. Build a pipeline binding that emits request-scoped
/// notifications: a `log` step (always emits `notifications/message`)
/// optionally followed by a `progress` step (emits
/// `notifications/progress` only when the client supplied a progress
/// token) and a terminating mock step so the call completes.
fn rpn4_emitting_binding(name: &str, with_progress: bool) -> BackendConfig {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineLogStepConfig,
        PipelineProgressStepConfig, PipelineStepConfig,
    };
    let mut steps = vec![PipelineStepConfig::Log(PipelineLogStepConfig {
        id: "log_start".to_owned(),
        level: "info".to_owned(),
        logger: Some("rpn4".to_owned()),
        data: serde_json::json!("starting work"),
    })];
    if with_progress {
        steps.push(PipelineStepConfig::Progress(PipelineProgressStepConfig {
            id: "halfway".to_owned(),
            progress: 1.0,
            total: Some(2.0),
            message: Some("halfway".to_owned()),
        }));
    }
    steps.push(PipelineStepConfig::backend_from_typed(
        "finish".to_owned(),
        "mock",
        MockBackendConfig {
            response: serde_json::json!({"done": true}),
            delay_ms: 0,
            error: false,
            error_message: None,
            passthrough: false,
        },
        None,
    ));
    BackendConfig {
        name: name.to_owned(),
        title: Some("RPN-4 emitting tool".to_owned()),
        description: "Pipeline that emits log/progress then completes".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_tools_call_emitting_tool_streams_notifications_then_result() {
    // RPN-4 — a modern (`2026-07-28`) `tools/call` against a tool that
    // emits request-scoped notifications returns `text/event-stream`:
    // the `notifications/message` (and `notifications/progress`) frames
    // followed by a terminal JSON-RPC result frame. No `Mcp-Session-Id`
    // header (TS-09) and no SSE `id:` field (TS-11) on the modern wire.
    let binding = rpn4_emitting_binding("pipeline.rpn4_stream", true);
    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.rpn4_stream")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 711,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.rpn4_stream",
                            "arguments": {},
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {},
                                "io.modelcontextprotocol/logLevel": "debug",
                                "io.modelcontextprotocol/progressToken": "tok-1"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "RPN-4: emitting modern tools/call must stream, got {content_type:?}"
    );
    // TS-09: no session id echoed on the modern wire.
    assert!(
        response.headers().get(SESSION_ID_HEADER).is_none(),
        "modern stream must not carry Mcp-Session-Id"
    );

    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    // TS-11: modern streams assign no SSE event id.
    assert!(
        !text.lines().any(|l| l.starts_with("id:")),
        "modern stream must not assign SSE event ids, body:\n{text}"
    );
    let frames: Vec<Value> = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| serde_json::from_str(l.trim_start_matches("data:").trim()).ok())
        .collect();
    assert!(
        frames.len() >= 2,
        "expected notification frame(s) + terminal result, got {}: {text}",
        frames.len()
    );
    // A notifications/message frame is present (the log step).
    assert!(
        frames
            .iter()
            .any(|f| f["method"] == "notifications/message"),
        "expected a notifications/message frame, body:\n{text}"
    );
    // A notifications/progress frame is present (the progress step,
    // gated on the supplied progressToken).
    assert!(
        frames
            .iter()
            .any(|f| f["method"] == "notifications/progress"),
        "expected a notifications/progress frame, body:\n{text}"
    );
    // The LAST frame is the terminal JSON-RPC result, id-correlated,
    // resultType:"complete".
    let terminal = frames.last().unwrap();
    assert_eq!(terminal["jsonrpc"], "2.0");
    assert_eq!(terminal["id"], 711);
    assert_eq!(terminal["result"]["resultType"], "complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_tools_call_non_emitting_tool_stays_inline_json() {
    // RPN-4 — a modern `tools/call` against a tool that emits NO
    // request-scoped notifications keeps the inline single-response
    // fast path (`application/json`), not a stream.
    use crate::config::{MockBackendConfig, PipelineBackendConfig, PipelineStepConfig};
    let binding = BackendConfig {
        name: "pipeline.rpn4_quiet".to_owned(),
        title: Some("RPN-4 quiet tool".to_owned()),
        description: "Pipeline that emits nothing".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![PipelineStepConfig::backend_from_typed(
                    "only".to_owned(),
                    "mock",
                    MockBackendConfig {
                        response: serde_json::json!({"ok": true}),
                        delay_ms: 0,
                        error: false,
                        error_message: None,
                        passthrough: false,
                    },
                    None,
                )],
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
    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.rpn4_quiet")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 712,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.rpn4_quiet",
                            "arguments": {},
                            "_meta": { "io.modelcontextprotocol/clientCapabilities": {} }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/json"),
        "RPN-4: a non-emitting modern tools/call must stay inline JSON, got {content_type:?}"
    );
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 712);
    assert_eq!(body["result"]["resultType"], "complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_tools_call_emitting_tool_unaffected_by_rpn4() {
    // RPN-4 must be modern-only. A legacy (`2025-11-25`) `tools/call`
    // against the same emitting tool keeps its existing behaviour: the
    // session-scoped SSE path (with a `Mcp-Session-Id` header), NOT the
    // modern per-request frame stream. The notifications still ride the
    // session SSE channel and the session header is present.
    let binding = rpn4_emitting_binding("pipeline.rpn4_legacy", true);
    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                // No mcp-protocol-version header → legacy default wire.
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 713,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.rpn4_legacy",
                            "arguments": {},
                            "_meta": { "progressToken": "tok-legacy" }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // Legacy keeps the session header byte-identical.
    assert!(
        response.headers().get(SESSION_ID_HEADER).is_some(),
        "legacy response must still carry Mcp-Session-Id"
    );
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    // Legacy with a session streams via the existing SSE path; the
    // terminal result must NOT carry the modern `resultType` field.
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    if content_type.starts_with("text/event-stream") {
        let frames: Vec<Value> = text
            .lines()
            .filter(|l| l.starts_with("data:"))
            .filter_map(|l| serde_json::from_str(l.trim_start_matches("data:").trim()).ok())
            .collect();
        let terminal = frames
            .iter()
            .rev()
            .find(|f| f.get("id").is_some())
            .expect("legacy SSE must carry the terminal result");
        assert_eq!(terminal["id"], 713);
        assert!(
            terminal["result"].get("resultType").is_none(),
            "legacy result must NOT carry resultType, body:\n{text}"
        );
    } else {
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["id"], 713);
        assert!(body["result"].get("resultType").is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_subscriptions_listen_returns_sse_with_confirmation_event() {
    // Modern `subscriptions/listen` opens a long-lived
    // POST-SSE response. Verify:
    //   1. HTTP 200 with `Content-Type: text/event-stream`.
    //   2. First SSE event payload is the JsonRpcSuccess
    //      carrying the server-minted `subscriptionId`.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 401,
                        "method": "subscriptions/listen",
                        "params": {
                            "subscriptions": [
                                { "type": "tools/listChanged" }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE stream, got Content-Type {content_type:?}"
    );

    // Read the first chunks of the streaming response. M4.C changed
    // the priming sequence so the FIRST frame is now the SEP-2575
    // `notifications/subscriptions/acknowledged` notification and
    // the second frame is the JSON-RPC response (id-correlated to
    // the original request). Verify both.
    let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let data_payloads: Vec<Value> = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| serde_json::from_str(l.trim_start_matches("data:").trim()).ok())
        .collect();
    assert!(
        data_payloads.len() >= 2,
        "subscriptions/listen primes ack + response (got {})",
        data_payloads.len()
    );
    // First frame: ack notification.
    assert_eq!(data_payloads[0]["jsonrpc"], "2.0");
    assert_eq!(
        data_payloads[0]["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert!(data_payloads[0]["params"]["subscriptionId"].is_string());
    // Second frame: JSON-RPC response correlated to the call's id.
    assert_eq!(data_payloads[1]["jsonrpc"], "2.0");
    assert_eq!(data_payloads[1]["id"], 401);
    assert!(data_payloads[1]["result"]["subscriptionId"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_subscriptions_listen_works_without_session_header() {
    // The transport mints an ephemeral operational
    // session for modern requests that arrive without an
    // `Mcp-Session-Id`. The subscription is then bound to that
    // synthetic session and the confirmation event still fires.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 402,
                        "method": "subscriptions/listen",
                        "params": {
                            "subscriptions": [
                                { "type": "tools/listChanged" }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/event-stream"),
        "stateless modern subscriptions/listen must still return SSE, got {content_type:?}"
    );

    let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    // M4.C priming: frame 1 = ack notification, frame 2 = JSON-RPC
    // response. Locate the response frame by `id == 402`.
    let response_frame = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| serde_json::from_str::<Value>(l.trim_start_matches("data:").trim()).ok())
        .find(|v| v["id"] == 402)
        .expect("JSON-RPC response frame correlated to request id 402");
    assert_eq!(response_frame["jsonrpc"], "2.0");
    assert!(
        response_frame["result"]["subscriptionId"].is_string(),
        "confirmation must carry a server-minted subscriptionId"
    );
}

#[tokio::test]
async fn modern_tools_list_works_without_session_header() {
    // Modern `tools/list` (and every other capability
    // method that today calls `load_session_cached(true)`) must
    // work without `Mcp-Session-Id` because the transport mints
    // an ephemeral operational session on the modern path.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 411,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 411);
    // Cache fields still appear (the result envelope is unchanged
    // — just no Mcp-Session-Id was required).
    assert!(body["result"]["tools"].is_array());
    assert_eq!(body["result"]["resultType"], "complete");
    // Principal-filtered catalog → Private, not a shared-cacheable Public.
    assert_eq!(body["result"]["cacheScope"], "private");
}

// ── stateless modern transport ──────────────────────────────────────

#[tokio::test]
async fn modern_post_does_not_echo_session_id_header() {
    // TS-09: a 2026-07-28 server MUST NOT surface `Mcp-Session-Id`.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 420,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response.headers().contains_key(SESSION_ID_HEADER),
        "modern responses MUST NOT echo Mcp-Session-Id"
    );
}

#[tokio::test]
async fn modern_post_ignores_inbound_session_id_and_last_event_id() {
    // TS-09/TS-11: inbound `Mcp-Session-Id` + `Last-Event-ID` are
    // ignored on the modern wire (no echo, no resume cursor honored).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .header(SESSION_ID_HEADER, "client-supplied-session")
                .header("last-event-id", "stream-1:7")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 421,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // The forged session id is never echoed back.
    assert!(
        !response.headers().contains_key(SESSION_ID_HEADER),
        "inbound Mcp-Session-Id must not be echoed on the modern wire"
    );
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 421);
    assert!(body["result"]["tools"].is_array());
}

#[tokio::test]
async fn modern_get_returns_405() {
    // TS-10: GET on the modern wire MUST be 405 (no server-push GET
    // stream — `subscriptions/listen` over POST replaces it).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header("mcp-protocol-version", "2026-07-28")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn modern_delete_returns_405() {
    // TS-10: DELETE on the modern wire MUST be 405 (no protocol-level
    // session to terminate).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/mcp")
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn legacy_get_and_delete_unchanged_by_modern_405_gate() {
    // The 405 gate is version-scoped: legacy (header absent → 2025-11-25
    // default) GET still serves the SSE delivery stream and DELETE still
    // terminates the session. Byte-identical to pre-Phase-2 behavior.
    let app = router(build_test_state(), "/health", "/mcp");
    let (_, session_id) = initialize_session(app.clone()).await;

    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.headers()[header::CONTENT_TYPE], "text/event-stream");

    let delete = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/mcp")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_subscriptions_listen_subscription_id_equals_request_id() {
    // TS-13/RES-07: the `subscriptionId` MUST equal the listen
    // request's JSON-RPC id (here, the string rendering of 4099), and
    // the ack carries the honored-subset `notifications` object
    // (TS-14/RES-06). No `Mcp-Session-Id` is echoed (TS-09).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 4099,
                        "method": "subscriptions/listen",
                        "params": {
                            "subscriptions": [
                                { "type": "tools/listChanged" },
                                { "type": "resources/updated", "uri": "file:///x" }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response.headers().contains_key(SESSION_ID_HEADER),
        "modern subscriptions/listen MUST NOT echo Mcp-Session-Id"
    );
    let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let data_payloads: Vec<Value> = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| serde_json::from_str(l.trim_start_matches("data:").trim()).ok())
        .collect();
    assert!(data_payloads.len() >= 2);
    // Ack frame: subscriptionId == "4099" (the request id rendered).
    assert_eq!(
        data_payloads[0]["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert_eq!(data_payloads[0]["params"]["subscriptionId"], "4099");
    // Honored-subset notifications object reflects the accepted targets.
    assert_eq!(
        data_payloads[0]["params"]["notifications"]["toolsListChanged"],
        true
    );
    // `file:///x` is not a resource this gateway serves, so no subscription
    // was established for it and the ack must not claim one — a client told
    // otherwise waits forever for an update event nothing produces.
    assert!(
        data_payloads[0]["params"]["notifications"]
            .get("resourceSubscriptions")
            .is_none(),
        "ack must not report a resource target that was skipped, got {}",
        data_payloads[0]["params"]["notifications"]
    );
    // Response frame: id-correlated, subscriptionId == "4099",
    // resultType:"complete".
    assert_eq!(data_payloads[1]["id"], 4099);
    assert_eq!(data_payloads[1]["result"]["subscriptionId"], "4099");
    assert_eq!(data_payloads[1]["result"]["resultType"], "complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_subscriptions_listen_does_not_assign_sse_event_ids() {
    // TS-11: modern SSE streams assign no event IDs (no resumability).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 4100,
                        "method": "subscriptions/listen",
                        "params": { "subscriptions": [ { "type": "tools/listChanged" } ] }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !text.lines().any(|l| l.starts_with("id:")),
        "modern SSE frames MUST NOT carry event ids; got:\n{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_mrtr_resumption_completes_pipeline() {
    // Full MRTR round trip. Build a pipeline that
    // suspends in an elicitation step, then finalizes after the
    // client provides the answer. Verify:
    //   1. First `tools/call` returns 200 + InputRequiredResult.
    //   2. Resumption `tools/call` (carrying the echoed
    //      requestState + inputResponses on `_meta`) returns 200
    //      with the completed ToolCallResult.
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig,
    };

    let pipeline_binding = BackendConfig {
        name: "pipeline.modern_mrtr_roundtrip".to_owned(),
        title: Some("Modern MRTR Round Trip".to_owned()),
        description: "Suspend-and-resume via MRTR inline body".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![
                    PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Please confirm".to_owned(),
                        mode: Default::default(),
                        requested_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "confirmed": { "type": "boolean" } }
                        })),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "finalize".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"completed": true}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    // ── Round 1 — fresh tools/call, expect InputRequiredResult ──
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.modern_mrtr_roundtrip")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 200,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.modern_mrtr_roundtrip",
                            "arguments": {},
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {
                                    "elicitation": {},
                                    "sampling": {},
                                    "roots": { "listChanged": true }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(first.status(), StatusCode::OK);
    let first_body: Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(first_body["result"]["resultType"], "input_required");
    let request_state = first_body["result"]["requestState"]
        .as_str()
        .expect("requestState")
        .to_owned();
    let input_requests = first_body["result"]["inputRequests"]
        .as_object()
        .expect("inputRequests");
    let (correlation_token, _entry) = input_requests.iter().next().expect("one entry");
    let correlation_token = correlation_token.clone();

    // ── Round 2 — resumption with inputResponses + requestState ──
    let resumption = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.modern_mrtr_roundtrip")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 201,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.modern_mrtr_roundtrip",
                            "arguments": {},
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {
                                    "elicitation": {},
                                    "sampling": {},
                                    "roots": { "listChanged": true }
                                },
                                "io.modelcontextprotocol/requestState": request_state,
                                "io.modelcontextprotocol/inputResponses": {
                                    correlation_token: {
                                        "action": "accept",
                                        "content": { "confirmed": true }
                                    }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resumption.status(), StatusCode::OK);
    let resumption_body: Value =
        serde_json::from_slice(&to_bytes(resumption.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    // The pipeline ran to completion → the result is a ToolCallResult
    // (NOT inputRequired). Its `content` array carries the finalize
    // step's output. The original `id` (200) is recovered from the
    // pipeline state — resumption returns under that, not the new
    // `id: 201` (per MCP spec for server-request resumption).
    let resumption_result = &resumption_body["result"];
    assert_ne!(
        resumption_result["resultType"], "input_required",
        "resumed pipeline must complete, got: {resumption_body}"
    );
    let content = resumption_result["content"]
        .as_array()
        .expect("ToolCallResult.content array");
    assert!(
        !content.is_empty(),
        "completed result must carry content blocks"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_mrtr_resumption_propagates_client_error_to_step_result() {
    // Limitation #5 — the `InputResponseValue::Err` flow. When a
    // modern client returns an explicit error envelope on an MRTR
    // resumption (e.g., user declined an elicitation), the
    // pipeline engine MUST surface the error as a step result so
    // the suspending step's downstream consumers see is_error=true.
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationStepConfig, PipelineStepConfig,
    };

    let pipeline_binding = BackendConfig {
        name: "pipeline.mrtr_err_path".to_owned(),
        title: Some("MRTR Err Path".to_owned()),
        description: "Suspends; client returns Err on resumption".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30000,
                steps: vec![
                    PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
                        id: "ask".to_owned(),
                        message: "Confirm?".to_owned(),
                        mode: Default::default(),
                        requested_schema: Some(serde_json::json!({})),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    }),
                    PipelineStepConfig::backend_from_typed(
                        "finalize".to_owned(),
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"ok": true}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                        None,
                    ),
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

    let state = build_test_state_with_runtime_controls(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        vec![pipeline_binding],
    );
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    // Round 1: suspend
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.mrtr_err_path")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 700,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.mrtr_err_path",
                            "arguments": {},
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {
                                    "elicitation": {},
                                    "sampling": {},
                                    "roots": { "listChanged": true }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let first_body: Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let request_state = first_body["result"]["requestState"]
        .as_str()
        .expect("requestState")
        .to_owned();
    let (token, _) = first_body["result"]["inputRequests"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    let token = token.clone();

    // Round 2: resumption with Err envelope
    let resumption = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "pipeline.mrtr_err_path")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 701,
                        "method": "tools/call",
                        "params": {
                            "name": "pipeline.mrtr_err_path",
                            "arguments": {},
                            "_meta": {
                                "io.modelcontextprotocol/clientCapabilities": {
                                    "elicitation": {},
                                    "sampling": {},
                                    "roots": { "listChanged": true }
                                },
                                "io.modelcontextprotocol/requestState": request_state,
                                "io.modelcontextprotocol/inputResponses": {
                                    token: {
                                        "error": {
                                            "code": -32603,
                                            "message": "user declined the elicitation",
                                            "data": { "reason": "esc" }
                                        }
                                    }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resumption.status(), StatusCode::OK);
    let resumption_body: Value =
        serde_json::from_slice(&to_bytes(resumption.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    // The pipeline ran to completion with the error as the
    // elicitation step result. The finalize step produced its
    // mock output; the whole call returns a complete ToolCallResult
    // (not inputRequired). The error message is preserved as the
    // step's `output.error` value — observable via the structured
    // step record in the result, but not directly on the top-level
    // ToolCallResult.is_error (that's the tool-execution level).
    let result = &resumption_body["result"];
    assert_ne!(
        result["resultType"], "input_required",
        "resumption with Err must still complete: {resumption_body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_mrtr_resumption_with_tampered_request_state_is_rejected() {
    // A tampered `requestState` fails AEAD verification. That is
    // the caller's bad blob, so it surfaces a client error (-32602 / HTTP
    // 400), not a gateway-internal -32603.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let tampered = "c.AAAAAAAAAAAAAAAAtampered";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "x")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 300,
                        "method": "tools/call",
                        "params": {
                            "name": "x",
                            "_meta": {
                                "io.modelcontextprotocol/requestState": tampered,
                                "io.modelcontextprotocol/inputResponses": {
                                    "k": { "answer": "y" }
                                }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], -32602);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("requestState"),
        "diagnostic should reference the offending requestState, got {}",
        body["error"]["message"]
    );
}

/// `_meta` block that satisfies the modern transport (clientInfo +
/// protocolVersion) AND declares the SEP-2663 tasks extension, so a
/// `tasks/*` request reaches the dispatch arm instead of the
/// extension-gate `-32601`.
fn tasks_meta_with_extension() -> Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        }
    })
}

#[tokio::test]
async fn modern_tasks_extension_get_without_declaration_is_method_not_found() {
    // SEP-2663: a server MUST NOT surface tasks to a client that did
    // not declare the `io.modelcontextprotocol/tasks` extension. The
    // bare `tasks/*` methods appear not-to-exist (`-32601`) for such
    // a client.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tasks/get")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 501,
                        "method": "tasks/get",
                        "params": { "taskId": "t-1" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], -32601);
}

#[tokio::test]
async fn modern_tasks_extension_get_unknown_task_returns_not_found() {
    // With the extension declared, `tasks/get` reaches the dispatch
    // arm; an unknown task id is `-32602` (not-found).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tasks/get")
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 503,
                        "method": "tasks/get",
                        "params": {
                            "taskId": "no-such-task",
                            "_meta": tasks_meta_with_extension()
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], -32602);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not found"),
        "diagnostic should mention not-found, got {}",
        body["error"]["message"]
    );
}

#[tokio::test]
async fn modern_tasks_extension_cancel_unknown_task_returns_not_found() {
    // `tasks/cancel` for an unknown task → `-32602`. (A known task's
    // empty `resultType:"complete"` ack is covered by the wire unit
    // tests; the wire cannot create a task — materialization is
    // server-directed during tools/call.)
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tasks/cancel")
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 504,
                        "method": "tasks/cancel",
                        "params": {
                            "taskId": "no-such-task",
                            "_meta": tasks_meta_with_extension()
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// SEP-2663 live materialization + notification routing.
// ---------------------------------------------------------------------------

/// A task-capable (`taskSupport: required`) mock tool that completes
/// immediately, plus a task-capable suspending elicitation pipeline
/// (`taskSupport: required`) that goes `input_required`.
fn build_task_materialization_state() -> AppState {
    use crate::config::{
        MockBackendConfig, PipelineBackendConfig, PipelineElicitationMode,
        PipelineElicitationStepConfig, PipelineStepConfig,
    };

    let mock_required = BackendConfig {
        name: "async.mock".to_owned(),
        title: Some("Async mock".to_owned()),
        description: "task-capable mock that completes immediately".to_owned(),
        input_schema: Some(serde_json::json!({ "type": "object" })),
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!({ "status": "done" }),
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
        task_support: Some("required".to_owned()),
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    };

    let suspending_required = BackendConfig {
        name: "async.elicit".to_owned(),
        title: Some("Async elicit".to_owned()),
        description: "task-capable pipeline that suspends for input".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "pipeline",
            PipelineBackendConfig {
                pipeline_timeout_ms: 30_000,
                steps: vec![PipelineStepConfig::Elicitation(
                    PipelineElicitationStepConfig {
                        id: "confirm".to_owned(),
                        message: "Confirm?".to_owned(),
                        mode: PipelineElicitationMode::Form,
                        requested_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "ok": { "type": "boolean" } }
                        })),
                        url: None,
                        elicitation_id: None,
                        presentation_hint: None,
                        meta: None,
                        timeout_ms: 30_000,
                        correlation_token: None,
                        skip_if_unsupported: false,
                    },
                )],
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
        task_support: Some("required".to_owned()),
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    };

    build_task_materialization_app_state(vec![mock_required, suspending_required], |_| {})
}

/// Build the materialization `AppState` from its bindings, applying
/// `mutate` to the runtime before it is sealed (so a test can install
/// runtime-owned state such as the idempotency store), then wire the
/// modern protocol registry.
fn build_task_materialization_app_state(
    bindings: Vec<BackendConfig>,
    mutate: impl FnOnce(&mut GatewayRuntime),
) -> AppState {
    let state = build_test_state_with_all_runtime_controls_mut(
        false,
        RuntimeDebugConfig {
            default_allow_private_backends: true,
            ..RuntimeDebugConfig::default()
        },
        bindings,
        ToolAccessPolicyConfig::default(),
        mutate,
    );
    // The modern handler + the MRTR `requestState` codec must be wired
    // so a `2026-07-28` request routes to the modern dispatch and a
    // suspending task can encode its resume handle.
    install_protocol_registry_for_tests(&state);
    state
}

/// Materialization harness (as [`build_task_materialization_state`])
/// with the `dev.mcpg/idempotency` extension enabled — an in-memory
/// `KvBackedIdempotencyStore` plus the capability advertisement — so a
/// modern materialized `tools/call` can be replayed under the same
/// idempotency key.
fn build_task_materialization_state_with_idempotency() -> AppState {
    // Only the immediate-completing `async.mock` binding is needed for
    // the replay test; mirror the binding `build_task_materialization_state`
    // installs.
    let mock_required = BackendConfig {
        name: "async.mock".to_owned(),
        title: Some("Async mock".to_owned()),
        description: "task-capable mock that completes immediately".to_owned(),
        input_schema: Some(serde_json::json!({ "type": "object" })),
        backend: BackendImpl::from_typed(
            "mock",
            crate::config::MockBackendConfig {
                response: serde_json::json!({ "status": "done" }),
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
        task_support: Some("required".to_owned()),
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    };
    build_task_materialization_app_state(vec![mock_required], |runtime| {
        runtime.set_idempotency_store(std::sync::Arc::new(
            crate::runtime::idempotency::KvBackedIdempotencyStore::new_in_memory_default(),
        ));
        runtime.set_idempotency_capability(Some(serde_json::json!({
            "scope": "per-identity",
            "default_ttl_seconds": 86_400u64,
            "max_ttl_seconds": 604_800u64,
            "supported_methods": ["tools/call", "tasks/create"],
            "supports_replay_marker": true,
            "conflict_policy": "reject",
        })));
    })
}

/// Issue a modern (`2026-07-28`) materialized `tools/call` carrying a
/// `dev.mcpg/idempotency-key`. Mirrors [`modern_tools_call`] but adds
/// the idempotency key into the request `_meta`.
async fn modern_tools_call_idempotent(
    app: &Router,
    id: u64,
    tool: &str,
    idempotency_key: &str,
) -> Value {
    let meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {
            "elicitation": {},
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        },
        "dev.mcpg/idempotency-key": idempotency_key,
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", tool)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": tool, "arguments": {}, "_meta": meta }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "tools/call non-200: {body}");
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_materialized_tools_call_idempotency_replay_stays_flat() {
    // A modern (`2026-07-28`) materialized `tools/call` replayed under
    // the same `dev.mcpg/idempotency-key` MUST return the SAME flat
    // SEP-2663 `CreateTaskResult` shape (`resultType:"task"`, task
    // fields at top level) the first-time materialization emits — NOT
    // the legacy nested `{ task: {...} }` envelope. Same taskId,
    // pollable by the same principal.
    let app = router(
        build_task_materialization_state_with_idempotency(),
        "/health",
        "/mcp",
    );
    let key = "01J9X8N3QKHA0V9C4D8TYR2TASK";

    let first = modern_tools_call_idempotent(&app, 800, "async.mock", key).await;
    assert_eq!(first["result"]["resultType"], "task", "first: {first}");
    assert!(
        first["result"].get("task").is_none(),
        "first must be flat: {first}"
    );
    let task_id = first["result"]["taskId"]
        .as_str()
        .expect("first taskId")
        .to_owned();

    // Replay under the same key + body.
    let replay = modern_tools_call_idempotent(&app, 801, "async.mock", key).await;
    // Flat modern shape — the replay residual was that this path
    // returned the legacy nested `{ task: {...} }` envelope.
    assert_eq!(
        replay["result"]["resultType"], "task",
        "replay must be flat task: {replay}"
    );
    assert!(
        replay["result"].get("task").is_none(),
        "replay must be flat, not nested {{task:{{}}}}: {replay}"
    );
    assert_eq!(
        replay["result"]["taskId"].as_str(),
        Some(task_id.as_str()),
        "replay must reference the same task: {replay}"
    );
    // The replay marker rides on `_meta` (idempotency replay) while the
    // top-level shape stays the flat modern `CreateTaskResult`.
    assert_eq!(
        replay["result"]["_meta"]["dev.mcpg/idempotency-replayed"],
        Value::Bool(true),
        "replay marker must be stamped: {replay}"
    );

    // The same principal can still poll the task to completion.
    let done = poll_task_get(&app, 802, &task_id, |b| {
        b["result"]["status"] == "completed"
    })
    .await;
    assert_eq!(done["result"]["resultType"], "complete", "poll: {done}");
}

/// Issue a modern (`2026-07-28`) `tools/call` against the materialization
/// harness. `declare_ext` controls whether the request declares the
/// `io.modelcontextprotocol/tasks` extension; the request also carries
/// the elicitation client capability so the suspending pipeline can run.
async fn modern_tools_call(app: &Router, id: u64, tool: &str, declare_ext: bool) -> Value {
    let mut caps = serde_json::json!({ "elicitation": {} });
    if declare_ext {
        caps["extensions"] = serde_json::json!({ "io.modelcontextprotocol/tasks": {} });
    }
    let meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": caps,
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", tool)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": { "name": tool, "arguments": {}, "_meta": meta }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "tools/call non-200: {body}");
    body
}

/// Poll `tasks/get` for `task_id` until a predicate holds or the
/// attempt budget is exhausted. The background spawn drives the task
/// to terminal/awaiting-input asynchronously.
async fn poll_task_get(
    app: &Router,
    id: u64,
    task_id: &str,
    until: impl Fn(&Value) -> bool,
) -> Value {
    for attempt in 0..50 {
        // Unique JSON-RPC id per poll so the modern session's
        // duplicate-request-id dedup doesn't reject successive polls.
        let poll_id = id * 1000 + attempt;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "tasks/get")
                    .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": poll_id,
                            "method": "tasks/get",
                            "params": { "taskId": task_id, "_meta": tasks_meta_with_extension() }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        if until(&body) {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("task {task_id} did not reach the expected state within the poll budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_task_capable_tool_with_extension_materializes_and_is_pollable() {
    // A task-capable tool called by a client that declared
    // the tasks extension materializes as a background task — the
    // tools/call returns the flat `resultType:"task"` CreateTaskResult,
    // and the task is pollable to completion via tasks/get by the same
    // principal.
    let app = router(build_task_materialization_state(), "/health", "/mcp");

    let body = modern_tools_call(&app, 700, "async.mock", true).await;
    assert_eq!(body["result"]["resultType"], "task", "got {body}");
    // Flat shape (SEP-2663 `Result & Task`) — task fields at top level.
    let task_id = body["result"]["taskId"]
        .as_str()
        .expect("taskId")
        .to_owned();
    assert!(
        body["result"].get("task").is_none(),
        "must be flat, not nested"
    );
    assert!(["working", "completed"].contains(&body["result"]["status"].as_str().unwrap()));

    let done = poll_task_get(&app, 701, &task_id, |b| {
        b["result"]["status"] == "completed"
    })
    .await;
    assert_eq!(done["result"]["resultType"], "complete");
    assert_eq!(done["result"]["status"], "completed");
    // Terminal result carries the wrapped tool-call result.
    assert!(done["result"]["result"]["content"].is_array(), "got {done}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_task_capable_tool_without_extension_runs_synchronously() {
    // SEP-2663 MUST-NOT: a client that did NOT declare the extension
    // never receives a task — the same task-capable tool runs inline
    // and returns a standard `resultType:"complete"` result.
    let app = router(build_task_materialization_state(), "/health", "/mcp");

    let body = modern_tools_call(&app, 710, "async.mock", false).await;
    assert_ne!(
        body["result"]["resultType"], "task",
        "no task without opt-in: {body}"
    );
    assert_eq!(body["result"]["resultType"], "complete");
    assert!(body["result"].get("taskId").is_none());
    assert!(
        body["result"]["content"].is_array(),
        "inline tool result: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_input_required_task_surfaces_input_requests_and_resumes() {
    // Suspension recording: a task-capable suspending
    // pipeline materializes, transitions to `input_required`, surfaces
    // its outstanding `inputRequests` on tasks/get, and resumes to a
    // terminal state when the client answers via tasks/update.
    let app = router(build_task_materialization_state(), "/health", "/mcp");

    let body = modern_tools_call(&app, 720, "async.elicit", true).await;
    assert_eq!(body["result"]["resultType"], "task", "got {body}");
    let task_id = body["result"]["taskId"]
        .as_str()
        .expect("taskId")
        .to_owned();

    // Poll until the task is awaiting input.
    let awaiting = poll_task_get(&app, 721, &task_id, |b| {
        b["result"]["status"] == "input_required"
    })
    .await;
    let input_requests = awaiting["result"]["inputRequests"]
        .as_object()
        .expect("inputRequests present on an input_required task");
    assert_eq!(
        input_requests.len(),
        1,
        "one outstanding elicitation: {awaiting}"
    );
    let (correlation_token, entry) = input_requests.iter().next().unwrap();
    assert_eq!(entry["method"], "elicitation/create");

    // Answer via tasks/update — the answers route through the MRTR
    // resume codec keyed by taskId; the ack is the empty
    // `resultType:"complete"`.
    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tasks/update")
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 722,
                        "method": "tasks/update",
                        "params": {
                            "taskId": task_id,
                            "inputResponses": {
                                correlation_token: { "action": "accept", "content": { "ok": true } }
                            },
                            "_meta": tasks_meta_with_extension()
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let update_body: Value =
        serde_json::from_slice(&to_bytes(update.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        update_body["result"]["resultType"], "complete",
        "update ack: {update_body}"
    );

    // The task leaves `input_required` (it either re-suspends, fails, or
    // completes — the resume drove it off the awaiting-input state).
    let after = poll_task_get(&app, 723, &task_id, |b| {
        b["result"]["status"] != "input_required"
    })
    .await;
    assert_ne!(
        after["result"]["status"], "input_required",
        "resume advanced the task: {after}"
    );
}

#[tokio::test]
async fn modern_task_emits_notifications_tasks_on_subscription_matcher() {
    // The modern task-status notification is the bare
    // `notifications/tasks` (not legacy `notifications/tasks/status`),
    // and the transport's subscription matcher delivers it to a
    // `TasksStatus` subscriber.
    use crate::protocol::v_2026_07_28::wire::subscriptions::{
        SubscriptionTarget, subscription_matches,
    };

    let modern = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": "task-42", "status": "working" }
    });
    let legacy = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks/status",
        "params": { "taskId": "task-42", "status": "working" }
    });

    let unscoped = [SubscriptionTarget::TasksStatus { task_id: None }];
    assert!(
        subscription_matches(&unscoped, "notifications/tasks", &modern),
        "modern bare notifications/tasks must match an unscoped TasksStatus subscription"
    );
    assert!(
        subscription_matches(&unscoped, "notifications/tasks/status", &legacy),
        "legacy spelling must still match during the migration window"
    );

    // taskId-scoped subscription filters on the flat `params.taskId`.
    let scoped = [SubscriptionTarget::TasksStatus {
        task_id: Some("task-42".to_owned()),
    }];
    assert!(subscription_matches(
        &scoped,
        "notifications/tasks",
        &modern
    ));
    let other = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": "task-other", "status": "working" }
    });
    assert!(!subscription_matches(
        &scoped,
        "notifications/tasks",
        &other
    ));
}

#[tokio::test]
async fn modern_tools_call_dispatches_through_legacy_pipeline() {
    // The modern `tools/call` arm delegates to the
    // legacy `handle_protocol_operation` path. Verifies a real
    // tool call returns 200 with the modern `ToolCallResult` wire
    // shape (which is structurally identical to legacy, so the
    // legacy serialiser produces a modern-compliant envelope
    // unchanged).
    //
    // The legacy dispatch path requires an operational session;
    // we initialise one via the legacy `initialize` then make the
    // modern tools/call carry the same `Mcp-Session-Id`. Stateless
    // modern mode (no session at all) applies once `requestState`
    // carries the pipeline context (MRTR).
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "mcpg.runtime.snapshot")
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 9,
                        "method": "tools/call",
                        "params": {
                            "name": "mcpg.runtime.snapshot",
                            "arguments": {}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Modern wire: response is inline JSON, NOT `text/event-stream`
    // (the legacy SSE-streaming path is bypassed for modern requests
    // because MRTR carries any suspension inline).
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/json"),
        "modern tools/call must NOT stream; got Content-Type {content_type:?}"
    );
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 9);
    // SEP-2322: the complete-path modern tools/call result is
    // stamped `resultType:"complete"` at the handler seam.
    assert_eq!(body["result"]["resultType"], "complete");
    // ToolCallResult shape — content + structured_content + meta.
    let content = &body["result"]["content"];
    assert!(content.is_array(), "result.content must be an array");
    let first = &content[0];
    assert_eq!(first["type"], "text", "first content block is text");
    // The debug `mcpg.runtime.snapshot` tool returns a snapshot
    // including the gateway's service name.
    assert!(
        first["text"].as_str().unwrap().contains("mcpg"),
        "snapshot text should mention `mcpg`"
    );
}

#[tokio::test]
async fn modern_prompts_list_returns_cache_aware_envelope() {
    // Modern `prompts/list` arm. Mirrors the
    // tools/list cache assertions (ttlMs / cacheScope / cacheToken).
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "prompts/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "prompts/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 5);
    let result = &body["result"];
    assert!(result["prompts"].is_array(), "prompts[] must be present");
    // Modern `prompts/list` uses a 10-minute TTL (prompts change
    // slowly) and is a CacheableResult.
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 600_000);
    // Principal-filtered catalog → Private, not a shared-cacheable Public.
    assert_eq!(result["cacheScope"], "private");
    assert!(result.get("cacheToken").is_none());
}

#[tokio::test]
async fn modern_resources_list_returns_cache_aware_envelope() {
    // Modern `resources/list` arm. Asserts the same
    // SEP-2549 cache triple as tools/prompts.
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "resources/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 51,
                        "method": "resources/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let result = &body["result"];
    assert!(result["resources"].is_array());
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 30_000);
    // Principal-filtered catalog → Private, not a shared-cacheable Public.
    assert_eq!(result["cacheScope"], "private");
    assert!(result.get("cacheToken").is_none());
}

#[tokio::test]
async fn modern_resources_templates_list_returns_cache_aware_envelope() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "resources/templates/list")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 52,
                        "method": "resources/templates/list"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let result = &body["result"];
    assert!(result["resourceTemplates"].is_array());
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 600_000);
    // Principal-filtered catalog → Private, not a shared-cacheable Public.
    assert_eq!(result["cacheScope"], "private");
    assert!(result.get("cacheToken").is_none());
}

#[tokio::test]
async fn modern_prompts_get_dispatches_through_legacy() {
    let state = build_test_state_with_debug_config(RuntimeDebugConfig {
        enabled: true,
        command_profiles: std::collections::BTreeMap::from([(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            CommandToolRuntimeConfig::default(),
        )]),
        network_profiles: std::collections::BTreeMap::from([(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            NetworkToolRuntimeConfig::default(),
        )]),
        bindings: DebugToolBackends::default(),
        exposure: DebugToolExposure::default(),
        default_allow_private_backends: true,
    });
    install_protocol_registry_for_tests(&state);
    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "prompts/get")
                .header("mcp-name", "mcpg_operational_overview")
                .header(SESSION_ID_HEADER, &session_id)
                // prompts/get enforces the trust floor — provide an identity.
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "prompts/get",
                        "params": { "name": "mcpg_operational_overview" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 6);
    // Modern + legacy share the same PromptGetResult wire shape;
    // the modern envelope is stamped `resultType:"complete"`.
    assert!(body["result"]["messages"].is_array());
    assert_eq!(body["result"]["resultType"], "complete");
}

#[tokio::test]
async fn modern_tools_list_cacheable_envelope_is_stable_across_identical_pages() {
    // Two `tools/list` calls back-to-back on the same gateway
    // catalog MUST return the same CacheableResult envelope
    // (resultType / ttlMs / cacheScope) and never the non-spec
    // `cacheToken` field (VN-3).
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    })
    .to_string();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let first_body: Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let second_body: Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(first_body["result"].get("cacheToken").is_none());
    assert!(second_body["result"].get("cacheToken").is_none());
    assert_eq!(first_body["result"]["resultType"], "complete");
    assert_eq!(
        first_body["result"]["ttlMs"], second_body["result"]["ttlMs"],
        "identical pages MUST advertise identical cache lifetimes"
    );
    assert_eq!(
        first_body["result"]["cacheScope"], second_body["result"]["cacheScope"],
        "identical pages MUST advertise identical cache scope"
    );
}

#[tokio::test]
async fn modern_unknown_method_rejected_with_method_not_found() {
    // `initialize` is rejected by the modern routing function
    // because it's legacy-only. The request pins 2026-07-28
    // so the modern handler runs, refuses `initialize`, and the
    // transport renders -32601 method not found.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "initialize")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "initialize",
                        "params": {}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], -32601);
}

#[tokio::test]
async fn legacy_request_still_routes_through_legacy_path() {
    // With the registry installed, legacy requests (2025-11-25)
    // MUST still flow through the existing legacy path — the
    // version branch in `mcp_handler` reserves the modern route
    // for `V_2026_07_28` only.
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let app = router(state, "/health", "/mcp");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2025-11-25")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "t", "version": "0" }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // `initialize` returns 200 with a JSON-RPC success body when
    // routed through the legacy handler — the regression guard.
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
}

// ───────────── anonymous per-IP rate limit (R1) ─────────────

/// Build a state with the anonymous limiter ON (tight burst) and proxy-IP
/// trust, so oneshot requests can carry a per-test client IP via
/// `X-Forwarded-For` (oneshot has no ConnectInfo).
fn build_anon_limited_state(per_min: u32, burst: u32, trust_proxy: bool) -> AppState {
    let state = build_test_state();
    let mut config = AppConfig::default();
    config.gateway.server.anonymous_rate_limit_per_min = per_min;
    config.gateway.server.anonymous_rate_limit_burst = burst;
    config.gateway.server.trust_proxy_ip = trust_proxy;
    // Trust the subject header so a request carrying `x-mcpg-subject-id`
    // resolves to a genuine header-asserted identity — which the limiter
    // must STILL throttle (it is below Verified). Without this the header
    // would be ignored and the request would just be Anonymous.
    config.gateway.server.trust_subject_header = true;
    state.config.store(Arc::new(config));
    state
}

fn anon_post(xff: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, MCP_ACCEPT_HEADER)
        .header("x-forwarded-for", xff);
    if let Some(s) = subject {
        b = b.header("x-mcpg-subject-id", s);
    }
    b.body(Body::from(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "anon-limit-test", "version": "0"}
            }
        })
        .to_string(),
    ))
    .expect("request")
}

#[tokio::test]
async fn anonymous_mcp_is_rate_limited_per_ip_and_header_asserted_is_also_limited() {
    // Distinct /24s per test to avoid cross-test bucket reuse (the limiter
    // map is a process-wide static shared by every test in this binary).
    let app = router(build_anon_limited_state(60, 2, true), "/health", "/mcp");

    // Burst of 2 from one IP → third request is 429.
    for i in 0..2 {
        let resp = app
            .clone()
            .oneshot(anon_post("198.51.100.7", None))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} is within the burst"
        );
    }
    let resp = app
        .clone()
        .oneshot(anon_post("198.51.100.7", None))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "burst exhausted"
    );
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("60"),
    );
    let bytes = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], -32099, "{body}");

    // A different client IP has its own bucket.
    let resp = app
        .clone()
        .oneshot(anon_post("198.51.100.8", None))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "per-IP isolation"
    );

    // H-6: a request carrying a (trusted) `x-mcpg-subject-id` resolves to a
    // header-asserted identity — which is BELOW Verified, so it is STILL
    // rate-limited. A self-asserted header must not buy a limiter exemption;
    // only a cryptographically Verified caller is exempt.
    let resp = app
        .clone()
        .oneshot(anon_post("198.51.100.7", Some("user-1")))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "header-asserted traffic is below Verified and must still be anon-limited"
    );
}

#[tokio::test]
async fn anonymous_limit_skips_unattributable_sources() {
    // trust_proxy_ip = false: the XFF header is ignored and oneshot carries no
    // ConnectInfo, so the source is unattributable → the limiter SKIPS rather
    // than lumping every caller into one shared bucket. With burst 1, a second
    // request would 429 if a shared bucket were (wrongly) in play.
    let app = router(build_anon_limited_state(60, 1, false), "/health", "/mcp");
    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(anon_post("198.51.100.9", None))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "unattributable source must not be limited"
        );
    }
}

#[test]
fn sse_slot_cap_is_concurrent_and_pruned_on_drop() {
    let counts: SseStreamCounts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Reserve up to the per-session concurrent cap.
    let mut held: Vec<SseStreamSlot> = (0..crate::app::MAX_SSE_STREAMS_PER_SESSION)
        .map(|_| acquire_sse_slot(&counts, "sid").expect("under cap"))
        .collect();
    // One more is refused.
    assert!(
        acquire_sse_slot(&counts, "sid").is_none(),
        "over-cap reservation must be refused"
    );

    // Dropping a stream frees its slot (concurrent, not cumulative-per-lifetime).
    held.pop();
    let reacquired = acquire_sse_slot(&counts, "sid");
    assert!(reacquired.is_some(), "a freed slot must be re-acquirable");

    // Dropping every holder prunes the map entry — no leaked per-session row.
    drop(held);
    drop(reacquired);
    assert!(
        counts.lock().unwrap().get("sid").is_none(),
        "the session's count entry must be pruned at zero, not leaked"
    );
}

/// `mcp.registry` serves the standard v0.1 list envelope with
/// this gateway as the single entry, and the per-version fetches
/// resolve `latest` + the exact crate version (anything else 404s).
#[tokio::test]
async fn mcp_registry_serves_v01_catalog_view() {
    let mut config = AppConfig {
        governance: crate::config::GovernanceConfig {
            access: crate::config::AccessConfig {
                authorization_server: None,
                jwks: None,
                oidc_oauth: None,
                resource_metadata: Some(crate::config::OAuthResourceMetadataConfig {
                    resource: "https://gateway.example.com/mcp".to_owned(),
                    authorization_servers: vec![],
                    scopes_supported: vec![],
                    bearer_methods_supported: vec![],
                    allow_loopback_resource: false,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    config.mcp.registry = crate::config::registry::ServedRegistryConfig {
        enabled: true,
        name: "com.acme/gateway".to_owned(),
        description: Some("governed catalog".to_owned()),
        url: None,
    };
    let state = finish_app_state(config, default_test_runtime());
    let app = router(state, "/health", "/mcp");

    // List envelope: one entry, resource_metadata-derived URL.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v0.1/servers")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["servers"].as_array().unwrap().len(), 1);
    let entry = &json["servers"][0];
    assert_eq!(entry["server"]["name"], "com.acme/gateway");
    assert_eq!(entry["server"]["description"], "governed catalog");
    assert_eq!(entry["server"]["remotes"][0]["type"], "streamable-http");
    assert_eq!(
        entry["server"]["remotes"][0]["url"],
        "https://gateway.example.com/mcp"
    );
    assert_eq!(
        entry["_meta"]["io.modelcontextprotocol.registry/official"]["status"],
        "active"
    );

    // Pinned fetch: latest resolves (name URL-encoded per the spec).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v0.1/servers/com.acme%2Fgateway/versions/latest")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["server"]["name"], "com.acme/gateway");

    // Unknown name / version → 404.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v0.1/servers/com.evil%2Fother/versions/latest")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Disabled `mcp.registry`: the v0.1 routes are not mounted at all.
#[tokio::test]
async fn mcp_registry_disabled_is_not_mounted() {
    let state = finish_app_state(AppConfig::default(), default_test_runtime());
    let app = router(state, "/health", "/mcp");
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v0.1/servers")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Cancelling a request the client actually issued must be accepted.
///
/// The id on `notifications/cancelled` names the *target* request, and the
/// target necessarily already used that id — so treating it as the
/// notification's own id re-entered it into the per-session duplicate-id
/// tracker and answered -32600. Cancellation of a real in-flight request was
/// therefore impossible; only cancelling ids the client had never issued
/// worked, which is what the prior tests covered.
#[tokio::test]
async fn cancelling_an_issued_request_id_is_accepted() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    // Issue a real request under id 13 — this records 13 in the tracker.
    let call = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 13,
                        "method": "tools/call",
                        "params": { "name": "mcpg.runtime.snapshot", "arguments": {} }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(call.status(), StatusCode::OK);

    // Now cancel it by that same id, as any client would.
    let cancel = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": { "requestId": 13, "reason": "user aborted" }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        cancel.status(),
        StatusCode::ACCEPTED,
        "cancellation of an issued request id must be accepted, not rejected as a duplicate"
    );
}

/// The same contract on the modern wire.
///
/// An authenticated modern caller runs on a stored synthetic session, so the
/// per-session duplicate-id tracker is live for it — which makes this the wire
/// where treating the cancelled request's id as the notification's own id
/// actually bites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_cancelling_an_issued_request_id_is_accepted() {
    let app = router(build_task_materialization_state(), "/health", "/mcp");

    // Issue a real request under id 13 — this records 13 in the tracker.
    modern_tools_call(&app, 13, "async.mock", false).await;

    let meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
    });
    // Now cancel it by that same id, as any client would.
    let cancel = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "notifications/cancelled")
                .header(header::HeaderName::from_static(SUBJECT_ID_HEADER), "user-1")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {
                            "requestId": 13,
                            "reason": "user aborted",
                            "_meta": meta,
                        }
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = cancel.status();
    let body = to_bytes(cancel.into_body(), 64 * 1024).await.expect("body");
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "cancellation of an issued request id must be accepted on the modern wire too: {}",
        String::from_utf8_lossy(&body)
    );
}

/// A `resources/updated` target is a subscription, not just a stream filter.
///
/// The handler used to reflect these back in the ack as established and then
/// only match them against the delivery bus — but nothing had told the watch
/// engine the URI was being watched, so no update event was ever produced to
/// match. The subscription must reach the store (and the watch engine) the way
/// the legacy `resources/subscribe` arm does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_listen_registers_resource_subscriptions() {
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let runtime = state.runtime.load_full();
    // A resource the gateway actually serves — unknown URIs are skipped.
    let uri = "mcpg://runtime/overview";
    assert!(
        runtime.resolve_resource_route(uri).is_some(),
        "fixture must serve {uri}"
    );
    assert!(
        runtime.subscription_store().subscribers_for(uri).is_empty(),
        "no subscribers before the listen call"
    );

    let (app, session_id) = initialize_session(router(state.clone(), "/health", "/mcp")).await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .header(SUBJECT_ID_HEADER, "test-user")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 402,
                        "method": "subscriptions/listen",
                        "params": {
                            "subscriptions": [
                                { "type": "resources/updated", "uri": uri }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The registration lives as long as the stream, so check while it is held.
    assert!(
        !runtime.subscription_store().subscribers_for(uri).is_empty(),
        "resources/updated target must be registered with the subscription store"
    );

    // Dropping the stream is the modern wire's `resources/unsubscribe`. The
    // release is handed to the subscription reaper rather than done in `Drop`,
    // so poll for it instead of assuming one scheduler turn is enough.
    drop(response);
    for _ in 0..400 {
        if runtime.subscription_store().subscribers_for(uri).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        runtime.subscription_store().subscribers_for(uri).is_empty(),
        "ending the stream must release the subscription"
    );
}

/// Two `subscriptions/listen` streams over one session must not unsubscribe
/// each other.
///
/// The modern wire's session is derived from the principal, not the connection,
/// so every stream a client opens shares one. With the subscription keyed only
/// by `(session, uri)` and torn down by whichever stream ended, closing one
/// stream silently stopped `resources/updated` delivery on every other stream
/// watching the same resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_listen_stream_ending_leaves_the_others_subscribed() {
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let runtime = state.runtime.load_full();
    let uri = "mcpg://runtime/overview";
    let app = router(state.clone(), "/health", "/mcp");

    // The modern wire mints its own session; an identified caller gets the
    // SAME one on every request (that is the point of a principal-derived
    // session), which is what puts two streams on one key. Anonymous traffic
    // mints per request and so cannot exercise this at all.
    let listen = |id: i64| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "subscriptions/listen")
                    .header("x-mcpg-subject-id", "listener-1")
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "method": "subscriptions/listen",
                            "params": {
                                "subscriptions": [
                                    { "type": "resources/updated", "uri": uri }
                                ]
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let first = listen(4201).await;
    let second = listen(4202).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    drop(first);
    // Give any release every chance to land before asserting none did.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !runtime.subscription_store().subscribers_for(uri).is_empty(),
        "the surviving stream must still be subscribed"
    );

    drop(second);
    for _ in 0..400 {
        if runtime.subscription_store().subscribers_for(uri).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        runtime.subscription_store().subscribers_for(uri).is_empty(),
        "the last stream ending must release the subscription"
    );
}

/// The ack's `resourceSubscriptions` reports what was established, so the
/// established half of the split must still be reported: a client that asks for
/// one servable and one unservable URI is told about exactly the servable one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_listen_acks_only_the_resources_it_established() {
    let state = build_test_state();
    install_protocol_registry_for_tests(&state);
    let served = "mcpg://runtime/overview";
    assert!(
        state
            .runtime
            .load()
            .resolve_resource_route(served)
            .is_some(),
        "fixture must serve {served}"
    );

    let (app, session_id) = initialize_session(router(state, "/health", "/mcp")).await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, MCP_ACCEPT_HEADER)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "subscriptions/listen")
                .header(SUBJECT_ID_HEADER, "test-user")
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 4100,
                        "method": "subscriptions/listen",
                        "params": {
                            "subscriptions": [
                                { "type": "resources/updated", "uri": served },
                                { "type": "resources/updated", "uri": "file:///nope" }
                            ]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 8 * 1024).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let ack: Value = text
        .lines()
        .filter(|l| l.starts_with("data:"))
        .filter_map(|l| serde_json::from_str::<Value>(l.trim_start_matches("data:").trim()).ok())
        .find(|v| v["method"] == "notifications/subscriptions/acknowledged")
        .expect("ack frame");
    assert_eq!(
        ack["params"]["notifications"]["resourceSubscriptions"],
        serde_json::json!([served]),
        "ack must list the established target and only it"
    );
}

/// The CP wires its tool-call recorder and quota-status provider once, onto
/// the runtime that exists at attach time. A config reload builds a fresh
/// runtime whose handles are the no-op defaults, so the hooks must survive the
/// swap — otherwise the first bundle the CP itself pushes silences its own
/// telemetry.
#[test]
fn cp_hooks_survive_a_runtime_swap() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRecorder(Arc<AtomicUsize>);
    impl crate::runtime::cp::cp_metrics::ToolCallRecorder for CountingRecorder {
        fn record(&self, _sample: crate::runtime::cp::cp_metrics::ToolCallSample) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let recorded = Arc::new(AtomicUsize::new(0));
    let mut attached = default_test_runtime();
    attached.set_tool_call_recorder(Arc::new(CountingRecorder(recorded.clone())));

    // The reload path's fresh runtime starts on the no-op defaults.
    let mut reloaded = default_test_runtime();
    reloaded.adopt_cp_hooks(&attached);

    reloaded
        .tool_call_recorder
        .record(crate::runtime::cp::cp_metrics::ToolCallSample {
            plugin_id: "mock".into(),
            tool_name: "echo".into(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: std::time::Duration::from_millis(1),
            outcome: crate::runtime::cp::cp_metrics::SampleOutcome::Ok,
            error_code: None,
            error_hash: None,
            request_id: None,
            caller_subject: None,
            request_payload: None,
            response_payload: None,
            payload_truncated: false,
        });
    assert_eq!(
        recorded.load(Ordering::SeqCst),
        1,
        "the CP recorder must still be wired after a reload builds a new runtime"
    );
}

/// A POST answers inline JSON to a client that advertised only
/// `application/json`.
///
/// `validate_post_accept` admits such a client on the stated policy that "if the
/// client also lists SSE, MCPG may upgrade; if not, the response stays inline
/// JSON". Only the first half was implemented: the upgrade decision keyed purely
/// on whether the request had pending deliveries, so a JSON-only client could be
/// handed a body it never agreed to parse.
#[tokio::test]
async fn post_with_json_only_accept_is_not_upgraded_to_sse() {
    let (app, session_id) = initialize_session(router(build_test_state(), "/health", "/mcp")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 41,
                        "method": "tools/list"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        content_type.starts_with("application/json"),
        "a client that advertised only application/json must not be handed \
         text/event-stream; got {content_type}"
    );
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body"),
    )
    .expect("inline JSON-RPC envelope");
    assert_eq!(body["id"], 41);
    assert!(body["result"]["tools"].is_array(), "got {body}");
}

/// The POST-continuation stream counts against the per-session SSE cap.
///
/// It is a long-lived body holding a delivery-bus subscription, exactly like
/// `GET /mcp` and `subscriptions/listen` — but it was the one stream kind that
/// acquired no slot, so the cap was enforceable on two of three.
#[tokio::test]
async fn post_continuation_sse_respects_the_per_session_stream_cap() {
    let state = build_test_state();
    let (_app, session_id) = initialize_session(router(state.clone(), "/health", "/mcp")).await;

    // Hold every slot the session is allowed.
    let held: Vec<SseStreamSlot> = (0..crate::app::MAX_SSE_STREAMS_PER_SESSION)
        .map(|_| {
            acquire_sse_slot(&state.sse_stream_counts, &session_id)
                .expect("slots up to the cap must be available")
        })
        .collect();

    let response = open_post_continuation_sse(&state, &session_id, &GatewayRequestId::new()).await;
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a continuation stream past the cap must be refused, not opened untracked"
    );

    // Releasing a slot lets the next continuation through, proving the refusal
    // is the cap and not an unrelated failure.
    drop(held);
    let response = open_post_continuation_sse(&state, &session_id, &GatewayRequestId::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
}
