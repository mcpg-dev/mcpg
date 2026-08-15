use crate::protocol::{
    CapabilityOperation, ListParams, LoggingLevel, LoggingOperation, ProtocolOperation,
};

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
        None,
        None,
        RequestIdentity::HttpHeader {
            subject_id: "user-1".to_owned(),
            source: "x-mcpg-subject-id".to_owned(),
        },
        TransportKind::Http,
    );

    assert_eq!(context.upstream_request_id.as_deref(), Some("upstream-123"));
    assert_eq!(context.identity.label(), "http_header");
    assert!(!context.request_id.as_str().is_empty());
}

// -- Per-request session-snapshot cache ----------------------------

/// Session store wrapper that counts `load_session` calls so we can
/// assert the cache short-circuits subsequent reads.
struct CountingSessionStore {
    inner: session_store::KvBackedSessionStore,
    load_calls: std::sync::atomic::AtomicUsize,
}

impl CountingSessionStore {
    fn new() -> Self {
        Self {
            inner: session_store::KvBackedSessionStore::new_in_memory(SessionStoreConfig::default()),
            load_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn load_call_count(&self) -> usize {
        self.load_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SessionStore for CountingSessionStore {
    fn create_session(
        &self,
        negotiated_protocol_version: &str,
        params: &crate::protocol::InitializeParams,
    ) -> SessionSnapshot {
        self.inner
            .create_session(negotiated_protocol_version, params)
    }
    fn session_protocol_version(&self, session_id: &str) -> Option<String> {
        self.inner.session_protocol_version(session_id)
    }
    fn load_session(
        &self,
        session_id: Option<&str>,
        require_operational: bool,
    ) -> Result<SessionSnapshot, SessionAccessError> {
        self.load_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.load_session(session_id, require_operational)
    }
    fn transition_session_to_operational(
        &self,
        session_id: &str,
    ) -> Result<(), SessionAccessError> {
        self.inner.transition_session_to_operational(session_id)
    }
    fn set_session_log_level(
        &self,
        session_id: Option<&str>,
        level: LoggingLevel,
    ) -> Result<(), SessionAccessError> {
        self.inner.set_session_log_level(session_id, level)
    }
    fn terminate_session(&self, session_id: &str) -> bool {
        self.inner.terminate_session(session_id)
    }
    fn open_sse_stream(
        &self,
        session_id: Option<&str>,
        resume_cursor: Option<&ResumeCursor>,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.inner.open_sse_stream(session_id, resume_cursor)
    }
    fn stream_protocol_response_with_pending(
        &self,
        session_id: &str,
        protocol_response: &crate::protocol::ProtocolResponse,
        pending_notifications: &[String],
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.inner.stream_protocol_response_with_pending(
            session_id,
            protocol_response,
            pending_notifications,
        )
    }
    fn stream_raw_message(
        &self,
        session_id: &str,
        message_json: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.inner.stream_raw_message(session_id, message_json)
    }
}

fn fresh_init_params() -> crate::protocol::InitializeParams {
    crate::protocol::InitializeParams {
        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
        capabilities: crate::protocol::ClientCapabilities::default(),
        client_info: crate::protocol::ImplementationInfo {
            name: "test-client".to_owned(),
            title: None,
            version: "0.0.0".to_owned(),
            description: None,
            website_url: None,
            icons: None,
        },
    }
}

fn make_request_context(session_id: Option<String>) -> RequestContext {
    RequestContext::new(
        GatewayRequestId::new(),
        None,
        session_id,
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    )
}

#[test]
fn load_session_cached_serves_first_call_from_store() {
    let store = CountingSessionStore::new();
    let snap = store.create_session("2025-11-25", &fresh_init_params());
    let ctx = make_request_context(Some(snap.session_id.clone()));

    let result = ctx.load_session_cached(&store, false).expect("first load");
    assert_eq!(result.session_id, snap.session_id);
    assert_eq!(store.load_call_count(), 1);
}

#[test]
fn load_session_cached_skips_store_on_repeat_calls() {
    let store = CountingSessionStore::new();
    let snap = store.create_session("2025-11-25", &fresh_init_params());
    let ctx = make_request_context(Some(snap.session_id.clone()));

    let _ = ctx.load_session_cached(&store, false).unwrap();
    let _ = ctx.load_session_cached(&store, false).unwrap();
    let _ = ctx.load_session_cached(&store, false).unwrap();
    assert_eq!(
        store.load_call_count(),
        1,
        "repeat load_session_cached calls within one request must hit the cache",
    );
}

#[test]
fn load_session_cached_applies_require_operational_per_call() {
    // Session is in AwaitingInitialized state until
    // transition_session_to_operational. The cache stores the raw
    // snapshot (require_operational=false semantics); each call
    // applies its own filter.
    let store = CountingSessionStore::new();
    let snap = store.create_session("2025-11-25", &fresh_init_params());
    let ctx = make_request_context(Some(snap.session_id.clone()));

    // First call with require_operational=true → fails
    // (AwaitingInitialized != Operational).
    let err = ctx.load_session_cached(&store, true).unwrap_err();
    assert_eq!(err, SessionAccessError::NotInitialized);

    // Same cache, require_operational=false → succeeds.
    let ok = ctx.load_session_cached(&store, false).unwrap();
    assert_eq!(ok.session_id, snap.session_id);

    // Both calls together drove exactly one underlying lookup.
    assert_eq!(store.load_call_count(), 1);
}

#[test]
fn load_session_cached_caches_unknown_session_error() {
    let store = CountingSessionStore::new();
    let ctx = make_request_context(Some("does-not-exist".to_owned()));

    let e1 = ctx.load_session_cached(&store, false).unwrap_err();
    let e2 = ctx.load_session_cached(&store, false).unwrap_err();
    assert_eq!(e1, SessionAccessError::UnknownSession);
    assert_eq!(e2, SessionAccessError::UnknownSession);
    assert_eq!(
        store.load_call_count(),
        1,
        "even error responses are cached — re-asking would yield the same answer",
    );
}

#[test]
fn load_session_cached_handles_missing_session_id() {
    let store = CountingSessionStore::new();
    let ctx = make_request_context(None);

    let err = ctx.load_session_cached(&store, false).unwrap_err();
    assert_eq!(err, SessionAccessError::MissingSessionId);
    // Still drives one underlying call (the store decides "missing
    // id" semantics; we don't short-circuit before reaching it).
    assert_eq!(store.load_call_count(), 1);
}

#[test]
fn load_session_cache_is_isolated_per_request_context() {
    // Different RequestContext instances get fresh caches, even if
    // they reference the same session — important so a second
    // request sees a freshly-loaded snapshot (e.g. picks up a
    // logging/setLevel change made between requests).
    let store = CountingSessionStore::new();
    let snap = store.create_session("2025-11-25", &fresh_init_params());
    let ctx_a = make_request_context(Some(snap.session_id.clone()));
    let ctx_b = make_request_context(Some(snap.session_id.clone()));

    let _ = ctx_a.load_session_cached(&store, false).unwrap();
    let _ = ctx_b.load_session_cached(&store, false).unwrap();
    assert_eq!(
        store.load_call_count(),
        2,
        "each RequestContext drives its own first-load",
    );
}

#[test]
fn load_session_cache_shared_across_clones_of_same_request() {
    // Cloning a RequestContext (e.g. when threading it through
    // layers) must share the cache so the inner clone serves from
    // it — the OnceLock lives behind an Arc.
    let store = CountingSessionStore::new();
    let snap = store.create_session("2025-11-25", &fresh_init_params());
    let ctx = make_request_context(Some(snap.session_id.clone()));

    let _ = ctx.load_session_cached(&store, false).unwrap();
    let cloned = ctx.clone();
    let _ = cloned.load_session_cached(&store, false).unwrap();
    assert_eq!(
        store.load_call_count(),
        1,
        "Clone of RequestContext shares the OnceLock cache",
    );
}

#[tokio::test]
async fn runtime_handles_readiness_gateway_request() {
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
    let request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Diagnostics(DiagnosticsOperation::Readiness),
    );

    let response = runtime.handle_request(request).await;

    match response.payload {
        GatewayResponsePayload::Readiness(snapshot) => {
            assert_eq!(snapshot.status, ReadinessStatus::Ready);
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_initialize_protocol_request() {
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
    let request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let response = runtime.handle_request(request).await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            assert_eq!(protocol_response.http_status, 200);
            assert!(protocol_response.session_id_header.is_some());
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(success.id, serde_json::json!(1));
            assert_eq!(
                success.result["protocolVersion"],
                SUPPORTED_PROTOCOL_VERSION
            );
            assert_eq!(success.result["serverInfo"]["name"], "mcpg");
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_tools_list_protocol_request() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let initialized_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id.clone()),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialized,
        )),
    );
    let _ = runtime.handle_request(initialized_request).await;

    let request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            None,
            RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Capabilities(
            CapabilityOperation::ToolsList {
                request_id: serde_json::json!(2),
                params: ListParams::default(),
            },
        )),
    );

    let response = runtime.handle_request(request).await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            // tools are returned lexicographically. The
            // first debug tool registered for this runtime is
            // `mcpg.debug.command_probe`; `mcpg.runtime.snapshot`
            // still appears later in the list.
            let names: Vec<_> = success.result["tools"]
                .as_array()
                .expect("tools array")
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect();
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
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn tools_list_invalid_cursor_returns_invalid_params() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.expect("session id"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let initialized = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id.clone()),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialized,
        )),
    );
    let _ = runtime.handle_request(initialized).await;

    // A cursor that does not decode against the session-bound key must
    // surface -32602, not silently restart at page 1.
    let request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            None,
            RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Capabilities(
            CapabilityOperation::ToolsList {
                request_id: serde_json::json!(2),
                params: ListParams {
                    cursor: Some("not-a-valid-cursor".to_owned()),
                    meta: None,
                },
            },
        )),
    );
    let response = runtime.handle_request(request).await;
    match response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcError(err) = p.response else {
                panic!("expected JsonRpcError for invalid cursor")
            };
            assert_eq!(err.error.code, -32602, "invalid cursor → -32602");
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_prompts_get_protocol_request() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::PromptsGet {
                    request_id: serde_json::json!(31),
                    params: crate::protocol::PromptGetParams {
                        name: "mcpg_operational_overview".to_owned(),
                        arguments: None,
                        meta: None,
                    },
                },
            )),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(success.result["messages"][0]["role"], "system");
            assert!(
                success.result["messages"][0]["content"]["text"]
                    .as_str()
                    .expect("prompt text")
                    .contains("Available tools")
            );
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_resources_read_protocol_request() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesRead {
                    request_id: serde_json::json!(32),
                    params: crate::protocol::ResourceReadParams {
                        uri: "mcpg://runtime/overview".to_owned(),
                        meta: None,
                    },
                },
            )),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(
                success.result["contents"][0]["uri"],
                "mcpg://runtime/overview"
            );
            assert_eq!(
                success.result["contents"][0]["mimeType"],
                "application/json"
            );
            assert!(
                success.result["contents"][0]["text"]
                    .as_str()
                    .expect("resource text")
                    .contains("\"service\": \"mcpg\"")
            );
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_resources_subscribe_and_unsubscribe() {
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
    let init_ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    let response = runtime
        .handle_request(GatewayRequest::new(
            init_ctx,
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match &response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.clone().unwrap(),
        _ => panic!("expected protocol response"),
    };
    runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    // Subscribe to the debug resource
    let sub_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesSubscribe {
                    request_id: serde_json::json!(10),
                    params: crate::protocol::ResourceSubscribeParams {
                        uri: "mcpg://runtime/overview".to_owned(),
                    },
                },
            )),
        ))
        .await;
    match &sub_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = &p.response else {
                panic!("expected success, got: {:?}", p.response)
            };
            assert_eq!(success.id, serde_json::json!(10));
        }
        _ => panic!("expected protocol response"),
    }

    // Verify subscription exists
    assert_eq!(
        runtime
            .subscription_store
            .subscriptions_for_session(&session_id)
            .len(),
        1
    );

    // Subscribe to unknown resource returns error
    let unknown_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesSubscribe {
                    request_id: serde_json::json!(11),
                    params: crate::protocol::ResourceSubscribeParams {
                        uri: "nonexistent://resource".to_owned(),
                    },
                },
            )),
        ))
        .await;
    match &unknown_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            assert!(matches!(&p.response, ProtocolResponse::JsonRpcError(_)));
        }
        _ => panic!("expected protocol response"),
    }

    // Unsubscribe
    let unsub_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesUnsubscribe {
                    request_id: serde_json::json!(12),
                    params: crate::protocol::ResourceSubscribeParams {
                        uri: "mcpg://runtime/overview".to_owned(),
                    },
                },
            )),
        ))
        .await;
    match &unsub_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = &p.response else {
                panic!("expected success")
            };
            assert_eq!(success.id, serde_json::json!(12));
        }
        _ => panic!("expected protocol response"),
    }

    // Subscription cleared
    assert_eq!(
        runtime
            .subscription_store
            .subscriptions_for_session(&session_id)
            .len(),
        0
    );
}

#[tokio::test]
async fn runtime_handles_resources_templates_list() {
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
    let init_ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    let response = runtime
        .handle_request(GatewayRequest::new(
            init_ctx,
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match &response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.clone().unwrap(),
        _ => panic!("expected protocol response"),
    };
    runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let tl_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesTemplatesList {
                    request_id: serde_json::json!(20),
                    params: ListParams::default(),
                },
            )),
        ))
        .await;
    match &tl_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = &p.response else {
                panic!("expected success")
            };
            assert_eq!(success.id, serde_json::json!(20));
            // Templates list is currently empty
            assert_eq!(success.result["resourceTemplates"], serde_json::json!([]));
        }
        _ => panic!("expected protocol response"),
    }
}

#[tokio::test]
async fn runtime_handles_notification_cancelled() {
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
    let init_ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        None,
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    let response = runtime
        .handle_request(GatewayRequest::new(
            init_ctx,
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match &response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.clone().unwrap(),
        _ => panic!("expected protocol response"),
    };

    // Send notifications/cancelled
    let cancel_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::NotificationCancelled {
                    request_id: serde_json::json!(999),
                    reason: Some("user abort".to_owned()),
                },
            )),
        ))
        .await;
    match &cancel_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            assert_eq!(p.http_status, 202);
        }
        _ => panic!("expected protocol response"),
    }
}

#[tokio::test]
async fn modern_notification_cancelled_reaches_cancellation_bus() {
    // CANCEL-1: a modern (`2026-07-28`) `notifications/cancelled` must
    // reach the SAME principal-partitioned cancellation bus the legacy
    // wire uses (not be collapsed into a bare 202). We install an
    // in-memory bus, subscribe, route a cancel through the shared
    // `handle_request_cancellation` entry-point with a modern-version
    // context, and assert the event lands on the bus.
    use crate::runtime::cancellation_bus::{BusBackedCancellationBus, CancellationBus};

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
    let bus = std::sync::Arc::new(BusBackedCancellationBus::new_in_memory());
    let mut rx = bus.subscribe().await;
    runtime.set_cancellation_bus(bus);

    let mut ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        Some("sess-modern".to_owned()),
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    ctx.negotiated_version = crate::protocol::version::ProtocolVersion::V_2026_07_28;

    runtime
        .handle_request_cancellation(&ctx, &serde_json::json!("req-42"), Some("user abort"))
        .await;

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("cancellation event should be broadcast within timeout")
        .expect("bus should deliver the event");
    // target_id is the JSON-RPC id stringified (a JSON string value
    // serialises with surrounding quotes), matching the legacy arm.
    assert_eq!(event.target_id, serde_json::json!("req-42").to_string());
    assert_eq!(event.reason.as_deref(), Some("user abort"));
    assert!(matches!(
        event.kind,
        crate::runtime::cancellation_bus::CancellationKind::Request
    ));
}

#[tokio::test]
async fn cancellation_targeting_initialize_is_dropped() {
    // §Cancellation MUST-NOT: a cancel aimed at `initialize` is ignored
    // (no bus broadcast) on the shared path.
    use crate::runtime::cancellation_bus::{BusBackedCancellationBus, CancellationBus};

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
    let bus = std::sync::Arc::new(BusBackedCancellationBus::new_in_memory());
    let mut rx = bus.subscribe().await;
    runtime.set_cancellation_bus(bus);

    let ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        Some("s".to_owned()),
        None,
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        },
        TransportKind::Http,
    );
    runtime
        .handle_request_cancellation(&ctx, &serde_json::json!("initialize"), None)
        .await;

    // Nothing should arrive.
    let got = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
    assert!(
        got.is_err(),
        "no cancellation event should be broadcast for initialize"
    );
}

#[tokio::test]
async fn initialize_response_includes_subscribe_capability() {
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
    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                None,
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    match &response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = &p.response else {
                panic!("expected success")
            };
            assert_eq!(
                success.result["capabilities"]["resources"]["subscribe"],
                true
            );
        }
        _ => panic!("expected protocol response"),
    }
}

#[tokio::test]
async fn session_termination_clears_subscriptions() {
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
    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                None,
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match &response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.clone().unwrap(),
        _ => panic!("expected protocol response"),
    };
    runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    // Subscribe
    runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesSubscribe {
                    request_id: serde_json::json!(10),
                    params: crate::protocol::ResourceSubscribeParams {
                        uri: "mcpg://runtime/overview".to_owned(),
                    },
                },
            )),
        ))
        .await;
    assert_eq!(
        runtime
            .subscription_store
            .subscriptions_for_session(&session_id)
            .len(),
        1
    );

    // Terminate
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                Some("upstream-1".to_owned()),
                Some(session_id),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsCall {
                    request_id: serde_json::json!(33),
                    params: crate::protocol::ToolCallParams {
                        name: "mcpg.request.echo".to_owned(),
                        arguments: Some(serde_json::json!({
                            "message": "hello"
                        })),
                        meta: None,
                        task: None,
                    },
                },
            )),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(
                success.result["structuredContent"]["toolName"],
                "mcpg.request.echo"
            );
            assert_eq!(
                success.result["structuredContent"]["arguments"]["message"],
                "hello"
            );
            assert_eq!(
                success.result["structuredContent"]["request"]["principalId"],
                "user-1"
            );
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_rejects_anonymous_tool_call_before_dispatch() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsCall {
                    request_id: serde_json::json!(404),
                    params: crate::protocol::ToolCallParams {
                        name: "mcpg.runtime.snapshot".to_owned(),
                        arguments: Some(serde_json::json!({})),
                        meta: None,
                        task: None,
                    },
                },
            )),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            assert_eq!(protocol_response.http_status, 403);
            let ProtocolResponse::JsonRpcError(error) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(error.error.code, -32003);
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
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
            }],
        },
    );
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsCall {
                    request_id: serde_json::json!(405),
                    params: crate::protocol::ToolCallParams {
                        name: "mcpg.runtime.snapshot".to_owned(),
                        arguments: Some(serde_json::json!({})),
                        meta: None,
                        task: None,
                    },
                },
            )),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            assert_eq!(protocol_response.http_status, 200);
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(success.result["structuredContent"]["service"], "mcpg");
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn runtime_handles_tool_call_protocol_request() {
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
    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );

    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };

    let initialized_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id.clone()),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialized,
        )),
    );
    let _ = runtime.handle_request(initialized_request).await;

    let request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            None,
            RequestIdentity::HttpHeader {
                subject_id: "user-1".to_owned(),
                source: "x-mcpg-subject-id".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Capabilities(
            CapabilityOperation::ToolsCall {
                request_id: serde_json::json!(3),
                params: crate::protocol::ToolCallParams {
                    name: "mcpg.runtime.snapshot".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                    task: None,
                },
            },
        )),
    );

    let response = runtime.handle_request(request).await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(success.result["content"][0]["type"], "text");
            assert_eq!(success.result["structuredContent"]["service"], "mcpg");
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn wait_for_task_terminal_unblocks_when_task_transitions() {
    use std::sync::Arc;
    use std::time::Duration;

    let runtime = Arc::new(GatewayRuntime::new(
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
    ));
    let session_id = "sess-wait";
    let record = runtime
        .task_store
        .create_task(session_id, serde_json::json!(1), "noop", None)
        .expect("create_task");
    let task_id = record.task.task_id.clone();

    // Drive the terminal transition from another task slightly after
    // wait_for_task_terminal starts polling.
    let store = runtime.task_store.clone();
    let task_id_write = task_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = store.store_task_terminal(
            &task_id_write,
            crate::protocol::TaskStatus::Completed,
            task_store::TerminalEnvelope::success(serde_json::json!({"ok": true})),
        );
    });

    let got = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.wait_for_task_terminal(&task_id, session_id),
    )
    .await
    .expect("wait_for_task_terminal did not hang past its bound")
    .expect("terminal envelope available");
    match got {
        task_store::TerminalEnvelope::Success { result } => {
            assert_eq!(result["ok"], true);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[tokio::test]
async fn open_sse_stream_returns_priming_event_for_operational_session() {
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

    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let events = runtime
        .open_sse_stream(&RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ))
        .expect("stream opened");

    assert_eq!(events.len(), 2);
    assert!(events[0].event_id.starts_with("stream-"));
    assert_eq!(events[0].data, "");
    assert_eq!(events[0].retry_ms, Some(1500));
    assert!(events[1].data.contains("notifications/message"));
}

#[tokio::test]
async fn stream_protocol_response_can_be_replayed_from_last_event_id() {
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

    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let streamed_events = runtime
        .stream_protocol_response(
            &session_id,
            &ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: serde_json::json!(2),
                result: serde_json::json!({"ok": true}),
            }),
        )
        .expect("streamed response");

    let replayed_events = runtime
        .open_sse_stream(&RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            Some(ResumeCursor {
                last_event_id: streamed_events[0].event_id.clone(),
            }),
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ))
        .expect("replayed stream");

    assert_eq!(replayed_events.len(), 2);
    assert!(replayed_events[0].data.contains("notifications/message"));
    assert!(replayed_events[1].data.contains("\"jsonrpc\":\"2.0\""));
}

#[tokio::test]
async fn runtime_handles_logging_set_level_request() {
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

    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Logging(LoggingOperation::SetLevel {
                request_id: serde_json::json!(44),
                params: crate::protocol::LoggingSetLevelParams {
                    level: LoggingLevel::Error,
                },
            })),
        ))
        .await;

    match response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => {
            let ProtocolResponse::JsonRpcSuccess(success) = protocol_response.response else {
                panic!("unexpected protocol response")
            };
            assert_eq!(success.id, serde_json::json!(44));
            assert_eq!(success.result, serde_json::json!({}));
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[tokio::test]
async fn open_sse_stream_hard_fails_when_cursor_has_expired() {
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

    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let streamed_events = runtime
        .stream_protocol_response(
            &session_id,
            &ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: serde_json::json!(2),
                result: serde_json::json!({"ok": true}),
            }),
        )
        .expect("streamed response");

    let expired = runtime
        .open_sse_stream(&RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            Some(ResumeCursor {
                last_event_id: format!(
                    "{}:999",
                    streamed_events[0]
                        .event_id
                        .split(':')
                        .next()
                        .expect("stream id")
                ),
            }),
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ))
        .expect_err("expired cursor rejected");

    assert!(matches!(
        expired,
        StreamAccessError::ExpiredCursor | StreamAccessError::InvalidCursor
    ));
}

#[tokio::test]
async fn replay_window_limit_from_store_config_is_enforced() {
    let runtime = GatewayRuntime::new_with_store_config(
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
        SessionStoreConfig {
            replay_window_limit: 1,
            session_idle_timeout_ms: 900_000,
            max_sessions: 10_000,
            max_sessions_per_tenant: 0,
        },
    );

    let initialize_request = GatewayRequest::new(
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ),
        GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
            LifecycleOperation::Initialize {
                request_id: serde_json::json!(1),
                params: crate::protocol::InitializeParams {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                    capabilities: crate::protocol::ClientCapabilities::default(),
                    client_info: crate::protocol::ImplementationInfo {
                        name: "client".to_owned(),
                        title: None,
                        version: "1.0.0".to_owned(),
                        description: None,
                        website_url: None,
                        icons: None,
                    },
                },
            },
        )),
    );
    let initialize_response = runtime.handle_request(initialize_request).await;
    let session_id = match initialize_response.payload {
        GatewayResponsePayload::Protocol(protocol_response) => protocol_response
            .session_id_header
            .expect("session id returned"),
        payload => panic!("unexpected payload: {payload:?}"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    let streamed_events = runtime
        .stream_protocol_response(
            &session_id,
            &ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: serde_json::json!(77),
                result: serde_json::json!({"ok": true}),
            }),
        )
        .expect("streamed response");

    let expired = runtime
        .open_sse_stream(&RequestContext::new(
            GatewayRequestId::new(),
            None,
            Some(session_id),
            Some(ResumeCursor {
                last_event_id: streamed_events[0].event_id.clone(),
            }),
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        ))
        .expect_err("cursor should expire when replay window keeps only the last event");

    assert!(matches!(expired, StreamAccessError::ExpiredCursor));
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

    // Initialize session
    let init_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                None,
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match init_response.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.expect("session"),
        _ => panic!("expected protocol response"),
    };
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    // HeaderAsserted caller should NOT see mcpg.runtime.snapshot (requires Verified)
    let header_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                RequestIdentity::HttpHeader {
                    subject_id: "user-1".to_owned(),
                    source: "x-mcpg-subject-id".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsList {
                    request_id: serde_json::json!(2),
                    params: ListParams::default(),
                },
            )),
        ))
        .await;

    let header_tools = match header_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = p.response else {
                panic!("expected success");
            };
            success.result["tools"]
                .as_array()
                .expect("tools array")
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
        _ => panic!("expected protocol response"),
    };
    assert!(
        !header_tools.contains(&"mcpg.runtime.snapshot".to_owned()),
        "header-asserted caller should not see verified-only tool, got: {:?}",
        header_tools
    );

    // Verified caller SHOULD see mcpg.runtime.snapshot
    let verified_response = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                RequestIdentity::Verified {
                    subject_id: "user-1".to_owned(),
                    issuer: "https://auth.example.com/".to_owned(),
                    auth_provider: "jwks".to_owned(),
                    source: "authorization:jwt".to_owned(),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: std::collections::BTreeMap::new(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ToolsList {
                    request_id: serde_json::json!(3),
                    params: ListParams::default(),
                },
            )),
        ))
        .await;

    let verified_tools = match verified_response.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = p.response else {
                panic!("expected success");
            };
            success.result["tools"]
                .as_array()
                .expect("tools array")
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
        _ => panic!("expected protocol response"),
    };
    assert!(
        verified_tools.contains(&"mcpg.runtime.snapshot".to_owned()),
        "verified caller should see verified-only tool, got: {:?}",
        verified_tools
    );
}

#[test]
fn paginate_list_returns_all_when_small() {
    let items: Vec<i32> = (0..5).collect();
    let (page, cursor) = super::paginate_list_bound(&items, None, None);
    assert_eq!(page.len(), 5);
    assert!(cursor.is_none());
}

#[test]
fn paginate_list_paginates_large_set() {
    let items: Vec<i32> = (0..250).collect();
    let (page1, cursor1) = super::paginate_list_bound(&items, None, None);
    assert_eq!(page1.len(), super::DEFAULT_PAGE_SIZE);
    assert_eq!(page1[0], 0);
    assert!(cursor1.is_some());

    let (page2, cursor2) = super::paginate_list_bound(&items, cursor1.as_deref(), None);
    assert_eq!(page2.len(), super::DEFAULT_PAGE_SIZE);
    assert_eq!(page2[0], 100);
    assert!(cursor2.is_some());

    let (page3, cursor3) = super::paginate_list_bound(&items, cursor2.as_deref(), None);
    assert_eq!(page3.len(), 50);
    assert_eq!(page3[0], 200);
    assert!(cursor3.is_none());
}

#[test]
fn paginate_list_invalid_cursor_returns_first_page() {
    let items: Vec<i32> = (0..5).collect();
    let (page, cursor) = super::paginate_list_bound(&items, Some("garbage_cursor"), None);
    assert_eq!(page.len(), 5);
    assert!(cursor.is_none());
}

#[test]
fn paginate_list_empty_input() {
    let items: Vec<i32> = vec![];
    let (page, cursor) = super::paginate_list_bound(&items, None, None);
    assert!(page.is_empty());
    assert!(cursor.is_none());
}

/// a MAC-bound cursor round-trips and carries the offset.
#[test]
fn bound_cursor_roundtrips_for_same_session() {
    let items: Vec<i32> = (0..250).collect();
    let key = b"session-A-key";
    let (_p1, c1) = super::paginate_list_bound(&items, None, Some(key));
    assert!(c1.is_some());
    let (p2, _) = super::paginate_list_bound(&items, c1.as_deref(), Some(key));
    assert_eq!(p2[0], 100);
}

/// a cursor minted under session A MUST NOT advance
/// pagination when presented under session B — it restarts at 0.
#[test]
fn bound_cursor_rejects_cross_session_replay() {
    let items: Vec<i32> = (0..250).collect();
    let key_a = b"session-A-key";
    let key_b = b"session-B-key";
    let (_p1, c1) = super::paginate_list_bound(&items, None, Some(key_a));
    let (replay_page, _) = super::paginate_list_bound(&items, c1.as_deref(), Some(key_b));
    // Replay resets to offset 0 rather than advancing.
    assert_eq!(replay_page[0], 0);
}

/// unbound cursor (from a client that used paginate_list
/// without a key) is rejected by the bound decoder.
#[test]
fn bound_cursor_rejects_unbound_input() {
    let items: Vec<i32> = (0..250).collect();
    let (_p1, c1) = super::paginate_list_bound(&items, None, None);
    assert!(c1.is_some());
    let (page, _) = super::paginate_list_bound(&items, c1.as_deref(), Some(b"key"));
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
fn composite_cursor_rejects_legacy_bare_offset() {
    // A bare-offset cursor (from `encode_cursor`) is NOT a
    // composite cursor — the resources/list handler keeps a
    // legacy fallback path, but `decode_composite_cursor`
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
        strategy: WatchStrategyConfig::Webhook { token: "t1".into() },
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
            group_id: "grp".into(),
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
        watch_engine::WatchStrategy::Webhook { token } => {
            assert_eq!(token, "t1");
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
        WatchStrategyConfig::PostgresListenNotify { url, channel } => {
            assert_eq!(url, "postgres://app@db/orders");
            assert_eq!(channel, "orders_changed");
        }
        other => panic!("expected PostgresListenNotify, got {other:?}"),
    }
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
    // Resource fixtures are mock-backed; register the in-tree mock plugin
    // + its per-binding profiles so the fetcher's dispatch resolves
    // (the bare dispatcher bypasses the Runtime's #[cfg(test)] fallback).
    let mut plugin_registry = mcpg_plugin_host::PluginRegistry::new();
    let mock_bindings: Vec<&crate::config::BackendConfig> = bindings
        .iter()
        .filter(|b| b.backend.kind == "mock")
        .collect();
    if !mock_bindings.is_empty() {
        let mock_plugin = Arc::new(mcpg_plugin_backend_mock::MockBackendPlugin::new());
        mcpg_plugin_host::FirstPartyRegistrar::new(&mut plugin_registry)
            .register(
                mcpg_plugin_backend_mock::BINDING_DESCRIPTOR_YAML,
                &[],
                (),
                |reg, _host| {
                    reg.register_backend(
                        mock_plugin.clone(),
                        mcpg_plugin_protocol::PluginTier::Native,
                    )
                },
            )
            .expect("register mock plugin");
        let host = mcpg_plugin_protocol::noop_backend_host();
        for binding in &mock_bindings {
            if let Some(spec) = crate::backends::dynamic_register_spec(&binding.backend, true) {
                futures::executor::block_on(mcpg_plugin_protocol::BackendPlugin::register_profile(
                    mock_plugin.as_ref(),
                    &binding.name,
                    &spec,
                    host.clone(),
                ))
                .expect("register mock profile");
            }
        }
    }
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

// Deterministic modern synthetic session id derivation.
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
        Some(crate::protocol::shared::apps::capability_value(&[])),
        apps_cfg.federate_upstream_enabled(),
        Some(apps_cfg.compiled_policy()),
        &apps_cfg.registry,
    );

    // initialize → session
    let init = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                None,
                None,
                RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialize {
                    request_id: serde_json::json!(1),
                    params: crate::protocol::InitializeParams {
                        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
                        capabilities: crate::protocol::ClientCapabilities::default(),
                        client_info: crate::protocol::ImplementationInfo {
                            name: "client".to_owned(),
                            title: None,
                            version: "1.0.0".to_owned(),
                            description: None,
                            website_url: None,
                            icons: None,
                        },
                    },
                },
            )),
        ))
        .await;
    let session_id = match init.payload {
        GatewayResponsePayload::Protocol(p) => p.session_id_header.expect("session id"),
        other => panic!("unexpected payload: {other:?}"),
    };
    let ident = || RequestIdentity::HttpHeader {
        subject_id: "user-1".to_owned(),
        source: "x-mcpg-subject-id".to_owned(),
    };

    // complete the lifecycle handshake before issuing capability requests
    let _ = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                ident(),
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Lifecycle(
                LifecycleOperation::Initialized,
            )),
        ))
        .await;

    // resources/list includes the gateway app descriptor
    let list = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id.clone()),
                None,
                ident(),
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesList {
                    request_id: serde_json::json!(2),
                    params: ListParams::default(),
                },
            )),
        ))
        .await;
    match list.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = p.response else {
                panic!("expected list success, got {:?}", p.response)
            };
            let found = success.result["resources"]
                .as_array()
                .expect("resources array")
                .iter()
                .find(|r| r["uri"] == "ui://mcpg/customers")
                .expect("gateway app listed");
            assert_eq!(found["mimeType"], "text/html;profile=mcp-app");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // resources/read serves the authored body + clamped _meta.ui
    let read = runtime
        .handle_request(GatewayRequest::new(
            RequestContext::new(
                GatewayRequestId::new(),
                None,
                Some(session_id),
                None,
                ident(),
                TransportKind::Http,
            ),
            GatewayOperation::Protocol(ProtocolOperation::Capabilities(
                CapabilityOperation::ResourcesRead {
                    request_id: serde_json::json!(3),
                    params: crate::protocol::ResourceReadParams {
                        uri: "ui://mcpg/customers".to_owned(),
                        meta: None,
                    },
                },
            )),
        ))
        .await;
    match read.payload {
        GatewayResponsePayload::Protocol(p) => {
            let ProtocolResponse::JsonRpcSuccess(success) = p.response else {
                panic!("expected read success")
            };
            let content = &success.result["contents"][0];
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
        other => panic!("unexpected payload: {other:?}"),
    }
}
