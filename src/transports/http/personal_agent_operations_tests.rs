//! The Personal Agent Protocol operations extension over HTTP: a tool
//! listed in `operations` proposes, and the operations endpoint reads,
//! confirms and cancels with a DPoP Session Token.

use std::collections::BTreeMap;

use super::*;
use crate::runtime::authorization_server::AuthorizationServer;
use crate::runtime::personal_agent_operations::OperationsService;

const ENDPOINT: &str = "https://gateway.example.com/poppy/operations";
const TOOL: &str = "mcpg.command.json_call";

/// The DPoP EMA gateway with operations on its command tool, which needs a
/// verified caller holding `mcp:admin`; `tool` adds to the tool's entry and
/// `operations` to the block.
fn build_operations_state(tool: Value, operations: Value) -> (AppState, Arc<AuthorizationServer>) {
    let mut entry = serde_json::json!({
        "tool": TOOL,
        "summary": "Send ${arguments.message}.",
        "action_key": "${arguments.key}",
    });
    let mut block = serde_json::json!({ "endpoint": ENDPOINT });
    for (target, extra) in [(&mut entry, tool), (&mut block, operations)] {
        if let Value::Object(extra) = extra {
            for (name, value) in extra {
                target[name] = value;
            }
        }
    }
    block["tools"] = serde_json::json!([entry]);
    let config: crate::config::personal_agent::PersonalAgentConfig =
        serde_json::from_value(serde_json::json!({
            "agent_extensions": { "source": "attribute", "attribute": "agent_extensions" },
            "operations": block,
        }))
        .expect("profile parses");
    config.validate().expect("profile validates");
    let mut access = dpop_ema_access(false, false);
    access.personal_agent = Some(config.clone());
    build_ema_state_with_runtime(access, move |runtime| {
        runtime.set_personal_agent(Some(Arc::new(
            crate::runtime::personal_agent::PersonalAgentProfile::from_config(&config)
                .expect("profile builds"),
        )));
        runtime.set_pap_operations(Some(Arc::new(
            OperationsService::in_process(config.operations.as_ref().expect("operations"), None)
                .expect("operations build"),
        )));
    })
}

/// A Personal Agent's Session on the gateway: its DPoP key and Session
/// Token, and its MCP session once connected.
struct Agent {
    app: Router,
    key: ClientDpopKey,
    token: String,
    mcp_session: Option<String>,
    next_id: std::sync::atomic::AtomicU64,
}

impl Agent {
    /// A Session `session` holding `scope`, listing `extensions`.
    fn new(
        app: &Router,
        server: &AuthorizationServer,
        session: &str,
        scope: &str,
        extensions: &str,
    ) -> Self {
        let key = ClientDpopKey::new();
        let token = server.mint_mapped_access_token_for_tests(
            "employee-7",
            EMA_IDP,
            Some(scope),
            Some(&key.jkt()),
            BTreeMap::from([
                ("session_id".to_owned(), session.to_owned()),
                ("agent_extensions".to_owned(), extensions.to_owned()),
            ]),
        );
        Self {
            app: app.clone(),
            key,
            token,
            mcp_session: None,
            next_id: std::sync::atomic::AtomicU64::new(10),
        }
    }

    async fn mcp(&self, body: Value) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, MCP_ACCEPT_HEADER)
            .header(header::AUTHORIZATION, format!("DPoP {}", self.token))
            .header("dpop", self.key.proof("POST", EMA_MCP_HTU, &self.token));
        if let Some(session) = &self.mcp_session {
            builder = builder
                .header(
                    PROTOCOL_VERSION_HEADER,
                    crate::protocol::SUPPORTED_PROTOCOL_VERSION,
                )
                .header(SESSION_ID_HEADER, session);
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("response")
    }

    /// `initialize`, then `notifications/initialized`.
    async fn connect(mut self) -> Self {
        let initialized = self
            .mcp(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "personal-agent", "version": "1.0.0" },
                },
            }))
            .await;
        assert_eq!(initialized.status(), StatusCode::OK);
        self.mcp_session = Some(
            initialized
                .headers()
                .get(SESSION_ID_HEADER)
                .expect("session header")
                .to_str()
                .expect("session id")
                .to_owned(),
        );
        let ready = self
            .mcp(serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        assert_eq!(ready.status(), StatusCode::ACCEPTED);
        self
    }

    /// The result of `tools/call` of the command tool with `arguments`.
    async fn call(&self, arguments: Value) -> Value {
        // A session takes each request id once.
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let response = self
            .mcp(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": TOOL, "arguments": arguments },
            }))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = extract_jsonrpc_response(response, id).await;
        body.get("result")
            .cloned()
            .unwrap_or_else(|| panic!("{body}"))
    }

    /// The operation a call proposes.
    async fn propose(&self, arguments: Value) -> Value {
        let result = self.call(arguments).await;
        assert_ne!(result["isError"], true, "{result}");
        result["structuredContent"]["operation"].clone()
    }

    /// A request to the operations endpoint at `/{id}{action}`.
    async fn operations(
        &self,
        method: &str,
        id: &str,
        action: &str,
        body: Option<Value>,
    ) -> axum::response::Response {
        let path = format!("/poppy/operations/{id}{action}");
        let htu = format!("https://gateway.example.com{path}");
        let builder = Request::builder()
            .method(method)
            .uri(&path)
            .header(header::AUTHORIZATION, format!("DPoP {}", self.token))
            .header("dpop", self.key.proof(method, &htu, &self.token))
            .header(header::CONTENT_TYPE, "application/json");
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        self.app
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response")
    }

    async fn read(&self, id: &str) -> axum::response::Response {
        self.operations("GET", id, "", None).await
    }

    async fn confirm(
        &self,
        id: &str,
        revision: u64,
        approved_by: &str,
    ) -> axum::response::Response {
        self.operations(
            "POST",
            id,
            "/confirm",
            Some(serde_json::json!({ "revision": revision, "approved_by": approved_by })),
        )
        .await
    }

    async fn cancel(&self, id: &str) -> axum::response::Response {
        self.operations("POST", id, "/cancel", None).await
    }
}

fn operation_id(operation: &Value) -> String {
    operation["operation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("an operation: {operation}"))
        .to_owned()
}

/// Operations §4 and §5: a Personal Agent that lists the extension gets a
/// proposal instead of the action; one confirm performs it, and a repeated
/// confirm returns the outcome without performing it again.
#[tokio::test]
async fn a_proposal_is_performed_by_its_confirm_once() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let app = router(state, "/health", "/mcp");
    let agent = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "operations")
        .connect()
        .await;

    let result = agent
        .call(serde_json::json!({ "message": "hello", "key": "k1" }))
        .await;
    assert_eq!(
        result["content"][0]["text"],
        "Proposed: Send hello. Not done until confirmed."
    );
    let operation = &result["structuredContent"]["operation"];
    assert_eq!(operation["state"], "proposed");
    assert_eq!(operation["revision"], 1);
    assert_eq!(
        operation["terms"],
        serde_json::json!({ "message": "hello", "key": "k1" })
    );
    let id = operation_id(operation);

    let read = agent.read(&id).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(response_json(read).await["state"], "proposed");

    let confirmed = agent.confirm(&id, 1, "user").await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let done = response_json(confirmed).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(done["confirmation"]["approved_by"], "user");
    let summary = done["result"]["summary"].as_str().expect("a summary");
    assert!(
        summary.contains("hello"),
        "the tool's own result: {summary}"
    );

    let again = agent.confirm(&id, 1, "standing_permission").await;
    assert_eq!(again.status(), StatusCode::OK);
    let again = response_json(again).await;
    assert_eq!(again["state"], "succeeded");
    assert_eq!(
        again["confirmation"], done["confirmation"],
        "not confirmed again"
    );
    assert_eq!(again["result"], done["result"]);
}

/// Without the extension a Personal Agent's call performs the tool, and
/// with `refuse_agent` such an agent is refused before it connects.
#[tokio::test]
async fn an_agent_without_the_extension_is_performed_for_or_refused() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let app = router(state, "/health", "/mcp");
    let agent = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "")
        .connect()
        .await;
    let result = agent
        .call(serde_json::json!({ "message": "hello", "key": "k1" }))
        .await;
    assert!(
        result
            .get("structuredContent")
            .is_none_or(|structured| structured.get("operation").is_none()),
        "{result}"
    );
    assert_ne!(result["isError"], true, "{result}");

    let (state, server) = build_operations_state(
        Value::Null,
        serde_json::json!({ "without_extension": "refuse_agent" }),
    );
    let app = router(state, "/health", "/mcp");
    let refused = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "")
        .mcp(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "personal-agent", "version": "1.0.0" },
            },
        }))
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let challenge = www_authenticate(&refused);
    assert!(
        challenge.contains("error=\"extension_required\", extension=\"operations\""),
        "{challenge}"
    );
}

/// Operations §5.2: the same action proposed again with other terms makes
/// the next revision, and a confirm of the older one gets 409
/// `terms_changed` with the current operation.
#[tokio::test]
async fn a_confirm_of_a_revised_operation_names_the_current_terms() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let app = router(state, "/health", "/mcp");
    let agent = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "operations")
        .connect()
        .await;
    let first = agent
        .propose(serde_json::json!({ "message": "hello", "key": "k1" }))
        .await;
    let revised = agent
        .propose(serde_json::json!({ "message": "goodbye", "key": "k1" }))
        .await;
    assert_eq!(revised["operation_id"], first["operation_id"]);
    assert_eq!(revised["revision"], 2);
    assert_eq!(revised["summary"], "Send goodbye.");

    let id = operation_id(&first);
    let stale = agent.confirm(&id, 1, "user").await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let body = response_json(stale).await;
    assert_eq!(body["error"], "terms_changed");
    assert_eq!(body["operation"]["revision"], 2);
    assert_eq!(body["operation"]["terms"]["message"], "goodbye");

    let current = agent.confirm(&id, 2, "user").await;
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(response_json(current).await["state"], "succeeded");
}

/// PAP §4.3 and operations §3.2: the endpoint takes DPoP Session Tokens of
/// the operation's owner only; to anyone else an operation does not exist.
#[tokio::test]
async fn the_endpoint_serves_the_owners_dpop_session_token_only() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let app = router(state, "/health", "/mcp");
    let owner = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "operations")
        .connect()
        .await;
    let id = operation_id(
        &owner
            .propose(serde_json::json!({ "message": "hello", "key": "k1" }))
            .await,
    );

    let bearer = server.mint_access_token_for_tests("employee-7", EMA_IDP, Some("mcp:admin"));
    let as_bearer = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/poppy/operations/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(as_bearer.status(), StatusCode::UNAUTHORIZED);
    assert!(
        www_authenticate(&as_bearer).starts_with("DPoP error=\"invalid_token\""),
        "{}",
        www_authenticate(&as_bearer)
    );

    let stranger = Agent::new(&app, &server, "ses_2", "mcp:tools mcp:admin", "operations");
    for response in [
        stranger.read(&id).await,
        stranger.confirm(&id, 1, "user").await,
        stranger.cancel(&id).await,
        owner.read("op_unknown").await,
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(response).await["error"],
            "operation_not_found"
        );
    }
    assert_eq!(
        response_json(owner.read(&id).await).await["state"],
        "proposed",
        "nothing a stranger sent changed it"
    );

    let malformed = owner
        .operations(
            "POST",
            &id,
            "/confirm",
            Some(serde_json::json!({ "revision": 1 })),
        )
        .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(malformed).await["error"], "invalid_request");
}

/// Operations §5.2 and PAP §6: a confirm the tool's scopes refuse tells a
/// signed-out Session to sign in, in the DPoP scheme, and performs nothing.
#[tokio::test]
async fn a_confirm_short_of_the_tools_scopes_is_told_to_sign_in() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let app = router(state, "/health", "/mcp");
    let proposer = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "operations")
        .connect()
        .await;
    let id = operation_id(
        &proposer
            .propose(serde_json::json!({ "message": "hello", "key": "k1" }))
            .await,
    );

    let narrower = Agent::new(&app, &server, "ses_1", "mcp:tools", "operations");
    let refused = narrower.confirm(&id, 1, "user").await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let challenge = www_authenticate(&refused);
    assert!(
        challenge.starts_with("DPoP resource_metadata="),
        "{challenge}"
    );
    assert!(
        challenge.contains("error=\"sign_in_required\""),
        "{challenge}"
    );
    assert_eq!(response_json(refused).await["error"], "sign_in_required");
    assert_eq!(
        response_json(proposer.read(&id).await).await["state"],
        "proposed"
    );
}

/// Operations §7 and §5.1: a cancelled operation is never performed, and a
/// tool that needs the User's approval refuses a standing permission.
#[tokio::test]
async fn cancel_and_user_approval_are_kept() {
    let (state, server) = build_operations_state(
        serde_json::json!({ "user_approval_required": true }),
        Value::Null,
    );
    let app = router(state, "/health", "/mcp");
    let agent = Agent::new(&app, &server, "ses_1", "mcp:tools mcp:admin", "operations")
        .connect()
        .await;

    let proposed = agent
        .propose(serde_json::json!({ "message": "hello", "key": "k1" }))
        .await;
    assert_eq!(proposed["user_approval_required"], true);
    let id = operation_id(&proposed);
    let standing = agent.confirm(&id, 1, "standing_permission").await;
    assert_eq!(standing.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(standing).await["error"],
        "user_approval_required"
    );

    let cancelled = agent.cancel(&id).await;
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(response_json(cancelled).await["state"], "cancelled");
    let after = agent.confirm(&id, 1, "user").await;
    assert_eq!(after.status(), StatusCode::OK);
    let after = response_json(after).await;
    assert_eq!(after["state"], "cancelled");
    assert!(after["confirmation"].is_null(), "{after}");
}

/// An operations tool's structured result is the operation, so `tools/list`
/// to an agent that lists the extension leaves out its `outputSchema`.
#[tokio::test]
async fn an_operations_tool_is_listed_without_its_output_schema() {
    let (state, server) = build_operations_state(Value::Null, Value::Null);
    let runtime = state.runtime.load_full();
    let context = |extensions: &str| {
        let agent = Agent::new(
            &router(state.clone(), "/health", "/mcp"),
            &server,
            "ses_1",
            "mcp:tools",
            extensions,
        );
        let runtime = Arc::clone(&runtime);
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("DPoP {}", agent.token).parse().expect("header"),
            );
            headers.insert(
                "dpop",
                agent
                    .key
                    .proof("POST", EMA_MCP_HTU, &agent.token)
                    .parse()
                    .expect("header"),
            );
            build_full_request_context(
                &headers,
                &runtime,
                None,
                false,
                &axum::http::Method::POST,
                Some("/mcp"),
                None,
            )
            .await
            .expect("the Session Token is accepted")
        }
    };
    let descriptor = |name: &str| crate::backends::ToolDescriptor {
        name: name.to_owned(),
        title: None,
        description: String::new(),
        input_schema: serde_json::json!({ "type": "object" }),
        output_schema: Some(serde_json::json!({ "type": "object" })),
        annotations: None,
        execution: None,
        icons: None,
        meta: None,
    };

    let mut listed = [descriptor(TOOL), descriptor("other")];
    runtime.hide_pap_operation_output_schemas(&context("operations").await, &mut listed);
    assert!(listed[0].output_schema.is_none());
    assert!(listed[1].output_schema.is_some(), "not an operations tool");

    let mut without = [descriptor(TOOL)];
    runtime.hide_pap_operation_output_schemas(&context("").await, &mut without);
    assert!(
        without[0].output_schema.is_some(),
        "the agent gets the tool's own result"
    );
}
