//! A federated `tools/call` honours its request's cancellation: the gateway
//! stops waiting on the upstream, sends the upstream `notifications/cancelled`
//! with the upstream request id, and answers the client with the cancelled
//! result a local backend gives.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, http::StatusCode};
use serde_json::{Value, json};

use super::tests::{discover_result, empty_policy, fed_config};
use super::*;
use crate::backends::CapabilityRegistry;

/// What an upstream whose `tools/call` never answers received.
#[derive(Default)]
struct Held {
    /// The JSON-RPC id of every `tools/call`.
    calls: Mutex<Vec<Value>>,
    /// Every `notifications/cancelled`, whole.
    cancels: Mutex<Vec<Value>>,
}

/// An upstream that lists one tool, `work`, holds every call of it open,
/// and records every `notifications/cancelled`.
async fn holding_upstream() -> (String, Arc<Held>) {
    let held = Arc::new(Held::default());
    let seen = Arc::clone(&held);
    let app = Router::new().route(
        "/mcp",
        post(move |Json(body): Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let id = body.get("id").cloned();
                match body["method"].as_str().unwrap_or("") {
                    "server/discover" => Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": discover_result(json!({ "tools": {} }))
                    }))
                    .into_response(),
                    "tools/list" => Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "tools": [{
                            "name": "work",
                            "description": "Runs until it is cancelled",
                            "inputSchema": { "type": "object" }
                        }] }
                    }))
                    .into_response(),
                    "tools/call" => {
                        seen.calls.lock().unwrap().push(id.unwrap_or(Value::Null));
                        std::future::pending::<Response>().await
                    }
                    "notifications/cancelled" => {
                        seen.cancels.lock().unwrap().push(body);
                        StatusCode::ACCEPTED.into_response()
                    }
                    _ => Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": "not served" }
                    }))
                    .into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/mcp"), held)
}

/// Poll `probe` until it yields, for at most ten seconds.
async fn eventually<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(found) = probe() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not observed within ten seconds");
}

fn engine_for(url: &str) -> FederationEngine {
    let registry = CapabilityRegistry::default();
    FederationEngine::new(
        vec![fed_config(url)],
        registry.federated_overlay(),
        empty_policy(),
        "via-1",
    )
}

#[tokio::test]
async fn a_cancelled_call_stops_waiting_and_tells_the_upstream() {
    let (url, held) = holding_upstream().await;
    let engine = engine_for(&url);
    let cancel = tokio_util::sync::CancellationToken::new();
    let call = engine.call_tool_cancellable(
        "notion",
        "work",
        None,
        FederationCaller::default(),
        None,
        Some(&cancel),
    );
    let cancel_once_called = async {
        let call_id = eventually(|| held.calls.lock().unwrap().first().cloned()).await;
        cancel.cancel();
        call_id
    };
    let (outcome, call_id) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(call, cancel_once_called)
    })
    .await
    .expect("the cancel ends the call while the upstream still holds it");
    assert!(matches!(outcome, Ok(None)), "{outcome:?}");
    let notice = eventually(|| held.cancels.lock().unwrap().first().cloned()).await;
    assert_eq!(notice["params"]["requestId"], call_id);
}

#[tokio::test]
async fn a_call_cancelled_before_it_starts_reaches_no_upstream() {
    let (url, held) = holding_upstream().await;
    let engine = engine_for(&url);
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let outcome = engine
        .call_tool_cancellable(
            "notion",
            "work",
            None,
            FederationCaller::default(),
            None,
            Some(&cancel),
        )
        .await;
    assert!(matches!(outcome, Ok(None)), "{outcome:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(held.calls.lock().unwrap().is_empty());
    assert!(held.cancels.lock().unwrap().is_empty());
}

/// The body of a JSON-RPC answer sent as JSON or as an event stream.
async fn rpc_body(response: reqwest::Response) -> Value {
    let streamed = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    let text = response.text().await.expect("body");
    if !streamed {
        return serde_json::from_str(&text).unwrap_or(Value::Null);
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|message| message.get("id").is_some())
        .unwrap_or(Value::Null)
}

/// The whole path: the client's `notifications/cancelled` for a running
/// federated `tools/call` reaches the call over the cancellation bus, the
/// upstream hears of it under its own request id, and the client gets the
/// cancelled result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_cancel_ends_a_running_federated_tools_call() {
    let (url, held) = holding_upstream().await;
    let yaml = format!(
        r#"
gateway:
  server:
    trust_subject_header: true
mcp:
  federations:
    - name: slow
      governance: {{ minimum_trust: unauthenticated }}
      upstream:
        url: "{url}"
        upstream_safety: {{ allow_private_backends: true, allow_insecure_http: true }}
      naming: {{ tool_prefix: "slow." }}
"#
    );
    let config = crate::config::AppConfig::load_from_yaml_str(&yaml).expect("config parses");
    let state = crate::app::build_from_config(config, Vec::new())
        .await
        .expect("boots");
    crate::app::install_shared_services_in_process(&state);
    state.runtime.load_full().start_cluster_listeners();
    let app = crate::transports::http::router(state.clone(), "/health", "/mcp");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let client = reqwest::Client::new();
    // One caller across requests: a cancel names a request of its own
    // session.
    let request = |body: Value| {
        let mut builder = client
            .post(&endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header(
                "mcp-protocol-version",
                crate::protocol::SUPPORTED_PROTOCOL_VERSION,
            )
            .header("mcp-method", body["method"].as_str().unwrap_or_default())
            .header("x-mcpg-subject-id", "user-1");
        if let Some(name) = body["params"]["name"].as_str() {
            builder = builder.header("mcp-name", name);
        }
        builder.json(&body)
    };

    // The import runs off the boot path.
    let mut listed = false;
    for _ in 0..200 {
        let answer = request(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .send()
            .await
            .expect("tools/list");
        let tools = rpc_body(answer).await;
        if tools["result"]["tools"]
            .as_array()
            .is_some_and(|t| t.iter().any(|tool| tool["name"] == "slow.work"))
        {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(listed, "the federated tool was never listed");

    let call = tokio::spawn(
        request(json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "slow.work", "arguments": {} }
        }))
        .send(),
    );
    let upstream_id = eventually(|| held.calls.lock().unwrap().first().cloned()).await;
    let cancelled = request(json!({
        "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 7, "reason": "the user stopped it" }
    }))
    .send()
    .await
    .expect("notifications/cancelled");
    assert_eq!(cancelled.status(), StatusCode::ACCEPTED);

    let answer = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("the cancel ends the call while the upstream still holds it")
        .expect("the call task")
        .expect("the tools/call answer");
    let body = rpc_body(answer).await;
    assert_eq!(body["id"], 7, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(
        body["result"]["content"][0]["text"],
        "backend adapter 'federation' aborted: request cancelled while the call ran",
        "{body}"
    );
    let notice = eventually(|| held.cancels.lock().unwrap().first().cloned()).await;
    assert_eq!(notice["params"]["requestId"], upstream_id);
    state.runtime.load_full().stop_cluster_listeners().await;
}
