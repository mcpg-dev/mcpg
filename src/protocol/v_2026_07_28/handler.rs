//! [`ProtocolHandler`] implementation for MCP revision `2026-07-28`.
//!
//! Mirrors [`v_2025_11_25::handler::Handler`] in shape but with a
//! different method surface:
//!
//! - `parse()` calls the modern
//!   [`map_client_message_to_operation`](super::wire::routing::map_client_message_to_operation)
//!   which routes the modern method set (`server/discover`,
//!   modern `tools/*`, `prompts/*`, `resources/*` with cache
//!   shapes) and rejects legacy methods.
//! - `validate_transport_headers()` enforces the SEP-2243 header
//!   contract: `Mcp-Method` is required and must equal the body
//!   method; `Mcp-Name` is required (and body-validated) for
//!   `tools/call` / `prompts/get` / `resources/read`; recognized
//!   `Mcp-Param-{Name}` headers are body-validated. Header values use
//!   the `=?base64?…?=` sentinel for non-ASCII. The
//!   [`wire::promote_param_headers`](super::wire::promote_param_headers)
//!   helper performs the server-side
//!   param→header promotion (with constraint-validated
//!   exclude-on-violation) for relays to header-routing
//!   intermediaries.
//! - `dispatch()` handles `server/discover` natively and routes the
//!   capability methods through the existing pipeline / backend
//!   machinery, applying the modern result shapes (cache fields,
//!   modern `ToolCallResult`, etc.).
//! - `build_suspension_response()` (a `ProtocolHandler` trait method)
//!   is unused by this wire: modern suspension is emitted inline as
//!   MRTR's `InputRequiredResult` body from the runtime tools/call
//!   tail, not through the legacy SSE delivery-bus envelope.
//!
//! The handler is registered with the runtime [`ProtocolRegistry`]
//! so the modern wire is selectable.

use async_trait::async_trait;
use axum::http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::error::{HEADER_MISMATCH_CODE, ProtocolError};
use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse, parse_client_message,
};
use crate::protocol::shared::messages::{ProtocolMessage, TransportRejection};
use crate::protocol::shared::traits::ProtocolHandler;
use crate::protocol::v_2026_07_28::dispatch::completion::dispatch_completion_complete;
use crate::protocol::v_2026_07_28::dispatch::lifecycle::build_discover_result;
use crate::protocol::v_2026_07_28::dispatch::prompts::{
    dispatch_prompts_get, dispatch_prompts_list,
};
use crate::protocol::v_2026_07_28::dispatch::resources::{
    dispatch_resources_list, dispatch_resources_read, dispatch_resources_templates_list,
};
use crate::protocol::v_2026_07_28::dispatch::support::handler_internal_error;
use crate::protocol::v_2026_07_28::dispatch::tasks::dispatch_tasks_extension;
use crate::protocol::v_2026_07_28::dispatch::tools::{dispatch_tools_call, dispatch_tools_list};
use crate::protocol::v_2026_07_28::wire::operations::{
    CapabilityOperation, LifecycleOperation, ProtocolOperation,
};
use crate::protocol::v_2026_07_28::wire::request_meta::{
    missing_meta_rejection, missing_request_meta_key,
};
use crate::protocol::v_2026_07_28::wire::routing::map_client_message_to_operation;
use crate::protocol::v_2026_07_28::wire::{
    METHOD_HEADER, PROTOCOL_VERSION_HEADER, SUPPORTED_PROTOCOL_VERSION, header_mismatch,
    name_source_field, validate_name_header, validate_param_headers,
};
use crate::protocol::version::ProtocolVersion;
use crate::runtime::RequestContext;
use crate::runtime::shared_services::SharedServices;

/// Per-version handler for MCP revision `2026-07-28`.
///
/// Stateless: zero-sized, every service handed in via
/// [`SharedServices`] at dispatch time.
#[derive(Debug, Clone, Default)]
pub struct Handler;

impl Handler {
    /// Construct the handler. The single instance is registered into
    /// the [`ProtocolRegistry`](crate::protocol::registry::ProtocolRegistry)
    /// at boot.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for Handler {
    fn version_string(&self) -> &'static str {
        SUPPORTED_PROTOCOL_VERSION
    }

    fn version(&self) -> ProtocolVersion {
        ProtocolVersion::V_2026_07_28
    }

    /// SEP-2243 mirrors selected body fields into HTTP routing headers
    /// so intermediaries can route without parsing the body, and makes
    /// the server validate the mirror against the body:
    ///
    /// - `Mcp-Method` is REQUIRED on every modern request and MUST
    ///   equal the body `method`.
    /// - `Mcp-Name` is REQUIRED for `tools/call` / `prompts/get`
    ///   (mirrors `params.name`) and `resources/read` (mirrors
    ///   `params.uri`), and MUST equal the body value after sentinel
    ///   decode.
    /// - Any recognized `Mcp-Param-{Name}` header MUST equal the body
    ///   value at `params.arguments.{name}` after sentinel decode.
    ///
    /// Any mismatch / missing-required / malformed header is rejected
    /// with HTTP 400 + the MCP-reserved `HeaderMismatch` code
    /// (`-32020`). Header rules apply only to JSON-RPC *requests*
    /// (id-bearing bodies); the revision leaves notification header
    /// rules undefined.
    fn validate_transport_headers(
        &self,
        headers: &HeaderMap,
        body: &Value,
    ) -> Result<(), TransportRejection> {
        let body_method = body
            .as_object()
            .and_then(|obj| obj.get("method"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let body_id = body.as_object().and_then(|obj| obj.get("id")).cloned();

        // SEP-2575 — the modern stateless wire removes a fixed set
        // of methods that lived on the legacy session-bound wire.
        // The spec says HTTP 404 + JSON-RPC `-32601` for these,
        // not the default HTTP 200 + JSON-RPC error that
        // `method_not_found` falls through to. Documented at
        // `wire/routing.rs:20-24`.
        if is_removed_modern_method(body_method) {
            return Err(TransportRejection {
                status: 404,
                error_code: -32601,
                message: format!(
                    "Method `{body_method}` is removed on the modern wire \
                     (2026-07-28) per SEP-2575. Legacy \
                     callers should pin `Mcp-Protocol-Version: 2025-11-25` \
                     to reach this method."
                ),
                data: None,
                jsonrpc_id: body_id,
            });
        }

        // SEP-2575 stateless `_meta` shape. `server/discover`
        // requests MUST carry
        // `params._meta.io.modelcontextprotocol/{protocolVersion,
        // clientInfo, clientCapabilities}` so the server can
        // negotiate without a prior `initialize` handshake. Other
        // methods don't carry this strict requirement (clients
        // routinely call `tools/list` etc. with minimal params).
        if body_id.is_some()
            && body_method == "server/discover"
            && let Some(missing) = missing_request_meta_key(body)
        {
            return Err(missing_meta_rejection(missing, body_id.clone()));
        }

        // SEP-2575 header / body protocol-version cross-check. When
        // both the `Mcp-Protocol-Version` HTTP header AND the body's
        // `params._meta.io.modelcontextprotocol/protocolVersion` are
        // present, they MUST agree. Mismatch = HTTP 400 carrying the
        // dedicated `-32020` "HeaderMismatch" JSON-RPC error (the
        // MCP-reserved-band code adopted in `2026-07-28`).
        // (Either one absent is acceptable — the registry has its
        // own legacy fall-through logic for absent / unknown values.)
        if let (Some(header_version), Some(body_version)) = (
            headers
                .get(PROTOCOL_VERSION_HEADER)
                .and_then(|v| v.to_str().ok()),
            body.as_object()
                .and_then(|obj| obj.get("params"))
                .and_then(|p| p.get("_meta"))
                .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
                .and_then(Value::as_str),
        ) && header_version != body_version
        {
            return Err(TransportRejection {
                status: 400,
                error_code: HEADER_MISMATCH_CODE,
                message: format!(
                    "Mcp-Protocol-Version header (`{header_version}`) disagrees \
                     with body `_meta.io.modelcontextprotocol/protocolVersion` \
                     (`{body_version}`); SEP-2575 requires the two to agree."
                ),
                data: None,
                jsonrpc_id: body_id.clone(),
            });
        }

        // SEP-2243 `Mcp-Method` is REQUIRED on every modern request
        // and MUST equal the body `method`. A request carrying a body
        // `id` is a JSON-RPC *request* (notification header rules are
        // left undefined by the revision, so id-less bodies are not
        // subject to the header contract).
        let is_request = body_id.is_some();
        let header_method = headers.get(METHOD_HEADER).and_then(|v| v.to_str().ok());
        match header_method {
            None if is_request => {
                return Err(header_mismatch(
                    "SEP-2243 requires the `Mcp-Method` header on modern requests; \
                     it is absent",
                    body_id.clone(),
                ));
            }
            Some(header_method) if header_method != body_method => {
                return Err(header_mismatch(
                    &format!(
                        "Mcp-Method header (`{header_method}`) does not match body \
                         method (`{body_method}`); SEP-2243 requires the two to agree"
                    ),
                    body_id.clone(),
                ));
            }
            _ => {}
        }

        if is_request {
            // SEP-2243 `Mcp-Name` is REQUIRED for `tools/call`,
            // `resources/read`, and `prompts/get`; its source value is
            // `params.name` for the two name-bearing methods and
            // `params.uri` for `resources/read`. The header value may
            // be `=?base64?…?=`-wrapped and is decoded before
            // comparison.
            if let Some(source_field) = name_source_field(body_method) {
                validate_name_header(headers, body, source_field, body_id.clone())?;
            }

            // SEP-2243 `x-mcp-header` param→header promotion. Any
            // recognized `Mcp-Param-{Name}` header MUST, after sentinel
            // decode, match the value carried at the corresponding
            // `params.arguments.{name}` position in the body. The
            // gateway routes/executes on the body, so a header that
            // disagrees with the body is a routing-vs-execution split.
            validate_param_headers(headers, body, body_id.clone())?;
        }
        Ok(())
    }

    /// Parse a JSON body into a [`ProtocolMessage`] carrying the
    /// modern [`ProtocolOperation`].
    fn parse(&self, body: Value) -> Result<ProtocolMessage, ProtocolError> {
        let mcp_method = body
            .as_object()
            .and_then(|obj| obj.get("method"))
            .and_then(Value::as_str)
            .map(str::to_owned);

        let message = parse_client_message(body)?;
        let operation = map_client_message_to_operation(message)?;
        let label = operation.label();
        let jsonrpc_id = operation.client_request_id();

        Ok(ProtocolMessage {
            label,
            inner: Box::new(operation),
            jsonrpc_id,
            mcp_method,
            negotiated_version: ProtocolVersion::V_2026_07_28,
        })
    }

    /// Dispatch a parsed modern operation.
    ///
    /// `server/discover` is handled natively in this file (builds
    /// the `DiscoverResult` from server identity + the static
    /// capability advertisement). Capability operations (tools,
    /// prompts, resources, completion) route through the modern
    /// dispatch arms. Notifications return the standard
    /// `NotificationAccepted` envelope.
    async fn dispatch(
        &self,
        ctx: &RequestContext,
        op: ProtocolMessage,
        services: &SharedServices,
    ) -> ProtocolHttpResponse {
        let jsonrpc_id = op.jsonrpc_id.clone();
        let operation = match op.downcast::<ProtocolOperation>() {
            Ok(operation) => *operation,
            Err(_) => {
                tracing::error!(
                    "v_2026_07_28::Handler::dispatch received a ProtocolMessage \
                     whose inner type is not v_2026_07_28::ProtocolOperation — \
                     registry routing bug"
                );
                return handler_internal_error(
                    jsonrpc_id,
                    "internal handler routing error: wrong operation type for v_2026_07_28",
                );
            }
        };

        match operation {
            ProtocolOperation::Lifecycle(LifecycleOperation::Discover { request_id, .. }) => {
                let result = build_discover_result(services);
                let result_value = match serde_json::to_value(&result) {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::error!(error = %error, "failed to serialize DiscoverResult");
                        return handler_internal_error(
                            Some(request_id),
                            "failed to serialize server/discover result",
                        );
                    }
                };
                ProtocolHttpResponse {
                    http_status: 200,
                    session_id_header: None,
                    response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id: request_id,
                        result: result_value,
                    }),
                }
            }
            ProtocolOperation::Lifecycle(LifecycleOperation::NotificationCancelled {
                request_id: cancelled_request_id,
                reason,
            }) => {
                // Route the modern `notifications/cancelled` into the
                // same principal-partitioned, cross-instance
                // cancellation machinery the legacy wire uses
                // (`GatewayRuntime::handle_request_cancellation`):
                // bus broadcast → `cancel_suspended_pipeline` on every
                // replica, plus the audit + metric records. Without a
                // runtime handle (shutdown) the cancel is dropped but
                // still acknowledged 202 — `notifications/cancelled`
                // carries no response.
                if let Some(runtime_handle) = services.runtime() {
                    let runtime = runtime_handle.load();
                    runtime
                        .handle_request_cancellation(ctx, &cancelled_request_id, reason.as_deref())
                        .await;
                }
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            ProtocolOperation::Lifecycle(LifecycleOperation::NotificationAccepted) => {
                ProtocolHttpResponse {
                    http_status: 202,
                    session_id_header: None,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ToolsList {
                request_id,
                params,
            }) => dispatch_tools_list(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::ToolsCall {
                request_id,
                params,
            }) => dispatch_tools_call(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::PromptsList {
                request_id,
                params,
            }) => dispatch_prompts_list(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::PromptsGet {
                request_id,
                params,
            }) => dispatch_prompts_get(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesList {
                request_id,
                params,
            }) => dispatch_resources_list(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesRead {
                request_id,
                params,
            }) => dispatch_resources_read(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesTemplatesList {
                request_id,
                params,
            }) => dispatch_resources_templates_list(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::Complete {
                request_id,
                params,
            }) => dispatch_completion_complete(ctx, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::SubscriptionsListen {
                request_id,
                ..
            }) => {
                // Defensive: `subscriptions/listen` is a long-lived
                // POST-SSE response that the transport intercepts
                // BEFORE calling `Handler::dispatch`. If we land
                // here, the transport's branch is missing.
                tracing::error!(
                    request_id = ctx.request_id.as_str(),
                    "v_2026_07_28::Handler::dispatch reached for subscriptions/listen — \
                     the transport's POST-SSE branch should have intercepted; \
                     this is a routing bug"
                );
                handler_internal_error(
                    Some(request_id),
                    "subscriptions/listen must be handled by the transport's \
                     POST-SSE branch, not the finite-response handler dispatch",
                )
            }
            ProtocolOperation::TasksExtension(op) => {
                dispatch_tasks_extension(ctx, services, op).await
            }
        }
    }
}

/// JSON-RPC method names the legacy `2025-11-25` wire accepts but the modern
/// `2026-07-28` revision removes.
///
/// SEP-2575 mandates HTTP 404 + JSON-RPC `-32601` for these on the stateless
/// wire; the parser's default `method_not_found` fallback returns HTTP 200,
/// which the conformance suite flags.
///
/// The inverse of the modern router's method table in
/// [`crate::protocol::v_2026_07_28::wire::routing`] — a method added there must
/// not appear here.
fn is_removed_modern_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "ping"
            | "logging/setLevel"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "tasks/result"
            | "tasks/list"
    )
}

// ── Dispatch arms ─────────────────────────────────────────────────────

// ── SEP-2663 tasks-extension dispatch ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::shared::error::{
        INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
    };
    use crate::protocol::shared::jsonrpc::{JsonRpcError, JsonRpcErrorBody};
    use crate::protocol::v_2026_07_28::dispatch::mrtr::resume_did_not_commit;
    use crate::protocol::v_2026_07_28::dispatch::prompts::{
        legacy_prompt_arg_to_modern, legacy_prompt_to_modern,
    };
    use crate::protocol::v_2026_07_28::dispatch::resources::legacy_resource_to_modern;
    use crate::protocol::v_2026_07_28::dispatch::support::map_request_state_decode_error;
    use crate::protocol::v_2026_07_28::dispatch::tasks::fold_resume_outcome_onto_task;
    use crate::protocol::v_2026_07_28::wire::NAME_HEADER;
    use crate::runtime::shared_services::SharedServices;
    use std::sync::Arc;

    fn error_response(code: i32) -> ProtocolHttpResponse {
        ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcError(JsonRpcError {
                jsonrpc: JSONRPC_VERSION,
                id: None,
                error: JsonRpcErrorBody {
                    code,
                    message: "x".to_owned(),
                    data: None,
                },
            }),
        }
    }

    #[test]
    fn resume_did_not_commit_for_retry_safe_errors() {
        // SR-7: on these the resume advanced nothing, so the inline
        // requestState blob must stay un-spent for a legitimate retry.
        for code in [-32600, -32001, -32603] {
            assert!(
                resume_did_not_commit(&error_response(code)),
                "code {code} must be treated as retry-safe (blob not spent)"
            );
        }
    }

    #[test]
    fn resume_committed_for_success_and_other_outcomes() {
        // Success → the resume committed; the blob is spent.
        let success = ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: Value::Null,
                result: Value::Null,
            }),
        };
        assert!(!resume_did_not_commit(&success));

        // A 202 (claim lost to a peer / re-suspension ack) is NOT retry-safe:
        // the pipeline already advanced on some replica, so spend the blob.
        let accepted = ProtocolHttpResponse {
            http_status: 202,
            session_id_header: None,
            response: ProtocolResponse::NotificationAccepted,
        };
        assert!(!resume_did_not_commit(&accepted));

        // An unrelated application error code is not in the retry-safe set.
        assert!(!resume_did_not_commit(&error_response(-32000)));
    }

    #[test]
    fn request_state_decode_error_classification() {
        use crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateError as E;

        // A KV read fault is the only genuinely gateway-internal case.
        let store = map_request_state_decode_error(None, &E::Store("kv down".to_owned()));
        assert_eq!(store.http_status, 500);
        assert!(matches!(
            store.response,
            ProtocolResponse::JsonRpcError(JsonRpcError { error, .. })
                if error.code == INTERNAL_ERROR_CODE
        ));

        // A malformed / tampered / foreign-owned blob is the caller's:
        // -32602 invalid params at HTTP 400, never a 500.
        for bad in [
            E::InvalidPrefix("z.".to_owned()),
            E::InvalidPayload("base64".to_owned()),
            E::AuthenticationFailed,
        ] {
            let resp = map_request_state_decode_error(None, &bad);
            assert_eq!(resp.http_status, 400, "{bad:?} must map to HTTP 400");
            assert!(matches!(
                resp.response,
                ProtocolResponse::JsonRpcError(JsonRpcError { error, .. })
                    if error.code == INVALID_PARAMS_CODE
            ));
        }

        // A blob whose server-side state is gone / already spent is a stale
        // request: -32600 at HTTP 200 (retry-safe, matching the code the
        // resume path treats as "committed nothing").
        for gone in [E::HandleNotFound("h".to_owned()), E::Replayed] {
            let resp = map_request_state_decode_error(None, &gone);
            assert_eq!(resp.http_status, 200, "{gone:?} must map to HTTP 200");
            assert!(matches!(
                resp.response,
                ProtocolResponse::JsonRpcError(JsonRpcError { error, .. })
                    if error.code == INVALID_REQUEST_CODE
            ));
        }
    }

    #[test]
    fn fold_keeps_task_resumable_on_retryable_resume_error() {
        use crate::runtime::task_store::{KvBackedTaskStore, TaskStore};

        let store = KvBackedTaskStore::new_in_memory_default();
        let session = "sess-A";
        let record = store
            .create_task(session, Value::from(1), "some_tool", None)
            .expect("create task");
        let task_id = record.task.task_id.clone();
        store
            .set_task_awaiting_input(
                &task_id,
                session,
                "c.blob".to_owned(),
                serde_json::json!({}),
            )
            .expect("await input");

        // A retryable resume error (`resume_did_not_commit`) must NOT latch a
        // terminal Failed — the blob stays claimable, so the task must stay
        // resumable.
        for retryable in [-32600, -32001, -32603] {
            fold_resume_outcome_onto_task(&store, &task_id, session, &error_response(retryable));
            let after = store.get_task(&task_id, session).expect("get task");
            assert_eq!(
                after.task.status,
                crate::protocol::TaskStatus::InputRequired,
                "code {retryable} must leave the task input_required"
            );
            assert_eq!(after.request_state.as_deref(), Some("c.blob"));
        }

        // A genuine (non-retryable) resume error latches terminal Failed.
        fold_resume_outcome_onto_task(&store, &task_id, session, &error_response(-32000));
        let failed = store.get_task(&task_id, session).expect("get task");
        assert_eq!(failed.task.status, crate::protocol::TaskStatus::Failed);
    }

    /// Compile-time guard pinning every modern well-known wire
    /// string to its spec value; accidental drift fails this test
    /// at the constant-equality assertion. Cross-references the
    /// originating SEP for each block.
    #[test]
    fn modern_wire_well_known_strings_match_spec() {
        use crate::protocol::v_2026_07_28::extensions::tasks::wire as tasks_ext;
        use crate::protocol::v_2026_07_28::wire as modern;

        // ── Negotiated version (default until the spec ships
        //    final on 2026-07-28).
        assert_eq!(modern::SUPPORTED_PROTOCOL_VERSION, "2026-07-28");

        // ── SEP-2243 transport-header routing.
        assert_eq!(modern::PROTOCOL_VERSION_HEADER, "mcp-protocol-version");
        assert_eq!(modern::METHOD_HEADER, "mcp-method");
        assert_eq!(modern::NAME_HEADER, "mcp-name");
        assert_eq!(modern::PARAM_HEADER_PREFIX, "mcp-param-");

        // ── Core method strings.
        assert_eq!(modern::lifecycle::METHOD_SERVER_DISCOVER, "server/discover");
        assert_eq!(modern::tools::METHOD_TOOLS_LIST, "tools/list");
        assert_eq!(modern::tools::METHOD_TOOLS_CALL, "tools/call");
        assert_eq!(modern::prompts::METHOD_PROMPTS_LIST, "prompts/list");
        assert_eq!(modern::prompts::METHOD_PROMPTS_GET, "prompts/get");
        assert_eq!(modern::resources::METHOD_RESOURCES_LIST, "resources/list");
        assert_eq!(modern::resources::METHOD_RESOURCES_READ, "resources/read");
        assert_eq!(
            modern::resources::METHOD_RESOURCES_TEMPLATES_LIST,
            "resources/templates/list"
        );
        assert_eq!(
            modern::completion::METHOD_COMPLETION_COMPLETE,
            "completion/complete"
        );
        assert_eq!(
            modern::subscriptions::METHOD_SUBSCRIPTIONS_LISTEN,
            "subscriptions/listen"
        );

        // ── SEP-2322 MRTR.
        assert_eq!(
            modern::mrtr::META_KEY_REQUEST_STATE,
            "io.modelcontextprotocol/requestState"
        );
        assert_eq!(
            modern::mrtr::META_KEY_INPUT_RESPONSES,
            "io.modelcontextprotocol/inputResponses"
        );
        assert_eq!(modern::mrtr::RESULT_TYPE_INPUT_REQUIRED, "input_required");

        // ── SEP-2549 cache discriminator strings live as serde
        //    rename targets on `CacheScope`; verify the round-trip
        //    matches each tagged string.
        // SEP-2549 mandates the two-value enum `public` / `private`.
        // MCPG's old richer taxonomy (`global` / `client` / `tenant` /
        // `none`) was collapsed at the wire boundary.
        for (scope, expected) in [
            (modern::tools::CacheScope::Public, "public"),
            (modern::tools::CacheScope::Private, "private"),
        ] {
            assert_eq!(serde_json::to_value(scope).unwrap(), expected);
        }

        // ── SEP-2243 + 2575 per-request `_meta` namespace keys.
        assert_eq!(modern::meta::META_NAMESPACE, "io.modelcontextprotocol");
        assert_eq!(
            modern::meta::META_KEY_TRACEPARENT,
            "io.modelcontextprotocol/traceparent"
        );
        assert_eq!(
            modern::meta::META_KEY_PROGRESS_TOKEN,
            "io.modelcontextprotocol/progressToken"
        );
        assert_eq!(
            modern::meta::META_KEY_LOG_LEVEL,
            "io.modelcontextprotocol/logLevel"
        );
        assert_eq!(
            modern::meta::META_KEY_CACHE_TOKEN,
            "io.modelcontextprotocol/cacheToken"
        );
        assert_eq!(
            modern::meta::META_KEY_IDEMPOTENCY,
            "io.modelcontextprotocol/idempotencyKey"
        );
        assert_eq!(
            modern::meta::META_KEY_PRESERVE_CONTEXT,
            "io.modelcontextprotocol/preserveContext"
        );

        // ── SEP-2575 subscriptions.
        assert_eq!(
            modern::subscriptions::META_KEY_SUBSCRIPTION_ID,
            "io.modelcontextprotocol/subscriptionId"
        );

        // ── SEP-2663 tasks extension (bare methods).
        assert_eq!(
            tasks_ext::EXTENSION_NAMESPACE,
            "io.modelcontextprotocol/tasks"
        );
        assert_eq!(tasks_ext::METHOD_GET_TASK, "tasks/get");
        assert_eq!(tasks_ext::METHOD_UPDATE_TASK, "tasks/update");
        assert_eq!(tasks_ext::METHOD_CANCEL_TASK, "tasks/cancel");
        assert_eq!(tasks_ext::METHOD_NOTIFICATIONS_TASKS, "notifications/tasks");
        assert_eq!(tasks_ext::RESULT_TYPE_TASK, "task");

        // ── SEP-2663 resultType discriminator vocabulary.
        assert_eq!(modern::tools::RESULT_TYPE_COMPLETE, "complete");
        assert_eq!(modern::tools::RESULT_TYPE_INPUT_REQUIRED, "input_required");
        assert_eq!(modern::tools::RESULT_TYPE_TASK, "task");
    }

    #[test]
    fn handler_version_identity() {
        let h = Handler::new();
        assert_eq!(h.version_string(), "2026-07-28");
        assert_eq!(h.version(), ProtocolVersion::V_2026_07_28);
    }

    /// Minimal SEP-2575 `_meta` block that satisfies the
    /// `server/discover` validator. Tests for *other* validators
    /// reuse this so they don't get rejected on the wrong axis.
    fn well_formed_discover_meta() -> serde_json::Value {
        serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "test-client",
                "version": "0.0.0",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    #[test]
    fn validate_transport_headers_rejects_when_mcp_method_absent() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": well_formed_discover_meta() },
        });
        let err = h
            .validate_transport_headers(&HeaderMap::new(), &body)
            .unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(
            err.error_code, -32020,
            "SEP-2243 makes Mcp-Method REQUIRED on the modern wire"
        );
        assert!(err.message.contains("Mcp-Method"));
    }

    #[test]
    fn validate_transport_headers_ok_when_mcp_method_absent_on_notification() {
        // Notification (no `id`) is outside the SEP-2243 header
        // contract — header rules apply only to requests.
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {},
        });
        assert!(
            h.validate_transport_headers(&HeaderMap::new(), &body)
                .is_ok()
        );
    }

    #[test]
    fn validate_transport_headers_ok_when_mcp_method_matches_body() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "server/discover".parse().unwrap());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": well_formed_discover_meta() },
        });
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    #[test]
    fn validate_transport_headers_rejects_mismatch_with_400() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/list".parse().unwrap());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": well_formed_discover_meta() },
        });
        let err = h.validate_transport_headers(&headers, &body).unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.error_code, -32020);
        assert!(
            err.message.contains("Mcp-Method"),
            "diagnostic should mention the header"
        );
        assert_eq!(err.jsonrpc_id, Some(serde_json::json!(1)));
    }

    fn tools_call_body(name: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": { "region": "us-west1" },
                "_meta": well_formed_discover_meta(),
            },
        })
    }

    #[test]
    fn validate_name_header_ok_when_matches_body() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/call".parse().unwrap());
        headers.insert(NAME_HEADER, "get_weather".parse().unwrap());
        let body = tools_call_body("get_weather");
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    #[test]
    fn validate_name_header_required_for_resources_read() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "resources/read".parse().unwrap());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/hosts",
                "_meta": well_formed_discover_meta(),
            },
        });
        let err = h.validate_transport_headers(&headers, &body).unwrap_err();
        assert_eq!(err.error_code, -32020);
        assert!(err.message.contains("Mcp-Name"));
    }

    #[test]
    fn validate_name_header_matches_resources_read_uri() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "resources/read".parse().unwrap());
        headers.insert(NAME_HEADER, "file:///etc/hosts".parse().unwrap());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/hosts",
                "_meta": well_formed_discover_meta(),
            },
        });
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    #[test]
    fn validate_name_header_decodes_encoded_word() {
        // "Hello, 世界" carried as the base64 sentinel must decode and
        // compare equal to the body `params.name`.
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/call".parse().unwrap());
        headers.insert(
            NAME_HEADER,
            "=?base64?SGVsbG8sIOS4lueVjA==?=".parse().unwrap(),
        );
        let body = tools_call_body("Hello, 世界");
        assert!(
            h.validate_transport_headers(&headers, &body).is_ok(),
            "encoded-word Mcp-Name must decode before comparison"
        );
    }

    #[test]
    fn validate_name_header_rejects_mismatch() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/call".parse().unwrap());
        headers.insert(NAME_HEADER, "wrong_tool".parse().unwrap());
        let body = tools_call_body("get_weather");
        let err = h.validate_transport_headers(&headers, &body).unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.error_code, -32020);
        assert!(err.message.contains("Mcp-Name"));
    }

    #[test]
    fn validate_param_header_ok_when_matches_body() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/call".parse().unwrap());
        headers.insert(NAME_HEADER, "execute_sql".parse().unwrap());
        headers.insert("mcp-param-region", "us-west1".parse().unwrap());
        let body = tools_call_body("execute_sql");
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    #[test]
    fn validate_param_header_rejects_mismatch() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/call".parse().unwrap());
        headers.insert(NAME_HEADER, "execute_sql".parse().unwrap());
        headers.insert("mcp-param-region", "eu-west1".parse().unwrap());
        let body = tools_call_body("execute_sql");
        let err = h.validate_transport_headers(&headers, &body).unwrap_err();
        assert_eq!(err.error_code, -32020);
        assert!(err.message.contains("Mcp-Param-region"));
    }

    #[test]
    fn parse_routes_discover_into_protocol_message() {
        let h = Handler::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "protocolVersion": "2026-07-28",
                "clientInfo": { "name": "t", "version": "0" }
            }
        });
        let msg = h.parse(body).expect("parse ok");
        assert_eq!(msg.label, "lifecycle.discover");
        assert_eq!(msg.jsonrpc_id, Some(serde_json::json!(1)));
        assert_eq!(msg.mcp_method.as_deref(), Some("server/discover"));
        assert_eq!(msg.negotiated_version, ProtocolVersion::V_2026_07_28);
        let Ok(op) = msg.downcast::<ProtocolOperation>() else {
            panic!("inner should be v_2026_07_28::ProtocolOperation");
        };
        assert!(matches!(
            *op,
            ProtocolOperation::Lifecycle(LifecycleOperation::Discover { .. })
        ));
    }

    #[test]
    fn parse_rejects_legacy_initialize_method() {
        let h = Handler::new();
        // `initialize` is legacy-only; the modern routing function
        // refuses it with -32601.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let Err(err) = h.parse(body) else {
            panic!("legacy `initialize` must not parse under the modern handler");
        };
        assert_eq!(err.code(), -32601);
    }

    #[tokio::test]
    async fn dispatch_discover_returns_serialized_capability_envelope() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        // discover is capability-gated. The test parses an operator
        // YAML carrying one tool / one prompt / one resource so the
        // envelope exercises the full surface. Using the YAML loader
        // keeps us insulated from BackendConfig's many required fields.
        let cfg: crate::config::AppConfig = serde_yaml::from_str(
            r#"
mcp:
  capabilities:
    tools:
      - name: test_tool
        description: Mock tool
        input_schema: { type: object }
        task_support: optional
        backend:
          kind: mock
          response: null
    prompts:
      - name: test_prompt
        description: Mock prompt
        backend:
          kind: mock
          response: {}
    resources:
      - name: test_resource
        description: Mock resource
        uri: "test://resource"
        backend:
          kind: mock
          response: {}
"#,
        )
        .expect("test AppConfig YAML parses");
        let services = SharedServices::with_no_runtime(Arc::new(cfg));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "clientInfo": { "name": "t", "version": "0" }
                }
            }))
            .expect("parse ok");

        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 200);
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                assert_eq!(success.id, serde_json::json!(1));
                // CacheableResult envelope; the singular
                // `protocolVersion` was dropped (VN-5).
                assert!(success.result.get("protocolVersion").is_none());
                assert_eq!(success.result["resultType"], "complete");
                assert!(success.result["ttlMs"].is_u64());
                assert_eq!(success.result["cacheScope"], "public");
                assert!(success.result["supportedVersions"].is_array());
                assert_eq!(success.result["serverInfo"]["name"], "mcpg");
                // Capability advertisement reflects the
                // configured bindings — tools/prompts/resources all
                // present with listChanged + cache flags.
                assert_eq!(success.result["capabilities"]["tools"]["listChanged"], true);
                assert!(success.result["capabilities"]["tools"]["cache"].is_object());
                assert!(success.result["capabilities"]["prompts"]["cache"].is_object());
                assert!(success.result["capabilities"]["resources"]["cache"].is_object());
                // completion intentionally absent: the method is
                // wired, but the dispatch's discover envelope
                // doesn't advertise it as a server capability —
                // operators with completion-backing tools see them
                // via `tools/list` instead.
                assert!(success.result["capabilities"].get("completion").is_none());
                // tasks extension advertised — keys are reverse-DNS.
                let ext = success.result["capabilities"]["extensions"]
                    .as_object()
                    .expect("extensions map");
                assert!(ext.contains_key("io.modelcontextprotocol/tasks"));
                let methods = ext["io.modelcontextprotocol/tasks"]["methods"]
                    .as_array()
                    .expect("methods array");
                // SEP-2663 final: three bare methods (get/update/cancel);
                // `createTask` was removed.
                assert_eq!(methods.len(), 3);
                let method_strs: Vec<&str> = methods.iter().filter_map(Value::as_str).collect();
                assert!(method_strs.contains(&"tasks/get"));
                assert!(method_strs.contains(&"tasks/update"));
                assert!(method_strs.contains(&"tasks/cancel"));
            }
            other => panic!("expected JsonRpcSuccess for server/discover, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_discover_advertises_apps_when_enabled() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let cfg: crate::config::AppConfig = serde_yaml::from_str(
            r#"
mcp:
  capabilities:
    resources:
      - name: chart_ui
        description: A UI resource
        uri: "ui://srv/chart"
        backend:
          kind: mock
          response: {}
  configurations:
    apps:
      enabled: true
"#,
        )
        .expect("test AppConfig YAML parses");
        let services = SharedServices::with_no_runtime(Arc::new(cfg));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "clientInfo": { "name": "t", "version": "0" }
                }
            }))
            .expect("parse ok");

        let response = h.dispatch(&ctx, msg, &services).await;
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let ext = success.result["capabilities"]["extensions"]
                    .as_object()
                    .expect("extensions map");
                let ui = ext
                    .get("io.modelcontextprotocol/ui")
                    .expect("apps extension advertised when enabled");
                assert_eq!(
                    ui["mimeTypes"],
                    serde_json::json!(["text/html;profile=mcp-app"])
                );
            }
            other => panic!("expected JsonRpcSuccess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_discover_omits_apps_when_disabled() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        // No `configurations.apps` block ⇒ default disabled.
        let cfg: crate::config::AppConfig = serde_yaml::from_str(
            r#"
mcp:
  capabilities:
    resources:
      - name: r
        description: r
        uri: "test://r"
        backend: { kind: mock, response: {} }
"#,
        )
        .expect("test AppConfig YAML parses");
        let services = SharedServices::with_no_runtime(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let extensions = &success.result["capabilities"]["extensions"];
                if let Some(ext) = extensions.as_object() {
                    assert!(!ext.contains_key("io.modelcontextprotocol/ui"));
                }
            }
            other => panic!("expected JsonRpcSuccess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_discover_advertises_completions_plural_key_when_configured() {
        // PR-02: a prompt argument with static completions makes the
        // gateway advertise the `completions` capability under the
        // PLURAL wire key.
        let h = Handler::new();
        let ctx = make_test_request_context();
        let cfg: crate::config::AppConfig = serde_yaml::from_str(
            r#"
mcp:
  capabilities:
    prompts:
      - name: greet
        description: A greeting prompt
        prompt_arguments:
          - name: lang
            completions: ["en", "fr"]
        backend: { kind: mock, response: {} }
"#,
        )
        .expect("test AppConfig YAML parses");
        let services = SharedServices::with_no_runtime(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let caps = &success.result["capabilities"];
                assert!(
                    caps["completions"].is_object(),
                    "completions advertised under plural key, got: {caps}"
                );
                assert!(caps.get("completion").is_none(), "no singular key");
            }
            other => panic!("expected JsonRpcSuccess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_discover_omits_completions_when_none_configured() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let cfg: crate::config::AppConfig = serde_yaml::from_str(
            r#"
mcp:
  capabilities:
    prompts:
      - name: greet
        description: A greeting prompt
        backend: { kind: mock, response: {} }
"#,
        )
        .expect("test AppConfig YAML parses");
        let services = SharedServices::with_no_runtime(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let caps = &success.result["capabilities"];
                assert!(caps.get("completions").is_none());
                assert!(caps.get("completion").is_none());
            }
            other => panic!("expected JsonRpcSuccess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_resources_list_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "resources/list"
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[tokio::test]
    async fn dispatch_resources_read_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "resources/read",
                "params": { "uri": "x://y" }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[tokio::test]
    async fn dispatch_resources_templates_list_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 33,
                "method": "resources/templates/list"
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[tokio::test]
    async fn dispatch_completion_complete_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "completion/complete",
                "params": {
                    "ref": { "type": "ref/prompt", "name": "x" },
                    "argument": { "name": "a", "value": "" }
                }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[test]
    fn legacy_resource_to_modern_carries_annotations() {
        // RES-08: annotations are carried through to the modern wire,
        // not dropped.
        let backend = crate::backends::ResourceDescriptor {
            uri: "u".to_owned(),
            name: "n".to_owned(),
            title: None,
            description: None,
            mime_type: Some("text/plain".to_owned()),
            size: Some(100),
            icons: None,
            annotations: Some(crate::protocol::ContentAnnotations {
                audience: Some(vec!["user".to_owned()]),
                priority: Some(0.5),
                last_modified: None,
            }),
            meta: None,
        };
        let modern = legacy_resource_to_modern(&backend);
        assert_eq!(modern.uri, "u");
        assert_eq!(modern.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(modern.size, Some(100));
        let ann = modern.annotations.as_ref().expect("annotations carried");
        assert_eq!(ann.priority, Some(0.5));
        assert_eq!(ann.audience.as_deref(), Some(&["user".to_owned()][..]));
        assert!(modern.cache_scope.is_none());
    }

    #[tokio::test]
    async fn dispatch_prompts_list_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "prompts/list"
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[tokio::test]
    async fn dispatch_prompts_get_returns_500_when_runtime_unavailable() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 22,
                "method": "prompts/get",
                "params": { "name": "x" }
            }))
            .expect("parse ok");
        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
    }

    #[test]
    fn legacy_prompt_to_modern_with_empty_arguments_omits_field() {
        let backend = crate::backends::PromptDescriptor {
            name: "x".to_owned(),
            title: None,
            description: Some("d".to_owned()),
            arguments: vec![],
            icons: None,
            meta: None,
        };
        let modern = legacy_prompt_to_modern(&backend);
        assert_eq!(modern.name, "x");
        assert_eq!(modern.description.as_deref(), Some("d"));
        assert!(
            modern.arguments.is_none(),
            "empty backend arguments must become None on modern wire"
        );
    }

    #[test]
    fn legacy_prompt_arg_to_modern_wraps_required_in_some() {
        let backend = crate::backends::PromptArgument {
            name: "n".to_owned(),
            title: None,
            description: None,
            required: true,
        };
        let modern = legacy_prompt_arg_to_modern(&backend);
        assert_eq!(modern.required, Some(true));
    }

    #[tokio::test]
    async fn dispatch_tools_call_returns_500_when_runtime_unavailable() {
        // Regression guard for the no-runtime path on the new
        // tools/call arm.
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": { "name": "x", "arguments": {} }
            }))
            .expect("parse ok");

        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
        match response.response {
            ProtocolResponse::JsonRpcError(err) => {
                assert_eq!(err.error.code, INTERNAL_ERROR_CODE);
                assert!(err.error.message.contains("shutting down"));
                assert_eq!(err.id, Some(serde_json::json!(11)));
            }
            other => panic!("expected JsonRpcError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_tools_list_returns_500_when_runtime_unavailable() {
        // The new `tools/list` arm reaches for the runtime via
        // `SharedServices.runtime()`; with the test's no-runtime
        // services it surfaces a -32603 with a clear shutdown
        // diagnostic (regression guard — make sure the new arm
        // handles the no-runtime case rather than panicking).
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/list"
            }))
            .expect("parse ok");

        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 500);
        match response.response {
            ProtocolResponse::JsonRpcError(err) => {
                assert_eq!(err.error.code, INTERNAL_ERROR_CODE);
                assert!(err.error.message.contains("shutting down"));
            }
            other => panic!("expected JsonRpcError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_notification_returns_202() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services =
            SharedServices::with_no_runtime(Arc::new(crate::config::AppConfig::default()));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 7, "reason": "user abort" }
            }))
            .expect("parse ok");

        let response = h.dispatch(&ctx, msg, &services).await;
        assert_eq!(response.http_status, 202);
        assert!(matches!(
            response.response,
            ProtocolResponse::NotificationAccepted
        ));
    }

    fn make_test_request_context() -> RequestContext {
        use crate::runtime::{GatewayRequestId, RequestIdentity, TransportKind};
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        )
    }
}
