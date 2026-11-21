//! The request [`Handler`] for MCP revision `2026-07-28`.
//!
//! For one request the transport runs, in order:
//! 1. [`negotiate`](crate::protocol::negotiate) — the protocol-version
//!    check.
//! 2. [`Handler::validate_transport_headers`] — the SEP-2243 header
//!    contract: `Mcp-Method` is required and must equal the body method;
//!    `Mcp-Name` is required (and body-validated) for `tools/call` /
//!    `prompts/get` / `resources/read` and for the `events/*` methods that
//!    name an event type; recognized `Mcp-Param-{Name}` headers are
//!    body-validated (on `events/*` by the events core, against the event
//!    type's annotations). Header values use the `=?base64?…?=`
//!    sentinel for non-ASCII. Methods MCP `2026-07-28` does not define
//!    answer HTTP 404 + `-32601` here.
//! 3. [`Handler::long_lived_stream_plan`] — a `subscriptions/listen` or
//!    `events/stream` request is answered with a stream the transport
//!    writes, not a finite response.
//! 4. [`Handler::parse`] — the body into a typed [`ProtocolMessage`].
//! 5. [`Handler::dispatch`] — `server/discover` is built here; every other
//!    method goes to its dispatch arm, which calls the runtime and shapes
//!    the result (cache fields, `resultType`, MRTR `InputRequiredResult`).

use axum::http::{HeaderMap, HeaderName};
use futures::FutureExt as _;
use serde_json::Value;

use crate::protocol::shared::error::{HEADER_MISMATCH_CODE, ProtocolError};
use crate::protocol::shared::jsonrpc::{
    JSONRPC_VERSION, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse, parse_client_message,
};
use crate::protocol::shared::messages::{ProtocolMessage, TransportRejection};
use crate::protocol::v_2026_07_28::dispatch::completion::dispatch_completion_complete;
use crate::protocol::v_2026_07_28::dispatch::events::dispatch_events_extension;
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
    name_source_field, param_headers, validate_name_header, validate_param_headers,
};
use crate::runtime::shared_services::SharedServices;
use crate::runtime::{GatewayRuntime, RequestContext};

/// The routing headers as header names: a lookup by one skips parsing it.
const PROTOCOL_VERSION_HEADER_NAME: HeaderName = HeaderName::from_static(PROTOCOL_VERSION_HEADER);
const METHOD_HEADER_NAME: HeaderName = HeaderName::from_static(METHOD_HEADER);

/// A request the transport answers with a long-lived stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPlan {
    /// `subscriptions/listen`: the server-initiated notifications the
    /// request names.
    SubscriptionsListen,
    /// `events/stream`: one MCP Events push subscription.
    EventsStream,
}

impl StreamPlan {
    /// The JSON-RPC method of the plan, for metrics and logs.
    pub fn method(self) -> &'static str {
        match self {
            Self::SubscriptionsListen => {
                crate::protocol::v_2026_07_28::wire::subscriptions::METHOD_SUBSCRIPTIONS_LISTEN
            }
            Self::EventsStream => {
                crate::protocol::v_2026_07_28::extensions::events::wire::METHOD_STREAM_EVENTS
            }
        }
    }
}

/// The request handler for MCP revision `2026-07-28`.
///
/// Zero-sized: the runtime and the [`SharedServices`] are handed in at
/// dispatch time.
#[derive(Debug, Clone, Copy, Default)]
pub struct Handler;

impl Handler {
    pub fn new() -> Self {
        Self
    }

    /// `subscriptions/listen` and an `events/stream` request (one with an
    /// id) are long-lived POST-SSE responses.
    pub fn long_lived_stream_plan(&self, body: &Value) -> Option<StreamPlan> {
        match body.get("method").and_then(Value::as_str)? {
            crate::protocol::v_2026_07_28::wire::subscriptions::METHOD_SUBSCRIPTIONS_LISTEN => {
                Some(StreamPlan::SubscriptionsListen)
            }
            crate::protocol::v_2026_07_28::extensions::events::wire::METHOD_STREAM_EVENTS
                if body.get("id").is_some() =>
            {
                Some(StreamPlan::EventsStream)
            }
            _ => None,
        }
    }

    /// SEP-2243 mirrors selected body fields into HTTP routing headers
    /// so intermediaries can route without parsing the body, and makes
    /// the server validate the mirror against the body:
    ///
    /// - `Mcp-Method` is REQUIRED on every request and MUST
    ///   equal the body `method`.
    /// - `Mcp-Name` is REQUIRED for `tools/call` / `prompts/get`
    ///   (mirrors `params.name`), `resources/read` (mirrors
    ///   `params.uri`) and `events/poll` / `events/stream` /
    ///   `events/subscribe` / `events/unsubscribe` (mirrors
    ///   `params.name`, the event name), and MUST equal the body value
    ///   after sentinel decode.
    /// - Any recognized `Mcp-Param-{Name}` header MUST equal the body
    ///   value at `params.arguments.{name}` after sentinel decode.
    ///
    /// Any mismatch / missing-required / malformed header is rejected
    /// with HTTP 400 + the MCP-reserved `HeaderMismatch` code
    /// (`-32020`). Header rules apply only to JSON-RPC *requests*
    /// (id-bearing bodies); the revision leaves notification header
    /// rules undefined.
    pub fn validate_transport_headers(
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

        // SEP-2575: a method the revision does not define answers HTTP 404
        // + JSON-RPC `-32601`, not the HTTP 200 + JSON-RPC error the
        // parser's `method_not_found` gives.
        if is_undefined_method(body_method) {
            return Err(undefined_method_rejection(body_method, body_id));
        }

        // SEP-2575 `_meta` shape. `server/discover` requests MUST carry
        // `params._meta.io.modelcontextprotocol/{protocolVersion,
        // clientInfo, clientCapabilities}`. Other methods don't carry
        // this strict requirement (clients routinely call `tools/list`
        // etc. with minimal params).
        if body_id.is_some()
            && body_method == "server/discover"
            && let Some(missing) = missing_request_meta_key(body)
        {
            return Err(missing_meta_rejection(missing, body_id.clone()));
        }

        // SEP-2575 header / body protocol-version cross-check. When
        // both the `Mcp-Protocol-Version` HTTP header AND the body's
        // `params._meta.io.modelcontextprotocol/protocolVersion` are
        // present, they MUST agree; a body value that is not a string
        // never does. Mismatch = HTTP 400 carrying the dedicated `-32020`
        // "HeaderMismatch" JSON-RPC error (the MCP-reserved-band code).
        // Either one alone is checked by `negotiate` before this runs.
        if let (Some(header_version), Some(body_version)) = (
            headers
                .get(&PROTOCOL_VERSION_HEADER_NAME)
                .and_then(|v| v.to_str().ok()),
            body.as_object()
                .and_then(|obj| obj.get("params"))
                .and_then(|p| p.get("_meta"))
                .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion")),
        ) && body_version.as_str() != Some(header_version)
        {
            let body_version = match body_version {
                Value::String(version) => version.clone(),
                other => other.to_string(),
            };
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

        // SEP-2243 `Mcp-Method` is REQUIRED on every request
        // and MUST equal the body `method`. A request carrying a body
        // `id` is a JSON-RPC *request* (notification header rules are
        // left undefined by the revision, so id-less bodies are not
        // subject to the header contract).
        let is_request = body_id.is_some();
        let header_method = headers
            .get(&METHOD_HEADER_NAME)
            .and_then(|v| v.to_str().ok());
        match header_method {
            None if is_request => {
                return Err(header_mismatch(
                    "SEP-2243 requires the `Mcp-Method` header on requests; \
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
            let events_name_field =
                crate::protocol::v_2026_07_28::extensions::events::wire::name_header_field(
                    body_method,
                );
            // An events request whose body names no event is invalid params,
            // which the events dispatch answers; there is nothing to mirror.
            let events_names_one = events_name_field.is_some_and(|field| {
                body.get("params")
                    .and_then(|p| p.get(field))
                    .is_some_and(Value::is_string)
            });
            if let Some(source_field) =
                name_source_field(body_method).or(events_name_field.filter(|_| events_names_one))
            {
                validate_name_header(headers, body, source_field, body_id.clone())?;
            }

            if events_name_field.is_some() {
                // The annotations of the event type decide which
                // `Mcp-Param-{Name}` headers an events request needs; the
                // events core checks them against its catalog. Here only
                // their shape is checked.
                param_headers(headers, body_id.clone())?;
            } else {
                // SEP-2243 `x-mcp-header` param→header promotion. Any
                // recognized `Mcp-Param-{Name}` header MUST, after sentinel
                // decode, match the value carried at the corresponding
                // `params.arguments.{name}` position in the body. The
                // gateway routes/executes on the body, so a header that
                // disagrees with the body is a routing-vs-execution split.
                validate_param_headers(headers, body, body_id.clone())?;
            }
        }
        Ok(())
    }

    /// Parse a JSON body into a [`ProtocolMessage`] carrying its typed
    /// [`ProtocolOperation`].
    pub fn parse(&self, body: Value) -> Result<ProtocolMessage, ProtocolError> {
        let message = parse_client_message(body)?;
        let operation = map_client_message_to_operation(message)?;
        Ok(ProtocolMessage::new(operation))
    }

    /// Dispatch a parsed operation against `runtime`, the runtime the
    /// transport holds for the whole request.
    ///
    /// `server/discover` is built here (server identity + the capability
    /// advertisement). Capability operations (tools, prompts, resources,
    /// completion) and the extensions go to their dispatch arms.
    /// Notifications return the `NotificationAccepted` envelope.
    pub async fn dispatch(
        &self,
        ctx: &std::sync::Arc<RequestContext>,
        runtime: &GatewayRuntime,
        op: ProtocolMessage,
        services: &SharedServices,
    ) -> ProtocolHttpResponse {
        match op.operation {
            ProtocolOperation::Lifecycle(LifecycleOperation::Discover { request_id, .. }) => {
                let result = build_discover_result(services, runtime, &ctx.transport);
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
                // `notifications/cancelled` goes into the principal-
                // partitioned, cross-instance cancellation machinery
                // (`GatewayRuntime::handle_request_cancellation`): bus
                // broadcast → `cancel_suspended_pipeline` on every replica,
                // plus the audit + metric records. `notifications/cancelled`
                // carries no response.
                runtime
                    .handle_request_cancellation(ctx, &cancelled_request_id, reason.as_deref())
                    .boxed()
                    .await;
                ProtocolHttpResponse {
                    http_status: 202,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            ProtocolOperation::Lifecycle(LifecycleOperation::NotificationAccepted) => {
                ProtocolHttpResponse {
                    http_status: 202,
                    response: ProtocolResponse::NotificationAccepted,
                }
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ToolsList {
                request_id,
                params,
            }) => {
                dispatch_tools_list(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ToolsCall {
                request_id,
                params,
            }) => dispatch_tools_call(ctx, runtime, services, request_id, params).await,
            ProtocolOperation::Capabilities(CapabilityOperation::PromptsList {
                request_id,
                params,
            }) => {
                dispatch_prompts_list(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::PromptsGet {
                request_id,
                params,
            }) => {
                dispatch_prompts_get(ctx, runtime, services, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesList {
                request_id,
                params,
            }) => {
                dispatch_resources_list(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesRead {
                request_id,
                params,
            }) => {
                dispatch_resources_read(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::ResourcesTemplatesList {
                request_id,
                params,
            }) => {
                dispatch_resources_templates_list(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
            ProtocolOperation::Capabilities(CapabilityOperation::Complete {
                request_id,
                params,
            }) => {
                dispatch_completion_complete(ctx, runtime, request_id, params)
                    .boxed()
                    .await
            }
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
                    "Handler::dispatch reached for subscriptions/listen — \
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
                dispatch_tasks_extension(ctx, runtime, services, op)
                    .boxed()
                    .await
            }
            ProtocolOperation::EventsExtension(op) => {
                dispatch_events_extension(ctx, runtime, services, op)
                    .boxed()
                    .await
            }
            ProtocolOperation::SkillsExtension(op) => {
                runtime.handle_skills_operation(op, ctx).boxed().await
            }
        }
    }
}

/// JSON-RPC methods that MCP `2026-07-28` does not define and that SEP-2575
/// answers with HTTP 404 + JSON-RPC `-32601`; the parser's
/// `method_not_found` fallback returns HTTP 200, which the conformance
/// suite flags.
///
/// Disjoint from the router's method table in
/// [`crate::protocol::v_2026_07_28::wire::routing`] — a method added there must
/// not appear here.
fn is_undefined_method(method: &str) -> bool {
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

/// The 404 + `-32601` answer to a method [`is_undefined_method`] names.
fn undefined_method_rejection(method: &str, jsonrpc_id: Option<Value>) -> TransportRejection {
    TransportRejection {
        status: 404,
        error_code: -32601,
        message: format!(
            "Method `{method}` is not defined in MCP {SUPPORTED_PROTOCOL_VERSION} (SEP-2575)"
        ),
        data: None,
        jsonrpc_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::shared::error::{
        INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
    };
    use crate::protocol::shared::jsonrpc::{JsonRpcError, JsonRpcErrorBody};
    use crate::protocol::v_2026_07_28::dispatch::mrtr::resume_did_not_commit;
    use crate::protocol::v_2026_07_28::dispatch::prompts::{prompt_argument, prompt_descriptor};
    use crate::protocol::v_2026_07_28::dispatch::resources::resource_descriptor;
    use crate::protocol::v_2026_07_28::dispatch::support::map_request_state_decode_error;
    use crate::protocol::v_2026_07_28::dispatch::tasks::fold_resume_outcome_onto_task;
    use crate::protocol::v_2026_07_28::wire::NAME_HEADER;
    use crate::runtime::shared_services::SharedServices;
    use std::sync::Arc;

    fn error_response(code: i32) -> ProtocolHttpResponse {
        ProtocolHttpResponse {
            http_status: 200,
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
        // On these the resume advanced nothing, so the inline
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
            .create_task(session, Value::from(1), "some_tool")
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

    /// Pins every well-known wire string to its spec value, grouped by
    /// the SEP that defines it.
    #[test]
    fn well_known_strings_match_spec() {
        use crate::protocol::v_2026_07_28::extensions::tasks::wire as tasks_ext;
        use crate::protocol::v_2026_07_28::wire;

        assert_eq!(wire::SUPPORTED_PROTOCOL_VERSION, "2026-07-28");
        assert_eq!(crate::protocol::SUPPORTED_PROTOCOL_VERSION, "2026-07-28");

        // ── SEP-2243 transport-header routing.
        assert_eq!(wire::PROTOCOL_VERSION_HEADER, "mcp-protocol-version");
        assert_eq!(wire::METHOD_HEADER, "mcp-method");
        assert_eq!(wire::NAME_HEADER, "mcp-name");
        assert_eq!(wire::PARAM_HEADER_PREFIX, "mcp-param-");

        // ── Core method strings.
        assert_eq!(wire::lifecycle::METHOD_SERVER_DISCOVER, "server/discover");
        assert_eq!(wire::tools::METHOD_TOOLS_LIST, "tools/list");
        assert_eq!(wire::tools::METHOD_TOOLS_CALL, "tools/call");
        assert_eq!(wire::prompts::METHOD_PROMPTS_LIST, "prompts/list");
        assert_eq!(wire::prompts::METHOD_PROMPTS_GET, "prompts/get");
        assert_eq!(wire::resources::METHOD_RESOURCES_LIST, "resources/list");
        assert_eq!(wire::resources::METHOD_RESOURCES_READ, "resources/read");
        assert_eq!(
            wire::resources::METHOD_RESOURCES_TEMPLATES_LIST,
            "resources/templates/list"
        );
        assert_eq!(
            wire::completion::METHOD_COMPLETION_COMPLETE,
            "completion/complete"
        );
        assert_eq!(
            wire::subscriptions::METHOD_SUBSCRIPTIONS_LISTEN,
            "subscriptions/listen"
        );

        // ── SEP-2322 MRTR.
        assert_eq!(wire::mrtr::RESULT_TYPE_INPUT_REQUIRED, "input_required");

        // ── SEP-2549 two-value `CacheScope` (`public` / `private`).
        for (scope, expected) in [
            (wire::tools::CacheScope::Public, "public"),
            (wire::tools::CacheScope::Private, "private"),
        ] {
            assert_eq!(serde_json::to_value(scope).unwrap(), expected);
        }

        // ── SEP-2243 + 2575 per-request `_meta` namespace keys.
        assert_eq!(wire::meta::META_NAMESPACE, "io.modelcontextprotocol");
        assert_eq!(
            wire::meta::META_KEY_TRACEPARENT,
            "io.modelcontextprotocol/traceparent"
        );
        assert_eq!(
            wire::meta::META_KEY_PROGRESS_TOKEN,
            "io.modelcontextprotocol/progressToken"
        );
        assert_eq!(
            wire::meta::META_KEY_LOG_LEVEL,
            "io.modelcontextprotocol/logLevel"
        );
        assert_eq!(
            wire::meta::META_KEY_CACHE_TOKEN,
            "io.modelcontextprotocol/cacheToken"
        );
        assert_eq!(
            wire::meta::META_KEY_IDEMPOTENCY,
            "io.modelcontextprotocol/idempotencyKey"
        );
        assert_eq!(
            wire::meta::META_KEY_PRESERVE_CONTEXT,
            "io.modelcontextprotocol/preserveContext"
        );

        // ── SEP-2575 subscriptions.
        assert_eq!(
            wire::subscriptions::META_KEY_SUBSCRIPTION_ID,
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
        assert_eq!(wire::tools::RESULT_TYPE_COMPLETE, "complete");
        assert_eq!(wire::tools::RESULT_TYPE_INPUT_REQUIRED, "input_required");
        assert_eq!(wire::tools::RESULT_TYPE_TASK, "task");
    }

    /// A method the revision does not define is a 404 + `-32601` that names
    /// the revision and offers no other one.
    #[test]
    fn undefined_methods_are_404_method_not_found() {
        let h = Handler::new();
        for method in [
            "initialize",
            "notifications/initialized",
            "ping",
            "logging/setLevel",
            "resources/subscribe",
            "resources/unsubscribe",
            "tasks/result",
            "tasks/list",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(METHOD_HEADER, method.parse().unwrap());
            let body = serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": method });
            let err = h.validate_transport_headers(&headers, &body).unwrap_err();
            assert_eq!(err.status, 404, "{method}");
            assert_eq!(err.error_code, -32601, "{method}");
            assert_eq!(err.jsonrpc_id, Some(serde_json::json!(5)));
            assert!(err.message.contains(method), "{}", err.message);
            assert!(err.message.contains("2026-07-28"), "{}", err.message);
            assert!(!err.message.contains("2025"), "{}", err.message);
        }
    }

    /// With the version header present, a body `_meta` version must be the
    /// same string: a different string, a number or `null` is a `-32020`.
    #[test]
    fn a_body_version_must_be_the_header_version() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "tools/list".parse().unwrap());
        headers.insert(PROTOCOL_VERSION_HEADER, "2026-07-28".parse().unwrap());
        let body = |version: Value| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/list",
                "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": version } }
            })
        };
        assert!(
            h.validate_transport_headers(&headers, &body(serde_json::json!("2026-07-28")))
                .is_ok()
        );
        for disagreeing in [
            serde_json::json!("2026-01-01"),
            serde_json::json!(20260728),
            Value::Null,
            serde_json::json!({ "v": "2026-07-28" }),
        ] {
            let err = h
                .validate_transport_headers(&headers, &body(disagreeing.clone()))
                .unwrap_err();
            assert_eq!(err.status, 400, "{disagreeing}");
            assert_eq!(err.error_code, HEADER_MISMATCH_CODE, "{disagreeing}");
            assert_eq!(err.jsonrpc_id, Some(serde_json::json!(3)));
        }
    }

    #[test]
    fn long_lived_stream_plans() {
        let h = Handler::new();
        assert_eq!(
            h.long_lived_stream_plan(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "subscriptions/listen"
            })),
            Some(StreamPlan::SubscriptionsListen)
        );
        assert_eq!(
            h.long_lived_stream_plan(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "events/stream"
            })),
            Some(StreamPlan::EventsStream)
        );
        // An `events/stream` notification has no stream to answer with.
        assert_eq!(
            h.long_lived_stream_plan(&serde_json::json!({
                "jsonrpc": "2.0", "method": "events/stream"
            })),
            None
        );
        assert_eq!(
            h.long_lived_stream_plan(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list"
            })),
            None
        );
        assert_eq!(
            StreamPlan::SubscriptionsListen.method(),
            "subscriptions/listen"
        );
        assert_eq!(StreamPlan::EventsStream.method(), "events/stream");
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
        assert_eq!(err.error_code, -32020, "SEP-2243 makes Mcp-Method REQUIRED");
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

    fn events_subscribe_body(name: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "events/subscribe",
            "params": {
                "name": name,
                "delivery": {
                    "url": "https://h.example/hook",
                    "secret": "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
                },
            },
        })
    }

    /// `Mcp-Name` is required on the four `events/*` methods that name an
    /// event type, and must agree with `params.name`.
    #[test]
    fn events_mcp_name_is_required_and_checked() {
        let h = Handler::new();
        for method in [
            "events/subscribe",
            "events/unsubscribe",
            "events/poll",
            "events/stream",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(METHOD_HEADER, method.parse().unwrap());
            let mut body = events_subscribe_body("orders.created");
            body["method"] = serde_json::json!(method);
            let err = h.validate_transport_headers(&headers, &body).unwrap_err();
            assert_eq!((err.status, err.error_code), (400, -32020), "{method}");
            assert!(err.message.contains("Mcp-Name"), "{method}");

            headers.insert(NAME_HEADER, "orders.created".parse().unwrap());
            assert!(
                h.validate_transport_headers(&headers, &body).is_ok(),
                "{method}"
            );

            headers.insert(NAME_HEADER, "orders.deleted".parse().unwrap());
            let err = h.validate_transport_headers(&headers, &body).unwrap_err();
            assert_eq!((err.status, err.error_code), (400, -32020), "{method}");
        }
    }

    /// A non-ASCII event name travels in the Base64 sentinel.
    #[test]
    fn events_mcp_name_decodes_the_sentinel() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "events/subscribe".parse().unwrap());
        headers.insert(
            NAME_HEADER,
            crate::protocol::v_2026_07_28::wire::encode_header_value("bestellung.erstellt.ü")
                .parse()
                .unwrap(),
        );
        let body = events_subscribe_body("bestellung.erstellt.ü");
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    /// On `events/*` an `Mcp-Param-*` header is checked for shape here and
    /// against the event type by the events core, so a header that names
    /// no argument passes this step.
    #[test]
    fn events_param_headers_are_checked_for_shape_only() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "events/subscribe".parse().unwrap());
        headers.insert(NAME_HEADER, "orders.created".parse().unwrap());
        headers.insert("mcp-param-region", "eu".parse().unwrap());
        let body = events_subscribe_body("orders.created");
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
        headers.insert("mcp-param-region", "=?base64?!!?=".parse().unwrap());
        let err = h.validate_transport_headers(&headers, &body).unwrap_err();
        assert_eq!((err.status, err.error_code), (400, -32020));
    }

    /// `events/list` names no type, so an `Mcp-Name` on it is ignored like
    /// on any other method that does not mirror a name.
    #[test]
    fn events_list_ignores_mcp_name() {
        let h = Handler::new();
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, "events/list".parse().unwrap());
        headers.insert(NAME_HEADER, "anything".parse().unwrap());
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 3, "method": "events/list" });
        assert!(h.validate_transport_headers(&headers, &body).is_ok());
    }

    #[test]
    fn events_methods_parse_with_their_labels() {
        let h = Handler::new();
        let msg = h
            .parse(events_subscribe_body("orders.created"))
            .expect("parse ok");
        assert_eq!(msg.label, "events_ext.subscribe");
        assert_eq!(msg.jsonrpc_id, Some(serde_json::json!(12)));
    }

    /// With events off (the default) the methods do not exist: the
    /// `-32601` on HTTP 404.
    #[tokio::test]
    async fn events_methods_are_method_not_found_by_default() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services = SharedServices::for_tests(Arc::new(crate::config::AppConfig::default()));
        for body in [
            serde_json::json!({ "jsonrpc": "2.0", "id": 3, "method": "events/list" }),
            events_subscribe_body("orders.created"),
        ] {
            let msg = h.parse(body).expect("parse ok");
            let response = dispatch(&h, &ctx, msg, &services).await;
            assert_eq!(response.http_status, 404);
            match response.response {
                ProtocolResponse::JsonRpcError(err) => assert_eq!(err.error.code, -32601),
                other => panic!("expected JsonRpcError, got {other:?}"),
            }
        }
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
        assert!(matches!(
            msg.operation,
            ProtocolOperation::Lifecycle(LifecycleOperation::Discover { .. })
        ));
    }

    #[test]
    fn parse_refuses_initialize() {
        let h = Handler::new();
        // The router does not define `initialize`; it answers -32601.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let Err(err) = h.parse(body) else {
            panic!("`initialize` must not parse");
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
        let services = SharedServices::for_tests(Arc::new(cfg));

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

        let response = dispatch(&h, &ctx, msg, &services).await;
        assert_eq!(response.http_status, 200);
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                assert_eq!(success.id, serde_json::json!(1));
                // CacheableResult envelope with the plural
                // `supportedVersions`, which lists the one served revision.
                assert!(success.result.get("protocolVersion").is_none());
                assert_eq!(success.result["resultType"], "complete");
                assert!(success.result["ttlMs"].is_u64());
                assert_eq!(success.result["cacheScope"], "public");
                assert_eq!(
                    success.result["supportedVersions"],
                    serde_json::json!(["2026-07-28"])
                );
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
                // The extension defines no settings, and this build
                // implements its initial revision, so it sends none.
                assert_eq!(ext["io.modelcontextprotocol/tasks"], serde_json::json!({}));
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
        let services = SharedServices::for_tests(Arc::new(cfg));

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

        let response = dispatch(&h, &ctx, msg, &services).await;
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
        let services = SharedServices::for_tests(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = dispatch(&h, &ctx, msg, &services).await;
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

    /// `server/discover` declares the Enterprise-Managed Authorization
    /// extension over HTTP when the embedded authorization server is
    /// configured, and never over stdio.
    #[tokio::test]
    async fn dispatch_discover_declares_ema_extension_with_an_authorization_server() {
        async fn discover(cfg: &str, transport: crate::runtime::TransportKind) -> Option<Value> {
            let h = Handler::new();
            let cfg: crate::config::AppConfig =
                serde_yaml::from_str(cfg).expect("test AppConfig YAML parses");
            let services = SharedServices::for_tests(Arc::new(cfg));
            let mut ctx = make_test_request_context();
            ctx.transport = transport;
            let msg = h
                .parse(serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                    "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
                }))
                .expect("parse ok");
            match dispatch(&h, &ctx, msg, &services).await.response {
                ProtocolResponse::JsonRpcSuccess(success) => {
                    success.result["capabilities"]["extensions"]
                        .get("io.modelcontextprotocol/enterprise-managed-authorization")
                        .cloned()
                }
                other => panic!("expected JsonRpcSuccess, got {other:?}"),
            }
        }
        let ema = r#"
governance:
  access:
    resource_metadata:
      resource: https://mcp.example.com/mcp
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: ema-signing-secret-0123456789abcdef
      trusted_idps:
        - issuer: https://acme.okta.com
      clients:
        - client_id: mcp-client
"#;

        assert_eq!(
            discover(ema, crate::runtime::TransportKind::Http).await,
            Some(serde_json::json!({}))
        );
        assert_eq!(
            discover(ema, crate::runtime::TransportKind::Stdio).await,
            None
        );
        assert_eq!(
            discover("{}", crate::runtime::TransportKind::Http).await,
            None
        );
    }

    #[tokio::test]
    async fn dispatch_discover_advertises_completions_plural_key_when_configured() {
        // A prompt argument with static completions makes the
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
        let services = SharedServices::for_tests(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = dispatch(&h, &ctx, msg, &services).await;
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
        let services = SharedServices::for_tests(Arc::new(cfg));
        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "protocolVersion": "2026-07-28", "clientInfo": { "name": "t", "version": "0" } }
            }))
            .expect("parse ok");
        let response = dispatch(&h, &ctx, msg, &services).await;
        match response.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                let caps = &success.result["capabilities"];
                assert!(caps.get("completions").is_none());
                assert!(caps.get("completion").is_none());
            }
            other => panic!("expected JsonRpcSuccess, got {other:?}"),
        }
    }

    #[test]
    fn resource_descriptor_carries_annotations() {
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
        let descriptor = resource_descriptor(&backend);
        assert_eq!(descriptor.uri, "u");
        assert_eq!(descriptor.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(descriptor.size, Some(100));
        let ann = descriptor
            .annotations
            .as_ref()
            .expect("annotations carried");
        assert_eq!(ann.priority, Some(0.5));
        assert_eq!(ann.audience.as_deref(), Some(&["user".to_owned()][..]));
        assert!(descriptor.cache_scope.is_none());
    }

    #[test]
    fn prompt_descriptor_with_empty_arguments_omits_field() {
        let backend = crate::backends::PromptDescriptor {
            name: "x".to_owned(),
            title: None,
            description: Some("d".to_owned()),
            arguments: vec![],
            icons: None,
            meta: None,
        };
        let descriptor = prompt_descriptor(&backend);
        assert_eq!(descriptor.name, "x");
        assert_eq!(descriptor.description.as_deref(), Some("d"));
        assert!(
            descriptor.arguments.is_none(),
            "empty backend arguments must serialize as no `arguments`"
        );
    }

    #[test]
    fn prompt_argument_wraps_required_in_some() {
        let backend = crate::backends::PromptArgument {
            name: "n".to_owned(),
            title: None,
            description: None,
            required: true,
        };
        assert_eq!(prompt_argument(&backend).required, Some(true));
    }

    #[tokio::test]
    async fn dispatch_notification_returns_202() {
        let h = Handler::new();
        let ctx = make_test_request_context();
        let services = SharedServices::for_tests(Arc::new(crate::config::AppConfig::default()));

        let msg = h
            .parse(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 7, "reason": "user abort" }
            }))
            .expect("parse ok");

        let response = dispatch(&h, &ctx, msg, &services).await;
        assert_eq!(response.http_status, 202);
        assert!(matches!(
            response.response,
            ProtocolResponse::NotificationAccepted
        ));
    }

    /// Dispatch `msg` over `services` and the runtime their config builds.
    async fn dispatch(
        h: &Handler,
        ctx: &RequestContext,
        msg: ProtocolMessage,
        services: &SharedServices,
    ) -> ProtocolHttpResponse {
        let runtime = crate::runtime::shared_services::test_runtime(&services.config_snapshot);
        h.dispatch(&Arc::new(ctx.clone()), &runtime, msg, services)
            .await
    }

    fn make_test_request_context() -> RequestContext {
        use crate::runtime::{GatewayRequestId, RequestIdentity, TransportKind};
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            TransportKind::Http,
        )
    }
}
