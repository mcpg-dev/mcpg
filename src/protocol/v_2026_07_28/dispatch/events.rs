//! `events/*` dispatch arms (MCP Events, experimental) for MCP revision
//! `2026-07-28`.
//!
//! The protocol layer owns everything a request needs before and after
//! the events core: whether the methods exist at all on this wire,
//! transport, and config; the typed params; and the mapping of an
//! [`EventsError`] onto a JSON-RPC error and an HTTP status. The events
//! core plugs in through [`EventsHandler`], installed once into
//! [`EventsHandlerSlot`] on the [`SharedServices`] bundle. Until a handler
//! is installed, or while `mcp.configurations.events.enabled` is off, the
//! methods do not exist: `-32601` on HTTP 404, the same answer as any
//! other unknown method on this wire.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use serde_json::Value;

use crate::config::EventsConfig;
use crate::protocol::shared::error::{
    INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE,
};
use crate::protocol::shared::jsonrpc::{ProtocolHttpResponse, ProtocolResponse};
use crate::protocol::v_2026_07_28::dispatch::support::serialize_jsonrpc_success;
use crate::protocol::v_2026_07_28::extensions::events::errors::{
    CodeNumbering, EventsError, FORBIDDEN_CODE,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    ListEventsParams, ListEventsResult, PollEventsParams, PollEventsResult, SubscribeEventsParams,
    SubscribeEventsResult, UnsubscribeEventsParams, UnsubscribeEventsResult,
};
use crate::protocol::v_2026_07_28::wire::operations::EventsExtensionOperation;
use crate::runtime::shared_services::SharedServices;
use crate::runtime::{RequestContext, TransportKind};

/// The events core, as the protocol layer sees it.
///
/// Each method receives the parsed params and the request context (the
/// caller's identity among it) and answers with a typed result or an
/// [`EventsError`]; the dispatcher renders both. An implementation never
/// sees a request while events are disabled or on a wire other than
/// `2026-07-28` over HTTP.
#[async_trait]
pub trait EventsHandler: Send + Sync {
    /// `events/list`: the types this caller may discover.
    async fn list(
        &self,
        ctx: &RequestContext,
        params: ListEventsParams,
    ) -> Result<ListEventsResult, EventsError>;

    /// `events/subscribe`: create or refresh a webhook subscription.
    async fn subscribe(
        &self,
        ctx: &RequestContext,
        params: SubscribeEventsParams,
    ) -> Result<SubscribeEventsResult, EventsError>;

    /// `events/unsubscribe`: drop a webhook subscription.
    async fn unsubscribe(
        &self,
        ctx: &RequestContext,
        params: UnsubscribeEventsParams,
    ) -> Result<UnsubscribeEventsResult, EventsError>;

    /// `events/poll`: the next batch of one subscription's log.
    async fn poll(
        &self,
        ctx: &RequestContext,
        params: PollEventsParams,
    ) -> Result<PollEventsResult, EventsError>;
}

/// Where the events core is installed. Set once, at boot; the core lives
/// across config reloads and reads each new config itself, so the slot is
/// never replaced.
#[derive(Default)]
pub struct EventsHandlerSlot(OnceLock<Arc<dyn EventsHandler>>);

impl EventsHandlerSlot {
    /// Install the events core. Fails, handing the handler back, when one
    /// is already installed.
    pub fn install(&self, handler: Arc<dyn EventsHandler>) -> Result<(), Arc<dyn EventsHandler>> {
        self.0.set(handler)
    }

    pub fn get(&self) -> Option<&Arc<dyn EventsHandler>> {
        self.0.get()
    }

    pub fn is_installed(&self) -> bool {
        self.0.get().is_some()
    }
}

impl std::fmt::Debug for EventsHandlerSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsHandlerSlot")
            .field("installed", &self.is_installed())
            .finish()
    }
}

/// The events config in force: the live runtime's, which a reload
/// replaces, else the boot snapshot while the runtime is shutting down.
pub(crate) fn live_events_config(services: &SharedServices) -> EventsConfig {
    match services.runtime() {
        Some(runtime) => runtime.load().events_config().clone(),
        None => services.config_snapshot.mcp.configurations.events.clone(),
    }
}

/// Whether `events/*` exist for this request: enabled by config, a core
/// installed, and the HTTP transport (the only one that carries the
/// `2026-07-28` wire).
pub(crate) fn events_served(
    config: &EventsConfig,
    services: &SharedServices,
    transport: &TransportKind,
) -> bool {
    config.enabled && *transport == TransportKind::Http && services.events.is_installed()
}

/// Dispatch one `events/*` operation.
pub(crate) async fn dispatch_events_extension(
    ctx: &RequestContext,
    services: &SharedServices,
    op: EventsExtensionOperation,
) -> ProtocolHttpResponse {
    let config = live_events_config(services);
    let handler = match services.events.get() {
        Some(handler) if events_served(&config, services, &ctx.transport) => Arc::clone(handler),
        _ => return method_not_found(op.request_id().clone(), op.method()),
    };
    let method = op.method();
    let numbering = config.error_codes.numbering();
    if let Some(runtime) = services.runtime()
        && let Err(limit) = runtime.load().admit_plan_rps("events")
    {
        return plan_rps_refusal(Some(op.request_id().clone()), limit, numbering);
    }
    match op {
        EventsExtensionOperation::List { request_id, params } => render(
            request_id,
            method,
            numbering,
            handler.list(ctx, params).await,
        ),
        EventsExtensionOperation::Subscribe { request_id, params } => render(
            request_id,
            method,
            numbering,
            handler.subscribe(ctx, params).await,
        ),
        EventsExtensionOperation::Unsubscribe { request_id, params } => render(
            request_id,
            method,
            numbering,
            handler.unsubscribe(ctx, params).await,
        ),
        EventsExtensionOperation::Poll { request_id, params } => render(
            request_id,
            method,
            numbering,
            handler.poll(ctx, params).await,
        ),
        EventsExtensionOperation::InvalidParams {
            request_id,
            message,
            ..
        } => events_error_response(
            Some(request_id),
            EventsError::invalid_params(message),
            numbering,
        ),
    }
}

fn render<T: serde::Serialize>(
    request_id: Value,
    method: &str,
    numbering: CodeNumbering,
    outcome: Result<T, EventsError>,
) -> ProtocolHttpResponse {
    match outcome {
        Ok(result) => serialize_jsonrpc_success(request_id, &result, method),
        Err(error) => events_error_response(Some(request_id), error, numbering),
    }
}

/// The answer to an `events/*` request past the licence's per-gateway
/// request ceiling: `-32013 {limit: "plan.rps_per_gateway", max}` on HTTP
/// 429, with `Retry-After: 1`.
pub(crate) fn plan_rps_refusal(
    id: Option<Value>,
    limit: u32,
    numbering: CodeNumbering,
) -> ProtocolHttpResponse {
    let error = EventsError::resource_exhausted("plan.rps_per_gateway", Some(u64::from(limit)))
        .with_data_entry(
            crate::transports::http::RETRY_AFTER_DATA_KEY,
            Value::from(1),
        );
    ProtocolHttpResponse {
        http_status: 429,
        ..events_error_response(id, error, numbering)
    }
}

/// HTTP status of an `events/*` error.
///
/// A malformed request is the client's (`400`). A denial is `403`, which
/// keeps the step-up path: a missing-scope marker in `data` becomes an
/// `insufficient_scope` challenge on the way out. A store or coordinator
/// fault is `503`, retryable, because the request left nothing behind. A
/// method that does not exist is `404`, as for every unknown method on
/// this wire. Every other events code is a well-formed answer and rides
/// on `200`.
pub(crate) fn events_error_http_status(code: i32) -> u16 {
    match code {
        INVALID_PARAMS_CODE => 400,
        FORBIDDEN_CODE => 403,
        INTERNAL_ERROR_CODE => 503,
        METHOD_NOT_FOUND_CODE => 404,
        _ => 200,
    }
}

/// Render an [`EventsError`] as the response to request `id`, its code in
/// `numbering`.
pub(crate) fn events_error_response(
    id: Option<Value>,
    error: EventsError,
    numbering: CodeNumbering,
) -> ProtocolHttpResponse {
    ProtocolHttpResponse {
        http_status: events_error_http_status(error.code()),
        session_id_header: None,
        response: ProtocolResponse::JsonRpcError(error.numbered(numbering).into_jsonrpc_error(id)),
    }
}

/// The answer while events are not served: the methods do not exist.
pub(crate) fn method_not_found(id: Value, method: &str) -> ProtocolHttpResponse {
    crate::protocol::v_2026_07_28::dispatch::support::handler_client_error(
        Some(id),
        404,
        METHOD_NOT_FOUND_CODE,
        &format!("Method not found: {method}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::protocol::v_2026_07_28::extensions::events::errors::{
        ForbiddenReason, NotFoundKind, RESOURCE_EXHAUSTED_CODE,
    };
    use crate::protocol::v_2026_07_28::extensions::events::wire::{
        DeliveryErrorCategory, DeliveryMode, EventDescriptor,
    };
    use crate::runtime::{GatewayRequestId, RequestIdentity};
    use serde_json::json;
    use std::sync::Mutex;

    /// Records what reached the core and answers from a script.
    #[derive(Default)]
    struct ScriptedCore {
        seen: Mutex<Vec<String>>,
        fail_with: Option<EventsError>,
    }

    #[async_trait]
    impl EventsHandler for ScriptedCore {
        async fn list(
            &self,
            _ctx: &RequestContext,
            params: ListEventsParams,
        ) -> Result<ListEventsResult, EventsError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("list {:?}", params.cursor));
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }
            Ok(ListEventsResult::new(
                vec![EventDescriptor {
                    name: "orders.created".to_owned(),
                    description: None,
                    delivery: vec![DeliveryMode::Webhook],
                    input_schema: json!({ "type": "object" }),
                    payload_schema: json!({ "type": "object" }),
                    meta: None,
                }],
                None,
            ))
        }

        async fn subscribe(
            &self,
            _ctx: &RequestContext,
            params: SubscribeEventsParams,
        ) -> Result<SubscribeEventsResult, EventsError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("subscribe {}", params.name));
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }
            Ok(SubscribeEventsResult::new(
                "sub_1".to_owned(),
                Some("2026-10-03T13:00:00Z".to_owned()),
                None,
                false,
            ))
        }

        async fn unsubscribe(
            &self,
            _ctx: &RequestContext,
            params: UnsubscribeEventsParams,
        ) -> Result<UnsubscribeEventsResult, EventsError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("unsubscribe {}", params.name));
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }
            Ok(UnsubscribeEventsResult::default())
        }

        async fn poll(
            &self,
            _ctx: &RequestContext,
            params: PollEventsParams,
        ) -> Result<PollEventsResult, EventsError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("poll {}", params.name));
            Err(self.fail_with.clone().unwrap_or_else(|| {
                EventsError::unsupported_delivery_mode(DeliveryMode::Poll.as_str())
            }))
        }
    }

    fn context(transport: TransportKind) -> RequestContext {
        RequestContext::new(
            GatewayRequestId::new(),
            None,
            None,
            None,
            RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            transport,
        )
    }

    fn services(enabled: bool) -> SharedServices {
        let mut config = AppConfig::default();
        config.mcp.configurations.events.enabled = enabled;
        SharedServices::with_no_runtime(Arc::new(config))
    }

    fn list_op() -> EventsExtensionOperation {
        EventsExtensionOperation::List {
            request_id: json!(4),
            params: ListEventsParams::default(),
        }
    }

    fn subscribe_op() -> EventsExtensionOperation {
        EventsExtensionOperation::Subscribe {
            request_id: json!("s-1"),
            params: serde_json::from_value(json!({
                "name": "orders.created",
                "delivery": {
                    "url": "https://h.example/hook",
                    "secret": "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
                }
            }))
            .unwrap(),
        }
    }

    fn error_body(response: &ProtocolHttpResponse) -> (i32, Option<Value>, Option<Value>) {
        match &response.response {
            ProtocolResponse::JsonRpcError(error) => {
                (error.error.code, error.error.data.clone(), error.id.clone())
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn install(services: &SharedServices, core: ScriptedCore) -> Arc<ScriptedCore> {
        let core = Arc::new(core);
        services
            .events
            .install(core.clone() as Arc<dyn EventsHandler>)
            .unwrap_or_else(|_| panic!("first install"));
        core
    }

    #[tokio::test]
    async fn not_served_without_a_core_even_when_enabled() {
        let services = services(true);
        let response =
            dispatch_events_extension(&context(TransportKind::Http), &services, list_op()).await;
        assert_eq!(response.http_status, 404);
        let (code, _, id) = error_body(&response);
        assert_eq!(code, -32601);
        assert_eq!(id, Some(json!(4)));
    }

    #[tokio::test]
    async fn not_served_while_disabled_and_the_core_is_never_reached() {
        let services = services(false);
        let core = install(&services, ScriptedCore::default());
        for op in [list_op(), subscribe_op()] {
            let response =
                dispatch_events_extension(&context(TransportKind::Http), &services, op).await;
            assert_eq!(response.http_status, 404);
            assert_eq!(error_body(&response).0, -32601);
        }
        assert!(core.seen.lock().unwrap().is_empty());
    }

    fn invalid_params_op() -> EventsExtensionOperation {
        EventsExtensionOperation::InvalidParams {
            request_id: json!("bad-1"),
            method: "events/subscribe",
            message: "invalid events/subscribe params: missing field `delivery`".to_owned(),
        }
    }

    /// Unparsable params do not exist either while events are off: the
    /// answer is the unknown method's, not a `-32602` naming a field.
    #[tokio::test]
    async fn invalid_params_are_method_not_found_while_not_served() {
        for services in [services(false), services(true)] {
            let response = dispatch_events_extension(
                &context(TransportKind::Http),
                &services,
                invalid_params_op(),
            )
            .await;
            assert_eq!(response.http_status, 404);
            let (code, _, id) = error_body(&response);
            assert_eq!(code, -32601);
            assert_eq!(id, Some(json!("bad-1")));
        }
    }

    /// Served, unparsable params are `-32602` on HTTP 400, the status a
    /// core's own `-32602` gets, and the core never sees them.
    #[tokio::test]
    async fn invalid_params_are_400_while_served() {
        let services = services(true);
        let core = install(&services, ScriptedCore::default());
        let response = dispatch_events_extension(
            &context(TransportKind::Http),
            &services,
            invalid_params_op(),
        )
        .await;
        assert_eq!(response.http_status, 400);
        match &response.response {
            ProtocolResponse::JsonRpcError(error) => {
                assert_eq!(error.error.code, -32602);
                assert_eq!(error.id, Some(json!("bad-1")));
                assert!(
                    error.error.message.contains("`delivery`"),
                    "{}",
                    error.error.message
                );
                assert_eq!(error.error.data, None);
            }
            other => panic!("expected an error, got {other:?}"),
        }
        assert!(core.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn not_served_over_stdio() {
        let services = services(true);
        let core = install(&services, ScriptedCore::default());
        let response =
            dispatch_events_extension(&context(TransportKind::Stdio), &services, list_op()).await;
        assert_eq!(error_body(&response).0, -32601);
        assert!(core.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn served_requests_reach_the_core_and_render_typed_results() {
        let services = services(true);
        let core = install(&services, ScriptedCore::default());
        let ctx = context(TransportKind::Http);

        let listed = dispatch_events_extension(&ctx, &services, list_op()).await;
        assert_eq!(listed.http_status, 200);
        match listed.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                assert_eq!(success.id, json!(4));
                assert_eq!(success.result["resultType"], "complete");
                assert_eq!(success.result["events"][0]["name"], "orders.created");
                assert_eq!(success.result["events"][0]["delivery"], json!(["webhook"]));
            }
            other => panic!("expected success, got {other:?}"),
        }

        let subscribed = dispatch_events_extension(&ctx, &services, subscribe_op()).await;
        match subscribed.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                assert_eq!(success.id, json!("s-1"));
                assert_eq!(success.result["id"], "sub_1");
                assert_eq!(success.result["cursor"], Value::Null);
            }
            other => panic!("expected success, got {other:?}"),
        }

        let unsubscribe = EventsExtensionOperation::Unsubscribe {
            request_id: json!(5),
            params: serde_json::from_value(
                json!({ "name": "orders.created", "delivery": { "url": "https://h.example/hook" } }),
            )
            .unwrap(),
        };
        let unsubscribed = dispatch_events_extension(&ctx, &services, unsubscribe).await;
        match unsubscribed.response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                assert_eq!(success.result, json!({ "resultType": "complete" }));
            }
            other => panic!("expected success, got {other:?}"),
        }

        assert_eq!(
            *core.seen.lock().unwrap(),
            vec![
                "list None".to_owned(),
                "subscribe orders.created".to_owned(),
                "unsubscribe orders.created".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn poll_reaches_the_core_and_renders_its_refusal() {
        let services = services(true);
        let core = install(&services, ScriptedCore::default());
        let poll = EventsExtensionOperation::Poll {
            request_id: json!(6),
            params: serde_json::from_value(json!({ "name": "orders.created" })).unwrap(),
        };
        let response =
            dispatch_events_extension(&context(TransportKind::Http), &services, poll).await;
        assert_eq!(response.http_status, 200);
        let (code, data, _) = error_body(&response);
        assert_eq!(code, -32014);
        assert_eq!(
            data,
            Some(json!({ "feature": "deliveryMode", "value": "poll" }))
        );
        assert_eq!(
            *core.seen.lock().unwrap(),
            vec!["poll orders.created".to_owned()]
        );
    }

    #[tokio::test]
    async fn core_errors_keep_their_code_data_and_status() {
        let cases = [
            (EventsError::invalid_params("bad url"), 400, -32602),
            (
                EventsError::forbidden(ForbiddenReason::Unauthenticated),
                403,
                -32012,
            ),
            (EventsError::not_found(NotFoundKind::Event), 200, -32011),
            (
                EventsError::resource_exhausted("subscriptions", Some(100)),
                200,
                RESOURCE_EXHAUSTED_CODE,
            ),
            (EventsError::unsupported_delivery_mode("push"), 200, -32014),
            (
                EventsError::callback_endpoint(DeliveryErrorCategory::Timeout),
                200,
                -32015,
            ),
            (EventsError::internal("store unavailable"), 503, -32603),
        ];
        for (error, status, code) in cases {
            let services = services(true);
            install(
                &services,
                ScriptedCore {
                    fail_with: Some(error.clone()),
                    ..Default::default()
                },
            );
            let response =
                dispatch_events_extension(&context(TransportKind::Http), &services, subscribe_op())
                    .await;
            assert_eq!(response.http_status, status, "{error}");
            let (got_code, data, id) = error_body(&response);
            assert_eq!(got_code, code);
            assert_eq!(data.as_ref(), error.data());
            assert_eq!(id, Some(json!("s-1")));
        }
    }

    #[tokio::test]
    async fn the_sep_3415_numbering_moves_only_the_events_codes() {
        let cases = [
            (EventsError::not_found(NotFoundKind::Event), 200, -32023),
            (
                EventsError::forbidden(ForbiddenReason::Unauthenticated),
                403,
                -32024,
            ),
            (
                EventsError::resource_exhausted("subscriptions", Some(100)),
                200,
                -32025,
            ),
            (EventsError::unsupported_delivery_mode("push"), 200, -32026),
            (
                EventsError::callback_endpoint(DeliveryErrorCategory::Timeout),
                200,
                -32027,
            ),
            (EventsError::invalid_params("bad url"), 400, -32602),
            (EventsError::internal("store unavailable"), 503, -32603),
        ];
        for (error, status, code) in cases {
            let mut config = AppConfig::default();
            config.mcp.configurations.events.enabled = true;
            config.mcp.configurations.events.error_codes =
                crate::config::events::EventErrorCodes::Sep3415;
            let services = SharedServices::with_no_runtime(Arc::new(config));
            install(
                &services,
                ScriptedCore {
                    fail_with: Some(error.clone()),
                    ..Default::default()
                },
            );
            let response =
                dispatch_events_extension(&context(TransportKind::Http), &services, subscribe_op())
                    .await;
            assert_eq!(response.http_status, status, "{error}");
            let (got_code, data, _) = error_body(&response);
            assert_eq!(got_code, code);
            assert_eq!(data.as_ref(), error.data());
        }
    }

    #[test]
    fn a_second_install_is_refused() {
        let slot = EventsHandlerSlot::default();
        assert!(!slot.is_installed());
        slot.install(Arc::new(ScriptedCore::default()))
            .unwrap_or_else(|_| panic!("first install"));
        assert!(slot.is_installed());
        assert!(slot.install(Arc::new(ScriptedCore::default())).is_err());
        assert_eq!(format!("{slot:?}"), "EventsHandlerSlot { installed: true }");
    }
}
