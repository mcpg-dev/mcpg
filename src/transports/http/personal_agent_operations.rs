//! The Personal Agent Protocol operations endpoint (`/poppy/operations`):
//! read, confirm and cancel an operation with a DPoP Session Token
//! (operations §5, §6 and §7).

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;

use super::response::sanitize_header_quotes;
use super::*;
use crate::config::personal_agent::OPERATIONS_PATH;
use crate::runtime::authorization_server::dpop::{DPOP_JKT_ATTRIBUTE, DPOP_SCHEME};
use crate::runtime::personal_agent::PersonalAgentCaller;
use crate::runtime::personal_agent_operations::{
    ApprovedBy, ConfirmOutcome, OperationError, OperationRecord,
};

/// How long a Personal Agent waits before it reads an `in_progress`
/// operation again.
const RETRY_AFTER_SECS: u64 = 2;

/// A confirm request (operations §5.2).
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    revision: u32,
    approved_by: ApprovedBy,
}

/// `GET /poppy/operations/{operation_id}`.
pub(crate) async fn pap_operation_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    axum::extract::Path(operation_id): axum::extract::Path<String>,
) -> Response {
    let path = format!("{OPERATIONS_PATH}/{operation_id}");
    let (runtime, _ctx, caller) = match operations_caller(
        &state,
        &headers,
        tls_info,
        &axum::http::Method::GET,
        &path,
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(operations) = runtime.pap_operations() else {
        return error_response(StatusCode::NOT_FOUND, "operation_not_found", None);
    };
    match operations.read(&operation_id, &caller).await {
        Ok(record) => operation_response(&record),
        Err(error) => operation_error_response(error),
    }
}

/// `POST /poppy/operations/{operation_id}/confirm`.
pub(crate) async fn pap_operation_confirm_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    axum::extract::Path(operation_id): axum::extract::Path<String>,
    body: Bytes,
) -> Response {
    let path = format!("{OPERATIONS_PATH}/{operation_id}/confirm");
    let (runtime, ctx, caller) =
        match operations_caller(&state, &headers, tls_info, &axum::http::Method::POST, &path).await
        {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let Some(operations) = runtime.pap_operations() else {
        return error_response(StatusCode::NOT_FOUND, "operation_not_found", None);
    };
    let request: ConfirmBody = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(json!({ "error_description": format!("the body is not a confirm: {error}") })),
            );
        }
    };
    // Operations §5.2: the Session may use it, then the tool's scopes.
    let record = match operations.read(&operation_id, &caller).await {
        Ok(record) => record,
        Err(error) => return operation_error_response(error),
    };
    if record.state == crate::runtime::personal_agent_operations::OperationState::Proposed
        && let Some(denial) = runtime.pap_operation_policy_denial(&record.tool, &ctx)
    {
        return denial_response(&state, &runtime, &caller, &denial);
    }
    let confirmed = match operations
        .confirm(
            &operation_id,
            &caller,
            request.revision,
            request.approved_by,
        )
        .await
    {
        Ok(ConfirmOutcome::AsIs(record)) => return operation_response(&record),
        Ok(ConfirmOutcome::Run(record)) => record,
        Err(error) => return operation_error_response(error),
    };
    runtime
        .audit_pap_operation(&ctx, "confirmed", &confirmed)
        .await;
    let wait = Duration::from_secs(operations.config().confirm_wait_secs);
    let running = std::sync::Arc::clone(&runtime);
    let execution =
        tokio::spawn(async move { running.execute_pap_operation(confirmed, ctx).await });
    match tokio::time::timeout(wait, execution).await {
        Ok(Ok(Ok(finished))) => operation_response(&finished),
        Ok(Ok(Err(error))) => operation_error_response(error),
        // Still running, or the task ended without recording: what the
        // store says now.
        _ => match operations.read(&operation_id, &caller).await {
            Ok(record) => operation_response(&record),
            Err(error) => operation_error_response(error),
        },
    }
}

/// `POST /poppy/operations/{operation_id}/cancel`.
pub(crate) async fn pap_operation_cancel_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    tls_info: TlsInfoExt,
    axum::extract::Path(operation_id): axum::extract::Path<String>,
) -> Response {
    let path = format!("{OPERATIONS_PATH}/{operation_id}/cancel");
    let (runtime, ctx, caller) =
        match operations_caller(&state, &headers, tls_info, &axum::http::Method::POST, &path).await
        {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let Some(operations) = runtime.pap_operations() else {
        return error_response(StatusCode::NOT_FOUND, "operation_not_found", None);
    };
    match operations.cancel(&operation_id, &caller).await {
        Ok(record) => {
            if record.state == crate::runtime::personal_agent_operations::OperationState::Cancelled
            {
                runtime
                    .audit_pap_operation(&ctx, "cancelled", &record)
                    .await;
            }
            operation_response(&record)
        }
        Err(error) => operation_error_response(error),
    }
}

/// The verified Personal Agent of an operations request, with a DPoP
/// Session Token: the endpoint takes no other (PAP §4.3).
async fn operations_caller(
    state: &AppState,
    headers: &HeaderMap,
    tls_info: TlsInfoExt,
    method: &axum::http::Method,
    path: &str,
) -> Result<
    (
        std::sync::Arc<crate::runtime::GatewayRuntime>,
        RequestContext,
        PersonalAgentCaller,
    ),
    Response,
> {
    let runtime = state.runtime.load_full();
    if runtime.pap_operations().is_none() {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "operation_not_found",
            None,
        ));
    }
    let config = state.config.load();
    let ctx = build_full_request_context(
        headers,
        &runtime,
        tls_info.into_inner(),
        config.gateway.server.trust_subject_header,
        method,
        Some(path),
        None,
    )
    .await?;
    if !ctx.identity.attributes().contains_key(DPOP_JKT_ATTRIBUTE) {
        let algs = runtime
            .dpop_challenge()
            .map(|dpop| dpop.algs.to_owned())
            .unwrap_or_default();
        let mut response = error_response(StatusCode::UNAUTHORIZED, "invalid_token", None);
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{DPOP_SCHEME} error=\"invalid_token\", error_description=\"the operations endpoint \
             takes DPoP Session Tokens\", algs=\"{algs}\""
        )) {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, value);
        }
        return Err(response);
    }
    let Some(caller) = ctx
        .personal_agent
        .clone()
        .filter(PersonalAgentCaller::is_personal_agent)
    else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "operation_not_found",
            None,
        ));
    };
    Ok((runtime, ctx, caller))
}

/// The operation, with `Retry-After` while it is `in_progress`.
fn operation_response(record: &OperationRecord) -> Response {
    let mut response = (StatusCode::OK, axum::Json(record.wire())).into_response();
    if record.state == crate::runtime::personal_agent_operations::OperationState::InProgress {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from(RETRY_AFTER_SECS),
        );
    }
    response
}

fn operation_error_response(error: OperationError) -> Response {
    match error {
        OperationError::NotFound => {
            error_response(StatusCode::NOT_FOUND, "operation_not_found", None)
        }
        OperationError::TermsChanged(record) => error_response(
            StatusCode::CONFLICT,
            "terms_changed",
            Some(json!({ "operation": record.wire() })),
        ),
        OperationError::UserApprovalRequired => {
            error_response(StatusCode::FORBIDDEN, "user_approval_required", None)
        }
        OperationError::Unavailable(reason) | OperationError::Template(reason) => {
            tracing::warn!(reason = %reason, "an operations request could not be served");
            let mut response = error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            );
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, HeaderValue::from(1u64));
            response
        }
    }
}

/// A confirm the tool's access rules refuse: `sign_in_required` for a
/// signed-out Session, `insufficient_scope` with the missing scopes for a
/// signed-in one (PAP §6), in the DPoP scheme; any other refusal a bare
/// 403.
fn denial_response(
    state: &AppState,
    runtime: &crate::runtime::GatewayRuntime,
    caller: &PersonalAgentCaller,
    denial: &crate::runtime::policy::PolicyDenial,
) -> Response {
    let Some(missing) = &denial.insufficient_scope else {
        return error_response(StatusCode::FORBIDDEN, "access_denied", None);
    };
    let config = state.config.load();
    let metadata = sanitize_header_quotes(&resource_metadata_url(&config, None));
    let algs = runtime
        .dpop_challenge()
        .map(|dpop| dpop.algs.to_owned())
        .unwrap_or_default();
    let (error, challenge) = if caller.signed_in {
        let scope = sanitize_header_quotes(&missing.join(" "));
        (
            "insufficient_scope",
            format!(
                "{DPOP_SCHEME} resource_metadata=\"{metadata}\", error=\"insufficient_scope\", \
                 scope=\"{scope}\", algs=\"{algs}\""
            ),
        )
    } else {
        (
            "sign_in_required",
            format!(
                "{DPOP_SCHEME} resource_metadata=\"{metadata}\", error=\"sign_in_required\", \
                 algs=\"{algs}\""
            ),
        )
    };
    let mut response = error_response(StatusCode::FORBIDDEN, error, None);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

/// A JSON error of the operations endpoint: `{ "error": … }` and `extra`'s
/// members.
fn error_response(status: StatusCode, error: &str, extra: Option<Value>) -> Response {
    let mut body = json!({ "error": error });
    if let Some(Value::Object(extra)) = extra {
        for (name, value) in extra {
            body[name] = value;
        }
    }
    (status, axum::Json(body)).into_response()
}
