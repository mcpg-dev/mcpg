use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) enum RetrySafetyContext {
    ReadOnlyProbe,
    PotentiallyNonIdempotentJsonCall,
}

pub(super) const DEFAULT_BACKOFF_BASE_MS: u64 = 1_000;

/// Classify whether an errored `ToolCallResult` is retryable under `rc`.
///
/// A downstream error that carries a structured `retryable` / `kind` /
/// `statusCode` field has already classified itself, and that classification
/// is authoritative — the transport-word text heuristic runs only for
/// genuinely unstructured error text (legacy plugins / opaque failures). This
/// ordering stops an incidental word (`"connection refused — do not retry"`)
/// from flipping an explicit `retryable:false` back to retryable.
pub(super) fn error_result_is_retryable(
    result: &ToolCallResult,
    rc: &crate::config::RetryConfig,
) -> bool {
    for content in &result.content {
        let text = match content {
            ToolContent::Text { text, .. } => text,
            _ => continue,
        };
        if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(text) {
            let is_classified = error_data.get("retryable").is_some()
                || error_data.get("kind").is_some()
                || error_data.get("statusCode").is_some();
            // Explicit downstream classification.
            if error_data.get("retryable") == Some(&serde_json::Value::Bool(true)) {
                return true;
            }
            if let Some(status) = error_data.get("statusCode").and_then(|v| v.as_u64())
                && rc.retry_on_status_codes.contains(&(status as u16))
            {
                return true;
            }
            if rc.retry_on_transport_error
                && let Some(kind) = error_data.get("kind").and_then(|v| v.as_str())
                && kind == "transport_error"
            {
                return true;
            }
            // The error classified itself and did not signal retryable — trust
            // it and do not fall through to the text heuristic.
            if is_classified {
                continue;
            }
        }
        // Unstructured error text: transport-word heuristic fallback.
        if rc.retry_on_transport_error
            && (text.contains("connection")
                || text.contains("timeout")
                || text.contains("transport"))
        {
            return true;
        }
    }
    false
}

pub(super) fn with_retry_guidance(
    mut error: DownstreamHttpError,
    retry_safety_context: RetrySafetyContext,
) -> DownstreamHttpError {
    let idempotency_hint = match retry_safety_context {
        RetrySafetyContext::ReadOnlyProbe => "idempotent_read_only",
        RetrySafetyContext::PotentiallyNonIdempotentJsonCall => "potentially_non_idempotent",
    };

    if !error.retryable {
        error.idempotency_hint = idempotency_hint.to_owned();
        error.caller_retry_decision = "do_not_retry".to_owned();
        error.retry_safety = "do_not_retry".to_owned();
        error.backoff_strategy = "no_retry".to_owned();
        error.minimum_backoff_ms = None;
        return error;
    }

    let (retry_safety, suggested_action, caller_retry_decision) = match retry_safety_context {
        RetrySafetyContext::ReadOnlyProbe => {
            let decision = if error.retry_after_ms.is_some() {
                "automatic_retry_after_delay"
            } else {
                "automatic_retry_with_backoff"
            };
            (
                "safe_for_automatic_retry",
                error.suggested_action.clone(),
                decision.to_owned(),
            )
        }
        RetrySafetyContext::PotentiallyNonIdempotentJsonCall => {
            let (action, decision) = if error.retry_after_ms.is_some() {
                (
                    "review_idempotency_then_retry_after_delay",
                    "confirm_idempotency_then_retry_after_delay",
                )
            } else {
                (
                    "review_idempotency_then_retry_with_backoff",
                    "confirm_idempotency_then_retry_with_backoff",
                )
            };
            (
                "review_idempotency_before_retry",
                action.to_owned(),
                decision.to_owned(),
            )
        }
    };

    let (backoff_strategy, minimum_backoff_ms) = if let Some(retry_after_ms) = error.retry_after_ms
    {
        ("respect_retry_after", Some(retry_after_ms))
    } else {
        ("exponential_backoff", Some(DEFAULT_BACKOFF_BASE_MS))
    };

    error.idempotency_hint = idempotency_hint.to_owned();
    error.caller_retry_decision = caller_retry_decision;
    error.retry_safety = retry_safety.to_owned();
    error.backoff_strategy = backoff_strategy.to_owned();
    error.minimum_backoff_ms = minimum_backoff_ms;
    error.suggested_action = suggested_action;
    error
}

pub(super) fn parse_retry_after_ms(value: &str) -> Option<u64> {
    let seconds = value.parse::<u64>().ok()?;
    seconds.checked_mul(1_000)
}
