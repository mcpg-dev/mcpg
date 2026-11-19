use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;

use super::super::*;
use crate::protocol::{
    CompletionCompleteParams, CompletionResult, JSONRPC_VERSION, JsonRpcSuccess,
    ProtocolHttpResponse, ProtocolResponse,
};

/// Entries the completion limiter holds before an insert drops the idle
/// ones.
const COMPLETION_LIMITER_PRUNE_AT: usize = 4_096;

/// A token bucket refills to its cap within this long, so an entry idle for
/// it is in the state a new entry starts in.
const COMPLETION_BUCKET_REFILL: Duration = Duration::from_secs(1);

impl GatewayRuntime {
    pub(crate) async fn handle_completion(
        &self,
        request_id: Value,
        params: CompletionCompleteParams,
        request_context: &RequestContext,
    ) -> ProtocolHttpResponse {
        // The per-principal completion rate limit runs before plugins and
        // the registry lookup, so a noisy autocomplete UI cannot DoS the
        // surface.
        if !self.allow_completion(&request_context.identity) {
            metrics::counter!("mcpg_completion_rate_limited_total").increment(1);
            return protocol_http_error(
                429,
                Some(request_id),
                -32099,
                "completion rate limit exceeded",
                None,
            );
        }
        // The registry takes the full completion params (ref, argument,
        // context), so it honors `context.arguments` for prompt completions
        // and serves `ref/resource` from the compiled template catalog.
        // Surface-aware gate plugins run before any value is served.
        let (backend_name, federation) = self.completion_subject(&params.reference);
        let args_value = serde_json::to_value(&params.argument).unwrap_or(serde_json::json!({}));
        let route = PolicyRoute::served_by(federation.as_deref());
        let route = match params.reference.ref_type.as_str() {
            "ref/prompt" => route.on(PolicySurface::Prompt),
            "ref/resource" => route.on(PolicySurface::Resource),
            _ => route,
        };
        if let Err(gate_response) = self
            .evaluate_surface_gate(
                "completion",
                "completion.complete.pre",
                &backend_name,
                route,
                &args_value,
                request_context,
                &request_id,
            )
            .await
        {
            return gate_response;
        }
        let mut result = self.capability_registry.complete_argument(&params);
        // Third tier: dynamic resource template completion. Dispatched when
        // (a) the static path returned no values and (b) the operator
        // declared `variable_completions: { var: { kind: dynamic, … } }` for
        // this template+variable. Backend errors and missing-plugin lookups
        // degrade silently to the empty result already in `result` —
        // completion is a UX hint, not load-bearing.
        if result.values.is_empty()
            && let Some(dyn_entry) = self.capability_registry.dynamic_completion_target(&params)
            && let Some(plugin) = self.plugin_registry.backend(&dyn_entry.kind)
        {
            const DYNAMIC_COMPLETION_TIMEOUT_MS: u64 = 3_000;
            // Forward the MCP completion `context.arguments` to the backend
            // so it can do owner-scoped lookups (`SELECT … WHERE owner =
            // :ctx_owner …`). The static path above already filtered these
            // values for the variable as a fallback; here the plugin gets
            // the raw map.
            let context_args = params
                .context
                .as_ref()
                .map(|c| c.arguments.clone())
                .unwrap_or_default();
            let fut = plugin.complete_template_variable(
                &dyn_entry.backend_name,
                &params.argument.name,
                &params.argument.value,
                &dyn_entry.config,
                &context_args,
            );
            match tokio::time::timeout(Duration::from_millis(DYNAMIC_COMPLETION_TIMEOUT_MS), fut)
                .await
            {
                Ok(Ok(values)) => {
                    result = crate::backends::clamp_completion_values(values);
                }
                Ok(Err(e)) => {
                    warn!(
                        backend = %dyn_entry.backend_name,
                        kind = %dyn_entry.kind,
                        error = %e,
                        "completion/complete: dynamic dispatch failed; returning empty"
                    );
                }
                Err(_) => {
                    warn!(
                        backend = %dyn_entry.backend_name,
                        kind = %dyn_entry.kind,
                        timeout_ms = DYNAMIC_COMPLETION_TIMEOUT_MS,
                        "completion/complete: dynamic dispatch timed out; returning empty"
                    );
                }
            }
        }
        // Audit: completion/complete.
        let audit_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: backend_name.clone(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
            surface: "completion".to_owned(),
        };
        let event = mcpg_plugin_host::audit_events::completion_requested_event(
            &audit_ctx,
            &params.reference.ref_type,
            &backend_name,
            &params.argument.name,
            result.values.len() as u64,
        )
        .with_upstream_request_id(request_context.upstream_request_id.clone());
        let _ = self.plugin_registry.emit_audit_event(&event).await;
        ProtocolHttpResponse {
            http_status: 200,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id,
                result: serde_json::to_value(CompletionResult { completion: result })
                    .expect("completion result serialized"),
            }),
        }
    }

    /// The name a completion is gated under, and the federation that serves
    /// it: the prompt a `ref/prompt` names or the URI template a
    /// `ref/resource` names, the same field `complete_argument` completes
    /// from. A reference may carry both fields, and gating the one it does
    /// not complete from would let a lenient name unlock a strict template.
    fn completion_subject(
        &self,
        reference: &crate::protocol::CompletionReference,
    ) -> (String, Option<String>) {
        match reference.ref_type.as_str() {
            "ref/prompt" => match &reference.name {
                Some(name) => {
                    let federation = self
                        .capability_registry
                        .prompt_route(name)
                        .and_then(|route| route.federation().map(str::to_owned));
                    (name.clone(), federation)
                }
                None => (reference.ref_type.clone(), None),
            },
            "ref/resource" => match &reference.uri {
                Some(uri) => {
                    let federation = self
                        .capability_registry
                        .resource_templates_with_source()
                        .into_iter()
                        .find(|(template, _)| &template.uri_template == uri)
                        .and_then(|(_, federation)| federation);
                    (uri.clone(), federation)
                }
                None => (reference.ref_type.clone(), None),
            },
            _ => (
                reference
                    .name
                    .clone()
                    .or_else(|| reference.uri.clone())
                    .unwrap_or_else(|| reference.ref_type.clone()),
                None,
            ),
        }
    }

    /// Configure the per-principal completion rate limit.
    pub fn set_completion_rate_limit(&mut self, per_sec: Option<u64>) {
        self.completion_rate_limit_per_sec = per_sec;
    }

    /// Per-principal token-bucket check for completion/complete.
    /// Returns true when the caller is allowed to proceed.
    fn allow_completion(&self, identity: &RequestIdentity) -> bool {
        match self.completion_rate_limit_per_sec {
            None | Some(0) => true,
            Some(cap) => take_completion_token(
                &self.completion_limiter,
                completion_limiter_key(identity),
                cap,
                Instant::now(),
            ),
        }
    }
}

/// The bucket a caller's completions draw from: its principal key, or one
/// bucket every anonymous caller shares. A per-request id would give every
/// anonymous request a fresh bucket, which neither limits nor stays bounded.
fn completion_limiter_key(identity: &RequestIdentity) -> String {
    identity
        .synthetic_principal_key()
        .unwrap_or_else(|| "anon".to_owned())
}

/// Take one token from `key`'s bucket of `cap` tokens per second; `false`
/// when the bucket is empty.
fn take_completion_token(
    limiter: &DashMap<String, (u64, Instant)>,
    key: String,
    cap: u64,
    now: Instant,
) -> bool {
    if limiter.len() >= COMPLETION_LIMITER_PRUNE_AT && !limiter.contains_key(&key) {
        limiter.retain(|_, (_, last)| now.duration_since(*last) < COMPLETION_BUCKET_REFILL);
    }
    let mut entry = limiter.entry(key).or_insert((cap, now));
    let (tokens, last) = entry.value_mut();
    let elapsed = now.duration_since(*last).as_secs_f64();
    let refill = (elapsed * cap as f64).floor() as u64;
    if refill > 0 {
        *tokens = tokens.saturating_add(refill).min(cap);
        *last = now;
    }
    if *tokens == 0 {
        return false;
    }
    *tokens -= 1;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anonymous() -> RequestIdentity {
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        }
    }

    #[test]
    fn anonymous_callers_share_one_bucket() {
        assert_eq!(completion_limiter_key(&anonymous()), "anon");
    }

    /// Anonymous requests each carry a fresh ephemeral session id; none of
    /// them adds an entry to the limiter.
    #[test]
    fn anonymous_completions_leave_the_limiter_map_bounded() {
        let limiter = DashMap::new();
        let now = Instant::now();
        for _ in 0..10_000 {
            take_completion_token(
                &limiter,
                completion_limiter_key(&anonymous()),
                1_000_000,
                now,
            );
        }
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn the_bucket_refuses_once_empty_and_refills() {
        let limiter = DashMap::new();
        let start = Instant::now();
        assert!(take_completion_token(&limiter, "p".to_owned(), 2, start));
        assert!(take_completion_token(&limiter, "p".to_owned(), 2, start));
        assert!(!take_completion_token(&limiter, "p".to_owned(), 2, start));
        // Another principal draws from its own bucket.
        assert!(take_completion_token(&limiter, "q".to_owned(), 2, start));
        assert!(take_completion_token(
            &limiter,
            "p".to_owned(),
            2,
            start + COMPLETION_BUCKET_REFILL
        ));
    }

    /// Past the prune threshold, a new key drops the buckets idle long
    /// enough to have refilled, and keeps the active ones.
    #[test]
    fn a_full_limiter_drops_idle_buckets() {
        let limiter = DashMap::new();
        let start = Instant::now();
        for i in 0..COMPLETION_LIMITER_PRUNE_AT {
            take_completion_token(&limiter, format!("idle-{i}"), 5, start);
        }
        let later = start + COMPLETION_BUCKET_REFILL;
        take_completion_token(&limiter, "active".to_owned(), 5, later);
        assert_eq!(limiter.len(), 1);
        assert!(limiter.contains_key("active"));
    }
}
