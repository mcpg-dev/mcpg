use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::app::AppState;
use crate::config::{AdminConfig, AuditOnFailure, DisclosureLevel};
use crate::runtime::GatewayRuntime;
use crate::runtime::session_store::SessionStore;

/// Map the gateway config's `AuditOnFailure` onto plugin-host's
/// policy enum. Trivial one-to-one; lives here so the admin
/// service stays the single converter.
fn audit_policy(cfg: AuditOnFailure) -> mcpg_plugin_host::AuditEmitPolicy {
    match cfg {
        AuditOnFailure::FailClosed => mcpg_plugin_host::AuditEmitPolicy::FailClosed,
        AuditOnFailure::FailOpen => mcpg_plugin_host::AuditEmitPolicy::FailOpen,
    }
}

/// Thin facade over existing runtime subsystems for admin inspection.
pub struct AdminService {
    session_store: Arc<dyn SessionStore>,
    runtime: Arc<ArcSwap<GatewayRuntime>>,
    config: AdminConfig,
    /// Copied from `config.governance.audit.on_failure` at
    /// construction so the admin service can honour the operator
    /// policy without threading the whole plugins config through.
    audit_on_failure: AuditOnFailure,
    /// Live `AppState` clone — required by [`Self::reload_config`]
    /// to call into `crate::app::reload_config`, which needs the
    /// `config_paths`, the `ArcSwap<AppConfig>`, the policy chain,
    /// and the rest of the bookkeeping the SIGHUP path mutates.
    /// `AppState` is `Clone` (every field is an `Arc`), so this is a
    /// cheap aliasing handle, not a deep copy.
    app_state: AppState,
}

impl AdminService {
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        runtime: Arc<ArcSwap<GatewayRuntime>>,
        config: AdminConfig,
        audit_on_failure: AuditOnFailure,
        app_state: AppState,
    ) -> Self {
        Self {
            session_store,
            runtime,
            config,
            audit_on_failure,
            app_state,
        }
    }

    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    /// GET /admin/v1/health
    pub fn health(&self) -> AdminHealthResponse {
        AdminHealthResponse {
            status: "ok".to_owned(),
        }
    }

    /// GET /admin/v1/readiness
    pub fn readiness(&self) -> ReadinessResponse {
        let rt = self.runtime.load();
        ReadinessResponse {
            ready: true,
            uptime_secs: rt.uptime_secs(),
            session_count: self.session_store.active_session_count(),
        }
    }

    /// GET /admin/v1/sessions
    pub fn list_sessions(&self) -> Vec<SessionSummary> {
        let snapshots = self.session_store.list_sessions();
        snapshots
            .into_iter()
            .map(|s| SessionSummary {
                session_id: s.session_id.clone(),
                phase: format!("{:?}", s.phase),
                created_at: s.created_at,
                log_level: format!("{:?}", s.log_level),
                subject_id: match self.config.disclosure {
                    DisclosureLevel::Summary => None,
                    _ => Some(s.session_id.clone()),
                },
            })
            .collect()
    }

    /// GET /admin/v1/sessions/{id}
    pub fn get_session(&self, session_id: &str) -> Option<SessionSummary> {
        let snapshots = self.session_store.list_sessions();
        snapshots
            .into_iter()
            .find(|s| s.session_id == session_id)
            .map(|s| SessionSummary {
                session_id: s.session_id.clone(),
                phase: format!("{:?}", s.phase),
                created_at: s.created_at,
                log_level: format!("{:?}", s.log_level),
                subject_id: match self.config.disclosure {
                    DisclosureLevel::Summary => None,
                    _ => Some(s.session_id.clone()),
                },
            })
    }

    /// POST /admin/v1/sessions/{id}:terminate
    ///
    /// delegate to the runtime's terminate path so resource
    /// subscriptions are cleared and non-terminal tasks are cancelled.
    /// Calling `session_store.terminate_session` directly would leave
    /// subscription fan-out and background task work dangling on the
    /// node that hosted the session.
    pub fn terminate_session(&self, session_id: &str) -> bool {
        self.runtime.load().terminate_session(session_id)
    }

    /// GET /admin/v1/bindings
    pub fn list_bindings(&self) -> Vec<BackendSummary> {
        let rt = self.runtime.load();
        rt.binding_summaries()
    }

    /// GET /admin/v1/bindings/{id}
    pub fn get_binding(&self, name: &str) -> Option<BackendSummary> {
        let rt = self.runtime.load();
        rt.binding_summaries().into_iter().find(|b| b.name == name)
    }

    /// GET /admin/v1/runtime
    pub fn runtime_info(&self) -> RuntimeInfoResponse {
        let rt = self.runtime.load();
        RuntimeInfoResponse {
            uptime_secs: rt.uptime_secs(),
            session_count: self.session_store.active_session_count(),
        }
    }

    /// GET /admin/v1/plugins
    pub fn list_plugins(&self) -> PluginListResponse {
        let rt = self.runtime.load();
        PluginListResponse {
            plugins: rt.plugin_summaries(),
        }
    }

    /// POST /admin/v1/plugins/:id:disable
    ///
    /// Flip a registered plugin into the `Disabled` state. The
    /// plugin's artifact stays loaded; chain evaluation and binding
    /// / watch-strategy lookups skip disabled entries until the
    /// next `enable`. Errors if the plugin is not registered or is
    /// in a state that cannot transition to Disabled.
    pub async fn disable_plugin(&self, id: &str) -> PluginOpResult {
        let rt = self.runtime.load();
        let result = rt.plugin_registry().disable(id);
        let (ok, error) = match &result {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let audit_error = self
            .emit_admin_audit(
                &rt,
                "mcpg.admin.plugin_disabled",
                id,
                if ok {
                    mcpg_plugin_protocol::audit::AuditOutcome::Success
                } else {
                    mcpg_plugin_protocol::audit::AuditOutcome::Failure
                },
                serde_json::json!({ "error": error.clone() }),
            )
            .await
            .err();
        PluginOpResult {
            ok,
            plugin_id: id.to_owned(),
            state: rt
                .plugin_registry()
                .lifecycle_state(id)
                .map(|s| s.to_string())
                .unwrap_or_default(),
            error,
            audit_error,
        }
    }

    /// POST /admin/v1/plugins/:id:enable
    ///
    /// Re-enable a previously disabled plugin. Errors if the plugin
    /// is not registered or is not currently disabled.
    pub async fn enable_plugin(&self, id: &str) -> PluginOpResult {
        let rt = self.runtime.load();
        let result = rt.plugin_registry().enable(id);
        let (ok, error) = match &result {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let audit_error = self
            .emit_admin_audit(
                &rt,
                "mcpg.admin.plugin_enabled",
                id,
                if ok {
                    mcpg_plugin_protocol::audit::AuditOutcome::Success
                } else {
                    mcpg_plugin_protocol::audit::AuditOutcome::Failure
                },
                serde_json::json!({ "error": error.clone() }),
            )
            .await
            .err();
        PluginOpResult {
            ok,
            plugin_id: id.to_owned(),
            state: rt
                .plugin_registry()
                .lifecycle_state(id)
                .map(|s| s.to_string())
                .unwrap_or_default(),
            error,
            audit_error,
        }
    }

    /// Fan an admin-action audit event out to every registered
    /// audit sink + honour the operator's `on_failure` policy.
    /// Called from every admin mutation path — every operator
    /// action that changes gateway state is compliance-relevant
    /// (SOC2: "record of privileged actions").
    ///
    /// Returns `Ok(())` when:
    ///   - every sink accepted the event, OR
    ///   - a sink failed but policy is `FailOpen`.
    ///
    /// Returns `Err(<human-readable summary>)` when policy is
    /// `FailClosed` and at least one sink failed. Callers attach
    /// the summary to the response body as `audit_error` so
    /// operators see precisely which sinks were broken. The
    /// mutation is NOT rolled back — by the time audit emits, the
    /// registry state has already changed; operators reconcile
    /// manually when the alarm fires.
    async fn emit_admin_audit(
        &self,
        rt: &crate::runtime::GatewayRuntime,
        action: &str,
        plugin_id: &str,
        outcome: mcpg_plugin_protocol::audit::AuditOutcome,
        details: serde_json::Value,
    ) -> Result<(), String> {
        let event = mcpg_plugin_host::audit_events::admin_event(
            mcpg_plugin_host::audit_events::system_identity(),
            action,
            plugin_id,
            outcome,
            details,
        );
        match rt
            .plugin_registry()
            .emit_audit_event_enforced(&event, audit_policy(self.audit_on_failure))
            .await
        {
            Ok(_) => Ok(()),
            Err(failure) => Err(failure.to_string()),
        }
    }

    /// GET /admin/v1/plugins/:id
    ///
    /// Return full detail for a single registered plugin: manifest,
    /// current state, tier, registration timestamp, in-flight call
    /// count, and config (redacted). `None` if no plugin with that id
    /// is registered — the handler converts to 404.
    pub fn get_plugin(&self, id: &str) -> Option<PluginDetailResponse> {
        let rt = self.runtime.load();
        let detail = rt.plugin_registry().plugin_detail(id)?;
        Some(PluginDetailResponse {
            id: detail.id,
            version: detail.version,
            name: detail.name,
            plugin_class: detail.plugin_class,
            tier: detail.tier,
            protocol_version: detail.protocol_version,
            required_capabilities: detail.required_capabilities,
            state: detail.state,
            registered_at_unix_secs: detail.registered_at_unix_secs,
            inflight: detail.inflight,
            enforce: detail.enforce,
            config: redact_sensitive(detail.config),
        })
    }

    /// POST /admin/v1/plugins/:id:drain
    ///
    /// Flip a plugin to `Draining` and wait up to `timeout` for
    /// in-flight calls to finish. On a clean drain, transition the
    /// plugin to `Disabled` and return 200-shaped `DrainResult`. On
    /// timeout, leave the plugin in `Draining` — the operator can
    /// retry with a longer budget or call `:disable` to force.
    ///
    /// Drain is only defined for chain plugins (tool_gate, transform,
    /// identity_provider). Binding + watch-strategy plugins surface
    /// an `error` field; the caller falls back to `:disable`.
    pub async fn drain_plugin(&self, id: &str, timeout: std::time::Duration) -> DrainResult {
        let rt = self.runtime.load();
        let token = match rt.plugin_registry().mark_draining(id) {
            Ok(t) => t,
            Err(e) => {
                return DrainResult {
                    ok: false,
                    plugin_id: id.to_owned(),
                    outcome: "refused".to_owned(),
                    state: rt
                        .plugin_registry()
                        .lifecycle_state(id)
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    inflight_remaining: 0,
                    waited_ms: 0,
                    timeout_ms: timeout.as_millis() as u64,
                    error: Some(e.to_string()),
                };
            }
        };

        let started = std::time::Instant::now();
        let outcome = token.wait(timeout).await;
        let waited_ms = started.elapsed().as_millis() as u64;

        match outcome {
            mcpg_plugin_host::registry::DrainOutcome::Completed => {
                // Finalise: flip Draining → Disabled. If the state
                // already drifted (operator cancelled, prober raced),
                // the Err is informational — report via `error` but
                // keep `ok: true` so the operator sees the drain
                // itself worked.
                let finalise_err = rt.plugin_registry().mark_disabled_after_drain(id).err();
                DrainResult {
                    ok: true,
                    plugin_id: id.to_owned(),
                    outcome: "completed".to_owned(),
                    state: rt
                        .plugin_registry()
                        .lifecycle_state(id)
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    inflight_remaining: 0,
                    waited_ms,
                    timeout_ms: timeout.as_millis() as u64,
                    error: finalise_err.map(|e| e.to_string()),
                }
            }
            mcpg_plugin_host::registry::DrainOutcome::TimedOut { inflight } => DrainResult {
                ok: false,
                plugin_id: id.to_owned(),
                outcome: "timed_out".to_owned(),
                state: rt
                    .plugin_registry()
                    .lifecycle_state(id)
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                inflight_remaining: inflight,
                waited_ms,
                timeout_ms: timeout.as_millis() as u64,
                error: Some(format!(
                    "{inflight} in-flight call(s) still running after {waited_ms}ms",
                )),
            },
        }
    }

    /// POST /admin/v1/config:validate
    pub fn validate_config(&self, yaml: &str) -> ConfigValidationResult {
        match crate::config::AppConfig::load_from_yaml_str(yaml) {
            Ok(_) => ConfigValidationResult {
                valid: true,
                errors: vec![],
            },
            Err(e) => ConfigValidationResult {
                valid: false,
                errors: vec![e.to_string()],
            },
        }
    }

    /// POST /admin/v1/policy:preview — Compare candidate policy against baseline.
    pub fn policy_preview(
        &self,
        candidate_yaml: &str,
        test_cases: Vec<PolicyTestCase>,
    ) -> PolicyPreviewResult {
        let candidate_config = match crate::config::AppConfig::load_from_yaml_str(candidate_yaml) {
            Ok(c) => c,
            Err(e) => {
                return PolicyPreviewResult {
                    results: vec![],
                    summary: PolicyPreviewSummary {
                        total_cases: 0,
                        mismatches: 0,
                        additive: 0,
                        subtractive: 0,
                    },
                    error: Some(e.to_string()),
                };
            }
        };

        let rt = self.runtime.load();

        // Evaluate each test case against baseline (current runtime)
        let mut results = Vec::new();
        for case in &test_cases {
            let baseline_decision = rt.evaluate_policy_for_preview(&case.tool_name, &case.identity);
            let candidate_decision =
                Self::evaluate_candidate_policy(&candidate_config, &case.tool_name, &case.identity);
            let mismatch = baseline_decision != candidate_decision;
            let severity = if mismatch {
                if baseline_decision == "allow" && candidate_decision == "deny" {
                    "subtractive"
                } else if baseline_decision == "deny" && candidate_decision == "allow" {
                    "additive"
                } else {
                    "behavioral"
                }
            } else {
                "none"
            };

            results.push(PolicyComparisonResult {
                tool_name: case.tool_name.clone(),
                baseline_decision: baseline_decision.clone(),
                candidate_decision: candidate_decision.clone(),
                mismatch,
                severity: severity.to_owned(),
            });
        }

        let summary = PolicyPreviewSummary {
            total_cases: results.len(),
            mismatches: results.iter().filter(|r| r.mismatch).count(),
            additive: results.iter().filter(|r| r.severity == "additive").count(),
            subtractive: results
                .iter()
                .filter(|r| r.severity == "subtractive")
                .count(),
        };

        PolicyPreviewResult {
            results,
            summary,
            error: None,
        }
    }

    fn evaluate_candidate_policy(
        candidate_config: &crate::config::AppConfig,
        tool_name: &str,
        identity: &TestIdentity,
    ) -> String {
        use crate::runtime::RequestTrustLevel;
        use crate::runtime::policy::{
            PreDispatchPolicyGate, ToolAccessPolicyConfig, ToolTrustRule,
        };

        fn map_trust(tl: crate::config::TrustLevelConfig) -> RequestTrustLevel {
            match tl {
                crate::config::TrustLevelConfig::Unauthenticated => {
                    RequestTrustLevel::Unauthenticated
                }
                crate::config::TrustLevelConfig::HeaderAsserted => {
                    RequestTrustLevel::HeaderAsserted
                }
                crate::config::TrustLevelConfig::Verified => RequestTrustLevel::Verified,
            }
        }

        let mut rules: Vec<ToolTrustRule> = candidate_config
            .governance
            .policy
            .tool_access
            .rules
            .iter()
            .map(|r| ToolTrustRule {
                tool_name: r.tool_name.clone(),
                minimum_trust: map_trust(r.minimum_trust),
                cel_allow_if: r.cel_allow_if.clone(),
                required_scopes: r.required_scopes.clone(),
            })
            .collect();

        // Include binding governance rules (same as app::build_tool_access_policy_config)
        for (_, binding) in candidate_config.all_bindings() {
            rules.push(ToolTrustRule {
                tool_name: binding.name.clone(),
                minimum_trust: map_trust(binding.governance.minimum_trust),
                cel_allow_if: binding.governance.allow_if.clone(),
                required_scopes: Vec::new(),
            });
        }

        let policy_config = ToolAccessPolicyConfig {
            default_minimum_trust: map_trust(
                candidate_config
                    .governance
                    .policy
                    .tool_access
                    .default_minimum_trust,
            ),
            cel_allow_if: candidate_config
                .governance
                .policy
                .tool_access
                .cel_allow_if
                .clone(),
            rules,
        };

        let gate = match PreDispatchPolicyGate::try_new(policy_config) {
            Ok(g) => g,
            Err(_) => return "error".to_owned(),
        };

        let trust_level = match identity.trust_level.as_str() {
            "unauthenticated" => RequestTrustLevel::Unauthenticated,
            "header_asserted" => RequestTrustLevel::HeaderAsserted,
            "verified" => RequestTrustLevel::Verified,
            _ => RequestTrustLevel::Unauthenticated,
        };

        let policy_ctx = crate::runtime::policy::ToolPolicyContext {
            tool_name: tool_name.to_owned(),
            trust_level,
            principal_id: identity.subject_id.clone(),
            auth_provider: None,
            identity_kind: identity.kind.clone(),
            roles: identity.roles.clone(),
            groups: identity.groups.clone(),
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        };

        match gate.evaluate_tool_call(&policy_ctx) {
            crate::runtime::policy::PreDispatchPolicyOutcome::Allow => "allow".to_owned(),
            crate::runtime::policy::PreDispatchPolicyOutcome::Deny(_) => "deny".to_owned(),
        }
    }

    /// POST /admin/v1/config:reload — trigger a config hot-reload.
    ///
    /// Same semantics as SIGHUP: full `GatewayRuntime` rebuild via
    /// [`crate::app::reload_config`], session store preserved,
    /// credential cache rebuilt fresh, `list_changed` notifications
    /// emitted to operational sessions on inventory delta. Each
    /// replica reloads independently — no cluster broadcast.
    ///
    /// Audit + metrics emit alongside the reload outcome:
    /// `mcpg.config.reloaded` event with `source: "admin_api"` and
    /// `mcpg_admin_reload_triggers_total{trigger="admin_api"}`
    /// counter. The pre-existing `mcpg_config_reloads_total` counter
    /// also increments so dashboards tracking aggregate reloads
    /// (SIGHUP + admin) keep working.
    pub async fn reload_config(&self) -> ReloadResult {
        let started = std::time::Instant::now();
        let prev_sha = self.app_state.config.load().canonical_sha256();

        let outcome = crate::app::reload_config(&self.app_state).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        metrics::counter!("mcpg_config_reloads_total").increment(1);
        metrics::counter!("mcpg_admin_reload_triggers_total", "trigger" => "admin_api")
            .increment(1);

        let (success, err_msg) = match &outcome {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let next_sha_owned: Option<String> = if success {
            Some(self.app_state.config.load().canonical_sha256())
        } else {
            None
        };

        let registry = self.app_state.runtime.load().plugin_registry_arc();
        let event = mcpg_plugin_host::audit_events::config_reloaded_event(
            "admin_api",
            success,
            err_msg.as_deref(),
            Some(prev_sha.as_str()),
            next_sha_owned.as_deref(),
        );
        let _ = registry.emit_audit_event(&event).await;

        ReloadResult {
            ok: success,
            duration_ms,
            prev_config_sha256: prev_sha,
            next_config_sha256: next_sha_owned,
            error: err_msg,
        }
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AdminHealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
    pub uptime_secs: i64,
    pub session_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub phase: String,
    pub created_at: DateTime<Utc>,
    pub log_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendSummary {
    pub name: String,
    pub title: Option<String>,
    pub backend: String,
    pub has_retry: bool,
    pub has_payment: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfoResponse {
    pub uptime_secs: i64,
    pub session_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginListResponse {
    pub plugins: Vec<PluginSummary>,
}

/// Response body for `GET /admin/v1/plugins/:id`.
///
/// Mirrors `mcpg_plugin_host::LoadedPluginDetail` with `config`
/// passed through `redact_sensitive` so operator responses never
/// leak passwords / tokens / keys stored verbatim in the config tree.
#[derive(Debug, Clone, Serialize)]
pub struct PluginDetailResponse {
    pub id: String,
    pub version: String,
    pub name: String,
    pub plugin_class: String,
    pub tier: String,
    pub protocol_version: String,
    pub required_capabilities: Vec<String>,
    pub state: String,
    pub registered_at_unix_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inflight: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce: Option<bool>,
    pub config: serde_json::Value,
}

/// Response body for `POST /admin/v1/plugins/:id:drain`.
#[derive(Debug, Clone, Serialize)]
pub struct DrainResult {
    /// `true` when the plugin drained within the budget. `false` on
    /// timeout or bad-state transitions (the `error` field carries
    /// the reason).
    pub ok: bool,
    pub plugin_id: String,
    /// `"completed" | "timed_out" | "refused"`.
    pub outcome: String,
    /// Current lifecycle state — `disabled` after a clean drain,
    /// `draining` after a timeout (operator follow-up needed),
    /// or the original state on `refused`.
    pub state: String,
    /// In-flight call count at the moment the drain budget expired.
    /// Always `0` on a successful completion.
    pub inflight_remaining: usize,
    pub waited_ms: u64,
    pub timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Walk a JSON tree and replace values whose keys look sensitive
/// (password, secret, token, api_key, auth, bearer, private,
/// pwd, pass) with `"***"`. The match is case-insensitive and
/// substring-based — catches `password`, `db_password`,
/// `api_token_v2`, etc.
///
/// Conservative by design: false positives (a harmless key
/// containing "auth") are redacted, which is fine for an admin
/// response. An operator needing the raw value reads it from the
/// gateway config directly; admin endpoints are observability,
/// not secret retrieval.
pub(crate) fn redact_sensitive(value: serde_json::Value) -> serde_json::Value {
    fn is_sensitive_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        const NEEDLES: &[&str] = &[
            "password",
            "pwd",
            "pass",
            "secret",
            "token",
            "api_key",
            "apikey",
            "auth",
            "bearer",
            "private",
            "credential",
        ];
        NEEDLES.iter().any(|n| lower.contains(n))
    }

    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive_key(&k) {
                    out.insert(k, serde_json::Value::String("***".into()));
                } else {
                    out.insert(k, redact_sensitive(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(redact_sensitive).collect())
        }
        other => other,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub class: String,
    pub tier: String,
    pub protocol_version: String,
    /// Current lifecycle state (e.g. `"active"`, `"disabled"`,
    /// `"degraded"`). See [`mcpg_plugin_host::PluginState`].
    pub state: String,
}

/// Response body for `POST /plugins/:id:disable` and `:enable`.
///
/// The admin handler returns 200 OK with `ok: false` + an `error`
/// string on bad-state transitions so operators get a structured
/// response (an HTTP 500 would be misleading — the request was
/// well-formed, the state just didn't permit the flip).
#[derive(Debug, Clone, Serialize)]
pub struct PluginOpResult {
    pub ok: bool,
    pub plugin_id: String,
    /// The plugin's state *after* the attempted operation — same
    /// as before the call if `ok: false`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Populated when the operator policy is `fail_closed` AND at
    /// least one audit sink failed to record the admin event. The
    /// mutation itself may have succeeded — the HTTP handler
    /// returns a 5xx status in this case so operators see the
    /// audit-failure alarm even when the registry state change
    /// landed cleanly. Operators reconcile the missed audit
    /// manually (the failed-sinks list is in this field; the
    /// gateway's `mcpg_audit_sink_failures_total` counter has
    /// already incremented).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Response body for `POST /admin/v1/config:reload`.
///
/// `ok: false` carries `error` (and `next_config_sha256` is `None`)
/// when the reload aborted before the runtime swap — the previous
/// config remains live and the gateway is unaffected.
#[derive(Debug, Clone, Serialize)]
pub struct ReloadResult {
    pub ok: bool,
    pub duration_ms: u64,
    pub prev_config_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_config_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy preview types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyTestCase {
    pub tool_name: String,
    pub identity: TestIdentity,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TestIdentity {
    pub kind: String,
    pub trust_level: String,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyPreviewResult {
    pub results: Vec<PolicyComparisonResult>,
    pub summary: PolicyPreviewSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyComparisonResult {
    pub tool_name: String,
    pub baseline_decision: String,
    pub candidate_decision: String,
    pub mismatch: bool,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyPreviewSummary {
    pub total_cases: usize,
    pub mismatches: usize,
    pub additive: usize,
    pub subtractive: usize,
}

// ---------------------------------------------------------------------------
// Config-redaction tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod redact_sensitive_tests {
    use super::redact_sensitive;
    use serde_json::json;

    #[test]
    fn redacts_password_key() {
        let out = redact_sensitive(json!({ "password": "hunter2" }));
        assert_eq!(out["password"], "***");
    }

    #[test]
    fn redacts_case_insensitively() {
        let out = redact_sensitive(json!({ "Password": "x", "API_TOKEN": "y" }));
        assert_eq!(out["Password"], "***");
        assert_eq!(out["API_TOKEN"], "***");
    }

    #[test]
    fn redacts_substring_matches() {
        let out = redact_sensitive(json!({
            "db_password": "x",
            "stripe_secret_key": "y",
            "auth_header": "z"
        }));
        assert_eq!(out["db_password"], "***");
        assert_eq!(out["stripe_secret_key"], "***");
        assert_eq!(out["auth_header"], "***");
    }

    #[test]
    fn preserves_non_sensitive_keys() {
        let out = redact_sensitive(json!({
            "endpoint": "https://api.example.com",
            "port": 8080,
            "enabled": true
        }));
        assert_eq!(out["endpoint"], "https://api.example.com");
        assert_eq!(out["port"], 8080);
        assert_eq!(out["enabled"], true);
    }

    #[test]
    fn recurses_into_nested_objects() {
        let out = redact_sensitive(json!({
            "upstream": {
                "url": "https://vault.example",
                "api_key": "leaked"
            }
        }));
        assert_eq!(out["upstream"]["url"], "https://vault.example");
        assert_eq!(out["upstream"]["api_key"], "***");
    }

    #[test]
    fn recurses_through_arrays() {
        let out = redact_sensitive(json!({
            "tenants": [
                { "id": "a", "secret": "x" },
                { "id": "b", "secret": "y" }
            ]
        }));
        assert_eq!(out["tenants"][0]["secret"], "***");
        assert_eq!(out["tenants"][1]["secret"], "***");
        assert_eq!(out["tenants"][0]["id"], "a");
    }

    #[test]
    fn null_and_primitives_pass_through() {
        assert_eq!(
            redact_sensitive(serde_json::Value::Null),
            serde_json::Value::Null
        );
        assert_eq!(redact_sensitive(json!(42)), json!(42));
        assert_eq!(redact_sensitive(json!("hello")), json!("hello"));
    }
}
