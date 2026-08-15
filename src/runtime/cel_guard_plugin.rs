#![allow(dead_code)]
//! CEL guard plugin — a sync ToolGatePlugin that evaluates CEL expressions
//! to make allow/deny decisions.
//!
//! This is the local, synchronous equivalent of the guardrails webhook system.
//! Where guardrails make async HTTP callouts to external services, this plugin
//! evaluates CEL expressions locally with zero network overhead.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "rules": [
//!     {
//!       "name": "require-verified-for-admin",
//!       "cel": "identity.trust_level == 'verified'",
//!       "tools": ["admin.*"],
//!       "deny_message": "Admin tools require verified identity"
//!     }
//!   ]
//! }
//! ```

use mcpg_plugin_protocol::{
    GateDecision, PROTOCOL_VERSION, PluginClass, PluginContext, PluginManifest, ToolGatePlugin,
    async_trait,
};

/// A CEL-based guard plugin for local, zero-latency access control.
pub(crate) struct CelGuardPlugin {
    manifest: PluginManifest,
    rules: Vec<CompiledCelRule>,
}

impl std::fmt::Debug for CelGuardPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CelGuardPlugin")
            .field("id", &self.manifest.id)
            .field("rules", &self.rules.len())
            .finish()
    }
}

struct CompiledCelRule {
    name: String,
    program: cel::Program,
    tool_patterns: Vec<String>,
    deny_message: String,
    deny_code: i32,
}

impl CelGuardPlugin {
    /// Create a new CEL guard plugin from a config value.
    ///
    /// The config should contain a `rules` array (see module docs).
    pub fn try_from_config(config: &serde_json::Value) -> Result<Self, String> {
        let rules = config
            .get("rules")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .map(|(i, rule)| Self::compile_rule(i, rule))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.cel-guard".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "CEL Guard".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: PROTOCOL_VERSION.to_owned(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            rules,
        })
    }

    fn compile_rule(index: usize, rule: &serde_json::Value) -> Result<CompiledCelRule, String> {
        let name = rule
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_owned();

        let cel_expr = rule
            .get("cel")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("rule[{}] '{}': missing 'cel' expression", index, name))?;

        let program = cel::Program::compile(cel_expr)
            .map_err(|e| format!("rule[{}] '{}': CEL compile error: {}", index, name, e))?;

        let tool_patterns = rule
            .get("tools")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                    .collect()
            })
            .unwrap_or_default();

        let deny_message = rule
            .get("deny_message")
            .and_then(|v| v.as_str())
            .unwrap_or("denied by CEL guard")
            .to_owned();

        let deny_code = rule
            .get("deny_code")
            .and_then(|v| v.as_i64())
            .unwrap_or(-32003) as i32;

        Ok(CompiledCelRule {
            name,
            program,
            tool_patterns,
            deny_message,
            deny_code,
        })
    }

    /// Evaluate all rules. First deny wins.
    fn evaluate_rules(&self, ctx: &PluginContext) -> GateDecision {
        for rule in &self.rules {
            // Check tool pattern match
            if !rule.tool_patterns.is_empty()
                && !rule
                    .tool_patterns
                    .iter()
                    .any(|p| glob_match(p, &ctx.tool_name))
            {
                continue;
            }

            // Evaluate CEL expression
            let mut cel_ctx = cel::Context::default();
            cel_ctx
                .add_variable("tool_name", ctx.tool_name.clone())
                .ok();
            cel_ctx
                .add_variable("request_id", ctx.request_id.clone())
                .ok();
            cel_ctx
                .add_variable("transport", ctx.transport.clone())
                .ok();

            // Build identity map
            let mut identity = std::collections::HashMap::new();
            identity.insert(
                "kind".to_owned(),
                cel::Value::String(ctx.identity.kind.clone().into()),
            );
            identity.insert(
                "trust_level".to_owned(),
                cel::Value::String(ctx.identity.trust_level.clone().into()),
            );
            if let Some(ref sub) = ctx.identity.subject_id {
                identity.insert(
                    "subject_id".to_owned(),
                    cel::Value::String(sub.clone().into()),
                );
            }
            if let Some(ref provider) = ctx.identity.auth_provider {
                identity.insert(
                    "auth_provider".to_owned(),
                    cel::Value::String(provider.clone().into()),
                );
            }

            // Claims — enables RBAC/ABAC in guard rules
            let roles_cel: Vec<cel::Value> = ctx
                .identity
                .roles
                .iter()
                .map(|r| cel::Value::String(r.clone().into()))
                .collect();
            identity.insert("roles".to_owned(), cel::Value::List(roles_cel.into()));
            let groups_cel: Vec<cel::Value> = ctx
                .identity
                .groups
                .iter()
                .map(|g| cel::Value::String(g.clone().into()))
                .collect();
            identity.insert("groups".to_owned(), cel::Value::List(groups_cel.into()));
            let scopes_cel: Vec<cel::Value> = ctx
                .identity
                .scopes
                .iter()
                .map(|s| cel::Value::String(s.clone().into()))
                .collect();
            identity.insert("scopes".to_owned(), cel::Value::List(scopes_cel.into()));

            cel_ctx
                .add_variable("identity", cel::Value::Map(identity.into()))
                .ok();

            match rule.program.execute(&cel_ctx) {
                Ok(cel::Value::Bool(true)) => {
                    // CEL returned true → allow for this rule
                    continue;
                }
                Ok(cel::Value::Bool(false)) => {
                    // CEL returned false → deny
                    return GateDecision::Deny {
                        http_status: 403,
                        code: rule.deny_code,
                        message: rule.deny_message.clone(),
                        error_data: Some(serde_json::json!({
                            "rule": rule.name,
                            "tool": ctx.tool_name,
                        })),
                    };
                }
                Ok(_) => {
                    // Non-boolean result — fail closed
                    return GateDecision::Deny {
                        http_status: 500,
                        code: -32603,
                        message: format!(
                            "CEL guard rule '{}' returned non-boolean result",
                            rule.name,
                        ),
                        error_data: None,
                    };
                }
                Err(e) => {
                    // Evaluation error — fail closed
                    return GateDecision::Deny {
                        http_status: 500,
                        code: -32603,
                        message: format!("CEL guard rule '{}' evaluation error: {}", rule.name, e,),
                        error_data: None,
                    };
                }
            }
        }

        // All rules passed
        GateDecision::allow()
    }
}

use mcpg_glob::glob_match;

#[async_trait]
impl ToolGatePlugin for CelGuardPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        self.evaluate_rules(ctx)
    }

    async fn evaluate_post_dispatch(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _result: &serde_json::Value,
        _execution_duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        // Post-dispatch uses the same rules for now
        self.evaluate_rules(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tool: &str, trust: &str) -> PluginContext {
        PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: tool.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: if trust == "unauthenticated" {
                    "anonymous".into()
                } else {
                    "verified".into()
                },
                trust_level: trust.into(),
                subject_id: if trust == "verified" {
                    Some("user@test.com".into())
                } else {
                    None
                },
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
            surface: "tool".to_owned(),
        }
    }

    #[tokio::test]
    async fn empty_rules_allows_all() {
        let plugin = CelGuardPlugin::try_from_config(&serde_json::json!({})).unwrap();
        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("any_tool", "unauthenticated"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn cel_rule_allows_matching_trust() {
        let config = serde_json::json!({
            "rules": [{
                "name": "require-verified",
                "cel": "identity.trust_level == 'verified'",
                "deny_message": "requires verified identity"
            }]
        });
        let plugin = CelGuardPlugin::try_from_config(&config).unwrap();

        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("tool", "verified"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn cel_rule_denies_non_matching_trust() {
        let config = serde_json::json!({
            "rules": [{
                "name": "require-verified",
                "cel": "identity.trust_level == 'verified'",
                "deny_message": "requires verified identity"
            }]
        });
        let plugin = CelGuardPlugin::try_from_config(&config).unwrap();

        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("tool", "unauthenticated"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(!decision.is_allow());
        match decision {
            GateDecision::Deny { message, .. } => {
                assert!(message.contains("verified identity"));
            }
            _ => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn tool_pattern_scoping() {
        let config = serde_json::json!({
            "rules": [{
                "name": "admin-only-verified",
                "cel": "identity.trust_level == 'verified'",
                "tools": ["admin.*"],
                "deny_message": "admin tools require verified"
            }]
        });
        let plugin = CelGuardPlugin::try_from_config(&config).unwrap();

        // Non-admin tool: rule doesn't apply, allow
        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("user.profile", "unauthenticated"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(decision.is_allow(), "non-admin tool should be allowed");

        // Admin tool + unauthenticated: denied
        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("admin.delete_user", "unauthenticated"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(
            !decision.is_allow(),
            "admin unauthenticated should be denied"
        );

        // Admin tool + verified: allowed
        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("admin.delete_user", "verified"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        assert!(decision.is_allow(), "admin verified should be allowed");
    }

    #[tokio::test]
    async fn multiple_rules_first_deny_wins() {
        let config = serde_json::json!({
            "rules": [
                {
                    "name": "rule1",
                    "cel": "true",
                    "deny_message": "should not fire"
                },
                {
                    "name": "rule2",
                    "cel": "false",
                    "deny_message": "denied by rule2"
                },
                {
                    "name": "rule3",
                    "cel": "true",
                    "deny_message": "should not fire"
                }
            ]
        });
        let plugin = CelGuardPlugin::try_from_config(&config).unwrap();

        let decision = plugin
            .evaluate_pre_dispatch(
                &ctx("tool", "verified"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            )
            .await;
        match decision {
            GateDecision::Deny { message, .. } => {
                assert_eq!(message, "denied by rule2");
            }
            _ => panic!("expected deny from rule2"),
        }
    }

    #[test]
    fn invalid_cel_expression_rejected() {
        let config = serde_json::json!({
            "rules": [{
                "name": "bad",
                "cel": "this is not valid CEL +++",
            }]
        });
        let err = CelGuardPlugin::try_from_config(&config).unwrap_err();
        assert!(err.contains("CEL compile error"), "got: {}", err);
    }

    #[test]
    fn missing_cel_field_rejected() {
        let config = serde_json::json!({
            "rules": [{"name": "no-cel"}]
        });
        let err = CelGuardPlugin::try_from_config(&config).unwrap_err();
        assert!(err.contains("missing 'cel'"), "got: {}", err);
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("admin.*", "admin.delete"));
        assert!(glob_match("admin.*", "admin."));
        assert!(!glob_match("admin.*", "user.profile"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = CelGuardPlugin::try_from_config(&serde_json::json!({})).unwrap();
        let m = plugin.manifest();
        assert_eq!(m.id, "dev.mcpg.cel-guard");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
    }
}
