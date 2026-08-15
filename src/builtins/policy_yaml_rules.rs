//! Built-in `policy_engine` plugin — `dev.mcpg.builtin.policy.yaml-rules`.
//!
//! Simple declarative YAML-rule-based engine for small
//! deployments. The operator writes a list of rules keyed by
//! decision point + optional identity filters; the engine matches
//! the first rule whose criteria satisfy the request context and
//! returns its effect. Replaceable by real engines (OPA, Cedar,
//! Casbin) for anything non-trivial.
//!
//! # Example policy document
//!
//! ```yaml
//! default_effect: deny
//! source: /etc/mcpg/policy.yaml      # optional, echoed in PolicyVersion
//! rules:
//!   - decision_point: tool.call.pre
//!     identity_kind: verified
//!     effect: allow
//!
//!   - decision_point: tool.call.pre
//!     effect: deny
//!     reason: unauthenticated tool calls are not allowed
//!
//!   - decision_point: admin.api
//!     role: admin
//!     effect: allow
//!
//!   - decision_point: admin.api
//!     effect: deny
//!     reason: admin API requires the admin role
//! ```
//!
//! # Match algorithm
//!
//! For each `(decision_point, context)` pair, scan rules in order
//! and pick the first one where:
//!   - `rule.decision_point` equals the request's decision_point
//!     (exact match; globbing is not supported)
//!   - `rule.identity_kind` is unset OR equals `context.identity.kind`
//!   - `rule.subject_id` is unset OR equals `context.identity.subject_id`
//!   - `rule.role` is unset OR `context.identity.roles` contains it
//!
//! If no rule matches, return `default_effect`. If the rule's
//! effect is `not_applicable`, the engine returns
//! `PolicyEffect::NotApplicable` — useful to selectively opt-out
//! some decision points from this engine when multiple engines
//! are configured.
//!
//! # Version hash
//!
//! The engine exposes the sha256 of the raw YAML bytes as its
//! policy version — deterministic, audit-friendly. Reloading the
//! engine with a new document bumps the hash automatically.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    PluginClass, PluginContext, PluginManifest,
    policy::{PolicyDecision, PolicyEffect, PolicyEngine, PolicyVersion},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.policy.yaml-rules
name: Built-in YAML Rules Policy Engine
description: |
  Gateway-bundled policy engine: declarative YAML rules keyed by
  decision point + optional identity filters. Replaceable by OPA /
  Cedar / Casbin for anything non-trivial.
class: policy_engine
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// Operator-authored YAML document describing the rule set.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDocument {
    /// Effect to apply when no rule matches. Default `deny` —
    /// fail-closed is the right default for an authorization
    /// engine.
    #[serde(default = "default_deny")]
    pub default_effect: PolicyEffect,
    /// Human-readable document source (file path, git ref). Echoed
    /// in `PolicyVersion.source`. Optional.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

fn default_deny() -> PolicyEffect {
    PolicyEffect::Deny
}

/// A single operator-authored rule. Unset filter fields are
/// wildcards: only the set fields must match.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub decision_point: String,
    #[serde(default)]
    pub identity_kind: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    pub effect: PolicyEffect,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Load a policy document from YAML bytes + compute its
/// deterministic sha256 version. Returns a ready-to-register
/// engine.
#[derive(Debug, Clone)]
struct LoadedDocument {
    doc: PolicyDocument,
    version_hash: String,
    loaded_at: String,
    source_label: String,
}

pub struct YamlRulesPolicyEngine {
    manifest: PluginManifest,
    loaded: Arc<LoadedDocument>,
}

impl YamlRulesPolicyEngine {
    /// Create a deny-all engine. Useful as a safe default when an
    /// operator enables the yaml-rules built-in without supplying
    /// any rules of their own.
    pub fn deny_all() -> Arc<Self> {
        let doc = "default_effect: deny\nrules: []\n";
        Self::from_yaml(doc, "builtin:deny-all").expect("deny_all YAML is internally valid")
    }

    /// Build an engine from raw YAML bytes. `source_label` is the
    /// string that shows up in `PolicyVersion.source` (typically
    /// the file path the bytes came from).
    pub fn from_yaml(
        yaml: &str,
        source_label: impl Into<String>,
    ) -> Result<Arc<Self>, serde_yaml::Error> {
        let doc: PolicyDocument = serde_yaml::from_str(yaml)?;
        let source_label = source_label.into();
        // Prefer the document's own `source` field if the operator
        // set it; fall back to the caller-supplied label.
        let effective_source = doc.source.clone().unwrap_or_else(|| source_label.clone());
        let mut h = Sha256::new();
        h.update(yaml.as_bytes());
        let version_hash = format!("sha256:{:x}", h.finalize());
        let loaded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Ok(Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.policy.yaml-rules".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in YAML Rules Policy Engine".into(),
                plugin_class: PluginClass::PolicyEngine,
                protocol_version: "1.0".into(),
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
            loaded: Arc::new(LoadedDocument {
                doc,
                version_hash,
                loaded_at,
                source_label: effective_source,
            }),
        }))
    }
}

/// Match a single rule against the request context. `true` if the
/// rule's filters are all satisfied; the caller still needs to
/// check `decision_point` equality (handled outside this fn to
/// keep the iteration cheap).
fn rule_matches(rule: &PolicyRule, context: &PluginContext) -> bool {
    if let Some(kind) = &rule.identity_kind
        && kind != &context.identity.kind
    {
        return false;
    }
    if let Some(subject) = &rule.subject_id
        && Some(subject) != context.identity.subject_id.as_ref()
    {
        return false;
    }
    if let Some(role) = &rule.role
        && !context.identity.roles.contains(role)
    {
        return false;
    }
    true
}

#[mcpg_plugin_protocol::async_trait]
impl PolicyEngine for YamlRulesPolicyEngine {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn name(&self) -> &str {
        "yaml-rules"
    }

    async fn evaluate(
        &self,
        decision_point: &str,
        _input: &serde_json::Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        let loaded = &self.loaded;
        for rule in &loaded.doc.rules {
            if rule.decision_point != decision_point {
                continue;
            }
            if !rule_matches(rule, context) {
                continue;
            }
            let mut decision = PolicyDecision {
                effect: rule.effect,
                obligations: Vec::new(),
                redactions: Vec::new(),
                attributes: Default::default(),
                reason: rule.reason.clone(),
                policy_version: loaded.version_hash.clone(),
            };
            // Leak no reason for Allow decisions — attack-surface
            // minimization. Operators who set a reason on an
            // Allow rule meant it for audit, but surfacing it to
            // the caller is a footgun; strip at the boundary.
            if decision.effect == PolicyEffect::Allow {
                decision.reason = None;
            }
            return decision;
        }
        // No rule matched; fall back to the default effect. Reason
        // is omitted for Allow per the same attack-surface rule.
        let reason = match loaded.doc.default_effect {
            PolicyEffect::Deny => Some("no policy rule matched; default_effect=deny".to_owned()),
            _ => None,
        };
        PolicyDecision {
            effect: loaded.doc.default_effect,
            obligations: Vec::new(),
            redactions: Vec::new(),
            attributes: Default::default(),
            reason,
            policy_version: loaded.version_hash.clone(),
        }
    }

    async fn policy_version(&self) -> PolicyVersion {
        PolicyVersion {
            hash: self.loaded.version_hash.clone(),
            loaded_at: self.loaded.loaded_at.clone(),
            source: self.loaded.source_label.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;

    fn ctx(kind: &str, subject: Option<&str>, roles: Vec<&str>) -> PluginContext {
        PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test-tool".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: kind.into(),
                trust_level: "test".into(),
                subject_id: subject.map(String::from),
                auth_provider: None,
                issuer: None,
                roles: roles.into_iter().map(String::from).collect(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: Default::default(),
            },
            transport: "http".into(),
        }
    }

    #[tokio::test]
    async fn deny_all_denies_every_decision_point() {
        let e = YamlRulesPolicyEngine::deny_all();
        let d = e
            .evaluate(
                "tool.call.pre",
                &serde_json::json!({}),
                &ctx("verified", Some("a@b.com"), vec!["admin"]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Deny);
        assert!(
            d.reason
                .as_deref()
                .unwrap_or("")
                .contains("default_effect=deny")
        );
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let yaml = r#"
default_effect: deny
rules:
  - decision_point: tool.call.pre
    identity_kind: verified
    effect: allow

  - decision_point: tool.call.pre
    effect: deny
    reason: unauthenticated
"#;
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "test.yaml").unwrap();
        let d = e
            .evaluate(
                "tool.call.pre",
                &serde_json::json!({}),
                &ctx("verified", Some("a@b.com"), vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Allow);
        // Reason stripped for Allow even if a rule had one.
        assert!(d.reason.is_none());

        let d = e
            .evaluate(
                "tool.call.pre",
                &serde_json::json!({}),
                &ctx("anonymous", None, vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Deny);
        assert_eq!(d.reason.as_deref(), Some("unauthenticated"));
    }

    #[tokio::test]
    async fn role_filter_matches_by_presence() {
        let yaml = r#"
default_effect: deny
rules:
  - decision_point: admin.api
    role: admin
    effect: allow
"#;
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "t.yaml").unwrap();
        let d = e
            .evaluate(
                "admin.api",
                &serde_json::json!({}),
                &ctx("verified", Some("a"), vec!["admin"]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Allow);

        let d = e
            .evaluate(
                "admin.api",
                &serde_json::json!({}),
                &ctx("verified", Some("a"), vec!["user"]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Deny);
    }

    #[tokio::test]
    async fn subject_id_filter_matches_exact() {
        let yaml = r#"
default_effect: deny
rules:
  - decision_point: admin.api
    subject_id: admin@tsok.org
    effect: allow
"#;
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "t.yaml").unwrap();
        let d = e
            .evaluate(
                "admin.api",
                &serde_json::json!({}),
                &ctx("verified", Some("admin@tsok.org"), vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Allow);

        let d = e
            .evaluate(
                "admin.api",
                &serde_json::json!({}),
                &ctx("verified", Some("other@tsok.org"), vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Deny);
    }

    #[tokio::test]
    async fn decision_point_mismatch_falls_to_default() {
        let yaml = r#"
default_effect: allow
rules:
  - decision_point: tool.call.pre
    effect: deny
"#;
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "t.yaml").unwrap();
        // Decision point "resource.read" has no rule → default.
        let d = e
            .evaluate(
                "resource.read",
                &serde_json::json!({}),
                &ctx("verified", Some("a"), vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::Allow);
    }

    #[tokio::test]
    async fn not_applicable_rule_declines_to_decide() {
        // Useful for selectively opting some decision_points out
        // of this engine when multiple engines are configured.
        let yaml = r#"
default_effect: deny
rules:
  - decision_point: tool.call.post
    effect: not_applicable
"#;
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "t.yaml").unwrap();
        let d = e
            .evaluate(
                "tool.call.post",
                &serde_json::json!({}),
                &ctx("verified", Some("a"), vec![]),
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::NotApplicable);
    }

    #[tokio::test]
    async fn policy_version_is_deterministic_sha256() {
        let yaml_a = "default_effect: deny\nrules: []\n";
        let yaml_b = "default_effect: deny\nrules: []\n";
        let yaml_c = "default_effect: allow\nrules: []\n";
        let a = YamlRulesPolicyEngine::from_yaml(yaml_a, "x").unwrap();
        let b = YamlRulesPolicyEngine::from_yaml(yaml_b, "x").unwrap();
        let c = YamlRulesPolicyEngine::from_yaml(yaml_c, "x").unwrap();
        let va = a.policy_version().await;
        let vb = b.policy_version().await;
        let vc = c.policy_version().await;
        assert_eq!(va.hash, vb.hash, "same bytes → same hash");
        assert_ne!(va.hash, vc.hash, "different bytes → different hash");
        assert!(va.hash.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn policy_version_prefers_doc_source_when_set() {
        let yaml = "default_effect: deny\nsource: /etc/mcpg/policy.yaml\nrules: []\n";
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "fallback-label").unwrap();
        let v = e.policy_version().await;
        assert_eq!(v.source, "/etc/mcpg/policy.yaml");
    }

    #[tokio::test]
    async fn policy_version_falls_back_to_caller_source_label() {
        let yaml = "default_effect: deny\nrules: []\n";
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "fallback-label").unwrap();
        let v = e.policy_version().await;
        assert_eq!(v.source, "fallback-label");
    }

    #[tokio::test]
    async fn decision_carries_policy_version_hash() {
        let yaml = "default_effect: deny\nrules: []\n";
        let e = YamlRulesPolicyEngine::from_yaml(yaml, "t").unwrap();
        let v = e.policy_version().await;
        let d = e
            .evaluate(
                "tool.call.pre",
                &serde_json::json!({}),
                &ctx("anonymous", None, vec![]),
            )
            .await;
        assert_eq!(d.policy_version, v.hash);
    }

    #[test]
    fn engine_name_is_yaml_rules() {
        let e = YamlRulesPolicyEngine::deny_all();
        assert_eq!(e.name(), "yaml-rules");
    }

    #[test]
    fn descriptor_yaml_parses_as_policy_engine() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.policy.yaml-rules");
        assert_eq!(d.class, PluginClass::PolicyEngine);
    }

    #[test]
    fn empty_rules_defaults_to_deny() {
        // Parses with no `rules` key at all.
        let yaml = "default_effect: allow\n";
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(doc.default_effect, PolicyEffect::Allow);
        assert!(doc.rules.is_empty());
    }

    #[test]
    fn default_effect_defaults_to_deny_when_omitted() {
        // Missing default_effect defaults to deny (fail-closed).
        let yaml = "rules: []\n";
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(doc.default_effect, PolicyEffect::Deny);
    }
}
