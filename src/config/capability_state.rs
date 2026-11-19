//! Capability-state storage blocks: `sessions:`, `pipelines:`,
//! `tasks:`, `subscriptions:`, `delivery:`, `cancellation:`,
//! `request_state:`.
//!
//! Each capability has the same uniform shape: an optional
//! `store:` (or `bus:`) override that pins the capability to an
//! in-process backend (memory / file). When unset, the capability
//! inherits its primitive from the cluster coordinator's
//! `key_value_store()` / `pub_sub()`.
//!
//! Tasks + Subscriptions also carry runtime tuning fields (TTL /
//! reaper interval / per-session quota) that are orthogonal to which
//! backend resolves.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::store_override::{BusOverrideConfig, StoreOverrideConfig};

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// `sessions:` config — the store of the internal session rows the
/// gateway keeps for callers that hold state across requests (tasks,
/// requests that wait for input, `subscriptions/listen` streams), plus
/// a per-capability `store:` override. Clients never see a session id.
/// When `store` is unset, the session KV inherits from the cluster's
/// `key_value_store()` primitive; when set, the override pins to an
/// in-process backend (memory / file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,

    /// Base64-encoded 32-byte secret used to derive the id of the session
    /// row the gateway keeps for a verified caller.
    ///
    /// When set **identically across every replica**, two requests from
    /// the same verified principal and client — on any replica — resolve
    /// to the same session id (HMAC of the principal and the client name
    /// under this key), so a task created on replica A is readable via
    /// `tasks/get` on B and `subscriptions/listen` streams converge. The
    /// id is an HMAC (not a bare hash), so a client that knows another
    /// principal's id still cannot compute — and therefore cannot
    /// hijack — that principal's session.
    ///
    /// Unset, a clustered gateway derives the key from
    /// `cluster.state_encryption_key_env` when that is set; otherwise each
    /// replica mints a random per-instance session id (no cross-replica
    /// continuity), and the gateway logs a boot WARN when a distributed
    /// coordinator is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthetic_session_key: Option<String>,

    /// Bind each session row to the principal that created it. When true,
    /// a `subscriptions/listen` stream opens on a row only when the
    /// caller's resolved principal matches the row's creator; a mismatch
    /// is refused as if the session did not exist (no existence leak).
    /// Default false. An anonymous row (no creating principal) can only be
    /// driven anonymously. Tasks, cancellation and resuming a request that
    /// waits for input check their own owner whatever this is set to.
    #[serde(default)]
    pub bind_session_owner: bool,
}

impl SessionsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.store.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("sessions.store override: {e}"))?;
        }
        // Key length / base64 validity are surfaced at runtime wiring time
        // with the actual byte count (mirrors request_state.encryption_key),
        // so a malformed key degrades to per-instance ids with a WARN rather
        // than aborting boot.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pipelines
// ---------------------------------------------------------------------------

/// `pipelines:` config — pipeline state store + per-capability
/// `store:` override. When `store` is unset, the pipeline KV
/// inherits from the cluster's `key_value_store()` primitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PipelinesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,
}

impl PipelinesConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.store.as_ref() {
            return over
                .validate()
                .map_err(|e| anyhow::anyhow!("pipelines.store override: {e}"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// `tasks:` config (MCP Tasks) — task store + per-capability
/// `store:` override + retention tuning. When `store` is unset, the
/// task KV inherits from the cluster's `key_value_store()` primitive.
/// Tuning fields (`default_ttl_ms`, `reaper_interval_ms`,
/// `max_tasks_per_session`) are orthogonal and apply to whichever
/// backend resolves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TasksConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,

    /// TTL of a task the gateway creates for a task-augmented
    /// `tools/call`; the reaper deletes the task once it has elapsed.
    #[serde(default = "TasksConfig::default_task_ttl_ms")]
    pub default_ttl_ms: u64,

    /// Background reaper sweep interval. The reaper deletes records whose
    /// `created_at + ttl` has elapsed.
    #[serde(default = "TasksConfig::default_reaper_interval_ms")]
    pub reaper_interval_ms: u64,

    /// Maximum concurrent tasks one task owner holds (the principal, or
    /// the session row of an anonymous caller). Creation above this quota
    /// is rejected with JSON-RPC `-32603 Internal error` rather than
    /// silently succeeding. `0` disables the quota.
    #[serde(default = "TasksConfig::default_max_tasks_per_session")]
    pub max_tasks_per_session: usize,
}

impl Default for TasksConfig {
    fn default() -> Self {
        Self {
            store: None,
            default_ttl_ms: Self::default_task_ttl_ms(),
            reaper_interval_ms: Self::default_reaper_interval_ms(),
            max_tasks_per_session: Self::default_max_tasks_per_session(),
        }
    }
}

impl TasksConfig {
    fn default_task_ttl_ms() -> u64 {
        // 30 minutes — matches the historical in-memory default.
        1800000
    }

    fn default_reaper_interval_ms() -> u64 {
        // 60000 seconds — balance between prompt cleanup and reaper overhead.
        60000
    }

    fn default_max_tasks_per_session() -> usize {
        // 256 concurrent tasks per session is generous for interactive
        // workloads and still caps abuse / runaway producers.
        256
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.store.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("tasks.store override: {e}"))?;
        }
        crate::config::require_positive("tasks", "default_ttl_ms", self.default_ttl_ms)?;
        crate::config::require_positive("tasks", "reaper_interval_ms", self.reaper_interval_ms)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

/// `subscriptions:` config (resource subscriptions) — subscription
/// store + per-capability `store:` override + per-session quota.
/// When `store` is unset, the subscription KV inherits from the
/// cluster's `key_value_store()` primitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,
    /// Maximum subscriptions per session (0 = unlimited).
    #[serde(default = "default_max_subscriptions_per_session")]
    pub max_per_session: usize,
}

fn default_max_subscriptions_per_session() -> usize {
    100
}

impl Default for SubscriptionsConfig {
    fn default() -> Self {
        Self {
            store: None,
            max_per_session: default_max_subscriptions_per_session(),
        }
    }
}

impl SubscriptionsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.store.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("subscriptions.store override: {e}"))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Delivery + Cancellation
// ---------------------------------------------------------------------------

/// `delivery:` config — delivery bus (the internal pub/sub that
/// fans notifications out to the `subscriptions/listen` streams and
/// in-flight responses of each session row, on whichever replica
/// holds them) + per-capability `bus:` override. When `bus` is unset,
/// the gateway inherits the cluster's `pub_sub()` primitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<BusOverrideConfig>,
}

impl DeliveryConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.bus.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("delivery.bus override: {e}"))?;
        }
        Ok(())
    }
}

/// `cancellation:` config — cluster-wide cancellation fan-out
/// (`notifications/cancelled` and `tasks/cancel`) plus a
/// per-capability `bus:` override. Same shape as `DeliveryConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancellationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<BusOverrideConfig>,
    /// When true, cancellations publish to
    /// `mcpg.cancel.<principal>` and the subscriber listens on the
    /// `mcpg.cancel.*` wildcard, so broker-native subject ACLs can fence
    /// per-principal cancel traffic. Defaults to `false` (a single flat
    /// `mcpg.cancel` topic). **Requires a wildcard-capable pub/sub
    /// backend (redis/nats)** — `AppConfig::validate` rejects it on the
    /// in-process single-node / memory bus, which is exact-match only and
    /// would silently drop every cancellation under a wildcard subscribe.
    #[serde(default)]
    pub partition_by_principal: bool,
}

impl CancellationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(over) = self.bus.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("cancellation.bus override: {e}"))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/// Default scope strategy for idempotency records. Operator can
/// widen to `per_tenant` (service-account dedupe).
///
/// Note: `global` is intentionally NOT a variant — cross-tenant
/// replay is a known anti-pattern, so we don't expose the footgun.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyScopeKind {
    /// All requests sharing one resolved identity (OIDC subject +
    /// auth provider) share the namespace. The default — matches
    /// Stripe / Square idempotency semantics.
    #[default]
    PerIdentity,
    /// All requests sharing one tenant id share the namespace.
    /// Useful for service-to-service workloads where multiple
    /// service accounts retry the same operation.
    PerTenant,
}

impl IdempotencyScopeKind {
    /// Serialised label emitted in the `server/discover` capability
    /// advertisement (kebab-case for human readability there;
    /// snake_case in YAML to match the rest of the config).
    pub fn advertisement_label(self) -> &'static str {
        match self {
            Self::PerIdentity => "per-identity",
            Self::PerTenant => "per-tenant",
        }
    }
}

/// Conflict policy on a body-hash mismatch with a stored record.
/// Today only `Reject` is implemented; `permissive_replay` is not
/// offered.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Same key + different body hash → JSON-RPC error
    /// `-33010 IdempotencyConflict` (HTTP 422).
    #[default]
    Reject,
}

impl ConflictPolicy {
    pub fn advertisement_label(self) -> &'static str {
        match self {
            Self::Reject => "reject",
        }
    }
}

/// `idempotency:` config — opt-in dedupe for `tools/call`, with
/// task-augmented calls in a namespace of their own (`tasks/create`).
/// When `enabled: false` (the default), the gateway omits the
/// `dev.mcpg/idempotency` extension from its `server/discover`
/// capability advertisement and silently ignores any
/// `_meta["dev.mcpg/idempotency-key"]` the caller sets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyConfig {
    /// Master switch. Default `false` (opt-in, like
    /// `governance.quotas` was before it became cargo-feature-gated).
    #[serde(default)]
    pub enabled: bool,

    /// Default TTL applied to any reservation. Default 86_400_000
    /// (24 hours) — matches Stripe's window.
    #[serde(default = "IdempotencyConfig::default_default_ttl_ms")]
    pub default_ttl_ms: u64,

    /// Hard upper bound on per-record TTL. Default 604_800_000
    /// (7 days). Future per-binding `idempotency.ttl_ms` overrides
    /// saturate at this cap.
    #[serde(default = "IdempotencyConfig::default_max_ttl_ms")]
    pub max_ttl_ms: u64,

    /// Scope strategy — `per_identity` (default) or `per_tenant`.
    #[serde(default)]
    pub scope: IdempotencyScopeKind,

    /// Conflict policy — only `reject` for v1.
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,

    /// JSON-RPC methods this extension applies to. Default
    /// `["tools/call", "tasks/create"]`, where `tasks/create` names a
    /// task-augmented `tools/call` — read-only methods
    /// (`resources/read`, `prompts/get`, `completion/complete`)
    /// are intentionally excluded as they're idempotent by nature.
    #[serde(default = "IdempotencyConfig::default_supported_methods")]
    pub supported_methods: Vec<String>,

    /// Per-capability `store:` override. Same shape as
    /// `tasks.store` / `sessions.store`. When unset, the
    /// idempotency KV inherits from the cluster coordinator's
    /// `key_value_store()` primitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,

    /// When true, a completed-replay hit re-runs the full pre-dispatch
    /// authz stack (external policy chain + tool_gate plugins) before
    /// serving the cached envelope, so authorization revoked since the
    /// original call is honored within the record TTL. Default false:
    /// only the built-in trust-floor + CEL allow_if is re-checked on
    /// replay (the cheap, side-effect-free layer).
    #[serde(default)]
    pub replay_revalidation: bool,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_ttl_ms: Self::default_default_ttl_ms(),
            max_ttl_ms: Self::default_max_ttl_ms(),
            scope: IdempotencyScopeKind::default(),
            conflict_policy: ConflictPolicy::default(),
            supported_methods: Self::default_supported_methods(),
            store: None,
            replay_revalidation: false,
        }
    }
}

impl IdempotencyConfig {
    pub(crate) fn default_default_ttl_ms() -> u64 {
        86_400_000 // 24h
    }

    pub(crate) fn default_max_ttl_ms() -> u64 {
        604_800_000 // 7d
    }

    fn default_supported_methods() -> Vec<String> {
        vec!["tools/call".to_owned(), "tasks/create".to_owned()]
    }

    pub(crate) fn validate(&self) -> Result<()> {
        // The dispatcher always builds a per-identity scope, so a
        // per_tenant choice would silently change the operator's chosen
        // dedupe namespace.
        if self.enabled && !matches!(self.scope, IdempotencyScopeKind::PerIdentity) {
            anyhow::bail!(
                "idempotency.scope '{}' is not yet implemented (only per_identity is honored by \
                 the dispatcher); selecting it would silently change the dedupe namespace. Use \
                 per_identity until per_tenant scoping is wired.",
                self.scope.advertisement_label()
            );
        }
        crate::config::require_positive("idempotency", "default_ttl_ms", self.default_ttl_ms)?;
        crate::config::require_positive("idempotency", "max_ttl_ms", self.max_ttl_ms)?;
        if self.default_ttl_ms > self.max_ttl_ms {
            anyhow::bail!(
                "idempotency.default_ttl_ms ({}) must be <= max_ttl_ms ({})",
                self.default_ttl_ms,
                self.max_ttl_ms
            );
        }
        if let Some(over) = self.store.as_ref() {
            over.validate()
                .map_err(|e| anyhow::anyhow!("idempotency.store override: {e}"))?;
            // Policy: redis / nats are not valid override kinds at
            // the per-capability level.
            // `StoreOverrideConfig::validate` accepts arbitrary
            // plugin kinds (deferred to plugin lookup), so we
            // explicitly fail closed here.
            match over.kind.as_str() {
                "redis" | "nats" => {
                    anyhow::bail!(
                        "idempotency.store.kind '{}' is not supported as a per-capability \
                         override. Set `cluster.kind: {}` and use `kind: cluster` here \
                         (or omit the override entirely).",
                        over.kind,
                        over.kind
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Request-state (MRTR)
// ---------------------------------------------------------------------------

/// `request_state:` config — the MRTR `requestState` codec that
/// encrypts the resumption state of a request that waits for input
/// (`InputRequiredResult`).
///
/// Lives under `mcp.configurations` because the codec manages runtime-emergent
/// resumption state alongside sessions / pipelines / subscriptions /
/// delivery / cancellation / idempotency — operator tunes the
/// encryption key, the runtime mints + serves the rest.
///
/// ```yaml
/// mcp:
///   configurations:
///     request_state:
///       # 32-byte ChaCha20-Poly1305 key, base64-encoded.
///       # Generate via: head -c 32 /dev/urandom | base64
///       encryption_key: "<base64-32-byte-secret>"
/// ```
///
/// Absent the key the gateway mints an ephemeral one at boot (with
/// a WARN log) — pending resumptions issued before a gateway
/// restart become undecodable after restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestStateConfig {
    /// Base64-encoded 32-byte ChaCha20-Poly1305 secret. `None` ⇒
    /// ephemeral key (random per process; resumptions lost on
    /// restart).
    ///
    /// In a clustered deployment, if this is unset but
    /// `cluster.state_encryption_key_env` IS set, the codec key is
    /// derived (HMAC-SHA256, domain-separated) from that cluster-stable
    /// key so every replica decodes the same `requestState` blob — no
    /// separate secret needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// Fail-closed guard for clustered resume. When `true` and the
    /// deployment is clustered (`cluster.kind != single_node`), the gateway
    /// REFUSES to boot if the `requestState` codec would fall back to an
    /// ephemeral per-process key — i.e. neither `encryption_key` nor a
    /// derivable `cluster.state_encryption_key_env` is available. An
    /// ephemeral key is undecodable on a peer, so a clustered (≤8 KiB
    /// inline) resume on another replica silently fails; this turns that
    /// silent fail-open into a loud boot error. Default `false`: a cluster
    /// whose clients never resume on another replica boots without a
    /// shared key.
    #[serde(default)]
    pub strict_encryption: bool,
}

impl RequestStateConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        // Key length / base64 validity are checked at codec wiring
        // time in app/mod.rs so the operator gets a single WARN with
        // the actual byte count, rather than an opaque config error.
        Ok(())
    }
}

#[cfg(test)]
mod idempotency_config_tests {
    use super::*;

    #[test]
    fn idempotency_default_disables_feature() {
        let cfg = IdempotencyConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_ttl_ms, 86_400_000);
        assert_eq!(cfg.max_ttl_ms, 604_800_000);
        assert_eq!(cfg.scope, IdempotencyScopeKind::PerIdentity);
        assert_eq!(cfg.conflict_policy, ConflictPolicy::Reject);
        assert_eq!(
            cfg.supported_methods,
            vec!["tools/call".to_owned(), "tasks/create".to_owned()]
        );
        assert!(!cfg.replay_revalidation);
        cfg.validate().expect("default config validates");
    }

    #[test]
    fn idempotency_replay_revalidation_round_trips() {
        let cfg: IdempotencyConfig =
            serde_yaml::from_str("enabled: true\nreplay_revalidation: true\n").unwrap();
        assert!(cfg.replay_revalidation);
        cfg.validate().expect("valid");
        // Omitted -> default false.
        let cfg2: IdempotencyConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert!(!cfg2.replay_revalidation);
    }

    #[test]
    fn idempotency_enabled_with_explicit_fields_validates() {
        let cfg = IdempotencyConfig {
            enabled: true,
            default_ttl_ms: 3_600_000,
            max_ttl_ms: 86_400_000,
            scope: IdempotencyScopeKind::PerIdentity,
            conflict_policy: ConflictPolicy::Reject,
            supported_methods: vec!["tools/call".to_owned()],
            store: None,
            replay_revalidation: false,
        };
        cfg.validate().expect("valid");
    }

    /// An enabled config selecting the unimplemented per_tenant scope is
    /// rejected, not silently served as per_identity.
    #[test]
    fn idempotency_unimplemented_scopes_rejected_when_enabled() {
        let cfg = IdempotencyConfig {
            enabled: true,
            scope: IdempotencyScopeKind::PerTenant,
            ..IdempotencyConfig::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("not yet implemented"), "{err}");
        // Disabled config with the same scope is fine (nothing is enforced).
        let disabled = IdempotencyConfig {
            enabled: false,
            scope: IdempotencyScopeKind::PerTenant,
            ..IdempotencyConfig::default()
        };
        disabled
            .validate()
            .expect("disabled config validates regardless of scope");
    }

    #[test]
    fn idempotency_default_ttl_above_max_rejected() {
        let cfg = IdempotencyConfig {
            enabled: true,
            default_ttl_ms: 1_000_000_000,
            max_ttl_ms: 100,
            ..IdempotencyConfig::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("max_ttl_ms"), "{err}");
    }

    #[test]
    fn idempotency_zero_ttl_rejected() {
        let cfg = IdempotencyConfig {
            enabled: true,
            default_ttl_ms: 0,
            ..IdempotencyConfig::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("default_ttl_ms"), "{err}");
    }

    #[test]
    fn idempotency_redis_override_kind_rejected() {
        let cfg = IdempotencyConfig {
            enabled: true,
            store: Some(StoreOverrideConfig {
                kind: "redis".to_owned(),
                config: Default::default(),
            }),
            ..IdempotencyConfig::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("redis"), "{err}");
        assert!(err.contains("cluster.kind"), "{err}");
    }

    #[test]
    fn idempotency_serde_round_trip_full() {
        let yaml = r#"
enabled: true
default_ttl_ms: 7200000
max_ttl_ms: 86400000
scope: per_identity
conflict_policy: reject
supported_methods:
  - tools/call
store:
  kind: memory
"#;
        let cfg: IdempotencyConfig = serde_yaml::from_str(yaml).expect("parse");
        cfg.validate().expect("valid");
        assert!(cfg.enabled);
        assert_eq!(cfg.default_ttl_ms, 7_200_000);
        assert_eq!(cfg.scope, IdempotencyScopeKind::PerIdentity);
        assert_eq!(cfg.supported_methods, vec!["tools/call".to_owned()]);
        assert!(cfg.store.is_some());
    }
}
