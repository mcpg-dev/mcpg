//! Top-level `cluster:` block — the cluster coordinator selection.
//!
//! The cluster plugin is the unified backbone for MCPG multi-instance
//! state + coordination — it internally instantiates the four
//! primitive impls (`KeyValueStore`, `PubSub`, `Lease`, `Watch`) and
//! exposes them via accessor methods. Capabilities (sessions /
//! pipelines / tasks / subscriptions / delivery / cancellation)
//! inherit those primitives by default; per-capability `store:` /
//! `bus:` overrides pin individual capabilities to in-process
//! backends.

use serde::{Deserialize, Serialize};

/// Top-level cluster config. The cluster plugin is the unified
/// backbone for MCPG multi-instance state + coordination — it
/// internally instantiates the four primitive impls
/// (`KeyValueStore`, `PubSub`, `Lease`, `Watch`) and exposes them
/// via accessor methods. `kind` is the discriminator; everything
/// else is kind-specific config that flows straight to the plugin's
/// factory as JSON.
///
/// ```yaml
/// cluster:
///   kind: redis              # single_node | etcd | consul | nats | redis
///   url: ${env.REDIS_URL}   # rest of the fields are kind-specific
///   key_prefix: "mcpg:cluster:"
/// ```
///
/// `kind: single_node` (the default when `cluster:` is omitted)
/// installs the in-process built-in coordinator and ignores the rest
/// of the block. Other kinds map to `mcpg-plugin-cluster-<kind>`;
/// the cdylib must still be declared under `plugins[]`
/// (the inline `cluster.*` fields override any `config:` block on
/// the matching entry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct ClusterConfig {
    #[serde(default = "default_cluster_kind")]
    pub kind: String,
    /// Permit a plaintext (non-TLS) coordinator transport for a
    /// non-`single_node` coordinator. Defaults to `false`:
    /// `validate()` refuses a plaintext redis/consul/etcd/nats
    /// coordinator at boot, because the coordinator carries all shared
    /// state (sessions, credentials, delivery) in clear. Set `true`
    /// ONLY for local/dev/CI. Gateway-only — NOT forwarded to the
    /// plugin (it is a named field, so serde keeps it out of `config`).
    #[serde(default)]
    pub allow_insecure_transport: bool,
    /// Whether coordinator health gates `/ready`. Defaults to
    /// `off` (fail-open): a coordinator outage
    /// is surfaced only via the `mcpg_cluster_backend_up` gauge + its
    /// alert, never on readiness. `degrade` adds an informational
    /// not-ready *check* to the readiness body but keeps `/ready` green
    /// (no LB flapping). `fail` makes `/ready` return not-ready while the
    /// coordinator is unreachable (fail-closed). Gateway-only named field
    /// — kept out of the flattened plugin `config`.
    #[serde(default)]
    pub readiness_gate: ClusterReadinessGate,
    /// Opt-in application-layer AEAD (XChaCha20-Poly1305) of ALL
    /// coordinator-backed *capability* state — sessions (incl. SSE replay),
    /// delivery, cancellation, tasks, pipelines, idempotency, request-state,
    /// subscriptions, quota, and the approvals backstop. Names the
    /// **env var** holding a URL-safe-base64 32-byte key (the key itself
    /// never sits in the config artifact). Unset = plaintext serde on the
    /// wire/at-rest; confidentiality then rests on the transport guard.
    /// Values are sealed per-key/per-topic
    /// (swap-resistant); keys/topics stay cleartext for routing. Does NOT
    /// cover the credential cache — it has its own
    /// `encryption_key` under the credentials config. Gateway-only named
    /// field — kept out of the flattened plugin `config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_encryption_key_env: Option<String>,
    /// Key id (kid) stamped on state envelopes for rotation visibility.
    /// Defaults to `mcpg-cluster-state` when a key is configured. Inert
    /// without `state_encryption_key_env`. Gateway-only named field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_encryption_key_id: Option<String>,
    /// Tolerate a coordinator that advertises `kv`/`bus` roles but fails the
    /// boot reachability probe (a live round-trip against the advertised
    /// primitives). Default `false`: for a clustered (non-`single_node`)
    /// coordinator the gateway probes each advertised primitive at boot and
    /// **refuses to start** if the round-trip fails or the accessor is absent,
    /// rather than silently de-clustering to per-replica in-process state.
    /// Set `true` ONLY when an operator knowingly wants the gateway to boot
    /// and run degraded (per-replica state) despite an unreachable
    /// coordinator — it logs a loud error and continues. Gateway-only named
    /// field — kept out of the flattened plugin `config`.
    #[serde(default)]
    pub allow_degraded_boot: bool,
    /// Tolerate plaintext (non-envelope) reads while `state_encryption_key_env`
    /// is set — a bounded migration window for rolling a key in across
    /// replicas. Default `false`: once a key is configured a plaintext value
    /// on the coordinator KV/bus is rejected (fail closed), so an unkeyed
    /// peer or attacker cannot inject unauthenticated capability state. Set
    /// `true` only transiently during a rollout; turn it off once every
    /// replica writes envelopes. Inert without `state_encryption_key_env`.
    /// Gateway-only named field — kept out of the flattened plugin `config`.
    #[serde(default)]
    pub state_encryption_allow_plaintext_reads: bool,
    /// Optional per-deployment tenant segment. When set, EVERY
    /// coordinator-backed capability KV key and bus topic is prefixed with
    /// `t.<segment>/` (keys) / `t.<segment>.` (topics) so a single
    /// coordinator namespace can be fenced per-tenant by broker-native
    /// ACLs — NATS subject perms `t.<segment>.>`, redis key-pattern ACLs
    /// (`~…t.<segment>/*`), consul/etcd path ACLs. Unset = today's flat,
    /// un-prefixed keys/topics (one coordinator namespace == one trust
    /// domain). This is a **deployment-level** label, not a per-request
    /// tenant — the gateway process serves one tenant segment; the runtime
    /// carries no per-request tenant at key/topic-formation time, so
    /// per-request multi-tenancy remains future work. Turning it on is a
    /// key-namespace cutover (existing flat-keyed state goes invisible).
    /// Must be a single token (no `. * > / : ` or whitespace). Gateway-only
    /// named field — kept out of the flattened plugin `config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_segment: Option<String>,
    /// Per-kind config. Flattened so operators write a flat map
    /// (`kind: redis` next to `url:`, `key_prefix:`, etc).
    #[serde(flatten, default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// How coordinator health affects `/ready`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClusterReadinessGate {
    /// Coordinator health never affects `/ready` (fail-open). Default.
    #[default]
    Off,
    /// Surface a not-ready *check* in the readiness body when the
    /// coordinator is down, but keep the overall `/ready` status green.
    Degrade,
    /// `/ready` returns not-ready while the coordinator is unreachable.
    Fail,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            kind: default_cluster_kind(),
            allow_insecure_transport: false,
            readiness_gate: ClusterReadinessGate::Off,
            allow_degraded_boot: false,
            state_encryption_key_env: None,
            state_encryption_key_id: None,
            state_encryption_allow_plaintext_reads: false,
            tenant_segment: None,
            config: serde_json::Map::new(),
        }
    }
}

fn default_cluster_kind() -> String {
    "single_node".to_owned()
}

impl ClusterConfig {
    /// Map the operator-supplied `kind` to the coordinator plugin id by the
    /// convention `dev.mcpg.cluster.<kind>`. `single_node` returns `None`
    /// (built-in in-process default, no plugin). The gateway stays
    /// kind-agnostic — any other `kind` resolves by convention and must have a
    /// matching `plugins[]` entry, else it fails closed at load.
    pub fn plugin_id(&self) -> Option<String> {
        if self.is_single_node() {
            None
        } else {
            Some(format!("dev.mcpg.cluster.{}", self.kind))
        }
    }

    /// True when the operator picked the in-process default.
    pub fn is_single_node(&self) -> bool {
        self.kind == "single_node"
    }

    /// Refuse a plaintext coordinator transport for a non-`single_node`
    /// coordinator unless the operator explicitly opted in via
    /// `allow_insecure_transport: true`. The coordinator carries
    /// all shared state — sessions, credential-cache events, delivery
    /// payloads — so a plaintext link exposes them deployment-wide.
    /// Per-kind "plaintext" definition (scheme tests trim leading
    /// whitespace to match the plugins):
    /// - redis: `url` uses the `redis://` (not `rediss://`) scheme;
    /// - consul: `address` uses `http://` (not `https://`);
    /// - etcd: any `endpoint` is not an `https://` URL — a plaintext `http://` or a scheme-less `host:port` endpoint (which etcd-client connects in clear);
    /// - nats: `tls.require_tls` is explicitly `false` (the nats plugin otherwise requires TLS by default, and a `nats://` URL can still negotiate TLS on the port).
    ///
    /// Error messages never echo the URL (it may carry credentials).
    ///
    /// **Scope.** This runs in `AppConfig::validate()`, which executes
    /// *before* `${env.X}` / `cred://` substitution — so the check sees the
    /// literal configured value. A URL supplied as an env placeholder
    /// (`url: ${env.REDIS_URL}`) is opaque here and is NOT statically
    /// classified (the guard neither fires nor passes judgement on it); the
    /// operator owns the resolved scheme and must point the env value at a
    /// TLS endpoint. The Helm chart renders *literal* URLs, so the stock
    /// deployment path is fully covered.
    pub fn validate_transport_security(&self) -> anyhow::Result<()> {
        if self.is_single_node() || self.allow_insecure_transport {
            return Ok(());
        }
        // Scheme tests trim leading whitespace so the gateway classifies a
        // value identically to the coordinator plugins (etcd trims; a bare
        // `" http://…"` must not slip past the guard while the plugin still
        // connects plaintext).
        let plaintext: Option<&str> = match self.kind.as_str() {
            "redis" => self
                .config
                .get("url")
                .and_then(|v| v.as_str())
                .filter(|u| u.trim_start().starts_with("redis://"))
                .map(|_| "the redis `url` uses the plaintext `redis://` scheme (use `rediss://`)"),
            "consul" => self
                .config
                .get("address")
                .and_then(|v| v.as_str())
                .filter(|a| a.trim_start().starts_with("http://"))
                .map(
                    |_| "the consul `address` uses the plaintext `http://` scheme (use `https://`)",
                ),
            // etcd is fail-closed on scheme: anything that is not provably
            // `https://` is treated as plaintext. A scheme-LESS endpoint
            // (`etcd:2379`) is accepted by etcd-client and connects over
            // plaintext HTTP, so "not https://" — not merely "starts with
            // http://" — is the correct plaintext test here.
            "etcd" => self
                .config
                .get("endpoints")
                .and_then(|v| v.as_array())
                .filter(|eps| {
                    eps.iter()
                        .filter_map(|e| e.as_str())
                        .any(|e| !e.trim_start().starts_with("https://"))
                })
                .map(|_| {
                    "an etcd `endpoint` is not an `https://` URL (a plaintext `http://` or \
                     scheme-less `host:port` endpoint connects in clear; use `https://`)"
                }),
            "nats" => self
                .config
                .get("tls")
                .and_then(|t| t.get("require_tls"))
                .and_then(|v| v.as_bool())
                .filter(|require_tls| !require_tls)
                .map(|_| "nats `tls.require_tls` is set to `false` (plaintext)"),
            _ => None,
        };
        if let Some(reason) = plaintext {
            anyhow::bail!(
                "cluster.kind='{}': {reason}. The cluster coordinator carries all shared \
                 state (sessions, credential-cache events, delivery payloads) — a plaintext \
                 transport exposes them across the deployment. Use a TLS scheme, or set \
                 `cluster.allow_insecure_transport: true` to accept plaintext (local/dev only).",
                self.kind,
            );
        }
        Ok(())
    }

    /// A configured `tenant_segment` must be a single token usable as
    /// a NATS subject token, a redis SCAN-MATCH-safe key segment, and a
    /// path segment — i.e. no `. * > / : ` or whitespace (those break
    /// subject tokenization, the `/` key head, the redis `prefix:key` join,
    /// or glob scans). Mirrors the cancellation-bus `partition_key`
    /// sanitizer's reserved set.
    pub fn validate_tenant_segment(&self) -> anyhow::Result<()> {
        let Some(seg) = self.tenant_segment.as_deref() else {
            return Ok(());
        };
        if seg.is_empty()
            || seg
                .chars()
                .any(|c| matches!(c, '.' | '*' | '>' | '/' | ':' | ' ' | '\t' | '\n' | '\r'))
        {
            anyhow::bail!(
                "cluster.tenant_segment must be a non-empty token without any of \
                 `. * > / : ` or whitespace (it becomes a NATS subject token + redis \
                 key segment): got {seg:?}"
            );
        }
        Ok(())
    }
}
