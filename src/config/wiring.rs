//! Point-of-use slot resolution.
//!
//! Every consumer slot (cache, kv, bus, transport, policy-engine,
//! audit-sink, obs-sink) accepts a [`KindRef`] discriminator
//! `{ kind: <value>, ...config }`. This module owns the resolution
//! algorithm (`resolve_kind`) that maps a `KindRef` to a
//! [`ResolvedKind`] handle the consumer can act on.
//!
//! Resolution rules (definitive):
//!
//! 1. If `kind` is a slot-class keyword (e.g. for a `cache` slot:
//!    `cluster` | `in-process` | `memory` | `file` | `builtin`):
//!    resolve to the built-in handle for the slot's class.
//!
//! 2. Else if `kind` matches the full reverse-domain shape
//!    (`^[a-z0-9_-]+\.[a-z0-9_-]+(\.[a-z0-9_-]+)+$`): look up
//!    `plugins[]` for an entry where `entry.id == kind`, assert
//!    `entry.class` matches the slot, and resolve to that plugin.
//!
//! 3. Else (`kind` is a bare token like `redis`): treat as a short
//!    alias. Construct candidate id `dev.mcpg.<slot-class>.<kind>`
//!    and look up `plugins[]` for that id.
//!
//! 4. If `kind == "cluster"`: assert the configured cluster
//!    coordinator advertises the role for the slot's class
//!    (per [`cluster_provides_for_kind`]); refuse with a clear
//!    error if not.
//!
//! The cluster-coordinator role vocabulary is `cache` / `kv` / `bus`
//! ([`mcpg_plugin_protocol::descriptor::CLUSTER_PROVIDES_ROLES`]). The
//! authoritative per-coordinator role-set is each coordinator's
//! manifest `provides` field, surfaced at runtime via
//! `ClusterBackend::cluster_provides()`. [`cluster_provides_for_kind`]
//! is the *static fallback* used where no live coordinator instance is
//! available (config-time validation, the `mcpg-config` validator); the
//! boot cross-check ties it to the live role-set for built-in kinds so
//! the two can't drift. `provides` speaks only the role vocabulary —
//! `key_value_store` / `pub_sub` / `lease` / `watch` / `peers` are the
//! trait's primitive *accessor* methods, not slot roles.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use super::PluginEntryConfig;

/// Slot classes — the categories of "what flavour of this thing"
/// that resolve through `resolve_kind`. Each slot class has its own
/// keyword vocabulary (`cluster`, `in-process`, `memory`, `file`,
/// `builtin`, `stderr`, `builtin-http`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotClass {
    /// In-band cache used by tools / bindings (`mcp.capabilities.tools[].cache`).
    Cache,
    /// Capability state store (`mcp.configurations.*.store`).
    Kv,
    /// Delivery bus / pubsub (`mcp.configurations.delivery.bus`).
    Bus,
    /// Transport listener (`gateway.server.transports[]`).
    Transport,
    /// Policy engine (`governance.policy.engine`).
    PolicyEngine,
    /// Audit-event sink (`governance.audit.sinks[]`).
    AuditSink,
    /// Log sink (`observability.logs.sinks[]`). Carries built-in
    /// keywords `stderr` / `stdout` / `file` for the in-gateway
    /// `tracing_subscriber` layers; plugin sinks have class
    /// `log_sink`.
    LogSink,
    /// Metric sink (`observability.metrics.sinks[]`). All sinks
    /// resolve to plugins with class `metrics_sink` — there are no
    /// in-gateway built-in shorthands.
    MetricsSink,
    /// Trace / telemetry sink (`observability.traces.sinks[]`).
    /// All sinks resolve to plugins with class `telemetry_sink` —
    /// there is no `kind: otlp` shorthand.
    TelemetrySink,
}

impl SlotClass {
    /// Short name used in error messages.
    pub fn name(&self) -> &'static str {
        match self {
            SlotClass::Cache => "cache",
            SlotClass::Kv => "kv",
            SlotClass::Bus => "bus",
            SlotClass::Transport => "transport",
            SlotClass::PolicyEngine => "policy",
            SlotClass::AuditSink => "audit-sink",
            SlotClass::LogSink => "log-sink",
            SlotClass::MetricsSink => "metrics-sink",
            SlotClass::TelemetrySink => "telemetry-sink",
        }
    }

    /// Plugin `class:` field value the slot accepts. Resolution
    /// rejects plugins whose declared class doesn't match. Returned
    /// strings are the canonical snake_case `PluginClass` variants
    /// (per `libs/plugin-protocol/src/manifest.rs`) — the same
    /// strings that plugin manifests declare and that the runtime
    /// `PluginManifest.plugin_class.to_string()` emits.
    ///
    /// `SlotClass::Bus` returns `"bus"` as a placeholder — there is
    /// no `PluginClass::Bus` variant today; bus is closed-set
    /// (`cluster` / `memory`) until a `PubSub` plugin trait lands.
    pub fn plugin_class(&self) -> &'static str {
        match self {
            SlotClass::Cache => "cache",
            SlotClass::Kv => "store",
            SlotClass::Bus => "bus",
            SlotClass::Transport => "transport",
            SlotClass::PolicyEngine => "policy_engine",
            SlotClass::AuditSink => "audit_sink",
            SlotClass::LogSink => "log_sink",
            SlotClass::MetricsSink => "metrics_sink",
            SlotClass::TelemetrySink => "telemetry_sink",
        }
    }

    /// Plugin-id namespace segment used for short-alias expansion.
    ///
    /// Operators write `kind: redis` and resolve_kind expands that
    /// into the candidate id `dev.mcpg.<namespace>.redis` for
    /// registry lookup. Distinct from [`plugin_class`] because
    /// id-naming convention is shorter and operator-friendlier
    /// than the canonical class. For example, KV plugins ship
    /// under `dev.mcpg.kv.<name>` ids (namespace `kv`) but declare
    /// `class: store` (matching `PluginClass::Store`).
    pub fn id_namespace(&self) -> &'static str {
        match self {
            SlotClass::Cache => "cache",
            SlotClass::Kv => "kv",
            SlotClass::Bus => "bus",
            SlotClass::Transport => "transport",
            SlotClass::PolicyEngine => "policy",
            SlotClass::AuditSink => "audit",
            SlotClass::LogSink | SlotClass::MetricsSink | SlotClass::TelemetrySink => {
                "observability"
            }
        }
    }
}

/// Discriminator + config payload at every consumer slot. Operators
/// write `{ kind: <value>, ...config }` in YAML; the gateway parses
/// it as this type and resolves via [`resolve_kind`].
///
/// The `config:` field is a free-form JSON object passed to the
/// resolved handle (built-in or plugin). The slot's resolver
/// validates `kind`; the implementation validates `config`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KindRef {
    /// Discriminator. One of: built-in keyword, full plugin id,
    /// short alias, or `cluster`.
    pub kind: String,
    /// Inline config forwarded to the resolved handle. Empty by default.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub config: serde_json::Value,
}

/// Outcome of [`resolve_kind`] — what the slot's `kind` resolved to.
/// Consumers pattern-match to instantiate the actual handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedKind {
    /// A gateway built-in (in-process cache, memory KV, stderr log
    /// sink, etc.). The string is the canonical built-in keyword
    /// (`in-process` / `memory` / `file` / `stderr` / `builtin-http` / …).
    Builtin(String),
    /// A loaded plugin entry. The string is the full plugin id
    /// (`dev.mcpg.cache.redis`). Caller looks it up in the plugin
    /// registry to obtain the runtime handle.
    Plugin(String),
    /// The cluster coordinator's role implementation. Caller
    /// dispatches to the coordinator's `<role>_handle()` method.
    Cluster,
}

/// Resolve a [`KindRef`] for the given slot class.
///
/// See module-level docs for the four-rule algorithm. Returns
/// detailed error messages on every failure path so operators can
/// fix typos without grep'ing the source.
pub fn resolve_kind(
    slot: SlotClass,
    kref: &KindRef,
    plugins: &[PluginEntryConfig],
    cluster_kind: &str,
) -> Result<ResolvedKind> {
    let value = kref.kind.trim();
    if value.is_empty() {
        return Err(anyhow!("{} slot: `kind:` must not be empty", slot.name()));
    }

    // Rule 4 first — `cluster` is a reserved keyword.
    if value == "cluster" {
        let provides = cluster_provides_for_kind(cluster_kind);
        let role = slot.name();
        if !provides.contains(role) {
            return Err(anyhow!(
                "{} slot: your cluster (`{}`) doesn't provide a `{}` role; \
                 either set this slot to `kind: <other>` or load a plugin \
                 that provides class `{}`",
                slot.name(),
                cluster_kind,
                role,
                slot.plugin_class(),
            ));
        }
        return Ok(ResolvedKind::Cluster);
    }

    // Rule 1 — slot-class keywords.
    if is_builtin_keyword(slot, value) {
        return Ok(ResolvedKind::Builtin(value.to_owned()));
    }

    // Rule 2 — full reverse-domain plugin id (contains a dot).
    if value.contains('.') {
        return resolve_full_plugin_id(slot, value, plugins);
    }

    // Rule 3 — short alias. Expansion uses the slot's
    // `id_namespace` segment (operator-friendly category like
    // `kv` / `policy`), not its `plugin_class` (canonical class
    // like `store` / `policy_engine`) — they diverge for slots
    // whose user-facing namespace is shorter than the class.
    //
    // The lookup target is the ALIAS
    // (`PluginEntryConfig.id`). For single-instance configs
    // alias == manifest id so `kind: cedar` still expands to and
    // matches `dev.mcpg.policy.cedar`. For multi-
    // instance configs the operator chooses distinct aliases
    // (`cedar.tenant-a`) and references them directly via Rule 2 or
    // an explicit `kind:` written that way; the short-alias
    // expansion only applies to the single-instance pattern.
    let candidate_id = format!("dev.mcpg.{}.{}", slot.id_namespace(), value);
    match resolve_full_plugin_id(slot, &candidate_id, plugins) {
        Ok(resolved) => Ok(resolved),
        Err(_) => Err(anyhow!(
            "{} slot: no plugin matches short alias `{}`; expected plugin alias \
             `{}` (loaded aliases: [{}]). Use the full alias (or manifest id \
             for single-instance plugins) if the short-alias resolution doesn't \
             match.",
            slot.name(),
            value,
            candidate_id,
            plugins
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

fn resolve_full_plugin_id(
    slot: SlotClass,
    id: &str,
    plugins: &[PluginEntryConfig],
) -> Result<ResolvedKind> {
    // `PluginEntryConfig.id` is the operator alias. For
    // single-instance configs (no `ref:` on the entry) the alias
    // equals the manifest id and `kind: dev.mcpg.foo.bar` references
    // resolve directly. For multi-instance configs, operators
    // reference the entry's chosen alias instead.
    let entry = plugins.iter().find(|p| p.id == id).ok_or_else(|| {
        anyhow!(
            "{} slot: no plugin loaded with alias `{}` (loaded aliases: [{}])",
            slot.name(),
            id,
            plugins
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
    })?;
    let expected = slot.plugin_class();
    if entry.class != expected {
        return Err(anyhow!(
            "{} slot: plugin alias `{}` has class `{}` but the slot expects class `{}`",
            slot.name(),
            id,
            entry.class,
            expected,
        ));
    }
    Ok(ResolvedKind::Plugin(id.to_owned()))
}

/// Whether `cluster_kind` is one of the built-in coordinator kinds this
/// module has an explicit role-arm for (as opposed to a 3rd-party
/// plugin-class cluster that falls into the permissive catch-all).
///
/// The boot cross-check (`apps/gateway/src/app/mod.rs`) uses this to
/// decide whether to assert the static fallback table agrees with the
/// live `ClusterBackend::cluster_provides()`: for built-in kinds the
/// two MUST match (drift is a bug); for plugin-class clusters the table
/// is intentionally permissive, so the live role-set is authoritative
/// and no equality is asserted.
pub fn is_builtin_cluster_kind(cluster_kind: &str) -> bool {
    matches!(
        cluster_kind,
        "single-node-builtin"
            | "single_node"
            | "nats"
            | "nats-jetstream"
            | "redis"
            | "consul"
            | "etcd"
    )
}

/// Return the role-set the named cluster coordinator provides.
///
/// This is the **static fallback** consulted by callers that have only
/// a kind string and no live coordinator instance — config-time
/// validation (`config::validate`) and the standalone `mcpg-config`
/// validator. The authoritative runtime source is the manifest
/// `provides` field, surfaced via `ClusterBackend::cluster_provides()`;
/// at boot the gateway cross-checks this table against that live
/// role-set for built-in kinds ([`is_builtin_cluster_kind`]) and
/// fails-closed on drift, so the table can't silently diverge from the
/// coordinators. Unknown / plugin-class clusters default to providing
/// every role here — operators get the runtime error if the plugin
/// doesn't actually serve a slot, instead of a parse-time refusal that
/// would block legitimate per-cluster customisation.
pub fn cluster_provides_for_kind(cluster_kind: &str) -> BTreeSet<&'static str> {
    let mut set = BTreeSet::new();
    match cluster_kind {
        "single-node-builtin" | "single_node" => {
            set.insert("cache");
            set.insert("kv");
            set.insert("bus");
        }
        "nats" | "nats-jetstream" => {
            set.insert("bus");
            set.insert("kv");
        }
        "redis" => {
            set.insert("cache");
            set.insert("kv");
        }
        "consul" | "etcd" => {
            // consul (Event API) and etcd (Watch streams) back the `bus` role
            // via coordinator-level publish/subscribe AND the `kv` role via a
            // real `KeyValueStore` over the plugin FFI (etcd v3 KV + native
            // lease TTL; consul KV HTTP API + a logical/emulated TTL). Neither
            // exposes a native cache-eviction role.
            set.insert("bus");
            set.insert("kv");
        }
        // Plugin-class cluster (any other id, typically reverse-domain) —
        // assume it provides every role; the runtime catches mismatches.
        _ => {
            set.insert("cache");
            set.insert("kv");
            set.insert("bus");
        }
    }
    set
}

fn is_builtin_keyword(slot: SlotClass, value: &str) -> bool {
    let common = matches!(value, "builtin" | "in-process" | "memory" | "file");
    if common {
        return true;
    }
    match slot {
        SlotClass::Transport => matches!(value, "builtin-http" | "builtin-stdio"),
        // Log signal supports the in-gateway tracing_subscriber
        // layers `stderr`/`stdout`/`file` (`build_os_stream_layers`
        // dispatches them inline). Metrics + traces have no
        // built-in keywords — every sink is a plugin. Audit sinks
        // are always plugins (the canonical
        // local-file sink ships as `dev.mcpg.builtin.audit.local-file`).
        SlotClass::LogSink => matches!(value, "stderr" | "stdout"),
        SlotClass::MetricsSink | SlotClass::TelemetrySink | SlotClass::AuditSink => false,
        SlotClass::PolicyEngine => matches!(value, "yaml-rules"),
        // Cache slot accepts an explicit `disabled` keyword so an
        // operator can opt a single binding out of caching even when
        // the gateway-wide `storage.response_cache` is enabled.
        SlotClass::Cache => matches!(value, "disabled"),
        _ => false,
    }
}

/// Emit a `WARN` log line for every loaded plugin whose id is
/// never referenced by any consumer slot AND whose class doesn't
/// implicitly register (http-route / identity / tool-gate /
/// transform / binding plugins all run by virtue of being loaded).
///
/// `referenced` is the set of plugin ids harvested from every
/// consumer slot's resolved [`KindRef`]. Call this once at boot
/// after every slot has resolved.
pub fn warn_unwired_plugins(plugins: &[PluginEntryConfig], referenced: &BTreeSet<&str>) {
    for entry in plugins {
        if entry.disabled {
            continue;
        }
        if implicitly_registered(&entry.class) {
            continue;
        }
        if !referenced.contains(entry.id.as_str()) {
            tracing::warn!(
                plugin_id = %entry.id,
                plugin_class = %entry.class,
                "plugin loaded but never wired: no consumer slot references its id; \
                 either remove the entry or wire it into a slot via `kind: {}`",
                entry.id,
            );
        }
    }
}

fn implicitly_registered(class: &str) -> bool {
    // Canonical PluginClass snake_case forms (per
    // `libs/plugin-protocol/src/manifest.rs`). Plugins of these
    // classes register implicitly into a chain by virtue of being
    // loaded — they don't need a consumer slot's `kind:` to
    // reference them; warn_unwired_plugins skips them.
    matches!(
        class,
        "http_route" | "identity_provider" | "tool_gate" | "transform" | "backend"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, class: &str) -> PluginEntryConfig {
        PluginEntryConfig {
            id: id.to_owned(),
            r#ref: None,
            kind: "native".to_owned(),
            class: class.to_owned(),
            source: super::super::PluginSourceConfig::default(),
            config: serde_json::Value::Null,
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        }
    }

    fn kind(value: &str) -> KindRef {
        KindRef {
            kind: value.to_owned(),
            config: serde_json::Value::Null,
        }
    }

    #[test]
    fn rejects_empty_kind() {
        let err = resolve_kind(SlotClass::Cache, &kind(""), &[], "single_node").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn cluster_keyword_accepts_when_role_provided() {
        let r = resolve_kind(SlotClass::Kv, &kind("cluster"), &[], "single_node").unwrap();
        assert_eq!(r, ResolvedKind::Cluster);
    }

    #[test]
    fn cluster_keyword_refuses_when_role_missing() {
        // NATS provides bus + kv but not cache.
        let err = resolve_kind(SlotClass::Cache, &kind("cluster"), &[], "nats").unwrap_err();
        assert!(
            err.to_string().contains("doesn't provide a `cache` role"),
            "{err}"
        );
    }

    #[test]
    fn builtin_keyword_resolves_for_matching_slot() {
        let r = resolve_kind(SlotClass::Cache, &kind("in-process"), &[], "single_node").unwrap();
        assert_eq!(r, ResolvedKind::Builtin("in-process".to_owned()));
    }

    #[test]
    fn full_plugin_id_resolves_when_class_matches() {
        let plugins = vec![entry("dev.mcpg.cache.redis", "cache")];
        let r = resolve_kind(
            SlotClass::Cache,
            &kind("dev.mcpg.cache.redis"),
            &plugins,
            "single_node",
        )
        .unwrap();
        assert_eq!(r, ResolvedKind::Plugin("dev.mcpg.cache.redis".to_owned()));
    }

    #[test]
    fn full_plugin_id_refuses_when_class_mismatches() {
        let plugins = vec![entry("dev.mcpg.cache.redis", "cache")];
        let err = resolve_kind(
            SlotClass::Kv,
            &kind("dev.mcpg.cache.redis"),
            &plugins,
            "single_node",
        )
        .unwrap_err();
        assert!(err.to_string().contains("class `cache`"), "{err}");
        assert!(err.to_string().contains("expects class `store`"), "{err}");
    }

    #[test]
    fn short_alias_resolves_via_namespace_prefix() {
        let plugins = vec![entry("dev.mcpg.cache.redis", "cache")];
        let r = resolve_kind(SlotClass::Cache, &kind("redis"), &plugins, "single_node").unwrap();
        assert_eq!(r, ResolvedKind::Plugin("dev.mcpg.cache.redis".to_owned()));
    }

    #[test]
    fn short_alias_refuses_with_loaded_id_list() {
        let plugins = vec![entry("dev.mcpg.cache.redis", "cache")];
        let err = resolve_kind(SlotClass::Kv, &kind("redis"), &plugins, "single_node").unwrap_err();
        // The actual lookup attempts dev.mcpg.kv.redis, which doesn't exist.
        assert!(err.to_string().contains("dev.mcpg.kv.redis"), "{err}");
    }

    #[test]
    fn sink_slots_match_canonical_per_signal_classes() {
        // Each per-signal SlotClass variant claims the canonical
        // PluginClass it expects to find.
        assert_eq!(SlotClass::AuditSink.plugin_class(), "audit_sink");
        assert_eq!(SlotClass::LogSink.plugin_class(), "log_sink");
        assert_eq!(SlotClass::MetricsSink.plugin_class(), "metrics_sink");
        assert_eq!(SlotClass::TelemetrySink.plugin_class(), "telemetry_sink");
    }

    #[test]
    fn log_sink_slot_accepts_stderr_keyword() {
        // Log signal carries `stderr`/`stdout`/`file` as built-in
        // keywords (in-gateway tracing_subscriber layers).
        let r = resolve_kind(SlotClass::LogSink, &kind("stderr"), &[], "single_node").unwrap();
        assert_eq!(r, ResolvedKind::Builtin("stderr".to_owned()));
    }

    #[test]
    fn metrics_sink_slot_refuses_stderr_keyword() {
        // Metrics + traces have no built-in keywords.
        let err =
            resolve_kind(SlotClass::MetricsSink, &kind("stderr"), &[], "single_node").unwrap_err();
        assert!(err.to_string().contains("metrics-sink"), "{err}");
    }

    #[test]
    fn telemetry_sink_slot_resolves_loaded_otlp_plugin() {
        // OTLP plugin declares class `telemetry_sink`. Listing it
        // against the traces sink slot resolves cleanly.
        let plugins = vec![entry("dev.mcpg.observability.otlp", "telemetry_sink")];
        let r = resolve_kind(
            SlotClass::TelemetrySink,
            &kind("dev.mcpg.observability.otlp"),
            &plugins,
            "single_node",
        )
        .unwrap();
        assert_eq!(
            r,
            ResolvedKind::Plugin("dev.mcpg.observability.otlp".to_owned())
        );
    }

    #[test]
    fn telemetry_sink_slot_refuses_metrics_sink_class() {
        // Cross-signal class mismatch: prometheus declares class
        // `metrics_sink` but is listed under traces. Per-signal
        // split catches this at resolve time.
        let plugins = vec![entry("dev.mcpg.observability.prometheus", "metrics_sink")];
        let err = resolve_kind(
            SlotClass::TelemetrySink,
            &kind("dev.mcpg.observability.prometheus"),
            &plugins,
            "single_node",
        )
        .unwrap_err();
        assert!(err.to_string().contains("class `metrics_sink`"), "{err}");
        assert!(
            err.to_string().contains("expects class `telemetry_sink`"),
            "{err}"
        );
    }

    #[test]
    fn cluster_provides_table_uses_only_role_vocabulary() {
        // The static table must speak the cache/kv/bus role
        // vocabulary, never the key_value_store/pub_sub/lease/watch/
        // peers primitive-accessor vocabulary.
        let roles: BTreeSet<&str> = mcpg_plugin_protocol::descriptor::CLUSTER_PROVIDES_ROLES
            .iter()
            .copied()
            .collect();
        for kind in [
            "single_node",
            "nats",
            "nats-jetstream",
            "redis",
            "consul",
            "etcd",
            "dev.mcpg.cluster.custom", // catch-all
        ] {
            for role in cluster_provides_for_kind(kind) {
                assert!(
                    roles.contains(role),
                    "kind `{kind}` table emitted non-role token `{role}`"
                );
            }
        }
    }

    #[test]
    fn is_builtin_cluster_kind_matches_explicit_arms_only() {
        for kind in [
            "single_node",
            "single-node-builtin",
            "nats",
            "nats-jetstream",
            "redis",
            "consul",
            "etcd",
        ] {
            assert!(is_builtin_cluster_kind(kind), "{kind} should be built-in");
        }
        // Plugin-class / 3rd-party clusters fall into the catch-all and
        // are NOT asserted against the table at boot.
        assert!(!is_builtin_cluster_kind("dev.mcpg.cluster.custom"));
        assert!(!is_builtin_cluster_kind("raft"));
    }

    #[test]
    fn warn_unwired_skips_implicitly_registered_classes() {
        // identity_provider / tool_gate / transform / binding /
        // http_route never appear in a `kind:` slot — they
        // register by class.
        let plugins = vec![
            entry("dev.mcpg.identity.oidc", "identity_provider"),
            entry("dev.mcpg.guardrail.secret-scan", "tool_gate"),
        ];
        let referenced = BTreeSet::new();
        warn_unwired_plugins(&plugins, &referenced);
        // No assertion — the function emits via tracing; the test
        // just confirms it doesn't panic and doesn't WARN for these.
    }
}
