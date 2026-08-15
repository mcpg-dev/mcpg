//! Plugin configuration types — `plugins[]` array entries plus all
//! plugin-related sub-types (sources, integrity, signature, resource
//! limits, observability overrides, http-route tuning).
//!
//! `plugins:` (top-level YAML) is a flat `Vec<PluginEntryConfig>` —
//! pure registration. The companion concerns it does NOT hold:
//! - Per-entry wiring (capability grants / signature trust /
//!   resource limits / observability overrides / http-route tuning)
//!   lives on the entry itself (`granted_capabilities`, `signature`,
//!   `limits`, `observability`, `http_route`).
//! - Plugin health-probe tuning lives at
//!   `observability.plugin_health_probe:`.
//! - OCI registry defaults live at `gateway.plugin_registry:`.
//! - The config-overlay URI list lives at `gateway.config_overlay:`.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::default_true;

/// Validate a `plugins[]` array (top-level Vec<PluginEntryConfig>).
///
/// There is no separate kill switch — an empty `plugins[]` array
/// loads no plugins — so this check always runs.
///
/// `entry.id` is the OPERATOR ALIAS (unique within the array).
/// `entry.r#ref` is the artifact's manifest id (reverse-DNS). When
/// `ref` is unset, alias and manifest id are the same string. The
/// pair `(alias, ref)` lets one artifact ship under multiple operator
/// aliases (multi-instance), e.g. two `cedar` engines bound to
/// different tenants.
pub fn validate_plugins(entries: &[PluginEntryConfig]) -> Result<()> {
    let mut seen_aliases = std::collections::HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let path = format!("plugins[{}]", i);
        if entry.id.trim().is_empty() {
            return Err(anyhow::anyhow!("{}.id (alias) must not be empty", path));
        }
        if !seen_aliases.insert(&entry.id) {
            return Err(anyhow::anyhow!(
                "{}.id alias '{}' is duplicated; plugin aliases must be unique within `plugins[]`",
                path,
                entry.id
            ));
        }
        // Ref format check (when set). The ref is the artifact's
        // manifest id; it MUST match a reverse-DNS form so it
        // cross-checks cleanly against the loaded plugin's
        // descriptor.id at boot. Aliases (entry.id) carry no such
        // constraint — operators are free to pick `cedar.tenant-a`
        // or `prod-cache` or whatever reads well in their config.
        if let Some(r) = entry.r#ref.as_deref() {
            if r.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "{}.ref must not be empty when set; omit the field for the simple case",
                    path
                ));
            }
            if !is_reverse_dns(r) {
                return Err(anyhow::anyhow!(
                    "{}.ref '{}' must be a reverse-DNS manifest id (lowercase, dot-separated, \
                     at least one dot, e.g. dev.mcpg.policy.cedar)",
                    path,
                    r
                ));
            }
        }
        match entry.kind.as_str() {
            "native" | "wasm" => {}
            other => {
                return Err(anyhow::anyhow!(
                    "{}.kind must be 'native' or 'wasm', got '{}'",
                    path,
                    other
                ));
            }
        }
        // Operator-facing `class:` field — must match the snake_case
        // serialization of a `PluginClass` variant (per
        // `libs/plugin-protocol/src/manifest.rs`). This is the
        // canonical form: the same string that plugin manifests
        // (`plugin.yaml`) declare and that the runtime
        // `PluginManifest.plugin_class.to_string()` emits.
        //
        // The allowlist iterates [`mcpg_plugin_protocol::abi::ALL_KINDS`]
        // — the single source of truth for the kind strings. Adding a
        // new entity kind updates `ALL_KINDS` exactly once and this
        // validator picks it up automatically.
        let class = entry.class.as_str();
        if !mcpg_plugin_protocol::abi::ALL_KINDS.contains(&class) {
            return Err(anyhow::anyhow!(
                "{path}.class: '{class}' is not a recognised PluginClass. \
                 Valid values (snake_case PluginClass variants): {valid}",
                valid = mcpg_plugin_protocol::abi::ALL_KINDS.join(", ")
            ));
        }
        if !entry.source.is_well_formed() {
            return Err(anyhow::anyhow!(
                "{}.source must specify exactly one of `path` or `oci` (got path={:?}, oci={:?})",
                path,
                entry.source.path,
                entry.source.oci,
            ));
        }
    }
    Ok(())
}

/// Periodic health-probe configuration. The probe is the only
/// writer of `PluginState::Degraded`; without it plugins stay
/// perpetually `Active` regardless of whether they're actually
/// responding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthProbeConfig {
    /// Probe plugins periodically. Default: `true`. Set `false` to
    /// turn off the prober entirely (the `Degraded` state then never
    /// flips — test-only or historical deployments).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Milliseconds between probe cycles. Default: 30000 (30s).
    #[serde(default = "default_health_probe_interval_ms")]
    pub interval_ms: u64,

    /// Per-probe deadline in milliseconds. A plugin whose FFI call
    /// exceeds this is counted as a failure. Default: 5000 (5s).
    #[serde(default = "default_health_probe_timeout_ms")]
    pub probe_timeout_ms: u64,

    /// Consecutive failures before flipping `Active` → `Degraded`.
    /// Default: 3.
    #[serde(default = "default_health_probe_failure_threshold")]
    pub failure_threshold: u32,
}

impl Default for HealthProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: default_health_probe_interval_ms(),
            probe_timeout_ms: default_health_probe_timeout_ms(),
            failure_threshold: default_health_probe_failure_threshold(),
        }
    }
}

fn default_health_probe_interval_ms() -> u64 {
    30000
}
fn default_health_probe_timeout_ms() -> u64 {
    5000
}
fn default_health_probe_failure_threshold() -> u32 {
    3
}

/// Configuration for a single plugin entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginEntryConfig {
    /// Operator alias for this entry — unique within the gateway's
    /// `plugins[]` array. Used as the registry key, audit attribution,
    /// and per-plugin observability target. When `ref` is omitted, the
    /// alias doubles as the artifact's manifest id (the simple,
    /// single-instance case). When `ref` is set, the alias is a
    /// separate operator-chosen label (multi-instance pattern).
    pub id: String,
    /// Manifest id (artifact identity) — reverse-DNS, e.g.
    /// `dev.mcpg.policy.cedar`. Optional; defaults to `id` when
    /// absent.
    ///
    /// Set this when one artifact must run under multiple aliases
    /// in the same gateway (e.g. two `cedar` engines bound to
    /// different tenants), or when the alias should read more
    /// naturally than the reverse-DNS manifest id. The boot loader
    /// cross-checks this value against the plugin's descriptor.id;
    /// a mismatch fails the load.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
    pub r#ref: Option<String>,
    /// Plugin tier: `"native"` or `"wasm"`.
    #[serde(default = "default_plugin_tier")]
    pub kind: String,
    /// Plugin class — the snake_case `PluginClass` variant the plugin
    /// implements. Must match the `class:` field in the plugin's
    /// own `plugin.yaml` manifest. Determines which plugin chain /
    /// slot the plugin is registered into. Valid values:
    /// `tool_gate`, `transform`, `identity_provider`, `backend`,
    /// `watch_strategy`, `http_route`, `audit_sink`, `store`,
    /// `cache`, `telemetry_sink`, `log_sink`, `metrics_sink`,
    /// `secret_provider`, `config_provider`, `transport`,
    /// `policy_engine`, `cluster`, `catalog_provider`,
    /// `credential_issuer`, `approval_notifier`, `content_store`.
    #[serde(default = "default_plugin_class")]
    pub class: String,
    /// Source path or reference for the plugin artifact.
    #[serde(default)]
    pub source: PluginSourceConfig,
    /// Plugin-specific configuration passed to the plugin instance.
    #[serde(default)]
    pub config: serde_json::Value,
    /// Plugin signature checks. Consolidates the content hash, the
    /// per-entry-overridable verification policy, and the trusted
    /// Ed25519 keys this plugin's artifact must verify against
    /// (per-entry, no global trust pool).
    ///
    /// `None` means defaults: integrity hash unset (no pin), policy
    /// inherits `gateway.plugin_registry.default_signature_policy:`,
    /// no per-plugin trusted keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureConfig>,
    /// Per-plugin typed host capability grants.
    /// Each entry is one of [`mcpg_plugin_protocol::capability::Capability`]'s
    /// known variants. Two equivalent YAML shapes accepted:
    ///
    /// ```yaml
    /// granted_capabilities:
    ///   - "network_outbound"                          # bare string (no-args variants only)
    ///   - { type: "audit_write" }                     # object form, no args
    ///   - { type: "filesystem_read", paths: ["/etc/myapp/"] }
    ///   - { type: "secrets_read", schemes: ["vault", "aws-sm"] }
    /// ```
    ///
    /// Variant-args kinds (`filesystem_read`, `filesystem_write`,
    /// `secrets_read`, `credential_issue`, `config_read`) require
    /// the object form — bare strings for them produce a parse
    /// error at config load time, citing the plugin id and the
    /// missing args field.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_granted_capabilities"
    )]
    // JsonSchema-wise, render the field as a JSON array — Capability's
    // wire shape (tagged enum + bare-string sugar) doesn't fit
    // schemars's auto-derive cleanly. The CLI / docs validator
    // accepts any JSON array; the eager `parse_value` deserialiser
    // does the actual typed-shape check at config load time.
    #[schemars(with = "Vec<serde_json::Value>")]
    pub granted_capabilities: Vec<mcpg_plugin_protocol::capability::Capability>,
    /// Resource limits for Wasm plugins (ignored for native).
    #[serde(default)]
    pub limits: Option<PluginResourceLimitsConfig>,
    /// Per-plugin FFI hardening overrides for native cdylib plugins.
    /// `None` = inherit the spec defaults
    /// (1s lifecycle / 5s control / 30s data / 256 KiB payload).
    /// Ignored for Wasm plugins (those use `limits.timeout_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ffi_limits: Option<PluginFfiLimitsConfig>,
    /// When false, the plugin runs in shadow mode: evaluate and log, but
    /// override Deny/Challenge → Allow. Defaults to true (enforce).
    #[serde(default = "bool_true")]
    pub enforce: bool,
    /// When `true`, the plugin entry is parsed + validated but not
    /// loaded at boot. Useful for keeping a plugin's config in source
    /// control while temporarily turning it off without removing the
    /// entry. Default `false`.
    #[serde(default)]
    pub disabled: bool,
    /// **Inline fast-slot dispatch.** When `true`, this plugin's hot-path
    /// slots are called **inline** — without the `spawn_blocking` ferry or
    /// per-call timeout: the typed/borrowed `*_fast` vtable path for Tier-1
    /// slots (`tool_gate`, cutting dispatch ~33×), and the synchronous
    /// `execute` slot for `backend` plugins (which also lets the sync tool
    /// dispatch bridge resolve the call on its first poll and skip
    /// `block_in_place`). This is an explicit operator-trust decision: the
    /// plugin's slots MUST be fast, non-blocking, and bounded, because a
    /// hung/blocking slot now wedges a runtime worker with no backstop.
    /// Defaults to `false` (the safe, ferried path). Only enable for trusted,
    /// pure-compute / in-process first-party plugins.
    #[serde(default)]
    pub inline_dispatch: bool,
    /// `http_route`-specific operator tuning. Ignored for non-`http_route`
    /// plugins. Absent = all defaults (enabled, namespaced mount, spec's
    /// own body cap + identity policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_route: Option<PluginHttpRouteConfig>,
    /// Per-plugin observability triad override.
    /// `inherit` (default), `replace`, or `tee` semantics for
    /// each signal independently. Absent = all signals inherit
    /// the global `observability.{logs,metrics,traces}` config.
    /// Routing is keyed by `module_path_prefix` from the plugin
    /// manifest — events from this plugin's crate get the
    /// override; events from gateway code about a plugin call
    /// stay on the global path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<PluginObservabilityToggle>,
}

impl PluginEntryConfig {
    /// Effective manifest id for this entry — `ref` if set, else
    /// `id`. Used by the boot loader's descriptor cross-check and by
    /// the library-load dedupe key. Single-instance configs where `id`
    /// equals the manifest id work because `ref_or_id()` falls back to
    /// `id`.
    pub fn ref_or_id(&self) -> &str {
        self.r#ref.as_deref().unwrap_or(&self.id)
    }
}

/// Reverse-DNS check for the `ref` field — lowercase letters, digits,
/// `_`, `-`, dot-separated, at least one dot. Mirrors the format the
/// host accepts for plugin `manifest.id` so the cross-check at boot
/// stays consistent.
fn is_reverse_dns(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    let segs: Vec<&str> = s.split('.').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return false;
    }
    segs.iter().all(|seg| {
        seg.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    })
}

/// Per-plugin signature configuration.
///
/// Consolidates three signature concerns into one per-plugin block:
/// - The content-hash pin.
/// - The verification policy — per-plugin overridable, with the
///   global default in
///   `gateway.plugin_registry.default_signature_policy:`.
/// - The Ed25519 trusted keys this artifact must verify against —
///   per-plugin so plugins from different vendors can carry
///   different keys without pooling them in one trust anchor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignatureConfig {
    /// Verification policy for this plugin. `None` = inherit
    /// `gateway.plugin_registry.default_signature_policy:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<SignaturePolicy>,
    /// SHA-256 content hash to pin (hex-encoded). When set, the
    /// gateway refuses to load the artifact if its computed hash
    /// doesn't match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Ed25519 verification keys this artifact's signature must
    /// verify against. Empty = inherit gateway-wide defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_keys: Vec<TrustedKeyConfig>,
}

/// One trusted-key entry inside `SignatureConfig.trusted_keys`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedKeyConfig {
    /// Operator-chosen id for the key (audit-trail label).
    pub id: String,
    /// PEM-encoded public key. Multi-line literal in YAML.
    pub pem: String,
}

/// Per-plugin observability toggle. Each signal is independent —
/// operators can disable metrics for one plugin while leaving its
/// logs and traces flowing. Events still route through the GLOBAL
/// `observability.{logs,metrics,traces}.sinks` list when
/// admitted; this struct only controls *whether* a plugin's
/// events make it that far + at what level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginObservabilityToggle {
    /// Logs toggle. `None` = inherit globals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<SignalToggle>,
    /// Metrics toggle. `None` = inherit globals. Note: metrics
    /// has no `level` (metrics-rs has no levels) — the field is
    /// accepted in YAML for forward compat but ignored today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<SignalToggle>,
    /// Traces toggle. `None` = inherit globals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traces: Option<SignalToggle>,
}

/// Per-plugin per-signal toggle. Four knobs:
///
/// - `enabled` (default `true`): when `false`, every event from
///   this plugin's crate is dropped at the bridge before it
///   reaches the sink fan-out — the "silence this noisy plugin"
///   pattern.
/// - `level` (logs / traces only): minimum severity an event
///   must clear to be emitted. Composed into the bridge layer's
///   permissive filter so per-plugin verbosity boosts AND
///   suppressions both work. Accepted: `trace` / `debug` /
///   `info` / `warn` / `error` (case-insensitive).
/// - `mode` (default `inherit`): how to route events that pass the
///   gate. `inherit` flows through the global sink list (the
///   default behaviour). `replace` routes ONLY to the
///   plugins listed under `sinks` — used for compliance carve-outs
///   ("audit logs go to my SIEM, never to stdout"). `tee` fans out
///   to BOTH the global sink list AND the per-plugin `sinks`.
/// - `sinks`: plugin ids of the sink plugins to use under
///   `mode: replace | tee`. Each id MUST match a registered sink
///   plugin for the corresponding signal — log sink for
///   `logs.sinks`, metrics sink for `metrics.sinks`, span sink for
///   `traces.sinks`. If any id is unknown to the matching signal,
///   the gateway refuses to boot (validated post-registration in
///   `app::validate_per_plugin_sink_ids`). Listing a real log sink
///   id under `metrics.sinks` is rejected — sink-kind crossover is
///   a typo, not a feature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalToggle {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "SinkMode::is_default")]
    pub mode: SinkMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<String>,
}

/// How to route events for a per-plugin signal toggle. Operator
/// schema: `mode: inherit | replace | tee`.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SinkMode {
    /// Inherit the global sink list — the same routing every
    /// other plugin's events use. Default.
    #[default]
    Inherit,
    /// Route admitted events ONLY to the per-plugin `sinks` list.
    /// Skips the global sink fan-out entirely. Used for compliance
    /// carve-outs (audit logs stay inside the SIEM).
    Replace,
    /// Tee — admitted events flow to BOTH the global sink list AND
    /// the per-plugin `sinks` list. Useful when an operator wants
    /// to keep default routing but additionally mirror a noisy
    /// plugin's events to a debugging sink.
    Tee,
}

impl SinkMode {
    fn is_default(&self) -> bool {
        matches!(self, SinkMode::Inherit)
    }
}

/// Discriminator passed into [`SignalToggle::validate`] so the
/// validator can apply signal-specific rules. `Metrics` rejects the
/// `level` field outright (metrics-rs has no severity concept — a
/// level on a metrics toggle is an operator typo, not a feature);
/// `Logs` and `Traces` accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Logs,
    Metrics,
    Traces,
}

impl SignalKind {
    fn as_label(self) -> &'static str {
        match self {
            SignalKind::Logs => "logs",
            SignalKind::Metrics => "metrics",
            SignalKind::Traces => "traces",
        }
    }
}

impl Default for SignalToggle {
    fn default() -> Self {
        Self {
            enabled: true,
            level: None,
            mode: SinkMode::default(),
            sinks: Vec::new(),
        }
    }
}

impl SignalToggle {
    /// Validate the operator-supplied combination at parse time.
    /// Returns a hint string for non-fatal config oddities; returns
    /// `Err(...)` for combinations the gateway refuses to boot
    /// with. `kind` lets the validator apply signal-specific rules
    /// (metrics rejects `level` outright; logs / traces accept it).
    pub fn validate(&self, kind: SignalKind) -> Result<Option<String>, String> {
        // Fatal: metrics + level — metrics-rs has no severity, so
        // the field can never have an effect. Schema accepts the key
        // for forward compat but boot refuses on use to surface the
        // typo loudly.
        if matches!(kind, SignalKind::Metrics) && self.level.is_some() {
            return Err(format!(
                "observability `level` is not supported for the `{}` signal \
                 (metrics-rs has no severity); remove the level field",
                kind.as_label(),
            ));
        }
        // Fatal: replace / tee with empty sinks list — would either
        // drop all events (replace) or be a no-op (tee). Both are
        // operator mistakes that should fail loud at boot.
        if matches!(self.mode, SinkMode::Replace | SinkMode::Tee) && self.sinks.is_empty() {
            return Err(format!(
                "observability mode = {:?} requires a non-empty `sinks` list; either \
                 list the per-plugin sink ids or change mode to `inherit`",
                self.mode,
            ));
        }
        // Fatal: sinks list non-empty under inherit — the operator
        // wrote per-plugin sinks but they will never be used.
        // Catching this early prevents silent confusion.
        if matches!(self.mode, SinkMode::Inherit) && !self.sinks.is_empty() {
            return Err(
                "observability `sinks` list is set but `mode: inherit` ignores it; \
                 either set mode to `replace` / `tee` or remove the sinks list"
                    .into(),
            );
        }
        // Hint-only: enabled=false with level — level is ignored
        // while enabled=false but operators sometimes flip enabled
        // to test sink config without dropping the level setting.
        if !self.enabled && self.level.is_some() {
            return Ok(Some(
                "enabled = false with a level field — the level is \
                 ignored while enabled is false; remove the level \
                 field once you confirm the disable behaviour"
                    .into(),
            ));
        }
        Ok(None)
    }
}

/// Operator-side tuning for an `http_route` plugin entry. Every
/// field is optional; the struct is omitted entirely for plugins
/// that don't need any override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginHttpRouteConfig {
    /// When `true`, the plugin is not registered at all. Operators
    /// use this to swap out a gateway built-in (e.g. the built-in
    /// `dev.mcpg.builtin.http.status`) for a custom implementation
    /// without patching the gateway. The gateway logs a warning if
    /// a disabled plugin also appears elsewhere in the plugins list
    /// with conflicting settings — disable is authoritative.
    #[serde(default)]
    pub disabled: bool,
    /// When `true`, plugin routes mount at the top-level paths the
    /// plugin declared (override mode), instead of the namespaced
    /// `/plugins/{id}/{entity}/` mount (the `false` default). The gate
    /// is this operator-set flag alone; the gateway refuses two
    /// plugins that claim the same top-level path. Override-mode
    /// dispatch is not yet wired — this field is the gate the
    /// dispatcher will consult once that support lands.
    #[serde(default)]
    pub allow_path_override: bool,
    /// Per-entity override for `RouteSpec.max_body_bytes`. When
    /// set, the dispatcher uses this value instead of the plugin's
    /// declared cap — operator tightens (or relaxes) the plugin's
    /// spec without a plugin rebuild. `None` = use the plugin's
    /// declared value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Per-entity override for `RouteSpec.requires_identity`. When
    /// set, the dispatcher enforces this instead of the plugin's
    /// declared value. Typical use: operator tightens an endpoint
    /// the plugin declared anonymous. `None` = use the plugin's
    /// declared value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_identity: Option<bool>,
}

/// Shared serde default helper — `true` for boolean fields that
/// should be on-by-default but stored as a real `bool` rather than
/// a Default-backed struct field.
fn bool_true() -> bool {
    true
}

fn default_plugin_tier() -> String {
    "native".into()
}

fn default_plugin_class() -> String {
    "tool_gate".into()
}

/// Plugin artifact source configuration.
///
/// Exactly one of `path` / `oci` must be set. Both unset is invalid;
/// both set is invalid. The source type determines how the gateway
/// resolves the artifact at boot time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSourceConfig {
    /// Path to the plugin artifact on the local filesystem. Accepts
    /// a raw `.so` / `.wasm` (with a sidecar `plugin.yaml`) or a
    /// packaged `.zip`.
    #[serde(default)]
    pub path: Option<String>,

    /// OCI reference (e.g. `ghcr.io/mcpg-dev/source-code/plugins/audit:1.0.0`
    /// or `plugins/audit@sha256:…`). At boot the gateway pulls the
    /// artifact, verifies the manifest digest, caches it to
    /// `plugin_registry.cache_dir`, and loads it through the same
    /// sidecar / packaged-zip path `path` would have taken. When
    /// the reference is missing a registry prefix, the
    /// `plugin_registry.default_registry` value is prepended — which is
    /// itself repointable per deployment via the
    /// `MCPG_DEFAULT_PLUGIN_REGISTRY` environment variable.
    ///
    /// **The reference is PLATFORM-AGNOSTIC.** Plugin artifacts are
    /// published per os/arch/libc (the CD tag suffix
    /// `-<os>[-musl]-<arch>`, plus `-wasi-wasm` for WASM), and the gateway
    /// resolves the right one for the host it runs on — you do NOT write the
    /// platform suffix:
    /// - **no tag** (`…/plugins/audit`) → tracks the floating
    ///   `protocol-<major>` tag for the plugin protocol this gateway speaks
    ///   (`…:protocol-1-linux-amd64` on a glibc x86-64 host, etc.).
    /// - **a version/tag** (`…/audit:1.0.0`, `…/audit:protocol-1`) → the
    ///   host's platform suffix is appended (`…:1.0.0-darwin-arm64`, …).
    /// - **already platform-suffixed** (`…:1.0.0-linux-amd64`) or
    ///   **`@sha256:` digest-pinned** → pulled verbatim (explicit pin; a
    ///   digest is inherently one specific platform's manifest).
    ///
    /// In every auto-resolved case the gateway prefers the native cdylib for
    /// its platform and transparently falls back to the WASM (`wasi-wasm`)
    /// build, so a bare reference works for native and WASM plugins alike.
    ///
    /// (Native plugins are ALSO published as a multi-platform OCI image index
    /// under the bare `:<version>` / `:protocol-<major>` tag — plus a separate
    /// `:<version>-musl` index — so generic OCI tooling (`docker pull`,
    /// `skopeo`, `crane`) resolves the right platform from one tag. The gateway
    /// does not use the index; it resolves the concrete per-platform tag above,
    /// which also pins libc, which an index cannot express.)
    #[serde(default)]
    pub oci: Option<String>,
}

impl PluginSourceConfig {
    /// Whether this source declares exactly one of `path` / `oci`.
    /// Used by `PluginsConfig::validate` to fail-fast on malformed
    /// operator input.
    pub(crate) fn is_well_formed(&self) -> bool {
        self.path.is_some() ^ self.oci.is_some()
    }
}

/// Configuration for resolving plugin artifacts from OCI
/// registries. Covers default registry, local cache, auth, TLS,
/// and signature policy.
///
/// This section is only consulted when at least one plugin entry
/// has `source.oci` set. For purely local deployments (every
/// plugin loaded from `source.path`), all defaults apply and the
/// registry subsystem does nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRegistryConfig {
    /// Default registry when an `oci:` reference has no registry
    /// prefix. Example: `ghcr.io/mcpg-dev/source-code/plugins`.
    ///
    /// Omitting the key falls back to the `MCPG_DEFAULT_PLUGIN_REGISTRY`
    /// environment variable, then to the compiled-in default. Setting it
    /// here always wins over both.
    #[serde(default = "default_plugin_registry")]
    pub default_registry: String,

    /// Local cache directory for pulled OCI artefacts. Keyed by
    /// manifest digest so digest-pinned references skip the
    /// network on subsequent boots. When unset, defaults to
    /// `$XDG_CACHE_HOME/mcpg/plugins/oci` (or
    /// `/var/cache/mcpg/plugins/oci` for system deployments).
    #[serde(default)]
    pub cache_dir: Option<String>,

    /// Registry authentication strategy.
    #[serde(default)]
    pub auth: PluginRegistryAuthConfig,

    /// TLS knobs for registry connections.
    #[serde(default)]
    pub tls: PluginRegistryTlsConfig,

    /// Mirror registries tried in order before the reference's
    /// source registry. Supports air-gap / pull-through caches.
    #[serde(default)]
    pub mirrors: Vec<PluginRegistryMirrorConfig>,

    /// Default signature verification policy applied to every
    /// `plugins[*]` entry that doesn't carry its own
    /// `signature.policy:` override. Defaults to `Warn` (log but
    /// don't fail) for first-rollout safety; flip to `Enforce`
    /// once trusted keys are wired up across all entries.
    #[serde(default)]
    pub default_signature_policy: SignaturePolicy,

    /// Gateway-wide Ed25519 trust anchors. An entry whose
    /// `signature.trusted_keys` is empty verifies against these
    /// (plus the built-in official mcpg release key); an entry that
    /// carries its own keys verifies against exactly those, so
    /// third-party vendors never pool into the global anchor set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_keys: Vec<TrustedKeyConfig>,

    /// Optional path to a JSON revocation list. When set, the
    /// gateway loads the file at startup, indexes the revoked
    /// artefact SHA-256s, and refuses to load any plugin whose
    /// hash matches an entry — even if its Ed25519 signature is
    /// valid. Format documented in
    /// [`mcpg_plugin_host::revocation::RevocationListFile`]. Absent
    /// means "no revocation list" — every signed plugin is allowed.
    #[serde(default)]
    pub revocation_list_path: Option<String>,

    /// Hostnames (optionally `host:port`) that the OCI client should
    /// reach over plain HTTP instead of HTTPS. `localhost`,
    /// `127.0.0.1`, and `::1` are always implicit — operators only
    /// need to list this for other dev / air-gap registries.
    #[serde(default)]
    pub insecure_registries: Vec<String>,

    /// When set, every `oci:`-sourced plugin entry must carry an
    /// integrity anchor the gateway can enforce independently of the
    /// transport: a digest-pinned reference (`…@sha256:<hex>`), a
    /// `signature.sha256` artifact-hash pin, or
    /// `signature.trusted_keys`. An entry pulled by bare tag with no
    /// anchor is refused at boot. Recommended whenever `mirrors` or
    /// `insecure_registries` are configured, since a tag pulled over a
    /// mirror / plain-HTTP hop is otherwise trusted on the registry's
    /// word alone. Defaults to `false` (every entry accepted; configured
    /// anchors are still enforced downstream).
    #[serde(default)]
    pub require_integrity_anchor: bool,
}

impl Default for PluginRegistryConfig {
    fn default() -> Self {
        Self {
            default_registry: default_plugin_registry(),
            cache_dir: None,
            auth: PluginRegistryAuthConfig::default(),
            tls: PluginRegistryTlsConfig::default(),
            mirrors: Vec::new(),
            default_signature_policy: SignaturePolicy::default(),
            trusted_keys: Vec::new(),
            revocation_list_path: None,
            insecure_registries: Vec::new(),
            require_integrity_anchor: false,
        }
    }
}

/// Compiled-in fallback for [`PluginRegistryConfig::default_registry`].
///
/// Must match where first-party plugins are actually published —
/// tools/release/publish-plugin.sh pushes to
/// `<this>/<short>:<ver>-<os>-<arch>`. A bare `oci:` reference (no registry
/// prefix) is resolved against it so it points at real artefacts.
pub const DEFAULT_PLUGIN_REGISTRY: &str = "ghcr.io/mcpg-dev/source-code/plugins";

/// Environment override for [`DEFAULT_PLUGIN_REGISTRY`], letting a
/// deployment repoint bare `oci:` references at a mirror or a
/// differently-named registry without editing config.
///
/// Precedence is explicit YAML (`plugin_registry.default_registry`) >
/// this > [`DEFAULT_PLUGIN_REGISTRY`]: serde only calls the default
/// function when the key is absent from the document.
pub const ENV_DEFAULT_PLUGIN_REGISTRY: &str = "MCPG_DEFAULT_PLUGIN_REGISTRY";

fn default_plugin_registry() -> String {
    resolve_default_plugin_registry(std::env::var(ENV_DEFAULT_PLUGIN_REGISTRY).ok().as_deref())
}

/// Normalise an [`ENV_DEFAULT_PLUGIN_REGISTRY`] value into a registry
/// prefix, falling back to [`DEFAULT_PLUGIN_REGISTRY`] when absent or
/// blank.
///
/// A blank override must not win: it would resolve every bare `oci:`
/// reference to a bare repository name with no registry. Trailing `/` is
/// trimmed to match what `normalise_oci_reference` expects. Neither
/// normalisation can alter the compiled default, which is already
/// trimmed.
fn resolve_default_plugin_registry(raw: Option<&str>) -> String {
    let trimmed = raw.unwrap_or_default().trim().trim_end_matches('/');
    if trimmed.is_empty() {
        DEFAULT_PLUGIN_REGISTRY.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Registry authentication configuration. At most one source of
/// credentials is consulted at push/pull time: an explicit
/// `username`+`password` pair (or env-interpolated variants),
/// otherwise the docker config.json at `docker_config_path`,
/// otherwise anonymous.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRegistryAuthConfig {
    /// Literal username (or `$VAR` / `env:VAR` for env-var
    /// interpolation).
    #[serde(default)]
    pub username: Option<String>,

    /// Literal password / bearer token (or `$VAR` / `env:VAR`).
    /// Wrapped in [`mcpg_sensitive::Sensitive`] so a stray `?config`
    /// log renders this field as `***` instead of the literal token.
    #[serde(default)]
    pub password: Option<mcpg_sensitive::Sensitive<String>>,

    /// Path to a docker config.json for credential helpers.
    /// Defaults to `~/.docker/config.json` when unset.
    #[serde(default)]
    pub docker_config_path: Option<String>,
}

/// TLS configuration for registry HTTPS connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRegistryTlsConfig {
    /// Path to a PEM bundle with extra trusted root CAs. Useful
    /// for internal registries with private CAs.
    #[serde(default)]
    pub ca_cert: Option<String>,

    /// Skip all TLS certificate verification. DANGEROUS —
    /// development-only escape hatch, emits a WARN at boot.
    #[serde(default)]
    pub insecure: bool,
}

/// A mirror registry entry. Mirrors are consulted in order
/// before the reference's source registry, matching the common
/// pull-through cache / air-gap deployment pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRegistryMirrorConfig {
    /// Mirror URL — a prefix that replaces the source registry
    /// in resolved pull URLs. Example:
    /// `harbor.internal.corp/mcpg-plugins`.
    pub url: String,

    /// Optional auth override for this mirror. When absent,
    /// inherits the top-level `plugin_registry.auth`.
    #[serde(default)]
    pub auth: Option<PluginRegistryAuthConfig>,
}

/// Signature verification policy for native plugin artefacts.
/// The Ed25519 signature attached to the artefact (`<artifact>.sig`
/// or the packaged `plugin.sig`) is the primary check; this
/// policy governs behaviour when the signature is missing or
/// invalid. Set per-plugin via `plugins[*].signature.policy:`,
/// or as a gateway-wide default via
/// `gateway.plugin_registry.default_signature_policy:`.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePolicy {
    /// Signature checks are skipped entirely. Development only;
    /// gateway emits a `governance.plugin.signature_policy_disabled`
    /// audit event for any entry that resolves to this policy
    /// so the choice is visible in the compliance trail.
    Disabled,
    /// Log a warning for missing or invalid signatures but
    /// proceed with the load — ONLY while no trusted keys are
    /// configured. The built-in official key means an inheriting
    /// entry always has keys, so this behaves like `enforce`
    /// unless a config empties the trust set.
    Warn,
    /// Refuse to load any artefact whose signature is missing or
    /// does not verify against the configured trusted keys.
    /// The default: a stock gateway loads only signed plugins.
    #[default]
    Enforce,
}

impl From<SignaturePolicy> for mcpg_plugin_host::SignaturePolicy {
    fn from(value: SignaturePolicy) -> Self {
        match value {
            SignaturePolicy::Disabled => mcpg_plugin_host::SignaturePolicy::Disabled,
            SignaturePolicy::Warn => mcpg_plugin_host::SignaturePolicy::Warn,
            SignaturePolicy::Enforce => mcpg_plugin_host::SignaturePolicy::Enforce,
        }
    }
}

impl SignaturePolicy {
    /// Human-friendly label for log lines + audit events.
    /// Mirrors [`mcpg_plugin_host::SignaturePolicy::as_label`].
    pub fn as_label(self) -> &'static str {
        match self {
            SignaturePolicy::Disabled => "disabled",
            SignaturePolicy::Warn => "warn",
            SignaturePolicy::Enforce => "enforce",
        }
    }
}

/// Resource limits for Wasm plugins.
///
/// These limits constrain the sandbox resources available to a Wasm plugin.
/// If not specified, system defaults are used (64 MiB memory, 10M fuel, 100ms timeout).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginResourceLimitsConfig {
    /// Maximum linear memory in megabytes (default: 64).
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Maximum fuel (instruction budget) per invocation (default: 10_000_000).
    #[serde(default)]
    pub fuel: Option<u64>,
    /// Wall-clock timeout per invocation in milliseconds (default: 100).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Per-plugin FFI hardening overrides for native cdylib plugins.
///
/// Native plugin calls are wrapped by the host in `spawn_blocking` +
/// `tokio::time::timeout` and bounded `RString` returns. Defaults are
/// the spec-level constants in `mcpg_plugin_protocol::abi`
/// (`FFI_{LIFECYCLE,CONTROL,DATA}_TIMEOUT_DEFAULT_MS`,
/// `FFI_MAX_PAYLOAD_BYTES`). Operators set per-plugin overrides here
/// to widen the budget for a known-slow plugin (e.g. a backend that
/// proxies an upstream multi-second API) or to tighten the cap on a
/// plugin that has a stricter SLO.
///
/// `None` on any field means "inherit the spec default".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginFfiLimitsConfig {
    /// Lifecycle slot timeout override (ms). Applies to `make`,
    /// `manifest`, `shutdown`, `drop_instance`, health probes.
    /// Default: `FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS = 1_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_timeout_ms: Option<u64>,
    /// Control slot timeout override (ms). Applies to config-set,
    /// snapshot, version, register-profile, refresh, describe,
    /// list-peers, list-catalog, etc.
    /// Default: `FFI_CONTROL_TIMEOUT_DEFAULT_MS = 5_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_timeout_ms: Option<u64>,
    /// Data slot timeout override (ms). Applies to execute, evaluate,
    /// transform, dispatch, http_route, sink-emit, etc.
    /// Default: `FFI_DATA_TIMEOUT_DEFAULT_MS = 30_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_timeout_ms: Option<u64>,
    /// Max byte-length of any single `RString` returned by this plugin
    /// to the host. Overflow rejected with a slot-appropriate
    /// fallback + bumps `mcpg_plugin_payload_oversize_total`.
    /// Default: `FFI_MAX_PAYLOAD_BYTES = 262144` (256 KiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<usize>,
}

/// Custom serde deserialiser for [`PluginEntryConfig::granted_capabilities`].
///
/// Accepts a YAML / JSON array whose entries are either:
///
/// * Bare strings (`"network_outbound"`) — no-args variants only.
/// * Objects (`{type: "filesystem_read", paths: [...]}`) — every variant.
///
/// Each entry is passed through [`Capability::parse_value`] so a typo
/// is caught **at config load time** with a clear error message
/// (operator sees `unknown capability kind "totally_made_up"` before
/// the gateway even tries to start). Deferring to the boot path's
/// `Capability::Unknown` route would still reject, but with a less
/// precise error site.
fn deserialize_granted_capabilities<'de, D>(
    deserializer: D,
) -> Result<Vec<mcpg_plugin_protocol::capability::Capability>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let raw: Vec<serde_json::Value> = Vec::deserialize(deserializer)?;
    let mut out = Vec::with_capacity(raw.len());
    for (idx, v) in raw.iter().enumerate() {
        match mcpg_plugin_protocol::capability::Capability::parse_value(v) {
            Ok(cap) => out.push(cap),
            Err(e) => {
                return Err(D::Error::custom(format!(
                    "granted_capabilities[{idx}]: {e}"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod default_registry_tests {
    use super::*;

    /// The shipped default must be byte-identical with no override
    /// present — this knob is configurability, not a migration.
    #[test]
    fn absent_override_yields_the_compiled_default() {
        assert_eq!(
            resolve_default_plugin_registry(None),
            "ghcr.io/mcpg-dev/source-code/plugins"
        );
        assert_eq!(
            DEFAULT_PLUGIN_REGISTRY,
            "ghcr.io/mcpg-dev/source-code/plugins"
        );
    }

    #[test]
    fn override_repoints_the_registry() {
        assert_eq!(
            resolve_default_plugin_registry(Some("registry.airgap.internal/mcpg/plugins")),
            "registry.airgap.internal/mcpg/plugins"
        );
    }

    /// The public channel drops the repository path segment.
    #[test]
    fn override_repoints_to_the_public_channel() {
        assert_eq!(
            resolve_default_plugin_registry(Some("ghcr.io/mcpg-dev/plugins")),
            "ghcr.io/mcpg-dev/plugins"
        );
    }

    /// A blank override would leave bare `oci:` references with no
    /// registry at all, so it must lose to the compiled default.
    #[test]
    fn blank_override_falls_back_to_the_compiled_default() {
        for blank in [Some(""), Some("   "), Some("\t\n"), Some("/"), None] {
            assert_eq!(
                resolve_default_plugin_registry(blank),
                DEFAULT_PLUGIN_REGISTRY,
                "blank override {blank:?} must not win"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_and_trailing_slash_are_trimmed() {
        assert_eq!(
            resolve_default_plugin_registry(Some("  registry.airgap.internal/mcpg/plugins/  ")),
            "registry.airgap.internal/mcpg/plugins"
        );
    }

    /// Explicit YAML outranks both the environment and the compiled
    /// default: serde never calls the default function when the key is
    /// present.
    #[test]
    fn explicit_yaml_outranks_the_default() {
        let cfg: PluginRegistryConfig =
            serde_yaml::from_str("default_registry: registry.example.com/team/plugins").unwrap();
        assert_eq!(cfg.default_registry, "registry.example.com/team/plugins");
    }

    #[test]
    fn omitted_yaml_key_takes_the_default() {
        let cfg: PluginRegistryConfig = serde_yaml::from_str("cache_dir: /var/cache/mcpg").unwrap();
        assert_eq!(cfg.default_registry, default_plugin_registry());
    }
}
