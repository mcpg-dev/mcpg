//! Shared per-source filter for the observability bridges
//! (logs / metrics / traces).
//!
//! The three bridges (`log_bridge`, `metrics_bridge`,
//! `telemetry_bridge`) each capture a source plugin id at the
//! emit site, then ask this module whether to admit the event +
//! which sink list to fan it out to, based on the operator's
//! per-plugin observability config.
//!
//! # Design
//!
//! Per-plugin observability has two layered controls:
//!
//! 1. **Gate** (`enabled` + `level`): drop events from a chatty
//!    plugin entirely, or set a per-plugin minimum severity floor
//!    that overrides the global level filter.
//! 2. **Sink redirection** (`mode` + `sinks`): once an event
//!    passes the gate, decide which sinks receive it. `inherit`
//!    (default) flows through the global sink list — every other
//!    plugin's path. `replace` routes ONLY to the per-plugin
//!    `sinks` list — used for compliance carve-outs (audit logs
//!    stay inside the SIEM). `tee` mirrors the event to BOTH the
//!    global list AND the per-plugin sinks.
//!
//! # Source plugin id resolution
//!
//! Resolution priority for tracing events:
//!
//! 1. Structured field `plugin_id = "..."` on the event — the
//!    explicit escape hatch. Gateway code that calls into a
//!    plugin uses this to attribute events to the called plugin.
//! 2. Span ancestor — the event's nearest enclosing span carries
//!    a `plugin_id` attribute. Wrap-style attribution
//!    ("everything inside this `plugin_call` span belongs to
//!    plugin X").
//! 3. Module-path prefix — `target.split("::").next()` is looked
//!    up in the boot-time `target_to_plugin_id` map. This is the
//!    default attribution; events from a plugin's own crate get
//!    routed to that plugin's id.
//! 4. Fallback `core` — the gateway crate itself. The pseudo-id
//!    `core` is not a registered plugin, but operators can target
//!    it with toggles too (`plugins: - id: core,
//!    observability: ...`).
//!
//! For metrics, only step 3 applies — `metrics::Metadata` has no
//! fields and no spans.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use mcpg_plugin_protocol::logs::LogLevel;

/// Shared, mutable target-prefix → plugin-id map. Wrapped in
/// `ArcSwap` so the bridges + recorder can hold a stable handle
/// taken at observability init time, while the gateway boot path
/// populates the actual map AFTER plugin registration completes.
/// Pre-population reads return an empty map — events all
/// attribute to the `core` pseudo-id, which is correct (only
/// gateway code emits before plugin registration).
pub type SharedTargetMap = Arc<ArcSwap<HashMap<String, String>>>;

/// Build an empty shared target map. The gateway calls this once
/// at `observability::init()`; the same `Arc` flows into the
/// metrics recorder + the log / telemetry layers, which all read
/// via `.load()` on every emit. Post-registration the gateway
/// calls `swap_target_map(&shared, populated)` to install the
/// real mapping.
pub fn new_target_map() -> SharedTargetMap {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// Replace the contents of a `SharedTargetMap`. Subsequent
/// `.load()` calls return the new map.
pub fn swap_target_map(shared: &SharedTargetMap, new_map: HashMap<String, String>) {
    shared.store(Arc::new(new_map));
}

/// Per-plugin per-signal filter. Built at boot from
/// `plugins[].observability.{logs,metrics,traces}`;
/// consulted on every emit. Absent from the map = "no override,
/// admit by default".
#[derive(Debug, Clone)]
pub struct SignalFilter {
    /// When `false`, every event for this signal is dropped at
    /// the bridge before it reaches the sink fan-out.
    pub enabled: bool,
    /// Minimum severity an event must clear to be emitted. Logs
    /// and traces only — metrics-rs has no levels and ignores
    /// this field. `None` = inherit the global level filter.
    pub level: Option<LogLevel>,
    /// Sink-redirection mode. `Inherit` (default) flows through the
    /// global sink list. `Replace` routes only to `sinks`. `Tee`
    /// emits to BOTH global + `sinks`.
    pub mode: SinkMode,
    /// Per-plugin sink id list. Used by `Replace` and `Tee`.
    /// Validated at boot — every id MUST match a registered sink
    /// plugin for the corresponding signal.
    pub sinks: Vec<String>,
}

/// Sink-routing mode for a per-plugin signal. Mirrors the operator
/// schema's `mode: inherit | replace | tee`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SinkMode {
    /// Default — events flow through the global sink list.
    #[default]
    Inherit,
    /// Route ONLY to the per-plugin `sinks` list.
    Replace,
    /// Tee — emit to both the global sink list AND `sinks`.
    Tee,
}

impl Default for SignalFilter {
    fn default() -> Self {
        Self {
            enabled: true,
            level: None,
            mode: SinkMode::default(),
            sinks: Vec::new(),
        }
    }
}

/// Routing decision for a single event. `Drop` short-circuits the
/// fan-out; `UseGlobal` falls through to the bridge's existing
/// global-allow-list path; `Override` swaps in a per-plugin sink
/// set (used by `Replace` and `Tee` modes).
#[derive(Debug, Clone)]
pub enum RouteDecision {
    /// Gate denied — drop event. The carried [`DropReason`] tells
    /// the caller WHY (for the per-plugin drop counter).
    Drop(DropReason),
    /// No override — use the bridge's existing global sink set.
    UseGlobal,
    /// Use this set instead of (or in addition to) the global set.
    /// `Tee` mode populates it with `global ∪ filter.sinks`;
    /// `Replace` populates it with just `filter.sinks`.
    Override(std::collections::HashSet<String>),
}

/// Why a [`RouteDecision::Drop`] fired. Surfaced as the `reason`
/// label on the bridges' `mcpg_observability_dropped_total` counter
/// so operators can tell whether events disappeared because their
/// filter said so (`disabled` / `below_level`) or because of a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Per-plugin filter has `enabled = false`.
    Disabled,
    /// Event level is below the per-plugin `level` floor.
    BelowLevel,
}

impl DropReason {
    /// Stable string label for the metric / log field. Operators
    /// match these values in alerts; do not change without bumping
    /// the observability docs.
    pub fn as_label(self) -> &'static str {
        match self {
            DropReason::Disabled => "disabled",
            DropReason::BelowLevel => "below_level",
        }
    }
}

/// Pseudo-id reserved for events that don't resolve to a registered
/// plugin (gateway core code, anything outside the
/// `target_to_plugin_id` map). Operators can target it via
/// `plugins: - id: core, observability: ...`.
pub const CORE_PSEUDO_ID: &str = "core";

/// Translate a tracing target / metrics module-path string into a
/// source plugin id. Splits on `::`, looks up the head segment in
/// the `target_to_plugin_id` map, and falls back to `core` on miss.
///
/// Caller-supplied `target` is typically `metadata.module_path()`
/// for metrics or `event.metadata().target()` for tracing events.
pub fn source_from_target(target: &str, target_to_plugin_id: &HashMap<String, String>) -> String {
    // The first `::` segment is the crate-root module name;
    // metrics-rs and tracing both default `target` to
    // `module_path!()` at the call site, which always begins with
    // the crate name.
    let head = target.split("::").next().unwrap_or(target);
    target_to_plugin_id
        .get(head)
        .cloned()
        .unwrap_or_else(|| CORE_PSEUDO_ID.to_owned())
}

/// Should an event from `source_plugin_id` at `event_level` be
/// admitted to the global sink fan-out? `None` (no per-plugin
/// override) → always admit. `Some(filter)` with `enabled = false`
/// → drop. `Some(filter)` with a `level` floor → drop events
/// below that floor.
///
/// `event_level: None` is for metrics (which have no severity);
/// the level floor is ignored in that case.
///
/// This is the gate-only check; it does NOT consider sink
/// redirection (`mode` / `sinks`). Most callers should use
/// [`route_event`] which combines gate + sink resolution into a
/// single [`RouteDecision`].
pub fn should_emit(
    source_plugin_id: &str,
    filters: &HashMap<String, SignalFilter>,
    event_level: Option<LogLevel>,
) -> bool {
    let Some(filter) = filters.get(source_plugin_id) else {
        return true;
    };
    if !filter.enabled {
        return false;
    }
    match (event_level, filter.level) {
        (Some(ev), Some(min)) => log_level_at_least(ev, min),
        // Metrics or no level floor — admit if enabled.
        _ => true,
    }
}

/// Combined gate + sink-redirection decision for one event.
///
/// Returns:
/// - `RouteDecision::Drop` — gate denied (disabled or below level
///   floor). Caller should skip the event entirely.
/// - `RouteDecision::UseGlobal` — no per-plugin filter OR
///   `mode: inherit`. Caller falls through to the bridge's
///   existing global-allow-list fan-out.
/// - `RouteDecision::Override(set)` — `mode: replace` or `tee`
///   produced an explicit sink set. For `replace`, `set =
///   filter.sinks`. For `tee`, `set = global_sinks ∪ filter.sinks`
///   (deduped). Caller fans out to exactly the ids in `set`.
///
/// `global_sinks` is the bridge's current global allow-list,
/// borrowed for the `Tee` union. `event_level: None` is for
/// metrics (no severity); the level floor is ignored.
pub fn route_event(
    source_plugin_id: &str,
    filters: &HashMap<String, SignalFilter>,
    event_level: Option<LogLevel>,
    global_sinks: &std::collections::HashSet<String>,
) -> RouteDecision {
    let Some(filter) = filters.get(source_plugin_id) else {
        return RouteDecision::UseGlobal;
    };
    if !filter.enabled {
        return RouteDecision::Drop(DropReason::Disabled);
    }
    if let (Some(ev), Some(min)) = (event_level, filter.level)
        && !log_level_at_least(ev, min)
    {
        return RouteDecision::Drop(DropReason::BelowLevel);
    }
    match filter.mode {
        SinkMode::Inherit => RouteDecision::UseGlobal,
        SinkMode::Replace => RouteDecision::Override(filter.sinks.iter().cloned().collect()),
        SinkMode::Tee => {
            let mut combined = global_sinks.clone();
            for s in &filter.sinks {
                combined.insert(s.clone());
            }
            RouteDecision::Override(combined)
        }
    }
}

/// Total order on `LogLevel` for the `event_level >= filter.level`
/// pass test. Trace < Debug < Info < Warn < Error.
fn log_level_rank(l: LogLevel) -> u8 {
    match l {
        LogLevel::Trace => 0,
        LogLevel::Debug => 1,
        LogLevel::Info => 2,
        LogLevel::Warn => 3,
        LogLevel::Error => 4,
    }
}

/// True when `event_level` is at or above `min` in the standard
/// tracing severity order. Equivalent to "the event clears the
/// per-plugin minimum level".
pub fn log_level_at_least(event_level: LogLevel, min: LogLevel) -> bool {
    log_level_rank(event_level) >= log_level_rank(min)
}

/// Parse a string `level` (case-insensitive) from the operator
/// config into a `LogLevel`. Returns `None` for unrecognized
/// values; callers surface that as a boot-time validation error.
pub fn parse_level(s: &str) -> Option<LogLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "trace" => Some(LogLevel::Trace),
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warn" | "warning" => Some(LogLevel::Warn),
        "error" => Some(LogLevel::Error),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "mcpg_plugin_observability_audit".into(),
            "dev.mcpg.observability.audit".into(),
        );
        m.insert(
            "mcpg_plugin_policy_cedar".into(),
            "dev.mcpg.policy.cedar".into(),
        );
        m
    }

    #[test]
    fn source_from_target_resolves_first_segment() {
        let map = make_target_map();
        assert_eq!(
            source_from_target("mcpg_plugin_observability_audit::write", &map),
            "dev.mcpg.observability.audit"
        );
        assert_eq!(
            source_from_target("mcpg_plugin_policy_cedar", &map),
            "dev.mcpg.policy.cedar"
        );
    }

    #[test]
    fn source_from_target_falls_back_to_core_on_unknown() {
        let map = make_target_map();
        assert_eq!(source_from_target("mcpg::runtime::execution", &map), "core");
        assert_eq!(source_from_target("", &map), "core");
        assert_eq!(source_from_target("nonexistent_crate::foo", &map), "core");
    }

    #[test]
    fn should_emit_admits_when_no_filter_present() {
        let filters: HashMap<String, SignalFilter> = HashMap::new();
        assert!(should_emit(
            "dev.unmapped.plugin",
            &filters,
            Some(LogLevel::Info)
        ));
        assert!(should_emit("dev.unmapped.plugin", &filters, None));
    }

    #[test]
    fn should_emit_drops_when_filter_disabled() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.noisy.plugin".to_owned(),
            SignalFilter {
                enabled: false,
                level: None,
                mode: SinkMode::Inherit,
                sinks: Vec::new(),
            },
        );
        assert!(!should_emit(
            "dev.noisy.plugin",
            &filters,
            Some(LogLevel::Info)
        ));
        assert!(!should_emit("dev.noisy.plugin", &filters, None));
        // Other plugins unaffected.
        assert!(should_emit(
            "dev.other.plugin",
            &filters,
            Some(LogLevel::Info)
        ));
    }

    #[test]
    fn should_emit_respects_level_floor() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: Some(LogLevel::Warn),
                mode: SinkMode::Inherit,
                sinks: Vec::new(),
            },
        );
        // Below floor — drop.
        assert!(!should_emit("dev.x", &filters, Some(LogLevel::Info)));
        assert!(!should_emit("dev.x", &filters, Some(LogLevel::Debug)));
        // At or above — admit.
        assert!(should_emit("dev.x", &filters, Some(LogLevel::Warn)));
        assert!(should_emit("dev.x", &filters, Some(LogLevel::Error)));
    }

    #[test]
    fn should_emit_ignores_level_for_metrics() {
        // event_level: None → metrics signal (no severity).
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: Some(LogLevel::Error),
                mode: SinkMode::Inherit,
                sinks: Vec::new(),
            },
        );
        // Even though level floor is Error, metrics admit when enabled.
        assert!(should_emit("dev.x", &filters, None));
    }

    #[test]
    fn parse_level_accepts_canonical_spellings() {
        assert_eq!(parse_level("trace"), Some(LogLevel::Trace));
        assert_eq!(parse_level("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(parse_level("Info"), Some(LogLevel::Info));
        assert_eq!(parse_level("warn"), Some(LogLevel::Warn));
        assert_eq!(parse_level("warning"), Some(LogLevel::Warn));
        assert_eq!(parse_level("error"), Some(LogLevel::Error));
        assert_eq!(parse_level("  ERROR  "), Some(LogLevel::Error));
    }

    #[test]
    fn parse_level_rejects_unknown() {
        assert_eq!(parse_level(""), None);
        assert_eq!(parse_level("verbose"), None);
        assert_eq!(parse_level("off"), None);
    }

    fn global_set(ids: &[&str]) -> std::collections::HashSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn route_event_inherit_admits_to_global() {
        let filters = HashMap::new();
        let global = global_set(&["sink.a", "sink.b"]);
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::UseGlobal => {}
            other => panic!("expected UseGlobal, got {other:?}"),
        }
    }

    #[test]
    fn route_event_inherit_mode_explicit() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: None,
                mode: SinkMode::Inherit,
                sinks: vec![],
            },
        );
        let global = global_set(&["sink.a"]);
        assert!(matches!(
            route_event("dev.x", &filters, Some(LogLevel::Info), &global),
            RouteDecision::UseGlobal
        ));
    }

    #[test]
    fn route_event_disabled_drops() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: false,
                level: None,
                mode: SinkMode::Replace,
                sinks: vec!["sink.audit".into()],
            },
        );
        let global = global_set(&["sink.a"]);
        // Even though mode = Replace with sinks present, disabled
        // wins — drop with reason = Disabled.
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Drop(DropReason::Disabled) => {}
            other => panic!("expected Drop(Disabled), got {other:?}"),
        }
    }

    #[test]
    fn route_event_replace_routes_only_to_per_plugin_sinks() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.policy.cedar".to_owned(),
            SignalFilter {
                enabled: true,
                level: None,
                mode: SinkMode::Replace,
                sinks: vec!["sink.siem".into()],
            },
        );
        let global = global_set(&["sink.stderr", "sink.json"]);
        match route_event("dev.policy.cedar", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Override(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains("sink.siem"));
                // Global sinks NOT in the override.
                assert!(!set.contains("sink.stderr"));
            }
            other => panic!("expected Override, got {other:?}"),
        }
    }

    #[test]
    fn route_event_tee_unions_with_global() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: None,
                mode: SinkMode::Tee,
                sinks: vec!["sink.debug".into()],
            },
        );
        let global = global_set(&["sink.stderr"]);
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Override(set) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains("sink.stderr"));
                assert!(set.contains("sink.debug"));
            }
            other => panic!("expected Override, got {other:?}"),
        }
    }

    #[test]
    fn route_event_tee_dedupes_overlap() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: None,
                mode: SinkMode::Tee,
                // Overlap with global.
                sinks: vec!["sink.stderr".into(), "sink.debug".into()],
            },
        );
        let global = global_set(&["sink.stderr"]);
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Override(set) => {
                // 2 unique ids — dedup'd via HashSet.
                assert_eq!(set.len(), 2);
            }
            other => panic!("expected Override, got {other:?}"),
        }
    }

    #[test]
    fn route_event_replace_below_level_drops() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: Some(LogLevel::Warn),
                mode: SinkMode::Replace,
                sinks: vec!["sink.audit".into()],
            },
        );
        let global = global_set(&["sink.a"]);
        // Below level floor — drop with reason = BelowLevel even
        // though mode = Replace.
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Drop(DropReason::BelowLevel) => {}
            other => panic!("expected Drop(BelowLevel), got {other:?}"),
        }
        // At level floor — admit, override.
        assert!(matches!(
            route_event("dev.x", &filters, Some(LogLevel::Warn), &global),
            RouteDecision::Override(_)
        ));
    }

    // -- DropReason carried through the variant. ----

    #[test]
    fn drop_reason_labels_are_stable() {
        // Operators alert on these — do not change without bumping
        // the observability docs.
        assert_eq!(DropReason::Disabled.as_label(), "disabled");
        assert_eq!(DropReason::BelowLevel.as_label(), "below_level");
    }

    #[test]
    fn route_event_drop_disabled_carries_reason() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: false,
                level: None,
                mode: SinkMode::Inherit,
                sinks: Vec::new(),
            },
        );
        let global = global_set(&["sink.a"]);
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Drop(reason) => assert_eq!(reason, DropReason::Disabled),
            other => panic!("expected Drop, got {other:?}"),
        }
        // Metrics signal (event_level: None) — same reason.
        match route_event("dev.x", &filters, None, &global) {
            RouteDecision::Drop(reason) => assert_eq!(reason, DropReason::Disabled),
            other => panic!("expected Drop, got {other:?}"),
        }
    }

    #[test]
    fn route_event_drop_below_level_carries_reason() {
        let mut filters = HashMap::new();
        filters.insert(
            "dev.x".to_owned(),
            SignalFilter {
                enabled: true,
                level: Some(LogLevel::Warn),
                mode: SinkMode::Inherit,
                sinks: Vec::new(),
            },
        );
        let global = global_set(&["sink.a"]);
        match route_event("dev.x", &filters, Some(LogLevel::Info), &global) {
            RouteDecision::Drop(reason) => assert_eq!(reason, DropReason::BelowLevel),
            other => panic!("expected Drop, got {other:?}"),
        }
    }
}
