use super::*;

/// Translate `plugins[].observability.{logs,
/// metrics, traces}` from the parsed config into the per-signal
/// `plugin_id → SignalFilter` maps the bridges consult on every
/// emit. Plugins without an `observability` block don't appear in
/// any map (they inherit globals via `should_emit`'s `None` arm).
pub(crate) fn build_per_plugin_observability_filters(
    entries: &[crate::config::PluginEntryConfig],
) -> Result<
    (
        Arc<std::collections::HashMap<String, crate::observability::signal_router::SignalFilter>>,
        Arc<std::collections::HashMap<String, crate::observability::signal_router::SignalFilter>>,
        Arc<std::collections::HashMap<String, crate::observability::signal_router::SignalFilter>>,
    ),
    String,
> {
    use crate::observability::signal_router::{SignalFilter, SinkMode, parse_level};
    let mut logs = std::collections::HashMap::new();
    let mut metrics = std::collections::HashMap::new();
    let mut traces = std::collections::HashMap::new();
    let to_mode = |m: crate::config::SinkMode| -> SinkMode {
        match m {
            crate::config::SinkMode::Inherit => SinkMode::Inherit,
            crate::config::SinkMode::Replace => SinkMode::Replace,
            crate::config::SinkMode::Tee => SinkMode::Tee,
        }
    };
    for entry in entries {
        let Some(obs) = entry.observability.as_ref() else {
            continue;
        };
        if let Some(toggle) = obs.logs.as_ref() {
            match toggle.validate(crate::config::SignalKind::Logs) {
                Ok(Some(hint)) => tracing::warn!(
                    plugin_id = %entry.id,
                    signal = "logs",
                    hint = %hint,
                    "per-plugin observability validation hint"
                ),
                Ok(None) => {}
                Err(msg) => {
                    return Err(format!("plugin '{}' observability.logs: {msg}", entry.id));
                }
            }
            logs.insert(
                entry.id.clone(),
                SignalFilter {
                    enabled: toggle.enabled,
                    level: toggle.level.as_deref().and_then(parse_level),
                    mode: to_mode(toggle.mode),
                    sinks: toggle.sinks.clone(),
                },
            );
        }
        if let Some(toggle) = obs.metrics.as_ref() {
            match toggle.validate(crate::config::SignalKind::Metrics) {
                Ok(Some(hint)) => tracing::warn!(
                    plugin_id = %entry.id,
                    signal = "metrics",
                    hint = %hint,
                    "per-plugin observability validation hint"
                ),
                Ok(None) => {}
                Err(msg) => {
                    return Err(format!(
                        "plugin '{}' observability.metrics: {msg}",
                        entry.id
                    ));
                }
            }
            metrics.insert(
                entry.id.clone(),
                SignalFilter {
                    enabled: toggle.enabled,
                    // metrics has no level; validate() refuses if
                    // the operator sets one, so this is unreachable
                    // for well-formed configs.
                    level: None,
                    mode: to_mode(toggle.mode),
                    sinks: toggle.sinks.clone(),
                },
            );
        }
        if let Some(toggle) = obs.traces.as_ref() {
            match toggle.validate(crate::config::SignalKind::Traces) {
                Ok(Some(hint)) => tracing::warn!(
                    plugin_id = %entry.id,
                    signal = "traces",
                    hint = %hint,
                    "per-plugin observability validation hint"
                ),
                Ok(None) => {}
                Err(msg) => {
                    return Err(format!("plugin '{}' observability.traces: {msg}", entry.id));
                }
            }
            traces.insert(
                entry.id.clone(),
                SignalFilter {
                    enabled: toggle.enabled,
                    level: toggle.level.as_deref().and_then(parse_level),
                    mode: to_mode(toggle.mode),
                    sinks: toggle.sinks.clone(),
                },
            );
        }
    }
    Ok((Arc::new(logs), Arc::new(metrics), Arc::new(traces)))
}

/// Cross-check that every per-plugin sink id in `*_filters` refers
/// to a sink plugin actually registered for the matching signal.
/// Returns an error string listing every unknown id; called once
/// at boot after plugin registration completes. The schema-level
/// `SignalToggle::validate()` already covered the degenerate
/// combos (empty sinks under replace/tee, non-empty under
/// inherit) — this is the runtime-state cross-check that closes
/// the operator-typo gap.
pub(crate) fn validate_per_plugin_sink_ids(
    logs_filters: &std::collections::HashMap<
        String,
        crate::observability::signal_router::SignalFilter,
    >,
    metrics_filters: &std::collections::HashMap<
        String,
        crate::observability::signal_router::SignalFilter,
    >,
    traces_filters: &std::collections::HashMap<
        String,
        crate::observability::signal_router::SignalFilter,
    >,
    log_sinks: &std::collections::HashSet<String>,
    metrics_sinks: &std::collections::HashSet<String>,
    span_sinks: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let mut bad: Vec<String> = Vec::new();
    let scan = |signal: &str,
                filters: &std::collections::HashMap<
        String,
        crate::observability::signal_router::SignalFilter,
    >,
                registered: &std::collections::HashSet<String>,
                bad: &mut Vec<String>| {
        for (plugin_id, filter) in filters {
            for sink_id in &filter.sinks {
                if !registered.contains(sink_id) {
                    bad.push(format!(
                        "plugin '{plugin_id}' observability.{signal}.sinks references \
                         '{sink_id}' which is not a registered {signal} sink"
                    ));
                }
            }
        }
    };
    scan("logs", logs_filters, log_sinks, &mut bad);
    scan("metrics", metrics_filters, metrics_sinks, &mut bad);
    scan("traces", traces_filters, span_sinks, &mut bad);
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

#[cfg(test)]
mod sink_validation_tests {
    use super::validate_per_plugin_sink_ids;
    use crate::observability::signal_router::{SignalFilter, SinkMode};
    use std::collections::{HashMap, HashSet};

    fn filter_with_sinks(sinks: &[&str]) -> SignalFilter {
        SignalFilter {
            enabled: true,
            level: None,
            mode: SinkMode::Replace,
            sinks: sinks.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn empty_filters() -> HashMap<String, SignalFilter> {
        HashMap::new()
    }

    #[test]
    fn admits_when_all_sink_ids_registered() {
        let mut logs = HashMap::new();
        logs.insert(
            "dev.x.policy".to_owned(),
            filter_with_sinks(&["dev.acme.siem"]),
        );
        let log_sinks: HashSet<String> = ["dev.acme.siem".to_owned()].into_iter().collect();
        assert!(
            validate_per_plugin_sink_ids(
                &logs,
                &empty_filters(),
                &empty_filters(),
                &log_sinks,
                &HashSet::new(),
                &HashSet::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_log_sink_id() {
        let mut logs = HashMap::new();
        logs.insert("dev.x.policy".to_owned(), filter_with_sinks(&["dev.typo"]));
        let log_sinks: HashSet<String> = ["dev.acme.siem".to_owned()].into_iter().collect();
        let err = validate_per_plugin_sink_ids(
            &logs,
            &empty_filters(),
            &empty_filters(),
            &log_sinks,
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("dev.x.policy"));
        assert!(err.contains("dev.typo"));
        assert!(err.contains("logs"));
    }

    #[test]
    fn rejects_log_sink_id_used_for_metrics_signal() {
        // The same id is registered as a log sink — but the operator
        // listed it under `metrics.sinks`, where it isn't valid.
        let mut metrics = HashMap::new();
        metrics.insert(
            "dev.x.audit".to_owned(),
            filter_with_sinks(&["dev.log.only"]),
        );
        let log_sinks: HashSet<String> = ["dev.log.only".to_owned()].into_iter().collect();
        // No metrics sinks registered.
        let err = validate_per_plugin_sink_ids(
            &empty_filters(),
            &metrics,
            &empty_filters(),
            &log_sinks,
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("metrics"));
        assert!(err.contains("dev.log.only"));
    }

    #[test]
    fn aggregates_multiple_unknowns() {
        let mut logs = HashMap::new();
        logs.insert("p1".to_owned(), filter_with_sinks(&["bad1", "bad2"]));
        let mut metrics = HashMap::new();
        metrics.insert("p2".to_owned(), filter_with_sinks(&["bad3"]));
        let err = validate_per_plugin_sink_ids(
            &logs,
            &metrics,
            &empty_filters(),
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        for needle in ["bad1", "bad2", "bad3"] {
            assert!(err.contains(needle), "expected error to mention {needle}");
        }
    }

    #[test]
    fn empty_filters_no_op() {
        assert!(
            validate_per_plugin_sink_ids(
                &empty_filters(),
                &empty_filters(),
                &empty_filters(),
                &HashSet::new(),
                &HashSet::new(),
                &HashSet::new(),
            )
            .is_ok()
        );
    }
}
