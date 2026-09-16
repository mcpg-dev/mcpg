//! `mcpg config check` — pre-flight YAML validator.
//!
//! Lives in the gateway crate, beside the `AppConfig` it validates, so the
//! answer comes from the same schema the gateway boots with and the check is
//! available wherever the gateway binary is. `mcpg-config check` calls it too:
//! one implementation, two entry points, no image that ships a `config check`
//! which cannot run.
//!
//! Loads one or more config files, runs `AppConfig::validate()` on the
//! merged tree, and prints errors. Multi-file invocations merge in
//! slice order with **later wins** semantics — same overlay logic the
//! gateway uses at boot. Exits 0 on success, 1 on validation failure,
//! 2 on usage / I/O errors. Designed to run in CI / pre-commit so
//! operators catch config typos before gateway boot.
//!
//! ```text
//! $ mcpg config check config.yaml
//! ✓ config.yaml: valid (12 bindings, 3 plugins, audit + observability on)
//!
//! $ mcpg config check base.yaml production.yaml
//! ✓ base.yaml + production.yaml: valid (8 bindings, audit on)
//!
//! $ mcpg config check broken.yaml
//! ✗ broken.yaml: invalid
//!   audit.sinks must not be empty when audit.enabled = true and audit.required = true
//! ```
//!
//! Validates the YAML files as written — does NOT apply `MCPG_*`
//! env-var overrides. The runtime `AppConfig::load_many` consumes
//! both, but the pre-flight check is for the operator's source of
//! truth on disk.

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
mcpg config check — pre-flight YAML validator for MCPG configuration

USAGE:
    mcpg config check [--deny-warnings] <config.yaml> [<override.yaml> ...]

OPTIONS:
    --deny-warnings   Exit 1 on a warning as well as an error. For a gate:
                      an unreachable trust floor is valid config that serves
                      nothing, so a run that only checks the exit code would
                      pass it.

NOTES:
    Multiple files merge in argument order with later-wins semantics
    (same as `MCPG_CONFIG=a.yaml:b.yaml` at runtime). Object fields
    deep-merge; arrays and scalars replace wholesale.

EXIT CODES:
    0 — config is valid
    1 — config failed validation (or warned, under --deny-warnings)
    2 — usage or I/O error
";

/// `ExitCode` wrapper for a `main` that returns one (`mcpg-config check`).
pub fn run(args: Vec<String>) -> ExitCode {
    ExitCode::from(run_code(args))
}

/// The checker itself, returning the process exit code so a caller that has to
/// `std::process::exit` (the gateway's `mcpg config check`) keeps the usage /
/// invalid distinction rather than collapsing both to 1.
pub fn run_code(args: Vec<String>) -> u8 {
    // The old standalone binary parsed `--help` as a filename — handled
    // first now, like every other subcommand.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return 0;
    }
    let deny_warnings = args.iter().any(|a| a == "--deny-warnings");
    let paths: Vec<PathBuf> = args
        .iter()
        .filter(|a| *a != "--deny-warnings")
        .map(PathBuf::from)
        .collect();
    if paths.is_empty() {
        eprintln!("{USAGE}");
        return 2;
    }

    let mut yamls: Vec<String> = Vec::with_capacity(paths.len());
    for path in &paths {
        if !path.exists() {
            eprintln!("error: config file not found: {}", path.display());
            return 2;
        }
        match std::fs::read_to_string(path) {
            Ok(s) => yamls.push(s),
            Err(e) => {
                eprintln!("error: failed to read {}: {}", path.display(), e);
                return 2;
            }
        }
    }

    let yaml_refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
    let label = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" + ");

    match crate::config::AppConfig::load_from_yaml_strs(&yaml_refs) {
        Ok(cfg) => {
            let summary = config_summary(&cfg);
            println!("\u{2713} {label}: valid ({summary})");
            // Valid, but these bindings are invisible at runtime — worth
            // saying out loud here rather than leaving the operator to
            // discover an empty tools/list.
            let unreachable = crate::config::unreachable_trust_bindings(&cfg);
            if !unreachable.is_empty() {
                let ceiling = crate::config::reachable_trust_ceiling(&cfg);
                eprintln!(
                    "  warning: unreachable trust floor on {} ({}): no request can \
                     exceed {ceiling:?} under this config, so they are hidden from \
                     every list and rejected on call",
                    if unreachable.len() == 1 {
                        "binding"
                    } else {
                        "bindings"
                    },
                    unreachable.join(", "),
                );
                eprintln!("  fix: {}", crate::config::trust_ceiling_remedy(ceiling));
                if deny_warnings {
                    return 1;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("\u{2717} {label}: invalid");
            eprintln!("  {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            1
        }
    }
}

fn config_summary(cfg: &crate::config::AppConfig) -> String {
    let mut parts = Vec::with_capacity(6);
    parts.push(format!("{} bindings", cfg.binding_count()));
    if !cfg.plugins.is_empty() {
        parts.push(format!("{} plugins", cfg.plugins.len()));
    }
    if cfg.governance.audit.enabled {
        parts.push("audit on".to_owned());
    }
    if cfg.observability.enabled {
        parts.push("observability on".to_owned());
    }
    if !cfg.cluster.is_single_node() {
        parts.push(format!("cluster: {}", cfg.cluster.kind));
    }
    parts.join(", ")
}
