//! Anonymous adoption reporting.
//!
//! A single, minimal, vendor-facing "this build is running" ping so the
//! project can see how the community grows: product version, host platform,
//! and the set of *first-party* plugins loaded (by id + version). Nothing
//! request-, tenant-, or content-derived is ever collected — the payload is a
//! fixed, schema-pinned shape (`mcpg.usage.v1`), never a free-form attribute
//! bag. This is deliberately distinct from the operator's own observability
//! (`observability:` → OTel/metrics/log sinks): those describe *their* system;
//! this describes *the software's* reach, to us.
//!
//! ## Principles (all enforced here)
//!
//! - **Under the operator's control.** Off entirely with `DO_NOT_TRACK=1`,
//!   `MCPG_TELEMETRY=off`, or `usage_reporting.enabled: false`. No account, no
//!   opt-in flow — one env var or one config line and it's done.
//! - **Fail-open.** The gateway never waits on, retries, or reacts to the
//!   endpoint. If it's slow, unreachable, or gone, the send is dropped and the
//!   gateway is unaffected. Works fully offline.
//! - **Fail-closed on the decision.** Any ambiguity in whether reporting is
//!   permitted (license won't resolve, state dir unwritable, …) resolves to
//!   *not sending*. The gate errs toward silence, the transport toward the app.
//! - **Self-suppressing where a ping would be wrong.** Air-gapped, sovereign,
//!   or licensed (non-community) installs, CP-attached fleets, and CI never
//!   report — those are either private by contract or already known to us.
//! - **First-party only, by namespace.** Only plugins under the canonical
//!   `dev.mcpg.*` namespace are named (see [`classify`]). A third-party /
//!   operator plugin — anything outside that namespace — is reduced to a coarse
//!   *count bucket*; its id never leaves the process, so an operator can't be
//!   fingerprinted by a bespoke plugin id.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{debug, info};

use crate::config::AppConfig;
use mcpg_plugin_host::LoadedPluginInfo;

/// Wire-format identifier. Pinned; a shape change mints `mcpg.usage.v2`.
const SCHEMA: &str = "mcpg.usage.v1";

/// The one product this binary reports as.
const PRODUCT: &str = "mcpg-gateway";

/// Static request User-Agent — deliberately versionless (the version is a
/// payload field) so the header is identical across every release and install.
const USER_AGENT: &str = "mcpg-usage/1";

/// Per-send network budget. A ping either lands within this or is dropped —
/// there is no retry and the gateway never blocks on it.
const SEND_TIMEOUT: Duration = Duration::from_secs(3);

/// Liveness heartbeat cadence. Coarse on purpose — this measures "still
/// running today", not usage volume.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The canonical namespace every first-party plugin ships under (reverse-DNS).
const FIRST_PARTY_NS: &str = "dev.mcpg.";

/// Sub-namespaces that carry no adoption signal and are dropped entirely:
/// compiled-in builtins (part of the binary, always present) and test fixtures.
const INTERNAL_NS: &[&str] = &["dev.mcpg.builtin.", "dev.mcpg.testing."];

/// How a loaded plugin id maps onto the report.
enum Class {
    /// Named in the payload (id + validated version).
    FirstParty,
    /// Compiled-in builtin or a test fixture — part of the binary / not a real
    /// deployment choice, so it carries no adoption signal and is dropped
    /// entirely (neither named nor counted).
    Internal,
    /// Anyone else's plugin — counted into a coarse bucket, never named.
    ThirdParty,
}

/// Classify by namespace, not by an exact allowlist: any `dev.mcpg.*` plugin is
/// first-party, minus the builtin/testing sub-namespaces. This is self-
/// maintaining — a new first-party plugin is reported the day it lands, with no
/// list to keep in sync. The residual risk is that a third party squatting the
/// `dev.mcpg.*` namespace would have its id named rather than bucketed; that's
/// accepted — the id is a plugin name (not operator PII), and namespace
/// squatting is itself signal we'd want to see.
fn classify(id: &str) -> Class {
    if INTERNAL_NS.iter().any(|ns| id.starts_with(ns)) {
        Class::Internal
    } else if id.starts_with(FIRST_PARTY_NS) {
        Class::FirstParty
    } else {
        Class::ThirdParty
    }
}

/// The reason reporting is (not) active, for the one boot log line.
enum Decision {
    Enabled,
    Disabled(&'static str),
}

/// Entry point, called once from `app::run`. Logs the decision unconditionally,
/// then — only when enabled and not in debug/dry-run — spawns the detached
/// reporter. Never blocks boot and never returns an error: telemetry failing is
/// a no-op by design.
pub fn spawn(
    config: Arc<AppConfig>,
    service_version: &'static str,
    plugins: Vec<LoadedPluginInfo>,
) {
    let debug_dry_run = env_flag_present("MCPG_TELEMETRY_DEBUG");

    // Dry-run: show operators exactly what a report would contain, and send
    // nothing. Works regardless of the gate so it's always inspectable.
    if debug_dry_run {
        let event = build_event(service_version, &plugins, "startup", "(debug)".to_string());
        match serde_json::to_string_pretty(&event) {
            Ok(json) => {
                eprintln!(
                    "[usage_reporting] MCPG_TELEMETRY_DEBUG set — dry run, NOT sent:\n{json}"
                );
            }
            Err(e) => eprintln!("[usage_reporting] debug serialise failed: {e}"),
        }
    }

    match decide(&config) {
        Decision::Disabled(reason) => {
            info!(
                target: "mcpg::usage_reporting",
                enabled = false,
                reason,
                "anonymous usage reporting is OFF"
            );
        }
        Decision::Enabled => {
            info!(
                target: "mcpg::usage_reporting",
                enabled = true,
                endpoint = %config.usage_reporting.endpoint,
                "anonymous usage reporting is ON (product version + first-party plugin set only; \
                 disable with DO_NOT_TRACK=1 or usage_reporting.enabled: false)"
            );
            if debug_dry_run {
                // Enabled, but debug forces print-not-send.
                return;
            }
            let endpoint = config.usage_reporting.endpoint.clone();
            tokio::spawn(run(endpoint, service_version, plugins, config));
        }
    }
}

/// Resolve whether reporting may proceed. Fail-closed: every uncertain branch
/// returns `Disabled`.
fn decide(config: &AppConfig) -> Decision {
    // 1. Operator kill switches (env), highest precedence, independent of the
    //    config block so they work even against a baked-in config.
    if env_flag_present("DO_NOT_TRACK") {
        return Decision::Disabled("DO_NOT_TRACK is set");
    }
    if let Some(v) = std::env::var_os("MCPG_TELEMETRY") {
        let v = v.to_string_lossy().trim().to_ascii_lowercase();
        if matches!(v.as_str(), "0" | "false" | "no" | "off" | "disabled") {
            return Decision::Disabled("MCPG_TELEMETRY disables reporting");
        }
    }

    // 2. The config block.
    if !config.usage_reporting.enabled {
        return Decision::Disabled("usage_reporting.enabled is false");
    }

    // 3. Contexts where a ping is either private-by-contract or redundant.
    if config.gateway.control_plane.is_some() {
        // A CP-attached gateway's fleet is already inventoried by the control
        // plane; a second, weaker signal adds nothing and could surprise.
        return Decision::Disabled("control-plane-attached (fleet already inventoried)");
    }
    if config.license.non_production_use {
        return Decision::Disabled("license.non_production_use");
    }
    if is_ci() {
        return Decision::Disabled("CI environment");
    }

    // 4. The license envelope. A failure to resolve is treated as "do not
    //    report" — never as "community, go ahead".
    match crate::license_gate::resolve_claims(&config.license) {
        Ok(claims) if claims.airgap => Decision::Disabled("license marks this install air-gapped"),
        Ok(claims) if claims.sovereign => {
            Decision::Disabled("license marks this install sovereign")
        }
        Ok(claims) if claims.plan != "community" => {
            Decision::Disabled("licensed (non-community) install")
        }
        Ok(_) => Decision::Enabled,
        Err(_) => Decision::Disabled("license envelope unresolved (fail-closed)"),
    }
}

/// Detached reporter task: first-run notice → install id → startup ping →
/// daily heartbeat. Every step is best-effort; a failure ends the task quietly.
async fn run(
    endpoint: String,
    service_version: &'static str,
    plugins: Vec<LoadedPluginInfo>,
    config: Arc<AppConfig>,
) {
    let state_dir = mcpg_cli_core::paths::default_state_dir();

    // Notice BEFORE the id is minted: under ePrivacy the durable identifier is
    // the trigger for disclosure, so it must not exist until the operator has
    // been told (once) what is collected and how to turn it off.
    show_first_run_notice_once(&state_dir);

    let install_id = load_or_create_install_id(&state_dir);

    let client = match build_client() {
        Some(c) => c,
        None => return,
    };

    let startup = build_event(service_version, &plugins, "startup", install_id.clone());
    send(&client, &endpoint, &startup).await;

    let started = Instant::now();
    loop {
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        // Re-check every cycle: a reload could have flipped the gate, or a
        // license could have been installed. Fail-closed here too.
        if !matches!(decide(&config), Decision::Enabled) {
            debug!(target: "mcpg::usage_reporting", "gate closed since boot; stopping heartbeat");
            return;
        }
        let mut hb = build_event(service_version, &plugins, "heartbeat", install_id.clone());
        hb.uptime_days_bucket = Some(uptime_bucket(started.elapsed()));
        send(&client, &endpoint, &hb).await;
    }
}

/// The wire payload. A fixed set of typed fields — deliberately NOT an
/// open attribute map — so nothing request/tenant/content-derived can ever be
/// added by accident, and the receiver's schema is a hard contract.
#[derive(Debug, Serialize)]
struct UsageEvent {
    /// `mcpg.usage.v1`.
    schema: &'static str,
    /// Random per-install UUID (or a coarse sentinel — see [`InstallId`]).
    install_id: String,
    /// `startup` | `heartbeat`.
    event: &'static str,
    /// `mcpg-gateway`.
    product: &'static str,
    /// The gateway's own semver.
    version: String,
    /// Coarse OS / arch / libc — never a hostname or IP.
    os: &'static str,
    arch: &'static str,
    libc: &'static str,
    /// Whether the process looks containerised (best-effort).
    container: bool,
    /// First-party plugins loaded, deduped by id, versions semver-validated.
    first_party_plugins: Vec<PluginEntry>,
    /// Coarse bucket for the count of distinct non-first-party plugins. Their
    /// ids are never included.
    third_party_plugins_bucket: &'static str,
    /// Present on heartbeats only: coarse days-of-uptime bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_days_bucket: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct PluginEntry {
    id: String,
    version: String,
}

/// Build a report from the loaded-plugin snapshot. Pure; does no I/O.
fn build_event(
    service_version: &str,
    plugins: &[LoadedPluginInfo],
    event: &'static str,
    install_id: String,
) -> UsageEvent {
    let mut first_party: Vec<PluginEntry> = Vec::new();
    let mut seen_ids: Vec<&str> = Vec::new();

    for p in plugins {
        match classify(&p.id) {
            Class::Internal | Class::ThirdParty => {}
            Class::FirstParty => {
                if seen_ids.contains(&p.id.as_str()) {
                    continue; // one entity per id (multi-entity cdylibs)
                }
                seen_ids.push(p.id.as_str());
                first_party.push(PluginEntry {
                    id: p.id.clone(),
                    version: normalize_version(&p.version),
                });
            }
        }
    }
    // Third-party plugins are only ever a distinct-by-id count bucket.
    let third_party_distinct = distinct_third_party(plugins);

    // Deterministic order so identical stacks produce identical payloads.
    first_party.sort_by_key(|e| e.id.clone());

    UsageEvent {
        schema: SCHEMA,
        install_id,
        event,
        product: PRODUCT,
        version: normalize_version(service_version),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        libc: libc_tag(),
        container: looks_containerised(),
        first_party_plugins: first_party,
        third_party_plugins_bucket: count_bucket(third_party_distinct),
        uptime_days_bucket: None,
    }
}

fn distinct_third_party(plugins: &[LoadedPluginInfo]) -> usize {
    let mut ids: Vec<&str> = Vec::new();
    for p in plugins {
        if matches!(classify(&p.id), Class::ThirdParty) && !ids.contains(&p.id.as_str()) {
            ids.push(p.id.as_str());
        }
    }
    ids.len()
}

/// Clamp a version string to a semver-ish shape, or `"unknown"`. Prevents an
/// operator-set version override from smuggling an arbitrary string into the
/// payload (first-party manifest versions are already semver; this is belt-and-
/// suspenders).
fn normalize_version(v: &str) -> String {
    if is_semverish(v) {
        v.to_string()
    } else {
        "unknown".to_string()
    }
}

/// A permissive `MAJOR.MINOR.PATCH[-pre][+build]` check — three numeric core
/// components, optional `-`/`+` suffixes with a bounded charset. No dependency.
fn is_semverish(v: &str) -> bool {
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    // Split off build metadata, then pre-release.
    let core_and_pre = v.split('+').next().unwrap_or("");
    let mut parts = core_and_pre.splitn(2, '-');
    let core = parts.next().unwrap_or("");
    if let Some(pre) = parts.next()
        && (pre.is_empty()
            || !pre
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return false;
    }
    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() != 3 {
        return false;
    }
    nums.iter()
        .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Coarse count buckets — enough to see "does anyone run third-party plugins",
/// not enough to fingerprint a specific stack.
fn count_bucket(n: usize) -> &'static str {
    match n {
        0 => "0",
        1..=3 => "1-3",
        4..=10 => "4-10",
        _ => "11+",
    }
}

fn uptime_bucket(elapsed: Duration) -> &'static str {
    let days = elapsed.as_secs() / (24 * 60 * 60);
    match days {
        0 => "0",
        1..=6 => "1-6",
        7..=29 => "7-29",
        _ => "30+",
    }
}

/// Static libc tag from compile-time target facts (musl-clean, unlike a runtime
/// probe). Not an OS string — just the C runtime family.
fn libc_tag() -> &'static str {
    if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "gnu"
    } else if cfg!(target_os = "macos") {
        "system"
    } else if cfg!(target_os = "windows") {
        "msvcrt"
    } else {
        "other"
    }
}

fn looks_containerised() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

/// True when the process is running under a recognised CI system.
fn is_ci() -> bool {
    const CI_VARS: &[&str] = &[
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_URL",
        "TEAMCITY_VERSION",
        "TF_BUILD",
    ];
    CI_VARS.iter().any(|k| env_flag_present(k))
}

/// Presence-and-truthy: an env var counts as "set" only when non-empty and not
/// an explicit falsey token. (`CI=` or `CI=false` do not enable the CI gate.)
fn env_flag_present(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "no" | "off")
        }
        Err(_) => false,
    }
}

// ----- install id + first-run notice -----------------------------------------

const INSTALL_ID_FILE: &str = "telemetry-install-id";
const NOTICE_MARKER_FILE: &str = "telemetry-notice-shown";

/// Print the one-time notice, then drop a marker so it never prints again. If
/// the state dir isn't writable the notice still prints (each boot, harmlessly)
/// — disclosure is the thing we must not skip.
fn show_first_run_notice_once(state_dir: &Path) {
    let marker = state_dir.join(NOTICE_MARKER_FILE);
    if marker.exists() {
        return;
    }
    eprintln!(
        "\n\
        ┌─ anonymous usage reporting ────────────────────────────────────────\n\
        │ mcpg sends an anonymous ping (product version, OS/arch, and the set\n\
        │ of first-party plugins loaded) so we can see how the community grows.\n\
        │ No request, tenant, or configuration content is ever collected, and\n\
        │ it never affects operation — the gateway works fully offline.\n\
        │ Turn it off any time:  DO_NOT_TRACK=1   or   usage_reporting.enabled: false\n\
        └────────────────────────────────────────────────────────────────────\n"
    );
    // Best-effort marker; a failure just means the notice shows again.
    let _ = mcpg_cli_core::paths::ensure_dir(state_dir);
    let _ = std::fs::write(&marker, b"1\n");
}

/// Load the persisted install id, or mint + persist a fresh UUIDv4. Falls back
/// to an in-memory `ephemeral-*` id when the state dir can't be used — the
/// report still goes out, just without cross-restart continuity.
fn load_or_create_install_id(state_dir: &Path) -> String {
    let path = state_dir.join(INSTALL_ID_FILE);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let fresh = uuid::Uuid::new_v4().to_string();
    if mcpg_cli_core::paths::ensure_dir(state_dir).is_ok()
        && write_private(&path, fresh.as_bytes()).is_ok()
    {
        fresh
    } else {
        // Couldn't persist — use it for this process only, flagged so the
        // receiver knows not to treat it as a stable install.
        format!("ephemeral-{fresh}")
    }
}

/// Write a file `0600` where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ----- transport -------------------------------------------------------------

fn build_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(SEND_TIMEOUT)
        .connect_timeout(SEND_TIMEOUT)
        // Static UA — the product version already travels in the payload, so the
        // header carries no extra bit and must not vary per release.
        .user_agent(USER_AGENT)
        .build()
        .ok()
}

/// Fire-and-forget POST. Any error — DNS, TLS, timeout, non-2xx — is logged at
/// debug and dropped. There is no retry: reporting must never cost the gateway
/// latency or attention.
async fn send(client: &reqwest::Client, endpoint: &str, event: &UsageEvent) {
    match client.post(endpoint).json(event).send().await {
        Ok(resp) => {
            debug!(
                target: "mcpg::usage_reporting",
                status = resp.status().as_u16(),
                event = event.event,
                "usage ping sent"
            );
        }
        Err(e) => {
            debug!(
                target: "mcpg::usage_reporting",
                error = %e,
                "usage ping dropped (fail-open)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_party_ids_are_deduped_and_sorted() {
        let plugins = vec![
            loaded("dev.mcpg.backend.http", "1.0.0"),
            loaded("dev.mcpg.identity.oidc", "1.0.0-rc.3"),
            loaded("dev.mcpg.backend.http", "1.0.0"), // dup entity, same id
        ];
        let ev = build_event("1.2.3", &plugins, "startup", "id".into());
        assert_eq!(ev.first_party_plugins.len(), 2);
        assert_eq!(ev.first_party_plugins[0].id, "dev.mcpg.backend.http");
        assert_eq!(ev.first_party_plugins[1].id, "dev.mcpg.identity.oidc");
    }

    #[test]
    fn third_party_is_bucketed_not_named() {
        let plugins = vec![
            loaded("acme.policy.secret", "9.9.9"),
            loaded("acme.backend.internal", "1.0.0"),
            loaded("dev.mcpg.backend.http", "1.0.0"),
        ];
        let ev = build_event("1.0.0", &plugins, "startup", "id".into());
        // Only the first-party one is named.
        assert_eq!(ev.first_party_plugins.len(), 1);
        // The two third-party ids are reduced to a count bucket.
        assert_eq!(ev.third_party_plugins_bucket, "1-3");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("acme."), "third-party id leaked: {json}");
    }

    #[test]
    fn builtins_and_fixtures_are_dropped_entirely() {
        let plugins = vec![
            loaded("dev.mcpg.builtin.tool-gate", "1.0.0"),
            loaded("dev.mcpg.testing.hello-native", "1.0.0"),
        ];
        let ev = build_event("1.0.0", &plugins, "startup", "id".into());
        assert_eq!(ev.first_party_plugins.len(), 0);
        assert_eq!(ev.third_party_plugins_bucket, "0");
    }

    #[test]
    fn non_semver_versions_become_unknown() {
        let plugins = vec![loaded("dev.mcpg.backend.http", "$(whoami)")];
        let ev = build_event("1.0.0", &plugins, "startup", "id".into());
        assert_eq!(ev.first_party_plugins[0].version, "unknown");
    }

    #[test]
    fn semver_shapes() {
        assert!(is_semverish("1.0.0"));
        assert!(is_semverish("0.1.0-dev.24"));
        assert!(is_semverish("1.2.3-rc.1+build.7"));
        assert!(!is_semverish("1.0"));
        assert!(!is_semverish("latest"));
        assert!(!is_semverish("1.0.0; rm -rf"));
        assert!(!is_semverish(""));
    }

    #[test]
    fn count_and_uptime_buckets() {
        assert_eq!(count_bucket(0), "0");
        assert_eq!(count_bucket(2), "1-3");
        assert_eq!(count_bucket(7), "4-10");
        assert_eq!(count_bucket(50), "11+");
        assert_eq!(uptime_bucket(Duration::from_secs(0)), "0");
        assert_eq!(uptime_bucket(Duration::from_secs(3 * 86400)), "1-6");
        assert_eq!(uptime_bucket(Duration::from_secs(60 * 86400)), "30+");
    }

    #[test]
    fn classify_by_namespace() {
        assert!(matches!(
            classify("dev.mcpg.backend.http"),
            Class::FirstParty
        ));
        assert!(matches!(
            classify("dev.mcpg.identity.oidc"),
            Class::FirstParty
        ));
        assert!(matches!(
            classify("dev.mcpg.builtin.tool-gate"),
            Class::Internal
        ));
        assert!(matches!(
            classify("dev.mcpg.testing.hello-native"),
            Class::Internal
        ));
        assert!(matches!(classify("acme.policy.secret"), Class::ThirdParty));
        assert!(matches!(classify("com.corp.internal"), Class::ThirdParty));
    }

    fn loaded(id: &str, version: &str) -> LoadedPluginInfo {
        LoadedPluginInfo {
            id: id.to_string(),
            version: version.to_string(),
            name: id.to_string(),
            plugin_class: "backend".to_string(),
            tier: "free".to_string(),
            protocol_version: "1.0".to_string(),
            state: "active".to_string(),
        }
    }
}
