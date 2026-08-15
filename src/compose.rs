//! Gateway composition flags + box status (CLI-REORGANIZATION.md §4.2).
//!
//! The rule: *flags shape the gateway; subcommands run or operate
//! everything else.* Three flags change what this process runs alongside
//! the data plane:
//!
//! - `--enroll <URL>` — run attached to a control plane, enrolling with the
//!   given URL on first contact. The pairing is STICKY: the CP's gRPC
//!   endpoint is persisted in the state dir, so subsequent plain `mcpg`
//!   runs re-attach with the cached agent credentials.
//! - `--no-cp` — one-off detached run despite a stored pairing.
//! - `--control-plane` (alias `--cp`) — supervise a sibling `mcpg-cp serve`
//!   as a child process (dev defaults: sqlite in the state dir, auth off,
//!   loopback binds) and auto-enroll the gateway to it over loopback gRPC.
//!   One command, and the console already shows this gateway enrolled —
//!   without linking the control-plane server into this binary. `--cp-<flag>`
//!   args pass through to the child's own option surface
//!   (`--cp-bind-http` → `--bind-http`).
//!
//! `mcpg status` (in-process subcommand) reports this box: the gateway,
//! the agent pairing, and any local control plane.

use std::path::{Path, PathBuf};

use crate::config::{AppConfig, ControlPlaneAttachConfig};

/// Parsed composition flags. Produced by [`parse`]; consumed by [`apply`]
/// (and, for `embed`, the `embedded-cp` boot in `main.rs`).
#[derive(Debug, Default)]
pub struct CompositionArgs {
    /// `--enroll <URL>` — enrollment URL minted by the CP (console or
    /// `mcpg cp enroll new`).
    pub enroll: Option<String>,
    /// `--cp-grpc <URL>` — explicit agent gRPC endpoint; defaults to the
    /// enrollment URL's host on the CP's standard gRPC port (7844).
    pub cp_grpc: Option<String>,
    /// `--no-cp` — ignore a stored pairing for this run.
    pub no_cp: bool,
    /// `--control-plane` / `--cp` — embed a control plane in-process.
    pub embed: bool,
    /// `--cp-<flag> [value]` passthrough for the embedded server, with the
    /// `cp-` prefix stripped (ready for the server's clap surface).
    pub cp_args: Vec<String>,
    /// `--tunnel [wss-url]` — dial out to a relay and serve the MCP surface
    /// through the tunnel. The optional value sets the relay endpoint
    /// (defaults to the MCPG Cloud relay; self-hosted relays pass their own).
    pub tunnel: bool,
    /// `--private` — federation-only tunnel (no public URL).
    pub tunnel_private: bool,
    /// `--tunnel-name <name>` — a stable tunnel name (relay allocates one
    /// otherwise).
    pub tunnel_name: Option<String>,
    /// `--tunnel-mode <relay_terminated|e2ee>`.
    pub tunnel_mode: Option<String>,
    /// Relay endpoint, from `--tunnel <wss-url>` or `--tunnel-relay <wss-url>`.
    pub tunnel_relay: Option<String>,
    /// `--config <source>` (repeatable) — explicit config layers, applied
    /// after any `MCPG_CONFIG` files (later wins). Each source is a local path,
    /// a `file://` path, an `https://` URL (fetched at boot), or inline
    /// `base64:`/`data:` YAML. Resolved in `main` (the fetch is async).
    pub config: Vec<String>,
    /// `--inspector` — supervise an `mcpg-inspector` sidecar pre-wired
    /// against this gateway.
    pub inspector: bool,
    /// `--inspector-<flag> [value]` passthrough for the sidecar, with the
    /// `inspector-` prefix stripped (ready for its clap surface).
    pub inspector_args: Vec<String>,
}

/// Record the relay endpoint, rejecting contradictory duplicates — the relay
/// can arrive as `--tunnel <url>`, `--tunnel=<url>`, or `--tunnel-relay <url>`.
fn set_relay(out: &mut CompositionArgs, url: String) -> anyhow::Result<()> {
    if let Some(existing) = &out.tunnel_relay
        && *existing != url
    {
        anyhow::bail!(
            "relay endpoint given twice ({existing:?} and {url:?}) — pass one of \
             `--tunnel <url>` or `--tunnel-relay <url>`"
        );
    }
    out.tunnel_relay = Some(url);
    Ok(())
}

/// Scan the gateway's argv for composition flags. Unrelated tokens are
/// left alone (the gateway has other flags, e.g. `--stdio`). Conflicting
/// combinations error here, before anything boots.
pub fn parse(args: &[String]) -> anyhow::Result<CompositionArgs> {
    let mut out = CompositionArgs::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut take_value = |name: &str| -> anyhow::Result<String> {
            if let Some(eq) = args[i].strip_prefix(&format!("{name}=")) {
                return Ok(eq.to_owned());
            }
            let v = args
                .get(i + 1)
                .ok_or_else(|| anyhow::anyhow!("{name} requires a value"))?;
            i += 1;
            Ok(v.clone())
        };
        match a {
            "--enroll" => out.enroll = Some(take_value("--enroll")?),
            "--cp-grpc" => out.cp_grpc = Some(take_value("--cp-grpc")?),
            "--no-cp" => out.no_cp = true,
            "--control-plane" | "--cp" => out.embed = true,
            "--inspector" => out.inspector = true,
            // `--inspector-<x> [v]` → `--<x> [v]` for the sidecar's clap.
            other if other.starts_with("--inspector-") => {
                let stripped = format!("--{}", &other["--inspector-".len()..]);
                if let Some((flag, v)) = stripped.split_once('=') {
                    out.inspector_args.push(flag.to_owned());
                    out.inspector_args.push(v.to_owned());
                } else {
                    out.inspector_args.push(stripped);
                    if let Some(v) = args.get(i + 1)
                        && !v.starts_with('-')
                    {
                        out.inspector_args.push(v.clone());
                        i += 1;
                    }
                }
            }
            "--tunnel" => {
                out.tunnel = true;
                // Optional relay value: `--tunnel wss://relay.example` — only a
                // URL-shaped token is consumed, so `--tunnel --private` and
                // other flag sequences parse unchanged.
                if let Some(v) = args.get(i + 1)
                    && v.contains("://")
                {
                    set_relay(&mut out, v.clone())?;
                    i += 1;
                }
            }
            other if other.starts_with("--tunnel=") => {
                out.tunnel = true;
                set_relay(&mut out, other["--tunnel=".len()..].to_owned())?;
            }
            "--private" => out.tunnel_private = true,
            "--tunnel-name" => out.tunnel_name = Some(take_value("--tunnel-name")?),
            "--tunnel-mode" => out.tunnel_mode = Some(take_value("--tunnel-mode")?),
            "--tunnel-relay" => {
                let v = take_value("--tunnel-relay")?;
                set_relay(&mut out, v)?;
            }
            "--config" => out.config.push(take_value("--config")?),
            other if other.starts_with("--config=") => {
                out.config.push(other["--config=".len()..].to_owned());
            }
            other if other.starts_with("--enroll=") => {
                out.enroll = Some(other["--enroll=".len()..].to_owned());
            }
            other if other.starts_with("--cp-grpc=") => {
                out.cp_grpc = Some(other["--cp-grpc=".len()..].to_owned());
            }
            // `--cp-<x> [v]` → `--<x> [v]` for the embedded server's clap.
            // Checked AFTER --cp-grpc (which is ours, not a passthrough).
            other if other.starts_with("--cp-") => {
                let stripped = format!("--{}", &other["--cp-".len()..]);
                if let Some((flag, v)) = stripped.split_once('=') {
                    out.cp_args.push(flag.to_owned());
                    out.cp_args.push(v.to_owned());
                } else {
                    out.cp_args.push(stripped);
                    // A following non-flag token is this option's value.
                    if let Some(v) = args.get(i + 1)
                        && !v.starts_with('-')
                    {
                        out.cp_args.push(v.clone());
                        i += 1;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    // The three modes have no coherent combinations: the embedded CP
    // auto-pairs (so an external enrollment is meaningless), and detaching
    // contradicts both.
    if out.embed && out.enroll.is_some() {
        anyhow::bail!("--control-plane conflicts with --enroll: the embedded CP auto-enrolls");
    }
    if out.no_cp && (out.embed || out.enroll.is_some()) {
        anyhow::bail!("--no-cp conflicts with --enroll/--control-plane");
    }
    if !out.embed && !out.cp_args.is_empty() {
        anyhow::bail!(
            "--cp-* options configure the embedded control plane — add --control-plane (--cp)"
        );
    }
    if !out.tunnel
        && (out.tunnel_private
            || out.tunnel_name.is_some()
            || out.tunnel_mode.is_some()
            || out.tunnel_relay.is_some())
    {
        anyhow::bail!(
            "--private / --tunnel-name / --tunnel-mode / --tunnel-relay require --tunnel"
        );
    }
    if !out.inspector && !out.inspector_args.is_empty() {
        anyhow::bail!("--inspector-* options configure the inspector sidecar — add --inspector");
    }
    // `gateway.inspector.enabled: true` can also start the sidecar, but the
    // stdio conflict is CLI×CLI: the flag combination is always wrong.
    if out.inspector && args.iter().any(|a| a == "--stdio") {
        anyhow::bail!("--inspector needs the HTTP listener and conflicts with --stdio");
    }
    Ok(out)
}

/// The sticky pairing record: enough to re-attach on a plain `mcpg` run.
/// Lives next to the agent state (`<state_dir>/gateway-pairing.json`); the
/// agent's own credentials live under `<state_dir>/gateway-agent/`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Pairing {
    /// gRPC endpoint of the paired control plane.
    pub cp_grpc: String,
}

fn pairing_path(state_dir: &Path) -> PathBuf {
    state_dir.join("gateway-pairing.json")
}

/// The agent's credential/LKG directory (same location the old
/// `mcpg-ctl gateway` used, so existing self-host agents keep their
/// enrollment across the upgrade).
pub fn agent_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("gateway-agent")
}

pub fn load_pairing(state_dir: &Path) -> Option<Pairing> {
    let raw = std::fs::read(pairing_path(state_dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub fn save_pairing(state_dir: &Path, pairing: &Pairing) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(pairing_path(state_dir), serde_json::to_vec_pretty(pairing)?)?;
    Ok(())
}

/// Default the agent gRPC endpoint from the enrollment URL's host: same
/// scheme + host, the CP's standard gRPC port (7844). `--cp-grpc`
/// overrides when the deployment moved the port.
fn derive_grpc_url(enrollment_url: &str) -> anyhow::Result<String> {
    let u = url::Url::parse(enrollment_url)
        .map_err(|e| anyhow::anyhow!("--enroll is not a URL: {e}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("--enroll URL has no host"))?;
    Ok(format!("{}://{}:7844", u.scheme(), host))
}

/// Fold the composition flags + sticky pairing into the loaded config.
/// Explicit operator config (`gateway.control_plane`) always wins over
/// stickiness; flags that contradict it error rather than silently fight.
pub fn apply(config: &mut AppConfig, comp: &CompositionArgs) -> anyhow::Result<()> {
    // Tunnel egress is orthogonal to control-plane attach (which returns early
    // below), so fold it in first.
    apply_tunnel(config, comp)?;

    let state_dir = mcpg_cli_core::paths::default_state_dir();

    if config.gateway.control_plane.is_some() {
        if comp.enroll.is_some() {
            anyhow::bail!(
                "--enroll conflicts with `gateway.control_plane` already present in the config — \
                 edit the config or drop the flag"
            );
        }
        if comp.no_cp {
            eprintln!("mcpg: --no-cp — ignoring `gateway.control_plane` from config for this run");
            config.gateway.control_plane = None;
        }
        return Ok(());
    }

    if comp.no_cp {
        if load_pairing(&state_dir).is_some() {
            eprintln!("mcpg: --no-cp — stored control-plane pairing ignored for this run");
        }
        return Ok(());
    }

    if let Some(enroll_url) = &comp.enroll {
        let cp_grpc = match &comp.cp_grpc {
            Some(u) => u.clone(),
            None => derive_grpc_url(enroll_url)?,
        };
        let agent_state = agent_dir(&state_dir);
        mcpg_cli_core::paths::ensure_dir(&agent_state)?;
        config.gateway.control_plane = Some(ControlPlaneAttachConfig {
            url: cp_grpc.clone(),
            enrollment_url: Some(enroll_url.clone()),
            state_dir: agent_state.to_string_lossy().into_owned(),
            ..Default::default()
        });
        if comp.embed {
            // Per-run wiring from the embedded CP — deliberately NOT sticky:
            // the CP only exists inside `--cp` processes, so a plain `mcpg`
            // run must not come up retrying against a closed loopback port.
        } else {
            eprintln!("mcpg: attaching to control plane at {cp_grpc} (enrolling)");
            // Persist the pairing BEFORE the agent finishes enrolling: the
            // agent retries Register with backoff, and a pairing whose creds
            // never materialise is harmless (re-attach requires creds).
            save_pairing(&state_dir, &Pairing { cp_grpc })?;
        }
        return Ok(());
    }

    // No flags: re-attach when a pairing AND its credentials exist.
    if let Some(pairing) = load_pairing(&state_dir) {
        let agent_state = agent_dir(&state_dir);
        if agent_state.join("agent-creds.json").exists() {
            eprintln!(
                "mcpg: re-attaching to control plane at {} (stored pairing; --no-cp to skip)",
                pairing.cp_grpc
            );
            config.gateway.control_plane = Some(ControlPlaneAttachConfig {
                url: pairing.cp_grpc,
                enrollment_url: None,
                state_dir: agent_state.to_string_lossy().into_owned(),
                ..Default::default()
            });
        }
    }
    Ok(())
}

/// Fold the `--tunnel*` flags into `server.tunnel`. Flags win PER FIELD over
/// a `server.tunnel` block already in the config file: `--tunnel` alone
/// enables the file's tunnel settings (keeping a file-set relay/name/mode),
/// and each explicit flag overrides only its own field.
fn apply_tunnel(config: &mut AppConfig, comp: &CompositionArgs) -> anyhow::Result<()> {
    if !comp.tunnel {
        return Ok(());
    }
    use crate::config::{TunnelConfig, TunnelExposure, TunnelTrustMode};
    let base = config.gateway.server.tunnel.take();
    let mode = match comp.tunnel_mode.as_deref() {
        Some("relay_terminated") => TunnelTrustMode::RelayTerminated,
        Some("e2ee") => TunnelTrustMode::E2ee,
        Some(other) => {
            anyhow::bail!("--tunnel-mode must be `relay_terminated` or `e2ee`, got {other:?}")
        }
        None => base
            .as_ref()
            .map(|t| t.mode)
            .unwrap_or(TunnelTrustMode::RelayTerminated),
    };
    // e2ee is mcpg-to-mcpg only, so it always implies a private tunnel.
    let exposure = if comp.tunnel_private || mode == TunnelTrustMode::E2ee {
        TunnelExposure::Private
    } else {
        base.as_ref()
            .map(|t| t.exposure)
            .unwrap_or(TunnelExposure::Public)
    };
    config.gateway.server.tunnel = Some(TunnelConfig {
        enabled: true,
        relay_url: comp
            .tunnel_relay
            .clone()
            .or_else(|| base.as_ref().map(|t| t.relay_url.clone()))
            .unwrap_or_else(crate::config::server::default_tunnel_relay_url),
        name: comp
            .tunnel_name
            .clone()
            .or_else(|| base.as_ref().and_then(|t| t.name.clone())),
        exposure,
        mode,
    });
    Ok(())
}

/// `mcpg status` — what's on this box: the gateway (from `MCPG_CONFIG`),
/// the agent pairing, and any local control plane. Absorbs the old
/// `mcpg-ctl status` / `gateway-status` / `doctor` trio.
pub async fn box_status() -> anyhow::Result<()> {
    let state_dir = mcpg_cli_core::paths::default_state_dir();
    println!("state_dir : {}", state_dir.display());

    // ── gateway ──
    let config_paths: Vec<PathBuf> = std::env::var_os("MCPG_CONFIG")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let path_refs: Vec<&Path> = config_paths.iter().map(|p| p.as_path()).collect();
    match AppConfig::load_many(&path_refs) {
        Ok(cfg) => {
            let bind = &cfg.gateway.server.bind_address;
            let health = &cfg.gateway.server.health_path;
            let probe = format!("http://{bind}{health}");
            let up = matches!(
                http.get(&probe).send().await,
                Ok(r) if r.status().is_success()
            );
            println!(
                "gateway   : bind {bind} — {}",
                if up { "running" } else { "not running" }
            );
            if let Some(t) = &cfg.gateway.server.tunnel
                && t.enabled
            {
                use crate::config::TunnelExposure;
                let exposure = match t.exposure {
                    TunnelExposure::Public => "public",
                    TunnelExposure::Private => "private (federation-only)",
                };
                println!(
                    "tunnel    : {exposure} via {} (configured — connection state not probed)",
                    t.relay_url
                );
            }
        }
        Err(e) => println!("gateway   : config did not load ({e})"),
    }

    // ── agent pairing ──
    match load_pairing(&state_dir) {
        Some(p) => {
            let creds = agent_dir(&state_dir).join("agent-creds.json");
            println!(
                "agent     : paired with {} (credentials: {})",
                p.cp_grpc,
                if creds.exists() {
                    "present"
                } else {
                    "missing — run `mcpg --enroll <url>`"
                }
            );
            #[cfg(feature = "cp-attached")]
            {
                let lkg = mcpg_control_plane_client::LkgCache::in_state_dir(&agent_dir(&state_dir));
                if let Ok(Some((hash, _))) = lkg.load_bundle() {
                    println!("agent lkg : config hash {hash}");
                }
            }
        }
        None => println!("agent     : not paired (run `mcpg --enroll <url>` or `mcpg --cp`)"),
    }

    // ── local control plane ──
    match http.get("http://127.0.0.1:7843/healthz").send().await {
        Ok(r) if r.status().is_success() => {
            let mut line = "control-plane : running at http://127.0.0.1:7843".to_string();
            if let Ok(meta) = http.get("http://127.0.0.1:7843/v1/meta").send().await
                && let Ok(v) = meta.json::<serde_json::Value>().await
                && let Some(ver) = v.get("version").and_then(|x| x.as_str())
            {
                line.push_str(&format!(" (version {ver})"));
            }
            println!("{line}");
        }
        _ => println!("control-plane : none on this box (mcpg cp serve --dev, or mcpg --cp)"),
    }

    // ── local inspector ──
    match http.get("http://127.0.0.1:7846/healthz").send().await {
        Ok(r) if r.status().is_success() => {
            println!("inspector : running at http://127.0.0.1:7846");
        }
        _ => println!("inspector : none on this box (mcpg-inspector serve, or mcpg --inspector)"),
    }
    Ok(())
}

/// Everything the embedded control plane hands back to `main`.
pub struct SidecarCp {
    /// Enrollment URL minted for this gateway's agent.
    pub enrollment_url: String,
    /// Loopback gRPC endpoint the agent attaches to.
    pub grpc_url: String,
    /// The supervised `mcpg-cp serve` child. Held by `main` for the life of
    /// the gateway; `kill_on_drop` tears the control plane down on any exit
    /// path, so quickstart never leaks a background server.
    pub child: tokio::process::Child,
}

/// The value of `--<name> <v>` / `--<name>=<v>` in the (already
/// prefix-stripped) `--cp-*` passthrough args, else the given env var. The
/// child re-parses the same args itself — this peek only exists so the
/// supervisor knows where the server will listen.
fn cp_arg_or_env(cp_args: &[String], name: &str, env: &str) -> Option<String> {
    let flag = format!("--{name}");
    let mut it = cp_args.iter();
    while let Some(a) = it.next() {
        if a == &flag {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_owned());
        }
    }
    std::env::var(env).ok()
}

/// Supervise a sibling `mcpg-cp serve` with dev defaults (sqlite in the
/// state dir, auth off, loopback external URL) and mint a one-shot
/// enrollment token for this gateway — the loopback auto-enroll that
/// replaces quickstart's copy-the-URL step. Dev defaults are injected only
/// when the corresponding flag is absent from the passthrough args, so
/// `--cp-<flag>` overrides win exactly as they did when the server ran
/// in-process.
pub async fn boot_sidecar_cp(cp_args: &[String]) -> anyhow::Result<SidecarCp> {
    let Some(cp_bin) = crate::cli::locate_binary("mcpg-control-plane") else {
        anyhow::bail!(
            "`--control-plane` supervises the sibling `mcpg-control-plane` binary, \
             which is not installed (not on PATH, not next to this executable). It \
             ships in the mcpg toolchain suite — install it with:\n\n  \
             curl -fsSL https://raw.githubusercontent.com/mcpg-dev/source-code/main/install.sh | sh\n\n\
             or run a control plane yourself and attach with `--enroll <URL>`."
        );
    };

    let state_dir = mcpg_cli_core::paths::default_state_dir();
    mcpg_cli_core::paths::ensure_dir(&state_dir)?;

    let has = |name: &str| {
        let flag = format!("--{name}");
        cp_args
            .iter()
            .any(|a| a == &flag || a.starts_with(&format!("{flag}=")))
    };

    // Where the child will listen: flag > its own env > its default. The
    // defaults mirror `mcpg-cp serve` (loopback 7843/7844) and only feed the
    // readiness probe + enrollment mint below.
    let bind_http = cp_arg_or_env(cp_args, "bind-http", "MCPG_CP_BIND_HTTP")
        .unwrap_or_else(|| "127.0.0.1:7843".into());
    let bind_grpc = cp_arg_or_env(cp_args, "bind-grpc", "MCPG_CP_BIND_GRPC")
        .unwrap_or_else(|| "127.0.0.1:7844".into());
    let external_url = cp_arg_or_env(cp_args, "external-url", "MCPG_CP_EXTERNAL_URL")
        .unwrap_or_else(|| format!("http://{bind_http}"));
    let external_url = external_url.trim_end_matches('/').to_owned();

    let mut cmd = tokio::process::Command::new(&cp_bin);
    cmd.arg("serve");
    if !has("db-url") {
        cmd.arg("--db-url")
            .arg(mcpg_cli_core::paths::db_url(&state_dir));
    }
    if !has("auth-mode") {
        cmd.arg("--auth-mode").arg("none");
    }
    if !has("external-url") {
        cmd.arg("--external-url").arg(&external_url);
    }
    cmd.args(cp_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        // Covers the graceful exits (Ctrl-C, SIGTERM) where destructors run.
        .kill_on_drop(true);
    // Destructors do NOT run on SIGKILL or when a closing terminal takes the
    // process group down, which would strand the control plane. Ask the
    // kernel to signal the child when this process dies, whatever the cause.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt as _;
        cmd.as_std_mut().pre_exec(|| {
            // SAFETY: async-signal-safe single syscall, the only work done
            // between fork and exec.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Race: if the parent died between fork and prctl, no signal is
            // ever delivered — check and self-terminate instead.
            if libc::getppid() == 1 {
                libc::_exit(0);
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start `{cp_bin} serve`: {e}"))?;

    // Wait for the child's HTTP surface, then mint the agent's enrollment
    // token over it (auth is off on loopback; `mcpg-cp serve` guarantees the
    // default org/workspace/environment exist). Enrollment-token TTL is in
    // seconds on the wire.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match http.get(format!("{external_url}/readyz")).send().await {
            Ok(r) if r.status().is_success() => break,
            _ if std::time::Instant::now() > deadline => {
                anyhow::bail!(
                    "mcpg-cp did not become ready at {external_url}/readyz within 60s \
                     — its log output above should say why"
                )
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    let resp = http
        .post(format!(
            "{external_url}/v1/orgs/default/workspaces/default/environments/default/enrollment-tokens"
        ))
        .json(&serde_json::json!({ "one_shot": true, "ttl_ms": 600 }))
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("minting the loopback enrollment token failed: {e}"))?;
    let body: serde_json::Value = resp.json().await?;
    let enrollment_url = body
        .get("enrollment_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("enrollment-token response had no enrollment_url"))?
        .to_owned();

    println!();
    println!("  ▸ MCPG Gateway + Control Plane (mcpg-cp sidecar)");
    println!();
    println!("    console: {external_url}");
    println!();

    Ok(SidecarCp {
        enrollment_url,
        grpc_url: format!("http://{bind_grpc}"),
        child,
    })
}

/// The supervised inspector child, held by `main` for the life of the
/// gateway (`kill_on_drop` + PDEATHSIG, exactly like the CP sidecar).
pub struct SidecarInspector {
    pub url: String,
    pub child: tokio::process::Child,
}

/// The gateway's own listener as dialable from this host: a wildcard bind is
/// reachable over loopback, but only loopback — handing the inspector
/// `0.0.0.0` gives it an address that means "everywhere" to a listener and
/// nothing to a client.
fn dial_authority(config: &AppConfig) -> String {
    let listen = &config.gateway.server.bind_address;
    let (host, port) = listen.rsplit_once(':').unwrap_or((listen.as_str(), "8787"));
    let host = match host {
        "0.0.0.0" | "::" | "[::]" | "" => "127.0.0.1",
        other => other,
    };
    format!("{host}:{port}")
}

/// Where to knock to learn whether the data plane is serving, or `None` when
/// this gateway has no local listener to knock on: stdio speaks over the
/// process's own pipes, and a tunnelled gateway is reachable only through the
/// relay it dials out to.
fn readiness_probe_authority(config: &AppConfig) -> Option<String> {
    if matches!(
        config.gateway.server.transport,
        crate::config::TransportMode::Stdio
    ) {
        return None;
    }
    if config
        .gateway
        .server
        .tunnel
        .as_ref()
        .is_some_and(|t| t.enabled)
    {
        return None;
    }
    Some(dial_authority(config))
}

/// Block until something accepts a connection at `authority`, or the deadline
/// passes. Returns whether it came up.
///
/// A TCP connect is the whole question — is the listener open — and it asks it
/// without depending on a health path being enabled or on TLS trust, either of
/// which would make a healthy gateway look unreachable.
async fn wait_for_listener(authority: &str, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(authority).await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// The targets `--inspector` hands its child.
///
/// This gateway first, then every federated upstream that has a URL, so one
/// session can compare what mcpg re-serves against what the upstream
/// actually offers — the question behind most "why is this tool missing"
/// reports.
///
/// No credentials travel here. `--target` lands on argv, which every process
/// on the box can read; the gateway's own token goes by environment instead.
/// A federation's credential belongs to the gateway anyway: the inspector
/// dialling that upstream directly is a *different* caller, and lending it
/// mcpg's identity would misrepresent who is asking.
fn prewired_targets(config: &AppConfig, gateway_url: &str) -> Vec<serde_json::Value> {
    let mut targets = vec![serde_json::json!({ "name": "gateway", "url": gateway_url })];
    for federation in &config.mcp.federations {
        let upstream = &federation.upstream;
        if upstream.url.is_empty() {
            continue; // a stdio federation has no URL to dial
        }
        targets.push(serde_json::json!({
            "name": format!("upstream:{}", federation.name),
            "url": upstream.url,
            // Pin what the gateway pinned; `auto` means it probes, so the
            // inspector should probe too rather than guess differently.
            "protocol_version": match upstream.protocol_version {
                crate::config::UpstreamProtocolVersion::V2026_07_28 => "2026-07-28",
                crate::config::UpstreamProtocolVersion::V2025_11_25 => "2025-11-25",
                _ => "auto",
            },
            "allow_private": upstream.upstream_safety.allow_private_backends,
        }));
    }
    targets
}

/// Supervise a sibling `mcpg-inspector serve` pre-wired against this
/// gateway. The supervisor derives child flags gap-only — the
/// `gateway.inspector` config block first, then defaults — so explicit
/// `--inspector-<flag>` passthrough always wins. It mints a per-boot
/// credential, installs it in the identity cascade
/// (`runtime::inspector_identity`) and hands it to the child through
/// its environment (never argv): a loopback caller presenting it is a
/// Verified principal, which is what lets the inspector see tools
/// through a stock config's trust floor.
pub async fn boot_sidecar_inspector(
    config: &AppConfig,
    inspector_args: &[String],
) -> anyhow::Result<SidecarInspector> {
    let Some(inspector_bin) = crate::cli::locate_binary("mcpg-inspector") else {
        anyhow::bail!(
            "`--inspector` supervises the sibling `mcpg-inspector` binary, which is \
             not installed (not on PATH, not next to this executable). It ships in \
             the mcpg toolchain suite — install it with:\n\n  \
             curl -fsSL https://raw.githubusercontent.com/mcpg-dev/source-code/main/install.sh | sh\n\n\
             or run it yourself: `mcpg-inspector serve`."
        );
    };

    let has = |name: &str| {
        let flag = format!("--{name}");
        inspector_args
            .iter()
            .any(|a| a == &flag || a.starts_with(&format!("{flag}=")))
    };

    // Where the child will listen: flag > its own env > the config
    // block > the inspector's default.
    let bind = cp_arg_or_env(inspector_args, "bind", "MCPG_INSPECTOR_BIND")
        .or_else(|| config.gateway.inspector.bind.clone())
        .unwrap_or_else(|| "127.0.0.1:7846".into());

    let authority = dial_authority(config);
    // A TLS-terminating gateway is not reachable over http, and the
    // inspector would report a connection failure that looks like the
    // gateway being down.
    let scheme = if config.gateway.server.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let gateway_url = format!("{scheme}://{authority}{}", config.gateway.server.mcp_path);

    // Per-boot credential: env to the child (argv would leak it to
    // `ps`), identity cascade on our side. Two v4 UUIDs = 244 random
    // bits from the OS RNG.
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    crate::runtime::inspector_identity::install(token.clone());

    let mut cmd = tokio::process::Command::new(&inspector_bin);
    cmd.arg("serve");
    if !has("bind") {
        cmd.arg("--bind").arg(&bind);
    }
    if !has("target") {
        for target in prewired_targets(config, &gateway_url) {
            cmd.arg("--target").arg(target.to_string());
        }
    }
    cmd.args(inspector_args)
        .env("MCPG_INSPECTOR_GATEWAY_TOKEN", &token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    // Same hard-death coverage as the CP sidecar: destructors don't run
    // on SIGKILL / a closing terminal, so the kernel delivers the
    // signal instead.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt as _;
        cmd.as_std_mut().pre_exec(|| {
            // SAFETY: async-signal-safe single syscall, the only work done
            // between fork and exec.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() == 1 {
                libc::_exit(0);
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start `{inspector_bin} serve`: {e}"))?;

    let url = format!("http://{bind}");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match http.get(format!("{url}/readyz")).send().await {
            Ok(r) if r.status().is_success() => break,
            _ if std::time::Instant::now() > deadline => {
                anyhow::bail!(
                    "mcpg-inspector did not become ready at {url}/readyz within 60s \
                     — its log output above should say why"
                )
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }

    // The sidecar is ready long before the data plane is: it boots in
    // milliseconds, while this process still has plugins to load and backends
    // to open, and its listener does not exist until all of that finishes.
    // Printing the URL here invites the first click to land on a refused
    // connection to the pre-wired target, which reads as the inspector being
    // broken. So the announcement waits for the gateway to answer — in the
    // background, because the listener it is waiting for is opened by the
    // caller, after this returns.
    let probe = readiness_probe_authority(config);
    let announce_url = url.clone();
    tokio::spawn(async move {
        let mut serving = true;
        if let Some(authority) = probe {
            serving = wait_for_listener(&authority, std::time::Duration::from_secs(60)).await;
        }
        println!();
        println!("  ▸ MCPG Gateway + Inspector (mcpg-inspector sidecar)");
        println!();
        println!("    inspector: {announce_url}/");
        if !serving {
            // Still worth printing the URL — the sidecar is up and can dial
            // anything else — but not worth implying the pre-wired target works.
            println!("    note: this gateway is not answering yet; its own target");
            println!("          will fail to connect until it does.");
        }
        println!();
    });

    Ok(SidecarInspector { url, child })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dial_authority_rewrites_a_wildcard_bind_to_loopback() {
        let mut config = AppConfig::default();
        for (bind, expected) in [
            ("0.0.0.0:8787", "127.0.0.1:8787"),
            ("[::]:9000", "127.0.0.1:9000"),
            ("127.0.0.1:7777", "127.0.0.1:7777"),
            ("10.1.2.3:8080", "10.1.2.3:8080"),
            // Port-less is defensive only: the transport parses this same
            // string as a `SocketAddr`, so a config without a port never
            // reaches a listener at all.
            ("0.0.0.0", "127.0.0.1:8787"),
        ] {
            config.gateway.server.bind_address = bind.to_owned();
            assert_eq!(dial_authority(&config), expected, "bind {bind}");
        }
    }

    /// Waiting for a listener that will never exist would hold the
    /// announcement for the full timeout and then claim the gateway is down,
    /// which is wrong: these transports are working exactly as configured.
    #[test]
    fn transports_without_a_local_listener_are_not_probed() {
        let mut config = AppConfig::default();
        config.gateway.server.bind_address = "127.0.0.1:8787".to_owned();
        assert_eq!(
            readiness_probe_authority(&config).as_deref(),
            Some("127.0.0.1:8787")
        );

        config.gateway.server.transport = crate::config::TransportMode::Stdio;
        assert!(readiness_probe_authority(&config).is_none(), "stdio");

        config.gateway.server.transport = crate::config::TransportMode::Http;
        let tunnel: crate::config::TunnelConfig =
            serde_yaml::from_str("enabled: true").expect("tunnel config");
        config.gateway.server.tunnel = Some(tunnel);
        assert!(readiness_probe_authority(&config).is_none(), "tunnel");
    }

    /// The probe has to answer the question it claims to: is something
    /// accepting connections here, right now.
    #[tokio::test]
    async fn wait_for_listener_distinguishes_open_from_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().to_string();
        assert!(
            wait_for_listener(&open, std::time::Duration::from_secs(5)).await,
            "an open listener should be seen immediately"
        );

        // Bind a second port, then drop it: nothing is listening there now.
        let closed = {
            let doomed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            doomed.local_addr().unwrap().to_string()
        };
        assert!(
            !wait_for_listener(&closed, std::time::Duration::from_millis(300)).await,
            "a closed port must time out rather than report ready"
        );
    }

    /// The real ordering: the sidecar is up first and the gateway's listener
    /// opens later, which is exactly when announcing early misleads.
    #[tokio::test]
    async fn wait_for_listener_waits_for_a_late_bind() {
        // Reserve a port, release it, and rebind after a delay.
        let addr = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap()
        };
        let late = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tokio::net::TcpListener::bind(addr).await
        });

        let seen = wait_for_listener(&addr.to_string(), std::time::Duration::from_secs(10)).await;
        let bound = late.await.unwrap();
        assert!(bound.is_ok(), "the late bind must have succeeded");
        assert!(seen, "the wait must survive a listener that opens late");
    }

    #[test]
    fn parse_extracts_composition_flags_and_ignores_others() {
        let c = parse(&args(&[
            "--stdio",
            "--enroll",
            "http://cp:7843/enroll/v1#token=X",
        ]))
        .unwrap();
        assert_eq!(
            c.enroll.as_deref(),
            Some("http://cp:7843/enroll/v1#token=X")
        );
        assert!(!c.no_cp && !c.embed);

        let c = parse(&args(&["--enroll=http://cp:7843/e"])).unwrap();
        assert_eq!(c.enroll.as_deref(), Some("http://cp:7843/e"));
    }

    #[test]
    fn parse_collects_repeatable_config_sources_in_order() {
        let c = parse(&args(&[
            "--config",
            "base.yaml",
            "--config=https://cfg.example/overlay.yaml",
            "--tunnel",
            "--config",
            "base64:Zm9v",
        ]))
        .unwrap();
        assert_eq!(
            c.config,
            vec![
                "base.yaml".to_owned(),
                "https://cfg.example/overlay.yaml".to_owned(),
                "base64:Zm9v".to_owned(),
            ]
        );
        // `--config` stands alone; it neither requires nor conflicts with the
        // tunnel/CP flags.
        assert!(parse(&args(&["--config", "gw.yaml"])).is_ok());
    }

    #[test]
    fn parse_cp_passthrough_strips_prefix_only_under_embed() {
        let c = parse(&args(&["--cp", "--cp-bind-http", "127.0.0.1:9999"])).unwrap();
        assert!(c.embed);
        assert_eq!(c.cp_args, vec!["--bind-http", "127.0.0.1:9999"]);

        // --cp-grpc is OURS (attach override), not a passthrough.
        let c = parse(&args(&[
            "--enroll",
            "http://h:7843/e",
            "--cp-grpc",
            "http://h:9444",
        ]))
        .unwrap();
        assert_eq!(c.cp_grpc.as_deref(), Some("http://h:9444"));
        assert!(c.cp_args.is_empty());

        // Passthrough without --cp is a user error, not a silent no-op.
        assert!(parse(&args(&["--cp-bind-http", "x"])).is_err());
    }

    #[test]
    fn parse_rejects_contradictory_modes() {
        assert!(parse(&args(&["--cp", "--enroll", "http://x/e"])).is_err());
        assert!(parse(&args(&["--no-cp", "--enroll", "http://x/e"])).is_err());
        assert!(parse(&args(&["--no-cp", "--cp"])).is_err());
    }

    #[test]
    fn parse_inspector_passthrough_and_conflicts() {
        let c = parse(&args(&["--inspector"])).unwrap();
        assert!(c.inspector);
        assert!(c.inspector_args.is_empty());

        // `--inspector-<x> [v]` → `--<x> [v]`, both spellings.
        let c = parse(&args(&[
            "--inspector",
            "--inspector-bind",
            "127.0.0.1:9000",
            "--inspector-dev",
        ]))
        .unwrap();
        assert_eq!(c.inspector_args, vec!["--bind", "127.0.0.1:9000", "--dev"]);
        let c = parse(&args(&["--inspector", "--inspector-bind=127.0.0.1:9000"])).unwrap();
        assert_eq!(c.inspector_args, vec!["--bind", "127.0.0.1:9000"]);

        // Passthrough without --inspector is a user error, not a no-op;
        // and the sidecar needs the HTTP listener --stdio replaces.
        assert!(parse(&args(&["--inspector-bind", "x"])).is_err());
        assert!(parse(&args(&["--inspector", "--stdio"])).is_err());

        // The two sidecars compose.
        let c = parse(&args(&["--cp", "--inspector"])).unwrap();
        assert!(c.embed && c.inspector);
    }

    #[test]
    fn grpc_url_derives_from_enrollment_host() {
        assert_eq!(
            derive_grpc_url("http://cp.example:7843/enroll/v1#token=ENROL-abc").unwrap(),
            "http://cp.example:7844"
        );
        assert_eq!(
            derive_grpc_url("https://cp.mcpg.cloud/enroll/v1#token=x").unwrap(),
            "https://cp.mcpg.cloud:7844"
        );
        assert!(derive_grpc_url("not a url").is_err());
    }

    #[test]
    fn pairing_round_trips_and_apply_is_sticky_only_with_creds() {
        let dir = tempfile::tempdir().unwrap();
        save_pairing(
            dir.path(),
            &Pairing {
                cp_grpc: "http://127.0.0.1:7844".into(),
            },
        )
        .unwrap();
        assert_eq!(
            load_pairing(dir.path()).unwrap().cp_grpc,
            "http://127.0.0.1:7844"
        );
    }

    #[test]
    fn apply_enroll_synthesizes_attach_and_persists_pairing() {
        let dir = tempfile::tempdir().unwrap();
        // Route the state dir at a tempdir via env for this test only.
        // (set_var is safe here: tests in this module don't race on it.)
        unsafe { std::env::set_var("MCPG_STATE_DIR", dir.path()) };
        let mut config = AppConfig::default();
        let comp = CompositionArgs {
            enroll: Some("http://127.0.0.1:7843/enroll/v1#token=T".into()),
            ..Default::default()
        };
        apply(&mut config, &comp).unwrap();
        let attach = config.gateway.control_plane.as_ref().expect("attach set");
        assert_eq!(attach.url, "http://127.0.0.1:7844");
        assert_eq!(
            attach.enrollment_url.as_deref(),
            Some("http://127.0.0.1:7843/enroll/v1#token=T")
        );
        assert!(load_pairing(dir.path()).is_some(), "pairing persisted");

        // Plain run without creds: pairing exists but no agent-creds.json →
        // NOT re-attached (enrollment never completed).
        let mut plain = AppConfig::default();
        apply(&mut plain, &CompositionArgs::default()).unwrap();
        assert!(plain.gateway.control_plane.is_none());

        // With creds present, the plain run re-attaches.
        let agent = agent_dir(dir.path());
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("agent-creds.json"), b"{}").unwrap();
        let mut plain2 = AppConfig::default();
        apply(&mut plain2, &CompositionArgs::default()).unwrap();
        let attach = plain2.gateway.control_plane.expect("re-attached");
        assert_eq!(attach.url, "http://127.0.0.1:7844");
        assert!(
            attach.enrollment_url.is_none(),
            "no re-enroll on sticky attach"
        );

        // --no-cp skips the sticky attach.
        let mut detached = AppConfig::default();
        apply(
            &mut detached,
            &CompositionArgs {
                no_cp: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(detached.gateway.control_plane.is_none());
        unsafe { std::env::remove_var("MCPG_STATE_DIR") };
    }

    #[test]
    fn parse_tunnel_accepts_an_optional_relay_value() {
        // Bare flag: tunnel on, relay unset (default resolves later).
        let c = parse(&args(&["--tunnel"])).unwrap();
        assert!(c.tunnel && c.tunnel_relay.is_none());

        // Space-separated URL value is consumed…
        let c = parse(&args(&["--tunnel", "wss://relay.example:7845"])).unwrap();
        assert!(c.tunnel);
        assert_eq!(c.tunnel_relay.as_deref(), Some("wss://relay.example:7845"));

        // …and the `=` form works too.
        let c = parse(&args(&["--tunnel=wss://relay.example"])).unwrap();
        assert_eq!(c.tunnel_relay.as_deref(), Some("wss://relay.example"));

        // Only URL-shaped tokens are consumed: a following flag survives.
        let c = parse(&args(&["--tunnel", "--private"])).unwrap();
        assert!(c.tunnel && c.tunnel_private && c.tunnel_relay.is_none());

        // --tunnel-relay still works, and agreeing values coexist.
        let c = parse(&args(&["--tunnel", "--tunnel-relay", "wss://r.example"])).unwrap();
        assert_eq!(c.tunnel_relay.as_deref(), Some("wss://r.example"));
        let c = parse(&args(&[
            "--tunnel",
            "wss://r.example",
            "--tunnel-relay",
            "wss://r.example",
        ]))
        .unwrap();
        assert_eq!(c.tunnel_relay.as_deref(), Some("wss://r.example"));

        // Contradictory relay endpoints are rejected.
        let err = parse(&args(&[
            "--tunnel",
            "wss://a.example",
            "--tunnel-relay",
            "wss://b.example",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("relay endpoint given twice"));

        // Tunnel sub-flags still require --tunnel.
        let err = parse(&args(&["--tunnel-relay", "wss://r.example"])).unwrap_err();
        assert!(err.to_string().contains("require --tunnel"));
    }

    #[test]
    fn apply_tunnel_merges_per_field_with_the_config_file() {
        use crate::config::{TunnelConfig, TunnelExposure, TunnelTrustMode};
        let file_tunnel = TunnelConfig {
            enabled: false,
            relay_url: "wss://relay.corp.example:7845".into(),
            name: Some("edge-1".into()),
            exposure: TunnelExposure::Private,
            mode: TunnelTrustMode::RelayTerminated,
        };

        // Bare `--tunnel` enables the file's tunnel and KEEPS its relay/name/
        // exposure instead of resetting them to defaults.
        let mut config = AppConfig::default();
        config.gateway.server.tunnel = Some(file_tunnel.clone());
        apply_tunnel(
            &mut config,
            &CompositionArgs {
                tunnel: true,
                ..Default::default()
            },
        )
        .unwrap();
        let t = config.gateway.server.tunnel.as_ref().unwrap();
        assert!(t.enabled);
        assert_eq!(t.relay_url, "wss://relay.corp.example:7845");
        assert_eq!(t.name.as_deref(), Some("edge-1"));
        assert_eq!(t.exposure, TunnelExposure::Private);

        // An explicit relay flag overrides only the relay field.
        let mut config = AppConfig::default();
        config.gateway.server.tunnel = Some(file_tunnel);
        apply_tunnel(
            &mut config,
            &CompositionArgs {
                tunnel: true,
                tunnel_relay: Some("wss://other.example".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let t = config.gateway.server.tunnel.as_ref().unwrap();
        assert_eq!(t.relay_url, "wss://other.example");
        assert_eq!(t.name.as_deref(), Some("edge-1"));

        // No file block at all: bare `--tunnel` gets the MCPG Cloud default.
        let mut config = AppConfig::default();
        apply_tunnel(
            &mut config,
            &CompositionArgs {
                tunnel: true,
                ..Default::default()
            },
        )
        .unwrap();
        let t = config.gateway.server.tunnel.as_ref().unwrap();
        assert_eq!(
            t.relay_url,
            crate::config::server::default_tunnel_relay_url()
        );
        assert_eq!(t.exposure, TunnelExposure::Public);
    }
}

#[cfg(test)]
mod prewired_target_tests {
    use super::*;

    fn config_with(federations: serde_json::Value) -> AppConfig {
        let mut config = AppConfig::default();
        config.mcp.federations = serde_json::from_value(federations).expect("federations");
        config
    }

    #[test]
    fn the_gateway_itself_is_always_first() {
        let targets = prewired_targets(&AppConfig::default(), "http://127.0.0.1:8787/mcp");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["name"], "gateway");
        assert_eq!(targets[0]["url"], "http://127.0.0.1:8787/mcp");
    }

    /// Federated upstreams ride along so one session can compare what the
    /// gateway re-serves against what the upstream offers.
    #[test]
    fn federated_upstreams_are_pre_wired_too() {
        let config = config_with(serde_json::json!([
            {
                "name": "notes",
                "upstream": {
                    "url": "https://notes.example/mcp",
                    "protocol_version": "2026-07-28"
                }
            },
            {
                "name": "docs",
                "upstream": { "url": "https://docs.example/mcp" }
            }
        ]));
        let targets = prewired_targets(&config, "http://127.0.0.1:8787/mcp");
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[1]["name"], "upstream:notes");
        assert_eq!(targets[1]["url"], "https://notes.example/mcp");
        assert_eq!(targets[1]["protocol_version"], "2026-07-28");
        // Unpinned upstream: the gateway probes, so the inspector probes.
        assert_eq!(targets[2]["name"], "upstream:docs");
        assert_eq!(targets[2]["protocol_version"], "auto");
    }

    /// Not one credential may travel on argv, which every process on the
    /// box can read. The gateway's own token goes by environment; a
    /// federation's belongs to the gateway and is not the inspector's to
    /// borrow.
    #[test]
    fn no_credential_reaches_the_command_line() {
        let config = config_with(serde_json::json!([{
            "name": "notes",
            "upstream": {
                "url": "https://notes.example/mcp",
                "auth": { "mode": "service_token", "token": "super-secret-value" },
                "headers": { "x-api-key": "another-secret" }
            }
        }]));
        let rendered = prewired_targets(&config, "http://127.0.0.1:8787/mcp")
            .iter()
            .map(|t| t.to_string())
            .collect::<String>();
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(!rendered.contains("another-secret"), "{rendered}");
        assert!(!rendered.contains("bearer"), "{rendered}");
    }

    /// A stdio federation has no URL; emitting one would produce a target
    /// that cannot be dialled.
    #[test]
    fn a_stdio_federation_is_skipped() {
        let config = config_with(serde_json::json!([{
            "name": "local",
            "upstream": { "transport": "stdio", "command": "some-server" }
        }]));
        let targets = prewired_targets(&config, "http://127.0.0.1:8787/mcp");
        assert_eq!(targets.len(), 1, "only the gateway itself");
    }

    /// The upstream's own egress posture carries over: an upstream the
    /// gateway is allowed to reach on a private address is one the
    /// inspector must also be allowed to reach, or the pre-wired target
    /// fails for a reason the operator did not configure.
    #[test]
    fn the_private_address_posture_carries_over() {
        let config = config_with(serde_json::json!([{
            "name": "local",
            "upstream": {
                "url": "http://127.0.0.1:9000/mcp",
                "upstream_safety": { "allow_private_backends": true }
            }
        }]));
        let targets = prewired_targets(&config, "http://127.0.0.1:8787/mcp");
        assert_eq!(targets[1]["allow_private"], true);
    }
}
