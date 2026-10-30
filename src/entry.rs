//! The `mcpg` command: parses CLI arguments, loads configuration from YAML /
//! environment, and delegates to the `app` module for bootstrap and
//! transport selection. Every binary that runs the gateway CLI calls
//! [`main`].

use std::path::PathBuf;

use anyhow::Context as _;

pub fn main() -> anyhow::Result<()> {
    // Install the process-level rustls CryptoProvider before any TLS client
    // can be built. The dependency graph compiles in both providers (aws_lc_rs
    // directly, ring transitively via tonic's tls feature), so rustls cannot
    // auto-select one — the cp-attach agent builds a TLS gRPC client to a
    // `https://` control plane and would otherwise panic. Idempotent + Once-
    // guarded; pins the whole process to aws_lc_rs, matching the rest of the
    // workspace binaries.
    crate::transports::tls::install_default_crypto_provider();

    let args: Vec<String> = std::env::args().collect();

    // `--version` / `-V` and `--health-check` answer and exit before any boot
    // work and before the multi-threaded runtime exists. Either one reaching
    // the boot path below would start a full gateway and never return, and a
    // script or a container runtime waits on both.
    if args.iter().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("mcpg {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    // A bare word in first place is a subcommand that owns the rest of argv,
    // so `--health-check` after it belongs to the sibling binary.
    if args
        .get(1)
        .is_some_and(|a| !crate::cli::is_subcommand_word(a))
        && args.iter().skip(1).any(|a| a == "--health-check")
    {
        std::process::exit(crate::health_probe::run(&args[1..]));
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_keep_alive(BLOCKING_THREAD_KEEP_ALIVE)
        .build()
        .context("cannot build the async runtime")?
        .block_on(run(args))
}

/// How long an idle blocking-pool thread waits for work before it exits.
/// Idle threads take new work in turn, so under tokio's 10 s a fleet's
/// periodic coordinator calls keep every thread of a burst, and its allocator
/// cache, alive.
const BLOCKING_THREAD_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(1);

async fn run(args: Vec<String>) -> anyhow::Result<()> {
    // CLI extension dispatch: `mcpg plugin <subcommand> [args...]`
    // Delegates to `mcpg-plugin <subcommand> [args...]` if found on PATH,
    // passing through MCPG_CONFIG and other environment variables.
    if args.len() >= 2 && args[1] == "plugin" {
        return crate::cli::dispatch_plugin_command(&args[2..]);
    }

    // `mcpg dev cluster <up|down|status>` — the local multi-node cluster
    // harness (NATS container + N gateway child processes). Handled before
    // the plugin-loader dev mode below, which owns every other `mcpg dev`
    // spelling.
    if args.len() >= 3 && args[1] == "dev" && args[2] == "cluster" {
        return crate::dev_cluster::run(&args[3..]).await;
    }

    // `mcpg dev [--plugin <path> ...]` — local dev
    // mode. Synthesises a minimal config layered on top of the
    // operator's existing `MCPG_CONFIG` (if any) so a plugin author
    // can iterate `cargo build` → run the cdylib through a live
    // gateway without authoring a full operator config. Each
    // `--plugin <path>` adds one `plugins[]` entry pointing at the
    // built artifact; the descriptor / id / class are read from a
    // sibling `plugin.yaml` next to the artifact, or from a
    // `<artifact>.plugin.yaml` override.
    if args.len() >= 2 && args[1] == "dev" {
        let _guard = crate::cli::prepare_dev_mode(&args[2..])?;
        // Fall through into the normal boot path — `prepare_dev_mode`
        // has populated `MCPG_CONFIG` (or layered onto it) so the
        // generated dev-config materialises like any other YAML.
        // Drop happens at the end of `run`; tempfiles outlive the gateway.
        let config_paths: Vec<PathBuf> = std::env::var_os("MCPG_CONFIG")
            .map(|v| std::env::split_paths(&v).collect())
            .unwrap_or_default();
        let state = crate::app::build(config_paths).await?;
        if crate::cli::stdio_requested(&args) {
            let mut config = (**state.config.load()).clone();
            config.gateway.server.transport = crate::config::TransportMode::Stdio;
            state.config.store(std::sync::Arc::new(config));
        }
        return crate::app::run(state).await;
    }

    // Top-level help: list the subcommand groups + the gateway-boot default.
    if args.len() >= 2 && matches!(args[1].as_str(), "help" | "--help" | "-h") {
        crate::cli::print_top_help();
        return Ok(());
    }

    // `mcpg status` — in-process box report (gateway, agent pairing, local
    // control plane). Checked before the sibling dispatch below, which would
    // otherwise try to exec a nonexistent `mcpg-status`.
    if args.len() >= 2 && args[1] == "status" {
        return crate::compose::box_status().await;
    }

    // `mcpg capabilities` — the capability manifest for THIS build, printed
    // in-process for the same reason as `status`: there is no sibling binary,
    // and a control plane invoking it inside the image must get the answer
    // from the binary it is about to run.
    if args.len() >= 2 && args[1] == "capabilities" {
        return crate::capabilities::print();
    }

    // Subcommand extension dispatch (kubectl-style): a bare-word first arg is a
    // toolchain subcommand delegated to a sibling `mcpg-*` binary, not a gateway
    // flag. `mcpg config <sub>` → `mcpg-config <sub>`; `mcpg cp …` → `mcpg-cp …`
    // (and any `mcpg <x>` → `mcpg-<x>`). Gateway boot takes no positional
    // argument — config comes from `MCPG_CONFIG`, the rest are `--flags` — so
    // this never shadows it. `plugin`, `dev`, and `status` are handled above.
    if args.len() >= 2 && crate::cli::is_subcommand_word(&args[1]) {
        return crate::cli::dispatch_subcommand(&args[1], &args[2..]);
    }

    // Composition flags (CLI-REORGANIZATION.md §4.2): `--enroll <URL>`
    // (sticky attach), `--no-cp` (one-off detach), `--control-plane`/`--cp`
    // (supervised CP sidecar). Conflicts error before anything boots.
    #[allow(unused_mut)]
    let mut comp = crate::compose::parse(&args[1..])?;

    // Held for the life of the process: dropping it kills the control plane
    // (`kill_on_drop`), so no exit path can leave a server behind.
    let mut _cp_sidecar = None;
    if comp.embed {
        // Start the CP first; it hands back the loopback attach coordinates
        // the agent enrolls with.
        let sidecar = crate::compose::boot_sidecar_cp(&comp.cp_args).await?;
        comp.enroll = Some(sidecar.enrollment_url.clone());
        comp.cp_grpc = Some(sidecar.grpc_url.clone());
        _cp_sidecar = Some(sidecar);
    }

    // Where the config comes from follows the precedence every CLI its
    // operators already use (kubectl, docker, terraform, cargo): the flag
    // the person typed outranks the environment, which outranks the file's
    // own defaults. So `--config <source>` (repeatable; a local path, a
    // `file://` path, an `https://` URL fetched now, or inline
    // `base64:`/`data:` YAML) is THE source list when given, and
    // `MCPG_CONFIG` — a single path or a path-separator-joined list of
    // files — is read only without it. An image bakes `MCPG_CONFIG` as its
    // default; a flag on the command line is never beaten by that default.
    // Layers within one list merge later-wins. `MCPG_*` setting overrides
    // apply over the loaded layers.
    if !comp.config.is_empty()
        && let Some(v) = std::env::var_os("MCPG_CONFIG").filter(|v| !v.is_empty())
    {
        eprintln!(
            "mcpg: --config given; MCPG_CONFIG={} is not loaded (a flag outranks the environment)",
            v.to_string_lossy()
        );
    }
    let config_sources = crate::config::source::gateway_sources(&comp.config).await?;
    // Load the config here (rather than via `app::build`) so the
    // composition flags can fold their control-plane attachment in before
    // the runtime is built.
    let mut config = crate::config::AppConfig::load_sources(&config_sources)?;
    // Anchor relative `schemas[].file` refs against the last FILE layer's
    // directory (inline/remote layers have no directory to anchor against).
    let config_dir = config_sources.iter().rev().find_map(|s| match s {
        crate::config::ConfigSource::File(p) => p.parent(),
        crate::config::ConfigSource::Inline { .. } => None,
    });
    config.resolve_schema_refs(config_dir).await?;
    crate::compose::apply(&mut config, &comp)?;

    // Held for the life of the process, like the CP sidecar: dropping it
    // kills the inspector. Boots after config load — the auto-wired
    // target needs the gateway's actual bind + mcp_path — and before
    // the runtime, so the minted identity is installed when the
    // listener opens.
    let mut _inspector_sidecar = None;
    if comp.inspector || config.gateway.inspector.enabled {
        _inspector_sidecar =
            Some(crate::compose::boot_sidecar_inspector(&config, &comp.inspector_args).await?);
    }

    let state = crate::app::build_from_sources(config, config_sources).await?;

    // --stdio flag overrides transport mode
    if crate::cli::stdio_requested(&args) {
        let mut config = (**state.config.load()).clone();
        config.gateway.server.transport = crate::config::TransportMode::Stdio;
        state.config.store(std::sync::Arc::new(config));
    }

    crate::app::run(state).await
}
