//! MCPG gateway entry point.
//!
//! Parses CLI arguments, loads configuration from YAML / environment,
//! and delegates to the `app` module for bootstrap and transport selection.

use std::path::PathBuf;

use anyhow::Context as _;

// Fast allocator on glibc-linux (see apps/gateway/Cargo.toml). Only wired for
// the glibc-linux target; every other target keeps the system allocator.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the process-level rustls CryptoProvider before any TLS client
    // can be built. The dependency graph compiles in both providers (aws_lc_rs
    // directly, ring transitively via tonic's tls feature), so rustls cannot
    // auto-select one — the cp-attach agent builds a TLS gRPC client to a
    // `https://` control plane and would otherwise panic. Idempotent + Once-
    // guarded; pins the whole process to aws_lc_rs, matching the rest of the
    // workspace binaries.
    mcpg::transports::tls::install_default_crypto_provider();

    let args: Vec<String> = std::env::args().collect();

    // `--version` / `-V` must print and exit BEFORE any boot work: without
    // this the flag fell through to the normal boot path and started a full
    // gateway (plugins registered, port bound, blocked on signals) — hanging
    // any script that shells out for a version string.
    if args.iter().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("mcpg {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // CLI extension dispatch: `mcpg plugin <subcommand> [args...]`
    // Delegates to `mcpg-plugin <subcommand> [args...]` if found on PATH,
    // passing through MCPG_CONFIG and other environment variables.
    if args.len() >= 2 && args[1] == "plugin" {
        return mcpg::cli::dispatch_plugin_command(&args[2..]);
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
        let _guard = mcpg::cli::prepare_dev_mode(&args[2..])?;
        // Fall through into the normal boot path — `prepare_dev_mode`
        // has populated `MCPG_CONFIG` (or layered onto it) so the
        // generated dev-config materialises like any other YAML.
        // Drop happens at end-of-main; tempfiles outlive the run.
        let config_paths: Vec<PathBuf> = std::env::var_os("MCPG_CONFIG")
            .map(|v| std::env::split_paths(&v).collect())
            .unwrap_or_default();
        let state = mcpg::app::build(config_paths).await?;
        if mcpg::cli::stdio_requested(&args) {
            let mut config = (**state.config.load()).clone();
            config.gateway.server.transport = mcpg::config::TransportMode::Stdio;
            state.config.store(std::sync::Arc::new(config));
        }
        return mcpg::app::run(state).await;
    }

    // Top-level help: list the subcommand groups + the gateway-boot default.
    if args.len() >= 2 && matches!(args[1].as_str(), "help" | "--help" | "-h") {
        mcpg::cli::print_top_help();
        return Ok(());
    }

    // `mcpg status` — in-process box report (gateway, agent pairing, local
    // control plane). Checked before the sibling dispatch below, which would
    // otherwise try to exec a nonexistent `mcpg-status`.
    if args.len() >= 2 && args[1] == "status" {
        return mcpg::compose::box_status().await;
    }

    // Subcommand extension dispatch (kubectl-style): a bare-word first arg is a
    // toolchain subcommand delegated to a sibling `mcpg-*` binary, not a gateway
    // flag. `mcpg config <sub>` → `mcpg-config <sub>`; `mcpg cp …` → `mcpg-cp …`
    // (and any `mcpg <x>` → `mcpg-<x>`). Gateway boot takes no positional
    // argument — config comes from `MCPG_CONFIG`, the rest are `--flags` — so
    // this never shadows it. `plugin`, `dev`, and `status` are handled above.
    if args.len() >= 2 && mcpg::cli::is_subcommand_word(&args[1]) {
        return mcpg::cli::dispatch_subcommand(&args[1], &args[2..]);
    }

    // Composition flags (CLI-REORGANIZATION.md §4.2): `--enroll <URL>`
    // (sticky attach), `--no-cp` (one-off detach), `--control-plane`/`--cp`
    // (supervised CP sidecar). Conflicts error before anything boots.
    #[allow(unused_mut)]
    let mut comp = mcpg::compose::parse(&args[1..])?;

    // Held for the life of the process: dropping it kills the control plane
    // (`kill_on_drop`), so no exit path can leave a server behind.
    let mut _cp_sidecar = None;
    if comp.embed {
        // Start the CP first; it hands back the loopback attach coordinates
        // the agent enrolls with.
        let sidecar = mcpg::compose::boot_sidecar_cp(&comp.cp_args).await?;
        comp.enroll = Some(sidecar.enrollment_url.clone());
        comp.cp_grpc = Some(sidecar.grpc_url.clone());
        _cp_sidecar = Some(sidecar);
    }

    // Config comes from two ordered inputs, both later-wins overlays:
    //   1. `MCPG_CONFIG` — a single path or a path-separator-joined list of
    //      FILES (`base.yaml:prod.yaml` on Unix, `;`-joined on Windows).
    //   2. `--config <source>` flags (repeatable), applied AFTER the env
    //      files. Each source is a local path, a `file://` path, an
    //      `https://` URL fetched now, or inline `base64:`/`data:` YAML — so
    //      URLs and inline blobs (which can't survive the `:`-split in
    //      `MCPG_CONFIG`) get a clean home here.
    // `MCPG_*` env vars are applied last, over everything.
    let mut config_sources: Vec<mcpg::config::ConfigSource> = std::env::var_os("MCPG_CONFIG")
        .map(|v| {
            std::env::split_paths(&v)
                .map(mcpg::config::ConfigSource::File)
                .collect()
        })
        .unwrap_or_default();
    for spec in &comp.config {
        config_sources.push(
            mcpg::config::source::resolve(spec)
                .await
                .with_context(|| format!("--config {spec}"))?,
        );
    }
    // Load the config here (rather than via `app::build`) so the
    // composition flags can fold their control-plane attachment in before
    // the runtime is built.
    let mut config = mcpg::config::AppConfig::load_sources(&config_sources)?;
    // Anchor relative `schemas[].file` refs against the last FILE layer's
    // directory (inline/remote layers have no directory to anchor against).
    let config_dir = config_sources.iter().rev().find_map(|s| match s {
        mcpg::config::ConfigSource::File(p) => p.parent(),
        mcpg::config::ConfigSource::Inline { .. } => None,
    });
    config.resolve_schema_refs(config_dir).await?;
    mcpg::compose::apply(&mut config, &comp)?;

    // Held for the life of the process, like the CP sidecar: dropping it
    // kills the inspector. Boots after config load — the auto-wired
    // target needs the gateway's actual bind + mcp_path — and before
    // the runtime, so the minted identity is installed when the
    // listener opens.
    let mut _inspector_sidecar = None;
    if comp.inspector || config.gateway.inspector.enabled {
        _inspector_sidecar =
            Some(mcpg::compose::boot_sidecar_inspector(&config, &comp.inspector_args).await?);
    }

    let state = mcpg::app::build_from_sources(config, config_sources).await?;

    // --stdio flag overrides transport mode
    if mcpg::cli::stdio_requested(&args) {
        let mut config = (**state.config.load()).clone();
        config.gateway.server.transport = mcpg::config::TransportMode::Stdio;
        state.config.store(std::sync::Arc::new(config));
    }

    mcpg::app::run(state).await
}
