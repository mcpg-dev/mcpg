//! `mcpg dev cluster` — a local multi-node cluster in one command.
//!
//! `up` boots one NATS JetStream container (via docker or podman) plus N
//! gateway nodes — re-invocations of this same executable — that coordinate
//! through it, so cross-node behaviour (a session minted on one node served
//! by another) is observable with nothing but curl. `down` stops everything;
//! `status` reports what is alive. Everything the harness writes — the
//! generated config, the state key, pidfiles, logs, per-node audit trails —
//! lives under `<state-dir>/dev-cluster` (`MCPG_STATE_DIR` overrides the
//! root, matching the rest of the CLI).
//!
//! The coordinator cdylib (`dev.mcpg.cluster.nats`) resolves like any other
//! plugin: a local artifact when one is available (`--cluster-plugin`,
//! `MCPG_PLUGIN_DIR`, or the container image's baked path), otherwise the
//! generated config carries the published OCI reference and the first node
//! boot pulls the right per-platform build through the gateway's normal
//! registry resolver.
//!
//! Config layering: one shared `config.yaml` (cluster block, plugins,
//! governance) plus a tiny per-node overlay (bind address, node-tagged demo
//! tools), joined via `MCPG_CONFIG` — the same later-wins file layering the
//! normal boot path uses. Nodes are byte-identical apart from the overlay.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context as _, bail};
use base64::Engine as _;

/// Deterministic container name so repeated `up` runs find and reuse the
/// same broker instead of leaking one container per invocation.
const NATS_CONTAINER: &str = "mcpg-dev-cluster-nats";
/// Pinned image — the same one the cluster e2e suites run against.
const NATS_IMAGE: &str = "nats:2.10-alpine";
/// Env var the generated config names via `state_encryption_key_env`. The
/// key bytes live in `state.key` in the harness dir, never in the config.
const STATE_KEY_ENV: &str = "MCPG_DEV_CLUSTER_STATE_KEY";
const CLUSTER_PLUGIN_ID: &str = "dev.mcpg.cluster.nats";
/// Public per-platform artifact. Tag-less on purpose: the gateway's OCI
/// resolver appends `:protocol-<major>-<os>-<arch>` for the plugin
/// protocol this binary speaks, so the reference never goes stale.
const CLUSTER_PLUGIN_OCI: &str = "ghcr.io/mcpg-dev/plugins/cluster-nats";
/// Baked-plugin layout, kept as a middle resolution step for an image that
/// carries one. Official images do not, so this normally misses and the OCI
/// reference above is what resolves.
const BAKED_PLUGIN_PATH: &str = "/usr/local/lib/mcpg/plugins/dev.mcpg.cluster.nats/plugin.so";

const DEFAULT_NODES: usize = 3;
/// One past the flagship single-gateway default (8787), so a dev cluster
/// coexists with a plain `mcpg` on the same box.
const DEFAULT_BASE_PORT: u16 = 8788;

/// Grace window between SIGTERM and SIGKILL on `down`.
const STOP_GRACE: Duration = Duration::from_secs(10);

const USAGE: &str = "\
mcpg dev cluster — run a local multi-node MCPG cluster (demo + dev harness)

USAGE:
    mcpg dev cluster up [-n <nodes>] [--base-port <port>] [--cluster-plugin <path>]
    mcpg dev cluster down [--purge]
    mcpg dev cluster status

COMMANDS:
    up       Start a NATS JetStream container (docker/podman) and <nodes>
             gateway nodes (default 3) on sequential loopback ports, all
             coordinating through it. Running pieces are reused; dead ones
             are restarted — `up` twice is safe.
    down     Stop the nodes (TERM, then KILL after 10s) and the NATS
             container. Keeps the state dir so a later `up` reuses the
             state key; --purge deletes it.
    status   Report node liveness (pid + /health) and the container state.

OPTIONS (up):
    -n, --nodes <N>          Number of gateway nodes (default 3)
        --base-port <P>      First node port; node i listens on P+i-1
                             (default 8788)
        --cluster-plugin <path>
                             Use a locally built dev.mcpg.cluster.nats
                             cdylib instead of pulling the published OCI
                             artifact (e.g. your build output directory's
                             libmcpg_plugin_cluster_nats.so)

PLUGIN RESOLUTION:
    Clustered mode needs the dev.mcpg.cluster.nats coordinator cdylib.
    The harness looks, in order: --cluster-plugin, $MCPG_PLUGIN_DIR (the
    baked `<id>/plugin.so` layout or a bare libmcpg_plugin_cluster_nats
    artifact), the container image path under /usr/local/lib/mcpg/plugins,
    and finally the published OCI artifact — that last option downloads it
    on the first node boot, so it needs network access to ghcr.io.

STATE:
    <state-dir>/dev-cluster (state dir: $MCPG_STATE_DIR, default ~/.mcpg) —
    generated config, state key, and one directory per node holding its
    pidfile, log, and audit trail.
";

pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(cmd) = args.first() else {
        eprintln!("{USAGE}");
        bail!("`mcpg dev cluster` requires a subcommand (up | down | status)");
    };
    match cmd.as_str() {
        "up" => up(&args[1..]).await,
        "down" => down(&args[1..]).await,
        "status" => status(&args[1..]).await,
        "--help" | "-h" | "help" => {
            eprintln!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("{USAGE}");
            bail!("unknown `mcpg dev cluster` subcommand: {other}");
        }
    }
}

// ---------------------------------------------------------------------------
// State layout + manifest
// ---------------------------------------------------------------------------

/// Root of everything this harness writes.
fn harness_dir() -> PathBuf {
    mcpg_cli_core::paths::default_state_dir().join("dev-cluster")
}

/// What `up` started, persisted so `down` / `status` (and a later `up`
/// with different flags) can find the exact ports and pids in play.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Manifest {
    nodes: Vec<ManifestNode>,
    nats_port: u16,
    /// Human-readable provenance of the coordinator cdylib (path or OCI
    /// reference) for `status` output.
    plugin_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ManifestNode {
    id: String,
    port: u16,
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("cluster.json")
}

fn load_manifest(dir: &Path) -> Option<Manifest> {
    let raw = std::fs::read(manifest_path(dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn save_manifest(dir: &Path, m: &Manifest) -> anyhow::Result<()> {
    let path = manifest_path(dir);
    std::fs::write(&path, serde_json::to_vec_pretty(m)?)
        .with_context(|| format!("write {}", path.display()))
}

fn node_dir(dir: &Path, node_id: &str) -> PathBuf {
    dir.join(node_id)
}

fn pidfile_path(dir: &Path, node_id: &str) -> PathBuf {
    node_dir(dir, node_id).join("gateway.pid")
}

fn logfile_path(dir: &Path, node_id: &str) -> PathBuf {
    node_dir(dir, node_id).join("gateway.log")
}

fn desired_nodes(count: usize, base_port: u16) -> Vec<ManifestNode> {
    (1..=count)
        .map(|i| ManifestNode {
            id: format!("node-{i}"),
            port: base_port + (i as u16) - 1,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Container runtime
// ---------------------------------------------------------------------------

/// Locate a container CLI (docker, then podman) that can actually reach a
/// daemon. Errors carry the install hint — this is the harness's only hard
/// external dependency.
fn require_container_cli() -> anyhow::Result<String> {
    let found = ["docker", "podman"]
        .iter()
        .find_map(|name| crate::cli::locate_binary(name));
    let Some(cli) = found else {
        bail!(
            "`mcpg dev cluster` needs docker (or podman) to run the NATS coordinator \
             container, and neither is on PATH.\n\
             Install docker: https://docs.docker.com/get-docker/ \
             (macOS: `brew install --cask docker`; Debian/Ubuntu: `apt install docker.io`)"
        );
    };
    let ok = Command::new(&cli)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        bail!(
            "found `{cli}` but `{cli} info` failed — is the daemon running? \
             (start Docker Desktop / `systemctl start docker`, then retry)"
        );
    }
    Ok(cli)
}

/// Run a container CLI subcommand, capturing stdout. Non-zero exit becomes
/// an error carrying stderr.
fn container_cmd(cli: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(cli)
        .args(args)
        .output()
        .with_context(|| format!("exec {cli} {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "{cli} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Is the named container present, and if so is it running?
fn container_state(cli: &str, name: &str) -> Option<bool> {
    let out = Command::new(cli)
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim() == "true")
}

/// Host port the container publishes NATS (4222) on.
fn container_nats_port(cli: &str, name: &str) -> anyhow::Result<u16> {
    let out = container_cmd(cli, &["port", name, "4222/tcp"])?;
    // First line looks like `127.0.0.1:49153` (a v6 line may follow).
    let line = out.lines().next().unwrap_or_default().trim();
    let port = line
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .with_context(|| format!("could not parse a host port from `{cli} port` output: {out}"))?;
    Ok(port)
}

/// Ensure the NATS JetStream container is up; returns `(host_port,
/// freshly_created)`. A running container is reused as-is (its published
/// port is stable for its lifetime); a stopped leftover is replaced.
fn ensure_nats(cli: &str) -> anyhow::Result<(u16, bool)> {
    let created = match container_state(cli, NATS_CONTAINER) {
        Some(true) => false,
        Some(false) => {
            // `--rm` containers normally vanish on stop; a daemon crash can
            // still strand one, and a stranded container pins a dead port
            // mapping — replace it.
            let _ = container_cmd(cli, &["rm", "-f", NATS_CONTAINER]);
            run_nats(cli)?;
            true
        }
        None => {
            run_nats(cli)?;
            true
        }
    };
    let port = container_nats_port(cli, NATS_CONTAINER)?;
    wait_for_tcp(port, Duration::from_secs(30)).with_context(|| {
        format!("NATS container never accepted connections on 127.0.0.1:{port}")
    })?;
    Ok((port, created))
}

fn run_nats(cli: &str) -> anyhow::Result<()> {
    // Loopback-only random published port: no clash with a NATS the user
    // already runs, nothing exposed off-box. `-sd /tmp` gives JetStream a
    // writable store dir on every base image variant.
    container_cmd(
        cli,
        &[
            "run",
            "-d",
            "--rm",
            "--name",
            NATS_CONTAINER,
            "-p",
            "127.0.0.1::4222",
            NATS_IMAGE,
            "--jetstream",
            "-sd",
            "/tmp",
        ],
    )
    .map(|_| ())
    .context("starting the NATS container (docker pull may need network on first use)")
}

fn wait_for_tcp(port: u16, deadline: Duration) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    while start.elapsed() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("timed out after {}s", deadline.as_secs())
}

// ---------------------------------------------------------------------------
// State key
// ---------------------------------------------------------------------------

/// Load the cluster state key, minting one on first use. Reusing the key
/// across `down`/`up` cycles keeps coordinator-persisted state decodable;
/// `down --purge` rotates it by deleting the file. URL-safe base64 of 32
/// random bytes — the format `cluster.state_encryption_key_env` expects.
fn load_or_create_state_key(dir: &Path) -> anyhow::Result<String> {
    let path = dir.join("state.key");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_owned();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let key = {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, aead::OsRng};
        // 32 CSPRNG bytes; the cipher type is only borrowed for its
        // correctly sized `generate_key`.
        let bytes = ChaCha20Poly1305::generate_key(&mut OsRng);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    std::fs::write(&path, &key).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Coordinator plugin resolution
// ---------------------------------------------------------------------------

/// Where the generated config points `plugins[].source` for the
/// coordinator cdylib.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PluginSource {
    Path(PathBuf),
    Oci(String),
}

impl PluginSource {
    fn display(&self) -> String {
        match self {
            Self::Path(p) => p.display().to_string(),
            Self::Oci(r) => format!("oci:{r}"),
        }
    }
}

/// Platform artifact names a build drops for the coordinator crate.
fn local_artifact_names() -> [&'static str; 3] {
    [
        "libmcpg_plugin_cluster_nats.so",
        "libmcpg_plugin_cluster_nats.dylib",
        "mcpg_plugin_cluster_nats.dll",
    ]
}

/// Resolve the coordinator cdylib: explicit flag, then `MCPG_PLUGIN_DIR`
/// (baked `<id>/plugin.so` layout or a bare build artifact), then the
/// container image's baked path, and finally the published OCI reference.
fn resolve_cluster_plugin(explicit: Option<&Path>) -> anyhow::Result<PluginSource> {
    if let Some(p) = explicit {
        let abs = p
            .canonicalize()
            .with_context(|| format!("--cluster-plugin {}: not found", p.display()))?;
        return Ok(PluginSource::Path(abs));
    }
    if let Some(dir) = std::env::var_os("MCPG_PLUGIN_DIR").filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        let mut candidates = vec![dir.join(CLUSTER_PLUGIN_ID).join("plugin.so")];
        candidates.extend(local_artifact_names().iter().map(|n| dir.join(n)));
        for c in candidates {
            if c.is_file() {
                return Ok(PluginSource::Path(c.canonicalize().unwrap_or(c)));
            }
        }
    }
    let baked = Path::new(BAKED_PLUGIN_PATH);
    if baked.is_file() {
        return Ok(PluginSource::Path(baked.to_path_buf()));
    }
    Ok(PluginSource::Oci(CLUSTER_PLUGIN_OCI.to_owned()))
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Shared config every node loads first. Node-specific bits (bind address,
/// node-tagged demo tools) live in the per-node overlay so this file is
/// byte-identical across the fleet — the property that makes it a clustering
/// demo rather than N separate gateways.
fn render_shared_config(nats_port: u16, plugin: &PluginSource) -> String {
    let source_lines = match plugin {
        PluginSource::Path(p) => format!("    source:\n      path: \"{}\"\n", p.display()),
        PluginSource::Oci(r) => format!(
            "    source:\n      # Tag-less on purpose: the gateway resolves the right\n      # per-platform build for the plugin protocol it speaks.\n      oci: \"{r}\"\n"
        ),
    };
    // Locally built artifacts carry no release signature; published OCI
    // artifacts do, so the default (warn) policy stays for those.
    let signature_policy = match plugin {
        PluginSource::Path(_) => {
            "  plugin_registry:\n    # Locally built cdylibs are unsigned.\n    default_signature_policy: disabled\n"
        }
        PluginSource::Oci(_) => "",
    };
    format!(
        r#"# Generated by `mcpg dev cluster up` — regenerated on every `up`, do not edit.
#
# Shared by every node of the local dev cluster. Each node layers a small
# overlay on top (MCPG_CONFIG="config.yaml:<node>/overlay.yaml") carrying
# its bind address and node-tagged demo tools; per-node identity for the
# coordinator comes from the MCPG_NODE_ID env var below.

gateway:
{signature_policy}  server:
    # Overridden per node by the overlay; kept valid so the file also
    # boots standalone.
    bind_address: "127.0.0.1:{DEFAULT_BASE_PORT}"
    mcp_path: "/mcp"
    health_path: "/health"
    allowed_origins: []

cluster:
  kind: nats
  # Plaintext NATS on loopback — acceptable for a throwaway local broker
  # only. Real deployments use tls:// servers and drop both opt-outs (see
  # the clustering docs).
  allow_insecure_transport: true
  state_encryption_key_env: "{STATE_KEY_ENV}"
  servers:
    - "nats://127.0.0.1:{nats_port}"
  tls:
    require_tls: false
  node:
    id: "${{env.MCPG_NODE_ID}}"
    heartbeat_interval_sec: 1
    peer_expiry_sec: 3
  jetstream:
    replicas: 1
    storage: memory
    state_bucket: "mcpg-dev-cluster"

# Cluster coordination is entitlement-gated; this harness runs under the
# license's non-production grant. Never copy this line into production.
license:
  non_production_use: true

# Anonymous callers are fine on loopback; the demo tools opt into the
# same floor explicitly.
governance:
  policy:
    tool_access:
      default_minimum_trust: unauthenticated

plugins:
  - id: {CLUSTER_PLUGIN_ID}
    class: cluster
{source_lines}    granted_capabilities:
      - network_outbound

observability:
  logs:
    level: info
    sinks:
      - kind: stderr
        config:
          format: json
"#
    )
}

/// Per-node overlay: the bind address plus the demo tools. The tools live
/// here (not in the shared file) because a config layer replaces list
/// values wholesale — and it lets `cluster.whoami` bake the node id into
/// its reply, which is what makes cross-node routing visible in a curl.
fn render_node_overlay(node: &ManifestNode) -> String {
    let ManifestNode { id, port } = node;
    format!(
        r#"# Generated by `mcpg dev cluster up` — overlay for {id}.
gateway:
  server:
    bind_address: "127.0.0.1:{port}"

mcp:
  capabilities:
    tools:
      - name: cluster.whoami
        description: Report which cluster node served this call.
        governance:
          minimum_trust: unauthenticated
        backend:
          kind: pipeline
          steps:
            - kind: transform
              id: reply
              expression: |
                "served by {id}"
      - name: cluster.ask
        description: Elicit an answer from the caller, then echo it back —
          pause the call on one node and resume it on another.
        governance:
          minimum_trust: unauthenticated
        backend:
          kind: pipeline
          pipeline_timeout_ms: 300000
          steps:
            - kind: elicitation
              id: ask
              message: "The paused pipeline needs an answer to continue."
              requested_schema:
                type: object
                properties:
                  answer:
                    type: string
                required: [answer]
              timeout_ms: 120000
            - kind: transform
              id: reply
              expression: |
                "{id} echoes: " + string(steps.ask.output.content.answer)
"#
    )
}

// ---------------------------------------------------------------------------
// Node process management (unix)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    // Signal 0 probes existence without delivering anything.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn send_signal(pid: i32, sig: i32) {
    unsafe {
        libc::kill(pid, sig);
    }
}

fn read_pidfile(dir: &Path, node_id: &str) -> Option<i32> {
    std::fs::read_to_string(pidfile_path(dir, node_id))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(unix)]
/// Spawn one gateway node. The returned [`std::process::Child`] must be
/// held for the life of the health wait: the node stays this process's
/// child until `up` exits, so exit detection there needs `try_wait` — a
/// dead child is a zombie that a signal-0 probe still reports alive.
fn spawn_node(
    dir: &Path,
    shared_config: &Path,
    key: &str,
    node: &ManifestNode,
) -> anyhow::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;

    let ndir = node_dir(dir, &node.id);
    mcpg_cli_core::paths::ensure_dir(&ndir)?;
    let overlay = ndir.join("overlay.yaml");
    std::fs::write(&overlay, render_node_overlay(node))
        .with_context(|| format!("write {}", overlay.display()))?;

    let log = std::fs::File::create(logfile_path(dir, &node.id))?;
    let exe = std::env::current_exe().context("resolve the mcpg executable path")?;
    let config_chain = std::env::join_paths([shared_config, overlay.as_path()])
        .context("join MCPG_CONFIG paths")?;

    let child = Command::new(exe)
        // cwd is the node dir so per-node relative outputs (the default
        // audit sink writes ./mcpg-audit.log) never interleave across nodes.
        .current_dir(&ndir)
        .env("MCPG_CONFIG", config_chain)
        .env("MCPG_NODE_ID", &node.id)
        .env(STATE_KEY_ENV, key)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        // Own process group: a Ctrl+C aimed at the `up` invocation must not
        // take the freshly started fleet down with it.
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawn gateway node {}", node.id))?;

    let pid = child.id() as i32;
    std::fs::write(pidfile_path(dir, &node.id), pid.to_string())?;
    Ok(child)
}

/// Stop one node: TERM, bounded wait, then KILL. Removes the pidfile.
/// Returns whether a live process was actually signalled.
#[cfg(unix)]
fn stop_node(dir: &Path, node_id: &str) -> bool {
    let Some(pid) = read_pidfile(dir, node_id) else {
        return false;
    };
    let was_alive = pid_alive(pid);
    if was_alive {
        send_signal(pid, libc::SIGTERM);
        let start = std::time::Instant::now();
        while start.elapsed() < STOP_GRACE {
            if !pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if pid_alive(pid) {
            send_signal(pid, libc::SIGKILL);
        }
    }
    let _ = std::fs::remove_file(pidfile_path(dir, node_id));
    was_alive
}

/// Fatal boot-log markers. Scanned while waiting for /health so a
/// mis-configured node fails the `up` with its log tail instead of a
/// silent timeout.
const FATAL_LOG_MARKERS: &[&str] = &[
    "panicked",
    "ABI version mismatch",
    "refuses to start",
    "reachability probe failed",
    "failed to load application config",
    // abi_stable layout-check rejections (a cdylib built from a different
    // tree or toolchain than this binary).
    "exports no entities",
    "mismatched package",
    "incompatible package versions",
];

fn log_has_fatal(dir: &Path, node_id: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(logfile_path(dir, node_id)) else {
        return false;
    };
    FATAL_LOG_MARKERS.iter().any(|m| text.contains(m))
}

fn print_log_tail(dir: &Path, node_id: &str) {
    let path = logfile_path(dir, node_id);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = text.lines().collect();
        let tail = &lines[lines.len().saturating_sub(20)..];
        eprintln!("--- {} (tail) ---", path.display());
        for l in tail {
            eprintln!("{l}");
        }
    }
}

async fn probe_health(client: &reqwest::Client, port: u16) -> bool {
    matches!(
        client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

// ---------------------------------------------------------------------------
// up
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
struct UpArgs {
    nodes: Option<usize>,
    base_port: Option<u16>,
    cluster_plugin: Option<PathBuf>,
}

fn parse_up_args(raw: &[String]) -> anyhow::Result<UpArgs> {
    let mut args = UpArgs::default();
    let mut iter = raw.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-n" | "--nodes" => {
                let v = iter.next().context("-n/--nodes requires a value")?;
                let n: usize = v
                    .parse()
                    .with_context(|| format!("invalid node count: {v}"))?;
                if !(1..=16).contains(&n) {
                    bail!("node count must be 1..=16 (got {n})");
                }
                args.nodes = Some(n);
            }
            "--base-port" => {
                let v = iter.next().context("--base-port requires a value")?;
                args.base_port = Some(v.parse().with_context(|| format!("invalid port: {v}"))?);
            }
            "--cluster-plugin" => {
                let v = iter.next().context("--cluster-plugin requires a path")?;
                args.cluster_plugin = Some(PathBuf::from(v));
            }
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown `mcpg dev cluster up` flag: {other}"),
        }
    }
    Ok(args)
}

#[cfg(not(unix))]
async fn up(_raw: &[String]) -> anyhow::Result<()> {
    bail!(
        "`mcpg dev cluster` manages node processes with unix signals and is not available on this platform yet"
    );
}

#[cfg(unix)]
async fn up(raw: &[String]) -> anyhow::Result<()> {
    let args = parse_up_args(raw)?;
    let count = args.nodes.unwrap_or(DEFAULT_NODES);
    let base_port = args.base_port.unwrap_or(DEFAULT_BASE_PORT);

    let dir = harness_dir();
    mcpg_cli_core::paths::ensure_dir(&dir)?;

    let cli = require_container_cli()?;
    let (nats_port, nats_created) = ensure_nats(&cli)?;
    let key = load_or_create_state_key(&dir)?;
    let plugin = resolve_cluster_plugin(args.cluster_plugin.as_deref())?;
    if let PluginSource::Oci(r) = &plugin {
        println!(
            "coordinator plugin: {r} — the first node boot downloads the per-platform \
             build from the registry (subsequent boots use the local cache)"
        );
    }

    let nodes = desired_nodes(count, base_port);

    // A surviving fleet member is only reusable when the world it was booted
    // into still holds: same port, the same broker (a recreated NATS
    // container publishes a fresh port and holds none of the old state), and
    // the same coordinator artifact.
    let prev = load_manifest(&dir);
    let world_changed = nats_created
        || prev
            .as_ref()
            .is_some_and(|p| p.plugin_source != plugin.display());
    if let Some(prev) = &prev {
        for stale in prev
            .nodes
            .iter()
            .filter(|p| world_changed || !nodes.contains(p))
        {
            if stop_node(&dir, &stale.id) {
                println!("stopped {} (superseded)", stale.id);
            }
        }
    }

    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, render_shared_config(nats_port, &plugin))
        .with_context(|| format!("write {}", config_path.display()))?;
    save_manifest(
        &dir,
        &Manifest {
            nodes: nodes.clone(),
            nats_port,
            plugin_source: plugin.display(),
        },
    )?;

    // Start what is missing; leave healthy nodes alone.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut started = Vec::new();
    let mut reused = Vec::new();
    // Children spawned by THIS invocation, keyed by node id: their exit is
    // detected via `try_wait` during the health wait (see `spawn_node`).
    let mut children: std::collections::HashMap<String, std::process::Child> =
        std::collections::HashMap::new();
    for node in &nodes {
        let running = match read_pidfile(&dir, &node.id) {
            Some(pid) => pid_alive(pid) && probe_health(&client, node.port).await,
            None => false,
        };
        if running && !world_changed {
            reused.push(node.id.clone());
            continue;
        }
        // A pid that is alive but unhealthy (or bound to the wrong world)
        // is torn down before its replacement starts on the same port.
        stop_node(&dir, &node.id);
        children.insert(node.id.clone(), spawn_node(&dir, &config_path, &key, node)?);
        started.push(node.id.clone());
    }

    // Wait for every node's /health. An OCI-sourced coordinator may be
    // downloading on first boot, so give that path a longer deadline.
    let deadline = match &plugin {
        PluginSource::Oci(_) => Duration::from_secs(180),
        PluginSource::Path(_) => Duration::from_secs(60),
    };
    // A pulled artifact only loads into a binary from the same release —
    // the plugin ABI gate and layout check are exact — so a dev/source
    // build failing here almost always needs a locally built cdylib.
    let boot_hint = match &plugin {
        PluginSource::Oci(_) => {
            "\n(If this mcpg is a source build, the published artifact will not match its \
             plugin ABI — pass --cluster-plugin <locally built \
             libmcpg_plugin_cluster_nats cdylib> instead.)"
        }
        PluginSource::Path(_) => "",
    };
    let start = std::time::Instant::now();
    let mut pending: Vec<&ManifestNode> = nodes.iter().collect();
    while !pending.is_empty() {
        let mut still = Vec::new();
        for node in pending {
            if probe_health(&client, node.port).await {
                continue;
            }
            if log_has_fatal(&dir, &node.id) {
                print_log_tail(&dir, &node.id);
                bail!(
                    "{} failed to boot — see {}{boot_hint}",
                    node.id,
                    logfile_path(&dir, &node.id).display()
                );
            }
            // Exit detection: our own children via `try_wait` (a dead child
            // is a zombie until reaped, so signal-0 would lie), reused nodes
            // from an earlier invocation via signal-0.
            let exited = match children.get_mut(&node.id) {
                Some(child) => child.try_wait().ok().flatten().is_some(),
                None => read_pidfile(&dir, &node.id).is_some_and(|pid| !pid_alive(pid)),
            };
            if exited {
                print_log_tail(&dir, &node.id);
                bail!(
                    "{} exited before becoming healthy — see {}{boot_hint}",
                    node.id,
                    logfile_path(&dir, &node.id).display()
                );
            }
            still.push(node);
        }
        pending = still;
        if pending.is_empty() {
            break;
        }
        if start.elapsed() > deadline {
            for node in &pending {
                print_log_tail(&dir, &node.id);
            }
            bail!(
                "{} node(s) not healthy after {}s",
                pending.len(),
                deadline.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    print_up_summary(&dir, &nodes, nats_port, &plugin, &started, &reused);
    Ok(())
}

fn print_up_summary(
    dir: &Path,
    nodes: &[ManifestNode],
    nats_port: u16,
    plugin: &PluginSource,
    started: &[String],
    reused: &[String],
) {
    // The examples span three members when they exist and degrade to
    // whatever the fleet has (a 1-node "cluster" still demos correctly,
    // just without the cross-node punchline).
    let first = nodes.first().map(|n| n.port).unwrap_or(DEFAULT_BASE_PORT);
    let second = nodes.get(1).map(|n| n.port).unwrap_or(first);
    let second_id = nodes
        .get(1)
        .or(nodes.first())
        .map(|n| n.id.as_str())
        .unwrap_or("node-1");
    let last = nodes.last().map(|n| n.port).unwrap_or(first);
    let last_id = nodes.last().map(|n| n.id.as_str()).unwrap_or("node-1");

    println!();
    if started.is_empty() {
        println!(
            "mcpg dev cluster: already running — {} node(s) healthy",
            nodes.len()
        );
    } else if reused.is_empty() {
        println!("mcpg dev cluster: {} node(s) up", nodes.len());
    } else {
        println!(
            "mcpg dev cluster: {} node(s) up ({} started, {} already running)",
            nodes.len(),
            started.len(),
            reused.len()
        );
    }
    println!();
    for node in nodes {
        let pid = read_pidfile(dir, &node.id)
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".into());
        println!(
            "  {}   http://127.0.0.1:{}   (pid {})",
            node.id, node.port, pid
        );
    }
    println!();
    println!("  coordinator : nats://127.0.0.1:{nats_port} (container {NATS_CONTAINER})");
    println!("  plugin      : {}", plugin.display());
    println!("  state dir   : {}", dir.display());
    println!("  logs        : {}/node-*/gateway.log", dir.display());
    println!();
    println!("Feel the cluster — the nodes are ONE gateway:");
    println!();
    println!("  # 1) Mint an MCP session on node-1 and complete the handshake via {second_id} …");
    println!(
        "  SID=$(curl -siX POST http://127.0.0.1:{first}/mcp \\\n    \
         -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \\\n    \
         -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"curl\",\"version\":\"0\"}}}}}}' \\\n    \
         | tr -d '\\r' | awk 'tolower($1)==\"mcp-session-id:\"{{print $2}}')"
    );
    println!(
        "  curl -so /dev/null -X POST http://127.0.0.1:{second}/mcp \\\n    \
         -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \\\n    \
         -H \"mcp-session-id: $SID\" -d '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}'"
    );
    println!();
    println!("  # 2) … then call a tool on {last_id}: the session lives in NATS, not in node-1.");
    println!(
        "  curl -sX POST http://127.0.0.1:{last}/mcp \\\n    \
         -H 'content-type: application/json' -H 'accept: application/json' \\\n    \
         -H \"mcp-session-id: $SID\" \\\n    \
         -d '{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"cluster.whoami\",\"arguments\":{{}}}}}}'"
    );
    println!();
    println!("  # 3) Same session against {second_id} — a different member answers.");
    println!(
        "  curl -sX POST http://127.0.0.1:{second}/mcp \\\n    \
         -H 'content-type: application/json' -H 'accept: application/json' \\\n    \
         -H \"mcp-session-id: $SID\" \\\n    \
         -d '{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"cluster.whoami\",\"arguments\":{{}}}}}}'"
    );
    println!();
    println!(
        "  (For a paused tool call resumed on a different node, call `cluster.ask` — \n   \
         it suspends with an elicitation whose requestState any node can resume.)"
    );
    println!();
    println!("Stop it:  mcpg dev cluster down   (add --purge to also delete the state dir)");
}

// ---------------------------------------------------------------------------
// down
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
async fn down(_raw: &[String]) -> anyhow::Result<()> {
    bail!(
        "`mcpg dev cluster` manages node processes with unix signals and is not available on this platform yet"
    );
}

#[cfg(unix)]
async fn down(raw: &[String]) -> anyhow::Result<()> {
    let mut purge = false;
    for arg in raw {
        match arg.as_str() {
            "--purge" => purge = true,
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => bail!("unknown `mcpg dev cluster down` flag: {other}"),
        }
    }

    let dir = harness_dir();
    let mut stopped_any = false;

    if let Some(manifest) = load_manifest(&dir) {
        for node in &manifest.nodes {
            if stop_node(&dir, &node.id) {
                println!("stopped {}", node.id);
                stopped_any = true;
            }
        }
    }

    // The container is stopped even with no manifest — a purged state dir
    // must not strand the broker.
    if let Some(cli) = ["docker", "podman"]
        .iter()
        .find_map(|name| crate::cli::locate_binary(name))
        && container_state(&cli, NATS_CONTAINER).is_some()
    {
        // `rm -f` covers both the running (`--rm` reaps on stop) and the
        // stranded-stopped case in one call.
        let _ = container_cmd(&cli, &["rm", "-f", NATS_CONTAINER]);
        println!("removed container {NATS_CONTAINER}");
        stopped_any = true;
    }

    if purge {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
            println!("purged {}", dir.display());
        } else {
            println!("mcpg dev cluster: nothing running, nothing to purge");
        }
    } else if !stopped_any {
        println!("mcpg dev cluster: nothing running");
    } else {
        println!(
            "state kept at {} (reused by the next `up`; --purge deletes it)",
            dir.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
async fn status(_raw: &[String]) -> anyhow::Result<()> {
    bail!(
        "`mcpg dev cluster` manages node processes with unix signals and is not available on this platform yet"
    );
}

#[cfg(unix)]
async fn status(raw: &[String]) -> anyhow::Result<()> {
    if let Some(arg) = raw.first() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => bail!("unknown `mcpg dev cluster status` flag: {other}"),
        }
    }

    let dir = harness_dir();
    let manifest = load_manifest(&dir);

    let container = ["docker", "podman"]
        .iter()
        .find_map(|name| crate::cli::locate_binary(name))
        .and_then(|cli| {
            container_state(&cli, NATS_CONTAINER).map(|running| {
                let port = running
                    .then(|| container_nats_port(&cli, NATS_CONTAINER).ok())
                    .flatten();
                (running, port)
            })
        });
    match container {
        Some((true, Some(port))) => {
            println!("coordinator : nats — container {NATS_CONTAINER} running on 127.0.0.1:{port}")
        }
        Some((true, None)) => {
            println!("coordinator : nats — container {NATS_CONTAINER} running (port unknown)")
        }
        Some((false, _)) => {
            println!("coordinator : container {NATS_CONTAINER} present but stopped")
        }
        None => println!("coordinator : container {NATS_CONTAINER} not found"),
    }

    let Some(manifest) = manifest else {
        println!("nodes       : none (no state at {})", dir.display());
        println!("hint        : mcpg dev cluster up -n 3");
        return Ok(());
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut alive = 0usize;
    for node in &manifest.nodes {
        let line = match read_pidfile(&dir, &node.id) {
            Some(pid) if pid_alive(pid) => {
                if probe_health(&client, node.port).await {
                    alive += 1;
                    format!(
                        "running (pid {pid}) — http://127.0.0.1:{}/health ok",
                        node.port
                    )
                } else {
                    format!("pid {pid} alive but /health on {} not answering", node.port)
                }
            }
            Some(pid) => format!("dead (stale pidfile {pid}) — heal with `mcpg dev cluster up`"),
            None => "not started".to_owned(),
        };
        println!("{:<11} : {line}", node.id);
    }
    println!("plugin      : {}", manifest.plugin_source);
    println!("state dir   : {}", dir.display());
    if alive < manifest.nodes.len() {
        println!("hint        : `mcpg dev cluster up` restarts dead nodes");
    }
    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn up_args_defaults_and_flags() {
        assert_eq!(parse_up_args(&[]).unwrap(), UpArgs::default());
        let a = parse_up_args(&s(&["-n", "5", "--base-port", "9100"])).unwrap();
        assert_eq!(a.nodes, Some(5));
        assert_eq!(a.base_port, Some(9100));
        let a = parse_up_args(&s(&["--cluster-plugin", "/tmp/x.so"])).unwrap();
        assert_eq!(a.cluster_plugin.as_deref(), Some(Path::new("/tmp/x.so")));
    }

    #[test]
    fn up_args_rejects_bad_input() {
        assert!(parse_up_args(&s(&["-n"])).is_err());
        assert!(parse_up_args(&s(&["-n", "0"])).is_err());
        assert!(parse_up_args(&s(&["-n", "17"])).is_err());
        assert!(parse_up_args(&s(&["--base-port", "notaport"])).is_err());
        assert!(parse_up_args(&s(&["--bogus"])).is_err());
    }

    #[test]
    fn desired_nodes_are_sequential_from_base() {
        let nodes = desired_nodes(3, 8788);
        assert_eq!(
            nodes,
            vec![
                ManifestNode {
                    id: "node-1".into(),
                    port: 8788
                },
                ManifestNode {
                    id: "node-2".into(),
                    port: 8789
                },
                ManifestNode {
                    id: "node-3".into(),
                    port: 8790
                },
            ]
        );
    }

    #[test]
    fn shared_config_parses_and_carries_the_cluster_block() {
        let yaml = render_shared_config(45999, &PluginSource::Oci(CLUSTER_PLUGIN_OCI.to_owned()));
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("generated YAML parses");
        assert_eq!(v["cluster"]["kind"].as_str(), Some("nats"));
        assert_eq!(
            v["cluster"]["servers"][0].as_str(),
            Some("nats://127.0.0.1:45999")
        );
        assert_eq!(
            v["cluster"]["state_encryption_key_env"].as_str(),
            Some(STATE_KEY_ENV)
        );
        assert_eq!(v["plugins"][0]["id"].as_str(), Some(CLUSTER_PLUGIN_ID));
        assert_eq!(
            v["plugins"][0]["source"]["oci"].as_str(),
            Some(CLUSTER_PLUGIN_OCI)
        );
        assert_eq!(v["license"]["non_production_use"].as_bool(), Some(true));
        // The per-node env reference survives YAML parsing verbatim; each
        // node resolves it at its own config load.
        assert_eq!(
            v["cluster"]["node"]["id"].as_str(),
            Some("${env.MCPG_NODE_ID}")
        );
    }

    #[test]
    fn path_sourced_config_disables_the_signature_gate() {
        let yaml = render_shared_config(4222, &PluginSource::Path(PathBuf::from("/tmp/lib.so")));
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            v["plugins"][0]["source"]["path"].as_str(),
            Some("/tmp/lib.so")
        );
        assert_eq!(
            v["gateway"]["plugin_registry"]["default_signature_policy"].as_str(),
            Some("disabled")
        );
        // The OCI-sourced variant keeps the default (published artifacts
        // are signed).
        let yaml = render_shared_config(4222, &PluginSource::Oci("x/y".into()));
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(v["gateway"]["plugin_registry"].is_null());
    }

    #[test]
    fn node_overlay_bakes_bind_address_and_node_id() {
        let node = ManifestNode {
            id: "node-2".into(),
            port: 8789,
        };
        let yaml = render_node_overlay(&node);
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("overlay YAML parses");
        assert_eq!(
            v["gateway"]["server"]["bind_address"].as_str(),
            Some("127.0.0.1:8789")
        );
        let tools = v["mcp"]["capabilities"]["tools"].as_sequence().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(
            tools[0]["backend"]["steps"][0]["expression"]
                .as_str()
                .unwrap()
                .contains("node-2")
        );
        // The elicitation step suspends in-runtime — no backend plugin —
        // and its transform folds the answer under the owning node's id.
        assert_eq!(
            tools[1]["backend"]["steps"][0]["kind"].as_str(),
            Some("elicitation")
        );
        assert!(
            tools[1]["backend"]["steps"][1]["expression"]
                .as_str()
                .unwrap()
                .contains("node-2 echoes:")
        );
    }

    #[test]
    fn manifest_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let m = Manifest {
            nodes: desired_nodes(2, 9000),
            nats_port: 41234,
            plugin_source: "oci:example/cluster-nats".into(),
        };
        save_manifest(dir.path(), &m).unwrap();
        let back = load_manifest(dir.path()).unwrap();
        assert_eq!(back.nodes, m.nodes);
        assert_eq!(back.nats_port, 41234);
    }

    #[test]
    fn state_key_is_stable_and_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_state_key(dir.path()).unwrap();
        let k2 = load_or_create_state_key(dir.path()).unwrap();
        assert_eq!(k1, k2, "the key survives for the life of the state dir");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&k1)
            .unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn plugin_resolution_prefers_explicit_then_plugin_dir_then_oci() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("libmcpg_plugin_cluster_nats.so");
        std::fs::write(&lib, b"not a real cdylib").unwrap();

        // Explicit flag wins outright.
        let got = resolve_cluster_plugin(Some(&lib)).unwrap();
        assert_eq!(got, PluginSource::Path(lib.canonicalize().unwrap()));

        // A missing explicit path is an error, not a silent fallback.
        assert!(resolve_cluster_plugin(Some(Path::new("/nonexistent/x.so"))).is_err());

        // No local artifact anywhere → the published OCI reference.
        // (MCPG_PLUGIN_DIR is process-global state; the probe order under it
        // is covered by the live harness run rather than an env-mutating test.)
        if std::env::var_os("MCPG_PLUGIN_DIR").is_none() && !Path::new(BAKED_PLUGIN_PATH).exists() {
            let got = resolve_cluster_plugin(None).unwrap();
            assert_eq!(got, PluginSource::Oci(CLUSTER_PLUGIN_OCI.to_owned()));
        }
    }
}
