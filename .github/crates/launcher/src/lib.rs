//! Launcher for the mcpg CLI suite.
//!
//! Each binary of this crate runs the release binary of the same name. On
//! first use it downloads the suite archive for this platform from the
//! mcpg release, checks it against the SHA-256 sum recorded in
//! `checksums.rs` when this crate was published, and unpacks it into a
//! cache directory. Later runs start the cached binary at once.
//!
//! `MCPG_SUITE_DIR` names the cache directory; `MCPG_SUITE_URL` replaces
//! the download base (a mirror for an air-gapped network).

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use sha2::{Digest, Sha256};

mod checksums;

const NAME: &str = "model-context-protocol-gateway";
const RELEASES: &str = "https://github.com/mcpg-dev/mcpg/releases/download";
// The largest archive is about 70 MB; the cap only stops a runaway body.
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// Run the suite binary `name` with this process's arguments.
pub fn run(name: &str) -> ExitCode {
    match launch(name) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{name}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The release target whose binaries run here. A Windows build of this
/// crate may use the MSVC toolchain; the GNU-built release binary runs there
/// all the same.
fn release_target() -> Option<&'static str> {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl"
    )) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "musl"
    )) {
        Some("aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("x86_64-pc-windows-gnu")
    } else {
        None
    }
}

fn cache_root() -> io::Result<PathBuf> {
    if let Some(dir) = env::var_os("MCPG_SUITE_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = || {
        env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library").join("Caches"))
    } else {
        env::var_os("XDG_CACHE_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".cache")))
    };
    base.map(|b| b.join(NAME))
        .ok_or_else(|| io::Error::other("no cache directory found; set MCPG_SUITE_DIR"))
}

fn launch(name: &str) -> io::Result<ExitCode> {
    let target = release_target().ok_or_else(|| {
        io::Error::other(format!(
            "no prebuilt binaries for this platform ({}/{}); supported: {}",
            env::consts::OS,
            env::consts::ARCH,
            checksums::ARCHIVES
                .iter()
                .map(|(t, _)| *t)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let sha256 = checksums::ARCHIVES
        .iter()
        .find(|(t, _)| *t == target)
        .map(|(_, s)| *s)
        .ok_or_else(|| io::Error::other(format!("this release has no archive for {target}")))?;

    let stem = format!("{NAME}-{}-{target}", checksums::VERSION);
    let dir = cache_root()?.join(checksums::VERSION).join(target);
    let bin_dir = dir.join(&stem);
    let exe = bin_dir.join(format!("{name}{}", env::consts::EXE_SUFFIX));
    if !dir.join(".complete").is_file() {
        install(&dir, &stem, sha256)?;
    }
    if !exe.is_file() {
        return Err(io::Error::other(format!(
            "{} is missing from the unpacked suite",
            exe.display()
        )));
    }
    exec(&exe, &bin_dir)
}

/// Download, verify and unpack the archive into `dir`. A temporary sibling
/// is renamed into place, so a concurrent or interrupted run never leaves a
/// half-unpacked suite that later runs would trust.
fn install(dir: &Path, stem: &str, sha256: &str) -> io::Result<()> {
    let base = env::var("MCPG_SUITE_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("{RELEASES}/v{}", checksums::VERSION));
    let url = format!("{}/{stem}.tar.gz", base.trim_end_matches('/'));
    eprintln!("{NAME}: downloading {url}");
    let archive = download(&url)?;

    let got: String = Sha256::digest(&archive)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != sha256 {
        return Err(io::Error::other(format!(
            "{url} has SHA-256 {got}, but this crate was published with {sha256}; refusing to run it"
        )));
    }

    let parent = dir
        .parent()
        .ok_or_else(|| io::Error::other("cache directory has no parent"))?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(
        ".{}.{}",
        dir.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    tar::Archive::new(flate2::read::GzDecoder::new(&archive[..])).unpack(&staging)?;
    fs::write(staging.join(".complete"), sha256)?;
    match fs::rename(&staging, dir) {
        Ok(()) => Ok(()),
        // Another run finished first; its copy is the same verified archive.
        Err(_) if dir.join(".complete").is_file() => {
            let _ = fs::remove_dir_all(&staging);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn download(url: &str) -> io::Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(ureq::Proxy::try_from_env())
        .timeout_global(Some(Duration::from_secs(900)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| io::Error::other(format!("{url}: {e}")))?;
    let mut body = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit(MAX_ARCHIVE_BYTES)
        .reader()
        .read_to_end(&mut body)?;
    Ok(body)
}

/// Run `exe` with this process's arguments. `mcpg <word>` runs a sibling
/// `mcpg-<word>` from PATH, so the suite's directory goes first on it.
fn exec(exe: &Path, bin_dir: &Path) -> io::Result<ExitCode> {
    let mut path = vec![bin_dir.to_path_buf()];
    if let Some(current) = env::var_os("PATH") {
        path.extend(env::split_paths(&current));
    }
    let path: OsString = env::join_paths(path).map_err(io::Error::other)?;
    let mut command = Command::new(exe);
    command.args(env::args_os().skip(1)).env("PATH", path);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec())
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        Ok(ExitCode::from(
            status.code().unwrap_or(1).clamp(0, 255) as u8
        ))
    }
}
