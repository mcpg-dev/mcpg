#!/usr/bin/env python3
"""Publish the model-context-protocol-gateway launcher crate to crates.io.

Runs in the public mcpg repository, next to the npm and PyPI suite
publishers and with the same suite. crates.io carries this one crate: a
small launcher whose binaries (`mcpg`, `mcpg-config`, `mcpg-cloud`,
`mcpg-plugin`) download the suite archive for their platform on first use
and run the release binaries; `cargo install` compiles the launcher only.

For a suite version the script:

1. builds one `model-context-protocol-gateway-<version>-<target>.tar.gz` per
   platform from the four CLIs' release assets, and attaches it with a
   `.sha256` to this repository's release — unless the release has it: an
   attached archive is never replaced, because a published crate pins it;
2. generates the crate from `.github/crates/launcher`, with the attached
   archives' SHA-256 sums in `src/checksums.rs` and cargo-binstall metadata
   that points at the same archives;
3. publishes it with cargo's verify build, unless crates.io has the version.

Environment:
    VERSION               suite (mcpg) version; default: the latest release
    DRY_RUN               true (default) = build and package, upload nothing
    CARGO_REGISTRY_TOKEN  crates.io token; required when DRY_RUN=false
    GH_TOKEN              GitHub token; attaching archives needs contents: write

``--selftest`` runs the offline checks the monorepo's CI runs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ORG = "mcpg-dev"
REPO = "mcpg"
NAME = "model-context-protocol-gateway"
SUITE = ["mcpg", "mcpg-config", "mcpg-cloud", "mcpg-plugin"]
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-gnu",
]
TEMPLATE = Path(".github/crates/launcher")
UA = "mcpg-dev/mcpg crates publisher (https://github.com/mcpg-dev/mcpg)"


def log(msg: str) -> None:
    print(f"[crates] {msg}", flush=True)


def http(url: str, *, github: bool = False) -> bytes | None:
    headers = {"User-Agent": UA}
    if github and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=300) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def latest_release(repo: str) -> str:
    # Not releases/latest: that endpoint hides prereleases, and the whole
    # pre-GA lineage is prerelease-flagged.
    rel = json.loads(http(f"https://api.github.com/repos/{ORG}/{repo}/releases?per_page=1", github=True) or b"[]")
    if not rel:
        raise SystemExit(f"::error::no release found for {repo}")
    return rel[0]["tag_name"].removeprefix("v")


def exe(name: str, target: str) -> str:
    return name + (".exe" if "windows" in target else "")


def release_binary(proj: str, version: str, target: str) -> bytes:
    """One CLI's binary, from its own repository's release asset."""
    stem = f"{proj}-{version}-{target}"
    ext = "zip" if "windows" in target else "tar.xz"
    url = f"https://github.com/{ORG}/{proj}/releases/download/v{version}/{stem}.{ext}"
    data = http(url)
    if data is None:
        raise SystemExit(f"::error::missing asset {stem}.{ext} on {proj} v{version}")
    member = f"{stem}/{exe(proj, target)}"
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.read(member)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as t:
        f = t.extractfile(member)
        if f is None:
            raise SystemExit(f"::error::{member} is not a file in {url}")
        return f.read()


def suite_archive(version: str, target: str, binaries: dict[str, bytes], license_text: bytes) -> bytes:
    """`<NAME>-<version>-<target>/` with the binaries and LICENSE, gzipped tar.

    Fixed owner, mode and time, so the same inputs give the same bytes.
    """
    root = f"{NAME}-{version}-{target}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as t:
        entries = [(f"{root}/{exe(n, target)}", binaries[n], 0o755) for n in sorted(binaries)]
        entries.append((f"{root}/LICENSE", license_text, 0o644))
        for path, data, mode in entries:
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def attached_assets(version: str) -> dict[str, str]:
    """The release's asset names → download URLs."""
    body = http(f"https://api.github.com/repos/{ORG}/{REPO}/releases/tags/v{version}", github=True)
    if body is None:
        raise SystemExit(f"::error::{ORG}/{REPO} has no release v{version}")
    return {a["name"]: a["browser_download_url"] for a in json.loads(body).get("assets", [])}


def render_crate(version: str, sums: dict[str, str]) -> dict[str, str]:
    """The generated files of the crate, besides the template's src/lib.rs."""
    pkg_url = f"{{ repo }}/releases/download/v{{ version }}/{NAME}-{{ version }}-{{ target }}.tar.gz"
    bin_dir = f"{NAME}-{{ version }}-{{ target }}/{{ bin }}{{ binary-ext }}"
    msvc_pkg = pkg_url.replace("{ target }", "x86_64-pc-windows-gnu")
    msvc_bin = bin_dir.replace("{ target }", "x86_64-pc-windows-gnu")
    lines = [
        "[package]",
        f'name = "{NAME}"',
        f'version = "{version}"',
        'edition = "2024"',
        'rust-version = "1.85"',
        f'description = "Model Context Protocol Gateway — installs the mcpg CLI suite ({", ".join(SUITE)}) and runs its release binaries"',
        'license = "Apache-2.0"',
        'homepage = "https://mcpg.dev"',
        f'repository = "https://github.com/{ORG}/{REPO}"',
        'readme = "README.md"',
        'keywords = ["mcp", "model-context-protocol", "mcp-gateway", "gateway", "mcpg"]',
        'categories = ["command-line-utilities", "network-programming"]',
        "",
        "[dependencies]",
        'flate2 = "1"',
        'sha2 = "0.11"',
        'tar = "0.4"',
        'ureq = "3"',
    ]
    for name in SUITE:
        lines += ["", "[[bin]]", f'name = "{name}"', f'path = "src/bin/{name}.rs"']
    lines += [
        "",
        "# `cargo binstall` installs the release binaries themselves.",
        "[package.metadata.binstall]",
        f'pkg-url = "{pkg_url}"',
        f'bin-dir = "{bin_dir}"',
        'pkg-fmt = "tgz"',
        "",
        "[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]",
        f'pkg-url = "{msvc_pkg}"',
        f'bin-dir = "{msvc_bin}"',
    ]
    files = {"Cargo.toml": "\n".join(lines) + "\n"}
    files["src/checksums.rs"] = (
        "// Written when this crate was published: the SHA-256 of each release\n"
        "// archive, so a download is checked against this crate, not the server.\n"
        f'pub const VERSION: &str = "{version}";\n'
        "pub const ARCHIVES: &[(&str, &str)] = &[\n"
        + "".join(f'    (\n        "{t}",\n        "{sums[t]}",\n    ),\n' for t in TARGETS)
        + "];\n"
    )
    for name in SUITE:
        files[f"src/bin/{name}.rs"] = (
            "fn main() -> std::process::ExitCode {\n"
            f'    model_context_protocol_gateway::run("{name}")\n'
            "}\n"
        )
    files["README.md"] = (
        "# Model Context Protocol Gateway\n\n"
        f"Installs the [mcpg](https://mcpg.dev) CLI suite: {', '.join(f'`{n}`' for n in SUITE)}.\n\n"
        "```sh\n"
        f"cargo install {NAME}      # a launcher; the first run downloads the release binaries\n"
        f"cargo binstall {NAME}     # the release binaries directly\n"
        "mcpg --version\n"
        "```\n\n"
        "The launcher checks each download against the SHA-256 sum published in this crate.\n"
        "`MCPG_SUITE_DIR` sets where the binaries are kept, and `MCPG_SUITE_URL` a mirror to\n"
        "download them from. Other install paths: <https://mcpg.dev/docs/install>.\n"
    )
    return files


def on_crates_io(version: str) -> bool:
    return http(f"https://crates.io/api/v1/crates/{NAME}/{version}") is not None


def main() -> int:
    dry = os.environ.get("DRY_RUN", "true") != "false"
    if not dry and not os.environ.get("CARGO_REGISTRY_TOKEN"):
        raise SystemExit("::error::CARGO_REGISTRY_TOKEN is required to publish")

    version = os.environ.get("VERSION") or latest_release(REPO)
    versions = {REPO: version} | {p: latest_release(p) for p in SUITE[1:]}
    log("suite: " + " ".join(f"{p}={v}" for p, v in versions.items()))

    work = Path(tempfile.mkdtemp(prefix="crates-"))
    try:
        assets = attached_assets(version)
        license_text = Path("LICENSE").read_bytes()
        sums: dict[str, str] = {}
        uploads: list[Path] = []
        for target in TARGETS:
            stem = f"{NAME}-{version}-{target}.tar.gz"
            if stem in assets and f"{stem}.sha256" in assets:
                sums[target] = http(assets[f"{stem}.sha256"]).decode().split()[0]
                log(f"{stem} is attached already — the crate pins it")
                continue
            binaries = {p: release_binary(p, versions[p], target) for p in SUITE}
            archive = suite_archive(version, target, binaries, license_text)
            sums[target] = hashlib.sha256(archive).hexdigest()
            (work / stem).write_bytes(archive)
            (work / f"{stem}.sha256").write_text(f"{sums[target]}  {stem}\n")
            uploads += [work / stem, work / f"{stem}.sha256"]
            log(f"built {stem} ({len(archive) / 1e6:.0f} MB)")
        if uploads and not dry:
            subprocess.run(["gh", "release", "upload", f"v{version}", "--repo", f"{ORG}/{REPO}",
                            *map(str, uploads)], check=True)
            log(f"attached {len(uploads) // 2} archive(s) to {REPO} v{version}")

        crate = work / NAME
        shutil.copytree(TEMPLATE, crate)
        for rel, content in render_crate(version, sums).items():
            (crate / rel).parent.mkdir(parents=True, exist_ok=True)
            (crate / rel).write_text(content)
        shutil.copy("LICENSE", crate / "LICENSE")
        env = dict(os.environ, CARGO_TERM_COLOR="never", CARGO_TARGET_DIR=str(work / "target"))
        if dry:
            subprocess.run(["cargo", "package", "--allow-dirty"], cwd=crate, env=env, check=True)
            log(f"DRY_RUN — packaged and built {NAME}@{version}")
            return 0
        if on_crates_io(version):
            log(f"{NAME}@{version} already on crates.io — skipping")
            return 0
        subprocess.run(["cargo", "publish", "--allow-dirty"], cwd=crate, env=env, check=True)
        log(f"published {NAME}@{version}")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def selftest() -> int:
    bad = []
    bins = {"mcpg": b"a", "mcpg-config": b"b", "mcpg-cloud": b"c", "mcpg-plugin": b"d"}
    one = suite_archive("1.0.0", "x86_64-pc-windows-gnu", bins, b"LICENSE TEXT")
    if one != suite_archive("1.0.0", "x86_64-pc-windows-gnu", bins, b"LICENSE TEXT"):
        bad.append("archive not deterministic")
    with tarfile.open(fileobj=io.BytesIO(one), mode="r:gz") as t:
        names = sorted(m.name for m in t.getmembers())
        modes = {m.name: m.mode for m in t.getmembers()}
    root = f"{NAME}-1.0.0-x86_64-pc-windows-gnu"
    want = sorted([f"{root}/LICENSE"] + [f"{root}/{n}.exe" for n in SUITE])
    if names != want:
        bad.append(f"archive layout {names}")
    if modes.get(f"{root}/mcpg.exe") != 0o755:
        bad.append("binary not executable")
    sums = {t: f"{i:064x}" for i, t in enumerate(TARGETS)}
    files = render_crate("1.0.0", sums)
    manifest = tomllib.loads(files["Cargo.toml"])
    if sorted(b["name"] for b in manifest["bin"]) != sorted(SUITE):
        bad.append("crate binaries")
    if set(manifest["dependencies"]) != {"flate2", "sha2", "tar", "ureq"}:
        bad.append("crate dependencies")
    binstall = manifest["package"]["metadata"]["binstall"]
    if "x86_64-pc-windows-gnu" not in binstall["overrides"]["x86_64-pc-windows-msvc"]["pkg-url"]:
        bad.append("msvc binstall override")
    if "{ target }.tar.gz" not in binstall["pkg-url"] or binstall["pkg-fmt"] != "tgz":
        bad.append("binstall archive")
    checks = files["src/checksums.rs"]
    if any(f'"{t}",\n        "{sums[t]}",' not in checks for t in TARGETS) or 'VERSION: &str = "1.0.0"' not in checks:
        bad.append("checksums.rs")
    if 'run("mcpg-cloud")' not in files["src/bin/mcpg-cloud.rs"]:
        bad.append("bin entry")
    lib = (Path(__file__).resolve().parents[1] / "crates" / "launcher" / "src" / "lib.rs").read_text()
    if "checksums::ARCHIVES" not in lib or "pub fn run(" not in lib:
        bad.append("launcher template")
    if len(manifest["package"]["description"]) > 1000:
        bad.append("description too long for crates.io")
    print(" ".join(bad) if bad else "selftest ok")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(selftest() if "--selftest" in sys.argv else main())
