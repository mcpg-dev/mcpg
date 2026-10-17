#!/usr/bin/env python3
"""Build platform-tagged wheels for the mcpg CLI suite from the dist/ tree.

One project — ``model-context-protocol-gateway`` — one wheel per platform,
each carrying every suite binary it is given (mcpg dispatches
``mcpg config|cloud|plugin|control-plane`` to its mcpg-* siblings by PATH,
and ``mcpg --control-plane`` supervises mcpg-control-plane; the
console-scripts dir is on PATH in any venv/pipx install, so both forms
work). Stdlib-only by design: wheels are deterministic zip files; no
setuptools/maturin at publish time.

Usage:
    build_wheels.py --version 0.2.0-beta.3 [--dist DIR] [--out DIR]
                    [--members mcpg,mcpg-config,...] [--flat] [--root DIR]

The monorepo stages binaries as ``<dist>/<project root>/bin/<arch>/<name>``
and builds the whole suite. ``--flat`` reads ``<dist>/<arch>/<name>``
instead, and ``--members`` narrows the suite: the public mcpg repository
builds its four public members from release assets that way. ``--root`` is
the repository whose LICENSE the wheels carry.

Version mapping (release semver → PEP 440): -beta.N → bN, -rc.N → rcN,
-alpha.N → aN. Anything else pre-release is refused — throwaway channels
never publish.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SUITE = {
    "mcpg": "apps/gateway",
    "mcpg-config": "apps/config",
    "mcpg-cloud": "apps/cloud/cli",
    "mcpg-plugin": "apps/plugin",
    "mcpg-control-plane": "apps/control-plane/server",
    "mcpg-inspector": "apps/inspector/server",
}

# dist arch dir → wheel platform tag. The glibc floor tracks what the release
# builders link against (verify with: objdump -T <bin> | grep -o 'GLIBC_[0-9.]*'
# | sort -uV | tail -1). musllinux_1_2 matches the dynamic-musl toolchain.
PLATFORM_TAGS = {
    "amd64": "manylinux_2_34_x86_64",
    "arm64": "manylinux_2_34_aarch64",
    "musl-amd64": "musllinux_1_2_x86_64",
    "musl-arm64": "musllinux_1_2_aarch64",
    "darwin-arm64": "macosx_11_0_arm64",
    "windows-amd64": "win_amd64",
}

PKG = "model_context_protocol_gateway"
DIST_NAME = "model-context-protocol-gateway"

# A console script named like the project, so `uvx` and `pipx run` find one;
# it runs `mcpg`.
ALIAS = DIST_NAME

SHIM = '''\
"""Console-script shims for the embedded mcpg suite binaries."""

import os
import subprocess
import sys
from pathlib import Path

_BIN = Path(__file__).resolve().parent / "bin"
_EXE = ".exe" if sys.platform == "win32" else ""


def _run(name):
    exe = _BIN / (name + _EXE)
    if not exe.exists():
        sys.stderr.write(f"{name}: embedded binary missing ({exe}) — reinstall model-context-protocol-gateway\\n")
        return 1
    env = dict(os.environ)
    # `mcpg <x>` execs sibling mcpg-<x> by PATH; the embedded bin dir must win.
    env["PATH"] = str(_BIN) + os.pathsep + env.get("PATH", "")
    if sys.platform == "win32":
        return subprocess.call([str(exe), *sys.argv[1:]], env=env)
    os.execve(str(exe), [str(exe), *sys.argv[1:]], env)


def mcpg():
    return _run("mcpg")


def mcpg_config():
    return _run("mcpg-config")


def mcpg_cloud():
    return _run("mcpg-cloud")


def mcpg_plugin():
    return _run("mcpg-plugin")


def mcpg_control_plane():
    return _run("mcpg-control-plane")


def mcpg_inspector():
    return _run("mcpg-inspector")
'''

def entry_points(members: list[str]) -> str:
    lines = ["[console_scripts]"]
    lines += [f"{m} = {PKG}._shim:{m.replace('-', '_')}" for m in members]
    if "mcpg" in members:
        lines.append(f"{ALIAS} = {PKG}._shim:mcpg")
    return "\n".join(lines) + "\n"


def pep440(version: str) -> str:
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(beta|rc|alpha)\.(\d+))?", version)
    if not m:
        raise SystemExit(f"refusing to map version {version!r} to PEP 440 "
                         "(only release/beta/rc/alpha publish)")
    base, kind, n = m.groups()
    if not kind:
        return base
    return base + {"beta": "b", "rc": "rc", "alpha": "a"}[kind] + n


def stripped(path: Path) -> bytes:
    """Read a binary, debug-stripped when a suitable tool exists.

    Release binaries ship unstripped (the tarballs keep symbols for
    backtraces); embedded copies don't need them, and PyPI's default
    per-file limit (100 MB) makes the saving load-bearing. llvm-strip
    (``LLVM_STRIP``, else on PATH) handles every target — ELF of any
    architecture, PE and Mach-O; binutils strip handles native ELF only.
    Each tool is tried in turn, and a binary no tool can strip keeps its
    original bytes with a warning.
    """
    head = path.open("rb").read(4)
    # Mach-O keeps its bytes: arm64 macOS runs only signed code, and the
    # linker's ad-hoc signature covers the file a strip would rewrite.
    if head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return path.read_bytes()
    tools = []
    llvm = os.environ.get("LLVM_STRIP") or shutil.which("llvm-strip")
    if llvm:
        tools.append([llvm])
    if head == b"\x7fELF" and shutil.which("strip"):
        tools.append(["strip"])
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        for tool in tools:
            shutil.copy2(path, tmp_path)
            if subprocess.run([*tool, str(tmp_path)], capture_output=True).returncode == 0:
                return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)
    print(f"::warning::build_wheels: {path.name} ships unstripped "
          "(set LLVM_STRIP to an llvm-strip that reads this format)")
    return path.read_bytes()


def wheel_record_entry(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{name},sha256={digest.decode()},{len(data)}"


def build_wheel(out: Path, version: str, py_version: str, tag: str,
                binaries: dict[str, bytes], license_text: bytes,
                members: list[str], license_expr: str) -> Path:
    wheel_tag = f"py3-none-{tag}"
    info = f"{PKG}-{py_version}.dist-info"
    commands = ", ".join(f"`{m}`" for m in members)
    metadata = "\n".join([
        "Metadata-Version: 2.1",
        f"Name: {DIST_NAME}",
        f"Version: {py_version}",
        "Summary: Model Context Protocol Gateway — the mcpg CLI suite (prebuilt binaries)",
        "Home-page: https://mcpg.dev",
        "Project-URL: Source, https://github.com/mcpg-dev/mcpg",
        "Keywords: mcp,model-context-protocol,mcp-gateway,gateway,mcpg",
        f"License: {license_expr}",
        "Requires-Python: >=3.8",
        "Description-Content-Type: text/markdown",
        "",
        "# Model Context Protocol Gateway",
        "",
        f"The [mcpg](https://mcpg.dev) CLI suite — {commands} — as prebuilt"
        " binaries. Installing puts every command on PATH; `mcpg config …`,"
        " `mcpg cloud …` and `mcpg plugin …` dispatch to the side-by-side"
        " binaries.",
        "",
        "```sh",
        f"uvx {DIST_NAME} --help",
        f"pipx install {DIST_NAME} && mcpg --version",
        "```",
        "",
        "On Alpine Linux the binaries need `libgcc` (`apk add libgcc`).",
        "",
    ]).encode()
    wheel_meta = "\n".join([
        "Wheel-Version: 1.0",
        "Generator: mcpg-build-wheels",
        "Root-Is-Purelib: false",
        f"Tag: {wheel_tag}",
        "",
    ]).encode()

    files: list[tuple[str, bytes, int]] = [
        (f"{PKG}/__init__.py", b"", 0o644),
        (f"{PKG}/_shim.py", SHIM.encode(), 0o644),
    ]
    for name, blob in binaries.items():
        files.append((f"{PKG}/bin/{name}", blob, 0o755))
    files += [
        (f"{info}/METADATA", metadata, 0o644),
        (f"{info}/WHEEL", wheel_meta, 0o644),
        (f"{info}/entry_points.txt", entry_points(members).encode(), 0o644),
        (f"{info}/LICENSE.md", license_text, 0o644),
    ]

    record_lines = [wheel_record_entry(n, d) for n, d, _ in files]
    record_lines.append(f"{info}/RECORD,,")
    record = ("\n".join(record_lines) + "\n").encode()

    out.mkdir(parents=True, exist_ok=True)
    wheel_path = out / f"{PKG}-{py_version}-{wheel_tag}.whl"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, mode in files + [(f"{info}/RECORD", record, 0o644)]:
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.external_attr = (0o100000 | mode) << 16
            # A ZipInfo entry carries its own compression (STORED unless
            # set) and ignores the archive's default, so it is named here.
            zf.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    wheel_path.write_bytes(buf.getvalue())
    return wheel_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="release semver (e.g. 0.2.0-beta.3)")
    ap.add_argument("--dist", default="dist", help="staged binaries root")
    ap.add_argument("--out", default="dist/pypi", help="wheel output dir")
    ap.add_argument(
        "--check-version",
        action="store_true",
        help="exit 0 if the version maps to PEP 440, 3 if its channel never "
             "publishes wheels; build nothing either way",
    )
    ap.add_argument(
        "--members",
        default=",".join(SUITE),
        help="comma-separated suite binaries every wheel must carry (default: all)",
    )
    ap.add_argument(
        "--flat",
        action="store_true",
        help="binaries are staged as <dist>/<arch>/<name>, not per project root",
    )
    ap.add_argument(
        "--root",
        default=None,
        help="repository root that holds LICENSE (default: the monorepo root)",
    )
    args = ap.parse_args()

    # Pre-flight for callers that must tell "this channel does not publish"
    # apart from "the build broke". Exit 3 is the former: canary and nightly
    # deliberately never reach an index, and a release that cuts one should
    # skip wheels rather than fail.
    if args.check_version:
        try:
            print(pep440(args.version))
        except SystemExit as e:
            print(e, file=sys.stderr)
            return 3
        return 0

    members = [m for m in args.members.split(",") if m]
    unknown = [m for m in members if m not in SUITE]
    if unknown or not members:
        print(f"::error::build_wheels: unknown suite member(s): {', '.join(unknown) or '(none given)'}",
              file=sys.stderr)
        return 1

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[3]
    dist = (root / args.dist) if not Path(args.dist).is_absolute() else Path(args.dist)
    out = (root / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    py_version = pep440(args.version)

    license_path = next((p for p in (root / "LICENSE.md", root / "LICENSE") if p.is_file()), None)
    if license_path is None:
        print("::error::build_wheels: no LICENSE.md/LICENSE at repo root", file=sys.stderr)
        return 1
    if "mcpg-control-plane" in members:
        # The suite then bundles binaries under two licenses, so the wheel's
        # LICENSE.md is composed: a per-binary map, then both full texts.
        # The repo-root Apache text alone would misstate mcpg-control-plane.
        busl_path = root / "apps" / "control-plane" / "server" / "LICENSE"
        if not busl_path.is_file():
            print(f"::error::build_wheels: no BUSL text at {busl_path}", file=sys.stderr)
            return 1
        apache = ", ".join(f"`{m}`" for m in members if m != "mcpg-control-plane")
        license_text = (
            b"# License\n\n"
            b"This package distributes the mcpg CLI suite. Each binary is licensed\n"
            b"on its own terms:\n\n"
            b"| binary | license |\n| --- | --- |\n"
            + f"| {apache} | Apache-2.0 |\n".encode()
            + b"| `mcpg-control-plane` | Business Source License 1.1 |\n\n"
            b"Both license texts follow.\n\n## Apache License 2.0\n\n"
            + license_path.read_bytes()
            + b"\n\n## Business Source License 1.1 (mcpg-control-plane)\n\n"
            + busl_path.read_bytes()
        )
        license_expr = "Apache-2.0 AND BUSL-1.1"
    else:
        license_text = license_path.read_bytes()
        license_expr = "Apache-2.0"

    def staged(proj: str, arch: str, exe: str) -> Path:
        if args.flat:
            return dist / arch / exe
        return dist / SUITE[proj] / "bin" / arch / exe

    built = []
    for arch, tag in PLATFORM_TAGS.items():
        exe_suffix = ".exe" if arch == "windows-amd64" else ""
        binaries: dict[str, bytes] = {}
        complete = True
        for proj in members:
            p = staged(proj, arch, proj + exe_suffix)
            if not p.is_file():
                complete = False
                break
            binaries[proj + exe_suffix] = stripped(p)
        if not complete:
            if staged("mcpg", arch, "mcpg" + exe_suffix).parent.is_dir():
                print(f"::warning::build_wheels: {arch} has a partial suite — wheel skipped")
            continue
        wheel = build_wheel(out, args.version, py_version, tag, binaries, license_text,
                            members, license_expr)
        built.append(wheel)
        size_mb = wheel.stat().st_size / 1_000_000
        if size_mb > 95:
            print(f"::warning::build_wheels: {wheel.name} is {size_mb:.0f} MB — "
                  "PyPI's default per-file limit is 100 MB; request a project "
                  "limit increase before this fails an upload")
        print(f"[build-wheels] {wheel.name} ({size_mb:.0f} MB)")

    if not built:
        print("::error::build_wheels: no complete platform suite found", file=sys.stderr)
        return 1
    print(f"[build-wheels] {len(built)} wheel(s) for {DIST_NAME} {py_version} in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
