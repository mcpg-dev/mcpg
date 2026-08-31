#!/usr/bin/env sh
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — curl-able installer for the mcpg CLIs.
#
#   curl -fsSL https://raw.githubusercontent.com/mcpg-dev/mcpg/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --bin mcpg-cloud --version 1.0.0-dev.3
#
# With no --bin it installs the public CLI suite: mcpg, mcpg-config,
# mcpg-cloud, mcpg-plugin, mcpg-inspector — each from its own public
# repository's latest release (`github.com/mcpg-dev/<project>`). The
# BUSL control plane (`--bin mcpg-control-plane`) ships from a private
# repository and needs authenticated access.
# Detects OS / arch / libc, picks the matching release tarball, verifies its
# sha256 (and the cosign sign-blob bundle when `cosign` is present), and
# installs the binaries to a PATH dir. POSIX sh (no bash-isms) so it runs
# under dash/ash too.
#
# Options (flags or env):
#   --bin NAME      / MCPG_BIN     one CLI instead of the suite:
#                                  mcpg | mcpg-config | mcpg-cloud |
#                                  mcpg-plugin | mcpg-inspector |
#                                  mcpg-control-plane (needs repo access)
#   --version VER   / MCPG_VERSION pin a version (applies to every selected
#                                  bin; default: each bin's latest release).
#   --dir DIR       / MCPG_DIR     install dir (default: ~/.local/bin, or
#                                  /usr/local/bin when writable + root).
#   --libc gnu|musl / MCPG_LIBC    override libc detection (linux only).
#   --no-verify     / MCPG_NO_VERIFY=1   skip sha256 + cosign verification.
#
# Covers the platforms the release lanes ship: linux {x86_64,aarch64} ×
# {gnu, musl}, macOS arm64. Windows ships a `.zip` — download it from the
# GitHub release directly (this sh installer doesn't target Windows).
# ─────────────────────────────────────────────────────────────────────────────
set -eu

# Every project releases from its own public repository; MCPG_REPO
# overrides the OWNER/REPO for every selected bin (e.g. a fork or the
# licensed control-plane channel).
REPO_OVERRIDE="${MCPG_REPO:-}"
BIN="${MCPG_BIN:-}"
VERSION="${MCPG_VERSION:-}"
DIR="${MCPG_DIR:-}"
LIBC="${MCPG_LIBC:-}"
NO_VERIFY="${MCPG_NO_VERIFY:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --libc) LIBC="$2"; shift 2 ;;
    --no-verify) NO_VERIFY=1; shift ;;
    -h|--help) sed -n '2,40p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done

err() { echo "install.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# The default suite: the CLIs whose repositories are public. The control
# plane is installable with `--bin mcpg-control-plane` but ships from a
# private (licensed) repository, so it is not in the anonymous default.
SUITE="mcpg mcpg-config mcpg-cloud mcpg-plugin mcpg-inspector"
KNOWN_BINS="$SUITE mcpg-control-plane"

# Release project (repo name + asset stem) that ships a given binary.
project_for() {
  case "$1" in
    mcpg-control-plane) echo "mcpg-control-plane-server" ;;
    *) echo "$1" ;;
  esac
}

# OWNER/REPO a binary installs from — its project's own repository.
repo_for() {
  if [ -n "$REPO_OVERRIDE" ]; then echo "$REPO_OVERRIDE"; return; fi
  echo "mcpg-dev/$(project_for "$1")"
}

if [ -n "$BIN" ]; then
  case " $KNOWN_BINS " in
    *" $BIN "*) BINS="$BIN" ;;
    *) err "unknown --bin '$BIN' (one of: $KNOWN_BINS)" ;;
  esac
else
  BINS="$SUITE"
fi

# ── platform → rust target triple ──────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) rarch="x86_64" ;;
  aarch64|arm64) rarch="aarch64" ;;
  *) err "unsupported arch '$arch'" ;;
esac
case "$os" in
  Linux)
    if [ -z "$LIBC" ]; then
      # Detect the RUNNING libc, not merely an installed one: `ldd --version`
      # prints "musl libc" on Alpine vs "GNU libc/GLIBC" on glibc, and Alpine
      # ships /lib/libc.musl-<arch>.so.1. Do NOT key off /lib/ld-musl-*.so.1 —
      # `musl-tools` drops that on glibc hosts too (false positive).
      if (have ldd && ldd --version 2>&1 | grep -qi musl) || ls /lib/libc.musl-*.so.1 >/dev/null 2>&1; then
        LIBC="musl"
      else
        LIBC="gnu"
      fi
    fi
    TRIPLE="${rarch}-unknown-linux-${LIBC}"
    EXT="tar.xz" ;;
  Darwin)
    [ "$rarch" = "aarch64" ] || err "macOS x86_64 is not shipped (Apple Silicon only); arch=$arch"
    TRIPLE="aarch64-apple-darwin"; EXT="tar.xz" ;;
  *) err "unsupported OS '$os' (Windows: download the .zip from the GitHub release)" ;;
esac

fetch() { if have curl; then curl -fsSL "$@"; elif have wget; then wget -qO- "$@"; else err "need curl or wget"; fi; }

if [ -z "$DIR" ]; then
  if [ "$(id -u)" = "0" ] && [ -w /usr/local/bin ]; then DIR="/usr/local/bin"; else DIR="${HOME}/.local/bin"; fi
fi
mkdir -p "$DIR"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

verify_asset() { # <asset-path> <asset-url-base> <asset-name>
  [ -n "$NO_VERIFY" ] && return 0
  if fetch "$2/$3.sha256" > "$1.sha256" 2>/dev/null; then
    want="$(awk '{print $1; exit}' "$1.sha256")"
    if have sha256sum; then got="$(sha256sum "$1" | awk '{print $1}')";
    elif have shasum; then got="$(shasum -a 256 "$1" | awk '{print $1}')";
    else got=""; echo "install.sh: no sha256 tool; skipping checksum" >&2; fi
    if [ -n "$got" ] && [ "$got" != "$want" ]; then err "sha256 mismatch on $3: want $want got $got"; fi
    [ -n "$got" ] && echo "install.sh: sha256 ok ($3)"
  else
    echo "install.sh: no .sha256 sidecar for $3; skipping checksum" >&2
  fi
  # cosign sign-blob bundle (keyless) — best-effort, only when cosign present.
  # The certificate identity is the org's shared release workflow (the
  # signing runs in a reusable workflow, so the SAN names the hub repo,
  # not the per-project repository) — match at org scope.
  if have cosign && fetch "$2/$3.sigstore.json" > "$1.sigstore.json" 2>/dev/null; then
    if cosign verify-blob --bundle "$1.sigstore.json" \
         --certificate-identity-regexp 'github.com/mcpg-dev/' \
         --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
         "$1" >/dev/null 2>&1; then
      echo "install.sh: cosign signature verified ($3)"
    else
      echo "install.sh: cosign verification FAILED ($3)" >&2; exit 1
    fi
  fi
}

install_one() { # <bin> — resolves its own version unless VERSION pins one
  bin="$1"; project="$(project_for "$1")"
  repo="$(repo_for "$1")"
  api="https://api.github.com/repos/${repo}"
  ver="$VERSION"
  if [ -z "$ver" ]; then
    echo "install.sh: resolving latest ${project} release…"
    # Every release is a prerelease until GA, so /releases/latest is
    # empty by GitHub's definition — take the newest from the list
    # (tags are plain v<version> on the per-project repositories).
    ver="$(fetch "${api}/releases?per_page=1" \
      | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[^"]+"' \
      | sed -E 's/.*"v([^"]+)"/\1/' | head -1)"
    [ -n "$ver" ] || err "could not find a published release in ${repo} (pin one with --version)"
  fi
  tag="v${ver}"
  # Assets are named after the PROJECT (pack-binary.sh), which differs from
  # the binary inside for the control plane.
  stem="${project}-${ver}-${TRIPLE}"
  asset="${stem}.${EXT}"
  base="https://github.com/${repo}/releases/download/${tag}"

  echo "install.sh: ${bin} ${ver} for ${TRIPLE}"
  echo "install.sh: downloading ${asset}…"
  fetch "${base}/${asset}" > "${tmp}/${asset}" || err "download failed: ${base}/${asset} (is ${TRIPLE} shipped for ${ver}?)"
  verify_asset "${tmp}/${asset}" "$base" "$asset"

  ( cd "$tmp" && tar -xf "$asset" )
  src="${tmp}/${stem}/${bin}"
  [ -f "$src" ] || src="$(find "${tmp}/${stem}" -name "$bin" -type f 2>/dev/null | head -1)"
  [ -n "$src" ] && [ -f "$src" ] || err "binary '${bin}' not found inside ${asset}"
  chmod 0755 "$src"
  install -m 0755 "$src" "${DIR}/${bin}" 2>/dev/null || { cp "$src" "${DIR}/${bin}"; chmod 0755 "${DIR}/${bin}"; }
  echo "install.sh: installed ${bin} → ${DIR}/${bin}"
}

for b in $BINS; do
  install_one "$b"
done

# The gateway's `mcpg config|cloud|plugin|control-plane <sub>` subcommands exec
# sibling binaries, and `mcpg --control-plane` supervises mcpg-control-plane;
# a single-bin install of mcpg leaves all of that unavailable until the
# siblings are installed too.
if [ "$BINS" = "mcpg" ]; then
  echo "install.sh: NOTE — \`mcpg config|cloud|plugin|control-plane\` delegate to sibling CLIs; re-run without --bin to install the full suite."
fi

case ":${PATH}:" in
  *":${DIR}:"*) : ;;
  *) echo "install.sh: NOTE — ${DIR} is not on your PATH; add it (e.g. export PATH=\"${DIR}:\$PATH\")." ;;
esac
for b in $BINS; do
  "${DIR}/${b}" --version 2>/dev/null || true
done
