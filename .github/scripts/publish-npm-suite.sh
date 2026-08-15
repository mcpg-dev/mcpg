#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Publish the @mcpg-dev/cli npm suite from published release artifacts.
#
# Runs in the public mcpg repository. Every binary comes from a GitHub
# Release of its own repository — nothing is built here, so what npm serves
# is byte-identical to what the releases attested. Emits one platform
# package per target plus the @mcpg-dev/cli launcher package.
#
#   VERSION       suite version; default: this repository's latest release
#   NPM_DIST_TAG  dist-tag for publish (default: beta)
#   DRY_RUN       true (default) = assemble + `npm pack` only; false = publish
#
# Auth comes from the ambient npm config (NODE_AUTH_TOKEN via setup-node).
# All six platforms are required: a missing sibling asset fails the publish
# rather than shipping a package that silently lacks a binary.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ORG="mcpg-dev"
DRY_RUN="${DRY_RUN:-true}"
NPM_DIST_TAG="${NPM_DIST_TAG:-beta}"
OUT_DIR="${OUT_DIR:-$PWD/dist-npm}"

# The PUBLIC suite: every member's source and releases are public. The
# control-plane server and the inspector are distributed on the private
# channel only and are deliberately absent here.
SUITE=(mcpg mcpg-config mcpg-cloud mcpg-plugin)

TRIPLES=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
         x86_64-unknown-linux-musl aarch64-unknown-linux-musl
         aarch64-apple-darwin x86_64-pc-windows-gnu)
declare -A NPM_SUFFIX=(
  [x86_64-unknown-linux-gnu]="linux-x64"    [aarch64-unknown-linux-gnu]="linux-arm64"
  [x86_64-unknown-linux-musl]="linux-x64-musl" [aarch64-unknown-linux-musl]="linux-arm64-musl"
  [aarch64-apple-darwin]="darwin-arm64"     [x86_64-pc-windows-gnu]="win32-x64"
)
declare -A NPM_OS=(
  [x86_64-unknown-linux-gnu]="linux" [aarch64-unknown-linux-gnu]="linux"
  [x86_64-unknown-linux-musl]="linux" [aarch64-unknown-linux-musl]="linux"
  [aarch64-apple-darwin]="darwin" [x86_64-pc-windows-gnu]="win32"
)
declare -A NPM_CPU=(
  [x86_64-unknown-linux-gnu]="x64" [aarch64-unknown-linux-gnu]="arm64"
  [x86_64-unknown-linux-musl]="x64" [aarch64-unknown-linux-musl]="arm64"
  [aarch64-apple-darwin]="arm64" [x86_64-pc-windows-gnu]="x64"
)
declare -A NPM_LIBC=(
  [x86_64-unknown-linux-gnu]="glibc" [aarch64-unknown-linux-gnu]="glibc"
  [x86_64-unknown-linux-musl]="musl" [aarch64-unknown-linux-musl]="musl"
)

latest_release() { # <repo> → version (no leading v)
  # Not releases/latest: that endpoint hides prereleases, and the whole
  # pre-GA lineage is prerelease-flagged. Newest release, whatever its flag.
  curl -fsSL "https://api.github.com/repos/${ORG}/$1/releases?per_page=1" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["tag_name"].lstrip("v"))'
}

if [ -z "${VERSION:-}" ]; then
  VERSION="$(latest_release mcpg)"
fi
[ -n "$VERSION" ] || { echo "::error::publish-npm-suite: could not determine version"; exit 1; }

# Sibling binaries ride each repository's own latest release — the projects
# version independently, and the packages record the suite (mcpg) version.
declare -A PROJ_VERSION=( [mcpg]="$VERSION" )
for proj in "${SUITE[@]}"; do
  [ "$proj" = "mcpg" ] && continue
  PROJ_VERSION[$proj]="$(latest_release "$proj")"
  [ -n "${PROJ_VERSION[$proj]}" ] || { echo "::error::no release found for ${proj}"; exit 1; }
done
echo "[suite] versions: $(for p in "${SUITE[@]}"; do printf '%s=%s ' "$p" "${PROJ_VERSION[$p]}"; done)"

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR/pkgs" "$OUT_DIR/dl"

# Every public suite binary is Apache-2.0, so the packaged license is this
# repository's own LICENSE, verbatim.
LICENSE_SRC="$OUT_DIR/LICENSE.md"
cp LICENSE "$LICENSE_SRC"

fetch_binary() { # <proj> <triple> <dest-dir>
  local proj="$1" triple="$2" dest="$3"
  local ver="${PROJ_VERSION[$proj]}"
  local exe="$proj" ext="tar.xz"
  case "$triple" in *windows*) exe="${proj}.exe"; ext="zip" ;; esac
  local stem="${proj}-${ver}-${triple}"
  local url="https://github.com/${ORG}/${proj}/releases/download/v${ver}/${stem}.${ext}"
  local dl="$OUT_DIR/dl/${stem}.${ext}"
  [ -f "$dl" ] || curl -fsSL --retry 3 -o "$dl" "$url" \
    || { echo "::error::missing asset ${stem}.${ext} on ${proj} v${ver}"; return 1; }
  local x="$OUT_DIR/dl/x-${stem}"
  rm -rf "$x"; mkdir -p "$x"
  case "$ext" in
    zip) unzip -q "$dl" -d "$x" ;;
    *)   tar -C "$x" -xJf "$dl" ;;
  esac
  install -m 0755 "$x/${stem}/${exe}" "$dest/${exe}"
}

publish_one() { # <pkg-dir> <name>
  local dir="$1" name="$2"
  ( cd "$dir" && npm pack --pack-destination "$OUT_DIR" >/dev/null )
  if [ "$DRY_RUN" = "false" ]; then
    if npm view "${name}@${VERSION}" version >/dev/null 2>&1; then
      echo "[suite] ${name}@${VERSION} already published — skipping"
      return 0
    fi
    ( cd "$dir" && npm publish --tag "$NPM_DIST_TAG" --access public --provenance )
    # Until a stable lane exists, `latest` deliberately tracks the newest
    # published version — npm only auto-sets it on a first-ever publish.
    npm dist-tag add "${name}@${VERSION}" latest
    echo "[suite] published ${name}@${VERSION} (dist-tags ${NPM_DIST_TAG}, latest)"
  else
    echo "[suite] DRY_RUN — packed ${name}@${VERSION}"
  fi
}

built=()
for triple in "${TRIPLES[@]}"; do
  suffix="${NPM_SUFFIX[$triple]}"
  name="@mcpg-dev/cli-${suffix}"
  dir="$OUT_DIR/pkgs/cli-${suffix}"
  mkdir -p "$dir/bin"
  for proj in "${SUITE[@]}"; do
    fetch_binary "$proj" "$triple" "$dir/bin"
  done
  cp "$LICENSE_SRC" "$dir/LICENSE.md"
  {
    printf '{\n'
    printf '  "name": "%s",\n' "$name"
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "description": "mcpg CLI suite binaries (%s)",\n' "$suffix"
    printf '  "license": "Apache-2.0",\n'
    printf '  "repository": { "type": "git", "url": "https://github.com/mcpg-dev/mcpg" },\n'
    printf '  "os": ["%s"],\n' "${NPM_OS[$triple]}"
    printf '  "cpu": ["%s"],\n' "${NPM_CPU[$triple]}"
    if [ -n "${NPM_LIBC[$triple]:-}" ]; then
      printf '  "libc": ["%s"],\n' "${NPM_LIBC[$triple]}"
    fi
    printf '  "files": ["bin/", "LICENSE.md"]\n'
    printf '}\n'
  } > "$dir/package.json"
  publish_one "$dir" "$name"
  built+=("$suffix")
done

[ "${#built[@]}" -eq "${#TRIPLES[@]}" ] || { echo "::error::incomplete platform set"; exit 1; }

# ── launcher package ────────────────────────────────────────────────────────
meta="$OUT_DIR/pkgs/cli"
mkdir -p "$meta/bin"
cp .github/npm/launcher.mjs "$meta/bin/launcher.mjs"
cp "$LICENSE_SRC" "$meta/LICENSE.md"
cat > "$meta/README.md" <<EOF
# @mcpg-dev/cli

The [mcpg](https://mcpg.dev) MCP gateway CLI suite — \`mcpg\`,
\`mcpg-config\`, \`mcpg-cloud\` and \`mcpg-plugin\` — as prebuilt binaries.

\`\`\`sh
npx @mcpg-dev/cli --help
npm install -g @mcpg-dev/cli && mcpg --version
\`\`\`

Installing puts every command above on \`PATH\`; the package name is scoped
but the commands are not.

The matching platform binary package installs via optionalDependencies; the
\`--omit=optional\` install flag therefore breaks this package by design.
EOF
{
  printf '{\n'
  printf '  "name": "@mcpg-dev/cli",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "description": "mcpg — MCP gateway CLI suite (prebuilt binaries)",\n'
  printf '  "license": "Apache-2.0",\n'
  printf '  "homepage": "https://mcpg.dev",\n'
  printf '  "repository": { "type": "git", "url": "https://github.com/mcpg-dev/mcpg" },\n'
  printf '  "type": "module",\n'
  printf '  "engines": { "node": ">=18" },\n'
  printf '  "bin": {\n'
  printf '    "mcpg": "bin/launcher.mjs",\n'
  printf '    "mcpg-config": "bin/launcher.mjs",\n'
  printf '    "mcpg-cloud": "bin/launcher.mjs",\n'
  printf '    "mcpg-plugin": "bin/launcher.mjs"\n'
  printf '  },\n'
  printf '  "optionalDependencies": {\n'
  for i in "${!built[@]}"; do
    sep=","; [ "$i" -eq $(( ${#built[@]} - 1 )) ] && sep=""
    printf '    "@mcpg-dev/cli-%s": "%s"%s\n' "${built[$i]}" "$VERSION" "$sep"
  done
  printf '  },\n'
  printf '  "files": ["bin/", "README.md", "LICENSE.md"]\n'
  printf '}\n'
} > "$meta/package.json"
publish_one "$meta" "@mcpg-dev/cli"
