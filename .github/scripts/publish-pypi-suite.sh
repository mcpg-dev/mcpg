#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Publish the model-context-protocol-gateway wheels to PyPI from published
# release artifacts.
#
# Runs in the public mcpg repository, next to publish-npm-suite.sh and with
# the same suite: every binary comes from a GitHub Release of its own
# repository, so what PyPI serves is byte-identical to what the releases
# attested (debug symbols aside — build_wheels.py strips them). One wheel per
# platform, each carrying the whole public suite.
#
#   VERSION     suite version; default: this repository's latest release
#   DRY_RUN     true (default) = build + `twine check` only; false = upload
#   PYPI_TOKEN  upload token (never printed); required when DRY_RUN=false
#
# All six platforms are required: a missing sibling asset fails the publish
# rather than shipping a wheel that silently lacks a binary.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ORG="mcpg-dev"
DRY_RUN="${DRY_RUN:-true}"
OUT_DIR="${OUT_DIR:-$PWD/dist-pypi}"
BUILD_WHEELS=".github/pypi/build_wheels.py"

# The PUBLIC suite, the same four as the npm suite: the control-plane server
# and the inspector are distributed on the private channel only.
SUITE=(mcpg mcpg-config mcpg-cloud mcpg-plugin)

TRIPLES=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
         x86_64-unknown-linux-musl aarch64-unknown-linux-musl
         aarch64-apple-darwin x86_64-pc-windows-gnu)
# Release triple → the arch key build_wheels.py maps to a wheel platform tag.
declare -A WHEEL_ARCH=(
  [x86_64-unknown-linux-gnu]="amd64"         [aarch64-unknown-linux-gnu]="arm64"
  [x86_64-unknown-linux-musl]="musl-amd64"   [aarch64-unknown-linux-musl]="musl-arm64"
  [aarch64-apple-darwin]="darwin-arm64"      [x86_64-pc-windows-gnu]="windows-amd64"
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
[ -n "$VERSION" ] || { echo "::error::publish-pypi-suite: could not determine version"; exit 1; }

# Exit 3 is the mapper saying "this channel never publishes wheels".
check_rc=0
python3 "$BUILD_WHEELS" --version "$VERSION" --check-version >/dev/null 2>&1 || check_rc=$?
if [ "$check_rc" -eq 3 ]; then
  echo "::notice::publish-pypi-suite: $VERSION is a channel that never publishes wheels — skipping"
  exit 0
elif [ "$check_rc" -ne 0 ]; then
  echo "::error::publish-pypi-suite: version check failed for $VERSION"
  exit "$check_rc"
fi

# Sibling binaries ride each repository's own latest release — the projects
# version independently, and the wheels record the suite (mcpg) version.
declare -A PROJ_VERSION=( [mcpg]="$VERSION" )
for proj in "${SUITE[@]}"; do
  [ "$proj" = "mcpg" ] && continue
  PROJ_VERSION[$proj]="$(latest_release "$proj")"
  [ -n "${PROJ_VERSION[$proj]}" ] || { echo "::error::no release found for ${proj}"; exit 1; }
done
echo "[pypi] versions: $(for p in "${SUITE[@]}"; do printf '%s=%s ' "$p" "${PROJ_VERSION[$p]}"; done)"

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR/dist" "$OUT_DIR/dl" "$OUT_DIR/wheels"

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

for triple in "${TRIPLES[@]}"; do
  dest="$OUT_DIR/dist/${WHEEL_ARCH[$triple]}"
  mkdir -p "$dest"
  for proj in "${SUITE[@]}"; do
    fetch_binary "$proj" "$triple" "$dest"
  done
done

python3 "$BUILD_WHEELS" --version "$VERSION" \
  --members "$(IFS=,; echo "${SUITE[*]}")" --flat --root . \
  --dist "$OUT_DIR/dist" --out "$OUT_DIR/wheels"

shopt -s nullglob
wheels=("$OUT_DIR"/wheels/*.whl)
[ "${#wheels[@]}" -eq "${#TRIPLES[@]}" ] \
  || { echo "::error::built ${#wheels[@]} wheel(s), expected ${#TRIPLES[@]}"; exit 1; }

twine check "${wheels[@]}"
if [ "$DRY_RUN" = "false" ]; then
  [ -n "${PYPI_TOKEN:-}" ] || { echo "::error::PYPI_TOKEN is required to upload"; exit 1; }
  # pypi.org answers an already-uploaded file as a duplicate, so a re-run
  # finishes a partial set instead of failing on what already landed.
  TWINE_USERNAME="__token__" TWINE_PASSWORD="$PYPI_TOKEN" \
    twine upload --non-interactive --skip-existing "${wheels[@]}"
  echo "[pypi] published model-context-protocol-gateway ${VERSION} (${#wheels[@]} wheels)"
else
  echo "[pypi] DRY_RUN — built ${#wheels[@]} wheel(s) for ${VERSION}"
fi
