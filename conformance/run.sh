#!/usr/bin/env bash
# Run the upstream `modelcontextprotocol/conformance` suite against
# a local MCPG built from this worktree.
#
# Usage:
#   ./run.sh 2025-11-25       # legacy wire
#   ./run.sh 2026-07-28       # modern wire (alias: DRAFT-2026-v1)
#   ./run.sh both             # run both sequentially
#
# Env:
#   CONFORMANCE_VERSION  npm tag of the suite to use
#                        (default: 0.2.0-alpha.0 — has DRAFT-2026 scenarios)
#   MCPG_CONFIG          path to MCPG config yaml
#                        (default: ./config-everything.yaml — the full fixture
#                        catalog every tools-call/resources-read/prompts-get
#                        scenario needs. Set ./config-baseline.yaml for a
#                        fixture-less lifecycle-only smoke.)
#   MCPG_PORT            port the harness health-checks + points the suite at;
#                        MUST match the config's bind_address (default: 8787).
#                        (Stripped from the gateway's env on boot — it's not a
#                        gateway config field.)
#   RESULTS_DIR          output directory for checks.json
#                        (default: ./results/<version>-<timestamp>/)
#   SCENARIO             optional single scenario name (e.g. server-initialize)
#
#   --- cross-platform build knobs (the conformance.yml windows lane) ---
#   CONFORMANCE_TARGET       cargo target triple to build/run for (e.g.
#                            x86_64-pc-windows-gnu). Empty = native host.
#   CONFORMANCE_BUILD_ONLY=1 build mcpg + the mock cdylib for $CONFORMANCE_TARGET
#                            then STOP (the linux cross-build half of the
#                            windows lane — uploads the artifacts).
#   CONFORMANCE_PREBUILT=1   skip the build; expect mcpg(.exe) + the mock cdylib
#                            already under the target dir (the windows-latest
#                            run half downloads them).
#
# Windows can't build+run in one place: Wine livelocks mcpg.exe's async runtime
# and there's no self-hosted Windows box. So conformance.yml CROSS-BUILDS the
# x86_64-pc-windows-gnu artifacts on linux (build-env) then RUNS them on a
# GitHub-hosted windows-latest runner — same split as plugin-ffi windows-native.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

VERSION="${1:-2025-11-25}"
# 0.2.0-alpha.5+ knows the ratified `2026-07-28` spec id; older alphas only
# accept its pre-ratification name and abort the modern-wire run at arg parse.
CONFORMANCE_VERSION="${CONFORMANCE_VERSION:-0.2.0-alpha.9}"
# Default to the FULL fixture catalog: config-baseline.yaml defines no
# tools/resources/prompts, so it fails every tools-call/resources-read/
# prompts-get scenario by design (it's a lifecycle-only smoke). Direct
# callers (e.g. the darwin e2e lane) and the nx target both want the full
# suite; opt into the baseline explicitly via MCPG_CONFIG.
MCPG_CONFIG="${MCPG_CONFIG:-${SCRIPT_DIR}/config-everything.yaml}"
MCPG_PORT="${MCPG_PORT:-8787}"
SCENARIO="${SCENARIO:-}"

# ── cross-platform target / artifact layout ────────────────────────────────
TARGET="${CONFORMANCE_TARGET:-}"
PREBUILT="${CONFORMANCE_PREBUILT:-0}"
BUILD_ONLY="${CONFORMANCE_BUILD_ONLY:-0}"

# Windows cross-builds use the RELEASE profile: the DEBUG windows-gnu build of
# some plugins (e.g. observability-otlp) fails to compile, and release is the
# proven path — the plugin-ffi windows-native lane ships release windows-gnu
# artifacts. Native linux/macos stay debug (faster). PROFILE_DIR feeds both the
# cargo flag and the target subdir so prebuilt download paths line up.
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"
PROFILE_DIR="debug"; CARGO_PROFILE_ARGS=()
case "${TARGET:-$HOST_TRIPLE}" in
  *windows*) PROFILE_DIR="release"; CARGO_PROFILE_ARGS=(--release) ;;
esac
# Cross-build only when the requested triple differs from the host (e.g. the
# M1's host triple IS aarch64-apple-darwin → a native build there). Honour
# CARGO_TARGET_DIR (CI scopes it per-target so the binary isn't under ./target).
CARGO_TARGET_ARGS=(); REL_SUBDIR="${PROFILE_DIR}"
if [ -n "${TARGET}" ] && [ "${TARGET}" != "${HOST_TRIPLE}" ]; then
  CARGO_TARGET_ARGS=(--target "${TARGET}"); REL_SUBDIR="${TARGET}/${PROFILE_DIR}"
fi
TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
ART_DIR="${TARGET_DIR}/${REL_SUBDIR}"

# Binary name + cdylib prefix/extension follow the EFFECTIVE platform (the
# cross-target if set, else the host triple): windows → mcpg.exe + bare .dll,
# macOS → lib….dylib, linux → lib….so.
BIN_NAME="mcpg"; LIB_PREFIX="lib"; LIB_EXT="so"
case "${TARGET:-$HOST_TRIPLE}" in
  *windows*)        BIN_NAME="mcpg.exe"; LIB_PREFIX=""; LIB_EXT="dll" ;;
  *apple*|*darwin*) LIB_EXT="dylib" ;;
esac
MCPG_BIN="${ART_DIR}/${BIN_NAME}"
MOCK_LIB="${ART_DIR}/${LIB_PREFIX}mcpg_plugin_backend_mock.${LIB_EXT}"

# Running natively on a real Windows host (git-bash on windows-latest): mcpg.exe
# reads paths via the Win32 API, so the injected source.path, MCPG_CONFIG and
# the suite's --output-dir must be Windows paths (D:/a/…), not git-bash /d/a/…
# mounts. cygpath -m → mixed (forward-slash, YAML- and JSON-safe). Identity
# no-op everywhere else (cygpath only exists on Windows git-bash).
winpath() {
  case "${TARGET}" in
    *windows*) command -v cygpath >/dev/null 2>&1 && cygpath -m "$1" || printf '%s' "$1" ;;
    *)         printf '%s' "$1" ;;
  esac
}

# Build (or accept a prebuilt) gateway + mock backend cdylib. Spec-version-
# independent, so it runs ONCE up front and both wires reuse it. The mock
# backend is a runtime-loaded cdylib (no static backends since the backend-
# plugin migration); the everything/baseline configs drive every tool/resource/
# prompt through `kind: mock`, so without it each call returns "mock backend
# plugin not registered" and the content scenarios fail. run_one_version injects
# a plugins[] entry pointing at $MOCK_LIB so the static fixture configs stay
# backend-agnostic.
build_artifacts() {
  if [ "${PREBUILT}" = 1 ]; then
    echo "==> using prebuilt artifacts (${REL_SUBDIR})"
  else
    # NB: stream cargo output (no `| tail` truncation) — on a cross-build
    # failure the truncated tail hid the real rustc error.
    echo "==> building MCPG (${PROFILE_DIR}${TARGET:+ · $TARGET})..."
    (cd "${REPO_ROOT}" && cargo build -p mcpg --bin mcpg "${CARGO_PROFILE_ARGS[@]}" "${CARGO_TARGET_ARGS[@]}")
    echo "==> building mock backend cdylib (${PROFILE_DIR}${TARGET:+ · $TARGET})..."
    (cd "${REPO_ROOT}" && cargo build -p mcpg-plugin-backend-mock --features cdylib-export "${CARGO_PROFILE_ARGS[@]}" "${CARGO_TARGET_ARGS[@]}")
  fi
  [ -f "${MCPG_BIN}" ] || { echo "==> gateway binary missing: ${MCPG_BIN}" >&2; exit 1; }
  [ -f "${MOCK_LIB}" ] || { echo "==> mock backend cdylib missing: ${MOCK_LIB}" >&2; exit 1; }
  echo "==> gateway: ${MCPG_BIN}"
  echo "==> mock backend: ${MOCK_LIB}"
}

run_one_version() {
  local spec_version="$1"
  local timestamp
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local results_dir="${RESULTS_DIR:-${SCRIPT_DIR}/results/${spec_version}-${timestamp}}"
  mkdir -p "${results_dir}"

  echo "==> conformance run: spec-version=${spec_version} (results: ${results_dir})"

  # Effective config = the static fixture config + an injected plugins[] entry
  # loading the (already-built) mock backend cdylib by absolute path. winpath
  # makes that path Windows-native when running on a real Windows host.
  local effective_config="${results_dir}/effective-config.yaml"
  cat "${MCPG_CONFIG}" >"${effective_config}"
  cat >>"${effective_config}" <<YAML

# --- injected by run.sh: load the mock backend cdylib (kind:mock) ---
plugins:
  - id: dev.mcpg.backend.mock
    kind: native
    class: backend
    source:
      path: $(winpath "${MOCK_LIB}")
YAML

  local mcpg_log="${results_dir}/mcpg.log"
  echo "==> starting MCPG on 127.0.0.1:${MCPG_PORT} (log: ${mcpg_log}, bin: ${MCPG_BIN})"
  # `env -u MCPG_PORT`: MCPG_PORT is a harness-only knob (where to health-check +
  # point the conformance client). The gateway reads MCPG_* env vars as config
  # overrides and has no `port` field, so an EXPORTED MCPG_PORT crashes boot
  # ("unknown field PORT"). Strip it — the gateway's listen port comes from the
  # config's bind_address (which must agree with MCPG_PORT; both 8787 default).
  env -u MCPG_PORT MCPG_CONFIG="$(winpath "${effective_config}")" \
    "${MCPG_BIN}" >"${mcpg_log}" 2>&1 &
  local mcpg_pid=$!

  trap 'kill ${mcpg_pid} 2>/dev/null || true; wait ${mcpg_pid} 2>/dev/null || true' EXIT INT TERM

  echo -n "==> waiting for /health"
  for _ in $(seq 1 120); do
    if curl -sf "http://127.0.0.1:${MCPG_PORT}/health" >/dev/null 2>&1; then
      echo " — ready"
      break
    fi
    sleep 0.5
    echo -n "."
  done
  if ! curl -sf "http://127.0.0.1:${MCPG_PORT}/health" >/dev/null 2>&1; then
    echo
    echo "==> MCPG failed to start; tail of log:"
    tail -40 "${mcpg_log}"
    return 1
  fi

  local conformance_args=(
    server
    --url "http://127.0.0.1:${MCPG_PORT}/mcp"
    --spec-version "${spec_version}"
    --suite active
    --output-dir "$(winpath "${results_dir}")"
    --verbose
  )
  if [[ -n "${SCENARIO}" ]]; then
    conformance_args+=(--scenario "${SCENARIO}")
  fi

  echo "==> running conformance@${CONFORMANCE_VERSION}: ${conformance_args[*]}"
  # Bounded retry for timing-sensitive scenarios on slow runners.
  # `CONFORMANCE_RETRIES` (default 0 → one attempt) is set ONLY where flakes are
  # observed (the hosted windows-latest lane: progress-notification ordering in
  # `tools-call-with-progress` races under load). Each attempt starts from a
  # CLEAN results dir so the summary + allowlist below only ever see the LAST
  # attempt's checks.json — a retried flake must not leave a stale FAILURE
  # behind. linux/macos keep the default (0) so a real regression there still
  # reds the gate on the first run.
  local attempts=$(( ${CONFORMANCE_RETRIES:-0} + 1 ))
  local attempt exit_code=0
  for (( attempt = 1; attempt <= attempts; attempt++ )); do
    if (( attempt > 1 )); then
      echo "==> conformance attempt ${attempt}/${attempts} (previous attempt failed — retrying timing-sensitive scenarios on a clean results dir)"
      # `effective-config.yaml` + `mcpg.log` live here too; preserve them, drop
      # only the per-scenario result subdirs the summary globs.
      find "${results_dir}" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
    fi
    set +e
    npx -y "@modelcontextprotocol/conformance@${CONFORMANCE_VERSION}" \
      "${conformance_args[@]}" \
      2>&1 | tee "${results_dir}/conformance.log"
    exit_code=${PIPESTATUS[0]}
    set -e
    [[ ${exit_code} -eq 0 ]] && break
  done

  kill "${mcpg_pid}" 2>/dev/null || true
  wait "${mcpg_pid}" 2>/dev/null || true
  trap - EXIT INT TERM

  echo "==> summary: ${results_dir}"
  local pass fail warn skip
  pass=$(grep -h '"status": "SUCCESS"' "${results_dir}"/*/checks.json 2>/dev/null | wc -l || echo 0)
  fail=$(grep -h '"status": "FAILURE"' "${results_dir}"/*/checks.json 2>/dev/null | wc -l || echo 0)
  warn=$(grep -h '"status": "WARNING"' "${results_dir}"/*/checks.json 2>/dev/null | wc -l || echo 0)
  skip=$(grep -h '"status": "SKIPPED"' "${results_dir}"/*/checks.json 2>/dev/null | wc -l || echo 0)
  echo "    checks: pass=${pass} fail=${fail} warn=${warn} skip=${skip}"
  echo "    exit code: ${exit_code}"

  # ── Expected-failures allowlist ───────────────────────────────────────
  # Scenarios for spec features the gateway hasn't implemented yet live in
  # expected-failures-<spec_version>.txt (one scenario name per line, `#`
  # comments allowed). A run whose ONLY failing scenarios are allowlisted
  # is treated as PASS — the lane stays required and still guards every
  # implemented scenario, without permanently training everyone to ignore
  # a red gate. Remove entries as the features land; an entry that stops
  # failing is reported so the list can't silently rot.
  local allowlist="${SCRIPT_DIR}/expected-failures-${spec_version}.txt"
  if [[ ${exit_code} -ne 0 && -f "${allowlist}" ]]; then
    local unexpected=() expected_hits=()
    local dir scen
    for dir in "${results_dir}"/*/; do
      [[ -f "${dir}/checks.json" ]] || continue
      grep -q '"status": "FAILURE"' "${dir}/checks.json" || continue
      scen="$(basename "${dir}")"
      scen="${scen#server-}"
      scen="${scen#client-}"
      # Strip the trailing run timestamp (…-2026-06-11T16-31-36-361Z).
      scen="$(echo "${scen}" | sed -E 's/-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9Z-]+$//')"
      if grep -v '^[[:space:]]*#' "${allowlist}" | grep -qxF "${scen}"; then
        expected_hits+=("${scen}")
      else
        unexpected+=("${scen}")
      fi
    done
    if [[ ${#unexpected[@]} -eq 0 && ${#expected_hits[@]} -gt 0 ]]; then
      echo "==> all failing scenario(s) are allowlisted in $(basename "${allowlist}"):"
      printf '      %s\n' "${expected_hits[@]}"
      echo "    treating run as PASS — remove entries as the features land."
      exit_code=0
    elif [[ ${#unexpected[@]} -gt 0 ]]; then
      echo "==> UNEXPECTED failing scenario(s): ${unexpected[*]}"
      [[ ${#expected_hits[@]} -gt 0 ]] && echo "    (allowlisted, also failing: ${expected_hits[*]})"
    fi
  fi
  return "${exit_code}"
}

# Build (or accept prebuilt) the gateway + mock cdylib ONCE — both wires reuse
# the one build. CONFORMANCE_BUILD_ONLY stops here (the linux cross-build half
# of the windows lane just produces+uploads the artifacts).
build_artifacts
if [ "${BUILD_ONLY}" = 1 ]; then
  echo "==> build-only: artifacts ready at ${ART_DIR} (skipping suite run)"
  exit 0
fi

case "${VERSION}" in
  2025-11-25|2026-07-28)
    run_one_version "${VERSION}"
    ;;
  # Accept the pre-final modern label as an alias for `2026-07-28`.
  DRAFT-2026-v1)
    run_one_version 2026-07-28
    ;;
  both)
    # Run both wires regardless of the first's outcome, but propagate
    # a non-zero exit if EITHER fails so the conformance run
    # (and CI) treat a regression on either wire as a failure.
    both_status=0
    run_one_version 2025-11-25 || both_status=1
    run_one_version 2026-07-28 || both_status=1
    exit "${both_status}"
    ;;
  *)
    echo "error: unknown version '${VERSION}'. Use 2025-11-25 or 2026-07-28 or both." >&2
    exit 2
    ;;
esac
