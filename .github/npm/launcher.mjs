#!/usr/bin/env node
// Launcher for the mcpg npm suite. Every bin entry (mcpg, mcpg-config,
// mcpg-cloud, mcpg-plugin) points here; the invoked name selects which
// embedded binary to exec from the platform package that npm's os/cpu/libc
// filtering actually installed.
//
// The whole suite rides in ONE platform package because `mcpg` is a
// dispatcher: `mcpg config|cloud|plugin|control-plane` exec their mcpg-*
// siblings by PATH (and `mcpg --control-plane` supervises
// mcpg-control-plane), and the .bin directory this launcher lives in is on
// the child's PATH under both npm-run and npx.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

function isMusl() {
  // glibc advertises itself in the process report; its absence on linux
  // means musl. The report call is cheap and needs no child process.
  try {
    const report = process.report?.getReport();
    if (report?.header && "glibcVersionRuntime" in report.header) {
      return !report.header.glibcVersionRuntime;
    }
  } catch {
    /* fall through */
  }
  return false;
}

const PLATFORMS = {
  "linux-x64": "@mcpg-dev/cli-linux-x64",
  "linux-x64-musl": "@mcpg-dev/cli-linux-x64-musl",
  "linux-arm64": "@mcpg-dev/cli-linux-arm64",
  "linux-arm64-musl": "@mcpg-dev/cli-linux-arm64-musl",
  "darwin-arm64": "@mcpg-dev/cli-darwin-arm64",
  "win32-x64": "@mcpg-dev/cli-win32-x64",
};

const key =
  process.platform === "linux"
    ? `linux-${process.arch}${isMusl() ? "-musl" : ""}`
    : `${process.platform}-${process.arch}`;

const pkg = PLATFORMS[key];
const invoked = path
  .basename(process.argv[1] ?? "mcpg")
  .replace(/\.(mjs|js|cmd|ps1)$/i, "");
const exe = process.platform === "win32" ? `${invoked}.exe` : invoked;

if (!pkg) {
  console.error(
    `mcpg: unsupported platform ${process.platform}/${process.arch}. ` +
      `Prebuilt binaries cover: ${Object.keys(PLATFORMS).join(", ")}. ` +
      `Use the install script or a release tarball instead.`,
  );
  process.exit(1);
}

let binPath;
try {
  const pkgJson = require.resolve(`${pkg}/package.json`);
  binPath = path.join(path.dirname(pkgJson), "bin", exe);
} catch {
  console.error(
    `mcpg: platform package ${pkg} is not installed. ` +
      `npm skips optionalDependencies when --omit=optional (or --no-optional) ` +
      `is set — reinstall without it, or install ${pkg} explicitly.`,
  );
  process.exit(1);
}

if (!fs.existsSync(binPath)) {
  console.error(`mcpg: ${exe} missing from ${pkg} — corrupt install; reinstall.`);
  process.exit(1);
}

const child = spawnSync(binPath, process.argv.slice(2), {
  stdio: "inherit",
  // The dispatcher resolves `mcpg <x>` to a sibling mcpg-<x> on PATH; make
  // sure the platform package's bin dir wins even outside npm-run contexts.
  env: {
    ...process.env,
    PATH: `${path.dirname(binPath)}${path.delimiter}${process.env.PATH ?? ""}`,
  },
});
if (child.error) {
  console.error(`mcpg: failed to exec ${binPath}: ${child.error.message}`);
  process.exit(1);
}
process.exit(child.status ?? 1);
