# 16 — iOS Simulator (xcrun simctl)

MCP server that wraps Apple's `xcrun simctl` CLI so an AI agent
can drive the iOS Simulator end-to-end.

## Upstream

- Local `xcrun simctl` (ships with Xcode).
- macOS only.

## Env vars

None. Inherits `DEVELOPER_DIR` from the shell (set via
`xcode-select`).

## Run

```bash
cargo run -p mcpg -- --config examples/16-ios-simulator/config.yaml
```

## Exposed tools

- `ios.simulator.list` — all devices + runtimes (JSON).
- `ios.simulator.boot` / `shutdown` — lifecycle.
- `ios.simulator.install_app` — install a .app bundle.
- `ios.simulator.launch` — launch an installed app.
- `ios.simulator.screenshot` — write a PNG to disk.
- `ios.simulator.openurl` — deep-link / universal link.
- `ios.simulator.privacy_grant` — grant a privacy permission
  to an installed bundle.
- `ios.simulator.erase` — factory reset.

## Resource template

- `simctl://{device_udid}/app/{bundle_id}/data` — returns the
  sandbox container path for an installed app.

## Patterns

Chain `ios.simulator.boot` → `ios.simulator.install_app` →
`ios.simulator.launch` → `ios.simulator.screenshot` in a
Pipeline for an end-to-end "bring up device and show me what
the app looks like" flow.
