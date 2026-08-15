# 25 — macOS system (shortcuts + open + osascript)

MCP server for macOS power users. Wraps `shortcuts`, `open`,
`osascript`, `screencapture`, `pbcopy`/`pbpaste` as typed MCP
tools.

## Upstream

Local macOS CLIs. macOS only.

## Env vars

None.

## Run

```bash
cargo run -p mcpg -- --config examples/25-macos-system/config.yaml
```

## Exposed tools

- `mac.shortcuts.list` / `mac.shortcuts.run` — Shortcuts app.
- `mac.open.url` / `mac.open.file` — open URLs and files.
- `mac.notify` — display a notification.
- `mac.screencapture` — PNG to disk.
- `mac.clipboard.get` / `mac.clipboard.set` — pasteboard I/O via
  stdin.
- `mac.apps.running` — list foreground apps.
- `mac.app.focus` — bring an app to the front.

## Safety

AppleScript inline via `osascript -e` can be misused. The
bindings here only expose narrow verbs; do not add a generic
`run_applescript` tool without the guardrails plugin gating it.
