# 25 — macOS computer use

A local MCP server that sees and drives the whole Mac desktop, built only from
the stock command backend and `osascript` (JavaScript for Automation). macOS
only; Apple silicon.

## Tools

| Area | Tools |
|---|---|
| Desktop | `desktop.status` (displays, cursor, frontmost app, permissions), `desktop.wait` |
| Screen | `screen.screenshot` — a display, a region or one window, as an image block |
| Input | `input.mouse_move`, `input.click`, `input.drag`, `input.scroll`, `input.type_text`, `input.key` |
| Clipboard | `clipboard.read`, `clipboard.write` |
| Apps | `app.list`, `app.activate`, `app.launch`, `app.quit` |
| Windows | `window.list`, `window.focus`, `window.set_bounds` |
| Accessibility | `ui.tree`, `ui.find`, `ui.action` (press, show menu, …), `ui.set_value` |
| Terminals | `terminal.list`, `terminal.read`, `terminal.send` (Terminal.app and iTerm2) |
| Browsers | `browser.tabs`, `browser.read_page`, `browser.open_url`, `browser.eval` (Safari, Chrome, Brave, Edge) |
| Processes | `process.list`, `process.signal` |

`terminal.send`, `process.signal` and `browser.eval` show the user the exact
text, process or script and ask first (MCP elicitation). A client without
elicitation support gets an error and nothing runs.

## Run

```bash
mkdir -p ~/Library/Logs/mcpg
claude mcp add mac-desktop -- mcpg --stdio --config /path/to/examples/25-macos-computer-use/config.yaml
```

Claude Desktop (`claude_desktop_config.json`):

```json
{ "mcpServers": { "mac-desktop": {
    "command": "/opt/homebrew/bin/mcpg",
    "args": ["--stdio", "--config", "/path/to/examples/25-macos-computer-use/config.yaml"] } } }
```

The plugins are pulled from `ghcr.io` on the first start.

## macOS permissions

System Settings > Privacy & Security. macOS gives these to the app that
**starts** `mcpg` (Claude Desktop, or your terminal app for Claude Code), not
to `mcpg` itself. Restart that app after you grant one.

| Permission | Needed by |
|---|---|
| Screen & System Audio Recording | `screen.screenshot`, window titles in `window.list` |
| Accessibility | `input.*`, `ui.*`, `window.focus`, `window.set_bounds` |
| Automation | asked on first use, per app: System Events, Terminal, iTerm2, Safari, Chrome, … |

`browser.read_page` and `browser.eval` also need "Allow JavaScript from Apple
Events" (Safari: Develop menu; Chrome: View > Developer).

## Coordinates

Input tools use macOS global points: the top-left of the main display is 0,0.
`screen.screenshot` returns `scale`, `origin_x` and `origin_y`; an input tool
that gets those three numbers takes `x` / `y` in screenshot pixels.

## Safety

- stdio only: no network port. Do not serve this file over HTTP; an anonymous
  local port that moves the mouse is open to every local process and web page.
- Arguments reach each script as JSON on stdin, never as code. The gateway
  checks them against each tool's `input_schema` and the script checks them
  again.
- `input.type_text` and `input.key` can type anything the user can, terminals
  included, without a confirmation. Keep the MCP client's own per-call
  approval on.
- Every call is written to `~/Library/Logs/mcpg/computer-use-audit.jsonl`,
  arguments included (set `include_arguments: false` to keep only a digest),
  and the destructive tools are rate limited.
