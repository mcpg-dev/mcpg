# Tool map

| Tool | Use it to | Notes |
|---|---|---|
| `desktop.status` | Learn displays, cursor, frontmost app, permissions | Call first |
| `desktop.wait` | Wait 0–30000 ms | Before a screenshot of a loading app |
| `screen.screenshot` | See a display, a region or one window | Returns `scale`, `origin_x`, `origin_y` |
| `input.mouse_move` | Move the pointer | Hover menus and tooltips |
| `input.click` | Click, double click (`clicks: 2`), right click | `modifiers: [cmd, shift, option, ctrl]` |
| `input.drag` | Press, move, release | `duration_ms` for slow drags |
| `input.scroll` | Scroll at a point | `delta_y > 0` scrolls down |
| `input.type_text` | Type into the focused field | Long or non-ASCII text goes through the clipboard |
| `input.key` | Keys and shortcuts | `cmd+c`, `enter`, `escape`, `repeat` 1–50 |
| `clipboard.read` / `clipboard.write` | Plain-text clipboard | |
| `app.list` / `app.activate` / `app.launch` / `app.quit` | Apps | Prefer `bundle_id`; quit may show a save dialog |
| `window.list` / `window.focus` / `window.set_bounds` | Windows | `window.list` ids feed `screen.screenshot window_id` |
| `ui.find` | Search the accessibility tree | Text and/or role, case-insensitive |
| `ui.tree` | Walk the accessibility tree | Bounded by `max_depth` / `max_nodes` |
| `ui.action` | `AXPress`, `AXShowMenu`, `AXConfirm`, `focus`, … | Pass `expect_role` / `expect_title` |
| `ui.set_value` | Set a field, slider or text area exactly | Faster than typing |
| `terminal.list` / `terminal.read` / `terminal.send` | Terminal.app and iTerm2 by `tty` | `send` asks the user first |
| `browser.tabs` / `browser.read_page` / `browser.open_url` / `browser.eval` | Safari, Chrome, Brave, Edge | `eval` asks the user first |
| `process.list` / `process.signal` | Processes | `signal` asks the user first |
