# 17 — Android adb + emulator

MCP server wrapping `adb` for Android development/QA.

## Upstream

- Local `adb` CLI (Android platform tools).

## Env vars

None. `ANDROID_HOME` / `ANDROID_SDK_ROOT` must point at the
platform tools so `adb` is on `PATH`.

## Run

```bash
cargo run -p mcpg -- --config examples/17-android-adb/config.yaml
```

## Exposed tools

- `adb.devices` — list connected devices / emulators.
- `adb.install` / `adb.uninstall` — app lifecycle.
- `adb.shell.am_start` — launch an activity.
- `adb.input.tap` / `adb.input.text` — UI automation primitives.
- `adb.screencap` — write a PNG to local disk (uses `exec-out`
  so binary stdout is piped safely).
- `adb.logcat.tail` — last N lines.
- `adb.push` — copy a file onto the device.

## Note

The `adb.screencap` binding uses a tiny `sh -c` invocation
because `adb exec-out screencap -p` writes binary bytes to
stdout; the MCPG Command binding does not redirect binary
stdout on its own. The `sh -c 'adb ... > "$2"' -- serial path`
pattern keeps argument passing safe — args are still passed
through `execve`, never concatenated into the shell string.
