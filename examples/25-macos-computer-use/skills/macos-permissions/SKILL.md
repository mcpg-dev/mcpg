---
name: macos-permissions
description: Diagnose and explain missing macOS privacy permissions (Screen Recording, Accessibility, Automation, browser JavaScript from Apple Events) when a computer-use tool fails, returns an empty result or desktop.status reports a permission as false.
license: Apache-2.0
metadata:
  version: "1.0"
---

# macOS permissions

macOS grants privacy permissions to the **app that starts mcpg** — Claude
Desktop, or the terminal app (Terminal, iTerm2, VS Code) that runs Claude
Code — not to `mcpg` itself. The user must grant them; you cannot.

## Diagnose

1. Call `desktop.status` and read `permissions`:
   - `screen_recording: false` — screenshots fail and `window.list` has no
     titles;
   - `accessibility: false` — `input.*`, `ui.*`, `window.focus` and
     `window.set_bounds` fail or do nothing.
2. Match the failing tool's error text with `references/error-messages.md`.

## Tell the user

Give one short instruction, the exact place, and what to restart:

> Open System Settings > Privacy & Security > **Screen & System Audio
> Recording** (or **Accessibility**), turn on **<the app that runs me>**,
> then quit and reopen that app.

- The change takes effect only after that app restarts. After the user
  restarts, call `desktop.status` again before you continue.
- **Automation** is asked per target app on first use (System Events,
  Terminal, iTerm2, Safari, Chrome). A dialog appears on the user's screen:
  ask the user to click OK. If they clicked "Don't Allow" before, the switch
  is in System Settings > Privacy & Security > Automation.
- **Browser JavaScript** is a browser setting, not a macOS one: see the
  `browser-tasks` skill.

## Do not

- Do not open System Settings and click the switches yourself. A permission
  is the user's decision, and macOS asks for the user's password there.
- Do not loop on a failing tool. One diagnosis, one instruction, then wait for
  the user.
