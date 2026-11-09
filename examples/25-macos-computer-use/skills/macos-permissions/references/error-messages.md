# Error messages and their cause

| Error text (start) | Cause | Fix |
|---|---|---|
| `screencapture wrote no image; grant Screen Recording …` | Screen Recording not granted | Screen & System Audio Recording, then restart the app |
| `the app has no accessible windows (check the Accessibility permission)` | Accessibility not granted, or the app has no window | Accessibility, then restart; or open a window first |
| `Not authorized to send Apple events to …` | Automation for that app was refused | Privacy & Security > Automation |
| `the browser refused to run JavaScript (…)` | "Allow JavaScript from Apple Events" is off | Browser setting (see `browser-tasks`) |
| `no Terminal or iTerm2 session uses …` | The tty closed or the app is not running | `terminal.list` again |
| `no window with id …; call window.list` / `no such window` | The window closed or the id is old | `window.list` again |
| `element … is now …; call ui.find again` | The UI changed after `ui.find` | `ui.find` again |
| `invalid element path: …` | A path that never came from `ui.tree` / `ui.find` | Use a returned `path` |
| `unknown argument: …` / `unknown key: …` | An argument the tool does not take | Check the tool's input schema |
| `refusing to signal pid …` / `refusing to quit …` | A protected process or app | Do not retry; tell the user |

A tool that returns successfully but with empty fields (no window titles, an
empty tree) usually means a missing permission too: check `desktop.status`.
