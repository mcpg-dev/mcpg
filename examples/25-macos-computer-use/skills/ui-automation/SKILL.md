---
name: ui-automation
description: Press buttons, fill text fields, pick menu items and read app state through the macOS accessibility tree (ui.find, ui.tree, ui.action, ui.set_value), which is exact and survives window moves, instead of clicking at pixel coordinates.
license: Apache-2.0
metadata:
  version: "1.0"
---

# Accessibility-first UI automation

The accessibility (AX) tree describes every control of an app: its role
(`AXButton`, `AXTextField`, `AXCheckBox`, `AXMenuItem`, …), title, description,
value and frame. Acting on the tree is exact; clicking pixels is a guess.

## Find, then act

1. Bring the app to the front: `app.activate` (or `app.launch`).
2. `ui.find` with `text` and/or `role`, for example
   `{ "text": "Save", "role": "AXButton" }`. Text matching is
   case-insensitive and also searches description and value.
3. Pick the match whose frame and title fit. Each match has a `path` such as
   `w0/3/1` (window 0, child 3, child 1).
4. Act:
   - a button, link, checkbox or menu item: `ui.action` with `AXPress`;
   - a text field, text area or slider: `ui.set_value` (exact, no typing);
   - a pop-up or context menu: `AXShowMenu`, then `ui.find` the item;
   - a stepper: `AXIncrement` / `AXDecrement`;
   - keyboard focus: `action: focus`, then `input.type_text`.
5. Always pass `expect_role` and `expect_title` (from the match) to
   `ui.action`. When the UI changed, the tool refuses the stale path instead of
   pressing something else; call `ui.find` again.
6. Verify with `ui.find` (the new value or state) or a screenshot.

Use `ui.tree` when `ui.find` returns too many or no matches: read the
structure near the target with a small `max_depth`, then search again with
better text.

## When the tree is not enough

- **No accessible windows** — the Accessibility permission is missing, or the
  app has no window yet. See `macos-permissions`.
- **Chromium and Electron apps** (Chrome, Slack, VS Code, Discord) hide web
  content from the tree. Pass `web_accessibility: true` to `ui.tree` /
  `ui.find` to ask the app to expose it. If it still shows nothing, use
  screenshots and coordinates (`screen-coordinates` skill).
- **Canvas content** (games, maps, image editors) has no elements. Use
  coordinates.
- **Menu bar:** the app's menus are in its tree under the menu bar; `ui.find`
  the menu title, `AXPress` it, then `ui.find` the item. A keyboard shortcut
  (`input.key cmd+s`) is often simpler.

## Keyboard shortcuts

`input.key` sends a key or combination to the frontmost app: `enter`,
`escape`, `tab`, `space`, arrow keys, `page_down`, `cmd+a`, `cmd+shift+t`,
`ctrl+c`. Use them for actions with a well-known shortcut. Check which app is
in front first.
