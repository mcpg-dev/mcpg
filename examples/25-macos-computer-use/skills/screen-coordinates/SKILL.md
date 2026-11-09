---
name: screen-coordinates
description: Take screenshots of a display, a region or a window, and turn a point you see in a screenshot into a correct click, drag, scroll or mouse move, on one or several displays and on Retina screens.
license: Apache-2.0
metadata:
  version: "1.0"
---

# Screenshots and coordinates

## Two coordinate systems

- **Global points.** What every input tool works in. The top-left of the main
  display is `0,0`, `x` grows right, `y` grows down. A display left of or
  above the main one has negative coordinates. `desktop.status` lists every
  display's frame in global points.
- **Screenshot pixels.** What you see in an image from `screen.screenshot`.
  The image is scaled down (the long edge is at most `max_long_edge`, default
  1568 px), so a pixel is not a point.

## The one rule

`screen.screenshot` returns `scale`, `origin_x` and `origin_y` (in the text
block and in `structuredContent`). To act on pixel `(px, py)` of that image,
pass to the input tool:

```json
{ "x": px, "y": py, "scale": <scale>, "origin_x": <origin_x>, "origin_y": <origin_y> }
```

Copy the three numbers unchanged from the **latest** screenshot. The tool
computes `global = origin + pixel × scale` itself. Do not do the arithmetic
yourself, and do not reuse the numbers of an older screenshot after a window
moved or you captured another region.

Without `scale` / `origin_*`, `x` / `y` are global points.

`input.drag` takes the same three numbers for both `from_*` and `to_*`.

## Choosing what to capture

| Need | Call |
|---|---|
| Overview of the main display | `screen.screenshot` |
| Another display | `screen.screenshot display: 2` (index from `desktop.status`) |
| Small text | `screen.screenshot region: {x, y, width, height}` in global points — fewer points per pixel, so text is sharper |
| One window, even when covered | `window.list`, then `screen.screenshot window_id: <id>` |
| Exact colours or thin lines | `format: png` (larger) |

A region or window screenshot has its own `origin_x` / `origin_y`: use them,
not the display's.

## Aim well

- Aim at the centre of a control, not its edge.
- Small targets: take a region screenshot around the target first, then click
  with that screenshot's numbers.
- After a click, take a new screenshot and check the result before the next
  action. A click that "did nothing" often hit the wrong window: check which
  app is in front.
- Prefer `ui.find` + `ui.action` (see the `ui-automation` skill) when the
  element is in the accessibility tree. Pixels are the fallback.

More on several displays and Retina scaling: `references/multi-display.md`.
