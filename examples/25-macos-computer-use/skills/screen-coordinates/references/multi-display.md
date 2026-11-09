# Several displays and Retina scaling

`desktop.status` returns each display as a frame in global points, for
example:

```json
[{ "index": 1, "main": true, "name": "Built-in Retina Display",
   "x": 0, "y": 0, "width": 1512, "height": 982, "backing_scale": 2 },
 { "index": 2, "main": false, "name": "DELL U2720Q",
   "x": -1920, "y": -98, "width": 1920, "height": 1080, "backing_scale": 1 }]
```

- Display 2 is left of the main display, so its points have negative `x`.
- A point belongs to the display whose frame holds it. A click outside every
  frame lands at the nearest edge.
- Global points are not physical pixels. `backing_scale: 2` is a Retina
  display with two pixels per point; macOS handles that, and the input tools
  always take points.
- `screen.screenshot display: 2` returns `origin_x: -1920, origin_y: -98` and
  its own `scale`. Pass those to the input tool and give `x` / `y` in that
  screenshot's pixels.

## Checks when a click misses

1. Did you pass the `scale` / `origin_*` of the screenshot you are looking at?
2. Did the window move or the display layout change since that screenshot?
3. Is the target on another display than you think? Compare its global point
   with the display frames.
4. Is something on top (a tooltip, a sheet, a notification)? Take a new
   screenshot.
