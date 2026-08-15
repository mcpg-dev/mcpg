# 24 — Home Assistant

MCP server over a Home Assistant instance's REST API. Great for
personal smart-home automation driven by an agent.

## Upstream

- Docs: https://developers.home-assistant.io/docs/api/rest/
- Auth: Bearer long-lived access token.

## Env vars

| Var | Purpose |
|---|---|
| `HA_URL`   | Base URL (e.g. `http://homeassistant.local:8123`) |
| `HA_TOKEN` | Long-lived access token |

## Run

```bash
cargo run -p mcpg -- --config examples/24-home-assistant/config.yaml
```

## Exposed tools

- `ha.states` — snapshot of every entity.
- `ha.state.get` — single entity.
- `ha.service.call` — call any `domain.service` (light.turn_on,
  scene.turn_on, climate.set_temperature, ...).
- `ha.template.render` — evaluate a Home Assistant template.
- `ha.events.fire` — custom events for automations.

## Resource template

- `ha://entity/{entity_id}` — bind a single entity as a resource
  the client can read.
