# 15 — Datadog

MCP server over Datadog's metrics, logs, monitors, incidents, and
SLOs.

## Upstream

- Docs: https://docs.datadoghq.com/api/latest/
- Auth: `DD-API-KEY` + `DD-APPLICATION-KEY` header pair.

## Env vars

| Var | Purpose |
|---|---|
| `DD_API_KEY` | Organization API key |
| `DD_APP_KEY` | User application key (scoped) |

## Run

```bash
cargo run -p mcpg -- --config examples/15-datadog/config.yaml
```

## Exposed tools

- `dd.metric.query` — instant/range metric query.
- `dd.logs.search` — logs explorer query with time window.
- `dd.monitors.list` — list monitors by trigger state.
- `dd.monitor.mute` — mute (optionally with auto-unmute).
- `dd.incident.create` — create an incident.
- `dd.slo.status` — SLO history for a given window.

## Region

Defaults to `datadoghq.com`; substitute `datadoghq.eu` or your
region-specific host in `config.yaml` with a single
find-and-replace.
