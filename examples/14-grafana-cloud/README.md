# 14 — Grafana Cloud (+ Loki + Mimir)

MCP server bridging Grafana dashboards, Loki logs, and Mimir
metrics behind a single configuration.

## Upstream

- Grafana HTTP API: https://grafana.com/docs/grafana/latest/developers/http_api/
- Loki query API: https://grafana.com/docs/loki/latest/reference/api/
- Mimir (Prometheus-compatible) API.

## Env vars

| Var | Purpose |
|---|---|
| `GRAFANA_URL` | e.g. `https://acme.grafana.net` |
| `LOKI_URL`    | e.g. `https://logs-prod3.grafana.net` |
| `MIMIR_URL`   | e.g. `https://prom-prod-nn.grafana.net` |
| `GRAFANA_TOKEN` | Cloud API key with appropriate scope |

## Run

```bash
cargo run -p mcpg -- --config examples/14-grafana-cloud/config.yaml
```

## Exposed tools

- `gf.dashboards.list` — search dashboards.
- `gf.dashboard.get` — full JSON by UID.
- `gf.loki.query` — LogQL `query_range`.
- `gf.mimir.query` — PromQL instant query.
- `gf.alert.rules` — list Grafana-managed rules.

## Pattern: summarize logs with sampling

A pipeline can layer `gf.loki.query` → `Sampling` to have the
model summarize a log slice; enable client
`capabilities.sampling` so the pipeline is allowed to emit.
