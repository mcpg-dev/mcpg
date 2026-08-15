# production-redis-cluster

Multi-replica production gateway behind a load balancer, every replica coordinating via the same Redis cluster. Designed for kubernetes Deployment semantics (any replica answers any session, drain on shutdown is safe).

## What's different from `production-single-redis`

- **Higher cluster pool size** (`cluster.pool_size: 32`) — more concurrent connections survive thundering-herd reconnects on rolling restart.
- **Longer drain window** (`server.shutdown_timeout_ms: 60000`) — gives in-flight SSE streams a chance to complete before SIGTERM forces a cut.
- **Cluster pub/sub for delivery + cancellation** — `delivery:` and `cancellation:` are intentionally omitted so the buses inherit the cluster's pub/sub primitive (Redis pub-sub here). A `notifications/cancelled` published on replica-A reaches the active SSE stream on replica-B.
- **OTLP traces enabled** pointing at an in-cluster collector.

> **Audit fan-out.** The bundled audit sink today is `dev.mcpg.builtin.audit.local-file` only — there is no built-in S3/object-storage sink. Each replica writes hash-chained JSON Lines to its own `path`. Mount that path on a host volume and forward it to a central SIEM (filebeat / vector / fluentbit sidecar, or a CloudWatch/Datadog agent) so the trail is greppable across all N pods. Operators who need a first-party off-node sink register their own `audit_sink` plugin and add its id to `audit.sinks[]`.

## What to change

| Field | Why |
|---|---|
| `server.allowed_origins`, `server.tls` | Same as single-redis. |
| `cluster.url` | Multi-replica deploys need a TLS Redis endpoint with sufficient connection capacity. |
| `governance.audit.sinks[0].config.path` | Host-mounted audit file each replica appends to. Forward it to your SIEM. |
| `observability.traces.sinks[0].config.url` | Your OTel Collector endpoint. |

## Required env vars

- `MCPG_REDIS_URL` — Redis cluster connection.
- `MCPG_OIDC_CLIENT_ID`, `MCPG_OIDC_CLIENT_SECRET` — IdP credentials.
- `ACCOUNTS_API_TOKEN` — for the placeholder binding (drop with the binding).

## Operational notes

- **Rolling restarts:** the `shutdown_timeout_ms: 60000` drain works in concert with the LB's deregistration + your `terminationGracePeriodSeconds`. Set the latter ≥ `shutdown_timeout_ms / 1000 + 5` to leave headroom for the OS-level signal cascade.
- **Redis HA:** the gateway tolerates Redis failover with reconnect, but in-flight tool calls during the failover may surface as transport errors. A tool's `retry.retry_on_transport_error: true` (under `mcp.capabilities.tools[].retry`, the default) recovers the affected calls automatically.
