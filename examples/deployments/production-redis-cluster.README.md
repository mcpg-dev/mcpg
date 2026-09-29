# production-redis-cluster

Multi-replica production gateway behind a load balancer, every replica coordinating via the same Redis cluster. Designed for kubernetes Deployment semantics (any replica answers any session, drain on shutdown is safe).

## What's different from `production-single-redis`

- **Longer drain window** (`server.shutdown_timeout_ms: 60000`) — gives in-flight SSE streams a chance to complete before SIGTERM forces a cut.
- **Cluster pub/sub for delivery + cancellation** — `delivery:` and `cancellation:` are intentionally omitted so the buses inherit the cluster's pub/sub primitive (Redis pub-sub here). A `notifications/cancelled` published on replica-A reaches the active SSE stream on replica-B.
- **OTLP traces enabled** pointing at an in-cluster collector, through the `dev.mcpg.observability.otlp` plugin.

Like single-redis, the `plugins` list names every plugin the file uses: `dev.mcpg.cluster.redis`, `dev.mcpg.identity.oidc`, `dev.mcpg.observability.prometheus` and `dev.mcpg.observability.otlp`. The gateway image carries no plugins. Without the Redis or the OIDC entry the gateway refuses to boot; without a sink's entry it boots and does not export that signal. The Redis coordinator is a licensed plugin, so the `license` block is the same as in single-redis.

> **Audit fan-out.** The bundled audit sink today is `dev.mcpg.builtin.audit.local-file` only — there is no built-in S3/object-storage sink. Each replica writes hash-chained JSON Lines to its own `path`. Mount that path on a host volume and forward it to a central SIEM (filebeat / vector / fluentbit sidecar, or a CloudWatch/Datadog agent) so the trail is greppable across all N pods. Operators who need a first-party off-node sink register their own `audit_sink` plugin and add its id to `audit.sinks[]`.

## What to change

| Field | Why |
|---|---|
| `server.allowed_origins`, `server.tls` | Same as single-redis. |
| `governance.access.oidc_oauth.providers`, the `dev.mcpg.identity.oidc` entry | Same as single-redis: your IdP's issuer and audience in both places. |
| `plugins[*].source.oci` | The plugin releases that match the gateway you run, or your mirror of them. |
| `cluster.url` | Multi-replica deploys need a TLS Redis endpoint with sufficient connection capacity. |
| `governance.audit.sinks[0].config.path` | Host-mounted audit file each replica appends to. Forward it to your SIEM. |
| `config.url` of the `dev.mcpg.observability.otlp` entry | Your OTel Collector's OTLP/gRPC endpoint (port 4317 by default). |

## Required env vars

- `MCPG_REDIS_URL` — Redis cluster connection.
- `MCPG_REDIS_PASSWORD` — Redis password, passed out of the URL.
- `MCPG_CLUSTER_STATE_KEY` — URL-safe-base64 32-byte state-encryption key, identical on every replica (`openssl rand -base64 32 | tr '+/' '-_'`). Required whenever `cluster.kind` is not `single_node`.
- `MCPG_LICENSE_PUBKEY` — the public key (SPKI PEM) that verifies the license token.
- `ACCOUNTS_API_TOKEN` — for the placeholder binding (drop with the binding).

## Operational notes

- **Rolling restarts:** the `shutdown_timeout_ms: 60000` drain works in concert with the LB's deregistration + your `terminationGracePeriodSeconds`. Set the latter ≥ `shutdown_timeout_ms / 1000 + 5` to leave headroom for the OS-level signal cascade.
- **Redis HA:** the gateway tolerates Redis failover with reconnect, but in-flight tool calls during the failover may surface as transport errors. A tool's `retry.retry_on_transport_error: true` (under `mcp.capabilities.tools[].retry`, the default) recovers the affected calls automatically.
