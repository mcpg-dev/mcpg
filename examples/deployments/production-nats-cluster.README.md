# production-nats-cluster

NATS JetStream variant of the multi-replica cluster topology. Functionally equivalent to `production-redis-cluster` — every replica coordinates via the same external service — but uses NATS for both KV state (JetStream KV bucket) and the pub/sub bus (NATS subjects).

## When to pick NATS over Redis

- You already run NATS for other services and want one less moving part.
- You need the wider pub/sub fan-out NATS gives you (subject hierarchies, consumer groups).
- Your platform team has stronger ops experience with NATS than Redis.

## What to change

Same as `production-redis-cluster` for the server / auth / audit / bindings / observability blocks. NATS-specific bits:

| Field | Why |
|---|---|
| `cluster.url` (`MCPG_NATS_URL`) | `tls://` or `nats://` connection. Use `tls://` outside localhost. |
| `cluster.bucket` | JetStream KV bucket name. Operators usually segment per-deployment. |

## Required env vars

- `MCPG_NATS_URL` — NATS connection.
- `MCPG_OIDC_CLIENT_ID`, `MCPG_OIDC_CLIENT_SECRET` — IdP credentials.

## Audit

Same as `production-redis-cluster`: the bundled sink is `dev.mcpg.builtin.audit.local-file` only (no built-in object-storage sink). Each replica writes hash-chained JSON Lines to its host-mounted `governance.audit.sinks[0].config.path`; forward that file to a central SIEM, or register your own `audit_sink` plugin for an off-node trail.

## NATS-specific operational notes

- **Subject hierarchy.** Cluster pub/sub uses `mcpg.{deployment}.delivery.>` etc. — confirm your NATS account permissions allow publish + subscribe on `mcpg.>`.
- **JetStream replication.** Match `bucket`'s replication factor to your durability needs; default 1 is fine for dev, ≥3 for prod.
- **Connection limits.** NATS clusters often cap clients per node — confirm your gateway replica count fits before scale-up.
