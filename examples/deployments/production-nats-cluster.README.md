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
| `cluster.servers` (`MCPG_NATS_URL`) | NATS server URLs. TLS is required by default, so use `tls://`; a plaintext `nats://` link needs `tls: { require_tls: false }` and `allow_insecure_transport: true`. |
| `cluster.jetstream.state_bucket` | JetStream KV bucket for capability state. Operators usually segment per-deployment. |
| The `dev.mcpg.cluster.nats` entry in `plugins` | The coordinator `cluster.kind: nats` selects, in place of `dev.mcpg.cluster.redis`. Without it the gateway refuses to boot. Pin the release that matches the gateway you run. Like the Redis coordinator it is a licensed plugin, so the `license` block is the same. |

## Required env vars

- `MCPG_NATS_URL` — NATS connection.
- `MCPG_CLUSTER_STATE_KEY` — URL-safe-base64 32-byte state-encryption key, identical on every replica (`openssl rand -base64 32 | tr '+/' '-_'`). Required whenever `cluster.kind` is not `single_node`.
- `MCPG_LICENSE_PUBKEY` — the public key (SPKI PEM) that verifies the license token.
- `HOSTNAME` — the replica's `cluster.node.id`, which must be unique per replica. A container runtime exports it. A shell such as bash sets it but does not export it, so export it (`export HOSTNAME`) when you run the gateway outside a container.

## Audit

Same as `production-redis-cluster`: the bundled sink is `dev.mcpg.builtin.audit.local-file` only (no built-in object-storage sink). Each replica writes hash-chained JSON Lines to its host-mounted `governance.audit.sinks[0].config.path`; forward that file to a central SIEM, or register your own `audit_sink` plugin for an off-node trail.

## NATS-specific operational notes

- **Subject hierarchy.** Cluster pub/sub uses `mcpg.{deployment}.delivery.>` etc. — confirm your NATS account permissions allow publish + subscribe on `mcpg.>`.
- **JetStream replication.** Match `cluster.jetstream.replicas` to your durability needs; the default 1 suits a single-node dev NATS, 3 (as here) a production cluster.
- **Connection limits.** NATS clusters often cap clients per node — confirm your gateway replica count fits before scale-up.
