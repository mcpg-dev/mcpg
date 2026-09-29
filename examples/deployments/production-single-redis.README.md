# production-single-redis

Single-instance production gateway with Redis-backed cluster primitives. The "Redis is for restart durability + clean LB drain" sweet spot — not yet multi-replica, but already production-grade enough for an external-facing single-pod deploy.

## What's in it

- TLS terminated at the gateway (`server.tls`) — drop this block if your LB terminates TLS instead.
- Redis cluster (`cluster.kind: redis`) for sessions / tasks / pipelines, served by the `dev.mcpg.cluster.redis` plugin.
- OIDC inbound auth — token verified against the IdP's JWKS. The `dev.mcpg.identity.oidc` plugin carries the same providers.
- File-backed audit sink at `/var/log/mcpg/audit.log` (built-in `dev.mcpg.builtin.audit.local-file`).
- One illustrative HTTP binding with retry + `governance.minimum_trust: verified`.
- Logs to stderr (JSON), metrics through the `dev.mcpg.observability.prometheus` plugin at `/metrics` on the gateway listener.
- A `plugins` list with those three plugins. The gateway image carries no plugins: the gateway pulls each signed artifact at boot. Without the Redis or the OIDC entry the gateway refuses to boot; without the Prometheus entry it boots and exports no metrics.
- A `license` block. The Redis coordinator is a licensed plugin: the gateway refuses to load it without a license that entitles `cluster.*` plugins (Team, Enterprise). Outside production, `license.non_production_use: true` in place of the token loads it under the non-production grant.

## What to change

| Field | Why |
|---|---|
| `server.allowed_origins` | Replace `gateway.example.com` with your real hostname(s). Wildcards are rejected. |
| `server.tls.cert_path` / `key_path` | Wire to your secret manager / cert-manager. |
| `cluster.url` (`MCPG_REDIS_URL`) | `rediss://` (TLS) preferred for non-localhost Redis. |
| `governance.access.oidc_oauth.providers[0].issuer` | Your IdP's issuer URL. |
| `governance.access.oidc_oauth.providers[0].audiences` | The audience claim your IdP issues for this gateway. |
| `config.providers` of the `dev.mcpg.identity.oidc` entry | Keep equal to `governance.access.oidc_oauth.providers`. |
| `plugins[*].source.oci` | The plugin releases that match the gateway you run, or your mirror of them. |
| `governance.audit.sinks[0].config.path` | Audit log file your filebeat / vector / fluentbit forwarder watches. |
| `license.token_file` | Where your license token is mounted. |
| `mcp.capabilities.tools` | Replace the placeholder binding with your tools. |

## Required env vars

- `MCPG_REDIS_URL` — Redis connection (`rediss://` recommended outside localhost).
- `MCPG_REDIS_PASSWORD` — Redis password, passed out of the URL.
- `MCPG_CLUSTER_STATE_KEY` — URL-safe-base64 32-byte state-encryption key (`openssl rand -base64 32 | tr '+/' '-_'`). Required whenever `cluster.kind` is not `single_node`; seals the Redis-held session/pipeline state.
- `MCPG_LICENSE_PUBKEY` — the public key (SPKI PEM) that verifies the license token.
- `ACCOUNTS_API_TOKEN` — bearer token the example HTTP binding sends to its upstream. Drop with the binding if you don't keep it.

## Verify before deploy

```bash
mcpg-config check examples/deployments/production-single-redis.yaml
```
