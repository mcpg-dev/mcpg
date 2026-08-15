# production-single-redis

Single-instance production gateway with Redis-backed cluster primitives. The "Redis is for restart durability + clean LB drain" sweet spot — not yet multi-replica, but already production-grade enough for an external-facing single-pod deploy.

## What's in it

- TLS terminated at the gateway (`server.tls`) — drop this block if your LB terminates TLS instead.
- Redis cluster (`cluster.kind: redis`) for sessions / tasks / pipelines.
- OIDC inbound auth — token verified against the IdP's JWKS.
- File-backed audit sink at `/var/log/mcpg/audit.log` (built-in `dev.mcpg.builtin.audit.local-file`).
- One illustrative HTTP binding with retry + `governance.minimum_trust: verified`.
- Logs to stderr (JSON), metrics via the built-in Prometheus plugin sink at `:9090/metrics`.

## What to change

| Field | Why |
|---|---|
| `server.allowed_origins` | Replace `gateway.example.com` with your real hostname(s). Wildcards are rejected. |
| `server.tls.cert_path` / `key_path` | Wire to your secret manager / cert-manager. |
| `cluster.url` (`MCPG_REDIS_URL`) | `rediss://` (TLS) preferred for non-localhost Redis. |
| `governance.access.oidc_oauth.providers[0].issuer` | Your IdP's issuer URL. |
| `governance.access.oidc_oauth.providers[0].audiences` | The audience claim your IdP issues for this gateway. |
| `governance.audit.sinks[0].config.path` | Audit log file your filebeat / vector / fluentbit forwarder watches. |
| `mcp.capabilities.tools` | Replace the placeholder binding with your tools. |

## Required env vars

- `MCPG_REDIS_URL` — Redis connection (`rediss://` recommended outside localhost).
- `MCPG_OIDC_CLIENT_ID`, `MCPG_OIDC_CLIENT_SECRET` — IdP credentials referenced by `${env.…}` in the YAML.
- `ACCOUNTS_API_TOKEN` — bearer token the example HTTP binding sends to its upstream. Drop with the binding if you don't keep it.

## Verify before deploy

```bash
mcpg-config check examples/deployments/production-single-redis.yaml
```
