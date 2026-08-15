# 03 — Vercel

MCP server covering Vercel projects, deployments, domains, and
project env-vars.

## Upstream

- **Docs**: https://vercel.com/docs/rest-api
- **Auth**: Bearer token (personal or team-scoped).

## Env vars

| Var | Purpose |
|---|---|
| `VERCEL_TOKEN` | Vercel access token |

## Run

```bash
cargo run -p mcpg -- --config examples/03-vercel/config.yaml
```

## Exposed tools

| Tool | Purpose |
|---|---|
| `vercel.projects.list` | List projects |
| `vercel.deployments.list` | List deployments (optionally per project) |
| `vercel.deployment.trigger` | Create a deployment from a GitHub ref |
| `vercel.deployment.status` | Get a single deployment's state |
| `vercel.deployment.logs` | Tail build events |
| `vercel.domains.add` | Attach a domain to a project |
| `vercel.env.get` | List project env vars |
| `vercel.env.set` | Create/update a project env var |

## Notes

- For team tokens prefix endpoints with the team id or add
  `?teamId=` — the template expressions make this easy to add
  per binding.
- `vercel.env.set` defaults to `encrypted`; never pass a real
  secret unencrypted.
