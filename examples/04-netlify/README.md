# 04 — Netlify

MCP server covering Netlify sites, deploys, forms, and functions.

## Upstream

- **Docs**: https://docs.netlify.com/api/
- **Auth**: Bearer personal access token.

## Env vars

| Var | Purpose |
|---|---|
| `NETLIFY_TOKEN` | Personal access token (User settings → Applications) |

## Run

```bash
cargo run -p mcpg -- --config examples/04-netlify/config.yaml
```

## Exposed tools

- `netlify.sites.list` — list sites.
- `netlify.site.create` — create a site.
- `netlify.deploys.list` — list deploys for a site.
- `netlify.deploy.trigger` — trigger a new build.
- `netlify.forms.list` — list forms on a site.
- `netlify.forms.submissions` — paginated form submissions.
- `netlify.functions.logs` — list functions + their latest
  invocations.

## Notes

Form submissions often carry PII — the gateway-side log redactor
(T12-07) will scrub credential-shaped fields in MCP logs, but
the raw upstream response is still what reaches the client.
Route via the guardrails plugin if you need DLP.
