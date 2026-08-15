# 02 — Cloudflare (DNS + Pages + Workers + R2)

MCP server covering Cloudflare's common account, DNS, Pages,
Workers, and R2 surfaces.

## Upstream

- **Docs**: https://developers.cloudflare.com/api/
- **Auth**: Bearer API token (scoped).

## Env vars

| Var | Purpose |
|---|---|
| `CF_API_TOKEN` | Cloudflare API token; scope per operation |

## Run

```bash
cargo run -p mcpg -- --config examples/02-cloudflare/config.yaml
```

## Exposed tools

| Tool | Purpose |
|---|---|
| `cf.zone.list` | List zones (optionally filter by name) |
| `cf.dns.list` | List DNS records in a zone |
| `cf.dns.create` | Create a DNS record |
| `cf.dns.delete` | Delete a DNS record |
| `cf.cache.purge` | Purge cache (all or specific URLs) |
| `cf.pages.deployments` | List deployments of a Pages project |
| `cf.workers.list` | List Workers scripts in the account |
| `cf.r2.objects` | List objects in an R2 bucket |

## Example calls

```
tools/call cf.zone.list { "name": "example.com" }
tools/call cf.dns.create { "zone_id":"abc","type":"A","name":"www","content":"203.0.113.10","proxied":true }
tools/call cf.cache.purge { "zone_id":"abc","purge_all":true }
```

## Notes

- A token with narrow scope is strongly preferred over a global key.
- `cf.cache.purge` is destructive; pair with a confirmation pipeline
  when exposed to less-trusted agents.
