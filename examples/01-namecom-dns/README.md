# 01 — Name.com DNS

Turn the Name.com v4 API into an MCP server so an agent can manage
domains and DNS records on your account.

## Upstream

- **Docs**: https://www.name.com/api-docs
- **Auth**: HTTP Basic (`username:apitoken`).

## Env vars

| Var | Value |
|---|---|
| `NAMECOM_BASIC_AUTH` | `base64(username + ':' + apitoken)` — see below |

```bash
export NAMECOM_BASIC_AUTH=$(printf 'alice:tok_abc123' | base64)
```

## Run

```bash
cargo run -p mcpg -- --config examples/01-namecom-dns/config.yaml
```

## Exposed tools

| Tool | Purpose | Hints |
|---|---|---|
| `namecom.domain.list` | List all domains | read-only |
| `namecom.domain.get` | Get metadata for one domain | read-only |
| `namecom.record.list` | List DNS records for a zone | read-only |
| `namecom.record.create` | Create a new DNS record | — |
| `namecom.record.update` | Update an existing record | idempotent |
| `namecom.record.delete` | Delete a record | destructive |

## Resource template

- `namecom://{zone}/records` — live JSON dump of a zone's records.

## Example client calls

```
tools/call namecom.record.list { "zone": "example.com" }
tools/call namecom.record.create { "zone":"example.com","host":"api","type":"A","answer":"203.0.113.10","ttl":3600 }
resources/read namecom://example.com/records
```

## Caveats

- Name.com rate-limits to ~20 req/s; enable `retry:` per binding
  if you need burst resilience.
- `record_id` is returned from `namecom.record.list`; keep the
  list call cached or pair with a pipeline that does
  list-then-match-then-delete.
