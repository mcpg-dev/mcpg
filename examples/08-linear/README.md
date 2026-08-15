# 08 — Linear

MCP server over the Linear GraphQL API.

## Upstream

- Docs: https://developers.linear.app/docs
- Auth: API key header.

## Env vars

| Var | Purpose |
|---|---|
| `LINEAR_TOKEN` | Linear API key (starts with `lin_api_` or OAuth token) |

## Run

```bash
cargo run -p mcpg -- --config examples/08-linear/config.yaml
```

## Exposed tools

- `linear.issue.search` — free-text issue search.
- `linear.issue.get` — fetch a single issue by identifier.
- `linear.issue.create` — create an issue in a team.
- `linear.teams` — list teams.
- `linear.cycles` — list active cycles.

## Resource template

- `linear://issue/{id}` — embed a single issue as a resource.
