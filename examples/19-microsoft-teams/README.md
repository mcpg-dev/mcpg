# 19 — Microsoft Teams + Microsoft Graph

MCP server covering the most-used Microsoft Graph endpoints for
Teams, Outlook, Calendar, and OneDrive.

## Upstream

- Microsoft Graph v1.0: https://learn.microsoft.com/en-us/graph/overview
- Auth: OAuth 2.0 Bearer token (user or app + client-credentials).

## Env vars

| Var | Purpose |
|---|---|
| `MS_GRAPH_TOKEN` | Delegated or application access token for Graph |

## Run

```bash
cargo run -p mcpg -- --config examples/19-microsoft-teams/config.yaml
```

## Exposed tools

- `graph.me` — current user profile.
- `teams.channel.list` — channels of a team.
- `teams.channel.post` — post a message to a channel.
- `calendar.event.create` — create an event in the user's calendar.
- `mail.send` — send email on behalf of the user.
- `onedrive.children` — list children of a OneDrive folder.

## Notes

Token refresh is out-of-scope for this sample; wire an auth
plugin (or a sidecar) to rotate `MS_GRAPH_TOKEN` for long-running
deployments.
