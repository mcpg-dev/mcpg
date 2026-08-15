# 20 — Google Workspace (Gmail + Calendar + Drive + Docs)

MCP server over the common Google Workspace surfaces.

## Upstream

- Gmail API v1
- Calendar API v3
- Drive API v3
- Docs API v1

## Env vars

| Var | Purpose |
|---|---|
| `GOOGLE_TOKEN` | OAuth 2.0 Bearer access token with appropriate scopes |

## Run

```bash
cargo run -p mcpg -- --config examples/20-google-workspace/config.yaml
```

## Exposed tools

- `gmail.list` / `gmail.get` / `gmail.send`
- `calendar.events.list` / `calendar.event.create`
- `drive.files.list`
- `docs.create`

## Scopes (typical)

- `https://www.googleapis.com/auth/gmail.modify`
- `https://www.googleapis.com/auth/calendar`
- `https://www.googleapis.com/auth/drive.file`
- `https://www.googleapis.com/auth/documents`

## Safety

`gmail.send` is irreversible. Wrap with a confirmation pipeline
(`Elicitation` → `BindingCall`) when driven by less-trusted
agents.
