# 18 — Slack

MCP server over the Slack Web API.

## Upstream

- Docs: https://api.slack.com/web
- Auth: Bearer bot token (`xoxb-...`).

## Env vars

| Var | Purpose |
|---|---|
| `SLACK_BOT_TOKEN` | Bot user OAuth token |

## Run

```bash
cargo run -p mcpg -- --config examples/18-slack/config.yaml
```

## Exposed tools

- `slack.chat.post` — send a message (optionally threaded / with
  Block Kit blocks).
- `slack.chat.schedule` — schedule a future message.
- `slack.conversations.list` — list channels (public + private).
- `slack.conversations.history` — recent messages in a channel.
- `slack.reaction.add` — add a reaction.
- `slack.files.upload` — step 1 of the v2 upload flow (returns
  an external upload URL; the agent does a direct PUT to it).

## Resource template

- `slack://channel/{channel}/msg/{ts}` — one-message fetch.

## Note

Slack's response always has an `ok` boolean; check it at the
pipeline / agent layer — HTTP 200 does not imply success.
