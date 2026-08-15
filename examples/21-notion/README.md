# 21 — Notion

MCP server over the Notion REST API.

## Upstream

- Docs: https://developers.notion.com/
- Auth: Bearer integration token. `Notion-Version: 2022-06-28`
  pinned on every call.

## Env vars

| Var | Purpose |
|---|---|
| `NOTION_TOKEN` | Internal integration token (Settings → Integrations) |

## Run

```bash
cargo run -p mcpg -- --config examples/21-notion/config.yaml
```

## Exposed tools

- `notion.search` — full-text search.
- `notion.page.get` — page metadata.
- `notion.page.create` — create a page under a parent.
- `notion.block.append` — append children blocks (rich text, etc.).
- `notion.db.query` — typed database query with filter/sort.

## Resource template

- `notion://page/{page_id}` — JSON for a single page.
