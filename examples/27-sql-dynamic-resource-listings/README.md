# 27 — SQL binding: dynamic resource listings (P2.3)

An MCP server that exposes `docs://{slug}` as a resource template
backed by a SQLite table and enumerates concrete URIs via the SQL
binding's `list_query` keyset-pagination block. Demonstrates the
end-to-end shape an agent sees when running `resources/list`
against a live table.

## Upstream

- **DB**: SQLite file. Created on first `docs.seed` call.

## Env vars

| Var | Value |
|---|---|
| `DOCS_DB_PATH` | Absolute path to a writable SQLite file, e.g. `/tmp/mcpg_docs.db` |

```bash
export DOCS_DB_PATH=/tmp/mcpg_docs.db
```

## Run

```bash
cargo run -p mcpg -- --config examples/27-sql-dynamic-resource-listings/config.yaml
```

## First-run setup

```
tools/call docs.seed {}
tools/call docs.seed_rows {}
```

This creates the `docs` table and inserts five rows.

## Exposed surfaces

| Kind | Name / URI | Purpose |
|---|---|---|
| tool | `docs.seed` | CREATE TABLE IF NOT EXISTS |
| tool | `docs.seed_rows` | Idempotent INSERT of 5 sample rows |
| resource template | `docs.read` → `docs://{slug}` | Read one doc by slug |

## Example client calls

```
resources/templates/list
# → [ { uriTemplate: "docs://{slug}", ... } ]

# Plugin-side list_resources (see Caveats): the SQL plugin's
# `list_resources(binding, cursor)` returns five rows here, three
# per page (page_size = 3), so a client paginates twice.

resources/read docs://readme
# → { contents: [ { uri: "docs://readme", text: "# Welcome", ... } ] }
```

## What to notice

- **`list_query` is keyset-paginated**: the SQL body references
  `:cursor` and `:page_size` — no other placeholders. The plugin
  rejects extra `:name` tokens at startup (defense in depth).
- **`page_size = 3`** makes the sample actually paginate — five
  rows over a page of three means the second call returns two
  rows plus `next_cursor: null` (short page signals exhaustion).
- **`cursor_column: id`** tells the plugin which column to read
  for the next-page cursor value. Pick a monotonic + indexed
  column; `updated_at` and `id` are the canonical choices.
- **`row_mode: resource_contents`** on `docs.read` wraps the
  SELECTed `uri` / `text` / `mime_type` columns as the MCP
  `{contents: [...]}` payload — no hand-written JSON aggregation.

## Caveats

- **Multi-page dynamic listings are truncated.** The gateway
  fan-out (P2.3 runtime) runs each dynamic provider only on the
  first `resources/list` page. If your `list_query` returns more
  rows than `page_size`, the extras appear only when `page_size`
  covers them — additional cursor-driven pages of dynamic
  resources aren't yet wired. A composite-cursor scheme that
  stitches static + multi-page dynamic together lands as a
  follow-up (tracked in FUTURE.md). For small-to-medium tables
  (< page_size * 10), raise `page_size` or reduce source rows.
- SQLite's `LIMIT :page_size` binding assumes the driver casts
  the bound integer correctly. Postgres + MySQL work identically.
