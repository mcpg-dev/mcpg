# 26 — SQL backend: SQLite todos

A zero-external-dependency MCP server that exposes CRUD over a
local SQLite `todos` table via the SQL backend. Demonstrates every
core `row_mode` and the `param_exprs` server-side clamp pattern.

## Upstream

- **DB**: SQLite file you point `TODOS_DB_PATH` at. The file is
  created on first call via the `todos.init_schema` tool.

## Env vars

| Var | Value |
|---|---|
| `TODOS_DB_PATH` | Absolute path to a writable SQLite file, e.g. `/tmp/mcpg_todos.db` |

```bash
export TODOS_DB_PATH=/tmp/mcpg_todos.db
```

## Run

```bash
cargo run -p mcpg -- --config examples/26-sql-sqlite-todos/config.yaml
```

## Exposed tools

| Tool | Purpose | row_mode |
|---|---|---|
| `todos.init_schema` | CREATE TABLE IF NOT EXISTS | `affected_rows` |
| `todos.create` | INSERT a new todo | `affected_rows` |
| `todos.list` | SELECT all todos | `many` |
| `todos.count_open` | Count of unfinished todos | `scalar` |
| `todos.complete` | Mark one todo done | `affected_rows` |
| `todos.purge_completed` | DELETE all `done = 1` rows | `affected_rows` |

## Example client calls

```
tools/call todos.init_schema {}
tools/call todos.create { "title": "ship sql_tx runtime" }
tools/call todos.list {}
tools/call todos.count_open {}
tools/call todos.complete { "id": 1 }
tools/call todos.purge_completed {}
```

## What to notice

- **`row_mode: affected_rows`** returns `{"rows_affected": N}` from
  INSERT/UPDATE/DELETE — what the server actually reports, not a
  fetch_all scan.
- **`row_mode: many`** returns a JSON array of rows. `max_rows`
  bounds the payload; the backend sets `_meta.truncated` when a
  query overflows.
- **`row_mode: scalar`** picks the first column of the first row
  and unwraps it — `SELECT COUNT(*)` returns `7`, not
  `[{"COUNT(*)": 7}]`.
- **`param_exprs`** compiles CEL once at registration and evaluates
  it per call. The `safe_id` clamp on `todos.complete` is
  server-side — callers can't bypass it.
- **`schema.derive: input`** on `todos.list` populates the MCP
  `tools/list` input schema from the statement's parameter
  metadata. For SQLite this is a no-op (no param introspection);
  on Postgres the derived types flow into the client.

## Caveats

- SQLite only honors `timeout_ms` cooperatively — a long-running
  query won't be forcibly cancelled. For strict cancel semantics,
  switch to Postgres (driver-level `pg_cancel_backend`) or MySQL
  (`KILL QUERY`).
- The sample uses the file mode `mode=rwc` so the file is created
  on first connect. Switch to `mode=ro` for read-only tools if
  you're protecting a shared DB.
