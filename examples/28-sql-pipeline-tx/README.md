# 28 — SQL backend: transactional pipeline (`sql_tx`) (P4.1)

An MCP server demonstrating the `sql_tx` pipeline container — two
SQL statements wrapped in a single transaction, with commit on
success and rollback on any nested-step failure. Uses SQLite
for zero external dependencies; swap the driver + URL to move to
Postgres / MySQL.

## Upstream

- **DB**: SQLite file. The first `*.init_schema` call creates the
  tables.

## Env vars

| Var | Value |
|---|---|
| `TX_DB_PATH` | Absolute path to a writable SQLite file, e.g. `/tmp/mcpg_tx.db` |

```bash
export TX_DB_PATH=/tmp/mcpg_tx.db
```

## Run

```bash
cargo run -p mcpg -- --config examples/28-sql-pipeline-tx/config.yaml
```

## First-run setup

```
tools/call inv.init_schema {}
tools/call inv.seed_inventory {}
tools/call orders.init_schema {}
```

## Exposed tools

| Tool | Purpose | Shape |
|---|---|---|
| `inv.init_schema` | CREATE TABLE inv | bootstrap |
| `inv.seed_inventory` | INSERT qty=5 | bootstrap |
| `orders.init_schema` | CREATE TABLE orders (UNIQUE user_id) | bootstrap |
| `orders.db` | SELECT 1 | sentinel backend; `sql_tx` borrows its pool |
| `inv.read_qty` | Read current qty | verifier |
| `orders.place` | **Pipeline** — deduct inventory + record order in one tx | the demo |

## Example client calls

### Happy path — first order commits

```
tools/call inv.read_qty {}
# → 5

tools/call orders.place { "user_id": 42, "item_id": 1 }
# → {
#     "steps": {
#       "charge_flow": {
#         "output": {
#           "steps": {
#             "deduct": { "rows_affected": 1 },
#             "record": { "rows_affected": 1 }
#           }
#         }
#       }
#     }
#   }

tools/call inv.read_qty {}
# → 4          ← committed
```

### Rollback path — second order for same user fails

```
tools/call orders.place { "user_id": 42, "item_id": 1 }
# → error: sql_tx 'charge_flow' nested step 'record': execute: ...
#          UNIQUE constraint failed: orders.user_id

tools/call inv.read_qty {}
# → 4          ← unchanged; the UPDATE rolled back
```

## What to notice

- **`type: sql_tx`** is a *container* pipeline step — nested
  `steps:` are SQL statements, not full pipeline steps. They run
  sequentially against the same pinned pool connection.
- **`binding: orders.db`** names any registered SQL backend whose
  pool should back the transaction. That backend's own `query`
  isn't invoked — the tx machinery bypasses it.
- **Per-statement results** surface under
  `steps.charge_flow.output.steps.<nested_id>` for downstream
  pipeline steps to reference via CEL (e.g. a follow-up
  `transform` that pulls `rows_affected`).
- **Supported nested `row_mode`s**: `affected_rows`, `many`,
  `single`, `scalar`. Richer modes (`resource_contents`,
  `stream`) aren't meaningful inside a tx — wrap a SELECT in its
  own backend instead.
- **Atomicity is driver-enforced.** SQLite commits on success and
  rolls back when the second INSERT hits the UNIQUE constraint.
  Postgres + MySQL behave identically; the plugin's `SqlTxHandle`
  is engine-specific but the contract is the same.

## Caveats

- SQLite's tx semantics are simpler than Postgres — no isolation
  levels, no deadlock detection. For production use cases like
  inventory deduction under concurrent traffic, run against
  Postgres and pair with `read_only: false` + an explicit
  `session_vars` isolation level.
- MySQL's `SqlTxHandle` impl is pending — `begin_transaction`
  returns `InvalidSpec` on MySQL pools today. Postgres and SQLite
  are the Phase-1 drivers.
