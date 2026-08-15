# 29 — SQL backend: fire-and-wait `await` block (P3.3)

A tool that submits a job and blocks until it's finished —
demonstrates the SQL backend's `await:` runtime. The server fires
a trigger INSERT (pending job), then polls a status query until a
CEL predicate matches or the timeout expires.

## Upstream

- **DB**: SQLite file. Created on first `jobs.init_schema` call.

## Env vars

| Var | Value |
|---|---|
| `JOBS_DB_PATH` | Absolute path to a writable SQLite file, e.g. `/tmp/mcpg_jobs.db` |

```bash
export JOBS_DB_PATH=/tmp/mcpg_jobs.db
```

## Run

```bash
cargo run -p mcpg -- --config examples/29-sql-await-job/config.yaml
```

## First-run setup

```
tools/call jobs.init_schema {}
```

## Exposed tools

| Tool | Purpose | Shape |
|---|---|---|
| `jobs.init_schema` | CREATE TABLE IF NOT EXISTS | bootstrap |
| `jobs.provision` | Fire-and-wait: submit + block until complete | **the demo** |
| `jobs.mark_completed` | Test helper — flip a job to `completed` (normally an external worker does this) |

## Example client calls

Open two MCP connections side by side (or run from two terminals).

**Connection A** — start the wait:

```
tools/call jobs.provision { "user_id": 42 }
# blocks...
```

**Connection B** — finish the job so A returns:

```
tools/call jobs.mark_completed { "user_id": 42 }
# → { "rows_affected": 1 }
```

**Connection A** — the earlier call now returns:

```
# → { "status": "completed" }
```

## Timeout behaviour

If nothing ever flips the job's status, `jobs.provision` returns
a `BackendError::Timeout` after 30 seconds (`timeout_ms: 30000`).
The row in `provision_jobs` stays as `pending` — the timeout
doesn't roll back the trigger INSERT. Operators who want atomic
"submit-and-wait" semantics can pair `await` with the `sql_tx`
pipeline step (sample 28) on the trigger side.

## What to notice

- **`query` is a stub**: the schema requires a `query` block but
  the `await` runtime bypasses it. `SELECT 1` / `row_mode: scalar`
  is the canonical no-op.
- **`:cursor` and `:page_size` are reserved for `list_query`**;
  any placeholder in `await.check.sql` / `await.trigger.sql`
  must appear in that step's `params` list, bound from caller
  arguments (or a `param_exprs` derivation).
- **CEL has two variables**: `row` (first check-query row as a
  JSON object, or `null` when the check returned no rows) and
  `arguments` (the caller's JSON arg object — same map the
  placeholders bind from). `row.status == "completed"` is a
  typical check.
- **Empty result sets are a miss, not an error**: if the check
  query returns zero rows, `row` is `null` and any predicate
  that references `row.status` evaluates to `false` — the loop
  keeps polling.
- **`poll_interval_ms` has a 100 ms floor** and `timeout_ms` must
  be `>= poll_interval_ms`. Both are enforced at config parse.
- **Metrics**: `mcpg_sql_await_polls_total{binding, driver,
  outcome}` counter bumps on termination with the actual poll
  count. Wire this to Prometheus to spot flows that consistently
  time out.

## Caveats

- The await loop holds an in-flight slot for the whole wait
  (`mcpg_sql_requests_in_flight` gauge reflects it). Don't set
  `timeout_ms` higher than your MCP client's connection timeout;
  long waits should use resource subscriptions (see sample 27 +
  P2.6 watch plugins) instead.
- Each poll issues one DB query. On a 60 s timeout with 500 ms
  polling that's up to 120 queries per blocked request — pair
  with a pool large enough that concurrent waits don't exhaust
  connections.
