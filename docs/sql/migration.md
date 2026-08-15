# Migrating HTTP-wrapped DB tools to direct SQL backends

Many existing MCP tool servers are thin REST wrappers around a
database — a Flask/Express/FastAPI service that does
`SELECT … WHERE id = ?`, returns JSON, and runs as its own
process. The MCPG SQL backend (`backend.kind: sql`, implemented
by the SQL backend plugin `mcpg-plugin-backend-sql`) lets you
collapse that whole layer into a YAML config and talk to the DB
directly.

This doc walks through the conversion. For the SQL backend's
full reference see [`backends.md`](../backends.md#sql-backend); for
ready-to-go recipes see [`cookbook.md`](cookbook.md).

> **Vocabulary note (Layout D'').** A YAML entry under
> `mcp.capabilities.tools[]` is a *tool*. Its `backend:` field is
> a *backend*, with `kind: sql` selecting the SQL implementation.
> The plugin code that handles `backend.kind: sql` is the *SQL
> backend plugin*. Layout #4 Slice B2 dropped per-entry `kind:` —
> list membership (`tools[]` vs `resources[]` vs …) carries that
> instead.

---

## When to migrate

Migrate when the wrapper is *only* doing query dispatch:

- It runs `SELECT` / `INSERT` / `UPDATE` against one DB.
- Auth comes from a header / JWT / mTLS principal — no
  per-request user→DB-role mapping in app code.
- Output is JSON-shaped rows (or a passthrough of the DB
  response).
- There's no business logic *between* the request and the
  query that you couldn't express as CEL `param_exprs`,
  `await:`, or a `sql_tx` pipeline.

**Don't migrate when:**

- The wrapper calls multiple unrelated DBs and joins in app
  code (a pipeline of multiple SQL backends is fine, but at
  some point a real service is cleaner).
- The wrapper does substantial post-query reshaping
  (aggregating across pages, custom scoring, calling other
  services). Use a `kind: pipeline` backend combining `sql`
  and `transform` steps, or keep the service.
- The wrapper enforces complex per-row authorization that
  isn't expressible as Postgres RLS or a `WHERE tenant = :t`
  filter. (Most are.)

---

## Before / after — full example

A typical "fetch order by ID" REST tool:

### Before (Python + FastAPI)

```python
# orders_service/app.py
from fastapi import FastAPI, Depends, HTTPException
import psycopg
from auth import get_principal

app = FastAPI()
DB = psycopg.connect(os.environ["ORDERS_DB_URL"])

@app.get("/orders/{order_id}")
async def get_order(order_id: int, principal=Depends(get_principal)):
    with DB.cursor() as cur:
        cur.execute(
            "SELECT id, customer_id, total_cents, status FROM orders "
            "WHERE id = %s AND tenant = %s",
            (order_id, principal.tenant),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404)
    return {
        "id": row[0],
        "customer_id": row[1],
        "total_cents": row[2],
        "status": row[3],
    }
```

Plus an MCP-side `tools/call` handler that posts to
`http://orders-service/orders/{id}` and reshapes the JSON
into a tool result.

### After (MCPG config)

```yaml
mcp:
  capabilities:
    tools:
      - name: get_order
        description: Fetch an order by ID. Tenant-scoped.
        input_schema:
          type: object
          properties:
            order_id: { type: integer, description: "Order primary key." }
          required: [order_id]
        backend:
          kind: sql
          driver: postgres
          url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
          pool:
            max_connections: 10
            acquire_timeout_ms: 5000
          query:
            sql: |
              SELECT id, customer_id, total_cents, status
              FROM orders
              WHERE id = :order_id AND tenant = :tenant
            params: [order_id, tenant]
            row_mode: single
            timeout_ms: 1500
            param_exprs:
              # Tenant comes from the auth chain — caller can't override.
              tenant: 'identity.tenant'
```

That's it. The whole `orders_service` process is gone. The
MCP gateway holds the pool, prepares the statement, binds the
caller's `order_id`, splices in `identity.tenant` from the
auth chain, runs the query, and returns the row as the tool
result. `single` returns `null` (not 404) when the row's
missing — call sites branch on that.

---

## Step-by-step migration

### 1. Inventory the wrapper

For each endpoint, record:

- HTTP method + path → MCP tool name
- Path/query/body parameters → tool input schema +
  `query.params`
- The SQL it actually runs (read the source, not the docs)
- Auth requirements → which CEL `identity.*` field maps
- Output shape → `row_mode`

If the SQL isn't visible in the source (ORM-generated), turn
on the DB's statement log for one request and grab it from
there. Don't reverse-engineer from the model; ORMs frequently
emit subqueries you wouldn't have written.

### 2. Pick the row mode

| Wrapper does                    | `row_mode`            |
|---------------------------------|-----------------------|
| Returns one row, 404 on miss    | `single`              |
| Returns a list                  | `many`                |
| Returns one number/string       | `scalar`              |
| `INSERT`/`UPDATE`/`DELETE`      | `affected_rows`       |
| Returns a CSV/PDF/etc. blob     | `resource_contents` (use `kind: resource_template`) |
| Paginates with `?cursor=…`      | `stream` (see [#11 in cookbook](cookbook.md#11-stream-large-result-set-with-single-column-cursor)) |

**Behaviour-difference watch:** the wrapper probably 404s on
"not found"; the backend returns `null`. That's a deliberate
shape choice — MCP clients can match `null` more cheaply than
catching an HTTP error. If your client-side code currently
catches the 404, update it to check for `null`.

### 3. Lift parameters and body fields into `params`

Every placeholder the wrapper uses becomes a named
placeholder in the backend's SQL. Order them in `params:`
identically — that's the binding order.

Caller-supplied:

```python
# Before
cur.execute("SELECT … WHERE id = %s", (req.id,))
```

```yaml
# After
sql: "SELECT … WHERE id = :id"
params: [id]
```

Server-derived (timestamp, principal, request ID):

```python
# Before
cur.execute("INSERT … VALUES (%s, %s, NOW())", (req.k, principal.user_id))
```

```yaml
# After
sql: |
  INSERT INTO t (k, user_id, created_at)
  VALUES (:k, :user_id, :now)
params: [k, user_id, now]
param_exprs:
  user_id: 'identity.subject'
  now: 'now()'
```

`param_exprs` lets you compute parameter values from request
context without exposing them to the caller. They're still
parameter-bound — never string-interpolated.

### 4. Move auth-driven filtering into RLS or `param_exprs`

The wrapper almost certainly does
`WHERE tenant = principal.tenant` in app code. You have two
choices:

**Postgres + RLS (preferred):** define the policy on the
table and use `session_vars` to set the GUC (see
[cookbook #19](cookbook.md#19-postgres-rls-via-session_vars)).
The query body doesn't mention `tenant` at all; the policy
appends it. One missed backend doesn't leak data because the
DB enforces the filter, not your YAML.

**Engine-portable:** bind `tenant` via `param_exprs` (see
[cookbook #20](cookbook.md#20-tenant-scoped-reads-via-cel-param_exprs)).
Less defense-in-depth — a missing `WHERE tenant = :tenant`
clause does leak data — but works on MySQL/SQLite/read replicas
without write-side GUC support.

### 5. Translate input schemas

The wrapper's input shape (FastAPI `BaseModel`, Express
schema, etc.) becomes the tool entry's `input_schema`. You can
hand-write it or rely on `backend.schema.derive: input`
(Postgres only — see
[`backends.md` §schema derivation](../backends.md#sql-backend)).
Hand-derived plus auto-derived merges field-by-field, with
operator fields winning at every key — so you can hand-write
descriptions and enum lists while letting the SQL backend fill
in types.

### 6. Decide pool size

The single shared `psycopg.connect` in the example service is
implicitly `max_connections: 1` — every request serializes.
That's almost never what you want under load. The SQL backend's
`pool` defaults to `max_connections: 10` per backend, which
is usually right for a single tool. Tune up for high-QPS
tools, tune down for tools that share a hot DB with other
SQL backends.

> **DB-side budget**: every gateway replica × every SQL backend
> × `max_connections` = upper bound on DB sessions. PG defaults
> to `max_connections=100`; a 4-replica gateway with 10 SQL
> backends at 10 each = 400 DB sessions. Watch this when
> scaling out — see
> [`troubleshooting.md`](troubleshooting.md#pool-acquire-timeout--max_connections-saturation).

### 7. Translate transactions

Multi-statement transactions in the wrapper become
`kind: sql_tx` pipeline steps (see
[cookbook #17](cookbook.md#17-two-statement-atomic-transaction)).
The transaction binds to one referenced SQL backend's pool,
runs each nested statement on a pinned connection, and
commits or rolls back atomically.

### 8. Translate "submit + poll" patterns

The wrapper that does

```python
job_id = enqueue(...)
while True:
    j = fetch_job(job_id)
    if j.done: return j
    sleep(2)
```

is `await:` (see
[cookbook #13](cookbook.md#13-submit--poll-until-done)).
You don't write the loop; the backend owns it. You get a
`mcpg_sql_await_polls_total` counter for free, plus a
`Timeout` error variant the caller can branch on.

### 9. Translate change notifications

If the wrapper exposes a webhook that fires on row changes,
or holds a long-poll connection that returns when something
updates, that's [`watch.strategy` (`sql_polling` or
`postgres_listen_notify`)](cookbook.md#15-poll-mode-watch-any-engine).
The MCP `notifications/resources/updated` event replaces the
webhook delivery; clients subscribe and the gateway pushes.

### 10. Verify auth equivalence

The wrapper enforces auth at the HTTP layer; the backend
enforces it via the gateway's auth chain. Confirm that:

- The gateway's auth chain (`access.identity.providers`) maps
  the same principal claim the wrapper relied on.
- `identity.tenant` (or whatever field you use in
  `param_exprs`) is populated for every successful auth.
- Tools that the wrapper restricted to specific roles are
  gated via the gateway's policy chain (`governance.policy.*`)
  or a CEL expression referencing `identity.role`.

A common pre-launch test: turn off the wrapper, flip the MCP
client's tool definitions to point at the gateway, and replay
yesterday's audit log. Spot-check that authorized calls
still succeed and unauthorized calls still fail with the
same outcome.

### 11. Move secrets out of the wrapper's `.env`

The wrapper reads `ORDERS_DB_URL` from its env; the backend
embeds the credential in the URL via the gateway's
interpolator (`${env.ORDERS_DB_PW}` resolved at config-load,
or `${secret.…}` once a secret-resolver plugin is wired —
see [`identity-and-authorization.md`](../identity-and-authorization.md)
for the credential-issuer surface). Cleartext lives only in
the gateway's process env, never in YAML source.

### 12. Decommission the wrapper

Once the backend has been live and stable for a release
window, delete the wrapper service. Keep the audit log
side-by-side for a billing cycle so you can compare wrapper
vs. backend traffic shape before you turn the wrapper off
permanently.

---

## What you gain

- **One process fewer.** The wrapper's deploy pipeline,
  Dockerfile, image registry, alerting, and on-call rotation
  all go away.
- **Direct prepared-statement parameter binding.** No serialize-to-JSON +
  deserialize-from-JSON-in-the-DB-driver round trip; values
  go straight into sqlx's prepared statement.
- **Built-in metrics, audit, and tracing.** The backend emits
  the same observability triad as every other MCPG plugin —
  `mcpg_sql_calls_total`, `mcpg_sql_duration_seconds`,
  per-backend spans, audit annotations — without you wiring
  Prometheus middleware into the wrapper.
- **Cancellation.** MCP `notifications/cancelled` flows through
  the gateway → the backend → `pg_cancel_backend`/`KILL QUERY`/
  `sqlite3_interrupt`. The wrapper had to plumb that itself.
- **Pool sharing across tools.** Multiple backends against
  the same DB share a pool by URL — the wrapper had one pool
  per service.

## What you lose

- **App-language post-processing.** If you needed Python /
  Node logic to massage rows, you now reach for `kind:
  pipeline` + `transform` steps (CEL) or keep the wrapper.
- **Custom HTTP semantics.** Status codes, headers, content
  negotiation — none of that exists in MCP tool calls. Most
  wrappers don't actually need it; if yours does, leave it.
- **Code-review-able SQL.** The SQL now lives in YAML, not
  Python source. Treat the YAML as production code: lint it,
  review it, version-control it, regression-test it (see
  `examples/26-sql-sqlite-todos` for the test pattern).

---

## See also

- [`backends.md`](../backends.md#sql-backend) — full reference
- [`cookbook.md`](cookbook.md) — recipes
- [`troubleshooting.md`](troubleshooting.md) — failure modes
- [`pipelines.md`](../pipelines.md) — multi-step pipelines + `sql_tx`
- [`identity-and-authorization.md`](../identity-and-authorization.md) — auth chain + CEL identity surface
