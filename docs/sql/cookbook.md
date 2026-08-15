# SQL backend cookbook

Worked recipes for the SQL backend (`backend.kind: sql`), implemented
by the SQL backend plugin (`mcpg-plugin-backend-sql`). Every recipe
is a complete YAML fragment that drops into `mcp.capabilities.tools[]`,
`mcp.capabilities.resources[]`, or `mcp.capabilities.resource_templates[]`
of an MCPG config — each recipe header notes which list it belongs
under.

For the full reference surface see [`backends.md`](../backends.md#sql-backend).
For known failure modes and how to diagnose them, see
[`troubleshooting.md`](troubleshooting.md). For converting
an existing REST-wrapped DB tool into a direct SQL backend, see
[`migration.md`](migration.md).

> **Vocabulary note (Layout D'').** A YAML entry under
> `mcp.capabilities.tools[]` (or the prompts/resources/resource_templates
> peers) is a *tool / prompt / resource / resource template*. Its
> implementation block is `backend: { kind: sql, ... }` — a *backend*.
> The plugin code that handles `backend.kind: sql` is the *SQL backend
> plugin*. List membership carries the capability kind, so entries
> have **no** `kind:` field at the top level — only `backend.kind`
> selects the implementation.

> All recipes use Postgres URLs unless a behaviour is engine-specific.
> Substitute `mysql://`, `mariadb://`, or `sqlite:` as needed —
> `row_mode`, `query`, `params`, `await`, and `stream` are
> driver-agnostic.

---

## Table of contents

**Tools (CRUD)** — `mcp.capabilities.tools[]`
1. [Read by primary key](#1-read-by-primary-key)
2. [Insert and return the new ID](#2-insert-and-return-the-new-id)
3. [Bulk update with a CEL-computed timestamp](#3-bulk-update-with-a-cel-computed-timestamp)
4. [Soft delete](#4-soft-delete)
5. [Upsert (Postgres `ON CONFLICT`)](#5-upsert-postgres-on-conflict)
6. [Upsert (MySQL `ON DUPLICATE KEY UPDATE`)](#6-upsert-mysql-on-duplicate-key-update)
7. [Stored procedure with rows-affected output](#7-stored-procedure-with-rows-affected-output)

**Resources** — `mcp.capabilities.resources[]` / `mcp.capabilities.resource_templates[]`

8. [Static document viewer](#8-static-document-viewer)
9. [Templated document viewer (`uri_template`)](#9-templated-document-viewer-uri_template)
10. [Dynamic listing with keyset pagination](#10-dynamic-listing-with-keyset-pagination)

**Tools (streaming reads)** — `mcp.capabilities.tools[]`

11. [Stream large result set with single-column cursor](#11-stream-large-result-set-with-single-column-cursor)
12. [Stream with composite cursor (timestamp + id)](#12-stream-with-composite-cursor-timestamp--id)

**Tools (fire-and-wait jobs)** — `mcp.capabilities.tools[]`

13. [Submit + poll until done](#13-submit--poll-until-done)
14. [Wait on an externally-triggered job](#14-wait-on-an-externally-triggered-job)

**Resources (watch / live updates)** — `mcp.capabilities.resources[]`

15. [Poll-mode watch (any engine)](#15-poll-mode-watch-any-engine)
16. [Postgres `LISTEN/NOTIFY` watch](#16-postgres-listennotify-watch)

**Tools (transactions)** — `mcp.capabilities.tools[]`

17. [Two-statement atomic transaction](#17-two-statement-atomic-transaction)
18. [Optimistic-lock retry on `xmin`](#18-optimistic-lock-retry-on-xmin)

**Tools (multi-tenancy)** — `mcp.capabilities.tools[]`

19. [Postgres RLS via `session_vars`](#19-postgres-rls-via-session_vars)
20. [Tenant-scoped reads via CEL `param_exprs`](#20-tenant-scoped-reads-via-cel-param_exprs)

**Tools / resource templates (reporting & analytics)**

21. [Scalar aggregate (`scalar`)](#21-scalar-aggregate-scalar) — `tools[]`
22. [Top-N report](#22-top-n-report) — `tools[]`
23. [Export-as-resource (CSV-shaped JSON)](#23-export-as-resource-csv-shaped-json) — `resource_templates[]`

**Tools (operations)** — `mcp.capabilities.tools[]`

24. [Feature flag check](#24-feature-flag-check)
25. [Audit log export with cursor continuation](#25-audit-log-export-with-cursor-continuation)
26. [DB health probe](#26-db-health-probe)

---

## 1. Read by primary key

**Lives under:** `mcp.capabilities.tools[]`.

Single row by ID, returned as a JSON object. `single` returns `null`
when the row doesn't exist — it does *not* error.

```yaml
- name: get_order
  description: Fetch one order by its primary key.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.ORDERS_DB_PW}@db:5432/orders"
    query:
      sql: "SELECT id, customer_id, total_cents, status FROM orders WHERE id = :id"
      params: [id]
      row_mode: single
      timeout_ms: 1000
```

## 2. Insert and return the new ID

**Lives under:** `mcp.capabilities.tools[]`.

Postgres / SQLite: use `RETURNING id` and `row_mode: scalar`.

```yaml
- name: create_ticket
  description: Open a support ticket; returns the new ticket id.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.SUPPORT_DB_PW}@db/support"
    query:
      sql: |
        INSERT INTO tickets (subject, body, opened_by)
        VALUES (:subject, :body, :opened_by)
        RETURNING id
      params: [subject, body, opened_by]
      row_mode: scalar
```

MySQL: use a separate `LAST_INSERT_ID()` call — `RETURNING` isn't
universal across versions.

```yaml
backend:
  kind: sql
  driver: mysql
  url: "mysql://app:${env.SUPPORT_DB_PW}@db/support"
  query:
    sql: "INSERT INTO tickets (subject, body, opened_by) VALUES (:subject, :body, :opened_by)"
    params: [subject, body, opened_by]
    row_mode: affected_rows
```

If you need the inserted ID on MySQL, wrap the INSERT + a
`SELECT LAST_INSERT_ID()` in a `sql_tx` step (recipe 17).

## 3. Bulk update with a CEL-computed timestamp

**Lives under:** `mcp.capabilities.tools[]`.

`param_exprs` lets you compute parameter values from request
context without exposing the timestamp to the caller. The CEL
result is bound as a regular parameter — fully parameterized,
not interpolated.

```yaml
- name: mark_messages_read
  description: Mark a list of messages read for the current user.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.CHAT_DB_PW}@db/chat"
    query:
      sql: |
        UPDATE messages
        SET read_at = :now
        WHERE recipient_id = :user AND id = ANY(:ids)
      params: [user, ids, now]
      row_mode: affected_rows
      param_exprs:
        # `now()` is an MCPG CEL builtin returning RFC3339.
        now: 'now()'
        user: 'identity.subject'
      # `ids` still comes from the caller via `arguments.ids`.
```

## 4. Soft delete

**Lives under:** `mcp.capabilities.tools[]`.

Same pattern as #3 — set a `deleted_at` column instead of
running `DELETE`.

```yaml
- name: archive_document
  description: Soft-delete a document by id.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.DOCS_DB_PW}@db/docs"
    query:
      sql: "UPDATE documents SET deleted_at = :now WHERE id = :id AND deleted_at IS NULL"
      params: [id, now]
      row_mode: affected_rows
      param_exprs:
        now: 'now()'
```

`affected_rows` returns `{"rows_affected": 0}` if the document
was already archived — call sites can branch on that.

## 5. Upsert (Postgres `ON CONFLICT`)

**Lives under:** `mcp.capabilities.tools[]`.

```yaml
- name: set_user_preference
  description: Insert-or-update a user preference; returns the stored value.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.PREFS_DB_PW}@db/prefs"
    query:
      sql: |
        INSERT INTO preferences (user_id, key, value)
        VALUES (:user, :key, :value)
        ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value
        RETURNING value
      params: [user, key, value]
      row_mode: scalar
```

## 6. Upsert (MySQL `ON DUPLICATE KEY UPDATE`)

**Lives under:** `mcp.capabilities.tools[]`.

```yaml
- name: set_user_preference
  description: Insert-or-update a user preference (MySQL flavour).
  backend:
    kind: sql
    driver: mysql
    url: "mysql://app:${env.PREFS_DB_PW}@db/prefs"
    query:
      sql: |
        INSERT INTO preferences (user_id, k, v)
        VALUES (:user, :key, :value)
        ON DUPLICATE KEY UPDATE v = VALUES(v)
      params: [user, key, value]
      row_mode: affected_rows
```

`affected_rows` returns `1` for a fresh insert and `2` for an
update under MySQL's quirky upsert semantics — that's a MySQL
behavior, not a backend behavior.

## 7. Stored procedure with rows-affected output

**Lives under:** `mcp.capabilities.tools[]`.

`procedure:` (instead of `sql:`) emits `CALL <procedure>(...)`
with the right placeholder syntax for each engine. The procedure
identifier is validated as a safe SQL identifier at config-load.

```yaml
- name: settle_invoice
  description: Run the settle_invoice stored procedure.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
    query:
      procedure: "orders.settle_invoice"
      params: [invoice_id, amount_cents]
      row_mode: affected_rows
```

If the procedure returns a row, switch to `row_mode: single` —
both Postgres and MySQL surface it the same way.

---

## 8. Static document viewer

**Lives under:** `mcp.capabilities.resources[]`.

A resource entry has a static `uri:`. The SELECT must produce
the columns `uri`, `text` (or `blob`), and optionally `mime_type` —
`row_mode: resource_contents` wraps them as the MCP
`{contents: [...]}` payload, no hand-rolled `json_build_object`
required.

```yaml
- name: tos
  uri: "doc://tos"
  description: The current Terms of Service document.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.DOCS_DB_PW}@db/docs"
    query:
      sql: |
        SELECT 'doc://tos' AS uri,
               body         AS text,
               'text/markdown' AS mime_type
        FROM documents
        WHERE slug = 'terms-of-service'
      row_mode: resource_contents
```

## 9. Templated document viewer (`uri_template`)

**Lives under:** `mcp.capabilities.resource_templates[]`.

A resource template entry has a `uri_template:` like
`doc://{slug}`. Captured variables flow into the placeholder
binding under their declared names, so `{slug}` becomes `:slug`.

```yaml
- name: doc
  uri_template: "doc://{slug}"
  description: A document by slug.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.DOCS_DB_PW}@db/docs"
    query:
      sql: |
        SELECT 'doc://' || slug    AS uri,
               body                AS text,
               'text/markdown'     AS mime_type
        FROM documents
        WHERE slug = :slug
      params: [slug]
      row_mode: resource_contents
```

## 10. Dynamic listing with keyset pagination

**Lives under:** `mcp.capabilities.resource_templates[]`.

`list_query` lets `resources/list` enumerate live rows. Pick a
cursor column that's monotonic and indexed — `id` for an
auto-incrementing PK, `updated_at + id` for a recency feed.

```yaml
- name: doc
  uri_template: "doc://{slug}"
  description: A document by slug, with a paginated listing.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.DOCS_DB_PW}@db/docs"
    query:
      sql: "SELECT 'doc://' || slug AS uri, body AS text, 'text/markdown' AS mime_type FROM documents WHERE slug = :slug"
      params: [slug]
      row_mode: resource_contents
    list_query:
      sql: |
        SELECT 'doc://' || slug AS uri,
               title            AS name,
               summary          AS description,
               'text/markdown'  AS mime_type
        FROM documents
        WHERE deleted_at IS NULL
          AND (:cursor IS NULL OR id > CAST(:cursor AS BIGINT))
        ORDER BY id
        LIMIT :page_size
      mode: keyset
      cursor_column: id
      page_size: 100
```

`:cursor` and `:page_size` are the only placeholders the gateway
binds — any other `:name` in `list_query.sql` is rejected at
startup.

---

## 11. Stream large result set with single-column cursor

**Lives under:** `mcp.capabilities.tools[]`.

`row_mode: stream` returns `{rows, next_cursor, truncated}` and
auto-binds the last row's cursor values to `:_after_<col>`
placeholders on continuation calls. The SQL must reference one
`:_after_<col>` per declared cursor column, ordered identically.

```yaml
- name: list_users
  description: Stream users; resumable via _cursor.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.AUTH_DB_PW}@db/auth"
    query:
      sql: |
        SELECT id, email, created_at
        FROM users
        WHERE id > :_after_id
        ORDER BY id
        LIMIT 500
      row_mode: stream
      max_rows: 500
      stream:
        cursor_columns: [id]
        initial: { id: 0 }
        # Set this to a shared secret across all gateway replicas
        # if you run multi-instance — otherwise cross-node
        # continuation calls fail HMAC verification.
        signing_key_env: USERS_STREAM_KEY
```

Clients pass the previous response's `next_cursor` as the
`_cursor` argument to continue. `next_cursor: null` signals
end-of-stream.

## 12. Stream with composite cursor (timestamp + id)

**Lives under:** `mcp.capabilities.tools[]`.

For recency feeds, a single `id` cursor either skips rows
(if `id` isn't strictly monotonic with `created_at`) or
re-reads them. Use a composite `(updated_at, id)` cursor.

```yaml
- name: list_tickets
  description: Stream tickets by recency; resumable.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.SUPPORT_DB_PW}@db/support"
    query:
      sql: |
        SELECT id, subject, updated_at
        FROM tickets
        WHERE (updated_at, id) > (:_after_updated_at, :_after_id)
        ORDER BY updated_at, id
        LIMIT 500
      row_mode: stream
      max_rows: 500
      stream:
        cursor_columns: [updated_at, id]
        initial: { updated_at: "1970-01-01T00:00:00Z", id: 0 }
        signing_key_env: TICKETS_STREAM_KEY
```

The `:_after_<col>` placeholders are emitted in the same order
as `cursor_columns`. The SQL must compare the row tuple in
that same order — if you flip them, you'll get duplicate or
skipped rows on continuation.

---

## 13. Submit + poll until done

**Lives under:** `mcp.capabilities.tools[]`.

`await:` runs an optional kickoff statement, then polls a check
query until a CEL predicate matches (or `timeout_ms` elapses).
The main `query:` block is required by the schema but bypassed
under `await:` — set it to a stub.

```yaml
- name: provision_workspace
  description: Submit a workspace provision job and wait for completion.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.PROVISION_DB_PW}@db/provision"
    query:
      sql: "SELECT 1"
      row_mode: scalar
    await:
      trigger:
        sql: |
          INSERT INTO provision_jobs (user_id, plan)
          VALUES (:user, :plan)
        params: [user, plan]
      check:
        sql: |
          SELECT id, status, error
          FROM provision_jobs
          WHERE user_id = :user
          ORDER BY id DESC
          LIMIT 1
        params: [user]
      # Match on `completed`; surface failures by including the
      # error column in the response when status = 'failed'.
      predicate: 'row.status == "completed" || row.status == "failed"'
      poll_interval_ms: 2000
      timeout_ms: 120000
```

The matched row returns to the caller as the response;
hitting `timeout_ms` returns `BindingError::Timeout`. The
`mcpg_sql_await_polls_total{outcome=matched|timeout}` counter
tracks the actual poll count at termination.

## 14. Wait on an externally-triggered job

**Lives under:** `mcp.capabilities.tools[]`.

If the job is started by something else (cron, another service,
a queue worker), drop the `trigger:` block entirely. The plugin
just polls the check query.

```yaml
backend:
  kind: sql
  driver: postgres
  url: "postgres://app:${env.RUNS_DB_PW}@db/runs"
  query:
    sql: "SELECT 1"
    row_mode: scalar
  await:
    check:
      sql: "SELECT status FROM nightly_runs WHERE run_date = :run_date"
      params: [run_date]
    predicate: 'row != null && row.status == "ready"'
    poll_interval_ms: 5000
    timeout_ms: 600000   # 10 min — match the longest expected run
```

`row` is `null` when the check returned no rows. The CEL
guard handles the "job hasn't been inserted yet" gap.

---

## 15. Poll-mode watch (any engine)

**Lives under:** `mcp.capabilities.resources[]`.

A `watch.strategy` block makes a resource entry reactive: the
strategy plugin runs a tracking query at `interval_ms` and
emits a `WatchEvent` whenever the scalar advances. The gateway
fans the event out as `notifications/resources/updated` to
every subscribed MCP session.

```yaml
- name: orders_feed
  uri: "sql://orders/feed"
  description: Recent orders, push-updated.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
    query:
      sql: "SELECT id, total_cents, status FROM orders ORDER BY id DESC LIMIT 100"
      row_mode: many
      max_rows: 100
  watch:
    strategy:
      type: sql_polling
      driver: postgres
      url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
      interval_ms: 2000
      query:
        sql: "SELECT MAX(updated_at) FROM orders"
        row_mode: scalar
```

`interval_ms` floor is 100 ms. Advance is detected by scalar
inequality, so the tracking query needs to return a value that
strictly increases with the data — `MAX(updated_at)`,
`COUNT(*)` for insert-only tables, `MAX(id)` for an
append-only feed.

## 16. Postgres `LISTEN/NOTIFY` watch

**Lives under:** `mcp.capabilities.resources[]`.

For Postgres-only deployments, `postgres_listen_notify` holds
one dedicated LISTEN connection and re-emits NOTIFY payloads
as `WatchEvent`s. Far lower overhead than polling.

```yaml
- name: orders_changes
  uri: "sql://orders/changes"
  description: Live notification feed for order changes.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
    query:
      sql: "SELECT 1"
      row_mode: scalar
  watch:
    strategy:
      type: postgres_listen_notify
      url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
      channel: orders_changed
```

Wire a trigger on the source table to `pg_notify('orders_changed', …)`
so writes emit a NOTIFY. Each replica runs its own LISTEN — DB
load scales with replica count, but the cluster bus dedupes
per-subscriber so each session only sees one event per change.

---

## 17. Two-statement atomic transaction

**Lives under:** `mcp.capabilities.tools[]`.

`sql_tx` is a *pipeline* step kind, not a backend kind. Wrap it
in a `backend.kind: pipeline` tool that references an existing
SQL-backed tool's pool by name (the `binding:` field below).

```yaml
- name: place_order
  description: Deduct inventory and record the order atomically.
  backend:
    kind: pipeline
    pipeline_timeout_ms: 5000
    steps:
      - id: charge
        kind: sql_tx
        binding: orders_db        # name of an existing tool whose backend.kind == sql
        steps:
          - id: deduct_inventory
            sql: "UPDATE inventory SET qty = qty - 1 WHERE sku = :sku AND qty > 0"
            params: [sku]
            row_mode: affected_rows
          - id: record_order
            sql: "INSERT INTO orders (user_id, sku) VALUES (:u, :sku) RETURNING id"
            params: [u, sku]
            row_mode: scalar
```

Either both nested steps commit together or both roll back —
`deduct_inventory` returning `rows_affected: 0` (out of stock)
returns `0` to the caller but does not roll back; downstream
pipeline steps can branch on it via
`steps.charge.output.steps.deduct_inventory.rows_affected`.
Roll back explicitly by returning an error from a transform
step downstream of the `sql_tx`. Supported nested row modes:
`affected_rows`, `many`, `single`, `scalar`. The `binding:`
field name is historical — it references the *tool name* of an
SQL-backed entry, not a backend plugin.

## 18. Optimistic-lock retry on `xmin`

**Lives under:** `mcp.capabilities.tools[]`.

When two writers race, you don't want a transaction; you want
a CAS-style update that returns `rows_affected: 0` on conflict
and lets the caller retry. Postgres's `xmin` system column
gives you a free row version.

```yaml
- name: update_settings_optimistic
  description: CAS-update settings; returns 0 affected if the row changed under us.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.SETTINGS_DB_PW}@db/settings"
    query:
      sql: |
        UPDATE settings
        SET value = :value, updated_at = :now
        WHERE id = :id AND xmin = CAST(:expected_xmin AS xid)
      params: [id, value, expected_xmin, now]
      row_mode: affected_rows
      param_exprs:
        now: 'now()'
```

The caller passes the `xmin` they read in a prior SELECT; the
UPDATE matches only if no concurrent writer touched the row in
between. `affected_rows: 0` = lost the race; the client decides
whether to re-read and retry.

---

## 19. Postgres RLS via `session_vars`

**Lives under:** `mcp.capabilities.tools[]`.

`session_vars` runs `set_config('<key>', $1, true)` (transaction-scoped)
before the query. A Postgres RLS policy keyed on
`current_setting('app.current_tenant')` then sees the
authenticated principal's tenant on every call.

```yaml
- name: list_tickets
  description: List tickets; tenant-scoped via Postgres RLS.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.SUPPORT_DB_PW}@db/support"
    query:
      sql: "SELECT id, subject, status FROM tickets"
      row_mode: many
      max_rows: 100
    session_vars:
      # Identifier safety enforced at config parse — values are
      # parameterized.
      "app.current_tenant": "${identity.tenant}"
```

DB-side RLS:

```sql
ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tickets_tenant_isolation ON tickets
  USING (tenant = current_setting('app.current_tenant'));
```

Session vars are Postgres-only — MySQL and SQLite ignore them
with a registration-time warning.

## 20. Tenant-scoped reads via CEL `param_exprs`

**Lives under:** `mcp.capabilities.tools[]`.

If you can't use RLS (MySQL pool, read replica without write
GUC), fall back to binding the tenant explicitly via CEL.

```yaml
- name: list_tickets
  description: List tickets; tenant filter bound via identity claim.
  backend:
    kind: sql
    driver: mysql
    url: "mysql://app:${env.SUPPORT_DB_PW}@db/support"
    query:
      sql: "SELECT id, subject, status FROM tickets WHERE tenant = :tenant"
      params: [tenant]
      row_mode: many
      max_rows: 100
      param_exprs:
        tenant: 'identity.tenant'
```

The principal's tenant comes from the auth chain; the caller
can't override it because `tenant` is computed, not from
`arguments`. Less defense-in-depth than RLS (one missed
binding leaks data) but engine-portable.

---

## 21. Scalar aggregate (`scalar`)

**Lives under:** `mcp.capabilities.tools[]`.

Pulls the first column of the first row out as a naked value —
no `{count: 42}` envelope, just `42`.

```yaml
- name: count_open_tickets
  description: Count open tickets for the current tenant.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.SUPPORT_DB_PW}@db/support"
    query:
      sql: "SELECT count(*) FROM tickets WHERE status = 'open' AND tenant = :tenant"
      params: [tenant]
      row_mode: scalar
      param_exprs:
        tenant: 'identity.tenant'
```

## 22. Top-N report

**Lives under:** `mcp.capabilities.tools[]`.

```yaml
- name: top_customers
  description: Top 20 customers by order volume in a date range.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://reports:${env.REPORTS_DB_PW}@db/orders"
    query:
      sql: |
        SELECT customer_id,
               sum(total_cents) AS revenue_cents,
               count(*)         AS order_count
        FROM orders
        WHERE created_at >= :since AND created_at < :until
        GROUP BY customer_id
        ORDER BY revenue_cents DESC
        LIMIT 20
      params: [since, until]
      row_mode: many
      timeout_ms: 10000
```

A 10-second timeout is generous for an aggregation; tune to
your data volume + index strategy. If you regularly hit the
timeout, the answer is usually a covering index, not a higher
budget.

## 23. Export-as-resource (CSV-shaped JSON)

**Lives under:** `mcp.capabilities.resource_templates[]`.

A CSV export becomes a one-row, one-column SELECT that builds
the CSV string in SQL and returns it as MCP resource contents.

```yaml
- name: ticket_export
  uri_template: "export://tickets/{date}.csv"
  description: Daily tickets export as CSV.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://reports:${env.REPORTS_DB_PW}@db/support"
    query:
      sql: |
        SELECT 'export://tickets/' || :date || '.csv' AS uri,
               string_agg(
                 id || ',' || quote_literal(subject) || ',' || status,
                 E'\n'
               ) AS text,
               'text/csv' AS mime_type
        FROM tickets
        WHERE date(created_at) = CAST(:date AS DATE)
      params: [date]
      row_mode: resource_contents
      timeout_ms: 30000
```

Use `quote_literal` (or your engine's equivalent) to escape
commas and newlines inside cells — the SQL backend parameterizes
*values*, but it's your SQL's job to produce well-formed CSV.

---

## 24. Feature flag check

**Lives under:** `mcp.capabilities.tools[]`.

A boolean flag lookup is just a `scalar` SELECT — but it's
worth wiring caching so 10k tool calls per second don't all
hit the DB.

```yaml
- name: feature_flag_enabled
  description: Read a per-tenant feature flag value.
  cache:
    # See backends.md → "Per-backend response cache".
    ttl_ms: 30000
    scope: per_principal
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.FLAGS_DB_PW}@db/flags"
    query:
      sql: |
        SELECT enabled
        FROM feature_flags
        WHERE key = :key AND tenant = :tenant
      params: [key, tenant]
      row_mode: scalar
      param_exprs:
        tenant: 'identity.tenant'
```

The 30s cache absorbs the read storm; flag flips take up to
30s to roll out — usually fine for a flag system.

## 25. Audit log export with cursor continuation

**Lives under:** `mcp.capabilities.tools[]`.

A months-long audit table won't fit in one page. `row_mode:
stream` paginates via keyset; the client (a SIEM exporter,
typically) calls until `next_cursor: null`.

```yaml
- name: audit_export
  description: Stream audit events; resumable via _cursor.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://siem_export:${env.AUDIT_DB_PW}@db/audit"
    query:
      sql: |
        SELECT id, occurred_at, principal, event_type, meta
        FROM audit_events
        WHERE occurred_at >= :since
          AND (occurred_at, id) > (:_after_occurred_at, :_after_id)
        ORDER BY occurred_at, id
        LIMIT 1000
      params: [since]
      row_mode: stream
      max_rows: 1000
      timeout_ms: 60000
      stream:
        cursor_columns: [occurred_at, id]
        initial: { occurred_at: "1970-01-01T00:00:00Z", id: 0 }
        signing_key_env: AUDIT_STREAM_KEY
```

The `:since` filter is a regular caller-supplied parameter;
the `:_after_*` placeholders are auto-bound by the SQL backend
on continuation. Stamp the export job with a fixed `since`
and let the cursor walk forward — don't re-bind `:since`
mid-export, you'll get inconsistency.

## 26. DB health probe

**Lives under:** `mcp.capabilities.tools[]`.

A liveness probe tool gives you a one-call latency floor
into your DB pool that an external monitor can poll. Keep it
on a *separate* tool (and pool) from your hot path so a
saturated production pool doesn't make the probe lie.

```yaml
- name: db_ping
  description: Health probe for the orders DB pool.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.ORDERS_DB_PW}@db/orders"
    pool:
      # Tiny pool: don't compete for connections with the hot path.
      max_connections: 2
      acquire_timeout_ms: 1000
    query:
      sql: "SELECT 1"
      row_mode: scalar
      timeout_ms: 1000
    circuit_breaker:
      failure_threshold: 3
      cooldown_ms: 10000
```

The circuit breaker keeps the probe from hammering a dead DB.
External monitors that scrape this tool should expect
`Transport`/`Timeout` during outages — that's the signal,
not a bug.

---

## See also

- [`backends.md`](../backends.md#sql-backend) — full reference
- [`troubleshooting.md`](troubleshooting.md) — failure modes + diagnosis
- [`migration.md`](migration.md) — converting a REST-wrapped DB tool
- [`pipelines.md`](../pipelines.md) — pipeline + `sql_tx` reference
- [`identity-and-authorization.md`](../identity-and-authorization.md) — `identity.*` CEL surface used in `param_exprs`
- Worked-example configs: `examples/26-sql-sqlite-todos`,
  `examples/27-sql-dynamic-resource-listings`,
  `examples/28-sql-pipeline-tx`,
  `examples/29-sql-await-job`
