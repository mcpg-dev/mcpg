# SQL backend troubleshooting

Practical failure modes that come up in production, with the
signal you'll see and how to fix them. Pair this with
[`backends.md`](../backends.md#sql-backend) for the spec surface
and [`cookbook.md`](cookbook.md) for working
configurations.

Each section follows the same shape: **symptom**, what the
backend emits (errors / metrics / logs), root cause, fix.

---

## Where to look first

Before diving into a specific symptom:

1. **Metrics.** `mcpg_sql_calls_total{binding,status}` shows
   per-backend error rate by status (`ok` / `error` / `timeout`).
   `mcpg_sql_requests_in_flight{driver}` shows the live
   queue depth — sustained > 0 when traffic is idle means a
   stuck call.
2. **Tracing.** `mcpg::sql::audit` spans wrap every call;
   `mcpg::sql::pool` spans wrap pool acquire. Filter to
   `level=ERROR` to see the failures alone, then walk
   upstream from a failing span to see what the caller
   passed.
3. **Audit events.** Each call stamps the tool result's
   `_meta.audit` with `{backend_kind, backend_profile,
   outcome}` — the audit log is the source of truth for
   "did the call run, did it succeed, who made it."
4. **DB-side log.** When the backend reports a
   `Transport`/`Timeout`, check the DB's slow-query / error
   log for the same wall-clock window. The DB usually has
   more context (lock wait, deadlock victim, killed by admin)
   than the backend does.

---

## Pool acquire timeout / `max_connections` saturation

**Symptom:** intermittent `BackendError::Timeout` with
`timeout_ms` matching `pool.acquire_timeout_ms`. Latency
histograms show a bimodal distribution — fast under normal
load, capped at the acquire timeout when the pool's full.
`mcpg_sql_pool_acquire_wait_seconds{binding}` histogram
shoulders rightward.

**Cause:** all `max_connections` connections are checked out;
new calls block on acquire and time out before a connection
frees. Common drivers:

- A long-running query holding a connection (cancel via
  MCP `notifications/cancelled`, or fix the query).
- Concurrent caller burst exceeding `max_connections`.
- A leaked transaction (rare — `sql_tx` rolls back on every
  failure; the leak tests in `tests/leak_*.rs` pin this).

**Fix order:**

1. Find the slow query. `pg_stat_activity` (Postgres) or
   `SHOW FULL PROCESSLIST` (MySQL) — the longest-running
   row by `state_change` / `time` is your culprit.
2. If the query is intentional, raise `pool.max_connections`
   for that backend and cross-check the DB-side
   `max_connections` headroom (every replica × every backend
   counts against the same DB-side limit).
3. If the query is unintentional, lower `query.timeout_ms`
   so the backend kills it via `pg_cancel_backend` /
   `KILL QUERY` rather than waiting for acquire timeout.

> **Sizing note:** `(replicas × backends × max_connections)
> ≤ DB max_connections × 0.7`. The 0.7 leaves headroom for
> admin sessions, pgbouncer overhead, and slow rollouts.

---

## "no such table" / "relation does not exist"

**Symptom:** `BackendError::Transport` with the engine's
"relation does not exist" / "no such table" message.
Reproducible 100% on the backend, fine when run via `psql` /
`mysql` interactively as the same user.

**Cause:** schema search path / database mismatch.

- Postgres: the user's `search_path` doesn't include the
  schema. Verify via `\dt schema_name.*`.
- MySQL: the URL connected to the wrong database — embed
  it in the URL path (`mysql://u:p@h/dbname`), don't rely on
  default-database settings.
- SQLite: each `:memory:` connection gets a private DB. Use
  `sqlite:file:memdb_xyz?mode=memory&cache=shared` to share
  state across connections in the same pool.

**Fix:** make the schema explicit in the SQL (`schema.table`
in Postgres / `db.table` in MySQL) or set `search_path` via
`session_vars` (Postgres):

```yaml
session_vars:
  search_path: "app, public"
```

---

## Schema drift after DDL — `mcpg_sql_prepare_retries_total` climbs

**Symptom:** brief error spike during a deploy that
included DDL; recovery within seconds. Errors carry SQLSTATE
`26000`, `42P18`, `0A000` (Postgres) or MySQL error 1615
(`ER_NEED_REPREPARE`).

**Cause:** the backend's prepared statement cache held a
plan that referenced a column shape no longer valid after
the DDL. The backend evicts the cached plan and retries
once on a fresh connection — that's the `prepare_retries`
counter incrementing.

**This is working as designed** (P8.5). If you see this
counter climb without a deploy, you have a background
process running ad-hoc DDL — find it and either gate it
behind an explicit migration step or accept the elevated
retry rate as the cost of online DDL.

If errors *fail to recover* after retries, the cache eviction
isn't reaching the connection that holds the stale plan —
file a bug with the SQLSTATE and a repro.

---

## TLS / certificate failures

**Symptom:** `BackendError::Transport` at boot with
`certificate verify failed`, `unknown CA`, `hostname
mismatch`, or an SSL/TLS handshake error.

**Cause one — `sslmode=` mismatch (Postgres):** sqlx defaults
differ by driver. Pin it explicitly in the URL:

```
postgres://app:pw@host:5432/db?sslmode=require
postgres://app:pw@host:5432/db?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem
```

`require` accepts any cert; `verify-ca` checks the chain;
`verify-full` checks chain + hostname. Use `verify-full` in
prod.

**Cause two — system trust store missing CA:** the gateway
process can't see the CA that signed the DB cert. Mount your
internal CA bundle at `/etc/ssl/certs/ca-certificates.crt`
or set `sslrootcert=` to a file the gateway can read.

**Cause three — MySQL/MariaDB `ssl-mode`:** same idea, but
the URL parameter is `ssl-mode=REQUIRED` /
`ssl-mode=VERIFY_CA` / `ssl-mode=VERIFY_IDENTITY`.

**Cause four — older MariaDB uses `ssl=true` / `ssl=false`**
without a mode parameter. If you're targeting MariaDB 10.x,
check the connector's URL syntax.

---

## MySQL auth-plugin mismatch

**Symptom:** boot fails with
`Authentication plugin 'caching_sha2_password' cannot be
loaded` or `client does not support authentication protocol
requested by server`.

**Cause:** the DB user is using `caching_sha2_password` (MySQL
8 default) but the client / proxy in front of the backend
expects the legacy `mysql_native_password`.

**Fix — sqlx handles it natively**, so the failure usually
means a proxy in between (PgBouncer-equivalent for MySQL,
ProxySQL, etc.) doesn't speak `caching_sha2_password`.
Either:

- Connect the backend directly to MySQL (skip the proxy).
- Switch the user to `mysql_native_password`:

  ```sql
  ALTER USER 'mcpg'@'%' IDENTIFIED WITH mysql_native_password BY 'pw';
  ```

  MySQL 8.4 dropped `mysql_native_password` from the default
  plugin list — re-enable with `--mysql-native-password=ON`
  on the server side. Plan to flip back to
  `caching_sha2_password` once the proxy supports it.

---

## MariaDB `mariadb://` vs `mysql://` URL scheme

**Symptom:** backend refuses to register against MariaDB
with `unsupported driver` even though sqlx supports it.

**Cause:** the backend's driver dispatch keys on the URL
scheme. MariaDB images accept both `mysql://` and
`mariadb://`; the backend's `MysqlDriver` is registered for
both. If you used a malformed scheme (`maria://`,
`mysql://?driver=mariadb`), the dispatch fails.

**Fix:** use one of the two canonical schemes:

```
mysql://app:pw@db/orders
mariadb://app:pw@db/orders
```

Both go through the same driver code; pick whichever your
team finds clearer.

---

## Cancel privilege probe fails (MySQL/MariaDB)

**Symptom:** backend fails to register with a long error
like:

> MySQL pool user lacks the PROCESS / CONNECTION_ADMIN
> privilege required to cancel another connection's
> in-flight statement (P5.4 / KILL QUERY) ...

**Cause:** the backend probes `SHOW GRANTS FOR CURRENT_USER`
at registration to confirm the pool user can `KILL QUERY`
on a sibling session — `pg_cancel_backend`'s MySQL
equivalent. The user has neither `PROCESS` nor
`CONNECTION_ADMIN`.

**Fix one (preferred):** grant the privilege.

```sql
GRANT PROCESS ON *.* TO 'mcpg'@'%';
FLUSH PRIVILEGES;
```

Use `CONNECTION_ADMIN` instead on MySQL 8+ for tighter
scoping — `PROCESS` also lets the user list other sessions'
queries.

**Fix two (opt out, with caveats):**

```yaml
pool:
  require_cancel_privilege: false
```

Cancellation requests will become no-ops — long-running
queries run to completion regardless of MCP
`notifications/cancelled` or `query.timeout_ms`. Acceptable
for low-stakes tools; not recommended for hot-path backends.

---

## PgBouncer + prepared-statement leaks

**Symptom:** transient `prepared statement … already exists`
errors against Postgres-via-PgBouncer; intermittent stale-plan
errors that don't match the schema-drift signal above.

**Cause:** PgBouncer's `pool_mode=transaction` (or
`statement`) shares server connections across client sessions.
sqlx's prepared-statement cache assumes a stable connection;
when PgBouncer rotates, the cached plan name collides on a
new server connection that already has its own version.

**Fix order:**

1. **Best:** point the backend directly at Postgres, not at
   PgBouncer. The backend's own pool replaces PgBouncer for
   this layer; PgBouncer's value is at the
   100-microservices-fan-in level, not 1-backend-1-DB.
2. **If PgBouncer is required:** set `pool_mode=session` on
   the PgBouncer route this backend uses. Session pooling
   pins a server connection for the client session's
   lifetime — sqlx's cache stays valid.
3. **As a last resort with `transaction` mode:** disable
   prepared-statement caching by setting up the URL with
   `application_name=disable_prepared` and using a custom
   PgBouncer config — this is a sqlx-level workaround and
   loses the perf benefit of cached plans. Most operators
   should prefer (1) or (2).

---

## RLS not applied (Postgres)

**Symptom:** the backend runs against a Postgres table with
RLS enabled, but rows leak across tenants. CEL identity is
populated correctly (verify with the audit log).

**Cause one — pool user is `BYPASSRLS`:** if your DB user
has `BYPASSRLS` or `SUPERUSER`, the policy is skipped. Check:

```sql
SELECT rolname, rolbypassrls, rolsuper FROM pg_roles WHERE rolname = 'mcpg';
```

**Fix:** revoke the bypass.

```sql
ALTER ROLE mcpg NOBYPASSRLS NOSUPERUSER;
```

**Cause two — `session_vars` reaching a hot-standby:**
`SET LOCAL` is a write-side GUC; if your URL points at a
read-only replica that doesn't support `set_config`, the
GUC silently fails to take effect on the replica. The
policy reads an empty `current_setting` and either denies
all rows (strict policy) or allows all (permissive default).

**Fix:** use the engine-portable approach (cookbook
[#20](cookbook.md#20-tenant-scoped-reads-via-cel-param_exprs))
on read replicas, or point the backend at the primary if
your traffic shape allows.

**Cause three — `current_setting('app.current_tenant')`
returns `null` mid-pool:** the GUC is `LOCAL`-scoped, so it
applies only to the current transaction. If your SQL spans
multiple statements without explicit `BEGIN`, the second one
won't see the GUC. Single-statement SQL is fine; multi-step
work belongs in a `sql_tx` step (see cookbook
[#17](cookbook.md#17-two-statement-atomic-transaction))
where the GUC + statements share one transaction.

---

## SQLite "database is locked" under WAL

**Symptom:** intermittent `database is locked` errors on a
filesystem-backed SQLite DB even though you set
`journal_mode=WAL`. WAL mode is supposed to let readers run
during writes.

**Cause one — `:memory:` per-connection privacy:** if you
configured `sqlite::memory:` instead of a file URL, each
connection gets its own DB. Schema visible to one connection
isn't visible to another. Use a shared-cache memdb URL:

```
sqlite:file:memdb_xyz?mode=memory&cache=shared
```

**Cause two — WAL not actually set:** `PRAGMA journal_mode =
WAL` is per-connection, but the result *persists* in the DB
file. If a connection closes before sqlite checkpoints, the
mode might revert. Verify with a separate tool (under
`mcp.capabilities.tools[]`):

```yaml
- name: check_journal
  description: Inspect the configured journal mode for the data DB.
  backend:
    kind: sql
    driver: sqlite
    url: "sqlite:/var/lib/app/data.db"
    query:
      sql: "PRAGMA journal_mode"
      row_mode: scalar
```

The expected response is `"wal"` (lowercase).

**Cause three — long write transactions blocking the WAL
checkpoint:** WAL accumulates pages until a checkpoint flushes
them. A multi-minute write transaction holds the
`SQLITE_BUSY` floor open. Keep write transactions short or
configure `wal_autocheckpoint` to a smaller page count.

---

## Stream cursor verification fails

**Symptom:** clients calling a `row_mode: stream` tool get
`InvalidSpec` with `cursor HMAC verification failed` on
continuation calls. First call works; second fails.

**Cause one — running multi-replica without a shared
signing key:** without `stream.signing_key_env`, each
gateway replica generates a per-process random HMAC key. A
continuation hitting replica B fails to verify a cursor
signed by replica A. A `WARN` fires at boot in this case —
check your logs for `signing key was not configured`.

**Fix:** set `stream.signing_key_env` to a shared secret.

```yaml
stream:
  cursor_columns: [id]
  initial: { id: 0 }
  signing_key_env: USERS_STREAM_KEY
```

The env var holds 32+ bytes of high-entropy material (use
`openssl rand -hex 32`). Roll it during scheduled
maintenance — every in-flight cursor invalidates on roll.

**Cause two — backend rename mid-stream:** the cursor's HMAC
binds to the backend name. Renaming `list_users` → `users`
between continuation calls invalidates every outstanding
cursor. Don't rename mid-traffic; if you must, drain
in-flight streams first.

**Cause three — clock skew on `:since`-bound exports:** the
`:since` filter is a regular caller-supplied parameter; the
cursor only carries the `:_after_*` keyset. If the exporter
re-binds `:since` to "now" each continuation call, the
filter window slides and you see duplicates / gaps. Stamp
`:since` at export-job creation and pass the same value
on every continuation.

---

## `LISTEN/NOTIFY` watch drops events

**Symptom:** subscribers miss `notifications/resources/updated`
events for changes they should have seen. Polling watch on
the same DB sees the changes.

**Cause one — payload too large:** Postgres caps NOTIFY
payloads at 8 KB by default. Sending row JSON in the payload
triggers silent drop on overflow. Send only an opaque key
(`pg_notify('orders_changed', new.id::text)`) and let
subscribers re-fetch.

**Cause two — listener connection died:** the
`postgres_listen_notify` strategy holds one dedicated
connection per watcher. If your DB drops idle TCP after
5 min and the backend hasn't re-listened, you miss events.
Keep-alives (`tcp_keepalives_idle=60` in the URL) keep the
socket warm; the strategy reconnects on read error but a
race between drop and next NOTIFY loses events in flight.

**Cause three — `NOTIFY` runs before listeners attach at
boot:** the strategy connects + LISTENs at gateway start.
If the data-producer fires NOTIFY *before* the gateway
finishes booting, those events are dropped (they're not
queued). Match readiness probes to "backend registered"
not "TCP open."

---

## Progress heartbeat says the query is alive but it's actually deadlocked

**Symptom:** `mcpg_sql_progress_heartbeats_total` keeps
incrementing for a backend well past `query.timeout_ms`.
The backend eventually returns `Timeout`.

**Cause:** the heartbeat is a *liveness* signal — the
backend's still polling the future — not a *progress*
signal from the DB. A query waiting on a row lock looks
identical to a query doing real work from the backend's
side.

**Fix:** look at the DB. `pg_stat_activity.wait_event_type`
shows `Lock`, `IO`, `Client` for the stuck session.

```sql
SELECT pid, state, wait_event_type, wait_event, query, now() - query_start AS run_time
FROM pg_stat_activity
WHERE state != 'idle' AND query NOT LIKE '%pg_stat_activity%'
ORDER BY run_time DESC
LIMIT 5;
```

For MySQL, `SHOW FULL PROCESSLIST` shows `Time` and
`State`. A persistent `Locked` state under a heartbeating
backend means lock contention, not a slow query — find
the holder of the conflicting lock and treat the symptom
there.

---

## Circuit breaker sticks open

**Symptom:** every call to a backend returns `Transport`
with `circuit breaker open` even though the DB has been
healthy for minutes.

**Cause:** the breaker is in the `Open` state; `cooldown_ms`
hasn't elapsed yet, or the half-open probe hasn't been
admitted. The state machine is Closed → Open → HalfOpen →
Closed, with one probe admitted at a time.

**Diagnose:** call `SqlBindingPlugin::circuit_snapshot(name)`
from a debug backend (or read the underlying tracing field
`mcpg::sql::breaker.state`). If `state=open` and your
`cooldown_ms` is 30000 but the last failure was 35 seconds
ago, the breaker should have transitioned. If it didn't, a
race condition is suspected — file a bug.

If `cooldown_ms` is too long for your deploy cadence, lower
it. Typical values: 5–30 s for low-stakes tools, longer for
budget-bound external DBs.

**Don't** raise `failure_threshold` to 1000 to "make it not
trip" — that defeats the breaker. The breaker exists to
keep a sick DB from getting hammered by retries; if it's
tripping spuriously, the upstream signal needs fixing
(reduce `query.timeout_ms` to fail fast, fix the slow
query).

---

## "Query failed: column 'x' does not exist" but the column does exist

**Symptom:** static config that was working starts failing
with a column-doesn't-exist error after a schema migration.
Manual verification shows the column is there.

**Cause:** prepared-statement cache referencing pre-migration
column types. This is the [schema-drift case](#schema-drift-after-ddl--mcpg_sql_prepare_retries_total-climbs)
— the backend will retry on stale-plan SQLSTATE and recover
within one call. If the error persists across multiple calls,
the SQLSTATE coming back from the engine isn't on the retry
list.

**Diagnose:** turn on driver-level tracing
(`RUST_LOG=mcpg_plugin_binding_sql=debug,sqlx=debug`) and
look for the SQLSTATE field on the failing error. If it's a
new code we should add to the retry list, file a bug with
the SQLSTATE + the DDL that triggered it.

---

## "InvalidSpec: named placeholder ':x' is not listed in `params`"

**Symptom:** registering a new backend fails immediately
with this error.

**Cause:** every named placeholder (`:foo`) in `query.sql`
must be declared in `params: [foo]`. The backend refuses
unlisted placeholders to prevent accidental
parameter-injection bugs (a typo in a placeholder name
would otherwise fall through to a default-bind).

**Fix:** add the placeholder to `params:` in the order it
should bind. `param_exprs` placeholders also count — if
`param_exprs.now` exists, `now` must be in `params`.

```yaml
query:
  sql: "INSERT INTO t (k, created_at) VALUES (:k, :now)"
  params: [k, now]                  # both placeholders listed
  param_exprs:
    now: 'now()'                    # supplied by CEL
```

---

## "InvalidSpec: multi-statement bodies are not allowed"

**Symptom:** registration fails with a multi-statement
rejection on a SQL body that contains an unquoted `;`
between statements.

**Cause:** the backend rejects multi-statement bodies at
config parse to keep parameter binding sane. Multi-step
atomic work belongs in a `kind: sql_tx` pipeline step (see
cookbook [#17](cookbook.md#17-two-statement-atomic-transaction)),
not in one body.

**Fix:** split into separate backends, or wrap in a `sql_tx`
pipeline.

A bare semicolon inside a string literal or a `--` /
`/* */` comment is fine — the rejector skips quoted
content and stripped comments. The error fires on
**unquoted, top-level `;`** between statements.

---

## "InvalidSpec: privileged DDL is rejected"

**Symptom:** backends containing `GRANT`, `REVOKE`, or
`CREATE/ALTER/DROP USER/ROLE/DATABASE/GROUP` fail at
registration.

**Cause:** P11.5 — the backend is for application-scoped
data access, not role/grant administration. Privileged
DDL is refused at config parse.

**Fix:** if you genuinely need to create users/roles via
the gateway, configure a separately-scoped admin backend
gated behind `governance.minimum_trust = "verified"` and
an allowlist policy. For most operators, this is a sign
the wrong tool is reaching for `GRANT` — admin DDL belongs
in a migration tool, not an MCP tool call.

Regular schema DDL (`CREATE TABLE`, `ALTER TABLE`,
`DROP INDEX`, …) is allowed.

---

## See also

- [`backends.md`](../backends.md#sql-backend) — full reference
- [`cookbook.md`](cookbook.md) — recipes
- [`migration.md`](migration.md) — converting REST wrappers
- [`observability.md`](../observability.md) — metrics + tracing setup
- [`audit.md`](../audit.md) — audit-event shape + sinks
