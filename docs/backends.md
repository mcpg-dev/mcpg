# MCPG Backends Reference

> Complete reference for the backend kinds MCPG ships. Each backend maps one
> MCP capability to one downstream integration, selected by a nested
> `backend.kind:` discriminator. The `BackendImpl` enum defines **27 kinds**:
> 10 general-purpose (`http`, `command`, `nats`, `grpc`, `graphql`, `kafka`,
> `mock`, `pipeline`, `openapi`, `sql`) plus a **17-kind LLM family**
> (OpenAI / Azure OpenAI / Anthropic / Gemini / Stability / OpenAI-compatible
> chat, embedding, image, TTS, and STT). This page documents the 10
> general-purpose kinds; the LLM family lives in the LLM backend plugins under
> `libs/plugins/backend/llms/` (see [the LLM backend docs](#llm-backend-family)).
> Source: `config/backend.rs` (`BackendImpl`, ~L313–415), `backends/mod.rs`
> (capability registry), `runtime/execution.rs` (execution dispatcher)

## Common Backend Fields

Every backend shares these fields:

```yaml
- name: "tool_name"                  # string — Unique MCP capability name (required)
  description: "What it does"        # string — MCP tool description (required)
  title: null                        # Option<string> — Display title
  minimum_trust: unauthenticated     # enum — unauthenticated | header_asserted | verified
  cel_allow_if: null                 # Option<string> — CEL expression for access control
  input_schema: null                 # Option<JSON> — JSON Schema for argument validation
  mcp_app_url: null                  # Option<string> — MCP App URL for _meta.mcpAppUrl (resource/resource_template only)
  backend:                           # required — implementation backend, discriminated by `kind:`
    kind: <variant>                  # tag — one of 27 BackendImpl kinds; the 10 general-purpose
                                     #   ones are: http, command, nats, grpc, graphql, kafka,
                                     #   mock, pipeline, openapi, sql (+ 17 LLM kinds)
    # …variant-specific fields are flattened siblings, e.g. url:, method:, headers: for `kind: http`
```

**`mcp_app_url`**: When set on entries under `mcp.capabilities.resources[]` or `mcp.capabilities.resource_templates[]`, the resolved value appears in `_meta.mcpAppUrl` on both `resources/list` descriptors and `resources/read` results. Supports CEL interpolation (e.g., `"https://app.example.com/docs/${arguments.id}"`). Static values are merged at build time with zero runtime cost.

**Governance**: `minimum_trust` and `cel_allow_if` are evaluated by the pre-dispatch policy gate before execution. See [identity-and-authorization.md](identity-and-authorization.md).

**Input validation**: When `input_schema` is a valid JSON Schema, tool arguments are validated against it before execution. Invalid arguments produce a JSON-RPC error without invoking the backend.

---

## HTTP Backend

Executes an HTTP request to a downstream endpoint. Supports POST and GET methods.

```yaml
backend:
  kind: http
  url: "https://api.example.com/endpoint"    # string — Target URL (required); CEL + cred:// supported
  method: post                               # enum — post | get (default: post)
  timeout_ms: 5000                           # u64 — Request timeout
  max_response_bytes: 1048576                # usize — Max response body size
  expected_status_codes: [200]               # Vec<u16> — Accepted HTTP status codes
  require_json_response: true                # bool — Require valid JSON response
  headers:                                   # BTreeMap<string, string> — Custom headers; CEL + cred:// supported
    Authorization: "Bearer ${cred://vault-oauth/api}"
```

**Dispatch**: Routed through `mcpg-plugin-backend-http` (a `BackendPlugin`
registered with `kind: "http"`). The plugin owns the `reqwest` client,
DNS-rebinding guard, body-limit truncation, structured-envelope shaping,
and per-credential client cache. The gateway no longer carries inline
HTTP/1.1 implementation; the operator-visible YAML shape is unchanged
from earlier releases.

**Requires**: a `plugins[]` entry declaring the http cdylib. http is a
runtime-loaded plugin (`dev.mcpg.backend.http`, `runtime: native-cdylib-v1`)
— **not** statically linked into the gateway. **Full pluggability is now
complete: every backend, http included, is a runtime-loaded cdylib; the
`mcpg` binary hard-wires no backend.** The operator-facing `backend: { kind:
http, … }` YAML is unchanged.

**Execution**:
- POST: sends tool arguments as JSON body
- GET: sends tool arguments as query parameters
- Response body is parsed as JSON (if `require_json_response`) or returned as text
- Non-matching status codes produce an error result with retry classification

**Per-call CEL.** Both `url` and individual header values support CEL
templates against the standard variable bag (`${arguments.X}`,
`${context.principal_id}`, `${tool_name}`, etc.). Templates are
compiled at config-load and evaluated per call by the plugin — same
engine the gateway uses for SQL `param_exprs`.

**Per-caller credentials.** `cred://<plugin>/<target>` URIs in `url`
or in any header value resolve at dispatch time. The plugin maintains
a per-credential `reqwest::Client` cache keyed on a BLAKE3 digest of
the resolved bundle (LRU + idle eviction + revocation subscriber,
mirroring the NATS/Kafka shape). See `docs/per-caller-credentials.md`
for the full recipe.

**Private-network guard.** By default the plugin refuses to dial
loopback / RFC1918 / link-local / ULA destinations after DNS
resolution (defence-in-depth against rebinding). Set
`gateway.server.allow_private_backends: true` (or per-binding
`allow_private_backends: true`) to permit them in trusted-network
deployments.

---

## Command Backend

Executes a local subprocess and captures its output.

```yaml
backend:
  kind: command
  command: "/usr/bin/my-tool"                # string — Executable path (required)
  args: ["--format", "json"]                 # Vec<string> — Arguments
  timeout_ms: 10000                          # u64 — Execution timeout
  max_output_bytes: 1048576                  # usize — Max stdout capture
  require_json_stdout: true                  # bool — Require valid JSON stdout
```

**Requires**: a `plugins[]` entry declaring the command cdylib
(`dev.mcpg.backend.command`, `runtime: native-cdylib-v1`) — **not** statically
linked into the gateway. The command runs locally (no network / SSRF surface,
so no `plugins[]` `config:` block); `args` support CEL templating against
`arguments` / `context` (the `command` path itself is never templated). A
command binding with no matching entry fails fast at boot.

**Execution**:
- Tool arguments are written to stdin as JSON
- Stdout is captured up to `max_output_bytes`
- Timeout kills the process
- Non-zero exit code produces an error result
- If `require_json_stdout`, output must parse as valid JSON

---

## NATS Backend

Sends a request via NATS Core request/reply pattern.

```yaml
backend:
  kind: nats
  url: "nats://broker:4222"                  # string — NATS server URL (all nats bindings must agree)
  credentials_path: "/etc/mcpg/nats.creds"   # optional — NATS credentials file
  subject: "backend.request"                 # string — NATS subject (required)
  timeout_ms: 5000                           # u64 — Request timeout
  max_response_bytes: 1048576                # usize — Max reply payload
```

**Requires**: a `plugins[]` entry declaring the NATS cdylib. NATS is a
runtime-loaded plugin (`dev.mcpg.backend.nats`, `runtime:
native-cdylib-v1`) — **not** statically linked into the gateway. The
plugin's connection (`url` / `credentials_path`) is taken from the NATS
bindings (single source of truth), so the entry needs no `config:` block:

```yaml
plugins:
  - id: dev.mcpg.backend.nats
    source:
      oci: ghcr.io/mcpg-dev/source-code/plugins/backend-nats:<version>-linux-amd64
      # or: path: /opt/mcpg/plugins/libmcpg_plugin_backend_nats.so
```

A NATS binding with no matching `plugins[]` entry fails fast at boot. The
single entry registers both the `nats` binding and the `nats_topic` watch
strategy.

**Dispatch**: Routed through `dev.mcpg.backend.nats` (a `BackendPlugin`
registered with `kind: "nats"`). The main gateway binary carries no
`async-nats` dependency; the plugin owns the NATS client (connected
lazily on first use) and request/reply logic.

**Execution**:
- Publishes tool arguments as JSON to the configured NATS subject
- Waits for a reply on an auto-generated inbox
- Propagates W3C `traceparent` / `tracestate` via NATS message headers
- Timeout produces an error result
- Reply payload is returned as tool output (truncated at `max_response_bytes`)

---

## gRPC Backend

Invokes a gRPC service method using proto-less JSON mapping via HTTP POST.

```yaml
backend:
  kind: grpc
  url: "https://grpc.example.com"                 # string — gRPC endpoint base (required)
  service: "example.UserService"                  # string — fully-qualified service (required)
  method: "GetUser"                               # string — method name (required)
  timeout_ms: 5000                                # u64 — Request timeout
  max_response_bytes: 1048576                     # usize — Max response size
  headers: {}                                     # BTreeMap<string, string> — Metadata
```

**Requires**: a `plugins[]` entry declaring the grpc cdylib
(`dev.mcpg.backend.grpc`, `runtime: native-cdylib-v1`) — **not** statically
linked. Built on the shared `net-core` HTTP core (reqwest client + per-cred
cache + DNS-rebinding guard + per-call CEL/`cred://` resolution), the same
core http/graphql use.

**Execution**:
- Sends tool arguments as JSON body via HTTP POST to `{endpoint}/{service}/{method}`
- Expects JSON response mapped from protobuf
- Uses standard HTTP/2 transport (not native gRPC framing)
- A non-200 status produces an error result

---

## GraphQL Backend

Executes a GraphQL query or mutation.

```yaml
backend:
  kind: graphql
  url: "https://api.example.com/graphql"           # string — GraphQL endpoint (required)
  operation: "query GetUser($id: ID!) { user(id: $id) { name } }"  # string — query/mutation document (required)
  timeout_ms: 5000                                 # u64 — Request timeout
  max_response_bytes: 1048576                      # usize — Max response size
  headers: {}                                      # BTreeMap<string, string> — Custom headers
```

**Requires**: a `plugins[]` entry declaring the graphql cdylib
(`dev.mcpg.backend.graphql`, `runtime: native-cdylib-v1`) — **not** statically
linked. Built on the shared `net-core` HTTP core, like grpc/http.

**Execution**:
- Sends `{ "query": "...", "variables": <arguments> }` as JSON POST
- Tool arguments become GraphQL variables
- Response `data` field is extracted as output
- A non-200 status **or** a non-empty `errors` array produces an error result

---

## Kafka Backend

Sends a message via Kafka and waits for a correlated response.

```yaml
backend:
  kind: kafka
  request_topic: "requests"                        # string — Kafka topic for requests
  response_topic: "responses"                      # string — Kafka topic for responses
  timeout_ms: 10000                                # u64 — Request timeout
  max_response_bytes: 1048576                      # usize — Max response size
  bootstrap_servers: "broker:9092"                 # string? — OPTIONAL per-binding override of the plugin-level brokers
```

**Requires**: a `plugins[]` entry declaring the kafka cdylib. Kafka is a
runtime-loaded plugin (`dev.mcpg.backend.kafka`, `runtime: native-cdylib-v1`)
— it is **not** statically linked into the gateway. `bootstrap_servers` comes
from the kafka bindings (a binding's value is used; no plugin `config:` block
needed); `group_id` is plugin-level and defaults to `mcpg` — it is **not** a
per-binding `backend:` field. (Kafka cross-compiles for **all** release targets —
linux-gnu, musl, macOS, and Windows — via rdkafka's `cmake-build` + vendored deps.)

```yaml
plugins:
  - id: dev.mcpg.backend.kafka
    source:
      oci: ghcr.io/mcpg-dev/source-code/plugins/backend-kafka:<version>-linux-amd64
      # or, for a locally-staged build:
      # path: /opt/mcpg/plugins/libmcpg_plugin_backend_kafka.so
```

A kafka binding with no matching `plugins[]` entry fails fast at boot.
The single entry registers both the `kafka` binding and the `kafka_topic`
watch strategy.

**Dispatch**: Routed through `mcpg-plugin-backend-kafka` (a `BackendPlugin`
registered with `kind: "kafka"`). The main gateway binary carries no
`rdkafka` dependency; the plugin owns the producer/consumer pair. The YAML
shape above is unchanged from the pre-extraction design.

**Execution**:
- Generates a unique correlation ID (`mcpg-corr-{uuid}`)
- Subscribes to `response_topic` before publishing
- Publishes tool arguments as JSON to `request_topic` with correlation ID header
- Forwards W3C `traceparent` as a Kafka record header when present
- Filters responses by correlation ID
- Timeout produces an error result

---

## SQL Backend

Executes a parameterized query (or stored procedure) against PostgreSQL,
MySQL/MariaDB, or SQLite, and returns rows shaped by `row_mode`.

> **Operator docs:**
> [`sql/cookbook.md`](sql/cookbook.md) — 26 worked recipes ·
> [`sql/migration.md`](sql/migration.md) — converting REST-wrapped DB tools ·
> [`sql/troubleshooting.md`](sql/troubleshooting.md) — failure modes + fixes

```yaml
backend:
  kind: sql
  driver: postgres                                       # postgres | mysql | mariadb | sqlite
  url: "postgres://app:${env.ORDERS_DB_PW}@db:5432/orders"  # connection URL with embedded creds
  pool:
    max_connections: 10
    min_idle: 1
    acquire_timeout_ms: 5000
    idle_timeout_ms: 300000
    max_lifetime_ms: 1800000
    test_before_acquire: true
  query:
    sql: "SELECT id, total FROM orders WHERE tenant = :tenant"  # or `procedure` or `sql_file`
    params: ["tenant"]                                   # named placeholders bind in this order
    row_mode: many                                       # single | many | scalar | affected_rows | resource_contents | stream
    max_rows: 1000
    timeout_ms: 3000
    progress_heartbeat_ms: 500                           # Optional — emit heartbeat every N ms
  schema:
    derive: input                                        # off | input | output | both — opt-in
  session_vars:                                          # Postgres only (SET LOCAL via set_config)
    app.current_tenant: "${identity.tenant}"
```

**Dispatch**: Routed through `mcpg-plugin-backend-sql` (a `BackendPlugin`
registered with `kind: "sql"`). Driver support is feature-gated at compile
time (`postgres`, `mysql`, `sqlite`).

**Credentials**: Three mutually-exclusive surfaces, exactly one per binding.

1. **Static password in `url`** (default).
   The gateway expands `${env.VAR}` against the process environment at
   config-load time, so literal secrets never live in YAML source. Future
   resolvers (`vault:…`, `aws-sm:…`, `gcp-sm:…`) land in the same gateway
   interpolator as distinct schemes.

2. **Per-caller dynamic credentials via `cred://`** in the URL or any
   `session_vars` value. Resolved at request time by the host against
   the `(plugin_id, target)` keys named in the URI. Pools are
   per-credential-bundle in a bounded LRU.

3. **Cloud-DB IAM token auth via the `auth:` block** (Postgres-only
   today). The plugin fetches a short-lived token from the configured
   provider at pool-construction time and refreshes it on schedule. Token
   rotation rebuilds connection options on the live pool — existing
   connections drain at `pool.max_lifetime` (auto-capped to
   `token_ttl - safety_margin`), new ones use the fresh token.

   ```yaml
   backend:
     kind: sql
     driver: postgres
     # IMPORTANT: no `:password@` segment — the auth provider supplies it.
     url: "postgres://app@orders.cluster-xyz.us-east-1.rds.amazonaws.com:5432/orders"
     query: { sql: "SELECT 1", row_mode: scalar }
     auth:
       kind: rds_iam               # P7.2 — Cargo feature `sql-rds-iam`
       region: us-east-1
       username: app
       # profile: prod             # optional; defaults to AWS_PROFILE / IMDS / IRSA
   ```

   Schemes available today:

   | `kind` | Cargo feature | Status |
   |---|---|---|
   | `rds_iam` | `sql-rds-iam` | ✅ Shipped (P7.2) |
   | `azure_ad` | `sql-azure-ad` | 📋 Scaffolded (P7.3) |
   | `gcp_iam` | `sql-gcp-iam` | 📋 Scaffolded (P7.4) |
   | `aurora_failover` | `sql-aurora-failover` | 📋 Scaffolded (P7.6) |

   All four parse + validate today; only `rds_iam` actually fetches tokens.
   The other three return a clear "not yet implemented" error at boot, so
   operator YAML targeting them stays valid across the rollout.

   Combining `auth:` with a password embedded in `url`, or with a
   `cred://` reference, is a config error — exactly one credential
   surface per binding. Validation rejects this at startup.

**Schema derivation (`schema.derive`)**: When set to `input` or `both`,
the plugin introspects the prepared statement's parameter types (Postgres
only today) and emits a JSON Schema fragment for each placeholder. The
derived schema flows into `tools/list` merged with any operator-supplied
`input_schema`: operator fields win at every key, so hand-authored
descriptions and enums coexist with derived types.

**Progress heartbeat (`progress_heartbeat_ms`)**: While a query is
in-flight, a background task emits a tracing event and bumps
`mcpg_sql_progress_heartbeats_total` every N ms. Zero overhead when
unset; zero ticks for queries that complete faster than the first
interval. Floor: 50 ms.

**Resources and resource templates (P2.1 / P2.2)**: Add the entry
under `mcp.capabilities.resources[]` with a static `uri`, or under
`mcp.capabilities.resource_templates[]` with a `uri_template` like
`sqldoc://{slug}`. For templates, the captured variables (`slug`,
…) flow into `arguments` under their declared names so the SQL
placeholder binding picks them up as `:slug`. Use
`row_mode: resource_contents` to have the plugin auto-wrap the
SELECTed `uri` / `text` (or `blob`) / `mime_type` columns as the
MCP `{contents: [...]}` payload — no hand-written
`json_build_object` required.

**Dynamic resource listings (`list_query`) (P2.3)**: A
resource-template entry can declare a `list_query` block so
`resources/list` enumerates concrete resources backed by live
rows. Keyset pagination is the default; operators should pick a
cursor column (id / updated_at) that's monotonic and indexed.

```yaml
list_query:
  sql: |
    SELECT uri, name, description, mime_type
    FROM documents
    WHERE (:cursor IS NULL OR id > CAST(:cursor AS BIGINT))
    ORDER BY id
    LIMIT :page_size
  mode: keyset                                         # keyset | offset
  cursor_column: id                                    # required for keyset mode
  page_size: 100                                       # 1..=1000
```

Only `:cursor` and `:page_size` placeholders are plugin-bound —
any other `:name` in `list_query.sql` is rejected at startup.
Short page (`rows < page_size`) signals the tail and the plugin
emits `next_cursor: null`. The gateway's `resources/list`
handler fans out to every entry under `mcp.capabilities.resources[]`
and `mcp.capabilities.resource_templates[]` whose backend plugin
supports `list_resources`, merging dynamic rows onto the static
registry on the first page.
Multi-page dynamic listings are capped to the first page in this
slice — composite cursor stitching is a follow-up.

**Streaming row shape (`row_mode: stream`) (P4.4)**: Pages large
result sets via *keyset* (cursor-bound) continuation. Response
shape:

```json
{ "rows": [...], "next_cursor": "s.<base64>.<hmac>", "truncated": false }
```

Operators declare a `stream:` block naming the cursor key columns:

```yaml
query:
  sql: |
    SELECT id, name FROM users
    WHERE id > :_after_id
    ORDER BY id
    LIMIT 500
  row_mode: stream
  max_rows: 500
  stream:
    cursor_columns: [id]      # required: keyset key
    initial: { id: 0 }        # bootstrap for first page
    # signing_key_env: USERS_STREAM_KEY  # required for cluster mode
```

The plugin auto-binds last-row values to `:_after_<col>` placeholders
on continuation calls — operators don't have to thread the cursor
into `params`. The SQL must reference one `:_after_<col>` placeholder
per declared cursor column, ordered by the same columns (validated
at config-load).

Continuation: clients pass the previous response's `next_cursor` as
the `_cursor` argument on the next call. The plugin verifies the
HMAC, checks backend-name match, and binds the keyset values. Empty
`next_cursor` (`null`) signals end-of-stream.

**Cluster correctness**: cursors are stateless — no server-side
cursor table, no pinned connections — so any gateway instance can
decode and resume. Operators running multi-instance gateways MUST
set `stream.signing_key_env` to a shared secret across all
instances; otherwise each gateway uses a per-process random key
and cross-node continuation calls fail HMAC verification (a WARN
fires at boot in that case). Single-node deploys work fine without
the env var.

**Fire-and-wait (`await`) (P3.3)**: For "submit work, poll until
it's done" flows, declare an `await` block alongside `query`. The
main `query` block is a schema requirement but is bypassed when
`await` is present — set it to `sql: "SELECT 1"` / `row_mode:
scalar` as a stub.

```yaml
await:
  trigger:                                             # optional kickoff statement
    sql: "INSERT INTO provision_jobs (user_id) VALUES (:u)"
    params: [u]
  check:                                               # polled until predicate true
    sql: "SELECT status FROM provision_jobs WHERE user_id = :u ORDER BY id DESC LIMIT 1"
    params: [u]
  predicate: 'row.status == "completed"'               # CEL against the check row
  poll_interval_ms: 2000                               # floor 100 ms
  timeout_ms: 120000                                   # >= poll_interval_ms
```

**Runtime:** when an `await`-configured backend is invoked, the
plugin fires the trigger once, then polls the check query on
`poll_interval_ms`. Each tick runs the check, binds the first row
into CEL as `row` (or `null` for empty result sets), and
evaluates the `predicate`. A match returns the check row to the
caller as the response; exceeding `timeout_ms` returns
`BackendError::Timeout`. Bound CEL variables: `row` (single
object shape, `null` when the check returned no rows) and
`arguments` (the caller's JSON arg object).

**Metrics:** `mcpg_sql_await_polls_total{binding, driver, outcome}`
counter increments by the actual poll count at termination
(`outcome` ∈ `matched` / `timeout`).

**Transactional pipeline steps (`sql_tx`) (P4.1)**: A pipeline
backend can nest a `kind: sql_tx` container (referencing the SQL
backend by name via `backend:`) to group statements under one
transaction on that backend's pool. The
executor threads a `SqlTxHandle` through every nested statement,
commits on success, and rolls back on any nested-step failure.
See the [Pipeline Backend](#pipeline-backend) section.

**Schema-drift retry (P8.5)**: When a prepared statement fails
with a SQLSTATE that signals a stale plan (Postgres `26000`
`42P18` `0A000`, MySQL `1615 ER_NEED_REPREPARE`), the plugin
transparently evicts the cached statement and retries once on a
fresh pool connection. Elevated
`mcpg_sql_prepare_retries_total` values correlate with concurrent
DDL / schema migrations mid-uptime.

**Audit annotations (`_meta.audit`) (P6.3)**: Every SQL call
stamps the tool result's `_meta.audit` with
`{backend_kind, backend_profile, outcome}`. When the AuditPlugin
is configured with `include_result_meta: true` (default), the
audit event's `meta` field picks this up so SIEM exports carry
the SQL-specific audit context alongside the principal /
transport half.

**Circuit breaker (`circuit_breaker`) (P6.6)**: Per-backend
fail-fast when the DB is unhealthy. Configure:

```yaml
circuit_breaker:
  failure_threshold: 5       # consecutive Transport/Timeout errors to trip
  cooldown_ms: 30000         # Open → HalfOpen transition
```

Omit the block to disable. State machine is Closed → Open →
HalfOpen → Closed; a single probe admitted at a time. Snapshot
available via `SqlBackendPlugin::circuit_snapshot(name)`.

**Metrics** (via the `metrics` crate, bounded-cardinality labels):

- `mcpg_sql_calls_total{binding,query,driver,status}` counter
- `mcpg_sql_duration_seconds{binding,query,driver}` histogram
- `mcpg_sql_rows_returned{binding,query}` histogram
- `mcpg_sql_progress_heartbeats_total{binding,driver}` counter
- `mcpg_sql_requests_in_flight{driver}` gauge
- `mcpg_sql_prepare_retries_total{binding,driver}` counter
- `mcpg_sql_await_polls_total{binding,driver,outcome}` counter
- `mcpg_sql_pool_connections{binding,state}` gauge (pool-sampler
  hookup point — idle/used/waiting; no sampler task yet, so
  operators wiring the metric today will see a default zero)
- `mcpg_sql_pool_acquire_wait_seconds{binding}` histogram (pool-level
  wait sampling; fires when a call blocks on pool acquire — reserved
  for the Phase-2 sampler task)
- `mcpg_sql_await_wait_seconds{binding,driver,outcome}` histogram
  (reserved hook for total-wait duration; use
  `mcpg_sql_await_polls_total × poll_interval_ms` as a derived
  signal until the sampler lands)

**Benchmarks**: Criterion benches covering the per-call hot path,
pool-saturation contention, `await` first-poll match, and
`list_resources` page cost live in
`libs/plugins/backend/sql/benches/`. Run locally with:

```bash
cargo bench -p mcpg-plugin-backend-sql --bench sql_binding_hot_paths
# or --quick for a fast signal pass:
cargo bench -p mcpg-plugin-backend-sql -- --quick
```

CI sanity-compiles the bench binary on every SQL PR so a
bench-side type break surfaces at review time; baselines are
tracked on operator hardware, not the CI runner.

**Driver-level cancel (P5.2 / P5.3 / P5.4)**: Postgres backends
cancel in-flight queries via `pg_cancel_backend` on a side
connection once the plugin captures the backend PID at
pool-acquire time. MySQL / MariaDB use `KILL QUERY
<connection_id>` — the DB pool user must hold `PROCESS` /
`CONNECTION_ADMIN` privilege for cancel to succeed, otherwise
the cancel surfaces a transport error and the query runs to
completion (acceptable degradation). SQLite backends now
participate via `sqlite3_interrupt` on the pinned connection
handle (the one SQLite C API documented as cross-thread safe),
so MCP cancellation lands within ~milliseconds on long-running
recursive queries even though SQLite has no server-side
side-channel.

**Watch strategies**: Two watch plugins register alongside the
backend plugin and are now exposed through the operator-facing
`watch.strategy` discriminator (P2.6):

Both example entries below live under `mcp.capabilities.resources[]`.

```yaml
- name: orders_feed
  uri: sql://orders/feed
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.PW}@db/orders"
    query: { … }
  watch:
    strategy:
      type: sql_polling                    # ← `kind: sql_polling` plugin
      driver: postgres
      url: "postgres://app:${env.PW}@db/orders"
      interval_ms: 2000
      query:
        sql: "SELECT MAX(updated_at) FROM orders"
        row_mode: scalar

- name: orders_changes
  uri: sql://orders/changes
  backend:
    kind: sql
    driver: postgres
    url: "postgres://app:${env.PW}@db/orders"
    query: { … }
  watch:
    strategy:
      type: postgres_listen_notify         # ← `kind: postgres_listen_notify` plugin
      url: "postgres://app:${env.PW}@db/orders"
      channel: orders_changed              # the NOTIFY channel
```

Two strategies, one trade-off: `sql_polling` runs a tracking
scalar query at `interval_ms` (floor 100 ms) and emits an event
on scalar advance — works against any SQL engine. The
`postgres_listen_notify` strategy (P3.1) holds one dedicated
LISTEN connection per watcher and re-emits NOTIFY payloads as
`WatchEvent`s — far lower overhead than polling, Postgres-only.

Both plumb through the same fan-out (P2.6): once a plugin emits
a `WatchEvent`, it flows through `notification_filter` (All /
SubjectId / SessionId / CEL `Expression`) → `SubscriptionStore`
→ `DeliveryBus` → MCP session SSE. The cluster delivery bus
routes per-session, so a watch event firing on replica A
reaches a subscriber session pinned to replica B with no extra
wiring. Every replica runs its own watch loop — DB load scales
with replica count for both polling and LISTEN — but the
cluster bus deduplicates delivery to one wire per subscriber.

---

## Mock Backend

Returns a configured response with no I/O. Used for testing and development.

```yaml
backend:
  kind: mock
  response:                                       # Value — configured response
    message: "hello from mock"
    status: "ok"
  delay_ms: 0                                     # u64 — simulated latency
  error: false                                    # bool — simulate a tool error
  error_message: null                             # optional string — error text (error mode)
  passthrough: false                              # bool — treat `response` as a literal CallToolResult
```

**Requires**: a `plugins[]` entry declaring the mock cdylib
(`dev.mcpg.backend.mock`, `runtime: native-cdylib-v1`) — **not** statically
linked. No network / SSRF surface, so no `config:` block. A mock binding with
no matching entry fails fast at boot.

**Execution**:
- Default: `response` is JSON-stringified into a text content block plus
  structured metadata (after `delay_ms`).
- `error: true`: returns a simulated error result (`is_error: true`) with
  `error_message` (default `"mock error"`).
- `passthrough: true`: `response` is surfaced as a **literal** `CallToolResult`
  (its own `content` / `isError` / `structuredContent`) — for image / audio /
  embedded-resource / mixed-content shapes the wrapping path can't reach.
  Validated at registration: `response` must be a CallToolResult-shaped object.

> Passthrough + the simulated-error mode rely on the host's
> `__mcpg_verbatim_result` envelope convention so the operator controls
> `is_error` + content exactly.

---

## OpenAPI Backend

Surfaces one operation of a registered OpenAPI spec as an MCP tool. The
operator names only a `source` + `operation`; the plugin parses the spec,
derives the tool's input/output JSON Schema from that operation, and
dispatches the call as an outbound HTTP request to the upstream API.

```yaml
backend:
  kind: openapi
  source: petstore        # string — a source declared in the plugin's config (required)
  operation: getPetById   # string — the OpenAPI operationId to surface (required)
```

The binding references a `source` declared in the **plugin's own config**
(`plugins[].config.sources[]`), where the spec, upstream `base_url`,
per-scheme auth, and safety limits live:

```yaml
plugins:
  - id: dev.mcpg.backend.openapi
    source:
      oci: ghcr.io/mcpg-dev/source-code/plugins/backend-openapi:<version>-linux-amd64
      # or: path: /opt/mcpg/plugins/libmcpg_plugin_backend_openapi.so
    config:
      sources:
        - name: petstore
          spec: "file:///etc/mcpg/specs/petstore.yaml"   # file:// URI or { inline: {...} }
          base_url: "https://api.petstore.example.com"    # overrides spec servers[0].url
          auth:
            apiKeyAuth: "${cred://vault-api/petstore}"     # keyed by the spec's securityScheme name
```

**Requires**: a `plugins[]` entry declaring the openapi cdylib
(`dev.mcpg.backend.openapi`, `runtime: native-cdylib-v1`). An openapi binding
with no matching entry — or naming a `source` / `operation` the plugin can't
resolve — fails fast at boot.

**Two surfacing modes**:
- **Reference-only (Tier 1)**: explicit `backend: { kind: openapi, source, operation }`
  bindings, one per operation you choose to expose.
- **Bulk auto-expose (Tier 2)**: set `expose.tools: true` on the source to
  fan out every (filtered) operation as a tool; read-by-id `GET`s become
  resource templates by default. `filter` (allow/deny) and `tool_prefix`
  scope and namespace the generated tools.

**Execution**:
- Path / query / header / body parameters are bound from the tool arguments
  per the operation's spec
- Security schemes named in `auth:` are injected the way the spec declares
  (header / query / bearer / basic)
- Built on the shared `net-core` HTTP core (per-cred client cache,
  DNS-rebinding guard, body-limit truncation), like http/grpc/graphql
- `${cred://<issuer>/<target>}` tokens in `headers` / `auth` resolve
  per-call through the host

---

## Pipeline Backend

Orchestrates multiple steps into a single tool call. See [pipelines.md](pipelines.md) for the complete pipeline reference.

```yaml
backend:
  kind: pipeline
  pipeline_timeout_ms: 30000                      # u64 — Total pipeline timeout
  steps:                                          # Vec<PipelineStepConfig> — Ordered steps
    - id: "fetch"
      kind: http
      # …http step fields
    - id: "transform"
      kind: transform
      expression: 'completed_steps.fetch.output.data'
```

**Execution**:
- Executes steps sequentially
- Each step reads from pipeline context (original_args, request_context, completed_steps)
- Suspending steps (elicitation, sampling) persist state and resume on client response
- First error aborts the pipeline

**`sql_tx` container step (P4.1)**: Groups one or more SQL
statements under a single transaction on a referenced SQL
backend's pool — all-or-nothing semantics.

```yaml
steps:
  - id: charge_flow
    kind: sql_tx
    backend: orders_db                                 # existing SQL backend name
    steps:
      - id: deduct_inventory
        sql: "UPDATE inventory SET qty = qty - 1 WHERE id = :id"
        params: [id]
      - id: record_order
        sql: "INSERT INTO orders (user_id, item_id) VALUES (:u, :i)"
        params: [u, i]
        row_mode: affected_rows                        # defaults to affected_rows
```

Validation (unique nested IDs, non-empty SQL, recognised
`row_mode`) runs at startup. At dispatch time the executor calls
`plugin.begin_transaction(binding)`, runs each nested statement
against the pinned `SqlTxHandle` (supported row modes:
`affected_rows`, `many`, `single`, `scalar`), and commits — a
failure at any nested step rolls the whole group back. Nested
results surface to downstream pipeline steps as
`steps.<tx_step_id>.output.steps.<nested_id>` so transforms and
CEL gates can reference them directly.

---

## LLM Backend Family

Beyond the 10 general-purpose kinds above, `BackendImpl` defines a **17-kind
LLM family** — managed bindings to hosted and self-hosted model APIs. Each is
a separate `backend.kind:` selected the same way (`backend: { kind: <llm-kind>, … }`),
backed by an LLM cdylib under `libs/plugins/backend/llms/`. Like `sql`, these
bindings forward a raw spec to the plugin, which owns the per-kind schema.

| `backend.kind` | Surface | Plugin |
|---|---|---|
| `openai_chat` | OpenAI chat completions | `mcpg-plugin-backend-llm-openai` |
| `azure_openai_chat` | Azure OpenAI chat (per-deployment URL) | `mcpg-plugin-backend-llm-openai` |
| `anthropic_chat` | Anthropic Messages API | `mcpg-plugin-backend-llm-anthropic` |
| `gemini_chat` | Google Gemini AI Studio chat | `mcpg-plugin-backend-llm-gemini` |
| `compat_chat` | Any OpenAI-compatible endpoint (vLLM, LocalAI, Together, Groq, OpenRouter, llama.cpp, Vertex compat) | `mcpg-plugin-backend-llm-compat` |
| `openai_embedding` | OpenAI embeddings | `mcpg-plugin-backend-llm-openai` |
| `azure_openai_embedding` | Azure OpenAI embeddings | `mcpg-plugin-backend-llm-openai` |
| `gemini_embedding` | Gemini embeddings | `mcpg-plugin-backend-llm-gemini` |
| `compat_embedding` | OpenAI-compatible embeddings | `mcpg-plugin-backend-llm-compat` |
| `openai_image` | OpenAI image generation (DALL·E) | `mcpg-plugin-backend-llm-openai` |
| `azure_openai_image` | Azure OpenAI image | `mcpg-plugin-backend-llm-openai` |
| `gemini_image` | Google Imagen | `mcpg-plugin-backend-llm-gemini` |
| `stability_image` | Stability AI Stable Image (Core / SD3 / Ultra) | `mcpg-plugin-backend-llm-stability` |
| `openai_tts` | OpenAI text-to-speech | `mcpg-plugin-backend-llm-openai` |
| `azure_openai_tts` | Azure OpenAI TTS | `mcpg-plugin-backend-llm-openai` |
| `openai_stt` | OpenAI speech-to-text (Whisper) | `mcpg-plugin-backend-llm-openai` |
| `azure_openai_stt` | Azure OpenAI STT | `mcpg-plugin-backend-llm-openai` |

Each LLM kind requires its cdylib declared in `plugins[]`. See the LLM
backend plugin docs under `libs/plugins/backend/llms/` for per-kind config
(model, API key via `cred://`, generation parameters, streaming).

---

## Debug Tools (Built-in)

When `debug: true`, the following tools are automatically registered:

| Tool Name | Description |
|---|---|
| `mcpg.runtime.snapshot` | Runtime metadata: service info, uptime, session count |
| `mcpg.request.echo` | Echo request context and arguments |
| `mcpg.debug.command_probe` | Execute a configured command profile |
| `mcpg.debug.network_probe` | HTTP GET to a configured endpoint |
| `mcpg.debug.network_json_call` | HTTP POST JSON to a configured endpoint |

Debug tools are controlled by `debug.tools.exposure` config flags. When `debug.enabled: false` (the default), none of these tools are registered.

Built-in prompts:
- `mcpg_operational_overview` — Operational summary prompt (when `exposure.operational_overview_prompt: true`)

Built-in resources:
- `mcpg://runtime/overview` — Runtime overview resource (when `exposure.runtime_overview_resource: true`)
