# Per-caller credentials with `cred://`

> **Status.** Available from PROTOCOL_VERSION 1.8 / ABI v25 onward.
> HTTP added at 1.10. Supported backends: **SQL** (Postgres, MySQL,
> MariaDB, SQLite), **NATS**, **Kafka**, **HTTP**. Pipeline steps
> that delegate to these backends inherit per-caller credentials
> automatically.

This doc walks operators through per-caller credentials end-to-end:
what they are, why you'd use them, how they work under the hood, and
how to configure each supported backend. If you're new to MCPG, start
at the top; if you already know what `cred://` is and just want the
config snippets, jump to [Configuration recipes](#configuration-recipes).

---

## What "per-caller credentials" means

In a typical MCPG deployment, every backend connection authenticates
with one static credential — the username/password baked into a
binding's connection URL, the SASL secret on a Kafka cluster, the
JWT file path on a NATS cluster. Every caller hitting that backend
shares that one identity.

Per-caller credentials flip that. The backend authenticates as
**the caller**, not as MCPG. Two callers hitting the same SQL
binding can land on the same Postgres server with different
DB-side users, getting different `pg_class` row visibility, different
audit trails on the DB side, and different blast radius if a
credential leaks.

The control plane is the `cred://<plugin>/<target>[#part]` URI scheme.
Anywhere a binding's config carries a connection-bearing string —
the SQL `url`, a NATS `auth_token`, a Kafka `sasl_password` — you
can drop in `${cred://vault-pg/orders}` instead of a literal value.
At dispatch time MCPG asks the named credential-issuer plugin to
mint a credential for the *caller's* identity and substitutes the
result before opening the connection.

---

## Why use it

Three concrete drivers:

1. **DB-side visibility.** PostgreSQL row-level security, Snowflake
   secure views, and many enterprise data-warehouse setups gate row
   visibility on the connecting role. Per-caller credentials let
   you delegate that gate to the database instead of re-implementing
   it at the gateway. The DB does what it's good at.

2. **Blast-radius containment.** A leaked static credential exposes
   every row reachable by that role. A per-caller credential is
   scoped to one identity and typically auto-rotates on a short TTL
   (Vault dynamic DB roles, AWS RDS IAM auth, Kafka SASL/OAUTHBEARER).
   When a caller's session ends — or their account is disabled —
   the credential is revoked and downstream connections drop within
   milliseconds.

3. **Auditability.** Database, NATS, and Kafka audit logs attribute
   actions to *the caller*, not to MCPG-the-shared-service-account.
   That makes server-side compliance posture (SOX, HIPAA, PCI)
   match the gateway-side caller identity that already lives in
   MCPG's audit ledger.

If you're running MCPG in front of multi-tenant data, financial
systems, or anything that needs caller-attributed audit, this is
the feature you want.

---

## How it works

### One-time setup: a credential-issuer plugin

A *credential issuer* is a plugin that knows how to mint credentials
for a (caller-identity, target) pair. MCPG ships with first-party
issuers for Vault dynamic DB roles, OAuth2 client-credentials, etc.;
custom issuers compose against the `CredentialIssuer` trait.

The issuer is registered like any other plugin:

```yaml
plugins:
  - id: dev.mcpg.credential.vault-dynamic-db
    class: credential_issuer
    config:
      vault_addr: ${env.VAULT_ADDR}
      role_path: db/creds/orders-rw
```

The plugin's *name* in `cred://<name>/<target>` is whatever you
named it in the registry. So `cred://vault-dynamic-db/orders` calls
the plugin above with `target = "orders"`.

### Per-call resolution flow

For every tool call against a backend that carries a `cred://`
reference, MCPG runs:

```
caller request
  └─ identity extraction (OIDC token / mTLS / SPIRE / API key)
      └─ for each cred:// in binding spec:
          ├─ check CredentialCache for (identity_hash, plugin, target)
          │   └─ HIT → return cached credential (within TTL)
          │   └─ MISS → call issuer plugin's `issue(identity, target)`
          │             └─ cache the result
          └─ substitute into a per-call snapshot of the spec
      └─ compute BLAKE3 digest of the resolved bundle
      └─ get-or-build connection from per-credential pool/client cache
      └─ execute the call
```

**Two cached layers, not one.** The credential cache holds the
*credential value* (DB password, JWT, etc.). The pool/client
registry holds *open connections*, keyed on a digest of the
resolved-credential bundle so two callers whose creds end up
identical (e.g. both mapped to the same Vault role) share one
connection.

**Why a digest, not the URI.** What controls DB-side identity is
what's *inside* the issued credential — the username, the
password, the session role. Two `cred://` URIs that resolve to
the same bundle should share one pool. Two URIs that *look*
identical but resolve to different bundles (per-caller) should
get different pools. Hashing the resolved bundle gives both for
free.

### Eviction

Three eviction triggers:

- **On revocation.** Issuer plugins broadcast revocation events
  (`CacheEvent::Revoked` for the plugin/target tuple). The
  registry subscribes; when a revocation matches an entry's
  `cred_keys`, the pool/client is dropped and the next call from
  that caller mints fresh credentials. In clustered mode, the
  broadcast reaches every replica, so revocation is gateway-wide.

- **On idle.** Pools/clients untouched for 15 minutes (default,
  configurable) drop. Bounds steady-state connection count when a
  large caller cohort goes quiet.

- **On capacity.** A bounded LRU triggers at 256 entries (default)
  per binding. An issuer that fans out to thousands of distinct
  callers cannot pin unbounded backend connections.

### Failure semantics

When a `cred://` resolution fails — issuer offline, target
unknown, missing required field — the caller sees an *opaque*
error message:

> `backend credential is not configured (id: 0a3f-…)`

The correlation ID matches an audit-log entry containing the full
`(plugin_id, target, part)` tuple. Operators can grep
`mcpg::credentials` audit events by correlation ID to triage,
without leaking which credential issuers and target names exist
to the caller. (Topology disclosure is a real concern for
multi-tenant deployments; the split is deliberate.)

---

## Configuration recipes

### SQL backend

Put `cred://` references in the connection URL or in any
`session_vars` value:

```yaml
- name: orders_query
  backend:
    kind: sql
    driver: postgres
    url: postgres://${cred://vault-dynamic-db/orders#username}:${cred://vault-dynamic-db/orders#password}@db.internal:5432/orders
    session_vars:
      app.user_id: ${cred://vault-dynamic-db/orders#username}
    query: |
      SELECT * FROM orders WHERE customer_id = $1
```

Each caller hits Postgres as their own DB user — `pg_stat_activity`
attributes connections per caller, RLS policies tied to
`current_user` work as expected, and revocation flows from Vault
through MCPG's credential cache to the connection pool.

### NATS backend

`cred://` is supported in `url`, `credentials_path`, and
`auth_token`:

```yaml
- name: place_order
  backend:
    kind: nats
    url: nats://nats.internal:4222
    auth_token: ${cred://vault-nats/orders-publisher}
    subject: orders.place
```

Each caller's published message authenticates with their own NATS
JWT/token. `auth_token` is the most common path; `credentials_path`
also works if your issuer plugin materialises NATS .creds files.

### Kafka backend

`cred://` is supported in `bootstrap_servers`, `sasl_username`, and
`sasl_password`:

```yaml
- name: emit_event
  backend:
    kind: kafka
    bootstrap_servers: kafka.internal:9092
    security_protocol: SASL_SSL
    sasl_mechanism: SCRAM-SHA-256
    sasl_username: ${cred://vault-kafka/orders}
    sasl_password: ${cred://vault-kafka/orders#password}
    request_topic: orders.requests
    response_topic: orders.responses
```

Each caller produces and consumes with their own SASL identity.

### HTTP backend

`cred://` is supported in `url` and in any `headers` value. The
plugin keeps a per-credential `reqwest::Client` cache mirroring the
NATS/Kafka shape — keyed on a BLAKE3 digest of `(resolved_url +
per-header values)`, with the same LRU + idle + revocation evictions:

```yaml
- name: orders_api
  backend:
    kind: http
    url: https://api.internal/v1/orders
    method: post
    headers:
      Authorization: "Bearer ${cred://vault-oauth/orders-api}"
      X-Caller-Id: "${cred://vault-oauth/orders-api#username}"
    expected_status_codes: [200]
    require_json_response: true
```

Each caller's request carries their own bearer token; the cached
client per (caller-cred-bundle) tuple keeps connection reuse hot
without leaking one caller's TLS session into another caller's
upstream.

You can combine `cred://` with operator CEL templates in the same
field — e.g. `${arguments.region}.api.example.com` for the URL
plus `${cred://vault-oauth/orders-api}` for the auth header. CEL
runs first at dispatch; `cred://` resolution runs against the
post-CEL value.

### Pipeline steps

Pipeline steps that delegate to SQL/NATS/Kafka/HTTP backends inherit
the caller's identity automatically — no extra config. A pipeline
binding that runs SQL → HTTP → Kafka hits all three with per-caller
credentials.

---

## Operational notes

### Tuning the registries

Each backend with `cred://` references maintains a per-binding
registry. Default config (per binding):

| Setting             | Default       | Knob                                   |
|---------------------|---------------|----------------------------------------|
| `pool_max_entries`  | 256           | LRU bound on distinct credentials      |
| `idle_eviction`     | 15 min        | Drop idle entries past this age        |
| Sweeper interval    | 60 s          | How often the idle scan runs           |

If your caller cohort is large but each caller is rare, raise
`idle_eviction` to keep warm connections. If it's narrow but
hot, you can tighten it.

### Metrics

Each registry emits a single counter, labelled by reason:

- `mcpg_sql_pool_registry_evictions_total{reason}` —
  `revoked` / `idle` / `lru`
- `mcpg_nats_client_registry_evictions_total{reason}`
- `mcpg_kafka_client_registry_evictions_total{reason}`
- `mcpg_http_client_registry_evictions_total{reason}`

Spike in `lru` evictions usually means `pool_max_entries` is too
low for your fan-out. Spike in `revoked` matches issuer-plugin
revocation activity. Sustained `idle` is healthy steady-state
churn.

### Audit events

Two new audit events ride alongside `credential_issued`:

- `credential_resolution_failed` — fires on every resolver
  failure with structured fields `(plugin_id, target, part?,
  error_kind, correlation_id)`. Caller-visible error never
  carries this detail.
- `pool_evicted_on_revoked` (logged via tracing target
  `mcpg::sql::pool_registry` / `mcpg::nats::client_registry` /
  `mcpg::kafka::client_registry`) — fires per `evict_for` call
  with the count of dropped entries.

Pipe both into your SIEM the same way you'd pipe
`credential_issued`; they share the redaction discipline (no
credential bytes ever land in audit fields).

### Backwards compatibility

A binding spec with no `cred://` references is **bit-for-bit
identical** to the pre-1.8 path. The static-cred fast path
short-circuits resolution + identity-keyed caching entirely —
your existing fleet does not silently start opening
per-credential pools just because you upgraded the gateway.

PROTOCOL_VERSION bumped 1.7 → 1.8 to reflect the new
`BackendRequest.identity` field. The field is optional, so
plugins built against 1.7 continue to deserialize 1.8 requests
(the field is `None` for those plugins). Operator-side: nothing
to migrate — the new spec fields on NATS/Kafka are all `Option<_>`
with sensible defaults.

---

## Use-case checklist

Reach for per-caller credentials when:

- ✅ The downstream system has its own RBAC/RLS that you'd rather
  delegate to than re-implement.
- ✅ Compliance requires server-side audit attribution to match
  caller identity.
- ✅ You have a credential issuer (Vault, AWS IAM RDS, Kafka
  OAUTHBEARER, etc.) that can mint per-identity credentials.
- ✅ Your caller cohort is bounded (hundreds, low thousands of
  distinct identities) so connection-pool fan-out stays sane.

Skip it when:

- ❌ Every caller is the same logical principal (a service-to-
  service tunnel where MCPG's audit identity is what matters).
- ❌ Your downstream has no per-identity auth surface (e.g. a
  legacy DB with a single shared connection user).
- ❌ Your fan-out is unbounded (millions of distinct callers
  hitting one binding) — you'd churn the registry's LRU and
  spend connect cost on every miss. Static credentials at the
  edge make more sense for that shape.

---

## See also

- Resolver implementation: `libs/plugin-host/src/credential_resolver.rs`
- Backend wiring:
  - SQL: `libs/plugins/backend/sql/src/pool.rs`
  - NATS: `libs/plugins/backend/nats/src/client_registry.rs`
  - Kafka: `libs/plugins/backend/kafka/src/client_registry.rs`
  - HTTP: `libs/plugins/backend/http/src/client_registry.rs`
- Credential cache + cluster broadcast:
  `libs/plugin-host/src/credential_cache.rs`,
  `libs/plugin-host/src/credential_cache_clustered.rs`
