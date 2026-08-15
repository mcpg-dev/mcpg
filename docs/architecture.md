# MCPG Architecture

> This document describes MCPG as implemented. Every statement is backed by code evidence.
> Last verified: April 12, 2026 — 42,000+ lines of Rust, 38 source files, 603 tests (+ 67 in plugin crates).

## System Overview

MCPG is a **Model Context Protocol Gateway** — a protocol-authority gateway that sits between MCP clients and downstream backend systems. It owns:

- MCP protocol handling (JSON-RPC 2.0 over Streamable HTTP)
- Session lifecycle (creation, SSE streaming, resumption, termination)
- Identity resolution and trust establishment
- Pre-dispatch authorization (trust levels + CEL expressions)
- Capability registration and discovery (tools, prompts, resources)
- Execution dispatch to operator-defined backends
- Multi-step pipeline orchestration with suspension and resumption
- Task-augmented tool execution (background tasks with polling, cancellation, result retrieval)
- Distributed coordination (session stores, delivery buses, pipeline stores, task stores)
- Observability (structured logging, Prometheus metrics, OpenTelemetry tracing)

MCPG is a **single-deployment product** — one gateway instance (or cluster) per customer environment. There is no multi-tenant runtime overlay.

## Module Structure

Module-level layout (file-by-file line counts intentionally omitted — they
drift; read the source for current detail):

```
src/
├── main.rs              — Process entry: config path, build + run
├── lib.rs               — Module re-exports
├── cli.rs               — CLI extension dispatch (plugin subcommand)
├── app/                 — Bootstrap, subsystem init, plugin-registry build, server launch
├── admin/               — Admin API surface
├── config/              — Config models, validation, loading — one module per section (see config/*.rs); `resolver.rs` = credential / `cred://` reference resolution
├── protocol/            — MCP types, JSON-RPC, message parsing, protocol-version negotiation
├── runtime/             — Async core: request dispatch, sessions, plugin-chain eval
│   ├── mod.rs, execution/                     — dispatch + backend execution / pipelines / debug tools
│   ├── stores/                                — session/subscription/pipeline/task/request-state/content-store state (KV-backed over the cluster API)
│   ├── buses/                                 — delivery + cancellation buses
│   ├── reapers/                               — background cleanup (task/pipeline reapers + reaper leadership)
│   ├── identity/                              — JWKS/JWT verify + OIDC multi-provider + IdentityPlugin adapter
│   ├── cp/                                    — control-plane attach hook + metrics/quota bridges
│   ├── watch_engine.rs                        — background resource watchers
│   ├── policy.rs, expr.rs, cel_guard_plugin.rs  — trust+CEL policy gate, CEL engine, local CEL guard
│   └── idempotency/                           — `dev.mcpg/idempotency` extension store
├── backends/            — Capability registry, routing, schema validation, plugin host
├── builtins/            — Plugins compiled into the binary (local-file audit sink, single-node cluster primitives)
├── transports/          — HTTP (SSE, webhook receiver, endpoints) + stdio JSON-RPC + tunnel
└── observability/       — Logging, metrics, tracing init + per-plugin sink routing
```

> Note: payment, policy enforcement, and guardrails are now **cdylib plugins**
> (under `libs/plugins/`), not `runtime/` modules — the per-tool gate chain
> evaluates them through the plugin host.

### Plugin System Crates

Directory names are shown; the Cargo package name is the `mcpg-` prefixed form
(e.g. `libs/plugin-host/` → package `mcpg-plugin-host`).

```
libs/
├── plugin-protocol/   — Plugin protocol surface: traits, manifests, FFI ABI
├── plugin-host/       — Registry, chain eval, cdylib loading, signature verification
├── plugin-sdk/        — Plugin development SDK + macros + test helpers
└── cluster-api/       — Cluster + orthogonal-primitive trait surface:
                          ClusterBackend, KeyValueStore, PubSub, Lease, Watch

libs/plugins/          — one flat directory per plugin class (all cdylibs)
├── backend/{http,command,nats,grpc,graphql,kafka,sql,mock,llms}/
│                        — backend bindings + their watch strategies
│                          (nats_topic, kafka_topic, sql_polling/pg_listen, …)
├── cluster/{redis,nats,consul,etcd}/ — cluster cdylibs. Each implements
│                          ClusterBackend + advertises its primitive accessors
│                          via `provides:` on the manifest. The single-node
│                          primitive impls live in apps/gateway/src/builtins/.
├── security/{guardrails,ip-allowlist}/ — HTTP guardrail hooks (CEL triggers) + IP gates
├── reliability/{rate-limit,circuit-breaker,response-cache}/ — reliability tool-gates
├── observability/     — audit + call-logger sinks (OCI-distributed)
├── identity/oidc/     — OIDC/JWT identity provider
├── credential/        — credential issuers (e.g. oauth-client-credentials)
├── payment/{mpp,x402,ucp,acp}/ — payment tool-gates
├── integration/webhook/ — webhook integration
├── storage/, cache/, catalog/, secret/, transform/ — storage / cache / catalog / secret / transform plugins
└── testing/{hello-native,wasm-test-gate}/ — reference native + Wasm plugins
```

The main `mcpg` binary has **no direct dependency** on `async-nats`, `rdkafka`,
or `redis` for backend/transport code — those live entirely in the plugin
crates, loaded at startup via the plugin registry and dispatched through
`BackendPlugin` / `WatchStrategyPlugin` traits defined in
`mcpg-plugin-protocol`. The gateway DOES path-depend on `mcpg-state-{redis,nats}`
because per-capability override (`<capability>.store: { kind: redis|nats, … }`)
opens its own connection pool — the helper crate keeps the redis/nats primitive
logic in one place rather than duplicating it between cdylib and gateway.

## Request Flow

```
Client HTTP Request
  │
  ▼
┌─────────────────────────┐
│  HTTP Transport          │  Parse headers, CORS, Accept validation
│  (transports/http/)      │  Identity resolution (OIDC → JWKS → Plugin → Header → Anonymous)
│                          │  Build RequestContext (request_id, session_id, identity)
└──────────┬──────────────┘
           │ GatewayRequest
           ▼
┌─────────────────────────┐
│  Gateway Runtime         │  Session management (create / load / validate phase)
│  (runtime/mod.rs)        │  Operation routing by GatewayOperation enum
│  [async]                 │  Capability matching (tool_route, prompt_route, resource_route)
└──────────┬──────────────┘
           │ ToolRoute / PromptRoute / ResourceRoute
           ▼
┌─────────────────────────┐
│  Plugin Chain (pre)      │  Async tool-gate chain: policy, payment, guardrails, custom
│  (plugin registry)       │  Any Deny/Challenge short-circuits
└──────────┬──────────────┘
           │ Allow
           ▼
┌─────────────────────────┐
│  Execution Dispatcher    │  Route to backend adapter by ToolRoute
│  (runtime/execution.rs)  │  Execute one of 27 backend kinds (http / command /
│                          │  nats / grpc / graphql / kafka / sql / openapi / mock
│                          │  / 17 LLM kinds), or Pipeline (multi-step w/ suspension)
└──────────┬──────────────┘
           │ ToolCallResult / PipelineOutcome
           ▼
┌─────────────────────────┐
│  Plugin Chain (post)     │  Async tool-gate chain: guardrails, custom post-checks
│  (plugin registry)       │  Post-dispatch transforms (result rewriting, PII masking)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Gateway Runtime         │  Wrap result in JSON-RPC response
│                          │  Stream via SSE (with event IDs for replay)
└─────────────────────────┘
```

## Identity Model

Three-tier identity, from lowest to highest trust:

| Trust Level | Identity Variant | Source |
|---|---|---|
| `Unauthenticated` | `Anonymous` | No identity headers present |
| `HeaderAsserted` | `HttpHeader` | `x-mcpg-subject-id` header (upstream proxy asserted) |
| `Verified` | `Verified` | JWT verified via JWKS or OIDC/OAuth provider |

Identity resolution priority in the HTTP transport:
1. **OIDC/OAuth** — async, multi-provider, supports discovery + introspection
2. **JWKS** — sync, single-provider, legacy JWT verification
3. **Identity plugins** — custom identity resolvers via the async IdentityPlugin trait
4. **Header-asserted** — `x-mcpg-subject-id` header
5. **Anonymous** — fallback

## Backend Model

All downstream integrations are **operator-defined backends**. Each backend
maps to exactly one MCP tool, prompt, or resource, selected by a nested
`backend.kind:` discriminator. The `BackendImpl` enum
(`config/backend.rs`, ~L313–415) defines **27 backend kinds** — 10
general-purpose plus a 17-kind LLM family:

| Backend Kind | Adapter | Implementation |
|---|---|---|
| `http` | HTTP POST/GET | `mcpg-plugin-backend-http` |
| `command` | Local subprocess | `mcpg-plugin-backend-command` |
| `nats` | NATS request/reply | `mcpg-plugin-backend-nats` |
| `grpc` | gRPC via HTTP POST (proto-less JSON) | `mcpg-plugin-backend-grpc` |
| `graphql` | GraphQL query/mutation | `mcpg-plugin-backend-graphql` |
| `kafka` | Kafka pub/sub with correlation ID | `mcpg-plugin-backend-kafka` |
| `sql` | SQL query/exec (sqlite/postgres/mysql) | `mcpg-plugin-backend-sql` |
| `openapi` | OpenAPI operation → MCP tool/resource | `mcpg-plugin-backend-openapi` |
| `mock` | Configurable fixture response | `mcpg-plugin-backend-mock` |
| `pipeline` | Multi-step orchestration | internal (gateway runtime) |

The remaining 17 kinds are the **LLM family** — `{openai, azure_openai,
anthropic, gemini, compat, stability}.{chat, embedding, image, tts, stt}`
combinations — managed bindings to hosted/self-hosted model APIs, backed by
the LLM cdylibs under `libs/plugins/backend/llms/`. See
[backends.md](backends.md) for the full kind-by-kind reference.

All backend dispatch lives in cdylib plugin crates under
`libs/plugins/backend/*` — the `mcpg` binary hard-wires no backend (the
backend-plugin migration completed this; `pipeline` orchestration remains
internal to the runtime). The operator-facing YAML (`backend: { kind: … }`)
is unchanged from the pre-migration shape.

Every backend carries:
- MCP descriptor (name, description, input_schema)
- Governance controls (minimum_trust, cel_allow_if)
- Optional input schema validation (JSON Schema)

## Pipeline Execution

Pipeline backends compose multiple steps into a single MCP tool. The
`PipelineStepConfig` enum (`config/backend.rs`, ~L1305) defines **18 step
kinds**, each a flat `kind:` discriminator with `id:` plus its own fields:

| Step Kind | Description | Suspending? |
|---|---|---|
| `http` | HTTP request | No |
| `command` | Local subprocess | No |
| `nats` | NATS request/reply | No |
| `kafka` | Kafka pub/sub | No |
| `grpc` | gRPC call | No |
| `graphql` | GraphQL query | No |
| `mock` | Fixture response | No |
| `transform` | CEL expression over context | No |
| `plugin_transform` | Reshape context via a named transform plugin (e.g. JSONata) | No |
| `cel_gate` | CEL guard condition | No |
| `log` | Emit `notifications/message` on the session SSE | No |
| `progress` | Emit `notifications/progress` (when a `progressToken` is present) | No |
| `sql_tx` | Nested transactional SQL container on a referenced `sql` backend | No |
| `sql_await` | Fire-and-wait against a `sql` backend's `await` runtime | No |
| `elicitation` | Server→Client prompt for input | **Yes** |
| `sampling` | Server→Client LLM sampling | **Yes** |
| `roots_list` | Server→Client `roots/list` request | **Yes** |
| `gather` | Multi-entry MRTR — several input requests in one suspension (SEP-2322) | **Yes** |

Suspending steps serialize pipeline state to the pipeline store, send a server-initiated JSON-RPC request to the client via the delivery bus, and resume when the client responds.

Pipeline context flows data between steps: each step reads from `original_args`, `request_context`, and `completed_steps[step_id].output`. CEL expressions in `transform` and `cel_gate` steps operate over this context.

## Distributed Infrastructure

After the cluster-backbone refactor every capability runs
over a single trait pair: `KvBacked*Store` over `Arc<dyn KeyValueStore>`
(for sessions / pipelines / tasks / subscriptions) and `BusBacked*Bus`
over `Arc<dyn PubSub>` (for delivery / cancellation). Backend choice
happens at the primitive layer, not the capability layer.

### KV-backed capability stores

| Capability | Impl | KeyValueStore source (default) |
|---|---|---|
| Session store | `KvBackedSessionStore` (`runtime/session_store.rs`) | inherited from `cluster.kind` |
| Pipeline store | `KvBackedPipelineStore` (`runtime/pipeline_store.rs`) | inherited from `cluster.kind` |
| Task store | `KvBackedTaskStore` (`runtime/task_store.rs`) | inherited from `cluster.kind` |
| Subscription store | `KvBackedSubscriptionStore` (`runtime/subscription_store.rs`) | inherited from `cluster.kind` |

Per-capability `<capability>.store: { kind, … }` override opens its
own connection pool. Recognised override kinds: `memory`, `file`,
`redis`, `nats`. Tasks are scoped to the session that created them;
the store enforces session-based authorization on all accessor
methods. Expired tasks / sessions are TTL-driven (entries carry an
`Instant` deadline; `get` checks before returning; reaper task
prunes).

### Bus-backed capabilities

| Capability | Impl | PubSub source (default) |
|---|---|---|
| Delivery bus | `BusBackedDeliveryBus` (`runtime/delivery_bus.rs`) | inherited from `cluster.kind` |
| Cancellation bus | `BusBackedCancellationBus` (`runtime/cancellation_bus.rs`) | inherited from `cluster.kind` |

Per-bus `<bus>.bus: { kind, … }` override opens its own connection
pool. Recognised override kinds: `memory`, `redis`, `nats`.

### Primitive sources

| `cluster.kind` | KeyValueStore | PubSub | Lease | Watch |
|---|---|---|---|---|
| `single_node` (default) | `MemoryKv` (or `FileKv` when `dir:` set) | `MemoryBus` (or `FileBus`) | always-acquire | `MemoryWatch` |
| `redis` | `RedisKv` | `RedisTopicBus` | `RedisLock` | `RedisWatch` (Streams) |
| `nats` | `NatsKv` (JetStream KV) | `NatsTopicBus` (core) | `NatsLock` (JS KV CAS) | `NatsWatch` (JS KV `watch_all`) |
| `consul` | — | — | consul session | — |
| `etcd` | — | — | etcd lease | — |

`—` means the cluster plugin doesn't expose that primitive; capabilities
needing it MUST set per-capability overrides.

### Pipeline Reaper

Background task (`runtime/pipeline_reaper.rs`) that periodically sweeps expired pipelines from the pipeline store. Emits `mcpg_pipeline_reaper_cleaned_total` and `mcpg_pipeline_reaper_last_sweep_count` metrics.

## Observability

- **Logging**: Structured JSON or pretty format. Multi-sink (stdout, stderr, file). Per-session log level control.
- **Metrics**: Prometheus exporter on `/metrics`. 18+ metrics covering requests, backends, sessions, policy, pipelines, plugins, and reaper.
- **Tracing**: OpenTelemetry OTLP exporter with per-request span propagation.

## Plugin System

MCPG uses an async plugin system with three plugin classes:

| Class | Trait | Purpose |
|---|---|---|
| **Tool Gate** | `ToolGatePlugin` | Pre/post-dispatch allow/deny/challenge decisions |
| **Transform** | `TransformPlugin` | Argument/result rewriting (PII masking, schema migration) |
| **Identity** | `IdentityPlugin` | Custom identity resolution from request headers |

All trait methods are `async` (via `#[async_trait]`), supporting plugins that need I/O (HTTP callouts, database queries, external PDP calls) while remaining zero-cost for pure compute plugins.

### Dual-Tier Model

| Tier | Trust | Sandbox | Use Case |
|---|---|---|---|
| **Native (Tier 2)** | Full trust | None | Enterprise modules (payment, policy, identity) |
| **Wasm (Tier 1)** | Untrusted | Wasmtime sandbox | Customer extensions (masking, filtering) |

### Plugin Registry

The `PluginRegistry` holds ordered chains per class. Chain evaluation:
- **Tool gates**: first non-Allow decision short-circuits
- **Transforms**: all plugins run in order, each transforms the previous output
- **Identity**: first non-NoToken result wins

Built-in plugins registered at startup:
- `PolicyGatePlugin` — trust level + CEL policy evaluation
- `PaymentGatePlugin` — payment gating via MPP (when `payment.enabled`)
- `GuardrailsGatePlugin` — HTTP webhook guardrails (when hooks configured)

External plugins loaded from the flat `plugins: [ … ]` array in config.

### Plugin Configuration

Two config paths:
- **Built-in plugins** consume strongly-typed global config (e.g., `payment:`, `guardrails:`) at construction time
- **External plugins** receive their `serde_json::Value` config blob (from `plugins[].config`) at every trait method call

## Authorization Model

Pre-dispatch policy gate with two evaluation layers:

1. **Trust level check** — Compares caller's `RequestTrustLevel` against the tool's `minimum_trust` requirement
2. **CEL expression evaluation** — Global `cel_allow_if` and per-tool `cel_allow_if` expressions

CEL context variables: `tool_name`, `trust_level`, `principal_id`, `auth_provider`, `identity_kind`.

Policy outcomes:
- `Allow` — Proceed with execution
- `Deny(PolicyDenial)` — Return structured JSON-RPC error with audit reason

## Key Design Decisions

1. **Backends are the product** — All downstream integrations are operator-defined backends, not code plugins
2. **Protocol authority** — MCPG owns MCP protocol legality; backends propose outcomes, gateway validates
3. **Single deployment** — One gateway per customer/environment, no multi-tenant overlays
4. **Fail closed** — Identity verification failures, policy denials, and provider errors fail closed
5. **CEL for policy** — CEL expressions power the authorization layer (not Rego, not custom DSL)
6. **Backend + step taxonomy is explicit** — 27 `BackendImpl` kinds (10 general-purpose + 17 LLM) and 18 pipeline step kinds; adding a kind requires clear business justification
7. **Cluster-backbone state model** — `cluster.kind` selects ONE backend (single_node / redis / nats / consul / etcd); every capability inherits its `KeyValueStore` / `PubSub` primitive from the cluster plugin's accessors by default. Per-capability `store:` / `bus:` overrides open their own pool when an operator wants finer control.
