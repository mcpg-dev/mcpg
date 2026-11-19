# MCPG Request Flow

> Complete lifecycle of a request through the Model Context Protocol Gateway.
> Every entity, decision point, plugin extension point, and cross-instance
> hop is documented.
>
> Last updated: November 18, 2026

---

## Overview

A request enters the gateway through one of two transports (HTTP or Stdio), flows through identity resolution, the MCP `2026-07-28` version check, policy evaluation, plugin chains, backend execution, and back out as a JSON-RPC response or SSE stream. This document traces every step.

```
                    ┌─────────────────────────────────┐
                    │         MCP Client               │
                    └──────────┬──────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                │                             │
        ┌───────▼───────┐           ┌─────────▼───────┐
        │ HTTP Transport│           │ Stdio Transport  │
        │ (POST /mcp)   │           │ (stdin/stdout)   │
        └───────┬───────┘           └─────────┬───────┘
                │                             │
                ▼                             ▼
        ┌───────────────┐           ┌─────────────────┐
        │ Identity       │           │ Anonymous        │
        │ Resolution     │           │ Identity         │
        └───────┬───────┘           └─────────┬───────┘
                │                             │
                └──────────────┬──────────────┘
                               ▼
                    ┌─────────────────────┐
                    │  RequestContext      │
                    │  + ProtocolMessage   │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────────┐
                    │  transports/dispatch.rs │
                    │  ensure_session         │
                    │  handle_protocol_message│
                    └──────────┬──────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼───────┐ ┌─────▼──────┐ ┌───────▼───────┐
     │ Discovery      │ │ Listen /   │ │ Capabilities  │
     │ (server/       │ │ events     │ │ (tools/call)  │
     │  discover)     │ │            │ │               │
     └────────────────┘ └────────────┘ └───────┬───────┘
                                               │
                               ┌───────────────┼───────────────┐
                               │               │               │
                        ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
                        │  Pre-Gate   │ │  Execution  │ │  Post-Gate  │
                        │  Chain      │ │  Dispatch   │ │  Chain      │
                        └─────────────┘ └─────────────┘ └─────────────┘
```

---

## 1. Transport Layer

The transport layer receives raw bytes, parses HTTP or JSON-RPC framing, and resolves the caller's identity. It produces a `RequestContext` (caller identity, transport, client) and a parsed `ProtocolMessage`, both transport-agnostic, and hands them to `runtime.handle_protocol_message`.

### 1.1 HTTP Transport (`transports/http/`)

The transport is split along seams that have no cross-talk:

| Module | Holds |
|---|---|
| `mod.rs` | the router, the `/mcp` handlers (POST and the `405` handler), and the POST request path |
| `identity.rs` | identity resolution + `RequestContext` construction (the only part `http_route` plugins need) |
| `validate.rs` | origin, `Accept`, content-type, and protocol-version-header gates |
| `response.rs` | JSON-RPC / SSE / rejection → HTTP response mapping |
| `sse.rs` | long-lived stream lifecycle: concurrency slots, subscription leases, delivery-bus wiring |
| `discovery.rs` | OAuth metadata + served-registry endpoints |
| `webhooks.rs` | resource-updated + approval-resolution webhooks |
| `probes.rs` | health, readiness, runtime, metrics |

The HTTP transport exposes these endpoints via an Axum router:

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| `GET` | `/health` | `health_handler` | Liveness probe |
| `GET` | `/readiness` | `readiness_handler` | Readiness (runtime snapshot) |
| `GET` | `/runtime` | `runtime_handler` | Runtime metadata |
| `GET` | `/metrics` | `metrics_handler` | Prometheus metrics |
| `POST` | `/mcp` | `mcp_handler` | MCP request (single JSON-RPC message only) |
| `GET` / `HEAD` / `DELETE` | `/mcp` | `mcp_405_handler` | Browser redirect (GET/HEAD), origin check, authentication, then `405` with `Allow: POST` |

All paths are configurable via `server.mcp_path` and `server.health_path`.

#### POST /mcp — Main request path

```
HTTP POST /mcp
│
├─ 1. Parse headers
│   ├─ Extract traceparent → TraceContext
│   └─ Extract x-request-id → upstream_request_id
│   (no session or resume-cursor header is read)
│
├─ 2. Identity resolution ← PLUGIN EXTENSION POINT
│   ├─ Try OIDC/OAuth  → Verified { subject, issuer, provider }
│   ├─ Try JWKS JWT    → Verified { subject, issuer, "jwks" }
│   ├─ Try x-mcpg-subject-id header → HttpHeader { subject }
│   └─ Fallback → Anonymous
│
├─ 3. Build RequestContext
│   └─ RequestContext::new(request_id, upstream_request_id, identity, Http)
│
├─ 4. Preflight (mcp_post_preflight)
│   ├─ per-IP rate limit
│   ├─ validate_origin() — CORS origin check
│   ├─ authentication gate (401 challenge) — before the version check
│   ├─ validate_post_accept() — returns whether the client admitted SSE
│   └─ validate_post_content_type()
│
├─ 5. Parse body; refuse a JSON-RPC batch
│
├─ 6. protocol::negotiate(headers, body)
│   ├─ Mcp-Protocol-Version header, else
│   ├─ body params._meta.io.modelcontextprotocol/protocolVersion
│   └─ anything but "2026-07-28", or neither → 400, -32022
│
├─ 7. Dispatch (transports/dispatch.rs, shared with stdio)
│   ├─ Handler::validate_transport_headers — Mcp-Method / Mcp-Name /
│   │  Mcp-Param-* against the body (-32020)
│   ├─ _meta client info and capabilities → RequestContext
│   ├─ runtime.ensure_session(ctx) → the caller's session row
│   │  (503 when the principal's row cap is reached)
│   ├─ the long-lived plan: subscriptions/listen and events/stream return
│   │  their stream here
│   └─ Handler::parse → runtime.handle_protocol_message
│
└─ 8. Shape the response (finish_response)
    per-request SSE (tools/call that emitted notifications) → inline JSON;
    METHOD_NOT_FOUND → 404; every exit stamps Mcp-Protocol-Version
```

Response shape:
- immediate completion → direct JSON response, or a per-request SSE response when a `tools/call` emitted progress or log notifications and the client accepts SSE
- a call that needs client input → inline `InputRequiredResult` (HTTP 200)
- a materialized task → inline `resultType: "task"` (HTTP 200)
- missing, invalid or unsupported `Mcp-Protocol-Version` → HTTP `400 Bad Request`

**Entity at each stage:**

| Step | Input | Output |
|------|-------|--------|
| 1 | `HeaderMap`, `Bytes` | Raw values |
| 2 | `HeaderMap` | `RequestIdentity` |
| 3 | Identity + parsed headers | `RequestContext` |
| 4 | `HeaderMap`, peer addr | `client_accepts_sse: bool` |
| 5 | Body bytes | JSON value |
| 6 | JSON body + headers | `Ok(())` or a `-32022` rejection |
| 7 | Context + body | `GatewayResponse` (or a complete `Response`) |
| 8 | `GatewayResponse` | HTTP response |

#### GET, HEAD and DELETE /mcp

```
HTTP GET | HEAD | DELETE /mcp
├─ Browser redirect (GET/HEAD from a browser)
├─ Identity resolution + origin check (403)
├─ Authentication gate (401 challenge)
└─ 405 Method Not Allowed, Allow: POST, x-mcpg-request-id
```

There is no GET stream and no session termination over HTTP. Server-to-client
traffic is the inline `InputRequiredResult`, the per-request SSE response,
`subscriptions/listen` and `events/stream`.

### 1.2 Stdio Transport (`transports/stdio.rs`)

For local piped operation (no HTTP server). No TLS.

```
stdin → newline-delimited JSON-RPC
│
├─ Identity: always Anonymous { source: "stdio" }
├─ Transport: TransportKind::Stdio
├─ One process session, minted at start (materialize_ephemeral_session),
│  set on every RequestContext
├─ A message without a _meta protocol version is served as 2026-07-28;
│  another version is refused with -32022
├─ Same dispatch path: transports/dispatch.rs
├─ subscriptions/listen subscribes the delivery bus and writes frames to
│  stdout; events/stream answers -32601
│
stdout ← JSON-RPC responses (one per line)
```

**Plugin extension point:** The `IdentityPlugin` trait could resolve identity from Stdio-provided credentials, but currently only the HTTP transport calls the identity chain.

---

## 2. Identity Resolution

Identity determines the caller's trust level, which gates all subsequent authorization decisions.

```
                    ┌─────────────────┐
                    │ Request Headers  │
                    └────────┬────────┘
                             │
               ┌─────────────┼─────────────┐
               │             │             │
         ┌─────▼─────┐ ┌────▼────┐ ┌──────▼──────┐
         │ OIDC/OAuth │ │  JWKS   │ │  Header     │
         │ (async)    │ │  (sync) │ │  Assertion  │
         └─────┬─────┘ └────┬────┘ └──────┬──────┘
               │             │             │
               ▼             ▼             ▼
         ┌───────────────────────────────────────┐
         │          RequestIdentity               │
         │  ┌──────────┬───────────┬───────────┐ │
         │  │ Verified │ HttpHeader│ Anonymous  │ │
         │  │ trust:3  │ trust:2   │ trust:1    │ │
         │  └──────────┴───────────┴───────────┘ │
         └───────────────────────────────────────┘
```

| Provider | Trust Level | Async? | Config Section |
|----------|-------------|--------|----------------|
| OIDC/OAuth | `Verified` (highest) | Yes | `auth.oidc_oauth_providers[]` |
| JWKS inline/URL | `Verified` (highest) | No | `auth.jwks_url` / `auth.jwks_keys[]` |
| Header assertion | `HeaderAsserted` | No | `x-mcpg-subject-id` header |
| Anonymous fallback | `Unauthenticated` | No | — |

**Plugin extension:** Custom identity resolvers can be registered as `IdentityPlugin` implementations. The plugin registry's `resolve_identity()` method iterates all registered identity plugins; the first non-`NoToken` result wins. Identity plugins receive request headers as `&[(String, String)]` pairs.

---

## 3. Session Rows

The wire has no session. The gateway keeps an internal **session row** per
caller to hold the state some features need: `subscriptions/listen` streams,
tasks, paused calls (MRTR) and the delivery-bus key. Clients never send or see
its id.

| Caller | Session row |
|-------|-------------|
| Verified principal | One id per principal and client name: an HMAC under `sessions.synthetic_session_key` (or a key derived from `cluster.state_encryption_key_env`). Every replica derives the same id. Without either key, one row per principal on each replica. |
| Header-asserted principal | One row per principal on each replica. |
| Anonymous | A fresh id per request; a row is written only when the request needs one (listen stream, task, paused call). |
| Stdio | One process session, minted at start. |

`GatewayRuntime::ensure_session(&ctx)` returns `SessionOutcome::Ready(ctx)` or
`SessionOutcome::CapacityExhausted`. It binds the owner as the caller's
synthetic principal key on every path.

The session store keeps rows in the key-value primitive the sessions
capability resolves: in-memory, file, or the cluster coordinator's (NATS KV
or Redis). Configurable via `mcp.configurations.sessions.store`.

**Expiration.** Idle rows expire after
`gateway.server.session_idle_timeout_ms` (default 15 minutes). MCPG does
not run a background reaper task for session rows: a row expires when a
store operation sees it past the idle deadline, and a throttled sweep that
rides request traffic (at most once per timeout window, capped at 60 s)
expires rows nobody reads again.
`max_sessions` (global) and `max_sessions_per_tenant` (per principal;
derived and anonymous rows count across the fleet in `session-t:` slots,
a row only one replica uses counts on that replica) are enforced where a
row is created; a refused row answers HTTP 503 and increments
`mcpg_tenant_session_quota_rejected_total`. When a row ends (idle
expiry, admin terminate), every replica releases the listen streams,
leases and admission it held, and the unfinished tasks the row owns are
cancelled. A row owns only the tasks of an anonymous or stdio caller: an
identified caller's tasks belong to its principal and run until they
finish or reach their TTL.

> **Multi-instance note.** In a clustered deployment the session store is
> always a shared backend (`NatsKV` or `Redis`) so any instance can load
> any row. A `subscriptions/listen` stream is held by the instance it
> landed on; notifications raised elsewhere ride the delivery bus to that
> instance. See §11 for the full cross-instance flow.

---

## 4. Operation Routing

`Handler::parse` turns the body into a `ProtocolMessage` whose `operation` is
the typed `2026-07-28` operation; `runtime.handle_protocol_message` routes it:

```
ProtocolMessage { label, operation, jsonrpc_id }
│
├─ server/discover        → DiscoverResult (capabilities, extensions,
│                            supportedVersions, ttlMs / cacheScope)
│
├─ Capabilities
│   ├─ tools/list          → filtered list of tools (visibility policy applied)
│   ├─ tools/call          → FULL DISPATCH PIPELINE (see §5); a retry with
│   │                        requestState + inputResponses resumes a paused call
│   ├─ prompts/list, prompts/get
│   ├─ resources/list, resources/templates/list, resources/read
│   └─ completion/complete
│
├─ Tasks extension
│   ├─ tasks/get           → task status, outstanding inputRequests (owner only)
│   ├─ tasks/update        → inputResponses for an input_required task
│   └─ tasks/cancel        → cancel a working task (owner only)
│
├─ subscriptions/listen, events/*  → long-lived streams and MCP Events
│
├─ notifications/cancelled         → owner check, then the cancellation bus
│
└─ any other method       → -32601, HTTP 404
```

**Plugin extension:** Currently, only `ToolsCall` passes through the full plugin chain. Future extensions could add plugin hooks to `PromptsGet`, `ResourcesRead`, or `ToolsList` for filtering and transformation.

---

## 5. Tool Call Dispatch Pipeline

This is the most complex path — a `tools/call` request passes through
13 stages, in this order. Every stage is labelled with its plugin
extension potential. Stages 5 and 7 each host a **plugin chain** and
are the primary extension seams.

```
 ┌─────────────────────────────────────────────────────────────┐
 │                    tools/call Request                        │
 └──────────────────────────┬──────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ① Session Row                                               │
 │  ensure_session(ctx) — the caller's row (done in dispatch)   │
 │  Entity: SessionStore                                        │
 │  Short-circuit: HTTP 503 when the principal's row cap is     │
 │                  reached                                      │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ② Tool Routing                                              │
 │  capability_registry.tool_route(&name) → Option<ToolRoute>   │
 │  Entity: CapabilityRegistry → ToolRoute enum                 │
 │  Short-circuit: JSON-RPC -32602 on unknown tool              │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ③ Task-Support Policy Check                         BUILTIN │
 │  capability_registry.tool_task_support(&name)                 │
 │  • Optional / Required + client declared the tasks extension  │
 │    → run as a task (resultType "task")                         │
 │  • otherwise → run synchronously                               │
 │  Entity: CapabilityRegistry → TaskSupport                     │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ④ Rate Limiter                                      BUILTIN │
 │  rate_limiter.allow_tool_call(&name, session_id, principal)   │
 │  • Per-tool / per-session / per-principal token buckets       │
 │  • NoOp in default config; NATS KV / Redis when clustered     │
 │  Entity: RateLimiter → Allow / Deny                           │
 │  Short-circuit: JSON-RPC -32000 with retryAfterMs meta        │
 │  Metric: mcpg_rate_limit_denials_total                        │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑤ Pre-Dispatch Policy Gate                          BUILTIN │
 │  pre_dispatch_policy.evaluate(ctx, route)                     │
 │  • Trust level check (Unauthenticated < HeaderAsserted        │
 │    < Verified) vs the tool's minimum_trust                    │
 │  • Global CEL allow_if expression evaluation                  │
 │  • Per-tool CEL allow_if expression evaluation                │
 │  Entity: PreDispatchPolicyGate → Allow / Deny(PolicyDenial)   │
 │  Short-circuit: HTTP 403 on Deny                              │
 │  Metric: mcpg_policy_evaluations_total                        │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑥ Plugin Tool-Gate Chain (Pre-Dispatch)       🔌 EXTENSIBLE │
 │  plugin_registry.evaluate_tool_gates_pre(ctx, args, meta)     │
 │  • Evaluates all registered ToolGatePlugin instances in       │
 │    registration order                                         │
 │  • Built-in plugins registered by the runtime (order):        │
 │      PaymentGatePlugin    — payment challenge / verify        │
 │      GuardrailsGatePlugin — HTTP webhook hooks with CEL       │
 │  • Custom: any ToolGatePlugin (Native Tier 2 or Wasm Tier 1)  │
 │  • First Deny or Challenge short-circuits                     │
 │  • Allow-decisions' metadata is merged into response `_meta`  │
 │  • Shadow mode (enforce=false) logs Deny/Challenge but        │
 │    continues the chain                                         │
 │  Entity: PluginRegistry → GateDecision                        │
 │  Short-circuit: HTTP 4xx on Deny (402 for Payment-Challenge)  │
 │  Metrics: mcpg_plugin_evaluations_total,                      │
 │           mcpg_plugin_cache_hits_total,                       │
 │           mcpg_shadow_evaluations_total                       │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑦ Schema Validation                                         │
 │  capability_registry.validate_tool_arguments(&name, &args)    │
 │  • JSON Schema validation against the tool's inputSchema      │
 │  Entity: CapabilityRegistry                                   │
 │  Short-circuit: JSON-RPC -32602 on validation failure         │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑧ Plugin Transform Chain (Pre-Dispatch)       🔌 EXTENSIBLE │
 │  plugin_registry.apply_transforms_pre(ctx, &args)             │
 │  • Evaluates all registered TransformPlugin instances         │
 │  • Each plugin sees the output of the previous one            │
 │  • Can rewrite, enrich, or redact tool arguments              │
 │  • Error outcomes are logged and passthrough (no short-       │
 │    circuit) — the last-good value is used                     │
 │  Entity: PluginRegistry → mutated arguments (Value)           │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑨ Execution Dispatch                                        │
 │                                                               │
 │  Routes via ToolRoute to one of:                              │
 │  ┌──────────────────────────────────────────────────────────┐ │
 │  │  Direct backends (dispatch_tool_call) — 27 kinds total  │ │
 │  │  ├─ HTTP      → reqwest POST/GET to downstream URL       │ │
 │  │  ├─ Command   → tokio::process subprocess                │ │
 │  │  ├─ NATS      → BackendPlugin (kind="nats") request/reply│ │
 │  │  ├─ gRPC      → reqwest HTTP POST (proto-less JSON)      │ │
 │  │  ├─ GraphQL   → reqwest POST with query/mutation         │ │
 │  │  ├─ Kafka     → BackendPlugin (kind="kafka") correlated  │ │
 │  │  ├─ SQL       → postgres/mysql/sqlite query/exec         │ │
 │  │  ├─ OpenAPI   → spec operation → outbound HTTP request   │ │
 │  │  ├─ Mock      → static fixture response                  │ │
 │  │  ├─ LLM ×17   → {openai,azure,anthropic,gemini,…} APIs   │ │
 │  │  └─ Internal  → built-in debug tools                     │ │
 │  └──────────────────────────────────────────────────────────┘ │
 │  ┌──────────────────────────────────────────────────────────┐ │
 │  │  Pipeline backends (execute_pipeline)                    │ │
 │  │  Multi-step orchestration with 18 step kinds:            │ │
 │  │  http, command, nats, kafka, grpc, graphql, mock,        │ │
 │  │  transform, plugin_transform, cel_gate, log, progress,   │ │
 │  │  sql_tx, sql_await + 4 suspending: elicitation, sampling,│ │
 │  │  roots_list, gather                                      │ │
 │  │  Suspending steps → serialize state → InputRequiredResult│ │
 │  └──────────────────────────────────────────────────────────┘ │
 │  Per-backend retry with configurable backoff                  │
 │  W3C traceparent is propagated into every outbound call       │
 │  Entity: ExecutionDispatcher → ToolCallResult / PipelineOutcome│
 │  Metrics: mcpg_binding_executions_total,                      │
 │           mcpg_binding_execution_duration_seconds             │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑩ Plugin Tool-Gate Chain (Post-Dispatch)      🔌 EXTENSIBLE │
 │  plugin_registry.evaluate_tool_gates_post(ctx, args,          │
 │      result, execution_duration_ms)                           │
 │  • Same chain as ⑥, but evaluates the result                  │
 │  • Content safety scanners, audit plugins, post-verify gates  │
 │  • First Deny/Challenge short-circuits                        │
 │  Entity: PluginRegistry → GateDecision                        │
 │  Short-circuit: HTTP error on Deny or Challenge               │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑪ Plugin Transform Chain (Post-Dispatch)      🔌 EXTENSIBLE │
 │  plugin_registry.apply_transforms_post(ctx, &result)          │
 │  • PII masking, response enrichment, schema migration         │
 │  Entity: PluginRegistry → mutated result (Value)              │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑫ Plugin Gate Metadata Merge                                │
 │  merge_plugin_gate_meta(result, &allow_metadata)              │
 │  • Attaches metadata from Allow decisions (receipts, audit    │
 │    stamps) into the result's `_meta` field                    │
 └──────────────────────────┬───────────────────────────────────┘
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  ⑬ Response Assembly                                         │
 │  ProtocolHttpResponse { 200, JsonRpcSuccess { id, result } }  │
 │  → per-request SSE (notifications emitted) or JSON response   │
 └──────────────────────────────────────────────────────────────┘
```

### Stage Summary

| # | Stage | Entity | Can Short-Circuit? | Plugin Extensible? |
|---|-------|--------|---|---|
| 1 | Session row | `SessionStore` | Yes (503) | No |
| 2 | Tool routing | `CapabilityRegistry` | Yes (unknown tool) | No |
| 3 | Task-support policy | `CapabilityRegistry` | No (task or sync) | No (config-driven) |
| 4 | Rate limiter | `RateLimiter` | Yes (-32000 + retryAfterMs) | No |
| 5 | Policy gate | `PreDispatchPolicyGate` | Yes (403) | No (CEL-configurable) |
| 6 | Pre-dispatch tool-gate chain (**includes** payment, guardrails) | `PluginRegistry` | Yes (any HTTP / 402) | **Yes** |
| 7 | Schema validation | `CapabilityRegistry` | Yes (-32602) | No |
| 8 | Pre-dispatch transforms | `PluginRegistry` | No | **Yes** |
| 9 | Execution | `ExecutionDispatcher` | No | Via `BackendPlugin` (see §6.4) |
| 10 | Post-dispatch tool-gate chain | `PluginRegistry` | Yes (any HTTP error) | **Yes** |
| 11 | Post-dispatch transforms | `PluginRegistry` | No | **Yes** |
| 12 | Plugin gate metadata merge | — | No | No |
| 13 | Response assembly | — | No | No |

**Payment gating** is implemented as a `ToolGatePlugin`
(`PaymentGatePlugin`, registered first in stage ⑥) — not as a
standalone stage — so operators can replace or layer payment logic
through the plugin system without forking the runtime.

---

## 6. Plugin Extension Points

Five async plugin traits are available as extension points. Three
(`ToolGatePlugin`, `TransformPlugin`, `IdentityPlugin`) are **chain**
extensions — the host evaluates every registered instance in
registration order. The other two (`BackendPlugin`,
`WatchStrategyPlugin`) are **dispatch** extensions — the host selects
one registered instance by `kind()`. Every extension point is
zero-cost when no plugins are registered (empty-chain or
missing-kind bail-out).

### 6.1 ToolGatePlugin — Pre/Post-Dispatch Gating

**When it runs:** Stages ⑥ (pre) and ⑩ (post)

**What it receives:**

```rust
// Pre-dispatch
async fn evaluate_pre_dispatch(
    &self,
    ctx: &PluginContext,       // request_id, session_id, tool_name, identity, transport
    arguments: &Value,         // tool arguments
    meta: Option<&Value>,      // client _meta
    config: &Value,            // per-plugin config blob
) -> GateDecision;            // Allow / Deny / Challenge

// Post-dispatch
async fn evaluate_post_dispatch(
    &self,
    ctx: &PluginContext,
    arguments: &Value,
    result: &Value,            // execution result
    execution_duration_ms: u64,
    config: &Value,
) -> GateDecision;
```

**Behavior:** Plugins are evaluated in registration order. The first `Deny` or `Challenge` short-circuits the chain.

**Built-in tool-gate plugins (registered in order):**

| Plugin | Purpose |
|--------|---------|
| `PaymentGatePlugin` | MPP payment challenges and verification |
| `GuardrailsGatePlugin` | External HTTP webhook hooks with CEL triggers |

Trust-level + CEL policy (stage ⑤) runs inline as `PreDispatchPolicyGate`
for performance; it is *not* a plugin today.

**Custom extensions (examples):**
- Rate limiter
- Budget enforcement
- External PDP callout (OPA, Cedar, SpiceDB)
- Human approval queue
- Content safety scanner

### 6.2 TransformPlugin — Argument/Result Rewriting

**When it runs:** Stages ⑧ (pre) and ⑪ (post)

**What it receives:**

```rust
async fn transform_arguments(
    &self,
    ctx: &PluginContext,
    arguments: &Value,
    config: &Value,
) -> TransformResult;          // { transformed: Value, modified: bool }

async fn transform_result(
    &self,
    ctx: &PluginContext,
    result: &Value,
    config: &Value,
) -> TransformResult;
```

**Behavior:** All transform plugins run in order. Each receives the output of the previous one (chained). Transforms cannot short-circuit — they always produce output.

**Custom extensions (examples):**
- PII masking / redaction
- Schema migration (v1 → v2 argument rewriting)
- Field mapping (rename keys for downstream compatibility)
- Response enrichment (add metadata, timestamps)
- Audit field injection

### 6.3 IdentityPlugin — Custom Identity Resolution

**When it runs:** During identity resolution (stage 2 of transport)

**What it receives:**

```rust
async fn resolve_identity(
    &self,
    headers: &[(String, String)],   // request headers as key-value pairs
    config: &Value,
) -> IdentityResolution;           // Resolved / NoToken / Error
```

**Behavior:** First non-`NoToken` result wins. The identity plugin chain runs after the built-in OIDC/JWKS/Header resolution.

**Custom extensions (examples):**
- Custom JWT claim expansion (map claims to internal roles)
- Enterprise group lookup (LDAP/Active Directory)
- Workload identity mapping (SPIFFE/mTLS)
- Proprietary token verification
- API key validation

### 6.4 BindingPlugin — Pluggable Dispatch Transports

**When it runs:** Stage ⑨ (Execution Dispatch), on tool routes whose
backend type matches a plugin's `kind()`.

**What it receives:**

```rust
#[async_trait]
pub trait BindingPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn kind(&self) -> &str;                     // "nats", "kafka", ...
    async fn register_profile(
        &self,
        binding_name: &str,
        spec: &serde_json::Value,               // serialized per-backend config
        host: Arc<dyn BindingHost>,             // re-entrant dispatch capability
    ) -> Result<(), BindingError>;
    async fn execute(
        &self,
        binding_name: &str,
        request: BindingRequest,                // payload + W3C headers + ids
    ) -> Result<BindingResponse, BindingError>;
    async fn shutdown(&self) {}                 // drain background state
}
```

**Behavior:** The host holds a map of `kind → BindingPlugin`. When a
tool call routes to e.g. `BindingTypeConfig::Nats(...)` the host
serializes the config fragment and hands it to the plugin whose
`kind() == "nats"`. Profile registration happens once at startup so
misconfiguration fails fast.

**Built-in backend plugins:**

| Crate | Kind | Transport |
|---|---|---|
| `mcpg-plugin-backend-nats` | `nats` | NATS request/reply with trace-header propagation |
| `mcpg-plugin-backend-kafka` | `kafka` | Kafka correlated request/reply |

**Custom extensions (examples):**
- MQTT request/response backend
- RabbitMQ RPC backend
- WebSocket request backend
- Any transport whose YAML is an additive backend type

### 6.5 WatchStrategyPlugin — Pluggable Resource-Change Sources

**When it runs:** when a subscription is established for a resource
whose watch config uses `WatchStrategy::Plugin { kind, spec }` — a
`subscriptions/listen` stream with a `resources/updated` target.

**What it receives:**

```rust
#[async_trait]
pub trait WatchStrategyPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn kind(&self) -> &str;                     // "nats_topic", "kafka_topic", ...
    async fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError>;
    async fn shutdown(&self) {}
}
```

**Behavior:** The plugin spawns a background watcher that calls
`sink.emit(...)` on every change. The host fans those events out to
every subscribed `subscriptions/listen` stream via the delivery bus.

**Built-in watch-strategy plugins:**

| Crate | Kind | Source |
|---|---|---|
| `mcpg-plugin-backend-nats` | `nats_topic` | NATS subject subscription |
| `mcpg-plugin-backend-kafka` | `kafka_topic` | Kafka consumer group |

#### Who owns a subscription (`runtime/subscriptions.rs`)

A `resources/updated` subscription is three pieces of state that must
agree: a row in the `SubscriptionStore` (which the fan-out reads to
decide who receives an update), a per-URI entry in the `WatchEngine`
(which is what *produces* updates and refcounts how many subscribers
still want them), and a holder whose lifetime says how long both should
exist. `SubscriptionService` owns all three; nothing else touches the
store directly to subscribe.

| Holder | Acquires | Releases |
|---|---|---|
| `subscriptions/listen` | one `SubscriptionLease` per stream per target | the stream's response body dropping, or session-row teardown |

The first holder of a `(session, uri)` writes the store row and starts
the watcher; the last one releases both. Two consequences worth knowing:

- The session row is derived from the *principal*, not the connection,
  so every stream a client opens shares one. Leases are what let two
  streams watch the same resource without unsubscribing each other.
  During a flaky reconnect both briefly hold a lease, which is intended
  — the overlapping SSE stream slot (three per session row) is the
  backpressure, not the subscription.
- The ack's `notifications.resourceSubscriptions` reports only the
  targets that were *established*. A URI no resource route resolves, or
  one the store refused (per-session limit, backend failure), is skipped
  and not acked — a client is never told to expect events nothing will
  produce.

Release is asynchronous by design: `Drop` decrements under a mutex and
posts to a reaper, because the store's sync surface blocks on a runtime
internally and the watch engine's channel is async — neither belongs in
a `Drop` that may run off-reactor.

Watchers stop when the last subscriber leaves, when the session row is torn
down (`cascade_session_cleanup` → `release_session`), and when the
runtime that owns them is retired — process drain and config reload both
call `SubscriptionService::shutdown()`. The engine's control loop also
cancels its watchers if it ends because its last sender dropped, so a
reload cannot leave a generation of them running.

In-engine strategies (`Poll`, `Webhook`) do not go through a plugin —
they are in the main binary because they need no external transport
dependency.

---

## 7. Pipeline Execution (Suspendable)

Pipeline backends are special — they compose multiple steps into a single tool call and can suspend to wait for client interaction.

```
tools/call (pipeline backend)
│
├─ execute_pipeline()
│   ├─ Step 1: http      → execute HTTP request
│   ├─ Step 2: transform → CEL expression over context
│   ├─ Step 3: cel_gate  → CEL guard (abort on failure)
│   ├─ Step 4: elicitation → SUSPEND ──┐
│   │                                   │ Serialize pipeline state
│   │                                   │ Return HTTP 200 InputRequiredResult
│   │                                   │ (inputRequests + requestState)
│   │                                   ▼
│   │                         Client collects the input
│   │                         Client retries tools/call with
│   │                         requestState + inputResponses
│   │                                   │
│   │          resume_single_input() / handle_multi_input_resumption()
│   │                                              ├─ Decode requestState
│   │                                              │  (owner check, single use)
│   │                                              ├─ Load + claim pipeline state
│   │                                              ├─ Resume from step 5
│   │                                              ▼
│   ├─ Step 5: http      → another HTTP request
│   └─ Complete → ToolCallResult
│
├─ Post-dispatch plugin gates (⑨)
├─ Post-dispatch transforms (⑩)
└─ Response inline (or per-request SSE when notifications were emitted)
```

Pipeline context flows data between steps: CEL expressions in `transform`, `cel_gate` and `input_transform` read `arguments`, `context` and `steps.<step_id>.output`.

**Suspending step kinds (4):** `elicitation` (asks client for input), `sampling` (asks client for LLM completion), `roots_list` (asks client to enumerate roots), and `gather` (emits several input requests in one suspension, SEP-2322).

> **Multi-instance note.** Pipeline state lives in `pipeline_store` (NATS KV
> or Redis when clustered). The client's retry may arrive at a different
> instance than the one that suspended; that instance decodes the
> `requestState` (every replica derives the same codec key), claims the
> pipeline with a compare-and-set, and resumes locally.

---

## 8. Response Path

### 8.1 JSON Response (non-streaming)

For every response that is not streamed:

```
ProtocolHttpResponse
├─ http_status: 200 (or error code)
└─ response: JsonRpcSuccess { jsonrpc: "2.0", id, result }
    │
    ▼
HTTP Response with Content-Type: application/json
+ x-mcpg-request-id header
+ Mcp-Protocol-Version: 2026-07-28
```

### 8.2 Per-request SSE Response

For a `tools/call` that emitted `notifications/progress` or
`notifications/message`, when the client accepts `text/event-stream`:

```
ProtocolHttpResponse (200, resultType "complete")
│
├─ take_pending_deliveries(session_id) — the notifications the call
│  stored during execution; empty ⇒ inline JSON instead
│
├─ map the notifications, then the response, to SSE events
│   { event: "message", data: JSON }   (no SSE id: the stream is not
│                                       resumable)
│
└─ Sse::new(stream)
   Content-Type: text/event-stream
   + x-mcpg-request-id, Mcp-Protocol-Version, X-Accel-Buffering: no
```

An `InputRequiredResult` and a task result are never streamed.

### 8.3 Long-lived SSE Streams (`subscriptions/listen`, `events/stream`)

```
POST /mcp subscriptions/listen
│
├─ caller_owns_session — before the slot
├─ acquire_sse_slot — at most 3 per session row
├─ SubscriptionLease per resources/updated target
├─ First event: the acknowledgement (honored targets)
├─ Live stream (delivery bus subscription, subscription_matches filter)
│
└─ KeepAlive enabled; leases and admission released on drop
```

> **Multi-instance note.** A listen stream is the one place traffic is
> pinned to a single instance — the TCP connection lives where it
> originated. Every other request can land on any instance. Notifications
> travel from the producing instance (e.g. a watcher or a task on
> instance B) to the instance holding the stream (instance A) via the
> **delivery bus** (NATS Core pub/sub or Redis pub/sub). See §11.

---

## 9. Entity Reference

Key structs and where they live in the request lifecycle:

| Entity | Module | Role |
|--------|--------|------|
| `RequestContext` | `runtime/mod.rs` | Per-request envelope: identity, session row, request ID, transport, request capabilities |
| `RequestIdentity` | `runtime/mod.rs` | Caller identity: Anonymous, HttpHeader, or Verified |
| `ProtocolMessage` | `mcpg-mcp-wire` (`shared::messages`) | Parsed request: label, typed operation, JSON-RPC id, `Mcp-Method` |
| `ProtocolOperation` | `mcpg-mcp-wire` (`v_2026_07_28::wire::operations`) | The `2026-07-28` operation |
| `ToolRoute` | `bindings/mod.rs` | Resolved backend: Http, Command, Nats, gRPC, GraphQL, Kafka, Mock, Pipeline |
| `ToolExecutionRequest` | `runtime/mod.rs` | Execution envelope: context, tool_name, arguments, expr_ctx |
| `ToolCallResult` | `runtime/execution.rs` | Execution result: content, is_error, metadata |
| `PluginContext` | `mcpg-plugin-api` | Plugin view of request: request_id, session_id, tool_name, identity |
| `GateDecision` | `mcpg-plugin-api` | Plugin gate outcome: Allow, Deny, Challenge |
| `TransformResult` | `mcpg-plugin-api` | Plugin transform outcome: transformed value + modified flag |
| `PluginRegistry` | `mcpg-plugin-host` | Ordered chain of registered plugins per class |
| `ProtocolHttpResponse` | `mcpg-mcp-wire` (`shared::jsonrpc`) | Final response: HTTP status, JSON-RPC payload |

---

## 10. Observability Through the Flow

The gateway emits Prometheus metrics and OpenTelemetry traces at each
stage. This table lists the primary metrics an operator or SRE will
typically alert on — see `apps/gateway/docs/observability.md` for the
complete catalog.

| Stage / Concern | Metric | Labels |
|---|---|---|
| Request lifecycle | `mcpg_requests_total` | `operation`, `transport` |
| Request lifecycle | `mcpg_request_duration_seconds` | `operation`, `transport` |
| Session rows | `mcpg_active_sessions` (gauge) | — |
| Session rows | `mcpg_session_duration_seconds` | — |
| Session rows | `mcpg_tenant_session_quota_rejected_total` | — |
| Listen streams | `mcpg_sse_stream_limit_rejected_total` | — |
| Rate limiting | `mcpg_rate_limit_denials_total` | `tool` |
| Policy gate | `mcpg_policy_evaluations_total` | `decision`, `reason` |
| Policy cache | `mcpg_policy_cache_hits_total` / `_misses_total` / `_evictions_total` | — |
| Plugin evaluation | `mcpg_plugin_evaluations_total` | `plugin_id`, `phase`, `decision` |
| Plugin cache | `mcpg_plugin_cache_hits_total` | `plugin_id` |
| Shadow mode | `mcpg_shadow_evaluations_total` | `plugin_id`, `decision` |
| Guardrail hook | `mcpg_guardrail_evaluations_total` | `hook`, `phase`, `decision` |
| Guardrail hook | `mcpg_guardrail_evaluation_duration_seconds` | `hook`, `phase` |
| Guardrail hook | `mcpg_guardrail_errors_total` | `hook`, `kind` |
| Binding execution | `mcpg_binding_executions_total` | `binding_name`, `binding_type`, `outcome` |
| Binding execution | `mcpg_binding_execution_duration_seconds` | `binding_name`, `binding_type`, `outcome` |
| Binding retries | `mcpg_binding_retries_total` / `_retries_exhausted_total` | `binding_name` |
| Binding health | `mcpg_binding_health_status` (gauge) | `binding_name` |
| Pipelines | `mcpg_pipeline_suspensions_total` / `_completions_total` | — |
| Pipelines | `mcpg_pipeline_step_duration_seconds` | `step_id` |
| Pipelines | `mcpg_pipeline_reaper_cleaned_total` | — |
| Cancellation | `mcpg_cancellation_applied_total` / `_cancellations_broadcast_total` / `mcpg_tasks_cancelled_total` | — |
| OAuth | `mcpg_oauth_token_refresh_total` / `_refresh_error_total` / `_cache_hit_total` | `provider` |
| Security | `mcpg_dns_rebinding_blocked_total` | — |
| Security | `mcpg_credential_header_stripped_total` | — |
| Config | `mcpg_config_reloads_total` | `outcome` |
| Errors | `mcpg_errors_total` | `error_kind`, `binding` |

Structured logging is JSON and carries `request_id`, `session_id`,
`identity_kind`, `identity_trust`, `tool_name`, `binding_kind`, and the
current `traceparent` on every relevant log line for correlation.

**OpenTelemetry trace context.** Inbound `traceparent` / `tracestate`
are parsed at the HTTP transport (`transports/mod.rs:28-73`) and
attached to the `RequestContext`. Every outbound backend call injects
a child `traceparent` so end-to-end traces span client → MCPG →
upstream:

- HTTP / reqwest backends: `traceparent` header on the outbound request
- Command backends: `TRACEPARENT` env var on the spawned process
- NATS / Kafka backends: `traceparent` message / record header
- Any `BackendPlugin`: injected via `BackendRequest.headers`

OpenTelemetry trace context (`traceparent`/`tracestate`) is propagated from inbound requests and attached to outbound backend calls.

---

## 11. Multi-Instance Deployment (Distributed Flows)

In a **single-instance** deployment every store, bus, limiter, and
subscription is in-memory and the request paths in §1–§8 run end-to-end on
that one instance.

In a **multi-instance** deployment (HA, horizontal scale) MCPG behaves as a
stateless request router over *shared state* + *shared buses*. The same
stages of §1–§8 run — but several of them now cross an instance boundary.
The sections below describe what hops where.

### 11.1 Topology

```
                        ┌───────────┐
                        │   L4/L7   │    (round-robin; no affinity when every
                        │ balancer  │     replica derives the same session-row
                        └─────┬─────┘     and requestState keys)
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐    ┌──────────┐    ┌──────────┐
        │  mcpg A  │    │  mcpg B  │    │  mcpg C  │
        └────┬─────┘    └────┬─────┘    └────┬─────┘
             │ ▲              │ ▲              │ ▲
             ▼ │              ▼ │              ▼ │
   ┌─────────────────────────────────────────────────────┐
   │  Shared state (NATS JetStream KV or Redis)           │
   │  • SessionStore    — per-caller session rows         │
   │  • PipelineStore   — suspended pipeline state        │
   │  • TaskStore       — MCP task status + result        │
   │  • SubscriptionStore — resource subscription index   │
   │  • RateLimiter     — token buckets (atomic CAS / Lua)│
   └─────────────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────────────┐
   │  Shared buses (NATS Core pub/sub or Redis pub/sub)   │
   │  • DeliveryBus      — notifications to listen streams│
   │  • CancellationBus  — cancellation IDs fan-out       │
   └─────────────────────────────────────────────────────┘
```

The shared KV + bus come from the **single top-level `cluster.kind`**
coordinator (`single_node | redis | nats`) — there is no
`plugins.backend.provider` knob. Every capability (sessions / tasks /
pipelines / delivery / cancellation) inherits the coordinator's
`key_value_store()` / `pub_sub()` primitives; a per-capability `store:` /
`bus:` override can pin an individual capability to an in-process backend
(`memory` / `file`). See [infrastructure.md](infrastructure.md) for
the coordinator capability matrix.

### 11.2 Per-operation cross-instance hops

| Request type | Landing instance | Cross-instance hops |
|---|---|---|
| `POST /mcp server/discover`, `*/list` | Any | No hops. |
| `POST /mcp tools/call` (sync result) | Any | Same instance handles the whole §5 dispatch pipeline. Result returns in-line as JSON-RPC (or as a per-request SSE response). |
| `POST /mcp tools/call` (`InputRequiredResult`) | Any | The suspending instance stores the pipeline in the shared PipelineStore and answers inline. |
| `POST /mcp tools/call` retry with `requestState` | Any | Decodes the `requestState`, claims the pipeline from the shared PipelineStore, resumes locally. The instance that *suspended* the pipeline and the instance that *resumes* it are often different. |
| `POST /mcp tools/call` (task) | Any (executor) | Spawns a background task on the landing instance. Task rows go to the shared TaskStore, keyed on the principal. Cancellation is subscribed from the CancellationBus by the executor. |
| `tasks/get` | Any | Pure read from the shared TaskStore — need not hit the executing instance. |
| `tasks/update` | Any | Feeds `inputResponses` to an `input_required` task through the MRTR resume codec. |
| `tasks/cancel` | Any | Owner check, then publishes `task_id` on the CancellationBus. The executor flips its local cancellation token when it observes the ID. |
| `notifications/cancelled` (JSON-RPC request cancel) | Any | Owner check, then a CancellationBus publish. |
| `subscriptions/listen` | Whichever instance the balancer picks | Pins there for the life of the TCP connection. Goes through `SubscriptionService`, which mutates the shared SubscriptionStore; the instance subscribes the DeliveryBus for the session row and pipes matching notifications into the stream. A broken stream is reopened, not resumed. |
| Resource-change event (from poll/webhook/plugin watch strategy) | Any (watcher-owning) | Watcher publishes `notifications/resources/updated` for every subscriber via the DeliveryBus; **every** instance holding at least one of the subscribed listen streams delivers the notification to its local clients. |
| Session row end (idle expiry, admin terminate) | Any | Recorded under `session-end:`; every instance releases the listen streams, leases and admission of that row. |

### 11.3 Delivery bus — notifications

The delivery bus is the cross-instance hop for notifications a listen stream
carries: `notifications/resources/updated`, `notifications/*/list_changed`
and `notifications/tasks`.

```
 Instance B — a watcher or a task fires
 ┌───────────────────────────────────────────────┐
 │  delivery_bus.publish(session_id, msg)        │
 └───────────────────────┬───────────────────────┘
                         │
                         ▼  NATS Core "mcpg.delivery.<sid>" / Redis channel
                         │
 Instance A — holds the client's listen stream  ──────────────────┐
 ┌───────────────────────────────────────────────┐                 │
 │  subscribe(session_id)                        │                 │
 │  subscription_matches → axum::sse::Event      │                 │
 │                                                                 ▼
 │  ── flushed to MCP client over the open HTTP/1.1 connection ───┘
 └───────────────────────────────────────────────┘
```

- The `delivery_bus.publish` call is fire-and-forget best-effort; the task
  and subscription stores are the durable record, and a client re-reads
  (`resources/read`, `tasks/get`) on a notification.
- In single-instance mode (`cluster.kind: single_node`, the default) the
  bus is the single-node coordinator's in-process broadcast `PubSub`, so the
  hop is a `tokio::sync::broadcast` send with no network cost. (There is no
  type named `InProcessDeliveryBus`; the delivery bus is always a
  `BusBackedDeliveryBus` over the coordinator's `pub_sub()` primitive —
  in-process for single_node, NATS/Redis pub/sub for a clustered kind.)

### 11.4 Cancellation bus — reaching the executor

`tasks/cancel` and `notifications/cancelled` are small but critical: the
instance receiving the cancellation is almost certainly not the one
executing the work. The cancellation bus fan-outs a single ID string; each
instance subscribes, looks up the ID in its local cancellation-token
registry, and flips the token if present. The executor's binding call
(HTTP, NATS, pipeline step, …) observes the cancelled token and aborts.

Subject layout:

- **NATS** — `mcpg.cancel.<partition_key>` where `partition_key` is the
  principal ID (hashed, with wildcards stripped) or `anon` when absent.
  Partitioning keeps per-tenant fan-out bounded.
- **Redis** — `mcpg:cancel:<partition_key>` pub/sub channel with the same
  partitioning rule.

### 11.5 Resource-change fan-out

Resource subscriptions are cluster-wide. A `subscriptions/listen` stream with
`resourceSubscriptions` mutates the shared `SubscriptionStore`; every instance
sees every subscription. When a change is detected (poll watcher, plugin watch
strategy via `WatchStrategyPlugin`, or an inbound
`/webhooks/resource-updated/{token}` POST), the watcher-owning instance
publishes `notifications/resources/updated` on the delivery bus, addressed by
`session_id`. Each instance holding a listen stream for a subscribed session
row delivers the notification to its local client. Notification filters
(`notification_filter.subject_id`, `session_id`, `expression`) are
evaluated *per subscriber* on each instance — the filter does not need to
cross the boundary because subscriber identity is stored alongside the
subscription.

### 11.6 Operational invariants

- **Pinning only applies to long-lived streams** (`subscriptions/listen`,
  `events/stream`). Every other MCP request can freely round-robin.
- **Writes are single-instance; reads are any-instance.** Every store
  operation that mutates state is the responsibility of one instance;
  reads are free-for-all.
- **Buses are best-effort; stores are durable.** If the delivery or
  cancellation bus drops a message, the corresponding durable store
  (pipeline state, task status, subscription set) still reflects the
  truth and the next poll recovers.
- **Single-instance parity.** The same code paths run in single-instance
  mode: the delivery + cancellation buses are `BusBackedDeliveryBus` /
  `BusBackedCancellationBus` over the single-node coordinator's in-process
  broadcast `PubSub`, and the stores are the single-node `MemoryKv` — the
  "hop" reduces to a channel send, so dev and prod behave the same
  logically.
- **Plugin backends are the only transport dep.** Removing `async-nats`,
  `rdkafka`, and `redis` from the main binary was the last step
  consolidating everything cluster-specific into plugin crates
  (`mcpg-plugin-backend-nats`, `mcpg-plugin-backend-redis`,
  `mcpg-plugin-backend-nats`, `mcpg-plugin-backend-kafka`).

---

## 12. Extension Summary

| Extension Point | Trait | Config Path | When |
|-----------------|-------|-------------|------|
| Pre-dispatch gating | `ToolGatePlugin` | `plugins[]` or `guardrails:` | Before execution |
| Post-dispatch gating | `ToolGatePlugin` | `plugins[]` or `guardrails:` | After execution |
| Argument rewriting | `TransformPlugin` | `plugins[]` | Before execution |
| Result rewriting | `TransformPlugin` | `plugins[]` | After execution |
| Identity resolution | `IdentityPlugin` | `plugins[]` | During transport |
| Backend transport | `BackendPlugin` | `backend: { ... }` per entry | Stage ⑧ |
| Watch-change source | `WatchStrategyPlugin` | `watch.strategy: ...` per entry | Resource change fan-out |
| Policy rules | CEL expressions | `governance.policy.tool_access.cel_allow_if`, `tool_access.rules[].cel_allow_if`, or per-binding `governance.allow_if` | Stage ③ |
| Payment gating | Config-driven | `payment:` section | Stage ④ |
| Guardrail webhooks | Config-driven | `guardrails:` section | Stages ⑤ ⑨ |

Plugins are async, support both Native (Tier 2, full trust) and Wasm (Tier 1, sandboxed), and receive a `serde_json::Value` config blob at every invocation. See [plugins.md](plugins.md) for the full plugin reference.
