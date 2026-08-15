# MCPG MCP Compliance Support Statement

> Source of truth for what MCPG supports on the primary `/mcp` endpoint.
> Keep this file in lockstep with runtime behavior — the CI conformance
> matrix (`apps/gateway/tests/conformance_matrix.rs`) pins it.

## Spec Revision

**Supported:** `2025-11-25`

**Support policy:** current-spec only. MCPG does not carry legacy behaviors
on the primary endpoint (no JSON-RPC batch POST, no legacy negotiation
fallback, no alternate task API). Clients connecting with older revisions
SHOULD upgrade to `2025-11-25`.

## Transport

| Area | Status |
|---|---|
| Streamable HTTP POST carrying exactly one JSON-RPC message | Supported |
| JSON-RPC batch arrays on the primary endpoint | **Not supported** (rejected per 2025-06-18 removal) |
| `Mcp-Protocol-Version` explicit header — supported value | Accepted |
| `Mcp-Protocol-Version` explicit header — invalid / unsupported value | **HTTP 400** |
| `Mcp-Protocol-Version` legacy values (`2025-06-18`, `2025-03-26`) | Accepted; counts `mcpg_protocol_version_legacy_total{version}` (T16-05) |
| `Mcp-Protocol-Version` header omitted on post-initialize HTTP | Accepted; assumed `2025-03-26` per spec; counts `mcpg_protocol_version_absent_total{assumed}` (T16-05) |
| POST body cap (operator-tunable, default 4 MiB) | Supported via `server.max_request_body_mb` (T13-02) |
| `Accept` header media-range parsing (q=0 rejection, prefix-collision-safe) | Supported (T12-08) |
| POST → JSON response | Supported (non-interactive operations) |
| POST → SSE continuation for suspended interactive requests | Supported (MCP 2025-11-25 canonical path) |
| POST → `202 Accepted` for JSON-RPC notifications / responses | Supported (still permitted by the spec) |
| `GET /mcp` SSE side-channel (server-initiated messages, resumption) | Supported |
| Multi-GET SSE (T7-01) | Supported with an **explicit contract**: one session has at most one *active* delivery stream at a time. A fresh `GET /mcp` supersedes the prior active stream for future live delivery; the prior stream's replay window stays available for `Last-Event-Id` resumption. `mcpg_sse_active_stream_superseded_total` counts transitions. |
| `Last-Event-Id` SSE resumption | Supported (unknown cursor → 4xx) |
| `DELETE /mcp` session termination | Supported |
| TLS / mTLS termination | Supported via `axum_server::tls_rustls` |

## Lifecycle

| Area | Status |
|---|---|
| `initialize` → `InitializeResult` | Supported |
| Negotiated session protocol version persisted on the session | Supported |
| `notifications/initialized` | Supported |
| Server advertises `capabilities.tasks.requests.tools.call` | Supported |
| Server echoes `capabilities.experimental` from initialize params | Supported (T15-09) |
| Per-session JSON-RPC `id` uniqueness (rejects duplicates with -32600) | Supported, FIFO window 65 536 (T15-03 / T16-03); evictions count `mcpg_request_id_window_evicted_total` |
| `id` MUST be string or number (null/bool/object/array rejected) | Supported (T15-01 / T15-02) |
| `_meta.progressToken` MUST be string or non-empty number | Supported (T15-04) |
| `_meta` reserved-prefix policing (`mcp.*` / `modelcontextprotocol.*`) | Supported (T15-05) |
| `notifications/cancelled` targeting `initialize` is silently dropped | Supported (T13-03) |
| Per-tenant session quota (`server.max_sessions_per_tenant`) | Supported (T16-07); rejected with HTTP 429; counts `mcpg_tenant_session_quota_rejected_total{tenant}` |
| Session idle timeout + max concurrent session quota | Supported via `session_store` config |

## Capabilities

| Capability | Server → Client | Client → Server |
|---|---|---|
| `tools.list` / `tools.call` | Supported | n/a |
| `prompts.list` / `prompts.get` | Supported (native codec; no text-JSON reparse) | n/a |
| `resources.list` / `resources.read` | Supported (native codec) | n/a |
| `resources.templates.list` + template-matched `resources/read` | Supported | n/a |
| `completion/complete` with `context.arguments` | Supported | n/a |
| `completion/complete` with `ref/resource` | Supported | n/a |
| `tasks.create` (via task-augmented `tools/call`) | Supported | n/a |
| `tasks.list` / `tasks.get` / `tasks.result` (blocking until terminal) | Supported | n/a |
| `tasks.cancel` (rejects terminal tasks with -32602) | Supported | n/a |
| `notifications/tasks/status` (full `Task` envelope + `related-task` `_meta`) | Supported | n/a |
| `elicitation/create` (form mode) | Supported, gated on client `capabilities.elicitation` | n/a |
| `elicitation/create` (URL mode) | Supported, gated on `capabilities.elicitation.url` | n/a |
| `sampling/createMessage` | Supported, gated on client `capabilities.sampling` | n/a |
| `sampling/createMessage` with `tools` / `toolChoice` | Supported; either field requires `capabilities.sampling.tools` (T12-05; fail-closed) | n/a |
| `sampling/createMessage` with `includeContext` (typed enum None/ThisServer/AllServers) | Supported, gated on `capabilities.sampling.context` (T13-05) | n/a |
| `sampling/createMessage` `maxTokens` always serialised (REQUIRED field) | Supported; pipeline sentinel `0` substitutes `DEFAULT_SAMPLING_MAX_TOKENS = 4096` (T17-01) | n/a |
| `SamplingMessage::ToolResult.content` restricted to text/image/audio/resource | Enforced by type system (T15-10) |
| `elicitation/create.requestedSchema` SEP-1330 primitive-only validation | Supported; non-primitive properties rejected with `mcpg_elicitation_schema_rejected_total` (T18-02) |
| `roots/list` | Supported, gated on client `capabilities.roots` | n/a |
| Incremental scope guidance on `401` (`error="insufficient_scope", scope="..."`) | Supported when auth/policy layer supplies the scopes |

## Descriptor Metadata

| Field | Surface |
|---|---|
| `title` | Tool, prompt, resource, resource_template |
| `icons` | Tool, prompt, resource, resource_template — populated from binding `icons` config |
| `_meta` | Tool, prompt, resource, resource_template — populated from binding `descriptor_meta` config |
| `annotations` (tool hints) | Tool |
| `outputSchema` | Tool — strict enforcement: non-conforming `structuredContent` fails the tool call with `isError: true` |

## Tool Contract Edge Cases

| Scenario | Behavior |
|---|---|
| Input arguments fail `inputSchema` | `isError: true` tool result with a human-readable message (T2-06). Not a JSON-RPC protocol error. |
| Tool declared `outputSchema` but returned non-conforming `structuredContent` | `isError: true` tool result; structured content stripped. |
| Unknown tool name | JSON-RPC `-32602` protocol error with a `tools/list` hint. |
| Malformed `tools/call` envelope | JSON-RPC `-32602` / `-32600` protocol error. |

## Plugin Mediation Scope

| Surface | Gate plugins run? |
|---|---|
| `tools/call` | Yes (legacy default) |
| `prompts/get` | Yes (T4-02; `PluginContext.surface = "prompt"`) |
| `resources/read` (exact) | Yes (`surface = "resource"`) |
| `resources/read` (template) | Yes (`surface = "resource_template"`) |
| `completion/complete` | Yes (`surface = "completion"`) |
| stdio identity plugin chain | **Not run** — stdio is anonymous-by-default by design (T4-01); identity plugins resolve remote principals from wire credentials stdio does not carry. |

## Cancellation

| Mechanism | Status |
|---|---|
| `notifications/cancelled` published to cluster bus | Supported |
| `tasks/cancel` published to cluster bus | Supported |
| Cancellation bus subscriber interrupts matching in-flight tokens | Supported (T4-05) |
| Cooperative mid-dispatch cancellation inside synchronous backend adapters | **Best-effort** — cancellation is applied at task-entry and between retry / pipeline boundaries; in-flight HTTP / NATS / gRPC calls continue until their own timeout fires |
| Cancellation bus subject partitioned per principal | Supported (T12-04). NATS subject `mcpg.internal.cancel.<principal>`; Redis channel `mcpg:cancel:<principal>`; PSUBSCRIBE wildcard for receivers |
| Cancellation bus preflight at bootstrap | Redis PING preflight refuses bootstrap on failure (T15-12) |

## Server-Initiated Utilities

| Utility | Status |
|---|---|
| `ping` responder | Supported |
| `ping` driver — server initiates pings on a cadence | Supported via `server.server_ping_interval_ms` (T15-08); counts `mcpg_server_ping_emitted_total` |
| `notifications/progress` monotonicity (per session+token) | Enforced (T16-06); non-monotonic emissions dropped + `mcpg_progress_non_monotonic_dropped_total` |
| `notifications/message` per-stream rate limit | 50/sec, burst 100 (T16-04); alert/critical/emergency bypass; counts `mcpg_logging_notification_rate_limited_total{logger}` |
| `notifications/message` credential redaction at emission | Enforced (T12-07) |
| `notifications/mcpg/server_draining` on graceful shutdown | Emitted to all active SSE streams before transport stop (T15-11) |
| SSE `retry:` field emitted on every event (default 3 s) | Supported (T15-07) |
| Pagination cursor HMAC-bound per session | Supported (T13-04); cross-session replay restarts at offset 0 |
| Deterministic lexicographic ordering on `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` | Supported (T13-01) |
| `completion/complete` per-session rate limit | Supported via `server.completion_rate_limit_per_sec` (T13-07); 429 + counts `mcpg_completion_rate_limited_total` |
| Resource subscription cascade on session terminate (HTTP DELETE + admin) | Supported (T12-06) |
| Resource URI normalization (RFC 3986 + scheme allow-list) | Supported (T15-06 / T16-01); operator extends via `server.extra_resource_uri_schemes` (T17-03) |
| W3C trace context (SEP-414) propagated via `_meta.traceparent` | Supported outbound on sampling+elicitation; lifted inbound when HTTP header absent (T14-01 / T14-02) |
| SEP-2260 server-initiated requests trace to client request id | Enforced at single choke point with `debug_assert!`; release-mode opt-in panic via `MCPG_SEP2260_PANIC=1` (T16-02 / T18-03) |

## Storage & Retention

| Store | Backends | Quota / TTL surface |
|---|---|---|
| Session | in-memory, file-backed, NATS KV, Redis | `session_store.session_idle_timeout_ms`, max concurrent sessions |
| Pipeline (suspended) | in-memory, NATS KV, Redis | per-pipeline `pipeline_timeout_ms`; pipeline reaper sweeps expired records every 30s |
| Task | in-memory, NATS KV, Redis | `task_store.default_ttl_ms` (default 1800 = 30 min), `task_store.max_tasks_per_session` (default 256), `task_store.reaper_interval_ms` (default 60) |
| Subscription | in-memory, NATS KV, Redis | `subscription_store.max_per_session` |

## Observability

| Signal | How to read it |
|---|---|
| Prometheus `mcpg_requests_total{operation,transport}` | Request counters |
| `mcpg_request_duration_seconds` histogram | Per-operation latency |
| `mcpg_binding_executions_total{binding_name,binding_type,outcome}` | Tool dispatch outcomes |
| `mcpg_binding_execution_duration_seconds` histogram | Per-binding latency |
| `mcpg_active_sessions` gauge | Active sessions |
| `mcpg_pipeline_suspensions_total{step_type,pipeline}` | Suspension counter |
| `mcpg_task_reaper_cleaned_total` / `mcpg_task_reaper_last_sweep_count` | Task retention |
| `mcpg_cancellation_applied_total{kind}` | Cancellation subscriber applied a cancel (T4-05) |
| OpenTelemetry traces | `traceparent` forwarded from incoming HTTP, propagated on outbound HTTP/NATS |

## Authorization

| Area | Status |
|---|---|
| OIDC `audience` REQUIRED by default (escape hatch: `auth.jwks.allow_missing_audience`) | T12-01 |
| HMAC algorithms (HS256/384/512) opt-in via `verification.allow_hmac` | T12-03 |
| OIDC discovery + JWKS SSRF guard (private/loopback/CGNAT/ULA blocklist + optional `allowed_issuer_hosts`) | T12-02 |
| JWKS refresh circuit breaker (5 consecutive failures → 30 s open) | T15-13; counts `mcpg_oidc_jwks_circuit_short_circuited_total{issuer}` |
| Insecure-public bind warning (0.0.0.0/:: without TLS+auth) | T15-15; counts `mcpg_insecure_public_bind_total` |
| Token-passthrough guard (strips `authorization`, `cookie`, `x-api-key`, ... at egress) | T15-14; escape hatch `MCPG_ALLOW_HEADER_PASSTHROUGH=1`; counts `mcpg_credential_header_stripped_total{header}` |

## Plugin System

| Area | Status |
|---|---|
| Surface-aware mediation (`PluginContext.surface`) | Supported across native + Wasm |
| FFI-stable plugin ABI via `abi_stable` | T9-03 — `mcpg_plugin_api::abi` exports `RPluginContext`, `RGateDecision`, `RTransformResult`, `RIdentityResolution`; `MCPG_PLUGIN_ABI_VERSION = 1` |
| Dynamic native plugin loading (`libloading` + signature/hash verify) | T4-03 — `mcpg_plugin_host::native_loader::load_native_plugin` |
| Plugin shutdown hook (drain background sinks) | T8-05 |
| Webhook plugin per-endpoint circuit breaker + jittered backoff | T8-04 |

## MCP App URLs

| Area | Status |
|---|---|
| `mcp_app_url` config field on resource/resource_template bindings | Supported (F4, ec0e32d) |
| `_meta.mcpAppUrl` on `resources/list` descriptors | Supported — static values merged at build time, CEL expressions resolved at list time |
| `_meta.mcpAppUrl` on `resources/read` content items | Supported — resolved with full `ExprContext` including `arguments` |

## OAuth 2.0 Outbound Token Management

| Area | Status |
|---|---|
| OAuth 2.0 client_credentials issuer (RFC 6749 §4.4) via `dev.mcpg.credential.oauth-client-credentials` plugin | Supported (Layout #2) |
| In-plugin DashMap token cache + per-provider async Mutex refresh coalescing | Supported |
| Proactive refresh window (`refresh_buffer_ms`) + 5-minute stale-token grace fallback | Supported (default refresh: 60s) |
| Host-side per-(identity, plugin, target) L1 credential cache with cluster pub/sub invalidation | Supported |
| `cred://dev.mcpg.credential.oauth-client-credentials/<provider>` URI substitution in binding headers | Supported |
| Metrics: `mcpg_oauth_token_refresh_total`, `mcpg_oauth_token_refresh_error_total`, `mcpg_oauth_token_cache_hit_total`, `mcpg_oauth_token_endpoint_latency_ms` | Supported |

## Subject-Scoped Resource Notifications

| Area | Status |
|---|---|
| `SubscriberIdentity` captured at subscribe time | Supported (F1, 885d585) |
| `notification_filter` on `ResourceWatchConfig` | Supported |
| Scope: `All` (broadcast, default) | Supported |
| Scope: `SubjectId` (principal match) | Supported |
| Scope: `SessionId` (originating session only) | Supported |
| Scope: `Expression { expression }` (CEL per subscriber) | Supported |

## Distributed Backend Plugin

| Area | Status |
|---|---|
| `plugins.backend.provider` runtime activation | Supported |
| Default "memory" provider (in-process, no external deps) | Supported |
| NATS distributed backend via `provider: nats` | Supported |
| Redis distributed backend via `provider: redis` | Supported |
| Config validation rejects unknown providers with actionable error | Supported |
| Config validation requires infrastructure enabled (nats/redis) | Supported |
| Individual store `kind` overrides for mixed configurations | Supported |

## Known Not-Yet-Done

| Area | State |
|---|---|
| Per-request `idempotency-key` deduplication | Deferred — MCP does not define a mechanism yet; see `apps/gateway/docs/FUTURE.md`. |
| Mid-flight cooperative cancellation of long-running backend calls | Token registry + subscriber in place (T4-05); deeper plumbing into individual backend adapters is a follow-up. |
| `mcpg-plugin-call-logger` Beta (full-payload default — pair with T12-07 redactor) | Beta |

## Source of Truth

If any of the above diverges from the code, the code wins and this document
is wrong — please file it and re-align. Tests that must stay green to claim
compliance:

- `apps/gateway/tests/transport_conformance.rs` (wire-level rules)
- `apps/gateway/tests/conformance_matrix.rs` (spec-versioned behavior)
- `apps/gateway/src/runtime/invocation.rs` tests (surface codecs)
- `apps/gateway/src/runtime/task_store.rs` tests (task lifecycle)
