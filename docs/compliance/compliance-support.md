# MCPG MCP Compliance Support Statement

> Source of truth for what MCPG supports on the primary `/mcp` endpoint.
> Keep this file in lockstep with runtime behavior — the CI conformance
> matrix (`apps/gateway/tests/conformance_matrix.rs`) pins the behavior it
> describes.

## Spec Revision

**Supported:** `2026-07-28`

**Support policy:** MCPG serves one MCP revision. A request that names another
revision, or names none, is refused with HTTP 400 and JSON-RPC `-32022`, with
`data.supported: ["2026-07-28"]`. No JSON-RPC batch POST.

## Transport

| Area | Status |
|---|---|
| Streamable HTTP POST carrying exactly one JSON-RPC message | Supported |
| JSON-RPC batch arrays on the primary endpoint | **Not supported** (rejected) |
| `Mcp-Protocol-Version: 2026-07-28` (or the `_meta` protocol version) | Required |
| `Mcp-Protocol-Version` with another value, or no version at all | **HTTP 400**, `-32022` (`data.requested` when a version was named) |
| `Mcp-Protocol-Version` that is not valid UTF-8 | **HTTP 400**, `-32600` |
| Authentication before the version check | Enforced: a caller without credentials gets the `401` challenge first |
| `Mcp-Method` header (SEP-2243) | Required; must match the body method (`-32020` on mismatch) |
| `Mcp-Name` header for `tools/call`, `prompts/get`, `resources/read` | Required; must match `params.name` / `params.uri` after `=?base64?…?=` decode (`-32020`) |
| `Mcp-Param-{Name}` promotions | Validated against `params.arguments` |
| `Mcp-Protocol-Version: 2026-07-28` on every response | Supported |
| POST body cap (operator-tunable, default 4 MiB) | Supported via `server.max_request_body_mb` |
| `Accept` header media-range parsing (q=0 rejection, prefix-collision-safe) | Supported |
| POST → JSON response | Supported |
| POST → per-request SSE for a `tools/call` that emits progress or log notifications | Supported; no SSE `id:` |
| POST → `202 Accepted` for JSON-RPC notifications | Supported |
| `subscriptions/listen` POST-SSE | Supported; at most 3 concurrent streams per session row |
| `GET` / `HEAD` / `DELETE` on the MCP path | Browser redirect (GET/HEAD), origin check, authentication, then **405** with `Allow: POST` |
| Session and resume-cursor request headers | Not read |
| TLS / mTLS termination | Supported via `axum_server::tls_rustls` |

## Requests

| Area | Status |
|---|---|
| `server/discover` → `DiscoverResult` (capabilities, extensions, `supportedVersions`, `ttlMs` / `cacheScope`) | Supported |
| `_meta` `protocolVersion` / `clientInfo` / `clientCapabilities` (SEP-2575) | Required on `server/discover`; on every id-bearing method with `server.enforce_request_meta` |
| `_meta` `logLevel` (per-request log floor) | Supported; absent ⇒ no `notifications/message` for the request |
| `id` MUST be string or number (null/bool/object/array rejected) | Supported |
| `_meta.progressToken` MUST be string or non-empty number | Supported |
| `_meta` reserved-prefix policing (second label `modelcontextprotocol` / `mcp`) | Supported |
| `requestState` / `inputResponses` under `_meta` | Refused with `-32600` (they are top-level params) |
| Method the revision does not define | **HTTP 404**, `-32601` |
| Per-principal session-row cap (`server.max_sessions_per_tenant`) | Supported; refused with HTTP 503, counts `mcpg_tenant_session_quota_rejected_total{tenant}` |
| Session-row idle timeout + max concurrent rows | Supported via `session_store` config |

## Capabilities

| Capability | Server → Client | Client → Server |
|---|---|---|
| `tools/list` / `tools/call` | Supported | n/a |
| `prompts/list` / `prompts/get` | Supported (native codec; no text-JSON reparse) | n/a |
| `resources/list` / `resources/read` | Supported (native codec) | n/a |
| `resources/templates/list` + template-matched `resources/read` | Supported | n/a |
| `completion/complete` with `context.arguments` | Supported | n/a |
| `completion/complete` with `ref/resource` | Supported | n/a |
| Tasks extension: server-directed task on `tools/call` (client declared the extension, tool `taskSupport` allows it) | Supported | n/a |
| `tasks/get` / `tasks/update` / `tasks/cancel` | Supported; principal-keyed ownership | n/a |
| `notifications/tasks` on `subscriptions/listen` | Supported | n/a |
| MRTR `InputRequiredResult` + retry with `requestState` / `inputResponses` | Supported; single- and multi-entry | n/a |
| `elicitation/create` (form mode) input request | Supported, gated on the request's `clientCapabilities.elicitation` | n/a |
| `elicitation/create` (URL mode) input request | Supported, gated on `clientCapabilities.elicitation.url` | n/a |
| `sampling/createMessage` input request | Supported, gated on `clientCapabilities.sampling` | n/a |
| `sampling/createMessage` with `tools` / `toolChoice` | Supported; either field requires `clientCapabilities.sampling.tools` (fail-closed) | n/a |
| `sampling/createMessage` with `includeContext` (typed enum None/ThisServer/AllServers) | Supported, gated on `clientCapabilities.sampling.context` | n/a |
| `sampling/createMessage` `maxTokens` always serialised (REQUIRED field) | Supported; pipeline sentinel `0` substitutes `DEFAULT_SAMPLING_MAX_TOKENS = 4096` | n/a |
| `SamplingMessage::ToolResult.content` restricted to text/image/audio/resource | Enforced by type system | n/a |
| `elicitation/create.requestedSchema` SEP-1330 primitive-only validation | Supported; non-primitive properties rejected with `mcpg_elicitation_schema_rejected_total` | n/a |
| `roots/list` input request | Supported, gated on `clientCapabilities.roots` | n/a |
| Incremental scope guidance (`error="insufficient_scope", scope="..."`) | Supported when auth/policy layer supplies the scopes | n/a |

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
| Input arguments fail `inputSchema` | `isError: true` tool result with a human-readable message. Not a JSON-RPC protocol error. |
| Tool declared `outputSchema` but returned non-conforming `structuredContent` | `isError: true` tool result; structured content stripped. |
| Unknown tool name | JSON-RPC `-32602` protocol error with a `tools/list` hint. |
| Malformed `tools/call` envelope | JSON-RPC `-32602` / `-32600` protocol error. |

## Plugin Mediation Scope

| Surface | Gate plugins run? |
|---|---|
| `tools/call` | Yes (default surface) |
| `prompts/get` | Yes (`PluginContext.surface = "prompt"`) |
| `resources/read` (exact) | Yes (`surface = "resource"`) |
| `resources/read` (template) | Yes (`surface = "resource_template"`) |
| `completion/complete` | Yes (`surface = "completion"`) |
| stdio identity plugin chain | **Not run** — stdio is anonymous-by-default by design; identity plugins resolve remote principals from wire credentials stdio does not carry. |

## Cancellation

| Mechanism | Status |
|---|---|
| `notifications/cancelled` published to cluster bus (requester must own the call) | Supported |
| `tasks/cancel` published to cluster bus (requester must own the task) | Supported |
| Cancellation bus subscriber interrupts matching in-flight tokens | Supported |
| Cooperative mid-dispatch cancellation inside synchronous backend adapters | **Best-effort** — cancellation is applied at task-entry and between retry / pipeline boundaries; in-flight HTTP / NATS / gRPC calls continue until their own timeout fires |
| Cancellation bus subject partitioned per principal | Supported. NATS subject `mcpg.internal.cancel.<principal>`; Redis channel `mcpg:cancel:<principal>`; PSUBSCRIBE wildcard for receivers |
| Cancellation bus preflight at bootstrap | Redis PING preflight refuses bootstrap on failure |

## Notifications and Utilities

| Utility | Status |
|---|---|
| `notifications/progress` monotonicity (per session row + token) | Enforced; non-monotonic emissions dropped + `mcpg_progress_non_monotonic_dropped_total` |
| `notifications/message` credential redaction at emission | Enforced |
| Pagination cursor HMAC-bound | Supported; an invalid cursor returns `-32602` |
| Deterministic lexicographic ordering on `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` | Supported |
| `completion/complete` per-caller rate limit | Supported via `server.completion_rate_limit_per_sec`; 429 + counts `mcpg_completion_rate_limited_total` |
| Listen streams and their leases released when a session row ends (admin terminate, idle expiry), on every replica | Supported |
| Resource URI normalization (RFC 3986 + scheme allow-list) | Supported; operator extends via `server.extra_resource_uri_schemes` |
| W3C trace context (SEP-414) via `_meta.traceparent` | Supported; lifted inbound when the HTTP header is absent |

## Storage & Retention

| Store | Backends | Quota / TTL surface |
|---|---|---|
| Session rows | in-memory, file-backed, NATS KV, Redis | `gateway.server.session_idle_timeout_ms`, max concurrent rows, `gateway.server.max_sessions_per_tenant` |
| Pipeline (suspended) | in-memory, NATS KV, Redis | per-pipeline `pipeline_timeout_ms`; pipeline reaper sweeps expired records every 30s |
| Task | in-memory, NATS KV, Redis | `mcp.capabilities.tasks.default_ttl_ms` (default 1 800 000 = 30 min), `mcp.capabilities.tasks.max_tasks_per_session` (default 256), `mcp.capabilities.tasks.reaper_interval_ms` (default 60 000) |
| Subscription | in-memory, NATS KV, Redis | `mcp.configurations.subscriptions.max_per_session` |

## Observability

| Signal | How to read it |
|---|---|
| Prometheus `mcpg_requests_total{operation,transport}` | Request counters |
| `mcpg_request_duration_seconds` histogram | Per-operation latency |
| `mcpg_binding_executions_total{binding_name,binding_type,outcome}` | Tool dispatch outcomes |
| `mcpg_binding_execution_duration_seconds` histogram | Per-binding latency |
| `mcpg_active_sessions` gauge | Active session rows |
| `mcpg_pipeline_suspensions_total{step_type,pipeline}` | Suspension counter |
| `mcpg_task_reaper_cleaned_total` / `mcpg_task_reaper_last_sweep_count` | Task retention |
| `mcpg_cancellation_applied_total{kind}` | Cancellation subscriber applied a cancel |
| OpenTelemetry traces | `traceparent` forwarded from incoming HTTP, propagated on outbound HTTP/NATS |

## Authorization

| Area | Status |
|---|---|
| OIDC `audience` REQUIRED by default (escape hatch: `auth.jwks.allow_missing_audience`) | Supported |
| HMAC algorithms (HS256/384/512) opt-in via `verification.allow_hmac` | Supported |
| OIDC discovery + JWKS SSRF guard (private/loopback/CGNAT/ULA blocklist + optional `allowed_issuer_hosts`) | Supported |
| JWKS refresh circuit breaker (5 consecutive failures → 30 s open) | Supported; counts `mcpg_oidc_jwks_circuit_short_circuited_total{issuer}` |
| Insecure-public bind warning (0.0.0.0/:: without TLS+auth) | Supported; counts `mcpg_insecure_public_bind_total` |
| Token-passthrough guard (strips `authorization`, `cookie`, `x-api-key`, ... at egress) | Supported; escape hatch `MCPG_ALLOW_HEADER_PASSTHROUGH=1`; counts `mcpg_credential_header_stripped_total{header}` |

## Plugin System

| Area | Status |
|---|---|
| Surface-aware mediation (`PluginContext.surface`) | Supported across native + Wasm |
| FFI-stable plugin ABI via `abi_stable` | `mcpg_plugin_api::abi` exports `RPluginContext`, `RGateDecision`, `RTransformResult`, `RIdentityResolution`; the version is `MCPG_PLUGIN_ABI_VERSION` |
| Dynamic native plugin loading (`libloading` + signature/hash verify) | `mcpg_plugin_host::native_loader::load_native_plugin` |
| Plugin shutdown hook (drain background sinks) | Supported |
| Webhook plugin per-endpoint circuit breaker + jittered backoff | Supported |

## MCP App URLs

| Area | Status |
|---|---|
| `mcp_app_url` config field on resource/resource_template bindings | Supported |
| `_meta.mcpAppUrl` on `resources/list` descriptors | Supported — static values merged at build time, CEL expressions resolved at list time |
| `_meta.mcpAppUrl` on `resources/read` content items | Supported — resolved with full `ExprContext` including `arguments` |

## OAuth 2.0 Outbound Token Management

| Area | Status |
|---|---|
| OAuth 2.0 client_credentials issuer (RFC 6749 §4.4) via `dev.mcpg.credential.oauth-client-credentials` plugin | Supported |
| In-plugin DashMap token cache + per-provider async Mutex refresh coalescing | Supported |
| Proactive refresh window (`refresh_buffer_ms`) + 5-minute stale-token grace fallback | Supported (default refresh: 60s) |
| Host-side per-(identity, plugin, target) L1 credential cache with cluster pub/sub invalidation | Supported |
| `cred://dev.mcpg.credential.oauth-client-credentials/<provider>` URI substitution in binding headers | Supported |
| Metrics: `mcpg_oauth_token_refresh_total`, `mcpg_oauth_token_refresh_error_total`, `mcpg_oauth_token_cache_hit_total`, `mcpg_oauth_token_endpoint_latency_ms` | Supported |

## Subject-Scoped Resource Notifications

| Area | Status |
|---|---|
| `SubscriberIdentity` captured when the listen stream opens | Supported |
| `notification_filter` on `ResourceWatchConfig` | Supported |
| Scope: `All` (broadcast, default) | Supported |
| Scope: `SubjectId` (principal match) | Supported |
| Scope: `SessionId` (originating session row only) | Supported |
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
| Mid-flight cooperative cancellation of long-running backend calls | Token registry + subscriber in place; deeper plumbing into individual backend adapters is open. |
| Anonymous cancellation | An anonymous HTTP caller cannot cancel its in-flight call (its session row is fresh per request). |
| Progress from pipeline steps and federated calls | Delivered on the delivery bus; the per-request response stream of the call does not carry it. |
| Concurrent calls of one principal and client | They share one session row, so the per-request stream of one call can carry a notification of another. |
| Upstream input in federation | An upstream's `InputRequiredResult` and its server-to-client requests are not relayed to the caller; the gateway declines upstream requests. |
| Per-URI upstream subscriptions | `resources/updated` for a subscribed federated resource comes from gateway-side polling (`federations[].synthesize`). |
| `mcpg-plugin-call-logger` Beta (full-payload default — pair with the redactor) | Beta |

See [mcpg.dev/docs/gateway/protocol-versions](https://mcpg.dev/docs/gateway/protocol-versions)
for how MCPG serves `2026-07-28`.

## Source of Truth

If any of the above diverges from the code, the code wins and this document
is wrong — please file it and re-align. Tests that must stay green to claim
compliance:

- `apps/gateway/tests/transport_conformance.rs` (wire-level rules)
- `apps/gateway/tests/conformance_matrix.rs` (spec-versioned behavior)
- `apps/gateway/src/runtime/invocation.rs` tests (surface codecs)
- `apps/gateway/src/runtime/task_store.rs` tests (task lifecycle)
