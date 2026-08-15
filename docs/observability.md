# MCPG Observability

> Structured logs, Prometheus metrics, and OpenTelemetry traces.
> Source: `observability/mod.rs`, metrics emitted across all runtime modules.

The `observability:` block follows the OpenTelemetry signal triad —
`logs`, `metrics`, `traces` — plus an `audit` channel. Each signal
exposes a `sinks: [{kind, config, level?}]` list; built-in `kind`
values are dispatched to in-gateway emitters, and any other `kind`
is resolved against an installed observability plugin by id.

## Structured Logs

MCPG emits structured logs via the `tracing` framework.

### Configuration

```yaml
observability:
  logs:
    enabled: true          # master toggle for logs
    level: "info"          # trace | debug | info | warn | error (workspace default)
    sinks:                 # fan-out targets
      - kind: stderr       # stderr | stdout | file | otlp | <plugin-id>
        config:
          format: json     # json | pretty (OS-stream sinks)
        # level: debug     # optional per-sink override
      # - kind: file
      #   config: { path: /var/log/mcpg.log, format: json }
      # - kind: otlp
      #   config: { url: "http://otel-collector:4317" }
```

**Built-in sink kinds**: `stderr`, `stdout`, `file`, `otlp`. Any other
`kind` must match an installed plugin id (e.g.
`dev.mcpg.observability.otlp`).

**Default**: a single `stderr` sink with `format: json` is installed
when the operator omits `logs.sinks`. Setting `logs.enabled: false`
or providing only plugin sinks suppresses the built-in OS-stream
emitter.

### Per-Session Log Level

The MCP `logging/setLevel` method allows clients to set their session's log level at runtime. Supported levels (ordered):

```
debug < info < notice < warning < error < critical < alert < emergency
```

### Logging Guidelines

MCPG follows these logging conventions:
- JSON format by default (machine-readable first)
- Stable field names for dashboard and grep compatibility
- Request ID, session ID, and backend name as structured fields
- No secrets, tokens, or raw credentials in logs
- Events at ownership boundaries (state transitions, decisions)

---

## Prometheus Metrics

When `observability.metrics.enabled: true` and a `prometheus` sink is
configured, MCPG exposes Prometheus metrics on the configured `path`
(default `/metrics`).

### Configuration

```yaml
observability:
  metrics:
    enabled: true
    sinks:
      - kind: prometheus
        config: { path: /metrics }   # must start with '/'
      # - kind: otlp
      #   config: { url: "http://otel-collector:4317" }
```

The first `prometheus` sink wins for the scrape endpoint. Add an
`otlp` sink (or any installed metrics plugin) to push metrics in
addition to — or instead of — the Prometheus scrape endpoint.

### Request Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_requests_total` | Counter | `operation`, `transport` | Total requests by operation type |
| `mcpg_request_duration_seconds` | Histogram | `operation` | Request latency |
| `mcpg_active_sessions` | Gauge | — | Currently active sessions |

### Backend Execution Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_binding_executions_total` | Counter | `binding_name`, `binding_type`, `outcome` | Binding execution count |
| `mcpg_binding_execution_duration_seconds` | Histogram | `binding_name`, `binding_type`, `outcome` | Binding execution latency |

### Policy Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_policy_evaluations_total` | Counter | `decision`, `reason` | Policy evaluation outcomes |

### Pipeline Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_pipeline_reaper_cleaned_total` | Counter | — | Expired pipelines cleaned |
| `mcpg_pipeline_reaper_last_sweep_count` | Gauge | — | Pipelines cleaned in last sweep |

### Infrastructure Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_nats_connected` | Gauge | — | NATS connection state (0/1) |

### Outcome Labels

The `outcome` label on backend metrics uses:
- `success` — Execution completed without error
- `error` — Execution produced an error result
- `timeout` — Execution timed out
- `suspended` — Pipeline suspended for client interaction

---

## OpenTelemetry Traces

When `observability.traces.enabled: true` and an `otlp` sink is
configured, MCPG exports spans to the OTLP collector at the sink's
`url`.

### Configuration

```yaml
observability:
  traces:
    enabled: true
    service_name: mcpg
    propagate_context: true                  # accept/inject W3C Trace Context headers
    sinks:
      - kind: otlp
        config: { url: "http://127.0.0.1:4317" }   # gRPC OTLP collector
```

The default `traces.sinks` list is empty — operators opt in by
declaring at least one sink. The first `otlp` sink drives the
in-gateway exporter; additional or non-builtin sinks fan out via
observability plugins.

### Span Structure

- **Root span**: Per HTTP request, includes request ID and operation
- **Child spans**: Binding execution, policy evaluation, session operations
- **Service attributes**: `service.name = "mcpg"`, `service.version`

### Integration

The tracing layer is composed with the logging subscriber via `tracing-opentelemetry`. This means:
- Log events automatically generate trace events
- Spans propagate through async boundaries via `tokio` instrumentation
- Tower HTTP middleware adds request-level spans

---

## Health and Readiness Endpoints

### `GET /health`

Always returns HTTP 200. Used by load balancers for liveness.

```json
{ "status": "ok" }
```

### `GET /ready`

Returns HTTP 200 when all subsystems are ready. Used for readiness probes.

### `GET /runtime`

Returns runtime metadata including uptime, version, and active session count. Used for operator inspection.

```json
{
  "service_name": "mcpg",
  "service_version": "0.1.0",
  "uptime_secs": 3600,
  "started_at": "2026-04-06T00:00:00Z"
}
```

## OAuth Token Management Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_oauth_token_refresh_total` | Counter | `provider` | Successful token refreshes |
| `mcpg_oauth_token_refresh_error_total` | Counter | `provider` | Failed token refresh attempts |
| `mcpg_oauth_token_cache_hit_total` | Counter | `provider` | Token served from cache without refresh |

**Alert guidance**:
- `mcpg_oauth_token_refresh_error_total` rising — OAuth provider endpoint
  is unreachable or credentials are invalid. **Investigate**.
- `mcpg_oauth_token_cache_hit_total` flat while `mcpg_oauth_token_refresh_total`
  rises — tokens are expiring too quickly; increase `refresh_buffer_ms` or
  check provider token lifetime.

---

## Operational metrics

The full metric reference lives in
`apps/gateway/docs/configuration.md` under the `MetricsConfig` block.
Highlights for SRE alerting:

- `mcpg_insecure_public_bind_total > 0` — gateway is listening on a
  public interface without TLS+auth. **Page**.
- `mcpg_credential_header_stripped_total{header} > 0` — operator
  config is attempting to forward client credentials. **Investigate**.
- `mcpg_oidc_jwks_circuit_short_circuited_total{issuer}` rising —
  IdP outage; cached keys are still being served within
  `max_staleness` (T15-13).
- `mcpg_request_id_window_evicted_total` rising — sustained pressure
  on per-session id tracker; reconsider the 64 Ki cap (T16-03).
- `mcpg_progress_non_monotonic_dropped_total` rising — pipeline or
  plugin emitting backwards progress (T16-06).
- `mcpg_tenant_session_quota_rejected_total{tenant}` — tenant has
  hit `server.max_sessions_per_tenant`.
- `mcpg_logging_notification_rate_limited_total{logger}` — a log
  source is exceeding 50 messages/sec/stream (T16-04).
- `mcpg_completion_rate_limited_total` — autocomplete UI is
  hammering `completion/complete` (T13-07).
- `mcpg_sep2260_orphan_server_request_total > 0` — internal bug;
  set `MCPG_SEP2260_PANIC=1` in staging to reproduce (T18-03).
- `mcpg_webhook_circuit_state{endpoint,state="open"}` — webhook
  receiver is unhealthy; the breaker is short-circuiting deliveries
  (T8-04).

## Security metrics

| Metric | Alert trigger |
|---|---|
| `mcpg_wasm_plugin_error_deny_total{plugin_id} > 0` | A Wasm gate plugin is crashing. **Page**. |
| `mcpg_admin_trusted_header_insecure_total > 0` | Admin API in legacy presence-only mode. **Fix config**. |
| `mcpg_native_plugin_timeout_total{plugin_id} > 0` | Native plugin hung for >30s. **Investigate**. |
| `mcpg_sse_stream_limit_rejected_total{session_id}` | Client hitting SSE cap (3). Likely reconnect loop. |
| `mcpg_infra_no_auth_warning_total{backend} > 0` | Plaintext NATS/Redis on non-loopback. **Investigate deployment**. |
