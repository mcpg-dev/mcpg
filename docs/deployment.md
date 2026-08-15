# MCPG Deployment Guide

> Docker images, Kubernetes via Helm, deployment topologies, and operational guidance.
> Source: `Dockerfile`, `helm/charts/mcpg/`

## Deployment Topologies

MCPG supports two deployment topologies that share the same binary and configuration format:

| Topology | State Backend | Delivery Bus | Use Case |
|----------|---------------|--------------|----------|
| **Single-instance** | Memory or file | In-process | Development, low-traffic, edge |
| **Multi-instance** | NATS KV or Redis | NATS or Redis pub/sub | Production HA, horizontal scaling |

The delivery bus is selected automatically at startup:
1. If NATS is enabled → NATS pub/sub
2. If Redis is configured → Redis pub/sub
3. Otherwise → in-process broadcast (single-instance only)

**Why multi-instance requires a distributed backend:**
Server-initiated messages (elicitation requests, sampling requests, deferred pipeline results) are emitted by the instance executing the pipeline. The SSE stream to the client may be held by a different instance behind a load balancer. The delivery bus routes these messages across instances. Without NATS or Redis, the message stays local and the pipeline hangs.

---

## Docker

### Building the Image

The Dockerfile is at `apps/gateway/Dockerfile`. Build from the repository root (the workspace root is the build context):

```bash
# Standard build
docker build -t mcpg:latest -f apps/gateway/Dockerfile .

# With WASM plugin support
docker build --build-arg FEATURES="wasm-plugins" -t mcpg:latest -f apps/gateway/Dockerfile .

# Specific Rust version
docker build --build-arg RUST_VERSION=1.86 -t mcpg:latest -f apps/gateway/Dockerfile .
```

### Build Arguments

| ARG | Default | Description |
|-----|---------|-------------|
| `RUST_VERSION` | `1.86` | Rust compiler version for the builder stage |
| `FEATURES` | `""` | Cargo features (e.g., `wasm-plugins`) |
| `PROFILE` | `release` | Cargo build profile (`release` or `dev`) |

### Image Details

| Property | Value |
|----------|-------|
| Base image | `debian:bookworm-slim` |
| User | `mcpg` (non-root, UID dynamically assigned) |
| Config path | `/etc/mcpg/config.yaml` |
| Data directory | `/var/lib/mcpg/` |
| Plugin directory | `/var/lib/mcpg/plugins/` |
| PID 1 | `tini` (signal forwarding, zombie reaping) |
| TLS library | rustls (no OpenSSL — `ca-certificates` package provides root CAs) |
| Exposed port | `8787` |

### Running with Docker

```bash
# Minimal — in-memory store, single instance
docker run -p 8787:8787 \
  -v $(pwd)/config.yaml:/etc/mcpg/config.yaml:ro \
  mcpg:latest

# With environment overrides
docker run -p 8787:8787 \
  -e MCPG_OBSERVABILITY__LOGS__LEVEL=debug \
  -e MCPG_GATEWAY__SERVER__BIND_ADDRESS=0.0.0.0:8787 \
  -v $(pwd)/config.yaml:/etc/mcpg/config.yaml:ro \
  mcpg:latest

# With TLS
docker run -p 8787:8787 \
  -v $(pwd)/config.yaml:/etc/mcpg/config.yaml:ro \
  -v $(pwd)/certs:/etc/mcpg/tls:ro \
  mcpg:latest

# With file-backed sessions (persistent across restarts)
docker run -p 8787:8787 \
  -v $(pwd)/config.yaml:/etc/mcpg/config.yaml:ro \
  -v mcpg-data:/var/lib/mcpg \
  mcpg:latest
```

### Docker Compose — Multi-Instance with NATS

```yaml
services:
  nats:
    image: nats:2-alpine
    command: ["--jetstream", "--store_dir=/data"]
    volumes:
      - nats-data:/data
    ports:
      - "4222:4222"

  mcpg:
    image: mcpg:latest
    deploy:
      replicas: 3
    ports:
      - "8787:8787"
    volumes:
      - ./config.yaml:/etc/mcpg/config.yaml:ro
    environment:
      MCPG_CLUSTER__KIND: "nats"
      MCPG_CLUSTER__URL: "nats://nats:4222"
      # Session/pipeline/task stores default to `kind: cluster`, so they
      # automatically use the NATS backend — no separate store env vars.
    depends_on:
      - nats

volumes:
  nats-data:
```

### Docker Compose — Multi-Instance with Redis

```yaml
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"

  mcpg:
    image: mcpg:latest
    deploy:
      replicas: 3
    ports:
      - "8787:8787"
    volumes:
      - ./config.yaml:/etc/mcpg/config.yaml:ro
    environment:
      MCPG_CLUSTER__KIND: "redis"
      MCPG_CLUSTER__URL: "redis://redis:6379"
      # Stores inherit the cluster backend (`kind: cluster`) by default.
    depends_on:
      - redis

volumes:
  redis-data:
```

---

## Kubernetes via Helm

Full chart documentation: [Kubernetes install with Helm](https://mcpg.dev/docs/self-hosting/k8s-install).

### Quick Start

```bash
# Build chart dependencies
cd helm/charts/mcpg && helm dependency build

# Install — single instance
helm install mcpg ./helm/charts/mcpg

# Install — HA with bundled NATS
helm install mcpg ./helm/charts/mcpg \
  --set replicaCount=3 \
  --set nats.enabled=true \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=true
```

### What the Chart Deploys

| Resource | Always | Conditional |
|----------|--------|-------------|
| Deployment | yes | |
| Service (ClusterIP) | yes | |
| ConfigMap (config.yaml) | yes | |
| ServiceAccount | yes | `serviceAccount.create` |
| Ingress | | `ingress.enabled` |
| HPA | | `autoscaling.enabled` |
| PDB | | `podDisruptionBudget.enabled` |
| NetworkPolicy | | `networkPolicy.enabled` |
| PVC | | `persistence.enabled` |
| TLS Secret | | `tls.enabled` + inline certs |
| ServiceMonitor | | `metrics.serviceMonitor.enabled` |
| PrometheusRule | | `metrics.prometheusRule.enabled` |
| NATS (subchart) | | `nats.enabled` |
| Redis (subchart) | | `redis.enabled` |

### Backend Auto-Wiring

When NATS or Redis is available (bundled or external), the chart automatically:

1. Auto-renders the top-level `cluster:` block — `cluster.kind: nats | redis`
   with the correct service URL. Every capability (sessions / pipelines /
   tasks / subscriptions / delivery / cancellation) inherits this connection
   per Phase 6c-10's cluster-primitive inheritance.
2. Allows egress to the backend pods in the NetworkPolicy.
3. Injects Redis password from Kubernetes Secrets via environment variable.

**Priority**: NATS > Redis > memory (single-node default).

Per-capability overrides (memory / file only, post-6c-10) go under
`extraConfig.{sessions,pipelines,tasks,subscriptions,delivery,cancellation}`.
The pre-6c-10 `storeBackend.*` knobs that drove redis / nats per-cap
overrides are gone — operators wanting cross-replica state for a specific
capability set `cluster.kind` once.

### Configuration Injection

MCPG configuration flows through three layers:

```
values.yaml: config.*         ← Base application config
          ↓
configmap template            ← Auto-wires nats/redis/store sections
          ↓
values.yaml: extraConfig.*    ← Force-override escape hatch (deepmerge)
          ↓
/etc/mcpg/config.yaml         ← Mounted into container
          ↓
MCPG_* environment variables  ← Runtime overrides (figment)
```

A config checksum annotation on the pod template triggers a rolling restart whenever the ConfigMap changes.

### Ingress Considerations

MCPG uses SSE (Server-Sent Events) for streaming. Configure your ingress controller to support long-lived connections:

**Nginx:**
```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
```

**AWS ALB:**
```yaml
ingress:
  annotations:
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/idle-timeout: "3600"
```

**GCE:**
```yaml
ingress:
  annotations:
    cloud.google.com/backend-config: '{"default": "mcpg-backend-config"}'
    # Create a BackendConfig with timeoutSec: 3600
```

### Secrets Management

Sensitive values (payment keys, OIDC secrets, API tokens) should not be placed in the ConfigMap. Use environment variable injection:

```yaml
extraEnv:
  - name: MPP_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: mcpg-secrets
        key: mpp-secret-key
  - name: MCPG_AUTH__OIDC_OAUTH__PROVIDERS__0__VERIFICATION__CLIENT_SECRET_REF
    value: "env:INTROSPECTION_SECRET"
  - name: INTROSPECTION_SECRET
    valueFrom:
      secretKeyRef:
        name: mcpg-secrets
        key: introspection-secret

# Or inject all secrets from a single Secret
extraEnvFrom:
  - secretRef:
      name: mcpg-env-secrets
```

---

## Health Checks

MCPG exposes three probe endpoints:

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `GET /health` | Liveness — process is alive | 200 with backend health status |
| `GET /ready` | Readiness — accepting traffic | 200 when operational |
| `GET /metrics` | Prometheus metrics | Prometheus text format |

The Helm chart configures all three probes with sensible defaults. The startup probe allows up to 60 seconds (12 attempts × 5s) for initial bootstrap.

---

## Monitoring

### Prometheus Metrics

Enable metrics in the mcpg config and (optionally) create a ServiceMonitor:

```yaml
config:
  observability:
    metrics:
      enabled: true
      sinks:
        - kind: prometheus
          config:
            path: /metrics

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s
```

Key metrics to monitor:

| Metric | Type | Description |
|--------|------|-------------|
| `mcpg_requests_total` | Counter | Total requests by operation and transport |
| `mcpg_request_duration_seconds` | Histogram | Request latency |
| `mcpg_active_sessions` | Gauge | Current active sessions |
| `mcpg_binding_executions_total` | Counter | Binding executions by name, type, and outcome |
| `mcpg_binding_execution_duration_seconds` | Histogram | Binding execution latency |
| `mcpg_policy_evaluations_total` | Counter | Policy decisions by outcome and reason |
| `mcpg_nats_connected` | Gauge | NATS connection state (0/1) |

### OpenTelemetry Tracing

```yaml
config:
  observability:
    traces:
      enabled: true
      service_name: mcpg
      propagate_context: true
      sinks:
        - kind: otlp
          config:
            url: "http://otel-collector:4317"
```

MCPG exports spans via gRPC OTLP and propagates W3C Trace Context headers.

### Recommended Alerts

```yaml
metrics:
  prometheusRule:
    enabled: true
    rules:
      - alert: McpgDown
        expr: up{job="mcpg"} == 0
        for: 1m
        labels:
          severity: critical

      - alert: McpgHighErrorRate
        expr: >
          rate(mcpg_binding_executions_total{outcome="error"}[5m])
          / rate(mcpg_binding_executions_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning

      - alert: McpgHighLatency
        expr: >
          histogram_quantile(0.99,
            rate(mcpg_request_duration_seconds_bucket[5m])
          ) > 5
        for: 5m
        labels:
          severity: warning

      - alert: McpgSessionsNearLimit
        expr: mcpg_active_sessions > 8000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Approaching 10,000 session limit"

      - alert: McpgNatsDisconnected
        expr: mcpg_nats_connected == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "NATS connection lost — delivery bus and KV stores are unavailable"
```

---

## Security Hardening Checklist

- [ ] Run as non-root (default in Helm chart: UID 65534)
- [ ] Read-only root filesystem (default: `true`)
- [ ] Drop all capabilities (default: `ALL`)
- [ ] Seccomp profile RuntimeDefault (default: `true`)
- [ ] Enable NetworkPolicy to restrict ingress/egress
- [ ] Use TLS for ingress (cert-manager or existing Secret)
- [ ] Use `rediss://` (TLS) for Redis connections in production
- [ ] Use `tls://` for NATS connections in production
- [ ] Mount NATS credentials from Secrets, not inline config
- [ ] Inject sensitive env vars from Kubernetes Secrets
- [ ] Set `policy.tool_access.default_minimum_trust: verified`
- [ ] Enable OIDC/OAuth authentication
- [ ] Set `ServiceAccount.automountServiceAccountToken: false` (default)
- [ ] Apply Pod Disruption Budget for rolling updates
- [ ] Spread pods across zones via topology constraints
