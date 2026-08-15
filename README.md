# MCPG — Model Context Protocol Gateway

MCPG is a protocol-authority gateway for the [Model Context Protocol](https://spec.modelcontextprotocol.io/). It sits between MCP clients and downstream backend systems, owning protocol handling, session lifecycle, identity, authorization, execution dispatch, and observability.

**Production-grade Rust · extensive unit + integration + MCP-conformance coverage · implements MCP `2026-07-28` and `2025-11-25` (both CI-conformance-gated; legacy `2025-06-18` / `2025-03-26` accepted on request)**

> **Build an MCP server with MCPG:** see
> [`docs/agent-authoring-guide.md`](docs/agent-authoring-guide.md)
> for the AI-agent authoring procedure, and
> [`docs/mcp-server-ideas.md`](docs/mcp-server-ideas.md) for 25
> concrete systems worth wrapping (name.com, Cloudflare, GitHub,
> Stripe, iPhone Simulator, and more) — each with a runnable sample
> under [`examples/`](examples/).
>
> **Compliance status:** start at
> [`docs/compliance/mcp-compliance.md`](docs/compliance/mcp-compliance.md)
> for the canonical reference. The supported-feature matrix is at
> [`docs/compliance/compliance-support.md`](docs/compliance/compliance-support.md);
> operator knobs and metrics are documented in
> [`docs/configuration.md`](docs/configuration.md) and
> [`docs/observability.md`](docs/observability.md). Doc index:
> [`docs/README.md`](docs/README.md).

## What MCPG Does

- Speaks **MCP over Streamable HTTP with SSE streaming** — the finalized **`2026-07-28`** revision (stateless, header-routed) and the session-based **`2025-11-25`** default; the server always emits `2026-07-28` as its wire string and accepts the legacy `2025-06-18` / `2025-03-26` revisions when a client requests them
- Routes tool calls, prompt gets, and resource reads to **operator-defined backends**
- Enforces **pre-dispatch authorization** with trust levels and CEL expressions
- Resolves identity via **JWKS, OIDC/OAuth (multi-provider)**, or header assertion
- Orchestrates **multi-step pipelines** with client interaction (elicitation, sampling)
- Supports **MCP Tasks** — task-augmented tool calls with background execution, polling, cancellation, and result retrieval
- Distributes state across **NATS, Redis, or in-process** backends per capability (activated via per-capability `<capability>.store` / `<bus>.bus` overrides)
- Manages **outbound credentials** (OAuth 2.0 client_credentials, Vault dynamic DB, static) via the `credential_issuer` plugin family — backends reference issued values through `cred://<plugin_id>/<target>` URIs, with cached, auto-refreshed tokens
- Surfaces **MCP App URLs** (`_meta.mcpAppUrl`) on resource descriptors with CEL interpolation
- Delivers **subject-scoped resource notifications** with 4 filter scopes (all, subject, session, expression)
- Extends via **async plugin system** — dual-tier (Native + Wasm) tool-gate, transform, and identity chains
- Enforces **external guardrails** via HTTP webhook callouts with CEL triggers and fail-open/fail-closed policies
- Gates tool calls via **Machine Payment Protocol** with HMAC-bound challenges
- Emits **Prometheus metrics** and **OpenTelemetry traces**

## Backends

Backends are cdylib **plugins** — the gateway binary hard-wires none. The
catalog ships **32 backend and connector plugins**; a caller selects one
per capability via a nested `backend.kind:` discriminator. Common kinds:

| Kind | Transport |
|---|---|
| `http` | HTTP POST/GET to downstream endpoints |
| `command` | Local subprocess execution |
| `nats` / `kafka` / `amqp` | Messaging (request/reply, pub/sub) |
| `grpc` | gRPC via proto-less JSON mapping |
| `graphql` / `soap` | GraphQL query/mutation, SOAP |
| `sql` | SQL + warehouse databases (Postgres, MySQL, Snowflake, BigQuery, ClickHouse, DuckDB, Oracle, …) |
| `ldap` / `dynamodb` / `email` / `sftp` | Directory, key-value, mail, file transfer |
| `openapi` | OpenAPI spec → generated tools |
| `mock` | Static fixture response |
| `pipeline` | Multi-step orchestration (11 step types) |
| LLM/media family | 17 kinds — OpenAI, Azure OpenAI, Anthropic, Gemini, Stability, and OpenAI-compatible chat/embedding/image/TTS/STT |

Full reference: [docs/backends.md](docs/backends.md).

## Quick Start

```bash
# Build
cargo build

# Test
cargo test

# Run
MCPG_CONFIG=config.example.yaml cargo run
```

## Docker & Kubernetes

```bash
# Build Docker image (from repo root)
docker build -t mcpg:latest -f apps/gateway/Dockerfile .

# Run single instance
docker run -p 8787:8787 -v $(pwd)/config.yaml:/etc/mcpg/config.yaml:ro mcpg:latest

# Deploy to Kubernetes via Helm (single instance)
helm install mcpg ./helm/charts/mcpg

# Deploy HA with NATS backend (multi-instance)
helm install mcpg ./helm/charts/mcpg \
  --set replicaCount=3 \
  --set nats.enabled=true \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=true
```

Full deployment guide: [docs/deployment.md](docs/deployment.md). Helm chart reference: [Kubernetes install with Helm](https://mcpg.dev/docs/self-hosting/k8s-install).

## Configuration

See `config.example.yaml` for a working configuration. Full reference: [docs/configuration.md](docs/configuration.md).

```yaml
server:
  bind_address: "127.0.0.1:8787"
observability:
  logs:
    level: "info"
    sinks:
      - kind: stderr
        config: { format: json }
mcp:
  capabilities:
    tools:
      - name: "my_tool"
        description: "Example HTTP backend"
        backend:
          kind: http
          url: "https://api.example.com/endpoint"
          method: post
          timeout_ms: 5000
```

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System architecture, module structure, request flow |
| [docs/request-flow.md](docs/request-flow.md) | Complete request lifecycle, all routes, plugin extension points |
| [docs/configuration.md](docs/configuration.md) | Complete configuration reference |
| [docs/backends.md](docs/backends.md) | Backend kinds and connector plugins with examples |
| [docs/pipelines.md](docs/pipelines.md) | Pipeline execution, 11 step types, suspension/resumption |
| [docs/identity-and-authorization.md](docs/identity-and-authorization.md) | JWKS, OIDC/OAuth, trust levels, CEL policy |
| [docs/infrastructure.md](docs/infrastructure.md) | Session stores, delivery buses, pipeline stores |
| [docs/observability.md](docs/observability.md) | Logging, Prometheus metrics, OpenTelemetry |
| [docs/api-reference.md](docs/api-reference.md) | HTTP endpoints, MCP operations, SSE protocol |
| [docs/deployment.md](docs/deployment.md) | Docker, Kubernetes/Helm, deployment topologies |
| [docs/plugins.md](docs/plugins.md) | Plugin system: traits, registry, Wasm, config |
| [Kubernetes install with Helm](https://mcpg.dev/docs/self-hosting/k8s-install) | Helm chart reference — parameters, examples, architecture |

## Architecture at a Glance

```
MCP Client
    │
    ▼
HTTP Transport ──→ Identity Resolution ──→ Gateway Runtime ──→ Plugin Chain ──→ Backend Execution
    │                (OIDC/JWKS/Plugin)           │           (gate/transform)   (backend plugins)
    │                                            │
    ├── SSE Streaming                    Session Management
    │   (replay window)                  (4 store backends)
    │
    └── Prometheus + OpenTelemetry
```

### Plugin System Crates

```
libs/
├── plugin-protocol/  — Trait contracts + FFI ABI types (ToolGatePlugin, BackendPlugin, etc.)
├── plugin-host/      — Registry, chain evaluation, Wasm hosting, artifact verification
├── plugin-sdk/       — SDK for building plugins (testing helpers, MockGateway)
├── sdk/              — `mcpg-sdk` umbrella crate plugin authors depend on
└── plugins/          — the production catalog: 92 shipping plugins across 14
                        categories (backend, security, identity, transform,
                        observability, payment, credential, …), cdylib + a few Wasm
```

## Design Decisions

Key architectural decisions:

- **ADR-0001**: Single-deployment, backend-driven runtime (no multi-tenancy)
- **ADR-0004**: Canonical backend execution contract (gateway as protocol authority)
- **ADR-0005**: Multi-node lease fencing with CAS semantics
- **ADR-0007**: OIDC/OAuth multi-provider authentication

## License

The gateway core is **Apache-2.0** (see [LICENSE](./LICENSE)).
Enterprise plugins and the fleet platform (Kubernetes operator, control
plane) ship under **BUSL-1.1**, each release auto-converting to Apache-2.0
three years later. To license production use of the BUSL-1.1 components,
email **agent@mcpg.dev** or use the managed service at **mcpg.cloud**. The
canonical component map is at [mcpg.dev/license](https://mcpg.dev/license).

Backend governance integrates with the policy layer. Each backend's `minimum_trust` and `allow_if` are injected as per-tool policy rules at startup. CEL expressions are compiled and validated during bootstrap.

### Debug Tools

The debug capability model is intentionally narrow:

- the top-level `debug.enabled: true` gate must be set before any debug capabilities exist
- command probes, network probes, and the debug HTTP JSON call use named execution profiles (under `debug.tools.command_profiles` / `debug.tools.network_profiles`) with bounded timeout and size limits
- built-in debug tools, prompt, and resource capabilities can be exposed or hidden independently via `debug.tools.exposure.*`
- debug tools emit structured logs with `backend_kind: debug_tool` to distinguish from operator backends

### Execution Contract

All downstream execution paths produce structured result envelopes with:

- tool name, profile, and request kind classification
- request and response details
- structured error objects with category, retry hints, idempotency, and suggested actions
- execution duration, status codes, and truncation indicators

Execution logs include `backend_kind` (`operator_backend` or `debug_tool`) on all call sites.

