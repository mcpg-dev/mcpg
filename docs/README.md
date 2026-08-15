# MCPG Documentation

This folder is the canonical home for everything written about MCPG.
Public/operator-facing docs live at the top level; subsystem guides live
in subdirectories; compliance evidence lives under
[`compliance/`](compliance/).

## Public documentation (operator + integrator audience)

| Document | Audience | What it covers |
|---|---|---|
| [`../README.md`](../README.md) | Everyone | Project overview + status |
| [`architecture.md`](architecture.md) | Operator, integrator | High-level architecture, components, request flow |
| [`request-flow.md`](request-flow.md) | Integrator | End-to-end MCP request handling diagrams |
| [`configuration.md`](configuration.md) | Operator | Every config knob, env var, and metric (OAuth providers, MCP App URLs, notification filters, feature gates) |
| [`configuration-intro.md`](https://github.com/mcpg-dev/mcpg-config/blob/main/docs/configuration-intro.md) | Operator | Curated preamble prepended to `configuration.md` by the `mcpg config doc` generator — quick-start, top-level key layout, env-var prefixes. Lives with the `mcpg-config` crate (`apps/config`), which generates this folder's `configuration.md` |
| [`string-interpolation.md`](string-interpolation.md) | Operator, integrator | The `${…}` interpolation grammar — env, arguments, credential, and CEL substitution |
| [`feature-flags.md`](feature-flags.md) | Operator | The `feature_flags:` block — opt-in runtime toggles and their effects |
| [`backends.md`](backends.md) | Integrator | All 27 backend kinds (10 general-purpose + 17 LLM) and their config |
| [`pipelines.md`](pipelines.md) | Integrator | Multi-step pipeline orchestration (18 step kinds) |
| [`pipeline-performance.md`](pipeline-performance.md) | Operator, SRE | Pipeline execution performance — bottleneck analysis and tuning |
| [`identity-and-authorization.md`](identity-and-authorization.md) | Operator, security | OIDC/OAuth, JWKS, audience binding, scope guidance |
| [`per-caller-credentials.md`](per-caller-credentials.md) | Operator, security | Per-caller `cred://` credential resolution and issuer plugins |
| [`payment.md`](payment.md) | Integrator | Machine Payment Protocol (x402, MPP, ACP, UCP) |
| [`guardrails.md`](guardrails.md) | Operator | Guardrails plugin and external policy gates |
| [`plugins.md`](plugins.md) | Plugin author | Plugin system overview (native + Wasm + dynamic loading) |
| [`api-reference.md`](api-reference.md) | Integrator | MCP API surface MCPG implements |
| [`observability.md`](observability.md) | Operator, SRE | Metrics, traces, logs, alerting |
| [`audit.md`](audit.md) | Operator, security, auditor | Tamper-evident compliance audit channel — event taxonomy, sink architecture, SOC2/HIPAA/PCI-DSS/GDPR/ISO 27001 recipes |
| [`infrastructure.md`](infrastructure.md) | Operator | Cluster topology, NATS/Redis, deployment model |
| [`hot-reload.md`](hot-reload.md) | Operator | Which config changes apply on hot-reload vs require a restart |
| [`deployment.md`](deployment.md) | Operator, SRE | Docker, Kubernetes/Helm, deployment topologies, security checklist |
| [`benchmarks.md`](benchmarks.md) | Operator, SRE | Performance benchmarks — throughput, latency, memory, concurrency (1-1000 sessions) |
| [Kubernetes install with Helm](https://mcpg.dev/docs/self-hosting/k8s-install) | Operator, SRE | Helm chart parameters, examples, architecture |
| [`agent-authoring-guide.md`](agent-authoring-guide.md) | AI agent, integrator | How to turn any API or CLI into an MCP server using MCPG — primitives, binding skeletons, worked examples (name.com DNS, iPhone Simulator), authoring procedure |
| [`mcp-server-ideas.md`](mcp-server-ideas.md) | Agent, integrator, builder | Catalogue of the shipped `examples/` MCP servers across web/hosting, dev productivity, infra/ops, comms, commerce, consumer productivity, and SQL/warehouse backends — each entry links its runnable example and lists upstream, bindings, and complexity |

## Subsystem guides

| Guide | Audience | What it covers |
|---|---|---|
| [`federation/`](federation/) | Operator, integrator | MCP federation — the [operator guide](federation/guide.md) plus the [design & status page](federation/README.md) |
| [`sql/`](sql/) | Integrator | SQL backend [cookbook](sql/cookbook.md), [migration guide](sql/migration.md), and [troubleshooting](sql/troubleshooting.md) |
| [`observability/`](observability/) | Operator, SRE | Observability operator references and a sink-redirection example |

## Compliance evidence

| Document | Purpose |
|---|---|
| [`compliance/mcp-compliance.md`](compliance/mcp-compliance.md) | Canonical compliance reference — start here |
| [`compliance/compliance-support.md`](compliance/compliance-support.md) | Supported-feature matrix (live, falsifiable) |
