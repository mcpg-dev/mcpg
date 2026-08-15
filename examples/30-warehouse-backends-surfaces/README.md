# 30 — Warehouse backends across MCP surfaces (P2(a) annotation defaults)

An MCP server that exposes a single warehouse backend (`duckdb`) across
three MCP surfaces — **tool**, **resource**, and **pipeline step** — and
ships the read-only / open-world annotation defaults operators should set
on read-only warehouse bindings. Zero code: every capability here is config.

The same shape applies to the other warehouse backends
(`bigquery` / `snowflake` / `oracle` / `dynamodb` / `elasticsearch`); DuckDB
is used here because it needs no external service or credentials and runs
fully in-memory.

## Run

```bash
cargo run -p mcpg -- --config examples/30-warehouse-backends-surfaces/config.yaml
```

(The DuckDB plugin artifact must be loadable for the bindings to dispatch;
the gateway resolves it from the `plugins:` entry. `mcpg-config check`
validates the config shape without loading the plugin.)

## Exposed surfaces

| Kind | Name / URI | Purpose |
|---|---|---|
| tool | `warehouse.region_revenue` | Read-only region-revenue query, `annotations: { read_only, open_world: false }` |
| tool (pipeline) | `warehouse.top_region` | `duckdb` step feeding a `transform` step |
| resource | `warehouse.regions` → `duckdb://warehouse/regions` | Same backend with `surface: resource` → `{contents:[…]}` |

## What to notice

- **Annotation defaults (P2(a)).** Every read-only binding carries
  `annotations: { read_only: true, open_world: false }`. This is the
  zero-code path to surfacing `readOnlyHint` / `openWorldHint` to clients —
  the warehouse plugins enforce read-only internally, but the hint has to be
  set in config until/unless a plugin trait default lands.
- **The pipeline step discriminator is `duckdb`** — the same tag as the
  top-level binding and the registry/dispatch kind resolved at runtime. (The
  other warehouses follow suit: `bigquery`, `oracle`, `snowflake`, `dynamodb`,
  `elasticsearch` — the step tag and the dispatch kind are identical.) Step
  config fields are flattened next to `id` / `kind`, and `input_transform`
  shapes the step input from prior steps.
- **`surface: resource`** makes the binding emit the `resources/read`
  `{contents:[…]}` body instead of the tool envelope. A static `uri:` on the
  backend is emitted verbatim on the content entry; omit it to use the URI
  the client requested.
- **Child tools.** With `governance.child_invoke.enforce_gates: true`, a
  read-only warehouse binding can also be invoked as a child tool by an
  LLM / generator binding — child calls run the policy + tool-gate chains and
  are bounded by the depth cap and self-call cycle refusal. (No LLM binding is
  declared here to keep the example credential-free.)
