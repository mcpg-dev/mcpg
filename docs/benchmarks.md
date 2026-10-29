# Benchmarks

The measured figures of the current build are on the benchmarks page,
[mcpg.dev/docs/operations/benchmarks](https://mcpg.dev/docs/operations/benchmarks):
tool calls on one gateway and on NATS and Redis fleets, sessions,
notifications, watches, limits, MCP Events, the coordinator store, the plugin
boundary, request costs, memory and threads, and how to size a deployment from
them.

This file names the gateway's own bench suites and how to run them.

## Request costs (criterion)

| Bench | What it measures |
|---|---|
| `benches/protocol_parse.rs` | `parse_client_message` and `map_client_message_to_operation` on realistic JSON-RPC payloads |
| `benches/uri_normalize.rs` | `normalize_resource_uri` on HTTP URLs, custom schemes, long paths and edge cases |
| `benches/redactor.rs` | `redact_credentials` on payloads of several sizes and depths |
| `benches/plugin_chain.rs` | the in-process gate chain with 0, 1, 3 and 5 gates (no plugin boundary) |

```sh
cargo bench -p mcpg                          # all four
cargo bench -p mcpg --bench protocol_parse   # one
```

## End to end over HTTP (`#[ignore]`d, release)

Each test starts a gateway with mock bindings and drives it over HTTP.

| Test | What it measures |
|---|---|
| `tests/bench_load.rs` | sustained `tools/call` load: throughput, latency, memory growth and session leaks; `bench_sustained_load_high` runs 250, 500 and 1 000 sessions (`BENCH_MAX_SESSIONS` caps the tiers) |
| `tests/bench_gateway.rs` | the full session lifecycle from 1 to 500 clients, `tools/list` throughput, the time of one session |
| `tests/bench_plugins.rs` | what plugins, the debug tools and the number of bindings cost at 100 sessions |
| `tests/bench_backend_latency.rs` | throughput and latency when the backend takes 0 to 500 ms, at 10, 50 and 100 sessions |
| `tests/bench_backends.rs` | the HTTP, GraphQL and command backends against a local upstream; gate costs; `bench_memory`: memory per session, idle memory and memory after a drain, against ceilings |
| `tests/bench_pipeline.rs` | the cost of each request-pipeline stage, of idempotency, of an out-of-process plugin, and the throughput ceiling |

```sh
cargo test -p mcpg --release --test bench_load -- --ignored --nocapture
cargo test -p mcpg --release --test bench_backends bench_memory -- --ignored --nocapture
```

The plugin boundary has its own suites in the `mcpg-plugin-host` crate:
`benches/ffi_roundtrip.rs` and `benches/ffi_matrix.rs` (criterion),
`benches/ffi_roundtrip_iai.rs` (instruction counts) and `benches/ffi_alloc.rs`
(allocations per call), against the no-op cdylib fixture `bench-noop`.
