# MCPG Benchmark Results

> 📈 **For the 2026-05-26 pipeline bottleneck investigation** (HTTP
> end-to-end benches, the tool-gate throughput collapse, its root cause —
> a per-event audit `fsync` — and the group-commit fix that restored gated
> throughput to ~92 % of baseline), see
> [`pipeline-performance.md`](pipeline-performance.md).

> ⚠️ **Read this first (2026-05).** Sections 1–18 below were measured
> **2026-04-15, before the backend-plugin migration**, and they exercise the
> gateway's **FFI-free path**: the integration benches dispatch through an
> **in-process `Arc<MockBackendPlugin>`** trait object — they never `dlopen` a
> plugin or cross the cdylib vtable. So "gateway overhead" here is the gateway's
> internal request machinery, **not** the plugin FFI boundary the migration made
> the dominant per-call cost. The real plugin-FFI numbers (and the measurement
> of that boundary) are in **§19** and `libs/plugin-host/benches/ffi_{roundtrip,matrix}.rs`.
> A few §1–18 entries reference benches since removed (the in-gateway rate
> limiter became the `dev.mcpg.rate-limit` plugin); those are flagged inline.

> **Date:** 2026-04-15 (§1–18, pre-migration); 2026-05 (§19, current).
> **Commit:** `8bcbd70` (§1–18, pre-migration).
> **Build:** dev profile for sections 1-15; release profile for section 16.
> **Profile:** unoptimized + debuginfo for dev; optimized for release.

## Test Environment

| | |
|---|---|
| **CPU** | 16 vCPU, Common KVM processor (x86_64) |
| **Memory** | 64 GB |
| **Kernel** | Linux 6.1.0-42-cloud-amd64 |
| **Rust** | 1.94.1 (2026-03-25) |
| **Tokio** | multi-thread, 8 worker threads (integration tests) |
| **Backend** | Mock bindings (0 ms delay) — measures pure gateway overhead |
| **Auth** | Disabled (benchmark isolation) |
| **Store** | In-memory session store |
| **Plugins** | None (except where noted in plugin-chain benchmarks) |

## Methodology

### Microbenchmarks (Criterion)

Located in `apps/gateway/benches/`. Each benchmark uses Criterion's
statistical engine with 100+ iterations and confidence intervals.
Measures the isolated cost of a single operation without network I/O.

```bash
cargo bench -p mcpg
```

### Integration benchmarks

Located in `apps/gateway/tests/bench_gateway.rs` and `bench_load.rs`.
Start a live MCPG instance with mock bindings, connect N concurrent
HTTP clients via reqwest, and measure end-to-end latency including
full JSON-RPC parsing, session lookup, plugin chain, and HTTP
response serialization.

```bash
cargo test -p mcpg --test bench_gateway -- --ignored --nocapture
cargo test -p mcpg --test bench_load -- --ignored --nocapture
```

---

## 1. Protocol Parsing

Single-threaded cost of parsing a JSON-RPC message and routing it to
a `ProtocolOperation` variant.

| Operation | Latency | Notes |
|---|---|---|
| `tools/list` | **788 ns** | Simplest — no arguments |
| `prompts/list` | 741 ns | |
| `resources/list` | 776 ns | |
| `notifications/cancelled` | 1.50 µs | |
| `initialize` | 3.15 µs | Full capability negotiation |
| `tools/call` (small args) | 3.68 µs | Typed argument struct |
| `tools/call` (10 KB args) | 3.40 µs | Serde overhead is struct shape, not payload size |

**Takeaway:** list operations parse in < 1 µs. Even the heaviest
operation (initialize with full capabilities) is < 4 µs.

---

## 2. Rate Limiter

> **Removed.** The in-gateway token-bucket rate limiter was extracted to the
> `dev.mcpg.rate-limit` tool-gate plugin; this microbench and `rate_limiter.rs`
> no longer exist. Numbers below are historical (pre-migration).

Per-call overhead of the in-memory token-bucket rate limiter.

| Scenario | Latency |
|---|---|
| Disabled (noop) | **4.9 ns** |
| Single thread, enabled | **214 ns** |
| With glob pattern rules | 231 ns |
| Deny path (bucket exhausted) | 222 ns |
| 4 threads contended | ~640 ns/call amortized |

**Takeaway:** < 5 ns when disabled. ~210 ns when enabled — negligible
compared to any network round-trip.

---

## 3. Plugin Mediation Chain

Cost of evaluating the tool-gate plugin chain with N noop plugins.

| Chain depth | Total | Per-plugin |
|---|---|---|
| 0 plugins | 313 ns | — (baseline: tokio overhead) |
| 1 plugin | 544 ns | **~231 ns** |
| 3 plugins | 993 ns | ~227 ns |
| 5 plugins | 1.44 µs | ~225 ns |

**Takeaway:** linear scaling at ~225 ns/plugin. Even a 10-plugin chain
adds only ~2.3 µs.

---

## 4. URI Normalization

Per-lookup cost of RFC 3986 normalization for resource matching.

| URI shape | Latency |
|---|---|
| `https://example.com/foo` | 663 ns |
| `https://example.com:443/foo` (default port strip) | 601 ns |
| `mcp://server/path` (custom scheme) | 478 ns |
| `urn:isbn:1234567890` | 400 ns |
| 50-segment long path | 2.94 µs |
| Mixed-case host normalization | 898 ns |

---

## 5. Credential Redactor

Cost of scrubbing credential-shaped fields from JSON payloads
(applied to every `notifications/message` emission).

| Payload | Latency |
|---|---|
| Small clean (no credentials) | 517 ns |
| Small with sensitive key | 334 ns |
| Medium nested (5 objects) | 1.66 µs |
| Large (20 events, ~50 credential fields) | **35.7 µs** |
| Deeply nested (10 levels) | 2.71 µs |
| JWT detection (50 strings) | 7.43 µs |

---

## 6. Cursor HMAC

Round-trip cost of HMAC-SHA256 cursor encoding + decoding with
session binding.

| Operation | Latency |
|---|---|
| `encode_cursor` | ~350 ns |
| `decode_cursor` (valid MAC) | ~380 ns |
| `decode_cursor` (invalid MAC) | ~370 ns |

---

## 7. Gateway Throughput — Concurrent Lifecycle

Full MCP lifecycle per client: `initialize` → `tools/list` →
`tools/call` ×10 → `DELETE`. Measured at varying concurrency levels.

| Concurrent clients | req/sec | p50 | p95 | p99 | max | errors |
|---|---|---|---|---|---|---|
| 1 | **1,099** | 784 µs | 1.1 ms | 1.1 ms | 1.1 ms | 0 |
| 5 | **1,364** | 3.6 ms | 3.9 ms | 4.1 ms | 4.1 ms | 0 |
| 10 | **1,404** | 6.4 ms | 7.3 ms | 7.9 ms | 8.1 ms | 0 |
| 25 | **1,224** | 14.4 ms | 18.0 ms | 53.7 ms | 54.1 ms | 0 |
| 50 | **1,316** | 28.0 ms | 39.2 ms | 63.5 ms | 64.0 ms | 0 |
| 100 | **1,300** | 66.6 ms | 81.2 ms | 118 ms | 119 ms | 0 |
| 250 | **1,224** | 155 ms | 185 ms | 200 ms | 222 ms | 0 |
| 500 | **1,096** | 263 ms | 307 ms | 336 ms | 354 ms | 0 |

**Takeaway:** throughput peaks at ~1,400 req/sec (10 clients) and
holds above 1,000 req/sec even at 500 concurrent clients. **Zero
errors at every concurrency level.** Latency scales linearly with
concurrency — no cliff edge.

---

## 8. Single-Operation Throughput

Dedicated `tools/list` throughput on a single session (measures the
fastest path without session churn).

| Metric | Value |
|---|---|
| Throughput | **1,197 req/sec** |
| p50 | 827 µs |
| p95 | 867 µs |
| p99 | 1.02 ms |

---

## 9. Session Lifecycle Cycle Time

Full init → tools/call → delete cycle, sequential.

| Metric | Value |
|---|---|
| p50 | **2,581 µs** |
| p95 | 2,617 µs |
| p99 | 2,644 µs |
| Cycles/sec | **386** |

---

## 10. Sustained Load (100–1000 concurrent sessions)

Each tier: establish N sessions, then hammer `tools/call` for 10
seconds continuously.

| Sessions | Throughput | p50 | p95 | p99 | max | Errors | Memory |
|---|---|---|---|---|---|---|---|
| 100 | **5,475 req/s** | 13.6 ms | 23.8 ms | 29.5 ms | 96 ms | 0% | 181 MB |
| 250 | **4,954 req/s** | 49.9 ms | 72.9 ms | 89.5 ms | 157 ms | 0% | 102 MB |
| 500 | **3,723 req/s** | 134 ms | 174 ms | 201 ms | 316 ms | 0% | 110 MB |
| 1000 | **2,532 req/s** | 405 ms | 476 ms | 523 ms | 702 ms | 0% | 122 MB |

**Takeaway:**
- **Zero errors at every session count** — the gateway does not break
  under load; it gracefully degrades latency.
- **~5.5K req/sec at 100 sessions** on a dev-profile binary on shared
  cloud compute. A release build on dedicated hardware would be 2-5×
  faster.
- **Memory: ~1 MB per active session** (100 sessions ≈ 100 MB, 1000
  sessions ≈ 122 MB). The sub-linear growth at higher counts suggests
  the initial overhead is dominated by the connection pool and reqwest
  client, not per-session state.
- **Session setup rate: ~600-1200 sessions/sec** — fast enough for
  burst onboarding.

---

## 11. Rate Limiter Accuracy

> **Removed.** `bench_rate_limiter_accuracy` was deleted when rate limiting
> moved to the `dev.mcpg.rate-limit` plugin. Historical (pre-migration).

Under burst conditions, the token-bucket rate limiter:
- Consumed all 50 burst tokens correctly
- Denied all 50 post-burst requests correctly
- Correctly allowed after the refill window elapsed

**100% accurate** — no over-counting, no under-counting.

---

## 12. Memory Profile

| State | VmRSS |
|---|---|
| Idle (0 sessions) | ~17 MB |
| 100 sessions under load | ~181 MB |
| 250 sessions under load | ~102 MB |
| 500 sessions under load | ~110 MB |
| 1000 sessions under load | ~122 MB |

The apparently lower memory at 250-1000 sessions vs 100 is due to
test ordering: the 100-session test runs first on a fresh process;
subsequent tiers reuse the process and its pre-warmed allocator pools.
The steady-state per-session overhead is ~0.5-1.0 MB.

---

## Interpretation for Production

| Deployment shape | Expected behavior |
|---|---|
| **Single agent, personal** (1-5 sessions) | Sub-millisecond p50. Gateway invisible. |
| **Small team** (10-50 sessions) | p50 < 30 ms. Comfortable. |
| **SaaS platform** (100-500 sessions) | 3.7-5.5K req/sec. Plan for ~500 MB RSS. |
| **Large scale** (1000+ sessions) | 2.5K req/sec. Use release build + dedicated hardware for 2-5× improvement. |

### What these numbers do NOT include

- **Backend latency.** All benchmarks use mock bindings with 0 ms delay.
  Real-world throughput will be backend-bound, not gateway-bound.
- **TLS termination overhead.** Benchmarks run over plain HTTP.
- **Plugin execution time.** Noop plugins add ~225 ns each; real
  plugins (guardrails HTTP callout, payment HMAC verification) add
  their own latency.
- **The plugin FFI boundary (the big one, post-migration).** Every bench
  here dispatches to backends/plugins **in-process** (a mock trait object /
  native noop gates) — none `dlopen` a cdylib or cross the vtable. Real
  backends are now runtime-loaded cdylibs whose per-call JSON-over-`RString`
  marshaling + `spawn_blocking` async↔sync ferry is the dominant gateway
  overhead. That boundary is measured separately in **§19**.

---

## 13. Plugin Impact (dev profile)

Measures the overhead of having noop tool-gate plugins registered in
the plugin chain. Each scenario runs 100 concurrent sessions for 10
seconds. Plugins are noop (always-allow) to isolate the dispatch
overhead from plugin logic.

| Scenario | req/s | p50 | p95 | p99 | max | Errors |
|---|---|---|---|---|---|---|
| A) No plugins (baseline) | **5,903** | 12.7 ms | 22.0 ms | 26.5 ms | 76.9 ms | 0 |
| B) 1 plugin (audit noop) | **5,840** | 12.9 ms | 22.4 ms | 26.9 ms | 42.7 ms | 0 |
| C) 1 plugin (cache noop) | **5,922** | 12.6 ms | 22.1 ms | 26.7 ms | 44.5 ms | 0 |
| D) 1 plugin (guardrails noop) | **5,872** | 12.8 ms | 22.0 ms | 26.3 ms | 43.3 ms | 0 |
| E) 3 plugins stacked | **5,823** | 12.9 ms | 22.2 ms | 26.6 ms | 42.0 ms | 0 |

**Takeaway:** Noop plugin overhead is **negligible** in the integration
path. Even stacking 3 plugins causes less than 1.5% throughput
reduction. The Criterion microbenchmark measures ~225 ns/plugin; at
integration scale the per-request plugin chain cost is swamped by HTTP
I/O, JSON serialization, and session lookup.

---

## 14. Debug Tools Impact

Tests whether having the 5 built-in debug tools registered (command
probe, network probe, runtime snapshot, session list, tool list)
affects `tools/call` dispatch time for non-debug tools.

| Scenario | req/s | p50 | p95 | p99 | max | Errors |
|---|---|---|---|---|---|---|
| F) Debug tools disabled | **5,892** | 12.7 ms | 22.1 ms | 26.7 ms | 73.6 ms | 0 |
| G) Debug tools enabled | **5,922** | 12.7 ms | 22.2 ms | 26.5 ms | 40.7 ms | 0 |

**Takeaway:** Debug tools have **zero measurable impact** on
non-debug dispatch. Tool lookup is by name (DashMap), so registering
extra tools does not degrade lookups for existing tools.

---

## 15. Binding Count Scaling (dev profile)

Tests whether the capability registry's tool lookup degrades as more
tools are registered. All scenarios call a single tool (`echo-0`)
with 100 concurrent sessions for 10 seconds.

| Bindings | req/s | p50 | p95 | p99 | max | Errors |
|---|---|---|---|---|---|---|
| 1 | **5,987** | 12.5 ms | 21.9 ms | 26.4 ms | 106 ms | 0 |
| 10 | **6,056** | 12.4 ms | 21.5 ms | 25.9 ms | 41.8 ms | 0 |
| 50 | **5,964** | 12.6 ms | 21.8 ms | 26.4 ms | 44.5 ms | 0 |
| 100 | **6,043** | 12.4 ms | 21.6 ms | 26.1 ms | 41.5 ms | 0 |

**Takeaway:** Tool lookup is **O(1)** — throughput is flat from 1 to
100 registered backends. The DashMap-based capability registry scales
without degradation.

---

## 16. Release Build Comparison

All previous integration benchmarks used the `dev` profile
(unoptimized + debuginfo). Here are the same tests compiled with
`cargo test --release`.

### Sustained load (release)

| Sessions | Throughput | p50 | p95 | p99 | max | Errors |
|---|---|---|---|---|---|---|
| 100 | **26,257 req/s** | 2.8 ms | 5.0 ms | 6.2 ms | 101 ms | 0% |
| 250 | **14,219 req/s** | 16.1 ms | 21.3 ms | 76.0 ms | 141 ms | 0% |
| 500 | **13,864 req/s** | 34.5 ms | 42.7 ms | 85.8 ms | 140 ms | 0% |
| 1000 | **11,976 req/s** | 83.7 ms | 93.8 ms | 100 ms | 118 ms | 0% |

### Plugin impact (release)

| Scenario | req/s | p50 | p95 | p99 |
|---|---|---|---|---|
| A) No plugins (baseline) | **26,920** | 2.8 ms | 4.9 ms | 5.9 ms |
| B) 1 plugin (audit noop) | **28,114** | 2.7 ms | 4.7 ms | 5.7 ms |
| C) 1 plugin (cache noop) | **27,835** | 2.7 ms | 4.7 ms | 5.8 ms |
| D) 1 plugin (guardrails noop) | **27,620** | 2.7 ms | 4.8 ms | 5.8 ms |
| E) 3 plugins stacked | **27,249** | 2.8 ms | 4.9 ms | 5.9 ms |

### Backend count scaling (release)

| Bindings | req/s | p50 | p95 | p99 |
|---|---|---|---|---|
| 1 | **27,273** | 2.8 ms | 4.8 ms | 5.9 ms |
| 10 | **28,226** | 2.7 ms | 4.7 ms | 5.7 ms |
| 50 | **28,201** | 2.7 ms | 4.7 ms | 5.7 ms |
| 100 | **27,243** | 2.8 ms | 4.9 ms | 5.9 ms |

### Dev vs release comparison

| Metric | Dev | Release | Speedup |
|---|---|---|---|
| Throughput (100 sessions) | 5,475 req/s | 26,257 req/s | **4.8x** |
| Throughput (500 sessions) | 3,723 req/s | 13,864 req/s | **3.7x** |
| Throughput (1000 sessions) | 2,532 req/s | 11,976 req/s | **4.7x** |
| p50 latency (100 sessions) | 13.6 ms | 2.8 ms | **4.9x** |

**Takeaway:** Release builds deliver a consistent **3.7-4.9x
improvement** across all session counts. At 100 concurrent sessions on
shared cloud compute, the gateway sustains **26K+ requests/second**
with a p50 of 2.8 ms. The improvement is larger at low-to-medium
concurrency where the CPU-bound gateway code dominates; at higher
concurrency the bottleneck shifts toward connection handling and
kernel scheduling.

---

## How to Reproduce

```bash
# Microbenchmarks (Criterion, statistical, 100+ iterations each)
cargo bench -p mcpg

# Gateway lifecycle benchmark (1-500 concurrent clients)
cargo test -p mcpg --test bench_gateway -- --ignored --nocapture

# Sustained load (100 sessions x 10 seconds)
cargo test -p mcpg --test bench_load bench_sustained_load -- --ignored --nocapture

# High-session sustained load (250/500/1000 sessions x 10 seconds)
cargo test -p mcpg --test bench_load bench_sustained_load_high -- --ignored --nocapture

# Plugin impact, debug tools, binding count scaling
cargo test -p mcpg --test bench_plugins -- --ignored --nocapture

# Release-mode integration benchmarks
cargo test -p mcpg --release --test bench_load -- --ignored --nocapture
cargo test -p mcpg --release --test bench_plugins -- --ignored --nocapture

# §19 — plugin FFI boundary (real cdylib). Build the fixture first:
cargo build -p mcpg-plugin-testing-bench-noop --release
cargo bench -p mcpg-plugin-host --bench ffi_roundtrip   # bench #1
cargo bench -p mcpg-plugin-host --bench ffi_matrix       # #2-#9
# Instruction-count variant (needs valgrind + iai-callgrind-runner):
cargo bench -p mcpg-plugin-host --bench ffi_roundtrip_iai
```

---

## Files

| Path | Purpose |
|---|---|
| `apps/gateway/benches/protocol_parse.rs` | Protocol parsing microbenchmarks |
| `apps/gateway/benches/uri_normalize.rs` | URI normalization microbenchmarks |
| `apps/gateway/benches/redactor.rs` | Credential redactor microbenchmarks |
| `apps/gateway/benches/plugin_chain.rs` | **Native** gate-chain registry baseline (in-process, not FFI) |
| `apps/gateway/tests/bench_gateway.rs` | Gateway lifecycle + throughput integration bench (FFI-free path) |
| `apps/gateway/tests/bench_load.rs` | Sustained load integration bench (FFI-free path) |
| `apps/gateway/tests/bench_plugins.rs` | Plugin impact, debug tools, binding count scaling bench (native plugins) |
| `libs/plugin-host/benches/ffi_roundtrip.rs` | **§19** — FFI round-trip cost (criterion), bench #1 |
| `libs/plugin-host/benches/ffi_roundtrip_iai.rs` | §19 — instruction-count variant (iai-callgrind) |
| `libs/plugin-host/benches/ffi_matrix.rs` | §19 — FFI matrix #2–#9 (typed/json, ferry, config, payload, fanout, streaming, load) |
| `libs/plugins/testing/bench-noop/` | No-op multi-kind cdylib fixture the §19 benches `dlopen` |

---

## 17. Backend Latency Impact (dev profile)

Simulated backend delay to isolate gateway overhead from end-to-end
latency. Each cell: 10 seconds of sustained `tools/call` load.

### Throughput vs backend latency

| Profile | Delay | 10 sessions | 50 sessions | 100 sessions | Errors |
|---|---|---|---|---|---|
| **Zero** (baseline) | 0 ms | 4,752 req/s | 5,254 req/s | 5,057 req/s | 0 |
| **Fast** (cache/local DB) | 5 ms | 1,233 req/s | 1,257 req/s | 1,256 req/s | 0 |
| **Medium** (networked DB) | 50 ms | 155 req/s | 158 req/s | 161 req/s | 0 |
| **Slow** (remote API) | 200 ms | 40 req/s | 43 req/s | 48 req/s | 0 |
| **Very slow** (LLM inference) | 500 ms | 16 req/s | 19 req/s | 22 req/s | 0 |

### Latency distribution (p50 ms)

| Profile | 10 sessions | 50 sessions | 100 sessions |
|---|---|---|---|
| Zero (0 ms) | 2.0 ms | 9.3 ms | 19.5 ms |
| Fast (5 ms) | 7.8 ms | 39.2 ms | 77.5 ms |
| Medium (50 ms) | 54.8 ms | 313.9 ms | 629.1 ms |
| Slow (200 ms) | 203.0 ms | 1,212 ms | 2,417 ms |
| Very slow (500 ms) | 503.1 ms | 3,011 ms | 5,507 ms |

### Gateway overhead isolation (50 sessions, dev)

| Backend delay | End-to-end p50 | Gateway overhead | Overhead % | Throughput |
|---|---|---|---|---|
| 0 ms | 9.4 ms | 9.4 ms | 100% | 5,264 req/s |
| 5 ms | 39.2 ms | 34.2 ms | 87% | 1,253 req/s |
| 50 ms | 314.7 ms | 264.7 ms | 84% | 158 req/s |
| 200 ms | 1,213 ms | 1,013 ms | 84% | 43 req/s |
| 500 ms | 3,013 ms | 2,513 ms | 83% | 19 req/s |

**Insight:** the "gateway overhead" at 50 sessions under dev profile
is dominated by the queuing effect — 50 concurrent requests contend
on the tokio runtime + mock delay. The overhead percentage stabilizes
at ~83-84% for slow backends, meaning the gateway adds minimal
absolute latency vs the backend delay. The 87% figure for 5 ms
backends reflects higher per-request gateway cost relative to a very
fast backend.

---

## 18. Backend Latency Impact (release profile)

Same matrix as §17 but compiled with `--release`.

### Throughput vs backend latency (release)

| Profile | Delay | 10 sessions | 50 sessions | 100 sessions | Errors |
|---|---|---|---|---|---|
| **Zero** | 0 ms | **12,741 req/s** | **14,441 req/s** | **14,566 req/s** | 0 |
| **Fast** | 5 ms | 1,467 req/s | 1,478 req/s | 1,485 req/s | 0 |
| **Medium** | 50 ms | 159 req/s | 161 req/s | 165 req/s | 0 |
| **Slow** | 200 ms | 40 req/s | 43 req/s | 46 req/s | 0 |
| **Very slow** | 500 ms | 16 req/s | 19 req/s | 22 req/s | 0 |

### Gateway overhead isolation (50 sessions, release)

| Backend delay | End-to-end p50 | Gateway overhead | Overhead % | Throughput |
|---|---|---|---|---|
| 0 ms | **3.1 ms** | 3.1 ms | 100% | **14,625 req/s** |
| 5 ms | 33.0 ms | 28.0 ms | 85% | 1,484 req/s |
| 50 ms | 303.8 ms | 253.8 ms | 84% | 162 req/s |
| 200 ms | 1,204 ms | 1,004 ms | 83% | 43 req/s |
| 500 ms | 2,505 ms | 2,005 ms | 80% | 20 req/s |

### Memory scaling by backend latency (50 sessions, release)

| Backend delay | Idle | Under load | Delta | Per session |
|---|---|---|---|---|
| 0 ms | 146 MB | 195 MB | 49 MB | ~1 MB |
| 5 ms | 196 MB | 196 MB | 0 MB | negligible |
| 50 ms | 196 MB | 193 MB | 0 MB | negligible |
| 200 ms | 181 MB | 181 MB | 0 MB | negligible |
| 500 ms | 181 MB | 181 MB | 0 MB | negligible |

**Key insights:**

1. **Gateway is invisible for slow backends.** At 200+ ms backend
   delay, the gateway adds < 4 ms absolute overhead in release mode
   (204 ms end-to-end vs 200 ms backend = 2% gateway contribution).
   The gateway is not the bottleneck.

2. **Fast backends expose the gateway's queuing overhead.** At 5 ms
   backend delay, 50 concurrent sessions see 33 ms end-to-end
   because requests queue behind each other in the tokio runtime.
   This is the concurrency scheduling cost, not protocol overhead.

3. **Throughput is backend-bound once delay > 0.** At 50 ms delay,
   50 sessions can only achieve ~160 req/s (50 sessions / 0.3s
   round-trip ≈ 167 theoretical max). The gateway achieves 97% of
   the theoretical maximum.

4. **Memory does not grow with backend latency.** Once sessions are
   established, the memory footprint is the same regardless of
   whether the backend takes 5 ms or 500 ms. The per-session state
   (replay window, request-id FIFO, completion limiter) is fixed-size.

5. **Zero errors at every combination.** No timeout, no panic, no
   session leak across all 30 (5 profiles × 3 session counts × 2
   build modes) scenarios.

---

## How to Reproduce

```bash
# Backend latency matrix (dev profile, ~4 minutes)
cargo test -p mcpg --test bench_backend_latency -- --ignored --nocapture

# Backend latency matrix (release profile, ~4 minutes)
cargo test -p mcpg --release --test bench_backend_latency -- --ignored --nocapture
```

---

## 19. Plugin FFI boundary (2026-05, measured against a real cdylib)

The first measurements that cross the **actual plugin FFI boundary** — a
`dlopen`'d cdylib called through the `extern "C"` vtable — rather than the
in-process mock path §1–18 use. Source: `libs/plugin-host/benches/` against the
`bench-noop` fixture (criterion, release, ~30 B args unless noted, one 16 vCPU
machine). Method: difference a real-cdylib call against the same no-op done
in-process, isolating the boundary.

### Per-call cost

| Path | wall-clock p50 | notes |
|---|---|---|
| in-process no-op (floor) | 35 ns | sync, no FFI |
| in-process no-op + `block_on` | 141 ns | runtime baseline |
| **`backend.execute`** (real cdylib) | **3.3–4.6 µs** | direct sync vtable — **no** ferry |
| **`tool_gate.evaluate_pre`** (typed return) | **34 µs** | incl. `spawn_blocking` ferry |
| **`log_sink.emit`** | **40 µs** | incl. ferry |
| streaming | **~41 µs setup + ~1.0 µs/chunk** | JSON chunk path |
| cdylib load (dlopen + register + make) | **686 µs** | one-time |

### What the numbers say

1. **The `spawn_blocking` async↔sync ferry — not JSON marshaling — dominates.**
   Every ferried slot (tool_gate 34 µs, sink 40 µs, streaming setup 41 µs) is
   ~10× `backend.execute` (3.3 µs), which is a *direct synchronous vtable call
   with no ferry*. The intuition that "JSON-Result is costlier than typed
   Tier-1" is **inverted** in practice.
2. **Payloads scaled badly (~15 MiB/s) — FIXED in ABI v37 (base64).**
   `BackendRequest/Response.payload: Vec<u8>` originally serialised as a JSON
   number-array (one decimal token per byte; serde visits every element), so a
   `backend.execute` round-trip was ~20 µs at 256 B but **~2 ms at 32 KiB**.
   Encoding the payload as base64 instead (a single string token + a tight loop)
   cut that **~5–14×** — measured same-machine via criterion `--baseline`:

   | payload | v36 number-array | v37 base64 | speed-up |
   |---|---|---|---|
   | 256 B | 20 µs · 12 MiB/s | **3.8 µs · 65 MiB/s** | 5.2× |
   | 4 KiB | 271 µs · 14 MiB/s | **20.6 µs · 190 MiB/s** | 12.6× |
   | 32 KiB | 2.07 ms · 15 MiB/s | **146 µs · 214 MiB/s** | 14× |

   No vtable/signature change and zero plugin-binding edits — the fix lives in
   the shared type's serde (a `#[serde(with)]` codec); the accompanying ABI bump
   just forces stale plugins to rebuild.

3. **Per-call `config_json` re-encode is negligible (~0.36 µs)** — *correcting
   an earlier ~7 µs claim that was ferry noise.* Tier-1 slots re-`serde_json::
   to_string` the plugin's static config every call; the `config_resend` group
   (empty vs realistic config, end-to-end) showed a ~4–7 µs Δ, but that Δ is
   dominated by ±3 µs run-to-run variance in the ~30 µs ferry, not by encoding.
   Isolated (`config_reencode_vs_cached`), a realistic ~120-byte config encodes
   in **360 ns**; caching the encoded form would bring it to **23 ns** — a
   ~0.34 µs/call saving, scaling with config size. Too small to be worth the
   host-side caching machinery (tested + reverted), so §3.D.1 is **closed as
   not-worthwhile**. **Fan-out** is ~38 µs/sink (linear: 1→40, 3→117, 10→384 µs).
   **The arena encoder** saves ~22% on the encode (1.71→1.34 µs at 256 B) —
   real but small next to the ferry.

### The serialization ceiling: typed structs vs JSON/binary (measured)

How much of the marshaling is serialization we could *eliminate*? The
`marshaling_*` group isolates the request round trip (no ferry, no vtable, no
real plugin): native data → wire/typed form → read `payload.len()` +
`request_id` back. Because a cdylib runs in the host's **own address space**, a
borrowed slice across the boundary is genuinely zero-copy — no IPC, no shared-mem
machinery.

| approach | 256 B | 4096 B | vs JSON |
|---|---|---|---|
| `json_base64` (current, full encode/decode) | 1.27 µs | 9.12 µs | 1× |
| `bincode_raw` (binary format, raw bytes) | 724 ns | 10.46 µs | ~same |
| `typed_owned` (`repr(C)` + `RVec`, one copy) | **41 ns** | **160 ns** | **~30–57×** |
| `typed_borrowed` (`RSlice`/`RStr`, zero-copy) | **2.3 ns** | **2.3 ns** | **~560–4000×** |

Three conclusions:
1. **Serialization is almost entirely eliminable.** Typed `repr(C)`/`abi_stable`
   structs drop the marshaling from µs to **tens of ns** (one payload copy) or
   **~2 ns** (zero-copy borrow, size-independent — it's just forming a
   pointer + length). The precedent already exists: the Tier-1 *returns*
   (`RGateDecision` etc.) are already typed; only the *inputs* are still JSON.
2. **The win is *eliminating* serialization, not swapping the format.**
   `bincode` over raw bytes is no better than JSON (and *slower* at 4 KiB —
   `serde_json` is highly optimised; a binary format still walks the struct +
   allocates + parses). Don't reach for bincode/protobuf; reach for no-serde.
3. **But it only matters where marshaling dominates** — which is nowhere hot
   today. `backend.execute` (the one un-ferried slot) is I/O-bound, so its
   ~3 µs marshaling is already noise next to a ms-scale upstream call; the hot
   Tier-1 slots are ferry-bound (~30 µs). Typed args reach near-native *only*
   in combination with **inline dispatch** (dropping the ferry — a sandbox-trust
   decision): inline turns a ~33 µs gate into ~3 µs (marshaling-bound), then
   typed/borrowed args take that ~3 µs → ~tens of ns. Near-native end-to-end
   needs both; serialization alone is the smaller, second lever.

### One slot, two dispatch policies: ferried default + inline opt-in (ABI v38)

**Unified.** Each Tier-1 op is now a *single* borrowed/typed slot; the
host dispatches it either **ferried** (default — `spawn_blocking` + per-call
timeout, the sandbox) or **inline** (operator opt-in `inline_dispatch` —
zero-copy, no ferry). No fast/slow slot pair; "fast" is just a host policy.
Same-machine `fast_slot` matrix (real cdylib):

| slot | ferried (default) | inline (opt-in) | speed-up |
|---|---|---|---|
| `tool_gate` pre  | 34 µs   | **1.69 µs** | ~20× |
| `tool_gate` post | 32.9 µs | **1.94 µs** | ~17× |
| `transform` args | 35.5 µs | **1.62 µs** | ~22× |
| `identity` resolve | 36.7 µs | **0.99 µs** | ~37× |
| `log_sink` emit | 30.3 µs | **1.18 µs** | ~26× |

Two things to note vs the earlier prototype numbers:
1. **`transform`/`identity` now ferry by default too.** They used to call the
   vtable inline *without* isolation (a latent hazard — a blocking transform
   could freeze a worker). Unifying gave them the ferried default + the
   per-call timeout. So their default cost rose (~1.5 µs → ~35 µs) but they
   **gained the sandbox**; the operator restores speed with `inline_dispatch`.
2. **Inline is ~1.7 µs (was 1.16 µs in the prototype).** The clean single
   interface hands authors a parsed `&Value` (the SDK parses the borrowed
   `RStr`), so we pay one ~0.5 µs parse rather than the prototype's zero-parse
   shortcut — a deliberate ergonomics-over-microopt choice. Still ~20×.

**The cost is the sandbox, not performance.** Inline means a hung/blocking
plugin wedges a runtime worker with no per-call timeout. So inline is gated on an
explicit **operator opt-in** (`plugins[].inline_dispatch`) — default-off,
ferried fallback unchanged.

### Context

For an I/O-bound backend (HTTP/SQL/LLM — the common case) the upstream call is
1 ms–seconds, so the ~5–40 µs FFI overhead is ~0.1–1% — in the noise. It bites
on cached/CPU-bound paths, long chains, large payloads, and many-sink fan-out.

### The dispatch ferry is irreducible by mechanism (measured 2026-05-25)

The ~30 µs ferry on Tier-1/sink slots is the host wrapping each synchronous
vtable call in `tokio::time::timeout(spawn_blocking(…))`, which buys two
properties: the slot runs **off** the async runtime (a hung plugin can't block a
worker) and the caller gets a **per-call timeout**. We tested whether a warm
per-plugin worker pool — fixed threads parked on a `crossbeam_channel` + a
`oneshot` wake-back — could keep both properties while cutting the handoff cost.

Same-machine A/B (criterion `--baseline`, `tool_gate.evaluate_pre`):

| dispatch mechanism | p50 | verdict |
|---|---|---|
| `spawn_blocking` (status quo) | 33.3 µs | — |
| warm per-plugin pool | 33.6 µs | `change +4.9%` (p = 0.05) → **no change detected** |

The cost is the **thread hop plus the timeout**, not the pool implementation:
moving the work to *any* other thread and waking back costs ~30 µs regardless of
where the thread comes from. So the ferry **cannot** be optimised by swapping the
async↔sync bridge mechanism. The only way to remove it is to **not hop threads**
— run the slot inline on the async worker — which gives up the per-call timeout
and the isolation from a hung/slow plugin. That is a sandbox-*policy* decision
(defensible only for slots whose contract guarantees fast, non-blocking,
pure-compute execution), not a mechanism swap, and is **deferred**. The
experiment was reverted; this row records the negative result.

### Instruction-count (iai-callgrind, deterministic)

`backend.execute` ≈ **48.3k instructions** vs **6.4k** for the in-process-async
baseline → ~**41.9k instructions** of FFI marshaling. The instruction count is
the stable regression signal; the µs above is the latency truth (callgrind's
cycle *estimate* runs high).

These measurements closed out the FFI latency levers:
- **Binary payloads — done** (base64 on the wire, ~5–14×; finding #2).
- **Config caching — closed, not worthwhile** (the motivating ~7 µs was
  ferry noise; real config re-encode is ~0.36 µs; finding #3).
- **The dispatch ferry — irreducible** without dropping isolation/timeout (the
  warm-pool negative result above). (The plugin→host re-entrancy/`block_on`
  path is a *different* ferry — a reliability, not latency, concern.)

So the one landed latency win is base64 payloads; the rest of the FFI overhead
is either irreducible (ferry) or already negligible (config).
