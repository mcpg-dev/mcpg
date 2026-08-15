# MCPG Pipeline Performance: Bottleneck Investigation & Fix (2026-05-26)

> A self-contained record of a pipeline-wide performance investigation:
> the benchmark suite used, the hot-path map it produced, the one
> dominant bottleneck it surfaced, how that bottleneck was root-caused
> (after a long chain of *wrong* hypotheses), the fix, and the
> before/after proof. Companion to [`benchmarks.md`](benchmarks.md)
> (which holds the older FFI-boundary micro-numbers).

---

## 1. Executive summary

The gateway's per-request pipeline is healthy across the board — backends,
CEL templating, GraphQL, the idempotency stage, and in/out-of-process
dispatch all cost **< 0.5 ms CPU/req marginal** and sustain **> 95 % of
baseline throughput**. The gateway is **not CPU-bound** at realistic loads
(it burns 2–3 of 16 cores; estimated CPU ceiling ~16–20 k req/s).

There was **one** dominant bottleneck, and it was severe: loading **any
tool-gate plugin** collapsed `tools/call` throughput **~5–50×** and made
latency wildly unstable (p99 up to **3.96 s**). After eliminating every
plausible FFI/dispatch/session/metrics cause, the culprit turned out to be
**outside the plugin path entirely**: the default **local-file audit sink
`fsync`s once per audit event**, and a gated tool call emits **two** audit
events. Two serialized disk syncs per request → a hard ~100 req/s ceiling.

**The fix** — group commit in the audit sink (one `fsync` per *batch* of
concurrently-queued events) — restored gated throughput to **~92 % of
baseline** with durability intact:

| Scenario | Before | After | Δ |
|---|---|---|---|
| rate-limit gate (ferried), req/s | 38 | 2064 | **54×** |
| rate-limit gate (inline), req/s | 202 | 2062 | 10× |
| gate path, gateway CPU ms/req | 29.6 | 2.1 | **14× less** |
| ferried gate p99 latency | 3.96 s | 43 ms | **92× lower** |

---

## 2. Environment & methodology

| | |
|---|---|
| **CPU** | 16 cores, x86_64 |
| **Kernel** | Linux 6.1.0-44-cloud-amd64 |
| **Build** | `--release` (optimized, symbols retained) |
| **Gateway runtime** | `#[tokio::main]` → 16 worker threads |
| **Load harness** | `#[tokio::test(worker_threads = 8)]`, reqwest clients |
| **Upstream (http/graphql)** | local `wiremock` |
| **Profiling** | `gdb` thread-sampling (no `perf`/`bpftrace` available) |

### Two benchmark drivers

- **`apps/gateway/tests/bench_backends.rs`** — spins up a real `mcpg`
  child per scenario, hammers it over HTTP with N concurrent sessions for
  a fixed window, reports `req/s`, latency percentiles, and **`gw CPU
  ms/req`**. Tests: `bench_backends_kinds`, `bench_gates`,
  `bench_gate_scaling`, `bench_gate_profile`.
- **`apps/gateway/tests/bench_pipeline.rs`** — stage-attribution +
  CPU-accounting ceiling. Tests: `bench_pipeline_attribution`,
  `bench_pipeline_idempotency`, `bench_pipeline_out_of_process`,
  `bench_pipeline_ceiling`.

```bash
cargo test --release -p mcpg --test bench_backends  <name> -- --ignored --nocapture
cargo test --release -p mcpg --test bench_pipeline             -- --ignored --nocapture
```

### The metric that mattered: `gw CPU ms/req`

Wall-clock `req/s` is **contention-sensitive** — with the load harness (8
threads) and gateway (16 threads) oversubscribing 16 cores, it swings
wildly run-to-run (we saw the same config report 238 req/s and 39 req/s on
back-to-back runs). **`gw CPU ms/req`** — gateway CPU-seconds
(`utime+stime` from `/proc/<pid>/stat`) divided by completed requests — is
**contention-invariant**: it measures the work the gateway actually does
per request regardless of scheduling noise. *This is the number that
cracked the investigation.* Always reason from it, not from raw `req/s`.

---

## 3. Hot-path map (everything that is *fine*)

All measured at 48–64 sessions, release, HTTP end-to-end.

### Backends — `bench_backends_kinds`

| Backend | req/s | CPU ms/req |
|---|---|---|
| mock (baseline) | 2275 | 1.41 |
| http (static URL) | 2236 | 1.38 |
| http (CEL url+header templating) | 2223 | 1.38 |
| graphql | 2118 | 1.79 |

**Takeaways:** CEL URL/header templating is **free** (within noise of static
http). GraphQL adds ~0.4 ms CPU/req (query assembly + response shaping). The
reqwest round-trip to a local upstream adds negligible CPU over mock.

### Pipeline stages — `bench_pipeline.rs`

| Stage | Marginal Δp50 | Throughput vs base |
|---|---|---|
| in-process no-op gate / transform / identity | < 0.15 ms each | ~100 % |
| idempotency (unique key) | +2.3 ms p50 | 96 % |
| out-of-process vs in-process backend | ~roundtrip | ~95 % |

### CPU ceiling — `bench_pipeline_ceiling`

| Sessions | req/s | gateway cores | CPU ms/req | est. ceiling |
|---|---|---|---|---|
| 32 | 1616 | 2.43 | 1.50 | ~10.6 k |
| 128 | 3123 | 3.07 | 0.98 | ~16.3 k |
| 256 | 3398 | 2.62 | 0.77 | ~20.8 k |

CPU ms/req **falls** as concurrency rises (1.50 → 0.77) — work amortizes,
the opposite of contention. The gateway is latency/IO-bound at these loads,
not CPU-bound, with large headroom (~16–20 k req/s CPU ceiling).

### Memory footprint — `bench_memory`

RSS from `/proc/<pid>/status` (`VmRSS` current, `VmHWM` peak) on the
gateway child.

**Footprint vs concurrent sessions (no gate, after a 5 s load window):**

| Sessions | idle MB | loaded MB | peak MB |
|---|---|---|---|
| 0 | 43.3 | 43.3 | 43.3 |
| 32 | 43.1 | 141.7 | 146.6 |
| 128 | 43.0 | 281.1 | 281.1 |
| 256 | 42.6 | 269.9 | 269.9 |

Idle footprint is **~43 MB** and constant. Under load it rises with active
sessions and in-flight request buffers — 256 active sessions hammering ⇒
~270 MB. The footprint reflects active-session state (each `tools/call`
accrues session history) plus transient per-request allocation, not a fixed
per-session cost, so "MB per session" isn't linear (it's a load high-water,
dominated by buffers + allocator arenas, not steady-state session bytes).

**Stability under 20 s sustained load (64 sessions):**

| Scenario | t=3s | t=18s | peak | drained (t+3s) |
|---|---|---|---|---|
| baseline (no gate) | 161.6 | 236.4 | 245.4 | 212.9 |
| + gate (group-commit audit) | 130.1 | 203.7 | 211.5 | 191.3 |

RSS climbs under load (active-session history accrues), then **partially
reclaims after sessions are deleted** (peak 245 → 213 MB baseline); the
~50 MB residual is glibc arena retention (memory freed but not returned to
the OS), not a leak. The key result for the audit fix: the **gated profile
tracks baseline** (gated peak is even a touch lower, and its post-drain
delta is within ~10 MB of baseline) — so the group-commit background writer
and its event channel stay **bounded** under sustained load and add no
unbounded memory growth.

---

## 4. The one bottleneck: a tool-gate collapses throughput

`bench_gate_scaling` compares, across concurrency, a no-gate baseline vs a
no-op cdylib gate on the **ferried** (default `spawn_blocking` + per-call
timeout) and **inline** (`inline_dispatch: true`, operator opt-in) dispatch
paths. **Before the fix:**

| conc | baseline req/s | ferried | inline |
|---|---|---|---|
| 1 | 223 | 162 | 137 |
| 4 | 724 | 283 | 251 |
| 16 | **1252** | **29** (p50 602 ms) | 208 |
| 48 | **1945** | 256 | 238 |

Baseline scales 223 → 1945; the inline gate is **dead flat ~240/s**; the
ferried gate **collapses** (29 req/s at conc 16, p50 602 ms). `bench_gates`
put a number on the cost with the contention-invariant metric:

| Scenario | req/s | **CPU ms/req** | p99 |
|---|---|---|---|
| baseline (no gate) | 1920 | 1.18 | 74 ms |
| + rate-limit (ferried) | 38 | **29.6** | 3.96 s |
| + rate-limit (inline) | 202 | **7.0** | 534 ms |
| + cache (miss) | 193 | 7.5 | 1.38 s |

A tool-gate inflated gateway CPU **6× (inline) to 25× (ferried)** per
request. That is not an off-CPU lock alone — real cycles were being burned.

---

## 5. Root-cause: the elimination chain

The hard part was that **every intuitive suspect was wrong**. Each was
ruled out by a controlled experiment, not by reading:

| Hypothesis | Disproof |
|---|---|
| Gate logic / host callbacks | A zero-host-call no-op gate (`hello-native`) is identical to rate-limit (4 host calls/eval) at every concurrency. |
| `spawn_blocking` ferry | `inline_dispatch:true` (no ferry) had the *same* cap as ferried. |
| Metrics recorder / `FfiCall` histograms | Gating off **all** FFI metric emissions (env-flag experiment) did not recover throughput. |
| Session store global `Mutex<HashMap>` | Instrumentation showed lock held only ~0.25 ms; baseline pays *more* session-store serde (bigger sessions) yet runs 5× faster. |
| Gateway gate-chain machinery | An in-process no-op gate through the same `evaluate_tool_gates_*` adds < 0.15 ms. |
| CPU-bound | Cores sat idle; the per-req CPU *rise* was real work, not saturation. |

**What cracked it — two observations:**

1. Under load the gated gateway used only **~1 core** (108 % CPU) despite
   24 concurrent sessions — a serialization signature.
2. **`gdb` leaf-frame sampling** (25 samples, all threads) found
   `__GI_fsync` as the live leaf in **24 of 25 samples**, under:

   ```
   #0 __GI_fsync
   #1 std::fs::File::sync_all
   #2 tokio::runtime::blocking::task::BlockingTask::poll   ← spawn_blocking
   ```

Tracing the caller closed the case:

- The request handler runs the gate chain only when
  `has_tool_gate_plugins()` is true (`runtime/mod.rs:4749`) — **baseline
  skips the entire path**, which is why baseline never fsynced.
- `evaluate_tool_gates_pre` and `evaluate_tool_gates_post`
  (`libs/plugin-host/src/registry.rs`) each emit an audit event —
  `mcpg.tool.call.allowed` and `mcpg.tool.call.completed` — both
  **default-on** (`config/audit.rs`: `emit_tool_call_allowed/completed =
  true`).
- The **default** audit sink is `dev.mcpg.builtin.audit.local-file`
  (`default_audit_sinks()`), and its `emit` held a `tokio::sync::Mutex`
  across `File::sync_all()` **per event**.

So **every gated tool call = 2 serialized `fsync`s**. At ~5 ms/fsync that
is a ~100 req/s hard ceiling, with latency that explodes under queueing —
exactly the observed shape. The SHA-256 hash chain (`prev_event_hash` per
event) forced the serial ordering, so the per-event fsync couldn't simply
be parallelized.

---

## 6. The fix: group commit

`apps/gateway/src/builtins/audit_local_file.rs` was rewritten from
"lock + write + fsync per event" to a **single background writer task** that
**group-commits**:

1. `emit` serializes the event, hands it to the writer over a channel, and
   awaits a durability reply (`oneshot`).
2. The writer drains **all** currently-queued events into one batch,
   appends their JSONL lines **in receive order** (so the SHA-256 chain
   stays deterministic — exactly one task writes), then issues **one**
   `sync_all` for the whole batch.
3. After the single fsync it replies to every waiter with its receipt. On
   fsync failure it rolls the in-memory chain back to the last durable hash
   and fails every waiter (FailClosed-safe).

**Durability is unchanged** — each `emit` still returns only after *its*
event is durably on disk (spec §9.12 synchronous-ack). What changes is that
under concurrency one fsync serves many events, so **fsync count scales with
batch size, not request count**. Throughput now scales with concurrency
instead of being pinned to fsync latency. All 7 existing audit-sink unit
tests (hash-chain, concurrent-emit, durable-hash) pass unchanged.

---

## 7. Before/after proof

`bench_gates` (48 sessions, release, HTTP e2e):

| Scenario | req/s before→after | CPU ms/req before→after | p99 before→after |
|---|---|---|---|
| baseline (no gate) | 1920 → 2242 | 1.18 → 1.38 | — |
| + rate-limit (ferried) | **38 → 2064** | 29.6 → 2.13 | 3.96 s → 43 ms |
| + rate-limit (inline) | 202 → 2062 | 7.00 → 2.03 | 534 ms → 44 ms |
| + cache (miss) | 193 → 2060 | 7.50 → 2.11 | 1.38 s → 44 ms |
| + cache (hit) | 152 → 2066 | 9.25 → 2.09 | 1.36 s → 46 ms |

`bench_gate_scaling` — the collapse is gone; both dispatch paths now scale:

| conc | baseline | ferried before→after | inline before→after |
|---|---|---|---|
| 1 | 270 | 162 → 178 | 137 → 180 |
| 4 | 817 | 283 → 604 | 251 → 628 |
| 16 | 1375 | **29 → 1229** | 208 → 1249 |
| 48 | 2213 | 256 → 1238 | 238 → 1917 |

A gated tool call went from **~2–13 % of baseline** to **~56–92 %**, with
stable latency (~11–24 ms p50, was 600 ms–1.45 s).

---

## 8. Residual & secondary items

- **Ferried < inline at high concurrency** (conc 48: 1238 vs 1917). With
  fsync no longer dominating, the `spawn_blocking` + per-call-timeout ferry
  is now the *secondary* cost — precisely the motivation for the ABI v38
  fast-slot work (`inline_dispatch`, operator opt-in). Minor; opt-in
  already available.
- **Off-node audit durability.** `local-file` is single-node by design;
  production deployments should still register an off-node sink. Group
  commit doesn't change that guidance — it just removes the per-event fsync
  wall for the bundled sink.
- **Deferred bench coverage**: WASM masking
  transform; infra-backed backends (grpc/kafka/nats/LLMs, redis cache);
  other native gates (ip-allowlist, guardrails, circuit-breaker, cedar/opa
  /casbin) — now worth adding since they no longer all just show the audit
  fsync wall.

---

## 9. Reproduce

```bash
# Backend kinds + gate cost + scaling + pipeline
cargo test --release -p mcpg --test bench_backends bench_backends_kinds -- --ignored --nocapture
cargo test --release -p mcpg --test bench_backends bench_gates          -- --ignored --nocapture
cargo test --release -p mcpg --test bench_backends bench_gate_scaling   -- --ignored --nocapture
cargo test --release -p mcpg --test bench_backends bench_memory         -- --ignored --nocapture
cargo test --release -p mcpg --test bench_pipeline                      -- --ignored --nocapture

# Off-CPU profile harness (prints PROFILE_PID; gdb-sample it during the 45s window)
cargo test --release -p mcpg --test bench_backends bench_gate_profile   -- --ignored --nocapture
```
