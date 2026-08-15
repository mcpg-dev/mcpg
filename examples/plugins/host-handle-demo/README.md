# `mcpg-example-host-handle-demo`

The canonical reference plugin for the [`HostHandle`] adoption pattern,
end-to-end. A no-network "echo" `Backend` whose interesting code is the
**instrumentation envelope** wrapped around the (trivial) work — not the
work itself.

## What this example shows

Every plugin factory receives an ergonomic [`HostHandle`] as its 2nd
argument. Most first-party plugins receive the handle and discard it;
this crate is **the answer to "OK, how do I actually use it?"**:

| Step | What it does | API call |
|------|--------------|----------|
| 1 | Store `HostHandle` on `Self` at make-time | `factory: |cfg, host| make_demo_backend(cfg, host)` |
| 2 | Open an RAII span around the work | `self.host.span(name, attrs) -> SpanGuard` |
| 3 | Resolve a secret URI from operator config | `self.host.resolve_secret(uri)` |
| 4 | Read a config snapshot from operator config | `self.host.config_snapshot(uri)` |
| 5 | Annotate the span with structured events | `span.event(name, attrs)` |
| 6 | Record per-call latency | `self.host.histogram(name, secs, &labels)` |
| 7 | Record call rate | `self.host.counter(name, 1, &labels)` |
| 8 | Audit on notable outcomes only | `self.host.audit_event(AuditEvent { ... })` |
| 9 | Close the span (RAII) | `drop(span)` |

Methods *not* demonstrated by the execute path but still callable
through the same handle: [`HostHandle::issue_credential`],
[`HostHandle::gauge`], [`HostHandle::cluster`],
[`HostHandle::alias`], [`HostHandle::emit_metric`] (raw).

## The pattern, annotated

```rust,ignore
// (1) Plugin stores HostHandle on Self.
//
// This is the L.10 gap. Without this field every host call
// would need the SDK to thread `HostHandle` through every
// per-request method signature — and that's exactly the
// boilerplate Wave L was meant to retire.
pub struct DemoBackend {
    manifest: PluginManifest,
    config: DemoConfig,
    host: HostHandle,
    calls: AtomicU64,
}

// The factory the SDK macro hands the config slice + the
// constructed HostHandle to. The macro builds the handle
// via `HostHandle::from_ffi(host)` on the cdylib path and
// `HostHandle::from_services(...)` on the static-firstparty
// path; both reach this signature unchanged.
pub fn make_demo_backend(config_json: &str, host: HostHandle) -> DemoBackend {
    let config: DemoConfig = serde_json::from_str(config_json).unwrap_or_default();
    DemoBackend { manifest: build_manifest(), config, host, calls: 0.into() }
}

// (2..9) Inside execute() — one span, two metric points,
// one conditional audit, two URI resolutions.
fn run_request(&self, request: BackendRequest) -> Result<BackendResponse, BackendError> {
    let span = self.host.span(
        "host_handle_demo.execute",
        serde_json::json!({ "endpoint": self.config.endpoint, "request_id": request.request_id }),
    );

    let secret = self.host.resolve_secret(&self.config.secret_uri);     // (3)
    let snap   = self.host.config_snapshot(&self.config.config_uri);    // (4)
    span.event("secret.resolved", serde_json::json!({ ... }));          // (5)

    let start = Instant::now();
    let result = self.do_work(&request);
    let elapsed = start.elapsed().as_secs_f64();
    let outcome = if result.is_ok() { "ok" } else { "err" };

    self.host.histogram("..._latency_seconds", elapsed, &[("outcome", outcome)]);  // (6)
    self.host.counter("..._calls_total", 1, &[("outcome", outcome)]);              // (7)

    if let Err(ref err) = result {
        let _ = self.host.audit_event(AuditEvent { /* ... */ });                   // (8)
    }

    drop(span);                                                                    // (9)
    result
}
```

## What plugin authors must NOT do

The example uses `resolve_secret` and `config_snapshot` on **every
`execute()`** purely to keep the demonstration surface visible in
one method. **Real plugins MUST cache config-static lookups at
`make()` time** — see §6.15.3.8 *HostHandle method caching guidance*.
A naïve per-request `resolve_secret()` adds ~30–100 µs of FFI plus
the resolution work to every call. The metric
`mcpg_plugin_host_call_per_request_avg{plugin_alias, method}`
surfaces the anti-pattern in production.

Cardinality discipline: keep metric label values bounded (here:
just `"ok"` / `"err"`). Per-request unique values (request_id,
caller subject_id) belong on **span attributes**, never on metric
labels — `metrics-rs` will compose them into Prometheus series and
explode the cardinality budget.

Don't audit every successful call. Audit sinks are durable and
expensive; reserve them for the compliance/forensics path
(failures, denials, sensitive operations). Use counters for the
per-call observability budget.

## Registering it in `mcpg.yaml`

```yaml
plugins:
  - id: my-demo
    ref: dev.mcpg.example.host-handle-demo
    class: backend
    source:
      path: ./target/release/libmcpg_example_host_handle_demo.so
    config:
      endpoint: "https://upstream.invalid/v1"
      secret_uri: "vault://kv/myapp/api-key"
      config_uri: "file:///etc/mcpg/demo.json"
      fail_every_n: 0
```

The plugin's `required_capabilities: []` — the demo doesn't gate
on capability presence, but the host still filters the
`resolve_secret` / `config_snapshot` calls through the operator's
grants. Add `SecretsRead{schemes: [vault]}` /
`ConfigRead{schemes: [file]}` if the operator's policy requires
explicit grants.

## Build

```sh
cargo build --release -p mcpg-example-host-handle-demo
```

Outputs `target/release/libmcpg_example_host_handle_demo.{so,dylib,dll}`
depending on platform.

## Smoke test

```sh
mcpg-plugin pack \
    --descriptor examples/plugins/host-handle-demo/plugin.yaml \
    --artifact target/release/libmcpg_example_host_handle_demo.so \
    --out /tmp/host-handle-demo.zip
mcpg-plugin test /tmp/host-handle-demo.zip
```

Or with `mcpg dev`:

```sh
mcpg dev --plugin target/release/libmcpg_example_host_handle_demo.so
```

## Static-firstparty embedding

Add the crate as a path-dep with `default-features = false,
features = ["static-firstparty"]`, then in the gateway's boot:

```rust,ignore
let host = build_host_handle("my-demo");
mcpg_example_host_handle_demo::register_static(&mut registrar, &[], host)?;
```

The macro-generated `register_static()` boxes the plugin via
`SyncBackendPluginAdapter` and registers it directly with
`FirstPartyRegistrar` — no FFI vtable, no JSON encode/decode, no
`spawn_blocking` — the in-process fast path is preserved.

## Unit test

```sh
cargo test -p mcpg-example-host-handle-demo
```

Three tests:

- `happy_path_emits_span_metric_and_resolves_uris` — drives one
  successful `execute()` through a Recorder `HostServices` impl
  and asserts the span lifecycle (start + end + events), histogram
  + counter emission, and secret/config URI resolution.
- `failure_path_emits_audit_event_with_expected_action` —
  configures `fail_every_n: 1` and asserts the audit event lands
  with action `dev.mcpg.example.host_handle_demo.execute_failed`
  + `AuditOutcome::Failure`, plus the histogram carries
  `outcome=err`.
- `manifest_advertises_backend_class` — structural smoke check.

The Recorder pattern is the same one
`libs/plugin-host/tests/host_bridge_wired.rs` uses on the FFI
side; the unit test exercises the equivalent flow through
`HostHandle::from_services` so plugin authors have a copy-paste
template for their own tests.

[`HostHandle`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html
[`HostHandle::issue_credential`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html#method.issue_credential
[`HostHandle::gauge`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html#method.gauge
[`HostHandle::cluster`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html#method.cluster
[`HostHandle::alias`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html#method.alias
[`HostHandle::emit_metric`]: https://docs.rs/mcpg-plugin-sdk/latest/mcpg_plugin_sdk/struct.HostHandle.html#method.emit_metric
