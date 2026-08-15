# MCPG Feature Flags (`feature_flags:` block)

Operator-controlled strictness / compatibility toggles. Every flag
defaults off (= safe / standards-compliant); flipping one is an
explicit acknowledgement that the operator is taking on the risk
the default protects against.

The block is rooted at `feature_flags:` in `AppConfig`:

```yaml
feature_flags:
  allow_header_passthrough: false
  sep2260_panic_on_orphan: false
  debug_tools_enabled: false
```

## Why a typed block instead of `MCPG_*` env vars

Both flags below started life as `MCPG_*` env-var reads at the
call site. That pattern was easy to ship but missed three things:

- **Discoverability.** Env vars don't surface in the curated
  configuration reference, the JSON Schema, or `mcpg config explain`.
  Operators had to hunt through source.
- **Audit trail.** A flipped strictness gate is a
  compliance-relevant decision. Env vars vanish into the
  process environment; there's no record of which deployments
  override which defaults.
- **Reload semantics.** Env vars resolve once at process start.
  The rest of MCPG config rotates atomically on SIGHUP. Mixing
  the two surfaces means flipping a flag *requires* a restart,
  and a SIGHUP might leave the gateway running with a stale
  flag the operator thought they'd flipped.

moving these toggles into `feature_flags:` fixes all three:

- They show up in [`configuration.md`](configuration.md) as
  `feature_flags.<flag>` rows, in the JSON Schema for IDE
  autocomplete, and respond to
  `mcpg config explain feature_flags.<flag>`.
- The boot path emits a `mcpg.config.feature_flags_active` audit event
  whenever any flag is flipped off the safe default. Auditors
  reviewing the ledger see "this deployment runs with X
  overridden" without parsing the YAML themselves.
- Reload is honoured: `app::reload_config` re-installs the
  process-wide atomic mirror from the new config on every
  SIGHUP, so rotations land instantly.

## Flag reference

### `feature_flags.allow_header_passthrough` *(default `false`)*

When `true`, the gateway forwards credential-shaped inbound HTTP
headers (`Authorization`, `Proxy-Authorization`, `Cookie`,
`Set-Cookie`, `X-API-Key`, `X-Auth-Token`) to outbound bindings.
Default `false` strips these at egress and increments the
`mcpg_credential_header_stripped_total{header=…}` counter, with a
warn log explaining the strip.

**Set this to `true` only when** the deployment is intentionally
acting as a token-forwarding router (e.g. a pure pass-through to
an upstream that authenticates the same client tokens MCPG
receives). In any other shape, flipping it on means inbound
client tokens reach upstream bindings unfiltered — a credential
leak in waiting if a tool definition routes them somewhere
unexpected.

**Where it's read.** `runtime::execution::format_request_headers`
checks the runtime atomic mirror per outbound HTTP request. The
config-block value is read at boot and on each SIGHUP, then
mirrored into a `process_wide AtomicBool` (see
`runtime::feature_flags::ALLOW_HEADER_PASSTHROUGH`). Hot-path reads
cost one relaxed atomic load.

### `feature_flags.sep2260_panic_on_orphan` *(default `false`)*

When `true`, SEP-2260 violations (a server-initiated request emitted
without an originating client `request_id`) upgrade from a warn +
metric counter to a process panic.

SEP-2260 is the MCP spec rule that every server-initiated
request — pipeline elicitation prompt, sampling request, roots
list — must carry the originating client's request id so clients
can correlate the response back to the call that triggered it.
A violation indicates a routing bug in MCPG; in production we
prefer the metric path so a single misrouted pipeline doesn't
take the gateway down. In CI / dev where the violation indicates
a code defect, panicking gives loud immediate feedback.

**Set this to `true`** in CI gateways that exercise pipeline
suspension (elicitation / sampling / roots-list) or in dev
environments where you'd rather crash than suspect a downstream
correlation bug. Keep it `false` in production.

**Where it's read.** `runtime::execution::mint_server_request_id`
checks the atomic mirror; same boot/reload + atomic-load semantics
as above.

### `feature_flags.debug_tools_enabled` *(default `false`)*

When `true`, the gateway exposes the operator-defined diagnostic
tools (`mcpg.command.*` / `mcpg.network.*`) declared under the
top-level `debug:` block. When `false` (the default), every field
under `debug:` is ignored AND the debug tools are stripped from
the capability registry regardless of `debug.tools.exposure`.

The `debug:` block owns the *surface* (command profiles, network
probes, exposure rules); the master switch lives here, next to the
other strictness toggles, so all operator-controlled "what does this
gateway expose / strict-mode" decisions are in one place.

**Production deploys** keep this `false`. Diagnostic tools
disclose process / network surface that doesn't belong on a
public listener; flip on for CI / dev rollouts only.

**Where it's read.** `app::build_from_config` snapshots the flag
into `RuntimeDebugConfig.enabled`, which the runtime tool-call
dispatch consults at registration time. Reload re-snapshots, so a
SIGHUP-driven flip strips or registers the tools accordingly.

## Audit emission

When `feature_flags.any_active()` is true at boot or after a reload,
the gateway emits exactly one audit event:

```json
{
  "action": "mcpg.config.feature_flags_active",
  "resource": "config://gateway/feature_flags",
  "outcome": "success",
  "actor": { "kind": "system", … },
  "details": {
    "allow_header_passthrough": true
  }
}
```

`details` only contains the *non-default* flags. A deployment
running with both flags off produces no event — the ledger stays
quiet for the common case.

The event fires from `app::run` immediately after
`mcpg.lifecycle.gateway_started`. It's emitted via
`registry.emit_audit_event(...)` (best-effort), not enforced; the
existing `gateway_started` event already runs through the
`fail_closed` audit policy, so a missing audit sink is caught
there.

## Adding a new flag

Future strictness gates should land under `feature_flags:` rather than
new env-var reads. The recipe:

1. Add the field to `FeatureFlagsConfig` in
   `apps/gateway/src/config/feature_flags.rs` with `#[serde(default)]`
   and a doc-comment that explains *what flipping it on costs you*.
2. Extend `FeatureFlagsConfig::audit_details()` to surface the field
   in the audit event when it's non-default.
3. If the read site is in a hot path, add an `AtomicBool` mirror
   to `apps/gateway/src/runtime/feature_flags.rs`, push it from
   `install(...)`, and read via a free function. Cold paths can
   just take `&FeatureFlagsConfig` as an argument.
4. Add tests covering: default-off, audit-detail emission when
   on, YAML round-trip.
5. Regenerate the config doc + schema (`cargo run --bin
   mcpg-config -- doc`, `cargo run --bin mcpg-config -- schema`).

The audit event id (`mcpg.config.feature_flags_active`) does not change
— a single emission carries every active flag.

## SIGHUP / reload behaviour

`feature_flags:` is reload-safe. `app::reload_config` calls
`runtime::feature_flags::install(&new_config.feature_flags)` on every
SIGHUP, which atomically updates the process-wide mirror. Hot-path
readers see the new value on their next request. Operators
verifying a rotation can:

```bash
$ kill -HUP $(pidof mcpg)                          # rotate config
$ grep mcpg.config.feature_flags_active /var/log/mcpg/audit.jsonl  # confirm new flag set
```

A non-emitted event after a reload means either no flag changed
state, OR every flag is back at its default — both safe outcomes.

## See also

- [`configuration.md`](configuration.md#featureflagsconfig) — generated
  reference for the full `FeatureFlagsConfig` shape.
- [`hot-reload.md`](hot-reload.md) — `feature_flags` is in the
  reload-safe table; the runtime mirror is what makes that true.
