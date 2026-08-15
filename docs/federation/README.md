# MCP Federation — design & status

> MCPG connects **outbound** to one or more upstream MCP servers as a
> client, imports their tools / resources / resource-templates / prompts,
> and re-serves them through its own MCP endpoint under operator-chosen
> prefixes — with MCPG's full governance stack (trust, CEL, payment,
> guardrails, rate limits, observability) applied uniformly.
>
> Federation is also MCPG's **protocol-version adapter**: the wire served
> to each client and the wire spoken to each upstream are independent, and
> `upstream.protocol_version: auto` (default) detects the upstream's
> revision at connect — so one entry fronts a `2025-11-25` or `2026-07-28`
> remote for clients on either revision.
>
> 📖 **Operators:** start with the [**Federation Operator Guide**](./guide.md) —
> configuration reference, every auth mode + transport, runtime behaviour, best
> practices, and worked samples. This page documents the design decisions and
> current implementation status.

## Why v2

The original federation design was written April 2026 and **deferred**
behind three gates. Two have since cleared:

- ✅ **Stable plugin API / footprint** — the backend-plugin migration
  completed: every backend is now a runtime-loaded cdylib over the
  v38 C ABI, and the binding+watch split is battle-tested.
- ✅ **Binding/watch battle-tested at scale** — http/kafka/nats/sql/grpc/
  graphql/command/mock/LLMs all shipped as cdylibs.
- 🟡 **First stable (1.0) release** — still pre-1.0 (`v1.0.0-rc.N`). The
  one remaining gate.

But that same migration **invalidated the original design's core
architectural assumption.** v1 assumed in-process plugin traits (`libs/plugin-api`,
`bindings/mod.rs`, `BindingTypeConfig`, `PLUGIN_API_VERSION 1→2`, "five
traits"). Today the plugin boundary is a cdylib JSON-over-`RString` C ABI
(`libs/plugin-protocol`, `backends/mod.rs`, `BackendImpl`, ABI v38, ~21
entity kinds). A `FederationPlugin`-as-cdylib would have to express
long-lived stateful upstream sessions, a notification-listener task, and
bidirectional server-request bridging across an ABI built for
request/reply + fire-and-forget sinks. That is the wrong shape.

v2 re-grounds the design on the current code and settles that question.

## The headline decisions

| # | Decision |
|---|----------|
| D1 | The federation **engine** lives **in-gateway** (like `pipeline`), not as a cdylib plugin. The MCP-client *wire transport* may be factored behind a trait and optionally extracted to a cdylib later. **No new ABI/entity-kind/vtable for Phases 1–3.** |
| D2 | Runtime capability mutation = a **federated overlay** on `CapabilityRegistry`, owned by a **preserved-across-reload** federation engine. Not full rebuild-and-swap (would cycle the upstream sessions), not in-place mutation of the native slice. |
| D3 | Config: a new **`mcp.federations: [...]`** list (a *capability source*), not an `mcp.capabilities.tools[]` entry and not `backend: { kind: mcp }`. |
| D4 | Upstream protocol version: **strict by default, negotiated opt-in, never translate.** MCPG-as-client speaks the versions it already implements as server. |
| D5 | **Per-client satellite** upstream sessions, lazy, instance-local; reuse `PipelineStore` for bridge state + cross-instance resume. |
| D6 | The "expand one source → N synthetic capabilities under a prefix" mechanism is a **single shared primitive** with the OpenAPI-import path; build it once. |

## Phase 1 implementation status

Implemented + tested (full gateway lib suite green, plus 3 federation
end-to-end tests):

- **Config** — `mcp.federations: [...]` (`config/federation.rs`) + cross-validation.
- **Outbound MCP client** — `McpUpstream` / `StreamableHttpUpstream`
  (`runtime/federation/upstream.rs`): initialize, tools/list, tools/call over
  Streamable HTTP with the net-core-style DNS-rebinding guard + capped body reads.
- **Capability import + overlay** — `FederationEngine::import_all` →
  `CapabilityRegistry` federated overlay (D2); federated tools surface in
  `tools/list`, prefixed + source-tagged in `_meta`.
- **Dispatch** — `BackendInvocationRoute::Federated` → engine `call_tool` via
  per-client satellites (D5), bridged onto the sync dispatch path.
- **Live wiring** — `GatewayRuntime::wire_federations` builds + attaches the
  engine at boot and on config reload, with a background idle-satellite sweeper.
- **Governance inheritance** — federated tools enforce their federation's
  `governance.minimum_trust` / `allow_if` via the policy gate's federated
  overlay (`PreDispatchPolicyGate` is now overlay-aware), so a federated call is
  gated exactly like a native one. CEL is compiled once at import time.
- **Auth modes** — `none`, `service_token`, and `pass_through` (the inbound
  caller bearer is captured at the transport into a serde-skipped
  `RequestContext` field and forwarded to the satellite).
- **Carry-across-reload preservation** — on config reload the capability +
  governance overlays are seeded from the prior runtime (no flicker / no
  governance gap), live upstream sessions for unchanged federations are carried
  to the new engine (`adopt_satellites`; changed/removed ones re-establish), and
  the upstream re-import is skipped when the federation config is unchanged.
- **End-to-end tests** — `tests/federation_e2e.rs`: list + dispatch + source
  tagging against a mock upstream; governance denial (a `verified`-only
  federation, anonymous caller); and **one MCPG federating another real MCPG
  instance** (exercising both the serving and client sides).

Phase-2+ surfaces (`list_changed`, notification forwarding, resources / prompts,
server-request bridging) are tracked in the progress section below.

Reload preservation is verified by `adopt_satellites_carries_only_unchanged_federations`
(carry-vs-drop) and `adopted_satellite_is_reused_without_reconnecting` (the carried
session is reused — no second upstream `initialize`). A full HTTP-driven
`reload_config` e2e is impractical: that path rebuilds the plugin registry
(environment-fragile — cf. `admin_reload_e2e`) and the per-federation SSE listener's
reconnect loop makes a global initialize count non-deterministic, so the guarantee is
verified deterministically at the engine-integration level instead.

## Phase 2 progress

- **Resources import + read** ✅ — `import.resources` federates upstream
  resources; they list (prefixed via `resource_uri_prefix`, source-tagged in
  `_meta`) and `resources/read` dispatches to the upstream via the per-client
  satellites. e2e: `federated_resource_is_listed_and_read_end_to_end`.
- **Prompts import + get** ✅ — `import.prompts` federates upstream prompts;
  they list (prefixed via `prompt_prefix`, source-tagged in `_meta`) and
  `prompts/get` dispatches to the upstream via the per-client satellites. e2e:
  `federated_prompt_is_listed_and_fetched_end_to_end`.
- **Resource-templates import** ✅ — `import.resource_templates` federates upstream
  templates; they list via `resources/templates/list` (prefixed via
  `resource_uri_prefix`, source-tagged in `_meta`). A concrete URI the client
  expands from the template is matched at read time, de-prefixed back to the
  upstream URI, and dispatched through the existing federated-resource read path
  (no new route variant). e2e: `federated_resource_template_is_listed_and_read_end_to_end`.
- **`oauth_client_credentials` auth** ✅ — federation rides the gateway's existing
  credential-issuer subsystem. `auth.mode: oauth_client_credentials` +
  `auth.credential: cred://<plugin_id>/<target>`; at connect the engine looks up the
  issuer plugin and `get_or_issue`s a cached, auto-refreshed machine token (shared
  per `(plugin_id, target)` via a fixed machine identity — the grant is
  identity-independent). No client secret lives in the federation config. The engine
  gets the credential subsystem via `with_credentials` (wired from the runtime, which
  already holds `plugin_registry` + `credential_cache`). Test:
  `oauth_client_credentials_mints_bearer_for_upstream` + config validation tests.
- **`oauth_impersonation` auth** ✅ — same credential-issuer subsystem, but the engine
  passes the *caller's* identity (carrying the inbound bearer as the RFC 8693
  `subject_token` in `attributes`) instead of the machine identity, so the issuer
  exchanges the caller's token for an upstream one (per-caller, host-cached). Backed by
  the `dev.mcpg.credential.oauth-token-exchange` issuer plugin. Import/listen (no caller) list
  anonymously, like `pass_through`. Tests:
  `oauth_impersonation_exchanges_caller_bearer_for_upstream` + config validation.
- **`list_changed` runtime refresh + notification forwarding** ✅ — a persistent
  per-federation listener opens the upstream's server→client SSE stream (GET) and
  reacts to pushes: on `notifications/{tools,resources,prompts}/list_changed` it
  refreshes the overlay (re-import) and broadcasts the same `list_changed` to MCPG's
  operational clients; on `notifications/resources/updated` it re-prefixes the URI
  and forwards it to that resource's subscribers. Listener tasks are `Weak`-held
  (exit on engine drop) with capped reconnect backoff. Decoupled from delivery
  internals via a `FederationNotifier` (session_store + delivery_bus +
  subscription_store) wired from the runtime. Tests:
  `listener_reimports_on_upstream_list_changed`,
  `resource_updated_is_reprefixed_and_forwarded_to_subscriber`.
- **Per-federation incremental re-import** ✅ — a `list_changed` (or TTL refresh)
  re-imports just the signaling federation via `reimport_one` + `republish`
  (rebuilds the overlay from a per-federation import cache), preserving every
  other federation's capabilities instead of re-listing all upstreams. Test:
  `reimport_one_preserves_other_federations`.
- **`capability_ttl_secs` poll-refresh** ✅ — `spawn_refreshers` runs one
  `Weak`-held timer per federation that re-imports every
  `cache.capability_ttl_secs` as a fallback for upstreams without a standalone
  SSE stream.

## Phasing (unchanged from v1, re-anchored)

1. **P1 (MVP)** — tools only, HTTP Streamable upstream, per-client
   satellites, auth `none`/`service_token`/`pass_through`, TTL refresh,
   no bridging.
2. **P2** — resources / templates / prompts, `resources/updated`
   forwarding, `*/list_changed` runtime refresh, OAuth auth modes.
3. **P3** — server-initiated request bridging (sampling / elicitation /
   roots), progress forwarding.
4. **P4** — stdio + legacy-SSE upstream transports, wildcard per-tenant.

Each phase is independently shippable behind a feature flag.
