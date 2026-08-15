# mcp-apps

Demonstrates **SEP-1865 MCP Apps** — interactive HTML UIs that a host (Claude Desktop, VS Code Copilot, …) renders inside a sandboxed `<iframe>` and drives over a `postMessage` protocol. Pair with this when the goal is "front Apps-capable servers through the gateway" or "serve my own UI-enabled tools".

It covers two postures: **proxy** (front Apps-capable tools/servers) and **templated** (let the gateway author the UI from config). The user-facing guide is at [mcpg.dev/docs/gateway/mcp-apps](https://mcpg.dev/docs/gateway/mcp-apps).

## What MCPG actually does

MCP Apps adds **no new MCP-wire methods**. The `ui/*` traffic is host↔iframe and never reaches the gateway; the action proxy (iframe → host → `tools/call`) re-enters through the ordinary `tools/call` arm and runs the full plugin pipeline (no app exemption). So MCPG's job is four things, all configured by the `mcp.configurations.apps` block:

1. **Passthrough** — `_meta.ui` on tool/resource descriptors and `resources/read` content survives unchanged; the `text/html;profile=mcp-app` mime type is preserved byte-exact.
2. **Capability advertisement** — `io.modelcontextprotocol/ui` is advertised **downstream** (to clients, so they enable Apps) and **upstream** (to federated servers, so they emit UI tools at all).
3. **Federation consistency** — a federated tool's `_meta.ui.resourceUri` and its `ui://` resource are rewritten in lockstep, keeping the `ui://` scheme: `ui://srv/widget` → `ui://partner/srv/widget`.
4. **Operator policy** — the upstream-declared CSP is **intersected** (never widened) with `csp_policy`, requested iframe permissions are stripped to `allowed_permissions`, and out-of-list sandbox `domain`s are dropped (or, with `strict: true`, rejected).

## What's in it

- A **native UI-enabled tool** (`analytics.chart`) whose `descriptor_meta.ui.resourceUri` points at a `ui://` resource, plus the `ui://analytics/chart` resource that serves the HTML + its `_meta.ui` (CSP + permissions).
- A **federation** (`partner`) showing how upstream UI tools are pulled in (`federate_upstream: true`) and re-served under a prefix with their `ui://` references rewritten automatically.
- A fully-annotated `mcp.configurations.apps` block — the canonical reference for every knob.

## What to change

- **`enabled`.** The master switch. `false` (default) = no advertisement, no policy, but `_meta.ui` still passes through. `true` lights up advertisement + the egress policy.
- **`federate_upstream`.** Leave it inheriting `enabled` unless you want to pull UI tools from upstreams without advertising Apps to your own clients (then set it `true` while `enabled: false`).
- **`csp_policy`.** Tighten-only. `["*"]` = no bound on that axis; a concrete list narrows the upstream's declared origins to the intersection; an omitted upstream axis is left to the host's restrictive default. Start permissive and ratchet down.
- **`allowed_permissions`.** Drop what your hosts shouldn't grant. This example allows only `clipboard_write`.
- **`strict`.** Turn on in locked-down deployments to reject (not just sanitize) a response whose `_meta.ui` escapes the policy.

## Templated apps

The `mcp.configurations.apps.registry` block is the second posture: instead of authoring HTML, you describe an app and the gateway mints `ui://mcpg/<id>` from a reviewed, per-`kind` shell. This example registers four:

- **`customers`** (`table`) over `crm.list`, with a per-row `open` action that re-enters as `crm.get`.
- **`account`** (`detail`) — a spec sheet for one `crm.get` result.
- **`new-account`** (`form`) — uiSchema groups/widgets; Submit calls `crm.create` via `tools/call`.
- **`revenue`** (`chart`) — a zero-network bar chart over `fin.revenue`.

The four `crm.*` / `fin.*` tools are `mock` bindings with `passthrough: true`, so their `structuredContent` reaches the shell verbatim and the apps render real rows in a host. Swap them for real backends (`sql`, `http`, a federated server) and the bindings are unchanged. Columns/fields are derived from a tool's `inputSchema`/`outputSchema` when omitted; explicit config always wins. Authored apps are still clamped by the same `csp_policy` / `allowed_permissions` as proxied ones, and `ui://mcpg/*` is a reserved gateway authority an upstream can't shadow.

## Verifying

- `server/discover` (modern wire) / `initialize` (legacy) advertises `capabilities.extensions["io.modelcontextprotocol/ui"].mimeTypes = ["text/html;profile=mcp-app"]` when `enabled: true`.
- `resources/list` includes `ui://mcpg/customers`, `…/account`, `…/new-account`, `…/revenue` (mimeType `text/html;profile=mcp-app`); `resources/read` of any returns the rendered shell with a `mcpg-app-config` data island and a clamped `_meta.ui`.
- `resources/read` of `ui://analytics/chart` returns the HTML with `_meta.ui.csp.connectDomains` already narrowed to the operator allow-list, and `clipboardWrite` retained while any other permission is stripped.
- Render end-to-end against the upstream `ext-apps` examples in a host that supports Apps (e.g. Claude Desktop) with this gateway in front.

Metrics emitted while policy runs: `mcpg_apps_csp_intersected_total{axis}`, `mcpg_apps_permission_stripped_total{permission}`, `mcpg_apps_domain_dropped_total`.
