# Authoring MCP Servers with MCPG — Guide for AI Agents

> **Audience**: AI coding agents asked to produce a ready-to-deploy
> MCP server using MCPG as the runtime.
>
> **Goal**: zero handwritten server code. You describe the upstream
> system declaratively in an MCPG config YAML; MCPG handles MCP
> protocol, transport, auth, observability, cancellation, tasks,
> pipelines, plugin mediation, and everything else documented in
> `apps/gateway/docs/compliance/mcp-compliance.md`.

---

## Mental model

MCPG is a **protocol-authority gateway**. You do not write request
handlers, SSE machinery, session stores, JSON-RPC envelopes, or
capability negotiation. You write a YAML config that declares:

1. A **backend** per upstream capability (tool, prompt, resource,
   resource-template, or pipeline).
2. Optional **plugins** (identity, guardrails, payment, audit, webhook,
   cache).
3. **Server config** (`server:`, `auth:`, stores, observability).

For 95 % of real-world systems you need two backend types: **http** for
REST APIs and **command** for local CLIs. Pipelines stitch multiple
backends together when one upstream call is not enough.

---

## Backend model — what MCPG actually supports

### A backend is a static profile plus dynamic expressions

- `url`, `headers`, and (for command backends) `args[i]` are strings
  that may contain **CEL expressions** delimited by `${…}`.
- Any other field on a backend is a literal — the operator does not
  interpolate argument values into `timeout_ms`, `method`, etc.
- There is **no per-backend request-body template**. For HTTP POST/GET:
  - `method: post` — MCPG serialises the incoming tool `arguments`
    object as the JSON request body.
  - `method: get` — MCPG serialises the incoming `arguments` as a
    query string on the URL.
- Path parameters are expressed via CEL in the URL field, e.g.
  `url: "https://api.example.com/v4/domains/${arguments.zone}/records"`.

### Expression language

| Variable | Where | Example |
|---|---|---|
| `arguments.<key>` | Request time | `${arguments.zone}` |
| `tool_name` | Request time | `${tool_name}` |
| `context.principal_id` | Request time | `${context.principal_id}` |
| `context.session_id` | Request time | `${context.session_id}` |
| `context.transport` | Request time | `${context.transport}` |
| `env.VAR_NAME` | Startup (evaluated once at config load) | `${env.NAMECOM_TOKEN}` |
| `cred://<plugin_id>/<target>[#part]` | Request time (cached, auto-refreshed) | `cred://dev.mcpg.credential.oauth-client-credentials/analytics` |
| `steps.<id>.output` | Pipeline | `${steps.fetch.output.count}` |

A string field with no `${` marker is a literal pass-through. Use
concatenation (`"A" + x + "B"`) inside `${…}` when mixing literal
and dynamic segments.

---

## The four primitives

### Tool

Maps to MCP `tools/call`. `input_schema` defines the argument shape;
MCPG validates every call against it before dispatching.

### Prompt

Maps to MCP `prompts/get`. List it under `mcp.capabilities.prompts[]` and
declare `prompt_arguments`.

### Resource (exact)

Maps to MCP `resources/read` for a fixed URI. List it under
`mcp.capabilities.resources[]` and set `uri:`.

### Resource template

Maps to MCP `resources/read` for a URI matching an RFC 6570 template.
List it under `mcp.capabilities.resource_templates[]` and set `uri_template:`.

### Pipeline

Multi-step orchestration. Use `backend: { kind: pipeline }` with a list of `steps`.
Steps can call other backends, suspend for `elicitation` /
`sampling`, read `roots`, branch, retry, transform, and merge.

---

## Minimal HTTP backend

```yaml
mcp:
  capabilities:
    tools:
      - name: namecom.record.list
        title: "List DNS records"
        description: "List DNS records for a zone."
        annotations: { read_only: true, idempotent: true }
        input_schema:
          type: object
          required: [zone]
          properties:
            zone: { type: string, description: "Apex domain" }
        backend:
          kind: http
          url: "https://api.name.com/v4/domains/${arguments.zone}/records"
          method: get
          headers:
            Authorization: "Basic ${env.NAMECOM_BASIC_AUTH}"
            Accept: "application/json"
          timeout_ms: 10000
          expected_status_codes: [200]
          require_json_response: true
          max_response_bytes: 524288
```

Key points:

- The backend lives in a nested `backend:` block discriminated by `kind:`
  (`kind: http` / `command` / `sql` / `pipeline` / …) — NOT a flat `type:`.
- `annotations` uses bare keys: `read_only`, `destructive`,
  `idempotent` (no `_hint` suffix).
- Bindings live under `mcp.capabilities.tools[]` (or `prompts` / `resources` /
  `resource_templates`) — the list determines the capability type.
- Env-var substitution uses `${env.VAR}` — resolved once at
  startup; no client can influence it.

For POST, omit `query`-shaping concerns; MCPG sends `arguments` as
the JSON body. For GET, MCPG serialises args into the URL query.

---

## Minimal command backend

```yaml
mcp:
  capabilities:
    tools:
      - name: ios.simulator.boot
        title: "Boot an iOS simulator"
        description: "Boot a simulator by UDID."
        annotations: { idempotent: true }
        input_schema:
          type: object
          required: [device_udid]
          properties:
            device_udid: { type: string }
        backend:
          kind: command
          command: xcrun
          args:
            - simctl
            - boot
            - "${arguments.device_udid}"
          timeout_ms: 30000
          max_output_bytes: 65536
```

Key points:

- `command:` is the program name (never dynamic — security).
- `args:` is a list of strings. Individual entries may contain
  `${…}` expressions.
- Arguments are passed through `execve`; there is no shell
  interpolation, so templates cannot cause shell-injection.

---

## Resource template

```yaml
mcp:
  capabilities:
    resource_templates:
      - name: github.issue
        description: "Fetch a GitHub issue as a JSON resource."
        uri_template: "github://{owner}/{repo}/issues/{number}"
        mime_type: "application/json"
        variable_completions:
          owner: ["acme", "anthropic"]
          repo: ["mcpg", "agent"]
          # number: dynamic — no static completion list provided
        backend:
          kind: http
          url: "https://api.github.com/repos/${arguments.owner}/${arguments.repo}/issues/${arguments.number}"
          method: get
          headers:
            Authorization: "Bearer ${env.GITHUB_TOKEN}"
            Accept: "application/vnd.github+json"
          timeout_ms: 10000
          expected_status_codes: [200]
          require_json_response: true
```

The template variables (`{owner}`, `{repo}`, `{number}`) are extracted
from the incoming URI and exposed as `arguments.<var>`.

### Static auto-complete lists (`variable_completions`)

Per-variable static completion lists feed MCP `completion/complete`
on `ref/resource`: when an MCP client opens auto-complete on a
resource-template variable, the gateway returns the configured values
filtered by the caller's prefix (capped at 100 per response per MCP
2025-11-25). Keys MUST match a `{variable}` declared in `uri_template`;
mismatched keys are dropped at startup with a warning.

Match precedence mirrors prompt-argument completion: prefix matches
projected from `context.arguments` (already-filled-in values from
sibling variables) win first, then the static `variable_completions`
list, then dynamic backend dispatch (below). Variables without any
configured source omit the field entirely — they fall through to the
empty result.

### Dynamic completion (`kind: dynamic`)

Static lists scale to dozens of options; high-cardinality variables
(user IDs, file paths, issue numbers, …) need backend lookups. Declare
a variable as `kind: dynamic` and the gateway dispatches to the named
backend's `complete_template_variable` method at request time:

```yaml
mcp:
  capabilities:
    tools:
      - name: github-issues-sql
        description: "Internal binding the completion source delegates to."
        backend:
          kind: sql
          driver: postgres
          url: "postgres://${env.DB_URL}"
          query:
            sql: "SELECT 1"
            row_mode: scalar
    resource_templates:
      - name: github.issue
        description: "Fetch a GitHub issue as a JSON resource."
        uri_template: "github://{owner}/{repo}/issues/{number}"
        mime_type: "application/json"
        variable_completions:
          owner: ["acme", "anthropic"]      # static shorthand
          repo:                              # tagged static (same effect)
            kind: static
            values: ["mcpg", "agent"]
          number:                            # dynamic — backend lookup
            kind: dynamic
            backend: github-issues-sql
            config:
              query: |
                SELECT DISTINCT number::text
                  FROM github.issues
                 WHERE number::text LIKE :prefix || '%'
                 ORDER BY number
                 LIMIT 100
              max_results: 100
        backend:
          kind: http
          url: "https://api.github.com/repos/${arguments.owner}/${arguments.repo}/issues/${arguments.number}"
          method: get
          timeout_ms: 10000
          expected_status_codes: [200]
          require_json_response: true
```

The dynamic-source `backend` MUST resolve to a registered binding
name. Dangling references log a warning at boot and drop the entry —
the variable then falls through to the empty result at request time.
The gateway clamps results to 100 with `hasMore: true`. Backend
errors and timeouts (3s budget) degrade silently to empty: completion
is a UX hint, not load-bearing. SQL bindings own a `:prefix` named
parameter and return the first column of each row.

---

## Pipeline skeleton

```yaml
mcp:
  capabilities:
    tools:
      - name: ec2.reboot_confirmed
        title: "Reboot EC2 (confirmed)"
        description: "Elicit operator confirmation, then reboot."
        annotations: { destructive: true, idempotent: false }
        input_schema:
          type: object
          required: [instance_id]
          properties:
            instance_id: { type: string }
        backend:
          kind: pipeline
          steps:
            - id: confirm
              kind: elicitation
              mode: form
              message: "Reboot ${arguments.instance_id}? Active sessions will drop."
              requested_schema:
                type: object
                properties:
                  confirm: { type: boolean }
                required: [confirm]
              timeout_ms: 60000
            - id: do_reboot
              kind: command
              command: aws
              args: ["ec2", "reboot-instances", "--instance-ids", "${arguments.instance_id}"]
              timeout_ms: 30000
```

Pipeline steps are themselves backend calls (`http`, `command`, `sql_tx`, …) plus
control steps (`elicitation`, `sampling`, `cel_gate`, `gather`, `log`, …). See
`apps/gateway/docs/pipelines.md` for the full step grammar.

---

## Naming, hints, and safety

- **Name tools dotted + namespaced**: `dns.list_records`,
  `ios.simulator.screenshot`.
- **Annotations, not hints**: `read_only: true`, `idempotent: true`,
  `destructive: true`.
- **Credential flow**: upstream credentials come from `${env.VAR}`
  for static secrets, or from `cred://<plugin_id>/<target>` for
  any registered `credential_issuer` plugin. OAuth 2.0
  client-credentials uses the
  `dev.mcpg.credential.oauth-client-credentials` plugin — declare
  providers in its `plugins[].config.providers` map and
  reference issued tokens via
  `cred://dev.mcpg.credential.oauth-client-credentials/<name>`.
  Token caching, refresh, and stale-grace fallback live inside the
  plugin; the host adds a per-(identity, plugin, target) L1 cache.
  The gateway's egress guard strips credential-shaped headers by
  default, and `feature_flags.allow_header_passthrough` is the
  explicit escape hatch — do not use it in production.
- **MCP App URLs**: resource and resource-template backends support
  `mcp_app_url` to surface a rich UI link in `_meta.mcpAppUrl`.
  Supports CEL interpolation for dynamic URLs.
- **Timeouts**: set `timeout_ms` on every backend (default 30 s is
  too long for interactive use).
- **Long-running tools**: set `task_support: required` so the
  client gets a `Task` handle and polls `tasks/result`.

---

## Authoring procedure for AI agents

1. **Read the upstream docs end-to-end.**
2. **Enumerate operations**: 5–30 typed verbs the average user cares
   about. Skip admin-only endpoints unless the brief names them.
3. **Classify**: GETs with stable URL → resource template; GETs
   with filters → tool; writes → tool; multi-step / confirm-then-
   act → pipeline.
4. **Write `input_schema` rigorously**: typed, `required` explicit,
   `enum` where the set is closed, pattern constraints where known.
5. **Pick the backend `kind:`** (nested `backend:` block):
   - REST API / GraphQL JSON endpoint → `backend: { kind: http }`
   - CLI → `backend: { kind: command }`
   - Orchestration → `backend: { kind: pipeline }`
6. **Fill `url` / `args` with CEL** where dynamic segments are needed.
7. **Env-var credentials** via `${env.X}`, or declare a provider on
   the `dev.mcpg.credential.oauth-client-credentials` plugin entry
   and reference the token via
   `cred://dev.mcpg.credential.oauth-client-credentials/<name>` for
   automatic caching + refresh.
8. **Set annotations honestly** (read-only / idempotent / destructive).
8b. **Add `mcp_app_url`** on resource/resource-template backends when a
   rich UI exists for the resource.
9. **Validate**: `cargo run -p mcpg -- --config <file>.yaml` and run
   `tools/list` to confirm backends discover cleanly.
10. **Document env vars + example invocations** in a sibling README.

---

## Pitfalls

- A flat `type: http` on the binding, or a top-level `bindings:` key — **wrong**
  (the gateway rejects unknown fields at boot). Put the implementation in a
  nested, kind-discriminated `backend: { kind: http, url: …, method: … }` block
  under a `mcp.capabilities.tools[]` (or `prompts`/`resources`/`resource_templates`) entry.
- `backend: { http: { … } }` (kind as a nested key) — **wrong**. The kind is a
  `kind:` field: `backend: { kind: http, … }`.
- `{{ args.x }}` — **wrong**. MCPG uses `${arguments.x}` (CEL).
- `program:` — **wrong**. Use `command:`.
- `read_only_hint: true` — **wrong**. Use `read_only: true`.
- `kind: Tool` — **wrong**. Use `kind: tool` (snake_case).
- Per-backend body templates — **not supported**. MCPG sends
  `arguments` as the POST body verbatim.
- Shell interpolation in command `args` — **impossible by design**
  (`execve` passes each entry as a separate argv element).
- Forwarding the client's `Authorization` header to upstream — the
  T15-14 guard strips it. Use a service credential via `$env`.

---

## Where to read next

- `apps/gateway/docs/configuration.md` — full config schema and
  operator knob reference.
- `apps/gateway/docs/backends.md` — detailed reference for each
  backend type.
- `apps/gateway/docs/pipelines.md` — 18-kind pipeline grammar.
- `apps/gateway/docs/plugins.md` — plugin authoring and activation.
- `examples/` (repo root) — 25+ runnable example configs demonstrating
  each pattern.
- `apps/gateway/docs/compliance/mcp-compliance.md` — what the gateway
  guarantees on the wire.
