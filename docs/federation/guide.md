# MCP Federation — Operator Guide

Federation makes MCPG act as an **MCP client to other MCP servers** and
re-serve their tools, resources, resource-templates, and prompts to *your*
clients under your own names, governance, and auth — a single MCP endpoint that
aggregates many upstreams.

This guide is operator-facing: configuration, every auth mode and transport,
runtime behaviour, and best practices, with copy-pasteable samples. For the
design rationale, headline decisions, and implementation status see
[`README.md`](./README.md#the-headline-decisions).

---

## 1. How it works (the one-paragraph model)

Federation is **in-gateway** (not a plugin — see [decision D1](./README.md#the-headline-decisions)).
At boot, the engine connects to each configured upstream, lists its
capabilities, and publishes them as **synthetic capabilities** into a
runtime-mutable overlay on the gateway's `CapabilityRegistry`. To your clients
they look native: they appear in `tools/list` / `resources/list` / etc. under
your prefixes, tagged with their source in `_meta`, and enforce *your*
governance. A `tools/call` (or resource read / prompt get) for a federated
capability is dispatched to the owning upstream over a **per-client satellite
session** and the result returned. Upstream changes (`list_changed`,
`resources/updated`) are forwarded to your clients, and upstream
server-requests (sampling / elicitation / roots) + progress are bridged through
to the real client and back.

```
  client ──MCP──▶  MCPG  ──MCP──▶  upstream A (HTTP)
                    │     ──MCP──▶  upstream B (stdio child)
                    └ native tools + federated tools, one endpoint
```

---

## 2. Quick start

Federate one HTTP upstream's tools, namespaced under `notion.`:

```yaml
mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
      import:
        tools: true
      naming:
        tool_prefix: "notion."
```

Boot MCPG; `tools/list` now includes `notion.search`, `notion.create_page`, …
and `tools/call` for them is proxied to the upstream. That's it — no auth (the
upstream is public), default governance (inherits the gateway default trust).

---

## 3. Configuration reference

Federations live under `mcp.federations: []`. Every field of one entry:

```yaml
mcp:
  federations:
    - name: notion                  # REQUIRED. Source id + default prefix namespace.
                                     #   Must be unique; must not shadow a native binding.

      governance:                   # Inherited by EVERY synthetic capability (like a native binding).
        minimum_trust: verified     #   unauthenticated | header_asserted | verified  (default: gateway default)
        allow_if: "identity.has_group('notion-users')"   # optional CEL; same engine as native per-tool rules

      retry:                        # optional; upstream call retry
        max_attempts: 2
        backoff_ms: 500

      upstream:
        url: https://notion-mcp.example.com/mcp   # required for streamable_http; omit for stdio
        transport: streamable_http  # streamable_http (default) | stdio
        protocol_version: auto      # MCP wire MCPG speaks AS A CLIENT to this upstream.
                                     #   auto (default; probe server/discover, fall back to the
                                     #   legacy initialize handshake, cache the detected wire) |
                                     #   2025-11-25 (pin the session-bound handshake) |
                                     #   2026-07-28 (pin the stateless modern wire: no handshake /
                                     #   Mcp-Session-Id, per-request _meta identity, SEP-2243
                                     #   routing headers).
                                     #   2026-07-28 is only honored on streamable_http (rejected
                                     #   on stdio); auto on stdio resolves to legacy, no probe.

        # stdio transport only:
        command: my-mcp-server      # the child process to spawn
        args: ["--stdio"]
        env: { API_TOKEN: "${env.UPSTREAM_TOKEN}" }

        auth:
          mode: none                # none | service_token | pass_through
                                    #   | oauth_client_credentials | oauth_impersonation
          token: "${env.SVC_TOKEN}"            # for service_token
          credential: "cred://<plugin_id>/<provider>"   # for the oauth_* modes

        upstream_safety:
          allow_private_backends: false   # permit private/loopback upstream addresses (SSRF guard)
          allow_insecure_http: false      # permit http:// (non-TLS) upstreams
          allow_stdio: false              # permit the stdio transport (local process exec) — default-deny

      import:                       # which surfaces to import (at least one true)
        tools: true                 #   default true
        resources: false
        resource_templates: false
        prompts: false

      naming:                       # prefixes applied to imported names/URIs (collision-avoidance)
        tool_prefix: "notion."
        resource_uri_prefix: "mcp://notion/"
        prompt_prefix: "notion."

      filter:                       # glob filter on imported TOOL names
        include_tools: ["*"]        #   default ["*"]
        exclude_tools: ["internal_*"]

      cache:
        capability_ttl_secs: 300    # poll-refresh interval (re-list even without a push); default 300

      synthesize:                   # change-notification synthesis for push-less upstreams
        resources_updated: auto     #   auto (default; poll only when the upstream can't push:
                                    #   modern wire / stdio) | poll (always) | off (never)
        poll_interval_ms: 30000     # poll cadence; subscriber-gated (no subscribers → no polling)

      session:
        mode: per_client            # per_client (default). `shared` not yet supported.
        idle_timeout_secs: 600      # idle satellite teardown; default 600

      response:
        max_response_bytes: 2097152 # per-call upstream response cap; default 2 MiB
```

Validation runs at boot and on reload; a bad federation fails fast with a
precise message. Names + prefixes must be unique across federations and must
not shadow native bindings.

### Auto-federating an MCP registry (`mcp.registries`)

Instead of hand-writing one federation per server, point MCPG at an MCP
registry (the standard `/v0.1` API — the official registry or an
enterprise sub-registry) and a background syncer materializes one
federation per usable server, kept in sync as the registry changes
(added servers appear, `deleted` servers are removed, `deprecated`
follows your policy — clients see `list_changed` either way):

```yaml
mcp:
  registries:
    - name: acme                      # prefixes every synthesized federation name
      url: https://registry.acme.internal
      auth: { mode: bearer, token: "${env.REGISTRY_TOKEN}" }   # none | bearer | headers | cred
      registry_safety:
        allow_private_registry: true  # a private registry URL is an explicit opt-in
      sync:
        interval_secs: 300            # crawl cadence (floor 30)
        max_servers: 100              # hard cap; excess skipped (name-sorted)
        incremental: false            # opt-in updated_since delta crawls
        full_resync_hours: 24         # full-crawl backstop when incremental
      filter:
        namespaces: [com.acme]        # publisher-namespace allowlist (anti-typosquat)
        include: ["*"]                # exact or trailing-* globs on server names
        exclude: ["com.acme/experimental-*"]
      on_deprecated: serve_and_warn   # | exclude
      defaults:                       # applied to every synthesized federation
        governance: { minimum_trust: verified }
        upstream_safety: { allow_private_backends: true }  # internal remotes opt-in
        auth: { mode: pass_through }
      servers:                        # per-server overrides, keyed by registry name
        "com.acme/crm":
          version: "2.3.1"            # pin (default: track latest)
          variables: { tenant_id: acme-prod }   # remote-URL {variable} values
          headers: { X-API-Key: "${env.CRM_KEY}" }  # declared request headers
```

The rules that keep this safe: synthesized federations always get a
unique per-server `tool_prefix` (derived from the reverse-DNS server
name, e.g. `com.acme.crm.`); operator-authored federations win on any
name/prefix collision; and the registry cannot relax transport security
— stdio, insecure HTTP, and `tunnel://` stay denied regardless of what
it lists, with `allow_private_backends` an explicit per-registry opt-in.
Servers whose remote declares required URL variables or secret headers
you have not supplied are skipped and reported
(`mcpg_registry_server_skipped_total{reason}`), as are packages-only
entries (npm/pypi/oci installables are a provisioning concern, not an
auto-federation one). Each synthesized upstream uses
`protocol_version: auto`, so legacy and modern registry servers both
work without per-server wire config.

#### Per-server credentials without per-server config

`{server}` in a synthesized federation's `auth.credential` expands to
the registry server name, and the ID-JAG / token-exchange issuers
accept a `target_template` block that derives a provider per target —
so one issuer block covers the whole fleet:

```yaml
mcp:
  registries:
    - name: acme
      url: https://registry.acme.internal
      # The registry itself can authenticate through an issuer too:
      # the crawl bearer is minted under the gateway's machine identity.
      auth: { mode: cred, credential: "cred://dev.mcpg.credential.oauth-client-credentials/registry" }
      defaults:
        auth:
          mode: oauth_impersonation   # per-caller Cross-App Access
          credential: "cred://dev.mcpg.credential.oauth-id-jag/{server}"

plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    config:
      target_template:
        allowed_targets: ["com.acme/*"]   # fail-closed: only these expand
        idp_token_url: https://idp.acme.example/oauth2/token
        client_id: mcpg-fleet
        client_secret: ${env.IDP_SECRET}
        audience_template: "https://{target}.mcp.acme.internal"
        redeem_token_url_template: "https://{target}.mcp.acme.internal/oauth2/token"
```

For each caller and server, the issuer exchanges the caller's bearer
(RFC 8693) for an ID-JAG assertion with the server's expanded audience,
then redeems it (RFC 7523) at the server's expanded token endpoint. An
exact `providers` entry always beats the template, and targets outside
`allowed_targets` fail closed. `oauth-token-exchange` supports the same
`target_template` shape (`token_url` + `audience_template` /
`resource_template`) for single-hop STS fleets.

#### OAuth discovery (`defaults.oauth_discovery`)

When each server's authorization server is not known a priori, let the
syncer discover it (the client half of MCP authorization):

```yaml
mcp:
  registries:
    - name: acme
      url: https://registry.acme.internal
      defaults:
        oauth_discovery: { enabled: true }
        auth:
          mode: oauth_impersonation
          credential: "cred://dev.mcpg.credential.oauth-id-jag/{server}"
```

At sync time MCPG fetches each OAuth-mode server's RFC 9728
protected-resource metadata (on the server's own URL; the document's
`resource` must round-trip exactly) and the advertised authorization
server's RFC 8414 metadata (issuer must round-trip), then injects the
derived values onto the synthesized federation as
`upstream.auth.credential_config` —
`{audience, resource, redeem_token_url}` — which the engine forwards to
the credential issuer on every issuance (the template issuers' per-call
overrides). Both fetches are SSRF-guarded like the crawl itself:
https-only, pinned DNS, private addresses only under
`upstream_safety.allow_private_backends`. If discovery fails for a
server, its previously discovered metadata is reused; a server with no
discovered metadata at all is skipped
(`mcpg_registry_server_skipped_total{reason="oauth_discovery"}`).

`credential_config` is an ordinary federation field too — a
hand-written federation can pin it explicitly (and a
`servers.<name>.auth` override carrying one bypasses discovery):

```yaml
mcp:
  federations:
    - name: crm
      upstream:
        url: https://crm.acme.example/mcp
        auth:
          mode: oauth_impersonation
          credential: "cred://dev.mcpg.credential.oauth-id-jag/crm"
          credential_config:
            audience: https://crm.acme.example/mcp
            redeem_token_url: https://as.crm.acme.example/oauth2/token
```

Note: the host credential cache keys on `(identity, plugin, target)` —
after a re-discovery changes the metadata, already-cached tokens serve
until their TTL expires.

#### Clustered deployments and incremental crawls

In a clustered gateway (a real cluster coordinator bound), exactly one
replica crawls the registries — leadership role `gateway.registry_sync`,
lease-renewed each tick — and publishes the synthesized overlay to the
coordinator KV (`registry_sync/overlay`). The other replicas adopt that
snapshot instead of crawling, and every replica warm-starts from it at
boot, so a restart serves registry federations before its first crawl
completes. Single-node deployments are unchanged (no leadership
traffic, no KV).

`sync.incremental: true` switches steady-state crawls to
`updated_since=<watermark>` deltas (the watermark is the max `updatedAt`
the registry has published; deletions bump `updatedAt`, so tombstones
arrive in deltas too), with a full crawl every
`sync.full_resync_hours` as the backstop. Incremental engages only once
the registry actually publishes `updatedAt` timestamps — otherwise
every crawl stays full.

#### Serving a registry view of the gateway (`mcp.registry`)

MCPG can also be the registry: an opt-in v0.1 surface publishing ONE
entry — this gateway — so registry-driven client policies (e.g.
Copilot's allowed-registry setting) resolve to exactly "the approved
server is MCPG", and every tool behind it stays governed:

```yaml
mcp:
  # `registries` = the registries mcpg CONSUMES (auto-federation);
  # `registry`   = the registry mcpg SERVES (this gateway as catalog).
  registry:
    enabled: true
    name: com.acme/gateway        # reverse-DNS, required
    description: Governed MCP catalog
    # url defaults to governance.access.resource_metadata.resource
    url: https://gw.acme.example/mcp
```

Serves `GET /v0.1/servers` (standard `{servers, metadata}` envelope)
and `GET /v0.1/servers/{name}/versions/{latest|version}` — the
three-endpoint contract registry clients consume. The entry carries a
`streamable-http` remote at the canonical URL, the gateway's version,
and an active/`isLatest` official `_meta` block.

---

## 4. What gets imported, and how it's named

`import.*` selects surfaces; **`naming.*` prefixes** keep federated capabilities
from colliding with native ones (or with each other):

| Surface | `import` flag | Prefixed by | Dispatched via |
|---|---|---|---|
| Tools | `tools` | `tool_prefix` | `tools/call` |
| Resources | `resources` | `resource_uri_prefix` | `resources/read` |
| Resource templates | `resource_templates` | `resource_uri_prefix` | `resources/read` (URI matched, de-prefixed) |
| Prompts | `prompts` | `prompt_prefix` | `prompts/get` |

Every federated capability carries `_meta.mcpg.source.federatedFrom: "<name>"`
so clients (and your audit) can see where it came from. The original upstream
name/URI is preserved on the dispatch route, so the upstream always sees its own
un-prefixed names.

Resource templates are special: the client expands a `uriTemplate` into a
concrete URI you've never registered, so at read time MCPG matches the URI
against the federated template, strips the prefix, and dispatches the upstream
URI — no separate route type.

---

## 5. Filtering tools

`filter` is a minimal glob (`*` = all, `prefix*` = prefix glob, exact otherwise)
applied to **upstream tool names** before prefixing:

```yaml
filter:
  include_tools: ["search*", "read_*"]   # only these import
  exclude_tools: ["*_admin", "delete_*"] # …minus these (exclude wins)
```

Use it to expose a safe subset of a powerful upstream.

---

## 6. Governance inheritance

A federation's `governance` block applies to **every** capability it imports,
exactly as if you'd written it on a native binding:

- **`minimum_trust`** — `unauthenticated` < `header_asserted` < `verified`. A
  caller below the bar can't call the federated tool — and the tool is **hidden
  from `tools/list`** for that caller (visibility honours trust).
- **`allow_if`** — a CEL expression evaluated per call against the caller's
  identity (groups, roles, claims). Same engine and semantics as native
  per-tool `allow_if`.

```yaml
governance:
  minimum_trust: verified
  allow_if: "identity.has_group('notion-users') && !request.tool.endsWith('.delete_page')"
```

This is enforced at dispatch by the same `PreDispatchPolicyGate` that guards
native tools — federation is not a governance bypass.

---

## 7. Authenticating to the upstream

`upstream.auth.mode` picks how MCPG presents itself (or the caller) to the
upstream:

### `none`
No `Authorization` sent. For public or network-trusted upstreams.

### `service_token`
A static bearer MCPG presents as itself. Source it from a secret, never inline:

```yaml
upstream:
  auth:
    mode: service_token
    token: "${env.JIRA_SERVICE_TOKEN}"
```

### `pass_through`
Forward the **inbound caller's** `Authorization` bearer verbatim. The bearer is
captured per request in memory only — never persisted to the pipeline store or
logged. At import/listen time (no caller) the upstream is listed anonymously.

```yaml
upstream:
  auth: { mode: pass_through }
```

Use when the upstream already understands your clients' tokens.

### `oauth_client_credentials` — machine identity
MCPG mints a machine token via the gateway's **credential-issuer subsystem**
and presents it. `credential` is a `cred://<plugin_id>/<provider>`
URI pointing at a configured `oauth-client-credentials` issuer. The token is
cached + auto-refreshed; no client secret lives in the federation config.

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-client-credentials
    config:
      providers:
        notion:
          token_url: https://auth.notion.example.com/oauth/token
          client_id: mcpg-gateway
          client_secret: "${env.NOTION_CLIENT_SECRET}"
          scopes: ["read", "write"]

mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
        auth:
          mode: oauth_client_credentials
          credential: cred://dev.mcpg.credential.oauth-client-credentials/notion
```

The same token is shared across all callers (the grant is identity-independent).

### `oauth_impersonation` — on-behalf-of the caller
MCPG exchanges the **caller's** inbound bearer for an upstream token (RFC 8693
token exchange), so the upstream sees the *end user*. Backed by the
`oauth-token-exchange` issuer plugin. Per-caller (cached per caller); at
import/listen (no caller) the upstream is listed anonymously, like
`pass_through`.

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    config:
      providers:
        notion:
          token_url: https://sts.example.com/oauth/token   # the STS
          client_id: mcpg-gateway
          client_secret: "${env.STS_CLIENT_SECRET}"        # optional
          audience: https://notion-mcp.example.com

mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-token-exchange/notion
```

> **Security review for impersonation:** the exchanged token is *user-scoped* —
> vet the STS audience/scope and the `minimum_trust` you require before enabling
> it against an upstream. Subject + exchanged tokens stay inside the issuer
> plugin and are never logged.

Impersonation requires a **verified** caller: the issuer plugins refuse
anonymous and header-asserted identities, so only callers that passed
cryptographic verification (OIDC, JWKS, or the embedded EMA
authorization server) can be exchanged on-behalf-of.

#### Cross-App Access (ID-JAG) upstreams

When the upstream MCP server sits behind an authorization server that
supports the MCP *Enterprise-Managed Authorization* extension (Cross-App
Access), use the `oauth-id-jag` issuer instead: it performs the two-hop
flow — RFC 8693 token exchange at your **enterprise IdP** for an
Identity Assertion JWT Authorization Grant
(`requested_token_type: urn:ietf:params:oauth:token-type:id-jag`,
`audience` = the upstream's authorization server), then RFC 7523
jwt-bearer redemption of that grant at the upstream's token endpoint.
The enterprise IdP's admin policy decides which users may reach the
upstream at all; the upstream's authorization server still applies its
own scope policy.

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    config:
      providers:
        partner:
          idp_token_url: https://acme.okta.com/oauth2/v1/token   # enterprise IdP
          client_id: mcpg-gateway
          client_secret: "${env.OKTA_MCPG_CLIENT_SECRET}"
          audience: https://auth.partner.example                 # upstream's AS issuer
          resource: https://mcp.partner.example                  # upstream MCP server
          scopes: ["tools:invoke"]
          redeem_token_url: https://auth.partner.example/oauth/token

mcp:
  federations:
    - name: partner
      upstream:
        url: https://mcp.partner.example/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/partner
```

### Choosing
| Want | Mode |
|---|---|
| Public upstream | `none` |
| One shared machine credential | `service_token` or `oauth_client_credentials` |
| Auto-refreshing machine OAuth token | `oauth_client_credentials` |
| Upstream understands your clients' tokens | `pass_through` |
| Upstream must see the end user (per-user authz/audit) | `oauth_impersonation` |
| Enterprise-governed upstream (Cross-App Access / ID-JAG) | `oauth_impersonation` + `oauth-id-jag` issuer |

---

## 8. Transports

### `streamable_http` (default)
Modern MCP Streamable HTTP (`POST` + SSE). All HTTP upstreams go through the
gateway's **DNS-rebinding / SSRF guard**: the upstream host is resolved + pinned
to a validated public address. Private/loopback addresses and `http://` are
rejected unless explicitly permitted:

```yaml
upstream:
  url: http://127.0.0.1:8931/mcp
  upstream_safety:
    allow_private_backends: true   # needed for loopback / RFC-1918
    allow_insecure_http: true      # needed for http://
```

A loop-detection header (`Mcpg-Upstream-Via`) is sent on every upstream request
so an MCPG-federates-MCPG topology can detect cycles.

### `stdio`
Federate a **local MCP server run as a child process** (JSON-RPC over the
child's stdin/stdout). This spawns an arbitrary local process, so it's a
different threat model than HTTP and is **default-deny**: you must set
`allow_stdio: true`.

```yaml
upstream:
  transport: stdio
  command: /usr/local/bin/my-mcp-server
  args: ["--stdio"]
  env: { API_TOKEN: "${env.UPSTREAM_TOKEN}" }
  upstream_safety:
    allow_stdio: true
```

`url` is unused for stdio. The child is reaped on shutdown / reload. (stdio has
no separate notification channel, so `*/list_changed` pushes between calls are
picked up on the next call or the TTL refresh, not in real time.)

### `tunnel://` — reverse federation

Federate a **same-org gateway that dials out to an MCPG-Cloud relay** instead of
exposing a public endpoint. The private gateway keeps its secrets on its own
infrastructure; a same-org cloud gateway reaches it *by name* through the
relay's federation ingress. Nothing about the private side is publicly routable.

The private gateway runs with an egress tunnel (`gateway.server.tunnel`, or
`mcpg --tunnel`) under `exposure: private`. The federating gateway points a
`streamable_http` upstream at it:

```yaml
gateway:
  server:
    tunnel_federation:                       # where tunnel:// upstreams resolve
      relay_ingress_url: https://relay.tunnels.mcpg.cloud
      token: "${env.MCPG_TUNNEL_TOKEN}"      # org token; falls back to this env var
mcp:
  federations:
    - name: acme-internal
      upstream:
        url: tunnel://acme-internal/mcp      # <name> = the private tunnel's name
      auth:
        mode: pass_through                   # forward the caller identity downstream
```

`tunnel://<name>/<path>` resolves at connect time to
`<relay_ingress_url>/federate/<name>/<path>`. The **org token** rides every
request in `X-MCPG-Tunnel-Token`; the relay resolves it to an org, enforces
**same-org isolation** (a wrong-org or unknown name is an indistinguishable
404), strips the header, and forwards the rest onto the named tunnel. The
end-user's `Authorization` bearer flows through untouched, so the private
gateway applies its own governance against the real caller identity.

`tunnel_federation` is required whenever any `tunnel://` upstream is configured —
the gateway fails closed at boot otherwise. It is independent of
`server.tunnel` (a gateway can federate tunnels without dialing one itself). See
[the tunneling guide](https://mcpg.dev/docs/gateway/tunneling).

---

## 9. Runtime behaviour

### Upstream protocol version — federation as a wire adapter

The wire MCPG serves each **client** and the wire it speaks to each
**upstream** are independent. Clients negotiate their revision per
request (`2025-11-25` or `2026-07-28`); `upstream.protocol_version`
selects the upstream side — so one federation entry adapts a remote MCP
server to whichever revision each caller uses, in both directions:

| Upstream speaks | Client speaks | What MCPG does |
|---|---|---|
| legacy `2025-11-25` | modern `2026-07-28` | holds the upstream session + handshake; serves a stateless face |
| modern `2026-07-28` | legacy `2025-11-25` | answers `initialize`, holds the client session; speaks stateless upstream |
| same on both sides | — | pass-through |

With the default `protocol_version: auto`, MCPG detects the upstream's
revision at connect: it attempts the modern `server/discover` and, if
the peer rejects it (HTTP 400 unsupported-version, method-not-found),
falls back to the legacy `initialize` handshake. The verdict is cached
per federation (re-detected on reload/restart), so satellites and
listeners connect without re-probing. Pin a dated revision to skip the
probe entirely.

### Staying fresh
Two refresh triggers keep the federated catalog current:
- **Push:** a persistent listener reacts to upstream catalog-change
  pushes and re-imports that federation. On a legacy upstream this is
  the standalone `GET` SSE stream; on a modern (`2026-07-28`) upstream
  it is a long-lived `subscriptions/listen` stream subscribed to the
  three `*ListChanged` targets (an upstream without the method degrades
  quietly to poll-only). (HTTP transports only.)
- **Poll:** `cache.capability_ttl_secs` re-imports on an interval — the
  fallback for upstreams that never push (and for stdio).

Either trigger broadcasts `list_changed` to *your* connected clients
**only for the kinds whose client-visible catalog actually changed**
(descriptor-level diff against the previous import) — a TTL poll that
detects a change notifies clients just like a push does, and an
upstream push that your filters make invisible wakes nobody.

A single upstream's change re-imports only *that* federation; the others keep
their capabilities.

### Resource subscriptions
If a client `resources/subscribe`s to a federated resource, an upstream
`notifications/resources/updated` is re-prefixed and forwarded to that
subscriber. When the upstream **cannot** push resource updates (the
modern wire's listener carries only catalog changes; stdio has no push
channel at all), the `synthesize` block manufactures them instead: the
first subscriber starts a poll watcher that re-reads the resource
through the normal federated dispatch on `poll_interval_ms` and emits
`resources/updated` when the content hash changes; the last unsubscribe
stops it. Polling runs under the gateway's machine identity — per-caller
upstream resources are not poll-watchable.

### Server-request bridging (sampling / elicitation / roots)
If an upstream needs to sample an LLM, elicit user input, or list roots **during
a tool call**, MCPG bridges the request to the *real* client and the answer
back. MCPG advertises to the upstream only the capabilities the **downstream
session** actually supports (so it never surfaces a request the client can't
handle). Upstream `notifications/progress` is forwarded too, correlated to the
client's own progress token.

### Sessions & reload
Dispatch uses one **satellite** (an upstream session) per `(caller,
federation)`, torn down after `session.idle_timeout_secs` idle. The
caller key is the authenticated principal — stable across that
principal's sessions and gateway replicas — falling back to the session
id for anonymous callers; for `pass_through` / `oauth_impersonation` a
fingerprint of the caller's bearer joins the key, so two tokens of the
same principal (scope change, rotation) never share an upstream
session. The upstream credential is re-resolved on every dispatch: a
rotated token replaces the satellite's connection instead of riding the
stale one into an upstream 401. On a config reload, capabilities +
governance carry across with no flicker, and satellites (and detected
wires) for **unchanged** federations are reused (no reconnect, no
re-probe); changed/removed ones re-establish.

---

## 10. Observability

| Metric | Meaning |
|---|---|
| `mcpg_oauth_token_exchange_total{provider}` | impersonation token exchanges |
| `mcpg_oauth_token_exchange_error_total{provider}` | failed exchanges |
| `mcpg_oauth_token_cache_hit_total{provider}` | client-credentials cache hits |
| `mcpg_credential_cache_total{plugin_id,outcome}` | host credential-cache hit/miss |

Federation also emits structured logs (`target: mcpg::runtime::federation::…`)
for import success/failure, list_changed refresh, and credential resolution
(never the token itself).

---

## 11. Best practices

**Naming & collisions**
- Always set a `tool_prefix` / `resource_uri_prefix` / `prompt_prefix` — even for
  a single upstream. It future-proofs against name collisions when you add more
  federations or native tools, and makes the source obvious to clients.
- Keep prefixes short + stable; clients hard-code tool names.

**Trust & governance**
- Treat a federated upstream as untrusted code: set `minimum_trust` to the
  highest level your callers legitimately have, and add an `allow_if` group/role
  gate. Federation inherits — but only what you configure.
- Use `filter.exclude_tools` to drop destructive/admin tools you don't want
  exposed (`exclude_tools: ["*_delete", "admin_*"]`).

**Auth**
- Never inline secrets — use `${env.VAR}` or `${cred://…}`; the literal then
  never appears in YAML or logs.
- Prefer `oauth_client_credentials` over a static `service_token` (rotation +
  expiry come for free).
- Reserve `oauth_impersonation` for upstreams that genuinely need per-user
  identity, and pair it with a high `minimum_trust` — it hands a user-scoped
  token to the upstream.
- `pass_through` only when you trust the upstream with your clients' raw tokens.

**Transport safety**
- Keep `allow_private_backends` / `allow_insecure_http` / `allow_stdio` **off**
  unless you specifically need them; each widens the attack surface.
- For `stdio`, pin an absolute `command` path and a minimal `env`; you own the
  trust of whatever you spawn.

**Sizing & resilience**
- Set `response.max_response_bytes` to bound a misbehaving upstream.
- Tune `cache.capability_ttl_secs` down for upstreams that change often (and
  can't push), up for stable ones.
- A failing upstream is logged and skipped at import — it never takes down the
  gateway or other federations.

**Topology**
- You can federate one MCPG through another (the loop-detection header guards
  cycles) — handy for tiered/edge aggregation.

---

## 12. Worked examples

### A. SaaS upstream over HTTP, machine OAuth, verified-only
```yaml
plugins:
  - id: dev.mcpg.credential.oauth-client-credentials
    config:
      providers:
        notion: { token_url: https://auth.notion.example.com/oauth/token,
                  client_id: mcpg-gateway, client_secret: "${env.NOTION_SECRET}",
                  scopes: ["read"] }
mcp:
  federations:
    - name: notion
      governance: { minimum_trust: verified, allow_if: "identity.has_group('notion')" }
      upstream:
        url: https://notion-mcp.example.com/mcp
        auth: { mode: oauth_client_credentials,
                credential: cred://dev.mcpg.credential.oauth-client-credentials/notion }
      import: { tools: true, resources: true, prompts: true }
      naming: { tool_prefix: "notion.", resource_uri_prefix: "mcp://notion/", prompt_prefix: "notion." }
      filter: { exclude_tools: ["*_delete"] }
```

### B. Local tool server over stdio
```yaml
mcp:
  federations:
    - name: localtools
      upstream:
        transport: stdio
        command: /opt/mcp/localtools
        args: ["--stdio"]
        upstream_safety: { allow_stdio: true }
      import: { tools: true }
      naming: { tool_prefix: "local." }
```

### C. Per-user impersonation
```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    config:
      providers:
        drive: { token_url: https://sts.example.com/token, client_id: mcpg,
                 audience: https://drive-mcp.example.com }
mcp:
  federations:
    - name: drive
      governance: { minimum_trust: verified }
      upstream:
        url: https://drive-mcp.example.com/mcp
        auth: { mode: oauth_impersonation,
                credential: cred://dev.mcpg.credential.oauth-token-exchange/drive }
      import: { tools: true, resources: true }
      naming: { tool_prefix: "drive.", resource_uri_prefix: "mcp://drive/" }
```

---

## 13. Limitations / roadmap

- **Wildcard per-tenant federation** — not yet implemented.
- **stdio notifications** — drained during calls / TTL, not pushed in real time
  (stdio has no standalone notification channel).

---

## 14. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Federated tools missing from `tools/list` | caller below `minimum_trust` (they're hidden), or import failed — check `mcpg::runtime::federation` logs |
| `oauth_* requires auth.credential (a cred:// URI)` at boot | set `auth.credential` to `cred://<plugin_id>/<provider>` |
| `no credential_issuer plugin id=…` at dispatch | the referenced issuer plugin isn't configured under `plugins` |
| stdio federation rejected at boot | set `upstream_safety.allow_stdio: true` and a `command` |
| upstream `http://…` rejected | set `upstream_safety.allow_insecure_http: true` (or use https) |
| loopback upstream rejected | set `upstream_safety.allow_private_backends: true` |
| impersonation tool fails with "subject token" error | the caller presented no inbound bearer to exchange |
