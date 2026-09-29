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
      governance:
        minimum_trust: unauthenticated
```

Boot MCPG; `tools/list` now includes `notion.search`, `notion.create_page`, …
and `tools/call` for them is proxied to the upstream. That's it — no auth (the
upstream is public). The `governance` line is there because this config has no
identity source, so every caller is `unauthenticated`. The default floor is
`header_asserted`, and a caller below the floor does not see the tools in
`tools/list`. When you add an identity source, remove the line or raise the
floor.

---

## 3. Configuration reference

Federations live under `mcp.federations: []`. Every field of one entry:

```yaml
mcp:
  federations:
    - name: notion                  # REQUIRED. Source id + default prefix namespace.
                                     #   Must be unique; must not shadow a native binding.

      governance:                   # Inherited by EVERY synthetic capability (like a native binding).
        minimum_trust: verified     #   unauthenticated | header_asserted | verified  (default: header_asserted)
        allow_if: '"notion-users" in identity.groups'   # optional CEL; same engine as native per-tool rules

      retry:                        # optional; upstream call retry
        max_attempts: 2
        initial_backoff_ms: 500

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
          import:                   # optional catalogue credential (import, refresh, listener)
            mode: service_token     #   service_token | oauth_client_credentials
            token: "${env.CATALOGUE_TOKEN}"

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
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-id-jag:protocol-1"
    granted_capabilities: [network_outbound]
    config:
      target_template:
        allowed_targets: ["com.acme/*"]   # fail-closed: only these expand
        idp_token_url: https://idp.acme.example/oauth2/token
        client_id: mcpg-fleet
        client_secret: ${env.IDP_SECRET}
        subject_token_type: id_token      # required: what the callers' bearers are
        audience_template: "https://{target_slug}.mcp.acme.internal"
        redeem_token_url_template: "https://{target_slug}.mcp.acme.internal/oauth2/token"
```

For each caller and server, the issuer exchanges the caller's bearer
(RFC 8693) for an ID-JAG assertion with the server's expanded audience,
then redeems it (RFC 7523) at the server's expanded token endpoint.
`{target_slug}` is the server name reduced to hostname characters
(`com.acme/crm` becomes `com-acme-crm`). A raw `{target}` in the host of
`redeem_token_url_template` refuses any name with other characters than
letters, digits, `.` and `-`, so registry names such as `com.acme/crm`
need `{target_slug}` (with `{target}` there, this example refuses to
load). An
exact `providers` entry always beats the template, and targets outside
`allowed_targets` fail closed. `oauth-token-exchange` supports the same
`target_template` shape (`token_url` + `audience_template` /
`resource_template`) for single-hop STS fleets.

#### OAuth discovery (`defaults.oauth_discovery`)

When a server's resource identifier and token endpoint are not known a
priori, let the syncer discover them (the client half of MCP
authorization). For `oauth-id-jag` the authorization server's issuer
still comes from the issuer config; discovery confirms it (see below):

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
`{audience, resource, redeem_token_url, issuer}` — which the engine
forwards to the credential issuer on every issuance (the template
issuers' per-call overrides). `resource` is the protected resource's
RFC 9728 identifier, `redeem_token_url` the AS `token_endpoint`, and
`issuer` the AS issuer exactly as its metadata states it. What
`audience` names depends on the issuer plugin:

- `dev.mcpg.credential.oauth-id-jag`: the **AS issuer**. Hop 1 asks the
  IdP for an ID-JAG addressed to the upstream authorization server
  (ID-JAG §4.3), and that server refuses one whose `aud` is not its own
  issuer. The MCP resource travels separately as `resource`.
- Every other OAuth issuer: the **resource**, because the token it
  obtains goes to the MCP server itself.

The metadata is the upstream's own document, so it cannot widen what the
issuer is configured for. `oauth-id-jag` keeps the operator's
`audience` / `audience_template` authoritative: a discovered issuer that
differs from it by more than a trailing `/` fails the issuance with
`Misconfigured` before the IdP is called (discovery supplies the exact
spelling, and the token endpoint on the same origin). Otherwise an
upstream could name a sibling authorization server on the same host,
for example another custom authorization server on one Okta tenant, and
receive a token issued for it. `redeem_token_url` must share its origin
with the configured endpoint.

For an `oauth-id-jag` federation the authorization server must also
offer ID-JAG redemption: `urn:ietf:params:oauth:grant-type:jwt-bearer`
in `grant_types_supported`, or
`urn:ietf:params:oauth:grant-profile:id-jag` in
`authorization_grant_profiles_supported` with no grant list that leaves
out jwt-bearer. The profile is only recommended (ID-JAG §7.2), so an AS
that lists the grant without it federates with a warning
(`mcpg_registry_oauth_discovery_warning_total{reason="id_jag_profile_missing"}`).
A server whose AS offers neither is skipped
(`mcpg_registry_server_skipped_total{reason="no_id_jag_support"}`)
rather than sent ID-JAGs it has not said it can redeem; the previous
snapshot does not keep it alive, because the AS answered.

Both fetches are SSRF-guarded like the crawl itself: https-only, pinned
DNS, no redirects, private addresses only under
`upstream_safety.allow_private_backends`. If discovery fails for a
server, its previously discovered metadata is reused; a server with no
discovered metadata at all is skipped
(`mcpg_registry_server_skipped_total{reason="oauth_discovery"}`).

`credential_config` is an ordinary federation field too — a
hand-written federation can pin it explicitly (and a
`servers.<name>.auth` override carrying one bypasses discovery and its
grant check). For `oauth-id-jag`, `audience` is the upstream AS issuer
and must match the provider's configured `audience`, and `resource` is
the MCP server:

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
            audience: https://as.crm.acme.example        # upstream AS issuer
            resource: https://crm.acme.example/mcp      # upstream MCP server
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
applied to **upstream tool names** before prefixing. There is no suffix glob: a
leading `*` is literal, so `*_admin` matches only a tool named `*_admin`.

```yaml
mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
      filter:
        include_tools: ["search*", "read_*"]    # only these import
        exclude_tools: ["admin_*", "delete_*"]  # …minus these (exclude wins)
```

Use it to expose a safe subset of a powerful upstream.

---

## 6. Governance inheritance

A federation's `governance` block applies to **every** capability it imports,
exactly as if you'd written it on a native binding:

- **`minimum_trust`** — `unauthenticated` < `header_asserted` < `verified`. A
  caller below the bar can't call the federated tool — and the tool is **hidden
  from `tools/list`** for that caller (visibility honours trust). Unset, it is
  `header_asserted`: `governance.policy.tool_access.default_minimum_trust` does
  not reach federated capabilities, so set the floor on each federation.
- **`allow_if`** — a CEL expression evaluated per call against the caller's
  identity (`identity.groups`, `identity.roles`, `identity.scopes`,
  `identity.attributes`) and `tool_name`, the prefixed name the client called.
  Same engine and semantics as native per-tool `allow_if`; an expression that
  fails to evaluate denies the call.

```yaml
mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
      naming:
        tool_prefix: "notion."
      governance:
        minimum_trust: verified
        allow_if: '"notion-users" in identity.groups && !tool_name.endsWith(".delete_page")'
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
logged. At import/listen time (no caller) the upstream is listed anonymously,
unless you set a [catalogue credential](#catalogue-credential-authimport).

```yaml
upstream:
  auth: { mode: pass_through }
```

Use when the upstream already understands your clients' tokens.

A bearer the gateway minted itself is never forwarded: an access token from
the embedded authorization server (enterprise-managed authorization) or the
supervised inspector's credential. Only this gateway can validate it, and an
upstream that received it could replay it here. Such a call fails before any
request to the upstream; the gateway log names the fix. For those callers,
use `service_token`, `oauth_client_credentials`, or `oauth_impersonation`
with the caller's [stored enterprise sign-in](#stored-sign-in).

### `oauth_client_credentials` — machine identity
MCPG mints a machine token via the gateway's **credential-issuer subsystem**
and presents it. `credential` is a `cred://<plugin_id>/<provider>`
URI pointing at a configured `oauth-client-credentials` issuer. The token is
cached + auto-refreshed; no client secret lives in the federation config.

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-client-credentials
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-client-credentials:protocol-1"
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
`pass_through`, unless you set a
[catalogue credential](#catalogue-credential-authimport).

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-token-exchange:protocol-1"
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
anonymous and header-asserted identities. Only callers that signed in
with a token an external identity provider issued, verified through
OIDC or JWKS, can be exchanged on-behalf-of. A caller of enterprise-managed
authorization presents an access token the embedded authorization
server minted, and the supervised inspector presents a credential the
gateway minted. Neither can be exchanged: only this gateway can
validate them. This holds when the IdP sets `principal_issuer` too,
although such a caller then has the same `issuer` and `auth_provider` as
an OIDC caller. The call fails before any request to the token service
or the upstream, and the gateway log names the fix: exchange the caller's
[stored enterprise sign-in](#stored-sign-in) instead
(`subject_token: idp_refresh_token`), authenticate the upstream with
`service_token` or `oauth_client_credentials`, or have callers sign in
with a token their identity provider issued. The issuer plugins refuse
such a caller with `Misconfigured` as well.

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
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-id-jag:protocol-1"
    granted_capabilities: [network_outbound]
    config:
      providers:
        partner:
          idp_token_url: https://acme.okta.com/oauth2/v1/token   # enterprise IdP
          client_id: mcpg-gateway
          client_secret: "${env.OKTA_MCPG_CLIENT_SECRET}"
          subject_token_type: id_token                           # required; see below
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

`subject_token_type` states what the caller's bearer is, and by default
`oauth_impersonation` sends that bearer as the subject token.
Okta's Cross App Access exchanges only an ID token or a refresh token,
and it accepts an ID token only when the token was issued to this
`client_id` (`aud` = `mcpg-gateway`). This example therefore works only
when callers present such an Okta ID token as their bearer. A typical
MCP client presents an OAuth access token, which Okta refuses with
`invalid_grant`. With users signing in to the gateway, present their
[stored enterprise sign-in](#stored-sign-in) instead.

Enterprise-managed upstreams usually refuse `initialize` and `tools/list`
without a token, so give the federation a
[catalogue credential](#catalogue-credential-authimport) as well.

#### <a id="stored-sign-in"></a>The caller's stored enterprise sign-in (`subject_token`)

When users sign in to the gateway itself (interactive sign-in, a `login`
block on a `governance.access.authorization_server.trusted_idps` entry),
the gateway keeps each user's IdP sign-in: one per user, for every MCP
client of that user. `upstream.auth.subject_token` makes an
`oauth_impersonation` federation exchange that sign-in instead of the
caller's bearer:

| `subject_token` | Subject token the issuer exchanges |
|---|---|
| `caller_bearer` (default) | the caller's own bearer |
| `idp_refresh_token` | the user's stored IdP refresh token (what Okta Cross App Access takes) |
| `idp_id_token` | an ID token of the stored sign-in, refreshed at the IdP first when it has less than 60 s left |

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-id-jag:protocol-1"
    granted_capabilities: [network_outbound]
    config:
      providers:
        partner:
          idp_token_url: https://acme.okta.com/oauth2/v1/token   # the login client's IdP
          client_id: 0oa-mcpg-agent                              # the login client
          client_auth: private_key_jwt
          private_key: "${secret.OKTA_AGENT_KEY}"
          subject_token_type: refresh_token
          audience: https://auth.partner.example
          redeem_token_url: https://auth.partner.example/oauth/token

mcp:
  federations:
    - name: partner
      upstream:
        url: https://mcp.partner.example/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/partner
          subject_token: idp_refresh_token
          import:
            mode: oauth_client_credentials
            credential: cred://dev.mcpg.credential.oauth-client-credentials/partner-catalogue
```

- Every caller of the user presents it: a client that signed in to the
  gateway, a client that redeemed an ID-JAG here, and an SSO caller the
  IdP's `principal_issuer` joins to the same user. The gateway picks the
  sign-in by the caller's principal; the caller's bearer is never sent.
- The stored token goes only to the IdP that issued it. `credential` must
  name `dev.mcpg.credential.oauth-id-jag` or
  `dev.mcpg.credential.oauth-token-exchange` (directly, or as the `ref` of
  a `plugins[]` entry): validation refuses any other issuer plugin, which
  could send the token anywhere, and the gateway refuses one again at
  call time, before the sign-in is read. Those two refuse the call before
  any request unless the provider's `idp_token_url` (`token_url`) and
  `client_id` are the gateway's login client's, and `idp_issuer`
  (`sts_issuer`), when set, is its IdP. `mcpg config check` warns about
  such a mismatch.
- A caller with no stored sign-in, for example a client that only ever
  redeemed ID-JAGs, is refused before any request, and so is a caller
  that is not verified. The failed call names where the user stores one:
  `{issuer}/oauth/connect`, a page that signs the user in at the IdP once
  (`idp_sessions.connect_page`, on by default).
- Only a caller whose principal a sign-in through the login IdP is
  stored under can ever present one: an ID-JAG caller of that IdP (of any
  tenant, unless `required_tenant` pins one), or an SSO caller of the
  provider its `principal_issuer` names. Any other caller (another IdP,
  an SSO provider no `principal_issuer` joins, the supervised inspector)
  is told that none can be stored for them, without the connect page or
  a link.
- A client that declares URL-mode elicitation (`elicitation.url`) gets a
  link to store the sign-in instead of the failed `tools/call`
  ([URL-mode elicitation](#stored-sign-in-links)).
- The upstream token is cached per user and sign-in, so the IdP rotating
  the stored refresh token costs no new exchange.
- It needs interactive sign-in: validation refuses `idp_*` without a
  `login` block, and inside `auth.import`, whose sessions have no caller.
  The catalogue sessions connect anonymously unless `auth.import` is set.
- Registry-synced federations accept it in `defaults.auth` and
  `servers.<name>.auth`.

#### <a id="stored-sign-in-links"></a>A link to store the sign-in (URL-mode elicitation)

When a verified caller has no stored sign-in and its client declared
`elicitation.url`, the `tools/call` answers with a link that stores it,
in the shape of the negotiated MCP version:

| Version | Answer | How the client continues |
|---|---|---|
| `2025-11-25` | JSON-RPC error `-32042` whose `data.elicitations` holds one URL-mode elicitation (`mode`, `elicitationId`, `url`, `message`); the error's own `message` repeats that text and the link, for a client that shows only it | The session receives `notifications/elicitation/complete` with the `elicitationId` once the user completes the link, and the client retries the call |
| `2026-07-28` | `InputRequiredResult` whose `inputRequests.connect_sign_in` is a URL-mode `elicitation/create` (no id), with a `requestState` | The client retries with the `requestState` and its answer in `inputResponses`: `accept` waits up to 10 s (a third of `request_timeout_ms` at most) for the user's sign-in to be stored; `decline` or `cancel` returns the failed call; no answer offers the same link again. A `requestState` whose link expired runs the call again: it succeeds when the sign-in is stored, else offers a link |

- The link is `{issuer}/oauth/connect?e=<id>`. The id is random and names
  nobody; the link carries no token and does not sign anyone in.
- The link is for the caller's principal only. The user opens it, confirms
  on the connect page and signs in at the IdP. When the IdP names another
  user, nothing is stored, the page says so, and
  `mcpg.as.connect_refused` is audited. A link is completed once, and
  lives as long as a sign-in transaction (`transaction_ttl_secs`).
- A retry on the same MCP session is offered the link that session is
  pending, so the store holds one link per user and session. A user is
  offered at most 20 new links per `transaction_ttl_secs`; past that, a
  call fails with the message that names the connect page.
- The `requestState` is sealed with the sign-in state key and bound to the
  caller and the tool; another user or another tool cannot present it.
- The message next to the link names the federation only when its name
  is plain (`[A-Za-z0-9._-]`, at most 128 characters); a registry-synced
  name with any other text reads as "a federated tool".
- No link is offered when `idp_sessions.connect_page` is off, to a caller
  no sign-in can be stored for (see above), to a caller that is not
  verified, for a call with an idempotency key, for a call run as a task,
  or for `resources/read` and `prompts/get`; those calls fail with the
  message that names the connect page, or says none can be stored.

### Catalogue credential (`auth.import`)

Some upstream sessions have no caller: the catalogue import at boot and
reload, the `list_changed` and TTL refreshes, and the notification
listener. With `pass_through` and `oauth_impersonation` there is nothing
to forward or exchange, so these sessions are anonymous by default. An
upstream that requires a token to list its tools refuses them, and the
federation imports nothing: MCPG logs a warning that names
`upstream.auth.import` and counts
`mcpg_federation_import_failed_total{reason="unauthorized"}`.

`upstream.auth.import` gives those sessions their own credential:

```yaml
mcp:
  federations:
    - name: partner
      upstream:
        url: https://mcp.partner.example/mcp
        auth:
          mode: oauth_impersonation                 # tool calls: the caller
          credential: cred://dev.mcpg.credential.oauth-id-jag/partner
          import:                                   # catalogue: the gateway
            mode: oauth_client_credentials          # or service_token + token
            credential: cred://dev.mcpg.credential.oauth-client-credentials/partner-catalogue
```

- `mode` is `service_token` (with `token`) or `oauth_client_credentials`
  (with `credential`, and optionally `credential_config`). The
  caller-derived modes and a nested `import` fail validation.
- Only the catalogue sessions use it. Tool calls, resource reads and
  prompt fetches keep the outer `mode`: an impersonated call carries the
  caller's exchanged token, and a call without a caller bearer never
  falls back to the catalogue credential.
- It works with every outer mode, for example a read-only listing token
  next to an `oauth_client_credentials` machine identity.
- The imported catalogue is what this credential can list. Per-user
  differences in what the upstream shows are not reflected: every caller
  sees the same federated catalogue (still narrowed by `filter` and
  `governance`), and a tool the upstream withholds from a caller fails
  when that caller invokes it.
- Registry-synced federations accept `defaults.auth.import` and
  `servers.<name>.auth.import`. `{server}` expands inside
  `import.credential` as it does in `auth.credential`, so a
  `target_template` issuer mints a catalogue token per server. OAuth
  discovery does not fill `import.credential_config`, and a
  `service_token` in `defaults.auth.import` goes to every server the
  registry lists.

### Choosing
| Want | Mode |
|---|---|
| Public upstream | `none` |
| One shared machine credential | `service_token` or `oauth_client_credentials` |
| Auto-refreshing machine OAuth token | `oauth_client_credentials` |
| Upstream understands your clients' tokens | `pass_through` |
| Upstream must see the end user (per-user authz/audit) | `oauth_impersonation` |
| Enterprise-governed upstream (Cross-App Access / ID-JAG) | `oauth_impersonation` + `oauth-id-jag` issuer |
| The same, for users who sign in to the gateway | add `subject_token: idp_refresh_token` |
| A caller-derived mode against an upstream that requires a token to list tools | add `auth.import` |

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
          mode: pass_through                 # forward the caller identity downstream
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
| `mcpg_federation_import_failed_total{reason}` | failed catalogue imports and refreshes; `unauthorized` = the upstream answered 401/403, `error` = anything else |
| `mcpg_federation_subject_token_total{mode,outcome}` | calls of `idp_refresh_token` / `idp_id_token` federations; `used` = the issuer exchanged the stored sign-in, `not_linked` = the caller has none, `refused` = the caller, the sign-in or the issuer plugin cannot be used, or the issuer refused the exchange, `unavailable` = the sign-in state, the issuer or the IdP cannot be reached now |
| `mcpg_federation_connect_link_total{outcome}` | links offered to callers with no stored sign-in; `offered` = a new link, `resumed` = the pending link of a retry or of the session, `limited` = the user was offered as many new links as one link lifetime allows, `unavailable` = the sign-in state could not store one |
| `mcpg_federation_url_elicitation_total{protocol_version}` | tool calls answered with a link, by MCP version |
| `mcpg_as_connect_total{purpose,outcome}` | the connect page; `purpose` = `connect` or `link`, `outcome` = `shown`, `refused`, `approved` or `denied` |
| `mcpg_registry_server_skipped_total{registry,reason}` | registry servers left unfederated; `oauth_discovery` = no metadata ever discovered, `no_id_jag_support` = an `oauth-id-jag` server whose AS does not offer jwt-bearer |
| `mcpg_registry_oauth_discovery_warning_total{registry,reason}` | servers federated despite a discovery warning; `id_jag_profile_missing` = the AS lists jwt-bearer but not the id-jag grant profile |

Federation also emits structured logs (`target: mcpg::runtime::federation::…`)
for import success/failure, list_changed refresh, and credential resolution
(never the token itself). A call refused for its stored sign-in (every
outcome but `used`, an exchange the issuer refused or that failed
included) is audited as `mcpg.federation.idp_subject_token`, with the
federation, the mode and the reason (the issuer's, for an exchange);
never the token. A link completed
by another user than the one it was offered to is audited as
`mcpg.as.connect_refused`, with the user who signed in and the principal
the link was for; never the link id.

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
  exposed (`exclude_tools: ["delete_*", "admin_*"]`).

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
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-client-credentials:protocol-1"
    config:
      providers:
        notion: { token_url: https://auth.notion.example.com/oauth/token,
                  client_id: mcpg-gateway, client_secret: "${env.NOTION_SECRET}",
                  scopes: ["read"] }
mcp:
  federations:
    - name: notion
      governance: { minimum_trust: verified, allow_if: '"notion" in identity.groups' }
      upstream:
        url: https://notion-mcp.example.com/mcp
        auth: { mode: oauth_client_credentials,
                credential: cred://dev.mcpg.credential.oauth-client-credentials/notion }
      import: { tools: true, resources: true, prompts: true }
      naming: { tool_prefix: "notion.", resource_uri_prefix: "mcp://notion/", prompt_prefix: "notion." }
      filter: { exclude_tools: ["delete_*"] }
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
    class: credential_issuer
    source:
      oci: "ghcr.io/mcpg-dev/plugins/credential-oauth-token-exchange:protocol-1"
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
| `upstream refused the anonymous catalogue session` warning, import fails with HTTP 401 | a `pass_through` / `oauth_impersonation` upstream requires a token to list tools; set [`auth.import`](#catalogue-credential-authimport) |
| `oauth_* requires auth.credential (a cred:// URI)` at boot | set `auth.credential` to `cred://<plugin_id>/<provider>` |
| `no credential_issuer plugin id=…` at dispatch | the referenced issuer plugin isn't configured under `plugins` |
| stdio federation rejected at boot | set `upstream_safety.allow_stdio: true` and a `command` |
| upstream `http://…` rejected | set `upstream_safety.allow_insecure_http: true` (or use https) |
| loopback upstream rejected | set `upstream_safety.allow_private_backends: true` |
| impersonation tool fails with "subject token" error | the caller presented no inbound bearer to exchange |
