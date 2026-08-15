# MCPG Configuration

> **Generated from `apps/gateway/src/config/` via `mcpg config doc`.**  
> The audience-facing sections below are curated inside the generator; the per-block reference at the bottom is sourced from `///` rustdoc + `#[serde(...)]` annotations on the live `AppConfig` tree.  
> Re-generate with: `mcpg config doc > apps/gateway/docs/configuration.md`.

## Overview

Top-level gateway configuration. Loaded from YAML file and/or `MCPG_` environment variables via figment. Bindings live under `mcp.capabilities.{tools,prompts,resources,resource_templates}[]`. Each binding carries an explicit nested `backend:` block that picks the implementation, discriminated by `kind:` (`kind: http`, `kind: sql`, `kind: openai_chat`, …). Env-var expansion (`${env.X}`) happens at startup time via CEL.

`deny_unknown_fields` is set so a typo at the root (or a stale renamed block left in an operator's YAML) fails parsing instead of silently parsing to defaults. The same strictness applies to every typed sub-config; this flag closes the gap at the root.

## Operator workflow

The four config-tooling binaries cover the operator's full loop — pick a starting point, drill into a field, validate, boot:

```bash
$ mcpg config init                                    # pick a deployment template, write config.yaml
$ mcpg config explain governance.audit.on_failure    # describe a field by dotted path
$ mcpg config check config.yaml                       # pre-flight validate (multi-file too)
$ MCPG_CONFIG=config.yaml mcpg                        # boot
```

Multi-file layering is supported — files later on the command line override earlier ones, and `MCPG_*` env vars apply last:

```bash
$ MCPG_CONFIG=base.yaml:production-overrides.yaml mcpg
```

For in-place config rotation (`kill -HUP`) vs restart-required fields, see the [config sources & hot-reload guide](https://mcpg.dev/docs/gateway/config-sources).

For IDE autocomplete, point your YAML language server at the committed schema:

```yaml
# yaml-language-server: $schema=examples/deployments/config.schema.json
gateway:
  server:
    bind_address: "127.0.0.1:8787"
    # ↑ IDE autocompletes here, with `///` doc-comment as hover.
```

---

## Top-level keys (Layout D'')

Layout D'' collapsed the pre-D'' flat root into seven typed top-level keys. The migration map for any pre-D'' YAML or env-var examples you might still be reading:

| Pre-D'' key | Layout D'' key |
|---|---|
| `auth:` | `governance.access:` |
| `policy:` | `governance.policy:` |
| `audit:` | `governance.audit:` |
| `approvals:` | `governance.approvals:` |
| `server:` | `gateway.server:` |
| `admin:` | `gateway.admin:` |
| `control_plane:` | `gateway.control_plane:` |
| `content_storage:` | `storage:` |
| `mcp.tools[]` (etc.) | `mcp.capabilities.tools[]` (etc.) |
| `plugins.entries[]` | `plugins[]` (flat array, no wrapper) |
| `plugins.kv` / `caches` / `secrets` / `configs` / `transports` / `policy` / `capability_grants` / `trust` / `credentials` | DELETED — point-of-use slots + per-entry configuration replace these |
| `plugins.health_probe` | `observability.plugin_health_probe` |
| `plugins.registry` | `gateway.plugin_registry` |
| `plugins.config_overlay` | `gateway.config_overlay` |
| `plugins.response_cache` | `storage.response_cache` |
| `plugins.enabled` / `plugins.plugin_dir` | DELETED |
| `BackendImpl.type:` (in a binding's `backend:` block) | `BackendImpl.kind:` |

The ten D'' top-level keys are: `mcp:`, `governance:`, `gateway:`, `observability:`, `feature_flags:`, `debug:`, `schema_registry:`, `storage:`, `cluster:`, `plugins:` (plus `MCPG_CONFIG`-only `config_source:`). `governance:` and `gateway:` are umbrellas — their children correspond one-to-one to former root peers.

`MCPG_*` env vars track the new shape with `__` as the dotted-path separator. The corresponding env-var prefix migrations:

| Pre-D'' env var | Layout D'' env var |
|---|---|
| `MCPG_AUTH__*` | `MCPG_GOVERNANCE__ACCESS__*` |
| `MCPG_POLICY__*` | `MCPG_GOVERNANCE__POLICY__*` |
| `MCPG_AUDIT__*` | `MCPG_GOVERNANCE__AUDIT__*` |
| `MCPG_APPROVALS__*` | `MCPG_GOVERNANCE__APPROVALS__*` |
| `MCPG_SERVER__*` | `MCPG_GATEWAY__SERVER__*` |
| `MCPG_ADMIN__*` | `MCPG_GATEWAY__ADMIN__*` |
| `MCPG_CONTROL_PLANE__*` | `MCPG_GATEWAY__CONTROL_PLANE__*` |
| `MCPG_CONTENT_STORAGE__*` | `MCPG_STORAGE__*` |
| `MCPG_MCP__TOOLS__*` (etc.) | `MCPG_MCP__CAPABILITIES__TOOLS__*` (etc.) |
| `MCPG_PLUGINS__HEALTH_PROBE__*` | `MCPG_OBSERVABILITY__PLUGIN_HEALTH_PROBE__*` |
| `MCPG_PLUGINS__REGISTRY__*` | `MCPG_GATEWAY__PLUGIN_REGISTRY__*` |
| `MCPG_PLUGINS__CONFIG_OVERLAY__*` | `MCPG_GATEWAY__CONFIG_OVERLAY__*` |
| `MCPG_PLUGINS__RESPONSE_CACHE__*` | `MCPG_STORAGE__RESPONSE_CACHE__*` |

---

## Quick start (minimal viable)

Goal: gateway answers `/health`, `tools/list`, and one `tools/call` against your binding. No auth, no cluster, no compliance plumbing.

**Template:** `dev-single-node` (`mcpg config init --template dev-single-node`). Six fields are load-bearing — everything else takes a sensible default.

| Field | Why it matters | Default | Reference |
|---|---|---|---|
| `gateway.server.bind_address` | The TCP listener. `127.0.0.1:8787` for dev; `0.0.0.0:8787` once you trust auth. | `"127.0.0.1:8787"` | [`ServerConfig`](#serverconfig) |
| `gateway.server.allowed_origins` | CORS allowlist for browser clients. Empty disables browser-cross-origin. | `[]` | [`ServerConfig`](#serverconfig) |
| `mcp.capabilities.tools[]` (and `prompts[]`, `resources[]`, `resource_templates[]`) | The tools / prompts / resources this gateway exposes. At least one entry to be useful. | `[]` | [`McpConfig`](#mcpconfig), [`BackendConfig`](#backendconfig) |
| `governance.access` | Inbound identity. Empty = anonymous (loopback only). | `{}` | [`AccessConfig`](#accessconfig) |
| `observability.logs.sinks` | Where logs go. Default stderr-JSON is fine for dev. | one stderr JSON sink | [`LogsConfig`](#logsconfig) |
| `governance.audit` | Compliance audit. On by default with the built-in local-file sink — drop directory into a tmpfs / scratch mount if your dev disk is read-only. | enabled, file sink | [`AuditConfig`](#auditconfig) |

**Boot it:**

```bash
$ mcpg config init --template dev-single-node --output config.yaml
$ mcpg config check config.yaml
$ MCPG_CONFIG=config.yaml mcpg
```

---

## Production hardening

Goal: external traffic, OIDC, audit you can ship to compliance, multi-replica behind an LB. Pick this once dev clicks.

**Templates:** `production-single-redis` (single instance), `production-redis-cluster` (multi-replica), `production-nats-cluster` (NATS variant) — all available via `mcpg config init --template <name>`.

| Block | What it gates | Reference |
|---|---|---|
| `gateway.server.tls` | Listener TLS — drop if your LB terminates TLS instead. | [`TlsConfig`](#tlsconfig) |
| `gateway.server.allowed_origins` | Browser CORS allowlist. Wildcards are rejected. | [`ServerConfig`](#serverconfig) |
| `gateway.server.max_sessions_per_tenant` | Per-tenant session quota. 0 = unlimited; tighten for SaaS deploys. | [`ServerConfig`](#serverconfig) |
| `cluster` | Coordinator (KV + pub/sub). `single_node` for single-replica, `redis` / `nats` for multi-replica. | [`ClusterConfig`](#clusterconfig) |
| `governance.access.oidc_oauth` | Inbound OIDC — verifies Bearer tokens against your IdP's JWKS. | [`OidcOAuthConfig`](#oidcoauthconfig) |
| `governance.access.jwks` | Static JWKS variant for air-gapped deploys (no IdP discovery call). | [`JwksConfig`](#jwksconfig) |
| `governance.policy` | Pre-dispatch tool gate. `default_minimum_trust` + per-tool overrides + CEL `allow_if`. | [`PolicyConfig`](#policyconfig) |
| `governance.audit` | Compliance audit fan-out. `required: true` refuses to boot without a serving sink. | [`AuditConfig`](#auditconfig) |
| `governance.approvals` | Human-in-the-loop approvals — signing key + callback URL + grace window. | [`ApprovalsConfig`](#approvalsconfig) |
| `plugins[]` | Tool-gate / transform / identity / cluster / catalog plugins. Rate limiting, IP allowlist, circuit breakers all live here. Each entry carries its own `signature.trusted_keys:` + `granted_capabilities:` (per-entry, not a wiring block). | [`PluginEntryConfig`](#pluginentryconfig) |
| `observability.metrics` / `traces` | Prometheus scrape endpoint + OTLP traces to your collector. | [`MetricsConfig`](#metricsconfig), [`TracesConfig`](#tracesconfig) |

**Cluster pub/sub inheritance.** Capability `store:`/`bus:` overrides default to `kind: cluster` (the cluster backend's primitive) when omitted, so when `cluster.kind` is `redis` or `nats`, `mcp.configurations.delivery.bus` and `mcp.configurations.cancellation.bus` automatically use the cluster's pub/sub. Server-initiated messages (cancellations, sampling responses, elicitations) reach the right replica without operator config. Override these only when you explicitly want single-replica behaviour despite a cluster (e.g. `bus: { kind: memory }`).

---

## Advanced / experimental

Goal: pipeline tools, server-initiated suspensions, per-plugin observability carve-outs, control-plane attachment. Ignore until production basics are solid.

| Feature | Block | Reference |
|---|---|---|
| Pipeline bindings — multi-step tools that chain HTTP / SQL / Command / Transform / CEL gate steps. | `mcp.capabilities.tools[].backend: { kind: pipeline, steps: [...] }` | [`PipelineBackendConfig`](#pipelinebackendconfig), [`PipelineStepConfig`](#pipelinestepconfig) |
| Suspending pipeline steps — `elicitation`, `sampling`, `roots_list`. The pipeline pauses, the gateway sends a server-initiated request, the step resumes when the client responds. | `mcp.capabilities.tools[].backend.steps[].kind: elicitation \| sampling \| roots_list` | [`PipelineElicitationStepConfig`](#pipelineelicitationstepconfig), [`PipelineSamplingStepConfig`](#pipelinesamplingstepconfig), [`PipelineRootsListStepConfig`](#pipelinerootsliststepconfig) |
| Approval gates — block a tool call until a human approves it via callback URL. | `governance.approvals` + plugin entry for the approvals provider | [`ApprovalsConfig`](#approvalsconfig) |
| MCP App URL — link a resource to a rich UI for client-side rendering. | `mcp.capabilities.resources[].mcp_app_url` / `mcp.capabilities.resource_templates[].mcp_app_url` (CEL-templatable) | [`BackendConfig`](#backendconfig) |
| Resource subscription with custom watch strategy — push-based change notification with `notifications/resources/updated`. | `mcp.capabilities.resources[].watch` / `mcp.capabilities.resource_templates[].watch` | [`ResourceWatchConfig`](#resourcewatchconfig) |
| Per-plugin observability override — silence a noisy plugin or boost its verbosity in isolation, optionally redirect its events to a separate sink set. | `plugins[].observability` | [`PluginObservabilityToggle`](#pluginobservabilitytoggle), [`SignalToggle`](#signaltoggle), [`SinkMode`](#sinkmode) |
| Control-plane attachment — gateway registers with a CP at boot, opens an agent Channel, ships per-tool-call samples. | `gateway.control_plane` + `cp-attached` Cargo feature | [`ControlPlaneAttachConfig`](#controlplaneattachconfig) |
| Notification filter — server-side filtering of `tools/list_changed` etc. before broadcast. | `mcp.capabilities.resources[].watch.notification_filter` / `mcp.capabilities.resource_templates[].watch.notification_filter` | [`NotificationFilterConfig`](#notificationfilterconfig) |
| Plugin config overlay — operator-staged dynamic config delivered via config-provider plugins (consul / k8s ConfigMap / etc.). | `gateway.config_overlay` | [`ConfigOverlayConfig`](#configoverlayconfig) |

---

## Multi-tenant deployments

MCPG has no top-level `tenants:` block by design. Per-tenant differentiation composes from three orthogonal primitives that already exist:

1. **Tenant identity.** Comes off the verified principal — `identity.subject_id`, `identity.attributes.<claim>`, `identity.roles[]`, `identity.groups[]`. Whichever OIDC claim represents your tenant (commonly `tid`, `org_id`, or a custom claim) ends up under `identity.attributes.<claim>` once the inbound JWT verifier resolves it. No config knob is needed for the tenant ID itself.

2. **Per-tenant binding allowlist.** Goes through `governance.policy.tool_access.rules[].cel_allow_if`. Each binding gets a CEL predicate that references the principal's tenant claim:

   ```yaml
   governance:
     policy:
       tool_access:
         default_minimum_trust: verified
         rules:
           - tool_name: "acme.*"
             cel_allow_if: 'identity.attributes.tenant == "acme" || "platform" in identity.groups'
           - tool_name: "partner.*"
             cel_allow_if: 'identity.attributes.tenant == "partner"'
           # shared.* falls through to default_minimum_trust (any verified caller).
   ```

   The CEL predicate runs pre-dispatch alongside trust-floor checks, so a deny is observable through the same audit shape (`mcpg.policy.tool_call.denied`) as any other policy denial.

3. **Per-tenant rate limit + quota.** Lives in the rate-limit plugin (rate limiting is plugin-only). The plugin's config is keyed by tenant identity from the same `identity` surface. Example shape (rate-limit plugin's config; the actual fields depend on the plugin you load):

   ```yaml
   plugins:
     - id: dev.mcpg.builtin.rate_limit
       config:
         default:
           tools_per_minute: 1000
         by_tenant:
           acme: { tools_per_minute: 10000, burst: 200 }
           partner: { tools_per_minute: 100, burst: 10 }
         tenant_key: 'identity.attributes.tenant'
   ```

   Per-binding rate-limit references go through the backend's own per-use slot (point-of-use wiring) — same shape as any other plugin reference.

The pre-existing `gateway.server.max_sessions_per_tenant` knob is the one *gateway-resident* tenant-aware quota; it's enforced inside the session store (per-tenant cap on concurrent sessions) and works regardless of which CEL gate let the request through.

A first-class `tenants:` block that desugars into the above is a possible future addition. Until the recipes turn out painful in operator hands, the existing primitives stay the source of truth — adding a parallel mechanism would split tenant config across two places.

---

## Templating and secret resolution

MCPG uses a single CEL-based expression syntax everywhere — `${...}` outer markers wrap a CEL expression. There's exactly one form for environment variables, identity, arguments, OAuth tokens, and credential lookups; no parallel layers.

```yaml
mcp:
  capabilities:
    tools:
      - name: github.user.repos.list
        description: Fetch a user's repositories from GitHub.
        backend:
          kind: http
          url: "https://api.github.com/users/${arguments.username}/repos"
          method: get
          headers:
            Authorization: "Bearer ${env.GITHUB_TOKEN}"
            X-Trace-Id: "${context.principal_id}-${arguments.username}"

gateway:
  plugin_registry:
    auth:
      username: "${env.GHCR_USERNAME}"
      password: "${env.GHCR_TOKEN}"

plugins:
  # Outbound OAuth 2.0 (RFC 6749 client_credentials) lives behind
  # the `dev.mcpg.credential.oauth-client-credentials` plugin.
  # Bindings reference issued tokens via the standard `cred://`
  # URI scheme — see the table below.
  - id: dev.mcpg.credential.oauth-client-credentials
    config:
      providers:
        analytics:
          token_url: "https://auth.example.com/oauth/token"
          client_id: "mcpg-prod"
          client_secret: "${env.ANALYTICS_CLIENT_SECRET}"
          scopes: ["read:events"]
```

**Available roots:**

| Root | Resolved at | Notes |
|---|---|---|
| `env.<NAME>` | Config-load (once) | Process environment. Errors if unset. |
| `arguments.<key>` | Per request | Tool-call arguments. |
| `identity.<field>` | Per request | `subject_id`, `attributes.<key>`, `roles[N]`, `groups[N]`, … |
| `cred://<plugin_id>/<target>[#part]` | Per request | Credential plugin lookup. Covers outbound OAuth tokens (`cred://dev.mcpg.credential.oauth-client-credentials/<provider>`), Vault dynamic DB creds (`cred://vault-dynamic-db/orders#username`), and any other registered `credential_issuer` plugin. |
| `context.<field>` | Per request | Transport, principal, trust level, etc. |
| `tool_name` | Per request | Current tool's MCP name. |
| `steps.<id>.output` | Pipeline only | Previous step's result. |

`env.X` is resolved once at config-load — restarts pick up new values. Everything else is per-request, so a token rotation reaches in-flight calls on the next dispatch without a reload.

---

## Reference

What follows is the full alphabetical reference of every type reachable from `AppConfig`, generated from `///` rustdoc + `#[serde(...)]` annotations. Use `mcpg config explain <field>` to drill into a single field on the command line.

## Top-level structure (`AppConfig`)

Every field on the root `AppConfig`, alphabetised. Click a type to jump to its per-block reference below.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cloud` | [`CloudConfig`](#cloudconfig) | (see type) | `cloud:` — managed-fleet (mcpg.cloud) identity + placement. Absent for self-host; inert when present-but-empty, so the gateway binary is byte-identical whether or not it runs in the cloud. Server-managed fields (`instance_id`, `subdomain`, `provenance.*`) are stamped by the provisioner/operator and ignored if hand-written. |
| `cluster` | [`ClusterConfig`](#clusterconfig) | (see type) | Cluster coordinator. Singleton: the operator picks one coordinator and configures it inline. Default is the built-in single-node coordinator — safe for single-instance deployments. Other kinds map to `mcpg-plugin-cluster-*` cdylib plugins; the cdylib must still be declared under `plugins[]` for the gateway to load it. The inline `cluster` block is the single source of truth for the coordinator's runtime config — it overrides any `config:` block on the matching `plugins[]` row. |
| `credentials` | [`CredentialsConfig`](#credentialsconfig) | (see type) | `credentials:` — the gateway-side L1 credential cache for `cred://` URI substitution (sizing, per-entry TTL cap, the `key_attributes` cache-key dimension) plus the optional cluster pub/sub wrapper. Defaults are safe for single-node; a multi-instance deploy issuing per-caller dynamic credentials configures `credentials.cluster` to keep peer caches consistent. |
| `debug` | [`DebugConfig`](#debugconfig) | (see type) | Operator-defined diagnostic tools (`mcpg.command.*` / `mcpg.network.*`) plus their probe profiles. The block is fully ignored unless `feature_flags.debug_tools_enabled` is `true`; production deploys keep that flag off and treat this block as scaffolding for CI / dev rollouts. |
| `feature_flags` | [`FeatureFlagsConfig`](#featureflagsconfig) | (see type) | Operator-controlled strictness / compatibility flags. Every flag defaults off; flipping one is an explicit acknowledgement that the operator is taking on the risk the default protects against. Collapsing them into this block lets them show up in the curated reference + JSON Schema and audit-emit when active. |
| `gateway` | [`GatewayConfig`](#gatewayconfig) | (see type) | `gateway:` umbrella — the binary's network face: listener (`server`), admin surface (`admin`), Control Plane attachment (`control_plane`). |
| `governance` | [`GovernanceConfig`](#governanceconfig) | (see type) | `governance:` umbrella — tool-call lifecycle: identity (`access`) → authorization (`policy`) → human gate (`approvals`) → evidence (`audit`). Co-located under one umbrella so the governance story reads as a coherent block. |
| `license` | [`LicenseConfig`](#licenseconfig) | (see type) | `license:` — offline license token (or the non-production declaration) for standalone deployments; the plugin load gate refuses entitlement-gated plugins the resolved envelope does not admit. Ignored when `gateway.control_plane` is attached. |
| `mcp` | [`McpConfig`](#mcpconfig) | (see type) | `mcp:` namespace — the MCP protocol surface. Two children: `capabilities:` (tools / prompts / resources / resource_templates / tasks / elicitation / sampling / roots — what the server advertises in `initialize`) and `configurations:` (sessions / pipelines / subscriptions / delivery / cancellation — runtime-emergent state). Capability persistence (`store:` / `bus:`) defaults to `kind: cluster` — the cluster coordinator's primitive — and can be overridden per capability with `kind: memory` / `file`. |
| `observability` | [`ObservabilityConfig`](#observabilityconfig) | (see type) | All observability concerns — log/metric/trace emission, the binding-backend health prober, and the sink fan-out routing for telemetry / log events. Sub-fields all default to safe single-node values so the block is fully optional. |
| `plugins` | array&lt;[`PluginEntryConfig`](#pluginentryconfig)&gt; | `[]` | Loaded plugin entries — flat array, no wrapper. Each entry is self-contained (id / class / source / signature / config / limits / enforce / granted_capabilities / observability / http_route / disabled). Identity / policy / credential / catalog / cluster plugins all dispatch via the `class:` field. An empty array is the kill switch — no plugins are loaded. |
| `schema_registry` | map&lt;string, [`SchemaEntry`](#schemaentry)&gt; | `{}` | Named JSON Schemas operator-declared once, referenced by `{"$schema_ref": "<name>"}` in any binding's `input_schema:` / `output_schema:`. Named `schema_registry:` (rather than `schemas:`) to disambiguate from the per-binding schema fields (`input_schema:`, `output_schema:`). Each entry (`SchemaEntry`) is inline / file / url. |
| `storage` | [`StorageConfig`](#storageconfig) | (see type) | `storage:` block. Holds operator-declared content-store providers AND the gateway-managed LLM response cache. Each provider entry produces a named `ContentStore` in the gateway's registry; bindings reference providers by id via their own `content_storage:` field. When `providers` is empty AND no binding declares a `content_storage:` route, the gateway auto-creates a single in-process provider with id `default` and the standard 256 MiB cap. |
| `usage_reporting` | [`UsageReportingConfig`](#usagereportingconfig) | (see type) | `usage_reporting:` — anonymous adoption ping. A minimal, vendor-facing, opt-out signal (product version + first-party plugin set) so we can see how the community grows. Wholly distinct from `observability:` (the operator's own OTel/metrics/log sinks). Fail-open, schema-pinned, and self-suppressing when air-gapped / licensed / CP-attached / CI; also disabled by `DO_NOT_TRACK` / `MCPG_TELEMETRY=off`. |


## Per-block reference

Every type reachable from `AppConfig`, alphabetised. Field tables show type, default, and the field's `///` doc-comment summary.

### `AccessConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `authorization_server` | [`AuthorizationServerConfig`](#authorizationserverconfig) (optional) |  | Embedded Enterprise-Managed Authorization server (MCP `io.modelcontextprotocol/enterprise-managed-authorization`). When set, the gateway acts as the OAuth Resource Authorization Server for ID-JAG grants: it serves RFC 8414 metadata at `GET /.well-known/oauth-authorization-server` advertising the `urn:ietf:params:oauth:grant-profile:id-jag` grant profile, and redeems Identity Assertion JWT Authorization Grants issued by the configured trusted enterprise IdPs at `POST /oauth/token` (`urn:ietf:params:oauth:grant-type:jwt-bearer`), minting audience-restricted access tokens the gateway itself accepts. Only this grant is supported — there is no authorization endpoint, no refresh tokens, and no dynamic client registration. |
| `jwks` | [`JwksConfig`](#jwksconfig) (optional) |  |  |
| `oidc_oauth` | [`OidcOAuthConfig`](#oidcoauthconfig) (optional) |  |  |
| `resource_metadata` | [`OAuthResourceMetadataConfig`](#oauthresourcemetadataconfig) (optional) |  | OAuth 2.1 Protected Resource Metadata (RFC 9728). When set, enables `GET /.well-known/oauth-protected-resource`. If omitted but oidc_oauth providers are configured, metadata is auto-derived. |

### `AdminAuthConfig`

**Variants:**

- **`static_bearer`**
  - `bearer_token_env`: string

- **`trusted_header`** — Security: trusted-header mode requires a value match via `trusted_value_env`. Header-presence-only is insecure and generates warnings on every request.
  - `header_name`: string
  - `trusted_value_env`: string (optional)

- **`disabled`**

### `AdminConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`AdminAuthConfig`](#adminauthconfig) | (see type) |  |
| `base_path` | string | `"/admin/v1"` |  |
| `bind_address` | string | `"127.0.0.1:9090"` |  |
| `disclosure` | [`DisclosureLevel`](#disclosurelevel) | `"summary"` |  |
| `enabled` | boolean | `false` |  |

### `Align`

Horizontal cell alignment.

**Allowed values:**

- `start`
- `center`
- `end`

### `AppColumn`

A table column bound to a JSON-path over each row.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `align` | [`Align`](#align) (optional) |  |  |
| `field` | string |  | JSON-path into the row object. |
| `format` | [`ColumnFormat`](#columnformat) | `"text"` |  |
| `header` | string (optional) |  |  |
| `visible_if` | string (optional) |  | Client-evaluated visibility expression over the row. |
| `width` | string (optional) |  |  |

### `AppCspDecl`

Per-app author CSP declaration. Each axis is still intersected by the egress `csp_policy`; declaring an axis can only narrow, never widen.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `connect_domains` | array&lt;string&gt; |  |  |
| `frame_domains` | array&lt;string&gt; |  |  |
| `redirect_domains` | array&lt;string&gt; |  |  |
| `resource_domains` | array&lt;string&gt; |  |  |

### `AppDensity`

Layout density.

**Allowed values:**

- `comfortable`
- `compact`

### `AppField`

A detail/form field bound to a JSON-path.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `field` | string |  |  |
| `format` | [`ColumnFormat`](#columnformat) (optional) |  |  |
| `label` | string (optional) |  |  |

### `AppProvidedTool`

A read-only App-Provided Tool: surfaces client state to the agent.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `description` | string (optional) |  |  |
| `name` | string |  | Advertised name; the host sees it auto-prefixed `app.<id>.<name>`. |
| `source` | [`AppToolSource`](#apptoolsource) |  | Which whitelisted client reader backs this tool. |

### `AppRowAction`

A per-row action: a `tools/call` with arguments mapped from the row.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `arg_map` | map&lt;string, string&gt; |  | argName → JSON-path over the row. |
| `confirm` | string (optional) |  | Optional confirmation prompt before firing. |
| `id` | string |  |  |
| `label` | string |  |  |
| `tool` | string |  | The tool this action invokes (re-enters the full pipeline). |

### `AppTheme`

Accent + density theming hints for the shell.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `accent` | string (optional) |  |  |
| `density` | [`AppDensity`](#appdensity) (optional) |  |  |

### `AppToolSource`

The whitelisted read-only client state sources for App-Provided Tools.

**Allowed values:**

- `selection`
- `visible_rows`
- `form_draft`
- `map_viewport`

### `ApprovalsConfig`

Tool-gate human approval configuration.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `callback_base_url` | string (optional) |  | Public base url the gateway hands to notifiers as the callback URL prefix (e.g. `"https://gw.example.com"`). The runtime appends `/webhooks/approvals/<id>?expires=...&sig=...`. |
| `callback_grace_ms` | integer | `60000` | Seconds beyond `deadline_at` during which late callbacks still authenticate. Defence-in-depth — the registry's own deadline timer already rejects late resolutions; this just keeps the URL valid for short retries. Default 60s. |
| `signing_key_env` | string (optional) |  | Env var name from which the gateway reads the HMAC signing key for approval callback URLs. The key MUST be at least 32 bytes (256 bits) — the gateway hard-fails boot if shorter. When unset, the gateway falls back to a random per-process key (callbacks won't survive a restart). |

### `AppsConfig`

`apps:` config — SEP-1865 MCP Apps support.

MCP Apps lets a server attach an interactive HTML UI to a tool. The `ui/*` postMessage protocol runs host↔iframe and never reaches the gateway; MCPG's role is passthrough of `_meta.ui`, capability advertisement (both downstream to clients and upstream to federated servers), federation `resourceUri` rewriting, and a tighten-only CSP/permission policy layer.

Off by default. When `enabled: false`, MCPG omits the `io.modelcontextprotocol/ui` extension from its capability advertisement and applies no policy — but `_meta.ui` still round-trips on tool/resource descriptors (passthrough is wire-shape, not capability-gated, so a client with a cached template keeps working). When `enabled: true`, advertisement lights up and the `csp_policy` / `allowed_permissions` / `allowed_domains` clamps below are enforced on egress.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allowed_domains` | array&lt;string&gt; (optional) |  | If set, a `_meta.ui.domain` outside this list is dropped (the host falls back to its default sandbox origin); in `strict` mode the whole response is rejected instead. `None` ⇒ any domain allowed. |
| `allowed_permissions` | array&lt;[`AppsPermission`](#appspermission)&gt; | (see type) | iframe permissions MCPG will let through; any `_meta.ui.permissions` key outside this list is stripped on egress. Default: all four standard permissions. |
| `csp_policy` | [`AppsCspPolicy`](#appscsppolicy) | (see type) | CSP upper bound. Each axis is **intersected** (never unioned) with the upstream's declared `_meta.ui.csp`. `["*"]` on an axis imposes no bound on that axis (upstream passes through). An *omitted* axis on the upstream is left omitted (the host applies its restrictive default — `frame-src 'none'` / `base-uri 'self'`); policy never materializes an absent axis. |
| `enabled` | boolean | `false` | Master switch for DOWNSTREAM advertisement + egress policy. Default `false` (opt-in). |
| `federate_upstream` | boolean (optional) |  | Advertise the Apps capability on MCPG's OUTGOING (client→upstream) `initialize` so federated servers emit their UI-enabled tools. A spec-compliant upstream checks the client's `io.modelcontextprotocol/ui` capability before registering UI tools — omit this and such an upstream withholds every UI tool. `None` ⇒ inherit `enabled`. Set `true` explicitly to pull UI tools from upstreams while still withholding the capability from your own clients. |
| `registry` | array&lt;[`GatewayAppConfig`](#gatewayappconfig)&gt; |  | Gateway-authored templated apps. Each entry mints a `ui://mcpg/<id>` resource whose behavior is driven by this config; the gateway ships the HTML, the operator supplies only the binding. Empty ⇒ no authored apps (pure proxy posture). Non-empty requires `enabled: true`. |
| `strict` | boolean | `false` | Reject (vs sanitize) an upstream response whose `_meta.ui` escaped the policy below — a domain/permission/CSP entry outside the operator allow-list. Default `false` (permissive: narrow + log, never reject). |

### `AppsCspPolicy`

The CSP-axis allow-lists. Defaults mirror a sensible middlebox posture: no bound on what the app may fetch/connect/redirect to (`["*"]`), but frame embedding and `<base>` pinned to `self`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `base_uri_domains` | array&lt;string&gt; | (see type) |  |
| `connect_domains` | array&lt;string&gt; | (see type) |  |
| `frame_domains` | array&lt;string&gt; | (see type) |  |
| `redirect_domains` | array&lt;string&gt; | (see type) | Allow-list for `openExternal` redirect targets. Clamps only the OpenAI `openai/widgetCSP.redirect_domains` alias (there is no `_meta.ui.csp` axis for it). Default `["*"]` ⇒ no bound. |
| `resource_domains` | array&lt;string&gt; | (see type) |  |

### `AppsPermission`

A standard iframe permission. Serialized snake_case in config; maps to the camelCase `_meta.ui.permissions` key on the wire.

**Allowed values:**

- `camera`
- `microphone`
- `geolocation`
- `clipboard_write`

### `AuditConfig`

Top-level `audit:` block. A top-level peer (rather than nested under `observability:`), with an inner schema aligned to the OTel signal-triad sinks-list pattern (`logs` / `metrics` / `traces`). Spec §9.12 defines the semantics; the fields here are the Rust projection.

Audit sinks fan out via `sinks: [{kind, config, level?}]`. The built-in `dev.mcpg.builtin.audit.local-file` activates only when its plugin id appears in `sinks[].kind` (there is no `disable_builtins` toggle — just omit the sink to disable it).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `emit_tool_call_allowed` | boolean | `true` | Emit `mcpg.tool.call.allowed` after every successful pre-dispatch tool_gate chain. Default `true` for the compliance posture most operators want — every tool call on record. High-volume / low-compliance deploys can set `false`; deny + challenge paths still emit regardless. |
| `emit_tool_call_completed` | boolean | `true` | Emit `mcpg.tool.call.completed` after every successful post-dispatch tool_gate chain. Default `true`. Records `execution_duration_ms` for auditors flagging long-running calls. |
| `enabled` | boolean | `true` | Master toggle for the audit channel. When `false`, no audit sinks are registered (built-in or plugin), no audit events are emitted, and `required` is ignored. Default `true`. Set `false` only for dev/test runs where compliance is out of scope. |
| `on_failure` | [`AuditOnFailure`](#auditonfailure) | `"fail_closed"` | Policy for per-event emit failures. Today the fan-out is always best-effort at the registry level (failures are metricsed but don't block the request). This field is captured + validated so the operator's intent is durable; the runtime behavior hookup lands in a future improvement (the emit site needs to translate this into "return error from the tool-gate chain" on `fail_closed`). |
| `required` | boolean | `true` | When `true` (default), the gateway REFUSES TO START unless at least one audit sink is serving traffic after plugin registration completes. Ignored when `enabled: false`. Operators explicitly set `false` only for dev / CI runs where compliance is not in scope. |
| `sinks` | array&lt;[`SinkConfig`](#sinkconfig)&gt; | (see type) | Audit-sink fan-out. Each entry's `kind:` is a plugin id resolved against the registered audit sinks at boot. The built-in `dev.mcpg.builtin.audit.local-file` is the canonical default — listed in [`AuditConfig::default`]. |

### `AuditOnFailure`

Operator policy when an audit-sink `emit` fails.

**Variants:**

- **`fail_closed`** — (default) On emit failure, refuse to serve the triggering request. Compliance-safe: no action happens without a durable audit trail. Subtle: this can wedge the gateway if every registered sink is broken — operators should always configure at least one sink whose availability they actually monitor.

- **`fail_open`** — On emit failure, log + continue. The triggering request completes even if the audit event does not persist. Dev / CI use only — a compliance auditor will not accept this as SOC2-clean.

### `AuthConfig`

How MCPG authenticates to the upstream.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `credential` | string (optional) |  | Credential-issuer reference for `oauth_client_credentials`: a standard `cred://<plugin_id>/<target>` URI, e.g. `cred://dev.mcpg.credential.oauth-client-credentials/notion`. The referenced issuer plugin mints + refreshes the upstream bearer; no client secret lives in the federation config. |
| `credential_config` | any |  | Per-issuance config object forwarded verbatim to the credential issuer on the OAuth modes (a template issuer's `audience` / `resource` / `redeem_token_url` overrides). Registry OAuth discovery populates this on synthesized federations; hand-written federations may set it to steer a template provider without a per-target issuer entry. |
| `mode` | [`AuthMode`](#authmode) | `"none"` |  |
| `token` | string (optional) |  | Static bearer token for `service_token` (supports `${env.X}`). |

### `AuthMode`

Identity-propagation mode: what the gateway presents to the upstream.

**Variants:**

- **`none`** — No auth sent.

- **`service_token`** — Static bearer token.

- **`pass_through`** — Forward the inbound `Authorization` header verbatim.

- **`oauth_client_credentials`** — Machine-identity token via an OAuth provider.

- **`oauth_impersonation`** — Per-caller token-exchange (RFC 8693).

### `AuthorizationServerClientConfig`

One OAuth client registered with the embedded authorization server.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `client_id` | string |  | The client identifier the enterprise IdP binds into ID-JAGs (`client_id` claim). For MCP clients identifying via a Client ID Metadata Document, this is the document URL. |
| `client_secret` | string (optional) |  | Client secret for `client_secret_basic` / `client_secret_post` authentication. Supply via `${env.X}`. Omit to register a public client (`token_endpoint_auth_method: none`). |

### `AuthorizationServerConfig`

Embedded EMA authorization server (`governance.access.authorization_server`).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `access_token_ttl_secs` | integer | `3600` | Lifetime of minted access tokens, in seconds. |
| `allowed_scopes` | array&lt;string&gt; (optional) |  | When set, the scopes granted on minted tokens are the intersection of the ID-JAG's `scope` claim with this list (the resource server may narrow, never widen, IdP-granted scopes). When omitted, IdP-granted scopes pass through unchanged. |
| `clients` | array&lt;[`AuthorizationServerClientConfig`](#authorizationserverclientconfig)&gt; | `[]` | OAuth clients allowed to redeem ID-JAGs at the token endpoint. Clients with a `client_secret` authenticate via `client_secret_basic` or `client_secret_post`; clients without one are public (`none`) — register an MCP client's Client ID Metadata Document URL as its `client_id` for that case. The ID-JAG's `client_id` claim must match the presenting client either way. |
| `clock_skew_secs` | integer | `60` | Clock-skew leeway applied to ID-JAG `exp`/`iat`/`nbf` validation, in seconds. |
| `enforce_single_use` | boolean | `true` | Enforce single-use ID-JAG redemption per instance: a `jti` seen once is refused until the assertion expires. Defense-in-depth on top of the assertion's short lifetime. |
| `issuer` | string |  | This authorization server's issuer identifier (RFC 8414). MUST be the canonical external `http(s)` origin the gateway is reached at — enterprise IdPs bind ID-JAGs to it as the `aud` claim, compared exactly. Also the `iss` of every access token this server mints. |
| `resource` | string (optional) |  | Resource identifier minted access tokens are audience-restricted to (RFC 8707). Defaults to `governance.access.resource_metadata.resource` when that block is configured, else to `issuer`. An ID-JAG carrying a `resource` claim must match this value or redemption fails with `invalid_target`. |
| `signing_secret` | string |  | HS256 signing secret for minted access tokens (≥ 32 bytes). Supply via `${env.X}`. Every gateway instance in a cluster must share this value so any instance can verify tokens minted by any other. |
| `trusted_idps` | array&lt;[`TrustedIdpConfig`](#trustedidpconfig)&gt; | `[]` | Enterprise IdPs trusted to issue ID-JAGs. An assertion whose `iss` is not listed here is refused (`invalid_grant`). |

### `BackendAnnotationsConfig`

Tool annotation hints configurable per binding. Maps to MCP `ToolAnnotations`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `destructive` | boolean (optional) |  |  |
| `idempotent` | boolean (optional) |  |  |
| `open_world` | boolean (optional) |  |  |
| `read_only` | boolean (optional) |  |  |

### `BackendConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `annotations` | [`BackendAnnotationsConfig`](#backendannotationsconfig) (optional) |  |  |
| `backend` | [`BackendImpl`](#backendimpl) |  | Implementation backend — discriminated by `kind:`. The backend is an explicit nested object (`backend: { kind: http, url: ... }`) rather than fields hoisted onto the binding itself. |
| `cache` | [`KindRef`](#kindref) (optional) |  | Per-binding LLM response-cache override. Resolves via `resolve_kind(SlotClass::Cache, ...)` at boot: |
| `content_storage` | string (optional) |  | Content-store provider this binding routes through. Must match one of the `storage.providers: [{id, ...}]` entries declared at the top level. When unset, the binding falls back to the provider id named in `content_storage.default` (or the conventional `default` id when neither is set). |
| `description` | string |  |  |
| `descriptor_meta` | any |  |  |
| `governance` | [`BackendGovernanceConfig`](#backendgovernanceconfig) | (see type) |  |
| `icons` | array&lt;[`BackendIconConfig`](#backendiconconfig)&gt; (optional) |  | MCP 2025-11-25 descriptor extensions — icons and free-form `_meta`. Populated directly on the tool/prompt/resource/template descriptor that this binding produces. |
| `input_schema` | any |  |  |
| `mcp_app_url` | string (optional) |  | MCP App URL — a link to a rich UI for this resource. Populated on `_meta.mcpAppUrl` in resources/list descriptors and resources/read results. Supports CEL interpolation for dynamic segments (e.g., `https://app.example.com/docs/${arguments.id}`). Only meaningful on `kind: resource` or `kind: resource_template`. |
| `mime_type` | string (optional) |  |  |
| `name` | string |  |  |
| `output_schema` | any |  |  |
| `prompt_arguments` | array&lt;[`PromptArgumentConfig`](#promptargumentconfig)&gt; (optional) |  |  |
| `quotas` | [`BackendQuotasRef`](#backendquotasref) (optional) |  | Per-binding quota policy reference. Names at most one of each kind by id; each id must resolve to a registered policy in `governance.quotas.{rate_limits,budgets,concurrency}[]`. `None` (default) means this binding is exempt from quota enforcement. The runtime gate that consults this field is behind the `governance-quotas` cargo feature — until that feature is on, the field is parsed + validated but inert. |
| `resource_annotations` | [`BackendResourceAnnotations`](#backendresourceannotations) (optional) |  | Optional resource annotations (`audience`, `priority`, `lastModified`) surfaced on `resources/list` entries. Meaningful only on `kind: resource` or `kind: resource_template` bindings. |
| `resource_size` | integer (optional) |  | Optional per-resource size hint (bytes) surfaced on `resources/list` entries. Meaningful only on `kind: resource` bindings; ignored elsewhere. |
| `retry` | [`RetryConfig`](#retryconfig) (optional) |  |  |
| `task_support` | string (optional) |  |  |
| `title` | string (optional) |  |  |
| `uri` | string (optional) |  |  |
| `uri_template` | string (optional) |  |  |
| `variable_completions` | map&lt;string, [`VariableCompletionSource`](#variablecompletionsource)&gt; (optional) |  | Optional completion sources per template variable. The `completion/complete` handler returns the filtered subset matching the caller's prefix when the MCP client opens auto-complete on a resource template variable. Keys MUST match a `{variable}` declared in `uri_template`; mismatched keys are dropped at registration with a warning. |
| `watch` | [`ResourceWatchConfig`](#resourcewatchconfig) (optional) |  |  |

### `BackendGovernanceConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_if` | string (optional) |  |  |
| `minimum_trust` | [`TrustLevelConfig`](#trustlevelconfig) | `"header_asserted"` |  |

### `BackendIconConfig`

Configurable descriptor icon shape, mirrored onto MCP's `Icon` type.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `mime_type` | string (optional) |  |  |
| `sizes` | array&lt;string&gt; (optional) |  |  |
| `src` | string |  |  |
| `theme` | string (optional) |  |  |

### `BackendImpl`

Implementation backend, identified by `kind:` with an opaque flattened `spec`. The gateway enumerates NO plugin kinds: a binding names a `kind` (a loaded `BackendPlugin::kind()` string) and every other key flattens into `spec`, forwarded verbatim to the plugin's `register_profile` / `execute`. The plugin owns and validates the schema; the gateway resolves `kind` against the registry at boot and fails closed on unknown / non-backend kinds. Mirrors `WatchStrategyConfig::Plugin`.

`spec` is an open object (no `deny_unknown_fields`); unknown keys are forwarded verbatim, so a spec-key typo is caught only by the owning plugin's `register_profile` (`InvalidSpec` at boot), not at config-load.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `kind` | string |  | Target `BackendPlugin::kind()` string, resolved against the registry at boot. |

### `BackendQuotasRef`

Per-binding quota reference — operator names at most one of each policy kind by id. The runtime gate that consults these refs is gated behind the `governance-quotas` cargo feature.

All three fields are independent options; an absent field means "no policy of that kind for this binding". A binding may name more than one kind at once (e.g. both a rate limit AND a concurrency cap), but at most one policy of each kind.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `budget` | string (optional) |  | Id from `governance.quotas.budgets[].id`. Optional. |
| `concurrency` | string (optional) |  | Id from `governance.quotas.concurrency[].id`. Optional. |
| `rate_limit` | string (optional) |  | Id from `governance.quotas.rate_limits[].id`. Optional. |

### `BackendResourceAnnotations`

Operator-configurable MCP `ContentAnnotations` for a resource binding.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `audience` | array&lt;string&gt; (optional) |  |  |
| `last_modified` | string (optional) |  |  |
| `priority` | number (optional) |  |  |

### `BudgetPolicy`

One named budget policy (cost cap / call count / token count).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `acknowledge_unenforced` | boolean |  | Acknowledge that a `cost` / `token_count` budget is advisory. Per-call USD spend and token usage are not available to the gateway after dispatch, so these caps cannot be enforced at runtime — only `call_count` is. A `cost`/`token_count` budget must set this to load, making the no-op posture an explicit operator choice rather than a silent fail-open. No effect for `call_count`. |
| `cap_calls` | integer (optional) |  | Call cap when `kind: call_count`. Required for that kind. |
| `cap_token_count` | integer (optional) |  | Token cap when `kind: token_count`. Required for that kind. |
| `cap_usd` | number (optional) |  | Cost cap in USD when `kind: cost`. Required for that kind. |
| `id` | string |  |  |
| `identity_claim` | string (optional) |  | JWT claim path for `per_identity` scope. |
| `kind` | string | `"cost"` | Budget kind: `cost` (USD), `call_count`, or `token_count`. |
| `on_exceeded` | string | `"deny"` | Action when the cap is hit (same vocabulary as RateLimitPolicy). |
| `scope` | string | `"per_identity"` | Scope discriminator (same vocabulary as RateLimitPolicy). |
| `warn_at_pct` | integer (optional) |  | Emit `governance.quota.warn` when drawdown crosses this percentage of the cap. Defaults to no warning. `0..=100`. |
| `window` | string |  | Rolling window over which the cap applies. Suffixes `s`/`m`/ `h`/`d`. Maximum `30d`. |

### `BusOverrideConfig`

`<capability>.bus: { kind, … }` — produces an `Arc<dyn mcpg_cluster_api::PubSub>` at boot.

Recognised `kind` values: `cluster`, `memory`. (`redis` and `nats` are not accepted here — set `cluster.kind: redis | nats` and use `kind: cluster` here, or omit the override entirely.)

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `kind` | string |  |  |

### `CancellationConfig`

`cancellation:` config — cluster-wide cancellation fan-out (`notifications/cancelled` and `tasks/cancel`) plus a per-capability `bus:` override. Same shape as `DeliveryConfig`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bus` | [`BusOverrideConfig`](#busoverrideconfig) (optional) |  |  |
| `partition_by_principal` | boolean | `false` | When true, cancellations publish to `mcpg.cancel.<principal>` and the subscriber listens on the `mcpg.cancel.*` wildcard, so broker-native subject ACLs can fence per-principal cancel traffic. Defaults to `false` (a single flat `mcpg.cancel` topic). **Requires a wildcard-capable pub/sub backend (redis/nats)** — `AppConfig::validate` rejects it on the in-process single-node / memory bus, which is exact-match only and would silently drop every cancellation under a wildcard subscribe. |

### `ChildInvokeConfig`

Governance for the agentic child-dispatch surface (`invoke_tool`).

Direct `tools/call` always runs the full pre-dispatch stack; the child path an LLM binding drives did not. When `enforce_gates` is on, child invocations are routed through the same external policy_engine chain and tool_gate plugin chain as a direct call before reaching the backend, so tool-level access controls are not silently absent on the LLM-driven surface.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enforce_gates` | boolean | `false` | Run the policy_engine chain + tool_gate plugin chain on every child `invoke_tool`. Default false (the agentic surface is ungated, matching prior behaviour) — enable to require the same authorization a direct `tools/call` gets. A child whose identity is unresolved (the LLM path carries no per-call principal today) evaluates against the inherited parent identity. |

### `ClaimMappingConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `attribute_claim_mappings` | map&lt;string, string&gt; | `{}` |  |
| `group_claim_paths` | array&lt;string&gt; | `[]` |  |
| `role_claim_paths` | array&lt;string&gt; | `[]` |  |
| `scope_claim_paths` | array&lt;string&gt; | (see type) |  |
| `subject_claim` | string | `"sub"` |  |

### `ClientCertMode`

Operator-facing client-cert acceptance mode.

**Allowed values:**

- `none`
- `optional`
- `mandatory`

### `CloudConfig`

`cloud:` — present only on managed-fleet (mcpg.cloud) instances. Absent for self-host; every field defaults so a bare `cloud: {}` is inert.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_anonymous` | boolean | `false` | Publish-time acknowledgement that this managed instance intentionally serves `/mcp` WITHOUT a configured token verifier (an anonymous / public MCP server). The CP publish guard requires EITHER a verifier (`governance.access.jwks` / `governance.access.oidc_oauth`) OR this opt-out, so a tenant can't expose an unauthenticated gateway on the public edge by omission. The gateway runtime does not read this field — it is a declaration the publish guard checks. |
| `custom_domains` | array&lt;string&gt; |  | Additional customer-owned hostnames that resolve to this instance (CNAME → the instance edge). Developer-owned; each must be a valid DNS hostname. Empty for the default-domain-only case. |
| `environment` | string (optional) |  | Environment slug (dev / staging / prod …). |
| `instance_id` | string (optional) |  | Server-assigned stable id. None for self-host. Read-only — set by the CP. |
| `isolation` | [`CloudIsolation`](#cloudisolation) | `"shared"` | Isolation tier for placement. |
| `name` | string (optional) |  | Human-friendly display name for the instance. |
| `provenance` | [`CloudProvenance`](#cloudprovenance) | `{}` | Server-managed placement provenance. Stamped by the provisioner/operator; ignored / overwritten if hand-written. |
| `region` | string (optional) |  | Placement region hint (free-form; matched against fleet capacity). |
| `subdomain` | string (optional) |  | Globally-unique DNS label that addresses this instance: `https://{subdomain}.mcpg.cloud/mcp`. Read-only — assigned/reserved by the CP. Defaults conceptually to `instance_id` when unset. |
| `tenant` | string (optional) |  | Tenant / org slug — billing + console grouping. Developer-owned. |
| `tier` | [`CloudTier`](#cloudtier) | `"unspecified"` | Billing tier the instance runs under. |
| `workspace` | string (optional) |  | Workspace slug within the tenant. |

### `CloudIsolation`

Default isolation tier for the instance's placement.

**Variants:**

- **`shared`** — Shares a namespace pool with other tenants (default).

- **`dedicated`** — Dedicated nodes / namespace for the tenant.

### `CloudProvenance`

Server-managed placement facts. Never trusted from a published config — the operator overwrites these at render time.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cluster_id` | string (optional) |  |  |
| `external_url` | string (optional) |  | Canonical external URL (`https://{subdomain}.mcpg.cloud/mcp`). Operator-injected into `governance.access.resource_metadata.resource`; OVERWRITTEN at render — never trust a published value. |
| `managed_by` | string (optional) |  |  |
| `namespace` | string (optional) |  |  |
| `provisioned_at` | string (optional) |  |  |

### `CloudTier`

Billing tier the instance was provisioned under.

The variants mirror the licensing vocabulary (`community` | `pro` | `team` | `enterprise`) so this block and a license claim can be compared without a translation table. `free` is accepted as an alias for `community`, which is what this variant used to be called.

**Variants:**

- **`community`**

- **`unspecified`** — No tier asserted (self-host / unmanaged).

### `ClusterConfig`

Top-level cluster config. The cluster plugin is the unified backbone for MCPG multi-instance state + coordination — it internally instantiates the four primitive impls (`KeyValueStore`, `PubSub`, `Lease`, `Watch`) and exposes them via accessor methods. `kind` is the discriminator; everything else is kind-specific config that flows straight to the plugin's factory as JSON.

```yaml cluster: kind: redis              # single_node | etcd | consul | nats | redis url: ${env.REDIS_URL}   # rest of the fields are kind-specific key_prefix: "mcpg:cluster:" ```

`kind: single_node` (the default when `cluster:` is omitted) installs the in-process built-in coordinator and ignores the rest of the block. Other kinds map to `mcpg-plugin-cluster-<kind>`; the cdylib must still be declared under `plugins[]` (the inline `cluster.*` fields override any `config:` block on the matching entry).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_degraded_boot` | boolean | `false` | Tolerate a coordinator that advertises `kv`/`bus` roles but fails the boot reachability probe (a live round-trip against the advertised primitives). Default `false`: for a clustered (non-`single_node`) coordinator the gateway probes each advertised primitive at boot and **refuses to start** if the round-trip fails or the accessor is absent, rather than silently de-clustering to per-replica in-process state. Set `true` ONLY when an operator knowingly wants the gateway to boot and run degraded (per-replica state) despite an unreachable coordinator — it logs a loud error and continues. Gateway-only named field — kept out of the flattened plugin `config`. |
| `allow_insecure_transport` | boolean | `false` | Permit a plaintext (non-TLS) coordinator transport for a non-`single_node` coordinator. Defaults to `false`: `validate()` refuses a plaintext redis/consul/etcd/nats coordinator at boot, because the coordinator carries all shared state (sessions, credentials, delivery) in clear. Set `true` ONLY for local/dev/CI. Gateway-only — NOT forwarded to the plugin (it is a named field, so serde keeps it out of `config`). |
| `kind` | string | `"single_node"` |  |
| `readiness_gate` | [`ClusterReadinessGate`](#clusterreadinessgate) | `"off"` | Whether coordinator health gates `/ready`. Defaults to `off` (fail-open): a coordinator outage is surfaced only via the `mcpg_cluster_backend_up` gauge + its alert, never on readiness. `degrade` adds an informational not-ready *check* to the readiness body but keeps `/ready` green (no LB flapping). `fail` makes `/ready` return not-ready while the coordinator is unreachable (fail-closed). Gateway-only named field — kept out of the flattened plugin `config`. |
| `state_encryption_allow_plaintext_reads` | boolean | `false` | Tolerate plaintext (non-envelope) reads while `state_encryption_key_env` is set — a bounded migration window for rolling a key in across replicas. Default `false`: once a key is configured a plaintext value on the coordinator KV/bus is rejected (fail closed), so an unkeyed peer or attacker cannot inject unauthenticated capability state. Set `true` only transiently during a rollout; turn it off once every replica writes envelopes. Inert without `state_encryption_key_env`. Gateway-only named field — kept out of the flattened plugin `config`. |
| `state_encryption_key_env` | string (optional) |  | Opt-in application-layer AEAD (XChaCha20-Poly1305) of ALL coordinator-backed *capability* state — sessions (incl. SSE replay), delivery, cancellation, tasks, pipelines, idempotency, request-state, subscriptions, quota, and the approvals backstop. Names the **env var** holding a URL-safe-base64 32-byte key (the key itself never sits in the config artifact). Unset = plaintext serde on the wire/at-rest; confidentiality then rests on the transport guard. Values are sealed per-key/per-topic (swap-resistant); keys/topics stay cleartext for routing. Does NOT cover the credential cache — it has its own `encryption_key` under the credentials config. Gateway-only named field — kept out of the flattened plugin `config`. |
| `state_encryption_key_id` | string (optional) |  | Key id (kid) stamped on state envelopes for rotation visibility. Defaults to `mcpg-cluster-state` when a key is configured. Inert without `state_encryption_key_env`. Gateway-only named field. |
| `tenant_segment` | string (optional) |  | Optional per-deployment tenant segment. When set, EVERY coordinator-backed capability KV key and bus topic is prefixed with `t.<segment>/` (keys) / `t.<segment>.` (topics) so a single coordinator namespace can be fenced per-tenant by broker-native ACLs — NATS subject perms `t.<segment>.>`, redis key-pattern ACLs (`~…t.<segment>/*`), consul/etcd path ACLs. Unset = today's flat, un-prefixed keys/topics (one coordinator namespace == one trust domain). This is a **deployment-level** label, not a per-request tenant — the gateway process serves one tenant segment; the runtime carries no per-request tenant at key/topic-formation time, so per-request multi-tenancy remains future work. Turning it on is a key-namespace cutover (existing flat-keyed state goes invisible). Must be a single token (no `. * > / : ` or whitespace). Gateway-only named field — kept out of the flattened plugin `config`. |

### `ClusterReadinessGate`

How coordinator health affects `/ready`.

**Variants:**

- **`off`** — Coordinator health never affects `/ready` (fail-open). Default.

- **`degrade`** — Surface a not-ready *check* in the readiness body when the coordinator is down, but keep the overall `/ready` status green.

- **`fail`** — `/ready` returns not-ready while the coordinator is unreachable.

### `ColumnFormat`

How a cell value is rendered client-side.

**Allowed values:**

- `text`
- `number`
- `currency`
- `date`
- `badge`
- `link`

### `ConcurrencyPolicy`

One named concurrency cap.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `id` | string |  |  |
| `identity_claim` | string (optional) |  |  |
| `max_concurrent` | integer |  | Maximum simultaneous in-flight calls. |
| `on_exceeded` | string | `"deny"` | Action when the cap is hit. `deny` returns immediately; `queue` waits up to `queue_timeout_ms`. |
| `queue_timeout_ms` | integer | `30000` | Timeout for queued callers when `on_exceeded: queue`. Default 30s. |
| `scope` | string | `"per_identity"` | Scope (typically `per_tool`, `global`, or `per_identity`). |

### `ConfigWatchConfig`

`gateway.config_watch:` — operator-tunable file-watch reload trigger. Same semantics as SIGHUP and the admin endpoint: full `GatewayRuntime` rebuild via `ArcSwap`; session store preserved; credential cache rebuilt fresh; `list_changed` emitted per category for operational sessions on inventory delta.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | When true, the gateway watches its config files on disk and triggers a hot-reload when contents change. Polling- based — handles editor-write-via-rename (vim/emacs) and K8s ConfigMap atomic-symlink-swap transparently because the watcher reads through the symlink chain regardless of how the write landed. Defaults to disabled — operators must opt in. |
| `poll_interval_ms` | integer | `5000` | Poll interval in milliseconds. Lower = faster reload after edit; higher = lower disk I/O. Default 5000 (5s) is imperceptible for config changes and trivial in I/O cost. Values below 1000 (1s) are clamped to 1000 at validate time with a warning — sub-second polling burns I/O for no human-perceivable benefit. |

### `ConflictPolicy`

Conflict policy on a body-hash mismatch with a stored record. Today only `Reject` is implemented; `permissive_replay` is not offered.

**Variants:**

- **`reject`** — Same key + different body hash → JSON-RPC error `-32010 IdempotencyConflict` (HTTP 422).

### `ControlPlaneAttachConfig`

Control Plane attachment config. See `apps/gateway/src/runtime/cp/attach.rs` for the wiring logic.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bootstrap_ca_pem` | string (optional) |  | PEM-encoded CA bundle to trust on the very first connect (Register), before the agent has its own creds. Once Register completes, the CP-issued cert/key/ca_chain trio supplants this. Optional; only required when the CP gRPC listener is TLS and the operator hasn't pre-populated a previous run's `agent-creds.json`. |
| `capture_payloads` | boolean | `false` | **Enterprise opt-in.** When `true`, the gateway captures the JSON-serialized request arguments + response of each tool call and ships them in the `MetricsReport` (Channel-encrypted; the CP further encrypts at-rest with a per-tenant KMS-derived key). The captured bytes can contain PII / secrets, so this is off by default; the CP also gates ingest on the active license carrying the `payload_capture` feature flag, so flipping this `true` without a matching license is a no-op (samples ship but CP drops the payload bytes). |
| `enrollment_url` | string (optional) |  | One-time enrollment URL minted by the CP UI. Required on first boot; subsequent boots reuse the cached creds in `state_dir`. |
| `heartbeat_interval_ms` | integer (optional) |  | Seconds between heartbeats. Default 30s. |
| `instance_uid` | string (optional) |  | Stable per-instance id. Defaults to `${HOSTNAME}-${uuid7-prefix}` when unset. |
| `state_dir` | string | `"./mcpg-cp-state"` | Where to persist agent creds (`agent-creds.json`) and the LKG cache. Defaults to `./mcpg-cp-state`. |
| `url` | string |  | gRPC URL of the Control Plane (e.g. `"https://cp.example.com:7844"`). |

### `CredentialsClusterConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_plaintext` | boolean | `false` | Explicit, INSECURE opt-in to publish credential events in plaintext (no `encryption_key_env`). Required to enable cluster credential pub/sub without a key — otherwise the gateway refuses to boot rather than silently broadcasting plaintext credentials. On this path `published_by` is forgeable, so plaintext mode also REQUIRES a non-empty `allowed_publishers`; that allowlist plus broker write-ACLs are the integrity boundary. AEAD via `encryption_key_env` is the only integrity-providing mode. |
| `allowed_publishers` | array&lt;string&gt; (optional) |  | Optional allowlist of peer node ids whose credential-cache events this instance will apply. When `Some`, an `Issued` / `Revoked` event whose `published_by` is not in the list is dropped. This is a genuine control on the **AEAD** path (`published_by` is inside the sealed payload, so it is authenticated) — it bounds the blast radius of a compromised-but-keyed peer. On the plaintext path (`allow_plaintext: true`) it is best-effort only: `published_by` is attacker-forgeable there, so the allowlist raises the bar but is NOT a substitute for `encryption_key_env`. MANDATORY (non-empty) when `allow_plaintext` is set. Unset = accept events from any peer (only valid on the AEAD path). |
| `enabled` | boolean | `false` |  |
| `encryption_key_env` | string (optional) |  | Env var holding a base64-encoded 32-byte key for application-layer AEAD (XChaCha20-Poly1305) of the credential events published on the cluster topic. STRONGLY recommended: without it, per-caller credentials are published as plaintext JSON and confidentiality rests entirely on transport TLS . All peers sharing the topic must use the same key. |
| `encryption_key_id` | string (optional) |  | Key id (kid) stamped on encrypted envelopes so operators can rotate keys. Defaults to `mcpg-cred-cache` when a key is set. |
| `topic` | string (optional) |  | Override the default cluster topic (`mcpg.credentials.events`). Operators with multiple independent MCPG deployments sharing one `cluster_backend` MUST namespace per-deployment so peer caches don't pollute each other. |

### `CredentialsConfig`

Defaults are safe for single-node deploys; multi-instance deploys with per-caller dynamic credentials (e.g. Vault dynamic DB) MUST configure `cluster.enabled: true` to avoid cache divergence.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cluster` | [`CredentialsClusterConfig`](#credentialsclusterconfig) | (see type) | Optional cluster pub/sub wrapper. When `enabled: true` AND a `cluster_backend` is bound, the gateway wraps the L1 cache with `ClusteredCredentialCache` so every peer instance sees Issued / Revoked events. Drops to local-only behaviour with a warning when `enabled: true` but no coordinator is bound. |
| `key_attributes` | array&lt;string&gt; |  | Identity attribute (token-claim) names folded into the credential-cache key so callers differing only by these claims (commonly the tenant claim) get separate cached credentials. Empty (default) excludes attributes from the key — set this to your tenant claim name(s) when a `credential_issuer` derives its principal from an attribute claim, otherwise those callers share one credential. In a clustered cache every peer MUST set the same `key_attributes` (the published event hash is computed with it) — divergence silently produces per-node cache misses, the same all-peers-agree constraint that already governs the hash algorithm. |
| `max_cache_ttl_ms` | integer | `3600000` | Operator-side cap on per-entry TTL. Even if a plugin returns a 24-hour TTL, the cache evicts at this cap to limit blast radius from leaked / compromised credentials. Default 3600 (1 hour). |
| `max_entries` | integer | `10000` | Maximum number of `(identity, plugin, target)` entries kept in the L1 cache. LRU eviction past this. Default 10000 — at ~500 bytes per entry that's ~5MB worst case. |

### `DebugCommandToolConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `args` | array&lt;string&gt; | (see type) |  |
| `command` | string | `"printf"` |  |
| `max_output_bytes` | integer | `4096` |  |
| `timeout_ms` | integer | `2000` |  |

### `DebugConfig`

Top-level `debug:` block — diagnostic tools surface only. The master switch lives at `feature_flags.debug_tools_enabled`. When that flag is `false`, every field below is ignored AND the `mcpg.debug.*` tools are stripped from the capability registry regardless of `tools.exposure`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `tools` | [`DebugToolsConfig`](#debugtoolsconfig) | (see type) | Operator-defined diagnostic tools surfaced as MCP tools when `feature_flags.debug_tools_enabled: true`. See [`DebugToolsConfig`] for the surface. |

### `DebugNetworkToolConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `expected_status_codes` | array&lt;integer&gt; | (see type) |  |
| `headers` | map&lt;string, string&gt; | `{}` |  |
| `max_response_bytes` | integer | `4096` |  |
| `require_json_response` | boolean | `false` |  |
| `timeout_ms` | integer | `2000` |  |
| `url` | string | `"http://127.0.0.1:8787/health"` |  |

### `DebugToolBackendsConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `command_probe_profile` | string | `"default_command_probe"` |  |
| `network_json_call_profile` | string | `"default_network_probe"` |  |
| `network_probe_profile` | string | `"default_network_probe"` |  |

### `DebugToolExposureConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `command_probe` | boolean | `true` |  |
| `network_json_call` | boolean | `false` |  |
| `network_probe` | boolean | `true` |  |
| `operational_overview_prompt` | boolean | `true` |  |
| `runtime_overview_resource` | boolean | `true` |  |

### `DebugToolsConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bindings` | [`DebugToolBackendsConfig`](#debugtoolbackendsconfig) | (see type) |  |
| `command_profiles` | map&lt;string, [`DebugCommandToolConfig`](#debugcommandtoolconfig)&gt; | `{}` |  |
| `exposure` | [`DebugToolExposureConfig`](#debugtoolexposureconfig) | (see type) |  |
| `network_profiles` | map&lt;string, [`DebugNetworkToolConfig`](#debugnetworktoolconfig)&gt; | `{}` |  |

### `DeliveryConfig`

`delivery:` config — delivery bus (the internal pub/sub that fans server-initiated messages out to the SSE stream owning each session) + per-capability `bus:` override. When `bus` is unset, the gateway inherits the cluster's `pub_sub()` primitive.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bus` | [`BusOverrideConfig`](#busoverrideconfig) (optional) |  |  |

### `DisclosureLevel`

**Allowed values:**

- `summary`
- `redacted`
- `full`

### `EnumSource`

A dynamic-enum source: a sibling tool whose result supplies options.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `args` | map&lt;string, string&gt; (optional) |  |  |
| `label_field` | string |  |  |
| `tool` | string |  |  |
| `value_field` | string |  |  |

### `FeatureFlagsConfig`

Operator-controlled strictness / compat flags.

Every field defaults to the safe / standards-compliant value; flipping a flag is an explicit acknowledgement that the operator is taking on the risk the default protects against.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_header_passthrough` | boolean | `false` | Forward credential-shaped inbound HTTP headers (`Authorization`, `Cookie`, `X-API-Key`, …) through to outbound bindings. The gateway strips these by default to avoid leaking client tokens to upstreams. Flip to `true` only for deployments that intentionally proxy bearer tokens to the binding (e.g., a pure-router deployment in a trusted network). |
| `debug_tools_enabled` | boolean | `false` | Master switch for the operator-defined diagnostic tools (`mcpg.command.*` / `mcpg.network.*`). When `false`, every field under the top-level `debug:` block is ignored AND the debug tools are stripped from the capability registry regardless of `debug.tools.exposure`. Production deploys keep this off; flip on for CI / dev only. |
| `sep2260_panic_on_orphan` | boolean | `false` | Upgrade SEP-2260 violations (server-initiated request emitted without an originating client request id) from a warning + metric counter to a process panic. Useful in CI / dev where the violation indicates a bug; should stay `false` in production so a single misrouted code path does not take the gateway down. |

### `FederationCacheConfig`

Capability-cache behaviour.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `capability_ttl_secs` | integer | `300` | Re-list the upstream's capabilities every N seconds even without a `list_changed` notification. |

### `FederationConfig`

One federated upstream MCP server.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cache` | [`FederationCacheConfig`](#federationcacheconfig) | (see type) | Capability-cache behaviour (TTL refresh). |
| `filter` | [`FilterConfig`](#filterconfig) | (see type) | Allow/deny filtering of imported tool names. |
| `governance` | [`BackendGovernanceConfig`](#backendgovernanceconfig) | (see type) | Governance inherited by every capability imported from this upstream — identical block to a native binding's, so the gate chain treats a federated call exactly like a native one. |
| `import` | [`ImportConfig`](#importconfig) | (see type) | Which capability surfaces to import. |
| `name` | string |  | Source id. Also the default capability-prefix namespace and the `federated_from` label on synthetic capabilities. |
| `naming` | [`NamingConfig`](#namingconfig) | `{}` | Prefixes applied to imported capability names / URIs. |
| `response` | [`ResponseConfig`](#responseconfig) | (see type) | Per-call response limits enforced gateway-side. |
| `retry` | [`RetryConfig`](#retryconfig) (optional) |  | Per-call retry policy for upstream dispatch. |
| `session` | [`SessionConfig`](#sessionconfig) | (see type) | Upstream-session behaviour. |
| `synthesize` | [`SynthesizeConfig`](#synthesizeconfig) | (see type) | Change-notification synthesis for upstreams that cannot push. |
| `upstream` | [`UpstreamConfig`](#upstreamconfig) |  | Upstream connection (url, transport, auth, safety). |

### `FilterConfig`

Allow/deny filtering of imported tool names (glob `*` suffix).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `exclude_tools` | array&lt;string&gt; | `[]` |  |
| `include_tools` | array&lt;string&gt; | (see type) |  |

### `GatewayAppConfig`

One gateway-authored templated app. Minted as `ui://mcpg/<id>`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_credential_values` | boolean | `false` | Gate that must be set for `cred://` to appear in `public_values`. |
| `app_tools` | array&lt;[`AppProvidedTool`](#appprovidedtool)&gt; |  | Read-only App-Provided Tools the app exposes to the agent. |
| `columns` | array&lt;[`AppColumn`](#appcolumn)&gt; (optional) |  | Explicit columns. `None` ⇒ derived from `data_tool.outputSchema`. |
| `csp` | [`AppCspDecl`](#appcspdecl) (optional) |  | Per-app author CSP declaration (still intersected by the egress `csp_policy` — declaring an axis never widens it). |
| `data_args` | map&lt;string, string&gt; (optional) |  | Static argument template passed to `data_tool` on the initial load (named string args; richer typing is a later phase). |
| `data_tool` | string (optional) |  | Data-source tool. Required for `form`; optional for static kinds (e.g. a `signature_pad`). Its `outputSchema`/`inputSchema` seeds the columns/fields when those are omitted. |
| `description` | string (optional) |  |  |
| `fields` | array&lt;[`AppField`](#appfield)&gt; (optional) |  | Explicit detail/form fields. `None` ⇒ derived from the schema. |
| `id` | string |  | Unique id; becomes the `ui://mcpg/<id>` authority path segment. `[a-z0-9]` then `[a-z0-9-]*`. |
| `id_field` | string (optional) |  | JSON-path to a row's stable id. Default `$.id`. |
| `kind` | [`GatewayAppKind`](#gatewayappkind) |  | Which shipped shell renders this app. |
| `map` | [`MapAppConfig`](#mapappconfig) (optional) |  | Map binding; present iff `kind == map`. |
| `page_size` | integer (optional) |  |  |
| `permissions` | array&lt;[`AppsPermission`](#appspermission)&gt; |  | iframe permissions the app requests (clamped by `allowed_permissions`). |
| `prefers_border` | boolean (optional) |  |  |
| `primary_action` | string (optional) |  | `row_actions[].id` fired on a row click / primary interaction. |
| `public_values` | map&lt;string, string&gt; |  | Opt-in non-secret config values injected into the data island. `cred://` here requires `allow_credential_values`. |
| `row_actions` | array&lt;[`AppRowAction`](#approwaction)&gt; |  | Per-row actions, each re-entering the gateway via `tools/call`. |
| `rows_path` | string (optional) |  | JSON-path to the row array inside the tool's structuredContent. Default introspected from the output schema. |
| `theme` | [`AppTheme`](#apptheme) (optional) |  |  |
| `title` | string |  | Human title shown in the resource descriptor. |
| `ui_schema` | [`UiSchema`](#uischema) (optional) |  | Widget/layout overlay (highest precedence over columns/fields). |

### `GatewayAppKind`

The shipped shells a templated app can select.

**Variants:**

- **`table`**

- **`key_value`** — Dense label/value spec sheet (a compact `detail`).

- **`code_viewer`** — Read-only syntax-highlight-free code/text viewer.

- **`chart`** — Numeric series chart (bar/line) over the result columns.

- **`signature_pad`** — Canvas to draw a signature/sketch; submits a PNG data URL.

- **`audio_recorder`** — Record audio (microphone) and submit the clip.

- **`camera_capture`** — Capture a still photo (camera) and submit it.

- **`media_player`** — Play an audio/video asset referenced by the result.

- **`image_gallery`** — Browse a set of images from the result.

- **`file_upload`** — Select/drag files and submit their contents.

### `GatewayConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `admin` | [`AdminConfig`](#adminconfig) | (see type) | Admin HTTP surface — `/admin/*` routes, mutual-TLS or bearer-token auth, the operator-facing `disclosure_level` gate that controls how much detail diagnostic endpoints expose. Defaults to disabled; production deploys mount it behind an internal-only listener. |
| `config_overlay` | array&lt;string&gt; |  | Ordered list of `config_provider` URIs to snapshot at gateway boot + deep-merge into an overlay value (spec §9.16). Lives here (rather than per-plugin) because it's gateway-process bootstrap config. Each URI must use a scheme bound by a registered config-provider plugin. |
| `config_watch` | [`ConfigWatchConfig`](#configwatchconfig) | (see type) | File-watch config-reload trigger (third trigger, alongside SIGHUP and `POST /admin/v1/config:reload`). Background task polls the `MCPG_CONFIG` source set on disk and triggers a hot-reload when contents change. Default disabled. See [`ConfigWatchConfig`] for tuning. Useful for bare-metal systemd deployments and K8s deployments without the MCPG operator (which already does cluster-level config propagation via `mcpg.dev/config-hash` annotation forcing rolling restart). |
| `control_plane` | [`ControlPlaneAttachConfig`](#controlplaneattachconfig) (optional) |  | Optional Control Plane attachment. When set AND the `cp-attached` Cargo feature is built in, the gateway registers with the CP at boot, opens an agent Channel, and ships per-tool-call samples for centralized observability. When the feature isn't built in, this block is silently ignored. |
| `inspector` | [`InspectorSidecarConfig`](#inspectorsidecarconfig) | (see type) | Supervised inspector sidecar (`mcpg --inspector`, or `enabled: true` here): the gateway spawns a sibling `mcpg-inspector serve` pre-wired against this gateway with a per-boot loopback credential. |
| `plugin_registry` | [`PluginRegistryConfig`](#pluginregistryconfig) | (see type) | OCI plugin-registry configuration. Lives here (rather than per-plugin) because it's gateway-process tuning — where to fetch plugin artifacts from — not per-plugin config. Per-plugin source auth/tls live inline in each plugin entry's `source.{auth,tls}:`. Only consulted when at least one plugin entry uses `source: { oci: ... }`. |
| `server` | [`ServerConfig`](#serverconfig) | (see type) | Listener configuration — bind address, transport mode (HTTP / stdio / SSE), TLS, allowed origins, and per-request timeouts. The block is mandatory in practice (the listener won't bind without `bind_address`) but defaults to a localhost dev-mode shape so out-of-the-box `mcpg` boots without any config. |

### `GovernanceConfig`

Tool-call governance lifecycle: who → allowed? → extra gate → recorded → within limits.

Every child defaults to its own zero-value: an empty `governance:` block is valid YAML and produces a fully-default configuration (anonymous identity, untrusted-by-default policy, no human-gate signing key, audit channel disabled, no quotas declared).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `access` | [`AccessConfig`](#accessconfig) | (see type) | Inbound identity establishment — JWKS-backed JWT verification or OIDC discovery + introspection. When unset the gateway accepts unauthenticated callers and stamps every request with `identity_kind: anonymous` so the policy gate can deny them. `jwks` and `oidc_oauth` are mutually exclusive. |
| `approvals` | [`ApprovalsConfig`](#approvalsconfig) | (see type) | Tool-gate human approval — signing key + callback base url + grace window. When unset, the runtime defaults to a random per-process signing key + empty callback base url (suitable for tests + dev only — production deploys must supply a stable signing key). |
| `audit` | [`AuditConfig`](#auditconfig) | (see type) | Compliance-grade event sink fan-out (spec §9.12). Lives under `governance:` (rather than `observability:`) so the audit-as-evidence-of-governance story reads alongside access / policy / approvals. |
| `child_invoke` | [`ChildInvokeConfig`](#childinvokeconfig) | (see type) | Authorization for agentic child tool calls — the backend-to-backend `invoke_tool` path an LLM Generator drives when it emits `tool_calls`. Off by default. |
| `policy` | [`PolicyConfig`](#policyconfig) | (see type) | Tool-access policy — default minimum trust level + per-tool override rules. Operators can also point at a Cedar / Casbin / OPA bundle plugin under `plugins[]` to delegate the actual decision; this block stays useful for the gateway-internal default-trust gate every tool flows through before any plugin policy fires. |
| `quotas` | [`QuotasConfig`](#quotasconfig) | (see type) | Registry of named rate-limit / budget / concurrency policies. Bindings opt into specific policies by id via their per-binding `quotas:` block. Storage backend is a `kind:` slot under `governance.quotas.store:`. |

### `HealthCheckConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `degraded_latency_threshold_ms` | integer | `1000` |  |
| `enabled` | boolean | `true` |  |
| `interval_ms` | integer | `30` |  |
| `timeout_ms` | integer | `2000` |  |
| `unhealthy_threshold` | integer | `3` |  |

### `HealthProbeConfig`

Periodic health-probe configuration. The probe is the only writer of `PluginState::Degraded`; without it plugins stay perpetually `Active` regardless of whether they're actually responding.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Probe plugins periodically. Default: `true`. Set `false` to turn off the prober entirely (the `Degraded` state then never flips — test-only or historical deployments). |
| `failure_threshold` | integer | `3` | Consecutive failures before flipping `Active` → `Degraded`. Default: 3. |
| `interval_ms` | integer | `30000` | Milliseconds between probe cycles. Default: 30000 (30s). |
| `probe_timeout_ms` | integer | `5000` | Per-probe deadline in milliseconds. A plugin whose FFI call exceeds this is counted as a failure. Default: 5000 (5s). |

### `IdempotencyConfig`

`idempotency:` config — opt-in dedupe for `tools/call` and `tasks/create`. When `enabled: false` (the default), the gateway omits the `dev.mcpg/idempotency` extension from its `initialize` capability advertisement and silently ignores any `_meta["dev.mcpg/idempotency-key"]` the caller sets.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `conflict_policy` | [`ConflictPolicy`](#conflictpolicy) | `"reject"` | Conflict policy — only `reject` for v1. |
| `default_ttl_ms` | integer | `86400000` | Default TTL applied to any reservation. Default 86_400_000 (24 hours) — matches Stripe's window. |
| `enabled` | boolean | `false` | Master switch. Default `false` (opt-in, like `governance.quotas` was before it became cargo-feature-gated). |
| `max_ttl_ms` | integer | `604800000` | Hard upper bound on per-record TTL. Default 604_800_000 (7 days). Future per-binding `idempotency.ttl_ms` overrides saturate at this cap. |
| `replay_revalidation` | boolean | `false` | When true, a completed-replay hit re-runs the full pre-dispatch authz stack (external policy chain + tool_gate plugins) before serving the cached envelope, so authorization revoked since the original call is honored within the record TTL. Default false: only the built-in trust-floor + CEL allow_if is re-checked on replay (the cheap, side-effect-free layer). |
| `scope` | [`IdempotencyScopeKind`](#idempotencyscopekind) | `"per_identity"` | Scope strategy — `per_identity` (default), `per_session`, or `per_tenant`. |
| `store` | [`StoreOverrideConfig`](#storeoverrideconfig) (optional) |  | Per-capability `store:` override. Same shape as `tasks.store` / `sessions.store`. When unset, the idempotency KV inherits from the cluster coordinator's `key_value_store()` primitive. |
| `supported_methods` | array&lt;string&gt; | (see type) | JSON-RPC methods this extension applies to. Default `["tools/call", "tasks/create"]` — read-only methods (`resources/read`, `prompts/get`, `completion/complete`) are intentionally excluded as they're idempotent by nature. |

### `IdempotencyScopeKind`

Default scope strategy for idempotency records. Operator can widen to `per_tenant` (service-account dedupe) or narrow to `per_session` (ephemeral test harnesses).

Note: `global` is intentionally NOT a variant — cross-tenant replay is a known anti-pattern, so we don't expose the footgun.

**Variants:**

- **`per_session`** — All requests sharing one MCP session share the namespace. Useful for ephemeral test harnesses; resets on every re-initialize.

- **`per_identity`** — All requests sharing one resolved identity (OIDC subject + auth provider) share the namespace. The default — matches Stripe / Square idempotency semantics.

- **`per_tenant`** — All requests sharing one tenant id share the namespace. Useful for service-to-service workloads where multiple service accounts retry the same operation.

### `ImportConfig`

Which capability surfaces to import.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `prompts` | boolean | `false` |  |
| `resource_templates` | boolean | `false` |  |
| `resources` | boolean | `false` |  |
| `tools` | boolean | `true` |  |

### `InspectorSidecarConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bind` | string (optional) |  | host:port of the inspector's web UI + API (single origin). Defaults to the inspector's own `127.0.0.1:7846`. |
| `enabled` | boolean | `false` | Supervise an `mcpg-inspector` sidecar. `--inspector` flips this on for a single run. |

### `JwksConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_missing_audience` | boolean | `false` | Dev escape-hatch: allow tokens without audience binding. Production MUST set an audience. |
| `audience` | string (optional) |  |  |
| `header_name` | string | `"authorization"` |  |
| `header_prefix` | string | `"Bearer "` |  |
| `issuer` | string (optional) |  |  |
| `keys_json` | string (optional) |  |  |
| `url` | string | `""` |  |

### `KindRef`

Discriminator + config payload at every consumer slot. Operators write `{ kind: <value>, ...config }` in YAML; the gateway parses it as this type and resolves via [`resolve_kind`].

The `config:` field is a free-form JSON object passed to the resolved handle (built-in or plugin). The slot's resolver validates `kind`; the implementation validates `config`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `config` | any |  | Inline config forwarded to the resolved handle. Empty by default. |
| `kind` | string |  | Discriminator. One of: built-in keyword, full plugin id, short alias, or `cluster`. |

### `LicenseConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `non_production_use` | boolean | `false` | Declares this deployment non-production. Entitlement-gated plugins then load without a token under their license's free non-production grant (development, testing, evaluation, staging), with a boot warning naming them. Production use still requires an entitling token. |
| `pubkey_pem` | string (optional) |  | Trusted license-signing public key (SPKI PEM, Ed25519) — the verification anchor for the configured token (`mcpg-license keygen --public-out`). Required when a token is configured; an unverifiable token refuses boot rather than silently degrading to community. |
| `token` | string (optional) |  | The signed license JWT, inline (commonly `${env.MCPG_LICENSE}`). Exactly one of `token` / `token_file` may be set. |
| `token_file` | string (optional) |  | Path to a file holding the signed license JWT (e.g. a mounted secret). Exactly one of `token` / `token_file` may be set. |

### `LogsConfig`

`observability.logs:` — the logs signal.

Gateway internals (every `tracing::info!()` / `warn!()` / `error!()` call) AND plugin-emitted log events both flow through the configured sink list. Default sinks ship one `stderr` JSON emitter — production deployments add `file`, `otlp`, or plugin sinks (Loki, Splunk, …) by appending entries to `sinks:`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master enable for the logs signal. When `false`, no log events are emitted regardless of `sinks:` content. |
| `level` | string | `"info"` | Signal-level severity floor (`trace` / `debug` / `info` / `warn` / `error`). Per-sink `level:` can raise it further but can't lower it below this floor. Default: `info`. |
| `sinks` | array&lt;[`SinkConfig`](#sinkconfig)&gt; | (see type) | Sink fan-out. Each entry's `kind:` resolves to a built-in factory (`stderr` / `stdout` / `file` / `otlp`) or plugin id. Default: one `stderr` sink with JSON format. |

### `MapAppConfig`

Map binding for `kind == map`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `geojson_path` | string (optional) |  | JSON-path to a GeoJSON FeatureCollection (alternative to lat/lng). |
| `label_field` | string (optional) |  |  |
| `lat_field` | string (optional) |  |  |
| `lng_field` | string (optional) |  |  |
| `mode` | [`MapRenderMode`](#maprendermode) | `"plot"` | Render mode. `plot` (default) needs no network; `raster_tiles` fetches from `tile_url` and requires a CSP allowance. |
| `popup_field` | string (optional) |  |  |
| `select_action` | string (optional) |  | Tool a region-draw selection invokes (geometry passed as args). |
| `tile_url` | string (optional) |  | Raster tile template URL (raster mode only). |

### `MapRenderMode`

Map rendering mode.

**Variants:**

- **`plot`** — Coordinate plot on a canvas — zero network, no CSP delta.

- **`raster_tiles`** — Raster basemap tiles — needs `tile_url` + a CSP allowance.

### `McpCapabilitiesConfig`

`mcp.capabilities:` — the MCP protocol-advertised surface.

Matches the protocol's `initialize` handshake's `capabilities` vocabulary: tools / prompts / resources / resource_templates, plus the gateway-side feature configs that govern protocol behaviour (tasks, elicitation, sampling, roots).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `elicitation` | [`McpElicitationConfig`](#mcpelicitationconfig) | (see type) | MCP elicitation — server-initiated prompt requests the gateway emits during pipeline execution. |
| `prompts` | array&lt;[`BackendConfig`](#backendconfig)&gt; | `[]` | Operator-declared prompts — the bindings that surface via `prompts/list` and `prompts/get`. Carry `prompt_arguments`. |
| `resource_templates` | array&lt;[`BackendConfig`](#backendconfig)&gt; | `[]` | Operator-declared resource templates — the bindings that surface via `resources/templates/list` and match `resources/read` URIs by template. Carry `uri_template` instead of `uri`. |
| `resources` | array&lt;[`BackendConfig`](#backendconfig)&gt; | `[]` | Operator-declared resources — the bindings that surface via `resources/list` and `resources/read`. Carry `uri`, `mime_type`, `mcp_app_url`, watch config. |
| `roots` | [`McpRootsConfig`](#mcprootsconfig) | (see type) | MCP roots-list — gateway requests roots from the client (e.g. for resource scoping). |
| `sampling` | [`McpSamplingConfig`](#mcpsamplingconfig) | (see type) | MCP sampling — server-initiated LLM completion requests forwarded back to the client. |
| `tasks` | [`TasksConfig`](#tasksconfig) | (see type) | MCP Tasks — task-augmented tool-call semantics. Carries the task store override, TTL/reaper tuning, and the task-supported tools list. |
| `tools` | array&lt;[`BackendConfig`](#backendconfig)&gt; | `[]` | Operator-declared tools — the bindings that surface via `tools/list` and `tools/call`. Each entry has its own implementation `backend:` (HTTP / SQL / NATS / LLM / pipeline / …) plus tool-specific MCP fields (`annotations`, `task_support`). |

### `McpConfig`

Top-level `mcp:` block — the MCP protocol surface.

Two children that mirror MCP's own vocabulary: - `capabilities:` — what the server advertises in the `initialize` handshake (tools, prompts, resources, resource_templates, tasks, elicitation, sampling, roots). - `configurations:` — runtime-emergent state handling (sessions, pipelines, subscriptions, delivery, cancellation). Operator only tunes persistence + constraints; the items themselves are created by clients at runtime.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `capabilities` | [`McpCapabilitiesConfig`](#mcpcapabilitiesconfig) | (see type) | What this MCP server advertises in the `initialize` handshake. Mirrors the protocol spec's `capabilities` vocabulary one-to-one. |
| `configurations` | [`McpConfigurationsConfig`](#mcpconfigurationsconfig) | (see type) | Runtime-emergent state handling. Operator only tunes persistence + constraints; the items themselves are created by clients at runtime. |
| `federations` | array&lt;[`FederationConfig`](#federationconfig)&gt; | `[]` | Upstream MCP servers federated through this gateway. Each entry is a *capability source* (1:N): MCPG connects to the upstream, imports its capabilities, and re-serves them under a prefix. Default empty — existing configs are unaffected. |
| `registries` | array&lt;[`McpRegistryConfig`](#mcpregistryconfig)&gt; | `[]` | MCP registries whose listed servers MCPG auto-federates: a background syncer crawls each registry's `/v0.1` API and materializes one federation per usable server, kept in sync as the registry changes. Default empty. |
| `registry` | [`ServedRegistryConfig`](#servedregistryconfig) | (see type) | The registry MCPG *serves* (contrast `registries`, the registries MCPG *consumes*): a v0.1 MCP-Registry view of this gateway — one entry describing the governed catalog — so registry-driven clients (e.g. Copilot's allowed-registry policy) can discover MCPG as their approved server. Off by default. |

### `McpConfigurationsConfig`

`mcp.configurations:` — runtime-emergent state handling.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `apps` | [`AppsConfig`](#appsconfig) | (see type) | `io.modelcontextprotocol/ui` (SEP-1865 MCP Apps) extension config. Off by default; `enabled: true` lights up the capability advertisement (downstream + upstream) and the tighten-only CSP/permission egress policy. |
| `cancellation` | [`CancellationConfig`](#cancellationconfig) | (see type) |  |
| `delivery` | [`DeliveryConfig`](#deliveryconfig) | `{}` |  |
| `idempotency` | [`IdempotencyConfig`](#idempotencyconfig) | (see type) | `dev.mcpg/idempotency` extension config. Off by default; flipping `enabled: true` lights up the SEP-2133 capability advertisement and the dispatcher dedupe path. |
| `pipelines` | [`PipelinesConfig`](#pipelinesconfig) | `{}` |  |
| `request_state` | [`RequestStateConfig`](#requeststateconfig) | (see type) | MRTR `requestState` codec configuration (2026-07-28 modern wire). Inert when no modern client connects; absent encryption_key the codec uses an ephemeral key at boot. |
| `sessions` | [`SessionsConfig`](#sessionsconfig) | (see type) |  |
| `subscriptions` | [`SubscriptionsConfig`](#subscriptionsconfig) | (see type) |  |

### `McpElicitationConfig`

`mcp.elicitation:` — gateway behavior for server-initiated elicitation prompts. Today carries only `timeout_ms`; future per-elicitation-type config can grow here.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `timeout_ms` | integer | `60000` | Maximum time the gateway waits for the client's response to an elicitation prompt before giving up. Default 60 000. |

### `McpRegistryConfig`

One MCP registry to auto-federate.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`RegistryAuthConfig`](#registryauthconfig) | (see type) | How MCPG authenticates to the registry (consumer side). |
| `defaults` | [`RegistryDefaultsConfig`](#registrydefaultsconfig) | (see type) | Applied to every synthesized federation. |
| `filter` | [`RegistryFilterConfig`](#registryfilterconfig) | (see type) | Which registry servers are eligible for federation. |
| `name` | string |  | Registry id. Prefixes every synthesized federation name (`<registry>--<server>`), so it must be stable and unique. Lowercase alphanumeric + `-`. |
| `on_deprecated` | [`OnDeprecated`](#ondeprecated) | `"serve_and_warn"` | What happens to servers the registry marks `deprecated`. (`deleted` servers are always removed.) |
| `registry_safety` | [`RegistrySafetyConfig`](#registrysafetyconfig) | (see type) | Network posture for the REGISTRY endpoint itself. Distinct from the per-server `defaults.upstream_safety`: a private registry URL is normal for enterprises, but stays an explicit opt-in. |
| `servers` | map&lt;string, [`RegistryServerOverride`](#registryserveroverride)&gt; | `{}` | Per-server overrides, keyed by the server's registry name (e.g. `com.acme/crm`). |
| `sync` | [`RegistrySyncConfig`](#registrysyncconfig) | (see type) | Sync cadence + size bounds. |
| `url` | string |  | Registry base URL; the syncer appends the standard API paths (`/v0.1/servers`, …). |

### `McpRootsConfig`

`mcp.roots:` — gateway behavior for server-initiated roots-list requests forwarded to the client.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `timeout_ms` | integer | `30000` | Maximum time the gateway waits for the client's roots-list response. Default 30 000. |

### `McpSamplingConfig`

`mcp.sampling:` — gateway behavior for server-initiated sampling (LLM completion) requests forwarded to the client.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `timeout_ms` | integer | `60000` | Maximum time the gateway waits for the client's sampling response. Default 60 000. |

### `MetricsConfig`

`observability.metrics:` — the metrics signal.

Gateway internals (every `metrics::counter!()` / `gauge!()` / `histogram!()`) flow through the configured sink list. The canonical Prometheus exporter is a plugin: operators wire `kind: dev.mcpg.observability.prometheus`. The `sinks: []` list otherwise carries plugin ids (`dev.acme.observability.datadog`, etc.) — there are no built-in factory kinds for metrics.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master enable for the metrics signal. When `false`, no metric recorders are installed. |
| `sinks` | array&lt;[`SinkConfig`](#sinkconfig)&gt; | (see type) | Sink fan-out. Every entry's `kind:` is a plugin id (there is no `kind: prometheus` / `kind: otlp` shorthand). Default: one `dev.mcpg.observability.prometheus` sink at `/metrics`. |

### `NamingConfig`

Prefixes applied to imported capability names / URIs.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `prompt_prefix` | string (optional) |  | Prepended to every imported prompt name. |
| `resource_uri_prefix` | string (optional) |  | Prepended to every imported resource URI (e.g. `"mcp://notion/"`). |
| `tool_prefix` | string (optional) |  | Prepended to every imported tool name (e.g. `"notion."`). |

### `NotificationFilterConfig`

Scoping filter for resource change notifications. Determines which subscribers receive `notifications/resources/updated` when the watch engine detects a change.

**Variants:**

- **`(unnamed variant)`** — Fan-out to all subscribers (default, no filter).

- **`(unnamed variant)`** — Only notify subscribers whose `principal_id` matches the event's user context.

- **`(unnamed variant)`** — Only notify the originating session.

- **`(unnamed variant)`** — CEL expression evaluated per subscriber. Variables: `subscriber.principal_id`, `subscriber.trust_level`, `subscriber.roles`, `subscriber.groups`, `subscriber.scopes`, `subscriber.attributes`, `event.uri`.
  - `expression`: string
  - `scope`: string

### `OAuthResourceMetadataConfig`

Configuration for the OAuth Protected Resource Metadata endpoint (RFC 9728).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_loopback_resource` | boolean | `false` | Local-development escape hatch: permit a loopback `resource` (`localhost` / `127.0.0.1` / `[::1]`). A wildcard host (`0.0.0.0` / `[::]`) is NEVER a valid resource identifier and is refused even with this set. Production deployments leave this `false` and configure the canonical public URL. |
| `authorization_servers` | array&lt;string&gt; | `[]` | Authorization server URLs. If empty, derived from OIDC provider issuers. |
| `bearer_methods_supported` | array&lt;string&gt; | (see type) | Bearer token presentation methods. Defaults to `["header"]`. |
| `resource` | string |  | The protected resource's canonical resource identifier (RFC 8707 `resource` / RFC 9728 `resource`). MUST be the real external, absolute URL clients reach the gateway at — the same value the authorization server binds tokens to as `aud`. A wildcard (`0.0.0.0`), bare loopback (`localhost`/`127.0.0.1`/`[::1]`), or derived `bind_address` value is refused at boot: it would publish a `resource` that does not match the audience the tokens carry, so audience-bound validation silently fails. Set the canonical public URL explicitly, or opt into the loopback form for local development with `allow_loopback_resource: true`. |
| `scopes_supported` | array&lt;string&gt; | `[]` | Scopes supported by this resource. |

### `ObservabilityConfig`

Top-level `observability:` block — the OpenTelemetry signal triad (logs / metrics / traces) plus audit fan-out.

Each signal carries a `sinks: [...]` list of [`SinkConfig`] entries. Each entry's `kind:` field dispatches to either a built-in sink factory (`stderr` / `stdout` / `file` / `otlp` / `prometheus`) or a plugin id resolved against the gateway's plugin registry at boot.

**Master switch.** `enabled: false` (default `true`) silences every child regardless of their own `enabled:` flags — useful for embedded use cases where the host process owns observability or for minimal-footprint test runs. Each child also has its own `enabled:` for finer-grained control. The accessor helpers below (`is_logs_on()`, `is_metrics_on()`, `is_traces_on()`, `is_audit_on()`) implement the AND-fold so call sites can't forget either flag.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master kill switch. When `false`, every child is treated as disabled regardless of its own `enabled:` field — no logs emitted, no metrics endpoint registered, no traces pipeline started, no audit fan-out wired. Default `true`. |
| `logs` | [`LogsConfig`](#logsconfig) | (see type) | Logs signal — gateway internals + plugin-emitted log events fanned to the configured sink list. |
| `metrics` | [`MetricsConfig`](#metricsconfig) | (see type) | Metrics signal — gateway internals + plugin-emitted metric events fanned to the configured sink list. |
| `plugin_call_sampling_rate` | number (optional) |  | Per-call span sampling rate for native-plugin host-side spans. Range `[0.0, 1.0]`; `None` inherits the global subscriber sampler (no extra dampening). |
| `plugin_health_probe` | [`HealthProbeConfig`](#healthprobeconfig) | (see type) | Plugin health probe. Lives under `observability:` because the probe is observability-shaped (it watches plugin liveness and writes `PluginState::Degraded` for monitoring consumers). |
| `traces` | [`TracesConfig`](#tracesconfig) | (see type) | Traces signal — span lifecycle events fanned to the configured sink list. |

### `OidcOAuthConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `providers` | array&lt;[`OidcProviderConfig`](#oidcproviderconfig)&gt; |  | One or more identity providers. At least one is required. |
| `token_source` | [`TokenSourceConfig`](#tokensourceconfig) | (see type) | How to extract the bearer token from the request. |

### `OidcProviderConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_any_audience` | boolean | `false` | Explicit opt-in to SKIP audience (`aud`) validation. When false (the default) an empty `audiences` is a hard config error at boot — otherwise a mistyped `audiences` key would silently disable audience binding and accept tokens minted for any gateway. Production MUST leave this false and set `audiences`; only the rare provider that genuinely issues no `aud` claim should opt in. |
| `allow_private_issuer` | boolean | `false` | Dev escape hatch: permit private/loopback ranges in OIDC URLs. Production MUST leave this false. |
| `allowed_issuer_hosts` | array&lt;string&gt; | `[]` | Optional hostname allowlist for OIDC discovery and JWKS fetches. Empty means only the private-range blocklist applies. |
| `audiences` | array&lt;string&gt; | `[]` |  |
| `claim_mappings` | [`ClaimMappingConfig`](#claimmappingconfig) | (see type) |  |
| `clock_skew_secs` | integer | `60` |  |
| `discovery_uri` | string (optional) |  |  |
| `issuer` | string |  |  |
| `verification` | [`VerificationConfig`](#verificationconfig) |  |  |

### `OnDeprecated`

Policy for `deprecated` servers.

**Variants:**

- **`serve_and_warn`** — Keep federating; log + count the deprecation.

- **`exclude`** — Drop the federation (clients see `list_changed`).

### `PipelinesConfig`

`pipelines:` config — pipeline state store + per-capability `store:` override. When `store` is unset, the pipeline KV inherits from the cluster's `key_value_store()` primitive.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `store` | [`StoreOverrideConfig`](#storeoverrideconfig) (optional) |  |  |

### `PluginEntryConfig`

Configuration for a single plugin entry.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `class` | string | `"tool_gate"` | Plugin class — the snake_case `PluginClass` variant the plugin implements. Must match the `class:` field in the plugin's own `plugin.yaml` manifest. Determines which plugin chain / slot the plugin is registered into. Valid values: `tool_gate`, `transform`, `identity_provider`, `backend`, `watch_strategy`, `http_route`, `audit_sink`, `store`, `cache`, `telemetry_sink`, `log_sink`, `metrics_sink`, `secret_provider`, `config_provider`, `transport`, `policy_engine`, `cluster`, `catalog_provider`, `credential_issuer`, `approval_notifier`, `content_store`. |
| `config` | any |  | Plugin-specific configuration passed to the plugin instance. |
| `disabled` | boolean | `false` | When `true`, the plugin entry is parsed + validated but not loaded at boot. Useful for keeping a plugin's config in source control while temporarily turning it off without removing the entry. Default `false`. |
| `enforce` | boolean | `true` | When false, the plugin runs in shadow mode: evaluate and log, but override Deny/Challenge → Allow. Defaults to true (enforce). |
| `ffi_limits` | [`PluginFfiLimitsConfig`](#pluginffilimitsconfig) (optional) |  | Per-plugin FFI hardening overrides for native cdylib plugins. `None` = inherit the spec defaults (1s lifecycle / 5s control / 30s data / 256 KiB payload). Ignored for Wasm plugins (those use `limits.timeout_ms`). |
| `granted_capabilities` | array&lt;any&gt; |  | Per-plugin typed host capability grants. Each entry is one of [`mcpg_plugin_protocol::capability::Capability`]'s known variants. Two equivalent YAML shapes accepted: |
| `http_route` | [`PluginHttpRouteConfig`](#pluginhttprouteconfig) (optional) |  | `http_route`-specific operator tuning. Ignored for non-`http_route` plugins. Absent = all defaults (enabled, namespaced mount, spec's own body cap + identity policy). |
| `id` | string |  | Operator alias for this entry — unique within the gateway's `plugins[]` array. Used as the registry key, audit attribution, and per-plugin observability target. When `ref` is omitted, the alias doubles as the artifact's manifest id (the simple, single-instance case). When `ref` is set, the alias is a separate operator-chosen label (multi-instance pattern). |
| `inline_dispatch` | boolean | `false` | **Inline fast-slot dispatch.** When `true`, this plugin's hot-path slots are called **inline** — without the `spawn_blocking` ferry or per-call timeout: the typed/borrowed `*_fast` vtable path for Tier-1 slots (`tool_gate`, cutting dispatch ~33×), and the synchronous `execute` slot for `backend` plugins (which also lets the sync tool dispatch bridge resolve the call on its first poll and skip `block_in_place`). This is an explicit operator-trust decision: the plugin's slots MUST be fast, non-blocking, and bounded, because a hung/blocking slot now wedges a runtime worker with no backstop. Defaults to `false` (the safe, ferried path). Only enable for trusted, pure-compute / in-process first-party plugins. |
| `kind` | string | `"native"` | Plugin tier: `"native"` or `"wasm"`. |
| `limits` | [`PluginResourceLimitsConfig`](#pluginresourcelimitsconfig) (optional) |  | Resource limits for Wasm plugins (ignored for native). |
| `observability` | [`PluginObservabilityToggle`](#pluginobservabilitytoggle) (optional) |  | Per-plugin observability triad override. `inherit` (default), `replace`, or `tee` semantics for each signal independently. Absent = all signals inherit the global `observability.{logs,metrics,traces}` config. Routing is keyed by `module_path_prefix` from the plugin manifest — events from this plugin's crate get the override; events from gateway code about a plugin call stay on the global path. |
| `ref` | string (optional) |  | Manifest id (artifact identity) — reverse-DNS, e.g. `dev.mcpg.policy.cedar`. Optional; defaults to `id` when absent. |
| `signature` | [`SignatureConfig`](#signatureconfig) (optional) |  | Plugin signature checks. Consolidates the content hash, the per-entry-overridable verification policy, and the trusted Ed25519 keys this plugin's artifact must verify against (per-entry, no global trust pool). |
| `source` | [`PluginSourceConfig`](#pluginsourceconfig) | (see type) | Source path or reference for the plugin artifact. |

### `PluginFfiLimitsConfig`

Per-plugin FFI hardening overrides for native cdylib plugins.

Native plugin calls are wrapped by the host in `spawn_blocking` + `tokio::time::timeout` and bounded `RString` returns. Defaults are the spec-level constants in `mcpg_plugin_protocol::abi` (`FFI_{LIFECYCLE,CONTROL,DATA}_TIMEOUT_DEFAULT_MS`, `FFI_MAX_PAYLOAD_BYTES`). Operators set per-plugin overrides here to widen the budget for a known-slow plugin (e.g. a backend that proxies an upstream multi-second API) or to tighten the cap on a plugin that has a stricter SLO.

`None` on any field means "inherit the spec default".

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `control_timeout_ms` | integer (optional) |  | Control slot timeout override (ms). Applies to config-set, snapshot, version, register-profile, refresh, describe, list-peers, list-catalog, etc. Default: `FFI_CONTROL_TIMEOUT_DEFAULT_MS = 5_000`. |
| `data_timeout_ms` | integer (optional) |  | Data slot timeout override (ms). Applies to execute, evaluate, transform, dispatch, http_route, sink-emit, etc. Default: `FFI_DATA_TIMEOUT_DEFAULT_MS = 30_000`. |
| `lifecycle_timeout_ms` | integer (optional) |  | Lifecycle slot timeout override (ms). Applies to `make`, `manifest`, `shutdown`, `drop_instance`, health probes. Default: `FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS = 1_000`. |
| `max_payload_bytes` | integer (optional) |  | Max byte-length of any single `RString` returned by this plugin to the host. Overflow rejected with a slot-appropriate fallback + bumps `mcpg_plugin_payload_oversize_total`. Default: `FFI_MAX_PAYLOAD_BYTES = 262144` (256 KiB). |

### `PluginHttpRouteConfig`

Operator-side tuning for an `http_route` plugin entry. Every field is optional; the struct is omitted entirely for plugins that don't need any override.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_path_override` | boolean | `false` | When `true`, plugin routes mount at the top-level paths the plugin declared (override mode), instead of the namespaced `/plugins/{id}/{entity}/` mount (the `false` default). The gate is this operator-set flag alone; the gateway refuses two plugins that claim the same top-level path. Override-mode dispatch is not yet wired — this field is the gate the dispatcher will consult once that support lands. |
| `disabled` | boolean | `false` | When `true`, the plugin is not registered at all. Operators use this to swap out a gateway built-in (e.g. the built-in `dev.mcpg.builtin.http.status`) for a custom implementation without patching the gateway. The gateway logs a warning if a disabled plugin also appears elsewhere in the plugins list with conflicting settings — disable is authoritative. |
| `max_body_bytes` | integer (optional) |  | Per-entity override for `RouteSpec.max_body_bytes`. When set, the dispatcher uses this value instead of the plugin's declared cap — operator tightens (or relaxes) the plugin's spec without a plugin rebuild. `None` = use the plugin's declared value. |
| `requires_identity` | boolean (optional) |  | Per-entity override for `RouteSpec.requires_identity`. When set, the dispatcher enforces this instead of the plugin's declared value. Typical use: operator tightens an endpoint the plugin declared anonymous. `None` = use the plugin's declared value. |

### `PluginObservabilityToggle`

Per-plugin observability toggle. Each signal is independent — operators can disable metrics for one plugin while leaving its logs and traces flowing. Events still route through the GLOBAL `observability.{logs,metrics,traces}.sinks` list when admitted; this struct only controls *whether* a plugin's events make it that far + at what level.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `logs` | [`SignalToggle`](#signaltoggle) (optional) |  | Logs toggle. `None` = inherit globals. |
| `metrics` | [`SignalToggle`](#signaltoggle) (optional) |  | Metrics toggle. `None` = inherit globals. Note: metrics has no `level` (metrics-rs has no levels) — the field is accepted in YAML for forward compat but ignored today. |
| `traces` | [`SignalToggle`](#signaltoggle) (optional) |  | Traces toggle. `None` = inherit globals. |

### `PluginRegistryAuthConfig`

Registry authentication configuration. At most one source of credentials is consulted at push/pull time: an explicit `username`+`password` pair (or env-interpolated variants), otherwise the docker config.json at `docker_config_path`, otherwise anonymous.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `docker_config_path` | string (optional) |  | Path to a docker config.json for credential helpers. Defaults to `~/.docker/config.json` when unset. |
| `password` | string (optional) |  | Literal password / bearer token (or `$VAR` / `env:VAR`). Wrapped in [`mcpg_sensitive::Sensitive`] so a stray `?config` log renders this field as `***` instead of the literal token. |
| `username` | string (optional) |  | Literal username (or `$VAR` / `env:VAR` for env-var interpolation). |

### `PluginRegistryConfig`

Configuration for resolving plugin artifacts from OCI registries. Covers default registry, local cache, auth, TLS, and signature policy.

This section is only consulted when at least one plugin entry has `source.oci` set. For purely local deployments (every plugin loaded from `source.path`), all defaults apply and the registry subsystem does nothing.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`PluginRegistryAuthConfig`](#pluginregistryauthconfig) | (see type) | Registry authentication strategy. |
| `cache_dir` | string (optional) |  | Local cache directory for pulled OCI artefacts. Keyed by manifest digest so digest-pinned references skip the network on subsequent boots. When unset, defaults to `$XDG_CACHE_HOME/mcpg/plugins/oci` (or `/var/cache/mcpg/plugins/oci` for system deployments). |
| `default_registry` | string | `"ghcr.io/mcpg-dev/source-code/plugins"` | Default registry when an `oci:` reference has no registry prefix. Example: `ghcr.io/mcpg-dev/source-code/plugins`. |
| `default_signature_policy` | [`SignaturePolicy`](#signaturepolicy) | `"enforce"` | Default signature verification policy applied to every `plugins[*]` entry that doesn't carry its own `signature.policy:` override. Defaults to `Warn` (log but don't fail) for first-rollout safety; flip to `Enforce` once trusted keys are wired up across all entries. |
| `insecure_registries` | array&lt;string&gt; | `[]` | Hostnames (optionally `host:port`) that the OCI client should reach over plain HTTP instead of HTTPS. `localhost`, `127.0.0.1`, and `::1` are always implicit — operators only need to list this for other dev / air-gap registries. |
| `mirrors` | array&lt;[`PluginRegistryMirrorConfig`](#pluginregistrymirrorconfig)&gt; | `[]` | Mirror registries tried in order before the reference's source registry. Supports air-gap / pull-through caches. |
| `require_integrity_anchor` | boolean | `false` | When set, every `oci:`-sourced plugin entry must carry an integrity anchor the gateway can enforce independently of the transport: a digest-pinned reference (`…@sha256:<hex>`), a `signature.sha256` artifact-hash pin, or `signature.trusted_keys`. An entry pulled by bare tag with no anchor is refused at boot. Recommended whenever `mirrors` or `insecure_registries` are configured, since a tag pulled over a mirror / plain-HTTP hop is otherwise trusted on the registry's word alone. Defaults to `false` (every entry accepted; configured anchors are still enforced downstream). |
| `revocation_list_path` | string (optional) |  | Optional path to a JSON revocation list. When set, the gateway loads the file at startup, indexes the revoked artefact SHA-256s, and refuses to load any plugin whose hash matches an entry — even if its Ed25519 signature is valid. Format documented in [`mcpg_plugin_host::revocation::RevocationListFile`]. Absent means "no revocation list" — every signed plugin is allowed. |
| `tls` | [`PluginRegistryTlsConfig`](#pluginregistrytlsconfig) | (see type) | TLS knobs for registry connections. |
| `trusted_keys` | array&lt;[`TrustedKeyConfig`](#trustedkeyconfig)&gt; |  | Gateway-wide Ed25519 trust anchors. An entry whose `signature.trusted_keys` is empty verifies against these (plus the built-in official mcpg release key); an entry that carries its own keys verifies against exactly those, so third-party vendors never pool into the global anchor set. |

### `PluginRegistryMirrorConfig`

A mirror registry entry. Mirrors are consulted in order before the reference's source registry, matching the common pull-through cache / air-gap deployment pattern.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`PluginRegistryAuthConfig`](#pluginregistryauthconfig) (optional) |  | Optional auth override for this mirror. When absent, inherits the top-level `plugin_registry.auth`. |
| `url` | string |  | Mirror URL — a prefix that replaces the source registry in resolved pull URLs. Example: `harbor.internal.corp/mcpg-plugins`. |

### `PluginRegistryTlsConfig`

TLS configuration for registry HTTPS connections.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `ca_cert` | string (optional) |  | Path to a PEM bundle with extra trusted root CAs. Useful for internal registries with private CAs. |
| `insecure` | boolean | `false` | Skip all TLS certificate verification. DANGEROUS — development-only escape hatch, emits a WARN at boot. |

### `PluginResourceLimitsConfig`

Resource limits for Wasm plugins.

These limits constrain the sandbox resources available to a Wasm plugin. If not specified, system defaults are used (64 MiB memory, 10M fuel, 100ms timeout).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `fuel` | integer (optional) |  | Maximum fuel (instruction budget) per invocation (default: 10_000_000). |
| `memory_mb` | integer (optional) |  | Maximum linear memory in megabytes (default: 64). |
| `timeout_ms` | integer (optional) |  | Wall-clock timeout per invocation in milliseconds (default: 100). |

### `PluginSourceConfig`

Plugin artifact source configuration.

Exactly one of `path` / `oci` must be set. Both unset is invalid; both set is invalid. The source type determines how the gateway resolves the artifact at boot time.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `oci` | string (optional) |  | OCI reference (e.g. `ghcr.io/mcpg-dev/source-code/plugins/audit:1.0.0` or `plugins/audit@sha256:…`). At boot the gateway pulls the artifact, verifies the manifest digest, caches it to `plugin_registry.cache_dir`, and loads it through the same sidecar / packaged-zip path `path` would have taken. When the reference is missing a registry prefix, the `plugin_registry.default_registry` value is prepended — which is itself repointable per deployment via the `MCPG_DEFAULT_PLUGIN_REGISTRY` environment variable. |
| `path` | string (optional) |  | Path to the plugin artifact on the local filesystem. Accepts a raw `.so` / `.wasm` (with a sidecar `plugin.yaml`) or a packaged `.zip`. |

### `PolicyCacheConfig`

Configuration for the policy decision cache (L1 process-local).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` |  |
| `max_entries` | integer | `10000` |  |
| `ttl_ms` | integer | `60000` |  |

### `PolicyConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cache` | [`PolicyCacheConfig`](#policycacheconfig) | (see type) |  |
| `engine` | array&lt;[`KindRef`](#kindref)&gt; |  | Ordered chain of policy engines consulted at every decision point (`tool.call.pre`, `plugin.lifecycle.register`, etc.). Each entry is a [`KindRef`] — `kind:` resolves to a built-in keyword (`yaml-rules`), a short alias (`cedar`, `opa`, `casbin` → `dev.mcpg.policy.<alias>`), or a full reverse-domain plugin id. Chain semantics: the host walks the list in order, short-circuiting on the first `Allow` / `Deny`; `NotApplicable` falls through to the next engine. An empty chain is equivalent to `NotApplicable` everywhere — callers (e.g. `enforce_plugin_registration_policy`) decide whether that means "allow" (default-allow gateway) or "fail-closed" per their own policy posture. |
| `tool_access` | [`ToolAccessPolicyConfig`](#toolaccesspolicyconfig) | (see type) |  |

### `PromptArgumentConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `completions` | array&lt;string&gt; (optional) |  |  |
| `description` | string (optional) |  |  |
| `name` | string |  |  |
| `required` | boolean | `false` |  |

### `QuotasConfig`

`governance.quotas:` registry.

Three named-policy lists (rate_limits / budgets / concurrency) plus the storage backend that holds the runtime counters. Bindings opt into specific policies by id via their own per-binding `quotas:` block.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `budgets` | array&lt;[`BudgetPolicy`](#budgetpolicy)&gt; |  | Named cost / call-count / token-count budgets. Bindings reference by id. |
| `concurrency` | array&lt;[`ConcurrencyPolicy`](#concurrencypolicy)&gt; |  | Named concurrency caps. Bindings reference by id. |
| `on_error` | string | `"deny"` | Posture when the quota gate itself errors (e.g. a quota-store read/write failure): `deny` (default, fail-closed — refuse the call so a storage outage cannot silently disable rate-limit / budget / concurrency enforcement) or `allow` (fail-open — proceed without a permit). An empty value is treated as `deny`. |
| `rate_limits` | array&lt;[`RateLimitPolicy`](#ratelimitpolicy)&gt; |  | Named rate-limit policies. Bindings reference by id. |
| `store` | [`KindRef`](#kindref) | (see type) | Storage backend for quota counters / token-buckets / in-flight concurrency. Uses the standard `KindRef` discriminator. `kind: cluster` (default) routes through the cluster coordinator's KV role; `kind: memory` resets on restart (dev-only); `kind: <plugin-id>` pins to a loaded KV plugin. |

### `RateLimitPolicy`

One named rate-limit policy.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `burst` | integer (optional) |  | Bucket burst capacity — number of calls a caller can spend in quick succession before refill rate kicks in. Defaults to the per-second equivalent of `rate` (i.e., one second's worth). |
| `id` | string |  | Operator-chosen id. Bindings reference this via `tools[].quotas.rate_limit: <id>`. |
| `identity_claim` | string (optional) |  | JWT claim path used to key the bucket when `scope: per_identity`. Required for that scope; rejected for others. Common values: `sub`, `org_id`, `email`. |
| `kind` | string | `"token_bucket"` | Algorithm. v1.0 ships `token_bucket` only; `leaky_bucket` and `sliding_window` are not implemented. |
| `on_exceeded` | string | `"deny"` | Action when the bucket runs dry. `deny` returns a 429-style error; `queue` is reserved and currently aliases to `deny` for rate limits; `shed_load` drops silently. |
| `rate` | [`RateLimitRate`](#ratelimitrate) |  | Refill rate. Today only `calls_per_minute` is supported; future variants will land here. |
| `scope` | string | `"per_identity"` | Scope discriminator: how the bucket is keyed. `per_identity` keys by the JWT claim path in `identity_claim`; `global` shares one bucket across all callers; `per_session`, `per_tool` are also valid. |

### `RateLimitRate`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `calls_per_minute` | integer |  | Calls allowed per minute. Bucket refills at this rate. |

### `RegistryAuthConfig`

Consumer auth presented to the registry API.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `credential` | string (optional) |  | Credential-issuer reference for `cred`: a standard `cred://<plugin_id>/<target>` URI. The issuer mints + refreshes the registry bearer under the gateway's machine identity; no static token lives in the config. |
| `headers` | map&lt;string, string&gt; |  | Arbitrary request headers for `headers` (e.g. `X-API-Key`); values support `${env.X}`. |
| `mode` | [`RegistryAuthMode`](#registryauthmode) | `"none"` |  |
| `token` | string (optional) |  | Bearer token for `bearer` (supports `${env.X}`). |

### `RegistryAuthMode`

**Variants:**

- **`none`** — Anonymous reads (the generic spec's default).

- **`bearer`** — `Authorization: Bearer <token>`.

- **`headers`** — Arbitrary static headers (API-key style sub-registries).

- **`cred`** — Bearer minted by a credential-issuer plugin (`credential` is a `cred://` URI) under the gateway's machine identity.

### `RegistryDefaultsConfig`

Defaults applied to every synthesized federation.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`AuthConfig`](#authconfig) | (see type) | Upstream auth for synthesized federations (same modes as a hand-written federation; per-server `servers.<name>.auth` overrides win). |
| `cache` | [`FederationCacheConfig`](#federationcacheconfig) | (see type) | Capability-cache TTL refresh. |
| `governance` | [`BackendGovernanceConfig`](#backendgovernanceconfig) | (see type) | Governance inherited by every synthesized federation (trust floor + CEL), exactly like a hand-written federation's block. |
| `import` | [`ImportConfig`](#importconfig) | (see type) | Surfaces to import. Defaults to everything — the point of auto-federation is the full surface; narrow it here if not. |
| `oauth_discovery` | [`RegistryOauthDiscoveryConfig`](#registryoauthdiscoveryconfig) | (see type) | Sync-time OAuth discovery (RFC 9728 protected-resource metadata → RFC 8414 AS metadata) for synthesized federations whose auth uses an OAuth credential mode: derives each server's audience + token endpoint and injects them as the issuer's per-call config (`auth.credential_config`). Off by default. |
| `synthesize` | [`SynthesizeConfig`](#synthesizeconfig) | (see type) | Change-notification synthesis for push-less servers. |
| `upstream_safety` | [`RegistryUpstreamSafetyConfig`](#registryupstreamsafetyconfig) | (see type) | Per-server upstream network posture. Only `allow_private_backends` is honored — stdio and insecure HTTP stay denied for registry-driven servers regardless. |

### `RegistryFilterConfig`

Which registry servers are eligible.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `exclude` | array&lt;string&gt; | `[]` | Server-name globs to exclude (exclude wins). |
| `include` | array&lt;string&gt; | (see type) | Server-name globs to include (exact or trailing-`*`). |
| `namespaces` | array&lt;string&gt; | `[]` | Publisher-namespace allowlist (the part before `/`, e.g. `com.acme`). Empty = all namespaces. The anti-typosquatting rail: registry namespace ownership is publisher-verified, so pinning namespaces pins trust. |

### `RegistryOauthDiscoveryConfig`

Sync-time OAuth discovery for registry servers.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Fetch each OAuth-mode server's RFC 9728 + RFC 8414 metadata at sync time. Servers whose discovery fails (and that have no prior discovered snapshot) are skipped — a server that cannot be authenticated against would only fail at dispatch. |

### `RegistrySafetyConfig`

Network posture for the registry endpoint.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_insecure_http` | boolean | `false` | Permit `http://` (non-TLS) registry endpoints. |
| `allow_private_registry` | boolean | `false` | Permit a private / loopback registry address (normal for enterprise sub-registries; still an explicit opt-in). |

### `RegistryServerOverride`

Per-server override, keyed by registry server name.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `auth` | [`AuthConfig`](#authconfig) (optional) |  | Upstream auth override for this server. |
| `enabled` | boolean | `true` | Set false to exclude this server regardless of filters. |
| `headers` | map&lt;string, string&gt; |  | Values for the remote's declared request headers (secrets via `${env.X}`). Required-header declarations without a value here (or a registry-provided default) skip the server. |
| `variables` | map&lt;string, string&gt; |  | Values for `{variable}` templates in the server's remote URL. |
| `version` | string (optional) |  | Pin an exact registry version (default: track the registry's latest). |

### `RegistrySyncConfig`

Sync cadence + bounds.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `full_resync_hours` | integer | `24` | Hours between full crawls when `incremental` is on. Floor 1. |
| `incremental` | boolean | `false` | Crawl with `updated_since=<watermark>` between periodic full crawls instead of listing everything each tick. Status flips (including deletions) bump `updatedAt`, so deltas carry tombstones too; the periodic full crawl is the backstop for anything missed. Engages only once the registry has yielded `updatedAt` timestamps. |
| `interval_secs` | integer | `300` | Seconds between crawls. Each crawl lists the registry's latest server versions in full (cursor-paginated), so deletions are observed without a separate backstop. Floor 30. |
| `max_servers` | integer | `100` | Hard cap on federated servers from this registry. Servers beyond the cap (name-sorted) are skipped and reported — back-pressure against unbounded task/connection growth. |

### `RegistryUpstreamSafetyConfig`

Upstream network posture defaults for synthesized federations. Deliberately narrower than a hand-written federation's `upstream_safety`: the registry chooses which servers exist, so the dangerous knobs are not registry-reachable.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_private_backends` | boolean | `false` | Permit private / loopback server addresses (internal remotes — the common enterprise case; still an explicit opt-in). |

### `RequestStateConfig`

`request_state:` config — the MRTR `requestState` codec used by the modern wire's suspending `tools/call` arm to encrypt pipeline-resumption blobs.

Inert until a modern client connects. Lives under `mcp.configurations` because the codec manages runtime-emergent resumption state alongside sessions / pipelines / subscriptions / delivery / cancellation / idempotency — operator tunes the encryption key, the runtime mints + serves the rest.

```yaml mcp: configurations: request_state: # 32-byte ChaCha20-Poly1305 key, base64-encoded. # Generate via: head -c 32 /dev/urandom | base64 encryption_key: "<base64-32-byte-secret>" ```

Absent the key the gateway mints an ephemeral one at boot (with a WARN log) — pending resumptions issued before a gateway restart become undecodable after restart.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `encryption_key` | string (optional) |  | Base64-encoded 32-byte ChaCha20-Poly1305 secret. `None` ⇒ ephemeral key (random per process; resumptions lost on restart). |
| `strict_encryption` | boolean | `false` | Fail-closed guard for clustered modern resume. When `true` and the deployment is clustered (`cluster.kind != single_node`), the gateway REFUSES to boot if the `requestState` codec would fall back to an ephemeral per-process key — i.e. neither `encryption_key` nor a derivable `cluster.state_encryption_key_env` is available. An ephemeral key is undecodable on a peer, so a clustered modern (≤8 KiB inline) resume on another replica silently fails; this turns that silent fail-open into a loud boot error. Default `false` to keep existing clustered (e.g. legacy-only) deployments booting unchanged. |

### `ResourceWatchConfig`

Per-binding resource watch configuration. Defines how changes to a resource are detected for `notifications/resources/updated`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `notification_filter` | [`NotificationFilterConfig`](#notificationfilterconfig) (optional) |  | Notification filter — controls which subscribers receive the `notifications/resources/updated` message when a change is detected. Defaults to fan-out to all subscribers when absent. |
| `strategy` | [`WatchStrategyConfig`](#watchstrategyconfig) | (see type) | Strategy for detecting resource changes. |

### `ResponseCacheConfig`

Operator-facing config for the gateway-managed LLM response cache. The cache backs `BackendHost::cache_get` / `cache_put`; chat + embedding bindings opt in per-binding via their own `cache.enabled: true` knob, the cache only exists at all if this config is non-disabled.

`kind: in_process` is the default — content-addressed BLAKE3 LRU cache with 64 MiB byte cap, lost on restart. `kind: disabled` turns the cache off gateway-wide; per-binding `cache.enabled` becomes a no-op.

**Variants:**

- **`(unnamed variant)`**
  - `kind`: string
  - `max_bytes`: integer

- **`(unnamed variant)`**

### `ResponseConfig`

Per-call response limits.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `max_response_bytes` | integer | `2097152` | Cap on a single upstream call's response, enforced gateway-side. |

### `RetryConfig`

Per-binding retry configuration. Only applies to HTTP, gRPC, GraphQL, NATS, and Kafka bindings.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `initial_backoff_ms` | integer | `200` | Initial backoff delay in milliseconds. Doubled on each subsequent retry. |
| `max_attempts` | integer | `3` | Maximum number of retry attempts (not counting the initial attempt). |
| `retry_on_status_codes` | array&lt;integer&gt; | (see type) | HTTP status codes that trigger a retry (only applicable to HTTP/gRPC/GraphQL bindings). |
| `retry_on_transport_error` | boolean | `true` | Whether to retry on transport/connection errors. |

### `SchemaEntry`

A named schema entry in the registry. Exactly one source must be provided.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `file` | string (optional) |  | Path to a local JSON Schema file (relative to the config file). |
| `inline` | any |  | Inline JSON Schema definition. |
| `url` | string (optional) |  | URL to fetch the JSON Schema from at startup. |

### `ServedRegistryConfig`

`mcp.registry:` — serve a v0.1 MCP-Registry view of this gateway. The catalog exposed is exactly one server entry: the gateway itself (its whole governed surface hangs off one MCP endpoint), so pointing a registry-driven client policy here yields "the approved server is MCPG".

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `description` | string (optional) |  | Human description shown by registry clients. |
| `enabled` | boolean | `false` | Serve `GET /v0.1/servers` (+ per-version fetches). Default off. |
| `name` | string | `""` | Published server name, reverse-DNS namespaced (`com.acme/gateway`). Required when enabled. |
| `url` | string (optional) |  | Canonical external MCP endpoint published in the entry's `remotes[]`. Defaults to `governance.access.resource_metadata.resource` when unset. |

### `ServerConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `access_log` | boolean | `true` | Emit the per-request access log (`request received` / `request completed` INFO events, one pair per request). Default `true` (the gateway logs every request's lifecycle). Set `false` to suppress the access log on latency/throughput-sensitive deployments: it removes two structured-log events — and their field formatting + sink write — from every request. Audit events, error/warn logs, metrics, and traces are unaffected. Leave `true` unless request-level access logging is provided elsewhere (an ingress/sidecar) or not required. |
| `allow_private_backends` | boolean | `false` | Allow outbound connections to private/loopback/link-local IPs. Default `false` enables the DNS rebinding guard. Set `true` for container-network deployments where backends live on RFC 1918. |
| `allowed_origins` | array&lt;string&gt; | `[]` |  |
| `anonymous_rate_limit_burst` | integer | `100` | Burst allowance for `anonymous_rate_limit_per_min`. |
| `anonymous_rate_limit_per_min` | integer | `600` | Per-IP request-rate cap on the MCP endpoint for requests below cryptographically-verified trust — i.e. anonymous AND header-asserted identities (sustained requests/minute, with `anonymous_rate_limit_burst` headroom). A self-asserted `x-mcpg-subject-id` does NOT buy an exemption. Only Verified traffic (a real OIDC/JWKS/identity-plugin credential) skips this — it is attributable and metered per tenant. Defaults generous (600/min = 10 rps sustained per client IP), far above interactive agent use; `0` disables (e.g. when an upstream WAF throttles, or for single-IP load testing). |
| `bind_address` | string | `"127.0.0.1:8787"` |  |
| `completion_rate_limit_per_sec` | integer (optional) |  | Per-session rate limit on `completion/complete` requests (cap per second). `None` disables. Guards against broken autocomplete UIs. |
| `enforce_modern_request_meta` | boolean | `false` | Enforce the SEP-2575 per-request `_meta` identity triple (`io.modelcontextprotocol/{protocolVersion, clientInfo, clientCapabilities}`) on EVERY id-bearing modern (`2026-07-28`) request, not just `server/discover`. When false (the default), only `server/discover` requires the triple and other modern methods may carry minimal `_meta`. Has no effect on the `2025-11-25` wire. Opt-in so existing modern clients are unaffected until they adopt the triple. |
| `extra_resource_uri_schemes` | array&lt;string&gt; | `[]` | Extra resource-URI schemes (beyond the built-in allow-list) treated as first-class by the resource normalizer. Matched case-insensitively. |
| `health_check` | [`HealthCheckConfig`](#healthcheckconfig) | (see type) | Periodic prober for every binding's backend (SQL server reachability, gRPC endpoint, REST upstream, ...). Distinct from `health_path:` above — that's the gateway's own liveness endpoint for load balancers; this prober actively pings each binding's underlying service and updates `PluginState::{Active, Degraded}` based on results. |
| `health_path` | string | `"/health"` |  |
| `max_request_body_mb` | integer | `4` | Maximum POST body accepted on the MCP endpoint, in MiB. Defaults to 4 MiB. `0` falls back to the default — an unbounded body is never acceptable on a public endpoint. |
| `max_sessions_per_tenant` | integer | `0` | Per-tenant session quota. 0 = unlimited. The stricter of this and the global cap wins. |
| `mcp_path` | string | `"/mcp"` |  |
| `relax_request_id_uniqueness` | boolean | `false` | Relax the per-session JSON-RPC request-id uniqueness rule. When false (default) a client-supplied `id` that has already been used on the same MCP session is rejected with `-32600` (JSON-RPC forbids id reuse). Set `true` only for load generators that replay a fixed request body (e.g. the fortio proxy-overhead benchmark in `tools/bench/fortio/`), where every request carries the same `id`. Never enable in production — it removes a duplicate-delivery / replay guard. |
| `replay_window_limit` | integer | `16` |  |
| `request_timeout_ms` | integer | `30000` |  |
| `revalidate_mutated_tool_arguments` | boolean | `false` | Re-validate tool arguments against the tool's inputSchema after a tool_gate / transform plugin rewrites them. When false (default) only the caller's original arguments are validated. Opt-in defense-in-depth — plugins are operator-signed, so a rewrite that diverges from the published schema is normally trusted. |
| `scrub_process_env_after_boot` | boolean | `false` | After boot (plugins loaded, config-origin `env://` / `${env.X}` secrets already captured by the env secret provider's snapshot), remove those referenced env vars from the live process environment so a loaded cdylib can no longer read them via `std::env::var` / shared-process env. Opt-in defense-in-depth, default off. NOTE: this is NOT a hard boundary — it does not clear `/proc/self/environ` (the exec-time copy), so a hostile in-process plugin can still recover the original values there; it raises the bar against accidental/casual exposure. Enable only once every plugin resolves its secrets via the host (`cred://` / `env://`) rather than reading env directly. |
| `server_ping_interval_ms` | integer (optional) |  | Emit a server-initiated `ping` to each active session's SSE stream on this cadence. `None` or `0` disables. Reasonable value: 30s. |
| `session_idle_timeout_ms` | integer | `900000` |  |
| `shutdown_timeout_ms` | integer | `30000` |  |
| `tls` | [`TlsConfig`](#tlsconfig) (optional) |  |  |
| `transport` | [`TransportMode`](#transportmode) | `"http"` |  |
| `transports` | array&lt;[`KindRef`](#kindref)&gt; |  | Additional plugin-supplied transports started at boot alongside the primary HTTP / stdio listener (which continues to be governed by `transport:` and `bind_address:`). Each entry is a [`KindRef`] — `kind:` resolves to either a built-in transport keyword (today only `dev.mcpg.builtin.transport.memory` is wired; `builtin-http` / `builtin-stdio` map to the in-tree HTTP / stdio paths and don't need a list entry) or a registered Transport plugin id. The plugin's `Transport::start(config, dispatcher)` runs once per list entry; transports that fail to start halt the boot. Empty list = no extra transports beyond the primary listener — today's default. |
| `trust_proxy_ip` | boolean | `false` | Trust `X-Forwarded-For` for the client IP used by the anonymous rate limit. Set ONLY when a trusted reverse proxy / edge fronts this gateway (the managed-cloud Envoy edge does) — the header is spoofable otherwise. When false (default) the TCP peer address is used. |
| `trust_subject_header` | boolean | `false` | Trust the `x-mcpg-subject-id` request header as a header-asserted identity. The header carries no proof of who the caller is, so when false (default) it is IGNORED and such requests resolve to Anonymous — only a verified credential (OIDC/JWKS/identity plugin) yields a non-anonymous principal. Set true ONLY behind a trusted upstream that authenticates the caller and injects this header. |
| `tunnel` | [`TunnelConfig`](#tunnelconfig) (optional) |  | Reverse-tunnel egress: dial out to an MCPG-Cloud relay and serve this gateway's MCP surface through the tunnel. `mcpg --tunnel` populates this. Absent / `enabled: false` = no tunnel. |
| `tunnel_federation` | [`TunnelFederationConfig`](#tunnelfederationconfig) (optional) |  | Reverse-federation ingress: how this gateway reaches same-org `tunnel://<name>` federation upstreams through the relay's federation ingress. Independent of `tunnel` (egress) — a gateway can federate other gateways' tunnels without dialing one of its own. |
| `unary_json_fast_path` | boolean | `false` | On the legacy (`2025-11-25`) wire, answer a unary request whose result is immediately available and that emitted NO server→client notifications (`log` / `progress`) with a single `application/json` response instead of a one-frame `text/event-stream` reply. This is spec-permitted (Streamable HTTP lets the server pick JSON or SSE) and mirrors what the modern (`2026-07-28`) wire already does; it skips the per-request SSE stream bookkeeping (replay-window append, priming + logging frames, session snapshot) that otherwise runs under the session lock, which materially raises tool-call throughput. Default `false` (unchanged SSE behaviour). A request that DOES emit notifications, or suspends (MRTR), still streams regardless of this flag. |

### `SessionConfig`

Upstream-session behaviour.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `idle_timeout_secs` | integer | `600` |  |

### `SessionsConfig`

`sessions:` config — session lifecycle store + per-capability `store:` override. When `store` is unset, the session KV inherits from the cluster's `key_value_store()` primitive; when set, the override pins to an in-process backend (memory / file).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `bind_session_owner` | boolean | `false` | Bind each session to the principal that created it. When true, session-scoped operations (GET→SSE stream, DELETE→terminate, subscriptions, POST→SSE continuation) require the caller's resolved principal to match the session's creator; a mismatch is refused as if the session did not exist (no existence leak). Default false (today's possession-only behaviour). An anonymous session (no creating principal) can only be driven anonymously. |
| `optional` | boolean | `false` | Make sessions optional on the legacy (`2025-11-25`) wire. When false (default), a legacy request without an `Mcp-Session-Id` header is rejected (`-32600`, HTTP 400) — a legacy client MUST `initialize` first. When true, such a request is instead served through an ephemeral, row-less session (the same lane the modern wire uses for anonymous stateless calls): the gateway does not issue a session, so it does not demand one. Spec-permitted (a server chooses whether to issue sessions), and lets fixed-tool-set proxy deployments skip the handshake round-trip. Features that inherently need a durable session — SSE resume cursors, server-initiated requests, cross-request task/subscription continuity — still require a real session; a session-less request that would need one gets a clear error. `initialize` continues to mint real sessions regardless. |
| `store` | [`StoreOverrideConfig`](#storeoverrideconfig) (optional) |  |  |
| `synthetic_session_key` | string (optional) |  | Base64-encoded 32-byte secret used to derive the per-principal synthetic session id minted for modern (2026-07-28) stateless requests that arrive without a session header. |

### `SignalToggle`

Per-plugin per-signal toggle. Four knobs:

- `enabled` (default `true`): when `false`, every event from this plugin's crate is dropped at the bridge before it reaches the sink fan-out — the "silence this noisy plugin" pattern. - `level` (logs / traces only): minimum severity an event must clear to be emitted. Composed into the bridge layer's permissive filter so per-plugin verbosity boosts AND suppressions both work. Accepted: `trace` / `debug` / `info` / `warn` / `error` (case-insensitive). - `mode` (default `inherit`): how to route events that pass the gate. `inherit` flows through the global sink list (the default behaviour). `replace` routes ONLY to the plugins listed under `sinks` — used for compliance carve-outs ("audit logs go to my SIEM, never to stdout"). `tee` fans out to BOTH the global sink list AND the per-plugin `sinks`. - `sinks`: plugin ids of the sink plugins to use under `mode: replace | tee`. Each id MUST match a registered sink plugin for the corresponding signal — log sink for `logs.sinks`, metrics sink for `metrics.sinks`, span sink for `traces.sinks`. If any id is unknown to the matching signal, the gateway refuses to boot (validated post-registration in `app::validate_per_plugin_sink_ids`). Listing a real log sink id under `metrics.sinks` is rejected — sink-kind crossover is a typo, not a feature.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` |  |
| `level` | string (optional) |  |  |
| `mode` | [`SinkMode`](#sinkmode) |  |  |
| `sinks` | array&lt;string&gt; |  |  |

### `SignatureConfig`

Per-plugin signature configuration.

Consolidates three signature concerns into one per-plugin block: - The content-hash pin. - The verification policy — per-plugin overridable, with the global default in `gateway.plugin_registry.default_signature_policy:`. - The Ed25519 trusted keys this artifact must verify against — per-plugin so plugins from different vendors can carry different keys without pooling them in one trust anchor.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `policy` | [`SignaturePolicy`](#signaturepolicy) (optional) |  | Verification policy for this plugin. `None` = inherit `gateway.plugin_registry.default_signature_policy:`. |
| `sha256` | string (optional) |  | SHA-256 content hash to pin (hex-encoded). When set, the gateway refuses to load the artifact if its computed hash doesn't match. |
| `trusted_keys` | array&lt;[`TrustedKeyConfig`](#trustedkeyconfig)&gt; |  | Ed25519 verification keys this artifact's signature must verify against. Empty = inherit gateway-wide defaults. |

### `SignaturePolicy`

Signature verification policy for native plugin artefacts. The Ed25519 signature attached to the artefact (`<artifact>.sig` or the packaged `plugin.sig`) is the primary check; this policy governs behaviour when the signature is missing or invalid. Set per-plugin via `plugins[*].signature.policy:`, or as a gateway-wide default via `gateway.plugin_registry.default_signature_policy:`.

**Variants:**

- **`disabled`** — Signature checks are skipped entirely. Development only; gateway emits a `governance.plugin.signature_policy_disabled` audit event for any entry that resolves to this policy so the choice is visible in the compliance trail.

- **`warn`** — Log a warning for missing or invalid signatures but proceed with the load — ONLY while no trusted keys are configured. The built-in official key means an inheriting entry always has keys, so this behaves like `enforce` unless a config empties the trust set.

- **`enforce`** — Refuse to load any artefact whose signature is missing or does not verify against the configured trusted keys. The default: a stock gateway loads only signed plugins.

### `SinkConfig`

One sink in an observability signal's `sinks: [...]` list. The `kind:` field dispatches to a built-in factory (`stderr`, `stdout`, `file`, `otlp`, `prometheus`) or to a plugin id (any other value is looked up in the plugin registry at boot).

`config:` is the sink-kind-specific config object. Built-in kinds validate their own `config:` shape at boot; for plugin sinks, the plugin's own config schema applies.

`level:` is an optional per-sink severity floor. When `None`, the sink inherits the signal's `level:`. Useful for `stderr: warn, file: debug` setups where the console is quiet but a file captures everything. Per-sink level overrides are parsed but not yet enforced; today signal-level `level:` is the only enforced floor.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `config` | any |  | Sink-specific config object. Schema depends on `kind:`. |
| `kind` | string |  | Sink kind. Built-in keywords: `stderr`, `stdout`, `file`, `otlp`, `prometheus`. Anything else is resolved as a plugin id at boot. |
| `level` | string (optional) |  | Per-sink severity floor. `None` = inherit signal-level `level:`. |

### `SinkMode`

How to route events for a per-plugin signal toggle. Operator schema: `mode: inherit | replace | tee`.

**Variants:**

- **`inherit`** — Inherit the global sink list — the same routing every other plugin's events use. Default.

- **`replace`** — Route admitted events ONLY to the per-plugin `sinks` list. Skips the global sink fan-out entirely. Used for compliance carve-outs (audit logs stay inside the SIEM).

- **`tee`** — Tee — admitted events flow to BOTH the global sink list AND the per-plugin `sinks` list. Useful when an operator wants to keep default routing but additionally mirror a noisy plugin's events to a debugging sink.

### `StorageConfig`

Top-level `storage:` block. Holds the gateway's content-store providers + the LLM response cache.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `default` | string (optional) |  | Provider id that bindings without an explicit `content_storage:` field route to. When unset, the gateway falls back to a provider with the conventional id `default`. Validated at boot — an unknown id fails fast. |
| `providers` | array&lt;[`StorageProviderConfig`](#storageproviderconfig)&gt; | `[]` | Content-store provider entries. Each entry produces an `Arc<dyn ContentStore>` registered under `id` in the gateway's runtime registry. Bindings reference providers by `id` via their own `content_storage:` field. |
| `response_cache` | [`ResponseCacheConfig`](#responsecacheconfig) | (see type) | Gateway-managed LLM response cache. Lives here (rather than under `plugins:`) so all "where bytes go to live" config shares one home. |

### `StorageProviderConfig`

One operator-declared content-store provider, an entry in `storage.providers: [...]`. The `kind` field selects the storage plugin (`in_process` / `file_system` / `s3` / future plugins); `config` is the per-plugin configuration object whose schema is owned by the plugin (see each plugin's `plugin.yaml`).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `config` | any |  | Plugin-specific configuration JSON. Validated by the plugin at `build_profile` time; gateway boot fails fast if the shape doesn't match. |
| `id` | string |  | Operator-chosen id. Bindings reference providers via this id (`content_storage: <id>` on the binding entry). The conventional `default` id is the fallback when a binding doesn't specify its own AND `storage.default` is unset. |
| `kind` | string |  | Storage plugin kind (e.g. `in_process`, `file_system`, `s3`). Resolved against the gateway's content-store plugin registry at boot. |

### `StoreOverrideConfig`

`<capability>.store: { kind, … }` — produces an `Arc<dyn mcpg_cluster_api::KeyValueStore>` at boot.

Recognised `kind` values: `cluster`, `memory`, `file`. (`redis` and `nats` are not accepted here — set `cluster.kind: redis | nats` and use `kind: cluster` here, or omit the override entirely.)

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `kind` | string |  |  |

### `SubscriptionsConfig`

`subscriptions:` config (resource subscriptions) — subscription store + per-capability `store:` override + per-session quota. When `store` is unset, the subscription KV inherits from the cluster's `key_value_store()` primitive.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `max_per_session` | integer | `100` | Maximum subscriptions per session (0 = unlimited). |
| `store` | [`StoreOverrideConfig`](#storeoverrideconfig) (optional) |  |  |

### `SynthesizeConfig`

Change-notification synthesis: when the upstream has no server→client push channel, the gateway can manufacture `notifications/resources/updated` for subscribed federated resources by polling them through the normal read path and hash-diffing the content (the watch engine's poll strategy). `list_changed` synthesis rides the existing capability TTL refresh (`cache.capability_ttl_secs`) and needs no knob here.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `poll_interval_ms` | integer | `30000` | Poll cadence for synthesized resource updates. Watchers are subscriber-gated: no subscribers, no polling. |
| `resources_updated` | [`SynthesizeMode`](#synthesizemode) | `"auto"` | When to poll-synthesize `resources/updated` for subscribed federated resources. |

### `SynthesizeMode`

Gate on synthesized change notifications.

**Variants:**

- **`auto`** — Synthesize only when the upstream demonstrably cannot push resource updates: the modern (`2026-07-28`) wire and the `stdio` transport. A legacy streamable-http upstream keeps its GET-SSE push path and is not polled.

- **`poll`** — Always poll, even for upstreams with a push channel (covers legacy servers that only emit `resources/updated` for subscriptions the gateway does not place upstream).

- **`off`** — Never synthesize.

### `TaggedVariableCompletionSource`

**Variants:**

- **`(unnamed variant)`** — Static list of completion values. Same shape as the shorthand bare-list but with explicit `kind` tag.
  - `kind`: string
  - `values`: array&lt;string&gt;

- **`(unnamed variant)`** — Dynamic dispatch: at completion time, the gateway calls [`crate::backends::CapabilityRegistry::complete_argument`], which routes to the named backend's `BackendPlugin::complete_template_variable(binding_name, variable_name, prefix, &config)`. The backend returns up to 100 completions matching the prefix.
  - `backend`: string
  - `config`: any
  - `kind`: string

### `TasksConfig`

`tasks:` config (MCP 2025-11-25 tasks system) — task store + per-capability `store:` override + retention tuning. When `store` is unset, the task KV inherits from the cluster's `key_value_store()` primitive. Tuning fields (`default_ttl_ms`, `reaper_interval_ms`, `max_tasks_per_session`, `result_wait_ms`) are orthogonal and apply to whichever backend resolves.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `default_ttl_ms` | integer | `1800000` | Default TTL applied to any task created without an explicit `task.ttl` from the client. Used by `tasks/create` and the reaper. |
| `max_tasks_per_session` | integer | `256` | Maximum concurrent tasks per session. Creation above this quota is rejected with JSON-RPC `-32603 Internal error` rather than silently succeeding. `0` disables the quota. |
| `reaper_interval_ms` | integer | `60000` | Background reaper sweep interval. The reaper deletes records whose `created_at + ttl` has elapsed. |
| `result_wait_ms` | integer | `30000` | Upper bound on a single `tasks/result` HTTP blocking wait. Clients that need longer-running tasks reconnect via GET SSE and `Last-Event-Id` until the task goes terminal. |
| `store` | [`StoreOverrideConfig`](#storeoverrideconfig) (optional) |  |  |

### `TlsConfig`

TLS configuration for the HTTP transport.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cert_path` | string |  |  |
| `client_ca_certs_path` | string (optional) |  | Optional path to a PEM bundle of CA certs that gate-keep client cert acceptance for mTLS. Required whenever `client_cert_required` is `"optional"` or `"mandatory"`; must be empty / absent when `"none"`. |
| `client_cert_required` | [`ClientCertMode`](#clientcertmode) | `"none"` | Client cert acceptance mode for mTLS connections: |
| `key_path` | string |  |  |
| `min_tls_version` | string | `"1.2"` | Minimum TLS version: `"1.2"` or `"1.3"`. Default `"1.2"`. |

### `TokenSourceConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `header_name` | string (optional) |  |  |
| `header_prefix` | string (optional) |  |  |
| `kind` | [`TokenSourceKind`](#tokensourcekind) | `"authorization_bearer"` |  |

### `TokenSourceKind`

**Allowed values:**

- `authorization_bearer`
- `custom_header`

### `ToolAccessPolicyConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cel_allow_if` | string (optional) |  |  |
| `default_minimum_trust` | [`TrustLevelConfig`](#trustlevelconfig) | `"header_asserted"` |  |
| `rules` | array&lt;[`ToolTrustRuleConfig`](#tooltrustruleconfig)&gt; | `[]` |  |

### `ToolTrustRuleConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `cel_allow_if` | string (optional) |  |  |
| `minimum_trust` | [`TrustLevelConfig`](#trustlevelconfig) |  |  |
| `required_scopes` | array&lt;string&gt; |  | OAuth scopes the caller's token MUST carry to invoke this tool (SEP-2350). A caller authenticated but lacking any of these is denied with HTTP 403 + a `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` step-up challenge naming the missing scopes, rather than a bare 403 — so a capability-aware client can request the additional scopes and retry. Empty (the default) means no scope requirement. |
| `tool_name` | string |  |  |

### `TracesConfig`

`observability.traces:` — the traces signal.

Span lifecycle events (every `tracing::info_span!()` / `debug_span!()` and every plugin-emitted span) flow through the configured sink list. The canonical sink is `otlp` (exports to an OpenTelemetry Collector). Default: traces disabled (operators opt in by setting `enabled: true` and adding sinks).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Master enable for the traces signal. Default `false` — tracing has non-trivial overhead so operators opt in. |
| `propagate_context` | boolean | `true` | Propagate W3C trace context (`traceparent` / `tracestate`) headers to outbound binding calls. Defaults to `true` — downstream services join the same trace. |
| `service_name` | string | `"mcpg"` | Service name advertised to OTel collectors. Default `"mcpg"`. |
| `sinks` | array&lt;[`SinkConfig`](#sinkconfig)&gt; | `[]` | Sink fan-out. Each entry's `kind:` resolves to a built-in factory (`otlp`) or plugin id. Default: empty — operators add an `otlp` sink to ship to a collector. |

### `TransportMode`

Transport mode determines whether MCPG runs as an HTTP server or a stdio JSON-RPC process.

**Allowed values:**

- `http`
- `stdio`

### `TrustLevelConfig`

**Allowed values:**

- `unauthenticated`
- `header_asserted`
- `verified`

### `TrustedIdpConfig`

One enterprise IdP trusted to issue ID-JAGs.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_private_network` | boolean | `false` | Local-development escape hatch: permit `http://` and private/loopback IdP addresses. Production deployments leave this `false`. |
| `allowed_hosts` | array&lt;string&gt; | `[]` | Optional host allowlist for discovery/JWKS fetches (exact or subdomain match). Empty = any public host. |
| `issuer` | string |  | The IdP's issuer identifier, compared exactly against the ID-JAG `iss` claim. |
| `jwks_uri` | string (optional) |  | JWKS endpoint override. When omitted, the JWKS URI is taken from the IdP's OIDC discovery document (`{issuer}/.well-known/openid-configuration`). |

### `TrustedKeyConfig`

One trusted-key entry inside `SignatureConfig.trusted_keys`.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `id` | string |  | Operator-chosen id for the key (audit-trail label). |
| `pem` | string |  | PEM-encoded public key. Multi-line literal in YAML. |

### `TunnelConfig`

Reverse-tunnel egress config. The gateway dials out to a relay and answers tunnelled MCP traffic through its own request path.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Master switch. `false` (default) dials no tunnel. |
| `exposure` | [`TunnelExposure`](#tunnelexposure) | `"public"` | `public` allocates a `<id>.tunnels.mcpg.cloud` URL (dev preview, third-party MCP clients); `private` (federation-only) allocates no public address and is reachable only as a `tunnel://` federation upstream from the same org. |
| `mode` | [`TunnelTrustMode`](#tunneltrustmode) | `"relay_terminated"` | `relay_terminated` (the relay sees plaintext) or `e2ee` (relay splices ciphertext — requires `private` exposure, mcpg-to-mcpg only). |
| `name` | string (optional) |  | Optional stable tunnel name; the relay allocates one when unset. |
| `relay_url` | string | `"wss://relay.tunnels.mcpg.cloud"` | Relay endpoint to dial (e.g. `wss://relay.tunnels.mcpg.cloud`). |

### `TunnelExposure`

Whether a tunnel gets a public hostname.

**Allowed values:**

- `public`
- `private`

### `TunnelFederationConfig`

Reverse-federation ingress config. A `tunnel://<name>/<path>` federation upstream resolves through the relay's federation ingress to `<relay_ingress_url>/federate/<name>/<path>`. This gateway authenticates its ORG to the relay with the `token` field below (carried in the `X-MCPG-Tunnel-Token` header, which the relay consumes and never forwards); the end-user's `Authorization` bearer flows through, untouched, to the tunnelled gateway as the MCP caller identity.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `relay_ingress_url` | string |  | Relay federation-ingress base URL, e.g. `https://relay.tunnels.mcpg.cloud`. Must be `http(s)`. |
| `token` | string (optional) |  | Org token presented to the relay in `X-MCPG-Tunnel-Token`. When unset, the gateway falls back to the `MCPG_TUNNEL_TOKEN` environment variable (the same org token used for egress dial), so a gateway that both dials and federates needs the token in one place. Supports `${env.X}`. |

### `TunnelTrustMode`

Who can read tunnelled payloads.

**Allowed values:**

- `relay_terminated`
- `e2ee`

### `UiGroup`

A labelled group of fields in a form/detail layout.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `fields` | array&lt;string&gt; |  |  |
| `label` | string |  |  |

### `UiSchema`

Widget/layout overlay — the tight mcpg-native uiSchema subset.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `groups` | array&lt;[`UiGroup`](#uigroup)&gt; (optional) |  | Labelled field groups / sections. |
| `order` | array&lt;string&gt; (optional) |  | Explicit field render order. |
| `widgets` | map&lt;string, [`UiWidget`](#uiwidget)&gt; |  | field-path → widget specification. |

### `UiWidget`

How a single field renders, plus its client-evaluated rules.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enum_from` | [`EnumSource`](#enumsource) (optional) |  | Options sourced from a sibling tool result (via the action proxy). |
| `help` | string (optional) |  |  |
| `label` | string (optional) |  |  |
| `placeholder` | string (optional) |  |  |
| `required_if` | string (optional) |  | Client-evaluated conditional-required expression. |
| `visible_if` | string (optional) |  | Client-evaluated visibility expression. |
| `widget` | [`WidgetKind`](#widgetkind) |  |  |

### `UpstreamConfig`

Upstream connection details.

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `args` | array&lt;string&gt; | `[]` | Arguments passed to the stdio `command`. |
| `auth` | [`AuthConfig`](#authconfig) | (see type) | How MCPG authenticates to the upstream. |
| `command` | string (optional) |  | Command to spawn for the `stdio` transport (ignored otherwise). |
| `env` | map&lt;string, string&gt; | `{}` | Extra environment for the stdio `command`. |
| `headers` | map&lt;string, string&gt; |  | Static request headers sent on every upstream call (API-key style upstreams, e.g. `X-API-Key`); values support `${env.X}`. Reserved protocol headers (`authorization`, `mcp-*`, `content-type`, `accept`) are rejected — auth goes through `auth`, the wire headers stay MCPG's. |
| `protocol_version` | [`UpstreamProtocolVersion`](#upstreamprotocolversion) | `"auto"` | MCP wire revision MCPG speaks to this upstream as a client. |
| `transport` | [`UpstreamTransport`](#upstreamtransport) | `"streamable_http"` | Wire transport. |
| `upstream_safety` | [`UpstreamSafetyConfig`](#upstreamsafetyconfig) | (see type) | SSRF / DNS-rebinding posture (http) + local-exec posture (stdio). |
| `url` | string | `""` | Base MCP endpoint URL (the upstream's `/mcp`). Required for the `streamable_http` transport; unused (empty) for `stdio`. |

### `UpstreamProtocolVersion`

MCP wire revision the federation client speaks to an upstream.

**Variants:**

- **`auto`** — Detect the upstream's wire at connect time (the default): attempt the modern `server/discover`, and fall back to the legacy `initialize` handshake when the peer rejects it (the SEP-2575 backward-compatibility probe). The detected wire is cached per federation for the engine's lifetime. Pin one of the dated revisions to skip probing. The `stdio` transport never probes (it is legacy-only).

- **`2025-11-25`** — Session-bound `2025-11-25` wire (`initialize` handshake, `Mcp-Session-Id`, no SEP-2243 headers) — byte-identical to the legacy federation client.

- **`2026-07-28`** — Stateless `2026-07-28` wire (no handshake / session, per-request `_meta` identity, SEP-2243 routing headers).

### `UpstreamSafetyConfig`

SSRF / DNS-rebinding posture for the upstream URL. Mirrors the HTTP binding's guard (`runtime/safe_dns.rs`).

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `allow_insecure_http` | boolean | `false` | Permit `http://` (non-TLS) upstreams. |
| `allow_private_backends` | boolean | `false` | Permit private / loopback upstream addresses. |
| `allow_stdio` | boolean | `false` | Permit the `stdio` transport, which spawns a local child process (arbitrary local execution — default-deny). |

### `UpstreamTransport`

Upstream wire transport.

**Variants:**

- **`streamable_http`** — MCP Streamable HTTP (POST + SSE).

- **`stdio`** — Local stdio child process.

### `UsageReportingConfig`

| Field | Type | Default | Summary |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Send the anonymous adoption ping. Defaults to `false`. `DO_NOT_TRACK=1` / `MCPG_TELEMETRY=off` disable regardless. |
| `endpoint` | string | `"https://telemetry.mcpg.dev/v1/usage"` | Ingest endpoint (HTTPS). Self-hostable — point it at your own collector. |

### `VariableCompletionSource`

Per-template-variable completion source.

The bare-list shorthand stays valid (post-launch shipping shape): `variable_completions: { region: ["us-east-1", "us-west-2"] }` is read by the `BareList` arm and treated as if the operator had written `{ kind: static, values: [...] }`. The tagged form is the new shape — `kind: dynamic` introduces backend dispatch.

Type: array&lt;string&gt; | [`TaggedVariableCompletionSource`](#taggedvariablecompletionsource)

### `VerificationConfig`

**Variants:**

- **`(unnamed variant)`**
  - `allow_hmac`: boolean
  - `allowed_algs`: array&lt;string&gt;
  - `kind`: string
  - `max_staleness_secs`: integer
  - `refresh_interval_secs`: integer
  - `timeout_ms`: integer

- **`(unnamed variant)`**
  - `client_id`: string
  - `client_secret_ref`: string
  - `introspection_url`: string
  - `kind`: string
  - `timeout_ms`: integer

- **`(unnamed variant)`** — JWTs are verified against the JWKS; opaque tokens are introspected.
  - `allow_hmac`: boolean
  - `allowed_algs`: array&lt;string&gt;
  - `client_id`: string
  - `client_secret_ref`: string
  - `introspection_timeout_ms`: integer
  - `introspection_url`: string
  - `kind`: string
  - `max_staleness_secs`: integer
  - `refresh_interval_secs`: integer
  - `timeout_ms`: integer

### `WatchStrategyConfig`

**Variants:**

- **`poll`** — Poll the resource periodically and compare SHA-256 hash.
  - `interval_ms`: integer

- **`nats_topic`** — Subscribe to a NATS subject — any message means the resource changed.
  - `subject`: string

- **`kafka_topic`** — Subscribe to a Kafka topic — any message means the resource changed.
  - `group_id`: string
  - `topic`: string

- **`webhook`** — Receive webhook POSTs from 3rd-party systems. MCPG exposes `/webhooks/resource-updated/{token}` and triggers `notifications/resources/updated` when a POST is received.
  - `token`: string

- **`sql_polling`** — SQL polling watch — `dev.mcpg.watch.sql_polling` plugin runs a scalar tracking query on a cadence and emits an event when the returned scalar advances. Spec mirrors the `[bindings.sql]` shape (`driver`, `url`, optional `pool` / `session_vars`, required `query` block, `interval_ms`); see the SQL binding plugin docs for the full field list. Pass-through here keeps the spec the single source of truth in the plugin crate.

- **`postgres_listen_notify`** — Postgres LISTEN/NOTIFY watch — `dev.mcpg.watch.postgres_listen_notify` plugin holds one dedicated connection per watch and re-emits NOTIFY payloads. Far lower overhead than polling for change-feed-style sources.
  - `channel`: string
  - `url`: string

- **`plugin`** — Generic escape hatch — delegate to ANY loaded `watch_strategy` plugin by its `kind()` discriminator. Use this for custom watch plugins that have no dedicated typed variant above (e.g. the Twilio plugin's `twilio_inbound` strategy). The remaining fields flatten into the spec passed verbatim to the plugin's `watch()`, so the plugin owns and validates its own spec schema.
  - `kind`: string

### `WidgetKind`

The closed widget vocabulary.

**Variants:**

- **`text`**

- **`array`** — Repeatable list of scalar inputs → a JSON array value.
