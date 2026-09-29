# multi-tenant

A single gateway serving multiple tenants identified by their OIDC subject claim. Every tenant lands at the same `bind_address` and gets isolated by:

1. **Per-tenant session quota** at the gateway level (`server.max_sessions_per_tenant`).
2. **Per-tenant rate limiting** via the rate-limit plugin's default `per_principal` scope (keyed on the authenticated principal).
3. **Group-gated bindings** via `governance.allow_if` CEL expressions.

This is *application-layer* multi-tenancy. Subdomain-based routing (different host → different gateway) belongs in your reverse proxy / ingress, not in this YAML.

## What's in it

- Redis cluster (same as the production-redis-cluster topology), served by the `dev.mcpg.cluster.redis` plugin.
- OIDC inbound auth — tenant identity comes from the `sub` claim. The `dev.mcpg.identity.oidc` plugin carries the same providers as `governance.access.oidc_oauth`.
- `gateway.server.max_sessions_per_tenant: 100` — each tenant capped at 100 concurrent sessions.
- One `dev.mcpg.rate-limit` plugin entry; its default `per_principal` scope buckets by tenant id.
- Metrics through the `dev.mcpg.observability.prometheus` plugin at `/metrics` on the gateway listener.
- The gateway image carries no plugins: the gateway pulls each signed artifact in `plugins` at boot. Without the Redis or the OIDC entry the gateway refuses to boot; without the Prometheus entry it boots and exports no metrics.
- A `license` block. The Redis coordinator is a licensed plugin: the gateway refuses to load it without a license that entitles `cluster.*` plugins (Team, Enterprise). Outside production, `license.non_production_use: true` in place of the token loads it under the non-production grant.
- Two bindings illustrating governance:
  - `api.tenant.lookup` — any authenticated tenant.
  - `api.admin.tenant.delete` — only `tenant_admins` group members.

## What to change

| Field | Why |
|---|---|
| `gateway.server.max_sessions_per_tenant` | Per-SLA-tier cap. 100 is a starting point; 0 = unlimited. |
| `governance.access.oidc_oauth.providers`, `config.providers` of the `dev.mcpg.identity.oidc` entry | Your IdP's issuer and the audience it issues for this gateway, the same in both places. |
| `config.default_limit` / `default_window_ms` / `default_burst` of the `dev.mcpg.rate-limit` entry | Rate-limit budget — pick by tenant tier. For per-tool overrides add a `rules:` entry; for multi-tier limits register multiple plugin entries with different `id`s. |
| `plugins[*].source.oci` | The plugin releases that match the gateway you run, or your mirror of them. |
| `mcp.capabilities.tools[1].governance.allow_if` | The CEL expression resolving "is this caller an admin?". Adapt to your IdP's group claim shape. |

## Required env vars

- `MCPG_REDIS_URL` — Redis cluster.
- `MCPG_REDIS_PASSWORD` — Redis password, passed out of the URL.
- `MCPG_CLUSTER_STATE_KEY` — URL-safe-base64 32-byte state-encryption key, identical on every replica (`openssl rand -base64 32 | tr '+/' '-_'`). Required whenever `cluster.kind` is not `single_node`.
- `MCPG_LICENSE_PUBKEY` — the public key (SPKI PEM) that verifies the license token.

The IdP needs no credentials here: issuer and audience are inline in the YAML, and the verification keys come from the IdP's JWKS.

## CEL primer for tenant-aware bindings

The gateway exposes the resolved identity to `governance.allow_if` CEL expressions via the bare `identity` variable (the `$`-prefix is not used in `allow_if` CEL):

| CEL access | What it returns |
|---|---|
| `identity.subject_id` | OIDC `sub` claim — your tenant id. |
| `identity.groups` | Array of group claim values. |
| `identity.attributes.<k>` | Arbitrary claim values mapped via `claim_mappings`. |
| `identity.trust_level` | Resolved trust enum (`unauthenticated` / `header_asserted` / `verified`). |

Examples:

```yaml
# Members of one specific tenant only
allow_if: 'identity.subject_id == "tenant-acme"'

# Members of an admin group, regardless of tenant
allow_if: 'has(identity.groups) && "tenant_admins" in identity.groups'

# Tier-based gating (claim_mappings populated `tier` from a custom claim)
allow_if: 'identity.attributes.tier in ["enterprise", "premium"]'
```

## Audit

The built-in `dev.mcpg.builtin.audit.local-file` sink writes a single hash-chained JSON Lines file (`config.path`); every event already carries the resolved `subject_id`, so per-tenant segmentation is a downstream concern — split on the `subject_id` field in your SIEM/forwarder, or register a custom `audit_sink` plugin if you need per-tenant files at the gateway.

## Operational notes

- **Onboarding a tenant.** No gateway change required — once their tokens validate, the rate-limit bucket spins up lazily on first request.
- **Removing a tenant.** Revoke the IdP grant; their existing tokens stop validating at the next key rotation. The session quota frees automatically as old sessions hit `session_idle_timeout_ms`.
- **Noisy-neighbor isolation.** The rate-limit plugin protects against noisy callers within their per-tenant budget; for hard isolation (CPU / memory) deploy separate gateway replicas behind subdomain routing.
