# multi-tenant

A single gateway serving multiple tenants identified by their OIDC subject claim. Every tenant lands at the same `bind_address` and gets isolated by:

1. **Per-tenant session quota** at the gateway level (`server.max_sessions_per_tenant`).
2. **Per-tenant rate limiting** via the rate-limit plugin's default `per_principal` scope (keyed on the authenticated principal).
3. **Group-gated bindings** via `governance.allow_if` CEL expressions.

This is *application-layer* multi-tenancy. Subdomain-based routing (different host → different gateway) belongs in your reverse proxy / ingress, not in this YAML.

## What's in it

- Redis cluster (same as the production-redis-cluster topology).
- OIDC inbound auth — tenant identity comes from the `sub` claim.
- `gateway.server.max_sessions_per_tenant: 100` — each tenant capped at 100 concurrent sessions.
- One rate-limit plugin entry; its default `per_principal` scope buckets by tenant id.
- Two bindings illustrating governance:
  - `api.tenant.lookup` — any authenticated tenant.
  - `api.admin.tenant.delete` — only `tenant_admins` group members.

## What to change

| Field | Why |
|---|---|
| `gateway.server.max_sessions_per_tenant` | Per-SLA-tier cap. 100 is a starting point; 0 = unlimited. |
| `plugins[0].config.default_limit` / `default_window_ms` / `default_burst` | Rate-limit budget — pick by tenant tier. For per-tool overrides add a `rules:` entry; for multi-tier limits register multiple plugin entries with different `id`s. |
| `plugins[0].source.oci` | The rate-limit plugin's OCI reference if your registry differs. |
| `mcp.capabilities.tools[1].governance.allow_if` | The CEL expression resolving "is this caller an admin?". Adapt to your IdP's group claim shape. |

## Required env vars

- `MCPG_REDIS_URL` — Redis cluster.
- IdP credentials (issuer / audience are inline in the YAML; verification keys come from the IdP's JWKS).

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
