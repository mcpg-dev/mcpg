# air-gapped

Zero-outbound deployment for secured networks: no OCI plugin pulls, no remote OIDC discovery, no remote storage, no remote audit sink. Everything that would normally call out is either disabled or pointed at a local artefact.

## What's in it

- `cluster.kind: single_node` — no Redis / NATS dependency.
- Static JWKS auth (`governance.access.jwks`) — gateway never contacts the IdP. You pre-stage the JWK Set yourself.
- `storage.providers[0].kind: file_system` rooted at `/var/lib/mcpg/storage`.
- `governance.audit` writes hash-chained JSON Lines to a local file at `/var/log/mcpg/audit.log`.
- `plugins: []` — the flat plugin array starts empty. Add entries directly (no `entries:` wrapper) with `source.path:` references once you have a pre-staged plugin tree.
- Logs to file (not stderr); local Prometheus scrape on `127.0.0.1:9090`.

## What to change

| Field | Why |
|---|---|
| `governance.access.jwks.keys_json` | Inline your IdP's JWK Set. Or load from disk via the secret-provider plugin (`${cred://file/etc/mcpg/jwks.json}`). |
| `governance.access.jwks.issuer` / `audience` | Your internal IdP's issuer + the audience claim it issues for the gateway. |
| `governance.audit.sinks[0].config.path` | Writable audit log file your local collector watches. |
| `storage.providers[0].config.root` | Writable directory for content-store blobs. |
| `plugins[]` | Add entries pointing to your pre-staged `.zip` files. |

## Pre-staging plugins

The gateway loads cdylibs from disk via `source.path` — no network call. The recommended layout:

```
/opt/mcpg/plugins/
├── ip-allowlist-1.0.0.zip
├── identity-oidc-1.2.3.zip
└── …
```

Then in YAML — `plugins:` is a flat array, so each entry sits directly under it (no `entries:` wrapper, no `enabled:` toggle):

```yaml
plugins:
  - id: dev.mcpg.ip-allowlist
    class: tool_gate
    source:
      path: "/opt/mcpg/plugins/ip-allowlist-1.0.0.zip"
    signature:
      sha256: "<the digest of ip-allowlist-1.0.0.zip>"
  - id: dev.mcpg.identity.oidc
    class: identity_provider
    source:
      path: "/opt/mcpg/plugins/identity-oidc-1.2.3.zip"
    signature:
      sha256: "<the digest of identity-oidc-1.2.3.zip>"
```

The `signature.sha256` is optional but recommended — even on a sealed network, defence in depth catches a corrupted file before it loads. (Use the canonical snake_case `PluginClass` names: `tool_gate`, `identity_provider`, `audit_sink`, `transform`, `backend`, … — the legacy `identity` / `toolGate` forms are rejected at boot.)

## Filesystem layout (illustrative)

| Path | Purpose |
|---|---|
| `/opt/mcpg/plugins/` | Pre-staged plugin `.zip` artefacts (referenced by `plugins[].source.path`). |
| `/etc/mcpg/jwks.json` | Pre-staged JWK Set (referenced via secret-provider, not inline). |
| `/var/log/mcpg/audit.log` | Audit sink output. |
| `/var/log/mcpg/gateway.log` | Application log. |
| `/var/lib/mcpg/storage/` | Content-store blobs. |

Mount these as named volumes in your container runtime so the gateway pod can be replaced without losing audit history.

## Defence-in-depth notes

- Set `gateway.plugin_registry.default_registry: "internal-registry.invalid"` — if anyone accidentally adds an `oci:` entry, resolution fails fast against a recognisable hostname instead of reaching the public internet.
- Keep `gateway.plugin_registry.default_signature_policy: enforce` (the strict posture; the policy values are `disabled` / `warn` / `enforce`) — even on a sealed network, signing keys are part of your supply chain. Pin per-plugin verification keys via each entry's `signature.trusted_keys[]` (`{ id, pem }`), and override `signature.policy` per entry where needed.
