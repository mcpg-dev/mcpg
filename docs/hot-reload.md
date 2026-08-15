# MCPG Hot-Reload Coverage

What SIGHUP picks up vs what requires a restart. Keep this honest — operators rely on it to plan rolling upgrades vs in-place config rolls.

> Source of truth: `apps/gateway/src/app/mod.rs` — the `reload_config` function. Anything it rebuilds is reload-safe; anything it reads-but-discards or doesn't read at all needs a restart.

## How reload works

Three triggers, identical semantics:

```
# Operator shell:
$ kill -HUP $(pidof mcpg)

# Helm / Kustomize / CI / curl from any pod with admin creds:
$ curl -X POST http://gw:9090/admin/v1/config:reload

# Background file-watcher (operator-opt-in; default off):
#   gateway:
#     config_watch:
#       enabled: true
#       poll_interval_ms: 5000
# Save the YAML on disk; the next poll tick picks it up.
$ vim /etc/mcpg/mcpg.yaml
```

The admin endpoint and the file-watcher both run the same `reload_config` function as the SIGHUP handler — full `GatewayRuntime` rebuild, ArcSwap atomic swap, session store preserved, credential cache rebuilt fresh. Each replica reloads independently; there is no cluster broadcast (Kustomize / CI loops over pods explicitly when they want fleet-wide propagation; the file-watcher reacts on each replica because every pod sees its own ConfigMap mount).

The admin endpoint is auth-gated by the existing `admin.auth` block (`disabled` / `static_bearer` / `trusted_header`). It returns `200 OK` on success, `500` on failure (the response body's `error` carries the cause + the previous config remains live). The audit event is tagged `source: "admin_api"` for HTTP triggers, `source: "sighup"` for signal triggers, and `source: "file_watch"` for file-watcher triggers — auditors can distinguish the three. Every trigger increments `mcpg_admin_reload_triggers_total{trigger="<source>"}` AND the pre-existing `mcpg_config_reloads_total` so dashboards tracking aggregate reloads (across all triggers) keep working.

1. Re-loads the same `MCPG_CONFIG` source set (single file or layered via `:` / `;` separator).
2. Re-applies the same `MCPG_*` env-var overlay.
3. Builds a fresh `GatewayRuntime` with the new config.
4. Atomically swaps the runtime via `ArcSwap`. In-flight requests on the old runtime complete safely — they hold an `Arc` to the previous runtime until they finish.
5. Emits an audit event tagged `source: "sighup"` / `source: "admin_api"` / `source: "file_watch"` (one of three) so the rotation is on record.

The session store is held outside the runtime in `AppState` and is **not rebuilt**. Active sessions, their replay buffers, and their session-keyed quotas survive the reload.

---

## Reload-safe (SIGHUP picks up automatically)

| Block | What changes | Notes |
|---|---|---|
| `mcp.capabilities.{tools,prompts,resources,resource_templates}[]` | Tools / prompts / resources / resource templates appear, disappear, or change shape. | Triggers `notifications/{tools,prompts,resources}/list_changed` to active sessions. |
| `mcp.capabilities.*[].governance` | Trust floor + CEL `allow_if`. | Next dispatch sees the new policy. |
| `mcp.capabilities.*[].retry` | Retry attempts / backoff / status codes. | New rules apply on next call. |
| `mcp.capabilities.*[].watch` | Resource subscription strategy. | Active subscriptions are re-registered. |
| `governance.access.jwks`, `governance.access.oidc_oauth` | JWT verifier rebuilds — new audience / issuer / JWKS URL takes effect. | In-flight requests still validate against the old verifier; new requests use the new one. |
| `governance.access.resource_metadata` | RFC 9728 metadata served at `/.well-known/oauth-protected-resource`. | |
| `governance.policy.tool_access` | Default minimum trust + per-tool overrides + CEL gates. | Next dispatch evaluates the new policy. |
| `governance.policy.cache.{enabled, ttl_ms, max_entries}` | L1 decision cache. | Cache is cleared on reload. |
| `governance.audit.sinks[]`, `governance.audit.on_failure`, `governance.audit.required` | Audit channel config. | Active sinks are flushed + closed; new sinks open before any new event is emitted. |
| `governance.audit.emit_tool_call_{allowed,completed}` | Per-event emission toggles. | |
| `plugins[]` | Plugin set — adds, removes, config changes. Each entry is self-contained: `class:` selects its chain/slot (tool_gate / store / cache / secret_provider / config_provider / transport / policy_engine / …), and per-entry `config`, `granted_capabilities`, and `signature` ride on the same row. | Each plugin's `init()` runs; `shutdown()` runs on the old set after in-flight requests drain. The new set re-populates every per-class registry, so role/namespace bindings apply to subsequent lookups. |
| `plugins[].signature` | Per-entry integrity hash + verification policy + trusted Ed25519 keys. | Next plugin load consults the new keys. |
| `plugins[].granted_capabilities` | Per-entry typed host capability grants. | Re-evaluated on the new plugin set. |
| `gateway.plugin_registry` | OCI plugin-registry defaults (where to fetch artifacts, default signature policy). | |
| `storage.response_cache` | Gateway-managed LLM response cache. | |
| `observability.plugin_health_probe` | Plugin liveness prober tuning. | |
| `gateway.config_overlay[]` | `config_provider` URI list snapshotted at boot + deep-merged into the overlay. | |
| `cluster` (kind unchanged) | Coordinator config (URL, key prefix, pool size). | The cluster plugin re-initialises with new params. |
| `mcp.capabilities.tasks.store`, `mcp.configurations.{sessions,pipelines,subscriptions}.store`, `mcp.configurations.{delivery,cancellation}.bus` | Capability-state overrides. Default `kind: cluster` (inherits from the backend); override to `kind: memory` / `file` to pin in-process. | Switching from in-process to a clustered backend mid-flight loses local-only state — see "Caveats" below. |
| `mcp.capabilities.tasks.{default_ttl_ms, max_tasks_per_session, result_wait_ms, reaper_interval_ms}` | Task retention policy. | Applied to existing + new task entries. |
| `mcp.configurations.subscriptions.max_per_session` | Per-session subscription quota. | New subscriptions fail if the new (lower) cap is exceeded. |
| `feature_flags.debug_tools_enabled`, `debug.tools.*` | Debug capability surface — master switch (moved to `feature_flags` in Layout #6) + command/network probe profiles. | Tools appear / disappear from `tools/list`. |
| `observability.logs.level`, `observability.logs.sinks[]` | Log severity floor + sink fan-out. | Old log sinks flush + close; new sinks open. |
| `observability.{enabled,is_*_on}` master switches | Observability triad master toggle. | |
| `schema_registry` | Operator-named JSON Schema entries (used by `mcp.capabilities.*[].input_schema.$schema_ref`). | Re-fetched (file / URL / inline) at reload time. |
| `guardrails.{pre,post}_execution[]` | External HTTP guardrail hooks. | New CEL `trigger_cel` compiles on reload. |
| `governance.approvals.{signing_key_env, callback_base_url, callback_grace_ms}` | Human-approval signing key + callback. | Tokens issued by the old key still verify until they expire. |
| `webhook.{enabled, endpoints[], retry, circuit_breaker}` | Outbound webhook delivery. | |
| `nats.*`, `redis.*`, `kafka.*` | Connection-side config for binding-side clients. | Reconnects pick up the new params. |
| `storage.providers[]`, `storage.default` | Content-store provider registry. | Existing content URIs keep resolving against the previous provider until next dispatch. |
| `mcp.capabilities.*[].mcp_app_url` | Resource UI link (CEL-templatable). | Rendered per-request, so picked up immediately. |

---

## Restart-only (SIGHUP does NOT pick up)

| Field | Why it's restart-only | Workaround |
|---|---|---|
| `gateway.server.bind_address` | The TCP listener is bound at process start. | Drain the gateway behind the LB, restart, re-add. |
| `gateway.server.tls.*` | Same — TLS materials are loaded into the listener at boot. | Same. Plus most cert managers handle this with a sidecar that signals SIGTERM on rotate. |
| `gateway.server.transport` (http ↔ stdio) | Transport mode picks the entire serve path; can't swap mid-process. | Restart. |
| `gateway.server.mcp_path`, `gateway.server.health_path` | Routes are bound at boot; changing them mid-flight would break in-flight handles. | Restart. |
| `gateway.server.allowed_origins` | CORS layer is set up at boot. | Restart. |
| `gateway.server.replay_window_limit`, `gateway.server.session_idle_timeout_ms`, `gateway.server.max_sessions_per_tenant` | Read on reload but discarded — the session store is preserved across reloads, so its config is sticky. | Drain sessions (or restart) to apply. |
| `gateway.server.allow_private_backends` | Read at command-tool / network-probe build time, baked into the runtime config. | Restart. |
| `gateway.server.{request_timeout_ms, shutdown_timeout_ms, completion_rate_limit_per_sec, max_request_body_mb, server_ping_interval_ms, extra_resource_uri_schemes}` | Wired into HTTP-layer middleware at boot. | Restart. |
| `cluster.kind` | Switching backends (e.g. `redis` → `nats`) mid-flight is unsafe — in-flight cluster state would diverge. The `kind` field is read on reload but switching it produces undefined behavior. | Drain via the LB, restart. |
| `observability.metrics.sinks[]` | Metrics recorder bridge is attached once at boot via `attach_metrics_bridge` and not re-attached on reload. | Restart. |
| `observability.traces.{enabled, service_name, propagate_context, sinks[]}` | Telemetry bridge is attached once at boot via `attach_telemetry_bridge`. | Restart. |
| `gateway.admin.*` | The admin listener is started at boot. | Restart. |
| `gateway.control_plane.*` | CP attach handshake runs once at boot. | Restart. |

---

## Trigger: file-watch (Tier 5)

Background polling task. Disabled by default; flip on in YAML:

```yaml
gateway:
  config_watch:
    enabled: true                # default false
    poll_interval_ms: 5000       # default 5000; floor 1000 (clamped at spawn time)
```

The watcher is the third reload trigger and is most useful for:

- **Bare-metal systemd deployments** where SIGHUP works but operators want a no-signal flow (`vim /etc/mcpg/mcpg.yaml; :wq` and walk away).
- **K8s without the MCPG operator.** A plain `Deployment` + `ConfigMap` mount sees the new YAML appear under the symlink-swapped mount path within ~60s of `kubectl apply -f cm.yaml`; the file-watcher then picks it up on the next poll tick. The MCPG operator already does cluster-level propagation via `mcpg.dev/config-hash` annotation forcing rolling restart, so operator-managed clusters should leave file-watch off and use the operator's path.
- **Local dev iteration** — drop the interval to `1000`, hit save, see the audit-event log line within a second.

How it picks up changes:

- SHA-256 fingerprints each path in `state.config_paths` independently every `poll_interval_ms`. If any digest differs from the previous tick, the watcher calls `reload_config` (same path the SIGHUP handler + admin endpoint take).
- Polling reads the file's *contents* — it doesn't watch the inode — so vim/emacs's "write to temp + rename over original" is invisible to the watcher (it just sees new bytes). Same for K8s ConfigMap atomic-symlink-swaps: the watcher reads through the symlink chain and sees the new bytes whenever the swap lands.
- Reload errors keep the *old* fingerprint as the baseline, so the next poll retries the failed reload until the new YAML validates. Operators get back-pressure-style retry rather than one shot at a bad config — fix the typo, save again, watch the next-tick audit event.
- The audit event payload carries `paths_changed: [<list>]` + `duration_ms`. File-watch is the only trigger that can attribute the reload to specific files in the layered config set; auditors see exactly which file the watcher saw change.

Cost:

- One `read()` per `config_paths[]` entry per `poll_interval_ms`. At the default 5s + a typical 1–3-file layered set, that's <1 ms of disk I/O every 5s — invisible in profiles. Sub-second polling burns I/O for no operator-visible benefit; values below 1000 ms clamp to 1000 ms at spawn time and log a warning at config-validate time.
- No `inotify` / `notify` dep — the codebase deliberately uses polling for all in-process file watchers (OPA / Cedar / Casbin / workload-identity bundles). Polling handles editor-rename writes + K8s atomic swaps transparently; inode-watching APIs miss them unless re-watched on every event.

Not a SIGHUP replacement. Operators still want SIGHUP for "reload right now" — file-watch is bounded by `poll_interval_ms`, so worst-case latency is one full interval. The two coexist; flipping `config_watch.enabled` doesn't disable SIGHUP.

---

## Caveats

**Capability storage backend swaps.** Changing `mcp.capabilities.tasks.store` (or `mcp.configurations.{pipelines,subscriptions,sessions}.store` / etc.) from `kind: memory` to `kind: cluster` on a running gateway means in-flight tasks held in the in-process map are lost — they never make it to the cluster-backed primitive. For lossless backend swaps, drain the gateway, switch the YAML, then restart.

**MCPG_* env vars.** Env vars are resolved at config-load time and applied last in the merge order (after every YAML file). SIGHUP re-reads the env block, so a `kill -HUP` after `export MCPG_REDIS_URL=...` picks up the new value. But CEL `${env.X}` expressions inside YAML resolve once at load — they're then cached on the config struct. The next reload re-resolves them, so an env-var rotation reaches the gateway on SIGHUP.

**OIDC discovery cache.** The OIDC plugin runs its own JWKS refresh + introspection cache. SIGHUP rebuilds the resolver, which clears those caches. Operators rotating an IdP signing key can SIGHUP to force the next request to fetch the new JWKS instead of waiting for the per-provider `refresh_interval_secs`.

**In-flight requests during reload.** The old runtime stays alive (held by `Arc`) until in-flight requests complete. If a request is mid-pipeline when SIGHUP fires, it finishes against the OLD config. New requests arriving after the swap see the new config. There's no "kill the old runtime forcefully" knob — to force, drain at the LB then SIGHUP.

---

## Verifying a reload landed

After any of the three triggers, watch for:

- An audit event with `source: "sighup"` / `"admin_api"` / `"file_watch"` (the audit channel emits a config-rotated event automatically). The `file_watch` variant additionally carries `paths_changed: [...]` so auditors see which file in a layered set actually changed.
- A `tools/list_changed` notification on every active session if `mcp.capabilities.*[]` shape changed.
- Health endpoint stays at 200 throughout — no listener bounce.
- `mcpg config check` against the new file set should already have been green before the trigger.

```bash
# SIGHUP path:
$ mcpg config check config.yaml override.yaml \
    && kill -HUP $(pidof mcpg)

# Admin-API path (Helm / Kustomize / CI):
$ mcpg config check config.yaml override.yaml \
    && curl -fsS -X POST http://gw:9090/admin/v1/config:reload

# File-watch path (operator opted in via gateway.config_watch.enabled):
$ mcpg config check config.yaml override.yaml \
    && cp -f config.yaml /etc/mcpg/config.yaml
# wait one poll_interval_ms; watch the audit log for source: "file_watch"
```
