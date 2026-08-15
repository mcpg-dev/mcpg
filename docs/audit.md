# MCPG Audit

> Tamper-evident, fan-out compliance audit stream for every
> security-relevant event the gateway produces.
> Source: `libs/plugin-host/src/audit_events.rs`,
> `libs/plugin-host/src/registry.rs::emit_audit_event`,
> protocol spec §9.12.

The audit lane is a parallel, contractually-stronger sibling of the
observability triad (logs / metrics / traces). Events carry actor
identity, action, resource, and outcome — the four fields every
SOC2 / HIPAA / PCI-DSS / GDPR / ISO 27001 auditor expects to find in
a compliance log — plus a hash-chain pointer that lets consumers
detect tampering or gaps after the fact.

This document covers:

- [Why audit is a separate channel](#why-audit-is-a-separate-channel)
- [Compliance posture](#compliance-posture)
- [Event schema](#event-schema)
- [Event taxonomy](#event-taxonomy) — every event family the gateway emits
- [Architecture](#architecture) — fan-out, sinks, FailOpen vs FailClosed
- [Operator configuration](#operator-configuration)
- [Built-in sink](#built-in-sink) — `dev.mcpg.builtin.audit.local-file`
- [Compliance recipes](#compliance-recipes) — sample queries
- [Tamper detection](#tamper-detection)
- [Authoring guides](#authoring-guides) — for plugins and custom sinks
- [Operational concerns](#operational-concerns)
- [References](#references)

---

## Why audit is a separate channel

Logs, metrics, and traces share three properties that make them
**unsuitable** for compliance audit on their own:

| Property | Logs / Metrics / Traces | Audit |
|----------|-------------------------|-------|
| **Durability** | best-effort (may be sampled / dropped under backpressure) | contractually durable — sinks MUST acknowledge persistence |
| **Cardinality** | high (per-line / per-span) — hot paths emit thousands per second | curated — only events with compliance value |
| **Schema** | free-form `kv!{...}` fields | structured `(actor, action, resource, outcome)` with stable wire schema |
| **Retention** | days–weeks (cost-driven) | years (regulatory: SOC2 = 1y, PCI-DSS = 1y, HIPAA = 6y, GDPR = "as long as the data") |
| **Tamper-evidence** | none | hash-chained per sink; gaps are detectable |
| **Routing** | broad — all signals to all sinks | per-event optional redirection (route payment events to a PCI-segregated sink) |

When an auditor asks "show me every access to PHI in the last 30
days, by user, with the outcome", a metrics dashboard cannot answer
that question. Audit logs can.

MCPG enforces this separation at the type level — `AuditEvent` is
not a `tracing::Event` and the `AuditSink` trait is distinct from
`LogSink` / `MetricsSink` / `TelemetrySink`. Plugins or operators
who want to *also* see audit events on their log lane configure a
sink plugin that mirrors to both; the gateway never blurs the two
lanes itself.

---

## Compliance posture

MCPG ships with audit coverage that satisfies the **"every access
attempt logged"** requirement common to enterprise compliance
frameworks:

| Framework | Clause | What MCPG covers |
|-----------|--------|------------------|
| **SOC2** | CC6.1 / CC6.6 | every authorization decision (`mcpg.tool.call.{allowed,denied,challenged}`, `mcpg.resource.read.{success,denied}`, `mcpg.tool.call.access_denied`) |
| **SOC2 Type II** | transaction integrity | pipeline lifecycle (`mcpg.pipeline.{started,completed,failed}`) |
| **HIPAA** | 164.312(b) | every access attempt to identifiable resources (resource read, prompt get, tool call) |
| **PCI-DSS** | 10.2.1 / 10.2.2 / 10.2.5 | every charge / capture / refund / void / authorize / dispute (`mcpg.payment.{charged,failed}`) with `receipt_id`, `amount`, `currency`, `merchant_id` |
| **GDPR** | 30.1.b | records of processing activities — every `resources/read` carries actor identity + outcome + URI |
| **ISO 27001** | A.12.4 | event logging, log protection, administrator + operator logs (`mcpg.admin.*` + `mcpg.lifecycle.*`) |
| **AI governance** | (industry-specific) | `mcpg.sampling.requested` carries prompt hash + cost-attribution fields for every LLM call the gateway proxies |

The audit lane covers **47 distinct event-builder families** across
ten domains:

- Tool-call lifecycle (allow / deny / challenge / unknown / access denied / completed)
- Resource access (read / list / subscribe / unsubscribe)
- Prompt access (get / list / not found / denied)
- LLM sampling (requested with prompt hash + FinOps fields)
- Payment processing (charged / failed with PCI-DSS-shaped receipt fields)
- Pipeline transactions (started / completed / failed)
- Session lifecycle (opened / terminated / initialized acked / handshake bookends)
- Cluster events (member join / leave / health change / leader changed)
- Approval workflow (requested / granted / denied / expired)
- Plugin chain (transform applied / catalog filtered / chain summary in tool.call.*)

See [Event taxonomy](#event-taxonomy) for the complete list with
field semantics.

---

## Event schema

Every audit event is a `mcpg_plugin_protocol::audit::AuditEvent`
with a fixed wire schema:

```rust
pub struct AuditEvent {
    pub event_id:        String,           // UUIDv7 — time-sortable
    pub occurred_at:     String,           // RFC 3339 UTC, ms precision
    pub actor:           PluginIdentity,   // who triggered the event
    pub action:          String,           // "mcpg.tool.call.allowed", "mcpg.payment.charged", …
    pub resource:        Option<String>,   // "tool://payments.charge", "session://abc-123", …
    pub outcome:         AuditOutcome,     // Success / Failure / Partial / Denied
    pub request_id:      Option<String>,   // correlate with the originating request
    pub node_id:         Option<String>,   // gateway node that emitted (cluster only)
    pub details:         serde_json::Value,// action-specific structured payload
    pub prev_event_hash: Option<String>,   // sink-side chain pointer (§Tamper detection)
}
```

### Field semantics

#### `event_id`
UUIDv7 — chronologically sortable. Auditors replaying the audit
stream in `event_id` order get the events in roughly the order they
were emitted (subject to occurred_at jitter under heavy concurrency,
typically <100 µs).

#### `occurred_at`
RFC 3339 UTC with millisecond precision (`2026-05-04T12:34:56.789Z`).
The wall clock of the gateway node that emitted; cluster deployments
SHOULD run NTP. Skew tolerance for `occurred_at` ordering: 5 minutes.

#### `actor: PluginIdentity`
The "who" of the event:

```rust
pub struct PluginIdentity {
    pub kind:          String,                          // "verified", "service", "system", "anonymous", "http_header", …
    pub trust_level:   String,                          // "verified", "service", "anonymous", "system"
    pub subject_id:    Option<String>,                  // user / service principal id (e.g., "alice@corp", "svc-billing")
    pub auth_provider: Option<String>,                  // resolver plugin id ("dev.mcpg.identity.oidc")
    pub issuer:        Option<String>,                  // JWT iss / OIDC issuer / SPIFFE trust domain
    pub roles:         Vec<String>,                     // RBAC role labels
    pub groups:        Vec<String>,                     // group memberships
    pub scopes:        Vec<String>,                     // OAuth scopes
    pub attributes:    BTreeMap<String, String>,        // custom attributes from the resolver
}
```

System-emitted events (gateway lifecycle, cluster events, config
reload) carry an actor with `kind = "system"` and
`subject_id = "mcpg-gateway"`. Anonymous client requests carry
`kind = "anonymous"` until an identity plugin elevates them.

#### `action`
Stable string identifier in dotted reverse-domain form:
`mcpg.<domain>.<verb>`. Action names are append-only — adding
new ones is a minor version bump, renaming is a major. The full
list is the [Event taxonomy](#event-taxonomy) below.

#### `resource`
URI of the resource the event acted on. Conventions:

| Scheme | Used by |
|--------|---------|
| `tool://<name>` | tool-call events |
| `resource://<uri>` | resources/read events |
| `prompt://<name>` | prompts/get events |
| `session://<id>` | session lifecycle |
| `pipeline://<profile>` | pipeline events |
| `payment://<receipt_id>` | payment events |
| `backend://<kind>/<profile>` | backend execution |
| `plugin://<id>` | transform / credential events |
| `catalog://<kind>` | catalog filter, list, list-changed broadcast |
| `approval://<approval_id>` | approval lifecycle |
| `node://<node_id>` | cluster member events |
| `leadership://<role>` | cluster leader events |
| `request://<id>` | cancellation, progress |
| `http_route://<plugin_id>/<entity>` | HTTP-route plugin dispatch |
| `config://gateway` | config reload |
| `system://*` | gateway-internal (ping, etc.) |

`None` is reserved for events with no resource concept (gateway
boot / shutdown).

#### `outcome: AuditOutcome`
- `Success` — the access succeeded.
- `Denied` — a policy explicitly denied (auth fail, gate deny, etc.).
- `Failure` — backend / system failure (5xx, plugin error, timeout).
- `Partial` — challenged / would-deny in shadow mode / payment requires-step-up.

The distinction matters: SOC2 / HIPAA auditors need to separate
"the system rejected access" (Denied — operator policy worked) from
"the system failed" (Failure — backend broke).

#### `request_id`
The originating `Mcp-Request-Id` header (or sampled UUID) so audit
events stitch back to the request lifecycle. Always present on
request-scoped events; `None` on system events.

#### `details`
Free-form JSON envelope carrying action-specific structured fields.
The taxonomy below enumerates the fields each event sets. Builder
functions in `libs/plugin-host/src/audit_events.rs` are the
authoritative schema.

#### `prev_event_hash`
Set by the **sink**, not by the builder. The gateway emits with
`prev_event_hash: None`; each sink that supports chaining computes
`SHA-256(canonical(event_with_prev=prev_hash))` and writes that as
the chain pointer when persisting. The `dev.mcpg.builtin.audit.local-file` built-in
file sink does this; off-node sinks (CloudTrail, Datadog) typically
record their own append sequence.

---

## Event taxonomy

The 47 event-builder families currently emitted by the gateway,
grouped by domain. **Action** is the wire `event.action` value;
**resource** is the URI scheme; **outcomes** lists which `outcome`
values the builder can produce.

### Tool calls

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.tool.call.allowed` | pre-dispatch tool-gate chain admitted the call | `tool://<name>` | Success |
| `mcpg.tool.call.completed` | post-dispatch chain admitted the result | `tool://<name>` | Success |
| `mcpg.tool.call.denied` | a tool-gate plugin returned `Deny` | `tool://<name>` | Denied |
| `mcpg.tool.call.challenged` | a tool-gate plugin returned `Challenge` | `tool://<name>` | Partial |
| `mcpg.tool.call.unknown` | client called a tool name that isn't registered | `tool://<name>` (truncated) | Failure |
| `mcpg.tool.call.access_denied` | trust-level / access policy rejected before tool-gate ran | `tool://<name>` | Denied |

`tool.call.allowed` and `tool.call.completed` carry `details.chain[]`
— an array of `{plugin_id, phase, decision, latency_ms}` per
plugin in evaluation order, so auditors can replay the entire gate
chain per call.

### Resources & prompts & catalog

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.resource.read.success` | `resources/read` returned bytes | `resource://<uri>` | Success |
| `mcpg.resource.read.denied` | `resources/read` was policy-rejected | `resource://<uri>` | Denied |
| `mcpg.resource.read.not_found` | `resources/read` URI is unknown | `resource://<uri>` | Failure |
| `mcpg.resource.subscribe` | `resources/subscribe` accepted | `resource://<uri>` | Success |
| `mcpg.resource.unsubscribe` | `resources/unsubscribe` accepted | `resource://<uri>` | Success |
| `mcpg.prompt.get.success` | `prompts/get` returned a prompt | `prompt://<name>` | Success |
| `mcpg.prompt.get.denied` | `prompts/get` was policy-rejected | `prompt://<name>` | Denied |
| `mcpg.prompt.get.not_found` | `prompts/get` name is unknown | `prompt://<name>` | Failure |
| `mcpg.tool.list` / `mcpg.prompt.list` / `mcpg.resource.list` / `mcpg.resource_template.list` | enumeration calls | `catalog://<kind>` | Success |
| `mcpg.catalog.filtered` | catalog provider chain hid one or more tools | `catalog://tool` | Success |
| `mcpg.list.changed_broadcast` | server pushed `notifications/{tools,prompts,resources}/list_changed` after reload | `catalog://<kind>` | Success |

`resource.read.success` carries `details.bytes` for a coarse access
volume signal. `catalog.filtered` carries `details.hidden[]` — an
array of `{name, plugin_id}` pairs for every tool the chain
removed, with the *first* provider to drop a tool getting attribution.

### LLM sampling

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.sampling.requested` | gateway-proxied `sampling/createMessage` | `sampling://<model_hint>` | Success |

Carries `details.prompt_hash` (BLAKE3 of canonical messages — full
prompt never lands on the audit lane), `details.message_count`,
`details.max_tokens`, `details.model_hint`,
`details.include_context`. AI-governance + cost-attribution
auditors run `SUM(max_tokens) GROUP BY actor.subject_id` on this
event.

### Sessions & auth

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.session.opened` | `initialize` succeeded | `session://<id>` | Success |
| `mcpg.session.terminated` | session evicted (idle / explicit close / quota) | `session://<id>` | Success |
| `mcpg.session.initialized_acked` | client sent `notifications/initialized` | `session://<id>` | Success |
| `mcpg.auth.failed` | identity-resolution failure (invalid JWT / mTLS / OIDC mismatch) | `auth://<provider>` | Failure / Denied |

`session.terminated` carries `details.duration_ms` and
`details.reason` so auditors can compute average session lifetimes
and detect anomalous early evictions.

### Pipelines

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.pipeline.started` | multi-step pipeline begins | `pipeline://<profile>` | Success |
| `mcpg.pipeline.completed` | pipeline reached terminal Complete | `pipeline://<profile>` | Success |
| `mcpg.pipeline.failed` | pipeline reached terminal Failure | `pipeline://<profile>` | Failure |

Started + completed/failed bookend the transaction. Each carries
`details.pipeline_id` so auditors can answer "did all 5 steps run,
or did step 3 fail and step 1+2 not roll back?".

### Pipeline server-initiated requests

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.elicitation.requested` | pipeline suspended on `elicitation/create` | `elicitation://<server_request_id>` | Success |
| `mcpg.elicitation.completed` | client posted `notifications/elicitation/complete` | `elicitation://<server_request_id>` | Success / Denied / Failure |
| `mcpg.roots.requested` | pipeline suspended on `roots/list` | `roots://<server_request_id>` | Success |
| `mcpg.completion.requested` | client called `completion/complete` | `completion://<ref_name>` | Success |
| `mcpg.operation.cancelled` | `notifications/cancelled` received | `request://<cancelled_request_id>` | Success |

`elicitation.completed` outcome maps from `user_action`:
`accept → Success`, `decline / cancel → Denied`, `other → Failure`.

### Payments

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.payment.charged` | payment plugin returned Allow with receipt metadata | `payment://<receipt_id>` | Success |
| `mcpg.payment.failed` | payment plugin returned Deny / Challenge | `payment://<receipt_id>` (or `unknown`) | Denied |

`details.receipt` projects the well-known
`org.paymentauth/receipt` envelope (reference, status, amount,
currency, recipient, network) so auditors get the PCI-DSS-grade
trinity (`receipt_id`, `amount`, `currency`) without parsing
plugin-specific metadata.

Plugin-id prefix matching: `dev.mcpg.payment.{mpp,x402,ucp,acp}`
trigger this event in addition to the generic
`mcpg.tool.call.{allowed,denied}`.

### Backends & transforms & HTTP routes

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.backend.executed` | backend dispatch succeeded (NATS / Kafka / SQL / webhook / LLM) | `backend://<kind>/<profile>` | Success |
| `mcpg.backend.failed` | backend dispatch failed | `backend://<kind>/<profile>` | Failure |
| `mcpg.transform.applied` | transform plugin returned `Modified` (pre or post) | `plugin://<plugin_id>` | Success |
| `mcpg.http_route.dispatched` | HTTP-route plugin handled an override request | `http_route://<plugin_id>/<entity>` | Success / Denied / Failure |

`backend.executed` / `.failed` carry `duration_ms`,
`payload_bytes`, `response_bytes`. `transform.applied` carries
`pre_hash` + `post_hash` (BLAKE3 of canonical JSON; auditors
correlate against the call-logger lane for plaintext replay).
`http_route.dispatched` outcome derives from HTTP status: 2xx →
Success, 4xx → Denied, 5xx → Failure.

### Watch strategies

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.watch.fired` | watch strategy detected an upstream change | `resource://<uri>` | Success |

`details.strategy` is `poll` / `webhook` / `plugin`;
`details.plugin_kind` is set for the plugin variant
(`nats_topic`, `kafka_topic`, …); `details.subscriber_count`
records how many subscribers received the notification (zero is
still emitted — the change is audit-worthy even if no one was
listening).

### Cluster events

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.cluster.member_joined` | `PeerEvent::Joined` from `watch_peers` | `node://<node_id>` | Success |
| `mcpg.cluster.member_left` | `PeerEvent::Left` from `watch_peers` | `node://<node_id>` | Success |
| `mcpg.cluster.member_health_changed` | `PeerEvent::HealthChanged` from `watch_peers` | `node://<node_id>` | Success |
| `mcpg.cluster.leader_changed` | `acquire_leadership` Ok | `leadership://<role>` | Success |
| `mcpg.cluster.leader_acquire_failed` | `acquire_leadership` Err | `leadership://<role>` | Failure |

Member events come from a single centralized subscriber spawned at
boot — fan-out to one consumer ensures no per-subscriber
duplicates. Leader events come from the cluster_metering wrapper.

### Approvals

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.approval.requested` | gateway opened a `PendingApproval` | `approval://<approval_id>` | Success |
| `mcpg.approval.granted` | operator approved | `approval://<approval_id>` | Success |
| `mcpg.approval.denied` | operator denied | `approval://<approval_id>` | Denied |
| `mcpg.approval.expired` | deadline elapsed without resolution | `approval://<approval_id>` | Failure |

`expired` is **Failure** (not Denied) so auditors can distinguish
"no operator decision was made" from "operator rejected" — different
SLA breach categories.

### Credentials & secrets & config

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.credential.issued` | credential resolver minted a credential | `plugin://<plugin_id>` | Success |
| `mcpg.credential.failed` | credential issuance / unknown plugin | `plugin://<plugin_id>` | Failure |
| `mcpg.secret.resolved` | `${scheme://path}` expanded to a secret value | `<secret_ref>` | Success |
| `mcpg.secret.failed` | secret resolution failed | `<secret_ref>` | Failure |
| `mcpg.config.reloaded` | SIGHUP / Control-Plane config reload completed | `config://gateway` | Success / Failure |

Secret events carry the `secret_ref` — the *location* of the secret,
not its value. Plaintext never hits the audit lane.

### Admin & lifecycle

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.admin.plugin_*` | admin API enabled / disabled / drained a plugin | `plugin://<id>` | Success / Denied |
| `mcpg.lifecycle.gateway_started` | gateway boot completed | `None` | Success |
| `mcpg.lifecycle.gateway_stopping` | shutdown signal received | `None` | Success |
| `mcpg.lifecycle.plugin_loaded` | plugin registered | `plugin://<id>` | Success |
| `mcpg.lifecycle.plugin_unloaded` | plugin unregistered | `plugin://<id>` | Success |

### Low-volume protocol bookends

| Action | Trigger | Resource | Outcomes |
|--------|---------|----------|----------|
| `mcpg.ping.received` | client `ping` keepalive | `system://ping` | Success |
| `mcpg.progress.notified` | gateway emitted `notifications/progress` | `request://<progress_token>` | Success |
| `mcpg.logging.level_set` | client adjusted log verbosity via `logging/setLevel` | `session://<id>` | Success |

These are emitted at typical rates that won't drown a SIEM; high-
volume installations should route them to a dedicated sink with
shorter retention via the per-event sink redirection mechanism
(below).

---

## Architecture

### Fan-out

```
┌─────────────────────┐                ┌──────────────────────┐
│  emit site (e.g.    │  AuditEvent    │ PluginRegistry       │
│  runtime/mod.rs,    │ ─────────────► │ ::emit_audit_event() │
│  registry.rs,       │                └──────────────────────┘
│  approvals.rs)      │                          │
└─────────────────────┘                          │ fan-out (one task per sink)
                                                 │
                            ┌────────────────────┼────────────────────┐
                            ▼                    ▼                    ▼
                     ┌────────────┐       ┌────────────┐       ┌────────────┐
                     │ AuditSink  │       │ AuditSink  │       │ AuditSink  │
                     │ (file)     │       │ (CloudTrail│       │ (operator's│
                     └────────────┘       │  webhook)  │       │  SIEM)     │
                                          └────────────┘       └────────────┘
```

The registry's `emit_audit_event(&AuditEvent) -> Vec<AuditEmitResult>`
calls every registered sink concurrently and returns one
`AuditEmitResult` per sink. The hot-path emit site does not block
on individual sinks — failure handling is governed by the
`on_failure` policy below.

### Sink trait

```rust
#[async_trait]
pub trait AuditSink: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Persist a single event. MUST durably persist before
    /// returning Ok. May block on I/O; the gateway awaits.
    async fn emit(
        &self,
        event: &AuditEvent,
    ) -> Result<AuditReceipt, AuditError>;

    /// Flush any in-flight buffered events. Called at gateway
    /// shutdown and on reload.
    async fn flush(&self, timeout: Duration) -> Result<(), AuditError>;

    async fn shutdown(&self) {}
}

pub struct AuditReceipt {
    pub sink_id:      String,         // which sink acknowledged
    pub persisted_at: DateTime<Utc>,
    pub durable_hash: String,         // SHA-256 of event + prev_event_hash
}
```

Sinks are **fan-out** plugins: every event reaches every sink (subject
to per-event redirection — see `routing` below). The `AuditReceipt`
returned to the registry feeds the metric
`mcpg_audit_emits_total{sink_id, outcome}` and lets the gateway
detect partial failure.

### `on_failure` policy

```yaml
governance:
  audit:
    on_failure: fail_closed   # default — refuse to serve if any sink failed
```

| Value | Behavior |
|-------|----------|
| `fail_closed` (default) | the registry's emit returns an enforcement error; the calling site (tool-gate chain, etc.) treats it as a Deny. Highest-strength compliance posture: a sink outage stops traffic. |
| `fail_open` | failures are metered (`mcpg_audit_emits_total{outcome=fail}`) and logged; traffic continues. Use only in dev / CI. |

The enforcement hookup uses
`PluginRegistry::emit_audit_event_enforced(&event, policy)` at
strict sites (see `tool-gate` chain emission for the canonical
example). Sites that invoke `emit_audit_event(&event)` without
the enforced wrapper are best-effort regardless of config.

### Per-event sink redirection (Phase 6c-23 / 6c-26)

Each sink can declare `routing` filters in the operator config so
specific event families bypass sinks they don't belong on:

```yaml
governance:
  audit:
    sinks:
      - kind: dev.mcpg.builtin.audit.local-file
        config: { path: /var/log/mcpg/audit.jsonl }
      - kind: dev.acme.pci-vault           # PCI-segregated SIEM
        config: { url: https://siem.acme.internal }
        routing:
          allow_actions: ["mcpg.payment.*"]    # only payment events
      - kind: dev.acme.high-volume
        config: { url: https://archive.acme.internal }
        routing:
          allow_actions: ["mcpg.ping.received", "mcpg.progress.notified"]
          # high-volume bookends to a separate retention tier
```

`allow_actions` matches the event's `action` field with simple glob
semantics; `deny_actions` is the inverse filter for "everything
except this list". When both are set, deny wins.

---

## Operator configuration

The full audit config block lives under `governance.audit` (Layout
D'' P1 — pre-D'' it was at top-level `audit:` and routed through
the plugin registry; D'' co-locates it with the other governance
peers `access` / `policy` / `approvals`):

```yaml
governance:
  audit:
    # Master toggle. false → no audit sinks loaded, no events
    # emitted. Set false ONLY in dev/CI where compliance is out
    # of scope.
    enabled: true                   # default

    # Refuse to start unless ≥1 audit sink is serving after plugin
    # registration. Ignored when enabled: false.
    required: true                  # default

    # Per-event emit-failure policy. See "on_failure policy" above.
    on_failure: fail_closed         # fail_closed | fail_open

    # Two operator-tunable allow-list events. Default true (every
    # tool call on record); high-volume / low-compliance deploys
    # may flip to false. Deny + challenge events ALWAYS emit.
    emit_tool_call_allowed:   true
    emit_tool_call_completed: true

    # Sink fan-out. Each entry's `kind` is a plugin id resolved
    # against the audit_sink entities in the plugin registry.
    sinks:
      - kind: dev.mcpg.builtin.audit.local-file   # built-in JSONL appender
        config:
          path: /var/log/mcpg/audit.jsonl
          format: json              # json | jsonl
          # No rotation knob: the sink never rotates or size-caps
          # `path`. Rotate it externally (logrotate); the sink
          # follows the rotated path on its own. See "Retention".

      # Off-node sink. Operators SHOULD register at least one for
      # production — single-node file persistence is not enough
      # when the node is the thing being audited.
      # - kind: dev.acme.cloudtrail
      #   config: { region: us-east-1, log_group: mcpg-prod }
      #
      # - kind: dev.acme.datadog-audit
      #   config: { api_key: ${secret://vault/datadog/key} }
```

The default sink is `dev.mcpg.builtin.audit.local-file` writing JSONL to a
gateway-managed path. **Production deployments SHOULD register a
multi-node or off-node sink** — the local file is the audit-of-
last-resort and a node compromise can tamper with its own log.

---

## Sinks that ship with MCPG

Two distinct components, easily confused. `dev.mcpg.builtin.audit.local-file`
is compiled into the gateway and is the default sink; it hash-chains and
does not redact. `dev.mcpg.audit` below is a cdylib you load like any other
plugin; it redacts unconditionally and does not chain.

### `dev.mcpg.audit`

Single cdylib plugin that ships with MCPG. Implements an audit-sink
with three configurable backend modes:

| Backend | Config | Use case |
|---------|--------|----------|
| **stdout** | `output: stdout` | dev runs, container log scraping (k8s, ECS, fluentd) |
| **file** | `output: { file: /path/to/audit.jsonl }` | single-node compliance |
| **both** | `output: both` + `file:` | dev + dual-write |

```yaml
governance:
  audit:
    sinks:
      - kind: dev.mcpg.audit
        config: { sink: { kind: file, path: /var/log/mcpg/audit.jsonl } }
```

Each event is serialized to canonical JSON and emitted as a single
line (JSONL). The file backend uses `O_APPEND` for crash-safe
append; the stdout backend takes a `stdout().lock()` guard per line
so concurrent emits never interleave.

**Tamper detection (this sink).** `prev_event_hash` is filled by the
sink with `SHA-256(canonical(prev_event))`. A consumer walking the
file in order can detect any insertion / deletion / mutation by
re-hashing the previous line and comparing against the next line's
`prev_event_hash`. The first event in the chain has
`prev_event_hash: null`.

### Recommended off-node sinks (third-party / operator)

These are NOT shipped — operators install them as dev.acme.*
plugins, using the [Sink author guide](#sink-author-guide):

- **`dev.acme.cloudtrail`** — AWS CloudTrail export
- **`dev.acme.datadog-audit`** — Datadog Audit Logs
- **`dev.acme.splunk-hec`** — Splunk HEC
- **`dev.acme.elastic`** — Elasticsearch index
- **`dev.acme.kafka`** — Kafka topic for downstream pipelines
- **`dev.acme.pci-vault`** — PCI-segregated SIEM with extra encryption
- **`dev.acme.s3-archive`** — S3 immutable bucket with object-lock

---

## Compliance recipes

Sample queries operators run against the audit JSONL stream
(answers each compliance ask). Examples use `jq`; SIEM equivalents
follow the same shape.

### "Every tool call by user X in the last 24h"
*(SOC2 CC6.1 — every authorization decision)*

```bash
jq -c 'select(.actor.subject_id == "alice@corp"
           and .action | startswith("mcpg.tool.call."))' \
  /var/log/mcpg/audit.jsonl
```

### "Every PHI access in the last 30 days"
*(HIPAA 164.312(b))*

```bash
jq -c 'select(.action == "mcpg.resource.read.success"
           and .resource | test("^resource://patient/"))' \
  /var/log/mcpg/audit.jsonl
```

### "Every payment > $1k that succeeded last quarter"
*(PCI-DSS 10.2.5)*

```bash
jq -c 'select(.action == "mcpg.payment.charged"
           and (.details.receipt.amount | tonumber) >= 100000)' \
  /var/log/mcpg/audit.jsonl
```

### "All identity-resolution failures by provider"
*(SOC2 CC6.6 — failed-login dashboards)*

```bash
jq -r 'select(.action == "mcpg.auth.failed")
       | "\(.actor.auth_provider // "unknown")\t\(.details.reason // "")"' \
  /var/log/mcpg/audit.jsonl | sort | uniq -c
```

### "Did Alice see tool X in tools/list?"
*(catalog filter audit)*

```bash
jq -c 'select(.action == "mcpg.catalog.filtered"
           and .actor.subject_id == "alice@corp"
           and (.details.hidden[]? | .name == "admin.delete"))' \
  /var/log/mcpg/audit.jsonl
```

### "Every operator approval decision with the approver"
*(SOC2 ITGC)*

```bash
jq -c 'select(.action | startswith("mcpg.approval."))
       | {action, approval_id: .details.approval_id,
          approver: .details.approver_subject,
          tool: .details.tool_name,
          reason: .details.reason}' \
  /var/log/mcpg/audit.jsonl
```

### "Pipeline transactions that started but never reached terminal"
*(SOC2 transaction integrity)*

```bash
jq -c 'select(.action == "mcpg.pipeline.started")
       | .details.pipeline_id' /var/log/mcpg/audit.jsonl \
  > /tmp/started.txt

jq -c 'select(.action == "mcpg.pipeline.completed"
           or .action == "mcpg.pipeline.failed")
       | .details.pipeline_id' /var/log/mcpg/audit.jsonl \
  > /tmp/terminated.txt

comm -23 <(sort /tmp/started.txt) <(sort /tmp/terminated.txt)
```

### "Cluster leadership flips in the last 7 days"
*(SRE incident reconstruction)*

```bash
jq -c 'select(.action == "mcpg.cluster.leader_changed")
       | {at: .occurred_at, role: .details.role, plugin: .details.plugin_id}' \
  /var/log/mcpg/audit.jsonl
```

---

## Tamper detection

Each sink implementation chooses how to chain events. The built-in
`dev.mcpg.builtin.audit.local-file` sink chains with SHA-256:

```
event[0]: {..., prev_event_hash: null,                   event_id: e0, …}
event[1]: {..., prev_event_hash: SHA-256(canonical(e0)), event_id: e1, …}
event[2]: {..., prev_event_hash: SHA-256(canonical(e1)), event_id: e2, …}
```

A consumer can verify the chain with:

```python
import hashlib, json

prev = None
with open("/var/log/mcpg/audit.jsonl", "rb") as f:
    for i, raw in enumerate(f):
        line = raw.rstrip(b"\n")              # the exact bytes that were hashed
        ev = json.loads(line)
        assert ev.get("prev_event_hash") == prev, f"chain break at event {i}"
        prev = hashlib.sha256(line).hexdigest()   # bare hex over the raw bytes
print("chain intact")
```

Hash the raw line bytes rather than a re-serialised object: parsing to a
dict and dumping it again reorders keys, and the stored hashes are bare
hex, not `sha256:`-prefixed. The chain belongs to the writer rather than
to any one file, so a log that has been rotated verifies when its
segments are read in write order (`cat audit.jsonl.2 audit.jsonl.1
audit.jsonl`).

A break detected by this walk means: an event was inserted, deleted,
or mutated. The hash by itself doesn't prevent rollback (an attacker
who controls the file can replace it with a shorter prefix), so
production deployments SHOULD pair the local sink with an
append-only off-node sink (S3 with object-lock, CloudTrail, etc.)
that the gateway node has no permission to delete from.

The integration test suite includes
`apps/gateway/tests/audit_chain_concurrency.rs` and
`apps/gateway/tests/audit_on_failure_enforcement.rs` which validate
chain integrity under concurrent emission and the FailClosed policy.

---

## Authoring guides

### Plugin author guide

Most plugins do not emit audit events directly — the gateway runtime
emits on their behalf at the canonical lifecycle points (tool-gate
chain → `tool.call.*`, transform plugin → `transform.applied`,
catalog plugin → `catalog.filtered`, etc.). A plugin that needs a
domain-specific audit event uses the host's audit-emit hook
(typically by returning metadata that the runtime then surfaces as
an audit event).

If your plugin genuinely owns an event nobody else can emit
(uncommon — examples include a custom approval workflow plugin or
a federated identity provider), expose it through a host-side
metering wrapper following the pattern in
`libs/plugin-host/src/credential_metering.rs` /
`libs/plugin-host/src/secret_metering.rs`. The wrapper holds the
`Arc<PluginRegistry>` and emits inline at the trait boundary; the
plugin code itself stays audit-free.

### Sink author guide

Implement `mcpg_plugin_protocol::audit::AuditSink` and declare your
plugin with the SDK macro:

```rust
use mcpg_plugin_sdk::declare_audit_sink_plugin;

declare_audit_sink_plugin!(
    id    = "dev.acme.datadog-audit",
    sink  = MyDatadogSink,
);

pub struct MyDatadogSink { /* ... */ }

#[async_trait]
impl AuditSink for MyDatadogSink {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
        // 1. Serialize canonical JSON
        let body = serde_json::to_vec(event)
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        // 2. POST to your durable backend; await ack BEFORE returning Ok
        let durable_hash = self.send_and_ack(body).await?;
        Ok(AuditReceipt {
            sink_id:      self.manifest.id.clone(),
            persisted_at: chrono::Utc::now(),
            durable_hash,
        })
    }

    async fn flush(&self, timeout: Duration) -> Result<(), AuditError> {
        // Drain in-flight buffered events. Best-effort — the
        // gateway calls this on shutdown.
        self.drain(timeout).await
    }
}
```

**Durability contract.** `emit` MUST NOT return Ok until the event
is durably persisted at the sink's contracted durability tier (disk
sync / network ack from a durable backend). Returning Ok prematurely
breaks the SOC2 / PCI-DSS expectation that "if the gateway accepted
the request, the audit record exists."

**Backpressure handling.** If your sink is overloaded, return
`AuditError::Throttled`. The gateway records
`mcpg_audit_emits_total{outcome=throttled}` and applies the
`on_failure` policy. Do NOT silently drop events.

**Hash chaining (optional).** Sinks may chain events with their own
sequence number / hash; if you do, fill the
`AuditReceipt::durable_hash` with that chain pointer so the gateway
can include it in metrics and the operator's `mcpg ctl audit verify`
output.

---

## Operational concerns

### Volume estimation

Approximate emission rate at typical workloads (per session-second):

| Workload | Events/s |
|----------|----------|
| Idle session | ~0.01 (ping every ~30s) |
| Active tool calls (1 RPS) | ~3 (allowed + chain entries + completed + backend executed) |
| Pipeline-heavy (1 RPS) | ~6–8 (started, per-step, completed) |
| LLM streaming (1 RPS, 50 chunks) | ~50 (one progress event per chunk if `progress` is on) |

For a 1k-RPS gateway, expect **~3k–8k audit events/sec** sustained
on the all-default config. JSONL line size averages 800 bytes, so
~6 MB/s sustained for the file sink. Plan retention budget
accordingly: one year at 6 MB/s = ~180 TB raw, ~50 TB compressed
at zstd-3.

### Retention

Regulatory minimums (consult your auditor — these are pointers, not
authoritative legal advice):

| Framework | Retention |
|-----------|-----------|
| SOC2 Type II | 1 year (audit observation period) |
| PCI-DSS 10.7 | 1 year, with immediately retrievable last 90 days |
| HIPAA 164.530(j) | 6 years |
| GDPR | "as long as the underlying data" — variable |
| ISO 27001 A.18.1.3 | "in line with retention policy" — variable |

The built-in `dev.mcpg.builtin.audit.local-file` sink does not rotate,
size-cap, or expire — operators pair it with `logrotate` or a similar
tool, OR (recommended) route to an off-node sink that handles retention
natively (S3 lifecycle, CloudTrail data retention, Datadog).

Rotation needs no `postrotate` hook and no signal. The sink holds one
long-lived append handle for throughput, and at each write batch checks
whether the configured path still resolves to that same file; when it
does not — `logrotate`'s default rename-then-create, or the file having
been rotated away entirely — the sink reopens the path append-only
(creating it if absent) and continues there. Without that check the
handle would stay bound to the renamed inode and, once it was compressed
away, to an unlinked one: writes would keep succeeding while the records
went nowhere.

One consequence to plan retention around: **the hash chain continues
across the rotation boundary.** Only the first file ever written begins
at genesis (`prev_event_hash: null`); a rotated file starts mid-chain and
is verifiable only against its predecessor's last line. Verify the
rotated files concatenated in write order, and keep the set intact (or
archive to an append-only off-node sink) if the chain has to be provable
end to end.

### Redaction

Some audit events would, by their nature, embed sensitive data in
`details` or `resource`:

- `mcpg.resource.read.*` — `resource://patient/<email>/profile`
  embeds PII in the URI.
- `mcpg.sampling.requested` — full prompts CAN'T be on the audit
  lane; the builder uses `prompt_hash: blake3:<hex>` instead.
- `mcpg.auth.failed` — `details.reason` may include user-typed
  data.

The `dev.mcpg.builtin.audit.local-file` sink does not redact — operators wanting
field-level redaction install a redaction-aware sink plugin or
pre-process the JSONL stream.

### Multi-region replication

For deployments where the audit log itself is in scope (SOC2 audit
of the audit system), operators register at least two off-node
sinks targeting different regions / providers:

```yaml
governance:
  audit:
    sinks:
      - kind: dev.mcpg.builtin.audit.local-file   # local file (last-resort)
        config: { path: /var/log/mcpg/audit.jsonl }
      - kind: dev.acme.s3-us-east-1       # primary region
        config: { bucket: mcpg-audit-us, object_lock: true }
      - kind: dev.acme.s3-eu-west-1       # secondary region
        config: { bucket: mcpg-audit-eu, object_lock: true }
```

Fan-out semantics: every event reaches every sink. The `on_failure:
fail_closed` policy ensures a region-out outage is detected
immediately rather than discovered at audit time.

### Metrics

Audit emission is itself observable:

| Metric | Labels | Meaning |
|--------|--------|---------|
| `mcpg_audit_emits_total` | `sink_id`, `outcome` (success / fail / throttled) | per-sink emission counter |
| `mcpg_audit_emit_latency_seconds` | `sink_id` | histogram of `emit()` latency |
| `mcpg_audit_chain_breaks_total` | (none) | sink-internal — incremented when a chain integrity check fails on read |
| `mcpg_audit_required_sinks_missing` | (gauge) | 1 if `required: true` but `sinks` is empty after registration; gateway boot fails |

---

## References

- **Protocol spec:** [the MCPG plugin protocol reference](https://mcpg.dev/docs/plugins/plugins-and-protocol)
  (the `audit_sink` entity kind).
- **Builders:** the `mcpg-plugin-host` crate's `src/audit_events.rs` —
  authoritative schema for every event family.
- **Fan-out:** `mcpg-plugin-host`'s `registry.rs::emit_audit_event`,
  `::emit_audit_event_enforced`.
- **Built-in sink:** `dev.mcpg.builtin.audit.local-file` (`builtins/audit_local_file.rs`).
- **Audit tool-gate plugin:** `dev.mcpg.audit` (`libs/plugins/observability/audit`).
- **Configuration reference:** [`configuration.md`](configuration.md)
  (`governance.audit` block).
- **Compliance support matrix:** [`compliance/compliance-support.md`](compliance/compliance-support.md).
