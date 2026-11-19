# MCPG Distributed Infrastructure

> Session stores, pipeline stores, delivery buses, and NATS / Redis / Kafka connectivity.
> Source: `runtime/session_store.rs`, `runtime/pipeline_store.rs`, `runtime/delivery_bus.rs`,
> plus the plugin crates `mcpg-plugin-backend-nats`, `mcpg-plugin-backend-redis`,
> `mcpg-plugin-backend-nats`, and `mcpg-plugin-backend-kafka`.
>
> The main `mcpg` binary has **no direct dependency** on `async-nats`, `rdkafka`,
> or `redis` — every use of those crates lives inside the plugin crates above.

## Deployment Topologies

MCPG supports two deployment topologies:

**Single-instance**: All state in-memory. InProcess delivery bus. Simplest deployment.

**Multi-instance**: Shared state via NATS KV or Redis. NATS or Redis delivery bus. Load balancer distributes requests across instances. Any instance can handle any request, task or paused call.

Every distributed mechanism degenerates to in-process equivalents in single-instance mode — the same code paths run in both topologies.

**Cluster backend**: NATS and Redis backends are activated via the
top-level `cluster:` block (Layout D'' P12 lifted the backend
out of the plugin wiring section into its own peer). All backend
implementations are compiled into the standard binary. When
`cluster.kind: single_node` (the default), every store and bus uses
the in-memory / in-process implementations. See
[configuration.md](configuration.md#clusterconfig) for the full
shape.

---

## Session Store

The `SessionStore` trait holds the gateway's internal per-caller session rows.
The MCP wire has no session; a row carries the state some features need —
`subscriptions/listen` streams, tasks, paused calls and the delivery-bus key —
and its owner. A row holds no stream or replay state.

### SessionStore Trait

```rust
pub trait SessionStore: Send + Sync {
    fn create_session(&self) -> SessionSnapshot;
    fn create_session_with_id(&self, session_id: &str) -> SessionSnapshot;
    fn bind_session_owner(&self, session_id: &str, owner_principal: Option<&str>);
    fn load_session(&self, session_id: &str) -> Option<SessionSnapshot>;
    fn terminate_session(&self, session_id: &str) -> Option<EndedSession>;
    fn claim_tenant_slot(&self, session_id: &str, cap: usize) -> Option<bool>;
    fn list_sessions(&self) -> Vec<SessionSnapshot>;
    // …lifetime, end notification, liveness and active-count helpers
}
```

`SessionSnapshot` is `{ session_id, created_at, owner_principal }`.

### Session Rows

- A verified caller's row id is derived from its principal and client name
  (`sessions.synthetic_session_key`, or a key derived from
  `cluster.state_encryption_key_env`), so every replica resolves the same row.
- `claim_tenant_slot` counts derived rows and anonymous rows across the fleet
  (`session-t:` keys) for `server.max_sessions_per_tenant`. A row that only
  one replica uses (an identified caller without a derived id) counts on
  that replica.
- An ended row is recorded under `session-end:`, so every replica releases the
  listen streams, leases and admission the row held.

### Backends

One implementation, `KvBackedSessionStore`, runs over the key-value primitive
the sessions capability resolves: in-memory (`MemoryKv`) for `single_node`, a
directory of files (`FileKv`) with `kind: file`, NATS JetStream KV or Redis
from the cluster coordinator. Idle rows expire after
`gateway.server.session_idle_timeout_ms`.

### Configuration

`mcp.configurations.sessions.store:` is a per-capability override. When
omitted, the session store uses the cluster coordinator's key-value primitive
(`kind: cluster`), so a `cluster.kind: redis` deployment keeps its rows in
Redis without an override.

```yaml
mcp:
  configurations:
    sessions:
      store:
        kind: file            # cluster | memory | file
        dir: "/var/lib/mcpg/sessions"
```

---

## Pipeline Store

The `PipelineStore` trait manages execution state for suspended pipelines.

### PipelineStore Trait

```rust
pub trait PipelineStore: Send + Sync {
    fn save_pipeline(&self, state: &PipelineExecutionState) -> Result<()>;
    fn load_pipeline(&self, pipeline_id: &str) -> Result<Option<PipelineExecutionState>>;
    fn try_claim_pipeline(&self, pipeline_id: &str, expected_version: u64) -> Result<bool>;
    fn delete_pipeline(&self, pipeline_id: &str) -> Result<()>;
    fn save_pending_server_request(...) -> Result<()>;
    fn load_pending_server_request(...) -> Result<Option<PendingServerRequest>>;
    fn delete_pending_server_request(...) -> Result<()>;
    fn store_pending_delivery(...) -> Result<String>;
    fn take_pending_deliveries(&self, session_id: &str) -> Result<Vec<DeliveryMessage>>;
    fn list_expired_pipelines(&self) -> Result<Vec<String>>;
}
```

### CAS Fencing

`try_claim_pipeline(id, expected_version)` implements compare-and-set semantics:
- Each pipeline state has a `state_version` (monotonically increasing)
- Only the instance that successfully claims at the expected version can resume
- Prevents split-brain execution of the same pipeline on multiple instances

### PipelineExecutionState

```rust
PipelineExecutionState {
    pipeline_id: String,           // = gateway_request_id
    session_id: String,
    original_jsonrpc_id: Value,
    tool_name: String,
    steps: Vec<PipelineStepConfig>,
    current_step_index: usize,
    completed_steps: BTreeMap<String, StepResult>,
    original_args: Value,
    request_context: RequestContext,
    created_at: DateTime<Utc>,
    suspended_at: Option<DateTime<Utc>>,
    pipeline_timeout_ms: u64,
    pending_server_request_id: Option<String>,
    state_version: u64,
}
```

### Backends

| Backend | State Storage | Key Pattern |
|---|---|---|
| `InMemoryPipelineStore` | `Mutex<HashMap>` × 3 | Direct string keys |
| `NatsKvPipelineStore` | NATS JetStream KV | `{prefix}.pipeline.{id}` |
| `RedisPipelineStore` | Redis with TTL | `{prefix}:pipeline:{id}` |

---

## Task Store

The `TaskStore` trait manages the lifecycle of tasks the `io.modelcontextprotocol/tasks` extension materializes from `tools/call`.

### TaskStore Trait

```rust
pub trait TaskStore: Send + Sync + std::fmt::Debug {
    fn retention_policy(&self) -> TaskRetentionPolicy;
    fn set_observer(&self, observer: Arc<dyn TaskObserver>);
    fn create_task(&self, session_id: &str, original_request_id: Value,
                   tool_name: &str) -> Result<TaskRecord, TaskStoreError>;
    fn get_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;
    fn update_task_status(&self, task_id: &str, session_id: &str, status: TaskStatus,
                          status_message: Option<String>) -> Result<(), TaskStoreError>;
    fn set_task_poll_interval(&self, task_id: &str, session_id: &str,
                              poll_interval_ms: Option<u64>) -> Result<(), TaskStoreError>;
    fn set_task_awaiting_input(&self, task_id: &str, session_id: &str,
                               request_state: String,
                               input_requests: Value) -> Result<(), TaskStoreError>;
    fn task_request_state(&self, task_id: &str,
                          session_id: &str) -> Result<Option<String>, TaskStoreError>;
    fn store_task_terminal(&self, task_id: &str, status: TaskStatus,
                           envelope: TerminalEnvelope) -> Result<(), TaskStoreError>;
    fn cancel_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;
    fn list_tasks(&self, session_id: &str) -> Result<Vec<Task>, TaskStoreError>;
    fn gc_expired_tasks(&self) -> usize;
}
```

The TTL comes from the store's `retention_policy()`
(`mcp.capabilities.tasks.default_ttl_ms`), and `create_task` returns
`QuotaExceeded` when the owner already holds
`mcp.capabilities.tasks.max_tasks_per_session` tasks.

### Owner Binding

The `session_id` a task is keyed on is the caller's task-owner key: the
principal for an identified caller, so every replica answers `tasks/get`
for the same principal, and the session row for an anonymous or stdio
caller.
Every accessor enforces that only the owner can query, update or cancel a
task. Cross-owner access returns `TaskStoreError::Forbidden`.

### Task Lifecycle

```
create_task() → Working ─┬─ set_task_awaiting_input() → InputRequired → (tasks/update resumes) → Working
                         ├─ store_task_terminal(Completed/Failed, envelope)
                         └─ cancel_task() → Cancelled
```

Tasks have a configurable TTL (default: 30 minutes). Expired tasks are garbage-collected by `gc_expired_tasks()`.

### Backends

One implementation, `KvBackedTaskStore`, runs over the key-value primitive
the task capability resolves (`mcp.capabilities.tasks.store`, else the
cluster coordinator's):
in-memory for `single_node`, NATS JetStream KV or Redis in a cluster.

| Key | Value |
|---|---|
| `task:{task_id}` | the JSON-encoded `TaskRecord`, with the task's TTL |
| `task-s:{owner}:{task_id}` | the owner's task index (per-owner limit, session-end cleanup) |

---

## Delivery Bus

The `DeliveryBus` trait routes notifications to the instance holding the client's `subscriptions/listen` stream.

### DeliveryBus Trait

```rust
pub trait DeliveryBus: Send + Sync {
    async fn subscribe(&self, session_id: &str) -> mpsc::Receiver<DeliveryMessage>;
    async fn publish(&self, session_id: &str, msg: DeliveryMessage) -> Result<()>;
}
```

### Auto-Selection

The delivery bus is selected automatically based on available infrastructure:

1. **NATS** (if `cluster.kind: nats`) — subject: `mcpg.internal.deliver.{session_id}`
2. **Redis** (if `cluster.kind: redis`) — channel: `mcpg:deliver:{session_id}`
3. **InProcess** (fallback) — tokio broadcast channels

### Pending Deliveries

A `log` or `progress` pipeline step stores its notification as a **pending
delivery** on the request's session row. After a `tools/call` returns, the
transport drains them with `take_pending_deliveries(session_id)` and, when
there are any, answers with a per-request SSE stream (notifications first,
then the result).

### Message Types

```rust
enum DeliveryKind {
    ProgressNotification, // notifications/progress
    ResourceUpdated,      // notifications/resources/updated
    Notification,         // list_changed, notifications/tasks, notifications/message
}
```

---

## NATS Connection Manager

Manages a single NATS connection with profile-based request routing.
Layout D'' P12 removed the standalone top-level `nats:` block — the
NATS connection is now driven by either the `cluster.kind: nats`
backend (for KV / pub-sub primitives) or by the
`mcpg-plugin-backend-nats` plugin entry (for binding-side
request/reply). Both ultimately resolve to the same connection
config keyed under their respective parents.

**Profile-based routing**: NATS backends register profiles at startup. Each profile specifies a subject, timeout, and max response size. The connection manager handles request/reply, retry, and payload truncation.

**JetStream KV**: The manager also provides `create_or_bind_kv_bucket()` for session, pipeline, and task store backends.

**Metrics**: `mcpg_nats_connected` gauge tracks connection state.

---

## Kafka Connection Manager

Manages Kafka producer and consumer for correlation-ID-based request/reply.
Driven by the `mcpg-plugin-backend-kafka` plugin entry under the
top-level `plugins[]` array (Layout D'' P4 removed the standalone
top-level `kafka:` block — Kafka is binding-side only and lives in
the backend plugin's own `config:` block).

**Profile-based routing**: Kafka backends register profiles specifying request topic, response topic, timeout, and max response size. The manager handles correlation ID generation, consumer subscription, and response filtering.

---

## Infrastructure Decision Matrix

| Feature | Single-Instance | Multi-Instance (NATS) | Multi-Instance (Redis) |
|---|---|---|---|
| Session Store | InMemory or File | NatsKV | Redis |
| Pipeline Store | InMemory | NatsKV | Redis |
| Task Store | InMemory | NatsKV | Redis |
| Delivery Bus | InProcess | NATS pub/sub | Redis pub/sub |
| Configuration | Minimal | `cluster.kind: nats` | `cluster.kind: redis` |
| Coordination | Not needed | CAS via KV revisions | CAS via Redis scripts |
| Session Affinity | Not needed | Not needed | Not needed |
