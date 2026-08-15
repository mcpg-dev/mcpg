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

**Multi-instance**: Shared state via NATS KV or Redis. NATS or Redis delivery bus. Load balancer distributes requests across instances. Any instance can handle any request for any session.

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

The `SessionStore` trait defines session lifecycle operations. Four backends are implemented.

### SessionStore Trait

```rust
pub trait SessionStore: Send + Sync {
    fn create_session(...) -> SessionSnapshot;
    fn session_protocol_version(session_id: &str) -> Option<String>;
    fn load_session(...) -> Result<SessionSnapshot, SessionAccessError>;
    fn transition_session_to_operational(session_id: &str) -> Result<()>;
    fn set_session_log_level(...) -> Result<()>;
    fn terminate_session(session_id: &str) -> bool;
    fn open_sse_stream(...) -> Result<Vec<SseEventRecord>, StreamAccessError>;
    fn stream_protocol_response(...) -> Result<Vec<SseEventRecord>>;
    fn stream_raw_message(...) -> Result<Vec<SseEventRecord>>;
}
```

### Session Lifecycle

```
Initialize → AwaitingInitialized → Initialized notification → Operational → Terminate
```

**Session phases**:
- `AwaitingInitialized` — After `initialize` response sent, waiting for `initialized` notification
- `Operational` — Ready for tool calls, capability queries

### SSE Stream Management

Each session can have one active SSE stream. Streams maintain:
- **Replay window**: Configurable number of recent events (default: 16)
- **Event IDs**: Format `stream-{N}:ordinal` for resumability
- **Last-Event-Id**: Client sends for cursor-based replay on reconnect

### Backends

#### InMemorySessionStore
- `Mutex<HashMap<String, Session>>` for sessions
- `Mutex<HashMap<String, StreamState>>` for streams
- Auto-expires idle sessions
- Suitable for development and single-instance production

#### FileBackedSessionStore
- Persists sessions to disk in JSONL format
- Recovers sessions on startup
- Configurable `data_dir`
- Suitable for single-instance with durability

#### NatsKvSessionStore
- Uses NATS JetStream KV bucket
- Key pattern: `{prefix}.{session_id}`
- Async operations (wrapped in `tokio::task::block_in_place`)
- Suitable for multi-instance clusters

#### RedisSessionStore
- Uses Redis with TTL-based expiration
- Key pattern: `{prefix}:{session_id}`
- Async multiplexed connections
- Suitable for multi-instance clusters

### Configuration

Layout D'' P5 lifted session-store config under
`mcp.configurations.sessions.store:` (a per-capability override).
When omitted, the session store inherits from the cluster
backend (`kind: cluster`) — so a `cluster.kind: redis`
deploy automatically gets `RedisSessionStore` without an explicit
override.

```yaml
mcp:
  configurations:
    sessions:
      store:
        kind: memory          # memory | file | nats_kv | redis | cluster
        # file:
        #   data_dir: "/var/lib/mcpg/sessions"
        # nats_kv:
        #   bucket: "mcpg_sessions"
        #   key_prefix: "sess"
        # redis:
        #   key_prefix: "mcpg:sess"
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

The `TaskStore` trait manages background task lifecycle for MCP 2025-11-25 task-augmented tool calls.

### TaskStore Trait

```rust
pub trait TaskStore: Send + Sync {
    fn create_task(&self, session_id: &str, original_request_id: Value,
                   tool_name: &str, ttl_ms: Option<u64>) -> TaskRecord;
    fn get_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;
    fn update_task_status(&self, task_id: &str, status: TaskStatus,
                          status_message: Option<String>) -> Result<(), TaskStoreError>;
    fn store_task_result(&self, task_id: &str, result: Value,
                         is_error: bool) -> Result<(), TaskStoreError>;
    fn get_task_result(&self, task_id: &str, session_id: &str) -> Result<(Value, bool), TaskStoreError>;
    fn cancel_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;
    fn list_tasks(&self, session_id: &str, cursor: Option<&str>,
                  limit: usize) -> Result<(Vec<Task>, Option<String>), TaskStoreError>;
    fn gc_expired_tasks(&self) -> usize;
}
```

### Session Authorization Binding

All accessor methods require `session_id` and enforce that only the owning session can query, cancel, or retrieve tasks. Cross-session access returns `TaskStoreError::Forbidden`.

### Task Lifecycle

```
create_task() → Working → update_task_status(Completed/Failed) → store_task_result()
                  │
                  └── cancel_task() → Cancelled
```

Tasks have a configurable TTL (default: 30 minutes). Expired tasks are garbage-collected by `gc_expired_tasks()`.

### Backends

| Backend | State Storage | Key Pattern |
|---|---|---|
| `InMemoryTaskStore` | `Mutex<HashMap>` | Direct string keys |
| `NatsKvTaskStore` | NATS JetStream KV | `{prefix}.task.{id}` |
| `RedisTaskStore` | Redis with TTL | `{prefix}:task:{id}` |

---

## Delivery Bus

The `DeliveryBus` trait routes server-initiated messages to the instance holding the client's SSE stream.

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

### Pending Delivery Fallback

If `publish` is called but no subscriber is connected (e.g., client temporarily disconnected), the message is stored as a **pending delivery** in the pipeline store. When the client reconnects via SSE, pending deliveries are drained and replayed.

### Message Types

```rust
enum DeliveryKind {
    ServerRequest,        // elicitation/create, sampling/createMessage
    DeferredToolResult,   // tools/call result after suspension
    PipelineError,        // Pipeline error during background execution
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
