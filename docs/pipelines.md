# MCPG Pipeline Execution

> Multi-step binding orchestration with data flow, conditional gates, and client interaction.
> Source: `config/backend.rs` (`PipelineStepConfig`, ~L1305), `runtime/execution.rs`, `runtime/pipeline_store.rs`, `runtime/delivery_bus.rs`

## Overview

A pipeline binding executes an ordered sequence of steps as a single MCP tool
call. Steps share data through a pipeline context, and four step kinds can
suspend execution to interact with the client.

**Step shape.** Every step is a flat object: a `kind:` discriminator, an
`id:` (unique within the pipeline), and that kind's own fields as siblings —
**not** a nested per-kind sub-block. Backend steps flatten the same config as
their standalone backend (e.g. an `http` step carries `url:` / `method:`
directly).

## Pipeline Configuration

```yaml
backend:
  kind: pipeline
  pipeline_timeout_ms: 30000           # Total timeout for all steps
  steps:
    - id: "step1"                      # Unique step ID within this pipeline
      kind: http                       # Step kind discriminator
      # …step-specific fields
    - id: "step2"
      kind: transform
      expression: 'steps.step1.output.data'
```

**Validation rules**:
- All step IDs must be unique within a pipeline
- CEL expressions in `transform`, `cel_gate`, and `input_transform` must not reference forward (undefined) step IDs
- Step IDs are used as keys in the `steps` context variable

## Pipeline Context

Every step has access to the pipeline context with three top-level variables:

| Variable | Type | Description |
|---|---|---|
| `original_args` | JSON object | Tool arguments from the original `tools/call` |
| `request_context` | JSON object | Request ID, session ID, identity, transport |
| `steps` | JSON object | Completed step results keyed by step ID |

Each `steps` entry:
```json
{
  "step_id": {
    "output": { ... },        // Step output value
    "is_error": false,        // Whether step produced an error
    "duration_ms": 42         // Step execution time
  }
}
```

## Step Kinds (18)

`PipelineStepConfig` defines **18 step kinds**, each a flat object keyed by
`kind:`. They group into backend steps (7), composition steps (3),
notification steps (2), SQL container steps (2), and suspending steps (4).

### Backend Steps (7)

Backend steps execute the same adapters as standalone backends — the backend
config flattens directly onto the step. Each supports an optional
`input_transform` CEL expression to reshape input before execution.

#### HTTP Step
```yaml
- kind: http
  id: "fetch_user"
  url: "https://api.example.com/users"
  method: post
  timeout_ms: 5000
  max_response_bytes: 1048576
  expected_status_codes: [200]
  require_json_response: true
  headers: {}
  input_transform: 'original_args'       # Optional CEL expression
```

#### Command Step
```yaml
- kind: command
  id: "run_script"
  command: "/usr/bin/process"
  args: ["--json"]
  timeout_ms: 10000
  max_output_bytes: 1048576
  require_json_stdout: true
```

#### NATS Step
```yaml
- kind: nats
  id: "backend_query"
  url: "nats://broker:4222"             # required — all nats steps/bindings must agree
  subject: "service.query"
  timeout_ms: 5000
  max_response_bytes: 1048576
```

#### Kafka Step
```yaml
- kind: kafka
  id: "kafka_request"
  bootstrap_servers: "broker:9092"      # required — all kafka steps/bindings must agree
  group_id: "mcpg"                      # required
  request_topic: "requests"
  response_topic: "responses"
  timeout_ms: 10000
  max_response_bytes: 1048576
```

#### gRPC Step
```yaml
- kind: grpc
  id: "grpc_call"
  url: "https://grpc.example.com"       # required (endpoint base)
  service: "example.UserService"        # required
  method: "GetUser"                     # required
  timeout_ms: 5000
  max_response_bytes: 1048576
  headers: {}
```

#### GraphQL Step
```yaml
- kind: graphql
  id: "graphql_query"
  url: "https://api.example.com/graphql"
  operation: "query { users { id name } }"   # required — query/mutation document
  timeout_ms: 5000
  max_response_bytes: 1048576
  headers: {}
```

#### Mock Step

Flattens the `mock` backend config (`response`, `delay_ms`, `error`,
`error_message`, `passthrough`).

```yaml
- kind: mock
  id: "fake_data"
  response: { "items": [1, 2, 3] }
  delay_ms: 100
```

### Composition Steps (3)

#### Transform Step

Produces a new value using a CEL expression evaluated over the pipeline context.

```yaml
- kind: transform
  id: "extract_name"
  expression: 'steps.fetch_user.output.user.name'
```

The expression result becomes the step's `output`. Common patterns:
- Extract nested fields: `steps.step1.output.data.field`
- Concatenate: `steps.a.output.first + " " + steps.a.output.last`
- Map structure: use CEL map/list literals

#### CEL Gate Step

Evaluates a CEL expression as a boolean guard. If false, the pipeline aborts with an error.

```yaml
- kind: cel_gate
  id: "check_permission"
  expression: 'steps.fetch_user.output.role == "admin"'
  error_message: "User does not have admin role"
```

If the expression evaluates to `false`, the pipeline returns an error result with `error_message` as the error text (default text used when omitted). If `true`, the pipeline continues to the next step.

#### Plugin Transform Step

Reshapes the pipeline context by invoking a named `transform` plugin, rather than an inline CEL expression. A generic bridge — works with any registered transform plugin; the first user is `dev.mcpg.transform.jsonata`, which evaluates a **JSONata** expression (far stronger than CEL at building nested objects, projecting, and aggregating arrays).

```yaml
- kind: plugin_transform
  id: reshape
  plugin: dev.mcpg.transform.jsonata
  config:
    expression: '{ "orderIds": steps.fetch.output.orders.id, "total": $sum(steps.fetch.output.orders.amount) }'
```

The plugin receives the full pipeline context — `steps.<id>.output`, `arguments`, `context.*`, `tool_name` (the same surface CEL sees) — and its output becomes the step's `output`. The transform plugin must be loaded in `plugins[]` (its id/alias is what `plugin:` references). A plugin error aborts the pipeline.

### Notification Steps (2)

Non-suspending steps that emit a server-to-client notification on the
session's SSE channel and then continue immediately.

#### Log Step

Emits a `notifications/message`.

```yaml
- kind: log
  id: "announce"
  level: info
  data: "Charging order ${original_args.order_id}"
```

#### Progress Step

Emits a `notifications/progress`. Silently skipped when the inbound request
carried no `progressToken`.

```yaml
- kind: progress
  id: "halfway"
  progress: 0.5
  message: "Validation complete"
```

### SQL Container Steps (2)

Steps that operate against a named `sql` backend's connection pool. See
[backends.md](backends.md#sql-backend) for the SQL backend itself.

#### SQL Transaction Step (`sql_tx`)

Groups one or more SQL statements under a single transaction on a referenced
SQL backend's pool — all-or-nothing. Reference the backend by name via
`backend:` (the SQL backend must be declared with `backend.kind: sql`).

```yaml
- kind: sql_tx
  id: charge_flow
  backend: orders_db                          # existing SQL backend name
  steps:
    - id: deduct_inventory
      sql: "UPDATE inventory SET qty = qty - 1 WHERE id = :id"
      params: [id]
    - id: record_order
      sql: "INSERT INTO orders (user_id, item_id) VALUES (:u, :i)"
      params: [u, i]
      row_mode: affected_rows
```

Nested results surface to downstream steps as
`steps.<tx_step_id>.output.steps.<nested_id>`.

#### SQL Await Step (`sql_await`)

Fire-and-wait against a referenced SQL backend whose profile declares an
`await` block — runs the trigger, polls the check query, and evaluates the
CEL predicate until it matches or times out. Same machinery as the
standalone SQL `await` binding, exposed for pipeline composability.

```yaml
- kind: sql_await
  id: wait_provisioned
  backend: provisioning_db                    # existing SQL backend with [await]
```

### Suspending Steps (4)

Suspending steps interrupt pipeline execution to interact with the client. The pipeline state is persisted to the pipeline store, and a server-initiated JSON-RPC request is delivered to the client via the delivery bus.

#### Elicitation Step

Prompts the client for input.

```yaml
- kind: elicitation
  id: "ask_user"
  message: "Please confirm the operation:"
  requested_schema:                     # Optional JSON Schema for expected response
    type: "object"
    properties:
      confirmed: { type: "boolean" }
```

**Execution flow**:
1. Pipeline state serialized to pipeline store
2. Server sends `elicitation/create` JSON-RPC request to client via delivery bus/SSE
3. Pipeline suspends — `tools/call` returns HTTP 202 Accepted
4. Client responds with `elicitation/create` response
5. Pipeline resumes from the next step
6. Client's response becomes the step's `output`

#### Sampling Step

Requests the client to perform LLM sampling.

```yaml
- kind: sampling
  id: "ai_analysis"
  messages:
    - role: "user"
      content: "Analyze this data: ${steps.fetch.output}"
  max_tokens: 500
```

**Execution flow**: Same as elicitation. Uses `sampling/createMessage` JSON-RPC method.

#### Roots List Step

Asks the client to enumerate its filesystem/URI roots (`roots/list`). The
client's response becomes the step's `output`.

```yaml
- kind: roots_list
  id: "discover_roots"
  timeout_ms: 30000
```

#### Gather Step (multi-entry MRTR)

Emits several server-to-client input requests (any mix of elicitation /
sampling / roots) in **one** suspension and resumes once the client answers
them together — distinct from listing the individual suspending steps in
sequence, which suspends/resumes one at a time (SEP-2322).

```yaml
- kind: gather
  id: "collect_inputs"
  inputs:                                  # two or more entries, each with a correlation_token
    - kind: elicitation
      correlation_token: confirm
      message: "Confirm the operation?"
    - kind: sampling
      correlation_token: summary
      messages:
        - role: user
          content: "Summarize: ${steps.fetch.output}"
      max_tokens: 200
```

Each answered input lands in this step's output under its
`correlation_token`, so downstream `transform` steps read
`steps.collect_inputs.output.confirm`, etc.

**Capability check**: Before suspending, the gateway checks `client_capabilities` from the session's `initialize` response. If the client does not support the requested interaction (elicitation / sampling / roots), the step returns an error instead of suspending.

## Pipeline Execution Lifecycle

```
tools/call with pipeline binding
  │
  ▼
┌─────────────────────────────┐
│  Sequential Step Execution   │
│  For each step:              │
│    1. Evaluate input_transform (if any)
│    2. Execute step adapter   │
│    3. Store result in the    │
│       `steps` context        │
│    4. Check for error        │
│       (abort if is_error)    │
└──────────┬──────────────────┘
           │
           ├── All steps complete → Return final step output
           │
           ├── Step error → Return error result
           │
           ├── Suspending step → Serialize state
           │   │                  Send server request
           │   │                  Return 202 Accepted
           │   │
           │   └── Client responds → Load state
           │                         Resume from next step
           │                         Continue sequential execution
           │
           └── Timeout → Return timeout error
```

## Distributed Pipeline Coordination

### Pipeline Store

Persists pipeline execution state for suspension/resumption across load-balanced instances.

| Backend | Selection |
|---|---|
| `InMemoryPipelineStore` | Default (single-instance) |
| `NatsKvPipelineStore` | When NATS is available |
| `RedisPipelineStore` | When Redis is available |

**CAS Fencing**: `state_version` field implements compare-and-set semantics. When resuming, the gateway claims the pipeline with `try_claim_pipeline(id, expected_version)`. Only one instance can resume a pipeline.

### Delivery Bus

Routes server-initiated messages (elicitation requests, sampling requests, deferred results) to the SSE-stream-holding instance.

**Auto-selection**: NATS > Redis > InProcess

**Pending delivery fallback**: If no subscriber is connected, messages are stored as pending deliveries in the pipeline store. When the client reconnects via SSE, pending deliveries are replayed.

### Pipeline Reaper

Background task that periodically cleans up expired pipeline states. Configurable sweep interval (default: 30s). Pipelines are expired when they exceed their `pipeline_timeout_ms`.

## Metrics

Pipeline execution emits these Prometheus metrics:

| Metric | Type | Labels |
|---|---|---|
| `mcpg_binding_executions_total` | Counter | `binding_name`, `binding_type=pipeline`, `outcome` |
| `mcpg_binding_execution_duration_seconds` | Histogram | `binding_name`, `binding_type=pipeline`, `outcome` |
| `mcpg_pipeline_reaper_cleaned_total` | Counter | — |
| `mcpg_pipeline_reaper_last_sweep_count` | Gauge | — |
