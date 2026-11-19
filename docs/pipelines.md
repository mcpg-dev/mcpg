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

**Step IDs**:
- Give each step an ID of its own: a step's result is kept under its ID, so a later step with the same ID replaces it
- An expression that names a step that has not run fails the step that evaluates it
- Step IDs are used as keys in the `steps` context variable

## Pipeline Context

`transform`, `cel_gate` and `input_transform` are CEL expressions over these
variables:

| Variable | Type | Description |
|---|---|---|
| `arguments` (also `args`) | JSON object | The arguments of the call: a tool's arguments, or `{uri}` for a resource read |
| `steps` | JSON object | Completed step results keyed by step ID |
| `context` | JSON object | The caller: `principal_id`, `trust_level`, `auth_provider`, `session_id`, `transport`, `roles`, `groups`, `scopes`, `attributes` |
| `tool_name` | string | The binding's name |

A backend step's own templates (`url`, headers, …) see `arguments` (the
step's input) and `context`, not `steps`; an earlier step's output reaches
a backend step through `input_transform`. An `elicitation` step's `message`
is a template over `arguments`, `steps`, `context` and `tool_name`; the text
of `log`, `progress` and `sampling` steps is sent as written.

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
  input_transform: '{"id": arguments.user_id}'   # Optional CEL expression: the JSON body
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

Non-suspending steps that emit a server-to-client notification for the
request and then continue immediately. A `tools/call` that emitted any
answers with a per-request SSE stream when the client accepts one: the
notifications first, then the result.

#### Log Step

Emits a `notifications/message` when the request's `_meta` carries
`io.modelcontextprotocol/logLevel` and the step's `level` is at or above it.
A request without that key gets no log notifications.

```yaml
- kind: log
  id: "announce"
  level: info
  data: "Charging the order"
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

Suspending steps interrupt pipeline execution to ask the client for input (Multi Round-Trip Requests). The pipeline state is persisted to the pipeline store, and the `tools/call` answers with an `InputRequiredResult` whose `inputRequests` carry the request and whose `requestState` names the paused pipeline.

#### Elicitation Step

Prompts the client for input.

```yaml
- kind: elicitation
  id: "ask_user"
  message: "Delete ${arguments.path}?"  # ${…} resolves against the pipeline context
  requested_schema:                     # Optional JSON Schema for expected response
    type: "object"
    properties:
      confirmed: { type: "boolean" }
```

Each `${…}` in `message` is a CEL expression over `arguments`, `steps`,
`context` and `tool_name`, resolved when the step runs, so the user sees what
they are asked to approve. A `${cred://…}` reference is refused, and a
message that cannot be rendered ends the pipeline with an error result
before anything is asked. Text without `${` is sent as written.

**Execution flow**:
1. Pipeline state serialized to pipeline store
2. `tools/call` returns HTTP 200 with an `InputRequiredResult`: an
   `elicitation/create` entry in `inputRequests`, and a `requestState`
3. Client collects the answer and calls the tool again with the
   `requestState` and its answer in `inputResponses`
4. The gateway checks the `requestState` (bound to the caller, accepted
   once), claims the pipeline, and resumes from the next step
5. Client's answer becomes the step's `output`

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

**Capability check**: Before suspending, the gateway checks the client capabilities the request carries in `_meta` (`io.modelcontextprotocol/clientCapabilities`). If the client does not support the requested interaction (elicitation / sampling / roots), the step returns an error instead of suspending.

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
           │   │                  Return InputRequiredResult
           │   │                  (inputRequests + requestState)
           │   │
           │   └── Client retries with requestState
           │       + inputResponses → Load + claim state
           │                          Resume from next step
           │                          Continue sequential execution
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

### requestState Codec

Every replica derives the same `requestState` codec key (from
`mcp.configurations.request_state.encryption_key`, or from
`cluster.state_encryption_key_env`), so the retry can land on any replica.

### Pending Deliveries

`log` and `progress` steps store their notifications as pending deliveries on
the request's session row; the transport drains them when the `tools/call`
returns and sends them on the per-request SSE stream.

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
