# MCPG Guardrails, Human Moderation, and Policy Controller Design

> Design document for external guardrail hooks, human-in-the-loop moderation,
> content scanning, budget enforcement, and pluggable policy controllers in MCPG.
>
> Status: **Partially implemented** — core guardrail hooks are live as a plugin crate
> Date: April 7, 2026 (design) · April 9, 2026 (implementation update)

---

## Implementation Status

The following items from this design are now implemented:

| Feature | Status | Location |
|---|---|---|
| Pre-execution HTTP guardrail hooks | **Implemented** | `libs/plugins/security/guardrails/` |
| Post-execution HTTP guardrail hooks | **Implemented** | `libs/plugins/security/guardrails/` |
| CEL trigger expressions | **Implemented** | `GuardrailsGatePlugin` |
| Glob-based tool filtering | **Implemented** | `libs/plugins/security/guardrails/src/glob.rs` |
| Fail-open / fail-closed on_error | **Implemented** | `GuardrailHookConfig.on_error` |
| Argument mutation from guardrail response | **Implemented** | `GuardrailServiceResponse.mutate_arguments` |
| Async HTTP callouts (non-blocking) | **Implemented** | `reqwest` async client |
| Prometheus metrics per hook | **Implemented** | `mcpg_guardrail_*` metric family |
| Plugin chain integration | **Implemented** | Registered as `ToolGatePlugin` in plugin registry |
| Human moderation queue | Not yet | Design only (section 5) |
| Budget/quota controllers | Not yet | Design only (section 6) |
| Pipeline-level guardrails | Not yet | Design only (section 4.2) |
| Approval workflows | Not yet | Design only (section 5) |

The guardrails are implemented as a standalone crate (`mcpg-plugin-guardrails`, 1,487 lines, 34 tests) that implements the `ToolGatePlugin` async trait. It is wired into the gateway's plugin registry at startup from the `guardrails:` config section. See [configuration.md](configuration.md#plugins) for config reference.

---

## 1. Problem Statement

MCP creates a powerful attack surface: LLM agents can discover and invoke arbitrary tools, read resources, and trigger multi-step pipelines. Unlike traditional API gateways, the consumer is an AI model that may hallucinate intent, be prompt-injected, or exhibit undesirable behavior without malice. This creates risks distinct from human API consumers:

- **Prompt injection → tool abuse** — a compromised LLM context calls tools it should not call
- **Over-permissive tool discovery** — agents see more capabilities than they should act on
- **Unreviewed high-impact operations** — destructive or expensive tool calls with no human checkpoint
- **Data exfiltration via tool chaining** — multi-step pipelines that extract data through seemingly innocent sequences
- **Unbounded spending/resource consumption** — AI calling paid APIs or heavy computations without budget controls
- **Compliance violations** — AI making decisions that require human approval for regulatory reasons (SOX, HIPAA, financial controls)

MCPG already has a pre-dispatch policy gate (trust levels + CEL expressions) and input schema validation. These are necessary but insufficient for content-aware scanning, external policy decisions, human approval workflows, and post-execution output filtering.

---

## 2. Industry Patterns for AI Guardrails

### 2.1 Pre-Execution Policy Gates (OPA / Cerbos / Cedar)

Evaluate structured policy before tool execution. Input: caller identity, tool name, arguments, session context. Output: allow / deny / require-approval with reason. Examples: AWS Cedar for Bedrock Agents, Anthropic tool-use policies.

### 2.2 Human-in-the-Loop Approval Workflows

High-sensitivity operations route to a human moderator queue. The moderator approves, modifies, or rejects the tool invocation. The MCP spec's own elicitation step is a primitive for this pattern. Examples: Salesforce Einstein human review, ServiceNow AI Action approvals.

### 2.3 Content and Argument Scanning (Shield / Guardrails AI)

Run tool arguments through scanning: PII detection, toxicity, injection detection. Run tool outputs through scanning: sensitive data leakage, hallucination detection. Examples: AWS Bedrock Guardrails, NVIDIA NeMo Guardrails, Anthropic Constitutional AI.

### 2.4 Budget, Rate, and Quota Controllers

Track cumulative cost, invocation count, and data volume per session, user, or tool. Enforce hard limits and soft warnings. Examples: OpenAI API budget controls, Azure AI Content Safety.

### 2.5 Audit Trail and Explainability

Log every tool invocation decision with policy context. Support regulatory audit and incident investigation. Examples: SOC2 audit requirements, GDPR Article 22 automated decision-making.

### 2.6 External Policy Decision Points (PDP)

The gateway calls out to an external service for each decision. Decouples policy authoring from gateway deployment. Examples: Ory Oathkeeper remote authorizer, SpiceDB/OpenFGA, Cerbos PDP.

### 2.7 What Makes MCP Gateways Different from API Gateways

A traditional API gateway guards well-defined REST/gRPC endpoints. An MCP gateway guards a dynamic capability surface where:

- The tool catalog changes per-subject and per-session
- Tool arguments are arbitrary JSON defined by schema, not fixed path parameters
- Pipelines compose N tools into one invocation — the guardrail needs to see the chain, not just individual calls
- The consumer is an AI model, not a human developer — so user intent verification takes a fundamentally different form
- Elicitation and sampling steps already create a server-to-client request path that can be repurposed for approval flows

---

## 3. MCPG Current State

### 3.1 What MCPG Already Has

| Layer | Mechanism | Scope |
|---|---|---|
| **Identity** | 3-tier trust model (Anonymous → HeaderAsserted → Verified) | Per-request |
| **Pre-dispatch policy** | Trust level check + global/per-tool CEL expressions | Per-tool-call |
| **Input validation** | JSON Schema validation on tool arguments | Per-tool-call |
| **Pipeline CEL gates** | `cel_gate` steps that can abort pipelines on conditions | Per-pipeline-step |
| **Elicitation** | Server-to-client human prompt with schema-validated response | Per-pipeline-step |
| **Tool visibility** | Policy gate hides denied tools from `tools/list` | Per-session |
| **Metrics and logging** | Structured audit of policy decisions, backend executions | Deployment-wide |

### 3.2 What Is Missing

| Gap | Description |
|---|---|
| **External policy callout** | ~~Not implemented~~ → **Done** via guardrails plugin (async HTTP hooks) |
| **Argument-level scanning** | ~~CEL only~~ → **Done** via pre-execution hooks with argument mutation |
| **Output scanning** | ~~Not implemented~~ → **Done** via post-execution hooks |
| **Human moderation queue** | Elicitation is client-directed; no moderator-directed approval queue |
| **Budget/quota controls** | No per-session or per-user invocation budget |
| **Chain-level policy** | Pipeline-level policy is step-by-step; no holistic pipeline-level guardrail |
| **Approval workflows** | No async approval queue for high-sensitivity tools |
| **Guardrail provider abstraction** | ~~Not implemented~~ → **Done** via ToolGatePlugin async trait |

### 3.3 Where Guardrails Fit in the Request Flow

The existing dispatch path in `runtime/mod.rs`:

```
Client Request
  → Identity Resolution (OIDC → JWKS → Plugin → Header → Anonymous)
  → Session Load
  → Capability Match (tool_route)
  → [1] Plugin Chain Pre-Dispatch                      ← IMPLEMENTED
        → Policy gate (trust + CEL)
        → Payment gate (MPP)
        → Guardrails (HTTP hooks, CEL triggers)
        → Custom tool-gate plugins
  → [2] Input Schema Validation                        ← EXISTING
  → Binding Execution (dispatch_tool_call / execute_pipeline)
  → [3] Plugin Chain Post-Dispatch                     ← IMPLEMENTED
        → Guardrails (HTTP hooks, post-execution)
        → Custom tool-gate plugins
  → JSON-RPC Response
```

Guardrails run as part of the async plugin chain. They do not replace the policy gate — policy is the first plugin in the tool-gate chain.

---

## 4. Design: MCPG Guardrail Hooks

### 4.1 Design Principles

1. **Guardrails are not policy.** The existing `policy` subsystem owns trust-level and CEL-based access control. Guardrails are a distinct concern: content scanning, human approval, budget enforcement, external PDP callouts. They operate after policy allows but before (or after) execution.

2. **Guardrails are operator-defined, HTTP-callable.** Like bindings, guardrails are operator-configurable. The gateway calls out to external guardrail services via HTTP. This keeps MCPG as protocol authority while letting operators plug in arbitrary guardrail logic.

3. **Pre and post hooks.** Guardrails have two natural positions: pre-execution (can block, modify, or require approval) and post-execution (can redact, block, or flag responses).

4. **Fail-closed.** Guardrail service unavailability blocks the tool call. This is consistent with MCPG's overall fail-closed design philosophy.

5. **Composable chain.** Multiple guardrails can be chained (e.g., PII scanner → budget check → human approval). They evaluate in order; the first deny stops the chain.

6. **Pipeline-aware.** For pipeline bindings, guardrails can evaluate at pipeline-level (before/after the whole pipeline) and optionally at step-level.

### 4.2 Configuration Model

```yaml
guardrails:
  # Pre-execution guardrails — evaluated after policy allows, before backend execution
  pre_execution:
    - name: content_scanner
      url: http://guardrails-service:8080/scan/input
      timeout_ms: 2000
      max_response_bytes: 4096
      # Which tools this guardrail applies to (empty = all tools)
      tools: []
      # Which tools this guardrail does NOT apply to
      exclude_tools:
        - "mcpg.*"        # skip debug tools
      # When to evaluate: "always", "verified_only", "when_cel_matches"
      trigger: always
      # Optional CEL expression for conditional activation
      trigger_cel: null
      # What to do on guardrail service error: "deny" (default) or "allow"
      on_error: deny
      # Whether this guardrail can modify the arguments (rewrite)
      allow_mutation: false

    - name: human_approval
      url: http://moderation-service:8080/approve
      timeout_ms: 120000       # 2 minutes — human review takes time
      tools:
        - "orders.place*"
        - "finance.*"
      trigger: always
      on_error: deny
      allow_mutation: true    # moderator can modify arguments

    - name: budget_check
      url: http://budget-service:8080/check
      timeout_ms: 1000
      trigger: always
      on_error: deny

  # Post-execution guardrails — evaluated after binding returns, before client response
  post_execution:
    - name: output_scanner
      url: http://guardrails-service:8080/scan/output
      timeout_ms: 2000
      tools: []
      on_error: deny          # if scanner is down, don't return unscanned output
      allow_mutation: true    # scanner can redact sensitive data
```

### 4.3 Guardrail Request/Response Contract

#### Pre-Execution Request (gateway → guardrail service)

```json
{
  "version": "1",
  "kind": "pre_execution",
  "request_id": "req-abc-123",
  "session_id": "sess-xyz",
  "tool_name": "orders.place_order",
  "arguments": { "item": "Widget A", "quantity": 5 },
  "identity": {
    "kind": "verified",
    "subject_id": "user-42",
    "trust_level": "verified",
    "auth_provider": "corporate-idp",
    "groups": ["engineering", "order-approvers"],
    "roles": ["developer"],
    "scopes": ["orders:write"],
    "attributes": { "department": "engineering" }
  },
  "binding_metadata": {
    "binding_type": "http",
    "minimum_trust": "verified",
    "is_pipeline": false
  },
  "session_metadata": {
    "tools_called_count": 12,
    "session_duration_secs": 340
  }
}
```

#### Guardrail Response (guardrail service → gateway)

```json
{
  "decision": "allow",
  "reason": "content scan passed",
  "modified_arguments": null,
  "metadata": {
    "scan_duration_ms": 45,
    "policy_version": "v2.3"
  }
}
```

Decision values:
- `"allow"` — proceed with execution (optionally with `modified_arguments`)
- `"deny"` — block execution, return error to client
- `"require_approval"` — suspend and route to human moderator (see §4.5)

#### Post-Execution Request (gateway → guardrail service)

```json
{
  "version": "1",
  "kind": "post_execution",
  "request_id": "req-abc-123",
  "tool_name": "orders.place_order",
  "arguments": { "item": "Widget A", "quantity": 5 },
  "result": {
    "content": [{"type": "text", "text": "{\"order_id\": \"ORD-999\"}"}],
    "is_error": false
  },
  "identity": { "kind": "verified", "subject_id": "user-42" },
  "execution_metadata": {
    "duration_ms": 234,
    "binding_type": "http"
  }
}
```

#### Post-Execution Response

```json
{
  "decision": "allow",
  "modified_result": null,
  "redactions": ["result.content[0].text contained PII — SSN redacted"]
}
```

### 4.4 Runtime Integration Point

The guardrail hooks fit into `runtime/mod.rs` at the `ToolsCall` handler between policy evaluation and dispatch:

```
Current flow:
  policy_gate.evaluate_tool_call()        → Allow/Deny
  capability_registry.validate_tool_arguments()
  execution_dispatcher.dispatch_tool_call()

Proposed flow:
  policy_gate.evaluate_tool_call()        → Allow/Deny
  capability_registry.validate_tool_arguments()
  guardrail_chain.evaluate_pre_execution() → Allow/Deny/RequireApproval
  execution_dispatcher.dispatch_tool_call()
  guardrail_chain.evaluate_post_execution() → Allow/Deny/Redact
  return response
```

### 4.5 Human Moderation: The `require_approval` Flow

This is where MCPG's existing pipeline suspension infrastructure becomes powerful. The `require_approval` decision works like this:

1. Pre-execution guardrail returns `decision: "require_approval"`
2. Gateway serializes the pending tool call to the pipeline store (reusing existing `PipelineExecutionState` serialization)
3. Gateway returns HTTP 202 Accepted to the client (same as pipeline suspension)
4. Gateway notifies the moderation service that an approval is pending (via the guardrail's webhook or the delivery bus)
5. Human moderator reviews in their moderation tool (a separate UI/API)
6. Moderator approves, rejects, or modifies via the moderation service
7. Moderation service calls a gateway API endpoint (e.g., `POST /mcp/guardrail-decisions/{request_id}`)
8. Gateway resumes execution with the original or modified arguments
9. Result is delivered to the client via SSE (same as pipeline resumption)

This reuses the entire suspend/resume infrastructure already built for elicitation and sampling steps, including:
- Pipeline store persistence (InMemory / NatsKV / Redis)
- Delivery bus for cross-instance routing
- CAS fencing for exactly-once resumption
- Timeout and reaper for cleanup

### 4.6 Module Structure

Following MCPG's separation of concerns:

```
src/runtime/
  ├── guardrails.rs     — GuardrailChain evaluation, HTTP callout, decision parsing
  └── ...existing...
```

Key types:

```rust
pub(crate) struct GuardrailChain {
    pre_execution: Vec<GuardrailConfig>,
    post_execution: Vec<GuardrailConfig>,
    http_client: reqwest::blocking::Client,
}

pub(crate) enum GuardrailDecision {
    Allow { modified_arguments: Option<Value> },
    Deny { reason: String, code: i32 },
    RequireApproval { approval_id: String, moderator_hint: Option<String> },
}

pub(crate) struct GuardrailEvaluation {
    pub guardrail_name: String,
    pub decision: GuardrailDecision,
    pub duration_ms: u64,
}
```

---

## 5. Use Cases

### 5.1 PII and Sensitive Data Scanner

**Scenario**: A financial services company uses MCPG to expose customer data tools to an AI assistant. They need to ensure neither the AI's requests nor the tool responses contain unredacted SSNs, credit card numbers, or medical records.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: pii_input_scan
      url: http://pii-scanner:8080/scan/input
      timeout_ms: 500
      trigger: always
  post_execution:
    - name: pii_output_scan
      url: http://pii-scanner:8080/scan/output
      timeout_ms: 500
      allow_mutation: true
```

**Flow**: AI calls `customer.lookup` → pre-scan passes → HTTP binding executes → response contains SSN → post-scan redacts SSN → client receives sanitized result.

### 5.2 Human Approval for High-Value Operations

**Scenario**: An e-commerce company has AI agents that can place orders. Orders above $10,000 require human approval per compliance policy.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: order_approval
      url: http://approval-service:8080/evaluate
      timeout_ms: 300000
      tools: ["orders.place_order"]
      trigger: always
```

**Flow**: AI calls `orders.place_order` with $15,000 order → guardrail service sees amount exceeds $10k → returns `require_approval` → gateway suspends → human moderator in Slack or dashboard reviews → approves → gateway resumes → order placed → AI gets confirmation.

### 5.3 Prompt Injection Detection

**Scenario**: A coding assistant uses MCP tools. Attackers may inject tool-calling prompts via code comments or PR descriptions. The operator wants to detect suspicious tool arguments.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: injection_detector
      url: http://ai-safety:8080/detect-injection
      timeout_ms: 1000
      trigger: always
      on_error: deny
```

**Flow**: AI calls `code.execute_review` with arguments that contain embedded prompt injection patterns → guardrail ML model detects injection → returns `deny` with reason → tool call blocked → incident logged.

### 5.4 Budget and Rate Control

**Scenario**: Each team has a monthly budget for AI tool calls to paid APIs. The operator needs per-team budget enforcement.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: budget_controller
      url: http://budget-service:8080/check
      timeout_ms: 500
      trigger: always
  post_execution:
    - name: budget_record
      url: http://budget-service:8080/record
      timeout_ms: 500
```

**Flow**: AI calls `search.premium_query` → budget service checks team-42's remaining budget → $2.50 remaining, query costs $0.10 → allows → binding executes → post-execution records $0.10 spend → budget decrements.

### 5.5 Compliance Audit Trail for Regulated Industries

**Scenario**: A healthcare AI assistant accesses patient records via MCP. HIPAA requires logging of every access with justification.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: hipaa_audit
      url: http://compliance:8080/pre-audit
      timeout_ms: 1000
      tools: ["patient.*"]
      trigger: always
  post_execution:
    - name: hipaa_post_audit
      url: http://compliance:8080/post-audit
      timeout_ms: 1000
      tools: ["patient.*"]
```

**Flow**: Every `patient.*` tool call is logged before and after execution with full identity context, arguments, and results, creating an immutable audit trail for HIPAA compliance.

### 5.6 OPA/Cerbos External Policy Decision

**Scenario**: Organization already has OPA policies for all services. They want MCPG to consult OPA before tool execution, not just use static CEL expressions.

**Configuration**:
```yaml
guardrails:
  pre_execution:
    - name: opa_policy
      url: http://opa:8181/v1/data/mcpg/tool_access
      timeout_ms: 500
      trigger: always
```

**Flow**: This bridges MCPG to any existing policy engine without MCPG needing built-in OPA/Cerbos/SpiceDB support. The guardrail contract is generic HTTP; the operator's guardrail service translates to OPA's Rego input format.

---

## 6. Relationship to Existing and Planned Architecture

### 6.1 Guardrails vs. Policy (`runtime/policy.rs`)

| Aspect | Existing Policy | Guardrails |
|---|---|---|
| **When** | Before execution | Before AND after execution |
| **Logic** | Local (trust level + CEL) | External (HTTP callout) |
| **Speed** | Microseconds | Milliseconds to minutes |
| **Concern** | Can this identity call this tool? | Should this specific invocation proceed? |
| **Mutation** | Never modifies arguments | Can modify arguments and redact output |
| **Human involvement** | Never | Can suspend for human approval |
| **Caching** | L1 process-local TTL | Delegated to guardrail service |

The policy gate remains the first line of defense (fast, local). Guardrails are the second line (rich, external).

### 6.2 Guardrails vs. Authorization (ADR-0002, ADR-0003)

The planned authorization subsystem handles who can see and call what. Guardrails handle what should happen with a specific invocation given its actual content and context. These are complementary:

- Authorization → "User X has permission to call tool Y"
- Guardrails → "This specific call to tool Y with these arguments should be reviewed, scanned, or approved"

### 6.3 Guardrails vs. Wasm Plugins (ADR-0008)

ADR-0008 plans Wasm plugins for `transform_plugin`, `authorization_provider_plugin`, and `identity_enrichment_plugin`. Guardrails take a different approach: they are external HTTP services, not in-process Wasm. This is deliberate:

- Guardrail logic (ML models, approval workflows, budget databases) is too heavy for Wasm
- Guardrail services have their own lifecycle, scaling, and deployment
- HTTP callouts keep MCPG's process footprint stable
- A future Wasm guardrail adapter could wrap the HTTP callout for lightweight in-process checks

### 6.4 Pipeline Integration

For pipeline bindings, guardrails evaluate at two levels:

1. **Pipeline-level** — pre-execution guardrails evaluate before the entire pipeline starts
2. **Step-level (optional)** — operators can configure per-step guardrails for sensitive individual steps within a pipeline

The `require_approval` flow for pipelines reuses the existing pipeline suspension infrastructure almost unchanged. It adds a new suspension reason (awaiting moderator approval) alongside the existing reasons (awaiting elicitation response, awaiting sampling response).

---

## 7. Observability

### Prometheus Metrics

| Metric | Type | Labels |
|---|---|---|
| `mcpg_guardrail_evaluations_total` | Counter | `guardrail_name`, `phase` (pre/post), `decision` (allow/deny/require_approval/error) |
| `mcpg_guardrail_evaluation_duration_seconds` | Histogram | `guardrail_name`, `phase` |
| `mcpg_guardrail_errors_total` | Counter | `guardrail_name`, `error_kind` (timeout/connection/invalid_response) |
| `mcpg_guardrail_approvals_pending` | Gauge | `guardrail_name` |
| `mcpg_guardrail_approval_duration_seconds` | Histogram | `guardrail_name` |

### Structured Log Events

- `guardrail_evaluated` — guardrail name, decision, duration, tool name, identity
- `guardrail_approval_requested` — request ID, tool, moderator hint
- `guardrail_approval_completed` — request ID, decision, reviewer identity

---

## 8. Implementation Plan

### Pre-Execution HTTP Guardrails (smallest useful slice)

- Add `guardrails` config section with validation
- Implement `GuardrailChain` with pre-execution support
- Add the hook point in `runtime/mod.rs` after policy gate, before dispatch
- Support `allow` and `deny` decisions only
- Add metrics and structured logging
- Config validation and tests

### Post-Execution Guardrails and Mutation

- Add post-execution hook after binding returns
- Support `allow_mutation: true` for argument rewriting and output redaction
- Add `modified_arguments` and `modified_result` to the guardrail contract

### Human Approval (`require_approval`)

- Reuse pipeline store for pending approval state
- Add approval webhook/endpoint for moderator responses
- Add delivery bus integration for cross-instance approval routing
- Support timeout-based auto-deny for unreviewed approvals

### Pipeline-Level Guardrails

- Per-pipeline and per-step guardrail configuration
- Chain-context in guardrail request (previous step results, pipeline progress)

---

## 9. Why This Design Fits MCPG

MCPG's architecture is well-positioned for a guardrails system because:

1. The request flow has clear hook points between policy evaluation and execution dispatch
2. The pipeline suspension infrastructure (pipeline store, delivery bus, CAS fencing) can be directly reused for human approval workflows
3. The external HTTP callout pattern is already proven in the binding model
4. The identity model provides rich context for guardrail decisions (groups, roles, scopes, attributes from OIDC claims)
5. The separation between coarse policy and richer authorization (per ADR-0003) creates a natural third layer for content-aware guardrails
6. The fail-closed philosophy applies uniformly to all new subsystems

The design keeps MCPG as protocol authority while allowing operators to flexibly connect external guardrail services — content scanners, human moderation tools, budget controllers, and compliance auditors — via a simple, well-defined HTTP contract.
