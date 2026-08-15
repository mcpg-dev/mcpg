# MCPG Payment Integration

> Per-tool payment gating using the Machine Payment Protocol (MPP) and related schemes.
> Status: Implemented — MPP, x402, UCP, and ACP ship as cdylib tool-gate plugins.

## Overview

MCPG adds an optional payment gate that sits between the pre-dispatch policy gate and the execution dispatcher. Operators configure per-backend payment requirements. Clients that call a paid tool without a valid payment credential receive a JSON-RPC error with payment challenge details. Clients that include a valid credential in `_meta` proceed to execution and receive a payment receipt in the result `_meta`.

## Protocol Landscape

Three protocols were evaluated. MPP was selected as the primary integration.

### Comparison

| Dimension | x402 (Coinbase) | ACP (Stripe + OpenAI) | MPP (Tempo + Stripe) |
|---|---|---|---|
| Core model | HTTP 402 + custom headers | REST checkout sessions | HTTP 402 + WWW-Authenticate |
| Scope | Per-request crypto | Full e-commerce | Per-request + streaming |
| Payment rails | Blockchain only | Stripe SPT | Multi-method |
| MCP binding | `_meta["x402/payment"]`, `structuredContent` | Transport-agnostic | JSON-RPC `-32042`, `_meta["org.paymentauth/*"]` |
| Rust SDK | No | No | Yes (`mpp` crate) |
| Streaming/session | No | No | Yes (`session` intent) |
| IETF spec | No | No | Yes |

### Why MPP

1. **Rust SDK** — `cargo add mpp --features tempo,server` provides server-side challenge issuance and credential verification in process.
2. **Native MCP transport** — The MPP specification defines `draft-payment-transport-mcp-00` with a dedicated JSON-RPC error code (`-32042`), credential placement in `_meta["org.paymentauth/credential"]`, and receipt placement in `_meta["org.paymentauth/receipt"]`.
3. **Multi-method** — Tempo (crypto) is Rust-native today. Stripe (cards) is available in the TypeScript SDK and can be added to the Rust SDK or implemented directly.
4. **Session support** — The `session` intent with payment channels supports streaming and metered billing, mapping naturally to long-running MCP operations.
5. **IETF specification** — `draft-httpauth-payment-00` provides a stable protocol surface.

### Protocol Details

#### MPP Challenge → Credential → Receipt (MCP transport)

```
Agent                                    MCPG Gateway
  │                                          │
  │  tools/call { name: "premium_tool" }     │
  │─────────────────────────────────────────>│
  │                                          │  ← payment gate: tool requires payment
  │  JSON-RPC error -32042                   │     no credential in _meta
  │  { data: { challenges: [...] } }         │
  │<─────────────────────────────────────────│
  │                                          │
  │  [Agent signs payment authorization]     │
  │                                          │
  │  tools/call { name: "premium_tool",      │
  │    _meta: { "org.paymentauth/            │
  │      credential": { ... } } }            │
  │─────────────────────────────────────────>│
  │                                          │  ← payment gate: verify credential
  │                                          │  ← execution dispatcher: run binding
  │  result: { content: [...],               │
  │    _meta: { "org.paymentauth/            │
  │      receipt": { ... } } }               │
  │<─────────────────────────────────────────│
```

#### Challenge (error response)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32042,
    "message": "Payment Required",
    "data": {
      "httpStatus": 402,
      "challenges": [{
        "id": "ch_abc123",
        "realm": "gateway.example.com",
        "method": "tempo",
        "intent": "charge",
        "request": {
          "amount": "100",
          "currency": "usd",
          "recipient": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        }
      }]
    }
  }
}
```

#### Credential (in tool call `_meta`)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "premium_tool",
    "arguments": { "query": "..." },
    "_meta": {
      "org.paymentauth/credential": {
        "challenge": {
          "id": "ch_abc123",
          "realm": "gateway.example.com",
          "method": "tempo",
          "intent": "charge",
          "request": { "amount": "100", "currency": "usd", "recipient": "0xf39F..." }
        },
        "source": "did:pkh:eip155:4217:0x1234...",
        "payload": {
          "type": "transaction",
          "signature": "0x1b2c3d4e5f..."
        }
      }
    }
  }
}
```

#### Receipt (in tool result `_meta`)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{ "type": "text", "text": "Analysis complete..." }],
    "_meta": {
      "org.paymentauth/receipt": {
        "status": "success",
        "challengeId": "ch_abc123",
        "method": "tempo",
        "reference": "0xtx789abc...",
        "settlement": { "amount": "100", "currency": "usd" },
        "timestamp": "2026-04-06T12:00:00Z"
      }
    }
  }
}
```

---

## Integration Into MCPG Request Flow

```
Client HTTP Request
  │
  ▼
┌────────────────────────────────┐
│ HTTP Transport                  │  Parse request, resolve identity
│ (transports/http/)              │  Extract _meta from tools/call params (NEW)
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Gateway Runtime                 │  Session management, operation routing
│ (runtime/mod.rs)                │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Pre-Dispatch Policy Gate        │  Trust level + CEL evaluation
│ (runtime/policy.rs)             │  (unchanged)
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ ★ Payment Gate (NEW)            │  Check binding payment config
│ (runtime/payment.rs)            │  No config → pass through
│                                 │  Config + no credential → -32042 Challenge
│                                 │  Config + credential → verify → allow/deny
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Execution Dispatcher            │  Execute binding (unchanged)
│ (runtime/execution.rs)          │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ ★ Receipt Attachment (NEW)      │  Attach receipt to result _meta
│ (runtime/mod.rs — post-exec)    │  if payment was verified
└────────────────────────────────┘
```

The payment gate is **architecturally parallel** to `PreDispatchPolicyGate`. It has the same evaluate → allow/deny interface and the same fail-closed behavior.

---

## Configuration

Payment is configured purely through `plugins[]`. Each of the
four payment plugins (`dev.mcpg.payment.{mpp,x402,ucp,acp}`) is loaded
like any other tool-gate cdylib; the per-tool charge map lives on
`plugins[*].config.tools` keyed by backend name (backend name = tool
name). There is no top-level `payment:` block, and no per-backend
`payment:` field.

### MPP Example

```yaml
plugins:
  - id: dev.mcpg.payment.mpp
    class: tool_gate
    source:
      path: /var/lib/mcpg/plugins/payment-mpp.so
    config:
      enabled: true
      secret_key_env: MCPG_PAYMENT_SECRET
      realm: "gateway.example.com"
      recipient: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
      challenge_timeout_seconds: 300
      tools:
        premium_analysis:
          charge: "100"          # smallest currency unit
          currency: "usd"
        metered_query:
          charge: "${arguments.count > 10 ? \"1.00\" : \"0.10\"}"
          currency: "usdc"
```

### x402 Example

```yaml
plugins:
  - id: dev.mcpg.payment.x402
    class: tool_gate
    source: { path: /var/lib/mcpg/plugins/payment-x402.so }
    config:
      rpc_urls: { "eip155:8453": "https://base.publicnode.com" }
      facilitator_url: "https://facilitator.x402.io"
      recipient_address: "0x1234..."
      http_timeout_ms: 5000
      tools:
        paid_lookup:
          charge: "0.10"
          currency: "USDC"
          chain_id: "eip155:8453"
          recipient: "0x1234..."
```

### UCP / ACP

UCP and ACP follow the same shape (`config: { ...protocol fields,
tools: { tool_name: { merchant_url, ... } } }`). See the plugin
crate's `from_config_json` for the full schema.

### Validation

Each plugin validates its own config inside `from_config_json`. A
malformed payment block fails plugin load (logged with the plugin id
and the deserialisation error) without bringing down the whole
gateway — the rest of the gateway boots without that plugin in the
chain. There is no cross-cutting "payment is enabled globally" gate
anymore: a tool is paid iff some payment plugin's `tools` map keys it.

---

## Module Structure

### New Files

| File | Purpose | Estimated Size |
|---|---|---|
| `src/runtime/payment.rs` | `PaymentGate` — challenge issuance, credential verification, receipt generation | ~500–700 lines |

### Modified Files

| File | Changes |
|---|---|
| `src/config/mod.rs` | Add `PaymentConfig`, `BackendPaymentConfig` types + validation rules + tests |
| `src/protocol/mod.rs` | Add `-32042` error constant, `_meta` extraction on `ToolCallParams`, `_meta` field on `ToolCallResult` |
| `src/runtime/mod.rs` | Wire `PaymentGate` into `GatewayRuntime`, call from `ToolsCall` dispatch branch |
| `src/app/mod.rs` | Construct `PaymentGate` during bootstrap |
| `src/observability/mod.rs` | Register payment metrics |
| `config.example.yaml` | Add `payment:` section with commented example |

### No Changes Required

| File | Why |
|---|---|
| `src/runtime/execution.rs` | Payment is transparent to execution — the dispatcher does not know about payments |
| `src/bindings/mod.rs` | Capability registry is unchanged — payment config lives on `BackendConfig`, not on the registry |
| `src/transports/http/` | HTTP transport passes `_meta` through; no transport-specific payment logic |
| `src/runtime/policy.rs` | Policy gate is unchanged — payment gate runs after policy |

---

## Type Definitions

### Config Types (in `config/mod.rs`)

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_payment_method")]
    pub method: String,
    #[serde(default)]
    pub recipient: String,
    #[serde(default = "default_realm")]
    pub realm: String,
    #[serde(default = "default_challenge_timeout")]
    pub challenge_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BindingPaymentConfig {
    pub charge: String,
    pub currency: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
}
```

Extension to existing `BackendConfig`:

```rust
pub struct BindingConfig {
    pub name: String,
    pub description: String,
    pub title: Option<String>,
    pub minimum_trust: RequestTrustLevel,
    pub cel_allow_if: Option<String>,
    pub input_schema: Option<Value>,
    pub payment: Option<BindingPaymentConfig>,    // NEW
    pub binding_type: BindingTypeConfig,
}
```

### Protocol Types (in `protocol/mod.rs`)

```rust
/// MPP-defined JSON-RPC error code for payment required.
pub const PAYMENT_REQUIRED_CODE: i64 = -32042;

/// Extended ToolCallParams with _meta passthrough.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
    #[serde(default, rename = "_meta")]
    pub meta: Option<Value>,                      // NEW
}

/// Extended ToolCallResult with _meta for receipts.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    #[serde(skip_serializing_if = "Option::is_none", rename = "_meta")]
    pub meta: Option<Value>,                      // NEW
}
```

### Payment Gate (in `runtime/payment.rs`)

```rust
pub struct PaymentGate {
    enabled: bool,
    default_method: String,
    default_recipient: String,
    realm: String,
    challenge_timeout_seconds: u64,
}

pub enum PaymentEvaluation {
    /// Tool does not require payment — proceed to execution.
    NotRequired,
    /// Tool requires payment, no credential provided — issue challenge.
    ChallengeRequired(PaymentChallenge),
    /// Credential provided and verified — proceed to execution with receipt.
    Verified(PaymentReceipt),
    /// Credential provided but verification failed.
    Failed(PaymentFailure),
}

pub struct PaymentChallenge {
    pub id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub amount: String,
    pub currency: String,
    pub recipient: String,
    pub expires_at: Option<String>,
}

pub struct PaymentReceipt {
    pub challenge_id: String,
    pub method: String,
    pub reference: String,
    pub amount: String,
    pub currency: String,
    pub status: String,
    pub timestamp: String,
}

pub struct PaymentFailure {
    pub reason: String,
}

impl PaymentGate {
    pub fn new(config: &PaymentConfig) -> Self { ... }

    /// Evaluate whether a tool call should proceed, be challenged, or be denied.
    pub fn evaluate(
        &self,
        binding_payment: Option<&BindingPaymentConfig>,
        meta: Option<&Value>,
    ) -> PaymentEvaluation { ... }

    /// Serialize a receipt into a _meta Value for attachment to ToolCallResult.
    pub fn receipt_meta(receipt: &PaymentReceipt) -> Value { ... }

    /// Serialize a challenge into a JSON-RPC -32042 error data payload.
    pub fn challenge_error_data(challenge: &PaymentChallenge) -> Value { ... }
}
```

---

## Dispatch Integration

The `ToolsCall` branch in `GatewayRuntime::handle_protocol_operation()` currently follows this sequence:

1. Load session
2. Route tool (capability registry)
3. Evaluate policy (pre-dispatch policy gate)
4. Validate schema
5. Execute binding (execution dispatcher)
6. Return result

With payment, it becomes:

1. Load session
2. Route tool
3. Evaluate policy
4. Validate schema
5. **Evaluate payment** ← NEW
   - `NotRequired` → continue
   - `ChallengeRequired` → return JSON-RPC error `-32042`
   - `Verified` → continue, save receipt for step 7
   - `Failed` → return JSON-RPC error
6. Execute binding
7. **Attach receipt to result `_meta`** ← NEW
8. Return result

This is a narrow change to the `ToolsCall` match arm (~30 lines) and does not affect any other operation type.

---

## Per-binding cost telemetry (SQL backends)

The four payment plugins above gate `tools/call` at the **gateway dispatch
layer** with a flat or arg-derived per-call price, which works for the
common case but cannot price post-execution facts like rows returned or
payload bytes. SQL backends (`mcpg-plugin-backend-sql`) ship a
complementary mechanism — a `cost:` block on each backend spec — that
**emits structured billing telemetry after the driver returns**, instead of
issuing a new payment challenge. Downstream billing reconcilers (or the
same four payment plugins, configured to log rather than gate) consume
the metric stream.

```yaml
mcp:
  tools:
    - name: search_orders
      backend:
        kind: dev.mcpg.backend.sql
        config:
          driver: postgres
          url: ${DATABASE_URL}
          query:
            sql: "SELECT id, total FROM orders WHERE customer_id = :cid"
            params: ["cid"]
            row_mode: many
          cost:
            unit: per_row          # per_call | per_query | per_row | per_byte
            amount: "0.001"        # static decimal in `currency`
            # OR: expression: "arguments.tier == 'pro' ? 0.001 : 0.005"
            currency: USD
            max_per_call: "1.00"   # refuse calls that would charge more
```

**Units.** `per_call` and `per_query` are flat per-execution; `per_row`
multiplies by the number of returned rows; `per_byte` multiplies by the
serialized payload byte count. CEL `expression` may be used in place of
`amount` and is evaluated against the caller's `arguments` object.

**Refund accounting.** Every error path emits a refund counter
(`mcpg_sql_cost_refunded_total{binding,driver,currency,reason}`) with a
`reason` label of `timeout` / `transport` / `invalid_spec`, so
reconcilers can credit back any pre-charged amount the gateway-side
payment plugin would have collected.

**Safety cap.** When the post-execution amount would exceed
`max_per_call`, the call is **refused** with `BindingError::InvalidSpec`
— overcharging is worse than rate-limiting.

**Audit metadata.** Bindings with a `cost:` block surface
`db.cost.{unit,currency,source,max_per_call}` via the existing
`audit_metadata()` hook so audit search can filter on
`db.cost.unit=per_row`.

### Metrics — payment gate (challenge / verify path)

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_payment_challenges_total` | Counter | `tool_name`, `method` | Challenges issued |
| `mcpg_payment_verifications_total` | Counter | `tool_name`, `method`, `outcome` | Credential verifications (success/failed) |
| `mcpg_payment_verification_duration_seconds` | Histogram | `tool_name`, `method` | Verification latency |
| `mcpg_payment_revenue_cents_total` | Counter | `tool_name`, `method`, `currency` | Revenue tracked (informational) |

### Metrics — SQL cost telemetry (post-execution path)

Amounts are recorded in **micro-units** of the configured currency
(1 USD = 1_000_000) so integer counters preserve sub-cent precision.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mcpg_sql_cost_total` | Counter | `binding`, `driver`, `currency`, `unit` | Cumulative charge across successful calls |
| `mcpg_sql_call_cost` | Histogram | `binding`, `driver`, `currency`, `unit` | Per-call charge distribution (decimal) |
| `mcpg_sql_cost_refunded_total` | Counter | `binding`, `driver`, `currency`, `reason` | Refund signal on error paths |

### Structured Log Fields

| Field | When | Description |
|---|---|---|
| `payment_required` | Challenge issued | `true` |
| `payment_challenge_id` | Challenge issued / credential verified | Challenge identifier |
| `payment_method` | Any payment event | MPP method name |
| `payment_outcome` | Credential verified | `success` / `failed` |
| `payment_amount` | Credential verified | Amount charged |
| `payment_currency` | Credential verified | Currency code |

---

## Dependency: MPP Rust Crate

```toml
# In apps/gateway/Cargo.toml
[dependencies]
mpp = { version = "0.x", features = ["tempo", "server"] }
```

The `mpp` crate provides:
- `mpp::server::Mpp` — server instance with challenge issuance
- `mpp::server::tempo::TempoConfig` — Tempo method configuration
- `mpp::parse_authorization()` — parse credential from string
- `mpp::format_www_authenticate()` — format challenge as header (HTTP transport; used for reference)
- Axum extractor `MppCharge<T>` (optional — we implement our own gate)

If the `mpp` crate API does not match these signatures at implementation time, the `PaymentGate` can implement MPP challenge/credential handling directly from the IETF spec. The protocol is simple enough (HMAC challenge IDs, signature verification) that a from-spec implementation is feasible.

---

## Implementation Plan

### Payment Gate with Tempo (Crypto)

**Scope**: `PaymentGate` + config types + `_meta` passthrough + challenge/verify for Tempo method.

**Deliverables**:
- `PaymentConfig` and `BackendPaymentConfig` in config with validation rules and tests
- `_meta` field added to `ToolCallParams` (deserialization) and `ToolCallResult` (serialization)
- `PaymentGate` in `runtime/payment.rs` with Tempo challenge issuance and credential verification
- Integration into `ToolsCall` dispatch in `runtime/mod.rs`
- 4 payment metrics registered
- `config.example.yaml` updated with payment section
- Tests: no-payment passthrough, challenge issuance, credential verification success/failure, receipt attachment, config validation

**Not in scope**: Stripe, x402, pipeline payment step, dynamic pricing.

### Stripe Method

**Scope**: Add `method: "stripe"` support to `PaymentGate`.

**Deliverables**:
- Stripe credential verification (SPT validation via Stripe API or MPP Rust SDK when available)
- Per-binding method override (`payment.method: "stripe"`)
- Additional config fields for Stripe: `stripe_secret_ref` (env-based secret like OIDC introspection)

### tools/list Payment Metadata

**Scope**: Expose payment requirements in `tools/list` responses so agents can discover pricing before calling.

**Deliverables**:
- `ToolDescriptor` extended with optional `payment` field showing charge/currency/method
- Agents can inspect tool pricing without trial-and-error 402 responses

### Payment Pipeline Step

**Scope**: Add `payment` as a new pipeline step type for dynamic pricing.

**Deliverables**:
- `PipelineStepConfig::Payment` variant
- CEL expression for amount computation (`expression: 'string(size(original_args.data) * 10)'`)
- Suspension behavior (like elicitation) if client needs to sign new credential for computed amount

### x402 + ACP Adapters

**Scope**: Add alternative protocol adapters behind the `PaymentGate` trait.

**Deliverables**:
- x402 adapter: facilitator-based verify/settle for EVM payments
- ACP adapter: checkout session orchestration for full commerce flows
- Per-binding protocol selection (`payment.protocol: "mpp" | "x402" | "acp"`)

---

## Interaction with Existing Subsystems

### Identity

Payment and identity are complementary:
- A `Verified` identity + payment credential means "we know who is paying and they paid."
- An `Anonymous` identity + payment credential means "we don't know who, but they paid" — valid for crypto-native use cases.
- The policy gate can enforce `minimum_trust: verified` on paid tools to require both identity and payment.

### Policy

The policy gate runs **before** the payment gate. A policy-denied tool never reaches payment evaluation. This is correct: policy denial is free (no challenge issued, no payment attempted).

CEL expressions can reference payment-related context in a future extension (e.g., `payment_method == "stripe"` in `cel_allow_if`).

### Sessions

Challenge state (issued challenge ID, expiration, binding parameters) is stored in the session. This reuses the existing session store infrastructure. Challenge IDs are scoped to the session to prevent cross-session replay.

### Pipelines

Pipeline bindings execute through the same `ToolsCall` dispatch path. The payment gate applies identically — the pipeline tool is challenged/verified as a unit. Individual pipeline steps are not independently charged.

The `payment` pipeline step (below) enables per-step or dynamic pricing within pipelines.

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Challenge replay | Challenge IDs are HMAC-bound, single-use, and expire after `challenge_timeout_seconds` |
| Credential replay | Each credential is bound to a specific challenge ID; challenge is consumed on verification |
| Overpayment | Gateway verifies exact amount match between challenge and credential |
| Underpayment | Gateway rejects credentials with insufficient amount |
| Man-in-the-middle | TLS required for all transport (existing MCPG TLS config) |
| Credential logging | Payment credentials are bearer tokens — never logged. Structured logging excludes `_meta` credential values |
| Backend exposure | Backends never see payment credentials — the gateway strips `_meta["org.paymentauth/credential"]` before forwarding |
| Denial of service | Challenge issuance is lightweight (HMAC); verification is bounded by `challenge_timeout_seconds` |

---

## Testing Plan

### Config Tests (in `config/mod.rs`)

| Test | Assertion |
|---|---|
| `payment_config_defaults` | Default config has `enabled: false` |
| `payment_config_enabled_requires_recipient` | Validation error if enabled without recipient |
| `binding_payment_charge_must_be_nonnegative` | Validation error for negative charge |
| `binding_payment_currency_must_be_iso` | Validation error for invalid currency |
| `binding_payment_warn_when_disabled` | Warning when binding has payment but global is disabled |

### Payment Gate Tests (in `runtime/payment.rs`)

| Test | Assertion |
|---|---|
| `no_payment_config_passes_through` | `PaymentEvaluation::NotRequired` when binding has no payment config |
| `payment_required_issues_challenge` | `PaymentEvaluation::ChallengeRequired` when no credential in meta |
| `valid_credential_verifies` | `PaymentEvaluation::Verified` with correct receipt |
| `invalid_credential_fails` | `PaymentEvaluation::Failed` with reason |
| `expired_challenge_fails` | `PaymentEvaluation::Failed` for expired challenge |
| `wrong_amount_fails` | `PaymentEvaluation::Failed` for mismatched amount |
| `challenge_id_is_single_use` | Second verification with same challenge ID fails |
| `receipt_meta_serialization` | Receipt serializes to correct `_meta` structure |

### Integration Tests (in `runtime/mod.rs`)

| Test | Assertion |
|---|---|
| `tools_call_free_tool_no_payment` | Free tool returns result without `_meta` |
| `tools_call_paid_tool_no_credential` | Paid tool returns `-32042` with challenge |
| `tools_call_paid_tool_with_credential` | Paid tool returns result with receipt in `_meta` |
| `tools_call_paid_tool_invalid_credential` | Paid tool returns error |
| `policy_denied_tool_no_challenge` | Policy-denied paid tool returns policy error, not payment challenge |

### Protocol Tests (in `protocol/mod.rs`)

| Test | Assertion |
|---|---|
| `tool_call_params_deserializes_meta` | `_meta` field parsed from tools/call params |
| `tool_call_params_without_meta` | Missing `_meta` deserializes as `None` |
| `tool_call_result_serializes_meta` | `_meta` included in JSON when present |
| `tool_call_result_omits_meta_when_none` | `_meta` not in JSON when `None` |
