# MCPG MCP Compliance — Canonical Reference

> **Single source of truth** for MCPG's compliance posture against
> Model Context Protocol revision **2025-11-25**.

| | |
|---|---|
| **Spec revision** | `2025-11-25` |
| **MUST compliance** | **100 %** |
| **SHOULD compliance** | **~99.5 %** |
| **Production readiness** | **~98 %** |
| **Supported-feature matrix** | [`compliance-support.md`](compliance-support.md) |
| **Operator config + metrics** | [`../configuration.md`](../configuration.md) |
| **SRE alerting** | [`../observability.md`](../observability.md) |

## How to read these documents

1. **`compliance-support.md`** — the feature matrix. Operators and
   integrators read this first; it answers "does MCPG support X?"
   and links every claim to a tier tag.
2. **This file** — the canonical headline numbers and the
   verification methodology behind the claims in
   `compliance-support.md`.

## Current status

MUST compliance is complete and SHOULD compliance is ~99.5 % against
MCP `2025-11-25` (assessed 2026-04-15); every claim is backed by a
regression test or a file:line-citable implementation site, and the
conformance suites below must stay green to keep the claim.

## What "100 % MUST" actually covers

Every normative MUST in MCP 2025-11-25 — base protocol, JSON-RPC
envelope rules (incl. 2025-06-18 deltas), lifecycle, transports
(Streamable HTTP + stdio + SSE), authorization, all utilities
(cancellation, progress, ping, logging), all server features
(tools, resources, prompts, completion, pagination), all client
features (elicitation, sampling, roots, tasks), and every Final
SEP applicable to a server — is implemented and asserted by a regression or conformance test.

`sampling/createMessage.maxTokens` optional serialisation is covered
by a regression test in `apps/gateway/src/protocol/`.

## What "100 %" does *not* mean

- **Client-scoped requirements.** Some SEPs (e.g. SEP-1034
  elicitation default-value validation) are about how *clients*
  render or validate; MCPG passes through the relevant fields
  unchanged, which is the correct server behaviour.
- **Operator misconfiguration.** Several knobs default to safe
  values but can be loosened (e.g. `auth.jwks.allow_missing_audience`,
  `MCPG_ALLOW_HEADER_PASSTHROUGH=1`, `verification.allow_hmac=true`).
  Running with those flags set is non-compliant by definition; loud
  warnings + metrics surface the condition.
- **Beta plugins.** `mcpg-plugin-call-logger` is Beta because its
  default behaviour (full payload capture) requires the redactor
  paired in. See `apps/gateway/docs/plugins.md`.

## Hardening summary

The knobs and metrics referenced below are documented in detail in
`apps/gateway/docs/configuration.md` (per-block reference) and
`apps/gateway/docs/observability.md` (operational metrics). Grouped
by hardening area:

- **Payment** — payment plugin error codes migrated off the
  MCP-reserved JSON-RPC range.
- **Identity & transport security** — OIDC audience required, HMAC
  opt-in, OIDC SSRF guard, cancellation bus partitioning per
  principal, sampling capability gating, subscription cascade on
  terminate, log redactor, media-range Accept parsing.
- **Protocol correctness** — deterministic list ordering, POST body
  cap, init-cancel rejection, cursor HMAC binding, typed
  `includeContext`, `statusMessage` propagation, completion rate
  limit.
- **Trace context** — SEP-414 trace context in `_meta` (outbound +
  inbound).
- **Wire-rule strictness** — `id` validation + uniqueness,
  `progressToken` typing, `_meta` reserved-prefix policing, RFC
  3986 URI normalization, SSE retry default, server-initiated ping,
  experimental capability echo, SamplingMessage invariant, graceful
  drain, Redis preflight, JWKS circuit breaker, passthrough guard,
  insecure-bind warning.
- **Adversarial hardening** — scheme allow-list, SEP-2260
  choke-point, request-id window, log notification rate limit,
  legacy protocol version fallback, monotonic progress, per-tenant
  session quota.
- **Spec MUST closure** — `maxTokens` always serialised, progress
  state pruning, operator-extensible URI scheme list.
- **Elicitation & release safety** — SEP-1330 enforcement, SEP-2260
  release panic opt-in, dead-code sweep, documentation refresh.

## Source-of-truth ordering

If any of these documents diverges from the implementation, the
implementation wins. Re-align in this order:

1. Code and tests (`apps/gateway/src/...`, `apps/gateway/tests/...`).
2. `compliance-support.md` (operator-facing).
3. This canonical file's headline numbers.

The conformance tests that must stay green to claim compliance:

- `apps/gateway/tests/transport_conformance.rs`
- `apps/gateway/tests/conformance_matrix.rs`
- `apps/gateway/src/runtime/invocation.rs` tests
- `apps/gateway/src/runtime/task_store.rs` tests
- The 727-strong `cargo test -p mcpg --lib` suite
