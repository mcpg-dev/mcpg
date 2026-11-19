# MCPG MCP Compliance — Canonical Reference

> **Single source of truth** for MCPG's compliance posture against
> Model Context Protocol revision **2026-07-28**.

| | |
|---|---|
| **Spec revision** | `2026-07-28` (the only revision MCPG serves) |
| **Upstream conformance suite** | **93 / 93** active checks pass (47 scenarios), a required CI job |
| **Supported-feature matrix** | [`compliance-support.md`](compliance-support.md) |
| **Conformance runs** | [mcpg.dev/docs/security/compliance](https://mcpg.dev/docs/security/compliance) |
| **How MCPG serves the revision** | [mcpg.dev/docs/gateway/protocol-versions](https://mcpg.dev/docs/gateway/protocol-versions) |
| **Operator config + metrics** | [`../configuration.md`](../configuration.md) |
| **SRE alerting** | [`../observability.md`](../observability.md) |

## How to read these documents

1. **`compliance-support.md`** — the feature matrix. Operators and
   integrators read this first; it answers "does MCPG support X?".
2. **This file** — the headline posture and the verification
   methodology behind the claims in `compliance-support.md`.

## What the claim covers

MCP `2026-07-28` as a server: the per-request `_meta` context and
`server/discover` (SEP-2575), the SEP-2243 routing headers, MRTR
(SEP-2322) with an AEAD-bound, single-use `requestState`,
`subscriptions/listen`, the tasks extension (SEP-2663), the caching
pair (SEP-2549), the error-code allocation (`-32020` / `-32021` /
`-32022`), JSON Schema 2020-12 tool schemas (SEP-2106), and the
authorization Resource-Server profile. Every claim is backed by a
regression test, a conformance scenario, or a file-citable
implementation site, and the suites below must stay green to keep
it.

`sampling/createMessage.maxTokens` serialisation is covered by a
regression test in `libs/mcp-wire/src/shared/server_requests.rs`.

## What the claim does *not* mean

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
- **Known limitations** are listed in
  [`compliance-support.md`](compliance-support.md#known-not-yet-done).

## Hardening summary

The knobs and metrics referenced below are documented in detail in
`apps/gateway/docs/configuration.md` (per-block reference) and
`apps/gateway/docs/observability.md` (operational metrics). Grouped
by hardening area:

- **Payment** — payment plugin error codes sit outside the
  MCP-reserved JSON-RPC range.
- **Identity & transport security** — authentication before the
  version check, OIDC audience required, HMAC opt-in, OIDC SSRF
  guard, origin check, cancellation bus partitioning per principal,
  owner checks on tasks, listen streams, MRTR resumes and
  cancellation, log redactor, media-range Accept parsing.
- **Protocol correctness** — one version check before dispatch,
  `Mcp-Method` / `Mcp-Name` cross-checks, deterministic list
  ordering, POST body cap, cursor HMAC binding, typed
  `includeContext`, `statusMessage` propagation, completion rate
  limit.
- **Trace context** — SEP-414 trace context in `_meta`.
- **Wire-rule strictness** — `id` validation, `progressToken`
  typing, `_meta` reserved-prefix policing, RFC 3986 URI
  normalization, SamplingMessage invariant, Redis preflight, JWKS
  circuit breaker, passthrough guard, insecure-bind warning.
- **Adversarial hardening** — scheme allow-list, monotonic
  progress, per-principal session-row cap, schema composition
  bounds and the network-`$ref` ban.
- **Elicitation safety** — SEP-1330 primitive-only schemas.

## Source-of-truth ordering

If any of these documents diverges from the implementation, the
implementation wins. Re-align in this order:

1. Code and tests (`apps/gateway/src/...`, `apps/gateway/tests/...`).
2. `compliance-support.md` (operator-facing).
3. This file's headline posture.

The conformance tests that must stay green to claim compliance:

- `apps/gateway/conformance/run.sh 2026-07-28` (the upstream suite)
- `apps/gateway/tests/transport_conformance.rs`
- `apps/gateway/tests/conformance_matrix.rs`
- `apps/gateway/src/runtime/invocation.rs` tests
- `apps/gateway/src/runtime/stores/task_store.rs` tests
- the `cargo test -p mcpg --lib` suite
