# MCPG Identity and Authorization

> How MCPG establishes caller identity and enforces tool access policy.
> Source: `runtime/identity.rs` (463 lines), `runtime/oidc.rs` (1,362 lines), `runtime/policy.rs` (547 lines)

## Layout D'' note

Layout D'' (P1) collapsed the four governance peers (`auth:`, `policy:`,
`approvals:`, `audit:`) under one umbrella, `governance:`. Identity
config now lives at `governance.access:` (renamed from `auth:` to
honestly name what the block does — *establish the caller's
identity*) and authorization at `governance.policy:`. Wire shapes
inside each block are unchanged from pre-D''. Env-var examples in
this doc use the D'' prefix `MCPG_GOVERNANCE__ACCESS__*` /
`MCPG_GOVERNANCE__POLICY__*`.

## Identity Model

MCPG uses a three-tier identity model. Every inbound request is classified into one of three trust levels:

```
Unauthenticated  <  HeaderAsserted  <  Verified
```

### Identity Variants

| Variant | Trust Level | Source | Fields |
|---|---|---|---|
| `Anonymous` | `Unauthenticated` | No identity headers | `source` |
| `HttpHeader` | `HeaderAsserted` | `x-mcpg-subject-id` header | `subject_id`, `source` |
| `Verified` | `Verified` | JWT/OIDC verification | `subject_id`, `issuer`, `auth_provider`, `source` |

### Resolution Priority

The HTTP transport resolves identity in this order (first match wins):

1. **OIDC/OAuth resolver** (async) — if `governance.access.oidc_oauth` is configured
2. **JWKS verifier** (sync) — if `governance.access.jwks` is configured
3. **Header-asserted** — if `x-mcpg-subject-id` header is present
4. **Anonymous** — fallback

## JWKS Verification (Legacy)

The `JwtVerifier` (`runtime/identity.rs`) provides stateless JWT verification against a pre-loaded JWKS key set.

**Capabilities**:
- Multiple JWK keys (selected by `kid` header)
- Supported algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA
- Issuer validation (optional)
- Audience validation (optional)
- Expiration and `nbf` validation
- Configurable header name and prefix

**Configuration**:
```yaml
governance:
  access:
    jwks:
      url: "https://auth.example.com/.well-known/jwks.json"
      keys_json: '{"keys": [...]}'    # Alternative: inline JWKS
      issuer: "https://auth.example.com/"
      audience: "mcpg"
      header_name: "authorization"
      header_prefix: "Bearer "
```

**Verification result**:
- `Verified { subject, issuer }` — Token valid, `sub` claim extracted
- `NoToken` — No token found in headers
- `Invalid(reason)` — Token present but verification failed

## OIDC/OAuth Verification (Enterprise)

The `OidcOAuthResolver` (`runtime/oidc.rs`) provides enterprise-grade bearer token federation with dynamic OIDC discovery and multiple identity providers.

### Provider Model

Each configured provider has:
- **Issuer** — OIDC issuer URL (e.g., `https://login.example.com/`)
- **Discovery URI** — defaults to `{issuer}/.well-known/openid-configuration`
- **Audiences** — accepted audience values
- **Verification mode** — one of three strategies
- **Claim mappings** — how JWT/introspection claims map to gateway identity
- **Clock skew tolerance** — seconds of clock drift allowed

### Verification Strategies

**1. OIDC JWKS** (`kind: oidc_jwks`)
- Fetches OpenID Connect discovery document
- Extracts `jwks_uri` from discovery
- Fetches and caches JWKS keys
- Verifies JWT tokens locally (no network call per request after cache warm)
- Key cache with configurable refresh interval and max staleness
- `kid`-miss triggers immediate JWKS refresh

**2. OAuth Introspection** (`kind: oauth_introspection`)
- Sends token to introspection endpoint (RFC 7662)
- Authenticates with `client_id` + `client_secret` (HTTP Basic)
- Checks `active: true` in response
- Validates issuer and audience from introspection response
- Secret reference supports `env:VAR_NAME` for environment variable resolution

**3. Hybrid** (`kind: hybrid`)
- First attempts JWKS-based JWT verification
- On JWT failure, falls back to introspection
- Useful for providers that issue both JWTs and opaque tokens

### Multi-Provider Resolution

When a request arrives:
1. Extract bearer token from configured source (Authorization header or custom header)
2. Decode the token's `iss` claim without verification (base64 decode)
3. Route to the provider whose `issuer` matches
4. If no issuer match, try all providers sequentially
5. Return the first successful verification, or aggregate failures

### Claim Mapping

The `ClaimMappingConfig` controls how verified claims are transformed into the gateway's identity model:

```yaml
claim_mappings:
  subject_claim: "sub"           # Which claim becomes the subject ID
  group_claim_paths:             # Dotted JSON paths for group membership
    - "groups"                   # Top-level "groups" array
    - "realm_access.roles"       # Nested: realm_access → roles array
  role_claim_paths:              # Dotted JSON paths for roles
    - "roles"
  scope_claim_paths:             # Dotted JSON paths for OAuth scopes
    - "scope"                    # Space-delimited scope string
    - "scp"                      # Array-form scopes
  attribute_claim_mappings:      # Static claim → attribute mapping
    email: "email"
    department: "department"
```

**Dotted path extraction**: `realm_access.roles` navigates to `claims["realm_access"]["roles"]`. Produces string arrays from JSON arrays, strings, or `null` (empty).

**Scope parsing**: A space-delimited string like `"read write admin"` is split into `["read", "write", "admin"]`.

### OidcIdentity Output

Successful OIDC verification produces:
```rust
OidcIdentity {
    subject_id: String,          // From subject_claim
    issuer: String,              // Provider's issuer URL
    provider_label: String,      // Provider identifier
    groups: Vec<String>,         // From group_claim_paths
    roles: Vec<String>,          // From role_claim_paths
    scopes: Vec<String>,         // From scope_claim_paths
    attributes: BTreeMap<String, String>,  // From attribute_claim_mappings
}
```

This maps to `RequestIdentity::Verified` for downstream authorization.

### Caching Behavior

| Component | Cache Type | Refresh | Staleness |
|---|---|---|---|
| Discovery document | Per-provider RwLock | `refresh_interval_secs` | N/A (always fetched on miss) |
| JWKS keys | Per-provider RwLock | `refresh_interval_secs` | `max_staleness_secs` on fetch failure |
| Introspection | Not cached | Per-request | N/A |

**Fail-closed behavior**: If discovery fetch fails and no cache exists, verification fails. If JWKS fetch fails but cached keys are within `max_staleness_secs`, cached keys are used. If cache exceeds max staleness, verification fails.

---

## Authorization (Pre-Dispatch Policy)

The `PreDispatchPolicyGate` (`runtime/policy.rs`) evaluates tool access before execution dispatch.

### Evaluation Sequence

```
1. Trust Level Check
   └─ Caller's trust_level >= tool's minimum_trust?
      └─ No → Deny (error -32003)

2. Global CEL Policy
   └─ governance.policy.tool_access.cel_allow_if evaluates to true?
      └─ No → Deny (error -32022)

3. Per-Tool CEL Policy
   └─ governance.policy.tool_access.rules[tool_name].cel_allow_if evaluates to true?
      └─ No → Deny (error -32005)

4. Allow → Proceed to execution
```

### CEL Context Variables

| Variable | Type | Description |
|---|---|---|
| `tool_name` | string | Name of the tool being called |
| `trust_level` | string | Caller's trust level ("unauthenticated", "header_asserted", "verified") |
| `principal_id` | string | Subject ID from identity (empty if anonymous) |
| `auth_provider` | string | Auth provider label (empty if not verified) |
| `identity_kind` | string | Identity variant name ("anonymous", "http_header", "verified") |

### Tool Visibility

The policy gate also controls tool visibility. `is_tool_visible()` determines whether a tool appears in `tools/list` responses. Denied tools are hidden from discovery.

### Policy Denial Response

When a tool call is denied, the response is a structured JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32003,
    "message": "trust requirement not met: tool 'sensitive_tool' requires 'verified' but caller has 'unauthenticated'"
  }
}
```

Error codes:
- `-32003` — Trust requirement not met
- `-32022` — Global CEL `allow_if` denied
- `-32005` — Per-tool CEL `allow_if` denied
