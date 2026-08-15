# String interpolation — the `${…}` grammar

MCPG resolves `${…}` placeholders inside string config values (a backend's
`url`, a `headers` value, a SQL connection `url`, a NATS `auth_token`, …)
and substitutes a value. **One delimiter, `${…}`, covers every kind of
substitution** — environment variables, credential references, and
per-request expressions.

```yaml
backend:
  kind: http
  url: "https://api.example.com/${arguments.path}"
  headers:
    Authorization: "Bearer ${cred://dev.mcpg.credential.oauth-client-credentials/notion}"
    X-Region: "${env.DEPLOY_REGION}"
    X-Caller: "${context.principal_id}"
```

## What you can put inside `${…}`

| Form | Resolves to | When | Notes |
|---|---|---|---|
| `${env.NAME}` | the value of environment variable `NAME` | **config load** (startup) | Errors if the variable is unset. |
| `${cred://<plugin_id>/<target>}` | a credential minted/fetched by a credential-issuer plugin | **per request**, per caller identity | Optional `#part` selects a sub-field: `${cred://vault-pg/orders#username}`. |
| `${arguments.<field>}` | a field of the tool-call arguments | per request | Full CEL — see below. |
| `${context.<field>}` | a field of the request context (see table) | per request | Identity/session/transport facts. |
| `${steps.<step_id>.<field>}` | the output of an earlier pipeline step | per request | Only populated inside a pipeline. |
| `${tool_name}` | the invoked tool's name | per request | |
| `${<expr>}` | the result of any CEL expression over the above | per request | e.g. `${arguments.count > 10 ? "high" : "low"}`. |

### `${context.*}` fields

`principal_id`, `trust_level`, `auth_provider`, `session_id`, `transport`,
`roles` (list), `groups` (list), `scopes` (list), `attributes` (map).

For ergonomics, the common ones are **also** exposed bare at the top level:
`${principal_id}`, `${trust_level}`, etc. — handy in policy-style expressions.

### Anything else is CEL

Every `${…}` that isn't `env.*` or `cred://…` is compiled as a
[CEL](https://github.com/google/cel-spec) expression evaluated against the
request. So you are not limited to a bare variable:

```yaml
url: "https://api.example.com/v${arguments.major}/${arguments.path}"
headers:
  X-Tier: "${has(arguments.premium) && arguments.premium ? \"gold\" : \"standard\"}"
  X-Roles: "${context.roles.join(\",\")}"
```

A whole value may be a single expression, or expressions may be embedded in
literal text (the literal parts are kept verbatim and the expressions are
concatenated as strings).

## When each layer resolves

The layers run at different times, which matters for security:

1. **Config load (startup):** `${env.NAME}` is substituted once, from the
   process environment, before the config reaches any plugin.
2. **Per request, per caller identity:** `${cred://…}` is resolved through
   the credential subsystem against the *caller's* identity (so different
   callers can get different secrets — see
   [`per-caller-credentials.md`](./per-caller-credentials.md)).
3. **Per request (per call):** `${arguments.*}`, `${context.*}`,
   `${steps.*}`, `${tool_name}`, and any CEL expression are evaluated from
   the live request.

## Security model (read this)

The grammar is designed so a **malicious caller cannot extract secrets**:

- **`${env.*}` is config-load-only.** A request argument that happens to
  contain the literal text `${env.SECRET}` is never expanded — it travels
  through as data.
- **`cred://` resolves only inside a `${cred://…}` token in operator
  config.** Credential references are parsed from the operator's template
  *at compile time*, so they are config-origin **by construction**. A
  request argument substituted into a `${arguments.x}` expression is only a
  value; it is never re-parsed, so a caller cannot smuggle
  `${cred://issuer/target}` (or a bare `cred://…`) through an argument and
  have it resolved.
- **A bare `cred://…` outside `${}` is *not* a credential reference.** In a
  templated value it travels verbatim. (The one exception is a *dedicated
  credential-reference field* such as a federation's `auth.credential`,
  whose entire value is a `cred://` URI by type — there is no template and
  therefore no ambiguity.)
- Resolved credentials never appear in error messages returned to callers
  (credential-resolution failures surface an opaque correlation id), and
  the inbound `Authorization` bearer is never reflected into a response.

## Backwards compatibility

The `$`-prefixed forms still work: `${env.NAME}`, `${arguments.x}`,
`${context.principal_id}`. The bare forms (`${env.NAME}`,
`${arguments.x}`) are the standard going forward; prefer them in new
config.

## Worked examples

```yaml
# HTTP backend: caller bearer minted per identity, region from env,
# a path segment from the tool arguments.
- name: search
  backend:
    kind: http
    method: post
    url: "https://${env.SEARCH_HOST}/v1/${arguments.index}/query"
    headers:
      Authorization: "Bearer ${cred://dev.mcpg.credential.oauth-token-exchange/search}"
      X-Tenant: "${context.attributes.tenant}"

# SQL backend: the DSN password comes from a credential issuer; the rest
# of the connection string is static config.
- name: orders
  backend:
    kind: sql
    url: "postgres://app:${cred://dev.mcpg.credential.vault-dynamic-db/orders}@db:5432/orders"

# Pipeline step referencing an earlier step's output.
  url: "https://api.example.com/items/${steps.lookup.id}"
```

## Where it's implemented

The grammar engine is `libs/expr` (`DynamicValue` + the `${cred://…}`
segment parser + `resolve_env_in_string`). The `${cred://…}` token helpers
shared by non-CEL backends are `mcpg_plugin_protocol::credential::{cred_tokens,
substitute_cred_tokens}`. The config secret-scanner
(`mcpg config secrets`) recognizes every `${env.*}` and `${cred://…}` in a
config so operators can audit what a deployment references.
