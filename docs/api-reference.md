# MCPG API Reference

> HTTP transport endpoints, MCP protocol operations, and SSE streaming.
> Source: `transports/http/` (router, request path, SSE, identity, validation,
> response mapping), `transports/dispatch.rs`, `protocol/`

## HTTP Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |
| `GET` | `/runtime` | Runtime metadata |
| `POST` | `/mcp` | MCP JSON-RPC requests |
| `GET` / `HEAD` / `DELETE` | `/mcp` | `405 Method Not Allowed` with `Allow: POST` (after the browser redirect, the origin check and authentication) |
| `GET` | `/metrics` | Prometheus metrics (if enabled) |

---

## MCP Protocol

MCPG supports MCP **`2026-07-28`** over Streamable HTTP (JSON-RPC 2.0). There is
no handshake and no protocol session: every request is self-contained.

### Protocol Version

```
Supported:  2026-07-28
```

Transport rules:
- `POST /mcp` accepts exactly one JSON-RPC request or notification body
- JSON-RPC batch arrays are rejected on the primary endpoint
- every request names the version, with the `Mcp-Protocol-Version: 2026-07-28`
  header or the `_meta` key `io.modelcontextprotocol/protocolVersion`
- a request that names another version, or none, gets HTTP `400` and JSON-RPC
  `-32022` with `data.supported: ["2026-07-28"]`
- authentication runs before the version check, so a caller without
  credentials gets the `401` challenge first
- every response carries `Mcp-Protocol-Version: 2026-07-28`

### Request/Response Headers

**Request headers**:
- `Content-Type: application/json` — Required for POST
- `Accept: application/json` — Required for POST; the minimum, and the response
  is then inline JSON. Add `text/event-stream`
  (`Accept: application/json, text/event-stream`) to consent to an SSE
  response — a `tools/call` that emits progress or log notifications, and
  `subscriptions/listen`
- `Mcp-Protocol-Version: 2026-07-28` — Required
- `Mcp-Method: {method}` — Required; must equal the body's `method`
  (`-32020` on mismatch)
- `Mcp-Name: {name}` — Required for `tools/call` and `prompts/get` (the
  `params.name`) and `resources/read` (the `params.uri`); a non-ASCII value is
  sent as `=?base64?…?=`
- `Mcp-Param-{Name}: {value}` — Optional promotions of tool arguments the
  tool's `inputSchema` marks with `x-mcp-header`; each must equal the argument

No session or resume-cursor request header is read.

**Response headers**:
- `X-Mcpg-Request-Id: {uuid}` — Gateway request ID (all responses)
- `Mcp-Protocol-Version: 2026-07-28` — All responses
- `X-Accel-Buffering: no` — On every `text/event-stream` response (an
  SSE-framed `tools/call` result, `subscriptions/listen`, `events/stream`). An
  nginx-family proxy in front of the gateway (nginx, APISIX, OpenResty) honours
  it per response and streams the body instead of holding it until the
  upstream closes — which an event stream never does on its own, so a
  buffering proxy shows the client no status line at all. A proxy that does
  not honour it needs its response buffering turned off for the MCP route.

### Request `_meta`

Every request carries its client context in `params._meta`:

| Key | Value |
|---|---|
| `io.modelcontextprotocol/protocolVersion` | `"2026-07-28"` |
| `io.modelcontextprotocol/clientInfo` | `{ "name": …, "version": … }` |
| `io.modelcontextprotocol/clientCapabilities` | The client's capabilities (`elicitation`, `sampling`, `roots`, `extensions`) |
| `io.modelcontextprotocol/logLevel` | Optional. The request's log floor; absent ⇒ no `notifications/message` for the request |
| `io.modelcontextprotocol/progressToken` | Optional. Progress token for the request |

`server/discover` requires the first three keys. Other methods require them
when `gateway.server.enforce_request_meta` is `true`.

The gateway reads the client's extensions from
`clientCapabilities.extensions` on each request, and from nowhere else. An
extension's settings object may carry a `revision` string. No `revision`
means the extension's initial revision, which is the revision the gateway
implements for the Tasks, Skills and Events extensions. An extension declared
with any `revision` is not enabled for that request. The gateway's own
declarations in `server/discover` carry no `revision`.

---

## A minimal client

```bash
U=https://gateway.example/mcp
META='"_meta": {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { "name": "my-client", "version": "1.0.0" },
  "io.modelcontextprotocol/clientCapabilities": {} }'
H=(-H 'Content-Type: application/json' -H 'Accept: application/json'
   -H 'Mcp-Protocol-Version: 2026-07-28')

# 1. server/discover — capabilities, extensions, supported versions.
curl -sS -X POST "$U" "${H[@]}" -H 'Mcp-Method: server/discover' -d "{
  \"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"server/discover\",
  \"params\": { $META } }" | jq .result

# 2. tools/list
curl -sS -X POST "$U" "${H[@]}" -H 'Mcp-Method: tools/list' -d "{
  \"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"tools/list\",
  \"params\": { $META } }" | jq '.result.tools[].name'

# 3. tools/call — Mcp-Name carries the tool name.
curl -sS -X POST "$U" "${H[@]}" -H 'Mcp-Method: tools/call' -H 'Mcp-Name: ping' -d "{
  \"jsonrpc\": \"2.0\", \"id\": 3, \"method\": \"tools/call\",
  \"params\": { \"name\": \"ping\", \"arguments\": {}, $META } }" | jq .result
```

Two rules carry most of the weight:

1. **`Accept: application/json` alone means inline JSON for every response.**
   With `text/event-stream` added, a `tools/call` that emits notifications
   answers with an SSE stream: the notifications first, then the frame whose
   `id` matches the request. A parser that takes the first `data:` frame as
   the answer reads a notification as its result.
2. **A notification carries no `id`.** `notifications/cancelled` sent with an
   `id` is a *request* for a method that does not exist.

---

## MCP Operations

### Discover

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "server/discover",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { "name": "my-client", "version": "1.0.0" },
      "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} }
    }
  }
}
```

The result carries `supportedVersions: ["2026-07-28"]`, the server's
`capabilities` (with the `extensions` map: `io.modelcontextprotocol/tasks`,
`io.modelcontextprotocol/skills`, `io.modelcontextprotocol/ui`,
`dev.mcpg/idempotency` when configured), `serverInfo`, `resultType`, `ttlMs`
and `cacheScope`.

### List Tools

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": { "_meta": { … } } }
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "resultType": "complete",
    "tools": [
      {
        "name": "my_tool",
        "description": "Does something",
        "inputSchema": {
          "type": "object",
          "properties": { "input": { "type": "string" } }
        }
      }
    ],
    "ttlMs": 60000,
    "cacheScope": "private"
  }
}
```

Tools filtered by policy (denied tools hidden from list).

### Call Tool

**Request** (with `Mcp-Name: my_tool`):
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "my_tool",
    "arguments": { "input": "hello" },
    "_meta": { … }
  }
}
```

**Response** (success):
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "resultType": "complete",
    "content": [
      { "type": "text", "text": "result data" }
    ],
    "isError": false
  }
}
```

**Response** (the call needs client input — HTTP 200, `InputRequiredResult`):
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "resultType": "input_required",
    "inputRequests": {
      "ask_user": {
        "method": "elicitation/create",
        "params": {
          "message": "Please confirm the operation:",
          "requestedSchema": { "type": "object", "properties": { "confirmed": { "type": "boolean" } } }
        }
      }
    },
    "requestState": "c.…"
  }
}
```

The client gets the input and calls the tool again with the same `name` and
`arguments`, plus `requestState` and `inputResponses` as **top-level params**
(under `_meta` they are refused with `-32600`):

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "my_tool",
    "arguments": { "input": "hello" },
    "requestState": "c.…",
    "inputResponses": {
      "ask_user": { "action": "accept", "content": { "confirmed": true } }
    },
    "_meta": { … }
  }
}
```

The call resumes where it stopped. A `requestState` is bound to the caller who
paused the call and is accepted once. `inputRequests` may carry several entries
(the `gather` pipeline step); each `inputRequests` entry is an
`elicitation/create`, `sampling/createMessage` or `roots/list` request, emitted
only when the request's `clientCapabilities` support it.

**Response** (task): a tool whose `execution.taskSupport` allows it, called by a
client that declared the `io.modelcontextprotocol/tasks` extension, answers
`resultType: "task"` with a `taskId`, `ttlMs` and `pollIntervalMs`. The client
polls `tasks/get`, answers input with `tasks/update`, and cancels with
`tasks/cancel`. The gateway declares the extension as
`"io.modelcontextprotocol/tasks": {}`. A `tasks/get`, `tasks/update` or
`tasks/cancel` request, or a `subscriptions/listen` request for `taskIds`, that
does not declare the extension gets HTTP 400 with error `-32021` (Missing
Required Client Capability) and
`data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"]`.

### List Prompts / Get Prompt

```json
{ "jsonrpc": "2.0", "id": 5, "method": "prompts/list", "params": { "_meta": { … } } }
```

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "prompts/get",
  "params": { "name": "mcpg_operational_overview", "_meta": { … } }
}
```

### List Resources / Read Resource

```json
{ "jsonrpc": "2.0", "id": 7, "method": "resources/list", "params": { "_meta": { … } } }
```

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "resources/read",
  "params": { "uri": "mcpg://runtime/overview", "_meta": { … } }
}
```

### Cancel

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/cancelled",
  "params": { "requestId": 3, "reason": "user aborted" }
}
```

Answered `202 Accepted`. Only the caller that started the request can cancel
it.

---

## SSE Streaming

### Per-request stream (`tools/call`)

A `tools/call` that emits `notifications/progress` or `notifications/message`
for the request answers with `Content-Type: text/event-stream` when the client
accepts it: each notification as an SSE `message` event, in order, then the
JSON-RPC response frame, then the stream closes. A call that emits nothing
answers inline. SSE events carry no `id:`; a broken stream is not resumed, and
the client issues the request again.

### `subscriptions/listen`

A long-lived POST that returns `text/event-stream`. Its params select what the
stream carries:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "subscriptions/listen",
  "params": {
    "notifications": {
      "toolsListChanged": true,
      "promptsListChanged": true,
      "resourcesListChanged": true,
      "resourceSubscriptions": ["mcpg://runtime/overview"]
    },
    "_meta": { … }
  }
}
```

The first event acknowledges the subscription. Then the stream carries
`notifications/*/list_changed`, `notifications/resources/updated` for the
subscribed URIs, and `notifications/tasks` for the task ids named in
`taskIds` (or `eventsListChanged` for MCP Events). A caller holds at most 3
concurrent listen streams per session row.

### `events/stream`

MCP Events push streams; see the MCP Events guide.

---

## Error Responses

### Protocol Errors

| Code | Meaning |
|---|---|
| `-32700` | Parse error (invalid JSON) |
| `-32600` | Invalid request (missing fields) |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32020` | Header mismatch (`Mcp-Method` / `Mcp-Name` / `Mcp-Param-*` against the body) |
| `-32021` | Missing required client capability |
| `-32022` | Unsupported protocol version |

### Gateway Errors

| Code | Meaning |
|---|---|
| `-32003` | Trust requirement not met (policy) |
| `-32005` | Per-tool CEL policy denied |
| `-32000` | Session capacity exhausted (per-principal session-row cap) |
| `-32099` | Rate limit exceeded |

### HTTP Status Codes

| Status | When |
|---|---|
| 200 | Successful JSON-RPC response, `InputRequiredResult`, task created |
| 202 | Notification accepted |
| 400 | Bad request (missing headers, invalid JSON, unsupported or missing protocol version, header mismatch) |
| 401 | Authentication required or credential invalid |
| 403 | Origin rejected, policy denial |
| 404 | Unknown endpoint, or a method the revision does not define |
| 405 | `GET` / `HEAD` / `DELETE` on the MCP path |
| 500 | Internal server error |
| 503 | Session capacity exhausted |

---

## Identity Headers

| Header | Direction | Description |
|---|---|---|
| `Authorization: Bearer {token}` | Request | JWT/OIDC bearer token |
| `x-mcpg-subject-id: {subject}` | Request | Header-asserted identity |
| `Mcp-Protocol-Version: {ver}` | Both | Protocol version (`2026-07-28`) |
| `X-Mcpg-Request-Id: {rid}` | Response | Gateway request ID |

---

## HTTP status ↔ JSON-RPC error code mapping

Every MCPG response carries **both** an HTTP status code and a
JSON-RPC envelope. They are deliberately decoupled: the HTTP status
describes the transport-layer outcome; the JSON-RPC `error.code`
(when the envelope is an `error`) describes the application-layer
outcome. The table below pins the cases where both are relevant.

| HTTP | JSON-RPC code | When | Notes |
|---|---|---|---|
| 200  | n/a        | Successful JSON-RPC result | `result` populated; no `error`. |
| 200  | n/a        | `InputRequiredResult` | `resultType: "input_required"`; the client retries with `requestState` + `inputResponses`. |
| 200  | `-32602`   | `tools/call` with bad arguments | `isError: true` `ToolCallResult` is still 200 + success envelope. Distinct from protocol `-32602`. |
| 202  | n/a        | Notification accepted | |
| 400  | `-32022`   | Protocol version absent or not `2026-07-28` | `data.supported: ["2026-07-28"]`; `data.requested` when a version was named. |
| 400  | `-32020`   | `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*` header does not match the body | |
| 400  | `-32600`   | `id` violates JSON-RPC 2.0 (null, bool, object, array, empty string) | |
| 400  | `-32600`   | `Mcp-Protocol-Version` header is not valid UTF-8 | |
| 400  | `-32600`   | Batch array on POST body | |
| 400  | `-32600`   | Missing `Accept` or non-SSE-compatible Accept | |
| 400  | `-32602`   | `_meta.progressToken` not string or non-empty number | |
| 400  | `-32600`   | `_meta` key uses an MCP-reserved prefix, or carries `requestState` / `inputResponses` | |
| 401  | `-32000`   | Identity gate: a presented credential is invalid, expired, or bound to another audience | `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"`. |
| 401  | `-32003` / `-32022` | Policy refused a caller that presented **no** credential (trust floor, CEL `allow_if`) while a bearer verifier (`jwks` / `oidc_oauth`) is configured | `WWW-Authenticate: Bearer resource_metadata="…"`. The URL names the metadata of the hostname the request arrived on (`Host`, or `X-Forwarded-Host` behind a trusted proxy), so an OAuth host starts its flow against the URL it connected to. Without a verifier the refusal stays a 403. |
| 402  | `-33042`   | Payment required (MPP, UCP, ACP) | Plugin-specific `-33050`..`-33061` when the plugin surfaces its own variant. |
| 403  | `-32003`   | An authenticated caller is below a tool's trust floor, or lacks a required scope | A scope denial carries `error="insufficient_scope"` and the required `scope=` (SEP-2350); a bare 403 carries no challenge — re-authenticating cannot help. |
| 403  | `-32022`   | CEL `allow_if` denial for an authenticated caller | |
| 403  | n/a        | Origin rejection | Empty body. Origin not on `server.allowed_origins`. |
| 404  | `-32601`   | Method the revision does not define | |
| 405  | n/a        | `GET` / `HEAD` / `DELETE` on the MCP path | `Allow: POST`. |
| 429  | `-32099`   | Completion rate limit exceeded | |
| 500  | `-32603`   | Internal error | Last resort; the gateway prefers specific codes where possible. |
| 503  | `-32000`   | Session capacity exhausted | The caller's principal holds `server.max_sessions_per_tenant` session rows. |

Gateway-reserved JSON-RPC codes live in the **`-33000`..`-33099`**
range to keep MCP's `-32000`..`-32099` reserved space untouched. See
the `PAYMENT_REQUIRED_CODE` and `PAYMENT_VERIFICATION_FAILED_CODE`
constants in `libs/mcp-wire/src/shared/error.rs`.

**Rule of thumb for clients**: treat HTTP 2xx as "transport ok, read
the envelope". Treat HTTP 4xx as "transport refused; the envelope may
not even be well-formed JSON-RPC". HTTP 5xx is always the gateway's
fault.
