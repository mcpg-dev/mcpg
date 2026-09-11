# MCPG API Reference

> HTTP transport endpoints, MCP protocol operations, and SSE streaming.
> Source: `transports/http/` (router, request path, SSE, identity, validation,
> response mapping), `protocol/mod.rs`

## HTTP Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |
| `GET` | `/runtime` | Runtime metadata |
| `POST` | `/mcp` | MCP JSON-RPC requests |
| `GET` | `/mcp` | SSE stream (session events) |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/metrics` | Prometheus metrics (if enabled) |

---

## MCP Protocol

MCPG implements the Model Context Protocol over Streamable HTTP (JSON-RPC 2.0).

### Protocol Version

```
Default:  2025-11-25   (production-grade; the negotiated default)
Legacy:   2025-03-26, 2025-06-18   (accepted when explicitly requested)
Modern:   2026-07-28   (stateless, MRTR-based; DRAFT-2026-v1 accepted inbound as a transitional alias)
```

The modern `2026-07-28` wire is stateless: it never emits an
`Mcp-Session-Id`, and modern `GET`/`DELETE /mcp` return `405`.
The `GET`/`DELETE`/`Mcp-Session-Id` rows below describe the stateful
`2025-11-25` wire.

Transport rules:
- `POST /mcp` accepts exactly one JSON-RPC request, notification, or response body
- JSON-RPC batch arrays are rejected on the primary endpoint
- clients should send `Mcp-Protocol-Version` on all post-initialize HTTP requests
- if the server receives an invalid or unsupported explicit `Mcp-Protocol-Version`, it returns HTTP `400 Bad Request`
- if the header is omitted after initialization, MCPG uses the negotiated session version

### Request/Response Headers

**Request headers**:
- `Content-Type: application/json` — Required for POST
- `Accept: application/json` — Required for POST; the minimum, and every response is then inline JSON. Add `text/event-stream` (`Accept: application/json, text/event-stream`) to consent to an SSE response for a non-initialize request on a session — then read frames until the one whose `id` matches (see [A minimal client](#a-minimal-client))
- `Mcp-Session-Id: {session_id}` — Required after initialization
- `Mcp-Protocol-Version: 2025-11-25` — Required on post-initialize HTTP requests; invalid/unsupported values return `400`
- `Last-Event-Id: {event_id}` — For SSE resumption (GET only)

**Response headers**:
- `X-Mcpg-Request-Id: {uuid}` — Gateway request ID (all responses)
- `Mcp-Session-Id: {session_id}` — Set on initialize response
- `Mcp-Protocol-Version: 2025-11-25` — Negotiated version

---

## A minimal client

The whole round trip on the default `2025-11-25` wire, in the order it
happens. Three rules carry most of the weight — two independently written
clients got two of them wrong on their first attempt, so they are stated
before the code:

1. **`Accept: application/json` alone means inline JSON for every response.**
   There is nothing to parse but the body. Add `text/event-stream` only when
   the client wants streaming, and then the response to a POST is an SSE
   stream whose first frames are *notifications* — a priming frame with no
   data, a `notifications/message` log line (`logger: "mcpg.transport"`,
   `"Streaming protocol response"`), any pipeline `log`/`progress`
   notifications — and the result is the frame whose `id` matches the
   request. A parser that takes the first `data:` frame as the answer reads a
   log entry as its result and reports success with a nonsense payload.
2. **A request id is used once per session — including by a request the
   server answered with an error.** The check runs before dispatch, so a
   failed attempt consumes its id; a reused id (number or string) is
   refused with `-32600 duplicate request id on this session` before
   anything else happens. Count up, or use UUIDs.
3. **A notification carries no `id`.** `notifications/initialized` sent with
   an `id` is a *request* for a method that does not exist, and is answered
   with `-32601 Method not found: notifications/initialized` — the session
   never becomes operational.

```bash
U=https://gateway.example/mcp
J='Content-Type: application/json'

# 1. initialize — the response is inline JSON; the session id is a header.
H=$(mktemp)
curl -sS -D "$H" -X POST "$U" -H "$J" -H 'Accept: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "initialize",
  "params": { "protocolVersion": "2025-11-25", "capabilities": {},
              "clientInfo": { "name": "my-client", "version": "1.0.0" } }
}' | jq .result.serverInfo
SID=$(tr -d '\r' < "$H" | awk 'tolower($1) == "mcp-session-id:" { print $2 }')

# Every later request carries the session and the negotiated version.
S=(-H "$J" -H 'Accept: application/json' -H "Mcp-Session-Id: $SID" -H 'Mcp-Protocol-Version: 2025-11-25')

# 2. initialized — a notification: no id. 202 Accepted, empty body.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$U" "${S[@]}" \
  -d '{ "jsonrpc": "2.0", "method": "notifications/initialized" }'

# 3. tools/list — a fresh id.
curl -sS -X POST "$U" "${S[@]}" \
  -d '{ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }' | jq '.result.tools[].name'

# 4. tools/call — another fresh id, even if the previous call failed.
curl -sS -X POST "$U" "${S[@]}" -d '{
  "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "ping", "arguments": {} }
}' | jq .result
```

The same call with streaming consented to. The result is the frame whose
`id` matches; everything before it is a notification:

```bash
# 5. tools/list again, over SSE — read frames until the id matches.
curl -sS -N -X POST "$U" -H "$J" -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" -H 'Mcp-Protocol-Version: 2025-11-25' \
  -d '{ "jsonrpc": "2.0", "id": 4, "method": "tools/list" }' \
  | sed -n 's/^data: //p' | jq -c 'select(.id == 4) | .result'

# 6. done — the session is released; its id is invalid from here on.
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE "$U" \
  -H "Mcp-Session-Id: $SID" -H 'Mcp-Protocol-Version: 2025-11-25'
```

What the stream carries, verbatim, for step 5:

```
event: message
id: stream-0:0
retry: 1500

event: message
id: stream-0:1
retry: 3000
data: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","logger":"mcpg.transport","data":{"message":"Streaming protocol response","sessionId":"…"}}}

event: message
id: stream-0:2
retry: 3000
data: {"jsonrpc":"2.0","id":4,"result":{"tools":[…],"ttlMs":60000,"cacheScope":"private"}}
```

With `server.unary_json_fast_path` enabled, a unary 200 result that emitted no
notifications comes back as a single `application/json` body even when the
client consented to SSE — a client that branches on the response's
`Content-Type`, not on what it asked for, needs no change either way.

## MCP Operations

### Initialize

Start a new session. Must be the first request.

**Request** (POST /mcp):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "elicitation": {},
      "sampling": {}
    },
    "clientInfo": {
      "name": "my-client",
      "version": "1.0.0"
    }
  }
}
```

**Response** (200 OK):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "tools": { "listChanged": false },
      "prompts": { "listChanged": false },
      "resources": { "listChanged": false },
      "logging": {}
    },
    "serverInfo": {
      "name": "mcpg",
      "version": "0.1.0"
    }
  }
}
```

The `Mcp-Session-Id` response header contains the session ID for subsequent requests.

### Initialized (Notification)

After receiving the initialize response, the client must send an `initialized` notification:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
```

This transitions the session from `AwaitingInitialized` to `Operational`.

### List Tools

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "my_tool",
        "description": "Does something",
        "inputSchema": {
          "type": "object",
          "properties": { "input": { "type": "string" } }
        }
      }
    ]
  }
}
```

Tools filtered by policy (denied tools hidden from list).

### Call Tool

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "my_tool",
    "arguments": { "input": "hello" }
  }
}
```

**Response** (success):
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      { "type": "text", "text": "result data" }
    ],
    "isError": false
  }
}
```

**Response** (pipeline suspended — HTTP 200 + SSE):
When a pipeline hits an elicitation or sampling step, the POST response upgrades to `text/event-stream`. The stream carries the server-initiated request first, then the eventual terminal JSON-RPC response for the original request.

### List Prompts

```json
{ "jsonrpc": "2.0", "id": 4, "method": "prompts/list" }
```

### Get Prompt

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "prompts/get",
  "params": { "name": "mcpg_operational_overview" }
}
```

### List Resources

```json
{ "jsonrpc": "2.0", "id": 6, "method": "resources/list" }
```

### Read Resource

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "resources/read",
  "params": { "uri": "mcpg://runtime/overview" }
}
```

### Set Log Level

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "logging/setLevel",
  "params": { "level": "debug" }
}
```

---

## SSE Streaming

### Opening a Stream

`GET /mcp` with `Accept: text/event-stream` and `Mcp-Session-Id: {session_id}`.

The SSE stream delivers:
1. **Priming event** — empty data (connection confirmation)
2. **Protocol responses** — JSON-RPC responses for tool calls, list operations
3. **Server-initiated requests** — Elicitation, sampling (for suspended pipelines)
4. **Pending deliveries** — Replayed on reconnect

The GET stream is also the canonical resumption path for any previously opened POST-originated SSE stream.

### Event Format

```
id: stream-1:0
data: {"jsonrpc":"2.0","id":3,"result":{...}}

id: stream-1:1
data: {"jsonrpc":"2.0","id":"srv-1","method":"elicitation/create","params":{...}}
```

### Resumption

Send `Last-Event-Id: stream-1:5` header on reconnect. Events after the cursor are replayed from the replay window. If the cursor has expired, the server returns HTTP 409 Conflict.

---

## Server-Initiated Requests

When a pipeline suspends for elicitation or sampling, the server sends a JSON-RPC request to the client:

### Elicitation Request
```json
{
  "jsonrpc": "2.0",
  "id": "srv-abc123",
  "method": "elicitation/create",
  "params": {
    "message": "Please confirm the operation:",
    "requestedSchema": { "type": "object", "properties": { "confirmed": { "type": "boolean" } } }
  }
}
```

### Sampling Request
```json
{
  "jsonrpc": "2.0",
  "id": "srv-def456",
  "method": "sampling/createMessage",
  "params": {
    "messages": [{ "role": "user", "content": { "type": "text", "text": "Analyze this" } }],
    "maxTokens": 500
  }
}
```

### Client Response

The client responds by POST-ing a JSON-RPC response to `/mcp`:

```json
{
  "jsonrpc": "2.0",
  "id": "srv-abc123",
  "result": {
    "action": "accept",
    "content": { "confirmed": true }
  }
}
```

This resumes the suspended pipeline.

---

## Error Responses

### Protocol Errors

| Code | Meaning |
|---|---|
| `-32700` | Parse error (invalid JSON) |
| `-32600` | Invalid request (missing fields) |
| `-32601` | Method not found |
| `-32602` | Invalid params |

### Gateway Errors

| Code | Meaning |
|---|---|
| `-32001` | Session not found |
| `-32002` | Session not initialized |
| `-32003` | Trust requirement not met (policy) |
| `-32022` | Global CEL policy denied |
| `-32005` | Per-tool CEL policy denied |

### HTTP Status Codes

| Status | When |
|---|---|
| 200 | Successful JSON-RPC response |
| 202 | Pipeline suspended (elicitation/sampling) |
| 400 | Bad request (missing headers, invalid JSON) |
| 403 | CORS origin rejected, policy denial |
| 404 | Unknown endpoint or session |
| 409 | Expired SSE cursor |
| 500 | Internal server error |

---

## Identity Headers

| Header | Direction | Description |
|---|---|---|
| `Authorization: Bearer {token}` | Request | JWT/OIDC bearer token |
| `x-mcpg-subject-id: {subject}` | Request | Header-asserted identity |
| `Mcp-Session-Id: {sid}` | Both | Session identifier |
| `Mcp-Protocol-Version: {ver}` | Both | Protocol version |
| `X-Mcpg-Request-Id: {rid}` | Response | Gateway request ID |
| `Last-Event-Id: {eid}` | Request | SSE resumption cursor |

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
| 200  | `-32602`   | `tools/call` with bad arguments | `isError: true` `ToolCallResult` is still 200 + success envelope. Distinct from protocol `-32602`. |
| 202  | n/a        | Notification accepted; pipeline suspended waiting for elicitation/sampling | Client follows up via SSE GET or `tasks/result`. |
| 400  | `-32600`   | `id` violates JSON-RPC 2.0 (null, bool, object, array, empty string, or reused on session) | T15-01/02/03. |
| 400  | `-32600`   | Invalid `Mcp-Protocol-Version` header | T16-05. |
| 400  | `-32600`   | Batch array on POST body | 2025-06-18 removed batch. |
| 400  | `-32600`   | Missing `Accept` or non-SSE-compatible Accept | T12-08. |
| 400  | `-32602`   | `_meta.progressToken` not string or non-empty number | T15-04. |
| 400  | `-32600`   | `_meta` key uses MCP-reserved prefix | T15-05. |
| 401  | `-32041`   | Identity gate: missing / invalid credential | `WWW-Authenticate` header carries `resource_metadata`. |
| 401  | `-32044`   | Identity gate: insufficient scope | Carries `error="insufficient_scope"` and required `scope=`. |
| 402  | `-33042`   | Payment required (MPP, UCP, ACP) | Plugin-specific `-33050`..`-33061` when the plugin surfaces its own variant. |
| 403  | `-32041`   | Policy denial / CORS rejection | Origin not on `server.allowed_origins`. |
| 404  | `-32600`   | Unknown session id on header | Operator-termed session never reuses an id. |
| 409  | `-32600`   | Expired `Last-Event-Id` SSE cursor | Client must reinitialise the session. |
| 429  | `-32099`   | Completion rate limit exceeded | T13-07. |
| 429  | `-32099`   | Per-tenant session quota exceeded | T16-07; reply body includes `tenant` hint. |
| 500  | `-32603`   | Internal error | Last resort; the gateway prefers specific codes where possible. |

Gateway-reserved JSON-RPC codes live in the **`-33000`..`-33099`**
range to keep MCP's `-32000`..`-32099` reserved space untouched. See
`apps/gateway/src/protocol/mod.rs` constants `PAYMENT_REQUIRED_CODE`,
`URL_ELICITATION_REQUIRED_CODE`, etc.

**Rule of thumb for clients**: treat HTTP 2xx as "transport ok, read
the envelope". Treat HTTP 4xx as "transport refused; the envelope may
not even be well-formed JSON-RPC". HTTP 5xx is always the gateway's
fault.
