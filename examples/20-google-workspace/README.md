# 20 — Google Workspace (Gmail + Calendar + Drive + Docs)

MCP server over the common Google Workspace surfaces, built entirely
from the generic `http` binding. There is no Workspace-specific plugin —
each tool is one REST call.

## Upstream

- Gmail API v1
- Calendar API v3
- Drive API v3
- Docs API v1

## Env vars

| Var | Purpose |
|---|---|
| `GOOGLE_TOKEN` | OAuth 2.0 Bearer access token with the scopes below |

## Run

```bash
cargo run -p mcpg -- --config examples/20-google-workspace/config.yaml
```

## Exposed tools

| Tool | Method | Upstream |
|---|---|---|
| `gmail.messages.list` | GET | `users/me/messages` |
| `gmail.messages.send` | POST | `users/me/messages/send` |
| `calendar.events.list` | GET | `calendars/primary/events` |
| `calendar.events.create` | POST | `calendars/primary/events` |
| `drive.files.list` | GET | `drive/v3/files` |
| `docs.documents.create` | POST | `v1/documents` |

## Why the tools look like this

The `http` binding puts **every** caller argument on the wire: into the
query string on GET, into the JSON body on POST. It has no notion of a
path parameter, and it cannot hold an argument back.

Google rejects query parameters and body fields it does not recognise,
so two rules follow, and both shape the config:

- **Every property in an `input_schema` is a real API field.** For
  example `docs.documents.create` takes exactly `title`, because the
  Docs `documents.create` body is exactly `{"title": …}`.
- **Anything the operator fixes stays in the URL, never in the schema.**
  The calendar id is hard-coded to `primary` for this reason. Making it
  an argument would interpolate it into the path *and* append
  `?calendar_id=…`, and the second copy fails the call.

The same rule rules out single-resource reads such as
`gmail.messages.get` or `drive.files.get`: the id belongs in the path,
but it would also be sent as an unknown query parameter. For an API with
many path-parameterised operations, use the `openapi` binding instead —
it reads `in: path` and `in: query` from the spec and routes each
parameter correctly. Point it at a vendored Google spec; remote spec
URLs are refused.

## Exposed resources (change watching)

A `watch:` block turns a binding into something an MCP client can
`resources/subscribe` to. The engine re-reads the binding, takes a
SHA-256 of the result, and sends `notifications/resources/updated`
**only when that hash moves**. An unchanged folder produces no traffic.

| Resource | Fires on | Cadence |
|---|---|---|
| `drive.folder.contents` | file added, renamed, trashed, or edited | 60 s |
| `drive.file.metadata` | one file edited, renamed, trashed, or deleted | 30 s |
| `docs.document.revision` | any edit to one document | 30 s |
| `calendar.events.recent` | event created, updated, or cancelled | 120 s |
| `gmail.unread` | unread mail arrives or is read | 60 s |
| `drive.folder.pushed` | the same folder, over Google's push channel | on POST |

Replace `FOLDER_ID`, `FILE_ID`, and `DOCUMENT_ID` before running. A
resource takes no caller arguments, so these are operator-fixed and the
whole Google query lives in the URL — the binding merges a URL query
with the generated one, and for a resource the generated one is empty.

### `fields` is the part that matters

The hash covers the whole response, so the `fields` parameter decides
which changes you can see, and which non-changes wake you up.

- **Include a content signal or you will miss edits.** `md5Checksum` on
  a Drive file and `revisionId` on a Doc both move when the content
  changes. Without one of them, a file edited in place looks identical
  and the watch stays silent.
- **Exclude anything that moves on its own.** The Calendar binding
  leaves `nextSyncToken` out of `fields` because it changes on every
  read, which would fire the watch on every poll.
- **Pin the order.** `orderBy` keeps an unchanged response
  byte-identical. Without it a reordered listing reads as a change.

### Seeing a delete

`drive.file.metadata` lists `expected_status_codes: [200, 404]` on
purpose. A hard delete replaces the file document with an error
document, which moves the hash and fires the notification. Treat 404 as
a failure instead and the watch errors rather than reporting the delete.

A file moved to the trash is a different event: it stays readable with
`trashed: true`, so it fires through the ordinary body change.

### Who gets told

`notification_filter` scopes the fan-out. `gmail.unread` sets
`scope: subject_id`, so only the subscriber whose principal matches the
event is notified — a mailbox must not fan out to every session on the
gateway. The default is `all`. `session_id` and a CEL `expression` are
the other two.

### Push instead of polling

`drive.folder.pushed` uses `type: webhook`. The gateway exposes
`POST /webhooks/resource-updated/{token}`, and Drive's
`changes.watch` / `files.watch` can target it directly for instant
notification with no poll cadence.

Three things to know before relying on it:

- **Channels expire and nothing here renews them.** Drive drops a
  channel within 24 hours. You need an external job that re-registers
  it.
- Google requires an HTTPS endpoint on a domain you have verified.
- The trigger fires on *any* POST to that path. It cannot filter on the
  `X-Goog-Resource-State` header, so Google's initial `sync` message
  fires it once too.

The token is the shared secret in the URL path. Leave it empty and the
gateway generates a UUID-v4 at startup, which is fine for a scratch run
but means the URL changes on every restart.

### What we cannot do yet

Drive's own `changes.list` with an advancing `pageToken` returns only
what changed since the last read. The poll watch is a stateless hash
compare with nowhere to keep that token, so this sample re-reads the
listing instead. That is why `fields` is kept narrow.

## Scopes (typical)

- `https://www.googleapis.com/auth/gmail.modify`
- `https://www.googleapis.com/auth/calendar`
- `https://www.googleapis.com/auth/drive.file`
- `https://www.googleapis.com/auth/documents`

## Using a service account instead of a user token

`${env.GOOGLE_TOKEN}` is one static token for every caller. To issue a
short-lived token per caller instead, run the
`dev.mcpg.credential.gcp-impersonation` plugin and swap the header. The
rest of each binding is unchanged.

```yaml
plugins:
  - id: dev.mcpg.credential.gcp-impersonation
    class: credential_issuer
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/credential-gcp-impersonation:protocol-1" }
    granted_capabilities: [network_outbound]
    config:
      # base_auth defaults to the GKE Workload Identity metadata server
      targets:
        drive-ro:
          service_account: "mcpg-drive@my-proj.iam.gserviceaccount.com"
          scopes: ["https://www.googleapis.com/auth/drive.readonly"]
```

```yaml
          headers:
            Authorization: "Bearer ${cred://dev.mcpg.credential.gcp-impersonation/drive-ro}"
```

Note the reach of a service account before you plan on it. It sees only
what is shared with it directly, or what lives in a Shared Drive where
it is a member. It cannot read a person's *My Drive*. That needs Google
Workspace domain-wide delegation, which this plugin does not implement.

## Safety

`gmail.messages.send` is irreversible, and `calendar.events.create` and
`docs.documents.create` both write. Wrap them with a confirmation
pipeline (`Elicitation` → `BindingCall`) when a less-trusted agent
drives them.
