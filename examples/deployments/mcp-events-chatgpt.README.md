# mcp-events-chatgpt

A short-lived single-node gateway for checking [MCP Events](https://mcpg.dev/docs/gateway/mcp-events) with ChatGPT in developer mode. ChatGPT adds the gateway as a connector, signs its user in, lists the event types and subscribes to each by webhook. The gateway signs and POSTs every occurrence to ChatGPT's callback.

## What's in it

- **Events on**, with a `file` subscription store and a `file` event log, so subscriptions and the log survive a restart. `cluster.state_encryption_key_env` names the key that seals both stores, the subscription secrets and the sign-in state.
- **Two event types:**
  - `test.heartbeat` fires every five minutes from the `cron` watch of `dev.mcpg.watch.cron`. Its `data` is `{scheduledAt, firedAt, catchUp}`. It needs no outside input, so it shows that deliveries arrive on their own.
  - `test.note` is posted by the operator on demand to `/webhooks/events/operator`, signed with the `standard_webhooks` profile and `TEST_NOTE_WEBHOOK_SECRET`. Its `data` is `{text}`. The secret is `whsec_` and the base64 of a key of 24 to 64 bytes, for example `whsec_$(openssl rand -base64 32)`. A key of another length fails the boot, and the error does not show the secret.
- **A verified principal for ChatGPT.** The embedded authorization server is the identity source: it is the one option where the gateway itself answers every OAuth step a client takes. ChatGPT registers itself at `POST /oauth/register` (open registration; an `https` redirect URI must be on `chatgpt.com`), the user approves the consent page and signs in at Keycloak, and ChatGPT gets the gateway's own access token. `require_authentication: true` answers an anonymous request with `401` and the resource metadata, where ChatGPT starts.
- **A `verified` trust floor** on both event types, which is also the webhook default (`webhook.require_trust: verified`).
- **Audit** of every delivery request (`events.audit.deliveries: every`) in the local audit file.

## Set up Keycloak

1. Create a confidential OpenID Connect client `mcpg-events-test` with the **Standard flow**, and add the valid redirect URI `https://events.acme.example/oauth/callback`. `mcpg config check mcp-events-chatgpt.yaml` prints it.
2. Copy the client secret into `KEYCLOAK_CLIENT_SECRET`.
3. Create one test user for the person who signs in from ChatGPT.

## Fire a test.note

Sign the body as Standard Webhooks does: `v1,` and the base64 HMAC-SHA256 of `{webhook-id}.{webhook-timestamp}.{body}` under the base64 part of `TEST_NOTE_WEBHOOK_SECRET`. The `webhook-id` becomes the event id, and the gateway takes a repeated id once. With the secret exported, the recipe reads the key from the environment, so the key is never on a command line.

```bash
id="note-$(date +%s)"; ts="$(date +%s)"; body='{"text":"hello from the operator"}'
sig="$(python3 -c 'import base64, hashlib, hmac, os, sys
key = base64.b64decode(os.environ["TEST_NOTE_WEBHOOK_SECRET"].removeprefix("whsec_"))
print(base64.b64encode(hmac.new(key, sys.argv[1].encode(), hashlib.sha256).digest()).decode())' "$id.$ts.$body")"
curl -sS -X POST https://events.acme.example/webhooks/events/operator \
  -H 'content-type: application/json' -H "webhook-id: $id" \
  -H "webhook-timestamp: $ts" -H "webhook-signature: v1,$sig" -d "$body"
```

The route answers `202` once the note is in the type's inbox, and `401` for a bad or stale signature. A body outside `payload_schema` also gets `202`, but the gateway drops it before the event log and delivers nothing. `mcpg_events_payload_dropped_total{reason="payload_schema"}` counts it when metrics are on.

## What to change

- **Hosts.** `events.acme.example` and `sso.acme.example` are placeholders. The issuer, `canonical_url`, `allowed_origins` and the resource must share one origin.
- **TLS.** The template expects a proxy in front that ends TLS (`trust_proxy_ip: true`). The gateway takes the first `X-Forwarded-For` hop as the client IP of every per-IP budget, registration included, and the first `X-Forwarded-Host` as the host of the resource identifier. So the proxy must replace any `X-Forwarded-For` and `X-Forwarded-Host` that the client sends, and port 8787 must be reachable only through the proxy. Without such a proxy, add a `tls:` block and set `trust_proxy_ip: false`.
- **The plugin.** The cron descriptor must declare `schedule.fired`. A build that declares no event types is refused at boot with "declares no event types … rebuild the plugin". The published channel that `protocol-1` names has no cron build with event types until a release includes MCP Events. Until then, a gateway built from source needs the cron cdylib from the same build, named by `source.path`.
- **License.** Interactive sign-in is an Enterprise feature (`sso.interactive_login`). The template declares `license.non_production_use: true` for a test; replace it with a license token for anything else.
- **Lifetime.** Remove the gateway, the Keycloak client and the test user after the test. Registered clients expire after one unused day (`client_ttl_secs: 86400`).

## Verifying

- An anonymous `POST /mcp` answers `401` with `WWW-Authenticate: Bearer resource_metadata="…"`.
- `/.well-known/oauth-authorization-server` lists a `registration_endpoint`.
- With a token, `server/discover` on the `2026-07-28` wire advertises `capabilities.events` and `capabilities.extensions["io.modelcontextprotocol/events"]`, and `events/list` returns `test.heartbeat` and `test.note`.
- `mcpg inspector events subscribe https://events.acme.example/mcp test.note --bearer <token> --callback-base https://<receiver>` prints each delivery and, at the end, the webhook checks: `events.webhook.signature`, `id-is-event-id`, `stable-retries`, `control-ids`, `id-has-no-dot` and `cursor`. `<receiver>` is a public `https` address that forwards to the inspector's `--listen` address.
- The access token lasts 15 minutes (`interactive.access_token_ttl_secs`, default 900). A subscription's `refreshBefore` is clamped to the token's expiry, but never to less than 5 minutes (`webhook.ttl.min_ms`). ChatGPT must refresh its token and subscribe again before `refreshBefore`, or deliveries stop.

## Required env vars

The header of the YAML lists them. `MCPG_CLUSTER_STATE_KEY` must stay the same across restarts: a new key voids every subscription and every sign-in.
