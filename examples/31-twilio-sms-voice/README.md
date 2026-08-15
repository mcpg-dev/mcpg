# 31 — Twilio SMS + Voice (tools, inbound webhooks, native push)

End-to-end sample for `dev.mcpg.backend.twilio`: an AI agent sends/lists SMS,
places/controls calls, **answers inbound calls/SMS** via signature-validated
webhooks that return TwiML, and gets pushed `notifications/resources/updated`
when new messages/calls arrive.

> This config mirrors the plugin's own
> [`config.yaml`](https://github.com/mcpg-dev/mcpg-plugin-backend-twilio/blob/main/examples/config.yaml).
> The plugin's
> [example README](https://github.com/mcpg-dev/mcpg-plugin-backend-twilio/blob/main/examples/README.md) is the
> canonical, deeper write-up; this page is the quick-start.

## Upstream

A Twilio account with a phone number (Voice + Messaging enabled). The
classic REST API (`https://api.twilio.com/2010-04-01`).

## Required env / credentials

| Var / cred | Purpose |
|---|---|
| `TWILIO_ACCOUNT_SID` (`AC…`) | Account SID — REST path + webhook-signing identity |
| `TWILIO_API_KEY_SID` (`SK…`) | Scoped REST API key SID (recommended over the Auth Token) |
| `cred://dev.mcpg.backend.twilio/api_key_secret` | The API key secret (REST auth) |
| `cred://dev.mcpg.backend.twilio/auth_token` | The Account **Auth Token** — required to validate inbound webhook signatures (an API key cannot) |

Provide the two `cred://` values through your gateway credential source; the
`${env.*}` IDs are not secret.

## What it wires (one plugin, three entities)

- **Tools** — `twilio.send_sms`, `twilio.list_messages`, `twilio.make_call`,
  the offline `twilio.build_twiml`, and `twilio.stage_call_response`. Each is a
  `kind: twilio` binding selected by its `operation`.
- **Resources** — `twilio://messages` (a `surface: resource` list) and the
  `twilio://message/{sid}` template; both proxy Twilio (the durable store).
- **Inbound webhook** — configured under `plugins[].config`. Register these on
  your Twilio number (`public_base_url` must be the externally reachable base):
  - Voice URL → `…/plugins/dev.mcpg.backend.twilio/hooks/voice`
  - Messaging URL → `…/hooks/sms`
  - Status callback → `…/hooks/status`
- **Native push** — the `watch:` on `twilio.inbox` uses
  `strategy: { type: plugin, kind: twilio_inbound, kinds: [sms] }`; a client that
  `resources/subscribe`s to `twilio://messages` gets `resources/updated` when an
  inbound SMS lands, then `resources/read`s the fresh data.

## Run

```bash
# Validate the config (offline; build_twiml needs no creds):
cargo run -p mcpg --bin mcpg-config -- check examples/31-twilio-sms-voice/config.yaml

# Boot the gateway with it:
MCPG_CONFIG=examples/31-twilio-sms-voice/config.yaml cargo run -p mcpg --bin mcpg
```

## Caveats

- **At-least-once sends** — Twilio has no idempotency key, so a retried
  `send_sms`/`make_call` double-sends (the bindings are annotated
  `idempotent: false`).
- **Signature validation is fail-closed** — a bad/missing `X-Twilio-Signature`
  is `403`d before any side effect; set `validate_signature: false` only for
  local `curl` testing.
- **In-process state is single-gateway** — live call-scripting + the recent-event
  ring live on the replica that handled the webhook; message/call history is
  always reread from Twilio. For multi-gateway push use `notify_webhook_url`
  (the cross-replica path) instead of / in addition to the watch entity.

See the [plugin example README](https://github.com/mcpg-dev/mcpg-plugin-backend-twilio/blob/main/examples/README.md)
for the full config-nuance walkthrough (auth model, the three inbound-call
control levels, TwiML verbs, and the push model).
