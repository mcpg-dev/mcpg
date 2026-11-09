# 32 — A public HTTPS endpoint through ngrok

A gateway on a laptop, behind NAT or in a private network gets a public HTTPS
URL that claude.ai, ChatGPT or any remote MCP client can reach. The
[`dev.mcpg.transport.ngrok`](https://github.com/mcpg-dev/mcpg-plugin-transport-ngrok)
plugin dials out to ngrok, so the machine needs no inbound port and no
public IP.

The plugin hands every request to the gateway's own HTTP router. Identity,
OAuth discovery, per-IP rate limits (keyed on the client address that ngrok
reports), SSE and both MCP revisions behave as on the gateway's HTTP listener.

## Run it

```bash
export NGROK_AUTHTOKEN=<token from the ngrok dashboard>
mcpg --config examples/32-ngrok-public-endpoint/config.yaml
```

The log names the endpoint:

```text
extra transport started kind=dev.mcpg.transport.ngrok wire=http listen=https://example-1234.ngrok-free.app
```

Give the MCP client `https://example-1234.ngrok-free.app/mcp`.

## What it serves

| Tool | Upstream | Purpose |
|---|---|---|
| `weather.current` | Open-Meteo (no key) | Current temperature and wind at a coordinate. |

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `NGROK_AUTHTOKEN` | yes | The ngrok authtoken. |

## Caveats

- The sample's Traffic Policy lets through only Anthropic's API network, which
  suits claude.ai connectors. Remove it to accept other clients, and put an
  identity provider in front of anything that is not public data.
- Without `domain`, the URL is the account's dev domain. Reserve a domain in
  the ngrok dashboard to keep a stable URL.
- ngrok terminates TLS at its edge and sees the traffic in plaintext.
- See [Serve through ngrok](https://mcpg.dev/docs/gateway/ngrok) for
  the internal binding, pooling and every config field.
