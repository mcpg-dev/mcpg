# 33 — A gateway on your tailnet

The gateway joins your tailnet as its own Tailscale node with the
[`dev.mcpg.transport.tailscale`](https://github.com/mcpg-dev/mcpg-plugin-transport-tailscale)
plugin. The node is embedded, so the machine runs no `tailscaled` and opens no
inbound port.

Every tailnet connection is attributed: the plugin asks the node who owns the
peer. A tailnet member is a **verified caller with no token**, and the roles of
the `example.com/cap/mcpg` app capability that your tailnet policy grants
become the caller's. With `governance.access.require_authentication: true`,
nobody else gets in.

## Run it

1. In the Tailscale admin console, turn on MagicDNS and HTTPS certificates,
   and create an auth key.
2. Grant the capability in your tailnet policy:

   ```json
   {
     "grants": [
       {
         "src": ["group:eng"],
         "dst": ["*"],
         "app": { "example.com/cap/mcpg": [{ "roles": ["developer"] }] }
       }
     ]
   }
   ```

3. Start the gateway:

   ```bash
   export TS_AUTHKEY=<your auth key>
   mcpg --config examples/33-tailscale-tailnet/config.yaml
   ```

The log names the node:

```text
tailscale node up node=mcp.example.ts.net listen=tailnet:https://mcp.example.ts.net
```

Give tailnet clients `https://mcp.example.ts.net/mcp`.

## What it serves

| Tool | Upstream | Purpose |
|---|---|---|
| `weather.current` | Open-Meteo (no key) | Current temperature and wind at a coordinate. Verified callers only. |

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `TS_AUTHKEY` | the first start only | The auth key that creates the node; its keys then live in `./tailscale-state`. |

## Caveats

- A device that the policy grants no `example.com/cap/mcpg` capability gets
  HTTP 403 from the plugin.
- The plugin ships for Linux (glibc) and macOS; not for musl or Windows.
- See [Serve on a tailnet](https://mcpg.dev/docs/gateway/tailscale) for Funnel,
  OAuth client secrets, workload identity federation, Headscale and every
  config field.
