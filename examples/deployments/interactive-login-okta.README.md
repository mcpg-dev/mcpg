# interactive-login-okta

One gateway whose embedded authorization server serves both ways into it through Okta, and reaches a Cross App Access upstream for each user:

- **EMA clients** (Claude with Okta Cross App Access) redeem ID-JAGs at `POST /oauth/token`, as without sign-in.
- **Interactive clients** (Claude Code, VS Code, `mcpg inspector`, a registered CLI) sign their user in through the browser: `authorization_code` with PKCE at `/oauth/authorize`, the consent page where it applies, then Okta. The user is the same principal whichever way they came in.
- **The `vendor` federation** presents the user's stored Okta refresh token as the RFC 8693 subject token, through `dev.mcpg.credential.oauth-id-jag`.

Interactive sign-in needs a license with the `sso.interactive_login` feature (enterprise). A gateway refuses to boot with a `login` or `interactive` block unless its `license:` block grants it or the deployment declares `license.non_production_use: true`. This holds for a gateway attached to a self-hosted control plane too, which never sees the gateway's local config. On mcpg.cloud, the control plane refuses to publish such a config for an org whose plan lacks it.

## Set up Okta

1. Use the **org** authorization server (`https://{org}.okta.com`) as `trusted_idps[].issuer`: custom authorization servers issue no ID-JAGs.
2. In the OIDC app linked to the mcpg AI agent, allow the `authorization_code` and `refresh_token` grants and register the sign-in redirect URI `https://mcp.acme.example/oauth/callback`. `mcpg config check interactive-login-okta.yaml` prints it.
3. Authenticate with `private_key_jwt`: the public key of `OKTA_AGENT_KEY` goes on the app, and `assertion_audience: token_endpoint`.
4. Keep `offline_access` in `login.scopes` (the default): without an Okta refresh token the gateway issues no refresh token and the federation cannot act for the user.

## What to change

- **Hosts.** `mcp.acme.example`, `acme.okta.com` and the vendor URLs are placeholders; the issuer, `canonical_url` and the resource must share one origin.
- **Clients.** Keep only the ones you use. A metadata-document client (Claude Code, VS Code) needs no `clients[]` entry, only its host under `client_id_metadata_documents.allowed_hosts`.
- **Lifetimes.** The `interactive` block shows the defaults: 15-minute access tokens, refresh tokens that expire after 14 idle days or 30 days, an Okta check every 15 minutes, and one hour of grace while Okta cannot be reached.
- **Single node.** With `cluster.kind: single_node` and no `interactive.store`, sign-in state lives in a sealed file store under `$MCPG_STATE_DIR/oauth`, else `/var/lib/mcpg/oauth` where `/var/lib/mcpg` exists (the container image, the operator's runtime volume, the Helm chart's volume with `persistence.enabled`), else `~/.mcpg/oauth`. A gateway that cannot open that directory refuses to start: on a read-only root filesystem, give it a writable volume or set `interactive.store.dir`. Without `interactive.state_keys` or `cluster.state_encryption_key_env`, the gateway generates the sealing key on first start at `state.key` in that directory (mode 0600, never logged): back it up with the store. To move that key into `interactive.state_keys`, list it with kid `generated` and the file's contents as its `secret` (for example `secret: ${secret.MCPG_AS_STATE_KEY}`). One gateway process opens a store directory at a time; put it on a persistent volume so sign-ins survive a restart.
- **Dynamic registration.** Off. Clients without a metadata document (Cursor) need an operator-registered `clients[]` entry, or `dynamic_client_registration` with `initial_access_tokens` (or `allow_open`) and, for their `https://` redirect URIs, `allowed_redirect_hosts`. Without it, a registration keeps only its loopback redirect URIs (VS Code desktop registers with those). A registered client is public, sees the consent page at every sign-in, and is never admitted by an IdP's `allowed_clients`.
- **Issuer.** A federation that presents the stored sign-in must name `dev.mcpg.credential.oauth-id-jag` or `dev.mcpg.credential.oauth-token-exchange`; validation refuses any other issuer.

## Required env vars

The header of the YAML lists them. Every replica must carry the same `MCPG_STATE_KEY` and `MCPG_AS_SIGNING_KEY`.
