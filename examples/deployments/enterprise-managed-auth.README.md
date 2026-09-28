# enterprise-managed-auth

A gateway whose embedded authorization server accepts enterprise-managed authorization from Okta (Cross App Access, Agent SSO):

- An MCP client (Claude, VS Code) that the user signed in to with Okta asks Okta for an ID-JAG for this gateway, then redeems it at `POST https://mcp.acme.example/oauth/token` with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant.
- The gateway checks the ID-JAG (signature against Okta's keys, `typ`, `aud`, `client_id`, lifetime, single use) and issues an access token for `https://mcp.acme.example/mcp` only. It issues no refresh token: the client asks Okta for a new ID-JAG when the token expires.
- Every MCP request carries that token. Policy sees the Okta user as a verified caller, with the client's `client_roles` and the granted scopes.

This is a core feature: no license is needed. For interactive sign-in (clients that cannot get an ID-JAG) and for calling Cross App Access upstreams per user, start from `interactive-login-okta.yaml` instead.

## Set up Okta

The full walkthrough, with a test agent to try the setup before a real client is connected, is at <https://mcpg.dev/docs/security/enterprise-managed-authorization#okta-setup>. In short:

1. **Decide the gateway's values.** Okta compares each of them as an exact string: the issuer `https://mcp.acme.example` (`authorization_server.issuer`), the resource `https://mcp.acme.example/mcp` (`resource_metadata.resource`), the scope `mcp:tools`, and the client's ID at this gateway, `claude-ema` (`clients[].client_id`). You choose that client ID; it is not an Okta client ID.
2. **Resource app.** In the Admin Console, **Applications > Applications > Create App Integration**, **OIDC - OpenID Connect**, **Web Application**. The gateway never signs anyone in through this app, so a sign-in redirect URI Okta asks for is never used. Assign the users who may reach the gateway. On the app's **Resource Server** tab, next to **Cross App Access (XAA)**, choose **Edit**, then **Enable**, and set **Issuer URL** to `https://mcp.acme.example`, with no trailing slash. It becomes the `aud` of every ID-JAG and cannot change without deleting and resetting the connection. Leave **Audience/tenant ID** empty.
3. **AI agent.** For Claude or VS Code, follow the vendor's instructions for Okta. For your own agent: **Directory > AI agents > Register AI agent > Register manually**, create a new OIDC app linked to the agent, choose its credential, allow the grant it signs users in with, assign users to the linked app, and **Activate** the agent.
4. **Resource connection.** On the AI agent, **Resource connections > Add resource connection**, choose the resource app, and set:
   - **Resource indicator**: `https://mcp.acme.example/mcp`.
   - **AI agent's client ID registered in this app**: `claude-ema`. Okta puts it in the ID-JAG `client_id` claim, and the gateway requires it to name the client that authenticates. A client that identifies with a metadata document uses its URL instead, such as `https://claude.ai/oauth/mcp-oauth-client-metadata`, admitted by `client_id_metadata_documents.allowed_hosts`.
   - **Scopes**: `mcp:tools`.
5. **Trusted IdP.** `trusted_idps[].issuer` is the Okta **org** authorization server, `https://{org}.okta.com`. Custom authorization servers (`/oauth2/default` and the like) issue no ID-JAGs.

Okta limits ID-JAGs on SSO plans to 250 per user, per resource app, per month. One ID-JAG buys one access token, so `access_token_ttl_secs` sets how fast a user spends the quota.

## What to change

- **Hosts.** `mcp.acme.example`, `acme.okta.com` and `crm.internal.example` are placeholders. The issuer, `canonical_url` and the resource share one origin.
- **The client.** Create the secret of `claude-ema` yourself and give the client ID and secret to the MCP client where its vendor's documentation says. For a client that authenticates with `private_key_jwt`, replace `client_secret` with `jwks_uri` (or inline `jwks`). A client that identifies with a Client ID Metadata Document needs no `clients[]` entry: list its host under `client_id_metadata_documents.allowed_hosts`.
- **Groups.** Okta ID-JAGs carry no group claim. Key policy on `identity.roles` from `client_roles`, on `identity.attributes["client_id"]`, or on claims you copy with `claim_mappings.attribute_claim_mappings`.
- **Single node.** With `cluster.kind: single_node`, remove `servers`, `node`, `jetstream` and `state_encryption_key_env`. The single-use ledger then lives in the process: it survives a reload but not a restart.
- **Signing key.** Generate a P-256 key (`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`). Its public half is served at `/oauth/jwks`. To rotate, list the new key first and keep the old one until the tokens it signed have expired.

## Required env vars

The header of the YAML lists them. Every replica must carry the same `MCPG_CLUSTER_STATE_KEY` and `MCPG_AS_SIGNING_KEY`.
