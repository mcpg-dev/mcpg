# personal-agent-company

The MCP server that a [Personal Agent Protocol](https://personalagentprotocol.org) Company lists in its `poppy.json` (PAP draft 0.2):

- A User's Personal Agent finds the Company in `https://shop.example/.well-known/poppy.json`, gets a Session Token from the Company's authorization server `https://auth.shop.example`, and calls `https://mcp.shop.example/mcp` with it, Bearer or DPoP.
- The gateway verifies the token (issuer, audience, signature, and the DPoP proof of a bound token) and reads the PAP values (`client_id`, Session, User ID, account) from its claims.
- `orders.lookup` runs at once. A signed-out Personal Agent without `orders:read` is told to sign in (`403 sign_in_required`); a signed-in one gets `insufficient_scope`.
- `orders.refund` is an **operation**. A Personal Agent that lists the `operations` extension gets a proposal ("Refund 20 EUR for order A-1.") instead of the refund. The User approves it, the agent confirms that revision at `https://mcp.shop.example/poppy/operations/{id}/confirm` with a DPoP Session Token, and the gateway performs the refund one time.

The gateway does not issue Session Tokens: the Company's authorization server does. DPoP, and with it the operations endpoint, needs a license with the `oauth.dpop` feature (Enterprise), or `license.non_production_use: true` outside production. The full guide is at <https://mcpg.dev/docs/security/personal-agent-protocol>.

## What to change

- **Hosts.** `shop.example`, `mcp.shop.example`, `auth.shop.example`, `orders.internal.example` and `registry.shop.example` are placeholders. The resource, the operations endpoint and `canonical_url` share one origin.
- **Claims.** `attribute_claim_mappings` maps the claims of this template (`client_id`, `sid`, `uid`, `acct`) to the identity attributes the PAP profile reads. Map your authorization server's names instead, in both `providers` lists. The account claim must be present only while the Session is signed in, or map a `signed_in` claim too.
- **Signing algorithms.** `verification.allowed_algs` lists what your authorization server signs Session Tokens with. `dpop.allowed_algs` must include `ES256`: every Personal Agent can sign with it.
- **Operations.** List each tool that changes something for the User under `personal_agent.operations.tools`, with a `summary` from which the User can decide alone. Keep `user_approval_required: true` where a standing permission is not enough.
- **More replicas.** With a cluster coordinator (`cluster.kind: redis` or `nats`, licensed), operations live in its key-value store and a confirm on any replica runs the action once. On `single_node` they live in the process.

## Check the deployment

The PAP repository has a validator kit for a whole Company (`kit/company/validate`). Its `mcp.*` checks test this server: the 401 that names the protected resource metadata, the metadata itself, a Bearer Session Token for the server's `url`, and the refusal of a token for any other resource.

## Required env vars

None: the template reads no secrets. The license token file is mounted at `/etc/mcpg/license/license.jwt`.
