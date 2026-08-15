# 22 — Stripe

MCP server covering Stripe customers, products, prices,
PaymentIntents, subscriptions, and invoices.

## Upstream

- Docs: https://stripe.com/docs/api
- Auth: Bearer secret key (or restricted key).

## Env vars

| Var | Purpose |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_...` or `rk_live_...` (prefer a restricted key) |

## Run

```bash
cargo run -p mcpg -- --config examples/22-stripe/config.yaml
```

## Exposed tools

- `stripe.customer.list` / `stripe.customer.create`
- `stripe.product.create` / `stripe.price.create`
- `stripe.payment_intent.create` — for one-time charges.
- `stripe.subscription.create` / `stripe.subscription.cancel`
- `stripe.invoice.list`

## Pairing with x402

Stripe APIs are form-encoded. `STRIPE_SECRET_KEY` is a root-of-
trust secret; never use a live-mode key for an exploratory agent.
For paid agent-tools that charge the user per call, front the
bindings with the `mcpg-plugin-payment-x402` plugin instead of
embedding the secret in each tool.
