# 23 — Shopify Admin

MCP server over the Shopify Admin REST + Admin GraphQL APIs for a
single shop.

## Upstream

- REST: https://shopify.dev/docs/api/admin-rest
- GraphQL: https://shopify.dev/docs/api/admin-graphql

## Env vars

| Var | Purpose |
|---|---|
| `SHOPIFY_STORE` | Shop handle, e.g. `mystore` (not the full URL) |
| `SHOPIFY_TOKEN` | Admin API access token (shpua_...) |

## Run

```bash
cargo run -p mcpg -- --config examples/23-shopify/config.yaml
```

## Exposed tools

- `shop.products.list` / `shop.product.create`
- `shop.inventory.adjust`
- `shop.orders.list` / `shop.order.fulfill`
- `shop.graphql` — escape-hatch for Admin GraphQL (analytics,
  custom objects).

## API version

Pinned to `2024-07`; rotate by editing the path.
