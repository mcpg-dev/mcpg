# Observability — operator references

Worked examples and operator-facing snippets for MCPG's
observability surface. The canonical schema reference lives in
[`../configuration.md`](../configuration.md); files here are
copy-paste-ready demonstrations of specific patterns.

## Files

- [`sink-redirection.yaml`](sink-redirection.yaml) — six patterns
  for the per-plugin observability override block
  (`plugins[*].observability`):
  1. Compliance carve-out (`mode: replace`)
  2. Silence a noisy plugin's traces
  3. Boost log verbosity for one plugin
  4. Tee — global routing PLUS extra debug sink
  5. Drop a plugin's metrics entirely
  6. Target the gateway-internal `core` pseudo-id

  See Phase 6c-23 / 6c-26 in the changelog for design context.

## Related docs

- [`../configuration.md` — Per-plugin observability override](../configuration.md#per-plugin-observability-override)
  — full schema reference table.
