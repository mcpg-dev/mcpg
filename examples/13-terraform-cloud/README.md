# 13 — Terraform Cloud

MCP server over Terraform Cloud's JSON:API.

## Upstream

- Docs: https://developer.hashicorp.com/terraform/cloud-docs/api-docs
- Auth: Bearer user/team/agent token.

## Env vars

| Var | Purpose |
|---|---|
| `TFC_TOKEN` | Terraform Cloud token |

## Run

```bash
cargo run -p mcpg -- --config examples/13-terraform-cloud/config.yaml
```

## Exposed tools

- `tfc.workspaces` — list workspaces in an org.
- `tfc.workspace.show` — inspect a workspace.
- `tfc.run.create` — create a run (optional destroy / auto-apply).
- `tfc.run.apply` — apply a plan.
- `tfc.run.cancel` — cancel a running plan.
- `tfc.variables` — list workspace variables.

## Safety

- `is_destroy: true` should never run without a confirmation
  pipeline. Wrap `tfc.run.create` via a Pipeline with an
  `Elicitation` step if the agent can trigger destroys.
