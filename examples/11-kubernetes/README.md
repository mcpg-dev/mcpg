# 11 — Kubernetes (kubectl-backed)

MCP server wrapping the local `kubectl` CLI. Picks the current
context + kubeconfig from the shell environment.

## Upstream

- Local `kubectl` binary.
- Kubeconfig at `${KUBECONFIG}` or `~/.kube/config`.

## Env vars

| Var | Purpose |
|---|---|
| `KUBECONFIG` | Optional kubeconfig path |

## Run

```bash
cargo run -p mcpg -- --config examples/11-kubernetes/config.yaml
```

## Exposed tools

- `k8s.get` — typed `kubectl get` across common kinds.
- `k8s.describe` — `kubectl describe`.
- `k8s.logs` — pod logs with tail limit.
- `k8s.apply` — apply a manifest file (destructive).
- `k8s.delete` — delete a resource (destructive).
- `k8s.scale` — scale a deployment.

## Safety

Production deployments **must** wrap the destructive tools in a
confirmation pipeline (`Elicitation` → `GuardTrue` → binding call)
so the agent cannot silently delete resources.
