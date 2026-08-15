# 10 — Docker Hub + GHCR

MCP server for image publishers: enumerate Docker Hub repos/tags
and GitHub Container Registry (GHCR) packages.

## Upstream

- Docker Hub: https://docs.docker.com/docker-hub/api/latest/
- GHCR (via GitHub REST): https://docs.github.com/en/rest/packages

## Env vars

| Var | Purpose |
|---|---|
| `DOCKERHUB_JWT` | Docker Hub JWT (obtained via `/v2/users/login`) |
| `GITHUB_TOKEN` | GitHub token with `read:packages` (+ `delete:packages` for teardown) |

## Run

```bash
cargo run -p mcpg -- --config examples/10-docker-hub-ghcr/config.yaml
```

## Exposed tools

- `dh.repos.list` — list repos for a namespace.
- `dh.tags.list` — list tags of a repo.
- `dh.tag.delete` — destructive.
- `ghcr.packages` — list user/org container packages.
- `ghcr.package.versions` — list versions of one package.

## Notes

- Docker Hub tokens expire; refresh via `/v2/users/login` and
  rotate `DOCKERHUB_JWT`.
- For private GHCR, use a GitHub App installation token.
