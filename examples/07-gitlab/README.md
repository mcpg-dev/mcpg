# 07 — GitLab

MCP server covering GitLab projects, merge requests, pipelines,
and issues.

## Upstream

- Docs: https://docs.gitlab.com/ee/api/
- Auth: `PRIVATE-TOKEN` header (personal access token).

## Env vars

| Var | Purpose |
|---|---|
| `GITLAB_TOKEN` | GitLab personal access token |

## Run

```bash
cargo run -p mcpg -- --config examples/07-gitlab/config.yaml
```

## Exposed tools

- `gl.projects.list` — list projects (`membership=true` by default).
- `gl.mr.list` — list merge requests.
- `gl.mr.create` — open a merge request.
- `gl.pipeline.trigger` — trigger a pipeline on a ref.
- `gl.pipelines.list` — list pipelines by status.
- `gl.issue.create` — open an issue.

## Notes

- `project_id` accepts either a numeric id or a URL-encoded
  `group/project` path.
- Self-hosted GitLab: replace `gitlab.com` with your instance
  host — a single find-and-replace in `config.yaml`.
