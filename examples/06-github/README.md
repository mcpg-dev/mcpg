# 06 — GitHub

MCP server covering GitHub issues, PRs, Actions runs, and releases.

## Upstream

- **Docs**: https://docs.github.com/en/rest
- **Auth**: Bearer (fine-grained PAT or GitHub App token).

## Env vars

| Var | Purpose |
|---|---|
| `GITHUB_TOKEN` | PAT / App token with the repo scopes you need |

## Run

```bash
cargo run -p mcpg -- --config examples/06-github/config.yaml
```

## Exposed tools

- `gh.issues.list` — list issues.
- `gh.issue.create` — open an issue.
- `gh.issue.comment` — comment on an issue / PR.
- `gh.pr.list` — list pull requests.
- `gh.pr.merge` — merge a PR (squash / merge / rebase).
- `gh.actions.runs` — list workflow runs.
- `gh.release.create` — cut a release.

## Resource template

- `github://{owner}/{repo}/issues/{number}` — single issue JSON.

## Notes

- `X-GitHub-Api-Version: 2022-11-28` pinned on every backend.
- Prefer fine-grained PATs with per-repo scopes over classic
  PATs.
