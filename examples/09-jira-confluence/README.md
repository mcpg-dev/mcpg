# 09 — Jira Cloud + Confluence

MCP server covering Jira issue search/CRUD and Confluence
pages/search on the same Atlassian Cloud tenant.

## Upstream

- Jira Cloud REST v3: https://developer.atlassian.com/cloud/jira/platform/rest/v3/
- Confluence Cloud REST: https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content/
- Auth: HTTP Basic using email + API token.

## Env vars

| Var | Purpose |
|---|---|
| `ATLASSIAN_BASE_URL` | e.g. `https://acme.atlassian.net` |
| `ATLASSIAN_BASIC_AUTH` | `base64(email + ':' + api_token)` |

## Run

```bash
export ATLASSIAN_BASE_URL=https://acme.atlassian.net
export ATLASSIAN_BASIC_AUTH=$(printf 'you@acme.com:ATATTxxx' | base64)
cargo run -p mcpg -- --config examples/09-jira-confluence/config.yaml
```

## Exposed tools

- `jira.search` — JQL search.
- `jira.issue.get` — single issue fetch.
- `jira.issue.create` — create (Task/Bug/Story/Epic).
- `jira.issue.transition` — move through workflow.
- `confluence.search` — CQL search.
- `confluence.page.create` — create a page with storage-format
  body under an optional parent.

## Notes

- Body fields are ADF (Atlassian Document Format) for Jira;
  the template above embeds plain text as a single paragraph.
- OAuth 2.0 (3LO) is also supported upstream; swap the
  `Authorization` header for `Bearer ...` when using it.
