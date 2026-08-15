# MCPG Sample MCP Servers

Sample MCPG configurations — one folder per idea in
[`../docs/mcp-server-ideas.md`](../docs/mcp-server-ideas.md) for
external-API coverage (#01–#25), plus three SQL-binding-focused
samples (#26–#28) that demonstrate the features shipped with the
Phase-2 SQL binding work (P2.3 / P4.1 / P4.4 etc.). Each folder
is a ready-to-run MCP server built declaratively with MCPG — no
Rust code to write, only `config.yaml`.

For the "how to author one" procedure see
[`../docs/agent-authoring-guide.md`](../docs/agent-authoring-guide.md).

## Running a sample

```bash
# 1. Set the env vars the sample's README lists.
export NAMECOM_BASIC_AUTH=$(printf 'user:apitoken' | base64)

# 2. Point MCPG at the sample's config.
cargo run -p mcpg -- --config examples/01-namecom-dns/config.yaml

# 3. Point your MCP client (Claude Code / Cursor / custom) at
#    http://127.0.0.1:8787/mcp (adjust per sample).
```

## Sample matrix

| # | Folder | Upstream | Primary user | Complexity |
|---|---|---|---|---|
| 01 | [`01-namecom-dns`](01-namecom-dns/) | Name.com v4 API | Site builder | S |
| 02 | [`02-cloudflare`](02-cloudflare/) | Cloudflare v4 API | Edge dev | L |
| 03 | [`03-vercel`](03-vercel/) | Vercel REST | Front-end dev | M |
| 04 | [`04-netlify`](04-netlify/) | Netlify REST | Front-end dev | M |
| 05 | [`05-aws-route53-s3`](05-aws-route53-s3/) | `aws` CLI | Site on AWS | M |
| 06 | [`06-github`](06-github/) | GitHub REST | Every developer | L |
| 07 | [`07-gitlab`](07-gitlab/) | GitLab API v4 | GitLab teams | L |
| 08 | [`08-linear`](08-linear/) | Linear GraphQL | Product + eng | M |
| 09 | [`09-jira-confluence`](09-jira-confluence/) | Atlassian Cloud REST | Enterprise PM | L |
| 10 | [`10-docker-hub-ghcr`](10-docker-hub-ghcr/) | Docker Hub + GHCR | Image publishers | M |
| 11 | [`11-kubernetes`](11-kubernetes/) | `kubectl` CLI | DevOps / platform | L |
| 12 | [`12-docker-local`](12-docker-local/) | `docker` CLI | Local dev | M |
| 13 | [`13-terraform-cloud`](13-terraform-cloud/) | Terraform Cloud REST | IaC teams | M |
| 14 | [`14-grafana-cloud`](14-grafana-cloud/) | Grafana / Loki / Mimir | SRE / on-call | L |
| 15 | [`15-datadog`](15-datadog/) | Datadog REST | SRE / ops | L |
| 16 | [`16-ios-simulator`](16-ios-simulator/) | `xcrun simctl` | iOS dev / QA | M |
| 17 | [`17-android-adb`](17-android-adb/) | `adb` + `emulator` | Android dev | M |
| 18 | [`18-slack`](18-slack/) | Slack Web API | Every team | M |
| 19 | [`19-microsoft-teams`](19-microsoft-teams/) | Microsoft Graph | M365 teams | L |
| 20 | [`20-google-workspace`](20-google-workspace/) | Google REST APIs | Individuals + small teams | L |
| 21 | [`21-notion`](21-notion/) | Notion REST | PKM users; teams | M |
| 22 | [`22-stripe`](22-stripe/) | Stripe REST | Indie / SaaS founder | L |
| 23 | [`23-shopify`](23-shopify/) | Shopify Admin | Shop owner | L |
| 24 | [`24-home-assistant`](24-home-assistant/) | Home Assistant REST | Smart-home owner | M |
| 25 | [`25-macos-system`](25-macos-system/) | Local macOS CLIs | macOS power user | M |
| 26 | [`26-sql-sqlite-todos`](26-sql-sqlite-todos/) | Local SQLite file | SQL binding intro | S |
| 27 | [`27-sql-dynamic-resource-listings`](27-sql-dynamic-resource-listings/) | Local SQLite file | Dynamic `resources/list` (P2.3) | M |
| 28 | [`28-sql-pipeline-tx`](28-sql-pipeline-tx/) | Local SQLite file | `sql_tx` pipeline container (P4.1) | M |
| 29 | [`29-sql-await-job`](29-sql-await-job/) | Local SQLite file | Fire-and-wait `await` runtime (P3.3) | M |
| 30 | [`30-warehouse-backends-surfaces`](30-warehouse-backends-surfaces/) | In-memory DuckDB | Warehouse backend as tool / resource / pipeline / child-tool | M |
| 31 | [`31-twilio-sms-voice`](31-twilio-sms-voice/) | Twilio API | SMS + Voice tools, inbound webhooks → TwiML, native `resources/updated` push | L |

## What every sample includes

- `config.yaml` — a complete MCPG config with `server:`, optional
  `auth:`, and the per-sample `bindings:` block.
- `README.md` — the upstream, required env vars, each tool's
  purpose, example client invocations, and any caveats.

## Security defaults in every sample

- `server.bind_address: 127.0.0.1:8787` — loopback only.
- Upstream credentials read from env vars; the client's bearer
  header is **not** forwarded to upstream (T15-14 egress guard
  on by default).
- `server.max_request_body_mb: 4`.
- `timeout_ms` set on every backend.

Audit evidence lives in [`../docs/compliance/mcp-compliance.md`](../docs/compliance/mcp-compliance.md).
