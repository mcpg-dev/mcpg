# MCP Servers Built with MCPG — Example Catalogue

> Companion to [`agent-authoring-guide.md`](agent-authoring-guide.md).
> Every entry below maps 1:1 to a runnable sample under
> [`examples/`](../examples/) — one folder per entry, each a
> ready-to-run MCP server built declaratively (only `config.yaml`,
> no Rust). Use an entry as the spec and the linked example as the
> reference implementation. Target audience: individual builders
> (websites / apps / personal automation) and company employees
> doing day-to-day work.

Each entry includes: the linked example, upstream, auth model,
bindings (Tools / Resources / ResourceTemplates / Pipelines),
primary users, and a build-complexity rating (S = small, M =
medium, L = large, measured in "how many distinct bindings and how
much schema work").

Legend:
- **Example**: the runnable sample folder under `examples/`.
- **U**: intended user persona (individual builder, team, ops/SRE).
- **Auth**: upstream authentication pattern.
- **Bindings**: count Tools + Resources + ResourceTemplates +
  Pipelines; higher means richer surface.

---

## A · Web & hosting (site builder category)

### 1. Name.com DNS + domain management

- **Example**: [`examples/01-namecom-dns/`](../examples/01-namecom-dns/) — runnable `config.yaml`.
- **U**: anyone with a domain; devs setting up custom domains.
- **Upstream**: name.com API v4 (REST, HTTP Basic).
- **Bindings**: 6 Tools + 1 ResourceTemplate. list/get domain,
  list/create/update/delete record, `namecom://{zone}/records`.
- **Why**: primary dev-ops task nobody wants to do by hand.
- **Complexity**: S.

### 2. Cloudflare (DNS + Pages + Workers + R2)

- **Example**: [`examples/02-cloudflare/`](../examples/02-cloudflare/) — runnable `config.yaml`.
- **U**: site builders, edge-compute users.
- **Upstream**: Cloudflare v4 API (Bearer token).
- **Bindings**: ~18 Tools (DNS CRUD, zone purge-cache, Pages
  deploy status, Workers list/deploy, R2 object list/upload).
- **Complexity**: L.

### 3. Vercel (project + deployment + domain)

- **Example**: [`examples/03-vercel/`](../examples/03-vercel/) — runnable `config.yaml`.
- **U**: front-end devs.
- **Upstream**: Vercel REST API (Bearer).
- **Bindings**: ~14. project list/create, deployment
  trigger/status/logs, domain add/verify, env-var get/set.
- **Complexity**: M.

### 4. Netlify (sites + deploys + forms + functions)

- **Example**: [`examples/04-netlify/`](../examples/04-netlify/) — runnable `config.yaml`.
- **U**: front-end devs, marketers.
- **Upstream**: Netlify REST API (personal access token).
- **Bindings**: ~12. create-site, trigger-deploy, list-forms,
  form-submissions paginated, function logs.
- **Complexity**: M.

### 5. AWS Route 53 + S3 static site

- **Example**: [`examples/05-aws-route53-s3/`](../examples/05-aws-route53-s3/) — runnable `config.yaml`.
- **U**: anyone hosting a static site on AWS.
- **Upstream**: AWS REST API, Signature V4 (plugin-provided
  signer or a tiny command-binding wrapper around the
  `aws` CLI).
- **Bindings**: ~10. Hosted-zone CRUD, record-set change batch,
  S3 list-bucket, S3 put-object, CloudFront invalidate.
- **Complexity**: M.

---

## B · Developer productivity

### 6. GitHub (issues + PRs + actions + releases)

- **Example**: [`examples/06-github/`](../examples/06-github/) — runnable `config.yaml`.
- **U**: every developer.
- **Upstream**: GitHub REST API (Bearer PAT / App token).
- **Bindings**: ~25. issues CRUD, PR list/create/merge, review
  comments, Actions run/list/logs, release create, label CRUD,
  `github://{owner}/{repo}/issues/{n}` ResourceTemplate.
- **Complexity**: L.

### 7. GitLab (projects + MRs + pipelines)

- **Example**: [`examples/07-gitlab/`](../examples/07-gitlab/) — runnable `config.yaml`.
- **U**: GitLab teams.
- **Upstream**: GitLab API v4 (PAT).
- **Bindings**: ~20. project, MR, pipeline trigger, runner list.
- **Complexity**: L.

### 8. Linear (issues + cycles + projects)

- **Example**: [`examples/08-linear/`](../examples/08-linear/) — runnable `config.yaml`.
- **U**: product + eng teams.
- **Upstream**: Linear GraphQL API (API key).
- **Bindings**: ~15, Graphql binding. issue CRUD, cycle list,
  project state, member assignments, resource template
  `linear://issue/{id}`.
- **Complexity**: M.

### 9. Jira Cloud + Confluence

- **Example**: [`examples/09-jira-confluence/`](../examples/09-jira-confluence/) — runnable `config.yaml`.
- **U**: enterprise PM/eng.
- **Upstream**: Atlassian Cloud REST (Bearer, OAuth 2.0).
- **Bindings**: ~22. Jira issue CRUD, JQL search, transition,
  worklog; Confluence page CRUD + search.
- **Complexity**: L.

### 10. Docker Hub + GHCR

- **Example**: [`examples/10-docker-hub-ghcr/`](../examples/10-docker-hub-ghcr/) — runnable `config.yaml`.
- **U**: devs publishing images.
- **Upstream**: Docker Hub API + GHCR token.
- **Bindings**: ~10. list repos, list tags, pull-count, create
  webhook, delete tag, login-token rotation.
- **Complexity**: M.

---

## C · Infrastructure & Ops

### 11. Kubernetes (kubectl-backed)

- **Example**: [`examples/11-kubernetes/`](../examples/11-kubernetes/) — runnable `config.yaml`.
- **U**: DevOps / platform.
- **Upstream**: local `kubectl` (Command binding).
- **Bindings**: ~20. get/describe/apply/delete/logs/exec,
  scaled over Pod/Deployment/Service/CronJob/Secret/ConfigMap.
  Pipeline: confirm-then-apply destructive changes.
- **Complexity**: L.

### 12. Docker (local daemon)

- **Example**: [`examples/12-docker-local/`](../examples/12-docker-local/) — runnable `config.yaml`.
- **U**: devs running containers locally.
- **Upstream**: `docker` CLI or daemon UNIX socket HTTP.
- **Bindings**: ~15. container list/inspect/logs/start/stop/rm,
  image pull/build/ls/rm, volume/network CRUD.
- **Complexity**: M.

### 13. Terraform Cloud

- **Example**: [`examples/13-terraform-cloud/`](../examples/13-terraform-cloud/) — runnable `config.yaml`.
- **U**: IaC teams.
- **Upstream**: Terraform Cloud REST (Bearer).
- **Bindings**: ~12. workspaces list/show, runs
  create/apply/cancel, variables CRUD, state-version diff.
- **Complexity**: M.

### 14. Grafana Cloud (Loki + Mimir + dashboards)

- **Example**: [`examples/14-grafana-cloud/`](../examples/14-grafana-cloud/) — runnable `config.yaml`.
- **U**: on-call / SRE.
- **Upstream**: Grafana REST + Loki + Mimir APIs.
- **Bindings**: ~14. dashboard list/get, folder CRUD, Loki
  LogQL query, Mimir PromQL query, alert-rule CRUD. Includes
  pipelines that embed `sampling/createMessage` to let the
  model summarize log slices.
- **Complexity**: L.

### 15. Datadog (metrics + logs + monitors + incidents)

- **Example**: [`examples/15-datadog/`](../examples/15-datadog/) — runnable `config.yaml`.
- **U**: SRE, ops.
- **Upstream**: Datadog REST API (DD-API-KEY + DD-APPLICATION-KEY).
- **Bindings**: ~18. metric query, log search, monitor CRUD,
  incident CRUD, SLO status.
- **Complexity**: L.

### 16. iPhone Simulator (xcrun simctl)

- **Example**: [`examples/16-ios-simulator/`](../examples/16-ios-simulator/) — runnable `config.yaml`.
- **U**: iOS developers; QA.
- **Upstream**: `xcrun simctl` CLI (Command binding).
- **Bindings**: ~15. list/boot/shutdown/install/launch/terminate,
  privacy grant, screenshot, openurl, addmedia, get_app_container,
  status_bar override, keyboard type. Resource template
  `simctl://{device_udid}/app/{bundle_id}/data`.
- **Complexity**: M.

### 17. Android emulator + adb

- **Example**: [`examples/17-android-adb/`](../examples/17-android-adb/) — runnable `config.yaml`.
- **U**: Android developers.
- **Upstream**: `adb` CLI, `emulator` CLI.
- **Bindings**: ~14. devices list, install apk, shell
  `am start`, logcat tail (pipeline streaming), input
  text/tap/swipe, screencap, push/pull files.
- **Complexity**: M.

---

## D · Communications & calendar

### 18. Slack (messages + channels + files)

- **Example**: [`examples/18-slack/`](../examples/18-slack/) — runnable `config.yaml`.
- **U**: every team.
- **Upstream**: Slack Web API (Bearer bot token).
- **Bindings**: ~15. post-message, schedule-message, list-
  channels, archive-channel, upload-file, reaction CRUD, user
  presence, `slack://channel/{id}/message/{ts}` ResourceTemplate.
- **Complexity**: M.

### 19. Microsoft Teams + Graph

- **Example**: [`examples/19-microsoft-teams/`](../examples/19-microsoft-teams/) — runnable `config.yaml`.
- **U**: M365 teams.
- **Upstream**: Microsoft Graph (OAuth, client-credentials flow).
- **Bindings**: ~18. Teams channel-message CRUD, chat create,
  calendar event CRUD, email send, OneDrive file CRUD.
- **Complexity**: L.

### 20. Google Workspace (Gmail + Calendar + Drive + Docs)

- **Example**: [`examples/20-google-workspace/`](../examples/20-google-workspace/) — runnable `config.yaml`.
- **U**: individuals + small teams.
- **Upstream**: Google REST APIs (OAuth).
- **Bindings**: ~22. send-mail, list-mail (with query), create-
  event, list-events, file upload, Docs create + append. Uses
  a Pipeline that asks `elicitation` for confirmation before
  sending mail.
- **Complexity**: L.

### 21. Notion (pages + databases + search)

- **Example**: [`examples/21-notion/`](../examples/21-notion/) — runnable `config.yaml`.
- **U**: PKM users; teams.
- **Upstream**: Notion REST API (Bearer integration token).
- **Bindings**: ~14. search, page CRUD, database-query with
  filter, block append, comment CRUD. Resource templates for
  `notion://page/{id}`, `notion://db/{id}/rows`.
- **Complexity**: M.

---

## E · Commerce & payments

### 22. Stripe (customers + charges + subscriptions + webhooks)

- **Example**: [`examples/22-stripe/`](../examples/22-stripe/) — runnable `config.yaml`.
- **U**: indie devs; small SaaS founders.
- **Upstream**: Stripe REST (Secret key / restricted key).
- **Bindings**: ~20. customer CRUD, product/price CRUD,
  payment-intent create + confirm, subscription CRUD,
  invoice list, webhook endpoint CRUD. Pair with the x402
  plugin for agent-native paid tools (metered API calls).
- **Complexity**: L.

### 23. Shopify Admin (products + orders + inventory)

- **Example**: [`examples/23-shopify/`](../examples/23-shopify/) — runnable `config.yaml`.
- **U**: small shop owners.
- **Upstream**: Shopify Admin REST + GraphQL (Shop access token).
- **Bindings**: ~18. product CRUD, variant inventory update,
  order list/fulfill/cancel, discount codes, shop analytics
  (GraphQL binding).
- **Complexity**: L.

---

## F · Consumer productivity

### 24. Home Assistant (local smart-home)

- **Example**: [`examples/24-home-assistant/`](../examples/24-home-assistant/) — runnable `config.yaml`.
- **U**: home-lab / smart-home owners.
- **Upstream**: Home Assistant REST (long-lived access token).
- **Bindings**: ~14. state list/get/set, service call (by
  domain.service), template render, config-entries list,
  calendar events. Resource template
  `ha://entity/{entity_id}`.
- **Complexity**: M.

### 25. macOS system (shortcuts + open + osascript)

- **Example**: [`examples/25-macos-system/`](../examples/25-macos-system/) — runnable `config.yaml`.
- **U**: macOS power users.
- **Upstream**: local CLIs (`shortcuts`, `open`, `osascript`,
  `pmset`, `caffeinate`, `screencapture`). Command bindings.
- **Bindings**: ~18. run-shortcut (by name), open URL, open
  file with app, run AppleScript (sandboxed via a restricted
  path), display notification, set Do Not Disturb, capture
  screenshot, list running apps, focus app.
- **Complexity**: M.

---

## G · SQL, warehouse & messaging backends

These entries showcase the SQL/warehouse backend and native
messaging surfaces rather than a REST upstream. Most use SQLite or
in-memory DuckDB so they run with zero external dependencies.

### 26. SQL backend — SQLite todos

- **Example**: [`examples/26-sql-sqlite-todos/`](../examples/26-sql-sqlite-todos/) — runnable `config.yaml`.
- **U**: anyone learning the SQL backend.
- **Upstream**: local SQLite file (`TODOS_DB_PATH`), schema created
  on first call.
- **Bindings**: CRUD Tools over a `todos` table; demonstrates every
  core `row_mode` and the `param_exprs` server-side clamp pattern.
- **Complexity**: S.

### 27. SQL binding — dynamic resource listings

- **Example**: [`examples/27-sql-dynamic-resource-listings/`](../examples/27-sql-dynamic-resource-listings/) — runnable `config.yaml`.
- **U**: builders exposing DB rows as MCP resources.
- **Upstream**: local SQLite file.
- **Bindings**: `docs://{slug}` ResourceTemplate backed by a table,
  with concrete URIs enumerated via the SQL binding's `list_query`
  keyset-pagination block for `resources/list`.
- **Complexity**: M.

### 28. SQL backend — transactional pipeline (`sql_tx`)

- **Example**: [`examples/28-sql-pipeline-tx/`](../examples/28-sql-pipeline-tx/) — runnable `config.yaml`.
- **U**: builders needing multi-statement atomicity.
- **Upstream**: local SQLite (swap driver + URL for Postgres/MySQL).
- **Bindings**: the `sql_tx` pipeline container — two statements in
  one transaction, commit on success, rollback on any nested-step
  failure.
- **Complexity**: M.

### 29. SQL backend — fire-and-wait `await` block

- **Example**: [`examples/29-sql-await-job/`](../examples/29-sql-await-job/) — runnable `config.yaml`.
- **U**: builders modelling async jobs over a table.
- **Upstream**: local SQLite file.
- **Bindings**: a tool that inserts a pending job then polls a status
  query until a CEL predicate matches or the timeout expires, via the
  SQL backend's `await:` runtime.
- **Complexity**: M.

### 30. Warehouse backends across MCP surfaces

- **Example**: [`examples/30-warehouse-backends-surfaces/`](../examples/30-warehouse-backends-surfaces/) — runnable `config.yaml`.
- **U**: operators exposing read-only warehouse data.
- **Upstream**: in-memory DuckDB (same shape applies to
  `bigquery` / `snowflake` / `oracle` / `dynamodb` / `elasticsearch`).
- **Bindings**: one warehouse backend surfaced as Tool, Resource, and
  pipeline step, with the read-only / open-world annotation defaults
  operators should set on read-only bindings.
- **Complexity**: M.

### 31. Twilio SMS + Voice

- **Example**: [`examples/31-twilio-sms-voice/`](../examples/31-twilio-sms-voice/) — runnable `config.yaml`.
- **U**: builders adding messaging/voice to an agent.
- **Upstream**: Twilio (`dev.mcpg.backend.twilio`).
- **Bindings**: send/list SMS, place/control calls, answer inbound
  calls/SMS via signature-validated webhooks returning TwiML, and
  native `notifications/resources/updated` push on new messages/calls.
- **Complexity**: L.

---

## Choosing which to build first

- For an **individual builder making websites**: pick (1)
  Name.com, (2) Cloudflare, (6) GitHub, (18) Slack. Four
  servers cover most of the loop.
- For a **mobile developer**: (16) iPhone Simulator, (17)
  Android emulator, (6) GitHub, (15) Datadog or (14) Grafana.
- For a **small SaaS founder**: (22) Stripe, (20) Google
  Workspace, (18) Slack, (6) GitHub, (12) Docker.
- For an **enterprise employee**: (9) Jira + Confluence, (18)
  Slack or (19) Teams, (20) Google Workspace or (19) M365,
  (6) GitHub or (7) GitLab.

Every server on this list ships as a single MCPG config file under
[`examples/`](../examples/). The agent-authoring procedure in
[`agent-authoring-guide.md`](agent-authoring-guide.md) covers the
end-to-end recipe for building your own.
