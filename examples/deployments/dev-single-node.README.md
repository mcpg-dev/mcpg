# dev-single-node

Local development on a laptop. Pair with this when the goal is "get the gateway running, prove it answers `tools/list`, iterate on bindings".

## What's in it

- Two bindings, one of each shape:
  - `dev.mock.echo` (`kind: mock`) answers from config alone — a smoke test for the request path that needs nothing outside the process.
  - `dev.http.get` (`kind: http`) makes a real outbound call, so `tools/call` exercises a live backend too.
- A `plugins[]` block declaring both backends. Every backend is a plugin — the gateway links none of them in, so a binding's `kind` resolves only when the matching artefact is declared. Drop a plugin entry and its binding stops resolving; that is the intended behaviour, not a bug.
- Stderr JSON logs at `info` level — readable in a terminal with `tail -f`.
- Single-node backend (no Redis / NATS dependency).
- Anonymous identity (no `governance.access` block) — fine on `127.0.0.1` only.
- Default audit sink (built-in local-file) writing to `./mcpg-audit.log` in the working directory.

## What to change

- **Bindings.** Replace either binding under `mcp.capabilities.tools` with whatever you're working on. The schema reference at the top of the YAML gives you autocomplete on every supported `backend.kind`.
- **Plugins.** Adding a binding of a new `kind` means adding its artefact to `plugins[]` as well, and pinning the tag to the release you run. `mcpg plugin` lists what is available.
- **The http binding calls out.** It fetches `https://example.com/` — point it somewhere useful, or delete it if the machine has no egress.
- **Working directory.** The audit sink writes `./mcpg-audit.log` by default; either `cd` to a scratch dir before launching or set the audit sink's `config.path` explicitly.
- **Don't expose the loopback.** This template binds `127.0.0.1` — promoting to `0.0.0.0` without auth is a footgun. Use `production-single-redis.yaml` as the next step.
