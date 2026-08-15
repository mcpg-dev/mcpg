# 12 — Docker (local daemon)

MCP server over the local `docker` CLI. Useful for personal dev
environments and self-hosted ops.

## Upstream

Local `docker` CLI; Docker Desktop or the daemon socket.

## Env vars

None — inherits the caller's docker context.

## Run

```bash
cargo run -p mcpg -- --config examples/12-docker-local/config.yaml
```

## Exposed tools

- `docker.ps` — list containers.
- `docker.logs` — last N lines of a container's logs.
- `docker.inspect` — full JSON for a container/image/network.
- `docker.start` / `docker.stop` / `docker.rm` — lifecycle.
- `docker.pull` — pull an image (long running, 2-minute timeout).
- `docker.images` — list local images.

## Safety

`docker.rm` is destructive; pair with a confirmation pipeline if
exposed to untrusted agents.
