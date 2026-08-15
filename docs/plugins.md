# MCPG Plugin System — gateway-internal view

> **Protocol spec:** see [the MCPG plugin protocol reference](https://mcpg.dev/docs/plugins/plugins-and-protocol) for the authoritative contract (entity kinds, traits, manifest, lifecycle, distribution, trust). This doc gives a gateway-developer-oriented tour of *where* the plugin machinery lives in this codebase.
>
> **Per-plugin docs:** every plugin crate ships its own `README.md` with a description, a sample configuration, and build/sign/load instructions. The full commented catalog of every plugin + config value lives in [`config.example.yaml`](../config.example.yaml) under `plugins:`.

## Crate layout

The plugin system is split across these crates. The main `mcpg` binary depends on no plugin-specific transport/backend dependency (`async-nats`, `rdkafka`, `redis`) directly — those live inside plugin crates.

| Crate | Location | Purpose |
|---|---|---|
| `mcpg-plugin-protocol` | `libs/plugin-protocol/` | Trait contracts, types, manifest, descriptor, ABI surface, capability vocabulary. The versioned wire contract. |
| `mcpg-plugin-host` | `libs/plugin-host/` | Registry, chain evaluation, native cdylib loader, Wasm host, OCI resolver, signature verification, `FirstPartyRegistrar`. |
| `mcpg-plugin-sdk` | `libs/plugin-sdk/` | Plugin-author-facing. FFI shim traits (`SyncToolGate`, `SyncIdentityResolver`, …), `declare_*_plugin!` macros, `testing::MockGateway`, authoring templates. |
| `mcpg-cluster-api` | `libs/cluster-api/` | Trait surface for the MCPG cluster backbone — orthogonal primitives `KeyValueStore`, `PubSub`, `Lease`, `Watch` plus the higher-level `ClusterBackend` (peer discovery, leader election, distributed locks, broadcast publish). |
| Cluster primitive impls | `libs/plugins/cluster/{redis,nats}/src/state/` | `KeyValueStore` / `PubSub` / `Lease` / `Watch` impls inlined inside each cluster plugin's `state/` sub-module. The single-node `MemoryKv` / `FileKv` / `MemoryBus` impls live under `apps/gateway/src/builtins/cluster_primitives/`. |
| `mcpg-plugin-cluster-{etcd,consul,nats,redis}` | `libs/plugins/cluster/*/` | Cluster cdylibs. Selected via top-level `cluster: { kind: ..., ...config }`. The cluster plugin internally instantiates the four primitive impls and exposes them via the trait's `key_value_store()` / `pub_sub()` / `lease()` / `watch()` accessors. |
| `mcpg-plugin-backend-nats` | `libs/plugins/backend/nats/` | NATS binding (`kind: "nats"`) + `nats_topic` watch strategy. |
| `mcpg-plugin-backend-kafka` | `libs/plugins/backend/kafka/` | Kafka binding (`kind: "kafka"`) + `kafka_topic` watch strategy. |
| `mcpg-plugin-backend-sql` | `libs/plugins/backend/sql/` | SQL binding + `sql_polling` + `pg_listen` watch strategies. |
| `libs/plugins/observability/*` | — | Migrated to cdylib (audit, call-logger). Distributed via OCI. |
| `libs/plugins/security/*` | — | Migrated to cdylib (ip-allowlist, guardrails). |
| `libs/plugins/reliability/*` | — | Migrated to cdylib (rate-limit, circuit-breaker, response-cache). |
| `libs/plugins/integration/webhook/` | — | Migrated to cdylib. |
| `libs/plugins/identity/oidc/` | — | Migrated to cdylib (Wave 3). |
| `libs/plugins/payment/{mpp,x402,ucp,acp}/` | — | Migrated to cdylib (Wave 4). |
| `libs/plugins/testing/hello-native/` | — | Reference native-cdylib plugin. |
| `libs/plugins/testing/wasm-test-gate/` | — | Reference Wasm plugin. |

## Gateway wiring

- `apps/gateway/src/app/mod.rs::build_from_config` — top-level gateway construction.
- `apps/gateway/src/app/mod.rs::build_plugin_registry` — loads and registers every plugin (first-party via `FirstPartyRegistrar::with_grants`; OCI-sourced via `resolve_oci_source`).
- `apps/gateway/src/app/mod.rs::load_trusted_signing_keys` — loads Ed25519 public keys at boot.
- `apps/gateway/src/transports/http.rs` — HTTP transport, MCP endpoint handler, admin endpoints.
- `libs/plugin-host/src/registry.rs` — `PluginRegistry` + chain evaluation (`evaluate_tool_gates_pre`, `evaluate_tool_gates_post`, etc.).
- `libs/plugin-host/src/native_loader.rs` — `libloading` + `abi_stable` cdylib loader.
- `libs/plugin-host/src/wasm.rs` — Wasmtime component host + WIT bindings.
- `libs/plugin-host/src/oci.rs` — OCI artifact pull + media-type handling.
- `libs/plugin-host/src/verify.rs` — Ed25519 signature verification.

## Development workflows

### Authoring a new plugin

See [the MCPG plugin protocol reference](https://mcpg.dev/docs/plugins/plugins-and-protocol) (SDK surface) for the contract. The plugin-author workflow (compiling, generating keys, release automation) lives in the plugin-authoring guide — **not** in the `mcpg-plugin` CLI, which is scoped to file management (pack / unpack / sign / push / pull / inspect / cache gc).

Crate shape (what the spec requires):

1. `cargo new --lib plugins/my-area/my-plugin`
2. `[lib] crate-type = ["cdylib", "rlib"]`
3. Depend on `mcpg-plugin-protocol` and `mcpg-plugin-sdk`.
4. Add `[features] default = ["cdylib-export"]; cdylib-export = []`.
5. Implement `SyncToolGate` (or the trait for your chosen entity kind).
6. Call `declare_tool_gate_plugin!` (or the relevant macro).
7. Write `plugin.yaml` per spec §5.

Turning that into a published OCI artifact uses the `mcpg-plugin` subcommands directly — one per concern — composed by your own CI or a shell script:

```bash
# Build — your own tooling (cargo, make, etc.).
cargo build -p mcpg-plugin-my-plugin --release

# Sign — key you generated with any standard Ed25519 tool.
mcpg-plugin sign target/release/libmcpg_plugin_my_plugin.so --key ./dev.key

# Pack, push.
mcpg-plugin pack \
    --descriptor plugins/my-area/my-plugin/plugin.yaml \
    --artifact target/release/libmcpg_plugin_my_plugin.so \
    --signature target/release/libmcpg_plugin_my_plugin.so.sig \
    --out /tmp/my-plugin-0.1.0.zip
mcpg-plugin push /tmp/my-plugin-0.1.0.zip --ref ghcr.io/you/my-plugin:0.1.0
```

### Running the gateway against a local OCI registry

```bash
docker run -d --rm -p 5000:5000 --name mcpg-oci registry:2
# After `mcpg-plugin push ... --ref localhost:5000/my-plugin:0.1.0`,
# point the gateway's plugins[].source.oci at
# localhost:5000/my-plugin:0.1.0
```

The full e2e smoke lives in `tools/verify-native-plugin-oci-e2e.sh`.

## Related docs

- **Protocol spec:** [the MCPG plugin protocol reference](https://mcpg.dev/docs/plugins/plugins-and-protocol) — normative contract.
- **Plugin security model:** [signature verification, capabilities, sandboxing](https://mcpg.dev/docs/security/plugin-security).
