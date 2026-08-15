# mcpg-example-tool-gate-hello — `dev.mcpg.example.tool-gate-hello`

> class `tool_gate` · `native` · package `mcpg-example-tool-gate-hello` · artifact `libmcpg_example_tool_gate_hello.so` · Apache-2.0

An always-allow **ToolGate** plugin for the MCPG gateway, kept at
minimum viable size so the authoring shape stays legible: one
`SyncToolGate` implementation, one `declare_plugin!` invocation, one
`plugin.yaml` descriptor. A tool gate sits on the gateway's request path
and returns a `GateDecision` before a tool call is dispatched, and again
after it returns. Reach for this crate as the copy-paste starting point
for a new plugin, or as a known-good smoke target when validating a
local plugin-loading setup.

## What it does
- Implements `SyncToolGate` with `evaluate_pre` and `evaluate_post`,
  both returning `GateDecision::allow()` — a real gate computes the
  decision from the `PluginContext`, the call arguments, and (post-call)
  the result.
- Declares no `required_capabilities`, so the host grants it nothing
  beyond the plugin call path itself.
- Emits the cdylib `mcpg_plugin_register` export the gateway's dynamic
  loader resolves after `dlopen`, gated on the `cdylib-export` feature.
- Emits `register_static()` for in-process embedding, gated on the
  `static-firstparty` feature — the same gate with no FFI seam.
- Publishes a `PluginManifest` carrying the plugin id, the crate
  version, the `tool_gate` class, and the `example` / `reference` tags.

## Configuration
Loaded from the flat top-level `plugins:` list. The entry carries no
`config:` block — the config JSON handed to the factory is ignored.

```yaml
plugins:
  - id: dev.mcpg.example.tool-gate-hello
    class: tool_gate
    kind: native
    source:
      path: ./plugins/libmcpg_example_tool_gate_hello.so
```

## Build
Both feature paths are enabled by default in this crate, so a single
workspace build produces a loadable cdylib *and* keeps `register_static()`
compiling. Production plugin crates default to neither and opt in
explicitly, so the workspace build does not link several
`mcpg_plugin_register` exports at once.

```bash
cargo build -p mcpg-example-tool-gate-hello --release   # → target/release/libmcpg_example_tool_gate_hello.so
```

To embed the gate in-process instead of loading it dynamically, depend
on the crate with `default-features = false, features = ["static-firstparty"]`
and call the macro-generated registrar during gateway boot:

```rust,ignore
mcpg_example_tool_gate_hello::register_static(&mut registrar, &[], host)?;
```

`register_static` boxes the gate in `SyncToolGateAdapter` and hands it to
`FirstPartyRegistrar` directly — no FFI vtable, no JSON encode/decode
across the seam.

## Testing
```bash
cargo test -p mcpg-example-tool-gate-hello
```

Package the artifact with its descriptor and exercise the vtable
contract against an in-process mock gateway:

```bash
mcpg plugin pack \
    --descriptor examples/plugins/tool-gate-hello/plugin.yaml \
    --artifact target/release/libmcpg_example_tool_gate_hello.so \
    --version <version> \
    --output /tmp/tool-gate-hello.zip
mcpg plugin test /tmp/tool-gate-hello.zip
```

`mcpg dev` skips packaging entirely — it reads the id and class from the
crate's `plugin.yaml` (looked up next to the artifact, or at the crate
root above a `target/<profile>/` build), synthesises a `plugins:` entry
pointing at the artifact, and layers it onto the config the gateway
already loads:

```bash
mcpg dev --plugin target/release/libmcpg_example_tool_gate_hello.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Writing a plugin: <https://mcpg.dev/docs/plugins/plugin-authoring>
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- The shipped plugin catalog: <https://mcpg.dev/docs/plugins/plugin-catalogue>
