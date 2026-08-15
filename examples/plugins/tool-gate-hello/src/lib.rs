//! Canonical reference plugin for the ToolGate entity kind.
//!
//! Demonstrates the unified [`declare_plugin!`](mcpg_plugin_sdk::declare_plugin)
//! macro at minimum viable size — one trait impl, one macro
//! invocation, one [`plugin.yaml`](../plugin.yaml). Reading this
//! file end-to-end should answer "what does a v25 plugin look
//! like?" without recourse to internal docs.
//!
//! - The plugin author writes [`HelloGate`] — a `SyncToolGate`
//!   impl with two `evaluate_pre`/`evaluate_post` methods.
//! - The macro emits the cdylib `mcpg_plugin_register()` extern
//!   (gated on the `cdylib-export` feature) so the host's
//!   dynamic loader picks the artifact up at boot.
//! - The macro emits `register_static()` for static-firstparty
//!   embedding — the same plugin in-process, with no FFI.

use mcpg_plugin_protocol::PROTOCOL_VERSION;
use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
use mcpg_plugin_protocol::types::{GateDecision, PluginContext};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;

const PLUGIN_ID: &str = "dev.mcpg.example.tool-gate-hello";

/// Always-allow gate. Real plugins compute a `GateDecision` from
/// the request context; this one is intentionally trivial so the
/// reading focus stays on the wiring shape rather than business
/// logic.
pub struct HelloGate {
    manifest: PluginManifest,
}

impl HelloGate {
    pub fn new(_config_json: &str) -> Self {
        Self {
            manifest: build_manifest(),
        }
    }
}

fn build_manifest() -> PluginManifest {
    PluginManifest {
        id: PLUGIN_ID.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        name: "mcpg-example-tool-gate-hello".into(),
        plugin_class: PluginClass::ToolGate,
        protocol_version: PROTOCOL_VERSION.into(),
        license: None,
        required_capabilities: vec![],
        tags: vec!["example".into(), "reference".into()],
        provides: vec![],
        provides_schemes: vec![],
        module_path_prefix: ::std::module_path!()
            .split("::")
            .next()
            .unwrap_or("mcpg_example_tool_gate_hello")
            .to_owned(),
        backend_profile: None,
    }
}

impl SyncToolGate for HelloGate {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        _ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        GateDecision::allow()
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _result: &serde_json::Value,
        _duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        GateDecision::allow()
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    entities: [
        tool_gate as hello {
            inner_name: "",
            plugin_type: HelloGate,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| HelloGate::new(cfg),
        },
    ],
}
