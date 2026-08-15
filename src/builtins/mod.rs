//! Built-in first-party plugins bundled with the gateway binary.
//!
//! Per spec §19, a plugin whose id starts with `dev.mcpg.builtin.*`
//! MAY be statically linked into the gateway. Distributed plugins
//! (tool_gate / transform / identity / payment families etc.) live
//! under `plugins/` at the workspace root and ship as OCI artefacts;
//! everything here is a reference implementation or scaffolding tied
//! to the gateway's own HTTP surface.
//!
//! Among these is the `http_route` reference plugin — it demonstrates
//! the full `HttpRoute` contract against a production-shaped request.
//! Future built-ins (health probes with deep checks, admin UI landing
//! pages, etc.) can live beside it.

pub mod audit_local_file;
pub mod cache_memory;
pub mod cluster_primitives;
pub mod cluster_single_node;
pub mod config_file;
pub mod http_status;
pub mod log_stderr_json;
pub mod policy_yaml_rules;
pub mod secret_env;
pub mod secret_file;
pub mod store_memory;
pub mod telemetry_debug;
pub mod transport_memory;
