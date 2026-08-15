//! Capability registry — compiled binding definitions for MCP tools, prompts,
//! resources, and resource templates.
//!
//! Built once at startup from operator config. Owns pre-compiled JSON Schema
//! validators, URI template matchers, and route maps used by the runtime for dispatch.

pub mod capability_registry;
pub use mcpg_mcp_wire::descriptors;
pub mod federation;
pub mod host;
pub mod routes;

pub use self::descriptors::*;
pub use capability_registry::*;
pub use federation::*;
pub use routes::*;

#[cfg(test)]
mod tests;
