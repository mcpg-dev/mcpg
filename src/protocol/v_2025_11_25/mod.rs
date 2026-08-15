//! MCP protocol revision `2025-11-25` — the current production-grade
//! version MCPG speaks.
//!
//! This module owns everything specific to revision 2025-11-25: the
//! per-feature wire types under [`wire`], the method-string →
//! operation router, the dispatch arms, and the [`Handler`]
//! `ProtocolHandler` impl. Cross-version primitives (JSON-RPC
//! envelope, content blocks, `ProtocolHandler` trait) live in
//! `crate::protocol::shared`, and the re-exports at the top of
//! `protocol/mod.rs` keep `crate::protocol::Type` imports stable.

pub mod handler;

pub use mcpg_mcp_wire::v_2025_11_25::wire;

pub use handler::Handler;

/// Wire-string identifier for this revision. Matches the value
/// `ProtocolVersion::V_2025_11_25.as_str()`.
pub const VERSION_STRING: &str = "2025-11-25";
