//! MCP revision `2026-07-28`.
//!
//! This module holds the [`Handler`] and the per-method dispatch arms:
//! `server/discover`, the SEP-2243 routing headers, the SEP-2549
//! `ttlMs` + `cacheScope` cache surface, the per-request
//! `_meta.io.modelcontextprotocol/*` namespace, MRTR
//! (`InputRequiredResult` + `inputResponses`), `subscriptions/listen`,
//! and the tasks, events and skills extensions.
//!
//! The folder name `v_2026_07_28/` matches the spec revision date; the
//! wire string is [`wire::SUPPORTED_PROTOCOL_VERSION`].

pub mod dispatch;
pub mod handler;

pub use mcpg_mcp_wire::v_2026_07_28::{extensions, wire};

pub use handler::Handler;
