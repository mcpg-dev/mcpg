//! MCP protocol revision `2026-07-28` — the modern, stateless,
//! MRTR-based revision.
//!
//! This module owns everything specific to the modern wire: the new
//! `server/discover` capability response, the SEP-2243 routing
//! header set, the SEP-2549 `ttlMs` + `cacheScope` cache surface, the
//! per-request `_meta.io.modelcontextprotocol/*` namespace, MRTR
//! (`InputRequiredResult` + `inputResponses`), `subscriptions/listen`,
//! and the tasks extension lifecycle.
//!
//! ## Surface areas
//!
//! The handler is registered alongside `v_2025_11_25::Handler` in the
//! [`ProtocolRegistry`]. The revision covers, layered roughly in the
//! order it was built up:
//!
//! - `server/discover`, lifecycle replacements, cache shapes, the
//!   basic `_meta` namespace.
//! - Modern dispatch for `tools/call`, `prompts/get`,
//!   `resources/read`, and `completion/complete` against the existing
//!   pipeline / backend layers.
//! - MRTR (`InputRequiredResult`, `inputResponses`),
//!   `subscriptions/listen`, the full `requestState` codec.
//! - The tasks extension (`io.modelcontextprotocol/tasks`).
//!
//! The folder name `v_2026_07_28/` matches the spec revision date;
//! the wire string is the canonical `"2026-07-28"` constant in
//! [`wire::SUPPORTED_PROTOCOL_VERSION`]. `ProtocolVersion::parse()`
//! also accepts the pre-final `"DRAFT-2026-v1"` label as a
//! transitional inbound alias.

pub mod dispatch;
pub mod handler;

pub use mcpg_mcp_wire::v_2026_07_28::{extensions, wire};

pub use handler::Handler;
