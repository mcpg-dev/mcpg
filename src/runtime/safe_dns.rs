//! DNS rebinding protection for outbound HTTP connections.
//!
//! The SSRF resolution guard lives in `mcpg-plugin-backend-net-core`
//! alongside the network backends' HTTP client machinery, so the check
//! that rejects a hostname resolving to a private IP exists in exactly one
//! place. This module re-exports it under the gateway's existing path.

pub use mcpg_plugin_backend_net_core::safe_dns::{
    PRIVATE_RANGES_DOC, is_private_address, validate_resolved_addr, validate_resolved_address,
};
