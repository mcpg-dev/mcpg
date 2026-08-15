//! MCPG — Model Context Protocol Gateway.
//!
//! A reverse proxy that sits between MCP clients and backend services,
//! providing session management, capability negotiation, identity resolution,
//! policy enforcement, plugin-based gating/transform, multi-step pipelines,
//! and observability.

// Mirrors `[lints.clippy]` in Cargo.toml. Cargo reads the manifest table and
// other build systems do not, and a command-line `-D warnings` outranks a
// build file's flags but not a source attribute — so the crate states its own
// lint decisions here, where every toolchain honours them.
#![allow(clippy::large_enum_variant)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

pub mod admin;
pub mod app;
pub mod backends;
pub mod builtins;
pub mod cli;
pub mod compose;
pub mod config;
pub mod license_gate;
pub mod observability;
pub mod protocol;
pub mod runtime;
pub mod transports;
pub mod usage_reporting;
