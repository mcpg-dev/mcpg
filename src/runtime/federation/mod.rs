//! In-gateway MCP federation engine.
//!
//! The engine lives in the gateway, not a cdylib plugin: it must
//! mutate the `CapabilityRegistry`, own live upstream sessions that
//! survive config reload, and reuse the pipeline suspend/resume +
//! delivery-bus machinery — none of which crosses the plugin FFI/ABI
//! cleanly.
//!
//! Submodules: the outbound MCP client ([`upstream`] + [`wire`]), the
//! engine + capability overlay, and dispatch wiring. Parts of the
//! client surface are exercised only by tests, so dead-code is
//! silenced module-wide.
#![allow(dead_code)]

pub(crate) mod bridge;
pub(crate) mod engine;

pub(crate) use mcpg_mcp_client::{upstream, wire};

pub(crate) use engine::FederationCaller;
