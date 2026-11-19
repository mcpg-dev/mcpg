//! In-gateway MCP federation engine.
//!
//! The engine lives in the gateway, not a cdylib plugin: it must
//! mutate the `CapabilityRegistry`, own live upstream connections that
//! survive config reload, and reuse the delivery-bus machinery — none of
//! which crosses the plugin FFI/ABI cleanly.
//!
//! Submodules: the outbound MCP client ([`upstream`] + [`wire`]), the
//! engine + capability overlay, the caller's stored IdP sign-in as a
//! subject token ([`idp_sessions`]), and dispatch wiring. Parts of the
//! client surface are exercised only by tests, so dead-code is
//! silenced module-wide.
#![allow(dead_code)]

pub(crate) mod engine;
pub(crate) mod idp_sessions;

pub(crate) use mcpg_mcp_client::{upstream, wire};

pub(crate) use engine::FederationCaller;
