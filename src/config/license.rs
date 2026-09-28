//! `license:` — the offline license token.
//!
//! The gateway resolves its claims envelope from here (or falls back to
//! the built-in community tier) and the license gate
//! (`crate::license_gate`) refuses entitlement-gated plugins and
//! feature-gated config blocks the envelope does not admit. A CP-attached
//! gateway's plugins are admitted by the control plane's plugin-set bind
//! instead, and so are the config blocks of a config the managed-cloud
//! platform rendered, which its publish guard checked.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LicenseConfig {
    /// The signed license JWT, inline (commonly `${env.MCPG_LICENSE}`).
    /// Exactly one of `token` / `token_file` may be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Path to a file holding the signed license JWT (e.g. a mounted
    /// secret). Exactly one of `token` / `token_file` may be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,

    /// Trusted license-signing public key (SPKI PEM, Ed25519) — the
    /// verification anchor for the configured token (`mcpg-license
    /// keygen --public-out`). Required when a token is configured; an
    /// unverifiable token refuses boot rather than silently degrading
    /// to community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_pem: Option<String>,

    /// Declares this deployment non-production. Entitlement-gated
    /// plugins and feature-gated config blocks (interactive sign-in at the
    /// embedded authorization server) then load without a token under
    /// their license's free non-production grant (development, testing,
    /// evaluation, staging), with a boot warning naming them. Production
    /// use still requires an entitling token.
    #[serde(default)]
    pub non_production_use: bool,
}
