//! `license:` — the offline license token for standalone deployments.
//!
//! CP-attached gateways never read this block: their entitlements are
//! enforced by the control plane at plugin-set bind. A standalone
//! gateway resolves its claims envelope from here (or falls back to the
//! built-in community tier) and the plugin load gate
//! (`crate::license_gate`) refuses entitlement-gated plugins the
//! envelope does not admit.

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
    /// plugins then load without a token under their license's free
    /// non-production grant (development, testing, evaluation,
    /// staging), with a boot warning naming them. Production use still
    /// requires an entitling token.
    #[serde(default)]
    pub non_production_use: bool,
}
