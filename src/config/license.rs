//! `license:` — the offline license token.
//!
//! A standalone gateway resolves its claims envelope from here, or falls back
//! to the built-in community tier. A gateway mcpg.cloud delivers a licence to
//! ignores this block and gates on that licence; under a customer's own
//! control plane the block counts.
//! The license gate (`crate::license_gate`) refuses entitlement-gated plugins
//! and feature-gated config blocks the envelope does not admit. A licence
//! verifies only against the MCPG issuer keys compiled into the binary.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The licence of a gateway that mcpg.cloud does not license. A gateway
/// mcpg.cloud delivers a licence to — the delivery carries a proof, signed
/// with an MCPG key, that mcpg.cloud made it on that very connection —
/// ignores the whole block (token, `token_file` and `non_production_use`)
/// and runs on that licence, so a config never chooses its own licence
/// there. Under a customer's own control plane, and until a delivery
/// arrives, the block counts, and takes precedence over a self-host licence
/// that control plane relays.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LicenseConfig {
    /// The MCPG-issued self-host license JWT, inline. Supply via `${env.X}`
    /// (commonly `${env.MCPG_LICENSE}`) or `${secret.NAME}`. A
    /// secret-provider reference (`cred://`, or a `vault://` path) is not
    /// resolved here: the licence is read before any plugin loads, because
    /// it decides which plugins may load, and the Vault provider is itself a
    /// licensed plugin. Exactly one of `token` / `token_file` may be set. It
    /// verifies against the MCPG issuer keys compiled into the binary. A
    /// token that does not verify refuses boot when the config has an
    /// entitlement-gated plugin or a licensed authorization-server block,
    /// rather than silently degrading them to community; with neither, the
    /// gateway logs a warning and runs the community tier. An expired token
    /// keeps its plan for a 14-day grace period, with warnings from 30 days
    /// before expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Path to a file holding the MCPG-issued self-host license JWT (e.g. a
    /// mounted secret), read verbatim. Exactly one of `token` / `token_file`
    /// may be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,

    /// Deprecated and ignored. A license verifies only against the MCPG
    /// issuer keys compiled into the binary, never a key from configuration;
    /// setting this logs a warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_pem: Option<String>,

    /// Declares this deployment non-production. Entitlement-gated
    /// plugins and feature-gated config blocks (interactive sign-in, DPoP
    /// and rich authorization requests at the embedded authorization
    /// server) then load without a token under their license's free
    /// non-production grant (development, testing, evaluation, staging).
    /// The declaration is visible: a boot warning repeated daily, the
    /// admin health endpoint's `license.non_production`, and the
    /// `non_production` label of the `mcpg_license_info` metric. Production
    /// use still requires an entitling token. A gateway mcpg.cloud delivers
    /// a licence to ignores it.
    #[serde(default)]
    pub non_production_use: bool,
}
