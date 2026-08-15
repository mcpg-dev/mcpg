//! Top-level `admin:` block — admin API listener + auth + disclosure
//! level.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_bind")]
    pub bind_address: String,
    #[serde(default = "default_admin_base_path")]
    pub base_path: String,
    #[serde(default)]
    pub auth: AdminAuthConfig,
    #[serde(default)]
    pub disclosure: DisclosureLevel,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_admin_bind(),
            base_path: default_admin_base_path(),
            auth: AdminAuthConfig::default(),
            disclosure: DisclosureLevel::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[derive(Default)]
pub enum AdminAuthConfig {
    StaticBearer {
        bearer_token_env: String,
    },
    /// Security: trusted-header mode requires a value match via
    /// `trusted_value_env`. Header-presence-only is insecure and
    /// generates warnings on every request.
    TrustedHeader {
        header_name: String,
        /// Env var whose value must match the header's value.
        /// Comparison is constant-time.
        #[serde(default)]
        trusted_value_env: Option<String>,
    },
    #[default]
    Disabled,
}

impl AdminAuthConfig {
    /// `true` only when this config actually authenticates the caller.
    /// `Disabled` (no auth) and presence-only `TrustedHeader` (no
    /// `trusted_value_env` to compare against) do NOT authenticate — the
    /// admin API must not be exposed on a public interface under either
    ///.
    pub fn is_authenticated(&self) -> bool {
        match self {
            Self::StaticBearer { .. } => true,
            Self::TrustedHeader {
                trusted_value_env, ..
            } => trusted_value_env.is_some(),
            Self::Disabled => false,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    #[default]
    Summary,
    Redacted,
    Full,
}

fn default_admin_bind() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_base_path() -> String {
    "/admin/v1".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the boot path refuses a public admin bind unless
    /// `is_authenticated()` is true; verify which auth configs count.
    #[test]
    fn is_authenticated_classifies_auth_modes() {
        assert!(!AdminAuthConfig::Disabled.is_authenticated());
        // Presence-only trusted header (no value to compare) is NOT auth.
        assert!(
            !AdminAuthConfig::TrustedHeader {
                header_name: "X-Admin".into(),
                trusted_value_env: None,
            }
            .is_authenticated()
        );
        assert!(
            AdminAuthConfig::TrustedHeader {
                header_name: "X-Admin".into(),
                trusted_value_env: Some("ADMIN_TOKEN".into()),
            }
            .is_authenticated()
        );
        assert!(
            AdminAuthConfig::StaticBearer {
                bearer_token_env: "ADMIN_BEARER".into(),
            }
            .is_authenticated()
        );
    }

    /// The default admin auth is Disabled — hence the public-bind guard.
    #[test]
    fn default_admin_auth_is_disabled() {
        assert!(!AdminAuthConfig::default().is_authenticated());
    }
}
