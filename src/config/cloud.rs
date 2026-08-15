//! `cloud:` — managed-fleet identity + placement. Inert when absent, so a
//! self-host gateway is byte-identical whether or not the block is
//! present. Every field is stamped by the provisioner/operator; the
//! gateway treats the block as read-only identity.

use serde::{Deserialize, Serialize};

/// Server-assigned stable instance id. Carried as an opaque string so the
/// gateway never needs to parse it; the CP mints it (UUIDv7 today).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(transparent)]
pub struct InstanceId(pub String);

/// Default isolation tier for the instance's placement.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CloudIsolation {
    /// Shares a namespace pool with other tenants (default).
    #[default]
    Shared,
    /// Dedicated nodes / namespace for the tenant.
    Dedicated,
}

/// Billing tier the instance was provisioned under.
///
/// The variants mirror the licensing vocabulary (`community` | `pro` | `team`
/// | `enterprise`) so this block and a license claim can be compared without a
/// translation table. `free` is accepted as an alias for `community`, which is
/// what this variant used to be called.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CloudTier {
    /// No tier asserted (self-host / unmanaged).
    #[default]
    Unspecified,
    #[serde(alias = "free")]
    Community,
    Pro,
    Team,
    Enterprise,
}

/// `cloud:` — present only on managed-fleet (mcpg.cloud) instances.
/// Absent for self-host; every field defaults so a bare `cloud: {}` is inert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct CloudConfig {
    /// Server-assigned stable id. None for self-host. Read-only — set by the CP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Human-friendly display name for the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Globally-unique DNS label that addresses this instance:
    /// `https://{subdomain}.mcpg.cloud/mcp`. Read-only — assigned/reserved by
    /// the CP. Defaults conceptually to `instance_id` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,

    /// Additional customer-owned hostnames that resolve to this instance
    /// (CNAME → the instance edge). Developer-owned; each must be a valid
    /// DNS hostname. Empty for the default-domain-only case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_domains: Vec<String>,

    /// Tenant / org slug — billing + console grouping. Developer-owned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,

    /// Workspace slug within the tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,

    /// Environment slug (dev / staging / prod …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Placement region hint (free-form; matched against fleet capacity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Billing tier the instance runs under.
    #[serde(default)]
    pub tier: CloudTier,

    /// Isolation tier for placement.
    #[serde(default)]
    pub isolation: CloudIsolation,

    /// Publish-time acknowledgement that this managed instance intentionally
    /// serves `/mcp` WITHOUT a configured token verifier (an anonymous / public
    /// MCP server). The CP publish guard requires EITHER a verifier
    /// (`governance.access.jwks` / `governance.access.oidc_oauth`) OR this
    /// opt-out, so a tenant can't expose an unauthenticated gateway on the
    /// public edge by omission. The gateway runtime does not read this field —
    /// it is a declaration the publish guard checks.
    #[serde(default)]
    pub allow_anonymous: bool,

    /// Server-managed placement provenance. Stamped by the provisioner/operator;
    /// ignored / overwritten if hand-written.
    #[serde(default)]
    pub provenance: CloudProvenance,
}

/// Server-managed placement facts. Never trusted from a published config —
/// the operator overwrites these at render time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct CloudProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Canonical external URL (`https://{subdomain}.mcpg.cloud/mcp`).
    /// Operator-injected into `governance.access.resource_metadata.resource`;
    /// OVERWRITTEN at render — never trust a published value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioned_at: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,
}

impl InstanceId {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        validate_dns_label("cloud.instance_id", &self.0)
    }
}

impl CloudConfig {
    /// Self-contained validation — no cross-block coupling, so the block stays
    /// inert for self-host. Region is free-form; provenance is server-owned.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if let Some(id) = &self.instance_id {
            id.validate()?;
        }
        for (field, value) in [
            ("cloud.subdomain", &self.subdomain),
            ("cloud.tenant", &self.tenant),
            ("cloud.workspace", &self.workspace),
            ("cloud.environment", &self.environment),
        ] {
            if let Some(s) = value {
                validate_dns_label(field, s)?;
            }
        }
        for domain in &self.custom_domains {
            validate_dns_hostname("cloud.custom_domains", domain)?;
        }
        Ok(())
    }
}

/// RFC 1123 DNS label: 1..=63 chars, lowercase alphanumeric or hyphen, no
/// leading/trailing hyphen. Written inline — never import an operator helper
/// (independence invariant).
fn validate_dns_label(field: &str, s: &str) -> anyhow::Result<()> {
    if s.is_empty() || s.len() > 63 {
        anyhow::bail!(
            "{field}: DNS label must be 1..=63 chars, got {} ({s:?})",
            s.len()
        );
    }
    let bytes = s.as_bytes();
    let ok_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    if !bytes.iter().all(|&b| ok_char(b)) {
        anyhow::bail!("{field}: DNS label must be [a-z0-9-], got {s:?}");
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        anyhow::bail!("{field}: DNS label must not start or end with a hyphen ({s:?})");
    }
    Ok(())
}

/// RFC 1123 DNS hostname: dot-separated labels, total <= 253 chars. Each label
/// is validated as a DNS label. Used for customer custom domains.
fn validate_dns_hostname(field: &str, s: &str) -> anyhow::Result<()> {
    if s.is_empty() || s.len() > 253 {
        anyhow::bail!(
            "{field}: hostname must be 1..=253 chars, got {} ({s:?})",
            s.len()
        );
    }
    for label in s.split('.') {
        validate_dns_label(field, label)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_rules() {
        assert!(validate_dns_label("f", "prod-1-abc123").is_ok());
        assert!(validate_dns_label("f", "Bad_Id!").is_err());
        assert!(validate_dns_label("f", "-x").is_err());
        assert!(validate_dns_label("f", "x-").is_err());
        assert!(validate_dns_label("f", "").is_err());
        assert!(validate_dns_label("f", &"a".repeat(64)).is_err());
    }

    #[test]
    fn hostname_rules() {
        assert!(validate_dns_hostname("f", "mcp.acme.com").is_ok());
        assert!(validate_dns_hostname("f", "acme.example.co.uk").is_ok());
        assert!(validate_dns_hostname("f", "bad_domain.com").is_err());
        assert!(validate_dns_hostname("f", ".leading.dot").is_err());
        assert!(validate_dns_hostname("f", "trailing.dot.").is_err());
    }

    #[test]
    fn default_is_valid() {
        assert!(CloudConfig::default().validate().is_ok());
    }

    #[test]
    fn full_block_validates() {
        let c = CloudConfig {
            instance_id: Some(InstanceId("inst-0190abcd".into())),
            name: Some("Acme prod".into()),
            subdomain: Some("inst-0190abcd".into()),
            custom_domains: vec!["mcp.acme.com".into()],
            tenant: Some("acme".into()),
            workspace: Some("payments".into()),
            environment: Some("prod".into()),
            region: Some("us-east-1".into()),
            tier: CloudTier::Pro,
            isolation: CloudIsolation::Dedicated,
            allow_anonymous: false,
            provenance: CloudProvenance::default(),
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn bad_subdomain_rejected() {
        let c = CloudConfig {
            subdomain: Some("Not_A_Label".into()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
}
