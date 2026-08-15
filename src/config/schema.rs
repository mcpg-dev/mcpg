//! Top-level `schema_registry:` block — operator-named JSON Schema entries
//! that bindings reference via `$schema_ref`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A named schema entry in the registry. Exactly one source must be provided.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaEntry {
    /// Inline JSON Schema definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<serde_json::Value>,
    /// Path to a local JSON Schema file (relative to the config file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// URL to fetch the JSON Schema from at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Security: SSRF guard for schema URLs. Resolves the host and rejects when
/// any/the-only resolved address is private/loopback/link-local/ULA/etc.,
/// then pins the resolved address into the returned client (and disables
/// redirect-following) so a later DNS rebind or a 30x to an internal host
/// cannot reach a private address. Requires http/https. `allow_private`
/// (operator `server.allow_private_backends`) opts into private targets for
/// container-network deployments.
pub(crate) async fn validate_and_pin_schema_url(
    url: &str,
    allow_private: bool,
) -> Result<reqwest::Client> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid schema URL '{url}'"))?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(anyhow::anyhow!(
            "schema URL must use http or https, got {scheme}"
        ));
    }
    // The fetched body becomes the validator every later call to the tool is
    // checked against, so over plain http an on-path party chooses that
    // validator. Permitted only under the same flag that admits private
    // targets, which is how an operator declares the network is trusted.
    if scheme == "http" && !allow_private {
        return Err(anyhow::anyhow!(
            "schema URL '{url}' uses plain http; the schema it returns becomes the \
             validator for every call to the bindings that reference it, so an \
             on-path party would choose it. Use https, or set \
             server.allow_private_backends=true if this is a trusted network"
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("schema URL '{url}' has no host"))?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("schema URL '{url}' has no port and no known default"))?;
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("schema URL '{url}': DNS resolution failed for host '{host}'"))?
        .collect();
    if addrs.is_empty() {
        return Err(anyhow::anyhow!(
            "schema URL '{url}': host '{host}' did not resolve to any address"
        ));
    }
    let chosen = if allow_private {
        addrs[0]
    } else {
        addrs
            .iter()
            .find(|a| !crate::runtime::safe_dns::is_private_address(&a.ip()))
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "schema URL '{url}': host '{host}' resolves only to private/loopback/\
                     link-local addresses (set server.allow_private_backends=true to permit). {}",
                    crate::runtime::safe_dns::PRIVATE_RANGES_DOC
                )
            })?
    };
    reqwest::Client::builder()
        .resolve(&host, chosen)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(|| format!("schema URL '{url}': failed to build client"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let err = validate_and_pin_schema_url("file:///etc/passwd", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("http or https"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_private_target_when_not_allowed() {
        // IP literals resolve locally (no DNS), so this exercises the guard
        // deterministically. 127.0.0.1 is loopback → private. https, so the
        // rejection is the address check rather than the scheme check.
        let err = validate_and_pin_schema_url("https://127.0.0.1:9/schema.json", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("resolves only to private"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_plain_http_unless_private_targets_are_allowed() {
        let err = validate_and_pin_schema_url("http://schemas.example.com/s.json", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("plain http"), "got: {err}");
    }

    #[tokio::test]
    async fn allows_private_target_when_opted_in() {
        // allow_private mirrors server.allow_private_backends; the call must
        // succeed and yield a usable (address-pinned) client.
        validate_and_pin_schema_url("http://127.0.0.1:9/schema.json", true)
            .await
            .expect("private target permitted when opted in");
    }

    #[tokio::test]
    async fn rejects_public_loopback_alias() {
        // Link-local / loopback ranges are all rejected; 169.254.169.254 is the
        // canonical cloud-metadata SSRF target.
        let err = validate_and_pin_schema_url("http://169.254.169.254/latest/meta-data", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("private"), "got: {err}");
    }
}
