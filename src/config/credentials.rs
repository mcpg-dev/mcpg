//! `credentials:` block — gateway-side L1 cache for
//! `cred://` URI substitution plus the optional cluster
//! pub/sub wrapper.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Defaults are safe for single-node deploys; multi-instance
/// deploys with per-caller dynamic credentials (e.g. Vault dynamic
/// DB) MUST configure `cluster.enabled: true` to avoid cache
/// divergence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    /// Maximum number of `(identity, plugin, target)` entries kept
    /// in the L1 cache. LRU eviction past this. Default 10000 —
    /// at ~500 bytes per entry that's ~5MB worst case.
    #[serde(default = "default_credential_cache_max_entries")]
    pub max_entries: usize,
    /// Operator-side cap on per-entry TTL. Even if a plugin
    /// returns a 24-hour TTL, the cache evicts at this cap to
    /// limit blast radius from leaked / compromised credentials.
    /// Default 3600 (1 hour).
    #[serde(default = "default_credential_cache_max_ttl_ms")]
    pub max_cache_ttl_ms: u64,
    /// Identity attribute (token-claim) names folded into the
    /// credential-cache key so callers differing only by these claims
    /// (commonly the tenant claim) get separate cached credentials.
    /// Empty (default) excludes attributes from the key — set this to
    /// your tenant claim name(s) when a `credential_issuer` derives its
    /// principal from an attribute claim, otherwise those callers share
    /// one credential. In a clustered cache every peer MUST set the same
    /// `key_attributes` (the published event hash is computed with it) —
    /// divergence silently produces per-node cache misses, the same
    /// all-peers-agree constraint that already governs the hash algorithm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_attributes: Vec<String>,
    /// Optional cluster pub/sub wrapper. When `enabled: true` AND
    /// a `cluster_backend` is bound, the gateway wraps the L1
    /// cache with `ClusteredCredentialCache` so every peer
    /// instance sees Issued / Revoked events. Drops to local-only
    /// behaviour with a warning when `enabled: true` but no
    /// coordinator is bound.
    #[serde(default)]
    pub cluster: CredentialsClusterConfig,
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            max_entries: default_credential_cache_max_entries(),
            max_cache_ttl_ms: default_credential_cache_max_ttl_ms(),
            key_attributes: Vec::new(),
            cluster: CredentialsClusterConfig::default(),
        }
    }
}

fn default_credential_cache_max_entries() -> usize {
    10_000
}

fn default_credential_cache_max_ttl_ms() -> u64 {
    3600000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: enabling cluster credential pub/sub without an
    /// encryption key (and without the explicit plaintext opt-in) must be
    /// rejected — otherwise per-caller credentials are broadcast in plaintext.
    #[test]
    fn cluster_without_key_or_optin_is_rejected() {
        let cfg = CredentialsClusterConfig {
            enabled: true,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("encryption_key_env"), "{err}");
    }

    #[test]
    fn cluster_with_key_validates() {
        let cfg = CredentialsClusterConfig {
            enabled: true,
            encryption_key_env: Some("MCPG_CRED_CACHE_KEY".into()),
            ..Default::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn cluster_plaintext_optin_requires_allowed_publishers() {
        // Plaintext mode without an allowlist is rejected: published_by is
        // forgeable there, so the allowlist is the integrity boundary.
        let cfg = CredentialsClusterConfig {
            enabled: true,
            allow_plaintext: true,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("allowed_publishers"), "{err}");
    }

    #[test]
    fn cluster_plaintext_optin_with_allowlist_validates() {
        let cfg = CredentialsClusterConfig {
            enabled: true,
            allow_plaintext: true,
            allowed_publishers: Some(vec!["node-a".into()]),
            ..Default::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn cluster_plaintext_optin_empty_allowlist_is_rejected() {
        let cfg = CredentialsClusterConfig {
            enabled: true,
            allow_plaintext: true,
            allowed_publishers: Some(vec![]),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("allowed_publishers"), "{err}");
    }

    #[test]
    fn disabled_cluster_validates_without_key() {
        let cfg = CredentialsClusterConfig::default();
        assert!(!cfg.enabled);
        cfg.validate().unwrap();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialsClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Override the default cluster topic
    /// (`mcpg.credentials.events`). Operators with multiple
    /// independent MCPG deployments sharing one
    /// `cluster_backend` MUST namespace per-deployment so
    /// peer caches don't pollute each other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Env var holding a base64-encoded 32-byte key for
    /// application-layer AEAD (XChaCha20-Poly1305) of the credential
    /// events published on the cluster topic. STRONGLY recommended:
    /// without it, per-caller credentials are published as plaintext
    /// JSON and confidentiality rests entirely on transport TLS
    ///. All peers sharing the topic must use the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key_env: Option<String>,
    /// Key id (kid) stamped on encrypted envelopes so operators can
    /// rotate keys. Defaults to `mcpg-cred-cache` when a key is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key_id: Option<String>,
    /// Explicit, INSECURE opt-in to publish credential events in
    /// plaintext (no `encryption_key_env`). Required to enable cluster
    /// credential pub/sub without a key — otherwise the gateway refuses
    /// to boot rather than silently broadcasting plaintext credentials.
    /// On this path `published_by` is forgeable, so plaintext mode also
    /// REQUIRES a non-empty `allowed_publishers`; that allowlist plus
    /// broker write-ACLs are the integrity boundary. AEAD via
    /// `encryption_key_env` is the only integrity-providing mode.
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Optional allowlist of peer node ids whose credential-cache events
    /// this instance will apply. When `Some`, an `Issued` /
    /// `Revoked` event whose `published_by` is not in the list is dropped.
    /// This is a genuine control on the **AEAD** path (`published_by` is
    /// inside the sealed payload, so it is authenticated) — it bounds the
    /// blast radius of a compromised-but-keyed peer. On the plaintext path
    /// (`allow_plaintext: true`) it is best-effort only: `published_by` is
    /// attacker-forgeable there, so the allowlist raises the bar but is
    /// NOT a substitute for `encryption_key_env`. MANDATORY (non-empty)
    /// when `allow_plaintext` is set. Unset = accept events from any peer
    /// (only valid on the AEAD path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_publishers: Option<Vec<String>>,
}

impl CredentialsClusterConfig {
    /// Fail-closed check: enabling cluster credential pub/sub without
    /// an encryption key would broadcast per-caller credentials in plaintext.
    /// Require either a key or an explicit plaintext opt-in, and on the
    /// plaintext path additionally require a non-empty publisher allowlist
    /// (since `published_by` is forgeable there).
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.encryption_key_env.is_none() && !self.allow_plaintext {
            anyhow::bail!(
                "credentials.cluster.enabled=true publishes per-caller credentials on \
                 the cluster topic. Set cluster.encryption_key_env (base64 32-byte key) to \
                 encrypt them, or set cluster.allow_plaintext=true to accept plaintext (relies \
                 on transport TLS only)."
            );
        }
        if self.enabled && self.encryption_key_env.is_none() && self.allow_plaintext {
            let has_allowlist = self
                .allowed_publishers
                .as_ref()
                .is_some_and(|v| !v.is_empty());
            if !has_allowlist {
                anyhow::bail!(
                    "credentials.cluster.allow_plaintext=true broadcasts per-caller \
                     credentials in plaintext with no publisher authentication; on this path \
                     published_by is forgeable, so any party that can write the cluster topic \
                     can inject Issued/Revoked events. Set \
                     credentials.cluster.allowed_publishers to a non-empty list of \
                     trusted peer node ids, or (strongly recommended) set encryption_key_env to \
                     enable AEAD — the only integrity-providing mode."
                );
            }
        }
        Ok(())
    }
}
