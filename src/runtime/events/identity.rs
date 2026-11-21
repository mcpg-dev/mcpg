//! Server identity of webhook deliveries.
//!
//! With `webhook.signing_keys` set, every delivery and challenge carries a
//! second signature beside its HMAC: Standard Webhooks `v1a,`, Ed25519
//! over the same `{webhook-id}.{webhook-timestamp}.{body}`. The first key
//! signs; every key is published, so a rotation lists the new key beside
//! the old. The keys and `webhook.egress_ip_ranges` are published on the
//! Server Card, under
//! `remotes[].extensionsInfo["io.modelcontextprotocol/events"].webhooks`.
//!
//! The receiving side reads an upstream's keys only from the Server Card
//! of the origin it connects to for MCP, and checks the `v1a,` signature
//! of each delivery against them.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use serde_json::{Value, json};

use crate::config::events::EventsWebhookConfig;

/// Prefix of an Ed25519 signature in `webhook-signature`.
pub const ASYMMETRIC_SIGNATURE_PREFIX: &str = "v1a,";

/// The Ed25519 keys this gateway signs deliveries with.
pub struct ServerIdentity {
    signer: EncodingKey,
    published: Vec<Jwk>,
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity")
            .field(
                "kids",
                &self
                    .published
                    .iter()
                    .map(|jwk| jwk.common.key_id.as_deref())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The bytes a Standard Webhooks signature covers.
fn signed_content(webhook_id: &str, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut content = format!("{webhook_id}.{timestamp}.").into_bytes();
    content.extend_from_slice(body);
    content
}

impl ServerIdentity {
    /// The identity `config` names; `None` without `signing_keys`.
    pub fn from_config(config: &EventsWebhookConfig) -> anyhow::Result<Option<Self>> {
        let mut keys = Vec::new();
        for (index, key) in config.signing_keys.iter().enumerate() {
            let field = format!("mcp.configurations.events.webhook.signing_keys[{index}]");
            let unusable = |error: jsonwebtoken::errors::Error| {
                anyhow::anyhow!(
                    "{field}.private_key is not a usable Ed25519 key ({error}): expected PKCS#8 \
                     PEM, as `openssl genpkey -algorithm ed25519` writes it"
                )
            };
            let encoding =
                EncodingKey::from_ed_pem(key.private_key.as_bytes()).map_err(unusable)?;
            let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::EdDSA).map_err(unusable)?;
            let kid = match &key.kid {
                Some(kid) => kid.clone(),
                None => jwk
                    .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
                    .map_err(unusable)?,
            };
            jwk.common.key_id = Some(kid);
            jwk.common.public_key_use = Some(PublicKeyUse::Signature);
            keys.push((encoding, jwk));
        }
        let mut kids = std::collections::BTreeSet::new();
        for (_, jwk) in &keys {
            let kid = jwk.common.key_id.clone().unwrap_or_default();
            if !kids.insert(kid.clone()) {
                anyhow::bail!(
                    "mcp.configurations.events.webhook.signing_keys: two keys carry kid `{kid}`"
                );
            }
        }
        let mut keys = keys.into_iter();
        let Some((signer, first)) = keys.next() else {
            return Ok(None);
        };
        let identity = Self {
            signer,
            published: std::iter::once(first)
                .chain(keys.map(|(_, jwk)| jwk))
                .collect(),
        };
        let probe = identity
            .sign("msg_probe", 0, b"{}")
            .ok_or_else(|| anyhow::anyhow!("the first webhook signing key cannot sign"))?;
        if !verify_asymmetric(&identity.published, "msg_probe", 0, b"{}", &probe) {
            anyhow::bail!("the first webhook signing key does not verify its own signature");
        }
        Ok(Some(identity))
    }

    /// The `v1a,` signature of one request, with the first key.
    pub fn sign(&self, webhook_id: &str, timestamp: u64, body: &[u8]) -> Option<String> {
        let content = signed_content(webhook_id, timestamp, body);
        let url_safe = jsonwebtoken::crypto::sign(&content, &self.signer, Algorithm::EdDSA).ok()?;
        let raw = URL_SAFE_NO_PAD.decode(url_safe).ok()?;
        Some(format!(
            "{ASYMMETRIC_SIGNATURE_PREFIX}{}",
            STANDARD.encode(raw)
        ))
    }

    /// The published keys, as a JWK set.
    pub fn jwks(&self) -> Value {
        json!({ "keys": self.published })
    }
}

/// The `webhooks` member of this gateway's events entry in the Server
/// Card's `extensionsInfo`; `None` when there is nothing to publish.
pub fn webhooks_info(
    config: &EventsWebhookConfig,
    identity: Option<&ServerIdentity>,
) -> Option<Value> {
    let mut webhooks = serde_json::Map::new();
    if let Some(identity) = identity {
        webhooks.insert("signingKeys".to_owned(), identity.jwks());
    }
    if !config.egress_ip_ranges.is_empty() {
        webhooks.insert("egressIpRanges".to_owned(), json!(config.egress_ip_ranges));
    }
    (!webhooks.is_empty()).then(|| json!({ "webhooks": webhooks }))
}

/// The Ed25519 keys a Server Card publishes for the remote at `mcp_url`:
/// the `signingKeys` of its events entry. `None` when the card names no
/// such remote or publishes no keys; keys that are not Ed25519 JWKs are
/// left out.
pub fn published_signing_keys(card: &Value, mcp_url: &str) -> Option<Vec<Jwk>> {
    let normalized = |url: &str| url.trim_end_matches('/').to_owned();
    let remote = card.get("remotes")?.as_array()?.iter().find(|remote| {
        remote.get("url").and_then(Value::as_str).map(normalized) == Some(normalized(mcp_url))
    })?;
    let keys = remote
        .get("extensionsInfo")?
        .get(crate::protocol::v_2026_07_28::extensions::events::wire::EXTENSION_ID)?
        .get("webhooks")?
        .get("signingKeys")?
        .get("keys")?
        .as_array()?;
    let keys: Vec<Jwk> = keys
        .iter()
        .filter(|key| {
            key.get("kty").and_then(Value::as_str) == Some("OKP")
                && key.get("crv").and_then(Value::as_str) == Some("Ed25519")
        })
        .filter_map(|key| serde_json::from_value(key.clone()).ok())
        .collect();
    (!keys.is_empty()).then_some(keys)
}

/// Whether `signature_header`, a `webhook-signature` value, holds a `v1a,`
/// signature of the request one of `keys` verifies.
pub fn verify_asymmetric(
    keys: &[Jwk],
    webhook_id: &str,
    timestamp: u64,
    body: &[u8],
    signature_header: &str,
) -> bool {
    let content = signed_content(webhook_id, timestamp, body);
    let decoding: Vec<DecodingKey> = keys
        .iter()
        .filter_map(|jwk| DecodingKey::from_jwk(jwk).ok())
        .collect();
    signature_header
        .split(' ')
        .filter_map(|token| token.strip_prefix(ASYMMETRIC_SIGNATURE_PREFIX))
        .filter_map(|encoded| STANDARD.decode(encoded).ok())
        .any(|raw| {
            let url_safe = URL_SAFE_NO_PAD.encode(raw);
            decoding.iter().any(|key| {
                jsonwebtoken::crypto::verify(&url_safe, &content, key, Algorithm::EdDSA)
                    .unwrap_or(false)
            })
        })
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
