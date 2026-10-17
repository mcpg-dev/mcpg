//! Proof that a callback endpoint wants a subscription's deliveries.
//!
//! Before the first delivery to a (principal, URL) pair the gateway POSTs a
//! signed `{"type": "verification", "challenge": …}` envelope with a fresh
//! 32-byte nonce; the endpoint proves intent by echoing the nonce in a `2xx`
//! JSON body, compared in constant time. A pass is reused for the same pair
//! for `verification.cache_ttl_ms`. A cluster-wide budget per destination
//! host (not per URL, so path and query variants add no capacity) and a
//! per-process limit on requests in flight bound how hard subscribe can make
//! the gateway hit one host.
//!
//! A host may instead publish a receiver document at
//! [`RECEIVER_DOCUMENT_PATH`]. `{"receivers": [...]}` lists path prefixes
//! of its own origin that accept deliveries, the sketch's shape;
//! `{"callbacks": [...]}` lists callback URLs, or URL prefixes ending in
//! `/`, of which only those of the callback's own origin count. A document
//! may carry both.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mcpg_safe_egress::{CallbackUrl, SafeEgress};
use mcpg_standard_webhooks::WhsecSecret;
use parking_lot::Mutex;
use subtle::ConstantTimeEq as _;

use super::delivery::{Attempt, SignedPost, random_token};
use crate::config::events::{VerificationMode, WebhookVerificationConfig};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    ControlEnvelope, DeliveryErrorCategory, VerificationResponse,
};

/// Where a host publishes the callback URLs it accepts deliveries at.
pub const RECEIVER_DOCUMENT_PATH: &str = "/.well-known/mcp-webhook-receiver.json";

/// A receiver document.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct ReceiverDocument {
    receivers: Vec<String>,
    callbacks: Vec<String>,
}

/// Whether the receiver document of `url`'s origin names `url`. A missing,
/// unreadable or oversized document names nothing.
pub async fn receiver_document_admits(
    egress: &SafeEgress,
    url: &CallbackUrl,
    timeout: Duration,
) -> Result<bool, DeliveryErrorCategory> {
    let Ok(document_url) = egress.check_url(&format!("{}{RECEIVER_DOCUMENT_PATH}", url.origin()))
    else {
        return Ok(false);
    };
    let response = match tokio::time::timeout(
        timeout,
        egress.get(&document_url, axum::http::HeaderMap::new()),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return Err(Attempt::Failed(error)
                .category()
                .unwrap_or(DeliveryErrorCategory::ConnectionRefused));
        }
        Err(_) => return Err(DeliveryErrorCategory::Timeout),
    };
    if !response.status.is_success() || response.body_truncated {
        return Ok(false);
    }
    let Ok(document) = serde_json::from_slice::<ReceiverDocument>(&response.body) else {
        return Ok(false);
    };
    Ok(document
        .receivers
        .iter()
        .any(|prefix| covers_path(prefix, url))
        || document
            .callbacks
            .iter()
            .any(|entry| names_callback(entry, url)))
}

/// Whether path prefix `prefix` of the document's origin covers `url`: a
/// prefix ending in `/` covers every path under it, any other covers that
/// path and the paths below it.
fn covers_path(prefix: &str, url: &CallbackUrl) -> bool {
    if !prefix.starts_with('/') {
        return false;
    }
    let Ok(callback) = url::Url::parse(url.as_str()) else {
        return false;
    };
    let path = callback.path();
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// Whether document entry `entry` names `url`: the same URL, or a prefix
/// ending in `/` of the same origin.
fn names_callback(entry: &str, url: &CallbackUrl) -> bool {
    let Ok(entry) = url::Url::parse(entry) else {
        return false;
    };
    let Ok(callback) = url::Url::parse(url.as_str()) else {
        return false;
    };
    if entry.origin() != callback.origin() {
        return false;
    }
    let (entry, callback) = (entry.as_str(), callback.as_str());
    if entry.ends_with('/') {
        callback.starts_with(entry)
    } else {
        callback == entry
    }
}

/// Bytes of a challenge nonce.
pub const CHALLENGE_BYTES: usize = 32;
/// Bytes of the random part of a control envelope's `webhook-id`.
pub const CONTROL_ID_BYTES: usize = 16;

/// Whether `host` is admitted without a challenge.
pub fn is_allowlisted(config: &WebhookVerificationConfig, host: &str) -> bool {
    config.modes.contains(&VerificationMode::Allowlist)
        && config
            .allowlist
            .iter()
            .any(|allowed| allowed.trim_end_matches('.').eq_ignore_ascii_case(host))
}

/// Send one challenge to `url` for subscription `subscription_id`, signed
/// with `secret`.
pub async fn challenge(
    egress: &SafeEgress,
    url: &CallbackUrl,
    subscription_id: &str,
    secret: &WhsecSecret,
    timeout: Duration,
    now_s: u64,
) -> Result<(), DeliveryErrorCategory> {
    let nonce = random_token(CHALLENGE_BYTES);
    let envelope = ControlEnvelope::Verification {
        challenge: nonce.clone(),
    };
    let webhook_id = envelope.webhook_id(&random_token(CONTROL_ID_BYTES));
    let body = serde_json::to_vec(&envelope).map_err(|_| DeliveryErrorCategory::ChallengeFailed)?;
    let post = SignedPost {
        egress,
        url,
        subscription_id,
        secrets: &[secret],
        webhook_id: &webhook_id,
        body: Bytes::from(body),
    };
    let attempt = match tokio::time::timeout(timeout, post.send(now_s)).await {
        Ok(attempt) => attempt,
        Err(_) => return Err(DeliveryErrorCategory::Timeout),
    };
    match attempt {
        Attempt::Accepted(response) => {
            if response.body_truncated {
                return Err(DeliveryErrorCategory::ChallengeFailed);
            }
            let echoed = serde_json::from_slice::<VerificationResponse>(&response.body)
                .map_err(|_| DeliveryErrorCategory::ChallengeFailed)?;
            if bool::from(echoed.challenge.as_bytes().ct_eq(nonce.as_bytes())) {
                Ok(())
            } else {
                Err(DeliveryErrorCategory::ChallengeFailed)
            }
        }
        other => Err(other
            .category()
            .unwrap_or(DeliveryErrorCategory::ChallengeFailed)),
    }
}

/// Challenge requests in flight from this process, per destination host.
#[derive(Debug, Default)]
pub struct InFlightHosts {
    by_host: Mutex<HashMap<String, u64>>,
}

impl InFlightHosts {
    /// Take a slot for `host` while fewer than `limit` are taken.
    pub fn take(self: &Arc<Self>, host: &str, limit: u64) -> Option<HostSlot> {
        let mut by_host = self.by_host.lock();
        let taken = by_host.entry(host.to_owned()).or_default();
        if *taken >= limit {
            return None;
        }
        *taken += 1;
        Some(HostSlot {
            hosts: Arc::clone(self),
            host: host.to_owned(),
        })
    }

    fn release(&self, host: &str) {
        let mut by_host = self.by_host.lock();
        if let Some(taken) = by_host.get_mut(host) {
            *taken = taken.saturating_sub(1);
            if *taken == 0 {
                by_host.remove(host);
            }
        }
    }
}

/// A taken slot; dropping it frees the slot.
pub struct HostSlot {
    hosts: Arc<InFlightHosts>,
    host: String,
}

impl Drop for HostSlot {
    fn drop(&mut self) {
        self.hosts.release(&self.host);
    }
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
