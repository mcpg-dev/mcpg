//! One signed POST to a callback endpoint, and the outbound client it goes
//! through.
//!
//! Every webhook request (a challenge, an event, a control envelope) is
//! signed per attempt with a fresh `webhook-timestamp`, carries the
//! subscription id in `X-MCP-Subscription-Id`, and goes through
//! [`SafeEgress`], which resolves and checks the host on every attempt and
//! never follows a redirect. Only a [`DeliveryErrorCategory`] leaves this
//! module: never a status line, a header, a body or an address.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chacha20poly1305::aead::Generate as _;
use mcpg_safe_egress::{
    CallbackUrl, EgressError, EgressPolicy, EgressResponse, ErrorCategory, PolicyError, Resolve,
    SafeEgress,
};
use mcpg_standard_webhooks::{SignError, WhsecSecret};

use crate::config::events::WebhookEgressConfig;
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    DeliveryErrorCategory, SUBSCRIPTION_ID_HEADER,
};

/// `User-Agent` of every webhook request.
pub const USER_AGENT: &str = "mcpg-events/1";

/// Builds the outbound client for a config. Tests replace it to reach
/// receivers on loopback.
pub type EgressFactory = Arc<dyn Fn(EgressPolicy) -> Result<SafeEgress, PolicyError> + Send + Sync>;

/// The egress policy of `config`.
pub fn egress_policy(config: &WebhookEgressConfig) -> EgressPolicy {
    EgressPolicy {
        allowed_ports: config.allowed_ports.clone(),
        deny_hosts: config.deny_hosts.clone(),
        connect_timeout: Duration::from_millis(config.connect_timeout_ms.max(1)),
        attempt_timeout: Duration::from_millis(config.attempt_timeout_ms.max(1)),
        allow_private_backends: config.allow_private_backends,
        user_agent: USER_AGENT.to_owned(),
        ..EgressPolicy::default()
    }
}

/// A factory that resolves through `resolver` and admits plain `http` and
/// loopback hosts, for tests that run their receivers in-process.
pub fn loopback_factory(resolver: Arc<dyn Resolve>) -> EgressFactory {
    Arc::new(move |mut policy: EgressPolicy| {
        policy.allow_private_backends = true;
        policy.allow_http = true;
        SafeEgress::with_resolver(policy, Arc::clone(&resolver))
    })
}

/// `count` random bytes as unpadded base64url.
pub fn random_token(count: usize) -> String {
    let mut out = Vec::with_capacity(count + 32);
    while out.len() < count {
        out.extend_from_slice(&<[u8; 32]>::generate());
    }
    out.truncate(count);
    URL_SAFE_NO_PAD.encode(out)
}

/// What one attempt came to.
#[derive(Debug)]
pub enum Attempt {
    /// A `2xx`.
    Accepted(EgressResponse),
    /// Any other status.
    Refused(EgressResponse),
    /// No response: refused, unreachable, timed out or a TLS failure.
    Failed(EgressError),
    /// Not sent: there is no secret to sign with.
    NotSent,
    /// Not sent: the id is no valid Standard Webhooks message id, so no
    /// later attempt can sign it either.
    Unsignable,
}

impl Attempt {
    /// The failure category, `None` for a `2xx`.
    pub fn category(&self) -> Option<DeliveryErrorCategory> {
        match self {
            Self::Accepted(_) => None,
            Self::Refused(response) => Some(status_category(response.status.as_u16())),
            Self::Failed(error) => Some(egress_category(error)),
            Self::NotSent | Self::Unsignable => Some(DeliveryErrorCategory::ConnectionRefused),
        }
    }

    /// The status, when a response came.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Accepted(r) | Self::Refused(r) => Some(r.status.as_u16()),
            Self::Failed(_) | Self::NotSent | Self::Unsignable => None,
        }
    }

    /// The bounded label metrics carry.
    pub fn outcome_label(&self) -> &'static str {
        if matches!(self, Self::Unsignable) {
            return UNSIGNABLE_ID;
        }
        match self.category() {
            None => "accepted",
            Some(category) => category.as_str(),
        }
    }
}

/// The label of an [`Attempt::Unsignable`] in metrics and audit records.
pub const UNSIGNABLE_ID: &str = "unsignable_id";

/// The category of a non-`2xx` status.
pub fn status_category(status: u16) -> DeliveryErrorCategory {
    match status {
        400..=499 => DeliveryErrorCategory::Http4xx,
        500..=599 => DeliveryErrorCategory::Http5xx,
        // A redirect is refused like an unreachable host: following it would
        // reach a destination nobody checked.
        _ => DeliveryErrorCategory::ConnectionRefused,
    }
}

/// The category of an egress failure. A blocked host and one that does not
/// resolve both read `connection_refused`, so the answer is no oracle for
/// internal names.
pub fn egress_category(error: &EgressError) -> DeliveryErrorCategory {
    match error.category() {
        ErrorCategory::Timeout => DeliveryErrorCategory::Timeout,
        ErrorCategory::TlsError => DeliveryErrorCategory::TlsError,
        ErrorCategory::ConnectionRefused => DeliveryErrorCategory::ConnectionRefused,
    }
}

/// One signed request.
pub struct SignedPost<'a> {
    pub egress: &'a SafeEgress,
    pub url: &'a CallbackUrl,
    pub subscription_id: &'a str,
    /// The current secret first; the previous one during a rotation.
    pub secrets: &'a [&'a WhsecSecret],
    /// `webhook-id`: the event id, or `msg_<type>_<random>`.
    pub webhook_id: &'a str,
    pub body: Bytes,
}

impl SignedPost<'_> {
    /// Sign and send at `now_s` (Unix seconds).
    pub async fn send(self, now_s: u64) -> Attempt {
        let mut headers = HeaderMap::new();
        let signed = match mcpg_standard_webhooks::sign_message(
            self.secrets,
            self.webhook_id,
            now_s,
            &self.body,
        ) {
            Ok(signed) => signed,
            Err(SignError::NoSecret) => return Attempt::NotSent,
            Err(SignError::InvalidMessageId) => return Attempt::Unsignable,
        };
        if signed.insert_into(&mut headers).is_err() {
            return Attempt::Unsignable;
        }
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Ok(value) = HeaderValue::from_str(self.subscription_id) {
            headers.insert(HeaderName::from_static(SUBSCRIPTION_ID_HEADER), value);
        }
        match self.egress.post(self.url, headers, self.body).await {
            Ok(response) if response.status.is_success() => Attempt::Accepted(response),
            Ok(response) => Attempt::Refused(response),
            Err(error) => {
                if error.is_blocked() {
                    metrics::counter!("mcpg_events_egress_blocked_total").increment(1);
                }
                Attempt::Failed(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_categories() {
        assert_eq!(status_category(404), DeliveryErrorCategory::Http4xx);
        assert_eq!(status_category(410), DeliveryErrorCategory::Http4xx);
        assert_eq!(status_category(503), DeliveryErrorCategory::Http5xx);
        assert_eq!(
            status_category(302),
            DeliveryErrorCategory::ConnectionRefused
        );
        assert_eq!(
            Attempt::NotSent.category(),
            Some(DeliveryErrorCategory::ConnectionRefused)
        );
        assert_eq!(Attempt::Unsignable.outcome_label(), "unsignable_id");
    }

    #[tokio::test]
    async fn a_dotted_id_is_unsignable_and_no_secret_is_not_sent() {
        let egress = crate::runtime::events::test_support::loopback_egress();
        let url = egress.check_url("http://127.0.0.1:9/hook").unwrap();
        let secret = WhsecSecret::from_key_bytes(&[7; 32]).unwrap();
        let dotted = SignedPost {
            egress: &egress,
            url: &url,
            subscription_id: "sub_1",
            secrets: &[&secret],
            webhook_id: "orders.created-1",
            body: Bytes::from_static(b"{}"),
        };
        assert!(matches!(dotted.send(1).await, Attempt::Unsignable));
        let keyless = SignedPost {
            egress: &egress,
            url: &url,
            subscription_id: "sub_1",
            secrets: &[],
            webhook_id: "evt_1",
            body: Bytes::from_static(b"{}"),
        };
        assert!(matches!(keyless.send(1).await, Attempt::NotSent));
    }

    #[test]
    fn random_tokens_have_the_requested_entropy() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(random_token(40)).unwrap().len(), 40);
    }

    #[test]
    fn the_policy_carries_the_config() {
        let config = WebhookEgressConfig {
            allowed_ports: vec![443],
            deny_hosts: vec!["corp.example".to_owned()],
            connect_timeout_ms: 1_500,
            attempt_timeout_ms: 4_000,
            allow_private_backends: false,
            probe_url: None,
        };
        let policy = egress_policy(&config);
        assert_eq!(policy.allowed_ports, vec![443]);
        assert_eq!(policy.deny_hosts, vec!["corp.example".to_owned()]);
        assert_eq!(policy.connect_timeout, Duration::from_millis(1_500));
        assert_eq!(policy.attempt_timeout, Duration::from_millis(4_000));
        assert!(!policy.allow_http);
        assert_eq!(policy.user_agent, USER_AGENT);
    }
}
