//! MCP Events (`io.modelcontextprotocol/events`, experimental) config.
//!
//! Two blocks. `mcp.capabilities.events[]` declares the event types the
//! gateway offers, each bound to exactly one source. `mcp.configurations.events`
//! holds the runtime behaviour: whether the `events/*` methods are served on
//! the `2026-07-28` wire, where `server/discover` advertises them, the stores
//! behind subscriptions and the event log, and the webhook delivery profile.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::store_override::StoreOverrideConfig;
use super::watch::WatchStrategyConfig;
use crate::protocol::v_2026_07_28::extensions::events::wire::MAX_STREAM_HEARTBEAT_MS;

/// Longest event-type name.
pub const MAX_EVENT_NAME_CHARS: usize = 128;
/// Longest inbound `source_id`.
pub const MAX_SOURCE_ID_CHARS: usize = 64;
/// Largest webhook request body a receiver accepts, per the delivery profile.
pub const MAX_WEBHOOK_BODY_BYTES: u64 =
    crate::protocol::v_2026_07_28::extensions::events::wire::MAX_WEBHOOK_BODY_BYTES as u64;
/// Room kept in every webhook body for the envelope fields and the cursor
/// around an occurrence's `data`.
pub const WEBHOOK_BODY_MARGIN_BYTES: u64 = 16_384;
/// Largest `webhook.max_payload_bytes`.
pub const MAX_PAYLOAD_BYTES_CEILING: u64 = MAX_WEBHOOK_BODY_BYTES - WEBHOOK_BODY_MARGIN_BYTES;
/// Retention byte budget of a type that sets no `retention.max_bytes`.
pub const DEFAULT_RETENTION_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Default size of the JetStream bucket the NATS coordinator gives the
/// events stores (`jetstream.named_bucket_max_bytes`).
pub const NATS_EVENTS_BUCKET_BYTES: u64 = 256 * 1024 * 1024;
/// Size assumed for an in-process memory store.
pub const MEMORY_STORE_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
/// The largest inbound request body an `inbound` source accepts.
pub const MAX_INBOUND_BODY_BYTES: usize = 262_144;

// ---------------------------------------------------------------------------
// mcp.configurations.events
// ---------------------------------------------------------------------------

/// `events:` config — the experimental MCP Events extension.
///
/// Off by default. With `enabled: false` the `events/*` methods answer
/// `-32601` and `server/discover` does not mention events. The extension
/// is served on the `2026-07-28` wire over HTTP only; the `2025-11-25`
/// wire and stdio never carry it. Event types are declared under
/// `mcp.capabilities.events`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// Serve the `events/*` methods of every delivery mode enabled below,
    /// and advertise the extension. Default `false`.
    pub enabled: bool,

    /// Where `server/discover` advertises the extension. The drafts
    /// disagree on the location, so both are on by default:
    /// `capability` is the top-level `capabilities.events` object (read
    /// by ChatGPT), `extension` is the
    /// `capabilities.extensions["io.modelcontextprotocol/events"]` entry.
    /// Must name at least one location when `enabled` is `true`.
    pub advertise: Vec<EventsAdvertiseLocation>,

    /// The answer to `events/unsubscribe` for a subscription that does
    /// not exist. `ok` (default) answers `{}`, as an idempotent
    /// unsubscribe; `not_found` answers `-32011` with
    /// `data.kind: "subscription"`.
    pub unsubscribe_unknown: UnsubscribeUnknown,

    /// How the extension's error codes are numbered. `draft` (default)
    /// answers `-32011` to `-32015`, the numbers the ChatGPT profile
    /// documents; `sep_3415` answers `-32023` to `-32027`, the numbers the
    /// upstream sketch assigns. The documentation names the `draft`
    /// numbers.
    pub error_codes: EventErrorCodes,

    /// Store of the webhook subscription records (store role
    /// `event-subscription`). Omitted, the cluster coordinator's store is
    /// used, which is in memory on a single node. Webhook delivery
    /// refuses a store that does not survive a restart unless
    /// `allow_ephemeral_subscriptions` is set; a single node keeps
    /// subscriptions with `{kind: file, dir: …}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreOverrideConfig>,

    /// Store of the event log (store role `event-log`). Omitted, the
    /// cluster coordinator's store is used. The retention byte budgets of
    /// every event type must fit this store (see
    /// `mcp.capabilities.events[].retention.max_bytes`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_store: Option<StoreOverrideConfig>,

    /// Accept webhook subscriptions on a store that loses them on a
    /// restart. Every grant is then capped at `webhook.ttl.min_ms`, so a
    /// client refreshes before a restart can matter for long. Default
    /// `false`.
    pub allow_ephemeral_subscriptions: bool,

    /// Hold every delivery, in every mode, while keeping every
    /// subscription and every event within retention: webhook deliveries
    /// wait, a poll answers no events and the cursor it was given, and a
    /// stream sends heartbeats only. Subscribe and refresh still answer,
    /// with `deliveryStatus.active: false` and `lastError: "paused"`.
    /// Delivery resumes from each position when this is cleared. Default
    /// `false`.
    pub delivery_paused: bool,

    /// How often the authorization of a long-lived grant is checked again
    /// from its stored identity: each webhook subscription and each open
    /// stream. In milliseconds; default 300 000 (5 minutes).
    pub reauthorize_interval_ms: u64,

    /// Audit of event delivery.
    pub audit: EventsAuditConfig,

    /// Lifecycle of event sources.
    pub sources: EventSourcesConfig,

    /// Signing profiles of inbound senders beyond the built-in ones
    /// (`standard_webhooks`, `github`, `stripe`, `slack`). A route names
    /// one in `source.inbound.verify.profile`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inbound_profiles: Vec<InboundProfileConfig>,

    /// Event log limits.
    pub log: EventLogConfig,

    /// Webhook delivery (`events/subscribe`).
    pub webhook: EventsWebhookConfig,

    /// Poll delivery (`events/poll`).
    pub poll: EventsPollConfig,

    /// Push delivery (`events/stream`).
    pub push: EventsPushConfig,
}

/// A place in the `server/discover` capabilities where MCP Events is
/// advertised.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventsAdvertiseLocation {
    /// The top-level `capabilities.events` object.
    Capability,
    /// The `capabilities.extensions["io.modelcontextprotocol/events"]`
    /// entry.
    Extension,
}

/// The answer to an `events/unsubscribe` naming no live subscription.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UnsubscribeUnknown {
    /// `{}`, the same answer as for a subscription that existed.
    #[default]
    Ok,
    /// `-32011` with `data.kind: "subscription"`.
    NotFound,
}

/// The numbering of the MCP Events error codes on the wire.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventErrorCodes {
    /// `-32011` to `-32015`.
    #[default]
    Draft,
    /// `-32023` to `-32027`.
    #[serde(rename = "sep_3415")]
    Sep3415,
}

impl EventErrorCodes {
    /// The wire crate's numbering of this choice.
    pub fn numbering(
        self,
    ) -> mcpg_mcp_wire::v_2026_07_28::extensions::events::errors::CodeNumbering {
        use mcpg_mcp_wire::v_2026_07_28::extensions::events::errors::CodeNumbering;
        match self {
            Self::Draft => CodeNumbering::Draft,
            Self::Sep3415 => CodeNumbering::Sep3415,
        }
    }
}

/// `events.audit:` — how delivery is audited.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventsAuditConfig {
    /// `summary` (default) writes one record per subscription per window
    /// with delivery counts; `every` writes one record per delivery
    /// request.
    pub deliveries: DeliveryAuditMode,
}

/// Granularity of delivery audit records.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryAuditMode {
    /// Counts per subscription per window.
    #[default]
    Summary,
    /// One record per delivery request.
    Every,
}

/// `events.sources:` — when event sources run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventSourcesConfig {
    /// How long a source keeps running after its last subscription ends,
    /// in milliseconds. Default 300 000 (5 minutes).
    pub linger_ms: u64,
}

impl Default for EventSourcesConfig {
    fn default() -> Self {
        Self { linger_ms: 300_000 }
    }
}

/// `events.log:` — the inbox that `inbound` routes write before an event
/// reaches the log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventLogConfig {
    /// How long an inbox row waits for the log writer, in milliseconds.
    /// An inbound route answers `503` with `Retry-After` once the inbox
    /// has not been drained for this long, so the sender keeps the event
    /// and retries. Default 86 400 000 (24 hours).
    pub inbox_ttl_ms: u64,
    /// Most rows one source's inbox holds; past it an inbound route
    /// answers `503` with `Retry-After`. Default 10 000.
    pub inbox_max_rows: u64,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            inbox_ttl_ms: 86_400_000,
            inbox_max_rows: 10_000,
        }
    }
}

/// `events.webhook:` — the webhook delivery profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventsWebhookConfig {
    /// Accept `events/subscribe` and deliver to callback URLs. Default
    /// `true`. Requires a store that survives a restart (or
    /// `allow_ephemeral_subscriptions`) and a key that every replica
    /// shares: `cluster.state_encryption_key_env` or
    /// `mcp.configurations.sessions.synthetic_session_key`.
    pub enabled: bool,
    /// The lowest caller trust that may subscribe. `verified` (default)
    /// requires a cryptographically verified principal;
    /// `header_asserted` also admits a principal named by a request
    /// header and is for self-hosted deployments that trust their
    /// front proxy.
    pub require_trust: SubscriberTrust,
    /// Lifetime of a subscription grant.
    pub ttl: WebhookTtlConfig,
    /// Subscription and delivery limits.
    pub limits: WebhookLimitsConfig,
    /// Proof that a callback endpoint wants the deliveries.
    pub verification: WebhookVerificationConfig,
    /// The outbound client that reaches callback URLs.
    pub egress: WebhookEgressConfig,
    /// Retries of one delivery.
    pub retry: WebhookRetryConfig,
    /// When failing deliveries suspend a subscription.
    pub suspension: WebhookSuspensionConfig,
    /// Largest serialized occurrence, in bytes; a larger occurrence is not
    /// delivered. At most 245 760 (the default), so the whole request body
    /// stays within 262 144 bytes.
    pub max_payload_bytes: u64,
    /// How long the previous secret keeps signing after a subscribe
    /// replaces it, in milliseconds. Default 600 000 (10 minutes).
    pub secret_rotation_grace_ms: u64,
    /// The control envelopes sent besides events. Default both `gap` and
    /// `terminated`; a `verification` envelope is always sent.
    pub control_envelopes: Vec<ControlEnvelopeKind>,
}

impl Default for EventsWebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_trust: SubscriberTrust::default(),
            ttl: WebhookTtlConfig::default(),
            limits: WebhookLimitsConfig::default(),
            verification: WebhookVerificationConfig::default(),
            egress: WebhookEgressConfig::default(),
            retry: WebhookRetryConfig::default(),
            suspension: WebhookSuspensionConfig::default(),
            max_payload_bytes: MAX_PAYLOAD_BYTES_CEILING,
            secret_rotation_grace_ms: 600_000,
            control_envelopes: vec![ControlEnvelopeKind::Gap, ControlEnvelopeKind::Terminated],
        }
    }
}

/// Lowest trust tier allowed to hold a webhook subscription.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberTrust {
    /// A cryptographically verified principal.
    #[default]
    Verified,
    /// Also a principal named by a trusted request header.
    HeaderAsserted,
}

/// A webhook control envelope the gateway may send.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlEnvelopeKind {
    /// Events were skipped; carries the cursor to persist.
    Gap,
    /// The subscription ended on the gateway's side.
    Terminated,
}

/// `events.webhook.ttl:` — subscription grant lifetimes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookTtlConfig {
    /// Grant for a subscribe that sends no `ttlMs`, in milliseconds.
    /// Default 3 600 000 (1 hour).
    pub default_ms: u64,
    /// Shortest grant; a shorter `ttlMs` is raised to it. Default 300 000
    /// (5 minutes).
    pub min_ms: u64,
    /// Longest grant; a longer `ttlMs` is lowered to it. Default
    /// 86 400 000 (24 hours).
    pub max_ms: u64,
    /// Grant a subscription with no expiry when the client sends
    /// `ttlMs: null`. Off by default, when such a request receives a
    /// `max_ms` grant instead.
    pub allow_no_expiry: bool,
    /// Never grant past the expiry of the subscriber's access token, when
    /// it is known (never below `min_ms`). Default `true`.
    pub clamp_to_token_expiry: bool,
}

impl Default for WebhookTtlConfig {
    fn default() -> Self {
        Self {
            default_ms: 3_600_000,
            min_ms: 300_000,
            max_ms: 86_400_000,
            allow_no_expiry: false,
            clamp_to_token_expiry: true,
        }
    }
}

/// `events.webhook.limits:` — subscription and delivery limits. A
/// subscribe past a subscription limit answers `-32013` naming the limit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookLimitsConfig {
    /// Subscriptions one principal may hold. Default 100.
    pub per_principal: u64,
    /// Distinct callback hosts one principal may name. Default 5.
    pub per_principal_callback_hosts: u64,
    /// Subscriptions on one event type. Default 5 000.
    pub per_type: u64,
    /// Subscriptions on this gateway. Default 10 000.
    pub total: u64,
    /// Concurrent delivery requests to one callback host. Default 8.
    pub per_host_concurrency: u64,
    /// Deliveries of one subscription in flight at once. Default 4.
    pub per_subscription_in_flight: u64,
}

impl Default for WebhookLimitsConfig {
    fn default() -> Self {
        Self {
            per_principal: 100,
            per_principal_callback_hosts: 5,
            per_type: 5_000,
            total: 10_000,
            per_host_concurrency: 8,
            per_subscription_in_flight: 4,
        }
    }
}

/// `events.webhook.verification:` — how a callback endpoint proves it
/// wants the deliveries before the first one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookVerificationConfig {
    /// Accepted proofs. `challenge` (default, and always required) POSTs
    /// a signed challenge that the endpoint echoes; `allowlist` also
    /// admits the hosts in `allowlist` without one; `well_known` admits a
    /// callback its origin's receiver document names.
    pub modes: Vec<VerificationMode>,
    /// Callback hosts admitted without a challenge when `modes` lists
    /// `allowlist`.
    pub allowlist: Vec<String>,
    /// How long a passed verification is reused for the same principal
    /// and callback URL, in milliseconds. Default 86 400 000 (24 hours).
    pub cache_ttl_ms: u64,
    /// Time allowed for a challenge request, in milliseconds. Default
    /// 10 000.
    pub timeout_ms: u64,
    /// Challenge requests per callback host per minute, across the
    /// cluster. Default 6.
    pub per_host_per_min: u64,
    /// Challenge requests in flight to one callback host. Default 3.
    pub per_host_in_flight: u64,
}

impl Default for WebhookVerificationConfig {
    fn default() -> Self {
        Self {
            modes: vec![VerificationMode::Challenge],
            allowlist: Vec::new(),
            cache_ttl_ms: 86_400_000,
            timeout_ms: 10_000,
            per_host_per_min: 6,
            per_host_in_flight: 3,
        }
    }
}

/// A proof of intent a callback endpoint may give.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    /// A signed challenge the endpoint echoes in a 2xx response.
    Challenge,
    /// The callback host is on `verification.allowlist`.
    Allowlist,
    /// The callback's origin publishes `/.well-known/mcp-webhook-receiver.json`
    /// naming it: `{"callbacks": [...]}`, each entry a URL or a prefix
    /// ending in `/`. Provisional: the upstream sketch has not fixed the
    /// document's shape.
    WellKnown,
}

/// `events.webhook.egress:` — the client that reaches callback URLs.
/// It resolves the host on every attempt, refuses a host when any
/// address is not globally routable, connects to the checked address,
/// and never follows a redirect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookEgressConfig {
    /// Ports a callback URL may name. Empty (default) allows any port.
    pub allowed_ports: Vec<u16>,
    /// Hosts never contacted: a domain (with every name under it) or an
    /// IP address. Applies to existing subscriptions from their next
    /// delivery.
    pub deny_hosts: Vec<String>,
    /// Time allowed to open a connection, in milliseconds. Default 3 000.
    pub connect_timeout_ms: u64,
    /// Time allowed for one whole request, in milliseconds. Default
    /// 10 000.
    pub attempt_timeout_ms: u64,
    /// Admit callback hosts outside the public internet. For self-hosted
    /// deployments that deliver inside their own network. Default
    /// `false`.
    pub allow_private_backends: bool,
    /// A URL fetched with `GET`, through this egress policy, when webhook
    /// delivery starts and whenever the egress settings change. Any HTTP
    /// answer shows callbacks are reachable and sets
    /// `mcpg_events_egress_probe_ok` to `1`; no answer sets it to `0` and
    /// logs a warning. Must pass the policy above. Omitted, no probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
}

impl Default for WebhookEgressConfig {
    fn default() -> Self {
        Self {
            allowed_ports: Vec::new(),
            deny_hosts: Vec::new(),
            connect_timeout_ms: 3_000,
            attempt_timeout_ms: 10_000,
            allow_private_backends: false,
            probe_url: None,
        }
    }
}

/// `events.webhook.retry:` — retries of one delivery. A `410` or `413`
/// answer is never retried.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookRetryConfig {
    /// Attempts per delivery, the first included. Default 5.
    pub max_attempts: u64,
    /// Time after the first attempt within which retries happen, in
    /// milliseconds. Default 900 000 (15 minutes). On a gateway a control
    /// plane manages, the plan's retry window is the most it can be.
    pub window_ms: u64,
    /// Wait as long as a `Retry-After` answer asks, inside the window.
    /// Default `true`.
    pub honor_retry_after: bool,
}

impl Default for WebhookRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_ms: 900_000,
            honor_retry_after: true,
        }
    }
}

/// `events.webhook.suspension:` — when failing deliveries suspend a
/// subscription. A refresh reactivates it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookSuspensionConfig {
    /// Share of failed attempts within `window_ms` that suspends delivery,
    /// greater than 0 and at most 1. Default 0.95.
    pub failure_rate: FailureRate,
    /// The window the failure rate is measured over, in milliseconds.
    /// Default 3 600 000 (1 hour).
    pub window_ms: u64,
    /// Fewest attempts within the window before the rate counts. Default
    /// 100.
    pub min_attempts: u64,
    /// How long a suspended subscription with no expiry is kept before it
    /// is dropped, in milliseconds. Default 604 800 000 (7 days).
    pub drop_no_expiry_after_ms: u64,
}

impl Default for WebhookSuspensionConfig {
    fn default() -> Self {
        Self {
            failure_rate: FailureRate(0.95),
            window_ms: 3_600_000,
            min_attempts: 100,
            drop_no_expiry_after_ms: 604_800_000,
        }
    }
}

/// A share between 0 and 1.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct FailureRate(pub f64);

impl PartialEq for FailureRate {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for FailureRate {}

/// `events.poll:` — `events/poll`: a client reads a type's log itself, on
/// any replica, with the cursor of its previous poll. Off by default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventsPollConfig {
    /// Serve `events/poll`, and offer `poll` on every type whose
    /// `delivery` lists it. Default `false`.
    pub enabled: bool,
    /// The lowest caller trust that may poll. `verified` (default)
    /// requires a cryptographically verified principal;
    /// `header_asserted` also admits a principal named by a request
    /// header.
    pub require_trust: SubscriberTrust,
    /// Suggested wait before the next poll, in milliseconds. Default 5 000.
    pub next_poll_ms: u64,
    /// Shortest wait the gateway asks for, in milliseconds. Default 1 000.
    pub min_next_poll_ms: u64,
    /// Events per poll when the client sets no `maxEvents`. Default 100.
    pub max_events: u64,
    /// Most events per poll. Default 1 000.
    pub max_events_cap: u64,
    /// A poll lease lasts this many `next_poll_ms` after the last poll.
    /// While a type has a lease, its source runs. Default 3.
    pub lease_multiplier: u64,
    /// Poll leases one principal may hold: one per event type and
    /// arguments it polls. Default 100.
    pub max_leases_per_principal: u64,
}

impl Default for EventsPollConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_trust: SubscriberTrust::Verified,
            next_poll_ms: 5_000,
            min_next_poll_ms: 1_000,
            max_events: 100,
            max_events_cap: 1_000,
            lease_multiplier: 3,
            max_leases_per_principal: 100,
        }
    }
}

/// `events.push:` — `events/stream`: one long-lived response per
/// subscription, on the replica the client reaches. Off by default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventsPushConfig {
    /// Serve `events/stream`, and offer `push` on every type whose
    /// `delivery` lists it. Default `false`.
    pub enabled: bool,
    /// The lowest caller trust that may open a stream. `verified`
    /// (default) requires a cryptographically verified principal;
    /// `header_asserted` also admits a principal named by a request
    /// header.
    pub require_trust: SubscriberTrust,
    /// Interval of heartbeat frames, in milliseconds, from 1 000 to
    /// 30 000. Default 20 000. A client that hears nothing for twice this
    /// treats the stream as dead and reconnects with its cursor.
    pub heartbeat_interval_ms: u64,
    /// Streams one principal may hold open across the cluster. Default 16.
    /// These do not count against the server-push stream cap of a session.
    pub max_streams_per_principal: u64,
}

impl Default for EventsPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_trust: SubscriberTrust::Verified,
            heartbeat_interval_ms: 20_000,
            max_streams_per_principal: 16,
        }
    }
}

impl EventsPushConfig {
    fn validate(&self) -> Result<()> {
        if !(1_000..=MAX_STREAM_HEARTBEAT_MS).contains(&self.heartbeat_interval_ms) {
            bail!(
                "push.heartbeat_interval_ms must be from 1000 to {MAX_STREAM_HEARTBEAT_MS}; the \
                 extension asks for a data frame at least every 30 seconds"
            );
        }
        positive(
            "push.max_streams_per_principal",
            self.max_streams_per_principal,
        )
    }
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertise: vec![
                EventsAdvertiseLocation::Capability,
                EventsAdvertiseLocation::Extension,
            ],
            unsubscribe_unknown: UnsubscribeUnknown::default(),
            error_codes: EventErrorCodes::default(),
            store: None,
            log_store: None,
            allow_ephemeral_subscriptions: false,
            delivery_paused: false,
            reauthorize_interval_ms: 300_000,
            audit: EventsAuditConfig::default(),
            sources: EventSourcesConfig::default(),
            inbound_profiles: Vec::new(),
            log: EventLogConfig::default(),
            webhook: EventsWebhookConfig::default(),
            poll: EventsPollConfig::default(),
            push: EventsPushConfig::default(),
        }
    }
}

impl EventsConfig {
    /// Checks that need nothing but this block.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.enabled && self.advertise.is_empty() {
            bail!(
                "advertise must name `capability`, `extension` or both while events are \
                 enabled; a client cannot discover an extension advertised nowhere"
            );
        }
        if let Some(store) = &self.store {
            store
                .validate()
                .map_err(|e| anyhow::anyhow!("store override: {e}"))?;
        }
        if let Some(store) = &self.log_store {
            store
                .validate()
                .map_err(|e| anyhow::anyhow!("log_store override: {e}"))?;
        }
        let mut profile_names = BTreeSet::new();
        for (index, profile) in self.inbound_profiles.iter().enumerate() {
            let at = format!("inbound_profiles[{index}]");
            validate_inbound_profile(&at, profile)?;
            if builtin_inbound_profiles()
                .iter()
                .any(|p| p.name == profile.name)
            {
                bail!(
                    "{at}.name `{}` is a built-in profile; give the declared one another name",
                    profile.name
                );
            }
            if !profile_names.insert(profile.name.as_str()) {
                bail!("{at}: duplicate profile name `{}`", profile.name);
            }
        }
        positive("sources.linger_ms", self.sources.linger_ms)?;
        positive("reauthorize_interval_ms", self.reauthorize_interval_ms)?;
        positive("log.inbox_ttl_ms", self.log.inbox_ttl_ms)?;
        positive("log.inbox_max_rows", self.log.inbox_max_rows)?;
        self.webhook.validate()?;
        self.poll.validate()?;
        self.push.validate()?;
        for (mode, trust) in [
            ("webhook", self.webhook.require_trust),
            ("poll", self.poll.require_trust),
            ("push", self.push.require_trust),
        ] {
            if trust == SubscriberTrust::HeaderAsserted {
                tracing::warn!(
                    "mcp.configurations.events.{mode}.require_trust is header_asserted: a \
                     principal named by a request header receives events by {mode}; use it \
                     only behind a proxy that sets that header itself"
                );
            }
        }
        Ok(())
    }

    /// Whether the top-level `capabilities.events` object is advertised.
    pub fn advertises_capability(&self) -> bool {
        self.enabled
            && self
                .advertise
                .contains(&EventsAdvertiseLocation::Capability)
    }

    /// Whether the extensions-map entry is advertised.
    pub fn advertises_extension(&self) -> bool {
        self.enabled && self.advertise.contains(&EventsAdvertiseLocation::Extension)
    }

    /// The delivery modes this config serves, in wire order.
    pub fn enabled_modes(&self) -> Vec<EventDeliveryMode> {
        let mut modes = Vec::new();
        if self.poll.enabled {
            modes.push(EventDeliveryMode::Poll);
        }
        if self.push.enabled {
            modes.push(EventDeliveryMode::Push);
        }
        if self.webhook.enabled {
            modes.push(EventDeliveryMode::Webhook);
        }
        modes
    }
}

impl EventsPollConfig {
    fn validate(&self) -> Result<()> {
        positive("poll.min_next_poll_ms", self.min_next_poll_ms)?;
        if self.min_next_poll_ms > self.next_poll_ms {
            bail!(
                "poll: min_next_poll_ms ({}) <= next_poll_ms ({}) must hold",
                self.min_next_poll_ms,
                self.next_poll_ms
            );
        }
        positive("poll.max_events", self.max_events)?;
        if self.max_events > self.max_events_cap {
            bail!(
                "poll: max_events ({}) <= max_events_cap ({}) must hold",
                self.max_events,
                self.max_events_cap
            );
        }
        positive("poll.lease_multiplier", self.lease_multiplier)?;
        positive(
            "poll.max_leases_per_principal",
            self.max_leases_per_principal,
        )?;
        Ok(())
    }
}

impl EventsWebhookConfig {
    fn validate(&self) -> Result<()> {
        let ttl = &self.ttl;
        positive("webhook.ttl.min_ms", ttl.min_ms)?;
        if !(ttl.min_ms <= ttl.default_ms && ttl.default_ms <= ttl.max_ms) {
            bail!(
                "webhook.ttl: min_ms ({}) <= default_ms ({}) <= max_ms ({}) must hold",
                ttl.min_ms,
                ttl.default_ms,
                ttl.max_ms
            );
        }
        let limits = &self.limits;
        positive("webhook.limits.per_principal", limits.per_principal)?;
        positive(
            "webhook.limits.per_principal_callback_hosts",
            limits.per_principal_callback_hosts,
        )?;
        positive("webhook.limits.per_type", limits.per_type)?;
        positive("webhook.limits.total", limits.total)?;
        positive(
            "webhook.limits.per_host_concurrency",
            limits.per_host_concurrency,
        )?;
        positive(
            "webhook.limits.per_subscription_in_flight",
            limits.per_subscription_in_flight,
        )?;
        let verification = &self.verification;
        if !verification.modes.contains(&VerificationMode::Challenge) {
            bail!(
                "webhook.verification.modes must include `challenge`: it is the proof every \
                 callback endpoint outside the allowlist gives"
            );
        }
        if verification.modes.contains(&VerificationMode::Allowlist)
            && verification.allowlist.is_empty()
        {
            bail!(
                "webhook.verification.modes lists `allowlist` but verification.allowlist is empty"
            );
        }
        if !verification.modes.contains(&VerificationMode::Allowlist)
            && !verification.allowlist.is_empty()
        {
            tracing::warn!(
                "mcp.configurations.events.webhook.verification.allowlist names hosts, but \
                 verification.modes does not list `allowlist`, so the list admits nothing"
            );
        }
        if let Some(index) = verification
            .allowlist
            .iter()
            .position(|host| host.trim().is_empty() || host.contains(['/', '*', ' ']))
        {
            bail!(
                "webhook.verification.allowlist[{index}] must be a host name or address, with \
                 no scheme, path or wildcard"
            );
        }
        positive(
            "webhook.verification.cache_ttl_ms",
            verification.cache_ttl_ms,
        )?;
        positive("webhook.verification.timeout_ms", verification.timeout_ms)?;
        positive(
            "webhook.verification.per_host_per_min",
            verification.per_host_per_min,
        )?;
        positive(
            "webhook.verification.per_host_in_flight",
            verification.per_host_in_flight,
        )?;
        let egress = &self.egress;
        positive(
            "webhook.egress.connect_timeout_ms",
            egress.connect_timeout_ms,
        )?;
        positive(
            "webhook.egress.attempt_timeout_ms",
            egress.attempt_timeout_ms,
        )?;
        if egress.connect_timeout_ms > egress.attempt_timeout_ms {
            bail!("webhook.egress.connect_timeout_ms must not exceed attempt_timeout_ms");
        }
        if egress.allowed_ports.contains(&0) {
            bail!("webhook.egress.allowed_ports must not contain 0");
        }
        if let Some(index) = egress.deny_hosts.iter().position(|h| h.trim().is_empty()) {
            bail!("webhook.egress.deny_hosts[{index}] must not be empty");
        }
        positive("webhook.retry.max_attempts", self.retry.max_attempts)?;
        positive("webhook.retry.window_ms", self.retry.window_ms)?;
        let suspension = &self.suspension;
        let rate = suspension.failure_rate.0;
        if !(rate.is_finite() && rate > 0.0 && rate <= 1.0) {
            bail!("webhook.suspension.failure_rate must be greater than 0 and at most 1");
        }
        positive("webhook.suspension.window_ms", suspension.window_ms)?;
        positive("webhook.suspension.min_attempts", suspension.min_attempts)?;
        positive(
            "webhook.suspension.drop_no_expiry_after_ms",
            suspension.drop_no_expiry_after_ms,
        )?;
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_PAYLOAD_BYTES_CEILING {
            bail!(
                "webhook.max_payload_bytes must be between 1 and {MAX_PAYLOAD_BYTES_CEILING}, so \
                 the whole request body stays within {MAX_WEBHOOK_BODY_BYTES} bytes"
            );
        }
        Ok(())
    }
}

fn positive(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        bail!("{field} must be greater than 0");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// mcp.capabilities.events[]
// ---------------------------------------------------------------------------

/// One event type the gateway offers (`mcp.capabilities.events[]`).
///
/// A type binds exactly one `source`. Subscription `arguments` are a
/// filter applied by `match`, never a parameter of the source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventTypeConfig {
    /// The type's name, unique, at most 128 characters of
    /// `[A-Za-z0-9._-]`. Publish a new name instead of changing a
    /// schema in a way that is not additive.
    pub name: String,

    /// What an occurrence means, for the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema of the subscription `arguments`. Omitted, a
    /// subscription carries no arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,

    /// JSON Schema of each occurrence's `data`. An occurrence that does
    /// not match it is dropped and counted. Omitted, any object is
    /// accepted. A `watch` or `resource` source sends `{observedAt}` (and
    /// `uri` for `resource`), which the schema must accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_schema: Option<Value>,

    /// Delivery modes offered, intersected with the modes
    /// `mcp.configurations.events` enables. Default every mode. The
    /// intersection must not be empty.
    #[serde(default = "EventTypeConfig::default_delivery")]
    pub delivery: Vec<EventDeliveryMode>,

    /// Whose credential reads the source. `shared` (default) reads with
    /// the gateway's own identity; per-subscriber visibility is then
    /// expressed in `match`.
    #[serde(default)]
    pub audience: EventAudience,

    /// CEL expression over `arguments`, `event` (`event.data`,
    /// `event.name`, `event.eventId`, `event.timestamp`) and `subscriber`
    /// that selects the occurrences a subscription receives. An error or
    /// a non-boolean result delivers nothing.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_expr: Option<String>,

    /// Operator transform applied to each occurrence's `data` before the
    /// payload schema check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<EventTransformConfig>,

    /// How long and how much of this type's log is kept.
    #[serde(default)]
    pub retention: EventRetentionConfig,

    /// `log` (default) lets a client resume from a cursor within
    /// retention; `none` always answers `cursor: null`.
    #[serde(default)]
    pub replay: EventReplay,

    /// Keep the source running with no subscriber, so the log covers
    /// periods without one. Default `false`: a source starts with the
    /// first subscription and stops `sources.linger_ms` after the last.
    #[serde(default)]
    pub always_on: bool,

    /// Where occurrences come from: exactly one of `watch`, `inbound`,
    /// `resource` or `builtin`.
    pub source: EventSourceConfig,
}

impl EventTypeConfig {
    fn default_delivery() -> Vec<EventDeliveryMode> {
        vec![
            EventDeliveryMode::Poll,
            EventDeliveryMode::Push,
            EventDeliveryMode::Webhook,
        ]
    }
}

/// A delivery mode of an event type.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventDeliveryMode {
    /// `events/poll`.
    Poll,
    /// `events/stream`.
    Push,
    /// `events/subscribe` with a callback URL.
    Webhook,
}

/// Whose credential reads an event source.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventAudience {
    /// The gateway's own identity; one source serves every subscriber.
    #[default]
    Shared,
    /// Each subscriber's own credential. No source kind of this build
    /// reads with a subscriber's credential, so this is refused.
    PerPrincipal,
}

/// Whether a type's log serves replay.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventReplay {
    /// Cursors resume from the log within retention.
    #[default]
    Log,
    /// No cursor is issued; every subscription starts from now.
    None,
}

/// An operator transform of occurrence data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventTransformConfig {
    /// Id of a loaded transform plugin, for example
    /// `dev.mcpg.transform.jsonata`.
    pub plugin: String,
    /// The expression handed to the plugin.
    pub expression: String,
}

/// `retention:` — the bounds of one type's log. The oldest occurrences
/// are evicted first; an append is never refused. On a gateway a control
/// plane manages, the plan's retention caps are the most each bound can be.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EventRetentionConfig {
    /// Oldest occurrence kept, in milliseconds. Default 86 400 000
    /// (24 hours).
    pub max_age_ms: u64,
    /// Most occurrences kept. Default 10 000.
    pub max_events: u64,
    /// Most bytes kept. Default 8 388 608 (8 MiB). The sum over every
    /// type, imported types included, must fit the event-log store: half
    /// of the NATS coordinator's events bucket
    /// (`jetstream.named_bucket_max_bytes`, 256 MiB by default), or
    /// 64 MiB for an in-process memory store. Redis, a `file` store and a
    /// store plugin set no limit on the sum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

impl Default for EventRetentionConfig {
    fn default() -> Self {
        Self {
            max_age_ms: 86_400_000,
            max_events: 10_000,
            max_bytes: None,
        }
    }
}

impl EventRetentionConfig {
    /// The byte budget in force: `max_bytes`, or the default.
    pub fn max_bytes_or_default(&self) -> u64 {
        self.max_bytes.unwrap_or(DEFAULT_RETENTION_MAX_BYTES)
    }

    /// Checks of the block written at `at`.
    pub(crate) fn validate(&self, at: &str) -> Result<()> {
        positive_at(at, "retention.max_age_ms", self.max_age_ms)?;
        positive_at(at, "retention.max_events", self.max_events)?;
        if self.max_bytes_or_default() < MAX_WEBHOOK_BODY_BYTES {
            bail!(
                "{at}.retention.max_bytes must be at least {MAX_WEBHOOK_BODY_BYTES}, the largest \
                 occurrence the log holds"
            );
        }
        Ok(())
    }
}

/// The source of an event type: exactly one of `watch`, `inbound`,
/// `resource` or `builtin`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventSourceConfig {
    /// A plugin watch strategy. Every change it reports is one
    /// occurrence: with the plugin's payload when `event_type` names one
    /// of the event types the plugin declares, else `data: {observedAt}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<EventWatchSourceConfig>,
    /// Signed webhooks that third parties POST to
    /// `/webhooks/events/{source_id}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<InboundSourceConfig>,
    /// The `uri` of the `resources[]` binding whose `watch:` block feeds
    /// the type. Every change is one occurrence with
    /// `data: {uri, observedAt}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// An event the gateway itself raises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin: Option<BuiltinEventSource>,
}

/// The one source an [`EventSourceConfig`] names.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventSource<'a> {
    Watch(&'a EventWatchSourceConfig),
    Inbound(&'a InboundSourceConfig),
    Resource(&'a str),
    Builtin(BuiltinEventSource),
}

impl EventSourceConfig {
    /// The source, when exactly one is named.
    pub fn get(&self) -> Option<EventSource<'_>> {
        match (&self.watch, &self.inbound, &self.resource, self.builtin) {
            (Some(watch), None, None, None) => Some(EventSource::Watch(watch)),
            (None, Some(inbound), None, None) => Some(EventSource::Inbound(inbound)),
            (None, None, Some(uri), None) => Some(EventSource::Resource(uri)),
            (None, None, None, Some(builtin)) => Some(EventSource::Builtin(builtin)),
            _ => None,
        }
    }
}

/// An event the gateway raises itself.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema)]
pub enum BuiltinEventSource {
    /// A task of the subscriber changed status. Delivered only to the
    /// principal whose session owns the task.
    #[serde(rename = "mcp.task.updated")]
    TaskUpdated,
    /// A tool gate asked a person to approve a call.
    #[serde(rename = "approval.requested")]
    ApprovalRequested,
    /// An approval was granted, denied or ran out of time.
    #[serde(rename = "approval.resolved")]
    ApprovalResolved,
}

impl BuiltinEventSource {
    /// The config spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskUpdated => "mcp.task.updated",
            Self::ApprovalRequested => "approval.requested",
            Self::ApprovalResolved => "approval.resolved",
        }
    }

    /// Every builtin source.
    pub const ALL: [Self; 3] = [
        Self::TaskUpdated,
        Self::ApprovalRequested,
        Self::ApprovalResolved,
    ];

    /// The schema of the `data` this source sends.
    pub fn payload_schema(self) -> Value {
        match self {
            Self::TaskUpdated => serde_json::json!({
                "type": "object",
                "required": ["taskId", "status"],
                "properties": {
                    "taskId": { "type": "string" },
                    "status": { "type": "string" },
                    "statusMessage": { "type": "string" },
                    "toolName": { "type": "string" },
                    "lastUpdatedAt": { "type": "string" }
                }
            }),
            Self::ApprovalRequested => serde_json::json!({
                "type": "object",
                "required": ["approvalId", "toolName"],
                "properties": {
                    "approvalId": { "type": "string" },
                    "toolName": { "type": "string" },
                    "summary": { "type": "string" },
                    "deadlineAt": { "type": "string" }
                }
            }),
            Self::ApprovalResolved => serde_json::json!({
                "type": "object",
                "required": ["approvalId", "outcome"],
                "properties": {
                    "approvalId": { "type": "string" },
                    "toolName": { "type": "string" },
                    "outcome": { "type": "string", "enum": ["approved", "denied", "expired"] }
                }
            }),
        }
    }
}

/// `source.watch:` — a plugin watch strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventWatchSourceConfig {
    /// A plugin-backed strategy: `nats_topic`, `kafka_topic` (it reads
    /// with its own `mcpg-events-{name}` group unless `group_id` names
    /// one), `sql_polling`, `postgres_listen_notify` or `plugin`. `poll`
    /// and `webhook` are refused: `poll` reads a resource the event type
    /// does not have, and the `webhook` token route is not an event source
    /// (use `inbound`).
    pub strategy: WatchStrategyConfig,
    /// One of the event types the strategy declares in its plugin's
    /// `plugin.yaml` (`watch_strategies[].event_types`). The type then
    /// carries the plugin's payload, its schemas unless this type declares
    /// its own, and resumes where it stopped when the strategy can. A
    /// strategy that declares no types is refused at boot. Omitted, every
    /// change is a payload-free `{observedAt}` occurrence. Either way the
    /// source runs where the strategy places it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
}

/// `source.inbound:` — a signed inbound webhook route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundSourceConfig {
    /// The route segment: senders POST to `/webhooks/events/{source_id}`.
    /// At most 64 characters of `[A-Za-z0-9_-]`. Types that share a route
    /// each take the requests their `when` keeps, and declare the same
    /// `verify`, `allow_unsigned` and `rate_limit`.
    pub source_id: String,
    /// How a request proves its sender. Required unless
    /// `allow_unsigned` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<InboundVerifyConfig>,
    /// Accept requests nobody signed. Anyone who can reach the route can
    /// then inject events. Default `false`.
    #[serde(default)]
    pub allow_unsigned: bool,
    /// JSON pointer to the sender's event id in the body (for example
    /// `/id`). Omitted, the scheme's id is used: the `webhook-id` header
    /// of Standard Webhooks, `X-GitHub-Delivery` of GitHub, `/id` of
    /// Stripe, `/event_id` of Slack; with none, the gateway mints an id.
    /// A repeated id is accepted once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// JSON pointer to the event time in the body, RFC 3339 or Unix
    /// seconds. Omitted, the scheme's time (`/created` of Stripe,
    /// `/event_time` of Slack), else the time the request arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Requests to keep; any other request is acknowledged and dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<InboundWhenConfig>,
    /// Requests accepted per second on each replica; past it the route
    /// answers `429` with `Retry-After`.
    #[serde(default)]
    pub rate_limit: InboundRateLimitConfig,
}

/// `verify:` — how an inbound request proves its sender: a signing
/// profile and this route's secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundVerifyConfig {
    /// The signing profile: a built-in one (`standard_webhooks`,
    /// `github`, `stripe`, `slack`) or the `name` of an entry of
    /// `mcp.configurations.events.inbound_profiles`.
    pub profile: String,
    /// Shared secrets, usually `${secret.NAME}`. Several are accepted at
    /// once during a rotation.
    pub secrets: Vec<String>,
    /// Largest age or skew of the signed timestamp, in seconds, in place
    /// of the profile's. Only for a profile that signs a timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance_secs: Option<u64>,
}

/// An entry of `inbound_profiles:` — how one kind of sender signs its
/// webhooks: an HMAC of a message built from the raw body, a signed
/// timestamp and headers. Routes name it in `verify.profile`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundProfileConfig {
    /// The name routes give in `verify.profile`. At most 64 characters
    /// of `[a-z0-9_-]`; a built-in name cannot be declared again.
    pub name: String,
    /// The HMAC hash. Default `sha256`.
    #[serde(default)]
    pub algorithm: HmacAlgorithm,
    /// How a configured secret becomes the HMAC key.
    #[serde(default)]
    pub secret: SecretFormatConfig,
    /// Where the request carries its signatures.
    pub signature: SignatureFormatConfig,
    /// The signed message. `{body}` is the raw body and must appear once;
    /// `{timestamp}` is the signed timestamp; `{header:NAME}` is the
    /// value of request header `NAME`. Default `{body}`.
    #[serde(default = "default_signed_payload")]
    pub signed_payload: String,
    /// The signed Unix-seconds timestamp, for a sender that signs one.
    /// A request outside the tolerance is refused as stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_timestamp: Option<SignedTimestampConfig>,
    /// Where the sender puts its event id. A route's own `event_id`
    /// takes its place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<InboundValueConfig>,
    /// JSON pointer to the event time in the body, RFC 3339 or Unix
    /// seconds. A route's own `timestamp` takes its place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_time: Option<String>,
    /// Requests the route answers itself, never as events: a sender's
    /// ping or URL challenge. The first match applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handshakes: Vec<InboundHandshakeConfig>,
}

/// The hash of an HMAC signature.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HmacAlgorithm {
    /// HMAC-SHA1, 20-byte digests.
    Sha1,
    /// HMAC-SHA256, 32-byte digests.
    #[default]
    Sha256,
    /// HMAC-SHA512, 64-byte digests.
    Sha512,
}

/// How bytes are written as text.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TextEncoding {
    /// The text's own UTF-8 bytes.
    #[default]
    Utf8,
    /// Hexadecimal.
    Hex,
    /// Standard base64, with or without padding.
    Base64,
}

/// `secret:` — how a configured secret becomes the HMAC key.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SecretFormatConfig {
    /// Text every secret starts with, removed before decoding; a secret
    /// without it is refused at boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// How the rest of the secret encodes the key. Default `utf8`.
    pub encoding: TextEncoding,
    /// Shortest key, in decoded bytes; a shorter secret is refused at boot.
    /// At least 1. Unset, any non-empty key.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub min_bytes: Option<u32>,
    /// Longest key, in decoded bytes; a longer secret is refused at boot.
    /// Unset, no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub max_bytes: Option<u32>,
}

/// `signature:` — where a request carries its signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignatureFormatConfig {
    /// The header with the signatures. It must appear once.
    pub header: String,
    /// The header holds several items split by this text. Omitted, the
    /// whole value is one item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    /// Items are `key=value` pairs, and the signatures are the values of
    /// this key. Needs `separator`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Text before each digest, removed before decoding. An item without
    /// it is skipped.
    #[serde(default)]
    pub prefix: String,
    /// How a digest is written: `hex` (default) or `base64`.
    #[serde(default = "default_digest_encoding")]
    pub encoding: TextEncoding,
}

/// `signed_timestamp:` — where the signed timestamp is. Name exactly one
/// of `header` and `key`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedTimestampConfig {
    /// The header that carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The `key=value` item of the signature header that carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Largest age or skew, in seconds. Default 300.
    #[serde(default = "default_tolerance_secs")]
    pub tolerance_secs: u64,
}

/// A value of the request. Name exactly one of `header` and `pointer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundValueConfig {
    /// A request header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// A JSON pointer into the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

/// An entry of `handshakes:` — a request the route answers itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundHandshakeConfig {
    /// The requests it answers. Every listed header and body field must
    /// match.
    pub when: InboundWhenConfig,
    /// The JSON object of a `200` reply: each key takes the string at a
    /// JSON pointer into the body, as a URL challenge is echoed. Omitted,
    /// the route acknowledges with `202`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reply: BTreeMap<String, String>,
}

/// The profiles every route can name, from `inbound_profiles.yaml`.
pub fn builtin_inbound_profiles() -> &'static [InboundProfileConfig] {
    static PROFILES: std::sync::LazyLock<Vec<InboundProfileConfig>> =
        std::sync::LazyLock::new(|| {
            serde_yaml::from_str(include_str!("inbound_profiles.yaml"))
                .expect("the built-in inbound profiles parse")
        });
    &PROFILES
}

/// The profile called `name`: a declared one, else a built-in one.
pub fn find_inbound_profile<'a>(
    declared: &'a [InboundProfileConfig],
    name: &str,
) -> Option<&'a InboundProfileConfig> {
    declared
        .iter()
        .chain(builtin_inbound_profiles())
        .find(|p| p.name == name)
}

fn default_tolerance_secs() -> u64 {
    300
}

fn default_signed_payload() -> String {
    "{body}".to_owned()
}

fn default_digest_encoding() -> TextEncoding {
    TextEncoding::Hex
}

/// `when:` — the requests an inbound source keeps. Every listed header
/// and every listed body field must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct InboundWhenConfig {
    /// Header name to the exact value it must carry.
    pub header: BTreeMap<String, String>,
    /// JSON pointer into the body to the exact JSON value it must hold.
    pub body: BTreeMap<String, Value>,
}

// A JSON number is never NaN, so equality of JSON values is total.
impl Eq for InboundWhenConfig {}

/// Request rate of one inbound source on each replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct InboundRateLimitConfig {
    /// Sustained requests per second. Default 50.
    pub per_sec: u64,
    /// Requests accepted in a burst. Default 100.
    pub burst: u64,
}

impl Default for InboundRateLimitConfig {
    fn default() -> Self {
        Self {
            per_sec: 50,
            burst: 100,
        }
    }
}

/// Input schema of a type that declares none: no arguments.
pub fn default_input_schema() -> Value {
    serde_json::json!({ "type": "object", "additionalProperties": false })
}

/// Payload schema of a type that declares none: any object.
pub fn default_payload_schema() -> Value {
    serde_json::json!({ "type": "object" })
}

/// The payload a `watch` source sends with every change.
pub fn watch_tick_sample() -> Value {
    serde_json::json!({ "observedAt": "2026-01-01T00:00:00Z" })
}

/// The payload a `resource` source sends with every change.
pub fn resource_tick_sample(uri: &str) -> Value {
    serde_json::json!({ "uri": uri, "observedAt": "2026-01-01T00:00:00Z" })
}

/// Whether `name` is a valid event-type name.
pub fn is_event_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_EVENT_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Whether `id` is a valid inbound `source_id`.
pub fn is_source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SOURCE_ID_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

// ---------------------------------------------------------------------------
// Whole-config validation
// ---------------------------------------------------------------------------

/// Where the event subscriptions or the log live, as far as durability
/// and capacity go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStoreClass {
    /// The cluster coordinator's own store on a single node: in memory.
    SingleNodeCoordinator,
    /// The shared store of a distributed coordinator.
    DistributedCoordinator,
    /// A `memory` override.
    Memory,
    /// A `file` override.
    File,
    /// A store plugin.
    Plugin,
}

impl EventStoreClass {
    /// Classify the store `over` resolves to under `cluster`.
    pub fn of(over: Option<&StoreOverrideConfig>, cluster: &crate::config::ClusterConfig) -> Self {
        match over.map(|o| o.kind.as_str()) {
            None | Some(super::store_override::CLUSTER_KIND) => {
                if cluster.is_single_node() {
                    Self::SingleNodeCoordinator
                } else {
                    Self::DistributedCoordinator
                }
            }
            Some("memory") => Self::Memory,
            Some("file") => Self::File,
            Some(_) => Self::Plugin,
        }
    }

    /// Whether what is written survives a gateway restart.
    pub fn is_durable(self) -> bool {
        !matches!(self, Self::SingleNodeCoordinator | Self::Memory)
    }

    /// Bytes the event log may take from this store in total, when the
    /// store has a known size. On NATS the events stores keep a bucket of
    /// their own, which the log shares with the subscriptions, so it takes
    /// at most half; Redis bounds no store by size.
    pub fn log_budget_bytes(self, cluster: &crate::config::ClusterConfig) -> Option<u64> {
        match self {
            Self::DistributedCoordinator if cluster.kind == "nats" => Some(
                cluster
                    .config
                    .get("jetstream")
                    .and_then(|jetstream| jetstream.get("named_bucket_max_bytes"))
                    .and_then(Value::as_u64)
                    .unwrap_or(NATS_EVENTS_BUCKET_BYTES)
                    / 2,
            ),
            Self::SingleNodeCoordinator | Self::Memory => Some(MEMORY_STORE_BUDGET_BYTES),
            Self::DistributedCoordinator | Self::File | Self::Plugin => None,
        }
    }
}

/// The base64 of `sessions.synthetic_session_key`, decoded, when it is a
/// 32-byte key.
pub(crate) fn decode_synthetic_session_key(raw: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .ok()?;
    decoded.try_into().ok()
}

/// Validate `mcp.capabilities.events` against the whole config, and the
/// parts of `mcp.configurations.events` that depend on other blocks.
pub(crate) fn validate_app(config: &crate::config::AppConfig) -> Result<()> {
    let events = &config.mcp.configurations.events;
    if events.enabled && events.webhook.enabled {
        let class = EventStoreClass::of(events.store.as_ref(), &config.cluster);
        if !class.is_durable() && !events.allow_ephemeral_subscriptions {
            bail!(
                "mcp.configurations.events: webhook delivery keeps subscriptions for their whole \
                 grant, across restarts, but the subscription store is in memory. Set \
                 mcp.configurations.events.store to `{{kind: file, dir: …}}`, run a distributed \
                 cluster coordinator, or set allow_ephemeral_subscriptions: true to cap every \
                 grant at webhook.ttl.min_ms"
            );
        }
    }
    // Ids, cursors, sealed secrets and the secrets of upstream callbacks are
    // derived from one key. Webhook delivery needs it to outlive a restart;
    // a cluster needs every replica to derive the same values.
    let needs_shared_key =
        events.enabled && (events.webhook.enabled || !config.cluster.is_single_node());
    if needs_shared_key && config.cluster.state_encryption_key_env.is_none() {
        let why = if events.webhook.enabled {
            "webhook delivery"
        } else {
            "a clustered gateway"
        };
        match config
            .mcp
            .configurations
            .sessions
            .synthetic_session_key
            .as_deref()
        {
            None => bail!(
                "mcp.configurations.events: {why} derives subscription ids, cursors and secrets \
                 from a key every replica shares, and none is set. Set \
                 cluster.state_encryption_key_env or \
                 mcp.configurations.sessions.synthetic_session_key (base64 of 32 bytes)"
            ),
            Some(raw) if decode_synthetic_session_key(raw).is_none() => bail!(
                "mcp.configurations.sessions.synthetic_session_key must be standard base64 of \
                 exactly 32 bytes while events use it as their key"
            ),
            Some(_) => {}
        }
    }

    if config.gateway.server.canonical_url.is_none() {
        for fed in config.mcp.federations.iter().filter(|fed| {
            fed.import.events
                && fed.events.delivery == crate::config::federation::UpstreamEventDelivery::Webhook
        }) {
            tracing::warn!(
                "mcp.federations[{}].events.delivery: webhook needs a public address of this \
                 gateway, and gateway.server.canonical_url is unset; the imported types are \
                 served only while a public tunnel provides one",
                fed.name
            );
        }
    }

    let enabled_modes: BTreeSet<EventDeliveryMode> = events.enabled_modes().into_iter().collect();
    let mut names = BTreeSet::new();
    let mut routes: BTreeMap<&str, (&str, &InboundSourceConfig)> = BTreeMap::new();
    let mut budget_sum: u64 = 0;
    for (index, ty) in config.mcp.capabilities.events.iter().enumerate() {
        let at = format!("mcp.capabilities.events[{index}]");
        validate_event_type(config, ty, &at, events.enabled, &enabled_modes)?;
        if !names.insert(ty.name.as_str()) {
            bail!("{at}: duplicate event name `{}`", ty.name);
        }
        if let Some(inbound) = &ty.source.inbound {
            match routes.get(inbound.source_id.as_str()) {
                None => {
                    routes.insert(inbound.source_id.as_str(), (ty.name.as_str(), inbound));
                }
                Some((first, route))
                    if route.verify != inbound.verify
                        || route.allow_unsigned != inbound.allow_unsigned
                        || route.rate_limit != inbound.rate_limit =>
                {
                    bail!(
                        "{at}.source.inbound: route `{}` is shared with event type `{first}`, \
                         which declares another verify, allow_unsigned or rate_limit; types \
                         that share a route declare the same three",
                        inbound.source_id
                    );
                }
                Some(_) => {}
            }
        }
        budget_sum = budget_sum.saturating_add(ty.retention.max_bytes_or_default());
    }

    let log_class = EventStoreClass::of(events.log_store.as_ref(), &config.cluster);
    if let Some(budget) = log_class.log_budget_bytes(&config.cluster)
        && budget_sum > budget
    {
        bail!(
            "mcp.capabilities.events: the retention byte budgets add up to {budget_sum} bytes, \
             more than the {budget} bytes the event-log store can give the log. Lower \
             retention.max_bytes (default {DEFAULT_RETENTION_MAX_BYTES} per type) or point \
             mcp.configurations.events.log_store at a dedicated store"
        );
    }
    Ok(())
}

fn validate_event_type(
    config: &crate::config::AppConfig,
    ty: &EventTypeConfig,
    at: &str,
    events_enabled: bool,
    enabled_modes: &BTreeSet<EventDeliveryMode>,
) -> Result<()> {
    use crate::config::schema_safety::compile_checked;

    if !is_event_name(&ty.name) {
        bail!(
            "{at}.name `{}` must be 1 to {MAX_EVENT_NAME_CHARS} characters of [A-Za-z0-9._-]",
            ty.name
        );
    }
    let at = format!("{at}[name=`{}`]", ty.name);
    for fed in config
        .mcp
        .federations
        .iter()
        .filter(|fed| fed.import.events)
    {
        let prefix = fed.event_prefix();
        if !prefix.is_empty() && ty.name.starts_with(prefix) {
            bail!(
                "{at}: the name starts with `{prefix}`, the prefix federation `{}` imports its \
                 event types under; rename the event type or change naming.event_prefix",
                fed.name
            );
        }
    }
    if ty.audience == EventAudience::PerPrincipal {
        bail!(
            "{at}.audience: per_principal needs a source that reads with each subscriber's \
             credential, and no source kind of this build does; use `shared` and select per \
             subscriber in `match`"
        );
    }
    if ty.delivery.is_empty() {
        bail!("{at}.delivery must list at least one delivery mode");
    }
    if events_enabled && !ty.delivery.iter().any(|m| enabled_modes.contains(m)) {
        bail!(
            "{at}.delivery lists no mode mcp.configurations.events enables; the type would \
             offer no way to receive it"
        );
    }
    let input_schema = ty.input_schema.clone().unwrap_or_else(default_input_schema);
    let payload_schema = ty
        .payload_schema
        .clone()
        .unwrap_or_else(default_payload_schema);
    for (field, schema) in [
        ("input_schema", &input_schema),
        ("payload_schema", &payload_schema),
    ] {
        if schema.get("$schema_ref").is_some() {
            bail!(
                "{at}.{field}: `$schema_ref` is not supported for event types; inline the schema"
            );
        }
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            bail!("{at}.{field} must be an object schema (`type: object`)");
        }
    }
    compile_checked(&input_schema, &format!("{at}.input_schema"))?;
    let payload_validator = compile_checked(&payload_schema, &format!("{at}.payload_schema"))?;
    if let Some(expr) = &ty.match_expr {
        cel::Program::compile(expr)
            .map_err(|e| anyhow::anyhow!("{at}.match is not a valid CEL expression: {e}"))?;
    }
    if let Some(transform) = &ty.transform
        && (transform.plugin.trim().is_empty() || transform.expression.trim().is_empty())
    {
        bail!("{at}.transform needs both `plugin` and `expression`");
    }
    ty.retention.validate(&at)?;

    let source = ty.source.get().ok_or_else(|| {
        anyhow::anyhow!(
            "{at}.source must name exactly one of `watch`, `inbound`, `resource` or `builtin`"
        )
    })?;
    match source {
        EventSource::Builtin(builtin) => {
            let builtin_payload = builtin.payload_schema();
            let sample = builtin_sample(builtin);
            if !payload_validator.is_valid(&sample) {
                bail!(
                    "{at}.payload_schema must accept what `{}` sends, which follows {}",
                    builtin.as_str(),
                    builtin_payload
                );
            }
        }
        EventSource::Watch(watch) if watch.event_type.is_some() => {
            if watch
                .event_type
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            {
                bail!("{at}.source.watch.event_type must not be empty");
            }
            watch
                .strategy
                .validate(&format!("{at}.source.watch.strategy"))?;
        }
        EventSource::Watch(watch) => {
            watch
                .strategy
                .validate(&format!("{at}.source.watch.strategy"))?;
            match &watch.strategy {
                WatchStrategyConfig::Poll { .. } => bail!(
                    "{at}.source.watch.strategy: `poll` reads a resource, and an event type has \
                     none; use `source.resource` naming a resource binding instead"
                ),
                WatchStrategyConfig::Webhook { .. } => bail!(
                    "{at}.source.watch.strategy: the `webhook` token route is not an event \
                     source; use `source.inbound`, which verifies a signature"
                ),
                WatchStrategyConfig::Plugin { kind, .. } if kind.trim().is_empty() => {
                    bail!("{at}.source.watch.strategy.kind must not be empty")
                }
                _ => {}
            }
            if !payload_validator.is_valid(&watch_tick_sample()) {
                bail!(
                    "{at}.payload_schema must accept the `{{observedAt}}` object a watch source \
                     sends with every change"
                );
            }
        }
        EventSource::Resource(uri) => {
            let binding = config
                .mcp
                .capabilities
                .resources
                .iter()
                .find(|b| b.uri.as_deref() == Some(uri))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{at}.source.resource `{uri}` names no mcp.capabilities.resources[] \
                         binding with that uri"
                    )
                })?;
            let watch = binding.watch.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "{at}.source.resource: binding `{}` has no `watch:` block to observe",
                    binding.name
                )
            })?;
            if matches!(watch.strategy, WatchStrategyConfig::Webhook { .. }) {
                bail!(
                    "{at}.source.resource: binding `{}` watches through the `webhook` token \
                     route, which is not an event source; use `source.inbound`",
                    binding.name
                );
            }
            if !payload_validator.is_valid(&resource_tick_sample(uri)) {
                bail!(
                    "{at}.payload_schema must accept the `{{uri, observedAt}}` object a resource \
                     source sends with every change"
                );
            }
        }
        EventSource::Inbound(inbound) => validate_inbound(
            &at,
            inbound,
            &config.mcp.configurations.events.inbound_profiles,
        )?,
    }
    Ok(())
}

/// An occurrence `builtin` could send, which the type's payload schema must
/// accept.
fn builtin_sample(builtin: BuiltinEventSource) -> Value {
    match builtin {
        BuiltinEventSource::TaskUpdated => serde_json::json!({
            "taskId": "t-1",
            "status": "completed",
            "toolName": "x",
            "lastUpdatedAt": "2026-01-01T00:00:00Z"
        }),
        BuiltinEventSource::ApprovalRequested => serde_json::json!({
            "approvalId": "a-1",
            "toolName": "x",
            "summary": "s",
            "deadlineAt": "2026-01-01T00:00:00Z"
        }),
        BuiltinEventSource::ApprovalResolved => serde_json::json!({
            "approvalId": "a-1",
            "toolName": "x",
            "outcome": "approved"
        }),
    }
}

fn validate_inbound(
    at: &str,
    inbound: &InboundSourceConfig,
    profiles: &[InboundProfileConfig],
) -> Result<()> {
    let at = format!("{at}.source.inbound");
    if !is_source_id(&inbound.source_id) {
        bail!(
            "{at}.source_id `{}` must be 1 to {MAX_SOURCE_ID_CHARS} characters of [A-Za-z0-9_-]",
            inbound.source_id
        );
    }
    match &inbound.verify {
        None if !inbound.allow_unsigned => bail!(
            "{at}: a route with no `verify` accepts events from anyone who can reach it; \
             configure `verify` or set allow_unsigned: true"
        ),
        None => tracing::warn!(
            source_id = %inbound.source_id,
            "an inbound event route accepts unsigned requests (allow_unsigned: true)"
        ),
        Some(verify) => {
            let Some(profile) = find_inbound_profile(profiles, &verify.profile) else {
                bail!(
                    "{at}.verify.profile `{}` is neither a built-in profile nor declared in \
                     mcp.configurations.events.inbound_profiles",
                    verify.profile
                );
            };
            if verify.secrets.is_empty() {
                bail!("{at}.verify.secrets must list at least one secret");
            }
            match verify.tolerance_secs {
                Some(0) => bail!("{at}.verify.tolerance_secs must be greater than 0"),
                Some(_) if profile.signed_timestamp.is_none() => bail!(
                    "{at}.verify.tolerance_secs: profile `{}` signs no timestamp",
                    profile.name
                ),
                _ => {}
            }
        }
    }
    for (field, pointer) in [
        ("event_id", inbound.event_id.as_deref()),
        ("timestamp", inbound.timestamp.as_deref()),
    ] {
        if let Some(pointer) = pointer
            && !pointer.starts_with('/')
        {
            bail!("{at}.{field} `{pointer}` must be a JSON pointer starting with `/`");
        }
    }
    if let Some(when) = &inbound.when {
        for name in when.header.keys() {
            if axum::http::HeaderName::try_from(name.as_str()).is_err() {
                bail!("{at}.when.header `{name}` is not a valid header name");
            }
        }
        for pointer in when.body.keys() {
            if !pointer.starts_with('/') {
                bail!("{at}.when.body key `{pointer}` must be a JSON pointer starting with `/`");
            }
        }
    }
    positive_at(&at, "rate_limit.per_sec", inbound.rate_limit.per_sec)?;
    positive_at(&at, "rate_limit.burst", inbound.rate_limit.burst)?;
    Ok(())
}

/// A piece of a profile's `signed_payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedPart {
    /// Text signed as it is.
    Text(String),
    /// The raw body.
    Body,
    /// The signed timestamp, as the request wrote it.
    Timestamp,
    /// The value of a request header.
    Header(String),
}

/// The pieces of a `signed_payload` template.
pub fn parse_signed_payload(template: &str) -> Result<Vec<SignedPart>> {
    let mut parts = Vec::new();
    let mut rest = template;
    while !rest.is_empty() {
        let Some(open) = rest.find(['{', '}']) else {
            parts.push(SignedPart::Text(rest.to_owned()));
            break;
        };
        if open > 0 {
            parts.push(SignedPart::Text(rest[..open].to_owned()));
        }
        let tail = &rest[open..];
        let Some(close) = tail.strip_prefix('{').and_then(|t| t.find('}')) else {
            bail!("`{template}` has a `{{` or `}}` outside a placeholder");
        };
        let name = &tail[1..=close];
        parts.push(match name {
            "body" => SignedPart::Body,
            "timestamp" => SignedPart::Timestamp,
            _ => match name.strip_prefix("header:") {
                Some(header) if axum::http::HeaderName::try_from(header).is_ok() => {
                    SignedPart::Header(header.to_owned())
                }
                _ => bail!(
                    "`{template}`: `{{{name}}}` is not {{body}}, {{timestamp}} or {{header:NAME}}"
                ),
            },
        });
        rest = &tail[close + 2..];
    }
    Ok(parts)
}

/// Checks of one signing profile, built-in or declared.
pub(crate) fn validate_inbound_profile(at: &str, profile: &InboundProfileConfig) -> Result<()> {
    let header_name = |field: &str, name: &str| -> Result<()> {
        if axum::http::HeaderName::try_from(name).is_err() {
            bail!("{at}.{field} `{name}` is not a valid header name");
        }
        Ok(())
    };
    let pointer = |field: &str, pointer: &str| -> Result<()> {
        if !pointer.starts_with('/') {
            bail!("{at}.{field} `{pointer}` must be a JSON pointer starting with `/`");
        }
        Ok(())
    };
    if profile.name.is_empty()
        || profile.name.len() > MAX_SOURCE_ID_CHARS
        || !profile
            .name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        bail!(
            "{at}.name `{}` must be 1 to {MAX_SOURCE_ID_CHARS} characters of [a-z0-9_-]",
            profile.name
        );
    }
    if profile.secret.prefix.as_deref() == Some("") {
        bail!("{at}.secret.prefix must not be empty");
    }
    match (profile.secret.min_bytes, profile.secret.max_bytes) {
        (Some(0), _) => bail!("{at}.secret.min_bytes must be at least 1"),
        (_, Some(0)) => bail!("{at}.secret.max_bytes must be at least 1"),
        (Some(min), Some(max)) if min > max => {
            bail!("{at}.secret.min_bytes ({min}) must not exceed secret.max_bytes ({max})")
        }
        _ => {}
    }
    let signature = &profile.signature;
    header_name("signature.header", &signature.header)?;
    if signature.separator.as_deref() == Some("") {
        bail!("{at}.signature.separator must not be empty");
    }
    match signature.key.as_deref() {
        Some("") => bail!("{at}.signature.key must not be empty"),
        Some(_) if signature.separator.is_none() => {
            bail!("{at}.signature.key needs signature.separator: the items are `key=value` pairs")
        }
        _ => {}
    }
    if signature.encoding == TextEncoding::Utf8 {
        bail!("{at}.signature.encoding must be `hex` or `base64`");
    }
    let parts = parse_signed_payload(&profile.signed_payload)
        .map_err(|e| anyhow::anyhow!("{at}.signed_payload {e}"))?;
    if parts.iter().filter(|p| **p == SignedPart::Body).count() != 1 {
        bail!("{at}.signed_payload must contain {{body}} exactly once");
    }
    match &profile.signed_timestamp {
        None if parts.contains(&SignedPart::Timestamp) => {
            bail!("{at}.signed_payload uses {{timestamp}}, and the profile has no signed_timestamp")
        }
        None => {}
        Some(timestamp) => {
            match (&timestamp.header, &timestamp.key) {
                (Some(header), None) => header_name("signed_timestamp.header", header)?,
                (None, Some(_)) if signature.key.is_none() => bail!(
                    "{at}.signed_timestamp.key needs signature.key: it names an item of the \
                     signature header"
                ),
                (None, Some(key)) if key.is_empty() => {
                    bail!("{at}.signed_timestamp.key must not be empty")
                }
                (None, Some(_)) => {}
                _ => bail!("{at}.signed_timestamp must name exactly one of `header` and `key`"),
            }
            if timestamp.tolerance_secs == 0 {
                bail!("{at}.signed_timestamp.tolerance_secs must be greater than 0");
            }
        }
    }
    if let Some(event_id) = &profile.event_id {
        match (&event_id.header, &event_id.pointer) {
            (Some(header), None) => header_name("event_id.header", header)?,
            (None, Some(p)) => pointer("event_id.pointer", p)?,
            _ => bail!("{at}.event_id must name exactly one of `header` and `pointer`"),
        }
    }
    if let Some(p) = &profile.event_time {
        pointer("event_time", p)?;
    }
    for (index, handshake) in profile.handshakes.iter().enumerate() {
        let field = format!("handshakes[{index}]");
        if handshake.when.header.is_empty() && handshake.when.body.is_empty() {
            bail!(
                "{at}.{field}.when must list a header or a body field; empty, it matches every request"
            );
        }
        for name in handshake.when.header.keys() {
            header_name(&format!("{field}.when.header"), name)?;
        }
        for p in handshake.when.body.keys() {
            pointer(&format!("{field}.when.body"), p)?;
        }
        for (key, p) in &handshake.reply {
            if key.is_empty() {
                bail!("{at}.{field}.reply has an empty key");
            }
            pointer(&format!("{field}.reply.{key}"), p)?;
        }
    }
    Ok(())
}

fn positive_at(at: &str, field: &str, value: u64) -> Result<()> {
    if value == 0 {
        bail!("{at}.{field} must be greater than 0");
    }
    Ok(())
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
